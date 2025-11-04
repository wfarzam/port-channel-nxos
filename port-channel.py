#!/usr/bin/env python3
"""
Nexus vPC Port-Channel builder (multi-pair via vpc_group, robust ID checks, non-identical ports OK)

Excel columns (required, case-insensitive):
  source_device | source_port | switchport_type | allowed_vlan | native_vlan |
  destination_device | destination_port | mtu_value | port-channel_required | vpc_group

Optional column:
  lag_key  -> explicit pairing key per LAG across the two peers (recommended if you have multiple LAGs
               per server with identical attributes)

Behavior
- port-channel_required = yes:
    * vpc_group REQUIRED (exactly two destination_device values in that group).
    * vPC health check per group (no LLDP/CDP): domain matches AND peer adjacency OK AND keepalive OK.
    * Pairs rows one-per-peer; member ports may differ (e.g., E1/17 <> E1/18).
    * Allocates a Po/vPC ID that is free on BOTH peers (checks Po IDs + vPC IDs from
      'show vpc brief' AND 'show vpc'). Uses next free id in --id-min..--id-max.
    * Builds vPC + Port-Channel; Po ID == vPC ID.
- port-channel_required = no:
    * vpc_group ignored; config single physical interface only (no channel-group/Po/vPC).
- Per-device VLAN precheck; missing VLANs abort work.
- One backup file per device/run: 'show run interface <port>' for all referenced ports.
"""

import argparse, os, re, sys, json, time
from pathlib import Path
from typing import Dict, List, Set, Tuple

import pandas as pd
from tqdm import tqdm
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

ID_MIN_DEFAULT = 1
ID_MAX_DEFAULT = 100

REQ_COLS = [
    "source_device","source_port","switchport_type","allowed_vlan","native_vlan",
    "destination_device","destination_port","mtu_value","port-channel_required","vpc_group",
]

# ----------------------- helpers -----------------------

def now_stamp(): return time.strftime("%Y%m%d-%H%M%S")
def fmt_vlans(v): return ", ".join(str(x) for x in sorted(v)) if isinstance(v,(list,set,tuple)) else str(v)

def to_eth_canonical(s:str)->str:
    s=s.strip(); m=re.match(r"(?i)^(?:eth|ethernet)(\d+/\d+)$",s)
    return f"Ethernet{m.group(1)}" if m else s

def norm_iface_for_match(s:str)->str:
    return s.strip().replace("Ethernet","eth").replace("ethernet","eth").lower()

def normalize_separators(s:str)->str:
    if s is None: return ""
    s = s.replace("\u060c", ",").replace("\uff0c", ",").replace(";", ",").replace("/", ",").replace("|", ",")
    s = re.sub(r"\s+", ",", s)
    s = s.replace("\u200b","").replace("\u00a0","")
    s = re.sub(r",+", ",", s).strip(",")
    return s

def yn(s:str)->str: return "yes" if str(s).strip().lower() in ("y","yes","true","1") else "no"

# ----------------------- Excel -------------------------

def load_plan(xlsx:str)->pd.DataFrame:
    df = pd.read_excel(xlsx, sheet_name=0, dtype=str)
    lowmap = {c.lower(): c for c in df.columns}; rename={}
    for col in REQ_COLS:
        if col not in df.columns:
            if col in lowmap: rename[lowmap[col]] = col
            else:
                m=[c for c in df.columns if c.lower()==col]
                if m: rename[m[0]]=col
    if rename: df=df.rename(columns=rename)
    missing=[c for c in REQ_COLS if c not in df.columns]
    if missing: raise ValueError(f"Excel missing required columns: {missing}")
    # Optional lag_key
    if "lag_key" not in df.columns:
        df["lag_key"] = ""

    for c in list(REQ_COLS)+["lag_key"]:
        df[c]=df[c].astype(str).str.replace("\u200b","",regex=False).str.replace("\u00a0","",regex=False).str.strip()

    df["allowed_vlan"]=df["allowed_vlan"].apply(normalize_separators)
    df["native_vlan"]=df["native_vlan"].apply(normalize_separators)
    df["port-channel_required"]=df["port-channel_required"].apply(yn)
    return df

# ----------------------- device ------------------------

class Nexus:
    def __init__(self, host, username, password):
        self.host=host; self.username=username; self.password=password; self.conn=None
    def connect(self):
        try:
            self.conn=ConnectHandler(device_type="cisco_nxos", host=self.host,
                                     username=self.username, password=self.password, fast_cli=False)
        except (NetmikoAuthenticationException, NetmikoTimeoutException) as e:
            raise RuntimeError(f"Failed to connect to {self.host}: {e}")
    def run(self, cmd:str)->str:
        return self.conn.send_command(cmd, expect_string=r"#", use_textfsm=False)
    def run_cfg(self, lines:List[str])->str:
        return self.conn.send_config_set(lines)
    def disconnect(self):
        if self.conn: self.conn.disconnect()

class ConnPool:
    def __init__(self, user, pwd): self.user=user; self.pwd=pwd; self.pool:Dict[str,Nexus]={}
    def get(self, host)->Nexus:
        if host not in self.pool:
            nx=Nexus(host,self.user,self.pwd); nx.connect(); self.pool[host]=nx
        return self.pool[host]
    def close_all(self):
        for nx in self.pool.values(): nx.disconnect()

# ----------------------- vPC health --------------------

def parse_vpc_facts(out:str)->Dict[str,str]:
    facts={"domain":"","peer_ok":"no","keepalive_ok":"no"}
    m=re.search(r"vPC\s+domain\s+id\s*:\s*(\d+)",out,re.I)
    if m: facts["domain"]=m.group(1)
    if re.search(r"\bpeer adjacency formed ok\b",out,re.I): facts["peer_ok"]="yes"
    if re.search(r"keep-?alive status\s*:\s*peer is alive",out,re.I): facts["keepalive_ok"]="yes"
    return facts

def vpc_healthy(nx1:Nexus,nx2:Nexus)->Tuple[bool,str]:
    f1=parse_vpc_facts(nx1.run("show vpc"))
    f2=parse_vpc_facts(nx2.run("show vpc"))
    ok=(f1["domain"] and f2["domain"] and f1["domain"]==f2["domain"]
        and f1["peer_ok"]=="yes" and f2["peer_ok"]=="yes"
        and f1["keepalive_ok"]=="yes" and f2["keepalive_ok"]=="yes")
    if ok:
        return True, f"vPC OK (domain {f1['domain']}) {nx1.host}<->{nx2.host}"
    return False,(f"[vPC MISMATCH]\n"
                  f"{nx1.host}: domain={f1['domain']} peer_ok={f1['peer_ok']} keepalive_ok={f1['keepalive_ok']}\n"
                  f"{nx2.host}: domain={f2['domain']} peer_ok={f2['peer_ok']} keepalive_ok={f2['keepalive_ok']}")

# ----------------------- inventory/VLAN ----------------

def get_used_portchannels(n:Nexus)->Set[int]:
    out=n.run("show port-channel summary"); used=set()
    for line in out.splitlines():
        m=re.search(r"\bPo(\d{1,4})\b",line)
        if m: used.add(int(m.group(1)))
    return used

def get_used_vpc_ids_brief(n:Nexus)->Set[int]:
    out=n.run("show vpc brief"); used=set()
    for line in out.splitlines():
        m=re.match(r"\s*(\d+)\s+\S+",line)
        if m:
            try: used.add(int(m.group(1)))
            except: pass
    return used

def get_used_vpc_ids_show_vpc(n:Nexus)->Set[int]:
    out = n.run("show vpc")
    used=set(); in_tbl=False
    for line in out.splitlines():
        if not in_tbl and re.search(r"\bvPC-id\b", line, re.I):
            in_tbl=True; continue
        if in_tbl:
            if not line.strip(): in_tbl=False; continue
            m=re.match(r"\s*(\d{1,4})\s+", line)
            if m:
                try: used.add(int(m.group(1)))
                except: pass
    return used

def interface_is_in_pc(n:Nexus, iface:str)->Tuple[bool,str]:
    run1=n.run(f"show run interface {to_eth_canonical(iface)}")
    if re.search(r"channel-group\s+\d+\s+mode\s+\S+",run1,re.I): return True,"channel-group present"
    summ=n.run("show port-channel summary")
    if re.search(rf"\b{re.escape(norm_iface_for_match(iface))}\b", summ.replace("Ethernet","eth").lower()): return True,"in Po summary"
    return False,""

def interface_link_up(n:Nexus, iface:str)->bool:
    out=n.run(f"show interface {to_eth_canonical(iface)} status")
    for line in out.splitlines():
        if norm_iface_for_match(iface) in line.replace("Ethernet","eth").lower() and re.search(r"\bconnected\b",line,re.I):
            return True
    return False

def pick_next_id(used:Set[int], lo:int, hi:int)->int:
    for i in range(lo,hi+1):
        if i not in used: return i
    raise RuntimeError("No free Port-Channel/vPC IDs left in the specified range.")

def parse_vlan_list(cell:str)->List[int]:
    s=normalize_separators(cell or "")
    if not s: return []
    if ("," not in s) and ("-" not in s) and len(s)>4:
        nums=re.findall(r"\d{1,4}",s)
        return sorted({int(x) for x in nums if 1<=int(x)<=4094})
    out=set()
    for part in s.split(","):
        part=part.strip()
        if not part: continue
        if "-" in part:
            a,b=part.split("-",1)
            if a.isdigit() and b.isdigit():
                lo,hi=int(a),int(b)
                if 1<=lo<=4094 and 1<=hi<=4094 and lo<=hi: out.update(range(lo,hi+1))
        elif part.isdigit():
            v=int(part)
            if 1<=v<=4094: out.add(v)
    return sorted(out)

def _get_vlans_json(txt:str)->Set[int]:
    vl=set()
    try:
        data=json.loads(txt)
        rows=data.get("TABLE_vlanbriefxbrief",{}).get("ROW_vlanbriefxbrief",[])
        if isinstance(rows,dict): rows=[rows]
        for r in rows:
            vid=r.get("vlanshowbr-vlanid")
            if vid and str(vid).isdigit():
                v=int(vid)
                if 1<=v<=4094: vl.add(v)
    except: pass
    return vl

def _get_vlans_text(txt:str)->Set[int]:
    vl=set()
    for line in txt.splitlines():
        m=re.match(r"\s*(\d{1,4})\s+",line)
        if m:
            v=int(m.group(1))
            if 1<=v<=4094: vl.add(v)
    return vl

def get_existing_vlans(n:Nexus)->Set[int]:
    j=n.run("show vlan brief | json"); vl=_get_vlans_json(j)
    if not vl: vl=_get_vlans_text(n.run("show vlan brief"))
    return vl

def required_vlans_per_device(df:pd.DataFrame)->Dict[str,Set[int]]:
    per:Dict[str,Set[int]]={}
    for _,r in df.iterrows():
        dev=r["destination_device"].strip()
        st=r["switchport_type"].strip().lower()
        allowed=r["allowed_vlan"].strip()
        native=r["native_vlan"].strip()
        need=per.setdefault(dev,set())
        if st=="access":
            lst=parse_vlan_list(allowed)
            if lst: need.add(lst[0])
        elif st=="trunk":
            need.update(parse_vlan_list(allowed))
            nv=parse_vlan_list(native)
            if nv: need.add(nv[0])
    return per

# ----------------------- builders ---------------------

def build_access_physical(desc,vlan,mtu,pc_id):
    return [f"description {desc}","switchport","switchport host",
            f"switchport access vlan {vlan}",f"mtu {mtu}",
            f"channel-group {pc_id} mode active","no shutdown"]

def build_access_physical_no_pc(desc,vlan,mtu):
    return [f"description {desc}","switchport","switchport host",
            f"switchport access vlan {vlan}",f"mtu {mtu}","no shutdown"]

def build_access_po(desc_po,vlan,mtu,pc_id):
    return [f"description {desc_po}","switchport",f"switchport access vlan {vlan}",
            f"mtu {mtu}","spanning-tree port type edge",f"vpc {pc_id}","no shutdown"]

def build_trunk_physical(desc,allowed,native,mtu,pc_id):
    return [f"description {desc}","switchport","switchport mode trunk",
            f"switchport trunk native vlan {native}",f"switchport trunk allowed vlan {allowed}",
            "spanning-tree port type edge trunk",f"mtu {mtu}",
            f"channel-group {pc_id} mode active","no shutdown"]

def build_trunk_physical_no_pc(desc,allowed,native,mtu):
    return [f"description {desc}","switchport","switchport mode trunk",
            f"switchport trunk native vlan {native}",f"switchport trunk allowed vlan {allowed}",
            "spanning-tree port type edge trunk",f"mtu {mtu}","no shutdown"]

def build_trunk_po(desc_po,allowed,native,mtu,pc_id):
    return [f"description {desc_po}","switchport","switchport mode trunk",
            f"switchport trunk native vlan {native}",f"switchport trunk allowed vlan {allowed}",
            "spanning-tree port type edge trunk",f"mtu {mtu}",f"vpc {pc_id}","no shutdown"]

# ----------------------- backups ----------------------

def backup_interfaces_single_file(nx:Nexus, ifaces:List[str], outdir:Path):
    outdir.mkdir(parents=True, exist_ok=True)
    ts=now_stamp(); fname=outdir/f"{nx.host}_{ts}.txt"
    with open(fname,"w",encoding="utf-8") as f:
        for iface in sorted(set(ifaces), key=lambda x:x.lower()):
            eth=to_eth_canonical(iface)
            f.write(f"\n===== {nx.host} :: {eth} :: {ts} =====\n")
            try: cfg=nx.run(f"show run interface {eth}")
            except Exception as e: cfg=f"ERROR retrieving {eth} on {nx.host}: {e}"
            f.write(cfg.strip()+"\n")

# ----------------------- pairing helpers ----------------------

def _auto_bundle_key(row:pd.Series)->Tuple:
    """Key rows by attributes that should match across peers for a LAG."""
    return (
        row.get("source_device","").strip().lower(),
        row.get("switchport_type","").strip().lower(),
        normalize_separators(row.get("allowed_vlan","")),
        normalize_separators(row.get("native_vlan","")),
        row.get("mtu_value","").strip(),
        # destination_port intentionally NOT included, so non-identical ports can pair
    )

def pair_rows_one_per_peer(group_df: pd.DataFrame, peers: List[str]) -> List[Tuple[dict, dict]]:
    """
    Return list of (row_for_peer0_dict, row_for_peer1_dict) bundles.
    If lag_key present -> pair by lag_key; else pair by attribute key and sorted order.
    """
    p0, p1 = peers[0], peers[1]
    left = group_df[group_df["destination_device"].str.strip() == p0].copy()
    right = group_df[group_df["destination_device"].str.strip() == p1].copy()

    pairs = []

    # 1) If lag_key provided, pair by it
    if "lag_key" in group_df.columns and (left["lag_key"].str.strip().any() or right["lag_key"].str.strip().any()):
        # build maps by lag_key
        lmap = {}
        for _, r in left.iterrows():
            k = r["lag_key"].strip()
            lmap.setdefault(k, []).append(r)
        rmap = {}
        for _, r in right.iterrows():
            k = r["lag_key"].strip()
            rmap.setdefault(k, []).append(r)
        # for each key present on both sides, pair in order
        for k in sorted(set(lmap.keys()) & set(rmap.keys())):
            lrows = sorted(lmap[k], key=lambda rr: (rr["destination_port"], rr["source_port"]))
            rrows = sorted(rmap[k], key=lambda rr: (rr["destination_port"], rr["source_port"]))
            for lr, rr in zip(lrows, rrows):
                pairs.append((lr.to_dict(), rr.to_dict()))
        return pairs

    # 2) No lag_key -> group by attribute key and pair in order
    left["__k"]  = left.apply(_auto_bundle_key, axis=1)
    right["__k"] = right.apply(_auto_bundle_key, axis=1)

    for k in sorted(set(left["__k"]) & set(right["__k"])):
        lrows = left[left["__k"]==k].sort_values(by=["destination_port","source_port"])
        rrows = right[right["__k"]==k].sort_values(by=["destination_port","source_port"])
        for (_, lr), (_, rr) in zip(lrows.iterrows(), rrows.iterrows()):
            pairs.append((lr.to_dict(), rr.to_dict()))
    return pairs

# ----------------------- main -------------------------

def main():
    ap=argparse.ArgumentParser(description="Nexus vPC Port-Channel builder (multi-pair, robust ID checks, non-identical ports OK).")
    ap.add_argument("--excel", required=True)
    ap.add_argument("--id-min", type=int, default=ID_MIN_DEFAULT)
    ap.add_argument("--id-max", type=int, default=ID_MAX_DEFAULT)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--username", default=os.getenv("N9K_USER","admin"))
    ap.add_argument("--password", default=os.getenv("N9K_PASS","cisco"))
    ap.add_argument("--backup-dir", default="backups")
    args=ap.parse_args()

    df=load_plan(args.excel)
    devices=sorted(set(df["destination_device"].astype(str).str.strip()))
    pool=ConnPool(args.username,args.password)

    try:
        # connect + backups
        for dev in devices:
            nx=pool.get(dev)
            ports=[r["destination_port"] for _,r in df[df["destination_device"]==dev].iterrows()]
            backup_interfaces_single_file(nx, ports, Path(args.backup_dir))

        # VLAN precheck per device
        need_per=required_vlans_per_device(df)
        missing=False
        for dev,need in need_per.items():
            nx=pool.get(dev); have=get_existing_vlans(nx)
            miss=sorted(v for v in need if v not in have)
            if miss:
                print(f"[ERROR] VLANs missing on {dev}: {fmt_vlans(miss)}"); missing=True
        if missing:
            print("Please create missing VLANs and re-run."); return
        print("[PASS] VLAN precheck successful — all VLANs exist on each device.")

        # -------- vPC bundles (port-channel_required=yes) --------
        yes_df=df[df["port-channel_required"]=="yes"]
        if not yes_df.empty and any(yes_df["vpc_group"].str.strip()==""):
            print("[ERROR] Rows with port-channel_required='yes' must include vpc_group labels."); return

        # iterate groups
        for grp,ggrp in yes_df.groupby("vpc_group"):
            peers=sorted(set(ggrp["destination_device"].str.strip()))
            if len(peers)!=2:
                print(f"[ERROR] vpc_group '{grp}' must reference exactly TWO devices, got: {peers}. Skipping.")
                continue

            nx1=pool.get(peers[0]); nx2=pool.get(peers[1])
            ok,msg=vpc_healthy(nx1,nx2)
            if not ok:
                print(f"[ERROR] {msg}\n[SKIP] Group '{grp}' will not be configured.")
                continue
            else:
                print(f"[CHECK] {msg}")

            # union used IDs on both peers
            used = (
                get_used_portchannels(nx1) | get_used_portchannels(nx2) |
                get_used_vpc_ids_brief(nx1) | get_used_vpc_ids_brief(nx2) |
                get_used_vpc_ids_show_vpc(nx1) | get_used_vpc_ids_show_vpc(nx2)
            )

            # Pair rows one-per-peer (non-identical ports allowed)
            bundles = pair_rows_one_per_peer(ggrp, peers)

            if not bundles:
                print(f"[INFO] Group '{grp}': no pairable rows found (check lag_key or attributes).")
                continue

            for left_row, right_row in tqdm(bundles, desc=f"Group {grp}: vPC bundles"):
                sw_type = (left_row["switchport_type"] or "").strip().lower()
                allowed = (left_row["allowed_vlan"] or "").strip()
                native  = (left_row["native_vlan"]  or "").strip()
                mtu     = (left_row["mtu_value"]    or "").strip()

                if not mtu.isdigit():
                    print(f"[SKIP] Invalid mtu '{mtu}' for bundle in {grp}."); continue

                iface1=to_eth_canonical(left_row["destination_port"])
                iface2=to_eth_canonical(right_row["destination_port"])

                # Safety prechecks per interface
                in1,why1=interface_is_in_pc(nx1,iface1); in2,why2=interface_is_in_pc(nx2,iface2)
                if in1: print(f"[SKIP] {nx1.host} {iface1}: already in Po ({why1})."); continue
                if in2: print(f"[SKIP] {nx2.host} {iface2}: already in Po ({why2})."); continue
                if interface_link_up(nx1,iface1):
                    print(f"[SKIP] {nx1.host} {iface1}: link connected; won't modify."); continue
                if interface_link_up(nx2,iface2):
                    print(f"[SKIP] {nx2.host} {iface2}: link connected; won't modify."); continue

                # Allocate a free Po/vPC ID common to both peers
                try: pc_id=pick_next_id(used, args.id_min, args.id_max)
                except RuntimeError as e: print(f"[ERROR] {grp}: {e}"); break
                used.add(pc_id)

                desc1=f"## {left_row['source_device']}  {left_row['source_port']} ##"
                desc2=f"## {right_row['source_device']}  {right_row['source_port']} ##"
                desc_po=f"## {left_row['source_device']} LACP ##"

                if sw_type=="access":
                    vl=parse_vlan_list(allowed)
                    if not vl: print(f"[SKIP] No valid access VLAN in '{allowed}' for group {grp}."); continue
                    vstr=str(vl[0])
                    cfg_po=[f"interface port-channel {pc_id}"]+build_access_po(desc_po,vstr,mtu,pc_id)
                    cfg_1=[f"interface {iface1}"]+build_access_physical(desc1,vstr,mtu,pc_id)
                    cfg_2=[f"interface {iface2}"]+build_access_physical(desc2,vstr,mtu,pc_id)
                elif sw_type=="trunk":
                    nv=parse_vlan_list(native); native_vlan=str(nv[0]) if nv else "1"
                    allowed_exact=",".join(str(v) for v in parse_vlan_list(allowed))
                    cfg_po=[f"interface port-channel {pc_id}"]+build_trunk_po(desc_po,allowed_exact,native_vlan,mtu,pc_id)
                    cfg_1=[f"interface {iface1}"]+build_trunk_physical(desc1,allowed_exact,native_vlan,mtu,pc_id)
                    cfg_2=[f"interface {iface2}"]+build_trunk_physical(desc2,allowed_exact,native_vlan,mtu,pc_id)
                else:
                    print(f"[SKIP] Unknown switchport_type '{sw_type}'."); continue

                print(f"[PLAN] (Group {grp}) vPC/Po{pc_id}: {nx1.host}:{iface1} <-> {nx2.host}:{iface2} ({sw_type})")
                if args.dry_run:
                    print(f"--- {nx1.host} CONFIG ---"); print("\n".join(cfg_po+cfg_1))
                    print(f"--- {nx2.host} CONFIG ---"); print("\n".join(cfg_po+cfg_2))
                else:
                    nx1.run_cfg(cfg_po); nx2.run_cfg(cfg_po)
                    nx1.run_cfg(cfg_1);  nx2.run_cfg(cfg_2)
                    print(f"[OK] Group {grp}: configured Po{pc_id}/vPC {pc_id}.")

        # -------- single-interface (no port-channel) --------
        no_df=df[df["port-channel_required"]=="no"]
        for _,r in tqdm(no_df.iterrows(), total=len(no_df), desc="Single interfaces (no PC)"):
            dev=r["destination_device"].strip(); nx=pool.get(dev)
            iface=to_eth_canonical(r["destination_port"])
            sw=(r["switchport_type"] or "").strip().lower()
            allowed=(r["allowed_vlan"] or "").strip()
            native=(r["native_vlan"] or "").strip()
            mtu=(r["mtu_value"] or "").strip()
            src_dev=(r["source_device"] or "").strip()
            src_port=(r["source_port"] or "").strip()

            if not mtu.isdigit(): print(f"[SKIP] Invalid mtu '{mtu}' for {dev}/{iface}."); continue
            inpc,why=interface_is_in_pc(nx,iface)
            if inpc: print(f"[SKIP] {dev} {iface}: already in Po ({why})."); continue
            if interface_link_up(nx,iface):
                print(f"[SKIP] {dev} {iface}: link connected; won't modify."); continue

            desc=f"## {src_dev}  {src_port} ##"
            if sw=="access":
                lst=parse_vlan_list(allowed)
                if not lst: print(f"[SKIP] No valid access VLAN in '{allowed}' for {dev}/{iface}."); continue
                cfg=[f"interface {iface}"]+build_access_physical_no_pc(desc,str(lst[0]),mtu)
            elif sw=="trunk":
                nv=parse_vlan_list(native); native_vlan=str(nv[0]) if nv else "1"
                allowed_exact=",".join(str(v) for v in parse_vlan_list(allowed))
                cfg=[f"interface {iface}"]+build_trunk_physical_no_pc(desc,allowed_exact,native_vlan,mtu)
            else:
                print(f"[SKIP] Unknown switchport_type '{sw}'."); continue

            print(f"[PLAN] (NO-PC) {dev}:{iface} ({sw})")
            if args.dry_run:
                print(f"--- {dev} CONFIG ---"); print("\n".join(cfg))
            else:
                nx.run_cfg(cfg); print(f"[OK] Configured {dev} {iface} (no PC).")

        print("[DONE] All rows processed.")
    finally:
        pool.close_all()

if __name__=="__main__":
    main()
