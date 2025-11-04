#!/usr/bin/env python3
# Nexus Port-Channel/vPC builder (short version)
# - Groups by (vpc_group, port_group)
# - vpc_required: yes → Po+vPC (same ID), no → local Po
# - switchport_type auto: tr_* = trunk, ac_* = access
# - Members can differ per peer (e.g., A:E1/29 + B:E1/30)

import argparse, json, re, time, pandas as pd
from typing import List, Set, Dict
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

# ---------- tiny helpers ----------
def ts(): return time.strftime("%Y%m%d-%H%M%S")
def norm(s): return s.strip().lower() if isinstance(s,str) else ""
def eth(s): m=re.search(r"(\d+/\d+)", str(s)); return f"Ethernet{m.group(1)}" if m else str(s)
def as_ints(vs: List[int]): return ",".join(str(v) for v in sorted(set(vs)))

def parse_vlans(s: str) -> List[int]:
    s = re.sub(r"[^\d,\-]", "", str(s or ""))
    out = set()
    for p in s.split(","):
        p = p.strip()
        if not p: continue
        if "-" in p:
            a,b = p.split("-",1)
            if a.isdigit() and b.isdigit(): out.update(range(int(a), int(b)+1))
        elif p.isdigit(): out.add(int(p))
    return sorted(v for v in out if 1 <= v <= 4094)

# ---------- device ----------
class NX:
    def __init__(self, host, user, pwd): self.h=host; self.u=user; self.p=pwd; self.c=None
    def connect(self): self.c=ConnectHandler(device_type="cisco_nxos", host=self.h, username=self.u, password=self.p, fast_cli=False)
    def cmd(self, x): return self.c.send_command(x, expect_string=r"#", use_textfsm=False)
    def cfg(self, lines: List[str]): return self.c.send_config_set(lines)
    def close(self): 
        try: self.c.disconnect()
        except: pass

# ---------- inventory/checks ----------
def used_po(n:NX) -> Set[int]:
    s=n.cmd("show port-channel summary"); out=set()
    for l in s.splitlines():
        m=re.search(r"\bPo(\d{1,4})\b", l)
        if m: out.add(int(m.group(1)))
    return out

def used_vpc(n:NX) -> Set[int]:
    out=set()
    s=n.cmd("show vpc brief")
    for l in s.splitlines():
        m=re.match(r"\s*(\d{1,4})\s+", l)
        if m: out.add(int(m.group(1)))
    s=n.cmd("show vpc")
    in_tbl=False
    for l in s.splitlines():
        if not in_tbl and re.search(r"\bvPC-id\b", l, re.I): in_tbl=True; continue
        if in_tbl and not l.strip(): in_tbl=False
        elif in_tbl:
            m=re.match(r"\s*(\d{1,4})\s+", l)
            if m: out.add(int(m.group(1)))
    return out

def pick_id(used:Set[int], lo:int, hi:int)->int:
    for i in range(lo, hi+1):
        if i not in used: return i
    raise RuntimeError("No free Po/vPC IDs in range")

def get_vlans(n:NX)->Set[int]:
    try:
        j=json.loads(n.cmd("show vlan brief | json"))
        rows=j["TABLE_vlanbriefxbrief"]["ROW_vlanbriefxbrief"]
        if isinstance(rows, dict): rows=[rows]
        return {int(r["vlanshowbr-vlanid"]) for r in rows if str(r.get("vlanshowbr-vlanid","")).isdigit()}
    except: pass
    out=set()
    for l in n.cmd("show vlan brief").splitlines():
        m=re.match(r"\s*(\d{1,4})\s+", l)
        if m: out.add(int(m.group(1)))
    return out

def iface_in_po(n:NX, iface:str)->bool:
    if re.search(r"channel-group\s+\d+\s+mode\s+\S+", n.cmd(f"show run interface {eth(iface)}"), re.I): return True
    return norm(iface) in n.cmd("show port-channel summary").lower().replace("ethernet","eth")

def iface_up(n:NX, iface:str)->bool:
    s=n.cmd(f"show interface {eth(iface)} status").lower().replace("ethernet","eth")
    return (norm(iface) in s) and ("connected" in s)

def vpc_ok(a:NX,b:NX)->bool:
    def f(n:NX):
        t=n.cmd("show vpc")
        dom=re.search(r"domain id\s*:\s*(\d+)",t,re.I)
        return (dom.group(1) if dom else "", "peer adjacency formed ok" in t, "peer is alive" in t)
    d1,p1,k1=f(a); d2,p2,k2=f(b)
    return d1 and d1==d2 and p1 and p2 and k1 and k2

# ---------- builders ----------
def build_trunk_member(desc, allowed, native, mtu, po):
    return [f"description {desc}","switchport","switchport mode trunk",
            f"switchport trunk native vlan {native}",
            f"switchport trunk allowed vlan {allowed}",
            "spanning-tree port type edge trunk", f"mtu {mtu}",
            f"channel-group {po} mode active","no shut"]

def build_trunk_po(desc, allowed, native, mtu, po, add_vpc:bool):
    cfg=[f"description {desc}","switchport","switchport mode trunk",
         f"switchport trunk native vlan {native}",
         f"switchport trunk allowed vlan {allowed}",
         "spanning-tree port type edge trunk", f"mtu {mtu}"]
    if add_vpc: cfg.append(f"vpc {po}")
    cfg.append("no shut"); return cfg

def build_access_member(desc, vlan, mtu, po):
    return [f"description {desc}","switchport","switchport host",
            f"switchport access vlan {vlan}", f"mtu {mtu}",
            f"channel-group {po} mode active","no shut"]

def build_access_po(desc, vlan, mtu, po, add_vpc:bool):
    cfg=[f"description {desc}","switchport", f"switchport access vlan {vlan}",
         f"mtu {mtu}","spanning-tree port type edge"]
    if add_vpc: cfg.append(f"vpc {po}")
    cfg.append("no shut"); return cfg

# ---------- main ----------
def main():
    ap=argparse.ArgumentParser(description="Nexus Port-Channel/vPC builder (vpc_required aware)")
    ap.add_argument("--excel", required=True)
    ap.add_argument("--username", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--id-min", type=int, default=1)
    ap.add_argument("--id-max", type=int, default=100)
    ap.add_argument("--dry-run", action="store_true")
    args=ap.parse_args()

    df = pd.read_excel(args.excel, dtype=str).fillna("")
    need = {"source_device","source_port","allowed_vlan","native_vlan","destination_device",
            "destination_port","mtu_value","port-channel_required","vpc_group","port_group","vpc_required"}
    miss = need - set(df.columns)
    if miss: raise SystemExit(f"Missing columns: {sorted(miss)}")

    # infer type from port_group prefix
    def infer(pg): 
        pg=norm(pg); 
        return "trunk" if pg.startswith("tr_") else ("access" if pg.startswith("ac_") else "")
    df["switchport_type"] = df["port_group"].apply(infer)

    # connect devices
    devs = sorted(df["destination_device"].unique())
    conns: Dict[str,NX] = {}
    for d in devs:
        nx = NX(d, args.username, args.password)
        try: nx.connect()
        except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
            raise SystemExit(f"Cannot connect {d}: {e}")
        conns[d]=nx

    try:
        # VLAN precheck per device
        print("[CHECK] VLANs…")
        want: Dict[str,Set[int]] = {}
        for _,r in df.iterrows():
            dev=r["destination_device"]
            want.setdefault(dev,set()).update(parse_vlans(r["allowed_vlan"]))
            want.setdefault(dev,set()).update(parse_vlans(r["native_vlan"]))
        for dev,need in want.items():
            miss = sorted(set(need) - get_vlans(conns[dev]))
            if miss: raise SystemExit(f"[ERROR] Missing VLANs on {dev}: {', '.join(map(str,miss))}")
        print("[PASS] VLANs verified.\n")

        # process: group by (vpc_group, port_group)
        for (vg, pg), sub in df.groupby(["vpc_group","port_group"]):
            peers = sorted(set(sub["destination_device"]))
            swt = sub["switchport_type"].iloc[0].lower()
            vpc_req = any(norm(x) in ("yes","y","true","1") for x in sub["vpc_required"])
            mtu = sub["mtu_value"].iloc[0]
            allowed = as_ints([v for s in sub["allowed_vlan"] for v in parse_vlans(s)])
            native_list = [v for s in sub["native_vlan"] for v in parse_vlans(s)]
            native = str(native_list[0]) if native_list else ("1" if swt=="trunk" else "")

            if vpc_req and len(peers)==2:
                a,b = conns[peers[0]], conns[peers[1]]
                if not vpc_ok(a,b):
                    print(f"[SKIP] {vg}/{pg}: vPC not healthy; skipping vPC build.")
                    continue
                used = used_po(a)|used_po(b)|used_vpc(a)|used_vpc(b)
                try: po = pick_id(used, args.id_min, args.id_max)
                except RuntimeError as e: print(f"[ERROR] {vg}/{pg}: {e}"); continue
                # members on each peer
                for dev, side in sub.groupby("destination_device"):
                    nx = conns[dev]
                    for _,r in side.iterrows():
                        iface = eth(r["destination_port"])
                        if iface_in_po(nx, iface) or iface_up(nx, iface):
                            print(f"[SKIP] {dev} {iface}: already in Po or link up.")
                            continue
                        desc = f"## {r['source_device']} {r['source_port']} ##"
                        cfg = ([f"interface {iface}"] + 
                               (build_trunk_member(desc, allowed, native, mtu, po) if swt=="trunk"
                                else build_access_member(desc, str(parse_vlans(r['allowed_vlan'])[0]), mtu, po)))
                        if args.dry_run: print(f"--- {dev} {iface} ---\n" + "\n".join(cfg))
                        else: nx.cfg(cfg)
                # Po with vpc on both
                desc_po = f"## {sub['source_device'].iloc[0]} LACP ##"
                po_cfg = [f"interface port-channel {po}"] + (
                    build_trunk_po(desc_po, allowed, native, mtu, po, add_vpc=True) if swt=="trunk"
                    else build_access_po(desc_po, str(parse_vlans(sub.iloc[0]['allowed_vlan'])[0]), mtu, po, add_vpc=True)
                )
                if args.dry_run:
                    print(f"--- {a.h}+{b.h} Po{po} ---\n" + "\n".join(po_cfg))
                else:
                    a.cfg(po_cfg); b.cfg(po_cfg); print(f"[OK] vPC {vg}/{pg}: Po{po}/vPC {po}")
                continue

            # LOCAL Po (either vpc_required=no, or only one device present)
            for dev, side in sub.groupby("destination_device"):
                nx = conns[dev]
                used = used_po(nx) | used_vpc(nx)  # keep Po/vPC IDs unique locally
                try: po = pick_id(used, args.id_min, args.id_max)
                except RuntimeError as e: print(f"[ERROR] {vg}/{pg}@{dev}: {e}"); continue
                for _,r in side.iterrows():
                    iface = eth(r["destination_port"])
                    if iface_in_po(nx, iface) or iface_up(nx, iface):
                        print(f"[SKIP] {dev} {iface}: already in Po or link up."); continue
                    desc = f"## {r['source_device']} {r['source_port']} ##"
                    cfg = ([f"interface {iface}"] +
                           (build_trunk_member(desc, allowed, native, mtu, po) if swt=="trunk"
                            else build_access_member(desc, str(parse_vlans(r['allowed_vlan'])[0]), mtu, po)))
                    if args.dry_run: print(f"--- {dev} {iface} ---\n" + "\n".join(cfg))
                    else: nx.cfg(cfg)
                # Po interface (no vpc)
                desc_po = f"## {side['source_device'].iloc[0]} LACP ##"
                po_cfg = [f"interface port-channel {po}"] + (
                    build_trunk_po(desc_po, allowed, native, mtu, po, add_vpc=False) if swt=="trunk"
                    else build_access_po(desc_po, str(parse_vlans(side.iloc[0]['allowed_vlan'])[0]), mtu, po, add_vpc=False)
                )
                if args.dry_run: print(f"--- {dev} Po{po} ---\n" + "\n".join(po_cfg))
                else: nx.cfg(po_cfg); print(f"[OK] LOCAL {vg}/{pg}@{dev}: Po{po}")

        print("\n[DONE] All groups processed.")
    finally:
        for n in conns.values(): n.close()

if __name__=="__main__":
    main()
