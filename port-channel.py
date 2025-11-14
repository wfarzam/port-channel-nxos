#!/usr/bin/env python3
# Nexus Port-Channel / vPC builder (no-orphan Po/vPC, strict flags)

import argparse, json, re, time
from typing import Dict, List, Optional, Set, Tuple
import pandas as pd
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

# ----------------- helpers -----------------
def norm(s: Optional[str]) -> str:
    return s.strip().lower() if isinstance(s, str) else ""

def eth(s: str) -> str:
    m = re.search(r"(\d+/\d+)", str(s))
    return f"Ethernet{m.group(1)}" if m else str(s)

def parse_vlans(cell: Optional[str]) -> List[int]:
    s = re.sub(r"[^\d,\-]", "", str(cell or ""))
    out: Set[int] = set()
    for p in s.split(","):
        p = p.strip()
        if not p:
            continue
        if "-" in p:
            a, b = p.split("-", 1)
            if a.isdigit() and b.isdigit():
                lo, hi = int(a), int(b)
                if 1 <= lo <= 4094 and 1 <= hi <= 4094 and lo <= hi:
                    out.update(range(lo, hi + 1))
        elif p.isdigit():
            v = int(p)
            if 1 <= v <= 4094:
                out.add(v)
    return sorted(out)

def first_vlan(cell: Optional[str]) -> Optional[str]:
    lst = parse_vlans(cell)
    return str(lst[0]) if lst else None

def join_vlans(vs: List[int]) -> str:
    return ",".join(str(v) for v in sorted(set(vs)))

# ----------------- device -----------------
class NX:
    def __init__(self, host, user, pwd):
        self.h = host; self.u = user; self.p = pwd; self.c = None
    def connect(self):
        self.c = ConnectHandler(device_type="cisco_nxos", host=self.h, username=self.u, password=self.p, fast_cli=False)
    def cmd(self, x): return self.c.send_command(x, expect_string=r"#", use_textfsm=False)
    def cfg(self, lines: List[str]): return self.c.send_config_set(lines)
    def close(self):
        try: self.c.disconnect()
        except: pass

def ensure_features(nx: NX):
    try:
        feat = nx.cmd("show feature").lower()
        todo = []
        if " lacp " not in feat or "enabled" not in feat: todo.append("feature lacp")
        if " vpc "  not in feat or "enabled" not in feat: todo.append("feature vpc")
        if todo: nx.cfg(todo)
    except: pass

def get_vlans(nx: NX) -> Set[int]:
    try:
        j = json.loads(nx.cmd("show vlan brief | json"))
        rows = j["TABLE_vlanbriefxbrief"]["ROW_vlanbriefxbrief"]
        rows = [rows] if isinstance(rows, dict) else rows
        return {int(r["vlanshowbr-vlanid"]) for r in rows if str(r.get("vlanshowbr-vlanid","")).isdigit()}
    except:
        out = set()
        for l in nx.cmd("show vlan brief").splitlines():
            m = re.match(r"\s*(\d{1,4})\s+", l)
            if m: out.add(int(m.group(1)))
        return out

def iface_in_po(nx: NX, iface: str) -> bool:
    if re.search(r"channel-group\s+\d+\s+mode\s+\S+", nx.cmd(f"show run interface {eth(iface)}"), re.I):
        return True
    return norm(iface) in nx.cmd("show port-channel summary").lower().replace("ethernet", "eth")

def iface_up(nx: NX, iface: str) -> bool:
    s = nx.cmd(f"show interface {eth(iface)} status").lower().replace("ethernet", "eth")
    return (norm(iface) in s) and ("connected" in s)

def used_po(nx: NX) -> Set[int]:
    out = nx.cmd("show port-channel summary"); s = set()
    for l in out.splitlines():
        m = re.search(r"\bPo(\d{1,4})\b", l)
        if m: s.add(int(m.group(1)))
    return s

def used_vpc(nx: NX) -> Set[int]:
    s = set()
    t = nx.cmd("show vpc brief")
    for l in t.splitlines():
        m = re.match(r"\s*(\d{1,4})\s+", l)
        if m: s.add(int(m.group(1)))
    t2 = nx.cmd("show vpc"); in_tbl = False
    for l in t2.splitlines():
        if not in_tbl and re.search(r"\bvPC-id\b", l, re.I): in_tbl = True; continue
        if in_tbl and not l.strip(): in_tbl = False
        elif in_tbl:
            m = re.match(r"\s*(\d{1,4})\s+", l)
            if m: s.add(int(m.group(1)))
    return s

def vpc_ok(a: NX, b: NX) -> bool:
    def f(n: NX):
        t = n.cmd("show vpc")
        dom = re.search(r"domain id\s*:\s*(\d+)", t, re.I)
        return (dom.group(1) if dom else "", "peer adjacency formed ok" in t, "peer is alive" in t)
    d1, p1, k1 = f(a); d2, p2, k2 = f(b)
    return d1 and d1 == d2 and p1 and p2 and k1 and k2

def pick_id(used: Set[int], lo: int, hi: int) -> int:
    for i in range(lo, hi + 1):
        if i not in used: return i
    raise RuntimeError("No free Po/vPC IDs")

# ----------------- build blocks -----------------
def build_trunk_member(desc, allowed, native_opt, mtu, po):
    cfg = [f"description {desc}", "switchport", "switchport mode trunk"]
    if native_opt: cfg.append(f"switchport trunk native vlan {native_opt}")
    cfg += [f"switchport trunk allowed vlan {allowed}",
            "spanning-tree port type edge trunk", f"mtu {mtu}",
            f"channel-group {po} mode active", "no shut"]
    return cfg

def build_trunk_po(desc, allowed, native_opt, mtu, po, add_vpc: bool):
    cfg = [f"description {desc}", "switchport", "switchport mode trunk"]
    if native_opt: cfg.append(f"switchport trunk native vlan {native_opt}")
    cfg += [f"switchport trunk allowed vlan {allowed}",
            "spanning-tree port type edge trunk", f"mtu {mtu}"]
    if add_vpc: cfg.append(f"vpc {po}")
    cfg.append("no shut")
    return cfg

def build_access_member(desc, vlan, mtu, po):
    return [f"description {desc}", "switchport", "switchport host",
            f"switchport access vlan {vlan}", f"mtu {mtu}",
            f"channel-group {po} mode active", "no shut"]

def build_access_po(desc, vlan, mtu, po, add_vpc: bool):
    cfg = [f"description {desc}", "switchport",
           f"switchport access vlan {vlan}", f"mtu {mtu}",
           "spanning-tree port type edge"]
    if add_vpc: cfg.append(f"vpc {po}")
    cfg.append("no shut")
    return cfg

def build_trunk_single(desc, allowed, native_opt, mtu):
    cfg = [f"description {desc}", "switchport", "switchport mode trunk"]
    if native_opt: cfg.append(f"switchport trunk native vlan {native_opt}")
    cfg += [f"switchport trunk allowed vlan {allowed}",
            "spanning-tree port type edge trunk", f"mtu {mtu}", "no shut"]
    return cfg

def build_access_single(desc, vlan, mtu):
    return [f"description {desc}", "switchport", "switchport host",
            f"switchport access vlan {vlan}", f"mtu {mtu}", "no shut"]

# Only consider members we will actually configure now
def collect_members_to_config(side_df: pd.DataFrame, nx: NX, swt: str):
    todo = []
    for _, r in side_df.iterrows():
        iface = eth(r["destination_port"])
        if iface_in_po(nx, iface) or iface_up(nx, iface):
            continue
        if swt == "access" and not first_vlan(r["allowed_vlan"]):
            continue
        todo.append((iface, r))
    return todo

# ----------------- main -----------------
def main():
    ap = argparse.ArgumentParser(description="Nexus Po/vPC builder (no-orphan Po/vPC)")
    ap.add_argument("--excel", required=True)
    ap.add_argument("--username", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--id-min", type=int, default=1)
    ap.add_argument("--id-max", type=int, default=100)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    df = pd.read_excel(args.excel, dtype=str).fillna("")
    need = {"source_device","source_port","switchport_type","allowed_vlan","native_vlan",
            "destination_device","destination_port","mtu_value",
            "port-channel_required","vpc_required","vpc_group","port_group"}
    miss = need - set(df.columns)
    if miss: raise SystemExit(f"Missing columns: {sorted(miss)}")

    # connect switches
    devices = sorted(set(df["destination_device"]))
    conns: Dict[str, NX] = {}
    for d in devices:
        nx = NX(d, args.username, args.password)
        try: nx.connect()
        except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
            raise SystemExit(f"Cannot connect {d}: {e}")
        ensure_features(nx)
        conns[d] = nx

    try:
        # VLAN precheck for rows we might touch
        need_per: Dict[str, Set[int]] = {}
        for _, r in df.iterrows():
            dev = r["destination_device"]; t = norm(r["switchport_type"])
            if t == "trunk":
                need_per.setdefault(dev, set()).update(parse_vlans(r["allowed_vlan"]))
                need_per.setdefault(dev, set()).update(parse_vlans(r["native_vlan"]))
            elif t == "access":
                v = first_vlan(r["allowed_vlan"])
                if v: need_per.setdefault(dev, set()).add(int(v))
        for dev, needv in need_per.items():
            have = get_vlans(conns[dev])
            missv = sorted(set(needv) - have)
            if missv: raise SystemExit(f"[ERROR] Missing VLANs on {dev}: {', '.join(map(str, missv))}")
        print("[PASS] VLANs verified.\n")

        # 1) Port-Channel path (only pc=yes)
        pc_df = df[df["port-channel_required"].str.lower().isin(["yes","y","true","1"])]
        if not pc_df.empty and any(pc_df["port_group"].str.strip() == ""):
            raise SystemExit("[ERROR] Rows with port-channel_required=yes must have port_group set.")

        for (vg, pg), sub in pc_df.groupby(["vpc_group","port_group"]):
            peers = sorted(set(sub["destination_device"]))
            swt = norm(sub["switchport_type"].iloc[0])
            mtu = sub["mtu_value"].iloc[0]
            vpc_req = any(sub["vpc_required"].str.lower().isin(["yes","y","true","1"]))

            # normalize VLANs
            if swt == "trunk":
                allowed = join_vlans([v for s in sub["allowed_vlan"] for v in parse_vlans(s)])
                if not allowed:
                    print(f"[SKIP] {vg}/{pg}: trunk group missing allowed_vlan."); continue
                native_list = [v for s in sub["native_vlan"] for v in parse_vlans(s)]
                native_opt = str(native_list[0]) if native_list else ""   # omit if empty
            elif swt == "access":
                allowed = ""; native_opt = ""
            else:
                print(f"[SKIP] {vg}/{pg}: unknown switchport_type '{swt}'."); continue

            if vpc_req:
                if len(peers) != 2:
                    print(f"[SKIP] {vg}/{pg}: vpc_required=yes but only {len(peers)} device(s) present.")
                    continue
                a, b = conns[peers[0]], conns[peers[1]]
                if not vpc_ok(a, b):
                    print(f"[SKIP] {vg}/{pg}: vPC not healthy."); continue

                # decide eligible members first
                todo_a = collect_members_to_config(sub[sub["destination_device"] == peers[0]], a, swt)
                todo_b = collect_members_to_config(sub[sub["destination_device"] == peers[1]], b, swt)
                total_todo = len(todo_a) + len(todo_b)
                if total_todo == 0:
                    print(f"[SKIP] {vg}/{pg}: no eligible member interfaces; not creating Po/vPC.")
                    continue

                used = used_po(a) | used_po(b) | used_vpc(a) | used_vpc(b)
                try: po = pick_id(used, args.id_min, args.id_max)
                except RuntimeError as e: print(f"[ERROR] {vg}/{pg}: {e}"); continue

                # Po first (with vpc)
                desc_po = f"## {sub['source_device'].iloc[0]} LACP ##"
                if swt == "trunk":
                    po_cfg = [f"interface port-channel {po}"] + build_trunk_po(desc_po, allowed, native_opt, mtu, po, add_vpc=True)
                else:
                    vpo = None
                    for _, r in sub.iterrows():
                        vpo = first_vlan(r["allowed_vlan"])
                        if vpo: break
                    if not vpo:
                        print(f"[SKIP] {vg}/{pg}: access group missing allowed_vlan."); continue
                    po_cfg = [f"interface port-channel {po}"] + build_access_po(desc_po, vpo, mtu, po, add_vpc=True)

                if args.dry_run:
                    print(f"--- {a.h}+{b.h} Po{po} (Po-first) ---\n" + "\n".join(po_cfg))
                else:
                    a.cfg(po_cfg); b.cfg(po_cfg)

                # push only eligible members
                for (iface, r) in todo_a:
                    desc = f"## {r['source_device']} {r['source_port']} ##"
                    cfg = ([f"interface {iface}"] +
                           (build_trunk_member(desc, allowed, native_opt, mtu, po) if swt == "trunk"
                            else build_access_member(desc, first_vlan(r["allowed_vlan"]), mtu, po)))
                    if args.dry_run: print(f"--- {a.h} {iface} ---\n" + "\n".join(cfg))
                    else: a.cfg(cfg)

                for (iface, r) in todo_b:
                    desc = f"## {r['source_device']} {r['source_port']} ##"
                    cfg = ([f"interface {iface}"] +
                           (build_trunk_member(desc, allowed, native_opt, mtu, po) if swt == "trunk"
                            else build_access_member(desc, first_vlan(r["allowed_vlan"]), mtu, po)))
                    if args.dry_run: print(f"--- {b.h} {iface} ---\n" + "\n".join(cfg))
                    else: b.cfg(cfg)

                print(f"[OK] vPC {vg}/{pg}: Po{po}/vPC {po} configured with {total_todo} new member(s).")
                continue

            # Local Po (no vpc) per device
            for dev, side in sub.groupby("destination_device"):
                nx = conns[dev]
                todo = collect_members_to_config(side, nx, swt)
                if len(todo) == 0:
                    print(f"[SKIP] {vg}/{pg}@{dev}: no eligible member interfaces; not creating Po.")
                    continue

                used_local = used_po(nx) | used_vpc(nx)
                try: po = pick_id(used_local, args.id_min, args.id_max)
                except RuntimeError as e: print(f"[ERROR] {vg}/{pg}@{dev}: {e}"); continue

                for (iface, r) in todo:
                    desc = f"## {r['source_device']} {r['source_port']} ##"
                    if swt == "trunk":
                        cfg = [f"interface {iface}"] + build_trunk_member(desc, allowed, native_opt, mtu, po)
                    else:
                        v1 = first_vlan(r["allowed_vlan"])
                        cfg = [f"interface {iface}"] + build_access_member(desc, v1, mtu, po)
                    if args.dry_run: print(f"--- {dev} {iface} ---\n" + "\n".join(cfg))
                    else: nx.cfg(cfg)

                desc_po = f"## {side['source_device'].iloc[0]} LACP ##"
                if swt == "trunk":
                    po_cfg = [f"interface port-channel {po}"] + build_trunk_po(desc_po, allowed, native_opt, mtu, po, add_vpc=False)
                else:
                    vpo = first_vlan(side.iloc[0]["allowed_vlan"])
                    po_cfg = [f"interface port-channel {po}"] + build_access_po(desc_po, vpo, mtu, po, add_vpc=False)

                if args.dry_run: print(f"--- {dev} Po{po} (LOCAL) ---\n" + "\n".join(po_cfg))
                else: nx.cfg(po_cfg); print(f"[OK] LOCAL {vg}/{pg}@{dev}: Po{po} configured with {len(todo)} new member(s).")

        # 2) Single-interface path (pc==no) — no Po, no channel-group
        si_df = df[df["port-channel_required"].str.lower().isin(["no","n","false","0",""])]
        for _, r in si_df.iterrows():
            dev = r["destination_device"]; nx = conns[dev]
            swt = norm(r["switchport_type"]); iface = eth(r["destination_port"]); mtu = r["mtu_value"].strip()
            desc = f"## {r['source_device']} {r['source_port']} ##"
            if iface_in_po(nx, iface):
                print(f"[SKIP] {dev} {iface}: already in a Port-Channel."); continue
            if swt == "trunk":
                allowed = join_vlans(parse_vlans(r["allowed_vlan"]))
                if not allowed: print(f"[SKIP] {dev} {iface}: trunk missing allowed_vlan."); continue
                native_opt = first_vlan(r["native_vlan"])  # may be None
                cfg = [f"interface {iface}"] + build_trunk_single(desc, allowed, native_opt, mtu)
            elif swt == "access":
                v1 = first_vlan(r["allowed_vlan"])
                if not v1: print(f"[SKIP] {dev} {iface}: access missing allowed_vlan."); continue
                cfg = [f"interface {iface}"] + build_access_single(desc, v1, mtu)
            else:
                print(f"[SKIP] {dev} {iface}: unknown switchport_type '{r['switchport_type']}'."); continue
            if args.dry_run: print(f"--- {dev} {iface} (NO-PC) ---\n" + "\n".join(cfg))
            else: nx.cfg(cfg); print(f"[OK] {dev} {iface} configured (no Po).")

        print("\n[DONE] All rows processed.")
    finally:
        for n in conns.values(): n.close()

if __name__ == "__main__":
    main()
