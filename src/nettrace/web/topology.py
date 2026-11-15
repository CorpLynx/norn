"""Topology for the web UI and the mapping of trace hops onto it.

A topology is plain JSON: groups (nested boxes), nodes (with match keys) and links.
Node match keys used to place hops:
  devices: inventory device names (and "prisma-access")
  ids:     AWS resource ids (ENIs, TGW / route tables / attachments, IGWs)
  vpcs:    VPC ids (VPC route tables, NACLs, and checks without an ENI)
  cidrs:   prefixes for sources / destinations (longest match wins; 0.0.0.0/0 is the Internet)
  accounts: AWS account ids (auto topology: one node per account)
  ips:      exact addresses of a host the live AWS map drew (web/aws_map.py); a source or destination that equals one
            lights that node. An address two nodes claim (overlapping address space) is never attributed to either.
"""

from __future__ import annotations

import copy
import ipaddress
import re
from typing import Any

from nettrace.inventory import Inventory

SEVERITY = {"BLOCK": 4, "UNKNOWN": 3, "WARN": 2, "PASS": 1, "INFO": 0}


# ==== interface addresses for the zoomed-in view ==============================================
# Interface abbreviations as they appear in topology link labels ("Gi1", "Tu200", "e1/1") -> the full name a device
# reports ("GigabitEthernet1", "Tunnel200", "ethernet1/1"). Only used to match labels to discovered addresses.
_IF_PREFIX = {"gi": "gigabitethernet", "te": "tengigabitethernet", "twe": "twentyfivegige", "fo": "fortygigabitethernet",
              "hu": "hundredgigabitethernet", "fa": "fastethernet", "tu": "tunnel", "lo": "loopback", "po": "port-channel",
              "vl": "vlan", "e": "ethernet", "eth": "ethernet"}
_ADDR_MAX = 32  # addresses listed for one device (inspector Device tab)


def canonical_interface(name: str) -> str:
    """Lower-case full interface name, so "Gi1" and "GigabitEthernet1" (or "e1/1" and "ethernet1/1") compare equal."""
    s = name.strip().lower()
    m = re.match(r"([a-z-]+)(.*)", s)
    if not m:
        return s
    word, rest = m.groups()
    return _IF_PREFIX.get(word, word) + rest


def annotate_addresses(topology: dict[str, Any], inv: Inventory) -> dict[str, Any]:
    """A copy of `topology` with interface addresses for the UI's close zoom level:
      node["addrs"] = [{"if": interface, "ip": address}, ...]  for nodes that stand for inventory devices
      link["a_ip"] / link["b_ip"] = the address of the interface named in a_if / b_if on that end's device
    Sources: the discovery cache (`nettrace inventory discover`: ip -> device, interface) and each device's static
    `addresses` (no interface). Nothing is queried; an address the cache does not have is simply not shown, and an
    ambiguous address (claimed by several devices) is never attributed to one. Values are device-reported text: the UI
    escapes them like every other trace or topology string."""
    by_dev: dict[str, list[tuple[str, str]]] = {}
    for ip, hit in (inv.discovered or {}).items():
        dev = hit.get("device")
        if dev in inv.devices:
            by_dev.setdefault(dev, []).append((str(hit.get("interface") or ""), str(ip)))
    for dev in inv.devices.values():
        known = {ip for _if, ip in by_dev.get(dev.name, [])}
        by_dev.setdefault(dev.name, []).extend(("", ip) for ip in dev.addresses if ip not in known)

    def ip_sort(item: tuple[str, str]) -> tuple[int, Any]:
        try:
            return 0, ipaddress.ip_address(item[1])
        except ValueError:
            return 1, item[1]

    topo = copy.deepcopy(topology)
    nodes = {n["id"]: n for n in topo.get("nodes", [])}
    node_addrs: dict[str, list[tuple[str, str]]] = {}
    for n in nodes.values():
        rows = sorted({row for d in n.get("devices", []) for row in by_dev.get(d, [])}, key=lambda r: (r[0] == "", ip_sort(r)))
        if rows:
            node_addrs[n["id"]] = rows
            if "addrs" in n:  # the live AWS map already set the node's addresses (its own ENIs)
                continue
            n["addrs"] = [{"if": i, "ip": ip} for i, ip in rows[:_ADDR_MAX]]
            if len(rows) > _ADDR_MAX:
                n["addrs_more"] = len(rows) - _ADDR_MAX
    for link in topo.get("links", []):
        for end in ("a", "b"):
            label, rows = link.get(f"{end}_if"), node_addrs.get(link.get(end, ""))
            if not label or not rows:
                continue
            ips = []
            for part in str(label).split("·"):  # "e1/1 · e1/2": one link drawn for two interfaces
                want = canonical_interface(part)
                ips.extend(ip for i, ip in rows if i and canonical_interface(i) == want)
            if ips:
                link[f"{end}_ip"] = " · ".join(ips)
    return topo


# ==== hop -> node ============================================================================
class Locator:
    def __init__(self, topology: dict[str, Any]):
        self.nodes = topology["nodes"]
        self.by_device: dict[str, str] = {}
        self.by_id: dict[str, str] = {}
        self.by_vpc: dict[str, str] = {}
        self.by_account: dict[str, str] = {}
        self.cidrs: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []
        self.by_addr: dict[str, str | None] = {}  # exact host address -> node (None: claimed by several nodes)
        for n in self.nodes:
            for ip in n.get("ips", []):
                self.by_addr[ip] = n["id"] if self.by_addr.get(ip, n["id"]) == n["id"] else None
            for d in n.get("devices", []):
                self.by_device[d] = n["id"]
            for i in n.get("ids", []):
                self.by_id[i] = n["id"]
            for v in n.get("vpcs", []):
                self.by_vpc[v] = n["id"]
            for a in n.get("accounts", []):
                self.by_account[a] = n["id"]
            for c in n.get("cidrs", []):
                self.cidrs.append((ipaddress.ip_network(c, strict=False), n["id"]))
        self.internet = next((nid for net, nid in self.cidrs if net.prefixlen == 0), None)

    def by_ip(self, ip: str | None, *, allow_default: bool = True) -> str | None:
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if self.by_addr.get(ip):
            return self.by_addr[ip]
        best = None
        for net, nid in self.cidrs:
            if net.version == addr.version and addr in net and (allow_default or net.prefixlen > 0):
                if best is None or net.prefixlen > best[0].prefixlen:
                    best = (net, nid)
        return best[1] if best else None

    def hop(self, h: dict[str, Any], flow: dict[str, Any]) -> str | None:
        domain, comp, node = h.get("domain"), h.get("component"), h.get("node", "")
        loc = h.get("location") or {}
        if domain in ("cisco", "panos"):
            return self.by_device.get(node)
        if domain == "prisma":
            return self.by_device.get("prisma-access")
        if domain == "engine":
            if comp == "source":
                return (self.by_ip(flow.get("src"), allow_default=False) or self._by_location(loc)
                        or self.by_device.get(node) or self.internet)
            if comp == "error":
                return self.by_device.get(node)
            return None  # links are drawn as edges, not nodes
        # AWS: the most specific thing the hop is about. Structured fields only (never summary text). An ENI the hop is
        # about wins (a security-group hop on a firewall's ENI belongs to the firewall; on a host's, to the host).
        # Where the order differs: a target-group hop's `egress` is the target's ENI, but the hop is the NLB's;
        # gateways, endpoints and load balancers are named by `node`; Transit Gateway hops by the attachment or table.
        ing, eg = h.get("ingress"), h.get("egress")
        if comp in ("nlb", "vpc-endpoint", "interface-endpoint", "gwlb-endpoint", "nat-gateway", "internet-gateway"):
            keys = (node, ing, eg)
        elif comp == "target-group":
            keys = (ing, node)
        elif comp in ("tgw", "tgw-route-table"):
            keys = (ing, eg, node, loc.get("tgw"))
        else:
            keys = (ing, eg, node)
        for key in keys:
            if key and key in self.by_id:
                return self.by_id[key]
        return self._by_location(loc)

    def _by_location(self, loc: dict[str, str]) -> str | None:
        if loc.get("vpc") and loc["vpc"] in self.by_vpc:
            return self.by_vpc[loc["vpc"]]
        if loc.get("account") and loc["account"] in self.by_account:
            return self.by_account[loc["account"]]
        return None


def overlay(topology: dict[str, Any], trace: dict[str, Any]) -> dict[str, Any]:
    """Where each hop sits on the topology, the node path, and per-node status."""
    loc = Locator(topology)
    flow = trace.get("Flow") or {}
    final = trace.get("FinalFlow") or flow
    hop_nodes: dict[str, str | None] = {}
    step_index: dict[str, int] = {}  # hop index -> position in `path` (the packet's place on the canvas)
    path: list[str] = []
    status: dict[str, str] = {}
    for h in trace.get("Hops", []):
        nid = loc.hop(h, flow)
        hop_nodes[str(h["index"])] = nid
        if nid is not None and (not path or path[-1] != nid):
            path.append(nid)
        step_index[str(h["index"])] = max(len(path) - 1, 0)
        if nid is None:
            continue
        st = h.get("status", "INFO")
        if SEVERITY.get(st, 0) > SEVERITY.get(status.get(nid, "INFO"), 0):
            status[nid] = st
        status.setdefault(nid, st)

    outcome, reason = trace.get("Outcome"), trace.get("Reason", "")
    dest = None
    if outcome == "EXITED" and "internet" in reason.lower():
        dest = loc.internet
    else:
        dest = loc.by_ip(final.get("dst"), allow_default=outcome == "EXITED")
        if dest is None and outcome != "REACHABLE":
            dest = loc.by_ip(flow.get("dst"), allow_default=False)
    reached = outcome in ("REACHABLE", "EXITED")
    if dest and reached and (not path or path[-1] != dest):
        path.append(dest)
        status.setdefault(dest, "PASS" if outcome == "REACHABLE" else "INFO")
    return {"hop_nodes": hop_nodes, "step_index": step_index, "path": path, "status": status,
            "dest": {"node": dest, "reached": reached and dest is not None}}


# ==== auto topology for a real inventory ==========================================================
def auto_topology(inv: Inventory) -> dict[str, Any]:
    """Columns: Prisma Access | one box per site | one box per AWS account. Hand-tuned positions
    are not possible without a saved layout, so this is a readable grid."""
    groups: list[dict[str, Any]] = []
    nodes: list[dict[str, Any]] = []
    links: list[dict[str, Any]] = []
    col_w, row_h, top = 300, 150, 70
    x = 30

    def box(gid: str, label: str, kind: str, n_rows: int, width: int = col_w - 30) -> dict[str, Any]:
        g = {"id": gid, "label": label, "kind": kind, "x": x, "y": 30, "w": width, "h": top + n_rows * row_h}
        groups.append(g)
        return g

    if inv.prisma:
        p = inv.prisma
        rows = 1 + len(p.mobile_user_pools) + len(p.remote_networks)
        box("g-prisma", "Prisma Access", "prisma", rows)
        nodes.append({"id": "prisma-access", "label": "Prisma Access", "sub": "SASE", "kind": "prisma",
                      "x": x + 135, "y": top + 60, "group": "g-prisma", "devices": ["prisma-access"]})
        r = 1
        for pool in p.mobile_user_pools:
            nodes.append({"id": f"mu-{pool}", "label": "Mobile users", "sub": pool, "kind": "users", "x": x + 135,
                          "y": top + 60 + r * row_h, "group": "g-prisma", "cidrs": [pool]})
            links.append({"a": f"mu-{pool}", "b": "prisma-access", "kind": "tunnel"})
            r += 1
        for rn in p.remote_networks:
            nodes.append({"id": f"rn-{rn.name}", "label": rn.name, "sub": ", ".join(rn.prefixes), "kind": "lan",
                          "x": x + 135, "y": top + 60 + r * row_h, "group": "g-prisma", "cidrs": rn.prefixes})
            links.append({"a": f"rn-{rn.name}", "b": "prisma-access", "kind": "tunnel"})
            r += 1
        x += col_w

    sites: dict[str, list[Any]] = {}
    for d in inv.devices.values():
        if d.aws:
            continue
        sites.setdefault(d.site or "On-prem", []).append(d)
    for site, devs in sites.items():
        gid = f"g-site-{site}"
        nets = [n for n in inv.networks if n.gateway in {d.name for d in devs}]
        box(gid, site, "site", max(len(devs), len(nets), 1), width=2 * col_w - 30)
        for i, d in enumerate(devs):
            nodes.append({"id": d.name, "label": d.name, "sub": d.platform.replace("_", " "),
                          "kind": "router" if d.platform == "cisco_iosxe" else "firewall",
                          "x": x + col_w + 120, "y": top + 60 + i * row_h, "group": gid, "devices": [d.name]})
        for i, n in enumerate(nets):
            nid = f"net-{n.prefix}"
            nodes.append({"id": nid, "label": n.prefix, "sub": f"via {n.gateway}", "kind": "lan", "x": x + 120,
                          "y": top + 60 + i * row_h, "group": gid, "cidrs": [n.prefix]})
            links.append({"a": nid, "b": n.gateway})
        x += 2 * col_w

    for a in inv.aws_accounts:
        gid = f"g-aws-{a.account_id}"
        fws = [d for d in inv.devices.values() if d.aws and d.aws.account in (a.name, a.account_id)]
        box(gid, f"AWS · {a.name} ({a.account_id})", "aws", 1 + len(fws))
        nodes.append({"id": f"aws-{a.account_id}", "label": a.name, "sub": ", ".join(a.regions), "kind": "account",
                      "x": x + 135, "y": top + 60, "group": gid, "accounts": [a.account_id]})
        for j, d in enumerate(fws, start=1):
            nodes.append({"id": d.name, "label": d.name, "sub": "VM-Series", "kind": "firewall", "x": x + 135,
                          "y": top + 60 + j * row_h, "group": gid, "devices": [d.name]})
            links.append({"a": d.name, "b": f"aws-{a.account_id}"})
        x += col_w

    # Wrap the boxes into rows (on-prem/Prisma first, AWS after) so the canvas stays readable.
    max_row_w, gap, cx, cy, row_h_max, width = 1500, 30, 30, 30, 0, 0
    for g in groups:
        if cx > 30 and cx + g["w"] > max_row_w:
            cx, cy, row_h_max = 30, cy + row_h_max + gap, 0
        dx, dy = cx - g["x"], cy - g["y"]
        g["x"], g["y"] = cx, cy
        for n in nodes:
            if n.get("group") == g["id"]:
                n["x"] += dx
                n["y"] += dy
        cx += g["w"] + gap
        row_h_max = max(row_h_max, g["h"])
        width = max(width, cx)
    x = width
    max_bottom = cy + row_h_max
    nodes.append({"id": "internet", "label": "Internet", "sub": "outside known networks", "kind": "external",
                  "x": x + 120, "y": 160, "cidrs": ["0.0.0.0/0"]})
    for link in inv.links:
        ends = []
        for end in (link.a, link.b):
            if end.device:
                ends.append(end.device)
            elif end.prisma_service_connection and inv.prisma:
                ends.append("prisma-access")
            elif end.external:
                ends.append("internet")
            elif end.aws_account:
                acct = inv.account(end.aws_account)
                ends.append(f"aws-{acct.account_id}" if acct else None)
            else:
                ends.append(None)
        if all(ends):
            links.append({"a": ends[0], "b": ends[1], "label": link.name, "kind": "tunnel",
                          "a_if": link.a.interface or "", "b_if": link.b.interface or ""})
    known = {n["id"] for n in nodes}
    links = [lk for lk in links if lk["a"] in known and lk["b"] in known]
    return {"title": f"Inventory {inv.path.name}", "size": [x + 300, max_bottom + 60], "groups": groups,
            "nodes": nodes, "links": links}
