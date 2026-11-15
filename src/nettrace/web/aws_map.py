"""A live AWS map for the web UI: accounts > VPCs > subnets > hosts, with the gateways, endpoints, load balancers and
the Transit Gateway between them. It is built from read-only Describe calls and has the same shape `auto_topology`
returns (`groups`, `nodes`, `links`, `size`, `title`), so the UI draws it like any other topology.

Every call goes through `AwsEnv.call` (allowlist, audit, deadline, cache); nothing here reaches boto3 directly.
Everything read from AWS is text somebody else typed (Name tags, descriptions, rule descriptions): it is cleaned with
`_s` (control characters removed, length capped) and the UI escapes it again when it draws it (rule 10). A call that
fails is never left out silently: the account node says "could not read: <reason>" (D22).

Extra fields on a node, beyond what `auto_topology` uses (see topology.py):
  ips     private and public addresses of the node, for placing a trace's source and destination exactly
  addrs   the same as [{"if": eni id, "ip": address}], for the UI's find box
  find    extra search words (security-group names and ids)
  detail  sections for the inspector's Device tab: {"title": str, "rows": [[key, value], ...]} or {"title", "items": [...]}
  minor   true for hosts (their names fade when the map is zoomed out)
Groups carry `parent` (the group they sit in), `kind` (aws / vpc / subnet) and an optional `meta` line.
"""

from __future__ import annotations

import contextvars
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable

from nettrace.drivers.aws import AwsEnv
from nettrace.inventory import Inventory

NODE_CAP = 400  # about this many nodes are drawn; the rest of a crowded subnet becomes one "+N more" node
CELL_W, CELL_H = 140, 112  # one node cell (tile, name and a sub line)
PAD, HEAD = 16, 48  # box padding and header height
GAP = 18
SUBNET_COLS = 3
SUBNETS_PER_ROW = 2

_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f  ]+")
Progress = Callable[[str], None]


def _s(value: Any, limit: int = 120) -> str:
    """Text from AWS made safe to carry: control characters become a space, and the length is capped."""
    text = _CTRL.sub(" ", str(value if value is not None else "")).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _name(obj: dict[str, Any]) -> str:
    for t in obj.get("Tags") or []:
        if t.get("Key") == "Name" and t.get("Value"):
            return _s(t["Value"], 80)
    return ""


def _reason(exc: BaseException) -> str:
    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "") if hasattr(exc, "response") else ""
    msg = _s(exc, 200)
    return _s(f"{code}: {msg}" if code and code not in msg else msg or type(exc).__name__, 200)


# ==== reading ==================================================================================
@dataclass
class Region:
    acct: str
    region: str
    errors: list[tuple[str, str]] = field(default_factory=list)  # (service:operation, reason)
    d: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    nlb: list[dict[str, Any]] = field(default_factory=list)  # {lb, listeners, groups: [{tg, health}]}
    services: dict[str, list[str]] = field(default_factory=dict)  # endpoint service name -> NLB arns (owner side)

    @property
    def core_failed(self) -> bool:
        return any(op.split(":")[1] in {"DescribeVpcs", "DescribeSubnets", "DescribeNetworkInterfaces"} for op, _ in self.errors)


def _read_region(env: AwsEnv, acct: str, region: str, progress: Progress | None) -> Region:
    r = Region(acct, region)

    def get(op: str, key: str, service: str = "ec2", **params: Any) -> list[dict[str, Any]]:
        try:
            return list(env.call(acct, region, op, service=service, **params).get(key, []))
        except Exception as exc:  # noqa: BLE001 - any failure is reported on the map, never fatal
            r.errors.append((f"{service}:{''.join(p.title() for p in op.split('_'))}", _reason(exc)))
            return []

    for key, op, out in (("Vpcs", "describe_vpcs", "vpcs"), ("Subnets", "describe_subnets", "subnets"),
                         ("NetworkInterfaces", "describe_network_interfaces", "enis"),
                         ("SecurityGroups", "describe_security_groups", "sgs"),
                         ("RouteTables", "describe_route_tables", "rtbs"), ("NatGateways", "describe_nat_gateways", "nats"),
                         ("VpcEndpoints", "describe_vpc_endpoints", "vpces"),
                         ("TransitGateways", "describe_transit_gateways", "tgws"),
                         ("TransitGatewayAttachments", "describe_transit_gateway_attachments", "tgw_atts"),
                         ("TransitGatewayVpcAttachments", "describe_transit_gateway_vpc_attachments", "tgw_vpc_atts")):
        r.d[out] = get(op, key)
    # DescribeInstances is used only for each instance's Name tag and state (D22): nothing else is kept.
    r.d["instances"] = [{"InstanceId": i.get("InstanceId"), "State": (i.get("State") or {}).get("Name"), "Name": _name(i)}
                        for res in get("describe_instances", "Reservations") for i in res.get("Instances", [])]
    for cfg in get("describe_vpc_endpoint_service_configurations", "ServiceConfigurations"):
        if cfg.get("ServiceName"):
            r.services[cfg["ServiceName"]] = list(cfg.get("NetworkLoadBalancerArns") or [])
    for lb in get("describe_load_balancers", "LoadBalancers", service="elbv2"):
        if lb.get("Type") != "network":
            continue
        arn = lb["LoadBalancerArn"]
        entry: dict[str, Any] = {"lb": lb, "listeners": get("describe_listeners", "Listeners", service="elbv2", LoadBalancerArn=arn),
                                 "groups": []}
        for tg in get("describe_target_groups", "TargetGroups", service="elbv2", LoadBalancerArn=arn):
            entry["groups"].append({"tg": tg, "health": get("describe_target_health", "TargetHealthDescriptions",
                                                            service="elbv2", TargetGroupArn=tg["TargetGroupArn"])})
        r.nlb.append(entry)
    if progress:
        n = sum(len(v) for v in r.d.values())
        progress(f"  read {acct}/{region}: {n} resources" + (f", {len(r.errors)} reads failed" if r.errors else ""))
    return r


# ==== text helpers ============================================================================
def _ports(p: dict[str, Any]) -> str:
    proto = p.get("IpProtocol", "-1")
    if proto == "-1":
        return "all"
    lo, hi = p.get("FromPort"), p.get("ToPort")
    if lo is None or lo == -1:
        return _s(proto)
    return f"{proto}/{lo}" if lo == hi else f"{proto}/{lo}-{hi}"


def _peers(p: dict[str, Any]) -> str:
    out = [x["CidrIp"] for x in p.get("IpRanges", []) if x.get("CidrIp")]
    out += [x["CidrIpv6"] for x in p.get("Ipv6Ranges", []) if x.get("CidrIpv6")]
    out += [x["PrefixListId"] for x in p.get("PrefixListIds", []) if x.get("PrefixListId")]
    out += [x["GroupId"] for x in p.get("UserIdGroupPairs", []) if x.get("GroupId")]
    return ", ".join(out[:4]) + (f" +{len(out) - 4}" if len(out) > 4 else "") or "nothing"


def _rules(perms: list[dict[str, Any]], inbound: bool) -> str:
    if not perms:
        return "none"
    parts = [f"{_ports(p)} {'from' if inbound else 'to'} {_peers(p)}" for p in perms]
    shown = "; ".join(parts[:5]) + (f"; +{len(parts) - 5} more" if len(parts) > 5 else "")
    return _s(shown, 360)


def _sg_row(sg: dict[str, Any]) -> list[str]:
    return [_s(f"{sg.get('GroupName', '')} ({sg.get('GroupId', '')})", 100),
            f"in: {_rules(sg.get('IpPermissions', []), True)} · out: {_rules(sg.get('IpPermissionsEgress', []), False)}"]


def _route_target(rt: dict[str, Any]) -> tuple[str, str]:
    """(kind, id) of where a route sends traffic."""
    for key, kind in (("TransitGatewayId", "tgw"), ("NatGatewayId", "nat"), ("VpcPeeringConnectionId", "pcx"),
                      ("NetworkInterfaceId", "eni"), ("EgressOnlyInternetGatewayId", "eigw"), ("VpcEndpointId", "vpce"),
                      ("CarrierGatewayId", "cagw"), ("LocalGatewayId", "lgw"), ("CoreNetworkArn", "cnet")):
        if rt.get(key):
            return kind, _s(rt[key])
    gw = str(rt.get("GatewayId") or "")
    if gw == "local":
        return "local", "local"
    if gw.startswith("igw-"):
        return "igw", gw
    if gw.startswith("vpce-"):
        return "vpce", gw
    if gw.startswith("vgw-"):
        return "vgw", gw
    return ("other", _s(gw)) if gw else ("other", "")


def _dest(rt: dict[str, Any]) -> str:
    return _s(rt.get("DestinationCidrBlock") or rt.get("DestinationIpv6CidrBlock") or rt.get("DestinationPrefixListId") or "?")


def _eni_ips(eni: dict[str, Any]) -> tuple[list[str], list[str]]:
    priv, pub = [], []
    for a in eni.get("PrivateIpAddresses") or []:
        if a.get("PrivateIpAddress"):
            priv.append(a["PrivateIpAddress"])
        if (a.get("Association") or {}).get("PublicIp"):
            pub.append(a["Association"]["PublicIp"])
    if eni.get("PrivateIpAddress") and eni["PrivateIpAddress"] not in priv:
        priv.insert(0, eni["PrivateIpAddress"])
    if (eni.get("Association") or {}).get("PublicIp") and eni["Association"]["PublicIp"] not in pub:
        pub.append(eni["Association"]["PublicIp"])
    return priv, pub


def _short(text: str, n: int = 22) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


def _titled(name: str, cidr: str, limit: int = 46) -> str:
    """"name · cidr", cutting the name (never the CIDR) to fit."""
    if not name:
        return cidr
    room = max(8, limit - len(cidr) - 3)
    return f"{_short(name, room)} · {cidr}"


# ==== the model ===============================================================================
@dataclass
class _Sub:
    sid: str
    vpc: str
    name: str
    cidr: str
    az: str
    nodes: list[dict[str, Any]] = field(default_factory=list)
    meta_route: str = ""


class _Build:
    def __init__(self, inv: Inventory, regions: list[Region]):
        self.inv = inv
        self.regions = regions
        self.nodes: dict[str, dict[str, Any]] = {}
        self.links: list[dict[str, Any]] = []
        self.vpcs: dict[str, dict[str, Any]] = {}
        self.subs: dict[str, _Sub] = {}
        self.vpc_strip: dict[str, list[dict[str, Any]]] = defaultdict(list)  # nodes at the top of a VPC box
        self.vpc_of_acct: dict[str, list[str]] = defaultdict(list)
        self.sgs: dict[str, dict[str, Any]] = {}
        self.notes: list[dict[str, str]] = []
        self.eni_node: dict[str, str] = {}
        self.inst_node: dict[str, str] = {}
        self.tgw_nodes: dict[str, dict[str, Any]] = {}
        self.account_regions: dict[str, list[Region]] = defaultdict(list)
        self.n_instances = 0

    # -- helpers
    def add(self, node: dict[str, Any]) -> dict[str, Any]:
        if len(node["label"]) > 18:  # the canvas has room for about this many characters; the tooltip and search keep the whole name
            node["full"] = node["label"]
            node["label"] = _short(node["label"], 18)
        if node["kind"] in ("host", "eni", "vpc-router", "igw", "vpce", "generic"):
            node["minor"] = True  # its name fades when the map is zoomed out
        node.setdefault("ids", [])
        node["ids"] = list(dict.fromkeys(node["ids"]))
        self.nodes[node["id"]] = node
        return node

    def link(self, a: str, b: str, **kw: Any) -> None:
        if a in self.nodes and b in self.nodes and a != b and not any({x["a"], x["b"]} == {a, b} for x in self.links):
            self.links.append({"a": a, "b": b, **kw})

    def acct_name(self, acct: str) -> str:
        a = self.inv.account(acct)
        return a.name if a else acct

    # -- steps
    def run(self) -> None:
        for r in self.regions:
            self.account_regions[r.acct].append(r)
            for e in r.errors:
                self.notes.append({"account": self.acct_name(r.acct), "region": r.region, "call": e[0], "reason": e[1]})
        self.read_vpcs()
        self.read_routes()
        self.read_hosts()
        self.read_gateways()
        self.read_nlbs()
        self.read_tgws()
        self.place_devices()

    def read_vpcs(self) -> None:
        for r in self.regions:
            for v in r.d.get("vpcs", []):
                vid = v["VpcId"]
                if vid in self.vpcs:
                    continue
                cidrs = [v["CidrBlock"]] if v.get("CidrBlock") else []
                cidrs += [a["CidrBlock"] for a in v.get("CidrBlockAssociationSet") or []
                          if a.get("CidrBlock") and a["CidrBlock"] not in cidrs]
                self.vpcs[vid] = {"id": vid, "acct": r.acct, "region": r.region, "name": _name(v), "cidrs": [_s(c, 43) for c in cidrs],
                                  "subnets": [], "rtbs": [], "state": _s(v.get("State")), "default": bool(v.get("IsDefault"))}
                self.vpc_of_acct[r.acct].append(vid)
            for s in r.d.get("subnets", []):
                sid = s["SubnetId"]
                if sid in self.subs or s.get("VpcId") not in self.vpcs:
                    continue
                self.subs[sid] = _Sub(sid, s["VpcId"], _name(s), _s(s.get("CidrBlock"), 43), _s(s.get("AvailabilityZone"), 20))
                self.vpcs[s["VpcId"]]["subnets"].append(sid)
            for g in r.d.get("sgs", []):
                self.sgs.setdefault(g["GroupId"], g)
        for ids in self.vpc_of_acct.values():  # the lab's own VPCs first, the account's default VPC last
            ids.sort(key=lambda i: (self.vpcs[i]["default"], self.vpcs[i]["name"] or i))
        for vid, v in self.vpcs.items():
            router = self.add({
                "id": f"vpc-router-{vid}", "label": "VPC router", "sub": f"{len(v['subnets'])} subnets", "kind": "vpc-router",
                "vpcs": [vid], "ids": [vid]})
            self.vpc_strip[vid].append(router)
            v["router"] = router["id"]

    def read_routes(self) -> None:
        """Route tables: which table each subnet uses, and the gateways the tables name."""
        self.igws: dict[str, str] = {}  # igw id -> vpc
        self.sub_default: dict[str, tuple[str, str]] = {}  # subnet -> (kind, id) of its default route
        self.default_users: dict[tuple[str, str], int] = defaultdict(int)  # (vpc, target id) -> subnets with a default route there
        self.any_users: dict[tuple[str, str], int] = defaultdict(int)  # (vpc, target id) -> subnets with any route there
        for vid, v in self.vpcs.items():
            tables = [t for r in self.regions for t in r.d.get("rtbs", []) if t.get("VpcId") == vid]
            seen = {}
            for t in tables:
                seen.setdefault(t["RouteTableId"], t)
            tables = sorted(seen.values(), key=lambda t: t["RouteTableId"])
            main = next((t for t in tables if any(a.get("Main") for a in t.get("Associations") or [])), None)
            by_sub = {a["SubnetId"]: t for t in tables for a in t.get("Associations") or [] if a.get("SubnetId")}
            v["rtbs"] = tables
            router = self.nodes[v["router"]]
            router["ids"] += [t["RouteTableId"] for t in tables]
            used: dict[str, list[str]] = defaultdict(list)
            for sid in v["subnets"]:
                t = by_sub.get(sid, main)
                if not t:
                    continue
                used[t["RouteTableId"]].append(sid)
                targets = {(_route_target(rt)) for rt in t.get("Routes", []) if rt.get("State") != "blackhole"}
                for kind, tid in targets:
                    if kind in ("igw", "nat", "vpce") and tid:
                        self.any_users[(vid, tid)] += 1
                    if kind == "igw":
                        self.igws[tid] = vid
                for rt in t.get("Routes", []):
                    k, tid = _route_target(rt)
                    if _dest(rt) in ("0.0.0.0/0", "::/0") and k != "local":
                        self.sub_default.setdefault(sid, (k, tid))
                        if k in ("igw", "nat"):
                            self.default_users[(vid, tid)] += 1
            for t in tables:  # an IGW named only by an unassociated table still gets drawn
                for rt in t.get("Routes", []):
                    k, tid = _route_target(rt)
                    if k == "igw":
                        self.igws[tid] = vid
            v["rtb_use"] = used
            rows_detail: list[dict[str, Any]] = [{"title": "VPC", "rows": [
                ["id", vid], ["account", f"{self.acct_name(v['acct'])} ({v['acct']})"], ["region", v["region"]],
                ["CIDRs", ", ".join(v["cidrs"]) or "none"]]}]
            for t in tables[:8]:
                label = f"{t['RouteTableId']}" + (f" ({_name(t)})" if _name(t) else "")
                subs = [self.subs[s].name or s for s in used.get(t["RouteTableId"], []) if s in self.subs]
                is_main = any(a.get("Main") for a in t.get("Associations") or [])
                rows = [["used by", ("main table, " if is_main else "") + (", ".join(subs[:6]) + (f" +{len(subs) - 6}" if len(subs) > 6 else "")
                                                                          if subs else ("no subnets" if not is_main else "other subnets"))]]
                for rt in t.get("Routes", [])[:14]:
                    k, tid = _route_target(rt)
                    rows.append([_dest(rt), f"{tid}" + (" (blackhole)" if rt.get("State") == "blackhole" else "")])
                rows_detail.append({"title": f"Route table {label}", "rows": rows})
            if len(tables) > 8:
                rows_detail.append({"title": "More route tables", "items": [f"+{len(tables) - 8} not listed"]})
            router["detail"] = rows_detail
        for sid, sub in self.subs.items():
            k, tid = self.sub_default.get(sid, ("", ""))
            sub.meta_route = f"0.0.0.0/0 → {k}" if k else ""

    def read_hosts(self) -> None:
        inst = {i["InstanceId"]: i for r in self.regions for i in r.d.get("instances", []) if i.get("InstanceId")}
        by_inst: dict[str, list[tuple[Region, dict[str, Any]]]] = defaultdict(list)
        others: list[tuple[Region, dict[str, Any]]] = []
        self.special_enis: dict[str, dict[str, Any]] = {}
        seen_enis = set()
        for r in self.regions:
            for e in r.d.get("enis", []):
                if e["NetworkInterfaceId"] in seen_enis or e.get("SubnetId") not in self.subs:
                    continue
                seen_enis.add(e["NetworkInterfaceId"])
                iid = (e.get("Attachment") or {}).get("InstanceId")
                if iid:
                    by_inst[iid].append((r, e))
                elif e.get("InterfaceType") in ("vpc_endpoint", "network_load_balancer", "nat_gateway", "transit_gateway",
                                                "gateway_load_balancer_endpoint", "gateway_load_balancer"):
                    self.special_enis[e["NetworkInterfaceId"]] = e
                else:
                    others.append((r, e))
        self.n_instances = len(by_inst)
        for iid, rows in sorted(by_inst.items()):
            rows.sort(key=lambda re_: ((re_[1].get("Attachment") or {}).get("DeviceIndex", 99), re_[1]["NetworkInterfaceId"]))
            info = inst.get(iid) or {}
            first = rows[0][1]
            priv: list[str] = []
            pub: list[str] = []
            addrs: list[dict[str, str]] = []
            find: list[str] = []
            eni_rows: list[list[str]] = []
            sg_ids: list[str] = []
            for _r, e in rows:
                p, q = _eni_ips(e)
                priv += p
                pub += q
                addrs += [{"if": e["NetworkInterfaceId"], "ip": ip} for ip in p] + [{"if": e["NetworkInterfaceId"] + " public", "ip": ip} for ip in q]
                sub = self.subs[e["SubnetId"]]
                eni_rows.append([e["NetworkInterfaceId"], _s(", ".join(p + [f"{x} (public)" for x in q]) + f" · {sub.name or sub.sid}"
                                                              + (" · source/dest check off" if e.get("SourceDestCheck") is False else ""), 200)])
                sg_ids += [g["GroupId"] for g in e.get("Groups", [])]
            sg_ids = list(dict.fromkeys(sg_ids))
            sg_names = [_s(self.sgs[g].get("GroupName", g), 60) if g in self.sgs else g for g in sg_ids]
            find += sg_names + sg_ids
            name = _s(info.get("Name") or "", 80)
            state = _s(info.get("State") or "", 20)
            node = self.add({
                "id": iid, "label": name or iid, "sub": _s((priv[0] if priv else "") + (f" +{len(priv) - 1}" if len(priv) > 1 else "")
                                                           + (f" · {state}" if state and state != "running" else "")),
                "kind": "host", "minor": True, "ids": [iid] + [e["NetworkInterfaceId"] for _r, e in rows],
                "ips": list(dict.fromkeys(priv + pub)), "addrs": addrs, "find": find, "group": first["SubnetId"],
                "detail": [
                    {"title": "Instance", "rows": [["name", name or "(no Name tag)"], ["id", iid], ["state", state or "unknown"],
                                                     ["account", self.acct_name(rows[0][0].acct)]]},
                    {"title": "Network interfaces", "rows": eni_rows},
                    {"title": "Security groups", "rows": [_sg_row(self.sgs[g]) if g in self.sgs else [g, "not readable"] for g in sg_ids]
                     or [["none", ""]]},
                ]})
            for _r, e in rows:
                self.eni_node[e["NetworkInterfaceId"]] = iid
            self.inst_node[iid] = iid
            self.subs[first["SubnetId"]].nodes.append(node)
        for _r, e in sorted(others, key=lambda re_: re_[1]["NetworkInterfaceId"]):
            p, q = _eni_ips(e)
            eid = e["NetworkInterfaceId"]
            sg_ids = [g["GroupId"] for g in e.get("Groups", [])]
            sg_names = [_s(self.sgs[g].get("GroupName", g), 60) if g in self.sgs else g for g in sg_ids]
            desc = _s(e.get("Description"), 100)
            node = self.add({
                "id": eid, "label": _short(desc or eid, 26), "sub": _s(p[0] if p else ""), "kind": "eni", "minor": True,
                "ids": [eid], "ips": p + q, "addrs": [{"if": eid, "ip": ip} for ip in p + q], "find": sg_names + sg_ids,
                "group": e["SubnetId"],
                "detail": [{"title": "Network interface", "rows": [["id", eid], ["description", desc or "none"],
                                                                   ["type", _s(e.get("InterfaceType"))],
                                                                   ["addresses", ", ".join(p + [f"{x} (public)" for x in q])],
                                                                   ["status", _s(e.get("Status"))]]},
                           {"title": "Security groups", "rows": [_sg_row(self.sgs[g]) if g in self.sgs else [g, "not readable"]
                                                                  for g in sg_ids] or [["none", ""]]}]})
            self.eni_node[eid] = eid
            self.subs[e["SubnetId"]].nodes.append(node)

    def read_gateways(self) -> None:
        # Internet gateways come from the route tables (there is no DescribeInternetGateways permission, D22).
        for igw, vid in sorted(self.igws.items()):
            users = self.default_users.get((vid, igw), 0)
            self.add({"id": igw, "label": _short(igw, 24), "sub": "internet gateway", "kind": "igw", "ids": [igw], "vpcs": [],
                      "detail": [{"title": "Internet gateway", "rows": [["id", igw], ["VPC", vid],
                                                                         ["subnets with a default route here", str(users)],
                                                                         ["subnets with any route here", str(self.any_users.get((vid, igw), 0))]]}]})
            self.vpc_strip[vid].append(self.nodes[igw])
        for r in self.regions:
            for n in r.d.get("nats", []):
                nid = n["NatGatewayId"]
                if nid in self.nodes or n.get("SubnetId") not in self.subs:
                    continue
                addrs = n.get("NatGatewayAddresses") or []
                priv = [a["PrivateIp"] for a in addrs if a.get("PrivateIp")]
                pub = [a["PublicIp"] for a in addrs if a.get("PublicIp")]
                enis = [a["NetworkInterfaceId"] for a in addrs if a.get("NetworkInterfaceId")]
                nm = _name(n)
                node = self.add({
                    "id": nid, "label": nm or _short(nid, 24), "sub": _s(", ".join(pub or priv) or "NAT gateway"), "kind": "natgw",
                    "ids": [nid] + enis, "ips": priv + pub, "addrs": [{"if": nid, "ip": ip} for ip in priv + pub],
                    "group": n["SubnetId"],
                    "detail": [{"title": "NAT gateway", "rows": [["id", nid], ["name", nm or "(no Name tag)"], ["state", _s(n.get("State"))],
                                                                  ["type", _s(n.get("ConnectivityType") or "public")],
                                                                  ["private IP", ", ".join(priv) or "none"],
                                                                  ["public IP", ", ".join(pub) or "none"],
                                                                  ["subnet", self.subs[n["SubnetId"]].name or n["SubnetId"]]]}]})
                for e in enis:
                    self.eni_node[e] = nid
                self.subs[n["SubnetId"]].nodes.append(node)
        for r in self.regions:
            for e in r.d.get("vpces", []):
                vid_ep = e["VpcEndpointId"]
                if vid_ep in self.nodes or e.get("VpcId") not in self.vpcs:
                    continue
                typ = _s(e.get("VpcEndpointType"))
                svc = _s(e.get("ServiceName"), 140)
                nm = _name(e)
                enis = list(e.get("NetworkInterfaceIds") or [])
                ips = []
                for en in enis:
                    eni = self.special_enis.get(en)
                    if eni:
                        ips += _eni_ips(eni)[0]
                short_svc = svc.rsplit(".", 1)[-1] if svc else "endpoint"
                sg_ids = [g["GroupId"] for g in e.get("Groups") or []]
                node = {"id": vid_ep, "label": nm or _short(short_svc, 24), "sub": _s(f"{typ.lower()} · {short_svc}", 60), "kind": "vpce",
                        "ids": [vid_ep] + enis, "ips": ips, "addrs": [{"if": vid_ep, "ip": ip} for ip in ips],
                        "find": [_s(self.sgs[g].get("GroupName", g), 60) if g in self.sgs else g for g in sg_ids],
                        "detail": [{"title": "VPC endpoint", "rows": [["id", vid_ep], ["type", typ], ["service", svc],
                                                                       ["state", _s(e.get("State"))], ["VPC", e["VpcId"]],
                                                                       ["addresses", ", ".join(ips) or "none"],
                                                                       ["route tables", ", ".join(e.get("RouteTableIds") or []) or "none"]]},
                                   {"title": "Security groups", "rows": [_sg_row(self.sgs[g]) if g in self.sgs else [g, "not readable"]
                                                                          for g in sg_ids] or [["none", ""]]}],
                        "_service": svc}
                if typ == "GatewayLoadBalancer":
                    node["kind"] = "gwlbe"
                self.add(node)
                for en in enis:
                    self.eni_node[en] = vid_ep
                subnet_ids = [s for s in e.get("SubnetIds") or [] if s in self.subs]
                if typ == "Gateway" or not subnet_ids:
                    self.vpc_strip[e["VpcId"]].append(node)
                else:
                    node["group"] = subnet_ids[0]
                    self.subs[subnet_ids[0]].nodes.append(node)
                if typ == "Gateway":
                    self.link(self.vpcs[e["VpcId"]]["router"], vid_ep, label="route")
        # routers reach the gateways their subnets send traffic to
        for (vid, tid), n_default in self.default_users.items():
            if tid in self.nodes:
                self.link(self.vpcs[vid]["router"], tid, label=f"0.0.0.0/0 ×{n_default}")
        for sid, sub in self.subs.items():  # a public NAT gateway reaches the internet through its subnet's gateway
            for node in sub.nodes:
                if node["kind"] == "natgw":
                    k, tid = self.sub_default.get(sid, ("", ""))
                    if k == "igw" and tid in self.nodes:
                        self.link(node["id"], tid)
        for igw in self.igws:
            if igw in self.nodes:
                self.nodes.setdefault("internet", {"id": "internet", "label": "Internet", "sub": "outside known networks",
                                                   "kind": "external", "cidrs": ["0.0.0.0/0"], "ids": []})
                self.link(igw, "internet")

    def read_nlbs(self) -> None:
        self.nlb_by_arn: dict[str, str] = {}
        target_ip: dict[str, str] = {}
        for n in self.nodes.values():
            for ip in n.get("ips", []):
                target_ip.setdefault(ip, n["id"])
        for r in self.regions:
            for ent in r.nlb:
                lb = ent["lb"]
                arn = lb["LoadBalancerArn"]
                if arn in self.nlb_by_arn:
                    continue
                nm = _s(lb.get("LoadBalancerName"), 80)
                subnet_ids = [az.get("SubnetId") for az in lb.get("AvailabilityZones") or [] if az.get("SubnetId") in self.subs]
                enis = [eid for eid, e in self.special_enis.items()
                        if e.get("InterfaceType") == "network_load_balancer" and f"net/{nm}/" in str(e.get("Description"))]
                ips = [ip for eid in enis for ip in _eni_ips(self.special_enis[eid])[0]]
                lids = [_s(f"{l.get('Protocol', '')}:{l.get('Port', '')}") for l in ent["listeners"]]
                rows_l = []
                for l in ent["listeners"]:
                    tgs = []
                    for a in l.get("DefaultActions") or []:
                        for t in ((a.get("ForwardConfig") or {}).get("TargetGroups") or [{"TargetGroupArn": a.get("TargetGroupArn")}]):
                            tgs.append(_s(str(t.get("TargetGroupArn") or "").rsplit("/", 2)[-2] if t.get("TargetGroupArn") else "?", 60))
                    rows_l.append([_s(f"{l.get('Protocol', '')}:{l.get('Port', '')}"), "forward to " + (", ".join(tgs) or "?")])
                tg_ids: list[str] = []
                tg_rows: list[list[str]] = []
                healthy = total = 0
                members: list[tuple[str, str, str]] = []
                for g in ent["groups"]:
                    tg = g["tg"]
                    tg_ids.append(_s(tg.get("TargetGroupName"), 60))
                    tg_rows.append([_s(tg.get("TargetGroupName"), 60), _s(f"{tg.get('Protocol', '')}:{tg.get('Port', '')} · {tg.get('TargetType', '')}")])
                    for h in g["health"]:
                        t = h.get("Target") or {}
                        state = _s((h.get("TargetHealth") or {}).get("State") or "unknown", 24)
                        total += 1
                        healthy += state == "healthy"
                        members.append((_s(t.get("Id"), 64), _s(t.get("Port", ""), 8), state))
                        tg_rows.append([f"  {_s(t.get('Id'), 64)}:{_s(t.get('Port', ''), 8)}", state])
                node = {"id": f"nlb-{nm}-{arn.rsplit('/', 1)[-1]}", "label": nm, "sub": _s(f"{lb.get('Scheme', '')} NLB · {healthy}/{total} healthy"),
                        "kind": "nlb", "ids": [nm, arn] + enis + tg_ids, "ips": ips, "addrs": [{"if": e, "ip": ip} for e in enis[:1] for ip in ips],
                        "find": [nm] + tg_ids + lids,
                        "detail": [{"title": "Network Load Balancer", "rows": [
                            ["name", nm], ["scheme", _s(lb.get("Scheme"))], ["state", _s((lb.get("State") or {}).get("Code"))],
                            ["VPC", _s(lb.get("VpcId"))], ["DNS", _s(lb.get("DNSName"), 120)],
                            ["security groups", ", ".join(_s(self.sgs[g].get("GroupName", g), 40) if g in self.sgs else g
                                                         for g in lb.get("SecurityGroups") or []) or "none"],
                            ["addresses", ", ".join(ips) or "not shown by AWS"]]},
                            {"title": "Listeners", "rows": rows_l or [["none", ""]]},
                            {"title": "Target groups and targets", "rows": tg_rows or [["none", ""]]}]}
                if subnet_ids:
                    node["group"] = subnet_ids[0]
                self.add(node)
                self.nlb_by_arn[arn] = node["id"]
                for e in enis:
                    self.eni_node[e] = node["id"]
                if subnet_ids:
                    self.subs[subnet_ids[0]].nodes.append(node)
                elif lb.get("VpcId") in self.vpcs:
                    self.vpc_strip[lb["VpcId"]].append(node)
                for tid, port, state in members:
                    dest = self.nodes.get(tid) and tid or target_ip.get(tid)
                    if dest:
                        self.link(node["id"], dest, label=_s(f":{port} {state}"))
        for n in list(self.nodes.values()):  # endpoint -> the NLB behind its service, when that NLB is on the map
            svc = n.pop("_service", "")
            if n.get("kind") != "vpce" or not svc:
                continue
            for r in self.regions:
                for arn in r.services.get(svc, []):
                    if arn in self.nlb_by_arn:
                        self.link(n["id"], self.nlb_by_arn[arn], label="PrivateLink")

    def read_tgws(self) -> None:
        tgws: dict[str, dict[str, Any]] = {}
        atts: dict[str, dict[str, Any]] = {}
        vatts: dict[str, dict[str, Any]] = {}
        seen_by: dict[str, str] = {}
        for r in self.regions:
            for t in r.d.get("tgws", []):
                tgws.setdefault(t["TransitGatewayId"], t)
                seen_by.setdefault(t["TransitGatewayId"], r.acct)
            for a in r.d.get("tgw_atts", []):
                atts.setdefault(a["TransitGatewayAttachmentId"], a)
            for a in r.d.get("tgw_vpc_atts", []):
                vatts.setdefault(a["TransitGatewayAttachmentId"], a)
        for tid, t in sorted(tgws.items()):
            mine = [a for a in atts.values() if a.get("TransitGatewayId") == tid]
            vmine = {a["TransitGatewayAttachmentId"]: a for a in vatts.values() if a.get("TransitGatewayId") == tid}
            rtbs = sorted({(a.get("Association") or {}).get("TransitGatewayRouteTableId") for a in mine} - {None})
            owner = t.get("OwnerId") or seen_by.get(tid, "")
            rows: list[list[str]] = []
            for a in sorted(mine, key=lambda a: (a.get("ResourceType", ""), a["TransitGatewayAttachmentId"]))[:40]:
                v = vmine.get(a["TransitGatewayAttachmentId"]) or {}
                res = self.vpcs.get(a.get("ResourceId") or "", {})
                rname = res.get("name") or ""
                extra = " · appliance mode" if (v.get("Options") or {}).get("ApplianceModeSupport") == "enable" else ""
                rows.append([_s(a["TransitGatewayAttachmentId"]),
                             _s(f"{a.get('ResourceType', '')} {a.get('ResourceId', '')}" + (f" ({rname})" if rname else "")
                                + f" · {a.get('State', '')} · table {(a.get('Association') or {}).get('TransitGatewayRouteTableId') or 'none'}{extra}", 220)])
            nm = _name(t)
            node = self.add({
                "id": tid, "label": nm or _short(tid, 24), "sub": _s(f"Transit Gateway · {self.acct_name(owner)}"), "kind": "tgw",
                "ids": [tid] + [a["TransitGatewayAttachmentId"] for a in mine] + rtbs,
                "detail": [{"title": "Transit Gateway", "rows": [["id", tid], ["name", nm or "(no Name tag)"],
                                                                 ["owner", f"{self.acct_name(owner)} ({owner})"], ["state", _s(t.get("State"))],
                                                                 ["route tables in use", ", ".join(rtbs) or "none"]]},
                           {"title": "Attachments", "rows": rows or [["none", ""]]}]})
            node["_owner"] = owner
            self.tgw_nodes[tid] = node
            for a in vmine.values():
                if a.get("VpcId") in self.vpcs:
                    self.link(self.vpcs[a["VpcId"]]["router"], tid, kind="attachment")
            for a in mine:
                if a.get("ResourceType") == "vpc" and a.get("ResourceId") in self.vpcs:
                    self.link(self.vpcs[a["ResourceId"]]["router"], tid, kind="attachment")

    def place_devices(self) -> None:
        """Inventory devices that are EC2 instances take over the instance's node (and all its ENIs)."""
        for d in self.inv.devices.values():
            if not (d.aws and d.aws.instance_id):
                continue
            node = self.nodes.get(d.aws.instance_id)
            if node is None or node.get("kind") not in ("host",):
                self.notes.append({"account": d.aws.account or "", "region": d.aws.region or "", "call": "inventory",
                                   "reason": f"device {_s(d.name, 60)} (instance {_s(d.aws.instance_id, 40)}) was not found among the instances read"})
                continue
            old_label = node["label"]
            node.update({"id": d.name, "label": d.name, "kind": "router" if d.platform == "cisco_iosxe" else "firewall",
                         "devices": [d.name], "minor": False, "sub": _s(f"{d.platform.replace('_', ' ')} · {old_label}", 60)})
            node["detail"] = [{"title": "Inventory device", "rows": [["name", d.name], ["platform", d.platform],
                                                                     ["EC2 name", old_label]]}] + node["detail"]
            del self.nodes[d.aws.instance_id]
            self.nodes[d.name] = node
            for sub in self.subs.values():
                sub.nodes = [node if x is node else x for x in sub.nodes]
            for k, v in list(self.eni_node.items()):
                if v == d.aws.instance_id:
                    self.eni_node[k] = d.name
            for lk in self.links:
                for end in ("a", "b"):
                    if lk[end] == d.aws.instance_id:
                        lk[end] = d.name


# ==== layout ==================================================================================
def _grid(n: int, cols: int) -> tuple[int, int, int]:
    c = max(1, min(cols, n))
    return c, -(-n // c), n


def build_map(inv: Inventory, regions: list[Region]) -> dict[str, Any]:
    b = _Build(inv, regions)
    b.run()

    # -- cap crowded subnets: devices and infrastructure are always drawn, hosts are listed by name and cut at K
    def drawn(k: int) -> int:
        in_subnets = {id(n) for s in b.subs.values() for n in s.nodes}
        total = len([n for n in b.nodes.values() if id(n) not in in_subnets])
        for s in b.subs.values():
            hosts = [n for n in s.nodes if n.get("minor")]
            total += len(s.nodes) - max(0, len(hosts) - k) + (1 if len(hosts) > k else 0)
        return total

    k = 12
    while k > 1 and drawn(k) > NODE_CAP:
        k -= 1
    for s in b.subs.values():
        hosts = sorted([n for n in s.nodes if n.get("minor")], key=lambda n: (n["kind"] != "host", n["label"].lower(), n["id"]))
        if len(hosts) > k:
            hide = hosts[k:]
            hidden = {id(n) for n in hide}
            more = {"id": f"more-{s.sid}", "label": f"+{len(hide)} more", "sub": f"{len(hide)} hosts not drawn", "kind": "generic",
                    "minor": True, "group": s.sid,
                    "ids": [i for n in hide for i in n.get("ids", [])], "ips": [i for n in hide for i in n.get("ips", [])],
                    "addrs": [a for n in hide for a in n.get("addrs", [])], "find": [f for n in hide for f in n.get("find", [])],
                    "detail": [{"title": f"Hosts not drawn in {s.name or s.sid}", "items": [f"{n['label']} · {n['sub']}" for n in hide[:120]]
                                + ([f"+{len(hide) - 120} more"] if len(hide) > 120 else [])}]}
            for n in hide:
                b.nodes.pop(n["id"], None)
            b.nodes[more["id"]] = more
            s.nodes = [n for n in s.nodes if id(n) not in hidden] + [more]
            b.links = [lk for lk in b.links if lk["a"] in b.nodes and lk["b"] in b.nodes]

    # -- groups and positions, bottom up
    groups: list[dict[str, Any]] = []
    cursor_x = 30
    top_y = 30
    acct_layout: list[dict[str, Any]] = []
    tgw_owner_acct = {}
    for tid, tn in b.tgw_nodes.items():
        tgw_owner_acct[tid] = tn.pop("_owner", "")
    accounts = list(inv.aws_accounts)
    owners = [a.account_id for a in accounts if a.account_id in tgw_owner_acct.values()]
    if owners and len(accounts) > 2:  # the account that owns the Transit Gateway goes in the middle
        mid = next(a for a in accounts if a.account_id == owners[0])
        rest = [a for a in accounts if a is not mid]
        accounts = rest[: len(rest) // 2] + [mid] + rest[len(rest) // 2:]

    def place_cells(nodes_: list[dict[str, Any]], x0: float, y0: float, cols: int) -> None:
        for i, n in enumerate(nodes_):
            n["x"], n["y"] = round(x0 + (i % cols + .5) * CELL_W), round(y0 + (i // cols) * CELL_H + 44)

    for a in accounts:
        regs = b.account_regions.get(a.account_id, [])
        errs = [e for r in regs for e in r.errors]
        failed_regions = [r for r in regs if r.core_failed]
        all_failed = bool(regs) and len(failed_regions) == len(regs)
        reason = (failed_regions[0].errors[0][1] if failed_regions else errs[0][1]) if errs else ""
        node_id = f"aws-{a.account_id}"
        n_vpc = len(b.vpc_of_acct.get(a.account_id, []))
        sub = ("could not read: " + reason) if all_failed else (f"{n_vpc} VPCs" + (f" · {len(errs)} reads failed" if errs else ""))
        det: list[dict[str, Any]] = [{"title": "Account", "rows": [["name", _s(a.name, 60)], ["id", a.account_id], ["regions", ", ".join(a.regions)],
                                                                      ["VPCs read", str(n_vpc)]]}]
        nlb_n = sum(len(r.nlb) for r in regs)
        det[0]["rows"].append(["Network Load Balancers", str(nlb_n) if nlb_n else "none"])
        if errs:
            det.append({"title": "Could not read", "rows": [[op, reason_] for _r in regs for op, reason_ in _r.errors][:30]})
        anode = b.add({"id": node_id, "label": _s(a.name, 40), "sub": sub, "kind": "error" if all_failed else "account",
                       "accounts": [a.account_id], "detail": det, "group": f"g-aws-{a.account_id}"})
        band = [anode] + [tn for tid, tn in b.tgw_nodes.items() if tgw_owner_acct.get(tid) == a.account_id]
        for tn in band[1:]:
            tn["group"] = f"g-aws-{a.account_id}"
        # VPC boxes
        vpc_boxes = []
        for vid in b.vpc_of_acct.get(a.account_id, []):
            v = b.vpcs[vid]
            subs = sorted((b.subs[s] for s in v["subnets"]), key=lambda s: (s.cidr, s.sid))
            strip = list(b.vpc_strip.get(vid, []))
            sub_boxes = []
            for s in subs:
                # hosts sorted: devices first, then by name
                s.nodes.sort(key=lambda n: (n.get("minor", False), n["kind"], n["label"].lower()))
                cols, rows, n = _grid(len(s.nodes), SUBNET_COLS)
                w = max(340, cols * CELL_W + 2 * PAD)
                h = HEAD + (rows * CELL_H + PAD if s.nodes else 14)
                sub_boxes.append((s, w, h, cols))
            srows = [sub_boxes[i: i + SUBNETS_PER_ROW] for i in range(0, len(sub_boxes), SUBNETS_PER_ROW)]
            strip_cols = min(max(len(strip), 1), 6)
            strip_w = strip_cols * CELL_W
            content_w = max([strip_w] + [sum(w for _s_, w, _h, _c in row) + GAP * (len(row) - 1) for row in srows])
            strip_h = -(-len(strip) // strip_cols) * CELL_H if strip else 0
            vw = content_w + 2 * PAD
            vh = HEAD + strip_h + sum(max(h for _s_, _w, h, _c in row) + GAP for row in srows) + (PAD if not srows else 0)
            vpc_boxes.append((v, subs, strip, srows, strip_cols, strip_h, vw, vh))
        band_w = len(band) * CELL_W + 2 * PAD
        acct_w = max([band_w, 420] + [vb[6] + 2 * PAD for vb in vpc_boxes])
        acct_h = HEAD + CELL_H + 6 + sum(vb[7] + GAP for vb in vpc_boxes) + PAD
        acct_layout.append({"a": a, "band": band, "vpcs": vpc_boxes, "w": acct_w, "h": acct_h})

    x = cursor_x
    max_h = 0
    for al in acct_layout:
        a, band, w, h = al["a"], al["band"], al["w"], al["h"]
        ay = top_y
        gid = f"g-aws-{a.account_id}"
        groups.append({"id": gid, "label": f"AWS · {_s(a.name, 40)}", "meta": a.account_id, "kind": "aws", "x": x, "y": ay, "w": w, "h": h})
        # band: account node left, Transit Gateway(s) centred
        for i, n in enumerate(band):
            if i == 0:
                n["x"], n["y"] = round(x + PAD + CELL_W / 2), ay + HEAD + 44
            else:
                tx = x + w / 2 + (i - 1) * CELL_W
                n["x"] = round(tx if tx - CELL_W / 2 >= x + PAD + CELL_W else x + PAD + (i + .5) * CELL_W)
                n["y"] = ay + HEAD + 44
        y = ay + HEAD + CELL_H + 6
        for (v, _subs, strip, srows, strip_cols, strip_h, _vw, vh) in al["vpcs"]:
            vx = x + PAD
            vgid = f"g-vpc-{v['id']}"
            cidr = ", ".join(v["cidrs"][:2]) + (f" +{len(v['cidrs']) - 2}" if len(v["cidrs"]) > 2 else "")
            vname = v["name"] or ("default VPC" if v["default"] else "")
            groups.append({"id": vgid, "label": _titled(vname, cidr, 52) if vname else f"{_short(v['id'], 22)} · {cidr}",
                           "meta": f"{v['id']} · {v['region']}" + (" · default VPC" if v["default"] and v["name"] else ""), "kind": "vpc",
                           "parent": gid, "x": vx, "y": y, "w": w - 2 * PAD, "h": vh})
            for n in strip:
                n["group"] = vgid
            place_cells(strip, vx + PAD, y + HEAD, strip_cols)
            sy = y + HEAD + strip_h
            for row in srows:
                sx = vx + PAD
                rh = max(h_ for _s_, _w, h_, _c in row)
                for s, sw, sh, cols in row:
                    meta = " · ".join(p for p in (s.az, s.meta_route) if p)
                    groups.append({"id": f"g-sub-{s.sid}", "label": _titled(s.name, s.cidr), "meta": meta, "kind": "subnet",
                                   "parent": vgid, "x": sx, "y": sy, "w": sw, "h": sh})
                    for n in s.nodes:
                        n["group"] = f"g-sub-{s.sid}"
                    place_cells(s.nodes, sx + (sw - cols * CELL_W) / 2, sy + HEAD - 6, cols)
                    sx += sw + GAP
                sy += rh + GAP
            y += vh + GAP
        x += w + 44
        max_h = max(max_h, h)

    width = x
    nodes = list(b.nodes.values())
    if "internet" in b.nodes:
        inet = b.nodes["internet"]
        inet["x"], inet["y"] = round(width + 100), top_y + 120
        width += 260
    # nodes that were never placed (e.g. a TGW whose owner account is not in the inventory) go in a column at the right
    spare = [n for n in nodes if "x" not in n]
    for i, n in enumerate(spare):
        n["x"], n["y"] = round(width - 130), top_y + 300 + i * CELL_H
        n.pop("group", None)
    for n in nodes:
        n.pop("_owner", None)
        n.pop("_service", None)
        n.setdefault("detail", [])
    notes = b.notes
    hosts = [n for n in nodes if n["kind"] in ("host", "eni")]
    if len(hosts) <= 60:  # a small map keeps host names visible when zoomed out; a big one fades them
        for n in hosts:
            n["minor"] = False
    counts = {"accounts": len(accounts), "vpcs": len(b.vpcs), "subnets": len(b.subs), "nodes": len(nodes), "links": len(b.links),
              "instances": b.n_instances, "load_balancers": len(b.nlb_by_arn), "transit_gateways": len(b.tgw_nodes),
              "read_failures": len(notes)}
    topo = {"title": f"AWS · {counts['accounts']} accounts · {counts['vpcs']} VPCs", "size": [width + 40, max_h + top_y + 50],
            "groups": groups, "nodes": nodes, "links": b.links, "notes": notes, "counts": counts, "aws_map": True}
    return topo


# ==== entry point ===============================================================================
def build_aws_map(inv: Inventory, *, progress: Progress | None = None, env: AwsEnv | None = None) -> dict[str, Any]:
    """Read every inventory account and region (read-only) and return the topology. Reads run in parallel, one worker
    per account and region. A read that fails is recorded on the map; this never raises for an AWS error."""
    own = env is None
    env = env or AwsEnv(inv)
    pairs = env.targets()
    if progress:
        progress(f"reading {len(pairs)} account/region pairs from AWS (read-only)")
    try:
        if len(pairs) <= 1:
            regions = [_read_region(env, a, r, progress) for a, r in pairs]
        else:
            ctxs = [contextvars.copy_context() for _ in pairs]
            with ThreadPoolExecutor(max_workers=min(8, len(pairs))) as pool:
                regions = list(pool.map(lambda pc: pc[0].run(_read_region, env, pc[1][0], pc[1][1], progress), zip(ctxs, pairs, strict=True)))
    finally:
        if own:
            env.close()
    return build_map(inv, regions)


def merge_with_inventory(aws: dict[str, Any], base: dict[str, Any]) -> dict[str, Any]:
    """An inventory with on-prem sites or Prisma Access as well as AWS: keep those boxes of `base` (the usual auto
    topology) on the left and draw the AWS map to their right. Links in `base` that named an AWS account node
    (`aws-<account id>`) still find it, because the AWS map's account nodes use the same ids."""
    keep_groups = [g for g in base["groups"] if not str(g["id"]).startswith("g-aws-")]
    aws_node_ids = {n["id"] for n in aws["nodes"]}
    keep_nodes = [n for n in base["nodes"] if n.get("group") in {g["id"] for g in keep_groups} or (n.get("group") is None and n["id"] != "internet")]
    keep_nodes = [n for n in keep_nodes if n["id"] not in aws_node_ids]
    if not keep_groups and not keep_nodes:
        return aws
    shift = max([g["x"] + g["w"] for g in keep_groups] + [30]) + 40
    for g in aws["groups"]:
        g["x"] += shift
    for n in aws["nodes"]:
        n["x"] += shift
    known = {n["id"] for n in keep_nodes} | aws_node_ids
    inet_base = next((n for n in base["nodes"] if n["id"] == "internet"), None)
    links = [lk for lk in base["links"] if lk["a"] in known | {"internet"} and lk["b"] in known | {"internet"}]
    out = dict(aws)
    out["groups"] = keep_groups + aws["groups"]
    out["nodes"] = keep_nodes + aws["nodes"]
    if inet_base and "internet" not in aws_node_ids:
        out["nodes"].append({**inet_base, "x": aws["size"][0] + shift - 120, "y": 150})
    out["links"] = [lk for lk in links if lk["a"] in {n["id"] for n in out["nodes"]} and lk["b"] in {n["id"] for n in out["nodes"]}] + aws["links"]
    out["size"] = [aws["size"][0] + shift, max(aws["size"][1], base["size"][1])]
    return out
