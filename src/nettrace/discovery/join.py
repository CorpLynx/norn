"""Observations -> candidate links (docs/discovery-spec.md section 9). Pure: no I/O, no clock.

A link is `learned` only when two observations from different sources agree on both ends. Anything weaker is
`inferred`. One end that matches two different far ends makes every such link inferred, with `conflicts`.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field, replace

from nettrace.discovery.links import end_key, make_id, node_of
from nettrace.discovery.model import (AwsVpn, Candidate, Observation, PrismaTunnel, Provenance, TunnelEnd, join_ip,
                                      normalise_interface)
from nettrace.inventory import Inventory, Link, LinkEnd


@dataclass
class JoinResult:
    links: list[Link] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)


def _oper(*states: str) -> str:
    if "down" in states:
        return "down"
    if states and all(s == "up" for s in states):
        return "up"
    return "unknown"


def _owner(inv: Inventory, ip: str | None) -> str | None:
    """The one inventory device owning `ip` (static address or unambiguous discovery cache entry)."""
    if not ip:
        return None
    hit = inv.device_by_address(ip)
    return hit[0].name if hit else None


class _Builder:
    def __init__(self, inv: Inventory) -> None:
        self.inv = inv
        self.links: dict[str, Link] = {}

    def add(self, kind: str, origin: str, a: LinkEnd, b: LinkEnd, oper: str, provs: Iterable[Provenance]) -> None:
        lid = make_id(kind, a, b, self.inv)
        provs = tuple(provs)
        seen = min((p.observed_at for p in provs), default=0.0)
        old = self.links.get(lid)
        if old:  # the same link found again (e.g. from both tunnel ends): keep the stronger origin, merge provenance
            merged = tuple(dict.fromkeys(old.provenance + provs))
            origin = "learned" if "learned" in (old.origin, origin) else origin
            self.links[lid] = replace(old, origin=origin, provenance=merged, oper=_oper(old.oper, oper),
                                      last_confirmed=min(old.last_confirmed, seen))
            return
        self.links[lid] = Link(name=f"{a.label()} <-> {b.label()}", a=a, b=b, origin=origin, kind=kind, oper=oper,
                               id=lid, provenance=provs, first_seen=seen, last_confirmed=seen)


def _device_end(inv: Inventory, t: TunnelEnd) -> LinkEnd:
    dev = inv.devices.get(t.device)
    return LinkEnd(device=t.device, interface=normalise_interface(t.interface, dev.platform if dev else None))


def join(observations: Iterable[Observation], inv: Inventory) -> JoinResult:
    obs = list(observations)
    tunnels = [o for o in obs if isinstance(o, TunnelEnd) and o.device in inv.devices]
    vpns = [o for o in obs if isinstance(o, AwsVpn)]
    prisma = [o for o in obs if isinstance(o, PrismaTunnel) and o.kind == "service_connection"]
    b = _Builder(inv)
    candidates: dict[tuple[str, str], Candidate] = {}
    used: set[int] = set()  # tunnels (by index) that took part in some link

    # 1. device tunnel <-> AWS VPN tunnel: peer = AWS outside IP; local = customer gateway IP (else NAT: inferred)
    by_outside: dict[str, list[AwsVpn]] = defaultdict(list)
    for v in vpns:
        if (k := join_ip(v.outside_ip)):
            by_outside[k].append(v)
    for i, t in enumerate(tunnels):
        peer = join_ip(t.peer_ip)
        for v in by_outside.get(peer or "", []):
            used.add(i)
            if v.tgw_attachment:
                far = LinkEnd(aws_tgw_attachment=v.tgw_attachment, aws_account=v.account, aws_region=v.region)
            elif v.vgw_id and not v.tgw_id:
                far = LinkEnd(aws_vgw=v.vgw_id, aws_account=v.account, aws_region=v.region)
            else:  # TGW VPN without a known attachment id: the engine could not use the far end
                candidates[(t.device, peer or "")] = Candidate(
                    t.device, peer or "", f"AWS VPN {v.vpn_id} tunnel; TGW attachment id not known")
                continue
            local = join_ip(t.local_ip)
            origin = "learned" if local and local == join_ip(v.cgw_ip) else "inferred"
            b.add("aws-vpn", origin, _device_end(inv, t), far, _oper(t.oper, v.oper), (t.prov, v.prov))

    # 2. device tunnel <-> Prisma service connection: SC's customer-side IP = tunnel local IP, owned by that device only
    by_local: dict[str, list[tuple[int, TunnelEnd]]] = defaultdict(list)
    for i, t in enumerate(tunnels):
        if (k := join_ip(t.local_ip)):
            by_local[k].append((i, t))
    for p in prisma:
        peer = join_ip(p.peer_ip)
        if not peer:
            continue
        far = LinkEnd(prisma_service_connection=p.name)
        owner = _owner(inv, peer)
        matched = by_local.get(peer, [])
        for i, t in matched:
            used.add(i)
            origin = "learned" if t.oper == "up" and owner == t.device else "inferred"
            b.add("prisma", origin, _device_end(inv, t), far, t.oper, (t.prov, p.prov))
        if not matched:
            if owner:  # SCM alone
                b.add("prisma", "inferred", LinkEnd(device=owner), far, "unknown", (p.prov,))
            else:
                candidates[("scm", peer)] = Candidate("scm", peer, f"service connection {p.name} peer, not in inventory")

    # 3. device tunnel <-> device tunnel: each one's peer is the other's local
    by_pair: dict[tuple[str, str], list[tuple[int, TunnelEnd]]] = defaultdict(list)
    for i, t in enumerate(tunnels):
        lo, pe = join_ip(t.local_ip), join_ip(t.peer_ip)
        if lo and pe:
            by_pair[(lo, pe)].append((i, t))
    for i, t in enumerate(tunnels):
        if i in used:
            continue
        lo, pe = join_ip(t.local_ip), join_ip(t.peer_ip)
        if not pe:
            continue
        mates = [(j, m) for j, m in by_pair.get((pe, lo or ""), []) if m.device != t.device] if lo else []
        for j, m in mates:
            used.update((i, j))
            kind = t.kind if t.kind == m.kind and t.kind in ("ipsec", "gre") else "unknown"
            b.add(kind, "learned", _device_end(inv, t), _device_end(inv, m), _oper(t.oper, m.oper), (t.prov, m.prov))
        if mates:
            continue
        owner = _owner(inv, pe)
        if owner and owner != t.device:
            used.add(i)
            kind = t.kind if t.kind in ("ipsec", "gre") else "unknown"
            b.add(kind, "inferred", _device_end(inv, t), LinkEnd(device=owner), t.oper, (t.prov,))
        elif not owner:
            candidates[(t.device, pe)] = Candidate(t.device, pe, f"tunnel peer of {t.interface}, not in inventory")

    links = _mark_conflicts(list(b.links.values()), inv)
    return JoinResult(links=sorted(links, key=lambda lk: lk.id),
                      candidates=sorted(candidates.values(), key=lambda c: (c.seen_by, c.address)))


def _platform(inv: Inventory, end: LinkEnd) -> str | None:
    dev = inv.devices.get(end.device or "")
    return dev.platform if dev else None


def _mark_conflicts(links: list[Link], inv: Inventory) -> list[Link]:
    """An end that leads to two different nodes is ambiguous: every link through it becomes inferred and names the
    others. A device end is keyed by (device, interface); an AWS/Prisma end by its id, so two tunnels from one device
    to the same VPN connection are not a conflict."""
    by_end: dict[tuple[str, ...], list[Link]] = defaultdict(list)
    for lk in links:
        for here in (lk.a, lk.b):
            by_end[end_key(here, _platform(inv, here))].append(lk)
    conflicts: dict[str, set[str]] = defaultdict(set)
    for key, group in by_end.items():
        far_nodes = set()
        for lk in group:
            here_is_a = end_key(lk.a, _platform(inv, lk.a)) == key
            far_nodes.add(node_of(lk.b if here_is_a else lk.a))
        if len(far_nodes) > 1:
            for lk in group:
                conflicts[lk.id].update(o.id for o in group if o.id != lk.id)
    return [replace(lk, origin="inferred", conflicts=tuple(sorted(conflicts[lk.id]))) if conflicts.get(lk.id) else lk
            for lk in links]
