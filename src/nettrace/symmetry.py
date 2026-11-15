"""Return-path trace helpers: build the reverse flow and compare the two directions (G15).

The comparison reads STRUCTURED hop fields only (domain, node, component, ingress, egress, location). It never parses
summary text. Anything it cannot decide is UNKNOWN, never SYMMETRIC: a path nettrace could not finish proves nothing.

What "stateful" means here: PAN-OS firewalls and Prisma Access keep a session per flow, so a reply that arrives at a
different firewall (or a different member of an HA pair) than the request is dropped as an invalid mid-stream packet.
AWS network ACLs and Cisco IOS-XE ACLs are stateless and do not care. AWS security groups are stateful but follow the
ENI, so they cannot differ between the directions of one flow (their hops are not compared).
"""

from __future__ import annotations

from nettrace.models import (
    Flow,
    Hop,
    Outcome,
    ReturnPath,
    Status,
    Symmetry,
    SymmetryStatus,
    TraceResult,
)
from nettrace.netutil import DEFAULT_EPHEMERAL_PORT, uses_ports

DEVICE_DOMAINS = frozenset({"cisco", "panos", "prisma"})
STATEFUL_DOMAINS = frozenset({"panos", "prisma"})
# AWS path elements that identify a route through the cloud network (not the endpoints' own SG / NACL / subnet route table)
# NOT listed, on purpose (D21): "interface-endpoint", "nlb" and "target-group". They are not routed hops. A reply
# returns over the connection the load balancer holds, not through them, so the return trace never contains them and
# listing them would call every PrivateLink / NLB path ASYMMETRIC. untraceable_return() below covers the cases where the
# return trace itself would be meaningless.
TRANSIT_COMPONENTS = frozenset({"tgw-route-table", "nat-gateway", "vgw", "vpc-peering", "gwlb-endpoint",
                                "internet-gateway", "vpc-endpoint"})


def return_flow(fwd: TraceResult) -> tuple[Flow, list[str]]:
    """The reverse of the forward flow, plus notes about what was assumed.

    - Source = the address the destination really has: after destination NAT that is the translated address
      (the forward trace's final flow), otherwise the original destination.
    - Destination = the ORIGINAL source. Source NAT is undone by the translating device; nettrace does not model that.
    - Ports (tcp/udp/sctp): the forward destination port becomes the source port. The return destination port is the
      forward source port if one was given, else the ephemeral port 49152 (the same assumption the AWS NACL return
      check makes). icmp and other protocols carry no ports."""
    orig = fwd.flow
    seen = fwd.final_flow or orig
    notes: list[str] = []
    ports = uses_ports(orig.protocol)
    src_port = seen.dst_port if ports else None
    dst_port = None
    if ports:
        dst_port = orig.src_port or DEFAULT_EPHEMERAL_PORT
        if not orig.src_port:
            notes.append(f"return destination port {DEFAULT_EPHEMERAL_PORT} is an assumed ephemeral port "
                         "(pass --source-port to use the real one)")
    if seen.dst != orig.dst or seen.dst_port != orig.dst_port:
        notes.append(f"destination NAT in the forward direction: the return flow starts at {seen.dst}"
                     f"{f':{seen.dst_port}' if seen.dst_port else ''}, the address the destination really has")
    if seen.src != orig.src:
        notes.append(f"source NAT in the forward direction ({orig.src} became {seen.src}): the return flow is "
                     f"addressed to {orig.src}; the un-NAT on the translating device is not evaluated")
    flow = Flow(src=seen.dst, dst=orig.src, protocol=orig.protocol, src_port=src_port, dst_port=dst_port,
                application=orig.application)  # no user: the user belongs to the forward source
    return flow, notes


def stateful_reply_enis(fwd: TraceResult) -> dict[str, int]:
    """ENIs whose security groups the reply passes because they passed the request (D16, amended 2026-11-14).

    AWS security groups are stateful per ENI: a response to traffic a group allowed is allowed whatever the rules say.
    That is documented AWS behaviour, not a session-table guess, but it holds only when the reply at that ENI is the
    exact reverse of what the group saw. So only the two endpoints count, and only when the forward hops prove it:
    - the source ENI: the security-group egress PASS before the first route lookup (no NAT can happen before it);
    - the destination ENI: the ingress PASS on the ENI the trace delivered to, and only without source NAT (with SNAT
      the reply really goes to the translated address, which the return trace does not follow).
    Returns {eni_id: forward hop index}. Anything else on the return path is evaluated as a new session, as before."""
    out: dict[str, int] = {}
    if fwd.outcome != Outcome.REACHABLE:
        return out
    for h in fwd.hops:
        if h.domain != "aws":
            continue
        if h.component == "route-table":
            break
        if h.component == "security-group" and h.status == Status.PASS and h.egress:
            out[h.egress] = h.index
    last = fwd.hops[-1] if fwd.hops else None
    seen = fwd.final_flow or fwd.flow
    if last is not None and last.domain == "aws" and last.component == "eni" and last.status == Status.PASS \
            and seen.src == fwd.flow.src:
        sg = next((h for h in reversed(fwd.hops[:-1]) if h.domain == "aws" and h.component == "security-group"), None)
        if sg is not None and sg.status == Status.PASS and sg.ingress == last.node:
            out[last.node] = sg.index
    return out


def untraceable_return(fwd: TraceResult) -> str | None:
    """Why a return trace would mean nothing for this forward path, or None (D21).

    PrivateLink: the provider sees the NLB node, not the client, and the client's address need not be routable from the
    provider VPC (overlapping ranges are normal); the reply travels back over the same connection. An NLB that replaced
    the source address (client IP not preserved) likewise: the real reply goes to the NLB node, and a trace to the original
    client would follow a path no packet takes. With the client address preserved the reply is routed to the client like
    any other, so that case is traced normally."""
    lb = [h for h in fwd.hops if h.domain == "aws" and h.component in ("interface-endpoint", "nlb")]
    if not lb:
        return None
    if any(h.component == "interface-endpoint" for h in lb):
        return ("the path crosses AWS PrivateLink: the reply returns over the same connection, and the client "
                "address is not what the service sees")
    seen = fwd.final_flow or fwd.flow
    if seen.src != fwd.flow.src:
        return "the NLB replaced the source address, so the reply is addressed to the NLB node, not the client"
    return None


def not_run(fwd: TraceResult, reason: str) -> ReturnPath:
    flow, _ = return_flow(fwd)
    return ReturnPath(flow=flow, outcome=None, reason=reason,
                      symmetry=Symmetry(SymmetryStatus.NOT_RUN, [reason]))


def _element(h: Hop) -> tuple[str, str, str] | None:
    if h.domain in DEVICE_DOMAINS:
        return (h.domain, "", h.node)
    if h.domain == "aws" and h.component == "tgw-route-table" and h.location.get("tgw"):
        # A TGW picks the route table by the attachment traffic enters from, so a request and its reply normally use
        # different tables of the same TGW. Compare the TGW and the attachments it uses (ingress/egress), not the
        # table: a reply that leaves by another attachment (around an inspection VPC) still differs.
        return (h.domain, "tgw", h.location["tgw"])
    if h.domain == "aws" and h.component in TRANSIT_COMPONENTS:
        return (h.domain, h.component, h.node)
    return None


def _label(key: tuple[str, str, str]) -> str:
    domain, component, node = key
    if domain == "aws":
        return f"{component} {node}"
    return node if domain != "panos" else f"{node} (PAN-OS firewall)"


def _collect(hops: list[Hop]) -> dict[tuple[str, str, str], dict[str, set[str]]]:
    out: dict[tuple[str, str, str], dict[str, set[str]]] = {}
    for h in hops:
        key = _element(h)
        if key is None:
            continue
        e = out.setdefault(key, {"interfaces": set(), "zones": set(), "members": set()})
        e["interfaces"].update(x for x in (h.ingress, h.egress) if x)
        e["zones"].update(h.location[k] for k in ("zone_from", "zone_to") if h.location.get(k))
        if h.location.get("serial"):
            e["members"].add(h.location["serial"])
    return out


def _stateful(key: tuple[str, str, str]) -> bool:
    return key[0] in STATEFUL_DOMAINS


def _blocking_hop(hops: list[Hop]) -> Hop | None:
    return next((h for h in hops if h.status == Status.BLOCK), None)


def _is_stateful_hop(h: Hop) -> bool:
    return h.domain in STATEFUL_DOMAINS or (h.domain == "aws" and h.component == "security-group")


def _fmt(values: set[str]) -> str:
    return ", ".join(sorted(values))


def compare(fwd: TraceResult, rflow: Flow, rres: TraceResult, notes: list[str]) -> ReturnPath:
    """Build the Return section from the finished forward trace and the finished return trace."""
    offset = len(fwd.hops)
    for i, h in enumerate(rres.hops, start=offset + 1):  # unique hop numbers across the whole result
        h.index = i

    details: list[str] = []
    outcome, reason = rres.outcome, rres.reason
    unknown_hops = [h for h in rres.hops if h.status == Status.UNKNOWN]

    if outcome == Outcome.BLOCKED:
        blocker = _blocking_hop(rres.hops)
        if blocker is not None and _is_stateful_hop(blocker):
            # The return flow was evaluated as a NEW session. A stateful device lets the reply of an established
            # session through whatever its rules say, and nettrace does not read session tables: so this is not
            # evidence that the return path is blocked.
            outcome = Outcome.INCOMPLETE
            reason = (f"return path unverified: {rres.reason}. {blocker.node} is stateful: a reply of an established "
                      "session is normally allowed by its session table, which nettrace does not read, so this is "
                      "not proof that the return path is blocked; nothing past it was evaluated")
        else:
            reason = f"return path blocked: {rres.reason}"

    f_el, r_el = _collect(fwd.hops), _collect(rres.hops)
    found: list[tuple[bool, str]] = []  # (stateful, text): stateful differences are listed first
    unclear: list[str] = []
    complete = outcome in (Outcome.REACHABLE, Outcome.EXITED)  # a return trace that stopped early did not reach the rest
    for key in sorted(set(f_el) - set(r_el) if complete else ()):
        found.append((_stateful(key), f"{_label(key)} is on the forward path only"
                     + (" (stateful: its session table has seen one direction only)" if _stateful(key) else "")))
    for key in sorted(set(r_el) - set(f_el)):
        found.append((_stateful(key), f"{_label(key)} is on the return path only"
                     + (" (stateful: it never saw the forward direction)" if _stateful(key) else "")))
    for key in sorted(set(f_el) & set(r_el)):
        for what in ("members", "interfaces", "zones"):
            a, b = f_el[key][what], r_el[key][what]
            if a and b and a != b:
                found.append((_stateful(key), f"{_label(key)}: forward uses {what[:-1] if what == 'members' else what} "
                              f"[{_fmt(a)}], return uses [{_fmt(b)}]" + (" (stateful)" if _stateful(key) else "")))
            elif bool(a) != bool(b):
                unclear.append(f"{_label(key)}: {what} reported in one direction only; not compared")

    diffs = [text for _, text in sorted(found, key=lambda t: not t[0])]
    if rres.outcome == Outcome.EXITED:
        details.append(f"the return path leaves the known network ({rres.reason}); delivery to the source is not verified")

    if outcome in (Outcome.INCOMPLETE, Outcome.BLOCKED) or unknown_hops or unclear:
        # one direction is blocked or unverified: there is no complete pair of paths to compare
        status = SymmetryStatus.UNKNOWN
        if outcome == Outcome.INCOMPLETE:
            details.append(reason if reason.startswith("return path unverified") else f"return path unverified: {reason}")
        elif outcome == Outcome.BLOCKED:
            details.append(reason)
        if unknown_hops:
            details.append("UNKNOWN hop(s) on the return path: "
                           + ", ".join(sorted({h.node for h in unknown_hops})))
        details.extend(unclear)
        if diffs:
            details.append("differences seen on the part that was traced: " + "; ".join(diffs))
    elif diffs:
        status = SymmetryStatus.ASYMMETRIC
        details = diffs + details
    else:
        status = SymmetryStatus.SYMMETRIC
        names = sorted(_label(k) for k in f_el)
        details.insert(0, "both directions cross the same " + (", ".join(names) if names else
                       "path: no device or transit element beyond the endpoints' own security groups and NACLs"))
    details.extend(notes)  # assumptions last: the finding comes first
    warnings = list(rres.warnings)
    return ReturnPath(flow=rflow, outcome=outcome, reason=reason, hops=rres.hops, warnings=warnings,
                      symmetry=Symmetry(status, details), cancelled=rres.cancelled)


def forward_warnings(rp: ReturnPath) -> list[str]:
    """Lines added to the forward result's Warnings so the table/text output and exit-code story stay visible."""
    out: list[str] = []
    s = rp.symmetry
    if rp.outcome == Outcome.BLOCKED:
        out.append(rp.reason)
    elif s.status == SymmetryStatus.ASYMMETRIC:
        out.append("return path is asymmetric: " + "; ".join(s.details[:3]))
    elif s.status == SymmetryStatus.UNKNOWN:
        out.append("return path could not be verified: " + rp.reason)
    return out
