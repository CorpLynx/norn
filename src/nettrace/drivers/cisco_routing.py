"""Why is there no route? Extra read-only evidence for a Cisco hop that has no forwarding entry.

This runs only after the router has already said it has no route (empty `show ip cef` lookup). It adds
detail lines and evidence from the BGP table, the BGP neighbor list and the static-route table so the
BLOCK says why. Rules:

- The verdict never changes because of this evidence, with one exception: if the BGP table or the static
  table says a usable route exists while CEF has none, the two disagree and nettrace cannot tell which is
  right. That hop is UNKNOWN (`RouteDiagnosis.contradiction`), never BLOCK (AGENTS.md rule 3, never guess).
- Output nettrace cannot read becomes a "not interpreted" detail line. It is never read as "no routes".
- A command the device rejects (feature missing on this image, BGP not running) becomes a detail line.
  A deadline or cancel is not caught here; it ends the trace as it does anywhere else.
- At most three extra commands: BGP prefix lookup, BGP summary, static-route table.

Formats were written from IOS-XE documentation and memory, not captured from a device: the static-route
table (`show ip static route`) in particular must be checked against real output before it is trusted
(docs/gaps-and-roadmap.md).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from nettrace.drivers.ntc import ntc_parse
from nettrace.errors import DeviceError
from nettrace.readonly import safe_token
from nettrace.steps import RouteDiagnosis

MAX_NEIGHBORS_SHOWN = 10


# ---- BGP prefix lookup -------------------------------------------------------------------
@dataclass
class BgpPrefix:
    state: str  # absent | best | no-best | unparsed
    prefix: str | None = None
    paths: int = 0
    inaccessible: int = 0


_NOT_IN_TABLE = re.compile(r"%\s*Network not in table", re.I)
_ENTRY = re.compile(r"BGP routing table entry for ([^\s,]+)", re.I)
_PATHS = re.compile(r"Paths:\s*\((\d+) available,\s*(best #\d+|no best path)", re.I)


def parse_bgp_prefix(output: str) -> BgpPrefix:
    """`show ip bgp <ip>` (or the vpnv4 vrf form) -> what the BGP table holds for that address."""
    if _NOT_IN_TABLE.search(output):
        return BgpPrefix("absent")
    entry = _ENTRY.search(output)
    paths = _PATHS.search(output)
    if not entry or not paths:
        return BgpPrefix("unparsed")
    return BgpPrefix(
        state="no-best" if paths.group(2).lower().startswith("no best") else "best",
        prefix=entry.group(1), paths=int(paths.group(1)),
        inaccessible=len(re.findall(r"\(inaccessible\)", output, re.I)),
    )


# ---- BGP neighbors -----------------------------------------------------------------------
@dataclass
class BgpNeighbor:
    address: str
    asn: str
    up_down: str
    state: str  # "Established" or the state text the router printed (Idle, Active, Idle (Admin), ...)


def parse_bgp_summary(output: str) -> list[BgpNeighbor]:
    rows = ntc_parse("show ip bgp summary", output)
    if output.strip() and "neighbor" in output.lower() and not rows:
        raise DeviceError("could not read the BGP neighbor table")  # a table we cannot parse is not "no neighbors"
    out = []
    for r in rows:
        s = (r.get("STATE_OR_PREFIXES_RECEIVED") or "").strip()
        out.append(BgpNeighbor(r.get("BGP_NEIGHBOR", ""), r.get("NEIGHBOR_AS", ""), r.get("UP_DOWN", ""),
                               "Established" if re.fullmatch(r"\d+", s) else (s or "?")))
    return out


# ---- static routes -----------------------------------------------------------------------
@dataclass
class StaticRoute:
    prefix: str
    via: str
    distance: str
    flag: str | None  # code in [] at the end of the line when the image prints one: A active, N non-active, ...
    line: str

    @property
    def active(self) -> bool | None:
        if self.flag is None:
            return None
        return True if self.flag == "A" else False if self.flag in ("N", "X") else None


_STATIC_LINE = re.compile(
    r"^\s*(?:[A-Z]{1,5}\s+)?(?P<prefix>\d+\.\d+\.\d+\.\d+/\d+)\s+(?:\[(?P<ad>\d+)/\d+\]\s+)?via\s+(?P<via>\S+)"
    r"(?P<rest>.*)$", re.M)


def parse_static_routes(output: str) -> list[StaticRoute]:
    """Route lines from `show ip static route`: prefix, optional [AD/metric], via, optional trailing [flag]."""
    out = []
    for m in _STATIC_LINE.finditer(output):
        flag = re.search(r"\[([A-Z]+)\]\s*$", m.group("rest"))
        out.append(StaticRoute(m.group("prefix"), m.group("via"), m.group("ad") or "?",
                               flag.group(1) if flag else None, m.group(0).strip()))
    return out


def covering(routes: list[StaticRoute], ip: str) -> list[StaticRoute]:
    addr = ipaddress.ip_address(ip)
    hit = [r for r in routes if addr in ipaddress.ip_network(r.prefix, strict=False)]
    return sorted(hit, key=lambda r: -ipaddress.ip_network(r.prefix, strict=False).prefixlen)


# ---- the diagnosis -----------------------------------------------------------------------
def _ask(client: Any, command: str, what: str, diag: RouteDiagnosis) -> str | None:
    """Run one evidence command. None = the device could not answer (a detail line says so)."""
    try:
        return client.show(command)
    except DeviceError as exc:
        msg = str(exc)
        if re.search(r"BGP not active|BGP is not", msg, re.I):
            diag.lines.append("BGP is not running on this router")
        elif re.search(r"Invalid input|Incomplete command|Unrecognized command", msg):
            diag.lines.append(f"{what}: this router image does not support '{command}'")
        else:
            diag.lines.append(f"{what}: could not be read ({msg.split(': ', 1)[-1][:120]})")
        return None


def explain_missing_route(client: Any, dst: str, vrf: str | None) -> RouteDiagnosis:
    ipaddress.ip_address(dst)
    diag = RouteDiagnosis()
    vrf_name = safe_token(vrf, "vrf") if vrf and vrf not in ("default", "global") else None
    bgp_prefix = f"show ip bgp vpnv4 vrf {vrf_name} {dst}" if vrf_name else f"show ip bgp {dst}"
    bgp_summary = f"show ip bgp vpnv4 vrf {vrf_name} summary" if vrf_name else "show ip bgp summary"
    static_cmd = f"show ip static route vrf {vrf_name}" if vrf_name else "show ip static route"
    reasons: list[str] = []

    # BGP: is there a path at all?
    out = _ask(client, bgp_prefix, "BGP table", diag)
    if out is not None:
        bgp = parse_bgp_prefix(out)
        if bgp.state == "unparsed":
            diag.lines.append(f"BGP table: reply to '{bgp_prefix}' not interpreted (see evidence)")
        elif bgp.state == "best":
            diag.contradiction = True
            diag.lines.append(f"BGP has a best path for {bgp.prefix} but the router has no forwarding entry for {dst}: "
                              "possibly a RIB failure (a route from another source won) or a timing gap. "
                              "nettrace cannot tell which")
            reasons.append("BGP shows a best path but CEF has none")
        else:
            if bgp.state == "absent":
                diag.lines.append(f"BGP: no path for {dst} in the BGP table (no neighbor advertises it, or an "
                                  "inbound filter drops it)")
                reasons.append("no path in the BGP table")
            else:
                why = (f"; {bgp.inaccessible} with an inaccessible next hop (no route to the BGP next hop)"
                       if bgp.inaccessible else "")
                diag.lines.append(f"BGP: {bgp.paths} path(s) for {bgp.prefix} but none is best{why}")
                reasons.append("BGP paths exist but none is best")
            # No usable path: which neighbors are down?
            summary = _ask(client, bgp_summary, "BGP neighbors", diag)
            if summary is not None:
                try:
                    neighbors = parse_bgp_summary(summary)
                except DeviceError:
                    diag.lines.append(f"BGP neighbors: reply to '{bgp_summary}' not interpreted (see evidence)")
                else:
                    down = [n for n in neighbors if n.state != "Established"]
                    if not neighbors:
                        diag.lines.append("BGP neighbors: none configured")
                    elif not down:
                        diag.lines.append(f"BGP neighbors: all {len(neighbors)} Established, so the missing route "
                                          "is not a neighbor outage")
                    else:
                        shown = ", ".join(f"{n.address} AS{n.asn} {n.state} ({n.up_down})"
                                          for n in down[:MAX_NEIGHBORS_SHOWN])
                        more = f" and {len(down) - MAX_NEIGHBORS_SHOWN} more" if len(down) > MAX_NEIGHBORS_SHOWN else ""
                        diag.lines.append(f"BGP neighbors not Established ({len(down)} of {len(neighbors)}): "
                                          f"{shown}{more}")
                        reasons.append(f"{len(down)} of {len(neighbors)} BGP neighbors not Established")

    # Static routes: is one configured for this destination but not installed?
    out = _ask(client, static_cmd, "static routes", diag)
    if out is not None:
        routes = parse_static_routes(out)
        if not routes:
            diag.lines.append(("static routes: no route lines found in the reply (see evidence)" if out.strip()
                               else "static routes: none returned"))
        else:
            hit = covering(routes, dst)
            if not hit:
                diag.lines.append(f"static routes: none of the {len(routes)} listed covers {dst}")
            for r in hit[:3]:
                if r.active:
                    diag.contradiction = True
                    diag.lines.append(f"static route {r.line} is marked active but the router has no forwarding "
                                      f"entry for {dst}: nettrace cannot tell which is right")
                    reasons.append("a static route is marked active but CEF has none")
                elif r.active is False:
                    diag.lines.append(f"static route {r.line} covers {dst} but is not installed "
                                      "(next hop or interface unresolved, or a tracked object is down)")
                    reasons.append(f"static route {r.prefix} configured but not installed")
                else:
                    diag.lines.append(f"static route {r.line} covers {dst}; the table does not say whether it is "
                                      "installed, and the routing table has no entry for it")
                    reasons.append(f"static route {r.prefix} configured, install state unknown")
    diag.reason = "; ".join(dict.fromkeys(reasons))
    return diag


def floating_static_note(source: str | None) -> str | None:
    """Detail line when the route in use is a static route with a non-default distance. `source` is the label
    from parse_route_source, which adds "(distance N)" to a static route only when N is not 1."""
    m = re.fullmatch(r"static \(distance (\d+)\)", source or "")
    if not m:
        return None
    return (f"the route in use is a static route with administrative distance {m.group(1)}, so it is a floating or "
            "backup static: it is used only because no better route is installed")
