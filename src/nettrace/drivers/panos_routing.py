"""Why is there no route on a PAN-OS firewall? Extra read-only evidence after `fib-lookup` found nothing.

Same rules as drivers/cisco_routing.py: it only runs once the firewall has said there is no route; the verdict
never changes because of it; anything it cannot read becomes a "not interpreted" or "not available" detail line,
never "no routes"; a deadline or cancel is not caught here.

- Static routes: `config show` of the virtual router's (or logical router's) running static-route table. Routes
  pushed from a Panorama template are in the firewall's running config, so they show up here too. Only routes
  that cover the destination are reported.
- BGP: the peer list from a `show` op. A BGP route can't be looked up per prefix here, so this reports peers that
  are not Established, which is the usual reason a learned route is missing.

The BGP reply shape was written from PAN-OS documentation and memory, not captured from a firewall. Check it
against a real device before trusting it (docs/gaps-and-roadmap.md). Wrong or surprising output is reported as
"not interpreted".
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from nettrace.errors import DeviceError
from nettrace.steps import RouteDiagnosis

_SAFE_NAME = re.compile(r"[A-Za-z0-9 _.:\-]{1,128}")
_DEVICE = "/config/devices/entry[@name='localhost.localdomain']"
MAX_PEERS_SHOWN = 10


def static_route_xpath(engine: str, router: str) -> str | None:
    """Xpath of the running static-route table, or None when the router name is not xpath-safe."""
    if not _SAFE_NAME.fullmatch(router or ""):
        return None
    if engine == "advanced":
        return (f"{_DEVICE}/network/logical-router/entry[@name='{router}']/vrf/entry[@name='default']"
                "/routing-table/ip/static-route")
    return f"{_DEVICE}/network/virtual-router/entry[@name='{router}']/routing-table/ip/static-route"


def parse_static_routes(result: Any, dst: str) -> tuple[int, list[str]]:
    """(routes seen, detail lines for the ones covering dst) from a static-route config result."""
    addr = ipaddress.ip_address(dst)
    seen = 0
    hits: list[tuple[int, str]] = []
    for entry in result.iter("entry"):
        dest = (entry.findtext("destination") or "").strip()
        if not dest:
            continue
        seen += 1
        try:
            net = ipaddress.ip_network(dest, strict=False)
        except ValueError:
            continue
        if net.version != 4 or addr not in net:
            continue
        nh = (entry.findtext("nexthop/ip-address") or "").strip()
        if not nh and entry.find("nexthop/discard") is not None:
            nh = "discard"
        if not nh and entry.find("nexthop/next-vr") is not None:
            nh = f"next-vr {(entry.findtext('nexthop/next-vr') or '').strip()}"
        intf = (entry.findtext("interface") or "").strip()
        metric = (entry.findtext("metric") or "10").strip()
        dist = (entry.findtext("admin-dist") or "10").strip()
        monitored = (entry.findtext("path-monitor/enable") or "").strip().lower() == "yes"
        text = (f"static route '{entry.get('name', '?')}' {dest} via {nh or '(no next hop)'}"
                f"{' ' + intf if intf else ''} (metric {metric}, distance {dist}) is configured but is not in the "
                f"forwarding table: the next hop may be unreachable, the interface down"
                f"{', or its path monitor failed (path monitoring is enabled on it)' if monitored else ''}")
        hits.append((net.prefixlen, text))
    return seen, [t for _, t in sorted(hits, key=lambda x: -x[0])[:3]]


def parse_bgp_peers(root: Any) -> list[tuple[str, str]]:
    """[(peer, status)] from a BGP peer reply: every element that has a <status> and a peer name or address."""
    result = root.find("result")
    if result is None:
        return []
    peers = []
    for e in result.iter():
        status = (e.findtext("status") or "").strip()
        name = e.get("peer") or (e.findtext("peer-name") or "").strip() or (e.findtext("peer-address") or "").strip()
        if status and name:
            peers.append((name, status))
    return peers


def explain_missing_route(client: Any, router: str, dst: str) -> RouteDiagnosis:
    from nettrace.drivers.panos import Unavailable  # imported here: panos.py imports this module

    ipaddress.ip_address(dst)
    diag = RouteDiagnosis()
    reasons: list[str] = []
    engine = getattr(client.device, "routing_engine", "legacy")

    # Static routes configured for this destination
    xpath = static_route_xpath(engine, router)
    if xpath is None:
        diag.lines.append(f"static routes: router name {router!r} is not safe to put in a query; not checked")
    else:
        result = client.config_get(xpath, action="show")
        if isinstance(result, Unavailable):
            diag.lines.append(f"static routes: could not be read ({result.reason[:120]})")
        elif result is None:
            diag.lines.append(f"static routes: none configured in {router}")
        else:
            seen, covering = parse_static_routes(result, dst)
            if not seen:
                diag.lines.append("static routes: reply not interpreted (no route entries found; see evidence)")
            elif not covering:
                diag.lines.append(f"static routes: none of the {seen} configured in {router} covers {dst}")
            else:
                diag.lines.extend(covering)
                reasons.append("a static route covers it but is not installed")

    # BGP peers
    path = ["show", "advanced-routing", "bgp", "peer", "status"] if engine == "advanced" \
        else ["show", "routing", "protocol", "bgp", "peer"]
    try:
        root = client.op(path)
    except DeviceError as exc:
        diag.lines.append(f"BGP peers: could not be read ({str(exc).split(': ', 1)[-1][:120]})")
    else:
        peers = parse_bgp_peers(root)
        if not peers:
            result = root.find("result")
            empty = result is None or (len(result) == 0 and not (result.text or "").strip())
            diag.lines.append("BGP peers: none returned (BGP is not configured here, or has no peers)" if empty
                              else "BGP peers: reply not interpreted (see evidence)")
        else:
            down = [(n, s) for n, s in peers if s.lower() != "established"]
            if not down:
                diag.lines.append(f"BGP peers: all {len(peers)} Established, so the missing route is not a peer outage")
            else:
                shown = ", ".join(f"{n} {s}" for n, s in down[:MAX_PEERS_SHOWN])
                more = f" and {len(down) - MAX_PEERS_SHOWN} more" if len(down) > MAX_PEERS_SHOWN else ""
                diag.lines.append(f"BGP peers not Established ({len(down)} of {len(peers)}): {shown}{more}")
                reasons.append(f"{len(down)} of {len(peers)} BGP peers not Established")
    diag.reason = "; ".join(dict.fromkeys(reasons))
    return diag
