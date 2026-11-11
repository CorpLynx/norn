"""Why-is-there-no-route evidence: BGP and static routes on Cisco, static routes and BGP peers on PAN-OS.

The rules under test (AGENTS.md rules 1 and 3):
- only allowlisted read-only commands are sent, and only when the router already found no route;
- the verdict stays BLOCK, except when the evidence shows a usable route while the forwarding lookup found none
  (the sources disagree): then the hop is UNKNOWN and the trace INCOMPLETE;
- unreadable output is reported as "not interpreted", never as "no routes".
"""

from types import SimpleNamespace

import pytest
from defusedxml import ElementTree as SafeET

from nettrace.drivers import cisco_iosxe, cisco_routing, panos, panos_routing
from nettrace.drivers.cisco_iosxe import CefEntry, CefResult, parse_route_source
from nettrace.errors import DeadlineExceeded, DeviceError, ReadOnlyViolation
from nettrace.models import Flow, Outcome, Status
from nettrace.readonly import check_cisco_command, check_panos_request
from nettrace.steps import DeviceAt

DST = "10.99.0.5"
FLOW = Flow("10.1.1.10", DST, "tcp", dst_port=443)

# ---- sample router output ---------------------------------------------------------------------------
BGP_BEST = """BGP routing table entry for 10.99.0.0/24, version 5
Paths: (1 available, best #1, table default)
  Advertised to update-groups:
     1
  Refresh Epoch 1
  65002
    192.0.2.2 from 192.0.2.2 (2.2.2.2)
      Origin IGP, metric 0, localpref 100, valid, external, best
      rx pathid: 0, tx pathid: 0x0
"""
BGP_INACCESSIBLE = """BGP routing table entry for 10.99.0.0/24, version 0
Paths: (1 available, no best path)
  Not advertised to any peer
  Refresh Epoch 1
  65002
    192.0.2.9 (inaccessible) from 192.0.2.9 (9.9.9.9)
      Origin IGP, metric 0, localpref 100, valid, internal
"""
BGP_SUMMARY = """BGP router identifier 192.0.2.1, local AS number 65001
BGP table version is 12, main routing table version 12
3 network entries using 744 bytes of memory

Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
192.0.2.2       4        65002    1234    1240       12    0    0 2d03h           5
192.0.2.6       4        65003       0       0        1    0    0 never    Idle
192.0.2.10      4        65004       0       0        1    0    0 never    Active
192.0.2.14      4        65005       0       0        1    0    0 never    Idle (Admin)
"""
BGP_SUMMARY_ALL_UP = """BGP router identifier 192.0.2.1, local AS number 65001
BGP table version is 12, main routing table version 12

Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
192.0.2.2       4        65002    1234    1240       12    0    0 2d03h           5
"""
NOT_IN_TABLE = "% Network not in table\n"
STATIC_TABLE = """Codes: M - Manual static, A - AAA download, N - IP NAT, D - DHCP
Codes in []: A - active, N - non-active, B - BFD-tracked, D - DHCP, X - Unresolved

Static local RIB for default

M  10.99.0.0/24  [1/0] via 192.0.2.77 [N]
M  172.16.0.0/12  [1/0] via 192.0.2.1 [A]
"""
STATIC_TABLE_ACTIVE = "Static local RIB for default\n\nM  10.99.0.0/24  [1/0] via 192.0.2.1 [A]\n"
STATIC_TABLE_NOFLAG = "Static local RIB for default\n\nM  10.99.0.0/24  [1/0] via 192.0.2.77\n"
STATIC_TABLE_OTHER = "Static local RIB for default\n\nM  172.16.0.0/12  [1/0] via 192.0.2.1 [A]\n"


class Script:
    """A `show` that runs every command through the real read-only guard, records it, and answers from a dict."""

    def __init__(self, replies=None):
        self.replies = replies or {}
        self.sent = []

    def __call__(self, command):
        check_cisco_command(command)
        self.sent.append(command)
        reply = self.replies.get(command, "")
        if isinstance(reply, Exception):
            raise reply
        return reply


def _router(show, entries=(), pbr=None, source=None, vrf=None):
    return SimpleNamespace(
        device=SimpleNamespace(name="r1", vrf=vrf), evidence=[], interface=lambda n: {},
        policy_route_map=lambda n: pbr, nat_interfaces=lambda: {}, zone_members=lambda: {}, inspect_rules=lambda: {},
        cef=lambda ip, v: CefResult(prefix=None, entries=list(entries)),
        route=lambda ip, v: (None, source), show=show)


def _step(client):
    return cisco_iosxe.step(client, DeviceAt(device="r1", arrival_interface="Gi0"), FLOW)


# ---- the guard -----------------------------------------------------------------------------------
@pytest.mark.parametrize("cmd", [
    "show ip bgp 10.99.0.5", "show ip bgp summary", "show ip bgp vpnv4 vrf RED 10.99.0.5",
    "show ip bgp vpnv4 vrf RED summary", "show ip static route", "show ip static route vrf RED"])
def test_new_commands_pass_the_allowlist(cmd):
    assert check_cisco_command(cmd) == cmd


@pytest.mark.parametrize("cmd", [
    "show ip bgp", "show ip bgp neighbors", "show ip bgp neighbors 192.0.2.2 received-routes",
    "sh ip bgp summary", "show ip bgp summary | include Idle", "show ip bgp 2001:db8::1", "show ip bgp 999.1.1.1",
    "show ip bgp 10.99.0.5; reload", "show ip bgp vpnv4 all", "show bgp all summary", "show ip bgp vpnv4 vrf RED",
    "show ip static route | begin 10", "show ip static", "show ip bgp  summary ", "clear ip bgp *"])
def test_nothing_broader_passes_the_allowlist(cmd):
    with pytest.raises(ReadOnlyViolation):
        check_cisco_command(cmd)


# ---- parsers -------------------------------------------------------------------------------------
def test_bgp_prefix_states():
    best = cisco_routing.parse_bgp_prefix(BGP_BEST)
    assert (best.state, best.prefix, best.paths, best.inaccessible) == ("best", "10.99.0.0/24", 1, 0)
    inacc = cisco_routing.parse_bgp_prefix(BGP_INACCESSIBLE)
    assert (inacc.state, inacc.inaccessible) == ("no-best", 1)
    assert cisco_routing.parse_bgp_prefix(NOT_IN_TABLE).state == "absent"
    assert cisco_routing.parse_bgp_prefix("something else entirely").state == "unparsed"
    assert cisco_routing.parse_bgp_prefix("").state == "unparsed"  # empty is not "absent"


def test_bgp_summary_neighbors():
    ns = cisco_routing.parse_bgp_summary(BGP_SUMMARY)
    assert [(n.address, n.state) for n in ns] == [("192.0.2.2", "Established"), ("192.0.2.6", "Idle"),
                                                  ("192.0.2.10", "Active"), ("192.0.2.14", "Idle (Admin)")]


def test_bgp_summary_with_a_table_we_cannot_read_raises():
    with pytest.raises(DeviceError):
        cisco_routing.parse_bgp_summary("Neighbor  garbage garbage\nnothing a template would match\n")


def test_static_table_parse_and_cover():
    routes = cisco_routing.parse_static_routes(STATIC_TABLE)
    assert [(r.prefix, r.via, r.flag, r.active) for r in routes] == [
        ("10.99.0.0/24", "192.0.2.77", "N", False), ("172.16.0.0/12", "192.0.2.1", "A", True)]
    assert [r.prefix for r in cisco_routing.covering(routes, DST)] == ["10.99.0.0/24"]
    assert cisco_routing.parse_static_routes(STATIC_TABLE_NOFLAG)[0].active is None


# ---- floating static ----------------------------------------------------------------------------
def test_route_source_marks_only_non_default_static_distance():
    assert parse_route_source('Routing entry for 0.0.0.0/0\n  Known via "static", distance 1, metric 0\n')[1] == "static"
    assert parse_route_source('Routing entry for 0.0.0.0/0\n  Known via "static", distance 250, metric 0\n')[1] \
        == "static (distance 250)"
    assert parse_route_source('Routing entry for 10.0.0.0/8\n  Known via "bgp 65001", distance 20, metric 0\n')[1] \
        == "bgp 65001"


def test_floating_static_is_noted_when_it_is_the_route_in_use():
    res = _step(_router(Script(), entries=[CefEntry("nexthop", "10.0.0.2", "Gi1")], source="static (distance 250)"))
    assert any("administrative distance 250" in d and "backup" in d for d in res.hops[0].details)
    plain = _step(_router(Script(), entries=[CefEntry("nexthop", "10.0.0.2", "Gi1")], source="static"))
    assert not any("administrative distance" in d for d in plain.hops[0].details)


# ---- Cisco: no route -----------------------------------------------------------------------------
def test_route_exists_so_no_evidence_command_is_sent():
    show = Script()
    res = _step(_router(show, entries=[CefEntry("nexthop", "10.0.0.2", "Gi1")]))
    assert show.sent == [] and res.hops[0].status == Status.PASS


def test_bgp_absent_and_neighbors_down_stays_block_and_says_why():
    show = Script({f"show ip bgp {DST}": NOT_IN_TABLE, "show ip bgp summary": BGP_SUMMARY, "show ip static route": ""})
    res = _step(_router(show))
    hop = res.hops[0]
    assert hop.status == Status.BLOCK and res.outcome == Outcome.BLOCKED
    text = "\n".join(hop.details)
    assert "no path" in text and "3 of 4" in text and "192.0.2.6 AS65003 Idle" in text and "Idle (Admin)" in text
    assert "no path in the BGP table" in res.reason and "3 of 4 BGP neighbors not Established" in res.reason
    assert show.sent == [f"show ip bgp {DST}", "show ip bgp summary", "show ip static route"]  # at most 3 commands


def test_bgp_absent_with_all_neighbors_up_says_it_is_not_an_outage():
    show = Script({f"show ip bgp {DST}": NOT_IN_TABLE, "show ip bgp summary": BGP_SUMMARY_ALL_UP})
    res = _step(_router(show))
    assert res.hops[0].status == Status.BLOCK
    assert any("all 1 Established" in d for d in res.hops[0].details)


def test_inaccessible_next_hop_is_named():
    show = Script({f"show ip bgp {DST}": BGP_INACCESSIBLE, "show ip bgp summary": BGP_SUMMARY_ALL_UP})
    res = _step(_router(show))
    assert res.hops[0].status == Status.BLOCK
    assert any("none is best" in d and "inaccessible next hop" in d for d in res.hops[0].details)


def test_bgp_best_path_but_no_forwarding_entry_is_unknown_not_block():
    show = Script({f"show ip bgp {DST}": BGP_BEST})
    res = _step(_router(show))
    assert res.hops[0].status == Status.UNKNOWN and res.outcome == Outcome.INCOMPLETE
    assert any("cannot tell which" in d for d in res.hops[0].details)
    assert "BGP shows a best path but CEF has none" in res.reason
    assert "10.99.0.0/24" in "\n".join(res.hops[0].details)
    assert "show ip bgp summary" not in show.sent  # a usable path exists: neighbors are not the question


def test_static_not_installed_is_reported_and_stays_block():
    show = Script({f"show ip bgp {DST}": NOT_IN_TABLE, "show ip bgp summary": BGP_SUMMARY_ALL_UP,
                   "show ip static route": STATIC_TABLE})
    res = _step(_router(show))
    assert res.hops[0].status == Status.BLOCK
    assert any("10.99.0.0/24" in d and "not installed" in d for d in res.hops[0].details)
    assert not any("172.16.0.0/12" in d for d in res.hops[0].details)  # only routes that cover the destination
    assert "static route 10.99.0.0/24 configured but not installed" in res.reason


def test_static_marked_active_while_cef_has_none_is_unknown():
    show = Script({f"show ip bgp {DST}": NOT_IN_TABLE, "show ip bgp summary": BGP_SUMMARY_ALL_UP,
                   "show ip static route": STATIC_TABLE_ACTIVE})
    res = _step(_router(show))
    assert res.hops[0].status == Status.UNKNOWN and res.outcome == Outcome.INCOMPLETE


def test_static_without_a_flag_says_install_state_is_unknown_and_stays_block():
    show = Script({f"show ip bgp {DST}": NOT_IN_TABLE, "show ip bgp summary": BGP_SUMMARY_ALL_UP,
                   "show ip static route": STATIC_TABLE_NOFLAG})
    res = _step(_router(show))
    assert res.hops[0].status == Status.BLOCK
    assert any("does not say whether it is installed" in d for d in res.hops[0].details)


def test_static_table_that_covers_nothing_is_stated():
    show = Script({f"show ip bgp {DST}": NOT_IN_TABLE, "show ip bgp summary": BGP_SUMMARY_ALL_UP,
                   "show ip static route": STATIC_TABLE_OTHER})
    assert any("none of the 1 listed covers" in d for d in _step(_router(show)).hops[0].details)


def test_unreadable_replies_are_not_interpreted_never_read_as_empty():
    show = Script({f"show ip bgp {DST}": "garbage the parser does not know", "show ip static route": "no routes here"})
    res = _step(_router(show))
    text = "\n".join(res.hops[0].details)
    assert res.hops[0].status == Status.BLOCK
    assert "not interpreted" in text and "no route lines found" in text


def test_empty_static_reply_is_reported_as_none_returned():
    res = _step(_router(Script({f"show ip bgp {DST}": NOT_IN_TABLE, "show ip bgp summary": BGP_SUMMARY_ALL_UP})))
    assert any("none returned" in d for d in res.hops[0].details)


def test_bgp_not_running_and_missing_commands_become_detail_lines():
    show = Script({f"show ip bgp {DST}": DeviceError("r1: 'show ip bgp x' rejected: % BGP not active"),
                   "show ip static route": DeviceError("r1: 'show ip static route' rejected: % Invalid input detected")})
    res = _step(_router(show))
    text = "\n".join(res.hops[0].details)
    assert res.hops[0].status == Status.BLOCK
    assert "BGP is not running on this router" in text and "does not support 'show ip static route'" in text


def test_other_device_errors_are_a_detail_line_and_the_verdict_stands():
    show = Script({f"show ip bgp {DST}": DeviceError("r1: SSH failed: timed out")})
    res = _step(_router(show))
    assert res.hops[0].status == Status.BLOCK
    assert any("BGP table: could not be read" in d for d in res.hops[0].details)


def test_a_deadline_during_the_evidence_ends_the_trace_not_the_diagnosis():
    show = Script({f"show ip bgp {DST}": DeadlineExceeded("trace deadline of 120s exceeded")})
    with pytest.raises(DeadlineExceeded):
        _step(_router(show))


def test_pbr_keeps_unknown_even_with_clean_no_route_evidence():
    show = Script({f"show ip bgp {DST}": NOT_IN_TABLE, "show ip bgp summary": BGP_SUMMARY_ALL_UP})
    res = _step(_router(show, pbr="STEER"))
    assert res.hops[0].status == Status.UNKNOWN and res.outcome == Outcome.INCOMPLETE


def test_vrf_uses_the_vpnv4_and_vrf_forms():
    show = Script({f"show ip bgp vpnv4 vrf RED {DST}": NOT_IN_TABLE,
                   "show ip bgp vpnv4 vrf RED summary": BGP_SUMMARY_ALL_UP})
    res = _step(_router(show, vrf="RED"))
    assert show.sent == [f"show ip bgp vpnv4 vrf RED {DST}", "show ip bgp vpnv4 vrf RED summary",
                         "show ip static route vrf RED"]
    assert res.hops[0].status == Status.BLOCK


def test_unsafe_vrf_name_is_refused_before_anything_is_sent():
    show = Script()
    with pytest.raises(ReadOnlyViolation):
        cisco_routing.explain_missing_route(SimpleNamespace(show=show), DST, "RED; reload")
    assert show.sent == []


def test_many_down_neighbors_are_capped():
    rows = "\n".join(f"192.0.2.{i}       4        65002       0       0        1    0    0 never    Idle"
                     for i in range(20, 40))
    summary = ("BGP router identifier 192.0.2.1, local AS number 65001\n\n"
               "Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd\n" + rows + "\n")
    diag = cisco_routing.explain_missing_route(
        SimpleNamespace(show=Script({f"show ip bgp {DST}": NOT_IN_TABLE, "show ip bgp summary": summary})), DST, None)
    line = next(ln for ln in diag.lines if "not Established" in ln)
    assert "(20 of 20)" in line and "and 10 more" in line


# ---- PAN-OS ---------------------------------------------------------------------------------------
STATIC_XML = """<response status="success"><result>
<static-route>
  <entry name="to-dc2"><destination>10.99.0.0/24</destination><nexthop><ip-address>192.0.2.77</ip-address></nexthop>
    <interface>ethernet1/2</interface><metric>10</metric><admin-dist>10</admin-dist>
    <path-monitor><enable>yes</enable></path-monitor></entry>
  <entry name="other"><destination>172.16.0.0/12</destination><nexthop><ip-address>192.0.2.1</ip-address></nexthop></entry>
  <entry name="drop"><destination>10.0.0.0/8</destination><nexthop><discard/></nexthop></entry>
</static-route></result></response>"""
BGP_PEERS_XML = """<response status="success"><result>
<entry peer="isp-a" vr="default"><status>Established</status><peer-address>203.0.113.1:179</peer-address></entry>
<entry peer="isp-b" vr="default"><status>Idle</status><peer-address>203.0.113.9:179</peer-address></entry>
</result></response>"""
EMPTY_XML = '<response status="success"><result/></response>'


def _xml(text):
    return SafeET.fromstring(text)


class FakeFw:
    """A PAN-OS client double that sends every request through the real read-only guard."""

    def __init__(self, static=None, peers=None, engine="legacy", op_error=None):
        self.device = SimpleNamespace(name="fw", routing_engine=engine, virtual_router="default", vsys=None)
        self.static, self.peers, self.op_error = static, peers, op_error
        self.sent = []

    def config_get(self, xpath, action="get"):
        check_panos_request({"type": "config", "action": action, "xpath": xpath})
        self.sent.append(("config", action, xpath))
        if self.static is None:
            return panos.Unavailable("API timeout")
        result = _xml(self.static).find("result")
        return result if len(result) else None

    def op(self, path, fields=None):
        cmd = panos.build_op(path, fields)
        check_panos_request({"type": "op", "cmd": cmd})
        self.sent.append(("op", cmd))
        if self.op_error:
            raise DeviceError(self.op_error)
        return _xml(self.peers if self.peers is not None else EMPTY_XML)


def test_panos_xpaths_pass_the_guard_for_both_engines():
    for engine in ("legacy", "advanced"):
        xp = panos_routing.static_route_xpath(engine, "default")
        assert check_panos_request({"type": "config", "action": "show", "xpath": xp})
    assert panos_routing.static_route_xpath("legacy", "vr'; drop") is None
    assert panos_routing.static_route_xpath("legacy", "") is None


def test_panos_static_route_covering_the_destination_is_reported_with_path_monitor():
    seen, lines = panos_routing.parse_static_routes(_xml(STATIC_XML).find("result"), DST)
    assert seen == 3 and len(lines) == 2  # the /24 and the /8 discard cover it; the /12 does not
    assert "to-dc2" in lines[0] and "10.99.0.0/24" in lines[0] and "path monitor failed" in lines[0]
    assert "discard" in lines[1]


def test_panos_diagnosis_static_and_bgp_peers():
    fw = FakeFw(static=STATIC_XML, peers=BGP_PEERS_XML)
    diag = panos_routing.explain_missing_route(fw, "default", DST)
    text = "\n".join(diag.lines)
    assert "to-dc2" in text and "BGP peers not Established (1 of 2): isp-b Idle" in text
    assert "a static route covers it but is not installed" in diag.reason and "1 of 2 BGP peers" in diag.reason
    assert not diag.contradiction
    assert [s[0] for s in fw.sent] == ["config", "op"] and fw.sent[0][1] == "show"  # running config, read-only


def test_panos_advanced_routing_engine_uses_logical_router_paths():
    fw = FakeFw(static=STATIC_XML, peers=BGP_PEERS_XML, engine="advanced")
    panos_routing.explain_missing_route(fw, "lr1", DST)
    assert "logical-router/entry[@name='lr1']" in fw.sent[0][2]
    assert "<advanced-routing>" in fw.sent[1][1]


def test_panos_unreadable_or_unavailable_replies_are_reported_not_assumed_empty():
    diag = panos_routing.explain_missing_route(FakeFw(static=None, peers="<response status='success'><result><x>1</x></result></response>"),
                                               "default", DST)
    text = "\n".join(diag.lines)
    assert "static routes: could not be read (API timeout)" in text and "BGP peers: reply not interpreted" in text
    empty = panos_routing.explain_missing_route(FakeFw(static=EMPTY_XML, peers=EMPTY_XML), "default", DST)
    assert any("none configured in default" in ln for ln in empty.lines)
    assert any("none returned" in ln for ln in empty.lines)


def test_panos_op_failure_is_a_detail_line():
    diag = panos_routing.explain_missing_route(FakeFw(static=STATIC_XML, op_error="fw: command failed: no bgp"),
                                               "default", DST)
    assert any(ln.startswith("BGP peers: could not be read") for ln in diag.lines)


def test_panos_step_no_route_stays_block_with_evidence():
    fw = FakeFw(static=STATIC_XML, peers=BGP_PEERS_XML)
    fw.notes, fw.meta, fw.evidence = [], {}, []
    fw.interfaces = lambda: {"ethernet1/1": {"zone": "trust", "fwd": "vr:default", "ip": "10.0.0.2/30", "vsys": "1"}}
    fw.interface_for_ip = lambda ip: "ethernet1/1"
    fw.fib_lookup = lambda router, ip: None
    res = panos.step(fw, DeviceAt(device="fw", arrival_interface="ethernet1/1"), FLOW)
    assert res.hops[0].status == Status.BLOCK and res.outcome == Outcome.BLOCKED
    assert any("to-dc2" in d for d in res.hops[0].details)
    assert "BGP peers" in res.reason or "static route" in res.reason


# ---- end to end through the real client, guard and demo simulator -------------------------------------
def test_real_client_and_simulator_answer_the_evidence_commands():
    from nettrace.demo import install

    inv = install()
    client = cisco_iosxe.CiscoClient(inv.devices["core-rtr1"])
    try:
        # The lab has a default route, so a real trace never gets here. Asking directly proves that the guard accepts
        # the commands, the simulator answers them in IOS-XE format, and the parsers read that format.
        diag = cisco_routing.explain_missing_route(client, "100.64.1.1", None)
        text = "\n".join(diag.lines)
        assert diag.contradiction and "BGP has a best path for 100.64.0.0/16" in text
        diag = cisco_routing.explain_missing_route(client, "8.8.8.8", None)
        text = "\n".join(diag.lines)
        assert "no path for 8.8.8.8" in text and "all 1 Established" in text
        assert [e.request for e in client.evidence] == ["show ip bgp 100.64.1.1", "show ip static route",
                                                        "show ip bgp 8.8.8.8", "show ip bgp summary"]
    finally:
        client.close()
