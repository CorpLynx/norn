"""Cisco hops must not pass silently when NAT / zone firewall / ip inspect / IPv6 are in play (G11, G20).
Fakes and the demo simulator only; nothing here talks to a device."""

from types import SimpleNamespace

import pytest

from nettrace import cli
from nettrace.demo import install, lab
from nettrace.drivers import aws, cisco_iosxe, panos, prisma
from nettrace.drivers.cisco_acl import evaluate_acl
from nettrace.drivers.cisco_iosxe import CefEntry, CefResult, CiscoClient
from nettrace.engine import Tracer
from nettrace.errors import DeviceError, ReadOnlyViolation
from nettrace.models import Flow, Outcome, Status
from nettrace.readonly import check_cisco_command
from nettrace.steps import AwsAt, DeviceAt, PrismaAt
from nettrace.viz.html import render_html

V4 = Flow(src="10.1.10.25", dst="10.20.1.50", protocol="tcp", dst_port=443)
V6 = Flow(src="2001:db8:10::25", dst="2001:db8:20::10", protocol="tcp", dst_port=443)
GUEST = Flow(src="10.1.40.25", dst="8.8.8.8", protocol="tcp", dst_port=443)
HOSTILE = "<script>alert(1)</script>[/bold]"


def _iface(name):
    return next(i for i in lab.CISCO["core-rtr1"]["interfaces"] if i["name"] == name)


# ---- read-only allowlist ----------------------------------------------------------------------
@pytest.mark.parametrize("cmd", ["show ip nat statistics", "show zone security", "show ip inspect interfaces"])
def test_new_commands_allowed(cmd):
    assert check_cisco_command(cmd) == cmd


@pytest.mark.parametrize("cmd", [
    "show ip nat translations", "show ip nat statistics | include x", "show ip nat statistics 10.1.1.1",
    "show zone security inside", "show zone-pair security", "show ip inspect all", "show ip inspect interfaces Gi1",
    "show ip nat", "show ip nat statistics; reload", "clear ip nat translation *", "show ip inspect sessions",
])
def test_nearby_commands_refused(cmd):
    with pytest.raises(ReadOnlyViolation):
        check_cisco_command(cmd)


# ---- parsers (real-looking IOS-XE wording) --------------------------------------------------------
NAT_STATS = """Total active translations: 3 (1 static, 2 dynamic; 3 extended)
Peak translations: 9, occurred 00:10:31 ago
Outside interfaces:
  GigabitEthernet1
Inside interfaces:
  GigabitEthernet2, GigabitEthernet4
Hits: 12  Misses: 0
Dynamic mappings:
-- Inside Source
[Id: 1] access-list NAT-ACL interface GigabitEthernet1 refcount 2
"""


def _client(**outputs):
    c = CiscoClient(install().devices["core-rtr1"])
    c.show = lambda cmd: outputs[cmd]
    return c


def test_nat_statistics_parsed():
    c = _client(**{"show ip nat statistics": NAT_STATS})
    assert c.nat_interfaces() == {"gigabitethernet1": "outside", "gigabitethernet2": "inside",
                                  "gigabitethernet4": "inside"}


def test_nat_statistics_unrecognised_output_raises_not_empty():
    with pytest.raises(DeviceError):
        _client(**{"show ip nat statistics": "something else\n"}).nat_interfaces()


def test_zone_and_inspect_parsed():
    zones = "zone self\n  Description: System defined zone\n\nzone inside\n  Description: lan\n  Member Interfaces:\n" \
            "    GigabitEthernet2\n    GigabitEthernet3\n\nzone outside\n  Member Interfaces:\n    GigabitEthernet1\n"
    assert _client(**{"show zone security": zones}).zone_members() == {
        "gigabitethernet2": "inside", "gigabitethernet3": "inside", "gigabitethernet1": "outside"}
    insp = "Interface Configuration\n Interface GigabitEthernet1\n  Inbound inspection rule is FW1\n" \
           "  Outgoing inspection rule is not set\n Interface GigabitEthernet2\n  Inbound inspection rule is not set\n"
    assert _client(**{"show ip inspect interfaces": insp}).inspect_rules() == {"gigabitethernet1": [("inbound", "FW1")]}
    with pytest.raises(DeviceError):
        _client(**{"show zone security": "garbage\n"}).zone_members()


def test_probe_invalid_input_means_feature_absent_but_other_errors_raise():
    class Conn:
        def __init__(self, text):
            self.text = text

        def send_command(self, cmd, read_timeout=60):
            return self.text

    c = CiscoClient(install().devices["core-rtr1"])
    c._conn = Conn("                ^\n% Invalid input detected at '^' marker.\n")
    assert c.zone_members() == {}
    c = CiscoClient(install().devices["core-rtr1"])
    c._conn = Conn("% Authorization failed.\n")
    with pytest.raises(DeviceError):
        c.zone_members()


# ---- simulator + engine ---------------------------------------------------------------------------
def test_demo_guest_nat_is_unknown_and_downgrades():
    r = Tracer(install()).trace(GUEST)
    router = next(h for h in r.hops if h.domain == "cisco")
    assert router.status == Status.UNKNOWN and router.ingress == "GigabitEthernet4"
    assert any("NAT configured on GigabitEthernet4 (inside): nettrace does not evaluate NAT, "
               "the real addresses may differ" in d for d in router.details)
    assert r.outcome == Outcome.INCOMPLETE and "UNKNOWN" in r.reason  # would be EXITED without the NAT
    assert any("NAT configured" in w for w in r.warnings)


def test_nat_on_egress_interface_is_unknown(monkeypatch):
    monkeypatch.setitem(_iface("GigabitEthernet1"), "nat", "outside")
    r = Tracer(install()).trace(Flow("10.1.10.25", "8.8.8.8", "tcp", 443))
    router = next(h for h in r.hops if h.domain == "cisco")
    assert router.status == Status.UNKNOWN
    assert any("NAT configured on GigabitEthernet1 (outside)" in d and "egress" in d for d in router.details)
    assert r.outcome == Outcome.INCOMPLETE


def test_nat_on_an_unrelated_interface_does_not_change_the_hop(monkeypatch):
    monkeypatch.setitem(_iface("GigabitEthernet3"), "nat", "inside")  # not ingress (Gi2) nor egress (Gi1)
    r = Tracer(install()).trace(Flow("10.1.10.25", "8.8.8.8", "tcp", 443))
    router = next(h for h in r.hops if h.domain == "cisco")
    assert router.status != Status.UNKNOWN and not any("NAT" in d for d in router.details)
    assert r.outcome == Outcome.EXITED


def test_zone_member_on_ingress_is_unknown(monkeypatch):
    monkeypatch.setitem(_iface("GigabitEthernet2"), "zone", "LAN")
    r = Tracer(install()).trace(Flow("10.1.10.25", "8.8.8.8", "tcp", 443))
    router = next(h for h in r.hops if h.domain == "cisco")
    assert router.status == Status.UNKNOWN
    assert any("zone-based firewall: GigabitEthernet2 is in security zone LAN" in d for d in router.details)
    assert r.outcome == Outcome.INCOMPLETE


def test_ip_inspect_on_egress_is_unknown(monkeypatch):
    monkeypatch.setitem(_iface("GigabitEthernet1"), "inspect", "CBAC1")
    r = Tracer(install()).trace(Flow("10.1.10.25", "8.8.8.8", "tcp", 443))
    router = next(h for h in r.hops if h.domain == "cisco")
    assert router.status == Status.UNKNOWN and any("ip inspect rule CBAC1" in d for d in router.details)


def test_features_do_not_hide_an_acl_block(monkeypatch):
    monkeypatch.setitem(_iface("GigabitEthernet2"), "nat", "inside")
    r = Tracer(install()).trace(Flow("10.1.10.25", "10.1.20.10", "tcp", 23))  # telnet: USERS-IN denies
    assert r.outcome == Outcome.BLOCKED


# ---- hostile text in a detail line --------------------------------------------------------------------
def _fake(nat=None, zones=None):
    dev = SimpleNamespace(name="r1", vrf=None)
    return SimpleNamespace(
        device=dev, evidence=[], interface=lambda n: {}, policy_route_map=lambda n: None,
        nat_interfaces=lambda: nat or {}, zone_members=lambda: zones or {}, inspect_rules=lambda: {},
        cef=lambda ip, vrf: CefResult(prefix="10.20.0.0/16", entries=[CefEntry("nexthop", "10.0.0.2", "Gi1")]),
        route=lambda ip, vrf: ("10.20.0.0/16", "static"))


def test_hostile_zone_name_is_escaped_in_html_and_text_output(tmp_path):
    res = cisco_iosxe.step(_fake(zones={"gi0": HOSTILE}), DeviceAt(device="r1", arrival_interface="Gi0"), V4)
    hop = res.hops[0]
    assert hop.status == Status.UNKNOWN and any(HOSTILE in d for d in hop.details)
    trace = {"Flow": {"src": V4.src, "dst": V4.dst, "protocol": "tcp", "dst_port": 443}, "Outcome": "INCOMPLETE",
             "Reason": "x", "Warnings": res.warnings,
             "Hops": [{"index": 1, "domain": "cisco", "node": "r1", "component": "router", "status": "UNKNOWN",
                       "summary": hop.summary, "details": hop.details, "evidence": [], "location": {}}]}
    page = render_html([trace])
    assert page.count("<script>alert(1)") == 0  # the viewer only embeds it as escaped JSON
    out = tmp_path / "m.html"
    cli.write_map([trace], str(out), with_evidence=False)
    assert "<script>alert(1)</script>" not in out.read_text()
    from io import StringIO

    from rich.console import Console

    from nettrace.models import TraceResult
    from nettrace.output import render_trace
    buf = StringIO()
    render_trace(Console(file=buf, width=200), TraceResult(flow=V4, outcome=Outcome.INCOMPLETE, reason="x", hops=[hop]),
                 verbose=True)  # rich markup in device text must not raise or be interpreted
    assert "alert(1)" in buf.getvalue()


# ---- IPv6 --------------------------------------------------------------------------------------------
class _NoCommands:
    """A Cisco client that fails the test if the IPv4 logic touches the device."""

    device = SimpleNamespace(name="r1", vrf=None)
    evidence: list = []

    def __getattr__(self, name):
        raise AssertionError(f"IPv4 logic ran on an IPv6 flow: {name}")


@pytest.mark.parametrize("flow", [V6, Flow("10.1.10.25", "2001:db8::5", "tcp", 443),
                                  Flow("2001:db8::5", "10.1.10.25", "tcp", 443)])
def test_cisco_ipv6_is_unknown_without_running_ipv4_logic(flow):
    res = cisco_iosxe.step(_NoCommands(), DeviceAt(device="r1"), flow)
    assert res.hops[0].status == Status.UNKNOWN and "IPv6 is not evaluated" in res.hops[0].summary
    assert res.outcome == Outcome.INCOMPLETE


def test_ipv6_trace_through_engine_does_not_crash_and_is_incomplete():
    inv = install()
    r = Tracer(inv).trace(V6, start_at="core-rtr1")
    assert r.outcome == Outcome.INCOMPLETE and r.hops[-1].status == Status.UNKNOWN
    assert "IPv6 is not evaluated" in r.hops[-1].summary
    r = Tracer(inv).trace(Flow("10.1.10.25", "2001:db8::5", "tcp", 443))  # source is IPv4, destination is not
    assert r.outcome == Outcome.INCOMPLETE and "IPv6 is not evaluated" in r.reason
    r = Tracer(inv).trace(V6)  # source not in any inventory network: no crash, clear INCOMPLETE
    assert r.outcome == Outcome.INCOMPLETE


def test_other_entry_points_refuse_ipv6():
    assert panos.step(SimpleNamespace(device=SimpleNamespace(name="fw")), DeviceAt(device="fw"), V6) \
        .hops[0].status == Status.UNKNOWN
    assert prisma.step(None, SimpleNamespace(prisma=object()), PrismaAt(entry="source"), V6) \
        .hops[0].status == Status.UNKNOWN
    walker = aws.AwsWalker(SimpleNamespace(evidence=[]), install())
    res = walker.walk(AwsAt(kind="subnet", account="1", region="r", resource_id="s"), V6)
    assert res.hops[0].status == Status.UNKNOWN and res.outcome == Outcome.INCOMPLETE


def test_acl_evaluator_refuses_ipv6():
    with pytest.raises(DeviceError):
        evaluate_acl("A", "Extended IP access list A\n    10 permit ip any any\n", V6)


def test_cli_ipv6_exits_4_without_traceback(monkeypatch):
    from click.testing import CliRunner
    monkeypatch.setenv("NETTRACE_AUDIT_LOG", "/dev/null")
    res = CliRunner().invoke(cli.cli, ["--demo", "--output", "json", "trace", "run", "-s", "2001:db8:10::25",
                                        "-d", "2001:db8:20::10", "-p", "443", "--start-at", "core-rtr1"])
    assert res.exit_code == 4 and "Traceback" not in res.output and "IPv6 is not evaluated" in res.output
