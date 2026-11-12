"""Discovery parsers, AWS/SCM keep-lists, the topology view and the dry-run plan. Pure; nothing is sent.

Fixtures are synthetic (V20 to V23): they prove the parsers match the assumed formats, not real devices.
"""

from __future__ import annotations

import json

import pytest
from defusedxml import ElementTree as SafeET

from nettrace.discovery.join import join
from nettrace.discovery.merge import merge
from nettrace.discovery.model import TunnelEnd
from nettrace.discovery.observe import provenance_factory
from nettrace.discovery.observe import aws as oaws
from nettrace.discovery.observe import cisco, panos, scm
from nettrace.discovery.plan import plan
from nettrace.discovery.store import RunRecord, StoreState
from nettrace.discovery.view import Found, TopologyView, Unusable
from nettrace.errors import DeviceError, InventoryError
from nettrace.inventory import LinkEnd, load_inventory

T0 = 1_800_000_000.0
P = provenance_factory("rtr1", "r1", T0)

INV = """
devices:
  - {name: rtr1, platform: cisco_iosxe, host: 10.0.0.1, addresses: [203.0.113.1]}
  - {name: rtr2, platform: cisco_iosxe, host: 10.0.0.2, addresses: [198.51.100.2]}
  - {name: fw1, platform: panos, host: 10.0.0.3, addresses: [192.0.2.10]}
aws:
  regions: [us-east-1]
  accounts: [{name: network, account_id: "111111111111"}]
prisma_access:
  service_connections: [{name: SC-East, routes: [10.0.0.0/8]}]
links:
  - name: fw1-internet
    a: {device: fw1, interface: ethernet1/4}
    b: {external: "Internet (ISP-A)"}
"""


@pytest.fixture(autouse=True)
def _cache(tmp_path, monkeypatch):
    monkeypatch.setenv("NETTRACE_CACHE_DIR", str(tmp_path / "cache"))


def _inv(tmp_path, extra=""):
    p = tmp_path / "inv.yaml"
    p.write_text(INV + extra)
    return load_inventory(p)


# ---- Cisco -----------------------------------------------------------------------

BRIEF = """Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet1       203.0.113.1     YES NVRAM  up                    up
Tunnel100              169.254.10.2    YES manual up                    up
Tunnel200              unassigned      YES unset  administratively down down
Loopback0              10.255.255.1    YES NVRAM  up                    up
"""

TUN100 = """Tunnel100 is up, line protocol is up
  Hardware is Tunnel
  Internet address is 169.254.10.2/30
  Tunnel source 203.0.113.1 (GigabitEthernet1), destination 52.0.0.1
  Tunnel protocol/transport IPSEC/IP
  Tunnel protection via IPSec (profile "aws")
"""

CRYPTO = """Crypto session current status

Interface: Tunnel100
Profile: aws
Session status: UP-ACTIVE
Peer: 52.0.0.1 port 500
  Session ID: 1
  IKEv2 SA: local 203.0.113.1/500 remote 52.0.0.1/500 Active
  IPSEC FLOW: permit ip 0.0.0.0/0.0.0.0 0.0.0.0/0.0.0.0
        Active SAs: 2, origin: crypto map
"""


def test_cisco_tunnel_names():
    assert cisco.tunnel_names(BRIEF) == ["Tunnel100", "Tunnel200"]


@pytest.mark.parametrize("text", ["% Invalid input detected at '^' marker.", "Interface IP\nGarbage row\n"])
def test_cisco_brief_unreadable_is_an_error(text):
    with pytest.raises(DeviceError):
        cisco.tunnel_names(text)


def test_cisco_brief_row_cap():
    rows = "".join(f"Tunnel{i}  unassigned  YES unset  up  up\n" for i in range(11))
    with pytest.raises(DeviceError, match="row cap"):
        cisco.tunnel_names(rows, row_cap=10)


def test_cisco_parse_tunnel():
    d = cisco.parse_tunnel(TUN100, "Tunnel100")
    assert (d.up, d.source, d.destination, d.kind) == (True, "203.0.113.1", "52.0.0.1", "ipsec")
    gre = TUN100.replace("IPSEC/IP", "GRE/IP").replace("  Tunnel protection via IPSec (profile \"aws\")\n", "")
    assert cisco.parse_tunnel(gre, "Tunnel100").kind == "gre"
    assert cisco.parse_tunnel(TUN100.replace("IPSEC/IP", "GRE/IP"), "Tunnel100").kind == "ipsec"  # GRE over IPsec


@pytest.mark.parametrize("text,expect", [
    (TUN100, "Tunnel101"),                                     # answer for another interface
    (TUN100.replace("Tunnel source", "Tunnel sauce"), "Tunnel100"),
    (TUN100.replace("IPSEC/IP", "MPLS").replace("  Tunnel protection via IPSec (profile \"aws\")\n", ""), "Tunnel100"),
    ("nothing here", "Tunnel100"),
])
def test_cisco_parse_tunnel_errors(text, expect):
    with pytest.raises(DeviceError):
        cisco.parse_tunnel(text, expect)


def test_cisco_crypto_sessions():
    s = cisco.parse_crypto_sessions(CRYPTO)["Tunnel100"]
    assert (s.status, s.peer, s.local) == ("up", "52.0.0.1", "203.0.113.1")
    assert cisco.parse_crypto_sessions("") == {}
    with pytest.raises(DeviceError):
        cisco.parse_crypto_sessions("something unexpected\n")


def test_cisco_two_sessions_on_one_interface_are_unknown():
    twice = CRYPTO + CRYPTO.split("\n", 2)[2].replace("52.0.0.1", "52.0.0.9")
    s = cisco.parse_crypto_sessions(twice)["Tunnel100"]
    assert (s.status, s.peer) == ("unknown", None)


@pytest.mark.parametrize("up,session,want", [
    (True, "UP-ACTIVE", "up"), (True, "DOWN", "down"), (False, "UP-ACTIVE", "down"), (True, None, "unknown"),
    (True, "UP-NO-IKE", "unknown"),
])
def test_cisco_tunnel_ends_oper(up, session, want):
    text = TUN100 if up else TUN100.replace("line protocol is up", "line protocol is down")
    sessions = cisco.parse_crypto_sessions(CRYPTO.replace("UP-ACTIVE", session)) if session else {}
    [end] = cisco.tunnel_ends("rtr1", [cisco.parse_tunnel(text, "Tunnel100")], sessions, P)
    assert end.oper == want and end.interface == "Tunnel100" and end.prov.subject == "rtr1"


def test_cisco_hostile_names_are_cleaned():
    text = TUN100.replace("destination 52.0.0.1", "destination 52.0.0.1\x1b[2J")
    d = cisco.parse_tunnel(text, "Tunnel100")
    assert d.destination is None  # not an IP once the escape is attached: no join key


# ---- PAN-OS -------------------------------------------------------------------------

def _xml(s):
    return SafeET.fromstring(s)


FLOW = """<response status="success"><result><total>2</total><IPSec>
<entry><name>aws-1</name><inner-if>tunnel.1</inner-if><localip>203.0.113.5</localip><peerip>52.0.0.1</peerip>
<state>active</state></entry>
<entry><name>aws-2</name><inner-if>Tunnel.2</inner-if><localip>203.0.113.5</localip><peerip>52.0.0.2</peerip>
<state>init</state></entry></IPSec></result></response>"""


def test_panos_vpn_flows():
    ends = panos.vpn_flows("fw1", _xml(FLOW), P)
    assert [(e.interface, e.peer_ip, e.oper) for e in ends] == [("tunnel.1", "52.0.0.1", "up"), ("tunnel.2", "52.0.0.2", "down")]
    assert panos.vpn_flows("fw1", _xml('<response status="success"><result><total>0</total></result></response>'), P) == []


@pytest.mark.parametrize("xml", [
    '<response status="error"><msg>no</msg></response>',
    '<response status="success"><result><other/></result></response>',
    '<foo/>',
    '<response status="success"><result><IPSec><entry><inner-if>ethernet1/1</inner-if></entry></IPSec></result></response>',
])
def test_panos_vpn_flow_errors(xml):
    with pytest.raises(DeviceError):
        panos.vpn_flows("fw1", _xml(xml), P)


def test_panorama_devices():
    xml = """<response status="success"><result><devices>
<entry name="0071"><serial>0071</serial><hostname>fw-dc1</hostname><ip-address>10.0.0.3</ip-address>
<model>PA-3220</model><connected>yes</connected><ha><state>active</state><peer><serial>0072</serial></peer></ha></entry>
<entry name="0072"><serial>0072</serial><hostname>fw-dc2</hostname><connected>no</connected></entry>
</devices></result></response>"""
    a, b = panos.managed_firewalls(_xml(xml), P)
    assert (a.serial, a.hostname, a.mgmt_ip, a.connected, a.ha_peer_serial) == ("0071", "fw-dc1", "10.0.0.3", True, "0072")
    assert (b.connected, b.ha_peer_serial, b.mgmt_ip) == (False, None, None)
    with pytest.raises(DeviceError):
        panos.managed_firewalls(_xml('<response status="success"><result><devices><entry name="x;y"/></devices>'
                                     '</result></response>'), P)


# ---- AWS ------------------------------------------------------------------------------

SECRET = "SENTINEL-psk-do-not-leak"

VPN_RESP = {"VpnConnections": [{
    "VpnConnectionId": "vpn-0aaa1111", "CustomerGatewayId": "cgw-0bbb2222", "TransitGatewayId": "tgw-0ccc3333",
    "State": "available", "Type": "ipsec.1", "Category": "VPN",
    "CustomerGatewayConfiguration": f"<vpn_connection><pre_shared_key>{SECRET}</pre_shared_key></vpn_connection>",
    "Options": {"TunnelOptions": [{"OutsideIpAddress": "52.0.0.1", "PreSharedKey": SECRET, "TunnelInsideCidr": "x"},
                                  {"OutsideIpAddress": "52.0.0.2", "PreSharedKey": SECRET}],
                "LocalIpv4NetworkCidr": "0.0.0.0/0", "Future": {"Key": SECRET}},
    "VgwTelemetry": [{"OutsideIpAddress": "52.0.0.1", "Status": "UP", "StatusMessage": SECRET},
                     {"OutsideIpAddress": "52.0.0.2", "Status": "DOWN"}],
    "Tags": [{"Key": "psk", "Value": SECRET}], "NewTopLevel": SECRET}],
    "ResponseMetadata": {"RequestId": "r"}}
CGW_RESP = {"CustomerGateways": [{"CustomerGatewayId": "cgw-0bbb2222", "IpAddress": "203.0.113.1", "State": "available",
                                  "CertificateArn": SECRET}]}
ATT_RESP = {"TransitGatewayAttachments": [{"TransitGatewayAttachmentId": "tgw-attach-0ddd4444",
                                           "ResourceType": "vpn", "ResourceId": "vpn-0aaa1111", "State": "available"}]}


def test_aws_keep_list_drops_every_secret():
    kept = oaws.keep_fields("ec2", "DescribeVpnConnections", VPN_RESP)
    assert SECRET not in json.dumps(kept)
    vc = kept["VpnConnections"][0]
    assert vc["Options"] == {"TunnelOptions": [{"OutsideIpAddress": "52.0.0.1"}, {"OutsideIpAddress": "52.0.0.2"}]}
    assert vc["VgwTelemetry"][0] == {"OutsideIpAddress": "52.0.0.1", "Status": "UP"}
    assert set(vc) == {"VpnConnectionId", "CustomerGatewayId", "TransitGatewayId", "State", "Type", "Options",
                       "VgwTelemetry"}
    assert SECRET not in json.dumps(oaws.keep_fields("ec2", "DescribeCustomerGateways", CGW_RESP))
    assert oaws.keep_fields("ec2", "DescribeRouteTables", {"x": 1}) == {"x": 1}


def test_aws_keep_list_drops_unexpected_shapes():
    weird = {"VpnConnections": [{"VpnConnectionId": {"nested": SECRET}, "Options": [SECRET]}]}
    assert SECRET not in json.dumps(oaws.keep_fields("ec2", "DescribeVpnConnections", weird))


def _vpns(vpn=VPN_RESP, att=ATT_RESP):
    keep = oaws.keep_fields
    return oaws.aws_vpns("network", "us-east-1", keep("ec2", "DescribeVpnConnections", vpn),
                         keep("ec2", "DescribeCustomerGateways", CGW_RESP), att, P)


def test_aws_vpns():
    a, b = _vpns()
    assert (a.vpn_id, a.outside_ip, a.cgw_ip, a.tgw_attachment, a.oper) == (
        "vpn-0aaa1111", "52.0.0.1", "203.0.113.1", "tgw-attach-0ddd4444", "up")
    assert b.oper == "down"


def test_aws_vpn_with_two_attachments_names_none():
    att = {"TransitGatewayAttachments": ATT_RESP["TransitGatewayAttachments"] * 2}
    att["TransitGatewayAttachments"][1] = {**att["TransitGatewayAttachments"][1],
                                           "TransitGatewayAttachmentId": "tgw-attach-0eee5555"}
    assert {v.tgw_attachment for v in _vpns(att=att)} == {None}


def test_aws_deleted_vpns_are_skipped_and_bad_ids_raise():
    gone = {"VpnConnections": [{**VPN_RESP["VpnConnections"][0], "State": "deleted"}]}
    assert _vpns(vpn=gone) == []
    bad = {"VpnConnections": [{**VPN_RESP["VpnConnections"][0], "VpnConnectionId": "vpn-0aaa; rm"}]}
    with pytest.raises(DeviceError):
        _vpns(vpn=bad)
    with pytest.raises(DeviceError):
        oaws.aws_vpns("network", "us-east-1", {}, CGW_RESP, ATT_RESP, P)


# ---- SCM -------------------------------------------------------------------------------

def _scm(sc_peer="203.0.113.1"):
    keep = scm.keep_scm_fields
    gws = keep(scm.IKE_GATEWAYS, [{"name": "gw-east", "peer_address": {"ip": sc_peer},
                                   "authentication": {"pre_shared_key": {"key": SECRET}}},
                                  {"name": "gw-dyn", "peer_address": {"dynamic": {}}}])
    tuns = keep(scm.IPSEC_TUNNELS, [{"name": "tun-east", "auto_key": {"ike_gateway": [{"name": "gw-east", "x": SECRET}],
                                                                     "ipsec_crypto_profile": SECRET}},
                                    {"name": "tun-branch", "auto_key": {"ike_gateway": [{"name": "gw-dyn"}]}}])
    scs = keep(scm.SERVICE_CONNECTIONS, [{"name": "SC-East", "ipsec_tunnel": "tun-east", "secret_thing": SECRET}])
    rns = keep(scm.REMOTE_NETWORKS, [{"name": "Branch-1", "ipsec_tunnel": "tun-branch"}])
    assert SECRET not in json.dumps([gws, tuns, scs, rns])
    return scm.prisma_tunnels(scs, rns, tuns, gws, provenance_factory("scm", "r1", T0))


def test_scm_tunnels():
    [t] = _scm()
    assert (t.name, t.kind, t.peer_ip) == ("SC-East", "service_connection", "203.0.113.1")  # dynamic peer: no row


def test_scm_errors():
    with pytest.raises(DeviceError):
        scm.prisma_tunnels("nope", [], [], [], P)  # type: ignore[arg-type]
    with pytest.raises(DeviceError):
        scm.prisma_tunnels([{"ipsec_tunnel": "x"}], [], [], [], P)


# ---- parsers feed join ------------------------------------------------------------------

def test_parsed_observations_join_to_learned_links(tmp_path):
    inv = _inv(tmp_path)
    ends = cisco.tunnel_ends("rtr1", [cisco.parse_tunnel(TUN100, "Tunnel100")], cisco.parse_crypto_sessions(CRYPTO), P)
    res = join(ends + _vpns(), inv)
    [lk] = res.links
    assert lk.origin == "learned" and lk.b.aws_tgw_attachment == "tgw-attach-0ddd4444"
    assert SECRET not in json.dumps([str(lk), [c.to_dict() for c in res.candidates]])


# ---- view -----------------------------------------------------------------------------

TOPO = "topology: {ttl_fresh: 3600, ttl_max: 86400}\n"


def _state(inv, *ends: TunnelEnd, t=T0):
    from nettrace.discovery.model import AwsVpn, Provenance
    vpn = lambda ip, att="tgw-attach-0abc": AwsVpn("network", "us-east-1", "vpn-0abc", ip, "203.0.113.1", "tgw-0abc",  # noqa: E731
                                                   None, att, "up", Provenance("aws", "aws:network/us-east-1", t, "r1", "d"))
    obs = list(ends) + [vpn("52.0.0.1"), vpn("52.0.0.2")]
    state, _ = merge(join(obs, inv), inv, StoreState(),
                     RunRecord("r1", t, t, ["rtr1", "rtr2", "aws:network/us-east-1"], {}), t)
    return state


def _tun(dev, intf, local, peer, t=T0):
    from nettrace.discovery.model import Provenance
    return TunnelEnd(dev, intf, local, peer, "ipsec", "up", Provenance("cisco", dev, t, "r1", "d"))


def test_view_without_topology_section_uses_declared_only(tmp_path):
    inv = _inv(tmp_path)
    state = _state(inv, _tun("rtr1", "Tunnel1", "203.0.113.1", "52.0.0.1"))
    view = TopologyView(inv, state, T0)
    assert view.from_device("rtr1", "Tunnel1", None) is None
    hit = view.from_device("fw1", "ethernet1/4", None)
    assert isinstance(hit, Found) and hit.tag() == "[declared]"


def test_view_fresh_stale_expired(tmp_path):
    inv = _inv(tmp_path, TOPO)
    state = _state(inv, _tun("rtr1", "Tunnel1", "203.0.113.1", "52.0.0.1"))
    fresh = TopologyView(inv, state, T0 + 720).from_device("rtr1", "Tu1", None)
    assert isinstance(fresh, Found) and fresh.freshness == "fresh" and fresh.tag() == "[learned 12m ago]"
    assert fresh.far_end.aws_tgw_attachment == "tgw-attach-0abc"
    assert fresh.link_field()["age_s"] == 720
    stale = TopologyView(inv, state, T0 + 7200).from_device("rtr1", "Tunnel1", None)
    assert isinstance(stale, Found) and stale.tag() == "[learned 2h ago, stale]"
    expired = TopologyView(inv, state, T0 + 90000).from_device("rtr1", "Tunnel1", None)
    assert isinstance(expired, Unusable) and "expired" in expired.reason
    assert TopologyView(inv, state, T0, use_learned=False).from_device("rtr1", "Tunnel1", None) is None


def test_view_inferred_is_unusable(tmp_path):
    inv = _inv(tmp_path, TOPO)
    state = _state(inv, _tun("rtr1", "Tunnel1", "10.9.9.9", "52.0.0.1"))  # NAT: inferred
    hit = TopologyView(inv, state, T0).from_device("rtr1", "Tunnel1", None)
    assert isinstance(hit, Unusable) and "inferred" in hit.reason


def test_view_two_tunnels_to_one_device_names_the_device_only(tmp_path):
    inv = _inv(tmp_path, TOPO)
    state = _state(inv, _tun("rtr1", "Tunnel1", "203.0.113.1", "52.0.0.1"), _tun("rtr1", "Tunnel2", "203.0.113.1", "52.0.0.2"))
    hit = TopologyView(inv, state, T0).from_aws("tgw-attach-0abc")
    assert isinstance(hit, Found) and hit.far_end == LinkEnd(device="rtr1") and "Tunnel1, Tunnel2" in hit.note


def test_view_conflict_is_unusable(tmp_path):
    inv = _inv(tmp_path, TOPO)
    state = _state(inv, _tun("rtr1", "Tunnel1", "203.0.113.1", "52.0.0.1"), _tun("rtr2", "Tunnel1", "203.0.113.1", "52.0.0.2"))
    assert isinstance(TopologyView(inv, state, T0).from_aws("tgw-attach-0abc"), Unusable)


def test_view_absent_link_is_unusable(tmp_path):
    inv = _inv(tmp_path, TOPO)
    state = _state(inv, _tun("rtr1", "Tunnel1", "203.0.113.1", "52.0.0.1"))
    state, _ = merge(join([], inv), inv, state, RunRecord("r2", T0, T0, ["rtr1", "aws:network/us-east-1"], {}), T0 + 10)
    hit = TopologyView(inv, state, T0 + 20).from_device("rtr1", "Tunnel1", None)
    assert isinstance(hit, Unusable) and "not seen" in hit.reason


def test_view_declared_confirmed_and_conflict(tmp_path):
    decl = """
  - name: rtr1-aws
    a: {device: rtr1, interface: Tunnel1}
    b: {aws: {tgw_attachment: ATT}}
"""
    inv = _inv(tmp_path, decl.replace("ATT", "tgw-attach-0abc") + TOPO)
    state = _state(inv, _tun("rtr1", "Tunnel1", "203.0.113.1", "52.0.0.1"))
    hit = TopologyView(inv, state, T0 + 600).from_device("rtr1", "Tunnel1", None)
    assert isinstance(hit, Found) and hit.tag() == "[declared, confirmed 10m ago]" and not hit.conflicts

    inv2 = _inv(tmp_path, decl.replace("ATT", "tgw-attach-0zzz") + TOPO)
    state2 = _state(inv2, _tun("rtr1", "Tunnel1", "203.0.113.1", "52.0.0.1"))
    hit2 = TopologyView(inv2, state2, T0).from_device("rtr1", "Tunnel1", None)
    assert isinstance(hit2, Found) and hit2.far_end.aws_tgw_attachment == "tgw-attach-0zzz" and hit2.conflicts
    # the disagreeing learned link is reachable from the AWS side, but never usable
    assert isinstance(TopologyView(inv2, state2, T0).from_aws("tgw-attach-0abc"), Unusable)


# ---- plan --------------------------------------------------------------------------------

def test_plan_names_only_inventory_subjects(tmp_path):
    inv = _inv(tmp_path)
    p = plan(inv)
    subjects = {x.subject for x in p}
    assert subjects == {"rtr1", "rtr2", "fw1", "aws:network/us-east-1", "scm"}
    assert {x.guard_id for x in p} == {"B3", "B6", "B7", "C2", "C4", "A1", "A2", "-", "D2", "D3", "D4", "D5"}
    assert {x.subject for x in plan(inv, scope="devices", devices=("rtr1",))} == {"rtr1"}
    assert not [x for x in plan(inv, aws=False, prisma=False) if x.subject.startswith(("aws", "scm"))]
    with pytest.raises(InventoryError):
        plan(inv, devices=("ghost",))
    with pytest.raises(ValueError):
        plan(inv, scope="everything")
