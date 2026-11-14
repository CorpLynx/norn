"""Driver refinements: every client can be closed; a connected destination with no ARP entry is a WARN.
Fakes and the demo simulators only; nothing here talks to a device."""

from types import SimpleNamespace

import pytest

from nettrace.demo import install
from nettrace.drivers import aws, cisco_iosxe, panos, prisma
from nettrace.drivers.cisco_iosxe import CefEntry, CefResult
from nettrace.engine import Tracer
from nettrace.errors import DeviceError
from nettrace.models import Flow, Status
from nettrace.steps import DeviceAt

FLOW = Flow(src="10.1.10.25", dst="10.20.0.9", protocol="tcp", dst_port=443)


# ---- close() ------------------------------------------------------------------------------------------
class _Closable:
    def __init__(self):
        self.closed = 0

    def close(self):
        self.closed += 1


def _api(**kw):
    return panos.XmlApi("fw", ["192.0.2.1"], None, None, True, **kw)


def test_xmlapi_close_owned_session_is_idempotent_and_lazily_recreated(monkeypatch):
    monkeypatch.setattr(panos.XmlApi, "session_override", None)
    api = _api()
    first = api.session
    spy = _Closable()
    first.close = spy.close
    api.close()
    api.close()
    assert spy.closed == 1 and api.session is None
    api._post  # still defined; the next request creates a fresh session
    assert api._new_session() is not first


def test_xmlapi_close_never_raises(monkeypatch):
    monkeypatch.setattr(panos.XmlApi, "session_override", None)
    api = _api()

    def boom():
        raise RuntimeError("x")
    api.session.close = boom
    api.close()
    api.close()


def test_xmlapi_close_leaves_seam_session_alone(monkeypatch):
    stand_in = _Closable()
    stand_in.verify = None
    monkeypatch.setattr(panos.XmlApi, "session_override", lambda api: stand_in)
    api = _api()
    api.close()
    api.close()
    assert stand_in.closed == 0 and api.session is stand_in


def test_xmlapi_close_leaves_replaced_session_alone(monkeypatch):
    monkeypatch.setattr(panos.XmlApi, "session_override", None)
    api = _api()
    mine = api.session
    other = _Closable()
    api.session = other
    api.close()
    assert other.closed == 0 and api.session is other
    mine.close()


def test_panos_and_panorama_clients_close(monkeypatch):
    monkeypatch.setattr(panos.XmlApi, "session_override", None)
    inv = install()
    fw = next(d for d in inv.devices.values() if d.platform.startswith("panos"))
    pano = panos.PanoramaClient(inv.panorama)
    shared = panos.PanosClient(fw, pano.api, target="0123")
    shared.close()  # the api belongs to Panorama: not closed here
    assert pano.api.session is not None
    own = panos.PanosClient(fw)
    own.close()
    own.close()
    assert own.api.session is None
    pano.close()
    pano.close()
    assert pano.api.session is None


def test_scm_close_idempotent_and_client_still_works_with_seam():
    install()
    scm = prisma.ScmClient()
    scm._token, scm._token_expiry = "tok", 1e12
    scm.close()
    scm.close()
    assert scm._token is None
    assert isinstance(scm.get_all("/config/security/v1/security-rules", {"folder": "Remote Networks"}), list)


def test_aws_env_close_with_backend_does_not_break_the_seam():
    inv = install()
    env = aws.AwsEnv(inv)
    backend = env._backend
    assert backend is not None
    env.close()
    env.close()
    assert env._backend is backend
    Tracer(inv).trace(Flow("10.1.10.25", "10.20.1.50", "tcp", 443))  # the lab backend still serves traces


def test_aws_env_close_closes_cached_boto_clients():
    env = aws.AwsEnv.__new__(aws.AwsEnv)
    c = _Closable()
    env._backend, env._clients, env._sessions = None, {("a", "r", "ec2"): c}, {"a": object()}
    env.close()
    env.close()
    assert c.closed == 1 and env._clients == {} and env._sessions == {}


def test_aws_env_close_swallows_client_errors():
    env = aws.AwsEnv.__new__(aws.AwsEnv)

    class Bad:
        def close(self):
            raise RuntimeError("x")
    env._backend, env._clients, env._sessions = None, {("a", "r", "ec2"): Bad()}, {}
    env.close()


# ---- ARP on an attached destination -----------------------------------------------------------------------
def _fake(arp):
    dev = SimpleNamespace(name="r1", vrf=None)
    return SimpleNamespace(
        device=dev, evidence=[], interface=lambda n: {}, policy_route_map=lambda n: None,
        nat_interfaces=lambda: {}, zone_members=lambda: {}, inspect_rules=lambda: {},
        cef=lambda ip, vrf: CefResult(prefix="10.20.0.0/24", entries=[CefEntry("attached", None, "Gi1")]),
        route=lambda ip, vrf: ("10.20.0.0/24", "connected"), arp=arp)


def _step(arp):
    return cisco_iosxe.step(_fake(arp), DeviceAt(device="r1", arrival_interface="Gi0"), FLOW)


def test_attached_with_arp_entry_is_unchanged():
    res = _step(lambda ip, vrf: {"MAC_ADDRESS": "aaaa.bbbb.cccc", "INTERFACE": "Gi1"})
    hop = res.hops[0]
    assert hop.status == Status.PASS
    assert any("ARP 10.20.0.9 -> aaaa.bbbb.cccc on Gi1" in d for d in hop.details)
    assert not any("no ARP entry" in w for w in res.warnings)


def test_attached_without_arp_entry_is_warn():
    res = _step(lambda ip, vrf: None)
    hop = res.hops[0]
    assert hop.status == Status.WARN
    assert any("no ARP entry for 10.20.0.9 on Gi1" in d for d in hop.details)
    assert any(w.startswith("r1:") and "no ARP entry" in w for w in res.warnings)


def test_unknown_hop_stays_unknown_when_arp_is_missing():
    fake = _fake(lambda ip, vrf: None)
    fake.nat_interfaces = lambda: {"gi1": "outside"}  # NAT on the egress interface makes the hop UNKNOWN
    res = cisco_iosxe.step(fake, DeviceAt(device="r1", arrival_interface="Gi0"), FLOW)
    assert res.hops[0].status == Status.UNKNOWN
    assert any("no ARP entry" in d for d in res.hops[0].details)


def test_arp_query_failure_is_not_no_entry():
    def boom(ip, vrf):
        raise DeviceError("arp failed")
    with pytest.raises(DeviceError):
        _step(boom)
