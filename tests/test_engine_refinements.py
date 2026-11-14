"""Engine refinements: unknown next hop, egress failures, Clients.close, return budget, max_hops, timing, callbacks."""

import json
from types import SimpleNamespace

import pytest

from nettrace.demo import install
from nettrace.engine import Clients, Tracer
from nettrace.errors import CancelToken, Deadline, DeviceError
from nettrace.models import Flow, Hop, Outcome, Status
from nettrace.steps import DeviceAt, Egress, StepResult

A, B = "10.1.1.10", "10.2.2.20"
FLOW = Flow(src=A, dst=B, protocol="tcp", dst_port=443)
DEMO_FLOW = Flow(src="10.1.10.25", dst="10.20.1.50", protocol="tcp", dst_port=443)


def info(node="dev1"):
    return Hop(domain="cisco", node=node, component="router", status=Status.PASS, summary="s")


class Scripted(Tracer):
    """Drivers replaced: `steps` is a list of StepResult factories consumed in order."""

    def __init__(self, steps, **kw):
        super().__init__(install(), **kw)
        self.steps, self.n = steps, 0

    def locate_source(self, flow, start_at):
        return DeviceAt(device="x"), Hop(domain="engine", node=flow.src, component="source", status=Status.INFO,
                                         summary="src")

    def _step(self, pos, flow):
        res = self.steps[min(self.n, len(self.steps) - 1)](flow)
        self.n += 1
        return res


def egress_step(nh, device=None):
    dev = device or "x"

    def make(flow):
        return StepResult(hops=[info(dev)], flow=flow, egress=Egress(device=dev, interface="e0", next_hop=nh))
    return make


def some_device(t):
    return next(n for n, d in t.inv.devices.items() if d.platform == "cisco_iosxe" and not d.aws)


def run_egress(nh, monkeypatch=None):
    t = Scripted([])
    dev = some_device(t)
    t.steps = [egress_step(nh, dev)]
    monkeypatch.setattr(t.inv, "link_from_device", lambda *a, **k: None) if monkeypatch else None
    monkeypatch.setattr(t.inv, "device_by_address", lambda ip: None)
    monkeypatch.setattr(t.inv, "ambiguous_owners", lambda ip: [])
    return t.trace(FLOW), dev


# ---- 1. unknown next hop ----------------------------------------------------------------------------------
@pytest.mark.parametrize("nh", ["10.99.99.99", "not-an-ip"])
def test_private_or_unparsable_unknown_next_hop_is_incomplete_with_unknown_hop(monkeypatch, nh):
    r, dev = run_egress(nh, monkeypatch)
    assert r.outcome == Outcome.INCOMPLETE
    hop = r.hops[-1]
    assert hop.component == "next-hop" and hop.status == Status.UNKNOWN and hop.node == dev
    assert "not in the inventory" in hop.summary and "cannot be verified" in hop.summary
    assert "nettrace inventory discover" in hop.summary


def test_next_hop_inside_an_inventory_network_is_unknown_even_if_global(monkeypatch):
    t = Scripted([])
    t.steps = [egress_step("8.8.8.8", some_device(t))]
    monkeypatch.setattr(t.inv, "device_by_address", lambda ip: None)
    monkeypatch.setattr(t.inv, "ambiguous_owners", lambda ip: [])
    monkeypatch.setattr(t.inv, "link_from_device", lambda *a, **k: None)
    monkeypatch.setattr(t.inv, "network_for", lambda ip: SimpleNamespace(prefix="8.8.8.0/24"))
    r = t.trace(FLOW)
    assert r.outcome == Outcome.INCOMPLETE and r.hops[-1].status == Status.UNKNOWN


def test_public_unknown_next_hop_is_exited_with_info_hop(monkeypatch):
    r, dev = run_egress("8.8.8.8", monkeypatch)
    assert r.outcome == Outcome.EXITED
    hop = r.hops[-1]
    assert hop.component == "next-hop" and hop.status == Status.INFO and hop.node == dev
    assert "8.8.8.8" in hop.summary


# ---- 2. failure while resolving egress --------------------------------------------------------------------
def test_exception_in_resolve_egress_becomes_unknown_hop(monkeypatch):
    t = Scripted([])
    t.steps = [egress_step("10.0.0.1", some_device(t))]

    def boom(self, eg, flow):
        raise DeviceError("device went away")

    monkeypatch.setattr(Tracer, "_resolve_egress", boom)
    r = t.trace(FLOW)
    assert r.outcome == Outcome.INCOMPLETE and "device went away" in r.reason
    bad = r.hops[-1]
    assert bad.component == "error" and bad.status == Status.UNKNOWN and "device went away" in bad.summary
    assert bad.node == some_device(t) and bad.location


def test_cancel_in_resolve_egress_is_a_cancel_not_an_error(monkeypatch):
    token = CancelToken()
    t = Scripted([], cancel=token)
    t.steps = [egress_step("10.0.0.1", some_device(t))]

    def boom(self, eg, flow):
        token.cancel()
        raise DeviceError("wrapped")

    monkeypatch.setattr(Tracer, "_resolve_egress", boom)
    r = t.trace(FLOW)
    assert r.cancelled and r.outcome == Outcome.INCOMPLETE and r.reason == "cancelled by user"
    assert not any(h.component == "error" for h in r.hops)


def test_deadline_is_checked_before_resolving_egress(monkeypatch):
    t = Scripted([])
    t.steps = [egress_step("10.0.0.1", some_device(t))]
    called = []
    monkeypatch.setattr(Tracer, "_resolve_egress", lambda self, eg, flow: called.append(1))
    real = t._step

    def step_then_expire(pos, flow):
        res = real(pos, flow)
        t.deadline._end = 0
        return res

    monkeypatch.setattr(t, "_step", step_then_expire)
    r = t.trace(FLOW)
    assert not called and r.outcome == Outcome.INCOMPLETE
    assert r.hops[-1].status == Status.UNKNOWN and "deadline" in r.hops[-1].summary


# ---- 3. Clients.close -------------------------------------------------------------------------------------
def test_clients_close_closes_everything_and_survives_failures():
    c = Clients(install())
    closed = []

    class Stub:
        def __init__(self, name, fail=False):
            self.name, self.fail = name, fail

        def close(self):
            closed.append(self.name)
            if self.fail:
                raise RuntimeError("boom")

    c._devices = {"d1": Stub("d1", fail=True), "d2": object()}
    c._scm, c._aws, c._panorama = Stub("scm"), Stub("aws", fail=True), Stub("panorama")
    c.close()  # must not raise
    assert sorted(closed) == ["aws", "d1", "panorama", "scm"]


def test_clients_close_with_nothing_created():
    Clients(install()).close()


# ---- 4. return trace budget -------------------------------------------------------------------------------
def test_deadline_renewed_is_fresh_and_shares_the_cancel_token():
    token = CancelToken()
    d = Deadline(5, token)
    d._end = 0
    n = d.renewed()
    n.check()
    assert n.seconds == 5 and n.cancel is token


def test_return_trace_uses_a_fresh_deadline_on_all_clients():
    t = Scripted([lambda flow: StepResult(hops=[info()], flow=flow, outcome=Outcome.REACHABLE, reason="ok")])
    fake = SimpleNamespace(deadline=t.deadline, api=SimpleNamespace(deadline=t.deadline))
    t.clients._devices["fake"] = fake
    seen = []
    orig = t.clients.set_deadline

    def spy(d):
        seen.append(d)
        orig(d)

    t.clients.set_deadline = spy
    first = t.deadline
    t.trace_with_return(FLOW)
    assert seen and seen[0] is not first and t.deadline is seen[0]
    assert fake.deadline is t.deadline and fake.api.deadline is t.deadline


# ---- 5. max_hops ------------------------------------------------------------------------------------------
def test_max_hops_counts_hops_not_steps():
    def many(flow):
        return StepResult(hops=[info(f"h{i}") for i in range(5)], flow=flow, next=DeviceAt(device="x2"))

    t = Scripted([many], max_hops=8)
    r = t.trace(FLOW)
    assert r.outcome == Outcome.INCOMPLETE and r.reason == "max hops reached (8)"
    assert len(r.hops) == 11, "hops a driver already returned are not truncated"
    assert t.n == 2


def test_max_hops_step_cap_still_guards_loops():
    t = Scripted([lambda flow: StepResult(hops=[info()], flow=flow, next=DeviceAt(device=f"d{t.n}"))], max_hops=4)
    r = t.trace(FLOW)
    assert r.outcome == Outcome.INCOMPLETE and "max hops reached" in r.reason


# ---- 6. timing and events ---------------------------------------------------------------------------------
def test_elapsed_ms_absent_when_none_present_when_set():
    from nettrace.models import TraceResult

    h1, h2 = info("a"), info("b")
    h2.elapsed_ms = 12
    d = TraceResult(flow=FLOW, outcome=Outcome.REACHABLE, reason="ok", hops=[h1, h2]).to_dict()
    assert "elapsed_ms" not in d["Hops"][0]
    assert d["Hops"][1]["elapsed_ms"] == 12
    json.dumps(d)


def test_engine_sets_elapsed_on_first_hop_of_each_step_only():
    t = Scripted([lambda flow: StepResult(hops=[info("a"), info("b")], flow=flow, outcome=Outcome.REACHABLE,
                                          reason="ok")])
    r = t.trace(FLOW)
    assert r.hops[0].elapsed_ms is None  # engine source hop
    assert isinstance(r.hops[1].elapsed_ms, int) and r.hops[2].elapsed_ms is None


def test_on_event_stream_and_raising_callbacks_do_not_break_the_trace():
    events = []

    def on_event(e):
        events.append(e)
        raise RuntimeError("consumer bug")

    def progress(msg):
        raise RuntimeError("progress bug")

    r = Tracer(install(), progress=progress, on_event=on_event).trace(DEMO_FLOW)
    assert r.outcome in (Outcome.REACHABLE, Outcome.EXITED, Outcome.BLOCKED, Outcome.INCOMPLETE) and r.hops
    kinds = [e["event"] for e in events]
    assert kinds[0] == "step_start" and kinds[-1] == "end" and "hops" in kinds
    hops_ev = next(e for e in events if e["event"] == "hops")
    assert hops_ev["count"] == len(hops_ev["hops"]) and {"node", "status", "component"} <= set(hops_ev["hops"][0])
    assert events[-1]["outcome"] == r.outcome.value and events[-1]["reason"] == r.reason


def test_progress_callback_still_receives_messages():
    msgs = []
    Tracer(install(), progress=msgs.append).trace(DEMO_FLOW)
    assert any("querying" in m for m in msgs)
