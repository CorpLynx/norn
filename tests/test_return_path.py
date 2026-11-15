"""Return-path trace (G15): reverse flow, symmetry comparison, exit codes, CLI, web API, UI text, audit label.
Engine tests use a scripted Tracer (fake drivers: no device, no network); the preset tests use the demo lab."""

import json
import re
from importlib import resources

import pytest
from click.testing import CliRunner

from nettrace import cli
from nettrace.demo import PRESETS, install
from nettrace.engine import Tracer
from nettrace.errors import CancelToken
from nettrace.models import Flow, Hop, Outcome, Status, SymmetryStatus
from nettrace.output import exit_code
from nettrace.steps import DeviceAt, StepResult
from nettrace.web import server

APP_HTML = resources.files("nettrace.web").joinpath("static/app.html").read_text(encoding="utf-8")
A, B = "10.1.1.10", "10.2.2.20"
FWD = Flow(src=A, dst=B, protocol="tcp", dst_port=443)


def fw(node, i="e1/1", e="e1/2", zf="a", zt="b", serial="S1", status=Status.PASS):
    return Hop(domain="panos", node=node, component="firewall", status=status, summary="s", ingress=i, egress=e,
               location={"zone_from": zf, "zone_to": zt, "serial": serial})


def nacl(status=Status.PASS):
    return Hop(domain="aws", node="acl-1", component="nacl", status=status, summary="s")


class Scripted(Tracer):
    """Engine with the drivers replaced: `script[direction]` = (hops, outcome, reason) or an Exception."""

    def __init__(self, script, **kw):
        super().__init__(install(), **kw)
        self.script, self.seen = script, []

    def locate_source(self, flow, start_at):
        d = "fwd" if flow.src == A else "ret"
        return DeviceAt(device=d), Hop(domain="engine", node=flow.src, component="source", status=Status.INFO, summary="src")

    def _step(self, pos, flow):
        self.seen.append((pos.device, flow))
        item = self.script[pos.device]
        if isinstance(item, Exception):
            raise item
        if callable(item):
            item(self)
            item = self.script[pos.device + "_result"]
        hops, outcome, reason = item
        if outcome is None:  # not finished: `reason` names the next scripted device
            return StepResult(hops=[*hops], flow=flow, next=DeviceAt(device=reason))
        return StepResult(hops=[*hops], flow=flow, outcome=outcome, reason=reason)


OK = Outcome.REACHABLE


def run(script, **kw):
    return Scripted(script, **kw).trace_with_return(FWD)


# ---- comparison ------------------------------------------------------------------------------------
def test_symmetric_when_same_device_and_swapped_interfaces():
    r = run({"fwd": ([fw("fw-a")], OK, "ok"), "ret": ([fw("fw-a", "e1/2", "e1/1", "b", "a")], OK, "back")})
    rp = r.return_path
    assert rp.outcome == OK and rp.symmetry.status == SymmetryStatus.SYMMETRIC
    assert exit_code(r) == 0


def test_asymmetric_stateful_device_on_forward_only_names_it_and_exits_0_with_warning():
    r = run({"fwd": ([fw("fw-a"), fw("fw-b")], OK, "ok"), "ret": ([fw("fw-a")], OK, "back")})
    sy = r.return_path.symmetry
    assert sy.status == SymmetryStatus.ASYMMETRIC
    assert any("fw-b" in d and "forward path only" in d and "stateful" in d for d in sy.details)
    assert exit_code(r) == 0
    assert any("asymmetric" in w and "fw-b" in w for w in r.warnings)
    assert r.outcome == OK  # the forward verdict is untouched


@pytest.mark.parametrize("ret_hop", [fw("fw-a", serial="S2"), fw("fw-a", "e1/3", "e1/4"), fw("fw-a", zf="x", zt="y")])
def test_asymmetric_other_member_interface_or_zone(ret_hop):
    r = run({"fwd": ([fw("fw-a")], OK, "ok"), "ret": ([ret_hop], OK, "back")})
    assert r.return_path.symmetry.status == SymmetryStatus.ASYMMETRIC


def test_nacl_is_stateless_and_not_compared():
    r = run({"fwd": ([fw("fw-a"), nacl()], OK, "ok"), "ret": ([fw("fw-a")], OK, "back")})
    assert r.return_path.symmetry.status == SymmetryStatus.SYMMETRIC


def test_return_only_device_is_asymmetric_too():
    r = run({"fwd": ([fw("fw-a")], OK, "ok"), "ret": ([fw("fw-a"), fw("fw-c")], OK, "back")})
    assert r.return_path.symmetry.status == SymmetryStatus.ASYMMETRIC
    assert any("fw-c" in d and "return path only" in d for d in r.return_path.symmetry.details)


def test_return_blocked_by_stateless_hop_exits_3_with_reason():
    r = run({"fwd": ([fw("fw-a")], OK, "ok"), "ret": ([nacl(Status.BLOCK)], Outcome.BLOCKED, "NACL denies")})
    rp = r.return_path
    assert rp.outcome == Outcome.BLOCKED and rp.reason == "return path blocked: NACL denies"
    assert rp.symmetry.status == SymmetryStatus.UNKNOWN
    assert exit_code(r) == 3 and r.outcome == OK


def test_return_denied_by_stateful_firewall_is_unverified_not_blocked():
    """A new-session policy match on the return flow says nothing about an established session: exit 4, not 3."""
    r = run({"fwd": ([fw("fw-a")], OK, "ok"), "ret": ([fw("fw-a", status=Status.BLOCK)], Outcome.BLOCKED, "rule deny")})
    rp = r.return_path
    assert rp.outcome == Outcome.INCOMPLETE and "session table" in rp.reason
    assert rp.symmetry.status == SymmetryStatus.UNKNOWN
    assert exit_code(r) == 4


def test_return_unknown_hop_makes_symmetry_unknown_never_symmetric():
    r = run({"fwd": ([fw("fw-a")], OK, "ok"), "ret": RuntimeError("boom")})
    rp = r.return_path
    assert rp.outcome == Outcome.INCOMPLETE and rp.symmetry.status == SymmetryStatus.UNKNOWN
    assert any(h.status == Status.UNKNOWN for h in rp.hops)
    assert exit_code(r) == 4


def test_missing_interface_data_in_one_direction_is_unknown():
    bare = Hop(domain="panos", node="fw-a", component="firewall", status=Status.PASS, summary="s")
    r = run({"fwd": ([fw("fw-a")], OK, "ok"), "ret": ([bare], OK, "back")})
    assert r.return_path.symmetry.status == SymmetryStatus.UNKNOWN
    assert exit_code(r) == 4


@pytest.mark.parametrize("outcome", [Outcome.BLOCKED, Outcome.INCOMPLETE, Outcome.EXITED])
def test_forward_not_reachable_skips_the_return(outcome):
    t = Scripted({"fwd": ([fw("fw-a")], outcome, "why")})
    r = t.trace_with_return(FWD)
    assert r.return_path.outcome is None and r.return_path.symmetry.status == SymmetryStatus.NOT_RUN
    assert outcome.value in r.return_path.reason and r.return_path.hops == []
    assert [d for d, _ in t.seen] == ["fwd"], "no return query may be sent"
    expected = {Outcome.BLOCKED: 3, Outcome.INCOMPLETE: 4, Outcome.EXITED: 0}[outcome]
    assert exit_code(r) == expected


def test_cancel_during_forward_skips_return():
    token = CancelToken()
    t = Scripted({"fwd": lambda self: token.cancel(), "fwd_result": ([fw("fw-a")], None, "fwd2"),
                  "fwd2": ([fw("fw-b")], OK, "ok")}, cancel=token)
    r = t.trace_with_return(FWD)
    assert r.cancelled and r.return_path.symmetry.status == SymmetryStatus.NOT_RUN
    assert "cancelled" in r.return_path.reason and exit_code(r) == 4
    assert [d for d, _ in t.seen] == ["fwd"]


def test_cancel_during_return_keeps_the_forward_result_and_marks_the_return_cancelled():
    token = CancelToken()
    t = Scripted({"fwd": lambda self: token.cancel(), "fwd_result": ([fw("fw-a")], OK, "ok"),
                  "ret": ([fw("fw-a")], OK, "never")}, cancel=token)
    r = t.trace_with_return(FWD)  # the cancel lands after the forward's last step; the return stops at its first check
    assert r.outcome == OK and not r.cancelled
    rp = r.return_path
    assert rp.cancelled and rp.outcome == Outcome.INCOMPLETE and rp.reason == "cancelled by user"
    assert rp.symmetry.status == SymmetryStatus.UNKNOWN and exit_code(r) == 4
    assert r.to_dict()["Return"]["Cancelled"] is True and [d for d, _ in t.seen] == ["fwd"]


def test_return_gets_a_fresh_time_budget():
    def expire(self):
        self.deadline._end = 0  # the forward trace used up its whole budget

    t = Scripted({"fwd": expire, "fwd_result": ([fw("fw-a")], OK, "ok"), "ret": ([fw("fw-a")], OK, "back")})
    r = t.trace_with_return(FWD)
    assert r.outcome == OK
    assert r.return_path.outcome == OK, "a slow forward trace must not make the return end 'deadline exceeded'"
    assert [d for d, _ in t.seen] == ["fwd", "ret"]


def test_return_still_ends_incomplete_when_its_own_budget_runs_out():
    def expire_ret(self):
        self.deadline._end = 0

    t = Scripted({"fwd": ([fw("fw-a")], OK, "ok"), "ret": expire_ret, "ret_result": ([fw("fw-a")], None, "ret2"),
                  "ret2": ([fw("fw-a")], OK, "never")})
    r = t.trace_with_return(FWD)
    assert r.outcome == OK
    assert "deadline" in r.return_path.reason and r.return_path.outcome == Outcome.INCOMPLETE
    assert exit_code(r) == 4


def test_hop_numbers_are_unique_across_both_directions():
    r = run({"fwd": ([fw("fw-a")], OK, "ok"), "ret": ([fw("fw-a")], OK, "back")})
    idx = [h.index for h in r.hops] + [h.index for h in r.return_path.hops]
    assert idx == list(range(1, len(idx) + 1))


# ---- the reverse flow --------------------------------------------------------------------------------
def result_for(flow, final=None):
    from nettrace.models import TraceResult
    return TraceResult(flow=flow, outcome=OK, reason="ok", final_flow=final or flow)


def test_return_flow_swaps_addresses_and_ports_and_says_the_port_is_assumed():
    from nettrace import symmetry
    f, notes = symmetry.return_flow(result_for(FWD))
    assert (f.src, f.dst, f.src_port, f.dst_port, f.protocol) == (B, A, 443, 49152, "tcp")
    assert any("49152" in n and "assumed" in n for n in notes)
    f2, notes2 = symmetry.return_flow(result_for(Flow(src=A, dst=B, protocol="tcp", dst_port=443, src_port=50000)))
    assert f2.dst_port == 50000 and not notes2


def test_return_flow_icmp_has_no_ports_and_no_user():
    from nettrace import symmetry
    f, _ = symmetry.return_flow(result_for(Flow(src=A, dst=B, protocol="icmp", user="alice")))
    assert f.src_port is None and f.dst_port is None and f.user is None


def test_return_flow_after_destination_nat_starts_at_the_real_server():
    from nettrace import symmetry
    f, notes = symmetry.return_flow(result_for(FWD, Flow(src=A, dst="10.9.9.9", protocol="tcp", dst_port=8443)))
    assert (f.src, f.dst, f.src_port) == ("10.9.9.9", A, 8443)
    assert any("destination NAT" in n for n in notes)


# ---- JSON contract ---------------------------------------------------------------------------------------
def test_forward_only_json_is_unchanged_and_has_no_return():
    inv = install()
    flow = Flow(src="10.1.10.25", dst="10.20.1.50", protocol="tcp", dst_port=443)
    def norm(data):  # evidence of parallel AWS lookups is appended in thread-completion order: sort it
        for h in data["Hops"]:
            h.pop("elapsed_ms", None)  # wall-clock timing differs run to run
            h["evidence"] = sorted(h["evidence"], key=lambda e: (e["source"], e["request"], e["response"]))
        return data

    d = norm(Tracer(inv).trace(flow).to_dict())
    assert set(d) == {"Flow", "Outcome", "Reason", "Hops", "Warnings"}
    with_ret = norm(Tracer(inv).trace_with_return(flow).to_dict())
    ret = with_ret.pop("Return")
    assert with_ret == d, "adding --return must not change a single forward byte"
    assert set(ret) == {"Flow", "Outcome", "Reason", "Hops", "Warnings", "Symmetry"}
    assert set(ret["Symmetry"]) == {"status", "details"}
    assert ret["Hops"][0]["index"] == len(d["Hops"]) + 1


# ---- demo presets ------------------------------------------------------------------------------------------
def preset(pid):
    f = dict(next(p for p in PRESETS if p["id"] == pid)["flow"])
    assert f.pop("return") is True
    start_at = f.pop("start_at", None)
    return Flow(src=f["src"], dst=f["dst"], protocol=f["protocol"], dst_port=f["port"]), start_at


@pytest.mark.parametrize("pid,sym,ret_outcome,code", [
    ("return-symmetric", "SYMMETRIC", "REACHABLE", 0),
    ("return-asymmetric", "ASYMMETRIC", "REACHABLE", 0),
    ("return-blocked", "UNKNOWN", "BLOCKED", 3),
])
def test_return_presets(pid, sym, ret_outcome, code):
    flow, start_at = preset(pid)
    r = Tracer(install()).trace_with_return(flow, start_at=start_at)
    assert r.outcome == OK
    assert r.return_path.symmetry.status.value == sym and r.return_path.outcome.value == ret_outcome
    assert exit_code(r) == code


def test_asymmetric_preset_names_the_skipped_firewall():
    flow, _ = preset("return-asymmetric")
    r = Tracer(install()).trace_with_return(flow)
    assert any("fw-aws-1" in d and "forward path only" in d for d in r.return_path.symmetry.details)


def test_existing_presets_keep_their_expectations_and_none_asks_for_return_by_accident():
    ids = [p["id"] for p in PRESETS]
    assert len(ids) == 19 and len([p for p in PRESETS if p["flow"].get("return")]) == 3
    assert ids[:2] == ["dc-to-prod-web", "dc-to-prod-db"]


# ---- audit label -----------------------------------------------------------------------------------------------
def audit_records(path):
    return [json.loads(line) for line in open(path).read().splitlines()]


def test_audit_records_carry_the_direction_only_with_return(monkeypatch, tmp_path):
    log = tmp_path / "dir" / "audit.log"
    monkeypatch.setenv("NETTRACE_AUDIT_LOG", str(log))
    from nettrace import audit
    audit._handlers.clear()
    flow = Flow(src="10.1.10.25", dst="10.20.1.50", protocol="tcp", dst_port=443)
    Tracer(install()).trace(flow)
    plain = audit_records(log)
    assert plain and all("direction" not in r for r in plain)
    Tracer(install()).trace_with_return(flow)
    recs = audit_records(log)[len(plain):]
    assert {r.get("direction") for r in recs} == {"forward", "return"}
    audit._handlers.clear()


# ---- CLI ------------------------------------------------------------------------------------------------------------
def cli_run(*extra, fmt="json", src="10.1.10.25", dst="10.20.1.50"):
    args = ["--demo", "--output", fmt, "trace", "run", "-s", src, *extra, "-d", dst, "--port", "443"]
    return CliRunner().invoke(cli.cli, args)


def test_cli_return_flag_anywhere_on_the_line_adds_return():
    res = cli_run("--return")
    assert res.exit_code == 0
    assert json.loads(res.output)["Return"]["Symmetry"]["status"] == "SYMMETRIC"
    res = CliRunner().invoke(cli.cli, ["--demo", "-o", "json", "trace", "run", "--return", "-s", "10.1.10.25",
                                       "-d", "10.20.1.50", "-p", "443"])
    assert "Return" in json.loads(res.output)


def test_cli_default_has_no_return_and_help_says_it_doubles_queries():
    assert "Return" not in json.loads(cli_run().output)
    helptext = CliRunner().invoke(cli.cli, ["trace", "run", "--help"]).output
    assert "--return" in helptext and "Off by default" in helptext and "doubles" in helptext


def test_cli_exit_codes_for_return_verdicts():
    assert cli_run("--return", src="10.50.12.40").exit_code == 3  # return blocked by the stateless NACL
    assert cli_run("--return", src="10.1.20.10").exit_code == 0  # asymmetric: delivered, warning only
    blocked = cli_run("--return", dst="10.20.2.10")  # forward blocked: stays 3, return not run
    assert blocked.exit_code == 3
    assert json.loads(blocked.output)["Return"]["Symmetry"]["status"] == "NOT_RUN"


def test_cli_table_has_a_separated_return_block():
    res = cli_run("--return", fmt="table", src="10.50.12.40")
    assert "Return path" in res.output and "SYMMETRY" in res.output and "RETURN BLOCKED" in res.output


def test_cli_text_output_has_return_lines():
    res = cli_run("--return", fmt="text")
    assert re.search(r"^RETURN\s+REACHABLE", res.output, re.M) and re.search(r"SYMMETRY\s+SYMMETRIC", res.output)


# ---- web API --------------------------------------------------------------------------------------------------------------
@pytest.fixture
def app():
    a = server.App(install(), demo=True)
    yield a
    a.close()


BODY = {"src": "10.1.10.25", "dst": "10.20.1.50", "protocol": "tcp", "port": 443}


def test_api_return_true_adds_section_overlay_and_exit_code(app):
    e = app.run_trace({**BODY, "return": True})
    assert e["trace"]["Return"]["Symmetry"]["status"] == "SYMMETRIC"
    assert e["return_overlay"]["path"] and e["exit_code"] == 0 and e["title"].endswith("+ return")
    assert set(e["return_overlay"]["hop_nodes"]).isdisjoint(e["overlay"]["hop_nodes"])
    assert app.history_get(e["id"]) is e


def test_api_return_defaults_to_off_and_false_is_off(app):
    for body in (BODY, {**BODY, "return": False}):
        e = app.run_trace(body)
        assert "Return" not in e["trace"] and "return_overlay" not in e


@pytest.mark.parametrize("bad", ["true", "yes", 1, 0, None, [], {}])
def test_api_return_must_be_a_boolean(app, bad):
    with pytest.raises(server.BadRequest, match="return: must be true or false"):
        app.run_trace({**BODY, "return": bad})


def test_api_cancel_during_return_ends_incomplete_with_forward_kept(app, monkeypatch):
    real = Tracer._step
    seen = []

    def step(self, pos, flow):
        seen.append(flow.src)
        res = real(self, pos, flow)
        if flow.src == "10.20.1.50":  # first return step: the user clicks Cancel
            self.cancel.cancel()
        return res

    monkeypatch.setattr(Tracer, "_step", step)
    e = app.run_trace({**BODY, "return": True, "id": "run-ret-cancel-1"})
    t = e["trace"]
    assert t["Outcome"] == "REACHABLE" and t["Return"]["Outcome"] == "INCOMPLETE"
    assert t["Return"].get("Cancelled") is True and e["exit_code"] == 4


def test_api_audit_entries_record_the_direction(app, monkeypatch, tmp_path):
    from nettrace import audit
    log = tmp_path / "a2" / "audit.log"
    monkeypatch.setenv("NETTRACE_AUDIT_LOG", str(log))
    audit._handlers.clear()
    app.run_trace({**BODY, "return": True})
    assert {r.get("direction") for r in audit_records(log)} == {"forward", "return"}
    audit._handlers.clear()


def test_api_hostile_device_name_is_data_in_json_not_markup(app, monkeypatch):
    evil = "<img src=x onerror=alert(1)>"
    real = Tracer._step

    def step(self, pos, flow):
        res = real(self, pos, flow)
        if flow.src == "10.20.1.50":
            for h in res.hops:
                if h.domain == "panos":
                    h.node = evil
        return res

    monkeypatch.setattr(Tracer, "_step", step)
    e = app.run_trace({**BODY, "return": True})
    s = e["trace"]["Return"]["Symmetry"]
    assert s["status"] == "ASYMMETRIC" and any(evil in d for d in s["details"])  # carried as text


# ---- UI text -------------------------------------------------------------------------------------------------------------------
def js_slice(start, end):
    a = APP_HTML.index(start)
    return APP_HTML[a:APP_HTML.index(end, a)]


def test_ui_has_the_checkbox_with_an_accessible_name_and_sends_a_boolean():
    assert 'id="f-return"' in APP_HTML and 'type="checkbox"' in APP_HTML
    assert 'aria-label="Include return path"' in APP_HTML
    assert "return: $(\"#f-return\").checked" in APP_HTML


@pytest.mark.parametrize("start,end", [("function symmetryLine(t){", "function verdictHtml"),
                                       ("function symmetryHtml(t){", "function showFinal"),
                                       ("function returnDivider(t){", "function renderEvents")])
def test_ui_return_text_goes_through_esc(start, end):
    """Every ${...} in the symmetry / divider templates is esc(...) or a value that was already escaped."""
    body = js_slice(start, end)
    for m in re.finditer(r"\$\{([^}]*)\}", body):
        expr = m.group(1).strip()
        assert expr.startswith("esc(") or expr in {"det"}, expr
    assert "det = (sy.details || []).map(d => `<li>${esc(d)}</li>`)" in body or "symmetryLine" in start or "Divider" in start


def test_ui_return_stream_rules():
    assert "innerHTML = entry.map_svg" in APP_HTML  # forward path map unchanged
    assert "forward path only" in APP_HTML.lower()
    for token in ("PKT_RET", "RET_OFF", ".seg.ret", "tr.rdiv", "← return", "Dotted teal line"):
        assert token in APP_HTML, token
    assert "https://" not in APP_HTML and "http://" not in re.sub(r"http://www\.w3\.org/2000/svg", "", APP_HTML)
    assert "localStorage" not in APP_HTML and "sessionStorage" not in APP_HTML


def test_ui_csp_is_unchanged():
    assert server.PAGE_CSP == ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                               "connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; "
                               "frame-ancestors 'none'")
