"""Text-level checks for the web UI and offline map: landmarks, ARIA, shortcuts, escaping, no storage/external URLs.

Nothing here runs a browser. Where node is installed, a few pure helpers are executed in a bare JS context.
"""

import json
import re
import shutil
import subprocess
from importlib import resources

import pytest

from nettrace.demo import PRESETS, install
from nettrace.engine import Tracer
from nettrace.models import Flow
from nettrace.viz.html import render_html
from nettrace.web import server

APP_HTML = resources.files("nettrace.web").joinpath("static/app.html").read_text(encoding="utf-8")
EVIL = "<img src=x onerror=alert(1)>"
NODE = shutil.which("node")
STORAGE_APIS = ("localStorage", "sessionStorage", "document.cookie", "indexedDB", "caches.open")


@pytest.fixture(scope="module")
def trace():
    inv = install()
    preset = next(p for p in PRESETS if p["expect"] == "BLOCKED")
    f = dict(preset["flow"])
    start_at = f.pop("start_at", None)
    flow = Flow(src=f["src"], dst=f["dst"], protocol=f["protocol"], dst_port=f["port"],
                application=f.get("application"), user=f.get("user"))
    return Tracer(inv).trace(flow, start_at=start_at).to_dict()


@pytest.fixture(scope="module")
def offline(trace):
    return render_html([trace])


def _slice(text, start, end):
    i = text.index(start)
    return text[i:text.index(end, i)]


def _script(text):
    return re.search(r"<script>(.*)</script>", text, re.S).group(1)


# ---- landmarks, labels, live regions ----------------------------------------------------------------
@pytest.mark.parametrize("marker", [
    '<html lang="en"', '<header id="top"', '<main id="ws"', '<aside id="left"', '<aside id="insp"',
    '<form id="form" aria-label="Trace a flow"', 'id="verdict" aria-label="Trace result" role="status" aria-live="polite"',
    'id="ferrs" aria-live="polite"', 'role="log"', 'id="err" role="alert"', 'aria-label="Position in the trace"',
    'class="skip"', "prefers-color-scheme:dark", "prefers-reduced-motion", ":focus-visible", 'name="color-scheme"',
])
def test_app_landmarks_and_aria(marker):
    assert marker in APP_HTML


def test_app_inputs_have_labels():
    for fid in ("f-src", "f-dst", "f-proto", "f-port", "f-app", "f-user", "f-start"):
        m = re.search(r"<label>([^<]+)<(?:input|select) id=\"%s\"" % fid, APP_HTML)
        assert m, fid
    assert 'aria-label="Animation speed"' in APP_HTML and '<label for="speed">' in APP_HTML


def test_app_never_uses_outline_none_without_replacement():
    # the only allowed outline:none is the SVG node (has its own :focus-visible rule) and the console input (wrapper shows focus)
    for m in re.finditer(r"[^{}]*\{[^{}]*outline:none[^{}]*\}", APP_HTML):
        assert ".node:focus" in m.group(0) or ".prompt input" in m.group(0), m.group(0)
    assert ".prompt:focus-within" in APP_HTML and ".node:focus-visible" in APP_HTML


def test_offline_landmarks(offline):
    for marker in ('<main id="map"', '<aside id="side"', 'id="summary"', 'role="status" aria-live="polite"',
                   'aria-label="Position in the packet flow"', ":focus-visible", "prefers-color-scheme:dark"):
        assert marker in offline, marker


# ---- verdict ---------------------------------------------------------------------------------------
def test_verdict_covers_every_outcome_and_exit_code():
    block = _slice(APP_HTML, "const VERDICT = {", "function verdictStop")
    for outcome in ("REACHABLE", "EXITED", "BLOCKED", "INCOMPLETE"):
        assert f"{outcome}:" in block
    assert "exit:3" in block and "exit:4" in block and block.count("exit:0") == 2
    assert "Unverified" in block and "do not treat this as reachable" in block
    assert re.search(r"V-INCOMPLETE\{[^}]*--b-warn", APP_HTML)  # amber, never green


def test_unknown_outcome_falls_back_to_unverified():
    assert "VERDICT[t.Outcome] || VERDICT.INCOMPLETE" in APP_HTML
    assert "VERDICT[t.Outcome] ? t.Outcome : \"INCOMPLETE\"" in _script_of_offline_source()


def _script_of_offline_source():
    from nettrace.viz import html as vh
    return vh._PAGE


def test_status_is_never_colour_only():
    assert "const badge = s =>" in APP_HTML and 'aria-hidden="true">${esc(GLYPH' in APP_HTML
    assert "const badge = s =>" in _script_of_offline_source()
    # canvas markers carry a glyph per status
    assert '{PASS:"✓", BLOCK:"✕", WARN:"!", UNKNOWN:"?"}' in APP_HTML


# ---- keyboard --------------------------------------------------------------------------------------
@pytest.mark.parametrize("src_name", ["app", "offline"])
def test_keyboard_shortcuts_present(src_name, offline):
    text = APP_HTML if src_name == "app" else offline
    for key in ('e.key === "ArrowRight"', 'e.key === "ArrowLeft"', 'e.key === "r"'):
        assert key in text, key
    assert 'e.key === " "' in text
    assert "<kbd>Space</kbd>" in text and "<kbd>R</kbd>" in text


def test_app_shortcuts_let_controls_keep_space():
    assert 'const own = e.target.closest("button,a,summary,tr.ev,.node")' in APP_HTML
    assert 'if (e.key === " ") { if (own) return;' in APP_HTML
    assert '$("#scrub").addEventListener("input"' in APP_HTML


def test_wheel_does_not_trap_page_scroll_when_stacked(offline):
    assert "STACKED.matches && !(e.ctrlKey || e.metaKey)) return;" in APP_HTML
    assert "STACKED.matches && !(e.ctrlKey || e.metaKey)) return;" in offline
    assert "max-width:900px" in APP_HTML and "max-width:900px" in offline
    assert 'id="fit"' in APP_HTML and 'id="fit"' in offline


# ---- hard rules ------------------------------------------------------------------------------------
@pytest.mark.parametrize("src_name", ["app", "offline"])
def test_no_external_urls_or_storage(src_name, offline):
    text = APP_HTML if src_name == "app" else offline
    assert not re.search(r"https?://", text.replace("http://www.w3.org/2000/svg", ""))
    assert "//cdn" not in text and "@import" not in text and "<link " not in text and "src=\"http" not in text
    for api in STORAGE_APIS:
        assert api not in text, api


def test_page_csp_unchanged():
    assert server.PAGE_CSP == ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; "
                               "img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def test_untrusted_fields_are_always_escaped():
    for name, text in (("app", _script(APP_HTML)), ("offline", _script_of_offline_source())):
        bare = re.findall(r"\$\{\s*(?:h|e|t|stop|x|p|d)\.(?:node|summary|status|component|domain|policy|nat|ingress|egress|Reason|"
                          r"title|created|outcome|index|source|request|response|label|sub)\s*\}", "\n".join(ln for ln in text.splitlines() if "textContent" not in ln and "setAttribute" not in ln))
        assert bare == [], (name, bare)


def test_console_notice_lists_allowed_commands_and_limits():
    for word in ("Read-only console, limited commands.", "show system info", "security-policy-match", "fib-lookup",
                 "show ip cef A.B.C.D", "One command per second", "256 KiB", "Copy output", r"\[truncated\]"):
        assert word in APP_HTML, word
    assert "err.status === 429" in APP_HTML and "err.status === 401" in APP_HTML
    assert "5 minutes after an authentication failure" in APP_HTML


def test_form_disables_while_running_and_validates():
    assert 'novalidate' in APP_HTML and "function validateForm" in APP_HTML and 'aria-invalid' in APP_HTML
    assert '$$("#form input, #form select, #run, .preset, .hist").forEach(el => el.disabled = on)' in APP_HTML
    assert "if (S.running) return;" in APP_HTML


# ---- executed in node (skipped when node is missing) ------------------------------------------------
def _run_node(js):
    out = subprocess.run([NODE, "-e", js], capture_output=True, text=True, timeout=30, check=True)
    return json.loads(out.stdout)


def _helpers(text):
    esc = re.search(r"^const esc = .*$", text, re.M).group(0)
    glyph = re.search(r"^const GLYPH = .*$", text, re.M).group(0)
    badge = re.search(r"^const badge = .*$", text, re.M).group(0)
    return "\n".join([esc, glyph, badge])


@pytest.mark.skipif(not NODE, reason="node not installed")
def test_malicious_hop_name_escaped_in_app_banner_and_list():
    script = _script(APP_HTML)
    src = "\n".join([
        _helpers(script), _slice(script, "const VERDICT = {", "function renderVerdict"),
        _slice(script, "function hopDetailHtml", "function renderEvents"),
        "const S = {nodes:{}, entry:{overlay:{path:[], hop_nodes:{}}}};",
        f"const evil = {json.dumps(EVIL)};",
        "const hop = {index:3, node:evil, domain:evil, component:evil, status:'BLOCK', summary:evil, policy:evil, nat:evil, details:[evil], location:{k:evil}};",
        "const t = {Outcome:'BLOCKED', Reason:evil, Hops:[hop]};",
        "const st = {hop, pidx:0};",
        "console.log(JSON.stringify({v: verdictHtml(t), row: eventRow(st, 0, t, {})}));",
    ])
    out = _run_node(src)
    for html in out.values():
        assert "<img" not in html and "onerror=alert(1)>" not in html.replace("&gt;", "")
        assert "&lt;img src=x onerror=alert(1)&gt;" in html


@pytest.mark.skipif(not NODE, reason="node not installed")
def test_malicious_hop_name_escaped_in_offline_banner(trace):
    import copy
    t = copy.deepcopy(trace)
    for h in t["Hops"]:
        h["node"] = EVIL
    page = render_html([t])
    assert EVIL not in page
    script = _script(_script_of_offline_source())
    src = "\n".join([
        _helpers(script), _slice(script, "const VERDICT = {", "function verdictHtml"),
        _slice(script, "function verdictHtml", "function apply"),
        f"const evil = {json.dumps(EVIL)};",
        "const t = {Outcome:'UNKNOWN-OUTCOME', Reason:evil, Hops:[{index:1,node:evil,domain:'d',component:'c',status:'UNKNOWN'}]};",
        "console.log(JSON.stringify({v: verdictHtml(t, evil)}));",
    ])
    html = _run_node(src)["v"]
    assert "<img" not in html and "&lt;img" in html
    assert "Unverified" in html and "pill vt INCOMPLETE" in html  # unknown outcome never styled as success


@pytest.mark.skipif(not NODE, reason="node not installed")
def test_inline_ip_and_port_validation_helpers():
    script = _script(APP_HTML)
    src = "\n".join([
        re.search(r"^const V4 = .*$", script, re.M).group(0), _slice(script, "function isIp", "const FIELDS"),
        "const cases = ['10.1.10.25','256.1.1.1','::1','2001:db8::1','abc','1.2.3','1:::2','10.1.10.025',''];",
        "console.log(JSON.stringify(cases.map(isIp)));",
    ])
    assert _run_node(src) == [True, False, True, True, False, False, False, False, False]


# ---- layout polish: lab toggle, scenario cards, sim bar, console, path map sizing ------------------
def test_about_lab_toggle_is_a_disclosure_collapsed_after_first_trace():
    assert ('<button type="button" id="labtoggle" aria-expanded="true" aria-controls="labinfo">' in APP_HTML)
    assert 'id="labinfo"' in APP_HTML and "#labinfo[hidden]{display:none}" in APP_HTML
    assert '$("#labtoggle").setAttribute("aria-expanded", String(open))' in APP_HTML
    load = _slice(_script(APP_HTML), "function loadEntry", "function renderSummary")
    assert "if (!S.labTouched) setLab(false);" in load   # collapses after the first trace unless the user chose a state


def test_scenario_cards_group_with_arrow_keys_and_clear_states():
    assert '<div id="presets" role="group" aria-label="Scenarios">' in APP_HTML
    nav = _slice(_script(APP_HTML), '$("#presets").addEventListener("keydown"', "async function refreshHistory")
    for key in ("ArrowDown", "ArrowUp", "ArrowLeft", "ArrowRight", "Home", "End"):
        assert key in nav, key
    assert "e.stopPropagation()" in nav   # arrows on a card never step the trace
    assert "p.tabIndex = p === on ? 0 : -1" in APP_HTML and 'aria-pressed' in APP_HTML
    assert '.preset.on::after{content:"Selected"' in APP_HTML and ".preset .x{display:inline-block" in APP_HTML


def test_sim_bar_stays_on_one_row_and_step_label_ellipsises():
    css = APP_HTML[:APP_HTML.index("</style>")]
    assert "#simbar{display:flex;flex-wrap:nowrap;" in css
    assert re.search(r"#stepinfo\{[^}]*text-overflow:ellipsis[^}]*white-space:nowrap", css)
    assert "grid-template-columns:minmax(0,1fr)" in _slice(css, "#sim{grid-area:sim", "}")   # never wider than its grid column
    assert '$("#stepinfo").textContent =' not in APP_HTML   # all writes go through setStepInfo (textContent + title)


def test_console_is_a_scroll_region_with_pinned_prompt():
    script = _script(APP_HTML)
    con = _slice(script, "function consoleHtml", "function bindConsole")
    assert con.index("`,\n    `<div class=\"term\"") < con.index('<div class="prompt">')   # term + prompt are the pinned part
    assert 'html = `<div class="devscroll">${html}${top}</div>${bottom}`' in script
    assert '<div class="term" id="term" role="log" aria-live="polite"' in con and 'tabindex="0"' in con
    assert re.search(r"\.term\{[^}]*flex:1 1 0;[^}]*overflow:auto", APP_HTML)


@pytest.mark.skipif(not NODE, reason="node not installed")
def test_hostile_names_escaped_in_console_and_step_label():
    script = _script(APP_HTML)
    src = "\n".join([
        _helpers(script), "const S = {boot:{mode:'demo'}};", f"const evil = {json.dumps(EVIL)};",
        "const el = {textContent:'', title:'', set innerHTML(v){ throw new Error('innerHTML used'); }};",
        "const $ = () => el;",
        re.search(r"^const CISCO_ALLOWED = [\s\S]*?\];$", script, re.M).group(0),
        re.search(r"^const PANOS_ALLOWED = [\s\S]*?\];$", script, re.M).group(0),
        _slice(script, "function consoleNotice", "function consoleError"),
        _slice(script, "function consoleHtml", "function bindConsole"),
        re.search(r"^function setStepInfo.*$", script, re.M).group(0),
        "setStepInfo(evil + ': 1 hop in this trace');",
        "const dev = {platform:'cisco_iosxe', quick:[evil]};",
        "const parts = consoleHtml(evil, dev, evil + '#', {lines: []});",
        "console.log(JSON.stringify({parts, text: el.textContent, title: el.title}));",
    ])
    out = _run_node(src)
    html = "".join(out["parts"])
    assert len(out["parts"]) == 2
    assert "<img" not in html and "&lt;img src=x onerror=alert(1)&gt;" in html
    assert out["text"].startswith(EVIL) and out["title"] == out["text"]   # text only, never parsed as HTML


@pytest.mark.skipif(not NODE, reason="node not installed")
def test_path_map_fit_rules():
    script = _script(APP_HTML)
    src = "\n".join([
        re.search(r"^const PM_MIN_SCALE = .*$", script, re.M).group(0),
        _slice(script, "function fitPm", "function curHopIndex"),
        "globalThis.getComputedStyle = () => ({paddingLeft:'0', paddingRight:'0', paddingTop:'0', paddingBottom:'0'});",
        "const run = (bw, bh) => { const svg = {style:{}, getAttribute: () => '0 0 2000 300'};",
        "  fitPm({clientWidth: bw, clientHeight: bh, querySelector: () => svg}); return [parseFloat(svg.style.width), parseFloat(svg.style.height)]; };",
        "console.log(JSON.stringify({wide: run(1800, 600), short: run(1800, 200), narrow: run(600, 200), tall: run(600, 900), hidden: run(0, 0)}));",
    ])
    out = _run_node(src)
    assert out["wide"] == [1800, 270]                 # fits the width
    assert out["short"] == [2000 * 200 / 300, 200]   # never taller than the panel
    assert out["narrow"] == [1500, 225]               # readable floor (0.75), scrolls
    assert out["tall"] == [2000, 300]                 # must scroll anyway: grow to actual size to use the height
    assert out["hidden"] == [None, None]              # a hidden panel is left alone
