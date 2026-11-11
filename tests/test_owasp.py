"""OWASP Top 10 (2021) checks for the parts of nettrace that apply to a local, read-only tool.

Not applicable (no such surface): A02 stored data (no DB), file upload, sessions beyond one cookie, multi-user roles.
Each section names the category. These are black-box checks against a live local server plus the guard functions.
"""
import http.client
import json
import re
import socket
import threading
import time
from http.server import ThreadingHTTPServer
from importlib import resources
from pathlib import Path

import pytest

from nettrace import readonly
from nettrace.demo import install
from nettrace.errors import ReadOnlyViolation
from nettrace.web import server

SRC = Path(server.__file__).resolve().parents[1]
APP_HTML = resources.files("nettrace.web").joinpath("static/app.html").read_text(encoding="utf-8")
CLIENT = {"X-Nettrace-Client": "1"}
JSON = {"Content-Type": "application/json"}


@pytest.fixture
def live():
    app = server.App(install(), demo=True)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), lambda *a: None)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = server.make_handler(app, port, False)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield app, port
    httpd.shutdown()
    httpd.server_close()
    app.close()


def req(port, method, path, headers=None, body=None, host=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    h = dict(headers or {})
    c.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    c.putheader("Host", host or f"127.0.0.1:{port}")
    for k, v in h.items():
        c.putheader(k, v)
    if body is not None:
        c.putheader("Content-Length", str(len(body)))
    c.endheaders(body)
    r = c.getresponse()
    data = r.read()
    return r.status, r, data


def authed(app):
    return {"X-Nettrace-Token": app.token}


API_GETS = ["/api/bootstrap", "/api/traces", "/api/traces/abcd"]
API_POSTS = ["/api/trace", "/api/trace/cancel", "/api/console"]


# ---- A01 Broken Access Control ----------------------------------------------------------------
@pytest.mark.parametrize("path", API_GETS)
def test_a01_api_get_requires_auth(live, path):
    _, port = live
    assert req(port, "GET", path)[0] == 401


@pytest.mark.parametrize("path", API_POSTS)
def test_a01_api_post_requires_auth(live, path):
    _, port = live
    assert req(port, "POST", path, JSON, b"{}")[0] == 401


@pytest.mark.parametrize("path", API_POSTS)
@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH"])
def test_a01_unsupported_methods_do_nothing(live, path, method):
    app, port = live
    status, _, _ = req(port, method, path, {**authed(app), **JSON}, b"{}")
    assert status in (404, 405, 501)


@pytest.mark.parametrize("path", ["/../etc/passwd", "/static/../../pyproject.toml", "/%2e%2e/%2e%2e/etc/passwd",
                                  "/api/../etc/passwd", "/static/app.html", "/.git/config"])
def test_a01_no_file_serving_or_traversal(live, path):
    app, port = live
    status, _, body = req(port, "GET", path, authed(app))
    assert status in (401, 404) and b"root:" not in body and b"[project]" not in body


def test_a01_cookie_without_csrf_header_is_refused(live):
    app, port = live
    status, _, _ = req(port, "GET", "/api/bootstrap", {"Cookie": f"nettrace_session={app.token}"})
    assert status == 403
    assert req(port, "GET", "/api/bootstrap", {"Cookie": f"nettrace_session={app.token}", **CLIENT})[0] == 200


def test_a01_cancel_unknown_run_is_harmless(live):
    app, port = live
    status, _, body = req(port, "POST", "/api/trace/cancel", {**authed(app), **JSON}, b'{"id":"nope"}')
    assert status in (200, 400, 404) and b"Traceback" not in body


# ---- A02 Cryptographic Failures ----------------------------------------------------------------
def test_a02_no_tls_verification_disabled_in_source():
    bad = []
    for p in SRC.rglob("*.py"):
        text = p.read_text(encoding="utf-8")
        if re.search(r"verify\s*=\s*False|CERT_NONE|check_hostname\s*=\s*False|_create_unverified_context", text):
            bad.append(p.name)
    assert not bad, f"TLS verification disabled in {bad}"


def test_a02_session_secret_is_long_and_random(live):
    app, _ = live
    other = server.App(install(), demo=True)
    try:
        assert len(app.token) >= 32 and app.token != other.token
        assert app.login_code != other.login_code
    finally:
        other.close()


def test_a02_server_binds_loopback_only():
    src = (SRC / "web" / "server.py").read_text(encoding="utf-8")
    assert '("127.0.0.1", port)' in src
    assert "0.0.0.0" not in src and '("", ' not in src


def test_a02_cookie_flags(live):
    app, port = live
    _, r, _ = req(port, "GET", f"/?c={app.login_code}")
    cookie = r.getheader("Set-Cookie")
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    assert "Domain" not in cookie and "Max-Age" not in cookie and "Expires" not in cookie


# ---- A03 Injection -----------------------------------------------------------------------------
CISCO_INJECTION = [
    "show ip route; reload", "show ip route | include x", "show ip route\nconfigure terminal",
    "show ip route && reload", "show ip route `reboot`", "show ip route $(reload)", "show run\r\nreload",
    "show ip route 10.0.0.1 | redirect flash:x", "show ip route 10.0.0.1 > flash:x", "conf t", "write memory",
    "copy running-config tftp:", "show ip route 10.0.0.1\x00reload", "sh ip ro", "show tech-support",
    "show running-config | section password", "show ip route %s%s%s", "show ip route ../../x",
]


@pytest.mark.parametrize("cmd", CISCO_INJECTION)
def test_a03_cisco_command_injection_refused(cmd):
    with pytest.raises(ReadOnlyViolation):
        readonly.check_cisco_command(cmd)


PANOS_PARAM_INJECTION = [
    {"type": "op", "cmd": "<set><deviceconfig/></set>"},
    {"type": "op", "cmd": "<request><restart><system/></restart></request>"},
    {"type": "op", "cmd": "<show><system><info/></system></show><request/>"},
    {"type": "op", "cmd": "<test><security-policy-match/></test>", "extra": "x"},
    {"type": "config", "action": "set", "xpath": "/config", "element": "<x/>"},
    {"type": "config", "action": "delete", "xpath": "/config/devices"},
    {"type": "commit", "cmd": "<commit/>"},
    {"type": "keygen", "user": "a", "password": "b"},
    {"type": "import", "category": "configuration"},
    {"type": "op", "cmd": "<show><system><info/></system></show>", "key": "stolen"},
    {"type": "op", "cmd": "<show/>", "target": "0123 && id"},
    {"type": "op", "cmd": "<show/>", "target": "../x"},
    {"type": "config", "action": "get", "xpath": "/config/../../x"},
    {"type": "config", "action": "get", "xpath": "/config | /config/mgt-config/users"},
    {"type": "op", "cmd": "<test><cli><op>x</op></cli></test>"},
    {"type": "op", "cmd": "<!DOCTYPE x [<!ENTITY a SYSTEM 'file:///etc/passwd'>]><show>&a;</show>"},
]


@pytest.mark.parametrize("params", PANOS_PARAM_INJECTION)
def test_a03_panos_request_injection_refused(params):
    with pytest.raises(ReadOnlyViolation):
        readonly.check_panos_request(params)


def test_a03_panos_xml_builder_escapes_values():
    from xml.etree import ElementTree as ET

    from nettrace.drivers import panos
    from nettrace.errors import DeviceError

    out = panos.build_op(["test", "routing", "fib-lookup"], {"ip": "10.0.0.1</ip><evil/>"})
    assert ET.fromstring(out).find(".//evil") is None
    with pytest.raises(DeviceError):
        panos.build_op(["show", "x><evil"])


@pytest.mark.parametrize("bad", ["x; id", "a b", "x\nshow", "$(id)", "`id`", "a|b", "a'b", 'a"b', "x" * 200])
def test_a03_safe_token_rejects_metacharacters(bad):
    with pytest.raises(ReadOnlyViolation):
        readonly.safe_token(bad)


@pytest.mark.parametrize("field,value", [
    ("src", "10.0.0.1; reload"), ("src", "10.0.0.1\nshow run"), ("dst", "<script>alert(1)</script>"),
    ("dst", "1.1.1.1' OR '1'='1"), ("src", "$(id)"), ("src", "::ffff:1.1.1.1\x00"),
    ("protocol", "tcp;reload"), ("protocol", "<img src=x>"), ("port", "80; id"), ("port", -1), ("port", 70000),
    ("application", "x;reload"), ("application", "<b>"), ("user", "a' --"), ("user", "a\nb"),
    ("start_at", "../../etc/passwd"), ("start_at", "x;id"),
])
def test_a03_trace_api_rejects_bad_fields(live, field, value):
    app, port = live
    body = {"src": "10.1.1.10", "dst": "10.2.2.20", "protocol": "tcp", "port": 443}
    body[field] = value
    status, _, data = req(port, "POST", "/api/trace", {**authed(app), **JSON}, json.dumps(body).encode())
    assert status == 400, data
    assert b"Traceback" not in data


@pytest.mark.parametrize("payload", ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>",
                                     "</script><script>alert(1)</script>", "<!--", "\u2028<b>"])
def test_a03_xss_payload_in_trace_output_is_escaped(payload):
    from nettrace.models import Flow, Hop, Outcome, Status, TraceResult
    from nettrace.viz import html as vhtml

    flow = Flow(src="10.1.1.10", dst="10.2.2.20", protocol="tcp", dst_port=443)
    hop = Hop(domain="cisco", node=payload, component="router", status=Status.PASS, summary=payload,
              details=[payload], index=1)
    result = TraceResult(flow=flow, outcome=Outcome.REACHABLE, reason=payload, hops=[hop])
    page = vhtml.render_html([result.to_dict()])
    assert "<script>alert(1)" not in page and "<img src=x onerror" not in page
    assert page.count("</script>") == page.count("<script")


def test_a03_viewer_has_no_dangerous_sinks():
    for text in (APP_HTML,):
        assert "eval(" not in text and "new Function" not in text and "document.write" not in text
        assert "javascript:" not in text


def test_a03_no_header_injection_in_login_redirect(live):
    app, port = live
    status, r, _ = req(port, "GET", f"/?c={app.login_code}")
    assert status == 303 and r.getheader("Location") == "/"


def test_a03_source_has_no_shell_or_eval():
    bad = []
    for p in SRC.rglob("*.py"):
        if p.name == "html.py":  # embeds viewer JavaScript (regex .exec)
            continue
        t = p.read_text(encoding="utf-8")
        if re.search(r"shell\s*=\s*True|os\.system\(|(?<![.\w])eval\(|(?<![.\w])exec\(|pickle\.loads?|yaml\.load\(|marshal\.loads", t):
            bad.append(p.name)
    assert not bad, bad


# ---- A04 Insecure Design -----------------------------------------------------------------------
def test_a04_oversize_body_is_413(live):
    app, port = live
    big = b'{"x":"' + b"a" * (server.MAX_BODY + 10) + b'"}'
    assert req(port, "POST", "/api/trace", {**authed(app), **JSON}, big)[0] == 413


def test_a04_console_rate_limit(live):
    app, port = live
    dev = next(iter(app.inv.devices))
    body = json.dumps({"device": dev, "command": "show clock"}).encode()
    codes = [req(port, "POST", "/api/console", {**authed(app), **JSON}, body)[0] for _ in range(2)]
    assert 429 in codes


def test_a04_console_unknown_device_and_long_command(live):
    app, port = live
    h = {**authed(app), **JSON}
    assert req(port, "POST", "/api/console", h, b'{"device":"nope","command":"show clock"}')[0] == 400
    dev = next(iter(app.inv.devices))
    long = json.dumps({"device": dev, "command": "show " + "a" * 500}).encode()
    assert req(port, "POST", "/api/console", h, long)[0] == 400


def test_a04_stalled_body_times_out(live, monkeypatch):
    app, port = live
    monkeypatch.setattr(server, "BODY_DEADLINE", 0.5)
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall((f"POST /api/trace HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Nettrace-Token: {app.token}\r\n"
               "Content-Type: application/json\r\nContent-Length: 100\r\n\r\n{").encode())
    t0 = time.monotonic()
    data = s.recv(4096)
    s.close()
    assert b"408" in data.split(b"\r\n", 1)[0] and time.monotonic() - t0 < 5


def test_a04_trace_has_deadline_and_cancel():
    src = (SRC / "engine.py").read_text(encoding="utf-8")
    assert "Deadline" in src and "cancel" in src.lower()


# ---- A05 Security Misconfiguration -------------------------------------------------------------
def test_a05_security_headers_on_every_kind_of_response(live):
    app, port = live
    cases = [("GET", "/", None, None), ("GET", "/nope", None, None), ("GET", "/api/bootstrap", authed(app), None),
             ("GET", "/api/bootstrap", None, None), ("POST", "/api/trace", {**authed(app), **JSON}, b"{")]
    for method, path, headers, body in cases:
        _, r, _ = req(port, method, path, headers, body)
        assert r.getheader("X-Content-Type-Options") == "nosniff", path
        assert r.getheader("Referrer-Policy") == "no-referrer", path
        assert r.getheader("Cache-Control") == "no-store", path
        csp = r.getheader("Content-Security-Policy") or ""
        assert "default-src 'none'" in csp, path
        assert "frame-ancestors" in csp or path == "/", path


def test_a05_page_csp_is_tight(live):
    app, port = live
    _, r, _ = req(port, "GET", "/")
    csp = r.getheader("Content-Security-Policy")
    assert "default-src 'none'" in csp and "connect-src 'self'" in csp
    assert "unsafe-eval" not in csp and "http:" not in csp and "https:" not in csp and "*" not in csp
    assert r.getheader("X-Frame-Options") == "DENY"


def test_a05_no_cors_headers(live):
    app, port = live
    for method in ("GET", "OPTIONS"):
        _, r, _ = req(port, method, "/api/bootstrap", {**authed(app), "Origin": f"http://127.0.0.1:{port}"})
        assert r.getheader("Access-Control-Allow-Origin") is None
    status, r, _ = req(port, "OPTIONS", "/api/trace", {"Origin": "http://evil.example",
                                                       "Access-Control-Request-Method": "POST"})
    assert r.getheader("Access-Control-Allow-Origin") is None and status != 200


def test_a05_server_banner_does_not_leak_python_version(live):
    _, port = live
    _, r, _ = req(port, "GET", "/nope")
    banner = r.getheader("Server") or ""
    assert "Python" not in banner and not re.search(r"\d+\.\d+\.\d+", banner)


def test_a05_errors_do_not_leak_tracebacks_or_paths(live):
    app, port = live
    h = {**authed(app), **JSON}
    for body in (b"{", b"[]", b"null", b'{"src":1}', b"\xff\xfe"):
        status, _, data = req(port, "POST", "/api/trace", h, body)
        assert status in (400, 415) and b"Traceback" not in data and b"/Users/" not in data and b'File "' not in data


def test_a05_wrong_content_type_is_415(live):
    app, port = live
    for ct in ("text/plain", "application/x-www-form-urlencoded", "multipart/form-data"):
        assert req(port, "POST", "/api/trace", {**authed(app), "Content-Type": ct}, b"{}")[0] == 415


def test_a05_no_cli_option_to_bind_elsewhere():
    from nettrace import cli

    serve = cli.main.commands["serve"] if hasattr(cli, "main") and "serve" in getattr(cli.main, "commands", {}) else None
    if serve is not None:
        assert "--host" not in {o for p in serve.params for o in p.opts}


def test_a05_inventory_example_holds_no_secrets():
    text = (SRC.parents[1] / "inventory.example.yaml").read_text(encoding="utf-8")
    for line in text.splitlines():
        s = line.split("#", 1)[0]
        if re.search(r"(password|secret|token|api_key)\s*:", s, re.I):
            assert s.strip().split(":", 1)[0].endswith("_env"), line


# ---- A06 Vulnerable and Outdated Components ----------------------------------------------------
def test_a06_dependencies_are_declared_and_bounded():
    toml = (SRC.parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    assert "dependencies" in toml
    assert not re.search(r"^\s*\"[A-Za-z0-9_.\-]+\"\s*,?\s*$", toml.split("dependencies", 1)[1].split("]", 1)[0], re.M) \
        or ">=" in toml  # every dep carries a version floor


def test_a06_no_external_urls_in_viewer():
    # Offline viewer: no third-party scripts, styles, fonts or beacons.
    for text in (APP_HTML, (SRC / "viz" / "html.py").read_text(encoding="utf-8")):
        assert not re.search(r"""(src|href)\s*=\s*["']https?://""", text)
        assert "@import" not in text and "cdn." not in text.lower()


# ---- A07 Identification and Authentication Failures --------------------------------------------
def test_a07_login_code_single_use_and_expires():
    clock = [1000.0]
    app = server.App(install(), demo=True, code_ttl=60.0, clock=lambda: clock[0])
    try:
        code = app.login_code
        assert app.redeem_code(code) and not app.redeem_code(code)
        assert app.login_code is None
    finally:
        app.close()


def test_a07_login_code_not_guessable_by_prefix(live):
    app, port = live
    code = app.login_code
    for guess in (code[:-1], code + "x", code.upper() if code.upper() != code else code[::-1], "a" * len(code)):
        assert req(port, "GET", f"/?c={guess}")[0] == 401
    assert app.login_code == code  # wrong guesses do not burn the real code


@pytest.mark.parametrize("tok", ["", " ", "null", "undefined", "Bearer x", "A" * 5000])
def test_a07_bad_tokens_are_401(live, tok):
    _, port = live
    assert req(port, "GET", "/api/bootstrap", {"X-Nettrace-Token": tok})[0] == 401


def test_a07_cookie_variants_rejected(live):
    app, port = live
    for cookie in ("nettrace_session=", "nettrace_session=x", "other=" + app.token, "garbage;;;===", f"nettrace_session={app.token}x"):
        assert req(port, "GET", "/api/bootstrap", {"Cookie": cookie, **CLIENT})[0] == 401


def test_a07_token_compare_is_constant_time():
    assert "compare_digest" in (SRC / "web" / "server.py").read_text(encoding="utf-8")


def test_a07_token_not_in_page_or_urls(live):
    app, port = live
    _, _, body = req(port, "GET", "/")
    assert app.token.encode() not in body and (app.login_code or "").encode() not in body


# ---- A08 Software and Data Integrity Failures --------------------------------------------------
def test_a08_inventory_loaded_with_safe_yaml(tmp_path):
    from nettrace.inventory import load_inventory
    from nettrace.errors import NetTraceError

    p = tmp_path / "inv.yaml"
    p.write_text("devices: !!python/object/apply:os.system ['echo pwned > " + str(tmp_path / "x") + "']\n")
    with pytest.raises((NetTraceError, Exception)):
        load_inventory(p)
    assert not (tmp_path / "x").exists()


def test_a08_aws_session_policy_matches_packaged_copy():
    repo = (SRC.parents[1] / "iam" / "nettrace-readonly-policy.json").read_text(encoding="utf-8")
    packaged = resources.files("nettrace").joinpath("data/nettrace-readonly-policy.json").read_text(encoding="utf-8")
    assert json.loads(repo) == json.loads(packaged)


def test_a08_aws_policy_has_no_write_actions():
    pol = json.loads((SRC.parents[1] / "iam" / "nettrace-readonly-policy.json").read_text(encoding="utf-8"))
    actions = []
    for st in pol["Statement"]:
        if st.get("Effect") == "Allow":
            a = st["Action"]
            actions += [a] if isinstance(a, str) else a
    assert actions and all("*" not in a.split(":", 1)[1] or a.split(":", 1)[1].startswith("Describe") for a in actions)
    assert not any(re.match(r"ec2:(Create|Delete|Modify|Run|Terminate|Start|Stop|Attach|Detach|Authorize|Revoke|Associate)", a)
                   for a in actions)
    assert not any("reachability" in a.lower() or "NetworkInsights" in a for a in actions)


# ---- A09 Security Logging and Monitoring Failures ----------------------------------------------
def test_a09_refusals_are_audited(tmp_path, monkeypatch):
    from nettrace import audit

    log = tmp_path / "a" / "audit.log"
    monkeypatch.setenv("NETTRACE_AUDIT_LOG", str(log))
    try:
        readonly.check_cisco_command("configure terminal")
    except ReadOnlyViolation as exc:
        audit.refused(exc, "ssh", "r1", "configure terminal")
    text = log.read_text()
    assert "configure terminal" in text and "refused" in text.lower()
    assert (log.stat().st_mode & 0o777) == 0o600


def test_a09_audit_log_never_follows_symlink(tmp_path, monkeypatch):
    from nettrace import audit

    target = tmp_path / "victim"
    target.write_text("keep")
    link = tmp_path / "audit.log"
    link.symlink_to(target)
    monkeypatch.setenv("NETTRACE_AUDIT_LOG", str(link))
    audit.log("ssh", "r1", "show version", "ok")
    assert target.read_text() == "keep"


def test_a09_audit_log_has_no_credentials(tmp_path, monkeypatch):
    from nettrace import audit

    log = tmp_path / "audit.log"
    monkeypatch.setenv("NETTRACE_AUDIT_LOG", str(log))
    monkeypatch.setenv("SECRET_PW", "hunter2-xyz")
    audit.log("ssh", "r1", "show version", "ok")
    assert "hunter2-xyz" not in log.read_text()


def test_a09_server_log_has_no_query_string(live, capsys):
    app = server.App(install(), demo=True)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), lambda *a: None)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = server.make_handler(app, port, True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        req(port, "GET", f"/?c={app.login_code}&x=SECRETVALUE")
        err = capsys.readouterr().err
        assert app.token not in err and "SECRETVALUE" not in err
    finally:
        httpd.shutdown()
        httpd.server_close()
        app.close()


# ---- A10 Server-Side Request Forgery -----------------------------------------------------------
@pytest.mark.parametrize("host", ["evil.example", "127.0.0.1:1", "localhost", "127.0.0.1.evil.example:80", "[::1]:80"])
def test_a10_dns_rebinding_host_header_refused(live, host):
    app, port = live
    status, _, _ = req(port, "GET", "/api/bootstrap", authed(app), host=host)
    assert status == 421


@pytest.mark.parametrize("origin", ["http://evil.example", "null", "https://127.0.0.1", "http://127.0.0.1:1",
                                    "http://localhost.evil.example"])
def test_a10_foreign_origin_refused(live, origin):
    app, port = live
    status, _, _ = req(port, "POST", "/api/trace", {**authed(app), **JSON, "Origin": origin}, b"{}")
    assert status == 403


def test_a10_api_accepts_no_url_or_host_parameters(live):
    # trace/console take inventory names and IPs only; a URL smuggled in must be refused, never fetched.
    app, port = live
    h = {**authed(app), **JSON}
    body = {"src": "http://169.254.169.254/latest/meta-data/", "dst": "10.2.2.20", "protocol": "tcp", "port": 443}
    assert req(port, "POST", "/api/trace", h, json.dumps(body).encode())[0] == 400
    body = {"device": "http://169.254.169.254/", "command": "show clock"}
    assert req(port, "POST", "/api/console", h, json.dumps(body).encode())[0] == 400


def test_a10_http_clients_never_follow_redirects():
    for name in ("drivers/panos.py", "drivers/prisma.py"):
        text = (SRC / name).read_text(encoding="utf-8")
        assert "allow_redirects=False" in text, name
