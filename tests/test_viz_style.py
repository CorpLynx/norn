"""The exported path map and the offline viewer use the Norn design tokens (docs/design-guide.md)."""

import re

import pytest

from nettrace.demo.lab import PRESETS, install
from nettrace.engine import Tracer
from nettrace.models import Flow
from nettrace.viz import svg as vsvg
from nettrace.viz.html import _PAGE, render_html
from nettrace.viz.model import build_map

OLD_COLOURS = ("#1e9e5a", "#d93636", "#3b82c4", "#8e5bd6", "#fbfcfd", "#1d2633", "#1d5fbf")


@pytest.fixture(scope="module")
def trace():
    inv = install()
    preset = next(p for p in PRESETS if p["expect"] == "BLOCKED")
    f = dict(preset["flow"])
    start_at = f.pop("start_at", None)
    flow = Flow(src=f["src"], dst=f["dst"], protocol=f["protocol"], dst_port=f["port"])
    return Tracer(inv).trace(flow, start_at=start_at).to_dict()


def test_status_colours_match_the_canvas():
    assert vsvg.STATUS_COLOR == {"PASS": "#157a43", "BLOCK": "#c62828", "WARN": "#d9971c", "UNKNOWN": "#6d3fc0", "INFO": "#2f5bd8"}
    assert vsvg.RETURN_COLOR == "#0b7285"


def test_container_tints_match_the_web_ui_gstyle():
    from importlib import resources
    app = resources.files("nettrace.web").joinpath("static/app.html").read_text(encoding="utf-8")
    for kind, tints in vsvg.CONTAINER_STYLE.items():
        for colour in tints:
            assert f'"{colour}"' in app, (kind, colour)


def test_svg_uses_tokens_and_no_old_colours(trace):
    out = vsvg.render_svg(build_map(trace))
    for c in OLD_COLOURS:
        assert c not in out, c
    assert "#eef1ef" in out and "system-ui" in out and "ui-monospace" in out
    assert 'stroke-dasharray="8 5"' in out  # the AWS account box is dashed
    assert "letter-spacing" not in out and "SOURCE" not in out  # sentence case labels


def test_status_has_a_glyph_or_word_in_the_svg(trace):
    out = vsvg.render_svg(build_map(trace))
    assert "✕ Blocked" in out and "✕</text>" in out and "✓</text>" in out


def test_svg_escapes_device_text(trace):
    import copy
    t = copy.deepcopy(trace)
    t["Reason"] = "<img src=x onerror=alert(1)>"
    for h in t["Hops"]:
        h["node"] = "<b>x</b>"
    out = vsvg.render_svg(build_map(t))
    assert "<img" not in out and "<b>x" not in out and "&lt;img" in out


def test_viewer_tokens_dark_variant_and_focus_ring(trace):
    page = render_html([trace])
    for tok in ("--accent:#2f5bd8", "--paper:#eef1ef", "--line:#d3d9d5", "--line2:#b4bdb8", "--text:#161a19", "--muted:#56605c",
                "--b-pass:#157a43", "--b-block:#c62828", "--b-unk:#6d3fc0", "--r1:5px", "--r2:8px", "--r3:12px"):
        assert tok in page, tok
    assert "@media (prefers-color-scheme:dark)" in page and "--accent:#9db7ff" in page
    assert ":focus-visible{outline:2px solid var(--accent);outline-offset:2px}" in page
    # the map pane resets to the light tokens so it stays paper in dark mode
    assert re.search(r"#map\{--text:#161a19", _PAGE) and "#map{position:relative;overflow:hidden;background:var(--paper)" in page
    for c in OLD_COLOURS:
        assert c not in page, c
    assert 'PC = {PASS:"#157a43", WARN:"#d9971c", UNKNOWN:"#6d3fc0", BLOCK:"#c62828", INFO:"#2f5bd8"}' in page
    assert "BLOCKED HERE" in page
