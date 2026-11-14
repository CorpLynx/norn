"""Zoom-dependent topology detail: interface addresses attached to the topology the web UI draws."""

import copy
import re
from importlib import resources

from nettrace.demo import lab
from nettrace.web.topology import annotate_addresses, canonical_interface

APP_HTML = resources.files("nettrace.web").joinpath("static/app.html").read_text(encoding="utf-8")


def _link(topo, a, b):
    return next(link for link in topo["links"] if link["a"] == a and link["b"] == b)


def test_canonical_interface_matches_abbreviations():
    assert canonical_interface("Gi1") == canonical_interface("GigabitEthernet1") == "gigabitethernet1"
    assert canonical_interface("Tu200") == canonical_interface("Tunnel200")
    assert canonical_interface("e1/1") == canonical_interface("ethernet1/1")
    assert canonical_interface("tunnel.1") == "tunnel.1"
    assert canonical_interface("Gi1") != canonical_interface("Gi10")


def test_demo_links_and_devices_get_addresses_without_touching_the_original():
    inv = lab.install()
    before = copy.deepcopy(lab.TOPOLOGY)
    topo = annotate_addresses(lab.TOPOLOGY, inv)
    assert lab.TOPOLOGY == before  # a copy is annotated, the lab's topology is not changed
    gi1 = _link(topo, "core-rtr1", "fw-dc1")
    assert (gi1["a_ip"], gi1["b_ip"]) == ("10.0.0.1", "10.0.0.2")
    assert _link(topo, "prisma-access", "core-rtr1")["b_ip"] == "169.254.200.2"
    assert _link(topo, "insp-rtr", "fw-aws-1")["b_ip"] == "10.100.1.10 · 10.100.2.10"  # one drawn link, two interfaces
    core = next(n for n in topo["nodes"] if n["id"] == "core-rtr1")
    assert {"if": "Loopback0", "ip": "10.255.0.1"} in core["addrs"]
    assert "addrs" not in next(n for n in topo["nodes"] if n["id"] == "users-lan")  # not a device


def test_ambiguous_and_unknown_addresses_are_not_attributed():
    inv = lab.install()
    saved = inv.discovered
    try:
        inv.discovered = {"10.0.0.1": {"device": "core-rtr1", "interface": "GigabitEthernet1"},
                          "10.9.9.9": {"device": "not-in-inventory", "interface": "Gi9"}}
        topo = annotate_addresses(lab.TOPOLOGY, inv)
        assert _link(topo, "core-rtr1", "fw-dc1").get("b_ip") is None  # fw-dc1 has no cached address: nothing shown
        assert all(r["ip"] != "10.9.9.9" for n in topo["nodes"] for r in n.get("addrs", []))
    finally:
        inv.discovered = saved


def test_ui_escapes_addresses_and_hides_detail_by_zoom():
    for needle in ("${esc(ip)}", "${esc(name)}", "${esc(r.if || \"(static)\")}", "${esc(r.ip)}"):
        assert needle in APP_HTML, needle
    assert "#stage[data-lod=near] .lod-near{opacity:1}" in APP_HTML
    assert re.search(r"const LOD_MID = [0-9.]+, LOD_NEAR = [0-9.]+;", APP_HTML)
    assert 'class="ifip lod-near"' in APP_HTML and 'class="iflbl lod-mid"' in APP_HTML and 'class="sub lod-mid"' in APP_HTML
