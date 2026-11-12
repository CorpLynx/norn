"""Discovery M0/M1 (docs/discovery-spec.md, D18): model, policy, store, join and merge. No I/O to devices."""

from __future__ import annotations

import json
import os
import stat
import warnings

import pytest

from nettrace.discovery.join import join
from nettrace.discovery.links import link_to_dict, make_id
from nettrace.discovery.merge import merge
from nettrace.discovery.model import (AwsVpn, Candidate, PrismaTunnel, Provenance, TunnelEnd, clean_text, join_ip,
                                      link_id, normalise_interface)
from nettrace.discovery.policy import CrawlLimits, TopologyPolicy, parse_topology
from nettrace.discovery.store import KEEP_RUNS, MAX_BYTES, RunRecord, StoreState, TopologyStore
from nettrace.errors import InventoryError
from nettrace.inventory import Link, LinkEnd, load_inventory

INV = """
devices:
  - {name: rtr1, platform: cisco_iosxe, host: 10.0.0.1, addresses: [203.0.113.1]}
  - {name: rtr2, platform: cisco_iosxe, host: 10.0.0.2, addresses: [198.51.100.2]}
  - {name: fw1, platform: panos, host: 10.0.0.3, addresses: [192.0.2.10]}
links:
  - name: fw1-internet
    a: {device: fw1, interface: ethernet1/4}
    b: {external: "Internet (ISP-A)"}
"""

T0 = 1_800_000_000.0


@pytest.fixture(autouse=True)
def _cache(tmp_path, monkeypatch):
    monkeypatch.setenv("NETTRACE_CACHE_DIR", str(tmp_path / "cache"))


def _inv(tmp_path, extra: str = ""):
    p = tmp_path / "inv.yaml"
    p.write_text(INV + extra)
    return load_inventory(p)


def prov(subject: str, source: str = "test", t: float = T0) -> Provenance:
    return Provenance(source=source, subject=subject, observed_at=t, run_id="r1", digest="d" * 64)


def tun(device, interface, local, peer, oper="up", kind="ipsec", t=T0):
    return TunnelEnd(device, interface, local, peer, kind, oper, prov(device, f"{device}:tunnels", t))


def vpn(outside, cgw, attach="tgw-attach-0abc", vgw=None, tgw="tgw-0abc", vpn_id="vpn-0abc", oper="up", t=T0):
    return AwsVpn("network", "us-east-1", vpn_id, outside, cgw, tgw, vgw, attach, oper,
                  prov("aws:network/us-east-1", "aws:ec2.DescribeVpnConnections", t))


def sc(name, peer):
    return PrismaTunnel(name, "service_connection", peer, prov("scm", "scm:service-connections"))


def run(ok, failed=None, rid="r1"):
    return RunRecord(id=rid, started=T0, ended=T0 + 1, subjects_ok=list(ok), subjects_failed=dict(failed or {}))


# ---- model -------------------------------------------------------------------------

@pytest.mark.parametrize("raw,platform,want", [
    ("Tu100", "cisco_iosxe", "Tunnel100"),
    ("tunnel100", "cisco_iosxe", "Tunnel100"),
    ("Gi 0/0/1", "cisco_iosxe", "GigabitEthernet0/0/1"),
    ("Te1/0/1.200", "cisco_iosxe", "TenGigabitEthernet1/0/1.200"),
    ("Po10", "cisco_iosxe", "Port-channel10"),
    ("T1", "cisco_iosxe", "T1"),            # ambiguous prefix: kept
    ("Weird9", "cisco_iosxe", "Weird9"),    # unknown: kept
    ("Tunnel.1", "panos", "tunnel.1"),
    ("ethernet1/4", None, "ethernet1/4"),
])
def test_normalise_interface(raw, platform, want):
    assert normalise_interface(raw, platform) == want


def test_clean_text_strips_controls_and_caps():
    assert clean_text("a\x1b[31mb\u2028c\u200ed\n") == "a[31mbcd"
    assert len(clean_text("x" * 500)) == 128


@pytest.mark.parametrize("raw,want", [
    ("203.0.113.1", "203.0.113.1"), (" 203.0.113.1 ", "203.0.113.1"), ("169.254.10.1", None), ("127.0.0.1", None),
    ("224.0.0.5", None), ("0.0.0.0", None), ("2001:db8::1", None), ("nope", None), (None, None), (5, None),
])
def test_join_ip(raw, want):
    assert join_ip(raw) == want


def test_link_id_is_order_independent_and_short():
    a, b = {"device": "rtr1", "interface": "Tunnel1"}, {"aws": {"tgw_attachment": "x"}}
    assert link_id("aws-vpn", a, b) == link_id("aws-vpn", b, a)
    assert len(link_id("aws-vpn", a, b)) == 16
    assert link_id("ipsec", a, b) != link_id("aws-vpn", a, b)


# ---- policy and inventory ----------------------------------------------------------------

def test_no_topology_section_means_none(tmp_path):
    assert _inv(tmp_path).topology is None


def test_topology_defaults_and_overrides(tmp_path):
    inv = _inv(tmp_path, "topology:\n  ttl_fresh: 600\n  crawl: {device_sessions: 2, device_budget: {commands: 10}}\n")
    assert inv.topology == TopologyPolicy(ttl_fresh=600.0, crawl=CrawlLimits(device_sessions=2, device_commands=10))
    assert parse_topology({}) == TopologyPolicy()


@pytest.mark.parametrize("raw", [
    {"use_learned": "yes"}, {"ttl_fresh": 10}, {"ttl_fresh": 7200, "ttl_max": 3600}, {"bogus": 1},
    {"crawl": {"device_sessions": 0}}, {"crawl": {"device_sessions": 2.5}}, {"crawl": {"timeout": True}},
    {"crawl": {"device_budget": {"seconds": 1}}}, {"crawl": {"extra": 1}}, {"crawl": []}, [],
])
def test_topology_rejects_bad_values(raw):
    with pytest.raises(InventoryError):
        parse_topology(raw)


def test_yaml_links_keep_declared_defaults(tmp_path):
    lk = _inv(tmp_path).links[0]
    assert (lk.origin, lk.kind, lk.oper, lk.id, lk.provenance, lk.conflicts) == ("declared", "unknown", "unknown", "", (), ())


def test_link_from_device_normalises_cisco_names(tmp_path):
    inv = _inv(tmp_path, """
  - name: rtr1-tun
    a: {device: rtr1, interface: Tunnel100}
    b: {device: rtr2, interface: Tu100}
""")
    assert inv.link_from_device("rtr1", "Tu100", None)[1].device == "rtr2"
    assert inv.link_from_device("rtr2", "tunnel100", None)[1].device == "rtr1"
    assert inv.link_from_device("fw1", "ETHERNET1/4", None)[1].external == "Internet (ISP-A)"
    assert inv.link_from_device("rtr1", "Tu101", None) is None


# ---- store ---------------------------------------------------------------------------

def _sample_state(inv) -> StoreState:
    a, b = LinkEnd(device="rtr1", interface="Tunnel1"), LinkEnd(aws_tgw_attachment="tgw-attach-0abc",
                                                                 aws_account="network", aws_region="us-east-1")
    lk = Link(name="rtr1 Tunnel1 <-> tgw-attach-0abc", a=a, b=b, origin="learned", kind="aws-vpn", oper="up",
              id=make_id("aws-vpn", a, b, inv), provenance=(prov("rtr1"),), first_seen=T0, last_confirmed=T0)
    return StoreState(runs=[run(["rtr1"])], links=[lk], candidates=[Candidate("rtr1", "198.51.100.9", "peer")])


def test_store_round_trip_and_permissions(tmp_path):
    inv = _inv(tmp_path)
    store = TopologyStore(inv)
    state = _sample_state(inv)
    path = store.save(state)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        back = store.load()
    assert [link_to_dict(x) for x in back.links] == [link_to_dict(x) for x in state.links]
    assert back.candidates == state.candidates and back.runs == state.runs
    assert store.clear() and not path.exists() and not store.clear()


def test_store_missing_file_is_silent_and_empty(tmp_path):
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert TopologyStore(_inv(tmp_path)).load() == StoreState()


def _write_raw(store, text):
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text(text)


def _ignored(store) -> bool:
    with pytest.warns(UserWarning, match="ignoring it"):
        return store.load() == StoreState()


def _good(inv) -> dict:
    return _sample_state(inv).to_dict()


@pytest.mark.parametrize("mutate", [
    lambda d: "{not json",
    lambda d: json.dumps({**d, "schema": 2}),
    lambda d: json.dumps({**d, "schema": True}),
    lambda d: json.dumps({**d, "extra": 1}),
    lambda d: json.dumps({**d, "links": [{**d["links"][0], "a": {"device": "ghost"}}]}),
    lambda d: json.dumps({**d, "links": [{**d["links"][0], "origin": "trusted"}]}),
    lambda d: json.dumps({**d, "links": [{**d["links"][0], "a": {"device": "rtr1", "interface": "Tu1; reload"}}]}),
    lambda d: json.dumps({**d, "links": [{**d["links"][0], "name": "x\x1b[2J"}]}),
    lambda d: json.dumps({**d, "links": [{**d["links"][0], "last_confirmed": -1}]}),
    lambda d: json.dumps({**d, "links": d["links"] * 2}),  # duplicate id
    lambda d: json.dumps({**d, "links": d["links"] * 5001}),
    lambda d: json.dumps({**d, "candidates": [{"seen_by": "rtr1", "address": "10.0.0.300", "note": ""}]}),
    lambda d: json.dumps({**d, "candidates": [{"seen_by": "ghost", "address": "198.51.100.9", "note": ""}]}),
    lambda d: json.dumps([d]),
])
def test_store_rejects_bad_files_whole(tmp_path, mutate):
    inv = _inv(tmp_path)
    store = TopologyStore(inv)
    _write_raw(store, mutate(_good(inv)))
    assert _ignored(store)


def test_store_rejects_oversized_file(tmp_path):
    inv = _inv(tmp_path)
    store = TopologyStore(inv)
    _write_raw(store, " " * (MAX_BYTES + 1))
    assert _ignored(store)


def test_store_never_follows_a_symlinked_file(tmp_path):
    inv = _inv(tmp_path)
    store = TopologyStore(inv)
    real = tmp_path / "elsewhere.json"
    real.write_text(json.dumps(_good(inv)))
    store.path.parent.mkdir(parents=True)
    store.path.symlink_to(real)
    assert _ignored(store)
    store.save(StoreState())  # replaces the link itself, the target is untouched
    assert not store.path.is_symlink() and json.loads(real.read_text())["links"]


def test_store_refuses_a_symlinked_directory(tmp_path, monkeypatch):
    inv = _inv(tmp_path)
    (tmp_path / "real").mkdir()
    (tmp_path / "linked").symlink_to(tmp_path / "real")
    store = TopologyStore(inv, tmp_path / "linked" / "topology.json")
    assert _ignored(store)
    with pytest.raises(OSError, match="symlink"):
        store.save(StoreState())


def test_store_keeps_last_runs_only(tmp_path):
    inv = _inv(tmp_path)
    state = StoreState(runs=[run([], rid=f"r{i}") for i in range(KEEP_RUNS + 3)])
    store = TopologyStore(inv)
    store.save(state)
    assert [r.id for r in store.load().runs] == [f"r{i}" for i in range(3, KEEP_RUNS + 3)]


# ---- join: section 9 rows ------------------------------------------------------------------

def _one(res):
    assert len(res.links) == 1, res.links
    return res.links[0]


def test_join_device_to_aws_vpn_learned(tmp_path):
    inv = _inv(tmp_path)
    lk = _one(join([tun("rtr1", "Tu1", "203.0.113.1", "52.0.0.1"), vpn("52.0.0.1", "203.0.113.1")], inv))
    assert (lk.origin, lk.kind, lk.oper) == ("learned", "aws-vpn", "up")
    assert lk.a == LinkEnd(device="rtr1", interface="Tunnel1")
    assert lk.b.aws_tgw_attachment == "tgw-attach-0abc" and lk.b.aws_account == "network"
    assert {p.subject for p in lk.provenance} == {"rtr1", "aws:network/us-east-1"}


def test_join_aws_vpn_behind_nat_is_inferred(tmp_path):
    inv = _inv(tmp_path)
    lk = _one(join([tun("rtr1", "Tu1", "10.9.9.9", "52.0.0.1"), vpn("52.0.0.1", "203.0.113.1")], inv))
    assert lk.origin == "inferred"


def test_join_aws_vgw_vpn(tmp_path):
    inv = _inv(tmp_path)
    lk = _one(join([tun("rtr1", "Tu1", "203.0.113.1", "52.0.0.1"),
                    vpn("52.0.0.1", "203.0.113.1", attach=None, tgw=None, vgw="vgw-0abc")], inv))
    assert lk.b.aws_vgw == "vgw-0abc" and lk.origin == "learned"


def test_join_tgw_vpn_without_attachment_is_a_candidate_not_a_link(tmp_path):
    inv = _inv(tmp_path)
    res = join([tun("rtr1", "Tu1", "203.0.113.1", "52.0.0.1"), vpn("52.0.0.1", "203.0.113.1", attach=None)], inv)
    assert res.links == [] and res.candidates[0].address == "52.0.0.1"


def test_join_down_tunnel_gives_down_link(tmp_path):
    inv = _inv(tmp_path)
    lk = _one(join([tun("rtr1", "Tu1", "203.0.113.1", "52.0.0.1", oper="down"), vpn("52.0.0.1", "203.0.113.1")], inv))
    assert lk.oper == "down" and lk.origin == "learned"


def test_join_two_tunnels_one_device_same_vpn_is_not_a_conflict(tmp_path):
    inv = _inv(tmp_path)
    res = join([tun("rtr1", "Tu1", "203.0.113.1", "52.0.0.1"), tun("rtr1", "Tu2", "203.0.113.1", "52.0.0.2"),
                vpn("52.0.0.1", "203.0.113.1"), vpn("52.0.0.2", "203.0.113.1")], inv)
    assert [lk.origin for lk in res.links] == ["learned", "learned"]
    assert all(not lk.conflicts for lk in res.links)


def test_join_one_vpn_attachment_to_two_devices_is_a_conflict(tmp_path):
    inv = _inv(tmp_path)
    res = join([tun("rtr1", "Tu1", "203.0.113.1", "52.0.0.1"), tun("rtr2", "Tu1", "198.51.100.2", "52.0.0.2"),
                vpn("52.0.0.1", "203.0.113.1"), vpn("52.0.0.2", "198.51.100.2")], inv)
    assert len(res.links) == 2 and all(lk.origin == "inferred" and lk.conflicts for lk in res.links)
    assert res.links[0].conflicts == (res.links[1].id,)


def test_join_one_tunnel_two_far_ends_is_a_conflict(tmp_path):
    inv = _inv(tmp_path)
    res = join([tun("rtr1", "Tu1", "203.0.113.1", "52.0.0.1"), vpn("52.0.0.1", "203.0.113.1"),
                sc("SC-East", "203.0.113.1")], inv)
    assert len(res.links) == 2 and all(lk.origin == "inferred" and lk.conflicts for lk in res.links)


def test_join_device_to_prisma_learned(tmp_path):
    inv = _inv(tmp_path)
    lk = _one(join([tun("rtr1", "Tu200", "203.0.113.1", "34.0.0.9"), sc("SC East", "203.0.113.1")], inv))
    assert (lk.origin, lk.kind) == ("learned", "prisma")
    assert lk.b.prisma_service_connection == "SC East"


def test_join_prisma_needs_an_up_session(tmp_path):
    inv = _inv(tmp_path)
    lk = _one(join([tun("rtr1", "Tu200", "203.0.113.1", "34.0.0.9", oper="unknown"), sc("SC", "203.0.113.1")], inv))
    assert lk.origin == "inferred"


def test_join_prisma_needs_the_ip_owned_by_that_device(tmp_path):
    inv = _inv(tmp_path)  # 203.0.113.50 is in no device's addresses
    lk = _one(join([tun("rtr1", "Tu200", "203.0.113.50", "34.0.0.9"), sc("SC", "203.0.113.50")], inv))
    assert lk.origin == "inferred"


def test_join_prisma_scm_alone_is_inferred_or_candidate(tmp_path):
    inv = _inv(tmp_path)
    lk = _one(join([sc("SC", "203.0.113.1")], inv))
    assert lk.origin == "inferred" and lk.a == LinkEnd(device="rtr1")
    res = join([sc("SC", "198.51.100.77")], inv)
    assert res.links == [] and res.candidates == [Candidate("scm", "198.51.100.77",
                                                            "service connection SC peer, not in inventory")]


def test_join_remote_networks_are_not_joined(tmp_path):
    inv = _inv(tmp_path)
    rn = PrismaTunnel("Branch-1", "remote_network", "203.0.113.1", prov("scm"))
    assert join([tun("rtr1", "Tu5", "203.0.113.1", "34.0.0.9"), rn], inv).links == []


def test_join_device_to_device_learned_once(tmp_path):
    inv = _inv(tmp_path)
    lk = _one(join([tun("rtr1", "Tu7", "203.0.113.1", "198.51.100.2", kind="gre"),
                    tun("rtr2", "Tunnel7", "198.51.100.2", "203.0.113.1", kind="gre")], inv))
    assert (lk.origin, lk.kind) == ("learned", "gre")
    assert {lk.a.device, lk.b.device} == {"rtr1", "rtr2"}


def test_join_device_to_device_one_side_is_inferred(tmp_path):
    inv = _inv(tmp_path)
    lk = _one(join([tun("rtr1", "Tu7", "203.0.113.1", "198.51.100.2")], inv))
    assert lk.origin == "inferred" and lk.b == LinkEnd(device="rtr2")


def test_join_unknown_peer_is_a_candidate(tmp_path):
    inv = _inv(tmp_path)
    res = join([tun("rtr1", "Tu7", "203.0.113.1", "198.51.100.200")], inv)
    assert res.links == [] and res.candidates[0] == Candidate("rtr1", "198.51.100.200", "tunnel peer of Tu7, not in inventory")


@pytest.mark.parametrize("peer", ["169.254.1.1", "127.0.0.1", "0.0.0.0", "2001:db8::2", "garbage"])
def test_join_never_keys_on_unusable_addresses(tmp_path, peer):
    inv = _inv(tmp_path)
    res = join([tun("rtr1", "Tu1", "203.0.113.1", peer), vpn(peer, "203.0.113.1")], inv)
    assert res.links == [] and res.candidates == []


def test_join_ignores_devices_not_in_inventory(tmp_path):
    inv = _inv(tmp_path)
    assert join([tun("ghost", "Tu1", "203.0.113.1", "52.0.0.1"), vpn("52.0.0.1", "203.0.113.1")], inv).links == []


# ---- merge: section 10 ---------------------------------------------------------------------

def _aws_found(inv, t=T0):
    return join([tun("rtr1", "Tu1", "203.0.113.1", "52.0.0.1", t=t), vpn("52.0.0.1", "203.0.113.1", t=t)], inv)


SUBJECTS = ["rtr1", "aws:network/us-east-1"]


def test_merge_new_link_then_seen_again_keeps_first_seen(tmp_path):
    inv = _inv(tmp_path)
    s1, r1 = merge(_aws_found(inv), inv, StoreState(), run(SUBJECTS), T0)
    assert r1.new == [s1.links[0].id] and s1.links[0].first_seen == T0
    s2, r2 = merge(_aws_found(inv, t=T0 + 50), inv, s1, run(SUBJECTS, rid="r2"), T0 + 50)
    assert r2.new == [] and s2.links[0].first_seen == T0 and s2.links[0].last_confirmed == T0 + 50


def test_merge_oper_change_is_reported(tmp_path):
    inv = _inv(tmp_path)
    s1, _ = merge(_aws_found(inv), inv, StoreState(), run(SUBJECTS), T0)
    down = join([tun("rtr1", "Tu1", "203.0.113.1", "52.0.0.1", oper="down"), vpn("52.0.0.1", "203.0.113.1")], inv)
    _, r2 = merge(down, inv, s1, run(SUBJECTS), T0 + 1)
    assert r2.changed == [s1.links[0].id]


def test_merge_absent_twice_with_answers_removes(tmp_path):
    inv = _inv(tmp_path)
    s1, _ = merge(_aws_found(inv), inv, StoreState(), run(SUBJECTS), T0)
    lid = s1.links[0].id
    s2, r2 = merge(join([], inv), inv, s1, run(SUBJECTS), T0 + 10)
    assert r2.absent == [lid] and s2.links[0].absent_since == T0 + 10
    s3, r3 = merge(join([], inv), inv, s2, run(SUBJECTS), T0 + 20)
    assert r3.removed == [lid] and s3.links == []


def test_merge_seen_again_clears_absent(tmp_path):
    inv = _inv(tmp_path)
    s1, _ = merge(_aws_found(inv), inv, StoreState(), run(SUBJECTS), T0)
    s2, _ = merge(join([], inv), inv, s1, run(SUBJECTS), T0 + 10)
    s3, _ = merge(_aws_found(inv), inv, s2, run(SUBJECTS), T0 + 20)
    assert s3.links[0].absent_since is None


@pytest.mark.parametrize("this_run", [
    run(["rtr1"]),                                              # AWS not crawled this time
    run(SUBJECTS, failed={"aws:network/us-east-1": "timeout"}),  # AWS failed
    run([]),
])
def test_merge_unanswered_is_not_absent(tmp_path, this_run):
    inv = _inv(tmp_path)
    s1, _ = merge(_aws_found(inv), inv, StoreState(), run(SUBJECTS), T0)
    for i in range(3):
        s1, rep = merge(join([], inv), inv, s1, this_run, T0 + 10 * (i + 1))
        assert rep.absent == [] and rep.removed == []
    assert len(s1.links) == 1 and s1.links[0].absent_since is None


DECLARED = """
  - name: rtr1-aws
    a: {device: rtr1, interface: Tunnel1}
    b: {aws: {tgw_attachment: tgw-attach-0abc, account: network, region: us-east-1}}
"""


def test_merge_declared_link_confirmed(tmp_path):
    inv = _inv(tmp_path, DECLARED)
    s, rep = merge(_aws_found(inv), inv, StoreState(), run(SUBJECTS), T0)
    assert rep.confirmed == ["rtr1-aws"] and rep.new == []
    assert [(lk.origin, lk.name, lk.conflicts) for lk in s.links] == [("declared", "rtr1-aws", ())]
    assert s.links[0].last_confirmed == T0 and len(s.links[0].provenance) == 2


def test_merge_declared_link_disagreeing_candidate_is_stored_with_conflict(tmp_path):
    inv = _inv(tmp_path, DECLARED.replace("tgw-attach-0abc", "tgw-attach-0zzz"))
    s, rep = merge(_aws_found(inv), inv, StoreState(), run(SUBJECTS), T0)
    assert rep.declared_conflicts == ["rtr1-aws"]
    declared = next(lk for lk in s.links if lk.origin == "declared")
    learned = next(lk for lk in s.links if lk.origin != "declared")
    assert declared.conflicts == (learned.id,) and declared.last_confirmed == 0.0
    assert learned.conflicts == ("declared:rtr1-aws",)


def test_merge_declared_next_hop_only_end_names_nothing(tmp_path):
    inv = _inv(tmp_path, """
  - name: rtr1-nh
    a: {device: rtr1, next_hop: 52.0.0.1}
    b: {aws: {tgw_attachment: tgw-attach-0zzz}}
""")
    s, rep = merge(_aws_found(inv), inv, StoreState(), run(SUBJECTS), T0)
    assert rep.new and not rep.declared_conflicts and not rep.confirmed


def test_merge_declared_record_dropped_when_declared_link_is_gone(tmp_path):
    inv = _inv(tmp_path, DECLARED)
    s1, _ = merge(_aws_found(inv), inv, StoreState(), run(SUBJECTS), T0)
    inv2 = _inv(tmp_path)  # same file without the declared link
    s2, _ = merge(join([], inv2), inv2, s1, run([]), T0 + 1)
    assert s2.links == []


def test_merge_keeps_candidates_of_subjects_not_crawled(tmp_path):
    inv = _inv(tmp_path)
    prev = StoreState(candidates=[Candidate("rtr2", "198.51.100.50", "old"), Candidate("rtr1", "198.51.100.51", "old")])
    found = join([tun("rtr1", "Tu7", "203.0.113.1", "198.51.100.200")], inv)
    s, _ = merge(found, inv, prev, run(["rtr1"]), T0)
    assert [(c.seen_by, c.address) for c in s.candidates] == [("rtr1", "198.51.100.200"), ("rtr2", "198.51.100.50")]


def test_merge_caps_runs(tmp_path):
    inv = _inv(tmp_path)
    s = StoreState()
    for i in range(KEEP_RUNS + 2):
        s, _ = merge(join([], inv), inv, s, run([], rid=f"r{i}"), T0 + i)
    assert [r.id for r in s.runs] == [f"r{i}" for i in range(2, KEEP_RUNS + 2)]


def test_merged_state_round_trips_through_the_store(tmp_path):
    inv = _inv(tmp_path, DECLARED.replace("tgw-attach-0abc", "tgw-attach-0zzz"))
    s, _ = merge(_aws_found(inv), inv, StoreState(), run(SUBJECTS), T0)
    store = TopologyStore(inv)
    store.save(s)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        back = store.load()
    assert [link_to_dict(x) for x in back.links] == [link_to_dict(x) for x in s.links]
