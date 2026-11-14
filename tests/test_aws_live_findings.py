"""Behaviour of real AWS found by running against the aws-networking-lab (2026-11-14), pinned so the
simulator and the driver cannot drift back. Simulators only; nothing here talks to AWS."""

from typing import Any

import pytest

from nettrace import symmetry
from nettrace.demo import install
from nettrace.demo.lab import ACCT_NET, TGW_RT_SPOKES
from nettrace.drivers import aws
from nettrace.errors import Cancelled
from nettrace.models import Flow, Hop, Outcome, Status, TraceResult

REGION = "us-east-1"


def _search(env: aws.AwsEnv, name: str, value: str) -> list[dict[str, Any]]:
    return env.call(ACCT_NET, REGION, "search_transit_gateway_routes", TransitGatewayRouteTableId=TGW_RT_SPOKES,
                    Filters=[{"Name": name, "Values": [value]}]).get("Routes", [])


def test_simulator_answers_tgw_route_filters_like_real_aws() -> None:
    """V9: longest-prefix-match takes a bare address, supernet-of-match a CIDR; the wrong form finds nothing."""
    env = aws.AwsEnv(install())
    assert [r["DestinationCidrBlock"] for r in _search(env, "route-search.longest-prefix-match", "10.20.1.50")]
    assert _search(env, "route-search.longest-prefix-match", "10.20.1.50/32") == []
    assert [r["DestinationCidrBlock"] for r in _search(env, "route-search.supernet-of-match", "10.20.1.50/32")]
    assert _search(env, "route-search.supernet-of-match", "10.20.1.50") == []


def test_tgw_route_search_finds_the_route() -> None:
    env = aws.AwsEnv(install())
    route = env.search_tgw_routes(ACCT_NET, REGION, TGW_RT_SPOKES, "10.20.1.50")
    assert route is not None and route["DestinationCidrBlock"] == "0.0.0.0/0"
    longest = env.search_tgw_routes(ACCT_NET, REGION, TGW_RT_SPOKES, "10.1.20.7")
    assert longest is not None and longest["DestinationCidrBlock"] == "10.1.20.0/24"  # not the 0/0 that also matches


def test_an_empty_longest_prefix_answer_is_confirmed_before_it_means_no_route(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty longest-prefix answer is how AWS says "wrong form", so it must not become "no route" (a false BLOCK)."""
    env = aws.AwsEnv(install())
    real_call = env.call
    asked: list[str] = []

    def call(acct: str, region: str, op: str, **params: Any) -> dict[str, Any]:
        if op == "search_transit_gateway_routes":
            name = params["Filters"][0]["Name"]
            asked.append(name)
            if name == "route-search.longest-prefix-match":
                return {"Routes": []}
        return real_call(acct, region, op, **params)

    monkeypatch.setattr(env, "call", call)
    route = env.search_tgw_routes(ACCT_NET, REGION, TGW_RT_SPOKES, "10.1.20.7")
    assert asked == ["route-search.longest-prefix-match", "route-search.supernet-of-match"]
    assert route is not None and route["DestinationCidrBlock"] == "10.1.20.0/24"


def test_no_route_only_when_both_filters_agree(monkeypatch: pytest.MonkeyPatch) -> None:
    env = aws.AwsEnv(install())
    monkeypatch.setattr(env, "call", lambda *a, **k: {"Routes": []})
    assert env.search_tgw_routes(ACCT_NET, REGION, TGW_RT_SPOKES, "10.1.20.7") is None


def test_cancel_is_not_swallowed_by_the_filter_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    env = aws.AwsEnv(install())

    def cancelled(*a: Any, **k: Any) -> dict[str, Any]:
        raise Cancelled("cancelled by user")

    monkeypatch.setattr(env, "call", cancelled)
    with pytest.raises(Cancelled):
        env.search_tgw_routes(ACCT_NET, REGION, TGW_RT_SPOKES, "10.1.20.7")


# ---- return path: security groups are stateful per ENI (D16, amended 2026-11-14) ---------------------------------
# Found on the lab: every --return trace ended INCOMPLETE at the source's security group, because the reply was
# evaluated as a new inbound session. AWS lets the reply of an allowed request through whatever the rules say.


SRC_ENI, DST_ENI = "eni-0source", "eni-0dest"


def _fwd(*, snat: bool = False, dst_sg: Status = Status.PASS) -> TraceResult:
    hops = [
        Hop("engine", "10.2.4.58", "source", Status.INFO, "source"),
        Hop("aws", "sg-src", "security-group", Status.PASS, "egress allowed", egress=SRC_ENI),
        Hop("aws", "rtb-1", "route-table", Status.INFO, "0.0.0.0/0 -> tgw"),
        Hop("aws", "sg-mid", "security-group", Status.PASS, "egress allowed", egress="eni-0appliance"),
        Hop("aws", "sg-dst", "security-group", dst_sg, "ingress", ingress=DST_ENI),
        Hop("aws", DST_ENI, "eni", Status.PASS, "delivered", ingress=DST_ENI),
    ]
    for i, h in enumerate(hops, 1):
        h.index = i
    flow = Flow("10.2.4.58", "10.0.20.113", "tcp", 80)
    final = Flow("10.9.9.9", "10.0.20.113", "tcp", 80) if snat else flow
    return TraceResult(flow, Outcome.REACHABLE, "delivered", hops, final_flow=final)


def test_only_the_endpoint_enis_carry_the_reply() -> None:
    assert symmetry.stateful_reply_enis(_fwd()) == {SRC_ENI: 2, DST_ENI: 5}  # not the appliance ENI after routing


def test_source_nat_drops_the_destination_eni() -> None:
    assert symmetry.stateful_reply_enis(_fwd(snat=True)) == {SRC_ENI: 2}


def test_nothing_when_the_forward_path_was_not_delivered() -> None:
    fwd = _fwd()
    fwd.outcome = Outcome.INCOMPLETE
    assert symmetry.stateful_reply_enis(fwd) == {}


def test_walker_records_a_stateful_reply_without_evaluating_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    env = aws.AwsEnv(install())
    walker = aws.AwsWalker(env, install(), stateful_replies={SRC_ENI: 2})

    def must_not_evaluate(*a: Any, **k: Any) -> Any:
        raise AssertionError("security group rules evaluated for a stateful reply")

    monkeypatch.setattr(env, "security_groups", must_not_evaluate)
    hops: list[Hop] = []
    eni = {"NetworkInterfaceId": SRC_ENI, "Groups": [{"GroupId": "sg-src"}], "VpcId": "vpc-1"}
    reply = Flow("10.0.20.113", "10.2.4.58", "tcp", 49152, src_port=80)
    assert walker._sg_check(ACCT_NET, REGION, eni, reply, egress=False, peer_eni=None, hops=hops)
    (hop,) = hops
    assert hop.status == Status.PASS and hop.ingress == SRC_ENI
    assert "stateful" in hop.summary and "forward hop 2" in (hop.policy or "")


def test_other_enis_are_still_evaluated_as_a_new_session(monkeypatch: pytest.MonkeyPatch) -> None:
    env = aws.AwsEnv(install())
    walker = aws.AwsWalker(env, install(), stateful_replies={SRC_ENI: 2})
    seen: list[list[str]] = []
    monkeypatch.setattr(env, "security_groups", lambda acct, region, ids: seen.append(ids) or [])
    eni = {"NetworkInterfaceId": "eni-0other", "Groups": [{"GroupId": "sg-x"}], "VpcId": "vpc-1"}
    walker._sg_check(ACCT_NET, REGION, eni, Flow("10.0.0.1", "10.0.0.2", "tcp", 80), egress=False, peer_eni=None, hops=[])
    assert seen == [["sg-x"]]
