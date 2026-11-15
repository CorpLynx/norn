"""The live AWS map for the web UI (D22), built from the demo lab's simulated AWS. Nothing here talks to AWS."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from nettrace.demo import install, lab, sim_aws
from nettrace.drivers import aws
from nettrace.drivers.aws import AwsEnv
from nettrace.engine import Tracer
from nettrace.models import Flow
from nettrace.readonly import _AWS_ALLOWED, AWS_IAM_PREFIX, aws_operation_allowed
from nettrace.web import aws_map
from nettrace.web.topology import Locator, overlay

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def inv() -> Any:
    return install()


@pytest.fixture
def model(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    m = copy.deepcopy(sim_aws.AWS)
    monkeypatch.setattr(sim_aws, "AWS", m)
    return m


def by_kind(topo: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    return [n for n in topo["nodes"] if n["kind"] == kind]


def test_groups_nest_account_vpc_subnet(inv: Any) -> None:
    t = aws_map.build_aws_map(inv)
    g = {x["id"]: x for x in t["groups"]}
    assert {x["kind"] for x in g.values()} == {"aws", "vpc", "subnet"}
    for x in g.values():
        if x["kind"] == "aws":
            assert "parent" not in x
            continue
        p = g[x["parent"]]
        assert p["kind"] == {"vpc": "aws", "subnet": "vpc"}[x["kind"]]
        assert p["x"] <= x["x"] and p["y"] <= x["y"] and x["x"] + x["w"] <= p["x"] + p["w"] and x["y"] + x["h"] <= p["y"] + p["h"]
    vpc = next(x for x in g.values() if x["kind"] == "vpc")
    assert "/16" in vpc["label"]
    sub = next(x for x in g.values() if x["kind"] == "subnet")
    assert "/" in sub["label"] and "us-east-1" in sub["meta"]
    for n in t["nodes"]:  # every node with a group sits inside its box
        if n.get("group"):
            b = g[n["group"]]
            assert b["x"] <= n["x"] <= b["x"] + b["w"] and b["y"] <= n["y"] <= b["y"] + b["h"], n["id"]


def test_infrastructure_nodes_and_links(inv: Any) -> None:
    t = aws_map.build_aws_map(inv)
    ids = {n["id"] for n in t["nodes"]}
    assert len(by_kind(t, "tgw")) == 1 and len(by_kind(t, "natgw")) == 1 and len(by_kind(t, "nlb")) == 1
    assert len(by_kind(t, "vpce")) == 1 and "internet" in ids and by_kind(t, "igw")
    pairs = {frozenset((lk["a"], lk["b"])) for lk in t["links"]}
    tgw, nlb, ep = by_kind(t, "tgw")[0]["id"], by_kind(t, "nlb")[0]["id"], by_kind(t, "vpce")[0]["id"]
    assert sum(1 for lk in t["links"] if tgw in (lk["a"], lk["b"])) == 3  # three VPC attachments
    assert frozenset((ep, nlb)) in pairs  # endpoint -> its service NLB
    assert any(nlb in p and any(n["kind"] == "host" and n["id"] in p for n in t["nodes"]) for p in pairs)  # NLB -> target
    igw = by_kind(t, "igw")[0]["id"]
    assert frozenset((igw, "internet")) in pairs and frozenset((by_kind(t, "natgw")[0]["id"], igw)) in pairs
    assert all(lk["a"] in ids and lk["b"] in ids for lk in t["links"])
    nlb_detail = json.dumps(by_kind(t, "nlb")[0]["detail"])
    assert "TCP:443" in nlb_detail and "tools-tg" in nlb_detail and "healthy" in nlb_detail


def test_instance_names_come_from_describe_instances_and_sgs_show(inv: Any, model: dict[str, Any]) -> None:
    for r in model["instances"]:
        for i in r["Instances"]:
            if i["InstanceId"] == lab.TOOLS01_INSTANCE:
                i["Tags"] = [{"Key": "Name", "Value": "renamed-tools"}]
    t = aws_map.build_aws_map(inv)
    labels = {n["label"] for n in t["nodes"]}
    assert "renamed-tools" in labels and "web01" in labels
    web = next(n for n in t["nodes"] if n["label"] == "web01")
    sgs = next(s for s in web["detail"] if s["title"] == "Security groups")["rows"]
    assert sgs[0][0].startswith("web-tier") and "tcp/443 from 10.0.0.0/8" in sgs[0][1]
    assert "web-tier" in web["find"] and "10.20.1.50" in web["ips"]
    fw = next(n for n in t["nodes"] if n.get("devices") == ["fw-aws-1"])  # inventory device placed on its instance's ENIs
    assert fw["kind"] == "firewall" and lab.ENI["fw-trust"] in fw["ids"]


def test_failing_account_shows_a_note_and_never_raises(inv: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    real = sim_aws.Backend.call

    def call(self: Any, account: str, region: str, op: str, params: dict[str, Any]) -> dict[str, Any]:
        if account == lab.ACCT_PROD:
            raise sim_aws.SimAwsError("UnauthorizedOperation: not allowed to " + op)
        if op == "describe_load_balancers":
            raise sim_aws.SimAwsError("AccessDenied: elb")
        return real(self, account, region, op, params)

    monkeypatch.setattr(sim_aws.Backend, "call", call)
    t = aws_map.build_aws_map(inv)
    acct = next(n for n in t["nodes"] if n["id"] == f"aws-{lab.ACCT_PROD}")
    assert acct["kind"] == "error" and acct["sub"].startswith("could not read: ") and "UnauthorizedOperation" in acct["sub"]
    assert any(g["id"] == f"g-aws-{lab.ACCT_PROD}" for g in t["groups"])  # still drawn
    assert t["notes"] and t["counts"]["read_failures"] == len(t["notes"])
    other = next(n for n in t["nodes"] if n["id"] == f"aws-{lab.ACCT_SHARED}")
    assert other["kind"] == "account" and "reads failed" in other["sub"]
    assert not by_kind(t, "nlb")  # the failed call is reported, not guessed around


def test_hops_light_the_most_specific_node(inv: Any) -> None:
    t = aws_map.build_aws_map(inv)
    nodes = {n["id"]: n for n in t["nodes"]}
    flow = Flow(src="10.20.1.50", dst=lab.EP_TOOLS_IP, protocol="tcp", dst_port=443)
    trace = Tracer(inv).trace(flow).to_dict()
    ov = overlay(t, trace)
    by_comp: dict[str, set[str]] = {}
    for h in trace["Hops"]:
        nid = ov["hop_nodes"][str(h["index"])]
        assert nid is not None, (h["component"], h["node"])
        by_comp.setdefault(h["component"], set()).add(nodes[nid]["kind"])
    assert by_comp["interface-endpoint"] == {"vpce"} and by_comp["nlb"] == {"nlb"} and by_comp["target-group"] == {"nlb"}
    assert by_comp["route-table"] == {"vpc-router"} and by_comp["nacl"] == {"vpc-router"}
    assert nodes[ov["hop_nodes"]["1"]]["label"] == "web01"  # source: exact address
    assert nodes[ov["path"][-1]]["label"] == "tools01"  # the target behind the NLB
    # a hybrid flow crosses the TGW and the VM-Series
    trace = Tracer(inv).trace(Flow(src="10.1.10.25", dst="10.20.1.50", protocol="tcp", dst_port=443)).to_dict()
    ov = overlay(t, trace)
    kinds = [nodes[n]["kind"] for n in ov["path"] if n in nodes]
    assert "tgw" in kinds and "firewall" in kinds
    loc = Locator(t)
    assert nodes[loc.hop({"domain": "aws", "component": "tgw-route-table", "node": "tgw-rtb-x", "location": {"tgw": lab.TGW}}, {})]["kind"] == "tgw"


def test_an_address_claimed_by_two_nodes_is_not_attributed() -> None:
    topo = {"nodes": [{"id": "a", "ips": ["10.0.0.5"]}, {"id": "b", "ips": ["10.0.0.5"]}, {"id": "c", "ips": ["10.0.0.6"]}]}
    loc = Locator(topo)
    assert loc.by_ip("10.0.0.5") is None and loc.by_ip("10.0.0.6") == "c"


def test_aws_text_is_cleaned_and_the_ui_escapes_it(inv: Any, model: dict[str, Any]) -> None:
    evil = '<img src=x onerror=alert(1)> \x00 ' + "A" * 300
    for r in model["instances"]:
        for i in r["Instances"]:
            i["Tags"] = [{"Key": "Name", "Value": evil}]
    t = aws_map.build_aws_map(inv)
    names = [n.get("full", n["label"]) for n in t["nodes"] if n["kind"] in ("host", "firewall")]
    assert names and all("\x00" not in x and " " not in x and len(x) <= 80 for x in names)
    blob = json.dumps(t)
    assert " " not in blob and "\\u0000" not in blob
    html = (ROOT / "src" / "nettrace" / "web" / "static" / "app.html").read_text()
    # every interpolation of map text in the group, node and detail renderers goes through esc()
    for snippet in ("${esc(g.label)}", "${esc(g.meta)}", "${esc(n.full || n.label)}", "${esc(sec.title)}",
                    "${esc(r[0])}", "${esc(r[1])}", "${esc(i)}"):
        assert snippet in html, snippet
    sec = html[html.index("function detailHtml"): html.index("function deviceHops")]
    assert "${sec." not in sec.replace("${sec.rows", "").replace("${sec.items", "")  # no raw sec.* interpolation


def test_big_subnet_is_capped_with_a_more_node(inv: Any, model: dict[str, Any]) -> None:
    base = next(e for e in model["enis"] if e["NetworkInterfaceId"] == lab.ENI["web01"])
    for k in range(40):
        e = copy.deepcopy(base)
        e["NetworkInterfaceId"] = f"eni-{k:017x}"
        e["PrivateIpAddress"] = f"10.20.1.{100 + k}"
        e["PrivateIpAddresses"] = [{"PrivateIpAddress": e["PrivateIpAddress"], "Primary": True}]
        e.pop("Attachment")
        e["Description"] = f"lambda {k}"
        model["enis"].append(e)
    t = aws_map.build_aws_map(inv)
    more = next(n for n in t["nodes"] if n["id"].startswith("more-"))
    assert more["label"].startswith("+") and "10.20.1.139" in more["ips"]
    assert Locator(t).by_ip("10.20.1.139") == more["id"]


def test_allowlist_policy_and_size_agree() -> None:
    assert aws_operation_allowed("ec2", "DescribeInstances")
    for bad in ("RunInstances", "TerminateInstances", "DescribeInstanceAttribute", "GetConsoleOutput", "DescribeInternetGateways"):
        assert not aws_operation_allowed("ec2", bad)
    expected = {f"{AWS_IAM_PREFIX.get(s, s)}:{o}" for s, o in _AWS_ALLOWED if s != "sts"}
    for p in (ROOT / "iam" / "nettrace-readonly-policy.json", ROOT / "src" / "nettrace" / "data" / "nettrace-readonly-policy.json"):
        assert set(json.loads(p.read_text())["Statement"][0]["Action"]) == expected
    doc = aws.session_policy()
    assert doc is not None and "ec2:DescribeInstances" in doc and len(doc) <= 2048


def test_every_map_call_goes_through_awsenv_and_is_read_only(inv: Any) -> None:
    env = AwsEnv(inv)
    aws_map.build_aws_map(inv, env=env)
    ops = {e.request.split()[0] for e in env.evidence}
    assert "ec2.describe_instances" in ops
    assert all(o.split(".")[1].startswith("describe_") for o in ops)
