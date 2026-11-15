"""PrivateLink interface endpoints and Network Load Balancers (D21). Simulators only; nothing here talks to AWS.

The demo lab holds the path: web01 (app-prod) -> interface endpoint 10.20.3.20 -> endpoint service owned by
shared-services -> internal NLB 10.30.2.10 (listener TCP/443) -> target group tools-tg (port 8443) -> instance tools01.
Variants are made by editing a private copy of the lab's AWS model, so the lab itself is never changed."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from nettrace import symmetry
from nettrace.demo import PRESETS, install, sim_aws
from nettrace.demo import lab
from nettrace.drivers import aws
from nettrace.engine import Tracer
from nettrace.errors import CancelToken, Deadline, DeadlineExceeded, ReadOnlyViolation
from nettrace.models import Flow, Outcome, Status
from nettrace.readonly import _AWS_ALLOWED, AWS_IAM_PREFIX, aws_operation_allowed, install_aws_guard

REGION = "us-east-1"
ELB = lab.ACCT_SHARED
PL_FLOW = Flow(src="10.20.1.50", dst=lab.EP_TOOLS_IP, protocol="tcp", dst_port=443)
ROOT = Path(__file__).resolve().parents[1]
NEW_EC2 = {"DescribeVpcEndpointServices", "DescribeVpcEndpointServiceConfigurations"}
NEW_ELB = {"DescribeLoadBalancers", "DescribeListeners", "DescribeTargetGroups", "DescribeTargetHealth",
           "DescribeTargetGroupAttributes", "DescribeLoadBalancerAttributes"}


@pytest.fixture
def model(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A private copy of the lab's AWS model that the simulator answers from."""
    m = copy.deepcopy(sim_aws.AWS)
    monkeypatch.setattr(sim_aws, "AWS", m)
    return m


def trace(flow: Flow = PL_FLOW, **kw: Any) -> Any:
    return Tracer(install(), **kw).trace(flow)


def comps(result: Any) -> list[str]:
    return [h.component for h in result.hops]


def hop(result: Any, component: str) -> Any:
    return next(h for h in result.hops if h.component == component)


def shared(m: dict[str, Any]) -> dict[str, Any]:
    return m["elb"][ELB]


def attr(m: dict[str, Any], key: str, value: str) -> None:
    for a in shared(m)["tg_attributes"][lab.TG_ARN]:
        if a["Key"] == key:
            a["Value"] = value


def sg(m: dict[str, Any], name: str) -> dict[str, Any]:
    return next(g for g in m["security_groups"] if g["GroupName"] == name)


# ---- allowlist, policy and the botocore guard agree -----------------------------------------------------------
def test_new_operations_are_allowlisted_exactly() -> None:
    assert {("ec2", o) for o in NEW_EC2} <= _AWS_ALLOWED
    assert {("elbv2", o) for o in NEW_ELB} <= _AWS_ALLOWED
    for bad in ("CreateLoadBalancer", "ModifyListener", "RegisterTargets", "DeleteTargetGroup", "ModifyTargetGroupAttributes",
                "DescribeRules", "DescribeSSLPolicies", "DescribeTags"):
        assert not aws_operation_allowed("elbv2", bad)
    # the ELB v2 operations are not valid under the old Classic ELB name or the IAM prefix
    assert not aws_operation_allowed("elb", "DescribeLoadBalancers")
    assert not aws_operation_allowed("elasticloadbalancing", "DescribeLoadBalancers")
    assert not any("Reachability" in o or "NetworkInsights" in o or "NetworkAccess" in o for _, o in _AWS_ALLOWED)


def test_policy_actions_equal_the_allowlist_in_both_copies() -> None:
    expected = {f"{AWS_IAM_PREFIX.get(s, s)}:{o}" for s, o in _AWS_ALLOWED if s != "sts"}
    for path in (ROOT / "iam" / "nettrace-readonly-policy.json", ROOT / "src" / "nettrace" / "data" / "nettrace-readonly-policy.json"):
        pol = json.loads(path.read_text())
        actions = [a for st in pol["Statement"] for a in st["Action"]]
        assert set(actions) == expected and len(actions) == len(set(actions)), path
        assert all(a.split(":")[1].startswith("Describe") or a.split(":")[1].startswith(("Get", "Search")) for a in actions)
    assert {"elasticloadbalancing:" + o for o in NEW_ELB} <= expected and {"ec2:" + o for o in NEW_EC2} <= expected


def test_packaged_session_policy_stays_under_the_sts_limit() -> None:
    doc = aws.session_policy()
    assert doc is not None and len(doc) <= aws._SESSION_POLICY_MAX == 2048
    assert "elasticloadbalancing:DescribeTargetHealth" in doc and "ec2:DescribeVpcEndpointServiceConfigurations" in doc
    print("session policy size:", len(doc))


def test_botocore_names_elbv2_the_way_the_guard_and_policy_expect() -> None:
    """botocore's service_name (what the before-call hook sees) is "elbv2"; the IAM prefix is "elasticloadbalancing"."""
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber

    from nettrace.errors import ReadOnlyViolation as RV

    session = install_aws_guard(boto3.Session(aws_access_key_id="x", aws_secret_access_key="y", region_name=REGION))
    client = session.client("elbv2")
    assert client.meta.service_model.service_name == "elbv2"
    assert client.meta.service_model.signing_name == "elasticloadbalancing" == AWS_IAM_PREFIX["elbv2"]
    with Stubber(client) as stub:
        for op, resp in (("describe_load_balancers", {"LoadBalancers": []}), ("describe_listeners", {"Listeners": []}),
                         ("describe_target_groups", {"TargetGroups": []}),
                         ("describe_target_health", {"TargetHealthDescriptions": []}),
                         ("describe_target_group_attributes", {"Attributes": []}),
                         ("describe_load_balancer_attributes", {"Attributes": []})):
            stub.add_response(op, resp)
        client.describe_load_balancers()
        client.describe_listeners(LoadBalancerArn="arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/net/a/b")
        client.describe_target_groups()
        client.describe_target_health(TargetGroupArn="arn:aws:elasticloadbalancing:us-east-1:1:targetgroup/a/b")
        client.describe_target_group_attributes(TargetGroupArn="arn:aws:elasticloadbalancing:us-east-1:1:targetgroup/a/b")
        client.describe_load_balancer_attributes(LoadBalancerArn="arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/net/a/b")
        stub.assert_no_pending_responses()
    for refused in (lambda: client.delete_load_balancer(LoadBalancerArn="arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/net/a/b"),
                    lambda: client.modify_listener(ListenerArn="arn:aws:elasticloadbalancing:us-east-1:1:listener/net/a/b/c"),
                    lambda: client.register_targets(TargetGroupArn="arn:aws:elasticloadbalancing:us-east-1:1:targetgroup/a/b",
                                                    Targets=[{"Id": "i-1"}])):
        with pytest.raises(RV, match="elbv2"):
            refused()
    ec2 = session.client("ec2")
    with Stubber(ec2) as stub:
        stub.add_response("describe_vpc_endpoint_services", {"ServiceDetails": []})
        stub.add_response("describe_vpc_endpoint_service_configurations", {"ServiceConfigurations": []})
        ec2.describe_vpc_endpoint_services()
        ec2.describe_vpc_endpoint_service_configurations()
    with pytest.raises(RV):
        ec2.create_vpc_endpoint_service_configuration(NetworkLoadBalancerArns=["a"])


def test_env_call_refuses_a_write_on_the_elbv2_service() -> None:
    env = aws.AwsEnv(install())
    with pytest.raises(ReadOnlyViolation, match="elbv2:ModifyListener"):
        env.call(ELB, REGION, "modify_listener", service="elbv2", ListenerArn="x")


def test_simulator_answers_like_the_elbv2_api() -> None:
    env = aws.AwsEnv(install())
    lb = env.call(ELB, REGION, "describe_load_balancers", service="elbv2", LoadBalancerArns=[lab.NLB_ARN])["LoadBalancers"][0]
    assert lb["Type"] == "network" and lb["Scheme"] == "internal"
    assert lb["AvailabilityZones"][0]["LoadBalancerAddresses"][0]["PrivateIPv4Address"] == lab.NLB_TOOLS_IP
    th = env.call(ELB, REGION, "describe_target_health", service="elbv2", TargetGroupArn=lab.TG_ARN)["TargetHealthDescriptions"]
    assert th[0]["Target"] == {"Id": lab.TOOLS01_INSTANCE, "Port": 8443} and th[0]["TargetHealth"]["State"] == "healthy"
    # visibility mirrors AWS: another account does not see the load balancer
    with pytest.raises(sim_aws.SimAwsError, match="LoadBalancerNotFound"):
        env.call(lab.ACCT_PROD, REGION, "describe_load_balancers", service="elbv2", LoadBalancerArns=[lab.NLB_ARN])
    svc = env.call(lab.ACCT_PROD, REGION, "describe_vpc_endpoint_services", ServiceNames=[lab.VPCE_SVC_NAME])["ServiceDetails"][0]
    assert svc["Owner"] == lab.ACCT_SHARED and svc["ServiceId"] == lab.VPCE_SVC_ID
    assert env.call(lab.ACCT_PROD, REGION, "describe_vpc_endpoint_service_configurations")["ServiceConfigurations"] == []


# ---- PrivateLink, end to end -----------------------------------------------------------------------------------
def test_privatelink_path_end_to_end() -> None:
    r = trace()
    assert r.outcome == Outcome.REACHABLE, r.reason
    names = comps(r)
    assert names.index("interface-endpoint") < names.index("nlb") < names.index("target-group") < len(names) - 1
    assert r.hops[-1].component == "eni" and r.hops[-1].status == Status.PASS
    # structured fields, not text
    ep, nlb, tg = hop(r, "interface-endpoint"), hop(r, "nlb"), hop(r, "target-group")
    assert ep.ingress and ep.egress == lab.VPCE_SVC_NAME and ep.node == lab.VPCE_TOOLS
    assert nlb.node == lab.NLB_NAME and nlb.egress == lab.TG_NAME and nlb.policy == "listener TCP:443 forward"
    assert tg.ingress == nlb.ingress and tg.egress == lab.ENI["tools01"]
    # the account of each hop: the endpoint is the consumer's, the NLB and target group the provider's
    assert ep.location["account"] == lab.ACCT_PROD and nlb.location["account"] == lab.ACCT_SHARED
    assert nlb.location["vpc"] == lab.VPC_SHARED
    # the flow was rewritten: destination NAT to the target and port, source NAT to the NLB node
    assert r.final_flow.dst == lab.TOOLS01_IP and r.final_flow.dst_port == 8443
    assert r.final_flow.src == lab.NLB_TOOLS_IP and r.flow.src == "10.20.1.50"
    assert tg.nat == f"DNAT {lab.EP_TOOLS_IP}:443 -> {lab.TOOLS01_IP}:8443; SNAT 10.20.1.50 -> {lab.NLB_TOOLS_IP}"
    # the target's security group admitted the NLB node (it references the NLB's group), not the client
    tsg = [h for h in r.hops if h.component == "security-group"][-1]
    assert "from " + lab.NLB_TOOLS_IP in tsg.summary
    assert "via NLB tools-nlb (PrivateLink)" in r.reason
    assert not any(h.status == Status.UNKNOWN for h in r.hops)


def test_every_new_request_is_audited_and_goes_through_the_allowlist(tmp_path: Path) -> None:
    trace()
    log = (tmp_path / "audit" / "audit.log").read_text()
    for op in ("elbv2.describe_load_balancers", "elbv2.describe_listeners", "elbv2.describe_target_groups",
               "elbv2.describe_target_health", "elbv2.describe_target_group_attributes",
               "ec2.describe_vpc_endpoints", "ec2.describe_vpc_endpoint_services",
               "ec2.describe_vpc_endpoint_service_configurations"):
        assert op in log, op
    # the cross-account reads were made as the right account: the service configuration as the owner
    recs = [json.loads(line) for line in log.splitlines()]
    cfg = next(x for x in recs if "describe_vpc_endpoint_service_configurations" in json.dumps(x))
    assert lab.ACCT_SHARED in json.dumps(cfg)


def test_the_two_presets_have_their_expected_outcomes() -> None:
    ids = {p["id"]: p for p in PRESETS}
    assert ids["prod-to-tools-privatelink"]["expect"] == "REACHABLE" and ids["prod-to-tools-no-listener"]["expect"] == "BLOCKED"
    r = trace(Flow(src="10.20.1.50", dst=lab.EP_TOOLS_IP, protocol="tcp", dst_port=8080))
    assert r.outcome == Outcome.BLOCKED and "no listener on tcp/8080" in r.reason


# ---- the NLB: listener -----------------------------------------------------------------------------------------
def test_no_listener_is_a_block_that_names_what_exists() -> None:
    r = trace(Flow(src="10.20.1.50", dst=lab.EP_TOOLS_IP, protocol="tcp", dst_port=8080))
    last = r.hops[-1]
    assert last.component == "nlb" and last.status == Status.BLOCK and last.summary == "no listener on tcp/8080"
    assert any("TCP/443" in d for d in last.details)
    assert r.outcome == Outcome.BLOCKED and "target-group" not in comps(r)


def test_listener_protocol_matters(model: dict[str, Any]) -> None:
    udp = Flow(src="10.20.1.50", dst=lab.EP_TOOLS_IP, protocol="udp", dst_port=443)
    ep_sg = sg(model, "tools-endpoint")
    ep_sg["IpPermissions"].append({"IpProtocol": "udp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.20.0.0/16"}],
                                   "Ipv6Ranges": [], "PrefixListIds": [], "UserIdGroupPairs": []})
    r = trace(udp)
    assert r.outcome == Outcome.BLOCKED and r.hops[-1].summary == "no listener on udp/443"
    shared(model)["listeners"][0]["Protocol"] = "TCP_UDP"  # one TCP_UDP listener serves both
    sg(model, "tools-server")["IpPermissions"].append(
        {"IpProtocol": "udp", "FromPort": 8443, "ToPort": 8443, "IpRanges": [{"CidrIp": "10.30.2.0/24"}],
         "Ipv6Ranges": [], "PrefixListIds": [], "UserIdGroupPairs": []})
    r = trace(udp)
    assert r.outcome == Outcome.REACHABLE and r.final_flow.protocol == "udp"


@pytest.mark.parametrize("flow", [Flow(src="10.20.1.50", dst=lab.EP_TOOLS_IP, protocol="tcp"),
                                  Flow(src="10.20.1.50", dst=lab.EP_TOOLS_IP, protocol="icmp")])
def test_icmp_and_missing_port_are_unknown_not_guessed(model: dict[str, Any], flow: Flow) -> None:
    sg(model, "tools-endpoint")["IpPermissions"] = [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "10.20.0.0/16"}],
                                                     "Ipv6Ranges": [], "PrefixListIds": [], "UserIdGroupPairs": []}]
    r = trace(flow)
    assert r.outcome == Outcome.INCOMPLETE and r.hops[-1].status == Status.UNKNOWN
    assert r.hops[-1].component == "nlb" and ("listener" in r.hops[-1].summary or "listeners carry" in r.hops[-1].summary)


def test_several_target_groups_follow_the_first_and_warn_listing_all(model: dict[str, Any]) -> None:
    second = copy.deepcopy(shared(model)["target_groups"][0])
    second_arn = lab.TG_ARN.replace("tools-tg", "tools-canary")
    second.update(TargetGroupArn=second_arn, TargetGroupName="tools-canary")
    shared(model)["target_groups"].append(second)
    shared(model)["tg_attributes"][second_arn] = copy.deepcopy(shared(model)["tg_attributes"][lab.TG_ARN])
    shared(model)["target_health"][second_arn] = copy.deepcopy(shared(model)["target_health"][lab.TG_ARN])
    shared(model)["listeners"][0]["DefaultActions"][0]["ForwardConfig"]["TargetGroups"] = [
        {"TargetGroupArn": lab.TG_ARN, "Weight": 80}, {"TargetGroupArn": second_arn, "Weight": 20}]
    r = trace()
    nlb = hop(r, "nlb")
    assert nlb.status == Status.WARN and r.outcome == Outcome.REACHABLE  # WARN does not make a trace INCOMPLETE
    text = " ".join(nlb.details)
    assert "tools-tg (weight 80)" in text and "tools-canary (weight 20)" in text and "following tools-tg" in text
    assert any("weighted target groups" in w for w in r.warnings)
    assert hop(r, "target-group").node == "tools-tg"


def test_a_zero_weight_group_is_not_chosen(model: dict[str, Any]) -> None:
    shared(model)["listeners"][0]["DefaultActions"][0]["ForwardConfig"]["TargetGroups"] = [
        {"TargetGroupArn": lab.TG_ARN.replace("tools-tg", "tools-off"), "Weight": 0},
        {"TargetGroupArn": lab.TG_ARN, "Weight": 1}]
    r = trace()
    assert hop(r, "target-group").node == "tools-tg" and hop(r, "nlb").status == Status.WARN


# ---- the target group ------------------------------------------------------------------------------------------
def _second_target(model: dict[str, Any], state: str = "healthy", port: int | None = 8443) -> str:
    other = lab.rid("i", "tools02")
    t: dict[str, Any] = {"Id": other}
    if port:
        t["Port"] = port
    shared(model)["target_health"][lab.TG_ARN].append({"Target": t, "TargetHealth": {"State": state}})
    return other


def test_several_targets_follow_the_first_and_warn_listing_the_others_with_health(model: dict[str, Any]) -> None:
    other = _second_target(model, "unhealthy")
    r = trace()
    tg = hop(r, "target-group")
    assert tg.status == Status.WARN and r.outcome == Outcome.REACHABLE
    text = " ".join(tg.details)
    assert f"{lab.TOOLS01_INSTANCE}:8443 healthy" in text and f"{other}:8443 unhealthy" in text
    assert f"following {lab.TOOLS01_INSTANCE}" in text
    assert r.final_flow.dst == lab.TOOLS01_IP


def test_a_healthy_target_is_preferred_over_an_earlier_unhealthy_one(model: dict[str, Any]) -> None:
    shared(model)["target_health"][lab.TG_ARN][0]["TargetHealth"]["State"] = "unhealthy"
    model["enis"].append(copy.deepcopy(next(e for e in model["enis"] if e["NetworkInterfaceId"] == lab.ENI["tools01"])))
    spare = model["enis"][-1]
    spare.update(NetworkInterfaceId=lab.rid("eni", "tools02"), PrivateIpAddress="10.30.3.41",
                 PrivateIpAddresses=[{"PrivateIpAddress": "10.30.3.41", "Primary": True}],
                 Attachment={"InstanceId": lab.rid("i", "tools02"), "DeviceIndex": 0, "Status": "attached"})
    _second_target(model, "healthy")
    r = trace()
    assert r.final_flow.dst == "10.30.3.41"
    assert hop(r, "target-group").egress == lab.rid("eni", "tools02")


def test_no_healthy_target_warns_that_the_nlb_fails_open(model: dict[str, Any]) -> None:
    shared(model)["target_health"][lab.TG_ARN][0]["TargetHealth"] = {"State": "unhealthy", "Reason": "Target.FailedHealthChecks"}
    r = trace()
    tg = hop(r, "target-group")
    assert tg.status == Status.WARN and r.outcome == Outcome.REACHABLE
    assert any("fails open" in d for d in tg.details) and any("fails open" in w for w in r.warnings)


def test_no_registered_target_blocks(model: dict[str, Any]) -> None:
    shared(model)["target_health"][lab.TG_ARN] = []
    r = trace()
    assert r.outcome == Outcome.BLOCKED and r.hops[-1].summary == "no registered targets"


def test_alb_and_lambda_target_groups_are_unknown(model: dict[str, Any]) -> None:
    shared(model)["target_groups"][0]["TargetType"] = "alb"
    r = trace()
    assert r.outcome == Outcome.INCOMPLETE and r.hops[-1].status == Status.UNKNOWN and "alb" in r.hops[-1].summary


def test_target_port_wins_else_the_target_group_port(model: dict[str, Any]) -> None:
    shared(model)["target_health"][lab.TG_ARN][0]["Target"]["Port"] = 9000
    mine = sg(model, "tools-server")["IpPermissions"][0]
    mine["FromPort"] = mine["ToPort"] = 9000
    r = trace()
    assert r.outcome == Outcome.REACHABLE and r.final_flow.dst_port == 9000
    del shared(model)["target_health"][lab.TG_ARN][0]["Target"]["Port"]
    mine["FromPort"] = mine["ToPort"] = 8443
    assert trace().final_flow.dst_port == 8443  # the target group's port


def test_ip_targets_are_followed_and_an_ip_outside_the_vpc_is_unknown(model: dict[str, Any]) -> None:
    shared(model)["target_groups"][0]["TargetType"] = "ip"
    shared(model)["target_health"][lab.TG_ARN][0]["Target"] = {"Id": lab.TOOLS01_IP, "Port": 8443, "AvailabilityZone": lab.AZ}
    attr(model, "preserve_client_ip.enabled", "false")
    r = trace()
    assert r.outcome == Outcome.REACHABLE and r.final_flow.dst == lab.TOOLS01_IP
    shared(model)["target_health"][lab.TG_ARN][0]["Target"]["AvailabilityZone"] = "all"
    r = trace()
    assert r.outcome == Outcome.INCOMPLETE and "outside the VPC" in r.hops[-1].summary


def test_the_targets_security_group_denying_the_nlb_blocks(model: dict[str, Any]) -> None:
    sg(model, "tools-server")["IpPermissions"] = []
    r = trace()
    assert r.outcome == Outcome.BLOCKED and r.hops[-1].component == "security-group"
    assert r.hops[-1].ingress == lab.ENI["tools01"] and lab.NLB_TOOLS_IP in r.hops[-1].summary


def test_a_nacl_between_the_nlb_and_the_target_is_checked(model: dict[str, Any]) -> None:
    nacl = next(n for n in model["nacls"] if n["Tags"][0]["Value"] == "shared-default")
    nacl["Entries"].insert(0, {"RuleNumber": 50, "Egress": False, "RuleAction": "deny", "CidrBlock": lab.NLB_TOOLS_IP + "/32",
                               "Protocol": "-1"})
    # the target sits in another subnet than the NLB, so its inbound NACL sees the NLB node's address
    r = trace()
    assert r.outcome == Outcome.BLOCKED and r.hops[-1].component == "nacl" and "DENIED" in r.hops[-1].summary


def test_the_nlb_security_group_egress_to_the_target_is_checked(model: dict[str, Any]) -> None:
    sg(model, "tools-nlb")["IpPermissionsEgress"] = []
    r = trace()
    assert r.outcome == Outcome.BLOCKED and "blocks egress to the target" in r.reason


# ---- client IP semantics -----------------------------------------------------------------------------------------
def _direct(src: str = "10.30.1.53") -> Flow:
    return Flow(src=src, dst=lab.NLB_TOOLS_IP, protocol="tcp", dst_port=443)


def test_direct_nlb_with_client_ip_preservation_keeps_the_client_address(model: dict[str, Any]) -> None:
    sg(model, "tools-server")["IpPermissions"][0]["IpRanges"] = [{"CidrIp": "10.30.1.0/24"}]  # the target must trust the client
    r = trace(_direct())
    assert r.outcome == Outcome.REACHABLE, r.reason
    tg = hop(r, "target-group")
    assert r.final_flow.src == "10.30.1.53" and r.final_flow.dst == lab.TOOLS01_IP and r.final_flow.dst_port == 8443
    assert tg.nat.endswith("client address preserved") and "SNAT" not in tg.nat
    assert "interface-endpoint" not in comps(r) and "via NLB tools-nlb (direct)" in r.reason


def test_direct_nlb_with_preservation_means_the_target_must_allow_the_client(model: dict[str, Any]) -> None:
    r = trace(_direct())  # tools-server only trusts the NLB's group: the client address is what it sees
    assert r.outcome == Outcome.BLOCKED and "from 10.30.1.53" in r.hops[-1].summary


def test_direct_nlb_without_preservation_uses_the_nlb_address(model: dict[str, Any]) -> None:
    attr(model, "preserve_client_ip.enabled", "false")
    r = trace(_direct())
    assert r.outcome == Outcome.REACHABLE, r.reason
    assert r.final_flow.src == lab.NLB_TOOLS_IP and f"SNAT 10.30.1.53 -> {lab.NLB_TOOLS_IP}" in hop(r, "target-group").nat


def test_privatelink_ignores_the_preservation_attribute(model: dict[str, Any]) -> None:
    attr(model, "preserve_client_ip.enabled", "true")
    r = trace()
    assert r.final_flow.src == lab.NLB_TOOLS_IP and any("whatever the target group attribute says" in d
                                                         for d in hop(r, "target-group").details)


def test_the_nlbs_own_security_group_is_checked_on_direct_traffic(model: dict[str, Any]) -> None:
    sg(model, "tools-nlb")["IpPermissions"] = []
    r = trace(_direct())
    assert r.outcome == Outcome.BLOCKED and r.hops[-1].component == "security-group" and r.hops[-1].ingress == lab.ENI["nlb-tools"]


def test_privatelink_inbound_rule_enforcement_attribute(model: dict[str, Any]) -> None:
    lb = shared(model)["load_balancers"][0]
    sg(model, "tools-nlb")["IpPermissions"] = []  # nothing allows the endpoint address by rule
    assert trace().outcome == Outcome.REACHABLE  # "off": inbound rules are not enforced for PrivateLink traffic
    lb["EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic"] = "on"
    r = trace()
    assert r.outcome == Outcome.INCOMPLETE and r.hops[-1].status == Status.UNKNOWN  # a deny on an undocumented address
    sg(model, "tools-nlb")["IpPermissions"] = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "UserIdGroupPairs": [],
                                                "IpRanges": [{"CidrIp": "10.20.0.0/16"}], "Ipv6Ranges": [], "PrefixListIds": []}]
    r = trace()
    assert r.outcome == Outcome.REACHABLE and any(h.component == "security-group" and h.ingress == lab.ENI["nlb-tools"]
                                                  and h.status == Status.PASS for h in r.hops)
    del lb["EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic"]
    r = trace()
    assert r.outcome == Outcome.INCOMPLETE and "does not report" in r.hops[-1].summary


# ---- cross-zone ----------------------------------------------------------------------------------------------------
def _move_target_to_zone_b(model: dict[str, Any]) -> None:
    next(e for e in model["enis"] if e["NetworkInterfaceId"] == lab.ENI["tools01"])["AvailabilityZone"] = "us-east-1b"


def test_target_in_a_zone_the_nlb_does_not_serve_warns_when_cross_zone_is_off(model: dict[str, Any]) -> None:
    _move_target_to_zone_b(model)
    r = trace()
    tg = hop(r, "target-group")
    assert tg.status == Status.WARN and r.outcome == Outcome.REACHABLE
    assert any("cross-zone load balancing is off" in d and "no subnet in us-east-1b" in d for d in tg.details)


def test_cross_zone_on_removes_the_warning(model: dict[str, Any]) -> None:
    _move_target_to_zone_b(model)
    attr(model, "load_balancing.cross_zone.enabled", "true")  # target group level override
    assert hop(trace(), "target-group").status == Status.INFO
    attr(model, "load_balancing.cross_zone.enabled", "use_load_balancer_configuration")
    for a in shared(model)["lb_attributes"][lab.NLB_ARN]:
        if a["Key"] == "load_balancing.cross_zone.enabled":
            a["Value"] = "true"
    assert hop(trace(), "target-group").status == Status.INFO


# ---- the endpoint service owner -----------------------------------------------------------------------------------------
def test_owner_account_outside_the_inventory_is_unknown_and_incomplete(model: dict[str, Any]) -> None:
    model["endpoint_services"][0]["Owner"] = "999900001111"
    r = trace()
    assert r.outcome == Outcome.INCOMPLETE and "999900001111" in r.reason
    last = r.hops[-1]
    assert last.component == "interface-endpoint" and last.status == Status.UNKNOWN and "not in the inventory" in last.summary
    assert "nlb" not in comps(r)  # nothing was guessed past it


def test_an_aws_owned_service_ends_at_the_endpoint(model: dict[str, Any]) -> None:
    model["endpoint_services"][0]["Owner"] = "amazon"
    r = trace()
    assert r.outcome == Outcome.REACHABLE and r.hops[-1].component == "interface-endpoint" and "AWS service" in r.hops[-1].summary


def test_gateway_load_balancer_services_are_unknown(model: dict[str, Any]) -> None:
    model["endpoint_services"][0]["ServiceType"] = [{"ServiceType": "GatewayLoadBalancer"}]
    r = trace()
    assert r.outcome == Outcome.INCOMPLETE and r.hops[-1].status == Status.UNKNOWN and "gateway load balancer" in r.hops[-1].summary
    model["endpoint_services"][0]["ServiceType"] = [{"ServiceType": "Interface"}]
    cfg = model["service_configs"][ELB][0]
    cfg["GatewayLoadBalancerArns"], cfg["NetworkLoadBalancerArns"] = cfg["NetworkLoadBalancerArns"], []
    r = trace()
    assert r.outcome == Outcome.INCOMPLETE and "gateway load balancer" in r.hops[-1].summary


def test_several_nlbs_behind_a_service_follow_the_first_and_warn(model: dict[str, Any]) -> None:
    model["service_configs"][ELB][0]["NetworkLoadBalancerArns"].append(lab.NLB_ARN.replace("tools-nlb", "tools-nlb-2"))
    r = trace()
    ep = hop(r, "interface-endpoint")
    assert ep.status == Status.WARN and any("tools-nlb-2" in d for d in ep.details) and r.outcome == Outcome.REACHABLE


@pytest.mark.parametrize("state", ["pendingAcceptance", "rejected"])
def test_an_endpoint_that_is_not_available_blocks(model: dict[str, Any], state: str) -> None:
    model["vpc_endpoints"][0]["State"] = state
    r = trace()
    assert r.outcome == Outcome.BLOCKED and r.hops[-1].component == "interface-endpoint" and state in r.hops[-1].summary


def test_endpoint_security_group_is_checked_before_the_endpoint_is_followed(model: dict[str, Any]) -> None:
    sg(model, "tools-endpoint")["IpPermissions"] = []
    r = trace()
    assert r.outcome == Outcome.BLOCKED and r.hops[-1].component == "security-group"
    assert "interface-endpoint" not in comps(r)


def test_an_unreadable_service_is_not_treated_as_not_configured(model: dict[str, Any]) -> None:
    model["service_configs"][ELB] = []
    r = trace()
    # the owner's account answers NotFound for the service id: a failed read, so an UNKNOWN hop, never "no NLB"
    assert r.outcome == Outcome.INCOMPLETE and r.hops[-1].status == Status.UNKNOWN and "NotFound" in r.reason
    assert "nlb" not in comps(r)


# ---- return path and symmetry -------------------------------------------------------------------------------------------
def test_a_privatelink_path_gets_no_return_trace_and_says_why() -> None:
    r = Tracer(install()).trace_with_return(PL_FLOW)
    assert r.outcome == Outcome.REACHABLE
    assert r.return_path.symmetry.status.value == "NOT_RUN" and "PrivateLink" in r.return_path.reason


def test_the_new_components_are_not_transit_components() -> None:
    """They are connection-level, not routed hops: the reply never crosses them, so they must not be compared."""
    assert not ({"interface-endpoint", "nlb", "target-group"} & symmetry.TRANSIT_COMPONENTS)


def test_a_preserved_client_address_keeps_the_return_trace(model: dict[str, Any]) -> None:
    sg(model, "tools-server")["IpPermissions"][0]["IpRanges"] = [{"CidrIp": "10.30.1.0/24"}]
    fwd = trace(_direct())
    assert symmetry.untraceable_return(fwd) is None
    attr(model, "preserve_client_ip.enabled", "false")
    assert "replaced the source address" in symmetry.untraceable_return(trace(_direct()))


# ---- deadline and cancel ---------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("after_op", ["describe_vpc_endpoint_services", "describe_load_balancers", "describe_listeners",
                                      "describe_target_groups", "describe_target_health"])
def test_cancel_during_the_new_calls_ends_incomplete_with_the_hops_so_far(monkeypatch: pytest.MonkeyPatch, after_op: str) -> None:
    token = CancelToken()
    real = sim_aws.Backend.call

    def call(self: Any, account: str, region: str, op: str, params: dict[str, Any]) -> dict[str, Any]:
        out = real(self, account, region, op, params)
        if op == after_op:
            token.cancel()  # the user clicks Cancel while this request is in flight
        return out

    monkeypatch.setattr(sim_aws.Backend, "call", call)
    r = Tracer(install(), cancel=token).trace(PL_FLOW)
    assert r.cancelled and r.outcome == Outcome.INCOMPLETE and r.reason == "cancelled by user"
    assert not any(h.status == Status.UNKNOWN for h in r.hops), "a cancel is not a failed read"
    # the step that was running is abandoned (as for every driver); the hops of earlier steps are kept
    assert r.hops[0].component == "source"


def test_deadline_propagates_from_the_new_calls() -> None:
    env = aws.AwsEnv(install())
    env.deadline = Deadline(-1)
    with pytest.raises(DeadlineExceeded):
        env.call(ELB, REGION, "describe_load_balancers", service="elbv2")
    walker = aws.AwsWalker(env, install())
    with pytest.raises(DeadlineExceeded):
        walker._elb(ELB, REGION, "describe_listeners", LoadBalancerArn=lab.NLB_ARN)


def test_a_deadline_in_the_middle_of_the_nlb_walk_keeps_the_hops(monkeypatch: pytest.MonkeyPatch) -> None:
    real = sim_aws.Backend.call
    tracer = Tracer(install())

    def call(self: Any, account: str, region: str, op: str, params: dict[str, Any]) -> dict[str, Any]:
        if op == "describe_target_health":
            tracer.deadline.seconds = -1
            tracer.deadline._end = 0.0  # the budget runs out right before the target-health read
            tracer.clients.set_deadline(tracer.deadline)
        return real(self, account, region, op, params)

    monkeypatch.setattr(sim_aws.Backend, "call", call)
    r = tracer.trace(PL_FLOW)
    assert r.outcome == Outcome.INCOMPLETE and "deadline" in r.reason.lower()


# ---- the map ------------------------------------------------------------------------------------------------------------------
def test_the_path_map_draws_the_new_components() -> None:
    from nettrace.viz import svg as vsvg
    from nettrace.viz.model import build_map

    out = vsvg.render_svg(build_map(trace().to_dict()))
    assert ">NLB<" in out and ">VPCE<" in out and "tools-nlb" in out
