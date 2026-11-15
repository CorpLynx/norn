"""PrivateLink and NLB tracing against answers captured from real AWS (us-east-1, 2026-11-15, a throwaway probe).

`tests/fixtures/aws_live/privatelink/<operation>.json` holds each read-only call's parameters and real response
(account id replaced by 111122223333). A replay backend plugs in through `AwsEnv.backend_override`, below the same
allowlist guard as every other backend. Nothing here talks to AWS.

Probe 2 (2026-11-15, real traffic, see D21): provider VPC 10.240.0.0/24 and consumer VPC 10.241.0.0/24; target 10.240.0.104
(az1) with SG 8080-8081 from the NLB security group only; NLB nodes 10.240.0.37 (az1) and 10.240.0.153 (az2); listeners
80 tg-pre (preserve client IP), 81 tg-nopre, 83 tg-83, 84 tg-84; endpoint ENIs 10.241.0.73 (az1) and 10.241.0.203 (az2);
client A 10.240.0.174 (az2) and client B 10.241.0.7 (az1). The NLB security group allows 80-82 from both VPCs, 83 from the
consumer VPC only and 84 from the provider VPC only. The console lines captured from the three instances are in
`tests/fixtures/aws_live/privatelink_console/`."""

import json
from pathlib import Path
from typing import Any

import pytest

from nettrace.drivers.aws import AwsEnv
from nettrace.engine import Tracer
from nettrace.inventory import load_inventory
from nettrace.models import Flow, Outcome, Status

FIX = Path(__file__).parent / "fixtures" / "aws_live" / "privatelink"
ACCT = "111122223333"


class Replay:
    def __init__(self, env: Any) -> None:
        self.answers: dict[str, dict[str, Any]] = {}
        for f in FIX.glob("*.json"):
            for item in json.loads(f.read_text()):
                self.answers[f.stem + json.dumps(item["params"], sort_keys=True)] = item["response"]

    def call(self, account: str, region: str, op: str, params: dict[str, Any]) -> dict[str, Any]:
        key = op + json.dumps(params, sort_keys=True)
        if key not in self.answers:
            raise AssertionError(f"no captured answer for {op} {params}")
        return json.loads(json.dumps(self.answers[key]))


@pytest.fixture
def inv(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    monkeypatch.setattr(AwsEnv, "backend_override", Replay)
    p = tmp_path / "inventory.yaml"
    p.write_text(f"aws:\n  regions: [us-east-1]\n  base_account_id: \"{ACCT}\"\n  accounts:\n"
                 f"    - name: probe\n      account_id: \"{ACCT}\"\n"
                 f"      role_arn: arn:aws:iam::{ACCT}:role/NetTraceReadOnlyProbe\n")
    return load_inventory(p)


def run(inv: Any, src: str, dst: str, port: int) -> Any:
    return Tracer(inv).trace(Flow(src=src, dst=dst, protocol="tcp", dst_port=port))


CON = Path(__file__).parent / "fixtures" / "aws_live" / "privatelink_console"
A, B, NODE_AZ2, ENDPOINT_AZ1 = "10.240.0.174", "10.241.0.7", "10.240.0.153", "10.241.0.73"


def test_console_evidence_matches_what_the_tests_assume() -> None:
    """The recorded real traffic: A port 80 reached the target with A's own address (Q1, Q4), A port 81 and every
    PrivateLink request arrived from an NLB node (Q2, control), B port 83 succeeded and 84 did not (Q3)."""
    a = (CON / "console_A.txt").read_text()
    b = (CON / "console_B.txt").read_text()
    t = (CON / "console_T.txt").read_text()
    assert "RESULT A port=80 code=200" in a and "RESULT A port=81 code=200" in a
    assert "code=000" not in a
    assert "RESULT B port=83 code=200" in b and "RESULT B port=84 code=000" in b and "RESULT B port=80 code=200" in b
    assert "RESULT B port=84 code=200" not in b and "RESULT B port=83 code=000" not in b
    peers = [ln.split() for ln in t.splitlines() if ln.startswith("PEER")]
    srcs = {(p[1], p[2]) for p in peers}
    assert srcs == {("port=8080", f"src={A}"), ("port=8080", f"src={NODE_AZ2}"), ("port=8081", f"src={NODE_AZ2}")}
    assert sum(p == ["PEER", "port=8080", f"src={A}"] for p in peers) == a.count("RESULT A port=80")


def test_live_direct_preserved_client_ip_reaches_a_target_that_allows_only_the_nlb_group(inv: Any) -> None:
    """Q1 and Q4: the connection succeeds although the target's rule names the NLB's group, and the target sees A."""
    r = run(inv, A, NODE_AZ2, 80)
    assert r.outcome is Outcome.REACHABLE, r.reason
    assert r.final_flow.src == A and r.final_flow.dst == "10.240.0.104" and r.final_flow.dst_port == 8080
    tg = next(h for h in r.hops if h.component == "target-group")
    assert "client address preserved" in tg.nat
    sg = r.hops[-2]
    assert sg.component == "security-group" and sg.status is Status.PASS
    assert any("references the NLB's security group" in d for d in sg.details)


def test_live_direct_without_preservation_is_snatted_to_the_node(inv: Any) -> None:
    """Control: the target saw the NLB node (10.240.0.153), as Norn says."""
    r = run(inv, A, NODE_AZ2, 81)
    assert r.outcome is Outcome.REACHABLE
    assert r.final_flow.src == NODE_AZ2
    assert "SNAT" in next(h for h in r.hops if h.component == "target-group").nat


def test_live_privatelink_target_sees_a_node_address(inv: Any) -> None:
    """Q2: through PrivateLink the target saw an NLB node address (never B's)."""
    r = run(inv, B, ENDPOINT_AZ1, 80)
    assert r.outcome is Outcome.REACHABLE
    assert r.final_flow.src in {"10.240.0.37", NODE_AZ2} and r.final_flow.src != B


def test_live_privatelink_consumer_side_rule_lets_port_83_in(inv: Any) -> None:
    """Q3: 83 (NLB inbound rule for the consumer CIDR) succeeded live."""
    r = run(inv, B, ENDPOINT_AZ1, 83)
    assert r.outcome is Outcome.REACHABLE
    sg = next(h for h in r.hops if h.component == "security-group" and "PrivateLink" in h.summary)
    assert sg.status is Status.PASS


@pytest.mark.parametrize("endpoint", [ENDPOINT_AZ1, "10.241.0.203"])
def test_live_privatelink_provider_side_rule_blocks_port_84(inv: Any, endpoint: str) -> None:
    """Q3: 84 (NLB inbound rule for the provider CIDR only) failed live (code 000), so this is a BLOCK, not UNKNOWN."""
    r = run(inv, B, endpoint, 84)
    assert r.outcome is Outcome.BLOCKED, r.reason
    last = r.hops[-1]
    assert last.component == "security-group" and last.status is Status.BLOCK
    assert not any(h.component == "target-group" for h in r.hops)
