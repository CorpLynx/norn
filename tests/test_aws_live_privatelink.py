"""PrivateLink and NLB tracing against answers captured from real AWS (us-east-1, 2026-11-15, a throwaway probe).

`tests/fixtures/aws_live/privatelink/<operation>.json` holds each read-only call's parameters and real response
(account id replaced by 111122223333). A replay backend plugs in through `AwsEnv.backend_override`, below the same
allowlist guard as every other backend. Nothing here talks to AWS.

Probe: client ENI 10.241.0.63 -> endpoint ENI 10.241.0.103 -> NLB (listeners TCP 80 -> tg-ok:8080, TCP 82 ->
tg-denied:8081, none on 81; target SG allows 8080 from the NLB SG only) -> instance 10.240.0.116."""

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


def test_live_privatelink_path_is_followed_to_the_target(inv: Any) -> None:
    r = run(inv, "10.241.0.63", "10.241.0.103", 80)
    assert r.outcome is Outcome.REACHABLE
    comps = [h.component for h in r.hops]
    assert comps.index("interface-endpoint") < comps.index("nlb") < comps.index("target-group")
    assert r.final_flow.src == "10.240.0.97" and r.final_flow.dst == "10.240.0.116" and r.final_flow.dst_port == 8080


def test_live_no_listener_blocks(inv: Any) -> None:
    r = run(inv, "10.241.0.63", "10.241.0.103", 81)
    assert r.outcome is Outcome.BLOCKED and "no listener on tcp/81" in r.reason


def test_live_target_security_group_blocks_8081(inv: Any) -> None:
    r = run(inv, "10.241.0.63", "10.241.0.103", 82)
    assert r.outcome is Outcome.BLOCKED
    last = r.hops[-1]
    assert last.component == "security-group" and last.status is Status.BLOCK and r.final_flow.dst_port == 8081


def test_live_direct_nlb_keeps_the_client_address_so_the_target_sg_blocks(inv: Any) -> None:
    """Live: preserve_client_ip.enabled is "true" for instance targets, so the target sees 10.240.0.4, which its
    security group (NLB security group only) does not allow."""
    r = run(inv, "10.240.0.4", "10.240.0.97", 80)
    assert r.outcome is Outcome.BLOCKED
    assert r.final_flow.src == "10.240.0.4"
