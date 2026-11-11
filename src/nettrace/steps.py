"""Positions the engine moves between, and what each driver step returns."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Union

from nettrace.models import Flow, Hop, Outcome, Status


@dataclass(frozen=True)
class DeviceAt:
    """Traffic is arriving at an inventory device (Cisco or PAN-OS)."""

    device: str
    arrival_ip: str | None = None  # the device address the previous hop sent to
    arrival_interface: str | None = None
    vrf: str | None = None
    gwlb_endpoint: str | None = None  # set when a PAN-OS VM sits behind an AWS GWLB
    resume: AwsAt | None = None  # where to continue in AWS after an inline (GWLB) firewall


@dataclass(frozen=True)
class AwsAt:
    """Traffic is at a point inside AWS."""

    kind: str  # source_eni | tgw_attachment | vgw | subnet | appliance_egress
    account: str | None = None  # account id
    region: str | None = None
    resource_id: str | None = None  # eni / tgw-attach / vgw / subnet id
    ip: str | None = None  # appliance egress interface IP
    note: str | None = None


@dataclass(frozen=True)
class PrismaAt:
    entry: str  # source | service_connection
    name: str | None = None


Position = Union[DeviceAt, AwsAt, PrismaAt]


@dataclass
class Egress:
    """A device forwarded the flow out of an interface; the engine decides where it goes next."""

    device: str
    interface: str | None
    next_hop: str | None  # None when the destination is directly connected
    vrf: str | None = None


@dataclass
class StepResult:
    hops: list[Hop]
    flow: Flow
    next: Position | None = None
    egress: Egress | None = None
    outcome: Outcome | None = None
    reason: str = ""
    warnings: list[str] = field(default_factory=list)


@dataclass
class RouteDiagnosis:
    """Read-only evidence for a hop that found no route (BGP table and peers, static routes). It explains a BLOCK;
    it never turns one into a PASS. `contradiction` means the evidence shows a usable route while the forwarding
    lookup found none: the sources disagree, so the hop is UNKNOWN, not BLOCK (never guess)."""

    lines: list[str] = field(default_factory=list)  # detail lines for the hop
    reason: str = ""  # short suffix for the trace reason
    contradiction: bool = False


def ipv6_unknown(flow: Flow, domain: str, node: str, component: str) -> StepResult | None:
    """Never guess on IPv6: every driver does IPv4 matching only (/32 hosts, IPv4 wildcard masks, CidrBlock
    without Ipv6Ranges...). Returns an UNKNOWN step that ends the trace as INCOMPLETE when src or dst is IPv6,
    else None. Called first in each driver's entry point."""
    v6 = [a for a in (flow.src, flow.dst) if ":" in a]
    if not v6:
        return None
    msg = f"IPv6 is not evaluated ({', '.join(v6)}): nettrace evaluates IPv4 flows only"
    hop = Hop(domain=domain, node=node, component=component, status=Status.UNKNOWN, summary=msg,
              details=["no IPv4 logic was run for this flow; the verdict for this component is unknown"])
    return StepResult([hop], flow, outcome=Outcome.INCOMPLETE, reason=f"{node}: IPv6 is not evaluated",
                      warnings=[f"{node}: IPv6 is not evaluated"])
