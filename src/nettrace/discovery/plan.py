"""The requests a crawl would send, per subject (`topology crawl --dry-run`, docs/discovery-spec.md 8). Pure.

The plan names only what the inventory names (rule 2 of section 3). Ids match section 6 (B, C, A, D) so the owner
can see which approved guard entry each request needs.
"""

from __future__ import annotations

from dataclasses import dataclass

from nettrace.discovery.observe.scm import IKE_GATEWAYS, IPSEC_TUNNELS, REMOTE_NETWORKS, SERVICE_CONNECTIONS
from nettrace.inventory import Inventory

SCOPES = ("control-plane", "devices", "all")


@dataclass(frozen=True)
class Planned:
    subject: str
    guard_id: str   # B7, C4, A1, ... ("-" = already allowed for traces)
    request: str


def plan(inv: Inventory, *, scope: str = "all", devices: tuple[str, ...] = (), aws: bool = True,
         prisma: bool = True) -> list[Planned]:
    if scope not in SCOPES:
        raise ValueError(f"scope must be one of {', '.join(SCOPES)}")
    for name in devices:
        inv.device(name)  # InventoryError for an unknown name
    out: list[Planned] = []
    if scope in ("control-plane", "all"):
        if inv.panorama:
            out.append(Planned("panorama", "C11", "<show><devices><all></all></devices></show>"))
        if aws:
            for acct in inv.aws_accounts:
                for region in acct.regions:
                    subject = f"aws:{acct.name}/{region}"
                    out += [Planned(subject, "A1", "ec2:DescribeVpnConnections"),
                            Planned(subject, "A2", "ec2:DescribeCustomerGateways"),
                            Planned(subject, "-", "ec2:DescribeTransitGatewayAttachments resource-type=vpn")]
        if prisma and inv.prisma:
            out += [Planned("scm", gid, f"GET {path}") for gid, path in
                    (("D2", SERVICE_CONNECTIONS), ("D3", REMOTE_NETWORKS), ("D5", IPSEC_TUNNELS), ("D4", IKE_GATEWAYS))]
    if scope in ("devices", "all"):
        for dev in inv.devices.values():
            if devices and dev.name not in devices:
                continue
            if dev.platform == "cisco_iosxe":
                out += [Planned(dev.name, "B3", "show ip interface brief"),
                        Planned(dev.name, "B6", "show interfaces Tunnel<n> (each tunnel in the brief)"),
                        Planned(dev.name, "B7", "show crypto session")]
            elif dev.platform == "panos":
                via = f" target={dev.serial}" if dev.via == "panorama" else ""
                out += [Planned(dev.name, "C2", f"<show><interface>all</interface></show>{via}"),
                        Planned(dev.name, "C4", f"<show><vpn><flow></flow></vpn></show>{via}")]
    return out
