"""AWS Site-to-Site VPN facts and the field keep-list (docs/discovery-spec.md 6.3).

`keep_fields` is the filter that must run on every DescribeVpnConnections / DescribeCustomerGateways answer before
anything else sees it: the per-run cache, Evidence, the audit log. It keeps only the listed keys, so a pre-shared
key (`CustomerGatewayConfiguration`, `Options.TunnelOptions[].PreSharedKey`) or any field AWS adds later is dropped.
M2 wires it into `AwsEnv._boto_call_once` and the backend path; today it is only tested.

Joining (V22, unverified): a tunnel's AWS outside IP is `Options.TunnelOptions[].OutsideIpAddress` (else
`VgwTelemetry[].OutsideIpAddress`), its state is `VgwTelemetry[].Status` (UP/DOWN) for that IP, the customer gateway
address is `CustomerGateways[].IpAddress`, and a TGW VPN's attachment is the `DescribeTransitGatewayAttachments` entry
with `ResourceType: vpn` and `ResourceId: <vpn id>`.
"""

from __future__ import annotations

import re
from typing import Any

from nettrace.discovery.model import AwsVpn, clean_text, join_ip
from nettrace.discovery.observe import DEFAULT_ROW_CAP, ProvFactory, check_rows
from nettrace.errors import DeviceError

# path -> keys kept at that level. "[]" = each list item. Anything not reachable through these paths is removed.
KEEP: dict[tuple[str, str], dict[str, tuple[str, ...]]] = {
    ("ec2", "DescribeVpnConnections"): {
        "": ("VpnConnections", "NextToken"),
        "VpnConnections[]": ("VpnConnectionId", "CustomerGatewayId", "TransitGatewayId", "VpnGatewayId", "State",
                             "Type", "VgwTelemetry", "Options"),
        "VpnConnections[].VgwTelemetry[]": ("OutsideIpAddress", "Status"),
        "VpnConnections[].Options": ("TunnelOptions",),
        "VpnConnections[].Options.TunnelOptions[]": ("OutsideIpAddress",),
    },
    ("ec2", "DescribeCustomerGateways"): {
        "": ("CustomerGateways", "NextToken"),
        "CustomerGateways[]": ("CustomerGatewayId", "IpAddress", "State"),
    },
}


def keep_fields(service: str, operation: str, response: Any) -> Any:
    """The response with only the keep-listed fields. Operations without a keep-list pass unchanged."""
    rules = KEEP.get((service, operation))
    if rules is None:
        return response
    return _keep(response, "", rules)


def _keep(value: Any, path: str, rules: dict[str, tuple[str, ...]]) -> Any:
    if isinstance(value, list):
        item = path + "[]"
        return [_keep(v, item, rules) for v in value] if item in rules else []
    if not isinstance(value, dict):
        return value
    allowed = rules.get(path)
    if allowed is None:
        return {}
    out = {}
    for k in allowed:
        if k in value:
            child = f"{path}.{k}" if path else k
            v = value[k]
            if isinstance(v, (dict, list)) and child not in rules and child + "[]" not in rules:
                continue  # a nested object with no rule of its own is dropped whole
            out[k] = _keep(v, child, rules)
    return out


_ID = re.compile(r"[a-z]+(?:-[a-z]+)*-[0-9a-f]{8,17}")


def _id(v: Any, what: str) -> str | None:
    if v in (None, ""):
        return None
    if not isinstance(v, str) or not _ID.fullmatch(v):
        raise DeviceError(f"AWS {what}: unexpected id {clean_text(v)!r}")
    return v


def aws_vpns(account: str, region: str, vpn_resp: Any, cgw_resp: Any, attach_resp: Any, prov: ProvFactory,
             row_cap: int = DEFAULT_ROW_CAP) -> list[AwsVpn]:
    """One AwsVpn per tunnel of every VPN connection that is not deleted. Inputs are already keep-filtered."""
    try:
        vpns = list(vpn_resp["VpnConnections"])
        cgws = list(cgw_resp["CustomerGateways"])
        attachments = list(attach_resp["TransitGatewayAttachments"])
    except (KeyError, TypeError):
        raise DeviceError("AWS VPN answer is missing VpnConnections, CustomerGateways or "
                          "TransitGatewayAttachments") from None
    for n, what in ((len(vpns), "DescribeVpnConnections"), (len(cgws), "DescribeCustomerGateways"),
                    (len(attachments), "DescribeTransitGatewayAttachments")):
        check_rows(n, row_cap, what)
    cgw_ip = {c.get("CustomerGatewayId"): join_ip(c.get("IpAddress")) for c in cgws if isinstance(c, dict)}
    attach: dict[str, list[str]] = {}
    for a in attachments:
        if isinstance(a, dict) and a.get("ResourceType") == "vpn" and a.get("State") not in ("deleted", "deleting"):
            aid = _id(a.get("TransitGatewayAttachmentId"), "attachment")
            rid = _id(a.get("ResourceId"), "attachment resource")
            if aid and rid:
                attach.setdefault(rid, []).append(aid)
    out = []
    for v in vpns:
        if not isinstance(v, dict) or v.get("State") in ("deleted", "deleting"):
            continue
        vpn_id = _id(v.get("VpnConnectionId"), "VPN connection")
        if not vpn_id:
            raise DeviceError("AWS VPN connection without an id")
        tgw, vgw = _id(v.get("TransitGatewayId"), "TGW"), _id(v.get("VpnGatewayId"), "VGW")
        found = attach.get(vpn_id, [])
        attachment = found[0] if len(found) == 1 else None  # two attachments for one VPN: never pick one
        status = {join_ip(t.get("OutsideIpAddress")): str(t.get("Status", "")).upper()
                  for t in v.get("VgwTelemetry") or [] if isinstance(t, dict)}
        outside = [join_ip(t.get("OutsideIpAddress")) for t in (v.get("Options") or {}).get("TunnelOptions") or []
                   if isinstance(t, dict)] or list(status)
        cgw = cgw_ip.get(v.get("CustomerGatewayId"))
        for ip in dict.fromkeys(outside):
            if not ip:
                continue
            s = status.get(ip, "")
            oper = "up" if s == "UP" else "down" if s == "DOWN" else "unknown"
            fragment = {"vpn": vpn_id, "outside": ip, "cgw": cgw, "tgw": tgw, "vgw": vgw, "attachment": attachment,
                        "status": s}
            out.append(AwsVpn(account, region, vpn_id, ip, cgw, tgw, vgw, attachment, oper,
                              prov("aws:ec2.DescribeVpnConnections", fragment)))
    return out
