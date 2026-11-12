"""Prisma Access facts from Strata Cloud Manager (D2 to D5 in docs/discovery-spec.md 6.4).

Chain (V23, unverified; field names from pan-scm-sdk): a service connection or remote network names its
`ipsec_tunnel`; the tunnel names its IKE gateway(s) in `auto_key.ike_gateway[].name`; the gateway's customer-side
address is `peer_address.ip`. A gateway with a dynamic or FQDN peer has no IP and gives no join key.

IKE gateways carry the pre-shared key (`authentication.pre_shared_key`), so `keep_scm_fields` must run on the
answer before anything else sees it, like the AWS keep-list.
"""

from __future__ import annotations

from typing import Any

from nettrace.discovery.model import PrismaTunnel, clean_text, join_ip
from nettrace.discovery.observe import DEFAULT_ROW_CAP, ProvFactory, check_rows
from nettrace.errors import DeviceError

SERVICE_CONNECTIONS = "/config/deployment/v1/service-connections"
REMOTE_NETWORKS = "/config/deployment/v1/remote-networks"
IKE_GATEWAYS = "/config/network/v1/ike-gateways"
IPSEC_TUNNELS = "/config/network/v1/ipsec-tunnels"

_KEEP: dict[str, tuple[str, ...]] = {
    SERVICE_CONNECTIONS: ("name", "ipsec_tunnel"),
    REMOTE_NETWORKS: ("name", "ipsec_tunnel"),
    IPSEC_TUNNELS: ("name", "auto_key"),
    IKE_GATEWAYS: ("name", "peer_address"),
}


def keep_scm_fields(path: str, items: list[Any]) -> list[dict[str, Any]]:
    """Only the listed keys of each item; nested values are narrowed too (auto_key -> ike_gateway names,
    peer_address -> ip). Paths without a rule pass unchanged."""
    keys = _KEEP.get(path)
    if keys is None:
        return items
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        row = {k: it[k] for k in keys if k in it}
        if isinstance(row.get("auto_key"), dict):
            gws = row["auto_key"].get("ike_gateway") or []
            row["auto_key"] = {"ike_gateway": [{"name": g.get("name")} for g in gws if isinstance(g, dict)]}
        elif "auto_key" in row:
            row["auto_key"] = {}
        if "peer_address" in row:
            pa = row["peer_address"]
            row["peer_address"] = {"ip": pa.get("ip")} if isinstance(pa, dict) and "ip" in pa else {}
        out.append(row)
    return out


def _name(v: Any) -> str:
    s = clean_text(v)
    if not s:
        raise DeviceError("SCM object without a name")
    return s


def prisma_tunnels(service_connections: list[Any], remote_networks: list[Any], tunnels: list[Any],
                   gateways: list[Any], prov: ProvFactory, row_cap: int = DEFAULT_ROW_CAP) -> list[PrismaTunnel]:
    """One PrismaTunnel per (service connection or remote network, IKE gateway peer IP). Inputs are keep-filtered."""
    for rows, what in ((service_connections, "service-connections"), (remote_networks, "remote-networks"),
                       (tunnels, "ipsec-tunnels"), (gateways, "ike-gateways")):
        if not isinstance(rows, list):
            raise DeviceError(f"SCM {what}: not a list")
        check_rows(len(rows), row_cap, f"SCM {what}")
    gw_ip = {_name(g.get("name")): join_ip((g.get("peer_address") or {}).get("ip"))
             for g in gateways if isinstance(g, dict)}
    tun_gws = {_name(t.get("name")): [clean_text(g.get("name")) for g in (t.get("auto_key") or {}).get("ike_gateway", [])]
               for t in tunnels if isinstance(t, dict)}
    out = []
    for rows, kind, source in ((service_connections, "service_connection", "scm:service-connections"),
                               (remote_networks, "remote_network", "scm:remote-networks")):
        for r in rows:
            if not isinstance(r, dict):
                raise DeviceError(f"{source}: item is not an object")
            name, tunnel = _name(r.get("name")), clean_text(r.get("ipsec_tunnel"))
            peers = [gw_ip.get(g) for g in tun_gws.get(tunnel, [])]
            for ip in dict.fromkeys(p for p in peers if p):
                fragment = {"name": name, "kind": kind, "tunnel": tunnel, "peer": ip}
                out.append(PrismaTunnel(name, kind, ip, prov(source, fragment)))
    return out
