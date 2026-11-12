"""Canonical dict form of links and link ends, shared by join (ids), merge (agreement) and the store (JSON).

The dict shape of a LinkEnd is the inventory YAML shape, so `topology show --as-inventory` can print it as is.
`end_from_dict` / `link_from_dict` treat their input as untrusted (they read the store file) and raise ValueError.
"""

from __future__ import annotations

import ipaddress
import math
from typing import Any

from nettrace.discovery.model import (LINK_KINDS, OPER, ORIGINS, Provenance, clean_text, is_token, link_id,
                                     normalise_interface)
from nettrace.inventory import Inventory, Link, LinkEnd


def end_to_dict(end: LinkEnd, platform: str | None = None) -> dict[str, Any]:
    if end.device:
        d: dict[str, Any] = {"device": end.device}
        if end.interface:
            d["interface"] = normalise_interface(end.interface, platform)
        if end.next_hop:
            d["next_hop"] = end.next_hop
        return d
    if end.aws_tgw_attachment or end.aws_vgw:
        aws = {k: v for k, v in (("tgw_attachment", end.aws_tgw_attachment), ("vgw", end.aws_vgw),
                                 ("account", end.aws_account), ("region", end.aws_region)) if v}
        return {"aws": aws}
    if end.prisma_service_connection:
        return {"prisma_access": {"service_connection": end.prisma_service_connection}}
    if end.external:
        return {"external": end.external}
    return {}


def end_key(end: LinkEnd, platform: str | None = None) -> tuple[str, ...]:
    """What identifies this end when the engine looks a link up from it."""
    if end.device:
        return ("device", end.device, normalise_interface(end.interface, platform) if end.interface else "")
    if end.aws_tgw_attachment or end.aws_vgw:
        return ("aws", end.aws_tgw_attachment or end.aws_vgw or "")
    if end.prisma_service_connection:
        return ("prisma", end.prisma_service_connection)
    return ("external", end.external or "")


def node_of(end: LinkEnd) -> tuple[str, str]:
    """The node behind an end: a device (any interface), an AWS attachment/VGW, a service connection."""
    if end.device:
        return ("device", end.device)
    return end_key(end)[:2]  # type: ignore[return-value]


def make_id(kind: str, a: LinkEnd, b: LinkEnd, inv: Inventory | None = None) -> str:
    return link_id(kind, end_to_dict(a, _platform(inv, a)), end_to_dict(b, _platform(inv, b)))


def _platform(inv: Inventory | None, end: LinkEnd) -> str | None:
    if inv is None or not end.device:
        return None
    dev = inv.devices.get(end.device)
    return dev.platform if dev else None


def ends_agree(x: LinkEnd, y: LinkEnd, inv: Inventory | None = None) -> bool:
    """Same kind and every field set on both is equal (interfaces normalised)."""
    if x.kind != y.kind:
        return False
    dx, dy = end_to_dict(x, _platform(inv, x)), end_to_dict(y, _platform(inv, y))
    fx, fy = _flatten(dx), _flatten(dy)
    for k in fx.keys() & fy.keys():
        a, b = fx[k], fy[k]
        if k == "interface":
            a, b = a.lower(), b.lower()
        if a != b:
            return False
    return True


def _flatten(d: dict[str, Any], prefix: str = "") -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out.update(_flatten(v, f"{prefix}{k}."))
        else:
            out[f"{prefix}{k}"] = str(v)
    return out


# ---- JSON (store) -------------------------------------------------------------------

def link_to_dict(link: Link) -> dict[str, Any]:
    return {"id": link.id, "name": link.name, "kind": link.kind, "origin": link.origin, "oper": link.oper,
            "a": end_to_dict(link.a), "b": end_to_dict(link.b),
            "provenance": [p.to_dict() for p in link.provenance],
            "first_seen": link.first_seen, "last_confirmed": link.last_confirmed,
            "absent_since": link.absent_since, "conflicts": list(link.conflicts)}


def _str(raw: dict[str, Any], key: str, *, token: bool = True, required: bool = False) -> str | None:
    v = raw.get(key)
    if v is None:
        if required:
            raise ValueError(f"{key} is required")
        return None
    if not isinstance(v, str) or not v or len(v) > 128:
        raise ValueError(f"{key} must be a short string")
    if token and not is_token(v):
        raise ValueError(f"{key} has unsafe characters")
    if clean_text(v) != v:
        raise ValueError(f"{key} has control characters")
    return v


def _keys(raw: Any, allowed: set[str], where: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError(f"{where} must be an object")
    extra = set(raw) - allowed
    if extra:
        raise ValueError(f"{where}: unknown key(s) {sorted(map(str, extra))}")
    return raw


def end_from_dict(raw: Any, inv: Inventory) -> LinkEnd:
    raw = _keys(raw, {"device", "interface", "next_hop", "aws", "prisma_access", "external"}, "end")
    end = LinkEnd()
    if "device" in raw:
        end.device = _str(raw, "device", required=True)
        if end.device not in inv.devices:
            raise ValueError(f"device {end.device!r} is not in the inventory")
        end.interface = _str(raw, "interface")
        nh = _str(raw, "next_hop")
        if nh is not None:
            end.next_hop = str(ipaddress.ip_address(nh))
    elif "aws" in raw:
        aws = _keys(raw["aws"], {"tgw_attachment", "vgw", "account", "region"}, "aws")
        end.aws_tgw_attachment = _str(aws, "tgw_attachment")
        end.aws_vgw = _str(aws, "vgw")
        end.aws_account = _str(aws, "account")
        end.aws_region = _str(aws, "region")
    elif "prisma_access" in raw:
        pa = _keys(raw["prisma_access"], {"service_connection"}, "prisma_access")
        end.prisma_service_connection = _str(pa, "service_connection", token=False, required=True)
    elif "external" in raw:
        end.external = _str(raw, "external", token=False, required=True)
    if end.kind == "unknown" or (len(raw) > 1 and not end.device):
        raise ValueError("end must name exactly one of device, aws, prisma_access, external")
    return end


def _time(v: Any, key: str, *, optional: bool = False) -> float | None:
    if v is None and optional:
        return None
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0:
        raise ValueError(f"{key} must be a non-negative number")
    return float(v)


def provenance_from_dict(raw: Any) -> Provenance:
    raw = _keys(raw, {"source", "subject", "observed_at", "run_id", "digest"}, "provenance")
    for k in ("source", "subject", "run_id", "digest"):
        _str(raw, k, token=False, required=True)
    return Provenance(source=raw["source"], subject=raw["subject"],
                      observed_at=_time(raw.get("observed_at"), "observed_at") or 0.0,
                      run_id=raw["run_id"], digest=raw["digest"])


_LINK_KEYS = {"id", "name", "kind", "origin", "oper", "a", "b", "provenance", "first_seen", "last_confirmed",
              "absent_since", "conflicts"}


def link_from_dict(raw: Any, inv: Inventory) -> Link:
    raw = _keys(raw, _LINK_KEYS, "link")
    origin, kind, oper = raw.get("origin"), raw.get("kind"), raw.get("oper", "unknown")
    if origin not in ORIGINS or kind not in LINK_KINDS or oper not in OPER:
        raise ValueError("bad origin, kind or oper")
    prov = raw.get("provenance") or []
    conflicts = raw.get("conflicts") or []
    if not isinstance(prov, list) or not isinstance(conflicts, list) or len(prov) > 50 or len(conflicts) > 50:
        raise ValueError("provenance and conflicts must be short lists")
    for c in conflicts:
        if not isinstance(c, str) or not c or len(c) > 160 or clean_text(c, 160) != c:
            raise ValueError("conflict entries must be link ids or declared:<name>")
    return Link(
        name=_str(raw, "name", token=False, required=True) or "",
        a=end_from_dict(raw.get("a"), inv), b=end_from_dict(raw.get("b"), inv),
        origin=origin, kind=kind, oper=oper,
        id=_str(raw, "id", required=True) or "",
        provenance=tuple(provenance_from_dict(p) for p in prov),
        first_seen=_time(raw.get("first_seen", 0.0), "first_seen") or 0.0,
        last_confirmed=_time(raw.get("last_confirmed", 0.0), "last_confirmed") or 0.0,
        absent_since=_time(raw.get("absent_since"), "absent_since", optional=True),
        conflicts=tuple(conflicts),
    )
