"""Observations, provenance, link ids and the text hygiene every device-supplied value goes through.

Pure: no I/O, no imports from the rest of nettrace except netutil-free stdlib, so `inventory.py` can use the
interface normalisation without an import cycle.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Union

ORIGINS = ("declared", "learned", "inferred")
LINK_KINDS = ("ipsec", "gre", "aws-vpn", "prisma", "unknown")
OPER = ("up", "down", "unknown")

TEXT_CAP = 128  # characters kept from any device-supplied name

# ---- text hygiene --------------------------------------------------------------


def clean_text(value: object, cap: int = TEXT_CAP) -> str:
    """Device text is untrusted: drop control and format characters (Cc, Cf, line/paragraph separators), cap length."""
    s = "" if value is None else str(value)
    s = "".join(ch for ch in s if unicodedata.category(ch) not in ("Cc", "Cf", "Zl", "Zp"))
    return s.strip()[:cap]


_TOKEN = re.compile(r"[A-Za-z0-9._:/\-]{1,128}")


def is_token(value: object) -> bool:
    """Same character set as readonly.safe_token, without raising."""
    return isinstance(value, str) and bool(_TOKEN.fullmatch(value))


_NEVER_KEYS = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("0.0.0.0/32"),
    ipaddress.ip_network("255.255.255.255/32"),
)


def join_ip(value: object) -> str | None:
    """Canonical IPv4 string usable as a join key, or None (unparseable, IPv6, link-local, loopback, multicast, 0.0.0.0)."""
    if not isinstance(value, str):
        return None
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if ip.version != 4 or any(ip in net for net in _NEVER_KEYS):
        return None
    return str(ip)


# ---- interface names -------------------------------------------------------------

# IOS-XE accepts any unique prefix of these. Matching is case-insensitive.
CISCO_INTERFACES = (
    "AppGigabitEthernet", "BDI", "Cellular", "Dialer", "Ethernet", "FastEthernet", "FortyGigabitEthernet",
    "GigabitEthernet", "HundredGigE", "Loopback", "Multilink", "Null", "Port-channel", "Serial",
    "TenGigabitEthernet", "Tunnel", "TwentyFiveGigE", "Virtual-Access", "Virtual-Template", "Vlan",
)
_CISCO_SPLIT = re.compile(r"([A-Za-z][A-Za-z-]*)\s*(\d[\d/.:]*)")


def normalise_interface(name: object, platform: str | None = None) -> str:
    """Canonical interface name for comparisons. Cisco: `Tu100`, `tunnel100`, `Gi 0/0/1` become `Tunnel100`,
    `GigabitEthernet0/0/1`; an ambiguous or unknown prefix is kept as given. PAN-OS and unknown platforms: lower-case."""
    s = clean_text(name, 64)
    if platform != "cisco_iosxe":
        return s.lower()
    m = _CISCO_SPLIT.fullmatch(s)
    if not m:
        return s
    prefix, rest = m.group(1).lower(), m.group(2)
    hits = [full for full in CISCO_INTERFACES if full.lower().startswith(prefix)]
    exact = [full for full in hits if full.lower() == prefix]
    if exact:
        return exact[0] + rest
    if len(hits) == 1:
        return hits[0] + rest
    return s


# ---- provenance and observations ------------------------------------------------


@dataclass(frozen=True)
class Provenance:
    source: str         # "cisco:show crypto session" | "panos:show vpn flow" | "aws:ec2.DescribeVpnConnections" | ...
    subject: str        # inventory device name | "aws:<account>/<region>" | "panorama" | "scm"
    observed_at: float  # local clock; a device's clock is never trusted
    run_id: str         # matches the audit log
    digest: str         # sha256 of the normalised fragment; raw output is not stored

    def to_dict(self) -> dict[str, object]:
        return {"source": self.source, "subject": self.subject, "observed_at": self.observed_at,
                "run_id": self.run_id, "digest": self.digest}


def digest(fragment: object) -> str:
    return hashlib.sha256(json.dumps(fragment, sort_keys=True, default=str).encode()).hexdigest()


@dataclass(frozen=True)
class TunnelEnd:
    """A device's own tunnel interface."""
    device: str
    interface: str
    local_ip: str | None
    peer_ip: str | None
    kind: str  # ipsec | gre
    oper: str  # up | down | unknown
    prov: Provenance


@dataclass(frozen=True)
class AwsVpn:
    """One tunnel of one Site-to-Site VPN connection."""
    account: str
    region: str
    vpn_id: str
    outside_ip: str | None  # AWS side of the tunnel
    cgw_ip: str | None      # customer gateway address
    tgw_id: str | None
    vgw_id: str | None
    tgw_attachment: str | None
    oper: str
    prov: Provenance


@dataclass(frozen=True)
class PrismaTunnel:
    """One Prisma Access service connection or remote network."""
    name: str
    kind: str  # service_connection | remote_network
    peer_ip: str | None  # customer side
    prov: Provenance


@dataclass(frozen=True)
class ManagedFirewall:
    """A firewall as Panorama lists it."""
    serial: str
    hostname: str
    mgmt_ip: str | None
    model: str
    connected: bool
    ha_peer_serial: str | None
    prov: Provenance


@dataclass(frozen=True)
class Unanswered:
    """A query that failed. Its subject's links are never concluded absent from this run."""
    subject: str
    source: str
    reason: str
    prov: Provenance


Observation = Union[TunnelEnd, AwsVpn, PrismaTunnel, ManagedFirewall, Unanswered]


@dataclass(frozen=True)
class Candidate:
    """A neighbour address seen by a subject that is not an inventory object. Recorded, never contacted."""
    seen_by: str
    address: str
    note: str

    def to_dict(self) -> dict[str, str]:
        return {"seen_by": self.seen_by, "address": self.address, "note": self.note}


def link_id(kind: str, end_a: dict[str, object], end_b: dict[str, object]) -> str:
    """Stable id: sha256(kind + the two canonical ends in sorted order), first 16 hex characters."""
    ends = sorted(json.dumps(e, sort_keys=True) for e in (end_a, end_b))
    return hashlib.sha256((kind + "|" + "|".join(ends)).encode()).hexdigest()[:16]
