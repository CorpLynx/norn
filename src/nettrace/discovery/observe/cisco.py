"""IOS-XE tunnel facts: `show ip interface brief`, `show interfaces Tunnel<n>`, `show crypto session`.

Assumed formats (V20, unverified):

    show interfaces Tunnel100
    Tunnel100 is up, line protocol is up
      Tunnel source 203.0.113.1 (GigabitEthernet1), destination 52.0.0.1
      Tunnel protocol/transport IPSEC/IP          (or GRE/IP)
      Tunnel protection via IPSec (profile "aws")  (optional)

    show crypto session
    Interface: Tunnel100
    Profile: aws
    Session status: UP-ACTIVE
    Peer: 52.0.0.1 port 500
      IKEv2 SA: local 203.0.113.1/500 remote 52.0.0.1/500 Active
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from nettrace.discovery.model import TunnelEnd, clean_text, is_token, join_ip, normalise_interface
from nettrace.discovery.observe import DEFAULT_ROW_CAP, ProvFactory, check_rows
from nettrace.errors import DeviceError

_CLI_ERROR = re.compile(r"^\s*% ", re.M)


def _check_cli(text: str, what: str) -> str:
    if not isinstance(text, str):
        raise DeviceError(f"{what}: no text output")
    if _CLI_ERROR.search(text):
        raise DeviceError(f"{what}: the device rejected the command: {clean_text(text.strip().splitlines()[0])!r}")
    return text


# ---- show ip interface brief ----------------------------------------------------------

_BRIEF_ROW = re.compile(r"^(?P<intf>\S+)\s+(?P<ip>\S+)\s+(?P<ok>YES|NO)\s+(?P<method>\S+)\s+"
                        r"(?P<status>administratively down|up|down|deleted)\s+(?P<proto>up|down)\s*$", re.I)


def tunnel_names(text: str, row_cap: int = DEFAULT_ROW_CAP) -> list[str]:
    """Tunnel interfaces from `show ip interface brief`, as `Tunnel<n>`. Raises DeviceError on an unreadable row."""
    _check_cli(text, "show ip interface brief")
    rows = [ln for ln in text.splitlines() if ln.strip()]
    if rows and rows[0].lower().startswith("interface"):
        rows = rows[1:]
    check_rows(len(rows), row_cap, "show ip interface brief")
    out = []
    for ln in rows:
        m = _BRIEF_ROW.match(ln.strip())
        if not m:
            raise DeviceError(f"show ip interface brief: unreadable row {clean_text(ln)!r}")
        name = normalise_interface(m.group("intf"), "cisco_iosxe")
        if re.fullmatch(r"Tunnel\d{1,10}", name):
            out.append(name)
    return out


# ---- show interfaces Tunnel<n> ----------------------------------------------------------

_HEAD = re.compile(r"^(?P<intf>\S+) is (?P<status>administratively down|up|down|deleted), "
                   r"line protocol is (?P<proto>up|down)", re.I | re.M)
_SOURCE = re.compile(r"^\s*Tunnel source (?P<src>\S+)(?: \((?P<srcif>[^)]*)\))?, destination (?P<dst>\S+)", re.I | re.M)
_TRANSPORT = re.compile(r"^\s*Tunnel protocol/transport (?P<proto>\S+)", re.I | re.M)
_PROTECTION = re.compile(r"^\s*Tunnel protection via IPSec", re.I | re.M)


@dataclass(frozen=True)
class TunnelDetail:
    interface: str
    up: bool
    source: str | None
    destination: str | None
    kind: str  # ipsec | gre


def parse_tunnel(text: str, expect: str) -> TunnelDetail:
    what = f"show interfaces {expect}"
    _check_cli(text, what)
    head = _HEAD.search(text)
    if not head:
        raise DeviceError(f"{what}: no '<name> is <state>, line protocol is <state>' line")
    name = normalise_interface(head.group("intf"), "cisco_iosxe")
    if name != expect:
        raise DeviceError(f"{what}: answer is for {clean_text(head.group('intf'))!r}")
    src = _SOURCE.search(text)
    if not src:
        raise DeviceError(f"{what}: no 'Tunnel source ..., destination ...' line")
    transport = _TRANSPORT.search(text)
    if not transport:
        raise DeviceError(f"{what}: no 'Tunnel protocol/transport' line")
    proto = transport.group("proto").upper()
    kind = "ipsec" if proto.startswith("IPSEC") or _PROTECTION.search(text) else "gre" if proto.startswith("GRE") else ""
    if not kind:
        raise DeviceError(f"{what}: tunnel transport {clean_text(proto)!r} is not IPsec or GRE")
    up = head.group("status").lower() == "up" and head.group("proto").lower() == "up"
    return TunnelDetail(name, up, join_ip(src.group("src")), join_ip(src.group("dst")), kind)


# ---- show crypto session -------------------------------------------------------------------

_SESSION_INTF = re.compile(r"^Interface:\s*(?P<intf>\S+)\s*$", re.I)
_SESSION_STATUS = re.compile(r"^Session status:\s*(?P<status>\S+)", re.I)
_SESSION_PEER = re.compile(r"^Peer:\s*(?P<peer>\S+)", re.I)
_SESSION_LOCAL = re.compile(r"\bSA:\s*local\s+(?P<local>[\d.]+)", re.I)


@dataclass(frozen=True)
class CryptoSession:
    interface: str
    status: str  # up | down | unknown
    peer: str | None
    local: str | None


def parse_crypto_sessions(text: str, row_cap: int = DEFAULT_ROW_CAP) -> dict[str, CryptoSession]:
    """{interface: session}. Empty output means no sessions; any other text without sessions is a DeviceError."""
    _check_cli(text, "show crypto session")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    blocks: list[list[str]] = []
    for ln in lines:
        if _SESSION_INTF.match(ln):
            blocks.append([ln])
        elif blocks:
            blocks[-1].append(ln)
        elif not ln.lower().startswith(("crypto session current status", "code:", "s - ", "-")):
            raise DeviceError(f"show crypto session: unreadable line {clean_text(ln)!r}")
    check_rows(len(blocks), row_cap, "show crypto session")
    out: dict[str, CryptoSession] = {}
    for block in blocks:
        name = normalise_interface(_SESSION_INTF.match(block[0]).group("intf"), "cisco_iosxe")  # type: ignore[union-attr]
        status, peer, local = "unknown", None, None
        for ln in block[1:]:
            if (m := _SESSION_STATUS.match(ln)):
                s = m.group("status").upper()
                status = "up" if s.startswith("UP-ACTIVE") else "down" if s.startswith("DOWN") else "unknown"
            elif (m := _SESSION_PEER.match(ln)) and peer is None:
                peer = join_ip(m.group("peer"))
            elif (m := _SESSION_LOCAL.search(ln)) and local is None:
                local = join_ip(m.group("local"))
        if name in out:  # several peers on one interface: never pick one
            status, peer, local = "unknown", None, None
        out[name] = CryptoSession(name, status, peer, local)
    return out


# ---- combine -------------------------------------------------------------------------------

def tunnel_ends(device: str, details: list[TunnelDetail], sessions: dict[str, CryptoSession],
                prov: ProvFactory) -> list[TunnelEnd]:
    """One TunnelEnd per tunnel. `prov(source, fragment)` builds the provenance for that fragment.

    oper: down when the interface is down or its IPsec session is down; up when the interface is up and (for IPsec)
    its session is UP-ACTIVE; otherwise unknown (an IPsec tunnel with no session line is not concluded up)."""
    out = []
    for d in details:
        if not is_token(d.interface):
            raise DeviceError(f"{device}: unsafe tunnel interface name {clean_text(d.interface)!r}")
        s = sessions.get(d.interface)
        if not d.up or (s and s.status == "down"):
            oper = "down"
        elif d.kind == "gre" or (s and s.status == "up"):
            oper = "up"
        else:
            oper = "unknown"
        local = d.source or (s.local if s else None)
        peer = d.destination or (s.peer if s else None)
        fragment = {"interface": d.interface, "up": d.up, "source": d.source, "destination": d.destination,
                    "kind": d.kind, "session": None if s is None else [s.status, s.peer, s.local]}
        source = "cisco:show interfaces Tunnel" + ("+show crypto session" if s else "")
        out.append(TunnelEnd(device, d.interface, local, peer, d.kind, oper, prov(source, fragment)))
    return out
