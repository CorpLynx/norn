"""PAN-OS and Panorama facts: `<show><vpn><flow>` (C4) and `<show><devices><all>` (C11).

Input is the parsed `<response>` element that `PanosClient.request` / `PanoramaClient` return (defusedxml).

Assumed formats (V21, unverified; tag names from pan-os-python and the PAN-OS CLI reference):

    <response status="success"><result>
      <IPSec><entry><name>aws-tun1</name><inner-if>tunnel.1</inner-if><outer-if>ethernet1/1</outer-if>
             <localip>203.0.113.1</localip><peerip>52.0.0.1</peerip><state>active</state></entry></IPSec>
    </result></response>

    <response status="success"><result><devices>
      <entry name="0071..."><serial>0071...</serial><hostname>fw-dc1</hostname><ip-address>10.0.0.3</ip-address>
             <model>PA-3220</model><connected>yes</connected><ha><state>active</state><peer><serial>0072...</serial>
             </peer></ha></entry>
    </devices></result></response>
"""

from __future__ import annotations

import re
from typing import Any

from nettrace.discovery.model import ManagedFirewall, TunnelEnd, clean_text, is_token, join_ip, normalise_interface
from nettrace.discovery.observe import DEFAULT_ROW_CAP, ProvFactory, check_rows
from nettrace.errors import DeviceError


def _result(root: Any, what: str) -> Any:
    if root is None or getattr(root, "tag", None) != "response":
        raise DeviceError(f"{what}: not a PAN-OS <response>")
    if root.get("status") != "success":
        raise DeviceError(f"{what}: status={clean_text(root.get('status'))!r}")
    result = root.find("result")
    if result is None:
        raise DeviceError(f"{what}: no <result>")
    return result


def _text(el: Any, tag: str) -> str:
    return clean_text(el.findtext(tag) or "")


def vpn_flows(device: str, root: Any, prov: ProvFactory, row_cap: int = DEFAULT_ROW_CAP) -> list[TunnelEnd]:
    """One TunnelEnd per IPsec flow. A `<result>` with no `<IPSec>` element and no `<total>` is unreadable."""
    what = "show vpn flow"
    result = _result(root, what)
    entries = result.findall("./IPSec/entry")
    if not entries and result.find("IPSec") is None and result.find("total") is None:
        raise DeviceError(f"{what}: no <IPSec> or <total> in the answer")
    check_rows(len(entries), row_cap, what)
    out = []
    for e in entries:
        intf = normalise_interface(_text(e, "inner-if"), "panos")
        if not re.fullmatch(r"tunnel(\.\d{1,10})?", intf) or not is_token(intf):
            raise DeviceError(f"{what}: unexpected tunnel interface {intf!r}")
        state = _text(e, "state").lower()
        oper = "up" if state == "active" else "down" if state in ("init", "inactive", "down") else "unknown"
        local, peer = join_ip(_text(e, "localip")), join_ip(_text(e, "peerip"))
        fragment = {"name": _text(e, "name"), "interface": intf, "local": local, "peer": peer, "state": state}
        out.append(TunnelEnd(device, intf, local, peer, "ipsec", oper, prov("panos:show vpn flow", fragment)))
    return out


_SERIAL = re.compile(r"[A-Za-z0-9]{1,32}")


def managed_firewalls(root: Any, prov: ProvFactory, row_cap: int = DEFAULT_ROW_CAP) -> list[ManagedFirewall]:
    what = "show devices all"
    result = _result(root, what)
    devices = result.find("devices")
    if devices is None:
        raise DeviceError(f"{what}: no <devices>")
    entries = devices.findall("entry")
    check_rows(len(entries), row_cap, what)
    out = []
    for e in entries:
        serial = _text(e, "serial") or clean_text(e.get("name"))
        if not _SERIAL.fullmatch(serial):
            raise DeviceError(f"{what}: unexpected serial {serial!r}")
        peer = _text(e, "ha/peer/serial") or None
        if peer and not _SERIAL.fullmatch(peer):
            peer = None
        fw = {"serial": serial, "hostname": _text(e, "hostname"), "mgmt_ip": join_ip(_text(e, "ip-address")),
              "model": _text(e, "model"), "connected": _text(e, "connected").lower() == "yes", "ha_peer_serial": peer}
        out.append(ManagedFirewall(**fw, prov=prov("panorama:show devices all", fw)))  # type: ignore[arg-type]
    return out
