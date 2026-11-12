"""What the engine asks about links: declared links merged with usable learned ones (docs/discovery-spec.md 11).

Each lookup returns `Found`, `Unusable` or None:
- Found: a declared link, or a learned one that is not expired, not absent, not in conflict and unambiguous.
- Unusable: the only matches are inferred, expired, absent from the last crawl, in conflict, or several different
  far ends. The engine turns this into an UNKNOWN link hop and the trace ends INCOMPLETE (never guess).
- None: nothing known; the engine carries on exactly as today.

Not wired into the engine yet (M3). Pure: the clock is an argument.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Union

from nettrace.discovery.links import end_key, node_of
from nettrace.discovery.policy import TopologyPolicy
from nettrace.discovery.store import StoreState
from nettrace.inventory import Inventory, Link, LinkEnd


@dataclass(frozen=True)
class Found:
    link: Link
    far_end: LinkEnd
    origin: str                     # declared | learned
    freshness: str = "declared"     # declared | fresh | stale
    age_s: float | None = None      # since last confirmed; None for a declared link never confirmed
    oper: str = "unknown"
    sources: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()  # only on a declared link a crawl disagreed with (hop WARN)
    note: str = ""                   # a detail line for the hop, e.g. several tunnels to one device

    def tag(self) -> str:
        """Hop summary suffix: [declared], [declared, confirmed 12m ago], [learned 12m ago] or [learned 3h ago, stale]."""
        if self.origin == "declared":
            return "[declared]" if self.age_s is None else f"[declared, confirmed {_age(self.age_s)} ago]"
        return f"[learned {_age(self.age_s or 0)} ago" + (", stale]" if self.freshness == "stale" else "]")

    def link_field(self) -> dict[str, object]:
        """The optional `link` field of a hop in JSON."""
        d: dict[str, object] = {"origin": self.origin, "oper": self.oper, "sources": list(self.sources)}
        if self.age_s is not None:
            d["age_s"] = int(self.age_s)
        if self.conflicts:
            d["conflicts"] = list(self.conflicts)
        return d


@dataclass(frozen=True)
class Unusable:
    reason: str
    candidates: tuple[Link, ...] = field(default_factory=tuple)


Lookup = Union[Found, Unusable, None]


def _age(seconds: float) -> str:
    s = max(0, int(seconds))
    if s < 3600:
        return f"{max(1, s // 60)}m"
    if s < 2 * 86400:
        return f"{s // 3600}h"
    return f"{s // 86400}d"


class TopologyView:
    def __init__(self, inv: Inventory, state: StoreState | None, now: float, *, use_learned: bool | None = None) -> None:
        self.inv = inv
        self.now = now
        self.policy: TopologyPolicy | None = inv.topology
        enabled = self.policy is not None and self.policy.use_learned
        self.use_learned = enabled if use_learned is None else (use_learned and self.policy is not None)
        state = state or StoreState()
        self._declared_rec = {lk.name: lk for lk in state.links if lk.origin == "declared"}
        self._learned = [lk for lk in state.links if lk.origin != "declared"] if self.use_learned else []

    # ---- the three engine lookups ------------------------------------------------------
    def from_device(self, device: str, interface: str | None, next_hop: str | None) -> Lookup:
        hit = self.inv.link_from_device(device, interface, next_hop)
        if hit:
            return self._declared(*hit)
        if not interface:
            return None
        dev = self.inv.devices.get(device)
        key = end_key(LinkEnd(device=device, interface=interface), dev.platform if dev else None)
        return self._learned_lookup(key)

    def from_aws(self, resource_id: str) -> Lookup:
        hit = self.inv.link_from_aws(resource_id)
        if hit:
            return self._declared(*hit)
        return self._learned_lookup(("aws", resource_id))

    def from_prisma(self, service_connection: str) -> Lookup:
        hit = self.inv.link_from_prisma(service_connection)
        if hit:
            return self._declared(*hit)
        return self._learned_lookup(("prisma", service_connection))

    # ---- internals ----------------------------------------------------------------------
    def _declared(self, link: Link, far: LinkEnd) -> Found:
        rec = self._declared_rec.get(link.name)
        age = self.now - rec.last_confirmed if rec and rec.last_confirmed else None
        return Found(link, far, "declared", "declared", age, rec.oper if rec else "unknown",
                     tuple(dict.fromkeys(p.source for p in rec.provenance)) if rec else (),
                     rec.conflicts if rec else ())

    def _platform(self, end: LinkEnd) -> str | None:
        dev = self.inv.devices.get(end.device or "")
        return dev.platform if dev else None

    def _learned_lookup(self, key: tuple[str, ...]) -> Lookup:
        matches: list[tuple[Link, LinkEnd]] = []
        for lk in self._learned:
            for here, there in ((lk.a, lk.b), (lk.b, lk.a)):
                if end_key(here, self._platform(here)) == key:
                    matches.append((lk, there))
        if not matches:
            return None
        links = tuple(m[0] for m in matches)
        if len({node_of(far) for _, far in matches}) > 1:
            return Unusable("learned links from this end lead to different places: "
                            + ", ".join(sorted(far.label() for _, far in matches)), links)
        for lk, _ in matches:
            if (why := self._unusable(lk)):
                return Unusable(why, links)
        lk, far = matches[0]
        oldest = min(m[0].last_confirmed for m in matches)
        age = self.now - oldest
        assert self.policy is not None
        freshness = "fresh" if age <= self.policy.ttl_fresh else "stale"
        sources = tuple(dict.fromkeys(p.source for m in matches for p in m[0].provenance))
        if len(matches) == 1:
            return Found(lk, far, "learned", freshness, age, lk.oper, sources)
        # Several tunnels to one device (an AWS VPN has two): the device is known, the interface is not. The far end
        # names the device only, so the engine treats the ingress interface as inferred (WARN), never picks one.
        opers = {m[0].oper for m in matches}
        oper = "up" if "up" in opers else "down" if opers == {"down"} else "unknown"
        return Found(lk, LinkEnd(device=far.device), "learned", freshness, age, oper, sources,
                     note=f"{len(matches)} learned tunnels reach {far.device} "
                          f"({', '.join(sorted(m[1].interface or '?' for m in matches))}); ingress interface not known")

    def _unusable(self, lk: Link) -> str | None:
        assert self.policy is not None
        age = self.now - lk.last_confirmed
        if lk.origin != "learned":
            return f"only an inferred link is known ({lk.name}); it is never used to forward a trace"
        if lk.conflicts:
            return f"learned link {lk.name} is in conflict with " + ", ".join(lk.conflicts)
        if lk.absent_since is not None:
            return f"learned link {lk.name} was not seen in the last crawl"
        if age > self.policy.ttl_max:
            return f"learned link {lk.name} is expired (last confirmed {_age(age)} ago); run `nettrace topology crawl`"
        return None
