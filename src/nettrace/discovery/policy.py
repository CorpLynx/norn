"""The inventory's optional `topology:` section (docs/discovery-spec.md section 7.4)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from nettrace.errors import InventoryError


@dataclass(frozen=True)
class CrawlLimits:
    timeout: float = 600.0
    max_devices: int = 200
    device_sessions: int = 4
    command_gap: float = 1.0
    device_seconds: float = 60.0
    device_commands: int = 40
    row_cap: int = 2000
    aws_concurrency: int = 8
    cooldown: float = 900.0


@dataclass(frozen=True)
class TopologyPolicy:
    use_learned: bool = True
    ttl_fresh: float = 3600.0
    ttl_max: float = 86400.0
    crawl: CrawlLimits = field(default_factory=CrawlLimits)


# key -> (min, max, integer?)
_TOP = {"ttl_fresh": (60, 30 * 86400, False), "ttl_max": (60, 30 * 86400, False)}
_CRAWL = {
    "timeout": (10, 7200, False),
    "max_devices": (1, 5000, True),
    "device_sessions": (1, 32, True),
    "command_gap": (0.5, 60, False),
    "aws_concurrency": (1, 32, True),
    "row_cap": (10, 20000, True),
    "cooldown": (0, 86400, False),
}
_BUDGET = {"seconds": (5, 3600, False), "commands": (1, 500, True)}


def _number(value: Any, where: str, lo: float, hi: float, integer: bool) -> float | int:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or (integer and not isinstance(value, int)):
        raise InventoryError(f"{where} must be {'an integer' if integer else 'a number'}")
    if not lo <= value <= hi:
        raise InventoryError(f"{where} must be between {lo} and {hi}")
    return value


def _mapping(raw: Any, where: str, allowed: set[str]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise InventoryError(f"{where} must be a mapping")
    unknown = sorted(set(map(str, raw)) - allowed)
    if unknown:
        raise InventoryError(f"{where}: unknown key(s) {', '.join(unknown)}")
    return raw


def parse_topology(raw: Any) -> TopologyPolicy | None:
    """None when the section is absent: then no store is read and traces use declared links only."""
    if raw is None:
        return None
    top = _mapping(raw, "topology", {"use_learned", "crawl", *_TOP})
    use_learned = top.get("use_learned", True)
    if not isinstance(use_learned, bool):
        raise InventoryError("topology.use_learned must be true or false")
    ttl = {k: float(_number(top[k], f"topology.{k}", *_TOP[k])) for k in _TOP if k in top}
    defaults = TopologyPolicy()
    ttl_fresh = ttl.get("ttl_fresh", defaults.ttl_fresh)
    ttl_max = ttl.get("ttl_max", defaults.ttl_max)
    if ttl_fresh > ttl_max:
        raise InventoryError("topology.ttl_fresh must not be larger than topology.ttl_max")

    limits: dict[str, Any] = {}
    if top.get("crawl") is not None:
        crawl = _mapping(top["crawl"], "topology.crawl", {"device_budget", *_CRAWL})
        for k, rule in _CRAWL.items():
            if k in crawl:
                limits[k] = _number(crawl[k], f"topology.crawl.{k}", *rule)
        if crawl.get("device_budget") is not None:
            budget = _mapping(crawl["device_budget"], "topology.crawl.device_budget", set(_BUDGET))
            if "seconds" in budget:
                limits["device_seconds"] = _number(budget["seconds"], "topology.crawl.device_budget.seconds",
                                                   *_BUDGET["seconds"])
            if "commands" in budget:
                limits["device_commands"] = _number(budget["commands"], "topology.crawl.device_budget.commands",
                                                    *_BUDGET["commands"])
    for k in ("timeout", "command_gap", "device_seconds", "cooldown"):
        if k in limits:
            limits[k] = float(limits[k])
    return TopologyPolicy(use_learned=use_learned, ttl_fresh=ttl_fresh, ttl_max=ttl_max, crawl=CrawlLimits(**limits))
