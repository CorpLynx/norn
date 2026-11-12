"""Parsers: one answered request (text, XML element or JSON) -> Observations. Pure: they send nothing.

Every parser treats its input as untrusted (docs/discovery-spec.md section 3, rule 7): names are cleaned and
capped, addresses are only kept if they parse, and anything it cannot read raises DeviceError (never "no rows").
`row_cap` bounds every table; more rows is a DeviceError too.

The formats are unverified on real equipment (V20 to V23 in docs/gaps-and-roadmap.md).
"""

from __future__ import annotations

from collections.abc import Callable

from nettrace.discovery.model import Provenance, digest
from nettrace.errors import DeviceError

DEFAULT_ROW_CAP = 2000

ProvFactory = Callable[[str, object], Provenance]


def check_rows(n: int, row_cap: int, what: str) -> None:
    if n > row_cap:
        raise DeviceError(f"{what}: {n} rows is more than the crawl row cap ({row_cap})")


def provenance_factory(subject: str, run_id: str, now: float) -> ProvFactory:
    """prov(source, fragment): provenance for one parsed fragment. Only its digest is kept, never the raw output."""
    def make(source: str, fragment: object) -> Provenance:
        return Provenance(source=source, subject=subject, observed_at=now, run_id=run_id, digest=digest(fragment))
    return make
