"""Candidate links + declared links + previous store -> new store state (docs/discovery-spec.md section 10).

Pure: no I/O; the clock is an argument. Rules, in order:
1. A declared link that names an end of a candidate wins. Agreeing candidates confirm it (a `declared` record keyed by
   the declared link's name); a disagreeing one gives it `conflicts` and is stored, never used.
2. Otherwise the candidate is stored with its own origin.
3. A stored link not seen this run is marked absent only if every subject behind it answered this run; on the
   second such run it is removed. If any of its subjects did not answer, it is left untouched (rule 5 of section 3:
   a failed query is not evidence of absence).
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from nettrace.discovery.join import JoinResult
from nettrace.discovery.links import end_key, ends_agree
from nettrace.discovery.store import KEEP_RUNS, RunRecord, StoreState
from nettrace.inventory import Inventory, Link, LinkEnd


@dataclass
class MergeReport:
    new: list[str] = field(default_factory=list)          # link ids
    changed: list[str] = field(default_factory=list)      # link ids whose origin, oper or conflicts changed
    confirmed: list[str] = field(default_factory=list)    # declared link names a candidate agreed with
    declared_conflicts: list[str] = field(default_factory=list)  # declared link names a candidate disagreed with
    absent: list[str] = field(default_factory=list)       # ids marked absent this run
    removed: list[str] = field(default_factory=list)      # ids removed (absent twice)


def _platform(inv: Inventory, end: LinkEnd) -> str | None:
    dev = inv.devices.get(end.device or "")
    return dev.platform if dev else None


def _same_end(declared: LinkEnd, cand: LinkEnd, inv: Inventory) -> bool:
    """A declared end names a candidate end. A declared device end with no interface (next_hop only) names none."""
    if declared.device and not declared.interface:
        return False
    return end_key(declared, _platform(inv, declared)) == end_key(cand, _platform(inv, cand))


def _declared_match(cand: Link, inv: Inventory) -> tuple[Link, bool] | None:
    """(declared link, agrees) for the first declared link naming an end of `cand`."""
    for d in inv.links:
        if d.origin != "declared":
            continue
        for dh, dt in ((d.a, d.b), (d.b, d.a)):
            for ch, ct in ((cand.a, cand.b), (cand.b, cand.a)):
                if _same_end(dh, ch, inv):
                    return d, ends_agree(dt, ct, inv)
    return None


def _subjects(link: Link) -> set[str]:
    return {p.subject for p in link.provenance}


def merge(found: JoinResult, inv: Inventory, previous: StoreState, run: RunRecord, now: float) -> tuple[StoreState, MergeReport]:
    report = MergeReport()
    answered = set(run.subjects_ok) - set(run.subjects_failed)
    prev_learned = {lk.id: lk for lk in previous.links if lk.origin != "declared"}
    prev_declared = {lk.name: lk for lk in previous.links if lk.origin == "declared"}
    declared_names = {d.name for d in inv.links if d.origin == "declared"}

    out: dict[str, Link] = {}
    decl: dict[str, Link] = {}
    for c in found.links:
        hit = _declared_match(c, inv)
        if hit:
            d, agrees = hit
            rec = decl.get(d.name) or Link(
                name=d.name, a=d.a, b=d.b, origin="declared", kind=c.kind, oper=c.oper, id=c.id,
                first_seen=prev_declared[d.name].first_seen if d.name in prev_declared else c.first_seen,
                last_confirmed=0.0)
            if agrees:
                rec = replace(rec, oper=c.oper, provenance=tuple(dict.fromkeys(rec.provenance + c.provenance)),
                              last_confirmed=max(rec.last_confirmed, c.last_confirmed))
                if d.name not in report.confirmed:
                    report.confirmed.append(d.name)
            else:
                rec = replace(rec, conflicts=tuple(sorted(set(rec.conflicts) | {c.id})),
                              provenance=tuple(dict.fromkeys(rec.provenance + c.provenance)))
                c = replace(c, conflicts=tuple(sorted(set(c.conflicts) | {f"declared:{d.name}"})))
                if d.name not in report.declared_conflicts:
                    report.declared_conflicts.append(d.name)
            decl[d.name] = rec
            if agrees:
                continue
        prev = prev_learned.get(c.id)
        if prev:
            c = replace(c, first_seen=min(prev.first_seen, c.first_seen) if prev.first_seen else c.first_seen)
            if (prev.origin, prev.oper, prev.conflicts) != (c.origin, c.oper, c.conflicts):
                report.changed.append(c.id)
        else:
            report.new.append(c.id)
        out[c.id] = replace(c, absent_since=None)

    def carry(old: Link) -> Link | None:
        subjects = _subjects(old)
        if not subjects or not subjects <= answered:
            return old  # someone behind it did not answer: no conclusion
        if old.absent_since is None:
            report.absent.append(old.id or old.name)
            return replace(old, absent_since=now)
        report.removed.append(old.id or old.name)
        return None

    for lid, old in prev_learned.items():
        if lid not in out and (kept := carry(old)) is not None:
            out[lid] = kept
    for name, old in prev_declared.items():
        if name in decl or name not in declared_names:
            continue
        if (kept := carry(old)) is not None:
            decl[name] = kept

    kept_candidates = [c for c in previous.candidates if c.seen_by not in answered]
    seen = {(c.seen_by, c.address) for c in found.candidates}
    candidates = list(found.candidates) + [c for c in kept_candidates if (c.seen_by, c.address) not in seen]

    state = StoreState(
        runs=(previous.runs + [run])[-KEEP_RUNS:],
        links=sorted(decl.values(), key=lambda lk: lk.name) + sorted(out.values(), key=lambda lk: lk.id),
        candidates=sorted(candidates, key=lambda c: (c.seen_by, c.address)),
    )
    return state, report
