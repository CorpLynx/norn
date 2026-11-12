"""topology.json: learned links, the last crawl runs and neighbour candidates (docs/discovery-spec.md 7.3).

The file is untrusted on load. Any failed check means the whole file is ignored with a warning and the store is
treated as empty; it is never partly used. Writes are atomic (temp file 0600, os.replace) under the same advisory
lock pattern as the address cache, and neither the file nor its directory is followed through a symlink.
"""

from __future__ import annotations

import errno
import json
import os
import secrets
import stat
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from nettrace.discovery.links import _keys, _str, _time, link_from_dict, link_to_dict
from nettrace.discovery.model import Candidate, join_ip
from nettrace.inventory import Inventory, Link, _cache_lock, cache_dir

SCHEMA = 1
MAX_BYTES = 5 * 1024 * 1024
MAX_LINKS = 5000
MAX_CANDIDATES = 5000
KEEP_RUNS = 5


@dataclass
class RunRecord:
    id: str
    started: float
    ended: float
    subjects_ok: list[str] = field(default_factory=list)
    subjects_failed: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "started": self.started, "ended": self.ended,
                "subjects_ok": list(self.subjects_ok), "subjects_failed": dict(self.subjects_failed)}


@dataclass
class StoreState:
    runs: list[RunRecord] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"schema": SCHEMA, "runs": [r.to_dict() for r in self.runs[-KEEP_RUNS:]],
                "links": [link_to_dict(lk) for lk in self.links],
                "candidates": [c.to_dict() for c in self.candidates]}


class StoreError(ValueError):
    pass


def default_path() -> Path:
    return cache_dir() / "topology.json"


def _run_from_dict(raw: Any) -> RunRecord:
    raw = _keys(raw, {"id", "started", "ended", "subjects_ok", "subjects_failed"}, "run")
    ok, failed = raw.get("subjects_ok") or [], raw.get("subjects_failed") or {}
    if not isinstance(ok, list) or not isinstance(failed, dict) or len(ok) > 10000 or len(failed) > 10000:
        raise StoreError("run subjects must be a list and an object")
    for s in ok:
        _str({"s": s}, "s", token=False, required=True)
    for s, why in failed.items():
        _str({"s": s}, "s", token=False, required=True)
        _str({"r": why}, "r", token=False, required=True)
    return RunRecord(id=_str(raw, "id", required=True) or "", started=_time(raw.get("started"), "started") or 0.0,
                     ended=_time(raw.get("ended"), "ended") or 0.0, subjects_ok=list(ok), subjects_failed=dict(failed))


def _candidate_from_dict(raw: Any, inv: Inventory) -> Candidate:
    raw = _keys(raw, {"seen_by", "address", "note"}, "candidate")
    seen_by = _str(raw, "seen_by", token=False, required=True) or ""
    if seen_by not in inv.devices and not seen_by.startswith(("aws:", "scm", "panorama")):
        raise StoreError(f"candidate seen_by {seen_by!r} is not an inventory subject")
    address = _str(raw, "address", required=True) or ""
    if join_ip(address) != address:
        raise StoreError(f"candidate address {address!r} is not a usable IPv4 address")
    return Candidate(seen_by=seen_by, address=address, note=_str(raw, "note", token=False) or "")


def parse_state(raw: Any, inv: Inventory) -> StoreState:
    """Validate a decoded store document against the inventory. Raises StoreError/ValueError on any problem."""
    raw = _keys(raw, {"schema", "runs", "links", "candidates"}, "store")
    if raw.get("schema") != SCHEMA or isinstance(raw.get("schema"), bool):
        raise StoreError(f"schema must be {SCHEMA}")
    runs, links, cands = raw.get("runs") or [], raw.get("links") or [], raw.get("candidates") or []
    if not all(isinstance(x, list) for x in (runs, links, cands)):
        raise StoreError("runs, links and candidates must be lists")
    if len(links) > MAX_LINKS or len(cands) > MAX_CANDIDATES:
        raise StoreError(f"more than {MAX_LINKS} links or {MAX_CANDIDATES} candidates")
    state = StoreState(runs=[_run_from_dict(r) for r in runs][-KEEP_RUNS:],
                       links=[link_from_dict(lk, inv) for lk in links],
                       candidates=[_candidate_from_dict(c, inv) for c in cands])
    ids = [lk.id for lk in state.links if lk.origin != "declared"]
    if len(ids) != len(set(ids)):
        raise StoreError("duplicate link id")
    return state


class TopologyStore:
    def __init__(self, inv: Inventory, path: Path | None = None) -> None:
        self.inv = inv
        self.path = path or default_path()

    def _dir_ok(self) -> bool:
        return not self.path.parent.is_symlink()

    def load(self) -> StoreState:
        """The stored state, or an empty one. A missing file is silent; anything else unusable warns."""
        def ignore(why: str) -> StoreState:
            warnings.warn(f"topology store {self.path}: {why}; ignoring it", stacklevel=2)
            return StoreState()

        if not self._dir_ok():
            return ignore("its directory is a symlink")
        try:
            fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            return StoreState()
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                return ignore("it is a symlink")
            return ignore(f"unreadable ({exc.strerror})")
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return ignore("not a regular file")
            if st.st_size > MAX_BYTES:
                return ignore(f"larger than {MAX_BYTES} bytes")
            with os.fdopen(fd, "rb") as fh:
                fd = -1
                data = fh.read(MAX_BYTES + 1)
        finally:
            if fd >= 0:
                os.close(fd)
        if len(data) > MAX_BYTES:
            return ignore(f"larger than {MAX_BYTES} bytes")
        try:
            return parse_state(json.loads(data), self.inv)
        except (ValueError, TypeError, RecursionError) as exc:
            return ignore(f"invalid ({str(exc)[:200]})")

    def save(self, state: StoreState) -> Path:
        path = self.path
        if path.parent.is_symlink():
            raise OSError(f"topology store directory {path.parent} is a symlink; refusing to follow it")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        body = json.dumps(state.to_dict(), indent=2, sort_keys=True)
        with _cache_lock(path):
            tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                with os.fdopen(fd, "w") as fh:
                    fh.write(body)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, path)  # replaces a symlink itself, never writes through it
            except BaseException:
                tmp.unlink(missing_ok=True)
                raise
        return path

    def clear(self) -> bool:
        """Delete topology.json only. True if a file was removed."""
        try:
            self.path.unlink()
            return True
        except FileNotFoundError:
            return False
