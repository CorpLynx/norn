"""Rendering: table (rich), json, text. --query applies a JMESPath expression first, like the AWS CLI."""

from __future__ import annotations

import json
import re
from typing import Any

import jmespath
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from nettrace.models import Hop, Outcome, ReturnPath, Status, SymmetryStatus, TraceResult

STATUS_STYLE = {
    Status.PASS: "bold green",
    Status.BLOCK: "bold red",
    Status.WARN: "bold yellow",
    Status.UNKNOWN: "bold magenta",
    Status.INFO: "cyan",
}
OUTCOME_STYLE = {
    Outcome.REACHABLE: "bold white on green",
    Outcome.BLOCKED: "bold white on red",
    Outcome.EXITED: "bold black on cyan",
    Outcome.INCOMPLETE: "bold black on yellow",
}


def emit(console: Console, data: Any, fmt: str, query: str | None = None, *, verbose: bool = False) -> None:
    if isinstance(data, TraceResult) and not query and fmt == "table":
        render_trace(console, data, verbose=verbose)
        return
    plain = data.to_dict() if isinstance(data, TraceResult) else data
    if query:
        plain = jmespath.search(query, plain)
    if fmt == "json":
        console.print_json(json.dumps(plain, default=str))
    elif fmt == "text":
        for line in _text_lines(plain):
            console.print(clean(line), markup=False, highlight=False, soft_wrap=True)
    else:
        render_generic(console, plain)


def _text_lines(data: Any) -> list[str]:
    if isinstance(data, dict) and "Hops" in data and "Outcome" in data:
        lines = [f"OUTCOME\t{_cell(data['Outcome'])}\t{_cell(data['Reason'])}"]
        for h in data["Hops"]:
            lines.append("\t".join(["HOP", _cell(h["index"]), _cell(h["status"]), _cell(h["domain"]), _cell(h["node"]),
                                    _cell(h["component"]), _cell(h.get("ingress") or "-"), _cell(h.get("egress") or "-"),
                                    _cell(h["summary"]), _cell(h.get("policy") or "-")]))
        lines += [f"WARNING\t{_cell(w)}" for w in data.get("Warnings", [])]
        ret = data.get("Return")
        if ret:  # only present with --return; forward-only output is unchanged
            sym = ret.get("Symmetry") or {}
            lines.append(f"RETURN\t{_cell(ret.get('Outcome') or 'NOT_RUN')}\t{_cell(ret.get('Reason'))}")
            for h in ret.get("Hops", []):
                lines.append("\t".join(["RETURN-HOP", _cell(h["index"]), _cell(h["status"]), _cell(h["domain"]),
                                        _cell(h["node"]), _cell(h["component"]), _cell(h.get("ingress") or "-"),
                                        _cell(h.get("egress") or "-"), _cell(h["summary"]), _cell(h.get("policy") or "-")]))
            lines.append(f"SYMMETRY\t{_cell(sym.get('status'))}")
            lines += [f"SYMMETRY-DETAIL\t{_cell(d)}" for d in sym.get("details", [])]
        return lines
    if isinstance(data, list):
        out = []
        for item in data:
            if isinstance(item, dict):
                out.append("\t".join(_scalar(v) for v in item.values()))
            else:
                out.append(_scalar(item))
        return out
    if isinstance(data, dict):
        return [f"{k}\t{_scalar(v)}" for k, v in data.items()]
    return [_scalar(data)]


def _cell(v: Any) -> str:
    """One tab-separated field: control characters removed and no tab/newline that would split the record."""
    return re.sub(r"[\t\n]", " ", clean(str(v)))


def _scalar(v: Any) -> str:
    if v is None:
        return "None"
    if isinstance(v, (dict, list)):
        return json.dumps(v, default=str)
    return str(v)


def render_generic(console: Console, data: Any) -> None:
    if isinstance(data, dict):
        data = [data]
    if isinstance(data, list) and data and all(isinstance(r, dict) for r in data):
        cols: list[str] = []
        for row in data:
            for k in row:
                if k not in cols:
                    cols.append(k)
        table = Table(show_lines=False, header_style="bold")
        for c in cols:
            table.add_column(c, overflow="fold")
        for row in data:
            table.add_row(*[_scalar(row.get(c)) if row.get(c) is not None else "" for c in cols])
        console.print(table)
    else:
        console.print_json(json.dumps(data, default=str))


def render_trace(console: Console, result: TraceResult, *, verbose: bool = False) -> None:
    title = f"nettrace  {result.flow.describe()}"
    if result.final_flow and result.final_flow != result.flow:
        title += f"   (after NAT: {result.final_flow.describe()})"
    console.print(Panel(Text(title, style="bold"), expand=False))
    if not result.hops:
        _footer(console, result)
        return

    _hops_table(console, result.hops, verbose=verbose)
    if result.return_path is None:
        _footer(console, result)
        return
    _banner(console, result)
    _render_return(console, result.return_path, verbose=verbose)
    _warnings(console, result)


def _hops_table(console: Console, hops: list[Hop], *, verbose: bool) -> None:
    table = Table(show_lines=True, header_style="bold", expand=True)
    table.add_column("#", justify="right", width=3)
    table.add_column("Status", width=8)
    table.add_column("Where", ratio=2, overflow="fold")
    table.add_column("In / Out", ratio=2, overflow="fold")
    table.add_column("Lookup / Decision", ratio=5, overflow="fold")
    table.add_column("Policy / NAT", ratio=3, overflow="fold")
    first_block = next((h.index for h in hops if h.status == Status.BLOCK), None)
    for h in hops:
        where = Text(clean(f"{h.node}\n"), style="bold")
        where.append(f"{h.domain} {h.component}", style="dim")
        io = " / ".join(clean(x) for x in (h.ingress or "-", h.egress or "-"))
        decision = Text(clean(h.summary))
        if h.details and verbose:
            for d in h.details:
                decision.append(clean(f"\n- {d}"), style="dim")
        policy = h.policy or ""
        if h.nat:
            policy = f"{policy}\nNAT: {h.nat}" if policy else f"NAT: {h.nat}"
        style = "on grey19" if h.index == first_block else ""
        table.add_row(str(h.index), Text(h.status.value, style=STATUS_STYLE[h.status]), where, Text(io if io != "- / -" else ""),
                      decision, Text(clean(policy)), style=style)
    console.print(table)

    if verbose:
        for h in hops:
            if not h.evidence:
                continue
            console.rule(f"[bold]#{h.index} {escape(clean(h.node))}[/] evidence", style="dim")
            for ev in h.evidence:
                console.print(Text(clean(f"[{ev.source}] {ev.request}"), style="cyan"))
                if ev.response:
                    console.print(Text(clean(_trim(ev.response)), style="dim"))



def _banner(console: Console, result: TraceResult) -> None:
    banner = Text(f" {result.outcome.value} ", style=OUTCOME_STYLE[result.outcome])
    banner.append(clean(f"  {result.reason}"))
    console.print(banner)


def _warnings(console: Console, result: TraceResult) -> None:
    for w in result.warnings:
        console.print(Text(clean(f"  ! {w}"), style="yellow"))


def _footer(console: Console, result: TraceResult) -> None:
    _banner(console, result)
    _warnings(console, result)


SYMMETRY_STYLE = {
    SymmetryStatus.SYMMETRIC: "bold white on green",
    SymmetryStatus.ASYMMETRIC: "bold black on yellow",
    SymmetryStatus.UNKNOWN: "bold black on yellow",
    SymmetryStatus.NOT_RUN: "bold white on grey30",
}


def _render_return(console: Console, rp: ReturnPath, *, verbose: bool) -> None:
    """The 'Return path' block: its own title, hop table (when it ran), verdict line and symmetry line."""
    console.print()
    console.rule(Text(clean(f"Return path  {rp.flow.describe()}"), style="bold"), style="dim")
    if rp.hops:
        _hops_table(console, rp.hops, verbose=verbose)
    if rp.outcome is not None:
        banner = Text(f" RETURN {rp.outcome.value} ", style=OUTCOME_STYLE[rp.outcome])
        banner.append(clean(f"  {rp.reason}"))
        console.print(banner)
    sym = Text(f" SYMMETRY {rp.symmetry.status.value} ", style=SYMMETRY_STYLE[rp.symmetry.status])
    console.print(sym)
    for d in rp.symmetry.details:
        console.print(Text(clean(f"  - {d}"), style="dim" if rp.symmetry.status != SymmetryStatus.ASYMMETRIC else "yellow"))


_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")  # incl. C1 controls such as CSI (0x9b)


def clean(text: str) -> str:
    """Strip control characters (ESC etc.) from device-supplied text before it reaches the terminal."""
    return _CONTROL.sub("", text)


def _trim(text: str, lines: int = 25) -> str:
    rows = text.splitlines()
    if len(rows) > lines:
        return "\n".join(rows[:lines] + [f"... ({len(rows) - lines} more lines)"])
    return text


EXIT_CODES = {Outcome.REACHABLE: 0, Outcome.EXITED: 0, Outcome.BLOCKED: 3, Outcome.INCOMPLETE: 4}


def exit_code(result: TraceResult) -> int:
    """Process exit code. The forward outcome decides first (BLOCKED 3, INCOMPLETE 4). Only for a forward trace that
    was delivered does the return trace matter: return BLOCKED -> 3 (reason "return path blocked"), return
    INCOMPLETE / symmetry UNKNOWN -> 4, otherwise 0 (an ASYMMETRIC path is delivered: exit 0 with a warning)."""
    code = EXIT_CODES[result.outcome]
    rp = result.return_path
    if code or rp is None or result.outcome != Outcome.REACHABLE:
        return code
    if rp.outcome == Outcome.BLOCKED:
        return EXIT_CODES[Outcome.BLOCKED]
    if rp.outcome == Outcome.INCOMPLETE or rp.symmetry.status == SymmetryStatus.UNKNOWN:
        return EXIT_CODES[Outcome.INCOMPLETE]
    return 0
