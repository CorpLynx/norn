"""Static SVG path map. Self-contained (no fonts, scripts or external images), so it can be
pasted into tickets, wikis or chat. Every element that maps to a hop carries data-hop for the
HTML viewer."""

from __future__ import annotations

from html import escape
from typing import Any

from nettrace.viz.model import BADGE_W, BLOCK, ICON, INFO, PASS, UNKNOWN, WARN, Edge, Node, PathMap

# Colours follow docs/design-guide.md ("Canvas"): fixed values, because the map is always a light paper surface.
STATUS_COLOR = {PASS: "#157a43", BLOCK: "#c62828", WARN: "#d9971c", UNKNOWN: "#6d3fc0", INFO: "#2f5bd8"}
RETURN_COLOR = "#0b7285"  # return path (teal, dotted); the offline map is forward-only, kept for callers
INK, MUTED, LINE, LINE2 = "#161a19", "#56605c", "#d3d9d5", "#b4bdb8"
PAPER, SHEET, PLINE, DOT = "#eef1ef", "#fafbfa", "#c6cec9", "#cfd6d2"
ACCENT, ON_WARN = "#2f5bd8", "#1a1300"
# (fill, stroke, label) per container kind: the GSTYLE table of the web UI canvas; accounts are drawn dashed.
CONTAINER_STYLE = {
    "prisma": ("#fff6ec", "#eaa567", "#8f4f12"),
    "site": ("#f1f5fc", "#9fb2d3", "#33466b"),
    "aws": ("#fffaf0", "#ecb467", "#855309"),
    "account": ("#fffdf8", "#e0b77d", "#7d541b"),
    "vpc": ("#f0f8f1", "#86be8d", "#2c6537"),
}
# header stamp: (word, glyph, fill, text colour); the word and glyph carry the outcome, colour is the third signal
OUTCOME_LABEL = {
    "REACHABLE": ("Reachable", "✓", STATUS_COLOR[PASS], "#fff"),
    "BLOCKED": ("Blocked", "✕", STATUS_COLOR[BLOCK], "#fff"),
    "EXITED": ("Exited known network", "↗", STATUS_COLOR[INFO], "#fff"),
    "INCOMPLETE": ("Unverified (incomplete)", "?", "#f5b700", ON_WARN),
}
UI_FACE = "system-ui,-apple-system,'Segoe UI',Roboto,Arial,sans-serif"
MONO_FACE = "ui-monospace,'SF Mono','Cascadia Mono',Menlo,Consolas,monospace"
FONT = f"font-family:{UI_FACE}"
HALO = f"paint-order:stroke;stroke:{SHEET};stroke-width:3px;stroke-linejoin:round"  # keeps labels legible over lines


def _f(size: float, weight: int = 400, mono: bool = False) -> str:
    return f"font:{weight} {size}px {MONO_FACE if mono else UI_FACE}"


def _t(s: Any) -> str:
    return escape(str(s), quote=True)


# ---- icons (drawn in a 56x56 box centred on 0,0) -------------------------------------------------
def _icon(kind: str) -> str:
    w = "#ffffff"
    if kind == "router":  # Cisco-style router: disc with four arrows
        return (f'<circle r="21" fill="#2f6db5"/><g stroke="{w}" stroke-width="3" fill="none" stroke-linecap="round">'
                '<path d="M-12 0H-3M3 0H12M0 -12V-3M0 3V12"/></g>'
                f'<g fill="{w}"><path d="M-14 0l5-4v8z"/><path d="M14 0l-5-4v8z"/>'
                '<path d="M0 -14l-4 5h8z"/><path d="M0 14l-4-5h8z"/></g>')
    if kind == "firewall":  # brick wall
        bricks = "".join(f'<rect x="{x}" y="{y}" width="12" height="7" rx="1"/>'
                         for y, xs in ((-14, (-18, -5, 8)), (-5, (-12, 1, 14)), (4, (-18, -5, 8)))
                         for x in xs if x + 12 <= 20)
        return (f'<rect x="-22" y="-19" width="44" height="34" rx="5" fill="#c4442e"/>'
                f'<g fill="#f6c7a8">{bricks}</g><rect x="-22" y="13" width="44" height="5" rx="2" fill="#8f2d1d"/>')
    if kind == "prisma":  # cloud with shield
        return ('<path d="M-20 10a10 10 0 0 1 2-19a13 13 0 0 1 24-5a11 11 0 0 1 14 12a8 8 0 0 1-2 12z" fill="#f08a24"/>'
                '<path d="M0 -6l9 3v6c0 6-4 9-9 11c-5-2-9-5-9-11v-6z" fill="#fff"/>')
    if kind == "tgw":  # hub with spokes
        spokes = "".join(f'<line x1="0" y1="0" x2="{x}" y2="{y}"/>' for x, y in ((-16, -12), (16, -12), (-16, 12), (16, 12)))
        dots = "".join(f'<circle cx="{x}" cy="{y}" r="4.5"/>' for x, y in ((-16, -12), (16, -12), (-16, 12), (16, 12)))
        return (f'<rect x="-22" y="-20" width="44" height="40" rx="8" fill="#8c4fff"/>'
                f'<g stroke="{w}" stroke-width="2.5">{spokes}</g><g fill="{w}">{dots}</g><circle r="7" fill="{w}"/>')
    if kind == "vpc-router":  # route table
        rows = "".join(f'<rect x="-13" y="{y}" width="26" height="4" rx="1"/>' for y in (-10, -3, 4))
        return (f'<rect x="-21" y="-19" width="42" height="38" rx="7" fill="#3f8f3f"/>'
                f'<g fill="{w}">{rows}</g><path d="M8 12h8l-3-3M16 12l-3 3" stroke="{w}" stroke-width="2" fill="none"/>')
    if kind == "lan":  # layer-2 switch: flat box with crossing arrows (Cisco style)
        return ('<rect x="-23" y="-12" width="46" height="24" rx="5" fill="#2f6db5"/>'
                f'<g stroke="{w}" stroke-width="2.2" fill="none" stroke-linecap="round">'
                '<path d="M-15 -4H13M9 -8l4 4-4 4"/><path d="M15 4H-13M-9 0l-4 4 4 4"/></g>')
    if kind == "users":  # group of people
        return ('<g fill="#4b5a6e"><circle cx="-9" cy="-9" r="6"/><path d="M-20 12a11 11 0 0 1 22 0z"/></g>'
                '<g fill="#2f6db5"><circle cx="8" cy="-6" r="7"/><path d="M-5 17a13 13 0 0 1 26 0z"/></g>')
    if kind == "account":  # AWS account: orange cloud
        return ('<path d="M-21 10a10 10 0 0 1 2-19a13 13 0 0 1 24-5a11 11 0 0 1 15 12a8 8 0 0 1-2 12z" fill="#f29d38"/>'
                f'<text y="7" text-anchor="middle" fill="{w}" style="font:700 10px system-ui,-apple-system,Roboto,Arial,sans-serif">AWS</text>')
    if kind in ("eni", "endpoint", "host"):  # server
        return ('<rect x="-15" y="-20" width="30" height="40" rx="4" fill="#4b5a6e"/>'
                '<g fill="#9fb0c4"><rect x="-10" y="-14" width="20" height="4" rx="1"/>'
                '<rect x="-10" y="-6" width="20" height="4" rx="1"/></g><circle cx="7" cy="12" r="2.5" fill="#5ee08a"/>')
    if kind == "igw":
        return (f'<circle r="20" fill="#2a8ac9"/><g fill="none" stroke="{w}" stroke-width="2">'
                '<ellipse rx="8" ry="18"/><line x1="-19" y1="0" x2="19" y2="0"/>'
                '<path d="M-16 -9H16M-16 9H16"/></g>')
    if kind == "external":
        return ('<path d="M-22 10a10 10 0 0 1 2-19a13 13 0 0 1 24-5a11 11 0 0 1 16 12a8 8 0 0 1-2 12z" '
                'fill="#e6edf5" stroke="#8aa0b8" stroke-width="2"/>')
    if kind == "natgw":
        return (f'<rect x="-21" y="-19" width="42" height="38" rx="7" fill="#d67a1e"/>'
                f'<text y="5" text-anchor="middle" fill="{w}" style="font:700 13px system-ui,-apple-system,Roboto,Arial,sans-serif">NAT</text>')
    if kind in ("gwlbe", "vpce", "nlb"):
        return (f'<rect x="-21" y="-19" width="42" height="38" rx="7" fill="#6a5acd"/>'
                f'<text y="5" text-anchor="middle" fill="{w}" style="font:700 11px system-ui,-apple-system,Roboto,Arial,sans-serif">'
                f'{"GWLB" if kind == "gwlbe" else "NLB" if kind == "nlb" else "VPCE"}</text>')
    if kind == "error":
        return (f'<circle r="20" fill="#6d3fc0"/><text y="7" text-anchor="middle" fill="{w}" '
                'style="font:700 20px system-ui,-apple-system,Roboto,Arial,sans-serif">?</text>')
    label = {"peering": "PCX", "vgw": "VGW", "exit": "→"}.get(kind, "•")
    return (f'<rect x="-21" y="-19" width="42" height="38" rx="7" fill="#5c6b80"/>'
            f'<text y="5" text-anchor="middle" fill="{w}" style="font:700 12px system-ui,-apple-system,Roboto,Arial,sans-serif">{_t(label)}</text>')


# ---- pieces ---------------------------------------------------------------------------------------
def _node(n: Node) -> str:
    color = STATUS_COLOR.get(n.status, "#888")
    ring = ""
    if n.status != INFO or n.role:
        unreached = n.synthetic and n.role == "destination" and n.subtitle != "destination"
        dash = ' stroke-dasharray="5 4"' if unreached else ""
        ring_color = LINE2 if unreached else color
        ring = (f'<rect x="{-ICON / 2 - 4}" y="{-ICON / 2 - 4}" width="{ICON + 8}" height="{ICON + 8}" rx="16" '
                f'fill="none" stroke="{ring_color}" stroke-width="{4 if n.status == BLOCK else 2.5}"{dash}/>')
    tile = f'<rect x="{-ICON / 2}" y="{-ICON / 2}" width="{ICON}" height="{ICON}" rx="12" fill="#fff" stroke="{PLINE}"/>'
    hop = f' data-hop="{n.hops[0]}"' if n.hops else ""
    badge = ""
    if n.status in (BLOCK, WARN, UNKNOWN):
        glyph_ink = ON_WARN if n.status == WARN else "#fff"
        glyph = {BLOCK: "✕", WARN: "!", UNKNOWN: "?"}[n.status]
        badge = (f'<circle cx="{ICON / 2}" cy="{-ICON / 2}" r="10" fill="{color}"/>'
                 f'<text x="{ICON / 2}" y="{-ICON / 2 + 4.5}" text-anchor="middle" fill="{glyph_ink}" '
                 f'style="{_f(12, 700)}">{glyph}</text>')
    role = ""
    if n.role:
        role = (f'<text y="{-ICON / 2 - 12}" text-anchor="middle" fill="{MUTED}" '
                f'style="{_f(11, 600)};{HALO}">{_t(n.role.capitalize())}</text>')
    lines = [f'<text y="{ICON / 2 + 18}" text-anchor="middle" fill="{INK}" style="{_f(13, 600)};{HALO}">{_t(_s(n.title, 26))}</text>',
             f'<text y="{ICON / 2 + 33}" text-anchor="middle" fill="{MUTED}" style="{_f(11, 400, True)};{HALO}">{_t(_s(n.subtitle, 30))}</text>']
    if n.extra:
        lines.append(f'<text y="{ICON / 2 + 47}" text-anchor="middle" fill="{ACCENT}" style="{_f(11, 400, True)};{HALO}">{_t(_s(n.extra, 30))}</text>')
    title = f"<title>{_t(n.title)} — {_t(n.subtitle)} ({_t(n.status)})</title>"
    return (f'<g class="node" id="{n.id}" transform="translate({n.x:.0f},{n.y:.0f})"{hop}>{title}{ring}{tile}'
            f'{_icon(n.kind)}{badge}{role}{"".join(lines)}</g>')


def _s(text: str, n: int) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


def _edge(e: Edge, a: Node, b: Node) -> str:
    color = STATUS_COLOR.get(e.status, "#888")
    x1, x2, y = a.x + ICON / 2 + 6, b.x - ICON / 2 - 10, a.y
    if e.status == BLOCK and e.badges:
        # Draw the path solid up to the blocking badge, faded after it.
        stop = next(i for i, bd in enumerate(e.badges) if bd.status == BLOCK)
        bx = _badge_x(e, a, b, stop)
        line = (f'<line x1="{x1:.0f}" y1="{y}" x2="{bx:.0f}" y2="{y}" stroke="{STATUS_COLOR[PASS]}" stroke-width="4"/>'
                f'<line x1="{bx:.0f}" y1="{y}" x2="{x2:.0f}" y2="{y}" stroke="{LINE2}" stroke-width="3" '
                f'stroke-dasharray="6 5"/>')
    else:
        dash = ' stroke-dasharray="7 6"' if e.dashed else ""
        width = 3 if e.dashed or e.status == INFO else 4
        line = (f'<line x1="{x1:.0f}" y1="{y}" x2="{x2:.0f}" y2="{y}" stroke="{color}" stroke-width="{width}"{dash} '
                f'marker-end="url(#arrow-{_t(e.status)})"/>')
    parts = [line]
    if e.label:
        mid = (x1 + x2) / 2
        hop = f' data-hop="{e.link_hop}"' if e.link_hop else ""
        parts.append(f'<g class="link"{hop}><rect x="{mid - 60:.0f}" y="{y - 31}" width="120" height="18" rx="9" '
                     f'fill="{SHEET}" stroke="{PLINE}"/><text x="{mid:.0f}" y="{y - 18}" text-anchor="middle" '
                     f'fill="{MUTED}" style="{_f(11, 400, True)}"><title>link {_t(e.label)}</title>⇄ {_t(_s(e.label, 16))}'
                     f'</text></g>')
    for i, bd in enumerate(e.badges):
        bx = _badge_x(e, a, b, i)
        c = STATUS_COLOR.get(bd.status, "#888")
        glyph = {PASS: "✓", BLOCK: "✕", WARN: "!", UNKNOWN: "?"}.get(bd.status, "")
        glyph_c = "#8a5a00" if bd.status == WARN else c  # amber text on white needs the darker text tone
        parts.append(f'<g class="badge" data-hop="{bd.hop}"><title>{_t(bd.label)}: {_t(bd.text)}</title>'
                     f'<rect x="{bx - 27:.0f}" y="{y - 11}" width="54" height="22" rx="11" fill="#fff" stroke="{c}" '
                     f'stroke-width="2"/><text x="{bx - 7:.0f}" y="{y + 4}" text-anchor="middle" fill="{INK}" '
                     f'style="{_f(11, 600)}">{_t(bd.label)}</text><text x="{bx + 16:.0f}" y="{y + 4.5}" '
                     f'text-anchor="middle" fill="{glyph_c}" style="{_f(12, 700)}">{glyph}</text></g>')
    if e.note and (e.dashed or e.status in (BLOCK, UNKNOWN)) and not e.badges:
        mid = (x1 + x2) / 2
        chars = max(8, int((x2 - x1) / 6.6))
        parts.append(f'<text x="{mid:.0f}" y="{y + 22}" text-anchor="middle" fill="{color}" '
                     f'style="{_f(11, 600)};{HALO}"><title>{_t(e.note)}</title>{_t(_s(e.note, chars))}</text>')
    return f'<g class="edge" id="{e.id}">{"".join(parts)}</g>'


def _badge_x(e: Edge, a: Node, b: Node, i: int) -> float:
    n = len(e.badges)
    mid = (a.x + b.x) / 2
    return mid + (i - (n - 1) / 2) * BADGE_W


def _header(pm: PathMap) -> str:
    t = pm.trace
    flow = t.get("Flow") or {}
    port = f":{flow['dst_port']}" if flow.get("dst_port") else ""
    proto = flow.get("protocol", "")
    title = f"{flow.get('src', '?')} → {flow.get('dst', '?')}{port} ({proto})"
    final = t.get("FinalFlow")
    if final and final != flow:
        fport = f":{final['dst_port']}" if final.get("dst_port") else ""
        title += f"   after NAT: {final.get('src')} → {final.get('dst')}{fport}"
    outcome = t.get("Outcome", "")
    word, glyph, fill, ink = OUTCOME_LABEL.get(outcome, (f"Unverified ({outcome})", "?", "#f5b700", ON_WARN))
    label = f"{glyph} {word}"
    w = len(label) * 7.6 + 24
    return (f'<g transform="translate(24,30)"><rect x="0" y="-18" width="{w:.0f}" height="26" rx="5" '
            f'fill="{fill}"/><text x="12" y="0" fill="{ink}" style="{_f(13, 700)}">{_t(label)}</text>'
            f'<text x="{w + 12:.0f}" y="0" fill="{INK}" style="{_f(13, 600, True)}">{_t(title)}</text>'
            f'<text x="0" y="24" fill="{MUTED}" style="{_f(12)}">{_t(_s(t.get("Reason", ""), 160))}</text></g>')


def _markers() -> str:
    out = []
    for status, color in STATUS_COLOR.items():
        out.append(f'<marker id="arrow-{_t(status)}" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" '
                   f'markerHeight="5" orient="auto"><path d="M0 0L10 5L0 10z" fill="{color}"/></marker>')
    return "".join(out)


def render_svg(pm: PathMap, *, header: bool = True) -> str:
    top = 62 if header else 0
    width, height = pm.width, pm.height + top
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width:.0f} {height:.0f}" '
             f'width="{width:.0f}" height="{height:.0f}" style="{FONT};background:{PAPER}">',
             f'<defs>{_markers()}<pattern id="grid" width="24" height="24" patternUnits="userSpaceOnUse">'
             f'<circle cx="1.2" cy="1.2" r="1.2" fill="{DOT}"/></pattern></defs>',
             f'<rect width="{width:.0f}" height="{height:.0f}" fill="{PAPER}"/>'
             f'<rect width="{width:.0f}" height="{height:.0f}" fill="url(#grid)"/>']
    if header:
        parts.append(_header(pm))
    parts.append(f'<g transform="translate(0,{top})">')
    for c in sorted(pm.containers, key=lambda c: c.depth):
        fill, stroke, text = CONTAINER_STYLE.get(c.kind, CONTAINER_STYLE["site"])
        dash = ' stroke-dasharray="8 5"' if c.kind == "account" else ""
        parts.append(f'<g class="container"><rect x="{c.x:.0f}" y="{c.y:.0f}" width="{c.w:.0f}" height="{c.h:.0f}" '
                     f'rx="12" fill="{fill}" stroke="{stroke}" stroke-width="1.2"{dash}/>'
                     f'<text x="{c.x + 14:.0f}" y="{c.y + 19:.0f}" fill="{text}" style="{_f(12, 600)}">'
                     f'{_t(_s(c.label, max(12, int(c.w / 7.2))))}</text></g>')
    by_id = {n.id: n for n in pm.nodes}
    for e in pm.edges:
        parts.append(_edge(e, by_id[e.src], by_id[e.dst]))
    for n in pm.nodes:
        parts.append(_node(n))
    parts.append("</g></svg>")
    return "".join(parts)
