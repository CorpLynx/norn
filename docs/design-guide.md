# Norn design guide

Norn is the product name shown in the web UI. The package, the CLI command and the environment
variables are still `nettrace`.

Read this before adding a screen, a control, a colour or an animation to the web UI
(`src/nettrace/web/static/app.html`). The page's CSS starts with the same tokens described here.
The hard rules in `AGENTS.md` (escaping, CSP, no external URLs, no storage) always win over
anything in this guide.

## What the UI is for

A network engineer wants to know why A cannot reach B on port X, and where the flow stops. Every
screen answers three questions in this order:

1. **What happened?** The verdict band: one word, one colour.
2. **Where?** The topology canvas: the path drawn on the network, with the stopping point marked.
3. **Why, and how do we know?** The hop list and the inspector: each decision and the read-only
   requests behind it.

A new feature belongs in the UI only if it helps answer one of these. Put it in the region that
owns that question.

## Principles

1. **Blue is the interface; the other colours are verdicts.** Blue (`--accent`) marks what you
   can act on, what is selected, and neutral information such as a lookup hop. Green, red, amber
   and violet mean pass, block, warn and unknown, and teal is the return path. Nothing else may
   use those five. The chrome itself is neutral grey.
2. **Never guess, visibly.** Unknown and warn are never drawn as success. An unverified result is
   amber or violet, never green. Status is always a glyph plus a word or colour, never colour
   alone.
3. **The canvas is paper.** The topology and path map sit on a light sheet in both light and dark
   mode, like a printed diagram on a desk. The chrome around it follows the system theme.
4. **Motion shows the packet's journey.** Animation is spent on the path: edges drawing, packets
   moving, a node pulsing when the packet arrives. Chrome moves only in answer to an action, and
   briefly.
5. **Dense, calm, readable.** This is a working tool. Prefer full-width panels divided by
   hairlines over cards. Prefer one more row of data over more padding.
6. **Device text is literal.** Addresses, interface names, commands and raw output are set in
   monospace exactly as the device wrote them. Everything else is the UI face.

## Colour

Tokens are CSS custom properties on `:root`, redefined for dark mode under
`@media (prefers-color-scheme:dark)`.

### Neutrals

| Token | Light | Dark | Use |
|---|---|---|---|
| `--bg` | `#e9ecea` | `#0f1211` | page behind the panels |
| `--panel` | `#fbfcfb` | `#171b1a` | top bar, rails, hop list, inspector |
| `--raised` | `#ffffff` | `#1f2423` | inputs, floating controls, cards over a panel |
| `--soft` | `#eff2f0` | `#1f2423` | hover, expanded detail rows |
| `--sel` / `--tint` | `#e6ecfd` | `#1f2a4a` | selected row or scenario; info tags and ticks |
| `--line` | `#d3d9d5` | `#2a312f` | hairlines between regions |
| `--line2` | `#b4bdb8` | `#414b48` | borders of controls |
| `--text` | `#161a19` | `#e8ecea` | body text |
| `--muted` | `#56605c` | `#9da8a4` | labels, secondary text (at least 4.5:1 on every surface) |
| `--accent` | `#2f5bd8` | `#9db7ff` | links, selected tab text, focus ring, current-row marker, hover |
| `--accent-bg` / `--on-accent` | `#2f5bd8` / `#fff` | `#3d63e0` / `#fff` | filled controls: Trace, Play, selected view, live badge |
| `--ink` / `--on-ink` | `#161a19` / `#fff` | `#e8ecea` / `#121514` | the ring around the current hop tick, the skip link |

The greys lean slightly green, after the light grey of rack cabinets. Do not add a second family
of greys beside them. The top bar carries a 2px accent line along its top edge.

### Status

| Status | Filled (`--b-*`, white text) | Text, light (`--t-*`) | Text, dark | Glyph |
|---|---|---|---|---|
| pass | `#157a43` | `#157a43` | `#4ade80` | ✓ |
| block | `#c62828` | `#c62828` | `#ff8f87` | ✕ |
| warn | `#f5b700` (dark text `--fg-warn`) | `#8a5a00` | `#fbbf24` | ! |
| unknown | `#6d3fc0` | `#6d3fc0` | `#c4a8ff` | ? |
| info | `#2f5bd8` (the accent) | `#2f5bd8` | `#9db7ff` | i |

- Use `--b-*` for filled tags and the verdict flag. Use `--t-*` for status-coloured text on a panel.
- On the canvas the same hues are fixed values, because the canvas is always light: pass
  `#157a43`, block `#c62828`, warn `#d9971c`, unknown `#6d3fc0`, info `#2f5bd8`, return path
  `#0b7285` (teal, dotted). They are the `PKT_COLOR` and `PKT_RET` constants in the script.
- Outcomes map to statuses: reachable is pass, blocked is block, exited is info, incomplete is
  warn. An outcome the UI does not recognise is treated as incomplete.
- A decision (pass, block, warn, unknown) is a solid tag. A lookup (info) is a soft blue tint, so
  decisions stand out in a long hop list.
- Tints carry colour into larger areas without shouting: the verdict band is the outcome colour
  at 9% over the panel, an on-path node tile takes a pale wash of its status, and a scenario's
  glyph disc is filled at 13%. Use `color-mix()` with a status or accent token; do not invent a
  new pale hex.

### Canvas

| Token | Value | Use |
|---|---|---|
| `--paper` | `#eef1ef` | canvas background, with a dot grid |
| `--sheet` | `#fafbfa` | group fill; also the halo behind map labels |
| `--pline` | `#c6cec9` | node tile and label-chip borders |

Groups carry soft, conventional tints so a node can be located at a glance: site is slate blue,
AWS and its accounts are pale orange (accounts dashed), a VPC is pale green, Prisma Access is
pale amber-orange. They are the `GSTYLE` table in the script, and they match the exported path
map. These tints are always pale; a saturated colour on the canvas is always a status. Links are
grey: a dashed link is a tunnel, a heavy link is a TGW attachment. Device icons keep their own colours; nodes off the traced path
are faded and greyed so the path stands out.

**Level of detail.** The topology shows more as you zoom in. `apply()` sets `#stage[data-lod]` from
the zoom scale (`LOD_MID` 0.75, `LOD_NEAR` 1.3) and `--z`:

| Tier | Scale | Shows |
|---|---|---|
| far | under 0.75 | device names only, grown so they stay at least about 9px on screen |
| mid | 0.75 to 1.3 | + model or subnet line, interface names at link ends, link labels |
| near | 1.3 and up | + the interface address under each interface name |

Detail that is out of range fades (`.lod-mid`, `.lod-near`); nothing is re-rendered while zooming.
Link labels sit in their own layer above the path and the packet stream, and dim with their link.
Addresses come from the server (`web.topology.annotate_addresses`): the `inventory discover` cache
and static `addresses`, never a new query. A device's full list is in the inspector's Device tab
under Interfaces. A new kind of canvas label picks a tier and takes the matching class.

`#ws` and `#pmview` reset the theme tokens to their light values. Anything placed on the canvas
inherits that, so it stays readable in dark mode without extra work.

## Type

No web fonts: the page must work offline and its CSP blocks them.

| Token | Stack | Use |
|---|---|---|
| `--ui` | `system-ui, -apple-system, "Segoe UI", Roboto, …` | everything except device literals |
| `--mono` | `ui-monospace, "SF Mono", "Cascadia Mono", Menlo, Consolas` | addresses, interfaces, commands, evidence, console |

| Size | Weight | Use |
|---|---|---|
| 15px | 700 | verdict word, product name, inspector heading |
| 13px | 400 / 600 | body, table cells, buttons |
| 12px | 400 / 600 | section headings (muted), secondary lines, notes |
| 11–11.5px | 400 / 500 | field captions, table headers, hints |
| 10.5px | 700 | status tags only |

- Sentence case everywhere. No all-caps labels and no letter-spaced headings. The one exception
  is the stamp on the map ("BLOCKED HERE", "NOT REACHED"), which is a mark on the diagram, not a label.
- Numbers use tabular figures (`font-variant-numeric: tabular-nums` on `body`).
- Do not add a size between these steps. If something needs emphasis, change weight or colour
  to `--text` from `--muted` first.

## Shape, spacing and depth

- Radii: `--r1` 5px (tags, small buttons), `--r2` 8px (inputs, buttons, notes), `--r3` 12px
  (dialogs, the path-map sheet). Pills (`99px`) only for the mode badge and chips.
- Spacing steps: 2, 4, 6, 8, 12, 14, 16, 20px. Panel padding is 12–16px; rows are 5–8px tall padding.
- Regions are divided by a 1px `--line`. Shadows (`--lift`) are only for things that float over
  the canvas: the view switch, the zoom tools, the busy dialog, the toast.
- Do not wrap panel content in cards. A list is rows with hairlines.

## Layout

```
+--------------------------------------------------------------------+
| Norn [mode] [ source ⇄ destination | proto | port ] [opts] Trace  ? |  top bar: the flow, as one line
+---------------------------------------------------------------------+
| > Verdict  stopped at, reason, exit code, ! warnings     [hop ticks] |  what happened
+-----------+--------------------------------------+------------------+
| scenarios | [Topology|Path map]   [find] [+ - Fit]| trace summary  × |
|  filter   |        topology / path map           | Hop|Device|JSON  |  where          why
| history   |           (paper canvas)             |                  |
|           +--------------------------------------+ inspector pane   |
|           | playback controls                    | + console        |
|           | hop list (one row per hop)           | (hidden at start)|
+-----------+--------------------------------------+------------------+
```

- Grid areas: `top`, `verd`, `left`, `ws`, `sim`, `insp`. Columns are 288px, flexible, 400px.
- Below 1180px the side columns narrow. Below 900px everything stacks and the page scrolls; the
  canvas then only zooms with Ctrl/⌘+scroll so it never traps the page.
- New global inputs go in the top bar's flow form. New per-trace facts go in the verdict band (if
  they change the answer) or the inspector summary (if they qualify it). New per-hop data goes in
  the hop detail and the inspector's Hop tab. New views of the same trace become a tab, either on
  the canvas (a different picture) or in the inspector (a different reading).

## Components

**Flow form.** Fields are cells of a joined bar: a small caption above a monospace value, no
individual borders. The required fields (source, destination, protocol, port) are one bar; the
optional ones are a second, quieter bar. A focused cell gets a 2px accent inset ring. An invalid cell
gets a red ring and the message appears in the list under the form. A new field is a
`<label>Caption<input></label>` cell in the right bar.

**Buttons.** Primary: filled accent blue, one per region at most (Trace, Play). Secondary: `--raised`
with a `--line2` border. Ghost: no border, `--sel` on hover (transport controls, canvas tools).
Destructive or cancelling: red text and border, never filled. Labels are verbs and say what
happens ("Trace", "Cancel trace", "Copy output"); no arrows or icons appended to text.

**Verdict band.** A flag in the status colour holding a glyph and the outcome, then the facts
(label in muted, value in text), then one tick per hop in path order. A tick is a button: it
carries the hop's status glyph and colour and jumps to that hop. The current hop has an ink ring. The whole band is washed with the outcome colour.

**Scenario and history rows.** Rows, not cards. An outlined glyph disc shows the expected
outcome (outlined and lightly filled because it is an expectation, not a result). The selected row
has the `--sel` fill, an accent bar on the left and the word "Selected".

**Status tag (`.pill`).** Glyph plus the status word. Filled for decisions, outlined for info.
Always produced by `badge()`, which escapes its input.

**Hop list.** One row per hop: number, tag, where, what happened. The current row has the `--sel`
fill and an accent bar; rows after the current step are muted. Details expand in place.

**Live progress.** While a trace runs, the page polls `POST /api/trace/progress` every 250ms. The
hop list fills row by row (the source row first, so numbers match the final list), each decided hop
lights its status ring on the canvas, and the device being asked gets a dashed accent ring. The busy
card floats over the bottom of the canvas rather than covering it. The final result replaces all of it.

**Verdict warnings.** A trace's warnings are a count at the end of the verdict facts ("! 2 warnings",
in the warn text colour) that expands into a list across the bottom of the band.

**Find.** A search box beside the zoom tools (<kbd>/</kbd>) matches device names, AWS ids, interface
names and IP addresses (an address the device owns first, then the most specific prefix a node
stands for; the default route only when nothing else matches). Picking a result centres the device
at the near zoom tier, highlights it and gives it keyboard focus; it does not open the inspector.
On a narrow canvas the search and zoom bar moves to a second row under the view switch.

**Left rail.** Scenarios collapse and filter by expected outcome (chips, `aria-pressed`). The legend
and the keyboard shortcuts live in the help dialog (`?` button in the top bar, or <kbd>?</kbd>), not
in the rail or under the hop list.

**Flow form.** The arrow between source and destination is a button: hover shows ⇄ and a click swaps
the two addresses.

**Playback bar at narrow widths.** `#sim` is a size container: under 640px the Replay label and the
"Playback"/"Speed" words go (screen-reader text stays); under 480px first/last go too. Controls
never clip.

**Inspector.** Hidden when Norn opens, so the canvas gets the width. Tabs: Hop, Device, JSON (the
path map lives only on the canvas). It opens when the user clicks a
device on the canvas (Device tab) or explicitly picks a step: an event row, a verdict tick, the
"Stopped at" link or a path-map hop (Hop tab). Playback, the step buttons, arrow keys and the
scrubber never open it. A deep link with `step=` or `node=` opens it. Its × button hides it again
and returns focus to the canvas. Opening shifts the camera by half the lost width so the view keeps
its centre, and pans a clicked device back into view if the panel would cover it. Underlined tabs. Key/value facts use `dl.kv`. Evidence is a `details` per request
with the request in monospace as its summary.

**Console.** Always dark, in both themes, because it is a terminal. The prompt is pinned under
the scrolling output.

**Panel edges.** The left rail, the inspector and the playback panel resize from the edge they share
with the canvas. Each edge is an invisible 9px strip (`.split`, `role="separator"`) that shows the
resize cursor at once and lights up as a 3px accent line after a 150ms hover, like a desktop window
edge. Drag to resize; when focused, arrow keys move it 16px (Shift 64px), Home and End jump to the
limits, and Enter or a double-click resets it. The canvas always keeps at least 360px of width and
180px of height. Sizes live in memory only (no storage APIs), so a reload restores the defaults. A
new panel that meets the canvas gets the same kind of edge.

**Canvas controls.** Floating segmented groups in the top corners. Anything else that floats on
the canvas goes in a corner and uses `--raised`, `--line` and `--lift`.

**Empty and error states.** An empty region says what to do next in one sentence. An error says
what happened and how to fix it; it never apologises and never says only "something went wrong".

## Motion

| Token | Value | Use |
|---|---|---|
| `--fast` | 120ms | hover, press, colour changes |
| `--med` | 220ms | selection moving, rows changing state, toast |
| `--slow` | 420ms | camera moves, verdict entering, a status ring appearing |
| `--ease` | `cubic-bezier(.2,.8,.2,1)` | everything that enters or moves |

The packet's journey is the one place the UI animates on its own:

- **Edge draw.** A newly reached edge draws itself from the source side over `FLOW_REVEAL`
  (600ms at 1x), in step with the front of the packet stream. Dashed edges (tunnels, the return
  path) fade in instead.
- **Packet stream.** `FLOW_N` packets per edge, each a head with a bright core, a short tail and
  a soft halo, coloured by the status of the hop the edge leaves. Packets ease in and out at the
  ends of an edge.
- **Arrival.** When the packet reaches a node, its status ring scales in and one ripple leaves
  the tile. At a blocking hop the ripple is red and fires twice, packets slow and pile up, and
  the node is stamped "BLOCKED HERE".
- **Camera.** Fit, zoom buttons and loading a trace glide the canvas (`--slow`). Dragging, wheel
  zoom and window resizes are direct, with no easing.
- **Waiting.** The busy dialog shows a probe stepping along five hops, not a spinner.

Rules for new motion:

- Chrome animates only in response to an action, once, for at most `--slow`.
- Do not animate anything that is re-rendered on every step (the inspector pane, map marks): it
  would flash during playback. Put one-shot animations on elements that persist and toggle a class.
- Animate `transform` and `opacity`. For SVG use `transform-box: fill-box`.
- Animation code builds DOM with `svgEl()` and numbers only. It never writes trace text.
- **Reduced motion.** Under `prefers-reduced-motion: reduce` every animation and transition is
  off, auto-play is disabled, and the path is a static dashed line stepped by hand. Anything new
  must be fully usable in that mode. Timing lives in CSS so the single reduced-motion rule covers it.

## Words

- Name things the way a network engineer would: hop, flow, return path, evidence. Not internal
  names (overlay, step index).
- Sentence case. Plain verbs. No exclamation marks.
- Say the uncertain thing plainly: "Unverified (incomplete)", "do not treat this as reachable".
- An action keeps one name everywhere: the button says "Trace", the busy text says "Tracing…".
- The mode badge reads "Simulated lab" or "Live, read-only". Keep both words of the live badge.

## Accessibility

- Every status has a glyph and a word; colour is the third signal.
- Text contrast is at least 4.5:1 on its surface, in both themes. Check `--muted` on `--sel` and
  `--soft` when adding a surface.
- Focus is a 2px accent outline with a 2px offset. Never remove an outline without replacing it
  (the form cells and the console prompt show focus on their wrapper).
- Everything is reachable by keyboard. Groups of similar items (scenarios) are one Tab stop with
  arrow keys inside. Global shortcuts never steal Space or Enter from a focused control.
- Results that appear on their own are announced (`role="status"`, `aria-live="polite"`).

## Constraints that shape the design

These come from `AGENTS.md` and are tested.

- One self-contained HTML file. No external URLs, fonts, images or scripts. CSP is
  `default-src 'none'` with inline style and script only.
- No `localStorage`, `sessionStorage`, cookies from script, or `prompt()`.
- Every value from a trace or a device goes through `esc()` before it reaches `innerHTML`.
- Several strings and selectors are asserted by `tests/test_ui_*.py`, `tests/test_packet_flow.py`
  and `tests/test_cancel.py`. Run the tests after any markup change.

## Checklist for a new feature

1. Which question does it answer: what, where, or why? Put it in that region.
2. Is anything coloured? Blue means it is actionable, selected or neutral information. Any other
   colour is a status: it uses the status tokens and has a glyph.
3. Does it use only the tokens above for colour, type size, radius and timing?
4. Does it read correctly in dark mode, at 1180px, and stacked at 900px?
5. Is it keyboard reachable with a visible focus ring, and announced if it appears on its own?
6. Does it work with reduced motion?
7. Are all trace and device values escaped?
8. Do the tests pass (`.venv/bin/pytest -q`), and have you looked at it in a browser
   (`nettrace demo serve`) in both themes?

## Not yet aligned

- `docs/demo-packet-flow.gif` was recorded before this design.
- The path map (`viz/`) shows the forward path only; the return path is on the topology and in the hop list.
