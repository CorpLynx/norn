# Decision log

Short records of choices made while building nettrace. Each one says why it was made, so a later
change can be judged against the original reason. Newest first.

## D20. First run against real AWS and a real VM-Series: three fixes (2026-11-14)
Norn's first live run: the aws-networking-lab (four accounts, one Transit Gateway with per-VPC route tables, a PAYG
VM-Series 11.1 in routed mode, reached `via: direct` with a read-only `superreader` API admin). Each check of the lab's
expected-reachability matrix was traced and compared; after these fixes all 23 traceable checks match (DNS checks skipped).
- **TGW route search (V9 refuted as written).** Real AWS wants different value forms per filter and answers the wrong form
  with an empty list, not an error: `route-search.longest-prefix-match` takes a bare address (`10.0.20.113/32` finds
  nothing), `route-search.supernet-of-match` takes a CIDR (`10.0.20.113` finds nothing). nettrace sent `/32` to the
  longest-prefix filter, so every TGW hop was "no route": a false BLOCK on every cross-VPC flow. Now: longest-prefix with
  the bare address; an empty answer is confirmed with supernet-of-match (`/32`) before it can mean "no route"; any
  `NetTraceError` (refusal, deadline, cancel) still propagates. `demo/sim_aws.py` now answers both filters exactly like
  AWS, so a regression fails the tests (`tests/test_aws_live_findings.py`).
- **Return path: a security group passes the reply of the request it passed (amends D16).** D16 reported every stateful
  deny on the return flow as INCOMPLETE. On AWS that made every `--return` trace INCOMPLETE at the source's own security
  group (the reply was evaluated as a new inbound session). Security groups are stateful per ENI by documented AWS
  behaviour, so a group that allowed the request allows its reply; that is not a session-table guess. Scope, kept
  narrow so it stays exact: only the forward **source ENI** (its egress PASS before the first route lookup, before any NAT)
  and the **destination ENI** (its ingress PASS, and only without source NAT, because with SNAT the real reply goes to the
  translated address). The return hop is a PASS that names the forward hop (`stateful reply (forward hop N ...)`); every
  other security group, and PAN-OS / Prisma, are still evaluated as a new session and a deny there is still INCOMPLETE.
- **Symmetry compares a TGW by its attachments, not its route tables.** A TGW picks the route table by the attachment
  traffic enters from, so the request and its reply normally use different tables (dev's table one way, shared's the other).
  Comparing tables called every cross-VPC flow ASYMMETRIC. The TGW hop now carries `ingress`/`egress` attachments and
  `location.tgw`, and the comparison keys on the TGW: same attachments both ways is symmetric; a reply that leaves by
  another attachment (around an inspection VPC) is still ASYMMETRIC (demo preset `return-asymmetric` unchanged).
- **Verified on the live systems (see gaps-and-roadmap section 1):** V9 (with the fix), V10, V11, and on PAN-OS 11.1 with
  legacy routing over the direct XML API: V1, V3, V4. Not exercised: Panorama (V5, V12-V15), advanced routing (V2), Prisma,
  Cisco. Load balancers and PrivateLink could not be tested: AWS refused `CreateLoadBalancer` in the new lab accounts
  ("This AWS account currently does not support creating load balancers"), so G13's NLB/PrivateLink work waits for that.

## D19. Engine: an unknown internal next hop is INCOMPLETE; return trace has its own budget; max_hops counts hops (2026-11-12)
- **Unknown next hop.** A next hop that is not in the inventory used to end EXITED (exit 0), the same as a declared
  `external` link. Now it ends EXITED only when the next hop is a global address outside every inventory network
  (an INFO `next-hop` hop shows where it left). A private or non-global address, one inside an inventory network, or
  text that is not an IP ends INCOMPLETE (exit 4) with an UNKNOWN `next-hop` hop. **Why:** an un-inventoried internal
  router or a stale discovery cache is not "left the known network"; calling it success was a guess (rule 3).
- **Egress resolution failures** (for example reading the egress interface IP of a VM-Series) become an UNKNOWN
  `error` hop, like a driver failure, instead of INCOMPLETE with no hop.
- **Return trace budget.** `trace_with_return` gives the reverse trace a fresh `Deadline` of the same length and the
  same cancel token (was: what the forward trace left). **Why:** a slow forward trace made a good path end "return
  unverified". Cost: a `--return` trace can take up to twice `--timeout`.
- **`max_hops` counts hops in the result**, not driver steps (one AWS step can add many hops). The default rose from 30
  to 64 so paths that fitted under the old step count still fit. Hops a driver already returned are never truncated.
- **Additive output.** `Hop.elapsed_ms` (first hop of each driver step, and link hops) appears in JSON only when set.
  `Tracer(on_event=...)` receives `step_start` / `hops` / `end` dicts; nothing consumes it yet (a `--return` trace
  emits `end` twice). A raising `progress` or `on_event` callback never breaks a trace.
- **`Clients.close()`** now closes PAN-OS, Panorama, SCM and AWS clients too. Each closes only what it created; a
  session or backend supplied through a transport seam is left alone, and every client stays usable after `close()`.

## D18. Learned links amend D5: tunnel and attachment joins only, two sources or nothing (2026-11-12)
- **Why:** every tunnel, TGW VPN attachment and Prisma service connection must be written by hand under `links:`
  today. The facts already sit in Panorama, the EC2 API, SCM and the devices' own tunnel tables.
- **Amends D5.** Topology still comes from the inventory. A crawler may add links, but only of the kinds in
  `docs/discovery-spec.md` section 9 (device tunnel to AWS VPN, to Prisma service connection, to device tunnel).
  No CDP/LLDP/IGP adjacency, and no login to a device the inventory does not name.
- **Two sources or nothing.** A link is `learned` only when two observations from different sources agree on both ends.
  One source is `inferred`, and an inferred, expired, ambiguous or conflicting link never forwards a trace: the hop is
  UNKNOWN and the trace INCOMPLETE (D6).
- **The inventory wins.** A declared link is always used; a learned link that disagrees is stored and reported,
  never applied. The crawler never writes `inventory.yaml` (`topology show --as-inventory` prints YAML to paste).
- **Accepted defaults (spec section 12):** learned links on once a `topology:` section exists, `--no-learned` to opt out
  (5); a stale link is used with WARN (6); new exit code 5 for `topology diff`, crawl exits 4 when a subject did not
  answer (8); store at `<cache_dir>/topology.json` (9); fresh 1 h, max 24 h, cooldown 15 min, 200 devices, 4 sessions (10).
- **Still open, and nothing depends on them yet:** decision 2 (each guard addition, B6, B7, C1, C2, C4, C11, A1, A2,
  D1 to D5), decision 3 (the AWS role can read VPN pre-shared keys; nettrace drops them with a field keep-list, IAM cannot)
  and decision 7 (Prisma via SCM or Panorama). No guard changes until each is approved; M2 waits for them.
- **Built so far:** M0 and M1 (`src/nettrace/discovery/`: model, policy, store, join, merge), plus pure parsers for every
  observer, the AWS and SCM field keep-lists, the dry-run plan and the topology view. They send nothing. Without a
  `topology:` section no store is read and no trace result changes.
- **SCM keys too.** `ike-gateways` (D4) returns the IKE pre-shared key, so the SCM answer gets a keep-list like AWS.
- **Two tunnels to one device** (every AWS VPN) give a far end that names the device only; the ingress is then inferred
  (WARN), never picked.

## D17. A hop with no route explains itself: BGP and static-route evidence; it never turns a BLOCK into a PASS (2026-11-11)
- **Why:** "no route to X" was true but useless. The next question is always whether BGP never learned it, a
  neighbor is down, or a static route exists but is not installed.
- **Only on the failure path.** The evidence commands run after the router/firewall already said there is no route.
  At most 3 extra Cisco commands (BGP host lookup, BGP summary, static table). PAN-OS: one config `show` of the static-route
  table and one BGP peer `show`. Nothing extra is sent when a route exists.
- **Evidence never changes the verdict, with one exception.** BLOCK stays BLOCK. If BGP shows a best path, or the static table
  marks a matching route active, while the forwarding lookup found none, the sources disagree and nettrace cannot tell which
  is right: the hop is UNKNOWN and the trace INCOMPLETE (rule 3). A policy-routing hop was already UNKNOWN.
- **Unreadable output is "not interpreted", never "no routes".** A command the device rejects (BGP not running, command
  missing on the image) is a detail line. A deadline or cancel is not swallowed.
- **Allowlist (Cisco):** `show ip bgp <ipv4>`, `show ip bgp summary`, `show ip bgp vpnv4 vrf <name> <ipv4>`,
  `show ip bgp vpnv4 vrf <name> summary`, `show ip static route [vrf <name>]`. Not allowed: the bare `show ip bgp` (whole table),
  `show ip bgp neighbors`, received/advertised routes. VRF traces use the vpnv4 forms.
- **Floating statics:** when the route in use is a static with distance other than 1 the label reads `static (distance N)`
  and a detail line says it is a backup route in use.
- **Unverified formats (V17 to V19 in `docs/gaps-and-roadmap.md`).** The static-table reply, the vpnv4 forms and the PAN-OS BGP
  peer reply were written from documentation and memory. The demo simulator answers in the same assumed format, so a green
  test run proves the parsers match the assumptions, not the devices.
- **Demo lab:** the simulator answers the new commands, but the lab routers all have default routes, so no preset reaches the
  no-route branch. Tests drive it with scripted replies that pass through the real read-only guards.

## D16. Return-path trace is opt-in; a blocked return exits 3; NACLs are not "stateful" (2026-11-11)
- **Why:** "why can't A reach B" is often the way back: asymmetric routing through a stateful firewall, or a stateless
  filter that drops the reply (G15).
- **Default off.** It doubles the read-only queries to devices, Panorama and AWS, so it is a flag (`--return`), a checkbox
  and a JSON field, never implicit. The forward JSON and exit codes are unchanged without it.
- **Only after a REACHABLE forward trace.** Otherwise there is no path to compare (NOT_RUN). EXITED is excluded because the
  destination is outside the known networks and the reverse trace would have to start from an address nettrace cannot place.
- **Exit codes:** forward BLOCKED stays 3. Forward REACHABLE + return BLOCKED by a stateless hop is 3 ("return path
  blocked"): the request arrives and the reply is dropped, which is a failed connection. Return INCOMPLETE, or an UNKNOWN
  symmetry, is 4. ASYMMETRIC is 0 with a warning: the traffic is delivered, but a stateful firewall that sees one direction
  drops it in real life, so the warning names the device.
- **A stateful deny on the return flow is not a block.** PAN-OS, Prisma Access and security groups let the reply of an
  established session through whatever their rules say. nettrace matches policy for a new session and does not read session
  tables, so a deny there is reported as INCOMPLETE (symmetry UNKNOWN, exit 4) with the reason spelled out. Only stateless
  hops (NACLs, route lookups, Cisco ACLs) produce a return BLOCKED.
- **NACLs and Cisco ACLs are stateless, so they are not part of the comparison.** A packet is judged on its own at each
  one; which NACL it meets does not depend on what the other direction did. Security groups are stateful but attached to the
  ENI, so both directions meet the same ones.
- **The comparison uses structured fields only** (device, interface, zone, HA serial, component), never summary text, and
  any UNKNOWN makes the symmetry UNKNOWN.
- **Not done:** session-table check, NAT of the return flow beyond what drivers report, ECMP all-paths (G15).
- **Demo lab:** three presets. The lab firewalls got explicit rules for the reply direction because the return flow is
  matched as a new session; a TGW static route sends replies to 10.1.20.0/24 around the inspection VPC (asymmetric); a NACL
  outbound deny to the branch prefix drops the reply (blocked).

## D15. Unmodelled Cisco features are UNKNOWN, not PASS (2026-11-10)
- **Why:** a router hop that printed PASS while NAT, a zone firewall or IPv6 was in play claimed more than nettrace
  checked (G11, G20). Never-guess (AGENTS.md rule 3) says to report what is not evaluated.
- **NAT, zone-based firewall, `ip inspect` on the ingress or egress interface: UNKNOWN, not WARN.** WARN means
  "forwards, but look at this"; here the verdict itself can be wrong. NAT rewrites the addresses the ACLs and
  routes were evaluated against, and a zone policy or inspection rule can drop a flow nettrace passed. UNKNOWN also
  makes the engine downgrade REACHABLE/EXITED to INCOMPLETE, which is the honest result. A feature on an interface
  that is neither ingress nor egress cannot touch the flow and is ignored. A hard ACL deny still ends BLOCKED (the
  deny is a fact about the packet as nettrace saw it; with NAT it may have been evaluated against pre-NAT addresses,
  see "left open" below).
- **Detection uses three new read-only commands**, added to the exact allowlist (`readonly.py`) with tests and
  answered by `sim_cisco.py`: `show ip nat statistics` (interface roles only; never `show ip nat translations`, which
  exposes live host addresses), `show zone security`, `show ip inspect interfaces`. No arguments. `show ip interface`
  does not name inside/outside reliably, so it is not used for NAT.
- **A failed probe is not "feature absent".** `% Invalid input`/`Incomplete command` (image without the feature)
  counts as absent; any other error or unparseable output raises `DeviceError`, so the hop is UNKNOWN. Empty output
  from `show zone security`/`show ip inspect interfaces` means none configured; empty `show ip nat statistics` too.
- **IPv6: UNKNOWN at every entry point** (`steps.ipv6_unknown`: Cisco, PAN-OS, AWS, Prisma), before any command is
  sent. The drivers match IPv4 only (`/32` hosts, wildcard masks, `CidrBlock` without `Ipv6Ranges`), so running them
  on IPv6 would mean guessing. The ACL evaluator raises for IPv6 as a second line of defence.
- **Demo lab:** `GigabitEthernet4` (guest VLAN 40, `ip nat inside`) and presets `guest-nat` and `ipv6-not-evaluated`
  (both expect INCOMPLETE); the original 12 presets are unchanged because only the guest VLAN uses the feature.
- **Left open:** NAT on the outside interface can also change which ACL entry matches an inbound deny; ECMP, PBR,
  uRPF and tunnel protection are unchanged (see the report in G11).

## D14. Web UI login: one-time code, then an HttpOnly session cookie (2026-11-09)
- **Why:** pasting a token (or opening a `#token=` URL by hand) made `serve` awkward, so `--open` was off by default.
  Now `serve` opens the browser by default at `http://127.0.0.1:PORT/?c=<code>`; `--no-open` only prints it.
- **Two secrets.** The long-lived session secret never leaves the server, the cookie and the `X-Nettrace-Token`
  header (kept for tests and scripts). The login code is a separate random value: single use, 60 s, compared in
  constant time, memory only. It does appear in argv (`ps`), which is why it is single-use and short-lived.
  No route mints codes, so an expired code means restarting the command.
- **Cookie:** `nettrace_session=...; HttpOnly; SameSite=Strict; Path=/`. No Domain or Max-Age (session cookie), no
  Secure (plain http on loopback). The redirect response sends `Referrer-Policy: no-referrer` and `no-store`; the
  query string is never logged.
- **CSRF reasoning.** A cookie is sent automatically, so three independent layers keep another site from using it:
  `SameSite=Strict` (not sent on cross-site requests), the existing Origin/Host checks, and the required custom
  header `X-Nettrace-Client: 1`. A cross-site page cannot add a custom header without a CORS preflight, and the
  server never answers preflights or sends CORS headers. POST bodies stay JSON-only. A cookie request without the
  header is refused (403); a token in the query string is still refused.
- **Rejected:** `localStorage`/`sessionStorage` (readable by page script), a token in the URL fragment (the old
  paste flow), and an endpoint that issues fresh codes (it would be an unauthenticated route).

## D13. Never-guess gaps closed, bounded waits, SSH/TLS edges (2026-11-08)
- **An unanswered question is not "no".** `PanosClient.config_get` returns `Unavailable(reason)` when the
  device errors or times out, and `None` only when the device answered "not configured". `_lookup`
  raises `DeviceError` (hop UNKNOWN, trace INCOMPLETE) when nothing was found and any query went
  unanswered. A hit after a failed query still wins.
- **Prisma:** a deny reached below rules nettrace could not evaluate is UNKNOWN, not BLOCK (an earlier
  rule might have allowed it). An app that is not listed in a rule is uncertain when the rule lists an
  application group or filter, or when those objects can't be read. Known assumption kept:
  `application-default` with `--application` is taken to mean the app's standard port.
- **Cisco:** ECMP (several CEF next hops) is WARN and lists every path; only the first is followed.
  Policy routing on the ingress interface (`Policy routing is enabled, using route-map X` in
  `show ip interface`, which the ntc template drops) is WARN, and a no-route/discard result there is
  UNKNOWN, since PBR may rescue it. Route-maps are not evaluated.
- **Time budget:** one `Deadline` per trace (default 120 s; inventory `trace_timeout`, CLI `--timeout`).
  Every request path checks it before sending; expiry raises `DeadlineExceeded`, which the engine turns
  into an UNKNOWN hop plus INCOMPLETE, keeping the hops so far. A request already in flight is bounded
  by its own timeout, not interrupted. botocore uses connect 5 s, read 20 s, standard retries x3.
  PAN-OS POSTs and SCM GETs retry once, on a timeout only (everything is read-only, so a retry has no
  side effects; the token POST is never retried).
- **Overlapping IP space:** `find_eni` takes an optional `vpc_id` filter. Several distinct ENIs for one
  IP raise `AmbiguousEni` listing them (the same ENI seen from two accounts counts once); nettrace does
  not pick one.
- **SSH:** a paramiko `SSHException` from the host-key check becomes a `DeviceError` (not in known_hosts:
  ssh once to verify; changed key: possible spoofing). `ssh_strict: false` is still not advised.
- **TLS:** `verify_tls: false` under `defaults:` or `panorama:` is refused unless
  `NETTRACE_ALLOW_INSECURE_TLS=1`; per-device `false` still works (with the warning). A string must be
  an existing CA bundle path at inventory load.
- **Cisco commands are an allowlist, not a deny list (re-audit R1):** IOS accepts abbreviations (`show run`),
  so `readonly.check_cisco_command` matches only full-word commands (a short fixed set plus IP / `safe_token`
  arguments) and the web console uses the same guard. The demo simulator expands abbreviations like IOS.
- **The AWS session policy fails closed (R6):** it ships as package data (`nettrace/data/`, equal to `iam/`;
  a test checks it) and AssumeRole is refused if it cannot be loaded or exceeds 2048 characters, unless
  `NETTRACE_ALLOW_NO_SESSION_POLICY=1`.

## D12. Demo lab simulates transports; web UI is a local stdlib server (2026-11-08, v0.4.0)
The owner asked for a demo architecture to show the tool off, with a live localhost UI in the
style of Packet Tracer, CML or NetBrain.
- **Simulate below the guards, not above them.** Four seams were added: the Cisco connection, the
  XML API session, the SCM page fetch and the AWS backend. Everything above them (drivers, engine,
  read-only guards, Panorama HA follow, NAT lookup chain) is the production code. The demo exercises
  it rather than a parallel fake, and a console "write" in the demo is refused by the real guard.
- **Simulators compute from one model, not canned replies.** Routing, ACLs, PAN-OS rule and NAT
  matching and AWS filters are all evaluated from `demo/lab.py`, so arbitrary flows work and
  the presets don't drift from the model.
- **The AWS simulator replaces moto for the demo.** moto can't do cross-account TGW, leaves
  `TransitGatewayAttachments` empty in route searches, and lacks some ENI filters (see G17
  notes). The lab needs three accounts on one TGW. A small Describe/Search responder with
  per-account visibility is about 150 lines and deterministic. moto is still fine for unit-style tests.
- **stdlib `http.server`, no web framework or front-end build.** This adds no dependencies and keeps
  the attack surface auditable. The page is a single HTML file with inline JS and SVG and works
  offline.
  - The server binds to localhost only and requires a per-run session on every API call (see D14).
  - It checks the Host header against DNS rebinding and the Origin header against cross-site requests.
  - Bodies must be JSON (which rules out form-post CSRF), and are size-limited.
- **Hand-placed topology for the demo, generated grid for real inventories.** A readable NetBrain or
  CML style canvas needs positions. Real inventories get a wrapped grid until saved layouts exist
  (roadmap R10).

## D11. Path maps are rendered from trace JSON, as offline files (2026-11-08, v0.3.0)
The user asked for a NetBrain-style visualizer. Choices:
- **Input is the saved trace JSON.** The renderer reads `TraceResult.to_dict()`, not live objects.
  A trace saved today renders identically later, traces can be shared and rendered on another
  machine, and the map can't trigger new device queries.
- **Static files, not a server.** The output is one `.html` (or `.svg`) with no CDN, web fonts or
  external scripts, plus a restrictive CSP. This works on air-gapped jump hosts, can be attached to
  tickets, and can't leak trace data (device configs, IPs) to third parties. A local server is
  roadmap R9.6, and it needs auth even on localhost.
- **No graph library.** The path is a sequence, so a deterministic single-row layout is enough and
  keeps the output stable between runs. A general graph layout (dagre, ELK, Graphviz) only becomes
  worth it with ECMP branches or topology context (R9.5, R9.7).
- **Checks are badges on links, not nodes.** SGs and NACLs filter traffic on a link rather than
  forwarding it. Drawing them as nodes doubled the node count and hid the forwarding path, which is
  what NetBrain users read first.
- **Hop locations were added to the data model** (`Hop.location`), instead of parsing strings like
  `account network (1111)` out of hop details. Grouping by site, account and VPC needs structured
  data. The field is additive and optional, so older trace JSON still renders, just without boxes.

## D10. Panorama as a proxy, firewall as the authority (2026-11-06, v0.2.0)
Firewalls are queried *through* Panorama (`target=<serial>`), not modelled from Panorama's
configuration. Reasons:
- **Live and authoritative.** The firewall still answers the policy, NAT and FIB tests itself. Its
  dynamic routes, pushed policy and local overrides are all included, as in D2.
- **Fewer moving parts.** One API key and one reachable endpoint replace a management path and key
  for every firewall.
- **One trustworthy source of HA state.** Panorama's `show devices all` reports it, so a passive member
  can be swapped for the active peer. The trace then reflects the box that actually forwards.

Policy tests are never sent to Panorama without `target`. Panorama's own "Test Policy Match" has a
documented failure mode (PAN KB: "Server error" when a source zone is given), and it can't see
firewall-local state anyway.

Panorama's device-group config is used only as a lookup fallback, to display NAT translations and
rule actions when the firewall's own config doesn't show the rule. It never decides a verdict.

`via: direct` stays supported for firewalls that aren't on Panorama or for troubleshooting Panorama
itself. `via` defaults to `panorama` whenever a serial and a `panorama:` section are both present.

## D9. Panorama exists but wasn't available during the build (2026-11-06)
The owner has a Panorama. "No live one to check against" meant none was reachable while building,
not that none exists. v0.1.0 was built direct-to-firewall on the mistaken reading that there was no
Panorama. v0.2.0 added Panorama support (see D10). The Panorama code was tested only against a
simulated Panorama whose XML shapes come from PAN docs and pan-os-python. Items V12–V16 in
`docs/gaps-and-roadmap.md` list what to confirm on the real one.

## D8. Exit codes encode the verdict
`trace run` exits 0 for REACHABLE/EXITED, 3 for BLOCKED, 4 for INCOMPLETE, 1 for errors and 2 for
usage errors. This lets scripts and CI gates use nettrace without parsing output. EXITED counts as
success because "left our network toward the internet / unmanaged hop" isn't a failure of anything
nettrace checks. Neither counts as success when the path crossed an UNKNOWN hop: the engine then
reports INCOMPLETE (exit 4), because a component nettrace skipped is not a verified pass.

## D7. Global options can go anywhere (AWS CLI parity)
The owner asked for AWS-CLI-like syntax. In the AWS CLI, `--output` and `--query` can follow the
subcommand. Click only accepts group options before the subcommand, so `cli.hoist_global_options`
moves `--output/-o`, `--query`, `--inventory/-i`, `--no-color` and `--debug` to the front.
`--query` uses JMESPath on the JSON form, as the AWS CLI does.

## D6. Uncertain is a first-class result
Firewall and ACL verdicts that depend on things nettrace can't see (App-ID, user groups,
object-groups, FQDN/dynamic objects, URL categories, HIP) are reported as UNKNOWN or WARN with the
reason. A confident wrong answer in a troubleshooting tool is worse than "can't tell". Don't "simplify"
this into assume-match or assume-no-match.

## D5. Topology comes from a YAML inventory plus discovery, not from L2/LLDP
The owner chose a YAML inventory. Next-hop -> device mapping uses static `addresses` and a discovery
cache filled by `inventory discover` (interface IPs read via show commands). Domain boundaries (IPsec
or DX to a TGW, Prisma service connections) are explicit `links`, because those can't be inferred
reliably from one side.

## D4. Credentials only from environment variables
The owner chose env vars. The inventory names the variable for each device (`*_env`) so different
devices can use different keys. For AWS, standard credential resolution provides the base identity,
which then assumes a per-account read-only role.

## D3. Read-only enforced in code, not only by credentials
Credentials can be over-privileged by mistake. `readonly.py` adds an independent guard per
transport. For AWS it is a botocore `before-call` hook, so even a coding mistake that calls a
mutating API is stopped before the request is signed. Reachability Analyzer and Network Access
Analyzer are excluded on purpose: they create `NetworkInsightsPath` / `Analysis` resources and are
billed per analysis, so they fail the read-only requirement.

## D2. Live queries per hop, with the device as the authority where possible
The owner wants current state ("pull from every part of the path"), not a model of saved configs.
- PAN-OS hops ask the firewall: `test routing fib-lookup`, `test nat-policy-match`,
  `test security-policy-match`. This captures Panorama-pushed policy, dynamic routes and the
  firewall's own match logic.
- Cisco hops use `show ip cef` (the forwarding table, not just the RIB) plus ACL evaluation.
- AWS is evaluated from Describe/Search calls, because the AWS control plane *is* configuration.
- Prisma Access is evaluated from config because no live policy-test API was found.

## D1. Build on libraries, not on an existing path-analysis platform
Existing tools were evaluated before building:
- **Batfish**: supports Cisco, PAN-OS and AWS configs and has a traceroute question. Rejected as the
  core because it models saved configs instead of querying live devices, doesn't cover Prisma Access,
  lists PAN-OS Advanced Routing as unsupported, and needs a heavyweight service (Docker, 8–32 GB RAM).
  It is still a candidate for a future offline "what-if" mode.
- **SuzieQ**: live polling of IOS-XE and PAN-OS with a `path show`, but no AWS, its path view ignores
  firewall policy, and it needs a constantly running poller.
- **AWS Reachability Analyzer**: AWS-only, same-region source and destination, and not read-only (see D3).
- **AHEAD-Ansible/ansible-nautobot-network-path-troubleshooting**: a similar hop-walker design, but it
  has no license file and is tied to Nautobot. Used only as a design reference; no code was copied.
- **Palo Alto's `pan-os-ansible` / `ansible_panos_policy_orchestration`**: used as references for the
  `test ...-policy-match` and fib-lookup XML formats (including the PAN-OS 8.1 `msg/line` response
  shape).
- **`pan-scm-sdk`**: used as a reference for SCM endpoints, paging and field names. Not taken as a
  dependency, to keep the GET-only surface small and auditable.

What was used: Netmiko (SSH), ntc-templates/TextFSM (Cisco parsing), boto3, requests + defusedxml,
click, rich and jmespath.
