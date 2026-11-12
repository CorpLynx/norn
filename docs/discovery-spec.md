# Crawler and auto-discovery spec

Status: DRAFT 2. D18 in `docs/decisions.md` amends D5 and records decisions 1, 4, 5, 6, 8, 9 and 10
(section 12). Decisions 2, 3 and 7 (guard additions, VPN pre-shared keys, Prisma management) are
still open, so nothing in section 6 is applied. M0 and M1 are built, plus the pure half of M2 and
M3: the observers' parsers, the AWS and SCM field keep-lists, the dry-run plan and `TopologyView`
(section 13). Nothing is wired to a transport, the engine or the CLI yet; that waits for decisions
2 and 3.

This spec turns `docs/topology-discovery-design.md` (the design, with the full rationale, command
tables and threat model) into something that can be built and tested. Where the two disagree, this
file wins; section 2 lists what changed since the design was written.

## 1. What gets built

The crawler learns the links that today must be written by hand under `links:` in the inventory,
and uses them in traces only when two independent sources agree.

Version 1 (this spec) covers:

- **Control-plane facts**: Panorama device list, AWS VPN / customer gateway / TGW attachment facts,
  Prisma Access service connections and remote networks.
- **Tunnel observations** on inventory devices: Cisco tunnel interfaces and crypto sessions, PAN-OS
  VPN flows.
- **Joins** that turn those into links: device tunnel to AWS VPN (TGW or VGW), device tunnel to
  Prisma service connection, device tunnel to device tunnel.
- A **store**, a **CLI** (`nettrace topology crawl | show | diff | clear`) and the **engine hook**
  that lets a trace use a learned link.

Not in version 1 (each is a later, separately approved step): CDP/LLDP/BGP/OSPF adjacency, logging
in to devices that are not in the inventory, Direct Connect, learned `networks`, refresh-on-miss
during a trace, any web UI crawl trigger, scheduled crawls.

## 2. What changed since the design

| Design said | Code today | Effect on this spec |
|---|---|---|
| The Cisco guard accepts any `show ...`, so nothing needs adding | `readonly._CISCO_ALLOWED` is an exact allowlist of 12 patterns | Discovery commands are refused today. They must be **added** (section 6), as a separate discovery list |
| Duplicate IPs in the discovery cache overwrite silently (P0 prerequisite) | Done: `Inventory.ambiguous`, `ambiguous_owners()`, UNKNOWN next-hop hop, validated and locked cache (R18, G17a) | Removed from the work list. The store reuses `_cache_lock` and the atomic-write pattern in `merge_discovered` |
| The AWS backend seam has no `service` argument | `AwsEnv.call(account_id, region, op, service="ec2", **params)` | No seam change needed for version 1 |
| Record the amendment as D14 | D14 to D17 are taken | Recorded as D18 |
| (not covered) | `CiscoClient._auth_failed` holds `time.monotonic()` values | A monotonic clock cannot be persisted across processes; the persisted cooldown stores wall-clock time (moved to M2, where the crawler first needs it) |
| 12 demo presets | 17 presets, including return-path ones | The golden test covers all of them |

Still true from the design and relied on here: the PAN-OS guard accepts any `<show>` tree, SCM has
no endpoint allowlist, the Cisco auth-failure cooldown is per process, and every PAN-OS, SCM and
new AWS response shape is **unverified on real equipment**.

## 3. Rules the crawler must keep

These restate the hard rules for this feature. A change that breaks one is rejected.

1. Every request goes through `CiscoClient.show`, `PanosClient.request` / `PanoramaClient`,
   `AwsEnv.call` or `ScmClient.get_all`, so the existing guards, deadline and audit apply. The
   crawler adds a second, narrower check on top (section 6). It never uses the web console path.
2. The crawler contacts only what the inventory names: its devices, its Panorama, its AWS accounts
   and regions, its SCM tenant. A neighbour it hears about is recorded, never contacted.
3. A link is **learned** only when two observations from different sources agree on both ends and
   both queries were answered. One-sided is **inferred** and never forwards a trace.
4. A declared link (inventory YAML) always wins. Disagreement is reported, never silently applied.
5. A query that failed is not evidence of absence. A failed device deletes nothing.
6. A parser that cannot parse raises `DeviceError`. It never returns "no rows".
7. Everything a device says about a neighbour is untrusted text: length-capped, control characters
   stripped at parse time, used as a join key only if it is an IP that parses or a `safe_token`.
8. No secret is stored, logged or shown. `DescribeVpnConnections` responses pass a field keep-list
   before the cache, evidence and audit (section 6.3).
9. No demo branches. Simulators grow new answers below the four transport seams.

## 4. Vocabulary

| Term | Meaning |
|---|---|
| Observation | One parsed fact from one answered request, with where and when it came from |
| Candidate | A neighbour name or address seen in an observation that is not an inventory object |
| Join | A rule that pairs two observations into a link |
| Origin | `declared` (inventory), `learned` (two sources agree), `inferred` (one source or a heuristic) |
| Store | The JSON file holding observations' digests and the links built from them |
| View | What the engine asks: declared links merged with usable learned links |

## 5. Code layout

```
src/nettrace/discovery/
  policy.py     CrawlPolicy: limits and switches from the inventory `topology:` section
  model.py      Observation types, Provenance, LearnedLink, link ids
  observe/
    cisco.py    tunnel interfaces, crypto sessions      -> Observations
    panos.py    vpn flow, interfaces; Panorama devices  -> Observations
    aws.py      VPN connections, customer gateways, TGW attachments, VGWs -> Observations
    scm.py      service connections, remote networks, IKE gateways, IPsec tunnels -> Observations
  join.py       pure functions: Observations -> candidate links (no I/O)
  merge.py      pure functions: candidate links + declared links + previous store -> new store state
  store.py      TopologyStore: load (validated), save (atomic, locked), TTL state
  crawl.py      Crawler: orchestration, limits, audit begin/end
  view.py       TopologyView: link lookups for the engine
```

Changes outside the package: `readonly.py` (discovery allowlists), `inventory.py` (`topology:`
section, `Link` gains optional fields), `engine.py` (`_resolve_egress` asks the view),
`drivers/aws.py` (scrubber hook in `_boto_call_once`), `drivers/prisma.py` (endpoint allowlist),
`cli.py` (`topology` group), the four simulators, `iam/nettrace-readonly-policy.json`.

`join.py` and `merge.py` do no I/O and take the clock as an argument. Most of the tests live there.

## 6. Guards

Nothing here is applied until the owner approves each line (section 12, decision 2).

### 6.1 Cisco

A second list, `_CISCO_DISCOVERY`, checked by a new `check_cisco_discovery_command`. The crawler
uses a dedicated client class, `DiscoveryCiscoClient(CiscoClient)`, whose `show` checks the
discovery list and then calls the normal guarded `show`. A flag argument on `CiscoClient.show` was
rejected: one wrong default would open the discovery list to trace and console calls. Trace and
console code never constructs the discovery class. The same pattern applies to PAN-OS (6.2).

| Id | Pattern | Already in `_CISCO_ALLOWED` |
|---|---|---|
| B1 | `show version` | yes |
| B2 | `show vrf` | yes |
| B3 | `show ip interface brief` | yes |
| B6 | `show interfaces Tunnel<1-10 digits>` | no |
| B7 | `show crypto session` | no |

`show crypto session` prints peers and session status, not keys. Unverified: its exact IOS-XE
output. Later phases add B4, B5, B8–B16 from the design; they are not requested now.

### 6.2 PAN-OS and Panorama

`check_panos_discovery_request`: exact `<show>` trees, applied to crawler calls in addition to
`check_panos_request`. No `<test>`, no `type=config`.

| Id | Request | Sent to |
|---|---|---|
| C1 | `<show><system><info></info></system></show>` | firewall (`target=serial` or direct) |
| C2 | `<show><interface>all</interface></show>` | firewall |
| C4 | `<show><vpn><flow></flow></vpn></show>` | firewall |
| C11 | `<show><devices><all></all></devices></show>` | Panorama only |

### 6.3 AWS

Two additions to `_AWS_ALLOWED` and to the IAM policy (also the STS session policy; it stays far
under 2048 characters):

- A1 `ec2:DescribeVpnConnections`
- A2 `ec2:DescribeCustomerGateways`

A1 returns VPN pre-shared keys (`CustomerGatewayConfiguration`, and tunnel options). IAM cannot
filter fields. So a **field filter** runs in `AwsEnv._boto_call_once` and in the backend path, before
the per-run cache, `Evidence` and anything else sees the response. It is a keep-list, not a list of
fields to remove: a field AWS adds later, or one this spec missed, is dropped by default.

```python
_KEEP = {("ec2", "DescribeVpnConnections"): {
            "VpnConnections[]": ("VpnConnectionId", "CustomerGatewayId", "TransitGatewayId",
                                 "VpnGatewayId", "State", "Type"),
            "VpnConnections[].VgwTelemetry[]": ("OutsideIpAddress", "Status"),
            "VpnConnections[].Options.TunnelOptions[]": ("OutsideIpAddress",)},
         ("ec2", "DescribeCustomerGateways"): {
            "CustomerGateways[]": ("CustomerGatewayId", "IpAddress", "State")}}
```

Every other key in those responses is removed. If the owner rejects A1, AWS VPN links stay declared
and the AWS join in section 9 is not built.

### 6.4 Strata Cloud Manager

Today only the HTTP method is checked. Add `check_scm_endpoint(path)`: an exact list of GET paths.

- D1 the five paths `drivers/prisma.py` already calls (behaviour unchanged)
- D2 `/config/deployment/v1/service-connections`
- D3 `/config/deployment/v1/remote-networks`
- D4 `/config/network/v1/ike-gateways`
- D5 `/config/network/v1/ipsec-tunnels`

D2–D5 are unverified paths. If Prisma Access turns out to be Panorama-managed (roadmap R2), the SCM
observer is replaced, not extended.

D4 (`ike-gateways`) returns the IKE pre-shared key (`authentication.pre_shared_key`). The SCM answer
gets a keep-list too (`discovery/observe/scm.py` `keep_scm_fields`): `ike-gateways` keeps only
`name` and `peer_address.ip`, `ipsec-tunnels` only `name` and the gateway names. Decision 3 covers
this key as well as the AWS one.

## 7. Data contracts

### 7.1 Observations (`model.py`)

All frozen dataclasses. Every one carries `prov: Provenance`.

```python
@dataclass(frozen=True)
class Provenance:
    source: str        # "cisco:show crypto session" | "panos:show vpn flow" | "aws:ec2.DescribeVpnConnections" | ...
    subject: str       # inventory device name | "aws:<account>/<region>" | "panorama" | "scm"
    observed_at: float # local clock; a device's clock is never trusted
    run_id: str        # matches the audit log
    digest: str        # sha256 of the normalised fragment; raw output is not stored

class TunnelEnd:       # a device's own tunnel interface
    device, interface, local_ip, peer_ip, kind ("ipsec"|"gre"), oper ("up"|"down"|"unknown"), prov
class AwsVpn:          # one tunnel of one VPN connection
    account, region, vpn_id, outside_ip, cgw_ip, tgw_id | None, vgw_id | None, tgw_attachment | None, oper, prov
class PrismaTunnel:    # one service connection or remote network
    name, kind ("service_connection"|"remote_network"), peer_ip (customer side), prov
class ManagedFirewall: # from Panorama
    serial, hostname, mgmt_ip, model, connected, ha_peer_serial | None, prov
class Unanswered:      # a query that failed; blocks "absent" conclusions for its subject
    subject, source, reason, prov
```

Interface names are normalised before they are stored (`Tu100` and `tunnel100` become `Tunnel100`;
PAN-OS names are lower-case). `Inventory.link_from_device` gets the same normalisation, because it
compares lower-cased raw strings today.

### 7.2 Links

`inventory.Link` gains optional fields with defaults, so existing YAML and constructors behave as
they do now:

```python
origin: str = "declared"          # declared | learned | inferred
kind: str = "unknown"             # ipsec | gre | aws-vpn | prisma
oper: str = "unknown"             # up | down | unknown
id: str = ""                      # sha256(kind + sorted canonical ends)[:16]
provenance: tuple[Provenance, ...] = ()
first_seen: float = 0.0
last_confirmed: float = 0.0
absent_since: float | None = None
conflicts: tuple[str, ...] = ()
```

`LinkEnd` is unchanged, so `Tracer._from_link_end`, `AwsWalker` and `prisma.step` need no change.

### 7.3 Store file

`<cache_dir>/topology.json` (`NETTRACE_CACHE_DIR`, default `~/.cache/nettrace`), beside
`addresses.json`. Directory 0700, file 0600, written with the temp-file-then-`os.replace` pattern
under `_cache_lock`, never following a symlink.

```json
{"schema": 1,
 "runs": [{"id": "c9f1...", "started": 1794400000.0, "ended": 1794400041.2,
           "subjects_ok": ["core-rtr1", "aws:network/us-east-1"], "subjects_failed": {"fw-dc1": "timeout"}}],
 "links": [{"id": "5b0c...", "kind": "aws-vpn", "origin": "learned", "oper": "up",
            "a": {"device": "fw-dc1", "interface": "tunnel.1"},
            "b": {"aws": {"tgw_attachment": "tgw-attach-0abc", "account": "network", "region": "us-east-1"}},
            "provenance": [{"source": "panos:show vpn flow", "subject": "fw-dc1", "observed_at": 1794400012.0,
                            "run_id": "c9f1...", "digest": "ab12..."}],
            "first_seen": 1794300000.0, "last_confirmed": 1794400012.0, "absent_since": null, "conflicts": []}],
 "candidates": [{"seen_by": "core-rtr1", "address": "198.51.100.9", "note": "tunnel peer, not in inventory"}]}
```

The file is untrusted on load: schema-checked, at most 5 MiB, at most 5000 links, device names must
exist in the inventory, addresses must parse. A file that fails any check is ignored with a warning
and treated as empty; it is never partly used. Only the last 5 runs are kept.

### 7.4 Inventory section

```yaml
topology:
  use_learned: true          # traces may use learned links (decision 5)
  ttl_fresh: 3600            # seconds: use without comment
  ttl_max: 86400             # older than this: treated as inferred
  crawl:
    timeout: 600
    max_devices: 200
    device_sessions: 4       # concurrent devices
    command_gap: 1.0         # seconds between commands to one device
    device_budget: {seconds: 60, commands: 40}
    row_cap: 2000            # rows kept per command; more is a DeviceError
    aws_concurrency: 8
    cooldown: 900            # seconds between crawls of one device unless --force
```

The whole section is optional. Without it nothing changes: no store is read and traces use declared
links only.

## 8. Crawl procedure

```
1. Load inventory and policy. run_id = 16 random hex bytes. Enter audit.mode("crawl").
   audit: "begin run=<id> scope=<...> limits=<...>".
2. Control planes, in parallel, each bounded by the crawl Deadline:
     Panorama  -> ManagedFirewall[]
     AWS       -> AwsVpn[] for every inventory (account, region)
     SCM       -> PrismaTunnel[]
   Any failure -> Unanswered(subject, ...), crawl continues.
3. Devices: every inventory device with platform cisco_iosxe or panos (or only --device ones).
   One session each, at most `device_sessions` at a time, `command_gap` between commands, and the
   per-device budget. Skip a device inside its cooldown unless --force.
     Cisco:  show ip interface brief -> for each Tunnel<n>: show interfaces Tunnel<n>; show crypto session
     PAN-OS: show interface all; show vpn flow
   A parse failure rejects that device's whole observation set for this run (Unanswered).
4. join(observations) -> candidate links.     (pure)
5. merge(candidates, declared, previous store, now) -> new store state.   (pure)
6. Save the store. audit: "end run=<id> devices=N ok=.. failed=.. links=.. new=.. changed=..".
7. Print the summary table. Exit 0 if every subject answered, 4 if any did not, 1 on error.
```

`crawl --dry-run` performs step 1, prints every request it would send per subject, and stops. It
sends nothing and writes nothing.

Authentication failures: two failures for one credential (the Cisco user, the Panorama key, the SCM
client, one AWS role) stop that credential for the rest of the run. The Cisco per-device cooldown
(`AUTH_COOLDOWN`) is persisted in the store so a second process honours it.

## 9. Joins (version 1)

Addresses never used as join keys: `169.254.0.0/16`, loopback, multicast, `0.0.0.0`.

| Link | Observation A | Observation B | Result |
|---|---|---|---|
| Device tunnel to AWS VPN | `TunnelEnd(device D, interface I, local L, peer P)` | `AwsVpn(outside_ip = P, cgw_ip = L)` | **learned**, far end = the TGW attachment whose resource is that VPN, else the VGW. If P matches and `cgw_ip` does not (NAT in front of D): **inferred** |
| Device tunnel to Prisma | `TunnelEnd(D, I, local L, ...)` with an up session | `PrismaTunnel(peer_ip = L)` and L is owned by exactly one inventory device (D) | **learned**, far end = that service connection. SCM alone: **inferred** |
| Device tunnel to device tunnel | `TunnelEnd(D1, I1, local L1, peer P1)` | `TunnelEnd(D2, I2, local L2 = P1, peer P2 = L1)` | **learned**. One side only: **inferred** |

Ambiguity: if one `(device, interface)` end matches two different far ends, neither link is
learned; both are stored as inferred with `conflicts` naming each other. Seen from the AWS or Prisma
end, two tunnels to the same device are not a conflict (a VPN connection has two tunnels); tunnels
to two different devices are.

Notes on the joins as built in M1:

- Join keys are IPv4 only (IPv6 is not evaluated anywhere in nettrace).
- A TGW VPN whose attachment id is not known yields no link: the engine looks AWS links up by
  attachment id, so the far end would be unusable. Its device end is listed as a candidate.
- Only service connections join. `LinkEnd` has no remote-network field and the engine never leaves
  a device towards a remote network, so remote networks are observed but not joined.
- A tunnel whose peer is an inventory device that reported no matching tunnel gives an inferred
  link to that device (no interface). A peer that is nowhere in the inventory is a candidate.

## 10. Merge and freshness

Applied in order, for each end of each candidate:

1. A declared link names this end: the declared link is used. If the candidate agrees, its
   provenance is attached to the declared link ("declared, confirmed"). If it disagrees, the
   declared link gets `conflicts`, and the candidate is stored but never used. The store keeps the
   confirmation or conflict as a record with `origin: declared` and the declared link's `name`,
   because a declared link has no stable id of its own (YAML may name a `next_hop`, not an
   interface). "Agrees" means both ends are the same kind and every field set on both is equal
   (interface names normalised).
2. No declared link: the candidate is stored with its origin.
3. A stored learned link not seen in this run: if **both** its subjects answered, set
   `absent_since`; after two such runs it is removed. If either subject did not answer, it is left
   untouched.

Freshness of a learned link, from `last_confirmed`:

| Age | State | Trace behaviour |
|---|---|---|
| under `ttl_fresh` | fresh | used; the hop shows the age |
| `ttl_fresh` to `ttl_max` | stale | used, hop status WARN "learned N hours ago; run `nettrace topology crawl`" |
| over `ttl_max` | expired | treated as inferred |

(The design's refresh-on-stale is deferred with refresh-on-miss. Until then a stale link warns.)

## 11. Engine and output

`TopologyView(inventory, store, now)` offers the three lookups the engine already uses and returns
the same `(Link, LinkEnd)` shape, plus a reason when it declines:

```python
view.from_device(device, interface, next_hop) -> Found(link, far_end) | Unusable(reason, candidates) | None
view.from_aws(resource_id)                    -> same
view.from_prisma(service_connection)          -> same
```

- `Found`: declared, or learned and not expired, and unambiguous.
- `Unusable`: the only matches are inferred, expired, absent from the last crawl (`absent_since`
  set), in conflict, or lead to different places.
- `None`: nothing known. The engine carries on exactly as today.

Several learned links from one end to the **same device** (an AWS VPN connection always has two
tunnels, so `from_aws(attachment)` finds both) are `Found` with a far end that names the device but
no interface, plus a detail note listing the tunnels. The engine then treats the ingress interface
as inferred (WARN, as today for a Cisco ingress inferred from the route back); it never picks one.

`Tracer._resolve_egress`, `AwsWalker._leave_via` and `prisma.step` call the view instead of
`Inventory.link_from_*`. On `Unusable` the engine emits one hop
(`domain="engine"`, `component="link"`, status UNKNOWN, summary = the reason and the candidates) and
the trace ends INCOMPLETE. That is the never-guess rule applied to links.

Link hops gain an optional field; nothing existing changes:

```json
"link": {"origin": "learned", "age_s": 742, "oper": "up",
         "sources": ["panos:show vpn flow", "aws:ec2.DescribeVpnConnections"]}
```

The hop summary ends with `[declared]`, `[declared, confirmed 12m ago]` or `[learned 12m ago]`. A
declared link with `conflicts` makes the hop WARN and lists the disagreement in `details`.

`trace run --no-learned` ignores the store (today's behaviour).

### CLI

```
nettrace topology crawl [--device NAME]... [--scope control-plane|devices|all] [--no-aws] [--no-prisma]
                        [--timeout S] [--force] [--dry-run]
nettrace topology show  [--origin declared|learned|inferred] [--stale] [--device D] [--as-inventory] [-o table|json|text]
nettrace topology diff                    # learned vs declared: not-declared, not-observed, conflicts
nettrace topology clear                   # deletes only topology.json
```

`show --as-inventory` prints `links:` YAML for the owner to paste; the crawler never writes
`inventory.yaml`. `diff` exits 0 when there is nothing to report and 5 when there is.
`show` output written to a file goes through `cli.write_private`.

The web UI gets nothing in version 1. `auto_topology` keeps drawing declared links.

## 12. Decisions needed from the owner

The spec assumes the recommended answer in each row. Changing one changes the listed sections.

| # | Decision | Recommended | Affects |
|---|---|---|---|
| 1 | Amend D5 to allow learned links at all | yes, tunnel and attachment joins only | everything |
| 2 | Approve guard additions B6, B7; C1, C2, C4, C11; A1, A2; D1–D5 | approve each | section 6 |
| 3 | Accept that the AWS role can read VPN pre-shared keys (scrubbed by nettrace, not by IAM) | accept, or keep AWS VPN links declared | 6.3, first join in 9 |
| 4 | Inferred links | never forward a trace (UNKNOWN) | 9, 11 |
| 5 | Learned links in traces | on by default once a `topology:` section exists, `--no-learned` to disable | 7.4, 11 |
| 6 | Stale learned link | used with WARN | 10 |
| 7 | Prisma Access management: SCM or Panorama (V6) | must be answered before the SCM observer is built | 6.4, second join in 9 |
| 8 | New exit code 5 for `topology diff`; crawl exits 4 when a subject did not answer | accept | 8, 11 |
| 9 | Store location | `~/.cache/nettrace/topology.json` | 7.3 |
| 10 | Defaults: fresh 1 h, max 24 h, cooldown 15 min, 200 devices, 4 sessions | accept | 7.4 |

## 13. Milestones

Each milestone leaves the test suite green and changes no trace result unless a `topology:` section
is present.

| # | Deliverable | Done when |
|---|---|---|
| M0 | Decision record. `model.py`, `store.py`, `policy.py`, `Link` fields, interface-name normalisation | Store round-trips; a corrupt, oversized, symlinked or wrong-schema file is ignored with a warning; all existing tests pass unchanged. (Persisted auth cooldown moved to M2: nothing crawls before then.) |
| M1 | `join.py`, `merge.py` with unit tests only (hand-built observations, injected clock) | Every row of sections 9 and 10 has a test, including each ambiguity and "unanswered is not absent" |
| M2 | Guards (6.1–6.4), AWS scrubber, observers, simulator answers, `topology crawl` and `--dry-run`, `topology show` | A recorder on each seam shows every crawl request matches a discovery list; `show running-config`, a `<request>` and an unlisted AWS call from crawler code raise `ReadOnlyViolation`; the sentinel pre-shared key appears in no cache file, evidence, audit line or CLI output; audit has `"mode":"crawl"` on every line plus begin and end |
| M3 | `view.py`, engine hook, hop `link` field, `--no-learned`, `topology diff` and `clear` | **Golden test:** with the lab's learnable `links:` removed, a crawl through the seams learns them, and every demo preset gives its `expect` outcome. With an expired or one-sided link the same presets end INCOMPLETE with an UNKNOWN link hop |
| M4 | Hostile-input tests: 5000 tunnel rows, control characters and markup in names, duplicate addresses, a hung device, two auth failures | Caps raise `DeviceError`; nothing unescaped reaches the terminal, JSON or audit log; the fake connection is opened at most twice |

Only `dc1-internet` (an `external` link) stays declared in the lab; it cannot be learned.

Built ahead of the wiring (all pure, tested in `tests/test_discovery_observe.py`): `observe/cisco.py`,
`observe/panos.py`, `observe/aws.py` (with `keep_fields`), `observe/scm.py` (with `keep_scm_fields`),
`plan.py` (the `--dry-run` request list, each line tagged with its guard id) and `view.py`. Left for
M2 once decisions 2 and 3 are made: the guard entries, `DiscoveryCiscoClient`, wiring the keep-lists
into `AwsEnv` and `ScmClient`, `crawl.py`, the persisted auth cooldown, simulator answers and the
CLI. Left for M3: the engine hook (`engine.py` is being changed by other work; wire it after that lands).

## 14. To verify on real equipment

Add these to the V-list in `docs/gaps-and-roadmap.md` when building. Until each is checked, its
parser is a guess and its fixture is synthetic.

- IOS-XE: `show interfaces Tunnel<n>` (source, destination, protection lines) and `show crypto session` output.
- PAN-OS: tag names in `<show><vpn><flow>` and whether `localip` / `peerip` are present through Panorama `target=`.
- AWS: exact field names carrying pre-shared keys in `DescribeVpnConnections`, and that a TGW VPN
  attachment's `ResourceId` is the VPN connection id.
- SCM: the four paths in 6.4 and their field names (`pan-scm-sdk` is the reference to check).
