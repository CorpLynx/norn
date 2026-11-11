# nettrace: value to the organization

Audience: IT leadership and the one or two teams that would pilot it.
Status of this paper: a position, not a sales sheet. Where I could not verify a vendor claim it says so.

## 1. The one question it answers

"Why can't A reach B on port X, and where exactly does it stop?"

Today an engineer answers this by logging into a Cisco router, Panorama, a firewall, and one or more AWS
consoles, then comparing what each said. It takes 20 to 90 minutes, needs several skills, and the answer lives
in someone's head.

nettrace takes source, destination, port and protocol. It asks each device, live and read-only, how it would
treat that exact flow. It prints one PASS/BLOCK table with the first hop that stops it and the rule that did it.

## 2. What it is, and what it is not

| nettrace is | nettrace is not |
|---|---|
| A flow "would it pass?" checker | A monitoring system (no polling, no alerts, no history of device health) |
| Live: asks the device now | A config archive or change tracker |
| Read-only, allowlisted, audit-logged | A discovery or CMDB product |
| Honest: says UNKNOWN when it can't tell | A traffic or flow-record analyser |
| Small: one team can read all the code | A vendor-supported product with an SLA |

## 3. Where it overlaps with the big products

Based on public product pages and my own knowledge. Vendor pages change; confirm with the rep before relying on a row.

| Capability | SolarWinds (NPM/NCM/NetPath/NTA) | NetBrain | nettrace |
|---|---|---|---|
| Device health and alerting | Strong, core product | Some | None |
| Config backup and change detection | Strong (NCM) | Yes | None |
| Flow records (NetFlow, sFlow) | Yes (NTA) | Limited | None |
| Hop path from probes | Yes (NetPath, needs real traffic and agents/probes) | n/a | No probes |
| Path calculation for a chosen flow | Not what I found on the product pages | Yes, core feature | Yes, core feature |
| Asks a Palo Alto firewall to policy-match a flow | Shows Palo Alto policies in NCM; I found no live per-flow match | Reported to support firewall path checks; verify depth | Yes, via `test security-policy-match` and `nat-policy-match`, through Panorama |
| AWS SG, NACL, route table, TGW, GWLB for one flow | Basic cloud monitoring; I found no per-flow rule evaluation | AWS support exists; verify depth | Yes |
| Prisma Access policy | Not found | Verify | Yes, config-based, uncertain rules reported as UNKNOWN |
| Path map visual | Yes | Yes, best in class | Yes, basic (offline HTML/SVG, web UI animation) |
| Runbooks, automation, ITSM tie-in | Yes | Yes, strong | No |

Plain reading: NetBrain is the true competitor. SolarWinds is mostly a different job (watching), with partial overlap.
nettrace does not beat NetBrain on breadth, polish, scale or support. It wins on the points below.

## 4. Where nettrace adds value

1. **Cost and speed to start.** No license, no sales cycle, no collectors. One container, existing read-only
   accounts. A team can be tracing in days.
2. **One narrow job done transparently.** Every PASS/BLOCK shows the evidence (the command, the rule, the route).
   The team can check it against the device. Nothing is a black box.
3. **Built for this exact estate.** Cisco IOS-XE, Panorama-managed Palo Alto (on-prem and VM-Series), Prisma Access
   and multi-account AWS in one trace. Large products cover many vendors shallowly; this covers four deeply.
4. **Safe by construction.** Allowlisted read-only commands, read-only roles recommended on top, every request in an
   audit log, no redirects, TLS and SSH verified. A security team can review it in an afternoon because it is small.
5. **It never guesses.** NAT, zone firewalls, IPv6, App-ID, user groups and similar are reported UNKNOWN, and a trace
   with any UNKNOWN hop ends INCOMPLETE. A wrong confident answer is worse than "I can't tell".
6. **Credentials stay in-house.** Runs in your own Kubernetes. No data leaves. No SaaS tenant holds device access.
7. **Owned and changeable.** A missing check can be added by the team in a day, and a decision log explains why
   the code looks the way it does.
8. **Complements, doesn't replace.** Keep SolarWinds to watch. Use nettrace when someone asks why a flow fails.

## 5. Business case

What it saves: engineer time on connectivity tickets, fewer escalations between network, firewall and cloud teams,
fewer "open the port and see" changes made without understanding.

Rough model to fill with your own numbers (I have no measured data):

```
tickets per month x minutes saved per ticket x loaded hourly cost
```

Measure it in the pilot (section 8) rather than assume.

## 6. Honest limits and risks

| Risk | Reality today | Mitigation |
|---|---|---|
| Never run on real devices | True. Demo lab and tests only. | Lab pilot first (section 8) |
| Accuracy | Wrong answers are possible where device output differs from the simulators | UNKNOWN-by-default, evidence shown, compare to manual for 20 flows |
| Coverage | No NAT, zone firewall or IPv6 on Cisco. No App-ID or user-group evaluation | Reported UNKNOWN; roadmap in `docs/gaps-and-roadmap.md` |
| Prisma Access | Code assumes Strata Cloud Manager; the estate may use Panorama (roadmap R2) | Confirm before pilot |
| Bus factor | Support is the internal team | Name two owners; keep docs current |
| No SLA | No vendor to call | Position as an aid, not a system of record |
| Single shared device credential | Every user reaches the same devices | Auth spec: roles, audit by user, optional device scoping |
| No multi-user access control today | Web UI is local and single-user by design | `docs/auth-spec.md` |
| Maintenance | Dependencies and device software change | CI, Dependabot, pinned lock file are in place |

## 7. Build versus buy

Buy NetBrain if you want a supported platform with automation, many vendors, and a polished map, and you can fund
the license and the discovery effort. Keep nettrace if the need is this narrow question on this estate, the team
values transparency and read-only safety, and you accept internal ownership. Running both for a quarter is a
legitimate way to decide: compare answers on the same 20 flows.

## 8. Pilot proposal (4 to 6 weeks, one or two teams)

1. Week 1: read-only accounts on a lab slice. Confirm the accounts permit the needed commands (PAN-OS `test`
   commands and Cisco `show` at the chosen privilege level are the two to prove).
2. Week 2: 20 known flows, half pass and half fail. Compare nettrace to manual results. Log every mismatch.
3. Weeks 3 to 4: deploy in Kubernetes behind SSO (`docs/auth-spec.md`). Pilot users trace real tickets.
4. Week 5: review metrics and mismatches. Decide: expand, fix, or stop.

Success measures: agreement with manual answers on at least 90 percent of flows with the rest reported as
UNKNOWN rather than wrong; median time per connectivity ticket; number of escalations avoided; zero write
operations in the audit log (a hard check: it must be empty of anything but allowlisted reads).

Stop conditions: any confident wrong answer that is not explained by a documented gap; any request outside the
allowlist reaching a device.

## 9. Open questions for the owner

- Is Prisma Access managed by Panorama or by Strata Cloud Manager?
- Does the Palo Alto read-only role permit `test` operational commands?
- Who are the two named owners and the pilot teams?
- What does SolarWinds already deliver for Palo Alto and AWS at your license level? Ask the rep for a per-flow
  policy-match demo.
