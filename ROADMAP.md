# Roadmap: xdp-engine → distributed detection/enforcement platform

This document is the single source of truth for the project's direction. Any
session (human or agent) picking this project back up should read this file
first — it should never be necessary to re-derive the plan from a chat log.

## Why this rewrite

The original xdp-engine is a correct, well-tested single-host eBPF/XDP
firewall with a SOAR-style rule engine. Its limits are architectural, not
bugs: detection logic is hardcoded in C++, enforcement is tied to one
process writing BPF maps directly, and nothing is reusable across hosts.

This rewrite re-architects it around the same pattern used by CrowdSec
(detection/enforcement split via a Local API and pluggable "bouncers") and
Cilium Tetragon (inline kernel enforcement), at a scale honest for a
3.5-month student project — see `docs/adr/0001-architecture.md` for the
full comparison and rationale.

## Target architecture

```
Network traffic & logs
        |
        v
   [ Agent ]  <---- [ Rule hub ]        (per protected host)
  parsers + XDP       hot-reload
  telemetry            parsers/scenarios
        |
        v
  [ Local API ]  ----> [ Observability ]  (shared control plane)
  decisions + alert       metrics + alerts
  store + export
        |
        v  (fan-out, same decision, different hosts)
   -----------------------------
   |            |              |
[XDP        [nftables      [Proxy
 bouncer]    bouncer]       bouncer]
   |            |              |
   -----------------------------
        |
        v
Attacker traffic dropped network-wide
```

## Phases and review mapping

| Phase | Window | Scope | Maps to |
|---|---|---|---|
| 1. Foundation | Now → mid-Dec | Local API (decisions/alerts/export), split XDP enforcement into its own bouncer binary that polls the API instead of deciding things in-process | Review I (15%) |
| 2. Detection content as data | Mid-Dec → Jan | Staged parser pipeline (raw/parse/enrich) in YAML instead of hardcoded regex; second bouncer (nftables); replay/backtest CLI | — |
| 3. Pluggable enforcement + hardening | Jan → Feb | Third bouncer (proxy/app-layer); Prometheus metrics; capability drop instead of root; parser fuzzing; IPv6 header parsing | Review II (25%) |
| 4. Proof at small scale | Feb → March | Multi-host lab (2-3 nodes sharing one Local API); 10-scenario attack testbench with measured results; packaging (Docker Compose, systemd); report + poster | Review III (60%) |

## Additions agreed in planning

- **Export**: `GET /export?format=csv|json&since=...` on the Local API,
  and `engine-cli export` as the CLI equivalent. Schema: timestamp,
  source IP, event type, matched rule, MITRE ID, severity, action taken,
  host. JSON-lines output is SIEM-ingestible (Elastic/Loki-compatible)
  without extra transformation.
- **10-scenario attack testbench** (`testbench/`): SSH brute force,
  credential stuffing (distributed/slow), SQL injection, path traversal,
  port scan, scan-then-brute correlation, volumetric SYN flood, web
  recon/scanner, ICMP sweep, spoofed-source distributed flood (the last
  one is expected to partially evade detection — that's intentional and
  should be reported honestly, not hidden). Scenarios 7/9/10 (floods,
  spoofing) run only inside an isolated lab network, never against a
  real public IP.

## Honest scope boundary

This project will not match CrowdSec, Tetragon, or Suricata in protocol
coverage, community threat intel, or production hardening — that gap is
years of accumulated scale, not something an architecture rewrite closes.
The goal is to correctly implement the same patterns those tools are built
on, at a scale that is demonstrable and defensible, and to be honest about
what's still a known limitation (see each phase's own limitations section
once written).

## Environment note

XDP attach requires a real Linux kernel with `CAP_BPF`/`CAP_NET_ADMIN` and
a real NIC. Agent-side sandboxes used for this work can build and unit-test
everything except the actual kernel attach/enforcement path — that must be
verified on a real box (VM or VPS) before being called done.
