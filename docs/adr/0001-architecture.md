# ADR 0001: split detection from enforcement, pluggable bouncers

## Status
Accepted

## Context

The original engine is a single process that tails logs, evaluates rules,
and writes BPF maps directly. That means:

- State lives in one process on one host; nothing is shareable across a
  fleet.
- Enforcement is tied to XDP specifically — a host without XDP support, or
  traffic that XDP can't see (TLS-terminated app traffic behind a proxy),
  can't be protected at all.
- Detection content (regex patterns, thresholds) is hardcoded in C++, so
  adding a new log format means a rebuild, not a config change.

## Decision

Re-architect around the pattern used by two production systems in this
space:

- **CrowdSec** separates a Log Processor (parses/scenarios) from a Local
  API (stores decisions) from Remediation Components / "bouncers"
  (enforce — nftables, iptables, reverse proxy, CDN). Detection content
  (parsers, scenarios) is versioned separately from the engine binary and
  hot-reloaded.
- **Cilium Tetragon** enforces inline in eBPF rather than reacting after
  the fact in user space, because by the time user space reacts an
  attacker may already have acted — the same principle applies to our XDP
  path, which should stay the fast, authoritative enforcement point rather
  than a mirror of a slower decision.

Concretely:

1. A **Local API** becomes the single source of truth for decisions and
   alerts (SQLite-backed initially, matching the existing storage layer).
2. **Bouncers** are separate processes that poll the Local API and
   enforce by whatever mechanism fits the host: XDP (existing kernel
   program, now consuming decisions instead of producing them), nftables,
   and eventually a proxy/app-layer bouncer.
3. **Detection content** (parsers, rule scenarios) moves to versioned YAML
   that can be hot-reloaded, instead of being compiled into the agent.

## Consequences

- The XDP kernel program itself barely changes — it's already correct and
  well-isolated. What changes is who writes to its maps and how.
- This buys horizontal scale (many hosts, one Local API) and portability
  (bouncers for hosts without XDP), at the cost of an extra network hop
  between detection and enforcement. The hop is local (same host or LAN)
  so the latency cost is small relative to the block TTLs involved
  (hundreds of seconds).
- This will not reach CrowdSec/Tetragon/Suricata's scale: no community
  threat intel, no multi-year protocol coverage, no formal security
  disclosure program. The explicit goal is to implement the same
  architectural pattern correctly at a defensible, honestly-scoped size —
  see ROADMAP.md's "honest scope boundary".

## Alternatives considered

- **Keep the monolith, add more rules to it.** Rejected: doesn't address
  single-host-only state or the hardcoded-detection problem, which are
  the two gaps most visible to anyone comparing this to a real product.
- **Full Suricata-style deep packet inspection.** Rejected for scope:
  building L7 protocol dissectors from scratch is a multi-year effort;
  Suricata itself uses XDP only as a fast pre-filter in front of that
  engine, which confirms XDP's role here should stay narrow (filter/drop),
  not try to become a full IDS.
