# ADR 0005: Prometheus metrics on Local API

## Status
Accepted

## Context

ROADMAP.md Phase 3 names "Prometheus metrics" as a hardening/observability
item, and the target architecture diagram already draws an "Observability"
box downstream of the Local API ("metrics + alerts"). Two kinds of metric
already exist in the codebase, in two different places:

- **Packet-level kernel counters** (`dropped`, `passed`, and a `tcp`/`udp`/
  `icmp`/`other` breakdown) - genuinely cumulative, per-CPU BPF counters
  (`XdpEngine::get_stats()` in `engine.cpp`), sampled once a second by
  `engine`'s `metrics_poller` thread and written to the `metrics` table in
  the shared SQLite DB. `dashboard/app.py`'s live showcase UI already reads
  this table's latest row for its own (non-Prometheus) JSON API.
- **Alert/event/decision counts** - already queryable from the `alerts`/
  `events`/`decisions` tables Local API already has open for `/export` and
  `/decisions`.

Nothing exposes either of these in a format an actual metrics system
(Prometheus, or anything that scrapes its exposition format - Grafana
Agent, VictoriaMetrics, etc.) can consume.

## Decision

Add `GET /metrics` to `local-api`, not a new standalone binary or a route
on `engine` itself:

1. **Why Local API and not `engine`**: Local API already owns read access
   to the one shared SQLite DB every other metric lives in, and is already
   the process every bouncer and the dashboard talk to - adding a route
   here needs no new port, no new process, and matches the architecture
   diagram's own "Local API → Observability" arrow directly. `engine`
   could expose a `/metrics` of its own cheaply too (it already computes
   these same packet counters once a second), but doing that would mean
   two different processes both claiming to be *the* metrics endpoint for
   the same underlying data, and a Prometheus scrape config would have to
   know which one to point at depending on what it wants - more moving
   parts for no present benefit, revisit only if a future phase needs
   metrics from something Local API genuinely can't see (e.g. a
   bouncer's own poll-success/poll-latency, which is specific to process
   choice and isn't in the shared DB at all - left out of this ADR's
   scope, see "Known gap" below).
2. **Storage::get_metrics_summary()** gathers the plain data (latest
   `metrics` row, lifetime `alerts`/`events` counts, and
   `get_active_decisions().size()`) and **`prometheus_metrics.h`'s
   `format_prometheus_metrics()`** turns it into the actual exposition
   text - kept as a pure, DB-independent function
   (`tests/test_prometheus_metrics.cpp`) the same way `bouncer_diff.h`
   and `nft_bouncer_core.h` keep their own logic testable without a real
   kernel.
3. **A missing packet-counter sample is reported as absent, not zero.**
   `PacketMetricsSnapshot::has_data` is `false` until `engine` has written
   at least one row to the `metrics` table; `format_prometheus_metrics()`
   omits every packet-derived metric entirely in that case. The
   alert/event/decision counts are emitted unconditionally, including as a
   real `0`, because an empty table there *is* a meaningful answer ("no
   alerts yet") in a way "no packet sample yet" is not ("this engine
   hasn't started" is a different fact than "0 packets have been seen").
4. **The engine's enforcement mode is reported with Prometheus's
   recommended enum-as-gauge pattern**: `xdp_engine_mode{mode="enforce"}`
   and `xdp_engine_mode{mode="detect"}` are both always emitted (0 or 1),
   rather than a single metric whose label value changes over time -
   the latter makes `sum by (mode)` and alerting on "is detect mode
   active" awkward (`absent()` tricks) in a way the former doesn't.
   `engine.cpp` only ever sets the `metrics` table's `xdp_mode` column to
   `"ENFORCE"`/`"DETECT"` during normal operation (`"OFFLINE"` is a
   one-shot row written at shutdown) - that third state reads as neither
   gauge being `1`, which is the correct answer (the engine isn't
   actively enforcing or detecting while offline).
5. **Auth**: `/metrics` is gated by the same `Authorization: Bearer
   <token>` check as `/decisions`/`/export`. Prometheus's own scrape
   config supports a static bearer token natively
   (`authorization: {credentials: "..."}`), so this adds no new
   authentication mechanism to document or implement.

## Consequences

- Any Prometheus-compatible scraper can now be pointed at `local-api` and
  get real numbers for packet drops/passes/protocol mix, SYN rate limit,
  current enforcement mode, and alert/event/active-decision counts,
  closing the gap between the architecture diagram's claimed
  "Observability" consumer and anything actually serving it data.
- The packet counters inherit the same caveat `XdpEngine::get_stats()`
  always had: they're cumulative since `bouncer-xdp` last attached fresh,
  not since the Unix epoch or since `local-api` started, and reset to 0
  on a fresh (non-resumed) XDP attach. A Prometheus `rate()`/`increase()`
  query across such a reset undercounts for one scrape interval - the
  same well-understood counter-reset behavior Prometheus's own
  client libraries document, not something specific to this
  implementation.
- Because `local-api` reads the same `metrics` table row the dashboard
  already reads, a staleness check (`now - xdp_engine_last_metrics_timestamp_seconds`)
  tells a Prometheus alerting rule the same thing
  `dashboard/app.py`'s own `engine_running` check already computes for
  the UI - one source of truth for "is the engine actually reporting in,"
  not two that could disagree.

## Alternatives considered

- **A separate `metrics-exporter` binary**, polling Local API's existing
  JSON-ish internals or reading the DB itself, Prometheus-exporter-style
  (as many `*_exporter` sidecars do for software with no native
  Prometheus support). Rejected: Local API already has everything this
  would need open and already serves other HTTP endpoints - a sidecar
  process whose only job is reformatting data from a process sitting
  right next to it is unneeded indirection here, not a pattern this
  project is replicating something else's constraint it doesn't have.
- **OpenMetrics content-type** (`application/openmetrics-text;
  version=1.0.0`) instead of the classic Prometheus text format. Rejected
  for now: the classic format is understood by every Prometheus version
  without content negotiation, and nothing here needs OpenMetrics-only
  features (exemplars, `_created` timestamps). Revisit if a consumer
  specifically needs one of those.

## Known gap, called out rather than hidden

Per-bouncer operational metrics - `bouncer-xdp`/`bouncer-nft`'s own poll
success/failure counts, last successful poll time, or how many IPs each
is currently enforcing from its own point of view - are not covered by
this ADR. Local API can't see that from the shared DB (a bouncer's poll
loop is a fact about that specific process, not a database row), so
exposing it would mean each bouncer growing its own HTTP server and its
own `/metrics` route - real, bounded-size follow-on work, intentionally
left out here rather than quietly expanded into this change.
