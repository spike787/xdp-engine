# ADR 0009: Fix GET /metrics serving a permanently stale snapshot

## Status
Accepted

## Context

Found while doing real-hardware verification for PR #16 (ADR-0008, IPv6
header parsing): `GET /metrics` kept returning the exact same numbers no
matter how much real traffic (including a genuine external IPv6 round
trip) crossed the interface. Cross-checking with `engine-cli stats` and a
direct `sqlite3 engine.db "SELECT ... FROM metrics ORDER BY ts DESC LIMIT 1"`
query showed both of those updating correctly and immediately - only the
HTTP endpoint was frozen. That immediately ruled out `xdp_prog.bpf.c`,
`engine`'s own BPF map reads, and the data actually landing in SQLite -
all three were fine. The bug had to be in `local-api`'s read path
specifically.

Reproduced it in complete isolation, no XDP/BPF/network involved at all:
start `local-api` against a fresh DB, insert a metrics row with a plain
`sqlite3` CLI call, query `/metrics` (correct), insert a second row with a
different value, query `/metrics` again (**still shows the first row's
values**). Two ordinary processes and a WAL-mode SQLite file reproduce it
on demand.

Root cause: `Storage::get_metrics_summary()` runs three single-row SELECT
statements back to back on one shared connection -
`get_latest_metrics_stmt_`, `count_alerts_stmt_`, `count_events_stmt_`.
Each was reset right before its own *next* use, but never reset (or
drained to `SQLITE_DONE`) right after reading its one row - so each was
left parked mid-execution in `SQLITE_ROW` state. In WAL mode, a
connection's implicit (autocommit) read transaction only truly ends once
*every* statement that participated in it has been reset or finalized -
not just the one a caller happens to reset next. With three statements
each left dangling from the previous call, resetting only the first one
at the top of a new call wasn't enough to guarantee a fresh snapshot for
that read, since the other two from the *prior* call were still parked at
that exact moment. The net effect: `local-api`'s connection could get
stuck observing one fixed point-in-time snapshot indefinitely, regardless
of how many new rows `engine` went on to insert.

This is `local-api`'s own pre-existing code (introduced with the original
Prometheus metrics endpoint, PR #12/ADR-0005) - nothing about ADR-0008's
IPv6 changes touches `storage.cpp`, `local_api.cpp`, or this connection at
all. Found *while* verifying that PR, not caused by it.

## Decision

Reset each statement immediately after reading its row, not only before
reusing it - so each one's participation in the connection's implicit
read transaction ends right away instead of carrying over into whatever
happens to run next:

```cpp
sqlite3_reset(get_latest_metrics_stmt_.get());
if (sqlite3_step(get_latest_metrics_stmt_.get()) == SQLITE_ROW) { ... }
sqlite3_reset(get_latest_metrics_stmt_.get()); // <- added
```

...and the same for `count_alerts_stmt_` and `count_events_stmt_`.
`Storage::get_offense_count()` had the identical single-step-no-reset-
after shape on `get_offense_stmt_` (unrelated code path, `engine`'s
per-IP offense counter) - fixed the same way as a defensive measure,
even though it's less exposed than the three-statement interaction that
actually caused the metrics bug, since it's only ever reset-before-reuse
against itself rather than interleaved with other dangling statements.

New regression test, `StorageMetricsTest.SummaryReflectsEachNewRowAcrossSeparateConnections`
(`tests/test_storage.cpp`): opens **two separate `Storage` instances**
against the same DB file - one standing in for `engine`'s connection
(the writer), one for `local-api`'s (the reader) - inserts three metrics
rows through the writer, and asserts the reader's
`get_metrics_summary()` reflects each one. Confirmed this fails without
the fix (stuck reporting the first row's values after the second and
third inserts) and passes with it, before and after, not just by
inspection.

## Consequences

- `GET /metrics` now reflects live data on every scrape, as a Prometheus
  endpoint is supposed to - this was silently broken since the metrics
  endpoint's introduction (PR #12), affecting any deployment scraping it,
  not just the IPv6 verification that happened to surface it.
- No schema, API, or metric-shape change - purely a connection-handling
  fix inside `storage.cpp`. Nothing downstream (Prometheus scrape config,
  the dashboard, `engine-cli`) needs to change.
- The regression test exercises the actual two-connections-one-file shape
  that matters (`engine` writes, `local-api` reads) without needing two
  real processes or a real BPF program - a useful pattern for any future
  change to this file to reuse.

## Alternatives considered

- **Wrap `get_metrics_summary()` in an explicit `BEGIN`/`COMMIT`** instead
  of fixing the per-statement reset discipline. Would also work (an
  explicit transaction's boundaries are unambiguous), but changes this
  function's transaction semantics more than the bug requires, and
  doesn't address the identical latent issue in `get_offense_count()`
  elsewhere in the same file.
- **A single combined query** (`UNION`/subqueries) instead of three
  separate prepared statements. Would sidestep the multi-statement
  interaction entirely, but is a larger rewrite of working, readable code
  for a bug whose actual fix is two added lines per statement.

## Known gap

- No audit was done of `engine.cpp`'s own SQL usage (it uses `storage.*`
  methods, not raw sqlite3 calls directly, so it's covered by this same
  fix) or of whether other, as-yet-unwritten `Storage` methods could
  introduce the same left-parked-statement shape in the future. The
  regression test added here guards the one path that was actually
  broken; it's a pattern worth watching for in review, not something this
  fix makes structurally impossible to repeat.
