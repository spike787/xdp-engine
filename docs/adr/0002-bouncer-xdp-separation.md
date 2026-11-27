# ADR 0002: bouncer-xdp as the first real bouncer

## Status
Accepted

## Context

ADR-0001 set the direction: a Local API as the source of truth for
decisions, with separate bouncer processes enforcing them. Phase 1 landed
the Local API and had `engine` persist decisions (`insert_decision`) — but
`engine` was still the only thing that ever touched the BPF maps. In
practice:

- `engine` loaded `xdp_prog.bpf.c`, attached it, and held `blocked_ips`/
  `allowed_ips` as anonymous fds. Nothing was pinned to bpffs, so no other
  process could reach them.
- `BlockList::block()`/`unblock()` wrote to the kernel map and persisted a
  decision in the same call — enforcement and the decision record were
  still coupled to one process's lifetime.
- Because the `bpf_link` wasn't pinned either, killing `engine` auto-
  detached the XDP program (the kernel drops a link when the last fd
  referencing it closes). There was no way for enforcement to outlive the
  detector, which defeats the point of a Local API: a restart of the
  detection/rule-engine process shouldn't open a window where nothing is
  blocked.

This matters once you actually try to add a second enforcement surface (an
nftables bouncer, say): it would need its own copy of "is this IP
blocked", with no shared source of truth other than re-reading the DB
directly, which is exactly the architecture ADR-0001 rejected.

## Decision

Introduce `bouncer-xdp` as the first real bouncer, matching CrowdSec's
Remediation Component role precisely:

1. `bouncer-xdp` is the **only** process that loads `xdp_prog.bpf.c` and
   attaches it to the interface. On attach, it pins every map the object
   defines under `XDP_ENGINE_PIN_DIR` (`/sys/fs/bpf/xdp_engine/<mapname>`),
   generically (`bpf_object__for_each_map`), and pins the `bpf_link` too.
2. It polls `GET /decisions` on an interval (default 2s) and reconciles
   `blocked_ips` to match: anything newly present gets added, anything that
   drops out of the result set (expired or manually unblocked — the SQL in
   `get_active_decisions` already filters to currently-active rows) gets
   removed. The diff itself (`bouncer_diff.h::diff_decisions`) is a pure
   function over two sets, independent of BPF/libcurl, so it's unit-tested
   directly (`tests/test_bouncer_diff.cpp`) rather than only exercisable
   through a real kernel attach.
3. Pinning the link means enforcement survives `bouncer-xdp` restarting:
   on startup it checks for an existing pin first and, if present, resumes
   polling against the already-attached program instead of re-attaching.
   A `bouncer-xdp cleanup <iface>` subcommand explicitly detaches and
   un-pins when a clean teardown is actually wanted.
4. `engine` no longer loads or attaches anything. `XdpEngine`'s constructor
   now does `bpf_obj_get()` against bouncer-xdp's pins instead of
   `bpf_object__open_file` + `bpf_program__attach_xdp`, with a clear error
   if the pins aren't there yet ("is bouncer-xdp running? start it
   first"). `BlockList::block()`/`unblock()` now only call
   `storage_->insert_decision(...)` — they no longer touch `blocked_ips`
   at all. The per-process `sweep_loop` that used to expire kernel entries
   on a timer is gone; expiry is decided once, in the Local API's SQL, and
   enforced once, by bouncer-xdp's next poll finding the IP missing from
   the result set.
5. `allowed_ips` is the one exception: `engine` still writes to it
   directly (`allow_ip`/`unallow_ip`). The allowlist isn't an enforcement
   *decision* in the CrowdSec sense — it's a safety rail `engine` itself
   must consult before it will even propose a block (`is_allowed()` guards
   `block()`), so there's no separation to make there.

This was a genuine fork in the design (see "Alternatives considered"): the
safer option was to let `engine` keep blocking instantly and add
`bouncer-xdp` as a second, redundant enforcer. That was rejected in favor
of the full cutover below, on the basis that a single-host redundant
enforcer doesn't actually demonstrate — or get any real testing of — the
separation this project's whole architecture argument rests on.

## Consequences

- **A block now takes effect after bouncer-xdp's next poll, not
  instantly.** Default interval is 2s. This applies to both automatic
  (rule-engine-driven) and manual (`engine-cli block`) blocks equally —
  the whole point is that `engine` can't tell the difference anymore, it
  just records a decision either way. `engine-cli list` reports each
  active decision's real TTL from storage and tags it `[enforced]` or
  `[pending]` by doing a read-only lookup against the pinned map, so the
  propagation lag is visible rather than silently hidden.
- **Startup order now matters**: `bouncer-xdp <iface>` must run before
  `engine <iface>`, since `engine` opens pins that only exist once
  bouncer-xdp has created them. `engine` fails fast with a message saying
  so rather than silently not enforcing anything.
- **Enforcement survives `engine` crashing or restarting** — the thing
  ADR-0001 was actually for. It does not yet survive a reboot (pins live
  under `/sys/fs/bpf`, which is typically on a tmpfs-backed bpffs), and
  nothing currently re-attaches automatically on boot; that's future work,
  not in scope here.
- `engine`'s own `cleanup`/`reset` subcommands no longer touch XDP or the
  pin directory (they never actually worked post-phase-1 anyway — see
  below) and instead point at `bouncer-xdp cleanup <iface>`.
- Adding a second bouncer (nftables, proxy) in a later phase is now
  additive: it reads the same `/decisions` feed and enforces by its own
  mechanism, with no engine.cpp changes required.

## Alternatives considered

- **Dual-write: keep `engine` enforcing instantly, add `bouncer-xdp` as a
  redundant second enforcer.** Zero latency regression, zero behavior
  change, lower risk. Rejected (explicit project decision) because on a
  single host it doesn't actually separate detection from enforcement —
  it just adds a second thing that can also block IPs, which isn't the
  same claim as "enforcement is independent of the detector's lifetime."
  Revisit this if a future phase needs `engine` on a host where
  `bouncer-xdp`'s poll latency is unacceptable.
- **Keep maps as anonymous fds, pass them to bouncer-xdp via `SCM_RIGHTS`
  over the existing Unix socket instead of pinning to bpffs.** Rejected:
  works, but ties bouncer-xdp's lifetime to engine's socket being up at
  the moment bouncer-xdp starts, reintroducing exactly the coupling this
  ADR is trying to remove. Pinning to bpffs is the standard libbpf-idiomatic
  way to share maps across unrelated processes and needs no IPC protocol
  of our own.
- **Have `bouncer-xdp` track per-decision expiry in the kernel map itself
  (`block_record.expires_at_ns`) instead of relying purely on "did it drop
  out of the next poll's result set."** Rejected for this phase: it would
  need bouncer-xdp to replicate the same expiry logic the SQL query
  already encodes, with two sources of truth that could disagree. Simpler
  for the kernel-side `block_record.expires_at_ns` to just be `0`
  (permanent, from bouncer-xdp's perspective) and let the next poll be the
  single expiry mechanism; the honest tradeoff is that an IP stays blocked
  for up to one extra poll interval past its real expiry, which is well
  inside the slack already accepted for the Local API hop in ADR-0001.

## Known gap, called out rather than hidden

`engine`'s pre-existing `reset`/`cleanup <iface>` commands referenced a pin
path (`/sys/fs/bpf/xdp_engine`) that nothing ever actually created —
dead code from before pinning existed at all. This ADR is what makes that
path real (bouncer-xdp creates and owns it now); `engine`'s own copies of
those commands were corrected to say so instead of silently continuing to
do nothing.
