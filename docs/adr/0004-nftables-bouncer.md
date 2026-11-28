# ADR 0004: bouncer-nft, a second Remediation Component

## Status
Accepted

## Context

ADR-0002 split enforcement out of `engine` into `bouncer-xdp`: a standalone
process that polls Local API's `GET /decisions` and reconciles a kernel
enforcement surface to match, independent of whatever decided those
decisions. It explicitly called this out as additive work for later:

> Adding a second bouncer (nftables, proxy) in a later phase is now
> additive: it reads the same `/decisions` feed and enforces by its own
> mechanism, with no engine.cpp changes required.

ROADMAP.md Phase 2 names that second bouncer. The motivation isn't "XDP
is bad" - `bouncer-xdp` drops packets in the driver before the kernel even
allocates an `sk_buff`, which `bouncer-nft` cannot match for raw packets-
per-second throughput (see `docs/THREAT_MODEL.md`'s performance section
for `bouncer-xdp`'s numbers). The motivation is that XDP attach has real
preconditions `bouncer-xdp` cannot work around:

- A NIC driver with native or generic XDP support (`ip link` reports
  `xdp` in its flags; not every virtual or embedded NIC does).
- A kernel recent enough to carry the BPF/XDP verifier and syscalls this
  project depends on.
- `CAP_BPF`/`CAP_NET_ADMIN` and, in practice on most distros, root.

`nft` has none of those requirements beyond `CAP_NET_ADMIN` and the
`nf_tables` kernel module, which ships enabled on essentially every
mainstream distro kernel built in the last several years. A host where
`bouncer-xdp` can't attach at all - a cloud VM with a virtio-net NIC that
only advertises generic (not native) XDP but under a constrained CAP set,
a container without the right capabilities, an older kernel - can still
run `bouncer-nft` and get the same decisions enforced, just without the
line-rate drop. That tradeoff (universal compatibility vs. raw pps) is
exactly the "pluggable enforcement" claim the target architecture diagram
in ROADMAP.md makes with its three parallel bouncer boxes, and until a
second bouncer actually exists and is tested, that claim is unverified.

## Decision

Introduce `bouncer-nft`, matching `bouncer-xdp`'s role precisely but
enforcing through an nftables set instead of a BPF map:

1. On startup, `bouncer-nft` runs an idempotent setup sequence via
   `nft -f -`: `add table inet xdp_engine`, `add set inet xdp_engine
   blocked_ips { type ipv4_addr; }`, `add chain inet xdp_engine input
   { type filter hook input priority 0; policy accept; }`. `nft add` is
   itself idempotent for tables/sets/chains (a repeat `add` is a silent
   no-op, confirmed against nftables 1.0.9) - this is the direct
   equivalent of `bouncer-xdp`'s "check for an existing pin, resume
   instead of re-attaching" logic, except nft does the idempotency check
   for us instead of our needing to probe for a pin file first.
2. `nft add rule` has no such idempotency - re-running it appends a
   second, third, ... identical drop rule rather than no-op'ing. The
   enforcement rule (`ip saddr @blocked_ips drop`) is tagged with a fixed
   comment (`xdp-engine-bouncer-nft`); setup lists the chain first
   (`nft -j list chain ...`) and only adds the rule if no existing rule
   carries that comment. This JSON-parsing check
   (`chain_has_rule_comment()`) is pure and unit-tested directly
   (`tests/test_nft_bouncer_core.cpp`), the same pattern ADR-0002 used for
   `diff_decisions()`.
3. The reconciliation loop is structurally identical to `bouncer-xdp`'s:
   poll `/decisions`, diff against currently-enforced, apply the result.
   **`diff_decisions()` from `bouncer_diff.h` is reused completely
   unmodified** - it was already a pure function over two
   `unordered_set<uint32_t>`s of network-order IPv4 addresses, with no
   BPF-specific assumption anywhere in it, so "a second bouncer is
   additive" turned out to be true at the header level, not just at the
   architecture level.
4. Reconciling the diff against the nftables set means a different
   failure mode than a direct `bpf_map_update_elem()` call: adds and
   removes for one poll cycle are built into a single `nft -f -` script
   and executed as one transaction (confirmed: nftables aborts the
   *entire* script if any one line fails, applying none of it - not a
   partial apply). Removals use `destroy element` rather than `delete
   element` (`destroy` is nft's idempotent-delete verb, a no-op if the
   element is already gone) specifically so that one stale removal - say,
   a decision that expired and was already independently cleared by a
   previous poll that we're re-processing after a crash - can't abort an
   otherwise-valid batch of adds. Additions use plain `add element`,
   which is likewise a no-op on a duplicate, for the same reason.
5. On resume (process restart with the table/set already populated from
   a previous run), `bouncer-nft` seeds `currently_enforced` by running
   `nft -j list set inet xdp_engine blocked_ips` and parsing the result
   (`parse_set_elements()`, also pure/unit-tested) - the direct nftables
   equivalent of `bouncer-xdp`'s `read_enforced_ips()` walking the live
   BPF map. Without this, exactly the same bug ADR-0002 called out for
   `bouncer-xdp` would exist here: an empty `currently_enforced` seed can
   never produce a removal, so anything left blocked by a previous,
   now-dead `bouncer-nft` process - but no longer in Local API's
   `/decisions` - would stay blocked forever.
6. `bouncer-nft cleanup` runs `nft destroy table inet xdp_engine`
   (idempotent - a no-op if the table was never created or was already
   removed), the nftables equivalent of `bouncer-xdp cleanup <iface>`.
7. An optional `--iface IFACE` flag adds an `iifname "IFACE"` match ahead
   of `ip saddr @blocked_ips` in the rule, scoping enforcement to one
   interface the same way `bouncer-xdp` is inherently scoped to the
   interface it attaches to. Left unset (the default), the rule applies
   to all interfaces - a deliberate difference from `bouncer-xdp`, which
   has no "all interfaces" option at all, because unlike an XDP program
   an nftables `input` hook rule isn't inherently tied to one NIC, and a
   host-wide default is the more useful one for the "can't do XDP here,
   fall back to nft" use case this bouncer mainly exists for.

### What's shared vs. duplicated with bouncer-xdp

`bouncer_diff.h` (the add/remove set diff) is shared verbatim - zero
changes. Everything else - the `/decisions` HTTP client, the CLI arg
parsing, the poll loop's shape - is a separate, self-contained copy in
`bouncer_nft.cpp`, not refactored into a shared base. This mirrors how
CrowdSec's own remediation components work: each bouncer is an
independent binary with its own copy of the small LAPI-polling client,
not subclasses of a shared bouncer framework. Sharing only the pure diff
logic, and nothing stateful or process-shaped, keeps each bouncer
independently buildable, testable, and deployable without the other even
present on the host - which is the entire point of this being a second,
optional enforcement surface rather than a required component.

## Consequences

- A host can now run `bouncer-nft` instead of `bouncer-xdp` with zero
  changes to `engine`, `local-api`, or anything upstream of
  `GET /decisions` - the "pluggable enforcement" claim in ROADMAP.md's
  architecture diagram is now true for two of its three bouncer boxes,
  not just asserted.
- `bouncer-nft` cannot match `bouncer-xdp`'s packets-per-second ceiling:
  nftables enforcement happens later in the kernel's networking stack
  (after `sk_buff` allocation) than an XDP hook does, which is a
  well-understood, inherent tradeoff of the mechanism, not a bug in this
  implementation. No throughput claim is made for `bouncer-nft` in this
  ADR; benchmarking it is out of scope for this phase.
- Like `bouncer-xdp`, `bouncer-nft` does not survive a reboot on its own -
  nftables rulesets live in kernel memory, not on disk, and nothing here
  re-applies them at boot. That's the same known gap ADR-0002 already
  called out for the BPF pins, now also true here, and still future work.
- Running both bouncers on the same host at once was in fact tested
  (real hardware, both `bouncer-xdp` and `bouncer-nft` polling the same
  `local-api` concurrently): `engine-cli block`/`unblock` correctly
  propagated to both - the kernel's `blocked_ips` BPF map and the
  `xdp_engine`/`blocked_ips` nftables set stayed in sync with each other
  the whole time, with no observed interaction between the two. This
  matches the expectation stated here originally (XDP runs earlier and a
  dropped packet never reaches the `input` hook, so the two can't
  conflict) - noted now as confirmed rather than merely expected.
- **Coexistence with a distro firewall manager (e.g. Fedora's
  `firewalld`) was not accounted for in the original design and is worth
  calling out.** `firewalld` installs its own `inet firewalld` table,
  which - like `bouncer-nft`'s `inet xdp_engine` table - registers chains
  on the same netfilter hooks. Multiple tables can coexist on one hook
  (nftables evaluates every table registered there, ordered by chain
  priority), and this was observed to work without conflict in testing,
  but nothing here verifies `firewalld`'s own base chains don't
  `accept`/`continue` traffic in a way that interacts unexpectedly with
  `bouncer-nft`'s own priority-0 `input` chain on every possible
  `firewalld` configuration (zones, rich rules, etc.) - only the default
  Fedora Workstation firewalld setup was exercised. Worth a closer look
  before relying on this combination for anything beyond testing.

## Alternatives considered

- **libnftables (the C library, `-lnftables`), instead of shelling out to
  the `nft` binary.** Rejected for this phase: it would remove one
  `fork`/`exec` per poll cycle, but at a 2-second default poll interval
  that cost is immaterial, and the library's C API is lower-level than
  its own CLI's scripting interface (the CLI's `-f -`/`-j` flags already
  give atomic multi-line transactions and structured JSON output for
  free). Shelling out is also exactly what CrowdSec's real nftables
  bouncer does, for the same reason. Revisit only if a future phase
  identifies the subprocess overhead as an actual measured bottleneck.
- **`ip saddr { 1.2.3.4, 5.6.7.8, ... }` inlined directly into the rule,
  instead of a named set the rule references.** Rejected: every change
  would mean rewriting the whole rule (`nft` has no "add one address to
  this inline list" operation), whereas a named set supports
  `add element`/`destroy element` for single addresses directly - the
  entire reason nftables sets exist as a first-class feature rather than
  everyone inlining match lists.
- **Track per-decision expiry inside the nftables set itself, using
  element timeouts (`add element ... { 1.2.3.4 timeout 10m }`)**, instead
  of relying purely on "did it drop out of the next poll's result set."
  Rejected for the same reason ADR-0002 rejected the BPF-side equivalent:
  it would duplicate the expiry logic Local API's SQL already encodes,
  with two sources of truth that could disagree. The same accepted
  tradeoff applies here too - an IP can stay blocked for up to one extra
  poll interval past its real expiry.

## Known gap, called out rather than hidden

Nftables element timeouts and automatic expiry support far richer
bookkeeping than this bouncer uses. None of that is wired up. This
bouncer does exactly one thing - keep a set of addresses in sync with
Local API's `/decisions` and drop traffic from them - on purpose, the
same honest-scope call `bouncer-xdp` makes. For hit counting
specifically, nftables sets can carry a `counter` per element (`add
element ... { 1.2.3.4 counter }`), which would be the closest nft
equivalent of `xdp_prog.bpf.c` atomically incrementing
`block_record.hits` on every dropped packet - but nothing here reads
those counters back out into Local API or the dashboard even on the
`bouncer-xdp` side, so adding per-element counters to `bouncer-nft` alone
would just be unused bookkeeping. Left out of scope here for the same
reason; worth revisiting only once something downstream actually
consumes per-IP hit counts.
