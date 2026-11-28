# ADR 0008: IPv6 header parsing

## Status
Accepted

## Context

ROADMAP.md Phase 3 names "IPv6 header parsing" directly. Before this
change, `xdp_prog.bpf.c`'s only EtherType check was:

```c
if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return XDP_PASS;
}
```

Any non-IPv4 traffic - IPv6 included, not just ARP/VLAN - took this branch
and returned immediately. Critically, this happened *before* the `bump(1)`
"passed" counter call later in the function, so IPv6 traffic wasn't just
unenforced, it was invisible to this firewall's own telemetry: an operator
running this on a dual-stack host would see `stats[passed]` and
`proto_stats` reflect only their IPv4 traffic, with no signal that IPv6
packets were crossing the interface at all.

Surveying how deep the IPv4 assumption goes: every map `xdp_prog.bpf.c`
keys by IP address (`allowed_ips`, `blocked_ips`, `rate_state`,
`scan_state`, `icmp_state`) uses a hardcoded 32-bit `__u32` key, and
`common.h`'s `struct drop_event` (the struct sent over the ringbuf to
userspace on every block/rate-limit/scan/ICMP-flood event) hardcodes a
32-bit `__u32 src_ip` field - a 128-bit IPv6 address simply doesn't fit in
it. Giving IPv6 real **enforcement** - blocking, rate-limiting, port-scan
and ICMP-flood detection - would mean new 128-bit-keyed BPF maps, a
`drop_event` layout change (or a parallel IPv6 event struct) that cascades
into `engine.cpp`'s ring-buffer poller, the SQLite schema, the Local API's
JSON shapes, and `bouncer-nft`'s nftables set type (`ipv4_addr` today,
would need an `ipv6_addr` set and matching rule). That is a substantially
larger feature than "parsing", and not what this PR does - see Known gap.

## Decision

`xdp_prog.bpf.c` now recognizes `ETH_P_IPV6` and parses the fixed 40-byte
IPv6 header (`struct ipv6hdr`, no variable-length options the way IPv4's
`ihl` has) far enough to:

- Read `nexthdr` and classify the packet into the **same** `proto_stats`
  buckets IPv4 traffic already uses: `IPPROTO_TCP` → bucket 0,
  `IPPROTO_UDP` → bucket 1, `IPPROTO_ICMPV6` → bucket 2 (shares the IPv4
  ICMP bucket - see Alternatives considered), anything else → bucket 3
  ("other").
- Bump the global `stats[1]` "passed" counter, so IPv6 traffic is now
  counted as passed rather than silently uncounted.
- Return `XDP_PASS` unconditionally - no enforcement decision is made for
  IPv6 traffic in this PR, it always passes, same as before, just now
  visibly.

This is additive and sits entirely in its own branch, checked *before* the
existing `eth->h_proto != ETH_P_IP` check (which is otherwise untouched,
byte-for-byte) - the IPv4 code path was not modified at all. A packet
whose IPv6 header is too short to safely read (fewer than 40 bytes after
the Ethernet header) returns `XDP_PASS` without bumping any counter,
mirroring the existing IPv4 path's precedent for a truncated IPv4 header.

**Extension headers are not walked.** A real IPv6 packet can carry zero or
more extension headers (Hop-by-Hop Options, Routing, Fragment, Destination
Options, ...) between the fixed header and its real transport payload,
each chained via its own `nexthdr` field. This PR reads the fixed header's
`nexthdr` directly and classifies on that value alone - a packet with, say,
a Hop-by-Hop Options header ahead of its TCP payload is classified by the
extension header's own protocol number (falls into the "other" bucket),
not resolved through to TCP. This is a deliberate, stated scope limit, not
a silent miscount: see "What was actually found" below for a concrete test
demonstrating exactly this case, and Known gap.

## What was actually found

Unlike prior XDP-touching changes in this project's history, this one
could be - and was - verified against the real kernel BPF verifier and the
real `xdp_firewall` program's actual runtime behavior, without needing a
NIC or the user's hardware. `BPF_PROG_TEST_RUN` (exposed by libbpf as
`bpf_prog_test_run_opts()`) runs a loaded BPF program against a
synthetic packet buffer and returns its verdict - the same mechanism the
kernel's own BPF selftests use to unit-test programs offline. A new tool,
`tools/xdp_prog_test.cpp` (`make xdp-prog-test`), loads the real,
compiled `xdp_prog.bpf.o`, confirms the verifier accepts it, and runs it
against eight synthetic packets, checking both the returned verdict and
the `proto_stats`/`stats` map counters afterward:

- IPv4 TCP (regression check: unmodified code path) - `XDP_PASS`,
  `proto_stats[tcp]` +1, `stats[passed]` +1.
- IPv6 TCP - `XDP_PASS`, `proto_stats[tcp]` +1 (shared bucket),
  `stats[passed]` +1 (previously uncounted).
- IPv6 UDP - `XDP_PASS`, `proto_stats[udp]` +1.
- IPv6 ICMPv6 - `XDP_PASS`, `proto_stats[icmp]` +1 (shared bucket).
- IPv6 with a Hop-by-Hop extension header ahead of an empty payload -
  `XDP_PASS`, `proto_stats[other]` +1 - the extension-header limitation
  above, demonstrated rather than just asserted.
- A truncated IPv6 header (20 of the required 40 bytes) - `XDP_PASS`, no
  counter bumped at all.
- ARP (an unrelated ethertype) - `XDP_PASS`, no counter bumped - confirms
  nothing outside the IPv4/IPv6 branches changed.

All eight ran clean (17 individual assertions, 0 failures) in this
sandbox. What this does *not* cover: real NIC/driver interaction (native
vs. generic XDP mode, however a specific card's driver hands off a packet
buffer), VLAN-tagged or otherwise non-trivial framing, and - as
`BPF_PROG_TEST_RUN` only runs the program, not an attach - whether
`bouncer-xdp` successfully attaches this updated program to a real
interface at all. That last part is unchanged by this PR (no attach-path
code was touched) but, per every prior XDP ADR in this project, still
needs the user's real hardware to confirm end to end.

## Consequences

- `proto_stats`'s TCP/UDP/ICMP buckets now mean "this L4 protocol, across
  either IP version" rather than "this L4 protocol, IPv4 only" - worth a
  line in the Prometheus/dashboard-facing docs so an operator reading
  `xdp_tcp_packets_total` (or equivalent) knows it includes IPv6 TCP too.
  No metric name or shape changed, so nothing downstream breaks - the
  numbers just became more complete.
- `stats[passed]` will visibly increase on any dual-stack host that was
  carrying IPv6 traffic before this change, with no corresponding rise in
  `stats[dropped]` - again, the numbers becoming accurate, not evidence of
  a new leak.
- `tools/xdp-prog-test` (new, `make xdp-prog-test`, not part of
  `all`/`test` - needs CAP_BPF to load an XDP-type program, same
  precondition ADR-0006 already established for `bouncer-xdp`/`engine`)
  is now available for any *future* change to `xdp_prog.bpf.c` too - the
  BPF_PROG_TEST_RUN technique this PR introduces isn't specific to IPv6,
  it's a general way to unit-test this program's parsing logic against
  synthetic packets without a NIC, and is worth reaching for again before
  the next kernel-side change rather than relying on "builds + passes
  verifier" as the only signal.

## Alternatives considered

- **New, separate `proto_stats` buckets for IPv6** (e.g. a 6-entry map:
  v4-tcp/v4-udp/v4-icmp/v6-tcp/v6-udp/v6-icmpv6) instead of sharing the
  existing four. Rejected for this PR: it changes the map's shape, which
  ripples into `engine.cpp`'s metrics poller and the Prometheus endpoint's
  output format - real value, but a metrics-schema change layered on top
  of "parse IPv6 headers", not required by it. Left as a natural
  follow-up if IPv4-vs-IPv6 traffic-mix visibility turns out to matter in
  practice.
- **Walking the extension header chain** (a bounded, unrolled loop
  handling Hop-by-Hop/Routing/Fragment/Destination Options to reach the
  real transport protocol) instead of reading `nexthdr` directly. Possible
  - the verifier can accept a statically-bounded unrolled loop - but adds
  real complexity and edge cases (a Fragment header's own sub-fields, more
  bounds checks) for a case this project has no way to generate real
  traffic for and confirm against; keeping the simple version and stating
  the limitation plainly matches this project's existing honest-scope-
  boundary pattern (ADR-0004, 0005, 0006, 0007) better than adding
  untested complexity.
- **IPv6 enforcement in this same PR** (blocklist/allowlist/rate-limit/
  port-scan/ICMP-flood for IPv6, via new 128-bit-keyed maps). Rejected as
  far too large for one PR, and explicitly not what ROADMAP.md's "IPv6
  header parsing" wording asks for - see Context and Known gap.

## Known gap

- **No IPv6 enforcement.** `allowed_ips`, `blocked_ips`, `rate_state`,
  `scan_state`, and `icmp_state` remain IPv4-only, `__u32`-keyed maps,
  untouched by this PR. An IPv6 packet is always passed, regardless of any
  blocklist/allowlist/rate-limit/port-scan/ICMP-flood state - there is no
  way to block an IPv6 address with this firewall today. A future PR
  adding that needs, at minimum: a 128-bit-keyed map type, a `drop_event`
  layout decision (extend it or add a parallel IPv6 variant), the
  corresponding `engine.cpp`/Local API/SQLite-schema/dashboard changes,
  and an `ipv6_addr` nftables set for `bouncer-nft`.
- **Extension headers are not walked**, as detailed in Decision above - a
  packet with an extension header ahead of its real transport payload is
  bucketed as "other" rather than resolved to its actual protocol.
- **Real NIC/driver behavior is still unverified by this PR** - see "What
  was actually found" for exactly what `BPF_PROG_TEST_RUN` does and
  doesn't cover. Attaching to a real interface and confirming real
  dual-stack traffic is classified as expected is the user's hardware to
  do, same as every prior XDP-touching change in this project.
