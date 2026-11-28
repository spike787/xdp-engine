# ADR 0011: Network-namespace multi-host lab

## Status
Accepted (partial result — see Known gap)

## Context

ROADMAP.md's Phase 4 names a "multi-host lab (2-3 nodes sharing one Local
API)" as the proof the architecture's central claim needed: that
`local-api` genuinely decouples detection from enforcement well enough
for several independent bouncers, on several independent hosts, to all
enforce the same decision correctly without any of them knowing the
others exist. Every previous bouncer PR tested its own bouncer alone,
against a `local-api` instance on the same host (often the same loopback
address) — never two bouncers at once, and never across a real network
boundary.

Separate physical or cloud machines were not available for this; this ADR
covers simulating that boundary with Linux network namespaces instead
(`tools/multihost_lab.sh`), each with its own independent kernel network
stack, routing table, and netfilter state, bridged into one L2 network
the way real separate hosts on a LAN would be.

## Decision

Build the lab, run all three bouncers against it, and report exactly what
each one proved — including where the attempt failed, rather than
narrowing scope quietly to only the parts that worked.

**`bouncer-nft` and `bouncer-proxy`**: both ran correctly in their own
namespaces, polling one shared `local-api` instance in the default
namespace, and independently converged on enforcing (and later releasing)
a decision inserted directly into the shared SQLite database — verified
not just by each bouncer's own report but by directly inspecting
`host-nft`'s own netfilter state (`nft list set`) and by exercising
`host-proxy`'s actual HTTP path end to end. This is the thing Phase 4 set
out to prove, for two of the three bouncers, and it held under a genuine
network/namespace boundary, not just on loopback.

**`bouncer-xdp`**: did not reach the same conclusion, after three
successive attempts, documented in full in
[docs/multihost-lab.md](../multihost-lab.md):

1. Its normal cold-start pinning (`/sys/fs/bpf/xdp_engine/`, ADR-0002)
   failed inside a non-default network namespace in this sandboxed agent
   environment specifically (`mkdir` under `/sys/fs/bpf` returned
   `ENOENT`, even as root with every capability present) — this sandbox
   appears to virtualize the BPF filesystem per network namespace, which
   is not standard Linux behavior and not something the real-hardware
   verification in PR #16/#17 ever encountered.
2. Attaching instead to the bridge device itself, in the default
   namespace, attached without error but broke the bridge's own L2
   forwarding for unrelated traffic - not a legitimate workaround, just a
   different failure.
3. Attaching to a plain point-to-point veth pair in the default namespace
   (mirroring `tools/setup_veth_lab.sh`'s already-proven pattern exactly)
   attached cleanly and pinned cleanly - a direct dump of the pinned
   `blocked_ips` map (written against this project's own `common.h` via
   `bpf_obj_get`, since no `bpftool` build was installable against this
   sandbox's kernel) confirmed the test decision was present and correctly
   formed. **The packet was still not dropped** - a dump of the `stats`
   map showed `dropped=0 passed=0`, meaning the XDP hook was never invoked
   for a single packet on that link at all, despite the attach reporting
   success.

That third result is the one worth stating plainly rather than explaining
away: in this kind of environment, a clean attach and a correctly updated
map are not sufficient evidence that enforcement actually works. This
doesn't contradict anything already established about `bouncer-xdp` -
every other claim about it was independently confirmed on real hardware
in PR #16 and PR #17 - it specifically means this *kind* of environment
cannot be used to validate the kernel packet-processing path, full stop,
which is exactly the caution ROADMAP.md's existing environment note
already carries. This ADR does not loosen that note; it adds a concrete
failure mode behind it, so a future session doesn't spend time on the
same workaround chain this one did.

## Consequences

- `tools/multihost_lab.sh` is a real, reusable tool for this lab, equally
  usable on real hardware or real VMs where `bouncer-xdp`'s equivalent
  proof remains to be completed - closing that gap needs ROADMAP.md's
  originally-stated resource (two or more real machines), not another
  attempt in an agent sandbox.
- The architecture's core claim - one control plane, many independently
  enforcing nodes - is now demonstrated, not just diagrammed, for two of
  the three bouncers.

## Alternatives considered

- **Docker containers instead of raw network namespaces.** `ip netns` was
  chosen because it needed no daemon (`dockerd` wasn't running in this
  environment and couldn't be started) and gives the same real kernel
  isolation (separate network stack, separate netfilter state) with less
  moving material between the host and each "node."
- **Silently dropping `bouncer-xdp` from the writeup once it didn't work.**
  Rejected - the three-step failure chain is itself useful information for
  whoever next tries this (don't bother with namespace-pinning
  workarounds or bridge-device attachment in a similar sandbox; just get
  real hardware), and it's cheap to just write it down honestly.

## Known gap

`bouncer-xdp`'s multi-host fan-out is not yet proven anywhere - single-host
only (real hardware, PR #16/#17) and this namespace lab (inconclusive, see
above). Completing it needs two or more real machines or real VMs running
`tools/multihost_lab.sh`'s topology, or the equivalent on genuinely
separate hosts.
