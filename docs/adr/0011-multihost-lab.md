# ADR 0011: Network-namespace multi-host lab

## Status
Accepted

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

**`bouncer-xdp`**: took three attempts to get right, two of them dead
ends, documented in full in [docs/multihost-lab.md](../multihost-lab.md):

1. Its normal cold-start pinning (`/sys/fs/bpf/xdp_engine/`, ADR-0002)
   failed inside `host-xdp`'s namespace with `mkdir ... ENOENT`. This
   turned out to be a general property of `ip netns exec`, not a sandbox
   artifact: each invocation gets a brand-new mount namespace (so it can
   remount `/sys` to show only that network namespace's interfaces), and
   bpffs mounted at `/sys/fs/bpf` in the default mount namespace doesn't
   carry over into that fresh one. **Root cause found, and fixed**:
   `tools/multihost_lab.sh exec <namespace> <cmd>` (re-)mounts bpffs
   inside the same invocation before running the command, which is what
   `bouncer-xdp` needs every time it's launched this way.
2. Before that root cause was found, attaching instead to the bridge
   device itself, in the default namespace, was tried as a workaround and
   attached without error but broke the bridge's own L2 forwarding for
   unrelated traffic - abandoned, not part of the shipped script.
3. Also before the root cause was found, attaching to a plain
   point-to-point veth pair in the default namespace attached cleanly and
   pinned cleanly - a direct dump of the pinned `blocked_ips` map (written
   against this project's own `common.h` via `bpf_obj_get`, since no
   `bpftool` build was installable in that environment) confirmed the test
   decision was present and correctly formed, but the packet was still not
   dropped (`stats` showed `dropped=0 passed=0` - the hook never fired for
   any packet on that link). This did not reproduce once the real
   `host-xdp` namespace was used with the bpffs-mount fix on real
   hardware, so it looks specific to whatever sandboxed environment first
   surfaced it, not to namespaces or to `bouncer-xdp` itself - but since it
   was never independently root-caused the way (1) was, ROADMAP.md's
   environment note is left exactly as strict as it already was: a clean
   attach and a correctly-updated map are still not, by themselves,
   sufficient evidence that enforcement works; confirm actual
   packet-level effects.

With the bpffs-mount fix in place, **`bouncer-xdp` was confirmed on real
hardware** running inside the lab's own `host-xdp` namespace: baseline
ping succeeded, a block decision produced 100% packet loss (and a `403`
from the independently-running `bouncer-proxy`, from the same decision),
and deleting the decision restored both. All three bouncers now have this
proof, independently, from one shared `local-api`.

## Consequences

- `tools/multihost_lab.sh` is a real, reusable tool for this lab on real
  hardware or real VMs, for all three bouncers - including `bouncer-xdp`
  via its `exec` subcommand.
- The architecture's core claim - one control plane, many independently
  enforcing nodes - is now demonstrated, not just diagrammed, for all
  three bouncers.
- The `ip netns exec` + bpffs interaction is worth remembering for any
  future BPF-pinning work that might run inside a namespace: mount bpffs
  fresh in the same invocation, don't assume it's inherited.

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

None outstanding for this ADR. The one remaining loose end is the
sandbox-only "hook never fired on a point-to-point veth" curiosity from
attempt 3 above, which is recorded in
[docs/multihost-lab.md](../multihost-lab.md) for the record but did not
reproduce in the real-hardware `host-xdp` test and is not believed to
reflect anything about `bouncer-xdp`, namespaces, or this project's code.
