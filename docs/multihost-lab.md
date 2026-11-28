# Multi-host lab (ROADMAP.md Phase 4)

ROADMAP.md's Phase 4 calls for proving the architecture's central claim —
one shared Local API, multiple independent enforcement nodes — against
something more convincing than a single process on localhost. This lab
uses Linux network namespaces to simulate several separate hosts on one
machine: each namespace gets its own kernel network stack, its own
routing table, and its own netfilter state, bridged together into one L2
network the way separate physical machines on a LAN would be. `local-api`
runs once, in the default namespace; each bouncer runs in its own
namespace, reachable only over real TCP/IP across that bridge, with no
shared process state between them.

Set up the topology with `tools/multihost_lab.sh start` (`stop` tears it
down). It creates:

```
br-lab (10.99.0.1/24)
  |-- client     (10.99.0.2/24)  - generates traffic
  |-- host-xdp   (10.99.0.11/24) - runs bouncer-xdp against its own veth
  |-- host-nft   (10.99.0.12/24) - runs bouncer-nft
  |-- host-proxy (10.99.0.13/24) - runs bouncer-proxy + a tiny backend
```

All four namespaces, including `host-xdp`, are part of the topology the
script creates, and all four are now confirmed working — `host-xdp`'s
`bouncer-xdp` needs one extra step to run inside a namespace (see
**bouncer-xdp and network namespaces**, below, and use
`tools/multihost_lab.sh exec host-xdp <cmd>` rather than raw `ip netns
exec` to get it). That section also covers two sandbox-only failures hit
while first investigating this, neither of which reproduced on real
hardware.

## What was actually run

With the topology up, `local-api` was started once in the default
namespace (`LOCAL_API_TOKEN=... ./local-api /tmp/multihost_lab.db 8088`,
bound to `0.0.0.0` so it's reachable via `10.99.0.1` from every
namespace). `bouncer-nft` was started inside `host-nft` (`--iface
veth-nft --lapi-url http://10.99.0.1:8088`), and a tiny Python HTTP
backend plus `bouncer-proxy` were started inside `host-proxy`
(`--backend http://10.99.0.13:5000 --listen-port 8080 --lapi-url
http://10.99.0.1:8088`).

Baseline, with no decisions recorded: a ping from `client` to `host-nft`
succeeded, and a `curl` from `client` to `host-proxy:8080` returned `200`.

A block decision for the client's address was inserted directly into
`/tmp/multihost_lab.db`'s `decisions` table (the same technique used to
test `bouncer-proxy` in isolation during its own PR, standing in for what
`engine` would otherwise write):

```sql
INSERT INTO decisions (ts, ip, action, reason, rule, expires_at_unix, ttl_seconds, host)
VALUES (datetime('now'), '10.99.0.2', 'block', 'multihost-lab-test', 'multihost-lab-test', <now+600>, 600, 'lab-ctrl');
```

After one poll interval (1s), **both** bouncers, in their own separate
namespaces, independently converged on enforcing it:

- `client → host-nft` ping: 100% packet loss.
- `client → host-proxy:8080`: `403`.
- `ip netns exec host-nft nft list set inet xdp_engine blocked_ips` showed
  `elements = { 10.99.0.2 }` — confirmed directly against the namespace's
  own, independent netfilter state, not inferred from the bouncer's own
  logs.

Deleting the decision and waiting one more poll interval: ping succeeded
again, `curl` returned `200` again, and the nft set was back to empty.
Neither bouncer was told about the other, and neither talked to anything
except the one shared `local-api` instance. This is the thing Phase 4 set
out to prove, and it held.

## bouncer-xdp and network namespaces

Getting `bouncer-xdp` running inside `host-xdp` surfaced a real,
reproducible interaction between `ip netns exec` and the BPF filesystem,
plus one separate sandbox-only curiosity along the way.

**The root cause (reproducible, fixed, confirmed on real hardware):**
`bouncer-xdp`'s cold-start pins its maps under `/sys/fs/bpf/xdp_engine/`
(ADR-0002). Running it via plain `sudo ip netns exec host-xdp
./bouncer-xdp ...` fails that pin with `ENOENT`:

```
libbpf: failed to mkdir /sys/fs/bpf/xdp_engine/icmp_state: -ENOENT
[bouncer-xdp] failed to pin map icmp_state: No such file or directory
```

This isn't a bug in `bouncer-xdp`, and it isn't sandbox-specific — it's
how `ip netns exec` works everywhere. Each invocation gets a brand-new
mount namespace (`unshare(CLONE_NEWNS)`) so it can remount `/sys` to show
only that network namespace's own interfaces under `/sys/class/net`. But
bpffs, mounted at `/sys/fs/bpf` in the *default* mount namespace, is a
separate mount that doesn't carry over into that fresh one — so
`/sys/fs/bpf` exists as a bare directory with nothing mounted on it, and
pinning anything under it fails. This happens on every ordinary Linux box,
not just in a sandbox; it was just easier to first notice in one.

The fix is to (re-)mount bpffs inside the same `ip netns exec` invocation
that runs `bouncer-xdp`, since the mount only lives as long as that
invocation's mount namespace does. `tools/multihost_lab.sh` now has an
`exec` subcommand that does exactly this:

```bash
sudo ./tools/multihost_lab.sh exec host-xdp env LOCAL_API_TOKEN=lab-secret \
    ./bouncer-xdp veth-xdp --lapi-url http://10.99.0.1:8088 --poll-interval 1
```

**Confirmed on real hardware**, using the lab's own `host-xdp` namespace
with the `exec` subcommand above: `bouncer-xdp` attached and pinned
cleanly, and actually enforced the fan-out this lab set out to prove —

- Baseline: `ping` from `client` to `host-xdp` (`10.99.0.11`) succeeded.
- After the block decision was inserted: **100% packet loss** on that same
  ping, and `bouncer-proxy` (running independently in `host-proxy`, from
  the same decision) returned `403`.
- After deleting the decision: ping succeeded again (`0%` loss), and the
  proxy returned `200` again.

That's the real thing Phase 4 asks for — actual packet drops at the
kernel level, not just a log line saying a decision was processed — and
all three bouncers (`bouncer-nft`, `bouncer-proxy`, `bouncer-xdp`) now
have it, independently, from one shared `local-api`.

**A separate, still-unexplained sandbox curiosity**, kept here for the
record rather than swept away: earlier, before finding the bpffs root
cause above, two sandbox-only workarounds were tried and are *not* part
of the shipped script or the real-hardware result above. Attaching
generic-mode XDP directly to the bridge device (`br-lab`) itself attached
without error but silently broke unrelated L2 forwarding through that
bridge — abandoned, since a bridge master device was never a documented
attach point for this project anyway. Separately, attaching `bouncer-xdp`
to a bare point-to-point veth pair in the *default* namespace (where
pinning works) attached cleanly, pinned cleanly, and updated `blocked_ips`
correctly (confirmed via a standalone libbpf dump tool), but the packet
was never actually dropped and the `stats`/`proto_stats` maps stayed at
all zeros — the hook itself never fired, despite every other signal
looking correct. That specific failure did not reproduce in the real
`host-xdp` namespace test above, so it looks like it was particular to
that one sandboxed environment's generic-XDP path rather than a general
risk — but since the cause was never root-caused the way the bpffs issue
was, ROADMAP.md's environment note still stands as written: a clean
attach plus a correctly-updated map is not, by itself, sufficient
evidence that enforcement works. Confirm packet-level effects (like the
ping/curl results above), not just the attach call succeeding.

## Conclusion

**Proven**, on real hardware as well as in this lab's nft/proxy run:
`bouncer-nft`, `bouncer-proxy`, and `bouncer-xdp` each correctly enforce
decisions from one shared `local-api` instance while running in genuinely
separate Linux network namespaces, with no communication between them —
ROADMAP.md Phase 4's central architectural claim, demonstrated for all
three bouncers. The one condition for `bouncer-xdp`: run it via
`tools/multihost_lab.sh exec <namespace> <cmd>` rather than raw `ip netns
exec`, so bpffs is mounted before it tries to pin its maps.
