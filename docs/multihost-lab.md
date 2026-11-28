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
  |-- host-nft   (10.99.0.12/24) - runs bouncer-nft
  |-- host-proxy (10.99.0.13/24) - runs bouncer-proxy + a tiny backend
```

(`host-xdp` is deliberately not part of the default topology — see
**What didn't work** below.)

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

## What didn't work: bouncer-xdp

Getting `bouncer-xdp` into the same proof turned out to need three
successive workarounds, the last of which exposed a limitation worth
being honest about rather than quietly working around further.

1. **BPF pinning failed inside any non-default network namespace.**
   `bouncer-xdp`'s cold-start pins its maps under
   `/sys/fs/bpf/xdp_engine/` (ADR-0002). Inside `host-xdp`'s namespace,
   even as root with every capability present (`cap_bpf`, `cap_sys_admin`,
   confirmed via `capsh --decode`), `mkdir` under `/sys/fs/bpf` failed
   with `ENOENT` — and a directory created from the default namespace was
   invisible from inside `host-xdp`'s. This points to the BPF filesystem
   being virtualized per network namespace in this particular sandboxed
   agent environment specifically — not standard Linux behavior, and not
   something ADR-0002 or the real-hardware verification in PR #16/#17 ever
   hit.
2. **Working around that by attaching to the bridge device itself
   (`br-lab`) in the default namespace broke the bridge entirely.**
   Generic-mode XDP attached to `br-lab` without error, but it silently
   broke L2 forwarding for traffic that had nothing to do with the
   bridge's own address — `host-nft → local-api` started timing out the
   moment the program was attached to `br-lab`, and recovered the moment
   it was detached. Also not something to route around further; a bridge
   master device is not a documented or intended XDP attach point for
   this project in the first place.
3. **Working around *that* with a plain point-to-point veth pair**
   (mirroring `tools/setup_veth_lab.sh`'s already-proven pattern exactly:
   `bouncer-xdp` attached in the default namespace, where pinning does
   work) **attached cleanly, pinned cleanly, and updated `blocked_ips`
   correctly** — a standalone dump of the pinned map (written against
   this project's own `common.h`/`bpf_obj_get`, since `bpftool` wasn't
   installable against this sandbox's kernel) confirmed the client's
   address was present with `expires_at_ns = 0` (permanent), exactly what
   the decision should have produced. **But the packet never got
   dropped** — a ping through that link still showed `0%` packet loss, and
   a dump of the `stats`/`proto_stats` maps showed `dropped=0 passed=0`
   and all four protocol counters at `0`, meaning the XDP program was
   never invoked for a single packet on that link at all, despite
   attaching without any reported error.

That third finding is the important one: the attach and the map update
both succeed and look correct, but the actual packet-processing hook
never fires. That's a sharper trap than "XDP needs a real NIC" — it means
a shallow check (attach succeeds, no errors) is not sufficient evidence
that enforcement works in an environment like this one, which is exactly
why ROADMAP.md's existing environment note (any kernel-attach change
"must be verified on a real box... before being called done") is correct
as written and is not being loosened by this lab. It's being sharpened: an
agent sandbox can get as far as a clean attach and a correctly-updated map
and still prove nothing about actual enforcement.

## Conclusion

- **Proven, in this lab, independent of any real hardware**: `bouncer-nft`
  and `bouncer-proxy` each correctly enforce decisions from one shared
  `local-api` instance while running in genuinely separate Linux network
  namespaces, with no communication between them.
- **Still open**: `bouncer-xdp`'s equivalent multi-host proof. It cannot
  be completed in this kind of sandboxed agent environment - not due to a
  bug in `bouncer-xdp` itself (every other property it has was already
  verified correct on real hardware in PR #16/#17), but because this
  environment's XDP packet-processing path does not actually fire,
  despite every surface signal (attach, JIT compile, map updates) looking
  correct. Confirming it needs what ROADMAP.md already asked for: two or
  more real machines or real VMs, not another pass at a sandbox.
