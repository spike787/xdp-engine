# Enforcement: bouncers and the privilege model

Detection and enforcement are separate processes. `engine` decides what to
block; a **bouncer** is a small, independent binary that polls
`local-api`'s `GET /decisions` and enforces it by whatever mechanism it
owns — the same Remediation Component pattern CrowdSec uses (see
[ADR-0001](adr/0001-architecture.md)). Three bouncers exist today, each
trading reach for performance differently; run whichever one(s) fit the
host you're protecting.

## bouncer-xdp — kernel-level, line-rate

`bouncer-xdp` is the only binary that ever loads `xdp_prog.bpf.c` and
attaches it to a NIC (see
[ADR-0002](adr/0002-bouncer-xdp-separation.md)). It has no rule engine and
no database of its own — it just polls `/decisions` and reconciles the
kernel's `blocked_ips` map to match.

```bash
sudo ./bouncer-xdp wlp8s0
# or, with non-default Local API settings:
sudo ./bouncer-xdp wlp8s0 --lapi-url http://127.0.0.1:8088 --lapi-token your-secret --poll-interval 2
# or, against a TLS-enabled Local API (ADR-0012):
sudo ./bouncer-xdp wlp8s0 --lapi-url https://127.0.0.1:8088 --lapi-token your-secret \
    --lapi-ca-cert dev-certs/ca.pem
```

On first attach it pins every map plus the XDP link itself under
`/sys/fs/bpf/xdp_engine/`. That means **restarting `bouncer-xdp` does not
drop enforcement** — on startup it notices the existing pins and resumes
polling against the already-attached program instead of re-attaching. To
actually detach and remove the pins:

```bash
sudo ./bouncer-xdp cleanup wlp8s0
```

## bouncer-nft — no XDP required

`bouncer-nft` is a second, independent Remediation Component — same role
as `bouncer-xdp`, but via an nftables set instead of a BPF map, so it works
on any host with `nft`/`nf_tables` and no XDP-capable NIC or kernel
required (see [ADR-0004](adr/0004-nftables-bouncer.md)). It trades
`bouncer-xdp`'s line-rate packets-per-second ceiling for running basically
anywhere.

```bash
sudo ./bouncer-nft
# scope enforcement to one interface instead of all of them:
sudo ./bouncer-nft --iface wlp8s0
# or, with non-default Local API settings:
sudo ./bouncer-nft --lapi-url http://127.0.0.1:8088 --lapi-token your-secret --poll-interval 2
# or, against a TLS-enabled Local API (ADR-0012):
sudo ./bouncer-nft --lapi-url https://127.0.0.1:8088 --lapi-token your-secret \
    --lapi-ca-cert dev-certs/ca.pem
```

On first run it creates `table inet xdp_engine` with a `blocked_ips` set
and an `input`-hook rule dropping `ip saddr @blocked_ips`. Restarting
`bouncer-nft` resumes against the existing table/set/rule rather than
duplicating them — the same resume-safety guarantee `bouncer-xdp` makes
for its pinned BPF map. To remove the table entirely:

```bash
sudo ./bouncer-nft cleanup
```

Run at most one packet-layer bouncer at a time per host — `bouncer-xdp`
and `bouncer-nft` both independently enforce the same decisions by
different mechanisms, and running both together is untested (see
ADR-0004).

## bouncer-proxy — application layer, no privilege required

`bouncer-proxy` is the third Remediation Component — same `/decisions`
feed, but enforced as an HTTP reverse proxy in front of a single backend
instead of at the packet layer (see [ADR-0010](adr/0010-proxy-bouncer.md)).
It covers traffic the other two bouncers can't see at all —
TLS-terminated application traffic, or a host with no XDP/`nf_tables`
capability whatsoever — and is the first bouncer that needs **zero** Linux
capabilities to run, not just after a brief privileged startup.

```bash
# fronts dashboard/app.py (127.0.0.1:5000) on :8080 by default:
./bouncer-proxy
# front a different backend, on a different listen port:
./bouncer-proxy --backend http://127.0.0.1:3000 --listen-port 9090
# or, with non-default Local API settings:
./bouncer-proxy --lapi-url http://127.0.0.1:8088 --lapi-token your-secret --poll-interval 2
# or, against a TLS-enabled Local API that also requires a client cert (mTLS, ADR-0012):
./bouncer-proxy --lapi-url https://127.0.0.1:8088 --lapi-token your-secret \
    --lapi-ca-cert dev-certs/ca.pem \
    --lapi-client-cert dev-certs/client.pem --lapi-client-key dev-certs/client-key.pem
```

Every request is checked against the current block set (keyed by the
client's TCP peer address) before anything is forwarded: a blocked client
gets `403` immediately and the backend never sees the request; everything
else is relayed through verbatim (method, full target including query
string, body, and headers minus the hop-by-hop ones RFC 7230 §6.1 says a
proxy must not forward), with the backend's response relayed back the same
way. If the backend is unreachable, the client gets `502`.

No `sudo` is needed, and there's no `cleanup` subcommand — unlike the
other two bouncers, `bouncer-proxy` has no persistent kernel-level state to
tear down; its entire enforcement state is an in-memory set that
disappears the moment the process stops. As with the other two bouncers,
run at most one enforcement mechanism per backend you care about —
`bouncer-proxy` only protects requests that actually go through it, not
the whole host.

`LOCAL_API_TOKEN`/`--lapi-token` work identically across all three
bouncers, and so do the TLS flags shown above
(`--lapi-ca-cert`/`LAPI_CA_CERT`, `--lapi-client-cert`+`--lapi-client-key`/
`LAPI_CLIENT_CERT`+`LAPI_CLIENT_KEY` for mTLS, and
`--lapi-insecure-skip-verify`/`LAPI_TLS_INSECURE_SKIP_VERIFY=1` for lab
use only) — see [Local API](local-api.md#tls-and-mtls-adr-0012) and
[ADR-0012](adr/0012-tls-local-api.md) for the server side and full design.

## Privileges & capability drop

See [ADR-0006](adr/0006-capability-drop.md) for the full writeup,
including the sandbox tests behind these claims.

| Binary | Needs privilege for | Capability footprint |
|---|---|---|
| `engine` | nothing, ever | drops to zero capabilities right after startup |
| `bouncer-xdp` | loading/attaching the XDP program (cold start only; resuming an existing attachment needs nothing) | `CAP_BPF`+`CAP_NET_ADMIN` during cold-start attach, then zero |
| `bouncer-nft` | every `nft` invocation, for its whole life | `CAP_NET_ADMIN` only, for its whole life |
| `bouncer-proxy` | nothing, ever | drops to zero capabilities right after startup (had none to begin with) |
| `local-api` | nothing | never needed privilege |
| either bouncer's `cleanup` subcommand | detach/unpin or flush, a short one-shot admin command | unchanged — stays fully privileged, by design |

**Simplest path — still `sudo`, nothing to configure.** Every command in
this document and the main README works exactly as written; each binary
now just drops what it isn't using once it's past any privileged step,
rather than keeping full root power for its whole life. Nothing to opt
into.

**Fully non-root, if you want it.** This requires provisioning a system
user/group yourself (this project doesn't create one for you — same
"don't auto-provision system state" boundary as everywhere else in this
codebase):

```bash
# One-time: a group engine can read pinned maps through, and a service user.
sudo groupadd xdp-engine
sudo useradd --system --no-create-home --gid xdp-engine xdp-engine-svc

# bouncer-xdp still needs a real privileged cold-start once, but hands
# engine a non-root path in afterward:
sudo XDP_ENGINE_GROUP=xdp-engine ./bouncer-xdp wlp8s0
sudo -u xdp-engine-svc ./engine wlp8s0 --enforce

# bouncer-nft, via setpriv (a systemd unit with User=xdp-engine-svc and
# AmbientCapabilities=CAP_NET_ADMIN gets you the same thing more durably):
sudo setpriv --reuid="$(id -u xdp-engine-svc)" --regid=xdp-engine --clear-groups \
    --inh-caps=+net_admin --ambient-caps=+net_admin --bounding-set=+net_admin \
    -- ./bouncer-nft --iface wlp8s0
```

Every command in that block was run as written against this project's own
sandboxed nftables stack while writing ADR-0006 (`bouncer-nft` really did
create a working table as uid 999/gid 30001 with nothing but
`CAP_NET_ADMIN`); the `bouncer-xdp`/`engine`/`XDP_ENGINE_GROUP` half still
needs real hardware to confirm against a physical NIC, the same as every
other XDP-attach change in this project.

---

See also: [Local API](local-api.md) for the `/decisions` feed every
bouncer polls, and the [main README](../README.md) for startup order.
