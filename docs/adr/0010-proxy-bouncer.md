# ADR 0010: bouncer-proxy, the third Remediation Component

## Status
Accepted

## Context

ADR-0001 named this from the start, as the answer to a gap neither of the
other two bouncers can close:

> Enforcement is tied to XDP specifically - a host without XDP support, or
> traffic that XDP can't see (TLS-terminated app traffic behind a proxy),
> can't be protected at all.

`bouncer-xdp` (ADR-0002) needs an XDP-capable NIC/kernel and
`CAP_BPF`/`CAP_NET_ADMIN`. `bouncer-nft` (ADR-0004) relaxes that to
`nf_tables` + `CAP_NET_ADMIN` - still real preconditions a container
without host networking, a locked-down PaaS, or a managed environment with
no path to any Linux capability at all simply doesn't have. Both also only
ever see raw IP packets: a TLS-terminated HTTP request behind a load
balancer or reverse proxy is already decrypted application traffic by the
time anything downstream of TLS termination could apply a rule to its
path, headers, or body - which is exactly the shape of attack this
project's own detection targets (SQL injection, path traversal - see
`http_detector.h`) once it's past the packet layer.

ROADMAP.md Phase 3 names this bouncer "proxy/app-layer" directly, and the
architecture diagram in ROADMAP.md has always drawn it as the third,
parallel box alongside the XDP and nftables bouncers - same `/decisions`
feed, same "pluggable enforcement" claim, now true for all three instead
of two.

## Decision

Introduce `bouncer-proxy`: a reverse HTTP proxy in front of **one**
backend, matching `bouncer-xdp`/`bouncer-nft`'s role precisely but
enforcing at the application layer instead of the packet layer.

1. **Same poll loop shape as its siblings**: `fetch_decisions()` against
   `GET /decisions` (a self-contained copy, same reasoning as ADR-0004 for
   why this isn't shared across bouncers), `diff_decisions()` from
   `bouncer_diff.h` reused **completely unmodified** - a third bouncer
   confirms that claim again, at the header level, not just the two
   ADR-0004 already proved it for.
2. **No kernel object to reconcile.** `bouncer-xdp` updates a BPF map;
   `bouncer-nft` runs an `nft` script. `bouncer-proxy`'s entire
   enforcement state is one in-memory `std::unordered_set<uint32_t>`,
   guarded by a mutex and read by every request-handling thread.
   "Applying" a diff is just replacing that set - `diff_decisions()` is
   still called, purely to log what changed (`[ENFORCE]`/`[RELEASE]`,
   matching the other two bouncers' output exactly), not because applying
   the result needs it.
3. **Every request goes through one `set_pre_routing_handler`** (cpp-httplib,
   already a dependency via `local-api`): look up the client's
   `req.remote_addr` against the current blocked set; if blocked, respond
   `403` immediately and never touch the backend; otherwise forward the
   request verbatim (method, raw target including the query string, body,
   headers minus the hop-by-hop ones - see `proxy_bouncer_core.h`) to the
   backend via `httplib::Client::send()`, and relay its response back the
   same way. One hook handles both routing decisions for every method and
   path - no per-method handler registration needed, because this proxy
   has no routes of its own to distinguish; it either blocks or forwards,
   always.
4. **Fail static, not fail open, applies to startup too.** Unlike
   `bouncer-xdp`/`bouncer-nft`, which can resume against a kernel object
   that survives a restart, `bouncer-proxy` has nothing to resume against
   - a fresh process genuinely starts with no information. Rather than
   begin serving with an empty (hence "nothing blocked yet") set and
   catching up on the first background poll a few seconds later,
   `bouncer-proxy` performs **one synchronous `fetch_decisions()` call
   before `httplib::Server::listen()` starts accepting connections at
   all** - refusing to start if that first fetch fails, the same
   "refusing to start with an unknown baseline" principle ADR-0004 applies
   to `bouncer-nft`'s own startup.
5. **No privilege required, and it proves that rather than asserting it.**
   `bouncer-proxy` is a plain userspace HTTP proxy: no BPF map, no
   netfilter rule, nothing that needs any Linux capability. It still calls
   `capdrop::drop_bounding_except({}); capdrop::drop_all_capabilities(...)`
   unconditionally at startup - a no-op if there was nothing to drop, but
   the same "don't assume, verify" spirit ADR-0006 established, and the
   clearest demonstration yet of a bouncer that needs no privilege in the
   first place rather than one that drops down to a minimal set.
6. **No `cleanup` subcommand**, unlike its two siblings. `bouncer-xdp` and
   `bouncer-nft` each leave persistent state behind in the kernel
   (a pinned BPF link/maps; an nftables table) that outlives the process
   and needs an explicit command to remove. `bouncer-proxy` leaves nothing
   behind - stopping the process *is* the cleanup, since its entire
   enforcement state is the in-memory set that dies with it.
7. **`--backend` defaults to `http://127.0.0.1:5000`** - this project's
   own Live Showcase Dashboard (`dashboard/app.py`) - so `bouncer-proxy`
   has something real and already-in-this-repo to front out of the box,
   not a placeholder requiring the person running it to stand up their own
   backend first. `--backend URL` overrides it for fronting anything else.

### What's shared vs. duplicated with the other two bouncers

Same answer ADR-0004 gave: `bouncer_diff.h` is shared verbatim, everything
else (`/decisions` HTTP client, CLI parsing, the poll loop's shape) is a
separate, self-contained copy - each bouncer stays independently
buildable, testable, and deployable without either of the other two even
present, which is the entire point of "pluggable" enforcement.

### New pure, testable logic

`proxy_bouncer_core.h`'s `is_hop_by_hop_header()` - whether a given header
name is one of RFC 7230 §6.1's hop-by-hop headers (plus `Content-Length`,
stripped so it's always recomputed from the body actually being sent
rather than copied from one hop and potentially mismatching the other) -
is the one piece of this bouncer's logic worth factoring out and unit
testing in isolation, the same role `bouncer_diff.h` plays for
`bouncer-xdp` and `nft_bouncer_core.h` plays for `bouncer-nft`. Covered in
`tests/test_proxy_bouncer_core.cpp`: every standard hop-by-hop header
name, case-insensitivity (header names are matched case-insensitively per
RFC 7230 §3.2), and that this is exact field-name matching, not a
substring search (`X-Connection-Id` must not match on `Connection`).

## What was actually tested

Run end to end in this sandbox - no BPF, no root, no kernel feature of any
kind required, unlike every prior bouncer ADR, which is itself one of this
bouncer's selling points:

- A trivial HTTP backend, `local-api`, and `bouncer-proxy` (built via
  `make all`, not just compiled standalone) all running together.
- **Pass-through**: a request through `bouncer-proxy` reached the backend
  and relayed its response (status, body) back correctly.
- **Block**: inserting a `block` decision for the client's own IP, waiting
  one poll interval, then the same request got `403` - the backend never
  saw it.
- **Release**: removing the decision, waiting one more poll interval, the
  same request got `200` again.
- **Backend down**: stopping the backend mid-test got a `502` with a
  clear message, not a hang or a crash.

## Consequences

- A host can now run `bouncer-proxy` in front of one HTTP service with
  zero changes to `engine`, `local-api`, `bouncer-xdp`, or `bouncer-nft` -
  the "pluggable enforcement" claim in ROADMAP.md's architecture diagram
  is now true for all three of its bouncer boxes.
- `bouncer-proxy` only protects the one backend it fronts, and only
  requests that actually go through it - unlike `bouncer-xdp`/`bouncer-nft`,
  which protect every service on the host at the packet layer, a blocked
  IP can still reach anything else on the machine directly if it's
  reachable by another path. This is an inherent, not accidental, tradeoff
  of application-layer enforcement and is the same one CrowdSec's own
  reverse-proxy bouncers make.
- Added latency: every request now makes two HTTP round trips end to end
  (client → `bouncer-proxy` → backend) instead of one. No benchmark is
  claimed here, matching ADR-0004's choice not to benchmark
  `bouncer-nft`'s throughput either - this bouncer's value proposition is
  reach (works anywhere a plain HTTP(S) listener can run), not raw
  performance.

## Alternatives considered

- **A generic TCP-level proxy** (raw socket forwarding, no HTTP parsing)
  instead of an HTTP-aware reverse proxy. Rejected: a TCP-level proxy
  can't apply a per-request decision (it would have to block or allow an
  entire connection, losing the "block this attacker's requests, not
  necessarily every byte on this TCP connection" granularity), and would
  duplicate HTTP framing logic cpp-httplib already provides correctly.
- **Registering per-method catch-all routes** (`Get("(.*)", ...)`,
  `Post("(.*)", ...)`, etc.) instead of one `set_pre_routing_handler`.
  Rejected: `set_pre_routing_handler` runs before routing for every method
  and path uniformly, which is exactly what a proxy with no routes of its
  own needs - registering six near-identical catch-all handlers would be
  pure duplication for the same outcome.
- **Sharing the `/decisions` HTTP client with `bouncer-xdp`/`bouncer-nft`**
  via a common header. Rejected for the reason ADR-0004 already gave:
  each bouncer stays independently buildable and deployable without the
  others present, which a shared dependency would compromise for very
  little duplication saved (under 50 lines per bouncer).

## Known gap

- **No WebSocket upgrade support.** `Upgrade`/`Connection: Upgrade` is
  stripped like every other hop-by-hop header, so a backend that serves
  WebSocket connections on the same origin this proxy fronts won't have
  them work through it. Out of scope for this phase - the attack
  scenarios this project detects (SQLi, path traversal, brute force) are
  all ordinary request/response HTTP, not WebSocket traffic.
- **No response trailers**, and large bodies are buffered in memory rather
  than streamed - `httplib::Client::send()`/the server's `Response::body`
  are both whole-buffer APIs here, not chunked `ContentProvider`
  streaming. Fine for the dashboard and any ordinary web app response
  size; would need revisiting for a backend serving very large responses.
- **Client IP comes from `req.remote_addr` only** - the raw TCP peer
  address of whoever connected to `bouncer-proxy` directly. If
  `bouncer-proxy` itself sits behind *another* reverse proxy or load
  balancer, every request would appear to come from that intermediary's
  address, not the real client's, and `X-Forwarded-For`/`X-Real-IP` are
  not consulted at all. This is a deliberate omission, not an oversight:
  trusting a client-supplied header for IP-based blocking decisions
  without first establishing which upstream hops are allowed to set it
  is a well-known spoofing vector, and getting that trust configuration
  right (which hop, how many, which header) is its own real feature, not
  a one-line addition - left for a future phase if `bouncer-proxy` is ever
  deployed behind another proxy rather than directly in front of clients.
- **IPv4 only**, consistent with every other enforcement surface in this
  project today (`bouncer_diff.h`'s `uint32_t` keys, `parse_ipv4` in
  `utils.h`) - see ADR-0008's Known gap for the same limitation stated for
  the kernel path.
