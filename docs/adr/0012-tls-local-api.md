# ADR 0012: TLS/mTLS for Local API

## Status
Accepted

## Context

`local_api.cpp` has carried this comment since it was first written:

> Constant-time-ish compare to avoid the most obvious timing side channel
> on the bearer token check. Not a substitute for TLS/mTLS (see
> ROADMAP.md phase 3), but cheap to get right now.

That gap was real: every deployment so far runs `local-api` and its
bouncers in plaintext HTTP. `THREAT_MODEL.md` already names the bearer
token as the Local API's access control, but a bearer token sent over
plaintext HTTP is readable by anything that can see the wire between a
bouncer and `local-api` — the same network position that would let an
attacker sniff the token can also just replay it, or read every
`/decisions`/`/export` response directly, token or no token. This matters
more, not less, now that ADR-0011's multi-host lab makes "bouncer and
`local-api` on different hosts, talking over a real network" the expected
deployment shape rather than a loopback convenience.

## Decision

Add optional TLS to `local-api`'s server, and matching optional TLS to
each bouncer's `/decisions` client — optional and off by default, so
every existing deployment keeps working unchanged until someone opts in.

**Server (`local_api.cpp`)**: two new environment variables,
`LOCAL_API_TLS_CERT` and `LOCAL_API_TLS_KEY`. Setting both switches the
listening socket from a plain `httplib::Server` to `httplib::SSLServer`,
constructed through a common base-class pointer so the rest of the file
(every route registration) doesn't change at all. A third variable,
`LOCAL_API_TLS_CLIENT_CA`, is optional on top of that: when set, it's
passed as `SSLServer`'s client-CA argument, which makes cpp-httplib
require and verify a client certificate against that CA on every
connection (confirmed directly: a handshake with no client cert, or one
signed by a different CA, is rejected before any request handler —
including the bearer-token check — ever runs). Setting only one of
`_CERT`/`_KEY`, or setting `_CLIENT_CA` without the other two, is treated
as a startup error, not a silent fallback to plaintext or a silently
ignored setting — a half-configured TLS setup is far more likely to be a
typo than an intentional choice.

**Clients (`bouncer_xdp.cpp`, `bouncer_nft.cpp`, `bouncer_proxy.cpp`)**:
each bouncer's `/decisions` poll already goes through libcurl (self-
contained in each file — see ADR-0004 on why this isn't shared), so TLS
for them is four new libcurl options applied identically in all three,
each with a CLI flag and matching environment variable:

| Flag | Env var | Purpose |
|---|---|---|
| `--lapi-ca-cert FILE` | `LAPI_CA_CERT` | Verify `local-api`'s server cert against this CA instead of the system bundle (needed for a private/self-signed CA — the normal case here) |
| `--lapi-client-cert FILE` | `LAPI_CLIENT_CERT` | Present this certificate (mTLS) |
| `--lapi-client-key FILE` | `LAPI_CLIENT_KEY` | ...and this private key |
| `--lapi-insecure-skip-verify` | `LAPI_TLS_INSECURE_SKIP_VERIFY=1` | Disable server certificate verification entirely — dev/lab only, warns loudly on every startup it's used |

`--lapi-url https://...` alone is enough to speak TLS at all (libcurl,
built with OpenSSL support here, dispatches on the URL scheme); the CA/
client-cert flags are about *verifying* that connection the way a real
deployment should, not about turning TLS on in the first place.
`--lapi-client-cert`/`--lapi-client-key` must be given together or not at
all, checked at startup the same way the server checks its own cert/key
pair.

**`tools/gen_dev_certs.sh`** (new) generates a throwaway CA, a server
cert (with `local-api`'s usual addresses as SAN entries, plus an optional
extra one for things like the multi-host lab's bridge IP), and a client
cert for mTLS testing — mirroring `tools/multihost_lab.sh`'s own
"a real reusable tool, not a one-off set of commands buried in a doc"
approach.

### Why this split (CA verification vs. mTLS vs. insecure-skip-verify) instead of just "add HTTPS"

- A bearer token and a client certificate check different things and
  fail differently: the token says "this caller knows the shared
  secret"; the client cert says "this caller holds a private key the CA
  vouches for." Keeping both (rather than treating mTLS as a replacement
  for the token) means a leaked token alone, or a stolen cert alone,
  still isn't enough on its own.
- A self-signed/private CA is the realistic case for this project — there
  is no public CA reason to issue a certificate for an internal control
  plane — so `--lapi-ca-cert` pointing at that CA's own cert is the normal
  path, not an edge case. Relying on the system CA bundle (the libcurl
  default when no CA is given) only actually works if someone puts a real
  publicly-trusted certificate on `local-api`, which is a valid but
  separate deployment choice this ADR doesn't need to assume.
- `--lapi-insecure-skip-verify` exists because a lab/test setup without
  properly wiring up a CA cert is a real, common step on the way to a
  correct configuration — the same reason `curl -k` exists — but it's
  named and warned about as loudly as this project's other "lab, not
  production" escape hatches (e.g. `LOCAL_API_TOKEN` unset already logs a
  warning the same way), never silently accepted.

## Consequences

- Every existing invocation of `local-api` or any bouncer, with none of
  the new environment variables/flags set, behaves identically to before
  this change — confirmed by running the full `make test` suite (88/88
  still passing, nothing in it touches TLS) and by re-running the
  plaintext path of `docs/multihost-lab.md`'s test sequence unchanged.
- Confirmed directly (not just by reading cpp-httplib/libcurl
  documentation) against a locally-generated dev CA/cert, both directions:
  - Server-only TLS: a client without the CA cert fails to connect; a
    client with `--lapi-ca-cert` (or curl's `--cacert`) succeeds; plain
    HTTP to the same TLS-only port fails, as expected (TLS replaces the
    plaintext listener on that port, it doesn't layer alongside it).
  - mTLS (`LOCAL_API_TLS_CLIENT_CA` set): a client with no certificate is
    rejected at the TLS handshake itself (confirmed against both a raw
    `curl` client and `bouncer-proxy`'s libcurl client); a client with a
    certificate signed by the configured CA succeeds.
  - `--lapi-insecure-skip-verify` connects successfully against a
    self-signed cert with no CA configured at all, and prints its warning
    on every startup.
- This closes the gap the `local_api.cpp` comment above has pointed at
  since the file was first written — it can be removed/updated now that
  the thing it deferred actually exists.
- Not addressed by this ADR: certificate rotation/expiry handling (no
  code here reloads a cert without a process restart), and TLS for
  `bouncer-proxy`'s own front-facing listener (the one serving the
  protected application) — that's a different, deliberately out-of-scope
  surface; ADR-0010 already frames `bouncer-proxy` as typically sitting
  behind a TLS-terminating load balancer, not as a TLS terminator itself.

## Alternatives considered

- **Reusing `httplib::Client`/`SSLClient` for the bouncers' `/decisions`
  poll instead of libcurl**, since `bouncer-proxy` already links
  cpp-httplib for its own listener. Rejected: `bouncer-xdp` and
  `bouncer-nft` link only libcurl today (no httplib dependency at all),
  and adding cpp-httplib to both just for this would be a heavier,
  non-uniform change across the three bouncers for no behavioral
  difference — libcurl's TLS options are a strict, smaller addition to
  code that was already there.
- **Making TLS mandatory** (removing the plaintext path entirely).
  Rejected: this project's own multi-host lab, local dev workflow, and
  every existing doc example assume plaintext loopback or lab-network
  HTTP; forcing TLS everywhere would break all of that for a security
  property that matters most once bouncer and `local-api` are on
  different hosts, which is already the case this ADR is aimed at, not
  the common local-dev case.
- **A single shared `--insecure` flag that also disables the bearer-token
  check**, to simplify lab setup further. Rejected: token auth and TLS
  verification are unrelated controls (see above) and collapsing them
  into one flag would make it too easy to accidentally disable both at
  once.
