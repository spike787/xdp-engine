# ADR 0006: Capability drop instead of root

## Status
Accepted

## Context

Every long-running binary in this project has, since its first commit, been
documented as "run with sudo": `engine`, `bouncer-xdp`, and `bouncer-nft` all
say so in their own usage banners and in README's Privileges section. That
was true in the sense that *something* at startup needs elevated privilege
(loading a BPF program, attaching XDP to a NIC, writing to nftables), but it
meant each of these processes ran as full root - with every capability,
including ones they never use (`CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`, etc.) -
for their entire lifetime, including the part of that lifetime spent parsing
untrusted log lines, running YAML-defined rules, and talking to an HTTP
endpoint in a loop. ROADMAP.md's Phase 3 names this directly: "capability
drop instead of root."

Rather than assume what each binary actually needs, every claim below was
checked against a real, running kernel (this sandbox's `6.18.44`, which -
unlike XDP attach, which still needs the user's real hardware to confirm,
see Consequences below - does support plain BPF map syscalls and real
`nft`/nf_tables), not just the `capabilities(7)` man page:

- **`BPF_MAP_CREATE` requires `CAP_BPF`.** Confirmed: with every capability
  dropped, a plain `BPF_MAP_CREATE` syscall fails with `EPERM`.
- **`BPF_PROG_LOAD` of an XDP-type program requires `CAP_BPF` *and*
  `CAP_NET_ADMIN`.** Confirmed: loading a trivial valid XDP program (`r0 =
  XDP_PASS; exit;`) succeeds with full root, and fails with `EPERM` when
  only `CAP_BPF` is held and `CAP_NET_ADMIN` is not - matching
  `capabilities(7)`'s "CAP_NET_ADMIN and CAP_BPF are required to load
  networking programs."
- **`BPF_OBJ_GET` on a pinned *map* needs no capability at all.** This is
  the one that isn't obvious from a skim of `capabilities(7)` - the kernel's
  BPF object-pinning code (`bpf_obj_do_get()`) only capability-gates
  `BPF_OBJ_GET`/`BPF_OBJ_PIN` for *program* and *link* objects; for *map*
  objects it falls back to an ordinary filesystem permission check
  (`path_permission()`) on the bpffs pin path instead, the same ACL model
  as any other file. Confirmed directly: a process with every capability
  dropped - including as a genuinely non-root user (uid 999, gid 30001,
  zero entries in `CapEff`/`CapPrm`/`CapBnd`) against a map pin file it
  only *group*-owns (mode `0660`) - successfully opened the pin and
  performed a real `BPF_MAP_UPDATE_ELEM` + `BPF_MAP_LOOKUP_ELEM` round
  trip (wrote `123`, read back `123`).
- **Map element operations (`UPDATE_ELEM`/`LOOKUP_ELEM`/`DELETE_ELEM`/
  `GET_NEXT_KEY`) on an fd already held need no capability either** -
  confirmed in the same test above; only *acquiring* a map or program fd
  from scratch is capability-gated (and only for non-map object types, per
  the point above).
- **Ambient capabilities propagate a single capability across `execve()`
  of a plain (non-setuid, no file capabilities) child binary, regardless
  of either process's uid.** Confirmed: a fully non-root parent (uid 999)
  with `CAP_NET_ADMIN` in its own permitted+inheritable+ambient sets
  `execve()`s a plain child binary that ends up with *exactly*
  `CAP_NET_ADMIN` (bit 12) in its own effective/permitted/ambient sets -
  nothing more, nothing less. This is exactly the real `bouncer-nft` →
  `nft` relationship, confirmed end to end: `bouncer-nft`, run via
  `setpriv` as uid 999/gid 30001 with only `CAP_NET_ADMIN` ambient, really
  did create a working `table inet xdp_engine { set blocked_ips; chain
  input { ... drop; } }` through its own `nft` subprocess.

What couldn't be checked in this sandbox: the actual `bpf_xdp_attach`-to-a-
real-NIC step (this project has consistently needed the user's own Fedora
hardware for anything that attaches XDP to a real interface, going back to
ADR-0002), and therefore whether `bpf_program__attach_xdp()`'s netlink-based
attach path needs exactly `CAP_NET_ADMIN` as expected. That part still needs
real-hardware confirmation, like every other XDP-attach change in this
project.

## Decision

A new `capdrop.h` (dependency-free - no `libcap`, same "shell out instead of
link a library" preference as ADR-0004's choice to shell out to `nft`
instead of linking `libnftables` - raw `capget()`/`capset()` via
`<linux/capability.h>`, which the libbpf build already needs kernel headers
for) gives each binary a `drop_capabilities_to({keep...})` call that always
succeeds, regardless of current privilege (it's one-way: it can only
*shrink* the effective/permitted/inheritable sets down to a subset of what's
already held, never grant something new), plus `drop_bounding_except()` and
`raise_ambient()` for the two patterns below. Applied per binary:

- **`engine`**: drops *everything*, immediately after its three pinned-map
  fds are open (it never acquires a program/link object, only maps, so per
  the finding above it never needed any capability to begin with - this
  mainly guards the rest of its long life: log tailing, rule evaluation,
  storage, playbooks).
- **`bouncer-xdp`**: keeps `CAP_BPF`+`CAP_NET_ADMIN` only through the
  cold-start attach+pin step (or nothing at all, on the resume-from-
  existing-pin path - resuming only opens a pinned *map*); drops
  everything right before entering the poll loop, since every loop
  iteration only calls `bpf_map_update_elem()`/`delete_elem()` on the fd
  already in hand.
- **`bouncer-nft`**: keeps `CAP_NET_ADMIN` in effective/permitted/
  inheritable *and* pushes it into the ambient set, for its entire life
  (every poll iteration re-execs `nft`, unlike the other two) - drops
  everything else immediately at startup, before `setup()`'s first `nft`
  call.
- **`local-api`**: no change. It never touched a capability-gated syscall
  to begin with (confirmed by inspection, not just absence of `sudo` in
  the README) - it only reads the shared SQLite DB and serves HTTP.

**Opt-in, not automatic: `XDP_ENGINE_GROUP`.** Dropping `bouncer-xdp`'s own
capabilities to nothing doesn't by itself let `engine` run as a non-root
user, because the *first* cold-start still creates `/sys/fs/bpf/xdp_engine`
and its pins under whatever root's default umask produces (typically
`root:root`, unreadable by anyone else). If the `XDP_ENGINE_GROUP`
environment variable names a real group, `bouncer-xdp` `chgrp`s the pin
directory (`0750`) and every map pin (`0660`) to it on a fresh cold-start
attach, so `engine` can then run as a plain member of that group with zero
capabilities of its own - confirmed with the same non-root/group-ownership
test referenced above. Left unset (the default), nothing changes: pins stay
root-owned, exactly today's behavior.

**Why `cleanup` stays fully privileged.** Both bouncers' `cleanup`
subcommands (detach/unpin, flush the nftables table) are short, operator-
invoked, one-shot commands, not long-running daemons - the "a bug or
compromise years into an uptime" threat model this ADR is written for
doesn't really apply to a command that runs for a few milliseconds and
exits. Dropping capabilities there would only add a chance of a confusing
`EPERM` for no real security benefit, so neither `cleanup` path calls into
`capdrop.h` at all.

## Consequences

- A process compromised or buggy well into its uptime (the realistic
  threat model for a long-running network-facing daemon) can no longer
  leverage its historical "runs as root" status into loading new BPF
  programs, attaching to arbitrary interfaces, or anything else root can
  do - `engine` and a running `bouncer-xdp` hold *zero* capabilities once
  past startup, and `bouncer-nft` holds exactly one (`CAP_NET_ADMIN`).
- This is additive and backward compatible: every binary still works
  exactly as before when invoked via plain `sudo` (the default, still-
  documented path) - the drop happens *after* whatever privileged step
  each binary needs, so nothing about today's behavior changes except
  that the resulting process is less powerful than it used to be for the
  rest of its life.
- A fully non-root deployment (no `sudo` at all) is possible today without
  further code changes, by combining this with external uid/capability
  provisioning the binaries don't do for themselves - e.g. a systemd unit
  with `AmbientCapabilities=CAP_NET_ADMIN` + `User=` for `bouncer-nft`, or
  `setpriv`/`CapabilityBoundingSet=` for `bouncer-xdp`'s one-time
  cold-start, plus `XDP_ENGINE_GROUP` for `engine`. See README's updated
  Privileges section for example commands - both were exercised directly
  in this sandbox (not just written down): `bouncer-nft` really ran as
  uid 999/gid 30001 via `setpriv --ambient-caps=+net_admin` and produced a
  working nftables table through its `nft` subprocess.
- `bouncer-xdp`'s own cold-start attach step (and `engine`'s very first
  run against a freshly-created pin directory, if `XDP_ENGINE_GROUP` is
  used) still needs root or `CAP_BPF`+`CAP_NET_ADMIN` from *somewhere* -
  this ADR reduces the *lifetime* each binary spends privileged, not the
  fact that loading/attaching BPF fundamentally requires it once.

## Alternatives considered

- **`libcap`** for a friendlier capability API. Rejected for the same
  reason ADR-0004 rejected `libnftables`: it's one more build dependency
  (`libcap-dev`/`libcap-devel`) for something the raw `capset()`/
  `capget()` syscalls - already a stone's throw from the libbpf/kernel
  headers this project already requires - do perfectly well without it.
- **Switching UID in-process** (the binaries themselves calling
  `setuid()`/`setgid()` to a hardcoded service account) instead of leaving
  that to the deployment layer (`systemd`'s `User=`, `setpriv`, etc).
  Rejected for this PR: it would mean inventing and provisioning a system
  user/group from inside the binary (adding a user is not this project's
  job), and the capability-drop story already delivers the main security
  property (an exploited process can't regain privileged BPF/netlink
  operations) without it. `XDP_ENGINE_GROUP` is the one piece of
  provisioning glue this PR *does* take on, because it's just a `chgrp`+
  `chmod` on files `bouncer-xdp` already owns, not a new system identity.
- **Dropping capabilities inside `xdp_prog.bpf.c` itself** - not
  applicable; that's kernel-side BPF bytecode, it has no capability set of
  its own to drop. This ADR is entirely about the userspace control-plane
  binaries.

## Known gap

- No binary here provisions the non-root system user/group the fully
  unprivileged deployment recipe in README assumes exists
  (`useradd`/`groupadd` is left to the admin, same "honest scope boundary"
  this project has applied elsewhere - e.g. ADR-0004 not sharing bouncer
  process code, ADR-0005 not adding per-bouncer metrics in that same PR).
- `bouncer-xdp`'s real XDP-attach path (as opposed to the BPF map/prog-load
  syscalls this ADR's claims were checked against directly) still needs
  the user's real Fedora hardware to confirm end to end, consistent with
  every prior ADR that touches XDP attach.
