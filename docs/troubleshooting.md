# Troubleshooting & FAQ

**The dashboard top-right badge stays on "Loading Mode..."**
- Ensure the engine is running (`sudo ./engine <INTERFACE>`). When the
  engine starts, it updates the status in `engine.db` within 1 second.
- Ensure both the engine and dashboard are run from the project root
  (`~/xdp-engine`).

**"open failed: Permission denied"**
- eBPF operations require root privileges. Run `./bouncer-xdp` and
  `./engine` with `sudo`, or see
  [Privileges & capability drop](enforcement.md#privileges--capability-drop)
  for a non-root setup.

**`engine` won't start — "could not open pinned maps under
/sys/fs/bpf/xdp_engine"**
- `bouncer-xdp` isn't running on that interface yet — `engine` no longer
  attaches XDP itself since [ADR-0002](adr/0002-bouncer-xdp-separation.md),
  it just opens the maps `bouncer-xdp` pinned. Start
  `sudo ./bouncer-xdp <INTERFACE>` first.

**How do I cleanly detach XDP if `bouncer-xdp` crashed?**
- A crash alone doesn't detach anything — that's the point of pinning
  (enforcement survives it). Run `sudo ./bouncer-xdp cleanup <INTERFACE>`
  to actually detach and remove the pins. If that binary is unavailable
  for some reason, the raw escape hatch is
  `sudo ip link set dev <INTERFACE> xdp off` plus
  `sudo rm -rf /sys/fs/bpf/xdp_engine`.

---

See also: [Enforcement (bouncers)](enforcement.md) and the
[main README](../README.md#running-the-stack) for the full startup
sequence.
