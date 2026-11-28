# Detection internals

How raw traffic and log lines become a classified alert, and the tooling
used to test and harden that path.

## Staged parser pipeline

The regex that recognizes a raw log line and extracts named fields from it
(an IP, a username, a request path, a user-agent) lives in versioned YAML
under `parsers/s01-parse/`, not hardcoded in C++ — see
[ADR-0003](adr/0003-staged-parser-pipeline.md). `SshDetector` and
`HttpDetector` each load one of these at startup via the `LogParser` class
(`log_parser.h`):

- **`parsers/s01-parse/ssh-auth.yaml`** — matches `Failed password for ...`
  lines from `/var/log/secure`/`/var/log/auth.log`, extracting `user` and
  `ip`.
- **`parsers/s01-parse/nginx-access.yaml`** — matches nginx's combined log
  format, extracting `ip`, `path` (URL-decoded), and `user_agent`.

A parser file looks like this:

```yaml
name: ssh-auth-failed-password
source: ssh_log
pattern: 'Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3}) port \d+ ssh2'
fields:
  - name: user
    group: 1          # 1-based regex capture group
  - name: ip
    group: 2
emit_type: ssh_failed  # fixed event type for this source; omit if
                       # classification depends on the extracted fields
                       # (see nginx-access.yaml, classified against
                       # rules.yaml's http_traversal/http_sqli/
                       # http_scanner pattern lists instead)
severity: 3
```

This only replaces *envelope* parsing. The attack-signature pattern lists
that classify an HTTP request as traversal/SQLi/scanner already live in
`rules.yaml` and are untouched by this — see the ADR for why those weren't
also duplicated into parser YAML.

## replay-cli — log replay / backtesting

`tools/replay-cli` is a standalone CLI (ROADMAP.md Phase 2) that answers
"would this rule have fired against this log?" without touching a kernel,
root, or the live engine at all. It feeds a captured log file through the
same `LogParser` + `HttpClassifier` + `RuleEngine` code paths the live
`engine` process uses, and prints what would have alerted:

```bash
./tools/replay-cli --rules rules.yaml \
    --parser parsers/s01-parse/ssh-auth.yaml \
    --log /var/log/auth.log
```

```
Replayed 1 file(s) through 'parsers/s01-parse/ssh-auth.yaml' + 'rules.yaml'
  lines read:       5
  lines matched:    5
  alerts fired:     1
    - SSH_BRUTE_FORCE  src_ip=203.0.113.9  severity=high
```

- `--log` may be repeated to replay several files (e.g. rotated logs) as
  one combined run.
- `--format json` prints a machine-readable summary instead (counts plus
  one object per fired alert) for piping into other tooling.
- Pass an HTTP-style parser (`parsers/s01-parse/nginx-access.yaml`) to
  replay web-attack logs instead — the tool classifies traversal/SQLi/
  scanner the same way `HttpDetector` does, against the same `rules.yaml`
  pattern lists.

**Known limitation:** replayed events are timestamped with the replay's
own wall-clock time, not any timestamp recorded in the original log line.
For a single burst of lines (the common "did this attack log trip my
rule" use case) that's immaterial — threshold/sequence windows still see
the lines arrive in a tight cluster. It does mean a log file whose entries
were originally spread across hours replays as if they all happened in
whatever time it takes the tool to read the file. Faithfully replaying
original log timing would mean changing `RuleEngine`'s window/threshold
logic to run off parsed log timestamps instead of `steady_clock`, which
the live engine also depends on — judged out of scope for this phase. See
the comment at the top of `replay_core.h` for the full reasoning.

## Parser fuzzing

[ADR-0007](adr/0007-parser-fuzzing.md) has the full writeup. Three
`libFuzzer` harnesses under `tools/` target the parts of this codebase
that actually run on attacker-reachable bytes — a log line's envelope
regex (`LogParser::parse()`), and the two hand-rolled, byte-level
`url_decode()`/`sanitize_utf8()` helpers every extracted field goes
through (`text_util.h`):

```bash
make fuzz               # builds all three (needs clang's fuzzer+ASan+UBSan runtime)
./tools/fuzz-url-decode      -max_total_time=60 fuzz/corpus/url_decode
./tools/fuzz-sanitize-utf8   -max_total_time=60 fuzz/corpus/sanitize_utf8
./tools/fuzz-log-parser      -max_total_time=120 -timeout=5 fuzz/corpus/log_parser
```

`-timeout=5` on the last one matters specifically: a log line is matched
against an operator-authored `std::regex`, which can hang (not crash) on a
pathological pattern+input combination (ReDoS) — a plain crash-only
fuzzing run wouldn't catch that class of bug. Not part of `all`/`test` —
these run until you stop them, so they're a developer/CI-triggered thing,
not a build step.

`make fuzz` needs clang's `compiler-rt` runtime (where libFuzzer itself
lives), which the base `clang`/`llvm` packages don't always pull in as a
dependency:

```bash
# Fedora/RHEL
sudo dnf install -y compiler-rt
# Ubuntu/Debian — package name's version suffix tracks your installed clang's
sudo apt install -y libclang-rt-18-dev
```

## IPv6 header parsing

[ADR-0008](adr/0008-ipv6-header-parsing.md) has the full writeup.
`xdp_prog.bpf.c` recognizes IPv6 traffic (previously it took the same
silent, uncounted `XDP_PASS` branch as ARP or anything else non-IPv4),
parses the fixed 40-byte IPv6 header, and classifies TCP/UDP/ICMPv6
packets into the same `proto_stats` counters IPv4 traffic already uses —
so `xdp_tcp_packets_total` (etc.) now means "this protocol, either IP
version", not "IPv4 only". This is visibility, not enforcement: every IPv6
packet still passes unconditionally. `allowed_ips`/`blocked_ips`/
`rate_state`/`scan_state`/`icmp_state` remain IPv4-only, `__u32`-keyed
maps — there is no way to block an IPv6 address with this firewall today
(see the ADR's known gap).

A tool verifies the kernel-side parsing logic itself, without needing a
NIC:

```bash
make xdp-prog-test          # needs CAP_BPF to load an XDP-type program - run as root
sudo ./tools/xdp-prog-test
```

It loads the real, compiled `xdp_prog.bpf.o` and runs synthetic IPv4 and
IPv6 packets through it via `BPF_PROG_TEST_RUN` (the same mechanism the
kernel's own BPF selftests use), checking both the returned verdict and
the counters it bumps — including a packet carrying an IPv6 extension
header, which demonstrates the one stated parsing limitation (extension
headers aren't walked; the packet is classified by the extension header's
own protocol number, not its real TCP/UDP/ICMPv6 payload) rather than just
asserting it in prose. Not part of `all`/`test`, same reasoning as
`asan`/`fuzz` being separate opt-in targets.

---

See also: [Testing & attack simulation](testing.md) for exercising this
pipeline end to end, and the [main README](../README.md) for build
instructions.
