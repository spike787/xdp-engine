# ADR 0007: Parser fuzzing

## Status
Accepted

## Context

ROADMAP.md Phase 3 names "parser fuzzing" directly. The part of this
codebase most worth fuzzing isn't hard to identify: `LogParser::parse()`
(`log_parser.h`) runs an operator-authored `std::regex` against a raw log
line, and anything it extracts - most notably `path`/`user_agent` for
HTTP, `user` for SSH - ultimately traces back to bytes a remote, untrusted
client controls (an attacker picks their own request path, their own
`User-Agent` header, their own SSH username). Two supporting functions
(`url_decode`/`sanitize_utf8`, `text_util.h`) do their own hand-rolled,
byte-level parsing on top of that - exactly the kind of manual index
arithmetic a fuzzer is good at breaking. None of the three had ever been
exercised with adversarial input before this; they're only ever covered by
example-driven unit tests (`tests/test_log_parser.cpp`,
`tests/test_http_classifier.cpp`) and real captured log lines (replay-cli,
ADR-0003's staged pipeline).

The BPF-side packet parsing in `xdp_prog.bpf.c` is a different problem
entirely (kernel bytecode, no `LLVMFuzzerTestOneInput` to link against) -
out of scope here, see Known gap.

## Decision

Three libFuzzer harnesses under `tools/`, narrowest-and-fastest first:

- **`fuzz_url_decode.cpp`** / **`fuzz_sanitize_utf8.cpp`**: call the one
  function directly, nothing else linked in - no YAML, no regex engine, so
  these run at ~100K-200K exec/s and get the most raw iterations for the
  byte-level code most likely to hide an off-by-one. Each also checks one
  real invariant beyond "didn't crash" (`url_decode` never *grows* its
  input; `sanitize_utf8` never exceeds its documented 128-byte cap) via
  `__builtin_trap()` - libFuzzer treats a trap exactly like a crash it
  needs to minimize and report.
- **`fuzz_log_parser.cpp`**: the realistic one - drives
  `replay_core.h`'s `replay_lines()` (the same function `replay-cli` uses
  for a real log file) one fuzzer-generated line at a time against both
  real parser YAMLs (`parsers/s01-parse/*.yaml`) and the real
  `rules.yaml`, exercising `LogParser::parse()` → `HttpClassifier::classify()`
  → `RuleEngine::process()` end to end exactly as the live engine would.
  A fresh `RuleEngine` is constructed per input (re-reading `rules.yaml`
  each time) rather than reused across iterations - slower (~900 exec/s
  measured), but it means a crash is reproducible from that one input
  alone, not from whatever unrelated inputs an earlier iteration happened
  to run first. `-timeout=5` is called out explicitly in the harness's own
  comment: `std::regex`'s backtracking engine can hang (ReDoS) rather than
  crash on a pathological pattern+input combination, which ASan/UBSan
  alone wouldn't catch - libFuzzer's own per-run timeout is what surfaces
  that class of finding.

**libFuzzer, not a standalone fuzzing framework (AFL++, honggfuzz).**
Already available for free: this project's build already requires clang
for the BPF compile stage (`CLANG ?= clang` in the Makefile), and clang
ships libFuzzer as part of its `compiler-rt` runtime - no new tool to
install, no new CI dependency, just a different set of `-fsanitize=`
flags on an existing compiler. The one gap: the base `clang`/`llvm`
packages this project already requires don't reliably pull in
`compiler-rt` as a dependency on every distro, so `make fuzz`/
`make fuzz-log-parser`/etc. can fail to link without it being installed
separately (`compiler-rt` on Fedora/RHEL, `libclang-rt-<ver>-dev` on
Ubuntu/Debian). Documented in README rather than silently handled, since
it's a dev-only, opt-in target, not something `make all` depends on.

**Separate `make fuzz*` targets, not part of `all` or `test`.** A fuzzer
is designed to run until you stop it (or `-max_total_time=N` tells it to)
- wiring it into `make test`'s normal "build it, run it once, exit"
contract would mean either an unbounded test suite or an arbitrary,
meaningless time box baked into CI. These are tools a developer or a
scheduled (not every-commit) CI job runs deliberately, the same reasoning
`asan`/`engine_asan` already established as a separate opt-in target
rather than folding sanitizer builds into the default build.

**Seed corpus checked in (`fuzz/corpus/<target>/`), fuzzer-discovered
corpus not.** Each seed is a small, hand-picked, real-shaped input (a
genuine SSH-failed-password line, a genuine sqlmap-flavored nginx access
line, a `url_decode` string mixing valid/invalid `%XX` sequences, a
`sanitize_utf8` string mixing valid multi-byte, overlong, surrogate, and
truncated UTF-8 sequences) - enough to get a fuzzing session started
productively without committing to the repo. The hundreds of
hash-named files libFuzzer itself adds to a corpus directory during a run
are gitignored (`fuzz/corpus/*/[0-9a-f]*`) - they're a regenerable
byproduct of running the fuzzer, not something meant to be reviewed or
diffed.

## What was actually found

All three harnesses were run against this seed corpus in a real sandbox,
not just written and left untested:

- `fuzz-url-decode`: **3,264,150 executions in 31s**, no crash.
- `fuzz-sanitize-utf8`: **6,095,720 executions in 31s**, no crash.
- `fuzz-log-parser`: **153,332 executions across two runs (61s + 121s)**,
  no crash, no `-timeout=5` hang (so no ReDoS found in either parser YAML
  shipped today, against this ruleset).

No bug was found or fixed by this PR - the three hand-rolled/regex-driven
functions this ADR targeted held up under real adversarial input. That's
a legitimate, useful outcome for a fuzzing PR to report (the alternative
to writing down "ran clean" is implying these harnesses were never
actually run, which would be worse): the harnesses now exist, are checked
into the repo, build correctly, and are ready to keep running - including
automatically catching a regression if a future change to `text_util.h`,
`log_parser.h`, or an operator-authored `rules.yaml`/parser YAML
introduces one.

## Consequences

- Running `make fuzz` (or an individual `fuzz-*` target) for longer than
  this PR's own verification pass costs nothing but time and the one
  extra package on Debian/Ubuntu - worth doing periodically, and
  certainly worth doing again after any future change to `text_util.h`,
  `log_parser.h`, `http_classifier.h`, or a new parser YAML.
- A real crash or hang found by any of these three, once fixed, is a
  candidate for a permanent regression entry in the relevant
  `tests/test_*.cpp` (the googletest suite `make test` already runs every
  build) - libFuzzer finding something and a unit test catching it forever
  after are complementary, not competing, the same way ASan/UBSan
  (`make asan`) complements `make test` rather than replacing it.

## Alternatives considered

- **AFL++ or honggfuzz** instead of libFuzzer. Rejected: both are
  perfectly good fuzzers, but neither is a dependency this project already
  has a reason to require, where clang (hence libFuzzer) already is one
  for the BPF build stage.
- **One harness fuzzing everything at once** (parser + classifier + rule
  engine + `url_decode` + `sanitize_utf8` all through a single entry
  point) instead of three. Rejected for the same reason this project
  keeps pure logic in its own small, separately-testable header
  (`bouncer_diff.h`, `nft_bouncer_core.h`, `prometheus_metrics.h`,
  `capdrop.h`): a narrow harness iterates orders of magnitude faster
  (100K+ exec/s vs. ~900 exec/s for the full pipeline) and a crash in one
  is immediately attributable to a specific function, not something that
  needs bisecting out of a combined harness afterward.
- **Fuzzing `rules.yaml`/parser-YAML *parsing itself*** (malformed YAML
  as the fuzz target, rather than malformed log lines against valid YAML)
  was considered and set aside: YAML files are operator-authored
  configuration, not attacker-reachable input, so a crash there is a
  "don't write broken YAML" problem, not a security one this project's
  threat model (ADR-0003's "staged parser pipeline" framing, CrowdSec-
  style attacker-vs-operator boundary) is concerned with.

## Known gap

- `xdp_prog.bpf.c`'s own packet-header parsing (the kernel-side XDP
  program, not any of the userspace log parsers this ADR covers) is not
  fuzzed here and can't be with the same tooling - there's no
  `LLVMFuzzerTestOneInput` to link a BPF program against. The kernel's own
  verifier already proves the program can't read out of bounds of the
  packet it was handed (this is XDP/eBPF's whole safety model, not
  something this project adds), so the risk profile is different in kind,
  not just untested - but it remains true that raw packet bytes reaching
  that parser have never been fuzzed the way this ADR's three harnesses
  fuzz the userspace log-line parsers.
