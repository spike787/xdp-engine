# ADR 0003: staged parser pipeline for log-source envelope parsing

## Status
Accepted

## Context

ADR 0001 named one of the original engine's architectural gaps as:
"Detection content (regex patterns, thresholds) is hardcoded in C++, so
adding a new log format means a rebuild, not a config change." ROADMAP.md
Phase 2 ("detection content as data") is the item that actually closes
that gap, for the piece of detection content that was still hardcoded.

Looking at what was actually hardcoded in C++ versus already config-driven
going into Phase 2:

- **Already data, not code**: the attack-signature pattern lists
  (`http_traversal`/`http_sqli`/`http_scanner`'s regex patterns,
  thresholds, windows, MITRE IDs, playbook steps) all live in
  `rules.yaml`/`playbooks.yaml` already, and are loaded by `RuleEngine`/
  `PlaybookRunner` at startup. This was true before this ADR.
- **Still hardcoded in C++**: the *envelope* parsing - recognizing that a
  raw line belongs to a given log source at all, and pulling the handful
  of named fields (an IP, a username, a request path, a user-agent) out of
  it by regex. This lived as a `static const std::regex` inside
  `SshDetector::handle_line` (engine.cpp) and `HttpDetector::process_line`
  (http_detector.cpp). Adding a third log source - say, a different
  application's log format - meant writing and shipping new C++, not
  editing a config file.

## Decision

Introduce a `LogParser` class (`log_parser.h`) that loads one YAML file
describing a single log source's envelope format:

```yaml
name: ssh-auth-failed-password
source: ssh_log
pattern: 'Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3}) port \d+ ssh2'
fields:
  - name: user
    group: 1
  - name: ip
    group: 2
emit_type: ssh_failed
severity: 3
```

`fields` maps 1-based `std::regex` capture groups to named fields;
`url_decode: true` on a field runs it through URL-decoding before the
(always-applied) UTF-8 sanitization pass, matching what the hardcoded
HTTP path extraction already did. `emit_type` is optional - present for
SSH (one event type per source), absent for HTTP, where the event type
still depends on testing the extracted `path`/`user_agent` fields against
`rules.yaml`'s existing pattern lists.

Parser definitions live under `parsers/s01-parse/` (one file per log
source), named for CrowdSec's own staged-parser convention even though
this project implements a much narrower slice of it - see "Alternatives
considered" below for what was deliberately left out.

`SshDetector` and `HttpDetector` now hold a `LogParser` member constructed
from their respective YAML file, and call `parser_.parse(line, fields)`
instead of running their own `std::regex_search`. Everything downstream of
that (ssh: build an `Event` directly; http: test `path`/`user_agent`
against `rules.yaml`'s pattern lists and call `emit(type)`) is unchanged.

## Consequences

- Adding a new log source is now: write a parser YAML file, add
  corresponding entries to `rules.yaml` if it needs threshold/sequence
  detection, and wire a `LogTailer` + `LogParser` pair into `engine.cpp`'s
  `main()`. No new C++ regex, no rebuild of the parsing logic itself
  (though wiring a new source into `main()`'s thread setup is still a
  C++ change in this phase - see "known limitation" below).
- `LogParser` is a small, independently unit-tested component
  (`tests/test_log_parser.cpp`) with no dependency on `LogTailer`,
  `RuleEngine`, or anything kernel/XDP-related - it can be exercised
  completely off a real box, unlike the enforcement path.
- Verified the two checked-in parser files reproduce byte-for-byte the
  same field extraction the old hardcoded regexes did, against real
  sample lines (including a CSV-injection-style crafted SSH username and
  a URL-encoded SQLi path captured during this project's own testing).

## Alternatives considered

- **Full CrowdSec-style grammar** (grok patterns, an `expr`-language filter
  per node, a `statics` block for arbitrary field assignment, hot-reload).
  Rejected for scope, per ROADMAP.md's "honest scope boundary": this
  project's parsers only ever need "does this regex match, and if so what
  are these N named groups" - building a general expression evaluator to
  express that would be solving a much bigger problem than the one this
  project actually has.
- **Also move attack-signature patterns into the new parser YAML**,
  duplicating a `classifiers:` block alongside the envelope `pattern:`.
  Rejected: those patterns already live in `rules.yaml` as data. Moving
  them into a second YAML file wouldn't make anything more configurable
  that isn't already configurable today - it would just create two
  sources of truth for the same `http_sqli`/`http_traversal`/
  `http_scanner` pattern lists, with the attendant risk of them drifting
  apart.
- **A generic `s02-enrich` YAML stage** for the "enrich" word in ROADMAP's
  "raw/parse/enrich" phrasing. Not added in this pass: `PlaybookRunner`'s
  existing `enrich` playbook step (labeling an IP from `known_ips.txt`)
  already satisfies the spirit of a config-driven enrichment step for
  what this project currently needs. A dedicated enrichment YAML stage is
  left as a later extension point if a concrete need for it shows up
  (e.g. GeoIP tagging), rather than building it speculatively now.

## Known limitation

Wiring a *new* log source into `engine.cpp`'s `main()` (constructing its
`LogTailer`/detector and spawning its watcher thread) is still a C++
change - this phase makes the envelope-parsing regex itself data-driven,
not the whole process of registering a new source. Generalizing
`SshDetector`/`HttpDetector` into one fully generic, declaratively-wired
log watcher is a reasonable next step but was judged a larger, riskier
change than this phase's actual goal warranted.
