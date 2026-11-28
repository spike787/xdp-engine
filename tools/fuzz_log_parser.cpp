// SPDX-License-Identifier: MIT
// libFuzzer harness for the full envelope-parse -> classify -> rule-engine
// pipeline (ROADMAP.md Phase 3, "parser fuzzing" - see
// docs/adr/0007-parser-fuzzing.md). Drives exactly the same code path
// replay_core.h's replay_lines() runs for a real log file (see
// tools/replay_cli.cpp) one fuzzer-generated line at a time, against both
// of this project's real parser YAMLs (parsers/s01-parse/*.yaml) and the
// real rules.yaml - this is the part of the engine that's genuinely
// attacker-reachable: an nginx access-log line's path/user-agent and an
// auth-log line's username both ultimately come from what a remote client
// sent.
//
// Must be run from the repository root (same convention every other
// binary here already assumes - engine.db, rules.yaml, parsers/, etc. are
// all relative paths).
//
// Build: make fuzz-log-parser
// Run:   ./tools/fuzz-log-parser -max_total_time=120 -timeout=5
//
// -timeout matters here specifically: LogParser::parse() runs an
// operator-authored std::regex against attacker-controlled bytes, and
// HttpClassifier::classify() does the same with rules.yaml's
// http_traversal/http_sqli/http_scanner patterns. std::regex's backtracking
// engine can blow up exponentially on a pathological combination of
// pattern and input (ReDoS) - a hang not a crash, so ASan/UBSan alone
// wouldn't catch it. libFuzzer's own per-run timeout is what surfaces that
// class of finding (see ADR-0007's "what was actually found" section for
// whether this run turned one up).
#include <cstdint>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include "../http_classifier.h"
#include "../log_parser.h"
#include "../replay_core.h"
#include "../rule_engine.h"

namespace {
std::unique_ptr<LogParser> g_ssh_parser;
std::unique_ptr<LogParser> g_http_parser;
std::unique_ptr<HttpClassifier> g_http_classifier;
} // namespace

extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/) {
    // These three are fixed, input-independent, and read-only after
    // construction (HttpClassifier's compiled regex list, in particular,
    // is immutable once built) - loading them once here rather than per
    // iteration is both the obvious performance win and the correct
    // modeling of how the real engine actually runs (every parser and the
    // classifier are constructed once at startup, not per log line).
    g_ssh_parser = std::make_unique<LogParser>("parsers/s01-parse/ssh-auth.yaml");
    g_http_parser = std::make_unique<LogParser>("parsers/s01-parse/nginx-access.yaml");
    RuleEngine rules_for_classifier{"rules.yaml"};
    g_http_classifier = std::make_unique<HttpClassifier>(rules_for_classifier);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::string line(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> one_line{line};

    // A fresh RuleEngine per input, deliberately, even though that means
    // re-reading+re-parsing rules.yaml on every iteration: RuleEngine's
    // threshold/sequence matching is stateful *across* process() calls by
    // design (rule_engine.h), but a fuzz target's whole value is that a
    // crash is reproducible from its one input alone - carrying state
    // across libFuzzer iterations would mean a crash could depend on
    // whatever earlier, unrelated inputs happened to run first.
    {
        RuleEngine rule_engine{"rules.yaml"};
        replay_lines(one_line, *g_ssh_parser, nullptr, rule_engine);
    }
    {
        RuleEngine rule_engine{"rules.yaml"};
        replay_lines(one_line, *g_http_parser, g_http_classifier.get(), rule_engine);
    }
    return 0;
}
