// SPDX-License-Identifier: MIT
#ifndef REPLAY_CORE_H
#define REPLAY_CORE_H

#include <ctime>
#include <string>
#include <unordered_map>
#include <vector>

#include "event.h"
#include "http_classifier.h"
#include "log_parser.h"
#include "rule_engine.h"
#include "utils.h"

// Feeds a corpus of already-read log lines through a LogParser + (for
// HTTP-style sources) an HttpClassifier, exactly as the live engine would,
// and runs the resulting Events through a RuleEngine to see what fires.
// This is ROADMAP.md Phase 2's "replay/backtest CLI" item - see
// tools/replay_cli.cpp for the thin main() wrapper around this.
//
// Known limitation, stated rather than hidden: Events built here are
// timestamped with the replay's own wall-clock time, not any timestamp
// recorded in the original log line. For a single burst of lines fed
// through quickly (the common "did this attack log trigger my rule"
// use case), that's immaterial - threshold/sequence window checks still
// see the lines as arriving in a tight cluster, same as they would if an
// attacker had actually sent them in a tight cluster. It does mean a log
// file whose entries were originally spread across hours replays as if
// they all happened within whatever real time it takes this tool to
// iterate the file - usually well under a second. Faithfully replaying a
// log's *original* timing would mean parsing each source's own timestamp
// format and driving RuleEngine's window/threshold logic from that
// instead of wall-clock time, which is a change to code the live engine
// also depends on - judged out of scope for this phase, the same
// honest-scope call ADR-0003 makes about what else Phase 2 does and
// doesn't do.
struct ReplayResult {
    int lines_read = 0;
    int lines_matched = 0;    // lines the parser successfully extracted fields from
    int lines_classified = 0; // of those, how many also classified as an attack type (HTTP-style sources only)
    std::vector<Alert> alerts;
};

inline std::string replay_now_iso() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&ts.tv_sec));
    return buf;
}

// `classifier` is nullptr for single-emit-type sources (e.g. SSH), where
// `parser.emit_type()` is already set and no further classification step
// is needed. Pass a real HttpClassifier for sources like HTTP, where
// `parser.emit_type()` is empty and the event type depends on the
// extracted fields.
inline ReplayResult replay_lines(const std::vector<std::string>& lines,
                                  const LogParser& parser,
                                  const HttpClassifier* classifier,
                                  RuleEngine& rule_engine) {
    ReplayResult result;
    result.lines_read = static_cast<int>(lines.size());

    for (const auto& line : lines) {
        std::unordered_map<std::string, std::string> fields;
        if (!parser.parse(line, fields)) continue;
        result.lines_matched++;

        auto ip_it = fields.find("ip");
        if (ip_it == fields.end() || !parse_ipv4(ip_it->second)) continue;

        std::string type = parser.emit_type();
        if (type.empty()) {
            if (!classifier) continue; // no fixed emit_type and no classifier - nothing to emit
            std::string path = fields.count("path") ? fields.at("path") : "";
            std::string ua = fields.count("user_agent") ? fields.at("user_agent") : "";
            type = classifier->classify(path, ua);
            if (type.empty()) continue;
            result.lines_classified++;
        }

        Event e;
        e.ts_iso = replay_now_iso();
        e.source = parser.source();
        e.type = type;
        e.src_ip = ip_it->second;
        auto user_it = fields.find("user");
        e.user = (user_it != fields.end()) ? user_it->second : "";
        e.severity = parser.severity();

        auto alerts = rule_engine.process(e);
        for (auto& a : alerts) result.alerts.push_back(std::move(a));
    }

    return result;
}

#endif // REPLAY_CORE_H
