// SPDX-License-Identifier: MIT
// replay-cli - ROADMAP.md Phase 2's "replay/backtest CLI": feed a captured
// log file through a parser (parsers/s01-parse/*.yaml) and a rules.yaml,
// and report what would have fired, without touching XDP, Local API, or
// anything root-privileged. See replay_core.h for the actual replay logic
// and its stated timing limitation.
//
// Usage:
//   replay-cli --rules rules.yaml --parser parsers/s01-parse/ssh-auth.yaml
//              --log auth.log [--log auth.log.1] [--format text|json]
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "../http_classifier.h"
#include "../log_parser.h"
#include "../replay_core.h"
#include "../rule_engine.h"

namespace {

void usage(const char* argv0) {
    std::cerr << "usage: " << argv0
              << " --rules RULES.yaml --parser PARSER.yaml --log LOGFILE [--log LOGFILE ...] "
                 "[--format text|json]\n";
}

std::vector<std::string> read_lines(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("could not open log file: " + path);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) lines.push_back(line);
    return lines;
}

} // namespace

int main(int argc, char** argv) {
    std::string rules_path, parser_path, format = "text";
    std::vector<std::string> log_paths;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--rules" && i + 1 < argc) rules_path = argv[++i];
        else if (arg == "--parser" && i + 1 < argc) parser_path = argv[++i];
        else if (arg == "--log" && i + 1 < argc) log_paths.push_back(argv[++i]);
        else if (arg == "--format" && i + 1 < argc) format = argv[++i];
        else { usage(argv[0]); return 1; }
    }

    if (rules_path.empty() || parser_path.empty() || log_paths.empty()) {
        usage(argv[0]);
        return 1;
    }
    if (format != "text" && format != "json") {
        std::cerr << "--format must be 'text' or 'json'\n";
        return 1;
    }

    try {
        RuleEngine rule_engine(rules_path);
        LogParser parser(parser_path);

        // Only HTTP-style sources (empty emit_type) need classification
        // against rules.yaml's http_traversal/http_sqli/http_scanner
        // pattern lists; single-emit-type sources (e.g. SSH) don't.
        bool needs_classifier = parser.emit_type().empty();
        HttpClassifier classifier(rule_engine); // cheap to build either way; only used if needed

        std::vector<std::string> all_lines;
        for (const auto& path : log_paths) {
            auto lines = read_lines(path);
            all_lines.insert(all_lines.end(), lines.begin(), lines.end());
        }

        ReplayResult result = replay_lines(all_lines, parser, needs_classifier ? &classifier : nullptr, rule_engine);

        if (format == "json") {
            nlohmann::json out;
            out["lines_read"] = result.lines_read;
            out["lines_matched"] = result.lines_matched;
            if (needs_classifier) out["lines_classified"] = result.lines_classified;
            out["alert_count"] = result.alerts.size();
            nlohmann::json alerts = nlohmann::json::array();
            for (const auto& a : result.alerts) alerts.push_back(a.to_json());
            out["alerts"] = alerts;
            std::cout << out.dump(2) << "\n";
        } else {
            std::cout << "Replayed " << log_paths.size() << " file(s) through '"
                      << parser_path << "' + '" << rules_path << "'\n";
            std::cout << "  lines read:       " << result.lines_read << "\n";
            std::cout << "  lines matched:    " << result.lines_matched << "\n";
            if (needs_classifier) {
                std::cout << "  lines classified: " << result.lines_classified
                          << " (matched an http_traversal/http_sqli/http_scanner pattern)\n";
            }
            std::cout << "  alerts fired:     " << result.alerts.size() << "\n";
            for (const auto& a : result.alerts) {
                std::cout << "    - " << a.rule << "  src_ip=" << a.src_ip
                          << "  severity=" << a.severity << "\n";
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "replay-cli: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
