// SPDX-License-Identifier: MIT
#ifndef HTTP_CLASSIFIER_H
#define HTTP_CLASSIFIER_H

#include <regex>
#include <string>
#include <vector>

#include "rule_engine.h"

// Loads the http_traversal/http_sqli/http_scanner pattern lists from
// rules.yaml (via RuleEngine::get_rules()) and classifies an already-
// parsed path/user_agent pair against them. This logic used to live
// inline inside HttpDetector::process_line; it's pulled out here so the
// live HttpDetector and the replay-cli tool (tools/replay_cli.cpp) both
// classify against exactly the same rules.yaml content through the same
// code path, rather than replay-cli re-typing its own copy of the loop.
class HttpClassifier {
public:
    explicit HttpClassifier(const RuleEngine& rule_engine) {
        for (const auto& r : rule_engine.get_rules()) {
            if (r.match_type == "http_traversal") {
                for (const auto& pat : r.patterns) traversal_patterns_.emplace_back(pat, std::regex::icase);
            } else if (r.match_type == "http_sqli") {
                for (const auto& pat : r.patterns) sqli_patterns_.emplace_back(pat, std::regex::icase);
            } else if (r.match_type == "http_scanner") {
                for (const auto& pat : r.patterns) scanner_patterns_.emplace_back(pat, std::regex::icase);
            }
        }
    }

    // Returns the matched event type ("http_traversal"/"http_sqli"/
    // "http_scanner"), or an empty string if nothing matched. Same
    // precedence and field-testing as the original inline loop:
    // traversal against `path` only, then sqli against `path` OR
    // `user_agent`, then scanner against `user_agent` only.
    std::string classify(const std::string& path, const std::string& user_agent) const {
        for (const auto& rx : traversal_patterns_) {
            if (std::regex_search(path, rx)) return "http_traversal";
        }
        for (const auto& rx : sqli_patterns_) {
            if (std::regex_search(path, rx) || std::regex_search(user_agent, rx)) return "http_sqli";
        }
        for (const auto& rx : scanner_patterns_) {
            if (std::regex_search(user_agent, rx)) return "http_scanner";
        }
        return "";
    }

private:
    std::vector<std::regex> traversal_patterns_;
    std::vector<std::regex> sqli_patterns_;
    std::vector<std::regex> scanner_patterns_;
};

#endif // HTTP_CLASSIFIER_H
