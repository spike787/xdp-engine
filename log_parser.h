// SPDX-License-Identifier: MIT
#ifndef LOG_PARSER_H
#define LOG_PARSER_H

#include <regex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include <yaml-cpp/yaml.h>

#include "text_util.h"

// Phase 2 of ROADMAP.md ("detection content as data"): before this, the
// line-format regex for each log source (the nginx combined-log pattern in
// http_detector.cpp, the "Failed password" pattern in engine.cpp's
// SshDetector) was hardcoded in C++. Adding a new log source meant a
// rebuild. LogParser moves that specific step - raw line in, named fields
// out - into a versioned YAML file instead.
//
// Deliberately narrow scope: a LogParser only replaces *envelope* parsing
// (recognizing a line belongs to this source and extracting named fields
// by regex capture group). What happens with those fields afterwards -
// e.g. HttpDetector testing `path`/`user_agent` against the
// http_traversal/http_sqli/http_scanner pattern lists - is unchanged,
// because that classification data already lived in rules.yaml as data
// before this phase. Duplicating those patterns into parser YAML too
// would just create a second, driftable source of truth for the same
// thing, not actually unlock anything new.
struct FieldCapture {
    std::string name;
    int group = 0;        // 1-based std::regex capture group index
    bool url_decode = false;
};

class LogParser {
public:
    explicit LogParser(const std::string& yaml_path) {
        YAML::Node config = YAML::LoadFile(yaml_path);

        name_ = config["name"].as<std::string>();
        source_ = config["source"].as<std::string>();
        pattern_ = std::regex(config["pattern"].as<std::string>());
        if (config["emit_type"]) emit_type_ = config["emit_type"].as<std::string>();
        if (config["severity"]) severity_ = config["severity"].as<int>();

        if (!config["fields"] || !config["fields"].IsSequence() || config["fields"].size() == 0) {
            throw std::runtime_error("log parser '" + name_ + "' (" + yaml_path +
                                      "): 'fields' must be a non-empty list");
        }

        for (const auto& f : config["fields"]) {
            FieldCapture fc;
            fc.name = f["name"].as<std::string>();
            fc.group = f["group"].as<int>();
            if (f["url_decode"]) fc.url_decode = f["url_decode"].as<bool>();
            if (fc.group < 1) {
                throw std::runtime_error("log parser '" + name_ + "': field '" + fc.name +
                                          "' has group " + std::to_string(fc.group) +
                                          " - capture groups are 1-based");
            }
            fields_.push_back(std::move(fc));
        }
    }

    // Tries to match `line` against this parser's pattern. On success,
    // fills `out` with each configured field's extracted value - url-
    // decoded first if the field asks for it, then always passed through
    // sanitize_utf8 since every value here comes from attacker-reachable
    // log content - and returns true. Leaves `out` untouched on failure
    // (no partial fill).
    bool parse(const std::string& line, std::unordered_map<std::string, std::string>& out) const {
        std::smatch m;
        if (!std::regex_search(line, m, pattern_)) return false;

        std::unordered_map<std::string, std::string> extracted;
        for (const auto& f : fields_) {
            if (static_cast<std::size_t>(f.group) >= m.size()) continue; // group didn't participate
            std::string value = m[f.group].str();
            if (f.url_decode) value = url_decode(value);
            extracted[f.name] = sanitize_utf8(value);
        }
        out = std::move(extracted);
        return true;
    }

    const std::string& name() const { return name_; }
    const std::string& source() const { return source_; }
    // Empty when classification happens downstream (e.g. HTTP, where the
    // event type depends on which rules.yaml pattern list matches).
    const std::string& emit_type() const { return emit_type_; }
    int severity() const { return severity_; }

private:
    std::string name_;
    std::string source_;
    std::string emit_type_;
    int severity_ = 3;
    std::regex pattern_;
    std::vector<FieldCapture> fields_;
};

#endif // LOG_PARSER_H
