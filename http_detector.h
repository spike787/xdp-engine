// SPDX-License-Identifier: MIT
#ifndef HTTP_DETECTOR_H
#define HTTP_DETECTOR_H

#include <string>
#include <thread>
#include <functional>
#include <regex>
#include <vector>
#include "event.h"
#include "rule_engine.h"
#include "log_parser.h"

class HttpDetector {
public:
    using EventCallback = std::function<void(const Event&)>;
    HttpDetector(const std::string& log_file, const RuleEngine& rule_engine, EventCallback cb);
    ~HttpDetector();

    void process_line(const std::string& line);

public:
    void watch_loop(std::stop_token st);

    std::string log_file_;
    EventCallback cb_;
    std::jthread watcher_;

    // Envelope parsing (ip/path/user_agent extraction) moved to
    // parsers/s01-parse/nginx-access.yaml, loaded through LogParser - see
    // docs/adr/0003-staged-parser-pipeline.md. Classification against the
    // pattern lists below is unchanged.
    LogParser parser_{"parsers/s01-parse/nginx-access.yaml"};

    // Extracted signatures
    std::vector<std::regex> traversal_patterns_;
    std::vector<std::regex> sqli_patterns_;
    std::vector<std::regex> scanner_patterns_;
};

#endif // HTTP_DETECTOR_H
