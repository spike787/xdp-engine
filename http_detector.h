// SPDX-License-Identifier: MIT
#ifndef HTTP_DETECTOR_H
#define HTTP_DETECTOR_H

#include <string>
#include <thread>
#include <functional>
#include <vector>
#include "event.h"
#include "rule_engine.h"
#include "log_parser.h"
#include "http_classifier.h"

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
    // docs/adr/0003-staged-parser-pipeline.md.
    LogParser parser_{"parsers/s01-parse/nginx-access.yaml"};

    // Classification of the extracted path/user_agent against rules.yaml's
    // http_traversal/http_sqli/http_scanner pattern lists - pulled out into
    // HttpClassifier so replay-cli (tools/replay_cli.cpp) classifies
    // against the exact same code path instead of a second copy of this
    // loop. No default constructor, so it's built in HttpDetector's own
    // constructor init list rather than here.
    HttpClassifier classifier_;
};

#endif // HTTP_DETECTOR_H
