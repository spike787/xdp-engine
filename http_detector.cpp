// SPDX-License-Identifier: MIT
#include "http_detector.h"
#include <fstream>
#include <iostream>
#include <unordered_map>
#include <arpa/inet.h>
#include <chrono>
#include <ctime>

static bool is_valid_ip(const std::string& ip) {
    struct in_addr addr;
    return inet_pton(AF_INET, ip.c_str(), &addr) == 1;
}

HttpDetector::HttpDetector(const std::string& log_file, const RuleEngine& rule_engine, EventCallback cb)
    : log_file_{log_file}, cb_{std::move(cb)} {
        
    for (const auto& r : rule_engine.get_rules()) {
        if (r.match_type == "http_traversal") {
            for (const auto& pat : r.patterns) traversal_patterns_.emplace_back(pat, std::regex::icase);
        } else if (r.match_type == "http_sqli") {
            for (const auto& pat : r.patterns) sqli_patterns_.emplace_back(pat, std::regex::icase);
        } else if (r.match_type == "http_scanner") {
            for (const auto& pat : r.patterns) scanner_patterns_.emplace_back(pat, std::regex::icase);
        }
    }
    
    watcher_ = std::jthread([this](std::stop_token st) { watch_loop(st); });
}

HttpDetector::~HttpDetector() {}

#include "log_tailer.h"

void HttpDetector::watch_loop(std::stop_token st) {
    LogTailer tailer(log_file_, [this](const std::string& line) {
        try { process_line(line); } catch(const std::exception& e) { static auto last_warn = std::chrono::steady_clock::time_point{}; auto now = std::chrono::steady_clock::now(); if (now - last_warn > std::chrono::seconds(5)) { std::cerr << "[WARN] Exception in http_detector: " << e.what() << "\n"; last_warn = now; } }
    });
    tailer.run(st);
}

void HttpDetector::process_line(const std::string& line) {
    if (line.size() > 4096) return; // cap line length

    // Envelope parsing (ip/path/user_agent) now lives in
    // parsers/s01-parse/nginx-access.yaml, loaded via parser_ - see
    // docs/adr/0003-staged-parser-pipeline.md. url_decode/sanitize_utf8
    // are applied inside LogParser::parse() itself now.
    std::unordered_map<std::string, std::string> fields;
    if (!parser_.parse(line, fields)) return;

    auto ip_it = fields.find("ip");
    if (ip_it == fields.end() || !is_valid_ip(ip_it->second)) return;
    std::string ip = ip_it->second;
    auto path_it = fields.find("path");
    auto ua_it = fields.find("user_agent");
    std::string path = (path_it != fields.end()) ? path_it->second : "";
    std::string ua = (ua_it != fields.end()) ? ua_it->second : "";

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&ts.tv_sec));

    auto emit = [&](const std::string& type) {
        Event e;
        e.ts_iso = time_buf;
        e.source = parser_.source();
        e.type = type;
        e.src_ip = ip;
        e.user = "";
        e.severity = parser_.severity();
        cb_(e);
    };
    
    for (const auto& rx : traversal_patterns_) {
        if (std::regex_search(path, rx)) { emit("http_traversal"); return; }
    }
    for (const auto& rx : sqli_patterns_) {
        if (std::regex_search(path, rx) || std::regex_search(ua, rx)) { emit("http_sqli"); return; }
    }
    for (const auto& rx : scanner_patterns_) {
        if (std::regex_search(ua, rx)) { emit("http_scanner"); return; }
    }
}
