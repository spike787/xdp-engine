// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <unistd.h>
#include "../replay_core.h"

namespace {

std::string write_temp(const std::string& prefix, const std::string& content) {
    static int counter = 0;
    std::string path = "/tmp/" + prefix + "_" + std::to_string(getpid()) + "_" +
                        std::to_string(counter++) + ".yaml";
    std::ofstream f(path);
    f << content;
    f.close();
    return path;
}

std::string ssh_parser_yaml() {
    return R"YAML(
name: test-ssh
source: ssh_log
pattern: 'Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3}) port \d+ ssh2'
fields:
  - name: user
    group: 1
  - name: ip
    group: 2
emit_type: ssh_failed
severity: 3
)YAML";
}

std::string ssh_rules_yaml(int threshold) {
    return R"YAML(
- name: SSH_BRUTE_FORCE
  type: threshold
  match_type: ssh_failed
  threshold: )YAML" + std::to_string(threshold) + R"YAML(
  window_seconds: 60
  severity: high
  mitre: T1110
  action: block
  block_seconds: 600
)YAML";
}

std::string nginx_parser_yaml() {
    return R"YAML(
name: test-nginx
source: http_log
pattern: '^(\S+)\s+\S+\s+\S+\s+\[.*?\]\s+"(?:[A-Z]+)\s+(\S+)\s+.*?"\s+\d+\s+\d+\s+"(?:[^"]*)"\s+"([^"]*)"'
fields:
  - name: ip
    group: 1
  - name: path
    group: 2
    url_decode: true
  - name: user_agent
    group: 3
severity: 3
)YAML";
}

std::string http_sqli_rules_yaml() {
    return R"YAML(
- name: HTTP_ATTACK
  type: threshold
  match_type: http_sqli
  threshold: 1
  window_seconds: 60
  severity: critical
  mitre: T1190
  action: block
  block_seconds: 600
  patterns: ["union.*select", "' or 1=1"]
)YAML";
}

struct TempFile {
    std::string path;
    explicit TempFile(std::string p) : path(std::move(p)) {}
    ~TempFile() { std::filesystem::remove(path); }
};

} // namespace

TEST(ReplayCoreTest, SshBruteForceFiresAfterThreshold) {
    TempFile parser_path(write_temp("replay_ssh_parser", ssh_parser_yaml()));
    TempFile rules_path(write_temp("replay_ssh_rules", ssh_rules_yaml(3)));

    LogParser parser(parser_path.path);
    RuleEngine rule_engine(rules_path.path);

    std::vector<std::string> lines = {
        "not a log line at all",
        "Failed password for invalid user root from 203.0.113.9 port 4444 ssh2",
        "Failed password for invalid user admin from 203.0.113.9 port 4445 ssh2",
        "Failed password for invalid user test from 203.0.113.9 port 4446 ssh2",
        "also garbage",
    };

    ReplayResult result = replay_lines(lines, parser, nullptr, rule_engine);

    EXPECT_EQ(result.lines_read, 5);
    EXPECT_EQ(result.lines_matched, 3);
    EXPECT_EQ(result.lines_classified, 0); // fixed emit_type source - no classify step
    ASSERT_EQ(result.alerts.size(), 1u);
    EXPECT_EQ(result.alerts[0].rule, "SSH_BRUTE_FORCE");
    EXPECT_EQ(result.alerts[0].src_ip, "203.0.113.9");
}

TEST(ReplayCoreTest, SshBelowThresholdFiresNoAlert) {
    TempFile parser_path(write_temp("replay_ssh_parser", ssh_parser_yaml()));
    TempFile rules_path(write_temp("replay_ssh_rules", ssh_rules_yaml(5)));

    LogParser parser(parser_path.path);
    RuleEngine rule_engine(rules_path.path);

    std::vector<std::string> lines = {
        "Failed password for invalid user root from 203.0.113.9 port 4444 ssh2",
        "Failed password for invalid user admin from 203.0.113.9 port 4445 ssh2",
    };

    ReplayResult result = replay_lines(lines, parser, nullptr, rule_engine);

    EXPECT_EQ(result.lines_matched, 2);
    EXPECT_TRUE(result.alerts.empty());
}

TEST(ReplayCoreTest, HttpSqliClassifiesAndFiresWithClassifier) {
    TempFile parser_path(write_temp("replay_http_parser", nginx_parser_yaml()));
    TempFile rules_path(write_temp("replay_http_rules", http_sqli_rules_yaml()));

    LogParser parser(parser_path.path);
    RuleEngine rule_engine(rules_path.path);
    HttpClassifier classifier(rule_engine);

    std::vector<std::string> lines = {
        R"(10.0.0.9 - - [27/Nov/2026:22:00:00 +0000] "GET /?id=1%20union%20select%201 HTTP/1.1" 200 512 "-" "curl/8.0")",
        R"(10.0.0.5 - - [27/Nov/2026:22:00:01 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0")",
    };

    ReplayResult result = replay_lines(lines, parser, &classifier, rule_engine);

    EXPECT_EQ(result.lines_matched, 2);     // both lines parse as valid nginx access lines
    EXPECT_EQ(result.lines_classified, 1);  // only the sqli-shaped one classifies as an attack
    ASSERT_EQ(result.alerts.size(), 1u);
    EXPECT_EQ(result.alerts[0].rule, "HTTP_ATTACK");
    EXPECT_EQ(result.alerts[0].src_ip, "10.0.0.9");
}

TEST(ReplayCoreTest, HttpSourceWithoutClassifierEmitsNothing) {
    TempFile parser_path(write_temp("replay_http_parser", nginx_parser_yaml()));
    TempFile rules_path(write_temp("replay_http_rules", http_sqli_rules_yaml()));

    LogParser parser(parser_path.path);
    RuleEngine rule_engine(rules_path.path);

    std::vector<std::string> lines = {
        R"(10.0.0.9 - - [27/Nov/2026:22:00:00 +0000] "GET /?id=1%20union%20select%201 HTTP/1.1" 200 512 "-" "curl/8.0")",
    };

    // Passing nullptr for an emit_type-less (HTTP-style) parser means there's
    // no way to classify the line, so it's matched but never emitted.
    ReplayResult result = replay_lines(lines, parser, nullptr, rule_engine);

    EXPECT_EQ(result.lines_matched, 1);
    EXPECT_EQ(result.lines_classified, 0);
    EXPECT_TRUE(result.alerts.empty());
}

TEST(ReplayCoreTest, LineWithUnparsableIpIsMatchedButNotEmitted) {
    // A field-capture pattern that can pull out something ip-shaped-ish but
    // not a valid IPv4 address (parse_ipv4 should reject it), exercising the
    // ip_it == end() / !parse_ipv4(...) guard in replay_lines.
    std::string parser_yaml = R"YAML(
name: test-bogus-ip
source: ssh_log
pattern: 'Failed password for (\S+) from (\S+) port \d+ ssh2'
fields:
  - name: user
    group: 1
  - name: ip
    group: 2
emit_type: ssh_failed
severity: 3
)YAML";
    TempFile parser_path(write_temp("replay_bad_ip_parser", parser_yaml));
    TempFile rules_path(write_temp("replay_ssh_rules", ssh_rules_yaml(1)));

    LogParser parser(parser_path.path);
    RuleEngine rule_engine(rules_path.path);

    std::vector<std::string> lines = {
        "Failed password for root from not-an-ip-address port 4444 ssh2",
    };

    ReplayResult result = replay_lines(lines, parser, nullptr, rule_engine);

    EXPECT_EQ(result.lines_matched, 1); // the envelope regex matched fine
    EXPECT_TRUE(result.alerts.empty()); // but it was never turned into an Event/Alert
}

TEST(ReplayCoreTest, EmptyInputProducesEmptyResult) {
    TempFile parser_path(write_temp("replay_ssh_parser", ssh_parser_yaml()));
    TempFile rules_path(write_temp("replay_ssh_rules", ssh_rules_yaml(1)));

    LogParser parser(parser_path.path);
    RuleEngine rule_engine(rules_path.path);

    ReplayResult result = replay_lines({}, parser, nullptr, rule_engine);

    EXPECT_EQ(result.lines_read, 0);
    EXPECT_EQ(result.lines_matched, 0);
    EXPECT_EQ(result.lines_classified, 0);
    EXPECT_TRUE(result.alerts.empty());
}
