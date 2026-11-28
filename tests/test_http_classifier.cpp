// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <unistd.h>
#include "../http_classifier.h"
#include "../rule_engine.h"

namespace {

std::string write_temp_rules(const std::string& content) {
    std::string path = "/tmp/test_http_classifier_" + std::to_string(getpid()) + "_" +
                        std::to_string(reinterpret_cast<uintptr_t>(&content)) + ".yaml";
    std::ofstream f(path);
    f << content;
    f.close();
    return path;
}

// Builds a RuleEngine from one rule per http_* match_type, each with its
// own small pattern list, mirroring how rules.yaml is actually structured.
std::string sample_rules_yaml() {
    return R"YAML(
- name: TRAVERSAL
  type: threshold
  match_type: http_traversal
  threshold: 1
  window_seconds: 60
  severity: high
  mitre: T1190
  action: block
  block_seconds: 600
  patterns: ["\\.\\./", "%2e%2e"]

- name: SQLI
  type: threshold
  match_type: http_sqli
  threshold: 1
  window_seconds: 60
  severity: critical
  mitre: T1190
  action: block
  block_seconds: 600
  patterns: ["union.*select", "' or 1=1"]

- name: SCANNER
  type: threshold
  match_type: http_scanner
  threshold: 1
  window_seconds: 60
  severity: medium
  mitre: T1595
  action: block
  block_seconds: 600
  patterns: ["sqlmap", "nikto"]
)YAML";
}

} // namespace

TEST(HttpClassifierTest, MatchesTraversalAgainstPathOnly) {
    auto path = write_temp_rules(sample_rules_yaml());
    RuleEngine rule_engine(path);
    HttpClassifier classifier(rule_engine);

    EXPECT_EQ(classifier.classify("/../../etc/passwd", "Mozilla/5.0"), "http_traversal");
    std::filesystem::remove(path);
}

TEST(HttpClassifierTest, MatchesSqliAgainstPathOrUserAgent) {
    auto path = write_temp_rules(sample_rules_yaml());
    RuleEngine rule_engine(path);
    HttpClassifier classifier(rule_engine);

    EXPECT_EQ(classifier.classify("/?id=1 union select 1", "Mozilla/5.0"), "http_sqli");
    EXPECT_EQ(classifier.classify("/", "' or 1=1"), "http_sqli");
    std::filesystem::remove(path);
}

TEST(HttpClassifierTest, MatchesScannerAgainstUserAgentOnly) {
    auto path = write_temp_rules(sample_rules_yaml());
    RuleEngine rule_engine(path);
    HttpClassifier classifier(rule_engine);

    EXPECT_EQ(classifier.classify("/", "sqlmap/1.6"), "http_scanner");
    // A traversal/sqli-shaped path should not accidentally trip scanner.
    EXPECT_NE(classifier.classify("/../etc/passwd", "sqlmap/1.6"), "http_scanner");
    std::filesystem::remove(path);
}

TEST(HttpClassifierTest, PrecedenceIsTraversalThenSqliThenScanner) {
    auto path = write_temp_rules(sample_rules_yaml());
    RuleEngine rule_engine(path);
    HttpClassifier classifier(rule_engine);

    // A path that matches both traversal and (via its sqlmap UA) scanner
    // should classify as traversal, since that's checked first.
    EXPECT_EQ(classifier.classify("/../../etc/passwd", "sqlmap/1.6"), "http_traversal");
    std::filesystem::remove(path);
}

TEST(HttpClassifierTest, NoMatchReturnsEmptyString) {
    auto path = write_temp_rules(sample_rules_yaml());
    RuleEngine rule_engine(path);
    HttpClassifier classifier(rule_engine);

    EXPECT_EQ(classifier.classify("/index.html", "Mozilla/5.0"), "");
    std::filesystem::remove(path);
}
