// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <unistd.h>
#include "../log_parser.h"

namespace {

// Writes `content` to a fresh temp YAML file and returns its path. Tests
// that need a LogParser build one of these rather than relying on the
// checked-in parsers/s01-parse/*.yaml files, so they keep working even if
// those files' content changes later.
std::string write_temp_yaml(const std::string& content) {
    std::string path = "/tmp/test_log_parser_" + std::to_string(getpid()) + "_" +
                        std::to_string(reinterpret_cast<uintptr_t>(&content)) + ".yaml";
    std::ofstream f(path);
    f << content;
    f.close();
    return path;
}

} // namespace

TEST(LogParserTest, ExtractsNamedFieldsByCaptureGroup) {
    auto path = write_temp_yaml(R"(
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
)");
    LogParser parser(path);

    std::unordered_map<std::string, std::string> fields;
    bool matched = parser.parse(
        "Nov 27 22:00:00 host sshd[1]: Failed password for invalid user root from 10.0.0.9 port 4444 ssh2",
        fields);

    ASSERT_TRUE(matched);
    EXPECT_EQ(fields["user"], "root");
    EXPECT_EQ(fields["ip"], "10.0.0.9");
    EXPECT_EQ(parser.source(), "ssh_log");
    EXPECT_EQ(parser.emit_type(), "ssh_failed");
    EXPECT_EQ(parser.severity(), 3);

    std::filesystem::remove(path);
}

TEST(LogParserTest, NonMatchingLineReturnsFalseAndLeavesOutUntouched) {
    auto path = write_temp_yaml(R"(
name: test-ssh
source: ssh_log
pattern: 'Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3}) port \d+ ssh2'
fields:
  - name: user
    group: 1
  - name: ip
    group: 2
)");
    LogParser parser(path);

    std::unordered_map<std::string, std::string> fields;
    fields["sentinel"] = "untouched";
    bool matched = parser.parse("this line matches nothing at all", fields);

    EXPECT_FALSE(matched);
    EXPECT_EQ(fields["sentinel"], "untouched");

    std::filesystem::remove(path);
}

TEST(LogParserTest, UrlDecodesOnlyFieldsThatAskForIt) {
    // Custom raw-string delimiter (YAML instead of the default) because the
    // pattern itself contains the sequence `)"`, which would otherwise be
    // misread as the end of the raw string literal.
    auto path = write_temp_yaml(R"YAML(
name: test-http
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
)YAML");
    LogParser parser(path);

    std::unordered_map<std::string, std::string> fields;
    bool matched = parser.parse(
        R"(10.0.0.9 - - [27/Nov/2026:22:00:00 +0000] "GET /?id=1%20union%20select%201 HTTP/1.1" 200 512 "-" "curl/8.0%20test")",
        fields);

    ASSERT_TRUE(matched);
    EXPECT_EQ(fields["ip"], "10.0.0.9");
    // path has url_decode: true, so %20 becomes a space
    EXPECT_EQ(fields["path"], "/?id=1 union select 1");
    // user_agent has no url_decode, so %20 is left as-is
    EXPECT_EQ(fields["user_agent"], "curl/8.0%20test");

    std::filesystem::remove(path);
}

TEST(LogParserTest, EmptyEmitTypeMeansClassificationIsExternal) {
    auto path = write_temp_yaml(R"(
name: test-http
source: http_log
pattern: '(\S+)'
fields:
  - name: ip
    group: 1
)");
    LogParser parser(path);
    EXPECT_EQ(parser.emit_type(), "");

    std::filesystem::remove(path);
}

TEST(LogParserTest, ConstructorThrowsOnMissingFieldsList) {
    auto path = write_temp_yaml(R"(
name: broken
source: ssh_log
pattern: 'anything'
)");
    EXPECT_THROW({ LogParser parser(path); }, std::runtime_error);

    std::filesystem::remove(path);
}

TEST(LogParserTest, ConstructorThrowsOnZeroOrNegativeGroup) {
    auto path = write_temp_yaml(R"(
name: broken
source: ssh_log
pattern: 'anything'
fields:
  - name: bad
    group: 0
)");
    EXPECT_THROW({ LogParser parser(path); }, std::runtime_error);

    std::filesystem::remove(path);
}
