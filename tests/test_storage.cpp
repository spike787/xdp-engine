// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <cstdio>
#include <filesystem>
#include <unistd.h>
#include "../storage.h"

namespace {

std::string fresh_db_path() {
    return "/tmp/test_storage_" + std::to_string(getpid()) + "_" +
           std::to_string(reinterpret_cast<uintptr_t>(&fresh_db_path)) + ".db";
}

} // namespace

// Exercises the Local API's data layer directly (ROADMAP.md phase 1):
// decisions (what bouncers poll) and export (the CSV/JSON evidence dump).

TEST(StorageDecisionsTest, ActiveBlockIsServed) {
    auto path = fresh_db_path();
    std::filesystem::remove(path);
    Storage storage(path);

    long long future = static_cast<long long>(std::time(nullptr)) + 600;
    storage.insert_decision({"10.0.0.5", "block", "SSH_BRUTE_FORCE", "SSH_BRUTE_FORCE", future, 600, "labhost1"});

    auto decisions = storage.get_active_decisions();
    ASSERT_EQ(decisions.size(), 1u);
    EXPECT_EQ(decisions[0].ip, "10.0.0.5");
    EXPECT_EQ(decisions[0].action, "block");
    EXPECT_EQ(decisions[0].host, "labhost1");

    std::filesystem::remove(path);
}

TEST(StorageDecisionsTest, UnblockSupersedesEarlierBlock) {
    auto path = fresh_db_path();
    std::filesystem::remove(path);
    Storage storage(path);

    long long future = static_cast<long long>(std::time(nullptr)) + 600;
    storage.insert_decision({"10.0.0.5", "block", "SSH_BRUTE_FORCE", "SSH_BRUTE_FORCE", future, 600, "labhost1"});
    storage.insert_decision({"10.0.0.5", "unblock", "manual unblock", "", 0, 0, "labhost1"});

    EXPECT_TRUE(storage.get_active_decisions().empty());
    std::filesystem::remove(path);
}

TEST(StorageDecisionsTest, ExpiredBlockIsNotServed) {
    auto path = fresh_db_path();
    std::filesystem::remove(path);
    Storage storage(path);

    long long past = static_cast<long long>(std::time(nullptr)) - 10;
    storage.insert_decision({"10.0.0.9", "block", "expired test", "RULE", past, 60, "labhost1"});

    EXPECT_TRUE(storage.get_active_decisions().empty());
    std::filesystem::remove(path);
}

TEST(StorageDecisionsTest, PermanentBlockHasZeroExpiry) {
    auto path = fresh_db_path();
    std::filesystem::remove(path);
    Storage storage(path);

    storage.insert_decision({"10.0.0.10", "block", "manual", "manual", 0, 0, "labhost1"});

    auto decisions = storage.get_active_decisions();
    ASSERT_EQ(decisions.size(), 1u);
    EXPECT_EQ(decisions[0].expires_at_unix, 0);
    std::filesystem::remove(path);
}

TEST(StorageExportTest, AlertsExportAsJsonAndCsv) {
    auto path = fresh_db_path();
    std::filesystem::remove(path);
    Storage storage(path);

    Alert a;
    a.rule = "SSH_BRUTE_FORCE";
    a.src_ip = "10.0.0.5";
    a.severity = "high";
    a.mitre = "T1110";
    a.action = "block";
    a.block_seconds = 600;
    a.ts_iso = "2026-11-26T22:00:00Z";
    a.label = "automatic";
    storage.insert_alert(a);

    auto json_str = storage.export_alerts("json", "", "");
    auto parsed = nlohmann::json::parse(json_str);
    ASSERT_EQ(parsed.size(), 1u);
    EXPECT_EQ(parsed[0]["rule"], "SSH_BRUTE_FORCE");
    EXPECT_EQ(parsed[0]["mitre"], "T1110");
    EXPECT_EQ(parsed[0]["host"], "local"); // schema default for pre-existing single-host rows

    auto csv_str = storage.export_alerts("csv", "", "");
    EXPECT_NE(csv_str.find("rule,src_ip"), std::string::npos);
    EXPECT_NE(csv_str.find("SSH_BRUTE_FORCE"), std::string::npos);

    std::filesystem::remove(path);
}

TEST(StorageExportTest, SinceFilterExcludesEarlierRows) {
    auto path = fresh_db_path();
    std::filesystem::remove(path);
    Storage storage(path);

    Alert early; early.rule = "OLD"; early.src_ip = "1.1.1.1"; early.severity = "low";
    early.mitre = ""; early.action = "block"; early.block_seconds = 60; early.ts_iso = "2026-01-01T00:00:00Z"; early.label = "";
    storage.insert_alert(early);

    Alert recent; recent.rule = "NEW"; recent.src_ip = "2.2.2.2"; recent.severity = "high";
    recent.mitre = ""; recent.action = "block"; recent.block_seconds = 60; recent.ts_iso = "2026-11-26T00:00:00Z"; recent.label = "";
    storage.insert_alert(recent);

    auto json_str = storage.export_alerts("json", "2026-06-01T00:00:00Z", "");
    auto parsed = nlohmann::json::parse(json_str);
    ASSERT_EQ(parsed.size(), 1u);
    EXPECT_EQ(parsed[0]["rule"], "NEW");

    std::filesystem::remove(path);
}

TEST(StorageExportTest, EventsExportIncludesHostColumn) {
    auto path = fresh_db_path();
    std::filesystem::remove(path);
    Storage storage(path);

    Event e;
    e.ts_iso = "2026-11-26T22:00:00Z";
    e.source = "ssh_log";
    e.type = "ssh_failed";
    e.src_ip = "10.0.0.5";
    e.user = "root";
    e.severity = 3;
    storage.insert_event(e);

    auto json_str = storage.export_events("json", "", "");
    auto parsed = nlohmann::json::parse(json_str);
    ASSERT_EQ(parsed.size(), 1u);
    EXPECT_EQ(parsed[0]["type"], "ssh_failed");
    EXPECT_EQ(parsed[0]["host"], "local");

    std::filesystem::remove(path);
}

// SshDetector accepts any non-whitespace string as the attempted username
// (engine.cpp's regex is `(\S+)`), so events.user can contain a value an
// attacker fully controls, such as a formula-injection payload. CSV export
// must neutralize that rather than passing it through to a spreadsheet.
TEST(StorageExportTest, CsvExportNeutralizesFormulaInjectionInUserField) {
    auto path = fresh_db_path();
    std::filesystem::remove(path);
    Storage storage(path);

    Event e;
    e.ts_iso = "2026-11-27T00:00:00Z";
    e.source = "ssh_log";
    e.type = "ssh_failed";
    e.src_ip = "10.0.0.9";
    e.user = "=HYPERLINK(\"http://evil/\",\"x\")";
    e.severity = 3;
    storage.insert_event(e);

    auto csv_str = storage.export_events("csv", "", "");
    // The raw payload must never appear un-neutralized: a leading '='
    // would be evaluated as a formula by Excel/LibreOffice/Sheets.
    EXPECT_EQ(csv_str.find("\"=HYPERLINK"), std::string::npos);
    // The mitigation (a leading single quote) should be present instead,
    // with the field still present and still comma/quote-escaped.
    EXPECT_NE(csv_str.find("'=HYPERLINK"), std::string::npos);

    std::filesystem::remove(path);
}

// ADR-0009: GET /metrics is served by local-api's own Storage connection,
// which is a *different process* from the one (engine.cpp) actually
// writing packet-counter rows - exactly the two-connections-one-file
// shape this test builds directly, without needing two real processes.
// get_metrics_summary() used to leave its prepared statements parked in
// SQLITE_ROW state after reading their one row, only resetting them at
// the top of the *next* call - which in WAL mode can leave a connection's
// implicit read transaction pinned to a stale snapshot indefinitely,
// since that transaction only truly ends once every participating
// statement has been reset or drained. The fix resets each statement
// immediately after use, not just before reuse - this test fails without
// that fix and passes with it.
TEST(StorageMetricsTest, SummaryReflectsEachNewRowAcrossSeparateConnections) {
    auto path = fresh_db_path();
    std::filesystem::remove(path);

    Storage writer(path);   // stands in for engine.cpp's connection
    Storage reader(path);   // stands in for local-api's connection

    writer.insert_metrics(1000, 0, 100, 50, 50, 0, 0, 200, "DETECT");
    auto first = reader.get_metrics_summary();
    ASSERT_TRUE(first.packets.has_data);
    EXPECT_EQ(first.packets.passed, 100u);

    writer.insert_metrics(1001, 0, 200, 90, 90, 20, 0, 200, "DETECT");
    auto second = reader.get_metrics_summary();
    EXPECT_EQ(second.packets.passed, 200u) << "reader is still serving a stale snapshot "
                                               "from before the second insert_metrics() call";
    EXPECT_EQ(second.packets.icmp, 20u);

    writer.insert_metrics(1002, 0, 300, 120, 120, 40, 0, 200, "DETECT");
    auto third = reader.get_metrics_summary();
    EXPECT_EQ(third.packets.passed, 300u) << "reader did not pick up the third insert_metrics() call either";
    EXPECT_EQ(third.packets.icmp, 40u);

    std::filesystem::remove(path);
}
