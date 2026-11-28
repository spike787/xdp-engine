// SPDX-License-Identifier: MIT
// Unit tests for Local API's GET /metrics formatter (ROADMAP.md phase 3).
// format_prometheus_metrics() is pure - plain struct in, string out - so
// this exercises it directly against canned MetricsSummary values, no
// SQLite or HTTP server involved, the same pattern bouncer_diff.h and
// nft_bouncer_core.h's tests already use for their own pure logic.
#include <gtest/gtest.h>

#include <sstream>

#include "../prometheus_metrics.h"

namespace {
// Finds the value on the actual metric data line (never a "# HELP"/
// "# TYPE" comment line - both of those also contain the metric name
// followed by a space, so a plain substring search would wrongly match
// whichever comes first) and returns it as a string, or "" if no data
// line starts with the given prefix.
std::string find_metric_value(const std::string& text, const std::string& metric_line_prefix) {
    std::istringstream iss(text);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line[0] == '#') continue;
        if (line.rfind(metric_line_prefix, 0) == 0) { // line starts with prefix
            size_t space = line.find_last_of(' ');
            return line.substr(space + 1);
        }
    }
    return "";
}
} // namespace

TEST(PrometheusMetricsTest, AlwaysEmitsAlertsEventsAndDecisionsCounts) {
    MetricsSummary m;
    m.alerts_total = 42;
    m.events_total = 100;
    m.active_decisions = 3;
    // packets.has_data left false (default) - no engine has ever run.

    std::string body = format_prometheus_metrics(m);

    EXPECT_EQ(find_metric_value(body, "xdp_engine_alerts_total "), "42");
    EXPECT_EQ(find_metric_value(body, "xdp_engine_events_total "), "100");
    EXPECT_EQ(find_metric_value(body, "xdp_engine_decisions_active "), "3");
}

TEST(PrometheusMetricsTest, ZeroCountsAreRealZerosNotOmitted) {
    MetricsSummary m; // everything defaults to 0/false
    std::string body = format_prometheus_metrics(m);

    EXPECT_EQ(find_metric_value(body, "xdp_engine_alerts_total "), "0");
    EXPECT_EQ(find_metric_value(body, "xdp_engine_events_total "), "0");
    EXPECT_EQ(find_metric_value(body, "xdp_engine_decisions_active "), "0");
}

TEST(PrometheusMetricsTest, NoPacketDataOmitsPacketMetricsEntirely) {
    MetricsSummary m; // packets.has_data stays false
    std::string body = format_prometheus_metrics(m);

    EXPECT_EQ(body.find("xdp_engine_packets_dropped_total"), std::string::npos);
    EXPECT_EQ(body.find("xdp_engine_packets_passed_total"), std::string::npos);
    EXPECT_EQ(body.find("xdp_engine_packets_by_protocol_total"), std::string::npos);
    EXPECT_EQ(body.find("xdp_engine_mode"), std::string::npos);
    EXPECT_EQ(body.find("xdp_engine_last_metrics_timestamp_seconds"), std::string::npos);
    EXPECT_EQ(body.find("xdp_engine_syn_rate_limit"), std::string::npos);
}

TEST(PrometheusMetricsTest, PacketDataEmitsAllPacketMetrics) {
    MetricsSummary m;
    m.packets.has_data = true;
    m.packets.ts = 1234567890;
    m.packets.dropped = 55;
    m.packets.passed = 1000;
    m.packets.tcp = 700;
    m.packets.udp = 250;
    m.packets.icmp = 40;
    m.packets.other = 10;
    m.packets.syn_limit = 200;
    m.packets.xdp_mode = "ENFORCE";

    std::string body = format_prometheus_metrics(m);

    EXPECT_EQ(find_metric_value(body, "xdp_engine_packets_dropped_total "), "55");
    EXPECT_EQ(find_metric_value(body, "xdp_engine_packets_passed_total "), "1000");
    EXPECT_EQ(find_metric_value(body, "xdp_engine_packets_by_protocol_total{protocol=\"tcp\"} "), "700");
    EXPECT_EQ(find_metric_value(body, "xdp_engine_packets_by_protocol_total{protocol=\"udp\"} "), "250");
    EXPECT_EQ(find_metric_value(body, "xdp_engine_packets_by_protocol_total{protocol=\"icmp\"} "), "40");
    EXPECT_EQ(find_metric_value(body, "xdp_engine_packets_by_protocol_total{protocol=\"other\"} "), "10");
    EXPECT_EQ(find_metric_value(body, "xdp_engine_syn_rate_limit "), "200");
    EXPECT_EQ(find_metric_value(body, "xdp_engine_last_metrics_timestamp_seconds "), "1234567890");
}

TEST(PrometheusMetricsTest, EnforceModeSetsOnlyEnforceGaugeToOne) {
    MetricsSummary m;
    m.packets.has_data = true;
    m.packets.xdp_mode = "ENFORCE";

    std::string body = format_prometheus_metrics(m);

    EXPECT_EQ(find_metric_value(body, "xdp_engine_mode{mode=\"enforce\"} "), "1");
    EXPECT_EQ(find_metric_value(body, "xdp_engine_mode{mode=\"detect\"} "), "0");
}

TEST(PrometheusMetricsTest, DetectModeSetsOnlyDetectGaugeToOne) {
    MetricsSummary m;
    m.packets.has_data = true;
    m.packets.xdp_mode = "DETECT";

    std::string body = format_prometheus_metrics(m);

    EXPECT_EQ(find_metric_value(body, "xdp_engine_mode{mode=\"enforce\"} "), "0");
    EXPECT_EQ(find_metric_value(body, "xdp_engine_mode{mode=\"detect\"} "), "1");
}

TEST(PrometheusMetricsTest, UnknownModeSetsBothGaugesToZero) {
    // e.g. the one-shot "OFFLINE" row engine.cpp writes at shutdown -
    // neither enforce nor detect is "currently active" in that state.
    MetricsSummary m;
    m.packets.has_data = true;
    m.packets.xdp_mode = "OFFLINE";

    std::string body = format_prometheus_metrics(m);

    EXPECT_EQ(find_metric_value(body, "xdp_engine_mode{mode=\"enforce\"} "), "0");
    EXPECT_EQ(find_metric_value(body, "xdp_engine_mode{mode=\"detect\"} "), "0");
}

TEST(PrometheusMetricsTest, ModeComparisonIsCaseInsensitive) {
    MetricsSummary m;
    m.packets.has_data = true;
    m.packets.xdp_mode = "enforce"; // lowercase, as if something stored it differently

    std::string body = format_prometheus_metrics(m);

    EXPECT_EQ(find_metric_value(body, "xdp_engine_mode{mode=\"enforce\"} "), "1");
}

TEST(PrometheusMetricsTest, EveryMetricHasHelpAndTypeLines) {
    MetricsSummary m;
    m.packets.has_data = true;
    m.packets.xdp_mode = "ENFORCE";
    std::string body = format_prometheus_metrics(m);

    for (const std::string& metric : {
             "xdp_engine_alerts_total", "xdp_engine_events_total", "xdp_engine_decisions_active",
             "xdp_engine_packets_dropped_total", "xdp_engine_packets_passed_total",
             "xdp_engine_packets_by_protocol_total", "xdp_engine_syn_rate_limit",
             "xdp_engine_mode", "xdp_engine_last_metrics_timestamp_seconds"}) {
        EXPECT_NE(body.find("# HELP " + metric + " "), std::string::npos) << metric << " missing HELP line";
        EXPECT_NE(body.find("# TYPE " + metric + " "), std::string::npos) << metric << " missing TYPE line";
    }
}
