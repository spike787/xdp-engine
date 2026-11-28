// SPDX-License-Identifier: MIT
// prometheus_metrics.h - pure formatting of Local API's GET /metrics
// (ROADMAP.md Phase 3: "Prometheus metrics"). Storage::get_metrics_summary()
// gathers the plain data this takes from the shared SQLite DB;
// format_prometheus_metrics() turns it into the Prometheus text exposition
// format (https://prometheus.io/docs/instrumenting/exposition_formats/),
// kept entirely separate from any DB/HTTP code so the format itself is
// unit-testable (tests/test_prometheus_metrics.cpp) the same way
// bouncer_diff.h and nft_bouncer_core.h keep their pure logic testable
// without BPF/nft respectively.
#ifndef PROMETHEUS_METRICS_H
#define PROMETHEUS_METRICS_H

#include <cctype>
#include <cstdint>
#include <sstream>
#include <string>

// A snapshot of the most recent row engine.cpp's metrics_poller wrote to
// the 'metrics' table: packet counters maintained per-CPU inside the
// kernel and summed cumulatively since bouncer-xdp last attached fresh
// (see XdpEngine::get_stats() in engine.cpp) - genuine monotonic
// Prometheus-counter semantics, not a per-interval delta.
//
// has_data is false when the table has no rows at all yet (engine has
// never run against this DB, or history was wiped via `engine reset`).
// Callers must tell that apart from "all counters are legitimately
// zero" and omit these metrics entirely rather than reporting a
// misleading zero - the same "unknown state is not empty state"
// principle nft_bouncer_core.h's parse_set_elements() already applies.
struct PacketMetricsSnapshot {
    bool has_data = false;
    std::uint64_t ts = 0; // unix seconds this row was written
    std::uint64_t dropped = 0;
    std::uint64_t passed = 0;
    std::uint64_t tcp = 0;
    std::uint64_t udp = 0;
    std::uint64_t icmp = 0;
    std::uint64_t other = 0;
    int syn_limit = 0;
    std::string xdp_mode; // "ENFORCE" / "DETECT" / "OFFLINE" / ... (case as stored)
};

struct MetricsSummary {
    PacketMetricsSnapshot packets;
    long long active_decisions = 0; // storage.get_active_decisions().size()
    long long alerts_total = 0;     // lifetime COUNT(*) FROM alerts
    long long events_total = 0;     // lifetime COUNT(*) FROM events
};

// Builds the full GET /metrics response body in Prometheus's classic text
// exposition format (content type text/plain; version=0.0.4). Always
// emits the alert/event/decision metrics (a real, meaningful zero for an
// empty table); only emits the packet-counter metrics when
// m.packets.has_data is true, per that field's own doc comment above.
inline std::string format_prometheus_metrics(const MetricsSummary& m) {
    std::ostringstream out;

    out << "# HELP xdp_engine_alerts_total Total alerts ever recorded.\n"
        << "# TYPE xdp_engine_alerts_total counter\n"
        << "xdp_engine_alerts_total " << m.alerts_total << "\n";

    out << "# HELP xdp_engine_events_total Total raw detection events ever recorded.\n"
        << "# TYPE xdp_engine_events_total counter\n"
        << "xdp_engine_events_total " << m.events_total << "\n";

    out << "# HELP xdp_engine_decisions_active Decisions currently serving an active block (see GET /decisions).\n"
        << "# TYPE xdp_engine_decisions_active gauge\n"
        << "xdp_engine_decisions_active " << m.active_decisions << "\n";

    if (!m.packets.has_data) return out.str();
    const auto& p = m.packets;

    out << "# HELP xdp_engine_packets_dropped_total Packets dropped by the XDP program, cumulative since bouncer-xdp last attached.\n"
        << "# TYPE xdp_engine_packets_dropped_total counter\n"
        << "xdp_engine_packets_dropped_total " << p.dropped << "\n";

    out << "# HELP xdp_engine_packets_passed_total Packets allowed through by the XDP program, cumulative since bouncer-xdp last attached.\n"
        << "# TYPE xdp_engine_packets_passed_total counter\n"
        << "xdp_engine_packets_passed_total " << p.passed << "\n";

    out << "# HELP xdp_engine_packets_by_protocol_total Packets seen by the XDP program by protocol, cumulative since bouncer-xdp last attached.\n"
        << "# TYPE xdp_engine_packets_by_protocol_total counter\n"
        << "xdp_engine_packets_by_protocol_total{protocol=\"tcp\"} " << p.tcp << "\n"
        << "xdp_engine_packets_by_protocol_total{protocol=\"udp\"} " << p.udp << "\n"
        << "xdp_engine_packets_by_protocol_total{protocol=\"icmp\"} " << p.icmp << "\n"
        << "xdp_engine_packets_by_protocol_total{protocol=\"other\"} " << p.other << "\n";

    out << "# HELP xdp_engine_syn_rate_limit Configured SYN-per-second rate limit threshold.\n"
        << "# TYPE xdp_engine_syn_rate_limit gauge\n"
        << "xdp_engine_syn_rate_limit " << p.syn_limit << "\n";

    // Prometheus's recommended "enum as gauge" pattern: every known state
    // is emitted every scrape (0 or 1), not just the current one, so a
    // dashboard or alert rule can reference a state that isn't active
    // right now without needing `absent()` tricks. Only the two states
    // engine.cpp actually sets during normal operation (ENFORCE/DETECT)
    // are enumerated here; anything else (e.g. the one-shot "OFFLINE" row
    // written at shutdown) reads as neither, which is correct - the
    // engine isn't actively enforcing or detecting in that state.
    std::string mode_lower;
    mode_lower.reserve(p.xdp_mode.size());
    for (char c : p.xdp_mode) mode_lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    out << "# HELP xdp_engine_mode Whether the engine is currently in this enforcement mode (1) or not (0).\n"
        << "# TYPE xdp_engine_mode gauge\n"
        << "xdp_engine_mode{mode=\"enforce\"} " << (mode_lower == "enforce" ? 1 : 0) << "\n"
        << "xdp_engine_mode{mode=\"detect\"} " << (mode_lower == "detect" ? 1 : 0) << "\n";

    out << "# HELP xdp_engine_last_metrics_timestamp_seconds Unix timestamp of the most recent packet-counter sample engine.cpp wrote.\n"
        << "# TYPE xdp_engine_last_metrics_timestamp_seconds gauge\n"
        << "xdp_engine_last_metrics_timestamp_seconds " << p.ts << "\n";

    return out.str();
}

#endif // PROMETHEUS_METRICS_H
