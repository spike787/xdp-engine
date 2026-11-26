#ifndef STORAGE_H
#define STORAGE_H

#include <string>
#include <vector>
#include <sqlite3.h>
#include <memory>
#include <mutex>
#include "event.h"
#include "rule_engine.h"

struct SqliteDeleter {
    void operator()(sqlite3* db) const noexcept {
        if (db) sqlite3_close(db);
    }
};
struct StmtDeleter {
    void operator()(sqlite3_stmt* stmt) const noexcept {
        if (stmt) sqlite3_finalize(stmt);
    }
};
using DbPtr = std::unique_ptr<sqlite3, SqliteDeleter>;
using StmtPtr = std::unique_ptr<sqlite3_stmt, StmtDeleter>;

struct ActionRecord {
    std::string ts_iso;
    std::string src_ip;
    std::string action;
    std::string reason;
};

// A single enforcement decision, as served to bouncers via the Local API
// and persisted so the decision survives an agent restart.
struct Decision {
    std::string ip;
    std::string action;        // "block" (only value for now; "unblock" is logged but not served)
    std::string reason;
    std::string rule;
    long long expires_at_unix; // 0 = never expires
    int ttl_seconds;
    std::string host;          // which protected host this decision applies to
};

class Storage {
public:
    Storage(const std::string& db_path);

    void insert_event(const Event& e);
    void insert_alert(const Alert& a);
    void insert_action(const ActionRecord& act);
    void wipe_history();
    void insert_metrics(uint64_t ts, uint64_t dropped, uint64_t passed, uint64_t tcp, uint64_t udp, uint64_t icmp, uint64_t other, int syn_limit, const std::string& xdp_mode);

    int get_offense_count(const std::string& ip);
    void record_offense(const std::string& ip);

    void print_last_alerts(int limit, std::function<void(const std::string&)> out);
    void generate_report(const std::string& path);

    // --- Local API support: decisions and export (see ROADMAP.md phase 1) ---

    // Records a decision (block or unblock). The most recent row per IP
    // determines whether get_active_decisions() currently serves it.
    void insert_decision(const Decision& d);

    // Returns every IP currently under an active, unexpired block decision.
    std::vector<Decision> get_active_decisions();

    // Exports alerts/events as "csv" or "json", optionally filtered by an
    // ISO-8601 ts range (either bound may be empty to leave it open).
    std::string export_alerts(const std::string& format, const std::string& since_iso, const std::string& until_iso);
    std::string export_events(const std::string& format, const std::string& since_iso, const std::string& until_iso);

private:
    void exec_schema();
    std::string run_export(const std::string& sql, const std::vector<std::string>& binds, const std::string& format);

    std::mutex db_mutex_;
    DbPtr db_;
    StmtPtr insert_event_stmt_;
    StmtPtr insert_alert_stmt_;
    StmtPtr insert_action_stmt_;
    StmtPtr get_alerts_stmt_;
    StmtPtr insert_metrics_stmt_;
    StmtPtr delete_metrics_stmt_;
    StmtPtr get_offense_stmt_;
    StmtPtr record_offense_stmt_;
    StmtPtr reset_offense_stmt_;
    StmtPtr insert_decision_stmt_;
    StmtPtr get_active_decisions_stmt_;
};

#endif // STORAGE_H
