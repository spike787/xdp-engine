// SPDX-License-Identifier: MIT
#ifndef PLAYBOOK_RUNNER_H
#define PLAYBOOK_RUNNER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <mutex>
#include <deque>
#include <chrono>
#include "rule_engine.h"
#include "storage.h"

class PlaybookRunner {
public:
    using BlockCallback = std::function<int(const std::string& ip, const std::string& rule, int seconds)>;
    using RecordCallback = std::function<void(const ActionRecord&)>;
    using NotifyCallback = std::function<void(const Alert&)>;
    using OffenseCallback = std::function<int(const std::string& ip)>;
    using RecordOffenseCallback = std::function<void(const std::string& ip)>;

    PlaybookRunner(const std::string& yaml_path, const std::string& known_ips_path,
                   const std::string& blocklist_path,
                   BlockCallback block_cb, RecordCallback record_cb, NotifyCallback notify_cb,
                   OffenseCallback off_cb, RecordOffenseCallback rec_off_cb);

    void execute(Alert& alert);
    void approve(int id);
    void deny(int id);
    void check_expiries();

private:
    struct Pending {
        Alert alert;
        std::chrono::steady_clock::time_point expiry;
    };

    std::unordered_map<std::string, std::vector<std::string>> playbooks_;
    std::unordered_map<std::string, std::vector<int>> ladders_;
    std::unordered_map<std::string, std::string> known_ips_;
    BlockCallback block_cb_;
    RecordCallback record_cb_;
    NotifyCallback notify_cb_;
    OffenseCallback offense_cb_;
    RecordOffenseCallback record_offense_cb_;
    
    // Safety state
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_run_;
    std::deque<std::chrono::steady_clock::time_point> recent_blocks_;

    // execute() is called concurrently from the SSH-watcher, HTTP-watcher,
    // and XDP ring-buffer-poller threads (see engine.cpp's on_event), and it
    // reads/writes last_run_ and recent_blocks_ with no synchronization of
    // its own. This guards the whole body of execute() - it is distinct
    // from approval_mutex_ (which only protects pending_approvals_, and is
    // also taken from approve()/deny()/check_expiries(), none of which call
    // back into execute(), so there is no lock-ordering cycle between them).
    std::mutex exec_mutex_;

    // Approval state
    std::mutex approval_mutex_;
    std::unordered_map<int, Pending> pending_approvals_;
    int next_approval_id_ = 1;
};

#endif // PLAYBOOK_RUNNER_H
