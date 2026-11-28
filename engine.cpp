// SPDX-License-Identifier: MIT
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <regex>
#include <fstream>
#include <csignal>
#include <unordered_set>
#include <map>
#include <mutex>
#include <optional>
#include <filesystem>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/un.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <bpf/bpf.h>
#include <sys/file.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <sys/socket.h>
#include <cstdint>
#include <cstring>
#include <deque>
#include <stdexcept>
#include <stop_token>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <numeric>

#include "common.h"
#include "event.h"
#include "rule_engine.h"
#include "storage.h"
#include "playbook_runner.h"
#include "notifier.h"
#include "http_detector.h"
#include "log_tailer.h"
#include "log_parser.h"
#include "text_util.h"
#include "utils.h"

using namespace std::chrono_literals;

static bool use_color = true;
static std::atomic<bool> g_running{true};
extern "C" void on_signal(int) { g_running = false; }

std::string get_iso_time_str() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&ts.tv_sec));
    return std::string(buf);
}

void print_log(std::string tag, const std::string& msg, const std::string& color_code = "") {
    std::string reset = use_color ? "\x1b[0m" : "";
    std::string color = use_color ? color_code : "";
    while (tag.length() < 10) tag += " ";
    std::cout << get_iso_time_str() << " " << color << tag << reset << " " << msg << "\n";
}
void log_info(const std::string& msg) { print_log("[INFO]", msg); }
void log_warn(const std::string& msg) { print_log("[WARN]", msg, "\x1b[33m"); }
void log(const std::string& msg) { log_info(msg); } // Compatibility

std::string ip_to_string(std::uint32_t ip_net) {
    char buf[INET_ADDRSTRLEN]{};
    in_addr addr{.s_addr = ip_net};
    inet_ntop(AF_INET, &addr, buf, sizeof buf);
    return buf;
}

std::optional<std::uint32_t> parse_ipv4_local(const std::string& text) {
    in_addr addr{};
    if (inet_pton(AF_INET, text.c_str(), &addr) != 1) return std::nullopt;
    return addr.s_addr;
}

void add_iface_ips(std::unordered_set<std::uint32_t>& allow, const std::string& ifname) {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        // Silent failure here means the engine's own interface IP never gets
        // auto-allowlisted, which can look like an unexplained self-lockout
        // later - worth a log line even though getifaddrs rarely fails.
        log_warn("getifaddrs() failed: " + std::string(std::strerror(errno)) +
                  " - this interface's own IP will not be auto-allowlisted");
        return;
    }
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if (ifa->ifa_addr->sa_family == AF_INET && std::string(ifa->ifa_name) == ifname) {
            auto* sa = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
            allow.insert(sa->sin_addr.s_addr);
        }
    }
    freeifaddrs(ifaddr);
}

void add_gateway_ips(std::unordered_set<std::uint32_t>& allow) {
    std::ifstream in("/proc/net/route");
    std::string line;
    std::getline(in, line);
    while (std::getline(in, line)) {
        std::istringstream iss(line);
        std::string iface, dest, gw;
        if (iss >> iface >> dest >> gw) {
            if (dest == "00000000") {
                unsigned int gw_ip;
                if (std::sscanf(gw.c_str(), "%X", &gw_ip) == 1 && gw_ip != 0) {
                    allow.insert(gw_ip);
                }
            }
        }
    }
}

bool check_process(const std::string& name) {
    DIR* dir = opendir("/proc");
    if (!dir) {
        log_warn("opendir(/proc) failed: " + std::string(std::strerror(errno)));
        return false;
    }
    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_type == DT_DIR && std::isdigit(ent->d_name[0])) {
            std::string comm_path = std::string("/proc/") + ent->d_name + "/comm";
            std::ifstream comm_file(comm_path);
            if (comm_file.is_open()) {
                std::string comm;
                if (std::getline(comm_file, comm) && comm == name) {
                    closedir(dir);
                    return true;
                }
            }
        }
    }
    closedir(dir);
    return false;
}

template <typename K, typename V>
bool map_update(int fd, const K& key, const V& value, __u64 flags = BPF_ANY) {
    return bpf_map_update_elem(fd, &key, &value, flags) == 0;
}

struct RingBufDeleter {
    void operator()(struct ring_buffer* rb) const { ring_buffer__free(rb); }
};
using RingBufPtr = std::unique_ptr<struct ring_buffer, RingBufDeleter>;

class BlockList {
public:
    // ADR-0002: blocked_fd here is opened read-only in spirit (engine never
    // writes to it anymore) - it's only used by print_blocked() to report
    // whether bouncer-xdp has actually applied a decision yet. allowed_fd is
    // still writable: the allowlist isn't an enforcement decision, it's a
    // safety rail engine itself needs to consult before even proposing a
    // block (see block() below), so engine keeps owning it.
    BlockList(int allowed_fd, int blocked_fd, int stats_fd, int proto_stats_fd, const std::unordered_set<std::uint32_t>& allow, Storage* storage = nullptr)
    : allowed_fd_{allowed_fd}, blocked_fd_{blocked_fd}, stats_fd_{stats_fd}, proto_stats_fd_{proto_stats_fd}, storage_{storage},
      host_{[]{ char buf[256]; return gethostname(buf, sizeof(buf)) == 0 ? std::string(buf) : std::string("local"); }()} {
        for (std::uint32_t ip : allow) {
            allow_ip(ip);
        }
    }

    bool allow_ip(std::uint32_t ip) {
        std::uint8_t dummy = 1;
        if (map_update(allowed_fd_, ip, dummy)) {
            print_log("[ALLOWED]", ip_to_string(ip));
            return true;
        }
        return false;
    }

    bool unallow_ip(std::uint32_t ip) {
        return bpf_map_delete_elem(allowed_fd_, &ip) == 0;
    }

    bool is_allowed(std::uint32_t ip) const {
        std::uint8_t dummy = 0;
        return (bpf_map_lookup_elem(allowed_fd_, &ip, &dummy) == 0);
    }

    // ADR-0002: this no longer touches the kernel map directly. It only
    // writes the decision to storage - bouncer-xdp picks it up on its next
    // poll of GET /decisions and applies it. Actual enforcement therefore
    // lags this call by up to bouncer-xdp's poll interval (default 2s).
    bool block(std::uint32_t ip, std::string_view reason, std::chrono::seconds duration = std::chrono::seconds(600), bool detect_only = false, bool manual = false) {
        if (detect_only) return false;
        if (is_allowed(ip)) {
            log_warn("refusing to block allow-listed " + ip_to_string(ip));
            return false;
        }
        if (!storage_) {
            log_warn("no storage attached - cannot persist block decision for " + ip_to_string(ip));
            return false;
        }

        std::string label = manual ? "manual" : "automatic";
        print_log("[BLOCKED]", ip_to_string(ip) + " ttl=" + std::to_string(duration.count()) + "s " + label +
                   " (decision recorded, bouncer-xdp will enforce)", "\x1b[31m");

        long long expires_unix = (duration.count() > 0)
            ? static_cast<long long>(std::time(nullptr)) + duration.count()
            : 0;
        storage_->insert_decision({ip_to_string(ip), "block", std::string(reason), std::string(reason), expires_unix, static_cast<int>(duration.count()), host_});
        return true;
    }

    void unblock(std::uint32_t ip) {
        print_log("[RELEASE]", ip_to_string(ip) + " (manual unblock, decision recorded)");
        if (storage_) {
            storage_->insert_decision({ip_to_string(ip), "unblock", "manual unblock", "", 0, 0, host_});
        }
    }

    // ADR-0002: the authoritative "should this IP be blocked" answer now
    // lives in storage's decisions, not the kernel map (bouncer-xdp owns
    // that and only mirrors it there). This reads the decisions and, for
    // each, does a read-only lookup against the pinned blocked_ips map to
    // show whether bouncer-xdp has actually caught up yet.
    void print_blocked(std::function<void(const std::string&)> out) {
        if (!storage_) { out("Active Blocks: <storage unavailable>"); return; }
        auto decisions = storage_->get_active_decisions();
        long long now_unix = static_cast<long long>(std::time(nullptr));

        out("Active Blocks (decisions; bouncer-xdp enforces within its poll interval):");
        if (decisions.empty()) { out("  <none>"); return; }

        for (const auto& d : decisions) {
            long long left = d.expires_at_unix - now_unix;
            if (left < 0) left = 0;
            std::string exp = (d.expires_at_unix == 0) ? "permanent" : std::to_string(left) + "s left";

            std::string enforced = "[pending]";
            if (auto ip = parse_ipv4_local(d.ip)) {
                struct block_record rec;
                if (bpf_map_lookup_elem(blocked_fd_, &*ip, &rec) == 0) enforced = "[enforced]";
            }
            out("  " + d.ip + " (" + exp + ", " + d.reason + ") " + enforced);
        }
    }

    std::tuple<std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t> get_stats() {
        int ncpus = libbpf_num_possible_cpus();
        std::uint64_t stats_vals[256] = {0};
        std::uint64_t dropped = 0, passed = 0;
        std::uint32_t key_dropped = 0, key_passed = 1;
        if (bpf_map_lookup_elem(stats_fd_, &key_dropped, stats_vals) == 0) {
            for(int i=0; i<ncpus && i<256; i++) dropped += stats_vals[i];
        }
        if (bpf_map_lookup_elem(stats_fd_, &key_passed, stats_vals) == 0) {
            for(int i=0; i<ncpus && i<256; i++) passed += stats_vals[i];
        }
        
        std::uint64_t tcp=0, udp=0, icmp=0, other=0;
        std::uint32_t proto_tcp=0, proto_udp=1, proto_icmp=2, proto_other=3;
        std::uint64_t vals[256] = {0};
        if (bpf_map_lookup_elem(proto_stats_fd_, &proto_tcp, vals) == 0) for(int i=0; i<ncpus && i<256; i++) tcp += vals[i];
        if (bpf_map_lookup_elem(proto_stats_fd_, &proto_udp, vals) == 0) for(int i=0; i<ncpus && i<256; i++) udp += vals[i];
        if (bpf_map_lookup_elem(proto_stats_fd_, &proto_icmp, vals) == 0) for(int i=0; i<ncpus && i<256; i++) icmp += vals[i];
        if (bpf_map_lookup_elem(proto_stats_fd_, &proto_other, vals) == 0) for(int i=0; i<ncpus && i<256; i++) other += vals[i];
        return {dropped, passed, tcp, udp, icmp, other};
    }

    void print_stats(std::function<void(const std::string&)> out) {
        auto [dropped, passed, tcp, udp, icmp, other] = get_stats();
        std::ostringstream oss;
        oss << "Stats: dropped=" << dropped << " passed=" << passed 
            << " | Proto: TCP=" << tcp << " UDP=" << udp << " ICMP=" << icmp << " Other=" << other;
        out(oss.str());
    }

private:
    // No sweep_loop anymore: expiry is decided by the Local API's SQL query
    // (get_active_decisions filters to non-expired rows) and enforced by
    // bouncer-xdp simply no longer finding an expired IP in the next poll's
    // result set, so it deletes it from blocked_ips itself. Nothing in this
    // process needs to touch the kernel map's expiry on a timer anymore.

    int allowed_fd_;
    int blocked_fd_;
    int stats_fd_;
    int proto_stats_fd_;
    Storage* storage_;
    std::string host_;
};

class XdpEngine {
public:
    // ADR-0002: engine no longer loads xdp_prog.bpf.c or attaches it itself.
    // bouncer-xdp owns the attach and pins every map it defines under
    // XDP_ENGINE_PIN_DIR; engine just opens what it needs from there. This
    // means bouncer-xdp must be started (on this interface) before engine -
    // see README.md.
    XdpEngine(const std::string& /*obj_path*/, const std::string& ifname) : ifname_{ifname} {
        const unsigned ifindex = if_nametoindex(ifname.c_str());
        if (ifindex == 0) throw std::runtime_error("no such interface: " + ifname);

        auto open_pinned = [](const char* name) {
            std::string path = std::string(XDP_ENGINE_PIN_DIR) + "/" + name;
            return bpf_obj_get(path.c_str());
        };

        allowed_fd_ = open_pinned("allowed_ips");
        blocked_fd_ = open_pinned("blocked_ips");
        if (allowed_fd_ < 0 || blocked_fd_ < 0) {
            throw std::runtime_error(
                "could not open pinned maps under " + std::string(XDP_ENGINE_PIN_DIR) +
                " - is bouncer-xdp running on " + ifname + "? Start it first: sudo ./bouncer-xdp " + ifname);
        }

        stats_fd_       = open_pinned("stats");
        events_fd_      = open_pinned("events");
        limits_fd_      = open_pinned("limits");
        proto_stats_fd_ = open_pinned("proto_stats");

        set_limit(200);
    }

    int allowed_fd() const { return allowed_fd_; }
    int blocked_fd() const { return blocked_fd_; }
    int stats_fd() const { return stats_fd_; }
    int events_fd() const { return events_fd_; }
    int proto_stats_fd() const { return proto_stats_fd_; }
    std::string get_ifname() const { return ifname_; }
    int get_limit() const { return limit_; }

    void set_limit(std::uint32_t limit) {
        if (limits_fd_ >= 0) {
            std::uint32_t zero = 0;
            if (!map_update(limits_fd_, zero, limit)) {
                log_warn("Failed to set limit");
            } else {
                limit_ = limit;
                log_info("SYN rate limit set to " + std::to_string(limit) + "/s");
            }
        }
    }

private:
    std::string ifname_;
    // No bpf_object/bpf_link members anymore: all fds below come from
    // bpf_obj_get() on bouncer-xdp's pins, which outlive this process
    // regardless of whether engine holds them open.
    int allowed_fd_{-1}, blocked_fd_{-1}, stats_fd_{-1}, events_fd_{-1}, limits_fd_{-1}, proto_stats_fd_{-1};
    int limit_{200};
};

using EventCallback = std::function<void(const Event&)>;

class SshDetector {
public:
    // The envelope regex used to be hardcoded right here; it now lives in
    // parsers/s01-parse/ssh-auth.yaml (see docs/adr/0003-staged-parser-
    // pipeline.md) and is loaded through LogParser instead.
    SshDetector(std::string path, EventCallback cb)
        : cb_(std::move(cb)),
          parser_("parsers/s01-parse/ssh-auth.yaml"),
          tailer_(std::move(path), [this](const std::string& line) { handle_line(line); }) {}

    void run(std::stop_token st) { tailer_.run(st); }

private:
    void handle_line(const std::string& line) {
        std::unordered_map<std::string, std::string> fields;
        if (!parser_.parse(line, fields)) return;

        auto ip_it = fields.find("ip");
        if (ip_it == fields.end() || !parse_ipv4_local(ip_it->second)) return;

        Event e;
        e.ts_iso = get_iso_time_str();
        e.source = parser_.source();
        e.type = parser_.emit_type();
        e.src_ip = ip_it->second;
        auto user_it = fields.find("user");
        e.user = (user_it != fields.end()) ? user_it->second : "";
        e.severity = parser_.severity();

        if (cb_) cb_(e);
    }
    EventCallback cb_;
    LogParser parser_;
    LogTailer tailer_;
};

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: sudo " << argv[0] << " <iface> [--enforce] [--allow IP]... [--ttl S] [--threshold N] [--window S] [--auth-log P] [--access-log P]\n";
        std::cerr << "       sudo " << argv[0] << " cleanup <iface>\n";
        std::cerr << "       sudo " << argv[0] << " reset\n";
        std::cerr << "       sudo " << argv[0] << " report\n";
        return 1;
    }

    std::string cmd_or_iface = argv[1];

    if (cmd_or_iface == "cleanup") {
        // ADR-0002: engine no longer loads/attaches the XDP program - bouncer-xdp
        // does, and owns detaching it too.
        std::cerr << "engine no longer attaches the XDP program (see docs/adr/0002-bouncer-xdp-separation.md).\n";
        std::cerr << "Use: sudo ./bouncer-xdp cleanup " << (argc >= 3 ? argv[2] : "<iface>") << "\n";
        return 1;
    }

    if (cmd_or_iface == "reset") {
        // Only engine's own control socket is engine's to clean up now; the
        // pinned maps/link under XDP_ENGINE_PIN_DIR belong to bouncer-xdp.
        std::cout << "Note: pinned maps/link are owned by bouncer-xdp now - use "
                     "'sudo ./bouncer-xdp cleanup <iface>' to remove those.\n";
        unlink("/run/xdp_engine.sock");
        // Database renaming removed; history is wiped inside instead.
        return 0;
    }

    if (cmd_or_iface == "report") {
        Storage storage{"engine.db"};
        storage.wipe_history();
        storage.generate_report("report.md");
        std::cout << "Report written to report.md\n";
        
        auto print = [](const std::string& msg) { std::cout << msg << "\n"; };
        std::cout << "=== Last 10 Alerts ===\n";
        storage.print_last_alerts(10, print);
        return 0;
    }

    // Normal Start
    std::string iface = cmd_or_iface;
    std::unordered_set<std::uint32_t> allow{*parse_ipv4_local("127.0.0.1")};
    add_iface_ips(allow, iface);
    add_gateway_ips(allow);

    std::atomic<bool> enforce_mode{false};
    int ttl = 600;
    int threshold = 5;
    int window = 60;
    std::string auth_log;
    if (access("/var/log/secure", R_OK) == 0) auth_log = "/var/log/secure";
    else auth_log = "/var/log/auth.log";
    std::string access_log = "/var/log/nginx/access.log";

    use_color = isatty(STDOUT_FILENO);

    for (int i = 2; i < argc; i++) {
        std::string_view arg{argv[i]};
        if (arg == "--allow" && i + 1 < argc) {
            if (auto ip = parse_ipv4_local(argv[++i])) allow.insert(*ip);
        } else if (arg == "--enforce") {
            enforce_mode = true;
        } else if (arg == "--ttl" && i + 1 < argc) {
            ttl = std::stoi(argv[++i]);
        } else if (arg == "--threshold" && i + 1 < argc) {
            threshold = std::stoi(argv[++i]);
        } else if (arg == "--window" && i + 1 < argc) {
            window = std::stoi(argv[++i]);
        } else if (arg == "--auth-log" && i + 1 < argc) {
            auth_log = argv[++i];
        } else if (arg == "--access-log" && i + 1 < argc) {
            access_log = argv[++i];
        }
    }

    bool all_pass = true;
    auto check_fail = [&](const std::string& msg) {
        std::cerr << "FAIL: " << msg << "\n";
        all_pass = false;
    };

    if (getuid() != 0) check_fail("Not running as root. Fix: use sudo");
    else std::cout << "PASS: Running as root\n";

    struct utsname buffer;
    if (uname(&buffer) == 0) std::cout << "PASS: Kernel " << buffer.release << "\n";
    else check_fail("uname failed");
    
    if (access("/sys/kernel/btf/vmlinux", R_OK) == 0) std::cout << "PASS: BTF file found\n";
    else check_fail("BTF file missing. Fix: install kernel headers");

    unsigned int ifindex = if_nametoindex(iface.c_str());
    if (ifindex > 0) std::cout << "PASS: Interface " << iface << " exists\n";
    else check_fail("Interface " + iface + " not found");

    if (check_process("sshd")) std::cout << "PASS: sshd is running\n";
    else check_fail("sshd not running. Fix: sudo systemctl start sshd");

    if (check_process("rsyslogd")) std::cout << "PASS: rsyslogd is running\n";
    else std::cout << "WARN: rsyslogd not running (journal-only setups do not populate /var/log by default)\n";

    if (access(auth_log.c_str(), R_OK) == 0) std::cout << "PASS: " << auth_log << " readable\n";
    else check_fail(auth_log + " not readable. Fix: ensure rsyslog is logging auth authpriv to it");

    if (access(access_log.c_str(), R_OK) == 0) std::cout << "PASS: " << access_log << " readable\n";
    else std::cout << "WARN: " << access_log << " not readable\n";

    auto check_ssh_conf = [&](const std::string& p) {
        std::ifstream f(p);
        std::string line;
        while (std::getline(f, line)) {
            if (line.find("PasswordAuthentication") != std::string::npos && line[0] != '#') return line;
        }
        return std::string("");
    };
    std::string pwd_auth = check_ssh_conf("/etc/ssh/sshd_config");
    if (pwd_auth.empty()) {
        std::error_code ec;
        if (std::filesystem::exists("/etc/ssh/sshd_config.d", ec)) {
            for (const auto& entry : std::filesystem::directory_iterator("/etc/ssh/sshd_config.d", ec)) {
            pwd_auth = check_ssh_conf(entry.path());
            if (!pwd_auth.empty()) break;
        }
        }
    }
    if (pwd_auth.find("yes") != std::string::npos) std::cout << "PASS: " << pwd_auth << "\n";
    else std::cout << "WARN: PasswordAuth not explicitly 'yes'. Failed password lines will not appear in logs if disabled!\n";

    if (ifindex > 0) {
        // Post-ADR-0002, bouncer-xdp - not engine - owns attaching the XDP
        // program, and it stays attached across restarts by design (that's
        // the whole point of pinning the link). So an attached program here
        // is the *expected*, healthy state, not a conflict: this used to
        // check for "no existing XDP program" (back when engine attached
        // its own), which would now spuriously fail on every normal
        // startup. What engine actually needs is for bouncer-xdp's pinned
        // maps to exist - XdpEngine's constructor will bpf_obj_get() them
        // and throw if they're missing - so check for that instead, which
        // gives a much more actionable failure than "XDP already attached"
        // ever did.
        std::string link_pin = std::string(XDP_ENGINE_PIN_DIR) + "/link_xdp_firewall";
        if (access(link_pin.c_str(), F_OK) == 0) {
            std::cout << "PASS: bouncer-xdp is attached to " << iface
                      << " (pinned maps found under " << XDP_ENGINE_PIN_DIR << ")\n";
        } else {
            check_fail("bouncer-xdp is not attached to " + iface + " yet - no pinned link found under " +
                       std::string(XDP_ENGINE_PIN_DIR) + ". Fix: start it first: sudo ./bouncer-xdp " + iface);
        }
    }

    if (!all_pass) return 1;

    std::string mode_str = enforce_mode ? "ENFORCE" : "DETECT";

    std::cout << "=== ENGINE STARTUP BANNER ===\n";
    std::cout << "Interface: " << iface << "\n";
    std::cout << "XDP Mode:  Auto\n";
    std::cout << "Mode:      " << mode_str << "\n";
    std::cout << "TTL:       " << ttl << "s\n";
    std::cout << "Threshold: " << threshold << "\n";
    std::cout << "Window:    " << window << "s\n";
    std::cout << "Auth Log:  " << auth_log << "\n";
    std::cout << "Access Log:" << access_log << "\n";
    std::cout << "Allowed:   ";
    for (auto ip : allow) std::cout << ip_to_string(ip) << " ";
    std::cout << "\nDashboard: http://127.0.0.1:5000/?showcase=1\n";
    std::cout << "=============================\n";
    
    struct sigaction sa{};
    sa.sa_handler = [](int) { g_running = false; };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    try {
        Storage storage{"engine.db"};
        storage.wipe_history();
        storage.insert_action({get_iso_time_str(), "", "mode_change", mode_str});
        struct timespec init_ts;
        clock_gettime(CLOCK_REALTIME, &init_ts);
        storage.insert_metrics(init_ts.tv_sec, 0, 0, 0, 0, 0, 0, 200, enforce_mode ? "ENFORCE" : "DETECT");

        RuleEngine rule_engine{"rules.yaml"};
        // override_rules removed to respect rules.yaml

        std::string bpf_obj = "xdp_prog.bpf.o";
        char proc_exe[256];
        ssize_t len = readlink("/proc/self/exe", proc_exe, sizeof(proc_exe)-1);
        if (len != -1) {
            proc_exe[len] = '\0';
            std::string exe_path(proc_exe);
            size_t last_slash = exe_path.find_last_of('/');
            if (last_slash != std::string::npos) {
                std::string bpf_path = exe_path.substr(0, last_slash) + "/xdp_prog.bpf.o";
                if (access(bpf_path.c_str(), R_OK) == 0) bpf_obj = bpf_path;
            }
        }

        XdpEngine engine{bpf_obj, iface};
        BlockList blocklist{engine.allowed_fd(), engine.blocked_fd(), engine.stats_fd(), engine.proto_stats_fd(), allow, &storage};
        
        PlaybookRunner::BlockCallback block_cb = [&](const std::string& ip_str, const std::string& rule, int seconds) -> int {
            auto ip = parse_ipv4_local(ip_str);
            if (!ip) return -1;
            if (blocklist.is_allowed(*ip)) return 1;
            
            if (!enforce_mode) {
                print_log("[DETECTED]", "would block " + ip_str + " (detect mode)", "\x1b[34m");
                storage.insert_action({get_iso_time_str(), ip_str, "detected", rule});
                return 1;
            }
            return blocklist.block(*ip, rule, std::chrono::seconds(seconds), false, false) ? 0 : -1;
        };
        
        PlaybookRunner::RecordCallback record_cb = [&](const ActionRecord& act) {
            storage.insert_action(act);
        };
        
        Notifier notifier;
        PlaybookRunner::NotifyCallback notify_cb = [&](const Alert& a) {
            notifier.notify(a);
        };
        
        PlaybookRunner::OffenseCallback off_cb = [&](const std::string& ip) {
            return storage.get_offense_count(ip);
        };
        PlaybookRunner::RecordOffenseCallback rec_off_cb = [&](const std::string& ip) {
            storage.record_offense(ip);
        };
        
        PlaybookRunner runner{"playbooks.yaml", "known_ips.txt", "blocklist.txt", block_cb, record_cb, notify_cb, off_cb, rec_off_cb};
        
        EventCallback on_event = [&](const Event& e) {
            if (e.type == "ssh_failed") {
                print_log("[AUTH]", "SSH failure from " + e.src_ip + " (" + e.user + ")", "\x1b[33m");
            } else if (e.type == "port_scan") {
                print_log("[SCAN]", "Port scan from " + e.src_ip, "\x1b[33m");
            } else if (e.type.find("http_") == 0) {
                print_log("[WEB]", e.type + " from " + e.src_ip, "\x1b[33m");
            } else if (e.type == "rate_limit_exceeded") {
                print_log("[FLOOD]", "SYN rate limit exceeded from " + e.src_ip, "\x1b[33m");
            }
            storage.insert_event(e);
            
            auto alerts = rule_engine.process(e);
            for (auto a : alerts) { 
                runner.execute(a); 
                storage.insert_alert(a);
            }
        };

        SshDetector detector{auth_log, on_event};
        std::jthread watcher{[&detector](std::stop_token st) { detector.run(st); }};
        
        // HttpDetector's own constructor already starts its watch_loop() on an
        // internal jthread (see HttpDetector::watcher_) - do not spawn a second
        // one here. An earlier version of this code spawned an explicit thread
        // at this call site too, which meant every HTTP access-log line was
        // tailed and processed twice concurrently, by two separate LogTailer
        // instances racing on the same file, doubling every HTTP-driven alert.
        HttpDetector http_detector{access_log, rule_engine, on_event};

        auto handle_event = [](void* ctx, void* data, size_t size) -> int {
            if (size < sizeof(drop_event)) return 0;
            auto* d = static_cast<const drop_event*>(data);
            if (d->reason == REASON_BLOCKLIST || d->reason == REASON_RATELIMIT) {
                static std::unordered_map<uint64_t, uint64_t> last_emit_ns;
                uint64_t key = (static_cast<uint64_t>(d->src_ip) << 32) | d->reason;
                auto it = last_emit_ns.find(key);
                if (it != last_emit_ns.end() && d->ts_ns >= it->second && (d->ts_ns - it->second) < 2000000000ULL) {
                    return 0;
                }
                if (last_emit_ns.size() > 10000) last_emit_ns.clear();
                last_emit_ns[key] = d->ts_ns;
            }
            auto* on_event_ptr = static_cast<EventCallback*>(ctx);
            Event e;
            e.ts_iso = get_iso_time_str();
            e.source = "xdp";
            if (d->reason == REASON_RATELIMIT) e.type = "rate_limit_exceeded";
            else if (d->reason == REASON_PORTSCAN) e.type = "port_scan";
            else if (d->reason == REASON_ICMP) e.type = "icmp_seen";
            else e.type = "xdp_drop";
            e.src_ip = ip_to_string(d->src_ip);
            e.severity = 4;
            (*on_event_ptr)(e);
            return 0;
        };

        RingBufPtr rb{ring_buffer__new(engine.events_fd(), handle_event, &on_event, nullptr)};
        if (!rb) throw std::runtime_error("failed to create ring buffer");
        std::jthread rb_poller{[&rb, &runner](std::stop_token st) {
            while (!st.stop_requested()) {
                ring_buffer__poll(rb.get(), 100);
                runner.check_expiries();
            }
        }};
        
        auto get_xdp_mode = [](const std::string& ifname) -> std::string {
            int ifindex = if_nametoindex(ifname.c_str());
            if (ifindex == 0) return "none";
            DECLARE_LIBBPF_OPTS(bpf_xdp_query_opts, opts);
            if (bpf_xdp_query(ifindex, 0, &opts) < 0) return "none";
            switch (opts.attach_mode) {
                case XDP_ATTACHED_DRV: return "native";
                case XDP_ATTACHED_SKB: return "skb";
                case XDP_ATTACHED_HW: return "offload";
                default: return "none";
            }
        };

        uint64_t last_dropped = 0;
        
        std::jthread metrics_poller{[&](std::stop_token st) {
            while (!st.stop_requested()) {
                std::mutex m; std::unique_lock lk(m);
                if (std::condition_variable_any().wait_for(lk, st, 1s, []{return false;})) {
                    break;
                }
                
                auto [dropped, passed, tcp, udp, icmp, other] = blocklist.get_stats();
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                
                std::string xdp_mode = get_xdp_mode(engine.get_ifname());
                storage.insert_metrics(ts.tv_sec, dropped, passed, tcp, udp, icmp, other, engine.get_limit(), enforce_mode ? "ENFORCE" : "DETECT");
                
                uint64_t delta = (dropped >= last_dropped) ? (dropped - last_dropped) : 0;
                if (delta > 0) {
                    std::string rate_str = std::to_string(delta) + "/s";
                    if (delta >= 1'000'000) {
                        double m = static_cast<double>(delta) / 1'000'000.0;
                        char buf[32];
                        std::snprintf(buf, sizeof(buf), " (%.2fM/s)", m);
                        rate_str += buf;
                    }
                    print_log("[DROPPING]", "total=" + std::to_string(dropped) + " rate=" + rate_str, "\x1b[31m");
                }
                last_dropped = dropped;
            }
        }};

        log_info("XDP attached to " + iface + ". Commands: mode [detect|enforce|show] | allow <ip> | unallow <ip> | block <ip> | unblock <ip> | list | stats | alerts | approve <id> | deny <id> | quit");

        auto process_command = [&](const std::string& line, std::function<void(const std::string&)> out) {
            std::istringstream iss{line};
            std::string cmd, arg, arg2;
            iss >> cmd >> arg >> arg2;
            if (cmd == "quit") {
                g_running = false;
                out("shutting down engine");
            }
            else if (cmd == "mode") {
                if (arg == "enforce") {
                    enforce_mode = true;
                    storage.insert_action({get_iso_time_str(), "", "mode_change", "ENFORCE"});
                    auto [d, p, t, u, ic, o] = blocklist.get_stats();
                    struct timespec ts;
                    clock_gettime(CLOCK_REALTIME, &ts);
                    storage.insert_metrics(ts.tv_sec, d, p, t, u, ic, o, engine.get_limit(), "ENFORCE");
                    out("Mode switched to: ENFORCE");
                } else if (arg == "detect") {
                    enforce_mode = false;
                    storage.insert_action({get_iso_time_str(), "", "mode_change", "DETECT"});
                    auto [d, p, t, u, ic, o] = blocklist.get_stats();
                    struct timespec ts;
                    clock_gettime(CLOCK_REALTIME, &ts);
                    storage.insert_metrics(ts.tv_sec, d, p, t, u, ic, o, engine.get_limit(), "DETECT");
                    out("Mode switched to: DETECT");
                } else if (arg == "show" || arg.empty()) {
                    out(std::string("Current mode: ") + (enforce_mode ? "ENFORCE" : "DETECT"));
                } else {
                    out("Usage: mode [detect|enforce|show]");
                }
            }
            else if (cmd == "enforce") {
                enforce_mode = true;
                storage.insert_action({get_iso_time_str(), "", "mode_change", "ENFORCE"});
                auto [d, p, t, u, ic, o] = blocklist.get_stats();
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                storage.insert_metrics(ts.tv_sec, d, p, t, u, ic, o, engine.get_limit(), "ENFORCE");
                out("Mode switched to: ENFORCE");
            }
            else if (cmd == "detect") {
                enforce_mode = false;
                storage.insert_action({get_iso_time_str(), "", "mode_change", "DETECT"});
                auto [d, p, t, u, ic, o] = blocklist.get_stats();
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                storage.insert_metrics(ts.tv_sec, d, p, t, u, ic, o, engine.get_limit(), "DETECT");
                out("Mode switched to: DETECT");
            }
            else if (cmd == "allow") {
                if (auto ip = parse_ipv4_local(arg)) {
                    if (blocklist.allow_ip(*ip)) out("allowed " + arg);
                    else out("failed to allow " + arg);
                } else out("invalid IPv4 address");
            }
            else if (cmd == "unallow") {
                if (auto ip = parse_ipv4_local(arg)) {
                    if (blocklist.unallow_ip(*ip)) out("unallowed " + arg);
                    else out("failed to unallow " + arg);
                } else out("invalid IPv4 address");
            }
            else if (cmd == "alerts") {
                storage.print_last_alerts(10, out);
            }
            else if (cmd == "list")  blocklist.print_blocked(out);
            else if (cmd == "stats") blocklist.print_stats(out);
            else if (cmd == "block" || cmd == "unblock") {
                if (auto ip = parse_ipv4_local(arg)) {
                    if (cmd == "block") {
                        try {
                            int seconds = arg2.empty() ? 600 : std::stoi(arg2);
                            blocklist.block(*ip, "manual", std::chrono::seconds(seconds), false, true);
                            out("ok");
                        } catch (...) {
                            out("error: invalid ttl");
                        }
                    }
                    else if (cmd == "unblock") { blocklist.unblock(*ip); out("ok"); }
                } else out("invalid IPv4 address");
            }
            else if (cmd == "approve" || cmd == "deny") {
                try {
                    int id = std::stoi(arg);
                    if (cmd == "approve") runner.approve(id);
                    else runner.deny(id);
                    out("ok");
                } catch (...) {
                    out("error: invalid approval id");
                }
            } else if (!cmd.empty()) out("unknown command");
        };

        std::jthread socket_listener{[&](std::stop_token st) {
            const char* sock_path = "/run/xdp_engine.sock";
            unlink(sock_path);
            int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
            if (server_fd < 0) return;
            
            struct sockaddr_un addr{};
            addr.sun_family = AF_UNIX;
            strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
            
            if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                chmod(sock_path, 0600);
                listen(server_fd, 5);
                
                struct timeval tv{1, 0};
                setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                
                while (!st.stop_requested()) {
                    int client_fd = accept(server_fd, nullptr, nullptr);
                    if (client_fd >= 0) {
                        struct ucred ucred{};
                        socklen_t len = sizeof(struct ucred);
                        if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len) == 0 && ucred.uid == 0) {
                            char buf[257];
                            int n = read(client_fd, buf, 256);
                            if (n > 0) {
                                buf[n] = '\0';
                                std::string req(buf);
                                req.erase(req.find_last_not_of(" \t\r\n") + 1);
                                process_command(req, [client_fd](const std::string& msg) {
                                    std::string out = msg + "\n";
                                    write(client_fd, out.c_str(), out.length());
                                });
                            }
                        }
                        close(client_fd);
                    }
                }
            }
            close(server_fd);
            unlink(sock_path);
        }};

        std::string line;
        if (isatty(STDIN_FILENO)) {
            while (g_running && std::getline(std::cin, line)) {
                process_command(line, [](const std::string& msg) { log_info(msg); });
            }
        }
        
        if (g_running) {
            log_info("running in daemon mode, control via engine-cli");
            while (g_running) {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
        }
        log_info("shutting down, detaching XDP");
        storage.insert_metrics(0, 0, 0, 0, 0, 0, 0, 0, "OFFLINE");
        storage.insert_action({get_iso_time_str(), "", "engine_stop", "shutdown"});
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
