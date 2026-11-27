// SPDX-License-Identifier: MIT
// bouncer-xdp.cpp - the enforcement component (ADR-0002).
//
// This is the only process that loads xdp_prog.bpf.c, attaches it to a
// NIC, and writes to blocked_ips. It has no rule engine, no log tailers,
// no SQLite writes of its own - it just polls Local API's GET /decisions
// and reconciles the kernel's blocked_ips map to match, the same way a
// CrowdSec "remediation component" (bouncer) consumes CAPI/LAPI decisions
// without knowing anything about how they were decided.
//
// Every map the BPF object defines is pinned under XDP_ENGINE_PIN_DIR so
// other processes (engine, future tools) can open them read-mostly with
// bpf_obj_get() instead of loading the object themselves. The XDP link
// itself is pinned too, so enforcement survives this process restarting -
// on startup we check for that pin first and, if present, just resume
// polling against the existing attachment rather than re-attaching.
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <sys/stat.h>
#include <unistd.h>

#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>
#include <unordered_set>

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include "bouncer_diff.h"
#include "common.h"

namespace {

volatile sig_atomic_t g_running = 1;

std::string ip_to_string(std::uint32_t ip_net) {
    char buf[INET_ADDRSTRLEN]{};
    in_addr addr{.s_addr = ip_net};
    inet_ntop(AF_INET, &addr, buf, sizeof buf);
    return buf;
}

std::string pin_path(const std::string& name) {
    return std::string(XDP_ENGINE_PIN_DIR) + "/" + name;
}

std::string getenv_or(const char* name, const std::string& fallback) {
    const char* v = std::getenv(name);
    return v ? std::string(v) : fallback;
}

// --- Local API client -------------------------------------------------

size_t write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* out = static_cast<std::string*>(userdata);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

// Fetches GET {lapi_url}/decisions and fills `out_ips` with the set of
// IPv4 addresses (network byte order, matching blocked_ips' key type)
// that should be blocked right now. Returns false on any network/auth/
// parse failure, in which case the caller should leave the previous
// enforced state untouched rather than blocking everyone or no one.
bool fetch_decisions(const std::string& lapi_url, const std::string& token,
                     std::unordered_set<std::uint32_t>& out_ips) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;

    std::string url = lapi_url + "/decisions";
    std::string response;
    struct curl_slist* headers = nullptr;
    std::string auth_header = "Authorization: Bearer " + token;
    headers = curl_slist_append(headers, auth_header.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        std::cerr << "[bouncer-xdp] Local API unreachable: " << curl_easy_strerror(res) << "\n";
        return false;
    }
    if (http_code != 200) {
        std::cerr << "[bouncer-xdp] Local API returned HTTP " << http_code << "\n";
        return false;
    }

    try {
        auto arr = nlohmann::json::parse(response);
        out_ips.clear();
        for (const auto& d : arr) {
            std::string ip_str = d.value("ip", "");
            in_addr addr{};
            if (!ip_str.empty() && inet_pton(AF_INET, ip_str.c_str(), &addr) == 1) {
                out_ips.insert(addr.s_addr);
            }
        }
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[bouncer-xdp] failed to parse decisions JSON: " << e.what() << "\n";
        return false;
    }
}

// --- map/link pinning ---------------------------------------------------

// Pins every map the loaded object defines under XDP_ENGINE_PIN_DIR, one
// file per map, named after the map. Generic over whatever maps
// xdp_prog.bpf.c currently defines so a future map doesn't need this file
// touched.
bool pin_all_maps(struct bpf_object* obj) {
    struct bpf_map* map;
    bpf_object__for_each_map(map, obj) {
        std::string path = pin_path(bpf_map__name(map));
        if (bpf_map__pin(map, path.c_str()) != 0 && errno != EEXIST) {
            std::cerr << "[bouncer-xdp] failed to pin map " << bpf_map__name(map)
                      << ": " << std::strerror(errno) << "\n";
            return false;
        }
    }
    return true;
}

int open_pinned_map(const char* name) {
    return bpf_obj_get(pin_path(name).c_str());
}

bool already_attached() {
    return access(pin_path("link_xdp_firewall").c_str(), F_OK) == 0;
}

// Walks the kernel's blocked_ips map and returns every IP currently
// enforced there. This is only needed on resume: when we re-attach fresh,
// the map starts empty and `currently_enforced` tracking it from {} is
// correct. But on resume against an *existing* pinned map, some other
// (now-dead) bouncer-xdp process may have left IPs blocked that are no
// longer in Local API's /decisions - without seeding `currently_enforced`
// from the real map contents first, diff_decisions() would never compute
// those as `to_remove` (its to_remove is `currently_enforced - desired`,
// and an empty currently_enforced can never produce a removal), leaving
// them blocked forever.
std::unordered_set<std::uint32_t> read_enforced_ips(int blocked_fd) {
    std::unordered_set<std::uint32_t> out;
    std::uint32_t key;
    std::uint32_t next_key;
    bool have_key = false;
    while (bpf_map_get_next_key(blocked_fd, have_key ? &key : nullptr, &next_key) == 0) {
        out.insert(next_key);
        key = next_key;
        have_key = true;
    }
    return out;
}

// --- cleanup subcommand --------------------------------------------------

int run_cleanup(const std::string& iface) {
    unsigned int ifindex = if_nametoindex(iface.c_str());
    if (ifindex == 0) {
        std::cerr << "Interface " << iface << " not found.\n";
    } else {
        __u32 prog_id = 0;
        if (bpf_xdp_query_id(ifindex, 0, &prog_id) == 0 && prog_id > 0) {
            DECLARE_LIBBPF_OPTS(bpf_xdp_attach_opts, attach_opts);
            if (bpf_xdp_detach(ifindex, 0, &attach_opts) == 0) {
                std::cout << "Detached XDP program (ID: " << prog_id << ") from " << iface << "\n";
            } else {
                std::cerr << "Failed to detach XDP program.\n";
            }
        } else {
            std::cout << "No XDP program attached to " << iface << ".\n";
        }
    }
    std::error_code ec;
    std::filesystem::remove_all(XDP_ENGINE_PIN_DIR, ec);
    std::cout << "Removed pinned maps/link under " << XDP_ENGINE_PIN_DIR << "\n";
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: sudo " << argv[0]
                  << " <iface> [--lapi-url URL] [--lapi-token TOKEN] [--poll-interval SEC]\n";
        std::cerr << "       sudo " << argv[0] << " cleanup <iface>\n";
        return 1;
    }

    std::string first_arg = argv[1];
    if (first_arg == "cleanup") {
        if (argc < 3) {
            std::cerr << "Usage: sudo " << argv[0] << " cleanup <iface>\n";
            return 1;
        }
        return run_cleanup(argv[2]);
    }

    const std::string iface = first_arg;
    std::string lapi_url = getenv_or("LOCAL_API_URL", "http://127.0.0.1:8088");
    std::string lapi_token = getenv_or("LOCAL_API_TOKEN", "");
    int poll_interval_s = 2;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--lapi-url" && i + 1 < argc) lapi_url = argv[++i];
        else if (arg == "--lapi-token" && i + 1 < argc) lapi_token = argv[++i];
        else if (arg == "--poll-interval" && i + 1 < argc) poll_interval_s = std::atoi(argv[++i]);
    }

    if (lapi_token.empty()) {
        std::cerr << "[warn] LOCAL_API_TOKEN is not set; requests to Local API will be "
                     "unauthenticated and will fail unless local-api was also started "
                     "without a token.\n";
    }

    unsigned int ifindex = if_nametoindex(iface.c_str());
    if (ifindex == 0) {
        std::cerr << "no such interface: " << iface << "\n";
        return 1;
    }

    struct sigaction sa{};
    sa.sa_handler = [](int) { g_running = 0; };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    int blocked_fd = -1;
    struct bpf_object* obj = nullptr;

    if (already_attached()) {
        std::cout << "[bouncer-xdp] Found an existing pinned attachment under "
                  << XDP_ENGINE_PIN_DIR << " - resuming against it instead of re-attaching.\n";
        std::cout << "[bouncer-xdp] (run 'sudo " << argv[0] << " cleanup " << iface
                  << "' first for a clean restart)\n";
        blocked_fd = open_pinned_map("blocked_ips");
        if (blocked_fd < 0) {
            std::cerr << "[bouncer-xdp] pin dir exists but blocked_ips map is missing/unreadable: "
                      << std::strerror(errno) << "\n";
            return 1;
        }
    } else {
        std::string bpf_obj_path = "xdp_prog.bpf.o";
        char proc_exe[256];
        ssize_t len = readlink("/proc/self/exe", proc_exe, sizeof(proc_exe) - 1);
        if (len != -1) {
            proc_exe[len] = '\0';
            std::string exe_path(proc_exe);
            size_t last_slash = exe_path.find_last_of('/');
            if (last_slash != std::string::npos) {
                std::string candidate = exe_path.substr(0, last_slash) + "/xdp_prog.bpf.o";
                if (access(candidate.c_str(), R_OK) == 0) bpf_obj_path = candidate;
            }
        }

        obj = bpf_object__open_file(bpf_obj_path.c_str(), nullptr);
        if (!obj) {
            std::cerr << "open failed: " << std::strerror(errno) << "\n";
            return 1;
        }
        if (int err = bpf_object__load(obj)) {
            std::cerr << "load failed: " << std::strerror(-err) << "\n";
            return 1;
        }

        struct bpf_program* prog = bpf_object__find_program_by_name(obj, "xdp_firewall");
        if (!prog) {
            std::cerr << "program xdp_firewall not found\n";
            return 1;
        }
        struct bpf_link* link = bpf_program__attach_xdp(prog, static_cast<int>(ifindex));
        if (!link) {
            std::cerr << "attach failed: " << std::strerror(errno) << "\n";
            return 1;
        }

        std::error_code ec;
        std::filesystem::create_directories(XDP_ENGINE_PIN_DIR, ec);

        if (!pin_all_maps(obj)) return 1;
        if (bpf_link__pin(link, pin_path("link_xdp_firewall").c_str()) != 0) {
            std::cerr << "[bouncer-xdp] failed to pin XDP link: " << std::strerror(errno) << "\n";
            return 1;
        }

        struct bpf_map* blocked_map = bpf_object__find_map_by_name(obj, "blocked_ips");
        blocked_fd = bpf_map__fd(blocked_map);
        std::cout << "[bouncer-xdp] attached xdp_firewall to " << iface
                  << " and pinned all maps + link under " << XDP_ENGINE_PIN_DIR << "\n";
    }

    std::cout << "[bouncer-xdp] polling " << lapi_url << "/decisions every "
              << poll_interval_s << "s\n";

    // Seed currently_enforced from the real map contents. On a fresh
    // attach the map is empty, so this is a no-op; on resume it's what
    // lets the first poll correctly release anything that should no
    // longer be blocked (see read_enforced_ips's comment).
    std::unordered_set<std::uint32_t> currently_enforced = read_enforced_ips(blocked_fd);
    if (!currently_enforced.empty()) {
        std::cout << "[bouncer-xdp] resuming with " << currently_enforced.size()
                  << " IP(s) already enforced in the kernel map\n";
    }

    while (g_running) {
        std::unordered_set<std::uint32_t> desired;
        if (fetch_decisions(lapi_url, lapi_token, desired)) {
            DecisionDiff diff = diff_decisions(currently_enforced, desired);

            for (std::uint32_t ip : diff.to_add) {
                block_record rec{};
                rec.hits = 0;
                rec.expires_at_ns = 0; // Local API already filters to active decisions
                                       // on every poll, so expiry is re-derived from
                                       // whether the IP still shows up next time around
                                       // rather than tracked in-kernel here.
                if (bpf_map_update_elem(blocked_fd, &ip, &rec, BPF_ANY) == 0) {
                    std::cout << "[bouncer-xdp] [ENFORCE] blocking " << ip_to_string(ip) << "\n";
                    currently_enforced.insert(ip);
                } else {
                    std::cerr << "[bouncer-xdp] failed to block " << ip_to_string(ip)
                              << ": " << std::strerror(errno) << "\n";
                }
            }
            for (std::uint32_t ip : diff.to_remove) {
                bpf_map_delete_elem(blocked_fd, &ip);
                std::cout << "[bouncer-xdp] [RELEASE] unblocking " << ip_to_string(ip) << "\n";
                currently_enforced.erase(ip);
            }
        }
        // On fetch failure: deliberately leave currently_enforced and the kernel
        // map untouched (fail static, not fail open) until Local API is reachable
        // again.

        for (int i = 0; i < poll_interval_s * 10 && g_running; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    std::cout << "\n[bouncer-xdp] shutting down (enforcement stays attached - "
                 "run 'cleanup' to detach and unpin)\n";
    if (obj) bpf_object__close(obj); // does NOT detach: the link and maps are pinned
    return 0;
}
