// SPDX-License-Identifier: MIT
// bouncer-nft.cpp - the second Remediation Component (ADR-0004).
//
// Same role as bouncer-xdp (ADR-0002): poll Local API's GET /decisions
// and reconcile an enforcement surface to match, independent of whatever
// decided those decisions. Where bouncer-xdp drops packets in the NIC
// driver via an XDP program, bouncer-nft drops them with an nftables
// `input` hook rule matching against a named set - no BPF/XDP-capable
// NIC or kernel required, just nf_tables + CAP_NET_ADMIN. See ADR-0004
// for the full tradeoff and why both exist.
//
// The actual `nft` invocation (fork/exec via popen) lives here, since
// that's the part that needs root and a real nftables-capable kernel.
// Everything else - script text, JSON parsing, the add/remove diff - is
// pure logic in nft_bouncer_core.h / bouncer_diff.h, unit-tested there.
#include <net/if.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <unordered_set>

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include "bouncer_diff.h"
#include "capdrop.h"
#include "nft_bouncer_core.h"

namespace {

volatile sig_atomic_t g_running = 1;

std::string getenv_or(const char* name, const std::string& fallback) {
    const char* v = std::getenv(name);
    return v ? std::string(v) : fallback;
}

// --- nft subprocess helpers ----------------------------------------------

// Runs `nft -f -`, writing `script` to its stdin. stdout/stderr are
// inherited (so an nft error shows up directly on our own stderr, which
// is what we want for a foreground process meant to be watched the way
// bouncer-xdp is). Returns true iff nft exited 0.
bool run_nft_script(const std::string& script) {
    if (script.empty()) return true; // nothing to do, same as bouncer_diff.h's no-op diff
    FILE* pipe = popen("nft -f -", "w");
    if (!pipe) {
        std::cerr << "[bouncer-nft] failed to spawn nft: " << std::strerror(errno) << "\n";
        return false;
    }
    std::fwrite(script.data(), 1, script.size(), pipe);
    int status = pclose(pipe);
    return status == 0;
}

// Runs `nft -j list set|chain ...` (built by the caller) and captures its
// stdout. Returns false (leaving `out` untouched) if nft couldn't even be
// spawned or exited non-zero - the caller decides what that means (see
// each call site; a missing set/chain is a real possibility on a
// completely fresh host and isn't necessarily an error worth logging
// loudly).
bool run_nft_capture(const std::string& cmd, std::string& out) {
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return false;
    std::string result;
    std::array<char, 4096> buf;
    size_t n;
    while ((n = std::fread(buf.data(), 1, buf.size(), pipe)) > 0) {
        result.append(buf.data(), n);
    }
    int status = pclose(pipe);
    if (status != 0) return false;
    out = std::move(result);
    return true;
}

// --- Local API client (self-contained copy - see ADR-0004 on why this
// isn't shared with bouncer-xdp's identical-looking version) -----------

size_t write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* out = static_cast<std::string*>(userdata);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

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
        std::cerr << "[bouncer-nft] Local API unreachable: " << curl_easy_strerror(res) << "\n";
        return false;
    }
    if (http_code != 200) {
        std::cerr << "[bouncer-nft] Local API returned HTTP " << http_code << "\n";
        return false;
    }

    try {
        auto arr = nlohmann::json::parse(response);
        out_ips.clear();
        for (const auto& d : arr) {
            std::string ip_str = d.value("ip", "");
            std::uint32_t ip_net = 0;
            if (!ip_str.empty() && ipv4_string_to_net(ip_str, ip_net)) {
                out_ips.insert(ip_net);
            }
        }
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[bouncer-nft] failed to parse decisions JSON: " << e.what() << "\n";
        return false;
    }
}

// --- setup / resume / cleanup --------------------------------------------

// Idempotently ensures table/set/chain/rule exist. Safe to call on every
// startup, resume or fresh. Returns false on any nft failure.
bool setup(const std::string& iface) {
    if (!run_nft_script(build_setup_script(NFT_TABLE, NFT_SET, NFT_CHAIN))) {
        std::cerr << "[bouncer-nft] failed to create table/set/chain\n";
        return false;
    }

    std::string chain_json;
    std::string list_chain_cmd =
        std::string("nft -j list chain inet ") + NFT_TABLE + " " + NFT_CHAIN;
    bool have_chain_listing = run_nft_capture(list_chain_cmd, chain_json);

    if (have_chain_listing && chain_has_rule_comment(chain_json, NFT_RULE_COMMENT)) {
        std::cout << "[bouncer-nft] enforcement rule already present (resuming)\n";
        return true;
    }

    // Either this is a genuinely fresh chain (no rule yet - expected) or
    // the listing failed for some other reason. Either way, `add rule`
    // itself has no "already there" ambiguity to worry about here: if a
    // rule with our comment truly exists, have_chain_listing would have
    // found it above. If the listing failed outright, that's a real
    // problem worth surfacing rather than silently skipping rule setup.
    if (!have_chain_listing) {
        std::cerr << "[bouncer-nft] could not list chain '" << NFT_CHAIN
                  << "' to check for an existing rule - continuing to add one "
                     "anyway, but a duplicate rule may result if one already exists\n";
    }

    if (!run_nft_script(build_rule_script(NFT_TABLE, NFT_SET, NFT_CHAIN, iface, NFT_RULE_COMMENT))) {
        std::cerr << "[bouncer-nft] failed to add enforcement rule\n";
        return false;
    }
    std::cout << "[bouncer-nft] added enforcement rule"
              << (iface.empty() ? " (all interfaces)" : " (iface=" + iface + ")") << "\n";
    return true;
}

// Reads the live kernel set contents. Unlike bouncer-xdp's
// read_enforced_ips (which can never fail - it's a direct BPF map walk),
// this goes through a subprocess and can fail for reasons unrelated to
// "the set is empty" (nft not found, a transient lock, etc.) - callers
// must not conflate a false return with an empty set. See the fatal exit
// in main() for why resuming on a false return would silently reintroduce
// the exact stale-block bug ADR-0002 already fixed once for bouncer-xdp.
bool read_enforced_ips(std::unordered_set<std::uint32_t>& out) {
    std::string set_json;
    std::string cmd = std::string("nft -j list set inet ") + NFT_TABLE + " " + NFT_SET;
    if (!run_nft_capture(cmd, set_json)) return false;
    return parse_set_elements(set_json, out);
}

int run_cleanup() {
    if (run_nft_script(std::string("destroy table inet ") + NFT_TABLE + "\n")) {
        std::cout << "[bouncer-nft] removed table inet " << NFT_TABLE << " (if it existed)\n";
        return 0;
    }
    std::cerr << "[bouncer-nft] failed to remove table inet " << NFT_TABLE << "\n";
    return 1;
}

} // namespace

int main(int argc, char** argv) {
    if (argc >= 2 && std::string(argv[1]) == "cleanup") {
        return run_cleanup();
    }

    std::string lapi_url = getenv_or("LOCAL_API_URL", "http://127.0.0.1:8088");
    std::string lapi_token = getenv_or("LOCAL_API_TOKEN", "");
    int poll_interval_s = 2;
    std::string iface;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--lapi-url" && i + 1 < argc) lapi_url = argv[++i];
        else if (arg == "--lapi-token" && i + 1 < argc) lapi_token = argv[++i];
        else if (arg == "--poll-interval" && i + 1 < argc) poll_interval_s = std::atoi(argv[++i]);
        else if (arg == "--iface" && i + 1 < argc) iface = argv[++i];
        else {
            std::cerr << "Usage: sudo " << argv[0]
                      << " [--iface IFACE] [--lapi-url URL] [--lapi-token TOKEN] "
                         "[--poll-interval SEC]\n";
            std::cerr << "       sudo " << argv[0] << " cleanup\n";
            return 1;
        }
    }

    if (!iface.empty() && if_nametoindex(iface.c_str()) == 0) {
        std::cerr << "no such interface: " << iface << "\n";
        return 1;
    }
    if (lapi_token.empty()) {
        std::cerr << "[warn] LOCAL_API_TOKEN is not set; requests to Local API will be "
                     "unauthenticated and will fail unless local-api was also started "
                     "without a token.\n";
    }

    // ADR-0006: unlike bouncer-xdp/engine, bouncer-nft needs CAP_NET_ADMIN for
    // its entire life, not just a one-time setup step - every poll iteration
    // execs `nft` again (run_nft_script(), above) to apply that round's diff.
    // So we drop everything else now, keep CAP_NET_ADMIN, and push it into
    // the *ambient* set: that's what makes a plain, non-file-capability
    // child binary like `nft` inherit exactly that one capability across
    // execve regardless of bouncer-nft's own uid (root via sudo today, or a
    // dedicated non-root service user under systemd's AmbientCapabilities=
    // in the future) - see docs/adr/0006-capability-drop.md for the sandbox
    // verification of this exact ambient-capability + execve pattern.
    capdrop::drop_bounding_except({CAP_NET_ADMIN});
    capdrop::drop_capabilities_to({CAP_NET_ADMIN}, "[bouncer-nft]");
    if (!capdrop::raise_ambient(CAP_NET_ADMIN)) {
        std::cerr << "[bouncer-nft] warning: could not raise CAP_NET_ADMIN into the ambient "
                     "set (" << std::strerror(errno) << ") - nft invocations below may fail "
                     "if this process isn't running as plain root\n";
    }

    struct sigaction sa{};
    sa.sa_handler = [](int) { g_running = 0; };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    if (!setup(iface)) return 1;

    std::unordered_set<std::uint32_t> currently_enforced;
    if (!read_enforced_ips(currently_enforced)) {
        std::cerr << "[bouncer-nft] could not read current set contents after setup - "
                     "refusing to start with an unknown baseline (a previous run's stale "
                     "blocks could otherwise never be released). Is 'nft' installed and "
                     "are we running as root?\n";
        return 1;
    }
    if (!currently_enforced.empty()) {
        std::cout << "[bouncer-nft] resuming with " << currently_enforced.size()
                  << " IP(s) already enforced in the nftables set\n";
    }

    std::cout << "[bouncer-nft] polling " << lapi_url << "/decisions every "
              << poll_interval_s << "s\n";

    while (g_running) {
        std::unordered_set<std::uint32_t> desired;
        if (fetch_decisions(lapi_url, lapi_token, desired)) {
            DecisionDiff diff = diff_decisions(currently_enforced, desired);
            std::string script = build_diff_script(NFT_TABLE, NFT_SET, diff);

            if (run_nft_script(script)) {
                for (std::uint32_t ip : diff.to_add) {
                    std::cout << "[bouncer-nft] [ENFORCE] blocking " << ipv4_net_to_string(ip) << "\n";
                    currently_enforced.insert(ip);
                }
                for (std::uint32_t ip : diff.to_remove) {
                    std::cout << "[bouncer-nft] [RELEASE] unblocking " << ipv4_net_to_string(ip) << "\n";
                    currently_enforced.erase(ip);
                }
            } else {
                std::cerr << "[bouncer-nft] failed to apply diff (" << diff.to_add.size()
                          << " add, " << diff.to_remove.size()
                          << " remove) - leaving currently_enforced untouched, will retry "
                             "with the same diff next poll\n";
                // Deliberately do NOT update currently_enforced here: the
                // whole script either lands or doesn't (nft transactions
                // are all-or-nothing - see nft_bouncer_core.h), so our
                // in-memory tracking staying stale is exactly correct,
                // not a partial-apply risk.
            }
        }
        // On fetch failure: leave currently_enforced and the kernel set
        // untouched (fail static, not fail open), same as bouncer-xdp.

        for (int i = 0; i < poll_interval_s * 10 && g_running; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    std::cout << "\n[bouncer-nft] shutting down (enforcement stays in place - "
                 "run 'cleanup' to remove the table)\n";
    return 0;
}
