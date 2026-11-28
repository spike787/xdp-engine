// SPDX-License-Identifier: MIT
// bouncer-proxy.cpp - the third Remediation Component (ADR-0010,
// ROADMAP.md Phase 3's "proxy/app-layer bouncer").
//
// Same role as bouncer-xdp (ADR-0002) and bouncer-nft (ADR-0004): poll
// Local API's GET /decisions and enforce the result, independent of
// whatever decided it. Where those two drop packets before or during
// kernel routing, bouncer-proxy sits in front of a single HTTP backend as
// a reverse proxy: every request's client address is checked against the
// current decision set before anything reaches the backend, and a
// blocked client gets 403 without the backend ever seeing the request.
//
// This is the one bouncer ADR-0001 named from the start as the answer to
// "traffic XDP can't see" - a TLS-terminated application behind a load
// balancer, a host with no XDP-capable NIC and not even CAP_NET_ADMIN for
// bouncer-nft, a container that can't touch the kernel's networking stack
// at all. The tradeoff: it only protects the one HTTP backend it fronts,
// at application-proxy latency, not line rate - see ADR-0010 for the full
// comparison against its two siblings.
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>

#include <curl/curl.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "bouncer_diff.h"
#include "capdrop.h"
#include "proxy_bouncer_core.h"
#include "utils.h"

namespace {

volatile sig_atomic_t g_running = 1;

std::string ip_to_string(std::uint32_t ip_net) {
    char buf[INET_ADDRSTRLEN]{};
    in_addr addr{.s_addr = ip_net};
    inet_ntop(AF_INET, &addr, buf, sizeof buf);
    return buf;
}

std::string getenv_or(const char* name, const std::string& fallback) {
    const char* v = std::getenv(name);
    return v ? std::string(v) : fallback;
}

// --- Local API client (self-contained copy - see ADR-0004 on why this
// isn't shared between bouncers) ------------------------------------------

size_t write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* out = static_cast<std::string*>(userdata);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

// TLS options for the Local API connection (ADR-0012). A self-contained
// copy, same reasoning as fetch_decisions() itself not being shared
// across bouncers (see ADR-0004): no shared TLS config header either.
// Unrelated to bouncer-proxy's own listening socket or its httplib::Client
// to the backend - this is only the libcurl path to Local API.
struct LapiTlsConfig {
    std::string ca_cert;     // --lapi-ca-cert / LAPI_CA_CERT
    std::string client_cert; // --lapi-client-cert / LAPI_CLIENT_CERT (mTLS)
    std::string client_key;  // --lapi-client-key / LAPI_CLIENT_KEY (mTLS)
    bool insecure_skip_verify = false; // --lapi-insecure-skip-verify / LAPI_TLS_INSECURE_SKIP_VERIFY=1
};

void apply_tls_options(CURL* curl, const LapiTlsConfig& tls) {
    if (!tls.ca_cert.empty()) curl_easy_setopt(curl, CURLOPT_CAINFO, tls.ca_cert.c_str());
    if (!tls.client_cert.empty()) curl_easy_setopt(curl, CURLOPT_SSLCERT, tls.client_cert.c_str());
    if (!tls.client_key.empty()) curl_easy_setopt(curl, CURLOPT_SSLKEY, tls.client_key.c_str());
    if (tls.insecure_skip_verify) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
}

bool fetch_decisions(const std::string& lapi_url, const std::string& token,
                     const LapiTlsConfig& tls,
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
    apply_tls_options(curl, tls);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        std::cerr << "[bouncer-proxy] Local API unreachable: " << curl_easy_strerror(res) << "\n";
        return false;
    }
    if (http_code != 200) {
        std::cerr << "[bouncer-proxy] Local API returned HTTP " << http_code << "\n";
        return false;
    }

    try {
        auto arr = nlohmann::json::parse(response);
        out_ips.clear();
        for (const auto& d : arr) {
            std::string ip_str = d.value("ip", "");
            if (auto ip = parse_ipv4(ip_str)) out_ips.insert(*ip);
        }
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[bouncer-proxy] failed to parse decisions JSON: " << e.what() << "\n";
        return false;
    }
}

// --- shared enforcement state ---------------------------------------------
// No kernel object to reconcile here - "enforcement" is just this set, read
// by every request-handling thread and replaced wholesale by the poll
// thread. diff_decisions() is still used (unmodified, same as bouncer-nft)
// purely to log what changed; applying the result is simply swapping the
// set in under the lock, since there's no subprocess or syscall "apply"
// step the way there is for bouncer-xdp/bouncer-nft.
std::mutex g_mutex;
std::unordered_set<std::uint32_t> g_blocked;

bool is_blocked(std::uint32_t ip) {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_blocked.count(ip) != 0;
}

void apply_decisions(const std::unordered_set<std::uint32_t>& desired) {
    std::lock_guard<std::mutex> lock(g_mutex);
    DecisionDiff diff = diff_decisions(g_blocked, desired);
    for (std::uint32_t ip : diff.to_add) {
        std::cout << "[bouncer-proxy] [ENFORCE] blocking " << ip_to_string(ip) << "\n";
    }
    for (std::uint32_t ip : diff.to_remove) {
        std::cout << "[bouncer-proxy] [RELEASE] unblocking " << ip_to_string(ip) << "\n";
    }
    g_blocked = desired;
}

// --- reverse proxy ---------------------------------------------------------

// Forwards req to backend_url verbatim (method, raw target incl. query
// string, body, and every header except the hop-by-hop ones
// is_hop_by_hop_header strips - see proxy_bouncer_core.h). Not a fully
// RFC 7230-compliant proxy (see ADR-0010's Known gap: no WebSocket
// upgrade, no trailers), but correct for ordinary request/response HTTP,
// which is what every attack scenario this project detects (SQLi, path
// traversal, SSH brute force reported via a web dashboard, etc.) actually
// looks like on the wire.
void proxy_to_backend(httplib::Client& client, const httplib::Request& req, httplib::Response& res) {
    httplib::Request fwd;
    fwd.method = req.method;
    fwd.path = req.target; // raw request-target, query string included
    fwd.body = req.body;
    for (const auto& [name, value] : req.headers) {
        if (!is_hop_by_hop_header(name)) fwd.headers.emplace(name, value);
    }

    auto result = client.send(fwd);
    if (!result) {
        res.status = 502;
        res.set_content("Bad Gateway: backend unreachable (" +
                         httplib::to_string(result.error()) + ")\n", "text/plain");
        return;
    }

    res.status = result->status;
    res.body = result->body;
    for (const auto& [name, value] : result->headers) {
        if (!is_hop_by_hop_header(name)) res.set_header(name, value);
    }
}

} // namespace

int main(int argc, char** argv) {
    std::string lapi_url = getenv_or("LOCAL_API_URL", "http://127.0.0.1:8088");
    std::string lapi_token = getenv_or("LOCAL_API_TOKEN", "");
    std::string backend_url = "http://127.0.0.1:5000"; // the showcase dashboard, by default
    int listen_port = 8080;
    int poll_interval_s = 2;
    LapiTlsConfig tls;
    tls.ca_cert = getenv_or("LAPI_CA_CERT", "");
    tls.client_cert = getenv_or("LAPI_CLIENT_CERT", "");
    tls.client_key = getenv_or("LAPI_CLIENT_KEY", "");
    tls.insecure_skip_verify = getenv_or("LAPI_TLS_INSECURE_SKIP_VERIFY", "") == "1";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--backend" && i + 1 < argc) backend_url = argv[++i];
        else if (arg == "--listen-port" && i + 1 < argc) listen_port = std::atoi(argv[++i]);
        else if (arg == "--lapi-url" && i + 1 < argc) lapi_url = argv[++i];
        else if (arg == "--lapi-token" && i + 1 < argc) lapi_token = argv[++i];
        else if (arg == "--poll-interval" && i + 1 < argc) poll_interval_s = std::atoi(argv[++i]);
        else if (arg == "--lapi-ca-cert" && i + 1 < argc) tls.ca_cert = argv[++i];
        else if (arg == "--lapi-client-cert" && i + 1 < argc) tls.client_cert = argv[++i];
        else if (arg == "--lapi-client-key" && i + 1 < argc) tls.client_key = argv[++i];
        else if (arg == "--lapi-insecure-skip-verify") tls.insecure_skip_verify = true;
        else {
            std::cerr << "Usage: " << argv[0]
                      << " [--backend URL] [--listen-port PORT] [--lapi-url URL] "
                         "[--lapi-token TOKEN] [--poll-interval SEC]\n"
                         "       [--lapi-ca-cert FILE] [--lapi-client-cert FILE] "
                         "[--lapi-client-key FILE] [--lapi-insecure-skip-verify]\n";
            return 1;
        }
    }

    if (lapi_token.empty()) {
        std::cerr << "[warn] LOCAL_API_TOKEN is not set; requests to Local API will be "
                     "unauthenticated and will fail unless local-api was also started "
                     "without a token.\n";
    }
    if (tls.client_cert.empty() != tls.client_key.empty()) {
        std::cerr << "[bouncer-proxy] --lapi-client-cert and --lapi-client-key must both be "
                     "set for mTLS, or both left unset.\n";
        return 1;
    }
    if (tls.insecure_skip_verify) {
        std::cerr << "[bouncer-proxy] [warn] --lapi-insecure-skip-verify is set - Local API's "
                     "TLS certificate will NOT be verified. Dev/lab use only.\n";
    }

    // Unlike bouncer-xdp (needs CAP_BPF/CAP_NET_ADMIN once) and bouncer-nft
    // (needs CAP_NET_ADMIN for its whole life), bouncer-proxy is a plain
    // userspace HTTP proxy: no BPF map, no netfilter rule, nothing that
    // needs any Linux capability at all. Dropping everything anyway is
    // zero-cost if there was nothing to drop, and proves that claim rather
    // than just asserting it - the same "don't assume, verify" spirit as
    // ADR-0006, and the clearest example yet of a bouncer that genuinely
    // needs no privilege to begin with.
    capdrop::drop_bounding_except({});
    capdrop::drop_all_capabilities("[bouncer-proxy]");

    struct sigaction sa{};
    sa.sa_handler = [](int) { g_running = 0; };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    // Fail static, not fail open (same principle ADR-0002/0004 state for
    // their own startup): block until the first decisions fetch succeeds,
    // so there is no window after startup where every request is let
    // through because the in-memory set simply hasn't been populated yet.
    // There is no persistent kernel object to "resume" against the way
    // bouncer-xdp/bouncer-nft do on restart - bouncer-proxy's entire
    // enforcement state is this one in-memory set, so "resume" and "cold
    // start" are the same thing: fetch once, synchronously, before
    // accepting any connection.
    {
        std::unordered_set<std::uint32_t> initial;
        if (!fetch_decisions(lapi_url, lapi_token, tls, initial)) {
            std::cerr << "[bouncer-proxy] could not reach Local API for an initial decision "
                         "fetch - refusing to start serving with an unknown baseline (every "
                         "request would otherwise pass through unblocked until the first poll "
                         "succeeds). Is local-api running and reachable at " << lapi_url << "?\n";
            return 1;
        }
        apply_decisions(initial);
        if (!initial.empty()) {
            std::cout << "[bouncer-proxy] starting with " << initial.size()
                      << " IP(s) already blocked\n";
        }
    }

    std::jthread poll_thread([&](std::stop_token st) {
        while (!st.stop_requested() && g_running) {
            for (int i = 0; i < poll_interval_s * 10 && g_running && !st.stop_requested(); ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            if (!g_running || st.stop_requested()) break;

            std::unordered_set<std::uint32_t> desired;
            if (fetch_decisions(lapi_url, lapi_token, tls, desired)) {
                apply_decisions(desired);
            }
            // On fetch failure: leave g_blocked untouched (fail static),
            // same as bouncer-xdp/bouncer-nft.
        }
    });

    httplib::Client backend_client(backend_url);
    backend_client.set_connection_timeout(5, 0);
    backend_client.set_read_timeout(10, 0);
    backend_client.set_keep_alive(true);

    httplib::Server svr;
    svr.set_pre_routing_handler([&](const httplib::Request& req, httplib::Response& res) {
        auto client_ip = parse_ipv4(req.remote_addr);
        if (client_ip && is_blocked(*client_ip)) {
            res.status = 403;
            res.set_content("Blocked by xdp-engine (bouncer-proxy)\n", "text/plain");
            return httplib::Server::HandlerResponse::Handled;
        }
        proxy_to_backend(backend_client, req, res);
        return httplib::Server::HandlerResponse::Handled;
    });

    std::cout << "[bouncer-proxy] listening on :" << listen_port << ", forwarding to "
              << backend_url << "\n";
    std::cout << "[bouncer-proxy] polling " << lapi_url << "/decisions every "
              << poll_interval_s << "s\n";

    std::jthread listen_thread([&] { svr.listen("0.0.0.0", listen_port); });
    while (g_running) std::this_thread::sleep_for(std::chrono::milliseconds(100));

    std::cout << "\n[bouncer-proxy] shutting down\n";
    svr.stop();
    poll_thread.request_stop();
    return 0;
}
