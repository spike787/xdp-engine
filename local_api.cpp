// SPDX-License-Identifier: MIT
// Local API: the shared control plane described in ROADMAP.md phase 1.
//
// Bouncers (currently: bouncer-xdp, see docs/adr/0002-bouncer-xdp-separation.md;
// later: standalone nftables/proxy bouncers) poll GET /decisions to learn
// which IPs to block. GET /export gives the evidence/forensics dump
// requested alongside it: alerts and raw events as CSV or JSON.
//
// This binary opens the SAME SQLite file the agent writes to (WAL mode,
// safe for concurrent readers) rather than owning its own copy of the
// data, so it can run on the same host as the agent today and, once the
// storage layer gains a networked backend, on a separate host later
// without changing this file's logic.
//
// TLS/mTLS (ADR-0012): optional, off by default so existing plaintext
// deployments keep working unchanged. Set LOCAL_API_TLS_CERT/_KEY to turn
// on TLS; additionally set LOCAL_API_TLS_CLIENT_CA to require and verify
// a client certificate from every caller (mTLS) on top of the existing
// bearer-token check, not instead of it - the two are independent layers
// (a stolen token alone, or a stolen cert alone, still isn't enough).
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>

#include "storage.h"

namespace {

// Constant-time-ish compare to avoid the most obvious timing side channel
// on the bearer token check. TLS/mTLS (see the file header above and
// ADR-0012) is the independent, separate control for the connection
// itself; this is just about the token comparison not leaking its own
// length/content via timing.
//
// Deliberately does NOT short-circuit on a.size() != b.size(): an early
// return there would still run in time proportional to whether the
// lengths matched, letting a remote attacker binary-search the real
// token's length (by timing requests with Authorization headers of
// different lengths) before attacking its content. Instead, the length
// mismatch is folded into the same accumulator as the byte comparison,
// and the loop always runs max(a.size(), b.size()) iterations.
bool tokens_match(const std::string& a, const std::string& b) {
    unsigned char diff = static_cast<unsigned char>(a.size() != b.size());
    size_t n = a.size() > b.size() ? a.size() : b.size();
    for (size_t i = 0; i < n; ++i) {
        unsigned char ca = i < a.size() ? static_cast<unsigned char>(a[i]) : 0;
        unsigned char cb = i < b.size() ? static_cast<unsigned char>(b[i]) : 0;
        diff |= ca ^ cb;
    }
    return diff == 0;
}

std::string require_env(const char* name, const std::string& fallback) {
    const char* v = std::getenv(name);
    return v ? std::string(v) : fallback;
}

bool file_readable(const std::string& path) {
    if (path.empty()) return false;
    std::ifstream f(path);
    return f.good();
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <path-to-engine.db> [port]\n";
        return 1;
    }
    const std::string db_path = argv[1];
    const int port = argc >= 3 ? std::stoi(argv[2]) : 8088;

    const std::string token = require_env("LOCAL_API_TOKEN", "");
    if (token.empty()) {
        std::cerr << "[warn] LOCAL_API_TOKEN is not set; the API is unauthenticated. "
                     "Set it before exposing this beyond localhost.\n";
    }

    // TLS (ADR-0012): both cert and key must be given together, or neither.
    // A single one set is almost certainly a typo'd env var, not an
    // intentional half-configuration, so this fails loudly at startup
    // rather than silently falling back to plaintext.
    const std::string tls_cert = require_env("LOCAL_API_TLS_CERT", "");
    const std::string tls_key = require_env("LOCAL_API_TLS_KEY", "");
    const std::string tls_client_ca = require_env("LOCAL_API_TLS_CLIENT_CA", "");
    if (tls_cert.empty() != tls_key.empty()) {
        std::cerr << "[local-api] LOCAL_API_TLS_CERT and LOCAL_API_TLS_KEY must both be set "
                     "to enable TLS, or both left unset to run plaintext. Only one was given.\n";
        return 1;
    }
    const bool tls_enabled = !tls_cert.empty();
    if (!tls_enabled && !tls_client_ca.empty()) {
        std::cerr << "[local-api] LOCAL_API_TLS_CLIENT_CA was set without LOCAL_API_TLS_CERT/"
                     "_KEY - mTLS needs TLS itself enabled first.\n";
        return 1;
    }
    if (tls_enabled && (!file_readable(tls_cert) || !file_readable(tls_key))) {
        std::cerr << "[local-api] could not read LOCAL_API_TLS_CERT (" << tls_cert
                  << ") or LOCAL_API_TLS_KEY (" << tls_key << ")\n";
        return 1;
    }
    if (!tls_client_ca.empty() && !file_readable(tls_client_ca)) {
        std::cerr << "[local-api] could not read LOCAL_API_TLS_CLIENT_CA (" << tls_client_ca << ")\n";
        return 1;
    }

    Storage storage(db_path);

    // A plain httplib::Server when TLS is off (unchanged default behavior
    // for every existing deployment); an SSLServer, constructed through the
    // same base-class pointer, when it's on. If LOCAL_API_TLS_CLIENT_CA is
    // also set, passing it as SSLServer's third constructor argument makes
    // cpp-httplib require *and verify* a client certificate against that CA
    // on every connection (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
    // under the hood) - a handshake with no cert, or a cert signed by some
    // other CA, is rejected before any request handler (including the
    // bearer-token check below) ever runs.
    std::unique_ptr<httplib::Server> svr_owner;
    if (tls_enabled) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        auto* ssl_svr = new httplib::SSLServer(
            tls_cert.c_str(), tls_key.c_str(),
            tls_client_ca.empty() ? nullptr : tls_client_ca.c_str());
        if (!ssl_svr->is_valid()) {
            std::cerr << "[local-api] failed to initialize TLS - check that "
                         "LOCAL_API_TLS_CERT/_KEY (and _CLIENT_CA, if set) are valid PEM files\n";
            delete ssl_svr;
            return 1;
        }
        svr_owner.reset(ssl_svr);
#else
        std::cerr << "[local-api] built without CPPHTTPLIB_OPENSSL_SUPPORT - cannot enable "
                     "TLS. Rebuild against a cpp-httplib with OpenSSL support.\n";
        return 1;
#endif
    } else {
        svr_owner = std::make_unique<httplib::Server>();
    }
    httplib::Server& svr = *svr_owner;

    auto check_auth = [&](const httplib::Request& req, httplib::Response& res) -> bool {
        if (token.empty()) return true; // explicitly opted out above
        auto it = req.headers.find("Authorization");
        const std::string expected = "Bearer " + token;
        if (it == req.headers.end() || !tokens_match(it->second, expected)) {
            res.status = 401;
            res.set_content(R"({"error":"unauthorized"})", "application/json");
            return false;
        }
        return true;
    };

    svr.Get("/healthz", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(R"({"status":"ok"})", "application/json");
    });

    svr.Get("/decisions", [&](const httplib::Request& req, httplib::Response& res) {
        if (!check_auth(req, res)) return;
        auto decisions = storage.get_active_decisions();
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& d : decisions) {
            arr.push_back({
                {"ip", d.ip},
                {"action", d.action},
                {"reason", d.reason},
                {"rule", d.rule},
                {"expires_at_unix", d.expires_at_unix},
                {"ttl_seconds", d.ttl_seconds},
                {"host", d.host},
            });
        }
        res.set_content(arr.dump(), "application/json");
    });

    svr.Get("/export", [&](const httplib::Request& req, httplib::Response& res) {
        if (!check_auth(req, res)) return;
        const std::string type = req.has_param("type") ? req.get_param_value("type") : "alerts";
        const std::string format = req.has_param("format") ? req.get_param_value("format") : "json";
        const std::string since = req.has_param("since") ? req.get_param_value("since") : "";
        const std::string until = req.has_param("until") ? req.get_param_value("until") : "";

        if (format != "csv" && format != "json") {
            res.status = 400;
            res.set_content(R"({"error":"format must be csv or json"})", "application/json");
            return;
        }

        std::string body;
        if (type == "alerts") {
            body = storage.export_alerts(format, since, until);
        } else if (type == "events") {
            body = storage.export_events(format, since, until);
        } else {
            res.status = 400;
            res.set_content(R"({"error":"type must be alerts or events"})", "application/json");
            return;
        }

        const std::string content_type = (format == "csv") ? "text/csv" : "application/json";
        res.set_header("Content-Disposition", "attachment; filename=\"" + type + "." + format + "\"");
        res.set_content(body, content_type);
    });

    // ROADMAP.md phase 3: Prometheus metrics. Auth-gated the same as
    // /decisions and /export - a scrape config authenticates with
    // `authorization: {credentials: "<token>"}`, the standard way
    // Prometheus sends a static bearer token.
    svr.Get("/metrics", [&](const httplib::Request& req, httplib::Response& res) {
        if (!check_auth(req, res)) return;
        auto summary = storage.get_metrics_summary();
        res.set_content(format_prometheus_metrics(summary), "text/plain; version=0.0.4; charset=utf-8");
    });

    std::cout << "[local-api] listening on :" << port << " (db=" << db_path << ", tls="
              << (tls_enabled ? (tls_client_ca.empty() ? "server-only" : "mutual") : "off")
              << ")\n";
    svr.listen("0.0.0.0", port);
    return 0;
}
