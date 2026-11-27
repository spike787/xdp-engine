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
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <cstdlib>
#include <iostream>
#include <string>

#include "storage.h"

namespace {

// Constant-time-ish compare to avoid the most obvious timing side channel
// on the bearer token check. Not a substitute for TLS/mTLS (see
// ROADMAP.md phase 3), but cheap to get right now.
bool tokens_match(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

std::string require_env(const char* name, const std::string& fallback) {
    const char* v = std::getenv(name);
    return v ? std::string(v) : fallback;
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

    Storage storage(db_path);
    httplib::Server svr;

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

    std::cout << "[local-api] listening on :" << port << " (db=" << db_path << ")\n";
    svr.listen("0.0.0.0", port);
    return 0;
}
