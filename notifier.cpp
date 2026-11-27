// SPDX-License-Identifier: MIT
#include "notifier.h"
#include <cstdlib>
#include <iostream>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

Notifier::Notifier() {
    const char* env_url = std::getenv("NOTIFY_WEBHOOK_URL");
    if (env_url) {
        webhook_url_ = env_url;
        worker_ = std::jthread{[this](std::stop_token st) { worker_loop(st); }};
    }
}

Notifier::~Notifier() {
    // Notify the worker to wake up and stop
    if (worker_.joinable()) {
        worker_.request_stop();
        cv_.notify_one();
    }
}

void Notifier::notify(const Alert& alert) {
    // Console notifier always on
    std::cout << "[NOTIFY] Alert triggered: Rule=" << alert.rule 
              << ", IP=" << alert.src_ip 
              << ", Severity=" << alert.severity 
              << ", BlockDuration=" << alert.block_seconds << "s\n";

    if (webhook_url_.empty()) {
        return;
    }

    // Build message safely using validated fields
    std::string text = "Intrusion Alert: " + alert.rule + 
                       " triggered by IP " + alert.src_ip + 
                       " (Severity: " + alert.severity + "). " +
                       "Action: block for " + std::to_string(alert.block_seconds) + " seconds.";
                       
    // Simple JSON payload for typical webhooks (Slack/Mattermost format).
    // Built with nlohmann::json rather than raw string concatenation so
    // quotes/backslashes/control characters in `text` are escaped
    // correctly - today every field going into `text` is validated
    // (rule/severity/mitre come from rules.yaml, src_ip is IPv4-checked),
    // but hand-rolled "{\"text\": \"" + text + "\"}"-style concatenation
    // is fragile against any future field that isn't similarly validated.
    std::string payload = nlohmann::json{{"text", text}}.dump();

    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(payload);
    }
    cv_.notify_one();
}

void Notifier::worker_loop(std::stop_token st) {
    CURL* curl = curl_easy_init();
    if (!curl) return;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    while (!st.stop_requested()) {
        std::string payload;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, st, [this] { return !queue_.empty(); });
            if (st.stop_requested() && queue_.empty()) break;
            if (!queue_.empty()) {
                payload = queue_.front();
                queue_.pop();
            }
        }

        if (payload.empty()) continue;

        curl_easy_setopt(curl, CURLOPT_URL, webhook_url_.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L); // 5s timeout

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "[error] Webhook failed: " << curl_easy_strerror(res) << "\n";
        }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}
