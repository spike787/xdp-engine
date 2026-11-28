// SPDX-License-Identifier: MIT
// nft_bouncer_core.h - pure, nft/root-independent logic for bouncer-nft
// (ADR-0004). Everything here is string/JSON in, string/set out; the
// actual `nft` subprocess invocation lives in bouncer_nft.cpp, which is
// the only part of this bouncer that needs root and a real
// nftables-capable kernel. Mirrors bouncer_diff.h's role for bouncer-xdp:
// factored out so it's unit-testable without either.
#ifndef NFT_BOUNCER_CORE_H
#define NFT_BOUNCER_CORE_H

#include <arpa/inet.h>

#include <cstdint>
#include <sstream>
#include <string>
#include <unordered_set>

#include <nlohmann/json.hpp>

#include "bouncer_diff.h"

// Fixed table/set/chain names bouncer-nft owns - not user-configurable,
// same as bouncer-xdp hardcoding XDP_ENGINE_PIN_DIR rather than taking a
// --pin-dir flag. One bouncer-nft instance per host is the supported
// shape (see ADR-0004's "Consequences" on running both bouncers at once).
constexpr const char* NFT_TABLE = "xdp_engine";
constexpr const char* NFT_SET = "blocked_ips";
constexpr const char* NFT_CHAIN = "input";
// Tags the one enforcement rule this bouncer owns, so setup can tell "no
// rule yet" apart from "rule already added by an earlier run" without
// `nft add rule` doing that check for us (unlike add table/set/chain,
// which are themselves idempotent - confirmed against nftables 1.0.9).
constexpr const char* NFT_RULE_COMMENT = "xdp-engine-bouncer-nft";

inline bool ipv4_string_to_net(const std::string& text, std::uint32_t& out) {
    in_addr addr{};
    if (inet_pton(AF_INET, text.c_str(), &addr) != 1) return false;
    out = addr.s_addr;
    return true;
}

inline std::string ipv4_net_to_string(std::uint32_t ip_net) {
    char buf[INET_ADDRSTRLEN]{};
    in_addr addr{.s_addr = ip_net};
    inet_ntop(AF_INET, &addr, buf, sizeof buf);
    return buf;
}

// Parses the JSON printed by `nft -j list set inet <table> <set>` into
// the set of IPv4 addresses it currently holds (network byte order,
// matching bouncer_diff.h's representation). Tolerates both the plain-
// string element form nft prints for a bare set (`"elem": ["1.2.3.4"]`)
// and the object form it would print if an element ever carried extra
// state such as a timeout (`"elem": [{"elem": {"val": "1.2.3.4", ...}}]`)
// - bouncer-nft doesn't use element timeouts (see ADR-0004) but parsing
// defensively here costs nothing and avoids a silent misread if that
// ever changes.
//
// Returns false (leaving `out` untouched) if the JSON doesn't look like
// a set listing at all - e.g. `nft` printing an error because the table/
// set doesn't exist yet. The caller should treat that as "unknown kernel
// state", not as "the set is confirmed empty"; see bouncer_nft.cpp's
// resume logic for why that distinction matters.
inline bool parse_set_elements(const std::string& nft_json, std::unordered_set<std::uint32_t>& out) {
    nlohmann::json root;
    try {
        root = nlohmann::json::parse(nft_json);
    } catch (const std::exception&) {
        return false;
    }
    if (!root.is_object() || !root.contains("nftables") || !root["nftables"].is_array()) return false;

    for (const auto& item : root["nftables"]) {
        if (!item.is_object() || !item.contains("set")) continue;
        const auto& set_obj = item["set"];

        if (!set_obj.contains("elem") || !set_obj["elem"].is_array()) {
            // A set with zero elements has no "elem" key at all in nft's
            // JSON output - that's a valid empty result, not a parse
            // failure.
            out.clear();
            return true;
        }

        std::unordered_set<std::uint32_t> result;
        for (const auto& e : set_obj["elem"]) {
            std::string ip_str;
            if (e.is_string()) {
                ip_str = e.get<std::string>();
            } else if (e.is_object() && e.contains("elem") && e["elem"].is_object()) {
                const auto& inner = e["elem"];
                if (inner.contains("val") && inner["val"].is_string()) {
                    ip_str = inner["val"].get<std::string>();
                }
            }
            std::uint32_t ip_net;
            if (!ip_str.empty() && ipv4_string_to_net(ip_str, ip_net)) {
                result.insert(ip_net);
            }
        }
        out = std::move(result);
        return true;
    }
    return false; // no "set" object anywhere in the listing
}

// Parses the JSON printed by `nft -j list chain inet <table> <chain>`
// and reports whether any rule in it already carries `comment`. See
// NFT_RULE_COMMENT's doc comment for why this check exists at all.
inline bool chain_has_rule_comment(const std::string& nft_json, const std::string& comment) {
    nlohmann::json root;
    try {
        root = nlohmann::json::parse(nft_json);
    } catch (const std::exception&) {
        return false;
    }
    if (!root.is_object() || !root.contains("nftables") || !root["nftables"].is_array()) return false;

    for (const auto& item : root["nftables"]) {
        if (!item.is_object() || !item.contains("rule")) continue;
        const auto& rule_obj = item["rule"];
        if (rule_obj.contains("comment") && rule_obj["comment"].is_string() &&
            rule_obj["comment"].get<std::string>() == comment) {
            return true;
        }
    }
    return false;
}

// Builds a single nft(8) script (fed to `nft -f -`) that applies `diff`
// as one atomic transaction against the named table/set: nftables aborts
// the *entire* script if any one line fails rather than partially
// applying it (confirmed against nftables 1.0.9), so a script mixing
// adds and removes either all lands or none does.
//
// Removals use `destroy element`, nft's idempotent-delete verb (a no-op
// if the element is already gone), rather than `delete element` (which
// errors on a missing element) - specifically so a single stale removal
// can't abort an otherwise-valid batch of adds in the same poll cycle.
// Additions use plain `add element`, itself a no-op on a duplicate, for
// the same reason.
//
// Returns an empty string if there's nothing to do, so the caller can
// skip the subprocess entirely on a no-op poll.
inline std::string build_diff_script(const std::string& table, const std::string& set_name,
                                      const DecisionDiff& diff) {
    if (diff.to_add.empty() && diff.to_remove.empty()) return "";

    std::ostringstream script;
    for (std::uint32_t ip : diff.to_add) {
        script << "add element inet " << table << " " << set_name
               << " { " << ipv4_net_to_string(ip) << " }\n";
    }
    for (std::uint32_t ip : diff.to_remove) {
        script << "destroy element inet " << table << " " << set_name
               << " { " << ipv4_net_to_string(ip) << " }\n";
    }
    return script.str();
}

// Builds the one-time (but safe-to-repeat) nft(8) script that creates
// the table/set/chain, all via the idempotent `add` verb. Does NOT add
// the enforcement rule - that needs the has-existing-rule check first
// (chain_has_rule_comment), which needs a live `nft -j list chain` call
// bouncer_nft.cpp makes between running this and build_rule_script().
inline std::string build_setup_script(const std::string& table, const std::string& set_name,
                                       const std::string& chain) {
    std::ostringstream script;
    script << "add table inet " << table << "\n";
    script << "add set inet " << table << " " << set_name << " { type ipv4_addr; }\n";
    script << "add chain inet " << table << " " << chain
           << " { type filter hook input priority 0; policy accept; }\n";
    return script.str();
}

// Builds the (at-most-once-per-process-lifetime, guarded by the caller
// checking chain_has_rule_comment first) script that adds the actual
// drop rule. `iface`, if non-empty, scopes the rule to that interface
// with `iifname "<iface>"` ahead of the address match; left empty, the
// rule applies regardless of interface (see ADR-0004 for why that's the
// default here, unlike bouncer-xdp which has no "all interfaces" mode).
inline std::string build_rule_script(const std::string& table, const std::string& set_name,
                                      const std::string& chain, const std::string& iface,
                                      const std::string& comment) {
    std::ostringstream script;
    script << "add rule inet " << table << " " << chain << " ";
    if (!iface.empty()) {
        script << "iifname \"" << iface << "\" ";
    }
    script << "ip saddr @" << set_name << " drop comment \"" << comment << "\"\n";
    return script.str();
}

#endif // NFT_BOUNCER_CORE_H
