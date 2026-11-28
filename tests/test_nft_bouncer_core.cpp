// SPDX-License-Identifier: MIT
// Unit tests for bouncer-nft's pure logic (ADR-0004): JSON parsing of
// `nft -j list ...` output and nft(8) script construction. None of this
// touches a real `nft` process, root, or the kernel's nftables state -
// it exercises nft_bouncer_core.h against canned JSON strings, the same
// way tests/test_bouncer_diff.cpp exercises bouncer-xdp's diff logic
// without a real BPF map.
#include <gtest/gtest.h>

#include "../nft_bouncer_core.h"

namespace {
std::uint32_t ip(const std::string& dotted) {
    std::uint32_t out;
    EXPECT_TRUE(ipv4_string_to_net(dotted, out));
    return out;
}
} // namespace

// --- ipv4_string_to_net / ipv4_net_to_string -----------------------------

TEST(NftBouncerCoreTest, Ipv4RoundTripsThroughNetworkOrder) {
    std::uint32_t net;
    ASSERT_TRUE(ipv4_string_to_net("203.0.113.9", net));
    EXPECT_EQ(ipv4_net_to_string(net), "203.0.113.9");
}

TEST(NftBouncerCoreTest, Ipv4StringToNetRejectsGarbage) {
    std::uint32_t net;
    EXPECT_FALSE(ipv4_string_to_net("not-an-ip", net));
    EXPECT_FALSE(ipv4_string_to_net("999.999.999.999", net));
    EXPECT_FALSE(ipv4_string_to_net("", net));
}

// --- parse_set_elements ---------------------------------------------------

TEST(NftBouncerCoreTest, ParsesPlainStringElements) {
    std::string json = R"({"nftables": [
        {"metainfo": {"version": "1.0.9"}},
        {"set": {"family": "inet", "name": "blocked_ips", "table": "xdp_engine",
                  "type": "ipv4_addr", "handle": 1,
                  "elem": ["203.0.113.9", "198.51.100.1"]}}
    ]})";
    std::unordered_set<std::uint32_t> out;
    ASSERT_TRUE(parse_set_elements(json, out));
    EXPECT_EQ(out, (std::unordered_set<std::uint32_t>{ip("203.0.113.9"), ip("198.51.100.1")}));
}

TEST(NftBouncerCoreTest, EmptySetHasNoElemKeyAtAllAndParsesAsEmpty) {
    // This is what nft actually prints for a set with zero elements - no
    // "elem" key, not an empty array.
    std::string json = R"({"nftables": [
        {"set": {"family": "inet", "name": "blocked_ips", "table": "xdp_engine",
                  "type": "ipv4_addr", "handle": 1}}
    ]})";
    std::unordered_set<std::uint32_t> out = {ip("1.2.3.4")}; // pre-seeded, must be cleared
    ASSERT_TRUE(parse_set_elements(json, out));
    EXPECT_TRUE(out.empty());
}

TEST(NftBouncerCoreTest, ParsesObjectFormElementsWithExtraState) {
    // The shape nft would use if an element carried a timeout/counter -
    // bouncer-nft doesn't add elements this way itself, but should still
    // read them correctly if something else populated the set.
    std::string json = R"({"nftables": [
        {"set": {"family": "inet", "name": "blocked_ips", "table": "xdp_engine",
                  "type": "ipv4_addr", "handle": 1,
                  "elem": [{"elem": {"val": "203.0.113.9", "timeout": 600}}]}}
    ]})";
    std::unordered_set<std::uint32_t> out;
    ASSERT_TRUE(parse_set_elements(json, out));
    EXPECT_EQ(out, (std::unordered_set<std::uint32_t>{ip("203.0.113.9")}));
}

TEST(NftBouncerCoreTest, MalformedJsonReturnsFalse) {
    std::unordered_set<std::uint32_t> out;
    EXPECT_FALSE(parse_set_elements("not json at all", out));
}

TEST(NftBouncerCoreTest, NftErrorOutputHasNoSetKeyAndReturnsFalse) {
    // What `nft -j list set ...` prints when the table/set doesn't exist
    // yet - valid JSON, but with no "set" object in it at all. Must be
    // told apart from a genuinely empty set (see the comment on
    // parse_set_elements in nft_bouncer_core.h for why that distinction
    // matters to the caller).
    std::string json = R"({"nftables": [{"metainfo": {"version": "1.0.9"}}]})";
    std::unordered_set<std::uint32_t> out;
    EXPECT_FALSE(parse_set_elements(json, out));
}

// --- chain_has_rule_comment -----------------------------------------------

TEST(NftBouncerCoreTest, FindsExistingRuleByComment) {
    std::string json = R"({"nftables": [
        {"chain": {"family": "inet", "table": "xdp_engine", "name": "input", "handle": 2}},
        {"rule": {"family": "inet", "table": "xdp_engine", "chain": "input", "handle": 3,
                   "comment": "xdp-engine-bouncer-nft",
                   "expr": [{"match": {}}, {"drop": null}]}}
    ]})";
    EXPECT_TRUE(chain_has_rule_comment(json, "xdp-engine-bouncer-nft"));
}

TEST(NftBouncerCoreTest, FreshChainWithNoRulesReturnsFalse) {
    std::string json = R"({"nftables": [
        {"chain": {"family": "inet", "table": "xdp_engine", "name": "input", "handle": 2}}
    ]})";
    EXPECT_FALSE(chain_has_rule_comment(json, "xdp-engine-bouncer-nft"));
}

TEST(NftBouncerCoreTest, DifferentCommentDoesNotMatch) {
    std::string json = R"({"nftables": [
        {"rule": {"family": "inet", "table": "xdp_engine", "chain": "input", "handle": 3,
                   "comment": "some-other-rule"}}
    ]})";
    EXPECT_FALSE(chain_has_rule_comment(json, "xdp-engine-bouncer-nft"));
}

// --- build_diff_script -----------------------------------------------------

TEST(NftBouncerCoreTest, EmptyDiffProducesEmptyScript) {
    EXPECT_EQ(build_diff_script("xdp_engine", "blocked_ips", DecisionDiff{}), "");
}

TEST(NftBouncerCoreTest, AddsUseAddElementAndRemovesUseDestroyElement) {
    DecisionDiff diff;
    diff.to_add = {ip("203.0.113.9")};
    diff.to_remove = {ip("198.51.100.1")};

    std::string script = build_diff_script("xdp_engine", "blocked_ips", diff);

    EXPECT_NE(script.find("add element inet xdp_engine blocked_ips { 203.0.113.9 }"), std::string::npos);
    EXPECT_NE(script.find("destroy element inet xdp_engine blocked_ips { 198.51.100.1 }"), std::string::npos);
    // destroy, not delete - a stale removal must not abort the whole
    // transaction (see nft_bouncer_core.h's comment on build_diff_script).
    EXPECT_EQ(script.find("delete element"), std::string::npos);
}

// --- build_setup_script / build_rule_script --------------------------------

TEST(NftBouncerCoreTest, SetupScriptOnlyUsesIdempotentAddVerb) {
    std::string script = build_setup_script("xdp_engine", "blocked_ips", "input");
    EXPECT_NE(script.find("add table inet xdp_engine"), std::string::npos);
    EXPECT_NE(script.find("add set inet xdp_engine blocked_ips"), std::string::npos);
    EXPECT_NE(script.find("add chain inet xdp_engine input"), std::string::npos);
    EXPECT_NE(script.find("type ipv4_addr"), std::string::npos);
    EXPECT_NE(script.find("hook input"), std::string::npos);
}

TEST(NftBouncerCoreTest, RuleScriptWithIfaceAddsIifnameMatch) {
    std::string script = build_rule_script("xdp_engine", "blocked_ips", "input", "eth0",
                                            "xdp-engine-bouncer-nft");
    EXPECT_NE(script.find("iifname \"eth0\""), std::string::npos);
    EXPECT_NE(script.find("ip saddr @blocked_ips drop"), std::string::npos);
    EXPECT_NE(script.find("comment \"xdp-engine-bouncer-nft\""), std::string::npos);
}

TEST(NftBouncerCoreTest, RuleScriptWithoutIfaceOmitsIifnameMatch) {
    std::string script = build_rule_script("xdp_engine", "blocked_ips", "input", "",
                                            "xdp-engine-bouncer-nft");
    EXPECT_EQ(script.find("iifname"), std::string::npos);
    EXPECT_NE(script.find("ip saddr @blocked_ips drop"), std::string::npos);
}
