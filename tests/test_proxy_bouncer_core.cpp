// SPDX-License-Identifier: MIT
// Unit tests for bouncer-proxy's pure logic (ADR-0010): which headers get
// stripped when relaying a request/response between client and backend.
// None of this touches a real socket, a real backend, or a running Local
// API - it exercises proxy_bouncer_core.h directly, the same way
// tests/test_bouncer_diff.cpp and tests/test_nft_bouncer_core.cpp do for
// the other two bouncers' pure logic.
#include <gtest/gtest.h>

#include "../proxy_bouncer_core.h"

TEST(ProxyBouncerCoreTest, StripsEveryStandardHopByHopHeader) {
    for (const char* h : {"Connection", "Keep-Alive", "Proxy-Authenticate",
                          "Proxy-Authorization", "TE", "Trailer",
                          "Transfer-Encoding", "Upgrade", "Content-Length"}) {
        EXPECT_TRUE(is_hop_by_hop_header(h)) << h;
    }
}

TEST(ProxyBouncerCoreTest, MatchIsCaseInsensitive) {
    EXPECT_TRUE(is_hop_by_hop_header("connection"));
    EXPECT_TRUE(is_hop_by_hop_header("CONNECTION"));
    EXPECT_TRUE(is_hop_by_hop_header("CoNnEcTiOn"));
    EXPECT_TRUE(is_hop_by_hop_header("content-length"));
    EXPECT_TRUE(is_hop_by_hop_header("TRANSFER-ENCODING"));
}

TEST(ProxyBouncerCoreTest, PassesThroughOrdinaryHeaders) {
    for (const char* h : {"Host", "User-Agent", "Accept", "Content-Type",
                          "Authorization", "Cookie", "X-Forwarded-For",
                          "Referer", "Accept-Encoding"}) {
        EXPECT_FALSE(is_hop_by_hop_header(h)) << h;
    }
}

// A field name that merely contains a hop-by-hop name as a substring (e.g.
// a hypothetical "X-Connection-Id") must not match - this is an exact
// field-name comparison, not a substring search.
TEST(ProxyBouncerCoreTest, DoesNotMatchOnSubstring) {
    EXPECT_FALSE(is_hop_by_hop_header("X-Connection-Id"));
    EXPECT_FALSE(is_hop_by_hop_header("Connections"));
    EXPECT_FALSE(is_hop_by_hop_header(""));
}
