// Unit tests for bouncer-xdp's decision-reconciliation logic. These touch
// no BPF syscalls and no network - bouncer_diff.h is pure by design so this
// can run in regular CI alongside the rest of the suite.
#include <gtest/gtest.h>

#include "../bouncer_diff.h"

namespace {
std::unordered_set<std::uint32_t> to_set(std::vector<std::uint32_t> v) {
    return std::unordered_set<std::uint32_t>(v.begin(), v.end());
}
} // namespace

TEST(BouncerDiffTest, NothingEnforcedYetAddsEverythingDesired) {
    auto diff = diff_decisions(/*currently_enforced=*/{}, to_set({1, 2, 3}));
    std::unordered_set<std::uint32_t> added(diff.to_add.begin(), diff.to_add.end());
    EXPECT_EQ(added, to_set({1, 2, 3}));
    EXPECT_TRUE(diff.to_remove.empty());
}

TEST(BouncerDiffTest, NothingDesiredRemovesEverythingEnforced) {
    auto diff = diff_decisions(to_set({1, 2, 3}), /*desired=*/{});
    std::unordered_set<std::uint32_t> removed(diff.to_remove.begin(), diff.to_remove.end());
    EXPECT_EQ(removed, to_set({1, 2, 3}));
    EXPECT_TRUE(diff.to_add.empty());
}

TEST(BouncerDiffTest, AlreadyEnforcedAndStillDesiredIsNoOp) {
    auto diff = diff_decisions(to_set({1, 2}), to_set({1, 2}));
    EXPECT_TRUE(diff.to_add.empty());
    EXPECT_TRUE(diff.to_remove.empty());
}

TEST(BouncerDiffTest, MixedAddAndRemove) {
    // 1 stays blocked, 2 expired/unblocked, 3 is newly decided.
    auto diff = diff_decisions(to_set({1, 2}), to_set({1, 3}));
    std::unordered_set<std::uint32_t> added(diff.to_add.begin(), diff.to_add.end());
    std::unordered_set<std::uint32_t> removed(diff.to_remove.begin(), diff.to_remove.end());
    EXPECT_EQ(added, to_set({3}));
    EXPECT_EQ(removed, to_set({2}));
}
