// SPDX-License-Identifier: MIT
// Unit tests for capdrop.h (ROADMAP.md Phase 3, ADR-0006).
//
// These tests deliberately do NOT assume the test process is root, has
// CAP_NET_ADMIN/CAP_BPF, or runs in any particular container privilege
// level - dropping capabilities down to a subset of what the process
// already holds always succeeds (capset() can only shrink or no-op here,
// never grant something new), so the assertions below hold whether this
// binary runs as full root (the common case for `make test` during local
// development) or as an unprivileged CI user. What's checked is the
// *shrinking* behavior and the bitmask/name-formatting logic, not any
// particular capability actually being present. See
// docs/adr/0006-capability-drop.md for how the underlying syscalls
// themselves were verified against a real running kernel.
#include <gtest/gtest.h>

#include "../capdrop.h"

// --- mask_from_caps (pure) -------------------------------------------------

TEST(CapdropTest, MaskFromCapsEmptyIsZero) {
    EXPECT_EQ(capdrop::mask_from_caps({}), 0u);
}

TEST(CapdropTest, MaskFromCapsSetsExactBits) {
    std::uint64_t mask = capdrop::mask_from_caps({CAP_NET_ADMIN, CAP_BPF});
    EXPECT_TRUE(mask & (std::uint64_t(1) << CAP_NET_ADMIN));
    EXPECT_TRUE(mask & (std::uint64_t(1) << CAP_BPF));
    // Nothing else should be set - exactly two bits.
    std::uint64_t only_two = (std::uint64_t(1) << CAP_NET_ADMIN) | (std::uint64_t(1) << CAP_BPF);
    EXPECT_EQ(mask, only_two);
}

TEST(CapdropTest, MaskFromCapsIgnoresOutOfRangeValues) {
    // -1 and anything past bit 63 must not corrupt the mask or crash.
    std::uint64_t mask = capdrop::mask_from_caps({-1, CAP_NET_ADMIN, 1000});
    EXPECT_EQ(mask, std::uint64_t(1) << CAP_NET_ADMIN);
}

// --- mask_to_names (pure) --------------------------------------------------

TEST(CapdropTest, MaskToNamesEmptyMaskSaysNone) {
    EXPECT_EQ(capdrop::mask_to_names(0), "(none)");
}

TEST(CapdropTest, MaskToNamesListsKnownCapabilities) {
    std::uint64_t mask = capdrop::mask_from_caps({CAP_NET_ADMIN});
    EXPECT_EQ(capdrop::mask_to_names(mask), "CAP_NET_ADMIN");
}

TEST(CapdropTest, MaskToNamesHandlesMultipleCapabilities) {
    std::uint64_t mask = capdrop::mask_from_caps({CAP_NET_ADMIN, CAP_BPF});
    std::string names = capdrop::mask_to_names(mask);
    EXPECT_NE(names.find("CAP_NET_ADMIN"), std::string::npos);
    EXPECT_NE(names.find("CAP_BPF"), std::string::npos);
}

// --- raw_capget / raw_capset round trip ------------------------------------

TEST(CapdropTest, CapgetSucceedsAndReturnsPlausibleSets) {
    std::uint64_t eff = 0, perm = 0, inh = 0;
    ASSERT_TRUE(capdrop::raw_capget(eff, perm, inh));
    // Can't assert any specific bit (depends on how the test runner is
    // invoked), but effective must always be a subset of permitted - that's
    // a kernel invariant, not an environment assumption.
    EXPECT_EQ(eff & ~perm, 0u);
}

// --- drop_capabilities_to: the real behavior that matters ------------------
//
// These two run before the "empty everything" test below on purpose: gtest
// executes TEST()s in source order within a binary, and once capabilities
// are dropped to nothing in this process there's no way to get them back
// to meaningfully re-exercise a nonzero `keep` set. Running the narrower
// drop first means that in a privileged test environment (this project's
// own sandbox verification was done as root - see ADR-0006) this test
// actually observes a real shrink from a fuller set down to the pair,
// rather than a vacuous zero-to-zero no-op; in an unprivileged environment
// (e.g. a contributor's non-root `make test`) the assertions still hold
// trivially, since an empty set is always a subset of `allowed`.

TEST(CapdropTest, DropCapabilitiesToIsSubsetOfRequested) {
    // Whatever this process started with, after asking to keep at most
    // {CAP_NET_ADMIN, CAP_BPF}, its effective set must never contain any
    // bit outside that pair - whether it actually had them to begin with
    // or not.
    ASSERT_TRUE(capdrop::drop_capabilities_to({CAP_NET_ADMIN, CAP_BPF}));
    std::uint64_t allowed = capdrop::mask_from_caps({CAP_NET_ADMIN, CAP_BPF});
    EXPECT_EQ(capdrop::current_effective_caps() & ~allowed, 0u);
}

TEST(CapdropTest, DropAllCapabilitiesEmptiesEffectiveSet) {
    ASSERT_TRUE(capdrop::drop_all_capabilities());
    EXPECT_EQ(capdrop::current_effective_caps(), 0u);
}

TEST(CapdropTest, DroppingIsOneWayWithinThisTestProcess) {
    // Once dropped to empty, asking to "keep" something again cannot regain
    // it (capset can only shrink the already-held permitted set, never grow
    // it) - this is the whole point of the feature: a later bug or compromise
    // in the same process can't un-ring this bell.
    ASSERT_TRUE(capdrop::drop_all_capabilities());
    ASSERT_EQ(capdrop::current_effective_caps(), 0u);
    capdrop::drop_capabilities_to({CAP_NET_ADMIN, CAP_BPF, CAP_SYS_ADMIN});
    EXPECT_EQ(capdrop::current_effective_caps(), 0u);
}
