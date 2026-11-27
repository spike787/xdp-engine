// SPDX-License-Identifier: MIT
// bouncer_diff.h - pure decision-reconciliation logic for bouncer-xdp.
//
// Factored out of bouncer-xdp.cpp so it can be unit tested without a real
// BPF map or a running Local API: given what the kernel currently has
// blocked and what the Local API says should be blocked right now, this
// computes the minimal set of adds/removes to reconcile the two. See
// docs/adr/0002-bouncer-xdp-separation.md.
#ifndef BOUNCER_DIFF_H
#define BOUNCER_DIFF_H

#include <cstdint>
#include <unordered_set>
#include <vector>

struct DecisionDiff {
    std::vector<std::uint32_t> to_add;
    std::vector<std::uint32_t> to_remove;
};

inline DecisionDiff diff_decisions(const std::unordered_set<std::uint32_t>& currently_enforced,
                                    const std::unordered_set<std::uint32_t>& desired) {
    DecisionDiff d;
    d.to_add.reserve(desired.size());
    for (std::uint32_t ip : desired) {
        if (!currently_enforced.count(ip)) d.to_add.push_back(ip);
    }
    d.to_remove.reserve(currently_enforced.size());
    for (std::uint32_t ip : currently_enforced) {
        if (!desired.count(ip)) d.to_remove.push_back(ip);
    }
    return d;
}

#endif
