// capdrop.h - minimal Linux capability-drop helper (ROADMAP.md Phase 3).
//
// Every long-running binary in this project (engine, bouncer-xdp, bouncer-nft)
// has historically been documented as "run with sudo" (see README's old
// Privileges section). In practice each of them only needs root for a brief
// privileged step, if at all - see docs/adr/0006-capability-drop.md for the
// full writeup and the empirical sandbox testing behind these claims. This
// header lets each binary voluntarily shed every capability it isn't using,
// right after any privileged step is done, rather than running with a full
// root capability set (or full root DAC power) for its entire lifetime.
//
// Deliberately dependency-free: no libcap (this project avoids pulling in a
// new library the same way bouncer-nft shells out to `nft` instead of linking
// libnftables - see ADR-0004). <linux/capability.h> (kernel headers, already
// a prerequisite for the libbpf build) has every constant we need; capset()/
// capget() have no glibc wrapper, so we call them directly via syscall(2).
//
// Pure logic (building the bitmask from a capability list, intersecting it
// with what the process actually holds) is separated from the two syscalls
// themselves so tests/test_capdrop.cpp can exercise it without needing any
// particular privilege level to produce a meaningful result - dropping
// capabilities down to a subset of what you already have always succeeds,
// whether that process started as root or not.
#pragma once

#include <cstdint>
#include <cstdio>
#include <initializer_list>
#include <string>
#include <vector>

#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace capdrop {

// --- pure logic ------------------------------------------------------------

// Builds a 64-bit mask (one bit per capability number, same numbering as
// <linux/capability.h>'s CAP_* constants) from a list of capabilities.
inline std::uint64_t mask_from_caps(std::initializer_list<int> caps) {
    std::uint64_t mask = 0;
    for (int cap : caps) {
        if (cap >= 0 && cap <= 63) mask |= (std::uint64_t(1) << cap);
    }
    return mask;
}

inline std::string mask_to_names(std::uint64_t mask) {
    static const struct { int cap; const char* name; } kKnown[] = {
        {CAP_NET_ADMIN, "CAP_NET_ADMIN"}, {CAP_BPF, "CAP_BPF"},
        {CAP_SETUID, "CAP_SETUID"},       {CAP_SETGID, "CAP_SETGID"},
        {CAP_SETPCAP, "CAP_SETPCAP"},     {CAP_SYS_ADMIN, "CAP_SYS_ADMIN"},
        {CAP_NET_RAW, "CAP_NET_RAW"},     {CAP_DAC_OVERRIDE, "CAP_DAC_OVERRIDE"},
    };
    if (mask == 0) return "(none)";
    std::string out;
    for (auto& k : kKnown) {
        if (mask & (std::uint64_t(1) << k.cap)) {
            if (!out.empty()) out += ", ";
            out += k.name;
        }
    }
    if (out.empty()) return "(unnamed bits: " + std::to_string(mask) + ")";
    return out;
}

// --- raw syscalls (capset/capget have no glibc wrapper) --------------------

struct RawCapHeader { std::uint32_t version; int pid; };
struct RawCapData { std::uint32_t effective, permitted, inheritable; };

// capget() always targets this process (pid 0 is self when combined with
// _LINUX_CAPABILITY_VERSION_3, same as libcap's cap_get_proc()).
inline bool raw_capget(std::uint64_t& effective, std::uint64_t& permitted,
                       std::uint64_t& inheritable) {
    RawCapHeader hdr{_LINUX_CAPABILITY_VERSION_3, 0};
    RawCapData data[2] = {};
    if (syscall(SYS_capget, &hdr, data) != 0) return false;
    effective = (std::uint64_t(data[1].effective) << 32) | data[0].effective;
    permitted = (std::uint64_t(data[1].permitted) << 32) | data[0].permitted;
    inheritable = (std::uint64_t(data[1].inheritable) << 32) | data[0].inheritable;
    return true;
}

inline bool raw_capset(std::uint64_t effective, std::uint64_t permitted,
                       std::uint64_t inheritable) {
    RawCapHeader hdr{_LINUX_CAPABILITY_VERSION_3, 0};
    RawCapData data[2] = {};
    data[0].effective = static_cast<std::uint32_t>(effective);
    data[1].effective = static_cast<std::uint32_t>(effective >> 32);
    data[0].permitted = static_cast<std::uint32_t>(permitted);
    data[1].permitted = static_cast<std::uint32_t>(permitted >> 32);
    data[0].inheritable = static_cast<std::uint32_t>(inheritable);
    data[1].inheritable = static_cast<std::uint32_t>(inheritable >> 32);
    return syscall(SYS_capset, &hdr, data) == 0;
}

// --- public API --------------------------------------------------------

// Returns this process's current effective capability set, or 0 on failure
// (capget() failing at all is itself unusual and treated as "nothing held").
inline std::uint64_t current_effective_caps() {
    std::uint64_t eff = 0, perm = 0, inh = 0;
    if (!raw_capget(eff, perm, inh)) return 0;
    return eff;
}

// Shrinks effective+permitted+inheritable down to at most `keep` - never
// more than what the process already holds, so this is safe to call
// unconditionally regardless of current privilege (already non-root with
// none of `keep`? this is a no-op; full root with everything? this drops
// down to exactly `keep`). Returns false only if the capset() syscall
// itself failed, which per capabilities(7) should not happen when only
// shrinking - that would indicate something has gone unexpectedly wrong,
// not that a caller asked for a capability it doesn't have.
inline bool drop_capabilities_to(std::initializer_list<int> keep,
                                 const char* log_prefix = nullptr) {
    std::uint64_t eff = 0, perm = 0, inh = 0;
    if (!raw_capget(eff, perm, inh)) {
        if (log_prefix) std::fprintf(stderr, "%s capget failed, assuming no capabilities held\n", log_prefix);
        return true; // nothing to drop; also nothing we could have kept anyway
    }
    std::uint64_t want = mask_from_caps(keep) & perm; // never request what we don't hold
    bool ok = raw_capset(want, want, want);
    if (log_prefix) {
        std::fprintf(stderr, "%s capabilities now: %s\n", log_prefix, mask_to_names(ok ? want : eff).c_str());
    }
    return ok;
}

inline bool drop_all_capabilities(const char* log_prefix = nullptr) {
    return drop_capabilities_to({}, log_prefix);
}

// Pushes `cap` into the ambient set so a later execve() of a plain (non-file-
// capability, non-setuid) binary - e.g. bouncer-nft execing `nft` - inherits
// exactly that one capability, regardless of the child's own uid and
// regardless of whether this process is still uid 0. Requires `cap` to
// already be in both the permitted and inheritable sets (drop_capabilities_to
// with `cap` in `keep` leaves both set, since it sets all three together).
// See docs/adr/0006-capability-drop.md for the sandbox verification of this
// exact pattern (a non-root parent with CAP_NET_ADMIN ambient, exec'ing a
// plain child binary that ends up with exactly CAP_NET_ADMIN effective).
inline bool raise_ambient(int cap) {
    return prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0) == 0;
}

// Best-effort: also drops every capability but `keep` from the bounding set,
// so they can never be regained later (e.g. via a setuid-root re-exec).
// This itself requires CAP_SETPCAP, so call it BEFORE drop_capabilities_to()
// removes that capability; a failure here (e.g. because the caller never
// had CAP_SETPCAP to begin with, or already dropped it) is not fatal - the
// effective/permitted shrink from drop_capabilities_to() is what actually
// matters day to day, this is only defense-in-depth on top of it.
inline void drop_bounding_except(std::initializer_list<int> keep) {
    std::uint64_t keep_mask = mask_from_caps(keep);
    for (int cap = 0; cap <= CAP_LAST_CAP; cap++) {
        if (keep_mask & (std::uint64_t(1) << cap)) continue;
        prctl(PR_CAPBSET_DROP, cap, 0, 0, 0); // ignore errors, see comment above
    }
}

} // namespace capdrop
