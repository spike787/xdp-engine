// SPDX-License-Identifier: MIT
// proxy_bouncer_core.h - pure, httplib-independent logic for bouncer-proxy
// (ADR-0010, ROADMAP.md Phase 3's "third bouncer"). Mirrors bouncer_diff.h's
// role for bouncer-xdp and nft_bouncer_core.h's role for bouncer-nft:
// factored out so it's unit-testable without a real HTTP server, a real
// backend, or a running Local API. bouncer_proxy.cpp is the only part of
// this bouncer that actually touches sockets.
#ifndef PROXY_BOUNCER_CORE_H
#define PROXY_BOUNCER_CORE_H

#include <algorithm>
#include <cctype>
#include <cstring>
#include <string>

// RFC 7230 §6.1 hop-by-hop headers plus Content-Length: hop-by-hop headers
// describe *this* connection (client<->bouncer-proxy), not the one
// bouncer-proxy makes to the backend, so forwarding them verbatim in
// either direction is wrong - most visibly, copying the backend's own
// Content-Length into the response bouncer-proxy sends the client would
// almost always be correct by coincidence (the body is usually unchanged)
// but is a latent bug waiting for the one case where it isn't (compression
// renegotiated, a future change that rewrites the body); recomputing it
// from the body the library is actually about to send is the only way
// that's always right, so it's stripped here regardless. Chunked transfer
// encoding either direction is handled by each hop's own HTTP library
// (bouncer-proxy's server and its httplib::Client to the backend both
// pick their own framing) rather than something this proxy tries to
// preserve byte-for-byte from one side to the other - see ADR-0010's Known
// gap for what that leaves unsupported (WebSocket upgrades, in particular).
//
// Case-insensitive per RFC 7230 §3.2's field-name grammar (ASCII token,
// matched case-insensitively) - exactly how every real HTTP stack treats
// header names.
inline bool is_hop_by_hop_header(const std::string& name) {
    auto ieq = [](const std::string& a, const char* b) {
        if (a.size() != std::strlen(b)) return false;
        for (size_t i = 0; i < a.size(); ++i) {
            if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) {
                return false;
            }
        }
        return true;
    };
    static constexpr const char* kHopByHop[] = {
        "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
        "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Content-Length",
    };
    for (const char* h : kHopByHop) {
        if (ieq(name, h)) return true;
    }
    return false;
}

#endif
