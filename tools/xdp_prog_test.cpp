// SPDX-License-Identifier: MIT
// xdp-prog-test: loads the real xdp_prog.bpf.o and runs synthetic packets
// through it via BPF_PROG_TEST_RUN (libbpf's bpf_prog_test_run_opts) -
// this exercises xdp_firewall's actual packet-parsing and classification
// logic, including the verdict it returns and which proto_stats/stats
// counters it bumps, *without* attaching to a real network interface.
//
// This matters specifically for ADR-0008 (ROADMAP.md "IPv6 header
// parsing"): every prior change to xdp_prog.bpf.c in this project's
// history (ADR-0002, the SYN rate limiter, the port-scan detector) could
// only be verified by loading the verifier's static proof that the
// program is safe (`make all` building it, or bouncer-xdp loading it) -
// actual runtime packet-classification behavior always needed the user's
// real hardware to confirm. BPF_PROG_TEST_RUN closes that gap for
// anything that doesn't depend on real driver/NIC interaction: it's the
// same mechanism the kernel's own BPF selftests use to unit-test programs
// offline. Real XDP attach to a real interface - and whatever a real
// NIC's native-XDP fast path might do differently from this synthetic
// harness - is still the user's hardware to confirm, same as always.
//
// Not part of `make test` (needs CAP_BPF to load an XDP-type BPF program,
// unlike the googletest suite's pure userspace logic) or `make all` (a
// one-shot verification tool, not something this project ships) - same
// "separate opt-in target" reasoning as `asan`/`fuzz`.
//
// Build: make xdp-prog-test
// Run:   sudo ./tools/xdp-prog-test   (needs root or CAP_BPF, same as
//                                      loading xdp_prog.bpf.o ever does)
#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <netinet/in.h> // IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMPV6, IPPROTO_HOPOPTS

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

namespace {

#pragma pack(push, 1)
struct EthHdr {
    std::uint8_t dst[6];
    std::uint8_t src[6];
    std::uint16_t ethertype;
};
struct Ipv4Hdr {
    std::uint8_t ver_ihl;
    std::uint8_t tos;
    std::uint16_t total_len;
    std::uint16_t id;
    std::uint16_t flags_frag;
    std::uint8_t ttl;
    std::uint8_t proto;
    std::uint16_t checksum;
    std::uint32_t saddr;
    std::uint32_t daddr;
};
struct Ipv6Hdr {
    std::uint8_t ver_tc_hi; // version(4) | top 4 bits of traffic class
    std::uint8_t tc_lo_flow_hi;
    std::uint16_t flow_lo;
    std::uint16_t payload_len;
    std::uint8_t nexthdr;
    std::uint8_t hop_limit;
    std::uint8_t saddr[16];
    std::uint8_t daddr[16];
};
struct TcpHdr {
    std::uint16_t sport, dport;
    std::uint32_t seq, ack;
    std::uint8_t data_off;
    std::uint8_t flags;
    std::uint16_t window;
    std::uint16_t checksum;
    std::uint16_t urgptr;
};
#pragma pack(pop)

constexpr std::uint16_t kEthPIp = 0x0800;
constexpr std::uint16_t kEthPIpv6 = 0x86DD;
constexpr std::uint16_t kEthPArp = 0x0806;
constexpr std::uint32_t kXdpPass = 2; // XDP_PASS
constexpr int kProtoTcpIdx = 0, kProtoUdpIdx = 1, kProtoIcmpIdx = 2, kProtoOtherIdx = 3;
constexpr int kStatsPassedIdx = 1;

int g_pass = 0, g_fail = 0;

void check(bool cond, const std::string& what) {
    if (cond) {
        g_pass++;
        std::printf("  ok   %s\n", what.c_str());
    } else {
        g_fail++;
        std::printf("  FAIL %s\n", what.c_str());
    }
}

std::vector<std::uint8_t> make_eth_ipv4_tcp(bool syn) {
    std::vector<std::uint8_t> pkt(sizeof(EthHdr) + sizeof(Ipv4Hdr) + sizeof(TcpHdr), 0);
    auto* eth = reinterpret_cast<EthHdr*>(pkt.data());
    std::memset(eth->dst, 0x11, 6);
    std::memset(eth->src, 0x22, 6);
    eth->ethertype = htons(kEthPIp);

    auto* ip = reinterpret_cast<Ipv4Hdr*>(pkt.data() + sizeof(EthHdr));
    ip->ver_ihl = 0x45;
    ip->total_len = htons(sizeof(Ipv4Hdr) + sizeof(TcpHdr));
    ip->ttl = 64;
    ip->proto = 6; // TCP
    inet_pton(AF_INET, "203.0.113.9", &ip->saddr);
    inet_pton(AF_INET, "10.0.0.1", &ip->daddr);

    auto* tcp = reinterpret_cast<TcpHdr*>(pkt.data() + sizeof(EthHdr) + sizeof(Ipv4Hdr));
    tcp->sport = htons(51234);
    tcp->dport = htons(80);
    tcp->data_off = 5 << 4;
    tcp->flags = syn ? 0x02 : 0x00;
    return pkt;
}

std::vector<std::uint8_t> make_eth_ipv6(std::uint8_t nexthdr, bool include_tcp_header) {
    std::size_t size = sizeof(EthHdr) + sizeof(Ipv6Hdr) + (include_tcp_header ? sizeof(TcpHdr) : 0);
    std::vector<std::uint8_t> pkt(size, 0);
    auto* eth = reinterpret_cast<EthHdr*>(pkt.data());
    std::memset(eth->dst, 0x11, 6);
    std::memset(eth->src, 0x22, 6);
    eth->ethertype = htons(kEthPIpv6);

    auto* ip6 = reinterpret_cast<Ipv6Hdr*>(pkt.data() + sizeof(EthHdr));
    ip6->ver_tc_hi = 0x60; // version 6, rest of traffic class 0
    ip6->payload_len = htons(include_tcp_header ? sizeof(TcpHdr) : 0);
    ip6->nexthdr = nexthdr;
    ip6->hop_limit = 64;
    inet_pton(AF_INET6, "2001:db8::9", ip6->saddr);
    inet_pton(AF_INET6, "2001:db8::1", ip6->daddr);

    if (include_tcp_header) {
        auto* tcp = reinterpret_cast<TcpHdr*>(pkt.data() + sizeof(EthHdr) + sizeof(Ipv6Hdr));
        tcp->sport = htons(51234);
        tcp->dport = htons(80);
        tcp->data_off = 5 << 4;
    }
    return pkt;
}

std::vector<std::uint8_t> make_truncated_ipv6() {
    // Ethernet + only 20 of the required 40 IPv6 header bytes - must not
    // be read past, must still return XDP_PASS, must not bump anything
    // (same "too short to classify" precedent the IPv4 path uses).
    std::vector<std::uint8_t> pkt(sizeof(EthHdr) + 20, 0);
    auto* eth = reinterpret_cast<EthHdr*>(pkt.data());
    eth->ethertype = htons(kEthPIpv6);
    return pkt;
}

std::vector<std::uint8_t> make_eth_arp() {
    std::vector<std::uint8_t> pkt(sizeof(EthHdr) + 28, 0); // enough for a real ARP packet's body
    auto* eth = reinterpret_cast<EthHdr*>(pkt.data());
    eth->ethertype = htons(kEthPArp);
    return pkt;
}

std::uint32_t run(int prog_fd, const std::vector<std::uint8_t>& pkt) {
    bpf_test_run_opts opts{};
    opts.sz = sizeof(opts);
    opts.data_in = pkt.data();
    opts.data_size_in = static_cast<std::uint32_t>(pkt.size());
    opts.repeat = 1;
    int ret = bpf_prog_test_run_opts(prog_fd, &opts);
    if (ret != 0) {
        std::fprintf(stderr, "bpf_prog_test_run_opts failed: %s\n", std::strerror(errno));
        return 0xFFFFFFFF;
    }
    return opts.retval;
}

std::uint64_t sum_percpu(int map_fd, std::uint32_t key, int ncpus) {
    std::vector<std::uint64_t> vals(ncpus, 0);
    if (bpf_map_lookup_elem(map_fd, &key, vals.data()) != 0) return 0;
    std::uint64_t total = 0;
    for (auto v : vals) total += v;
    return total;
}

} // namespace

int main() {
    struct bpf_object* obj = bpf_object__open_file("xdp_prog.bpf.o", nullptr);
    if (!obj) {
        std::fprintf(stderr, "bpf_object__open_file failed - run this from the repo root, "
                              "after 'make xdp_prog.bpf.o'\n");
        return 1;
    }
    if (bpf_object__load(obj)) {
        std::fprintf(stderr, "bpf_object__load failed: %s (need root or CAP_BPF to load an "
                              "XDP-type BPF program at all - see ADR-0006)\n", std::strerror(errno));
        return 1;
    }
    std::printf("verifier accepted xdp_prog.bpf.o\n\n");

    struct bpf_program* prog = bpf_object__find_program_by_name(obj, "xdp_firewall");
    int prog_fd = bpf_program__fd(prog);
    int proto_fd = bpf_object__find_map_fd_by_name(obj, "proto_stats");
    int stats_fd = bpf_object__find_map_fd_by_name(obj, "stats");
    int ncpus = libbpf_num_possible_cpus();

    auto proto_count = [&](int idx) { return sum_percpu(proto_fd, static_cast<std::uint32_t>(idx), ncpus); };
    auto passed_count = [&]() { return sum_percpu(stats_fd, kStatsPassedIdx, ncpus); };

    // --- IPv4 regression: confirms this PR didn't change the existing path ---
    {
        std::uint64_t tcp_before = proto_count(kProtoTcpIdx), passed_before = passed_count();
        auto pkt = make_eth_ipv4_tcp(/*syn=*/false);
        std::uint32_t verdict = run(prog_fd, pkt);
        check(verdict == kXdpPass, "IPv4 TCP: XDP_PASS");
        check(proto_count(kProtoTcpIdx) == tcp_before + 1, "IPv4 TCP: proto_stats[tcp] +1");
        check(passed_count() == passed_before + 1, "IPv4 TCP: stats[passed] +1");
    }

    // --- IPv6 TCP: new path, classified correctly, now counted as passed ---
    {
        std::uint64_t tcp_before = proto_count(kProtoTcpIdx), passed_before = passed_count();
        auto pkt = make_eth_ipv6(IPPROTO_TCP, /*include_tcp_header=*/true);
        std::uint32_t verdict = run(prog_fd, pkt);
        check(verdict == kXdpPass, "IPv6 TCP: XDP_PASS");
        check(proto_count(kProtoTcpIdx) == tcp_before + 1, "IPv6 TCP: proto_stats[tcp] +1 (shared w/ IPv4)");
        check(passed_count() == passed_before + 1, "IPv6 TCP: stats[passed] +1 (previously uncounted)");
    }

    // --- IPv6 UDP ---
    {
        std::uint64_t udp_before = proto_count(kProtoUdpIdx);
        auto pkt = make_eth_ipv6(IPPROTO_UDP, /*include_tcp_header=*/false);
        std::uint32_t verdict = run(prog_fd, pkt);
        check(verdict == kXdpPass, "IPv6 UDP: XDP_PASS");
        check(proto_count(kProtoUdpIdx) == udp_before + 1, "IPv6 UDP: proto_stats[udp] +1");
    }

    // --- IPv6 ICMPv6: shares the IPv4 ICMP bucket, by design (see ADR-0008) ---
    {
        std::uint64_t icmp_before = proto_count(kProtoIcmpIdx);
        auto pkt = make_eth_ipv6(IPPROTO_ICMPV6, /*include_tcp_header=*/false);
        std::uint32_t verdict = run(prog_fd, pkt);
        check(verdict == kXdpPass, "IPv6 ICMPv6: XDP_PASS");
        check(proto_count(kProtoIcmpIdx) == icmp_before + 1, "IPv6 ICMPv6: proto_stats[icmp] +1 (shared w/ IPv4 ICMP)");
    }

    // --- IPv6 with a Hop-by-Hop extension header ahead of its real payload:
    // demonstrates ADR-0008's stated extension-header limitation concretely
    // (classified by the extension header's own protocol number, landing in
    // "other" - not silently misreported as something else, but not resolved
    // to the real payload protocol either) ---
    {
        std::uint64_t other_before = proto_count(kProtoOtherIdx);
        auto pkt = make_eth_ipv6(IPPROTO_HOPOPTS, /*include_tcp_header=*/false);
        std::uint32_t verdict = run(prog_fd, pkt);
        check(verdict == kXdpPass, "IPv6 Hop-by-Hop ext header: XDP_PASS");
        check(proto_count(kProtoOtherIdx) == other_before + 1,
              "IPv6 Hop-by-Hop ext header: proto_stats[other] +1 (known limitation, not a bug)");
    }

    // --- Truncated IPv6 header: must not read out of bounds, must not crash,
    // must not bump any counter (same silent-pass precedent as a truncated
    // IPv4 header) ---
    {
        std::uint64_t other_before = proto_count(kProtoOtherIdx), passed_before = passed_count();
        auto pkt = make_truncated_ipv6();
        std::uint32_t verdict = run(prog_fd, pkt);
        check(verdict == kXdpPass, "Truncated IPv6 header: XDP_PASS");
        check(proto_count(kProtoOtherIdx) == other_before, "Truncated IPv6 header: no proto_stats bump");
        check(passed_count() == passed_before, "Truncated IPv6 header: no stats[passed] bump");
    }

    // --- Unrelated ethertype (ARP): confirms completely unchanged behavior ---
    {
        std::uint64_t passed_before = passed_count();
        auto pkt = make_eth_arp();
        std::uint32_t verdict = run(prog_fd, pkt);
        check(verdict == kXdpPass, "ARP: XDP_PASS");
        check(passed_count() == passed_before, "ARP: no stats[passed] bump (unchanged pre-existing behavior)");
    }

    bpf_object__close(obj);

    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
