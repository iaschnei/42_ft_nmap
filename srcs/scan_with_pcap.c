#include "ft_nmap.h"
#include <pcap.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Global or shared context (you may embed in config) */
typedef struct s_pcap_ctx {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net;
    bpf_u_int32 mask;
    struct in_addr src_ip;
    int if_index;     /* if needed for link layer */
} t_pcap_ctx;

/* Build BPF filter and open pcap */
static int pcap_ctx_init(t_pcap_ctx *ctx, const char *iface) {
    /* Open live on iface */
    ctx->handle = pcap_open_live(iface, 65536, 1, 1000, ctx->errbuf);
    if (!ctx->handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", ctx->errbuf);
        return -1;
    }
    if (pcap_lookupnet(iface, &ctx->net, &ctx->mask, ctx->errbuf) < 0) {
        ctx->net = 0;
        ctx->mask = 0;
    }

    /* Compile filter: capture TCP or ICMP to/from our host */
    // Example filter: "tcp or icmp"
    struct bpf_program fp;
    const char *filter = "tcp or icmp";
    if (pcap_compile(ctx->handle, &fp, filter, 1, ctx->mask) < 0) {
        fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(ctx->handle));
        return -1;
    }
    if (pcap_setfilter(ctx->handle, &fp) < 0) {
        fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(ctx->handle));
        pcap_freecode(&fp);
        return -1;
    }
    pcap_freecode(&fp);

    return 0;
}

/* Build raw IPv4 + TCP packet with desired flags */
static int build_tcp_packet(u_char *buf, const struct in_addr *src, const struct in_addr *dst,
                            uint16_t sport, uint16_t dport, uint16_t seq, uint8_t flags) {
    /* You must build IP header, TCP header, compute checksums, etc. */
    struct ip *ip_hdr = (struct ip *)buf;
    struct tcphdr *tcp_hdr = (struct tcphdr *)(buf + sizeof(struct ip));

    /* Fill IP header */
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_v = 4;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
    ip_hdr->ip_id = htons(rand() & 0xFFFF);
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = IPPROTO_TCP;
    ip_hdr->ip_src = *src;
    ip_hdr->ip_dst = *dst;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = your_ip_checksum_func((uint16_t *)ip_hdr, sizeof(struct ip));

    /* Fill TCP header */
    tcp_hdr->th_sport = htons(sport);
    tcp_hdr->th_dport = htons(dport);
    tcp_hdr->th_seq = htonl(seq);
    tcp_hdr->th_ack = 0;
    tcp_hdr->th_off = 5;
    tcp_hdr->th_flags = flags;  /* e.g. TH_SYN, TH_FIN, TH_ACK, etc. */
    tcp_hdr->th_win = htons(1024);
    tcp_hdr->th_sum = 0;
    tcp_hdr->th_sum = your_tcp_checksum_func(ip_hdr, tcp_hdr);

    return sizeof(struct ip) + sizeof(struct tcphdr);
}

/* Build raw UDP packet (just header + zero data) */
static int build_udp_packet(u_char *buf, const struct in_addr *src, const struct in_addr *dst,
                            uint16_t sport, uint16_t dport) {
    struct ip *ip_hdr = (struct ip *)buf;
    struct udphdr *udp_hdr = (struct udphdr *)(buf + sizeof(struct ip));

    ip_hdr->ip_hl = 5;
    ip_hdr->ip_v = 4;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr));
    ip_hdr->ip_id = htons(rand() & 0xFFFF);
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = IPPROTO_UDP;
    ip_hdr->ip_src = *src;
    ip_hdr->ip_dst = *dst;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = your_ip_checksum_func((uint16_t *)ip_hdr, sizeof(struct ip));

    udp_hdr->uh_sport = htons(sport);
    udp_hdr->uh_dport = htons(dport);
    udp_hdr->uh_ulen = htons(sizeof(struct udphdr));
    udp_hdr->uh_sum = 0;
    udp_hdr->uh_sum = your_udp_checksum_func(ip_hdr, udp_hdr, NULL, 0);

    return sizeof(struct ip) + sizeof(struct udphdr);
}

/* Wait for a matching reply in pcap with timeout (ms) */
static int pcap_wait_for_reply(t_pcap_ctx *ctx, const char *dst_ip, int dst_port,
                               uint8_ttcp_flags_req, int timeout_ms) {
    /* Use pcap_next_ex / pcap_dispatch in loop until timeout or match */
    struct pcap_pkthdr *hdr;
    const u_char *pkt;
    int ret;
    time_t start = time(NULL);
    while (1) {
        ret = pcap_next_ex(ctx->handle, &hdr, &pkt);
        if (ret == 0) {
            /* timeout packet arrival, keep waiting */
            if ((time(NULL) - start) * 1000 >= timeout_ms) break;
            continue;
        }
        if (ret < 0) {
            /* error or EOF */
            break;
        }

        /* parse packet: skip link-layer, then IP, then TCP/ICMP */
        struct ip *ip_hdr = (struct ip *)(pkt + sizeof(struct ether_header));
        int ip_hdr_len = ip_hdr->ip_hl * 4;
        if (ip_hdr->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_hdr = (struct tcphdr *)((u_char *)ip_hdr + ip_hdr_len);
            /* match source/dest + ports */
            if (strcmp(inet_ntoa(ip_hdr->ip_src), dst_ip) == 0 &&
                ntohs(tcp_hdr->th_dport) == dst_port) {
                return tcp_hdr->th_flags; /* return flags seen */
            }
        } else if (ip_hdr->ip_p == IPPROTO_ICMP) {
            /* parse ICMP type/code, if it indicates port unreachable, return special code */
            struct icmp *ic = (struct icmp *)((u_char *)ip_hdr + ip_hdr_len);
            if (ic->icmp_type == ICMP_UNREACH && ic->icmp_code == ICMP_UNREACH_PORT) {
                return -100; /* marker for port unreachable */
            }
        }
    }
    /* timeout or no matching packet */
    return 0;
}

/* Replace perform_scan_job() with this version */
static void perform_scan_job_pcap(t_config *config, t_scan_result *res_entry,
                                  t_pcap_ctx *pcap_ctx, int target_idx, int port) {
    const char *target = config->targets[target_idx];
    res_entry->target = strdup(target);
    res_entry->port = port;
    res_entry->syn_res = res_entry->null_res = res_entry->fin_res =
        res_entry->xmas_res = res_entry->ack_res = res_entry->udp_res =
        RES_NOT_PERFORMED;

    struct in_addr dst_addr;
    inet_pton(AF_INET, target, &dst_addr);  /* handle FQDN later with lookup */

    /* You need src_addr (local) from pcap_ctx or by your own method */
    struct in_addr src_addr = pcap_ctx->src_ip;

    uint16_t sport = 12345;  /* random, you may randomize per packet */

    /* SYN scan */
    if (config->scan_flags & SCAN_SYN) {
        u_char buf[1500];
        int pkt_len = build_tcp_packet(buf, &src_addr, &dst_addr, sport, port, rand(), TH_SYN);
        pcap_sendpacket(pcap_ctx->handle, buf, pkt_len);

        int flags = pcap_wait_for_reply(pcap_ctx, target, sport, port, 2000);
        if (flags & TH_RST) {
            res_entry->syn_res = PORT_RES_CLOSED;
        } else if (flags & (TH_SYN | TH_ACK)) {
            res_entry->syn_res = PORT_RES_OPEN;
        } else {
            res_entry->syn_res = PORT_RES_FILTERED;
        }
    }

    /* For NULL, FIN, XMAS, ACK: similar approach but change flags */
    if (config->scan_flags & SCAN_NULL) {
        /* send packet with no flags (zero) */
        u_char buf[1500];
        int pkt_len = build_tcp_packet(buf, &src_addr, &dst_addr, sport, port, rand(), 0);
        pcap_sendpacket(pcap_ctx->handle, buf, pkt_len);

        int flags = pcap_wait_for_reply(pcap_ctx, target, sport, port, 2000);
        if (flags & TH_RST) res_entry->null_res = PORT_RES_CLOSED;
        else res_entry->null_res = PORT_RES_OPEN;  /* per nmap logic */
    }
    if (config->scan_flags & SCAN_FIN) {
        u_char buf[1500];
        int pkt_len = build_tcp_packet(buf, &src_addr, &dst_addr, sport, port, rand(), TH_FIN);
        pcap_sendpacket(pcap_ctx->handle, buf, pkt_len);
        int flags = pcap_wait_for_reply(pcap_ctx, target, sport, port, 2000);
        if (flags & TH_RST) res_entry->fin_res = PORT_RES_CLOSED;
        else res_entry->fin_res = PORT_RES_OPEN;
    }
    if (config->scan_flags & SCAN_XMAS) {
        u_char buf[1500];
        int pkt_len = build_tcp_packet(buf, &src_addr, &dst_addr, sport, port, rand(),
                                       TH_FIN | TH_PUSH | TH_URG);
        pcap_sendpacket(pcap_ctx->handle, buf, pkt_len);
        int flags = pcap_wait_for_reply(pcap_ctx, target, sport, port, 2000);
        if (flags & TH_RST) res_entry->xmas_res = PORT_RES_CLOSED;
        else res_entry->xmas_res = PORT_RES_OPEN;
    }
    if (config->scan_flags & SCAN_ACK) {
        u_char buf[1500];
        int pkt_len = build_tcp_packet(buf, &src_addr, &dst_addr, sport, port, rand(), TH_ACK);
        pcap_sendpacket(pcap_ctx->handle, buf, pkt_len);
        int flags = pcap_wait_for_reply(pcap_ctx, target, sport, port, 2000);
        /* If we see RST, treat as unfiltered per nmap ACK scan */
        if (flags & TH_RST) res_entry->ack_res = PORT_RES_FILTERED;
        else res_entry->ack_res = PORT_RES_FILTERED;
    }

    /* UDP scan: send UDP and wait for ICMP unreachable */
    if (config->scan_flags & SCAN_UDP) {
        u_char buf[1500];
        int pkt_len = build_udp_packet(buf, &src_addr, &dst_addr, sport, port);
        pcap_sendpacket(pcap_ctx->handle, buf, pkt_len);
        int reply = pcap_wait_for_reply(pcap_ctx, target, port, 0, 2000);
        if (reply == -100) {
            /* ICMP unreachable => closed */
            res_entry->udp_res = PORT_RES_CLOSED;
        } else {
            /* no ICMP => open|filtered */
            res_entry->udp_res = PORT_RES_OPEN_OR_FILTERED;
        }
    }
}
