
#include "tcp_scan.h"
#include "tcp_builder.h"
#include "ft_nmap.h"
#include "packet_store.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

static uint32_t rand32(void) {
    uint32_t x = (uint32_t)rand();
    x ^= (uint32_t)rand() << 1;
    x ^= (uint32_t)rand() << 2;
    return x;
}

int pick_source_ipv4(uint32_t dst_ip_be, uint32_t *src_ip_be_out)
{
    if (!src_ip_be_out) return -1;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(53);
    dst.sin_addr.s_addr = dst_ip_be;

    if (connect(s, (struct sockaddr *)&dst, sizeof(dst)) == 0) {
        struct sockaddr_in local = {0};
        socklen_t len = sizeof(local);
        if (getsockname(s, (struct sockaddr *)&local, &len) == 0 && local.sin_addr.s_addr != 0) {
            close(s);
            *src_ip_be_out = local.sin_addr.s_addr;


            //debug
            struct in_addr ip;
            ip.s_addr = *src_ip_be_out;
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
            printf("[pick_source_ipv4] Selected source IP: %s\n", ip_str);
            //debug end

            return 0;
        }
    }
    close(s);

    //TODO REMOVE
    struct in_addr fallback;
    //TODO Change ip to ifconfig's result
    if (inet_aton("192.168.1.138", &fallback)) {
        *src_ip_be_out = fallback.s_addr;
        return 0;
    }


    return -1;
}


int send_tcp_flags(uint32_t src_ip_be, uint32_t dst_ip_be,
                   uint16_t src_port, uint16_t dst_port,
                   uint8_t flags, uint32_t seq, uint32_t ack)
{
    //debug
    printf("[send_tcp_flags] src=%u dst=%u sport=%u dport=%u flags=0x%02x\n",
       src_ip_be, dst_ip_be, src_port, dst_port, flags);


    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s < 0) return -1;
    int one = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        int e = errno;
        close(s);
        errno = e;
        return -1;
    }

    uint8_t packet[sizeof(struct ip) + sizeof(struct tcphdr)];
    struct ip *iph = (struct ip *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ip));

    build_ipv4_header(iph, src_ip_be, dst_ip_be,
                      sizeof(struct tcphdr), IPPROTO_TCP, (uint16_t)(rand() & 0xFFFF));
    build_tcp_header(tcph, src_port, dst_port, seq, ack, flags, 65535);
    finalize_tcp_checksum(iph, tcph, NULL, 0);

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = dst_ip_be;
    dst.sin_port = htons(dst_port);

    //debug
    printf("[send_tcp_flags] Sending packet...\n");


    ssize_t n = sendto(s, packet, sizeof(packet), 0,
                       (struct sockaddr *)&dst, sizeof(dst));


    //debug
    if (n < 0) perror("[send_tcp_flags] sendto failed");
    else printf("[send_tcp_flags] Packet sent successfully (%zd bytes)\n", n);

        
    int ret = 0;
    if (n < 0 || (size_t)n != sizeof(packet)) ret = -1;
    close(s);
    return ret;
}

int send_syn(uint32_t src_ip_be, uint32_t dst_ip_be,
             uint16_t src_port, uint16_t dst_port, uint32_t seq_out[1])
{
    uint32_t seq = rand32();
    if (send_tcp_flags(src_ip_be, dst_ip_be, src_port, dst_port, TH_SYN, seq, 0) < 0)
        return -1;
    if (seq_out) seq_out[0] = seq;
    return 0;
}

int send_rst(uint32_t src_ip_be, uint32_t dst_ip_be,
             uint16_t src_port, uint16_t dst_port,
             uint32_t seq, uint32_t ack)
{
    return send_tcp_flags(src_ip_be, dst_ip_be, src_port, dst_port, TH_RST | TH_ACK, seq, ack);
}

int probe_tcp_target(const char *target_ip_str, uint16_t dst_port, e_scan_type scan_type,
                     int timeout_ms, e_scan_result *out_result)
{

    printf("[probe_tcp_target] Target: %s, Port: %u, Type: %s\n",
       target_ip_str, dst_port, scan_type_to_string(scan_type));
    fflush(stdout);

    if (!target_ip_str || !out_result) {
        errno = EINVAL;
        return -1;
    }

    struct in_addr dst;
    if (inet_aton(target_ip_str, &dst) == 0) {
        errno = EINVAL;
        return -1;
    }
    uint32_t dst_be = dst.s_addr;

    uint32_t src_be = 0;
    if (pick_source_ipv4(dst_be, &src_be) < 0) return -1;

    uint16_t src_port = (uint16_t)(49152 + (rand() % (65535 - 49152)));
    uint32_t our_isn = rand32();

    uint8_t probe_flags = 0;
    switch (scan_type) {
        case SCAN_SYN:  probe_flags = TH_SYN; break;
        case SCAN_NULL: probe_flags = 0; break;
        case SCAN_ACK:  probe_flags = TH_ACK; break;
        case SCAN_FIN:  probe_flags = TH_FIN; break;
        case SCAN_XMAS: probe_flags = TH_FIN | TH_PUSH | TH_URG; break;
        default: errno = EINVAL; return -1;
    }

    //debug
    printf("[probe_tcp_target] Sending flags for port %u\n", dst_port);

    if (send_tcp_flags(src_be, dst_be, src_port, dst_port, probe_flags, our_isn, 0) < 0) {
        return -1;
    }

    //debug
    char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src_be, src_str, sizeof(src_str));
    inet_ntop(AF_INET, &dst_be, dst_str, sizeof(dst_str));
    printf("[probe_tcp_target] src_be=%s, dst_be=%s\n", src_str, dst_str);
    //debug end

    // Build the reverse tuple to wait for a reply (dst -> src)
    t_tuple tuple;
    memset(&tuple, 0, sizeof(tuple));
    tuple.src.s_addr = dst_be;
    tuple.dst.s_addr = src_be;
    tuple.sport = dst_port;
    tuple.dport = src_port;
    tuple.proto = IPPROTO_TCP;

    uint8_t reply_flags = 0;
    uint32_t peer_seq = 0, peer_ack = 0;


    //debug
    printf("[probe_tcp_target] Waiting for TCP reply (timeout: %dms)\n", timeout_ms);
    bool got = get_tcp_reply_info(&tuple, timeout_ms, &reply_flags, &peer_seq, &peer_ack);

    if (!got) {
        // timeout classification
        if (scan_type == SCAN_ACK) {
            *out_result = RES_FILTERED;
        } else if (scan_type == SCAN_NULL || scan_type == SCAN_FIN || scan_type == SCAN_XMAS) {
            *out_result = RES_OPEN_OR_FILTERED;
        } else if (scan_type == SCAN_SYN) {
            *out_result = RES_FILTERED;
        } else {
            *out_result = RES_UNKNOWN;
        }
        return 0;
    }

    // Got a reply: interpret
    if (reply_flags & TH_RST) {
        if (scan_type == SCAN_ACK) *out_result = RES_UNFILTERED;
        else *out_result = RES_CLOSED;
        return 0;
    }

    if ((reply_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK) && scan_type == SCAN_SYN) {
        // Open -> send polite RST; ack should be peer_seq+1, seq = our_isn+1
        (void)send_rst(src_be, dst_be, src_port, dst_port, our_isn + 1, peer_seq + 1);
        *out_result = RES_OPEN;
        return 0;
    }

    *out_result = RES_UNKNOWN;
    return 0;
}
