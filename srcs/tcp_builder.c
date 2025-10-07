
#include "tcp_builder.h"
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>

// Calculate the checksum of given data, following RFC 1071
uint16_t in_cksum(const void *data, size_t len)
{
    const uint16_t *w = (const uint16_t *)data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += *w++;
        len -= 2;
    }
    if (len == 1) {
        uint16_t last = 0;
        *(uint8_t *)&last = *(const uint8_t *)w;
        sum += last;
    }

    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

// Fills an IPv4 header (required for final tcp checksum)
int build_ipv4_header(struct ip *iph,
                      uint32_t src_be, uint32_t dst_be,
                      uint16_t payload_len, uint8_t proto, uint16_t id)
{
    memset(iph, 0, sizeof(*iph));
    iph->ip_hl = 5;
    iph->ip_v  = 4;
    iph->ip_tos = 0;
    iph->ip_len = htons(sizeof(struct ip) + payload_len);
    iph->ip_id  = htons(id);
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p   = proto;
    iph->ip_src.s_addr = src_be;
    iph->ip_dst.s_addr = dst_be;
    iph->ip_sum = 0;
    iph->ip_sum = in_cksum(iph, sizeof(struct ip));
    return sizeof(struct ip);
}

// Fills a tcp header that we will send as a request
int build_tcp_header(struct tcphdr *tcph,
                     uint16_t src_port, uint16_t dst_port,
                     uint32_t seq, uint32_t ack_seq,
                     uint8_t flags, uint16_t window)
{
    memset(tcph, 0, sizeof(*tcph));
    tcph->source = htons(src_port);
    tcph->dest   = htons(dst_port);
    tcph->seq    = htonl(seq);
    tcph->ack_seq= htonl(ack_seq);
    tcph->doff   = 5; // 20 bytes (no options)
    // set flags
    tcph->syn = !!(flags & TH_SYN);
    tcph->ack = !!(flags & TH_ACK);
    tcph->rst = !!(flags & TH_RST);
    tcph->fin = !!(flags & TH_FIN);
    tcph->psh = !!(flags & TH_PUSH);
    tcph->urg = !!(flags & TH_URG);
    tcph->window = htons(window);
    tcph->urg_ptr= 0;
    tcph->check  = 0;
    return sizeof(struct tcphdr);
}

// Calculate the payload of the whole tcp packet
void finalize_tcp_checksum(struct ip *iph, struct tcphdr *tcph,
                           const uint8_t *payload, size_t payload_len)
{
    struct tcp_pseudo_hdr ph;
    ph.src  = iph->ip_src.s_addr;
    ph.dst  = iph->ip_dst.s_addr;
    ph.zero = 0;
    ph.proto= IPPROTO_TCP;
    ph.len  = htons(sizeof(struct tcphdr) + payload_len);

    size_t tcp_len = sizeof(struct tcphdr) + payload_len;
    size_t buf_len = sizeof(ph) + tcp_len;
    uint8_t *buf = malloc(buf_len);
    if (!buf) return;
    memcpy(buf, &ph, sizeof(ph));
    memcpy(buf + sizeof(ph), tcph, sizeof(struct tcphdr));
    if (payload_len && payload) memcpy(buf + sizeof(ph) + sizeof(struct tcphdr), payload, payload_len);

    // ensure zero checksum field in the copy
    ((struct tcphdr *)(buf + sizeof(ph)))->check = 0;

    uint16_t sum = in_cksum(buf, buf_len);

    tcph->check  = sum;
    free(buf);
}
