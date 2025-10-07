
#ifndef TCP_BUILDER_H
#define TCP_BUILDER_H

#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>


// Contains the relevant information from the IPv4 header created by build_ipv4_header
// __attribute__((packed)) is required because it must be exactly 12 bytes
struct tcp_pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t len;
} __attribute__((packed));

uint16_t in_cksum(const void *data, size_t len);

int build_ipv4_header(struct ip *iph,
                      uint32_t src_be, uint32_t dst_be,
                      uint16_t payload_len, uint8_t proto, uint16_t id);

int build_tcp_header(struct tcphdr *tcph,
                     uint16_t src_port, uint16_t dst_port,
                     uint32_t seq, uint32_t ack_seq,
                     uint8_t flags, uint16_t window);

void finalize_tcp_checksum(struct ip *iph, struct tcphdr *tcph,
                           const uint8_t *payload, size_t payload_len);

#endif
