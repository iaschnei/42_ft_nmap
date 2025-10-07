
#ifndef TCP_SCAN_H
#define TCP_SCAN_H

#include <stdint.h>
#include "ft_nmap.h"

int pick_source_ipv4(uint32_t dst_ip_be, uint32_t *src_ip_be_out);

int send_tcp_flags(uint32_t src_ip_be, uint32_t dst_ip_be,
                   uint16_t src_port, uint16_t dst_port,
                   uint8_t flags, uint32_t seq, uint32_t ack);

int send_syn(uint32_t src_ip_be, uint32_t dst_ip_be,
             uint16_t src_port, uint16_t dst_port, uint32_t seq_out[1]);

int send_rst(uint32_t src_ip_be, uint32_t dst_ip_be,
             uint16_t src_port, uint16_t dst_port,
             uint32_t seq, uint32_t ack);

/* High-level probe using packet_store's get_tcp_reply_info() */
int probe_tcp_target(const char *target_ip_str, uint16_t dst_port, e_scan_type scan_type,
                     int timeout_ms, e_scan_result *out_result);

#endif /* TCP_SCAN_H */
