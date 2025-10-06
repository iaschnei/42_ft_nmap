#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>
#include <pthread.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include "ft_nmap.h"
#include "packet_store.h"

typedef struct {
    pcap_t *handle;
    pthread_t thread;
    bool running;
    char errbuf[PCAP_ERRBUF_SIZE];
} t_capture;

int capture_start(t_capture *cap, const char *iface, const t_config *config);
void capture_stop(t_capture *cap);

#endif
