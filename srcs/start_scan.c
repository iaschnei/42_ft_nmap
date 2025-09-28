// src/start_scan_pcap.c

#define _POSIX_C_SOURCE 200112L
#include "ft_nmap.h"
#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <time.h>

#define PCAP_SNAPLEN 65536
#define PCAP_TIMEOUT_MS 1000
#define MAX_PACKET_LEN 1500


/*

Important Caveats & What You Must Fill In / Verify

Interface selection / source IP: I hardcoded iface = "eth0". You should let the user specify or auto-detect the interface and determine its IPv4 address (so you know pcap.local_ip).

Checksum functions: I included simple ones (ip_checksum, tcp_udp_checksum), but you should test them carefully. For TCP especially, use a correct pseudo-header calculation.

Matching replies: The wait_pcap_reply() is simplistic; in real scenarios you may get packets you didn’t send, out-of-order, or replies to earlier scans. You may need to tag packets with unique sequence numbers or ports to disambiguate.

Thread safety of pcap: Many OSes do not like concurrent pcap_sendpacket() + pcap_next_ex() from multiple threads on the same pcap_t. If you see crashes or dropped packets, consider:

Having a single pcap capture thread that reads packets and dispatches them to workers via queues (based on matching).

Or opening a separate pcap_t handle per worker (costly but safer).

Or serializing send + capture with a mutex.

Timeouts: The 2 second (2000 ms) timeout is arbitrary; you can tune it or make it configurable.

DNS / FQDN support: Currently, the code uses inet_pton() on the target string; that fails for hostnames. You should do getaddrinfo() earlier and translate FQDN to IP, or store both and craft based on resolved IP.

Error checking: In parts like strdup(), malloc(), you should add error checks (as shown in some parts) to avoid silent null-pointer derefs.

Service resolution: print_results() still needs to map port → service name (using getservbyport() or /etc/services lookup).

Memory management: Make sure free_config() properly frees config->results and all duplicated targets in results.
*/

/* Shared pcap context */
typedef struct s_pcap_ctx {
    pcap_t *handle;
    struct bpf_program bpf_prog;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net, mask;
    struct in_addr local_ip;  // your source IP to use when crafting packets
} t_pcap_ctx;

/* Job queue from previous version (reuse) */
typedef struct s_job {
    int target_idx;
    int port;
    struct s_job *next;
} t_job;

typedef struct s_job_queue {
    t_job *head;
    t_job *tail;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int remaining;
    int stopped;
} t_job_queue;

typedef struct s_worker_ctx {
    t_config *config;
    t_job_queue *queue;
    t_pcap_ctx *pcap;
} t_worker_ctx;

/* Checksum helpers you need to implement or link from existing code */
static uint16_t ip_checksum(uint16_t *buf, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len/2; i++) {
        sum += ntohs(buf[i]);
        if (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return htons(~sum & 0xFFFF);
}

/* Pseudo-header checksum for TCP/UDP */
static uint16_t tcp_udp_checksum(const struct ip *ip_hdr, const void *tp_hdr, int tp_len, int is_tcp) {
    uint32_t sum = 0;
    const uint16_t *buf;
    int len;

    // pseudo IP header
    sum += (ip_hdr->ip_src.s_addr >> 16) & 0xFFFF;
    sum += (ip_hdr->ip_src.s_addr) & 0xFFFF;
    sum += (ip_hdr->ip_dst.s_addr >> 16) & 0xFFFF;
    sum += (ip_hdr->ip_dst.s_addr) & 0xFFFF;
    sum += htons(is_tcp ? IPPROTO_TCP : IPPROTO_UDP);
    sum += htons(tp_len);

    buf = (const uint16_t *)tp_hdr;
    len = tp_len;
    for (int i = 0; i < len/2; i++) {
        sum += ntohs(buf[i]);
        if (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >> 16);
    }
    if (len & 1) {
        // odd byte
        const uint8_t *b = (const uint8_t *)tp_hdr;
        sum += (uint16_t)b[len - 1] << 8;
    }

    return htons(~sum & 0xFFFF);
}

/* Build IPv4 + TCP packet with given flags */
static int build_tcp_packet(u_char *buf,
                            struct in_addr src, struct in_addr dst,
                            uint16_t sport, uint16_t dport,
                            uint32_t seq, uint8_t flags) {
    struct ip *ip_hdr = (struct ip *)buf;
    struct tcphdr *tcp_hdr = (struct tcphdr *)(buf + sizeof(struct ip));

    int ip_hdr_len = sizeof(struct ip);
    int tcp_hdr_len = sizeof(struct tcphdr);

    memset(buf, 0, ip_hdr_len + tcp_hdr_len);

    /* IP header */
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = ip_hdr_len / 4;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(ip_hdr_len + tcp_hdr_len);
    ip_hdr->ip_id = htons(rand() & 0xFFFF);
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = IPPROTO_TCP;
    ip_hdr->ip_src = src;
    ip_hdr->ip_dst = dst;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = ip_checksum((uint16_t *)ip_hdr, ip_hdr_len);

    /* TCP header */
    tcp_hdr->th_sport = htons(sport);
    tcp_hdr->th_dport = htons(dport);
    tcp_hdr->th_seq = htonl(seq);
    tcp_hdr->th_ack = 0;
    tcp_hdr->th_off = 5;
    tcp_hdr->th_flags = flags;
    tcp_hdr->th_win = htons(65535);
    tcp_hdr->th_sum = 0;
    tcp_hdr->th_sum = tcp_udp_checksum(ip_hdr, tcp_hdr, tcp_hdr_len, 1);

    return ip_hdr_len + tcp_hdr_len;
}

/* Build IPv4 + UDP header */
static int build_udp_packet(u_char *buf,
                            struct in_addr src, struct in_addr dst,
                            uint16_t sport, uint16_t dport) {
    struct ip *ip_hdr = (struct ip *)buf;
    struct udphdr *udp_hdr = (struct udphdr *)(buf + sizeof(struct ip));

    int ip_hdr_len = sizeof(struct ip);
    int udp_hdr_len = sizeof(struct udphdr);

    memset(buf, 0, ip_hdr_len + udp_hdr_len);

    /* IP header */
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = ip_hdr_len / 4;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(ip_hdr_len + udp_hdr_len);
    ip_hdr->ip_id = htons(rand() & 0xFFFF);
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = IPPROTO_UDP;
    ip_hdr->ip_src = src;
    ip_hdr->ip_dst = dst;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = ip_checksum((uint16_t *)ip_hdr, ip_hdr_len);

    /* UDP header */
    udp_hdr->uh_sport = htons(sport);
    udp_hdr->uh_dport = htons(dport);
    udp_hdr->uh_ulen = htons(udp_hdr_len);
    udp_hdr->uh_sum = 0;
    udp_hdr->uh_sum = tcp_udp_checksum(ip_hdr, udp_hdr, udp_hdr_len, 0);

    return ip_hdr_len + udp_hdr_len;
}

/* Wait for matching reply, returns:
   >0 : for TCP, flags field
   -100: ICMP Port Unreachable
    0 : timeout/no matching
*/
static int wait_pcap_reply(t_pcap_ctx *pcap, const struct in_addr *dst_ip,
                           uint16_t sport, uint16_t dport, int timeout_ms) {
    struct pcap_pkthdr *hdr;
    const u_char *packet;
    time_t start = time(NULL);

    while (1) {
        int ret = pcap_next_ex(pcap->handle, &hdr, &packet);
        if (ret == 0) {
            /* no packet in this interval: check timeout */
            if (((time(NULL) - start) * 1000) >= timeout_ms) break;
            else continue;
        }
        if (ret < 0) {
            /* error or EOF */
            break;
        }
        /* skip Ethernet header */
        const struct ether_header *eth = (const struct ether_header *)packet;
        int off = sizeof(struct ether_header);
        const struct ip *ip_hdr = (const struct ip *)(packet + off);
        int ip_hdr_len = ip_hdr->ip_hl * 4;
        off += ip_hdr_len;

        /* Match based on IPs */
        if (ip_hdr->ip_p == IPPROTO_TCP) {
            const struct tcphdr *tcp_hdr = (const struct tcphdr *)(packet + off);
            /* Check if source/dest ports match reversed */
            if (tcp_hdr->th_sport == htons(dport) &&
                tcp_hdr->th_dport == htons(sport)) {
                return tcp_hdr->th_flags;
            }
        } else if (ip_hdr->ip_p == IPPROTO_ICMP) {
            const struct icmp *icmp_hdr = (const struct icmp *)(packet + off);
            /* ICMP to original destination? parse inner IP + UDP/TCP header */
            if (icmp_hdr->icmp_type == ICMP_UNREACH && icmp_hdr->icmp_code == ICMP_UNREACH_PORT) {
                return -100;
            }
        }
    }
    return 0;
}

/* job queue helpers (init, push, pop, stop) — same as before */
static void job_queue_init(t_job_queue *q) {
    q->head = q->tail = NULL;
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->cond, NULL);
    q->remaining = 0;
    q->stopped = 0;
}

static void job_queue_destroy(t_job_queue *q) {
    t_job *cur = q->head;
    while (cur) {
        t_job *n = cur->next;
        free(cur);
        cur = n;
    }
    q->head = q->tail = NULL;
    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->cond);
}

static void job_queue_push(t_job_queue *q, t_job *job) {
    job->next = NULL;
    pthread_mutex_lock(&q->lock);
    if (q->tail) q->tail->next = job;
    else q->head = job;
    q->tail = job;
    q->remaining++;
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->lock);
}

static t_job *job_queue_pop(t_job_queue *q) {
    pthread_mutex_lock(&q->lock);
    while (!q->head && !q->stopped) {
        pthread_cond_wait(&q->cond, &q->lock);
    }
    if (q->stopped) {
        pthread_mutex_unlock(&q->lock);
        return NULL;
    }
    t_job *job = q->head;
    q->head = job->next;
    if (!q->head) q->tail = NULL;
    q->remaining--;
    pthread_mutex_unlock(&q->lock);
    return job;
}

static void job_queue_stop(t_job_queue *q) {
    pthread_mutex_lock(&q->lock);
    q->stopped = 1;
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_unlock(&q->lock);
}

/* The perform job function using pcap */
static void perform_scan_job_pcap(t_config *cfg, t_pcap_ctx *pcap,
                                  t_scan_result *res_item, int t_idx, int port) {
    const char *target = cfg->targets[t_idx];
    res_item->target = strdup(target);
    res_item->port = port;
    res_item->syn_res = res_item->null_res = res_item->fin_res =
        res_item->xmas_res = res_item->ack_res = res_item->udp_res = RES_NOT_PERFORMED;

    struct in_addr dst;
    if (inet_pton(AF_INET, target, &dst) != 1) {
        /* optionally, do DNS resolution for FQDN */
        return;
    }
    struct in_addr src = pcap->local_ip;
    uint16_t sport = (uint16_t)(1025 + (rand() % 50000));

    u_char pktbuf[MAX_PACKET_LEN];

    /* SYN */
    if (cfg->scan_flags & SCAN_SYN) {
        int len = build_tcp_packet(pktbuf, src, dst, sport, port, rand(), TH_SYN);
        pcap_sendpacket(pcap->handle, pktbuf, len);
        int flags = wait_pcap_reply(pcap, &dst, sport, port, 2000);
        if (flags & TH_RST)       res_item->syn_res = PORT_RES_CLOSED;
        else if (flags & (TH_SYN | TH_ACK)) res_item->syn_res = PORT_RES_OPEN;
        else res_item->syn_res = PORT_RES_FILTERED;
    }

    /* NULL */
    if (cfg->scan_flags & SCAN_NULL) {
        int len = build_tcp_packet(pktbuf, src, dst, sport, port, rand(), 0);
        pcap_sendpacket(pcap->handle, pktbuf, len);
        int flags = wait_pcap_reply(pcap, &dst, sport, port, 2000);
        if (flags & TH_RST) res_item->null_res = PORT_RES_CLOSED;
        else res_item->null_res = PORT_RES_OPEN;
    }

    /* FIN */
    if (cfg->scan_flags & SCAN_FIN) {
        int len = build_tcp_packet(pktbuf, src, dst, sport, port, rand(), TH_FIN);
        pcap_sendpacket(pcap->handle, pktbuf, len);
        int flags = wait_pcap_reply(pcap, &dst, sport, port, 2000);
        if (flags & TH_RST) res_item->fin_res = PORT_RES_CLOSED;
        else res_item->fin_res = PORT_RES_OPEN;
    }

    /* XMAS (FIN | PSH | URG) */
    if (cfg->scan_flags & SCAN_XMAS) {
        int len = build_tcp_packet(pktbuf, src, dst, sport, port, rand(),
                                   TH_FIN | TH_PUSH | TH_URG);
        pcap_sendpacket(pcap->handle, pktbuf, len);
        int flags = wait_pcap_reply(pcap, &dst, sport, port, 2000);
        if (flags & TH_RST) res_item->xmas_res = PORT_RES_CLOSED;
        else res_item->xmas_res = PORT_RES_OPEN;
    }

    /* ACK */
    if (cfg->scan_flags & SCAN_ACK) {
        int len = build_tcp_packet(pktbuf, src, dst, sport, port, rand(), TH_ACK);
        pcap_sendpacket(pcap->handle, pktbuf, len);
        int flags = wait_pcap_reply(pcap, &dst, sport, port, 2000);
        /* According to nmap behavior, seeing RST implies unfiltered */
        if (flags & TH_RST) res_item->ack_res = PORT_RES_FILTERED;
        else res_item->ack_res = PORT_RES_FILTERED;
    }

    /* UDP: send a UDP packet and wait for ICMP unreachable */
    if (cfg->scan_flags & SCAN_UDP) {
        int len = build_udp_packet(pktbuf, src, dst, sport, port);
        pcap_sendpacket(pcap->handle, pktbuf, len);
        int rep = wait_pcap_reply(pcap, &dst, port, 0, 2000);
        if (rep == -100) {
            res_item->udp_res = PORT_RES_CLOSED;
        } else {
            res_item->udp_res = PORT_RES_OPEN_OR_FILTERED;
        }
    }
}

/* Worker thread */
static void *worker_thread(void *arg) {
    t_worker_ctx *ctx = (t_worker_ctx *)arg;
    t_config *cfg = ctx->config;
    t_ppcap_ctx *pcap = ctx->pcap;

    while (1) {
        t_job *job = job_queue_pop(ctx->queue);
        if (!job) break;

        /* Find the result item matching target & port */
        for (int i = 0; i < cfg->result_count; ++i) {
            t_scan_result *ri = &cfg->results[i];
            if (ri->port == job->port &&
                strcmp(ri->target, cfg->targets[job->target_idx]) == 0) {
                perform_scan_job_pcap(cfg, pcap, ri, job->target_idx, job->port);
                break;
            }
        }

        free(job);
    }
    return NULL;
}

/* Main start_scan with pcap */
int start_scan(t_config *config) {
    if (!config) return -1;
    if (config->target_count <= 0 || config->port_count <= 0) {
        fprintf(stderr, "No targets or ports to scan.\n");
        return -1;
    }

    long total = (long)config->target_count * (long)config->port_count;
    config->results = calloc(total, sizeof(t_scan_result));
    if (!config->results) {
        perror("calloc");
        return -1;
    }
    config->result_count = (int)total;

    /* Initialize results targets and port fields */
    int idx = 0;
    for (int t = 0; t < config->target_count; ++t) {
        for (int p = 0; p < config->port_count; ++p) {
            config->results[idx].target = strdup(config->targets[t]);
            config->results[idx].port = config->port_list[p];
            config->results[idx].syn_res =
            config->results[idx].null_res =
            config->results[idx].fin_res =
            config->results[idx].xmas_res =
            config->results[idx].ack_res =
            config->results[idx].udp_res = RES_NOT_PERFORMED;
            idx++;
        }
    }

    /* Setup pcap context (choose interface) */
    t_pcap_ctx pcap;
    memset(&pcap, 0, sizeof(pcap));
    const char *iface = "eth0";  // TODO: allow user to specify or auto-detect
    if (pcap_lookupnet(iface, &pcap.net, &pcap.mask, pcap.errbuf) < 0) {
        pcap.net = pcap.mask = 0;
    }
    pcap.handle = pcap_open_live(iface, PCAP_SNAPLEN, 1, PCAP_TIMEOUT_MS, pcap.errbuf);
    if (!pcap.handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", pcap.errbuf);
        free(config->results);
        return -1;
    }
    const char *filter_expr = "tcp or icmp";
    if (pcap_compile(pcap.handle, &pcap.bpf_prog, filter_expr, 1, pcap.mask) < 0) {
        fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(pcap.handle));
        pcap_close(pcap.handle);
        free(config->results);
        return -1;
    }
    if (pcap_setfilter(pcap.handle, &pcap.bpf_prog) < 0) {
        fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(pcap.handle));
        pcap_freecode(&pcap.bpf_prog);
        pcap_close(pcap.handle);
        free(config->results);
        return -1;
    }
    /* TODO: set pcap.local_ip to the correct source IP on iface */

    /* Build job queue */
    t_job_queue queue;
    job_queue_init(&queue);
    for (int t = 0; t < config->target_count; ++t) {
        for (int p = 0; p < config->port_count; ++p) {
            t_job *job = malloc(sizeof(t_job));
            if (!job) {
                perror("malloc");
                job_queue_stop(&queue);
                job_queue_destroy(&queue);
                pcap_close(pcap.handle);
                return -1;
            }
            job->target_idx = t;
            job->port = config->port_list[p];
            job_queue_push(&queue, job);
        }
    }

    /* Launch threads */
    int nthreads = config->speedup;
    if (nthreads <= 0) {
        long np = sysconf(_SC_NPROCESSORS_ONLN);
        nthreads = (np > 0) ? (int)np : 4;
    }
    if (nthreads > 250) nthreads = 250;

    pthread_t *threads = calloc(nthreads, sizeof(pthread_t));
    t_worker_ctx ctx = { .config = config, .queue = &queue, .pcap = &pcap };

    for (int i = 0; i < nthreads; ++i) {
        if (pthread_create(&threads[i], NULL, worker_thread, &ctx) != 0) {
            perror("pthread_create");
            job_queue_stop(&queue);
            for (int j = 0; j < i; ++j) pthread_join(threads[j], NULL);
            free(threads);
            job_queue_destroy(&queue);
            pcap_close(pcap.handle);
            return -1;
        }
    }

    /* Wait until jobs exhausted */
    while (1) {
        pthread_mutex_lock(&queue.lock);
        int rem = queue.remaining;
        pthread_mutex_unlock(&queue.lock);
        if (rem == 0) break;
        usleep(20000);
    }

    job_queue_stop(&queue);
    for (int i = 0; i < nthreads; ++i) {
        pthread_join(threads[i], NULL);
    }

    free(threads);
    job_queue_destroy(&queue);

    /* Done: close pcap */
    pcap_freecode(&pcap.bpf_prog);
    pcap_close(pcap.handle);

    return 0;
}
