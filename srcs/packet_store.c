#include "packet_store.h"
#include "ft_nmap.h"
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>

// Utility functions for packet storage, see .h for details and get_response_for()

static int tuple_equal(const t_tuple *a, const t_tuple *b)
{
    return (a->src.s_addr == b->src.s_addr &&
            a->dst.s_addr == b->dst.s_addr &&
            a->sport == b->sport &&
            a->dport == b->dport &&
            a->proto == b->proto);
}

void packet_store_init(t_packet_store *store)
{
    store->head = NULL;
    pthread_mutex_init(&store->mutex, NULL);
    pthread_cond_init(&store->cond, NULL);
}

void packet_store_destroy(t_packet_store *store)
{
    pthread_mutex_lock(&store->mutex);
    t_packet_entry *cur = store->head;
    while (cur) {
        t_packet_entry *n = cur->next;
        free(cur);
        cur = n;
    }
    store->head = NULL;
    pthread_mutex_unlock(&store->mutex);
    pthread_mutex_destroy(&store->mutex);
    pthread_cond_destroy(&store->cond);
}

void packet_store_add(t_packet_store *store,
                      struct in_addr src, struct in_addr dst,
                      uint16_t sport, uint16_t dport, uint8_t proto)
{
    pthread_mutex_lock(&store->mutex);
    t_packet_entry *e = malloc(sizeof(*e));
    e->tuple.src = src;
    e->tuple.dst = dst;
    e->tuple.sport = sport;
    e->tuple.dport = dport;
    e->tuple.proto = proto;
    e->next = store->head;
    store->head = e;
    pthread_cond_broadcast(&store->cond);
    pthread_mutex_unlock(&store->mutex);
}

bool packet_store_find(t_packet_store *store, const t_tuple *tuple)
{
    t_packet_entry *cur = store->head;
    while (cur) {
        if (tuple_equal(&cur->tuple, tuple))
            return true;
        cur = cur->next;
    }
    return false;
}

// Check if we got a response for a given request (tuple) 
// Try for timeout_ms to find it (return true), or return false
bool get_response_for(const t_tuple *tuple, int timeout_ms)
{
    extern t_packet_store g_store;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (timeout_ms % 1000) * 1000000;
    if (ts.tv_nsec >= 1000000000) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000;
    }

    pthread_mutex_lock(&g_store.mutex);
    while (!packet_store_find(&g_store, tuple)) {
        if (pthread_cond_timedwait(&g_store.cond, &g_store.mutex, &ts) == ETIMEDOUT) {
            pthread_mutex_unlock(&g_store.mutex);
            return false;
        }
    }
    pthread_mutex_unlock(&g_store.mutex);
    return true;
}


// ---- TCP reply info (flags + seq + ack) ----
typedef struct s_tcp_reply_entry {
    t_tuple tuple;
    uint8_t flags;
    uint32_t seq;
    uint32_t ack;
    struct timespec when;
    struct s_tcp_reply_entry *next;
} t_tcp_reply_entry;

static t_tcp_reply_entry *g_tcp_replies = NULL;

void packet_store_add_tcp_ex(t_packet_store *store,
                             struct in_addr src, struct in_addr dst,
                             uint16_t sport, uint16_t dport,
                             uint8_t tcp_flags, uint32_t seq, uint32_t ack)
{
    (void)store; // we reuse the global store's mutex/cond
    t_tcp_reply_entry *e = (t_tcp_reply_entry *)malloc(sizeof(*e));
    if (!e) return;
    e->tuple.src = src;
    e->tuple.dst = dst;
    e->tuple.sport = sport;
    e->tuple.dport = dport;
    e->tuple.proto = IPPROTO_TCP;
    e->flags = tcp_flags;
    e->seq = seq;
    e->ack = ack;
    clock_gettime(CLOCK_REALTIME, &e->when);

    pthread_mutex_lock(&g_store.mutex);
    e->next = g_tcp_replies;
    g_tcp_replies = e;
    // Signal generic presence as well for legacy queries
    packet_store_add(&g_store, src, dst, sport, dport, IPPROTO_TCP);
    pthread_cond_broadcast(&g_store.cond);
    pthread_mutex_unlock(&g_store.mutex);
}

bool get_tcp_reply_info(const t_tuple *tuple, int timeout_ms,
                        uint8_t *out_flags, uint32_t *out_seq, uint32_t *out_ack)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec  += timeout_ms / 1000;
    ts.tv_nsec += (timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }

    //debug
    char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &tuple->src, src_str, sizeof(src_str));
    inet_ntop(AF_INET, &tuple->dst, dst_str, sizeof(dst_str));
    printf("[get_tcp_reply_info] Waiting for reply tuple: src=%s dst=%s sport=%u dport=%u proto=%u\n",
        src_str, dst_str, tuple->sport, tuple->dport, tuple->proto);
    //debug end



    pthread_mutex_lock(&g_store.mutex);
    while (1) {
        for (t_tcp_reply_entry *p = g_tcp_replies; p; p = p->next) {
            if (p->tuple.src.s_addr == tuple->src.s_addr &&
                p->tuple.dst.s_addr == tuple->dst.s_addr &&
                p->tuple.sport == tuple->sport &&
                p->tuple.dport == tuple->dport &&
                p->tuple.proto == tuple->proto) {
                if (out_flags) *out_flags = p->flags;
                if (out_seq)   *out_seq   = p->seq;
                if (out_ack)   *out_ack   = p->ack;
                pthread_mutex_unlock(&g_store.mutex);
                return true;
            }
        }

        // If we timeout or there is any error, break the loop
        int rc = pthread_cond_timedwait(&g_store.cond, &g_store.mutex, &ts);
        if (rc == ETIMEDOUT) { pthread_mutex_unlock(&g_store.mutex); return false; }
        if (rc != 0)         { pthread_mutex_unlock(&g_store.mutex); return false; }
    }
    // unreachable
    pthread_mutex_unlock(&g_store.mutex);
    return false;
}
