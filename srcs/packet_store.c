#include "packet_store.h"
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
