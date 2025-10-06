#ifndef PACKET_STORE_H
#define PACKET_STORE_H

#include <pthread.h>
#include <stdbool.h>
#include <netinet/in.h>

// Stores information about a packet
typedef struct {
    struct in_addr src;
    struct in_addr dst;
    uint16_t sport;
    uint16_t dport;
    uint8_t proto;
} t_tuple;

// List of stored packets
typedef struct packet_entry {
    t_tuple tuple;
    struct packet_entry *next;
} t_packet_entry;

// Holds the list, a mutex to protect it and a cond
// (cond works with a mutex and will update when the list has something new to check, that prevents workers from constantly trying and wasting CPU power)
typedef struct {
    t_packet_entry *head;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} t_packet_store;

void packet_store_init(t_packet_store *store);
void packet_store_destroy(t_packet_store *store);
void packet_store_add(t_packet_store *store,
                      struct in_addr src, struct in_addr dst,
                      uint16_t sport, uint16_t dport, uint8_t proto);
bool packet_store_find(t_packet_store *store, const t_tuple *tuple);
bool get_response_for(const t_tuple *tuple, int timeout_ms);

#endif
