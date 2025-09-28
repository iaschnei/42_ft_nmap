#ifndef FT_NMAP_H
# define FT_NMAP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h> 
#include <ctype.h> 
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <time.h>

#define MAX_TARGETS 1024
#define MAX_PORTS   1024
#define RES_NOT_PERFORMED  -2
#define RES_NOT_IMPL       -3

enum {
    PORT_RES_CLOSED = 0,
    PORT_RES_OPEN = 1,
    PORT_RES_FILTERED = 2,
    PORT_RES_OPEN_OR_FILTERED = 3
};

typedef struct s_scan_result {
    char *target;    /* strdup'd string, points into config->targets or own strdup */
    int   port;
    int   syn_res;   /* use enum/values above, or RES_NOT_IMPL */
    int   null_res;
    int   fin_res;
    int   xmas_res;
    int   ack_res;
    int   udp_res;
} t_scan_result;


typedef struct s_config {
    char    *ip_target;
    char    *file;
    char    *ports;
    char    *scan_type;

    int     speedup;
    int     port_list[MAX_PORTS];
    int     port_count;

    int     scan_flags;

    char    *targets[MAX_TARGETS];  /* Array of strdup'd target strings */
    int     target_count;

    t_scan_result *results;
    int            result_count;
} t_config;

#define SCAN_SYN    (1 << 0)
#define SCAN_NULL   (1 << 1)
#define SCAN_FIN    (1 << 2)
#define SCAN_XMAS   (1 << 3)
#define SCAN_ACK    (1 << 4)
#define SCAN_UDP    (1 << 5)

void init_config(t_config *config);
void free_config(t_config * config);
int parse_arguments(int argc, char **argv, t_config *config);
int parse_ports(const char *port_str, int *ports_array, int *port_count);
int parse_scan_types(const char *scan_str, int *scan_flags);

int load_targets(t_config *config);

int start_scan(t_config *config);
void print_results(t_config *config);

int start_scan(t_config *config);
void print_results(t_config *config);


#endif
