#ifndef FT_NMAP_H
# define FT_NMAP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

typedef struct s_config {
    char    *ip_target;
    char    *file;
    char    *ports;
    char    *scan_type;

    int     speedup;
    int     port_list[1024];
    int     port_count;

    int     scan_flags;
} t_config;


#define SCAN_SYN    (1 << 0)
#define SCAN_NULL   (1 << 1)
#define SCAN_FIN    (1 << 2)
#define SCAN_XMAS   (1 << 3)
#define SCAN_ACK    (1 << 4)
#define SCAN_UDP    (1 << 5)

void init_config(t_config *config);
int parse_arguments(int argc, char **argv, t_config *config);
int parse_ports(const char *port_str, int *ports_array, int *port_count);
int parse_scan_types(const char *scan_str, int *scan_flags);



#endif