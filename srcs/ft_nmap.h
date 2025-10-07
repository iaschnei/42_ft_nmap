#ifndef FT_NMAP_H
#define FT_NMAP_H

/* -------------------------------------------------------------------------
 * Includes
 * ------------------------------------------------------------------------- */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <pthread.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * Constants
 * ------------------------------------------------------------------------- */
#define MAX_TARGETS        512
#define MAX_PORTS          1024
#define MAX_THREADS        250
#define DEFAULT_TIMEOUT_MS 2000
#define DEFAULT_PORT_START 1
#define DEFAULT_PORT_END   1024
#define MAX_IP_STRLEN      16
#define MAX_SERVICE_NAME   64
#define MAX_RAWINFO        128

typedef enum {
    SCAN_SYN = 0,
    SCAN_NULL,
    SCAN_ACK,
    SCAN_FIN,
    SCAN_XMAS,
    SCAN_UDP,
    SCAN_TYPE_MAX
} e_scan_type;

typedef enum {
    RES_UNKNOWN = 0,
    RES_OPEN,
    RES_CLOSED,
    RES_FILTERED,
    RES_UNFILTERED,
    RES_OPEN_OR_FILTERED
} e_scan_result;

typedef struct {
    char *targets[MAX_TARGETS];         /* tableau de chaînes (IP ou FQDN) */
    size_t target_count;
    uint16_t ports[MAX_PORTS];
    size_t port_count;
    int speedup;            /* nombre de threads demandés (0 -> default) */
    bool scans[SCAN_TYPE_MAX]; /* bitset des scans demandés */
    int timeout_ms;         /* timeout en millisecondes pour attendre réponses */
} t_config;

/* -------------------------------------------------------------------------
 * Tâche élémentaire (unit de travail poussée dans la queue)
 * ------------------------------------------------------------------------- */

typedef struct scan_task {
    char target[MAX_IP_STRLEN];
    uint16_t port;
    e_scan_type scan;
    struct scan_task *next;
} scan_task;

typedef struct {
    scan_task *head;
    scan_task *tail;
    size_t size;
    bool closed;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} t_task_queue;

/* -------------------------------------------------------------------------
 * Résultat d'un scan individuel
 * ------------------------------------------------------------------------- */
typedef struct {
    e_scan_type scan;
    e_scan_result conclusion;
    char raw_info[MAX_RAWINFO]; /* texte additionnel (ex: "ICMP Type 3 Code 3") */
} t_scan_result;

/* -------------------------------------------------------------------------
 * Rapport pour un port (agrège résultats des différents scans sur ce port)
 * ------------------------------------------------------------------------- */
typedef struct {
    char target[MAX_IP_STRLEN];
    uint16_t port;
    char service[MAX_SERVICE_NAME];
    t_scan_result results[SCAN_TYPE_MAX];
    size_t result_count;
} t_port_report;

typedef struct {
    int id;
    t_task_queue *queue;
    const t_config *config;
} t_worker_args;


extern t_port_report g_reports[MAX_TARGETS * MAX_PORTS];
extern size_t g_report_count;
extern pthread_mutex_t g_report_mutex;


int parse_args(int ac, char **av, t_config *config);

const char *result_to_str(e_scan_result res);
const char *scan_type_to_string(e_scan_type t);
void    cleanup_config(t_config *config);
char    *trim_whistespaces(char *s);
void    print_config(const t_config *config);
const char *resolve_service_name(uint16_t port, e_scan_type scan);
void display_report(const t_config *config);
t_port_report *get_or_create_report(const char *target, uint16_t port);

int task_queue_init(t_task_queue *q);
int populate_task_queue(t_task_queue *queue, const t_config *config);
void task_queue_destroy(t_task_queue *q);
int task_queue_push(t_task_queue *q, const scan_task *task);
int task_queue_pop(t_task_queue *q, scan_task *out);
int task_queue_try_pop(t_task_queue *q, scan_task *out);
void task_queue_close(t_task_queue *q);
size_t task_queue_size(t_task_queue *q);

int launch_workers(t_task_queue *queue, const t_config *config);

#endif
