#include "ft_nmap.h"
#include "tcp_scan.h"

void *worker_thread_func(void *arg)
{
    t_worker_args *args = (t_worker_args *)arg;
    scan_task task;

    //debug
    printf("[Worker %d] Started\n", args->id);

    while (task_queue_pop(args->queue, &task) == 1) {

        // Only TCP scans here; UDP handled elsewhere if implemented
        e_scan_type st = task.scan;

        if (st == SCAN_UDP) {
            // TODO: integrate UDP scan; skip for now
            continue;
        }

        e_scan_result res = RES_UNKNOWN;
        if (probe_tcp_target(task.target, (uint16_t)task.port, st, 2000, &res) < 0) {
            fprintf(stderr, "[Worker %d] %s:%d %s -> error: %s", args->id, task.target, task.port, scan_type_to_string(st), strerror(errno));
        } else {
            const char *svc = resolve_service_name(task.port, st);
            printf("Port %d %s %s(%s)\n",
                task.port,
                svc,
                scan_type_to_string(st),
                result_to_str(res));

            fflush(stdout);
        }
    }

    //debug
    printf("[Worker %d] Exiting\n", args->id); // <--- ADD THIS LINE

    return NULL;
}

// Global workers launching
int launch_workers(t_task_queue *queue, const t_config *config)
{
    int thread_count = config->speedup;

    //debug
    printf("Launching workers: speedup = %d\n", thread_count);

    if (thread_count <= 0) {
        // Run directly in main thread
        t_worker_args args = {.id = 0, .queue = queue, .config = config};
        worker_thread_func(&args);
        return 0;
    }

    if (thread_count > MAX_THREADS) thread_count = MAX_THREADS;

    pthread_t threads[MAX_THREADS];
    t_worker_args args[MAX_THREADS];

    for (int i = 0; i < thread_count; ++i) {
        args[i].id = i + 1;
        args[i].queue = queue;
        args[i].config = config;

        if (pthread_create(&threads[i], NULL, worker_thread_func, &args[i]) != 0) {
            perror("pthread_create");
            return -1;
        }
    }

    for (int i = 0; i < thread_count; ++i) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}

const char *result_to_str(e_scan_result res)
{
    switch (res) {
        case RES_OPEN:             return "Open";
        case RES_CLOSED:           return "Closed";
        case RES_FILTERED:         return "Filtered";
        case RES_UNFILTERED:       return "Unfiltered";
        case RES_OPEN_OR_FILTERED: return "Open|Filtered";
        default:                   return "Unknown";
    }
}

const char *scan_type_to_string(e_scan_type t)
{
    switch (t) {
        case SCAN_SYN:  return "SYN";
        case SCAN_NULL: return "NULL";
        case SCAN_ACK:  return "ACK";
        case SCAN_FIN:  return "FIN";
        case SCAN_XMAS: return "XMAS";
        case SCAN_UDP:  return "UDP";
        default:        return "UNKNOWN";
    }
}
