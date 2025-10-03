#include "ft_nmap.h"


// Worker's start function
void *worker_thread_func(void *arg)
{
    t_worker_args *args = (t_worker_args *)arg;
    scan_task task;

    while (task_queue_pop(args->queue, &task) == 1) {

        printf("[Worker %d] Scanning %s:%d (%d)\n", args->id, task.target, task.port, task.scan);

        
        // TODO: Replace with actual scan function:
        // perform_scan(&task, args->config);

        usleep(100000);
    }

    return NULL;
}

// Global workers launching
int launch_workers(t_task_queue *queue, const t_config *config)
{
    int thread_count = config->speedup;
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
