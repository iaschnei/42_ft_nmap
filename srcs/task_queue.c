#include "ft_nmap.h"

// Functions related to the task queue 
// A task is a scan of a certain type on a certain port of a certain IP
// Total number of tasks is number_of_targets(IP) * number_of_ports * number_of_scans_types
// Workers (threads) take tasks until there are none left

int task_queue_init(t_task_queue *q)
{
    if (!q) return -1;
    q->head = q->tail = NULL;
    q->size = 0;
    q->closed = false;
    if (pthread_mutex_init(&q->mutex, NULL) != 0) return -1;
    if (pthread_cond_init(&q->cond, NULL) != 0) {
        pthread_mutex_destroy(&q->mutex);
        return -1;
    }
    return 0;
}

int populate_task_queue(t_task_queue *queue, const t_config *config)
{
    if (!queue || !config) return -1;

    for (size_t t = 0; t < config->target_count; ++t) {
        const char *target_ip = config->targets[t];

        for (size_t p = 0; p < config->port_count; ++p) {
            uint16_t port = config->ports[p];

            for (e_scan_type st = 0; st < SCAN_TYPE_MAX; ++st) {
                if (!config->scans[st]) continue;

                scan_task task;
                memset(&task, 0, sizeof(scan_task));
                strncpy(task.target, target_ip, MAX_IP_STRLEN - 1);
                task.port = port;
                task.scan = st;

                if (task_queue_push(queue, &task) != 0) {
                    fprintf(stderr, "Error: failed to push task for %s:%u (scan %d)\n",
                            target_ip, port, st);
                    return -1;
                }
            }
        }
    }

    return 0;
}

void task_queue_destroy(t_task_queue *q)
{
    if (!q) return;

    /* free any remaining nodes */
    pthread_mutex_lock(&q->mutex);
    scan_task *cur = q->head;
    while (cur) {
        scan_task *next = cur->next;
        free(cur);
        cur = next;
    }
    q->head = q->tail = NULL;
    q->size = 0;
    pthread_mutex_unlock(&q->mutex);

    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->cond);
}

static scan_task *alloc_node_from(const scan_task *task)
{
    scan_task *node = (scan_task *)malloc(sizeof(scan_task));
    if (!node) return NULL;
    /* copy fields */
    node->port = task->port;
    node->scan = task->scan;
    node->next = NULL;
    /* safe copy of target */
    strncpy(node->target, task->target, MAX_IP_STRLEN - 1);
    node->target[MAX_IP_STRLEN - 1] = '\0';
    return node;
}

int task_queue_push(t_task_queue *q, const scan_task *task)
{
    if (!q || !task) return -1;
    pthread_mutex_lock(&q->mutex);
    if (q->closed) {
        pthread_mutex_unlock(&q->mutex);
        return -1; /* cannot push to closed queue */
    }
    scan_task *node = alloc_node_from(task);
    if (!node) {
        pthread_mutex_unlock(&q->mutex);
        return -1;
    }
    if (q->tail == NULL) {
        q->head = q->tail = node;
    } else {
        q->tail->next = node;
        q->tail = node;
    }
    q->size++;
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->mutex);
    return 0;
}

int task_queue_pop(t_task_queue *q, scan_task *out)
{
    if (!q || !out) return -1;
    pthread_mutex_lock(&q->mutex);
    for (;;) {
        if (q->head != NULL) break;
        if (q->closed) {
            /* no more tasks will arrive */
            pthread_mutex_unlock(&q->mutex);
            return 0;
        }
        /* wait for tasks or close */
        pthread_cond_wait(&q->cond, &q->mutex);
    }

    /* take head */
    scan_task *node = q->head;
    q->head = node->next;
    if (q->head == NULL) q->tail = NULL;
    q->size--;
    /* copy out */
    memcpy(out, node, sizeof(scan_task));
    /* the copied 'next' pointer in out is irrelevant for user; zero it */
    out->next = NULL;
    free(node);
    pthread_mutex_unlock(&q->mutex);
    return 1;
}


// Non-blocking check if queue is empty or has tasks
int task_queue_try_pop(t_task_queue *q, scan_task *out)
{
    if (!q || !out) return -1;
    pthread_mutex_lock(&q->mutex);
    if (q->head == NULL) {
        pthread_mutex_unlock(&q->mutex);
        return 0;
    }
    scan_task *node = q->head;
    q->head = node->next;
    if (q->head == NULL) q->tail = NULL;
    q->size--;
    memcpy(out, node, sizeof(scan_task));
    out->next = NULL;
    free(node);
    pthread_mutex_unlock(&q->mutex);
    return 1;
}

void task_queue_close(t_task_queue *q)
{
    if (!q) return;
    pthread_mutex_lock(&q->mutex);
    q->closed = true;
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_unlock(&q->mutex);
}

size_t task_queue_size(t_task_queue *q)
{
    if (!q) return 0;
    pthread_mutex_lock(&q->mutex);
    size_t s = q->size;
    pthread_mutex_unlock(&q->mutex);
    return s;
}