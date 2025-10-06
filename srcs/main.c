#include "capture.h"
#include "ft_nmap.h"
#include "packet_store.h"

t_packet_store g_store; 

int main(int ac, char **av) {

    t_config config = {0};
    t_task_queue queue = {0};

    if (parse_args(ac, av, &config) != 0) {
        cleanup_config(&config);
        return (1);
    }

    //debug
    print_config(&config);

     if (task_queue_init(&queue) != 0) {
        fprintf(stderr, "Error: could not initialize task queue\n");
        cleanup_config(&config);
        return 1;
    }

    if (populate_task_queue(&queue, &config) != 0) {
        fprintf(stderr, "Error: failed to populate task queue\n");
        task_queue_destroy(&queue);
        cleanup_config(&config);
        return 1;
    }

    //debug
    printf("Task queue populated with %zu tasks\n", task_queue_size(&queue));

    task_queue_close(&queue);

    // Initialise packet storage
    packet_store_init(&g_store);

    // Initialise capture
    t_capture capture;
    const char *iface = "enp4s0"; //TODO : change that based on ifconfig's result on the VM  
    if (capture_start(&capture, iface, &config) != 0) {
        fprintf(stderr, "Failed to start capture\n");
        return 1;
    }

    if (launch_workers(&queue, &config) != 0) {
        fprintf(stderr, "Error launching workers\n");
        task_queue_destroy(&queue);
        cleanup_config(&config);
        return 1;
    }

    task_queue_destroy(&queue);
    capture_stop(&capture);
    packet_store_destroy(&g_store);
    cleanup_config(&config);

    return (0);
}