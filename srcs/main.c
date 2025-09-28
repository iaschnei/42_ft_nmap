#include "ft_nmap.h"

int main(int argc, char **argv) {
    t_config *config;

    config = malloc(sizeof(t_config));
    if (!config) {
        fprintf(stderr, "Error with malloc, aborting\n");
        return EXIT_FAILURE;
    }

    /* Initialize config with defaults */
    init_config(config);

    /* Parse command-line arguments */
    if (parse_arguments(argc, argv, config) != 0) {
        fprintf(stderr, "Error: Invalid arguments.\n");
        free_config(config);
        return EXIT_FAILURE;
    }

    /* Load targets from --ip or --file */
    if (load_targets(config) != 0) {
        fprintf(stderr, "Error: Could not load targets.\n");
        free_config(config);
        return EXIT_FAILURE;
    }

    /* Run scans */
    if (start_scan(config) != 0) {
        fprintf(stderr, "Error: Scan failed.\n");
        free_config(config);
        return EXIT_FAILURE;
    }

    /* Output results */
    print_results(config);

    /* Cleanup */
    free_config(config);

    return EXIT_SUCCESS;
}

void free_config(t_config *config) {
    if (!config) return;

    if (config->ip_target) { free(config->ip_target); config->ip_target = NULL; }
    if (config->file)      { free(config->file); config->file = NULL; }
    if (config->ports)     { free(config->ports); config->ports = NULL; }
    if (config->scan_type) { free(config->scan_type); config->scan_type = NULL; }

    for (int i = 0; i < config->target_count; i++) {
        if (config->targets[i]) {
            free(config->targets[i]);
            config->targets[i] = NULL;
        }
    }

    /* free results array and their target strings (if allocated) */
    if (config->results) {
        for (int i = 0; i < config->result_count; ++i) {
            if (config->results[i].target) {
                free(config->results[i].target);
                config->results[i].target = NULL;
            }
        }
        free(config->results);
        config->results = NULL;
        config->result_count = 0;
    }

    free(config);
}
