// src/main.c
#include "ft_nmap.h"

int main(int argc, char **argv) {
    t_config *config;

    config = malloc(sizeof(t_config));
    if (!config) {
        fprintf(stderr, "Error with malloc, aborting");
        return EXIT_FAILURE;
    }

    // Initialize config with defaults
    init_config(config);

    // Parse command-line arguments
    if (parse_arguments(argc, argv, config) != 0) {
        fprintf(stderr, "Error: Invalid arguments.\n");
        free_config(config);
        return EXIT_FAILURE;
    }

    // Load targets from --ip or --file
    if (load_targets(&config) != 0) {
        fprintf(stderr, "Error: Could not load targets.\n");
        free_config(config);
        return EXIT_FAILURE;
    }

    // Prepare ports to scan
    if (parse_ports(&config) != 0) {
        fprintf(stderr, "Error: Could not parse ports.\n");
        free_config(config);
        return EXIT_FAILURE;
    }

    // Run scans
    if (start_scan(&config) != 0) {
        fprintf(stderr, "Error: Scan failed.\n");
        free_config(config);
        return EXIT_FAILURE;
    }

    // Output results
    print_results(&config);

    // Cleanup
    free_config(config);

    return EXIT_SUCCESS;
}

void    free_config(t_config * config) {

    if (config->ip_target) {
        free(config->ip_target);
    }
    if (config->file) {
        free(config->file);
    }
    if (config->ports) {
        free(config->ports);
    }
    if (config->scan_type) {
        free(config->scan_type);
    }

    free(config);
}