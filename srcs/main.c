// src/main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ft_nmap.h"

int main(int argc, char **argv) {
    config_t config;

    // Initialize config with defaults
    init_config(&config);

    // Parse command-line arguments
    if (parse_arguments(argc, argv, &config) != 0) {
        fprintf(stderr, "Error: Invalid arguments.\n");
        return EXIT_FAILURE;
    }

    // Load targets from --ip or --file
    if (load_targets(&config) != 0) {
        fprintf(stderr, "Error: Could not load targets.\n");
        return EXIT_FAILURE;
    }

    // Prepare ports to scan
    if (parse_ports(&config) != 0) {
        fprintf(stderr, "Error: Could not parse ports.\n");
        return EXIT_FAILURE;
    }

    // Run scans
    if (start_scan(&config) != 0) {
        fprintf(stderr, "Error: Scan failed.\n");
        return EXIT_FAILURE;
    }

    // Output results
    print_results(&config);

    // Cleanup
    free_config(&config);

    return EXIT_SUCCESS;
}
