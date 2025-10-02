#include "ft_nmap.h"

void    cleanup_config(t_config *config) {
    if (config) {
        free(config);
    }
}

char *trim_whistespaces(char *s)
{
    char *end;

    if (s == NULL) return NULL;

    while (isspace((unsigned char)*s)) s++;

    if (*s == '\0') return s;

    /* trailing */
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) end--;
    end[1] = '\0';

    return (s);
}


/* -------------------------------------------------------------------------
 * DEBUG
 * ------------------------------------------------------------------------- */

 void print_config(const t_config *config)
{
    if (!config) return;

    printf("\n===== Parsed Configuration =====\n");

    // Targets
    printf("Targets (%zu):\n", config->target_count);
    for (size_t i = 0; i < config->target_count; ++i) {
        printf("  [%zu] %s\n", i + 1, config->targets[i]);
    }

    // Ports
    printf("Ports (%zu):\n", config->port_count);
    for (size_t i = 0; i < config->port_count; ++i) {
        printf("  [%zu] %u\n", i + 1, config->ports[i]);
    }

    // Speedup
    printf("Speedup: %d\n", config->speedup);

    // Scans
    const char *scan_names[] = {"SYN", "NULL", "ACK", "FIN", "XMAS", "UDP"};
    printf("Scan types:\n");
    bool any_scan = false;
    for (int i = 0; i < SCAN_TYPE_MAX; ++i) {
        if (config->scans[i]) {
            printf("  - %s\n", scan_names[i]);
            any_scan = true;
        }
    }
    if (!any_scan)
        printf("  (none enabled)\n");

    // Timeout (if relevant)
    printf("Timeout: %d ms\n", config->timeout_ms);

    printf("================================\n\n");
}
