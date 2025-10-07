#include "ft_nmap.h"

void    cleanup_config(t_config *config) {
    //TODO
    for (size_t i = 0; i < config->target_count; ++i)
        free(config->targets[i]);
    printf("cleaning up");
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

const char *resolve_service_name(uint16_t port, e_scan_type scan) {
    // pick "tcp" or "udp" based on scan
    const char *proto = (scan == SCAN_UDP) ? "udp" : "tcp";
    struct servent *s = getservbyport(htons(port), proto);
    if (s && s->s_name) return s->s_name;
    return "Unassigned"; // fallback
}

// Used to add reports to our global structure
t_port_report *get_or_create_report(const char *target, uint16_t port) {
    for (size_t i = 0; i < g_report_count; ++i) {
        if (strcmp(g_reports[i].target, target) == 0 && g_reports[i].port == port)
            return &g_reports[i];
    }

    if (g_report_count >= MAX_TARGETS * MAX_PORTS)
        return NULL;

    t_port_report *rep = &g_reports[g_report_count++];
    memset(rep, 0, sizeof(*rep));
    strncpy(rep->target, target, MAX_IP_STRLEN - 1);
    rep->port = port;

    struct servent *s = getservbyport(htons(port), "tcp");
    if (s) strncpy(rep->service, s->s_name, MAX_SERVICE_NAME - 1);
    else strncpy(rep->service, "Unassigned", MAX_SERVICE_NAME - 1);

    return rep;
}

void display_report(const t_config *config) {
    printf("\nScan complete. Results:\n");

    for (size_t t = 0; t < config->target_count; ++t) {
        const char *target = config->targets[t];
        printf("\nIP address: %s\n", target);

        printf("\nOpen ports:\n");
        printf("Port  Service     Results                          Conclusion\n");
        printf("-------------------------------------------------------------\n");
        for (size_t i = 0; i < g_report_count; ++i) {
            t_port_report *rep = &g_reports[i];
            if (strcmp(rep->target, target) != 0) continue;

            bool is_open = false;
            for (size_t j = 0; j < rep->result_count; ++j) {
                if (rep->results[j].conclusion == RES_OPEN) {
                    is_open = true;
                    break;
                }
            }
            if (!is_open) continue;

            printf("%-5u %-11s ", rep->port, rep->service);
            for (size_t j = 0; j < rep->result_count; ++j)
                printf("%s ", rep->results[j].raw_info);
            printf("Open\n");
        }

        printf("\nClosed/Filtered/Unfiltered ports:\n");
        printf("Port  Service     Results                          Conclusion\n");
        printf("-------------------------------------------------------------\n");
        for (size_t i = 0; i < g_report_count; ++i) {
            t_port_report *rep = &g_reports[i];
            if (strcmp(rep->target, target) != 0) continue;

            bool is_open = false;
            for (size_t j = 0; j < rep->result_count; ++j) {
                if (rep->results[j].conclusion == RES_OPEN) {
                    is_open = true;
                    break;
                }
            }
            if (is_open) continue;

            printf("%-5u %-11s ", rep->port, rep->service);
            for (size_t j = 0; j < rep->result_count; ++j)
                printf("%s ", rep->results[j].raw_info);

            printf("%s\n", result_to_str(rep->results[0].conclusion));
        }
    }
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
