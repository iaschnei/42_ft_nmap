#include "ft_nmap.h"

/* Helper: convert scan-res integer to string for a particular scan type */
static const char *res_to_str(int res) {
    switch (res) {
    case RES_NOT_PERFORMED:
        return "-";
    case RES_NOT_IMPL:
        return "N/I";
    case PORT_RES_OPEN:
        return "Open";
    case PORT_RES_CLOSED:
        return "Closed";
    case PORT_RES_FILTERED:
        return "Filtered";
    case PORT_RES_OPEN_OR_FILTERED:
        return "Open|Filtered";
    default:
        return "?";
    }
}

/* Print header for a target */
static void print_target_header(const char *target, int port_count, int scan_flags, int speedup) {
    printf("Scan Configurations\n");
    printf("Target Ip-Address : %s\n", target);
    printf("No of Ports to scan : %d\n", port_count);
    printf("Scans to be performed : ");
    int first = 1;
    if (scan_flags & SCAN_SYN)   { printf(first?"SYN":" SYN"); first = 0; }
    if (scan_flags & SCAN_NULL)  { printf(first?"NULL":" NULL"); first = 0; }
    if (scan_flags & SCAN_FIN)   { printf(first?"FIN":" FIN"); first = 0; }
    if (scan_flags & SCAN_XMAS)  { printf(first?"XMAS":" XMAS"); first = 0; }
    if (scan_flags & SCAN_ACK)   { printf(first?"ACK":" ACK"); first = 0; }
    if (scan_flags & SCAN_UDP)   { printf(first?"UDP":" UDP"); first = 0; }
    printf("\n");
    printf("No of threads : %d\n", speedup);
    printf("Scanning..\n");
}

/* Print blank lines or dots as progress indicator — optional */
static void print_progress(int i, int total) {
    /* simple: print a dot every so often */
    if (i % 50 == 0) putchar('.');
}

/* The main print function */
void print_results(t_config *config) {
    if (!config || !config->results) {
        fprintf(stderr, "No results to print\n");
        return;
    }

    /* For each target, print its scan result block */
    for (int t = 0; t < config->target_count; ++t) {
        /* Collect results for this target */
        char *target = config->targets[t];
        print_target_header(target, config->port_count, config->scan_flags, config->speedup);

        /* Build "Open ports" and "Closed/Filtered" lists */
        printf("Open ports:\n");
        printf("Port  Service  ");
        /* For each scan type, print column header as “TYPE(Result)” */
        int use_udp = (config->scan_flags & SCAN_UDP) != 0;
        printf("Results\n");
        printf("---------------------------------------------------------------\n");

        for (int i = 0; i < config->result_count; ++i) {
            t_scan_result *res = &config->results[i];
            if (strcmp(res->target, target) != 0) continue;
            /* If any of the scan_res indicates open, list it here */
            int is_open = 0;
            if (config->scan_flags & SCAN_SYN && res->syn_res == PORT_RES_OPEN) is_open = 1;
            if (config->scan_flags & SCAN_UDP && res->udp_res == PORT_RES_OPEN_OR_FILTERED) is_open = 1;
            /* Could also treat “Open|Filtered” less strictly, per your spec */

            if (is_open) {
                printf("%5d  %-8s  ", res->port,
                       "(service)");  /* TODO: service name resolution if you add */
                if (config->scan_flags & SCAN_SYN)
                    printf("SYN(%s) ", res_to_str(res->syn_res));
                if (config->scan_flags & SCAN_NULL)
                    printf("NULL(%s) ", res_to_str(res->null_res));
                if (config->scan_flags & SCAN_FIN)
                    printf("FIN(%s) ", res_to_str(res->fin_res));
                if (config->scan_flags & SCAN_XMAS)
                    printf("XMAS(%s) ", res_to_str(res->xmas_res));
                if (config->scan_flags & SCAN_ACK)
                    printf("ACK(%s) ", res_to_str(res->ack_res));
                if (use_udp)
                    printf("UDP(%s) ", res_to_str(res->udp_res));
                printf("Open\n");
            }
        }

        printf("Closed/Filtered/Unfiltered ports:\n");
        printf("Port  Service    Results\n");
        printf("---------------------------------------------------------------\n");

        for (int i = 0; i < config->result_count; ++i) {
            t_scan_result *res = &config->results[i];
            if (strcmp(res->target, target) != 0) continue;
            /* If *no* scan shows “open”, then list here */
            int any_open = 0;
            if ((config->scan_flags & SCAN_SYN) && res->syn_res == PORT_RES_OPEN) any_open = 1;
            if ((config->scan_flags & SCAN_UDP) && res->udp_res == PORT_RES_OPEN_OR_FILTERED) any_open = 1;
            if (any_open) continue;

            printf("%5d  %-8s  ", res->port, "(service)");
            if (config->scan_flags & SCAN_SYN)
                printf("SYN(%s) ", res_to_str(res->syn_res));
            if (config->scan_flags & SCAN_NULL)
                printf("NULL(%s) ", res_to_str(res->null_res));
            if (config->scan_flags & SCAN_FIN)
                printf("FIN(%s) ", res_to_str(res->fin_res));
            if (config->scan_flags & SCAN_XMAS)
                printf("XMAS(%s) ", res_to_str(res->xmas_res));
            if (config->scan_flags & SCAN_ACK)
                printf("ACK(%s) ", res_to_str(res->ack_res));
            if (use_udp)
                printf("UDP(%s) ", res_to_str(res->udp_res));
            printf("Closed/Filtered\n");
        }

        printf("\n");
    }
}
