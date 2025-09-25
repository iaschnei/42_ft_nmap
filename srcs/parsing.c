#include "ft_nmap.h"

void init_config(t_config *config) {

    config->ip_target = NULL;
    config->file = NULL;
    config->ports = NULL;
    config->scan_type = NULL;
    config->speedup = 60;
    config->port_count = 0;
    config->scan_flags = 0;

}

void print_help(void) {
    printf("Usage: ./ft_nmap [OPTIONS]\n");
    printf("  --help                 Show this help message\n");
    printf("  --ip IP               Target IP address\n");
    printf("  --file FILE           File with list of IPs\n");
    printf("  --ports PORTS         Ports to scan (e.g. 1-1024 or 80,443)\n");
    printf("  --scan TYPES          Scan types (e.g. SYN,NULL,FIN)\n");
    printf("  --speedup N           Number of threads to use (max 250)\n");
}

int parse_arguments(int argc, char **argv, t_config *config) {
    static struct option long_options[] = {
        {"help",     no_argument,       0,  0 },
        {"ip",       required_argument, 0,  0 },
        {"file",     required_argument, 0,  0 },
        {"ports",    required_argument, 0,  0 },
        {"scan",     required_argument, 0,  0 },
        {"speedup",  required_argument, 0,  0 },
        {0,          0,                 0,  0 }
    };

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "", long_options, &option_index)) != -1) {
        if (opt == '?') {
            // Unknown option
            return 1;
        }

        if (opt == 0) {
            const char *opt_name = long_options[option_index].name;

            if (strcmp(opt_name, "help") == 0) {
                print_help();
                return 0;
            } else if (strcmp(opt_name, "ip") == 0) {
                config->ip_target = optarg;
            } else if (strcmp(opt_name, "file") == 0) {
                config->file = optarg;
            } else if (strcmp(opt_name, "ports") == 0) {
                config->ports = optarg;
            } else if (strcmp(opt_name, "scan") == 0) {
                config->scan_type = optarg;
            } else if (strcmp(opt_name, "speedup") == 0) {
                config->speedup = atoi(optarg);
            }
        }
    }

    // Simple debug output
    printf("Parsed args:\n");
    if (config->ip_target)      printf("  IP       : %s\n", config->ip_target);
    if (config->file)    printf("  File     : %s\n", config->file);
    if (config->ports)   printf("  Ports    : %s\n", config->ports);
    if (config->scan_type)    printf("  Scan     : %s\n", config->scan_type);
    printf("  Speedup  : %d\n", config->speedup);

    // Validate: must have either IP or file
    if (!config->ip_target && !config->file) {
        fprintf(stderr, "Error: Either --ip or --file must be specified.\n");
        return 1;
    }

    // Checking speedup (number of threads to use) limit
    if (config->speedup < 0 || config->speedup > 250) {
        fprintf(stderr, "Error: --speedup must be between 0 and 250.\n");
        return 1;
    }

   // Parse ports
    if (config->ports) {
        if (parse_ports(config->ports, config->port_list, &config->port_count) != 0)
            return 1;
    } else {
        // Default range: 1-1024
        config->port_count = 1024;
        for (int i = 0; i < 1024; i++)
            config->port_list[i] = i + 1;
    }

    // Parse scan types
    if (config->scan_type) {
        if (parse_scan_types(config->scan_type, &config->scan_flags) != 0)
            return 1;
    } else {
        // Default: all scan types
        config->scan_flags = SCAN_SYN | SCAN_NULL | SCAN_FIN | SCAN_XMAS | SCAN_ACK | SCAN_UDP;
    }

    return 0;
}

int parse_ports(const char *port_str, int *ports_array, int *port_count) {
    char *input = strdup(port_str);
    char *token = strtok(input, ",");

    *port_count = 0;

    while (token && *port_count < 1024) {
        if (strchr(token, '-')) {
            int start, end;
            if (sscanf(token, "%d-%d", &start, &end) == 2) {
                if (start > end || start < 1 || end > 65535) {
                    fprintf(stderr, "Invalid port range: %s\n", token);
                    free(input);
                    return -1;
                }
                for (int p = start; p <= end && *port_count < 1024; p++) {
                    ports_array[(*port_count)++] = p;
                }
            }
        } else {
            int port = atoi(token);
            if (port < 1 || port > 65535) {
                fprintf(stderr, "Invalid port: %s\n", token);
                free(input);
                return -1;
            }
            ports_array[(*port_count)++] = port;
        }
        token = strtok(NULL, ",");
    }

    free(input);
    return 0;
}

int parse_scan_types(const char *scan_str, int *scan_flags) {
    char *input = strdup(scan_str);
    char *token = strtok(input, ",");

    *scan_flags = 0;

    while (token) {
        if (strcasecmp(token, "SYN") == 0)
            *scan_flags |= SCAN_SYN;
        else if (strcasecmp(token, "NULL") == 0)
            *scan_flags |= SCAN_NULL;
        else if (strcasecmp(token, "FIN") == 0)
            *scan_flags |= SCAN_FIN;
        else if (strcasecmp(token, "XMAS") == 0)
            *scan_flags |= SCAN_XMAS;
        else if (strcasecmp(token, "ACK") == 0)
            *scan_flags |= SCAN_ACK;
        else if (strcasecmp(token, "UDP") == 0)
            *scan_flags |= SCAN_UDP;
        else {
            fprintf(stderr, "Unknown scan type: %s\n", token);
            free(input);
            return -1;
        }

        token = strtok(NULL, ",");
    }

    free(input);
    return 0;
}
