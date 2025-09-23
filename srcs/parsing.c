#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>


/*
    Example usage of getopt long, needs adapting to the project
*/


void print_help(void) {
    printf("Usage: ./ft_nmap [OPTIONS]\n");
    printf("  --help                 Show this help message\n");
    printf("  --ip IP               Target IP address\n");
    printf("  --file FILE           File with list of IPs\n");
    printf("  --ports PORTS         Ports to scan (e.g. 1-1024 or 80,443)\n");
    printf("  --scan TYPES          Scan types (e.g. SYN,NULL,FIN)\n");
    printf("  --speedup N           Number of threads to use (max 250)\n");
}

int main(int argc, char **argv) {
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

    // Example config struct (you'll need to define and use one)
    char *ip = NULL, *file = NULL, *ports = NULL, *scan = NULL;
    int speedup = 0;

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
                ip = optarg;
            } else if (strcmp(opt_name, "file") == 0) {
                file = optarg;
            } else if (strcmp(opt_name, "ports") == 0) {
                ports = optarg;
            } else if (strcmp(opt_name, "scan") == 0) {
                scan = optarg;
            } else if (strcmp(opt_name, "speedup") == 0) {
                speedup = atoi(optarg);
            }
        }
    }

    // Simple debug output
    printf("Parsed args:\n");
    if (ip)      printf("  IP       : %s\n", ip);
    if (file)    printf("  File     : %s\n", file);
    if (ports)   printf("  Ports    : %s\n", ports);
    if (scan)    printf("  Scan     : %s\n", scan);
    printf("  Speedup  : %d\n", speedup);

    // Validate: must have either IP or file
    if (!ip && !file) {
        fprintf(stderr, "Error: Either --ip or --file must be specified.\n");
        return 1;
    }

    // Additional validation (e.g., speedup limit)
    if (speedup < 0 || speedup > 250) {
        fprintf(stderr, "Error: --speedup must be between 0 and 250.\n");
        return 1;
    }

    // Continue with the scan logic...

    return 0;
}
