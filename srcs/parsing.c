#include "ft_nmap.h"
#include <bits/getopt_ext.h>
#include <stdio.h>
#include <string.h>

static struct option long_options[] = {
    {"help", no_argument, 0, 'h'},
    {"ip", required_argument, 0, 'i'},
    {"file", required_argument, 0, 'f'},
    {"speedup", required_argument, 0, 's'},
    {"scan", required_argument, 0, 't'},
    {"ports", required_argument, 0, 'p'},
    {0, 0, 0, 0} // end of options
};

static void     display_help();
static int      is_ip_valid(const char *ip, char *resolved_ip);
static int      target_exists(t_config *config, const char *ipstr);
static int      add_target(t_config *config, const char *resolved_ip);
static int      parse_targets_file(const char *filename, t_config *config);
static int      validate_speedup(const char *s, int *out);
static int      validate_and_set_scan(const char *s, t_config *config);
static int      add_port(t_config *config, uint16_t port);
static int      parse_ports(const char *arg, t_config *config);

int parse_args(int ac, char **av, t_config *config) {

    int opt;
    int option_index = 0;

    //Store args locally for check later
    char *ip = NULL;
    char *file = NULL;
    char *speedup = NULL;
    char *scan = NULL;
    char *ports = NULL;

    while ((opt = getopt_long(ac, av, "h:i:f:s:t:p", long_options, &option_index)) != -1) {

        switch (opt) {
            case 'h':
                goto display_help;
            case 'i':
                ip = optarg;
                break;
            case 'f':
                file = optarg;
                break;
            case 's':
                speedup = optarg;
                break;
            case 't':
                scan = optarg;
                break;
            case 'p':
                ports = optarg;
                break;
            default:
                fprintf(stderr, "Error parsing args, unknown arg, see --help\n");
                return (1);
        }
    }

    if (!ip && !file) {
        fprintf(stderr, "Error: --ip or --file is required, see --help\n");
        return (1);
    }


    //Checking every argument
    if (ip) {
        char resolved_ip[16] = {0};
        if (is_ip_valid(ip, resolved_ip)) {
            if (add_target(config, resolved_ip)) {
                fprintf(stderr, "Error: failed to add target %s\n", resolved_ip);
                return (1);
            }
            config->target_count++;
        } else {
            fprintf(stderr, "Error: invalid IP address or domain name\n");
        }
    }
    if (file) {
        if (parse_targets_file(file, config)) {
            return (1);
        }
    }
    if (speedup) {
        if (!validate_speedup(speedup, &config->speedup)) {
            return 1;
        }
    }
    if (!validate_and_set_scan(scan, config)) {
        return 1;
    }
    if (ports) {
        if (!parse_ports(ports, config)) {
            return 1; // error already printed
        }
    }

    
    //Final checks (probably useless since it has been checked before)
    if (config->target_count == 0) {
        fprintf(stderr, "Error: no valid targets found (from --ip or --file)\n");
        return (1);
    }

    return (0);

display_help:
    display_help();
    return (0);

}

static void    display_help() {

    printf("Usage : sudo ./ft_nmap ([--ip xxx.xxx.x.xx] / [--file filename]) [--speedup number] [--scan scan_type] [--ports port/ports_range]\n");
    printf("Note : ip or file are required, both can be specified as well");
    printf("   --ip      =>  target ip or domain name to perform scan on\n");
    printf("   --file    =>  file containing a list of ips/domain names to perform scan on\n");
    printf("   --speedup =>  number of additional threads to use (0-250)\n");
    printf("   --scan    =>  scan type to use (SYN, NULL, ACK, FIN, XMAS, UDP), omit the option to use ALL\n");
    printf("   --ports   =>  single port or ports range (X-X) ports to use for the scan\n");
}

static int is_ip_valid(const char *ip, char *resolved_ip) {

    if (ip == NULL) return 0;

    // Is it an IP ?
    struct in_addr addr4;
    if (inet_pton(AF_INET, ip, &addr4) == 1) {
        // It's a valid IPv4 string
        if (resolved_ip)
            strncpy(resolved_ip, ip, 16 - 1);
        return 1;
    }


    // Is it a valid domain name ?
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;

    int err = getaddrinfo(ip, NULL, &hints, &res);
    if (err != 0 || !res) {
        return 0;
    }

    // Try to resolve the IP from the domain name
    if (resolved_ip) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
        const char *resolved = inet_ntop(AF_INET, &(ipv4->sin_addr), resolved_ip, 16);
        if (!resolved) {
            freeaddrinfo(res);
            return 0;
        }
    }

    freeaddrinfo(res);

    return (1);
}

// Look for duplicate targets in config
static int target_exists(t_config *config, const char *ipstr)
{
    if (!config || !ipstr) return 0;
    for (size_t i = 0; i < config->target_count; ++i) {
        if (config->targets[i] && strcmp(config->targets[i], ipstr) == 0)
            return 1;
    }
    return 0;
}

// Add a target to config
static int add_target(t_config *config, const char *resolved_ip)
{
    if (!config || !resolved_ip) return 1;

    if (config->target_count >= MAX_TARGETS) {
        fprintf(stderr, "Error: reached maximum targets (%d)\n", MAX_TARGETS);
        return 1;
    }

    if (target_exists(config, resolved_ip)) {
        return 0;
    }

    char *dup = strdup(resolved_ip);
    if (!dup) {
        perror("strdup");
        return 1;
    }

    config->targets[config->target_count++] = dup;
    return 0;
}

static int parse_targets_file(const char *filename, t_config *config)
{
    if (!filename || !config) return 1;

    FILE *f = fopen(filename, "r");
    if (!f) {
        perror(filename);
        return 1;
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    char resolved[MAX_IP_STRLEN];

    while ((nread = getline(&line, &len, f)) != -1) {

        char *ptr = trim_whistespaces(line);

        // Skip empty lines
        if (*ptr == '\0' || *ptr == '#') continue;

        memset(resolved, 0, sizeof(resolved));
        if (!is_ip_valid(ptr, resolved)) {
            fprintf(stderr, "Warning: skipping invalid target: %s\n", ptr);
            continue;
        }

        if (add_target(config, resolved)) {
            free(line);
            fclose(f);
            return 1;
        }
    }

    free(line);
    fclose(f);
    return 0;
}

static int validate_speedup(const char *s, int *out)
{
    if (s == NULL) {
        fprintf(stderr, "Error: --speedup requires a value\n");
        return 0;
    }

    char *end = NULL;
    errno = 0;
    long val = strtol(s, &end, 10);

    if (end == s || *end != '\0') {
        fprintf(stderr, "Error: --speedup must be an integer, got '%s'\n", s);
        return 0;
    }
    if (errno == ERANGE || val < 0 || val > MAX_THREADS) {
        fprintf(stderr, "Error: --speedup must be between 0 and %d (got %ld)\n",
                MAX_THREADS, val);
        return 0;
    }

    if (out) *out = (int)val;
    return 1;
}

static int validate_and_set_scan(const char *s, t_config *config)
{
    if (!config) return 0;

    for (size_t i = 0; i < SCAN_TYPE_MAX; ++i) config->scans[i] = false;

    if (s == NULL) {
        for (size_t i = 0; i < SCAN_TYPE_MAX; ++i) config->scans[i] = true;
        return 1;
    }

    if (strcmp(s, "SYN") == 0) {
        config->scans[SCAN_SYN] = true;
        return 1;
    }
    if (strcmp(s, "NULL") == 0) {
        config->scans[SCAN_NULL] = true;
        return 1;
    }
    if (strcmp(s, "ACK") == 0) {
        config->scans[SCAN_ACK] = true;
        return 1;
    }
    if (strcmp(s, "FIN") == 0) {
        config->scans[SCAN_FIN] = true;
        return 1;
    }
    if (strcmp(s, "XMAS") == 0) {
        config->scans[SCAN_XMAS] = true;
        return 1;
    }
    if (strcmp(s, "UDP") == 0) {
        config->scans[SCAN_UDP] = true;
        return 1;
    }

    fprintf(stderr, "Error: invalid --scan value '%s' (allowed: SYN, NULL, ACK, FIN, XMAS, UDP)\n", s);
    return 0;
}

static int add_port(t_config *config, uint16_t port)
{
    if (config->port_count >= MAX_PORTS) {
        fprintf(stderr, "Error: too many ports (max: %d)\n", MAX_PORTS);
        return 0;
    }

    // Optional: skip duplicates
    for (size_t i = 0; i < config->port_count; ++i) {
        if (config->ports[i] == port)
            return 1;
    }

    config->ports[config->port_count++] = port;
    return 1;
}

// Accept a single port or a range (X-X)
int parse_ports(const char *arg, t_config *config)
{
    if (!arg || !config) return 0;

    char *copy = strdup(arg);
    if (!copy) {
        perror("strdup");
        return 0;
    }

    char *dash = strchr(copy, '-');
    char *endptr = NULL;
    long start_port, end_port;

    if (dash == NULL) {
        errno = 0;
        start_port = strtol(copy, &endptr, 10);
        free(copy);

        if (errno != 0 || start_port < 1 || start_port > 65535) {
            fprintf(stderr, "Error: invalid port number '%s'\n", arg);
            return 0;
        }

        return add_port(config, (uint16_t)start_port);
    }

    // Port range
    *dash = '\0';
    const char *start_str = copy;
    const char *end_str = dash + 1;

    errno = 0;
    start_port = strtol(start_str, &endptr, 10);
    if (*endptr != '\0' || errno != 0 || start_port < 1 || start_port > 65535) {
        fprintf(stderr, "Error: invalid start port in range '%s'\n", start_str);
        free(copy);
        return 0;
    }

    errno = 0;
    end_port = strtol(end_str, &endptr, 10);
    if (*endptr != '\0' || errno != 0 || end_port < 1 || end_port > 65535) {
        fprintf(stderr, "Error: invalid end port in range '%s'\n", end_str);
        free(copy);
        return 0;
    }

    free(copy);

    if (start_port > end_port) {
        fprintf(stderr, "Error: port range must be in ascending order: %ld-%ld\n", start_port, end_port);
        return 0;
    }

    for (long port = start_port; port <= end_port; ++port) {
        if (!add_port(config, (uint16_t)port)) {
            return 0;
        }
    }

    return 1;
}
