#include "ft_nmap.h"

int main(int ac, char **av) {

    t_config    *config = malloc(sizeof(t_config));
    if (config == NULL) {
        perror("malloc:");
        return (1);
    }

    config->port_count = 0;
    config->speedup = 60;

    if (parse_args(ac, av, config) != 0) {
        cleanup_config(config);
        return (1);
    }

    print_config(config);

    return (0);
}