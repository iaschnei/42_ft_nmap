#include "ft_nmap.h"

int load_targets(t_config *config) {
    if (config->ip_target) {
        // Single IP/hostname mode
        config->targets[0] = strdup(config->ip_target);
        if (!config->targets[0]) {
            perror("strdup");
            return -1;
        }
        config->target_count = 1;
    } else if (config->file) {
        FILE *fp = fopen(config->file, "r");
        if (!fp) {
            perror("fopen");
            return -1;
        }

        char line[256];
        config->target_count = 0;

        while (fgets(line, sizeof(line), fp)) {
            /* remove newline */
            line[strcspn(line, "\r\n")] = '\0';
            char *p = line;
            while (*p && isspace((unsigned char)*p)) p++;
            if (*p == '\0' || *p == '#') continue; /* skip empty/comment lines */

            if (config->target_count >= MAX_TARGETS) {
                fprintf(stderr, "Too many targets (max %d)\n", MAX_TARGETS);
                fclose(fp);
                return -1;
            }

            config->targets[config->target_count] = strdup(p);
            if (!config->targets[config->target_count]) {
                perror("strdup");
                fclose(fp);
                return -1;
            }
            config->target_count++;
        }

        fclose(fp);
    } else {
        fprintf(stderr, "No target source provided.\n");
        return -1;
    }

    return 0;
}
