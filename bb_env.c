#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <mtd/mtd-user.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CONFIG_BLOCK_SIZE   0x2000
#define CONFIG_BLOCK_OFFSET 0x4000

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

struct config {
    // v1
    uint32_t version;
    uint8_t boot_source;
    uint8_t console;
    uint8_t nic;
    uint8_t boot_type;
    uint32_t load_address;
    char cmdline[1024];
    uint16_t kernel_max;
    uint8_t button;
    // v2
    uint8_t upgrade_available;
    uint8_t boot_count;
    uint8_t boot_part;
} __attribute__((packed));

struct config_block {
    struct config cfg;
    char padding[CONFIG_BLOCK_SIZE - sizeof(struct config) - 128/8 /* md5 */];
    char md5[128/8];
} __attribute__((packed));

int read_config_block(struct config_block *blk)
{
    int rv = 0;
    int fd = open("/dev/mtd0ro", O_RDONLY);
	if (fd < 0) {
        rv = errno;
		perror("open");
		return rv;
	}

	if (lseek(fd, CONFIG_BLOCK_OFFSET, SEEK_SET) < 0) {
        rv = errno;
        perror("lseek");
        goto out;
    }

    if (read(fd, blk, sizeof(*blk)) < 0) {
        rv = errno;
        perror("read");
        goto out;
    }
out:
    close(fd);
    return rv;
}

static const char * config_strings[] = {
    "version",
    "bootsource",
    "console",
    "nic",
    "boottype",
    "loadaddress",
    "cmndline", // [sic]
    "kernelmax",
    "button",
    "upgrade",
    "upgrade_available", // same as "upgrade"
    "bootcount",
    "boot_part",
};

bool valid_config_variable(const char* variable)
{
    for (int i = 0; i < ARRAY_SIZE(config_strings); ++i) {
        if (!strcmp(variable, config_strings[i])) {
            return true;
        }
    }

    return false;
}

int compare_and_print_header(const char* key, const char* variable, bool header)
{
    int rv = strcmp(variable, key);
    if (!rv && header) {
        printf("%s=", variable);
    }
    return rv;
}

int print_config(const struct config * const cfg, const int start, const int end, const char *variables[], const bool header)
{
    int rv = 0;
    for (int i = start; i < end; ++i) {
        const char * variable = variables[i];
        if (!compare_and_print_header("version", variable, header)) {
            printf("%d\n", cfg->version);
        }
        else if (!compare_and_print_header("bootsource", variable, header)) {
            printf("%d\n", cfg->boot_source);
        }
        else if (!compare_and_print_header("console", variable, header)) {
            printf("%d\n", cfg->console);
        }
        else if (!compare_and_print_header("nic", variable, header)) {
            printf("%d\n", cfg->nic);
        }
        else if (!compare_and_print_header("boottype", variable, header)) {
            printf("%d\n", cfg->boot_type);
        }
        else if (!compare_and_print_header("loadaddress", variable, header)) {
            printf("0x%X\n", cfg->load_address);
        }
        else if (!compare_and_print_header("cmndline", variable, header)) {
            printf("%s\n", cfg->cmdline);
        }
        else if (!compare_and_print_header("kernelmax", variable, header)) {
            printf("0x%x\n", cfg->kernel_max);
        }
        else if (!compare_and_print_header("button", variable, header)) {
            printf("%d\n", cfg->button);
        }
        else if (cfg->version >= 2 && !compare_and_print_header("upgrade", variable, header)) {
            printf("%d\n", cfg->upgrade_available);
        }
        else if (cfg->version >= 2 && !compare_and_print_header("upgrade_available", variable, header)) {
            printf("%d\n", cfg->upgrade_available);
        }
        else if (cfg->version >= 2 && !compare_and_print_header("bootcount", variable, header)) {
            printf("%d\n", cfg->boot_count);
        }
        else if (cfg->version >= 2 && !compare_and_print_header("boot_part", variable, header)) {
            printf("%d\n", cfg->boot_part);
        }
        else {
            fprintf(stderr, "## Error: \"%s\" not defined\n", variable);
            rv = -1;
        }
    }
    return rv;
}

int bb_printenv(const char* exe, int argc, char *argv[])
{
    static const char * printenv_usage =
        "Usage: %s [OPTIONS]... [VARIABLE]...\n"
        "Print variables from biffboot config\n"
        "\n"
        " -h, --help           print this help.\n"
        " -n, --noheader       do not repeat variable name in output\n"
        "\n";
    static struct option printenv_options[] = {
        {"help",     no_argument, 0, 'h'},
        {"noheader", no_argument, 0, 'n'},
        {0,          0,           0,  0 },
    };
    int c;
    bool header = true;
    struct config_block *blk;
    
    while ((c = getopt_long(argc, argv, "hn", printenv_options, NULL)) != -1) {
        switch (c) {
        case 'h':
            printf(printenv_usage, exe);
            return 0;
        case 'n':
            header = false;
            break;
        case '?':
        default:
            printf(printenv_usage, exe);
            return -1;
        };
    }
    if (!header) {
        if ((optind+1) != argc) {
            fprintf(stderr, "## Error: `-n' option requires exactly one argument\n");
            return -1;
        }
        if (!valid_config_variable(argv[optind])) {
            fprintf(stderr, "## Error: \"%s\" not defined\n", argv[optind]);
            return -1;
        }
    }

    blk = malloc(sizeof(struct config_block));
    if (!blk) {
        perror("malloc");
        return -ENOMEM;
    }
    c = read_config_block(blk);
    if (c == 0) {
        if (optind == argc) {
            c = print_config(&blk->cfg, 0, ARRAY_SIZE(config_strings), config_strings, header);
        }
        else {
            c = print_config(&blk->cfg, optind, argc, (const char**)argv, header);
        }
    }
    free(blk);
    return c;
}

int bb_setenv(const char* exe, int argc, char *argv[])
{
    static const char * setenv_usage =
        "Usage: %s [OPTIONS]... [VARIABLE]...\n"
        "Modify variables in biffboot config\n"
        "\n"
        " -h, --help           print this help.\n"
        "\n";
    static struct option setenv_options[] = {
        {"help",     no_argument, 0, 'h'},
        {0,          0,           0,  0 },
    };
    int c;
    const char* variable;
    
    while ((c = getopt_long(argc, argv, "h", setenv_options, NULL)) != -1) {
        switch (c) {
        case 'h':
            printf(setenv_usage, exe);
            return 0;
        case '?':
        default:
            printf(setenv_usage, exe);
            return -1;
        };
    }

    if (argc <= optind) {
        fprintf(stderr, "## Error: variable name missing\n");
        return -1;
    }

    variable = argv[optind];

    if (!strcmp("version", variable)) {
    }
    else if (!strcmp("bootsource", variable)) {
    }
    else if (!strcmp("console", variable)) {
    }
    else if (!strcmp("nic", variable)) {
    }
    else if (!strcmp("boottype", variable)) {
    }
    else if (!strcmp("loadaddress", variable)) {
    }
    else if (!strcmp("cmndline", variable)) {
    }
    else if (!strcmp("kernelmax", variable)) {
    }
    else if (!strcmp("button", variable)) {
    }
    else if (!strcmp("upgrade", variable) || !strcmp("upgrade_available", variable)) {
    }
    else if (!strcmp("bootcount", variable)) {
    }
    else if (!strcmp("boot_part", variable)) {
    }
    else {
        // silently ignore
    }
    return 0;
}

// POSIX basename might alter path, so work with copies
const char * get_executable_name(const char * argv0)
{
    char * path = strdup(argv0);
    char * exe = strdup(basename(path));
    free(path);
    return exe;
}

int main(int argc, char *argv[])
{
    int ret = 0;
    const char *exe = get_executable_name(argv[0]);
    if (strncmp(exe, "bb_printenv", 11) == 0 || strncmp(exe, "fw_printenv", 11) == 0) {
        ret = bb_printenv(exe, argc, argv);
    }
    else if (strncmp(exe, "bb_setenv", 9) == 0 || strncmp(exe, "fw_setenv", 9) == 0) {
        ret = bb_setenv(exe, argc, argv);
    }
    else {
        printf("Identity crisis - may be called as `bb_printenv', `fw_printenv', `bb_setenv', or as `fw_setenv' but not as `%s'\n", exe);
        ret = -1;
    }
    free((void*)exe);
    return ret;
}
