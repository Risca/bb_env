#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <gnutls/crypto.h>
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
    union {
        struct config cfg;
        char data[CONFIG_BLOCK_SIZE - 128/8 /* md5 hash */];
    };
    char hash[128/8];
} __attribute__((packed));

static int set_u8(uint8_t* value, const char* str)
{
    long v;

    errno = 0;
    v = strtol(str, NULL, 0);
    if (errno != 0 || v < 0 || v > 0xFF) {
        return -1;
    }

    *value = v & 0xff;
    return 0;
}

static int set_u16(uint16_t* value, const char* str)
{
    long v;

    errno = 0;
    v = strtol(str, NULL, 0);
    if (errno != 0 || v < 0 || v > 0xffff) {
        return -1;
    }

    *value = v & 0xffff;
    return 0;
}

static int set_u32(uint32_t* value, const char* str)
{
    long long v;

    errno = 0;
    v = strtoll(str, NULL, 0);
    if (errno != 0 || v < 0 || v > 0xffffffff) {
        return -1;
    }

    *value = v & 0xffffffff;
    return 0;
}

static int read_config_block(struct config_block **config)
{
    struct config_block *blk = NULL;
    char hash[sizeof(blk->hash)];
    ssize_t bytes_read;
    int rv = 0;
    int fd;

    if (config == NULL) {
        return -EINVAL;
    }

    blk = malloc(sizeof(struct config_block));
    if (!blk) {
        perror("malloc");
        return -ENOMEM;
    }

    fd = open("/dev/mtd0ro", O_RDONLY);
    if (fd < 0) {
        rv = errno;
        perror("open");
        goto out;
    }

    if (lseek(fd, CONFIG_BLOCK_OFFSET, SEEK_SET) < 0) {
        rv = errno;
        perror("lseek");
        close(fd);
        goto out;
    }

    bytes_read = read(fd, blk, sizeof(*blk));
    close(fd);
    if (bytes_read != sizeof(*blk)) {
        rv = bytes_read < 0 ? errno : -EIO;
        goto out;
    }

    rv = gnutls_hash_fast(GNUTLS_DIG_MD5, blk->data, sizeof(blk->data), hash);
    if (rv < 0) {
        fprintf(stderr, "## Error: failed to calculate hash\n");
        goto out;
    }

    if (memcmp(blk->hash, hash, sizeof(hash))) {
        fprintf(stderr, "## Error: hash mismatch\n");
        rv = -1;
        goto out;
    }

out:
    if (rv) {
        free(blk);
        *config = NULL;
    }
    else {
        *config = blk;
    }
    return rv;
}

static int write_config_block(struct config_block *blk)
{
    char hash[sizeof(blk->hash)];
    int rv = 0;
    int fd;
    size_t bytes_written;

    rv = gnutls_hash_fast(GNUTLS_DIG_MD5, blk->data, sizeof(blk->data), hash);
    if (rv < 0) {
        fprintf(stderr, "## Error: failed to calculate hash\n");
        return rv;
    }

    if (0 == memcmp(blk->hash, hash, sizeof(hash))) {
        // Nothing's changed
        return 0;
    }

    memcpy(blk->hash, hash, sizeof(hash));

    fd = open("/dev/mtd0", O_WRONLY);
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

    // TODO: rewrite for proper flash handling
    bytes_written = 0;
    while (bytes_written < CONFIG_BLOCK_SIZE) {
        ssize_t len = write(fd, (uint8_t*)blk + bytes_written, CONFIG_BLOCK_SIZE - bytes_written);
        if (len < 0) {
            if (errno == EINTR) {
                continue;
            }
            rv = errno;
            goto out;
        }
        bytes_written += len;
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
    "mender_boot_part", // same as "boot_part"
    "mender_boot_part_hex", // same as "boot_part"
};

static bool valid_config_variable(const char* variable)
{
    for (int i = 0; i < ARRAY_SIZE(config_strings); ++i) {
        if (!strcmp(variable, config_strings[i])) {
            return true;
        }
    }

    return false;
}

static int compare_and_print_header(const char* key, const char* variable, bool header)
{
    int rv = strcmp(variable, key);
    if (!rv && header) {
        printf("%s=", variable);
    }
    return rv;
}

static int print_config(const struct config * const cfg, const int start, const int end, const char *variables[], const bool header)
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
        else if (cfg->version >= 2 && !compare_and_print_header("mender_boot_part", variable, header)) {
            printf("%d\n", cfg->boot_part);
        }
        else if (cfg->version >= 2 && !compare_and_print_header("mender_boot_part_hex", variable, header)) {
            printf("%x\n", cfg->boot_part);
        }
        else {
            fprintf(stderr, "## Error: \"%s\" not defined\n", variable);
            rv = -1;
        }
    }
    return rv;
}

static int bb_printenv(const char* exe, int argc, char *argv[])
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

    c = read_config_block(&blk);
    if (c == 0) {
        if (optind == argc) {
            c = print_config(&blk->cfg, 0, ARRAY_SIZE(config_strings), config_strings, header);
        }
        else {
            c = print_config(&blk->cfg, optind, argc, (const char**)argv, header);
        }
        free(blk);
    }
    return c;
}

static int set_variable(struct config *cfg, const char* variable, const char* value)
{
    int rv = 0;

    if (!strcmp("version", variable)) {
        // Nope
    }
    else if (!strcmp("bootsource", variable)) {
        rv = set_u8(&cfg->boot_source, value);
    }
    else if (!strcmp("console", variable)) {
        rv = set_u8(&cfg->console, value);
    }
    else if (!strcmp("nic", variable)) {
        rv = set_u8(&cfg->nic, value);
    }
    else if (!strcmp("boottype", variable)) {
        rv = set_u8(&cfg->boot_type, value);
    }
    else if (!strcmp("loadaddress", variable)) {
        uint32_t v; // use temp variable to avoid unaligned access
        rv = set_u32(&v, value);
        if (rv == 0) {
            cfg->load_address = v;
        }
    }
    else if (!strcmp("cmndline", variable)) {
        int len = snprintf(cfg->cmdline, sizeof(cfg->cmdline), "%s", value);
        rv = (len < sizeof(cfg->cmdline)) ? 0 : -1;
    }
    else if (!strcmp("kernelmax", variable)) {
        uint16_t v; // use temp variable to avoid unaligned access
        rv = set_u16(&v, value);
        if (rv == 0) {
            cfg->kernel_max = v;
        }
    }
    else if (!strcmp("button", variable)) {
        rv = set_u8(&cfg->button, value);
    }
    else if (!strcmp("upgrade", variable) || !strcmp("upgrade_available", variable)) {
        rv = set_u8(&cfg->upgrade_available, value);
    }
    else if (!strcmp("boot_part", variable) || !strcmp("mender_boot_part", variable) || !strcmp("mender_boot_part_hex", variable)) {
        rv = set_u8(&cfg->boot_part, value);
    }
    else {
        // silently ignore
    }

    return 0;
}

static int bb_setenv(const char* exe, int argc, char *argv[])
{
    static const char * setenv_usage =
        "Usage: %s [OPTIONS]... [VARIABLE]...\n"
        "Modify variables in biffboot config\n"
        "\n"
        " -h, --help           print this help.\n"
        "\n";
    static struct option setenv_options[] = {
        {"help",     no_argument,       0, 'h'},
        {"script",   required_argument, 0, 's'},
        {0,          0,                 0,  0 },
    };
    int c;
    const char* variable;
    char* value = NULL;
    size_t size;
    struct config_block *blk;
    const char* script_file = NULL;
    
    while ((c = getopt_long(argc, argv, "hs:", setenv_options, NULL)) != -1) {
        switch (c) {
        case 'h':
            printf(setenv_usage, exe);
            return 0;
        case 's':
            script_file = optarg;
            break;
        case '?':
        default:
            printf(setenv_usage, exe);
            return -1;
        };
    }

    if (script_file) {
        FILE *fp;
        char *line = NULL;
        size_t len = 0;

        printf("Reading from %s\n", script_file);
        if (strcmp("-", script_file) == 0) {
            fp = stdin;
        }
        else {
            fp = fopen(script_file, "r");
            if (!fp) {
                c = errno;
                perror("fopen");
                return c;
            }
        }

        c = read_config_block(&blk);
        if (c == 0) {
            while (!c && getline(&line, &len, fp) != -1) {
                const char* variable;
                const char* value;
                int rv;

                variable = strtok(line, "=");
                if (!variable) {
                    // It's either a comment or a variable to clear, so it's ok
                    goto next;
                }
                if (variable[0] == '#') {
                    goto next;
                }

                value = strtok(NULL, "\n");
                if (!value) {
                    // "clear" variable
                    goto next;
                }
                printf("\"%s\" = \"%s\"\n", variable, value);
                c = set_variable(&blk->cfg, variable, value);
            next:
                free(line);
                line = NULL;
                len = 0;
            }
            if (c == 0) {
                c = write_config_block(blk);
            }
            free(blk);
        }
        if (fp != stdin) {
            fclose(fp);
        }
    }
    else {
        if (argc <= optind) {
            fprintf(stderr, "## Error: variable name missing\n");
            return -1;
        }

        if (argc == (optind+1)) {
            // only 1 argument means clear that variable, which we don't support.
            return 0;
        }

        variable = argv[optind];
        if (!valid_config_variable(variable)) {
            // "ok"
            return 0;
        }

        // This has horrible performance
        size = 0;
        for (int i = optind+1; i < argc; ++i) {
            size += strlen(argv[i]) + 1; // +1 for either ' ' or '\0'
        }

        value = malloc(size);
        if (!value) {
            perror("malloc");
            return -ENOMEM;
        }

        // Ugh...
        value[0] = '\0';
        strcat(value, argv[optind+1]);
        for (int i = optind+2; i < argc; ++i) {
            strcat(value, " ");
            strcat(value, argv[i]);
        }
        if (value[0] == '\0') {
            free(value);
            return 0;
        }

        printf("%s=%s\n", variable, value);
        c = read_config_block(&blk);
        if (c == 0) {
            c = set_variable(&blk->cfg, variable, value);
            if (c == 0) {
                c = write_config_block(blk);
            }
            free(blk);
        }
        free(value);
    }

    return c;
}

// POSIX basename might alter path, so work with copies
static const char * get_executable_name(const char * argv0)
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
