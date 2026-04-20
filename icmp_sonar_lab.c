#include "capture_engine.h"
#include "classifier.h"
#include "common.h"
#include "scheduler.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
    IpVersion ip_version;
    char prefix[INET6_ADDRSTRLEN + 8];
    char asn[32];
} PrefixAsEntry;

typedef struct {
    PrefixAsEntry *items;
    size_t len;
    size_t cap;
} PrefixAsList;

typedef struct {
    char asn[32];
    IpVersion ip_version;
    char prefix[INET6_ADDRSTRLEN + 8];
    char target[INET6_ADDRSTRLEN];
} NoIsavAsRecord;

typedef struct {
    NoIsavAsRecord *items;
    size_t len;
    size_t cap;
} NoIsavAsList;

static void set_default_config(Config *config) {
    memset(config, 0, sizeof(*config));
    config->ports[0] = 22;
    config->ports[1] = 53;
    config->ports[2] = 80;
    config->ports[3] = 443;
    config->port_count = 4;
    config->methods.enabled_unreachable = 1;
    config->methods.enabled_fragmentation = 1;
    config->mtu = 1300;
    config->cooldown = 600;
    config->retry_missing = 1;
    config->ipv4_global_limit = 4096;
    config->ipv4_global_batch_size = 4096;
    strncpy(config->ipv4_global_cursor_file, ".ipv4_global_cursor", sizeof(config->ipv4_global_cursor_file) - 1);
}

static void print_usage(const char *prog) {
    fprintf(
        stderr,
        "Usage:\n"
        "  %s --iface eth0 --capture-observations lab_capture.csv --out-prefix output/run1 \\\n"
        "     [--ipv4-cidr 192.168.10.0/24] [--ipv4-global [--ipv4-global-limit 4096]] \\\n"
        "     [--ipv4-global-progressive [--ipv4-global-batch-size 4096] [--ipv4-global-cursor-file .ipv4_global_cursor]] \\\n"
        "     [--ipv6-csv ipv6_targets.csv] \\\n"
        "     [--ports 22,53,80,443] [--methods unreachable,fragmentation] \\\n"
        "     [--mtu 1300] [--cooldown 600] [--retry-missing 1]\n\n"
        "  %s --iface lab0 [--capture-observations sample.csv] \\\n"
        "     --prefix-as-v4-txt v4_prefix_as.txt --prefix-as-v6-txt v6_prefix_as.txt \\\n"
        "     --no-isav-addr-csv no_isav_address.csv --no-isav-as-csv no_isav_as.csv\n\n"
        "Notes:\n"
        "  1) This lab tool consumes isolated-environment observations from CSV.\n"
        "  2) --ipv4-global samples addresses across 0.0.0.0/0 with a safe cap.\n"
        "  3) --ipv4-global-progressive scans global IPv4 in sequential batches and persists a cursor.\n"
        "  4) Prefix-AS mode without --capture-observations performs live TCP probing.\n"
        "  5) It reproduces the paper decision logic and deployment classification.\n",
        prog,
        prog
    );
}

static int ensure_capacity(void **items, size_t item_size, size_t *cap, size_t needed) {
    size_t new_cap;
    void *new_items;

    if (*cap >= needed) {
        return 1;
    }
    new_cap = (*cap == 0) ? 128 : (*cap * 2);
    while (new_cap < needed) {
        new_cap *= 2;
    }
    new_items = realloc(*items, item_size * new_cap);
    if (new_items == NULL) {
        return 0;
    }
    *items = new_items;
    *cap = new_cap;
    return 1;
}

static void prefix_as_list_init(PrefixAsList *list) {
    memset(list, 0, sizeof(*list));
}

static void prefix_as_list_free(PrefixAsList *list) {
    free(list->items);
    memset(list, 0, sizeof(*list));
}

static int prefix_as_list_append(PrefixAsList *list, const PrefixAsEntry *entry) {
    if (!ensure_capacity((void **)&list->items, sizeof(PrefixAsEntry), &list->cap, list->len + 1)) {
        return 0;
    }
    list->items[list->len++] = *entry;
    return 1;
}

static void no_isav_as_list_init(NoIsavAsList *list) {
    memset(list, 0, sizeof(*list));
}

static void no_isav_as_list_free(NoIsavAsList *list) {
    free(list->items);
    memset(list, 0, sizeof(*list));
}

static int no_isav_as_list_contains(const NoIsavAsList *list, const char *asn) {
    size_t i;
    for (i = 0; i < list->len; i++) {
        if (strcmp(list->items[i].asn, asn) == 0) {
            return 1;
        }
    }
    return 0;
}

static int no_isav_as_list_append(NoIsavAsList *list, const NoIsavAsRecord *record) {
    if (no_isav_as_list_contains(list, record->asn)) {
        return 1;
    }
    if (!ensure_capacity((void **)&list->items, sizeof(NoIsavAsRecord), &list->cap, list->len + 1)) {
        return 0;
    }
    list->items[list->len++] = *record;
    return 1;
}

static int load_prefix_as_txt(const char *path, IpVersion ip_version, PrefixAsList *list, char *err, size_t err_len) {
    FILE *fp;
    char line[512];

    if (path[0] == '\0') {
        return 1;
    }

    fp = fopen(path, "r");
    if (fp == NULL) {
        snprintf(err, err_len, "cannot open prefix-as txt: %s", path);
        return 0;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        PrefixAsEntry entry;
        char *prefix;
        char *asn;
        char *sep;

        prefix = trim(line);
        if (*prefix == '\0' || *prefix == '#') {
            continue;
        }
        sep = strchr(prefix, '\t');
        if (sep == NULL) {
            sep = strchr(prefix, ' ');
        }
        if (sep == NULL) {
            continue;
        }
        *sep = '\0';
        asn = trim(sep + 1);
        if (*asn == '\0') {
            continue;
        }

        memset(&entry, 0, sizeof(entry));
        entry.ip_version = ip_version;
        strncpy(entry.prefix, trim(prefix), sizeof(entry.prefix) - 1);
        strncpy(entry.asn, asn, sizeof(entry.asn) - 1);
        if (!prefix_as_list_append(list, &entry)) {
            fclose(fp);
            snprintf(err, err_len, "failed to append prefix-as entry");
            return 0;
        }
    }

    fclose(fp);
    return 1;
}

static int mask_ipv6_prefix(struct in6_addr *addr, int prefix) {
    int bit;
    if (prefix < 0 || prefix > 128) {
        return 0;
    }
    for (bit = prefix; bit < 128; bit++) {
        int byte_idx = bit / 8;
        int bit_in_byte = 7 - (bit % 8);
        addr->s6_addr[byte_idx] &= (unsigned char)~(1u << bit_in_byte);
    }
    return 1;
}

static int add_ipv6_targets_from_cidr(const char *cidr, TargetList *list, char *err, size_t err_len) {
    char buf[128];
    char *slash;
    int prefix;
    int host_bits;
    uint32_t count;
    uint32_t i;
    struct in6_addr base;

    strncpy(buf, cidr, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    slash = strchr(buf, '/');
    if (slash == NULL) {
        snprintf(err, err_len, "invalid IPv6 CIDR: %s", cidr);
        return 0;
    }
    *slash = '\0';
    prefix = atoi(slash + 1);
    if (inet_pton(AF_INET6, buf, &base) != 1) {
        snprintf(err, err_len, "invalid IPv6 CIDR: %s", cidr);
        return 0;
    }
    if (!mask_ipv6_prefix(&base, prefix)) {
        snprintf(err, err_len, "invalid IPv6 prefix length: %d", prefix);
        return 0;
    }

    host_bits = 128 - prefix;
    if (host_bits > 16) {
        snprintf(err, err_len, "IPv6 CIDR too large to enumerate safely: %s", cidr);
        return 0;
    }
    count = 1u << host_bits;
    if ((int)count > MAX_IPV4_ENUM_TARGETS) {
        snprintf(err, err_len, "IPv6 CIDR exceeds %d targets", MAX_IPV4_ENUM_TARGETS);
        return 0;
    }

    for (i = 0; i < count; i++) {
        Target target;
        struct in6_addr addr;
        uint32_t value;
        int bit;

        memset(&target, 0, sizeof(target));
        target.ip_version = IP_VERSION_6;
        addr = base;
        value = i;

        for (bit = 0; bit < host_bits; bit++) {
            int global_bit = 127 - bit;
            int byte_idx = global_bit / 8;
            int bit_in_byte = 7 - (global_bit % 8);
            if ((value >> bit) & 1u) {
                addr.s6_addr[byte_idx] |= (unsigned char)(1u << bit_in_byte);
            }
        }

        if (inet_ntop(AF_INET6, &addr, target.address, sizeof(target.address)) == NULL) {
            snprintf(err, err_len, "failed to format IPv6 target");
            return 0;
        }
        if (!target_list_append(list, &target)) {
            snprintf(err, err_len, "failed to append IPv6 target");
            return 0;
        }
    }
    return 1;
}

static int write_no_isav_addr_csv(const char *path, const HostObservationList *rows, const PrefixAsList *refs, char *err, size_t err_len) {
    FILE *fp;
    size_t i;

    fp = fopen(path, "w");
    if (fp == NULL) {
        snprintf(err, err_len, "cannot write no-isav address csv: %s", path);
        return 0;
    }
    fprintf(fp, "ip_version,asn,prefix,target,method,result\n");
    for (i = 0; i < rows->len; i++) {
        const HostObservation *o = &rows->items[i];
        const PrefixAsEntry *ref = &refs->items[i];
        fprintf(fp, "%d,%s,%s,%s,%s,%s\n", (int)o->ip_version, ref->asn, ref->prefix, o->target, o->method, o->result);
    }
    fclose(fp);
    return 1;
}

static int write_no_isav_as_csv(const char *path, const NoIsavAsList *list, char *err, size_t err_len) {
    FILE *fp;
    size_t i;

    fp = fopen(path, "w");
    if (fp == NULL) {
        snprintf(err, err_len, "cannot write no-isav as csv: %s", path);
        return 0;
    }
    fprintf(fp, "asn,ip_version,first_prefix,first_target\n");
    for (i = 0; i < list->len; i++) {
        fprintf(
            fp,
            "%s,%d,%s,%s\n",
            list->items[i].asn,
            (int)list->items[i].ip_version,
            list->items[i].prefix,
            list->items[i].target
        );
    }
    fclose(fp);
    return 1;
}

static int connect_with_timeout(int fd, const struct sockaddr *addr, socklen_t addr_len, int timeout_ms) {
    int flags;
    int rc;
    struct pollfd pfd;
    int so_error = 0;
    socklen_t so_error_len = sizeof(so_error);

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return 0;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return 0;
    }

    rc = connect(fd, addr, addr_len);
    if (rc == 0) {
        return 1;
    }
    if (errno != EINPROGRESS) {
        return 0;
    }

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLOUT;
    rc = poll(&pfd, 1, timeout_ms);
    if (rc <= 0) {
        return 0;
    }

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len) != 0) {
        return 0;
    }
    return (so_error == 0 || so_error == ECONNREFUSED);
}

static int target_has_live_response(const Config *config, const Target *target, int *hit_port, char *err, size_t err_len) {
    size_t i;

    for (i = 0; i < config->port_count; i++) {
        int port = config->ports[i];
        int fd;
        int ok = 0;

        if (target->ip_version == IP_VERSION_4) {
            struct sockaddr_in sa4;
            memset(&sa4, 0, sizeof(sa4));
            sa4.sin_family = AF_INET;
            sa4.sin_port = htons((uint16_t)port);
            if (inet_pton(AF_INET, target->address, &sa4.sin_addr) != 1) {
                continue;
            }
            fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0) {
                continue;
            }
            ok = connect_with_timeout(fd, (const struct sockaddr *)&sa4, sizeof(sa4), config->cooldown > 0 ? config->cooldown : 800);
            close(fd);
        } else if (target->ip_version == IP_VERSION_6) {
            struct sockaddr_in6 sa6;
            memset(&sa6, 0, sizeof(sa6));
            sa6.sin6_family = AF_INET6;
            sa6.sin6_port = htons((uint16_t)port);
            if (inet_pton(AF_INET6, target->address, &sa6.sin6_addr) != 1) {
                continue;
            }
            fd = socket(AF_INET6, SOCK_STREAM, 0);
            if (fd < 0) {
                continue;
            }
            ok = connect_with_timeout(fd, (const struct sockaddr *)&sa6, sizeof(sa6), config->cooldown > 0 ? config->cooldown : 800);
            close(fd);
        } else {
            continue;
        }

        if (ok) {
            *hit_port = port;
            return 1;
        }
    }

    snprintf(err, err_len, "no live tcp response");
    return 0;
}

static uint32_t load_ipv4_cursor(const char *path) {
    FILE *fp;
    unsigned long value;

    fp = fopen(path, "r");
    if (fp == NULL) {
        return 1;
    }

    value = 1;
    if (fscanf(fp, "%lu", &value) != 1) {
        value = 1;
    }
    fclose(fp);

    if (value == 0 || value >= 0xFFFFFFFFul) {
        return 1;
    }
    return (uint32_t)value;
}

static int save_ipv4_cursor(const char *path, uint32_t next_ip) {
    FILE *fp;

    fp = fopen(path, "w");
    if (fp == NULL) {
        return 0;
    }
    fprintf(fp, "%u\n", next_ip);
    fclose(fp);
    return 1;
}

static int parse_ports(Config *config, const char *value) {
    char buf[256];
    char *token;
    size_t count = 0;

    strncpy(buf, value, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    token = strtok(buf, ",");
    while (token != NULL) {
        int port;

        token = trim(token);
        port = atoi(token);
        if (port <= 0 || port > 65535 || count >= MAX_PORTS) {
            return 0;
        }
        config->ports[count++] = port;
        token = strtok(NULL, ",");
    }

    if (count == 0) {
        return 0;
    }

    config->port_count = count;
    return 1;
}

static int parse_methods(Config *config, const char *value) {
    char buf[128];
    char *token;

    config->methods.enabled_unreachable = 0;
    config->methods.enabled_fragmentation = 0;

    strncpy(buf, value, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    token = strtok(buf, ",");
    while (token != NULL) {
        Method method = parse_method_name(trim(token));

        if (method == METHOD_UNREACHABLE) {
            config->methods.enabled_unreachable = 1;
        } else if (method == METHOD_FRAGMENTATION) {
            config->methods.enabled_fragmentation = 1;
        } else {
            return 0;
        }
        token = strtok(NULL, ",");
    }

    return config->methods.enabled_unreachable || config->methods.enabled_fragmentation;
}

static int parse_args(int argc, char **argv, Config *config) {
    int i;

    set_default_config(config);

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) {
            strncpy(config->iface, argv[++i], sizeof(config->iface) - 1);
        } else if (strcmp(argv[i], "--ipv4-cidr") == 0 && i + 1 < argc) {
            config->has_ipv4_cidr = 1;
            strncpy(config->ipv4_cidr, argv[++i], sizeof(config->ipv4_cidr) - 1);
        } else if (strcmp(argv[i], "--ipv4-global") == 0) {
            config->has_ipv4_global = 1;
        } else if (strcmp(argv[i], "--ipv4-global-limit") == 0 && i + 1 < argc) {
            config->ipv4_global_limit = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--ipv4-global-progressive") == 0) {
            config->has_ipv4_global_progressive = 1;
        } else if (strcmp(argv[i], "--ipv4-global-batch-size") == 0 && i + 1 < argc) {
            config->ipv4_global_batch_size = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--ipv4-global-cursor-file") == 0 && i + 1 < argc) {
            strncpy(config->ipv4_global_cursor_file, argv[++i], sizeof(config->ipv4_global_cursor_file) - 1);
        } else if (strcmp(argv[i], "--ipv6-csv") == 0 && i + 1 < argc) {
            config->has_ipv6_csv = 1;
            strncpy(config->ipv6_csv, argv[++i], sizeof(config->ipv6_csv) - 1);
        } else if (strcmp(argv[i], "--prefix-as-v4-txt") == 0 && i + 1 < argc) {
            strncpy(config->prefix_as_v4_txt, argv[++i], sizeof(config->prefix_as_v4_txt) - 1);
        } else if (strcmp(argv[i], "--prefix-as-v6-txt") == 0 && i + 1 < argc) {
            strncpy(config->prefix_as_v6_txt, argv[++i], sizeof(config->prefix_as_v6_txt) - 1);
        } else if (strcmp(argv[i], "--no-isav-addr-csv") == 0 && i + 1 < argc) {
            strncpy(config->no_isav_addr_csv, argv[++i], sizeof(config->no_isav_addr_csv) - 1);
        } else if (strcmp(argv[i], "--no-isav-as-csv") == 0 && i + 1 < argc) {
            strncpy(config->no_isav_as_csv, argv[++i], sizeof(config->no_isav_as_csv) - 1);
        } else if (strcmp(argv[i], "--capture-observations") == 0 && i + 1 < argc) {
            strncpy(config->capture_csv, argv[++i], sizeof(config->capture_csv) - 1);
        } else if (strcmp(argv[i], "--out-prefix") == 0 && i + 1 < argc) {
            strncpy(config->out_prefix, argv[++i], sizeof(config->out_prefix) - 1);
        } else if (strcmp(argv[i], "--ports") == 0 && i + 1 < argc) {
            if (!parse_ports(config, argv[++i])) {
                return 0;
            }
        } else if (strcmp(argv[i], "--methods") == 0 && i + 1 < argc) {
            if (!parse_methods(config, argv[++i])) {
                return 0;
            }
        } else if (strcmp(argv[i], "--mtu") == 0 && i + 1 < argc) {
            config->mtu = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--cooldown") == 0 && i + 1 < argc) {
            config->cooldown = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--retry-missing") == 0 && i + 1 < argc) {
            config->retry_missing = atoi(argv[++i]);
        } else {
            return 0;
        }
    }

    if (config->iface[0] == '\0') {
        return 0;
    }
    if (config->prefix_as_v4_txt[0] == '\0' && config->prefix_as_v6_txt[0] == '\0' && config->out_prefix[0] == '\0') {
        return 0;
    }
    if (config->prefix_as_v4_txt[0] == '\0' && config->prefix_as_v6_txt[0] == '\0' &&
        !config->has_ipv4_cidr && !config->has_ipv4_global && !config->has_ipv4_global_progressive && !config->has_ipv6_csv) {
        return 0;
    }
    if ((config->prefix_as_v4_txt[0] != '\0' || config->prefix_as_v6_txt[0] != '\0') &&
        (config->no_isav_addr_csv[0] == '\0' || config->no_isav_as_csv[0] == '\0')) {
        return 0;
    }
    if ((config->prefix_as_v4_txt[0] == '\0' && config->prefix_as_v6_txt[0] == '\0') && config->capture_csv[0] == '\0') {
        return 0;
    }
    if (config->mtu <= 0 || config->cooldown < 0 || config->retry_missing < 0 || config->ipv4_global_limit <= 0 ||
        config->ipv4_global_batch_size <= 0 || config->ipv4_global_cursor_file[0] == '\0') {
        return 0;
    }

    return 1;
}

int main(int argc, char **argv) {
    Config config;
    TargetList targets;
    TargetList prefix_targets;
    CaptureStore captures;
    HostObservationList observations;
    HostObservationList prefix_observations;
    HostObservationList no_isav_addr_rows;
    PrefixAsList no_isav_addr_refs;
    PrefixAsList prefix_entries;
    NoIsavAsList no_isav_as_rows;
    DeploymentList deployments;
    char err[256];
    char host_csv[MAX_PATH_LEN + 64];
    char deployment_csv[MAX_PATH_LEN + 64];
    int ok = 0;
    int use_prefix_mode;
    int use_live_prefix;

    if (!parse_args(argc, argv, &config)) {
        print_usage(argv[0]);
        return 1;
    }

    target_list_init(&targets);
    target_list_init(&prefix_targets);
    capture_store_init(&captures);
    host_observation_list_init(&observations);
    host_observation_list_init(&prefix_observations);
    host_observation_list_init(&no_isav_addr_rows);
    prefix_as_list_init(&no_isav_addr_refs);
    prefix_as_list_init(&prefix_entries);
    no_isav_as_list_init(&no_isav_as_rows);
    deployment_list_init(&deployments);

    use_prefix_mode = (config.prefix_as_v4_txt[0] != '\0' || config.prefix_as_v6_txt[0] != '\0');
    use_live_prefix = (use_prefix_mode && config.capture_csv[0] == '\0');

    if (!use_live_prefix) {
        if (!capture_engine_load_csv(config.capture_csv, &captures, err, sizeof(err))) {
            fprintf(stderr, "%s\n", err);
            goto cleanup;
        }
    }

    if (use_prefix_mode) {
        size_t i;

        if (!load_prefix_as_txt(config.prefix_as_v4_txt, IP_VERSION_4, &prefix_entries, err, sizeof(err))) {
            fprintf(stderr, "%s\n", err);
            goto cleanup;
        }
        if (!load_prefix_as_txt(config.prefix_as_v6_txt, IP_VERSION_6, &prefix_entries, err, sizeof(err))) {
            fprintf(stderr, "%s\n", err);
            goto cleanup;
        }
        if (prefix_entries.len == 0) {
            fprintf(stderr, "no prefix-as entries loaded\n");
            goto cleanup;
        }

        for (i = 0; i < prefix_entries.len; i++) {
            const PrefixAsEntry *entry = &prefix_entries.items[i];
            size_t j;
            Config run_config;

            if (no_isav_as_list_contains(&no_isav_as_rows, entry->asn)) {
                continue;
            }

            run_config = config;
            prefix_targets.len = 0;
            if (entry->ip_version == IP_VERSION_4) {
                run_config.has_ipv4_cidr = 1;
                strncpy(run_config.ipv4_cidr, entry->prefix, sizeof(run_config.ipv4_cidr) - 1);
                if (!add_ipv4_targets_from_cidr(entry->prefix, &prefix_targets, err, sizeof(err))) {
                    fprintf(stderr, "%s\n", err);
                    goto cleanup;
                }
            } else {
                run_config.has_ipv6_csv = 1;
                if (!add_ipv6_targets_from_cidr(entry->prefix, &prefix_targets, err, sizeof(err))) {
                    fprintf(stderr, "%s\n", err);
                    goto cleanup;
                }
            }

            prefix_observations.len = 0;
            if (use_live_prefix) {
                size_t k;
                for (k = 0; k < prefix_targets.len; k++) {
                    int hit_port = 0;
                    if (target_has_live_response(&run_config, &prefix_targets.items[k], &hit_port, err, sizeof(err))) {
                        HostObservation o;
                        PrefixAsEntry ref;
                        NoIsavAsRecord as_row;

                        memset(&o, 0, sizeof(o));
                        make_timestamp_utc(o.timestamp, sizeof(o.timestamp));
                        o.ip_version = prefix_targets.items[k].ip_version;
                        strncpy(o.target, prefix_targets.items[k].address, sizeof(o.target) - 1);
                        strncpy(o.method, "live_tcp", sizeof(o.method) - 1);
                        o.port = hit_port;
                        o.measurable = 1;
                        strncpy(o.result, "not_intercepted", sizeof(o.result) - 1);
                        strncpy(o.note, "live_tcp_connect_or_refused", sizeof(o.note) - 1);

                        if (!host_observation_list_append(&no_isav_addr_rows, &o)) {
                            fprintf(stderr, "failed to append no-isav address row\n");
                            goto cleanup;
                        }

                        memset(&ref, 0, sizeof(ref));
                        ref.ip_version = entry->ip_version;
                        strncpy(ref.prefix, entry->prefix, sizeof(ref.prefix) - 1);
                        strncpy(ref.asn, entry->asn, sizeof(ref.asn) - 1);
                        if (!prefix_as_list_append(&no_isav_addr_refs, &ref)) {
                            fprintf(stderr, "failed to append no-isav address reference\n");
                            goto cleanup;
                        }

                        memset(&as_row, 0, sizeof(as_row));
                        strncpy(as_row.asn, entry->asn, sizeof(as_row.asn) - 1);
                        as_row.ip_version = entry->ip_version;
                        strncpy(as_row.prefix, entry->prefix, sizeof(as_row.prefix) - 1);
                        strncpy(as_row.target, o.target, sizeof(as_row.target) - 1);
                        if (!no_isav_as_list_append(&no_isav_as_rows, &as_row)) {
                            fprintf(stderr, "failed to append no-isav AS row\n");
                            goto cleanup;
                        }
                        break;
                    }
                }
                continue;
            } else if (!scheduler_run(&run_config, &prefix_targets, &captures, &prefix_observations, err, sizeof(err))) {
                fprintf(stderr, "%s\n", err);
                goto cleanup;
            }

            for (j = 0; j < prefix_observations.len; j++) {
                HostObservation *o = &prefix_observations.items[j];
                if (strcmp(o->result, "not_intercepted") == 0) {
                    PrefixAsEntry ref;
                    NoIsavAsRecord as_row;

                    if (!host_observation_list_append(&no_isav_addr_rows, o)) {
                        fprintf(stderr, "failed to append no-isav address row\n");
                        goto cleanup;
                    }
                    memset(&ref, 0, sizeof(ref));
                    ref.ip_version = entry->ip_version;
                    strncpy(ref.prefix, entry->prefix, sizeof(ref.prefix) - 1);
                    strncpy(ref.asn, entry->asn, sizeof(ref.asn) - 1);
                    if (!prefix_as_list_append(&no_isav_addr_refs, &ref)) {
                        fprintf(stderr, "failed to append no-isav address reference\n");
                        goto cleanup;
                    }

                    memset(&as_row, 0, sizeof(as_row));
                    strncpy(as_row.asn, entry->asn, sizeof(as_row.asn) - 1);
                    as_row.ip_version = entry->ip_version;
                    strncpy(as_row.prefix, entry->prefix, sizeof(as_row.prefix) - 1);
                    strncpy(as_row.target, o->target, sizeof(as_row.target) - 1);
                    if (!no_isav_as_list_append(&no_isav_as_rows, &as_row)) {
                        fprintf(stderr, "failed to append no-isav AS row\n");
                        goto cleanup;
                    }
                    break;
                }
            }
        }

        if (!write_no_isav_addr_csv(config.no_isav_addr_csv, &no_isav_addr_rows, &no_isav_addr_refs, err, sizeof(err))) {
            fprintf(stderr, "%s\n", err);
            goto cleanup;
        }
        if (!write_no_isav_as_csv(config.no_isav_as_csv, &no_isav_as_rows, err, sizeof(err))) {
            fprintf(stderr, "%s\n", err);
            goto cleanup;
        }
        fprintf(stderr, "done. no_isav_addr_rows=%lu no_isav_as_rows=%lu\n", (unsigned long)no_isav_addr_rows.len, (unsigned long)no_isav_as_rows.len);
        fprintf(stderr, "no_isav_addr_csv=%s\n", config.no_isav_addr_csv);
        fprintf(stderr, "no_isav_as_csv=%s\n", config.no_isav_as_csv);
        ok = 1;
        goto cleanup;
    }

    if (config.has_ipv4_cidr && !add_ipv4_targets_from_cidr(config.ipv4_cidr, &targets, err, sizeof(err))) {
        fprintf(stderr, "%s\n", err);
        goto cleanup;
    }
    if (config.has_ipv4_global && !add_ipv4_targets_global(config.ipv4_global_limit, &targets, err, sizeof(err))) {
        fprintf(stderr, "%s\n", err);
        goto cleanup;
    }
    if (config.has_ipv4_global_progressive) {
        uint32_t cursor = load_ipv4_cursor(config.ipv4_global_cursor_file);
        uint32_t next_cursor = cursor;

        if (!add_ipv4_targets_global_progressive(config.ipv4_global_batch_size, cursor, &next_cursor, &targets, err, sizeof(err))) {
            fprintf(stderr, "%s\n", err);
            goto cleanup;
        }
        if (!save_ipv4_cursor(config.ipv4_global_cursor_file, next_cursor)) {
            fprintf(stderr, "failed to write IPv4 global cursor file: %s\n", config.ipv4_global_cursor_file);
            goto cleanup;
        }
    }
    if (config.has_ipv6_csv && !add_ipv6_targets_from_csv(config.ipv6_csv, &targets, err, sizeof(err))) {
        fprintf(stderr, "%s\n", err);
        goto cleanup;
    }
    if (targets.len == 0) {
        fprintf(stderr, "no targets loaded from the configured scope\n");
        goto cleanup;
    }

    if (!scheduler_run(&config, &targets, &captures, &observations, err, sizeof(err))) {
        fprintf(stderr, "%s\n", err);
        goto cleanup;
    }

    if (!classifier_build_deployments(&observations, &deployments, err, sizeof(err))) {
        fprintf(stderr, "%s\n", err);
        goto cleanup;
    }

    snprintf(host_csv, sizeof(host_csv), "%s_host_observations.csv", config.out_prefix);
    snprintf(deployment_csv, sizeof(deployment_csv), "%s_deployment.csv", config.out_prefix);

    if (!classifier_write_host_csv(host_csv, &observations, err, sizeof(err))) {
        fprintf(stderr, "%s\n", err);
        goto cleanup;
    }
    if (!classifier_write_deployment_csv(deployment_csv, &deployments, err, sizeof(err))) {
        fprintf(stderr, "%s\n", err);
        goto cleanup;
    }

    fprintf(
        stderr,
        "done. targets=%lu host_rows=%lu deployment_rows=%lu\n",
        (unsigned long)targets.len,
        (unsigned long)observations.len,
        (unsigned long)deployments.len
    );
    fprintf(stderr, "host_csv=%s\n", host_csv);
    fprintf(stderr, "deployment_csv=%s\n", deployment_csv);
    ok = 1;

cleanup:
    deployment_list_free(&deployments);
    no_isav_as_list_free(&no_isav_as_rows);
    prefix_as_list_free(&prefix_entries);
    prefix_as_list_free(&no_isav_addr_refs);
    host_observation_list_free(&no_isav_addr_rows);
    host_observation_list_free(&prefix_observations);
    host_observation_list_free(&observations);
    capture_store_free(&captures);
    target_list_free(&prefix_targets);
    target_list_free(&targets);
    return ok ? 0 : 1;
}
