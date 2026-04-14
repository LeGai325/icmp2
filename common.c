#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

char *trim(char *text) {
    char *end;

    while (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n') {
        text++;
    }

    if (*text == '\0') {
        return text;
    }

    end = text + strlen(text) - 1;
    while (end > text && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
        *end = '\0';
        end--;
    }

    return text;
}

void target_list_init(TargetList *list) {
    memset(list, 0, sizeof(*list));
}

void target_list_free(TargetList *list) {
    free(list->items);
    memset(list, 0, sizeof(*list));
}

static int target_list_contains(const TargetList *list, const Target *target) {
    size_t i;

    for (i = 0; i < list->len; i++) {
        if (list->items[i].ip_version == target->ip_version &&
            strcmp(list->items[i].address, target->address) == 0) {
            return 1;
        }
    }

    return 0;
}

int target_list_append(TargetList *list, const Target *target) {
    if (target_list_contains(list, target)) {
        return 1;
    }

    if (!ensure_capacity((void **)&list->items, sizeof(Target), &list->cap, list->len + 1)) {
        return 0;
    }

    list->items[list->len++] = *target;
    return 1;
}

int ipv4_cidr_bounds(const char *cidr, uint32_t *start, uint32_t *end, int *prefix) {
    char buf[64];
    char *slash;
    int pfx;
    struct in_addr addr;
    uint32_t ip;
    uint32_t mask;

    strncpy(buf, cidr, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    slash = strchr(buf, '/');
    if (slash == NULL) {
        return 0;
    }
    *slash = '\0';

    pfx = atoi(slash + 1);
    if (pfx < 0 || pfx > 32) {
        return 0;
    }

    if (inet_pton(AF_INET, buf, &addr) != 1) {
        return 0;
    }

    ip = ntohl(addr.s_addr);
    mask = (pfx == 0) ? 0 : (0xFFFFFFFFu << (32 - pfx));

    if (prefix != NULL) {
        *prefix = pfx;
    }
    if (start != NULL) {
        *start = ip & mask;
    }
    if (end != NULL) {
        *end = (ip & mask) | (~mask);
    }
    return 1;
}

int target_in_ipv4_cidr(const char *cidr, const char *ip) {
    uint32_t start;
    uint32_t end;
    struct in_addr addr;
    uint32_t value;

    if (!ipv4_cidr_bounds(cidr, &start, &end, NULL)) {
        return 0;
    }

    if (inet_pton(AF_INET, ip, &addr) != 1) {
        return 0;
    }

    value = ntohl(addr.s_addr);
    return value >= start && value <= end;
}

int add_ipv4_targets_from_cidr(const char *cidr, TargetList *list, char *err, size_t err_len) {
    uint32_t start;
    uint32_t end;
    uint32_t first;
    uint32_t last;
    int prefix;
    uint64_t count;
    uint32_t ip;

    if (!ipv4_cidr_bounds(cidr, &start, &end, &prefix)) {
        snprintf(err, err_len, "invalid IPv4 CIDR: %s", cidr);
        return 0;
    }

    count = (uint64_t)end - (uint64_t)start + 1;
    if (count > MAX_IPV4_ENUM_TARGETS) {
        snprintf(err, err_len, "IPv4 CIDR exceeds %d targets", MAX_IPV4_ENUM_TARGETS);
        return 0;
    }

    first = start;
    last = end;
    if (prefix <= 30) {
        first = start + 1;
        last = end - 1;
    }

    if (last < first) {
        snprintf(err, err_len, "IPv4 CIDR does not contain usable hosts");
        return 0;
    }

    for (ip = first; ip <= last; ip++) {
        Target target;
        struct in_addr addr;

        memset(&target, 0, sizeof(target));
        target.ip_version = IP_VERSION_4;
        addr.s_addr = htonl(ip);

        if (inet_ntop(AF_INET, &addr, target.address, sizeof(target.address)) == NULL) {
            snprintf(err, err_len, "failed to format IPv4 target");
            return 0;
        }

        if (!target_list_append(list, &target)) {
            snprintf(err, err_len, "failed to append IPv4 target");
            return 0;
        }

        if (ip == last) {
            break;
        }
    }

    return 1;
}

int add_ipv6_targets_from_csv(const char *path, TargetList *list, char *err, size_t err_len) {
    FILE *fp;
    char line[1024];

    fp = fopen(path, "r");
    if (fp == NULL) {
        snprintf(err, err_len, "cannot open IPv6 CSV: %s", path);
        return 0;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        Target target;
        char *value;
        char *comma;
        struct in6_addr addr6;

        value = trim(line);
        if (*value == '\0' || *value == '#') {
            continue;
        }

        comma = strchr(value, ',');
        if (comma != NULL) {
            *comma = '\0';
        }
        value = trim(value);

        if (inet_pton(AF_INET6, value, &addr6) != 1) {
            continue;
        }

        memset(&target, 0, sizeof(target));
        target.ip_version = IP_VERSION_6;
        strncpy(target.address, value, sizeof(target.address) - 1);

        if (!target_list_append(list, &target)) {
            fclose(fp);
            snprintf(err, err_len, "failed to append IPv6 target");
            return 0;
        }
    }

    fclose(fp);
    return 1;
}

int same_ipv6_prefix_64(const char *a, const char *b) {
    struct in6_addr left;
    struct in6_addr right;

    if (inet_pton(AF_INET6, a, &left) != 1) {
        return 0;
    }
    if (inet_pton(AF_INET6, b, &right) != 1) {
        return 0;
    }

    return memcmp(left.s6_addr, right.s6_addr, 8) == 0;
}

void capture_store_init(CaptureStore *store) {
    memset(store, 0, sizeof(*store));
}

void capture_store_free(CaptureStore *store) {
    free(store->items);
    memset(store, 0, sizeof(*store));
}

int capture_store_append(CaptureStore *store, const CaptureRecord *record) {
    if (!ensure_capacity((void **)&store->items, sizeof(CaptureRecord), &store->cap, store->len + 1)) {
        return 0;
    }

    store->items[store->len++] = *record;
    return 1;
}

void host_observation_list_init(HostObservationList *list) {
    memset(list, 0, sizeof(*list));
}

void host_observation_list_free(HostObservationList *list) {
    free(list->items);
    memset(list, 0, sizeof(*list));
}

int host_observation_list_append(HostObservationList *list, const HostObservation *observation) {
    if (!ensure_capacity((void **)&list->items, sizeof(HostObservation), &list->cap, list->len + 1)) {
        return 0;
    }

    list->items[list->len++] = *observation;
    return 1;
}

void deployment_list_init(DeploymentList *list) {
    memset(list, 0, sizeof(*list));
}

void deployment_list_free(DeploymentList *list) {
    free(list->items);
    memset(list, 0, sizeof(*list));
}

int deployment_list_append(DeploymentList *list, const DeploymentObservation *observation) {
    if (!ensure_capacity((void **)&list->items, sizeof(DeploymentObservation), &list->cap, list->len + 1)) {
        return 0;
    }

    list->items[list->len++] = *observation;
    return 1;
}

void make_timestamp_utc(char *buf, size_t len) {
    time_t now;
    struct tm tm_now;

    now = time(NULL);
    gmtime_r(&now, &tm_now);
    strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", &tm_now);
}

Method parse_method_name(const char *text) {
    if (strcmp(text, "unreachable") == 0) {
        return METHOD_UNREACHABLE;
    }
    if (strcmp(text, "fragmentation") == 0) {
        return METHOD_FRAGMENTATION;
    }
    return METHOD_NONE;
}

const char *method_name(Method method) {
    switch (method) {
        case METHOD_UNREACHABLE:
            return "unreachable";
        case METHOD_FRAGMENTATION:
            return "fragmentation";
        default:
            return "unknown";
    }
}

const char *result_name(ResultKind result) {
    switch (result) {
        case RESULT_INTERCEPTED:
            return "intercepted";
        case RESULT_NOT_INTERCEPTED:
            return "not_intercepted";
        case RESULT_UNMEASURABLE:
            return "unmeasurable";
        default:
            return "unset";
    }
}
