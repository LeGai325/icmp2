#include "classifier.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    IpVersion ip_version;
    char target[INET6_ADDRSTRLEN];
    int has_unreachable;
    int has_fragmentation;
    int has_intercepted;
    int has_not_intercepted;
    int observation_count;
    int conflict;
    char classification[20];
} TargetAgg;

typedef struct {
    TargetAgg *items;
    size_t len;
    size_t cap;
} TargetAggList;

typedef struct {
    IpVersion ip_version;
    char scope[MAX_SCOPE_LEN];
    int has_unreachable;
    int has_fragmentation;
    int has_deployed;
    int has_no_isav;
    int conflict;
    int observation_count;
} ScopeAgg;

typedef struct {
    ScopeAgg *items;
    size_t len;
    size_t cap;
} ScopeAggList;

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

    new_items = realloc(*items, new_cap * item_size);
    if (new_items == NULL) {
        return 0;
    }

    *items = new_items;
    *cap = new_cap;
    return 1;
}

static void target_agg_list_free(TargetAggList *list) {
    free(list->items);
    memset(list, 0, sizeof(*list));
}

static void scope_agg_list_free(ScopeAggList *list) {
    free(list->items);
    memset(list, 0, sizeof(*list));
}

static TargetAgg *find_or_add_target(TargetAggList *list, IpVersion ip_version, const char *target) {
    size_t i;

    for (i = 0; i < list->len; i++) {
        if (list->items[i].ip_version == ip_version && strcmp(list->items[i].target, target) == 0) {
            return &list->items[i];
        }
    }

    if (!ensure_capacity((void **)&list->items, sizeof(TargetAgg), &list->cap, list->len + 1)) {
        return NULL;
    }

    memset(&list->items[list->len], 0, sizeof(TargetAgg));
    list->items[list->len].ip_version = ip_version;
    strncpy(list->items[list->len].target, target, sizeof(list->items[list->len].target) - 1);
    list->len++;
    return &list->items[list->len - 1];
}

static ScopeAgg *find_or_add_scope(ScopeAggList *list, IpVersion ip_version, const char *scope) {
    size_t i;

    for (i = 0; i < list->len; i++) {
        if (list->items[i].ip_version == ip_version && strcmp(list->items[i].scope, scope) == 0) {
            return &list->items[i];
        }
    }

    if (!ensure_capacity((void **)&list->items, sizeof(ScopeAgg), &list->cap, list->len + 1)) {
        return NULL;
    }

    memset(&list->items[list->len], 0, sizeof(ScopeAgg));
    list->items[list->len].ip_version = ip_version;
    strncpy(list->items[list->len].scope, scope, sizeof(list->items[list->len].scope) - 1);
    list->len++;
    return &list->items[list->len - 1];
}

static void build_ipv4_scope(const char *target, char *scope, size_t scope_len) {
    struct in_addr addr;
    uint32_t value;
    unsigned int a;
    unsigned int b;
    unsigned int c;

    if (inet_pton(AF_INET, target, &addr) != 1) {
        snprintf(scope, scope_len, "invalid/24");
        return;
    }

    value = ntohl(addr.s_addr);
    a = (value >> 24) & 0xFFu;
    b = (value >> 16) & 0xFFu;
    c = (value >> 8) & 0xFFu;
    snprintf(scope, scope_len, "%u.%u.%u.0/24", a, b, c);
}

static void build_ipv6_scope(const char *target, char *scope, size_t scope_len) {
    struct in6_addr addr6;

    if (inet_pton(AF_INET6, target, &addr6) != 1) {
        snprintf(scope, scope_len, "invalid/40");
        return;
    }

    snprintf(
        scope,
        scope_len,
        "%02x%02x:%02x%02x:%02x00::/40",
        addr6.s6_addr[0],
        addr6.s6_addr[1],
        addr6.s6_addr[2],
        addr6.s6_addr[3],
        addr6.s6_addr[4]
    );
}

static void build_scope(const TargetAgg *target, char *scope, size_t scope_len) {
    if (target->ip_version == IP_VERSION_4) {
        build_ipv4_scope(target->target, scope, scope_len);
    } else {
        build_ipv6_scope(target->target, scope, scope_len);
    }
}

static const char *coverage_name(int has_unreachable, int has_fragmentation) {
    if (has_unreachable && has_fragmentation) {
        return "both";
    }
    if (has_unreachable) {
        return "unreachable";
    }
    if (has_fragmentation) {
        return "fragmentation";
    }
    return "none";
}

static void write_csv_escaped(FILE *fp, const char *value) {
    const char *cursor;
    int needs_quotes = 0;

    for (cursor = value; *cursor != '\0'; cursor++) {
        if (*cursor == ',' || *cursor == '"' || *cursor == '\n') {
            needs_quotes = 1;
            break;
        }
    }

    if (!needs_quotes) {
        fputs(value, fp);
        return;
    }

    fputc('"', fp);
    for (cursor = value; *cursor != '\0'; cursor++) {
        if (*cursor == '"') {
            fputc('"', fp);
        }
        fputc(*cursor, fp);
    }
    fputc('"', fp);
}

int classifier_build_deployments(
    const HostObservationList *observations,
    DeploymentList *deployments,
    char *err,
    size_t err_len
) {
    TargetAggList target_aggs;
    ScopeAggList scope_aggs;
    size_t i;

    memset(&target_aggs, 0, sizeof(target_aggs));
    memset(&scope_aggs, 0, sizeof(scope_aggs));

    for (i = 0; i < observations->len; i++) {
        const HostObservation *observation = &observations->items[i];
        TargetAgg *agg = find_or_add_target(&target_aggs, observation->ip_version, observation->target);

        if (agg == NULL) {
            snprintf(err, err_len, "failed to allocate target aggregation");
            target_agg_list_free(&target_aggs);
            scope_agg_list_free(&scope_aggs);
            return 0;
        }

        agg->observation_count++;
        if (strcmp(observation->method, "unreachable") == 0) {
            agg->has_unreachable = 1;
        } else if (strcmp(observation->method, "fragmentation") == 0) {
            agg->has_fragmentation = 1;
        }

        if (strcmp(observation->result, "intercepted") == 0) {
            agg->has_intercepted = 1;
        } else if (strcmp(observation->result, "not_intercepted") == 0) {
            agg->has_not_intercepted = 1;
        }
    }

    for (i = 0; i < target_aggs.len; i++) {
        TargetAgg *target = &target_aggs.items[i];

        if (target->has_intercepted && target->has_not_intercepted) {
            target->conflict = 1;
            strncpy(target->classification, "Unmeasurable", sizeof(target->classification) - 1);
        } else if (target->has_intercepted) {
            strncpy(target->classification, "Deployed ISAV", sizeof(target->classification) - 1);
        } else if (target->has_not_intercepted) {
            strncpy(target->classification, "No ISAV", sizeof(target->classification) - 1);
        } else {
            strncpy(target->classification, "Unmeasurable", sizeof(target->classification) - 1);
        }
    }

    for (i = 0; i < target_aggs.len; i++) {
        TargetAgg *target = &target_aggs.items[i];
        ScopeAgg *scope;
        char scope_key[MAX_SCOPE_LEN];

        build_scope(target, scope_key, sizeof(scope_key));
        scope = find_or_add_scope(&scope_aggs, target->ip_version, scope_key);
        if (scope == NULL) {
            snprintf(err, err_len, "failed to allocate scope aggregation");
            target_agg_list_free(&target_aggs);
            scope_agg_list_free(&scope_aggs);
            return 0;
        }

        scope->observation_count += target->observation_count;
        scope->has_unreachable |= target->has_unreachable;
        scope->has_fragmentation |= target->has_fragmentation;

        if (target->conflict) {
            scope->conflict = 1;
        } else if (strcmp(target->classification, "Deployed ISAV") == 0) {
            scope->has_deployed = 1;
        } else if (strcmp(target->classification, "No ISAV") == 0) {
            scope->has_no_isav = 1;
        }
    }

    for (i = 0; i < scope_aggs.len; i++) {
        DeploymentObservation observation;
        const ScopeAgg *scope = &scope_aggs.items[i];

        memset(&observation, 0, sizeof(observation));
        observation.ip_version = scope->ip_version;
        strncpy(observation.scope, scope->scope, sizeof(observation.scope) - 1);
        strncpy(
            observation.method_coverage,
            coverage_name(scope->has_unreachable, scope->has_fragmentation),
            sizeof(observation.method_coverage) - 1
        );
        observation.observation_count = scope->observation_count;

        if (scope->conflict) {
            strncpy(observation.classification, "Unmeasurable", sizeof(observation.classification) - 1);
        } else if (scope->has_deployed && scope->has_no_isav) {
            strncpy(observation.classification, "Partial ISAV", sizeof(observation.classification) - 1);
        } else if (scope->has_deployed) {
            strncpy(observation.classification, "Deployed ISAV", sizeof(observation.classification) - 1);
        } else if (scope->has_no_isav) {
            strncpy(observation.classification, "No ISAV", sizeof(observation.classification) - 1);
        } else {
            strncpy(observation.classification, "Unmeasurable", sizeof(observation.classification) - 1);
        }

        if (!deployment_list_append(deployments, &observation)) {
            snprintf(err, err_len, "failed to append deployment observation");
            target_agg_list_free(&target_aggs);
            scope_agg_list_free(&scope_aggs);
            return 0;
        }
    }

    target_agg_list_free(&target_aggs);
    scope_agg_list_free(&scope_aggs);
    return 1;
}

int classifier_write_host_csv(const char *path, const HostObservationList *observations, char *err, size_t err_len) {
    FILE *fp;
    size_t i;

    fp = fopen(path, "w");
    if (fp == NULL) {
        snprintf(err, err_len, "cannot open host output CSV: %s", path);
        return 0;
    }

    fprintf(
        fp,
        "timestamp,ip_version,target,method,port,measurable,result,n1,n2,baseline_fragmented,post_fragmented,retry_count,note\n"
    );

    for (i = 0; i < observations->len; i++) {
        const HostObservation *observation = &observations->items[i];

        write_csv_escaped(fp, observation->timestamp);
        fprintf(fp, ",%d,", (int)observation->ip_version);
        write_csv_escaped(fp, observation->target);
        fputc(',', fp);
        write_csv_escaped(fp, observation->method);
        fprintf(
            fp,
            ",%d,%d,",
            observation->port,
            observation->measurable
        );
        write_csv_escaped(fp, observation->result);
        fprintf(
            fp,
            ",%d,%d,%d,%d,%d,",
            observation->n1,
            observation->n2,
            observation->baseline_fragmented,
            observation->post_fragmented,
            observation->retry_count
        );
        write_csv_escaped(fp, observation->note);
        fputc('\n', fp);
    }

    fclose(fp);
    return 1;
}

int classifier_write_deployment_csv(const char *path, const DeploymentList *deployments, char *err, size_t err_len) {
    FILE *fp;
    size_t i;

    fp = fopen(path, "w");
    if (fp == NULL) {
        snprintf(err, err_len, "cannot open deployment output CSV: %s", path);
        return 0;
    }

    fprintf(fp, "ip_version,scope,classification,method_coverage,observation_count\n");

    for (i = 0; i < deployments->len; i++) {
        const DeploymentObservation *observation = &deployments->items[i];

        fprintf(fp, "%d,", (int)observation->ip_version);
        write_csv_escaped(fp, observation->scope);
        fputc(',', fp);
        write_csv_escaped(fp, observation->classification);
        fputc(',', fp);
        write_csv_escaped(fp, observation->method_coverage);
        fprintf(fp, ",%d\n", observation->observation_count);
    }

    fclose(fp);
    return 1;
}
