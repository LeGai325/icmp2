#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#define MAX_LINE 2048
#define MAX_KEY 128
#define MAX_METHOD 32
#define MAX_STATE 32

typedef struct {
    char key[MAX_KEY];
    int has_intercepted;
    int has_not_intercepted;
    int count;
} Agg;

static int split_csv_simple(char *line, char **cols, int max_cols) {
    int n = 0;
    char *p = line;
    while (*p && n < max_cols) {
        cols[n++] = p;
        while (*p && *p != ',') p++;
        if (*p == ',') {
            *p = '\0';
            p++;
        }
    }
    return n;
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    if (*s == '\0') return s;
    char *e = s + strlen(s) - 1;
    while (e > s && (*e == ' ' || *e == '\t' || *e == '\r' || *e == '\n')) {
        *e-- = '\0';
    }
    return s;
}

static uint32_t ipv4_to_u32(const char *ip) {
    struct in_addr a;
    if (inet_pton(AF_INET, ip, &a) != 1) return 0;
    return ntohl(a.s_addr);
}

static void subnet_key_ipv4_24(const char *ip, char *out, size_t out_len) {
    uint32_t v = ipv4_to_u32(ip);
    unsigned a = (v >> 24) & 0xFF;
    unsigned b = (v >> 16) & 0xFF;
    unsigned c = (v >> 8) & 0xFF;
    snprintf(out, out_len, "%u.%u.%u.0/24", a, b, c);
}

static void subnet_key_ipv6_40(const char *ip, char *out, size_t out_len) {
    struct in6_addr a6;
    if (inet_pton(AF_INET6, ip, &a6) != 1) {
        snprintf(out, out_len, "invalid/40");
        return;
    }
    unsigned b0 = a6.s6_addr[0], b1 = a6.s6_addr[1], b2 = a6.s6_addr[2], b3 = a6.s6_addr[3], b4 = a6.s6_addr[4];
    snprintf(out, out_len, "%02x%02x:%02x%02x:%02x00::/40", b0, b1, b2, b3, b4);
}

static int find_or_add(Agg **arr, int *len, int *cap, const char *key) {
    for (int i = 0; i < *len; i++) {
        if (strcmp((*arr)[i].key, key) == 0) return i;
    }
    if (*len >= *cap) {
        int ncap = (*cap == 0) ? 1024 : (*cap * 2);
        Agg *tmp = (Agg *)realloc(*arr, sizeof(Agg) * ncap);
        if (!tmp) return -1;
        *arr = tmp;
        *cap = ncap;
    }
    Agg *a = &((*arr)[*len]);
    memset(a, 0, sizeof(*a));
    strncpy(a->key, key, sizeof(a->key) - 1);
    (*len)++;
    return (*len) - 1;
}

static const char *classify(const Agg *a) {
    if (a->has_intercepted && !a->has_not_intercepted) return "Deployed ISAV";
    if (!a->has_intercepted && a->has_not_intercepted) return "No ISAV";
    return "Partial ISAV";
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr,
            "Usage: %s <host_observations.csv> <level:host|subnet> <output.csv>\n"
            "Input columns (required): ip_version,target,method,result\n"
            "result must be: intercepted | not_intercepted\n", argv[0]);
        return 1;
    }

    const char *infile = argv[1];
    const char *level = argv[2];
    const char *outfile = argv[3];

    int by_subnet = 0;
    if (strcmp(level, "host") == 0) by_subnet = 0;
    else if (strcmp(level, "subnet") == 0) by_subnet = 1;
    else {
        fprintf(stderr, "level must be host or subnet\n");
        return 1;
    }

    FILE *in = fopen(infile, "r");
    if (!in) {
        fprintf(stderr, "cannot open input: %s\n", infile);
        return 1;
    }

    Agg *arr = NULL;
    int len = 0, cap = 0;

    char line[MAX_LINE];
    int line_no = 0;
    while (fgets(line, sizeof(line), in)) {
        line_no++;
        char *t = trim(line);
        if (*t == '\0') continue;
        if (line_no == 1 && strstr(t, "ip_version") && strstr(t, "target")) continue;

        char *cols[8] = {0};
        int n = split_csv_simple(t, cols, 8);
        if (n < 4) continue;

        char *ipver = trim(cols[0]);
        char *target = trim(cols[1]);
        char *result = trim(cols[3]);

        char key[MAX_KEY];
        if (!by_subnet) {
            snprintf(key, sizeof(key), "%s|%s", ipver, target);
        } else {
            char subnet[96];
            if (strcmp(ipver, "4") == 0) subnet_key_ipv4_24(target, subnet, sizeof(subnet));
            else if (strcmp(ipver, "6") == 0) subnet_key_ipv6_40(target, subnet, sizeof(subnet));
            else continue;
            snprintf(key, sizeof(key), "%s|%s", ipver, subnet);
        }

        int idx = find_or_add(&arr, &len, &cap, key);
        if (idx < 0) {
            fclose(in);
            free(arr);
            fprintf(stderr, "memory allocation failed\n");
            return 1;
        }

        if (strcmp(result, "intercepted") == 0) arr[idx].has_intercepted = 1;
        else if (strcmp(result, "not_intercepted") == 0) arr[idx].has_not_intercepted = 1;
        else continue;
        arr[idx].count++;
    }
    fclose(in);

    FILE *out = fopen(outfile, "w");
    if (!out) {
        free(arr);
        fprintf(stderr, "cannot open output: %s\n", outfile);
        return 1;
    }

    fprintf(out, "ip_version,scope,classification,observations\n");
    for (int i = 0; i < len; i++) {
        char *sep = strchr(arr[i].key, '|');
        if (!sep) continue;
        *sep = '\0';
        const char *ipver = arr[i].key;
        const char *scope = sep + 1;
        fprintf(out, "%s,%s,%s,%d\n", ipver, scope, classify(&arr[i]), arr[i].count);
    }

    fclose(out);
    fprintf(stderr, "done. groups=%d output=%s\n", len, outfile);
    free(arr);
    return 0;
}
