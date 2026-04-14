#include "packet_builder.h"

#include <stdio.h>
#include <string.h>

static int choose_ipv4_neighbor(const char *cidr, const char *target, char *out, size_t out_len) {
    uint32_t start;
    uint32_t end;
    int prefix;
    struct in_addr addr;
    uint32_t value;
    uint32_t first;
    uint32_t last;
    uint32_t candidate;

    if (!ipv4_cidr_bounds(cidr, &start, &end, &prefix)) {
        return 0;
    }
    if (inet_pton(AF_INET, target, &addr) != 1) {
        return 0;
    }

    value = ntohl(addr.s_addr);
    first = start;
    last = end;
    if (prefix <= 30) {
        first = start + 1;
        last = end - 1;
    }

    if (last < first) {
        return 0;
    }

    candidate = value;
    if (value > first) {
        candidate = value - 1;
    } else if (value < last) {
        candidate = value + 1;
    } else {
        return 0;
    }

    addr.s_addr = htonl(candidate);
    return inet_ntop(AF_INET, &addr, out, out_len) != NULL;
}

static int choose_ipv6_neighbor(const char *target, char *out, size_t out_len) {
    struct in6_addr addr6;
    struct in6_addr candidate;
    char candidate_text[INET6_ADDRSTRLEN];
    int i;

    if (inet_pton(AF_INET6, target, &addr6) != 1) {
        return 0;
    }

    memcpy(&candidate, &addr6, sizeof(candidate));
    for (i = 15; i >= 8; i--) {
        candidate.s6_addr[i]++;
        if (candidate.s6_addr[i] != 0) {
            break;
        }
    }

    if (inet_ntop(AF_INET6, &candidate, candidate_text, sizeof(candidate_text)) == NULL) {
        return 0;
    }
    if (!same_ipv6_prefix_64(target, candidate_text)) {
        return 0;
    }

    strncpy(out, candidate_text, out_len - 1);
    out[out_len - 1] = '\0';
    return 1;
}

int packet_builder_build_probe_plan(
    const Config *config,
    const Target *target,
    Method method,
    int port,
    ProbePlan *plan,
    char *err,
    size_t err_len
) {
    memset(plan, 0, sizeof(*plan));

    if (target->ip_version == IP_VERSION_4) {
        if (!config->has_ipv4_cidr) {
            snprintf(err, err_len, "missing IPv4 scope");
            return 0;
        }
        if (!target_in_ipv4_cidr(config->ipv4_cidr, target->address)) {
            snprintf(err, err_len, "target %s outside IPv4 scope", target->address);
            return 0;
        }
        if (!choose_ipv4_neighbor(config->ipv4_cidr, target->address, plan->spoofed_source, sizeof(plan->spoofed_source))) {
            snprintf(err, err_len, "cannot derive IPv4 neighbor for %s", target->address);
            return 0;
        }
    } else if (target->ip_version == IP_VERSION_6) {
        if (!config->has_ipv6_csv) {
            snprintf(err, err_len, "missing IPv6 scope");
            return 0;
        }
        if (!choose_ipv6_neighbor(target->address, plan->spoofed_source, sizeof(plan->spoofed_source))) {
            snprintf(err, err_len, "cannot derive IPv6 neighbor for %s", target->address);
            return 0;
        }
    } else {
        snprintf(err, err_len, "unsupported IP version");
        return 0;
    }

    plan->permitted = 1;
    snprintf(
        plan->note,
        sizeof(plan->note),
        "iface=%s method=%s port=%d mtu=%d spoofed_source=%s",
        config->iface,
        method_name(method),
        port,
        config->mtu,
        plan->spoofed_source
    );
    return 1;
}
