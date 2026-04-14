#include "capture_engine.h"
#include "classifier.h"
#include "common.h"
#include "scheduler.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
}

static void print_usage(const char *prog) {
    fprintf(
        stderr,
        "Usage:\n"
        "  %s --iface eth0 --capture-observations lab_capture.csv --out-prefix output/run1 \\\n"
        "     [--ipv4-cidr 192.168.10.0/24] [--ipv6-csv ipv6_targets.csv] \\\n"
        "     [--ports 22,53,80,443] [--methods unreachable,fragmentation] \\\n"
        "     [--mtu 1300] [--cooldown 600] [--retry-missing 1]\n\n"
        "Notes:\n"
        "  1) This lab tool consumes isolated-environment observations from CSV.\n"
        "  2) It reproduces the paper decision logic and deployment classification.\n",
        prog
    );
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
        } else if (strcmp(argv[i], "--ipv6-csv") == 0 && i + 1 < argc) {
            config->has_ipv6_csv = 1;
            strncpy(config->ipv6_csv, argv[++i], sizeof(config->ipv6_csv) - 1);
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
    if (config->capture_csv[0] == '\0' || config->out_prefix[0] == '\0') {
        return 0;
    }
    if (!config->has_ipv4_cidr && !config->has_ipv6_csv) {
        return 0;
    }
    if (config->mtu <= 0 || config->cooldown < 0 || config->retry_missing < 0) {
        return 0;
    }

    return 1;
}

int main(int argc, char **argv) {
    Config config;
    TargetList targets;
    CaptureStore captures;
    HostObservationList observations;
    DeploymentList deployments;
    char err[256];
    char host_csv[MAX_PATH_LEN + 64];
    char deployment_csv[MAX_PATH_LEN + 64];
    int ok = 0;

    if (!parse_args(argc, argv, &config)) {
        print_usage(argv[0]);
        return 1;
    }

    target_list_init(&targets);
    capture_store_init(&captures);
    host_observation_list_init(&observations);
    deployment_list_init(&deployments);

    if (config.has_ipv4_cidr && !add_ipv4_targets_from_cidr(config.ipv4_cidr, &targets, err, sizeof(err))) {
        fprintf(stderr, "%s\n", err);
        goto cleanup;
    }
    if (config.has_ipv6_csv && !add_ipv6_targets_from_csv(config.ipv6_csv, &targets, err, sizeof(err))) {
        fprintf(stderr, "%s\n", err);
        goto cleanup;
    }
    if (targets.len == 0) {
        fprintf(stderr, "no targets loaded from the configured scope\n");
        goto cleanup;
    }

    if (!capture_engine_load_csv(config.capture_csv, &captures, err, sizeof(err))) {
        fprintf(stderr, "%s\n", err);
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
    host_observation_list_free(&observations);
    capture_store_free(&captures);
    target_list_free(&targets);
    return ok ? 0 : 1;
}
