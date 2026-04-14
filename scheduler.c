#include "scheduler.h"

#include "capture_engine.h"
#include "packet_builder.h"

#include <stdio.h>
#include <string.h>

static void init_observation(HostObservation *observation, const Target *target, Method method, int port) {
    memset(observation, 0, sizeof(*observation));
    make_timestamp_utc(observation->timestamp, sizeof(observation->timestamp));
    observation->ip_version = target->ip_version;
    strncpy(observation->target, target->address, sizeof(observation->target) - 1);
    strncpy(observation->method, method_name(method), sizeof(observation->method) - 1);
    observation->port = port;
    observation->measurable = 0;
    strncpy(observation->result, result_name(RESULT_UNMEASURABLE), sizeof(observation->result) - 1);
}

static int append_observation(HostObservationList *observations, const HostObservation *observation, char *err, size_t err_len) {
    if (!host_observation_list_append(observations, observation)) {
        snprintf(err, err_len, "failed to append host observation");
        return 0;
    }
    return 1;
}

static int run_unreachable(
    const Config *config,
    const Target *target,
    const CaptureStore *captures,
    int port,
    HostObservationList *observations,
    char *err,
    size_t err_len
) {
    HostObservation observation;
    ProbePlan plan;
    const CaptureRecord *record = NULL;
    int attempt;
    char local_err[128];

    init_observation(&observation, target, METHOD_UNREACHABLE, port);

    if (!packet_builder_build_probe_plan(config, target, METHOD_UNREACHABLE, port, &plan, local_err, sizeof(local_err))) {
        snprintf(observation.note, sizeof(observation.note), "%s", local_err);
        return append_observation(observations, &observation, err, err_len);
    }

    for (attempt = 0; attempt <= config->retry_missing; attempt++) {
        record = capture_engine_find(captures, target->ip_version, target->address, METHOD_UNREACHABLE, port, attempt);
        observation.retry_count = attempt;
        if (record == NULL) {
            continue;
        }
        if (record->missing) {
            continue;
        }
        observation.n1 = record->meas_n1;
        observation.n2 = record->meas_n2;
        break;
    }

    if (record == NULL || record->missing) {
        snprintf(observation.note, sizeof(observation.note), "%s; capture=missing_after_retries", plan.note);
        return append_observation(observations, &observation, err, err_len);
    }

    if ((record->meas_n1 - record->meas_n2) < 2) {
        snprintf(
            observation.note,
            sizeof(observation.note),
            "%s; measurable_threshold_failed n1=%d n2=%d capture_note=%s",
            plan.note,
            record->meas_n1,
            record->meas_n2,
            record->note
        );
        return append_observation(observations, &observation, err, err_len);
    }

    observation.measurable = 1;
    if ((record->detect_n1 - record->detect_n2) >= 2) {
        strncpy(observation.result, result_name(RESULT_NOT_INTERCEPTED), sizeof(observation.result) - 1);
    } else {
        strncpy(observation.result, result_name(RESULT_INTERCEPTED), sizeof(observation.result) - 1);
    }

    snprintf(
        observation.note,
        sizeof(observation.note),
        "%s; detect_n1=%d detect_n2=%d capture_note=%s",
        plan.note,
        record->detect_n1,
        record->detect_n2,
        record->note
    );

    return append_observation(observations, &observation, err, err_len);
}

static int run_fragmentation(
    const Config *config,
    const Target *target,
    const CaptureStore *captures,
    HostObservationList *observations,
    char *err,
    size_t err_len
) {
    HostObservation observation;
    ProbePlan plan;
    const CaptureRecord *record = NULL;
    int attempt;
    char local_err[128];

    init_observation(&observation, target, METHOD_FRAGMENTATION, 0);

    if (!packet_builder_build_probe_plan(config, target, METHOD_FRAGMENTATION, 0, &plan, local_err, sizeof(local_err))) {
        snprintf(observation.note, sizeof(observation.note), "%s", local_err);
        return append_observation(observations, &observation, err, err_len);
    }

    for (attempt = 0; attempt <= config->retry_missing; attempt++) {
        record = capture_engine_find(captures, target->ip_version, target->address, METHOD_FRAGMENTATION, 0, attempt);
        observation.retry_count = attempt;
        if (record == NULL) {
            continue;
        }
        if (record->missing) {
            continue;
        }
        observation.baseline_fragmented = record->meas_baseline_fragmented;
        observation.post_fragmented = record->meas_post_fragmented;
        break;
    }

    if (record == NULL || record->missing) {
        snprintf(observation.note, sizeof(observation.note), "%s; capture=missing_after_retries", plan.note);
        return append_observation(observations, &observation, err, err_len);
    }

    if (record->meas_baseline_fragmented) {
        snprintf(
            observation.note,
            sizeof(observation.note),
            "%s; baseline_already_fragmented capture_note=%s",
            plan.note,
            record->note
        );
        return append_observation(observations, &observation, err, err_len);
    }

    if (!record->meas_post_fragmented) {
        snprintf(
            observation.note,
            sizeof(observation.note),
            "%s; measurable_threshold_failed baseline=%d post=%d capture_note=%s",
            plan.note,
            record->meas_baseline_fragmented,
            record->meas_post_fragmented,
            record->note
        );
        return append_observation(observations, &observation, err, err_len);
    }

    if (record->detect_baseline_fragmented) {
        snprintf(
            observation.note,
            sizeof(observation.note),
            "%s; detect_baseline_fragmented capture_note=%s",
            plan.note,
            record->note
        );
        return append_observation(observations, &observation, err, err_len);
    }

    observation.measurable = 1;
    if (record->detect_post_fragmented) {
        strncpy(observation.result, result_name(RESULT_NOT_INTERCEPTED), sizeof(observation.result) - 1);
    } else {
        strncpy(observation.result, result_name(RESULT_INTERCEPTED), sizeof(observation.result) - 1);
    }

    snprintf(
        observation.note,
        sizeof(observation.note),
        "%s; detect_baseline=%d detect_post=%d capture_note=%s",
        plan.note,
        record->detect_baseline_fragmented,
        record->detect_post_fragmented,
        record->note
    );

    return append_observation(observations, &observation, err, err_len);
}

int scheduler_run(
    const Config *config,
    const TargetList *targets,
    const CaptureStore *captures,
    HostObservationList *observations,
    char *err,
    size_t err_len
) {
    size_t i;
    size_t j;

    for (i = 0; i < targets->len; i++) {
        const Target *target = &targets->items[i];

        if (config->methods.enabled_unreachable) {
            for (j = 0; j < config->port_count; j++) {
                if (!run_unreachable(config, target, captures, config->ports[j], observations, err, err_len)) {
                    return 0;
                }
            }
        }

        if (config->methods.enabled_fragmentation) {
            if (!run_fragmentation(config, target, captures, observations, err, err_len)) {
                return 0;
            }
        }
    }

    return 1;
}
