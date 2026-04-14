#ifndef SCHEDULER_H
#define SCHEDULER_H

#include "common.h"

int scheduler_run(
    const Config *config,
    const TargetList *targets,
    const CaptureStore *captures,
    HostObservationList *observations,
    char *err,
    size_t err_len
);

#endif
