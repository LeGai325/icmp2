#ifndef CAPTURE_ENGINE_H
#define CAPTURE_ENGINE_H

#include "common.h"

int capture_engine_load_csv(const char *path, CaptureStore *store, char *err, size_t err_len);
const CaptureRecord *capture_engine_find(
    const CaptureStore *store,
    IpVersion ip_version,
    const char *target,
    Method method,
    int port,
    int attempt
);

#endif
