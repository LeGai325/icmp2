#ifndef PACKET_BUILDER_H
#define PACKET_BUILDER_H

#include "common.h"

typedef struct {
    char spoofed_source[INET6_ADDRSTRLEN];
    int permitted;
    char note[MAX_NOTE_LEN];
} ProbePlan;

int packet_builder_build_probe_plan(
    const Config *config,
    const Target *target,
    Method method,
    int port,
    ProbePlan *plan,
    char *err,
    size_t err_len
);

#endif
