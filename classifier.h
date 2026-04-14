#ifndef CLASSIFIER_H
#define CLASSIFIER_H

#include "common.h"

int classifier_build_deployments(
    const HostObservationList *observations,
    DeploymentList *deployments,
    char *err,
    size_t err_len
);

int classifier_write_host_csv(const char *path, const HostObservationList *observations, char *err, size_t err_len);
int classifier_write_deployment_csv(const char *path, const DeploymentList *deployments, char *err, size_t err_len);

#endif
