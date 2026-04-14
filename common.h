#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>

#define MAX_PORTS 32
#define MAX_PATH_LEN 512
#define MAX_NOTE_LEN 256
#define MAX_SCOPE_LEN 96
#define MAX_IPV4_ENUM_TARGETS 65536

typedef enum {
    IP_VERSION_UNKNOWN = 0,
    IP_VERSION_4 = 4,
    IP_VERSION_6 = 6
} IpVersion;

typedef enum {
    METHOD_NONE = 0,
    METHOD_UNREACHABLE = 1,
    METHOD_FRAGMENTATION = 2
} Method;

typedef enum {
    RESULT_UNSET = 0,
    RESULT_INTERCEPTED,
    RESULT_NOT_INTERCEPTED,
    RESULT_UNMEASURABLE
} ResultKind;

typedef struct {
    int enabled_unreachable;
    int enabled_fragmentation;
} MethodSelection;

typedef struct {
    IpVersion ip_version;
    char address[INET6_ADDRSTRLEN];
} Target;

typedef struct {
    Target *items;
    size_t len;
    size_t cap;
} TargetList;

typedef struct {
    char iface[64];
    int has_ipv4_cidr;
    char ipv4_cidr[64];
    int has_ipv6_csv;
    char ipv6_csv[MAX_PATH_LEN];
    char capture_csv[MAX_PATH_LEN];
    char out_prefix[MAX_PATH_LEN];
    int ports[MAX_PORTS];
    size_t port_count;
    MethodSelection methods;
    int mtu;
    int cooldown;
    int retry_missing;
} Config;

typedef struct {
    IpVersion ip_version;
    char target[INET6_ADDRSTRLEN];
    Method method;
    int port;
    int attempt;
    int meas_n1;
    int meas_n2;
    int meas_baseline_fragmented;
    int meas_post_fragmented;
    int detect_n1;
    int detect_n2;
    int detect_baseline_fragmented;
    int detect_post_fragmented;
    int missing;
    char note[MAX_NOTE_LEN];
} CaptureRecord;

typedef struct {
    CaptureRecord *items;
    size_t len;
    size_t cap;
} CaptureStore;

typedef struct {
    char timestamp[32];
    IpVersion ip_version;
    char target[INET6_ADDRSTRLEN];
    char method[24];
    int port;
    int measurable;
    char result[20];
    int n1;
    int n2;
    int baseline_fragmented;
    int post_fragmented;
    int retry_count;
    char note[MAX_NOTE_LEN];
} HostObservation;

typedef struct {
    HostObservation *items;
    size_t len;
    size_t cap;
} HostObservationList;

typedef struct {
    IpVersion ip_version;
    char scope[MAX_SCOPE_LEN];
    char classification[20];
    char method_coverage[20];
    int observation_count;
} DeploymentObservation;

typedef struct {
    DeploymentObservation *items;
    size_t len;
    size_t cap;
} DeploymentList;

void target_list_init(TargetList *list);
void target_list_free(TargetList *list);
int target_list_append(TargetList *list, const Target *target);
int add_ipv4_targets_from_cidr(const char *cidr, TargetList *list, char *err, size_t err_len);
int add_ipv6_targets_from_csv(const char *path, TargetList *list, char *err, size_t err_len);
int target_in_ipv4_cidr(const char *cidr, const char *ip);
int ipv4_cidr_bounds(const char *cidr, uint32_t *start, uint32_t *end, int *prefix);
int same_ipv6_prefix_64(const char *a, const char *b);

void capture_store_init(CaptureStore *store);
void capture_store_free(CaptureStore *store);
int capture_store_append(CaptureStore *store, const CaptureRecord *record);

void host_observation_list_init(HostObservationList *list);
void host_observation_list_free(HostObservationList *list);
int host_observation_list_append(HostObservationList *list, const HostObservation *observation);

void deployment_list_init(DeploymentList *list);
void deployment_list_free(DeploymentList *list);
int deployment_list_append(DeploymentList *list, const DeploymentObservation *observation);

void make_timestamp_utc(char *buf, size_t len);
Method parse_method_name(const char *text);
const char *method_name(Method method);
const char *result_name(ResultKind result);
char *trim(char *text);

#endif
