#include "capture_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int split_csv_line(char *line, char **cols, int max_cols) {
    int count = 0;
    char *cursor = line;

    while (*cursor != '\0' && count < max_cols) {
        char *write;
        int quoted = 0;

        cols[count++] = cursor;
        write = cursor;

        if (*cursor == '"') {
            quoted = 1;
            cursor++;
            cols[count - 1] = write;
        }

        while (*cursor != '\0') {
            if (quoted) {
                if (*cursor == '"' && cursor[1] == '"') {
                    *write++ = '"';
                    cursor += 2;
                    continue;
                }
                if (*cursor == '"') {
                    cursor++;
                    if (*cursor == ',') {
                        cursor++;
                    }
                    break;
                }
            } else if (*cursor == ',') {
                cursor++;
                break;
            }

            if (*cursor == '\r' || *cursor == '\n') {
                break;
            }

            *write++ = *cursor++;
        }
        *write = '\0';
    }

    return count;
}

static int parse_ip_version(const char *value) {
    if (strcmp(value, "4") == 0) {
        return IP_VERSION_4;
    }
    if (strcmp(value, "6") == 0) {
        return IP_VERSION_6;
    }
    return IP_VERSION_UNKNOWN;
}

int capture_engine_load_csv(const char *path, CaptureStore *store, char *err, size_t err_len) {
    FILE *fp;
    char line[2048];
    int line_no = 0;

    fp = fopen(path, "r");
    if (fp == NULL) {
        snprintf(err, err_len, "cannot open capture observations: %s", path);
        return 0;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *cols[16];
        int count;
        CaptureRecord record;
        char *value;

        line_no++;
        value = trim(line);
        if (*value == '\0' || *value == '#') {
            continue;
        }
        if (line_no == 1 && strstr(value, "ip_version") != NULL && strstr(value, "target") != NULL) {
            continue;
        }

        count = split_csv_line(value, cols, 16);
        if (count < 15) {
            fclose(fp);
            snprintf(err, err_len, "invalid capture CSV at line %d", line_no);
            return 0;
        }

        memset(&record, 0, sizeof(record));
        record.ip_version = parse_ip_version(trim(cols[0]));
        strncpy(record.target, trim(cols[1]), sizeof(record.target) - 1);
        record.method = parse_method_name(trim(cols[2]));
        record.port = atoi(trim(cols[3]));
        record.attempt = atoi(trim(cols[4]));
        record.meas_n1 = atoi(trim(cols[5]));
        record.meas_n2 = atoi(trim(cols[6]));
        record.meas_baseline_fragmented = atoi(trim(cols[7]));
        record.meas_post_fragmented = atoi(trim(cols[8]));
        record.detect_n1 = atoi(trim(cols[9]));
        record.detect_n2 = atoi(trim(cols[10]));
        record.detect_baseline_fragmented = atoi(trim(cols[11]));
        record.detect_post_fragmented = atoi(trim(cols[12]));
        record.missing = atoi(trim(cols[13]));
        strncpy(record.note, trim(cols[14]), sizeof(record.note) - 1);

        if (record.ip_version == IP_VERSION_UNKNOWN || record.method == METHOD_NONE) {
            fclose(fp);
            snprintf(err, err_len, "invalid method or IP version at line %d", line_no);
            return 0;
        }

        if (!capture_store_append(store, &record)) {
            fclose(fp);
            snprintf(err, err_len, "failed to append capture record");
            return 0;
        }
    }

    fclose(fp);
    return 1;
}

const CaptureRecord *capture_engine_find(
    const CaptureStore *store,
    IpVersion ip_version,
    const char *target,
    Method method,
    int port,
    int attempt
) {
    size_t i;

    for (i = 0; i < store->len; i++) {
        const CaptureRecord *record = &store->items[i];

        if (record->ip_version != ip_version) {
            continue;
        }
        if (record->method != method) {
            continue;
        }
        if (strcmp(record->target, target) != 0) {
            continue;
        }
        if (record->attempt != attempt) {
            continue;
        }
        if (method == METHOD_UNREACHABLE && record->port != port) {
            continue;
        }
        return record;
    }

    return NULL;
}
