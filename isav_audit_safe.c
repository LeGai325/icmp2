#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
typedef int socklen_t;
#else
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#endif

#define MAX_LINE 1024
#define MAX_IPV6_TARGETS 2000000
#define MAX_IPV4_TARGETS 65536

static const int k_ports[] = {22, 53, 80, 443};
static const size_t k_port_count = sizeof(k_ports) / sizeof(k_ports[0]);

typedef struct {
    int use_ipv4;
    int use_ipv6;
    char ipv4_cidr[64];
    char ipv6_csv[512];
    char out_csv[512];
    int timeout_ms;
} Config;

static void socket_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        exit(1);
    }
#endif
}

static void socket_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

static void close_socket(int s) {
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
}

static int set_nonblocking(int fd) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(fd, FIONBIO, &mode);
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    if (*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while (end > s && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
        *end-- = '\0';
    }
    return s;
}

static int connect_with_timeout(const struct sockaddr *sa, socklen_t salen, int timeout_ms) {
    int fd = socket(sa->sa_family, SOCK_STREAM, 0);
    if (fd < 0) return 0;

    if (set_nonblocking(fd) != 0) {
        close_socket(fd);
        return 0;
    }

    int rc = connect(fd, sa, salen);
    if (rc == 0) {
        close_socket(fd);
        return 1;
    }

#ifdef _WIN32
    int err = WSAGetLastError();
    if (!(err == WSAEWOULDBLOCK || err == WSAEINPROGRESS || err == WSAEINVAL)) {
        close_socket(fd);
        return 0;
    }
#else
    if (errno != EINPROGRESS) {
        close_socket(fd);
        return 0;
    }
#endif

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    rc = select(fd + 1, NULL, &wfds, NULL, &tv);
    if (rc <= 0) {
        close_socket(fd);
        return 0;
    }

    int so_error = 0;
    socklen_t len = sizeof(so_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&so_error, &len) != 0) {
        close_socket(fd);
        return 0;
    }

    close_socket(fd);
    return so_error == 0;
}

static int ipv4_private_only(uint32_t host_order_ip) {
    uint8_t a = (host_order_ip >> 24) & 0xFF;
    uint8_t b = (host_order_ip >> 16) & 0xFF;

    if (a == 10) return 1;
    if (a == 172 && b >= 16 && b <= 31) return 1;
    if (a == 192 && b == 168) return 1;
    return 0;
}

static int parse_ipv4_cidr(const char *cidr, uint32_t *network, int *prefix) {
    char buf[64];
    strncpy(buf, cidr, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    if (!slash) return 0;
    *slash = '\0';

    int pfx = atoi(slash + 1);
    if (pfx < 0 || pfx > 32) return 0;

    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1) return 0;

    uint32_t ip = ntohl(addr.s_addr);
    uint32_t mask = (pfx == 0) ? 0 : (0xFFFFFFFFu << (32 - pfx));
    *network = ip & mask;
    *prefix = pfx;
    return 1;
}

static int scan_ports_ipv4(uint32_t host_ip, int timeout_ms, int *open_count, char *open_ports, size_t open_ports_len) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(host_ip);

    *open_count = 0;
    open_ports[0] = '\0';

    for (size_t i = 0; i < k_port_count; i++) {
        sa.sin_port = htons((uint16_t)k_ports[i]);
        if (connect_with_timeout((struct sockaddr *)&sa, sizeof(sa), timeout_ms)) {
            char tmp[32];
            snprintf(tmp, sizeof(tmp), "%s%d", (*open_count == 0) ? "" : "|", k_ports[i]);
            strncat(open_ports, tmp, open_ports_len - strlen(open_ports) - 1);
            (*open_count)++;
        }
    }
    return *open_count > 0;
}

static int scan_ports_ipv6(const struct in6_addr *addr, int timeout_ms, int *open_count, char *open_ports, size_t open_ports_len) {
    struct sockaddr_in6 sa6;
    memset(&sa6, 0, sizeof(sa6));
    sa6.sin6_family = AF_INET6;
    sa6.sin6_addr = *addr;

    *open_count = 0;
    open_ports[0] = '\0';

    for (size_t i = 0; i < k_port_count; i++) {
        sa6.sin6_port = htons((uint16_t)k_ports[i]);
        if (connect_with_timeout((struct sockaddr *)&sa6, sizeof(sa6), timeout_ms)) {
            char tmp[32];
            snprintf(tmp, sizeof(tmp), "%s%d", (*open_count == 0) ? "" : "|", k_ports[i]);
            strncat(open_ports, tmp, open_ports_len - strlen(open_ports) - 1);
            (*open_count)++;
        }
    }
    return *open_count > 0;
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s --out result.csv [--timeout 800] [--ipv4-cidr 10.0.0.0/24] [--ipv6-csv ipv6.csv]\n\n"
            "Notes:\n"
            "  1) IPv4 only allows RFC1918 private ranges and at most 65536 hosts.\n"
            "  2) IPv6 targets are loaded from CSV, one address per line (or first column).\n",
            prog);
}

static int parse_args(int argc, char **argv, Config *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->timeout_ms = 800;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ipv4-cidr") == 0 && i + 1 < argc) {
            cfg->use_ipv4 = 1;
            strncpy(cfg->ipv4_cidr, argv[++i], sizeof(cfg->ipv4_cidr) - 1);
        } else if (strcmp(argv[i], "--ipv6-csv") == 0 && i + 1 < argc) {
            cfg->use_ipv6 = 1;
            strncpy(cfg->ipv6_csv, argv[++i], sizeof(cfg->ipv6_csv) - 1);
        } else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            strncpy(cfg->out_csv, argv[++i], sizeof(cfg->out_csv) - 1);
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            cfg->timeout_ms = atoi(argv[++i]);
            if (cfg->timeout_ms < 100) cfg->timeout_ms = 100;
            if (cfg->timeout_ms > 10000) cfg->timeout_ms = 10000;
        } else {
            return 0;
        }
    }

    if (!cfg->use_ipv4 && !cfg->use_ipv6) return 0;
    if (cfg->out_csv[0] == '\0') return 0;
    return 1;
}

static int run_ipv4_scan(FILE *out, const Config *cfg, uint64_t *total, uint64_t *open_hosts) {
    uint32_t network;
    int prefix;
    if (!parse_ipv4_cidr(cfg->ipv4_cidr, &network, &prefix)) {
        fprintf(stderr, "Invalid IPv4 CIDR: %s\n", cfg->ipv4_cidr);
        return 0;
    }

    if (prefix < 16) {
        fprintf(stderr, "Refused: IPv4 CIDR too large. Use /16 or smaller range only.\n");
        return 0;
    }

    uint64_t host_count = (prefix == 32) ? 1 : (1ull << (32 - prefix));
    if (host_count > MAX_IPV4_TARGETS) {
        fprintf(stderr, "Refused: IPv4 target count exceeds %d hosts.\n", MAX_IPV4_TARGETS);
        return 0;
    }

    uint32_t start = network;
    uint32_t end = network + (uint32_t)host_count - 1;

    for (uint32_t ip = start; ip <= end; ip++) {
        if (!ipv4_private_only(ip)) {
            fprintf(stderr, "Refused: Non-private IPv4 target detected. Only RFC1918 ranges are allowed.\n");
            return 0;
        }
    }

    uint32_t first = start;
    uint32_t last = end;
    if (prefix <= 30) {
        first = start + 1;
        last = end - 1;
    }

    char ipbuf[INET_ADDRSTRLEN];
    for (uint32_t ip = first; ip <= last; ip++) {
        struct in_addr ia;
        ia.s_addr = htonl(ip);
        if (!inet_ntop(AF_INET, &ia, ipbuf, sizeof(ipbuf))) continue;

        int open_count = 0;
        char open_ports[128];
        scan_ports_ipv4(ip, cfg->timeout_ms, &open_count, open_ports, sizeof(open_ports));

        fprintf(out, "4,%s,%d,%s\n", ipbuf, open_count, open_count ? open_ports : "-");
        (*total)++;
        if (open_count > 0) (*open_hosts)++;

        if (((*total) % 500) == 0) {
            fprintf(stderr, "[IPv4] scanned=%llu open_hosts=%llu\n",
                    (unsigned long long)(*total), (unsigned long long)(*open_hosts));
        }

        if (ip == last) break;
    }

    return 1;
}

static int run_ipv6_scan(FILE *out, const Config *cfg, uint64_t *total, uint64_t *open_hosts) {
    FILE *f = fopen(cfg->ipv6_csv, "r");
    if (!f) {
        fprintf(stderr, "Cannot open IPv6 CSV: %s\n", cfg->ipv6_csv);
        return 0;
    }

    char line[MAX_LINE];
    uint64_t loaded = 0;
    while (fgets(line, sizeof(line), f)) {
        char *s = trim(line);
        if (*s == '\0' || *s == '#') continue;

        char *comma = strchr(s, ',');
        if (comma) *comma = '\0';
        s = trim(s);

        struct in6_addr a6;
        if (inet_pton(AF_INET6, s, &a6) != 1) continue;

        int open_count = 0;
        char open_ports[128];
        scan_ports_ipv6(&a6, cfg->timeout_ms, &open_count, open_ports, sizeof(open_ports));

        char ipbuf[INET6_ADDRSTRLEN];
        if (!inet_ntop(AF_INET6, &a6, ipbuf, sizeof(ipbuf))) continue;

        fprintf(out, "6,%s,%d,%s\n", ipbuf, open_count, open_count ? open_ports : "-");
        (*total)++;
        loaded++;
        if (open_count > 0) (*open_hosts)++;

        if ((loaded % 500) == 0) {
            fprintf(stderr, "[IPv6] scanned=%llu open_hosts=%llu\n",
                    (unsigned long long)loaded, (unsigned long long)(*open_hosts));
        }

        if (loaded >= MAX_IPV6_TARGETS) {
            fprintf(stderr, "IPv6 scan capped at %d targets.\n", MAX_IPV6_TARGETS);
            break;
        }
    }

    fclose(f);
    return 1;
}

int main(int argc, char **argv) {
    Config cfg;
    if (!parse_args(argc, argv, &cfg)) {
        usage(argv[0]);
        return 1;
    }

    socket_init();

    FILE *out = fopen(cfg.out_csv, "w");
    if (!out) {
        fprintf(stderr, "Cannot open output file: %s\n", cfg.out_csv);
        socket_cleanup();
        return 1;
    }

    fprintf(out, "ip_version,target,open_port_count,open_ports\n");

    uint64_t total = 0;
    uint64_t open_hosts = 0;

    if (cfg.use_ipv4) {
        if (!run_ipv4_scan(out, &cfg, &total, &open_hosts)) {
            fclose(out);
            socket_cleanup();
            return 1;
        }
    }

    if (cfg.use_ipv6) {
        if (!run_ipv6_scan(out, &cfg, &total, &open_hosts)) {
            fclose(out);
            socket_cleanup();
            return 1;
        }
    }

    fclose(out);
    socket_cleanup();

    fprintf(stderr, "Done. total_scanned=%llu open_hosts=%llu output=%s\n",
            (unsigned long long)total, (unsigned long long)open_hosts, cfg.out_csv);
    return 0;
}
