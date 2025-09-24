/*
 * netutils.c - Network utilities
 *
 * Copyright (C) 2013 - 2019, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <math.h>

#include <libcork/core.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include "netutils.h"
#include "utils.h"
#include "crypto.h"

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

extern int verbose;

static const char valid_label_bytes[] =
    "-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";

int
set_reuseport(int socket)
{
    int opt = 1;
    return setsockopt(socket, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
}

size_t
get_sockaddr_len(struct sockaddr *addr)
{
    if (addr->sa_family == AF_INET) {
        return sizeof(struct sockaddr_in);
    } else if (addr->sa_family == AF_INET6) {
        return sizeof(struct sockaddr_in6);
    }
    return 0;
}

#ifdef SET_INTERFACE
int
setinterface(int socket_fd, const char *interface_name)
{
    struct ifreq interface;
    memset(&interface, 0, sizeof(struct ifreq));
    strncpy(interface.ifr_name, interface_name, IFNAMSIZ - 1);
    int res = setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, &interface,
                         sizeof(struct ifreq));
    return res;
}

#endif

int
bind_to_addr(struct sockaddr_storage *storage,
             int socket_fd)
{
    if (storage->ss_family == AF_INET) {
        return bind(socket_fd, (struct sockaddr *)storage, sizeof(struct sockaddr_in));
    } else if (storage->ss_family == AF_INET6) {
        return bind(socket_fd, (struct sockaddr *)storage, sizeof(struct sockaddr_in6));
    }
    return -1;
}

int
construct_udprelay_header(const struct sockaddr_storage *in_addr,
                          char *addr_header)
{
    int addr_header_len = 0;

    if (in_addr->ss_family == AF_INET) {
        struct sockaddr_in *addr = (struct sockaddr_in *)in_addr;
        size_t addr_len          = sizeof(struct in_addr);

        addr_header[addr_header_len++] = 1;
        memcpy(addr_header + addr_header_len, &addr->sin_addr, addr_len);
        addr_header_len += addr_len;
        memcpy(addr_header + addr_header_len, &addr->sin_port, 2);
        addr_header_len += 2;
    } else if (in_addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)in_addr;
        size_t addr_len           = sizeof(struct in6_addr);

        addr_header[addr_header_len++] = 4;
        memcpy(addr_header + addr_header_len, &addr->sin6_addr, addr_len);
        addr_header_len += addr_len;
        memcpy(addr_header + addr_header_len, &addr->sin6_port, 2);
        addr_header_len += 2;
    } else {
        return 0;
    }

    return addr_header_len;
}

int
parse_udprelay_header(const char *buf, const size_t buf_len,
                      char *host, char *port, struct sockaddr_storage *storage)
{
    if (buf == NULL || buf_len == 0) return 0;

    const uint8_t atyp = *(const uint8_t *)buf;
    int offset = 1;

    /* helper to check remaining length */
    #define REMAIN_AT_LEAST(x) ((size_t)(offset) + (size_t)(x) <= (buf_len))

    if ((atyp & ADDRTYPE_MASK) == 1) {
        /* IPv4 */
        size_t in_addr_len = sizeof(struct in_addr);
        /* need: 1 (atyp) + in_addr_len + 2 (port) */
        if (!REMAIN_AT_LEAST(in_addr_len + 2)) {
            LOGE("[udp] parse header: IPv4 header too short");
            return 0;
        }
        if (storage != NULL) {
            struct sockaddr_in *addr = (struct sockaddr_in *)storage;
            addr->sin_family = AF_INET;
            memcpy(&addr->sin_addr, buf + offset, in_addr_len);
            memcpy(&addr->sin_port, buf + offset + in_addr_len, sizeof(uint16_t));
        }
        if (host != NULL) {
            if (inet_ntop(AF_INET, (const void *)(buf + offset), host, INET_ADDRSTRLEN) == NULL) {
                /* inet_ntop 失敗也不致命，但清空 host */
                host[0] = '\0';
            }
        }
        offset += in_addr_len + 2;
    } else if ((atyp & ADDRTYPE_MASK) == 3) {
        /* Domain name */
        if (!REMAIN_AT_LEAST(1)) {
            LOGE("[udp] parse header: domain length byte missing");
            return 0;
        }
        uint8_t name_len = *(const uint8_t *)(buf + offset);
        /* total needed: 1 (atyp) + 1 (name_len) + name_len + 2 (port) */
        if (!REMAIN_AT_LEAST(1 + name_len + 2)) {
            LOGE("[udp] parse header: domain header too short (name_len=%d, buf_len=%zu)", name_len, buf_len);
            return 0;
        }
        /* guard tmp buffer size */
        if (name_len >= MAX_HOSTNAME_LEN) {
            LOGE("[udp] parse header: domain name too long (%d >= %d)", name_len, MAX_HOSTNAME_LEN);
            return 0;
        }

        if (storage != NULL) {
            char tmp[MAX_HOSTNAME_LEN];
            memset(tmp, 0, sizeof(tmp));
            memcpy(tmp, buf + offset + 1, name_len);
            tmp[name_len] = '\0'; /* ensure nul-terminated */

            struct cork_ip ip;
            if (cork_ip_init(&ip, tmp) != -1) {
                if (ip.version == 4) {
                    struct sockaddr_in *addr = (struct sockaddr_in *)storage;
                    memset(addr, 0, sizeof(*addr));
                    addr->sin_family = AF_INET;
                    if (inet_pton(AF_INET, tmp, &(addr->sin_addr)) <= 0) {
                        LOGE("[udp] inet_pton failed for %s", tmp);
                    }
                    memcpy(&addr->sin_port, buf + offset + 1 + name_len, sizeof(uint16_t));
                } else if (ip.version == 6) {
                    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)storage;
                    memset(addr6, 0, sizeof(*addr6));
                    addr6->sin6_family = AF_INET6;
                    if (inet_pton(AF_INET6, tmp, &(addr6->sin6_addr)) <= 0) {
                        LOGE("[udp] inet_pton failed for %s", tmp);
                    }
                    memcpy(&addr6->sin6_port, buf + offset + 1 + name_len, sizeof(uint16_t));
                } else {
                    /* leave storage with AF_UNSPEC so caller can know it failed */
                    ((struct sockaddr_storage*)storage)->ss_family = AF_UNSPEC;
                }
            } else {
                /* try resolving later — for now leave storage untouched or AF_UNSPEC */
                ((struct sockaddr_storage*)storage)->ss_family = AF_UNSPEC;
            }
        }
        if (host != NULL) {
            /* copy and NUL-terminate host */
            memcpy(host, buf + offset + 1, name_len);
            host[name_len] = '\0';
        }
        offset += 1 + name_len + 2;
    } else if ((atyp & ADDRTYPE_MASK) == 4) {
        /* IPv6 */
        size_t in6_addr_len = sizeof(struct in6_addr);
        /* need: 1 (atyp) + in6_addr_len + 2 (port) */
        if (!REMAIN_AT_LEAST(in6_addr_len + 2)) {
            LOGE("[udp] parse header: IPv6 header too short");
            return 0;
        }
        if (storage != NULL) {
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *)storage;
            addr->sin6_family = AF_INET6;
            memcpy(&addr->sin6_addr, buf + offset, in6_addr_len);
            memcpy(&addr->sin6_port, buf + offset + in6_addr_len, sizeof(uint16_t));
        }
        if (host != NULL) {
            if (inet_ntop(AF_INET6, (const void *)(buf + offset), host, INET6_ADDRSTRLEN) == NULL) {
                host[0] = '\0';
            }
        }
        offset += in6_addr_len + 2;
    } else {
        LOGE("[udp] parse header: unknown atyp %d", atyp);
        return 0;
    }

    /* final sanity */
    if (offset <= 1 || (size_t)offset > buf_len) {
        LOGE("[udp] invalid header parsing result (offset=%d, buf_len=%zu)", offset, buf_len);
        return 0;
    }

    /* fill port if requested (offset currently points just past port) */
    if (port != NULL) {
        /* port bytes are at offset-2 .. offset-1 */
        int port_val = load16_be((const uint8_t *)buf + offset - 2);
        sprintf(port, "%d", port_val);
    }

    return offset;
}

ssize_t
get_sockaddr(char *host, char *port,
             struct sockaddr_storage *storage, int block,
             int ipv6first)
{
    struct cork_ip ip;
    if (cork_ip_init(&ip, host) != -1) {
        if (ip.version == 4) {
            struct sockaddr_in *addr = (struct sockaddr_in *)storage;
            addr->sin_family = AF_INET;
            inet_pton(AF_INET, host, &(addr->sin_addr));
            if (port != NULL) {
                addr->sin_port = htons(atoi(port));
            }
        } else if (ip.version == 6) {
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *)storage;
            addr->sin6_family = AF_INET6;
            inet_pton(AF_INET6, host, &(addr->sin6_addr));
            if (port != NULL) {
                addr->sin6_port = htons(atoi(port));
            }
        }
        return 0;
    } else {
        struct addrinfo hints;
        struct addrinfo *result, *rp;

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family   = AF_UNSPEC;   /* Return IPv4 and IPv6 choices */
        hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */

        int err = getaddrinfo(host, port, &hints, &result);

        if (err != 0) {
            LOGE("getaddrinfo: %s", gai_strerror(err));
            return -1;
        }

        int prefer_af = ipv6first ? AF_INET6 : AF_INET;
        for (rp = result; rp != NULL; rp = rp->ai_next)
            if (rp->ai_family == prefer_af) {
                if (rp->ai_family == AF_INET)
                    memcpy(storage, rp->ai_addr, sizeof(struct sockaddr_in));
                else if (rp->ai_family == AF_INET6)
                    memcpy(storage, rp->ai_addr, sizeof(struct sockaddr_in6));
                break;
            }

        if (rp == NULL) {
            for (rp = result; rp != NULL; rp = rp->ai_next) {
                if (rp->ai_family == AF_INET)
                    memcpy(storage, rp->ai_addr, sizeof(struct sockaddr_in));
                else if (rp->ai_family == AF_INET6)
                    memcpy(storage, rp->ai_addr, sizeof(struct sockaddr_in6));
                break;
            }
        }

        if (rp == NULL) {
            LOGE("failed to resolve remote addr");
            return -1;
        }

        freeaddrinfo(result);
        return 0;
    }

    return -1;
}

char *
get_addr_str(const struct sockaddr *sa, bool has_port)
{
    static char s[SS_ADDRSTRLEN];
    memset(s, 0, SS_ADDRSTRLEN);
    char addr[INET6_ADDRSTRLEN] = { 0 };
    char port[PORTSTRLEN]       = { 0 };
    uint16_t p;
    struct sockaddr_in sa_in;
    struct sockaddr_in6 sa_in6;

    if (sa == NULL) {
        strncpy(s, "null", SS_ADDRSTRLEN - 1);
        return s;
    }

    switch (sa->sa_family) {
    case AF_INET:
        memcpy(&sa_in, sa, sizeof(struct sockaddr_in));
        inet_ntop(AF_INET, &sa_in.sin_addr, addr, INET_ADDRSTRLEN);
        p = ntohs(sa_in.sin_port);
        sprintf(port, "%d", p);
        break;

    case AF_INET6:
        memcpy(&sa_in6, sa, sizeof(struct sockaddr_in6));
        inet_ntop(AF_INET6, &sa_in6.sin6_addr, addr, INET6_ADDRSTRLEN);
        p = ntohs(sa_in6.sin6_port);
        sprintf(port, "%d", p);
        break;

    default:
        strncpy(s, "Unknown AF", SS_ADDRSTRLEN - 1);
        return s;
    }

    snprintf(s, SS_ADDRSTRLEN, has_port ? "%s:%s" : "%s", addr, port);

    return s;
}

int
sockaddr_cmp(struct sockaddr_storage *addr1,
             struct sockaddr_storage *addr2, socklen_t len)
{
    struct sockaddr_in *p1_in   = (struct sockaddr_in *)addr1;
    struct sockaddr_in *p2_in   = (struct sockaddr_in *)addr2;
    struct sockaddr_in6 *p1_in6 = (struct sockaddr_in6 *)addr1;
    struct sockaddr_in6 *p2_in6 = (struct sockaddr_in6 *)addr2;
    if (p1_in->sin_family < p2_in->sin_family)
        return -1;
    if (p1_in->sin_family > p2_in->sin_family)
        return 1;
    /* compare ip4 */
    if (p1_in->sin_family == AF_INET) {
        /* just order it, ntohs not required */
        if (p1_in->sin_port < p2_in->sin_port)
            return -1;
        if (p1_in->sin_port > p2_in->sin_port)
            return 1;
        return memcmp(&p1_in->sin_addr, &p2_in->sin_addr, INET_SIZE);
    } else if (p1_in6->sin6_family == AF_INET6) {
        /* just order it, ntohs not required */
        if (p1_in6->sin6_port < p2_in6->sin6_port)
            return -1;
        if (p1_in6->sin6_port > p2_in6->sin6_port)
            return 1;
        return memcmp(&p1_in6->sin6_addr, &p2_in6->sin6_addr,
                      INET6_SIZE);
    } else {
        /* eek unknown type, perform this comparison for sanity. */
        return memcmp(addr1, addr2, len);
    }
}

int
sockaddr_cmp_addr(struct sockaddr_storage *addr1,
                  struct sockaddr_storage *addr2, socklen_t len)
{
    struct sockaddr_in *p1_in   = (struct sockaddr_in *)addr1;
    struct sockaddr_in *p2_in   = (struct sockaddr_in *)addr2;
    struct sockaddr_in6 *p1_in6 = (struct sockaddr_in6 *)addr1;
    struct sockaddr_in6 *p2_in6 = (struct sockaddr_in6 *)addr2;
    if (p1_in->sin_family < p2_in->sin_family)
        return -1;
    if (p1_in->sin_family > p2_in->sin_family)
        return 1;
    if (verbose) {
        LOGI("sockaddr_cmp_addr: sin_family equal? %d", p1_in->sin_family == p2_in->sin_family);
    }
    /* compare ip4 */
    if (p1_in->sin_family == AF_INET) {
        return memcmp(&p1_in->sin_addr, &p2_in->sin_addr, INET_SIZE);
    } else if (p1_in6->sin6_family == AF_INET6) {
        return memcmp(&p1_in6->sin6_addr, &p2_in6->sin6_addr,
                      INET6_SIZE);
    } else {
        /* eek unknown type, perform this comparison for sanity. */
        return memcmp(addr1, addr2, len);
    }
}

int
validate_hostname(const char *hostname, const int hostname_len)
{
    if (hostname == NULL)
        return 0;

    if (hostname_len < 1 || hostname_len > 255)
        return 0;

    if (hostname[0] == '.')
        return 0;

    const char *label = hostname;
    while (label < hostname + hostname_len) {
        size_t label_len = hostname_len - (label - hostname);
        char *next_dot   = strchr(label, '.');
        if (next_dot != NULL)
            label_len = next_dot - label;

        if (label + label_len > hostname + hostname_len)
            return 0;

        if (label_len > 63 || label_len < 1)
            return 0;

        if (label[0] == '-' || label[label_len - 1] == '-')
            return 0;

        if (strspn(label, valid_label_bytes) < label_len)
            return 0;

        label += label_len + 1;
    }

    return 1;
}

int
is_ipv6only(ss_addr_t *servers, size_t server_num, int ipv6first)
{
    int i;
    for (i = 0; i < server_num; i++) {
        struct sockaddr_storage storage;
        memset(&storage, 0, sizeof(struct sockaddr_storage));
        if (get_sockaddr(servers[i].host, servers[i].port, &storage, 1, ipv6first) == -1) {
            FATAL("failed to resolve the provided hostname");
        }
        if (storage.ss_family != AF_INET6) {
            return 0;
        }
    }
    return 1;
}
