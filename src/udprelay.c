/*
 * udprelay.c - Setup UDP relay for both client and server
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

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#ifndef __MINGW32__
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#endif
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include <libcork/core.h>

#include "utils.h"
#include "netutils.h"
#include "cache.h"
#include "udprelay.h"
#include "probe.h"
#include "dot.h"
#include "metrics.h"
#include "winsock.h"
#define MAX_UDP_CONN_NUM 256

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

static void server_recv_cb(EV_P_ ev_io *w, int revents);
static void remote_recv_cb(EV_P_ ev_io *w, int revents);
static void remote_timeout_cb(EV_P_ ev_timer *watcher, int revents);

static void hash_key_fill(char *out_key, const int af, const struct sockaddr_storage *addr);
static void close_and_free_remote(EV_P_ remote_ctx_t *ctx);
static remote_ctx_t *new_remote(int fd, server_ctx_t *server_ctx);

extern int verbose;
extern int reuse_port;

static int packet_size                               = DEFAULT_PACKET_SIZE;
static int buf_size                                  = DEFAULT_PACKET_SIZE * 2;
static int server_num                                = 0;
static server_ctx_t *server_ctx_list[MAX_REMOTE_NUM] = { NULL };

const char *s_port = NULL;

#ifdef SO_NOSIGPIPE
static int
set_nosigpipe(int socket_fd)
{
    int opt = 1;
    return setsockopt(socket_fd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
}
#endif

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT       19
#endif

#ifndef IPV6_TRANSPARENT
#define IPV6_TRANSPARENT     75
#endif

#ifndef IP_RECVORIGDSTADDR
#ifdef  IP_ORIGDSTADDR
#define IP_RECVORIGDSTADDR   IP_ORIGDSTADDR
#else
#define IP_RECVORIGDSTADDR   20
#endif
#endif

#ifndef IPV6_RECVORIGDSTADDR
#ifdef  IPV6_ORIGDSTADDR
#define IPV6_RECVORIGDSTADDR   IPV6_ORIGDSTADDR
#else
#define IPV6_RECVORIGDSTADDR   74
#endif
#endif

/* key length should match usage in cache (keep stable) */
#define HASH_KEY_LEN (sizeof(struct sockaddr_storage) + sizeof(int))

/* Fill caller-provided buffer with key (no static buffer) */
static void
hash_key_fill(char *out_key, const int af, const struct sockaddr_storage *addr)
{
    memset(out_key, 0, HASH_KEY_LEN);
    memcpy(out_key, &af, sizeof(int));
    memcpy(out_key + sizeof(int), (const uint8_t *)addr, sizeof(struct sockaddr_storage));
}

char *
get_addr_str(const struct sockaddr *sa, bool has_port)
{
#ifdef __GNUC__
    static __thread char s[SS_ADDRSTRLEN];
#else
    static _Thread_local char s[SS_ADDRSTRLEN];
#endif
    memset(s, 0, SS_ADDRSTRLEN);
    char addr[INET6_ADDRSTRLEN] = { 0 };
    char port[PORTSTRLEN]       = { 0 };
    uint16_t p;
    struct sockaddr_in sa_in;
    struct sockaddr_in6 sa_in6;

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
        strncpy(s, "Unknown AF", SS_ADDRSTRLEN);
    }

    int addr_len = strlen(addr);
    int port_len = strlen(port);
    memcpy(s, addr, addr_len);

    if (has_port) {
        memcpy(s + addr_len + 1, port, port_len);
        s[addr_len] = ':';
    }

    return s;
}

int
create_remote_socket(int ipv6)
{
    int remote_sock = -1;

    if (ipv6) {
        struct sockaddr_in6 addr6;
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_addr = in6addr_any;
        addr6.sin6_port = 0;

        remote_sock = socket(AF_INET6, SOCK_DGRAM, 0);
        if (remote_sock == -1) {
            ERROR("[udp] cannot create IPv6 socket");
            return -1;
        }
        if (bind(remote_sock, (struct sockaddr *)&addr6, sizeof(addr6)) != 0) {
            ERROR("[udp] cannot bind IPv6 socket");
            close(remote_sock);
            return -1;
        }
    } else {
        struct sockaddr_in addr4;
        memset(&addr4, 0, sizeof(addr4));
        addr4.sin_family = AF_INET;
        addr4.sin_addr.s_addr = INADDR_ANY;
        addr4.sin_port = 0;

        remote_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (remote_sock == -1) {
            ERROR("[udp] cannot create IPv4 socket");
            return -1;
        }
        if (bind(remote_sock, (struct sockaddr *)&addr4, sizeof(addr4)) != 0) {
            ERROR("[udp] cannot bind IPv4 socket");
            close(remote_sock);
            return -1;
        }
    }

    // Disable fragmentation
    int val = IP_PMTUDISC_DO;
    setsockopt(remote_sock, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));

    return remote_sock;
}


int
create_server_socket(const char *host, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp, *ipv4v6bindall;
    int s, server_sock = -1;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_UNSPEC;               /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_DGRAM;              /* We want a UDP socket */
    hints.ai_flags    = AI_PASSIVE | AI_ADDRCONFIG; /* For wildcard IP address */
    hints.ai_protocol = IPPROTO_UDP;

    s = getaddrinfo(host, port, &hints, &result);
    if (s != 0) {
        LOGE("[udp] getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    if (result == NULL) {
        LOGE("[udp] cannot bind");
        return -1;
    }

    rp = result;

    /*
     * On Linux, with net.ipv6.bindv6only = 0 (the default), getaddrinfo(NULL) with
     * AI_PASSIVE returns 0.0.0.0 and :: (in this order). AI_PASSIVE was meant to
     * return a list of addresses to listen on, but it is impossible to listen on
     * 0.0.0.0 and :: at the same time, if :: implies dualstack mode.
     */
    if (!host) {
        ipv4v6bindall = result;

        /* Loop over all address infos found until a IPV6 address is found. */
        while (ipv4v6bindall) {
            if (ipv4v6bindall->ai_family == AF_INET6) {
                rp = ipv4v6bindall; /* Take first IPV6 address available */
                break;
            }
            ipv4v6bindall = ipv4v6bindall->ai_next; /* Get next address info, if any */
        }
    }

    for (/*rp = result*/; rp != NULL; rp = rp->ai_next) {
        server_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (server_sock == -1) {
            continue;
        }

        if (rp->ai_family == AF_INET6) {
            // When binding to a specific host, enable IPV6_V6ONLY.
            // When binding to a wildcard address (host is NULL), disable IPV6_V6ONLY
            // to allow the socket to accept both IPv4 and IPv6 traffic.
            // This is the standard way to create a dual-stack server socket.
            int ipv6only = (host != NULL);
            setsockopt(server_sock, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only));
        }

        int opt = 1;
        setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
        set_nosigpipe(server_sock);
#endif
        if (reuse_port) {
            int err = set_reuseport(server_sock);
            if (err == 0) {
                LOGI("udp port reuse enabled");
            }
        }
#ifdef IP_TOS
        // Set QoS flag
        int tos   = 46 << 2;
        int rc = setsockopt(server_sock, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
        if (rc < 0 && errno != ENOPROTOOPT) {
            ERROR("setting ipv4 dscp failed");
        }
#ifdef IPV6_TCLASS
        rc = setsockopt(server_sock, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos));
        if (rc < 0 && errno != ENOPROTOOPT) {
            ERROR("setting ipv6 dscp failed");
        }
#endif
#endif

        /* For a dual-stack socket, we must set options for BOTH protocols */
        if (rp->ai_family == AF_INET6 && host == NULL) {
            if (setsockopt(server_sock, SOL_IPV6, IPV6_TRANSPARENT, &opt, sizeof(opt)) ||
                setsockopt(server_sock, SOL_IP, IP_TRANSPARENT, &opt, sizeof(opt))) {
                ERROR("[udp] setsockopt IP_TRANSPARENT for dual-stack failed");
                goto next_addr;
            }
            if (setsockopt(server_sock, SOL_IPV6, IPV6_RECVORIGDSTADDR, &opt, sizeof(opt)) ||
                setsockopt(server_sock, SOL_IP, IP_RECVORIGDSTADDR, &opt, sizeof(opt))) {
                ERROR("[udp] setsockopt IP_RECVORIGDSTADDR for dual-stack failed");
                goto next_addr;
            }
        } else { /* Single-stack socket */
            int sol = rp->ai_family == AF_INET ? SOL_IP : SOL_IPV6;
            if (setsockopt(server_sock, sol, rp->ai_family == AF_INET ? IP_TRANSPARENT : IPV6_TRANSPARENT, &opt, sizeof(opt)) ||
                setsockopt(server_sock, sol, rp->ai_family == AF_INET ? IP_RECVORIGDSTADDR : IPV6_RECVORIGDSTADDR, &opt, sizeof(opt))) {
                ERROR("[udp] setsockopt for TPROXY failed");
                goto next_addr;
            }
        }

        s = bind(server_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        } else {
            ERROR("[udp] bind");
        }

next_addr:
        close(server_sock);
        server_sock = -1;
    }

    freeaddrinfo(result);

    // Disable fragmentation
    int val = IP_PMTUDISC_DO;
    setsockopt(server_sock, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));

    return server_sock;
}
/* new_remote: 初始化 remote_ctx，remote_idx 初始来自 server_ctx->preferred_remote_idx */
remote_ctx_t *
new_remote(int fd, server_ctx_t *server_ctx)
{
    remote_ctx_t *ctx = ss_malloc(sizeof(remote_ctx_t));
    if (!ctx) {
        ERROR("[udp] out of memory new_remote");
        close(fd);
        return NULL;
    }
    memset(ctx, 0, sizeof(remote_ctx_t));

    ctx->fd         = fd;
    ctx->server_ctx = server_ctx;
    ctx->af         = AF_UNSPEC;
    ctx->remote_idx = 0; /* Will be set properly when used */
    ctx->state      = STATE_IDLE;

    ev_io_init(&ctx->io, remote_recv_cb, fd, EV_READ);
    ev_timer_init(&ctx->watcher, remote_timeout_cb, server_ctx->timeout, server_ctx->timeout);

    return ctx;
}

server_ctx_t *
new_server_ctx(int fd)
{
    server_ctx_t *ctx = ss_malloc(sizeof(server_ctx_t));
    if (!ctx) return NULL;
    memset(ctx, 0, sizeof(server_ctx_t));

    ctx->fd = fd;
    ev_io_init(&ctx->io, server_recv_cb, fd, EV_READ);

    return ctx;
}

void
close_and_free_remote(EV_P_ remote_ctx_t *ctx)
{
    if (ctx != NULL) {
        ev_timer_stop(EV_A_ & ctx->watcher);
        ev_io_stop(EV_A_ & ctx->io);
        close(ctx->fd);
        ss_free(ctx);
    }
}

void convert_ipv4_mapped_ipv6(struct sockaddr_storage* addr) {
    if (addr->ss_family == AF_INET) {
        struct sockaddr_in* ipv4_addr = (struct sockaddr_in*)addr;

        struct sockaddr_storage mapped_addr;
        memset(&mapped_addr, 0, sizeof(mapped_addr));

        struct sockaddr_in6* mapped_ipv6_addr = (struct sockaddr_in6*)&mapped_addr;
        mapped_ipv6_addr->sin6_family = AF_INET6;
        mapped_ipv6_addr->sin6_port = ipv4_addr->sin_port;
        uint8_t* ipv6_raw_addr = mapped_ipv6_addr->sin6_addr.s6_addr;
        ipv6_raw_addr[10] = 0xff;
        ipv6_raw_addr[11] = 0xff;
        in_addr_t ipv4_raw_addr = ntohl(ipv4_addr->sin_addr.s_addr);
        ipv6_raw_addr[12] = (ipv4_raw_addr >> 24) & 0xff;
        ipv6_raw_addr[13] = (ipv4_raw_addr >> 16) & 0xff;
        ipv6_raw_addr[14] = (ipv4_raw_addr >> 8) & 0xff;
        ipv6_raw_addr[15] = ipv4_raw_addr & 0xff;

        memcpy(addr, &mapped_addr, sizeof(mapped_addr));
    }
}

/* 当 remote 超时时，尝试将 listener 的 preferred_remote_idx 向后移动一位（failover），并删除 cache */
static void
remote_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
    remote_ctx_t *remote_ctx = cork_container_of(watcher, remote_ctx_t, watcher);
    server_ctx_t *server_ctx = remote_ctx->server_ctx;

    ev_timer_stop(EV_A_ & remote_ctx->watcher);

    if (server_ctx == NULL) {
        close_and_free_remote(EV_A_ remote_ctx);
        return;
    }

    if (remote_ctx->state == STATE_AWAITING_REPLY) {
        const char *addr_str = get_addr_str(server_ctx->remote_addr[remote_ctx->remote_idx], true);
        LOGI("[udp] session timed out for remote %d (%s) waiting for reply.", remote_ctx->remote_idx, addr_str);
        metrics_inc_remote_udp_session_timeouts_total(remote_ctx->remote_idx, addr_str);
    } else {
        if (verbose) LOGI("[udp] idle session timed out for remote %d.", remote_ctx->remote_idx);
    }

    if (verbose) {
        LOGI("[udp] connection timeout for src %s", get_addr_str((struct sockaddr *)&remote_ctx->src_addr, true));
    }

    /* 使用栈上的 key 以移除 cache 条目（触发 free_cb） */
    char key[HASH_KEY_LEN];
    hash_key_fill(key, remote_ctx->af, &remote_ctx->src_addr);
    cache_remove(server_ctx->conn_cache, key, HASH_KEY_LEN);
}

/* remote recv: 收到从 remote 发回的加密数据，解密并发回对应的客户端地址 */
static void
remote_recv_cb(EV_P_ ev_io *w, int revents)
{
    /* safe container_of to get remote_ctx */
    remote_ctx_t *remote_ctx = cork_container_of(w, remote_ctx_t, io);
    server_ctx_t *server_ctx = remote_ctx->server_ctx;

    if (server_ctx == NULL) {
        LOGE("[udp] invalid server_ctx in remote_recv_cb");
        close_and_free_remote(EV_A_ remote_ctx);
        return;
    }

    if (verbose) LOGI("[udp] remote receive a packet");

    struct sockaddr_storage src_addr;
    socklen_t src_addr_len = sizeof(src_addr);
    memset(&src_addr, 0, src_addr_len);

    buffer_t *buf = ss_malloc(sizeof(buffer_t));
    balloc(buf, buf_size);

    ssize_t r = recvfrom(remote_ctx->fd, buf->data, buf_size, 0, (struct sockaddr *)&src_addr, &src_addr_len);
    if (r == -1) {
        ERROR("[udp] remote_recv_recvfrom");
        goto CLEAN_UP;
    }
    if (r > packet_size && verbose) {
        LOGI("[udp] remote_recv fragmentation: " SSIZE_FMT, r + PACKET_HEADER_SIZE);
    }
    buf->len = r;

    int err = server_ctx->crypto->decrypt_all(buf, server_ctx->crypto->cipher, buf_size);
    if (err) {
        LOGE("[udp] decrypt_all failed or suspicious packet from %s", get_addr_str((struct sockaddr *)&src_addr, true));
        goto CLEAN_UP;
    }

    struct sockaddr_storage dst_addr;
    memset(&dst_addr, 0, sizeof(dst_addr));
    int len = parse_udprelay_header(buf->data, buf->len, NULL, NULL, &dst_addr);
    if (len == 0) {
        LOGE("[udp] parse header failed in remote_recv_cb");
        goto CLEAN_UP;
    }

    buf->len -= len;
    memmove(buf->data, buf->data + len, buf->len);

    if (buf->len > packet_size && verbose) {
        LOGI("[udp] remote_sendto fragmentation MTU maybe: " SSIZE_FMT, buf->len + PACKET_HEADER_SIZE);
    }

    convert_ipv4_mapped_ipv6(&dst_addr);

    size_t remote_dst_addr_len = get_sockaddr_len((struct sockaddr *)&dst_addr);

    int reply_fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (reply_fd < 0) {
        ERROR("[udp] remote_recv_socket");
        goto CLEAN_UP;
    }
    int opt = 1;
    if (setsockopt(reply_fd, SOL_IPV6, IPV6_TRANSPARENT, &opt, sizeof(opt))) {
        ERROR("[udp] remote_recv_setsockopt");
        close(reply_fd);
        goto CLEAN_UP;
    }
    // Allow binding to non-local IP addresses. This is essential for TPROXY
    // to be able to send a reply with the original destination as the source.
    if (setsockopt(reply_fd, SOL_IP, IP_FREEBIND, &opt, sizeof(opt))) {
        ERROR("[udp] remote_recv_setsockopt IP_FREEBIND failed");
        // This is not a fatal error on all systems, so we just log it.
        // If bind() fails later, we will know for sure.
        // On some systems, IP_TRANSPARENT implies IP_FREEBIND.
    }
    if (setsockopt(reply_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        ERROR("[udp] remote_recv_setsockopt");
        close(reply_fd);
        goto CLEAN_UP;
    }
    if (reuse_port) {
        if (set_reuseport(reply_fd) != 0) {
            ERROR("[udp] remote_recv port_reuse");
        }
    }
#ifdef IP_TOS
    // Set QoS flag
    int tos = 46 << 2;
    int rc = setsockopt(reply_fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
    if (rc < 0 && errno != ENOPROTOOPT) {
        LOGE("setting ipv4 dscp failed: %d", errno);
    }
#ifdef IPV6_TCLASS
    rc = setsockopt(reply_fd, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos));
    if (rc < 0 && errno != ENOPROTOOPT) {
        LOGE("setting ipv6 dscp failed: %d", errno);
    }
#endif
#endif
    if (bind(reply_fd, (struct sockaddr *)&dst_addr, remote_dst_addr_len) != 0) {
        ERROR("[udp] remote_recv_bind");
        close(reply_fd);
        goto CLEAN_UP;
    }

    struct sockaddr_storage mapped_src_addr;
    memcpy(&mapped_src_addr, &remote_ctx->src_addr, sizeof(remote_ctx->src_addr));
    convert_ipv4_mapped_ipv6(&mapped_src_addr);

    size_t remote_src_addr_len = get_sockaddr_len((struct sockaddr *)&mapped_src_addr);

    ssize_t s = sendto(reply_fd, buf->data, buf->len, 0,
                   (struct sockaddr *)&mapped_src_addr, remote_src_addr_len);
    if (s > 0) {
        metrics_inc_udp_tx_bytes(s);
    }

    close(reply_fd);

    if (s == -1 && !(errno == EAGAIN || errno == EWOULDBLOCK)) {
        ERROR("[udp] remote_recv sendto to client failed");
    }

    /* Mark as idle since we've successfully processed a reply */
    remote_ctx->state = STATE_IDLE;

    /* 成功收到回包後，重置 remote 的 watcher（延長可用時間） */
    ev_timer_again(EV_A_ & remote_ctx->watcher);

CLEAN_UP:
    bfree(buf);
    ss_free(buf);
}


static void
server_recv_cb(EV_P_ ev_io *w, int revents)
{
    /* get server_ctx by container_of (safer than casting) */
    server_ctx_t *server_ctx = cork_container_of(w, server_ctx_t, io);

    buffer_t *buf = ss_malloc(sizeof(buffer_t));
    balloc(buf, buf_size);

    struct msghdr msgh;
    struct iovec iov[1];
    char cbuf[CMSG_SPACE(sizeof(struct sockaddr_in6))];
    struct sockaddr_storage src_addr, dst_addr;

    memset(&src_addr, 0, sizeof(src_addr));
    memset(&dst_addr, 0, sizeof(dst_addr));

    /* IMPORTANT: initialize msgh to zero to avoid uninitialized fields */
    memset(&msgh, 0, sizeof(msgh));

    iov[0].iov_base = buf->data;
    iov[0].iov_len = buf_size;

    msgh.msg_name = &src_addr;
    msgh.msg_namelen = sizeof(src_addr);
    msgh.msg_iov = iov;
    msgh.msg_iovlen = 1;
    msgh.msg_control = cbuf;
    msgh.msg_controllen = sizeof(cbuf);
    msgh.msg_flags = 0;

    ssize_t r = recvmsg(server_ctx->fd, &msgh, 0);
    if (r == -1) {
        ERROR("[udp] server_recv_recvfrom");
        goto CLEAN_UP;
    }

    if (r > packet_size && verbose) {
        LOGI("[udp] server_recv_recvfrom fragmentation: " SSIZE_FMT, r + PACKET_HEADER_SIZE);
    }
    buf->len = r;
    metrics_inc_udp_rx_bytes(r);

    struct cmsghdr *cmsg;
    for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg != NULL; cmsg = CMSG_NXTHDR(&msgh, cmsg)) {
        if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVORIGDSTADDR) {
            memcpy(&dst_addr, CMSG_DATA(cmsg), sizeof(struct sockaddr_in));
        } else if (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_RECVORIGDSTADDR) {
            memcpy(&dst_addr, CMSG_DATA(cmsg), sizeof(struct sockaddr_in6));
        }
    }

    if (dst_addr.ss_family == AF_UNSPEC) {
        LOGE("[udp] could not get original destination address for TPROXY "
             "(is it enabled and configured correctly?)");
        goto CLEAN_UP;
    }

    // Check for DNS query to be routed to DoT
    if (server_ctx->dot_server_addr != NULL) {
        uint16_t dest_port = ntohs(((struct sockaddr_in*)&dst_addr)->sin_port);
        if (dest_port == 53) {
            start_dot_session(EV_A_ server_ctx, &src_addr, msgh.msg_namelen, buf);
            goto CLEAN_UP; // DoT session will handle the rest
        }
    }


    if (verbose) LOGI("[udp] server receive a packet from %s", get_addr_str((struct sockaddr *)&src_addr, true));

    char addr_header[MAX_ADDR_HEADER_SIZE] = {0};
    int addr_header_len = construct_udprelay_header(&dst_addr, addr_header);
    if (addr_header_len == 0) {
        LOGE("[udp] failed to construct addr header (tproxy)");
        goto CLEAN_UP;
    }
    brealloc(buf, buf->len + addr_header_len, buf_size);
    memmove(buf->data + addr_header_len, buf->data, buf->len);
    memcpy(buf->data, addr_header, addr_header_len);
    buf->len += addr_header_len;

    /* key: 用 src_addr + family 作为 cache key */
    char key[HASH_KEY_LEN];
    hash_key_fill(key, src_addr.ss_family, &src_addr);

    struct cache *conn_cache = server_ctx->conn_cache;
    remote_ctx_t *remote_ctx = NULL;
    cache_lookup(conn_cache, key, HASH_KEY_LEN, (void *)&remote_ctx);

    /* 校验 cache 里的 remote_ctx 是否属于相同的 src_addr（防止 hash 冲突） */
    if (remote_ctx) {
        if (sockaddr_cmp(&src_addr, &remote_ctx->src_addr, sizeof(src_addr)) != 0) {
            /* 不同 src_addr 的 entry，不复用（hash 冲突） */
            remote_ctx = NULL;
        }
    }

    if (remote_ctx) {
        /* cache 命中：重置 timer */
        ev_timer_again(EV_A_ & remote_ctx->watcher);
        if (verbose) LOGI("[udp] cache hit for %s", get_addr_str((struct sockaddr *)&src_addr, true));
    } else {
        if (verbose) LOGI("[udp] cache miss for %s, creating remote_ctx", get_addr_str((struct sockaddr *)&src_addr, true));

        /* Find first available remote */
        int start_idx = -1;
        for (int i = 0; i < server_ctx->remote_num; i++) {
            if (server_ctx->remote_status[i]) {
                start_idx = i;
                break;
            }
        }
        if (start_idx == -1) {
            LOGE("[udp] No remote servers available, dropping packet.");
            goto CLEAN_UP;
        }
        const struct sockaddr *start_remote_addr = server_ctx->remote_addr[start_idx];
        int prefer_is_v6 = start_remote_addr->sa_family == AF_INET6 ? 1 : 0;

        int remotefd = create_remote_socket(prefer_is_v6);
        if (remotefd < 0) {
            ERROR("[udp] create_remote_socket failed");
            goto CLEAN_UP;
        }
        setnonblocking(remotefd);

#ifdef SO_MARK
        if (server_ctx->fwmark > 0) {
            if (setsockopt(remotefd, SOL_SOCKET, SO_MARK, &server_ctx->fwmark, sizeof(server_ctx->fwmark)) != 0) {
                ERROR("setsockopt SO_MARK");
            }
        }
#endif

#ifdef SO_NOSIGPIPE
        set_nosigpipe(remotefd);
#endif

#ifdef IP_TOS
        // Set QoS flag
        int tos = 46 << 2;
        int rc = setsockopt(remotefd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
        if (rc < 0 && errno != ENOPROTOOPT) {
            LOGE("setting ipv4 dscp failed: %d", errno);
        }
#ifdef IPV6_TCLASS
        rc = setsockopt(remotefd, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos));
        if (rc < 0 && errno != ENOPROTOOPT) {
            LOGE("setting ipv6 dscp failed: %d", errno);
        }
#endif
#endif

#ifdef SET_INTERFACE
        if (server_ctx->iface && strlen(server_ctx->iface) > 0) {
            if (setinterface(remotefd, server_ctx->iface) == -1) ERROR("setinterface");
        }
#endif

        /* 新建 remote_ctx */
        remote_ctx = new_remote(remotefd, server_ctx);
        if (!remote_ctx) {
            close(remotefd);
            goto CLEAN_UP;
        }
        remote_ctx->src_addr = src_addr; /* 保存客户端地址 */
        remote_ctx->af = src_addr.ss_family;
        remote_ctx->remote_idx = start_idx;

        /* 插入 cache（cache 应复制 key 内容） */
        cache_insert(conn_cache, key, HASH_KEY_LEN, (void *)remote_ctx);
        const char *addr_str = get_addr_str(server_ctx->remote_addr[remote_ctx->remote_idx], true);
        metrics_inc_remote_udp_sessions(remote_ctx->remote_idx, addr_str);
        metrics_inc_remote_udp_sessions_total(remote_ctx->remote_idx, addr_str);
        metrics_inc_udp_sessions_total();
        metrics_set_udp_sessions(HASH_COUNT(conn_cache->entries));
        ev_io_start(EV_A_ & remote_ctx->io);
        ev_timer_start(EV_A_ & remote_ctx->watcher);
    }

    /*
     * If the remote for this session is now offline, we must failover.
     * This is an "in-session" failover.
     */
    if (!server_ctx->remote_status[remote_ctx->remote_idx]) {
        int next_idx = -1;
        for (int i = 0; i < server_ctx->remote_num; i++) {
            if (server_ctx->remote_status[i]) {
                next_idx = i;
                break;
            }
        }
        if (next_idx != -1) {
            LOGI("[udp] in-session failover for %s: %d -> %d", get_addr_str((struct sockaddr *)&src_addr, true), remote_ctx->remote_idx, next_idx);
            remote_ctx->remote_idx = next_idx;
        }
    }
    const struct sockaddr *remote_addr = server_ctx->remote_addr[remote_ctx->remote_idx];
    int remote_addr_len = get_sockaddr_len((struct sockaddr *)remote_addr);

    /* 对 payload 进行加密 */
    int err = server_ctx->crypto->encrypt_all(buf, server_ctx->crypto->cipher, buf_size);
    if (err) {
        LOGE("[udp] encrypt_all failed, drop packet");
        goto CLEAN_UP;
    }

    if (buf->len > packet_size && verbose) {
        LOGI("[udp] sending possibly fragmented UDP packet to remote (len=%d)", (int)buf->len);
    }

    int s = sendto(remote_ctx->fd, buf->data, buf->len, 0, remote_addr, remote_addr_len);
    if (remote_ctx) remote_ctx->state = STATE_AWAITING_REPLY;
    if (s == -1) {
        if (errno == EMSGSIZE) {
            LOGE("[udp] server->sendto to remote failed: Message too large (packet size: %zu, current MTU setting leads to max payload: %d)",
                 buf->len, packet_size);
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            ERROR("[udp] server->sendto to remote failed");
            /* If send fails immediately, mark remote as down and destroy this session */
            if (server_ctx->remote_num > 1) {
                /* Remove from cache to force re-creation on next packet */
                char key_to_remove[HASH_KEY_LEN];
                hash_key_fill(key_to_remove, remote_ctx->af, &remote_ctx->src_addr);
                cache_remove(conn_cache, key_to_remove, HASH_KEY_LEN);
                remote_ctx = NULL; /* Prevent timer reset below */
            }
        } else {
            /* send succeeded */
        }
    }

CLEAN_UP:
    bfree(buf);
    ss_free(buf);
    return;
}

/* cache free callback: 由 cache 在删除条目时调用（移除 remote_ctx） */
void
free_cb(void *key, void *element)
{
    remote_ctx_t *remote_ctx = (remote_ctx_t *)element;
    if (verbose) LOGI("[udp] freeing remote_ctx %p", (void *)remote_ctx);
    metrics_dec_remote_udp_sessions(remote_ctx->remote_idx);
    metrics_set_udp_sessions(HASH_COUNT(remote_ctx->server_ctx->conn_cache->entries));
    if (remote_ctx) close_and_free_remote(EV_DEFAULT, remote_ctx);
}

/* 初始化 udprelay，支持多个 remote_addr，记录 preferred_remote_idx 并注册 failback timer */
int
init_udprelay(const char *server_host, const char *server_port, int remote_num,
              struct sockaddr **remote_addr, int mtu, crypto_t *crypto,
              int timeout, const char *iface, int fwmark,
              volatile bool *remote_status)
{
    s_port = server_port;
    struct ev_loop *loop = EV_DEFAULT;

    /*
     * Adjust packet_size calculation to account for AEAD overhead (salt + tag).
     * This provides a more accurate upper bound for the original payload.
     * We assume a common case (e.g., chacha20-ietf-poly1305: 32-byte salt, 16-byte tag).
     */
    if (mtu > 0) {
        packet_size = mtu - PACKET_HEADER_SIZE - crypto->cipher->key_len - crypto->cipher->tag_len;
        buf_size = packet_size * 2;
    }

    int serverfd = create_server_socket(server_host, server_port);
    if (serverfd < 0) return -1;
    setnonblocking(serverfd);

    struct cache *conn_cache = NULL;
    cache_create(&conn_cache, MAX_UDP_CONN_NUM, free_cb);

    server_ctx_t *server_ctx = new_server_ctx(serverfd);
    if (!server_ctx) {
        close(serverfd);
        return -1;
    }

    server_ctx->timeout = max(timeout, MIN_UDP_TIMEOUT);
    server_ctx->crypto = crypto;
    server_ctx->iface = iface;
    server_ctx->conn_cache = conn_cache;
    server_ctx->fwmark = fwmark;
    server_ctx->remote_num = remote_num;
    server_ctx->remote_addr = remote_addr;
    server_ctx->remote_status = remote_status;
    server_ctx->dot_server_addr = NULL;
    server_ctx->dot_server_host = NULL;

    if (dot_server_str != NULL && strlen(dot_server_str) > 0) {
        char *host = strdup(dot_server_str);
        char *port = strrchr(host, ':');
        if (port != NULL) {
            *port = '\0';
            port++;
        } else {
            port = strdup("853");
        }

        server_ctx->dot_server_host = host;
        server_ctx->dot_server_port = port;
        LOGI("[udp] DNS-over-TLS (DoT) enabled, server: %s:%s", server_ctx->dot_server_host, server_ctx->dot_server_port);
    } else {
        free(host);
    }

    ev_io_start(loop, &server_ctx->io);

    if (server_num < MAX_REMOTE_NUM) {
        server_ctx_list[server_num++] = server_ctx;
    } else {
        LOGE("[udp] too many server instances");
    }
    probe_add_udp_server(server_ctx);
    return serverfd;
}

void
free_udprelay()
{
    struct ev_loop *loop = EV_DEFAULT;
    while (server_num > 0) {
        server_ctx_t *server_ctx = server_ctx_list[--server_num];
        ev_io_stop(loop, &server_ctx->io);
        /* Use a temporary variable to hold the pointer for ss_free */
        void *status_ptr = (void *)server_ctx->remote_status;
        ss_free(status_ptr);
        if (server_ctx->dot_server_addr) {
            ss_free(server_ctx->dot_server_addr);
            free((void*)server_ctx->dot_server_host);
            free((void*)server_ctx->dot_server_port);
        }
        close(server_ctx->fd);
        cache_delete(server_ctx->conn_cache, 0);
#ifdef MODULE_LOCAL
        free((char*) server_ctx->remote_addr);
#endif
        ss_free(server_ctx);
        server_ctx_list[server_num] = NULL;
    }
}
