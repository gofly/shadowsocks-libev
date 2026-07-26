/*
 * redir.c - Provide a transparent TCP proxy through remote shadowsocks
 *           server
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
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>
#include <linux/if.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

#include <libcork/core.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "plugin.h"
#include "netutils.h"
#include "utils.h"
#include "common.h"
#include "redir.h"
#include "udprelay.h"
#include "probe.h"
#include "metrics.h"

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT       19
#endif

#ifndef IPV6_TRANSPARENT
#define IPV6_TRANSPARENT     75
#endif

#define MAX_LISTEN_SOCKETS   2

static void accept_cb(EV_P_ ev_io *w, int revents);
static void server_recv_cb(EV_P_ ev_io *w, int revents);
static void server_send_cb(EV_P_ ev_io *w, int revents);
static void remote_recv_cb(EV_P_ ev_io *w, int revents);
static void remote_send_cb(EV_P_ ev_io *w, int revents);

static remote_t *new_remote(int fd, int timeout);
static server_t *new_server(int fd);

static void free_remote(remote_t *remote);
static void close_and_free_remote(EV_P_ remote_t *remote);
static void free_server(server_t *server);
static void close_and_free_server(EV_P_ server_t *server);

static void start_connect_remote(EV_P_ server_t *server);
static void handle_tcp_fail(EV_P_ server_t *server);

int verbose    = 0;
int reuse_port = 0;
int tcp_incoming_sndbuf = 0;
int tcp_incoming_rcvbuf = 0;
int tcp_outgoing_sndbuf = 0;
int tcp_outgoing_rcvbuf = 0;

static crypto_t *crypto;

static int ipv6first = 0;
static int mode      = TCP_ONLY;
#ifdef HAVE_SETRLIMIT
static int nofile = 0;
#endif
int fast_open       = 0;
static int no_delay = 0;
static int fwmark = 0;
static int ret_val  = 0;

static struct ev_signal sigint_watcher;
static struct ev_signal sigterm_watcher;
static struct ev_signal sigchld_watcher;

static int tcp_tproxy = 0; /* use tproxy instead of redirect (for tcp) */

#define MAX_LISTEN_CTX 128
static listen_ctx_t *listen_ctx_list[MAX_LISTEN_CTX] = { NULL };
static int listen_ctx_count                          = 0;

static int
getdestaddr(int serverfd, int family,
            struct sockaddr_storage *destaddr)
{
    socklen_t socklen;
    memset(destaddr, 0, sizeof(*destaddr));

    if (family == AF_INET6) {
        socklen = sizeof(struct sockaddr_in6);
    } else {
        socklen = sizeof(struct sockaddr_in);
    }


    if (tcp_tproxy) {
        return getsockname(serverfd,
                (struct sockaddr *)destaddr,
                &socklen);
    }

    switch(family)
    {
    case AF_INET:
        return getsockopt(serverfd,
                SOL_IP,
                SO_ORIGINAL_DST,
                destaddr,
                &socklen);
    case AF_INET6:
        return getsockopt(serverfd,
                SOL_IPV6,
                IP6T_SO_ORIGINAL_DST,
                destaddr,
                &socklen);
    default:
        errno=EAFNOSUPPORT;
        return -1;
    }
}

int
create_and_bind(const char *addr, const char *port, int af, int *fds, int *family, int reuse_port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, fd_count = 0;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_UNSPEC;   /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
    if (addr == NULL) {
        /* For wildcard IP address */
        hints.ai_flags = AI_PASSIVE;
    }

    result = NULL;

    s = getaddrinfo(addr, port, &hints, &result);
    if (s != 0) {
        LOGI("[redir] getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    if (result == NULL) {
        LOGE("[redir] Could not bind");
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        if (af != AF_UNSPEC && rp->ai_family != af) {
            continue;
        }

        int listen_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_sock == -1) {
            continue;
        }

        if (rp->ai_family == AF_INET6) {

            int v6only = 0;

            if (setsockopt(listen_sock,
                        IPPROTO_IPV6,
                        IPV6_V6ONLY,
                        &v6only,
                        sizeof(v6only)) != 0) {

                LOGW("[redir] failed to disable IPV6_V6ONLY");
            }
        }

        int opt = 1;
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
        setsockopt(listen_sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
        if (reuse_port) {
            int err = set_reuseport(listen_sock);
            if (err == 0) {
                LOGI("[redir] tcp port reuse enabled");
            }
        }

        if (tcp_tproxy) {
            int level = 0, optname = 0;
            if (rp->ai_family == AF_INET) {
                level = IPPROTO_IP;
                optname = IP_TRANSPARENT;
            } else {
                level = IPPROTO_IPV6;
                optname = IPV6_TRANSPARENT;
            }

            if (setsockopt(listen_sock, level, optname, &opt, sizeof(opt)) != 0) {
                ERROR("[redir] setsockopt IP_TRANSPARENT");
                exit(EXIT_FAILURE);
            }
        }

        s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            if (listen(listen_sock, SOMAXCONN) == -1) {
                ERROR("listen() error");
                close(listen_sock);
                continue;
            }
            setnonblocking(listen_sock);
            if (fd_count >= MAX_LISTEN_SOCKETS) {
                LOGW("[redir] too many listen sockets returned by getaddrinfo(), ignoring extra socket");
                close(listen_sock);
                continue;
            }
            fds[fd_count++] = listen_sock;
        } else {
            ERROR("bind");
            close(listen_sock);
        }
    }

    freeaddrinfo(result);

    return fd_count;
}

static void
server_recv_cb(EV_P_ ev_io *w, int revents)
{
    tcp_server_ctx_t *server_recv_ctx = (tcp_server_ctx_t *)w;
    server_t *server             = server_recv_ctx->server;
    remote_t *remote              = server->remote;

    /* Safety check: remote may have been freed by another callback
     * (e.g. remote_timeout_cb or remote_send_cb error path) that ran
     * before this callback fired.  close_and_free_remote() clears
     * server->remote before close_and_free_server() stops the io
     * watcher, so there is a window where server is still alive but
     * remote is gone. */
    if (remote == NULL) {
        close_and_free_server(EV_A_ server);
        return;
    }

    ev_timer_stop(EV_A_ & server->delayed_connect_watcher);

    ssize_t r = recv(server->fd, remote->buf->data + remote->buf->len,
                     SOCKET_BUF_SIZE - remote->buf->len, 0);

    if (r == 0) {
        // connection closed
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("[redir] server recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    remote->buf->len += r;
    metrics_inc_tcp_rx_bytes(r);

    if (verbose) {
        uint16_t port = 0;
        char ipstr[INET6_ADDRSTRLEN];
        memset(&ipstr, 0, INET6_ADDRSTRLEN);

        if (AF_INET == server->destaddr.ss_family) {
            struct sockaddr_in *sa = (struct sockaddr_in *)&(server->destaddr);
            inet_ntop(AF_INET, &(sa->sin_addr), ipstr, INET_ADDRSTRLEN);
            port = ntohs(sa->sin_port);
        } else {
            struct sockaddr_in6 *sa = (struct sockaddr_in6 *)&(server->destaddr);
            inet_ntop(AF_INET6, &(sa->sin6_addr), ipstr, INET6_ADDRSTRLEN);
            port = ntohs(sa->sin6_port);
        }

        LOGI("[redir] redir to %s:%d, len=%zu, recv=%zd", ipstr, port, remote->buf->len, r);
    }

    if (!remote->send_ctx->connected) {
        ev_io_stop(EV_A_ & server_recv_ctx->io);
        ev_io_start(EV_A_ & remote->send_ctx->io);
        return;
    }

    int err = crypto->encrypt(remote->buf, server->e_ctx, SOCKET_BUF_SIZE);

    if (err) {
        LOGE("[redir] invalid password or cipher");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    }

    int s = send(remote->fd, remote->buf->data, remote->buf->len, 0);

    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            remote->buf->idx = 0;
            ev_io_stop(EV_A_ & server_recv_ctx->io);
            ev_io_start(EV_A_ & remote->send_ctx->io);
            return;
        } else {
            ERROR("[redir] send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    } else if (s < remote->buf->len) {
        remote->buf->len -= s;
        remote->buf->idx  = s;
        ev_io_stop(EV_A_ & server_recv_ctx->io);
        ev_io_start(EV_A_ & remote->send_ctx->io);
        return;
    } else {
        remote->buf->idx = 0;
        remote->buf->len = 0;
    }
}

static void
server_send_cb(EV_P_ ev_io *w, int revents)
{
    tcp_server_ctx_t *server_send_ctx = (tcp_server_ctx_t *)w;
    server_t *server             = server_send_ctx->server;
    remote_t *remote              = server->remote;

    if (remote == NULL) {
        close_and_free_server(EV_A_ server);
        return;
    }

    if (server->buf->len == 0) {
        // close and free
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(server->fd, server->buf->data + server->buf->idx,
                         server->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("[redir] send");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < server->buf->len) {
            // partly sent, move memory, wait for the next time to send
            server->buf->len -= s;
            server->buf->idx += s;
            return;
        } else {
            // all sent out, wait for reading
            server->buf->len = 0;
            server->buf->idx = 0;
            ev_io_stop(EV_A_ & server_send_ctx->io);
            ev_io_start(EV_A_ & remote->recv_ctx->io);
        }
    }
}

static void
delayed_connect_cb(EV_P_ ev_timer *watcher, int revents)
{
    server_t *server =
        cork_container_of(watcher,
                          server_t,
                          delayed_connect_watcher);

    remote_t *remote = server->remote;

    if (remote == NULL) {
        close_and_free_server(EV_A_ server);
        return;
    }

    struct sockaddr *addr =
        (struct sockaddr *)&remote->addr_storage;

    int r =
        connect(remote->fd,
                addr,
                get_sockaddr_len(addr));

    if (r == -1 &&
        errno != CONNECT_IN_PROGRESS) {
        ERROR("[redir] connect");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    }

    ev_io_start(EV_A_
                &remote->send_ctx->io);


    ev_timer_start(EV_A_
                   &remote->send_ctx->watcher);
}

static void
remote_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
    tcp_remote_ctx_t *remote_ctx
        = cork_container_of(watcher, tcp_remote_ctx_t, watcher);

    remote_t *remote = remote_ctx->remote;

    if (remote == NULL)
        return;

    server_t *server = remote->server;

    if (server == NULL)
        return;

    ev_timer_stop(EV_A_ watcher);

    /* On remote connect/send timeout, try failover (don't immediately
     * kill the server). The failover function will close the current
     * remote socket and start connect to next remote in the listener
     * address list.
     */
    handle_tcp_fail(EV_A_ server);
}

static void
remote_recv_cb(EV_P_ ev_io *w, int revents)
{
    tcp_remote_ctx_t *remote_recv_ctx = (tcp_remote_ctx_t *)w;
    remote_t *remote                    = remote_recv_ctx->remote;

    if (remote == NULL)
        return;

    server_t *server              = remote->server;

    if (server == NULL)
        return;

    ssize_t r = recv(remote->fd, server->buf->data, SOCKET_BUF_SIZE, 0);

    if (r == 0) {
        // connection closed
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("[redir] remote recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    server->buf->len = r;

    int err = crypto->decrypt(server->buf, server->d_ctx, SOCKET_BUF_SIZE);
    if (err == CRYPTO_ERROR) {
        LOGE("[redir] invalid password or cipher");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (err == CRYPTO_NEED_MORE) {
        return; // Wait for more
    }

    int s = send(server->fd, server->buf->data, server->buf->len, 0);

    if (s > 0) {
        metrics_inc_tcp_tx_bytes(s);
    }

    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            server->buf->idx = 0;
            ev_io_stop(EV_A_ & remote_recv_ctx->io);
            ev_io_start(EV_A_ & server->send_ctx->io);
        } else {
            ERROR("[redir] send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    } else if (s < server->buf->len) {
        server->buf->len -= s;
        server->buf->idx  = s;
        ev_io_stop(EV_A_ & remote_recv_ctx->io);
        ev_io_start(EV_A_ & server->send_ctx->io);
    }

    // Disable TCP_NODELAY after the first response are sent
    if (!remote->recv_ctx->connected && !no_delay) {
        int opt = 0;
        setsockopt(server->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
        setsockopt(remote->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
    }
    remote->recv_ctx->connected = 1;
}

static void
remote_send_cb(EV_P_ ev_io *w, int revents)
{
    tcp_remote_ctx_t *remote_send_ctx =
        (tcp_remote_ctx_t *)w;

    remote_t *remote =
        remote_send_ctx->remote;


    if (remote == NULL)
        return;


    server_t *server =
        remote->server;


    if (server == NULL)
        return;



    ev_timer_stop(EV_A_
                  &remote_send_ctx->watcher);



    if (!remote_send_ctx->connected) {


        int r = 0;


        /*
         * Check whether TCP connection is established.
         *
         * addr_storage is always valid when using fast_open.
         */
        struct sockaddr_storage addr;

        memset(&addr,
               0,
               sizeof(addr));


        socklen_t len =
            sizeof(addr);



        r = getpeername(remote->fd,
                        (struct sockaddr *)&addr,
                        &len);



        if (r == 0) {


            remote_send_ctx->connected = 1;


            ev_io_stop(EV_A_
                       &remote_send_ctx->io);


            ev_io_stop(EV_A_
                       &server->recv_ctx->io);



            ev_io_start(EV_A_
                        &remote->recv_ctx->io);



            /*
             * Send destination address header.
             */
            buffer_t ss_addr_to_send;

            buffer_t *abuf =
                &ss_addr_to_send;


            balloc(abuf,
                   SOCKET_BUF_SIZE);



            int addr_len =
                construct_udprelay_header(
                    &server->destaddr,
                    abuf->data);



            if (addr_len == 0) {


                LOGE("[redir] failed to construct address header");


                bfree(abuf);


                close_and_free_remote(
                    EV_A_
                    remote);


                close_and_free_server(
                    EV_A_
                    server);


                return;
            }



            abuf->len =
                addr_len;



            bprepend(remote->buf,
                     abuf,
                     SOCKET_BUF_SIZE);



            bfree(abuf);



            /*
             * Encrypt:
             * [address header][payload]
             */
            int err =
                crypto->encrypt(
                    remote->buf,
                    server->e_ctx,
                    SOCKET_BUF_SIZE);



            if (err) {


                LOGE("[redir] invalid password or cipher");


                close_and_free_remote(
                    EV_A_
                    remote);


                close_and_free_server(
                    EV_A_
                    server);


                return;
            }


        } else {


            ERROR("[redir] getpeername");


            handle_tcp_fail(
                EV_A_
                server);


            return;
        }
    }




    if (remote->buf->len == 0) {


        close_and_free_remote(
            EV_A_
            remote);


        close_and_free_server(
            EV_A_
            server);


        return;
    }




    int s = -1;



    /*
     * TCP Fast Open
     *
     * addr_storage replaces remote->addr.
     */
    if (fast_open) {


        struct sockaddr *addr =
            (struct sockaddr *)&remote->addr_storage;



#if defined(TCP_FASTOPEN_CONNECT)


        int optval = 1;


        if (setsockopt(remote->fd,
                       IPPROTO_TCP,
                       TCP_FASTOPEN_CONNECT,
                       &optval,
                       sizeof(optval)) < 0) {


            ERROR("[redir] failed to set TCP_FASTOPEN_CONNECT");


            handle_tcp_fail(
                EV_A_
                server);


            return;
        }



        s =
            connect(remote->fd,
                    addr,
                    get_sockaddr_len(addr));



        if (s == 0) {


            s =
                send(remote->fd,
                     remote->buf->data +
                     remote->buf->idx,
                     remote->buf->len,
                     0);
        }



#elif defined(MSG_FASTOPEN)


        s =
            sendto(remote->fd,
                   remote->buf->data +
                   remote->buf->idx,
                   remote->buf->len,
                   MSG_FASTOPEN,
                   addr,
                   get_sockaddr_len(addr));


#else


        FATAL("[redir] tcp fast open is not supported on this platform");


#endif



        if (s == -1) {


            if (errno == CONNECT_IN_PROGRESS) {


                ev_io_start(
                    EV_A_
                    &remote_send_ctx->io);


                ev_timer_start(
                    EV_A_
                    &remote_send_ctx->watcher);


            } else {


                if (errno == EOPNOTSUPP ||
                    errno == EPROTONOSUPPORT ||
                    errno == ENOPROTOOPT) {


                    fast_open = 0;


                    LOGE("[redir] fast open is not supported");
                }
                else {


                    ERROR("[redir] fast_open_connect");
                }


                handle_tcp_fail(
                    EV_A_
                    server);
            }


            return;
        }



    } else {



        s =
            send(remote->fd,
                 remote->buf->data +
                 remote->buf->idx,
                 remote->buf->len,
                 0);
    }




    if (s == -1) {


        if (errno != EAGAIN &&
            errno != EWOULDBLOCK) {


            ERROR("[redir] send");


            handle_tcp_fail(
                EV_A_
                server);
        }


        return;
    }




    if (s < remote->buf->len) {


        remote->buf->len -= s;

        remote->buf->idx += s;


        ev_io_start(
            EV_A_
            &remote_send_ctx->io);


        return;
    }




    /*
     * All data sent.
     */
    remote->buf->len = 0;

    remote->buf->idx = 0;



    ev_io_stop(
        EV_A_
        &remote_send_ctx->io);



    ev_io_start(
        EV_A_
        &server->recv_ctx->io);
}

static remote_t *
new_remote(int fd, int timeout)
{
    remote_t *remote =
        ss_malloc(sizeof(remote_t));

    if (remote == NULL) {
        ERROR("[redir] malloc remote failed");
        return NULL;
    }

    memset(remote,
           0,
           sizeof(remote_t));

    remote->recv_ctx =
        ss_malloc(sizeof(tcp_remote_ctx_t));

    remote->send_ctx =
        ss_malloc(sizeof(tcp_remote_ctx_t));

    remote->buf =
        ss_malloc(sizeof(buffer_t));

    if (remote->recv_ctx == NULL ||
        remote->send_ctx == NULL ||
        remote->buf == NULL) {

        ERROR("[redir] malloc remote context failed");

        free(remote->recv_ctx);
        free(remote->send_ctx);
        free(remote->buf);
        free(remote);

        return NULL;
    }

    memset(remote->recv_ctx,
           0,
           sizeof(tcp_remote_ctx_t));

    memset(remote->send_ctx,
           0,
           sizeof(tcp_remote_ctx_t));

    balloc(remote->buf,
           SOCKET_BUF_SIZE);

    remote->fd = fd;

    remote->recv_ctx->remote = remote;
    remote->recv_ctx->connected = 0;

    remote->send_ctx->remote = remote;
    remote->send_ctx->connected = 0;

    ev_io_init(&remote->recv_ctx->io,
               remote_recv_cb,
               fd,
               EV_READ);

    ev_io_init(&remote->send_ctx->io,
               remote_send_cb,
               fd,
               EV_WRITE);

    ev_timer_init(&remote->send_ctx->watcher,
                  remote_timeout_cb,
                  min(MAX_CONNECT_TIMEOUT,
                      timeout),
                  0);

    return remote;
}

static void
free_remote(remote_t *remote)
{
    if (remote->server != NULL) {
        remote->server->remote = NULL;
    }
    if (remote->buf != NULL) {
        bfree(remote->buf);
        ss_free(remote->buf);
    }
    /* Clear the back-pointers in the context structs so that if a
     * callback fires after the remote is freed (but before the server
     * is fully torn down), it can detect the invalid state. */
    if (remote->recv_ctx != NULL) {
        remote->recv_ctx->remote = NULL;
    }
    if (remote->send_ctx != NULL) {
        remote->send_ctx->remote = NULL;
    }
    ss_free(remote->recv_ctx);
    ss_free(remote->send_ctx);
    ss_free(remote);
}

static void
close_and_free_remote(EV_P_ remote_t *remote)
{
    if (remote != NULL) {
        ev_timer_stop(EV_A_ & remote->send_ctx->watcher);
        ev_io_stop(EV_A_ & remote->send_ctx->io);
        ev_io_stop(EV_A_ & remote->recv_ctx->io);
        close(remote->fd);
        free_remote(remote);
    }
}

static server_t *
new_server(int fd)
{
    server_t *server = ss_malloc(sizeof(server_t));
    memset(server, 0, sizeof(server_t));

    server->recv_ctx = ss_malloc(sizeof(tcp_server_ctx_t));
    server->send_ctx = ss_malloc(sizeof(tcp_server_ctx_t));
    server->buf      = ss_malloc(sizeof(buffer_t));
    balloc(server->buf, SOCKET_BUF_SIZE);
    memset(server->recv_ctx, 0, sizeof(tcp_server_ctx_t));
    memset(server->send_ctx, 0, sizeof(tcp_server_ctx_t));
    server->fd                  = fd;
    server->recv_ctx->server    = server;
    server->recv_ctx->connected = 0;
    server->send_ctx->server    = server;
    server->send_ctx->connected = 0;

    server->e_ctx = ss_malloc(sizeof(cipher_ctx_t));
    server->d_ctx = ss_malloc(sizeof(cipher_ctx_t));
    crypto->ctx_init(crypto->cipher, server->e_ctx, 1);
    crypto->ctx_init(crypto->cipher, server->d_ctx, 0);

    ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);
    ev_io_init(&server->send_ctx->io, server_send_cb, fd, EV_WRITE);

    ev_timer_init(&server->delayed_connect_watcher, delayed_connect_cb, 0.05,
                  0);

    return server;
}

static void
free_server(server_t *server)
{
    if (server->remote != NULL) {
        server->remote->server = NULL;
    }
    if (server->e_ctx != NULL) {
        crypto->ctx_release(server->e_ctx);
        ss_free(server->e_ctx);
    }
    if (server->d_ctx != NULL) {
        crypto->ctx_release(server->d_ctx);
        ss_free(server->d_ctx);
    }
    if (server->buf != NULL) {
        bfree(server->buf);
        ss_free(server->buf);
    }
    /* Clear the back-pointers in the context structs so that if a
     * callback fires after the server is freed, it can detect the
     * invalid state. */
    if (server->recv_ctx != NULL) {
        server->recv_ctx->server = NULL;
    }
    if (server->send_ctx != NULL) {
        server->send_ctx->server = NULL;
    }
    ss_free(server->recv_ctx);
    ss_free(server->send_ctx);
    ss_free(server);
}

static void
close_and_free_server(EV_P_ server_t *server)
{
    if (server != NULL) {
        ev_io_stop(EV_A_ & server->send_ctx->io);
        ev_io_stop(EV_A_ & server->recv_ctx->io);
        ev_timer_stop(EV_A_ & server->delayed_connect_watcher);
        metrics_dec_remote_tcp_connections(server->remote_idx);
        metrics_dec_tcp_connections();
        close(server->fd);
        free_server(server);
    }
}

static void
handle_tcp_fail(EV_P_ server_t *server)
{
    if (server->remote) {
        close_and_free_remote(EV_A_ server->remote);
        server->remote = NULL;
    }

    if (server->listener) {
        const char *addr_str = get_addr_str(server->listener->remote_addr[server->remote_idx], true);
        metrics_inc_remote_tcp_failures_total(server->remote_idx, addr_str);
    }

    /*
    * Do not failover to the next remote on connection failure.
    * The probing mechanism is now solely responsible for managing remote status.
    * We just close the server connection and let the client retry.
    */
    LOGE("[redir] TCP connection to remote %d failed, closing connection.", server->remote_idx);

    close_and_free_server(EV_A_ server);
}

static void
start_connect_remote(EV_P_ server_t *server)
{
    if (server == NULL ||
        server->listener == NULL) {

        ERROR("[redir] tcp: invalid server context");
        return;
    }


    listen_ctx_t *listener = server->listener;


    if (server->remote_idx >= listener->remote_num) {

        LOGE("[redir] all remote servers failed to connect");

        handle_tcp_fail(EV_A_ server);

        return;
    }



    struct sockaddr *remote_addr =
        listener->remote_addr[server->remote_idx];


    if (remote_addr == NULL) {

        ERROR("[redir] tcp: remote address is NULL");

        handle_tcp_fail(EV_A_ server);

        return;
    }



    socklen_t remote_addr_len =
        get_sockaddr_len(remote_addr);


    if (remote_addr_len == 0) {

        ERROR("[redir] tcp: invalid remote address family %d",
              remote_addr->sa_family);

        handle_tcp_fail(EV_A_ server);

        return;
    }



    const char *addr_str =
        get_addr_str(remote_addr, true);


    if (verbose) {

        LOGI("[redir] tcp: connecting remote %d at %s",
             server->remote_idx,
             addr_str);
    }



    metrics_inc_remote_tcp_connections_total(
        server->remote_idx,
        addr_str);



    int protocol = IPPROTO_TCP;


    if (listener->mptcp < 0) {

        protocol = IPPROTO_MPTCP;
    }



    int remotefd =
        socket(remote_addr->sa_family,
               SOCK_STREAM,
               protocol);



    /*
     * MPTCP fallback
     */
    if (remotefd < 0 &&
        protocol == IPPROTO_MPTCP) {

        ERROR("[redir] MPTCP socket failed, fallback TCP");


        remotefd =
            socket(remote_addr->sa_family,
                   SOCK_STREAM,
                   IPPROTO_TCP);
    }



    if (remotefd < 0) {

        ERROR("[redir] tcp: socket");

        handle_tcp_fail(EV_A_ server);

        return;
    }



    int opt = 1;



    setsockopt(remotefd,
               SOL_TCP,
               TCP_NODELAY,
               &opt,
               sizeof(opt));


#ifdef SO_NOSIGPIPE

    setsockopt(remotefd,
               SOL_SOCKET,
               SO_NOSIGPIPE,
               &opt,
               sizeof(opt));

#endif



    /*
     * TCP keepalive
     */
    int keepAlive = 1;
    int keepIdle = 40;
    int keepInterval = 20;
    int keepCount = 5;


    setsockopt(remotefd,
               SOL_SOCKET,
               SO_KEEPALIVE,
               &keepAlive,
               sizeof(keepAlive));


    setsockopt(remotefd,
               SOL_TCP,
               TCP_KEEPIDLE,
               &keepIdle,
               sizeof(keepIdle));


    setsockopt(remotefd,
               SOL_TCP,
               TCP_KEEPINTVL,
               &keepInterval,
               sizeof(keepInterval));


    setsockopt(remotefd,
               SOL_TCP,
               TCP_KEEPCNT,
               &keepCount,
               sizeof(keepCount));



    setnonblocking(remotefd);




    /*
     * DSCP
     */
    if (listener->tos >= 0) {


        if (remote_addr->sa_family == AF_INET) {


            if (setsockopt(remotefd,
                           IPPROTO_IP,
                           IP_TOS,
                           &listener->tos,
                           sizeof(listener->tos)) < 0 &&
                errno != ENOPROTOOPT) {

                ERROR("[redir] setting ipv4 dscp failed");
            }


        } else if (remote_addr->sa_family == AF_INET6) {


#ifdef IPV6_TCLASS

            if (setsockopt(remotefd,
                           IPPROTO_IPV6,
                           IPV6_TCLASS,
                           &listener->tos,
                           sizeof(listener->tos)) < 0 &&
                errno != ENOPROTOOPT) {

                ERROR("[redir] setting ipv6 dscp failed");
            }

#endif
        }
    }





#ifdef SO_MARK

    if (fwmark > 0) {


        if (setsockopt(remotefd,
                       SOL_SOCKET,
                       SO_MARK,
                       &fwmark,
                       sizeof(fwmark)) != 0) {

            ERROR("[redir] setsockopt SO_MARK");
        }
    }

#endif





    /*
     * Enable MPTCP
     */
    if (listener->mptcp > 1) {


        if (setsockopt(remotefd,
                       SOL_TCP,
                       listener->mptcp,
                       &opt,
                       sizeof(opt)) < 0) {

            ERROR("[redir] enable MPTCP failed");
        }


    } else if (listener->mptcp == 1) {


        int i = 0;
        int mptcp_opt;


        while ((mptcp_opt =
                mptcp_enabled_values[i]) > 0) {


            if (setsockopt(remotefd,
                           SOL_TCP,
                           mptcp_opt,
                           &opt,
                           sizeof(opt)) != -1) {

                break;
            }


            i++;
        }


        if (mptcp_opt <= 0) {

            ERROR("[redir] enable MPTCP failed");
        }
    }





    if (tcp_outgoing_sndbuf > 0) {

        setsockopt(remotefd,
                   SOL_SOCKET,
                   SO_SNDBUF,
                   &tcp_outgoing_sndbuf,
                   sizeof(int));
    }



    if (tcp_outgoing_rcvbuf > 0) {

        setsockopt(remotefd,
                   SOL_SOCKET,
                   SO_RCVBUF,
                   &tcp_outgoing_rcvbuf,
                   sizeof(int));
    }




    remote_t *remote =
        new_remote(remotefd,
                   listener->timeout);



    if (remote == NULL) {

        ERROR("[redir] tcp: new_remote failed");

        close(remotefd);

        handle_tcp_fail(EV_A_ server);

        return;
    }



    server->remote = remote;

    remote->server = server;



    /*
     * Save remote address.
     *
     * Never keep listener->remote_addr pointer.
     */
    memset(&remote->addr_storage,
           0,
           sizeof(remote->addr_storage));


    memcpy(&remote->addr_storage,
           remote_addr,
           remote_addr_len);





    if (fast_open) {


        if (verbose) {

            LOGI("[redir] tcp: using TCP Fast Open");
        }


        ev_timer_start(
            EV_A_
            &server->delayed_connect_watcher);



    } else {


        struct sockaddr *addr =
            (struct sockaddr *)&remote->addr_storage;



        int r =
            connect(remotefd,
                    addr,
                    get_sockaddr_len(addr));



        if (r < 0 &&
            errno != CONNECT_IN_PROGRESS) {


            ERROR("[redir] tcp: connect");


            close_and_free_remote(
                EV_A_
                remote);


            return;
        }



        if (verbose) {

            LOGI("[redir] tcp: connect issued fd=%d",
                 remotefd);
        }



        ev_io_start(
            EV_A_
            &remote->send_ctx->io);


        ev_timer_start(
            EV_A_
            &remote->send_ctx->watcher);
    }




    ev_io_start(
        EV_A_
        &server->recv_ctx->io);
}

static void
accept_cb(EV_P_ ev_io *w, int revents)
{
    listen_io_ctx_t *io_ctx =
        (listen_io_ctx_t *)w->data;

    if (io_ctx == NULL ||
        io_ctx->listener == NULL) {

        ERROR("[redir] tcp: invalid listener context");
        return;
    }

    listen_ctx_t *listener =
        io_ctx->listener;
    int family = io_ctx->family;

    if (family != AF_INET &&
        family != AF_INET6) {
        ERROR("[redir] tcp: unsupported address family %d",
              family);
        return;
    }

    struct sockaddr_storage destaddr;

    memset(&destaddr,
           0,
           sizeof(destaddr));

    int listenfd = w->fd;

    int serverfd =
        accept(listenfd,
               NULL,
               NULL);

    if (serverfd < 0) {
        if (errno != EINTR &&
            errno != EAGAIN &&
            errno != EWOULDBLOCK) {
            ERROR("[redir] tcp: accept");
        }
        return;
    }

    /*
     * Get original destination address
     */
    if (getdestaddr(serverfd,
                    family,
                    &destaddr) != 0) {
        ERROR("[redir] tcp: get original dst failed (%s)",
              family == AF_INET ?
              "IPv4" :
              "IPv6");
        close(serverfd);
        return;
    }



    /*
     * Verify returned sockaddr family
     */
    if (destaddr.ss_family != family) {
        ERROR("[redir] tcp: address family mismatch "
              "(expect %d got %d)",
              family,
              destaddr.ss_family);
        close(serverfd);
        return;
    }



#ifdef DEBUG
    char addrbuf[INET6_ADDRSTRLEN];
    if (family == AF_INET) {
        inet_ntop(AF_INET,
            &((struct sockaddr_in *)&destaddr)->sin_addr,
            addrbuf,
            sizeof(addrbuf));
    } else {
        inet_ntop(AF_INET6,
            &((struct sockaddr_in6 *)&destaddr)->sin6_addr,
            addrbuf,
            sizeof(addrbuf));
    }

    LOGI("[redir] tcp original dst %s",
         addrbuf);
#endif

    setnonblocking(serverfd);

    int opt = 1;

    setsockopt(serverfd,
               SOL_TCP,
               TCP_NODELAY,
               &opt,
               sizeof(opt));

#ifdef SO_NOSIGPIPE
    setsockopt(serverfd,
               SOL_SOCKET,
               SO_NOSIGPIPE,
               &opt,
               sizeof(opt));
#endif

    if (tcp_incoming_sndbuf > 0) {
        setsockopt(serverfd,
                   SOL_SOCKET,
                   SO_SNDBUF,
                   &tcp_incoming_sndbuf,
                   sizeof(int));
    }

    if (tcp_incoming_rcvbuf > 0) {
        setsockopt(serverfd,
                   SOL_SOCKET,
                   SO_RCVBUF,
                   &tcp_incoming_rcvbuf,
                   sizeof(int));
    }

    server_t *server =
        new_server(serverfd);

    if (server == NULL) {
        ERROR("[redir] tcp: failed to allocate server");
        close(serverfd);
        return;
    }

    server->destaddr = destaddr;

    /*
     * associate listener
     */
    server->listener = listener;

    /*
     * find available remote
     */
    int start_idx = -1;

    if (listener->remote_num > 0) {
        for (int i = 0;
             i < listener->remote_num;
             i++) {
            if (listener->remote_status[i]) {
                start_idx = i;
                break;
            }
        }
    }

    if (start_idx < 0) {
        LOGE("[redir] tcp: no remote servers "
             "available for fd %d",
             serverfd);
        close(serverfd);
        free_server(server);
        return;
   }

    server->remote_idx = start_idx;

    metrics_inc_tcp_connections();
    metrics_inc_tcp_connections_total();
    metrics_inc_remote_tcp_connections(
        server->remote_idx,
        get_addr_str(
            listener->remote_addr[server->remote_idx],
            true));

    if (verbose) {
        LOGI("[redir] tcp: starting remote "
             "connect for fd %d",
             serverfd);
    }

    start_connect_remote(EV_A_ server);
}

static void
signal_cb(EV_P_ ev_signal *w, int revents)
{
    if (revents & EV_SIGNAL) {
        switch (w->signum) {
        case SIGCHLD:
            if (!is_plugin_running()) {
                LOGE("[redir] plugin service exit unexpectedly");
                ret_val = -1;
            } else
                return;
        case SIGINT:
        case SIGTERM: {
            ev_signal_stop(EV_DEFAULT, &sigint_watcher);
            ev_signal_stop(EV_DEFAULT, &sigterm_watcher);
            ev_signal_stop(EV_DEFAULT, &sigchld_watcher);
            metrics_cleanup(EV_A);
            probe_cleanup(EV_A);

            ev_unloop(EV_A_ EVUNLOOP_ALL);
        }
        }
    }
}

int
main(int argc, char **argv)
{
    time_t start_time = time(NULL);
    srand(start_time);

    int i, c;
    int pid_flags    = 0;
    int mptcp        = 0;
    int mtu          = 0;
    char *user       = NULL;
    char *local_port = NULL;
    char *local_addr = NULL;
    char *password   = NULL;
    char *key        = NULL;
    char *timeout    = NULL;
    char *method     = NULL;
    char *pid_path   = NULL;
    char *conf_path  = NULL;

    char *plugin      = NULL;
    char *plugin_opts = NULL;
    char *plugin_host = NULL;
    char *plugin_port = NULL;
    uint16_t metrics_port = 0;
    int probe_interval = 0;
    int probe_timeout = 0;
    int probe_up_count = 0;
    int probe_down_count = 0;
    char *probe_domain = NULL;
    char tmp_port[8];

    int dscp_num    = 0;
    ss_dscp_t *dscp = NULL;

    int remote_num    = 0;
    char *remote_port = NULL;
    ss_addr_t remote_addr[MAX_REMOTE_NUM];

    memset(remote_addr, 0, sizeof(ss_addr_t) * MAX_REMOTE_NUM);

    static struct option long_options[] = {
        { "fast-open",   no_argument,       NULL, GETOPT_VAL_FAST_OPEN   },
        { "mtu",         required_argument, NULL, GETOPT_VAL_MTU         },
        { "mptcp",       no_argument,       NULL, GETOPT_VAL_MPTCP       },
        { "plugin",      required_argument, NULL, GETOPT_VAL_PLUGIN      },
        { "plugin-opts", required_argument, NULL, GETOPT_VAL_PLUGIN_OPTS },
        { "reuse-port",  no_argument,       NULL, GETOPT_VAL_REUSE_PORT  },
        { "tcp-incoming-sndbuf", required_argument, NULL, GETOPT_VAL_TCP_INCOMING_SNDBUF },
        { "tcp-incoming-rcvbuf", required_argument, NULL, GETOPT_VAL_TCP_INCOMING_RCVBUF },
        { "tcp-outgoing-sndbuf", required_argument, NULL, GETOPT_VAL_TCP_OUTGOING_SNDBUF },
        { "tcp-outgoing-rcvbuf", required_argument, NULL, GETOPT_VAL_TCP_OUTGOING_RCVBUF },
        { "no-delay",    no_argument,       NULL, GETOPT_VAL_NODELAY     },
        { "password",    required_argument, NULL, GETOPT_VAL_PASSWORD    },
        { "key",         required_argument, NULL, GETOPT_VAL_KEY         },
        { "fwmark",      required_argument, NULL, GETOPT_VAL_FWMARK      },
        { "probe-interval", required_argument, NULL, GETOPT_VAL_PROBE_INTERVAL },
        { "probe-timeout",  required_argument, NULL, GETOPT_VAL_PROBE_TIMEOUT  },
        { "probe-up-count", required_argument, NULL, GETOPT_VAL_PROBE_UP_COUNT },
        { "probe-down-count", required_argument, NULL, GETOPT_VAL_PROBE_DOWN_COUNT },
        { "probe-domain", required_argument, NULL, GETOPT_VAL_PROBE_DOMAIN },
        { "metrics-port", required_argument, NULL, GETOPT_VAL_METRICS_PORT },
        { "help",        no_argument,       NULL, GETOPT_VAL_HELP        },
        { NULL,          0,                 NULL, 0                      }
    };

    opterr = 0;

    USE_TTY();

    while ((c = getopt_long(argc, argv, "f:s:p:l:k:t:m:c:b:a:n:huUTv6A:",
                            long_options, NULL)) != -1) {
        switch (c) {
        case GETOPT_VAL_FAST_OPEN:
            fast_open = 1;
            break;
        case GETOPT_VAL_MTU:
            mtu = atoi(optarg);
            break;
        case GETOPT_VAL_MPTCP:
            mptcp = get_mptcp(1);
            break;
        case GETOPT_VAL_NODELAY:
            no_delay = 1;
            break;
        case GETOPT_VAL_PLUGIN:
            plugin = optarg;
            break;
        case GETOPT_VAL_PLUGIN_OPTS:
            plugin_opts = optarg;
            break;
        case GETOPT_VAL_KEY:
            key = optarg;
            break;
        case GETOPT_VAL_FWMARK:
            fwmark = atoi(optarg);
            break;
        case GETOPT_VAL_PROBE_INTERVAL:
            probe_interval = atoi(optarg);
            break;
        case GETOPT_VAL_PROBE_TIMEOUT:
            probe_timeout = atoi(optarg);
            break;
        case GETOPT_VAL_PROBE_UP_COUNT:
            probe_up_count = atoi(optarg);
            break;
        case GETOPT_VAL_PROBE_DOWN_COUNT:
            probe_down_count = atoi(optarg);
            break;
        case GETOPT_VAL_PROBE_DOMAIN:
            probe_domain = optarg;
            break;
        case GETOPT_VAL_METRICS_PORT:
            metrics_port = atoi(optarg);
            break;
        case GETOPT_VAL_REUSE_PORT:
            reuse_port = 1;
            break;
        case GETOPT_VAL_TCP_INCOMING_SNDBUF:
            tcp_incoming_sndbuf = atoi(optarg);
            break;
        case GETOPT_VAL_TCP_INCOMING_RCVBUF:
            tcp_incoming_rcvbuf = atoi(optarg);
            break;
        case GETOPT_VAL_TCP_OUTGOING_SNDBUF:
            tcp_outgoing_sndbuf = atoi(optarg);
            break;
        case GETOPT_VAL_TCP_OUTGOING_RCVBUF:
            tcp_outgoing_rcvbuf = atoi(optarg);
            break;
        case 's':
            if (remote_num < MAX_REMOTE_NUM) {
                parse_addr(optarg, &remote_addr[remote_num++]);
            }
            break;
        case 'p':
            remote_port = optarg;
            break;
        case 'l':
            local_port = optarg;
            break;
        case GETOPT_VAL_PASSWORD:
        case 'k':
            password = optarg;
            break;
        case 'f':
            pid_flags = 1;
            pid_path  = optarg;
            break;
        case 't':
            timeout = optarg;
            break;
        case 'm':
            method = optarg;
            break;
        case 'c':
            conf_path = optarg;
            break;
        case 'b':
            local_addr = optarg;
            break;
        case 'a':
            user = optarg;
            break;
#ifdef HAVE_SETRLIMIT
        case 'n':
            nofile = atoi(optarg);
            break;
#endif
        case 'u':
            mode = TCP_AND_UDP;
            break;
        case 'U':
            mode = UDP_ONLY;
            break;
        case 'T':
            tcp_tproxy = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        case GETOPT_VAL_HELP:
        case 'h':
            usage();
            exit(EXIT_SUCCESS);
        case '6':
            ipv6first = 1;
            break;
        case 'A':
            FATAL("[redir] One time auth has been deprecated. Try AEAD ciphers instead.");
            break;
        case '?':
            // The option character is not recognized.
            LOGE("[redir] Unrecognized option: %s", optarg);
            opterr = 1;
            break;
        }
    }

    if (opterr) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (argc == 1) {
        if (conf_path == NULL) {
            conf_path = get_default_conf();
        }
    }

    if (conf_path != NULL) {
        jconf_t *conf = read_jconf(conf_path);
        if (remote_num == 0) {
            remote_num = conf->remote_num;
            for (i = 0; i < remote_num; i++)
                remote_addr[i] = conf->remote_addr[i];
        }
        if (remote_port == NULL) {
            remote_port = conf->remote_port;
        }
        if (local_addr == NULL) {
            local_addr = conf->local_addr;
        }
        if (local_port == NULL) {
            local_port = conf->local_port;
        }
        if (password == NULL) {
            password = conf->password;
        }
        if (key == NULL) {
            key = conf->key;
        }
        if (method == NULL) {
            method = conf->method;
        }
        if (timeout == NULL) {
            timeout = conf->timeout;
        }
        if (user == NULL) {
            user = conf->user;
        }
        if (plugin == NULL) {
            plugin = conf->plugin;
        }
        if (plugin_opts == NULL) {
            plugin_opts = conf->plugin_opts;
        }
        if (mode == TCP_ONLY) {
            mode = conf->mode;
        }
        if (tcp_tproxy == 0) {
            tcp_tproxy = conf->tcp_tproxy;
        }
        if (mtu == 0) {
            mtu = conf->mtu;
        }
        if (mptcp == 0) {
            mptcp = conf->mptcp;
        }
        if (no_delay == 0) {
            no_delay = conf->no_delay;
        }
        if (reuse_port == 0) {
            reuse_port = conf->reuse_port;
        }
        if (tcp_incoming_sndbuf == 0) {
            tcp_incoming_sndbuf = conf->tcp_incoming_sndbuf;
        }
        if (tcp_incoming_rcvbuf == 0) {
            tcp_incoming_rcvbuf = conf->tcp_incoming_rcvbuf;
        }
        if (tcp_outgoing_sndbuf == 0) {
            tcp_outgoing_sndbuf = conf->tcp_outgoing_sndbuf;
        }
        if (tcp_outgoing_rcvbuf == 0) {
            tcp_outgoing_rcvbuf = conf->tcp_outgoing_rcvbuf;
        }
        if (fast_open == 0) {
            fast_open = conf->fast_open;
        }
#ifdef HAVE_SETRLIMIT
        if (nofile == 0) {
            nofile = conf->nofile;
        }
#endif
        if (ipv6first == 0) {
            ipv6first = conf->ipv6_first;
        }
        dscp_num = conf->dscp_num;
        dscp     = conf->dscp;
        if (fwmark == 0 && conf->fwmark > 0) {
            fwmark = conf->fwmark;
        }
        if (probe_interval == 0) {
            probe_interval = conf->probe_interval;
        }
        if (probe_timeout == 0) {
            probe_timeout = conf->probe_timeout;
        }
        if (probe_up_count == 0) {
            probe_up_count = conf->probe_up_count;
        }
        if (probe_down_count == 0) {
            probe_down_count = conf->probe_down_count;
        }
        if (probe_domain == NULL) {
            probe_domain = conf->probe_domain;
        }
        if (metrics_port == 0) {
            metrics_port = conf->metrics_port;
        }
    }

    if (remote_num == 0 || remote_port == NULL || local_port == NULL
        || (password == NULL && key == NULL)) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (plugin != NULL) {
        uint16_t port = get_local_port();
        if (port == 0) {
            FATAL("[redir] failed to find a free port");
        }
        snprintf(tmp_port, 8, "%d", port);
        if (is_ipv6only(remote_addr, remote_num, ipv6first)) {
            plugin_host = "::1";
        } else {
            plugin_host = "127.0.0.1";
        }
        plugin_port = tmp_port;

        LOGI("[redir] plugin \"%s\" enabled", plugin);
    }

    if (method == NULL) {
        method = "chacha20-ietf-poly1305";
    }

    if (timeout == NULL) {
        timeout = "600";
    }

#ifdef HAVE_SETRLIMIT
    /*
     * no need to check the return value here since we will show
     * the user an error message if setrlimit(2) fails
     */
    if (nofile > 1024) {
        if (verbose) {
            LOGI("[redir] setting NOFILE to %d", nofile);
        }
        set_nofile(nofile);
    }
#endif

    if (fast_open == 1) {
#ifdef TCP_FASTOPEN
        LOGI("[redir] using tcp fast open");
#else
        LOGE("[redir] tcp fast open is not supported by this environment");
        fast_open = 0;
#endif
    }

    USE_SYSLOG(argv[0], pid_flags);
    if (pid_flags) {
        daemonize(pid_path);
    }

    if (no_delay) {
        LOGI("[redir] enable TCP no-delay");
    }

    if (ipv6first) {
        LOGI("[redir] resolving hostname to IPv6 address first");
    }

    if (mptcp != 0){
        LOGI("[redir]enable multipath TCP (%s)", mptcp > 0 ? "out-of-tree" : "upstream");
    }

    if (mtu > 0) {
        LOGI("[redir] set MTU to %d", mtu);
    }

    if (timeout) {
        LOGI("[redir] set timeout to %s", timeout);
    }

    if (fwmark > 0) {
        LOGI("[redir] set fwmark to %d", fwmark);
    }

    if (tcp_incoming_sndbuf != 0 && tcp_incoming_sndbuf < SOCKET_BUF_SIZE) {
        tcp_incoming_sndbuf = 0;
    }

    if (tcp_incoming_sndbuf != 0) {
        LOGI("[redir] set TCP incoming connection send buffer size to %d", tcp_incoming_sndbuf);
    }

    if (tcp_incoming_rcvbuf != 0 && tcp_incoming_rcvbuf < SOCKET_BUF_SIZE) {
        tcp_incoming_rcvbuf = 0;
    }

    if (tcp_incoming_rcvbuf != 0) {
        LOGI("[redir] set TCP incoming connection receive buffer size to %d", tcp_incoming_rcvbuf);
    }

    if (tcp_outgoing_sndbuf != 0 && tcp_outgoing_sndbuf < SOCKET_BUF_SIZE) {
        tcp_outgoing_sndbuf = 0;
    }

    if (tcp_outgoing_sndbuf != 0) {
        LOGI("[redir] set TCP outgoing connection send buffer size to %d", tcp_outgoing_sndbuf);
    }

    if (tcp_outgoing_rcvbuf != 0 && tcp_outgoing_rcvbuf < SOCKET_BUF_SIZE) {
        tcp_outgoing_rcvbuf = 0;
    }

    if (tcp_outgoing_rcvbuf != 0) {
        LOGI("[redir] set TCP outgoing connection receive buffer size to %d", tcp_outgoing_rcvbuf);
    }

    if (probe_interval <= 0) {
        probe_interval = 60; /* default 60s */
    }

    if (probe_timeout <= 0){
        probe_timeout = 5; /* default 5s */
    }

    if (probe_up_count <= 0) {
        probe_up_count = 3; /* default 3 */
    }

    if (probe_down_count <= 0){
        probe_down_count = 3; /* default 3 */
    }

    if(!probe_domain || strlen(probe_domain) == 0) {
        probe_domain = "www.google.com";
    }

    if (plugin != NULL) {
        int len          = 0;
        size_t buf_size  = 256 * remote_num;
        char *remote_str = ss_malloc(buf_size);

        snprintf(remote_str, buf_size, "%s", remote_addr[0].host);
        for (int i = 1; i < remote_num; i++) {
            snprintf(remote_str + len, buf_size - len, "|%s", remote_addr[i].host);
            len = strlen(remote_str);
        }
        int err = start_plugin(plugin, plugin_opts, remote_str,
                               remote_port, plugin_host, plugin_port, MODE_CLIENT);
        if (err) {
            FATAL("[redir] failed to start the plugin");
        }
    }


    /* ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);

    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_init(&sigchld_watcher, signal_cb, SIGCHLD);
    ev_signal_start(EV_DEFAULT, &sigint_watcher);
    ev_signal_start(EV_DEFAULT, &sigterm_watcher);
    ev_signal_start(EV_DEFAULT, &sigchld_watcher);

    struct ev_loop *loop = EV_DEFAULT;

    probe_init(EV_A_ probe_interval, probe_timeout, probe_up_count, probe_down_count, probe_domain);

    if (metrics_port > 0) {
        const char *metrics_addr = "0.0.0.0";
        metrics_init(EV_A_ metrics_addr, metrics_port, remote_num, start_time);
    }

    LOGI("[redir] initializing ciphers... %s", method);
    crypto = crypto_init(password, key, method);
    if (crypto == NULL) {
        FATAL("[redir] failed to initialize ciphers");
    }

    /* Setup proxy context */
    struct listen_ctx listen_ctx;
    memset(&listen_ctx, 0, sizeof(struct listen_ctx));
    listen_ctx.remote_num  = remote_num;
    listen_ctx.remote_addr = ss_malloc(sizeof(struct sockaddr *) * remote_num);
    memset(listen_ctx.remote_addr, 0, sizeof(struct sockaddr *) * remote_num);
    listen_ctx.remote_status = ss_malloc(sizeof(bool) * remote_num);

    for (i = 0; i < remote_num; i++) {
        listen_ctx.remote_status[i] = true; /* Assume all are up initially */
        char *host = remote_addr[i].host;
        char *port = remote_addr[i].port == NULL ? remote_port :
                     remote_addr[i].port;
        if (plugin != NULL) {
            host = plugin_host;
            port = plugin_port;
        }
        struct sockaddr_storage *storage = ss_malloc(sizeof(struct sockaddr_storage));
        memset(storage, 0, sizeof(struct sockaddr_storage));
        if (get_sockaddr(host, port, storage, 1, ipv6first) == -1) {
            FATAL("[redir] failed to resolve the provided hostname");
        }
        listen_ctx.remote_addr[i] = (struct sockaddr *)storage;

        if (plugin != NULL)
            break;
    }
    listen_ctx.timeout = atoi(timeout);
    listen_ctx.mptcp   = mptcp;

    /*
     * Initialize UDP relay first if enabled.
     * This is crucial because the UDP module allocates and manages the
     * `remote_status` array that the TCP module will share.
     */
    if (mode != TCP_ONLY) {
        init_udprelay(local_addr, local_port, listen_ctx.remote_num,
                      listen_ctx.remote_addr, mtu, crypto,
                      listen_ctx.timeout, NULL, fwmark, listen_ctx.remote_status);
    }

    /*
     * Now, set up TCP listeners. They will all share the same `remote_status`
     * array, which is either managed by the UDP prober or statically set to true.
     */
    if (mode != UDP_ONLY) {
        listen_ctx_t *listen_ctx_current = &listen_ctx;
        do {
            listen_ctx_current->local_port = local_port;
            if (listen_ctx_current->tos) {
                LOGI("[redir] listening at %s:%s (TOS 0x%x)", local_addr, local_port, listen_ctx_current->tos);
            } else {
                LOGI("[redir] listening at %s:%s", local_addr, local_port);
            }

            if (listen_ctx_count < MAX_LISTEN_CTX) {
                listen_ctx_list[listen_ctx_count++] = listen_ctx_current;
            } else {
                LOGE("[redir] too many listen ctx; increase MAX_LISTEN_CTX");
            }

            /* Handle additional TOS/DSCP listening ports */
            if (dscp_num > 0) {
                listen_ctx_t *new_lc = (listen_ctx_t *)ss_malloc(sizeof(listen_ctx_t));
                memcpy(new_lc, &listen_ctx, sizeof(listen_ctx_t));
                local_port = dscp[dscp_num - 1].port;
                new_lc->tos = dscp[dscp_num - 1].dscp << 2;
                listen_ctx_current = new_lc;
            }
        } while (dscp_num-- > 0 && listen_ctx_current != NULL);

        /* Now, create sockets for all configured listeners */
        for (i = 0; i < listen_ctx_count; i++) {
            listen_ctx_t *listener = listen_ctx_list[i];
            int fds[MAX_LISTEN_SOCKETS];
            int family[MAX_LISTEN_SOCKETS];
            int fd_count = create_and_bind(local_addr, listener->local_port, AF_UNSPEC, fds, family, reuse_port);
            if (fd_count <= 0) {
                FATAL("bind() error");
            }
            listener->fd_num = fd_count;
            for (int j = 0; j < fd_count; j++) {
                listener->fd[j] = fds[j];
                listener->family[j] = family[j];
                listener->io_ctx[j].listener = listener;
                listener->io_ctx[j].family = rp->ai_family;

                ev_io_init(&listener->io[j],
                        accept_cb,
                        fds[j],
                        EV_READ);

                listener->io[j].data = &listener->io_ctx[j];
                ev_io_start(EV_A_ &listener->io[j]);
            }
        }
    } else {
        /* free listen_ctx if only UDP is enabled */
        LOGI("[redir] TCP relay disabled");
    }

    /* setuid */
    if (user != NULL && !run_as(user)) {
        FATAL("[redir] failed to switch user");
    }

    if (geteuid() == 0) {
        LOGI("[redir] running from root user");
    }

    ev_run(loop, 0);

    if (plugin != NULL) {
        stop_plugin();
    }

    for (i = 0; i < remote_num; i++) {
        ss_free(listen_ctx.remote_addr[i]);
    }
    
    ss_free(listen_ctx.remote_addr);

    /* Free dynamically allocated listen contexts for DSCP */
    for (i = 0; i < listen_ctx_count; i++) {
        if (listen_ctx_list[i] != &listen_ctx) {
            ss_free(listen_ctx_list[i]);
        }
    }

    return ret_val;
}