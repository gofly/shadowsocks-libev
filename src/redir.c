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
#define IP_TRANSPARENT 19
#endif

#ifndef IPV6_TRANSPARENT
#define IPV6_TRANSPARENT 75
#endif

#define MAX_LISTEN_SOCKETS 2

static void accept_cb(EV_P_ ev_io *w, int revents);

static void server_recv_cb(EV_P_ ev_io *w, int revents);
static void server_send_cb(EV_P_ ev_io *w, int revents);

static void remote_recv_cb(EV_P_ ev_io *w, int revents);
static void remote_send_cb(EV_P_ ev_io *w, int revents);

static void delayed_connect_cb(EV_P_ ev_timer *watcher,
                               int revents);

static void remote_timeout_cb(EV_P_ ev_timer *watcher,
                              int revents);

static remote_t *new_remote(int fd, int timeout);
static server_t *new_server(int fd);

static void free_remote(remote_t *remote);
static void close_and_free_remote(EV_P_ remote_t *remote);

static void free_server(server_t *server);
static void close_and_free_server(EV_P_ server_t *server);

static void start_connect_remote(EV_P_ server_t *server);
static void handle_tcp_fail(EV_P_ server_t *server);

int verbose = 0;

int reuse_port = 0;

int tcp_incoming_sndbuf = 0;
int tcp_incoming_rcvbuf = 0;

int tcp_outgoing_sndbuf = 0;
int tcp_outgoing_rcvbuf = 0;

static crypto_t *crypto = NULL;

static int ipv6first = 0;

static int mode = TCP_ONLY;

#ifdef HAVE_SETRLIMIT
static int nofile = 0;
#endif

int fast_open = 0;

static int no_delay = 0;

static int fwmark = 0;

static int ret_val = 0;

static struct ev_signal sigint_watcher;
static struct ev_signal sigterm_watcher;
static struct ev_signal sigchld_watcher;

static int tcp_tproxy = 0;

#define MAX_LISTEN_CTX 128

static listen_ctx_t *
listen_ctx_list[MAX_LISTEN_CTX] = {
    NULL
};

static int listen_ctx_count = 0;

/*
 * Get original destination address.
 *
 * For REDIRECT:
 *     SO_ORIGINAL_DST
 *
 * For TPROXY:
 *     getsockname()
 */
static int
getdestaddr(int serverfd,
            int family,
            struct sockaddr_storage *destaddr)
{
    socklen_t socklen;

    memset(destaddr,
           0,
           sizeof(*destaddr));

    if (family == AF_INET6) {

        socklen =
            sizeof(struct sockaddr_in6);

        ((struct sockaddr_in6 *)destaddr)
            ->sin6_family = AF_INET6;

    } else {

        socklen =
            sizeof(struct sockaddr_in);

        ((struct sockaddr_in *)destaddr)
            ->sin_family = AF_INET;
    }

    if (tcp_tproxy) {

        return getsockname(
            serverfd,
            (struct sockaddr *)destaddr,
            &socklen);
    }

    switch (family) {

    case AF_INET:

        return getsockopt(
            serverfd,
            SOL_IP,
            SO_ORIGINAL_DST,
            destaddr,
            &socklen);

    case AF_INET6:

        return getsockopt(
            serverfd,
            SOL_IPV6,
            IP6T_SO_ORIGINAL_DST,
            destaddr,
            &socklen);

    default:

        errno = EAFNOSUPPORT;

        return -1;
    }
}

int
create_and_bind(const char *addr,
                const char *port,
                int af,
                int *fds,
                int *family,
                int reuse_port)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *rp;

    int s;
    int fd_count = 0;

    memset(&hints,
           0,
           sizeof(hints));

    hints.ai_family = AF_UNSPEC;

    hints.ai_socktype = SOCK_STREAM;

    if (addr == NULL) {

        hints.ai_flags = AI_PASSIVE;
    }

    s = getaddrinfo(addr,
                    port,
                    &hints,
                    &result);

    if (s != 0) {

        LOGI("[redir] getaddrinfo: %s",
             gai_strerror(s));

        return -1;
    }

    if (result == NULL) {

        LOGE("[redir] no address returned");

        return -1;
    }

    for (rp = result;
         rp != NULL;
         rp = rp->ai_next) {

        if (af != AF_UNSPEC &&
            rp->ai_family != af) {

            continue;
        }

        int listen_sock =
            socket(rp->ai_family,
                   rp->ai_socktype,
                   rp->ai_protocol);

        if (listen_sock < 0) {

            continue;
        }

        /*
         * Keep IPv4 and IPv6 separated.
         *
         * This avoids IPv6 TPROXY/REDIRECT ambiguity.
         */
        if (rp->ai_family == AF_INET6) {

            int v6only = 1;

            setsockopt(
                listen_sock,
                IPPROTO_IPV6,
                IPV6_V6ONLY,
                &v6only,
                sizeof(v6only));
        }

        int opt = 1;

        setsockopt(
            listen_sock,
            SOL_SOCKET,
            SO_REUSEADDR,
            &opt,
            sizeof(opt));

#ifdef SO_NOSIGPIPE

        setsockopt(
            listen_sock,
            SOL_SOCKET,
            SO_NOSIGPIPE,
            &opt,
            sizeof(opt));

#endif

        if (reuse_port) {

            if (set_reuseport(listen_sock) == 0) {

                LOGI("[redir] tcp port reuse enabled");
            }
        }

        if (tcp_tproxy) {

            int level;
            int optname;

            if (rp->ai_family == AF_INET) {

                level = IPPROTO_IP;
                optname = IP_TRANSPARENT;

            } else {

                level = IPPROTO_IPV6;
                optname = IPV6_TRANSPARENT;
            }

            if (setsockopt(
                    listen_sock,
                    level,
                    optname,
                    &opt,
                    sizeof(opt)) < 0) {

                ERROR("[redir] IP_TRANSPARENT");

                close(listen_sock);

                continue;
            }
        }

        if (bind(listen_sock,
                 rp->ai_addr,
                 rp->ai_addrlen) < 0) {

            ERROR("[redir] bind");

            close(listen_sock);

            continue;
        }

        if (listen(listen_sock,
                   SOMAXCONN) < 0) {

            ERROR("[redir] listen");

            close(listen_sock);

            continue;
        }

        setnonblocking(listen_sock);

        if (fd_count >= MAX_LISTEN_SOCKETS) {

            close(listen_sock);

            break;
        }

        fds[fd_count] = listen_sock;

        family[fd_count] =
            rp->ai_family;

        fd_count++;
    }

    freeaddrinfo(result);

    return fd_count;
}

static void
accept_cb(EV_P_ ev_io *w, int revents)
{
    listen_io_ctx_t *io_ctx =
        (listen_io_ctx_t *)w->data;

    if (io_ctx == NULL ||
        io_ctx->listener == NULL) {

        ERROR("[redir] invalid listener context");

        return;
    }

    listen_ctx_t *listener =
        io_ctx->listener;

    int family =
        io_ctx->family;

    int serverfd =
        accept(w->fd,
               NULL,
               NULL);

    if (serverfd < 0) {

        if (errno != EAGAIN &&
            errno != EWOULDBLOCK &&
            errno != EINTR) {

            ERROR("[redir] accept");
        }

        return;
    }

    struct sockaddr_storage destaddr;

    memset(&destaddr,
           0,
           sizeof(destaddr));

    if (getdestaddr(serverfd,
                    family,
                    &destaddr) != 0) {

        ERROR("[redir] failed to get original destination");

        close(serverfd);

        return;
    }

    if (destaddr.ss_family != family) {

        ERROR("[redir] destination family mismatch");

        close(serverfd);

        return;
    }

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

        close(serverfd);

        ERROR("[redir] create server failed");

        return;
    }

    server->destaddr =
        destaddr;

    server->listener =
        listener;

    server->remote_idx = -1;

    /*
     * Select available remote.
     */
    for (int i = 0;
         i < listener->remote_num;
         i++) {

        if (listener->remote_status == NULL ||
            listener->remote_status[i]) {

            server->remote_idx = i;

            break;
        }
    }

    if (server->remote_idx < 0) {

        LOGE("[redir] no available remote server");

        close_and_free_server(EV_A_
                              server);

        return;
    }

    metrics_inc_tcp_connections();

    metrics_inc_tcp_connections_total();

    metrics_inc_remote_tcp_connections(
        server->remote_idx,
        get_addr_str(
            listener->remote_addr[
                server->remote_idx],
            true));

    start_connect_remote(EV_A_
                         server);
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

        ss_free(remote->recv_ctx);
        ss_free(remote->send_ctx);
        ss_free(remote->buf);

        ss_free(remote);

        return NULL;
    }

    memset(remote->recv_ctx,
           0,
           sizeof(tcp_remote_ctx_t));

    memset(remote->send_ctx,
           0,
           sizeof(tcp_remote_ctx_t));

    memset(remote->buf,
           0,
           sizeof(buffer_t));

    balloc(remote->buf,
           SOCKET_BUF_SIZE);

    remote->fd = fd;

    remote->recv_ctx->remote = remote;

    remote->send_ctx->remote = remote;

    remote->recv_ctx->connected = 0;

    remote->send_ctx->connected = 0;

    ev_io_init(
        &remote->recv_ctx->io,
        remote_recv_cb,
        fd,
        EV_READ);

    ev_io_init(
        &remote->send_ctx->io,
        remote_send_cb,
        fd,
        EV_WRITE);

    ev_timer_init(
        &remote->send_ctx->watcher,
        remote_timeout_cb,
        min(MAX_CONNECT_TIMEOUT,
            timeout),
        0);

    return remote;
}

static void
free_remote(remote_t *remote)
{
    if (remote == NULL) {

        return;
    }

    /*
     * Break all references first.
     *
     * Prevent callback using freed memory.
     */
    if (remote->server != NULL) {

        remote->server->remote = NULL;

        remote->server = NULL;
    }

    if (remote->recv_ctx != NULL) {

        remote->recv_ctx->remote = NULL;
    }

    if (remote->send_ctx != NULL) {

        remote->send_ctx->remote = NULL;
    }

    if (remote->buf != NULL) {

        bfree(remote->buf);

        ss_free(remote->buf);

        remote->buf = NULL;
    }

    if (remote->recv_ctx != NULL) {

        ss_free(remote->recv_ctx);

        remote->recv_ctx = NULL;
    }

    if (remote->send_ctx != NULL) {

        ss_free(remote->send_ctx);

        remote->send_ctx = NULL;
    }

    ss_free(remote);
}

static void
close_and_free_remote(EV_P_ remote_t *remote)
{
    if (remote == NULL) {

        return;
    }

    /*
     * Stop watchers before close/free.
     */
    if (remote->send_ctx != NULL) {

        ev_timer_stop(
            EV_A_
            &remote->send_ctx->watcher);

        ev_io_stop(
            EV_A_
            &remote->send_ctx->io);
    }

    if (remote->recv_ctx != NULL) {

        ev_io_stop(
            EV_A_
            &remote->recv_ctx->io);
    }

    if (remote->fd >= 0) {

        close(remote->fd);

        remote->fd = -1;
    }

    free_remote(remote);
}

static server_t *
new_server(int fd)
{
    server_t *server =
        ss_malloc(sizeof(server_t));

    if (server == NULL) {

        ERROR("[redir] malloc server failed");

        return NULL;
    }

    memset(server,
           0,
           sizeof(server_t));

    server->recv_ctx =
        ss_malloc(sizeof(tcp_server_ctx_t));

    server->send_ctx =
        ss_malloc(sizeof(tcp_server_ctx_t));

    server->buf =
        ss_malloc(sizeof(buffer_t));

    if (server->recv_ctx == NULL ||
        server->send_ctx == NULL ||
        server->buf == NULL) {

        ERROR("[redir] malloc server context failed");

        ss_free(server->recv_ctx);

        ss_free(server->send_ctx);

        ss_free(server->buf);

        ss_free(server);

        return NULL;
    }

    memset(server->recv_ctx,
           0,
           sizeof(tcp_server_ctx_t));

    memset(server->send_ctx,
           0,
           sizeof(tcp_server_ctx_t));

    memset(server->buf,
           0,
           sizeof(buffer_t));

    balloc(server->buf,
           SOCKET_BUF_SIZE);

    server->e_ctx =
        ss_malloc(sizeof(cipher_ctx_t));

    server->d_ctx =
        ss_malloc(sizeof(cipher_ctx_t));

    if (server->e_ctx == NULL ||
        server->d_ctx == NULL) {

        ERROR("[redir] malloc cipher ctx failed");

        ss_free(server->e_ctx);

        ss_free(server->d_ctx);

        bfree(server->buf);

        ss_free(server->buf);

        ss_free(server->recv_ctx);

        ss_free(server->send_ctx);

        ss_free(server);

        return NULL;
    }

    crypto->ctx_init(
        crypto->cipher,
        server->e_ctx,
        1);

    crypto->ctx_init(
        crypto->cipher,
        server->d_ctx,
        0);

    server->fd = fd;

    server->recv_ctx->server = server;

    server->send_ctx->server = server;

    ev_io_init(
        &server->recv_ctx->io,
        server_recv_cb,
        fd,
        EV_READ);

    ev_io_init(
        &server->send_ctx->io,
        server_send_cb,
        fd,
        EV_WRITE);

    ev_timer_init(
        &server->delayed_connect_watcher,
        delayed_connect_cb,
        0.05,
        0);

    return server;
}

static void
free_server(server_t *server)
{
    if (server == NULL) {

        return;
    }

    if (server->remote != NULL) {

        server->remote->server = NULL;

        server->remote = NULL;
    }

    if (server->e_ctx != NULL) {

        crypto->ctx_release(server->e_ctx);

        ss_free(server->e_ctx);

        server->e_ctx = NULL;
    }

    if (server->d_ctx != NULL) {

        crypto->ctx_release(server->d_ctx);

        ss_free(server->d_ctx);

        server->d_ctx = NULL;
    }

    if (server->buf != NULL) {

        bfree(server->buf);

        ss_free(server->buf);

        server->buf = NULL;
    }

    if (server->recv_ctx != NULL) {

        server->recv_ctx->server = NULL;

        ss_free(server->recv_ctx);

        server->recv_ctx = NULL;
    }

    if (server->send_ctx != NULL) {

        server->send_ctx->server = NULL;

        ss_free(server->send_ctx);

        server->send_ctx = NULL;
    }

    ss_free(server);
}

static void
close_and_free_server(EV_P_ server_t *server)
{
    if (server == NULL) {

        return;
    }

    if (server->recv_ctx != NULL) {

        ev_io_stop(
            EV_A_
            &server->recv_ctx->io);
    }

    if (server->send_ctx != NULL) {

        ev_io_stop(
            EV_A_
            &server->send_ctx->io);
    }

    ev_timer_stop(
        EV_A_
        &server->delayed_connect_watcher);

    if (server->fd >= 0) {

        close(server->fd);

        server->fd = -1;
    }

    metrics_dec_remote_tcp_connections(
        server->remote_idx);

    metrics_dec_tcp_connections();

    free_server(server);
}
static void
server_recv_cb(EV_P_ ev_io *w, int revents)
{
    tcp_server_ctx_t *server_recv_ctx =
        (tcp_server_ctx_t *)w;

    server_t *server =
        server_recv_ctx->server;

    if (server == NULL)
        return;

    remote_t *remote =
        server->remote;

    if (remote == NULL) {
        close_and_free_server(EV_A_ server);
        return;
    }

    ev_timer_stop(EV_A_
                  &server->delayed_connect_watcher);

    if (remote->buf == NULL) {
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    }

    ssize_t r =
        recv(server->fd,
             remote->buf->data + remote->buf->len,
             SOCKET_BUF_SIZE - remote->buf->len,
             0);

    if (r == 0) {

        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);

        return;

    } else if (r < 0) {

        if (errno == EAGAIN ||
            errno == EWOULDBLOCK) {

            return;
        }

        ERROR("[redir] server recv");

        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);

        return;
    }

    remote->buf->len += r;

    metrics_inc_tcp_rx_bytes(r);

    if (!remote->send_ctx->connected) {

        ev_io_stop(EV_A_
                   &server_recv_ctx->io);

        ev_io_start(EV_A_
                    &remote->send_ctx->io);

        return;
    }

    /*
     * Encrypt payload.
     *
     * Shadowsocks AEAD:
     *
     * [payload]
     *
     * encrypt()
     *
     * [ciphertext]
     */
    int err =
        crypto->encrypt(remote->buf,
                        server->e_ctx,
                        SOCKET_BUF_SIZE);

    if (err) {

        LOGE("[redir] encryption failed");

        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);

        return;
    }

    ssize_t s =
        send(remote->fd,
             remote->buf->data + remote->buf->idx,
             remote->buf->len,
             0);

    if (s < 0) {

        if (errno == EAGAIN ||
            errno == EWOULDBLOCK) {

            remote->buf->idx = 0;

            ev_io_stop(EV_A_
                       &server_recv_ctx->io);

            ev_io_start(EV_A_
                        &remote->send_ctx->io);

            return;

        }

        ERROR("[redir] remote send");

        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);

        return;
    }

    if (s < remote->buf->len) {

        remote->buf->len -= s;
        remote->buf->idx += s;

        ev_io_stop(EV_A_
                   &server_recv_ctx->io);

        ev_io_start(EV_A_
                    &remote->send_ctx->io);

        return;
    }

    remote->buf->len = 0;
    remote->buf->idx = 0;

}

static void
server_send_cb(EV_P_ ev_io *w, int revents)
{
    tcp_server_ctx_t *server_send_ctx =
        (tcp_server_ctx_t *)w;

    server_t *server =
        server_send_ctx->server;

    if (server == NULL)
        return;

    remote_t *remote =
        server->remote;

    if (remote == NULL) {

        close_and_free_server(EV_A_ server);

        return;
    }

    if (server->buf == NULL ||
        server->buf->len == 0) {

        ev_io_stop(EV_A_
                   &server_send_ctx->io);

        if (remote->recv_ctx != NULL) {

            ev_io_start(EV_A_
                        &remote->recv_ctx->io);
        }

        return;
    }

    ssize_t s =
        send(server->fd,
             server->buf->data +
             server->buf->idx,
             server->buf->len,
             0);

    if (s < 0) {

        if (errno == EAGAIN ||
            errno == EWOULDBLOCK) {

            return;
        }

        ERROR("[redir] server send");

        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);

        return;
    }

    if (s < server->buf->len) {

        server->buf->len -= s;
        server->buf->idx += s;

        return;
    }

    server->buf->len = 0;
    server->buf->idx = 0;

    ev_io_stop(EV_A_
               &server_send_ctx->io);

    if (remote->recv_ctx != NULL) {

        ev_io_start(EV_A_
                    &remote->recv_ctx->io);
    }

}

static void
remote_recv_cb(EV_P_ ev_io *w, int revents)
{
    tcp_remote_ctx_t *remote_recv_ctx =
        (tcp_remote_ctx_t *)w;

    remote_t *remote =
        remote_recv_ctx->remote;

    if (remote == NULL)
        return;

    server_t *server =
        remote->server;

    if (server == NULL)
        return;

    if (server->buf == NULL)
        return;

    ssize_t r =
        recv(remote->fd,
             server->buf->data,
             SOCKET_BUF_SIZE,
             0);

    if (r == 0) {

        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);

        return;

    } else if (r < 0) {

        if (errno == EAGAIN ||
            errno == EWOULDBLOCK) {

            return;
        }

        ERROR("[redir] remote recv");

        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);

        return;
    }

    server->buf->len = r;
    server->buf->idx = 0;

    int err =
        crypto->decrypt(server->buf,
                        server->d_ctx,
                        SOCKET_BUF_SIZE);

    if (err == CRYPTO_ERROR) {

        LOGE("[redir] decrypt failed");

        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);

        return;

    } else if (err == CRYPTO_NEED_MORE) {

        /*
         * AEAD packet incomplete.
         *
         * Wait for next recv.
         */
        return;
    }

    ssize_t s =
        send(server->fd,
             server->buf->data +
             server->buf->idx,
             server->buf->len,
             0);

    if (s < 0) {

        if (errno == EAGAIN ||
            errno == EWOULDBLOCK) {

            server->buf->idx = 0;

            ev_io_stop(EV_A_
                       &remote_recv_ctx->io);

            ev_io_start(EV_A_
                        &server->send_ctx->io);

            return;
        }

        ERROR("[redir] server send");

        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);

        return;
    }

    if (s < server->buf->len) {

        server->buf->len -= s;
        server->buf->idx += s;

        ev_io_stop(EV_A_
                   &remote_recv_ctx->io);

        ev_io_start(EV_A_
                    &server->send_ctx->io);

        return;
    }

    server->buf->len = 0;
    server->buf->idx = 0;

    if (!remote->recv_ctx->connected &&
        !no_delay) {

        int opt = 0;

        setsockopt(server->fd,
                   SOL_TCP,
                   TCP_NODELAY,
                   &opt,
                   sizeof(opt));

        setsockopt(remote->fd,
                   SOL_TCP,
                   TCP_NODELAY,
                   &opt,
                   sizeof(opt));
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

    /*
     * Stop timeout timer.
     *
     * If this callback is called because the socket became
     * writable, the connection attempt finished.
     */
    ev_timer_stop(EV_A_
                  &remote_send_ctx->watcher);

    if (!remote_send_ctx->connected) {

        int error = 0;

        socklen_t len =
            sizeof(error);

        /*
         * Check connect() result.
         *
         * Do NOT use getpeername().
         *
         * getpeername() may return success on some IPv6
         * transparent proxy situations even when connect
         * failed.
         */
        if (getsockopt(remote->fd,
                       SOL_SOCKET,
                       SO_ERROR,
                       &error,
                       &len) < 0) {

            ERROR("[redir] getsockopt SO_ERROR");

            handle_tcp_fail(EV_A_
                            server);

            return;
        }

        if (error != 0) {

            errno = error;

            ERROR("[redir] remote connect failed");

            handle_tcp_fail(EV_A_
                            server);

            return;
        }

        remote_send_ctx->connected = 1;

        ev_io_stop(EV_A_
                   &remote_send_ctx->io);

        /*
         * Stop receiving local data temporarily.
         *
         * We must send the Shadowsocks destination header
         * before forwarding payload.
         */
        ev_io_stop(EV_A_
                   &server->recv_ctx->io);

        ev_io_start(EV_A_
                    &remote->recv_ctx->io);

        /*
         * Build SOCKS-like address header:
         *
         * [DST.ADDR]
         * [DST.PORT]
         *
         */
        buffer_t addr_buf;

        memset(&addr_buf,
               0,
               sizeof(addr_buf));

        balloc(&addr_buf,
               SOCKET_BUF_SIZE);

        int addr_len =
            construct_udprelay_header(
                &server->destaddr,
                addr_buf.data);

        if (addr_len <= 0) {

            LOGE("[redir] failed to construct destination header");

            bfree(&addr_buf);

            close_and_free_remote(EV_A_
                                  remote);

            close_and_free_server(EV_A_
                                  server);

            return;
        }

        addr_buf.len = addr_len;

        /*
         * Prepend destination address before payload.
         */
        bprepend(remote->buf,
                 &addr_buf,
                 SOCKET_BUF_SIZE);

        bfree(&addr_buf);

        /*
         * Encrypt:
         *
         * [destination][payload]
         */
        int err =
            crypto->encrypt(remote->buf,
                            server->e_ctx,
                            SOCKET_BUF_SIZE);

        if (err) {

            LOGE("[redir] encrypt failed");

            close_and_free_remote(EV_A_
                                  remote);

            close_and_free_server(EV_A_
                                  server);

            return;
        }

    }

    if (remote->buf == NULL ||
        remote->buf->len == 0) {

        ev_io_stop(EV_A_
                   &remote_send_ctx->io);

        ev_io_start(EV_A_
                    &server->recv_ctx->io);

        return;
    }

    ssize_t s =
        send(remote->fd,
             remote->buf->data +
             remote->buf->idx,
             remote->buf->len,
             0);

    if (s < 0) {

        if (errno == EAGAIN ||
            errno == EWOULDBLOCK) {

            return;
        }

        ERROR("[redir] remote send");

        handle_tcp_fail(EV_A_
                        server);

        return;
    }

    if (s < remote->buf->len) {

        remote->buf->len -= s;

        remote->buf->idx += s;

        ev_io_start(EV_A_
                    &remote_send_ctx->io);

        return;
    }

    /*
     * All encrypted data sent.
     */
    remote->buf->len = 0;
    remote->buf->idx = 0;

    ev_io_stop(EV_A_
               &remote_send_ctx->io);

    ev_io_start(EV_A_
                &server->recv_ctx->io);

}

static void
delayed_connect_cb(EV_P_ ev_timer *watcher, int revents)
{
    server_t *server =
        cork_container_of(watcher,
                          server_t,
                          delayed_connect_watcher);

    if (server == NULL)
        return;

    remote_t *remote =
        server->remote;

    if (remote == NULL) {

        close_and_free_server(EV_A_
                              server);

        return;
    }

    struct sockaddr *addr =
        (struct sockaddr *)&remote->addr_storage;

    int r =
        connect(remote->fd,
                addr,
                get_sockaddr_len(addr));

    if (r < 0 &&
        errno != CONNECT_IN_PROGRESS) {

        ERROR("[redir] delayed connect");

        handle_tcp_fail(EV_A_
                        server);

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
    tcp_remote_ctx_t *remote_ctx =
        cork_container_of(watcher,
                          tcp_remote_ctx_t,
                          watcher);

    if (remote_ctx == NULL)
        return;

    remote_t *remote =
        remote_ctx->remote;

    if (remote == NULL)
        return;

    server_t *server =
        remote->server;

    if (server == NULL)
        return;

    ev_timer_stop(EV_A_
                  watcher);

    LOGE("[redir] remote connect timeout");

    handle_tcp_fail(EV_A_
                    server);

}

static void
start_connect_remote(EV_P_ server_t *server)
{
    if (server == NULL ||
        server->listener == NULL) {

        ERROR("[redir] invalid server context");

        return;
    }

    listen_ctx_t *listener =
        server->listener;

    if (server->remote_idx >=
        listener->remote_num) {

        LOGE("[redir] no remote available");

        handle_tcp_fail(EV_A_
                        server);

        return;
    }

    struct sockaddr *addr =
        listener->remote_addr[server->remote_idx];

    if (addr == NULL) {

        ERROR("[redir] remote address NULL");

        handle_tcp_fail(EV_A_
                        server);

        return;
    }

    socklen_t addr_len =
        get_sockaddr_len(addr);

    if (addr_len == 0) {

        ERROR("[redir] invalid remote address");

        handle_tcp_fail(EV_A_
                        server);

        return;
    }

    int protocol =
        IPPROTO_TCP;

#ifdef IPPROTO_MPTCP

    if (listener->mptcp < 0) {

        protocol = IPPROTO_MPTCP;
    }

#endif

    int fd =
        socket(addr->sa_family,
               SOCK_STREAM,
               protocol);

    if (fd < 0 &&
        protocol == IPPROTO_MPTCP) {

        LOGI("[redir] MPTCP unavailable, fallback TCP");

        fd =
            socket(addr->sa_family,
                   SOCK_STREAM,
                   IPPROTO_TCP);
    }

    if (fd < 0) {

        ERROR("[redir] socket");

        handle_tcp_fail(EV_A_
                        server);

        return;
    }

    int opt = 1;

    setsockopt(fd,
               SOL_TCP,
               TCP_NODELAY,
               &opt,
               sizeof(opt));

#ifdef SO_NOSIGPIPE

    setsockopt(fd,
               SOL_SOCKET,
               SO_NOSIGPIPE,
               &opt,
               sizeof(opt));

#endif

    if (tcp_outgoing_sndbuf > 0) {

        setsockopt(fd,
                   SOL_SOCKET,
                   SO_SNDBUF,
                   &tcp_outgoing_sndbuf,
                   sizeof(int));
    }

    if (tcp_outgoing_rcvbuf > 0) {

        setsockopt(fd,
                   SOL_SOCKET,
                   SO_RCVBUF,
                   &tcp_outgoing_rcvbuf,
                   sizeof(int));
    }

    setnonblocking(fd);

    remote_t *remote =
        new_remote(fd,
                   listener->timeout);

    if (remote == NULL) {

        close(fd);

        ERROR("[redir] new_remote failed");

        handle_tcp_fail(EV_A_
                        server);

        return;
    }

    server->remote = remote;

    remote->server = server;

    /*
     * Copy address.
     *
     * Never store listener pointer.
     */
    memset(&remote->addr_storage,
           0,
           sizeof(remote->addr_storage));

    memcpy(&remote->addr_storage,
           addr,
           addr_len);

    if (fast_open) {

        ev_timer_start(EV_A_
                       &server->delayed_connect_watcher);

    } else {

        int r =
            connect(fd,
                    (struct sockaddr *)
                    &remote->addr_storage,
                    addr_len);

        if (r < 0 &&
            errno != CONNECT_IN_PROGRESS) {

            ERROR("[redir] connect");

            close_and_free_remote(EV_A_
                                  remote);

            close_and_free_server(EV_A_
                                  server);

            return;
        }

        ev_io_start(EV_A_
                    &remote->send_ctx->io);

        ev_timer_start(EV_A_
                       &remote->send_ctx->watcher);
    }

    ev_io_start(EV_A_
                &server->recv_ctx->io);
}

static void
handle_tcp_fail(EV_P_ server_t *server)
{
    if (server == NULL)
        return;

    /*
     * Current remote connection failed.
     */
    if (server->remote != NULL) {

        close_and_free_remote(EV_A_
                              server->remote);

        server->remote = NULL;
    }

    if (server->listener != NULL &&
        server->remote_idx >= 0 &&
        server->remote_idx <
        server->listener->remote_num) {

        const char *addr_str =
            get_addr_str(
                server->listener
                ->remote_addr[server->remote_idx],
                true);

        metrics_inc_remote_tcp_failures_total(
            server->remote_idx,
            addr_str);
    }

    LOGE("[redir] TCP remote connection failed, closing client");

    close_and_free_server(EV_A_
                          server);
}
static void
signal_cb(EV_P_ ev_signal *w, int revents)
{
    if (!(revents & EV_SIGNAL))
        return;

    switch (w->signum) {

    case SIGCHLD:

        if (!is_plugin_running()) {

            LOGE("[redir] plugin exited unexpectedly");

            ret_val = -1;
        }

        break;

    case SIGINT:

    case SIGTERM:

        ev_signal_stop(
            EV_A_
            &sigint_watcher);

        ev_signal_stop(
            EV_A_
            &sigterm_watcher);

        ev_signal_stop(
            EV_A_
            &sigchld_watcher);

        metrics_cleanup(EV_A);

        probe_cleanup(EV_A);

        ev_unloop(
            EV_A_
            EVUNLOOP_ALL);

        break;

    default:

        break;
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

    /*
    * Setup proxy context
    */
    struct listen_ctx listen_ctx;

    memset(&listen_ctx,
        0,
        sizeof(listen_ctx));

    listen_ctx.remote_num =
        remote_num;

    listen_ctx.remote_addr =
        ss_malloc(sizeof(struct sockaddr *) *
                remote_num);

    if (listen_ctx.remote_addr == NULL) {

        FATAL("[redir] malloc remote addr failed");
    }

    memset(listen_ctx.remote_addr,
        0,
        sizeof(struct sockaddr *) *
        remote_num);

    /*
    * Allocate remote status table.
    *
    * This table is shared with UDP relay
    * and probe module.
    */
    listen_ctx.remote_status =
        ss_malloc(sizeof(bool) *
                remote_num);

    if (listen_ctx.remote_status == NULL) {

        FATAL("[redir] malloc remote status failed");
    }

    memset((void *)listen_ctx.remote_status,
        0,
        sizeof(bool) *
        remote_num);

    /*
    * Resolve remote address
    */
    for (i = 0;
        i < remote_num;
        i++) {

        listen_ctx.remote_status[i] = true;

        char *host =
            remote_addr[i].host;

        char *port =
            remote_addr[i].port == NULL ?
            remote_port :
            remote_addr[i].port;

        if (plugin != NULL) {

            host = plugin_host;
            port = plugin_port;
        }

        struct sockaddr_storage *storage =
            ss_malloc(sizeof(struct sockaddr_storage));

        if (storage == NULL) {

            FATAL("[redir] malloc sockaddr failed");
        }

        memset(storage,
            0,
            sizeof(struct sockaddr_storage));

        if (get_sockaddr(host,
                        port,
                        storage,
                        1,
                        ipv6first) == -1) {

            FATAL("[redir] failed to resolve remote address");
        }

        listen_ctx.remote_addr[i] =
            (struct sockaddr *)storage;

        if (plugin != NULL) {

            break;
        }
    }

    listen_ctx.timeout =
        atoi(timeout);

    listen_ctx.mptcp =
        mptcp;

    /*
    * Initialize UDP relay first
    *
    * UDP relay owns remote probing status.
    * TCP shares the same remote_status table.
    */
    if (mode != TCP_ONLY) {

        init_udprelay(local_addr,
                    local_port,
                    listen_ctx.remote_num,
                    listen_ctx.remote_addr,
                    mtu,
                    crypto,
                    listen_ctx.timeout,
                    NULL,
                    fwmark,
                    listen_ctx.remote_status);
    }

    /*
    * Setup TCP listeners
    */
    if (mode != UDP_ONLY) {

        listen_ctx_t *listen_ctx_current =
            &listen_ctx;

        do {

            listen_ctx_current->local_port =
                local_port;

            if (listen_ctx_current->tos) {

                LOGI("[redir] listening at %s:%s (TOS 0x%x)",
                    local_addr,
                    local_port,
                    listen_ctx_current->tos);

            } else {

                LOGI("[redir] listening at %s:%s",
                    local_addr,
                    local_port);
            }

            if (listen_ctx_count < MAX_LISTEN_CTX) {

                listen_ctx_list[listen_ctx_count++] =
                    listen_ctx_current;

            } else {

                LOGE("[redir] too many listen contexts");
            }

            /*
            * DSCP additional listener
            */
            if (dscp_num > 0) {

                listen_ctx_t *new_lc =
                    ss_malloc(sizeof(listen_ctx_t));

                if (new_lc == NULL) {

                    FATAL("[redir] malloc listen ctx failed");
                }

                memcpy(new_lc,
                    &listen_ctx,
                    sizeof(listen_ctx_t));

                local_port =
                    dscp[dscp_num - 1].port;

                new_lc->tos =
                    dscp[dscp_num - 1].dscp << 2;

                listen_ctx_current =
                    new_lc;

            }

        } while (dscp_num-- > 0 &&
                listen_ctx_current != NULL);

        /*
        * Create TCP listen sockets
        */
        for (i = 0;
            i < listen_ctx_count;
            i++) {

            listen_ctx_t *listener =
                listen_ctx_list[i];

            int fds[MAX_LISTEN_SOCKETS];

            int families[MAX_LISTEN_SOCKETS];

            int fd_count =
                create_and_bind(local_addr,
                                listener->local_port,
                                AF_UNSPEC,
                                fds,
                                families,
                                reuse_port);

            if (fd_count <= 0) {

                FATAL("[redir] bind failed");
            }

            listener->fd_num =
                fd_count;

            for (int j = 0;
                j < fd_count;
                j++) {

                listener->fd[j] =
                    fds[j];

                listener->family[j] =
                    families[j];

                listener->io_ctx[j].listener =
                    listener;

                /*
                * FIX:
                *
                * old:
                * listener->io_ctx[j].family = rp->ai_family;
                *
                * rp is undefined.
                *
                * Use family returned by create_and_bind().
                */
                listener->io_ctx[j].family =
                    listener->family[j];

                listener->io_ctx[j].fd =
                    fds[j];

                ev_io_init(&listener->io[j],
                        accept_cb,
                        fds[j],
                        EV_READ);

                listener->io[j].data =
                    &listener->io_ctx[j];

                ev_io_start(EV_A_
                            &listener->io[j]);
            }
        }

    } else {

        LOGI("[redir] TCP relay disabled");
    }

    /*
     * Drop privileges
     */
    if (user != NULL &&
        !run_as(user)) {

        FATAL("[redir] failed to switch user");
    }

    if (geteuid() == 0) {

        LOGI("[redir] running from root user");
    }

    /*
     * Main event loop
     */
    ev_run(loop,
           0);

    /*
     * Shutdown plugin
     */
    if (plugin != NULL) {

        stop_plugin();
    }

    /*
     * Free remote sockaddr
     */
    for (i = 0;
         i < remote_num;
         i++) {

        if (listen_ctx.remote_addr[i] != NULL) {

            ss_free(listen_ctx.remote_addr[i]);
        }
    }

    ss_free(listen_ctx.remote_addr);

    if (listen_ctx.remote_status != NULL) {

        ss_free(listen_ctx.remote_status);
    }

    /*
     * Free DSCP listener contexts
     */
    for (i = 0;
         i < listen_ctx_count;
         i++) {

        if (listen_ctx_list[i] != &listen_ctx) {

            ss_free(listen_ctx_list[i]);
        }
    }

    /*
     * Release crypto context
     */
    if (crypto != NULL) {
        crypto = NULL;
    }

    return ret_val;
}