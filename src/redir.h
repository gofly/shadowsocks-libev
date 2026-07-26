#ifndef _REDIR_H
#define _REDIR_H

#ifdef HAVE_LIBEV_EV_H
#include <libev/ev.h>
#else
#include <ev.h>
#endif

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#include "crypto.h"
#include "jconf.h"

typedef struct listen_ctx listen_ctx_t;
typedef struct listen_io_ctx listen_io_ctx_t;
typedef struct server server_t;
typedef struct remote remote_t;

struct listen_io_ctx {
    listen_ctx_t *listener;
    int fd;
    int family;
};

struct listen_ctx {
    ev_io io[MAX_LISTEN_SOCKETS];
    int fd[MAX_LISTEN_SOCKETS];
    int family[MAX_LISTEN_SOCKETS];
    listen_io_ctx_t io_ctx[MAX_LISTEN_SOCKETS];
    int fd_num;
    int remote_num;
    int timeout;
    int mptcp;
    int tos;
    volatile bool *remote_status;
    const char *local_port;
    struct sockaddr **remote_addr;
};

typedef struct tcp_server_ctx {
    ev_io io;
    int connected;
    server_t *server;
} tcp_server_ctx_t;

struct server {
    int fd;
    buffer_t *buf;
    cipher_ctx_t *e_ctx;
    cipher_ctx_t *d_ctx;
    tcp_server_ctx_t *recv_ctx;
    tcp_server_ctx_t *send_ctx;
    remote_t *remote;
    struct sockaddr_storage destaddr;
    ev_timer delayed_connect_watcher;
    int remote_idx;
    listen_ctx_t *listener;
};

typedef struct tcp_remote_ctx {
    ev_io io;
    ev_timer watcher;
    int connected;
    remote_t *remote;
} tcp_remote_ctx_t;

struct remote {
    int fd;
    buffer_t *buf;
    tcp_remote_ctx_t *recv_ctx;
    tcp_remote_ctx_t *send_ctx;
    server_t *server;
    uint32_t counter;
    struct sockaddr_storage addr_storage;

};


#endif