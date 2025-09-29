/*
 * dot.h - DNS-over-TLS client implementation
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

#ifndef _DOT_H
#define _DOT_H

#include <ev.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>

#include "crypto.h"

/* Forward declarations to avoid circular dependencies */
struct server_ctx;

typedef struct dot_ctx {
    ev_io io;
    ev_timer watcher;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    buffer_t *request;  // DNS query from client
    buffer_t *response; // DNS response from DoT server
    mbedtls_net_context net_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    int state; // handshake, write, read, done
    struct server_ctx *server_ctx;
} dot_ctx_t;

void start_dot_session(EV_P_ struct server_ctx *server_ctx, struct sockaddr_storage *client_addr, socklen_t client_addr_len, buffer_t *dns_query);

#endif // _DOT_H