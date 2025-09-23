/*
 * udprelay.h - Define UDP relay's buffers and callbacks
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

#ifndef _UDPRELAY_H
#define _UDPRELAY_H

#include <time.h>

#ifdef HAVE_LIBEV_EV_H
#include <libev/ev.h>
#else
#include <ev.h>
#endif

#include "crypto.h"
#include "jconf.h"

#include "cache.h"

#include "common.h"

#define MAX_UDP_PACKET_SIZE (65507)

#define PACKET_HEADER_SIZE (1 + 28 + 2 + 64)
#define DEFAULT_PACKET_SIZE 1397 // 1492 - PACKET_HEADER_SIZE = 1397, the default MTU for UDP relay
#define MAX_ADDR_HEADER_SIZE (1 + 256 + 2) // 1-byte atyp + 256-byte hostname + 2-byte port

typedef struct server_ctx {
    ev_io io;
    int fd;
    crypto_t *crypto;
    int timeout;
    const char *iface;
    struct cache *conn_cache;
    int remote_num;
    struct sockaddr **remote_addr;
    int fwmark;
    volatile bool *remote_status;
} server_ctx_t;

typedef enum {
    STATE_IDLE,
    STATE_AWAITING_REPLY
} remote_state_t;

typedef struct remote_ctx {
    ev_io io;
    ev_timer watcher;
    int af;
    int fd;
    struct sockaddr_storage src_addr;
    remote_state_t state;
    server_ctx_t *server_ctx;
    int remote_idx;
} remote_ctx_t;

#endif // _UDPRELAY_H
