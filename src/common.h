/*
 * common.h - Provide global definitions
 *
 * Copyright (C) 2013 - 2019, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
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

#ifndef _COMMON_H
#define _COMMON_H

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

#include "crypto.h"

int init_udprelay(const char *server_host, const char *server_port,
                  int remote_num, struct sockaddr **remote_addr, int mtu,
                  crypto_t *crypto, int timeout, const char *iface, int fwmark,
                  volatile bool *remote_status);

void free_udprelay(void);

#define STAGE_ERROR     -1  /* Error detected                   */
#define STAGE_INIT       0  /* Initial stage                    */
#define STAGE_HANDSHAKE  1  /* Handshake with client            */
#define STAGE_RESOLVE    4  /* Resolve the hostname             */
#define STAGE_STREAM     5  /* Stream between client and server */
#define STAGE_STOP       6  /* Server stop to response          */

/* Vals for long options */
enum {
    GETOPT_VAL_HELP = 257,
    GETOPT_VAL_REUSE_PORT,
    GETOPT_VAL_FAST_OPEN,
    GETOPT_VAL_NODELAY,
    GETOPT_VAL_MTU,
    GETOPT_VAL_MPTCP,
    GETOPT_VAL_PLUGIN,
    GETOPT_VAL_PLUGIN_OPTS,
    GETOPT_VAL_PASSWORD,
    GETOPT_VAL_KEY,
    GETOPT_VAL_TCP_INCOMING_SNDBUF,
    GETOPT_VAL_TCP_INCOMING_RCVBUF,
    GETOPT_VAL_TCP_OUTGOING_SNDBUF,
    GETOPT_VAL_TCP_OUTGOING_RCVBUF,
    GETOPT_VAL_FWMARK,
    GETOPT_VAL_PROBE_INTERVAL,
    GETOPT_VAL_PROBE_TIMEOUT,
    GETOPT_VAL_PROBE_UP_COUNT,
    GETOPT_VAL_PROBE_DOWN_COUNT,
    GETOPT_VAL_PROBE_DOMAIN,
};

#endif // _COMMON_H
