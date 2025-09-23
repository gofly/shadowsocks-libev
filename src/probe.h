/*
 * probe.h - Active probing for remote server status
 *
 * Copyright (C) 2019, zkc <zkc@tcpip.fun>
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

#ifndef _PROBE_H
#define _PROBE_H

#include <ev.h>

void probe_init(EV_P_ int udp_interval, int udp_timeout, int up_count, int down_count, const char *domain);
void probe_add_udp_server(void *server);
void probe_cleanup(EV_P);

#endif // _PROBE_H