/*
 * metrics.h - Prometheus metrics exporter
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

#ifndef _METRICS_H
#define _METRICS_H

#include <ev.h>

void metrics_init(EV_P_ const char *addr, uint16_t port, int remote_num, time_t start_time);
void metrics_cleanup(EV_P);

void metrics_inc_tcp_connections(void);
void metrics_dec_tcp_connections(void);
void metrics_inc_tcp_connections_total(void);
void metrics_set_udp_sessions(size_t count);
void metrics_inc_udp_sessions_total(void);

void metrics_inc_tcp_tx_bytes(size_t bytes);
void metrics_inc_tcp_rx_bytes(size_t bytes);
void metrics_inc_udp_tx_bytes(size_t bytes);
void metrics_inc_udp_rx_bytes(size_t bytes);

void metrics_set_remote_server_up(int remote_idx, const char *remote_addr_str, bool up);
void metrics_set_remote_server_latency(int remote_idx, const char *remote_addr_str, int latency_millisecs);
void metrics_inc_remote_probes_total(int remote_idx, const char *remote_addr_str);
void metrics_inc_remote_probe_failures_total(int remote_idx, const char *remote_addr_str);

void metrics_inc_remote_tcp_connections(int remote_idx, const char *remote_addr_str);
void metrics_dec_remote_tcp_connections(int remote_idx);
void metrics_inc_remote_tcp_connections_total(int remote_idx, const char *remote_addr_str);
void metrics_inc_remote_tcp_failures_total(int remote_idx, const char *remote_addr_str);

void metrics_inc_remote_udp_sessions(int remote_idx, const char *remote_addr_str);
void metrics_dec_remote_udp_sessions(int remote_idx);
void metrics_inc_remote_udp_sessions_total(int remote_idx, const char *remote_addr_str);
void metrics_inc_remote_udp_session_timeouts_total(int remote_idx, const char *remote_addr_str);

#endif // _METRICS_H