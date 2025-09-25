/*
 * metrics.c - Prometheus metrics exporter
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "metrics.h"
#include "utils.h"

static ev_io metrics_watcher;
static int metrics_fd = -1;
static pthread_mutex_t metrics_lock = PTHREAD_MUTEX_INITIALIZER;

/* Metrics data */
static time_t process_start_time = 0;
static long tcp_connections = 0;
static long tcp_connections_total = 0;
static long tcp_tx_bytes_total = 0;
static long tcp_rx_bytes_total = 0;
static size_t udp_sessions = 0;
static long udp_sessions_total = 0;
static long udp_tx_bytes_total = 0;
static long udp_rx_bytes_total = 0;

static int total_remotes = 0;
static char **remote_addr_labels = NULL;
static bool *remote_up = NULL;
static int *remote_latency = NULL;
static long *remote_probes_total = NULL;
static long *remote_probe_failures_total = NULL;
static long *remote_tcp_connections_total = NULL;
static long *remote_tcp_connections = NULL;
static long *remote_tcp_failures_total = NULL;
static long *remote_udp_sessions = NULL;
static long *remote_udp_sessions_total = NULL;
static long *remote_udp_session_timeouts_total = NULL;

static void
metrics_accept_cb(EV_P_ ev_io *w, int revents)
{
    int client_fd = accept(w->fd, NULL, NULL);
    if (client_fd == -1) {
        return;
    }

    char req_buffer[1024];
    ssize_t nread = recv(client_fd, req_buffer, sizeof(req_buffer) - 1, 0);

    if (nread > 0) {
        req_buffer[nread] = '\0';
        if (strstr(req_buffer, "GET /metrics") != NULL) {
            char res_buffer[4096];
            char *pos = res_buffer;
            char *end = res_buffer + sizeof(res_buffer);

            pthread_mutex_lock(&metrics_lock);

            pos += snprintf(pos, end - pos, "# HELP process_start_time_seconds Start time of the process since unix epoch in seconds.\n");
            pos += snprintf(pos, end - pos, "# TYPE process_start_time_seconds gauge\n");
            pos += snprintf(pos, end - pos, "process_start_time_seconds %lld\n", (long long)process_start_time);

            pos += snprintf(pos, end - pos, "# HELP ss_tcp_connections Current number of TCP connections.\n");
            pos += snprintf(pos, end - pos, "# TYPE ss_tcp_connections gauge\n");
            pos += snprintf(pos, end - pos, "ss_tcp_connections %ld\n", tcp_connections);

            pos += snprintf(pos, end - pos, "# HELP ss_tcp_connections_total Total number of TCP connections.\n");
            pos += snprintf(pos, end - pos, "# TYPE ss_tcp_connections_total counter\n");
            pos += snprintf(pos, end - pos, "ss_tcp_connections_total %ld\n", tcp_connections_total);

            pos += snprintf(pos, end - pos, "# HELP ss_udp_sessions Current number of UDP sessions.\n");
            pos += snprintf(pos, end - pos, "# TYPE ss_udp_sessions gauge\n");
            pos += snprintf(pos, end - pos, "ss_udp_sessions %zu\n", udp_sessions);

            pos += snprintf(pos, end - pos, "# HELP ss_udp_sessions_total Total number of UDP sessions created.\n");
            pos += snprintf(pos, end - pos, "# TYPE ss_udp_sessions_total counter\n");
            pos += snprintf(pos, end - pos, "ss_udp_sessions_total %ld\n", udp_sessions_total);

            pos += snprintf(pos, end - pos, "# HELP ss_tcp_tx_bytes_total Total bytes sent from client to remote (TCP).\n");
            pos += snprintf(pos, end - pos, "# TYPE ss_tcp_tx_bytes_total counter\n");
            pos += snprintf(pos, end - pos, "ss_tcp_tx_bytes_total %ld\n", tcp_tx_bytes_total);

            pos += snprintf(pos, end - pos, "# HELP ss_tcp_rx_bytes_total Total bytes received from remote to client (TCP).\n");
            pos += snprintf(pos, end - pos, "# TYPE ss_tcp_rx_bytes_total counter\n");
            pos += snprintf(pos, end - pos, "ss_tcp_rx_bytes_total %ld\n", tcp_rx_bytes_total);

            pos += snprintf(pos, end - pos, "# HELP ss_udp_tx_bytes_total Total bytes sent from client to remote (UDP).\n");
            pos += snprintf(pos, end - pos, "# TYPE ss_udp_tx_bytes_total counter\n");
            pos += snprintf(pos, end - pos, "ss_udp_tx_bytes_total %ld\n", udp_tx_bytes_total);

            pos += snprintf(pos, end - pos, "# HELP ss_udp_rx_bytes_total Total bytes received from remote to client (UDP).\n");
            pos += snprintf(pos, end - pos, "# TYPE ss_udp_rx_bytes_total counter\n");
            pos += snprintf(pos, end - pos, "ss_udp_rx_bytes_total %ld\n", udp_rx_bytes_total);

            pos += snprintf(pos, end - pos, "# HELP ss_remote_server_up Remote server availability (1=up, 0=down).\n");
            pos += snprintf(pos, end - pos, "# TYPE ss_remote_server_up gauge\n");
            for (int i = 0; i < total_remotes; i++) {
                if (remote_addr_labels[i]) {
                    pos += snprintf(pos, end - pos, "ss_remote_server_up{remote=\"%s\"} %d\n", remote_addr_labels[i], remote_up[i]);
                }
            }

            pos += snprintf(pos, end - pos, "# HELP ss_remote_server_probe_latency_milli_seconds Latency of remote server probe.\n");
            pos += snprintf(pos, end - pos, "# TYPE ss_remote_server_probe_latency_milli_seconds gauge\n");
            for (int i = 0; i < total_remotes; i++) {
                if (remote_addr_labels[i]) {
                    pos += snprintf(pos, end - pos, "ss_remote_server_probe_latency_milli_seconds{remote=\"%s\"} %d\n", remote_addr_labels[i], remote_latency[i]);
                }
            }

            pos += snprintf(pos, end - pos, "# HELP ss_remote_server_probes_total Total number of probes sent to remote servers.\n");
            pos += snprintf(pos, end - pos, "# TYPE ss_remote_server_probes_total counter\n");
            for (int i = 0; i < total_remotes; i++) {
                if (remote_addr_labels[i]) {
                    pos += snprintf(pos, end - pos, "ss_remote_server_probes_total{remote=\"%s\"} %ld\n", remote_addr_labels[i], remote_probes_total[i]);
                }
            }

            pos += snprintf(pos, end - pos, "# HELP ss_remote_server_probe_failures_total Total number of failed probes for remote servers.\n");
            pos += snprintf(pos, end - pos, "# TYPE ss_remote_server_probe_failures_total counter\n");
            for (int i = 0; i < total_remotes; i++) {
                if (remote_addr_labels[i]) {
                    pos += snprintf(pos, end - pos, "ss_remote_server_probe_failures_total{remote=\"%s\"} %ld\n", remote_addr_labels[i], remote_probe_failures_total[i]);
                }
            }

            pos += snprintf(pos, end - pos, "# HELP ss_remote_server_tcp_connections Current number of TCP connections for each remote server.\n");
            pos += snprintf(pos, end - pos, "# TYPE ss_remote_server_tcp_connections gauge\n");
            for (int i = 0; i < total_remotes; i++) {
                if (remote_addr_labels[i]) {
                    pos += snprintf(pos, end - pos, "ss_remote_server_tcp_connections{remote=\"%s\"} %ld\n", remote_addr_labels[i], remote_tcp_connections[i]);
                }
            }

            pos += snprintf(pos, end - pos, "# HELP ss_remote_server_tcp_connections_total Total number of TCP connection attempts to remote servers.\n");
            pos += snprintf(pos, end - pos, "# TYPE ss_remote_server_tcp_connections_total counter\n");
            for (int i = 0; i < total_remotes; i++) {
                if (remote_addr_labels[i]) {
                    pos += snprintf(pos, end - pos, "ss_remote_server_tcp_connections_total{remote=\"%s\"} %ld\n", remote_addr_labels[i], remote_tcp_connections_total[i]);
                }
            }

            pos += snprintf(pos, end - pos, "# HELP ss_remote_server_tcp_failures_total Total number of failed TCP connection attempts to remote servers.\n");
            pos += snprintf(pos, end - pos, "# TYPE ss_remote_server_tcp_failures_total counter\n");
            for (int i = 0; i < total_remotes; i++) {
                if (remote_addr_labels[i]) {
                    pos += snprintf(pos, end - pos, "ss_remote_server_tcp_failures_total{remote=\"%s\"} %ld\n", remote_addr_labels[i], remote_tcp_failures_total[i]);
                }
            }

            pos += snprintf(pos, end - pos, "# HELP ss_remote_server_udp_sessions Current number of UDP sessions for each remote server.\n");
            pos += snprintf(pos, end - pos, "# TYPE ss_remote_server_udp_sessions gauge\n");
            for (int i = 0; i < total_remotes; i++) {
                if (remote_addr_labels[i]) {
                    pos += snprintf(pos, end - pos, "ss_remote_server_udp_sessions{remote=\"%s\"} %ld\n", remote_addr_labels[i], remote_udp_sessions[i]);
                }
            }

            pos += snprintf(pos, end - pos, "# HELP ss_remote_server_udp_sessions_total Total number of UDP sessions created for each remote server.\n");
            pos += snprintf(pos, end - pos, "# TYPE ss_remote_server_udp_sessions_total counter\n");
            for (int i = 0; i < total_remotes; i++) {
                if (remote_addr_labels[i]) {
                    pos += snprintf(pos, end - pos, "ss_remote_server_udp_sessions_total{remote=\"%s\"} %ld\n", remote_addr_labels[i], remote_udp_sessions_total[i]);
                }
            }

            pos += snprintf(pos, end - pos, "# HELP ss_remote_server_udp_session_timeouts_total Total number of UDP sessions that timed out waiting for a reply from remote servers.\n");
            pos += snprintf(pos, end - pos, "# TYPE ss_remote_server_udp_session_timeouts_total counter\n");
            for (int i = 0; i < total_remotes; i++) {
                if (remote_addr_labels[i]) {
                    pos += snprintf(pos, end - pos, "ss_remote_server_udp_session_timeouts_total{remote=\"%s\"} %ld\n", remote_addr_labels[i], remote_udp_session_timeouts_total[i]);
                }
            }

            pthread_mutex_unlock(&metrics_lock);

            char http_response[8192];
            int body_len = strlen(res_buffer);
            int header_len = snprintf(http_response, sizeof(http_response),
                                      "HTTP/1.1 200 OK\r\n"
                                      "Content-Type: text/plain; version=0.0.4\r\n"
                                      "Content-Length: %d\r\n"
                                      "\r\n", body_len);

            if (header_len + body_len < sizeof(http_response)) {
                memcpy(http_response + header_len, res_buffer, body_len);
                send(client_fd, http_response, header_len + body_len, 0);
            }
        }
    }

    close(client_fd);
}

void
metrics_init(EV_P_ const char *addr, uint16_t port, int remote_num, time_t start_time)
{
    if (!addr || port == 0) {
        return;
    }

    process_start_time = start_time;

    total_remotes = remote_num;
    remote_up = ss_malloc(sizeof(bool) * total_remotes);
    remote_latency = ss_malloc(sizeof(int) * total_remotes);
    remote_addr_labels = ss_malloc(sizeof(char*) * total_remotes);
    remote_probes_total = ss_malloc(sizeof(long) * total_remotes);
    remote_probe_failures_total = ss_malloc(sizeof(long) * total_remotes);
    remote_tcp_connections = ss_malloc(sizeof(long) * total_remotes);
    remote_tcp_connections_total = ss_malloc(sizeof(long) * total_remotes);
    remote_tcp_failures_total = ss_malloc(sizeof(long) * total_remotes);
    remote_udp_sessions = ss_malloc(sizeof(long) * total_remotes);
    remote_udp_sessions_total = ss_malloc(sizeof(long) * total_remotes);
    remote_udp_session_timeouts_total = ss_malloc(sizeof(long) * total_remotes);

    for (int i = 0; i < total_remotes; i++) {
        remote_up[i] = true; /* Assume all remotes are up initially */
    }

    memset(remote_latency, 0, sizeof(int) * total_remotes);
    memset(remote_addr_labels, 0, sizeof(char*) * total_remotes);
    memset(remote_probes_total, 0, sizeof(long) * total_remotes);
    memset(remote_probe_failures_total, 0, sizeof(long) * total_remotes);
    memset(remote_tcp_connections, 0, sizeof(long) * total_remotes);
    memset(remote_tcp_connections_total, 0, sizeof(long) * total_remotes);
    memset(remote_tcp_failures_total, 0, sizeof(long) * total_remotes);
    memset(remote_udp_sessions, 0, sizeof(long) * total_remotes);
    memset(remote_udp_sessions_total, 0, sizeof(long) * total_remotes);
    memset(remote_udp_session_timeouts_total, 0, sizeof(long) * total_remotes);

    metrics_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (metrics_fd == -1) {
        ERROR("[metrics] failed to create socket");
        return;
    }

    int opt = 1;
    setsockopt(metrics_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setnonblocking(metrics_fd);

    struct sockaddr_in sock_addr;
    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, addr, &sock_addr.sin_addr) <= 0) {
        ERROR("[metrics] inet_pton");
        close(metrics_fd);
        metrics_fd = -1;
        return;
    }

    if (bind(metrics_fd, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) != 0) {
        ERROR("[metrics] bind");
        close(metrics_fd);
        metrics_fd = -1;
        return;
    }

    if (listen(metrics_fd, SOMAXCONN) != 0) {
        ERROR("[metrics] listen");
        close(metrics_fd);
        metrics_fd = -1;
        return;
    }

    ev_io_init(&metrics_watcher, metrics_accept_cb, metrics_fd, EV_READ);
    ev_io_start(EV_A_ &metrics_watcher);

    LOGI("[metrics] metrics server started on %s:%d", addr, port);
}

void
metrics_cleanup(EV_P)
{
    if (metrics_fd != -1) {
        ev_io_stop(EV_A_ &metrics_watcher);
        close(metrics_fd);
        metrics_fd = -1;
    } else {
    }
    ss_free(remote_up);
    ss_free(remote_latency);
    ss_free(remote_probes_total);
    ss_free(remote_probe_failures_total);
    ss_free(remote_tcp_connections);
    ss_free(remote_tcp_connections_total);
    ss_free(remote_tcp_failures_total);
    ss_free(remote_udp_sessions);
    ss_free(remote_udp_sessions_total);
    ss_free(remote_udp_session_timeouts_total);
    if (remote_addr_labels) {
        for (int i = 0; i < total_remotes; i++) {
            ss_free(remote_addr_labels[i]);
        }
        ss_free(remote_addr_labels);
    }

}

void metrics_inc_tcp_connections(void) {
    __sync_fetch_and_add(&tcp_connections, 1);
}

void metrics_dec_tcp_connections(void) {
    __sync_fetch_and_sub(&tcp_connections, 1);
}

void metrics_inc_tcp_connections_total(void) {
    __sync_fetch_and_add(&tcp_connections_total, 1);
}

void metrics_set_udp_sessions(size_t count) {
    pthread_mutex_lock(&metrics_lock);
    udp_sessions = count;
    pthread_mutex_unlock(&metrics_lock);
}

void metrics_inc_udp_sessions_total(void) {
    __sync_fetch_and_add(&udp_sessions_total, 1);
}

void metrics_inc_tcp_tx_bytes(size_t bytes) {
    __sync_fetch_and_add(&tcp_tx_bytes_total, bytes);
}

void metrics_inc_tcp_rx_bytes(size_t bytes) {
    __sync_fetch_and_add(&tcp_rx_bytes_total, bytes);
}

void metrics_inc_udp_tx_bytes(size_t bytes) {
    __sync_fetch_and_add(&udp_tx_bytes_total, bytes);
}

void metrics_inc_udp_rx_bytes(size_t bytes) {
    __sync_fetch_and_add(&udp_rx_bytes_total, bytes);
}

void metrics_set_remote_server_up(int idx, const char *addr, bool up) {
    pthread_mutex_lock(&metrics_lock);
    if(idx<total_remotes){
        if(!remote_addr_labels[idx]) remote_addr_labels[idx]=strdup(addr);
        remote_up[idx]=up;
    }
    pthread_mutex_unlock(&metrics_lock);
}

void metrics_set_remote_server_latency(int idx, const char *addr, int latency_millisecs) {
    pthread_mutex_lock(&metrics_lock);
    if(idx<total_remotes){
        if(!remote_addr_labels[idx]) remote_addr_labels[idx]=strdup(addr);
        remote_latency[idx]=latency_millisecs;
    }
    pthread_mutex_unlock(&metrics_lock);
}

void metrics_inc_remote_probes_total(int idx, const char *addr) {
    pthread_mutex_lock(&metrics_lock);
    if(idx < total_remotes){
        if(!remote_addr_labels[idx]) remote_addr_labels[idx]=strdup(addr);
        remote_probes_total[idx]++;
    }
    pthread_mutex_unlock(&metrics_lock);
}

void metrics_inc_remote_probe_failures_total(int idx, const char *addr) {
    pthread_mutex_lock(&metrics_lock);
    if(idx < total_remotes){
        if(!remote_addr_labels[idx]) remote_addr_labels[idx]=strdup(addr);
        remote_probe_failures_total[idx]++;
    }
    pthread_mutex_unlock(&metrics_lock);
}

void metrics_inc_remote_tcp_connections(int idx, const char *addr) {
    pthread_mutex_lock(&metrics_lock);
    if(idx < total_remotes){
        if(!remote_addr_labels[idx]) remote_addr_labels[idx]=strdup(addr);
        remote_tcp_connections[idx]++;
    }
    pthread_mutex_unlock(&metrics_lock);
}

void metrics_dec_remote_tcp_connections(int idx) {
    pthread_mutex_lock(&metrics_lock);
    if(idx < total_remotes && remote_tcp_connections[idx] > 0){
        remote_tcp_connections[idx]--;
    }
    pthread_mutex_unlock(&metrics_lock);
}

void metrics_inc_remote_tcp_connections_total(int idx, const char *addr) {
    pthread_mutex_lock(&metrics_lock);
    if(idx < total_remotes){
        if(!remote_addr_labels[idx]) remote_addr_labels[idx]=strdup(addr);
        remote_tcp_connections_total[idx]++;
    }
    pthread_mutex_unlock(&metrics_lock);
}

void metrics_inc_remote_tcp_failures_total(int idx, const char *addr) {
    pthread_mutex_lock(&metrics_lock);
    if(idx < total_remotes){
        if(!remote_addr_labels[idx]) remote_addr_labels[idx]=strdup(addr);
        remote_tcp_failures_total[idx]++;
    }
    pthread_mutex_unlock(&metrics_lock);
}

void metrics_inc_remote_udp_sessions(int idx, const char *addr) {
    pthread_mutex_lock(&metrics_lock);
    if(idx < total_remotes){
        if(!remote_addr_labels[idx]) remote_addr_labels[idx]=strdup(addr);
        remote_udp_sessions[idx]++;
    }
    pthread_mutex_unlock(&metrics_lock);
}

void metrics_dec_remote_udp_sessions(int idx) {
    pthread_mutex_lock(&metrics_lock);
    if(idx < total_remotes && remote_udp_sessions[idx] > 0){
        remote_udp_sessions[idx]--;
    }
    pthread_mutex_unlock(&metrics_lock);
}

void metrics_inc_remote_udp_sessions_total(int idx, const char *addr) {
    pthread_mutex_lock(&metrics_lock);
    if(idx < total_remotes){
        if(!remote_addr_labels[idx]) remote_addr_labels[idx]=strdup(addr);
        remote_udp_sessions_total[idx]++;
    }
    pthread_mutex_unlock(&metrics_lock);
}

void metrics_inc_remote_udp_session_timeouts_total(int idx, const char *addr) {
    pthread_mutex_lock(&metrics_lock);
    if(idx < total_remotes){
        if(!remote_addr_labels[idx]) remote_addr_labels[idx]=strdup(addr);
        remote_udp_session_timeouts_total[idx]++;
    }
    pthread_mutex_unlock(&metrics_lock);
}
