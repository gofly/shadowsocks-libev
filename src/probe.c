/*
 * probe.c - Active probing for remote server status
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

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libcork/core.h>

#include "probe.h"
#include "utils.h"
#include "netutils.h"
#include "udprelay.h"
#include "metrics.h"

#define MAX_SERVERS 32

/* UDP Probe */
typedef struct udp_probe_ctx {
    ev_io io;
    ev_timer watcher;
    int remote_idx;
    server_ctx_t *server_ctx;
    crypto_t *crypto;
    ev_tstamp start_time;
} udp_probe_ctx_t;

static ev_timer udp_probe_timer;
static server_ctx_t *udp_servers[MAX_SERVERS] = { NULL };
static int probe_timeout_secs = 5;
static int probe_up_threshold = 1;
static int probe_down_threshold = 3;
static int udp_server_count = 0;

static int *udp_probe_success_count = NULL;
static int *udp_probe_failure_count = NULL;

static unsigned char *dns_probe_packet = NULL;
static size_t dns_probe_packet_len = 0;

/*
 * build_dns_query - Constructs a DNS query packet for a given domain name.
 * Returns the length of the generated packet, or 0 on failure.
 */
static size_t build_dns_query(const char *domain, unsigned char *buf, size_t buf_len) {
    if (!domain || !buf) return 0;

    // DNS Header (12 bytes)
    // ID (random), QR=0, Opcode=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0
    // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    unsigned char header[] = {
        rand() % 256, rand() % 256, // Transaction ID
        0x01, 0x00, // Flags: 0x0100 (Standard query)
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00  // Additional RRs: 0
    };
    size_t offset = sizeof(header);
    if (buf_len < offset) return 0;
    memcpy(buf, header, offset);

    // QNAME section
    const char *p = domain;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (dot - p) : strlen(p);
        if (buf_len < offset + 1 + len) return 0;
        buf[offset++] = (unsigned char)len;
        memcpy(buf + offset, p, len);
        offset += len;
        p += len;
        if (dot) p++; // Skip the dot
    }
    if (buf_len < offset + 5) return 0; // 1 (null terminator) + 2 (QTYPE) + 2 (QCLASS)
    buf[offset++] = 0x00; // Null terminator for QNAME
    buf[offset++] = 0x00; buf[offset++] = 0x01; // QTYPE: A
    buf[offset++] = 0x00; buf[offset++] = 0x01; // QCLASS: IN
    return offset;
}

/* UDP Probe Implementation */
static void udp_probe_cleanup(EV_P_ udp_probe_ctx_t *p_ctx) {
    ev_io_stop(EV_A_ &p_ctx->io);
    ev_timer_stop(EV_A_ &p_ctx->watcher);
    close(p_ctx->io.fd);
    ss_free(p_ctx);
}

static void udp_probe_recv_cb(EV_P_ ev_io *w, int revents) {
    udp_probe_ctx_t *p_ctx = (udp_probe_ctx_t *)w;
    buffer_t *buf = ss_malloc(sizeof(buffer_t));
    balloc(buf, MAX_UDP_PACKET_SIZE);

    ev_tstamp latency = ev_time() - p_ctx->start_time;
    const char *addr_str = get_addr_str(p_ctx->server_ctx->remote_addr[p_ctx->remote_idx], true);

    ssize_t r = recv(p_ctx->io.fd, buf->data, MAX_UDP_PACKET_SIZE, 0);
    bool success = false;
    if (r > 0) {
        buf->len = r;
        if (p_ctx->crypto->decrypt_all(buf, p_ctx->crypto->cipher, buf->capacity) == 0) {
            // The decrypted payload is: [ss addr header][dns response]
            // We need to parse the ss addr header first to get to the dns response.
            int header_len = parse_udprelay_header(buf->data, buf->len, NULL, NULL, NULL);

            if (header_len > 0 && buf->len > header_len) {
                const char *dns_response_ptr = buf->data + header_len;
                const size_t dns_response_len = buf->len - header_len;

                /*
                 * A successful probe requires:
                 * 1. DNS RCODE is 0 (No Error).
                 * 2. ANCOUNT (Answer Record Count) is greater than 0.
                 */
                const bool rcode_ok = (dns_response_len >= 12) && ((dns_response_ptr[3] & 0x0F) == 0);
                const bool has_answers = rcode_ok && (load16_be((const uint8_t *)dns_response_ptr + 6) > 0);

                if (rcode_ok && has_answers) {
                    success = true;
                }
            }
        }
    }

    if (success) {
        udp_probe_failure_count[p_ctx->remote_idx] = 0;
        udp_probe_success_count[p_ctx->remote_idx]++;

        if (!p_ctx->server_ctx->remote_status[p_ctx->remote_idx] &&
            udp_probe_success_count[p_ctx->remote_idx] >= probe_up_threshold) {
            LOGI("[probe] remote %d is back online after %d successful probes.", p_ctx->remote_idx, udp_probe_success_count[p_ctx->remote_idx]);
            p_ctx->server_ctx->remote_status[p_ctx->remote_idx] = true;
            metrics_set_remote_server_up(p_ctx->remote_idx, addr_str, true);
        }
        metrics_set_remote_server_latency(p_ctx->remote_idx, addr_str, latency*1000);
        
        /* If already up, we don't need to log anything, just update the metric */
        if (p_ctx->server_ctx->remote_status[p_ctx->remote_idx]) {
            metrics_set_remote_server_up(p_ctx->remote_idx, addr_str, true);
        }
    } else {
        udp_probe_success_count[p_ctx->remote_idx] = 0;
        udp_probe_failure_count[p_ctx->remote_idx]++;

        if (p_ctx->server_ctx->remote_status[p_ctx->remote_idx] &&
            udp_probe_failure_count[p_ctx->remote_idx] >= probe_down_threshold) {
            LOGI("[probe] remote %d is offline after %d failed probes.", p_ctx->remote_idx, udp_probe_failure_count[p_ctx->remote_idx]);
            p_ctx->server_ctx->remote_status[p_ctx->remote_idx] = false;
            metrics_inc_remote_probe_failures_total(p_ctx->remote_idx, addr_str);
            metrics_set_remote_server_up(p_ctx->remote_idx, addr_str, false);
        }
    }

    bfree(buf);
    ss_free(buf);
    udp_probe_cleanup(EV_A_ p_ctx);
}

static void udp_probe_timeout_cb(EV_P_ ev_timer *w, int revents) {
    udp_probe_ctx_t *p_ctx = cork_container_of(w, udp_probe_ctx_t, watcher);

    udp_probe_success_count[p_ctx->remote_idx] = 0;
    udp_probe_failure_count[p_ctx->remote_idx]++;

    const char *addr_str = get_addr_str(p_ctx->server_ctx->remote_addr[p_ctx->remote_idx], true);
    if (p_ctx->server_ctx->remote_status[p_ctx->remote_idx] &&
        udp_probe_failure_count[p_ctx->remote_idx] >= probe_down_threshold) {
        LOGI("[probe] remote %d is offline after %d probe timeouts.", p_ctx->remote_idx, udp_probe_failure_count[p_ctx->remote_idx]);
        p_ctx->server_ctx->remote_status[p_ctx->remote_idx] = false;
        metrics_set_remote_server_up(p_ctx->remote_idx, addr_str, false);
        metrics_inc_remote_probe_failures_total(p_ctx->remote_idx, addr_str);
    }

    udp_probe_cleanup(EV_A_ p_ctx);
}

static void start_one_udp_probe(EV_P_ server_ctx_t *s_ctx, int idx) {
    struct sockaddr *remote_addr = s_ctx->remote_addr[idx];
    const char *addr_str = get_addr_str(remote_addr, true);
    metrics_inc_remote_probes_total(idx, addr_str);

    int probefd = socket(remote_addr->sa_family, SOCK_DGRAM, 0);
    if (probefd == -1) return;

    setnonblocking(probefd);

    if (!dns_probe_packet) {
        close(probefd);
        return;
    }

    /* This logic now mirrors server_recv_cb to ensure packet format is identical
     * to a real proxied packet. */

    struct sockaddr_storage dns_server_addr;
    if (get_sockaddr("8.8.8.8", "53", &dns_server_addr, 1, 0) != 0) {
        LOGE("[probe] failed to resolve 8.8.8.8:53");
        close(probefd);
        return;
    }
    char addr_header[MAX_ADDR_HEADER_SIZE] = {0};
    int addr_header_len = construct_udprelay_header(&dns_server_addr, addr_header);

    buffer_t *buf = ss_malloc(sizeof(buffer_t));
    balloc(buf, MAX_UDP_PACKET_SIZE);

    /* 1. Start with the raw DNS query as the initial payload */
    memcpy(buf->data, dns_probe_packet, dns_probe_packet_len);
    buf->len = dns_probe_packet_len;

    /* 2. Prepend the shadowsocks address header */
    brealloc(buf, buf->len + addr_header_len, MAX_UDP_PACKET_SIZE);
    memmove(buf->data + addr_header_len, buf->data, buf->len);
    memcpy(buf->data, addr_header, addr_header_len);
    buf->len += addr_header_len;

    /* 3. Encrypt the entire payload ([addr_header][dns_packet]) */
    if (s_ctx->crypto->encrypt_all(buf, s_ctx->crypto->cipher, buf->capacity) != 0) {
        bfree(buf);
        ss_free(buf);
        close(probefd);
        return;
    }

    sendto(probefd, buf->data, buf->len, 0, remote_addr, get_sockaddr_len(remote_addr));
    bfree(buf);
    ss_free(buf);

    udp_probe_ctx_t *p_ctx = ss_malloc(sizeof(udp_probe_ctx_t));
    memset(p_ctx, 0, sizeof(udp_probe_ctx_t));
    p_ctx->server_ctx = s_ctx;
    p_ctx->remote_idx = idx;
    p_ctx->crypto = s_ctx->crypto;
    p_ctx->start_time = ev_time();

    ev_io_init(&p_ctx->io, udp_probe_recv_cb, probefd, EV_READ);
    ev_timer_init(&p_ctx->watcher, udp_probe_timeout_cb, probe_timeout_secs, 0);
    ev_io_start(EV_A_ &p_ctx->io);
    ev_timer_start(EV_A_ &p_ctx->watcher);
}

static void udp_probe_timer_cb(EV_P_ ev_timer *w, int revents) {
    for (int i = 0; i < udp_server_count; i++) {
        server_ctx_t *s_ctx = udp_servers[i];
        if (s_ctx && s_ctx->remote_num > 1) {
            for (int j = 0; j < s_ctx->remote_num; j++) {
                start_one_udp_probe(EV_A_ s_ctx, j);
            }
        }
    }
}

/* Public Interface */
void probe_init(EV_P_ int udp_interval, int udp_timeout, int up_count, int down_count, const char *probe_domain) {
    /*
     * Initialize the timer to fire immediately (after=0) upon starting the event loop,
     * and then repeat at the specified interval.
     */
    ev_timer_init(&udp_probe_timer, udp_probe_timer_cb, 0, udp_interval);
    probe_timeout_secs = udp_timeout;

    if (up_count > 0) probe_up_threshold = up_count;
    if (down_count > 0) probe_down_threshold = down_count;

    /* Allocate counters for all possible remotes */
    udp_probe_success_count = ss_malloc(sizeof(int) * MAX_REMOTE_NUM);
    udp_probe_failure_count = ss_malloc(sizeof(int) * MAX_REMOTE_NUM);
    memset(udp_probe_success_count, 0, sizeof(int) * MAX_REMOTE_NUM);
    memset(udp_probe_failure_count, 0, sizeof(int) * MAX_REMOTE_NUM);

    /* Build the DNS probe packet */
    dns_probe_packet = ss_malloc(512);
    dns_probe_packet_len = build_dns_query(probe_domain, dns_probe_packet, 512);
    if (dns_probe_packet_len == 0) {
        LOGE("[probe] failed to build DNS query packet for domain: %s", probe_domain);
        ss_free(dns_probe_packet);
        dns_probe_packet = NULL;
    }
    LOGI("[probe] initialized with domain=%s, interval=%d, timeout=%d, up_threshold=%d, down_threshold=%d", 
        probe_domain, udp_interval, udp_timeout, probe_up_threshold, probe_down_threshold);
}

void probe_add_udp_server(void *server_ptr) {
    server_ctx_t *server = (server_ctx_t *)server_ptr;
    if (udp_server_count < MAX_SERVERS) {
        udp_servers[udp_server_count++] = server;
        if (server->remote_num > 1 && !ev_is_active(&udp_probe_timer)) {
            ev_timer_start(EV_DEFAULT, &udp_probe_timer);
        }
    } else {
        LOGE("[probe] too many udp servers");
    }
}

void probe_cleanup(EV_P) {
    if (ev_is_active(&udp_probe_timer)) {
        ev_timer_stop(EV_A_ &udp_probe_timer);
    }
    ss_free(udp_probe_success_count);
    ss_free(udp_probe_failure_count);
    udp_probe_success_count = NULL;
    udp_probe_failure_count = NULL;
    ss_free(dns_probe_packet);
    dns_probe_packet = NULL;
}