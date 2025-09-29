/*
 * dot.c - DNS-over-TLS client implementation
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
#include <arpa/inet.h>

#include "dot.h"
#include "udprelay.h"
#include "utils.h"
#include "netutils.h"

extern int verbose;

/* DoT states */
#define DOT_STATE_CONNECTING 0
#define DOT_STATE_HANDSHAKE  1
#define DOT_STATE_WRITE      2
#define DOT_STATE_READ       3
#define DOT_STATE_DONE       4

static void dot_io_cb(EV_P_ ev_io *w, int revents);

static void close_and_free_dot(EV_P_ dot_ctx_t *ctx) {
    if (ctx == NULL) return;

    if (verbose) LOGI("[dot] closing connection and freeing context");

    ev_io_stop(EV_A_ &ctx->io);
    ev_timer_stop(EV_A_ &ctx->watcher);

    mbedtls_net_free(&ctx->net_ctx);
    mbedtls_ssl_free(&ctx->ssl);
    mbedtls_ssl_config_free(&ctx->conf);
    mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
    mbedtls_entropy_free(&ctx->entropy);

    if (ctx->request) {
        bfree(ctx->request);
        ss_free(ctx->request);
    }
    if (ctx->response) {
        bfree(ctx->response);
        ss_free(ctx->response);
    }
    ss_free(ctx);
}

static void dot_timeout_cb(EV_P_ ev_timer *watcher, int revents) {
    dot_ctx_t *ctx = cork_container_of(watcher, dot_ctx_t, watcher);
    LOGE("[dot] connection timed out");
    close_and_free_dot(EV_A_ ctx);
}

static void dot_io_cb(EV_P_ ev_io *w, int revents) {
    dot_ctx_t *ctx = (dot_ctx_t *)w;
    int ret;

    if (ctx->state == DOT_STATE_CONNECTING || ctx->state == DOT_STATE_HANDSHAKE) {
        if (verbose) LOGI("[dot] performing TLS handshake");
        ctx->state = DOT_STATE_HANDSHAKE;
        ret = mbedtls_ssl_handshake(&ctx->ssl);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            return; // Handshake not finished, wait for more IO
        }
        if (ret != 0) {
            LOGE("[dot] mbedtls_ssl_handshake failed: -0x%x", -ret);
            goto fail;
        }
        if (verbose) LOGI("[dot] TLS handshake successful");
        ctx->state = DOT_STATE_WRITE;
    }

    if (ctx->state == DOT_STATE_WRITE && (revents & EV_WRITE)) {
        ret = mbedtls_ssl_write(&ctx->ssl, (unsigned char*)ctx->request->data + ctx->request->idx, ctx->request->len - ctx->request->idx);
        if (ret > 0) {
            ctx->request->idx += ret;
            if (ctx->request->idx >= ctx->request->len) {
                if (verbose) LOGI("[dot] sent %zu bytes of DNS query", ctx->request->len);
                ctx->state = DOT_STATE_READ;
                ev_io_stop(EV_A_ w); // Stop watching for write
                ev_io_set(w, w->fd, EV_READ);
                ev_io_start(EV_A_ w);
            }
        } else if (ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != MBEDTLS_ERR_SSL_WANT_READ) {
            LOGE("[dot] mbedtls_ssl_write failed: -0x%x", -ret);
            goto fail;
        }
    }

    if (ctx->state == DOT_STATE_READ && (revents & EV_READ)) {
        ret = mbedtls_ssl_read(&ctx->ssl, (unsigned char*)ctx->response->data + ctx->response->len, ctx->response->capacity - ctx->response->len);
        if (ret > 0) {
            ctx->response->len += ret;
            if (ctx->response->len >= 2) {
                uint16_t resp_len = ntohs(*(uint16_t*)ctx->response->data);
                if (ctx->response->len >= (size_t)(resp_len + 2)) {
                    if (verbose) LOGI("[dot] received %d bytes of DNS response", resp_len);
                    // Send back to client
                    sendto(ctx->server_ctx->fd, ctx->response->data + 2, resp_len, 0, (struct sockaddr*)&ctx->client_addr, ctx->client_addr_len);
                    ctx->state = DOT_STATE_DONE;
                    goto fail; // Use fail to cleanup
                }
            }
        } else if (ret == 0 || (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)) {
            LOGE("[dot] mbedtls_ssl_read failed or connection closed: -0x%x", -ret);
            goto fail;
        }
    }

    return;

fail:
    close_and_free_dot(EV_A_ ctx);
}

void start_dot_session(EV_P_ server_ctx_t *server_ctx, struct sockaddr_storage *client_addr, socklen_t client_addr_len, buffer_t *dns_query) {
    if (server_ctx->dot_server_addr == NULL) {
        LOGE("[dot] DoT server address not configured, dropping DNS query.");
        return;
    }

    if (verbose) LOGI("[dot] starting new DoT session for client %s", get_addr_str((struct sockaddr*)client_addr, true));

    dot_ctx_t *ctx = ss_malloc(sizeof(dot_ctx_t));
    memset(ctx, 0, sizeof(dot_ctx_t));

    ctx->server_ctx = server_ctx;
    ctx->client_addr = *client_addr;
    ctx->client_addr_len = client_addr_len;
    ctx->state = DOT_STATE_CONNECTING;

    // Prepare DNS query for DoT (prepend 2-byte length)
    ctx->request = ss_malloc(sizeof(buffer_t));
    balloc(ctx->request, dns_query->len + 2);
    uint16_t len_be = htons(dns_query->len);
    memcpy(ctx->request->data, &len_be, 2);
    memcpy(ctx->request->data + 2, dns_query->data, dns_query->len);
    ctx->request->len = dns_query->len + 2;

    ctx->response = ss_malloc(sizeof(buffer_t));
    balloc(ctx->response, MAX_UDP_PACKET_SIZE);

    mbedtls_net_init(&ctx->net_ctx);
    mbedtls_ssl_init(&ctx->ssl);
    mbedtls_ssl_config_init(&ctx->conf);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
    mbedtls_entropy_init(&ctx->entropy);

    if (mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy, NULL, 0) != 0) {
        LOGE("[dot] mbedtls_ctr_drbg_seed failed");
        goto fail;
    }

    if (mbedtls_ssl_config_defaults(&ctx->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        LOGE("[dot] mbedtls_ssl_config_defaults failed");
        goto fail;
    }

    // For simplicity, we skip certificate verification.
    // In a production environment, you should load trusted CAs.
    mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&ctx->conf, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);

    if (mbedtls_ssl_setup(&ctx->ssl, &ctx->conf) != 0) {
        LOGE("[dot] mbedtls_ssl_setup failed");
        goto fail;
    }

    if (mbedtls_ssl_set_hostname(&ctx->ssl, server_ctx->dot_server_host) != 0) {
        LOGE("[dot] mbedtls_ssl_set_hostname failed");
        goto fail;
    }

    if (mbedtls_net_connect(&ctx->net_ctx, server_ctx->dot_server_host, server_ctx->dot_server_port, MBEDTLS_NET_PROTO_TCP) != 0) {
        LOGE("[dot] mbedtls_net_connect failed");
        goto fail;
    }

    mbedtls_ssl_set_bio(&ctx->ssl, &ctx->net_ctx, mbedtls_net_send, mbedtls_net_recv, NULL);

    ev_io_init(&ctx->io, dot_io_cb, ctx->net_ctx.fd, EV_READ | EV_WRITE);
    ctx->io.data = ctx;
    ev_io_start(EV_A_ &ctx->io);

    ev_timer_init(&ctx->watcher, dot_timeout_cb, server_ctx->timeout, 0);
    ev_timer_start(EV_A_ &ctx->watcher);

    dot_io_cb(EV_A_ &ctx->io, EV_WRITE); // Start the process
    return;

fail:
    close_and_free_dot(EV_A_ ctx);
}