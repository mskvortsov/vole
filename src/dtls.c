#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(dtls, CONFIG_DTLS_LOG_LEVEL);

#include <strings.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/base64.h>
#include <zephyr/sys/clock.h>
#include <zephyr/sys/util.h>

#include <zephyr/net/net_core.h>
#include <zephyr/net/ethernet.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/virtual.h>
#include <zephyr/net_buf.h>

#include "ipv4.h"
#include "icmpv4.h"
#include "net_private.h"
#include "udp_internal.h"

#include <wolfssl/ssl.h>

#include "dtls.h"
#include "crypto.h"
#include "npf.h"

#define PKT_ALLOC_TIMEOUT K_MSEC(1)
#define BUF_ALLOC_TIMEOUT K_MSEC(1)

#define DTLS_MTU_MAX                   1458
#define DTLS_MTU_DEFAULT               1420
#define DTLS_CONN_STALE_NUM_KEEPALIVES 3

NET_PKT_SLAB_DEFINE(dtls_pkt_slab, CONFIG_DTLS_PKT_COUNT);

#if defined(CONFIG_NET_BUF_FIXED_DATA_SIZE)
NET_BUF_POOL_FIXED_DEFINE(dtls_buf_pool, CONFIG_DTLS_PKT_COUNT, NET_ETH_MAX_FRAME_SIZE, 0, NULL);
#else
NET_BUF_POOL_VAR_DEFINE(dtls_buf_pool, CONFIG_DTLS_PKT_COUNT,
			CONFIG_DTLS_PKT_COUNT * NET_ETH_MAX_FRAME_SIZE, 0, NULL);
#endif

static const uint8_t *client_id = "default";

static const struct proto protos[] = {
	{ "TLS13-AES128-CCM-8-SHA256", 14 },
	{ "TLS13-CHACHA20-POLY1305-SHA256", 22 },
	{ "TLS13-SHA256-SHA256", 37 },
	{ 0 }
};

struct dtls_context {
	/* Interface which this context belongs to */
	struct net_if *iface;
	/* Underlying interface */
	struct net_if *iface_base;

	/* UDP connection data */
	struct net_sockaddr_in remote_address;
	uint16_t local_port; /* Network byte order */
	struct net_context udp_context;
	struct net_conn_handle *udp_conn_handle;

	/* A sink for egress IPv4 data packets */
	route_fn route;

	/* Flags */
	bool init_done;
	bool status;
	bool connected;

	/* TLS context data */
	const struct proto *proto;
	uint8_t psk[32];
	size_t psk_len;
	WOLFSSL_CTX *ssl_ctx;
	WOLFSSL *ssl;

	/* TLS scratch data */
	uint8_t buf[DTLS_MTU_MAX];
	struct net_pkt *pkt_ingress;
	struct net_pkt *pkt_egress;

	struct k_mutex ssl_lock;

	/* A work item for negotiation stage and keepalives */
	struct k_work_delayable periodic_work;
	size_t keepalive_secs; /* Zero keepalive means no keepalives */
	k_timepoint_t keepalive_expires;
	size_t keepalive_expired_count;
	uint32_t keepalive_cookie;
	uint64_t keepalive_timestamp;

	/* Statistics */
	struct dtls_stats stats;
};

static int dtls_ingress(struct dtls_context *ctx, struct net_pkt *pkt);
static int dtls_egress(struct dtls_context *ctx, struct net_pkt *pkt);
static void dtls_close(struct dtls_context *ctx, bool notify_net_mgmt);

static void __attribute__((unused)) print_net_bufs(struct net_pkt *pkt)
{
	const struct net_buf *buf = pkt->frags;
	printk("frags ");
	while (buf) {
		printk("%u(%zu)%u ", buf->size, net_buf_headroom(buf), buf->len);
		buf = buf->frags;
	}
	printk("\n");
}

static unsigned int psk_client_cb(WOLFSSL *ssl, const char *hint, char *identity,
			unsigned int id_max_len, unsigned char *key, unsigned int key_max_len)
{
	ARG_UNUSED(hint);
	struct dtls_context *ctx = wolfSSL_get_psk_callback_ctx(ssl);

	if (ctx->psk_len > key_max_len) {
		LOG_ERR("key is longer than %u bytes", key_max_len);
		return 0;
	}

	if (strlen(client_id) + 1 > id_max_len) {
		LOG_ERR("identity is longer than %u bytes", id_max_len);
		return 0;
	}

	strncpy(identity, client_id, id_max_len);
	memcpy(key, ctx->psk, ctx->psk_len);

	return ctx->psk_len;
}

static unsigned int psk_client_tls13_cb(WOLFSSL *ssl, const char *hint, char *identity,
			unsigned int id_max_len, unsigned char *key, unsigned int key_max_len,
			const char** ciphersuite)
{
	ARG_UNUSED(hint);
	struct dtls_context *ctx = wolfSSL_get_psk_callback_ctx(ssl);

	unsigned int ret = psk_client_cb(ssl, hint, identity, id_max_len, key, key_max_len);
	if (ret != 0) {
		*ciphersuite = ctx->proto->cipher_suite;
	}

	return ret;
}

/* wolfSSL calls this function to get a packet from a peer. */
static int dtls_recv_cb(WOLFSSL *ssl, char *buf, int max_size, void *p)
{
	ARG_UNUSED(ssl);

	struct dtls_context *ctx = p;
	int ret;

	struct net_pkt *pkt = ctx->pkt_egress;
	if (!pkt) {
		/* Expected during negotiation stage. */
		return WOLFSSL_CBIO_ERR_WANT_READ;
	} else {
		ctx->pkt_egress = NULL;
	}

	/* An egress packet arrives with headers already skipped. */
	size_t size = net_pkt_remaining_data(pkt);
	if (size > (size_t)max_size) {
		LOG_ERR("cannot fit %zu bytes into buffer size %d", size, max_size);
		goto fail;
	}

	ret = net_pkt_read(pkt, buf, size);
	if (ret != 0) {
		LOG_ERR("cannot read %zu bytes from egress packet (%d)", size, ret);
		goto fail;
	}

	net_pkt_unref(pkt);

	return size;

fail:
	if (pkt) {
		net_pkt_unref(pkt);
	}
	return WOLFSSL_CBIO_ERR_GENERAL;
}

/* wolfSSL calls this function to send a packet to a peer. */
static int dtls_send_cb(WOLFSSL *ssl, char *encrypted, int size, void *p)
{
	ARG_UNUSED(ssl);

	int ret;
	struct dtls_context *ctx = p;
	struct net_pkt *pkt = NULL;
	struct net_buf *buf;
	net_time_t rx_timestamp = 0;

	if (ctx->pkt_ingress) {
		rx_timestamp = net_pkt_timestamp_ns(ctx->pkt_ingress);
		net_pkt_unref(ctx->pkt_ingress);
		ctx->pkt_ingress = NULL;
	}

	uint16_t base_mtu = net_if_get_mtu(ctx->iface_base);
	if (NET_IPV4UDPH_LEN + size > base_mtu) {
		LOG_DBG("cannot send %d+%d bytes, mtu is %u",
			NET_IPV4UDPH_LEN, size, base_mtu);
		goto fail;
	}

	LOG_DBG("allocating ingress pkt len %d", size);

	buf = net_buf_alloc_len(&dtls_buf_pool, NET_ETH_MAX_HDR_SIZE + NET_IPV4UDPH_LEN + size,
				BUF_ALLOC_TIMEOUT);
	if (!buf) {
		LOG_DBG("cannot allocate a net_buf for ingress packet size %d", size);
		ctx->stats.allocs_failed += 1;
		/* Tell wolfSSL we have sent the packet, there's no point to retransmit it
		 * when there's no memory left.
		 */
		return size;
	}
	pkt = net_pkt_alloc_from_slab(&dtls_pkt_slab, PKT_ALLOC_TIMEOUT);
	if (!pkt) {
		LOG_DBG("cannot allocate ingress packet, size %d", size);
		ctx->stats.allocs_failed += 1;
		net_buf_unref(buf);
		/* The same resolution as above. */
		return size;
	}

	size_t in_use = CONFIG_DTLS_PKT_COUNT - k_mem_slab_num_free_get(&dtls_pkt_slab);
	if (in_use > ctx->stats.pkt_pool_hwm) {
		ctx->stats.pkt_pool_hwm = in_use;
	}

	net_buf_reserve(buf, NET_ETH_MAX_HDR_SIZE);
	net_pkt_append_buffer(pkt, buf);
	net_pkt_set_iface(pkt, ctx->iface_base);
	net_pkt_set_family(pkt, NET_PF_INET);
	net_pkt_set_timestamp_ns(pkt, rx_timestamp);

	/* RFC 4301 table 5.1.2.1 suggests that the outer TTL needs to be constructed;
	 * let it be the TTL of the base interface. Inner TTL is decremented by the forwarding
	 * logic before entering the tunnel.
	 */
	net_pkt_set_ipv4_ttl(pkt, net_if_ipv4_get_ttl(ctx->iface_base));

	const struct net_in_addr *src =
		net_if_ipv4_select_src_addr(ctx->iface_base, &ctx->remote_address.sin_addr);
	ret = net_ipv4_create(pkt, src, &ctx->remote_address.sin_addr);
	if (ret != 0) {
		LOG_ERR("cannot create ipv4 header (%d)", ret);
		goto fail;
	}

	ret = net_udp_create(pkt, ctx->local_port, ctx->remote_address.sin_port);
	if (ret != 0) {
		LOG_ERR("cannot create udp header (%d)", ret);
		goto fail;
	}

	ret = net_pkt_write(pkt, encrypted, size);
	if (ret != 0) {
		LOG_ERR("cannot write data (%d)", ret);
		goto fail;
	}

	net_pkt_cursor_init(pkt);
	ret = net_ipv4_finalize(pkt, NET_IPPROTO_UDP);
	if (ret != 0) {
		LOG_ERR("cannot finalize ipv4 packet (%d)", ret);
		goto fail;
	}

	net_pkt_set_ll_proto_type(pkt, NET_ETH_PTYPE_IP);
	net_pkt_trim_buffer(pkt);
	net_pkt_cursor_init(pkt);

	// net_pkt_hexdump(pkt, "encapsulated");

	if (net_if_try_send_data(ctx->iface_base, pkt, K_NO_WAIT) == NET_DROP) {
		LOG_ERR("cannot send");
		goto fail;
	}

	ctx->stats.sent_bytes += size;

	return size;

fail:
	LOG_WRN("drop on ingress");
	if (pkt) {
		net_pkt_unref(pkt);
	}

	return WOLFSSL_CBIO_ERR_GENERAL;
}

/* Send an empty UDP packet without payload to port 0. Remote peer is expected to send
 * some reply, for example ICMP "udp port 0 unreachable". TODO make it just an ICMP ping request
 */
static int dtls_send_keepalive(struct dtls_context *ctx)
{
	int ret;
	size_t size;
	struct net_pkt *pkt;

	struct net_in_addr gateway = net_if_ipv4_get_gw(ctx->iface);
	if (net_ipv4_addr_cmp(&gateway, net_ipv4_unspecified_address())) {
		LOG_ERR("cannot get gateway address");
		return 1;
	}
	const struct net_in_addr *src = net_if_ipv4_select_src_addr(ctx->iface, &gateway);
	if (!src) {
		LOG_ERR("cannot get own address");
		return 1;
	}

	pkt = net_pkt_alloc_from_slab(&dtls_pkt_slab, PKT_ALLOC_TIMEOUT);
	if (!pkt) {
		LOG_ERR("cannot allocate keepalive packet");
		ctx->stats.allocs_failed += 1;
		return 1;
	}

	net_pkt_set_family(pkt, NET_PF_INET);

	size = ctx->proto->dtls_overhead + NET_IPV4ICMPH_LEN + 4;
	ret = net_pkt_alloc_buffer_with_reserve(pkt, size, NET_ETH_MAX_HDR_SIZE, NET_IPPROTO_ICMP,
						BUF_ALLOC_TIMEOUT);
	if (ret != 0) {
		LOG_ERR("cannot allocate keepalive buffer (%d)", ret);
		ctx->stats.allocs_failed += 1;
		goto exit;
	}

	net_pkt_set_ipv4_ttl(pkt, 1);

	ret = net_ipv4_create(pkt, src, &gateway);
	if (ret != 0) {
		LOG_ERR("cannot create keepalive ipv4 header (%d)", ret);
		goto exit;
	}

	ret = net_icmpv4_create(pkt, NET_ICMPV4_ECHO_REQUEST, 0);
	if (ret != 0) {
		LOG_ERR("cannot create icmpv4 echo request (%d)", ret);
		goto exit;
	}

	sys_rand_get(&ctx->keepalive_cookie, sizeof(uint32_t));
	ret = net_pkt_write_le32(pkt, ctx->keepalive_cookie);
	if (ret != 0) {
		LOG_ERR("cannot write icmpv4 id/seq (%d)", ret);
		goto exit;
	}

	net_pkt_cursor_init(pkt);
	ret = net_ipv4_finalize(pkt, NET_IPPROTO_ICMP);
	if (ret != 0) {
		LOG_ERR("cannot finalize keepalive packet (%d)", ret);
		goto exit;
	}

	ctx->keepalive_timestamp = k_uptime_ticks();

	net_pkt_cursor_init(pkt);
	return dtls_ingress(ctx, pkt);

exit:
	net_pkt_unref(pkt);
	return ret;
}

static int dtls_recv_keepalive(struct dtls_context *ctx, struct net_pkt *pkt)
{
	struct net_pkt_cursor backup;
	uint32_t keepalive_cookie;
	uint64_t now;
	int ret;

	now = k_uptime_ticks();
	net_pkt_cursor_backup(pkt, &backup);

	ret = net_pkt_skip(pkt, NET_IPV4ICMPH_LEN);
	if (ret != 0) {
		LOG_WRN("cannot skip ipv4/icmpv4 header (%d)", ret);
		net_pkt_cursor_restore(pkt, &backup);
		return ret;
	}

	ret = net_pkt_read_le32(pkt, &keepalive_cookie);
	if (ret != 0) {
		LOG_WRN("cannot read icmpv4 id/seq (%d)", ret);
		net_pkt_cursor_restore(pkt, &backup);
		return ret;
	}

	if (ctx->keepalive_cookie == keepalive_cookie) {
		if (now >= ctx->keepalive_timestamp) {
			ctx->stats.rtt_us = k_ticks_to_us_ceil32(now - ctx->keepalive_timestamp);
		} else {
			LOG_WRN("time machine does exist");
		}
	}

	net_pkt_unref(pkt);
	return 0;
}

static void dtls_input_negotiate(struct dtls_context *ctx, struct net_pkt *pkt)
{
	int current_timeout;
	int ret, err;

	k_mutex_lock(&ctx->ssl_lock, K_FOREVER);

	/* dtls_recv_cb will read the packet */
	ctx->pkt_egress = pkt;

	ret = wolfSSL_negotiate(ctx->ssl);

	if (ctx->pkt_egress) {
		LOG_WRN("tls negotiate hasn't consumed ingress pkt");
		net_pkt_unref(ctx->pkt_egress);
		ctx->pkt_egress = NULL;
	}

	err = wolfSSL_get_error(ctx->ssl, ret);
	current_timeout = wolfSSL_dtls_get_current_timeout(ctx->ssl);

	if (ret == WOLFSSL_SUCCESS) {
		LOG_INF("connection established");
		ctx->connected = true;
		net_if_dormant_off(ctx->iface);

		ctx->stats.version = wolfSSL_get_version(ctx->ssl);
		ctx->stats.curve_name = wolfSSL_get_curve_name(ctx->ssl);
		ctx->stats.cipher_suite = wolfSSL_get_cipher(ctx->ssl);

		k_mutex_unlock(&ctx->ssl_lock);

		if (ctx->keepalive_secs > 0) {
			/* Periodic work was to retransmit, now it's to send keepalives. */
			k_timeout_t timeout = K_SECONDS(ctx->keepalive_secs);
			ctx->keepalive_expired_count = 0;
			ctx->keepalive_expires = sys_timepoint_calc(timeout);
			ret = k_work_reschedule(&ctx->periodic_work, timeout);
			if (ret < 0) {
				LOG_DBG("cannot reschedule periodic work (%d)", ret);
			}
		}

		net_mgmt_event_notify(NET_EVENT_VPN_CONNECTED, ctx->iface);
		return;
	}

	k_mutex_unlock(&ctx->ssl_lock);

	if (ret != WOLFSSL_FATAL_ERROR) {
		LOG_ERR("unexpected return code from tls negotiate %d", ret);
		return;
	}

	if (err == WOLFSSL_ERROR_WANT_READ) {
		LOG_DBG("want read, rescheduling timer to fire in %d seconds", current_timeout);
		ret = k_work_reschedule(&ctx->periodic_work, K_SECONDS(current_timeout));
		if (ret < 0) {
			LOG_DBG("cannot reschedule periodic work (%d)", ret);
		}
	} else {
		LOG_ERR("negotiation failed: %s (%d)", wolfSSL_ERR_error_string(err, NULL), err);
		/* No disconnection notification because there was no connection. */
		dtls_close(ctx, false);

		k_work_cancel_delayable(&ctx->periodic_work);
	}
}

static enum net_verdict random_early_detection(size_t threshold)
{
       size_t free_blocks = k_mem_slab_num_free_get(&dtls_pkt_slab);
       if (free_blocks > threshold) {
               return NET_OK;
       }

       uint32_t r = 8 - 8 * free_blocks / threshold;
       uint32_t p = 1 << r;
       enum net_verdict verdict = sys_rand8_get() < p ? NET_DROP : NET_OK;

       return verdict;
}

static enum net_verdict dtls_input(struct net_conn *conn, struct net_pkt *pkt,
				   union net_ip_header *ip_hdr, union net_proto_header *udp_hdr,
				   void *p)
{
	ARG_UNUSED(conn);
	ARG_UNUSED(ip_hdr);
	ARG_UNUSED(udp_hdr);

	struct dtls_context *ctx = p;
	int ret;

	if (!ctx->connected) {
		LOG_DBG("negotiating");
		dtls_input_negotiate(ctx, pkt);
		return NET_OK;
	}

	if (random_early_detection(CONFIG_DTLS_PKT_COUNT / 4) == NET_DROP) {
		ctx->stats.early_drops += 1;
		return NET_DROP;
	}

	ret = dtls_egress(ctx, pkt);
	if (ret != 0) {
		LOG_DBG("stopping");
		dtls_close(ctx, true);
		k_work_cancel_delayable(&ctx->periodic_work);
	}

	return NET_OK;
}

static void dtls_close(struct dtls_context *ctx, bool notify_net_mgmt)
{
	int ret = 0;

	ctx->connected = false;
	net_if_dormant_on(ctx->iface);

	LOG_DBG("unregistering udp handler");
	ret = net_udp_unregister(ctx->udp_conn_handle);
	if (ret != 0) {
		if (ret == -ENOENT) {
			LOG_DBG("net_udp_unregister: no entry");
		} else {
			LOG_ERR("cannot unregister udp (%d)", ret);
		}
	}

	if (notify_net_mgmt) {
		net_mgmt_event_notify(NET_EVENT_VPN_DISCONNECTED, ctx->iface);
	}

	/* Don't destroy TLS object yet, let it live until interface gets stopped. */
}

static void dtls_periodic(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct dtls_context *ctx = CONTAINER_OF(dwork, struct dtls_context, periodic_work);
	int ret;

	if (!ctx->connected) {
		LOG_DBG("got timeout");
		/* Call TLS to retransmit (or stop trying if max timeout is reached). */
		k_mutex_lock(&ctx->ssl_lock, K_FOREVER);
		ret = wolfSSL_dtls_got_timeout(ctx->ssl);
		int current_timeout = wolfSSL_dtls_get_current_timeout(ctx->ssl);
		k_mutex_unlock(&ctx->ssl_lock);
		if (ret == WOLFSSL_FATAL_ERROR) {
			LOG_WRN("no response from the peer");
			dtls_close(ctx, false);
		} else {
			LOG_DBG("waiting again %d seconds", current_timeout);
			k_work_schedule(dwork, K_SECONDS(current_timeout));
		}
	} else if (ctx->keepalive_secs > 0) {
		if (sys_timepoint_expired(ctx->keepalive_expires)) {
			ctx->keepalive_expired_count += 1;
			if (ctx->keepalive_expired_count == 1) {
				LOG_DBG("keepalive expired");
			} else {
				LOG_DBG("keepalive expired %zu times",
					ctx->keepalive_expired_count);
			}

			if (ctx->keepalive_expired_count > DTLS_CONN_STALE_NUM_KEEPALIVES) {
				LOG_WRN("stale connection");
				k_mutex_lock(&ctx->ssl_lock, K_FOREVER);
				wolfSSL_shutdown(ctx->ssl);
				k_mutex_unlock(&ctx->ssl_lock);
				dtls_close(ctx, true);
				return;
			}

			ret = dtls_send_keepalive(ctx);
			if (ret == 0) {
				LOG_DBG("keepalive sent");
				/* Keepalive packet was sent through dtls_ingress() which calculated
				 * a new ctx->keepalive_expires. */
			} else {
				LOG_DBG("keepalive sending failed");
				ctx->keepalive_expires =
					sys_timepoint_calc(K_SECONDS(ctx->keepalive_secs));
			}
		} else {
			/* A packet was recently sent through the tunnel and dtls_ingress()
			 * reset the keepalive expiration time. */
			LOG_DBG("keepalive hasn't expired yet");
		}

		k_work_schedule(dwork, sys_timepoint_timeout(ctx->keepalive_expires));
	}
}

static int dtls_connect(struct dtls_context *ctx)
{
	int ret, err;

	WOLFSSL *ssl = wolfSSL_new(ctx->ssl_ctx);
	if (!ssl) {
		LOG_ERR("cannot allocate tls object");
		return -ENOMEM;
	}

	wolfSSL_set_psk_callback_ctx(ssl, ctx);
	wolfSSL_SetIOReadCtx(ssl, ctx);
	wolfSSL_SetIOWriteCtx(ssl, ctx);

	struct net_sockaddr local_addr = {
		.sa_family = NET_AF_INET,
	};

	ctx->udp_context.iface = net_if_get_by_iface(ctx->iface_base);
	ctx->udp_context.flags |= NET_CONTEXT_BOUND_TO_IFACE;

	ret = net_udp_register(NET_AF_INET,
			       (struct net_sockaddr *)&ctx->remote_address,
			       &local_addr,
			       net_ntohs(ctx->remote_address.sin_port),
			       net_ntohs(ctx->local_port),
			       &ctx->udp_context,
			       dtls_input,
			       ctx,
			       &ctx->udp_conn_handle);
	if (ret != 0) {
		LOG_ERR("cannot register udp callback (%d)", ret);
		wolfSSL_free(ssl);
		return ret;
	}

	LOG_INF("initiating connection");
	ret = wolfSSL_negotiate(ssl);
	err = wolfSSL_get_error(ssl, ret);

	if (ret != WOLFSSL_FATAL_ERROR || err != WOLFSSL_ERROR_WANT_READ) {
		LOG_ERR("unexpected tls negotiate return code %d %d", ret, err);
		wolfSSL_free(ssl);
		ret = net_udp_unregister(ctx->udp_conn_handle);
		if (ret != 0) {
			LOG_WRN("cannot unregister udp (%d)", ret);
		}
		ctx->udp_conn_handle = NULL;
		return -EINVAL;
	}

	ctx->ssl = ssl;

	int current_timeout = wolfSSL_dtls_get_current_timeout(ssl);

	k_work_init_delayable(&ctx->periodic_work, dtls_periodic);
	k_work_schedule(&ctx->periodic_work, K_SECONDS(current_timeout));

	return 0;
}

/* Tunnel egress path decapsulates an inner IP packet from an outer tunnel packet. */
static int dtls_egress(struct dtls_context *ctx, struct net_pkt *pkt)
{
	NET_PKT_DATA_ACCESS_CONTIGUOUS_DEFINE(ipv4_access, struct net_ipv4_hdr);
	struct net_ipv4_hdr *ip4_hdr;
#if defined(CONFIG_NET_IPV6)
	NET_PKT_DATA_ACCESS_CONTIGUOUS_DEFINE(ipv6_access, struct net_ipv6_hdr);
	struct net_ipv6_hdr *ip6_hdr;
#endif
	struct net_buf *buf;
	net_time_t rx_timestamp;
	int ret, err;

	ctx->stats.rcvd_bytes += net_pkt_get_len(pkt);

	k_mutex_lock(&ctx->ssl_lock, K_FOREVER);

	/* dtls_recv_cb will read the packet */
	ctx->pkt_egress = pkt;
	rx_timestamp = net_pkt_timestamp_ns(pkt);

	ret = wolfSSL_read(ctx->ssl, ctx->buf, net_if_get_mtu(ctx->iface));
	err = wolfSSL_get_error(ctx->ssl, ret);

	if (ctx->pkt_egress) {
		LOG_WRN("tls read hasn't consumed egress pkt");
		net_pkt_unref(ctx->pkt_egress);
		ctx->pkt_egress = NULL;
	}

	k_mutex_unlock(&ctx->ssl_lock);

	if (ret == 0) {
		LOG_WRN("connection closed: %s", wolfSSL_ERR_error_string(err, NULL));
		return 1;
	}
	if (ret == WOLFSSL_FATAL_ERROR) {
		if (err == WOLFSSL_ERROR_WANT_READ) {
			LOG_DBG("tls read wants to read more");
			return 0;
		}
		LOG_ERR("tls read error %d: %s", err, wolfSSL_ERR_error_string(err, NULL));
		net_pkt_unref(pkt);
		return 1;
	}

	size_t size = ret;
	ctx->stats.rcvd_packets += 1;

	if (ctx->keepalive_secs > 0) {
		/* Since keepalives aren't being sent while data is flowing, treat any incoming
		 * (and successfully decrypted) packet as the liveness criterion.
		 */
		ctx->keepalive_expired_count = 0;
	}

	LOG_DBG("allocating egress pkt len %zu", size);

	buf = net_buf_alloc_len(&dtls_buf_pool, NET_ETH_MAX_HDR_SIZE + size, BUF_ALLOC_TIMEOUT);
	if (!buf) {
		LOG_DBG("cannot allocate a net_buf for egress packet size %zu", size);
		ctx->stats.allocs_failed += 1;
		return 0;
	}
	pkt = net_pkt_alloc_from_slab(&dtls_pkt_slab, PKT_ALLOC_TIMEOUT);
	if (!pkt) {
		LOG_DBG("cannot allocate egress packet, size %zu", size);
		ctx->stats.allocs_failed += 1;
		net_buf_unref(buf);
		return 0;
	}

	size_t in_use = CONFIG_DTLS_PKT_COUNT - k_mem_slab_num_free_get(&dtls_pkt_slab);
	if (in_use > ctx->stats.pkt_pool_hwm) {
		ctx->stats.pkt_pool_hwm = in_use;
	}

	net_buf_reserve(buf, NET_ETH_MAX_HDR_SIZE);
	net_pkt_append_buffer(pkt, buf);

	ret = net_pkt_write(pkt, ctx->buf, size);
	if (ret != 0) {
		LOG_ERR("cannot write into packet (%d)", ret);
		net_pkt_unref(pkt);
		return 0;
	}

	net_pkt_set_timestamp_ns(pkt, rx_timestamp);
	net_pkt_set_l2_processed(pkt, true);
	net_pkt_set_iface(pkt, ctx->iface);
	net_pkt_set_overwrite(pkt, true);

	ctx->stats.rcvd_orig_bytes += size;

	uint8_t version = (ctx->buf[0] >> 4) & 0x0f;
	if (version == 4) {
		net_pkt_cursor_init(pkt);
		ip4_hdr = net_pkt_get_data(pkt, &ipv4_access);
		if (!ip4_hdr) {
			LOG_ERR("cannot get ipv4 header");
			net_pkt_unref(pkt);
			return 0;
		}

		if (ctx->keepalive_secs > 0) {
			if (ip4_hdr->proto == NET_IPPROTO_ICMP && size == NET_IPV4ICMPH_LEN + 4) {
				ret = dtls_recv_keepalive(ctx, pkt);
				if (ret == 0) {
					return 0;
				}
			}
		}

		/* Decrement inner TTL according to RFC 2003. */
		if (ip4_hdr->ttl == 0) {
			LOG_WRN("drop ipv4 due to zero ttl");
			net_pkt_unref(pkt);
			return 0;
		}
		ip4_hdr->ttl -= 1;
		/* Update the checksum incrementally as described in RFC 1624. */
		ip4_hdr->chksum = ipv4_chksum_ttl_dec(ip4_hdr->chksum);
		ret = net_pkt_set_data(pkt, &ipv4_access);
		if (ret != 0) {
			LOG_ERR("cannot set ipv4 header (%d)", ret);
			net_pkt_unref(pkt);
			return 0;
		}

		net_pkt_set_ll_proto_type(pkt, NET_ETH_PTYPE_IP);
		net_pkt_set_family(pkt, NET_PF_INET);

		net_pkt_cursor_init(pkt);
		if (ctx->route(pkt, ip4_hdr) != 0) {
			net_pkt_unref(pkt);
		}
#if defined(CONFIG_NET_IPV6)
	} else if (version == 6) {
		net_pkt_cursor_init(pkt);
		ip6_hdr = net_pkt_get_data(pkt, &ipv6_access);
		if (!ip6_hdr) {
			LOG_ERR("cannot get ipv6 header");
			net_pkt_unref(pkt);
			return 0;
		}

		if (ip6_hdr->hop_limit == 0) {
			/* TODO RFC 4443 §3.3 requires sending ICMPv6 Time Exceeded
			 * back to the source. */
			LOG_WRN("drop ipv6 due to zero hop limit");
			net_pkt_unref(pkt);
			return 0;
		}
		ip6_hdr->hop_limit -= 1;

		ret = net_pkt_set_data(pkt, &ipv6_access);
		if (ret != 0) {
			LOG_ERR("cannot set ipv6 header (%d)", ret);
			net_pkt_unref(pkt);
			return 0;
		}

		net_pkt_set_ll_proto_type(pkt, NET_ETH_PTYPE_IPV6);
		net_pkt_set_family(pkt, NET_PF_INET6);

		net_pkt_cursor_init(pkt);
		if (net_recv_data(ctx->iface, pkt) < 0) {
			net_pkt_unref(pkt);
		}
#endif
	} else {
#if defined(CONFIG_NET_IPV6)
		LOG_WRN("unknown inner packet version %u, dropping", version);
#endif
		net_pkt_unref(pkt);
	}

	return 0;
}

/* Tunnel ingress path encapsulates an inner IP packet into an outer tunnel packet
 * with the structure: IP_outer | UDP | DTLS | < IP_inner | payload >_encrypted
 */
static int dtls_ingress(struct dtls_context *ctx, struct net_pkt *pkt)
{
	int ret, err;

	size_t len = net_pkt_get_len(pkt);
	ret = net_pkt_read(pkt, ctx->buf, len);
	if (ret != 0) {
		LOG_ERR("drop on ingress: cannot read %zu bytes (%d)", len, ret);
		net_pkt_unref(pkt);
		return 0;
	}

	k_mutex_lock(&ctx->ssl_lock, K_FOREVER);

	/* Do not unref the packet yet, let dtls_send_cb() copy RX timestamp
	 * to a newly allocated one. */
	ctx->pkt_ingress = pkt;

	ret = wolfSSL_write(ctx->ssl, ctx->buf, len);
	err = wolfSSL_get_error(ctx->ssl, ret);

	k_mutex_unlock(&ctx->ssl_lock);

	if (ctx->pkt_ingress) {
		LOG_WRN("tls write hasn't consumed ingress pkt");
		net_pkt_unref(ctx->pkt_ingress);
		ctx->pkt_ingress = NULL;
	}
	if (ret == 0) {
		LOG_WRN("connection closed: %s", wolfSSL_ERR_error_string(err, NULL));
		return 1;
	}
	if (ret == WOLFSSL_FATAL_ERROR) {
		LOG_ERR("tls write error %d: %s", err, wolfSSL_ERR_error_string(err, NULL));
		return 1;
	}

	if (ret < 0) {
		LOG_ERR("unexpected tls write return code %d", ret);
		return 1;
	}

	if ((size_t)ret != len) {
		LOG_WRN("tls partial write %d/%zu", ret, len);
	}

	ctx->stats.sent_packets += 1;
	ctx->stats.sent_orig_bytes += ret;

	if (ctx->keepalive_secs > 0) {
		ctx->keepalive_expires = sys_timepoint_calc(K_SECONDS(ctx->keepalive_secs));
	}

	return 0;
}

static int dtls_init(struct dtls_context *ctx)
{
	WOLFSSL_METHOD *method = NULL;
	WOLFSSL_CTX *ssl_ctx = NULL;
	int ret;

	/* wolfSSL_Init() has been called by this point. */

	method = wolfDTLSv1_3_client_method();
	if (!method) {
		LOG_ERR("cannot create tls method");
		return -ENOMEM;
	}

	ssl_ctx = wolfSSL_CTX_new(method);
	if (!ssl_ctx) {
		LOG_ERR("cannot create tls context");
		return -ENOMEM;
	}

	ret = wolfSSL_CTX_SetDevId(ssl_ctx, ZEPHYR_DEVID);
	if (ret != WOLFSSL_SUCCESS) {
		LOG_ERR("cannot set crypto device (%d)", ret);
		wolfSSL_CTX_free(ssl_ctx);
		return -EINVAL;
	}

	wolfSSL_CTX_set_psk_client_tls13_callback(ssl_ctx, psk_client_tls13_cb);

	ret = wolfSSL_CTX_set_cipher_list(ssl_ctx, ctx->proto->cipher_suite);
	if (ret != WOLFSSL_SUCCESS) {
		LOG_ERR("cannot set cipher list (%d)", ret);
		wolfSSL_CTX_free(ssl_ctx);
		return -EINVAL;
	}

	ret = wolfSSL_CTX_only_dhe_psk(ssl_ctx);
	if (ret != 0) {
		LOG_ERR("cannot force dhe-only psk auth (%d)", ret);
		wolfSSL_CTX_free(ssl_ctx);
		return -EINVAL;
	}

	int groups[] = { WOLFSSL_ECC_X25519 };
	ret = wolfSSL_CTX_set_groups(ssl_ctx, groups, ARRAY_SIZE(groups));
	if (ret != WOLFSSL_SUCCESS) {
		LOG_ERR("cannot set key exchange groups (%d)", ret);
		wolfSSL_CTX_free(ssl_ctx);
		return -EINVAL;
	}

	wolfSSL_CTX_SetIORecv(ssl_ctx, dtls_recv_cb);
	wolfSSL_CTX_SetIOSend(ssl_ctx, dtls_send_cb);

	ctx->ssl_ctx = ssl_ctx;
	return 0;
}

static void iface_init(struct net_if *iface)
{
	struct dtls_context *ctx = net_if_get_device(iface)->data;

	if (ctx->init_done) {
		return;
	}

	ctx->iface = iface;

	net_if_flag_set(iface, NET_IF_NO_AUTO_START);
	net_if_flag_set(iface, NET_IF_POINTOPOINT);
	net_if_set_name(iface, "dtls0");

	net_virtual_set_name(iface, "DTLS Tunnel");
	net_virtual_set_flags(iface, NET_L2_POINT_TO_POINT);

	ctx->init_done = true;
}

static enum virtual_interface_caps get_capabilities(struct net_if *iface)
{
	ARG_UNUSED(iface);

	return VIRTUAL_INTERFACE_VPN;
}

static int interface_start(const struct device *dev)
{
	struct dtls_context *ctx = dev->data;
	int ret;

	if (ctx->status) {
		return -EALREADY;
	}

	LOG_DBG("starting iface %d", net_if_get_by_iface(ctx->iface));

	ctx->keepalive_expired_count = 0;
	ctx->connected = false;
	net_if_dormant_on(ctx->iface);

	ret = k_mutex_init(&ctx->ssl_lock);
	if (ret != 0) {
		LOG_ERR("cannot initialize tls mutex");
		return ret;
	}

	ret = dtls_init(ctx);
	if (ret != 0) {
		return ret;
	}

	memset(&ctx->stats, 0, sizeof(struct dtls_stats));

	ret = dtls_connect(ctx);
	if (ret != 0) {
		wolfSSL_CTX_free(ctx->ssl_ctx);
		ctx->ssl_ctx = NULL;
		ctx->ssl = NULL;
		return ret;
	}

	ctx->status = true;

	return 0;
}

static int interface_stop(const struct device *dev)
{
	struct dtls_context *ctx = dev->data;

	if (!ctx->status) {
		return -EALREADY;
	}

	LOG_DBG("stopping iface %d", net_if_get_by_iface(ctx->iface));

	if (ctx->connected) {
		/* Send a "close notify" alert to the peer. */
		wolfSSL_shutdown(ctx->ssl);
	} else {
		LOG_DBG("not connected");
	}

	/* No disconnection notification because stop is requested externally. */
	dtls_close(ctx, false);

	struct k_work_sync sync;
	k_work_cancel_delayable_sync(&ctx->periodic_work, &sync);

	wolfSSL_free(ctx->ssl);
	wolfSSL_CTX_free(ctx->ssl_ctx);

	LOG_DBG("stopped");

	ctx->status = false;

	return 0;
}

static int interface_send(struct net_if *iface, struct net_pkt *pkt)
{
	struct dtls_context *ctx = net_if_get_device(iface)->data;

	if (!ctx->iface_base) {
		return -ENOENT;
	}

	if (!ctx->connected) {
		return -ENOTCONN;
	}

	if (net_pkt_family(pkt) != NET_AF_INET &&
	    (!IS_ENABLED(CONFIG_NET_IPV6) || net_pkt_family(pkt) != NET_AF_INET6)) {
		LOG_ERR("unsupported packet family %d", net_pkt_family(pkt));
		return -ENOTSUP;
	}

	size_t len = net_pkt_get_len(pkt);
	if (len > net_if_get_mtu(ctx->iface)) {
		LOG_ERR("interface_send: pkt len %zu > mtu %u", len, net_if_get_mtu(ctx->iface));
		return -EINVAL;
	}

#if defined(CONFIG_NET_IPV6)
	if (net_pkt_family(pkt) == NET_AF_INET6) {
		NET_PKT_DATA_ACCESS_DEFINE(ipv6_access, struct net_ipv6_hdr);
		struct net_ipv6_hdr *ip6_hdr = net_pkt_get_data(pkt, &ipv6_access);

		if (ip6_hdr && ip6_hdr->nexthdr == NET_IPPROTO_TCP &&
		    net_pkt_skip(pkt, sizeof(struct net_ipv6_hdr)) == 0) {
			clamp_mss(pkt, net_if_get_mtu(iface) -
				  (sizeof(struct net_ipv6_hdr) + sizeof(struct net_tcp_hdr)));
		}
		net_pkt_cursor_init(pkt);
	}
#endif

	if (dtls_ingress(ctx, pkt) != 0) {
		LOG_ERR("ingress error");
		dtls_close(ctx, true);
		return -ENOTCONN;
	}

	return 0;
}

static int interface_attach(struct net_if *iface, struct net_if *iface_base)
{
	if (net_if_get_by_iface(iface) < 0) {
		return -ENOENT;
	}

	struct dtls_context *ctx = net_if_get_device(iface)->data;
	ctx->iface_base = iface_base;

	return 0;
}

/* A workaround for a definition at wolfssl/wolfssl/wolfcrypt/settings.h:2671 */
#undef send

static const struct virtual_interface_api dtls_iface_api = {
	.iface_api.init = iface_init,

	.get_capabilities = get_capabilities,
	.start = interface_start,
	.stop = interface_stop,
	.send = interface_send,
	.attach = interface_attach,
};

static struct dtls_context dtls_context_data;

static void init_context_iface(void);

static int virt_dev_init(const struct device *dev)
{
	ARG_UNUSED(dev);
	init_context_iface();
	return 0;
}

NET_VIRTUAL_INTERFACE_INIT_INSTANCE(dtls,
	"dtls",
	0,
	virt_dev_init,
	NULL,
	&dtls_context_data,
	NULL,
	CONFIG_KERNEL_INIT_PRIORITY_DEFAULT,
	&dtls_iface_api,
	DTLS_MTU_MAX)

static void init_context_iface(void)
{
	static bool init_done = false;
	if (!init_done) {
		init_done = true;
		dtls_context_data.iface = NET_IF_GET(dtls, 0);
	}
}

const struct proto *find_cipher_suite(const char *cipher_suite)
{
	ARRAY_FOR_EACH_PTR(protos, proto) {
		if (strcasecmp(proto->cipher_suite, cipher_suite) == 0) {
			return proto;
		}
	}
	return NULL;
}

int dtls_set_config(struct net_if *iface, const struct dtls_interface_config *config)
{
	int ret;
	struct dtls_context *ctx = net_if_get_device(iface)->data;

	ctx->proto = find_cipher_suite(config->cipher_suite);
	if (!ctx->proto) {
		LOG_DBG("cannot find cipher suite %s", config->cipher_suite);
		return -EINVAL;
	}

	ctx->remote_address = config->remote_address;
	ctx->local_port = net_htons(config->local_port);
	ctx->psk_len = sizeof(ctx->psk);

	ret = base64_decode(ctx->psk, sizeof(ctx->psk), &ctx->psk_len, config->psk_base64,
			    strlen(config->psk_base64));
	if (ret != 0) {
		LOG_DBG("cannot decode psk (%d)", ret);
		return -EINVAL;
	}

	ctx->keepalive_secs = config->keepalive_secs;

	ctx->route = config->route;

	if (NET_IPV4_MTU <= config->mtu && config->mtu <= DTLS_MTU_MAX) {
		net_if_set_mtu(iface, config->mtu);
	} else {
		LOG_WRN("using default MTU %u", DTLS_MTU_DEFAULT);
		net_if_set_mtu(iface, DTLS_MTU_DEFAULT);
	}

	return 0;
}

struct dtls_stats *dtls_stats(void)
{
	struct net_if *iface = NET_IF_GET(dtls, 0);
	struct dtls_context *ctx = net_if_get_device(iface)->data;
	return &ctx->stats;
}
