#include <stdint.h>
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(telemetry, LOG_LEVEL_INF);

#include <zephyr/kernel.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/ethernet.h>
#include <zephyr/net/sntp.h>
#include <zephyr/shell/shell.h>

#include "net_private.h"
#include "ipv4.h"
#include "udp_internal.h"

#include "aqm.h"
#include "dtls.h"
#include "wifi.h"

/* Parser is at telemetry/telegraf/parser.py */
struct telemetry_header {
	uint8_t tag;
	int64_t timestamp_ms;
} __attribute__((packed));

struct telemetry_basic {
	uint32_t allocs_failed;
	uint32_t early_drops;
	uint32_t heap_used;
	uint32_t tx_backlog;
	uint32_t codel_drop_count;
	uint32_t codel_drop_len;
} __attribute__((packed));

struct telemetry_sojourn_hist {
	uint16_t lan[SOJOURN_HIST_SIZE];
	uint16_t wan[SOJOURN_HIST_SIZE];
} __attribute__((packed));

struct telemetry {
	struct telemetry_header h;
	union {
		struct telemetry_basic basic;
		struct telemetry_sojourn_hist sojourn_hist;
	} u;
} __attribute__((packed));

#define TELEMETRY_TAG_BASIC    1
#define TELEMETRY_TAG_SOJOURN  2
#define TELEMETRY_PERIOD       K_MSEC(40)
#define TELEMETRY_SOJOURN_DIV  25
#define TELEMETRY_PORT         58761
#define TELEMETRY_PKT_SIZE     (NET_ETH_MAX_HDR_SIZE + NET_IPV4UDPH_LEN + sizeof(struct telemetry))
#define TELEMETRY_PKT_COUNT    2
#define TELEMETRY_SNTP_SERVER  "195.186.1.101" /* from europe.pool.ntp.org */
#define TELEMETRY_SNTP_PORT    123
#define TELEMETRY_SNTP_TIMEOUT 1000

NET_PKT_SLAB_DEFINE(telemetry_pkt_slab, TELEMETRY_PKT_COUNT);
NET_BUF_POOL_FIXED_DEFINE(telemetry_buf_pool, TELEMETRY_PKT_COUNT, TELEMETRY_PKT_SIZE, 0, NULL);

static bool telemetry_running;
static size_t telemetry_counter;
static int64_t telemetry_timestamp_offset;
static struct net_if *telemetry_iface;
static struct net_sockaddr_in telemetry_src = {
	.sin_family = AF_INET,
	.sin_port = net_htons(TELEMETRY_PORT),
};
static struct net_sockaddr_in telemetry_dst = {
	.sin_family = AF_INET,
	.sin_port = net_htons(TELEMETRY_PORT),
};

extern struct k_heap _system_heap;

static size_t telemetry_basic_collect(struct telemetry *telemetry)
{
	struct dtls_stats *tun_stats;
	struct sys_memory_stats heap_stats = {0};
	struct aqm_stats aqm_stats = {0};
	int ret;

	telemetry->h.tag = TELEMETRY_TAG_BASIC;

	tun_stats = dtls_stats();
	telemetry->u.basic.allocs_failed = tun_stats->allocs_failed;
	telemetry->u.basic.early_drops = tun_stats->early_drops;

	ret = sys_heap_runtime_stats_get(&_system_heap.heap, &heap_stats);
	if (ret != 0) {
		LOG_WRN("cannot get heap runtime stats (%d)", ret);
	}
	telemetry->u.basic.heap_used = heap_stats.allocated_bytes;

	aqm_stats_get(&aqm_stats);
	telemetry->u.basic.tx_backlog = aqm_stats.backlog; /* FIXME skips peaks */
	telemetry->u.basic.codel_drop_count = aqm_stats.codel_stats->drop_count;
	telemetry->u.basic.codel_drop_len = aqm_stats.codel_stats->drop_len;

	return sizeof(struct telemetry_header) + sizeof(struct telemetry_basic);
}

static size_t telemetry_sojourn_collect(struct telemetry *telemetry)
{
	atomic_t *hist_lan = sojourn_hist_get(lan_get_iface());
	atomic_t *hist_wan = sojourn_hist_get(wan_get_iface());

	telemetry->h.tag = TELEMETRY_TAG_SOJOURN;

	for (size_t i = 0; i < SOJOURN_HIST_SIZE; ++i) {
		telemetry->u.sojourn_hist.lan[i] = hist_lan ? atomic_get(&hist_lan[i]) : 0;
		telemetry->u.sojourn_hist.wan[i] = hist_wan ? atomic_get(&hist_wan[i]) : 0;
	}

	return sizeof(struct telemetry_header) + sizeof(struct telemetry_sojourn_hist);
}

static void telemetry_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);

	struct net_buf *buf;
	struct net_pkt *pkt;
	struct telemetry telemetry = {
		.h.timestamp_ms = telemetry_timestamp_offset + k_uptime_get(),
	};
	size_t size;
	int ret;

	buf = net_buf_alloc_len(&telemetry_buf_pool, TELEMETRY_PKT_SIZE, K_NO_WAIT);
	if (!buf) {
		LOG_DBG("cannot allocate telemetry buf");
		return;
	}
	pkt = net_pkt_alloc_from_slab(&telemetry_pkt_slab, K_NO_WAIT);
	if (!pkt) {
		LOG_DBG("cannot allocate telemetry packet");
		net_buf_unref(buf);
		return;
	}

	net_buf_reserve(buf, NET_ETH_MAX_HDR_SIZE);
	net_pkt_append_buffer(pkt, buf);

	net_pkt_set_l2_processed(pkt, true);
	net_pkt_set_ll_proto_type(pkt, NET_ETH_PTYPE_IP);
	net_pkt_set_family(pkt, NET_PF_INET);
	net_pkt_set_iface(pkt, telemetry_iface);

	ret = net_ipv4_create(pkt, &telemetry_src.sin_addr, &telemetry_dst.sin_addr);
	if (ret != 0) {
		LOG_ERR("cannot create ipv4 header (%d)", ret);
		net_pkt_unref(pkt);
		return;
	}

	ret = net_udp_create(pkt, telemetry_src.sin_port, telemetry_dst.sin_port);
	if (ret != 0) {
		LOG_ERR("cannot create udp header (%d)", ret);
		net_pkt_unref(pkt);
		return;
	}

	telemetry_counter += 1;
	if (telemetry_counter != TELEMETRY_SOJOURN_DIV) {
		size = telemetry_basic_collect(&telemetry);
	} else {
		telemetry_counter = 0;
		size = telemetry_sojourn_collect(&telemetry);
		sojourn_hist_reset();
	}

	ret = net_pkt_write(pkt, &telemetry, size);
	if (ret != 0) {
		LOG_ERR("cannot write into telemetry packet (%d)", ret);
		net_pkt_unref(pkt);
		return;
	}

	net_pkt_cursor_init(pkt);
	ret = net_ipv4_finalize(pkt, NET_IPPROTO_UDP);
	if (ret != 0) {
		LOG_ERR("cannot finalize ipv4 packet (%d)", ret);
		net_pkt_unref(pkt);
		return;
	}

	net_pkt_cursor_init(pkt);
	if (net_if_try_send_data(telemetry_iface, pkt, K_NO_WAIT) == NET_DROP) {
		LOG_ERR("cannot send telemetry packet");
		net_pkt_unref(pkt);
	}
}

static K_WORK_DEFINE(telemetry_work, telemetry_work_handler);

static void telemetry_timer_handler(struct k_timer *timer)
{
	ARG_UNUSED(timer);
	k_work_submit(&telemetry_work);
}

static K_TIMER_DEFINE(telemetry_timer, telemetry_timer_handler, NULL);

static int64_t sntp_time(void)
{
	struct sntp_ctx ctx = {0};
	struct sntp_time ts;
	struct net_sockaddr_in sntp_addr = {
		.sin_family = AF_INET,
		.sin_port = net_htons(TELEMETRY_SNTP_PORT),
	};
	struct net_in_addr *src;
	struct net_sockaddr_in local_addr = {
		.sin_family = AF_INET,
		.sin_port = 0,
	};
	int ret;

	ret = net_addr_pton(AF_INET, TELEMETRY_SNTP_SERVER, &sntp_addr.sin_addr);
	if (ret != 0) {
		return ret;
	}

	src = net_if_ipv4_get_global_addr(wan_get_iface(), NET_ADDR_PREFERRED);
	if (!src) {
		return -EINVAL;
	}
	memcpy(&local_addr.sin_addr, src, sizeof(struct net_in_addr));

	ctx.sock.fd = zsock_socket(AF_INET, NET_SOCK_DGRAM, IPPROTO_UDP);
	if (ctx.sock.fd < 0) {
		return -errno;
	}

	ret = zsock_bind(ctx.sock.fd, (struct net_sockaddr *)&local_addr,
			 sizeof(struct net_sockaddr_in));
	if (ret < 0) {
		zsock_close(ctx.sock.fd);
		return -errno;
	}

	ret = zsock_connect(ctx.sock.fd, (struct net_sockaddr *)&sntp_addr,
			    sizeof(struct net_sockaddr_in));
	if (ret < 0) {
		zsock_close(ctx.sock.fd);
		return -errno;
	}

	ctx.sock.fds[0].fd = ctx.sock.fd;
	ctx.sock.fds[0].events = ZSOCK_POLLIN;
	ctx.sock.nfds = 1;

	ret = sntp_query(&ctx, TELEMETRY_SNTP_TIMEOUT, &ts);
	sntp_close(&ctx);
	if (ret != 0) {
		return ret;
	}

	return ts.seconds * MSEC_PER_SEC + (((uint64_t)ts.fraction * MSEC_PER_SEC) >> 32);
}

static void print_timestamp_offset_iso8601(const struct shell *sh)
{
	struct tm time;
	time_t seconds;
	char buf[32];
	uint32_t fraction_ms;

	seconds = telemetry_timestamp_offset / MSEC_PER_SEC;
	gmtime_r(&seconds, &time);
	fraction_ms = telemetry_timestamp_offset % MSEC_PER_SEC;
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &time);

	shell_print(sh, "timestamp offset %s.%03uZ", buf, fraction_ms);
}

static int cmd_telemetry_start(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	struct net_in_addr *src;
	int ret;

	if (telemetry_running) {
		shell_warn(sh, "already running");
		return 0;
	}

	ret = net_addr_pton(AF_INET, argv[1], &telemetry_dst.sin_addr);
	if (ret != 0) {
		shell_error(sh, "cannot parse target address");
		return ret;
	}

	telemetry_iface = net_if_ipv4_select_src_iface(&telemetry_dst.sin_addr);
	if (!telemetry_iface) {
		shell_error(sh, "cannot select interface");
		return -EINVAL;
	}

	src = net_if_ipv4_get_global_addr(telemetry_iface, NET_ADDR_PREFERRED);
	if (!src) {
		shell_error(sh, "cannot get interface address");
		return -EINVAL;
	}
	memcpy(&telemetry_src.sin_addr, src, sizeof(struct net_in_addr));

	if (argc == 3) {
		int err = 0;
		time_t seconds = shell_strtol(argv[2], 10, &err);
		if (err != 0) {
			shell_error(sh, "cannot parse the argument (%d)", err);
			return -EINVAL;
		}
		telemetry_timestamp_offset = seconds * MSEC_PER_SEC - k_uptime_get();
	} else {
		int64_t res = sntp_time();
		if (res < 0) {
			shell_error(sh, "cannot get sntp time from %s (%lld)",
				    TELEMETRY_SNTP_SERVER, res);
			shell_print(sh, "supply an additional seconds argument (unix time)");
			return -EINVAL;
		}
		telemetry_timestamp_offset = res - k_uptime_get();
	}

	print_timestamp_offset_iso8601(sh);

	k_timer_start(&telemetry_timer, K_NO_WAIT, TELEMETRY_PERIOD);

	shell_print(sh, "sending telemetry to udp %s:%d",
		    net_sprint_addr(telemetry_dst.sin_family, &telemetry_dst.sin_addr),
		    net_ntohs(telemetry_dst.sin_port));

	telemetry_running = true;

	return 0;
}

static int cmd_telemetry_stop(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	if (!telemetry_running) {
		shell_warn(sh, "not running");
		return 0;
	}

	k_timer_stop(&telemetry_timer);

	shell_print(sh, "stopped sending");

	telemetry_running = false;

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_telemetry,
	SHELL_CMD_ARG(start, NULL, "Start telemetry.", cmd_telemetry_start, 2, 1),
	SHELL_CMD_ARG(stop,  NULL, "Stop telemetry.",  cmd_telemetry_stop,  1, 0),
	SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(telemetry, &sub_telemetry, "Telemetry commands", NULL);
