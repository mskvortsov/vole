#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(status, LOG_LEVEL_INF);

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/data/json.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_stats.h>
#include <zephyr/net/wifi.h>
#include <zephyr/sys/sys_heap.h>
#include <zephyr/sys/math_extras.h>

#include "net_private.h"

#include "config.h"
#include "status.h"
#include "dtls.h"
#include "wifi.h"

static K_EVENT_DEFINE(event);
static enum status states[SUBSYS_COUNT];
struct info info;
extern struct k_heap _system_heap;

#define JSON_ENTRY(indent, name, fmt)      indent "\"" name "\": " fmt ",\n"
#define JSON_ENTRY_LAST(indent, name, fmt) indent "\"" name "\": " fmt "\n"

void event_post(enum event ev)
{
	LOG_DBG("%s", event_name(ev));
	k_event_post(&event, ev);
}

uint32_t event_consume(uint32_t events, k_timeout_t timeout)
{
	return k_event_wait_safe(&event, events, false, timeout);
}

void status_set(enum subsys ss, enum status st)
{
	if (states[ss] != st) {
		LOG_DBG("%s:%s", subsys_name(ss), status_name(st));
		states[ss] = st;
	}
}

enum status status_get(enum subsys ss)
{
	return states[ss];
}

static inline const char *str_or(const char *str, const char *fallback)
{
	return str ? str : fallback;
}

struct cursor {
	char *p;
	size_t rem;
};

static int cursor_emit(struct cursor *c, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int ret = vsnprintf(c->p, c->rem, fmt, ap);
	va_end(ap);

	if (ret < 0) {
		LOG_ERR("vsnprintf error (%d)", ret);
		return 1;
	}
	if ((size_t)ret >= c->rem) {
		LOG_ERR("string of %d bytes doesn't fit into %zu bytes", ret, c->rem);
		return 1;
	}
	c->p += ret;
	c->rem -= ret;
	return 0;
}

static int cursor_emit_json_field(struct cursor *c, const char *indent, const char *name,
				  const char *value, bool last)
{
	size_t value_len = strlen(value);
	size_t escaped_len = json_calc_escaped_len(value, value_len);
	char *escaped = k_malloc(escaped_len + 1);
	int ret;

	if (!escaped) {
		LOG_ERR("cannot allocate %zu bytes for json field %s", escaped_len + 1, name);
		return 1;
	}

	memcpy(escaped, value, value_len + 1);
	ret = json_escape(escaped, &value_len, escaped_len + 1);
	if (ret < 0) {
		LOG_ERR("cannot escape json field %s", name);
		k_free(escaped);
		return 1;
	}

	ret = cursor_emit(c, "%s\"%s\": \"%s\"%s\n", indent, name, escaped, last ? "" : ",");
	k_free(escaped);
	return ret;
}

static int status_sys_json(struct cursor *c)
{
	if (cursor_emit(c, " \"sys\": {\n") != 0 ||
	    cursor_emit_json_field(c, "  ", "version", VERSION_STRING, false) != 0 ||
	    cursor_emit_json_field(c, "  ", "board", CONFIG_BOARD, false) != 0 ||
	    cursor_emit(c, "  \"uptime\": %lld,\n", k_uptime_get() / MSEC_PER_SEC) != 0 ||
	    cursor_emit(c, "  \"reboot_count\": %zu\n", info.reboot_count) != 0 ||
	    cursor_emit(c, " },\n") != 0) {
		return 1;
	}

	return 0;
}

static int status_heap_json(struct cursor *c)
{
	struct sys_memory_stats stats = {0};
	int ret;

	ret = sys_heap_runtime_stats_get(&_system_heap.heap, &stats);
	if (ret != 0) {
		LOG_WRN("cannot get heap runtime stats (%d)", ret);
	}

	return cursor_emit(c,
		" \"heap\": {\n"
			JSON_ENTRY("  ", "free", "%zu")
			JSON_ENTRY("  ", "allocated", "%zu")
			JSON_ENTRY_LAST("  ", "max_allocated", "%zu")
		" },\n",
		stats.free_bytes,
		stats.allocated_bytes,
		stats.max_allocated_bytes);
}

static const char *wifi_band_str(enum wifi_frequency_bands band)
{
	switch (band) {
	case WIFI_FREQ_BAND_2_4_GHZ: return "2.4 GHz";
	case WIFI_FREQ_BAND_5_GHZ:   return "5 GHz";
	case WIFI_FREQ_BAND_6_GHZ:   return "6 GHz";
	default:                     return "";
	}
}

static const char *wifi_link_mode_str(enum wifi_link_mode link_mode)
{
	switch (link_mode) {
	case WIFI_0:  return "802.11 (legacy)";
	case WIFI_1:  return "802.11b";
	case WIFI_2:  return "802.11a";
	case WIFI_3:  return "802.11g";
	case WIFI_4:  return "802.11n";
	case WIFI_5:  return "802.11ac";
	case WIFI_6:  return "802.11ax";
	case WIFI_6E: return "802.11ax 6GHz";
	case WIFI_7:  return "802.11be";
	default:      return "";
	}
}

static int status_lan_json(struct cursor *c)
{
	struct net_if *iface = lan_get_iface();
	if (!iface) {
		return 0;
	}

#if defined(CONFIG_NET_STATISTICS_WIFI)
	struct net_stats_wifi stats = {0};
	int ret;
	ret = net_mgmt(NET_REQUEST_STATS_GET_WIFI, iface, &stats,
		       sizeof(struct net_stats_wifi));
	if (ret != 0) {
		LOG_WRN("cannot get lan iface stats (%d)", ret);
	}
#endif

	if (cursor_emit(c, " \"lan\": {\n") != 0 ||
	    cursor_emit_json_field(c, "  ", "bssid", mac_str(net_if_get_link_addr(iface)->addr),
				   false) != 0 ||
#if defined(CONFIG_NET_STATISTICS_WIFI)
	    cursor_emit(c, "  \"errors_rx\": %u,\n", stats.errors.rx) != 0 ||
	    cursor_emit(c, "  \"errors_tx\": %u,\n", stats.errors.tx) != 0 ||
#endif
	    cursor_emit(c, "  \"num_connected\": %zu\n", info.lan_num_connected) != 0 ||
	    cursor_emit(c, " },\n") != 0) {
		return 1;
	}

	return 0;
}

static int status_wan_json(struct cursor *c)
{
	struct net_if *iface = wan_get_iface();
	struct cidr4_addr address = {0};
	struct net_in_addr gateway = {0};
	struct net_sockaddr_in netmask = {
		.sin_family = NET_AF_INET,
	};
	struct wifi_iface_status status = {0};
	char address_buf[NET_IPV4_ADDR_LEN + 4];
	char gateway_buf[NET_IPV4_ADDR_LEN];
	int ret;

	const struct net_if_ipv4 *if_ipv4 = iface->config.ip.ipv4;
	const struct net_if_addr_ipv4 *if_addr_ipv4 = &if_ipv4->unicast[0];
	if (if_addr_ipv4->ipv4.addr_type == NET_ADDR_DHCP && if_addr_ipv4->ipv4.is_used) {
		address.addr = if_addr_ipv4->ipv4.address.net_in_addr;
		netmask.sin_addr = if_addr_ipv4->netmask;
		ret = net_netmask_to_mask_len(NET_AF_INET, (struct net_sockaddr *)&netmask,
					      &address.prefix);
		if (ret != 0) {
			LOG_WRN("cannot derive prefix length from wan netmask (%d)", ret);
			address.prefix = 0;
		}
		gateway = if_ipv4->gw;
	}

	ret = net_mgmt(NET_REQUEST_WIFI_IFACE_STATUS, iface, &status,
		       sizeof(struct wifi_iface_status));
	if (ret != 0) {
		LOG_WRN("cannot get wan iface status (%d)", ret);
	}

#if defined(CONFIG_NET_STATISTICS_WIFI)
	struct net_stats_wifi stats = {0};
	ret = net_mgmt(NET_REQUEST_STATS_GET_WIFI, iface, &stats,
		       sizeof(struct net_stats_wifi));
	if (ret != 0) {
		LOG_WRN("cannot get wan iface stats (%d)", ret);
	}
#endif

	if (cursor_emit(c, " \"wan\": {\n") != 0 ||
	    cursor_emit_json_field(c, "  ", "bssid", mac_str(net_if_get_link_addr(iface)->addr),
				   false) != 0 ||
	    cursor_emit_json_field(c, "  ", "ap_bssid", mac_str(status.bssid), false) != 0 ||
	    cursor_emit_json_field(c, "  ", "band", wifi_band_str(status.band), false) != 0 ||
	    cursor_emit(c, "  \"channel\": %u,\n", status.channel) != 0 ||
	    cursor_emit_json_field(c, "  ", "link_mode", wifi_link_mode_str(status.link_mode),
				   false) != 0 ||
	    cursor_emit(c, "  \"rssi\": %d,\n", status.rssi) != 0 ||
#if defined(CONFIG_NET_STATISTICS_WIFI)
	    cursor_emit(c, "  \"errors_rx\": %u,\n", stats.errors.rx) != 0 ||
	    cursor_emit(c, "  \"errors_tx\": %u,\n", stats.errors.tx) != 0 ||
#endif
	    cursor_emit_json_field(c, "  ", "status", info.wan_status, false) != 0) {
		return 1;
	}

	snprintk(address_buf, sizeof(address_buf), "%s/%u",
		 net_sprint_addr(NET_AF_INET, &address.addr), address.prefix);
	snprintk(gateway_buf, sizeof(gateway_buf), "%s", net_sprint_addr(NET_AF_INET, &gateway));

	if (cursor_emit_json_field(c, "  ", "address", address_buf, false) != 0 ||
	    cursor_emit_json_field(c, "  ", "gateway", gateway_buf, true) != 0 ||
	    cursor_emit(c, " },\n") != 0) {
		return 1;
	}

	return 0;
}

static int status_tun_json(struct cursor *c)
{
	struct dtls_stats *stats;

	if (config.tun.opts.proto == PROTO_WIREGUARD) {
		if (cursor_emit(c, " \"tun\": {\n") != 0 ||
		    cursor_emit(c, "  \"proto\": \"wireguard\",\n") != 0 ||
		    cursor_emit(c, "  \"downs\": %zu\n", info.tun_downs) != 0 ||
		    cursor_emit(c, " }\n") != 0) {
			return 1;
		}
		return 0;
	}

	if (config.tun.opts.proto != PROTO_DTLS) {
		if (cursor_emit(c, " \"tun\": {\n") != 0 ||
		    cursor_emit(c, "  \"proto\": \"unknown\"\n") != 0 ||
		    cursor_emit(c, " }\n") != 0) {
			return 1;
		}
		return 0;
	}

	stats = dtls_stats();
	if (cursor_emit(c, " \"tun\": {\n") != 0 ||
	    cursor_emit(c, "  \"proto\": \"dtls\",\n") != 0 ||
	    cursor_emit(c, "  \"rtt\": %zu,\n", stats->rtt_us) != 0 ||
	    cursor_emit(c, "  \"rcvd_orig_bytes\": %zu,\n", stats->rcvd_orig_bytes) != 0 ||
	    cursor_emit(c, "  \"rcvd_bytes\": %zu,\n", stats->rcvd_bytes) != 0 ||
	    cursor_emit(c, "  \"rcvd_packets\": %zu,\n", stats->rcvd_packets) != 0 ||
	    cursor_emit(c, "  \"sent_orig_bytes\": %zu,\n", stats->sent_orig_bytes) != 0 ||
	    cursor_emit(c, "  \"sent_bytes\": %zu,\n", stats->sent_bytes) != 0 ||
	    cursor_emit(c, "  \"sent_packets\": %zu,\n", stats->sent_packets) != 0 ||
	    cursor_emit(c, "  \"allocs_failed\": %zu,\n", stats->allocs_failed) != 0 ||
	    cursor_emit(c, "  \"pkt_pool_hwm\": %zu,\n", stats->pkt_pool_hwm) != 0 ||
	    cursor_emit(c, "  \"early_drops\": %zu,\n", stats->early_drops) != 0 ||
	    cursor_emit(c, "  \"downs\": %zu,\n", info.tun_downs) != 0 ||
	    cursor_emit_json_field(c, "  ", "version", str_or(stats->version, ""), false) != 0 ||
	    cursor_emit_json_field(c, "  ", "curve_name", str_or(stats->curve_name, ""),
				   false) != 0 ||
	    cursor_emit_json_field(c, "  ", "cipher_suite", str_or(stats->cipher_suite, ""),
				   true) != 0 ||
	    cursor_emit(c, " }\n") != 0) {
		return 1;
	}

	return 0;
}

size_t status_json(char *buf, size_t len)
{
	struct cursor c = {
		.p = buf,
		.rem = len,
	};

	if (cursor_emit(&c, "{\n") != 0 ||
	    status_sys_json(&c) != 0 ||
	    status_heap_json(&c) != 0 ||
	    status_lan_json(&c) != 0 ||
	    status_wan_json(&c) != 0 ||
	    status_tun_json(&c) != 0 ||
	    cursor_emit(&c, "}\n") != 0) {
		return 0;
	}

	return len - c.rem;
}
