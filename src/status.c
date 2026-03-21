#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(status, LOG_LEVEL_INF);

#include <stdarg.h>
#include <stdio.h>

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
	if ((size_t)ret > c->rem) {
		LOG_ERR("string of %d bytes doesn't fit into %zu bytes", ret, c->rem);
		return 1;
	}
	c->p += ret;
	c->rem -= ret;
	return 0;
}

static int status_sys_json(struct cursor *c)
{
	return cursor_emit(c,
		" \"sys\": {\n"
			JSON_ENTRY("  ", "version", "\"" VERSION_STRING "\"")
			JSON_ENTRY("  ", "board", "\"" CONFIG_BOARD "\"")
			JSON_ENTRY("  ", "uptime", "%lld")
			JSON_ENTRY_LAST("  ", "reboot_count", "%zu")
		" },\n",
		k_uptime_get() / MSEC_PER_SEC,
		info.reboot_count);
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

	return cursor_emit(c,
		" \"lan\": {\n"
			JSON_ENTRY("  ", "bssid", "\"%s\"")
#if defined(CONFIG_NET_STATISTICS_WIFI)
			JSON_ENTRY("  ", "errors_rx", "%u")
			JSON_ENTRY("  ", "errors_tx", "%u")
#endif
			JSON_ENTRY_LAST("  ", "num_connected", "%zu")
		" },\n",
		mac_str(net_if_get_link_addr(iface)->addr),
#if defined(CONFIG_NET_STATISTICS_WIFI)
		stats.errors.rx,
		stats.errors.tx,
#endif
		info.lan_num_connected);
}

static int status_wan_json(struct cursor *c)
{
	struct net_if *iface = wan_get_iface();
	struct cidr4_addr address = {0};
	struct net_in_addr gateway = {0};
	struct wifi_iface_status status = {0};
	int ret;

	const struct net_if_ipv4 *if_ipv4 = iface->config.ip.ipv4;
	const struct net_if_addr_ipv4 *if_addr_ipv4 = &if_ipv4->unicast[0];
	if (if_addr_ipv4->ipv4.addr_type == NET_ADDR_DHCP && if_addr_ipv4->ipv4.is_used) {
		address.addr = if_addr_ipv4->ipv4.address.net_in_addr;
		address.prefix = 32 - u32_count_leading_zeros(if_addr_ipv4->netmask.s_addr);
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

	return cursor_emit(c,
		" \"wan\": {\n"
			JSON_ENTRY("  ", "bssid", "\"%s\"")
			JSON_ENTRY("  ", "ap_bssid", "\"%s\"")
			JSON_ENTRY("  ", "band", "\"%s\"")
			JSON_ENTRY("  ", "channel", "%u")
			JSON_ENTRY("  ", "link_mode", "\"%s\"")
			JSON_ENTRY("  ", "rssi", "%d")
#if defined(CONFIG_NET_STATISTICS_WIFI)
			JSON_ENTRY("  ", "errors_rx", "%u")
			JSON_ENTRY("  ", "errors_tx", "%u")
#endif
			JSON_ENTRY("  ", "status", "\"%s\"")
			JSON_ENTRY("  ", "address", "\"%s/%u\"")
			JSON_ENTRY_LAST("  ", "gateway", "\"%s\"")
		" },\n",
		mac_str(net_if_get_link_addr(iface)->addr),
		mac_str(status.bssid),
		wifi_band_str(status.band),
		status.channel,
		wifi_link_mode_str(status.link_mode),
		status.rssi,
#if defined(CONFIG_NET_STATISTICS_WIFI)
		stats.errors.rx,
		stats.errors.tx,
#endif
		info.wan_status,
		net_sprint_addr(NET_AF_INET, &address.addr), address.prefix,
		net_sprint_addr(NET_AF_INET, &gateway));
}

static int status_tun_json(struct cursor *c)
{
	struct dtls_stats *stats = dtls_stats();

	return cursor_emit(c,
		" \"tun\": {\n"
			JSON_ENTRY("  ", "rtt", "%zu")
			JSON_ENTRY("  ", "rcvd_orig_bytes", "%zu")
			JSON_ENTRY("  ", "rcvd_bytes", "%zu")
			JSON_ENTRY("  ", "rcvd_packets", "%zu")
			JSON_ENTRY("  ", "sent_orig_bytes", "%zu")
			JSON_ENTRY("  ", "sent_bytes", "%zu")
			JSON_ENTRY("  ", "sent_packets", "%zu")
			JSON_ENTRY("  ", "allocs_failed", "%zu")
			JSON_ENTRY("  ", "pkt_pool_hwm", "%zu")
			JSON_ENTRY("  ", "early_drops", "%zu")
			JSON_ENTRY("  ", "downs", "%zu")
			JSON_ENTRY("  ", "version", "\"%s\"")
			JSON_ENTRY("  ", "curve_name", "\"%s\"")
			JSON_ENTRY_LAST("  ", "cipher_suite", "\"%s\"")
		" }\n",
		stats->rtt_us,
		stats->rcvd_orig_bytes,
		stats->rcvd_bytes,
		stats->rcvd_packets,
		stats->sent_orig_bytes,
		stats->sent_bytes,
		stats->sent_packets,
		stats->allocs_failed,
		stats->pkt_pool_hwm,
		stats->early_drops,
		info.tun_downs,
		str_or(stats->version, ""),
		str_or(stats->curve_name, ""),
		str_or(stats->cipher_suite, ""));
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
