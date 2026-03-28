#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(wifi, LOG_LEVEL_INF);

#include <zephyr/init.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/drivers/gpio.h>

#include "net_private.h"

#include "config.h"
#include "status.h"

#if defined(CONFIG_NET_IPV6)
#include "ipv6.h"
#include "nbr.h"
#include "ra.h"

#define IPV6_NAT64_PREFIX "64:ff9b::"
#endif

#define WAN_CONNECT_TIMEOUT    K_SECONDS(15)
#define WAN_BOUND_TIMEOUT      K_SECONDS(15)
#define WAN_DISCONNECT_TIMEOUT K_SECONDS(5)
#define LAN_ENABLE_TIMEOUT     K_SECONDS(5)
#define LAN_DISABLE_TIMEOUT    K_SECONDS(5)

#define NET_EVENT_WIFI_MASK                                                                        \
	NET_EVENT_WIFI_CONNECT_RESULT | NET_EVENT_WIFI_DISCONNECT_RESULT |                         \
		NET_EVENT_WIFI_AP_ENABLE_RESULT | NET_EVENT_WIFI_AP_DISABLE_RESULT |               \
		NET_EVENT_WIFI_AP_STA_CONNECTED | NET_EVENT_WIFI_AP_STA_DISCONNECTED

static struct net_if *iface_lan;
static struct net_if *iface_wan;

#if defined(CONFIG_NET_IPV6)
static struct net_if_addr *lan_if_addr6;
static struct net_if_ipv6_prefix *lan_if_prefix6;
#endif

static struct net_mgmt_event_callback net_mgmt_cb;
static struct net_mgmt_event_callback wifi_mgmt_cb;

struct net_if *lan_get_iface(void)
{
	return iface_lan;
}

struct net_if *wan_get_iface(void)
{
	return iface_wan;
}

static const char *wifi_conn_status_msg(enum wifi_conn_status status)
{
	switch (status) {
	case WIFI_STATUS_CONN_SUCCESS:        return "connected";
	case WIFI_STATUS_CONN_FAIL:           return "connection failed";
	case WIFI_STATUS_CONN_WRONG_PASSWORD: return "wrong password";
	case WIFI_STATUS_CONN_TIMEOUT:        return "connection timeout";
	case WIFI_STATUS_CONN_AP_NOT_FOUND:   return "ap not found";
	default:                              return "";
	}
}

const char *mac_str(const uint8_t *mac)
{
#define NBUFS 2
	static char buf[NBUFS][WIFI_MAC_ADDR_LEN * 3];
	static int i;
	char *s = buf[++i % NBUFS];
	snprintf(s, WIFI_MAC_ADDR_LEN * 3,
		"%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return s;
}

#if defined(CONFIG_NET_IPV6)
struct sta_left_ctx {
	const uint8_t *mac;
	struct net_in6_addr addr;
	bool found;
};

static void find_nbr_by_mac(struct net_nbr *nbr, void *user_data)
{
	struct sta_left_ctx *ctx = user_data;

	if (ctx->found || nbr->iface != iface_lan || nbr->idx == NET_NBR_LLADDR_UNKNOWN) {
		return;
	}

	struct net_linkaddr *lladdr = net_nbr_get_lladdr(nbr->idx);
	if (lladdr->len == WIFI_MAC_ADDR_LEN &&
	    memcmp(lladdr->addr, ctx->mac, WIFI_MAC_ADDR_LEN) == 0) {
		ctx->addr = net_ipv6_nbr_data(nbr)->addr;
		ctx->found = true;
	}
}

static void remove_sta_neighbors(const uint8_t *mac)
{
	struct sta_left_ctx ctx;

	do {
		ctx.found = false;
		ctx.mac = mac;
		net_ipv6_nbr_foreach(find_nbr_by_mac, &ctx);
		if (ctx.found) {
			LOG_DBG("removing neighbor for station %s", mac_str(mac));
			net_ipv6_nbr_rm(iface_lan, &ctx.addr);
		}
	} while (ctx.found);
}
#endif /* CONFIG_NET_IPV6 */

static void net_mgmt_event_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
				   struct net_if *iface)
{
	switch (mgmt_event) {
	case NET_EVENT_WIFI_CONNECT_RESULT: {
		const struct wifi_status *status = cb->info;
		if (status->conn_status == WIFI_STATUS_CONN_SUCCESS) {
			event_post(EVENT_WAN_CONN_SUCCESS);
		} else {
			event_post(EVENT_WAN_CONN_FAILED);
		}
		const char *msg = wifi_conn_status_msg(status->conn_status);
		strncpy(info.wan_status, msg, sizeof(info.wan_status));
		break;
	}
	case NET_EVENT_WIFI_DISCONNECT_RESULT: {
 		const struct wifi_status *status = cb->info;
   		const char *msg = wifi_conn_status_msg(status->conn_status);
		strncpy(info.wan_status, msg, sizeof(info.wan_status));
		event_post(EVENT_WAN_DISCONNECTED);
		break;
	}
	case NET_EVENT_WIFI_AP_ENABLE_RESULT:
		event_post(EVENT_LAN_ENABLED);
		break;
	case NET_EVENT_WIFI_AP_DISABLE_RESULT:
		event_post(EVENT_LAN_DISABLED);
		break;
	case NET_EVENT_WIFI_AP_STA_CONNECTED:
	case NET_EVENT_WIFI_AP_STA_DISCONNECTED: {
		const struct wifi_ap_sta_info *sta_info = cb->info;
		if (mgmt_event == NET_EVENT_WIFI_AP_STA_CONNECTED) {
			LOG_INF("station %s joined", mac_str(sta_info->mac));
			info.lan_num_connected += 1;
		} else {
			LOG_INF("station %s left", mac_str(sta_info->mac));
			if (info.lan_num_connected > 0) {
				info.lan_num_connected -= 1;
			} else {
				LOG_WRN("got disconnect with zero lan client count");
			}
#if defined(CONFIG_NET_IPV6)
			remove_sta_neighbors(sta_info->mac);
#endif
		}
		break;
	}
	case NET_EVENT_IPV4_ADDR_ADD:
		if (iface == iface_wan) {
			if (status_get(SUBSYS_WAN) == STATUS_ON) {
				/* address has changed, reconnect */
				event_post(EVENT_TUN_DISCONNECTED);
			} else {
				event_post(EVENT_WAN_BOUND);
			}
		}
		break;
	default:
		LOG_ERR("unhandled mgmt event %llu", mgmt_event);
	}
}

/* Clear unwanted flags before WiFi calls carrier_on */
static int wifi_iface_preconfigure(void)
{
	struct net_if *wan = net_if_get_wifi_sta();

	if (wan && IS_ENABLED(CONFIG_NET_IPV6)) {
		net_if_flag_clear(wan, NET_IF_IPV6);
	}
	return 0;
}
SYS_INIT(wifi_iface_preconfigure, APPLICATION, 0);

int wifi_init(void)
{
	iface_wan = net_if_get_wifi_sta();
	if (!iface_wan) {
		LOG_ERR("cannot get wan iface");
		return 1;
	}

#if defined(CONFIG_VOLE_LAN)
	iface_lan = net_if_get_wifi_sap();
	if (!iface_lan) {
		LOG_ERR("cannot get lan iface");
		return 1;
	}
	net_if_flag_clear(iface_lan, NET_IF_IPV4);
#endif
	net_mgmt_init_event_callback(&wifi_mgmt_cb, net_mgmt_event_handler, NET_EVENT_WIFI_MASK);
	net_mgmt_add_event_callback(&wifi_mgmt_cb);

	net_mgmt_init_event_callback(&net_mgmt_cb, net_mgmt_event_handler, NET_EVENT_IPV4_ADDR_ADD);
	net_mgmt_add_event_callback(&net_mgmt_cb);

	return 0;
}

int lan_start(void)
{
	if (!iface_lan) {
		return 0;
	}

	info.lan_num_connected = 0;

#if defined(CONFIG_NET_IPV6)
	struct net_in6_addr prefix;
	struct net_in6_addr nat64_prefix;
#endif
	uint32_t ev;
	int ret;

	struct wifi_connect_req_params params = {
		.ssid = config.lan.ssid,
		.ssid_length = strlen(config.lan.ssid),
		.psk = config.lan.psk,
		.psk_length = strlen(config.lan.psk),
		.channel = WIFI_CHANNEL_ANY,
		.band = WIFI_FREQ_BAND_2_4_GHZ,
		.security = WIFI_SECURITY_TYPE_PSK,
	};

	ret = net_mgmt(NET_REQUEST_WIFI_AP_ENABLE, iface_lan,
		       &params, sizeof(struct wifi_connect_req_params));
	if (ret != 0) {
		LOG_ERR("cannot request lan enable: %s (%d)", strerror(-ret), ret);
		return ret;
	}
	ev = event_consume(EVENT_LAN_ENABLED, LAN_ENABLE_TIMEOUT);
	if ((ev & EVENT_LAN_ENABLED) == 0) {
		LOG_ERR("timed out on waiting for lan enabled event");
		return 1;
	}

#if defined(CONFIG_NET_IPV6)
	lan_if_addr6 = net_if_ipv6_addr_add(iface_lan, &config.lan.address6.addr, NET_ADDR_MANUAL, 0);
	if (!lan_if_addr6) {
		LOG_ERR("cannot add ipv6 address for lan interface");
		return 1;
	}

	net_ipv6_addr_prefix_mask(config.lan.address6.addr.s6_addr, prefix.s6_addr,
				  config.lan.address6.prefix);

	lan_if_prefix6 = net_if_ipv6_prefix_add(iface_lan, &prefix, config.lan.address6.prefix, ~0U);
	if (!lan_if_prefix6) {
		LOG_ERR("cannot add ipv6 prefix for lan interface");
		return 1;
	}

	ret = net_addr_pton(NET_AF_INET6, IPV6_NAT64_PREFIX, &nat64_prefix);
	if (ret != 0) {
		LOG_ERR("cannot parse nat64 (%d)", ret);
		return ret;
	}

	ra_start(iface_lan, &prefix, 64, config.lan.dns6, config.lan.dns6_num, &nat64_prefix,
		 config.tun.mtu);
#endif

	LOG_INF("lan started");
	status_set(SUBSYS_LAN, STATUS_ON);
	return 0;
}

int lan_stop(void)
{
	if (!iface_lan) {
		return 0;
	}

	int ret;

	struct wifi_iface_status status = { 0 };
	ret = net_mgmt(NET_REQUEST_WIFI_IFACE_STATUS, iface_lan, &status,
		sizeof(struct wifi_iface_status));
	if (ret != 0) {
		LOG_ERR("cannot request lan status: %s (%d)", strerror(-ret), ret);
		return ret;
	}
	if (status.state <= WIFI_STATE_INACTIVE) {
		LOG_DBG("lan is already stopped");
		return 0;
	}

	ret = net_mgmt(NET_REQUEST_WIFI_AP_DISABLE, iface_lan, NULL, 0);
	if (ret != 0) {
		LOG_ERR("cannot request lan disable (%d)", ret);
		return ret;
	}
	uint32_t events = event_consume(EVENT_LAN_DISABLED, LAN_DISABLE_TIMEOUT);
	if (events == 0) {
		LOG_ERR("cannot disable lan (%d)", ret);
		return 1;
	}

#if defined(CONFIG_NET_IPV6)
	ra_stop();

	if (lan_if_prefix6) {
		if (!net_if_ipv6_prefix_rm(iface_lan, &lan_if_prefix6->prefix, 64)) {
			LOG_ERR("cannot remove ipv6 prefix for lan interface");
			return 1;
		}
		lan_if_prefix6 = NULL;
	}

	if (lan_if_addr6) {
		if (!net_if_ipv6_addr_rm(iface_lan, &lan_if_addr6->address.net_in6_addr)) {
			LOG_ERR("cannot remove ipv6 address for lan interface");
			return 1;
		}
		lan_if_addr6 = NULL;
	}
#endif

	info.lan_num_connected = 0;
	LOG_INF("lan stopped");
	status_set(SUBSYS_LAN, STATUS_OFF);
	return 0;
}

int wan_start(void)
{
	int ret;
	uint32_t ev;

	if (!config.wan.configured) {
		return 1;
	}

	struct wifi_connect_req_params params = {
		.ssid = config.wan.ssid,
		.ssid_length = strlen(config.wan.ssid),
		.psk = config.wan.psk,
		.psk_length = strlen(config.wan.psk),
		.channel = WIFI_CHANNEL_ANY,
		.security = WIFI_SECURITY_TYPE_PSK,
		.band = WIFI_FREQ_BAND_2_4_GHZ,
	};

	ret = net_mgmt(NET_REQUEST_WIFI_CONNECT, iface_wan, &params,
		       sizeof(struct wifi_connect_req_params));
	if (ret != 0) {
		LOG_ERR("cannot request wan connect: %s (%d)", strerror(-ret), ret);
		return 1;
	}

	ev = event_consume(EVENT_WAN_CONN_SUCCESS | EVENT_WAN_CONN_FAILED | EVENT_WAN_DISCONNECTED,
			   WAN_CONNECT_TIMEOUT);
	if (ev & EVENT_WAN_DISCONNECTED) {
		LOG_WRN("wan disconnected on a request to connect");
		return 1;
	}
	if (ev & EVENT_WAN_CONN_FAILED) {
		LOG_WRN("wan failed to connect: %s", info.wan_status);
		return 1;
	}
	if ((ev & EVENT_WAN_CONN_SUCCESS) == 0) {
		LOG_ERR("wan connection request timed out with neither success nor failure");
		return 1;
	}

	ev = event_consume(EVENT_WAN_BOUND, WAN_BOUND_TIMEOUT);
	if ((ev & EVENT_WAN_BOUND) == 0) {
		LOG_WRN("wan cannot get an ip address");
		return 1;
	}

	LOG_INF("wan connected to '%s'", config.wan.ssid);

	status_set(SUBSYS_WAN, STATUS_ON);
	return 0;
}

int wan_stop(void)
{
	int ret;
	uint32_t ev;

	struct wifi_iface_status status = {0};
	ret = net_mgmt(NET_REQUEST_WIFI_IFACE_STATUS, iface_wan, &status,
		sizeof(struct wifi_iface_status));
	if (ret != 0) {
		LOG_ERR("cannot request wan status: %s (%d)", strerror(-ret), ret);
		return ret;
	}
	if (status.state != WIFI_STATE_COMPLETED) {
		LOG_DBG("wan is already stopped");
		return 0;
	}

	ret = net_mgmt(NET_REQUEST_WIFI_DISCONNECT, iface_wan, NULL, 0);
	if (ret != 0) {
		LOG_ERR("cannot request wan disconnect (%d)", ret);
		return ret;
	}

	ev = event_consume(EVENT_WAN_DISCONNECTED, WAN_DISCONNECT_TIMEOUT);
	if ((ev & EVENT_WAN_DISCONNECTED) == 0) {
		LOG_ERR("cannot disconnect wan (timeout)");
		return 1;
	}

	LOG_INF("wan stopped");
	status_set(SUBSYS_WAN, STATUS_OFF);
	return 0;
}
