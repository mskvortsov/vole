#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(wg, LOG_LEVEL_INF);

#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/base64.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/virtual.h>
#include <zephyr/net/virtual_mgmt.h>
#include <zephyr/net/wireguard.h>
#include <zephyr/net/sntp.h>
#include <zephyr/net/socket.h>

#include "wg.h"

extern int64_t sntp_time(void);
static int64_t wg_epoch_ms;
static int64_t wg_offset_ms;
static int wg_active_peer_id = -1;

/* Override the weak default wireguard_get_current_time() */
int wireguard_get_current_time(uint64_t *seconds, uint32_t *nanoseconds)
{
	int64_t now_ms;

	if (wg_epoch_ms > 0) {
		now_ms = wg_epoch_ms + (k_uptime_get() - wg_offset_ms);
	} else {
		LOG_DBG("using uptime instead of a proper wall clock time");
		now_ms = k_uptime_get();
	}

	*seconds = (uint64_t)(now_ms / MSEC_PER_SEC);
	*nanoseconds = (uint32_t)((now_ms % MSEC_PER_SEC) * NSEC_PER_MSEC);
	return 0;
}

int wg_set_config(struct net_if *iface, const struct wg_interface_config *cfg)
{
	struct virtual_interface_req_params params = {0};
	struct wireguard_peer_config peer_config = {0};
	uint8_t private_key[NET_VIRTUAL_MAX_PUBLIC_KEY_LEN];
	uint8_t psk[32];
	struct net_if *peer_iface = NULL;
	size_t olen;
	int ret;

	if (wg_active_peer_id >= 0) {
		LOG_ERR("wireguard peer already configured");
		return -EALREADY;
	}

	/* Decode and install the local private key. */
	ret = base64_decode(private_key, sizeof(private_key), &olen, cfg->private_key_base64,
			    strlen(cfg->private_key_base64));
	if (ret != 0) {
		return -EINVAL;
	}

	params.private_key.data = private_key;
	params.private_key.len = olen;

	ret = net_mgmt(NET_REQUEST_VIRTUAL_INTERFACE_SET_PRIVATE_KEY, iface, &params,
		       sizeof(params));
	memset(private_key, 0, sizeof(private_key));
	if (ret != 0) {
		LOG_ERR("cannot set wireguard private key (%d)", ret);
		return ret;
	}

	/* Server public key. */
	peer_config.public_key = cfg->public_key_base64;

	/* Optional pre-shared key. */
	if (cfg->psk_base64 != NULL && cfg->psk_base64[0] != '\0') {
		ret = base64_decode(psk, sizeof(psk), &olen, cfg->psk_base64,
				    strlen(cfg->psk_base64));
		if (ret != 0) {
			LOG_ERR("cannot decode pre-shared key (%d)", ret);
			return -EINVAL;
		}
		peer_config.preshared_key = psk;
	}

	/* Server endpoint. */
	memcpy(&peer_config.endpoint_ip, &cfg->remote_address, sizeof(struct net_sockaddr_in));

	/* Allow all IPv4 traffic through the tunnel. */
	peer_config.allowed_ip[0].addr.family = AF_INET;
	memset(&peer_config.allowed_ip[0].addr.in_addr, 0, sizeof(struct net_in_addr));
	peer_config.allowed_ip[0].mask_len = 0;
	peer_config.allowed_ip[0].is_valid = true;

	/* Allow all IPv6 traffic through the tunnel. */
	peer_config.allowed_ip[1].addr.family = AF_INET6;
	memset(&peer_config.allowed_ip[1].addr.in6_addr, 0, sizeof(struct net_in6_addr));
	peer_config.allowed_ip[1].mask_len = 0;
	peer_config.allowed_ip[1].is_valid = true;

	peer_config.keepalive_interval = cfg->keepalive_secs;
	peer_config.awg = cfg->awg;

	ret = wireguard_peer_add(&peer_config, &peer_iface);
	memset(psk, 0, sizeof(psk));
	if (ret < 0) {
		LOG_ERR("cannot add wireguard peer (%d)", ret);
		return ret;
	}

	if (peer_iface != iface) {
		LOG_ERR("unexpected peer iface");
		wireguard_peer_remove(ret);
		return -EINVAL;
	}

	wg_active_peer_id = ret;

	LOG_INF("peer %d added on interface %d", wg_active_peer_id, net_if_get_by_iface(peer_iface));

	return 0;
}

int wg_initiate(void)
{
	int64_t res;
	int ret;

	if (wg_active_peer_id < 0) {
		return -EINVAL;
	}

	res = sntp_time();
	if (res < 0) {
		LOG_WRN("cannot get sntp time (%lld)", res);
		res = 0;
	}

	wg_epoch_ms = res;
	wg_offset_ms = k_uptime_get();

	ret = wireguard_peer_keepalive(wg_active_peer_id);
	if (ret != 0 && ret != -EAGAIN && ret != -ENOTCONN) {
		LOG_ERR("cannot initiate wireguard handshake (%d)", ret);
		return ret;
	}

	LOG_INF("wireguard handshake initiated for peer %d", wg_active_peer_id);
	return 0;
}

int wg_remove(void)
{
	int ret;

	if (wg_active_peer_id < 0) {
		return 0;
	}

	ret = wireguard_peer_remove(wg_active_peer_id);
	if (ret != 0) {
		LOG_ERR("cannot remove wireguard peer %d (%d)", wg_active_peer_id, ret);
		return ret;
	}

	LOG_INF("wireguard peer %d removed", wg_active_peer_id);
	wg_active_peer_id = -1;

	return 0;
}
