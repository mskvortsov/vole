#ifndef _WIREGUARD_H_
#define _WIREGUARD_H_

#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>

struct wg_interface_config {
	struct net_sockaddr_in remote_address;
	const char *private_key_base64;
	const char *public_key_base64;
	const char *psk_base64;
	int keepalive_secs;
};

/**
 * Configure and start a WireGuard peer.
 *
 * Returns 0 on success, negative errno on failure.
 */
int wg_set_config(struct net_if *iface, const struct wg_interface_config *cfg);

/**
 * Initiate the WireGuard handshake with the configured peer.
 *
 * Returns 0 or -EAGAIN on success (handshake sent), negative errno on error.
 */
int wg_initiate(void);

/**
 * Remove the active WireGuard peer and bring its interface down.
 */
int wg_remove(void);

/**
 * Sync the WireGuard TAI64N clock from an NTP server.
 */
int wg_sntp_sync(void);

#endif /* _WIREGUARD_H_ */
