#ifndef _DTLS_H_
#define _DTLS_H_

#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/sys/clock.h>

struct proto {
	const char *cipher_suite;
	uint8_t dtls_overhead;
};

struct dtls_interface_config {
	struct net_sockaddr_in remote_address;
	uint16_t local_port; /* Host byte order */
	const char *psk_base64;
	size_t keepalive_secs;
	uint16_t mtu;
	const char *cipher_suite;
};

struct dtls_stats {
	size_t sent_packets;
	size_t sent_orig_bytes;
	size_t sent_bytes;
	size_t rcvd_packets;
	size_t rcvd_orig_bytes;
	size_t rcvd_bytes;

	size_t allocs_failed;
	size_t pkt_pool_hwm;
	size_t early_drops;

	const char *version;
	const char *curve_name;
	const char *cipher_suite;

	size_t rtt_us;
};

const struct proto *find_cipher_suite(const char *cipher_suite);
int dtls_set_config(struct net_if *iface, const struct dtls_interface_config *config);
struct dtls_stats *dtls_stats(void);

#endif
