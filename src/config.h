#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <stdint.h>
#include <zephyr/app_version.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/wifi.h>
#include <zephyr/sys/util_macro.h>

#define VERSION_STRING "v" APP_VERSION_STRING "-" STRINGIFY(APP_BUILD_VERSION)

#define MAX_DNS_ADDRESSES 2

struct cidr4_addr {
	struct net_in_addr addr;
	uint8_t prefix;
};

struct cidr6_addr {
	struct net_in6_addr addr;
	uint8_t prefix;
};

struct config_lan {
	char ssid[33];
	char psk[64];
	struct cidr6_addr address6;
	size_t dns6_num;
	struct net_in6_addr dns6[MAX_DNS_ADDRESSES];
};

struct config_wan {
	bool configured;
	char ssid[33];
	char psk[64];
	uint8_t hwaddr[WIFI_MAC_ADDR_LEN];
	bool hwaddr_set;
	bool http;
};

struct config_tun_options {
	enum {
		PROTO_UNKNOWN = 0,
		PROTO_DTLS,
		PROTO_WIREGUARD,
	} proto;
	union {
		struct {
			char cipher_suite[48];
			char psk[64];
		} dtls;
		struct {
			char key[45];
			char pubkey[45];
		} wg;
	} u;
};

struct config_tun {
	bool configured;
	struct net_sockaddr_in endpoint;
	uint16_t local_port; /* Host byte order */
	struct cidr4_addr address4;
	struct net_in_addr peer4;
	size_t keepalive_secs;
	uint16_t mtu;
	struct config_tun_options opts;
#if defined(CONFIG_NET_IPV6)
	struct cidr6_addr address6;
	struct net_in6_addr peer6;
#endif
};

struct config {
	struct config_lan lan;
	struct config_wan wan;
	struct config_tun tun;
};

extern struct config config;

const struct net_in_addr *netmask_by_prefix(uint8_t prefix);

int config_init();
int config_reset();
int config_save();
void config_apply(void);

#endif
