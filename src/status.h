#ifndef _STATE_H_
#define _STATE_H_

#include <stdint.h>
#include <zephyr/sys/clock.h>
#include <zephyr/sys/util_macro.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/wifi.h>

enum event {
	EVENT_LAN_ENABLED       = BIT(0),
	EVENT_LAN_DISABLED      = BIT(1),

	EVENT_WAN_CONN_FAILED   = BIT(2),
	EVENT_WAN_CONN_SUCCESS  = BIT(3),
	EVENT_WAN_BOUND         = BIT(4),
	EVENT_WAN_DISCONNECTED  = BIT(5),

	EVENT_TUN_CONNECTED     = BIT(6),
	EVENT_TUN_DISCONNECTED  = BIT(7),

	EVENT_CONF_LAN          = BIT(8),
	EVENT_CONF_WAN          = BIT(9),
	EVENT_CONF_TUN          = BIT(10),
};

static inline const char *event_name(enum event event)
{
	switch (event) {
	case EVENT_LAN_ENABLED:      return "LAN_ENABLED";
	case EVENT_LAN_DISABLED:     return "LAN_DISABLED";
	case EVENT_WAN_CONN_FAILED:  return "WAN_CONN_FAILED";
	case EVENT_WAN_CONN_SUCCESS: return "WAN_CONN_SUCCESS";
	case EVENT_WAN_BOUND:        return "WAN_BOUND";
	case EVENT_WAN_DISCONNECTED: return "WAN_DISCONNECTED";
	case EVENT_TUN_CONNECTED:    return "TUN_CONNECTED";
	case EVENT_TUN_DISCONNECTED: return "TUN_DISCONNECTED";
	case EVENT_CONF_LAN:         return "CONF_LAN";
	case EVENT_CONF_WAN:         return "CONF_WAN";
	case EVENT_CONF_TUN:         return "CONF_TUN";
	default:                     return "<unknown-event>";
	}
}

void event_post(enum event event);
uint32_t event_consume(uint32_t events, k_timeout_t timeout);

enum status {
	STATUS_OFF = 0,
	STATUS_STARTED,
	STATUS_ON,
};

enum subsys {
	SUBSYS_LAN = 0,
	SUBSYS_WAN,
	SUBSYS_TUN,
	SUBSYS_COUNT = 3
};

static inline const char *status_name(enum status st)
{
	switch (st) {
	case STATUS_OFF:     return "OFF";
	case STATUS_STARTED: return "STARTED";
	case STATUS_ON:      return "ON";
	default:             return "<unknown-state>";
	}
}

static inline const char *subsys_name(enum subsys ss)
{
	switch (ss) {
	case SUBSYS_LAN: return "lan";
	case SUBSYS_WAN: return "wan";
	case SUBSYS_TUN: return "tun";
	default:         return "<unknown-subsys>";
	}
}

void status_set(enum subsys ss, enum status st);
enum status status_get(enum subsys ss);

struct info {
	size_t reboot_count;
	size_t tun_downs;
	char wan_status[32];
	size_t lan_num_connected;
};

extern struct info info;

size_t status_json(char *buf, size_t len);

#endif
