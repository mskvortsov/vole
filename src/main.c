#include <string.h>
#include <stdnoreturn.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(main, LOG_LEVEL_INF);

#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/watchdog.h>
#include <zephyr/input/input.h>
#include <zephyr/logging/log_ctrl.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/virtual.h>
#include <zephyr/sys/math_extras.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/timing/timing.h>
#include <zephyr/debug/thread_analyzer.h>

#include "net_private.h"
#if defined(CONFIG_NET_IPV6)
#include "ipv6.h"
#endif

#include "config.h"
#include "crypto.h"
#include "dtls.h"
#include "npf.h"
#include "status.h"
#include "wifi.h"

static struct net_if *iface_tun;
static struct net_if_addr *tun_if_addr;

#if defined(CONFIG_NET_IPV6)
static struct net_if_addr *tun_if_addr6;
static struct net_if_ipv6_prefix *tun_if_prefix6;
static struct net_if_router *tun_router6;
#endif

static const struct gpio_dt_spec led_wan = GPIO_DT_SPEC_GET(DT_ALIAS(led_wan), gpios);
static const struct gpio_dt_spec led_tun = GPIO_DT_SPEC_GET(DT_ALIAS(led_tun), gpios);
static const struct device *const wdt = DEVICE_DT_GET(DT_ALIAS(watchdog0));

struct crypto_context crypto;
extern void bench();

#define TUN_CONNECT_TIMEOUT K_SECONDS(15)
#define EVENTS_POLL_TIMEOUT K_SECONDS(10)
#define WDT_TIMEOUT_MSECS   60000

static struct net_mgmt_event_callback vpn_mgmt_cb;

static void tun_mgmt_event_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
				   struct net_if *iface)
{
	ARG_UNUSED(cb);
	switch (mgmt_event) {
	case NET_EVENT_VPN_CONNECTED:
		if (iface == iface_tun) {
			event_post(EVENT_TUN_CONNECTED);
		}
		break;
	case NET_EVENT_VPN_DISCONNECTED:
		if (iface == iface_tun) {
			info.tun_downs += 1;
			event_post(EVENT_TUN_DISCONNECTED);
		}
		break;
	default:
		LOG_ERR("unhandled mgmt event %llu", mgmt_event);
	}
}

static int tun_start(void)
{
#if defined(CONFIG_NET_IPV6)
	struct net_in6_addr prefix6;
#endif
	int ret;

	if (!config.tun.configured) {
		return 0;
	}

	tun_if_addr = net_if_ipv4_addr_add(iface_tun, &config.tun.address4.addr, NET_ADDR_MANUAL, 0);
	if (!tun_if_addr) {
		LOG_ERR("cannot add address for tun iface");
		return 1;
	}
	if (!net_if_ipv4_set_netmask_by_addr(iface_tun, &config.tun.address4.addr,
					     netmask_by_prefix(config.tun.address4.prefix))) {
		LOG_ERR("cannot set netmask for tun iface");
		return 1;
	}
	net_if_ipv4_set_gw(iface_tun, &config.tun.peer4);

#if defined(CONFIG_NET_IPV6)
	tun_if_addr6 = net_if_ipv6_addr_add(iface_tun, &config.tun.address6.addr, NET_ADDR_MANUAL, 0);
	if (!tun_if_addr6) {
		LOG_ERR("cannot add ipv6 address for tun interface");
		return 1;
	}

	net_ipv6_addr_prefix_mask(config.tun.address6.addr.s6_addr, prefix6.s6_addr,
				  config.tun.address6.prefix);

	tun_if_prefix6 = net_if_ipv6_prefix_add(iface_tun, &prefix6, config.tun.address6.prefix, ~0U);
	if (!tun_if_prefix6) {
		LOG_ERR("cannot add ipv6 prefix for tun interface");
		return 1;
	}

	struct net_nbr *nbr = net_ipv6_nbr_add(iface_tun, &config.tun.peer6,
					       net_if_get_link_addr(iface_tun),
					       false, NET_IPV6_NBR_STATE_STATIC);
	if (!nbr) {
		LOG_ERR("cannot add ipv6 neighbor for tun peer");
		return 1;
	}

	tun_router6 = net_if_ipv6_router_add(iface_tun, &config.tun.peer6, true, 0);
	if (!tun_router6) {
		LOG_ERR("cannot add ipv6 default router via tun");
		net_ipv6_nbr_rm(iface_tun, &config.tun.peer6);
		return 1;
	}
#endif

	struct dtls_interface_config cfg = {
		.remote_address = config.tun.endpoint,
		.local_port = config.tun.local_port,
		.psk_base64 = config.tun.psk,
		.keepalive_secs = config.tun.keepalive_secs,
		.route = route_tun,
		.mtu = config.tun.mtu,
		.cipher_suite = config.tun.cipher_suite,
	};
	ret = dtls_set_config(iface_tun, &cfg);
	if (ret != 0) {
		LOG_ERR("cannot configure tun iface (%d)", ret);
		return ret;
	}

	ret = net_virtual_interface_attach(iface_tun, wan_get_iface());
	if (ret != 0) {
		LOG_ERR("cannot attach tun iface to sta: %s (%d)", strerror(-ret), ret);
		return ret;
	}
	ret = net_if_up(iface_tun);
	if (ret != 0) {
		LOG_ERR("cannot set tun iface up: %s (%d)", strerror(-ret), ret);
		return ret;
	}

	ret = npf_start(lan_get_iface(), wan_get_iface(), iface_tun);
	if (ret != 0) {
		return ret;
	}

	/* TODO EVENT_TUN_CONN_FAILED */
	uint32_t events = event_consume(EVENT_TUN_CONNECTED, TUN_CONNECT_TIMEOUT);
	if (events == 0) {
		LOG_DBG("no connected event from tun");
		return 1;
	}

	status_set(SUBSYS_TUN, STATUS_ON);
	return 0;
}

static int tun_stop(void)
{
	int ret;

	ret = npf_stop();
	if (ret != 0) {
		LOG_ERR("cannot stop npf");
		return ret;
	}

#if defined(CONFIG_NET_IPV6)
	if (tun_router6) {
		net_if_ipv6_router_rm(tun_router6);
		tun_router6 = NULL;
	}

	net_ipv6_nbr_rm(iface_tun, &config.tun.peer6);
#endif

	ret = net_if_down(iface_tun);
	if (ret == -EALREADY) {
		LOG_DBG("tun is already stopped");
	} else if (ret != 0) {
		LOG_ERR("cannot set tun iface down (%d)", ret);
		return ret;
	}

	ret = net_virtual_interface_attach(iface_tun, NULL);
	if (ret == -EALREADY) {
		LOG_DBG("tun is already detached");
	} else if (ret != 0) {
		LOG_ERR("cannot detach tun iface from wan (%d)", ret);
		return ret;
	}

#if defined(CONFIG_NET_IPV6)
	if (tun_if_prefix6) {
		if (!net_if_ipv6_prefix_rm(iface_tun, &tun_if_prefix6->prefix,
					   config.tun.address6.prefix)) {
			LOG_ERR("cannot remove ipv6 prefix for tun iface");
			return 1;
		}
		tun_if_prefix6 = NULL;
	}

	if (tun_if_addr6) {
		if (!net_if_ipv6_addr_rm(iface_tun, &tun_if_addr6->address.net_in6_addr)) {
			LOG_ERR("cannot remove ipv6 address for tun iface");
			return 1;
		}
		tun_if_addr6 = NULL;
	}
#endif

	if (tun_if_addr) {
		if (!net_if_ipv4_addr_rm(iface_tun, &tun_if_addr->address.net_in_addr)) {
			LOG_ERR("cannot remove address for tun iface");
			return 1;
		}
		tun_if_addr = NULL;
	}

	status_set(SUBSYS_TUN, STATUS_OFF);
	return 0;
}

static noreturn void fatal(void)
{
	LOG_ERR("fatal condition reached, halting");
	gpio_pin_set_dt(&led_wan, 0);
	gpio_pin_set_dt(&led_tun, 1);
	while (true) {
		gpio_pin_toggle_dt(&led_wan);
		gpio_pin_toggle_dt(&led_tun);
		k_sleep(K_MSEC(250));
	}
}

static int wdt_start(void)
{
	int ret;
	int channel_id;
	struct wdt_timeout_cfg wdt_config = {
		.flags = WDT_FLAG_RESET_SOC,
		.window.max = WDT_TIMEOUT_MSECS,
	};

	ret = wdt_install_timeout(wdt, &wdt_config);
	if (ret < 0) {
		LOG_ERR("cannot start watchdog (%d)", ret);
		return -EINVAL;
	}

	channel_id = ret;

	ret = wdt_setup(wdt, WDT_OPT_PAUSE_HALTED_BY_DBG);
	if (ret < 0) {
		LOG_ERR("cannot set watchdog up (%d)", ret);
		return -EINVAL;
	}

	return channel_id;
}

#if DT_HAS_ALIAS(btn_reset)
#define RESET_HOLD_MS 5000

static void reset_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	LOG_WRN("reset button held, resetting config");
	config_reset();
	sys_reboot(SYS_REBOOT_COLD);
}

static K_WORK_DELAYABLE_DEFINE(reset_work, reset_work_handler);

static void reset_button_cb(struct input_event *evt, void *user_data)
{
	ARG_UNUSED(user_data);
	if (evt->type != INPUT_EV_KEY || evt->code != INPUT_KEY_0) {
		return;
	}
	if (evt->value) {
		k_work_schedule(&reset_work, K_MSEC(RESET_HOLD_MS));
	} else {
		k_work_cancel_delayable(&reset_work);
	}
}

INPUT_CALLBACK_DEFINE(NULL, reset_button_cb, NULL);
#endif

static void stack_safety_handler(struct k_thread *thread, size_t unused_space,
				 uint32_t *stack_issue)
{
	LOG_WRN("thread %s unused %zu issue %u", thread->name, unused_space, *stack_issue);
}

extern void aqm_stats_print(void);
extern void aqm_init(uint16_t mtu);

int main(void)
{
	int ret;
	LOG_INF("starting " CONFIG_NET_HOSTNAME " " VERSION_STRING);
	log_flush();

	if (!device_is_ready(wdt)) {
		LOG_ERR("watchdog device isn't ready");
		fatal();
	}
	ret = wdt_disable(wdt);
	if (ret != 0) {
		LOG_ERR("cannot temporarily disable the watchdog (%d)", ret);
		fatal();
	}

	if (!gpio_is_ready_dt(&led_wan) || !gpio_is_ready_dt(&led_tun)) {
		LOG_ERR("gpio port is not ready");
		fatal();
	}
	ret = gpio_pin_configure_dt(&led_wan, GPIO_OUTPUT_ACTIVE);
	if (ret != 0) {
		LOG_ERR("cannot configure sta gpio pin");
		fatal();
	}
	ret = gpio_pin_configure_dt(&led_tun, GPIO_OUTPUT_ACTIVE);
	if (ret != 0) {
		LOG_ERR("cannot configure tun gpio pin");
		fatal();
	}
	gpio_pin_set_dt(&led_wan, 1);
	gpio_pin_set_dt(&led_tun, 1);

	thread_analyzer_stack_safety_handler_set(stack_safety_handler);

	if (crypto_init(&crypto) != 0) {
		LOG_ERR("cannot initialize crypto");
		fatal();
	}

	log_flush();

	bench();

	ret = config_init();
	if (ret != 0) {
		ret = config_reset();
		if (ret != 0) {
			fatal();
		}
	}

	aqm_init(NET_ETH_MAX_FRAME_SIZE);

	ret = wifi_init();
	if (ret != 0) {
		fatal();
	}

	iface_tun = net_if_get_by_index(net_if_get_by_name("dtls0"));
	if (!iface_tun) {
		LOG_ERR("cannot get tun iface");
		fatal();
	}

	net_mgmt_init_event_callback(&vpn_mgmt_cb, tun_mgmt_event_handler,
				     NET_EVENT_VPN_CONNECTED | NET_EVENT_VPN_DISCONNECTED);
	net_mgmt_add_event_callback(&vpn_mgmt_cb);

	status_set(SUBSYS_LAN, STATUS_OFF);
	status_set(SUBSYS_WAN, STATUS_OFF);
	status_set(SUBSYS_TUN, STATUS_OFF);
	event_post(EVENT_CONF_LAN);

	int wdt_channel_id = wdt_start();
	if (wdt_channel_id < 0) {
		LOG_ERR("cannot start the watchdog");
	}

	while (true) {
		uint32_t events = EVENT_CONF_LAN | EVENT_CONF_WAN | EVENT_CONF_TUN |
				  EVENT_WAN_DISCONNECTED | EVENT_TUN_DISCONNECTED;
		events = event_consume(events, EVENTS_POLL_TIMEOUT);

#if 0
		sojourn_print();
		aqm_stats_print();
#endif

		if (wdt_channel_id >= 0) {
			ret = wdt_feed(wdt, wdt_channel_id);
			if (ret != 0) {
				LOG_ERR("cannot feed the watchdog");
			}
		}

		if (events & EVENT_CONF_LAN) {
			/* let http server finish to respond */
			k_sleep(K_SECONDS(1));

			tun_stop();
			gpio_pin_set_dt(&led_tun, 1);
			wan_stop();
			gpio_pin_set_dt(&led_wan, 1);
			lan_stop();
			if (lan_start() == 0) {
				if (wan_start() == 0) {
					gpio_pin_set_dt(&led_wan, 0);
					if (tun_start() == 0) {
						gpio_pin_set_dt(&led_tun, 0);
					}
				}
			}
		} else if ((events & EVENT_CONF_WAN) || (events & EVENT_WAN_DISCONNECTED) ||
			   status_get(SUBSYS_WAN) != STATUS_ON) {
			tun_stop();
			gpio_pin_set_dt(&led_tun, 1);
			wan_stop();
			gpio_pin_set_dt(&led_wan, 1);
			if (wan_start() == 0) {
				gpio_pin_set_dt(&led_wan, 0);
				if (tun_start() == 0) {
					gpio_pin_set_dt(&led_tun, 0);
				}
			}
		} else if ((events & EVENT_CONF_TUN) || (events & EVENT_TUN_DISCONNECTED) ||
			   status_get(SUBSYS_TUN) != STATUS_ON) {
			tun_stop();
			gpio_pin_set_dt(&led_tun, 1);
			if (tun_start() == 0) {
				gpio_pin_set_dt(&led_tun, 0);
			}
		}
	}

	LOG_ERR("unreachable");
	return 0;
}
