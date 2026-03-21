#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(config, LOG_LEVEL_INF);

#include <zephyr/kernel.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/http/server.h>
#include <zephyr/net/http/service.h>
#include <zephyr/settings/settings.h>

#include "net_private.h"

#include <tomlc17.h>

#include "config.h"
#include "status.h"
#include "dtls.h"

#define SETTINGS_ROOT CONFIG_NET_HOSTNAME

#define TUN_MTU_DEFAULT     1300
#define TUN_MTU_MAX         1480
#define KEEPALIVE_SECS_DEFAULT 15

#define HTTP_STATUS_PAYLOAD_SIZE 1024
#define HTTP_CONFIG_PAYLOAD_SIZE 2048
#define HTTP_CONFIG_REPORT_SIZE  256

struct config config;

static const uint8_t default_config_toml[] = {
	#include "default.toml.inc"
};

BUILD_ASSERT(sizeof(default_config_toml) < HTTP_CONFIG_PAYLOAD_SIZE,
	     "default config exceeds maximum payload size");

static const uint8_t index_html_gz[] = {
	#include "index.html.gz.inc"
};

static char config_toml[HTTP_CONFIG_PAYLOAD_SIZE];
static char http_post_report[HTTP_CONFIG_REPORT_SIZE];

typedef int (*storage_func_cb)(const char *name, const void *value, size_t val_len);

#define SETTINGS_GET(name)                                                                         \
	do {                                                                                       \
		val_len_max = MIN((size_t)val_len_max, sizeof(name));                              \
		memcpy(val, &name, val_len_max);                                                   \
		return val_len_max;                                                                \
	} while (false)

static int handle_get(const char *key, char *val, int val_len_max)
{
	LOG_DBG("get \"%s\" val_len_max %d", key, val_len_max);
	if (!strcmp(key, "reboot_count")) {
		SETTINGS_GET(info.reboot_count);
	} else if (!strcmp(key, "config_toml")) {
		SETTINGS_GET(config_toml);
	}
	return -ENOENT;
}

#define SETTINGS_SET(name)                                                                         \
	do {                                                                                       \
		if (len != sizeof(name)) {                                                         \
			return -EINVAL;                                                            \
		}                                                                                  \
		rc = read_cb(cb_arg, &name, len);                                                  \
		if (rc >= 0) {                                                                     \
			return 0;                                                                  \
		}                                                                                  \
		return rc;                                                                         \
	} while (false)

static int handle_set(const char *key, size_t len, settings_read_cb read_cb, void *cb_arg)
{
	int rc;
	LOG_DBG("set \"%s\" from flash, len %zu", key, len);
	if (!strcmp(key, "reboot_count")) {
		SETTINGS_SET(info.reboot_count);
	} else if (!strcmp(key, "config_toml")) {
		SETTINGS_SET(config_toml);
	}
	return -ENOENT;
}

#define SETTINGS_EXPORT(name, var)                                                                 \
	do {                                                                                       \
		ret = cb(name, &var, sizeof(var));                                                 \
		if (ret != 0) {                                                                    \
			return ret;                                                                \
		}                                                                                  \
	} while (false)

static int handle_export(storage_func_cb cb)
{
	int ret;
	LOG_DBG("export");
	SETTINGS_EXPORT(SETTINGS_ROOT "/reboot_count", info.reboot_count);
	SETTINGS_EXPORT(SETTINGS_ROOT "/config_toml",  config_toml);
	return 0;
}

static struct settings_handler settings_handler = {
	.name = SETTINGS_ROOT,
	.h_get = handle_get,
	.h_set = handle_set,
	.h_export = handle_export,
};

static void settings_print()
{
	LOG_DBG("reboot_count: %zu", info.reboot_count);
	LOG_DBG("config_toml:");
	LOG_DBG("%s", config_toml);
}

#define REPORT(...)                                                                                \
	do {                                                                                       \
		LOG_INF(__VA_ARGS__);                                                              \
		snprintf(http_post_report, HTTP_CONFIG_REPORT_SIZE, __VA_ARGS__);                  \
	} while (false)

const struct net_in_addr *netmask_by_prefix(uint8_t prefix)
{
	static struct net_in_addr netmask;
	if (prefix == 0 || prefix > 32) {
		return net_ipv4_unspecified_address();
	}
	netmask.s_addr = net_htonl(~0U << (32 - prefix));
	return &netmask;
}

static int config_load_endpoint(struct net_sockaddr_in *addr, toml_datum_t t)
{
	int ret;
	toml_datum_t endpoint = toml_get(t, "endpoint");
	if (endpoint.type == TOML_UNKNOWN) {
		REPORT("tun.endpoint is missing");
		return 1;
	} else if (endpoint.type != TOML_STRING) {
		REPORT("tun.endpoint has invalid type: must be a string");
		return 1;
	}

	char *port = strchr(endpoint.u.s, ':');
	if (!port) {
		REPORT("cannot parse tun.endpoint %s: valid format is ipv4:port",
		       endpoint.u.s);
		return 1;
	}

	char c = *port;
	*port = 0;
	ret = net_addr_pton(AF_INET, endpoint.u.s, &addr->sin_addr);
	*port = c;
	if (ret != 0) {
		REPORT("cannot parse tun.endpoint %s: invalid ipv4", endpoint.u.s);
		return 1;
	}

	errno = 0;
	++port;
	char *endptr;
	uint32_t n = strtoul(port, &endptr, 10);
	if (errno == ERANGE || endptr == port || *endptr != 0 || n > 65535) {
		REPORT("cannot parse tun.endpoint %s: invalid port", endpoint.u.s);
		return 1;
	}
	addr->sin_port = net_htons(n);
	addr->sin_family = NET_AF_INET;

	return 0;
}

static int config_parse_cidr(const char *str, sa_family_t family, void *addr, uint8_t *prefix)
{
	uint8_t max = (family == NET_AF_INET) ? 32 : 128;
	char *pos = strchr(str, '/');

	if (!pos) {
		return 1;
	}

	errno = 0;
	char *endptr;
	uint32_t n = strtoul(pos + 1, &endptr, 10);

	if (errno == ERANGE || endptr == pos + 1 || *endptr != 0 || n > max) {
		return 1;
	}

	char c = *pos;
	*pos = 0;
	int ret = net_addr_pton(family, str, addr);
	*pos = c;
	if (ret != 0) {
		return 1;
	}

	*prefix = n;
	return 0;
}

static int config_load_string(char *buf, size_t size, const char *key, const char *hint,
			      toml_datum_t t)
{
	toml_datum_t dat = toml_get(t, key);
	if (dat.type == TOML_UNKNOWN) {
		REPORT("%s is missing", hint);
		return 1;
	}
	if (dat.type != TOML_STRING) {
		REPORT("%s has invalid type: must be a string", hint);
		return 1;
	}
	if (strlen(dat.u.s) + 1 > size) {
		REPORT("%s is too long", hint);
		return 1;
	}
	strcpy(buf, dat.u.s);
	return 0;
}

struct int_result {
	int val;
	int ret;
};

static struct int_result config_load_int(int lower, int upper, bool optional, int default_val,
					 const char *key, const char *hint, toml_datum_t t)
{
	struct int_result res = {0};
	toml_datum_t dat = toml_get(t, key);
	if (dat.type == TOML_UNKNOWN) {
		if (optional) {
			res.val = default_val;
		} else {
			REPORT("%s is missing", hint);
			res.ret = 1;
		}
	} else if (dat.type == TOML_INT64) {
		if (dat.u.int64 < lower || dat.u.int64 > upper) {
			REPORT("invalid %s %lld: must be in range [%d, %d]", hint, dat.u.int64,
			       lower, upper);
			res.ret = 1;
		} else {
			res.val = dat.u.int64;
		}
	} else {
		REPORT("%s has invalid type: must be an integer", hint);
		res.ret = 1;
	}
	return res;
}

static int config_load_lan_dns(struct config *c, toml_datum_t t)
{
	int ret;

	toml_datum_t array = toml_get(t, "dns6");
	if (array.type == TOML_UNKNOWN) {
		c->lan.dns6_num = 0;
		LOG_DBG("no dns6 addresses specified");
		return 0;
	}

	if (array.type != TOML_ARRAY) {
		REPORT("lan.dns6 has invalid type: must be an array");
		return 1;
	}

	int32_t dns6_num = array.u.arr.size;
	if (dns6_num > MAX_DNS_ADDRESSES) {
		REPORT("at most %d dns6 addresses are supported", MAX_DNS_ADDRESSES);
		return 1;
	}

	for (int32_t i = 0; i < dns6_num; ++i) {
		toml_datum_t dns6 = array.u.arr.elem[i];
		if (dns6.type == TOML_UNKNOWN) {
			REPORT("cannot read dns6 address at index %d", i);
			return 1;
		}
		if (dns6.type != TOML_STRING) {
			REPORT("cannot read dns6 address at index %d: must be string", i);
			return 1;
		}
		ret = net_addr_pton(NET_AF_INET6, dns6.u.s, &c->lan.dns6[i]);
		if (ret != 0) {
			REPORT("cannot parse dns6 address %s at index %i", dns6.u.s, i);
			return ret;
		}
	}

	c->lan.dns6_num = dns6_num;
	return 0;
}

static int config_load_lan(struct config *c, toml_datum_t t)
{
	int ret;
	ret = config_load_string(c->lan.ssid, sizeof(c->lan.ssid), "ssid", "lan.ssid", t);
	if (ret != 0) {
		return ret;
	}
	ret = config_load_string(c->lan.psk, sizeof(c->lan.psk), "psk", "lan.psk", t);
	if (ret != 0) {
		return ret;
	}

	toml_datum_t address6 = toml_get(t, "address6");
	if (address6.type == TOML_UNKNOWN) {
		REPORT("lan.address6 is missing");
		return 1;
	}
	if (address6.type != TOML_STRING) {
		REPORT("lan.address6 has invalid type: must be a string");
		return 1;
	}

	ret = config_parse_cidr(address6.u.s, NET_AF_INET6, &c->lan.address6.addr,
				&c->lan.address6.prefix);
	if (ret != 0) {
		REPORT("cannot parse lan.address6 %s: valid format is ipv6/prefix", address6.u.s);
		return 1;
	}

	ret = config_load_lan_dns(c, t);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

static int config_load_wan(struct config *c, toml_datum_t t)
{
	int ret;
	ret = config_load_string(c->wan.ssid, sizeof(c->wan.ssid), "ssid", "wan.ssid", t);
	if (ret != 0) {
		return ret;
	}
	ret = config_load_string(c->wan.psk, sizeof(c->wan.psk), "psk", "wan.psk", t);
	if (ret != 0) {
		return ret;
	}

	toml_datum_t http = toml_get(t, "http");
	if (http.type == TOML_BOOLEAN) {
		c->wan.http = http.u.boolean;
	} else if (http.type != TOML_UNKNOWN) {
		REPORT("wan.http has invalid type: must be a boolean");
		return 1;
	}

	return 0;
}

static int config_load_tun(struct config *c, toml_datum_t t)
{
	struct int_result res;
	int ret;
	ret = config_load_endpoint(&c->tun.endpoint, t);
	if (ret != 0) {
		return ret;
	}

	res = config_load_int(1, UINT16_MAX, true, 0, "local_port", "tun.local_port", t);
	if (res.ret != 0) {
		return res.ret;
	}
	c->tun.local_port = res.val;

	toml_datum_t address4 = toml_get(t, "address4");
	if (address4.type == TOML_UNKNOWN) {
		REPORT("tun.address4 is missing");
		return 1;
	}
	if (address4.type != TOML_STRING) {
		REPORT("tun.address4 has invalid type: must be a string");
		return 1;
	}

	ret = config_parse_cidr(address4.u.s, NET_AF_INET, &c->tun.address4.addr,
				&c->tun.address4.prefix);
	if (ret != 0) {
		REPORT("cannot parse tun.address4 %s: valid format is ipv4/prefix", address4.u.s);
		return ret;
	}

	toml_datum_t peer4 = toml_get(t, "peer4");
	if (peer4.type == TOML_UNKNOWN) {
		REPORT("tun.peer4 is missing");
		return 1;
	}
	if (peer4.type != TOML_STRING) {
		REPORT("tun.peer4 has invalid type: must be a string");
		return 1;
	}

	ret = net_addr_pton(NET_AF_INET, peer4.u.s, &c->tun.peer4.s4_addr);
	if (ret != 0) {
		REPORT("cannot parse tun.peer4 %s: valid format is ipv4 address", peer4.u.s);
		return ret;
	}

	ret = config_load_string(c->tun.cipher_suite, sizeof(c->tun.cipher_suite), "cipher_suite",
				 "tun.cipher_suite", t);
	if (ret != 0) {
		return ret;
	}
	if (!find_cipher_suite(c->tun.cipher_suite)) {
		REPORT("cannot parse tun.cipher_suite %s: invalid value", c->tun.cipher_suite);
		return 1;
	}

	ret = config_load_string(c->tun.psk, sizeof(c->tun.psk), "psk", "tun.psk", t);
	if (ret != 0) {
		return ret;
	}

	res = config_load_int(0, UINT16_MAX, true, KEEPALIVE_SECS_DEFAULT, "keepalive",
			      "tun.keepalive", t);
	if (res.ret != 0) {
		return res.ret;
	}
	c->tun.keepalive_secs = res.val;

	res = config_load_int(NET_IPV4_MTU, TUN_MTU_MAX, true, TUN_MTU_DEFAULT, "mtu", "tun.mtu", t);
	if (res.ret != 0) {
		return res.ret;
	}
	c->tun.mtu = res.val;

#if defined(CONFIG_NET_IPV6)
	toml_datum_t address6 = toml_get(t, "address6");
	if (address6.type == TOML_UNKNOWN) {
		REPORT("tun.address6 is missing");
		return 1;
	}
	if (address6.type != TOML_STRING) {
		REPORT("tun.address6 has invalid type: must be a string");
		return 1;
	}
	ret = config_parse_cidr(address6.u.s, NET_AF_INET6, &c->tun.address6.addr,
				&c->tun.address6.prefix);
	if (ret != 0) {
		REPORT("cannot parse tun.address6 %s: valid format is ipv6/prefix", address6.u.s);
		return 1;
	}

	toml_datum_t peer6 = toml_get(t, "peer6");
	if (peer6.type == TOML_UNKNOWN) {
		REPORT("tun.peer6 is missing");
		return 1;
	}
	if (peer6.type != TOML_STRING) {
		REPORT("tun.peer6 has invalid type: must be a string");
		return 1;
	}
	ret = net_addr_pton(NET_AF_INET6, peer6.u.s, &c->tun.peer6);
	if (ret != 0) {
		REPORT("cannot parse tun.peer6 %s: valid format is ipv6 address", peer6.u.s);
		return 1;
	}
#endif

	return 0;
}

static int config_load_toptab(struct config *c, toml_datum_t toptab)
{
	int ret;

	toml_datum_t lan = toml_get(toptab, "lan");
	if (lan.type == TOML_TABLE) {
		ret = config_load_lan(c, lan);
		if (ret != 0) {
			return ret;
		}
	} else if (lan.type == TOML_UNKNOWN) {
		REPORT("lan table is missing");
		return 1;
	} else {
		REPORT("lan datum has invalid type %d", lan.type);
		return 1;
	}

	toml_datum_t wan = toml_get(toptab, "wan");
	if (wan.type == TOML_TABLE) {
		ret = config_load_wan(c, wan);
		if (ret != 0) {
			return ret;
		}
		c->wan.configured = true;
	} else if (wan.type != TOML_UNKNOWN) {
		REPORT("wan datum has invalid type %d", wan.type);
		return 1;
	}

	toml_datum_t tun = toml_get(toptab, "tun");
	if (tun.type == TOML_TABLE) {
		ret = config_load_tun(c, tun);
		if (ret != 0) {
			return ret;
		}
		c->tun.configured = true;
	} else if (tun.type != TOML_UNKNOWN) {
		REPORT("tun datum has invalid type %d", tun.type);
		return 1;
	}

	return 0;
}

/* TODO warn on extra fields */
static int config_load(struct config *c, const char *buf, size_t len)
{
	int ret;
	toml_result_t res = toml_parse(buf, len);
	if (!res.ok) {
		REPORT("cannot parse config: %s", res.errmsg);
		toml_free(res);
		return 1;
	}

	ret = config_load_toptab(c, res.toptab);
	toml_free(res);
	return ret;
}

static bool config_eq_lan(struct config *l, struct config *r)
{
	return strcmp(l->lan.ssid, r->lan.ssid) == 0 &&
	       strcmp(l->lan.psk, r->lan.psk) == 0 &&
	       memcmp(&l->lan.address6, &r->lan.address6, sizeof(l->lan.address6)) == 0 &&
	       l->lan.dns6_num == r->lan.dns6_num &&
	       memcmp(&l->lan.dns6, &r->lan.dns6, sizeof(l->lan.dns6[0]) * l->lan.dns6_num) == 0;
}

static bool config_eq_wan(struct config *l, struct config *r)
{
	return strcmp(l->wan.ssid, r->wan.ssid) == 0 &&
	       strcmp(l->wan.psk, r->wan.psk) == 0 &&
	       l->wan.http == r->wan.http;
}

static bool config_eq_tun(struct config *l, struct config *r)
{
	return memcmp(&l->tun.endpoint, &r->tun.endpoint, sizeof(l->tun.endpoint)) == 0 &&
	       l->tun.local_port == r->tun.local_port &&
	       memcmp(&l->tun.address4, &r->tun.address4, sizeof(l->tun.address4)) == 0 &&
	       memcmp(&l->tun.peer4, &r->tun.peer4, sizeof(l->tun.peer4)) == 0 &&
	       strcmp(l->tun.psk, r->tun.psk) == 0 &&
	       l->tun.keepalive_secs == r->tun.keepalive_secs &&
	       l->tun.mtu == r->tun.mtu &&
	       strcmp(l->tun.cipher_suite, r->tun.cipher_suite) == 0
#if defined(CONFIG_NET_IPV6)
	       && memcmp(&l->tun.address6, &r->tun.address6, sizeof(l->tun.address6)) == 0
	       && memcmp(&l->tun.peer6, &r->tun.peer6, sizeof(l->tun.peer6)) == 0
#endif
	       ;
}

static void config_print(void)
{
	LOG_DBG("%-16s: '%s'", "lan.ssid", config.lan.ssid);
	LOG_DBG("%-16s: '%s'", "lan.psk", config.lan.psk);
	LOG_DBG("%-16s: %s/%u", "lan.address6",
		net_sprint_addr(NET_AF_INET6, &config.lan.address6.addr), config.lan.address6.prefix);

	LOG_DBG("%-16s: '%s'", "wan.ssid", config.wan.ssid);
	LOG_DBG("%-16s: '%s'", "wan.psk", config.wan.psk);

	LOG_DBG("%-16s: %s:%d", "tun.endpoint",
		net_sprint_addr(NET_AF_INET, &config.tun.endpoint.sin_addr),
		net_ntohs(config.tun.endpoint.sin_port));
	LOG_DBG("%-16s: %d", "tun.local_port", config.tun.local_port);
	LOG_DBG("%-16s: '%s'", "tun.psk", config.tun.psk);
	LOG_DBG("%-16s: %zu", "tun.keepalive", config.tun.keepalive_secs);
	LOG_DBG("%-16s: %d", "tun.mtu", config.tun.mtu);
}

static int config_set(const char *buf, size_t len)
{
	int ret;
	static struct config new;

	memset(&new, 0, sizeof(new));

	LOG_DBG("config_set %zu", len);

	ret = config_load(&new, buf, len);
	if (ret != 0) {
		return ret;
	}

	/* config is valid -- save it to flash even if params stay the same */
	memcpy(config_toml, buf, len);
	config_toml[len] = 0;
	ret = settings_save();
	if (ret != 0) {
		REPORT("cannot save settings");
		return ret;
	}
	LOG_INF("settings saved");

	/* check for any actual change in parameters and make a cascading reload */
	if (!config_eq_lan(&config, &new)) {
		memcpy(&config, &new, sizeof(struct config));
		REPORT("accepted and saved, reloading lan, wan and tun");
		event_post(EVENT_CONF_LAN);
	} else if (!config_eq_wan(&config, &new)) {
		memcpy(&config, &new, sizeof(struct config));
		REPORT("accepted and saved, reloading wan and tun");
		event_post(EVENT_CONF_WAN);
	} else if (!config_eq_tun(&config, &new)) {
		memcpy(&config, &new, sizeof(struct config));
		REPORT("accepted and saved, reloading tun");
		event_post(EVENT_CONF_TUN);
	} else {
		REPORT("accepted and saved, nothing to reload");
	}

	return 0;
}

static int config_get_handler(enum http_transaction_status status,
			      struct http_response_ctx *response_ctx)
{
	switch (status) {
	case HTTP_SERVER_TRANSACTION_ABORTED:
		LOG_DBG("aborting transaction");
		/* fallthrough */
	case HTTP_SERVER_TRANSACTION_COMPLETE:
		return 0;

	case HTTP_SERVER_REQUEST_DATA_MORE:
		LOG_DBG("unexpected data fragments for http get");
		return 0;

	case HTTP_SERVER_REQUEST_DATA_FINAL:
		LOG_DBG("responding with config toml");
		response_ctx->body = config_toml;
		response_ctx->body_len = strlen(config_toml);
		response_ctx->final_chunk = true;
		return 0;

	default:
		LOG_ERR("unhandled http req %d", status);
		return -EINVAL;
	}
}

static int config_handler(struct http_client_ctx *client, enum http_transaction_status status,
			  const struct http_request_ctx *request_ctx,
			  struct http_response_ctx *response_ctx, void *user_data)
{
	ARG_UNUSED(user_data);

	static char *payload;
	static size_t payload_size;
	static char *report;
	int ret, len;

	/* TODO Check Content-Type */

	if (client->method == HTTP_GET) {
		return config_get_handler(status, response_ctx);
	}

	if (client->method != HTTP_POST) {
		LOG_DBG("unsupported http method %d", client->method);
		response_ctx->status = HTTP_405_METHOD_NOT_ALLOWED;
		response_ctx->final_chunk = true;
		return -ECONNRESET;
	}

	switch (status) {
	case HTTP_SERVER_TRANSACTION_ABORTED:
		LOG_DBG("aborting transaction");
		/* fallthrough */
	case HTTP_SERVER_TRANSACTION_COMPLETE:
		LOG_DBG("freeing req payload");
		if (payload) {
			k_free(payload);
			payload = NULL;
			payload_size = 0;
		}
		if (report) {
			k_free(report);
			report = NULL;
		}
		return 0;

	case HTTP_SERVER_REQUEST_DATA_MORE:
	case HTTP_SERVER_REQUEST_DATA_FINAL:
		if (!payload) {
			LOG_DBG("allocating %d bytes for req payload", HTTP_CONFIG_PAYLOAD_SIZE);
			payload = k_malloc(HTTP_CONFIG_PAYLOAD_SIZE);
			if (!payload) {
				LOG_DBG("cannot allocate");
				response_ctx->status = HTTP_500_INTERNAL_SERVER_ERROR;
				return -ECONNRESET;
			}
		}
		if (payload_size + request_ctx->data_len > HTTP_CONFIG_PAYLOAD_SIZE - 1) {
			LOG_DBG("cannot append fragment size %zu", request_ctx->data_len);
			response_ctx->status = HTTP_413_PAYLOAD_TOO_LARGE;
			return -ECONNRESET;
		}

		LOG_DBG("appending fragment size %zu", request_ctx->data_len);
		memcpy(payload + payload_size, request_ctx->data, request_ctx->data_len);
		payload_size += request_ctx->data_len;

		if (status == HTTP_SERVER_REQUEST_DATA_MORE) {
			/* More fragments to follow until the final fragment. */
			return 0;
		}

		LOG_DBG("final fragment received");
		/* tomlc17 expects a null-terminated input */
		payload[payload_size] = '\0';

		ret = config_set(payload, payload_size);

		const char resp_fmt[] = "{\n"
				" \"status\": %d,\n"
				" \"report\": \"%s\"\n"
			"}\n";

		const size_t report_len = sizeof(resp_fmt) + sizeof(http_post_report);
		report = k_malloc(report_len);
		if (report) {
			/* TODO Escape http_post_report string */
			len = snprintf(report, report_len, resp_fmt, ret, http_post_report);
			response_ctx->body = report;
			response_ctx->body_len = len;
		} else {
			LOG_ERR("cannot allocate a buffer for json report");
		}

		/* TODO Set Content-Type: application/json */

		response_ctx->status = (ret == 0) ? HTTP_200_OK : HTTP_400_BAD_REQUEST;
		response_ctx->final_chunk = true;

		LOG_DBG("status %d", response_ctx->status);
		LOG_DBG("report %s", report);

		return 0;

	default:
		LOG_ERR("unhandled http req %d", status);
		return -EINVAL;
	}
}

static int status_handler(struct http_client_ctx *client, enum http_transaction_status status,
			  const struct http_request_ctx *request_ctx,
			  struct http_response_ctx *response_ctx, void *user_data)
{
	ARG_UNUSED(user_data);
	ARG_UNUSED(request_ctx);

	static char *payload;
	size_t len;

	if (client->method != HTTP_GET) {
		LOG_DBG("unsupported http method %d", client->method);
		response_ctx->status = HTTP_405_METHOD_NOT_ALLOWED;
		response_ctx->final_chunk = true;
		return -ECONNRESET;
	}

	switch (status) {
	case HTTP_SERVER_TRANSACTION_ABORTED:
		LOG_DBG("aborting transaction");
		/* fallthrough */
	case HTTP_SERVER_TRANSACTION_COMPLETE:
		if (payload) {
			k_free(payload);
			payload = NULL;
		}
		return 0;

	case HTTP_SERVER_REQUEST_DATA_MORE:
		LOG_DBG("unexpected data fragments for http get");
		return 0;

	case HTTP_SERVER_REQUEST_DATA_FINAL:
		payload = k_malloc(HTTP_STATUS_PAYLOAD_SIZE);
		if (!payload) {
			LOG_DBG("cannot allocate %d bytes", HTTP_STATUS_PAYLOAD_SIZE);
			response_ctx->status = HTTP_500_INTERNAL_SERVER_ERROR;
			response_ctx->final_chunk = true;
			return -ECONNRESET;
		}
		len = status_json(payload, HTTP_STATUS_PAYLOAD_SIZE - 1);
		response_ctx->body = payload;
		response_ctx->body_len = len;
		response_ctx->final_chunk = true;
		return 0;

	default:
		LOG_ERR("unhandled http req %d", status);
		return -EINVAL;
	}
}

static struct http_resource_detail_static index_resource_detail = {
	.common = {
		.type = HTTP_RESOURCE_TYPE_STATIC,
		.bitmask_of_supported_http_methods = BIT(HTTP_GET),
		.content_encoding = "gzip",
	},
	.static_data = index_html_gz,
	.static_data_len = sizeof(index_html_gz),
};

static struct http_resource_detail_dynamic status_resource_detail = {
	.common = {
		.type = HTTP_RESOURCE_TYPE_DYNAMIC,
		.bitmask_of_supported_http_methods = BIT(HTTP_GET),
		.content_type = "application/json",
	},
	.cb = status_handler,
	.user_data = NULL,
};

static struct http_resource_detail_dynamic config_resource_detail = {
	.common = {
		.type = HTTP_RESOURCE_TYPE_DYNAMIC,
		.bitmask_of_supported_http_methods = BIT(HTTP_GET) | BIT(HTTP_POST),
		.content_type = "application/toml",
	},
	.cb = config_handler,
	.user_data = NULL,
};

static uint16_t http_service_port = 80;
HTTP_SERVICE_DEFINE(http_service, NULL, &http_service_port, 1, 3, NULL, NULL, NULL);
HTTP_RESOURCE_DEFINE(index_resource, http_service, "/", &index_resource_detail);
HTTP_RESOURCE_DEFINE(config_resource, http_service, "/api/config", &config_resource_detail);
HTTP_RESOURCE_DEFINE(uptime_resource, http_service, "/api/status", &status_resource_detail);
HTTP_SERVER_CONTENT_TYPE(json, "application/json");
HTTP_SERVER_CONTENT_TYPE(toml, "application/toml");

int config_init()
{
	int ret;
	ret = settings_subsys_init();
	if (ret != 0) {
		LOG_ERR("cannot init settings subsys (%d)", ret);
		return ret;
	}

	ret = settings_register(&settings_handler);
	if (ret != 0) {
		LOG_ERR("cannot register settings handlers (%d)", ret);
		return ret;
	}

	ret = settings_load();
	if (ret != 0) {
		LOG_ERR("cannot load settings (%d)", ret);
		return ret;
	}

	info.reboot_count += 1;
	ret = settings_save();
	if (ret != 0) {
		LOG_ERR("cannot update reboot count (%d)", ret);
		return ret;
	}

	settings_print();

	if (strlen(config_toml) == 0) {
		if (config_reset() == 0) {
			LOG_WRN("reset empty config to default");
		} else {
			LOG_ERR("cannot reset config");
		}
	}

	ret = config_load(&config, config_toml, strlen(config_toml));
	if (ret != 0) {
		LOG_ERR("cannot load config (%d)", ret);
		return ret;
	}

	LOG_INF("config loaded");

	config_print();

	ret = http_server_start();
	if (ret != 0) {
		LOG_ERR("cannot start http server (%d)", ret);
		return ret;
	}

	LOG_INF("http server started");
	return 0;
}

int config_save()
{
	int ret = settings_save();
	if (ret != 0) {
		LOG_ERR("cannot save settings (%d)", ret);
		return ret;
	}
	return 0;
}

int config_reset()
{
	int ret;
	size_t size = sizeof(default_config_toml);
	memcpy(config_toml, default_config_toml, size);
	config_toml[size] = 0;
	ret = config_load(&config, config_toml, strlen(config_toml));
	if (ret != 0) {
		return ret;
	}
	return config_save();
}
