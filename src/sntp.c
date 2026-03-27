#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(sntp, LOG_LEVEL_INF);

#include <zephyr/kernel.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/sntp.h>

#include "wifi.h"

/* from europe.pool.ntp.org */
#define SNTP_SERVER  "195.186.1.101"
#define SNTP_PORT    123
#define SNTP_TIMEOUT 1000

int64_t sntp_time(void)
{
	struct sntp_ctx ctx = {0};
	struct sntp_time ts;
	struct net_sockaddr_in sntp_addr = {
		.sin_family = AF_INET,
		.sin_port = net_htons(SNTP_PORT),
	};
	struct net_in_addr *src;
	struct net_sockaddr_in local_addr = {
		.sin_family = AF_INET,
		.sin_port = 0,
	};
	int ret;

	ret = net_addr_pton(AF_INET, SNTP_SERVER, &sntp_addr.sin_addr);
	if (ret != 0) {
		return ret;
	}

	src = net_if_ipv4_get_global_addr(wan_get_iface(), NET_ADDR_PREFERRED);
	if (!src) {
		return -EINVAL;
	}
	memcpy(&local_addr.sin_addr, src, sizeof(struct net_in_addr));

	ctx.sock.fd = zsock_socket(AF_INET, NET_SOCK_DGRAM, IPPROTO_UDP);
	if (ctx.sock.fd < 0) {
		return -errno;
	}

	ret = zsock_bind(ctx.sock.fd, (struct net_sockaddr *)&local_addr,
			 sizeof(struct net_sockaddr_in));
	if (ret < 0) {
		zsock_close(ctx.sock.fd);
		return -errno;
	}

	ret = zsock_connect(ctx.sock.fd, (struct net_sockaddr *)&sntp_addr,
			    sizeof(struct net_sockaddr_in));
	if (ret < 0) {
		zsock_close(ctx.sock.fd);
		return -errno;
	}

	ctx.sock.fds[0].fd = ctx.sock.fd;
	ctx.sock.fds[0].events = ZSOCK_POLLIN;
	ctx.sock.nfds = 1;

	ret = sntp_query(&ctx, SNTP_TIMEOUT, &ts);
	sntp_close(&ctx);
	if (ret != 0) {
		return ret;
	}

	return ts.seconds * MSEC_PER_SEC + (((uint64_t)ts.fraction * MSEC_PER_SEC) >> 32);
}
