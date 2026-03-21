#ifndef _RA_H_
#define _RA_H_

#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>

/*
 * Start sending IPv6 Router Advertisements on @iface.
 *
 * Sends an unsolicited RA immediately and then every RA_INTERVAL_S seconds.
 * Responds to Router Solicitations with a solicited RA.
 *
 * The RA advertises @prefix/@prefix_len with the L and A flags set (SLAAC),
 * includes an RDNSS option pointing at @dns, and a PREF64 option for the
 * NAT64 /96 prefix @nat64 (RFC 8781).
 */
int ra_start(struct net_if *iface, const struct net_in6_addr *prefix, uint8_t prefix_len,
	     const struct net_in6_addr *dns, size_t dns_num, const struct net_in6_addr *nat64,
	     uint32_t mtu);

void ra_stop(void);

#endif
