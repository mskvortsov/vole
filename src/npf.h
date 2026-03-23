#ifndef _NPF_H_
#define _NPF_H_

#include <zephyr/net/net_if.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/net_ip.h>

int npf_start(struct net_if *iface_lan, struct net_if *iface_wan, struct net_if *iface_tun);
int npf_stop(void);
void clamp_mss(struct net_pkt *pkt, uint16_t max_mss);

static inline uint16_t ipv4_chksum_ttl_dec(uint16_t chksum_net)
{
	uint32_t chksum = net_ntohs(chksum_net);
	chksum += 0x0100;
	chksum = (chksum & 0xffff) + (chksum >> 16);
	return net_htons(chksum);
}

#endif
