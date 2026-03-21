#ifndef _NPF_H_
#define _NPF_H_

#include <zephyr/net/net_if.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/net_ip.h>

int npf_start(struct net_if *iface_lan, struct net_if *iface_wan, struct net_if *iface_tun);
int npf_stop(void);
void clamp_mss(struct net_pkt *pkt, uint16_t max_mss);
int route_tun(struct net_pkt *pkt, struct net_ipv4_hdr *ip_hdr);

#endif
