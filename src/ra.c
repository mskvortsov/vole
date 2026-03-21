#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(ra, CONFIG_RA_LOG_LEVEL);

#include <zephyr/kernel.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/icmp.h>

#include "net_private.h"
#include "icmpv6.h"
#include "ipv6.h"

#include "ra.h"

/* RFC 4861 §6.2.1 defaults. */
#define RA_INTERVAL_S      200U   /* seconds between unsolicited RAs         */
#define RA_LIFETIME_S      1800U  /* router lifetime (3 × MaxRtrAdvInterval) */
#define RA_VALID_LFT_S     86400U /* prefix valid lifetime                   */
#define RA_PREFERRED_LFT_S 14400U /* prefix preferred lifetime               */
#define RA_RDNSS_LFT_S     1200U  /* >= 2 × MaxRtrAdvInterval                */
#define RA_HOP_LIMIT       64U

/* RFC 8781 PREF64 option, type 38. */
#define NET_ICMPV6_ND_OPT_PREF64 38U

static struct net_if *ra_iface;
static struct net_in6_addr ra_prefix;
static uint8_t ra_prefix_len;
static size_t ra_dns_num;
static const struct net_in6_addr *ra_dns_array;
static struct net_in6_addr ra_nat64; /* NAT64 prefix (/96) for PREF64 option */
static uint32_t ra_mtu;

static struct k_work_delayable ra_work;
static struct net_icmp_ctx rs_ctx;

static int send_ra(struct net_if *iface, const struct net_in6_addr *dst)
{
	NET_PKT_DATA_ACCESS_CONTIGUOUS_DEFINE(ra_access, struct net_icmpv6_ra_hdr);
	const struct net_linkaddr *ll = net_if_get_link_addr(iface);
	struct net_pkt *pkt;
	struct net_icmpv6_ra_hdr *ra_hdr;
	const struct net_in6_addr *src = net_if_ipv6_get_ll(iface, NET_ADDR_PREFERRED);
	if (!src) {
		LOG_DBG("cannot get src address for ra packet");
		return -ENOENT;
	}

	/*
	 * Packet payload after the ICMPv6 header:
	 *   RA header:          12 bytes
	 *   Source LL option:    8 bytes  (len = 1 × 8)
	 *   MTU option:          8 bytes  (len = 1 × 8)
	 *   Prefix option:      32 bytes  (len = 4 × 8)
	 *   RDNSS option:  8 + 16×N bytes  (len = (1 + 2×N) × 8, one option for all servers)
	 *   PREF64 option:      16 bytes  (len = 2 × 8)
	 */
	pkt = net_pkt_alloc_with_buffer(
		iface,
		sizeof(struct net_icmpv6_ra_hdr) + 8 + 8 + 32 +
			(ra_dns_num > 0 ? 8 + 16 * ra_dns_num : 0) + 16,
		NET_AF_INET6, NET_IPPROTO_ICMPV6,
		K_MSEC(100));
	if (!pkt) {
		LOG_ERR("cannot allocate ra packet");
		return -ENOMEM;
	}

	net_pkt_set_ipv6_hop_limit(pkt, NET_IPV6_ND_HOP_LIMIT);

	if (net_ipv6_create(pkt, src, dst) ||
	    net_icmpv6_create(pkt, NET_ICMPV6_RA, 0)) {
		goto drop;
	}

	/* RA fixed header. */
	ra_hdr = net_pkt_get_data(pkt, &ra_access);
	if (!ra_hdr) {
		goto drop;
	}

	memset(ra_hdr, 0, sizeof(*ra_hdr));
	ra_hdr->cur_hop_limit  = RA_HOP_LIMIT;
	ra_hdr->router_lifetime = net_htons(RA_LIFETIME_S);

	if (net_pkt_set_data(pkt, &ra_access)) {
		goto drop;
	}

	/* Source Link-Layer Address option (type=1, len=1, 8 bytes total). */
	if (net_pkt_write_u8(pkt, NET_ICMPV6_ND_OPT_SLLAO) ||
	    net_pkt_write_u8(pkt, 1) ||
	    net_pkt_write(pkt, ll->addr, 6)) {
		goto drop;
	}

	/* MTU option (RFC 4861 §4.6.4, type=5, len=1, 8 bytes total). */
	if (net_pkt_write_u8(pkt, NET_ICMPV6_ND_OPT_MTU) ||
	    net_pkt_write_u8(pkt, 1) ||
	    net_pkt_write_be16(pkt, 0) ||   /* reserved */
	    net_pkt_write_be32(pkt, ra_mtu)) {
		goto drop;
	}

	/* Prefix Information option (type=3, len=4, 32 bytes total). */
	if (net_pkt_write_u8(pkt, NET_ICMPV6_ND_OPT_PREFIX_INFO) ||
	    net_pkt_write_u8(pkt, 4) ||
	    net_pkt_write_u8(pkt, ra_prefix_len) ||
	    net_pkt_write_u8(pkt, NET_ICMPV6_RA_FLAG_ONLINK |
				  NET_ICMPV6_RA_FLAG_AUTONOMOUS) ||
	    net_pkt_write_be32(pkt, RA_VALID_LFT_S) ||
	    net_pkt_write_be32(pkt, RA_PREFERRED_LFT_S) ||
	    net_pkt_write_be32(pkt, 0) ||   /* reserved */
	    net_pkt_write(pkt, ra_prefix.s6_addr, NET_IPV6_ADDR_SIZE)) {
		goto drop;
	}

	if (ra_dns_num > 0) {
		/* RDNSS option (RFC 8106, type=25): all servers in one option.
		 * len = 1 + 2×N in units of 8, i.e. 8 + 16×N bytes total. */
		if (net_pkt_write_u8(pkt, NET_ICMPV6_ND_OPT_RDNSS) ||
		    net_pkt_write_u8(pkt, 1 + 2 * ra_dns_num) ||
		    net_pkt_write_be16(pkt, 0) ||   /* reserved */
		    net_pkt_write_be32(pkt, RA_RDNSS_LFT_S)) {
			goto drop;
		}
		for (size_t i = 0; i < ra_dns_num; ++i) {
			if (net_pkt_write(pkt, ra_dns_array[i].s6_addr, NET_IPV6_ADDR_SIZE)) {
				goto drop;
			}
		}
	}

	/* PREF64 option (RFC 8781, type=38, len=2, 16 bytes total).
	 * Scaled Lifetime = RA_RDNSS_LFT_S/8 in the upper 13 bits; PLC=0 for /96 in lower 3. */
	if (net_pkt_write_u8(pkt, NET_ICMPV6_ND_OPT_PREF64) ||
	    net_pkt_write_u8(pkt, 2) ||
	    net_pkt_write_be16(pkt, (RA_RDNSS_LFT_S / 8) << 3 /* PLC=0 for /96 */) ||
	    net_pkt_write(pkt, ra_nat64.s6_addr, 12)) {   /* first 96 bits */
		goto drop;
	}

	net_pkt_cursor_init(pkt);
	net_ipv6_finalize(pkt, NET_IPPROTO_ICMPV6);

	/* With CONFIG_NET_L2_ETHERNET_RESERVE_HEADER=y, ethernet_fill_header()
	 * calls net_buf_push() before ethernet_fill_in_dst_on_ipv6_mcast(),
	 * shifting pkt->frags->data so NET_IPV6_HDR(pkt)->dst no longer points
	 * at the IPv6 destination.  The multicast-MAC mapping never fires and
	 * the fallback copies net_pkt_lladdr_dst->addr into the Ethernet
	 * header.  Set it explicitly to ensure 33:33:00:00:00:01 is used.
	 */
	static const uint8_t all_nodes_mac[] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
	net_linkaddr_set(net_pkt_lladdr_dst(pkt), all_nodes_mac, sizeof(all_nodes_mac));

	if (net_send_data(pkt) != 0) {
		goto drop;
	}

	LOG_DBG("sent ra to %s", net_sprint_addr(NET_AF_INET6, dst));

	return 0;

drop:
	LOG_DBG("cannot sent ra to %s", net_sprint_addr(NET_AF_INET6, dst));
	net_pkt_unref(pkt);
	return -EIO;
}

static void ra_work_handler(struct k_work *work)
{
	struct net_in6_addr allnodes;

	ARG_UNUSED(work);

	net_ipv6_addr_create_ll_allnodes_mcast(&allnodes);

	if (send_ra(ra_iface, &allnodes) == -ENOENT) {
		/* Link-local address not ready yet (DAD in progress); retry. */
		k_work_schedule(&ra_work, K_SECONDS(1));
		return;
	}

	k_work_schedule(&ra_work, K_SECONDS(RA_INTERVAL_S));
}

static enum net_verdict handle_rs_input(struct net_icmp_ctx *ctx, struct net_pkt *pkt,
					struct net_icmp_ip_hdr *hdr, struct net_icmp_hdr *icmp_hdr,
					void *user_data)
{
	struct net_in6_addr allnodes;

	ARG_UNUSED(ctx);
	ARG_UNUSED(hdr);
	ARG_UNUSED(icmp_hdr);
	ARG_UNUSED(user_data);

	net_ipv6_addr_create_ll_allnodes_mcast(&allnodes);
	send_ra(net_pkt_iface(pkt), &allnodes);

	return NET_OK;
}

int ra_start(struct net_if *iface, const struct net_in6_addr *prefix, uint8_t prefix_len,
	     const struct net_in6_addr *dns, size_t dns_num, const struct net_in6_addr *nat64,
	     uint32_t mtu)
{
	struct net_in6_addr allrouters;
	struct net_if_mcast_addr *maddr;
	int ret;

	LOG_DBG("iface %s prefix %s/%d nat64 %s mtu %u", net_if_get_config(iface)->name,
		net_sprint_addr(NET_AF_INET6, prefix), prefix_len,
		net_sprint_addr(NET_AF_INET6, nat64), mtu);
	for (size_t i = 0; i < dns_num; ++i) {
		LOG_DBG("dns %s", net_sprint_addr(NET_AF_INET6, &dns[i]));
	}

	ra_iface = iface;
	net_ipv6_addr_copy_raw(ra_prefix.s6_addr, prefix->s6_addr);
	ra_prefix_len = prefix_len;
	ra_dns_num = dns_num;
	ra_dns_array = dns;
	net_ipv6_addr_copy_raw(ra_nat64.s6_addr, nat64->s6_addr);
	ra_mtu = mtu;

	/* Join ff02::2 so Router Solicitations reach us. */
	net_ipv6_addr_create_ll_allrouters_mcast(&allrouters);
	maddr = net_if_ipv6_maddr_add(iface, &allrouters);
	if (maddr) {
		net_if_ipv6_maddr_join(iface, maddr);
	}

	ret = net_icmp_init_ctx(&rs_ctx, NET_AF_INET6, NET_ICMPV6_RS, 0, handle_rs_input);
	if (ret != 0) {
		LOG_ERR("cannot register RS handler (%d)", ret);
		return ret;
	}

	k_work_init_delayable(&ra_work, ra_work_handler);
	k_work_schedule(&ra_work, K_NO_WAIT);

	return 0;
}

void ra_stop(void)
{
	struct k_work_sync sync;
	struct net_in6_addr allrouters;

	k_work_cancel_delayable_sync(&ra_work, &sync);
	net_icmp_cleanup_ctx(&rs_ctx);

	net_ipv6_addr_create_ll_allrouters_mcast(&allrouters);
	net_if_ipv6_maddr_rm(ra_iface, &allrouters);

	ra_iface = NULL;
}
