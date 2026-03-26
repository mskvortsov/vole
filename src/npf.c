#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(npf, CONFIG_NPF_LOG_LEVEL);

#include <zephyr/kernel.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/net_pkt_filter.h>
#include <zephyr/net/dhcpv4_server.h>

#include <zephyr/sys/clock.h>
#include <zephyr/sys/util.h>

#include "net_private.h"
#include "ipv4.h"
#if defined(CONFIG_NET_IPV6)
#include "ipv6.h"
#include "icmpv6.h"
#endif
#include "icmpv4.h"
#include "tcp_internal.h"

#include "config.h"
#include "npf.h"

#define NET_ICMPV4_FRAGMENTATION_REQUIRED   4
#define NET_ICMPV4_FRAGMENTATION_ORIG_BYTES 64

#if defined(CONFIG_NET_IPV6)
/* 1280 (min IPv6 MTU) - 40 (IPv6 hdr) - 4 (ICMPv6 hdr) - 4 (PTB MTU field) */
#define NET_ICMPV6_PTB_ORIG_BYTES 1232
#endif

#define ICMP_RATE_LIMIT_ENTRIES_NUM 8
#define ICMP_RATE_LIMIT_TIMEOUT     K_SECONDS(1)
#define ICMP_PKT_ALLOC_TIME         K_MSEC(50)

/* RFC 6691 */
#define IPV4_TCP_MSS_OVERHEAD (sizeof(struct net_ipv4_hdr) + sizeof(struct net_tcp_hdr))
#if defined(CONFIG_NET_IPV6)
#define IPV6_TCP_MSS_OVERHEAD (sizeof(struct net_ipv6_hdr) + sizeof(struct net_tcp_hdr))
#endif

struct icmp_rate_limit_entry {
	bool used;
	struct net_addr addr;
	k_timepoint_t denial_expires;
};

static struct {
	struct net_if *iface_lan;
	struct net_if *iface_wan;
	struct net_if *iface_tun;
	struct net_in_addr wan_address;
	size_t tun_mtu;

	struct k_work icmp_work;
	struct k_fifo icmp_tx_fifo;
	struct icmp_rate_limit_entry icmp_rate_limited[ICMP_RATE_LIMIT_ENTRIES_NUM];
	struct k_mutex icmp_lock;

	bool status;
} ctx;

#define LOG_PKT_IPV4(message, pkt, ip_hdr)                                                         \
	LOG_DBG("%s: [rx %12lld] %s -> %s", message, net_pkt_timestamp_ns(pkt) / NSEC_PER_USEC,    \
		net_sprint_addr(AF_INET, ip_hdr->src), net_sprint_addr(AF_INET, ip_hdr->dst))

#if defined(CONFIG_NET_IPV6)
#define LOG_PKT_IPV6(message, pkt, ip_hdr)                                                         \
	LOG_DBG("%s: [rx %12lld] %s -> %s", message, net_pkt_timestamp_ns(pkt) / NSEC_PER_USEC,    \
		net_sprint_addr(AF_INET6, ip_hdr->src), net_sprint_addr(AF_INET6, ip_hdr->dst))
#endif

static size_t tcp_mss_opt_offset(uint8_t *opts, size_t opts_len)
{
	for (size_t i = 0; i < opts_len; ) {
		if (opts[i] == NET_TCP_END_OPT) {
			break;
		}
		if (opts[i] == NET_TCP_NOP_OPT) {
			i += NET_TCP_NOP_SIZE;
			continue;
		}
		if (i + 1 >= opts_len) {
			break;
		}

		uint8_t kind = opts[i];
		uint8_t olen = opts[i + 1];

		if (olen < 2 || i + olen > opts_len) {
			break;
		}
		if (kind == NET_TCP_MSS_OPT && olen == NET_TCP_MSS_SIZE) {
			return i + 2;
		}
		i += olen;
	}
	return 0;
}

/*
 * Clamp the TCP MSS option in a SYN packet to max_mss.
 * Cursor must be positioned at the start of the TCP header on entry.
 */
void clamp_mss(struct net_pkt *pkt, uint16_t max_mss)
{
	NET_PKT_DATA_ACCESS_DEFINE(tcp_access, struct net_tcp_hdr);
	struct net_pkt_cursor tcp_start, opts_start;
	struct net_tcp_hdr *tcp_hdr;
	size_t tcp_hlen, opts_len;
	size_t mss_offset = 0;
	uint32_t chksum;
	uint8_t opts[40];

	net_pkt_cursor_backup(pkt, &tcp_start);

	tcp_hdr = net_pkt_get_data(pkt, &tcp_access);
	if (!tcp_hdr || !(tcp_hdr->flags & SYN)) {
		return;
	}
	if (net_pkt_skip(pkt, sizeof(struct net_tcp_hdr)) != 0) {
		return;
	}

	/* Cursor is now at TCP options. */
	tcp_hlen = (tcp_hdr->offset >> 4) * 4;
	if (tcp_hlen <= sizeof(struct net_tcp_hdr)) {
		/* No options, no MSS to clamp. */
		return;
	}

	net_pkt_cursor_backup(pkt, &opts_start);

	opts_len = tcp_hlen - sizeof(struct net_tcp_hdr);
	if (opts_len > 40 || net_pkt_read(pkt, opts, opts_len) != 0) {
		return;
	}

	mss_offset = tcp_mss_opt_offset(opts, opts_len);
	if (!mss_offset) {
		return;
	}

	uint16_t mss = ((uint16_t)opts[mss_offset] << 8) | opts[mss_offset + 1];
	if (mss <= max_mss) {
		return;
	}

	uint16_t old_mss_net = net_htons(mss);
	uint16_t new_mss_net = net_htons(max_mss);

	net_pkt_cursor_restore(pkt, &opts_start);
	if (net_pkt_skip(pkt, mss_offset) != 0 ||
	    net_pkt_write(pkt, &new_mss_net, sizeof(new_mss_net)) != 0) {
		LOG_ERR("cannot write tcp mss");
		return;
	}

	net_pkt_cursor_restore(pkt, &tcp_start);
	tcp_hdr = net_pkt_get_data(pkt, &tcp_access);
	if (!tcp_hdr) {
		LOG_ERR("cannot get tcp header");
		return;
	}

	chksum = (uint16_t)~tcp_hdr->chksum + (uint16_t)~old_mss_net + new_mss_net;
	chksum = (chksum >> 16) + (chksum & 0xffff);
	tcp_hdr->chksum = (uint16_t)~chksum;
	net_pkt_set_data(pkt, &tcp_access);

	LOG_DBG("clamped tcp mss from %u to %u", mss, max_mss);
}

static bool npf_test_recv_fn(struct npf_test *t, struct net_pkt *pkt)
{
	NET_PKT_DATA_ACCESS_DEFINE(eth_access, struct net_eth_hdr);
	NET_PKT_DATA_ACCESS_DEFINE(ipv4_access, struct net_ipv4_hdr);
	struct net_eth_hdr *eth_hdr;
	struct net_ipv4_hdr *ip_hdr;
	struct net_pkt_cursor backup;
	struct net_if *iface = net_pkt_iface(pkt);
	int ret;

	ARG_UNUSED(t);

	/* First, process IPv4 packets coming from TUN. */
	if (net_pkt_family(pkt) == NET_AF_INET && iface == ctx.iface_tun) {
		ip_hdr = net_pkt_get_data(pkt, &ipv4_access);
		if (!ip_hdr) {
			LOG_ERR("cannot get ipv4 header");
			return false;
		}

		/* Pass input packets destined for the TUN interface address. */
		if (net_ipv4_addr_cmp_raw(ip_hdr->dst, config.tun.address4.addr.s4_addr)) {
			LOG_PKT_IPV4("tun input", pkt, ip_hdr);
			return true;
		}

		/* Forward source-NAT-ed packets to the WAN interface. */
		if (net_ipv4_addr_cmp_raw(ip_hdr->src, ctx.wan_address.s4_addr)) {
			LOG_PKT_IPV4("wan forward", pkt, ip_hdr);
			net_pkt_set_iface(pkt, ctx.iface_wan);
			net_pkt_ref(pkt);
			if (net_try_send_data(pkt, K_NO_WAIT) != 0) {
				net_pkt_unref(pkt);
			}
			return false;
		}

		/* Forward everything else to the LAN interface. */
		if (!ctx.iface_lan) {
			LOG_WRN("no lan iface, dropping packet");
			return false;
		}
		LOG_PKT_IPV4("lan forward", pkt, ip_hdr);
		net_pkt_set_iface(pkt, ctx.iface_lan);
		net_pkt_ref(pkt);
		if (net_try_send_data(pkt, K_NO_WAIT) != 0) {
			net_pkt_unref(pkt);
		}

		return false;
	}

#if defined(CONFIG_NET_IPV6)
	/* Second, process IPv6 packets coming from TUN: redirect to the correct
	 * interface if the destination address belongs to us. */
	if (net_pkt_family(pkt) == NET_AF_INET6 && iface == ctx.iface_tun) {
		NET_PKT_DATA_ACCESS_CONTIGUOUS_DEFINE(ipv6_access, struct net_ipv6_hdr);
		struct net_ipv6_hdr *ip6_hdr = net_pkt_get_data(pkt, &ipv6_access);
		if (ip6_hdr) {
			struct net_if *dst_iface = NULL;
			net_if_ipv6_addr_lookup_raw(ip6_hdr->dst, &dst_iface);
			if (dst_iface && dst_iface != ctx.iface_tun) {
				LOG_PKT_IPV6("tun ipv6 redir", pkt, ip6_hdr);
				net_pkt_set_iface(pkt, dst_iface);
			}
		}
		return true;
	}
#endif

	/* Third, process Ethernet packets coming from LAN and WAN. */
	if (iface != ctx.iface_lan && iface != ctx.iface_wan) {
		return true;
	}

	if (net_pkt_family(pkt) != NET_AF_UNSPEC) {
		LOG_DBG("skipping pre-classified packet family %u", net_pkt_family(pkt));
		return true;
	}

	eth_hdr = net_pkt_get_data(pkt, &eth_access);
	if (!eth_hdr) {
		LOG_ERR("cannot get ethernet header");
		return true;
	}

	if (eth_hdr->type != net_htons(NET_ETH_PTYPE_IP)) {
		return true;
	}

	net_pkt_cursor_backup(pkt, &backup);

	ret = net_pkt_skip(pkt, sizeof(struct net_eth_hdr));
	if (ret != 0) {
		LOG_ERR("cannot skip ethernet header");
		goto pass;
	}

	ip_hdr = net_pkt_get_data(pkt, &ipv4_access);
	if (!ip_hdr) {
		LOG_ERR("cannot get ipv4 header");
		goto pass;
	}

	/* Pass packets from outside the WAN subnet. */
	if (iface == ctx.iface_wan &&
	    !net_if_ipv4_addr_mask_cmp(ctx.iface_wan, (const struct net_in_addr *)ip_hdr->src)) {
		goto pass;
	}

	/* Pass broadcast/multicast. */
	if ((ctx.iface_lan && net_ipv4_is_addr_bcast_raw(ctx.iface_lan, ip_hdr->dst)) ||
	    net_ipv4_is_addr_bcast_raw(ctx.iface_wan, ip_hdr->dst) ||
	    net_ipv4_is_addr_mcast_raw(ip_hdr->dst)) {
		goto pass;
	}

	/* WAN reply packets (dst == our WAN IP): pass DHCP and optionally HTTP,
	 * forward the rest to tunnel. */
	if (net_ipv4_addr_cmp_raw(ip_hdr->dst, ctx.wan_address.s4_addr)) {
		uint8_t ip_hlen = (ip_hdr->vhl & 0x0f) * 4;
		if (net_pkt_skip(pkt, ip_hlen) != 0) {
			goto pass;
		}

		if (ip_hdr->proto == NET_IPPROTO_UDP) {
			NET_PKT_DATA_ACCESS_DEFINE(udp_access, struct net_udp_hdr);
			struct net_udp_hdr *udp_hdr = net_pkt_get_data(pkt, &udp_access);
			if (!udp_hdr || net_htons(udp_hdr->dst_port) == 68) {
				goto pass;
			}
		} else if (ip_hdr->proto == NET_IPPROTO_TCP && config.wan.http) {
			NET_PKT_DATA_ACCESS_DEFINE(tcp_access, struct net_tcp_hdr);
			struct net_tcp_hdr *tcp_hdr = net_pkt_get_data(pkt, &tcp_access);
			if (!tcp_hdr || net_htons(tcp_hdr->dst_port) == 80) {
				goto pass;
			}
		}
	}

	/* LAN client packets and WAN reply packets: strip Ethernet header, decrement TTL,
	 * clamp MSS, forward to tunnel.
	 */
	net_buf_pull(pkt->frags, sizeof(struct net_eth_hdr));
	net_pkt_cursor_init(pkt);

	net_pkt_set_family(pkt, NET_AF_INET);
	net_pkt_set_ll_proto_type(pkt, NET_ETH_PTYPE_IP);
	net_pkt_set_iface(pkt, ctx.iface_tun);

	/* Decrement TTL, update IP header checksum. */
	if (ip_hdr->ttl == 0) {
		LOG_WRN("drop due to zero ttl");
		return false;
	}
	ip_hdr->ttl -= 1;
	ip_hdr->chksum = ipv4_chksum_ttl_dec(ip_hdr->chksum);
	ret = net_pkt_set_data(pkt, &ipv4_access);
	if (ret != 0) {
		LOG_ERR("cannot update ipv4 header (%d)", ret);
		return false;
	}

	/* Packet will be unreferenced on return, but we want to forward it. */
	net_pkt_ref(pkt);

	/* Send to the tunnel. */
	net_pkt_cursor_init(pkt);
	ret = net_if_try_send_data(ctx.iface_tun, pkt, K_NO_WAIT);
	if (ret != NET_OK) {
		LOG_ERR("cannot forward to tun (%d)", ret);
		net_pkt_unref(pkt);
	}

	/* Signal the caller to stop processing the packet. */
	return false;

pass:
	net_pkt_cursor_restore(pkt, &backup);
	return true;
}

static struct npf_test npf_test_recv = {
	.fn = npf_test_recv_fn,
	IF_ENABLED(NPF_TEST_ENABLE_NAME,
	(.name = "npf_test_recv",))
};
static struct npf_rule npf_rule_recv = {
	.result = NET_OK,
	.nb_tests = 1,
	.tests = { &npf_test_recv },
};

static void icmp_worker(struct k_work *work)
{
	ARG_UNUSED(work);

	while (!k_fifo_is_empty(&ctx.icmp_tx_fifo)) {
		struct net_pkt *pkt = k_fifo_get(&ctx.icmp_tx_fifo, K_FOREVER);
		if (net_send_data(pkt) != 0) {
			net_pkt_unref(pkt);
		}
	}
}

static void send_icmpv4_unreach(struct net_if *iface, struct net_pkt *pkt_bad, uint16_t mtu)
{
	NET_PKT_DATA_ACCESS_DEFINE(ipv4_access, struct net_ipv4_hdr);
	NET_PKT_DATA_ACCESS_CONTIGUOUS_DEFINE(icmpv4_access, struct net_icmpv4_dest_unreach);
	struct net_ipv4_hdr *bad_ip_hdr = net_pkt_get_data(pkt_bad, &ipv4_access);
	struct net_icmpv4_dest_unreach *frag_needed;

	struct net_in_addr *dst = (struct net_in_addr *)bad_ip_hdr->src;
	const struct net_in_addr *src = net_if_ipv4_select_src_addr(iface, dst);

	size_t size = sizeof(struct net_icmpv4_dest_unreach) + NET_ICMPV4_FRAGMENTATION_ORIG_BYTES;
	struct net_pkt *pkt = net_pkt_alloc_with_buffer(iface, size, NET_AF_INET, NET_IPPROTO_ICMP,
							ICMP_PKT_ALLOC_TIME);
	if (!pkt) {
		LOG_ERR("cannot allocate fragmentation needed packet");
		return;
	}

	net_pkt_set_ipv4_ttl(pkt, net_if_ipv4_get_ttl(iface));

	if (net_ipv4_create(pkt, src, dst) ||
	    net_icmpv4_create(pkt, NET_ICMPV4_DST_UNREACH, NET_ICMPV4_FRAGMENTATION_REQUIRED)) {
		goto fail;
	}

	frag_needed = net_pkt_get_data(pkt, &icmpv4_access);
	if (!frag_needed) {
		goto fail;
	}

	frag_needed->unused = 0;
	frag_needed->mtu = net_htons(mtu);
	if (net_pkt_set_data(pkt, &icmpv4_access) != 0) {
		goto fail;
	}

	if (net_pkt_copy(pkt, pkt_bad, NET_ICMPV4_FRAGMENTATION_ORIG_BYTES) != 0) {
		goto fail;
	}

	net_pkt_cursor_init(pkt);
	if (net_ipv4_finalize(pkt, NET_IPPROTO_ICMP) != 0) {
		goto fail;
	}

	/* Send later from the system work queue thread. */
	k_fifo_put(&ctx.icmp_tx_fifo, pkt);
	k_work_submit(&ctx.icmp_work);

	return;

fail:
	LOG_ERR("cannot send fragmentation needed packet");
	net_pkt_unref(pkt);
}

#if defined(CONFIG_NET_IPV6)
static void send_icmpv6_ptb(struct net_if *iface, struct net_pkt *pkt_bad, uint16_t mtu)
{
	NET_PKT_DATA_ACCESS_CONTIGUOUS_DEFINE(ipv6_access, struct net_ipv6_hdr);
	struct net_ipv6_hdr *bad_ip_hdr;
	struct net_pkt *pkt;
	const struct net_in6_addr *src;
	const struct net_in6_addr *dst;

	net_pkt_cursor_init(pkt_bad);
	bad_ip_hdr = net_pkt_get_data(pkt_bad, &ipv6_access);
	if (!bad_ip_hdr) {
		LOG_ERR("cannot get ipv6 header");
		return;
	}

	dst = (struct net_in6_addr *)bad_ip_hdr->src;
	src = net_if_ipv6_select_src_addr(iface, dst);
	if (!src) {
		LOG_ERR("cannot select ipv6 src address");
		return;
	}

	size_t orig_bytes = MIN(net_pkt_get_len(pkt_bad), (size_t)NET_ICMPV6_PTB_ORIG_BYTES);
	size_t size = 4 + orig_bytes;

	pkt = net_pkt_alloc_with_buffer(iface, size, NET_AF_INET6, NET_IPPROTO_ICMPV6,
					ICMP_PKT_ALLOC_TIME);
	if (!pkt) {
		return;
	}

	net_pkt_set_ipv6_hop_limit(pkt, net_if_ipv6_get_hop_limit(iface));

	if (net_ipv6_create(pkt, src, dst) ||
	    net_icmpv6_create(pkt, NET_ICMPV6_PACKET_TOO_BIG, 0)) {
		goto fail;
	}

	if (net_pkt_write_be32(pkt, mtu)) {
		goto fail;
	}

	if (net_pkt_copy(pkt, pkt_bad, orig_bytes)) {
		goto fail;
	}

	net_pkt_cursor_init(pkt);
	if (net_ipv6_finalize(pkt, NET_IPPROTO_ICMPV6)) {
		goto fail;
	}

	k_fifo_put(&ctx.icmp_tx_fifo, pkt);
	k_work_submit(&ctx.icmp_work);
	return;

fail:
	LOG_ERR("cannot send icmpv6 ptb packet");
	net_pkt_unref(pkt);
}
#endif /* CONFIG_NET_IPV6 */

static inline bool net_addr_cmp(struct net_addr *lhs, struct net_addr *rhs)
{
	if (lhs->family != rhs->family) {
		return false;
	}

	if (lhs->family == NET_AF_INET) {
		return net_ipv4_addr_cmp_raw(lhs->net_in_addr.s4_addr, rhs->net_in_addr.s4_addr);
#if defined(CONFIG_NET_IPV6)
	} else if (lhs->family == NET_AF_INET6) {
		return net_ipv6_addr_cmp_raw(lhs->net_in6_addr.s6_addr, rhs->net_in6_addr.s6_addr);
#endif
	}

	LOG_ERR("unknown address family %d", lhs->family);
	return false;
}

static bool is_icmp_allowed(struct net_addr *addr)
{
	struct icmp_rate_limit_entry *vacant = NULL;
	k_mutex_lock(&ctx.icmp_lock, K_FOREVER);
	ARRAY_FOR_EACH_PTR(ctx.icmp_rate_limited, entry) {
		if (!entry->used) {
			if (!vacant) {
				vacant = entry;
			}
		} else if (sys_timepoint_expired(entry->denial_expires)) {
			if (net_addr_cmp(&entry->addr, addr)) {
				LOG_DBG("allowed again for %s",
					net_sprint_addr(addr->family, addr));
				entry->denial_expires = sys_timepoint_calc(ICMP_RATE_LIMIT_TIMEOUT);
				k_mutex_unlock(&ctx.icmp_lock);
				return true;
			} else {
				LOG_DBG("reset expired entry for %s",
					net_sprint_addr(addr->family, addr));
				entry->used = false;
				if (!vacant) {
					vacant = entry;
				}
			}
		} else if (net_addr_cmp(&entry->addr, addr)) {
			LOG_DBG("denied for %s", net_sprint_addr(addr->family, addr));
			k_mutex_unlock(&ctx.icmp_lock);
			return false;
		}
	}
	if (vacant) {
		LOG_DBG("created entry for %s", net_sprint_addr(addr->family, addr));
		memcpy(&vacant->addr, addr, sizeof(struct net_addr));
		vacant->denial_expires = sys_timepoint_calc(ICMP_RATE_LIMIT_TIMEOUT);
		k_mutex_unlock(&ctx.icmp_lock);
		return true;
	}
	LOG_DBG("all entries used");
	k_mutex_unlock(&ctx.icmp_lock);
	return false;
}

static bool npf_test_send_fn(struct npf_test *t, struct net_pkt *pkt)
{
	uint8_t family = net_pkt_family(pkt);
	NET_PKT_DATA_ACCESS_DEFINE(ipv4_access, struct net_ipv4_hdr);
	struct net_ipv4_hdr *ip_hdr;
#if defined(CONFIG_NET_IPV6)
	NET_PKT_DATA_ACCESS_DEFINE(ipv6_access, struct net_ipv6_hdr);
	struct net_ipv6_hdr *ip6_hdr;
#endif
	struct net_addr src;

	ARG_UNUSED(t);

	if (net_pkt_iface(pkt) != ctx.iface_tun) {
		return true;
	}

	if (family == NET_AF_INET) {
		ip_hdr = net_pkt_get_data(pkt, &ipv4_access);
		if (!ip_hdr) {
			LOG_ERR("cannot get ipv4 header");
			return true;
		}

		if (ip_hdr->proto == NET_IPPROTO_TCP) {
			/* Skip any IPv4 options beyond the standard 20-byte header. */
			uint8_t ip_hlen = (ip_hdr->vhl & 0x0f) * 4;
			if (ip_hlen > sizeof(struct net_ipv4_hdr)) {
				if (net_pkt_skip(pkt, ip_hlen - sizeof(struct net_ipv4_hdr)) != 0) {
					LOG_ERR("cannot skip ipv4 header options");
					return false;
				}
			}
			clamp_mss(pkt, ctx.tun_mtu - IPV4_TCP_MSS_OVERHEAD);
		}

		net_pkt_cursor_init(pkt);

		if (net_pkt_get_len(pkt) <= ctx.tun_mtu) {
			return true;
		}

		ip_hdr = net_pkt_get_data(pkt, &ipv4_access);
		if (!ip_hdr) {
			LOG_ERR("cannot get ipv4 header");
			return true;
		}

		bool dont_fragment = ip_hdr->offset[0] & (NET_IPV4_DF << 5);
		if (dont_fragment) {
			LOG_DBG("sending icmpv4 unreachable for %s",
				net_sprint_addr(NET_AF_INET, ip_hdr->src));

			src.family = NET_AF_INET;
			net_ipv4_addr_copy_raw(src.net_in_addr.s4_addr, ip_hdr->src);
			if (is_icmp_allowed(&src)) {
				struct net_if *reply_iface =
					net_if_ipv4_addr_mask_cmp(ctx.iface_wan, &src.net_in_addr)
					? ctx.iface_wan
					: (ctx.iface_lan ? ctx.iface_lan : ctx.iface_wan);
				send_icmpv4_unreach(reply_iface, pkt, ctx.tun_mtu);
			}
		} else {
			LOG_WRN("fragmentation is not implemented, silent drop");
		}

		return false;
#if defined(CONFIG_NET_IPV6)
	} else if (family == NET_AF_INET6) {
		if (net_pkt_get_len(pkt) <= ctx.tun_mtu) {
			return true;
		}

		ip6_hdr = net_pkt_get_data(pkt, &ipv6_access);
		if (!ip6_hdr) {
			LOG_ERR("cannot get ipv6 header");
			return true;
		}

		LOG_DBG("sending icmpv6 ptb for %s", net_sprint_addr(NET_AF_INET6, ip6_hdr->src));

		src.family = NET_AF_INET6;
		net_ipv6_addr_copy_raw(src.net_in6_addr.s6_addr, ip6_hdr->src);
		if (ctx.iface_lan && is_icmp_allowed(&src)) {
			send_icmpv6_ptb(ctx.iface_lan, pkt, ctx.tun_mtu);
		}

		return false;
#endif
	}
	return true;
}

static struct npf_test npf_test_send = {
	.fn = npf_test_send_fn,
	IF_ENABLED(NPF_TEST_ENABLE_NAME,
	(.name = "npf_test_send",))
};
static struct npf_rule npf_rule_send = {
	.result = NET_OK,
	.nb_tests = 1,
	.tests = { &npf_test_send },
};

static int npf_init()
{
	static bool init_done = false;
	if (init_done) {
		return 0;
	}
	init_done = true;

	k_fifo_init(&ctx.icmp_tx_fifo);
	k_work_init(&ctx.icmp_work, icmp_worker);
	k_mutex_init(&ctx.icmp_lock);

	return 0;
}

int npf_start(struct net_if *iface_lan, struct net_if *iface_wan, struct net_if *iface_tun)
{
	int ret;
	struct net_in_addr *addr;

	if (ctx.status) {
		return -EALREADY;
	}

	ctx.iface_lan = iface_lan;
	ctx.iface_wan = iface_wan;
	ctx.iface_tun = iface_tun;

	addr = net_if_ipv4_get_global_addr(ctx.iface_wan, NET_ADDR_PREFERRED);
	if (!addr) {
		LOG_ERR("cannot get wan ip address");
		return 1;
	}

	memcpy(&ctx.wan_address, addr, sizeof(struct net_in_addr));
	ctx.tun_mtu = net_if_get_mtu(iface_tun);

	ret = npf_init();
	if (ret != 0) {
		return ret;
	}

	memset(&ctx.icmp_rate_limited, 0, sizeof(ctx.icmp_rate_limited));

	npf_insert_recv_rule(&npf_rule_recv);
	npf_insert_send_rule(&npf_rule_send);

	ctx.status = true;
	return 0;
}

int npf_stop(void)
{
	struct k_work_sync sync;

	if (!ctx.status) {
		LOG_DBG("npf is already stopped");
		return 0;
	}

	if (!npf_remove_recv_rule(&npf_rule_recv)) {
		return 1;
	}
	if (!npf_remove_send_rule(&npf_rule_send)) {
		return 1;
	}

	k_work_cancel_sync(&ctx.icmp_work, &sync);

	while (!k_fifo_is_empty(&ctx.icmp_tx_fifo)) {
		struct net_pkt *pkt = k_fifo_get(&ctx.icmp_tx_fifo, K_FOREVER);
		net_pkt_unref(pkt);
	}

	ctx.status = false;
	return 0;
}
