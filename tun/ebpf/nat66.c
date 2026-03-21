// SPDX-License-Identifier: GPL-2.0
//
// Stateless 1:1 NAT66 with dynamic allocation.
//
// ULA scheme: fdf7:0fa8:ed0c:LLLL::/64 where LLLL is the LAN ID.
// Public scheme: <pub64>:LLLL:0000:0000:HHHH where HHHH is per-host.
// ULA recognition: first 6 bytes match a configured prefix.
// LAN ID: bytes 6-7 of the ULA (the LLLL above).

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ── Maps ────────────────────────────────────────────────────────────────

// Forward: full ULA address (16 bytes) → public address (16 bytes).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct in6_addr);
	__type(value, struct in6_addr);
} ula_to_pub SEC(".maps");

// Reverse: public address (16 bytes) → ULA address (16 bytes).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct in6_addr);
	__type(value, struct in6_addr);
} pub_to_ula SEC(".maps");

// Per-LAN allocation counter.  Key = LAN ID (u32).
// Value = next host number to allocate (u32, only low 16 bits used).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u32);
} pool_next SEC(".maps");

// ULA /48 prefix — first 6 bytes (padded to 8 in map, only 6 compared).
// key=0.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8[8]);
} ula_prefix48 SEC(".maps");

// Public /64 prefix — 8 bytes.  key=0.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8[8]);
} pub_prefix SEC(".maps");

// VPS's own addresses — skip NAT on ingress.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, struct in6_addr);
	__type(value, __u8);
} vps_addrs SEC(".maps");

// ── Helpers ─────────────────────────────────────────────────────────────

static __always_inline int
l4_csum_offset(__u8 nexthdr)
{
	switch (nexthdr) {
	case IPPROTO_TCP:
		return offsetof(struct tcphdr, check);
	case IPPROTO_UDP:
		return offsetof(struct udphdr, check);
	case IPPROTO_ICMPV6:
		return offsetof(struct icmp6hdr, icmp6_cksum);
	default:
		return -1;
	}
}

static __always_inline int
fixup_csum(struct __sk_buff *skb, int l4_off, int csum_off,
	   const struct in6_addr *old_addr, const struct in6_addr *new_addr)
{
	int off = l4_off + csum_off;
	__be32 o0, o1, o2, o3, n0, n1, n2, n3;

	__builtin_memcpy(&o0, (__u8 *)old_addr +  0, 4);
	__builtin_memcpy(&n0, (__u8 *)new_addr +  0, 4);
	__builtin_memcpy(&o1, (__u8 *)old_addr +  4, 4);
	__builtin_memcpy(&n1, (__u8 *)new_addr +  4, 4);
	__builtin_memcpy(&o2, (__u8 *)old_addr +  8, 4);
	__builtin_memcpy(&n2, (__u8 *)new_addr +  8, 4);
	__builtin_memcpy(&o3, (__u8 *)old_addr + 12, 4);
	__builtin_memcpy(&n3, (__u8 *)new_addr + 12, 4);

	if (o0 != n0)
		if (bpf_l4_csum_replace(skb, off, o0, n0, BPF_F_PSEUDO_HDR | 4) < 0)
			return -1;
	if (o1 != n1)
		if (bpf_l4_csum_replace(skb, off, o1, n1, BPF_F_PSEUDO_HDR | 4) < 0)
			return -1;
	if (o2 != n2)
		if (bpf_l4_csum_replace(skb, off, o2, n2, BPF_F_PSEUDO_HDR | 4) < 0)
			return -1;
	if (o3 != n3)
		if (bpf_l4_csum_replace(skb, off, o3, n3, BPF_F_PSEUDO_HDR | 4) < 0)
			return -1;

	return 0;
}

static __always_inline int
rewrite_addr(struct __sk_buff *skb, int addr_off, __u8 nexthdr,
	     const struct in6_addr *old_addr, const struct in6_addr *new_addr)
{
	if (bpf_skb_store_bytes(skb, addr_off, new_addr, 16, 0) < 0)
		return -1;

	int csum_off = l4_csum_offset(nexthdr);
	if (csum_off >= 0) {
		int l4_off = ETH_HLEN + sizeof(struct ipv6hdr);
		fixup_csum(skb, l4_off, csum_off, old_addr, new_addr);
	}
	return 0;
}

// Build public address: pub_prefix : LLLL : 0000 : 0000 : HHHH
static __always_inline void
build_pub_addr(struct in6_addr *out, const __u8 *pub, __u16 lan_id, __u16 host)
{
	__u8 *b = (__u8 *)out;

	__builtin_memcpy(b, pub, 8);
	b[8]  = (__u8)(lan_id >> 8);
	b[9]  = (__u8)(lan_id & 0xFF);
	b[10] = 0;
	b[11] = 0;
	b[12] = 0;
	b[13] = 0;
	b[14] = (__u8)(host >> 8);
	b[15] = (__u8)(host & 0xFF);
}

// ── Egress: ULA src → public src ────────────────────────────────────────

SEC("tc/egress")
int nat66_egress(struct __sk_buff *skb)
{
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IPV6))
		return TC_ACT_OK;

	struct ipv6hdr *ip6 = (void *)(eth + 1);
	if ((void *)(ip6 + 1) > data_end)
		return TC_ACT_OK;

	// Match first 6 bytes against our ULA /48.
	__u32 zero = 0;
	__u8 *ula48 = bpf_map_lookup_elem(&ula_prefix48, &zero);
	if (!ula48)
		return TC_ACT_OK;

	__u8 *src = (__u8 *)&ip6->saddr;
	if (src[0] != ula48[0] || src[1] != ula48[1] ||
	    src[2] != ula48[2] || src[3] != ula48[3] ||
	    src[4] != ula48[4] || src[5] != ula48[5])
		return TC_ACT_OK;

	// LAN ID = bytes 6-7 of source address.
	__u16 lan_id = ((__u16)src[6] << 8) | src[7];

	struct in6_addr old_saddr = ip6->saddr;
	__u8 nexthdr = ip6->nexthdr;

	// Existing mapping?
	struct in6_addr *pub_addr = bpf_map_lookup_elem(&ula_to_pub, &old_saddr);
	if (pub_addr) {
		rewrite_addr(skb,
			     ETH_HLEN + offsetof(struct ipv6hdr, saddr),
			     nexthdr, &old_saddr, pub_addr);
		return TC_ACT_OK;
	}

	// Allocate from pool.
	__u32 lanid_key = lan_id;
	__u32 *next_p = bpf_map_lookup_elem(&pool_next, &lanid_key);
	if (!next_p) {
		// First host on this LAN — seed counter at 1 (skip ::0).
		__u32 init = 1;
		bpf_map_update_elem(&pool_next, &lanid_key, &init, BPF_NOEXIST);
		next_p = bpf_map_lookup_elem(&pool_next, &lanid_key);
		if (!next_p)
			return TC_ACT_SHOT;
	}

	__u16 host = (__u16)*next_p;
	if (host == 0 || host > 0xFFFE)
		return TC_ACT_SHOT;  // Pool exhausted.

	(*next_p)++;

	__u8 *pub = bpf_map_lookup_elem(&pub_prefix, &zero);
	if (!pub)
		return TC_ACT_OK;

	struct in6_addr new_addr;
	build_pub_addr(&new_addr, pub, lan_id, host);

	bpf_map_update_elem(&ula_to_pub, &old_saddr, &new_addr, BPF_NOEXIST);
	bpf_map_update_elem(&pub_to_ula, &new_addr, &old_saddr, BPF_NOEXIST);

	rewrite_addr(skb,
		     ETH_HLEN + offsetof(struct ipv6hdr, saddr),
		     nexthdr, &old_saddr, &new_addr);

	return TC_ACT_OK;
}

// ── Ingress: public dst → ULA dst ───────────────────────────────────────

SEC("tc/ingress")
int nat66_ingress(struct __sk_buff *skb)
{
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IPV6))
		return TC_ACT_OK;

	struct ipv6hdr *ip6 = (void *)(eth + 1);
	if ((void *)(ip6 + 1) > data_end)
		return TC_ACT_OK;

	// Check destination prefix against public /64.
	__u32 zero = 0;
	__u8 *pub = bpf_map_lookup_elem(&pub_prefix, &zero);
	if (!pub)
		return TC_ACT_OK;

	if (__builtin_memcmp(&ip6->daddr, pub, 8) != 0)
		return TC_ACT_OK;

	// Skip VPS's own addresses.
	if (bpf_map_lookup_elem(&vps_addrs, &ip6->daddr))
		return TC_ACT_OK;

	struct in6_addr old_daddr = ip6->daddr;
	__u8 nexthdr = ip6->nexthdr;

	// Reverse lookup.
	struct in6_addr *ula_addr = bpf_map_lookup_elem(&pub_to_ula, &old_daddr);
	if (!ula_addr)
		return TC_ACT_OK;

	rewrite_addr(skb,
		     ETH_HLEN + offsetof(struct ipv6hdr, daddr),
		     nexthdr, &old_daddr, ula_addr);

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
