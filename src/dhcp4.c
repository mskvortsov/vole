#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(dhcp4, LOG_LEVEL_INF);

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
#include "udp_internal.h"

/* Minimal DHCP (RFC 2131) server: responds to Discover with Offer + RFC 8925
 * option 108 (IPv6-Only Preferred) so Android enters IPv6-only mode immediately.
 * Responds to Request with NAK.  No IPv4 addresses are assigned. */

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define DHCP_OP_REQUEST  1
#define DHCP_OP_REPLY    2
#define DHCPDISCOVER     1
#define DHCPOFFER        2
#define DHCPREQUEST      3
#define DHCPNAK          6
#define DHCP_OPT_PAD      0
#define DHCP_OPT_MSG_TYPE 53
#define DHCP_OPT_PRL      55  /* Parameter Request List */
#define DHCP_OPT_IPV6ONLY 108 /* RFC 8925 */
#define DHCP_OPT_END      255
/* V6ONLY_WAIT must be >= 300 s per RFC 8925; use max (effectively forever). */
#define V6ONLY_WAIT 0xFFFFFFFFU

#define DHCP_PKT_ALLOC_TIME K_MSEC(100)

/* Fixed DHCP fields we copy from request into reply. */
struct dhcp_pkt_hdr {
	uint8_t  op;
	uint8_t  htype;
	uint8_t  hlen;
	uint8_t  hops;
	uint32_t xid;
	uint16_t secs;
	uint16_t flags;
	uint8_t  ciaddr[4];
	uint8_t  yiaddr[4];
	uint8_t  siaddr[4];
	uint8_t  giaddr[4];
	uint8_t  chaddr[16];
} __packed;

#define DHCP_SNAME_FILE_LEN (64 + 128)
static const uint8_t dhcp_magic[4] = { 0x63, 0x82, 0x53, 0x63 };

static struct net_pkt *send_dhcp_reply(struct net_if *iface, const struct dhcp_pkt_hdr *req,
				       uint8_t reply_type)
{
	/* Payload written after IPv4+UDP headers:
	 *   fixed hdr (44) + sname+file (192) + magic (4)
	 *   + opt53 (3) + opt108 (6, OFFER only) + end (1)  */
	const size_t dhcp_size = sizeof(struct dhcp_pkt_hdr) + DHCP_SNAME_FILE_LEN + 4 + 3 +
				 (reply_type == DHCPOFFER ? 6 : 0) + 1;

	static const struct net_in_addr src_any; /* 0.0.0.0 */
	static const uint8_t sname_file[DHCP_SNAME_FILE_LEN];

	struct dhcp_pkt_hdr rep = {0};
	uint32_t v6only = net_htonl(V6ONLY_WAIT);
	uint8_t opt53[3] = {DHCP_OPT_MSG_TYPE, 1, reply_type};
	uint8_t opt108[2] = {DHCP_OPT_IPV6ONLY, 4};
	uint8_t opt_end = DHCP_OPT_END;
	struct net_pkt *pkt;

	pkt = net_pkt_alloc_with_buffer(iface, dhcp_size, NET_AF_INET, NET_IPPROTO_UDP,
					DHCP_PKT_ALLOC_TIME);
	if (!pkt) {
		LOG_ERR("cannot alloc dhcp reply");
		return NULL;
	}

	rep.op = DHCP_OP_REPLY;
	rep.htype = req->htype;
	rep.hlen = req->hlen;
	rep.xid = req->xid;
	rep.flags = req->flags;
	memcpy(rep.giaddr, req->giaddr, 4);
	memcpy(rep.chaddr, req->chaddr, 16);

	net_pkt_set_ipv4_ttl(pkt, 64);

	if (net_ipv4_create(pkt, &src_any, net_ipv4_broadcast_address()) ||
	    net_udp_create(pkt, net_htons(DHCP_SERVER_PORT), net_htons(DHCP_CLIENT_PORT)) ||
	    net_pkt_write(pkt, &rep, sizeof(rep)) ||
	    net_pkt_write(pkt, sname_file, sizeof(sname_file)) ||
	    net_pkt_write(pkt, dhcp_magic, sizeof(dhcp_magic)) ||
	    net_pkt_write(pkt, opt53, sizeof(opt53)) ||
	    (reply_type == DHCPOFFER &&
	     (net_pkt_write(pkt, opt108, sizeof(opt108)) || net_pkt_write(pkt, &v6only, 4))) ||
	    net_pkt_write(pkt, &opt_end, 1)) {
		goto fail;
	}

	net_pkt_cursor_init(pkt);
	if (net_ipv4_finalize(pkt, NET_IPPROTO_UDP)) {
		goto fail;
	}

	net_pkt_hexdump(pkt, "dhcp reply");

	return pkt;

fail:
	LOG_ERR("cannot build dhcp reply");
	net_pkt_unref(pkt);
	return NULL;
}

/* Called with cursor at the start of the UDP header. */
struct net_pkt *dhcp_lan_recv(struct net_pkt *pkt)
{
	struct dhcp_pkt_hdr req;
	uint8_t magic[4];
	uint8_t msg_type = 0;
	bool prl_has_opt108 = false;
	uint8_t code;
	uint8_t optlen;

	if (net_pkt_skip(pkt, sizeof(struct net_udp_hdr)) != 0 ||
	    net_pkt_read(pkt, &req, sizeof(req)) != 0) {
		return NULL;
	}
	if (req.op != DHCP_OP_REQUEST) {
		return NULL;
	}
	if (net_pkt_skip(pkt, DHCP_SNAME_FILE_LEN) != 0) {
		return NULL;
	}
	if (net_pkt_read(pkt, magic, sizeof(magic)) != 0 ||
	    memcmp(magic, dhcp_magic, sizeof(magic)) != 0) {
		return NULL;
	}

	/* Parse options scanning for type 53 (message type) and 55 (PRL). */
	while (net_pkt_read_u8(pkt, &code) == 0) {
		if (code == DHCP_OPT_PAD) {
			continue;
		}
		if (code == DHCP_OPT_END) {
			break;
		}
		if (net_pkt_read_u8(pkt, &optlen) != 0) {
			break;
		}
		if (code == DHCP_OPT_MSG_TYPE && optlen >= 1) {
			if (net_pkt_read_u8(pkt, &msg_type) != 0) {
				break;
			}
			if (optlen > 1) {
				net_pkt_skip(pkt, optlen - 1);
			}
		} else if (code == DHCP_OPT_PRL) {
			/* RFC 8925 §3.1: only send opt108 if client requested it. */
			for (uint8_t i = 0; i < optlen; i++) {
				uint8_t req_opt;

				if (net_pkt_read_u8(pkt, &req_opt) != 0) {
					goto done;
				}
				if (req_opt == DHCP_OPT_IPV6ONLY) {
					prl_has_opt108 = true;
				}
			}
		} else if (net_pkt_skip(pkt, optlen) != 0) {
			break;
		}
	}

done:
	if (msg_type == DHCPDISCOVER && prl_has_opt108) {
		LOG_DBG("dhcp discover -> offer+opt108");
		return send_dhcp_reply(net_pkt_iface(pkt), &req, DHCPOFFER);
	} else if (msg_type == DHCPREQUEST) {
		LOG_DBG("dhcp request -> nak");
		return send_dhcp_reply(net_pkt_iface(pkt), &req, DHCPNAK);
	}
	return NULL;
}
