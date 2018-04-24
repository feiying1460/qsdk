/* Copyright (c) 2014-2017, The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 *
 */

/* nss_cfi_ipsec.c
 *	NSS IPsec offload glue for Openswan/KLIPS
 */
#include <linux/version.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/memory.h>
#include <linux/io.h>
#include <linux/clk.h>
#include <linux/uaccess.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include <linux/if.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/arp.h>
#include <net/neighbour.h>
#include <net/route.h>
#include <net/dst.h>
#include <net/esp.h>

#include <nss_api_if.h>
#include <nss_crypto_if.h>
#include <nss_ipsec.h>
#include <nss_cfi_if.h>
#include "nss_ipsecmgr.h"

#define NSS_CFI_IPSEC_BASE_NAME "ipsec"
#define NSS_CFI_IPSEC_TUN_IFNAME(x) NSS_CFI_IPSEC_BASE_NAME#x

/* NSS IPsec rule type */
enum nss_cfi_ipsec_rule_type {
	NSS_CFI_IPSEC_RULE_TYPE_NONE = 0,
	NSS_CFI_IPSEC_RULE_TYPE_ENCAP = 1,
	NSS_CFI_IPSEC_RULE_TYPE_DECAP = 2,
	NSS_CFI_IPSEC_RULE_TYPE_MAX
};

/*
 * This is used by KLIPS for communicate the device along with the
 * packet. We need this to derive the mapping of the incoming flow
 * to the IPsec tunnel
 */
struct nss_cfi_ipsec_skb_cb {
	struct net_device *hlos_dev;
};

/*
 * Per tunnel object created w.r.t the HLOS IPsec stack
 */
struct nss_cfi_ipsec_sa {
	enum nss_cfi_ipsec_rule_type type;
	struct net_device *nss_dev;
	struct nss_ipsecmgr_sa sa;
};

/*
 * CFI IPsec netdevice  mapping between HLOS devices and NSS devices
 * Essentially various HLOS IPsec devices will be used as indexes to
 * map into the NSS devices. For example
 * "ipsec0" --> "ipsectun0"
 * "ipsec1" --> "ipsectun1"
 *
 * Where the numeric suffix of "ipsec0", "ipsec1" is used to index into
 * the table
 */
struct nss_cfi_ipsec_tunnel {
	struct net_device *nss_dev;
};

/*
 ************************
 * Globals
 ***********************
 */
/*
 * List of supported tunnels in Openswan/KLIPS
 */
const static uint8_t *max_tun_supp[] = {
	NSS_CFI_IPSEC_TUN_IFNAME(0),	/* ipsec0 */
	NSS_CFI_IPSEC_TUN_IFNAME(1),	/* ipsec1 */
};
#define NSS_CFI_IPSEC_MAX_TUN (sizeof(max_tun_supp) / sizeof(max_tun_supp[0]))

struct nss_cfi_ipsec_tunnel tunnel_map[NSS_CFI_IPSEC_MAX_TUN];	/* per tunnel device table */
struct nss_cfi_ipsec_sa sa_tbl[NSS_CRYPTO_MAX_IDXS];		/* per crypto session table */

/*
 * nss_cfi_ipsec_get_iv_len
 * 	get ipsec algorithm specific iv len
 */
static int32_t nss_cfi_ipsec_get_iv_len(uint32_t algo)
{
	uint32_t result = -1;

	switch (algo) {
	case NSS_CRYPTO_CIPHER_AES_CBC:
	case NSS_CRYPTO_CIPHER_AES_CTR:
		result = NSS_CRYPTO_MAX_IVLEN_AES;
		break;

	case NSS_CRYPTO_CIPHER_DES:
		result = NSS_CRYPTO_MAX_IVLEN_DES;
		break;

	case NSS_CRYPTO_CIPHER_NULL:
		result = NSS_CRYPTO_MAX_IVLEN_NULL;
		break;

	default:
		nss_cfi_err("Invalid algorithm\n");
		break;
	}
	return result;
}

/*
 * nss_cfi_ipsec_get_dev()
 * 	get ipsec netdevice from skb. Openswan stack fills up ipsec_dev in skb.
 */
static inline struct net_device * nss_cfi_ipsec_get_dev(struct sk_buff *skb)
{
	struct nss_cfi_ipsec_skb_cb *ipsec_cb;

	ipsec_cb = (struct nss_cfi_ipsec_skb_cb *)skb->cb;

	return ipsec_cb->hlos_dev;
}

/*
 * nss_cfi_ipsec_verify_ifname()
 * 	Verify the IPsec tunnel interface name
 *
 * This will ensure that only supported interface names
 * are used for tunnel creation
 */
static bool nss_cfi_ipsec_verify_ifname(uint8_t *name)
{
	int i;

	for (i = 0; i < NSS_CFI_IPSEC_MAX_TUN; i++) {
		if (strncmp(name, max_tun_supp[i], strlen(max_tun_supp[i])) == 0) {
			return true;
		}
	}

	return false;
}

/*
 * nss_cfi_ipsec_get_index()
 * 	given a interface name retrived the numeric suffix
 */
static int16_t nss_cfi_ipsec_get_index(uint8_t *name)
{
	uint16_t idx;

	if (nss_cfi_ipsec_verify_ifname(name) == false) {
		return -1;
	}

	name += strlen(NSS_CFI_IPSEC_BASE_NAME);

	for (idx = 0; (*name >= '0') && (*name <= '9'); name++) {
		idx = (*name - '0') + (idx * 10);
	}

	if (idx >= NSS_CFI_IPSEC_MAX_TUN) {
		return -1;
	}

	return idx;
}

/*
 * nss_cfi_ipsec_get_next_hdr()
 * 	get next hdr after IPv4 header.
 */
static inline void * nss_cfi_ipsec_get_next_hdr(struct iphdr *ip)
{
	return ((uint8_t *)ip + sizeof(struct iphdr));
}

/*
 * nss_cfi_ipsec_free_session()
 * 	Free perticular session on NSS.
 */
static int32_t nss_cfi_ipsec_free_session(uint32_t crypto_sid)
{
	struct nss_cfi_ipsec_sa *sa;

	if (crypto_sid >= NSS_CRYPTO_MAX_IDXS) {
		return -1;
	}

	sa = &sa_tbl[crypto_sid];
	/*
	 * check whether crypto index correspond to encap/decap and
	 * send message to ipsecmgr to delete the session
	 */
	switch (sa->type) {
	case NSS_CFI_IPSEC_RULE_TYPE_ENCAP:
	case NSS_CFI_IPSEC_RULE_TYPE_DECAP:
		nss_ipsecmgr_sa_flush(sa->nss_dev, &sa->sa);
		break;

	default:
		return 0;
	}

	sa->type = NSS_CFI_IPSEC_RULE_TYPE_NONE;

	return 0;
}

/*
 * nss_cfi_ipsec_trap_encap()
 * 	Trap IPsec pkts for sending encap fast path rules.
 */
static int32_t nss_cfi_ipsec_trap_encap(struct sk_buff *skb, struct nss_cfi_crypto_info* crypto)
{
	struct nss_ipsecmgr_encap_flow encap_flow = {0};
	struct nss_ipsecmgr_encap_v4_tuple *v4_tuple;
	struct nss_ipsecmgr_sa_data data = {0};
	struct nss_ipsecmgr_sa encap_sa = {0};
	struct nss_ipsecmgr_sa_v4 *sa_v4;
	struct ip_esp_hdr *esp = NULL;
	struct net_device *hlos_dev;
	struct net_device *nss_dev;
	struct iphdr *outer_ip;
	struct iphdr *inner_ip;
	uint32_t index = 0;
	uint32_t ivsize = 0;

	hlos_dev = nss_cfi_ipsec_get_dev(skb);
	if (hlos_dev == NULL) {
		nss_cfi_err("ipsec dev is NULL\n");
		return -1;
	}

	ivsize = nss_cfi_ipsec_get_iv_len(crypto->cipher_algo);
	if (ivsize < 0) {
		nss_cfi_err("Invalid IV\n");
		return -1;
	}

	outer_ip = (struct iphdr *)skb->data;
	esp = (struct ip_esp_hdr *)(skb->data + sizeof(struct iphdr));
	/* XXX: this should use the IV len fed by CFI */
	inner_ip = (struct iphdr *)(skb->data + sizeof(struct iphdr) + sizeof(struct ip_esp_hdr) + ivsize);

	if ((outer_ip->version != IPVERSION) || (outer_ip->ihl != 5)) {
		nss_cfi_dbg("Outer non-IPv4 packet {0x%x, 0x%x}\n", outer_ip->version, outer_ip->ihl);
		return 0;
	}

	if ((inner_ip->version != IPVERSION) || (inner_ip->ihl != 5)) {
		nss_cfi_dbg("Inner non-IPv4 packet {0x%x, 0x%x}\n", inner_ip->version, inner_ip->ihl);
		return -1;
	}

	skb->skb_iif = hlos_dev->ifindex;
	encap_flow.type = NSS_IPSECMGR_FLOW_TYPE_V4_TUPLE;

	/*
	 * construct flow information
	 */
	v4_tuple = &encap_flow.data.v4_tuple;
	v4_tuple->src_ip = ntohl(inner_ip->saddr);
	v4_tuple->dst_ip = ntohl(inner_ip->daddr);
	v4_tuple->protocol = inner_ip->protocol;

	/*
	 * construct SA information
	 */
	encap_sa.type = NSS_IPSECMGR_SA_TYPE_V4;
	sa_v4 = &encap_sa.data.v4;

	sa_v4->src_ip = ntohl(outer_ip->saddr);
	sa_v4->dst_ip = ntohl(outer_ip->daddr);
	sa_v4->ttl = outer_ip->ttl;
	sa_v4->spi_index = ntohl(esp->spi);

	data.esp.icv_len = crypto->hash_len;
	data.esp.nat_t_req = false;
	data.esp.seq_skip = false;
	data.esp.trailer_skip = false;

	data.crypto_index = crypto->sid;
	data.use_pattern = false;

	index = nss_cfi_ipsec_get_index(hlos_dev->name);
	if (index < 0) {
		return -1;
	}

	nss_dev = tunnel_map[index].nss_dev;

	if (nss_ipsecmgr_encap_add(nss_dev, &encap_flow, &encap_sa, &data) == false) {
		nss_cfi_err("Error in Pushing the Encap Rule \n");
		return -1;
	}

	/*
	 * Need to save the selector for deletion as it will for issued for
	 * session delete
	 */
	sa_tbl[crypto->sid].type = NSS_CFI_IPSEC_RULE_TYPE_ENCAP;
	sa_tbl[crypto->sid].nss_dev = nss_dev;

	memcpy(&sa_tbl[crypto->sid].sa, &encap_sa, sizeof(struct nss_ipsecmgr_sa));

	nss_cfi_dbg("encap pushed rule successfully\n");

	return 0;
}

/*
 * nss_cfi_ipsec_trap_decap()
 * 	Trap IPsec pkts for sending decap fast path rules.
 */
static int32_t nss_cfi_ipsec_trap_decap(struct sk_buff *skb, struct nss_cfi_crypto_info* crypto)
{
	struct nss_ipsecmgr_sa decap_sa = {0};
	struct nss_ipsecmgr_sa_data data = {0};
	struct nss_ipsecmgr_sa_v4 *sa_v4;
	struct iphdr *outer_ip;
	struct iphdr *inner_ip;
	struct ip_esp_hdr *esp = NULL;
	struct net_device *hlos_dev;
	struct net_device *nss_dev;
	uint8_t index = 0;
	uint32_t ivsize = 0;

	hlos_dev = nss_cfi_ipsec_get_dev(skb);
	if (hlos_dev == NULL) {
		nss_cfi_dbg("hlos dev is NULL\n");
		return -1;
	}

	ivsize = nss_cfi_ipsec_get_iv_len(crypto->cipher_algo);
	if (ivsize < 0) {
		nss_cfi_err("Invalid IV\n");
		return -1;
	}

	skb->skb_iif = hlos_dev->ifindex;

	outer_ip = (struct iphdr *)skb_network_header(skb);
	esp = (struct ip_esp_hdr *)skb->data;
	/* XXX: this should use the IV len fed by CFI */
	inner_ip = (struct iphdr *)(skb->data + sizeof(struct ip_esp_hdr) + ivsize);

	/*
	 * construct SA information
	 */
	decap_sa.type = NSS_IPSECMGR_SA_TYPE_V4;
	sa_v4 = &decap_sa.data.v4;

	sa_v4->src_ip = ntohl(outer_ip->saddr);
	sa_v4->dst_ip = ntohl(outer_ip->daddr);
	sa_v4->spi_index = ntohl(esp->spi);

	data.crypto_index = crypto->sid;
	data.esp.icv_len = crypto->hash_len;

	index = nss_cfi_ipsec_get_index(hlos_dev->name);
	if (index < 0) {
		return -1;
	}

	nss_dev = tunnel_map[index].nss_dev;

	if (nss_ipsecmgr_decap_add(nss_dev, &decap_sa, &data) == false) {
		nss_cfi_err("Error in Pushing the Decap Rule\n");
		return -1;
	}

	/*
	 * Need to save the selector for deletion as it will for issued for
	 * session delete
	 */
	sa_tbl[crypto->sid].type = NSS_CFI_IPSEC_RULE_TYPE_DECAP;
	sa_tbl[crypto->sid].nss_dev = nss_dev;

	memcpy(&sa_tbl[crypto->sid].sa, &decap_sa, sizeof(struct nss_ipsecmgr_sa));

	nss_cfi_dbg("decap pushed rule successfully\n");

	return 0;
}

/*
 * nss_ipsec_data_cb()
 * 	ipsec exception routine for handling exceptions from NSS IPsec package
 *
 * exception function called by NSS HLOS driver when it receives
 * a packet for exception with the interface number for decap
 */
static void nss_cfi_ipsec_data_cb(void *cb_ctx, struct sk_buff *skb)
{
	struct nss_ipsecmgr_sa_v4 *sa_v4;
	struct nss_ipsecmgr_sa_v6 *sa_v6;
	struct net_device *dev = cb_ctx;
	struct ip_esp_hdr *esp = NULL;
	struct net_device *nss_dev;
	struct nss_ipsecmgr_sa sa;
	struct frag_hdr *frag;
	struct ipv6hdr *ip6;
	struct udphdr *udp;
	struct iphdr *ip;
	int16_t index = 0;

	nss_cfi_dbg("exception data ");

	/*
	 * need to hold the lock prior to accessing the dev
	 */
	if (!dev) {
		dev_kfree_skb_any(skb);
		return;
	}

	dev_hold(dev);

	index = nss_cfi_ipsec_get_index(dev->name);
	if (index < 0) {
		nss_cfi_err("unable to find local index %s\n", dev->name);
		return;
	}

	nss_dev = tunnel_map[index].nss_dev;
	if (!nss_dev) {
		nss_cfi_err("NSS IPsec tunnel dev allocation failed for %s\n", dev->name);
		goto drop;
	}

	/*
	 * We can only work with IP headers tunnelled inside ESP. Hence, assume
	 * that the start of the packet is IPv4 header. Then check for the version
	 */
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	ip = ip_hdr(skb);

	/*
	 * Check the exception packet is IPv4/IPv6
	 */
	switch (ip->version) {
	case 4:
		/*
		 * set the protocol to IPv4
		 */
		skb->protocol = htons(ETH_P_IP);

		/*
		 * If, ESP packet is exceptioned from NSS flush the SA
		 * corresponding to the packet
		 */
		skb_set_transport_header(skb, sizeof(struct iphdr));

		if ((ip->protocol != IPPROTO_ESP) && (ip->protocol != IPPROTO_UDP)) {
			break;
		}

		/*
		 * At this point the next header can be UDP or ESP. Blindly, assume
		 * that it is UDP and perform the test for NAT-T port number
		 */
		udp = udp_hdr(skb);
		if ((ip->protocol == IPPROTO_UDP) && udp->dest == NSS_IPSECMGR_NATT_PORT_DATA) {
			skb_set_transport_header(skb, sizeof(struct iphdr) + sizeof(struct udphdr));
		}

		esp = ip_esp_hdr(skb);

		/*
		 * construct SA from packet
		 */
		sa.type = NSS_IPSECMGR_SA_TYPE_V4;
		sa_v4 = &sa.data.v4;

		sa_v4->src_ip = ntohl(ip->saddr);
		sa_v4->dst_ip = ntohl(ip->daddr);

		sa_v4->ttl = ip->ttl;
		sa_v4->spi_index = ntohl(esp->spi);

		/*
		 * drop the packet as this is an ESP packet which should
		 * only be used for flushing the rule
		 */
		nss_ipsecmgr_sa_flush(nss_dev, &sa);
		goto drop;

	case 6:
		/*
		 * set the protocol to IPv6
		 */
		skb->protocol = htons(ETH_P_IPV6);

		/*
		 * If, ESP packet is exceptioned from NSS flush the SA
		 * corresponding to the packet
		 */
		ip6 = ipv6_hdr(skb);
		skb_set_transport_header(skb, sizeof(struct ipv6hdr));

		if ((ip6->nexthdr != IPPROTO_ESP) && (ip6->nexthdr != NEXTHDR_FRAGMENT)) {
			break;
		}

		/*
		 * At this point the next header can be Fragment or ESP. Blindly, assume
		 * that it is Fragment and perform the test for next header in fragment
		 */
		frag = (struct frag_hdr *)skb_transport_header(skb);

		if ((ip6->nexthdr == NEXTHDR_FRAGMENT) && (frag->nexthdr == IPPROTO_ESP)) {
			skb_set_transport_header(skb, sizeof(struct ipv6hdr) + sizeof(struct frag_hdr));
		}

		esp = ip_esp_hdr(skb);

		/*
		 * construct SA from packet
		 */
		sa.type = NSS_IPSECMGR_SA_TYPE_V6;
		sa_v6 = &sa.data.v6;

		sa_v6->src_ip[0] = ntohl(ip6->saddr.s6_addr32[0]);
		sa_v6->src_ip[1] = ntohl(ip6->saddr.s6_addr32[1]);
		sa_v6->src_ip[2] = ntohl(ip6->saddr.s6_addr32[2]);
		sa_v6->src_ip[3] = ntohl(ip6->saddr.s6_addr32[3]);

		sa_v6->dst_ip[0] = ntohl(ip6->daddr.s6_addr32[0]);
		sa_v6->dst_ip[1] = ntohl(ip6->daddr.s6_addr32[1]);
		sa_v6->dst_ip[2] = ntohl(ip6->daddr.s6_addr32[2]);
		sa_v6->dst_ip[3] = ntohl(ip6->daddr.s6_addr32[3]);
		sa_v6->spi_index = ntohl(esp->spi);

		sa_v6->hop_limit = ip6->hop_limit;

		/*
		 * drop the packet as this is an ESP
		 * packet which should only be used for
		 * flushing the rule
		 */
		nss_ipsecmgr_sa_flush(nss_dev, &sa);
		goto drop;

	default:
		nss_cfi_dbg("malformed IP header\n");
		goto drop;
	}


	skb->dev = dev;
	skb->skb_iif = dev->ifindex;
	skb->pkt_type = PACKET_HOST;

	netif_receive_skb(skb);
	dev_put(dev);

	return;

drop:
	dev->stats.rx_dropped++;
	dev_kfree_skb_any(skb);
	dev_put(dev);
	return;
}

/*
 * nss_ipsec_ev_cb()
 * 	Receive events from NSS IPsec package
 *
 * Event callback called by IPsec manager
 */
static void nss_cfi_ipsec_ev_cb(void *ctx, struct nss_ipsecmgr_event *ev)
{
	switch (ev->type) {

	default:
		nss_cfi_dbg("unknown IPsec manager event\n");
		break;
	}
}

/*
 * nss_cfi_ipsec_dev_event()
 * 	notifier function for IPsec device events.
 */
static int nss_cfi_ipsec_dev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(3, 10, 0))
	struct net_device *hlos_dev = (struct net_device *)ptr;
#else
	struct net_device *hlos_dev = netdev_notifier_info_to_dev(ptr);
#endif
	struct nss_ipsecmgr_callback ipsec_cb;
	struct net_device *nss_dev;
	int16_t index = 0;

	switch (event) {
	case NETDEV_UP:

		index = nss_cfi_ipsec_get_index(hlos_dev->name);
		if (index < 0) {
			return NOTIFY_DONE;
		}

		ipsec_cb.ctx = hlos_dev;
		ipsec_cb.data_fn = nss_cfi_ipsec_data_cb;
		ipsec_cb.event_fn = nss_cfi_ipsec_ev_cb;

		nss_cfi_info("IPsec interface being registered: %s\n", hlos_dev->name);

		nss_dev = nss_ipsecmgr_tunnel_add(&ipsec_cb);
		if (nss_dev == NULL) {
			nss_cfi_err("NSS IPsec tunnel dev allocation failed for %s\n", hlos_dev->name);
			return NOTIFY_BAD;
		}

		tunnel_map[index].nss_dev = nss_dev;

		break;

        case NETDEV_UNREGISTER:

		index = nss_cfi_ipsec_get_index(hlos_dev->name);
		if (index < 0) {
			return NOTIFY_DONE;
		}

		nss_dev = tunnel_map[index].nss_dev;
		if (nss_dev == NULL) {
			return NOTIFY_DONE;
		}

		nss_cfi_info("IPsec interface being unregistered: %s\n", hlos_dev->name);

		nss_ipsecmgr_tunnel_del(nss_dev);

		tunnel_map[index].nss_dev = NULL;

		break;

	default:
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block nss_cfi_ipsec_notifier = {
	.notifier_call = nss_cfi_ipsec_dev_event,
};

/*
 * nss_ipsec_init_module()
 * 	Initialize IPsec rule tables and register various callbacks
 */
int __init nss_cfi_ipsec_init_module(void)
{
	int i;

	nss_cfi_info("NSS IPsec (platform - IPQ806x , %s) loaded\n", NSS_CFI_BUILD_ID);

	for (i = 0; i < NSS_CRYPTO_MAX_IDXS; i++) {
		sa_tbl[i].type = NSS_CFI_IPSEC_RULE_TYPE_NONE;
	}

	register_netdevice_notifier(&nss_cfi_ipsec_notifier);

	nss_cfi_ocf_register_ipsec(nss_cfi_ipsec_trap_encap, nss_cfi_ipsec_trap_decap, nss_cfi_ipsec_free_session);

	return 0;
}

/*
 * nss_ipsec_exit_module()
 */
void __exit nss_cfi_ipsec_exit_module(void)
{
	nss_cfi_ocf_unregister_ipsec();

	unregister_netdevice_notifier(&nss_cfi_ipsec_notifier);

	nss_cfi_info("module unloaded\n");
}


MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("NSS IPsec offload glue");

module_init(nss_cfi_ipsec_init_module);
module_exit(nss_cfi_ipsec_exit_module);

