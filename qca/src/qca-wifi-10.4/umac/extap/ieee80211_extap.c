/*
 * Copyright (c) 2010, Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/*
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <osdep_internal.h>
#include <if_llc.h>
#include <if_upperproto.h>
#include <if_media.h>
#include <ieee80211_var.h>
#include <ieee80211_defines.h>

#include <ieee80211_extap.h>
#include <ieee80211_mitbl.h>

#if EXTAP_DEBUG
#define dbg4(...)	IEEE80211_DPRINTF(NULL, 0, __VA_ARGS_)
#else
#define dbg4(...)
#endif

#if EXTAP_DEBUG
#define dbg6(...)	IEEE80211_DPRINTF(NULL, 0, __VA_ARGS_)
#else
#define dbg6(...)
#endif

#define PROTO_UDP 17
#define UDP_DST_PORT 67

#define csum_ipv6(s, d, l, p, sum)          \
	            csum_ipv6_magic((struct in6_addr *)s,       \
                      (struct in6_addr *)d, l, p, sum)

static void ieee80211_extap_out_ipv4(wlan_if_t, struct ether_header *);
static int ieee80211_extap_out_arp(wlan_if_t, struct ether_header *);

#ifdef EXTAP_DEBUG
static void print_arp_pkt(const char *, int, struct ether_header *);
#endif

#if ATH_SUPPORT_EXTAP_IPV6
static void ieee80211_extap_in_ipv6(wlan_if_t, struct ether_header *);
static int ieee80211_extap_out_ipv6(wlan_if_t, struct ether_header *);
#ifdef EXTAP_DEBUG
static void print_ipv6_pkt(char *, wlan_if_t, struct ether_header *);
#endif
#endif /* ATH_SUPPORT_EXTAP_IPV6 */

#ifdef EXTAP_DEBUG
static void
print_arp_pkt(const char *f, int l, struct ether_header *eh)
{
	eth_arphdr_t *arp = (eth_arphdr_t *)(eh + 1);

	if (arp->ar_op == qdf_htons(QDF_ARP_REQ) ||
	    arp->ar_op == qdf_htons(QDF_ARP_RREQ)) {
		eadbg1("%s(%d): arp request for " eaistr " from "
			eaistr "-" eamstr "\n", f, l,
			eaip(arp->ar_tip), eaip(arp->ar_sip),
			eamac(arp->ar_sha));
	}

	if (arp->ar_op == qdf_htons(QDF_ARP_RSP) || arp->ar_op == qdf_htons(ADF_ARP_RRSP)) {
		eadbg1("%s(%d): arp reply for " eaistr "-" eamstr " from "
			eaistr "-" eamstr "\n", f, l,
			eaip(arp->ar_tip), eamac(arp->ar_tha),
			eaip(arp->ar_sip), eamac(arp->ar_sha));
	}

}

#if ATH_SUPPORT_EXTAP_IPV6

static void
print_ipv6_pkt(char *s, wlan_if_t vap, struct ether_header *eh)
{
	qdf_net_ipv6hdr_t	*iphdr = (qdf_net_ipv6hdr_t *)(eh + 1);
	qdf_net_nd_msg_t	*nd = (qdf_net_nd_msg_t *)(iphdr + 1);

	if (iphdr->ipv6_nexthdr != NEXTHDR_ICMP) {
		return;
	}

	if (nd->nd_icmph.icmp6_type >= NDISC_ROUTER_SOLICITATION &&
	    nd->nd_icmph.icmp6_type <= NDISC_REDIRECT) {
		eth_icmp6_lladdr_t	*ha;
		char			*type,
					*nds[] = { "rsol", "r-ad", "nsol", "n-ad", "rdr" };
		ha = (eth_icmp6_lladdr_t *)nd->nd_opt;
		type = nds[nd->nd_icmph.icmp6_type - NDISC_ROUTER_SOLICITATION];
		dbg6(	"%s (%s):\ts-ip: " eastr6 "\n"
			"\t\td-ip: " eastr6 "\n"
			"s: " eamstr "\td: " eamstr "\n"
			"\tha: " eamstr " cksum = 0x%x len = %u\n", s, type,
			eaip6(iphdr->ipv6_saddr.s6_addr), eaip6(iphdr->ipv6_daddr.s6_addr),
			eamac(eh->ether_shost), eamac(eh->ether_dhost),
			eamac(ha->addr), nd->nd_icmph.icmp6_cksum, ntohs(iphdr->ipv6_payload_len));
		return;
	} else if (nd->nd_icmph.icmp6_type == ICMPV6_ECHO_REQUEST) {
		dbg6(	"%s (ping req):\ts-ip: " eastr6 "\n"
			"\t\td-ip: " eastr6 "\n"
			"s: " eamstr "\td: " eamstr "\n", s,
			eaip6(iphdr->ipv6_saddr.s6_addr), eaip6(iphdr->ipv6_daddr.s6_addr),
			eamac(eh->ether_shost), eamac(eh->ether_dhost));
	} else if (nd->nd_icmph.icmp6_type == ICMPV6_ECHO_REPLY) {
		dbg6(	"%s (ping rpl):\ts-ip: " eastr6 "\n"
			"\t\td-ip: " eastr6 "\n"
			"s: " eamstr "\td: " eamstr "\n", s,
			eaip6(iphdr->ipv6_saddr.s6_addr), eaip6(iphdr->ipv6_daddr.s6_addr),
			eamac(eh->ether_shost), eamac(eh->ether_dhost));
	} else {
		dbg6("%s unknown icmp packet 0x%x\n", s, nd->nd_icmph.icmp6_type);
		return;
	}


}
#endif /* ATH_SUPPORT_EXTAP_IPV6 */
#endif /* EXTAP_DEBUG */

#if ATH_SUPPORT_EXTAP_IPV6

static inline int is_ipv6_addr_multicast(const qdf_net_ipv6_addr_t *addr)
{
	    return (addr->s6_addr32[0] & htonl(0xff000000U)) == htonl(0xff000000U);
}

static void
ieee80211_extap_in_ipv6(wlan_if_t vap, struct ether_header *eh)
{
	qdf_net_ipv6hdr_t	*iphdr = (qdf_net_ipv6hdr_t *)(eh + 1);
	u_int8_t		*mac;

	print_ipv6("inp6", vap, eh);

	if (iphdr->ipv6_nexthdr == QDF_NEXTHDR_ICMP) {
		qdf_net_nd_msg_t	*nd = (qdf_net_nd_msg_t *)(iphdr + 1);
		eth_icmp6_lladdr_t	*ha;
		switch(nd->nd_icmph.icmp6_type) {
		case QDF_ND_NSOL:	/* ARP Request */
			ha = (eth_icmp6_lladdr_t *)nd->nd_opt;
			/* save source ip */
			mi_add(&vap->iv_ic->ic_miroot, iphdr->ipv6_saddr.s6_addr,
				ha->addr, ATH_MITBL_IPV6);
			return;
		case QDF_ND_NADVT:	/* ARP Response */
			if((is_ipv6_addr_multicast(&nd->nd_target)) || (nd->nd_icmph.icmp6_dataun.u_nd_advt.override))
			{

			ha = (eth_icmp6_lladdr_t *)nd->nd_opt;
			/* save target ip */
			mi_add(&vap->iv_ic->ic_miroot, nd->nd_target.s6_addr,
				ha->addr, ATH_MITBL_IPV6);
			}
			/*
			 * Unlike ipv4, source IP and MAC is not present.
			 * Nothing to restore in the packet
			 */
			break;
		case QDF_ND_RSOL:
		case QDF_ND_RADVT:
		default:
			/* Don't know what to do */
			;
		dbg6("%s(%d): icmp type 0x%x\n", __func__,
			__LINE__, nd->nd_icmph.icmp6_type);

		}
	} else {
		dbg6(	"inp6 (0x%x):\ts-ip: " eastr6 "\n"
			"\t\td-ip: " eastr6 "\n"
			"s: " eamstr "\td: " eamstr "\n", iphdr->ipv6_nexthdr,
			eaip6(iphdr->ipv6_saddr.s6_addr), eaip6(iphdr->ipv6_daddr.s6_addr),
			eamac(eh->ether_shost), eamac(eh->ether_dhost));
	}
	mac = mi_lkup(vap->iv_ic->ic_miroot, iphdr->ipv6_daddr.s6_addr,
			ATH_MITBL_IPV6);
	if (mac) {
		eadbg2(eh->ether_dhost, mac);
		IEEE80211_ADDR_COPY(eh->ether_dhost, mac);
	}
	print_ipv6("INP6", vap, eh);
	return;
}
#endif /* ATH_SUPPORT_EXTAP_IPV6 */

static inline bool is_multicast_group(u_int32_t addr)
{
	return ((addr & 0xf0000000) == 0xe0000000);
}

char *arps[] = { NULL, "req", "rsp", "rreq", "rrsp" };
int
ieee80211_extap_input(wlan_if_t vap, struct ether_header *eh)
{
	u_int8_t	*mac;
	u_int8_t	*sip, *dip;
	qdf_net_iphdr_t	*iphdr = NULL;
	eth_arphdr_t	*arp = NULL;

	switch (qdf_ntohs(eh->ether_type)) {
	case ETHERTYPE_IP:
		iphdr = (qdf_net_iphdr_t *)(eh + 1);
		sip = (u_int8_t *)&iphdr->ip_saddr;
		dip = (u_int8_t *)&iphdr->ip_daddr;
		break;

	case ETHERTYPE_ARP:
		arp = (eth_arphdr_t *)(eh + 1);
		dbg4("inp %s\t" eaistr "\t" eamstr "\t" eaistr "\t" eamstr "\n",
			arps[qdf_ntohs(arp->ar_op)],
			eaip(arp->ar_sip), eamac(arp->ar_sha),
            eaip(arp->ar_tip), eamac(arp->ar_tha));
        if ((arp->ar_op == qdf_htons(QDF_ARP_REQ) ||
                    arp->ar_op == qdf_htons(QDF_ARP_RREQ)) &&
                (IEEE80211_IS_MULTICAST(eh->ether_dhost))) {

			return 0;
		}

		print_arp(eh);
		sip = arp->ar_sip;
		dip = arp->ar_tip;
        	break;

	case ETHERTYPE_PAE:
		eadbg1("%s(%d): Not fwd-ing EAPOL packet from " eamstr "\n",
			__func__, __LINE__, eh->ether_shost);
		IEEE80211_ADDR_COPY(eh->ether_dhost, vap->iv_myaddr);
		return 0;
#if ATH_SUPPORT_EXTAP_IPV6
	case ETHERTYPE_IPV6:
		ieee80211_extap_in_ipv6(vap, eh);
		return 0;
#endif /* ATH_SUPPORT_EXTAP_IPV6 */
	default:
		eadbg1("%s(%d): Uknown packet type - 0x%x\n",
			__func__, __LINE__, eh->ether_type);
		return 0;
	}

	mac = mi_lkup(vap->iv_ic->ic_miroot, dip, ATH_MITBL_IPV4);
	/*
	 * XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX
	 * XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX
	 *
	 * dont do anything if destination IP is self
	 *
	 * XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX
	 * XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX
	 */
	if (mac) {
		eadbg2(eh->ether_dhost, mac);
		IEEE80211_ADDR_COPY(eh->ether_dhost, mac);

                if (qdf_ntohs(eh->ether_type) == ETHERTYPE_ARP) {
                    eadbg2(arp->ar_tha, mac);
                    IEEE80211_ADDR_COPY(arp->ar_tha, mac);
                }
	} else {
		/* XXX XXX what should we do XXX XXX */
		if ( iphdr != NULL ) {
			u_int32_t   groupaddr = 0;
			u_int8_t    groupaddr_l2[IEEE80211_ADDR_LEN];
			groupaddr = ntohl(iphdr->ip_daddr);
			if(is_multicast_group(groupaddr)) {
				groupaddr_l2[0] = 0x01;
				groupaddr_l2[1] = 0x00;
				groupaddr_l2[2] = 0x5e;
				groupaddr_l2[3] = (groupaddr >> 16) & 0x7f;
				groupaddr_l2[4] = (groupaddr >>  8) & 0xff;
				groupaddr_l2[5] = (groupaddr >>  0) & 0xff;

				IEEE80211_ADDR_COPY(eh->ether_dhost, groupaddr_l2);
			}
		}
	}
	if (arp) {
		dbg4("INP %s\t" eaistr "\t" eamstr "\t" eaistr "\t" eamstr "\n",
			arps[qdf_ntohs(arp->ar_op)],
			eaip(arp->ar_sip), eamac(arp->ar_sha),
			eaip(arp->ar_tip), eamac(arp->ar_tha));
	}
	return 0;
}

static int
ieee80211_extap_out_arp(wlan_if_t vap, struct ether_header *eh)
{
	eth_arphdr_t *arp = (eth_arphdr_t *)(eh + 1);

	print_arp(eh);

	/* For ARP requests/responses, note down the sender's details */
	mi_add(&vap->iv_ic->ic_miroot, arp->ar_sip, arp->ar_sha,
		ATH_MITBL_IPV4);

	dbg4("\t\t\tout %s\t" eaistr "\t" eamstr "\t" eaistr "\t" eamstr "\n",
		arps[qdf_ntohs(arp->ar_op)],
		eaip(arp->ar_sip), eamac(arp->ar_sha),
		eaip(arp->ar_tip), eamac(arp->ar_tha));
	dbg4("\t\t\ts: " eamstr "\td: " eamstr "\n",
		eamac(eh->ether_shost), eamac(eh->ether_dhost));

	/* Modify eth frame as if we sent */
	eadbg2(eh->ether_shost, vap->iv_myaddr);
	IEEE80211_ADDR_COPY(eh->ether_shost, vap->iv_myaddr);

	/* Modify ARP content as if we initiated the req */
	eadbg2(arp->ar_sha, vap->iv_myaddr);
	IEEE80211_ADDR_COPY(arp->ar_sha, vap->iv_myaddr);

	dbg4("\t\t\tOUT %s\t" eaistr "\t" eamstr "\t" eaistr "\t" eamstr "\n",
		arps[qdf_ntohs(arp->ar_op)],
		eaip(arp->ar_sip), eamac(arp->ar_sha),
		eaip(arp->ar_tip), eamac(arp->ar_tha));
	dbg4("\t\t\tS: " eamstr "\tD: " eamstr "\n",
		eamac(eh->ether_shost), eamac(eh->ether_dhost));

	return 0;
}

void compute_udp_checksum(qdf_net_iphdr_t *p_iph, unsigned short  *ip_payload) {
        register unsigned long sum = 0;
        qdf_net_udphdr_t *udphdrp = (qdf_net_udphdr_t *)ip_payload;
        unsigned short udpLen = htons(udphdrp->udp_len);

        sum += (p_iph->ip_saddr>>16)&0xFFFF;
        sum += (p_iph->ip_saddr)&0xFFFF;
        //the dest ip
        sum += (p_iph->ip_daddr>>16)&0xFFFF;
        sum += (p_iph->ip_daddr)&0xFFFF;
        //protocol and reserved: 17
        sum += htons(IPPROTO_UDP);
        //the length
        sum += udphdrp->udp_len;

        //add the IP payload
        //initialize checksum to 0
        udphdrp->udp_cksum = 0;
        while (udpLen > 1) {
          sum += * ip_payload++;
          udpLen -= 2;
        }
        //if any bytes left, pad the bytes and add
        if(udpLen > 0) {
          sum += ((*ip_payload)&htons(0xFF00));
        }
        //Fold sum to 16 bits: add carrier to result
        while (sum>>16) {
          sum = (sum & 0xffff) + (sum >> 16);
        }
        sum = ~sum;
        //set computation result
        udphdrp->udp_cksum = ((unsigned short)sum == 0x0000)?0xFFFF:(unsigned short)sum;
#ifdef EXTAP_DEBUG
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " UDP check sum calculated is %x \n",udphdrp->udp_cksum);
#endif
}

static void
ieee80211_extap_out_ipv4(wlan_if_t vap, struct ether_header *eh)
{
	qdf_net_iphdr_t	*iphdr = (qdf_net_iphdr_t *)(eh + 1);

	if(iphdr->ip_proto == PROTO_UDP){ /* protocol is udp*/
           qdf_net_udphdr_t *udphdr = (qdf_net_udphdr_t *) (iphdr + 1);

           if (udphdr->dst_port == htons(UDP_DST_PORT)){ /* protocol is DHCP*/
              qdf_net_dhcphdr_t *dhcphdr = (qdf_net_dhcphdr_t *) (udphdr + 1);
              if(dhcphdr->dhcp_cookie[0] == 0x63 && dhcphdr->dhcp_cookie[1] == 0x82 && dhcphdr->dhcp_cookie[2] == 0x53 && dhcphdr->dhcp_cookie[3] == 0x63) {
#ifdef EXTAP_DEBUG
                QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " Found DHCP cookie .. \n");
#endif
                if (dhcphdr->dhcp_msg_type == 1) /* dhcp REQ or DISCOVER*/
                {
#ifdef EXTAP_DEBUG
                 QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " This should be DHCP DISCOVER or REQUEST... \n");
#endif

#ifdef BIG_ENDIAN_HOST
                 if((dhcphdr->dhcp_flags & 0x8000) == 0) {
                     dhcphdr->dhcp_flags |= 0x8000;
#else
                 if((dhcphdr->dhcp_flags & 0x0080) == 0) {
                     dhcphdr->dhcp_flags |= 0x0080;
#endif

#ifdef EXTAP_DEBUG
                   QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " Make the dhcp flag to broadcast ... \n");
#endif
                   compute_udp_checksum(iphdr, (unsigned short *)udphdr);
#ifdef EXTAP_DEBUG
                   QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ReComputed udp cksum is %d .. \n", udphdr->udp_cksum);
#endif
                 }
               }
             } /* Magic cookie for DHCP*/
          } // for dhcp pkt
        }

	eadbg2(eh->ether_shost, vap->iv_myaddr);
	IEEE80211_ADDR_COPY(eh->ether_shost, vap->iv_myaddr);
}

#if ATH_SUPPORT_EXTAP_IPV6
static int
ieee80211_extap_out_ipv6(wlan_if_t vap, struct ether_header *eh)
{
	qdf_net_ipv6hdr_t	*iphdr = (qdf_net_ipv6hdr_t *)(eh + 1);
	u_int8_t		*mac, *ip;

	//dbg6("out ipv6(0x%x): " eastr6 " " eamstr,
	//	iphdr->ipv6_nexthdr,
	//	eaip6(iphdr->ipv6_saddr.s6_addr),
	//	eamac(eh->ether_shost));
	print_ipv6("out6", vap, eh);

	if (iphdr->ipv6_nexthdr == QDF_NEXTHDR_ICMP) {
		qdf_net_nd_msg_t	*nd = (qdf_net_nd_msg_t *)(iphdr + 1);
		eth_icmp6_lladdr_t	*ha;

		/* Modify eth frame as if we sent */
		eadbg2(eh->ether_shost, vap->iv_myaddr);
		IEEE80211_ADDR_COPY(eh->ether_shost, vap->iv_myaddr);

		switch(nd->nd_icmph.icmp6_type) {
		case QDF_ND_NSOL:	/* ARP Request */
			ha = (eth_icmp6_lladdr_t *)nd->nd_opt;
			/* save source ip */
			mi_add(&vap->iv_ic->ic_miroot, iphdr->ipv6_saddr.s6_addr,
				ha->addr, ATH_MITBL_IPV6);
#if ATH_EXTAP_IPV6_CSUM_RECHECK
			eadbg2(ha->addr, vap->iv_myaddr);
			IEEE80211_ADDR_COPY(ha->addr, vap->iv_myaddr);

			nd->nd_icmph.icmp6_cksum = 0;
			nd->nd_icmph.icmp6_cksum =
				csum_ipv6(&iphdr->ipv6_saddr, &iphdr->ipv6_daddr,
					ntohs(iphdr->ipv6_payload_len), IPPROTO_ICMPV6,
					csum_partial((__u8 *) nd,
						ntohs(iphdr->ipv6_payload_len), 0));
#endif /* ATH_EXTAP_IPV6_CSUM_RECHECK */
			break;
		case QDF_ND_NADVT:	/* ARP Response */

			if((is_ipv6_addr_multicast(&nd->nd_target)) || (nd->nd_icmph.icmp6_dataun.u_nd_advt.override))
			{

			ha = (eth_icmp6_lladdr_t *)nd->nd_opt;
			/* save target ip */
			mi_add(&vap->iv_ic->ic_miroot, nd->nd_target.s6_addr,
				ha->addr, ATH_MITBL_IPV6);
#if ATH_EXTAP_IPV6_CSUM_RECHECK
			eadbg2(ha->addr, vap->iv_myaddr);
			IEEE80211_ADDR_COPY(ha->addr, vap->iv_myaddr);
			}
			nd->nd_icmph.icmp6_cksum = 0;
			nd->nd_icmph.icmp6_cksum =
				csum_ipv6(&iphdr->ipv6_saddr, &iphdr->ipv6_daddr,
					ntohs(iphdr->ipv6_payload_len), IPPROTO_ICMPV6,
					csum_partial((__u8 *) nd,
						ntohs(iphdr->ipv6_payload_len), 0));
#else /* ATH_SUPPORT_EXTAP_IPV6 */
                        }
#endif /* ATH_SUPPORT_EXTAP_IPV6 */
			break;
		case QDF_ND_RSOL:
		case QDF_ND_RADVT:
		default:
			/* Don't know what to do */
			dbg6("%s(%d): icmp type 0x%x\n", __func__,
				__LINE__, nd->nd_icmph.icmp6_type);
		}
		print_ipv6("OUT6", vap, eh);
		return 0;
	} else {
		dbg6(	"out6 (0x%x):\ts-ip:" eastr6 "\n"
			"\t\td-ip: " eastr6 "\n"
			"s: " eamstr "\td: " eamstr "\n", iphdr->ipv6_nexthdr,
			eaip6(iphdr->ipv6_saddr.s6_addr), eaip6(iphdr->ipv6_daddr.s6_addr),
			eamac(eh->ether_shost), eamac(eh->ether_dhost));
	}

	ip = iphdr->ipv6_daddr.s6_addr;
	mac = mi_lkup(vap->iv_ic->ic_miroot, ip, ATH_MITBL_IPV6);

	/*
	 * XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX
	 * XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX
	 *
	 * dont do anything if destination IP is self ???
	 *
	 * XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX
	 * XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX
	 */

	if (mac) {
		eadbg2i(eh->ether_dhost, mac, ip);
		IEEE80211_ADDR_COPY(eh->ether_dhost, mac);
	} else {
		/* XXX XXX what should we do XXX XXX */
	}

	eadbg2(eh->ether_shost, vap->iv_myaddr);
	IEEE80211_ADDR_COPY(eh->ether_shost, vap->iv_myaddr);

	return 0;
}

#endif /* ATH_SUPPORT_EXTAP_IPV6 */

int
ieee80211_extap_output(wlan_if_t vap, struct ether_header *eh)
{
	switch(qdf_ntohs(eh->ether_type)) {
	case ETHERTYPE_ARP:
		return ieee80211_extap_out_arp(vap, eh);

	case ETHERTYPE_IP:
		ieee80211_extap_out_ipv4(vap, eh);
		break;

	case ETHERTYPE_PAE:
		eadbg1("%s(%d): Not fwd-ing EAPOL packet from " eamstr "\n",
			__func__, __LINE__, eh->ether_shost);
		IEEE80211_ADDR_COPY(eh->ether_shost, vap->iv_myaddr);
		break;

#if ATH_SUPPORT_EXTAP_IPV6
	case ETHERTYPE_IPV6:
		return ieee80211_extap_out_ipv6(vap, eh);
#endif

	default:
		eadbg1("%s(%d): Uknown packet type - 0x%x\n",
			__func__, __LINE__, eh->ether_type);
	}
	return 0;
}
