/*
 *
 * Copyright (c) 2017 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * Copyright (c) 2010-2014, Atheros Communications Inc.
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


#include "osif_private.h"
#include <wlan_opts.h>
#include <ieee80211_var.h>
#include <ieee80211_extap.h>
#include "htc_thread.h"
#include "if_athvar.h"
#include "ieee80211_aponly.h"
#include <ieee80211_acfg.h>
#include <acfg_drv_event.h>
#if MESH_MODE_SUPPORT
#include <if_meta_hdr.h>
#endif

#include <qdf_nbuf.h> /* qdf_nbuf_map_single */
#include <net/osif_net.h>

#include <qdf_perf.h>
#include <qdf_time.h>
#include "ath_netlink.h"

#if ATH_BAND_STEERING
#include "ath_band_steering.h"
#endif

#include "ieee80211_ev.h"
#include "ald_netlink.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
#include <fs/proc/internal.h>
#else
#include <linux/proc_fs.h>
#endif

#include <linux/seq_file.h>
#include "ieee80211_ioctl_acfg.h"
#include <ieee80211_vi_dbg.h>

#if UMAC_SUPPORT_PROXY_ARP
int wlan_proxy_arp(wlan_if_t vap, wbuf_t wbuf);
#endif

#if (HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE || HOST_SW_LRO_ENABLE || HOST_SW_SG_ENABLE)
#include <linux/ethtool.h>
#endif /* HOST_SW_TSO_ENABLE  || HOST_SW_TSO_SG_ENABLE || HOST_SW_LRO_ENABLE || HOST_SW_SG_ENABLE*/

#if UNIFIED_SMARTANTENNA
#include <if_smart_ant.h>
#endif
#include <ieee80211_nl.h>

#if ATH_SUPPORT_WRAP
#include "ieee80211_api.h"
#endif
#if ATH_PERF_PWR_OFFLOAD
#include <ol_cfg_raw.h>
#include <osif_rawmode.h>
#include <ol_if_athvar.h>
#endif /* ATH_PERF_PWR_OFFLOAD */
#include "ol_ath.h"
#include <linux/ethtool.h>
#include <osif_ol.h>

/* ahbskip usage  : Skip registering direct attach devices only when set to 1 */
unsigned int ahbskip = 0;
module_param(ahbskip, int, 0644);

#if ATH_SUPPORT_WRAP
#include "osif_wrap_private.h"
extern osif_dev * osif_wrap_wdev_find(struct wrap_devt *wdt,unsigned char *mac);
extern osif_dev * osif_wrap_wdev_vma_find(struct wrap_devt *wdt,unsigned char *mac);
#endif

extern int osif_delete_vap_wait_and_free(struct net_device *dev);
extern int ol_ath_ucfg_get_vap_info(struct ol_ath_softc_net80211 *scn,
                                    struct ieee80211_profile *profile);


#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include "osif_nss_wifiol_if.h"
#include "osif_nss_wifiol_vdev_if.h"
#endif

#if QCA_PARTNER_DIRECTLINK_TX
#define QCA_PARTNER_DIRECTLINK_OSIF_UMAC 1
#include "ath_carr_pltfrm.h"
#undef QCA_PARTNER_DIRECTLINK_OSIF_UMAC
#endif /* QCA_PARTNER_DIRECTLINK_TX */

#if !PEER_FLOW_CONTROL_FORCED_MODE0
#define TXOVERFLOW_PRINT_LIMIT 100
#endif

void ieee80211_proc_vattach(struct ieee80211vap *vap);
void ieee80211_proc_vdetach(struct ieee80211vap *vap);
#if IEEE80211_DEBUG_NODELEAK
void wlan_debug_dump_nodes_tgt(void);
#endif

#if ATH_PERF_PWR_OFFLOAD
extern int ol_print_scan_config(wlan_if_t vaphandle, struct seq_file *m);
#endif
#if MESH_MODE_SUPPORT
void (*external_tx_complete)(struct sk_buff *skb) = NULL;
EXPORT_SYMBOL(external_tx_complete);

#endif

struct ath_softc_net80211 *global_scn[GLOBAL_SCN_SIZE];
int num_global_scn = 0;

struct ol_ath_softc_net80211 *ol_global_scn[GLOBAL_SCN_SIZE] = {NULL};
int ol_num_global_scn = 0;

#ifdef CONFIG_AR900B_SUPPORT
unsigned int enable_mesh_peer_cap_update = 0;
module_param(enable_mesh_peer_cap_update, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
EXPORT_SYMBOL(enable_mesh_peer_cap_update);
#endif /* CONFIG_AR900B_SUPPORT */

#if ATH_SUPPORT_WIFIPOS
unsigned int wifiposenable  = 1;
module_param(wifiposenable, int, 0644);
EXPORT_SYMBOL(wifiposenable);
#endif  //ATH_SUPPORT_WIFIPOS


unsigned long ath_ioctl_debug = 0;      /* for run-time debugging of ioctl commands */
/* For storing LCI and LCR info for this AP */
u_int32_t ap_lcr[RTT_LOC_CIVIC_REPORT_LEN]={0};
int num_ap_lcr=0;
u_int32_t ap_lci[RTT_LOC_CIVIC_INFO_LEN]={0};
int num_ap_lci=0;
EXPORT_SYMBOL(num_ap_lci);
EXPORT_SYMBOL(ap_lci);
EXPORT_SYMBOL(num_ap_lcr);
EXPORT_SYMBOL(ap_lcr);
#if ATH_DEBUG
unsigned long ath_rtscts_enable = 0;
#endif
	A_UINT32 dscp_tid_map[WMI_HOST_DSCP_MAP_MAX] = {
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			0, 0, 0, 0, 0, 0, 0, 0,
			5, 5, 5, 5, 5, 5, 5, 5,
			5, 5, 5, 5, 5, 5, 5, 5,
			6, 6, 6, 6, 6, 6, 6, 6,
			6, 6, 6, 6, 6, 6, 6, 6,
	};
EXPORT_SYMBOL(dscp_tid_map);

struct g_wifi_info g_winfo;
EXPORT_SYMBOL(g_winfo);

qdf_spinlock_t asf_amem_lock;
qdf_spinlock_t asf_print_lock;

#ifdef OSIF_DEBUG
#define IEEE80211_ADD_MEDIA(_media, _s, _o) \
    do { \
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "adding media word 0x%x \n",IFM_MAKEWORD(IFM_IEEE80211, (_s), (_o), 0));
        ifmedia_add(_media, IFM_MAKEWORD(IFM_IEEE80211, (_s), (_o), 0), 0, NULL); \
    } while(0);
#else
#define IEEE80211_ADD_MEDIA(_media, _s, _o) \
        ifmedia_add(_media, IFM_MAKEWORD(IFM_IEEE80211, (_s), (_o), 0), 0, NULL);
#endif
#ifndef MAC2STR
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#endif

#if (HOST_SW_LRO_ENABLE && ATH_PERF_PWR_OFFLOAD)
extern unsigned int ath_lro_process_nbuf(qdf_nbuf_t nbuf, void *priv);
extern void ath_lro_flush_all(void *priv);
#endif

#ifndef QCA_PARTNER_PLATFORM
#define PARTNER_ETHTOOL_SUPPORTED 0
#endif

#if DBDC_REPEATER_SUPPORT
struct global_ic_list ic_list = {
    .radio_list_lock = __SPIN_LOCK_UNLOCKED(ic_list.radio_list_lock),
};
EXPORT_SYMBOL(ic_list);
#endif

#define OLE_HEADER_PADDING 2

#include <ieee80211.h>

void
transcap_nwifi_to_8023(qdf_nbuf_t msdu)
{
    struct ieee80211_frame_addr4 *wh;
    uint32_t hdrsize;
    struct llc *llchdr;
    struct ether_header *eth_hdr;
    uint16_t ether_type = 0;
    uint8_t a1[IEEE80211_ADDR_LEN], a2[IEEE80211_ADDR_LEN], a3[IEEE80211_ADDR_LEN], a4[IEEE80211_ADDR_LEN];
    uint8_t fc1;

    wh = (struct ieee80211_frame_addr4 *)qdf_nbuf_data(msdu);
    IEEE80211_ADDR_COPY(a1, wh->i_addr1);
    IEEE80211_ADDR_COPY(a2, wh->i_addr2);
    IEEE80211_ADDR_COPY(a3, wh->i_addr3);
    fc1 = wh->i_fc[1] & IEEE80211_FC1_DIR_MASK;

    /* Native Wifi header  give only 80211 non-Qos packets */
    if (fc1 == IEEE80211_FC1_DIR_DSTODS )
    {
        hdrsize = sizeof(struct ieee80211_frame_addr4);

        /* In case of WDS frames, , padding is enabled by default
         * in Native Wifi mode, to make ipheader 4 byte aligned
         */
        hdrsize = hdrsize + OLE_HEADER_PADDING;
    }
    else
    {
        hdrsize = sizeof(struct ieee80211_frame);
    }

    llchdr = (struct llc *)(((uint8_t *)qdf_nbuf_data(msdu)) + hdrsize);
    ether_type = llchdr->llc_un.type_snap.ether_type;

    /*
     * Now move the data pointer to the beginning of the mac header :
     * new-header = old-hdr + (wifhdrsize + llchdrsize - ethhdrsize)
     */
    qdf_nbuf_pull_head(
        msdu, (hdrsize + sizeof(struct llc) - sizeof(struct ether_header)));
    eth_hdr = (struct ether_header *)(qdf_nbuf_data(msdu));
    switch (fc1) {
    case IEEE80211_FC1_DIR_NODS:
        IEEE80211_ADDR_COPY(eth_hdr->ether_dhost, a1);
        IEEE80211_ADDR_COPY(eth_hdr->ether_shost, a2);
        break;
    case IEEE80211_FC1_DIR_TODS:
        IEEE80211_ADDR_COPY(eth_hdr->ether_dhost, a3);
        IEEE80211_ADDR_COPY(eth_hdr->ether_shost, a2);
        break;
    case IEEE80211_FC1_DIR_FROMDS:
        IEEE80211_ADDR_COPY(eth_hdr->ether_dhost, a1);
        IEEE80211_ADDR_COPY(eth_hdr->ether_shost, a3);
        break;
    case IEEE80211_FC1_DIR_DSTODS:
        IEEE80211_ADDR_COPY(a4, wh->i_addr4);
        IEEE80211_ADDR_COPY(eth_hdr->ether_dhost, a3);
        IEEE80211_ADDR_COPY(eth_hdr->ether_shost, a4);
        break;
    }
    eth_hdr->ether_type = ether_type;
}
EXPORT_SYMBOL(transcap_nwifi_to_8023);

#ifdef ATH_EXT_AP

int
ath_ext_ap_tx_process(wlan_if_t vap, struct sk_buff **skb)
{
    struct ether_header *eh;
    if (qdf_unlikely(IEEE80211_VAP_IS_EXT_AP_ENABLED(vap))) {
        if (vap->iv_opmode == IEEE80211_M_STA) {
	    *skb =  qdf_nbuf_unshare(*skb);
	    if (*skb == NULL) {
                return 1;
	    }
            eh = (struct ether_header *)((*skb)->data + vap->mhdr_len);
            if (ieee80211_extap_output(vap, eh)) {
                return 1;
            }
        } else {
#ifdef EXTAP_DEBUG
            extern char *arps[];
            eth_arphdr_t *arp = (eth_arphdr_t *)(eh + 1);
            if(eh->ether_type == ETHERTYPE_ARP) {
                QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\tOuT %s\t" eaistr "\t" eamstr "\t" eaistr "\t" eamstr "\n"
                        "\ts: " eamstr "\td: " eamstr "\n",
                        arps[arp->ar_op],
                        eaip(arp->ar_sip), eamac(arp->ar_sha),
                        eaip(arp->ar_tip), eamac(arp->ar_tha),
                        eamac(eh->ether_shost), eamac(eh->ether_dhost));
            }
#endif
        }

    }
    return 0;
}
EXPORT_SYMBOL(ath_ext_ap_tx_process);

void obss_scan_event(void * data);
void bringup_vaps_event(void * data);

static
void osif_bringup_vap_iter_func(void *arg, wlan_if_t vap);
static
void osif_bkscan_ht40_event_handler(void *arg, wlan_chan_t channel);

int ath_ext_ap_rx_process(wlan_if_t vap, struct sk_buff *skb, int *nwifi)
{
    if (qdf_unlikely(IEEE80211_VAP_IS_EXT_AP_ENABLED(vap))) {
        if (vap->iv_opmode == IEEE80211_M_STA) {
            struct ether_header *eh;
           if (*nwifi) {
               transcap_nwifi_to_8023(skb);
               *nwifi = 0;
           }

            eh = (struct ether_header *)skb->data;
            if (ieee80211_extap_input(vap, eh)) {
                return 1;
            }
        } else {
#ifdef EXTAP_DEBUG
            extern char *arps[];
            eth_arphdr_t *arp = (eth_arphdr_t *)(eh + 1);
            if(eh->ether_type == ETHERTYPE_ARP) {
                QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\tOuT %s\t" eaistr "\t" eamstr "\t" eaistr "\t" eamstr "\n"
                        "\ts: " eamstr "\td: " eamstr "\n",
                        arps[arp->ar_op],
                        eaip(arp->ar_sip), eamac(arp->ar_sha),
                        eaip(arp->ar_tip), eamac(arp->ar_tha),
                        eamac(eh->ether_shost), eamac(eh->ether_dhost));
            }
#endif
        }

    }
    return 0;
}

EXPORT_SYMBOL(ath_ext_ap_rx_process);
#endif /* ATH_EXT_AP */

#ifdef LIMIT_MTU_SIZE

static struct net_device __fake_net_device = {
    .hard_header_len    = ETH_HLEN
};

static struct rtable __fake_rtable = {
    .u = {
        .dst = {
            .__refcnt       = ATOMIC_INIT(1),
            .dev            = &__fake_net_device,
            .path           = &__fake_rtable.u.dst,
            .metrics        = {[RTAX_MTU - 1] = 1500},
        }
    },
    .rt_flags   = 0,
};
#else
#define __fake_rtable 0
#endif


#if UMAC_VOW_DEBUG
void update_vow_dbg_counters(osif_dev  *osifp, qdf_nbuf_t msdu, unsigned long *vow_counter, int rx, int peer);
#endif
void osif_check_pending_ap_vaps(wlan_dev_t comhandle, wlan_if_t vap);
static void osif_bringdown_vap_iter_func(void *arg, wlan_if_t vap);
extern void ol_notify_if_low_on_buffers(struct ath_softc_net80211 *scn, uint32_t free_buff);

extern void ieee80211_ioctl_vattach(struct net_device *dev);
extern void ieee80211_ioctl_vdetach(struct net_device *dev);
#if ATH_SUPPORT_WRAP
extern int osif_wrap_attach(wlan_dev_t comhandle);
extern int osif_wrap_detach(wlan_dev_t comhandle);
extern void osif_wrap_reinit(wlan_dev_t comhandle);
extern int osif_wrap_dev_add(osif_dev *osdev);
extern void osif_wrap_dev_remove(osif_dev *osdev);
/* TODO -
 * These definitons should be removed and osif_wrap.h should be included */
extern void osif_wrap_dev_remove_vma(osif_dev *osdev);
#endif

#ifdef QCA_PARTNER_PLATFORM
extern void wlan_pltfrm_attach(struct net_device *dev);
extern void wlan_pltfrm_detach(struct net_device *dev);
extern void osif_pltfrm_receive (os_if_t osif, wbuf_t wbuf,
                        u_int16_t type, u_int16_t subtype,
                        ieee80211_recv_status *rs);
extern void osif_pltfrm_record_macinfor(unsigned char unit, unsigned char* mac);
extern bool osif_pltfrm_deliver_data(os_if_t osif, wbuf_t wbuf);
extern void osif_pltfrm_vap_init( struct net_device *dev );
extern void osif_pltfrm_vap_stop( osif_dev  *osifp );
#endif
#if QCA_NSS_PLATFORM
extern void osif_send_to_nss(os_if_t osif, struct sk_buff *skb, int nwifi);
#endif
#if defined (QCA_PARTNER_PLATFORM) || (QCA_NSS_PLATFORM)
extern void osif_pltfrm_create_vap(osif_dev *osifp);
extern void osif_pltfrm_delete_vap(osif_dev *osifp);
#endif

#if UMAC_SUPPORT_IBSS
static int
osif_ibss_init(struct net_device *dev);
#endif

static void osif_bkscan_acs_event_handler(void *arg, wlan_chan_t channel);
static void osif_bkscan_ht40_event_handler(void *arg, wlan_chan_t channel);

/* The code below is used to register a parent file in sysfs */
static ssize_t ath_parent_show(struct device *dev,
                               struct device_attribute *attr, char *buf)
{
    struct net_device *net = to_net_dev(dev);
    osif_dev  *osifp = ath_netdev_priv(net);
    struct net_device *parent = osifp->os_comdev;

    return snprintf(buf, IFNAMSIZ,"%s\n", parent->name);
}
static DEVICE_ATTR(parent, S_IRUGO, ath_parent_show, NULL);
static struct attribute *ath_device_attrs[] = {
    &dev_attr_parent.attr,
    NULL
};

static struct attribute_group ath_attr_group = {
    .attrs  = ath_device_attrs,
};

static void osif_acs_bk_scantimer_fn( void * arg );
#ifdef USE_HEADERLEN_RESV
/*
* The kernel version of this function alters the skb in a manner
* inconsistent with dev->hard_header_len header reservation. This
* is a rewrite of the portion of eth_type_trans() that we need.
*/
static unsigned short
ath_eth_type_trans(struct sk_buff *skb, struct net_device *dev)
{
    struct ethhdr *eth;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
    skb->mac.raw = skb->data;
#else
    skb_reset_mac_header(skb);
#endif
    skb_pull(skb, ETH_HLEN);
    /*
    * NB: mac.ethernet is replaced in 2.6.9 by eth_hdr but
    *     since that's an inline and not a define there's
    *     no easy way to do this cleanly.
    */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22))
    eth= (struct ethhdr *)skb->mac.raw;
#else
    eth= (struct ethhdr *)skb_mac_header(skb);
#endif

    if(*eth->h_dest&1)
    {
        if(IEEE80211_ADDR_EQ(eth->h_dest,dev->broadcast))
            skb->pkt_type=PACKET_BROADCAST;
        else
            skb->pkt_type=PACKET_MULTICAST;
    }

    /*
    *  This ALLMULTI check should be redundant by 1.4
    *  so don't forget to remove it.
    *
    *  Seems, you forgot to remove it. All silly devices
    *  seems to set IFF_PROMISC.
    */
    else if(1 /*dev->flags&IFF_PROMISC*/)
    {
        if(!IEEE80211_ADDR_EQ(eth->h_dest,dev->dev_addr))
            skb->pkt_type=PACKET_OTHERHOST;
    }

    return eth->h_proto;
}
#endif

#ifdef ATHEROS_LINUX_PERIODIC_SCAN
static void osif_periodic_scan_start(os_if_t osif)
{
    osif_dev  *osdev = (osif_dev *) osif;
    wlan_if_t vap;

    vap = osdev->os_if;

    if (osdev->os_periodic_scan_period){
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN, "%s: Periodic Scan Timer Start. %d msec \n",
                            __func__, osdev->os_periodic_scan_period);
        OS_SET_TIMER(&osdev->os_periodic_scan_timer, osdev->os_periodic_scan_period);
    }

    return;
}

static void osif_periodic_scan_stop(os_if_t osif)
{
    osif_dev  *osdev = (osif_dev *) osif;
    wlan_if_t vap;

    vap = osdev->os_if;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN, "%s: Periodic Scan Timer Stop. \n", __func__);
    OS_CANCEL_TIMER(&osdev->os_periodic_scan_timer);

    return;
}

static OS_TIMER_FUNC(periodic_scan_timer_handler)
{
    osif_dev *osifp;
    wlan_if_t vap;
    struct net_device *dev;
    ieee80211_scan_params scan_params;
    int chan[3];
    struct ieee80211_node   *ni = NULL;
    struct ieee80211com *ic;
    OS_GET_TIMER_ARG(osifp, osif_dev *);
    vap = osifp->os_if;
    ic  = vap->iv_ic;
    dev = OSIF_TO_NETDEV(osifp);

    if (!(dev->flags & IFF_UP)) {
        return;
    }

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN, "%s: Periodic Scan Timer Go. \n", __func__);

    if ( (wlan_vap_get_opmode(vap) == IEEE80211_M_STA )  && (vap->iv_bss->ni_chwidth == IEEE80211_CWM_WIDTH40)
          && !(vap->iv_ic->ic_flags & IEEE80211_F_COEXT_DISABLE))  { /*do not trigger scan, if it disable coext is set */
        if (osifp->sm_handle &&
            wlan_connection_sm_is_connected(osifp->sm_handle) &&
            !wlan_scan_in_progress(vap)){

            OS_MEMZERO(&scan_params,sizeof(ieee80211_scan_params));

            /* Fill scan parameter */
            wlan_set_default_scan_parameters(vap,&scan_params,IEEE80211_M_STA,true,false,true,true,0,NULL,1);

            scan_params.max_dwell_time_active = 120;
            scan_params.min_dwell_time_active = 80;
            scan_params.idle_time = 610;
            scan_params.repeat_probe_time = 0;
            scan_params.min_beacon_count = 0;
            scan_params.max_scan_time = OSIF_PERIODICSCAN_MIN_PERIOD;
            scan_params.type = IEEE80211_SCAN_BACKGROUND;
            scan_params.flags |= (IEEE80211_SCAN_ALLBANDS | IEEE80211_SCAN_ACTIVE | IEEE80211_SCAN_ADD_BCAST_PROBE);

            if (osifp->os_scan_band != OSIF_SCAN_BAND_ALL) {
                scan_params.flags &= ~IEEE80211_SCAN_ALLBANDS;
                if (osifp->os_scan_band == OSIF_SCAN_BAND_2G_ONLY)
                    scan_params.flags |= IEEE80211_SCAN_2GHZ;
                else if (osifp->os_scan_band == OSIF_SCAN_BAND_5G_ONLY)
                    scan_params.flags |= IEEE80211_SCAN_5GHZ;
                else {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
                                      "%s: unknow scan band, scan all bands.\n", __func__);
                    scan_params.flags |= IEEE80211_SCAN_ALLBANDS;
                }
            }
#define HT40_CHAN_EXTENT 6
#define MAX_2_4_CHAN 15
            if(vap->iv_bsschan && IEEE80211_IS_CHAN_11N_HT40(vap->iv_bsschan)) {
                int max_chan, min_chan, nchans;
                wlan_chan_t supp_chans[MAX_2_4_CHAN];

                scan_params.chan_list = chan;
                scan_params.num_channels = 3;

                /* Get the list of supported channel */
                nchans = wlan_get_channel_list(vap->iv_ic, IEEE80211_MODE_11G,
                        supp_chans, MAX_2_4_CHAN);
                /* This is list is sorted already,
                 * Get Max and min supported chan */
                min_chan = supp_chans[0]->ic_ieee;
                max_chan = supp_chans[nchans > 0 ? nchans-1 : 0]->ic_ieee;

                /* Get to the end of 40MHz chan span in case of HT40+ and
                 * then derive centre and start of extension channel for scan
                 * for e.g.,
                 * channel 1 uses 1 - 7 block.
                 * channel 1 + 6 = 7. 7 - 2 = 5 (centre) 7 - 4 = 3
                 * similarly in HT40-, it goes back to the start of the block and
                 * then derive centre and end of extn channel.
                 */
                if (vap->iv_bsschan->ic_flags & IEEE80211_CHAN_HT40PLUS) {
                    /* MIN of maximum channel num supported in the reg domain and end of block.
                     * to sure we are not scanning on channles not supported in reg domain */
                    chan[0] = MIN((vap->iv_bsschan->ic_ieee + HT40_CHAN_EXTENT),max_chan);
                    chan[1] = chan[0] - 2;
                    chan[2] = chan[0] - 4;
                } else if (vap->iv_bsschan->ic_flags & IEEE80211_CHAN_HT40MINUS) {
                    /* MAX of minmum channel num supported in the reg domain and start of block.
                     * to be sure we are not passing negative channel num for scan */
                    chan[0] = MAX((vap->iv_bsschan->ic_ieee - HT40_CHAN_EXTENT),min_chan);
                    chan[1] = chan[0] + 2;
                    chan[2] = chan[0] + 4;
                }
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
                                  "%s: Curr chan = %d scan Chan = %d %d %d\n", __func__,
                                  vap->iv_bsschan->ic_ieee, chan[0], chan[1], chan[2]);
            }
            else {
              scan_params.chan_list = NULL;
              scan_params.num_channels = 0;
            }
            if(vap->iv_bss)
            {
                ni = vap->iv_bss;
            }

            if(ic->ic_use_custom_chan_list !=0 && vap->iv_opmode == IEEE80211_M_STA)
            {
                if(ni->ni_associd >0 && ic->ic_custom_chanlist_assoc_size)
                {
                    scan_params.chan_list = (u_int32_t *)ic->ic_custom_chan_list_associated;
                    scan_params.num_channels = ic->ic_custom_chanlist_assoc_size;
                }
                else
                {
                    if(ic->ic_custom_chanlist_nonassoc_size)
                    {
                        scan_params.chan_list = (u_int32_t *)ic->ic_custom_chan_list_nonassociated;
                        scan_params.num_channels = ic->ic_custom_chanlist_nonassoc_size;
                    }
                }
                /*flush the old scan results*/
                wlan_scan_table_flush(vap);
            }


            if (wlan_scan_start(vap, &scan_params, osifp->scan_requestor, IEEE80211_SCAN_PRIORITY_LOW, &(osifp->scan_id)) != 0 ) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
                    "%s: Issue a scan fail.\n",
                    __func__);
            }
        }

        /* restart the timer */
        osif_periodic_scan_start((os_if_t)osifp);
    }

    return;
}
#endif

#if ATH_SUPPORT_WAPI
static void
osif_wapi_rekeytimer_start (os_if_t osif)
{
    osif_dev  *osdev = (osif_dev *) osif;
//  IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "%s: WAPI Rekeying Timer Start. \n", __func__);
    OS_SET_TIMER(&osdev->os_wapi_rekey_timer, osdev->os_wapi_rekey_period);

}

static void
osif_wapi_rekeytimer_stop (os_if_t osif)
{
    osif_dev  *osdev = (osif_dev *) osif;
//  IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "%s: WAPI Rekeying Timer Stop. \n", __func__);
    OS_CANCEL_TIMER(&osdev->os_wapi_rekey_timer);

}
static OS_TIMER_FUNC(osif_wapi_rekey_timeout )
{
    osif_dev *osifp;
    wlan_if_t vap;
    struct net_device *dev;

    OS_GET_TIMER_ARG(osifp, osif_dev *);
    vap = osifp->os_if;
    dev = OSIF_TO_NETDEV(osifp);

    if (!(dev->flags & IFF_UP)) {
        return;
    }

    if(ieee80211_vap_active_is_set(vap) &&
		ieee80211_vap_wapi_is_set(vap))
    {
        if(vap->iv_wapi_urekey_pkts)
        {
            wlan_iterate_station_list(vap,
				(ieee80211_sta_iter_func)wlan_wapi_unicast_rekey, (void*)vap);
        }
        if(vap->iv_wapi_mrekey_pkts)
        {
            wlan_wapi_multicast_rekey(vap,vap->iv_bss);
         }
    }

    osif_wapi_rekeytimer_start((os_if_t)osifp);
    return;
}

#endif  /* ATH_SUPPORT_WAPI */

#if UMAC_SUPPORT_PROXY_ARP
int
do_proxy_arp(wlan_if_t vap, qdf_nbuf_t netbuf)
{
    struct ether_header *eh = (struct ether_header *)netbuf->data;

    if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
        if (qdf_unlikely(ieee80211_vap_proxyarp_is_set(vap))) {
            /* IEEE 802.11v Proxy ARP */
            if (wlan_proxy_arp(vap, netbuf))
                goto drop;
        }
#if UMAC_SUPPORT_DGAF_DISABLE
        if (qdf_unlikely(ieee80211_vap_dgaf_disable_is_set(vap))) {
            /* IEEE 802.11u DGAF Disable */
            if (IEEE80211_IS_MULTICAST(eh->ether_dhost)) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_PROXYARP, "HS20 DGAF: "
                    "discard multicast packet from %s\n",
                    ether_sprintf(eh->ether_shost));
                goto drop;
            }
        }
#endif /* UMAC_SUPPORT_DGAF_DISABLE */
    }
    return 0;

drop:
    return 1;
}
#endif /* UMAC_SUPPORT_PROXY_ARP */

#if UMAC_VOW_DEBUG
void update_vow_dbg_counters(osif_dev  *osifp, qdf_nbuf_t msdu, unsigned long *vow_counter, int rx, int peer)
{
    u_int8_t *data, *l3_hdr, *bp;
    u_int16_t ethertype;
    u_int32_t len;
    int offset;
#define ETHERNET_ADDR_LEN 6 /* bytes */
    struct vow_dbg_ethernet_hdr_t {
        u_int8_t dest_addr[ETHERNET_ADDR_LEN];
        u_int8_t src_addr[ETHERNET_ADDR_LEN];
        u_int8_t ethertype[2];
    };

#define ETHERNET_HDR_LEN (sizeof(struct vow_dbg_ethernet_hdr_t))

#ifndef ETHERTYPE_IPV4
#define ETHERTYPE_IPV4  0x0800 /* Internet Protocol, Version 4 (IPv4) */
#endif
#define IPV4_ADDR_LEN 4 /* bytes */
    struct vow_dbg_ipv4_hdr_t {
        u_int8_t ver_hdrlen;       /* version and hdr length */
        u_int8_t tos;              /* type of service */
        u_int8_t len[2];           /* total length */
        u_int8_t id[2];
        u_int8_t flags_fragoff[2]; /* flags and fragment offset field */
        u_int8_t ttl;              /* time to live */
        u_int8_t protocol;
        u_int8_t hdr_checksum[2];
        u_int8_t src_addr[IPV4_ADDR_LEN];
        u_int8_t dst_addr[IPV4_ADDR_LEN];
    };

#define IP_PROTOCOL_UDP         0x11 /* User Datagram Protocol */
#define IPV4_HDR_OFFSET_PROTOCOL (offsetof(struct vow_dbg_ipv4_hdr_t, protocol))
#define IPV4_HDR_OFFSET_TOS (offsetof(struct vow_dbg_ipv4_hdr_t, tos))
#define EXT_HDR_OFFSET 54     /* Extension header offset in network buffer */
#define UDP_PDU_RTP_EXT  0x90   /* ((2 << 6) | (1 << 4)) RTP Version 2 + X bit */
#define IP_VER4_N_NO_EXTRA_HEADERS 0x45
#define RTP_HDR_OFFSET  42
    data = qdf_nbuf_data(msdu);

    len = qdf_nbuf_len(msdu);
    if ( len < (EXT_HDR_OFFSET + 5) )
        return;

    offset = ETHERNET_ADDR_LEN * 2;
    l3_hdr = data + ETHERNET_HDR_LEN - rx;
    ethertype = (data[offset] << 8) | data[offset+1];
    if (rx || ethertype == ETHERTYPE_IPV4) {
        if(osifp->vow_dbg_en == 2) {
            int tid;
            int tos = l3_hdr[IPV4_HDR_OFFSET_TOS];
            wlan_if_t vap = osifp->os_if;

            tid = vap->iv_ic->ic_dscp_tid_map[tos>>IP_DSCP_SHIFT] & 0x7;
            if ((tid == 4) || (tid == 5)) {
                *vow_counter = *vow_counter + 1;
            }
        } else {
            offset = IPV4_HDR_OFFSET_PROTOCOL;
            if ((l3_hdr[offset] == IP_PROTOCOL_UDP) && (l3_hdr[0] == IP_VER4_N_NO_EXTRA_HEADERS)) {
                bp = data+EXT_HDR_OFFSET - rx ;

                if ( (data[RTP_HDR_OFFSET - rx] == UDP_PDU_RTP_EXT) &&
                        (bp[0] == 0x12) &&
                        (bp[1] == 0x34) &&
                        (bp[2] == 0x00) &&
                        (bp[3] == 0x08)) {

                    *vow_counter = *vow_counter + 1;
                    if( !rx && (peer >=0 && peer < MAX_VOW_CLIENTS_DBG_MONITOR) )
                    {
                        unsigned long pkt_count;
                        pkt_count = ntohl(*((unsigned long*)(bp + 4)));
                        if( pkt_count & 0x80000000 )
                            pkt_count &= 0x7FFFFFFF;
                        if( osifp->tx_prev_pkt_count[peer] )
                        {
                            if ( pkt_count > (osifp->tx_prev_pkt_count[peer] + 1) )
                                ; //printk("***TX-Gap identified for peer %d(%s) prev=%u curr=%u Gap = %d\n", peer, (peer < 3 ? "valid":"Unknown"),
                            //      tx_prev_pkt_count[peer], pkt_count, pkt_count - tx_prev_pkt_count[peer]);
                        }
                        osifp->tx_prev_pkt_count[peer] = pkt_count;
                    }
                }
            }
        }
    }
}
EXPORT_SYMBOL(update_vow_dbg_counters);
#endif

#if ATH_SUPPORT_WRAP
static inline int wrap_rx_bridge(os_if_t *osif ,struct net_device **dev ,wlan_if_t *rxvap, struct sk_buff *skb)
{
    /* Assuming native wifi or raw mode is not
     * enabled in beeliner, to be revisted later
     */
    struct ether_header *eh = (struct ether_header *) skb->data;
    wlan_if_t mpsta_vap, wrap_vap, vap = *rxvap, tvap;
    osif_dev *tx_osdev;
    int isolation = vap->iv_ic->ic_wrap_com->wc_isolation;
    int ret=0;
    mpsta_vap = vap->iv_ic->ic_mpsta_vap;
    wrap_vap = vap->iv_ic->ic_wrap_vap;

    if (isolation == 0) {

        /* Isolatio mode,Wired and wireless clients connected
         * to Qwrap Ap can talk through Qwrap bridge
         */
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_WRAP, "%s: Iso(%d)\n", __func__, isolation);
        if( ( vap->iv_mpsta==0 ) && ( vap->iv_psta ) && ( NULL != mpsta_vap ) ) {
             if(qdf_likely(!(eh->ether_type == htons(ETHERTYPE_PAE)))) {
                /*get mpsta vap , for qwrap bridge learning
                 * is always through main proxy sta
                 */
                 skb->dev = OSIF_TO_NETDEV(mpsta_vap->iv_ifp);
                 *dev = skb->dev;
                 *osif = mpsta_vap->iv_ifp;
             }
            ret=0;
        }
    } else {
        /* isolation mode enabled. Wired and wireless client
         * connected to Qwrap AP can talk through root AP
         */
        if(vap->iv_psta && vap->iv_isolation==1 && vap->iv_wired_pvap) {
            /* Packets recevied through wired psta vap */

            if(qdf_likely(!(eh->ether_type == htons(ETHERTYPE_PAE))) && (mpsta_vap != NULL)) {
                /* rx packets from wired psta should go through
                 * bridge . here qwrap bridge learning for wired proxy
                 * clients is always through main proxy sta
                 */
                skb->dev = OSIF_TO_NETDEV(mpsta_vap->iv_ifp);
                *dev = skb->dev;
                *osif = mpsta_vap->iv_ifp;
                ret=0;
        }
        } else if(vap->iv_psta && vap->iv_isolation==1 && !vap->iv_wired_pvap && !(eh->ether_type == htons(ETHERTYPE_PAE)) &&
                  (wrap_vap != NULL)) {
            /* rx unicast from wireless proxy, client
             * should always xmit through wrap AP vap
             */
            wrap_vap->iv_evtable->wlan_vap_xmit_queue(wrap_vap->iv_ifp, skb);
            ret=1;
        } else if ((vap->iv_wrap && !(eh->ether_type == htons(ETHERTYPE_PAE))) && (mpsta_vap != NULL)) {
            /* rx from wrap AP , since wrap not connected to
             * in isolation , should always xmit through
             * main proxy vap
             */
            mpsta_vap->iv_evtable->wlan_vap_xmit_queue(mpsta_vap->iv_ifp, skb);
            ret=1;
        } else if (vap->iv_mpsta && IEEE80211_IS_MULTICAST(eh->ether_dhost) && (mpsta_vap != NULL) && (wrap_vap != NULL)) {

            if((OS_MEMCMP(mpsta_vap->iv_myaddr,eh->ether_shost,6)==0))  {
                /* Multicast orginated from mpsta/bridge
             	* should always xmit through wrap AP vap
             	*/
            	wrap_vap->iv_evtable->wlan_vap_xmit_queue(wrap_vap->iv_ifp, skb);
            	ret=1;
            } else {
                tx_osdev = osif_wrap_wdev_vma_find(&vap->iv_ic->ic_wrap_com->wc_devt,eh->ether_shost);
            	if (tx_osdev) {
                    tvap = tx_osdev->os_if;
                    if(tvap->iv_wired_pvap) {
                        /*Multicast received from wired clients , forward to wrap AP side */
                        wrap_vap->iv_evtable->wlan_vap_xmit_queue(wrap_vap->iv_ifp, skb);
                        ret=1;
                    } else {
                        /*Multicast received from wireless clients , forward to bridge side */
                        skb->dev = OSIF_TO_NETDEV(mpsta_vap->iv_ifp);
                        *dev = skb->dev;
                        *osif = mpsta_vap->iv_ifp;
                        ret=0;
                    }
                } else  {
                    qdf_nbuf_t copy;
                    copy = qdf_nbuf_copy(skb);
                    /*Multicast received from clients behind root side forward to both wrap and bridge side */
                    if (copy) {
                        wrap_vap->iv_evtable->wlan_vap_xmit_queue(wrap_vap->iv_ifp, copy);
                    } else {
                       QDF_PRINT_INFO(mpsta_vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Wrap nbuf copy failed \n");
                    }
                    skb->dev = OSIF_TO_NETDEV(mpsta_vap->iv_ifp);
                    *dev = skb->dev;
                    *osif = mpsta_vap->iv_ifp;
                    ret=0;
                }
            }
        }
    }
    return ret;
}

static inline void wrap_tx_bridge_da ( wlan_if_t *vap , osif_dev **osdev,  struct sk_buff **skb) {


    /* Assuming native wifi or raw mode is not
     * enabled in beeliner, to be revisted later
     */
    struct ether_header *eh = (struct ether_header *) ((*skb)->data);
    wlan_if_t prev_vap = *vap;
    osif_dev *tx_osdev, *prev_osdev = *osdev;

    /* Mpsta vap here, find the correct tx vap from the wrap common based on src address */
    tx_osdev = osif_wrap_wdev_find(&prev_vap->iv_ic->ic_wrap_com->wc_devt,eh->ether_shost);
    if (tx_osdev) {
        if(qdf_unlikely((IEEE80211_IS_MULTICAST(eh->ether_dhost) || IEEE80211_IS_BROADCAST(eh->ether_dhost)))) {
            *skb =  qdf_nbuf_unshare(*skb);
        }
        /* since tx vap gets changed , handle tx vap synchorization */
        spin_unlock(&prev_osdev->tx_lock);
        *vap = tx_osdev->os_if;
        *osdev  = tx_osdev;
        spin_lock(&((*osdev)->tx_lock));
    }
}

#endif  /*end of ATH_SUPPORT_WRAP*/

#if ATH_SUPPORT_WRAP
int ol_wrap_rx_process (os_if_t *osif ,struct net_device **dev ,wlan_if_t vap, struct sk_buff *skb, int *nwifi)
{

    if (qdf_unlikely(wlan_is_psta(vap)) || wlan_is_wrap(vap)) {
        if (*nwifi) {
            transcap_nwifi_to_8023(skb);
            *nwifi = 0;
        }

        vap->iv_wrap_mat_rx(vap, (wbuf_t)skb);
    }
        return wrap_rx_bridge(osif, dev, &vap, skb);

}
EXPORT_SYMBOL(ol_wrap_rx_process);

#endif


#if ATH_SUPPORT_WRAP
#define DA_WRAP_TX_PROCESS(_osdev, _vap, _skb) \
{ \
    if (qdf_unlikely(wlan_is_mpsta(_vap)))   { \
        wrap_tx_bridge_da (&_vap, _osdev , _skb); \
        if (*(_skb) == NULL) {\
            goto bad;\
        }\
        if (wlan_is_psta(_vap))   { \
            vap->iv_wrap_mat_tx(_vap, (wbuf_t)*_skb); \
        } \
    } \
    if (!((*_osdev)->is_up)) {\
        goto bad; \
   } \
}

#else
#define DA_WRAP_TX_PROCESS(_osdev, _vap, _skb)
#endif /* ATH_SUPPORT_WRAP */

#if DBDC_REPEATER_SUPPORT
static int
mcast_echo_check(struct ieee80211com *ic, u_int8_t *macaddr)
{
    struct ieee80211_node *ni = NULL;
    wlan_if_t other_ic_sta_vap = NULL;
#if ATH_SUPPORT_WRAP
    wlan_if_t tmpvap;
#endif
    int i;

    for (i = 0; i < MAX_RADIO_CNT-1; i++) {
        spin_lock(&ic->ic_lock);
	if (ic->other_ic[i] == NULL) {
	    spin_unlock(&ic->ic_lock);
	    continue;
	}
	other_ic_sta_vap = ic->other_ic[i]->ic_sta_vap;

	if (other_ic_sta_vap == NULL) {
	    spin_unlock(&ic->ic_lock);
	    continue;
	}

        spin_unlock(&ic->ic_lock);
	if(IEEE80211_ADDR_EQ(macaddr, other_ic_sta_vap->iv_myaddr)) {
	    return 1;
#if ATH_SUPPORT_WRAP
	} else if (wlan_is_mpsta(other_ic_sta_vap)) {
	    TAILQ_FOREACH(tmpvap, &other_ic_sta_vap->iv_ic->ic_vaps, iv_next) {
		if (wlan_is_psta(tmpvap)) {
		    if(IEEE80211_ADDR_EQ(macaddr, tmpvap->iv_myaddr)) {
			return 1;
		    }
		}
	    }
#endif
	} else {
	    ni = ieee80211_find_node(&other_ic_sta_vap->iv_ic->ic_sta, macaddr);
	    if (ni) {
		ieee80211_free_node(ni);
		return 1;
	    }
        }
    }
    return 0;
}

static int
dbdc_rx_bridge(os_if_t *osif ,struct net_device **dev ,wlan_if_t *rxvap, struct sk_buff *skb, int *nwifi)
{
    struct ether_header *eh;
    struct ieee80211vap *vap = *rxvap;
    struct ieee80211com *ic  = vap->iv_ic;
    bool is_mcast = 0;
    bool mcast_echo = 0;
    wlan_if_t max_priority_stavap_up = ic_list.max_priority_stavap_up;
    if (*nwifi) {
       transcap_nwifi_to_8023(skb);
       *nwifi = 0;
    }

    eh = (struct ether_header *) skb->data;
    if (!ic_list.is_dbdc_rootAP) {
       /*Loop is not yet detected*/
       is_mcast = IEEE80211_IS_MULTICAST(eh->ether_dhost);
       if (is_mcast) {
           /*check for multicast echo packets*/
           mcast_echo = mcast_echo_check(ic, eh->ether_shost);
           if (mcast_echo) {
               GLOBAL_IC_LOCK(&ic_list);
               ic_list.is_dbdc_rootAP = 1;
               GLOBAL_IC_UNLOCK(&ic_list);
               QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Loop detected, Repeater connection is with DBDC RootAP\n");
               qdf_nbuf_free(skb);
               return 1;
           }
       }
       /* unicast/multicst data pkt received on secondary vap should be dropped when always_primary is set
	* This is to support always_primary in two separate ROOTAP configuration
	*/
       if (ic_list.always_primary && (vap != max_priority_stavap_up)) {
	   if(qdf_likely(!(eh->ether_type == htons(ETHERTYPE_PAE)))) {
	       qdf_nbuf_free(skb);
               return 1;
           }
       }
    } else {
       /*Loop is detected, connection is with dbdc RootAP*/
       if (vap != max_priority_stavap_up) {
           is_mcast = IEEE80211_IS_MULTICAST(eh->ether_dhost);
           if (is_mcast) {
               /* dropping mcast pkt in secondary radio */
               qdf_nbuf_free(skb);
               return 1;
           }

           if(qdf_likely(!(eh->ether_type == htons(ETHERTYPE_PAE)))) {
               /*
                * if not primary radio, bridge learning is always through other radio's sta vap
                */
               if ((max_priority_stavap_up == NULL) || (((osif_dev *)((os_if_t)max_priority_stavap_up->iv_ifp))->is_delete_in_progress))
               {
                   qdf_nbuf_free(skb);
                   return 1;
               }
               skb->dev = OSIF_TO_NETDEV(max_priority_stavap_up->iv_ifp);
               *dev = skb->dev;
               *osif = max_priority_stavap_up->iv_ifp;
           } else {
               skb->dev = *dev; /* pass on EAPOL to same interface */
           }
       } else {
           is_mcast = IEEE80211_IS_MULTICAST(eh->ether_dhost);
           if (is_mcast) {
               /*check for multicast echo packets*/
               mcast_echo = mcast_echo_check(ic, eh->ether_shost);
               if (mcast_echo) {
                   qdf_nbuf_free(skb);
                   return 1;
               }
           }
       }
    }
    return 0;
}

static int
dbdc_tx_bridge(wlan_if_t *vap , osif_dev **osdev,  struct sk_buff *skb)
{
    struct ether_header *eh = (struct ether_header *) skb->data;
    struct ieee80211vap *tx_vap = *vap;
    struct ieee80211com *ic = tx_vap->iv_ic;
    struct ieee80211_node *ni = NULL;
    struct ieee80211_node *other_ic_ni = NULL;
    struct ieee80211com *other_ic = NULL, *fastlane_ic = NULL;
    bool is_mcast = 0;
    bool is_bcast = 0;
    struct ieee80211vap *other_ic_stavap = NULL;
    struct ieee80211vap *fastlane_ic_stavap = NULL;
    wlan_if_t max_priority_stavap_up = ic_list.max_priority_stavap_up;
    uint8_t i;

    if (ic_list.is_dbdc_rootAP || ic_list.force_client_mcast_traffic || ic_list.always_primary) {
        if (ic_list.force_client_mcast_traffic && !ic_list.is_dbdc_rootAP) {
            is_mcast = IEEE80211_IS_MULTICAST(eh->ether_dhost);
            if(!is_mcast) {
                 return 0;
            }
        }
	/* Scenarios
	   1. unicast : Alwaysprimary set - in general all unicast packets
	   2. unicast : after loop is detected - in general all unicast packets
	   3. Mcast packets
	 */
	if (tx_vap == max_priority_stavap_up) {
            if (ic_list.always_primary) {
               return 0;
            }
	    for (i=0;i<MAX_RADIO_CNT-1;i++) {
		spin_lock(&ic->ic_lock);
		other_ic = ic->other_ic[i];
		spin_unlock(&ic->ic_lock);


		/* TODO - For readability move the check based on fast lane to a common place for MCAST and ucast packets*/
		if (other_ic) {
		    other_ic_ni = ieee80211_find_node(&other_ic->ic_sta,eh->ether_shost);
		} else {
                    continue;
                }
		if (other_ic_ni) {
                    /* The sender is a client of a non-primary radio */
		    ieee80211_free_node(other_ic_ni);
		    is_bcast = IEEE80211_IS_BROADCAST(eh->ether_dhost);
		    if (is_bcast && !(ic->fast_lane && other_ic->fast_lane)) {
			qdf_nbuf_free(skb);
			return 1;
		    }
		    spin_lock(&other_ic->ic_lock);
                    other_ic_stavap = other_ic->ic_sta_vap;
		    spin_unlock(&other_ic->ic_lock);

		    if (other_ic_stavap && wlan_is_connected(other_ic_stavap)) {
			if (((osif_dev *)((os_if_t)other_ic_stavap->iv_ifp))->is_delete_in_progress)
			{
			    qdf_nbuf_free(skb);
			    return 1;
			}
			other_ic_stavap->iv_evtable->wlan_vap_xmit_queue(other_ic_stavap->iv_ifp, skb);
			return 1;
		    }
		    if (other_ic->fast_lane && !ic->fast_lane) {
			/* If pkt is from fast lane radio, send it
                           on corresponding fast lane radio which is connected */
			fastlane_ic = other_ic->fast_lane_ic;
			spin_lock(&fastlane_ic->ic_lock);
			fastlane_ic_stavap = fastlane_ic->ic_sta_vap;
			spin_unlock(&fastlane_ic->ic_lock);
			if (fastlane_ic_stavap && wlan_is_connected(fastlane_ic_stavap)) {
			    if (((osif_dev *)((os_if_t)fastlane_ic_stavap->iv_ifp))->is_delete_in_progress)
			    {
				qdf_nbuf_free(skb);
				return 1;
			    }
			    fastlane_ic_stavap->iv_evtable->wlan_vap_xmit_queue(fastlane_ic_stavap->iv_ifp, skb);
			    return 1;
			}

		    }
                    return 0;
		}
	    }
        } else {
            /* Scenarios
               1. unicast : Alwaysprimary set , only when primary sta vap just conneted
               2. unicast : after loop is detected, primary sta vap call this same vap_hard_start function for secondary radio clients
               3. Mcast packet
            */
            is_mcast = IEEE80211_IS_MULTICAST(eh->ether_dhost);
	    if (ic_list.always_primary) {
		/* Send unicast pkt thru primary - do not drop
		 */
		if(qdf_likely(!(eh->ether_type == htons(ETHERTYPE_PAE)))) {
		    if (is_mcast) {
			qdf_nbuf_free(skb);
			return 1;
		    } else {
                        if (max_priority_stavap_up) {
                            if (((osif_dev *)((os_if_t)max_priority_stavap_up->iv_ifp))->is_delete_in_progress)
                            {
                               qdf_nbuf_free(skb);
                               return 1;
                            }
                            max_priority_stavap_up->iv_evtable->wlan_vap_xmit_queue(max_priority_stavap_up->iv_ifp, skb);
			    return 1;
			}
		    }
		}
	    }

            /* Check if this is from a client connected to my AP VAP
             * Or from a client connected to my fast lane AP
             */
	    if (is_mcast) {
		ni = ieee80211_find_node(&ic->ic_sta,eh->ether_shost);
		if (ni == NULL) {
		    if (ic->fast_lane && ic->fast_lane_ic) {
			fastlane_ic = ic->fast_lane_ic;
			ni = ieee80211_find_node(&fastlane_ic->ic_sta,eh->ether_shost);
			if (ni == NULL) {
			    qdf_nbuf_free(skb);
			    return 1;
			}
		    } else {
			qdf_nbuf_free(skb);
			return 1;
		    }
		}
                /*Drop the mcast frame if packet source mac address is same as that of Root AP mac address*/
                if (ni == tx_vap->iv_bss) {
                    ieee80211_free_node(ni);
                    qdf_nbuf_free(skb);
                    return 1;
                }
                ieee80211_free_node(ni);
            }
        }
    }
    return 0;
}

static int
drop_mcast_tx(wlan_if_t *vap , osif_dev **osdev,  struct sk_buff *skb)
{
    struct ether_header *eh = (struct ether_header *) skb->data;
    wlan_if_t tx_vap = *vap;
    struct ieee80211com *ic = tx_vap->iv_ic;
    bool is_mcast = 0;

    if ((tx_vap->iv_opmode == IEEE80211_M_STA) && (ic_list.num_stavaps_up > 1) && !ic->ic_primary_radio && ic_list.drop_secondary_mcast) {
       is_mcast = IEEE80211_IS_MULTICAST(eh->ether_dhost);
       if(is_mcast) {
           qdf_nbuf_free(skb);
           return 1;
       }
    }
    return 0;
}

static int
drop_mcast_rx(os_if_t *osif ,struct net_device **dev ,wlan_if_t *rxvap, struct sk_buff *skb, int *nwifi)
{
    struct ether_header *eh;
    wlan_if_t vap = *rxvap;
    struct ieee80211com *ic  = vap->iv_ic;
    bool is_mcast = 0;

    if ((vap->iv_opmode == IEEE80211_M_STA) && (ic_list.num_stavaps_up > 1) && !ic->ic_primary_radio && ic_list.drop_secondary_mcast) {
       if (*nwifi) {
           transcap_nwifi_to_8023(skb);
           *nwifi = 0;
       }

       eh = (struct ether_header *) skb->data;
       is_mcast = IEEE80211_IS_MULTICAST(eh->ether_dhost);
       if (is_mcast) {
           qdf_nbuf_free(skb);
           return 1;
       }
    }
    return 0;
}

int dbdc_rx_process (os_if_t *osif ,struct net_device **dev , struct sk_buff *skb, int *nwifi)
{
    osif_dev  *osdev = (osif_dev *)(*osif);
    wlan_if_t vap = osdev->os_if;
    if(ic_list.dbdc_process_enable) {
	if ((vap->iv_opmode == IEEE80211_M_STA) && (ic_list.num_stavaps_up > 1)) {
	    return dbdc_rx_bridge(osif, dev, &vap, skb, nwifi);
	}
    } else {
        if(ic_list.delay_stavap_connection) {
            return drop_mcast_rx(osif, dev, &vap, skb, nwifi);
        }
    }
    return 0;
}
EXPORT_SYMBOL(dbdc_rx_process);

int dbdc_tx_process (wlan_if_t vap, osif_dev **osdev , struct sk_buff *skb)
{
    if(ic_list.dbdc_process_enable) {
	if ((vap->iv_opmode == IEEE80211_M_STA) && (ic_list.num_stavaps_up > 1)) {
	    return dbdc_tx_bridge(&vap, osdev, skb);
	}
    } else {
        if(ic_list.delay_stavap_connection) {
           return drop_mcast_tx(&vap, osdev, skb);
        }
    }
    return 0;
}
EXPORT_SYMBOL(dbdc_tx_process);

#endif

#if ATH_SUPPORT_WRAP
/*
 * osif_ol_wrap_rx_process()
 *  wrap rx process
 */
int
osif_ol_wrap_rx_process(osif_dev **osifp, struct net_device **dev, wlan_if_t vap, struct sk_buff *skb)
{
    int nwifi = (*osifp)->nss_nwifi;
    if (vap == NULL) {
        qdf_nbuf_free(skb);
        return 1;
    }

    return OL_WRAP_RX_PROCESS((os_if_t *)osifp, dev, vap, skb, &nwifi);
}
EXPORT_SYMBOL(osif_ol_wrap_rx_process);
#endif

#ifdef ATH_DIRECT_ATTACH
/* accept a single sk_buff at a time */
void
osif_deliver_data(os_if_t osif, struct sk_buff *skb)
{
    struct net_device *dev = OSIF_TO_NETDEV(osif);
#if ATH_SUPPORT_WRAP
    osif_dev  *osdev = (osif_dev *)osif;
    wlan_if_t vap = osdev->os_if;
#endif
#if ATH_SUPPORT_VLAN
    osif_dev  *osifp = (osif_dev *) osif;
#endif
#if ATH_RXBUF_RECYCLE
    struct net_device *comdev;
    struct ath_softc_net80211 *scn;
    struct ath_softc *sc;
#endif /* ATH_RXBUF_RECYCLE */
    int nwifi = ((osif_dev *)osif)->nss_nwifi;

    skb->dev = dev;

    if (OL_WRAP_RX_PROCESS(&osif, &dev, vap, skb, &nwifi))
        goto done;
#if DBDC_REPEATER_SUPPORT
    if (dbdc_rx_process(&osif, &dev, skb, &nwifi))
        goto done;
#endif

#ifdef QCA_PARTNER_PLATFORM
    if ( osif_pltfrm_deliver_data(osif, skb ) )
        goto done;
#endif

#if !QCA_NSS_PLATFORM
#ifdef USE_HEADERLEN_RESV
    skb->protocol = ath_eth_type_trans(skb, dev);
#else
    skb->protocol = eth_type_trans(skb, dev);
#endif
#endif
#if ATH_RXBUF_RECYCLE
    comdev = ((osif_dev *)osif)->os_comdev;
    scn = ath_netdev_priv(comdev);
    sc = ATH_DEV_TO_SC(scn->sc_dev);
	/*
	 * Do not recycle the received mcast frame becasue it will be cloned twice
	 */
    if (sc->sc_osdev->rbr_ops.osdev_wbuf_collect && !(wbuf_is_cloned(skb))) {
        sc->sc_osdev->rbr_ops.osdev_wbuf_collect((void *)sc, (void *)skb);
    }
#endif /* ATH_RXBUF_RECYCLE */

#if ATH_SUPPORT_VLAN
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0)
    if ( osifp->vlanID != 0)
    {
        /* attach vlan tag */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
        __vlan_hwaccel_put_tag(skb, osifp->vlanID);
#else
        __vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), osifp->vlanID);
#endif
    }
#else
    if ( osifp->vlanID != 0 && osifp->vlgrp != NULL)
    {
        /* attach vlan tag */
        vlan_hwaccel_rx(skb, osifp->vlgrp, osifp->vlanID);
    }
    else
#endif
#endif

#if !QCA_NSS_PLATFORM
#ifdef ATH_SUPPORT_HTC
    qdf_nbuf_count_dec(skb);
    if (in_interrupt())
        netif_rx(skb);
    else
        netif_rx_ni(skb);
#else
    qdf_nbuf_count_dec(skb);
    netif_rx(skb);
#endif
#else /*QCA_NSS_PLATFORM*/
    osif_send_to_nss(osif, skb, 0);
#endif /*QCA_NSS_PLATFORM*/
done:
    dev->last_rx = jiffies;
}
EXPORT_SYMBOL(osif_deliver_data);
#endif /* ATH_DIRECT_ATTACH */

#define LEN_FIELD_SIZE     2

void transcap_dot3_to_eth2(struct sk_buff *skb)
{
    struct vlan_ethhdr *veh, veth_hdr;
    veh = (struct vlan_ethhdr *)skb->data;

    if (ntohs(veh->h_vlan_encapsulated_proto) >= IEEE8023_MAX_LEN)
        return;

    qdf_mem_copy(&veth_hdr, veh, sizeof(veth_hdr));
    qdf_nbuf_pull_head(skb, LEN_FIELD_SIZE);

    veh = (struct vlan_ethhdr *)skb->data;

    qdf_mem_copy(veh, &veth_hdr, (sizeof(veth_hdr) - LEN_FIELD_SIZE));
}

#if QCA_OL_VLAN_WAR
static int encap_eth2_to_dot3(qdf_nbuf_t msdu);

inline  int
_ol_tx_vlan_war(struct sk_buff **skb, struct ol_ath_softc_net80211 *scn){
    struct ether_header *eh = (struct ether_header *)((*skb)->data);
    struct ethervlan_header *evh = (struct ethervlan_header *) eh;
    if ((htons(eh->ether_type) == ETH_P_8021Q)) {
	if ((scn)->target_type == TARGET_TYPE_AR9888) {
	    /* For Peregrine, enable VLAN WAR irrespective of eth2 + VLAN packet or 802.3 + VLAN packet*/
	    *skb =  qdf_nbuf_unshare(*skb);
	    if (*skb == NULL) {
		return 1;
	    }
	    if (encap_eth2_to_dot3(*skb)){
		return 1;
	    }
	} else {
	    /* For other OL chipstes (Beeliner, Cascade, Besra, Dakota and hawkeye v1), enable VLAN WAR only for 802.3 + VLAN packet*/
	    /* This WAR is not needed in future chipsets (hawkeye v2), if this HW issue got fixed*/
	    if (htons(evh->ether_type) < IEEE8023_MAX_LEN) {
		*skb =  qdf_nbuf_unshare(*skb);
		if (*skb == NULL) {
		    return 1;
		}
		if (encap_eth2_to_dot3(*skb)){
		    return 1;
		}
	    }
	}
    }
    return 0;
}
EXPORT_SYMBOL(_ol_tx_vlan_war);
#endif /* QCA_OL_VLAN_WAR */

#if ATH_PERF_PWR_OFFLOAD

#if HOST_SW_LRO_ENABLE
void ath_lro_process_skb(struct sk_buff *skb, struct net_device *dev)
{
    unsigned int ret;
    skb->next = NULL;
    /*
     *** ath_lro_process_nbuf() function will identify if pkt
     *** is LRO eligible and if so aggregate's the pkt
     *** In this case the function returns 0.
     *** If the pkt is a non LRO eligible pkt or out-of-seq
     *** pkt then he function returns 1 and the pkt is given
     *** to netif_rx (Regular path).
     ***/

    ret = ath_lro_process_nbuf(skb, dev);
    if (ret == ATH_TCP_LRO_FAILURE || ret == ATH_TCP_LRO_NOT_SUPPORTED)
    {
        /* Pkt not consumed by LRO, send it through normal path */
        qdf_nbuf_count_dec(skb);
        skb->dev = dev;
        netif_rx(skb);
        return ;
    }
}
EXPORT_SYMBOL(ath_lro_process_skb);
#endif /* HOST_SW_LRO_ENABLE */

#if QCA_NSS_PLATFORM
#if UMAC_VOW_DEBUG || UMAC_SUPPORT_VI_DBG
extern int transcap_nwifi_hdrsize(qdf_nbuf_t msdu);
#endif

#ifdef ATH_EXT_AP
static inline int
ath_ext_ap_nss_rx_deliver(os_if_t osif,  struct sk_buff * skb, int *nwifi)
{

    osif_dev  *osdev = (osif_dev *)osif;
    wlan_if_t vap = osdev->os_if;

    if ((vap->iv_opmode == IEEE80211_M_STA) && qdf_unlikely(IEEE80211_VAP_IS_EXT_AP_ENABLED(vap))) {

        struct ether_header *eh;

        if(*nwifi) {
            transcap_nwifi_to_8023(skb);
            *nwifi = 0;
        }
        eh = (struct ether_header *)skb->data;
        if (ieee80211_extap_input(vap, eh)) {
            qdf_nbuf_free(skb);
            return 1;
        }

    }
    return 0;
}
EXPORT_SYMBOL(ath_ext_ap_nss_rx_deliver);
#else
#define ath_ext_ap_nss_rx_deliver 0
#endif
#endif /*QCA_NSS_PLATFORM*/

#if ATH_SUPPORT_WAPI
bool
osif_wai_check(os_if_t osif, struct sk_buff *skb_list_head, struct sk_buff *skb_list_tail)
{
#define TYPEORLEN(_skb) (*(u_int16_t *)((_skb)->data + IEEE80211_ADDR_LEN * 2))
#define WAI_TYPE_CHECK(_skb)  do { if(TYPEORLEN(_skb) == ETHERTYPE_WAI) return true; } while(0)

    struct sk_buff *skb;

    if(!skb_list_head) {
        return false;
    }

    do {
        skb = skb_list_head;
        skb_list_head = skb_list_head->next;
        WAI_TYPE_CHECK(skb);
    } while((skb != skb_list_tail) && !skb_list_head);

    return false;
}
EXPORT_SYMBOL(osif_wai_check);
#endif /* ATH_SUPPORT_WAPI */

#endif /* ATH_PERF_PWR_OFFLOAD */

static void
osif_deliver_l2uf(os_handle_t osif, u_int8_t *macaddr)
{
    struct net_device *dev = OSIF_TO_NETDEV(osif);
    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap;
    struct sk_buff *skb;
    struct l2_update_frame *l2uf;
    struct ether_header *eh;

    vap = osdev->os_if;
    /* add 2 more bytes to meet minimum packet size allowed with LLC headers */
    skb = qdf_nbuf_alloc(NULL, sizeof(*l2uf) + 2, 0, 0, 0);
    if (!skb)
    {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_INPUT, "%s\n",
                            "ieee80211_deliver_l2uf: no buf available");
        return;
    }
    skb_put(skb, sizeof(*l2uf) + 2);
    l2uf = (struct l2_update_frame *)(skb->data);
    eh = &l2uf->eh;
    /* dst: Broadcast address */
    IEEE80211_ADDR_COPY(eh->ether_dhost, dev->broadcast);
    /* src: associated STA */
    IEEE80211_ADDR_COPY(eh->ether_shost, macaddr);
    eh->ether_type = htons(skb->len - sizeof(*eh));

    l2uf->dsap = 0;
    l2uf->ssap = 0;
    l2uf->control = IEEE80211_L2UPDATE_CONTROL;
    l2uf->xid[0] = IEEE80211_L2UPDATE_XID_0;
    l2uf->xid[1] = IEEE80211_L2UPDATE_XID_1;
    l2uf->xid[2] = IEEE80211_L2UPDATE_XID_2;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
    skb->mac.raw = skb->data;
#else
    skb_reset_mac_header(skb);
#endif

    __osif_deliver_data(osif, skb);
}

#if DBDC_REPEATER_SUPPORT
static void
osif_hardstart_l2uf(os_handle_t osif, u_int8_t *macaddr)
{
    struct net_device *dev = OSIF_TO_NETDEV(osif);
    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap;
    struct sk_buff *skb;
    struct l2_update_frame *l2uf;
    struct ether_header *eh;

    vap = osdev->os_if;
    /* add 2 more bytes to meet minimum packet size allowed with LLC headers */
    skb = qdf_nbuf_alloc(NULL, sizeof(*l2uf) + 2, 0, 0, 0);
    if (!skb)
    {
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,  "%s\n",
                            "ieee80211_hardstart_l2uf: no buf available");
        return;
    }
    skb_put(skb, sizeof(*l2uf) + 2);
    l2uf = (struct l2_update_frame *)(skb->data);
    eh = &l2uf->eh;
    /* dst: Broadcast address */
    IEEE80211_ADDR_COPY(eh->ether_dhost, dev->broadcast);
    /* src: associated STA */
    IEEE80211_ADDR_COPY(eh->ether_shost, macaddr);
    eh->ether_type = htons(skb->len - sizeof(*eh));

    l2uf->dsap = 0;
    l2uf->ssap = 0;
    l2uf->control = IEEE80211_L2UPDATE_CONTROL;
    l2uf->xid[0] = IEEE80211_L2UPDATE_XID_0;
    l2uf->xid[1] = IEEE80211_L2UPDATE_XID_1;
    l2uf->xid[2] = IEEE80211_L2UPDATE_XID_2;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
    skb->mac.raw = skb->data;
#else
    skb_reset_mac_header(skb);
#endif
    if (vap->iv_evtable) {
        vap->iv_evtable->wlan_vap_xmit_queue(vap->iv_ifp, skb);
    }
}
#endif

static void osif_get_active_vap_iter_func(void *arg, wlan_if_t vap)
{
    osif_dev *osifp;
    u_int16_t *active_vaps = (u_int16_t *) arg;
    struct net_device *dev;

    osifp = (osif_dev *)wlan_vap_get_registered_handle(vap);
    if(osifp == NULL) {
        return;
    }
    dev = osifp->netdev;
    if (dev->flags & IFF_UP) {
        ++(*active_vaps);
    }
}

static void osif_get_running_vap_iter_func(void *arg, wlan_if_t vap)
{
    osif_dev *osifp;
    u_int16_t *running_vaps = (u_int16_t *) arg;

    osifp = (osif_dev *)wlan_vap_get_registered_handle(vap);
    if(osifp == NULL) {
        return;
    }
    if (osifp->is_up) {
        ++(*running_vaps);
    }
}

u_int32_t osif_get_num_active_vaps( wlan_dev_t  comhandle)
{
    u_int16_t num_active_vaps=0;
    wlan_iterate_vap_list(comhandle,osif_get_active_vap_iter_func,(void *)&num_active_vaps);
    return num_active_vaps;
}
#if QCA_PARTNER_PLATFORM
EXPORT_SYMBOL(osif_get_num_active_vaps);
#endif

static u_int16_t osif_get_num_running_vaps( wlan_dev_t  comhandle)
{
    u_int16_t num_running_vaps=0;
    wlan_iterate_vap_list(comhandle,osif_get_running_vap_iter_func,(void *)&num_running_vaps);
    return num_running_vaps;
}

uint32_t promisc_is_active (struct ieee80211com *ic)
{
    struct ieee80211vap *vap = NULL;
    osif_dev  *osifp = NULL;
    struct net_device *netdev = NULL;
    uint32_t promisc_active = false;

    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if (vap && (vap->iv_opmode == IEEE80211_M_MONITOR)) {
            osifp = (osif_dev *)vap->iv_ifp;
            netdev = osifp->netdev;
            promisc_active = ((netdev->flags & IFF_UP) ? true : false);
            if (promisc_active) {
                break;
            }
        }
    }
    return promisc_active;
}

#if QCA_LTEU_SUPPORT
static void
osif_nl_scan_evhandler(wlan_if_t vap, ieee80211_scan_event *event, void *arg)
{
    struct ieee80211_nl_handle *nl_handle = (struct ieee80211_nl_handle *)arg;
    osif_dev *osdev;
    struct net_device *dev;
    union iwreq_data wreq;
    struct event_data_scan scan;
    u_int8_t scan_id;

    if (!nl_handle) {
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Scan completion (type=%d reason=%d id=%d) but on non NL "
               "radio\n", __func__, event->type, event->reason, event->scan_id);
        return;
    }

    if (event->requestor != nl_handle->scanreq) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_NL, "%s: Skip requestor=%d, "
                 "nl_requestor=%d\n", __func__, event->requestor, nl_handle->scanreq);
        return;
    }

    if (event->type != IEEE80211_SCAN_COMPLETED ||
        event->reason == IEEE80211_REASON_CANCELLED) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_NL, "%s: Skip type=%d, "
                 "reason=%d\n", __func__, event->type, event->reason);
        return;
    }

    spin_lock_bh(&nl_handle->mu_lock);
    if (atomic_read(&nl_handle->scan_in_progress) == 0) {
        spin_unlock_bh(&nl_handle->mu_lock);
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Scan completion id=%d (%d), but scan not active\n",
               __func__, event->scan_id, nl_handle->scanid);
        return;
    }

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_NL, "%s: Scan completion id=%d, expected=%d, "
             "type=%d, reason=%d, userid=%d\n", __func__, event->scan_id, nl_handle->scanid,
             event->type, event->reason, nl_handle->scan_id);

    scan_id = nl_handle->scan_id;
    atomic_set(&nl_handle->scan_in_progress, 0);
    spin_unlock_bh(&nl_handle->mu_lock);

    osdev = (osif_dev *)wlan_vap_get_registered_handle(vap);
    dev = OSIF_TO_NETDEV(osdev);

    memset(&wreq, 0, sizeof(wreq));
    wreq.data.flags = IEEE80211_EV_SCAN;
    wreq.data.length = sizeof(struct event_data_scan);
    wreq.data.length = sizeof(struct event_data_scan);
    scan.scan_req_id = scan_id;
    scan.scan_status = event->reason == IEEE80211_REASON_RUN_FAILED ?
                              SCAN_FAIL : SCAN_SUCCESS;
    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wreq, (void *)&scan);

    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Scan %s, reason %d, scanid %d\n", __func__,
           event->reason == IEEE80211_REASON_RUN_FAILED ? "failed" : "succeeded",
           event->reason, nl_handle->scan_id);
}
#endif

void
osif_notify_scan_done(struct net_device *dev, ieee80211_scan_completion_reason reason)
{
    union iwreq_data wreq;
    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap;
#if DBDC_REPEATER_SUPPORT
    struct ieee80211com *ic;
    static int count = 1;
#endif

    vap = osdev->os_if;
#if DBDC_REPEATER_SUPPORT
    ic = vap->iv_ic;
    if (ic->ic_global_list->delay_stavap_connection && !(ic->ic_radio_priority ==1) && count) {
        count--;
        return;
    }
#endif
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN, "%s\n", "notify scan done");

    /* dispatch wireless event indicating scan completed */
    wreq.data.length = 0;
    wreq.data.flags = 0;
#if QCA_LTEU_SUPPORT
    if (vap->iv_ic->ic_nl_handle) {
        if (reason == IEEE80211_REASON_RUN_FAILED) {
            wreq.data.flags = IEEE80211_REASON_RUN_FAILED;
        } else {
            wreq.data.flags = IEEE80211_REASON_COMPLETED;
        }
    }
#else
    reason = reason; /* in case it warns for unused variable */
#endif
    WIRELESS_SEND_EVENT(dev, SIOCGIWSCAN, &wreq, NULL);

    if (vap->iv_ic->ic_nl_handle)
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Scan %s, reason %d\n", __func__,
               reason == IEEE80211_REASON_RUN_FAILED ? "failed" : "succeeded", reason);
}

/*
 * scan handler used by the ioctl.
 */
static void osif_scan_evhandler(wlan_if_t vap, ieee80211_scan_event *event, void *arg)
{
    osif_dev  *osifp = (osif_dev *) arg;
    struct ieee80211com *ic = vap->iv_ic;
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN, "%s scan_id %08X event %d reason %d requestor %X\n",
                      __func__, event->scan_id, event->type, event->reason, event->requestor);
#if ATH_SUPPORT_MULTIPLE_SCANS
    /*
     * Ignore notifications received due to scans requested by other modules
     * and handle new event IEEE80211_SCAN_DEQUEUED.
     */
    ASSERT(0);

    if (osifp->scan_id != event->scan_id) {
        return;
    }
#endif    /* ATH_SUPPORT_MULTIPLE_SCANS */

    /* For offchan scan, event handling is not needed */
    if ((event->requestor == osifp->offchan_scan_requestor) ||
                        ieee80211_ic_offchanscan_is_set(vap->iv_ic)) {
        return;
    }

    if ((event->type == IEEE80211_SCAN_COMPLETED) &&
        (event->reason != IEEE80211_REASON_CANCELLED) &&
        (event->requestor == osifp->scan_requestor)) {

        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s SCAN DONE  reason %d \n",
                    __func__, event->reason);

        /* Reset Probe Response override flag */
        wlan_set_device_param(ic,
                IEEE80211_DEVICE_OVERRIDE_SCAN_PROBERESPONSE_IE, 1);
#if QCA_LTEU_SUPPORT
        if (ic->ic_nl_handle) {
            spin_lock_bh(&ic->ic_nl_handle->mu_lock);
            if (atomic_read(&ic->ic_nl_handle->scan_in_progress) == 0) {
                spin_unlock_bh(&ic->ic_nl_handle->mu_lock);
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Scan completion id=%d (%d), but scan not active\n",
                       __func__, event->scan_id, osifp->scan_id);
                return;
            }

            IEEE80211_DPRINTF(vap, IEEE80211_MSG_NL, "%s: Scan completion id=%d, "
                     "expected=%d, type=%d, reason=%d\n", __func__, event->scan_id,
                     osifp->scan_id, event->type, event->reason);

            atomic_set(&ic->ic_nl_handle->scan_in_progress, 0);
            spin_unlock_bh(&ic->ic_nl_handle->mu_lock);
        }
#endif

        osif_notify_scan_done(osifp->netdev, event->reason);
        /* The AP vaps might not have come up due to this scan ... */
        /* Fix for evid 97581 - Enhancement to support independent VAP in multi mode*/
        if (!wlan_get_param(vap, IEEE80211_FEATURE_VAP_ENHIND)) {
            if ((osifp->os_opmode == IEEE80211_M_HOSTAP) ||
                /* sta-vap is ready */
                ((osifp->os_opmode == IEEE80211_M_STA) && wlan_is_connected(vap))) {
                osif_check_pending_ap_vaps(wlan_vap_get_devhandle(vap), vap);
            }
        }
    }
    if (!wlan_is_connected(vap) &&
            (vap->iv_opmode == IEEE80211_M_STA) &&
            (vap->iv_state_info.iv_state != IEEE80211_S_DFS_WAIT) &&
            (event->type == IEEE80211_SCAN_STARTED ||
            event->type == IEEE80211_SCAN_RESTARTED) &&
            !wlan_get_param(vap, IEEE80211_FEATURE_VAP_ENHIND) &&
            !(vap->iv_ic->ic_repeater_move.state == REPEATER_MOVE_IN_PROGRESS)) {
        wlan_iterate_vap_list(wlan_vap_get_devhandle(vap), osif_bringdown_vap_iter_func, NULL);
    }
}

static int osif_acs_start_bss(wlan_if_t vap, wlan_chan_t channel)
{
    int error = 0;
    osif_dev  *osifp = (osif_dev *)wlan_vap_get_registered_handle(vap);

    if ((error = wlan_mlme_start_bss(vap,0))!=0) {
        if (error == EAGAIN) {
            /* Radio resource is busy on scanning, try later */
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s :mlme busy mostly scanning \n", __func__);
            osifp->is_vap_pending = 1;
            osifp->is_up = 0;
        } else {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACS,
                              "%s : failed start bss with error code %d\n",
                              __func__, error);
        }
        return error;
    } else {
        wlan_mlme_connection_up(vap);
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACS,
                        "%s :vap up \n", __func__);
    }

    if (wlan_coext_enabled(vap))
    {
        wlan_determine_cw(vap, channel);
    }

    osifp->is_up = 1;

    return error;
}

static void osif_ht40_event_handler(void *arg, wlan_chan_t channel)
{
    int error;
    osif_dev *osifp = (osif_dev *) arg;
    wlan_if_t vap = osifp->os_if;

    if ( vap == NULL ) {
        int i;
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n%s osif: (%p) ", __func__, osifp);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\nstop_pending: (%d),is_deleted: (%d),delete_in_prog: (%d) \n",
                  osifp->is_stop_event_pending,
                   osifp->is_deleted,
                    osifp->is_delete_in_progress);
        for ( i = 0; i < 25; i++ ) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\nosif [%d] 0x%x\n",i,(unsigned int)((char *)(osifp + i)));
        }
        return;
    }

    if ((!channel) || (channel == IEEE80211_CHAN_ANYC) ||
        (osifp->is_stop_event_pending == 1))
        goto done;

    if ((error = osif_acs_start_bss(vap, channel))!=0) {
        osifp->is_vap_pending = 1;
        spin_lock(&osifp->tx_lock);
        osifp->is_up = 0;
        spin_unlock(&osifp->tx_lock);
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s :mlme busy mostly scanning \n", __func__);
    } else {
        osifp->is_up = 1;
    }

done:
    wlan_autoselect_unregister_event_handler(vap,
                                            &osif_ht40_event_handler,
                                            osifp);
}

/*
* Auto Channel Select handler used for interface up.
*/
static void osif_acs_event_handler(void *arg, wlan_chan_t channel)
{
    osif_dev *osifp = (osif_dev *) arg;
    wlan_if_t vap = osifp->os_if;
    int error = 0;

    if ((!channel) || (channel == IEEE80211_CHAN_ANYC) ||
        (osifp->is_stop_event_pending == 1))
        goto done;

    error = wlan_set_ieee80211_channel(vap, channel);
    if (error !=0) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACS,
                        "%s : failed to set channel with error code %d\n",
                        __func__, error);
        goto done;
    }

    osif_acs_start_bss(vap, channel);

    /*setting mcast rate is defered */
    if (vap->iv_mcast_rate_config_defered) {
        wlan_set_param(vap, IEEE80211_MCAST_RATE, vap->iv_mcast_rate);
        vap->iv_mcast_rate_config_defered = FALSE;
    }

    /*setting bcast rate is defered */
    if (vap->iv_bcast_rate_config_defered) {
        wlan_set_param(vap, IEEE80211_BCAST_RATE, vap->iv_bcast_fixedrate);
        vap->iv_bcast_rate_config_defered = FALSE;
    }

    /*setting mgmt rate is defered */
    if (vap->iv_mgt_rate_config_defered) {
        wlan_set_param(vap, IEEE80211_MGMT_RATE, vap->iv_mgt_rate);
        vap->iv_mgt_rate_config_defered = FALSE;
    }

    /*Set default mgmt rate*/
    if(vap->iv_mgt_rate == 0){
        if(IEEE80211_IS_CHAN_5GHZ(channel)){
            vap->iv_mgt_rate = DEFAULT_LOWEST_RATE_5G;
        }else if(IEEE80211_IS_CHAN_2GHZ(channel)){
            if (ieee80211_vap_oce_check(vap)) {
				/* Set OCE OOB rate */
                vap->iv_mgt_rate = OCE_OOB_RATE_2G;
			} else {
                vap->iv_mgt_rate = DEFAULT_LOWEST_RATE_2G;
			}
        }
    }

    /* if rates set, use previous rates */
    /* for offload radios, fw will reset rates to default everytime VAP bringup */
    if(vap->iv_mgt_rate){
        wlan_set_param(vap, IEEE80211_MGMT_RATE, vap->iv_mgt_rate);
    }
    if (vap->iv_disabled_legacy_rate_set) {
        wlan_set_param(vap, IEEE80211_RTSCTS_RATE, vap->iv_mgt_rate);
    }
    if(vap->iv_bcast_fixedrate){
        wlan_set_param(vap, IEEE80211_BCAST_RATE, vap->iv_bcast_fixedrate);
    }
    if(vap->iv_mcast_fixedrate){
        wlan_set_param(vap, IEEE80211_MCAST_RATE, vap->iv_mcast_fixedrate);
    }

    if(vap->iv_bcn_rate) {
        wlan_set_param(vap, IEEE80211_BEACON_RATE_FOR_VAP, vap->iv_bcn_rate);
    }

done:
    wlan_autoselect_unregister_event_handler(vap, &osif_acs_event_handler, (void *)osifp);
}

static void osif_start_acs_on_other_vaps(void *arg, wlan_if_t vap)
{
    osif_dev *osifp     = NULL;
    wlan_if_t *orig_vap = ((wlan_if_t *)arg);
    wlan_chan_t chan    =  NULL;

    chan = wlan_get_current_channel(vap, false);
    osifp = (osif_dev *)wlan_vap_get_registered_handle(vap);
    if(osifp == NULL) {
        return;
    }

    if(*orig_vap != vap) {
        if(osifp->is_up == 0 && vap->iv_needs_up_on_acs == 1) {
            if ((!chan) || (chan == IEEE80211_CHAN_ANYC)) {
                wlan_autoselect_register_event_handler(vap,
                            &osif_acs_event_handler,
                            (void *)wlan_vap_get_registered_handle(vap));
                wlan_autoselect_find_infra_bss_channel(vap);

                IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACS,
                            "%s: vap-%d needs acs\n", __func__, vap->iv_unit);
            }
        }
    } else {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACS,
            "%s: vap-%d brought down, acs not req.\n", __func__, vap->iv_unit);
    }
}

void delete_default_vap_keys(struct ieee80211vap *vap)
{
    int i;
    /*
     * delete any default keys, if the vap is to be deleted.
     */
     for (i=0;i<IEEE80211_WEP_NKID; ++i) {
        u_int8_t macaddr[] = {0xff,0xff,0xff,0xff,0xff,0xff };
        wlan_del_key(vap,i,macaddr);
     }
}

void osif_vap_down(struct net_device *dev)
{
    osif_dev  *osdev = ath_netdev_priv(dev);
    wlan_if_t vap = osdev->os_if;
    int waitcnt = 0;
#if QCN_IE
    struct tasklet_hrtimer *t_bpr_timer = &vap->bpr_timer;
#endif

    osdev->tx_dev_lock_acquire((void *) osdev);
    osdev->is_up = 0;
    osdev->tx_dev_lock_release((void *) osdev);

    if (osdev->os_opmode == IEEE80211_M_MONITOR) {
        struct ieee80211com    *ic = vap->iv_ic;
        int flags =  WLAN_MLME_STOP_BSS_F_NO_RESET;
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : sending MLME Event \n",__func__);
        if (!ic->ic_is_mode_offload(ic)) {
            ieee80211_vap_active_clear(vap);
            /*Call VAP down for Monitor VAP to leave the HW in Promisc mode*/
            vap->iv_down(vap);
        }
        wlan_mlme_stop_bss(vap, flags);
        OS_DELAY(1000);

        /* TODO : wait for vap stop event before letting the caller go */
        return;
    }

    if (osdev->os_opmode == IEEE80211_M_HOSTAP ||
        osdev->os_opmode ==  IEEE80211_M_P2P_GO) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : sending MLME Event \n",__func__);

        osdev->is_stop_event_pending = 1;
        if( osdev->is_delete_in_progress ) {
            wlan_mlme_stop_bss(vap,WLAN_MLME_STOP_BSS_F_FORCE_STOP_RESET);
        } else {
            wlan_mlme_stop_bss(vap,0);
        }

        /* wait for vap stop event before letting the caller go */
        waitcnt = 0;
        /*
         * commenting following line.
         * If the stop is syncronous, stop_event_pending is already cleared, so check first.
         */
        // schedule_timeout_interruptible(OSIF_STOP_VAP_TIMEOUT);
        while( osdev->is_stop_event_pending && waitcnt < OSIF_MAX_STOP_VAP_TIMEOUT_CNT) {
            schedule_timeout_interruptible(OSIF_STOP_VAP_TIMEOUT);
            waitcnt++;
            if ( osdev->is_stop_event_pending) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : XXXXXXXX WAITING FOR STOP EVENT  \n",__func__);
            }
        }
        if (osdev->is_stop_event_pending) {
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Timeout waiting for %s vap %d to stop...check\n", __FUNCTION__,
                    osdev->osif_is_mode_offload ? "OL" : "DA",
                    vap->iv_unit);
#if IEEE80211_DEBUG_NODELEAK
           QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n%s: ########## INVOKING NODELEAK DEBUG DUMP ##########\n", __func__);
           wlan_debug_dump_nodes_tgt();
#endif
        }
        osdev->is_stop_event_pending = 0;

    } else if(osdev->os_opmode == IEEE80211_M_IBSS) {
        if( osdev->is_delete_in_progress ) {
            wlan_mlme_stop_bss(vap,WLAN_MLME_STOP_BSS_F_FORCE_STOP_RESET);
        } else {
            wlan_mlme_stop_bss(vap,0);
        }

    } else if(osdev->os_opmode == IEEE80211_M_STA) {
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
            wlan_mlme_stacac_restore_defaults(vap);
#endif
    }
    OS_DELAY(1000);
    if (osdev->is_delete_in_progress) {
        OS_DELAY(5000);
        delete_default_vap_keys(vap);

        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : Keys Deleted \n",__func__);
    }
#if ATH_SUPPORT_WAPI
    if (osdev->os_opmode == IEEE80211_M_HOSTAP)
        osif_wapi_rekeytimer_stop((os_if_t)osdev);
#endif
#if QCN_IE
    if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
        tasklet_hrtimer_cancel(t_bpr_timer);
    }
#endif

    vap->iv_needs_up_on_acs = 0;
}

static void
osif_auth_complete_ap(os_handle_t osif, IEEE80211_STATUS status)
{

	struct net_device *dev = ((osif_dev *)osif)->netdev;
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif
	struct ev_msg msg;
	union iwreq_data wrqu;

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)kmalloc(sizeof(acfg_event_data_t), GFP_ATOMIC);
	if (acfg_event == NULL)
		return;

	acfg_event->result = status;
	acfg_event->downlink = 0;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_AUTH_AP, acfg_event);
#endif
	msg.status = status;
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.flags = IEEE80211_EV_AUTH_COMPLETE_AP;
	WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
#if UMAC_SUPPORT_ACFG
	kfree(acfg_event);
#endif

	return;
}

static void
osif_assoc_complete_ap(os_handle_t osif, IEEE80211_STATUS status,
						u_int16_t aid, wbuf_t wbuf)
{
	struct net_device *dev = ((osif_dev *)osif)->netdev;
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif
	union iwreq_data wrqu;
	struct ev_msg msg;

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)kmalloc(sizeof(acfg_event_data_t), GFP_ATOMIC);
	if (acfg_event == NULL)
		return;

	acfg_event->result = status;
	acfg_event->downlink = 0;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_ASSOC_AP, acfg_event);
#endif
	msg.status = status;
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.flags = IEEE80211_EV_ASSOC_COMPLETE_AP;
	WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
#if UMAC_SUPPORT_ACFG
	kfree(acfg_event);
#endif
	return;
}

static void
osif_deauth_complete_ap(os_handle_t osif, u_int8_t *macaddr,
							IEEE80211_STATUS status)
{
	struct net_device *dev = ((osif_dev *)osif)->netdev;
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif
	struct ev_msg msg;
	union iwreq_data wrqu;

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)kmalloc(sizeof(acfg_event_data_t), GFP_ATOMIC);
	if (acfg_event == NULL)
		return;

	acfg_event->result = status;
	IEEE80211_ADDR_COPY(acfg_event->addr, macaddr);
	acfg_event->downlink = 0;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_DEAUTH_AP, acfg_event);
#endif

	msg.status = status;
	IEEE80211_ADDR_COPY(msg.addr, macaddr);
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.flags = IEEE80211_EV_DEAUTH_COMPLETE_AP;
	WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
#if UMAC_SUPPORT_ACFG
	kfree(acfg_event);
#endif
	return;
}

static void
osif_auth_indication_ap(os_handle_t osif, u_int8_t *macaddr,
							u_int16_t status)
{
	struct net_device *dev = ((osif_dev *)osif)->netdev;
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif
	struct ev_msg msg;
	union iwreq_data wrqu;

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)kmalloc(sizeof(acfg_event_data_t), GFP_ATOMIC);
	if (acfg_event == NULL)
		return;

	acfg_event->result = status;
	IEEE80211_ADDR_COPY(acfg_event->addr, macaddr);
	acfg_event->downlink = 1;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_AUTH_AP, acfg_event);
#endif

	msg.status = status;
	IEEE80211_ADDR_COPY(msg.addr, macaddr);
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.flags = IEEE80211_EV_AUTH_IND_AP;
	wrqu.data.length = sizeof(msg);
	WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
#if UMAC_SUPPORT_ACFG
	kfree(acfg_event);
#endif
	return;
}
static void
osif_assoc_indication_ap(os_handle_t osif, u_int8_t *macaddr,
							u_int16_t result, wbuf_t wbuf,
							wbuf_t resp_buf, bool reassoc)
{
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    union iwreq_data wreq;
#if ATH_SUPPORT_WAPI
    union iwreq_data wapi_wreq;
    u_int8_t *sta_msg;
    int msg_len;
#endif
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif
    struct ev_msg msg;

    if (osifp->os_opmode != IEEE80211_M_P2P_GO) {
        if (!wlan_get_param(vap, IEEE80211_TRIGGER_MLME_RESP))
        {
        	OS_MEMSET(&wreq, 0, sizeof(wreq));
	        IEEE80211_ADDR_COPY(wreq.addr.sa_data, macaddr);
	        wreq.addr.sa_family = ARPHRD_ETHER;
        	WIRELESS_SEND_EVENT(dev, IWEVREGISTERED, &wreq, NULL);
        }
        IEEE80211_ADDR_COPY(msg.addr, macaddr);
        memset(&wreq, 0, sizeof(wreq));
        if(reassoc)
		wreq.data.flags = IEEE80211_EV_REASSOC_IND_AP;
        else
		wreq.data.flags = IEEE80211_EV_ASSOC_IND_AP;
        wreq.data.length = sizeof(msg);
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wreq, (char *)&msg);

#if ATH_SUPPORT_WAPI
        sta_msg = wlan_wapi_callback_begin(vap, macaddr, &msg_len, WAPI_WAI_REQUEST);
        if (sta_msg) {
            OS_MEMSET(&wapi_wreq, 0, sizeof(wapi_wreq));
            wapi_wreq.data.length = msg_len;
            wapi_wreq.data.flags = IEEE80211_EV_WAPI;
            WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wapi_wreq, sta_msg);
            wlan_wapi_callback_end(sta_msg);
        }
#endif
    }
    else { /* For P2P supplicant needs entire stuff */
        char *concat_buf;
        int wbuf_len =  wbuf_get_pktlen(wbuf);

        concat_buf = OS_MALLOC(osifp->os_handle, wbuf_len + ETHER_ADDR_LEN,
                                GFP_ATOMIC);
        if (!concat_buf) {
            return;
        }
        OS_MEMSET(&wreq, 0, sizeof(wreq));
        wreq.data.length = wbuf_len + ETHER_ADDR_LEN;
        IEEE80211_ADDR_COPY(concat_buf, macaddr);
        OS_MEMCPY(concat_buf+ETHER_ADDR_LEN, wbuf_header(wbuf), wbuf_len);

        WIRELESS_SEND_EVENT(dev, IWEVGENIE, &wreq, concat_buf);
        OS_FREE(concat_buf);
    }

    /* Send TGf L2UF frame on behalf of newly associated station */
    osif_deliver_l2uf(osif, macaddr);

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)kmalloc(sizeof(acfg_event_data_t), GFP_ATOMIC);
	if (acfg_event == NULL)
		return;

	acfg_event->result = result;
	IEEE80211_ADDR_COPY(acfg_event->addr, macaddr);
	acfg_event->downlink = 1;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_ASSOC_AP, acfg_event);
	kfree(acfg_event);
#endif
	return;
}

static void osif_deauth_indication_ap(os_handle_t osif, u_int8_t *macaddr, u_int16_t associd, u_int16_t reason)
{
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    union iwreq_data wreq;
    u_int8_t *msg;
    union iwreq_data wrqu;
    struct ev_msg evmsg;
    wlan_if_t vap = ((osif_dev *)osif)->os_if;
    union iwreq_data staleave_wreq;
    struct ev_sta_leave staleave_ev;
#if ATH_SUPPORT_WAPI
    union iwreq_data wapi_wreq;
    u_int8_t *sta_msg;
    int msg_len;
#endif
#if UMAC_SUPPORT_ACFG
    acfg_event_data_t *acfg_event = NULL;
#endif

    msg = NULL;
    /* fire off wireless event station leaving */
    memset(&wreq, 0, sizeof(wreq));
    IEEE80211_ADDR_COPY(wreq.addr.sa_data, macaddr);
    wreq.addr.sa_family = ARPHRD_ETHER;
    WIRELESS_SEND_EVENT(dev, IWEVEXPIRED, &wreq, NULL);
    ald_assoc_notify(((osif_dev *)osif)->os_if, macaddr, ALD_ACTION_DISASSOC);
#if ATH_SUPPORT_WAPI
    sta_msg = wlan_wapi_callback_begin(vap, macaddr, &msg_len, WAPI_STA_AGING);
    if (sta_msg) {
        OS_MEMSET(&wapi_wreq, 0, sizeof(wapi_wreq));
        wapi_wreq.data.length = msg_len;
        wapi_wreq.data.flags = IEEE80211_EV_WAPI;
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wapi_wreq, sta_msg);
        wlan_wapi_callback_end(sta_msg);
    }
    msg = sta_msg;
#endif
#if UMAC_SUPPORT_ACFG
    acfg_event = (acfg_event_data_t *)kmalloc(sizeof(acfg_event_data_t), GFP_ATOMIC);
    if (acfg_event == NULL)
        return;

    acfg_event->reason = reason;
    IEEE80211_ADDR_COPY(acfg_event->addr, macaddr);
    acfg_event->downlink = 1;
    acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_DEAUTH_AP, acfg_event);
#endif
    if (msg == NULL) {
        evmsg.reason = reason;
        memset(&wrqu, 0, sizeof(wrqu));
        wrqu.data.flags = IEEE80211_EV_DEAUTH_IND_AP;
        wrqu.data.length = sizeof(evmsg);
        IEEE80211_ADDR_COPY(evmsg.addr, macaddr);
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&evmsg);
    }
#if UMAC_SUPPORT_ACFG
    kfree(acfg_event);
#endif

    /* check for smart mesh configuration and send event */
    if (vap->iv_smart_mesh_cfg & SMART_MESH_80211_EVENTS) {

        OS_MEMZERO(&staleave_ev, sizeof(staleave_ev));

        /* populate required fileds */
        OS_MEMCPY(&(staleave_ev.mac_addr), macaddr, IEEE80211_ADDR_LEN);
        staleave_ev.channel_num = vap->iv_bsschan->ic_ieee;
        staleave_ev.assoc_id = IEEE80211_AID(associd);
        staleave_ev.reason = reason;

        /* prepare custom event */
        staleave_wreq.data.flags = IEEE80211_EV_STA_LEAVE;
        staleave_wreq.data.length = sizeof(staleave_ev);
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &staleave_wreq, (char *)&staleave_ev);

    }

    return;
}


static void
osif_auth_complete_sta(os_handle_t osif, IEEE80211_STATUS status)
{
	struct net_device *dev = ((osif_dev *)osif)->netdev;
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif
	union iwreq_data wrqu;
	struct ev_msg msg;

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)kmalloc(sizeof(acfg_event_data_t), GFP_ATOMIC);
	if (acfg_event == NULL)
		return;

	acfg_event->result = status;
	acfg_event->downlink = 0;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_AUTH_STA, acfg_event);
#endif

	msg.status = status;
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.flags = IEEE80211_EV_AUTH_COMPLETE_STA;
	WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
#if UMAC_SUPPORT_ACFG
	kfree(acfg_event);
#endif
	return;
}

static void
osif_assoc_complete_sta(os_handle_t osif, IEEE80211_STATUS status,
						u_int16_t aid, wbuf_t wbuf)
{
	struct net_device *dev = ((osif_dev *)osif)->netdev;
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif
	union iwreq_data wrqu;
	struct ev_msg msg;

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)kmalloc(sizeof(acfg_event_data_t), GFP_ATOMIC);
	if (acfg_event == NULL)
		return;

	acfg_event->result = status;
	acfg_event->downlink = 0;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_ASSOC_STA, acfg_event);
#endif

	msg.status = status;
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.flags = IEEE80211_EV_ASSOC_COMPLETE_STA;
	WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
#if UMAC_SUPPORT_ACFG
	kfree(acfg_event);
#endif
	return;

}

static void
osif_deauth_complete_sta(os_handle_t osif, u_int8_t *macaddr,
							IEEE80211_STATUS status)
{
	struct net_device *dev = ((osif_dev *)osif)->netdev;
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif
	union iwreq_data wrqu;
	struct ev_msg msg;

    memset(&wrqu, 0, sizeof(wrqu));
    IEEE80211_ADDR_COPY(wrqu.addr.sa_data, macaddr);
    wrqu.addr.sa_family = ARPHRD_ETHER;
    WIRELESS_SEND_EVENT(dev, IWEVEXPIRED, &wrqu, NULL);

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)kmalloc(sizeof(acfg_event_data_t), GFP_ATOMIC);
	if (acfg_event == NULL)
		return;

	acfg_event->result = status;
	IEEE80211_ADDR_COPY(acfg_event->addr, macaddr);
	acfg_event->downlink = 0;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_DEAUTH_STA, acfg_event);
#endif

	msg.status = status;
	IEEE80211_ADDR_COPY(msg.addr, macaddr);
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.flags = IEEE80211_EV_DEAUTH_COMPLETE_STA;
	WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
#if UMAC_SUPPORT_ACFG
	kfree(acfg_event);
#endif
	return;
}

static void
osif_disassoc_complete_sta(os_handle_t osif, u_int8_t *macaddr,
							u_int32_t reason,
							IEEE80211_STATUS status)
{
	struct net_device *dev = ((osif_dev *)osif)->netdev;
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event;
#endif
	struct ev_msg msg;
	union iwreq_data wrqu;

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)kmalloc(sizeof(acfg_event_data_t), GFP_ATOMIC);
	if (acfg_event == NULL)
		return;

	acfg_event->result = status;
	acfg_event->reason = reason;
	IEEE80211_ADDR_COPY(acfg_event->addr, macaddr);
	acfg_event->downlink = 0;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_DISASSOC_STA, acfg_event);
#endif

	msg.status = status;
	msg.reason = reason;
	IEEE80211_ADDR_COPY(msg.addr, macaddr);
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.flags = IEEE80211_EV_DISASSOC_COMPLETE_STA;
	WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
#if UMAC_SUPPORT_ACFG
	kfree(acfg_event);
#endif
	return;
}

static void
osif_auth_indication_sta(os_handle_t osif, u_int8_t *macaddr,
							u_int16_t status)
{
	struct net_device *dev = ((osif_dev *)osif)->netdev;
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif
	struct ev_msg msg;
	union iwreq_data wrqu;

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)kmalloc(sizeof(acfg_event_data_t), GFP_ATOMIC);
	if (acfg_event == NULL)
		return;

	acfg_event->result = status;
	IEEE80211_ADDR_COPY(acfg_event->addr, macaddr);
	acfg_event->downlink = 1;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_AUTH_STA, acfg_event);
#endif

	msg.status = status;
	IEEE80211_ADDR_COPY(msg.addr, macaddr);
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.flags = IEEE80211_EV_AUTH_IND_STA;
	WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
#if UMAC_SUPPORT_ACFG
	kfree(acfg_event);
#endif
	return;
}

static void
osif_deauth_indication_sta(os_handle_t osif, u_int8_t *macaddr,
							u_int16_t associd, u_int16_t reason)
{
	struct net_device *dev = ((osif_dev *)osif)->netdev;
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif
	union iwreq_data wrqu;
	struct ev_msg msg;

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)kmalloc(sizeof(acfg_event_data_t), GFP_ATOMIC);
	if (acfg_event == NULL)
		return;

	acfg_event->reason = reason;
	IEEE80211_ADDR_COPY(acfg_event->addr, macaddr);
	acfg_event->downlink = 1;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_DEAUTH_STA, acfg_event);
#endif

	msg.reason = reason;
	IEEE80211_ADDR_COPY(msg.addr, macaddr);
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.flags = IEEE80211_EV_DEAUTH_IND_STA;
	WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
#if UMAC_SUPPORT_ACFG
	kfree(acfg_event);
#endif
	return;
}

static void
osif_unprotected_deauth_indication_sta(os_handle_t osif, u_int8_t *macaddr,
                                                        u_int16_t associd, u_int16_t reason)
{
        struct net_device *dev = ((osif_dev *)osif)->netdev;
        union iwreq_data wrqu;
        struct ev_msg msg;

        msg.reason = reason;
        /* sa/ta addr / addr2 */
        IEEE80211_ADDR_COPY(msg.addr, macaddr);
        memset(&wrqu, 0, sizeof(wrqu));
        wrqu.data.flags = IEEE80211_EV_UNPROTECTED_DEAUTH_IND_STA;
        wrqu.data.length = sizeof(struct ev_msg);
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);

        return;

}

static void
osif_assoc_indication_sta(os_handle_t osif, u_int8_t *macaddr,
							u_int16_t result, wbuf_t wbuf,
							wbuf_t resp_buf, bool reassoc)
{
	struct net_device *dev = ((osif_dev *)osif)->netdev;
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif
	struct ev_msg msg;
	union iwreq_data wrqu;

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)kmalloc(sizeof(acfg_event_data_t), GFP_ATOMIC);
	if (acfg_event == NULL)
		return;

	acfg_event->result = result;
	IEEE80211_ADDR_COPY(acfg_event->addr, macaddr);
	acfg_event->downlink = 1;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_ASSOC_STA, acfg_event);
#endif

	msg.status = result;
	IEEE80211_ADDR_COPY(msg.addr, macaddr);
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.flags = IEEE80211_EV_ASSOC_IND_STA;
	WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
#if UMAC_SUPPORT_ACFG
	kfree(acfg_event);
#endif
	return;
}

static void osif_disassoc_indication_sta(os_handle_t osif,
									       u_int8_t *macaddr,
									       u_int16_t associd,
									       u_int32_t reason)
{
	struct net_device *dev = ((osif_dev *)osif)->netdev;
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif
	struct ev_msg msg;
	union iwreq_data wrqu;

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)kmalloc(sizeof(acfg_event_data_t), GFP_ATOMIC);
	if (acfg_event == NULL)
		return;

	acfg_event->reason = reason;
	IEEE80211_ADDR_COPY(acfg_event->addr, macaddr);
	acfg_event->downlink = 1;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_DISASSOC_STA, acfg_event);
#endif

	msg.reason = reason;
	IEEE80211_ADDR_COPY(msg.addr, macaddr);
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.flags = IEEE80211_EV_DISASSOC_IND_STA;
	WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
#if UMAC_SUPPORT_ACFG
	kfree(acfg_event);
#endif
	return;
}
#if UMAC_SUPPORT_RRM_MISC
static void  osif_nonerpcnt(os_handle_t osif, u_int8_t nonerpcnt)
{
    ath_netlink_event_t event;
    memset(&event, 0x0, sizeof(event));
    event.type = ATH_EVENT_NODE_NONERP_JOINED;
    ath_adhoc_netlink_send(&event, (char *)&nonerpcnt, sizeof(u_int8_t));
    return;
}

static void  osif_bgjoin(os_handle_t osif, u_int8_t value)
{
    ath_netlink_event_t event;
    memset(&event, 0x0, sizeof(event));
    event.type = ATH_EVENT_NODE_BG_JOINED;
    ath_adhoc_netlink_send(&event, (char *)&value, sizeof(u_int8_t));
    return;
}

static void  osif_cochannelap_cnt(os_handle_t osif, u_int8_t cnt)
{
    ath_netlink_event_t event;
    memset(&event, 0x0, sizeof(event));
    event.type = ATH_EVENT_NODE_COCHANNEL_AP_CNT;
    ath_adhoc_netlink_send(&event, (char *)&cnt, sizeof(u_int8_t));
    return;
}
static void  osif_chload(os_handle_t osif, u_int8_t chload)
{
    ath_netlink_event_t event;
    memset(&event, 0x0, sizeof(event));
    event.type = ATH_EVENT_NODE_CHLOAD;
    ath_adhoc_netlink_send(&event, (char *)&chload, sizeof(u_int8_t));
    return;
}
#endif
static void  osif_ch_hop_channel_change(os_handle_t osif, u_int8_t channel)
{
    ath_netlink_event_t event;
    memset(&event, 0x0, sizeof(event));
    event.type = ATH_EVENT_CH_HOP_CHANNEL_CHANGE;
    ath_adhoc_netlink_send(&event, (char *)&channel, sizeof(u_int8_t));
    return;
}

static void osif_recv_probereq(os_handle_t osif, u_int8_t *mac_addr ,  u_int8_t *ssid_element)
{
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    union iwreq_data wreq;
    struct ieee80211_node *ni = NULL;
    struct ieee80211_node *ni_bss = NULL;
    u_int8_t ssid_len = 0;
    struct ev_recv_probereq probe_ev;

    ssid_len = ssid_element[1];
    ni_bss = vap->iv_bss;

    if (vap->iv_smart_mesh_cfg & SMART_MESH_80211_EVENTS) {

        if ((ssid_len == 0) || ((ssid_len == ni_bss->ni_esslen)
                                && (OS_MEMCMP((ssid_element)+2, ni_bss->ni_essid, ssid_len) == 0))) {
            ni = ieee80211_find_node(&vap->iv_ic->ic_sta, mac_addr);
            if (ni) {

                OS_MEMZERO(&probe_ev, sizeof(probe_ev));

                /* populate required fileds */
                OS_MEMCPY(&(probe_ev.mac_addr), ni->ni_macaddr, IEEE80211_ADDR_LEN);
                probe_ev.rssi = ni->ni_stats.ns_rx_mgmt_rssi;
                probe_ev.rate = ni->ni_stats.ns_last_rx_mgmt_rate;
                probe_ev.channel_num = ni->ni_chan->ic_ieee;

                /* prepare custom event */
                wreq.data.flags = IEEE80211_EV_RECV_PROBEREQ;
                wreq.data.length = sizeof(probe_ev);
                WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wreq, (char *)&probe_ev);

                ieee80211_free_node(ni);
            }

        }
    }
    return;
}

#if DBDC_REPEATER_SUPPORT
static void osif_dbdc_stavap_connection (os_handle_t osif)
{
    struct net_device *dev = OSIF_TO_NETDEV(osif);
    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap;
    vap = osdev->os_if;
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Send layer2 update frame on vap:%s to detect loop\n",ether_sprintf(vap->iv_myaddr));
    osif_hardstart_l2uf(osif, vap->iv_myaddr);
}
#endif


static void osif_session_timeout(os_handle_t osif, u_int8_t *mac)
{
#if MESH_MODE_SUPPORT || UMAC_SUPPORT_ACFG
    struct net_device *dev = ((osif_dev *)osif)->netdev;
#endif

#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif

#if MESH_MODE_SUPPORT
    union iwreq_data  wrqu;
    struct ev_msg evmsg;
    evmsg.reason = IEEE80211_REASON_KICK_OUT;
    memset(&wrqu, 0, sizeof(wrqu));
    wrqu.data.flags = IEEE80211_EV_MESH_PEER_TIMEOUT;
    IEEE80211_ADDR_COPY(evmsg.addr, mac);
    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&evmsg);
#endif

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)kmalloc(sizeof(acfg_event_data_t), GFP_ATOMIC);
	if (acfg_event == NULL)
		return;

	acfg_event->reason = ACFG_SESSION_TIMEOUT;
	IEEE80211_ADDR_COPY(acfg_event->addr, mac);
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_STA_SESSION, acfg_event);
	kfree(acfg_event);
#endif
    return;
}
#if ATH_BAND_STEERING
#ifdef HOST_OFFLOAD
extern void
atd_bsteer_event_send(struct net_device *dev,
        struct ath_netlink_bsteering_event *event,
        uint16_t msg_len);
#endif

static void  osif_band_steering_event(os_handle_t osif,
                                      ATH_BSTEERING_EVENT type,
                                      uint32_t len, const char *data)
{
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    ath_netlink_bsteering_event_t  netlink_event;
#ifndef HOST_OFFLOAD
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
#endif

    memset(&netlink_event, 0x0, sizeof(netlink_event));
    netlink_event.type = type;
    netlink_event.sys_index = dev->ifindex;
    if (len && data) {
        OS_MEMCPY(&(netlink_event.data), data, len);
    }
#ifdef HOST_OFFLOAD
        atd_bsteer_event_send(((osif_dev *)osif)->netdev,
            &netlink_event,
            sizeof(ath_netlink_bsteering_event_t));
#else
    ath_band_steering_netlink_send(&netlink_event, vap->lbd_pid);
#endif
    return;

} /* void (*bsteering_event)(os_handle_t,enum,char eventlen,char *data); */
#endif
#if ATH_SSID_STEERING
static void  osif_ssid_event(os_handle_t osif, u_int8_t *macaddr)
{
    osif_dev *osifp = (osif_dev *)osif;
#if ATH_DEBUG
    wlan_if_t vap = osifp->os_if;
#endif

    ssidsteering_event_t    ssidsteering;
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: macaddr(%02x:%02x:%02x:%02x:%02x:%02x) VAP VALUE(%d)\n",
            __func__, macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);

    memset(&ssidsteering, 0x0, sizeof(ssidsteering));
    ssidsteering.type = ATH_EVENT_SSID_NODE_ASSOCIATED;
    IEEE80211_ADDR_COPY(ssidsteering.mac, macaddr);
    ath_ssid_steering_netlink_send(&ssidsteering);
} /* void (*ssid_event)(os_handle_t, u_int8_t *macaddr); */
#endif

#if UMAC_SUPPORT_ACL
static void  osif_assocdeny_event(os_handle_t osif, u_int8_t *macaddr)
{
    static const char *tag = "MLME-ASSOCDENIAL.indication";
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    osif_dev *osdev        = ath_netdev_priv(dev);
    wlan_if_t vap          = osdev->os_if;
    union iwreq_data         wrqu;
    char *buf              = NULL;
#define BUF_SIZE           128
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: macaddr(%pM) VAP(%d) device %s\n",__func__, macaddr, vap->iv_unit, dev->name);
    if(NULL != (buf = OS_MALLOC(osif, BUF_SIZE, GFP_KERNEL))){
        OS_MEMZERO(&wrqu, sizeof(wrqu));
        OS_MEMZERO(buf, BUF_SIZE);
        snprintf(buf, BUF_SIZE, "%s(macaddr=%pM, vap=%s)", tag, macaddr, dev->name);
        wrqu.data.length = strlen(buf);
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, buf);
        OS_FREE(buf);
    } else
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: failed to allocate memory of size (%d)\n",__func__,BUF_SIZE);
#undef BUF_SIZE
} /* void (*assocdeny_event)(os_handle_t, u_int8_t *macaddr); */
#endif /*UMAC_SUPPORT_ACL */

static void osif_leave_indication_ap(os_handle_t osif, u_int8_t *macaddr, u_int16_t associd, u_int32_t reason)
{
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    union iwreq_data wreq;
    u_int8_t *msg;
    union iwreq_data wrqu;
    struct ev_msg evmsg;
    wlan_if_t vap = ((osif_dev *)osif)->os_if;
    union iwreq_data staleave_wreq;
    struct ev_sta_leave staleave_ev;
#if ATH_SUPPORT_WAPI
    union iwreq_data wapi_wreq;
    u_int8_t *sta_msg;
    int msg_len;
#endif
#if UMAC_SUPPORT_ACFG
    acfg_event_data_t *acfg_event = NULL;
#endif

    msg = NULL;
    /* fire off wireless event station leaving */
    memset(&wreq, 0, sizeof(wreq));
    IEEE80211_ADDR_COPY(wreq.addr.sa_data, macaddr);
    wreq.addr.sa_family = ARPHRD_ETHER;
    WIRELESS_SEND_EVENT(dev, IWEVEXPIRED, &wreq, NULL);
    ald_assoc_notify(((osif_dev *)osif)->os_if, macaddr, ALD_ACTION_DISASSOC);
#if ATH_SUPPORT_WAPI
    sta_msg = wlan_wapi_callback_begin(vap, macaddr, &msg_len, WAPI_STA_AGING);
    if (sta_msg) {
        OS_MEMSET(&wapi_wreq, 0, sizeof(wapi_wreq));
        wapi_wreq.data.length = msg_len;
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s size:%d *\n", __func__, wreq.data.length);
        wapi_wreq.data.flags = IEEE80211_EV_WAPI;
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wapi_wreq, sta_msg);
        wlan_wapi_callback_end(sta_msg);
    }
    msg = sta_msg;
#endif
#if UMAC_SUPPORT_ACFG
    acfg_event = (acfg_event_data_t *)kmalloc(sizeof(acfg_event_data_t), GFP_ATOMIC);
    if (acfg_event == NULL)
        return;

    acfg_event->reason = reason;
    IEEE80211_ADDR_COPY(acfg_event->addr, macaddr);
    acfg_event->downlink = 1;
    acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_DISASSOC_AP, acfg_event);
#endif
    if (msg == NULL) {
        evmsg.reason = reason;
        memset(&wrqu, 0, sizeof(wrqu));
        wrqu.data.flags = IEEE80211_EV_DISASSOC_IND_AP;
        wrqu.data.length = sizeof(evmsg);
        IEEE80211_ADDR_COPY(evmsg.addr, macaddr);
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&evmsg);
    }

#if UMAC_SUPPORT_ACFG
    kfree(acfg_event);
#endif

    /* check for smart mesh configuration and send event */
    if (vap->iv_smart_mesh_cfg & SMART_MESH_80211_EVENTS) {

        OS_MEMZERO(&staleave_ev, sizeof(staleave_ev));

        /* populate required fileds */
        OS_MEMCPY(&(staleave_ev.mac_addr), macaddr, IEEE80211_ADDR_LEN);
        staleave_ev.channel_num = vap->iv_bsschan->ic_ieee;
        staleave_ev.assoc_id = IEEE80211_AID(associd);
        staleave_ev.reason = reason;

        /* prepare custom event */
        staleave_wreq.data.flags = IEEE80211_EV_STA_LEAVE;
        staleave_wreq.data.length = sizeof(staleave_ev);
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &staleave_wreq, (char *)&staleave_ev);

    }
    return;
}


static void  osif_disassoc_complete_ap(os_handle_t osif, u_int8_t *macaddr, u_int32_t reason, IEEE80211_STATUS status)
{
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    union iwreq_data wreq;
    struct ev_msg msg;
#if UMAC_SUPPORT_ACFG
	acfg_event_data_t *acfg_event = NULL;
#endif

    /* fire off wireless event station leaving */
    memset(&wreq, 0, sizeof(wreq));
    IEEE80211_ADDR_COPY(wreq.addr.sa_data, macaddr);
    wreq.addr.sa_family = ARPHRD_ETHER;
    WIRELESS_SEND_EVENT(dev, IWEVEXPIRED, &wreq, NULL);

    IEEE80211_ADDR_COPY(msg.addr, macaddr);
    memset(&wreq, 0, sizeof(wreq));
    wreq.data.flags = IEEE80211_EV_DISASSOC_COMPLETE_AP;
    wreq.data.length = sizeof(wreq);
    msg.reason=reason;
    msg.status=status;
    WIRELESS_SEND_EVENT(dev,IWEVCUSTOM,&wreq, (char *)&msg);

#if UMAC_SUPPORT_ACFG
	acfg_event = (acfg_event_data_t *)kmalloc(sizeof(acfg_event_data_t), GFP_ATOMIC);
	if (acfg_event == NULL)
		return;

	acfg_event->result = status;
	acfg_event->reason = reason;
	IEEE80211_ADDR_COPY(acfg_event->addr, macaddr);
	acfg_event->downlink = 0;
	acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_DISASSOC_AP, acfg_event);
	kfree(acfg_event);
#endif
	return;
}

static void osif_node_authorized_indication_ap(os_handle_t osif, u_int8_t *mac_addr)
{

    struct net_device *dev = ((osif_dev *)osif)->netdev;
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    union iwreq_data wreq;
    struct ieee80211_node *ni = NULL;
    struct ev_node_authorized authorize_ev;

    /* check for smart mesh configuration and send event */
    if (vap->iv_smart_mesh_cfg & SMART_MESH_80211_EVENTS) {
        ni = ieee80211_find_node(&vap->iv_ic->ic_sta, mac_addr);
        if (ni) {

            OS_MEMZERO(&authorize_ev, sizeof(authorize_ev));

            /* populate required fileds */
            OS_MEMCPY(&(authorize_ev.mac_addr), ni->ni_macaddr, IEEE80211_ADDR_LEN);
            authorize_ev.channel_num = ni->ni_chan->ic_ieee;
            authorize_ev.assoc_id = IEEE80211_AID(wlan_node_get_associd(ni));
            authorize_ev.phymode = wlan_node_get_mode(ni);
            authorize_ev.nss = wlan_node_get_nss(ni);
            authorize_ev.is_256qam   = wlan_node_get_256qam_support(ni);

            /* prepare custom event */
            wreq.data.flags = IEEE80211_EV_STA_AUTHORIZED;
            wreq.data.length = sizeof(authorize_ev);
            WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wreq, (char *)&authorize_ev);

            ieee80211_free_node(ni);
        }
    }

    return;
}

#if ATH_SUPPORT_WAPI
static void osif_rekey_indication_ap(os_handle_t osif, u_int8_t *macaddr)
{
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    wlan_if_t vap = ((osif_dev *)osif)->os_if;
    union iwreq_data wapi_wreq;
    u_int8_t *sta_msg;
    int msg_len;

    if (IEEE80211_IS_MULTICAST(macaddr))
        sta_msg = wlan_wapi_callback_begin(vap, macaddr, &msg_len, WAPI_MULTI_REKEY);
    else
        sta_msg = wlan_wapi_callback_begin(vap, macaddr, &msg_len, WAPI_UNICAST_REKEY);
    if (sta_msg) {
        OS_MEMSET(&wapi_wreq, 0, sizeof(wapi_wreq));
        wapi_wreq.data.length = msg_len;
        wapi_wreq.data.flags = IEEE80211_EV_WAPI;
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wapi_wreq, sta_msg);
        wlan_wapi_callback_end(sta_msg);
    }
}
#endif

#if ATH_SUPPORT_MGMT_TX_STATUS
/*
 * Handler to provide TX status for MGMT frames
 */
void osif_mgmt_tx_status(os_handle_t osif, IEEE80211_STATUS status, wbuf_t wbuf)
{
    osif_dev *osifp = (osif_dev *)osif;
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    union iwreq_data wreq;
    int wbuf_len =  wbuf_get_pktlen(wbuf);
    char *concat_buf;

    concat_buf = OS_MALLOC(osifp->os_handle, wbuf_len + sizeof(IEEE80211_STATUS),
                                GFP_ATOMIC);
    if (!concat_buf) {
        return;
    }

    OS_MEMSET(&wreq, 0, sizeof(wreq));
    wreq.data.flags = IEEE80211_EV_TX_MGMT;
    wreq.data.length = wbuf_len + sizeof(IEEE80211_STATUS);
    *((IEEE80211_STATUS*)concat_buf) = status;
    OS_MEMCPY(concat_buf+sizeof(IEEE80211_STATUS), wbuf_header(wbuf), wbuf_len);
    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wreq, concat_buf);
    OS_FREE(concat_buf);
}
#endif
/*
 * handler called when the AP vap comes up asynchronously.
 * (happens only when resource  manager is present).
 */
static void  osif_create_infra_complete( os_handle_t osif, IEEE80211_STATUS status)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = ((osif_dev *)osif)->os_if;
    struct net_device *dev;

    dev = OSIF_TO_NETDEV(osifp);

	if(osifp->is_delete_in_progress)
		return;

    if(status == IEEE80211_STATUS_SUCCESS) {
        wlan_mlme_connection_up(vap);
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s :vap-%d up\n", __func__, vap->iv_unit);
        osifp->is_up = 1;
    } else {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s :vap-%d down, status=%d\n", __func__, vap->iv_unit, status);
        osifp->is_up = 0;
        dev->flags &= ~(IFF_RUNNING | IFF_UP);
    }

}

static void bringup_ap_vaps(void *arg, wlan_if_t vap)
{
    enum ieee80211_state cur_state;
    int count = 0;

    if (wlan_vap_get_opmode(vap) == IEEE80211_M_HOSTAP) {
        for (count = 0; count < 50; count++) {
            cur_state =(enum ieee80211_state)vap->iv_state_info.iv_state;
            if(cur_state == IEEE80211_S_INIT) {
                osif_bringup_vap_iter_func(NULL, vap);
                break;
            } else {
                schedule_timeout_interruptible(10);
            }
        }
        if (count == 50) {
            ASSERT(0);
        }
    }
}

static void osif_bringup_vap_iter_func(void *arg, wlan_if_t vap)
{
    osif_dev  *osifp = NULL;
    int error;
    struct net_device *dev;

    if (wlan_vap_get_opmode(vap) != IEEE80211_M_HOSTAP) {
        return;
    }
    osifp  = (osif_dev *)wlan_vap_get_registered_handle(vap);
    if(osifp == NULL) {
        return;
    }

    dev = OSIF_TO_NETDEV(osifp);
    if(dev == NULL) {
        return;
    }
    if (!(dev->flags & IFF_UP)) {
        return;
    }

    if(arg) {
        if(((struct ieee80211_vap_info *)arg)->chan) {
            vap->iv_des_chan[vap->iv_des_mode] = ((struct ieee80211_vap_info *)arg)->chan;
        }
        vap->iv_no_cac = ((struct ieee80211_vap_info *)arg)->no_cac;
    } else {
        vap->iv_no_cac = 0;
    }


    if ((!osifp->is_up) && (!osifp->is_delete_in_progress)) {
        if ((error = wlan_mlme_start_bss(vap,0))!=0) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE,
                        "Error %s : failed start bss with error code %d\n",
                        __func__, error);
        } else {
            wlan_mlme_connection_up(vap);
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE,
                        "%s :vap up \n", __func__);
            osifp->is_up = 1;
            osifp->is_vap_pending = 0;
        }
    } else {
        vap->iv_no_cac = 0;
    }
}

static void
osif_bringdown_vap_iter_obss_scan_func(void *arg, wlan_if_t vap)
{
    int waitcnt;
    osif_dev  *osifp = (osif_dev *)wlan_vap_get_registered_handle(vap);

    if(wlan_vap_get_opmode(vap) != IEEE80211_M_HOSTAP) {
        return;
    }

    if (osifp->is_up) {
        osifp->is_stop_event_pending = 1;
        wlan_mlme_stop_bss(vap, 0);

        /* wait for vap stop event before letting the caller go */
        waitcnt = 0;
        schedule_timeout_interruptible(OSIF_STOP_VAP_TIMEOUT);
        while(osifp->is_stop_event_pending && (waitcnt < OSIF_MAX_STOP_VAP_TIMEOUT_CNT)) {
            schedule_timeout_interruptible(OSIF_STOP_VAP_TIMEOUT);
            waitcnt++;
            if ( osifp->is_stop_event_pending) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : XXXXXXXX WAITING FOR STOP EVENT  \n",__func__);
            }
        }

        OS_DELAY(1000);
        if (osifp->is_stop_event_pending) {
#if IEEE80211_DEBUG_NODELEAK
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n%s: ########## INVOKING NODELEAK DEBUG DUMP ##########\n", __func__);
            wlan_debug_dump_nodes_tgt();
#endif
            return;
        }

        osifp->is_stop_event_pending = 0;
        wlan_mlme_connection_down(vap);
        spin_lock(&osifp->tx_lock);
        osifp->is_up = 0;
        spin_unlock(&osifp->tx_lock);
    }
}

static void osif_bringdown_vap_iter_func(void *arg, wlan_if_t vap)
{
    osif_dev  *osifp = NULL;

    osifp  = (osif_dev *)wlan_vap_get_registered_handle(vap);
    if(osifp == NULL) {
        return;
    }
    if(wlan_vap_get_opmode(vap) != IEEE80211_M_HOSTAP) {
        return;
    }
	if (osifp->is_up) {
		wlan_mlme_stop_bss(vap,0);
		wlan_mlme_connection_down(vap);
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE,
				"%s :vap down \n", __func__);
		spin_lock(&osifp->tx_lock);
		osifp->is_up = 0;
		spin_unlock(&osifp->tx_lock);
	}
}


static void osif_restart_start_vap_iter_func(void *arg, wlan_if_t vap)
{
    osif_dev  *osifp = NULL;
    int error;

    if (wlan_vap_get_opmode(vap) != IEEE80211_M_HOSTAP) {
        return;
    }

    if(arg)
        vap->iv_des_chan[vap->iv_des_mode] = (struct ieee80211_channel *)arg;

    osifp  = (osif_dev *)wlan_vap_get_registered_handle(vap);
    if(osifp == NULL) {
        return;
    }

    if (!osifp->is_up) {
        if ((error = wlan_mlme_start_bss(vap,1))!=0) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE,
                        "Error %s : failed start bss with error code %d\n",
                        __func__, error);
        } else {
            wlan_mlme_connection_up(vap);
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE,
                        "%s :vap up \n", __func__);
            spin_lock(&osifp->tx_lock);
            osifp->is_up = 1;
            spin_unlock(&osifp->tx_lock);
        }
    }
}

static void osif_restart_stop_vap_iter_func(void *arg, wlan_if_t vap)
{
    osif_dev  *osifp = NULL;

    osifp  = (osif_dev *)wlan_vap_get_registered_handle(vap);
    if(osifp == NULL) {
        return;
    }
    if(wlan_vap_get_opmode(vap) != IEEE80211_M_HOSTAP) {
        return;
    }
    if(osifp->is_up) {
       spin_lock(&osifp->tx_lock);
       osifp->is_up = 0;
       spin_unlock(&osifp->tx_lock);
       wlan_mlme_restart_stop_bss(vap);
    }
}

void bringup_vaps_event(void *arg)
{
    wlan_dev_t comhandle = NULL;

    comhandle = (struct ieee80211com *)arg;
    wlan_iterate_vap_list(comhandle, bringup_ap_vaps, NULL);
}

void osif_check_pending_ap_vaps(wlan_dev_t comhandle, wlan_if_t vap)
{
    qdf_sched_work((qdf_os_handle_t)vap, &(wlan_vap_get_devhandle(vap))->ic_bringup_vaps);
}

void osif_restart_stop_ap_vaps(wlan_dev_t comhandle, wlan_if_t vap)
{
    wlan_iterate_vap_list(comhandle, osif_restart_stop_vap_iter_func, NULL);
}

void osif_restart_start_ap_vaps(wlan_dev_t comhandle, wlan_if_t vap)
{
    wlan_iterate_vap_list(comhandle, osif_restart_start_vap_iter_func, NULL);
}

static void osif_sta_sm_evhandler(wlan_connection_sm_t smhandle, os_if_t osif,
                                  wlan_connection_sm_event *smevent)
{
    osif_dev  *osdev = (osif_dev *) osif;
    struct net_device *dev = osdev->netdev;
    wlan_if_t vap = osdev->os_if;
    wlan_dev_t comhandle = wlan_vap_get_devhandle(vap);
    enum ieee80211_phymode des_mode = wlan_get_desired_phymode(vap);
    u_int8_t bssid[IEEE80211_ADDR_LEN] = {0, 0, 0, 0, 0, 0};
    union iwreq_data wreq;
#if UNIFIED_SMARTANTENNA
    struct ieee80211_node *ni = NULL;
#endif
#if UMAC_REPEATER_DELAYED_BRINGUP
    struct ieee80211_rsnparms *rsn = &vap->iv_rsn;
#endif

    memset(&wreq, 0, sizeof(wreq));

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : event %d reason %d \n",
                      __func__, smevent->event,smevent->disconnect_reason);
    if (smevent->event == WLAN_CONNECTION_SM_EVENT_CONNECTION_UP) {
        wlan_mlme_connection_up(vap);
        if (ieee80211_ic_enh_ind_rpt_is_set(vap->iv_ic)) {
           wlan_determine_cw(vap, vap->iv_ic->ic_curchan);
	}
        wlan_vap_get_bssid(vap,bssid);
        wlan_node_authorize(vap,1,bssid);
#if UNIFIED_SMARTANTENNA
        ni = ieee80211_find_node(&vap->iv_ic->ic_sta, bssid);
        if (ni) {
            if (ni->ni_ic->radio_id == RADIO_ID_DIRECT_ATTACH) {
                ieee80211_smart_ant_node_connect(ni, NULL);
            }
            ieee80211_free_node(ni);
        }
#endif

        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s :vap up ,connection up"
                          " to bssid=%s, ifname=%s\n",
                          __func__, ether_sprintf(bssid), dev->name);
        _netif_carrier_on(dev);
        osdev->is_up = 1;
        memset(&wreq, 0, sizeof(wreq));
        IEEE80211_ADDR_COPY(wreq.addr.sa_data, bssid);
        wreq.addr.sa_family = ARPHRD_ETHER;
        WIRELESS_SEND_EVENT(dev, SIOCGIWAP, &wreq, NULL);
        /* Fix for evid 97581 - Enhancement to support independent VAP in multi mode*/
        /* No check required on pending AP VAPs for repeater move trigger by cloud */
        if ( (!wlan_get_param(vap, IEEE80211_FEATURE_VAP_ENHIND)) &&
              !(vap->iv_ic->ic_repeater_move.state == REPEATER_MOVE_IN_PROGRESS)) {
            if (!ic_list.iface_mgr_up) {
#if UMAC_REPEATER_DELAYED_BRINGUP
                /* Note: This should be moved to resource manager later */
                if (!RSN_AUTH_IS_WPA2(rsn) && !RSN_AUTH_IS_WPA(rsn))
                {
                    osif_check_pending_ap_vaps(comhandle,vap);
                }
#else
                osif_check_pending_ap_vaps(comhandle,vap);
#endif
            }
#ifdef ATHEROS_LINUX_PERIODIC_SCAN
            if ( (wlan_vap_get_opmode(vap) == IEEE80211_M_STA ) && (vap->iv_bss->ni_chwidth == IEEE80211_CWM_WIDTH40) &&
                ((des_mode == IEEE80211_MODE_11NG_HT40PLUS) ||
                (des_mode == IEEE80211_MODE_11NG_HT40MINUS) ||
                (des_mode == IEEE80211_MODE_11NG_HT40))) {
                if(!(vap->iv_ic->ic_flags & IEEE80211_F_COEXT_DISABLE)) {
                    if(!osdev->os_periodic_scan_period) {
                        osdev->os_periodic_scan_period = OSIF_PERIODICSCAN_COEXT_PERIOD;
                    }
                    osdev->os_scan_band = OSIF_SCAN_BAND_2G_ONLY;
                    osif_periodic_scan_start(osif);
                } else {
                    osdev->os_periodic_scan_period = OSIF_PERIODICSCAN_DEF_PERIOD;
                }
            }
#endif
        }
        /* Update repeater move state to STOP once connection is up */
        if (vap->iv_ic->ic_repeater_move.state == REPEATER_MOVE_IN_PROGRESS) {
            vap->iv_ic->ic_repeater_move.state = REPEATER_MOVE_STOP;
        }
    } else if (smevent->event == WLAN_CONNECTION_SM_EVENT_CONNECTION_DOWN) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s :sta disconnected \n", __func__);

        if (((smevent->disconnect_reason == WLAN_CONNECTION_SM_RECONNECT_TIMEDOUT) ||
             (smevent->disconnect_reason == WLAN_CONNECTION_SM_CONNECT_TIMEDOUT)) &&
            (vap->auto_assoc || osdev->authmode == IEEE80211_AUTH_AUTO)) {
	            _netif_carrier_off(dev);
            /* Connection timed out - retry connection */
            if (osdev->authmode == IEEE80211_AUTH_AUTO) {
                /* If the auth mode is set to AUTO
                 * switch between SHARED and AUTO mode
                 */
                ieee80211_auth_mode modes[IEEE80211_AUTH_MAX];
                u_int nmodes;
                struct ieee80211com *ic = NULL;
                nmodes=wlan_get_auth_modes(vap,modes,IEEE80211_AUTH_MAX);
                nmodes=1;
                if (modes[0] == IEEE80211_AUTH_SHARED) {
                    modes[0] = IEEE80211_AUTH_OPEN;
                    /*
                     *fix for CR#586870; The roaming should be set to
                     *AUTO so that the state machine is restarted
                     *for the connection to happen in OPEN mode.
                     */
                    ic=vap->iv_ic;
                    if(ic)
                        ieee80211com_set_roaming(ic, IEEE80211_ROAMING_AUTO);
                }
                else {
                    modes[0] = IEEE80211_AUTH_SHARED;
                }
                wlan_set_authmodes(vap,modes,nmodes);
            }
           /* Fix for evid 97581 - Enhancement to support independent VAP in multi mode*/
           /* Do not bring down VAPs for repeater move trigger by cloud */
            if ( (!wlan_get_param(vap, IEEE80211_FEATURE_VAP_ENHIND)) &&
                  !(vap->iv_ic->ic_repeater_move.state == REPEATER_MOVE_IN_PROGRESS)) {
                /* Note: This should be moved to resource manager later */
                if (!ic_list.iface_mgr_up) {
                    wlan_iterate_vap_list(comhandle, osif_bringdown_vap_iter_func, NULL);
                }
            }
	    if(vap->iv_ic->ic_roaming != IEEE80211_ROAMING_MANUAL)
                wlan_connection_sm_start(osdev->sm_handle);
        }
        else {
            /* Fix for evid 97581 - Enhancement to support independent VAP in multi mode*/
            /* Do not bring down VAPs for repeater move trigger by cloud */
            if ( (!wlan_get_param(vap, IEEE80211_FEATURE_VAP_ENHIND)) &&
                  !(vap->iv_ic->ic_repeater_move.state == REPEATER_MOVE_IN_PROGRESS)) {
                /* Note: This should be moved to resource manager later */
                if (!ic_list.iface_mgr_up) {
                    wlan_iterate_vap_list(comhandle, osif_bringdown_vap_iter_func, NULL);
                }
            }
#ifdef ATHEROS_LINUX_PERIODIC_SCAN
            else {
                osif_periodic_scan_stop(osif);
            }
#endif
            if (!osdev->is_restart) { /* bring down the vap only if it is not a restart */
                if (osdev->is_up) {
                    memset(wreq.ap_addr.sa_data, 0, ETHER_ADDR_LEN);
                    wreq.ap_addr.sa_family = ARPHRD_ETHER;
                    WIRELESS_SEND_EVENT(dev, SIOCGIWAP, &wreq, NULL);
                }
                _netif_carrier_off(dev);
                osif_vap_down(dev);
            }
            else {
                /* clear the restart and is_up flag */
                spin_lock(&osdev->tx_lock);
                osdev->is_up = 0;
                spin_unlock(&osdev->tx_lock);
                osdev->is_restart = 0;
            }
        }
    } else if (smevent->event == WLAN_CONNECTION_SM_EVENT_CONNECTION_LOST) {
    	#ifndef __linux__
    	spin_lock(&osdev->tx_lock);
     	osdev->is_up = 0;
    	spin_unlock(&osdev->tx_lock);
    	#endif
	/* Repeater dependancy implemented here  */
        /* Fix for evid 97581 - Enhancement to support independent VAP in multi mode*/
        if ( !wlan_get_param(vap, IEEE80211_FEATURE_VAP_ENHIND)) {
            /* Note: This should be moved to resource manager later */
            if (!ic_list.iface_mgr_up) {
                wlan_iterate_vap_list(comhandle, osif_bringdown_vap_iter_func, NULL);
            }
        }
#ifdef ATHEROS_LINUX_PERIODIC_SCAN
        else {
            osif_periodic_scan_stop(osif);
        }
#endif
				#ifdef __linux__
				if (osdev->is_up) {
            memset(wreq.ap_addr.sa_data, 0, ETHER_ADDR_LEN);
            wreq.ap_addr.sa_family = ARPHRD_ETHER;
            WIRELESS_SEND_EVENT(dev, SIOCGIWAP, &wreq, NULL);
        }
        spin_lock(&osdev->tx_lock);
        osdev->is_up = 0;
        spin_unlock(&osdev->tx_lock);
        #endif
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s :connection lost \n", __func__);
    } else if (smevent->event == WLAN_CONNECTION_SM_EVENT_CONNECTION_RESET) {
        _netif_carrier_on(dev);
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s :vap reset \n", __func__);
        wlan_mlme_connection_up(vap);
        osdev->is_up = 1;
        wlan_vap_get_bssid(vap,bssid);
        /* Fix for evid 97581 - Enhancement to support independent VAP in multi mode*/
	if (!wlan_get_param(vap, IEEE80211_FEATURE_VAP_ENHIND)) {
            if (!ic_list.iface_mgr_up) {
                if (!osdev->osif_is_mode_offload) {
                    /* Note: This should be moved to resource manager later */
                   wlan_iterate_vap_list(comhandle, osif_bringdown_vap_iter_func, NULL);
#if UMAC_REPEATER_DELAYED_BRINGUP
                   if (!RSN_AUTH_IS_WPA2(rsn) && !RSN_AUTH_IS_WPA2(rsn))
                   {
                       osif_check_pending_ap_vaps(comhandle,vap);
                   }
#else
                   osif_check_pending_ap_vaps(comhandle,vap);
#endif
                } else {
                   wlan_iterate_vap_list(comhandle, osif_restart_stop_vap_iter_func, NULL);
                   wlan_iterate_vap_list(comhandle, osif_restart_start_vap_iter_func, NULL);
                }
            }
        }
        memset(&wreq, 0, sizeof(wreq));
        IEEE80211_ADDR_COPY(wreq.addr.sa_data, bssid);
        wreq.addr.sa_family = ARPHRD_ETHER;
        WIRELESS_SEND_EVENT(dev, SIOCGIWAP, &wreq, NULL);
        wlan_node_authorize(vap,1,bssid);
    }
    #ifdef __linux__
    else if ((smevent->event == WLAN_CONNECTION_SM_EVENT_REJOINING) &&
               (wlan_vap_get_opmode(vap) == IEEE80211_M_STA) &&
               !vap->auto_assoc) {
        ieee80211_auth_mode modes[IEEE80211_AUTH_MAX];
        int count, i;
        int iswpa = 0;

        count = wlan_get_auth_modes(vap,modes,IEEE80211_AUTH_MAX);
        for (i = 0; i < count; i++) {
            if (modes[i] == IEEE80211_AUTH_WPA || modes[i] == IEEE80211_AUTH_RSNA) {
                iswpa = 1;
                break;
            }
        }
        if (iswpa) {
            if(osdev->is_up) {
                memset(wreq.ap_addr.sa_data, 0, ETHER_ADDR_LEN);
                wreq.ap_addr.sa_family = ARPHRD_ETHER;
                WIRELESS_SEND_EVENT(dev, SIOCGIWAP, &wreq, NULL);
            }
        }
    }
    #endif
     else if (smevent->event == WLAN_CONNECTION_SM_EVENT_ENH_IND_STOP)  {
        if ( wlan_get_param(vap, IEEE80211_FEATURE_VAP_ENHIND)) {
            wlan_iterate_vap_list(comhandle, osif_bringdown_vap_iter_func, NULL);
        }
    } else if ((smevent->event == WLAN_CONNECTION_SM_EVENT_ENH_IND_START)) {
        if ( wlan_get_param(vap, IEEE80211_FEATURE_VAP_ENHIND)) {
            wlan_iterate_vap_list(comhandle, osif_bringup_vap_iter_func, NULL);
        }
    }

}

#if UMAC_SUPPORT_IBSS
static void osif_ibss_scan_evhandler(wlan_if_t vaphandle, ieee80211_scan_event *event, void *arg)
{
    osif_dev  *osifp = (osif_dev *) arg;
    wlan_if_t vap = osifp->os_if;

    if ((event->type == IEEE80211_SCAN_COMPLETED) &&
        (event->reason != IEEE80211_REASON_CANCELLED) &&
        (event->requestor == osifp->scan_requestor)) {
        int error = 0;
        int chan = vap->iv_des_ibss_chan;
        struct ath_softc_net80211 *scn;
        struct net_device *comdev = ((osif_dev *)osifp)->os_comdev;

        IEEE80211_DPRINTF(vaphandle, IEEE80211_MSG_IOCTL, "%s SCAN DONE  reason %d \n",
                    __func__, event->reason);

        scn = ath_netdev_priv(comdev);

        /* Work around for WMM parameter update. Since we will issue scan to work
           around problems in creating IBSS, and WMM parameters will be clear. */
        ieee80211_wme_updateparams(vap);

        /* Work around for IBSS ACS functions. In IBSS ACS, the beacon timer will
           not be updated, thus, use set channel to make the timer update. */
        scn->sc_syncbeacon = 0;
        error = wlan_set_channel(vap, chan, vap->iv_des_cfreq2);

        /* Show message for debug if set channel fail */
        if (error != 0) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                            "%s : failed to set channel with error code %d\n",
                            __func__, error);
        }

        wlan_scan_unregister_event_handler(vap,
                                           &osif_ibss_scan_evhandler,
                                           (void *) osifp);

        wlan_scan_register_event_handler(vap, &osif_scan_evhandler, (void*)osifp);
        osif_notify_scan_done(osifp->netdev, IEEE80211_REASON_NONE);
    }
}

static void osif_ibss_scan(osif_dev *osdev)
{
    wlan_if_t vap = osdev->os_if;
    ieee80211_scan_params scan_params;
    enum ieee80211_opmode opmode = wlan_vap_get_opmode(vap);

    OS_MEMZERO(&scan_params,sizeof(ieee80211_scan_params));

    /* Fill scan parameter */
    wlan_set_default_scan_parameters(vap,&scan_params,opmode,true,false,true,
              true,0,NULL,1);

    scan_params.max_dwell_time_active = 2 * scan_params.min_dwell_time_active;
    scan_params.idle_time = 610;
    scan_params.repeat_probe_time = 0;
    scan_params.min_beacon_count = 0;
    scan_params.max_scan_time = OSIF_PERIODICSCAN_MIN_PERIOD;
    scan_params.type = IEEE80211_SCAN_FOREGROUND;
    scan_params.flags |= (IEEE80211_SCAN_ALLBANDS | IEEE80211_SCAN_PASSIVE);

    wlan_scan_unregister_event_handler(vap,
                                       &osif_scan_evhandler,
                                       (void *) osdev);

    wlan_scan_register_event_handler(vap, &osif_ibss_scan_evhandler, (void*)osdev);

    if (wlan_scan_start(vap, &scan_params, osdev->scan_requestor,
            IEEE80211_SCAN_PRIORITY_LOW, &(osdev->scan_id)) != 0) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: Issue a scan fail.\n",
                             __func__);
    }
}

static void osif_ibss_sm_evhandler(wlan_ibss_sm_t smhandle, os_if_t osif,
                                   wlan_ibss_sm_event *smevent)
{
    osif_dev  *osdev = (osif_dev *) osif;
    struct net_device *dev = osdev->netdev;
    wlan_if_t vap = osdev->os_if;
    u_int8_t bssid[IEEE80211_ADDR_LEN];
#if !ATH_SUPPORT_IBSS_NETLINK_NOTIFICATION
    union iwreq_data wreq;
#endif

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : event %d reason %d \n",
                      __func__, smevent->event, smevent->reason);
    if (smevent->event == WLAN_IBSS_SM_EVENT_SUCCESS) {
        wlan_mlme_connection_up(vap);
        wlan_vap_get_bssid(vap, bssid);
        wlan_node_authorize(vap, 1, bssid);
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s :vap up \n", __func__);
        netif_carrier_on(dev);
        osdev->is_up = 1;

       // join success: update WMM
        if (!osdev->is_ibss_create) {
            ieee80211_wme_updateparams(vap);
        }

        osdev->is_ibss_create = 0;

#if !ATH_SUPPORT_IBSS_NETLINK_NOTIFICATION
        memset(&wreq, 0, sizeof(wreq));
        IEEE80211_ADDR_COPY(wreq.addr.sa_data, bssid);
        wreq.addr.sa_family = ARPHRD_ETHER;
        WIRELESS_SEND_EVENT(dev, SIOCGIWAP, &wreq, NULL);
#endif
    } else if (smevent->event == WLAN_IBSS_SM_EVENT_FAILED) {
        /*
         * If join fail, switch ibss to create.
         */
        if (!osdev->is_ibss_create) {
            if (!osdev->disable_ibss_create) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s :join fail, switch to create  \n", __func__);
                osdev->is_ibss_create = 1;
            } else {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s :join fail, retry join  \n", __func__);
            }
            osif_ibss_init(dev);
        } else {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s :create fail! vap down!  \n", __func__);
            osdev->is_ibss_create = 0;
            netif_carrier_off(dev);
            osif_vap_down(dev);
        }
    } else if (smevent->event == WLAN_IBSS_SM_EVENT_DISCONNECT) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s :ibss disconnected \n", __func__);
        osdev->is_ibss_create = 0;
        netif_carrier_off(dev);
        osif_vap_down(dev);
    }
}
#endif

void
osif_replay_failure_indication(os_handle_t osif, const u_int8_t *frm, u_int keyix)
{
    static const char * tag = "MLME-REPLAYFAILURE.indication";
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap;
    struct ieee80211_frame *wh = (struct ieee80211_frame *)frm;
    union iwreq_data wrqu;
    char buf[128];

    vap = osdev->os_if;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_CRYPTO,
        "%s: replay detected <keyix %d>\n",
        ether_sprintf(wh->i_addr2), keyix);

    /* TODO: needed parameters: count, keyid, key type, src address, TSC */
    snprintf(buf, sizeof(buf), "%s(keyid=%d %scast addr=%s)", tag,
        keyix, IEEE80211_IS_MULTICAST(wh->i_addr1) ?  "broad" : "uni",
        ether_sprintf(wh->i_addr1));
    memset(&wrqu, 0, sizeof(wrqu));
    wrqu.data.length = strlen(buf);
    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, buf);
}
/*Event trigger when receive one packet with MIC error*/
void
osif_michael_failure_indication(os_handle_t osif, const u_int8_t *frm, u_int keyix)
{
    static const char *tag = "MLME-MICHAELMICFAILURE.indication";
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap;
    struct ieee80211_frame *wh = (struct ieee80211_frame *)frm;
    union iwreq_data wrqu;
    char buf[128];
    struct ev_msg msg;

    vap = osdev->os_if;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_CRYPTO,
        "%s: Michael MIC verification failed <keyix %d>",
        ether_sprintf(wh->i_addr2), keyix);

    /* TODO: needed parameters: count, keyid, key type, src address, TSC */
    snprintf(buf, sizeof(buf), "%s(keyid=%d addr=%s)", tag,
        keyix, ether_sprintf(wh->i_addr2));
    memset(&wrqu, 0, sizeof(wrqu));
    wrqu.data.length = strlen(buf);
    wrqu.data.flags = 0;            /*hostapd use this event and expects this flags to be 0.*/
    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, buf);

    IEEE80211_ADDR_COPY(msg.addr,wh->i_addr2);
    memset(&wrqu, 0, sizeof(wrqu));
    wrqu.data.flags = IEEE80211_EV_MIC_ERR_IND_AP;    /*Sends two event for backward support.*/
    wrqu.data.length = sizeof(msg);
    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu,(char*)&msg);
}
/*Event trigger when WPA unicast key setting*/
void
osif_keyset_done_indication(os_handle_t osif, u_int8_t *macaddr, u_int8_t status)
{
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    union iwreq_data wrqu;
    struct ev_msg msg;

    IEEE80211_ADDR_COPY(msg.addr, macaddr);
    memset(&wrqu, 0, sizeof(wrqu));
    wrqu.data.flags = IEEE80211_EV_KEYSET_DONE_IND_AP;
    wrqu.data.length = sizeof(msg);
    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
}
/*Event trigger when received AUTH request from one STA and this STA is in the blacklist */
void
osif_blklst_sta_auth_indication(os_handle_t osif, u_int8_t *macaddr, u_int8_t status)
{
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    union iwreq_data wrqu;
    struct ev_msg msg;
    IEEE80211_ADDR_COPY(msg.addr, macaddr);
    memset(&wrqu, 0, sizeof(wrqu));
    wrqu.data.flags = IEEE80211_EV_BLKLST_STA_AUTH_IND_AP;
    wrqu.data.length = sizeof(msg);
    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, (char *)&msg);
}

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
static void osif_sta_cac_started (os_handle_t osif, u_int32_t frequency, u_int32_t timeout)
{
	static const char *tag = "CAC.started";
    struct net_device *dev = ((osif_dev *)osif)->netdev;
    union iwreq_data wrqu;
    char buf[128];

    /* TODO: needed parameters: count, keyid, key type, src address, TSC */
    snprintf(buf, sizeof(buf), "%s freq=%u timeout=%d", tag,
        frequency, timeout);
    memset(&wrqu, 0, sizeof(wrqu));
    wrqu.data.length = strlen(buf);
    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, buf);
}
#endif

void
osif_notify_push_button(osdev_t osdev, u_int32_t push_time)
{
    struct net_device *dev = osdev->netdev;
    static char *tag = "PUSH-BUTTON.indication";
    union iwreq_data wrqu;
    char buf[128];

#if UMAC_SUPPORT_ACFG
    acfg_event_data_t *acfg_event = NULL;

	acfg_event = (acfg_event_data_t *)kmalloc(sizeof(acfg_event_data_t), GFP_ATOMIC);
	if (acfg_event == NULL)
		return;
#endif

    snprintf(buf, sizeof(buf), "%s Push dur=%d", tag, push_time);
    memset(&wrqu, 0, sizeof(wrqu));
    wrqu.data.length = strlen(buf);
    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, buf);
#if UMAC_SUPPORT_ACFG
	acfg_send_event(dev, osdev, WL_EVENT_TYPE_PUSH_BUTTON, acfg_event);
	kfree(acfg_event);
#endif
}

int
ieee80211_load_module(const char *modname)
{
    request_module(modname);
    return 0;
}

static void osif_channel_change (os_handle_t osif, wlan_chan_t chan)
{
#if UMAC_SUPPORT_ACFG || ATH_BAND_STEERING
    osif_dev  *osdev = (osif_dev *) osif;
    struct net_device *dev = osdev->netdev;
    wlan_if_t vap = osdev->os_if;
#endif

#if UMAC_SUPPORT_ACFG
    struct ieee80211com *ic = vap->iv_ic;
    acfg_event_data_t *acfg_event = NULL;
    osdev_t  os_handle = ((osif_dev *)osif)->os_handle;
#endif
#if ATH_BAND_STEERING
    union iwreq_data wreq;
    u_int8_t freq;
#endif

#if UMAC_SUPPORT_ACFG
    if (!os_handle) {
        return;
    }
	acfg_event = (acfg_event_data_t *)kmalloc(sizeof(acfg_event_data_t), GFP_ATOMIC);
	if (acfg_event == NULL)
		return;

    memset(acfg_event, 0, sizeof(acfg_event_data_t));

    if ((!chan) || (chan == IEEE80211_CHAN_ANYC))
        acfg_event->freqs[0] = 0;
    else
        acfg_event->freqs[0] = wlan_channel_ieee(chan);

    if(ic->ic_flags & IEEE80211_F_DFS_CHANSWITCH_PENDING){
        acfg_event->reason = ACFG_CHAN_CHANGE_DFS;
    }else{
        acfg_event->reason = ACFG_CHAN_CHANGE_NORMAL;
    }

    acfg_send_event(dev, os_handle, WL_EVENT_TYPE_CHAN, acfg_event);
	kfree(acfg_event);
#endif

#if ATH_BAND_STEERING
    // Band steering needs to be notified of channel change events so that
    // it can stop it and then re-enable once any ACS/CAC logic has completed.
    // Although this could have been done with a band steering event, a generic
    // link event seemed more consistent as a user-initiated channel change
    // already generates a link event (of type SIOCSIWFREQ).

    if(wlan_scan_in_progress(vap)) {
        return;
    }

    OS_MEMSET(&wreq, 0, sizeof(wreq));
    wreq.data.flags = IEEE80211_EV_CHAN_CHANGE;
    wreq.data.length = sizeof(freq);
    if ((!chan) || (chan == IEEE80211_CHAN_ANYC)) {
        freq = 0;
    } else {
        freq = wlan_channel_ieee(chan);
    }
    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wreq,
                        (char *)&freq);
#endif
}

#if ATH_SUPPORT_HYFI_ENHANCEMENTS
static void osif_buffull_warning (os_handle_t osif)
{
    struct net_device *dev = OSIF_TO_NETDEV(osif);
    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap;
    vap = osdev->os_if;
    ald_buffull_notify(((osif_dev *)osif)->os_if);
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: buffull \n", __func__);

}
#endif

static void osif_country_changed (os_handle_t osif, char *country)
{

}

static void osif_receive (os_if_t osif, wbuf_t wbuf,
                        u_int16_t type, u_int16_t subtype,
                        ieee80211_recv_status *rs)
{
    struct sk_buff *skb = (struct sk_buff *)wbuf;

    if (type != IEEE80211_FC0_TYPE_DATA) {
        wbuf_free(wbuf);
        return;
    }
    /* deliver the data to network interface */
    __osif_deliver_data(osif, skb);
}

#if ATH_RX_INFO_EN
static void osif_send_mgmt_rx_info_event(os_handle_t osif, wbuf_t wbuf, ieee80211_recv_status *rs)
{
    osif_dev  *osdev = (osif_dev *) osif;
#if UMAC_SUPPORT_ACFG
    acfg_event_data_t *acfg_event;
#endif
    struct sk_buff *skb = (struct sk_buff *)wbuf;
    struct net_device *dev = osdev->netdev;
    acfg_mgmt_rx_info_t *mgmt_ri = NULL;
    int len = 0;
    static u_int32_t acfg_limit_print = 0;

    /*Drop event eariler here if acfg_event_list is full*/
    qdf_spin_lock_bh(&(osdev->os_handle->acfg_event_queue_lock));
    if(qdf_nbuf_queue_len(&(osdev->os_handle->acfg_event_list)) >= ACFG_EVENT_LIST_MAX_LEN){
        qdf_spin_unlock_bh(&(osdev->os_handle->acfg_event_queue_lock));
        if(!(acfg_limit_print % ACFG_EVENT_PRINT_LIMIT)){
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Work queue full, drop acfg event!\n");
        }
        ++acfg_limit_print;
        return;
    }
    qdf_spin_unlock_bh(&(osdev->os_handle->acfg_event_queue_lock));

#if UMAC_SUPPORT_ACFG
    acfg_event = OS_MALLOC(osdev->os_handle, sizeof(acfg_event_data_t), GFP_KERNEL);
    if (acfg_event == NULL){
        return;
    }
    OS_MEMZERO(acfg_event, sizeof(acfg_event_data_t));

    mgmt_ri = &(acfg_event->mgmt_ri);
    mgmt_ri->ri_channel = rs->rs_channel;
    mgmt_ri->ri_rssi = rs->rs_rssi;
    mgmt_ri->ri_datarate = rs->rs_datarate;
    mgmt_ri->ri_flags = rs->rs_flags;
    len = ((skb->len)>MGMT_FRAME_MAX_SIZE) ? MGMT_FRAME_MAX_SIZE: skb->len;
    OS_MEMCPY(mgmt_ri->raw_mgmt_frame, skb->data, len);

    acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_MGMT_RX_INFO, acfg_event);

    OS_FREE(acfg_event);
#endif
}
#endif

/* From Atheros version:
* //depot/sw/releases/linuxsrc/src/802_11/madwifi/madwifi/net80211/ieee80211_input.c
*
* This is an entirely different approach which uses "wireless events"...
*/
#define GET_BE16(a) ((u16) (((a)[0] << 8) | (a)[1]))
#define ELEMENT_TYPE 0x1012

int push_method(const u_int8_t *frm)
{
     int len=6;
     int rc = 0;

     while ((len+4) < frm[1] ) {
        if((GET_BE16(frm+len) == ELEMENT_TYPE) && (frm[len+3] ==2)&& (GET_BE16(frm+len+4)== 0x0004))
        {
            rc = 1;
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "wps pb detected\n");
            return rc;
        } else {
          len += frm[len+3]+4;
        }
     }
     return rc;
}

void osif_forward_mgmt_to_app(os_if_t osif, wbuf_t wbuf,
                                        u_int16_t type, u_int16_t subtype, ieee80211_recv_status *rs)
{
    struct net_device *dev = OSIF_TO_NETDEV(osif);
    struct sk_buff *skb = (struct sk_buff *)wbuf;
    osif_dev  *osifp = (osif_dev *) osif;
    wlan_if_t vap = osifp->os_if;

    int filter_flag =0;
#define MGMT_FRAM_TAG_SIZE 30 /* hardcoded in atheros_wireless_event_wireless_custom */
    char *tag=NULL;
    char *wps_tag = NULL;
    #if 0       /* should be, but IW_CUSTOM_MAX is only 256 */
    const int bufmax = IW_CUSTOM_MAX;
    #else       /* HACK use size for IWEVASSOCREQIE instead */
    const int bufmax = IW_GENERIC_IE_MAX;
    #endif

    /* forward only if app filter is enabled */
    if (!osifp->app_filter){
        return;
    }

    switch (subtype)
    {
    case IEEE80211_FC0_SUBTYPE_BEACON:
        filter_flag = osifp->app_filter & IEEE80211_FILTER_TYPE_BEACON;
        tag = "Manage.beacon";
        break;
    case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
        /* HACK: Currently only WPS needs Probe reqs,
         * so forward WPS frames only */
        if (!wlan_frm_haswscie(wbuf) &&
            !wlan_get_param(vap, IEEE80211_TRIGGER_MLME_RESP)) {
            break;
        }
        if (!wlan_get_param(vap, IEEE80211_WPS_MODE) &&
            (subtype == IEEE80211_FC0_SUBTYPE_PROBE_REQ)) {
            break;
        }

        filter_flag = osifp->app_filter & IEEE80211_FILTER_TYPE_PROBE_REQ;
        tag = "Manage.prob_req";
        if(IEEE80211_VAP_IS_BACKHAUL_ENABLED(vap))// && IEEE80211_VAP_IS_HIDESSID_ENABLED(vap) /*orbi_ie*/)
        {
            struct ieee80211_frame *wh;
            u_int8_t *frm, *efrm;

            wh = (struct ieee80211_frame *) wbuf_header(wbuf);
            frm = (u_int8_t *)&wh[1];
            efrm = wbuf_header(wbuf) + wbuf_get_pktlen(wbuf);

            while (((frm+1) < efrm) && (frm + frm[1] + 1 < efrm)) {
                if (iswpsoui(frm) && push_method(frm))
                {
                    wps_tag = "Manage.prob_req_wps";
                    break;
                }
                else
                    wps_tag = NULL;
                frm += frm[1] + 2;
            }
        }
        break;
    case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
        filter_flag = osifp->app_filter & IEEE80211_FILTER_TYPE_PROBE_RESP;
        tag = "Manage.prob_resp";
        break;
    case IEEE80211_FC0_SUBTYPE_ASSOC_REQ:
    case IEEE80211_FC0_SUBTYPE_REASSOC_REQ:
        filter_flag = osifp->app_filter & IEEE80211_FILTER_TYPE_ASSOC_REQ;
        tag = "Manage.assoc_req";
        break;
    case IEEE80211_FC0_SUBTYPE_ASSOC_RESP:
    case IEEE80211_FC0_SUBTYPE_REASSOC_RESP:
        filter_flag = osifp->app_filter & IEEE80211_FILTER_TYPE_ASSOC_RESP;
        tag = "Manage.assoc_resp";
        break;
    case IEEE80211_FC0_SUBTYPE_AUTH:
        filter_flag = osifp->app_filter & IEEE80211_FILTER_TYPE_AUTH;
        tag = "Manage.auth";
        break;
    case IEEE80211_FC0_SUBTYPE_DEAUTH:
        filter_flag = osifp->app_filter & IEEE80211_FILTER_TYPE_DEAUTH;
        tag = "Manage.deauth";
        break;
    case IEEE80211_FC0_SUBTYPE_DISASSOC:
        filter_flag = osifp->app_filter & IEEE80211_FILTER_TYPE_DISASSOC;
        tag = "Manage.disassoc";
        break;
    case IEEE80211_FC0_SUBTYPE_ACTION:
        filter_flag = osifp->app_filter & IEEE80211_FILTER_TYPE_ACTION;
        tag = "Manage.action";
        break;
    default:
        break;
    }
    if (filter_flag)
    {
        union iwreq_data wrqu;
        char *buf;
        size_t bufsize = MGMT_FRAM_TAG_SIZE + skb->len;

        if(bufsize > bufmax) {
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "FIXME:%s: Event length more than expected..dropping\n", __FUNCTION__);
            return;
        }
        buf = OS_MALLOC(osifp->os_handle, bufsize, GFP_KERNEL);
        if (buf == NULL) return;
        OS_MEMZERO(&wrqu, sizeof(wrqu));
        wrqu.data.length = bufsize;
        OS_MEMZERO(buf, bufsize);
        snprintf(buf, MGMT_FRAM_TAG_SIZE, "%s %d", tag, skb->len);
        OS_MEMCPY(buf+MGMT_FRAM_TAG_SIZE, skb->data, skb->len);
        #if 0   /* the way it should? be */
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, buf);
        #else   /* HACK to get around 256 byte limit of IWEVCUSTOM */
        /* Note: application should treat IWEVASSOCREQIE same as IWEVCUSTOM
        * and should check for both.
        * IWEVASSOCREQIE is not used for anything (else) at least
        * not for Atheros chip driver.
        */

//        IEEE80211_DPRINTF(NULL, IEEE80211_MSG_IOCTL, "%s : filter_flag=%x, subtype=%x\n",
//                                      __func__,osifp->app_filter,subtype);
        WIRELESS_SEND_EVENT(dev, IWEVASSOCREQIE, &wrqu, buf);
        #endif
        OS_FREE(buf);

#if ATH_RX_INFO_EN
        osif_send_mgmt_rx_info_event(osif, skb, rs);
#endif
    }

    if(wps_tag != NULL)
    {
        union iwreq_data wrqu;
        char *buf;
        size_t bufsize = MGMT_FRAM_TAG_SIZE + skb->len;

        if(bufsize > bufmax) {
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "FIXME:%s: Event length more than expected..dropping\n", __FUNCTION__);
            return;
        }
        buf = OS_MALLOC(osifp->os_handle, bufsize, GFP_KERNEL);
        if (buf == NULL) return;
        OS_MEMZERO(&wrqu, sizeof(wrqu));
        wrqu.data.length = bufsize;
        OS_MEMZERO(buf, bufsize);
        snprintf(buf, MGMT_FRAM_TAG_SIZE, "%s %d", wps_tag, skb->len);
        OS_MEMCPY(buf+MGMT_FRAM_TAG_SIZE, skb->data, skb->len);
        WIRELESS_SEND_EVENT(dev, IWEVASSOCREQIE, &wrqu, buf);
        OS_FREE(buf);

#if ATH_RX_INFO_EN
        osif_send_mgmt_rx_info_event(osif, skb, rs);
#endif
    }

#undef  MGMT_FRAM_TAG_SIZE
}


static int  osif_receive_filter_80211 (os_if_t osif, wbuf_t wbuf,
                                        u_int16_t type, u_int16_t subtype,
                                        ieee80211_recv_status *rs)
{
#if 0
    osif_dev *osifp = (osif_dev *)osif;
    struct ieee80211vap *vap = osifp->os_if;

    if (type == IEEE80211_FC0_TYPE_DATA &&
        ieee80211_vap_l2tif_is_set(vap))
    {
        struct ieee80211_frame *wh = (struct ieee80211_frame *)wbuf_header(wbuf);
        struct ieee80211_node *ni;

        /* HS20 L2TIF: we only care about TODS frames */
        if ((wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) != IEEE80211_FC1_DIR_TODS)
            return 0;

        ni = ieee80211_vap_find_node(vap, wh->i_addr3);
        if (ni == NULL)
            ni = ieee80211_find_wds_node(&vap->iv_ic->ic_sta, wh->i_addr3);

        if (ni && ni->ni_vap == vap && ieee80211_node_is_authorized(ni) &&
            ni != vap->iv_bss)
        {
            /*
             * Hotspot 2.0 L2 Traffic Inspection and Filtering
             *
             * We don't support filtering at this time. So dropping
             * the frame only.
             */
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_L2TIF, "HS20 "
                    "L2TIF: discard packet %pM -> %pM, %d bytes\n",
                    &wh->i_addr2, &wh->i_addr3, wbuf_get_pktlen(wbuf));
            ieee80211_free_node(ni);
            return 1;
        }
        if (ni)
            ieee80211_free_node(ni);
    }
#endif
    if (type == IEEE80211_FC0_TYPE_MGT && wbuf) {
        osif_forward_mgmt_to_app(osif, wbuf, type, subtype, rs);
    }
    return 0;
}

void osif_receive_monitor_80211_base (os_if_t osif, wbuf_t wbuf,
                                        ieee80211_recv_status *rs)
{
    osif_dev *osifp = (osif_dev *)osif;
    struct ieee80211vap *vap = osifp->os_if;
    struct sk_buff *skb;
    int found = 0;
    struct net_device *dev = osifp->netdev;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
    struct net_device_stats *stats = &osifp->os_devstats;
#else
    struct rtnl_link_stats64 *stats = &osifp->os_devstats;
#endif
    struct ieee80211com *ic = wlan_vap_get_devhandle(vap);
    char *data = wbuf_header(wbuf);

    /* Decryption of the packet is not required in specialvap(ap_monitor) mode */
    if(!vap->iv_special_vap_mode) {
        u_int16_t hdrspace;
        struct ieee80211_rx_status decap_mon_rs;
        struct ieee80211_qosframe_addr4 *qwh = (struct ieee80211_qosframe_addr4 *)data;
        if (qdf_unlikely(qwh->i_fc[1] == (IEEE80211_FC1_DIR_DSTODS |  IEEE80211_FC1_WEP))) {
            if(IEEE80211_ADDR_IS_VALID(vap->mcast_encrypt_addr)){
                if (IEEE80211_ADDR_EQ(qwh->i_addr1,vap->mcast_encrypt_addr)) {
                    memset(&decap_mon_rs, 0, sizeof(decap_mon_rs));
                    hdrspace = ieee80211_hdrsize(data);
                    ieee80211_crypto_decap_mon(vap->iv_bss, wbuf, hdrspace, &decap_mon_rs);
                }
            }
        }
    }
    skb = (struct sk_buff *)wbuf;

#if ATH_SUPPORT_NAC
    if (vap->iv_smart_monitor_vap) {
        int i,j;
        char nullmac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        struct ieee80211_qosframe_addr4 *qwh = (struct ieee80211_qosframe_addr4 *)wbuf_header(skb);
        int max_addrlimit = NAC_MAX_CLIENT;
        struct ieee80211_nac_info  *nac_list = vap->iv_nac.client;

        for(i=0,j=0; i < max_addrlimit && j < max_addrlimit; i++) {

            if (IEEE80211_IS_MULTICAST((char *)(nac_list +i)->macaddr) ||
                IEEE80211_ADDR_EQ((char *)(nac_list +i)->macaddr, nullmac)) {
                continue;
            }

            if(OS_MEMCMP(qwh->i_addr2 , (nac_list +i)->macaddr, IEEE80211_ADDR_LEN)==0) {
                (nac_list +i)->rssi = rs->rs_rssi;
            }

            j++;
        }
    }
#endif

    if (vap->mac_entries) {
        int hash;
        struct ieee80211_qosframe_addr4 *qwh = (struct ieee80211_qosframe_addr4 *)wbuf_header(skb);
        struct ieee80211_mac_filter_list *mac_en;

        hash = MON_MAC_HASH(qwh->i_addr1);
        LIST_FOREACH(mac_en, &vap->mac_filter_hash[hash], mac_entry) {
            if (mac_en->mac_addr != NULL) {
                if (IEEE80211_ADDR_EQ(qwh->i_addr1, mac_en->mac_addr)){
                    found = 1;
                }
            }
        }
    }

    if (qdf_likely(ic->ic_mon_decoder_type == MON_DECODER_RADIOTAP)) {
        osif_mon_add_radiotap_header(osif, skb, rs);
        dev->type = ARPHRD_IEEE80211_RADIOTAP;
        skb->protocol = __constant_htons(ETH_P_802_2);
    } else {
        osif_mon_add_prism_header(osif, skb, rs);
        dev->type = ARPHRD_IEEE80211_PRISM;
        skb->protocol = __constant_htons(ETH_P_80211_RAW);
    }

    skb->dev = dev;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
    skb->mac.raw = skb->data;
#else
    skb_reset_mac_header(skb);
#endif
    skb->ip_summed = CHECKSUM_NONE;
    skb->pkt_type = PACKET_OTHERHOST;

    if (ic->mon_filter_osif_mac == 1) {
        /*If osif MAC addr based filter enabled,*/
        /*only input pkts from specified MAC*/
        if (qdf_unlikely(found == 1)) {
            qdf_nbuf_count_dec(skb);
            netif_rx(skb);
            stats->rx_packets++;
            stats->rx_bytes += skb->len;
        } else {
            qdf_nbuf_free(skb);
        }
    }else{
        qdf_nbuf_count_dec(skb);
        netif_rx(skb);
        stats->rx_packets++;
        stats->rx_bytes += skb->len;
    }
}
EXPORT_SYMBOL(osif_receive_monitor_80211_base);

void osif_receive_monitor_80211 (os_if_t osif, wbuf_t wbuf,
                                        ieee80211_recv_status *rs)
{
    /* This breaks for man reasons
     * 1. Doesnt handle the generic fraglist skb case
     * 2. Doesnt handled non FCS trailers like encryption
     * Change model to have lower layer call in with non-trailer added
     * packet length
     */
    ((struct sk_buff *) wbuf)->len -= 4;
    osif_receive_monitor_80211_base(osif, wbuf, rs);
}


#if ATH_SUPPORT_FLOWMAC_MODULE
int
dev_queue_status(struct net_device *dev, int margin)
{
	struct Qdisc *fifoqdisc;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,15))
    struct netdev_queue *txq;
#endif
    int qlen = 0;

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,15))
    txq = netdev_get_tx_queue(dev, 0);
    ASSERT((txq != NULL));
    fifoqdisc = txq->qdisc;
#else
	fifoqdisc = rcu_dereference(dev->qdisc);
#endif

    qlen = skb_queue_len(&fifoqdisc->q);
    if ((dev->tx_queue_len > margin) &&
            (qlen > dev->tx_queue_len - margin)) {
        return -ENOBUFS;
    }
    return 0;
}
int
dev_queue_length(struct net_device *dev)
{
	struct Qdisc *fifoqdisc;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,15))
    struct netdev_queue *txq;
#endif
    int qlen = 0;

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,15))
    txq = netdev_get_tx_queue(dev, 0);
    ASSERT((txq != NULL));
    fifoqdisc = txq->qdisc;
#else
	fifoqdisc = rcu_dereference(dev->qdisc);
#endif
    qlen = skb_queue_len(&fifoqdisc->q);
    return qlen;
}
#endif

/*
* hand over the wbuf to the com device (ath dev).
*/
static int
osif_dev_xmit_queue (os_if_t osif, wbuf_t wbuf)
{
    int err;
    struct net_device *comdev;
    struct sk_buff *skb = (struct sk_buff *)wbuf;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    struct ieee80211_cb * cb = NULL;
#endif

    int rval=0;
    comdev = ((osif_dev *)osif)->os_comdev;

    skb->dev = comdev;
    /*
     * rval would be -ENOMEM if there are 1000-128 frames left in the backlog
     * queue. We return this value out to the caller. The assumption of
     * caller is to make sure that he stalls the queues just after this. If
     * we do not let this frame out, node_ref issues might show up.
     */
#if ATH_SUPPORT_FLOWMAC_MODULE
    rval = dev_queue_status(comdev, 128);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    cb = (struct ieee80211_cb *) skb->cb;
    cb->_u.context = cb->ni;
#endif

    err = dev_queue_xmit(skb);
#if ATH_SUPPORT_FLOWMAC_MODULE
    if (err == NET_XMIT_DROP) {
        /* TODO FIXME to stop the queue here with flow control enabled
        */
        rval = -ENOBUFS;
    }
    /* if there is no space left in below queue, make sure that we pause the
     * vap queue also
     */
    if (err == -ENOMEM) rval = -ENOBUFS;
#endif
    return rval;
}

DECLARE_N_EXPORT_PERF_CNTR(vap_xmit);

/*
* hand over the wbuf to the vap if (queue back into the umac).
*/
static void osif_vap_xmit_queue (os_if_t osif, wbuf_t wbuf)
{
    int err;
    struct net_device *dev = OSIF_TO_NETDEV(osif);
    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap;
    struct sk_buff *skb = (struct sk_buff *)wbuf;

    START_PERF_CNTR(vap_xmit, vap_xmit);

    vap = osdev->os_if;
    skb->dev = dev;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22))
    skb->mac.raw = skb->data;
    skb->nh.raw = skb->data + sizeof(struct ether_header);
#else
    skb_reset_mac_header(skb);
    skb_set_network_header(skb, sizeof(struct ether_header));
#endif
    skb->protocol = __constant_htons(ETH_P_802_2);
    /* XXX inser`t vlan tage before queue it? */
    err = dev_queue_xmit(skb);

    if (err != 0) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY, "%s: wbuf xmit failed \n", __func__);
    }
    END_PERF_CNTR(vap_xmit);
}


#if ATH_SUPPORT_FLOWMAC_MODULE
static void
osif_pause_queue (os_if_t osif, int pause, unsigned int pctl)
{
    struct net_device *dev = OSIF_TO_NETDEV(osif);
    struct ath_softc_net80211 *scn = ath_netdev_priv(((osif_dev*)osif)->os_comdev);
    /* if puase, call the pause other wise wake */

    if (!dev || !scn) return ;

    if (pause) {
        netif_stop_queue(dev);
        /* Literally we should have stopped the ethernet just over 2/3 queue
         * is full. But for this to happen this should get called through
         * network stack first. As soon as we stopped the queue, we would
         * not be getting any calls to hard_start. That way we never able to
         * pause the Ethernet effectivly. The only simple way is to let us
         * pause the both. Otherwise kernel code need to change, but that
         * becomes more non-portable code.
         * Or else, the vap should have queue of frames and when reaches
         * limit pause the Ethernet.
         */

        if (scn->sc_ops->flowmac_pause && pctl ) {
            scn->sc_ops->flowmac_pause(scn->sc_dev, 1);

        }


    } else {
        netif_wake_queue(dev);

        if (scn->sc_ops->flowmac_pause && pctl) {
            scn->sc_ops->flowmac_pause(scn->sc_dev, 0);

        }

    }
}

#endif

static void
osif_vap_scan_cancel(os_if_t osif)
{
    struct net_device *dev = OSIF_TO_NETDEV(osif);
    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap;

    vap = osdev->os_if;
    wlan_scan_cancel(vap, osdev->scan_requestor,
                        IEEE80211_VAP_SCAN, true);
}

static void osif_bringup_ap_vaps(os_if_t osif)
{
    osif_dev  *osdev = (osif_dev *) osif;
    wlan_if_t tmpvap = NULL, vap = osdev->os_if;
    wlan_dev_t comhandle = wlan_vap_get_devhandle(vap);

    TAILQ_FOREACH(tmpvap, &comhandle->ic_vaps, iv_next) {
        if(tmpvap->iv_opmode == IEEE80211_M_HOSTAP ||
                tmpvap->iv_opmode == IEEE80211_M_MONITOR ) {
            tmpvap->iv_des_chan[tmpvap->iv_des_mode] = comhandle->ic_curchan;
        }
    }
    osif_check_pending_ap_vaps(comhandle,vap);
}

static void osif_bringdown_ap_vaps(os_if_t osif)
{
    osif_dev  *osdev = (osif_dev *) osif;
    wlan_if_t vap = osdev->os_if;
    wlan_dev_t comhandle = wlan_vap_get_devhandle(vap);

    wlan_iterate_vap_list(comhandle, osif_bringdown_vap_iter_func, NULL);
}

static void osif_xmit_update_status(os_if_t osif, wbuf_t wbuf,
                                    ieee80211_xmit_status *ts)
{

}

#if ATH_SUPPORT_IWSPY

#define RSSI_QUAL_MIN		1
#define RSSI_QUAL_THRESH1	5
#define RSSI_QUAL_THRESH2	30
#define RSSI_QUAL_MAX		42
#define QUAL_VALUE_MIN		0
#define QUAL_VALUE_THRESH1	5
#define QUAL_VALUE_THRESH2	85
#define QUAL_VALUE_MAX	94

static void
osif_set_linkquality(struct iw_quality *iq, u_int rssi)
{
    if(rssi >= RSSI_QUAL_MAX)
        iq->qual = QUAL_VALUE_MAX ;
    else if(rssi >= RSSI_QUAL_THRESH2)
        iq->qual = QUAL_VALUE_THRESH2 + ((QUAL_VALUE_MAX-QUAL_VALUE_THRESH2)*(rssi-RSSI_QUAL_THRESH2) + (RSSI_QUAL_MAX-RSSI_QUAL_THRESH2)/2) \
					/ (RSSI_QUAL_MAX-RSSI_QUAL_THRESH2) ;
    else if(rssi >= RSSI_QUAL_THRESH1)
        iq->qual = QUAL_VALUE_THRESH1 + ((QUAL_VALUE_THRESH2-QUAL_VALUE_THRESH1)*(rssi-RSSI_QUAL_THRESH1) + (RSSI_QUAL_THRESH2-RSSI_QUAL_THRESH1)/2) \
					/ (RSSI_QUAL_THRESH2-RSSI_QUAL_THRESH1) ;
    else if(rssi >= RSSI_QUAL_MIN)
        iq->qual = rssi;
    else
        iq->qual = QUAL_VALUE_MIN;

    iq->noise = 161;        /* -95dBm */
    iq->level = iq->noise + rssi ;
    iq->updated = 0xf;
}

/*
 * Call for the driver to update the spy data.
 * For now, the spy data is a simple array. As the size of the array is
 * small, this is good enough. If we wanted to support larger number of
 * spy addresses, we should use something more efficient...
 */
void osif_iwspy_update(os_if_t osif,
			 u_int8_t *address,
			 int8_t rssi)
{
    osif_dev  *osifp = (osif_dev *) osif;
    struct iw_spy_data *spydata = &osifp->spy_data;
	int	                i;
	int                 match = -1;
    struct iw_quality   iq;

	/* Make sure driver is not buggy or using the old API */
	if(!spydata)
		return;

	/* Update all records that match */
	for(i = 0; i < spydata->spy_number; i++)
		if(IEEE80211_ADDR_EQ(address, spydata->spy_address[i])) {
            osif_set_linkquality(&iq, rssi);
			memcpy(&(spydata->spy_stat[i]), &iq, sizeof(struct iw_quality));
			match = i;
		}

#if 0 /* for SIOCSIWTHRSPY/SIOCGIWTHRSPY, not to implement now */
	/* Generate an event if we cross the spy threshold.
	 * To avoid event storms, we have a simple hysteresis : we generate
	 * event only when we go under the low threshold or above the
	 * high threshold. */
	if(match >= 0) {
		if(spydata->spy_thr_under[match]) {
			if(wstats->level > spydata->spy_thr_high.level) {
				spydata->spy_thr_under[match] = 0;
				iw_send_thrspy_event(dev, spydata,
						     address, wstats);
			}
		} else {
			if(wstats->level < spydata->spy_thr_low.level) {
				spydata->spy_thr_under[match] = 1;
				iw_send_thrspy_event(dev, spydata,
						     address, wstats);
			}
		}
	}
#endif
}
/*
 * Call for reset the spy data by mac address
 */
void osif_iwspy_reset_data(os_if_t osif,
			 u_int8_t *address)
{
    osif_dev  *osifp = (osif_dev *) osif;
    struct iw_spy_data *spydata = &osifp->spy_data;
	int	                i;

	/* Make sure driver is not buggy or using the old API */
	if(!spydata)
		return;

	/* Reset all records that match */
	for(i = 0; i < spydata->spy_number; i++)
		if(!memcmp(address, spydata->spy_address[i], ETH_ALEN)) {
            memset(&(spydata->spy_stat[i]), 0x0, sizeof(struct iw_quality));
		}
}
#endif

static void osif_linkspeed(os_handle_t osif, u_int32_t rxlinkspeed, u_int32_t txlinkspeed)
{

}

static void osif_beacon_miss(os_handle_t osif)
{
    struct net_device *dev = OSIF_TO_NETDEV(osif);
    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap;

    vap = osdev->os_if;
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: beacon miss \n", __func__);

}

static void osif_device_error(os_handle_t osif)
{
    struct net_device *dev = OSIF_TO_NETDEV(osif);
    osif_dev *osdev = ath_netdev_priv(dev);
    wlan_if_t vap;
    ieee80211_reset_request reset_req;

    reset_req.reset_mac=0;
    reset_req.type = IEEE80211_RESET_TYPE_INTERNAL;
    reset_req.no_flush=0;
    vap = osdev->os_if;
    wlan_reset_start(vap, &reset_req);
    wlan_reset(vap, &reset_req);
    wlan_reset_end(vap, &reset_req);

}


/*
 * caller gets first element of list. Caller must free the element.
 */
struct pending_rx_frames_list *osif_fetch_p2p_mgmt(struct net_device *dev)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    unsigned long flags=0;
    struct pending_rx_frames_list *pending = NULL;

    spin_lock_irqsave(&osifp->list_lock, flags);
    if (!list_empty(&osifp->pending_rx_frames)) {
        pending = (void *) osifp->pending_rx_frames.next;
        list_del(&pending->list);
    }
    spin_unlock_irqrestore(&osifp->list_lock, flags);

    return pending;
}

#ifdef HOST_OFFLOAD
/*
 * Is the list of pending frames empty or not
 */
int osif_is_pending_frame_list_empty(struct net_device *dev)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    unsigned long flags=0;
    int empty = 0;

    spin_lock_irqsave(&osifp->list_lock, flags);
    if (list_empty(&osifp->pending_rx_frames))
        empty = 1;
    spin_unlock_irqrestore(&osifp->list_lock, flags);

    return empty;
}
#endif

/*
 * queue a big event for later delivery to user space
 * Caller must provide event->u.rx_frame.frame_len and
 * event->u.rx_frame.frame_buf for the data to be queued for later delivery
 */
void osif_p2p_rx_frame_handler(osif_dev *osifp,
                               wlan_p2p_event *event,
                               int frame_type)
{
    struct pending_rx_frames_list *pending;
    unsigned long flags;

    pending = (struct pending_rx_frames_list *)OS_MALLOC(osifp->os_handle,
                                 sizeof(*pending) + event->u.rx_frame.frame_len,
                                 GFP_ATOMIC);
    if (pending) {
        pending->frame_type = frame_type;
        pending->rx_frame = event->u.rx_frame;

        memcpy(pending->extra, event->u.rx_frame.frame_buf,
                                event->u.rx_frame.frame_len);

        INIT_LIST_HEAD (&pending->list);
        spin_lock_irqsave(&osifp->list_lock, flags);
        list_add_tail(&pending->list, &osifp->pending_rx_frames);
        spin_unlock_irqrestore(&osifp->list_lock, flags);
    } else {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_CRIT "%s OS_MALLOC failed, frame lost", __func__);
    }
}

struct event_data_chan_start {
    u_int32_t freq;
    u_int32_t duration;
    u_int32_t req_id;
};

struct event_data_chan_end {
    u_int32_t freq;
    u_int32_t reason;
    u_int32_t duration;
    u_int32_t req_id;
};

static void osif_p2p_dev_event_handler(void *arg, wlan_p2p_event *event)
{
    osif_dev *osifp = arg;
    union iwreq_data wreq;

    memset(&wreq, 0, sizeof(wreq));

    switch (event->type) {
    case WLAN_P2PDEV_CHAN_START:
        do {
            struct event_data_chan_start event_data;
            wreq.data.flags = IEEE80211_EV_CHAN_START;
            wreq.data.length = sizeof(struct event_data_chan_start);
            event_data.freq = event->u.chan_start.freq;
            event_data.duration = event->u.chan_start.duration;
            event_data.req_id = event->req_id;
            WIRELESS_SEND_EVENT(osifp->netdev, IWEVCUSTOM, &wreq,
                                (void *) &event_data);
        } while(0);
        break;
    case WLAN_P2PDEV_CHAN_END:
        do {
            struct event_data_chan_end event_data;
            wreq.data.flags = IEEE80211_EV_CHAN_END;
            wreq.data.length = sizeof(struct event_data_chan_end);
            event_data.freq = event->u.chan_end.freq;
            event_data.reason = event->u.chan_end.reason;
            event_data.duration = event->u.chan_end.duration;
            event_data.req_id = event->req_id;
            WIRELESS_SEND_EVENT(osifp->netdev, IWEVCUSTOM, &wreq,
                                (void *) &event_data);
        } while(0);
        break;
    case WLAN_P2PDEV_RX_FRAME:
        /* actually send that, data is available */
        wreq.data.flags = IEEE80211_EV_RX_MGMT;
        osif_p2p_rx_frame_handler(osifp, event, IEEE80211_EV_RX_MGMT);
        WIRELESS_SEND_EVENT(osifp->netdev, IWEVCUSTOM, &wreq, NULL);
        break;
    case WLAN_P2PDEV_SCAN_END:
        break;
    default:
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " *Unhandled P2P EVENT: %d *\n", event->type);
        break;
    }
}

#if ATH_SUPPORT_IBSS_NETLINK_NOTIFICATION
/*
 * WLAN MLME ibss event handler support function
 */
void osif_join_complete_adhoc(os_handle_t osif, IEEE80211_STATUS ieeeStatus)
{
    osif_dev *osifp = (osif_dev *)osif;
#if ATH_DEBUG
    wlan_if_t vap = osifp->os_if;
#endif
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: Status(%d)\n", __func__, ieeeStatus);

    /*
     * Linux IBSS mode re-register mlme event handle which replace original handle in UMAC-SME,
     * so notify UMAC-SME when adhoc join complete.
     * reference funcion : sm_join_complete()  umac\sme\ieee80211_ibss_sm.c
     */
    wlan_ibss_sm_join_complete(osifp->sm_ibss_handle, ieeeStatus);
}

void osif_auth_complete(os_handle_t osif, IEEE80211_STATUS ieeeStatus)
{
    osif_dev *osifp = (osif_dev *)osif;
#if ATH_DEBUG
    wlan_if_t vap = osifp->os_if;
#endif
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: Status(%d)\n", __func__, ieeeStatus);
}

void osif_assoc_req(os_handle_t osif, wbuf_t wbuf)
{
    osif_dev *osifp = (osif_dev *)osif;
#if ATH_DEBUG
    wlan_if_t vap = osifp->os_if;
#endif

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: \n", __func__);
}

void osif_assoc_complete(os_handle_t osif, IEEE80211_STATUS ieeeStatus, u_int16_t aid, wbuf_t wbuf)
{
    osif_dev *osifp = (osif_dev *)osif;
#if ATH_DEBUG
    wlan_if_t vap = osifp->os_if;
#endif
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: Status(%d) aid(%d)\n", __func__, ieeeStatus, aid);
}

void osif_reassoc_complete(os_handle_t osif, IEEE80211_STATUS ieeeStatus, u_int16_t aid, wbuf_t wbuf)
{
    osif_dev *osifp = (osif_dev *)osif;
#if ATH_DEBUG
    wlan_if_t vap = osifp->os_if;
#endif

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: Status(%d) aid(%d)\n", __func__, ieeeStatus, aid);
}

void osif_deauth_indication_ibss(os_handle_t osif, u_int8_t *macaddr, u_int16_t associd, u_int16_t reason_code)
{
    osif_dev *osifp = (osif_dev *)osif;
#if ATH_DEBUG
    wlan_if_t vap = osifp->os_if;
#endif
    union iwreq_data wreq;
    struct net_device *dev = osifp->netdev;
    ath_netlink_event_t event;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: macaddr(%02x:%02x:%02x:%02x:%02x:%02x) reason(%d)\n",
                      __func__, macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5], reason_code);
    /*
     * notify upper layor application an IBSS leave
     */

    memset(&wreq, 0, sizeof(wreq));
    IEEE80211_ADDR_COPY(wreq.addr.sa_data, macaddr);
    wreq.addr.sa_family = ARPHRD_ETHER;
    WIRELESS_SEND_EVENT(dev, IWEVEXPIRED, &wreq, NULL);


    memset(&event, 0x0, sizeof(event));
    event.type = ATH_EVENT_NODE_LEAVE;
    IEEE80211_ADDR_COPY(event.mac, macaddr);
    ath_adhoc_netlink_send(&event, NULL, 0);
}

void osif_assoc_indication_ibss(os_handle_t osif, u_int8_t *macaddr, u_int16_t result, wbuf_t wbuf, wbuf_t resp_wbuf, bool reassoc)
{
    osif_dev *osifp = (osif_dev *)osif;
#if ATH_DEBUG
    wlan_if_t vap = osifp->os_if;
#endif
    union iwreq_data wreq;
    struct net_device *dev = osifp->netdev;
    ath_netlink_event_t event;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: macaddr(%02x:%02x:%02x:%02x:%02x:%02x) result(%d)\n",
                      __func__, macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5], result);
    /*
     * notify upper layor application an IBSS join
     */

    memset(&wreq, 0, sizeof(wreq));
    IEEE80211_ADDR_COPY(wreq.addr.sa_data, macaddr);
    wreq.addr.sa_family = ARPHRD_ETHER;
    WIRELESS_SEND_EVENT(dev, IWEVREGISTERED, &wreq, NULL);

    memset(&event, 0x0, sizeof(event));
    event.type = ATH_EVENT_NODE_JOIN;
    IEEE80211_ADDR_COPY(event.mac, macaddr);
    ath_adhoc_netlink_send(&event, NULL, 0);
}

void osif_disassoc_indication_ibss(os_handle_t osif, u_int8_t *macaddr, u_int16_t associd, u_int32_t reason_code)
{
    osif_dev *osifp = (osif_dev *)osif;
#if ATH_DEBUG
    wlan_if_t vap = osifp->os_if;
#endif
    union iwreq_data wreq;
    struct net_device *dev = osifp->netdev;
    ath_netlink_event_t event;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: macaddr(%02x:%02x:%02x:%02x:%02x:%02x) reason_code(%d)\n",
                      __func__, macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5], reason_code);

#if ATH_SUPPORT_IWSPY
	/* Reset iwspy data */
	osif_iwspy_reset_data(osif, macaddr);
#endif

    /*
     * notify upper layor application an IBSS leave
     */

    memset(&wreq, 0, sizeof(wreq));
    IEEE80211_ADDR_COPY(wreq.addr.sa_data, macaddr);
    wreq.addr.sa_family = ARPHRD_ETHER;
    WIRELESS_SEND_EVENT(dev, IWEVEXPIRED, &wreq, NULL);

    memset(&event, 0x0, sizeof(event));
    event.type = ATH_EVENT_NODE_LEAVE;
    IEEE80211_ADDR_COPY(event.mac, macaddr);
    ath_adhoc_netlink_send(&event, NULL, 0);
}

void osif_ibss_merge_start_indication(os_handle_t osif, u_int8_t *bssid)
{
    osif_dev *osifp = (osif_dev *)osif;
#if ATH_DEBUG
    wlan_if_t vap = osifp->os_if;
#endif

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: \n", __func__);
}

void osif_ibss_merge_completion_indication(os_handle_t osif, u_int8_t *bssid)
{
    osif_dev *osifp = (osif_dev *)osif;
#if ATH_DEBUG
    wlan_if_t vap = osifp->os_if;
#endif

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: \n", __func__);
}
#endif /* end of #if ATH_SUPPORT_IBSS_NETLINK_NOTIFICATION */

#if ATH_SUPPORT_IBSS_NETLINK_NOTIFICATION
void osif_ibss_rssi_monitor(os_handle_t osif, u_int8_t *macaddr, u_int32_t rssi_class)
{
  osif_dev *osifp = (osif_dev *)osif;
#if ATH_DEBUG
  wlan_if_t vap = osifp->os_if;
#endif
  ath_netlink_event_t event;

  IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: macaddr(%02x:%02x:%02x:%02x:%02x:%02x) RSSI level(%d)\n",
		    __func__, macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5], rssi_class);

  memset(&event, 0x0, sizeof(event));
  event.type = ATH_EVENT_NODE_RSSI_MONITOR;
  IEEE80211_ADDR_COPY(event.mac, macaddr);
  ath_adhoc_netlink_send(&event, (char *)&rssi_class, sizeof(u_int32_t));
}
#endif

#if ATH_TX_OVERFLOW_IND
static void osif_wlan_tx_overflow_event(os_handle_t osif)
{
#if UMAC_SUPPORT_ACFG
    osif_dev  *osdev = (osif_dev *) osif;
#if !PEER_FLOW_CONTROL_FORCED_MODE0
    wlan_if_t vap = osdev->os_if;
    static u_int32_t tx_overflow_limit_print = 0;
#endif
    struct net_device *dev = osdev->netdev;
    acfg_event_data_t *acfg_event = NULL;

    acfg_event = (acfg_event_data_t *)kmalloc(sizeof(acfg_event_data_t), GFP_ATOMIC);
    if (acfg_event == NULL)
        return;

    memset(acfg_event, 0, sizeof(acfg_event_data_t));
    acfg_send_event(dev, ((osif_dev *)osif)->os_handle, WL_EVENT_TYPE_TX_OVERFLOW, acfg_event);
#if !PEER_FLOW_CONTROL_FORCED_MODE0
    if(!(tx_overflow_limit_print % TXOVERFLOW_PRINT_LIMIT))
    {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY, "%s: TX overflow event sent. \n", __func__);
    }
    tx_overflow_limit_print++;
#endif
    kfree(acfg_event);
#endif
}
#endif

#if QCA_LTEU_SUPPORT
static void
osif_mu_report(wlan_if_t vap, struct event_data_mu_rpt *mu_rpt)
{
    osif_dev *osdev = (osif_dev *)wlan_vap_get_registered_handle(vap);
    struct net_device *dev = OSIF_TO_NETDEV(osdev);
    union iwreq_data wreq;
    int i;

    memset(&wreq, 0, sizeof(wreq));
    wreq.data.flags = IEEE80211_EV_MU_RPT;
    wreq.data.length = sizeof(struct event_data_mu_rpt);
    WIRELESS_SEND_EVENT(dev, IWEVGENIE, &wreq, (void *)mu_rpt);

    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: MU report id %d completed, status %d, MUs -",
           __func__, mu_rpt->mu_req_id, mu_rpt->mu_status);
    for (i = 0; i < (MU_MAX_ALGO - 1); i++)
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %d", mu_rpt->mu_total_val[i]);
    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ", num bssid %d, MUs (hidden algo) -", mu_rpt->mu_num_bssid);
    for (i = 0; i < LTEU_MAX_BINS; i++)
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %d", mu_rpt->mu_hidden_node_algo[i]);
    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n");
}
#endif

static wlan_misc_event_handler_table sta_misc_evt_handler = {
    osif_channel_change,                   /* wlan_channel_change */
    osif_country_changed,                  /* wlan_country_changed */
    osif_linkspeed,                        /* wlan_linkspeed */
    osif_michael_failure_indication,       /* wlan_michael_failure_indication */
    osif_replay_failure_indication,        /* wlan_replay_failure_indication */
    osif_beacon_miss,                      /* wlan_beacon_miss_indication */
    NULL,                                  /* wlan_beacon_rssi_indication */
    osif_device_error,                     /* wlan_device_error_indication */
    NULL,                                  /* wlan_sta_clonemac_indication */
    NULL,                                  /* wlan_sta_scan_entry_update */
    NULL,                                  /* wlan_ap_stopped */
#if ATH_SUPPORT_WAPI
    NULL,                                  /*wlan_sta_rekey_indication*/
#endif
#if ATH_SUPPORT_IBSS_NETLINK_NOTIFICATION
    NULL,
#endif
#if UMAC_SUPPORT_RRM_MISC
    NULL,				                   /* osif_chload */
    NULL,                                                  /* osif_nonerpcnt */
    NULL,				                   /* osif_bgjoin */
    NULL,				                   /* osif_cochannelap_cnt*/
#endif
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
   osif_buffull_warning,                                     /* wlan_buffull */
#endif
    NULL,                   /* wlan_session_timeout */
#if ATH_SUPPORT_MGMT_TX_STATUS
   NULL,
#endif
#if ATH_BAND_STEERING
    NULL, /* bsteering_event ,  void (*bsteering_event)(os_handle_t,enum,char eventlen,char *data); */
#endif
#if ATH_SSID_STEERING
    NULL, /* ssid_event , void (*ssid_event)(os_handle_t, u_int8_t *macaddr); */
#endif
#if UMAC_SUPPORT_ACL
    NULL,                                 /* assocdeny_event */
#endif /*UMAC_SUPPORT_ACL*/
#if ATH_TX_OVERFLOW_IND
    NULL,                                 /*wlan_tx_overflow */
#endif
    NULL,                                 /*wlan_ch_hop_channel_change*/
    NULL,                                 /*  wlan_recv_probereq */
#if DBDC_REPEATER_SUPPORT
    osif_dbdc_stavap_connection,                /*stavap_connection*/
#endif
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
    osif_sta_cac_started,                 /* wlan_sta_cac_started */
#endif
    NULL,				/*chan_util_event*/
    NULL,				/*wlan_keyset_done_indication*/
    NULL,				/*wlan_blklst_sta_auth_indication*/
};

static wlan_event_handler_table common_evt_handler = {
    osif_receive,
    osif_receive_filter_80211,
    osif_receive_monitor_80211,
    osif_dev_xmit_queue,
    osif_vap_xmit_queue,
    NULL,
#if ATH_SUPPORT_IWSPY
	osif_iwspy_update,
#endif
#if ATH_SUPPORT_FLOWMAC_MODULE
    osif_pause_queue,
#endif
    osif_vap_scan_cancel,       /* wlan_vap_scan_cancel */
    osif_bringup_ap_vaps,       /* wlan_bringup_ap_vaps */
    osif_bringdown_ap_vaps,     /* wlan_bringdown_ap_vaps */
};
static void
osif_join_complete_infra_sta(os_handle_t osif, IEEE80211_STATUS status)
{
    osif_dev  *osdev = (osif_dev *) osif;
    wlan_if_t vap = osdev->os_if;
    wlan_dev_t comhandle = wlan_vap_get_devhandle(vap);
    struct ieee80211_vap_info vap_info;

    if ( wlan_get_param(vap, IEEE80211_FEATURE_VAP_ENHIND)) {
        if (!ic_list.iface_mgr_up) {
            vap_info.chan = 0;
            vap_info.no_cac = 1;
            wlan_iterate_vap_list(comhandle, osif_bringup_vap_iter_func, &vap_info);
            vap_info.no_cac = 0;
        }
    } else if (!vap->iv_ic->ic_is_mode_offload(vap->iv_ic) && IEEE80211_IS_CHAN_2GHZ(vap->iv_ic->ic_curchan) && \
              wlan_get_param(vap, IEEE80211_FEATURE_VAP_ENHIND)) {
        struct ieee80211vap *tmp_vap = NULL;
        bool   is_bss_chan_changed = false;

        /* In case of multi BSSID, make sure all the VAPs change channel */
         TAILQ_FOREACH(tmp_vap, &vap->iv_ic->ic_vaps, iv_next) {

                if((tmp_vap == vap) || (IEEE80211_M_HOSTAP != ieee80211vap_get_opmode(tmp_vap)) || \
                   (tmp_vap->iv_bsschan == vap->iv_ic->ic_curchan)) {
                   continue;
                }

                tmp_vap->iv_bsschan = vap->iv_ic->ic_curchan;
                /* This is needed to make the beacon is re-initlized */
                tmp_vap->channel_change_done = 1;
                is_bss_chan_changed = true;
                IEEE80211_DPRINTF(tmp_vap, IEEE80211_MSG_STATE, "%s switch channel %d\n",
                                    __func__, vap->iv_ic->ic_curchan->ic_ieee);
        }

        if(is_bss_chan_changed) {
               vap->iv_ic->ic_chwidth_change(vap->iv_bss);
        }
     }
}
#define IEEE80211_MSG_CSL_STR         "[CSL] "
static void osif_join_complete_infra_csl (os_handle_t osif, IEEE80211_STATUS status)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_JOIN_COMPLETE_INFRA_EVENT");
}

static void osif_join_complete_adhoc_csl (os_handle_t osif, IEEE80211_STATUS status)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_JOIN_COMPLETE_ADHOC_EVENT");
}

static void osif_auth_complete_csl (os_handle_t osif, IEEE80211_STATUS status)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_AUTH_COMPLETE_EVENT");
}

static void osif_assoc_req_csl (os_handle_t osif, wbuf_t wbuf)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_ASSOC_REQ_EVENT");
}

static void osif_assoc_complete_csl (os_handle_t osif, IEEE80211_STATUS status, u_int16_t aid, wbuf_t wbuf)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_ASSOC_COMPLETE_EVENT");
}

static void osif_reassoc_complete_csl (os_handle_t osif, IEEE80211_STATUS status, u_int16_t aid, wbuf_t wbuf)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_REASSOC_COMPLETE_EVENT");
}

static void osif_deauth_complete_csl (os_handle_t osif, u_int8_t *macaddr, IEEE80211_STATUS status)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_DEAUTH_COMPLETE_EVENT");
}

static void osif_disassoc_complete_csl (os_handle_t osif, u_int8_t *macaddr, u_int32_t reason, IEEE80211_STATUS status)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_DISASSOC_COMPLETE_EVENT");
}

static void osif_txchanswitch_complete_csl (os_handle_t osif, IEEE80211_STATUS status)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_TXCHANSWITCH_COMPLETE_EVENT");
}

static void osif_repeater_cac_complete_csl (os_handle_t osif, IEEE80211_STATUS status)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_REPEATER_CAC_COMPLETE_EVENT");
}

static void osif_auth_indication_csl (os_handle_t osif, u_int8_t *macaddr, u_int16_t result)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_AUTH_INDICATION_EVENT");
}

static void osif_deauth_indication_csl (os_handle_t osif, u_int8_t *macaddr, u_int16_t associd, u_int16_t reason_code)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_DEAUTH_INDICATION_EVENT");
}

static void osif_assoc_indication_csl (os_handle_t osif, u_int8_t *macaddr, u_int16_t result, wbuf_t wbuf, wbuf_t resp_wbuf, bool reassoc)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_ASSOC_INDICATION_EVENT");
}

static void osif_reassoc_indication_csl (os_handle_t osif, u_int8_t *macaddr, u_int16_t result, wbuf_t wbuf, wbuf_t resp_wbuf, bool reassoc)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_REASSOC_INDICATION_EVENT");
}

static void osif_disassoc_indication_csl (os_handle_t osif, u_int8_t *macaddr, u_int16_t associd, u_int32_t reason_code)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_DISASSOC_INDICATION_EVENT");
}

static void osif_ibss_merge_start_indication_csl (os_handle_t osif, u_int8_t *bssid)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_IBSS_MERGE_START_INDICATION_EVENT");
}

static void osif_ibss_merge_completion_indication_csl (os_handle_t osif, u_int8_t *bssid)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_IBSS_MERGE_COMPLETION_INDICATION_EVENT");
}

static void osif_radar_detected_csl (os_handle_t osif, u_int32_t csa_delay)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_RADAR_DETECTED_EVENT");
}

static void osif_node_authorized_indication_csl (os_handle_t osif, u_int8_t *macaddr)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_NODE_AUTHORIZED_INDICATION_EVENT");
}

static void osif_unprotected_deauth_indication_csl (os_handle_t osif, u_int8_t *macaddr, u_int16_t associd, u_int16_t reason_code)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MLME_UNPROTECTED_DEAUTH_INDICATION_EVENT");
}

static void osif_channel_change_csl (os_handle_t osif, wlan_chan_t chan)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "CHANNEL_CHANGE_EVENT");
}

static void osif_country_changed_csl (os_handle_t osif, char *country)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "COUNTRY_CHANGED_EVENT");
}

static void osif_linkspeed_csl (os_handle_t osif, u_int32_t rxlinkspeed, u_int32_t txlinkspeed)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "LINKSPEED_EVENT");
}

static void osif_michael_failure_indication_csl (os_handle_t osif, const u_int8_t *frm, u_int keyix)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MICHAEL_FAILURE_INDICATION_EVENT");
}

static void osif_replay_failure_indication_csl (os_handle_t osif, const u_int8_t *frm, u_int keyix)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "REPLAY_FAILURE_INDICATION_EVENT");
}

static void osif_beacon_miss_indication_csl (os_handle_t osif)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "BEACON_MISS_INDICATION_EVENT");
}

static void osif_beacon_rssi_indication_csl (os_handle_t osif)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "BEACON_RSSI_INDICATION_EVENT");
}

static void osif_device_error_indication_csl (os_handle_t osif)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "DEVICE_ERROR_INDICATION_EVENT");
}

static void osif_sta_clonemac_indication_csl (os_handle_t osif)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "STA_CLONEMAC_INDICATION_EVENT");
}

static void osif_sta_scan_entry_update_csl (os_handle_t osif, wlan_scan_entry_t scan_entry, bool flag)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "STA_SCAN_ENTRY_UPDATE_EVENT");
}

static void osif_ap_stopped_csl (os_handle_t osif, ieee80211_ap_stopped_reason reason)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "AP_STOPPED_EVENT");
}

#if ATH_SUPPORT_WAPI

static void osif_sta_rekey_indication_csl (os_handle_t osif, u_int8_t *macaddr)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "STA_REKEY_INDICATION_EVENT");
}
#endif

#if ATH_SUPPORT_IBSS_NETLINK_NOTIFICATION

static void osif_ibss_rssi_monitor_csl (os_handle_t osif, u_int8_t *macaddr, u_int32_t rssi_class)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "IBSS_RSSI_MONITOR_EVENT");
}
#endif

#if UMAC_SUPPORT_RRM_MISC

static void osif_channel_load_csl (os_handle_t osif, u_int8_t chload)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "CHANNEL_LOAD_EVENT");
}

static void osif_nonerpcnt_csl (os_handle_t osif, u_int8_t erpcnt)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "NONERPCNT_EVENT");
}

static void osif_bgjoin_csl (os_handle_t osif, u_int8_t val)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "BGJOIN_EVENT");
}

static void osif_cochannelap_cnt_csl (os_handle_t osif, u_int8_t val)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "COCHANNELAP_CNT_EVENT");
}
#endif

#if ATH_SUPPORT_HYFI_ENHANCEMENTS

static void osif_buffull_csl (os_handle_t osif)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "BUFFULL_EVENT");
}
#endif

static void osif_session_timeout_csl (os_handle_t osif, u_int8_t *macaddr)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "SESSION_TIMEOUT_EVENT");
}

#if ATH_SUPPORT_MGMT_TX_STATUS

static void osif_mgmt_tx_status_csl (os_handle_t osif, IEEE80211_STATUS status, wbuf_t wbuf)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "MGMT_TX_STATUS_EVENT");
}
#endif

#if ATH_BAND_STEERING

static void osif_bsteering_event_csl (os_handle_t osif, ATH_BSTEERING_EVENT type, uint32_t eventlen, const char *data)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "BSTEERING_EVENT");
}
#endif

#if ATH_SSID_STEERING

static void osif_ssid_event_csl (os_handle_t osif, u_int8_t *macaddr)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "SSID_EVENT");
}
#endif

#if UMAC_SUPPORT_ACL

static void osif_assocdeny_event_csl (os_handle_t osif, u_int8_t *macaddr)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "ASSOCDENY_EVENT");
}
#endif /* UMAC_SUPPORT_ACL */

#if ATH_TX_OVERFLOW_IND

static void osif_tx_overflow_csl (os_handle_t osif)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "TX_OVERFLOW_EVENT");
}
#endif

static void osif_ch_hop_channel_change_csl (os_handle_t osif, u_int8_t channel)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "CH_HOP_CHANNEL_CHANGE_EVENT");
}

static void osif_recv_probereq_csl (os_handle_t osif, u_int8_t *macaddr, u_int8_t *ssid_element)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "RECV_PROBEREQ_EVENT");
}

#if DBDC_REPEATER_SUPPORT

static void osif_stavap_connection_csl (os_handle_t osif)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "STAVAP_CONNECTION_EVENT");
}
#endif

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS

static void osif_sta_cac_started_csl (os_handle_t osif, u_int32_t frequency, u_int32_t timeout)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "STA_CAC_STARTED_EVENT");
}
#endif

static void osif_chan_util_event_csl (os_handle_t osif, u_int32_t self_util, u_int32_t obss_util)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "CHAN_UTIL_EVENT");
}

static void osif_keyset_done_indication_csl (os_handle_t osif, u_int8_t *macaddr, u_int8_t status)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "KEYSET_DONE_INDICATION_EVENT");
}

static void osif_blklst_sta_auth_indication_csl (os_handle_t osif, u_int8_t *macaddr, u_int8_t status)
{
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    ieee80211_note(vap, IEEE80211_MSG_MLME, IEEE80211_MSG_CSL_STR "BLKLST_STA_AUTH_INDICATION_EVENT");
}

static wlan_mlme_event_handler_table sta_mlme_evt_handler = {
    osif_join_complete_infra_sta,
    NULL,
    osif_auth_complete_sta,
    NULL,
    osif_assoc_complete_sta,
    osif_assoc_complete_sta,
    osif_deauth_complete_sta,
    osif_disassoc_complete_sta,
    NULL,                           /* mlme_txchanswitch_complete */
    NULL,                           /* mlme_repeater_cac_complete  */
    osif_auth_indication_sta,
    osif_deauth_indication_sta,
    osif_assoc_indication_sta,
    osif_assoc_indication_sta,
    osif_disassoc_indication_sta,
    NULL,
    NULL,
    NULL,                             /* wlan_radar_detected */
    NULL,                             /* wlan_node_authorized_indication */
    osif_unprotected_deauth_indication_sta,   /* unprotected deauth indication */
} ;

#if ATH_SUPPORT_IBSS_NETLINK_NOTIFICATION
/* MLME handlers */
static wlan_mlme_event_handler_table ibss_mlme_evt_handler = {
    /* MLME confirmation handler */
    NULL,                                  /* mlme_join_complete_infra */
    osif_join_complete_adhoc,              /* mlme_join_complete_adhoc */
    osif_auth_complete,                    /* mlme_auth_complete */
    osif_assoc_req,                        /* mlme_assoc_req */
    osif_assoc_complete,                   /* mlme_assoc_complete */
    osif_reassoc_complete,                 /* mlme_reassoc_complete */
    NULL,                                  /* mlme_deauth_complete */
    NULL,                                  /* mlme_deassoc_complete */
    NULL,                                  /* mlme_txchanswitch_complete */
    NULL,                                  /* mlme_repeater_cac_complete */

    /* MLME indication handler */
    NULL,                                  /* mlme_auth_indication */
    osif_deauth_indication_ibss,           /* mlme_deauth_indication */
    osif_assoc_indication_ibss,            /* mlme_assoc_indication */
    NULL,                                  /* mlme_reassoc_indication */
    osif_disassoc_indication_ibss,         /* mlme_disassoc_indication */
    osif_ibss_merge_start_indication,      /* mlme_ibss_merge_start_indication */
    osif_ibss_merge_completion_indication, /* mlme_ibss_merge_completion_indication */
    NULL,                                  /* wlan_radar_detected */
    NULL,                                  /* wlan_node_authorized_indication */
    NULL,                                  /* unprotected deauth indication */
};
#endif /* end of #if ATH_SUPPORT_IBSS_NETLINK_NOTIFICATION */

#if ATH_SUPPORT_IBSS_NETLINK_NOTIFICATION
static wlan_misc_event_handler_table ibss_misc_evt_handler = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,                               /* wlan_ap_stopped */
#if ATH_SUPPORT_WAPI
    NULL,
#endif
#if ATH_SUPPORT_IBSS_NETLINK_NOTIFICATION
    osif_ibss_rssi_monitor,
#endif
#if UMAC_SUPPORT_RRM_MISC
    NULL, /*void (*wlan_channel_load) (os_handle_t, u_int8_t chload);*/
    NULL , /* void (*wlan_nonerpcnt) (os_handle_t, u_int8_t erpcnt);*/
    NULL, /* void (*wlan_bgjoin) (os_handle_t, u_int8_t val); */
    NULL ,/* void (*wlan_cochannelap_cnt) (os_handle_t, u_int8_t val); */
#endif
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
    osif_buffull_warning,                                     /* wlan_buffull */
#endif
    NULL, /* void (*wlan_session_timeout) (os_handle_t, u_int8_t *macaddr);*/
#if ATH_SUPPORT_MGMT_TX_STATUS
    NULL,
#endif
#if ATH_BAND_STEERING
    NULL , /* void (*bsteering_event)(os_handle_t,enum,char eventlen,char *data); */
#endif
#if ATH_SSID_STEERING
    NULL , /* ssid_event , void (*ssid_event)(os_handle_t, u_int8_t *macaddr); */
#endif
#if UMAC_SUPPORT_ACL
    NULL,                /* assocdeny_event */
#endif /*UMAC_SUPPORT_ACL*/
    NULL,                /*wlan_ch_hop_channel_change*/
    NULL,                /*  wlan_recv_probereq */
#if DBDC_REPEATER_SUPPORT
    NULL,                /*stavap_connection*/
#endif
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
    NULL,                 /* wlan_sta_cac_started */
#endif
    NULL,                               /*chan_util_event*/
    NULL,                               /*wlan_keyset_done_indication*/
    NULL,                               /*wlan_blklst_sta_auth_indication*/
};
#endif

static wlan_mlme_event_handler_table ap_mlme_evt_handler = {
	osif_create_infra_complete,
    NULL,
    osif_auth_complete_ap,
    NULL,
    osif_assoc_complete_ap,
    osif_assoc_complete_ap,
    osif_deauth_complete_ap,
    osif_disassoc_complete_ap,
    NULL,                                 /* mlme_txchanswitch_complete */
    NULL,                                 /* mlme_repeater_cac_complete */
    osif_auth_indication_ap,
    osif_deauth_indication_ap,
    osif_assoc_indication_ap,
    osif_assoc_indication_ap,
    osif_leave_indication_ap,
    NULL,
    NULL,
    NULL,
    osif_node_authorized_indication_ap,   /* wlan_node_authorized_indication */
    NULL,                                 /* unprotected deauth indication */
} ;

static wlan_misc_event_handler_table ap_misc_evt_handler = {
    osif_channel_change,
    osif_country_changed,
    osif_linkspeed,
    osif_michael_failure_indication,
    osif_replay_failure_indication,
    NULL,
    NULL,                               /* wlan_beacon_rssi_indication */
    NULL,
    NULL,
    NULL,
    NULL,                               /* wlan_ap_stopped */
#if ATH_SUPPORT_WAPI
    osif_rekey_indication_ap,
#endif
#if ATH_SUPPORT_IBSS_NETLINK_NOTIFICATION
    NULL,
#endif
#if UMAC_SUPPORT_RRM_MISC
    osif_chload,
    osif_nonerpcnt,
    osif_bgjoin,
    osif_cochannelap_cnt,
#endif
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
   osif_buffull_warning,                                     /* wlan_buffull */
#endif
    osif_session_timeout,                   /* wlan_session_timeout */
#if ATH_SUPPORT_MGMT_TX_STATUS
   osif_mgmt_tx_status,
#endif
#if ATH_BAND_STEERING
    osif_band_steering_event , /* void (*bsteering_event)(os_handle_t,enum,char eventlen,char *data); */
#endif
#if ATH_SSID_STEERING
    osif_ssid_event,   /* ssid_event , void (*ssid_event)(os_handle_t, u_int8_t *macaddr); */
#endif
#if UMAC_SUPPORT_ACL
    osif_assocdeny_event,   /* assocdeny_event */
#endif /*UMAC_SUPPORT_ACL*/
#if ATH_TX_OVERFLOW_IND
    osif_wlan_tx_overflow_event,            /* wlan_tx_overflow */
#endif
    osif_ch_hop_channel_change , /*wlan_ch_hop_channel_change*/
    osif_recv_probereq,     /*  wlan_recv_probereq */
#if DBDC_REPEATER_SUPPORT
    NULL,                /*stavap_connection*/
#endif
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
    NULL,                 /* wlan_sta_cac_started */
#endif
    NULL,
    osif_keyset_done_indication,/*keyset_done_indication*/
    osif_blklst_sta_auth_indication, /*blklst_sta_auth_indication*/
};

static wlan_mlme_event_handler_table csl_mlme_evt_handler = {
    osif_join_complete_infra_csl,
    osif_join_complete_adhoc_csl,
    osif_auth_complete_csl,
    osif_assoc_req_csl,
    osif_assoc_complete_csl,
    osif_reassoc_complete_csl,
    osif_deauth_complete_csl,
    osif_disassoc_complete_csl,
    osif_txchanswitch_complete_csl,
    osif_repeater_cac_complete_csl,
    osif_auth_indication_csl,
    osif_deauth_indication_csl,
    osif_assoc_indication_csl,
    osif_reassoc_indication_csl,
    osif_disassoc_indication_csl,
    osif_ibss_merge_start_indication_csl,
    osif_ibss_merge_completion_indication_csl,
    osif_radar_detected_csl,
    osif_node_authorized_indication_csl,
    osif_unprotected_deauth_indication_csl,
};

static wlan_misc_event_handler_table csl_misc_evt_handler = {
    osif_channel_change_csl,
    osif_country_changed_csl,
    osif_linkspeed_csl,
    osif_michael_failure_indication_csl,
    osif_replay_failure_indication_csl,
    osif_beacon_miss_indication_csl,
    osif_beacon_rssi_indication_csl,
    osif_device_error_indication_csl,
    osif_sta_clonemac_indication_csl,
    osif_sta_scan_entry_update_csl,
    osif_ap_stopped_csl,
#if ATH_SUPPORT_WAPI
    osif_sta_rekey_indication_csl,
#endif
#if ATH_SUPPORT_IBSS_NETLINK_NOTIFICATION
    osif_ibss_rssi_monitor_csl,
#endif
#if UMAC_SUPPORT_RRM_MISC
    osif_channel_load_csl,
    osif_nonerpcnt_csl,
    osif_bgjoin_csl,
    osif_cochannelap_cnt_csl,
#endif
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
    osif_buffull_csl,
#endif
    osif_session_timeout_csl,
#if ATH_SUPPORT_MGMT_TX_STATUS
    osif_mgmt_tx_status_csl,
#endif
#if ATH_BAND_STEERING
    osif_bsteering_event_csl,
#endif
#if ATH_SSID_STEERING
    osif_ssid_event_csl,
#endif
#if UMAC_SUPPORT_ACL
    osif_assocdeny_event_csl,
#endif /* UMAC_SUPPORT_ACL */
#if ATH_TX_OVERFLOW_IND
    osif_tx_overflow_csl,
#endif
    osif_ch_hop_channel_change_csl,
    osif_recv_probereq_csl,
#if DBDC_REPEATER_SUPPORT
    osif_stavap_connection_csl,
#endif
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
    osif_sta_cac_started_csl,
#endif
    osif_chan_util_event_csl,
    osif_keyset_done_indication_csl,
    osif_blklst_sta_auth_indication_csl,
};

void wlan_csl_enable(struct ieee80211vap *vap, int csl_val)
{
    u_int64_t old = wlan_get_debug_flags(vap);

    if (csl_val & LOG_CSL_BASIC) {
        wlan_set_debug_flags (vap, old | (IEEE80211_MSG_CSL));
    } else {
        wlan_set_debug_flags (vap, old & ~(IEEE80211_MSG_CSL));
    }

    if (csl_val & LOG_CSL_MLME_EVENTS) {
        wlan_vap_register_mlme_event_handlers (vap, (os_handle_t)vap->iv_ifp, &csl_mlme_evt_handler);
    } else {
        wlan_vap_unregister_mlme_event_handlers (vap, (os_handle_t)vap->iv_ifp, &csl_mlme_evt_handler);
    }

    if (csl_val & LOG_CSL_MISC_EVENTS) {
        wlan_vap_register_misc_event_handlers (vap, (os_handle_t)vap->iv_ifp, &csl_misc_evt_handler);
    } else {
        wlan_vap_unregister_misc_event_handlers (vap, (os_handle_t)vap->iv_ifp, &csl_misc_evt_handler);
    }

    vap->iv_csl_support = csl_val;
}

static void osif_tx_lock(void *ptr)
{
    osif_dev *osifp =  (osif_dev *)ptr;
    spin_lock(&osifp->tx_lock);

}

static void osif_tx_unlock(void *ptr)
{
    osif_dev *osifp =  (osif_dev *)ptr;
    spin_unlock(&osifp->tx_lock);
}

static void osif_vap_setup(wlan_if_t vap, struct net_device *dev,
                            enum ieee80211_opmode opmode)
{
    osif_dev  *osifp = ath_netdev_priv(dev);

    osifp->osif_is_mode_offload = vap->iv_ic->ic_is_mode_offload(vap->iv_ic);
    vap->iv_netdev_name = dev->name;

#if QCA_LTEU_SUPPORT
    if (vap->iv_ic->ic_nl_handle)
        ieee80211_nl_register_handler(vap, osif_mu_report, osif_nl_scan_evhandler);
#endif

    switch(opmode) {
    case IEEE80211_M_STA:
    case IEEE80211_M_P2P_CLIENT:
        wlan_vap_set_registered_handle(vap,(os_if_t)osifp);
        wlan_vap_register_event_handlers(vap,&common_evt_handler);
        wlan_vap_register_mlme_event_handlers(vap,(os_handle_t)osifp,&sta_mlme_evt_handler);
        wlan_vap_register_misc_event_handlers(vap,(os_handle_t)osifp,&sta_misc_evt_handler);
        osifp->sm_handle = wlan_connection_sm_create(osifp->os_handle,vap);
        if (!osifp->sm_handle) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : sm creation failed\n",
                            __func__);
            return ;
        }
        wlan_connection_sm_register_event_handlers(osifp->sm_handle,(os_if_t)osifp,
                                            osif_sta_sm_evhandler);
        wlan_connection_sm_set_param(osifp->sm_handle,
                                    WLAN_CONNECTION_PARAM_RECONNECT_TIMEOUT, 4*60*1000 /* 4 minutes */);
#if ATH_PERF_PWR_OFFLOAD
       /* WAR. disable BG scan until the proper rssi value is returned from target */
        wlan_connection_sm_set_param(osifp->sm_handle,
                                                     WLAN_CONNECTION_PARAM_BGSCAN_POLICY,
                                                     WLAN_CONNECTION_BGSCAN_POLICY_NONE);
#endif

#ifdef ATH_SUPPORT_P2P
        if (osifp->p2p_client_handle ) {
            wlan_connection_sm_set_param(osifp->sm_handle, WLAN_CONNECTION_PARAM_BGSCAN_MIN_DWELL_TIME, 105);
            wlan_connection_sm_set_param(osifp->sm_handle, WLAN_CONNECTION_PARAM_BGSCAN_MAX_DWELL_TIME, 105);
            wlan_connection_sm_set_param(osifp->sm_handle,
                                    WLAN_CONNECTION_PARAM_RECONNECT_TIMEOUT, 0);
            wlan_connection_sm_set_param(osifp->sm_handle,
                                    WLAN_CONNECTION_PARAM_CONNECT_TIMEOUT, 10);
            wlan_p2p_client_register_event_handlers(osifp->p2p_client_handle, (void *)osifp, osif_p2p_dev_event_handler);
        }
#endif
        break;

#if UMAC_SUPPORT_IBSS
    case IEEE80211_M_IBSS:
        wlan_vap_set_registered_handle(vap,(os_if_t)osifp);
        wlan_vap_register_event_handlers(vap,&common_evt_handler);

        osifp->sm_ibss_handle = wlan_ibss_sm_create(osifp->os_handle,vap);
        if (!osifp->sm_ibss_handle) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : sm creation failed\n",
                              __func__);
            return ;
        }

#if ATH_SUPPORT_IBSS_NETLINK_NOTIFICATION
        /* re-register ibss mlme event handler */
        wlan_vap_register_mlme_event_handlers(vap,(os_handle_t)osifp, &ibss_mlme_evt_handler);
#endif
#if ATH_SUPPORT_IBSS_NETLINK_NOTIFICATION
        wlan_vap_register_misc_event_handlers(vap,(os_handle_t)osifp, &ibss_misc_evt_handler);
#endif

        wlan_ibss_sm_register_event_handlers(osifp->sm_ibss_handle,(os_if_t)osifp,
                                              osif_ibss_sm_evhandler);
        break;
#endif /* end of #if UMAC_SUPPORT_IBSS */

    case IEEE80211_M_HOSTAP:
    case IEEE80211_M_P2P_GO:
        wlan_vap_set_registered_handle(vap,(os_if_t)osifp);
        wlan_vap_register_event_handlers(vap,&common_evt_handler);
        wlan_vap_register_mlme_event_handlers(vap,(os_handle_t)osifp,&ap_mlme_evt_handler);
        wlan_vap_register_misc_event_handlers(vap,(os_handle_t)osifp,&ap_misc_evt_handler);
#ifdef ATH_SUPPORT_P2P
        if (osifp->p2p_go_handle) {
            wlan_p2p_GO_register_event_handlers(osifp->p2p_go_handle, (void *)osifp, osif_p2p_dev_event_handler);
        }
#endif
        break;
#ifdef ATH_SUPPORT_P2P
    case IEEE80211_M_P2P_DEVICE:
        wlan_vap_set_registered_handle(vap,(os_if_t)osifp);
        wlan_vap_register_event_handlers(vap,&common_evt_handler);
        wlan_vap_register_mlme_event_handlers(vap,(os_handle_t)dev,&ap_mlme_evt_handler);
        wlan_vap_register_misc_event_handlers(vap,(os_handle_t)dev,&ap_misc_evt_handler);
        wlan_p2p_register_event_handlers(osifp->p2p_handle, osifp, osif_p2p_dev_event_handler);
        break;
#endif
    case IEEE80211_M_MONITOR:
        wlan_vap_set_registered_handle(vap,(os_if_t)osifp);
        wlan_vap_register_event_handlers(vap,&common_evt_handler);
        break;
    default:
        break;
    }
    if (!osifp->osif_is_mode_offload && opmode == IEEE80211_M_MONITOR) {
            /* set vap_ready if the device mode is ready */
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:%d **** monitor_vap set ready by default ****\n",
                   __func__, __LINE__);
            ieee80211_vap_ready_set(vap);
    }

    /* For OL, these will be later overloaded with OL specific lock APIs */
    osifp->tx_dev_lock_acquire = osif_tx_lock;
    osifp->tx_dev_lock_release = osif_tx_unlock;

    if (!osifp->osif_is_mode_offload)
        return;

}

static void
osif_set_multicast_list(struct net_device *dev)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    struct net_device *parent = osifp->os_comdev;
	wlan_if_t vap = osifp->os_if;
    wlan_if_t tmpvap;
	struct ieee80211com *ic = vap->iv_ic;
	int flags = 0;

    if (dev->flags & IFF_PROMISC)
    {
        parent->flags |= IFF_PROMISC;
    } else {
        parent->flags &= ~IFF_PROMISC;
    }
    if (dev->flags & IFF_ALLMULTI)
    {
        parent->flags |= IFF_ALLMULTI;
	} else {
	    TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
            os_if_t handle = wlan_vap_get_registered_handle(tmpvap);
            if (handle) {
                struct net_device *tmpdev = ((osif_dev *)handle)->netdev;
                if (tmpdev) {
			        flags |= tmpdev->flags;
                }
            }
	}
		if(!(flags & IFF_ALLMULTI))
			parent->flags &= ~IFF_ALLMULTI;
	}

    /* XXX merge multicast list into parent device */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0)
    parent->netdev_ops->ndo_set_rx_mode(parent);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
    parent->netdev_ops->ndo_set_multicast_list(parent);
#else
    parent->set_multicast_list(parent);
#endif
}


static int
osif_change_mtu(struct net_device *dev, int mtu)
{
    if (!(IEEE80211_MTU_MIN < mtu && mtu <= IEEE80211_MTU_MAX))
        return -EINVAL;
    dev->mtu = mtu;
    /* XXX coordinate with parent device */
    return 0;
}

#if UMAC_SUPPORT_IBSS

#if ATH_SUPPORT_IBSS_ACS
static void osif_ibss_acs_event_handler(void *arg, wlan_chan_t channel)
{
    osif_dev *osifp = (osif_dev *) arg;
    wlan_if_t vap = osifp->os_if;
    int chan = wlan_channel_ieee(channel);
    int error = 0;

    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s chan[%d]\n", __func__, chan);

    error = wlan_set_desired_ibsschan(vap, chan);

    if (error !=0) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACS,
                        "%s : failed to set ibss channel with error code %d\n",
                        __func__, error);
        goto done;
    }

    /* Work around soultion to avoid the problem that we might not be able to
       receive frames when going to create the IBSS */
    osif_ibss_scan(osifp);

    /* adhoc create */
    if ( wlan_ibss_sm_start(osifp->sm_ibss_handle, IEEE80211_IBSS_CREATE_NETWORK ) != 0) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : sm start failed\n",
                              __func__);
        //return -EINVAL;
    }

done:
    wlan_autoselect_unregister_event_handler(vap, &osif_ibss_acs_event_handler, (void *)osifp);
}
#endif  /* end of #if ATH_SUPPORT_IBSS_ACS */

static int
osif_ibss_init(struct net_device *dev)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    int waitcnt,error,connection_attempt = 0;

    ieee80211_ssid ssid;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s \n", __func__);

    if (osifp->is_up) return 0;

    osifp->is_up = 0;

    ssid.len = 0;
    wlan_get_desired_ssidlist(vap, &ssid, 1);
    if (ssid.len) {
        if (osifp->sm_ibss_handle) {
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: wlan_ibss_sm_stop\n", __func__);
            /* stop if it is running */
            if (wlan_ibss_sm_stop(osifp->sm_ibss_handle, IEEE80211_IBSS_SM_STOP_ASYNC) == 0) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : wait for connection sm to stop \n",
                                  __func__);
            }
        }
        if (!osifp->is_ibss_create) {
            /* adhoc join */
            do {
                if(!osifp->sm_ibss_handle){
                    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s[%d] osifp->sm_ibss_handle is NULL",__func__,__LINE__);
                    return -EINVAL;
                }
                error =   wlan_ibss_sm_start(osifp->sm_ibss_handle, 0 );
                if (!error) {
                    break;
                }
                /* we are checking error code and resecheduling start as
                * stop may already be in progress
                */
                if (error == -EINPROGRESS)
                {
                    waitcnt = 0;
                    while(waitcnt < 2) {
                        schedule_timeout_interruptible(OSIF_CONNECTION_TIMEOUT);
                        waitcnt++;
                    }
                }
                else {
                      IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "Error %s : sm start failed\n",
                      __func__);
                      return -EINVAL;
                      }
                } while (connection_attempt++ < OSIF_MAX_CONNECTION_ATTEMPT);
        } else {
#if ATH_SUPPORT_IBSS_ACS
            /*
             * ACS : ieee80211_ioctl_siwfreq = 0
             *       wlan_set_desired_ibsschan = 255 for IBSS-create ACS start.
             */
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s iv_des_ibss_chan[%d]\n", __func__, vap->iv_des_ibss_chan);

            if (vap->iv_des_ibss_chan == IEEE80211_CHAN_MAX) {
                /*
                 * start ACS module to get channel
                 */
                wlan_autoselect_register_event_handler(vap,
                        &osif_ibss_acs_event_handler, (void *)osifp);
                wlan_autoselect_find_infra_bss_channel(vap);
                return 0;
            }
#endif

            /* Work around soultion to avoid the problem that we might not be able to
               receive frames when going to create the IBSS */
            osif_ibss_scan(osifp);

            /* adhoc create */
            if ( wlan_ibss_sm_start(osifp->sm_ibss_handle, IEEE80211_IBSS_CREATE_NETWORK ) != 0) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : sm start failed\n",
                                      __func__);
                return -EINVAL;
            }
        }

    } /* end of if (ssid.len) */

    return 0;
}
#endif /* end of #if UMAC_SUPPORT_IBSS */

void osif_vap_acs_cancel(struct net_device *dev, u_int8_t wlanscan)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    int acs_active_on_this_vap = 0;

    if (!vap) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Error: vap is NULL for osifp: 0x%p [%s] \n",
            __func__, osifp, dev->name);
        return;
    }
    if(wlan_autoselect_in_progress(vap)) {
        acs_active_on_this_vap = wlan_autoselect_cancel_selection(vap);
        /* unregister all event handlers as this vap is going down */
        wlan_autoselect_unregister_event_handler(vap,
                &osif_bkscan_acs_event_handler, (void *)osifp);
        wlan_autoselect_unregister_event_handler(vap,
                &osif_bkscan_ht40_event_handler, osifp);
        wlan_autoselect_unregister_event_handler(vap,
                &osif_ht40_event_handler, osifp);
        wlan_autoselect_unregister_event_handler(vap,
                &osif_acs_event_handler, (void *)osifp);
#if ATH_SUPPORT_IBSS_ACS
        wlan_autoselect_unregister_event_handler(vap,
                &osif_ibss_acs_event_handler, (void *)osifp);
#endif  /* #if ATH_SUPPORT_IBSS_ACS */
        /* cancel WLAN scan, if ACS was active on this vap and scan was requested */
        if (acs_active_on_this_vap) {
            if (wlanscan && wlan_scan_in_progress(vap)) {
                QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Scan in progress.. Cancelling it vap: 0x%p\n", __func__, vap);
                wlan_scan_cancel(vap, osifp->scan_requestor,
                        IEEE80211_VAP_SCAN, true);
#if BEELINER_HOST_FPGA_FLAG
                OS_DELAY (2000);
#else
                OS_DELAY (1000);
#endif
            }
        }
    }
}

wlan_if_t osif_get_vap(osif_dev *osifp)
{
    return osifp->os_if;
}
EXPORT_SYMBOL(osif_get_vap);

int
osif_delete_vap_wait_and_free(struct net_device *dev)
{
    osif_dev *osnetdev = ath_netdev_priv(dev);
    struct ieee80211com *ic;
    wlan_if_t vap = osnetdev->os_if;
    osif_dev  *osifp;
    int waitcnt = 0;
    struct net_device *parent = NULL;
    int numvaps = 0;

    osifp = ath_netdev_priv(dev);
    parent = osifp->os_comdev;

    ic = wlan_vap_get_devhandle(vap);

    while(!osifp->is_deleted && waitcnt < OSIF_MAX_DELETE_VAP_TIMEOUT) {
        schedule_timeout_interruptible(HZ);
        waitcnt++;
    }
    /* If not set after waiting deinit vap from here*/
    if (!osifp->is_deleted) {
        ic->ic_vap_delete(vap);
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : tsleep failed \n",
                          __func__);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WARNING: Waiting for VAP delete timedout!!!\n");
    }
    ic->ic_vap_free(vap);

    osnetdev->is_delete_in_progress = 0;
    if (TAILQ_EMPTY(&ic->ic_vaps)) {
        wlan_stop(ic);
#if ATH_SUPPORT_WRAP
        osif_wrap_reinit(ic);
#endif
    }

    numvaps = osif_get_num_active_vaps(ic);
    if((numvaps == 0) && (parent != NULL) && (parent->flags & IFF_RUNNING)){
        if(dev_close(parent))
            qdf_print("Unable to close parent Interface\n");
    }
    return 0;
}

int
osif_vap_init(struct net_device *dev, int forcescan)
{
#define IS_RUNNING(_dev)                                            \
    ((_dev->flags & (IFF_RUNNING|IFF_UP)) == (IFF_RUNNING|IFF_UP))
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct net_device *parent = osifp->os_comdev;
    enum ieee80211_opmode opmode;
    wlan_dev_t comhandle = wlan_vap_get_devhandle(vap);
    int waitcnt;
    int error = 0;
    wlan_chan_t chan;
    int connection_attempt = 0;

    int return_val=0;

#if QCN_IE
    vap->iv_next_beacon_tstamp = ktime_add_ns(ktime_get(), vap->iv_ic->ic_intval * NSEC_PER_MSEC);
#endif

    if (comhandle->no_chans_available == 1) {
        qdf_print("%s: vap-%d(%s) channel is not available\n",
                __func__,vap->iv_unit,vap->iv_netdev_name);
        return 0;
    }

    IEEE80211_DPRINTF(vap,
                      IEEE80211_MSG_STATE | IEEE80211_MSG_DEBUG,
                      "%s, ifname=%s, opmode=%d\n", "start running", osifp->netdev->name, vap->iv_opmode);


    if ((dev->flags & IFF_RUNNING) == 0)
    {
        if (osif_get_num_active_vaps(comhandle) == 0 &&
            (parent->flags & IFF_RUNNING) == 0){
            return_val=dev_open(parent);
            if (return_val!=0)
                return return_val;
        }
        /*
         * Mark us running.  Note that we do this after
         * opening the parent device to avoid recursion.
         */
        dev->flags |= IFF_RUNNING;      /* mark us running */
    }

    if (osifp->os_opmode == IEEE80211_M_P2P_DEVICE) {
        osifp->is_vap_pending = 0;
        osifp->is_up = 1;
        QDF_PRINT_INFO(comhandle->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %s: called...for P2P_DEVICE, ifname=%s\n", __func__, osifp->netdev->name);
        return 0;
    }

#if ATH_SUPPORT_WAPI
    if (osifp->os_opmode == IEEE80211_M_HOSTAP)
        osif_wapi_rekeytimer_start((os_if_t)osifp);
#endif

    /*
     * initialize scan variable
     */
    osifp->os_last_siwscan = 0;

    /*
     * If the parent is up and running, then kick the
     * 802.11 state machine as appropriate.
     * XXX parent should always be up+running
     */
#if 0
    if (IS_RUNNING(parent) && ((osifp->os_opmode == IEEE80211_M_HOSTAP)
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
                               || (osifp->os_opmode == IEEE80211_M_STA)
#endif
                               || (osifp->os_if->iv_ic->ic_roaming != IEEE80211_ROAMING_MANUAL)
                               || (osifp->os_if->iv_mlmeconnect))) {
#else
    if (IS_RUNNING(parent)) {

#endif
        osifp->os_if->iv_mlmeconnect=0;
        opmode = wlan_vap_get_opmode(vap);
        if (opmode == IEEE80211_M_STA ||
            osifp->os_opmode == IEEE80211_M_P2P_CLIENT) {
            ieee80211_ssid ssid;
            int desired_bssid = 0;

            ssid.len=0;
            wlan_get_desired_ssidlist(vap,&ssid,1);
            desired_bssid = wlan_aplist_get_desired_bssid_count(vap);
            /* check if there is only one desired bssid and it is broadcast , ignore the setting if it is */
            if (desired_bssid == 1) {
                u_int8_t des_bssid[IEEE80211_ADDR_LEN];
                wlan_aplist_get_desired_bssidlist(vap, &des_bssid);
                if (IEEE80211_IS_BROADCAST(des_bssid)) {
                    desired_bssid=0;
                }
            }
            if ((desired_bssid || ssid.len) && osifp->sm_handle) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: desired bssid %d ssid len %d \n",__func__,
                              desired_bssid, ssid.len);
                if (forcescan) {
                    osifp->is_restart = 1;
                }
                else {
                    if (wlan_get_param(vap, IEEE80211_FEATURE_WDS)) {
                        /* Disable bgscan  for WDS STATION */
                        wlan_connection_sm_set_param(osifp->sm_handle,
                                                     WLAN_CONNECTION_PARAM_BGSCAN_POLICY,
                                                     WLAN_CONNECTION_BGSCAN_POLICY_NONE);
                        /* Set the connect timeout as infinite for WDS STA*/
                        wlan_connection_sm_set_param(osifp->sm_handle,
                                                     WLAN_CONNECTION_PARAM_CONNECT_TIMEOUT,10);
                        /* Set the connect timeout as infinite for WDS STA*/
                        wlan_connection_sm_set_param(osifp->sm_handle,
                                                     WLAN_CONNECTION_PARAM_RECONNECT_TIMEOUT,10);
                        /*
                         * Bad AP Timeout value should be specified in ms
                         * so converting seconds to ms
                         */
                        /* Set BAD AP timeout to 0 for linux repeater config
                         * as AUTH_AUTO mode in WEP needs connection SM to alternate AUTH mode
                         * from open to shared continously for reconnection
                         */
                        wlan_connection_sm_set_param(osifp->sm_handle,
                                                     WLAN_CONNECTION_PARAM_BAD_AP_TIMEOUT, 0);
                        wlan_aplist_set_bad_ap_timeout(vap, 0);
                    }
                }

                /*If in TXCHANSWITCH then do not send a stop */
                if(wlan_connection_sm_get_param(osifp->sm_handle, WLAN_CONNECTION_PARAM_CURRENT_STATE) == WLAN_ASSOC_STATE_TXCHANSWITCH) {
                    schedule_timeout_interruptible(OSIF_DISCONNECT_TIMEOUT); /* atleast wait for one iteration */
                    waitcnt = 0;
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                                        "%s: Tx ChanSwitch is happening\n", __func__);
                    while(waitcnt < OSIF_TXCHANSWITCH_LOOPCOUNT) {
                        schedule_timeout_interruptible(OSIF_DISCONNECT_TIMEOUT);
                        waitcnt++;
                    }
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                                        "%s: Tx ChanSwitch is Completed\n", __func__);
                }

                /* stop if it is running */
                if (wlan_connection_sm_stop(osifp->sm_handle, IEEE80211_CONNECTION_SM_STOP_ASYNC ) == 0) {
                    waitcnt = 0;
                    schedule_timeout_interruptible(OSIF_DISCONNECT_TIMEOUT); /* atleast wait for one iteration */
                    while(osifp->is_up && waitcnt < OSIF_MAX_CONNECTION_STOP_TIMEOUT) {
                        schedule_timeout_interruptible(OSIF_DISCONNECT_TIMEOUT);
                        waitcnt++;
                    }
                    if (osifp->is_up) {
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                                          "%s : wait for connection SM stop failed \n",
                                          __func__);
                    } else {
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                                          "%s : wakeup from wait for connection SM to stop \n",
                                          __func__);
                    }
                }
                if (osifp->authmode == IEEE80211_AUTH_AUTO) {
                    /* If the auth mode is set to AUTO, set the auth mode
                     * to SHARED for first connection try */
                    ieee80211_auth_mode modes[1];
                    u_int nmodes=1;
                    modes[0] = IEEE80211_AUTH_SHARED;
                    wlan_set_authmodes(vap,modes,nmodes);
                }
                do {
                    error = wlan_connection_sm_start(osifp->sm_handle);
                    if (!error) {
                        break;
                    }
                    if (error == -EINPROGRESS) {
                        /* wait for 2 secs for connection to be stopped completely */
                        waitcnt = 0;
                        while(waitcnt < 40) {
                            schedule_timeout_interruptible(OSIF_CONNECTION_TIMEOUT);
                            waitcnt++;
                        }
                    }
                    else {
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "Error %s : sm start failed\n",
                                          __func__);
                        return -EINVAL;
                    }
                } while (connection_attempt++ < OSIF_MAX_CONNECTION_ATTEMPT);
                if (error) {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "Error %s : all sm start attempt failed\n",
                                      __func__);
                    return -EINVAL;
                }


            }
            else {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE,
                                  "Did not start connection SM : num desired_bssid %d ssid len %d \n",
                                  desired_bssid, ssid.len);
            }
            /*
             * TBD: Try to be intelligent about clocking the state
             * machine.  If we're currently in RUN state then
             * we should be able to apply any new state/parameters
             * simply by re-associating.  Otherwise we need to
             * re-scan to select an appropriate ap.
             */
#if UMAC_SUPPORT_IBSS
        } else if (opmode == IEEE80211_M_IBSS) {
            osif_ibss_init(dev);
#endif
        } else if (opmode == IEEE80211_M_MONITOR) {
            wlan_mlme_start_monitor(vap);
        } else {
            enum ieee80211_phymode des_mode = wlan_get_desired_phymode(vap);
            ieee80211_ssid ssid;
            waitcnt = 0;

            ssid.len=0;
            wlan_get_desired_ssidlist(vap,&ssid,1);
            if (ssid.len == 0) {
                /* do not start AP if no ssid is set */
                return 0;
            }
            /*
             * TBD: Assuming AP mode. No monitor mode support yet
             */

            /* If ACS is in progress, unregister scan handlers in ACS */
            if(osifp->osif_is_mode_offload) {

                osif_vap_acs_cancel(dev, 0);

                if (wlan_scan_in_progress(vap)) {
                    QDF_PRINT_INFO(comhandle->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Scan in progress.. Cancelling it. vap: 0x%p \n", __func__, vap);
                    wlan_scan_cancel(vap, osifp->scan_requestor,
                                IEEE80211_VAP_SCAN, true);
#if BEELINER_HOST_FPGA_FLAG
                    OS_DELAY (2000);
#else
                    OS_DELAY (1000);
#endif
                    /* we know a scan was interrupted because we're stopping
                     * the VAP. This may lead to an invalid channel pointer.
                     * Thus, initialise it with the default channel information
                     * from the ic to prevent a crash in
                     * ieee80211_init_node_rates() during bss reset.
                     */
                   if (vap->iv_bsschan == IEEE80211_CHAN_ANYC) {
                       QDF_PRINT_INFO(comhandle->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "Info: overwriting invalid BSS channel"
                           "info by defaults (%p)\n", vap->iv_ic->ic_curchan);
                       vap->iv_bsschan = vap->iv_ic->ic_curchan;
                   }
                }
            }
            /* Wait for previous vdev_start and vdev_stop command to complete */
            while( (osifp->is_stop_event_pending ||
                       ((qdf_atomic_read(&(vap->init_in_progress))) && (vap->iv_state_info.iv_state != IEEE80211_S_DFS_WAIT))) &&
                                                             waitcnt < OSIF_MAX_STOP_VAP_TIMEOUT_CNT) {
                schedule_timeout_interruptible(OSIF_STOP_VAP_TIMEOUT);
                waitcnt++;
                if ( osifp->is_stop_event_pending) {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : XXXXXXXX WAITING FOR prev STOP EVENT  \n",__func__);
                }
                if ((qdf_atomic_read(&(vap->init_in_progress))) && (vap->iv_state_info.iv_state != IEEE80211_S_DFS_WAIT)) {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : XXXXXXXX WAITING FOR prev START RESP EVENT \n",__func__);
                }
            }
            if (osifp->is_stop_event_pending) {
                QDF_PRINT_INFO(comhandle->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Timeout waiting for %s vap %d to stop...continuing\n", __FUNCTION__,
                        osifp->osif_is_mode_offload ? "OL" : "DA",
                        vap->iv_unit);
            }

            osifp->is_stop_event_pending = 1;
            wlan_mlme_stop_bss(vap, 0);
            /* wait for vap stop event before letting the caller go */
            waitcnt = 0;
#if QCA_LTEU_SUPPORT
            if (vap->iv_ic->ic_nl_handle) {
                while( osifp->is_stop_event_pending && waitcnt < OSIF_MAX_STOP_VAP_TIMEOUT_CNT) {
                    schedule_timeout_interruptible((CONVERT_SEC_TO_SYSTEM_TIME(1)/200) + 1);
                    waitcnt++;
                    if ( osifp->is_stop_event_pending) {
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : XXXXXXXX WAITING FOR STOP EVENT  \n",__func__);
                    }
                }
            } else {
#endif
                schedule_timeout_interruptible(OSIF_STOP_VAP_TIMEOUT);
                while( osifp->is_stop_event_pending && waitcnt < OSIF_MAX_STOP_VAP_TIMEOUT_CNT) {
                    schedule_timeout_interruptible(OSIF_STOP_VAP_TIMEOUT);
                    waitcnt++;
                    if ( osifp->is_stop_event_pending) {
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : XXXXXXXX WAITING FOR STOP EVENT  \n",__func__);
                    }
                }
                if (osifp->is_stop_event_pending) {
                    OS_DELAY(1000);
                }
#if QCA_LTEU_SUPPORT
            }
#endif

            if (osifp->is_stop_event_pending) {
                QDF_PRINT_INFO(comhandle->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Timeout waiting for %s vap %d to stop...returning\n", __FUNCTION__,
                        osifp->osif_is_mode_offload ? "OL" : "DA",
                        vap->iv_unit);
#if IEEE80211_DEBUG_NODELEAK
                QDF_PRINT_INFO(comhandle->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n%s: ########## INVOKING NODELEAK DEBUG DUMP #############\n", __func__);
                wlan_debug_dump_nodes_tgt();
#endif
                return -EINVAL;
            }

            osifp->is_stop_event_pending =0;

#ifdef QCA_PARTNER_PLATFORM
            while ( wlan_autoselect_in_progress(vap) ) {
               qdf_udelay(1000);
            }
#endif
            chan = wlan_get_current_channel(vap, false);
            if ((!chan) || (chan == IEEE80211_CHAN_ANYC)) {
                if (ieee80211_vap_ext_ifu_acs_is_set(vap)) {
                    /* If any VAP is active, the channel is already selected
                     * so go ahead and init the VAP, the same channel will be used */
                    if (ieee80211_vaps_active(vap->iv_ic)) {
                        /* Set the curent channel to the VAP */
                        wlan_chan_t sel_chan;
                        int sel_ieee_chan = 0;
                        sel_chan = wlan_get_current_channel(vap, true);
                        sel_ieee_chan = wlan_channel_ieee(sel_chan);
                        error = wlan_set_channel(vap, sel_ieee_chan, sel_chan->ic_vhtop_ch_freq_seg2);
                        if (error !=0) {
                            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACS,
                                              "%s : failed to set channel with error code %d\n",
                                              __func__, error);
                            return -EINVAL;
                        }
                    } else {
                        /* No VAPs active */
                        /* An external entity is responsible for
                           Auto Channel Selection at VAP init
                           time */
                        /* XXX - Any signalling that may be
                           required. */
                        return 0;
                    }
                } else {
                    /* start ACS module to get channel */
                    vap->iv_needs_up_on_acs = 1;
                    wlan_autoselect_register_event_handler(vap,
                        &osif_acs_event_handler, (void *)osifp);
                    wlan_autoselect_find_infra_bss_channel(vap);
                    return 0;
                }
            }
            if (((des_mode == IEEE80211_MODE_11NG_HT40PLUS) ||
                (des_mode == IEEE80211_MODE_11NG_HT40MINUS) ||
                (des_mode == IEEE80211_MODE_11NG_HT40)) &&
                (wlan_coext_enabled(vap) &&
                (osif_get_num_running_vaps(comhandle) == 0))) {
                wlan_autoselect_register_event_handler(vap,
                                                       &osif_ht40_event_handler,
                                                       (void *)osifp);
                wlan_attempt_ht40_bss(vap);
                vap->iv_needs_up_on_acs = 1;
                return 0;
            }
            if (forcescan) {
                    vap->iv_rescan = 1;
            }

            IEEE80211_VAP_LOCK(vap);
            if (wlan_scan_in_progress(vap) && (osifp->is_vap_pending == 1)) {
                /* do not start AP if there is already a pending vap_init */
                IEEE80211_VAP_UNLOCK(vap);
                return 0;
            }
            osifp->is_vap_pending = 1;
            IEEE80211_VAP_UNLOCK(vap);

            error = wlan_mlme_start_bss(vap, 0);
            if (error != 0) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s :mlme returned error %d \n", __func__, error);
                if (error == EAGAIN) {
                    /* Radio resource is busy on scanning, try later */
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s :mlme busy mostly scanning \n", __func__);
                    spin_lock_bh(&osifp->tx_lock);
                    osifp->is_up = 0;
                    spin_unlock_bh(&osifp->tx_lock);
                    return 0;
                } else if (error == EBUSY) {
                    /* resource manager is asynchronously bringing up the vap */
                    /* Wait for the connection up */
                    waitcnt = 0;
                    while((!osifp->is_up) && (waitcnt < OSIF_VAPUP_TIMEOUT_COUNT)) {
                        schedule_timeout_interruptible(OSIF_VAPUP_TICK);
                        waitcnt++;
                    }

                    if (!osifp->is_up) {
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : timed out waitinfor AP to come up \n", __func__);
                        return error;
                    }
                    error=0;
                }
                else {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : failed with error code %d\n",
                                      __func__, error);
                    return error;
                }
            } else {
                wlan_mlme_connection_up(vap);
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s :vap up \n", __func__);
                if (wlan_coext_enabled(vap))
                {
                    wlan_determine_cw(vap, vap->iv_ic->ic_curchan);
                }
            }

            /*Set default mgmt rate*/
            if(vap->iv_mgt_rate == 0){
                chan = wlan_get_des_channel(vap);
                if(IEEE80211_IS_CHAN_5GHZ(chan)){
                    vap->iv_mgt_rate = DEFAULT_LOWEST_RATE_5G;
                }else if(IEEE80211_IS_CHAN_2GHZ(chan)){
                    if (ieee80211_vap_oce_check(vap)) {
                        /* Set OCE OOB rate */
                        vap->iv_mgt_rate = OCE_OOB_RATE_2G;
                    } else {
                        vap->iv_mgt_rate = DEFAULT_LOWEST_RATE_2G;
                    }
                }
            }

            wlan_restore_vap_params(vap);

            osifp->is_up = 1;
            vap->iv_needs_up_on_acs = 1;
            osifp->is_vap_pending = 0;
        }

    }
    return 0;
#undef IS_RUNNING
}

int
osif_vap_open(struct net_device *dev)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    int err = 0;
#ifdef ATH_BUS_PM
    struct net_device *comdev = osifp->os_comdev;
    struct ath_softc_net80211 *scn = ath_netdev_priv(comdev);
#endif
    wlan_if_t vap = osifp->os_if;
    enum ieee80211_opmode opmode;
    struct ieee80211com *ic = vap->iv_ic;

#ifdef ATH_BUS_PM
    if (scn->sc_osdev->isDeviceAsleep)
	return -EPERM;
#endif /* ATH_BUS_PM */

    opmode = wlan_vap_get_opmode(vap);
#if UNIFIED_SMARTANTENNA
    if (opmode == IEEE80211_M_STA) {
        /* Initialise smart antenna with default param to help scanning */
        (vap->iv_ic)->sta_not_connected_cfg = TRUE;
    }
#endif
#ifdef QCA_PARTNER_PLATFORM
    osif_pltfrm_vap_init( dev );
#endif
    wlan_vap_up_check_beacon_interval(vap,opmode);

    if (ic->ic_need_vap_reinit) {
        wlan_if_t tmpvap;
        TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
            struct net_device *tmpvap_netdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
            osifp = (osif_dev *)wlan_vap_get_registered_handle(tmpvap);
            if ((tmpvap != vap) && IS_UP(tmpvap_netdev) && (osifp->is_up)) {
                OS_DELAY(10000);
                osif_vap_init(tmpvap_netdev, RESCAN);
            }
        }
        ic->ic_need_vap_reinit = 0;
    }

    err = osif_vap_init(dev, 0);
    return err;
}

int
osif_restart_for_config(struct ieee80211com *ic, int (*config_callback)(struct ieee80211com *ic))
{
    struct ieee80211vap *tmpvap = NULL;
    int tempretval = 0, retval = 0;

    qdf_assert_always(ic != NULL);

    TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
        struct net_device *tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
        if (IS_UP(tmpdev)) {
            tempretval = osif_vap_stop(tmpdev);
            /* If an error is seen for one of the VAPs, retain error value for
             * returning to caller. Else overwrite with latest.*/
            if (retval >= 0) {
                retval = tempretval;
            }

            OS_DELAY(OSIF_VAP_STOP_TIMEBUFF_US);
        }
    }

    if (config_callback) {
        config_callback(ic);
    }

    TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
        struct net_device *tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
        tempretval = osif_vap_open(tmpdev);
        if (retval >= 0) {
            retval = tempretval;
        }

        OS_DELAY(OSIF_VAP_OPEN_TIMEBUFF_US);
    }

    return retval;
}

int
osif_restart_vaps(struct ieee80211com *ic)
{
    struct ieee80211vap *tmpvap = NULL;
    int tempretval = 0, retval = 0;

    qdf_assert_always(ic != NULL);

    TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
        struct net_device *tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
        if (IS_UP(tmpdev)) {
            tempretval = osif_vap_stop(tmpdev);
            /* If an error is seen for one of the VAPs, retain error value for
             * returning to caller. Else overwrite with latest.*/
            if (retval >= 0) {
                retval = tempretval;
            }

            OS_DELAY(OSIF_VAP_STOP_TIMEBUFF_US);

            tempretval = osif_vap_open(tmpdev);
            if (retval >= 0) {
                retval = tempretval;
            }

            OS_DELAY(OSIF_VAP_OPEN_TIMEBUFF_US);
        }
    }

    return retval;
}

/*
* Return netdevice statistics.
*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
static struct rtnl_link_stats64*
    osif_getstats(struct net_device *dev, struct rtnl_link_stats64* stats64)
#else
static struct net_device_stats *
    osif_getstats(struct net_device *dev)
#endif
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211_stats *vapstats;
    const struct ieee80211_mac_stats *unimacstats ;
    const struct ieee80211_mac_stats *multimacstats;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
    struct net_device_stats *stats = &osifp->os_devstats;
#else
    struct rtnl_link_stats64 *stats = &osifp->os_devstats;
#endif
    if (!vap || osifp->is_delete_in_progress || (vap->iv_opmode == IEEE80211_M_MONITOR)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
        memcpy(stats64, &osifp->os_devstats, sizeof(struct rtnl_link_stats64));
#endif
        return stats64;
    }

#if QCA_PARTNER_DIRECTLINK_RX
    /* get netdevice statistics through partner API */
    if (qdf_unlikely(osifp->is_directlink)) {
	    return osif_getstats_partner(dev);
    }
#endif /* QCA_PARTNER_DIRECTLINK_RX */

    vapstats = wlan_get_stats(vap);
    unimacstats = wlan_mac_stats(vap, 0);
    multimacstats = wlan_mac_stats(vap, 1);
    stats->rx_packets = (stats_t)(unimacstats->ims_rx_packets + multimacstats->ims_rx_packets);
    stats->tx_packets = (stats_t)(unimacstats->ims_tx_packets + multimacstats->ims_tx_packets);

    /* XXX total guess as to what to count where */
    /* update according to private statistics */

    stats->tx_bytes = (stats_t)(unimacstats->ims_tx_bytes+ multimacstats->ims_tx_bytes);

    stats->tx_errors = (stats_t)(vapstats->is_tx_nodefkey
        + vapstats->is_tx_noheadroom
        + vapstats->is_crypto_enmicfail
        + vapstats->is_tx_not_ok);

    stats->tx_dropped = (stats_t)(vapstats->is_tx_nobuf
        + vapstats->is_tx_nonode
        + vapstats->is_tx_unknownmgt
        + vapstats->is_tx_badcipher
        + vapstats->is_tx_nodefkey);

    stats->rx_bytes = (stats_t)(unimacstats->ims_rx_bytes+ multimacstats->ims_rx_bytes);

    stats->rx_errors = (stats_t)(vapstats->is_rx_tooshort
            + unimacstats->ims_rx_wepfail
            + multimacstats->ims_rx_wepfail
            + vapstats->is_rx_decap
            + vapstats->is_rx_nobuf
            + unimacstats->ims_rx_decryptcrc
            + multimacstats->ims_rx_decryptcrc
            + unimacstats->ims_rx_ccmpmic
            + multimacstats->ims_rx_ccmpmic
            + unimacstats->ims_rx_tkipmic
            + multimacstats->ims_rx_tkipmic
            + unimacstats->ims_rx_tkipicv
            + multimacstats->ims_rx_tkipicv
            + unimacstats->ims_rx_wpimic
            + multimacstats->ims_rx_wpimic);

    stats->rx_crc_errors = 0;
    stats->rx_dropped = (stats_t)stats->rx_errors;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
    memcpy(stats64, stats, sizeof(struct rtnl_link_stats64));
    return stats64;
#else
    return stats;
#endif
}
EXPORT_SYMBOL(osif_getstats);

static void osif_com_vap_event_handler(void *event_arg, wlan_dev_t devhandle, os_if_t osif, ieee80211_dev_vap_event event)
{
    osif_dev  *osifp = (osif_dev *) osif;
#if UMAC_SUPPORT_ACFG
    acfg_netlink_pvt_t *acfg_nl = NULL;
    wlan_if_t vap = osifp->os_if;
#endif

    switch(event) {
    case IEEE80211_VAP_CREATED:
        break;
    case IEEE80211_VAP_DELETED:
        osifp->is_deleted=1;
#if UMAC_SUPPORT_ACFG
        acfg_nl = (acfg_netlink_pvt_t *)vap->iv_ic->ic_acfg_handle;
        if (vap == acfg_nl->vap) {
            acfg_nl->vap = NULL;
        }
#endif
        break;
    case IEEE80211_VAP_STOPPED:
       osifp->is_stop_event_pending = 0;
       break;
    case IEEE80211_VAP_STOP_ERROR:
        /* The requested STOP returned error.
         * Tasks waiting for is_stop_event_pending may not receive the Stop event.
         */
        /* TODO: handle this case in conjuction with is_stop_event_pending */
       break;
    default:
        break;
    }

}

static wlan_dev_event_handler_table com_evtable = {
    osif_com_vap_event_handler,
#if ATH_SUPPORT_SPECTRAL
    NULL,
#endif
#if UMAC_SUPPORT_ACFG
    osif_radio_evt_radar_detected_ap,           /*wlan_radar_event*/
    osif_radio_evt_watch_dog,                   /*wlan_wdt_event*/
    osif_radio_evt_dfs_cac_start,               /*wlan_cac_start_event*/
    osif_radio_evt_dfs_up_after_cac,            /*wlan_up_after_cac_event*/
    osif_radio_evt_chan_util,                   /*wlan_chan_util_event*/
#endif
};

void osif_attach(struct net_device *comdev)
{
    wlan_dev_t devhandle = ath_netdev_priv(comdev);
    wlan_device_register_event_handlers(devhandle,comdev,&com_evtable);
    wlan_autoselect_register_scantimer_handler(devhandle, osif_acs_bk_scantimer_fn , devhandle);

#ifdef QCA_PARTNER_PLATFORM
    wlan_pltfrm_attach(comdev);
#endif /* QCA_PARTNER_PLATFORM */

#if ATH_SUPPORT_WRAP
    osif_wrap_attach(devhandle);
#endif
    /* Create deferred work for obss scan */
    ATH_CREATE_WORK(&devhandle->ic_obss_scan_work, obss_scan_event, (void *)devhandle);
    ATH_CREATE_WORK(&devhandle->ic_bringup_vaps, bringup_vaps_event, (void *)devhandle);
}
EXPORT_SYMBOL(osif_attach);

void osif_detach(struct net_device *comdev)
{
    wlan_dev_t devhandle = ath_netdev_priv(comdev);
    wlan_device_unregister_event_handlers(devhandle,(void *)comdev,&com_evtable);

#ifdef QCA_PARTNER_PLATFORM
    wlan_pltfrm_detach(comdev);
#endif

#if ATH_SUPPORT_WRAP
    osif_wrap_detach(devhandle);
#endif
    qdf_destroy_work(NULL, &devhandle->ic_obss_scan_work);
    qdf_destroy_work(NULL, &devhandle->ic_bringup_vaps);
}
EXPORT_SYMBOL(osif_detach);

#if QCA_OL_VLAN_WAR
#define MAC_ADDR_CPY(a,b)       \
    do {     \
        *(uint32_t *)&a[0] = *(uint32_t *)&b[0]; \
        a[4]=b[4]; \
        a[5]=b[5]; \
    } while (0);

static int encap_eth2_to_dot3(qdf_nbuf_t msdu)
{
    u_int16_t typeorlen;
    struct ether_header eth_hdr, *eh;
    struct llc *llcHdr;
    qdf_assert(msdu != NULL);
    if (qdf_nbuf_headroom(msdu) < sizeof(*llcHdr))
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Encap: Don't have enough headroom\n");
        return 1;
    }

    eh = (struct ether_header *) qdf_nbuf_data(msdu);

    /*
     * Save addresses to be inserted later
     */
    MAC_ADDR_CPY(eth_hdr.ether_dhost, eh->ether_dhost);
    MAC_ADDR_CPY(eth_hdr.ether_shost, eh->ether_shost);
     /*** NOTE: REQUIRES NTOHS IF REFERENCED ***/
    typeorlen = eh->ether_type;

    /*
     * Make room for LLC + SNAP headers
     */
    if (qdf_nbuf_push_head(msdu, sizeof(*llcHdr)) == NULL){
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Encap: Failed to push LLC header\n");
        return 1;
    }

    eh = (struct ether_header *) qdf_nbuf_data(msdu);

    MAC_ADDR_CPY(eh->ether_dhost, eth_hdr.ether_dhost);
    MAC_ADDR_CPY(eh->ether_shost, eth_hdr.ether_shost);
    eh->ether_type = htons((uint16_t) (msdu->len - sizeof(eth_hdr)));

    llcHdr = (struct llc *)((u_int8_t *)eh + sizeof(eth_hdr));
    llcHdr->llc_dsap                     = LLC_SNAP_LSAP;
    llcHdr->llc_ssap                     = LLC_SNAP_LSAP;
    llcHdr->llc_un.type_snap.control     = LLC_UI;
    llcHdr->llc_un.type_snap.org_code[0] = RFC1042_SNAP_ORGCODE_0;
    llcHdr->llc_un.type_snap.org_code[1] = RFC1042_SNAP_ORGCODE_1;
    llcHdr->llc_un.type_snap.org_code[2] = RFC1042_SNAP_ORGCODE_2;
    llcHdr->llc_un.type_snap.ether_type  = typeorlen;
    return 0;
}
#endif

int
osif_vap_hardstart_generic(struct sk_buff *skb, struct net_device *dev)
{
    osif_dev  *osdev = ath_netdev_priv(dev);
    wlan_if_t vap = osdev->os_if;
    struct net_device *comdev = osdev->os_comdev;
    //struct ieee80211_cb *cb;
    struct ether_header *eh = (struct ether_header *)skb->data;
    int send_err=0;

#if QCA_OL_VLAN_WAR
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(comdev);
#endif /* QCA_OL_VLAN_WAR */
    qdf_nbuf_count_inc(skb);
    spin_lock(&osdev->tx_lock);
    if (!osdev->is_up) {
        goto bad;
    }

    /* NB: parent must be up and running */
    if ((comdev->flags & (IFF_RUNNING|IFF_UP)) != (IFF_RUNNING|IFF_UP) ||
        (!ieee80211_vap_ready_is_set(vap)) ||
        (IEEE80211_IS_CHAN_RADAR(vap->iv_bsschan))) {
        goto bad;
    }


#ifdef ATH_SUPPORT_HTC
    /*In some STA platforms like PB44-small-xx, skb_unshare will introduce
          extra copies if there is no need to reallocate headroom. By skipping the
          skb_unshare, we can reduce 3~5% CPU utilization on pb44-usb(300MHz)
          for Newma. However, we already verified this won't happen in every platform.
          It depends on how the upper layer allocate skb_headroom. In the repeater mode
          we should enable check for multicast packets, to avoid modifing shared packets*/
    if((vap->iv_opmode != IEEE80211_M_STA) ||
       IEEE80211_IS_MULTICAST(eh->ether_dhost))
    {
        skb =  qdf_nbuf_unshare(skb);
        if (skb == NULL) {
            goto bad;
        }
    }

#else
    skb =  qdf_nbuf_unshare(skb);
    if (skb == NULL) {
        goto bad;
    }
#endif /* ATH_SUPPORT_HTC */
#if DBDC_REPEATER_SUPPORT
    if (dbdc_tx_process(vap,&osdev,skb)) {
        spin_unlock(&osdev->tx_lock);
        return 0;
    }
#endif
    /* Raw mode or native wifi mode not
     * supported in qwrap , revisit later
     */
    DA_WRAP_TX_PROCESS(&osdev,vap,&skb);

#ifdef ATH_EXT_AP
    if (qdf_unlikely(IEEE80211_VAP_IS_EXT_AP_ENABLED(vap))) {
        if (vap->iv_opmode == IEEE80211_M_STA) {
            eh = (struct ether_header *)skb->data;
            if (ieee80211_extap_output(vap, eh)) {
                goto bad;
            }
        } else {
#ifdef EXTAP_DEBUG
            extern char *arps[];
            eth_arphdr_t *arp = (eth_arphdr_t *)(eh + 1);
            if(eh->ether_type == ETHERTYPE_ARP) {
                QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\tOuT %s\t" eaistr "\t" eamstr "\t" eaistr "\t" eamstr "\n"
                        "\ts: " eamstr "\td: " eamstr "\n",
                      arps[arp->ar_op],
                      eaip(arp->ar_sip), eamac(arp->ar_sha),
                      eaip(arp->ar_tip), eamac(arp->ar_tha),
                      eamac(eh->ether_shost), eamac(eh->ether_dhost));
            }
#endif
        }
    }
#endif /* ATH_EXT_AP */

    if (skb_headroom(skb) < dev->hard_header_len + dev->needed_headroom) {
        struct sk_buff *tmp = skb;

#ifdef ATH_SUPPORT_HTC
        if((vap->iv_opmode == IEEE80211_M_STA) &&
           (!IEEE80211_IS_MULTICAST(eh->ether_dhost))) {
            skb =  qdf_nbuf_unshare(skb);
            if (skb == NULL) {
                goto bad;
            }
            tmp = skb;
        }
#endif /* ATH_SUPPORT_HTC */

        skb = skb_realloc_headroom(tmp, dev->hard_header_len + dev->needed_headroom);
        qdf_nbuf_free(tmp);

        if (skb == NULL) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_OUTPUT,
                "%s: cannot expand skb\n", __func__);
            goto bad;
        }
    }

    /*
    * Find the node for the destination so we can do
    * things like power save.
    */
    eh = (struct ether_header *)skb->data;

#if ADF_SUPPORT
    N_FLAG_KEEP_ONLY(skb, N_PWR_SAV);
#else
    M_FLAG_KEEP_ONLY(skb, M_PWR_SAV);
#endif
#if UMAC_SUPPORT_WNM
    if (wlan_wnm_tfs_filter(vap, (wbuf_t) skb)) {
        goto bad;
    }
#endif
#ifdef ATH_SUPPORT_HTC
    /*
     * In power save mode, tx pkt will send wmi command to wake up.
     * Tasklet can't schedule while waiting wmi response to release mutex.
     * Defer to tx thread when power save is on.
     */
    if ((wlan_get_powersave(vap) != IEEE80211_PWRSAVE_NONE) ||
        (vap->iv_txrx_event_info.iv_txrx_event_filter & IEEE80211_VAP_OUTPUT_EVENT_DATA)) {
        if (ath_put_txbuf(skb))
            goto bad;
    }
    else
#endif
    {
        if (osdev->osif_is_mode_offload) {
#if ATH_PERF_PWR_OFFLOAD
            u_int8_t bssid[IEEE80211_ADDR_LEN];
            /*
             * Zero out the cb part of the sk_buff, so it can be used
             * by the driver.
             */
            memset(skb->cb, 0x0, sizeof(skb->cb));
            /* SW encapsulation */
            wlan_vap_get_bssid(vap, bssid);

#if QCA_OL_VLAN_WAR
	    if(OL_TX_VLAN_WAR(&skb, scn))
		goto bad;
#endif
        {
            /*
             * DMA mapping is done within the OS shim prior to sending
             * the frame to the driver.
             */
            qdf_nbuf_map_single(
                vap->iv_ic->ic_qdf_dev, (qdf_nbuf_t) skb, QDF_DMA_TO_DEVICE);
            /* terminate the (single-element) list of tx frames */
            skb->next = NULL;

            skb = osdev->iv_vap_send(osdev->iv_txrx_handle, skb);
        }
            /*
             * Check whether all tx frames were accepted by the txrx stack.
             * If the txrx stack cannot accept all the provided tx frames,
             * it will return a linked list of tx frames it couldn't handle.
             * Drop these overflowed tx frames.
             */
            while (skb) {
                struct sk_buff *next = skb->next;
                qdf_nbuf_unmap_single(
                    vap->iv_ic->ic_qdf_dev, (qdf_nbuf_t) skb, QDF_DMA_TO_DEVICE);
                qdf_nbuf_free(skb);
                skb = next;
            }
#endif /* ATH_PERF_PWR_OFFLOAD */
            send_err = 0;
        } else {
#if UMAC_SUPPORT_PROXY_ARP
            if (do_proxy_arp(vap, skb))
                goto bad;
#endif /* UMAC_SUPPORT_PROXY_ARP */
            send_err = vap->iv_vap_send(vap, (wbuf_t)skb);
        }
    }
#if ATH_SUPPORT_FLOWMAC_MODULE
    if (send_err == -ENOBUFS && vap->iv_flowmac) {
        /* pause the Ethernet and the queues as well */
        if (!((struct ieee80211vap*)vap)->iv_dev_stopped) {
            if (((struct ieee80211vap*)vap)->iv_evtable->wlan_pause_queue) {
                ((struct ieee80211vap*)vap)->iv_evtable->wlan_pause_queue(
                                               vap->iv_ifp, 1, vap->iv_flowmac);
                ((struct ieee80211vap*)vap)->iv_dev_stopped = 1;
            }
        }
    }
#endif
    spin_unlock(&osdev->tx_lock);

    return 0;

bad:
    if (vap) {
        vap->iv_stats.is_tx_nobuf++;
    }
    spin_unlock(&osdev->tx_lock);
    if (skb != NULL)
        qdf_nbuf_free(skb);
    return 0;
}
EXPORT_SYMBOL(osif_vap_hardstart_generic);

#if MESH_MODE_SUPPORT
void
os_if_tx_free_batch_ext(struct sk_buff *bufs, int tx_err)
{
    while (bufs) {
        struct sk_buff *next = bufs->next;
        if (external_tx_complete != NULL) {
            external_tx_complete(bufs);
        } else {
            qdf_nbuf_free(bufs);
        }
        bufs = next;
    }
}

void
os_if_tx_free_ext(struct sk_buff *skb)
{
    if (external_tx_complete != NULL) {
        qdf_nbuf_count_dec(skb);
        external_tx_complete(skb);
    } else {
        qdf_nbuf_free(skb);
    }
}
EXPORT_SYMBOL(os_if_tx_free_ext);
#endif

/*
* Convert a media specification to an 802.11 phy mode.
*/
static int
media2mode(const struct ifmedia_entry *ime, enum ieee80211_phymode *mode)
{

    switch (IFM_MODE(ime->ifm_media)) {
    case IFM_IEEE80211_11A:
        *mode = IEEE80211_MODE_11A;
        break;
    case IFM_IEEE80211_11B:
        *mode = IEEE80211_MODE_11B;
        break;
    case IFM_IEEE80211_11G:
        *mode = IEEE80211_MODE_11G;
        break;
    case IFM_IEEE80211_FH:
        *mode = IEEE80211_MODE_FH;
        break;
        case IFM_IEEE80211_11NA:
                *mode = IEEE80211_MODE_11NA_HT20;
                break;
        case IFM_IEEE80211_11NG:
                *mode = IEEE80211_MODE_11NG_HT20;
                break;
    case IFM_AUTO:
        *mode = IEEE80211_MODE_AUTO;
        break;
    default:
        return 0;
    }

    if (ime->ifm_media & IFM_IEEE80211_HT40PLUS) {
            if (*mode == IEEE80211_MODE_11NA_HT20)
                    *mode = IEEE80211_MODE_11NA_HT40PLUS;
            else if (*mode == IEEE80211_MODE_11NG_HT20)
                    *mode = IEEE80211_MODE_11NG_HT40PLUS;
            else
                    return 0;
    }

    if (ime->ifm_media & IFM_IEEE80211_HT40MINUS) {
            if (*mode == IEEE80211_MODE_11NA_HT20)
                    *mode = IEEE80211_MODE_11NA_HT40MINUS;
            else if (*mode == IEEE80211_MODE_11NG_HT20)
                    *mode = IEEE80211_MODE_11NG_HT40MINUS;
            else
                    return 0;
    }

    return 1;
}

/*
 * convert IEEE80211 ratecode to ifmedia subtype.
 */
static int
rate2media(struct ieee80211vap *vap,int rate,enum ieee80211_phymode mode)
{
#define N(a)    (sizeof(a) / sizeof(a[0]))
    struct ieee80211com    *ic = wlan_vap_get_devhandle(vap);
    static const struct
    {
        u_int   m;      /* rate + mode */
        u_int   r;      /* if_media rate */
    } rates[] = {
                {   0x1b | IFM_IEEE80211_FH, IFM_IEEE80211_FH1 },
                {   0x1a | IFM_IEEE80211_FH, IFM_IEEE80211_FH2 },
                {   0x1b | IFM_IEEE80211_11B, IFM_IEEE80211_DS1 },
                {   0x1a | IFM_IEEE80211_11B, IFM_IEEE80211_DS2 },
                {   0x19 | IFM_IEEE80211_11B, IFM_IEEE80211_DS5 },
                {   0x18 | IFM_IEEE80211_11B, IFM_IEEE80211_DS11 },
                {   0x1a | IFM_IEEE80211_11A, IFM_IEEE80211_OFDM2_25 },
                {   0x0b | IFM_IEEE80211_11A, IFM_IEEE80211_OFDM6 },
                {   0x0f | IFM_IEEE80211_11A, IFM_IEEE80211_OFDM9 },
                {   0x0a | IFM_IEEE80211_11A, IFM_IEEE80211_OFDM12 },
                {   0x0e | IFM_IEEE80211_11A, IFM_IEEE80211_OFDM18 },
                {   0x09 | IFM_IEEE80211_11A, IFM_IEEE80211_OFDM24 },
                {   0x0d | IFM_IEEE80211_11A, IFM_IEEE80211_OFDM36 },
                {   0x08 | IFM_IEEE80211_11A, IFM_IEEE80211_OFDM48 },
                {   0x0c | IFM_IEEE80211_11A, IFM_IEEE80211_OFDM54 },
                {   0x1b | IFM_IEEE80211_11G, IFM_IEEE80211_DS1 },
                {   0x1a | IFM_IEEE80211_11G, IFM_IEEE80211_DS2 },
                {   0x19 | IFM_IEEE80211_11G, IFM_IEEE80211_DS5 },
                {   0x18 | IFM_IEEE80211_11G, IFM_IEEE80211_DS11 },
                {   0x0b | IFM_IEEE80211_11G, IFM_IEEE80211_OFDM6 },
                {   0x0f | IFM_IEEE80211_11G, IFM_IEEE80211_OFDM9 },
                {   0x0a | IFM_IEEE80211_11G, IFM_IEEE80211_OFDM12 },
                {   0x0e | IFM_IEEE80211_11G, IFM_IEEE80211_OFDM18 },
                {   0x09 | IFM_IEEE80211_11G, IFM_IEEE80211_OFDM24 },
                {   0x0d | IFM_IEEE80211_11G, IFM_IEEE80211_OFDM36 },
                {   0x08 | IFM_IEEE80211_11G, IFM_IEEE80211_OFDM48 },
                {   0x0c | IFM_IEEE80211_11G, IFM_IEEE80211_OFDM54 },
                /* NB: OFDM72 doesn't realy exist so we don't handle it */
        };
    u_int mask, i, phytype;

    mask = rate & IEEE80211_RATE_VAL;
    switch (mode)
    {
    case IEEE80211_MODE_11A:
    case IEEE80211_MODE_TURBO_A:
    case IEEE80211_MODE_11NA_HT20:
    case IEEE80211_MODE_11NA_HT40MINUS:
    case IEEE80211_MODE_11NA_HT40PLUS:
    case IEEE80211_MODE_11NA_HT40:
    case IEEE80211_MODE_11AC_VHT20:
    case IEEE80211_MODE_11AC_VHT40PLUS:
    case IEEE80211_MODE_11AC_VHT40MINUS:
    case IEEE80211_MODE_11AC_VHT40:
    case IEEE80211_MODE_11AC_VHT80:
    case IEEE80211_MODE_11AC_VHT160:
    case IEEE80211_MODE_11AC_VHT80_80:
        mask |= IFM_IEEE80211_11A;
        break;
    case IEEE80211_MODE_11B:
        mask |= IFM_IEEE80211_11B;
        break;
    case IEEE80211_MODE_FH:
        mask |= IFM_IEEE80211_FH;
        break;
    case IEEE80211_MODE_AUTO:
        phytype = wlan_get_current_phytype(ic);

        if (phytype == IEEE80211_T_FH)
        {
            mask |= IFM_IEEE80211_FH;
            break;
        }
        /* NB: hack, 11g matches both 11b+11a rates */
        /* fall thru... */
    case IEEE80211_MODE_11G:
    case IEEE80211_MODE_TURBO_G:
    case IEEE80211_MODE_11NG_HT20:
    case IEEE80211_MODE_11NG_HT40MINUS:
    case IEEE80211_MODE_11NG_HT40PLUS:
    case IEEE80211_MODE_11NG_HT40:
        mask |= IFM_IEEE80211_11G;
        break;
    }
    for (i = 0; i < N(rates); i++) {
        if (rates[i].m == mask) {
            return rates[i].r;
     }
    }
    return IFM_AUTO;
#undef N
}


static int
osif_media_change(struct net_device *dev)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    enum ieee80211_phymode newphymode;
    struct ifmedia_entry *ime = osifp->os_media.ifm_cur;

    /*
    * First, identify the phy mode.
    */
    if (!media2mode(ime, &newphymode))
        return EINVAL;
    if (newphymode != wlan_get_desired_phymode(vap)) {
        return wlan_set_desired_phymode(vap,newphymode);
    }
    return 0;
}

static const u_int mopts[] = {
        IFM_AUTO,
        IFM_IEEE80211_11A,
        IFM_IEEE80211_11B,
        IFM_IEEE80211_11G,
        IFM_IEEE80211_FH,
        IFM_IEEE80211_11A | IFM_IEEE80211_TURBO,
        IFM_IEEE80211_11G | IFM_IEEE80211_TURBO,
        IFM_IEEE80211_11NA,
        IFM_IEEE80211_11NG,
        IFM_IEEE80211_11NA | IFM_IEEE80211_HT40PLUS,
        IFM_IEEE80211_11NA | IFM_IEEE80211_HT40MINUS,
        IFM_IEEE80211_11NG | IFM_IEEE80211_HT40PLUS,
        IFM_IEEE80211_11NG | IFM_IEEE80211_HT40MINUS,
        0,
        0,
        IFM_IEEE80211_11AC,
        IFM_IEEE80211_11AC | IFM_IEEE80211_VHT40PLUS,
        IFM_IEEE80211_11AC | IFM_IEEE80211_VHT40MINUS,
        0,
        IFM_IEEE80211_11AC | IFM_IEEE80211_VHT80,
        IFM_IEEE80211_11AC | IFM_IEEE80211_VHT160,
        IFM_IEEE80211_11AC | IFM_IEEE80211_VHT80_80
};

/*
* Common code to calculate the media status word
* from the operating mode and channel state.
*/
static int
media_status(enum ieee80211_opmode opmode, wlan_chan_t chan)
{
    int status;
    enum ieee80211_phymode mode = IEEE80211_MODE_AUTO;    /* autoselect */

    status = IFM_IEEE80211;
    switch (opmode) {
    case IEEE80211_M_STA:
        break;
    case IEEE80211_M_IBSS:
        status |= IFM_IEEE80211_ADHOC;
        break;
    case IEEE80211_M_HOSTAP:
    case IEEE80211_M_P2P_GO:
        status |= IFM_IEEE80211_HOSTAP;
        break;
    case IEEE80211_M_MONITOR:
        status |= IFM_IEEE80211_MONITOR;
        break;
    case IEEE80211_M_AHDEMO:
    case IEEE80211_M_WDS:
        /* should not come here */
        break;
    default:
        break;
    }
    if (chan) {
        mode = wlan_channel_phymode(chan);
    }
    if (mode >= 0 && mode < (sizeof(mopts)/sizeof(mopts[0])) ) {
        status |= mopts[mode];
    }

    /* XXX else complain? */

    return status;
}

static void
osif_media_status(struct net_device *dev, struct ifmediareq *imr)
{

    int rate;
    osif_dev  *osdev = ath_netdev_priv(dev);
    wlan_if_t vap = osdev->os_if;
    wlan_chan_t chan;
    enum ieee80211_phymode mode;

    imr->ifm_status = IFM_AVALID;
    if ((dev->flags & IFF_UP))
        imr->ifm_status |= IFM_ACTIVE;
    chan = wlan_get_current_channel(vap,true);
    if (chan != (wlan_chan_t)0 && chan != (wlan_chan_t)-1) {
        imr->ifm_active = media_status(osdev->os_opmode, chan);
    }

    if(wlan_is_connected(vap)) {
         mode = wlan_get_bss_phymode(vap);
    }
    else {
         mode = IEEE80211_MODE_AUTO;
    }

    rate = wlan_get_param(vap, IEEE80211_FIXED_RATE);
    if (rate != IEEE80211_FIXED_RATE_NONE)
    {
        /*
        * A fixed rate is set, report that.
        */
        imr->ifm_active &= ~IFM_TMASK;
        if ( rate & 0x80) {
            imr->ifm_active |= IFM_IEEE80211_HT_MCS;
        }
        else {
            imr->ifm_active |= rate2media(vap,rate,mode);
        }
    }
    else {
        imr->ifm_active |= IFM_AUTO;
    }
    imr->ifm_current = imr->ifm_active;
}


static int os_if_media_init(osif_dev *osdev)
{
    wlan_if_t vap;
    int i,mopt;
    u_int16_t nmodes;
    enum ieee80211_phymode modes[IEEE80211_MODE_MAX];
    struct ifmedia *media = &osdev->os_media;
    struct ifmediareq imr;
    ifmedia_init(media, 0, osif_media_change, osif_media_status);

    vap = osdev->os_if;
    if (wlan_get_supported_phymodes(osdev->os_devhandle,modes,
                                    &nmodes,IEEE80211_MODE_MAX) != 0 ) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : get_supported_phymodes failed \n", __func__);
        return -EINVAL;
    }
    for (i=0;i<nmodes;++i) {
        mopt = mopts[(u_int32_t)modes[i]];
        IEEE80211_ADD_MEDIA(media, IFM_AUTO, mopt); /* e.g. 11a auto */
        IEEE80211_ADD_MEDIA(media, IFM_AUTO, mopt | IFM_IEEE80211_ADHOC);
        IEEE80211_ADD_MEDIA(media, IFM_AUTO, mopt | IFM_IEEE80211_HOSTAP);
        IEEE80211_ADD_MEDIA(media, IFM_AUTO, mopt | IFM_IEEE80211_ADHOC | IFM_FLAG0);
        IEEE80211_ADD_MEDIA(media, IFM_AUTO, mopt | IFM_IEEE80211_MONITOR);
    }

    osif_media_status(osdev->netdev, &imr);
    ifmedia_set(media, imr.ifm_active);
    return 0;
}

int osif_vap_stop(struct net_device *dev)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    int waitcnt;
    int error = 0;
    u_int32_t is_up = osifp->is_up;
    int i;
	struct ieee80211com *ic = NULL;
    union iwreq_data wreq;

    enum ieee80211_opmode opmode;
    wlan_dev_t  comhandle;
    u_int32_t numvaps;
    struct net_device *comdev;
    comdev = osifp->os_comdev;

    if (!vap) {
       return 0;
    }
    ic = vap->iv_ic;
#ifdef QCA_PARTNER_PLATFORM
    osif_pltfrm_vap_stop( osifp );
#endif
    /* Wait for vdev_start and vdev_up to be processed before vdev_stop
     * for correct initialization of channel structures in the firmware.
     */
    i = 0;
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
    while (qdf_atomic_read(&(vap->init_in_progress)) && ((vap->iv_state_info.iv_state != IEEE80211_S_DFS_WAIT) && !mlme_is_stacac_running(vap)))
#else
    while (qdf_atomic_read(&(vap->init_in_progress)) && (vap->iv_state_info.iv_state != IEEE80211_S_DFS_WAIT))
#endif
    {
        msleep(10);
        if (i > 20) {
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:Timeout for VAP start response event\n", __func__);
            break;
        }
        i++;
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "vap%d: Init in progress. Delay vap_stop\n", vap->iv_unit);
    }

    /* If ACS is in progress, unregister scan handlers in ACS */
    osif_vap_acs_cancel(dev, 0);

#if UNIFIED_SMARTANTENNA
    (vap->iv_ic)->vap_down_in_progress = TRUE;
#endif
    if (wlan_scan_in_progress(vap)) {
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Scan in progress.. Cancelling it. vap: 0x%p \n", __func__, vap);
        wlan_scan_cancel(vap, osifp->scan_requestor, IEEE80211_VAP_SCAN, true);
#if BEELINER_HOST_FPGA_FLAG
        OS_DELAY (2000);
#else
        OS_DELAY (1000);
#endif
        /* we know a scan was interrupted because we're stopping the VAP
         * This may lead to an invalid channel pointer.
         * Thus, initialise it with the default channel information from the ic
         * to prevent a crash in ieee80211_init_node_rates() during bss reset.
         */
        if (vap->iv_bsschan == IEEE80211_CHAN_ANYC) {
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "Info: overwriting invalid BSS channel info by defaults (%p)\n",
                                                                            vap->iv_ic->ic_curchan);
            vap->iv_bsschan = vap->iv_ic->ic_curchan;
        }
    }

    opmode = wlan_vap_get_opmode(vap);

    switch(opmode) {
    case IEEE80211_M_STA:
    case IEEE80211_M_P2P_CLIENT:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : stopping %s vap \n",__func__, opmode==IEEE80211_M_STA?"STA":"P2P client");
        if (!osifp->sm_handle) {
            osif_vap_down(dev);
        } else {
            u_int32_t flags;
            if (!vap->auto_assoc)
            {
                ieee80211_ssid   tmpssid;
                u_int8_t des_bssid[IEEE80211_ADDR_LEN];

                /* reset desired ssid */
                tmpssid.ssid[0] = '\0';
                tmpssid.len = 0;
                wlan_set_desired_ssidlist(vap,1,&tmpssid);

                /* To reset desired bssid after vap stop.
                   Otherwise, after interface down and up, it will try to unexpectedly connect to the previous AP. */
                memset(des_bssid, 0xff, IEEE80211_ADDR_LEN);
                wlan_aplist_set_desired_bssidlist(vap, 1, &des_bssid);
            }
            /* vap down will be called asynchronously */
            flags = IEEE80211_CONNECTION_SM_STOP_ASYNC;
            if (osifp->no_stop_disassoc)
                flags |= IEEE80211_CONNECTION_SM_STOP_NO_DISASSOC;
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
            if(IEEE80211_M_STA == opmode) {
                wlan_mlme_stacac_restore_defaults(vap);
            }
#endif
            if (wlan_connection_sm_stop(osifp->sm_handle, flags) == 0) {
                waitcnt = 0;
                while((is_up ? osifp->is_up : 1) && waitcnt < 60) {
                    schedule_timeout_interruptible(OSIF_CONNECTION_TIMEOUT);
                    waitcnt++;
                }
                if (osifp->is_up) {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : connection stop failed \n",
                                    __func__);
                    error = -EBUSY;
                }
            }
            /* if vap is not down force it down */
            if (osifp->is_up) {
                osif_vap_down(dev);
            }
        }
        break;
#if UMAC_SUPPORT_IBSS
    case IEEE80211_M_IBSS:
        if (!osifp->sm_ibss_handle) {
            osif_vap_down(dev);
        } else {
            /* vap down will be called asynchronously */
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : stopping IBSS vap \n",
                                      __func__);
            if (wlan_ibss_sm_stop(osifp->sm_ibss_handle, IEEE80211_IBSS_SM_STOP_ASYNC) == 0) {

                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : IBSS stop failed \n",
                                      __func__);

            } else {
               osif_vap_down(dev);
            }
        }
        break;
#endif
    case IEEE80211_M_HOSTAP:
    case IEEE80211_M_P2P_GO:
        osifp->is_vap_pending=0;
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : stopping %s vap \n",__func__, opmode==IEEE80211_M_HOSTAP?"AP":"P2P GO");
        osif_vap_down(dev);
        break;
    case IEEE80211_M_MONITOR:
        osifp->is_vap_pending=0;
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : stopping monitor vap \n", __func__);
        osif_vap_down(dev);
        break;
    default:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : mode not suported \n",__func__);
        break;
    }

#if UNIFIED_SMARTANTENNA
    if (opmode == IEEE80211_M_STA){
        ieee80211_smart_ant_deinit(vap->iv_ic, vap, SMART_ANT_RECONFIGURE);
        ieee80211_smart_ant_init(vap->iv_ic, vap, SMART_ANT_STA_NOT_CONNECTED | SMART_ANT_RECONFIGURE);
        (vap->iv_ic)->sta_not_connected_cfg = TRUE;
    }
    (vap->iv_ic)->vap_down_in_progress = FALSE;
#endif

    wlan_vap_down_check_beacon_interval(vap,opmode);

    if (ic->ic_need_vap_reinit) {
        wlan_if_t tmpvap;
        TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
            struct net_device *tmpvap_netdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
            osifp = (osif_dev *)wlan_vap_get_registered_handle(tmpvap);
            if ((tmpvap != vap) && IS_UP(tmpvap_netdev) && (osifp->is_up)) {
                osif_vap_init(tmpvap_netdev, RESCAN);
            }
        }
        ic->ic_need_vap_reinit = 0;
    }

    comhandle = wlan_vap_get_devhandle(vap);

    if (dev->flags & IFF_RUNNING)
    {
        dev->flags &= ~IFF_RUNNING;     /* mark us stopped */

#if IEEE80211_DEBUG_NODELEAK
            QDF_PRINT_INFO( comhandle->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n\n\n####################### DUMP NODES BEGIN ################## \n");
            wlan_dump_alloc_nodes(comhandle);
            QDF_PRINT_INFO( comhandle->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "####################### DUMP NODES  END ################## \n");
#endif
        numvaps = osif_get_num_active_vaps(comhandle);
        if (numvaps == 0 && (comdev->flags & IFF_RUNNING)) {
            dev_close(comdev);
        }
    }

    /* check if other vaps need acs at this stage */
    wlan_iterate_vap_list(wlan_vap_get_devhandle(vap),
                    osif_start_acs_on_other_vaps, (void *) &vap);

    memset(&wreq, 0, sizeof(wreq));
    wreq.data.flags = IEEE80211_EV_IF_NOT_RUNNING;
    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wreq, NULL);
    return error;
}

static const u_int8_t ieee80211broadcastaddr[IEEE80211_ADDR_LEN] =
    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static int osif_setup_vap( osif_dev *osifp, enum ieee80211_opmode opmode,
                            u_int32_t flags, char *bssid)
{
    wlan_dev_t devhandle = osifp->os_devhandle;
    int error;
    wlan_if_t vap;
    ieee80211_privacy_exemption privacy_filter;
    int scan_priority_mapping_base;

    switch (opmode) {

#ifdef  ATH_SUPPORT_P2P
    case IEEE80211_M_P2P_GO:
        QDF_PRINT_INFO(devhandle->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %s: Creating NEW P2P GO interface\n", __func__);
        osifp->p2p_go_handle = wlan_p2p_GO_create((wlan_p2p_t) devhandle, NULL);
        if (osifp->p2p_go_handle == NULL) {
            return EIO;
        }
        vap=wlan_p2p_GO_get_vap_handle(osifp->p2p_go_handle);
        break;

    case IEEE80211_M_P2P_CLIENT:
        QDF_PRINT_INFO(devhandle->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %s: Creating NEW P2P Client interface\n", __func__);
        osifp->p2p_client_handle = wlan_p2p_client_create((wlan_p2p_t) devhandle, NULL);
        if (osifp->p2p_client_handle == NULL) {
            return EIO;
        }
        vap=wlan_p2p_client_get_vap_handle(osifp->p2p_client_handle);
        break;

    case IEEE80211_M_P2P_DEVICE:
        QDF_PRINT_INFO(devhandle->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %s: Creating NEW P2P Device interface\n", __func__);
        osifp->p2p_handle = wlan_p2p_create(devhandle, NULL);
        if (osifp->p2p_handle == NULL) {
            return EIO;
        }
        vap=wlan_p2p_get_vap_handle(osifp->p2p_handle);
        break;
#endif
    default:
        QDF_PRINT_INFO(devhandle->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %s: Creating NEW DEFAULT interface\n", __func__);
        if (opmode == IEEE80211_M_STA) {
            scan_priority_mapping_base = DEF_VAP_SCAN_PRI_MAP_OPMODE_STA_BASE;
        }
        else if (opmode == IEEE80211_M_IBSS) {
            scan_priority_mapping_base = DEF_VAP_SCAN_PRI_MAP_OPMODE_IBSS_BASE;
        }
        else if (opmode == IEEE80211_M_HOSTAP) {
            scan_priority_mapping_base = DEF_VAP_SCAN_PRI_MAP_OPMODE_AP_BASE;
        }
        else if (opmode == IEEE80211_M_MONITOR) {
            scan_priority_mapping_base = DEF_VAP_SCAN_PRI_MAP_OPMODE_STA_BASE;
        }
        else {
            scan_priority_mapping_base = DEF_VAP_SCAN_PRI_MAP_OPMODE_STA_BASE;
        }
        vap = wlan_vap_create(devhandle, opmode, scan_priority_mapping_base, flags, bssid, NULL, NULL);

        break;
    }

    if (!vap) {
        return ENOMEM;
    }

    osifp->os_opmode = opmode;
    osifp->os_if = vap;            /* back pointer */
    osif_vap_setup(vap, osifp->netdev, opmode);

    if (opmode == IEEE80211_M_P2P_DEVICE)
       wlan_set_desired_phymode(vap,IEEE80211_MODE_11G);
    else
       wlan_set_desired_phymode(vap, IEEE80211_MODE_AUTO);

    /* always setup a privacy filter to allow receiving unencrypted EAPOL frame */
    privacy_filter.ether_type = ETHERTYPE_PAE;
    privacy_filter.packet_type = IEEE80211_PRIVACY_FILTER_PACKET_BOTH;
    privacy_filter.filter_type = IEEE80211_PRIVACY_FILTER_KEY_UNAVAILABLE;
    wlan_set_privacy_filters(vap,&privacy_filter,1);
    do {
            ieee80211_auth_mode modes[1];
            ieee80211_cipher_type ctypes[1];
            u_int nmodes=1;

            /*
            * set default mode to OPEN.
            * default cipher set to NONE.
            */
            modes[0] = IEEE80211_AUTH_OPEN;
            error = wlan_set_authmodes(vap,modes,nmodes);

            ctypes[0] = IEEE80211_CIPHER_NONE;
            osifp->uciphers[0] = osifp->mciphers[0] = IEEE80211_CIPHER_NONE;
            osifp->u_count = osifp->m_count = 1;
            error = wlan_set_ucast_ciphers(vap,ctypes,1);
            error = wlan_set_mcast_ciphers(vap,ctypes,1);
    } while(0);

    /* register scan event handler */
    wlan_scan_register_event_handler(vap, &osif_scan_evhandler, (void*)osifp);
    wlan_scan_get_requestor_id(vap,(u_int8_t*)"osif_umac", &osifp->scan_requestor);
    wlan_scan_get_requestor_id(vap,(u_int8_t*)"offchan", &osifp->offchan_scan_requestor);

    return 0;
}

static void osif_delete_vap(struct net_device *dev, int recover)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211com *ic = vap->iv_ic;
    //wlan_dev_t comhandle = wlan_vap_get_devhandle(vap); //FIXME

#if QCA_LTEU_SUPPORT
    if (vap->iv_ic->ic_nl_handle)
        ieee80211_nl_unregister_handler(vap, osif_mu_report, osif_nl_scan_evhandler);
#endif
    STA_VAP_DOWNUP_LOCK(ic);
    if(vap == ic->ic_sta_vap)
        ic->ic_sta_vap = NULL;
    if(vap == ic->ic_mon_vap)
        ic->ic_mon_vap = NULL;
    STA_VAP_DOWNUP_UNLOCK(ic);

    GLOBAL_IC_LOCK(ic->ic_global_list);
    if (vap == ic->ic_global_list->max_priority_stavap_up) {
        ic->ic_global_list->max_priority_stavap_up = NULL;
    }
    GLOBAL_IC_UNLOCK(ic->ic_global_list);

    /* unregister scan event handler */
#if UMAC_SUPPORT_IBSS
    wlan_scan_unregister_event_handler(vap, &osif_ibss_scan_evhandler, (void *) osifp);
#endif
    wlan_scan_unregister_event_handler(vap, &osif_scan_evhandler, (void *) osifp);
    wlan_scan_clear_requestor_id(vap,osifp->scan_requestor);
    wlan_scan_clear_requestor_id(vap,osifp->offchan_scan_requestor);

    /* If ACS is in progress, unregister scan handlers in ACS */
    osif_vap_acs_cancel(dev, 0);

  #ifdef ATH_SUPPORT_HTC
    /* delay a while for timer events handled by HTCThread */
    schedule_timeout_interruptible(HTC_THREAD_DELAY);
  #endif

    if (osifp->sm_handle) {
        wlan_connection_sm_delete(osifp->sm_handle);
        osifp->sm_handle = NULL;
    }

#if UMAC_SUPPORT_IBSS
    if (osifp->sm_ibss_handle) {
        wlan_ibss_sm_delete(osifp->sm_ibss_handle);
        osifp->sm_ibss_handle = NULL;
    }
#endif

    osifp->is_deleted = 0;
    /*
    * flush the frames belonging to this vap from osdep queues.
    */
    // ath_flush_txqueue(osifp->os_devhandle, vap);
    switch( osifp->os_opmode) {
#ifdef  ATH_SUPPORT_P2P
    case IEEE80211_M_P2P_GO:
        QDF_PRINT_INFO(comhandle->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " Deleting  P2PGO vap \n");
        wlan_p2p_GO_delete(osifp->p2p_go_handle);
        osifp->p2p_go_handle = NULL;
        break;

    case IEEE80211_M_P2P_CLIENT:
        QDF_PRINT_INFO(comhandle->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " Deleting  P2P Client  \n");
        wlan_mlme_cancel(vap);
        wlan_p2p_client_delete(osifp->p2p_client_handle);
        osifp->p2p_client_handle = NULL;
        break;

    case IEEE80211_M_P2P_DEVICE:
        QDF_PRINT_INFO(comhandle->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " Deleting  P2P device  \n");
        wlan_p2p_delete(osifp->p2p_handle);
        osifp->p2p_handle = NULL;
        break;
#endif
    default:
        if (recover) {
            ic->ic_if_mgmt_drain (vap->iv_bss, 1);
            wlan_vap_recover(vap);
        } else {
            wlan_vap_delete(vap);
        }
        break;
    }
}

#if ATH_SUPPORT_SPECTRAL
int
osif_ioctl_eacs(struct net_device *dev, struct ifreq *ifr, osdev_t os_handle)
{

    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    ieee80211_scan_params scan_params;
    enum ieee80211_opmode opmode = wlan_vap_get_opmode(vap);
    ieee80211_ssid    ssid_list[IEEE80211_SCAN_MAX_SSID];
    int               n_ssid;

    if (!(dev->flags & IFF_UP)) {
        return -EINVAL;     /* XXX */
    }
    if (wlan_scan_in_progress(vap)) {
        wlan_scan_cancel(vap, osifp->scan_requestor, IEEE80211_ALL_SCANS, true);
        OS_DELAY (1000);
    }
    /* Fill scan parameter */
    n_ssid = wlan_get_desired_ssidlist(vap, ssid_list, IEEE80211_SCAN_MAX_SSID);
    OS_MEMZERO(&scan_params,sizeof(ieee80211_scan_params));
    wlan_set_default_scan_parameters(vap,&scan_params,IEEE80211_M_HOSTAP,
                                    false,true,false,true,0,NULL,0);

    switch (opmode)
    {
    case IEEE80211_M_HOSTAP:
        scan_params.type = IEEE80211_SCAN_BACKGROUND;
        scan_params.flags = IEEE80211_SCAN_PASSIVE | IEEE80211_SCAN_2GHZ;
        /* XXX tunables */
        scan_params.min_dwell_time_passive = 200;
        scan_params.max_dwell_time_passive = 300;

        break;
    default:break;
    }

    if (wlan_scan_start(vap, &scan_params, osifp->scan_requestor, IEEE80211_SCAN_PRIORITY_LOW, &(osifp->scan_id)) != 0 ) {
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Issue a scan fail.\n", __func__);
    }
    return 0;
}
EXPORT_SYMBOL(osif_ioctl_eacs);
#endif

extern int ieee80211_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd);

/*
 * ndo_ops structure for 11AC fast path
 */


#if WLAN_FEATURE_FASTPATH
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
static struct net_device_ops osif_11ac_fp_dev_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
    .ndo_get_stats64 = osif_getstats,
#else
    .ndo_get_stats = osif_getstats,
#endif
    .ndo_open = osif_vap_open,
    .ndo_stop = osif_vap_stop,
    .ndo_start_xmit = NULL,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
    .ndo_set_multicast_list = osif_set_multicast_list,
#else
    .ndo_set_rx_mode = osif_set_multicast_list,
#endif
    .ndo_do_ioctl = ieee80211_ioctl,
    .ndo_change_mtu = osif_change_mtu,
};
#endif
#endif /* WLAN_FEATURE_FASTPATH */

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
static struct net_device_ops osif_dev_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
    .ndo_get_stats64 = osif_getstats,
#else
    .ndo_get_stats = osif_getstats,
#endif
    .ndo_open = osif_vap_open,
    .ndo_stop = osif_vap_stop,
    .ndo_start_xmit = NULL,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
    .ndo_set_multicast_list = osif_set_multicast_list,
#else
    .ndo_set_rx_mode = osif_set_multicast_list,
#endif
    .ndo_do_ioctl = ieee80211_ioctl,
    .ndo_change_mtu = osif_change_mtu,
};
#endif

#if (HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE || HOST_SW_LRO_ENABLE || HOST_SW_SG_ENABLE)
#if (LINUX_VERSION_CODE > KERNEL_VERSION(3,2,0)) || PARTNER_ETHTOOL_SUPPORTED
static struct ethtool_ops osif_ethtool_ops;
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(3,2,0) */
#endif /* (HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE || HOST_SW_LRO_ENABLE || HOST_SW_SG_ENABLE) */

#if TCP_CHECKSUM_OFFLOAD
static inline
void osif_dev_set_offload_tx_csum(struct net_device *dev)
{
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Enabling TX checksum bit for the vap %s features %x \n",dev->name,(unsigned int)dev->features);
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,2,0)
    dev->hw_features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
    dev->vlan_features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
    dev->ethtool_ops = &osif_ethtool_ops;
#else
    dev->features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,3,0)
    /* ethtool interface changed for kernel versions > 3.3.0,
     * Corresponding changes as follows */
    dev->wanted_features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
#endif
}
#else
#define osif_dev_set_offload_tx_csum(dev)  /* no - op */
#endif


#if (HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE)
static inline
void osif_dev_set_tso(struct net_device *dev)
{
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Enabling TSO bit for the vap %s features %x \n",dev->name,(unsigned int)dev->features);
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,2,0) || PARTNER_ETHTOOL_SUPPORTED
    dev->hw_features |= NETIF_F_TSO | NETIF_F_TSO6 | NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
    /*  dev->gso_max_size  not setting explicitly since our HW capable handling any size packet,
     *  No limitation for MAX Jumbo Pkt size */
    /* Folowing is required to have TSO support for VLAN over VAP interfaces */
    dev->vlan_features |= NETIF_F_TSO | NETIF_F_TSO6 | NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
    dev->ethtool_ops = &osif_ethtool_ops;
#else
    /* For Lower kernel versions TSO is enabled always,
     * when enabled in build using the option HOST_SW_TSO_ENABLE */
    dev->features |= NETIF_F_TSO | NETIF_F_TSO6 | NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,3,0) || PARTNER_ETHTOOL_SUPPORTED
    /* ethtool interface changed for kernel versions > 3.3.0,
     * Corresponding changes as follows */
    dev->wanted_features |= NETIF_F_TSO | NETIF_F_TSO6 | NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
#endif
}
#else /* HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE */
#define osif_dev_set_tso(dev)  /* no - op */
#endif /* HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE */

#if HOST_SW_SG_ENABLE
static inline
void osif_dev_set_sg(struct net_device *dev)
{
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Enabling SG bit for the vap %s features %x \n",dev->name,(unsigned int)dev->features);
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,2,0)
    dev->hw_features |= NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
    /*  dev->gso_max_size  not setting explicitly since our HW capable handling any size packet,
     *  No limitation for MAX Jumbo Pkt size */
    /* Folowing is required to have TSO support for VLAN over VAP interfaces */
    dev->vlan_features |= NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
    dev->ethtool_ops = &osif_ethtool_ops;
#else
    /* For Lower kernel versions TSO is enabled always,
     * when enabled in build using the option HOST_SW_TSO_ENABLE */
    dev->features |= NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,3,0)
    /* ethtool interface changed for kernel versions > 3.3.0,
     * Corresponding changes as follows */
    dev->wanted_features |= NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
#endif
}
#else /* HOST_SW_SG_ENABLE */
#define osif_dev_set_sg(dev)  /* no - op */
#endif /* HOST_SW_SG_ENABLE */


#if HOST_SW_LRO_ENABLE
static inline
void osif_dev_set_lro(struct net_device *dev)
{
    /* LRO HW Support available only for 11ac Beeliner */
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Enabling LRO bit for the vap %s features %x \n",dev->name,(unsigned int)dev->features);
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,2,0) || PARTNER_ETHTOOL_SUPPORTED
    dev->hw_features |= NETIF_F_LRO;
    /* Folowing is required to have LRO support for VLAN over VAP interfaces */
    dev->vlan_features |= NETIF_F_LRO;
    dev->ethtool_ops = &osif_ethtool_ops;
#else
    /* For Lower kernel versions LRO is enabled always,
     * when enabled in build using the option HOST_SW_LRO_ENABLE */
    dev->features |= NETIF_F_LRO;
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,3,0) || PARTNER_ETHTOOL_SUPPORTED
    /* ethtool interface changed for kernel versions > 3.3.0,
     * Corresponding changes as follows */
    dev->wanted_features |= NETIF_F_LRO ;
#endif
}
#else /* HOST_SW_LRO_ENABLE */
#define osif_dev_set_lro(dev)  /* no - op */
#endif /* HOST_SW_LRO_ENABLE */

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
static struct net_device_ops osif_nss_wifiol_dev_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
    .ndo_get_stats64 = osif_getstats,
#else
    .ndo_get_stats = osif_getstats,
#endif
    .ndo_open = osif_vap_open,
    .ndo_stop = osif_vap_stop,
    .ndo_start_xmit = NULL,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
    .ndo_set_multicast_list = osif_set_multicast_list,
#else
    .ndo_set_rx_mode = osif_set_multicast_list,
#endif
    .ndo_do_ioctl = ieee80211_ioctl,
    .ndo_change_mtu = osif_change_mtu,
};
#endif
#endif /* QCA_NSS_WIFI_OFFLOAD_SUPPORT */

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
int osif_register_dev_ops_xmit(int (*vap_hardstart)(struct sk_buff *skb, struct net_device *dev), int netdev_type) {
    if (vap_hardstart == NULL)
        return -EINVAL;

    switch (netdev_type) {
    case OSIF_NETDEV_TYPE_DA:
        osif_dev_ops.ndo_start_xmit = vap_hardstart;
        break;
    case OSIF_NETDEV_TYPE_OL:
        osif_11ac_fp_dev_ops.ndo_start_xmit = vap_hardstart;
        break;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    case OSIF_NETDEV_TYPE_NSS_WIFIOL:
        osif_nss_wifiol_dev_ops.ndo_start_xmit = vap_hardstart;
        break;
#endif
    default:
        return -EINVAL;
        break;
    }
    return 0;
}
#else
int osif_register_dev_ops_xmit(int (*vap_hardstart)(struct sk_buff *skb, struct net_device *dev), int netdev_type) {
    return 0;
}
#endif
EXPORT_SYMBOL(osif_register_dev_ops_xmit);

int 
osif_create_vap_check(struct net_device *comdev,
        struct ieee80211_clone_params *cp)
{
    wlan_dev_t devhandle = ath_netdev_priv(comdev);
    struct ath_softc_net80211 *scn = (struct ath_softc_net80211 *)devhandle;
    struct ieee80211com *ic = &scn->sc_ic;

    if (!capable(CAP_NET_ADMIN))
        return -EPERM;

#if QCA_LTEU_SUPPORT
    if (ic->ic_nl_handle && cp->icp_opmode != IEEE80211_M_HOSTAP) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Only AP mode %d is supported for NL, not %d\n", IEEE80211_M_HOSTAP, cp->icp_opmode);
        return -EINVAL;
    }
#endif

    if(devhandle->ic_is_mode_offload(devhandle) &&
            ( IEEE80211_M_IBSS == cp->icp_opmode))
    {
        /* IBSS is not supported in partial offload architecture in linux
           As wlanconfig does not know about arhictecure i.e.e DA or partial offload
           so it sets the mode which may result a crash of firmware
           so refining it here and making sure if mode is IBSS and architecture
           is peregrine then we should not create VAP */
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ADHOC Not enabled in partial offload \n");
        return -EPERM;
    }

    return 0;
}

osif_dev *
osif_recover_vap_netdev(struct ieee80211vap *vap)
{
    struct net_device *dev = NULL;
    osif_dev  *osifp = NULL;
    int unit;

    osifp = (osif_dev *)wlan_vap_get_registered_handle(vap);
    dev = osifp->netdev;
    unit = osifp->os_unit;

    ieee80211_vap_deleted_clear(vap); /* clear the deleted */

    memset(osifp,0,sizeof(osif_dev));

    spin_lock_init(&osifp->list_lock);

    spin_lock_init(&osifp->tx_lock);

    osifp->os_unit = unit;
    osifp->os_if = vap;
    osifp->netdev = dev;

    return osifp;
}

int
osif_create_vap_netdev_free(struct net_device *dev, int unit)
{
    qdf_net_delete_wlanunit(unit);
    free_netdev(dev);

    return 0;
}

osif_dev *
osif_create_vap_netdev_alloc(struct ieee80211_clone_params *cp)
{
    struct net_device *dev = NULL;
    char name[IFNAMSIZ];
    int error, unit;
    osif_dev  *osifp = NULL;

    error = qdf_net_ifc_name2unit(cp->icp_name, &unit);
    if (error)
        return NULL;

    /* Allocation is tricky here, so let's give a few explanation.
     * We are basically trying to handle two cases:
     * - if the number isn't specified by the user, we have to allocate one,
     *   in which case we need to make sure it's not already been allocated
     *   already. User says "ath" and we create "athN" with N being a new unit#
     * - if the number is specified, we just need to make sure it's not been
     *   allocated already, which we check using dev_get_by_name()
     */
    if (unit == -1) {
        unit = qdf_net_new_wlanunit();
        if (unit == -1) {
            return NULL;
        }
        snprintf(name, sizeof(name), "%s%d", cp->icp_name, unit);
    } else {
         int dev_exist = qdf_net_dev_exist_by_name(cp->icp_name);
         if (dev_exist)
             return NULL;

        qdf_net_alloc_wlanunit(unit);
        if (strlcpy(name, cp->icp_name, sizeof(name)) >=  sizeof(name)) {
            qdf_print("source too long\n");
            return NULL;
        }
        name[IFNAMSIZ - 1] = '\0';
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
    dev = alloc_netdev(sizeof(osif_dev), "wifi%d", 0, ether_setup);
#else
    dev = alloc_netdev(sizeof(osif_dev), name, ether_setup);
#endif
    if(dev == NULL) {
        qdf_net_delete_wlanunit(unit);
        return NULL;
    }

    if (name != NULL)   /* XXX */
        if (strlcpy(dev->name, name, sizeof(dev->name)) >= sizeof(dev->name)) {
            qdf_print("source too long\n");
            return NULL;
        }

    /*
    ** Clear and initialize the osif structure
    */
    osifp = ath_netdev_priv(dev);

    memset(osifp,0,sizeof(osif_dev));
    osifp->netdev = dev;

    spin_lock_init(&osifp->list_lock);

    spin_lock_init(&osifp->tx_lock);

    osifp->os_unit  = unit;

    return osifp;
}

int
osif_create_vap_bssid_free(struct ieee80211com *ic,
                   uint8_t *req_mac,
                   struct ieee80211_clone_params *cp)
{
    bool macreq_enabled = FALSE;

    macreq_enabled = ic->ic_is_macreq_enabled(ic);
    /* remove the bssid from vapid */
    if( (cp->icp_vapid != VAP_ID_AUTO) &&
        ((cp->icp_flags & IEEE80211_CLONE_BSSID) == 0) &&
        (macreq_enabled == TRUE))
        {
            wlan_vap_free_mac_addr(ic, req_mac);
        }

    return 0;
}

int
osif_create_vap_bssid(struct net_device *comdev,
            struct ieee80211_clone_params *cp)
{
    wlan_dev_t devhandle = ath_netdev_priv(comdev);
    struct ath_softc_net80211 *scn = (struct ath_softc_net80211 *)devhandle;
    struct ieee80211com *ic = &scn->sc_ic;
    bool macreq_enabled = FALSE;
    u_int32_t prealloc_idmask;
    u_int8_t req_mac[IEEE80211_ADDR_LEN] = {0, 0, 0, 0, 0, 0};

    macreq_enabled = ic->ic_is_macreq_enabled(ic);
    prealloc_idmask = ic->ic_get_mac_prealloc_idmask(ic);

    if( (cp->icp_vapid == VAP_ID_AUTO) &&
        (macreq_enabled == TRUE))
    {
        int id;
        for(id = 0; id < ATH_MAX_PREALLOC_ID; id++)
        {
            if((prealloc_idmask & (1 << id)) == 0)
                break;
        }
        if(id == ATH_MAX_PREALLOC_ID)
        {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: no dynamic vaps free\n", __func__);
            return -EIO;
        }
    }
    /* generate the bssid from vapid */
    if( (cp->icp_vapid != VAP_ID_AUTO) &&
        ((cp->icp_flags & IEEE80211_CLONE_BSSID) == 0) &&
        (macreq_enabled == TRUE))
    {
        if((cp->icp_vapid >= ATH_MAX_PREALLOC_ID))
        {
            /* Support for Higher vapids (8-15) logic is added. */
            cp->icp_vapid = (cp->icp_vapid - ATH_MAX_PREALLOC_ID);
        } else {
            /* To support backward compatibility lower vapids (0-7) logic is unchanged. */
            cp->icp_vapid = (cp->icp_vapid + ATH_MAX_PREALLOC_ID);
        }

        IEEE80211_ADDR_COPY(req_mac, ic->ic_my_hwaddr);

        ATH_SET_VAP_BSSID(req_mac, ic->ic_my_hwaddr, cp->icp_vapid);

        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Requested VPA id %d and MAC %s\n", cp->icp_vapid, ether_sprintf(req_mac));

        if(wlan_vap_allocate_mac_addr(ic, req_mac) != -1)
        {
            IEEE80211_ADDR_COPY(cp->icp_bssid, req_mac);
        }
        else
        {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Invalid MAC requested\n", __func__);
            return -EIO;
        }
    }
    return 0;
}

wlan_if_t osifp_create_wlan_vap(struct ieee80211_clone_params *cp, osif_dev * osifp,
                                struct net_device *comdev)
{
    int scan_priority_mapping_base;
    struct net_device *dev;
    wlan_if_t vap = NULL;
    wlan_dev_t devhandle = ath_netdev_priv(comdev);

    dev = osifp->netdev;

    switch (cp->icp_opmode) {
#ifdef ATH_SUPPORT_P2P
    case IEEE80211_M_P2P_GO:
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " IEEE80211_M_P2P_GO created \n");
        osifp->p2p_go_handle = wlan_p2p_GO_create((wlan_p2p_t) devhandle, NULL);
        if (osifp->p2p_go_handle == NULL) {
            return NULL;
        }
        vap=wlan_p2p_GO_get_vap_handle(osifp->p2p_go_handle);
        /* enable UAPSD by default for GO Vap */
        /*  wlan_set_param(vap, IEEE80211_FEATURE_UAPSD, 0x1); */
        break;

    case IEEE80211_M_P2P_CLIENT:
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " IEEE80211_M_P2P_CLIENT created \n");
        osifp->p2p_client_handle = wlan_p2p_client_create((wlan_p2p_t) devhandle, NULL);
        if (osifp->p2p_client_handle == NULL) {
            return NULL;
        }
        vap=wlan_p2p_client_get_vap_handle(osifp->p2p_client_handle);
        break;

    case IEEE80211_M_P2P_DEVICE:
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " IEEE80211_M_P2P_DEVICE created \n");
        osifp->p2p_handle = wlan_p2p_create(devhandle, NULL);
        if (osifp->p2p_handle == NULL) {
            return NULL;
        }
        vap=wlan_p2p_get_vap_handle(osifp->p2p_handle);
        break;
#endif
    default:
        if (cp->icp_opmode == IEEE80211_M_STA) {
            scan_priority_mapping_base = DEF_VAP_SCAN_PRI_MAP_OPMODE_STA_BASE;
        }
        else if (cp->icp_opmode == IEEE80211_M_IBSS) {
            scan_priority_mapping_base = DEF_VAP_SCAN_PRI_MAP_OPMODE_IBSS_BASE;
        }
        else if (cp->icp_opmode == IEEE80211_M_HOSTAP) {
            scan_priority_mapping_base = DEF_VAP_SCAN_PRI_MAP_OPMODE_AP_BASE;
            if ((cp->icp_flags & IEEE80211_SPECIAL_VAP) && !(cp->icp_flags & IEEE80211_SMART_MONITOR_VAP)) {
                dev->type = ARPHRD_IEEE80211_PRISM;
            }
        }
        else if (cp->icp_opmode == IEEE80211_M_MONITOR) {
            scan_priority_mapping_base = DEF_VAP_SCAN_PRI_MAP_OPMODE_STA_BASE;
            dev->type = ARPHRD_IEEE80211_PRISM;
        }
        else {
            scan_priority_mapping_base = DEF_VAP_SCAN_PRI_MAP_OPMODE_STA_BASE;
        }
        vap = wlan_vap_create(devhandle, cp->icp_opmode, scan_priority_mapping_base, cp->icp_flags, cp->icp_bssid, cp->icp_mataddr, (void *) osifp);
        break;
    }
    if (vap == NULL) {
        return NULL;
    }

    osifp->os_if = vap;
    return vap;
}

int
osif_create_vap_complete(struct net_device *comdev,
                         struct ieee80211_clone_params *cp,
                         osif_dev *osifp,
                         osdev_t os_handle)
{
    wlan_dev_t devhandle = ath_netdev_priv(comdev);
    wlan_if_t vap = osifp->os_if;
    u_int8_t *vap_macaddr;
    struct net_device *dev = osifp->netdev;
    struct ath_softc_net80211 *scn = (struct ath_softc_net80211 *)devhandle;
    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211vap *parent_vap;
#if ATH_SUPPORT_WAPI
    /* for WAPI support, ETHERTYPE_WAPI should be added to the privacy filter */
    ieee80211_privacy_exemption privacy_filter[2];
#else
    ieee80211_privacy_exemption privacy_filter;
#endif
    int error;

    memcpy(&vap->cp, cp, sizeof(vap->cp));

    INIT_LIST_HEAD(&osifp->pending_rx_frames);
    spin_lock_init(&osifp->list_lock);

    osifp->os_handle = os_handle;
    osifp->os_devhandle = devhandle;
    osifp->os_comdev = comdev;
    osifp->os_opmode = cp->icp_opmode;

#ifdef ATHEROS_LINUX_PERIODIC_SCAN
    osifp->os_periodic_scan_period = OSIF_PERIODICSCAN_DEF_PERIOD;
    OS_INIT_TIMER(os_handle, &(osifp->os_periodic_scan_timer), periodic_scan_timer_handler,
            (void *)osifp, QDF_TIMER_TYPE_WAKE_APPS);
#endif
#ifdef ATH_SUPPORT_WAPI
    osifp->os_wapi_rekey_period = OSIF_WAPI_REKEY_TIMEOUT;
    OS_INIT_TIMER(os_handle, &(osifp->os_wapi_rekey_timer), osif_wapi_rekey_timeout,
            (void *)osifp, QDF_TIMER_TYPE_WAKE_APPS);
#endif
    osif_vap_setup(vap, dev, cp->icp_opmode);
#if ATH_NON_BEACON_AP
    if( (cp->icp_opmode == IEEE80211_M_HOSTAP) &&
        (cp->icp_flags & IEEE80211_NON_BEACON_AP) ){
        IEEE80211_VAP_NON_BEACON_ENABLE(vap);
    }
#endif
    vap_macaddr = wlan_vap_get_macaddr(vap);
    IEEE80211_ADDR_COPY(dev->dev_addr, vap_macaddr);

    ic_sta_vap_update(devhandle, vap);
    ic_mon_vap_update(devhandle, vap);

#if WLAN_FEATURE_FASTPATH
    if (osifp->osif_is_mode_offload) {
        spin_lock_init(&osifp->nbuf_arr_lock);
        osifp->nbuf_arr = (qdf_nbuf_t *)qdf_mem_malloc(MSDUS_ARRAY_SIZE * sizeof(qdf_nbuf_t));
        if (!osifp->nbuf_arr) {
            return ENOMEM;
        }
    }
#endif

#ifdef QCA_PARTNER_PLATFORM
    osif_pltfrm_record_macinfor(osifp->os_unit,dev->dev_addr);
#endif

    /* Note: Set the dev features flag to comdev features
     * before qdf_net_vlan_attach - otherwise
     * VLAN flag settings in qdf_net_vlan_attach gets
     * overwritten
     */
    dev->features = comdev->features;

    /* enable TSO/LRO only of HW Supports */
    if(osifp->osif_is_mode_offload) {
        if (ic->ic_offload_tx_csum_support) {
            osif_dev_set_offload_tx_csum(dev);
        }
        if (ic->ic_sg_support) {
            osif_dev_set_sg(dev);
        }
        if (ic->ic_sg_support) {
            osif_dev_set_sg(dev);
        }
        if (ic->ic_tso_support) {
            osif_dev_set_tso(dev);
        }
        if (ic->ic_lro_support) {
            osif_dev_set_lro(dev);
        }
    }

// fixme where is this done in the new scheme?    dev->priv = vap;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
#if WLAN_FEATURE_FASTPATH
    if (osifp->osif_is_mode_offload) {
        dev->netdev_ops = &osif_11ac_fp_dev_ops;
    } else
#endif /* WLAN_FEATURE_FASTPATH*/
    {
        osif_dev_ops.ndo_start_xmit = os_handle->vap_hardstart;
        dev->netdev_ops = &osif_dev_ops;
    }

    ((struct net_device_ops *) (dev->netdev_ops))->ndo_do_ioctl = ieee80211_ioctl;
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30) */
    dev->get_stats = osif_getstats;
    dev->open = osif_vap_open;
    dev->stop = osif_vap_stop;

    dev->hard_start_xmit = os_handle->vap_hardstart;
    dev->set_multicast_list = osif_set_multicast_list;
#if 0
    dev->set_mac_address = ieee80211_set_mac_address;
#endif
    dev->change_mtu = osif_change_mtu;
#endif
    dev->tx_queue_len = 0;          /* NB: bypass queueing */
    dev->needed_headroom = comdev->needed_headroom;
    dev->hard_header_len = comdev->hard_header_len;


#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if ( osifp->osif_is_mode_offload && ic->nss_funcs &&
            (( osifp->nss_wifiol_ctx = ic->nss_funcs->ic_osif_nss_vdev_get_nss_wifiol_ctx(osifp->iv_txrx_handle)) != NULL)) {
        osifp->radio_id = ic->nss_funcs->ic_osif_nss_vdev_get_nss_id(osifp->iv_txrx_handle);
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
        dev->netdev_ops = &osif_nss_wifiol_dev_ops;
#else
        if(os_handle->vap_hardstart)
            dev->hard_start_xmit = os_handle->vap_hardstart;
#endif
    } else
#endif
        {
#if QCA_NSS_PLATFORM
            if (!(of_machine_is_compatible("qcom,ipq40xx"))) {
                osif_pltfrm_create_vap(osifp);
            }
#elif  defined(QCA_PARTNER_PLATFORM )
            osif_pltfrm_create_vap(osifp);
#endif
        }

    /*
     * qdf_net_vlan_attach() sets the vlan as a active feature in dev->features
     * and assigns vlan functions in dev->netdev_ops
     *
     * Should be called after final dev->netdev_ops is assigned to keep
     * dev->features flag and func pointers in dev->netdev_ops in a sync
     *
     */
#if ATH_SUPPORT_VLAN
    if (!ic->ic_no_vlan) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
    	qdf_net_vlan_attach(dev,(struct net_device_ops *) dev->netdev_ops);
#else
    	qdf_net_vlan_attach(dev);
#endif
    }
#endif

    /*
     * The caller is assumed to allocate the device with
     * alloc_etherdev or similar so we arrange for the
     * space to be reclaimed accordingly.
     */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    /* in 2.4 things are done differently... */
    dev->features |= NETIF_F_DYNALLOC;
#else
    dev->destructor = free_netdev;
#endif


    os_if_media_init(osifp);
    if (cp->icp_opmode == IEEE80211_M_P2P_DEVICE)
        wlan_set_desired_phymode(vap, IEEE80211_MODE_11G);
    else
        wlan_set_desired_phymode(vap, IEEE80211_MODE_AUTO);

    parent_vap = TAILQ_FIRST(&ic->ic_vaps);
    if (parent_vap != NULL && parent_vap != vap) {
        wlan_set_desired_phymode(vap, parent_vap->iv_des_mode);
    }

#if ATH_SUPPORT_WAPI
    /* always setup a privacy filter to allow receiving unencrypted EAPOL frame and/or WAI frame for WAPI*/
    privacy_filter[0].ether_type = ETHERTYPE_PAE;
    privacy_filter[0].packet_type = IEEE80211_PRIVACY_FILTER_PACKET_BOTH;
    privacy_filter[0].filter_type = IEEE80211_PRIVACY_FILTER_KEY_UNAVAILABLE;
    privacy_filter[1].ether_type = ETHERTYPE_WAI;
    privacy_filter[1].packet_type = IEEE80211_PRIVACY_FILTER_PACKET_BOTH;
    privacy_filter[1].filter_type =IEEE80211_PRIVACY_FILTER_ALLWAYS;
    wlan_set_privacy_filters(vap,privacy_filter,2);
#else
    /* always setup a privacy filter to allow receiving unencrypted EAPOL frame */
    privacy_filter.ether_type = ETHERTYPE_PAE;
    privacy_filter.packet_type = IEEE80211_PRIVACY_FILTER_PACKET_BOTH;
    privacy_filter.filter_type = IEEE80211_PRIVACY_FILTER_KEY_UNAVAILABLE;
    wlan_set_privacy_filters(vap,&privacy_filter,1);
#endif /* ATH_SUPPORT_WAPI */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
    dev->do_ioctl = ieee80211_ioctl;
#endif
    ieee80211_ioctl_vattach(dev);
    ieee80211_proc_vattach(vap);

    do {
        ieee80211_auth_mode modes[1];
        u_int nmodes=1;

        /*
         * set default mode to OPEN.
         */
        modes[0] = IEEE80211_AUTH_OPEN;
        error = wlan_set_authmodes(vap,modes,nmodes);

    } while(0);

#if UMAC_PER_PACKET_DEBUG
    if (strlcpy(vap->iv_proc_fname,"pppdata",PROC_FNAME_SIZE) >= PROC_FNAME_SIZE) {
        qdf_print("source too long\n");
        return NULL;
    }
    strcat(vap->iv_proc_fname, dev->name);
    vap->iv_proc_entry = create_proc_entry(vap->iv_proc_fname, 0644, vap->iv_proc_root);
    if(vap->iv_proc_entry == NULL) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " iv null \n");
    } else {
        vap->iv_proc_entry->data = (void *)vap;
        vap->iv_proc_entry->write_proc = osif_proc_pppdata_write;
    }
#endif
    /* register scan event handler */
    ieee80211_scan_register_event_handler(vap->iv_ic->ic_scanner, &osif_scan_evhandler, (void *)osifp);
    wlan_scan_get_requestor_id(vap,(u_int8_t*)"osif_umac", &osifp->scan_requestor);
    wlan_scan_get_requestor_id(vap,(u_int8_t*)"offchan", &osifp->offchan_scan_requestor);


#if ATH_SUPPORT_WRAP
    if (wlan_is_psta(vap)) {
        osif_wrap_dev_add(osifp);
        /* disable power save for the PSTA VAPS*/
        wlan_set_powersave(vap, IEEE80211_PWRSAVE_NONE);
    }
#endif

#if QCA_PARTNER_DIRECTLINK_TX
    osifp->is_directlink = 0;
    if (osifp->osif_is_mode_offload) {
        if (ol_is_directlink(osifp->iv_txrx_handle)) {
            osifp->is_directlink = 1;
            if (wlan_pltfrm_directlink_enable(osifp)) {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: direct link unable to register device\n", dev->name);
            }
        }
    }
#endif /* QCA_PARTNER_DIRECTLINK_TX */

    return 0;
}

int
osif_create_vap_netdev_register(struct net_device *dev)
{
    /* NB: rtnl is held on entry so don't use register_netdev */
    if (register_netdevice(dev)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: unable to register device\n", dev->name);

        osif_vap_stop(dev);

        return -EINVAL;
    }
    return 0;
}

int
osif_create_vap_recover(struct net_device *comdev,
                          struct ieee80211vap *vap,
                          osdev_t os_handle)
{
    osif_dev  *osifp;
    int ret;
    wlan_dev_t devhandle = ath_netdev_priv(comdev);
    struct ieee80211_clone_params cp;
    struct ath_softc_net80211 *scn = (struct ath_softc_net80211 *)devhandle;
    struct ieee80211com *ic = &scn->sc_ic;
    struct net_device *dev;

    memcpy(&cp, &vap->cp, sizeof(cp));

    osifp = osif_recover_vap_netdev(vap);
    if (osifp == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: netdev failed\n", __FUNCTION__);
        goto fail0;
    }

    dev = osifp->netdev;

    ret = osif_create_vap_bssid(comdev, &cp);
    if (ret != 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: vap bssid failed\n", __FUNCTION__);
        goto fail1;
    }

    vap = osifp_create_wlan_vap(&cp, osifp, comdev);
    if (vap == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: wlan vap failed\n", __FUNCTION__);
        goto fail2;
    }

    ret = osif_create_vap_complete(comdev, &cp, osifp, os_handle);
    if (ret != 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: wlan vap compl failed\n", __FUNCTION__);
        goto fail3;
    }

    sysfs_create_group(&dev->dev.kobj, &ath_attr_group);

    return 0;

 fail3:
    osif_delete_vap(dev, 0);
    osif_delete_vap_wait_and_free(dev);
 fail2:
    osif_create_vap_bssid_free(ic, cp.icp_bssid, &cp);
 fail1:
    osif_create_vap_netdev_free(osifp->netdev, osifp->os_unit);
 fail0:
    return -EINVAL;
}

/*
* Create a virtual ap.  This is public as it must be implemented
* outside our control (e.g. in the driver).
*/
int
osif_ioctl_create_vap(struct net_device *comdev, struct ifreq *ifr,
                        struct ieee80211_clone_params *cp,
                        osdev_t os_handle)
{
    osif_dev  *osifp;
    int ret;
    wlan_dev_t devhandle = ath_netdev_priv(comdev);
    struct ath_softc_net80211 *scn = (struct ath_softc_net80211 *)devhandle;
    struct ieee80211com *ic = &scn->sc_ic;
    struct net_device *dev;
    struct ieee80211vap *vap;

    ret = osif_create_vap_check(comdev, cp);
    if (ret) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: check failed\n", __FUNCTION__);
        return ret;
    }

    osifp = osif_create_vap_netdev_alloc(cp);
    if (osifp == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:create netdev failed\n", __FUNCTION__);
        goto fail0;
    }

    ret = osif_create_vap_bssid(comdev, cp);
    if (ret != 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: vap bssid failed\n", __FUNCTION__);
        goto fail1;
    }

    vap = osifp_create_wlan_vap(cp, osifp, comdev);
    if (vap == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: wlan vap failed\n", __FUNCTION__);
        goto fail2;
    }

    dev = osifp->netdev;

    ret = osif_create_vap_complete(comdev, cp, osifp, os_handle);
    if (ret != 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: wlan vap compl failed\n", __FUNCTION__);
        goto fail3;
    }

    ret = osif_create_vap_netdev_register(dev);
    if (ret != 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:register netdev failed\n", __FUNCTION__);
        goto fail3;
    }

    sysfs_create_group(&dev->dev.kobj, &ath_attr_group);
    if (strlcpy(ifr->ifr_name, dev->name, IFNAMSIZ) >= IFNAMSIZ) {
        qdf_print("source too long\n");
        return  -EINVAL;
    }
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "VAP device %s created osifp: (%p) os_if: (%p)\n",
           dev->name, osifp, osifp->os_if);

    return 0;

 fail3:
    osif_delete_vap(dev, 0);
    osif_delete_vap_wait_and_free(dev);
 fail2:
    osif_create_vap_bssid_free(ic, cp->icp_bssid, cp);
 fail1:
    osif_create_vap_netdev_free(osifp->netdev, osifp->os_unit);
 fail0:
    return -EINVAL;
}
EXPORT_SYMBOL(osif_ioctl_create_vap);

int
osif_delete_vap_start(struct net_device *dev)
{
    osif_dev *osnetdev = ath_netdev_priv(dev);
    wlan_if_t vap = osnetdev->os_if;
    struct ieee80211com *ic;
#if QCA_PARTNER_DIRECTLINK_TX
    osif_dev  *osifp;
#endif /* QCA_PARTNER_DIRECTLINK_TX */

    ic = wlan_vap_get_devhandle(vap);
    osnetdev->is_delete_in_progress=1;
    vap->iv_needs_up_on_acs = 0;

    ieee80211_proc_vdetach(vap);
#if QCA_PARTNER_DIRECTLINK_TX
    osifp = ath_netdev_priv(dev);
    if (qdf_unlikely(osifp->is_directlink)) {
        if (wlan_pltfrm_directlink_disable(osnetdev)) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: direct link unable to deregister device\n", dev->name);
        }
    }
#endif /* QCA_PARTNER_DIRECTLINK_TX */



#ifdef ATHEROS_LINUX_PERIODIC_SCAN
    OS_FREE_TIMER(&(osnetdev->os_periodic_scan_timer));
#endif
#ifdef ATH_SUPPORT_WAPI
    OS_FREE_TIMER(&(osnetdev->os_wapi_rekey_timer));
#endif
    ifmedia_removeall(&osnetdev->os_media);
    /* unregister scan event handler */
#if UMAC_SUPPORT_IBSS
    wlan_scan_unregister_event_handler(vap, &osif_ibss_scan_evhandler, (void *)osnetdev);
#endif
    ieee80211_scan_unregister_event_handler(vap->iv_ic->ic_scanner, &osif_scan_evhandler, (void *)osnetdev);
    wlan_scan_clear_requestor_id(vap, osnetdev->scan_requestor);
    wlan_scan_clear_requestor_id(vap, osnetdev->offchan_scan_requestor);

#if UMAC_PER_PACKET_DEBUG
    remove_proc_entry(vap->iv_proc_fname, vap->iv_proc_root);
#endif
    sysfs_remove_group(&dev->dev.kobj, &ath_attr_group);

#if ATH_SUPPORT_WRAP
    if (wlan_is_psta(vap)) {
        osif_wrap_dev_remove(osnetdev);
        osif_wrap_dev_remove_vma(osnetdev);
    }
#endif

    dev_change_flags(dev, dev->flags & (~IFF_UP));

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        if (osnetdev->nss_wifiol_ctx) {
            /*
             * When wifi offload is enabled, we could have NSS qdiscs configured
             * on the wifi interface. These need to be destroyed before we
             * can destroy the interface.
             */
            dev_shutdown(dev);
            if (ic->nss_funcs)
                ic->nss_funcs->ic_osif_nss_ol_vap_delete(osnetdev);
            osnetdev->nss_ifnum =  -1;
            mdelay(100);
        } else
#endif
        {
#if QCA_NSS_PLATFORM
            if (!(of_machine_is_compatible("qcom,ipq40xx"))) {
                osif_pltfrm_delete_vap(osnetdev);
            }
#elif defined(QCA_PARTNER_PLATFORM )
            osif_pltfrm_delete_vap(osnetdev);
#endif
        }
#if ATH_SUPPORT_WRAP
    /* ProxySTA VAP has its own mac address and doesn't use mBSSID */
    if (!vap->iv_psta)
        wlan_vap_free_mac_addr(ic, vap->iv_myaddr);
#else
    /* free the MAC address */
    wlan_vap_free_mac_addr(ic, vap->iv_myaddr);
#endif

    return 0;
}

int
osif_delete_vap_complete(struct net_device *dev)
{
    osif_dev *osnetdev = ath_netdev_priv(dev);

    osnetdev->is_delete_in_progress = 0;

    spin_lock_destroy(&osnetdev->list_lock);
    spin_lock_destroy(&osnetdev->tx_lock);

#if WLAN_FEATURE_FASTPATH
        if (osnetdev->osif_is_mode_offload) {
            ASSERT(osnetdev->nbuf_arr);
            /* Free up the accumulated SKB's also */
            qdf_mem_free(osnetdev->nbuf_arr);
            osnetdev->nbuf_arr = NULL;
            spin_lock_destroy(&osnetdev->nbuf_arr_lock);
        }
#endif

    osnetdev->os_if = NULL;

    ieee80211_ioctl_vdetach(dev);

    return 0;
}

int
osif_delete_vap_netdev_unregister(struct net_device *dev)
{
    osif_dev *osnetdev = ath_netdev_priv(dev);

    qdf_net_delete_wlanunit(osnetdev->os_unit);
    unregister_netdevice(dev);

    return 0;
}

int
osif_delete_vap_recover(struct net_device *dev)
{
    osif_delete_vap_start(dev);

    osif_delete_vap(dev, 1);

    osif_delete_vap_complete(dev);

    return 0;
}

int
osif_ioctl_delete_vap(struct net_device *dev)
{

    osif_delete_vap_start(dev);

    osif_delete_vap(dev, 0);

    osif_delete_vap_wait_and_free(dev);

    osif_delete_vap_complete(dev);

    osif_delete_vap_netdev_unregister(dev);

    return 0;
}
EXPORT_SYMBOL(osif_ioctl_delete_vap);

int
osif_ioctl_switch_vap(struct net_device *dev, enum ieee80211_opmode opmode)
{
        osif_dev *osifp = ath_netdev_priv(dev);
        wlan_if_t vap = osifp->os_if;
        u_int8_t *macaddr;
        u_int64_t msg_flags;

        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : from %d to %d  \n",
                        __func__, osifp->os_opmode, opmode);


        if (osifp->os_opmode == opmode) {
            return 0;
        }

        macaddr = wlan_vap_get_macaddr(vap);
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : old mac addr %s   \n", __func__, ether_sprintf(macaddr));

        _netif_carrier_off(dev);
        msg_flags = wlan_get_debug_flags(vap);
        osifp->is_delete_in_progress = 1;
        osif_vap_stop(dev);
        osif_delete_vap(dev, 0);
        osif_delete_vap_wait_and_free(dev);
        osifp->os_if = NULL;
        osif_setup_vap(osifp,opmode,IEEE80211_CLONE_BSSID,NULL);
        vap = osifp->os_if;
        if (!vap) {
           return -EINVAL;
        }
        wlan_set_debug_flags(vap, msg_flags);
        _netif_carrier_on(dev);
        macaddr = wlan_vap_get_macaddr(vap);
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : new mac addr %s   \n", __func__, ether_sprintf(macaddr));

        return 0;
}

int
wlan_get_vap_info(struct ieee80211vap *vap,
                  struct ieee80211vap_profile *vap_profile,
                  void *handle);

int osif_recover_profile_alloc(struct ieee80211com *ic)
{
    struct ieee80211_profile *profile;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct net_device *dev = scn->sc_osdev->netdev;
    struct ieee80211vap *vap = NULL;
    struct ieee80211vap_profile *vap_profile;
    wlan_chan_t chan;

    if(ic->profile) {
        kfree(ic->profile);
        ic->profile = NULL;
    }

    profile = (struct ieee80211_profile *)kmalloc(
                  sizeof (struct ieee80211_profile), GFP_KERNEL);
    if (profile == NULL) {
        return -ENOMEM;
    }
    OS_MEMSET(profile, 0, sizeof (struct ieee80211_profile));

    if (strlcpy(profile->radio_name, dev->name, IFNAMSIZ) >= IFNAMSIZ) {
        qdf_print("source too long\n");
        return -ENOMEM;
    }
    wlan_get_device_mac_addr(ic, profile->radio_mac);
    profile->cc = (u_int16_t)wlan_get_device_param(ic,
                                IEEE80211_DEVICE_COUNTRYCODE);
    chan = wlan_get_dev_current_channel(ic);
    if (chan != NULL) {
        profile->channel = chan->ic_ieee;
        profile->freq = chan->ic_freq;
    }
    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        vap_profile = &profile->vap_profile[profile->num_vaps];
        wlan_get_vap_info(vap, vap_profile, (void *)scn->sc_osdev);
        profile->num_vaps++;
    }

    ic->profile = profile;

    return 0;
}

int osif_recover_profile_free(struct ieee80211com *ic)
{
    if(ic->profile)
        kfree(ic->profile);
    ic->profile = NULL;

    return 0;
}

int
osif_recover_vap_delete(struct ieee80211com *ic)
{
    struct ieee80211vap *vap;
    struct ieee80211vap *vapnext;
    osif_dev  *osifp;
    struct net_device *netdev;

    if (osif_recover_profile_alloc(ic) != 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ERROR: FW Recovery profile alloc failed\n");
        return -1;
    }

    vap = TAILQ_FIRST(&ic->ic_vaps);
    while (vap != NULL) {
        vapnext = TAILQ_NEXT(vap, iv_next);
        osifp = (osif_dev *)vap->iv_ifp;
        netdev = osifp->netdev;

        osif_delete_vap_recover(netdev);

        vap = vapnext;
    }

    return 0;
}
EXPORT_SYMBOL(osif_recover_vap_delete);

void
osif_recover_vap_create(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ieee80211_profile *profile = ic->profile;
    struct ieee80211vap_profile *vap_profile = NULL;
    int i, ret = 0;

    for(i = 0; i < profile->num_vaps; i++) {
        vap_profile = &profile->vap_profile[i];

        ret = osif_create_vap_recover(scn->sc_osdev->netdev,
                                vap_profile->vap,
                                (osdev_t) scn->sc_osdev);
        if (ret != 0) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, 
                           "Warning: Vap %p recovery failed, trying other vaps...\n",
                   vap_profile->vap);
        }

    }

    osif_recover_profile_free(ic);
}
EXPORT_SYMBOL(osif_recover_vap_create);

int
wlan_get_vap_info(struct ieee80211vap *vap,
                    struct ieee80211vap_profile *vap_profile,
                    void *handle)
{
    int ret, i  = 0;
    ieee80211_cipher_type uciphers[IEEE80211_CIPHER_MAX];
    ieee80211_keyval k;
    int kid;
    u_int8_t *macaddr;
    u_int8_t ieee80211broadcastaddr[IEEE80211_ADDR_LEN] =
                                    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    osif_dev *osif;
	ieee80211_auth_mode modes[IEEE80211_AUTH_MAX];

    osif = (osif_dev *)wlan_vap_get_registered_handle(vap);
    vap_profile->vap = vap;
    if (strlcpy(vap_profile->name, osif->netdev->name, IFNAMSIZ) >= IFNAMSIZ) {
        qdf_print("source too long\n");
        return -1;
    }
    wlan_get_vap_addr(vap, vap_profile->vap_mac);
	vap_profile->phymode = wlan_get_desired_phymode(vap);
	ret = wlan_get_auth_modes(vap, modes, IEEE80211_AUTH_MAX);
    if (ret > 0) {
        vap_profile->sec_method = modes[0];
        if ((ret > 1) && (modes[0] == IEEE80211_AUTH_OPEN) &&
                 (modes[1] == IEEE80211_AUTH_SHARED))
        {
            vap_profile->sec_method = IEEE80211_AUTH_AUTO;
        }
    }

    ret = wlan_get_ucast_ciphers(vap, uciphers, IEEE80211_CIPHER_MAX);
    for (i = 0; i < ret; i++) {
        vap_profile->cipher |= 1<<uciphers[i];
    }
    if (wlan_get_param(vap, IEEE80211_FEATURE_PRIVACY))
    {
        vap_profile->cipher |= 1<<IEEE80211_CIPHER_WEP;
        kid = wlan_get_default_keyid(vap);
        if (kid == IEEE80211_KEYIX_NONE) {
            kid = 0;
        }
        if ((0 <= kid) && (kid < IEEE80211_WEP_NKID)) {
            macaddr = (u_int8_t *)ieee80211broadcastaddr;
            k.keydata = vap_profile->wep_key[kid];
            if (wlan_get_key(vap, kid, macaddr, &k, 64) == 0) {
                vap_profile->wep_key_len[kid] = k.keylen;
            }
        }
    } else {
        vap_profile->cipher &= ~(1<<IEEE80211_CIPHER_WEP);
    }
    return 0;
}
EXPORT_SYMBOL(wlan_get_vap_info);

#if UMAC_SUPPORT_ACFG
int
osif_set_vap_vendor_param(struct net_device *dev, acfg_vendor_param_req_t *req)
{
    int status = 0, reinit = 0;

    /* vendors can add their commands here */
    switch(req->param)
    {
        case ACFG_VENDOR_PARAM_CMD_PRINT:
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Received user print data %s\n", (char *)&req->data);
            break;
        case ACFG_VENDOR_PARAM_CMD_INT:
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Received user int data %d\n", *(uint32_t *)&req->data);
            break;
        case ACFG_VENDOR_PARAM_CMD_MAC:
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Received user mac data %02x:%02x:%02x:%02x:%02x:%02x\n", req->data.data[0], \
                                                                             req->data.data[1], \
                                                                             req->data.data[2], \
                                                                             req->data.data[3], \
                                                                             req->data.data[4], \
                                                                             req->data.data[5]);
            break;
        default:
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ACFG driver unknown vendor param\n");
            status = -1;
    }
    /* If driver restart required, please set the "ENETRESET" flag in reinit variable */
    if(reinit == ENETRESET)
    {
        /* Reinit the wlan driver */
        return IS_UP(dev) ? -osif_vap_init(dev, RESCAN) : 0;
    }
    return status;
}

int
osif_get_vap_vendor_param(struct net_device *dev, acfg_vendor_param_req_t *req)
{
    int status = 0;

    /* vendors can add their commands here */
    switch(req->param)
    {
        case ACFG_VENDOR_PARAM_CMD_PRINT:
            strlcpy((char *)&req->data, "QCA", sizeof(req->data));
            req->type = ACFG_TYPE_STR;
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Sending driver data %s type %d\n", (char *)&req->data, req->type);
            break;
        case ACFG_VENDOR_PARAM_CMD_INT:
            req->type = ACFG_TYPE_INT;
            *(uint32_t *)&req->data = 12345678;
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Sending driver data %d type %d\n", *(uint32_t *)&req->data, req->type);
            break;
        case ACFG_VENDOR_PARAM_CMD_MAC:
        {
            int i;
            req->type = ACFG_TYPE_MACADDR;
            for(i = 0; i < MAC_ADDR_LEN; i++)
                req->data.data[i] = i;
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Sending driver mac data %02x:%02x:%02x:%02x:%02x:%02x type %d\n", req->data.data[0], \
                                                                                      req->data.data[1], \
                                                                                      req->data.data[2], \
                                                                                      req->data.data[3], \
                                                                                      req->data.data[4], \
                                                                                      req->data.data[5], req->type);
            break;
        }
        default:
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ACFG driver invalid vendor param\n");
            status = -1;
    }
    return status;
}
#endif //UMAC_SUPPORT_ACFG

#if UMAC_PER_PACKET_DEBUG

int  osif_atoi_proc(char *buf) {
    int value=0;
    while(*buf) {
        value=(value << 3) + (value << 1) + (*buf - '0');
        buf++;
    }
    return value;
}


ssize_t osif_proc_pppdata_write(struct file *filp, const char __user *buff,
                        unsigned long len, void *data )
{
	struct ieee80211vap *vap;
    struct ieee80211com    *ic;
	char cmd[20], buf1[10], buf2[10];
	int filter,selevm;

	vap = (struct ieee80211vap *) data;
    ic = wlan_vap_get_devhandle(vap);
    sscanf(buff,"%s %s %s",cmd ,buf1 ,buf2);
    if (strcmp("rate_retry", cmd) == 0) {
	    vap->iv_userrate = osif_atoi_proc(buf1);
        vap->iv_userretries = osif_atoi_proc(buf2);
	} else if(strcmp("txchainmask", cmd) == 0) {
	    vap->iv_usertxchainmask = osif_atoi_proc(buf1);
	} else if(strcmp("txpower", cmd) == 0) {
	    vap->iv_usertxpower = osif_atoi_proc(buf1);
	} else if(strcmp("rxfilter", cmd) == 0) {
	    filter = osif_atoi_proc(buf1);
        ic->ic_set_rxfilter(ic, filter);
    } else if(strcmp("plcpheader", cmd) == 0) {
        selevm = osif_atoi_proc(buf1);
        ic->ic_set_rx_sel_plcp_header(ic, !selevm, 0);
    }
    return len;
}

#endif



static INLINE void
ieee80211_vap_resetdeschan(void *arg, struct ieee80211vap *vap, bool is_last_vap)
{
    vap->iv_des_chan[vap->iv_des_mode] = IEEE80211_CHAN_ANYC;

}
extern void osif_ht40_event_handler(void *arg, wlan_chan_t channel);

static void
is_sta_connected(void *arg, wlan_node_t node)
{
    u_int32_t *is_valid = (u_int32_t *)arg;
    *is_valid =1;

}


static void osif_staconnected_check(void *arg, wlan_if_t vap)
{
    u_int32_t  *staconnected = (u_int32_t *) arg;
    u_int32_t is_valid = 0 ;

    wlan_iterate_station_list(vap, is_sta_connected, &is_valid);
    if(is_valid == 1){
        *staconnected= 1;
    }

}


/*
* Auto Channel Select handler used for interface up.
*/
static void osif_bkscan_acs_event_handler(void *arg, wlan_chan_t channel)
{
    osif_dev *osifp = (osif_dev *) arg;
    wlan_if_t vap = osifp->os_if;
    int chan;
    int error = 0;
    struct ieee80211_vap_info vap_info;

    if ((!channel) || (channel == IEEE80211_CHAN_ANYC) ||
        (osifp->is_stop_event_pending == 1))
        goto done;

    chan = wlan_channel_ieee(channel);

    error = wlan_set_channel(vap, chan, channel->ic_vhtop_ch_freq_seg2);

    if (error !=0) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACS,
                        "%s : failed to set channel with error code %d\n",
                        __func__, error);
        goto done;
    }

    vap_info.chan = vap->iv_des_chan[vap->iv_des_mode];
    vap_info.no_cac = 0;
    wlan_iterate_vap_list(wlan_vap_get_devhandle(vap), osif_bringup_vap_iter_func,
            &vap_info);

    if (wlan_coext_enabled(vap))
    {
        wlan_determine_cw(vap, channel);
    }

done:
    wlan_autoselect_unregister_event_handler(vap, &osif_bkscan_acs_event_handler, (void *)osifp);
}


static void osif_bkscan_ht40_event_handler(void *arg, wlan_chan_t channel)
{
    osif_dev *osifp = (osif_dev *) arg;
    wlan_if_t vap = osifp->os_if;

    if ((!channel) || (channel == IEEE80211_CHAN_ANYC) ||
        (osifp->is_stop_event_pending == 1))
        goto done;

    wlan_iterate_vap_list(wlan_vap_get_devhandle(vap), osif_bringup_vap_iter_func, NULL);

    if (wlan_coext_enabled(vap))
    {
        wlan_determine_cw(vap, channel);
    }
done:
    wlan_autoselect_unregister_event_handler(vap,
                                            &osif_bkscan_ht40_event_handler,
                                            osifp);
}

/* Argument passed is  wlan_dev_t comhandle(ic) value */
void obss_scan_event(void * arg)
{
    struct ieee80211com *ic = NULL;
    struct ieee80211vap *vap = NULL, *vapnext = NULL;
    struct net_device *dev = NULL;
    osif_dev  *osifp = NULL;


    if (arg == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s(%d) ic is null\n", __func__, __LINE__);
        return;
    }

    ic = (struct ieee80211com *)arg;
    /* Loop through and figure the first VAP on this radio */
    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
            if (!vap->iv_list_scanning) {
                goto vapfound_obss_scan;
            }
        }
    }

vapfound_obss_scan :
    if (vap == NULL) {
        return;
    }

    dev = OSIF_TO_NETDEV(vap->iv_ifp);
    osifp = ath_netdev_priv(dev);
    vapnext = TAILQ_FIRST(&ic->ic_vaps);
    while (vapnext) {
        osif_bringdown_vap_iter_obss_scan_func(arg, vapnext);
        vapnext = TAILQ_NEXT(vapnext, iv_next);
    }
    wlan_autoselect_register_event_handler(vap, &osif_bkscan_ht40_event_handler, (void *)osifp);
    wlan_attempt_ht40_bss(vap);
}

static void osif_acs_bk_scantimer_fn( void *arg )
{
    struct ieee80211com *ic = (struct ieee80211com *)arg ;
    struct ieee80211vap *vap;
    u_int32_t  staconnected = 0, num_vaps;
    int acs_ctrlflags = ic->ic_acs_ctrlflags;

    if(!osif_get_num_active_vaps(ic)){
        return;
    }

    /* Check if CW Interference is already been found and being handled */
    if (ic->cw_inter_found) {
        return;
    }
    if((acs_ctrlflags & ( ACS_PEREODIC_OBSS_CHK |ACS_PEIODIC_SCAN_CHK)) == 0)  {
        return ;
    }
    wlan_iterate_vap_list(ic,osif_staconnected_check,(void *)&staconnected);
    if(staconnected == 1)
        return ;


    /* Loop through and figure the first VAP on this radio */
    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
#ifdef QCA_PARTNER_PLATFORM
            if (vap->iv_des_chan[vap->iv_des_mode] == IEEE80211_CHAN_ANYC)
            	return;
            if (!vap->iv_list_scanning)
#endif
            goto vapfound;
        }
    }

vapfound :
    if(vap == NULL)
        return;
    if(acs_ctrlflags & ACS_PEIODIC_SCAN_CHK){
        struct net_device *dev = OSIF_TO_NETDEV(vap->iv_ifp);
        osif_dev  *osifp = ath_netdev_priv(dev);
        ieee80211_iterate_vap_list_internal(ic, ieee80211_vap_resetdeschan,vap,num_vaps);
        wlan_iterate_vap_list(wlan_vap_get_devhandle(vap), osif_bringdown_vap_iter_func, NULL);
        vap->iv_des_chan[vap->iv_des_mode] = IEEE80211_CHAN_ANYC;
        wlan_autoselect_register_event_handler(vap,
                &osif_bkscan_acs_event_handler, (void *)osifp);
        wlan_autoselect_find_infra_bss_channel(vap);

    } else if(acs_ctrlflags & ACS_PEREODIC_OBSS_CHK){
        enum ieee80211_phymode des_mode = wlan_get_desired_phymode(vap);
        /* Check only for HT40 or HT20  do not change channel */
        if (((des_mode == IEEE80211_MODE_11NG_HT40PLUS) ||
                    (des_mode == IEEE80211_MODE_11NG_HT40MINUS) ||
                    (des_mode == IEEE80211_MODE_11NG_HT40)) && wlan_coext_enabled(vap)) {
#ifdef QCA_PARTNER_PLATFORM
        vap->iv_list_scanning = 1;
#endif
            qdf_sched_work((qdf_handle_t)vap, &(wlan_vap_get_devhandle(vap))->ic_obss_scan_work);
        }
    }
}



static void
dump_11_key(struct seq_file *m, const char *type, struct ieee80211_node *ni, struct ieee80211_key *k)
{
    int i;
    if (!k->wk_valid)
        return;
    seq_printf(m, "%s %s flg:0x%x hw_keyix:%d",
               ether_sprintf(ni->ni_macaddr), type, k->wk_flags, k->wk_keyix);
    if (k->wk_cipher)
        seq_printf(m, " ciph:%s", k->wk_cipher->ic_name);
    seq_printf(m, " key:");
    for (i = 0; i < k->wk_keylen && i < 32; ++i)
        seq_printf(m, "%s%02x", (i > 0 && (i % 8) == 0) ? "-" : "", k->wk_key[i]);
    seq_printf(m, "\n");
}

static int
proc_clients_keys_show(struct seq_file *m, void *v)
{
    struct ieee80211vap *vap = (struct ieee80211vap *) (((uint32_t) m->private) & ~0x3);
    struct ieee80211_node *ni;
    static const char *strs[4] = {"wep0","wep1","wep2","wep3"};
    int i;

    for (i = 0; i < 4; ++i) {
      dump_11_key(m, strs[i], vap->iv_bss, &vap->iv_nw_keys[i]);
    }

    LIST_FOREACH(ni, &vap->iv_dump_node_list, ni_dump_list) {
        dump_11_key(m, "ucast", ni, &ni->ni_ucastkey);
        /* ni_persta key is allocated only for IBSS nodes */
        if (ni->ni_persta) {
            for (i = 0; i < 4; ++i) {
                dump_11_key(m, strs[i], ni, &ni->ni_persta->nips_swkey[i]);
            }
        }
    }
    return 0;
}

static int
proc_iv_config_show(struct seq_file *m, void *v)
{
    struct ieee80211vap *vap = (struct ieee80211vap *) m->private;
    struct ieee80211com *ic = vap->iv_ic;

    seq_printf(m, "iv_myaddr: %s\n", ether_sprintf(vap->iv_myaddr));
    seq_printf(m, "iv_hw_addr: %s\n", ether_sprintf(wlan_vap_get_hw_macaddr(vap)));
    {
        int id = 0;
        ATH_GET_VAP_ID(vap->iv_myaddr, ic->ic_myaddr, id);
        seq_printf(m, "vap_id: %d\n", id);
    }
    seq_printf(m, "ic_my_hwaddr: %s\n", ether_sprintf(ic->ic_my_hwaddr));
    seq_printf(m, "ic_myaddr: %s\n", ether_sprintf(ic->ic_myaddr));

#define VAP_UINT_FIELD(x) seq_printf(m, #x ": %u\n", vap->x)

    VAP_UINT_FIELD(iv_unit);
    VAP_UINT_FIELD(iv_debug);
    VAP_UINT_FIELD(iv_opmode);
    VAP_UINT_FIELD(iv_scan_priority_base);
    VAP_UINT_FIELD(iv_create_flags);
    VAP_UINT_FIELD(iv_flags);
    VAP_UINT_FIELD(iv_flags_ext);
    VAP_UINT_FIELD(iv_deleted);
    VAP_UINT_FIELD(iv_active);
    VAP_UINT_FIELD(iv_scanning);
    VAP_UINT_FIELD(iv_smps);
    VAP_UINT_FIELD(iv_ready);
    VAP_UINT_FIELD(iv_standby);
    VAP_UINT_FIELD(iv_cansleep);
    VAP_UINT_FIELD(iv_sw_bmiss);
    VAP_UINT_FIELD(iv_copy_beacon);
    VAP_UINT_FIELD(iv_wapi);
    VAP_UINT_FIELD(iv_sta_fwd);
    VAP_UINT_FIELD(iv_dynamic_mimo_ps);
    VAP_UINT_FIELD(iv_doth);
    VAP_UINT_FIELD(iv_country_ie);
    VAP_UINT_FIELD(iv_wme);
    VAP_UINT_FIELD(iv_dfswait);
#if 0
    VAP_UINT_FIELD(iv_enable_when_dfs_clear);
#endif
    VAP_UINT_FIELD(iv_erpupdate);
    VAP_UINT_FIELD(iv_needs_scheduler);
    VAP_UINT_FIELD(iv_vap_ind);
    VAP_UINT_FIELD(iv_forced_sleep);
    VAP_UINT_FIELD(iv_ap_reject_dfs_chan);

#if 0
    VAP_UINT_FIELD(iv_one_mb_enabled);
    VAP_UINT_FIELD(iv_two_mb_enabled);
    VAP_UINT_FIELD(iv_five_mb_enabled);
#endif

    VAP_UINT_FIELD(iv_state);

    VAP_UINT_FIELD(iv_caps);
    VAP_UINT_FIELD(iv_ath_cap);
    VAP_UINT_FIELD(iv_chanchange_count);
    VAP_UINT_FIELD(iv_mcast_rate);
    VAP_UINT_FIELD(iv_mcast_fixedrate);
    VAP_UINT_FIELD(iv_node_count);
    VAP_UINT_FIELD(iv_unicast_counterm.mic_count_in_60s);
    VAP_UINT_FIELD(iv_unicast_counterm.timestamp);
    VAP_UINT_FIELD(iv_multicast_counterm.mic_count_in_60s);
    VAP_UINT_FIELD(iv_multicast_counterm.timestamp);
    VAP_UINT_FIELD(iv_max_aid);
    VAP_UINT_FIELD(iv_sta_assoc);
    VAP_UINT_FIELD(iv_ps_sta);
    VAP_UINT_FIELD(iv_ps_pending);
#if 0
    VAP_UINT_FIELD(iv_bad_count_ps_pending_underflow);
    VAP_UINT_FIELD(iv_bad_count_tim_bitmap_empty);
#endif

    VAP_UINT_FIELD(iv_dtim_period);
    VAP_UINT_FIELD(iv_dtim_count);
    VAP_UINT_FIELD(iv_atim_window);
    VAP_UINT_FIELD(iv_tim_len);
    VAP_UINT_FIELD(iv_rtsthreshold);
    VAP_UINT_FIELD(iv_fragthreshold);
    VAP_UINT_FIELD(iv_def_txkey);
    VAP_UINT_FIELD(iv_num_privacy_filters);
    VAP_UINT_FIELD(iv_pmkid_count);
    VAP_UINT_FIELD(iv_wps_mode);
    VAP_UINT_FIELD(iv_wep_mbssid);

    VAP_UINT_FIELD(iv_des_mode);
    VAP_UINT_FIELD(iv_des_modecaps);
    VAP_UINT_FIELD(iv_cur_mode);
    VAP_UINT_FIELD(iv_des_ibss_chan);
    VAP_UINT_FIELD(iv_rateCtrlEnable);
    VAP_UINT_FIELD(iv_des_nssid);

    VAP_UINT_FIELD(iv_bmiss_count);
    VAP_UINT_FIELD(iv_bmiss_count_for_reset);
    VAP_UINT_FIELD(iv_bmiss_count_max);

    VAP_UINT_FIELD(iv_keep_alive_timeout);
    VAP_UINT_FIELD(iv_inact_count);
    VAP_UINT_FIELD(iv_smps_rssithresh);
    VAP_UINT_FIELD(iv_smps_datathresh);

    /* country ie data */
    VAP_UINT_FIELD(iv_country_ie_chanflags);

    /* U-APSD Settings */
    VAP_UINT_FIELD(iv_uapsd);
    VAP_UINT_FIELD(iv_wmm_enable);
    VAP_UINT_FIELD(iv_wmm_power_save);

    VAP_UINT_FIELD(iv_disable_HTProtection);
    VAP_UINT_FIELD(iv_ht40_intolerant);
    VAP_UINT_FIELD(iv_chwidth);
    VAP_UINT_FIELD(iv_chextoffset);
    VAP_UINT_FIELD(iv_chscaninit);

    VAP_UINT_FIELD(iv_ccmpsw_seldec);
    VAP_UINT_FIELD(iv_mgt_rate);
#ifdef ATH_SUPPORT_TxBF
    VAP_UINT_FIELD(iv_txbfmode);
#endif

    VAP_UINT_FIELD(iv_vhtsubfer);
    VAP_UINT_FIELD(iv_vhtsubfee);
    VAP_UINT_FIELD(iv_vhtmubfer);
    VAP_UINT_FIELD(iv_vhtmubfee);
    VAP_UINT_FIELD(iv_implicitbf);

    return 0;
}

int ol_print_scan_config(wlan_if_t vaphandle, struct seq_file *m);

static int
proc_scan_config_show(struct seq_file *m, void *v)
{
    struct ieee80211vap *vap = (struct ieee80211vap *) m->private;
    struct ieee80211com *ic = vap->iv_ic;
    ieee80211_scanner_t ss = ic->ic_scanner;

    if (ss) {
        /* Calls DA or offload print scan
         * function accordingly.
         */
        ic->ic_print_scan_config(vap, m);
    }

    seq_printf(m, "bg_scan_enabled: %d\n", (vap->iv_flags & IEEE80211_F_BGSCAN) ? 1 : 0);
    return 0;
}

static int
proc_clients_rates_show(struct seq_file *m, void *v)
{
    struct ieee80211vap *vap = (struct ieee80211vap *) (((uint32_t) m->private) & ~0x3);
    struct ieee80211_node *ni;
    struct ieee80211_node_table *nt = (struct ieee80211_node_table *) &vap->iv_ic->ic_sta;
    rwlock_state_t lock_state;
    OS_BEACON_DECLARE_AND_RESET_VAR(flags);

    IEEE80211_VAP_LOCK(vap);
    OS_BEACON_READ_LOCK(&nt->nt_nodelock, &lock_state, flags);
    TAILQ_FOREACH(ni, &nt->nt_node, ni_list) {
        if (ni->ni_vap == vap &&
            (0 != memcmp(vap->iv_myaddr, ni->ni_macaddr, IEEE80211_ADDR_LEN))) {
            struct ieee80211_rateset *rs= &(ni->ni_rates);
            int i;

            seq_printf(m, "entry mac=%s\n", ether_sprintf(ni->ni_macaddr));
            seq_printf(m, "rate_info:\n");

            for (i=0; i < (rs->rs_nrates); i++)
              seq_printf(m, " RateIndex[%d], %d\n", i,
                         rs->rs_rates[i] & IEEE80211_RATE_VAL);

        }
    }
    OS_BEACON_READ_UNLOCK(&nt->nt_nodelock, &lock_state, flags);
    IEEE80211_VAP_UNLOCK(vap);

    return 0;
}

struct osif_proc_info {
    const char *name;
    struct file_operations *ops;
    int extra;
};

#define PROC_FOO(func_base, extra) { #func_base, &proc_ieee80211_##func_base##_ops, extra }

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#define GENERATE_PROC_STRUCTS(func_base)				\
	static int proc_##func_base##_open(struct inode *inode, \
					   struct file *file)		\
	{								\
		struct proc_dir_entry *dp = PDE(inode);			\
		return single_open(file, proc_##func_base##_show, dp->data); \
	}								\
									\
	static struct file_operations proc_ieee80211_##func_base##_ops = { \
		.open		= proc_##func_base##_open,	\
		.read		= seq_read,				\
		.llseek		= seq_lseek,				\
		.release	= single_release,			\
	};
#else
#define GENERATE_PROC_STRUCTS(func_base)				\
	static int proc_##func_base##_open(struct inode *inode, \
					   struct file *file)		\
	{								\
        return single_open(file, proc_##func_base##_show, PDE_DATA(inode)); \
    } \
									\
									\
	static struct file_operations proc_ieee80211_##func_base##_ops = { \
		.open		= proc_##func_base##_open,	\
		.read		= seq_read,				\
		.llseek		= seq_lseek,				\
		.release	= single_release,			\
	};
#endif

GENERATE_PROC_STRUCTS(clients_keys);
GENERATE_PROC_STRUCTS(clients_rates);
GENERATE_PROC_STRUCTS(iv_config);
GENERATE_PROC_STRUCTS(scan_config);

const struct osif_proc_info osif_proc_infos[] = {
    PROC_FOO(clients_keys, 0),
    PROC_FOO(clients_rates, 0),
    PROC_FOO(iv_config, 0),
    PROC_FOO(scan_config, 0),
};

#define NUM_PROC_INFOS (sizeof(osif_proc_infos) / sizeof(osif_proc_infos[0]))

void
ieee80211_proc_vattach(struct ieee80211vap *vap)
{
    char *devname = NULL;

    /*
     * Reserve space for the device name outside the net_device structure
     * so that if the name changes we know what it used to be.
     */
    devname = kmalloc((strlen(((osif_dev *)vap->iv_ifp)->netdev->name) + 1) * sizeof(char), GFP_KERNEL);
    if (devname == NULL) {
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: no memory for VAP name!\n", __func__);
        return;
    }
    if (strlcpy(devname, ((osif_dev *)vap->iv_ifp)->netdev->name,
            strlen(((osif_dev *)vap->iv_ifp)->netdev->name) + 1) >= strlen(((osif_dev *)vap->iv_ifp)->netdev->name) + 1) {
        qdf_print("source too long\n");
        goto entry_creation_failed;
        return ;
    }
    vap->iv_proc = proc_mkdir(devname, NULL);
    if (vap->iv_proc) {
      	int i;
        for (i = 0; i < NUM_PROC_INFOS; ++i) {
            struct proc_dir_entry *entry;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
            entry = proc_create(osif_proc_infos[i].name,
                                      0644, vap->iv_proc, (const struct file_operations *) osif_proc_infos[i].ops);
#else
            entry = create_proc_entry(osif_proc_infos[i].name,
                                       0644, vap->iv_proc);
#endif
            if (entry == NULL) {
                QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: Proc Entry creation failed!\n", __func__);
                goto entry_creation_failed;
            }

            entry->data = vap;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
            entry->proc_fops = osif_proc_infos[i].ops;
#endif
        }
    }
entry_creation_failed:
    kfree(devname);

}

void
ieee80211_proc_vdetach(struct ieee80211vap *vap)
{
    if (vap->iv_proc) {
        int i;
        for (i = 0; i < NUM_PROC_INFOS; ++i)
            remove_proc_entry(osif_proc_infos[i].name, vap->iv_proc);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
        remove_proc_entry(vap->iv_proc->name, vap->iv_proc->parent);
#else
        proc_remove(vap->iv_proc);
#endif
        vap->iv_proc = NULL;

    }
}

int
ath_get_radio_index(struct net_device *netdev)
{
    if (!qdf_mem_cmp(netdev->name, "wifi0", 5)) {
        return 0;
    } else if (!qdf_mem_cmp(netdev->name, "wifi1", 5)) {
        return 1;
    } else if (!qdf_mem_cmp(netdev->name, "wifi2", 5)) {
        return 2;
    } else {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Error: Could not match the device name : %s\n", netdev->name);
        return -1;
    }
}
EXPORT_SYMBOL(ath_get_radio_index);
int
asf_adf_attach(void)
{
    static int first = 1;

    /*
     * Configure the shared asf_amem and asf_print instances with ADF
     * function pointers for mem alloc/free, lock/unlock, and print.
     * (Do this initialization just once.)
     */
    if (first) {
        first = 0;

        qdf_spinlock_create(&asf_amem_lock);
        asf_amem_setup(
            (asf_amem_alloc_fp) qdf_mem_alloc_outline,
            (asf_amem_free_fp) qdf_mem_free_outline,
            (void *) NULL,
            (asf_amem_lock_fp) qdf_spin_lock_bh_outline,
            (asf_amem_unlock_fp) qdf_spin_unlock_bh_outline,
            (void *) &asf_amem_lock);
        qdf_spinlock_create(&asf_print_lock);
        asf_print_setup(
            (asf_vprint_fp) qdf_vprint,
            (asf_print_lock_fp) qdf_spin_lock_bh_outline,
            (asf_print_unlock_fp) qdf_spin_unlock_bh_outline,
            (void *) &asf_print_lock);
    }

    return EOK;
}
EXPORT_SYMBOL(asf_adf_attach);

#ifndef REMOVE_PKT_LOG
struct ath_pktlog_funcs *g_pktlog_funcs = NULL;
struct ath_pktlog_rcfuncs *g_pktlog_rcfuncs = NULL;
struct ol_pl_os_dep_funcs *g_ol_pl_os_dep_funcs = NULL;

EXPORT_SYMBOL(g_pktlog_funcs);
EXPORT_SYMBOL(g_pktlog_rcfuncs);
EXPORT_SYMBOL(g_ol_pl_os_dep_funcs);

struct ath_softc *
ath_get_softc(struct net_device *dev)
{
    struct ath_softc_net80211 *scn = ath_netdev_priv(dev);
    return (struct ath_softc *)scn->sc_dev;
}
EXPORT_SYMBOL(ath_get_softc);

void (*g_osif_hal_ani)(void *) = NULL;
/*
 * ath_pktlog module passes the ani func here.
 * This func is passed to HAL using the callback registered by qca_da in the below func.
 */
void osif_pktlog_log_ani_callback_register(void *pktlog_ani)
{
    if (g_osif_hal_ani) {
        g_osif_hal_ani(pktlog_ani);
    }
}
EXPORT_SYMBOL(osif_pktlog_log_ani_callback_register);

/* qca_da module registers the HAL function here */
void osif_hal_log_ani_callback_register(void *hal_ani)
{
    g_osif_hal_ani = hal_ani;
}
EXPORT_SYMBOL(osif_hal_log_ani_callback_register);
#endif
#if ATH_SUPPORT_WIFIPOS
#define IEEE80211_SUBIE_COLOCATED_BSSID 0x7
#define MAXBSSID_INDICATOR_DEFAULT      0

/* Function called by VAP iterator that adds active vaps as colocated bssids */
void ieee80211_vap_iter_get_colocated_bss(void *arg, wlan_if_t vap)
{
    /* This function is called iteratively for each active VAP and populate params array */
    /* params[]: subelementId (1octet), num_vaps(1 octet), maxbssidInd (1octect), BSSIDs...(each 6 octets) */
    u_int8_t *params, num_vaps;
    params = (u_int8_t *) arg;
    params[0]=IEEE80211_SUBIE_COLOCATED_BSSID; //Colocated BSSID Subelement ID
    params[2]=MAXBSSID_INDICATOR_DEFAULT; //MaxBSSID Indicator: Default: 0
    /* params[1] contains num_vaps added so far */
    num_vaps = params[1];

    /* If an active vap, add it to correct location in params */
    if (ieee80211_vap_ready_is_set(vap)) {
        /* Position to store this vap: First 3 octets + 6*(Num of Vaps already added) */
        /* Position is always w.r.t params as there could already be non-zero num_vaps(bssids) */
        /* stored in the params array previously or coming into the function */
        memcpy(params+((num_vaps*IEEE80211_ADDR_LEN)+3), vap->iv_myaddr, IEEE80211_ADDR_LEN);
        params[1]++;
    }
}
EXPORT_SYMBOL(ieee80211_vap_iter_get_colocated_bss);
#endif

int
ieee80211_rate_is_valid_basic(struct ieee80211vap *vap, u_int32_t rate)
{
    enum ieee80211_phymode mode = wlan_get_desired_phymode(vap);
    struct ieee80211_rateset *op_rs = &(vap->iv_op_rates[mode]);
    int i;
    int rs_rate,basic_rate;

    /* Find all basic rates */
    for (i=0; i < op_rs->rs_nrates; i++) {
        rs_rate = op_rs->rs_rates[i];
        /* Added this check for 11ng. Since 6,12 and 24 Mbps rates are not showing as basic rate as per the current code*/
        if (vap->iv_disabled_legacy_rate_set) {
            basic_rate = rs_rate & IEEE80211_RATE_VAL;
        } else {
            basic_rate = rs_rate & IEEE80211_RATE_BASIC;
        }
        if (basic_rate) {
            if (rate == ((rs_rate & IEEE80211_RATE_VAL) * 1000)/2) {
                return 1;
            }
        }
    }

    return 0;
}
EXPORT_SYMBOL(ieee80211_rate_is_valid_basic);

#if ATH_SUPPORT_WRAP && DBDC_REPEATER_SUPPORT
void osif_set_primary_radio_event (struct ieee80211com *ic)
{
    osif_dev *osdev;
    struct net_device *dev;
    union iwreq_data wreq;
    wlan_if_t mpsta_vap;
    if (ic->ic_mpsta_vap == NULL) {
       return;
    }
    mpsta_vap = ic->ic_mpsta_vap;

    osdev = (osif_dev *)wlan_vap_get_registered_handle(mpsta_vap);
    dev = OSIF_TO_NETDEV(osdev);
    memset(&wreq, 0, sizeof(wreq));
    wreq.data.flags = IEEE80211_EV_PRIMARY_RADIO_CHANGED;
    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wreq, NULL);
}
#endif

MODULE_DESCRIPTION("Support for Atheros 802.11 wireless LAN cards.");
MODULE_SUPPORTED_DEVICE("Atheros WLAN cards");
#ifdef MODULE_LICENSE
MODULE_LICENSE("Dual BSD/GPL");
#endif

