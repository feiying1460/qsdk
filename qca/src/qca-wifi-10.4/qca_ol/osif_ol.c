/*
 * Copyright (c) 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include "osif_private.h"
#include <wlan_opts.h>
#include <ieee80211_var.h>
#include <ieee80211_extap.h>
#include <ieee80211_api.h>
#include "htc_thread.h"
#include "if_athvar.h"
#include "ieee80211_aponly.h"
#include <ieee80211_acfg.h>
#include <acfg_drv_event.h>
#if MESH_MODE_SUPPORT
#include <if_meta_hdr.h>
#endif

#include <qdf_perf.h>
#include "ath_netlink.h"

#if ATH_BAND_STEERING
#include "ath_band_steering.h"
#endif

#include "ieee80211_ev.h"
#include "ald_netlink.h"
#include <ol_txrx_api.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
#include <fs/proc/internal.h>
#else
#include <linux/proc_fs.h>
#endif

#include <linux/seq_file.h>

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
#include <qdf_nbuf.h> /* qdf_nbuf_map_single */

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
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_if.h>
#include <osif_nss_wifiol_vdev_if.h>
#endif


#if (HOST_SW_LRO_ENABLE && ATH_PERF_PWR_OFFLOAD)
extern void ath_lro_process_skb(struct sk_buff *skb, struct net_device *dev);
extern void ath_lro_flush_all(void *priv);
extern void transcap_nwifi_to_8023(qdf_nbuf_t msdu);
#endif

#if DBDC_REPEATER_SUPPORT
extern int dbdc_rx_process (os_if_t *osif ,struct net_device **dev, struct sk_buff *skb, int *nwifi);
extern int dbdc_tx_process (wlan_if_t vap, osif_dev **osdev , struct sk_buff *skb);
#endif

#if ATH_SUPPORT_WRAP
extern osif_dev * osif_wrap_wdev_find(struct wrap_devt *wdt,unsigned char *mac);
#endif

#if UMAC_VOW_DEBUG
extern void update_vow_dbg_counters(osif_dev  *osifp,
                        qdf_nbuf_t msdu, unsigned long *vow_counter, int rx, int peer);
#endif

#if ATH_EXT_AP
extern int ath_ext_ap_nss_rx_deliver(os_if_t osif,  struct sk_buff * skb, int *nwifi);
#endif

#if QCA_NSS_PLATFORM
extern void osif_send_to_nss(os_if_t osif, struct sk_buff *skb, int nwifi);
#endif

#ifdef QCA_PARTNER_PLATFORM
extern bool osif_pltfrm_deliver_data(os_if_t osif, wbuf_t wbuf);
#endif

#if UMAC_VOW_DEBUG
static inline void
osif_ol_hadrstart_vap_vow_debug(osif_dev  *osdev, struct sk_buff *skb){

    if(osdev->vow_dbg_en) {
        //This needs to be changed if multiple skbs are sent
        struct ether_header *eh = (struct ether_header *)skb->data;
        int i=0;

        for( i = 0; i < MAX_VOW_CLIENTS_DBG_MONITOR; i++ )
        {
            if( eh->ether_dhost[4] == osdev->tx_dbg_vow_peer[i][0] &&
                    eh->ether_dhost[5] == osdev->tx_dbg_vow_peer[i][1] ) {
                update_vow_dbg_counters(osdev, (qdf_nbuf_t) skb, &osdev->tx_dbg_vow_counter[i], 0, i);
                break;
            }
        }
    }
    return;
}

#endif /* UMAC_VOW_DEBUG*/


#if QCA_NSS_PLATFORM
#if UMAC_VOW_DEBUG || UMAC_SUPPORT_VI_DBG
extern int transcap_nwifi_hdrsize(qdf_nbuf_t msdu);
#endif

#if UMAC_VOW_DEBUG
#define VOW_DBG_RX_OFFSET 14
#define VOW_DBG_INVALID_IDX -1
#define    UMAC_VOW_NSSRX_DELIVER_DEBUG(_osif, _skb, _nwifi) \
        {\
            osif_dev  *osifp = (osif_dev *) _osif; \
            int rx_offset =0;\
            if (osifp->vow_dbg_en) { \
                if (_nwifi) { \
                    rx_offset = VOW_DBG_RX_OFFSET - transcap_nwifi_hdrsize(_skb); \
                } \
                update_vow_dbg_counters(osifp, (qdf_nbuf_t)_skb, &osifp->umac_vow_counter, rx_offset, \
                        VOW_DBG_INVALID_IDX); \
            } \
        }
#elif UMAC_SUPPORT_VI_DBG
#define UMAC_VOW_NSSRX_DELIVER_DEBUG(_osif, _skb, _nwifi) \
{\
        osif_dev  *osifp = (osif_dev *) _osif; \
        if (osifp->vi_dbg) { \
                ieee80211_vi_dbg_input(osifp->os_if, _skb); \
        } \
}
#else /* UMAC_VOW_DEBUG */
#define    UMAC_VOW_NSSRX_DELIVER_DEBUG(osif, skb, nwifi)
#endif /* UMAC_VOW_DEBUG */


#if ATH_SUPPORT_VLAN
#if LINUX_VERSION_CODE <  KERNEL_VERSION(3,1,0)
#error "KERNEL_VERSION less then 3.1.0 not supported in NWIFI offload"
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#define ATH_ADD_VLAN_TAG(_osif, _skb) \
{ \
    osif_dev  *osifp = (osif_dev *) _osif; \
    if ( osifp->vlanID != 0) { \
        __vlan_hwaccel_put_tag(_skb, osifp->vlanID); \
    } \
}
#else
#define ATH_ADD_VLAN_TAG(_osif, _skb) \
{ \
    osif_dev  *osifp = (osif_dev *) _osif; \
    if ( osifp->vlanID != 0) { \
        __vlan_hwaccel_put_tag(_skb, htons(ETH_P_8021Q), osifp->vlanID); \
    } \
}
#endif
#else
#define ATH_ADD_VLAN_TAG(_osif, _skb)
#endif /*ATH_SUPPORT_VLAN*/


#endif /* QCA_NSS_PLATFORM*/




#if UMAC_VOW_DEBUG
#define  OL_TX_LL_UMAC_VAP_HARDSTART_VOW_DEBUG(_osdev, _skb) osif_ol_hadrstart_vap_vow_debug(_osdev, _skb)
#elif UMAC_SUPPORT_VI_DBG
#define  OL_TX_LL_UMAC_VAP_HARDSTART_VOW_DEBUG(_osdev, _skb) \
{\
	osif_dev  *osifp = (osif_dev *) _osdev; \
			   if (osifp->vi_dbg) { \
				   ieee80211_vi_dbg_input(osifp->os_if, _skb); \
			   } \
}
#else
#define OL_TX_LL_UMAC_VAP_HARDSTART_VOW_DEBUG(_osdev, _skb)
#endif /* UMAC_VOW_DEBUG */

#if ATH_SUPPORT_WRAP
inline void wrap_tx_bridge ( wlan_if_t *vap , osif_dev **osdev,  struct sk_buff **skb) {

    /* Assuming native wifi or raw mode is not
     * enabled in beeliner, to be revisted later
     */
    struct ether_header *eh = (struct ether_header *) ((*skb)->data);
    wlan_if_t prev_vap = *vap;
    osif_dev *tx_osdev;
    osif_dev *prev_osdev = *osdev;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    void *nss_wifiol_ctx = prev_osdev->nss_wifiol_ctx;
#endif


    /* Mpsta vap here, find the correct tx vap from the wrap common based on src address */
    tx_osdev = osif_wrap_wdev_find(&prev_vap->iv_ic->ic_wrap_com->wc_devt,eh->ether_shost);
    if (tx_osdev) {
        if(qdf_unlikely((IEEE80211_IS_MULTICAST(eh->ether_dhost) || IEEE80211_IS_BROADCAST(eh->ether_dhost)))) {
            *skb = qdf_nbuf_unshare(*skb);
        }
        /* since tx vap gets changed , handle tx vap synchorization */
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        if (!nss_wifiol_ctx)
#endif
        {
            OSIF_VAP_TX_UNLOCK(prev_osdev);
        }
        *vap = tx_osdev->os_if;
        *osdev  = tx_osdev;

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        if (!nss_wifiol_ctx)
#endif
        {
            OSIF_VAP_TX_LOCK(*osdev);
        }
    }
}

#define OL_WRAP_TX_PROCESS(_osdev, _vap, _skb) \
{ \
    if (qdf_unlikely(wlan_is_mpsta(_vap)))   { \
        wrap_tx_bridge (&_vap, _osdev , _skb); \
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

/*
 * osif_ol_wrap_tx_process()
 *  wrap tx process
 */
int
osif_ol_wrap_tx_process(osif_dev **osifp, struct ieee80211vap *vap, struct sk_buff **skb)
{
    /*
     * The below addiitonal check is to make compilation when the ATH_WRAP_TX Macro is disabled.
     * the bad label will come as unused variable
     */
    if (vap == NULL) {
        goto bad;
    }
    OL_WRAP_TX_PROCESS(osifp, vap, skb);
    return 0;
bad :
    return 1;
}
#else /* ATH_SUPPORT_WRAP */

#define OL_WRAP_TX_PROCESS(_osdev, _vap, _skb)
int
osif_ol_wrap_tx_process(osif_dev **osifp, struct ieee80211vap *vap, struct sk_buff **skb)
{
    return 0;
}
#endif /* ATH_SUPPORT_WRAP */


#if ATH_DATA_RX_INFO_EN || MESH_MODE_SUPPORT
u_int32_t osif_rx_status_dump(void* rs)
{
#if ATH_DATA_RX_INFO_EN
    struct per_msdu_data_recv_status *rs1 = rs;
#else
    struct per_msdu_mesh_data_recv_status *rs1 = rs;
    u_int32_t count;
#endif
    u_int32_t rate1 = rs1->rs_ratephy1;
    u_int32_t rate2 = rs1->rs_ratephy2 & 0xFFFFFF;
//    u_int32_t rate3 = rs->rs_ratephy3 & 0x1FFFFFFF;
    u_int32_t rate1_1 = ((rate1 & 0xFFFFFF0) >> 4);

    if(!(rs1->rs_flags & IEEE80211_RX_FIRST_MSDU)){
        /*Only for the 1st msdu, we populate the rx status struct,
          check unified_rx_desc_update_pkt_info() */
        return 0;
    }

    /*We save receive status info in skb->cb[48] after struct cvg_nbuf_cb,
      so we have struct cvg_nbuf_cb + struct per_msdu_data_recv_status in cb.
      Since, sizeof(struct cvg_nbuf_cb)=44, only 48-44=4 bytes left for rs here,
      we only have space to save the 1st int(rs_flags) of the struct per_msdu_data_recv_status.
    */
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: rs_flags=0x%x \n",__FUNCTION__, rs1->rs_flags);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: frame is decrypted=0x%x \n", __FUNCTION__, (rs1->rs_flags & IEEE80211_RX_DECRYPTED)
            ? 1 : 0);


    /*Below fields only valid when skb->cb has enough space to store them*/
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: rs_rssi=0x%x \n",__FUNCTION__, rs1->rs_rssi);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: rs_ratephy1=0x%x \n",__FUNCTION__, rs1->rs_ratephy1);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: rs_ratephy2=0x%x \n",__FUNCTION__, rs1->rs_ratephy2);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: rs_ratephy3=0x%x \n",__FUNCTION__, rs1->rs_ratephy3);

#if MESH_MODE_SUPPORT
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: rs_channel=0x%x \n",__FUNCTION__,  rs1->rs_channel);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: rs_key=",__FUNCTION__);
    for (count = 0; count < 32; count++) {
	    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "0x%x ", rs1->rs_decryptkey[count]);
    }
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n");
#endif

    switch (rate1 & 0xF) // preamble
        {
        case 0: //CCK
            {
                switch(rate1_1) //l_sig_rate
                    {
                    case 0x1:  //long 1M
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "CCK 1 Mbps long preamble\n");
                        break;
                    case 0x2: //long 2M
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "CCK 2 Mbps long preamble\n");
                        break;
                    case 0x3: //long 5.5M
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "CCK 5.5 Mbps long preamble\n");
                        break;
                    case 0x4: //long 11M
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "CCK 11 Mbps long preamble\n");
                        break;
                    case 0x5: //short 2M
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "CCK 2 Mbps short preamble\n");
                        break;
                    case 0x6: //short 5.5M
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "CCK 5.5 Mbps short preamble\n");
                        break;
                    case 0x7: //short 11M
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "CCK 11 Mbps short preamble\n");
                        break;
                    }
            }
            break;
        case 1: //OFDM
            {
                switch(rate1_1) //l_sig_rate
                    {
                    case 0x8:
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "OFDM 48 Mbps\n");
                        break;

                    case 0x9:
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "OFDM 24 Mbps\n");
                        break;

                    case 0xa:
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "OFDM 12 Mbps\n");
                        break;

                    case 0xb:
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "OFDM 6 Mbps\n");
                        break;

                    case 0xc:
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "OFDM 54 Mbps\n");
                        break;

                    case 0xd:
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "OFDM 36 Mbps\n");
                        break;

                    case 0xe:
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "OFDM 18 Mbps\n");
                        break;

                    case 0xf:
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "OFDM 9 Mbps\n");
                        break;
                    }
            }
            break;
        case 2:
            {
                if(rate1_1 & 0x80) //HT40
                    {
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "HT40 MCS%c\n", '0' + (rate1_1 & 0x1f));
                    }
                else // HT20
                    {
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "HT20 MCS%c\n", '0' + (rate1_1 & 0x1f));
                    }
            }
            break;
        case 3:
            switch (rate1_1 & 0x3)
                {
                case 0x0: // VHT20
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "VHT20 NSS%c MCS%c\n", '1' + ((rate1_1 >> 10) & 0x3),
                           '0' + ((rate2 >> 4) & 0xf));

                    break;

                case 0x1: // VHT40
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "VHT40 NSS%c MCS%c\n", '1' + ((rate1_1 >> 10) & 0x3),
                           '0' + ((rate2 >> 4) & 0xf));

                    break;

                case 0x2: // VHT80
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "VHT80 NSS%c MCS%c\n", '1' + ((rate1_1 >> 10) & 0x3),
                           '0' + ((rate2 >> 4) & 0xf));

                    break;
                }
            break;
        }
    return 0;
}
#endif /*end of ATH_DATA_RX_INFO_EN*/



#if QCA_NSS_PLATFORM
void
osif_deliver_data_ol(os_if_t osif, struct sk_buff *skb_list)
{
    struct net_device *dev = OSIF_TO_NETDEV(osif);
    osif_dev  *osdev = (osif_dev *)osif;
    int nwifi = ((osif_dev *)osif)->nss_nwifi;

#if ATH_SUPPORT_WRAP
    wlan_if_t vap = osdev->os_if;
#endif

#if QCA_OL_VLAN_WAR
    struct net_device *comdev;
    struct ol_ath_softc_net80211 *scn;
    struct ether_header *eh;
    comdev = ((osif_dev *)osif)->os_comdev;
    scn = ath_netdev_priv(comdev);
#endif /* QCA_OL_VLAN_WAR */

    while (skb_list) {
        struct sk_buff *skb;
        skb = skb_list;
        skb_list = skb_list->next;
        skb->dev = dev;
        skb->next = NULL;

#if QCA_OL_VLAN_WAR
	eh = (struct ether_header *)(skb->data);

	/* For VLAN, remove the extra two bytes of length field inserted by OLE.
	 * This is standard behavior for OLE RX any format that looks weird
	 * it keeps it in 802.3 format as that preserves all the information.
	 * Frame Format : {dst_addr[6], src_addr[6], 802.1Q header[4], EtherType[2], Payload}
	 * Example :
	 * Before Removal : xx xx xx xx xx xx xx xx xx xx xx xx 81 00 00 02 00 4e 08 00 45 00 00...
	 * After Removal  : xx xx xx xx xx xx xx xx xx xx xx xx 81 00 00 02 08 00 45 00 00...
	 */

	if (htons(eh->ether_type) == ETH_P_8021Q) {
	    transcap_dot3_to_eth2(skb);

	}
#endif /* QCA_OL_VLAN_WAR */

#if ATH_DATA_RX_INFO_EN
        if (qdf_nbuf_get_ftype(skb) == CB_FTYPE_RX_INFO)
        /*
         * provide callback to collect rx_status here if required.
         * The data will no longer be available after this point
         */
            osif_rx_status_dump((void *)qdf_nbuf_get_fctx(skb));
#elif MESH_MODE_SUPPORT
        if ((vap->mdbg & 0x2) && (qdf_nbuf_get_ftype(skb) == CB_FTYPE_MESH_RX_INFO)) {
        /*
         * provide callback to collect rx_status here if required.
         * The data will no longer be available after this point
         */
            osif_rx_status_dump((void *)qdf_nbuf_get_fctx(skb));
        }
#endif

#if ATH_DATA_RX_INFO_EN
        if (qdf_nbuf_get_ftype(skb) == CB_FTYPE_RX_INFO){
            qdf_mem_free((void *)qdf_nbuf_get_fctx(skb));
            qdf_nbuf_set_fctx_type(skb, 0, CB_FTYPE_INVALID);
        }
#elif MESH_MODE_SUPPORT
        if (qdf_nbuf_get_ftype(skb) == CB_FTYPE_MESH_RX_INFO) {
            qdf_mem_free((void *)qdf_nbuf_get_fctx(skb));
            qdf_nbuf_set_fctx_type(skb, 0, CB_FTYPE_INVALID);
       }
#endif

#if ATH_SUPPORT_WRAP
        if(OL_WRAP_RX_PROCESS(&osif, &dev, vap, skb, &nwifi))
            continue;
#endif

        UMAC_VOW_NSSRX_DELIVER_DEBUG(osif, skb, nwifi);

        if(ath_ext_ap_nss_rx_deliver(osif, skb, &nwifi))
            continue;
#if DBDC_REPEATER_SUPPORT
        if(dbdc_rx_process(&osif, &dev, skb, &nwifi))
            continue;
#endif

#ifdef QCA_PARTNER_PLATFORM
        if ( osif_pltfrm_deliver_data (osif, skb))
            continue;
#endif

	ATH_ADD_VLAN_TAG(osif, skb)

#if HOST_SW_LRO_ENABLE
        if (dev->features & NETIF_F_LRO) /* LRO is enabled via ethtool */
        {
        if (nwifi) {
           transcap_nwifi_to_8023(skb);
        }
            skb->protocol = eth_type_trans(skb, dev);
            ath_lro_process_skb(skb,dev);
	    continue;
	}
#endif  /* HOST_SW_LRO_ENABLE */

        osif_send_to_nss(osif, skb, nwifi);
    }

#if HOST_SW_LRO_ENABLE
    if ((dev->features & NETIF_F_LRO) || osdev->os_if->lro_to_flush) {
        ath_lro_flush_all(dev);         /* flush all LRO pkts */
    }
#endif /* HOST_SW_LRO_ENABLE */

    dev->last_rx = jiffies;
}
#else /*QCA_NSS_PLATFORM*/
void
osif_deliver_data_ol(os_if_t osif, struct sk_buff *skb_list)
{
    struct net_device *dev = OSIF_TO_NETDEV(osif);
#if ATH_SUPPORT_VLAN || UMAC_VOW_DEBUG
    osif_dev  *osifp = (osif_dev *) osif;
#endif
#if defined(ATH_EXT_AP) || ATH_SUPPORT_WRAP || HOST_SW_LRO_ENABLE
    osif_dev  *osdev = (osif_dev *)osif;
    wlan_if_t vap = osdev->os_if;
#endif
#if ATH_RXBUF_RECYCLE
    struct net_device *comdev;
    struct ath_softc_net80211 *scn;
    struct ath_softc *sc;
#endif /* ATH_RXBUF_RECYCLE */

    int nwifi = ((osif_dev *)osif)->nss_nwifi;
#if QCA_OL_VLAN_WAR
    struct net_device *comdev_war;
    struct ol_ath_softc_net80211 *scn_war;
    comdev_war = ((osif_dev *)osif)->os_comdev;
    scn_war = ath_netdev_priv(comdev_war);
#endif /* QCA_OL_VLAN_WAR */

#if ATH_RXBUF_RECYCLE
    comdev = ((osif_dev *)osif)->os_comdev;
    scn = ath_netdev_priv(comdev);
    sc = ATH_DEV_TO_SC(scn->sc_dev);
#endif /* ATH_RXBUF_RECYCLE */

    while (skb_list) {
        struct sk_buff *skb;
#if QCA_OL_VLAN_WAR
        u_int16_t typeorlen;
#endif

        skb = skb_list;
        skb_list = skb_list->next;

        skb->dev = dev;
        /*
         * SF#01368954
         * Thanks to customer for the fix.
         *
         * Each skb of the list is delivered to the OS.
         * Thus, we need to unlink each skb.
         * Otherwise, the OS processes the linked skbs, as well,
         * which results in sending the same skb twice to the LAN driver.
         * This, also leads to unpredictable frame drops.
         * Note that this (most likely) only occurs when sending frames
         * using dev_queue_xmit().
         * Delivering linked skbs through netif_rx() seems not to be a problem.
         */
        skb->next = NULL;

#if ATH_DATA_RX_INFO_EN
        if (qdf_nbuf_get_ftype(skb) == CB_FTYPE_RX_INFO)
        /*
         * provide callback to collect rx_status here if required.
         * The data will no longer be available after this point
         */
            osif_rx_status_dump((void *)qdf_nbuf_get_fctx(skb));
#elif MESH_MODE_SUPPORT
        if ((vap->mdbg & 0x2) && (qdf_nbuf_get_ftype(skb) == CB_FTYPE_MESH_RX_INFO)) {
        /*
         * provide callback to collect rx_status here if required.
         * The data will no longer be available after this point
         */
            osif_rx_status_dump((void *)qdf_nbuf_get_fctx(skb));
        }
#endif

#if ATH_DATA_RX_INFO_EN
        if (qdf_nbuf_get_ftype(skb) == CB_FTYPE_RX_INFO){
            qdf_mem_free((void *)qdf_nbuf_get_fctx(skb));
            qdf_nbuf_set_fctx_type(skb, 0, CB_FTYPE_INVALID);
       }
#elif MESH_MODE_SUPPORT
       if (qdf_nbuf_get_ftype(skb) == CB_FTYPE_MESH_RX_INFO) {
            qdf_mem_free((void *)qdf_nbuf_get_fctx(skb));
            qdf_nbuf_set_fctx_type(skb, 0, CB_FTYPE_INVALID);
       }
#endif

#if QCA_OL_VLAN_WAR
       typeorlen = ntohs(*(u_int16_t *)(skb->data + IEEE80211_ADDR_LEN * 2));
       /* For VLAN, remove the extra two bytes of length field inserted by OLE.
	* This is standard behavior for OLE RX any format that looks weird
	* it keeps it in 802.3 format as that preserves all the information.
	*/
       if (typeorlen == ETH_P_8021Q) {
	   transcap_dot3_to_eth2(skb);
       }
#endif /* QCA_OL_VLAN_WAR */

    if(OL_WRAP_RX_PROCESS(&osif, &dev, vap, skb, &nwifi))
            return;

    if(ATH_RX_EXT_AP_PROCESS(vap, skb, &nwifi)){
                qdf_nbuf_free(skb);
                return;
            }
#if DBDC_REPEATER_SUPPORT
    if(dbdc_rx_process(&osif, &dev, skb, &nwifi))
       continue;
#endif

#ifdef HOST_OFFLOAD
        /* For the Full Offload solution, diverting the data packet into the
           offload stack for further processing and hand-off to Host processor */
        atd_rx_from_wlan(skb);
        continue;
#endif

#ifdef QCA_PARTNER_PLATFORM
        if ( osif_pltfrm_deliver_data (osif, skb))
            continue;
#endif

#ifdef USE_HEADERLEN_RESV
        skb->protocol = ath_eth_type_trans(skb, dev);
#else
        skb->protocol = eth_type_trans(skb, dev);
#endif

#if ATH_RXBUF_RECYCLE
	    /*
	     * Do not recycle the received mcast frame b/c it will be cloned twice
	     */
        if (sc->sc_osdev->rbr_ops.osdev_wbuf_collect && !(wbuf_is_cloned(skb)))
        {
            sc->sc_osdev->rbr_ops.osdev_wbuf_collect((void *)sc, (void *)skb);
        }
#endif /* ATH_RXBUF_RECYCLE */

#if UMAC_VOW_DEBUG
#define VOW_DBG_RX_OFFSET 14 /*RX packet ethernet header is stripped off. Need to adjust offset accordingly*/
#define VOW_DBG_INVALID_IDX -1
        if(osifp->vow_dbg_en) {
            update_vow_dbg_counters(osifp, (qdf_nbuf_t)skb, &osifp->umac_vow_counter, VOW_DBG_RX_OFFSET,
                    VOW_DBG_INVALID_IDX);
        }
#endif

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
        else  /*XXX NOTE- There is an else here. Be careful while adding any code below */
#endif
#endif

#if HOST_SW_LRO_ENABLE
        if (dev->features & NETIF_F_LRO) /* LRO is enabled via ethtool */
        {
            ath_lro_process_skb(skb,dev);
            continue;
	}
#endif  /* HOST_SW_LRO_ENABLE */

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
    }

#if HOST_SW_LRO_ENABLE
    if ((dev->features & NETIF_F_LRO) || osdev->os_if->lro_to_flush) {
        ath_lro_flush_all(dev);         /* flush all LRO pkts */
    }
#endif /* HOST_SW_LRO_ENABLE */

    dev->last_rx = jiffies;
}
#endif /*QCA_NSS_PLATFORM*/


#if MESH_MODE_SUPPORT
extern int add_mesh_meta_hdr(qdf_nbuf_t nbuf, struct ieee80211vap *vap);
#endif

#if WLAN_FEATURE_FASTPATH
/*
 * TODO: Move this to a header file
 */
extern void
ol_tx_stats_inc_map_error(ol_txrx_vdev_handle vdev,
                             uint32_t num_map_error);

#ifdef QCA_PARTNER_PLATFORM
extern void
ol_tx_stats_inc_pkt_cnt(ol_txrx_vdev_handle vdev);
#else
extern void
ol_tx_stats_inc_pkt_cnt(ol_txrx_vdev_handle vdev)
                    __attribute__((always_inline));
#endif


/*
 * OS entry point for Fast Path 11AC offload data-path
 * NOTE : It is unlikely that we need lock protection
 * here, since we are called under OS lock (HARD_TX_LOCK()))
 * in linux. So this function is can be called by a single
 * at a given instance of time.

 * TODO : This function does not implement full fledged packet
 * batching. This function receives a single packet and calls
 * the underlying API. The subsequent OL layer API's however,
 * can operate on batch of packets and hence is provided a packet
 * array (special case, array size = 1).
 */
int
osif_ol_ll_vap_hardstart(struct sk_buff *skb, struct net_device *dev)
{


    osif_dev  *osdev ;
    wlan_if_t vap ;

#if QCA_OL_VLAN_WAR
    struct net_device *comdev;
    struct ol_ath_softc_net80211 *scn;
#endif /* QCA_OL_VLAN_WAR */
#if QCA_PARTNER_DIRECTLINK_TX || QCA_AIRTIME_FAIRNESS
    struct ether_header *eh;
#endif

#if QCA_AIRTIME_FAIRNESS
    struct ieee80211_node *ni = NULL;
    struct ieee80211com *ic = NULL;
    struct ol_ath_softc_net80211 *pscn = NULL;
#endif

    qdf_nbuf_count_inc(skb);
    if (qdf_unlikely((dev->flags & (IFF_RUNNING|IFF_UP)) != (IFF_RUNNING|IFF_UP))) {
	    goto bad1;
    }

    osdev = ath_netdev_priv(dev);
    vap = osdev->os_if;

#if MESH_MODE_SUPPORT
    if (vap->iv_mesh_vap_mode && (vap->mdbg & 0x1)) {
        if (OL_CFG_NONRAW_TX_LIKELINESS(vap->iv_tx_encap_type != osif_pkt_type_raw)) {
            if(add_mesh_meta_hdr(skb, vap)) {
                goto bad;
            }
        }
    }
#endif

#if QCA_AIRTIME_FAIRNESS
    ic = vap->iv_ic;
    pscn = (struct ol_ath_softc_net80211 *)ic;
    if(ic->atf_mode && (pscn->target_type == TARGET_TYPE_AR9888 &&
                            pscn->target_version == AR9888_REV2_VERSION)) {
        if(vap->iv_block_tx_traffic == 1)
        {
            goto bad1;
        }
        if(vap->tx_blk_cnt) {
            eh = (struct ether_header *)(wbuf_header(skb) + vap->mhdr_len);
            ni = ieee80211_find_txnode(vap, eh->ether_dhost);
            if(ni && ni->ni_block_tx_traffic) {
                ieee80211_free_node(ni);
                goto bad1;
            } else if(ni) {
                ieee80211_free_node(ni);
            }
        }
    }
#endif

#if QCA_OL_VLAN_WAR
    comdev = osdev->os_comdev;
    scn = ath_netdev_priv(comdev);
#endif /* QCA_OL_VLAN_WAR */

#if UMAC_SUPPORT_WNM
    if (wlan_wnm_tfs_filter(vap, (wbuf_t) skb)) {
        goto bad1;
    }
#endif
    OSIF_VAP_TX_LOCK(osdev);

    if ((!osdev->is_up ) ||
         (!ieee80211_vap_ready_is_set(vap)) ||
          (IEEE80211_IS_CHAN_RADAR(vap->iv_bsschan))) {
        OSIF_VAP_TX_UNLOCK(osdev);
        goto bad1;
    }

    /* Update packet count */
    /* Note: it is for the user to use skb_unshare with caution */

    /*
     * Comment this for now and re-enable after debug
     */
   /* ol_tx_stats_inc_pkt_cnt(osdev->iv_txrx_handle); */

#if QCA_PARTNER_DIRECTLINK_TX
    if (qdf_unlikely(osdev->is_directlink)) {
#if !ATH_MCAST_HOST_INSPECT
        eh = (struct ether_header *)(skb->data) + vap->mhdr_len;
        if (IEEE80211_IS_IPV4_MULTICAST((eh)->ether_dhost) || IEEE80211_IS_IPV6_MULTICAST((eh)->ether_dhost)) {
            if (ol_tx_mcast_enhance_process( vap, skb) > 0 ){
                goto out;
            }
        }
#endif
        {
            OSIF_VAP_TX_UNLOCK(osdev);
            ol_tx_partner(skb, dev, HTT_INVALID_PEER);
            return 0;
        }
    } else
#endif /* QCA_PARTNER_DIRECTLINK_TX */

{
    if (OL_CFG_RAW_TX_LIKELINESS(vap->iv_tx_encap_type == osif_pkt_type_raw)) {
        /* In Raw Mode, the payload normally comes encrypted by an external
         * Access Controller and we won't have the keys. Besides, the format
         * isn't 802.3/Ethernet II.
         * Hence, VLAN WAR, Ext AP functionality, VoW debug and Multicast to
         * Unicast conversion aren't applicable, and are skipped.
         *
         * Additionally, TSO and nr_frags based scatter/gather are currently
         * not required and thus not supported with Raw Mode.
         *
         * Error conditions are handled internally by the below function.
         */
        OL_TX_LL_UMAC_RAW_PROCESS(dev, &skb);
        goto out;
    }
#if MESH_MODE_SUPPORT
    if (!vap->iv_mesh_vap_mode) {
#endif
#if DBDC_REPEATER_SUPPORT
        if(dbdc_tx_process(vap,&osdev,skb)) {
            OSIF_VAP_TX_UNLOCK(osdev);
            return 0;
        }
#endif

        /* Raw mode or native wifi mode not
         * supported in qwrap , revisit later
         */
        OL_WRAP_TX_PROCESS(&osdev,vap,&skb);

        if(ATH_TX_EXT_AP_PROCESS(vap, &skb))
            goto bad;

#if QCA_OL_VLAN_WAR
	if(OL_TX_VLAN_WAR(&skb, scn))
	    goto bad;
#endif /* QCA_OL_VLAN_WAR */

        skb->next = NULL;

        OL_TX_LL_UMAC_VAP_HARDSTART_VOW_DEBUG(osdev, skb);

#if MESH_MODE_SUPPORT
    }
#endif


    osdev->iv_vap_send(osdev->iv_txrx_handle, skb);

out:
    OSIF_VAP_TX_UNLOCK(osdev);
    return 0;
}

bad:
    OSIF_VAP_TX_UNLOCK(osdev);
bad1:
    if (skb != NULL)
        qdf_nbuf_free(skb);
    return 0;
}

#endif /* WLAN_FEATURE_FASTPATH */

#if ATH_PERF_PWR_OFFLOAD
#if UMAC_SUPPORT_PROXY_ARP
extern int do_proxy_arp(wlan_if_t vap, qdf_nbuf_t netbuf);
#endif /* UMAC_SUPPORT_PROXY_ARP */
extern void osif_receive_monitor_80211_base (os_if_t osif, wbuf_t wbuf,
                                        ieee80211_recv_status *rs);


#if UMAC_SUPPORT_PROXY_ARP
int
osif_proxy_arp_ol(os_if_t osif, qdf_nbuf_t netbuf)
{
    osif_dev  *osdev = (osif_dev *)osif;
    wlan_if_t vap = osdev->os_if;

    return(do_proxy_arp(vap, netbuf));
}
#endif /* UMAC_SUPPORT_PROXY_ARP */

#if ATH_SUPPORT_WAPI
extern bool osif_wai_check(os_if_t osif,
                struct sk_buff *skb_list_head, struct sk_buff *skb_list_tail);
#endif /* ATH_SUPPORT_WAPI */

void osif_vap_setup_ol (struct ieee80211vap *vap, osif_dev *osifp) {
        struct ol_txrx_ops ops;

        /*
         * Get vdev data handle for all down calls to offload data path.
         */
        osifp->iv_txrx_handle = wlan_vap_get_ol_data_handle(vap);
        if (!osifp->iv_txrx_handle) {
            IEEE80211_DPRINTF(
                vap, IEEE80211_MSG_ANY, "%s : Bad ol_data_handle\n", __func__);
            return;
        }
        /*
         * This function registers rx and monitor functions,
         * and a callback handle.
         * It fills in the transmit handler to be called from shim.
         */
        ops.rx.rx = (ol_txrx_rx_fp) osif_deliver_data_ol;
#if ATH_SUPPORT_WAPI
        ops.rx.wai_check = (ol_txrx_rx_check_wai_fp) osif_wai_check;
#endif
        ops.rx.mon = (ol_txrx_rx_mon_fp) osif_receive_monitor_80211_base;
#if UMAC_SUPPORT_PROXY_ARP
        ops.proxy_arp = (ol_txrx_proxy_arp_fp) osif_proxy_arp_ol;
#endif
        ol_txrx_vdev_register(
            osifp->iv_txrx_handle, (void *) osifp, &ops);
        osifp->iv_vap_send = ops.tx.tx;

        /* Override the Tx lock for OL with OL specific lock */
        osifp->tx_dev_lock_acquire = ol_ath_vap_tx_lock;
        osifp->tx_dev_lock_release = ol_ath_vap_tx_unlock;

        osifp->nss_nwifi = OL_TXRX_GET_NWIFI_MODE(osifp->iv_txrx_handle);
        osifp->is_ar900b = OL_TXRX_IS_TARGET_AR900B(osifp->iv_txrx_handle);
        return;
}
#endif /* ATH_PER_PWR_OFFLOAD */



#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
int osif_nss_ol_ext_ap_rx(struct net_device *dev, struct sk_buff *skb)
{
    osif_dev  *osdev ;
    wlan_if_t vap ;

    int nwifi;
    osdev = ath_netdev_priv(dev);
    vap = osdev->os_if;
    nwifi = osdev->nss_nwifi;
    return ATH_RX_EXT_AP_PROCESS(vap, skb, &nwifi);
}

int osif_nss_ol_ext_ap_tx(struct net_device *dev, struct sk_buff *skb)
{
    osif_dev  *osdev ;
    wlan_if_t vap ;
    osdev = ath_netdev_priv(dev);
    vap = osdev->os_if;
    return ATH_TX_EXT_AP_PROCESS(vap, &skb);
}

int
osif_nss_ol_vap_hardstart(struct sk_buff *skb, struct net_device *dev)
{
    osif_dev  *osdev ;
    wlan_if_t vap ;

    qdf_nbuf_count_inc(skb);
    if (qdf_unlikely((dev->flags & (IFF_RUNNING|IFF_UP)) != (IFF_RUNNING|IFF_UP))) {
        qdf_nbuf_free(skb);
        return 0;
    }

    osdev = ath_netdev_priv(dev);
    vap = osdev->os_if;

    if ((!osdev->is_up ) ||
                    (!ieee80211_vap_ready_is_set(vap)) ||
                    (IEEE80211_IS_CHAN_RADAR(vap->iv_bsschan))) {

        qdf_nbuf_free(skb);
        return 0;
    }

    if (qdf_unlikely(!qdf_nbuf_is_tso(skb) != 0)) {
        skb = qdf_nbuf_unshare(skb);
        if (skb == NULL)
            return 0;
    }

#if UMAC_SUPPORT_WNM
    if (wlan_wnm_tfs_filter(vap, (wbuf_t) skb)) {
        goto bad;
    }
#endif

    if (vap->iv_mpsta || vap->iv_psta) {
#if DBDC_REPEATER_SUPPORT
        if (dbdc_tx_process(vap, &osdev, skb)) {
            return 0;
        }
        vap = osdev->os_if;
#endif
        if (vap->iv_ic->nss_funcs)
            vap->iv_ic->nss_funcs->ic_osif_nss_vdev_process_mpsta_tx(dev, skb);
        return 0;
    }

    if (OL_CFG_RAW_TX_LIKELINESS(vap->iv_tx_encap_type == osif_pkt_type_raw)) {
        /* In Raw Mode, the payload normally comes encrypted by an external
         * Access Controller and we won't have the keys. Besides, the format
         * isn't 802.3/Ethernet II.
         * Hence, VLAN WAR, Ext AP functionality, VoW debug and Multicast to
         * Unicast conversion aren't applicable, and are skipped.
         *
         * Additionally, TSO and nr_frags based scatter/gather are currently
         * not required and thus not supported with Raw Mode.
         *
         * Error conditions are handled internally by the below function.
         */
        OL_TX_LL_UMAC_RAW_PROCESS(dev, &skb);
        goto out;
    }

#if MESH_MODE_SUPPORT
    if (vap->iv_mesh_vap_mode && (vap->mdbg & MESH_DEBUG_ENABLED)) {
        if (add_mesh_meta_hdr(skb, vap)) {
            goto bad;
        }
    }
#endif

    if (IEEE80211_VAP_IS_EXT_AP_ENABLED(vap) && (vap->iv_opmode == IEEE80211_M_STA)) {
#if DBDC_REPEATER_SUPPORT
        if (dbdc_tx_process(vap, &osdev, skb)) {
            return 0;
        }
        vap = osdev->os_if;
#endif
        if (vap->iv_ic->nss_funcs)
            vap->iv_ic->nss_funcs->ic_osif_nss_vdev_process_extap_tx(dev, skb);
        return 0;
    }

    if (vap->iv_ic->nss_funcs && vap->iv_ic->nss_funcs->ic_osif_nss_ol_vap_xmit(osdev, skb)) {
        goto bad;
    }

out:
    return 0;

bad:
    if (skb != NULL) {
        qdf_nbuf_free(skb);
    }
    return 0;
}

#endif /* QCA_NSS_WIFI_OFFLOAD_SUPPORT */



