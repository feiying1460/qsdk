/*
 * Copyright (c) 2015-2017 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * 2015-2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary. 
 */

/*
 * osif_nss_wifiol_if.c
 *
 * This file used for for interface   NSS WiFi Offload Radio
 * ------------------------REVISION HISTORY-----------------------------
 * Qualcomm Atheros         15/june/2015              Created
 */

#include <linux/types.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/ipv6.h>
#include <linux/version.h>

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(3,9,0))
#include <net/ipip.h>
#else
#include <net/ip_tunnels.h>
#endif

#include <ol_txrx_types.h>
#include <ol_txrx_peer_find.h> /* ol_txrx_peer_find_by_id */
#include <linux/if_arp.h>
#include <linux/etherdevice.h>
#include <linux/in.h>
#include <asm/cacheflush.h>
#include <nss_api_if.h>
#include <nss_cmn.h>
#include "ath_pci.h"
#include <hif.h>
#include "osif_private.h"
#include "pktlog_ac_i.h"
#include <wdi_event.h>
#include "osif_nss_wifiol_vdev_if.h"
#include "osif_nss_wifiol_if.h"
#include <htt_internal.h>
#include <ol_txrx_dbg.h>
#include <ieee80211_ique.h>

#define NSS_PEER_MEMORY_DEFAULT_LENGTH 204000
#define NSS_RRA_MEMORY_DEFAULT_LENGTH 35400
#define STATS_COOKIE_LSB_OFFSET 3
#define STATS_COOKIE_MSB_OFFSET 4

static struct nss_wifi_offload_funcs nss_wifi_funcs = {
    osif_nss_ol_store_other_pdev_stavap,
    osif_nss_vdev_me_reset_snooplist,
    osif_nss_vdev_me_update_member_list,
    osif_nss_ol_vap_xmit,
    osif_nss_vdev_me_update_hifitlb,
    osif_nss_vdev_me_dump_denylist,
    osif_nss_vdev_me_add_deny_member,
    osif_nss_ol_vdev_set_cfg,
    osif_nss_vdev_process_mpsta_tx,
    osif_nss_ol_wifi_monitor_set_filter,
    osif_nss_vdev_get_nss_id,
    osif_nss_vdev_process_extap_tx,
    osif_nss_vdev_me_dump_snooplist,
    osif_nss_ol_vap_delete,
    osif_nss_vdev_me_add_member_list,
    osif_nss_vdev_vow_dbg_cfg,
    osif_nss_ol_enable_dbdc_process,
    osif_nss_vdev_get_nss_wifiol_ctx,
    osif_nss_vdev_me_delete_grp_list,
    osif_nss_vdev_me_create_grp_list,
    osif_nss_vdev_me_delete_deny_list,
    osif_nss_vdev_me_remove_member_list
};

extern void
ieee80211_me_SnoopListUpdate_timestamp(struct MC_LIST_UPDATE* list_entry, u_int32_t ether_type);

void osif_nss_vdev_aggregate_msdu(ar_handle_t arh, struct ol_txrx_pdev_t *pdev, qdf_nbuf_t msduorig, qdf_nbuf_t *head_msdu, uint8_t no_clone_reqd);
static int osif_nss_ol_ce_raw_send(struct ol_txrx_pdev_t *pdev, void *nss_wifiol_ctx, uint32_t radio_id, qdf_nbuf_t netbuf, uint32_t  len);

int osif_nss_ol_vap_hardstart(struct sk_buff *skb, struct net_device *dev);

void osif_nss_ol_event_receive(struct ol_ath_softc_net80211 *scn, struct nss_cmn_msg *wifimsg);
int glbl_allocated_radioidx=0;

/*
 * osif_nss_ol_assign_ifnum : Get NSS IF Num based on Radio ID
 */

int osif_nss_ol_assign_ifnum(int radio_id, struct ol_ath_softc_net80211 *scn, bool is_2g) {

	uint32_t i = 0;
	uint32_t found_idx = 0;
	uint32_t start_idx = 0;

	if (is_2g) {
		start_idx = 1;
	}

	for (i = start_idx; i < 3; i++) {
		if ((glbl_allocated_radioidx & (1 << i)) == 0) {
			glbl_allocated_radioidx |= (1 << i);
			found_idx = 1;
			break;
		}
	}

	if (!found_idx) {
		qdf_print("%s: Unable to allocate nss interface is_2g %d radioidx val %x startidx %x\n", __FUNCTION__, is_2g, glbl_allocated_radioidx, start_idx);
		scn->nss_idx = -1;
		return -1;
	}

	scn->nss_idx = i;

	switch (i) {
		case 0:
			return NSS_WIFI_INTERFACE0;

		case 1:
			return NSS_WIFI_INTERFACE1;

		case 2:
			return NSS_WIFI_INTERFACE2;
	}

	return -1;

}


void update_ring_info(
        struct nss_wifi_ce_ring_state_msg *sring,
        struct nss_wifi_ce_ring_state_msg *dring,
        struct hif_pipe_addl_info *hif_info) {

    sring->nentries = hif_info->ul_pipe.nentries;
    sring->nentries_mask = hif_info->ul_pipe.nentries_mask;
    sring->sw_index = hif_info->ul_pipe.sw_index;
    sring->write_index = hif_info->ul_pipe.write_index;
    sring->hw_index = hif_info->ul_pipe.hw_index;
    sring->base_addr_CE_space = hif_info->ul_pipe.base_addr_CE_space;
    sring->base_addr_owner_space = (unsigned int)hif_info->ul_pipe.base_addr_owner_space;
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "src -> NSS:nentries %d mask %x swindex %d write_index %d hw_index %d CE_space %x ownerspace %x \n",
            sring->nentries,
            sring->nentries_mask,
            sring->sw_index,
            sring->write_index,
            sring->hw_index,
            sring->base_addr_CE_space,
            sring->base_addr_owner_space);
    dring->nentries = hif_info->dl_pipe.nentries;
    dring->nentries_mask = hif_info->dl_pipe.nentries_mask;
    dring->sw_index = hif_info->dl_pipe.sw_index;
    dring->write_index = hif_info->dl_pipe.write_index;
    dring->hw_index = hif_info->dl_pipe.hw_index;
    dring->base_addr_CE_space = hif_info->dl_pipe.base_addr_CE_space;
    dring->base_addr_owner_space = (unsigned int)hif_info->dl_pipe.base_addr_owner_space;
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "dest -> NSS:nentries %d mask %x swindex %d write_index %d hw_index %d CE_space %x ownerspace %x \n",
            dring->nentries,
            dring->nentries_mask,
            dring->sw_index,
            dring->write_index,
            dring->hw_index,
            dring->base_addr_CE_space,
            dring->base_addr_owner_space);
}

static int osif_nss_ol_send_peer_memory(struct ol_ath_softc_net80211 *scn)
{
    struct htt_pdev_t *htt_pdev = scn->htt_pdev;
    struct ol_txrx_pdev_t *pdev = htt_pdev->txrx_pdev;
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_peer_freelist_append_msg *pfam;
    void *nss_wifiol_ctx = pdev->nss_wifiol_ctx;
    uint32_t len = NSS_PEER_MEMORY_DEFAULT_LENGTH;
    int if_num;
    int pool_id;
    nss_tx_status_t status;
    nss_wifi_msg_callback_t msg_cb;

    if_num = pdev->nss_ifnum;
    if (if_num == -1) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no if found return ");
        return -1;
    }

    pool_id = pdev->last_peer_pool_used + 1;
    if (pool_id > (OSIF_NSS_OL_MAX_PEER_POOLS - 1)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "pooil_id %d is out of limit\n", pool_id);
        return -1;
    }

    pdev->peer_mem_pool[pool_id] = kmalloc(len, GFP_KERNEL);
    if (!pdev->peer_mem_pool[pool_id]) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Not able to allocate memory for peer mem pool with pool_id %d", pool_id);
        return -1;
    }

    pdev->last_peer_pool_used = pool_id;

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    pfam = &wifimsg.msg.peer_freelist_append;

    pfam->addr = dma_map_single(NULL,  pdev->peer_mem_pool[pool_id], len, DMA_TO_DEVICE);
    pfam->length = len;
    pfam->num_peers = pdev->max_peers_per_pool;

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "sending peer pool with id %d start addr %x length %d num_peers %d\n", pool_id, pfam->addr, pfam->length, pfam->num_peers);
    /*
     * Send WIFI peer mem pool configure
     */
    nss_cmn_msg_init(&wifimsg.cm, if_num, NSS_WIFI_PEER_FREELIST_APPEND_MSG,
            sizeof(struct nss_wifi_peer_freelist_append_msg), msg_cb, NULL);


    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WIFI peer memory send failed %d \n", status);
        kfree(pdev->peer_mem_pool[pool_id]);
        pdev->last_peer_pool_used--;
        return -1;
    }

    return 0;
}

static int osif_nss_ol_send_rra_memory(struct ol_ath_softc_net80211 *scn)
{
    struct htt_pdev_t *htt_pdev = scn->htt_pdev;
    struct ol_txrx_pdev_t *pdev = htt_pdev->txrx_pdev;

    struct nss_wifi_msg wifimsg;
    struct nss_wifi_rx_reorder_array_freelist_append_msg *pfam;
    void *nss_wifiol_ctx = pdev->nss_wifiol_ctx;
    uint32_t len = NSS_RRA_MEMORY_DEFAULT_LENGTH;
    int if_num;
    int pool_id;
    nss_tx_status_t status;
    nss_wifi_msg_callback_t msg_cb;

    if_num = pdev->nss_ifnum;
    if (if_num == -1) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no if found return ");
        return -1;
    }

    pool_id = pdev->last_rra_pool_used + 1;
    if (pool_id > (OSIF_NSS_OL_MAX_RRA_POOLS - 1)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "pooil_id %d is out of limit\n", pool_id);
        return -1;
    }

    pdev->rra_mem_pool[pool_id] = kmalloc(len, GFP_KERNEL);
    if (!pdev->rra_mem_pool[pool_id]) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Not able to allocate memory for peer mem pool with pool_id %d", pool_id);
        return -1;
    }

    pdev->last_rra_pool_used = pool_id;

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    pfam = &wifimsg.msg.rx_reorder_array_freelist_append;

    pfam->addr = dma_map_single(NULL,  pdev->rra_mem_pool[pool_id], len, DMA_TO_DEVICE);
    pfam->length = len;
    pfam->num_rra = pdev->max_rra_per_pool;
    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "sending rra pool with id %d start addr %x length %d num_rra %d\n", pool_id, pfam->addr, pfam->length, pfam->num_rra);

    /*
     * Send WIFI rra mem pool configure
     */
    nss_cmn_msg_init(&wifimsg.cm, if_num, NSS_WIFI_RX_REORDER_ARRAY_FREELIST_APPEND_MSG,
            sizeof(struct nss_wifi_rx_reorder_array_freelist_append_msg), msg_cb, NULL);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WIFI rra memory send failed %d \n", status);
        kfree(pdev->rra_mem_pool[pool_id]);
        pdev->last_rra_pool_used--;
        return -1;
    }

    return 0;
}

/*
 * osif_nss_ol_process_bs_peer_state_msg
 *     Process the peer state message from NSS-FW
 *      and inform the bs handler
 */
int osif_nss_ol_process_bs_peer_state_msg(struct ol_ath_softc_net80211 *scn,  struct nss_wifi_bs_peer_activity *msg)
{
    struct ol_txrx_pdev_t *pdev = scn->pdev_txrx_handle;
    struct ol_txrx_peer_t *peer;
    uint16_t i;

    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211_node *ni = NULL;
    struct ieee80211vap *vap = NULL;
    uint16_t peer_id;
    bool secured;

    /*
     *  NSS-FW has sent the message regarding the
     *  activity for each peer.
     *  This infomation has to be passed on to the
     *  band-steering module.
     */
    for (i = 0 ; i < msg->nentries ; i++) {
        qdf_spin_lock_bh(&pdev->peer_ref_mutex);
        secured = (msg->peer_id[i] & (0x8000)) >> 15;
        peer_id = msg->peer_id[i] & (~(0x8000));
        if (peer_id > pdev->max_peers) {
	    continue;
        }
        peer = ol_txrx_peer_find_by_id(pdev, peer_id);
        if (peer) {
            ol_txrx_mark_peer_inact(peer, false);
            vap = ol_ath_vap_get(scn, peer->vdev->vdev_id);
            if (ieee80211_vap_wnm_is_set(vap) && ieee80211_wnm_bss_is_set(vap->wnm)) {
                ni = ieee80211_find_node(&ic->ic_sta, peer->mac_addr.raw);
                if (ni && ni != ni->ni_bss_node) {
                    ieee80211_wnm_bssmax_updaterx(ni, secured);
                }
            }
        }
        qdf_spin_unlock_bh(&pdev->peer_ref_mutex);
    }
    return 0;
}

/*
 *  * osif_nss_ol_process_ol_stats_msg
 *   *     Process the enhanced stats message from NSS-FW
 *    */
int osif_nss_ol_process_ol_stats_msg(struct ol_ath_softc_net80211 *scn,  struct nss_wifi_ol_stats_msg *msg)
{
#if ENHANCED_STATS
    struct ieee80211com *ic = NULL;
    struct ieee80211_node *ni = NULL;
    struct ol_txrx_vdev_t *vdev = NULL;
    struct ieee80211vap *vap = NULL;
    struct ieee80211_mac_stats *mac_stats = NULL;
    uint32_t num_msdus = 0, byte_cnt = 0, discard_cnt = 0, i = 0, tx_mgmt = 0, j = 0;
    struct ol_txrx_peer_t *peer = NULL;
    struct ol_txrx_pdev_t *pdev = scn->pdev_txrx_handle;

    scn = (struct ol_ath_softc_net80211 *)pdev->ctrl_pdev;
    ic  = &scn->sc_ic;
    scn->scn_stats.tx_bawadv += msg->bawadv_cnt;
    scn->scn_stats.tx_beacon += msg->bcn_cnt;

    /*
     *  Extract per peer ol stats from the message sent by NSS-FW.
     */
    for (i = 0 ; i < msg->npeers ; i++) {
        peer = ol_txrx_peer_find_by_id(pdev, msg->peer_ol_stats[i].peer_id);
        if (peer) {
            num_msdus = msg->peer_ol_stats[i].tx_data;
            byte_cnt = msg->peer_ol_stats[i].tx_bytes;
            discard_cnt = msg->peer_ol_stats[i].tx_fail;
            tx_mgmt = msg->peer_ol_stats[i].tx_mgmt;
            peer->peer_data_stats.data_packets = num_msdus;
            peer->peer_data_stats.data_bytes = byte_cnt;
            peer->peer_data_stats.thrup_bytes = byte_cnt;
            peer->peer_data_stats.discard_cnt = discard_cnt;

            vdev = peer->vdev;
            vap = ol_ath_vap_get(scn, vdev->vdev_id);
            if (vap) {
                vap->iv_unicast_stats.ims_tx_discard += discard_cnt;
                vap->iv_stats.is_tx_not_ok += discard_cnt;
                ni = ieee80211_vap_find_node(vap,peer->mac_addr.raw);
                if (ni) {
                    ni->ni_stats.ns_tx_discard += discard_cnt;
                    ni->ni_stats.ns_tx_mcast += msg->peer_ol_stats[i].tx_mcast;
                    ni->ni_stats.ns_tx_ucast += msg->peer_ol_stats[i].tx_ucast;
                    if (peer->bss_peer) {
#if UMAC_SUPPORT_STA_STATS_ENHANCEMENT
                        ni->ni_stats.ns_tx_mcast_bytes += byte_cnt;
#endif
                    } else {
#if UMAC_SUPPORT_STA_STATS_ENHANCEMENT
                        ni->ni_stats.ns_tx_ucast_bytes += byte_cnt;
#endif
                        ni->ni_stats.ns_tx_data_success += num_msdus;
                        ni->ni_stats.ns_tx_bytes_success += byte_cnt;
                    }
                    ni->ni_stats.ns_tx_data += num_msdus;
                    ni->ni_stats.ns_tx_bytes += byte_cnt;
                    ni->ni_stats.ns_is_tx_not_ok += discard_cnt;
                    ni->ni_stats.ns_tx_mgmt += tx_mgmt;
                    for (j = 0; j < WME_NUM_AC; j++) {
                        ni->ni_stats.ns_tx_wme[j] += msg->peer_ol_stats[i].tx_wme[j];
                        ni->ni_stats.ns_rx_wme[j] += msg->peer_ol_stats[i].rx_wme[j];
                        ni->ni_stats.ns_rssi_chain[j] += msg->peer_ol_stats[i].rssi_chains[j];
                    }
                    ieee80211_free_node(ni);
                }
                mac_stats = peer->bss_peer ? &vap->iv_multicast_stats :
                               &vap->iv_unicast_stats;
                mac_stats->ims_tx_packets += num_msdus;
                mac_stats->ims_tx_bytes += byte_cnt;
                mac_stats->ims_tx_data_packets += num_msdus;
                mac_stats->ims_tx_data_bytes += byte_cnt;
                mac_stats->ims_tx_mgmt += tx_mgmt;
                mac_stats->ims_tx_datapyld_bytes = mac_stats->ims_tx_data_bytes -
                                                    (mac_stats->ims_tx_data_packets * (ETHERNET_HDR_LEN + 24));
                for (j = 0; j < WME_NUM_AC; j++) {
                    mac_stats->ims_tx_wme[j] += msg->peer_ol_stats[i].tx_wme[j];
                    mac_stats->ims_rx_wme[j] += msg->peer_ol_stats[i].rx_wme[j];
                }
                mac_stats->ims_retries += msg->peer_ol_stats[i].ppdu_retries;
            }
            scn->scn_stats.tx_num_data += num_msdus;
            scn->scn_stats.tx_bytes += byte_cnt;
            scn->scn_stats.tx_compaggr += msg->peer_ol_stats[i].tx_aggr;
            scn->scn_stats.tx_compunaggr += msg->peer_ol_stats[i].tx_unaggr;
            scn->scn_stats.tx_mgmt += tx_mgmt;
        }
    }
#endif
    return 0;
}

/*
 * osif_nss_ol_process_sta_kickout_msg
 *     Process the sta kickout message from NSS-FW
 */
int osif_nss_ol_process_sta_kickout_msg(struct ol_ath_softc_net80211 *scn, struct nss_wifi_sta_kickout_msg *msg)
{
    struct htt_pdev_t *htt_pdev = scn->htt_pdev;
    struct ol_txrx_pdev_t *pdev = htt_pdev->txrx_pdev;
    struct ol_txrx_peer_t *peer;
    uint8_t peer_macaddr_raw[OL_TXRX_MAC_ADDR_LEN];

    qdf_spin_lock_bh(&pdev->peer_ref_mutex);
    peer = ol_txrx_peer_find_by_id(pdev, msg->peer_id);
    if (peer) {
        memcpy(peer_macaddr_raw, peer->mac_addr.raw, OL_TXRX_MAC_ADDR_LEN);
    }
    qdf_spin_unlock_bh(&pdev->peer_ref_mutex);
    peer_sta_kickout(scn, (A_UINT8 *)&peer_macaddr_raw);
    return 0;
}


/*
 * osif_nss_ol_process_wnm_peer_rx_activity_msg
 *     Process the rx activity message from NSS-FW
 *      and inform the wnm handler
 */
int osif_nss_ol_process_wnm_peer_rx_activity_msg(struct ol_ath_softc_net80211 *scn, struct nss_wifi_wnm_peer_rx_activity_msg *msg)
{
#if UMAC_SUPPORT_WNM
    struct htt_pdev_t *htt_pdev;
    struct ol_txrx_pdev_t *pdev;
    struct ieee80211com *ic;
    struct ieee80211_node *ni;
    struct ol_txrx_peer_t *peer;
    struct ieee80211vap *vap;
    uint16_t i;

    ic = &scn->sc_ic;
    htt_pdev = scn->htt_pdev;
    pdev = htt_pdev->txrx_pdev;

    /*
     *  NSS-FW has sent the message regarding the
     *  rx activity for each peer.
     *  This infomation has to be passed on to wnm.
     */
    for (i = 0 ; i < msg->nentries ; i++) {
        if (msg->peer_id[i] > pdev->max_peers) {
            continue;
        }
        qdf_spin_lock_bh(&pdev->peer_ref_mutex);

        peer = ol_txrx_peer_find_by_id(pdev, msg->peer_id[i]);
        if (peer) {
            vap = ol_ath_vap_get(scn, peer->vdev->vdev_id);
        } else {
            qdf_spin_unlock_bh(&pdev->peer_ref_mutex);
            continue;
        }

        if (vap && ieee80211_vap_wnm_is_set(vap) && ieee80211_wnm_bss_is_set(vap->wnm)) {
            ni = ieee80211_find_node(&ic->ic_sta, peer->mac_addr.raw);
            if (ni) {
                ieee80211_wnm_bssmax_updaterx(ni, 0);
            }
            ieee80211_free_node(ni);
        }
        qdf_spin_unlock_bh(&pdev->peer_ref_mutex);
    }
#endif
    return 0;
}

void osif_nss_ol_event_receive(struct ol_ath_softc_net80211 *scn, struct nss_cmn_msg *wifimsg)
{
    struct ol_txrx_pdev_t *pdev = NULL;
    struct htt_pdev_t *htt_pdev;
    uint32_t msg_type = wifimsg->type;
    enum nss_cmn_response response = wifimsg->response;
    struct ol_txrx_stats *pdev_txrxstats = NULL;

    htt_pdev = scn->htt_pdev;
    pdev = htt_pdev->txrx_pdev;

    /*
     * Handle the message feedback returned from FW
     */
    switch (msg_type) {
        case NSS_WIFI_POST_RECV_MSG:
            {
                if (response == NSS_CMN_RESPONSE_EMSG) {
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS WIFI OFFLOAD - FAILED TO INITIALIZE CE for NSS radio %d\n", scn->nss_wifiol_id);
                    scn->nss_wifiol_ce_enabled = 0;
                    return;
                }
                scn->nss_wifiol_ce_enabled = 1;
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS CE init succeeded for NSS radio %d\n", scn->nss_wifiol_id);
            }
            break;

        case NSS_WIFI_INIT_MSG:
            {
                if (response == NSS_CMN_RESPONSE_EMSG) {
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS WIFI INIT MSG Failed for NSS radio %d\n", scn->nss_wifiol_id);
                }
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS WIFI init succeeded for NSS radio %d\n", scn->nss_wifiol_id);
            }
            break;

        case NSS_WIFI_TX_INIT_MSG:
            {
                if (response == NSS_CMN_RESPONSE_EMSG) {
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS WIFI TX INIT MSG failed for NSS radio %d\n", scn->nss_wifiol_id);
                }
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS WIFI TX init succeeded for NSS radio %d\n", scn->nss_wifiol_id);
            }
            break;

        case NSS_WIFI_RAW_SEND_MSG:
            {
                if (response == NSS_CMN_RESPONSE_EMSG) {
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS WIFI RAW SEND MSG failed for NSS radio %d\n", scn->nss_wifiol_id);
                }
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS WIFI RAW SEND succeeded for NSS radio %d\n", scn->nss_wifiol_id);
            }
            break;

        case NSS_WIFI_MGMT_SEND_MSG:
            {
                if (response == NSS_CMN_RESPONSE_EMSG) {
                    struct nss_wifi_mgmtsend_msg *msg=  &((struct nss_wifi_msg *)wifimsg)->msg.mgmtmsg;

                    uint32_t desc_id = msg->desc_id;
                    htt_pdev = scn->htt_pdev;

                    if(scn->radio_attached == 0)
                        return;

                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Mgmt send failed for NSS radio %d\n", scn->nss_wifiol_id);
                    htt_tx_mgmt_desc_free(htt_pdev, desc_id, IEEE80211_TX_ERROR, MGMT_PPDU_ID_NON_USED);
                }
            }
            break;

        case NSS_WIFI_FW_STATS_MSG:
            {

                if (response == NSS_CMN_RESPONSE_EMSG) {
                    struct nss_wifi_fw_stats_msg *msg = &((struct nss_wifi_msg *)wifimsg)->msg.fwstatsmsg;
                    struct ol_txrx_stats_req_internal *req;
                    uint8_t *data = msg->array;
                    uint32_t cookie_base = (uint32_t)(data + (HTC_HDR_LENGTH + HTC_HDR_ALIGNMENT_PADDING));
                    uint32_t *ptr = (uint32_t *)(cookie_base);

                    u_int64_t cookie = *(ptr + STATS_COOKIE_MSB_OFFSET);
                    cookie = ((cookie << 32) |(*(ptr + STATS_COOKIE_LSB_OFFSET)));

                    if(scn->radio_attached == 0)
                        return;
                    /*
                     * Drop the packet;
                     */
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Fw stats request send failed\n");
                    req = (struct ol_txrx_stats_req_internal *) ((size_t) cookie);

                    htt_pdev = scn->htt_pdev;
                    pdev = htt_pdev->txrx_pdev;

                    htt_pkt_buf_list_del(htt_pdev, cookie);
                    if (req->base.wait.blocking) {
                        qdf_semaphore_release(&scn->scn_stats_sem);
                    }

                    qdf_mem_free(req);
                }
            }
            break;

        case NSS_WIFI_STATS_MSG:
            {
                struct nss_wifi_stats_sync_msg *stats = &((struct nss_wifi_msg *)wifimsg)->msg.statsmsg;

                if(scn->radio_attached == 0)
                    return;

                if (stats->rx_bytes_deliverd) {
                    scn->scn_led_byte_cnt += stats->rx_bytes_deliverd;
                    ol_ath_led_event(scn, OL_ATH_LED_RX);
                }

                if (stats->tx_bytes_transmit_completions) {
                    scn->scn_led_byte_cnt += stats->tx_bytes_transmit_completions;
                    ol_ath_led_event(scn, OL_ATH_LED_TX);
                }

                htt_pdev = scn->htt_pdev;
                pdev = htt_pdev->txrx_pdev;

                /*
                 * Update the pdev stats
                 */
                pdev_txrxstats = &pdev->stats.pub;
                pdev_txrxstats->rx.delivered.bytes += stats->rx_bytes_deliverd;
                pdev_txrxstats->rx.delivered.pkts += stats->rx_pkts_deliverd;
                pdev_txrxstats->tx.delivered.bytes += stats->rx_bytes_deliverd;
                pdev_txrxstats->tx.delivered.pkts += stats->tx_transmit_completions;
                pdev_txrxstats->tx.delivered.bytes += stats->tx_bytes_transmit_completions;
                pdev_txrxstats->tx.dropped.nss_ol_dropped.pkts += stats->tx_transmit_dropped;

            }
            break;

        case NSS_WIFI_SEND_PEER_MEMORY_REQUEST_MSG:
            {

                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "event: sending peer pool memory\n");
                osif_nss_ol_send_peer_memory(scn);
            }
            break;

        case NSS_WIFI_SEND_RRA_MEMORY_REQUEST_MSG:
            {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "event: sending rra pool memory\n");
                osif_nss_ol_send_rra_memory(scn);
            }
            break;

        case NSS_WIFI_PEER_BS_STATE_MSG:
            {
                struct nss_wifi_bs_peer_activity *msg =  &((struct nss_wifi_msg *)wifimsg)->msg.peer_activity;
                osif_nss_ol_process_bs_peer_state_msg(scn, msg);
            }
            break;

        case NSS_WIFI_OL_STATS_MSG:
            {
                struct nss_wifi_ol_stats_msg *msg =  &((struct nss_wifi_msg *)wifimsg)->msg.ol_stats_msg;
                osif_nss_ol_process_ol_stats_msg(scn, msg);
            }
            break;

        case NSS_WIFI_STA_KICKOUT_MSG:
            {
                struct nss_wifi_sta_kickout_msg *msg =  &((struct nss_wifi_msg *)wifimsg)->msg.sta_kickout_msg;
                osif_nss_ol_process_sta_kickout_msg(scn, msg);
            }
            break;

        case NSS_WIFI_WNM_PEER_RX_ACTIVITY_MSG:
            {
                struct nss_wifi_wnm_peer_rx_activity_msg *msg;
                msg = &((struct nss_wifi_msg *)wifimsg)->msg.wprm;
                osif_nss_ol_process_wnm_peer_rx_activity_msg(scn, msg);
            }
            break;

        case NSS_WIFI_HTT_INIT_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "HTT RX init configuration failed with error for NSS radio %d\n", scn->nss_wifiol_id);
                scn->osif_nss_ol_wifi_cfg_complete.response = NSS_TX_FAILURE;
                complete(&scn->osif_nss_ol_wifi_cfg_complete.complete);
                return;
            }

            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "HTT RX INIT configuration success for NSS radio %d\n", scn->nss_wifiol_id);
            scn->osif_nss_ol_wifi_cfg_complete.response = NSS_TX_SUCCESS;
            complete(&scn->osif_nss_ol_wifi_cfg_complete.complete);
            break;

        case NSS_WIFI_PEER_STATS_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Peer Stats Message - send to NSS failed %d\n", scn->nss_wifiol_id);
                scn->osif_nss_ol_wifi_cfg_complete.response = NSS_TX_FAILURE;
                complete(&scn->osif_nss_ol_wifi_cfg_complete.complete);
                return;
            }

            scn->osif_nss_ol_wifi_cfg_complete.response = NSS_TX_SUCCESS;
            complete(&scn->osif_nss_ol_wifi_cfg_complete.complete);
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Peer Stats Message - success %d\n", scn->nss_wifiol_id);
	    break;

        case NSS_WIFI_WDS_PEER_ADD_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS WIFI PEER ADD MSG failed for NSS radio %d\n", scn->nss_wifiol_id);
                return;
            }
            break;

        case NSS_WIFI_WDS_PEER_DEL_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS WIFI PEER DEL MSG failed for NSS radio %d\n", scn->nss_wifiol_id);
            }
            break;

        case NSS_WIFI_PEER_FREELIST_APPEND_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS WIFI PEER FREELIST APPEND MSG failed for NSS radio %d\n", scn->nss_wifiol_id);
            }
            break;

        case NSS_WIFI_RX_REORDER_ARRAY_FREELIST_APPEND_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS WIFI RX REORDER ARRAY FREELIST APPEND MSG failed for NSS radio %d\n", scn->nss_wifiol_id);
            }
            break;

        case NSS_WIFI_WDS_VENDOR_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS WIFI WDS VENDOR MSG failed for NSS radio %d\n", scn->nss_wifiol_id);
            }
            break;

        case NSS_WIFI_DBDC_PROCESS_ENABLE_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS WIFI DBDC Process Enable failed for NSS radio %d\n", scn->nss_wifiol_id);
            }
            break;

        case NSS_WIFI_PRIMARY_RADIO_SET_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS WIFI Primary Radio Set failed for NSS radio %d\n", scn->nss_wifiol_id);
            }
            break;

        case NSS_WIFI_FORCE_CLIENT_MCAST_TRAFFIC_SET_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS Client MCast Traffic Set failed for NSS radio %d\n", scn->nss_wifiol_id);
            }
            break;

        case NSS_WIFI_STORE_OTHER_PDEV_STAVAP_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS Store Other Pdev STAVAP MSG failed for NSS radio %d\n", scn->nss_wifiol_id);
            }
            break;

        case NSS_WIFI_ENABLE_PERPKT_TXSTATS_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS Perpacket TX Stats MSG failed for NSS radio %d\n", scn->nss_wifiol_id);
            }
            break;

        case NSS_WIFI_IGMP_MLD_TOS_OVERRIDE_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS IGMP MLD TOS OVERRIDE failed for NSS radio %d\n", scn->nss_wifiol_id);
            }
            break;

        case NSS_WIFI_MSDU_TTL_SET_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS MSDU_TTL configure msg failed for NSS radio %d\n", scn->nss_wifiol_id);
            }
            break;

        case NSS_WIFI_MONITOR_FILTER_SET_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS Monitor Filter set msg failed for NSS radio %d\n", scn->nss_wifiol_id);
            }
            break;

        case NSS_WIFI_OL_STATS_CFG_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS OL_Stats configure msg failed for NSS radio %d\n", scn->nss_wifiol_id);
            }
            break;

        case NSS_WIFI_PKTLOG_CFG_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS PCKTLOG configure msg failed for NSS radio %d\n", scn->nss_wifiol_id);
            }
            break;

        case NSS_WIFI_STOP_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS WIFI STOP msg failed for NSS radio %d\n", scn->nss_wifiol_id);
            }
            break;

        case NSS_WIFI_TX_QUEUE_CFG_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS WIFI TX QUEUE config failed for NSS radio %d\n", scn->nss_wifiol_id);
            }
            break;

        case NSS_WIFI_TX_MIN_THRESHOLD_CFG_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS WIFI TX MIN THRESHOLD config failed for NSS radio %d\n", scn->nss_wifiol_id);
            }
            break;

        case NSS_WIFI_RESET_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS WIFI RESET config failed for NSS radio %d\n", scn->nss_wifiol_id);
            }
            break;

        default:
            break;
    }

    /* printk("%s\n",__FUNCTION__); */
    /*
     * TODO : Need to add stats updates
     */
    return;
}

void
htt_t2h_msg_handler_fast(void *htt_pdev, qdf_nbuf_t *nbuf_cmpl_arr,
        uint32_t num_cmpls);

static void osif_nss_ol_wifi_ce_callback_func(struct ol_ath_softc_net80211 *scn, struct sk_buff * nbuf, __attribute__((unused)) struct napi_struct *napi) {

    struct ol_txrx_pdev_t *pdev ;
    struct htt_pdev_t *htt_pdev ;
    qdf_nbuf_t  nbuf_cmpl_arr[32];
    /* uint32_t num_htt_cmpls; */
    uint32_t count;

    qdf_nbuf_count_inc(nbuf);

    if (scn == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: scn is NULL free the nbuf: %p\n", __func__, nbuf);
        goto fail;
    }
    pdev = scn->pdev_txrx_handle;
    htt_pdev=  pdev->htt_pdev;

    if (htt_pdev == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: htt_pdev is NULL free the nbuf: %p for radio ID: %d\n", __func__, nbuf, scn->radio_id);
        goto fail;
    }

    nbuf_cmpl_arr[0] = nbuf;

    htt_t2h_msg_handler_fast(htt_pdev, nbuf_cmpl_arr, 1);
    return;

fail:
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "nbuf->data: ");
    for (count = 0; count < 16; count++) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%x ", nbuf->data[count]);
    }
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n");
    qdf_nbuf_free(nbuf);
}

void
ol_rx_process_inv_peer(ol_txrx_pdev_handle pdev, void *rx_mpdu_desc,
        	qdf_nbuf_t msdu);
void
phy_data_type_chk(qdf_nbuf_t head_msdu, u_int32_t *cv_chk_status);

void
cbf_type_chk(qdf_nbuf_t head_msdu, u_int32_t *cv_chk_status);

/*
 * To check whether msdu is rx_cbf_type
 */
int osif_nss_ol_is_rx_cbf(qdf_nbuf_t msdu, struct htt_pdev_t *htt_pdev)
{
	uint32_t mgmt_type = 0;
	uint32_t phy_data_type = 0;
	uint32_t cv_chk_status = 1;
	uint8_t rx_phy_data_filter;

	phy_data_type = htt_pdev->ar_rx_ops->check_desc_phy_data_type(msdu, &rx_phy_data_filter);
	mgmt_type = htt_pdev->ar_rx_ops->check_desc_mgmt_type(msdu);

	if (phy_data_type == 0) {
		phy_data_type_chk(msdu, &cv_chk_status);
	} else {
		if (mgmt_type == 0) {
			cbf_type_chk(msdu, &cv_chk_status);
		} else {
			return -1;
		}
	}
	return cv_chk_status;
}

/*
 * Extended data callback
 */
static void osif_nss_ol_wifi_ext_callback_func(struct ol_ath_softc_net80211 *scn, struct sk_buff * nbuf,  __attribute__((unused)) struct napi_struct *napi)
{
    struct nss_wifi_rx_ext_metadata *wrem = (struct nss_wifi_rx_ext_metadata *)nbuf->data;
    struct ol_txrx_pdev_t *pdev = scn->pdev_txrx_handle;
    struct htt_pdev_t *htt_pdev = pdev->htt_pdev;

    uint32_t rx_desc_size = htt_pdev->ar_rx_ops->sizeof_rx_desc();
    void *rx_mpdu_desc = (void *)nbuf->head;
    qdf_nbuf_t mon_skb, skb_list_head, next;
    int discard = 1;
    uint32_t type  =  wrem->type;
    enum htt_rx_status status;
    mon_skb = NULL;
    qdf_nbuf_count_inc(nbuf);

    switch (type) {
        case NSS_WIFI_RX_EXT_PKTLOG_TYPE:
            {
                uint16_t peer_id = wrem->peer_id;
                struct ol_txrx_peer_t *peer = ol_txrx_peer_find_by_id(pdev, peer_id);
                uint32_t pad_bytes = htt_pdev->ar_rx_ops->get_l3_header_padding(nbuf);

                dma_unmap_single (NULL, virt_to_phys(rx_mpdu_desc), rx_desc_size, DMA_FROM_DEVICE);
                status = wrem->htt_rx_status;
                peer = ol_txrx_peer_find_by_id(pdev, peer_id);
                nbuf->data = nbuf->head + rx_desc_size + pad_bytes;

                if (((status == htt_rx_status_err_fcs) || ((status == htt_rx_status_ctrl_mgmt_null) && peer))
                        && (osif_nss_ol_is_rx_cbf(nbuf, htt_pdev) == 0)) {
                    wdi_event_handler(WDI_EVENT_RX_CBF_REMOTE, pdev, nbuf, peer_id, status);
                } else {
                    wdi_event_handler(WDI_EVENT_RX_DESC_REMOTE, pdev, nbuf, peer_id, status);
                }
            }
            break;

        case NSS_WIFI_RX_EXT_INV_PEER_TYPE:
        default :
            {
                uint8_t is_mcast, drop_packet = 0;
                uint32_t not_mgmt_type, not_ctrl_type;
                struct ether_header *eh;

                dma_unmap_single (NULL, virt_to_phys(rx_mpdu_desc), rx_desc_size, DMA_FROM_DEVICE);
                ol_rx_process_inv_peer(pdev, rx_mpdu_desc, nbuf);
                qdf_spin_lock_bh(&pdev->mon_mutex);

                if ((pdev->monitor_vdev) && (!pdev->filter_neighbour_peers)) {
                    discard = 0;

                    osif_nss_vdev_aggregate_msdu(htt_pdev->arh, pdev, nbuf, &skb_list_head, 1);

                    if (skb_list_head) {
                        not_mgmt_type = htt_pdev->ar_rx_ops->check_desc_mgmt_type(skb_list_head);
                        not_ctrl_type = htt_pdev->ar_rx_ops->check_desc_ctrl_type(skb_list_head);
                        eh = (struct ether_header *)(nbuf->data);

                        if (qdf_likely((not_mgmt_type && not_ctrl_type) != 0)) {

                            is_mcast = IEEE80211_IS_MULTICAST(eh->ether_dhost);

                            if (qdf_likely(is_mcast != 1)) {
                                /*ucast data pkts*/
                                if (ol_txrx_monitor_get_filter_ucast_data(pdev->monitor_vdev) == 1) {
                                    /*drop ucast pkts*/
                                    drop_packet = 1;
                                }
                            } else {
                                /*mcast data pkts*/
                                if (ol_txrx_monitor_get_filter_mcast_data(pdev->monitor_vdev) == 1) {
                                    /*drop mcast pkts*/
                                    drop_packet = 1;
                                }
                            }
                        } else {
                            /*mgmt/ctrl etc. pkts*/
                            if (ol_txrx_monitor_get_filter_non_data(pdev->monitor_vdev) == 1) {
                                drop_packet = 1;
                            }
                        }

                        if (drop_packet == 0) {
                            mon_skb = htt_pdev->ar_rx_ops->restitch_mpdu_from_msdus(
                                    htt_pdev->arh, skb_list_head, pdev->rx_mon_recv_status, 1);
                        }

                        if (mon_skb) {
                            pdev->monitor_vdev->osif_rx_mon(pdev->monitor_vdev->osif_vdev, mon_skb, pdev->rx_mon_recv_status);
                        } else {
                            mon_skb = skb_list_head;
                            while (mon_skb) {
                                next = qdf_nbuf_next(mon_skb);
                                qdf_nbuf_free(mon_skb);
                                mon_skb = next;
                            }
                        }
                    }
                }
                qdf_spin_unlock_bh(&pdev->mon_mutex);
            }
            break;
    }

    if (discard) {
        qdf_nbuf_free(nbuf);
    }
}

#if WDS_VENDOR_EXTENSION
/*
 * nss_wifi_wds_extn_peer_cfg_msg
 *
 *   Send Peer CFG frame to NSS
 */
int osif_nss_ol_wds_extn_peer_cfg_send(struct ol_txrx_pdev_t *pdev, struct ol_txrx_peer_t *peer)
{
    int ifnum;
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_wds_extn_peer_cfg_msg *wds_msg;
    nss_tx_status_t status;
    int radio_id;
    void *nss_wifiol_ctx = pdev->nss_wifiol_ctx;
    nss_wifi_msg_callback_t msg_cb;

    if (!nss_wifiol_ctx) {
        return 0;
    }

    radio_id = pdev->nss_wifiol_id;

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s %p %d Peer CFG ol stats enable \n",__func__, nss_wifiol_ctx, radio_id);

    ifnum = pdev->nss_ifnum;
    if (if_num == -1) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no if found return ");
        return -1;
    }

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    wds_msg = &wifimsg.msg.wpeercfg;
    wds_msg->peer_id = peer->peer_ids[0];
    peer = ol_txrx_peer_find_by_id(pdev, wds_msg->peer_id);
    if (!peer) {
        return -1;
    }
    wds_msg->wds_flags = (peer->wds_enabled |
      (peer->wds_tx_mcast_4addr << 1)
     | (peer->wds_tx_ucast_4addr << 2)
     | (peer->wds_rx_filter << 3)
     | (peer->wds_rx_ucast_4addr << 4)
     | (peer->wds_rx_mcast_4addr << 5));

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;

    /*
     * Display these info as it comes only during association
     */
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "peer->wds_enabled %d\n", peer->wds_enabled);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "peer->wds_tx_mcast_4addr %d\n", peer->wds_tx_mcast_4addr);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "peer->wds_tx_ucast_4addr %d\n", peer->wds_tx_ucast_4addr);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "peer->wds_rx_filter %d\n", peer->wds_rx_filter);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "peer->wds_rx_ucast_4addr %d\n", peer->wds_rx_ucast_4addr);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "peer->wds_rx_mcast_4addr %d\n", peer->wds_rx_mcast_4addr);

    /*
     * Send wds vendor message
     */
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_WDS_VENDOR_MSG,
            sizeof(struct nss_wifi_wds_extn_peer_cfg_msg), msg_cb, NULL);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WIFI Pause message send failed  %d \n", status);
        return -1;
    }

    return 0;
}
#endif

/*
 * osif_nss_ol_mgmt_frame_send
 * 	Send Management frame to NSS
 */
int osif_nss_ol_mgmt_frame_send(struct ol_txrx_pdev_t *pdev, void *nss_wifiol_ctx, int32_t radio_id, uint32_t desc_id, qdf_nbuf_t netbuf)
{
    int32_t len;
    int32_t ifnum = -1;
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_mgmtsend_msg *mgmtmsg;
    nss_wifi_msg_callback_t msg_cb;
    nss_tx_status_t status;

    if (!nss_wifiol_ctx) {
        return 1;
    }

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;

    if (pdev) {
	    ifnum = pdev->nss_ifnum;
	    if (ifnum == -1) {
		    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no i/f found return ");
		    return 1;
	    }
    }


    len = qdf_nbuf_len(netbuf);
    if (len > NSS_WIFI_MGMT_DATA_LEN) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: The specified length :%d is beyond allowed length:%d\n", __FUNCTION__, len, NSS_WIFI_MGMT_DATA_LEN);
        return 1;
    }

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    mgmtmsg = &wifimsg.msg.mgmtmsg;
    mgmtmsg->len = len;
    mgmtmsg->desc_id = desc_id;
    memcpy(mgmtmsg->array, (uint8_t *)netbuf->data, len);

    /*
     * Send wifi Mgmnt Send message
     */
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_MGMT_SEND_MSG,
            sizeof(struct nss_wifi_mgmtsend_msg), msg_cb, NULL);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: WIFI Management send failed %d \n",__FUNCTION__, status);
        return 1;
    }

    return 0;
}

/*
 * osif_nss_ol_stats_frame_send
 * 	Send FW Stats frame to NSS
 */
int osif_nss_ol_stats_frame_send(struct ol_txrx_pdev_t *pdev, void *nss_wifiol_ctx, int32_t radio_id, qdf_nbuf_t netbuf)
{
    int32_t len = 0;
    int32_t ifnum = 0;
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_fw_stats_msg *statsmsg;
    nss_wifi_msg_callback_t msg_cb;
    nss_tx_status_t status;

    if (!nss_wifiol_ctx) {
        return 0;
    }

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;

    if (pdev) {
	    ifnum = pdev->nss_ifnum;
	    if (ifnum == -1) {
		    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no i/f found return ");
		    return 1;
	    }
    }

    len = qdf_nbuf_len(netbuf);
    if (len > NSS_WIFI_FW_STATS_DATA_LEN) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: The specified length :%d is beyond allowed length:%d\n", __FUNCTION__, len, NSS_WIFI_FW_STATS_DATA_LEN);
        return 1;
    }

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    statsmsg = &wifimsg.msg.fwstatsmsg;
    statsmsg->len = len;
    memcpy(statsmsg->array, (uint8_t *)netbuf->data, len);

    /*
     * Send wifi FW status message
     */
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_FW_STATS_MSG,
                      sizeof(struct nss_wifi_fw_stats_msg), msg_cb, NULL);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: WIFI CE configure failed %d \n",__FUNCTION__, status);
        return 1;
    }

    return 0;
}

/*
 * osif_nss_peer_stats_frame_send
 *      Send Peer Stats Request Message to NSS
 */
int osif_nss_peer_stats_frame_send(struct ol_txrx_pdev_t *pdev, uint16_t peer_id)
{
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_peer_stats_msg *peer_stats_msg;
    nss_wifi_msg_callback_t msg_cb;
    nss_tx_status_t status;
    uint32_t ret;
    struct ol_ath_softc_net80211 *scn;
    void *nss_wifiol_ctx;
    int32_t ifnum = 0;
    struct ol_txrx_peer_t *peer = NULL;
    int32_t radio_id = -1;
    uint8_t tid = 0;

    if (pdev) {
            radio_id = pdev->nss_wifiol_id;
            ifnum = pdev->nss_ifnum;
            if (ifnum == -1) {
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no i/f found return ");
                    return 1;
            }
            nss_wifiol_ctx = pdev->nss_wifiol_ctx;
    }

    if (!pdev || !nss_wifiol_ctx) {
        return 0;
    }

    peer = ol_txrx_peer_find_by_id(pdev, peer_id);
    if (!peer) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Invalid peer id :%d\n", __FUNCTION__, peer_id);
        return 1;
    }

    scn = (struct ol_ath_softc_net80211 *)pdev->ctrl_pdev;

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    peer_stats_msg = &wifimsg.msg.peer_stats_msg;
    peer_stats_msg->peer_id = peer->peer_ids[0];

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;
    init_completion(&scn->osif_nss_ol_wifi_cfg_complete.complete);

    /*
     * Send wifi peer stats message
     */
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_PEER_STATS_MSG,
                      sizeof(struct nss_wifi_peer_stats_msg), msg_cb, NULL);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: WiFi peer stats send request %d \n",__FUNCTION__, status);
        return 1;
    }


    /*
     * Blocking call, wait till we get ACK for this msg.
     */
    ret = wait_for_completion_timeout(&scn->osif_nss_ol_wifi_cfg_complete.complete, msecs_to_jiffies(OSIF_NSS_WIFI_CFG_TIMEOUT_MS));
    if (ret == 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Waiting for peer stats req msg ack timed out %d\n", radio_id);
        return 1;
    }

    /*
     * ACK/NACK received from NSS FW
     */
    if (NSS_TX_FAILURE == scn->osif_nss_ol_wifi_cfg_complete.response) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NACK for peer_stats_send request from NSS FW %d\n", radio_id);
        return 1;
    }

    for (tid = 0; tid < NSS_WIFI_TX_NUM_TOS_TIDS; tid++) {
        peer->tidq[tid].stats[TIDQ_ENQUEUE_CNT] += peer_stats_msg->tidq_enqueue_cnt[tid];
        peer->tidq[tid].stats[TIDQ_DEQUEUE_CNT] += peer_stats_msg->tidq_dequeue_cnt[tid];
        peer->tidq[tid].stats[TIDQ_MSDU_TTL_EXPIRY] += peer_stats_msg->tidq_ttl_expire_cnt[tid];
        peer->tidq[tid].stats[TIDQ_PEER_Q_FULL] += peer_stats_msg->tidq_full_cnt[tid];
        peer->tidq[tid].stats[TIDQ_DEQUEUE_REQ_PKTCNT] += peer_stats_msg->tidq_dequeue_req_cnt[tid];
        peer->tidq[tid].high_watermark = peer_stats_msg->tidq_queue_max[tid];
        peer->tidq[tid].byte_count = peer_stats_msg->tidq_byte_cnt[tid];
    }

    return 0;
}

void osif_nss_ol_enable_dbdc_process(struct ieee80211com* ic, uint32_t enable)
{
    void *nss_wifiol_ctx = NULL;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    uint32_t radio_id;
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_dbdc_process_enable_msg *dbdc_enable = NULL;
    int ifnum;
    nss_tx_status_t status;
    struct ol_txrx_pdev_t *pdev = scn->pdev_txrx_handle;
    nss_wifi_msg_callback_t msg_cb;

    if (!pdev) {
        return;
    }

    nss_wifiol_ctx = pdev->nss_wifiol_ctx;
    if (!nss_wifiol_ctx) {
        return;
    }

    radio_id = pdev->nss_wifiol_id;

    ifnum = pdev->nss_ifnum;
    if (ifnum == -1) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no if found return ");
        return;
    }

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    dbdc_enable = &wifimsg.msg.dbdcpe_msg;

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;

#if DBDC_REPEATER_SUPPORT
    if (enable) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Enabling dbdc repeater process\n");
    } else {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Disabling dbdc repeater process\n");
    }

    dbdc_enable->dbdc_process_enable = enable;
#else
    dbdc_enable->dbdc_process_enable = 0;
#endif

    /*
     * Send enable dbdc process msg
     */
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_DBDC_PROCESS_ENABLE_MSG,
            sizeof(struct nss_wifi_dbdc_process_enable_msg), msg_cb, NULL);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WIFI enable dbdc process message send failed  %d \n", status);
        return;
    }

    return;
}

void osif_nss_ol_set_primary_radio(struct ol_txrx_pdev_t *pdev , uint32_t enable)
{
    void *nss_wifiol_ctx = NULL;
    uint32_t radio_id;
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_primary_radio_set_msg *primary_radio = NULL;
    int ifnum;
    nss_tx_status_t status;
    nss_wifi_msg_callback_t msg_cb;

    if (!pdev) {
        return;
    }

    nss_wifiol_ctx = pdev->nss_wifiol_ctx;
    if (!nss_wifiol_ctx) {
        return;
    }

    radio_id = pdev->nss_wifiol_id;

    ifnum = pdev->nss_ifnum;
    if (ifnum == -1) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no if found return ");
        return;
    }

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    primary_radio = &wifimsg.msg.wprs_msg;

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;

#if DBDC_REPEATER_SUPPORT
    if (enable) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Enabling primary_radio for if_num %d\n", ifnum);
    } else {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Disabling primary_radio for if_num %d\n", ifnum);
    }

    primary_radio->flag = enable;
#else
    primary_radio->flag = 0;
#endif

    /*
     * Send set primary radio msg
     */
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_PRIMARY_RADIO_SET_MSG,
            sizeof(struct nss_wifi_primary_radio_set_msg), msg_cb, NULL);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WIFI set primary radio message send failed  %d \n", status);
        return;
    }

    return;
}

void osif_nss_ol_set_always_primary(struct ieee80211com* ic, bool enable)
{
    void *nss_wifiol_ctx = NULL;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    uint32_t radio_id;
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_always_primary_set_msg *primary_radio = NULL;
    int ifnum;
    nss_tx_status_t status;
    struct ol_txrx_pdev_t *pdev = scn->pdev_txrx_handle;

    if (!pdev) {
        return;
    }

    nss_wifiol_ctx = pdev->nss_wifiol_ctx;
    if (!nss_wifiol_ctx) {
        return;
    }

    radio_id = pdev->nss_wifiol_id;
    ifnum = pdev->nss_ifnum;
    if (ifnum == -1) {
        qdf_print("no if found return \n");
        return;
    }

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    primary_radio = &wifimsg.msg.waps_msg;

    if (enable) {
        qdf_print("Enabling always primary \n");
    } else {
        qdf_print("Disabling always primary \n");
    }

    primary_radio->flag = enable;

    /*
     * Send set always primary msg
     */
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_ALWAYS_PRIMARY_SET_MSG,
            sizeof(struct nss_wifi_always_primary_set_msg), NULL, NULL);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        qdf_print("WIFI set always primary msg failed  %d \n", status);
    }

    return;
}

void osif_nss_ol_set_force_client_mcast_traffic(struct ieee80211com* ic)
{
    void *nss_wifiol_ctx = NULL;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    uint32_t radio_id;
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_force_client_mcast_traffic_set_msg *force_client_mcast_traffic = NULL;
    int ifnum;
    nss_tx_status_t status;
    struct ol_txrx_pdev_t *pdev = scn->pdev_txrx_handle;
    nss_wifi_msg_callback_t msg_cb;

    if (!pdev) {
        return;
    }

    nss_wifiol_ctx = pdev->nss_wifiol_ctx;
    if (!nss_wifiol_ctx) {
        return;
    }

    radio_id = pdev->nss_wifiol_id;

    ifnum = pdev->nss_ifnum;
    if (ifnum == -1) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no if found return ");
        return;
    }

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    force_client_mcast_traffic = &wifimsg.msg.wfcmts_msg;

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;

#if DBDC_REPEATER_SUPPORT
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "force_client_mcast_traffic for if_num %d is %d\n", ifnum, ic->ic_global_list->force_client_mcast_traffic);

    force_client_mcast_traffic->flag = ic->ic_global_list->force_client_mcast_traffic;
#else
    force_client_mcast_traffic->flag = 0;
#endif

    /*
     * Send force client mcast traffic msg
     */
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_FORCE_CLIENT_MCAST_TRAFFIC_SET_MSG,
            sizeof(struct nss_wifi_force_client_mcast_traffic_set_msg), msg_cb, NULL);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WIFI force client mcast traffic message send failed  %d \n", status);
        return;
    }

    return;
}

uint32_t osif_nss_ol_validate_dbdc_process(struct ieee80211com* ic) {
    struct global_ic_list *glist = ic->ic_global_list;
    int i;
    uint32_t nss_radio_sta_vap = 0;
    uint32_t non_nss_radio_sta_vap = 0;
    struct ieee80211com* tmpic;

    if (glist->dbdc_process_enable) {

        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "DBDC process check  num IC %d \n",glist->num_global_ic);
        for(i=0; i < glist->num_global_ic; i++) {
            tmpic = glist->global_ic[i];
            if (tmpic && tmpic->ic_sta_vap) {
                if (tmpic->ic_is_mode_offload(tmpic)) {
                    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(tmpic);
                    struct ol_txrx_pdev_t *pdev = scn->pdev_txrx_handle;
                    if (!pdev) {
                        continue;
                    }
                    if(pdev->nss_wifiol_ctx) {

                        nss_radio_sta_vap++;
                    }else {
                        non_nss_radio_sta_vap++;
                    }
                } else {
                    non_nss_radio_sta_vap++;
                }
            }
        }
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "nss_radio sta vap %d non nss radio sta vap %d \n", nss_radio_sta_vap, non_nss_radio_sta_vap);
        if( nss_radio_sta_vap && non_nss_radio_sta_vap) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS Offload: Disable dbdc process ,non supported configuration\n");
            glist->dbdc_process_enable = 0;

            for(i=0; i < glist->num_global_ic; i++) {
                tmpic = glist->global_ic[i];
                if (tmpic->ic_is_mode_offload(tmpic)) {
			QDF_PRINT_INFO(tmpic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS Offload: Send command to Disable dbdc process \n");
			osif_nss_ol_enable_dbdc_process(tmpic, 0);
                }
            }
            return 1;
        }
    }
    return 0;
}

void osif_nss_ol_store_other_pdev_stavap(struct ieee80211com* ic)
{
    void *nss_wifiol_ctx = NULL;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_softc_net80211 *tscn ;
    uint32_t radio_id, i;
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_store_other_pdev_stavap_msg *pdev_stavap = NULL;
    int ifnum;
    nss_tx_status_t status;
    struct ieee80211vap *vap = NULL;
    ol_txrx_vdev_handle vdev = NULL;
    osif_dev *osifp = NULL;
    struct ieee80211com* other_ic = NULL;
    struct ieee80211com* tmp_ic;
    struct ol_txrx_pdev_t *pdev;
    struct ol_txrx_pdev_t *tpdev;
    nss_wifi_msg_callback_t msg_cb;

    if (!ic->ic_is_mode_offload(ic)) {
        qdf_print("NSS offload : DBDC repeater IC is not in partial offload mode discard command to NSS \n");
        return;
    }

    pdev = scn->pdev_txrx_handle;

    if (!pdev) {
        return;
    }

    nss_wifiol_ctx = pdev->nss_wifiol_ctx;
    if (!nss_wifiol_ctx) {
        return;
    }

    radio_id = pdev->nss_wifiol_id;


    ifnum = pdev->nss_ifnum;
    if (ifnum == -1) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no if found return ");
        return;
    }

    if(osif_nss_ol_validate_dbdc_process(ic)){
        return;
    }

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    pdev_stavap = &wifimsg.msg.wsops_msg;

    for (i = 0 ;i < MAX_RADIO_CNT-1; i++) {
        tmp_ic = ic->other_ic[i];

        if (tmp_ic && tmp_ic->ic_is_mode_offload(tmp_ic)) {
            tscn = OL_ATH_SOFTC_NET80211(tmp_ic);
            tpdev = tscn->pdev_txrx_handle;
            if (!tpdev ) {
                continue ;
            }
            if (tpdev->nss_wifiol_ctx && tmp_ic->ic_sta_vap) {
                qdf_print("NSS : Other IC in NSS mode with station VAP \n");
                other_ic = tmp_ic;
                break;
            }
        }
    }

    if (!other_ic) {
        qdf_print("No other sta vap in nss offload mode \n");
        return;
    }

    vap = other_ic->ic_sta_vap;
    vdev = vap->iv_txrx_handle;
    osifp = (osif_dev *)vdev->osif_vdev;
    pdev_stavap->stavap_ifnum = osifp->nss_ifnum;

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;
    qdf_print("pdev if_num %d other pdev stavap if_num is %d other_stavap: %p ",ifnum,  pdev_stavap->stavap_ifnum, vap);

    /*
     * Send store other pdev stavap msg
     */
    if(ifnum == NSS_PROXY_VAP_IF_NUMBER) {
        qdf_print("Error : Psta vap not supported for mcast recv \n");
        return;
    }
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_STORE_OTHER_PDEV_STAVAP_MSG,
            sizeof(struct nss_wifi_store_other_pdev_stavap_msg), msg_cb, NULL);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        qdf_print("WIFI store other pdev stavap message send failed  %d \n", status);
        return;
    }

    return;
}

void osif_nss_ol_set_perpkt_txstats(struct ol_ath_softc_net80211 *scn)
{
    void *nss_wifiol_ctx = NULL;
    uint32_t radio_id;
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_enable_perpkt_txstats_msg *set_perpkt_txstats;
    int ifnum;
    nss_tx_status_t status;
    struct ol_txrx_pdev_t *pdev = scn->pdev_txrx_handle;
    nss_wifi_msg_callback_t msg_cb;

    if (!pdev) {
        return;
    }

    nss_wifiol_ctx = pdev->nss_wifiol_ctx;
    if (!nss_wifiol_ctx) {
        return;
    }

    radio_id = pdev->nss_wifiol_id;

    ifnum = pdev->nss_ifnum;
    if (ifnum == -1) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no if found return ");
        return;
    }

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    set_perpkt_txstats = &wifimsg.msg.ept_msg;

#if ATH_DATA_TX_INFO_EN
    set_perpkt_txstats->perpkt_txstats_flag = scn->enable_perpkt_txstats;
#else
    set_perpkt_txstats->perpkt_txstats_flag = 0;
#endif

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;

    /*
     * Send perpkt_txstats configure msg
     */
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_ENABLE_PERPKT_TXSTATS_MSG,
            sizeof(struct nss_wifi_enable_perpkt_txstats_msg), msg_cb, NULL);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WIFI set perpkt txstats message send failed  %d \n", status);
        return;
    }

    return;
}

void osif_nss_ol_set_igmpmld_override_tos(struct ol_ath_softc_net80211 *scn)
{
    void *nss_wifiol_ctx = NULL;
    uint32_t radio_id;
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_igmp_mld_override_tos_msg *igmp_mld_tos;
    int ifnum;
    nss_tx_status_t status;
    struct ol_txrx_pdev_t *pdev = scn->pdev_txrx_handle;
    nss_wifi_msg_callback_t msg_cb;

    if (!pdev) {
        return;
    }

    nss_wifiol_ctx = pdev->nss_wifiol_ctx;
    if (!nss_wifiol_ctx) {
        return;
    }

    radio_id = pdev->nss_wifiol_id;

    ifnum = pdev->nss_ifnum;
    if (ifnum == -1) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no if found return ");
        return;
    }

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    igmp_mld_tos = &wifimsg.msg.wigmpmldtm_msg;

    igmp_mld_tos->igmp_mld_ovride_tid_en = scn->igmpmld_override;
    igmp_mld_tos->igmp_mld_ovride_tid_val = scn->igmpmld_tid;

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;

    /*
     * Send igmp_mld_tos override configure msg
     */
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_IGMP_MLD_TOS_OVERRIDE_MSG,
            sizeof(struct nss_wifi_igmp_mld_override_tos_msg), msg_cb, NULL);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WIFI set igmp/mld tos configuration failed :%d \n", status);
        return;
    }

    return;
}

void osif_nss_ol_set_msdu_ttl(struct ol_txrx_pdev_t *pdev)
{
    void *nss_wifiol_ctx = pdev->nss_wifiol_ctx;
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_msdu_ttl_set_msg *set_msdu_ttl;
    int ifnum;
    nss_tx_status_t status;
    nss_wifi_msg_callback_t msg_cb;

    if (!nss_wifiol_ctx) {
        return;
    }

    ifnum = pdev->nss_ifnum;
    if (ifnum == -1) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no if found return ");
        return;
    }

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    set_msdu_ttl = &wifimsg.msg.msdu_ttl_set_msg;
    set_msdu_ttl->msdu_ttl = pdev->pflow_msdu_ttl * pdev->pflow_cong_ctrl_timer_interval;

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;

    /*
     * Send msdu_ttl configure msg
     */
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_MSDU_TTL_SET_MSG,
            sizeof(struct nss_wifi_msdu_ttl_set_msg), msg_cb, NULL);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WIFI set msdu ttl message send failed  %d \n", status);
        return;
    }

    return;
}

int osif_nss_ol_wifi_monitor_set_filter(struct ieee80211com* ic, uint32_t filter_type)
{

    struct ol_ath_softc_net80211 *scn;
    int ifnum ;
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_monitor_set_filter_msg *set_filter_msg ;
    nss_tx_status_t status;
    void *nss_wifiol_ctx;
    int radio_id;
    nss_wifi_msg_callback_t msg_cb;
    struct ol_txrx_pdev_t *pdev = NULL;

    if (!ic->ic_is_mode_offload(ic)) {
        return 0;
    }

    scn = OL_ATH_SOFTC_NET80211(ic);
    nss_wifiol_ctx= scn->nss_wifiol_ctx;
    radio_id = scn->nss_wifiol_id;
    pdev = scn->pdev_txrx_handle;

    if (!nss_wifiol_ctx) {
        return 0;
    }

    ifnum = pdev->nss_ifnum;
    if (ifnum == -1) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no if found return ");
        return -1;
    }

    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s %p %p %d %d \n",__func__,nss_wifiol_ctx, scn, radio_id, filter_type);

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    set_filter_msg = &wifimsg.msg.monitor_filter_msg;
    set_filter_msg->filter_type = filter_type;

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;

    /*
     * Send Monitor Filter Set message
     */
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_MONITOR_FILTER_SET_MSG,
            sizeof(struct nss_wifi_monitor_set_filter_msg), msg_cb, NULL);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WIFI monitor set filter message send failed  %d \n", status);
        return -1;
    }

    return 0;
}

/*
 *osif_nss_ol_stats_cfg
 * 	configuring pkt log for wifi
 */

int osif_nss_ol_stats_cfg(struct ol_ath_softc_net80211 *scn, uint32_t cfg)
{
    int ifnum=-1;
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_ol_stats_cfg_msg *pcm_msg ;
    nss_tx_status_t status;
    void *nss_wifiol_ctx= scn->nss_wifiol_ctx;
    int radio_id = scn->nss_wifiol_id;
    nss_wifi_msg_callback_t msg_cb;

    if (!nss_wifiol_ctx) {
        return 0;
    }

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s %p %p %d ol stats enable %d\n",__func__, nss_wifiol_ctx, scn, radio_id, cfg);

    ifnum = scn->nss_ifnum;
    if (ifnum == -1) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no if found return ");
        return -1;
    }

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    pcm_msg = &wifimsg.msg.scm_msg;
    pcm_msg->stats_cfg = cfg;

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;

    /*
     * Send ol_stats configure
     */
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_OL_STATS_CFG_MSG,
            sizeof(struct nss_wifi_ol_stats_cfg_msg), msg_cb, NULL);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WIFI Pause message send failed  %d \n", status);
        return -1;
    }

    return 0;
}

/*
 *osif_nss_ol_pktlog_cfg
 * 	configuring pkt log for wifi
 */

int osif_nss_ol_pktlog_cfg(struct ol_ath_softc_net80211 *scn, int enable)
{
    int ifnum=-1;
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_pktlog_cfg_msg *pcm_msg ;
    nss_tx_status_t status;
    void *nss_wifiol_ctx= scn->nss_wifiol_ctx;
    int radio_id = scn->nss_wifiol_id;
    nss_wifi_msg_callback_t msg_cb;
    struct ol_txrx_pdev_t *pdev = NULL;
    scn->nss_pktlog_en = enable;

    if (!nss_wifiol_ctx) {
        return 0;
    }

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s %p %p %d PKT log enable %d buf 64 \n",__func__,nss_wifiol_ctx, scn, radio_id, enable);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "pktlog hdrsize %d msdu_id_offset %d \n", scn->pl_dev->pktlog_hdr_size, scn->pl_dev->msdu_id_offset);

    pdev = scn->pdev_txrx_handle;
    if(pdev) {
	    ifnum = pdev->nss_ifnum;
	    if (ifnum == -1) {
		    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no if found return ");
		    return -1;
	    }
    }

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    pcm_msg = &wifimsg.msg.pcm_msg;
    pcm_msg->enable = enable;
    pcm_msg->bufsize = 64;
    pcm_msg->hdrsize = scn->pl_dev->pktlog_hdr_size;
    pcm_msg->msdu_id_offset = scn->pl_dev->msdu_id_offset;

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;

    /*
     * Send packet_log configure
     */
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_PKTLOG_CFG_MSG,
            sizeof(struct nss_wifi_pktlog_cfg_msg), msg_cb, NULL);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WIFI Pause message send failed  %d \n", status);
        return -1;
    }
    return 0;
}


int osif_nss_ol_wifi_pause(struct ol_ath_softc_net80211 *scn)
{
    int ifnum=-1;
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_stop_msg *pausemsg ;
    nss_tx_status_t status;
    void *nss_wifiol_ctx;
    int radio_id, retrycnt = 0;
    nss_wifi_msg_callback_t msg_cb;

    radio_id = scn->nss_wifiol_id;
    nss_wifiol_ctx= scn->nss_wifiol_ctx;
    if (!nss_wifiol_ctx) {
        return 0;
    }

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s %p %p %d \n",__func__,nss_wifiol_ctx, scn, radio_id);

    ifnum = scn->nss_ifnum;
    if (ifnum == -1) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no if found return ");
        return -1;
    }



    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    pausemsg = &wifimsg.msg.stopmsg;
    pausemsg->radio_id = radio_id;

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;

    /*
     * Send WIFI Stop Message
     */
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_STOP_MSG,
            sizeof(struct nss_wifi_stop_msg), msg_cb, NULL);

    while((status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg)) != NSS_TX_SUCCESS)
    {
        retrycnt++;
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WIFI Pause message send failed  %d Retrying %d \n", status, retrycnt);
        if (retrycnt >= OSIF_NSS_OL_MAX_RETRY_CNT){
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Max retry reached : Unregistering with NSS\n");
            return -1;
        }
    }

    return 0;
}

/*
 *osif_nss_tx_queue_cfg
 * 	configuring tx queue size for wifi
 */
int osif_nss_tx_queue_cfg(struct ol_txrx_pdev_t *pdev, uint32_t range, uint32_t buf_size)
{
    void *nss_wifiol_ctx = pdev->nss_wifiol_ctx;
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_tx_queue_cfg_msg *wtxqcm ;
    int ifnum;
    nss_tx_status_t status;
    nss_wifi_msg_callback_t msg_cb;

    if (!nss_wifiol_ctx) {
        return 0;
    }

    ifnum = pdev->nss_ifnum;
    if (ifnum == -1) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no if found return ");
        return 0;
    }

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    wtxqcm = &wifimsg.msg.wtxqcm;
    wtxqcm->range = range;
    wtxqcm->size = buf_size;

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;

    /*
     * Send tx_queue configure
     */
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_TX_QUEUE_CFG_MSG,
            sizeof(struct nss_wifi_tx_queue_cfg_msg), msg_cb, NULL);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WIFI radio mode message failed  %d \n", status);
        return -1;
    }

    return 0;
}

/*
 * osif_nss_tx_queue_min_threshold_cfg
 * 	configuring tx min threshold for queueing for wifi
 */
int osif_nss_tx_queue_min_threshold_cfg(struct ol_txrx_pdev_t *pdev, uint32_t min_threshold)
{
    void *nss_wifiol_ctx = pdev->nss_wifiol_ctx;
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_tx_min_threshold_cfg_msg *wtx_min_threshold_cm;
    int ifnum;
    nss_tx_status_t status;
    nss_wifi_msg_callback_t msg_cb;

    if (!nss_wifiol_ctx) {
        return 0;
    }

    ifnum = pdev->nss_ifnum;
    if (ifnum == -1) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no if found return ");
        return 0;
    }

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    wtx_min_threshold_cm = &wifimsg.msg.wtx_min_threshold_cm;
    wtx_min_threshold_cm->min_threshold = min_threshold;

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;

    /*
     * Send min_threshold configure
     */
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_TX_MIN_THRESHOLD_CFG_MSG,
            sizeof(struct nss_wifi_tx_min_threshold_cfg_msg), msg_cb, NULL);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WIFI radio mode message failed  %d \n", status);
        return -1;
    }

    return 0;
}

/*
 * osif_nss_ol_wifi_tx_capture_set
 *  Enable Tx Data Capture from TX Completion MSG
 */
int osif_nss_ol_wifi_tx_capture_set(struct ol_txrx_pdev_t *pdev, uint8_t tx_capture_enable)
{
    void *nss_wifiol_ctx = pdev->nss_wifiol_ctx;
    uint32_t radio_id = pdev->nss_wifiol_id;
    struct nss_wifi_msg wifimsg;
    int ifnum ;
    struct nss_wifi_tx_capture_msg *tx_capture_msg ;
    nss_tx_status_t status;

    if (!nss_wifiol_ctx) {
        return 0;
    }

    ifnum = pdev->nss_ifnum;
    if (ifnum == -1) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no if found return ");
        return -1;
    }

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s %p %d %d \n",__func__,nss_wifiol_ctx,radio_id,tx_capture_enable);

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    tx_capture_msg = &wifimsg.msg.tx_capture_msg;
    tx_capture_msg->tx_capture_enable = tx_capture_enable;

    /*
     * Send WIFI CE configure
     */
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_TX_CAPTURE_SET_MSG,
            sizeof(struct nss_wifi_tx_capture_msg), NULL, NULL);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WIFI TX Data Capture message send failed  %d \n", status);
        return -1;
    }

    return 0;
}

int osif_nss_ol_wifi_reset(struct ol_ath_softc_net80211 *scn, uint16_t delay)
{
    int ifnum=-1;
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_reset_msg *resetmsg ;
    nss_tx_status_t status;
    void *nss_wifiol_ctx;
    int radio_id, retrycnt = 0;
    struct ol_txrx_pdev_t *pdev;
    int i = 0;
    nss_wifi_msg_callback_t msg_cb;

    /*
     * Reset the Global Allocated RadioIDX
     */
    if (scn->nss_idx != -1) {
            glbl_allocated_radioidx &= ~(1 << scn->nss_idx);
            qdf_print("%s: Reset Glbl RadioIDX to %d\n", __FUNCTION__, glbl_allocated_radioidx);
	    scn->nss_idx = -1;
    }

    nss_wifiol_ctx= scn->nss_wifiol_ctx;
    if (!nss_wifiol_ctx) {
        return 0;
    }

    radio_id = scn->nss_wifiol_id;

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s %p %p %d \n",__func__,nss_wifiol_ctx, scn, radio_id);

    pdev = scn->pdev_txrx_handle;
    if (pdev) {
        /*
         * clear the wifiol ctx
         */
        pdev->nss_wifiol_ctx = NULL;
    }

    scn->nss_wifiol_ctx = NULL;
    ifnum = scn->nss_ifnum;
    if (ifnum == -1) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no if found return ");
        return -1;
    }

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    resetmsg = &wifimsg.msg.resetmsg;
    resetmsg->radio_id = radio_id;

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;

    /*
     * Send WIFI CE configure
     */
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_RESET_MSG,
            sizeof(struct nss_wifi_reset_msg), msg_cb, NULL);

    while((status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg)) != NSS_TX_SUCCESS)
    {
        retrycnt++;
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WIFI reset message send failed  %d Retrying %d \n", status, retrycnt);
        if (retrycnt >= OSIF_NSS_OL_MAX_RETRY_CNT){
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Max retry reached : Unregistering with NSS\n");
            break;
        }
    }

    if (pdev) {

        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "freeing rra memory pool\n");
        for (i = 0; i < OSIF_NSS_OL_MAX_RRA_POOLS; i++) {
            if (pdev->rra_mem_pool[i]) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "freeing rra mem pool for pool_id %d", i);
                kfree(pdev->rra_mem_pool[i]);
            }
        }

        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "freeing peer memory pool\n");
        for (i = 0; i < OSIF_NSS_OL_MAX_PEER_POOLS; i++) {
            if (pdev->peer_mem_pool[i]) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "freeing peer mem pool for pool_id %d", i);
                kfree(pdev->peer_mem_pool[i]);
            }
        }
    }

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "nss wifi offload reset\n");
    if (delay) {
        mdelay(delay);
    }
    /*
     * Unregister wifi with NSS
     */
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "unregister wifi with nss\n");

    /*
     * Clear nss variable state
     */
    nss_unregister_wifi_if(ifnum);
    scn->nss_wifiol_ce_enabled = 0;

    return 0;
}

int osif_nss_ol_wifi_init(struct ol_ath_softc_net80211 *scn) {

#define CE_HTT_MSG_CE           5
#define CE_HTT_TX_CE            4

    struct hif_opaque_softc *osc = (struct hif_opaque_softc *)(scn->hif_hdl);
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_init_msg *msg;
    int ifnum ;
    void * nss_wifiol_ctx= NULL;
    int features = 0;
    struct hif_pipe_addl_info *hif_info_rx;
    struct hif_pipe_addl_info *hif_info_tx;
    nss_tx_status_t status;
    nss_wifi_msg_callback_t msg_cb;

    if (!osc) {
        qdf_print(" hif handle is NULL : %s \n", __func__ );
        return -1;
    }

    if (!scn->nss_wifi_ol_mode) {
        qdf_print(" nss wifi ol mode is NULL: %s \n", __func__);
        return -1;
    }

    hif_set_nss_wifiol_mode(osc, scn->nss_wifi_ol_mode);
    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    msg = &wifimsg.msg.initmsg;
    hif_info_rx = (struct hif_pipe_addl_info*)qdf_mem_malloc(sizeof(struct hif_pipe_addl_info));

    if (hif_info_rx == NULL) {
	    qdf_print(" Unable to allocate memory : %s \n", __func__);
	    return -1;
    }

    hif_info_tx = (struct hif_pipe_addl_info*)qdf_mem_malloc(sizeof(struct hif_pipe_addl_info));

    if (hif_info_tx == NULL) {
	    qdf_print(" Unable to allocate memory : %s \n", __func__);
	    qdf_mem_free(hif_info_rx);
	    return -1;
    }

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;

    msg->radio_id = scn->nss_wifiol_id;
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS %s :sc %p NSS ID %d  Taret type %x \n",__FUNCTION__, osc, scn->nss_wifiol_id, scn->target_type);

    memset(hif_info_rx, 0, sizeof(struct hif_pipe_addl_info));
    memset(hif_info_tx, 0, sizeof(struct hif_pipe_addl_info));


    hif_get_addl_pipe_info(osc, hif_info_tx, CE_HTT_TX_CE);
    hif_get_addl_pipe_info(osc, hif_info_rx, CE_HTT_MSG_CE);

    msg->pci_mem = hif_info_tx->pci_mem;

    msg->ce_tx_state.ctrl_addr = hif_info_tx->ctrl_addr;
    msg->ce_rx_state.ctrl_addr = hif_info_rx->ctrl_addr;

    update_ring_info(&msg->ce_tx_state.src_ring, &msg->ce_tx_state.dest_ring, hif_info_tx);
    update_ring_info(&msg->ce_rx_state.src_ring, &msg->ce_rx_state.dest_ring, hif_info_rx);

    qdf_mem_free(hif_info_tx);
    qdf_mem_free(hif_info_rx);

    msg->target_type = scn->target_type;

    ifnum = scn->nss_ifnum;
    if (ifnum == -1) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no if found return ");
        return -1;
    }

    /*
     * Register wifi with NSS
     */
    nss_wifiol_ctx   = nss_register_wifi_if(ifnum,
            (nss_wifi_callback_t)osif_nss_ol_wifi_ce_callback_func,
            (nss_wifi_callback_t)osif_nss_ol_wifi_ext_callback_func,
            (nss_wifi_msg_callback_t)osif_nss_ol_event_receive,
             (struct net_device *)scn, features
             );

     if(nss_wifiol_ctx  == NULL){
         QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS-WifiOffload: NSS regsiter fail\n");
     }

     scn->nss_wifiol_ctx = nss_wifiol_ctx;


     /*
      * Enable new Data path for MU-MIMO
      */
     msg->mu_mimo_enhancement_en = 1;

     /*
      * Update NW process bypass cfg in NSS for ingress packets on radio
      */
     msg->bypass_nw_process = scn->nss_wifiol_bypass_nw_process;

     scn->nss_wifiol_ctx= nss_wifiol_ctx;
     QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS-WifiOffload: nss_wifiol_ctx %p \n",nss_wifiol_ctx);

     /*
      * Send WIFI CE configure
      */
     nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_INIT_MSG,
             sizeof(struct nss_wifi_init_msg), msg_cb, NULL);

     status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
     if (status != NSS_TX_SUCCESS) {
         QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS-WifiOffload: wifi initialization fail%d \n", status);
         return -1;
     }
     mdelay(100);

     return 0;
}

void osif_nss_ol_post_recv_buffer(struct ol_ath_softc_net80211 *scn)
{

    struct hif_opaque_softc *sc = (struct hif_opaque_softc *)(scn->hif_hdl);
    int ifnum ;
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_init_msg *intmsg;
    nss_tx_status_t status;
    void *nss_wifiol_ctx;
    int radio_id;
    nss_wifi_msg_callback_t msg_cb;

    nss_wifiol_ctx= scn->nss_wifiol_ctx;
    if (!nss_wifiol_ctx) {
        return;
    }

    if (!sc) {
        qdf_print(" hif handle is NULL : %s \n",__func__ );
        return;
    }

    radio_id = scn->nss_wifiol_id;

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s %p %p %d \n",__func__,nss_wifiol_ctx, sc, radio_id);

    ifnum = scn->nss_ifnum;
    if (ifnum == -1) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no if found return ");
        return ;
    }

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    intmsg = &wifimsg.msg.initmsg;

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;

    /*
     * Send WIFI Post Receive Message
     */
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_POST_RECV_MSG,
            sizeof(struct nss_wifi_init_msg), msg_cb, NULL);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WIFI CE configure failed %d \n", status);
        return;
    }
    /* CE_per_engine_disable_interupt((struct CE_handle *)CE_state); */
    hif_disable_interrupt(sc, CE_HTT_MSG_CE);
    mdelay(100);
}

int osif_nss_ol_pdev_attach(struct ol_ath_softc_net80211 *scn, void *nss_wifiol_ctx,
        int radio_id,
        uint32_t desc_pool_size,
        uint32_t *tx_desc_array,
        uint32_t wlanextdesc_addr,
        uint32_t wlanextdesc_size,
        uint32_t htt_tx_desc_base_vaddr, uint32_t htt_tx_desc_base_paddr ,
        uint32_t htt_tx_desc_offset,
        uint32_t pmap_addr)
{
    int ifnum ;
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_tx_init_msg *st ;
    nss_tx_status_t status;
    nss_wifi_msg_callback_t msg_cb;
    int mem_send = -1;
    struct htt_pdev_t *htt_pdev = scn->htt_pdev;
    struct ol_txrx_pdev_t *pdev = htt_pdev->txrx_pdev;
    struct ieee80211com *ic = &scn->sc_ic;;


    if (!nss_wifiol_ctx) {
        return 0;
    }

    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s :NSS %p NSS ID %d  target type  \n",__FUNCTION__, nss_wifiol_ctx, radio_id);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s :NSS %p NSS ID %d \n",__FUNCTION__, nss_wifiol_ctx, radio_id);

    ifnum = scn->nss_ifnum;
    if (ifnum == -1) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no if found return ");
        return -1;
    }

    if (scn->nss_wifiol_ce_enabled != 1) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " CE init was unsuccesful \n");
        return -1;
    }

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    st = &wifimsg.msg.pdevtxinitmsg;

    st->desc_pool_size   = desc_pool_size;
    st->tx_desc_array = 0;
    st->wlanextdesc_addr = wlanextdesc_addr;
    st->wlanextdesc_size = wlanextdesc_size;
    st->htt_tx_desc_base_vaddr = htt_tx_desc_base_vaddr;
    st->htt_tx_desc_base_paddr = htt_tx_desc_base_paddr;
    st->htt_tx_desc_offset = htt_tx_desc_offset;
    st->pmap_addr = pmap_addr;

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;

    // Register the nss related functions
    ic->nss_funcs = &nss_wifi_funcs;
    osif_register_dev_ops_xmit(osif_nss_ol_vap_hardstart, OSIF_NETDEV_TYPE_NSS_WIFIOL);

    /*
     * Send WIFI CE configure
     */
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_TX_INIT_MSG,
            sizeof(struct nss_wifi_tx_init_msg), msg_cb, NULL);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS-WifiOffload: pdev init fail %d \n", status);
        return -1;
    }
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS-WifiOffload: pdev init delay\n");
    mdelay(100);

    pdev->last_rra_pool_used = -1;
    pdev->last_peer_pool_used = -1;
    pdev->max_peers_per_pool = 67;
    pdev->max_rra_per_pool = 67;

    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "sending peer pool memory\n");
    mem_send = osif_nss_ol_send_peer_memory(scn);
    if (mem_send != 0) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Not able to send memory for peer to NSS\n");
        return -1;
    }
    mdelay(100);

    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "sending rra pool memory\n");
    mem_send = osif_nss_ol_send_rra_memory(scn);
    if (mem_send != 0) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Not able to send memory for rx reorder array to NSS\n");
        return -1;
    }
    mdelay(100);

    if (scn->nss_wifiol_id == 0) {
        osif_nss_ol_set_primary_radio(pdev, 1);
    } else {
        osif_nss_ol_set_primary_radio(pdev, 0);
    }

    return 0;
}
#ifndef HTC_HEADER_LEN
#define HTC_HEADER_LEN 8
#endif
struct htc_frm_hdr_t {
    uint32_t   EndpointID : 8,
               Flags : 8,
               PayloadLen : 16;
    uint32_t   ControlBytes0 : 8,
               ControlBytes1 : 8,
               reserved : 16;
};

int osif_ol_nss_htc_send(struct ol_txrx_pdev_t *pdev, void *nss_wifiol_ctx, int nssid, qdf_nbuf_t netbuf, uint32_t transfer_id)
{

    struct htc_frm_hdr_t * htchdr;
    int status =0, len;

    if (!nss_wifiol_ctx) {
        return 0;
    }

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s :NSS %p NSS ID %d \n",__FUNCTION__, nss_wifiol_ctx, nssid);

    len =  qdf_nbuf_len(netbuf);
    qdf_nbuf_push_head(netbuf, HTC_HEADER_LEN);
    netbuf->len += HTC_HEADER_LEN;
    htchdr = (struct htc_frm_hdr_t *)qdf_nbuf_data(netbuf);

    memset(htchdr, 0, HTC_HEADER_LEN);
    htchdr->EndpointID = transfer_id;
    htchdr->PayloadLen = len;

    status = osif_nss_ol_ce_raw_send(
            pdev,
            nss_wifiol_ctx,
            nssid,
            netbuf, len+HTC_HEADER_LEN);
    return status;
}

int osif_ol_nss_htc_flush(struct ol_txrx_pdev_t *pdev, void *nss_wifiol_ctx, int nssid)
{
    int ifnum ;
    struct nss_wifi_msg wifimsg;
    nss_tx_status_t status;

    if (!nss_wifiol_ctx) {
        return 0;
    }

    printk("%s :NSS %p NSS ID %d \n",__FUNCTION__, nss_wifiol_ctx, nssid);

    if (pdev->nss_wifiol_htc_flush_done) {
	    return 0;
    }

    ifnum = pdev->nss_ifnum;
    if(ifnum == -1){
        printk("no iunterface found return");
        return 1;
    }

    /*
     * Send WIFI CE configure
     */
    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));

    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_FLUSH_HTT_CMD_MSG,
            sizeof(struct nss_wifi_rawsend_msg), NULL, NULL);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        printk("WIFI CE flush raw send msg failed %d \n", status);
        return 1;
    }

    /*
     * set the flag first time; no need to send it for each vap
     */
    pdev->nss_wifiol_htc_flush_done = 1;

    printk("delay 100ms \n");
    mdelay(100);
    return 0;
}

void
htt_t2h_msg_handler_fast(void *htt_pdev, qdf_nbuf_t *nbuf_cmpl_arr,
                         uint32_t num_cmpls);

int osif_nss_ol_htt_rx_init(void *htt_handle)
{
    struct htt_pdev_t *htt_pdev;
    void *nss_wifiol_ctx;
    int radio_id ;
    int ringsize;
    int fill_level;
    uint32_t paddrs_ringptr;
    uint32_t paddrs_ringpaddr;
    uint32_t alloc_idx_vaddr;
    uint32_t alloc_idx_paddr;
    int ifnum ;
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_htt_init_msg *st ;
    nss_tx_status_t status;
    nss_wifi_msg_callback_t msg_cb;
    struct ol_ath_softc_net80211 *scn;
    uint32_t ret;

    if (!htt_handle) {
        return 0;
    }


    htt_pdev = (struct htt_pdev_t *)htt_handle;
    scn = (struct ol_ath_softc_net80211 *)htt_pdev->ctrl_pdev;

    nss_wifiol_ctx = htt_pdev->nss_wifiol_ctx;
    if (!nss_wifiol_ctx) {
        return 0;
    }

    radio_id = htt_pdev->nss_wifiol_id;
    ringsize = htt_pdev->rx_ring.size;
    fill_level = htt_pdev->rx_ring.fill_level;
    paddrs_ringptr = (uint32_t)htt_pdev->rx_ring.buf.paddrs_ring;
    paddrs_ringpaddr = (uint32_t)htt_pdev->rx_ring.base_paddr;
    alloc_idx_vaddr = (uint32_t)htt_pdev->rx_ring.alloc_idx.vaddr;
    alloc_idx_paddr = (uint32_t)htt_pdev->rx_ring.alloc_idx.paddr;

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s :NSS %p NSS ID %d \n",__FUNCTION__, nss_wifiol_ctx, radio_id);

    ifnum = htt_pdev->txrx_pdev->nss_ifnum;
    if (ifnum == -1) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no if found return ");
        return 1;
    }

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    st = &wifimsg.msg.httinitmsg;

    st->radio_id = radio_id;
    st->ringsize         = ringsize;
    st->fill_level       = fill_level;
    st->paddrs_ringptr   = paddrs_ringptr;
    st->paddrs_ringpaddr = paddrs_ringpaddr;
    st->alloc_idx_vaddr  = alloc_idx_vaddr;
    st->alloc_idx_paddr  = alloc_idx_paddr;

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;
    init_completion(&scn->osif_nss_ol_wifi_cfg_complete.complete);
    /*
     * Send WIFI HTT Init
     */
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_HTT_INIT_MSG,
            sizeof(struct nss_wifi_htt_init_msg), msg_cb, NULL);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS-WifiOffload: htt rx configure fail %d \n", status);
        return 1;
    }

    /*
     * Blocking call, wait till we get ACK for this msg.
     */
    ret = wait_for_completion_timeout(&scn->osif_nss_ol_wifi_cfg_complete.complete, msecs_to_jiffies(OSIF_NSS_WIFI_CFG_TIMEOUT_MS));
    if (ret == 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Waiting for htt rx init config msg ack timed out\n");
        return 1;
    }

    /*
     * ACK/NACK received from NSS FW
     */
    if (NSS_TX_FAILURE == scn->osif_nss_ol_wifi_cfg_complete.response) {

        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "nack for htt_rx_init config msg\n");
        return 1;
    }

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS-WifiOffload: htt rx configure  delay 100ms start \n");
    mdelay(100);
    return 0;
}

static int osif_nss_ol_ce_raw_send(struct ol_txrx_pdev_t *pdev, void *nss_wifiol_ctx, uint32_t radio_id, qdf_nbuf_t netbuf, uint32_t  len )
{
    int ifnum ;
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_rawsend_msg *st ;
    nss_tx_status_t status;
    nss_wifi_msg_callback_t msg_cb;

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s :NSS %p NSS ID %d \n",__FUNCTION__, nss_wifiol_ctx, radio_id);

    ifnum = pdev->nss_ifnum;
    if (ifnum == -1) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no if found return ");
        return 1;
    }

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    st = &wifimsg.msg.rawmsg;

    st->len   = len;
    memcpy(st->array, netbuf->data, len);

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;

    /*
     * Send WIFI Raw Send Message
     */
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_RAW_SEND_MSG,
            sizeof(struct nss_wifi_rawsend_msg), msg_cb, NULL);

    qdf_nbuf_free(netbuf);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "htt config message failed %d \n", status);
        return 1;
    }
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "delay 100ms \n");
    mdelay(100);
    return 0;
}

int osif_nss_ol_pdev_add_wds_peer(ol_txrx_pdev_handle pdev, uint8_t *peer_mac, uint8_t *dest_mac)
{
    void *nss_wifiol_ctx;
    uint32_t radio_id;
    int ifnum ;
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_wds_peer_msg *st ;
    nss_tx_status_t status;
    nss_wifi_msg_callback_t msg_cb;

    if (!pdev) {
        return 0;
    }

    nss_wifiol_ctx = pdev->nss_wifiol_ctx;
    radio_id = pdev->nss_wifiol_id;

    if (!nss_wifiol_ctx) {
        return 0;
    }

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : Add NSS %p NSS ID %d peer: %02x:%02x:%02x:%02x:%02x:%02x "
           "dest: %02x:%02x:%02x:%02x:%02x:%02x\n",
           __FUNCTION__, nss_wifiol_ctx, radio_id,
           peer_mac[0], peer_mac[1], peer_mac[2],
           peer_mac[3], peer_mac[4], peer_mac[5],
           dest_mac[0], dest_mac[1], dest_mac[2],
           dest_mac[3], dest_mac[4], dest_mac[5]);

    ifnum = pdev->nss_ifnum;
    if (ifnum == -1) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "no if found return ");
        return 1;
    }

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    st = &wifimsg.msg.pdevwdspeermsg;
    memcpy(st->peer_mac, peer_mac, 6);
    memcpy(st->dest_mac, dest_mac, 6);

    /*
     * Send peer add message
     */
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_WDS_PEER_ADD_MSG,
            sizeof(struct nss_wifi_tx_init_msg), msg_cb, NULL);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WIFI CE configure failt %d \n", status);
        return 1;
    }

    return 0;
}

/*
 * osif_nss_send_cmd()
 *	API for notifying the pdev related command to NSS.
 */
static void osif_nss_send_cmd(struct nss_ctx_instance *nss_wifiol_ctx, int32_t if_num,
        enum nss_wifi_cmd cmd, uint32_t value)

{
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_cmd_msg *wificmd;

    bool status;

    wificmd = &wifimsg.msg.wcmdm;
    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));

    wificmd->cmd = cmd;
    wificmd->value = value;
    nss_cmn_msg_init(&wifimsg.cm, if_num, NSS_WIFI_CMD_MSG,
            sizeof(struct nss_wifi_cmd_msg), NULL, NULL);

    /*
     * Send the pdev configure message down to NSS
     */
    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        printk("Unable to send the pdev command message to NSS\n");
    }
}

/*
 * osif_nss_ol_set_cfg
 */
void osif_nss_ol_set_cfg(ol_txrx_pdev_handle pdev, enum osif_nss_wifi_cmd osif_cmd)
{
    void *nss_wifiol_ctx;
    uint32_t radio_id;
    int ifnum;
    uint32_t cmd, val;

    nss_wifiol_ctx = pdev->nss_wifiol_ctx;
    radio_id = pdev->nss_wifiol_id;
    cmd = NSS_WIFI_MAX_CMD;

    if (!nss_wifiol_ctx) {
        return;
    }

    ifnum = pdev->nss_ifnum;
    if(ifnum == -1){
        printk("no if found return ");
        return;
    }

    switch (osif_cmd) {
        case OSIF_NSS_WIFI_FILTER_NEIGH_PEERS_CMD:
            cmd = NSS_WIFI_FILTER_NEIGH_PEERS_CMD;
            val = pdev->filter_neighbour_peers;
            break;

        default:
            printk("Command :%d is not supported in NSS\n", cmd);
            return;
    }

    osif_nss_send_cmd(nss_wifiol_ctx, ifnum, cmd, val);
}

int osif_nss_ol_pdev_del_wds_peer(ol_txrx_pdev_handle pdev, uint8_t *peer_mac, uint8_t *dest_mac)
{
    void *nss_wifiol_ctx;
    uint32_t radio_id;
    int ifnum ;
    struct nss_wifi_msg wifimsg;
    struct nss_wifi_wds_peer_msg *st ;
    nss_tx_status_t status;
    nss_wifi_msg_callback_t msg_cb;

    if (!pdev) {
        return 0;
    }

    nss_wifiol_ctx = pdev->nss_wifiol_ctx;
    if (!nss_wifiol_ctx) {
        return 0;
    }

    radio_id = pdev->nss_wifiol_id;

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : Delete NSS %p NSS ID %d peer:  %02x:%02x:%02x:%02x:%02x:%02x "
           "dest: %02x:%02x:%02x:%02x:%02x:%02x\n",
           __FUNCTION__, nss_wifiol_ctx, radio_id,
           peer_mac[0], peer_mac[1], peer_mac[2],
           peer_mac[3], peer_mac[4], peer_mac[5],
           dest_mac[0], dest_mac[1], dest_mac[2],
           dest_mac[3], dest_mac[4], dest_mac[5]);

    ifnum = pdev->nss_ifnum;
    if (ifnum == -1) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS-WifOffoad: No if num\n");
        return 1;
    }

    memset(&wifimsg, 0, sizeof(struct nss_wifi_msg));
    st = &wifimsg.msg.pdevwdspeermsg;
    memcpy(st->peer_mac, peer_mac, 6);
    memcpy(st->dest_mac, dest_mac, 6);

    msg_cb = (nss_wifi_msg_callback_t)osif_nss_ol_event_receive;

    /*
     * Send peer del message
     */
    nss_cmn_msg_init(&wifimsg.cm, ifnum, NSS_WIFI_WDS_PEER_DEL_MSG,
            sizeof(struct nss_wifi_tx_init_msg), msg_cb, NULL);

    status = nss_wifi_tx_msg(nss_wifiol_ctx, &wifimsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS-WifOffoad: del wds fail %d \n", status);
        return 1;
    }

    return 0;
}

