/*
 * Copyright (c) 2011-2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <qdf_nbuf.h>          /* qdf_nbuf_t, etc. */
/*#include <qdf_io.h>         *//* qdf_cpu_to_le64 */
#include <ieee80211.h>         /* ieee80211_frame */
#include <ieee80211_var.h>     /* IEEE80211_ADDR_COPY */
#include <net.h>               /* ETHERTYPE_IPV4, etc. */

/* external API header files */
#include <ol_ctrl_txrx_api.h>  /* ol_rx_notify */
#include <ol_htt_api.h>        /* htt_pdev_handle */
#include <ol_txrx_api.h>       /* ol_txrx_pdev_handle */
#include <ol_txrx_htt_api.h>   /* ol_rx_indication_handler */
#include <ol_htt_rx_api.h>     /* htt_rx_peer_id, etc. */
#include <ol_txrx_ctrl_api.h>   /*ol_txrx_mark_peer_inact*/

/* internal API header files */
#include <ol_txrx_types.h>     /* ol_txrx_vdev_t, etc. */
#include <ol_txrx_peer_find.h> /* ol_txrx_peer_find_by_id */
#include <ol_rx_reorder.h>     /* ol_rx_reorder_store, etc. */
#include <ol_rx_defrag.h>      /* ol_rx_defrag_waitlist_flush */
#include <ol_txrx_internal.h>
#include <ol_rawmode_txrx_api.h>
#include <wdi_event.h>

#include <htt_types.h>
#include <ol_if_athvar.h>
#include <net.h>
#include <ol_vowext_dbg_defs.h>
#include <linux/icmp.h>

#ifndef REMOVE_PKT_LOG
#include <pktlog_ac_fmt.h>
#endif

#if QCA_PARTNER_DIRECTLINK_RX
#define QCA_PARTNER_DIRECTLINK_OL_RX 1
#include "ath_carr_pltfrm.h"
#undef QCA_PARTNER_DIRECTLINK_OL_RX
#endif

extern void transcap_nwifi_to_8023(qdf_nbuf_t msdu);
#if MESH_MODE_SUPPORT
void ol_rx_mesh_mode_per_pkt_rx_info(qdf_nbuf_t nbuf, struct ol_txrx_peer_t *peer, struct ol_txrx_vdev_t *vdev)
{
    struct ieee80211_node *ni = NULL;
    ieee80211_keyval k = {0};
    struct ieee80211vap *vap = NULL;
    void *rx_desc;
    uint8_t kid;
    struct per_msdu_mesh_data_recv_status *rx_info = NULL;

    ol_txrx_pdev_handle pdev = vdev->pdev;
    htt_pdev_handle htt_pdev = pdev->htt_pdev;

    vap = ol_ath_getvap(vdev);

    htt_pdev->ar_rx_ops->update_pkt_info(htt_pdev->arh, nbuf, NULL, 1);
    rx_desc = htt_rx_msdu_desc_retrieve(htt_pdev, nbuf);
    kid = (uint8_t)htt_rx_msdu_key_id_octet(htt_pdev, rx_desc);

    if (qdf_nbuf_get_ftype(nbuf) != CB_FTYPE_MESH_RX_INFO) {
        return;
    }

    rx_info = (struct per_msdu_mesh_data_recv_status *)qdf_nbuf_get_fctx(nbuf);

    ni = ieee80211_vap_find_node(vap, peer->mac_addr.raw);
    if (!ni) {
        return;
    }

    rx_info->rs_channel = ni->ni_chan->ic_ieee;

    if (rx_info->rs_flags & IEEE80211_RX_FIRST_MSDU) {
        if (htt_rx_mpdu_is_encrypted(htt_pdev, rx_desc)) {
            rx_info->rs_flags |= IEEE80211_RX_DECRYPTED;
        }
    }

    /* remove extra node ref count added by find_node above */
    ieee80211_free_node(ni);

    k.keydata = (uint8_t *)&rx_info->rs_decryptkey[0];

    if (wlan_get_key(vap, kid, peer->mac_addr.raw, &k, IEEE80211_KEYBUF_SIZE+IEEE80211_MICBUF_SIZE) != 0) {
        return;
    }
}
#endif

static int ol_rx_monitor_deliver(
    ol_txrx_pdev_handle pdev,
    qdf_nbuf_t head_msdu,
    u_int32_t no_clone_reqd, void *rx_desc, enum htt_rx_status status,
    struct ol_txrx_peer_t *peer)
{
    qdf_nbuf_t mon_mpdu = NULL;
    htt_pdev_handle htt_pdev = pdev->htt_pdev;
    struct ieee80211_rx_status *rs = pdev->rx_mon_recv_status;
    u_int8_t is_mcast = 0;
    u_int32_t mgmt_type;
    u_int32_t ctrl_type;

    if (pdev->monitor_vdev == NULL) {
        return -1;
    }

    if(qdf_unlikely(rs->rs_rssi > 127)){
        rs->rs_rssi = 127;
    }

    /* When smart monitor vap is configured , Only deliver
     * valid neighbour peer packets that comes from nac bss
     * peer id and filter out all other other packets
     * including valid and invalid peers
     */
     if(pdev->filter_neighbour_peers && peer
#if ATH_SUPPORT_NAC
        && peer->nac
#endif
       ){
         /* Deliver all non associated packets to smart
          * monitor vap.htt status check not needed, as
          * we might receive varied htt status and all
          * packets are passed to interface & not dropped
          */

    /*Filter based on pkt types to monitor VAP*/
     } else {
         /*data pkts*/
         is_mcast = htt_rx_msdu_is_wlan_mcast(htt_pdev, rx_desc);
         mgmt_type = htt_pdev->ar_rx_ops->check_desc_mgmt_type(head_msdu);
         ctrl_type = htt_pdev->ar_rx_ops->check_desc_ctrl_type(head_msdu);

         if (qdf_likely((mgmt_type && ctrl_type) != 0)) {

             is_mcast = htt_rx_msdu_is_wlan_mcast(htt_pdev, rx_desc);

             if (qdf_likely(is_mcast != 1)) {
                 /*ucast data pkts*/
                 if (pdev->mon_filter_ucast_data == 1) {
                     /*drop ucast pkts*/
                     return -1;
                 }
             } else {
                 /*mcast data pkts*/
                 if (pdev->mon_filter_mcast_data == 1) {
                     /*drop mcast pkts*/
                     return -1;
                 }
             }
         } else {
             /*mgmt/ctrl etc. pkts*/
             if (pdev->mon_filter_non_data == 1) {
                 return -1;
             }
         }
    }

     /* Cloned mon MPDU for delivery via monitor intf */
     mon_mpdu = htt_pdev->ar_rx_ops->restitch_mpdu_from_msdus(
        htt_pdev->arh, head_msdu, pdev->rx_mon_recv_status, no_clone_reqd);

    if (peer) {
        rs->rs_peer_valid = 1;
    } else {
        rs->rs_peer_valid = 0;
    }

    if (mon_mpdu) {
        pdev->monitor_vdev->osif_rx_mon(
            pdev->monitor_vdev->osif_vdev, mon_mpdu, pdev->rx_mon_recv_status);
    } else if (no_clone_reqd) {
       return -1;
    }

    return 0;
}

void ol_rx_process_inv_peer(
    ol_txrx_pdev_handle pdev,
    void *rx_mpdu_desc,
    qdf_nbuf_t msdu
    )
{
    uint8_t a1[IEEE80211_ADDR_LEN];
    htt_pdev_handle htt_pdev = pdev->htt_pdev;
    struct ol_txrx_vdev_t *vdev = NULL;
    struct ieee80211_frame *wh;
    struct wdi_event_rx_peer_invalid_msg msg;

    wh = (struct ieee80211_frame *)htt_pdev->ar_rx_ops->wifi_hdr_retrieve(rx_mpdu_desc);
    if (!IEEE80211_IS_DATA(wh))
        return;

    /* ignore frames for non-existent bssids */
    IEEE80211_ADDR_COPY(a1, wh->i_addr1);
    TAILQ_FOREACH(vdev, &pdev->vdev_list, vdev_list_elem) {
        if (qdf_mem_cmp(a1, vdev->mac_addr.raw, IEEE80211_ADDR_LEN) == 0) {
            break;
        }
    }
    if (!vdev)
        return;

    if (qdf_nbuf_len(msdu) < sizeof(struct ieee80211_frame)) {
        return;
    }

    msg.wh = wh;
    msg.msdu = msdu;
    msg.vdev_id = vdev->vdev_id;
    wdi_event_handler(WDI_EVENT_RX_PEER_INVALID, pdev, &msg, HTT_INVALID_PEER, WDI_NO_VAL);
}

#if WDS_VENDOR_EXTENSION
static inline int wds_rx_policy_check(
    htt_pdev_handle htt_pdev,
    struct ol_txrx_vdev_t *vdev,
    struct ol_txrx_peer_t *peer,
    void *rx_mpdu_desc,
    int rx_mcast
    )

{
    struct ol_txrx_peer_t *bss_peer;
    int fr_ds, to_ds, rx_3addr, rx_4addr;
    int rx_policy_ucast, rx_policy_mcast;


    if (vdev->opmode == wlan_op_mode_ap) {
        TAILQ_FOREACH(bss_peer, &vdev->peer_list, peer_list_elem) {
            if (bss_peer->bss_peer) {
                /* if wds policy check is not enabled on this vdev, accept all frames */
                if (!bss_peer->wds_rx_filter) {
                    return 1;
                }
                break;
            }
        }
        rx_policy_ucast = bss_peer->wds_rx_ucast_4addr;
        rx_policy_mcast = bss_peer->wds_rx_mcast_4addr;
    }
    else {             /* sta mode */
        if (!peer->wds_rx_filter) {
            return 1;
        }
        rx_policy_ucast = peer->wds_rx_ucast_4addr;
        rx_policy_mcast = peer->wds_rx_mcast_4addr;
    }

/* ------------------------------------------------
 *                       self
 * peer-             rx  rx-
 * wds  ucast mcast dir policy accept note
 * ------------------------------------------------
 * 1     1     0     11  x1     1      AP configured to accept ds-to-ds Rx ucast from wds peers, constraint met; so, accept
 * 1     1     0     01  x1     0      AP configured to accept ds-to-ds Rx ucast from wds peers, constraint not met; so, drop
 * 1     1     0     10  x1     0      AP configured to accept ds-to-ds Rx ucast from wds peers, constraint not met; so, drop
 * 1     1     0     00  x1     0      bad frame, won't see it
 * 1     0     1     11  1x     1      AP configured to accept ds-to-ds Rx mcast from wds peers, constraint met; so, accept
 * 1     0     1     01  1x     0      AP configured to accept ds-to-ds Rx mcast from wds peers, constraint not met; so, drop
 * 1     0     1     10  1x     0      AP configured to accept ds-to-ds Rx mcast from wds peers, constraint not met; so, drop
 * 1     0     1     00  1x     0      bad frame, won't see it
 * 1     1     0     11  x0     0      AP configured to accept from-ds Rx ucast from wds peers, constraint not met; so, drop
 * 1     1     0     01  x0     0      AP configured to accept from-ds Rx ucast from wds peers, constraint not met; so, drop
 * 1     1     0     10  x0     1      AP configured to accept from-ds Rx ucast from wds peers, constraint met; so, accept
 * 1     1     0     00  x0     0      bad frame, won't see it
 * 1     0     1     11  0x     0      AP configured to accept from-ds Rx mcast from wds peers, constraint not met; so, drop
 * 1     0     1     01  0x     0      AP configured to accept from-ds Rx mcast from wds peers, constraint not met; so, drop
 * 1     0     1     10  0x     1      AP configured to accept from-ds Rx mcast from wds peers, constraint met; so, accept
 * 1     0     1     00  0x     0      bad frame, won't see it
 *
 * 0     x     x     11  xx     0      we only accept td-ds Rx frames from non-wds peers in mode.
 * 0     x     x     01  xx     1
 * 0     x     x     10  xx     0
 * 0     x     x     00  xx     0      bad frame, won't see it
 * ------------------------------------------------
 */


    fr_ds = htt_rx_mpdu_desc_frds(htt_pdev, rx_mpdu_desc);
    to_ds = htt_rx_mpdu_desc_tods(htt_pdev, rx_mpdu_desc);
    rx_3addr = fr_ds ^ to_ds;
    rx_4addr = fr_ds & to_ds;


    if (vdev->opmode == wlan_op_mode_ap) {
        /* printk("AP m %d 3A %d 4A %d UP %d MP %d ", rx_mcast, rx_3addr, rx_4addr, rx_policy_ucast, rx_policy_mcast); */
        if ((!peer->wds_enabled && rx_3addr && to_ds) ||
            (peer->wds_enabled && !rx_mcast && (rx_4addr == rx_policy_ucast)) ||
            (peer->wds_enabled && rx_mcast && (rx_4addr == rx_policy_mcast))) {
            /* printk("A\n"); */
            return 1;
        }
    }
    else {           /* sta mode */
        /* printk("STA m %d 3A %d 4A %d UP %d MP %d ", rx_mcast, rx_3addr, rx_4addr, rx_policy_ucast, rx_policy_mcast); */
        if ((!rx_mcast && (rx_4addr == rx_policy_ucast)) ||
            (rx_mcast && (rx_4addr == rx_policy_mcast))) {
            /* printk("A\n"); */
            return 1;
        }
    }

    /* printk("D\n"); */
    return 0;
}
#endif

#ifndef REMOVE_PKT_LOG
void
phy_data_type_chk(
    qdf_nbuf_t   head_msdu,
    u_int32_t    *cv_chk_status)
{
  struct bb_tlv_pkt_hdr *bb_hdr = NULL;
  qdf_nbuf_t   next_msdu = head_msdu;

  bb_hdr    = (struct bb_tlv_pkt_hdr *)qdf_nbuf_data(next_msdu);
  if ((bb_hdr->sig == PKTLOG_PHY_BB_SIGNATURE) &&
      (bb_hdr->tag == PKTLOG_RX_IMPLICIT_CV_TRANSFER || bb_hdr->tag == PKTLOG_BEAMFORM_DEBUG_H))
  {
    *cv_chk_status = 0;
  }else{
    *cv_chk_status = 1;
  }
}

void
cbf_type_chk(
    qdf_nbuf_t   head_msdu,
    u_int32_t    *cv_chk_status)
{
  struct ieee80211_frame *wh = NULL;
  u_int8_t  type, subtype;
  qdf_nbuf_t   next_msdu = head_msdu;

  wh = (struct ieee80211_frame *)qdf_nbuf_data(next_msdu);
  type    = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
  subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
  if((type == IEEE80211_FC0_TYPE_MGT )&&(subtype == IEEE80211_FCO_SUBTYPE_ACTION_NO_ACK))
  {
    *cv_chk_status = 0;
  }else{
    *cv_chk_status = 1;
  }
}

#endif

#if UMAC_SUPPORT_WNM
int ol_ath_wnm_update_bssidle_time( struct ol_ath_softc_net80211 *scn ,
                                struct ol_txrx_peer_t *peer,
                                htt_pdev_handle htt_pdev ,
                                void *rx_mpdu_desc )
{
    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211_node *ni = NULL;
    struct ieee80211vap *vap = NULL;
    int secured = 0;

    vap = ol_ath_vap_get(scn, peer->vdev->vdev_id);

    if (!vap) {
        return 0 ;
    }
    if (ieee80211_vap_wnm_is_set(vap) && ieee80211_wnm_bss_is_set(vap->wnm)) {
        ni = ieee80211_find_node(&ic->ic_sta, peer->mac_addr.raw);
        secured = htt_rx_mpdu_is_encrypted(htt_pdev, rx_mpdu_desc);
        if (ni && ni != ni->ni_bss_node)
            ieee80211_wnm_bssmax_updaterx(ni, secured);
            ieee80211_free_node(ni);
        }
    return 1;
}
#endif

void
ol_rx_indication_handler(
    ol_txrx_pdev_handle pdev,
    qdf_nbuf_t rx_ind_msg,
    u_int16_t peer_id,
    u_int8_t tid,
    int num_mpdu_ranges)
{
    int mpdu_range;
    int seq_num_start = 0, seq_num_end = 0, rx_ind_release = 0;
    struct ol_txrx_vdev_t *vdev = NULL;
    struct ol_txrx_peer_t *peer;
    htt_pdev_handle htt_pdev;
    int skip_monitor =0;
    struct ieee80211_mac_stats *mac_stats;
    struct ieee80211vap *vap = NULL;
    struct ethhdr * eh;
    struct ieee80211_frame *wh;
    struct ol_ath_softc_net80211 *scn = NULL;
#if UNIFIED_SMARTANTENNA
    struct sa_rx_feedback rx_feedback;
    int smart_ant_rx_feedback_done = 0;
    static int total_npackets=0;
#endif

    qdf_spin_lock(&pdev->mon_mutex);
    if (pdev->monitor_vdev == NULL) {
        skip_monitor= 1;
        qdf_spin_unlock(&pdev->mon_mutex);
    }


    scn = (struct ol_ath_softc_net80211 *)pdev->ctrl_pdev;

    htt_pdev = pdev->htt_pdev;
    peer = ol_txrx_peer_find_by_id(pdev, peer_id);
    if (peer) {
        vdev = peer->vdev;
    }

#if RX_DEBUG
    htt_pdev->g_peer_id = peer_id;
    if (peer) {
        memcpy(htt_pdev->g_peer_mac, peer->mac_addr.raw, 6);
    }
    htt_pdev->g_tid = tid;
#endif

    TXRX_STATS_INCR(pdev, priv.rx.normal.ppdus);

    if (htt_rx_ind_flush(rx_ind_msg) && peer) {

        htt_rx_ind_flush_seq_num_range(
            rx_ind_msg, &seq_num_start, &seq_num_end);

        if (tid == HTT_INVALID_TID) {
            /*
             * host/FW reorder state went out-of sync
             * for a while because FW ran out of Rx indication
             * buffer. We have to discard all the buffers in
             * reorder queue.
             */
            ol_rx_reorder_peer_cleanup(vdev, peer);
        } else {
            ol_rx_reorder_flush(
                vdev, peer, tid, seq_num_start,
                seq_num_end, htt_rx_flush_release);
        }
    }

    if (htt_rx_ind_release(rx_ind_msg)) {
        /* the ind info of release is saved here and do release at the end.
         * This is for the reason of in HL case, the qdf_nbuf_t for msg and
         * payload are the same buf. And the buf will be changed during
         * processing */
        rx_ind_release = 1;
        htt_rx_ind_release_seq_num_range(
            rx_ind_msg, &seq_num_start, &seq_num_end);
    }

#if RX_DEBUG
    htt_pdev->g_mpdu_ranges = num_mpdu_ranges;
#endif

    for (mpdu_range = 0; mpdu_range < num_mpdu_ranges; mpdu_range++) {
        enum htt_rx_status status;
        int i, num_mpdus;
        qdf_nbuf_t head_msdu = NULL;
        qdf_nbuf_t tail_msdu = NULL;
        qdf_nbuf_t msdu = NULL;
        void *rx_mpdu_desc;
        u_int32_t npackets = 0;
        htt_rx_ind_mpdu_range_info(
            pdev->htt_pdev, rx_ind_msg, mpdu_range, &status, &num_mpdus);
#if RX_DEBUG
        htt_pdev->g_num_mpdus = num_mpdus;
        htt_pdev->g_htt_status = status;
#endif
        if ((status == htt_rx_status_ok) && peer
#if ATH_SUPPORT_NAC
            && !peer->nac
#endif
           ) {
#if ATH_BAND_STEERING
            // For non-Null Data Packet, mark inactivity as false
            ol_txrx_mark_peer_inact(peer, false);
#endif
            TXRX_STATS_ADD(pdev, priv.rx.normal.mpdus, num_mpdus);
            /*   The below stat i.e "rx_aggr" will not be valid if a single
             *   frame is treated as a ampdu, in the case of single frame = 1 ampdu
             *   the num_mpdus will be 1 and my check "num_mpdus > 1" will
             *   fail even though if it
             *   is a aggr.
             */
            if (num_mpdus > 1)
                TXRX_STATS_ADD(pdev, priv.rx.normal.rx_aggr, 1);
            /* valid frame - deposit it into the rx reordering buffer */
            for (i = 0; i < num_mpdus; i++) {
                int seq_num, msdu_chaining;
                npackets = 0;
                /*
                 * Get a linked list of the MSDUs that comprise this MPDU.
                 * This also attaches each rx MSDU descriptor to the
                 * corresponding rx MSDU network buffer.
                 * (In some systems, the rx MSDU desc is already in the
                 * same buffer as the MSDU payload; in other systems they
                 * are separate, so a pointer needs to be set in the netbuf
                 * to locate the corresponding rx descriptor.)
                 *
                 * It is neccessary to call htt_rx_amsdu_pop before
                 * htt_rx_mpdu_desc_list_next, because the (MPDU) rx
                 * descriptor has the DMA unmapping done during the
                 * htt_rx_amsdu_pop call.  The rx desc should not be
                 * accessed until this DMA unmapping has been done,
                 * since the DMA unmapping involves making sure the
                 * cache area for the mapped buffer is flushed, so the
                 * data written by the MAC DMA into memory will be
                 * fetched, rather than garbage from the cache.
                 */
                msdu_chaining = htt_rx_amsdu_pop(
                    htt_pdev,
#if QCA_OL_SUPPORT_RAWMODE_TXRX
                    vdev,
#endif
                    rx_ind_msg, &head_msdu, &tail_msdu, &npackets);

#if QCA_PARTNER_DIRECTLINK_RX
                /*
                 * For Direct Link RX, htt_rx_msdu_desc_retrieve() would finally
                 * call partner API for get rx descriptor.
                 */
                if (CE_is_directlink(((struct ol_txrx_pdev_t*)htt_pdev->txrx_pdev)->ce_tx_hdl)) {
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ERROR: %s called over Directlink\n",__func__);
                        A_ASSERT(0);
                }
#endif /* QCA_PARTNER_DIRECTLINK_RX */
                rx_mpdu_desc =
                    htt_rx_mpdu_desc_list_next(htt_pdev, rx_ind_msg);


#if UMAC_SUPPORT_WNM
                ol_ath_wnm_update_bssidle_time(scn, peer, htt_pdev, rx_mpdu_desc);
#endif

#if UNIFIED_SMARTANTENNA
                total_npackets += npackets;
                if (!smart_ant_rx_feedback_done &&
                    ol_smart_ant_rx_feedback_enabled((struct ol_ath_softc_net80211 *)(htt_pdev->ctrl_pdev))) {
                    /* Smart Antenna Module feed back */
                    OS_MEMZERO(&rx_feedback, sizeof(rx_feedback));
                    smart_ant_rx_feedback_done = htt_pdev->ar_rx_ops->get_smart_ant_stats(htt_pdev->arh, rx_ind_msg, head_msdu, tail_msdu, &rx_feedback);
                }
#endif
                /* Pktlog */
                wdi_event_handler(WDI_EVENT_RX_DESC_REMOTE, pdev, head_msdu,
                                    peer_id, status);
                if (!skip_monitor) {
                    /*
                     * TBDXXX - to deliver SDU with chaining in monitor mode.
                     * Though the stitch function is available, there is a chance
                     * that the skb->len can get bad values, due to which kernel
                     * panics are seen.
                     */

                    if(!msdu_chaining) {
                        ol_rx_monitor_deliver(pdev, head_msdu, 0, rx_mpdu_desc, status, peer);
                    }
                }
                /*
                 * We assume that the packet delivered in the monitor VAP will not have the
                 * rx_pkt_info, which should be ok, because RSSI and Rate info for the monitor
                 * VAP packets are alraedy part of the prism2 header
                 */
#if ATH_DATA_RX_INFO_EN
                htt_pdev->ar_rx_ops->update_pkt_info(htt_pdev->arh, head_msdu, tail_msdu, 0);
#endif

#if RX_DEBUG
                htt_pdev->g_msdu_chained = msdu_chaining;
#endif
                if (vdev && (OL_CFG_NONRAW_RX_LIKELINESS(
                        vdev->rx_decap_type != htt_pkt_type_raw))
                    && msdu_chaining) {
                    /*
                     * TBDXXX - to deliver SDU with chaining, we need to
                     * stitch those scattered buffers into one single buffer.
                     * Just discard it now.
                     *
                     * In Raw mode however, we accept them for delivery to higher
                     * layers as-is.
                     */
		           while (1) {
                        qdf_nbuf_t next;
                        next = qdf_nbuf_next(head_msdu);
                        htt_rx_desc_frame_free(htt_pdev, head_msdu);
                        if (head_msdu == tail_msdu) {
                            break;
                        }
                        head_msdu = next;
                    }
                } else {
#if WDS_VENDOR_EXTENSION
                    int accept = 1, rx_mcast;
                    void *msdu_desc;
#endif

                    seq_num = htt_rx_mpdu_desc_seq_num(htt_pdev, rx_mpdu_desc);
                    OL_RX_REORDER_TRACE_ADD(pdev, tid, seq_num, 1);
#if HTT_DEBUG_DATA
                    HTT_PRINT("t%ds%d ",tid, seq_num);
#endif
#if WDS_VENDOR_EXTENSION
                    msdu_desc = htt_rx_msdu_desc_retrieve(htt_pdev, head_msdu);
                    if (vdev->opmode == wlan_op_mode_ap ||
                        vdev->opmode == wlan_op_mode_sta) {
                        if (vdev->opmode == wlan_op_mode_ap) {
                            rx_mcast = (htt_rx_msdu_forward(htt_pdev, msdu_desc) && !htt_rx_msdu_discard(htt_pdev, msdu_desc));
                        }
                        else {
                            rx_mcast = htt_rx_msdu_is_wlan_mcast(htt_pdev, msdu_desc);
                        }
                        /* wds rx policy check only applies to vdevs in ap/sta mode */
                        accept = wds_rx_policy_check(htt_pdev, vdev, peer, rx_mpdu_desc, rx_mcast);
                    }
#endif
                    if (scn && scn->scn_stats.ap_stats_tx_cal_enable) {

		        struct ieee80211_node *ni;
			int ac;
			void *rx_desc;

			/* retrieve access class */
			vap = ol_ath_vap_get(scn, peer->vdev->vdev_id);
			if( vap != NULL){
			  if (tid < 8) {
			    rx_desc = htt_rx_msdu_desc_retrieve(htt_pdev, head_msdu);
			    mac_stats = htt_rx_msdu_is_wlan_mcast(htt_pdev, rx_desc) ?
			      &vap->iv_multicast_stats : &vap->iv_unicast_stats;
			    ni = ieee80211_vap_find_node(vap,peer->mac_addr.raw);
                            ac = TID_TO_WME_AC(tid);
                            mac_stats->ims_rx_wme[ac]++;
                            if (ni) {
                                ni->ni_stats.ns_rx_wme[ac]++;
                                ieee80211_free_node(ni);
                            }
			  }
			}


                        if (scn->host_80211_enable) {
                            int is_bcast, dir;
                            wh = (struct ieee80211_frame *) head_msdu->data;
                            dir = wh->i_fc[1] & IEEE80211_FC1_DIR_MASK;
                            is_bcast = (dir == IEEE80211_FC1_DIR_DSTODS ||
                                    dir == IEEE80211_FC1_DIR_TODS ) ?
                                IEEE80211_IS_BROADCAST(IEEE80211_WH4(wh)->i_addr3) :
                                IEEE80211_IS_BROADCAST(wh->i_addr1);
                            if (is_bcast) {
                                vap = ol_ath_vap_get(scn, peer->vdev->vdev_id);
                                if( vap != NULL){
                                    mac_stats =&vap->iv_multicast_stats;
                                    mac_stats->ims_rx_bcast_data_packets++;
                                }
                            }
                        }

                        else {
                            eh = (struct ethhdr *)qdf_nbuf_data(head_msdu);
                            if (IEEE80211_IS_BROADCAST(eh->h_dest)){
                                vap = ol_ath_vap_get(scn, peer->vdev->vdev_id);
                                if( vap != NULL){
                                    mac_stats =&vap->iv_multicast_stats;
                                    mac_stats->ims_rx_bcast_data_packets++;
                                }
                            }
                        }
                    }

                    if (
#if WDS_VENDOR_EXTENSION
                        !accept ||
#endif
                        ol_rx_reorder_store(pdev, peer, tid, seq_num,
                                head_msdu, tail_msdu)
                                ) {

                        /* free the mpdu if it could not be stored, e.g.
                         * duplicate non-aggregate mpdu detected */
                        while (1) {
                            qdf_nbuf_t next;
                            next = qdf_nbuf_next(head_msdu);
                            htt_rx_desc_frame_free(htt_pdev, head_msdu);
                            if (head_msdu == tail_msdu) {
                                break;
                            }
                            head_msdu = next;
                        }

                        /*
                         * ol_rx_reorder_store should only fail for the case
                         * of (duplicate) non-aggregates.
                         *
                         * Confirm this is a non-aggregate
                         */
                        TXRX_ASSERT2(num_mpdu_ranges == 1 && num_mpdus == 1);

                        /* the MPDU was not stored in the rx reorder array,
                         * so there's nothing to release */
                        rx_ind_release = 0;
                    }
                }
            } /* end of for loop */

        } else {
            u_int32_t    mgmt_type = 0;
#ifndef REMOVED_PKT_LOG
            u_int32_t    phy_data_type = 0;
            u_int32_t    cv_chk_status = 1;
#endif
            int msdu_chaining = 0;

            /* invalid frames - discard them */
            OL_RX_REORDER_TRACE_ADD(
                pdev, tid, TXRX_SEQ_NUM_ERR(status), num_mpdus);
            TXRX_STATS_ADD(pdev, priv.rx.err.mpdu_bad, num_mpdus);
            for (i = 0; i < num_mpdus; i++) {
                int discard = 1;
                npackets = 0;
                discard = 1;
                /* pull the MPDU's MSDUs off the buffer queue */
                msdu_chaining = htt_rx_amsdu_pop(htt_pdev,
#if QCA_OL_SUPPORT_RAWMODE_TXRX
                        vdev,
#endif
                        rx_ind_msg, &msdu, &tail_msdu, &npackets);
#if RX_DEBUG
                if (!npackets) {
                    if ( skip_monitor == 0 ) {
                        qdf_spin_unlock(&pdev->mon_mutex);
                    }
                    return;
                }
#endif
                /* pull the MPDU desc off the desc queue */
                rx_mpdu_desc =
                    htt_rx_mpdu_desc_list_next(htt_pdev, rx_ind_msg);

		        if (status == htt_rx_status_tkip_mic_err && vdev != NULL &&  peer != NULL) {
                    ol_rx_err(pdev->ctrl_pdev, vdev->vdev_id, peer->mac_addr.raw,
                        tid,0, OL_RX_ERR_TKIP_MIC, msdu);
                }
#ifndef REMOVE_PKT_LOG
                if (((status == htt_rx_status_err_fcs)) || ((status == htt_rx_status_ctrl_mgmt_null) && peer))
                {
                    uint8_t rx_phy_data_filter;

                    phy_data_type = htt_pdev->ar_rx_ops->check_desc_phy_data_type(msdu, &rx_phy_data_filter);
                    mgmt_type = htt_pdev->ar_rx_ops->check_desc_mgmt_type(msdu);

                    if(phy_data_type == 0)
                    {
                        phy_data_type_chk(msdu,&cv_chk_status);
                    }else{
                        if(mgmt_type == 0)
                        {
                            cbf_type_chk(msdu,&cv_chk_status);
                        }else{
                            goto normalproc;
                        }
                    }

                    if(cv_chk_status == 0)
                    {
                        /* Walk through CBF and H-info and dump frame into system pktlog file*/
                        wdi_event_handler(WDI_EVENT_RX_CBF_REMOTE, pdev, msdu,
                                peer_id, status);
                    }
                }
normalproc:
#endif

                wdi_event_handler(WDI_EVENT_RX_DESC_REMOTE,
                                        pdev, msdu, peer_id, status);

                if (status == htt_rx_status_err_inv_peer) {
                    /* once per mpdu */
                    ol_rx_process_inv_peer(pdev, rx_mpdu_desc, msdu);
                }

                mgmt_type = htt_pdev->ar_rx_ops->check_desc_mgmt_type(msdu);

                if (!skip_monitor) {
                    /*
                     * TBDXXX - to deliver SDU with chaining in monitor mode.
                     * Though the stitch function is available, there is a chance
                     * that the skb->len can get bad values, due to which kernel
                     * panics are seen.
                     */

                    if(!msdu_chaining){
                        discard = ol_rx_monitor_deliver(pdev, msdu, 1,
                                        rx_mpdu_desc, status, peer);
                    }

                }

                if (discard) {
                    /* Free the nbuf iff monitor layer did not absorb */
                    while (1) {
                        qdf_nbuf_t next;
                        next = qdf_nbuf_next(msdu);
                        htt_rx_desc_frame_free(htt_pdev, msdu);
                        if (msdu == tail_msdu) {
                            break;
                        }
                        msdu = next;
                    }
                }
            }
        }
    }
#if UNIFIED_SMARTANTENNA
    /* Assuming most of the time smart_ant_rx_feedback_done will be false */
    if (smart_ant_rx_feedback_done &&
        ol_smart_ant_rx_feedback_enabled((struct ol_ath_softc_net80211 *)(htt_pdev->ctrl_pdev))) {
        /* send smart antenna rx feed back */
        rx_feedback.npackets = total_npackets;
        ol_ath_smart_ant_rxfeedback(pdev, peer, &rx_feedback);
        total_npackets = 0;
    }
#endif
    /*
     * Now that a whole batch of MSDUs have been pulled out of HTT
     * and put into the rx reorder array, it is an appropriate time
     * to request HTT to provide new rx MSDU buffers for the target
     * to fill.
     * This could be done after the end of this function, but it's
     * better to do it now, rather than waiting until after the driver
     * and OS finish processing the batch of rx MSDUs.
     */
#if QCA_PARTNER_DIRECTLINK_RX
    /*
     * For Direct Link RX, replenish already done on partner side so skip it.
     */
    if (CE_is_directlink(((struct ol_txrx_pdev_t*)htt_pdev->txrx_pdev)->ce_tx_hdl)) {
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ERROR: %s called over Directlink\n",__func__);
        A_ASSERT(0);
    }
#endif /* QCA_PARTNER_DIRECTLINK_RX */

    htt_rx_msdu_buff_replenish(htt_pdev);

    if (rx_ind_release && peer
#if ATH_SUPPORT_NAC
        && !peer->nac
#endif
       ){
#if HTT_DEBUG_DATA
        HTT_PRINT("t%dr[%d,%d)\n",tid, seq_num_start, seq_num_end);
#endif
        ol_rx_reorder_release(vdev, peer, tid, seq_num_start, seq_num_end);
        if (pdev->rx.flags.defrag_timeout_check) {
            ol_rx_defrag_waitlist_flush(pdev);
        }

    }

    if ( skip_monitor == 0) {
        qdf_spin_unlock(&pdev->mon_mutex);
    }
}

void
ol_rx_sec_ind_handler(
    ol_txrx_pdev_handle pdev,
    u_int16_t peer_id,
    enum htt_sec_type sec_type,
    int is_unicast,
    u_int32_t *michael_key,
    u_int32_t *rx_pn)
{
    struct ol_txrx_peer_t *peer;
    int sec_index, i;

    peer = ol_txrx_peer_find_by_id(pdev, peer_id);
    if (! peer) {
        TXRX_PRINT(TXRX_PRINT_LEVEL_ERR,
            "Couldn't find peer from ID %d - skipping security inits\n",
            peer_id);
        return;
    }
    TXRX_PRINT(TXRX_PRINT_LEVEL_INFO1,
        "sec spec for peer %p (%02x:%02x:%02x:%02x:%02x:%02x): "
        "%s key of type %d\n",
        peer,
        peer->mac_addr.raw[0], peer->mac_addr.raw[1], peer->mac_addr.raw[2],
        peer->mac_addr.raw[3], peer->mac_addr.raw[4], peer->mac_addr.raw[5],
        is_unicast ? "ucast" : "mcast",
        sec_type);
    sec_index = is_unicast ? txrx_sec_ucast : txrx_sec_mcast;
    peer->security[sec_index].sec_type = sec_type;
    /* michael key only valid for TKIP, but for simplicity, copy it anyway */
    qdf_mem_copy(
        &peer->security[sec_index].michael_key[0],
        michael_key,
        sizeof(peer->security[sec_index].michael_key));
#ifdef BIG_ENDIAN_HOST
    OL_IF_SWAPBO(peer->security[sec_index].michael_key[0],
                 sizeof(peer->security[sec_index].michael_key));
#endif /* BIG_ENDIAN_HOST */

    if (sec_type != htt_sec_type_wapi) {
        qdf_mem_set(peer->tids_last_pn_valid, OL_TXRX_NUM_EXT_TIDS, 0x00);
    } else {
        for (i = 0; i < OL_TXRX_NUM_EXT_TIDS; i++) {
            /*
             * Setting PN valid bit for WAPI sec_type,
             * since WAPI PN has to be started with predefined value
             */
            peer->tids_last_pn_valid[i] = 1;
            qdf_mem_copy(
                (u_int8_t *) &peer->tids_last_pn[i],
                (u_int8_t *) rx_pn, sizeof(union htt_rx_pn_t));
            peer->tids_last_pn[i].pn128[1] =
                qdf_cpu_to_le64(peer->tids_last_pn[i].pn128[1]);
            peer->tids_last_pn[i].pn128[0] =
                qdf_cpu_to_le64(peer->tids_last_pn[i].pn128[0]);
        }
    }

#if QCA_PARTNER_DIRECTLINK_RX
    /*
     * inform partner side for security information update.
     */
    if (CE_is_directlink(pdev->ce_tx_hdl)) {
        ol_rx_sec_ind_handler_partner(peer, peer_id, sec_type, rx_pn);
    }
#endif /* QCA_PARTNER_DIRECTLINK_RX */

}


#define OLE_HEADER_PADDING 2

#include <ieee80211.h>

uint16_t
transcap_nwifi_ether_type(qdf_nbuf_t msdu)
{
    struct ieee80211_frame_addr4 *wh;
    uint32_t hdrsize;
    uint8_t fc1;
    struct llc *llchdr;
    uint16_t ether_type = 0;
    wh = (struct ieee80211_frame_addr4 *)qdf_nbuf_data(msdu);
    fc1 = wh->i_fc[1] & IEEE80211_FC1_DIR_MASK;

    /* Native Wifi header  give only 80211 non-Qos packets */
    if (fc1 == IEEE80211_FC1_DIR_DSTODS )
    {
        hdrsize = sizeof(struct ieee80211_frame_addr4);

        /* In case of WDS frames, , padding is enabled by default
         * in Native Wifi mode, to make ipheader 4 byte aligned
         */
        hdrsize = hdrsize + OLE_HEADER_PADDING;
    } else {
        hdrsize = sizeof(struct ieee80211_frame);
    }

    /*
     *
     * header size (wifhdrsize + llchdrsize )
     */
    llchdr = (struct llc *)(((uint8_t *)qdf_nbuf_data(msdu)) + hdrsize);
    ether_type = llchdr->llc_un.type_snap.ether_type;
    return ntohs(ether_type);
}

int
transcap_nwifi_hdrsize(qdf_nbuf_t msdu)
{
    struct ieee80211_frame_addr4 *wh;
    uint32_t hdrsize;
    uint8_t fc1;

    wh = (struct ieee80211_frame_addr4 *)qdf_nbuf_data(msdu);
    fc1 = wh->i_fc[1] & IEEE80211_FC1_DIR_MASK;

    /* Native Wifi header  give only 80211 non-Qos packets */
    if (fc1 == IEEE80211_FC1_DIR_DSTODS )
    {
        hdrsize = sizeof(struct ieee80211_frame_addr4);

        /* In case of WDS frames, , padding is enabled by default
         * in Native Wifi mode, to make ipheader 4 byte aligned
         */
        hdrsize = hdrsize + OLE_HEADER_PADDING;
    } else {
        hdrsize = sizeof(struct ieee80211_frame);
    }

    /*
     *
     * header size (wifhdrsize + llchdrsize )
     */
    hdrsize +=sizeof(struct llc);
    return hdrsize;
}

/**
 * @brief Look into a rx MSDU to see what kind of special handling it requires
 * @details
 *      This function is called when the host rx SW sees that the target
 *      rx FW has marked a rx MSDU as needing inspection.
 *      Based on the results of the inspection, the host rx SW will infer
 *      what special handling to perform on the rx frame.
 *      Currently, the only type of frames that require special handling
 *      are IGMP frames.  The rx data-path SW checks if the frame is IGMP
 *      (it should be, since the target would not have set the inspect flag
 *      otherwise), and then calls the ol_rx_notify function so the
 *      control-path SW can perform multicast group membership learning
 *      by sniffing the IGMP frame.
 */
#define SIZEOF_80211_HDR (sizeof(struct ieee80211_frame))
int
ol_rx_inspect(
    struct ol_txrx_vdev_t *vdev,
    struct ol_txrx_peer_t *peer,
    unsigned tid,
    qdf_nbuf_t msduorig,
    void *rx_desc)
{
    ol_txrx_pdev_handle pdev = vdev->pdev;
    u_int8_t *data, *l3_hdr;
    u_int16_t ethertype;
    int offset;
    int discard = 0;
    qdf_nbuf_t msdu =NULL;

    if (pdev->nss_nwifi_offload) {
	    if ( (msdu = qdf_nbuf_copy(msduorig)) == NULL){
		    /*
		     * Cannot handle inspection so exit
		     * */
		    goto out ;
	    }
	    transcap_nwifi_to_8023(msdu);
    } else {
        msdu = msduorig;
    }

    data = qdf_nbuf_data(msdu);
    if (pdev->rx_decap_mode == htt_pkt_type_native_wifi) {
        offset = SIZEOF_80211_HDR + LLC_SNAP_HDR_OFFSET_ETHERTYPE;
        l3_hdr = data + SIZEOF_80211_HDR + LLC_SNAP_HDR_LEN;
    } else {
        offset = ETHERNET_ADDR_LEN * 2;
        l3_hdr = data + ETHERNET_HDR_LEN;
    }
    ethertype = (data[offset] << 8) | data[offset+1];
    if (ethertype == ETHERTYPE_IPV4) {
        offset = IPV4_HDR_OFFSET_PROTOCOL;
        if (l3_hdr[offset] == IP_PROTOCOL_IGMP) {
            discard = ol_rx_notify(
                pdev->ctrl_pdev,
                vdev->vdev_id,
                peer->mac_addr.raw,
                tid,
                htt_rx_mpdu_desc_tsf32(pdev->htt_pdev, rx_desc),
                OL_RX_NOTIFY_IPV4_IGMP,
                msdu);
        }
    } else if ((ethertype == ETHERTYPE_IPV6) &&
                (IEEE80211_IS_IPV6_MULTICAST(data))) {
        discard = ol_rx_notify(
                pdev->ctrl_pdev,
                vdev->vdev_id,
                peer->mac_addr.raw,
                tid,
                htt_rx_mpdu_desc_tsf32(pdev->htt_pdev, rx_desc),
                OL_RX_NOTIFY_IPV4_IGMP,
                msdu);

    }
    if (pdev->nss_nwifi_offload) {
	    /*
	     * Free the copy msdu after inspection done
	     * leave the actual message for further processing
	     */
	    qdf_nbuf_free(msdu);
    }
out :
    return discard;
}

/**
 * @brief Check the first msdu to decide whether the a-msdu should be accepted.
 */
int
ol_rx_filter(
    struct ol_txrx_vdev_t *vdev,
    struct ol_txrx_peer_t *peer,
    qdf_nbuf_t msdu,
    void *rx_desc)
{
    #define FILTER_STATUS_REJECT 1
    #define FILTER_STATUS_ACCEPT 0
    u_int8_t *wh;
    u_int32_t offset = 0;
    u_int16_t ether_type = 0;
    u_int8_t is_encrypted = 0, is_mcast = 0, i;
    privacy_filter_packet_type packet_type = PRIVACY_FILTER_PACKET_UNICAST;
    ol_txrx_pdev_handle pdev = vdev->pdev;
    htt_pdev_handle htt_pdev = pdev->htt_pdev;

    /* Safemode must avoid the PrivacyExemptionList and ExcludeUnencrypted checking */
    if (vdev->safemode) {
        return FILTER_STATUS_ACCEPT;
    }

    is_mcast = htt_rx_msdu_is_wlan_mcast(htt_pdev, rx_desc);
    if (pdev->nss_nwifi_offload) {
    /*
     *  If this is a open connection, it will be accepted.
     *  Here a shortcut is taken for performance in nwifi mode,
     *  As privacy filters are not applicable for Open connection.
     *  there's a little overhead in finding the eth type in case of nwifi mode.
     */
        if(peer->security[is_mcast ? txrx_sec_mcast : txrx_sec_ucast].sec_type == htt_sec_type_none) {
            return FILTER_STATUS_ACCEPT;
        }
    }

    if (vdev->filters_num > 0) {
        if (pdev->rx_decap_mode == htt_pkt_type_native_wifi) {
            offset = SIZEOF_80211_HDR + LLC_SNAP_HDR_OFFSET_ETHERTYPE;
        } else {
            offset = ETHERNET_ADDR_LEN * 2;
        }

        if (!pdev->nss_nwifi_offload) {
            /* get header info from msdu */
            wh = qdf_nbuf_data(msdu);

            /* get ether type */
            ether_type = (wh[offset] << 8) | wh[offset+1];
        }
        else {
            ether_type = transcap_nwifi_ether_type(msdu);
        }

        /* get packet type */
        if (is_mcast) {
            packet_type = PRIVACY_FILTER_PACKET_MULTICAST;
        } else {
            packet_type = PRIVACY_FILTER_PACKET_UNICAST;
        }
    }
    /* get encrypt info */
    is_encrypted = htt_rx_mpdu_is_encrypted(htt_pdev, rx_desc);

    for (i=0; i < vdev->filters_num; i++) {
        /* skip if the ether type does not match */
        if (vdev->privacy_filters[i].ether_type != ether_type) {
            continue;
        }

        /* skip if the packet type does not match */
        if (vdev->privacy_filters[i].packet_type != packet_type &&
            vdev->privacy_filters[i].packet_type != PRIVACY_FILTER_PACKET_BOTH) {
            continue;
        }

        if (vdev->privacy_filters[i].filter_type == PRIVACY_FILTER_ALWAYS) {
            /*
             * In this case, we accept the frame if and only if it was originally
             * NOT encrypted.
             */
            if (is_encrypted) {
                return FILTER_STATUS_REJECT;
            } else {
                return FILTER_STATUS_ACCEPT;
            }
        } else if (vdev->privacy_filters[i].filter_type  == PRIVACY_FILTER_KEY_UNAVAILABLE) {
            /*
             * In this case, we reject the frame if it was originally NOT encrypted but
             * we have the key mapping key for this frame.
             */
            if (!is_encrypted && !is_mcast && (peer->security[txrx_sec_ucast].sec_type != htt_sec_type_none)) {
                 return FILTER_STATUS_REJECT;
            } else {
                return FILTER_STATUS_ACCEPT;
            }
        } else {
            /*
             * The privacy exemption does not apply to this frame.
             */
            break;
        }
    }

    /* Reject if the the node is not authorized */
    if (!peer->authorize) {
        return FILTER_STATUS_REJECT;
    }

    /*
     * If the privacy exemption list does not apply to the frame, check ExcludeUnencrypted.
     * if ExcludeUnencrypted is not set, or if this was oringially an encrypted frame,
     * it will be accepted.
     *
     */
    if (!vdev->drop_unenc || is_encrypted) {
        return FILTER_STATUS_ACCEPT;
    }

    /*
     *  If this is a open connection, it will be accepted.
     */
    if(peer->security[is_mcast ? txrx_sec_mcast : txrx_sec_ucast].sec_type == htt_sec_type_none) {
        return FILTER_STATUS_ACCEPT;
    }

    return FILTER_STATUS_REJECT;
}

void
ol_rx_deliver(
    struct ol_txrx_vdev_t *vdev,
    struct ol_txrx_peer_t *peer,
    unsigned tid,
    qdf_nbuf_t msdu_list)
{
    ol_txrx_pdev_handle pdev = vdev->pdev;
    htt_pdev_handle htt_pdev = pdev->htt_pdev;
    qdf_nbuf_t deliver_list_head = NULL;
    qdf_nbuf_t deliver_list_tail = NULL;
    qdf_nbuf_t msdu;
    uint8_t filter = 0;
#if OL_ATH_SUPPORT_LED
    uint32_t   byte_cnt = 0;
#endif

    if (OL_CFG_RAW_RX_LIKELINESS(vdev->rx_decap_type == htt_pkt_type_raw)) {
        /* Mixed VAP implementations for chipsets lacking per-VDEV (via
         * per-peer) capability can add requisite exceptions here.
         * Rx delivery function pointers unaltered to facilitate this.
         */
        OL_RX_DELIVER_RAW(vdev, peer, tid, msdu_list);
        return;
    }

    msdu = msdu_list;
    /*
     * Check each MSDU to see whether it requires special handling,
     * and free each MSDU's rx descriptor
     */
    while (msdu) {
        void *rx_desc;
        int discard, inspect, dummy_fwd;
        qdf_nbuf_t next = qdf_nbuf_next(msdu);

        rx_desc = htt_rx_msdu_desc_retrieve(pdev->htt_pdev, msdu);

#if ATH_RX_PRI_SAVE
        /* Save to skb->priority */
        wbuf_set_priority(msdu,tid);
#endif

        // for HL, point to payload right now
        if (pdev->cfg.is_high_latency) {
            qdf_nbuf_pull_head(msdu,
                    htt_rx_msdu_rx_desc_size_hl(htt_pdev,
                        rx_desc));
        }

        htt_rx_msdu_actions(
            pdev->htt_pdev, rx_desc, &discard, &dummy_fwd, &inspect);

	if (pdev->host_80211_enable && !pdev->nss_nwifi_offload) {
		transcap_nwifi_to_8023(msdu);
	}


        if (inspect) {
//TODO Need to debug why it is crashing in QVIT
#ifdef QVIT
#else
            discard = ol_rx_inspect(vdev, peer, tid, msdu, rx_desc);
#endif
        }

        /* Check the first msdu in mpdu, if it will be filter out, then discard all the mpdu */
        if (htt_rx_msdu_first_msdu_flag(htt_pdev, rx_desc)) {
            filter = ol_rx_filter(vdev, peer, msdu, rx_desc);
        }

        htt_rx_msdu_desc_free(htt_pdev, msdu);
        if (discard || filter) {
#if HTT_DEBUG_DATA
            HTT_PRINT("-\n");
            if (tid == 0) {
                if (qdf_nbuf_data(msdu)[0x17] == 0x6) {
                    // TCP, dump seq
                    HTT_PRINT("0x%02x 0x%02x 0x%02x 0x%02x\n",
                            qdf_nbuf_data(msdu)[0x26],
                            qdf_nbuf_data(msdu)[0x27],
                            qdf_nbuf_data(msdu)[0x28],
                            qdf_nbuf_data(msdu)[0x29]);
                } else {
                    HTT_PRINT_BUF(printk, qdf_nbuf_data(msdu),
                            0x41,__func__);
                }
            }

#endif
            qdf_nbuf_free(msdu);
            /* If discarding packet is last packet of the delivery list,NULL terminator should be added for delivery list. */
            if (next == NULL && deliver_list_head){
                qdf_nbuf_set_next(deliver_list_tail, NULL); /* add NULL terminator */
            }
        } else {
#if OL_ATH_SUPPORT_LED
            byte_cnt += qdf_nbuf_len(msdu);
#endif
#if MESH_MODE_SUPPORT
            if (vdev->mesh_vdev) {
                ol_rx_mesh_mode_per_pkt_rx_info(msdu, peer, vdev);
            }
#endif
            TXRX_STATS_MSDU_INCR(vdev->pdev, rx.delivered, msdu);
            OL_TXRX_PROT_AN_LOG(vdev->pdev->prot_an_rx_sent, msdu);
            OL_TXRX_LIST_APPEND(deliver_list_head, deliver_list_tail, msdu);
        }
        msdu = next;
    }
    /* sanity check - are there any frames left to give to the OS shim? */
    if (!deliver_list_head) {
        return;
    }


#if HTT_DEBUG_DATA
    /*
     * we need a place to dump rx data buf
     * to host stack, here's a good place
     */
    for (msdu = deliver_list_head; msdu; msdu = qdf_nbuf_next(msdu)) {
        if (tid == 0) {
            if (qdf_nbuf_data(msdu)[0x17] == 0x6) {
                // TCP, dump seq
                HTT_PRINT("0x%02x 0x%02x 0x%02x 0x%02x\n",
                        qdf_nbuf_data(msdu)[0x26],
                        qdf_nbuf_data(msdu)[0x27],
                        qdf_nbuf_data(msdu)[0x28],
                        qdf_nbuf_data(msdu)[0x29]);
            } else {
                HTT_PRINT_BUF(printk, qdf_nbuf_data(msdu),
                        0x41,__func__);
            }
        }
    }
#endif

    vdev->osif_rx(vdev->osif_vdev, deliver_list_head);
#if OL_ATH_SUPPORT_LED
    {
        struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)pdev->ctrl_pdev;
        scn->scn_led_byte_cnt += byte_cnt;
        ol_ath_led_event(scn, OL_ATH_LED_RX);
    }
#endif

}

inline int
ol_get_rx_decap_mode_frmvdev(ol_txrx_vdev_handle vdev)
{
    return vdev->rx_decap_type;
}

void
ol_rx_discard(
    struct ol_txrx_vdev_t *vdev,
    struct ol_txrx_peer_t *peer,
    unsigned tid,
    qdf_nbuf_t msdu_list)
{
    ol_txrx_pdev_handle pdev = vdev->pdev;
    htt_pdev_handle htt_pdev = pdev->htt_pdev;

    while (msdu_list) {
        qdf_nbuf_t msdu = msdu_list;

        msdu_list = qdf_nbuf_next(msdu_list);
        TXRX_PRINT(TXRX_PRINT_LEVEL_INFO2,
            "discard rx %p from partly-deleted peer %p "
            "(%02x:%02x:%02x:%02x:%02x:%02x)\n",
            msdu, peer,
            peer->mac_addr.raw[0], peer->mac_addr.raw[1],
            peer->mac_addr.raw[2], peer->mac_addr.raw[3],
            peer->mac_addr.raw[4], peer->mac_addr.raw[5]);
        htt_rx_desc_frame_free(htt_pdev, msdu);
    }
}

void
ol_rx_peer_init(struct ol_txrx_pdev_t *pdev, struct ol_txrx_peer_t *peer)
{
    int tid;
    for (tid = 0; tid < OL_TXRX_NUM_EXT_TIDS; tid++) {
        ol_rx_reorder_init(&peer->tids_rx_reorder[tid], tid);

        /* invalid sequence number */
        peer->tids_last_seq[tid] = 0xffff;
    }
    /*
     * Set security defaults: no PN check, no security.
     * The target may send a HTT SEC_IND message to overwrite these defaults.
     */
    peer->security[txrx_sec_ucast].sec_type =
        peer->security[txrx_sec_mcast].sec_type = htt_sec_type_none;
}

void
ol_rx_peer_cleanup(struct ol_txrx_vdev_t *vdev, struct ol_txrx_peer_t *peer)
{
    ol_rx_reorder_peer_cleanup(vdev, peer);
}

/*
 * Free frames including both rx descriptors and buffers
 */
void
ol_rx_frames_free(
    htt_pdev_handle htt_pdev,
    qdf_nbuf_t frames)
{
    qdf_nbuf_t next, frag = frames;

    while (frag) {
        next = qdf_nbuf_next(frag);
        htt_rx_desc_frame_free(htt_pdev, frag);
        frag = next;
    }
}



void ol_ath_arp_debug(htt_pdev_handle pdev, qdf_nbuf_t msdu)
{
    struct ol_ath_softc_net80211 * scn;
    u_int8_t *data, *l3_hdr;
    u_int16_t ethertype;
    int offset;
    struct ethhdr * eh = NULL;
    uint32_t arp_src = 0;
    uint32_t arp_dst = 0;
    uint16_t arp_cmd = 0;
    struct iphdr *iph = NULL;
    struct icmphdr *icmp = NULL;

    data = qdf_nbuf_data(msdu);
    eh = (struct ethhdr *)data;
    scn = (struct ol_ath_softc_net80211 *)pdev->ctrl_pdev;

    if(scn->sc_arp_dbg_conf) {
        iph = (struct iphdr*)(((uint8_t *)eh) + sizeof(struct ethhdr));

        if (iph->protocol == IPPROTO_ICMP ) {
            icmp = (struct icmphdr*)(((uint8_t *)iph) + (iph->ihl * 4));

            if ((iph->daddr == ntohl(scn->sc_arp_dbg_srcaddr)) && (iph->saddr == ntohl(scn->sc_arp_dbg_dstaddr))) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: ICMP type: %d: Sequence: %u From Source Address: 0x%08x To Destination Address: 0x%08x \n", __func__, icmp->type, icmp->un.echo.sequence
                        , iph->saddr , iph->daddr);

            }
        }

#define ARP_SRC_OFFSET 28
#define ARP_DESTINATION_OFFSET 40
#define ARP_DEST_SHIFT 16
#define ARP_DEST_SHIFT_OFFSET 38
#define ARP_CMD_OFFSET 20

        arp_src = *(uint32_t *)((uint8_t *)data + ARP_SRC_OFFSET);
        arp_dst = *(uint16_t *)((uint8_t *)data + ARP_DESTINATION_OFFSET);
        arp_dst <<= ARP_DEST_SHIFT;
        arp_dst |= *(uint16_t *)((uint8_t *)data + ARP_DEST_SHIFT_OFFSET);
        arp_cmd = *(uint16_t *)((uint8_t *)data + ARP_CMD_OFFSET);

#undef ARP_SRC_OFFSET
#undef ARP_DESTINATION_OFFSET
#undef ARP_DEST_SHIFT
#undef ARP_DEST_SHIFT_OFFSET
#undef ARP_CMD_OFFSET

        if (scn->host_80211_enable) {
            struct ieee80211_frame_addr4 *wh;
            uint8_t fc1;
            uint32_t hdrsize;
            wh = (struct ieee80211_frame_addr4 *)data;
            fc1 = wh->i_fc[1] & IEEE80211_FC1_DIR_MASK;

            /* Native Wifi header  give only 80211 non-Qos packets */
            if (fc1 == IEEE80211_FC1_DIR_DSTODS ) {
                hdrsize = sizeof(struct ieee80211_frame_addr4);

                /* In case of WDS frames, , padding is enabled by default
                 * in Native Wifi mode, to make ipheader 4 byte aligned
                 */
                hdrsize = hdrsize + OLE_HEADER_PADDING;
            } else {
                hdrsize = sizeof(struct ieee80211_frame);
            }
            /* adjust data to point to ethernet header */
            data += hdrsize;

#define ETHER_TYPE_OFFSET 6  /* offset from llc header */
            ethertype = (data[ETHER_TYPE_OFFSET] << 8) | data[ETHER_TYPE_OFFSET + 1];

            l3_hdr = data + sizeof(struct llc);
            data = data + sizeof(struct llc) - sizeof(struct ether_header);
        }
        else {
            offset = ETHERNET_ADDR_LEN * 2;
            ethertype = (data[offset] << 8) | data[offset+1];
        }

#define ARP_REQ 0x100
#define ARP_RESP 0x200

        if (ethertype == ETHERTYPE_ARP) {
            if ((arp_dst == ntohl(scn->sc_arp_dbg_srcaddr)) && (arp_src == ntohl(scn->sc_arp_dbg_dstaddr))) {
                if (arp_cmd == ARP_REQ) {
                    scn->sc_rx_arp_req_count++;
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\nARP_DEBUG : %s: Rx ARP Request Packet from SourceIP %x to Destination IP %x, ethertype %x \n", __func__, ntohl(scn->sc_arp_dbg_dstaddr),ntohl(scn->sc_arp_dbg_srcaddr), ethertype);
                }
                else if (arp_cmd == ARP_RESP) {
                    scn->sc_rx_arp_resp_count++;
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\nARP_DEBUG : %s: Rx ARP Response Packet from SourceIP %x to Destination IP %x, ethertype %x \n", __func__,ntohl(scn->sc_arp_dbg_dstaddr),ntohl(scn->sc_arp_dbg_srcaddr), ethertype);
                }
            }
        }
#undef ARP_REQ
#undef ARP_RESP
    }
}

/**
 * @brief populates vow ext stats in given network buffer.
 * @param msdu - network buffer handle
 * @param pdev - handle to htt dev.
 */
void ol_ath_add_vow_extstats(rx_handle_t rxh, qdf_nbuf_t msdu)
{
    struct ol_ath_softc_net80211 * scn;
    htt_pdev_handle pdev = (htt_pdev_handle) rxh;

    if (ol_scn_vow_extstats(pdev->ctrl_pdev) == 0) {
        return;
    } else {
        u_int8_t *data, *l3_hdr, *bp;
        u_int16_t ethertype;
        int offset;
        u_int32_t phy_err_cnt=0, rx_clear_cnt=0, rx_cycle_cnt=0;
        struct vow_extstats vowstats;

        data = qdf_nbuf_data(msdu);

        scn = (struct ol_ath_softc_net80211 *)pdev->ctrl_pdev;
        if (scn->host_80211_enable) {
            struct ieee80211_frame_addr4 *wh;
            uint8_t fc1;
            uint32_t hdrsize;
            wh = (struct ieee80211_frame_addr4 *)data;
            fc1 = wh->i_fc[1] & IEEE80211_FC1_DIR_MASK;

            /* Native Wifi header  give only 80211 non-Qos packets */
            if (fc1 == IEEE80211_FC1_DIR_DSTODS ) {
                hdrsize = sizeof(struct ieee80211_frame_addr4);

                /* In case of WDS frames, , padding is enabled by default
                 * in Native Wifi mode, to make ipheader 4 byte aligned
                 */
                hdrsize = hdrsize + OLE_HEADER_PADDING;
            } else {
                hdrsize = sizeof(struct ieee80211_frame);
            }
            /* adjust data to point to ethernet header */
            data += hdrsize;

#define ETHER_TYPE_OFFSET 6  /* offset from llc header */
            ethertype = (data[ETHER_TYPE_OFFSET] << 8) | data[ETHER_TYPE_OFFSET + 1];

            l3_hdr = data + sizeof(struct llc);
            data = data + sizeof(struct llc) - sizeof(struct ether_header);
        }
        else {
            offset = ETHERNET_ADDR_LEN * 2;
            l3_hdr = data + ETHERNET_HDR_LEN;
            ethertype = (data[offset] << 8) | data[offset+1];
        }

        if (ethertype == ETHERTYPE_IPV4) {
            offset = IPV4_HDR_OFFSET_PROTOCOL;
            if ((l3_hdr[offset] == IP_PROTOCOL_UDP) && (l3_hdr[0] == IP_VER4_N_NO_EXTRA_HEADERS)) {
                bp = data+EXT_HDR_OFFSET;

                if ( (data[RTP_HDR_OFFSET] == UDP_PDU_RTP_EXT) &&
                        (bp[0] == 0x12) &&
                        (bp[1] == 0x34) &&
                        (bp[2] == 0x00) &&
                        (bp[3] == 0x08)) {
                    /* clear udp checksum so we do not have to recalculate it after
                     * filling in status fields */
                    data[UDP_CKSUM_OFFSET] = 0;
                    data[(UDP_CKSUM_OFFSET+1)] = 0;

                    bp += IPERF3_DATA_OFFSET;

                    pdev->ar_rx_ops->get_vowext_stats(msdu, &vowstats);

                    /* control channel RSSI */
                    *bp++ = vowstats.rx_rssi_ctl0;
                    *bp++ = vowstats.rx_rssi_ctl1;
                    *bp++ = vowstats.rx_rssi_ctl2;

                    /* rx rate info */
                    *bp++ = vowstats.rx_bw;
                    *bp++ = vowstats.rx_sgi;
                    *bp++ = vowstats.rx_nss;

                    *bp++ = vowstats.rx_rssi_comb;
                    *bp++ = vowstats.rx_rs_flags; /* rsflags */

                    /* Time stamp Lo*/
                    *bp++ = (u_int8_t)((vowstats.rx_macTs & 0x0000ff00) >> 8);
                    *bp++ = (u_int8_t)(vowstats.rx_macTs & 0x000000ff);

                    ol_scn_vow_get_rxstats(pdev->ctrl_pdev, &phy_err_cnt, &rx_clear_cnt, &rx_cycle_cnt);

                    /* rx phy errors */
                    *bp++ = (u_int8_t)((phy_err_cnt >> 8) & 0xff);
                    *bp++ = (u_int8_t)(phy_err_cnt & 0xff);
                    /* rx clear count */
                    *bp++ = (u_int8_t)((rx_clear_cnt >> 24) & 0xff);
                    *bp++ = (u_int8_t)((rx_clear_cnt >> 16) & 0xff);
                    *bp++ = (u_int8_t)((rx_clear_cnt >>  8) & 0xff);
                    *bp++ = (u_int8_t)(rx_clear_cnt & 0xff);
                    /* rx cycle count */
                    *bp++ = (u_int8_t)((rx_cycle_cnt >> 24) & 0xff);
                    *bp++ = (u_int8_t)((rx_cycle_cnt >> 16) & 0xff);
                    *bp++ = (u_int8_t)((rx_cycle_cnt >>  8) & 0xff);
                    *bp++ = (u_int8_t)(rx_cycle_cnt & 0xff);

                    *bp++ = vowstats.rx_ratecode;
                    *bp++ = vowstats.rx_moreaggr;

                    /* sequence number */
                    *bp++ = (u_int8_t)((vowstats.rx_seqno >> 8) & 0xff);
                    *bp++ = (u_int8_t)(vowstats.rx_seqno & 0xff);
                }
            }
        }
    }
}

