/*
 * Copyright (c) 2011, 2015, Atheros Communications Inc.
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
 * LMAC VAP specific offload interface functions for UMAC - for power and performance offload model
 */
#include "ol_if_athvar.h"
#include "wmi_unified_api.h"
#include "qdf_mem.h"
#if 0
#include "wmi_unified.h"
#endif
#if ATH_SUPPORT_GREEN_AP
#include "ath_green_ap.h"
#endif  /* ATH_SUPPORT_GREEN_AP */
#include "a_debug.h"
#include <ol_htt_tx_api.h>

#include <htt_internal.h>
#include <ol_txrx_types.h>
#include <ieee80211_acfg.h>


#if ATH_PERF_PWR_OFFLOAD

#ifndef HT_RC_2_STREAMS
#define HT_RC_2_STREAMS(_rc)    ((((_rc) & 0x78) >> 3) + 1)
#endif

#define NUM_LEGACY_RATES 12
#define L_BPS_COL         0
#define L_RC_COL          1

#define ALD_MSDU_SIZE 1300
#define DEFAULT_MSDU_SIZE 1000
static const int legacy_rate_idx[][2] = {
    {1000,        0x1b},
    {2000,        0x1a},
    {5500,        0x19},
    {6000,        0xb},
    {9000,        0xf},
    {11000,       0x18},
    {12000,       0xa},
    {18000,       0xe},
    {24000,       0x9},
    {36000,       0xd},
    {48000,       0x8},
    {54000,       0xc},
};

#define NUM_VHT_HT_RATES 40
#define BW_COL 0
#define MCS_COL 1
#define NBPS_COL 2
static const int vht_ht_tbl[][3] = {
   /*BW        MCS       Data bits per symbol*/
    {0,        0,        26000},
    {0,        1,        52000},
    {0,        2,        78000},
    {0,        3,        104000},
    {0,        4,        156000},
    {0,        5,        208000},
    {0,        6,        234000},
    {0,        7,        260000},
    {0,        8,        312000},
    {0,        9,        346680},
    {1,        0,        54000},
    {1,        1,        108000},
    {1,        2,        162000},
    {1,        3,        216000},
    {1,        4,        324000},
    {1,        5,        432000},
    {1,        6,        486000},
    {1,        7,        540000},
    {1,        8,        648000},
    {1,        9,        720000},
    {2,        0,        117000},
    {2,        1,        234000},
    {2,        2,        351000},
    {2,        3,        468000},
    {2,        4,        702000},
    {2,        5,        936000},
    {2,        6,        1053000},
    {2,        7,        1170000},
    {2,        8,        1404000},
    {2,        9,        1560000},
    {3,        0,        234000},
    {3,        1,        468000},
    {3,        2,        702000},
    {3,        3,        936000},
    {3,        4,        1404000},
    {3,        5,        1872000},
    {3,        6,        2106000},
    {3,        7,        2340000},
    {3,        8,        2808000},
    {3,        9,        3120000},
};

#define NG_VHT_MODES 3

static u_int32_t max_rates[IEEE80211_MODE_11AC_VHT80_80+NG_VHT_MODES+1][8] = {
    /*
     *    * 1x1            2x2             3x3                 4x4
     *       * GI     SGI     GI      SGI     GI      SGI         GI        SGI
     *          */

    {    0,      0,      0,      0,      0,       0,        0,      0},  /* IEEE80211_MODE_AUTO, autoselect */
    {54000,  54000,  54000,  54000,  54000,   54000,    54000,  54000},  /* IEEE80211_MODE_11A, 5GHz, OFDM */
    {11000,  11000,  11000,  11000,  11000,   11000,    11000,  11000},  /* IEEE80211_MODE_11B 2GHz, CCK  */
    {54000,  54000,  54000,  54000,  54000,   54000,    54000,  54000},  /* IEEE80211_MODE_11G 2GHz, OFDM */
    {    0,      0,      0,      0,      0,       0,        0,      0},  /* IEEE80211_MODE_FH 2GHz, GFSK */
    {    0,      0,      0,      0,      0,       0,        0,      0},  /* IEEE80211_MODE_TURBO_A 5GHz, OFDM, 2x clock dynamic turbo   */
    {    0,      0,      0,      0,      0,       0,        0,      0},  /* IEEE80211_MODE_TURBO_G 2GHz, OFDM, 2x clock dynamic turbo   */
    {65000,  72200,  130000, 144400, 195000,  216700,   260000,  288900},/* IEEE80211_MODE_11NA_HT20 5Ghz, HT20 */
    {65000,  72200,  130000, 144400, 195000,  216700,   260000,  288900},/* IEEE80211_MODE_11NG_HT20 2Ghz, HT20 */
    {135000, 150000, 270000, 300000, 405000,  450000,   540000,  600000},/* IEEE80211_MODE_11NA_HT40PLUS 5Ghz, HT40 (ext ch +1)*/
    {135000, 150000, 270000, 300000, 405000,  450000,   540000,  600000},/* IEEE80211_MODE_11NA_HT40MINUS 5Ghz, HT40 (ext ch -1)*/
    {135000, 150000, 270000, 300000, 405000,  450000,   540000,  600000},/* IEEE80211_MODE_11NG_HT40PLUS 2Ghz, HT40 (ext ch +1)*/
    {135000, 150000, 270000, 300000, 405000,  450000,   540000,  600000},/* IEEE80211_MODE_11NG_HT40MINUS   2Ghz, HT40 (ext ch -1)*/
    {135000, 150000, 270000, 300000, 405000,  450000,   540000,  600000},/* IEEE80211_MODE_11NG_HT40  2Ghz, Auto HT40*/
    {135000, 150000, 270000, 300000, 405000,  450000,   540000,  600000},/* IEEE80211_MODE_11NA_HT40  2Ghz, Auto HT40*/
    {78000,  86700,  156000, 173300, 260000,  288900,   312000,  346700},/* IEEE80211_MODE_11AC_VHT20 5Ghz, VHT20*/
    {180000, 200000, 360000, 400000, 540000,  600000,   720000,  800000},/* IEEE80211_MODE_11AC_VHT40PLUS 5Ghz, VHT40 (Ext ch +1)*/
    {180000, 200000, 360000, 400000, 540000,  600000,   720000,  800000},/* IEEE80211_MODE_11AC_VHT40MINUS  5Ghz  VHT40 (Ext ch -1)*/
    {180000, 200000, 360000, 400000, 540000,  600000,   720000,  800000},/* IEEE80211_MODE_11AC_VHT40 5Ghz, VHT40 */
    {390000, 433300, 780000, 866700, 1170000, 1300000,  1560000,1733300},/* IEEE80211_MODE_11AC_VHT80 5Ghz, VHT80 */
    {780000, 866700, 1560000, 1733300, 2106000, 2340000, 3120000, 3466700},/* IEEE80211_MODE_11AC_VHT160 5Ghz, VHT160 */
    {780000, 866700, 1560000, 1733300, 2106000, 2340000, 3120000, 3466700},/* IEEE80211_MODE_11NG_HT80_80 5Ghz, VHT80_80 */
    {78000,  86700,  156000, 173300, 260000,  288900,   312000,  346700},/* IEEE80211_MODE_11NG_HT20 2Ghz, VHT20 BCC*/
    {86500,  96000,  173000, 192000, 260000,  288900,   344000,  378400},/* IEEE80211_MODE_11NG_HT20 2Ghz, VHT20 LDPC*/
    {180000, 200000, 360000, 400000, 540000,  600000,   720000,  800000},/* IEEE80211_MODE_11NG_HT40(+/-) 2Ghz, VHT40 LDPC*/
};

/* WMI interface functions */
int
ol_ath_node_set_param(struct ol_ath_softc_net80211 *scn, u_int8_t *peer_addr,u_int32_t param_id,
        u_int32_t param_val,u_int32_t vdev_id)
{
    struct peer_set_params param;
    qdf_mem_set(&param, sizeof(param), 0);
    param.param_id = param_id;
    param.vdev_id = vdev_id;
    param.param_value = param_val;

    return wmi_set_peer_param_send(scn->wmi_handle, peer_addr, &param);
}



static void
set_node_wep_keys(struct ieee80211vap *vap, const u_int8_t *macaddr)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    u_int8_t keymac[IEEE80211_ADDR_LEN];
    struct ieee80211_key *wkey;
    struct ieee80211_rsnparms *rsn = &vap->iv_rsn;
    int i, opmode;

    wkey = (struct ieee80211_key *)OS_MALLOC(scn->sc_osdev,
						sizeof(struct ieee80211_key),
                                                0);
    OS_MEMZERO(wkey, sizeof(struct ieee80211_key));
    opmode = ieee80211vap_get_opmode(vap);

    /* push only valid static WEP keys from vap */

    if (RSN_AUTH_IS_8021X(rsn)) {
        OS_FREE(wkey);
        return ;
    }

    for(i=0;i<IEEE80211_WEP_NKID;i++) {

        OS_MEMCPY(wkey,&vap->iv_nw_keys[i],sizeof(struct ieee80211_key));

        if(wkey->wk_valid && wkey->wk_cipher->ic_cipher==IEEE80211_CIPHER_WEP) {
               IEEE80211_ADDR_COPY(keymac,macaddr);

            /* setting the broadcast/multicast key for sta */
            if(opmode == IEEE80211_M_STA || opmode == IEEE80211_M_IBSS){
                vap->iv_key_set(vap, wkey, keymac);
            }

            /* setting unicast key */
            wkey->wk_flags &= ~IEEE80211_KEY_GROUP;
            vap->iv_key_set(vap, wkey, keymac);
        }
    }
    OS_FREE(wkey);

}

static A_BOOL
is_node_self_peer(struct ieee80211vap *vap, const u_int8_t *macaddr)
{
    A_BOOL is_self_peer = FALSE;

    switch (vap->iv_opmode) {
    case IEEE80211_M_STA:
        if (IEEE80211_ADDR_EQ(macaddr, vap->iv_myaddr)) {
            is_self_peer = TRUE;
        }
        break;
    default:
        break;
    }

    return is_self_peer;
}

/* Interface functions */
static struct ieee80211_node *
ol_ath_node_alloc(struct ieee80211vap *vap, const u_int8_t *macaddr, bool tmpnode)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_node_net80211 *anode;
    struct peer_create_params param;
#if UMAC_SUPPORT_ACFG
    acfg_event_data_t *acfg_event = NULL;

#endif

    qdf_mem_set(&param, sizeof(param), 0);
    anode = (struct ol_ath_node_net80211 *)qdf_mempool_alloc(scn->qdf_dev, scn->mempool_ol_ath_node);
    if (anode == NULL)
        return NULL;

    OS_MEMZERO(anode, sizeof(struct ol_ath_node_net80211));

    anode->an_node.ni_vap = vap;

    /* do not create/delete peer on target for temp nodes and self-peers */
    if (!tmpnode && !is_node_self_peer(vap, macaddr) && (vap->iv_opmode != IEEE80211_M_MONITOR)) {
        if (qdf_atomic_dec_and_test(&scn->peer_count)) {
            AR_DEBUG_PRINTF(ATH_DEBUG_INFO,
                    ("%s: vap (%p) scn (%p) the peer count exceeds the supported number %d \n",
                     __func__, vap, scn, scn->wlan_resource_config.num_peers));
#if UMAC_SUPPORT_ACFG
            acfg_event = (acfg_event_data_t *)qdf_mem_malloc( sizeof(acfg_event_data_t));
            if (acfg_event != NULL){
                acfg_send_event(scn->sc_osdev->netdev, scn->sc_osdev, WL_EVENT_TYPE_EXCEED_MAX_CLIENT, acfg_event);
                qdf_mem_free(acfg_event);
            }
#endif
            qdf_mempool_free(scn->qdf_dev, scn->mempool_ol_ath_node, anode);
            goto err_node_alloc;
        }

        param.peer_addr = macaddr;
        param.vdev_id = avn->av_if_id;
        if (wmi_unified_peer_create_send(scn->wmi_handle, &param)) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : Unable to create peer in Target \n", __func__);
            qdf_mempool_free(scn->qdf_dev, scn->mempool_ol_ath_node, anode);
            goto err_node_alloc;
        }

        qdf_spin_lock_bh(&scn->scn_lock);
        anode->an_txrx_handle = ol_txrx_peer_attach(avn->av_txrx_handle, 
                                               (u_int8_t *) macaddr);

        if (anode->an_txrx_handle == NULL) {
			qdf_spin_unlock_bh(&scn->scn_lock);
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : Unable to attach txrx peer\n", __func__);
            qdf_mempool_free(scn->qdf_dev, scn->mempool_ol_ath_node, anode);
            goto err_node_alloc;
        }
        qdf_spin_unlock_bh(&scn->scn_lock);

        /* static wep keys stored in vap needs to be
         * pushed to all nodes except self node
         */
        if(IEEE80211_VAP_IS_PRIVACY_ENABLED(vap) &&
                (OS_MEMCMP(macaddr,vap->iv_myaddr,IEEE80211_ADDR_LEN) != 0 )) {
            set_node_wep_keys(vap,macaddr);
        }
    }
#if ATH_SUPPORT_NAC
    if(vap->iv_smart_monitor_vap) {
        qdf_spin_lock_bh(&scn->scn_lock);
        if ((anode->an_txrx_handle == NULL) &&
            ((anode->an_txrx_handle = ol_txrx_peer_attach(avn->av_txrx_handle,
                                                   (u_int8_t *) macaddr)) == NULL)) {
                qdf_spin_unlock_bh(&scn->scn_lock);
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : Unable to attach txrx peer\n", __func__);
                qdf_mempool_free(scn->qdf_dev, scn->mempool_ol_ath_node, anode);
                goto err_node_alloc;
        }
        qdf_spin_unlock_bh(&scn->scn_lock);
        anode->an_txrx_handle->nac =1;
    }
#endif
#if IEEE80211_DEBUG_REFCNT
    anode->an_node.trace = (struct node_trace_all *)OS_MALLOC(ic->ic_osdev, sizeof(struct node_trace_all), GFP_KERNEL);
    if (anode->an_node.trace == NULL) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Can't create an node trace\n");
        return NULL;
    }
    OS_MEMZERO(anode->an_node.trace, sizeof(struct node_trace_all));
#endif
    return &anode->an_node;

err_node_alloc:
    qdf_atomic_inc(&scn->peer_count);
    return NULL;

}

static void
ol_ath_node_free(struct ieee80211_node *ni)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    u_int32_t ni_flags = ni->ni_flags;

    qdf_spin_lock_bh(&scn->scn_lock);
    if (ni_flags & IEEE80211_NODE_EXT_STATS) {
        scn->peer_ext_stats_count--;
    }
    qdf_spin_unlock_bh(&scn->scn_lock);
    /* Call back the umac node free function */
    scn->net80211_node_free(ni);
    /* Moved node free here from umac layer since allocation is actually done by ol_if layer */
    qdf_mempool_free(scn->qdf_dev, scn->mempool_ol_ath_node, ni);
}

static inline uint32_t
ol_if_drain_mgmt_backlog_queue(struct ieee80211_node *ni)
{

    struct ieee80211com *ic = ni->ni_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct htt_pdev_t *hpdev = scn->pdev_txrx_handle->htt_pdev;
    int vdev_id = (OL_ATH_VAP_NET80211(ni->ni_vap))->av_if_id;
    uint16_t mgmt_type = (OL_TXRX_MGMT_NUM_TYPES-1);
    qdf_nbuf_t tx_mgmt_frm = NULL;
    ol_txrx_mgmt_tx_cb  cb = NULL;
    void *ctxt = NULL;
    qdf_nbuf_queue_t *MgmtQ = NULL;
    qdf_nbuf_queue_t tmpQ;
    qdf_nbuf_queue_t cbQ;
    uint32_t nfreed = 0;
    struct ieee80211_node *temp_ni = NULL;
    int temp_vid = 0;

    /* Init temp queues */
    qdf_nbuf_queue_init(&tmpQ);
    qdf_nbuf_queue_init(&cbQ);

    cb = hpdev->txrx_pdev->tx_mgmt.callbacks[mgmt_type].ota_ack_cb;
    ctxt = hpdev->txrx_pdev->tx_mgmt.callbacks[mgmt_type].ctxt;

    MgmtQ = (&scn->pdev_txrx_handle->htt_pdev->mgmtbufQ);

    /* Iterate over backlog management queue and check
     * whether this frames belongs to this particular vap?
     * If this frame belongs to this vap, call completion
     * handler ol_txrx_mgmt_tx_complete() with flag
     * IEEE80211_FORCE_FLUSH. Since frames in backlog SW queue
     * are not DMA mapped, unmapping is not required.
     * Frames which do not belong to this vap, add them to a
     * seperate list.
     */
    qdf_spin_lock_bh(&scn->pdev_txrx_handle->htt_pdev->mgmtbufLock);
    while(!qdf_nbuf_is_queue_empty(MgmtQ)) {
        tx_mgmt_frm = qdf_nbuf_queue_remove(MgmtQ);
        temp_ni = wbuf_get_node(tx_mgmt_frm);
        temp_vid = (OL_ATH_VAP_NET80211(temp_ni->ni_vap))->av_if_id;
        if (temp_vid == vdev_id) {
            qdf_nbuf_queue_add(&cbQ, tx_mgmt_frm);
        } else {
            qdf_nbuf_queue_add(&tmpQ, tx_mgmt_frm);
        }
    }
    /* Assign temp queue back to management backlog queue
     */
    scn->pdev_txrx_handle->htt_pdev->mgmtbufQ = tmpQ;
    qdf_spin_unlock_bh(&scn->pdev_txrx_handle->htt_pdev->mgmtbufLock);

    /* Call completion handler for each mgmt_frm in cbQ */
    if (cb) {
        while(!qdf_nbuf_is_queue_empty(&cbQ)) {
            ++nfreed;
            tx_mgmt_frm = qdf_nbuf_queue_remove(&cbQ);
            qdf_assert_always(tx_mgmt_frm);
            cb(ctxt, tx_mgmt_frm, IEEE80211_TX_ERROR);
        }
    }
    /* Clear temp queues to avoid any dangling reference.*/
    qdf_nbuf_queue_init(&tmpQ);
    qdf_nbuf_queue_init(&cbQ);

    return nfreed;
}

/* flush the mgmt packets when vap is going down */
void
ol_if_mgmt_drain(struct ieee80211_node *ni, int force)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct htt_pdev_t *hpdev = scn->pdev_txrx_handle->htt_pdev;
    uint8_t vdev_id = (uint8_t)(OL_ATH_VAP_NET80211(ni->ni_vap))->av_if_id;

    /* First drain SW queue to make sure no new frame is queued
     * to Firmware for this vap. It may also give us some time
     * to receive completions for outstanding frames.
     */
    (void)ol_if_drain_mgmt_backlog_queue(ni);
    if (force) {
        (void)htt_tx_mgmt_desc_drain(hpdev, vdev_id);
    } else {
        /* Mark frames waiting completions as delayed free.*/
        (void)htt_tx_mgmt_desc_mark_delayed_free(hpdev, vdev_id, IEEE80211_TX_ERROR_NO_SKB_FREE);
    }
}

EXPORT_SYMBOL(ol_if_mgmt_drain);



static void
ol_ath_node_cleanup(struct ieee80211_node *ni)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(ni->ni_vap);
    struct peer_flush_params param;
    u_int32_t peer_tid_bitmap = 0xffffffff; /* TBD : fill with all valid TIDs */

    /* flush all TIDs except MGMT TID for this peer in Target */
    peer_tid_bitmap &= ~(0x1 << WMI_HOST_MGMT_TID);
    param.peer_tid_bitmap = peer_tid_bitmap;
    param.vdev_id = avn->av_if_id;
    if (wmi_unified_peer_flush_tids_send(scn->wmi_handle, ni->ni_macaddr, &param)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : Unable to Flush tids peer in Target \n", __func__);
    }
    /* TBD: Cleanup the key index mapping */

    qdf_spin_lock_bh(&scn->scn_lock);
    if ((OL_ATH_NODE_NET80211(ni))->an_txrx_handle) {
        ol_txrx_peer_detach( (OL_ATH_NODE_NET80211(ni))->an_txrx_handle);

#if ATH_SUPPORT_GREEN_AP
        if ((ic->ic_opmode == IEEE80211_M_HOSTAP) && (ni->ni_associd > 0) && (ni != ni->ni_bss_node)) {
            ath_green_ap_state_mc(ic, ATH_PS_EVENT_DEC_STA);
        }
#endif  /* ATH_SUPPORT_GREEN_AP */

        /* Delete key */
        ieee80211_node_clear_keys(ni);
        /* Delete peer in Target */
        if (wmi_unified_peer_delete_send(scn->wmi_handle, ni->ni_macaddr, avn->av_if_id)) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : Unable to Delete peer in Target \n", __func__);
        }
        /*
         * It is possible that a node will be cleaned up for multiple times
         * before it is freed. Make sure we only remove TxRx/FW peer once.
         */
        (OL_ATH_NODE_NET80211(ni))->an_txrx_handle = NULL;
    }
    qdf_spin_unlock_bh(&scn->scn_lock);

    /* Call back the umac node cleanup function */
    scn->net80211_node_cleanup(ni);


}

#define OL_ATH_DUMMY_RSSI    254
static u_int8_t
ol_ath_node_getrssi(const struct ieee80211_node *ni,int8_t chain, u_int8_t flags )
{
    struct ieee80211vap *vap = ni->ni_vap ;
    if ( vap ) {
        if( !ni->ni_rssi &&
            (wlan_vap_get_opmode(vap) == IEEE80211_M_HOSTAP &&
             ieee80211_vap_ready_is_set(vap)) ) {
            return OL_ATH_DUMMY_RSSI ;
        }
    }
    return ni->ni_rssi;
}

static u_int32_t
ol_ath_node_getrate(const struct ieee80211_node *ni, u_int8_t type)
{
   if (type == IEEE80211_RATE_TX) {
        return (OL_ATH_NODE_NET80211(ni))->an_ni_tx_rate;

    } else if (type == IEEE80211_RATE_RX) {
        return (OL_ATH_NODE_NET80211(ni))->an_ni_rx_rate;
    } else if (type == IEEE80211_RATECODE_TX) {
        return (OL_ATH_NODE_NET80211(ni))->an_ni_tx_ratecode;
    } else if (type == IEEE80211_RATEFLAGS_TX) {
        return (OL_ATH_NODE_NET80211(ni))->an_ni_tx_flags;
    } else {
        return 0;
    }
   return 0;
}

#if QCA_AIRTIME_FAIRNESS
static u_int32_t
ol_ath_node_getairtime(const struct ieee80211_node *ni)
{
    u_int32_t airtime = 0;
    u_int32_t token_allocated;
    u_int32_t token_utilized;

    token_allocated = (OL_ATH_NODE_NET80211(ni))->an_ni_atf_token_allocated;
    token_utilized = (OL_ATH_NODE_NET80211(ni))->an_ni_atf_token_utilized;

    /* calc airtime %age */
    if (token_allocated)
        airtime = (token_utilized / token_allocated) * 100;

    return airtime;
}
#endif

static u_int32_t
ol_ath_node_get_last_txpower(const struct ieee80211_node *ni)
{
    return ((OL_ATH_NODE_NET80211(ni))->an_ni_tx_power / 2);
}

static void
ol_ath_node_psupdate(struct ieee80211_node *ni, int pwrsave, int pause_resume)
{
    struct ieee80211vap *vap = ni->ni_vap;

    if (pwrsave) {
        (void)wmi_unified_set_ap_ps_param(OL_ATH_VAP_NET80211(vap),
                   OL_ATH_NODE_NET80211(ni), WMI_HOST_AP_PS_PEER_PARAM_WNM_SLEEP,
                                          WMI_HOST_AP_PS_PEER_PARAM_WNM_SLEEP_ENABLE);
    } else {
        (void)wmi_unified_set_ap_ps_param(OL_ATH_VAP_NET80211(vap),
                   OL_ATH_NODE_NET80211(ni), WMI_HOST_AP_PS_PEER_PARAM_WNM_SLEEP,
                                          WMI_HOST_AP_PS_PEER_PARAM_WNM_SLEEP_DISABLE);
    }
}

static u_int32_t
ol_ath_node_get_maxphyrate(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    u_int8_t mcs;
    u_int8_t bw;
    struct ieee80211vap *vap = ni->ni_vap;
    u_int8_t curr_phy_mode = wlan_get_current_phymode(vap);
    enum ieee80211_fixed_rate_mode rate_mode = vap->iv_fixed_rate.mode;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    u_int8_t nss = 0;
    u_int8_t sgi = 0;
    int ratekbps;

    bw = wlan_get_param(vap, IEEE80211_CHWIDTH);

    if (ieee80211_vap_get_opmode(vap) == IEEE80211_M_STA) {
        if (((ni->ni_htcap & IEEE80211_HTCAP_C_SHORTGI40) && (bw == IEEE80211_CWM_WIDTH40)) ||
            ((ni->ni_htcap & IEEE80211_HTCAP_C_SHORTGI20) && (bw == IEEE80211_CWM_WIDTH20)) ||
            ((ni->ni_vhtcap & IEEE80211_VHTCAP_SHORTGI_80) && (bw == IEEE80211_CWM_WIDTH80))||
            ((ni->ni_vhtcap & IEEE80211_VHTCAP_SHORTGI_160) && (bw == IEEE80211_CWM_WIDTH160))) {
           sgi = 1;
        }
    } else {
           sgi = wlan_get_param(vap, IEEE80211_SHORT_GI);
    }

    if (rate_mode != IEEE80211_FIXED_RATE_NONE) {
        /* Get rates for fixed rate */
        u_int32_t nbps = 0; /*Number of bits per symbol*/
        u_int32_t rc; /* rate code*/
        u_int32_t i;

	/* For fixed rate ensure that SGI is enabled by user */
	sgi = vap->iv_data_sgi;

        switch (rate_mode)
        {
        case IEEE80211_FIXED_RATE_MCS:
            nss = HT_RC_2_STREAMS(vap->iv_fixed_rateset);
            rc = wlan_get_param(vap, IEEE80211_FIXED_RATE);
            mcs = (rc & 0x07);
            for (i = 0; i < NUM_VHT_HT_RATES; i++) {
                if (vht_ht_tbl[i][BW_COL] == bw &&
                    vht_ht_tbl[i][MCS_COL] == mcs) {
                    nbps = vht_ht_tbl[i][NBPS_COL];
                }
            }
            break;
        case IEEE80211_FIXED_RATE_VHT:
            nss = vap->iv_nss;
            mcs = wlan_get_param(vap, IEEE80211_FIXED_VHT_MCS);
            for (i = 0; i < NUM_VHT_HT_RATES; i++) {
                if (vht_ht_tbl[i][BW_COL] == bw &&
                    vht_ht_tbl[i][MCS_COL] == mcs) {
                    nbps = vht_ht_tbl[i][NBPS_COL];
                }
            }
            break;
        case IEEE80211_FIXED_RATE_LEGACY:
            rc = wlan_get_param(vap, IEEE80211_FIXED_RATE);
            for (i = 0; i < NUM_LEGACY_RATES; i++) {
                if (legacy_rate_idx[i][L_RC_COL] == (rc & 0xff)) {
                    return legacy_rate_idx[i][L_BPS_COL];
                }
            }
            break;
        default:
            break;
        }

        if (sgi) {
            return (nbps * 5 * nss / 18) ;
        } else {
            return (nbps * nss / 4) ;
        }
    } else {
        /* Get rates for auto rate */
        nss = ni->ni_streams;
        if(ieee80211_vap_get_opmode(vap) == IEEE80211_M_HOSTAP ||
           ieee80211_vap_get_opmode(vap) == IEEE80211_M_MONITOR) {
            nss = (vap->iv_nss >
                   ieee80211_getstreams(ic, ic->ic_tx_chainmask)) ?
                   ieee80211_getstreams(ic, ic->ic_tx_chainmask) :
                   vap->iv_nss;

        }
    }

    if (ni != vap->iv_bss) {
        curr_phy_mode = ni->ni_phymode;
        nss = ni->ni_streams;

        if (ni->ni_htcap) {
            sgi = ((ni->ni_htcap & IEEE80211_HTCAP_C_SHORTGI20) || (ni->ni_htcap & IEEE80211_HTCAP_C_SHORTGI40));
        }
        if (ni->ni_vhtcap) {
            sgi = ((ni->ni_vhtcap & IEEE80211_VHTCAP_SHORTGI_80) || (ni->ni_vhtcap & IEEE80211_VHTCAP_SHORTGI_160));
        }
    }

    if(ieee80211_vap_256qam_is_set(ni->ni_vap) &&
        (((ieee80211_vap_get_opmode(vap) == IEEE80211_M_HOSTAP) && (ic->ic_vhtcap)) ||
        ((ieee80211_vap_get_opmode(vap) == IEEE80211_M_STA) && (ni->ni_vhtcap)))) {
       switch(curr_phy_mode) {
          case IEEE80211_MODE_11NG_HT20:
             if(((ieee80211_vap_get_opmode(vap) == IEEE80211_M_HOSTAP) &&
                                 (vap->iv_ldpc == IEEE80211_HTCAP_C_LDPC_NONE)) ||
                      ((ieee80211_vap_get_opmode(vap) == IEEE80211_M_STA) &&
                        !((ni->ni_htcap & IEEE80211_HTCAP_C_ADVCODING) &&
                          (ni->ni_vhtcap & IEEE80211_VHTCAP_RX_LDPC)))) {
                 /*256QAM 2G BCC rateset */
                 /* array max_rates has been modified to add entries for 160 and 80+80, therefore entry for IEEE80211_MODE_11NG_HT20 2Ghz,
                    VHT20 BCC will come after IEEE80211_MODE_11AC_VHT80_80*/

                 curr_phy_mode = IEEE80211_MODE_11AC_VHT80_80 + 1;
             } else {
                   /*256 QAM 2G LDPC rateset */
                 curr_phy_mode = IEEE80211_MODE_11AC_VHT80_80 + 2;
             }
          break;
          case IEEE80211_MODE_11NG_HT40PLUS:
          case IEEE80211_MODE_11NG_HT40MINUS:
          case IEEE80211_MODE_11NG_HT40:
                /*256 QAM 2G */
             curr_phy_mode = IEEE80211_MODE_11AC_VHT80_80 + 3;
          break;
          default:
          break;
       }
    }

    if (nss > ieee80211_getstreams(ic, ic->ic_tx_chainmask)) {
        nss = ieee80211_getstreams(ic, ic->ic_tx_chainmask);
    }

    if(curr_phy_mode == IEEE80211_MODE_11AC_VHT160 || curr_phy_mode == IEEE80211_MODE_11AC_VHT80_80 ) {

	/* For cascade chipset , highest value used for nss is 2 . For future chipsets, nss 3 and 4 might
	   be used with bw 160 . There we need to be careful with the size of _s32 value(struct iw_param ).
	   This size is not enough for the rate values with nss 3 & 4 with 160 bw */

	u_int8_t nss_11ac_160 = 0;
	u_int32_t max_rate_11ac_vht160 = 0;
	u_int32_t max_rate_11ac_vht80 = 0;
	if ( scn->target_type == TARGET_TYPE_QCA9984 ){
            switch (ic->ic_tx_chainmask) {
                    case 5:    /* 0101 */
                    case 6:    /* 0110 */
#if ATH_SUPPORT_4SS
                    case 9:    /* 1001 */
                    case 0xa:  /* 1010 */
                    case 0xc:  /* 1100 */
#endif
                            nss_11ac_160 = 1;
                            break;
                    case 7:    /* 0111 */ /* As per FR FR32731 we permit chainmask
                                             0x7 for VHT160 and VHT80_80 mode */
                            nss_11ac_160 = 1;
                            break;
#if ATH_SUPPORT_4SS
                    case 0xf:
                            nss_11ac_160 = 2;
                            break;
#endif
                    default:
                            break;
            }

            if(nss_11ac_160 > nss)
                nss_11ac_160 = nss;

	}else if (scn->target_type == TARGET_TYPE_QCA9888){
	    if (nss > 1)
		nss = 1;
	}else{
	     qdf_assert_always(0);
	}

	if(nss_11ac_160) {
	    if(sgi) {
	            max_rate_11ac_vht160 = max_rates[curr_phy_mode][(nss_11ac_160 * 2) - 1];
	            max_rate_11ac_vht80 = max_rates[IEEE80211_MODE_11AC_VHT80][(nss * 2) - 1];
	    } else {
	            max_rate_11ac_vht160 = max_rates[curr_phy_mode][(nss_11ac_160 - 1) * 2];
	            max_rate_11ac_vht80 = max_rates[IEEE80211_MODE_11AC_VHT80][(nss - 1) * 2];
	    }
	    return max_rate_11ac_vht160 >= max_rate_11ac_vht80 ? max_rate_11ac_vht160 : max_rate_11ac_vht80;
	}
    }
    if (nss < 1) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: WARN: nss is; %d\n", __func__, nss);
        return 0;
    }

    if (sgi) {
        ratekbps = max_rates[curr_phy_mode][(nss * 2) - 1];
    } else {
        ratekbps = max_rates[curr_phy_mode][(nss - 1) * 2];
    }
   /*
    * Applicable only to the modes which will be using only legacy rates (max phy rate :54 mbps)
    * This is to display max phy bit rate. In 11g, if user will disable 54 Mbps rate then
    * the VAP will come up in the next highest rate available.
    */

    if (vap->iv_disabled_legacy_rate_set && (ratekbps <= 54000)) {
        ratekbps = (((ni->ni_rates.rs_rates[ni->ni_rates.rs_nrates -1] & IEEE80211_RATE_VAL) * 1000) / 2);
    }
    return ratekbps;
}

static int
ol_ath_node_add_wds_entry(struct ieee80211com *ic, const u_int8_t *dest_mac,
                          u_int8_t *peer_mac, u_int32_t flags)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct peer_add_wds_entry_params param;
    u_int8_t wmi_wds_flags = 0;

    qdf_mem_set(&param, sizeof(param), 0);
    if (flags & IEEE80211_NODE_F_WDS_HM) {
        wmi_wds_flags |= WMI_HOST_WDS_FLAG_STATIC;
    } else {
        /* Currently this interface is used only for host managed WDS entries */
        return -1;
    }

    param.dest_addr = dest_mac;
    param.peer_addr = peer_mac;
    param.flags = wmi_wds_flags;

    if (wmi_unified_peer_add_wds_entry_cmd_send(scn->wmi_handle, &param)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:Unable to add wds entry\n", __func__);
        return -1;
    }
    return 0;
}

static void
ol_ath_node_del_wds_entry(struct ieee80211com *ic, u_int8_t *dest_mac, u_int32_t flags)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct peer_del_wds_entry_params param;

    if (!(flags & IEEE80211_NODE_F_WDS_HM)) {
        /* Currently this interface is used only for host managed WDS entries */
        return;
    }

    qdf_mem_set(&param, sizeof(param), 0);
    param.dest_addr = dest_mac;

    if (wmi_unified_peer_del_wds_entry_cmd_send(scn->wmi_handle, &param)){
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:Unable to delete wds entry\n", __func__);
    }
}

#if ATH_SUPPORT_HYFI_ENHANCEMENTS
static int
ol_ath_node_update_wds_entry(struct ieee80211com *ic, u_int8_t *wds_macaddr, u_int8_t *peer_macaddr, u_int32_t flags)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct peer_update_wds_entry_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.flags = (flags & IEEE80211_NODE_F_WDS_HM);
    param.wds_macaddr = wds_macaddr;
    param.peer_macaddr = peer_macaddr;
    return wmi_unified_peer_update_wds_entry_cmd_send(scn->wmi_handle, &param);
}

int
ol_ath_node_ext_stats_enable(struct ieee80211_node *ni, u_int32_t enable)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(ni->ni_vap);
    int retval = 0;

    qdf_spin_lock_bh(&scn->scn_lock);
    if (enable && scn->peer_ext_stats_count >=
        scn->wlan_resource_config.max_peer_ext_stats) {
        qdf_spin_unlock_bh(&scn->scn_lock);
        return -ENOMEM;
    }

    if ((retval = ol_ath_node_set_param(scn, ni->ni_macaddr,
                WMI_HOST_PEER_EXT_STATS_ENABLE, enable, avn->av_if_id)) == 0) {
        if (enable) {
            scn->peer_ext_stats_count++;
        } else {
            scn->peer_ext_stats_count--;
        }
    }
    qdf_spin_unlock_bh(&scn->scn_lock);

    return retval;
}
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
static void ol_ath_node_collect_stats(struct ieee80211_node *ni)
{
    u_int32_t msdu_size, max_msdu_size;

    ni->ni_ald.ald_phyerr = ni->ni_vap->iv_ald->phyerr_rate;

	ni->ni_ald.ald_capacity = (OL_ATH_NODE_NET80211(ni))->an_tx_cnt ?
					((OL_ATH_NODE_NET80211(ni))->an_tx_rates_used/ (OL_ATH_NODE_NET80211(ni))->an_tx_cnt) : 0;

	if(ni->ni_ald.ald_capacity == 0)
		ni->ni_ald.ald_capacity = (OL_ATH_NODE_NET80211(ni))->an_ni_tx_rate/1000;


	if(!(OL_ATH_NODE_NET80211(ni))->an_tx_bytes || !ni->ni_ald.ald_txcount)
		msdu_size = ALD_MSDU_SIZE;
	else
		msdu_size = (OL_ATH_NODE_NET80211(ni))->an_tx_bytes/ni->ni_ald.ald_txcount;

	if (msdu_size < DEFAULT_MSDU_SIZE)
		ni->ni_ald.ald_msdusize = ALD_MSDU_SIZE;
	else
		ni->ni_ald.ald_msdusize = msdu_size;
	max_msdu_size = (msdu_size > ALD_MSDU_SIZE) ? msdu_size : ALD_MSDU_SIZE;
	if ((OL_ATH_NODE_NET80211(ni))->an_tx_ratecount > 0)
	    ni->ni_ald.ald_avgmax4msaggr = ni->ni_ald.ald_max4msframelen / ((OL_ATH_NODE_NET80211(ni))->an_tx_ratecount * max_msdu_size);

    if(ni->ni_ald.ald_avgmax4msaggr > 192)
	    ni->ni_ald.ald_avgmax4msaggr = 192;

	if(ni->ni_ald.ald_avgmax4msaggr > 0)
		ni->ni_ald.ald_aggr = ni->ni_ald.ald_avgmax4msaggr/2;
	else
		ni->ni_ald.ald_aggr = 96; //Max aggr 192/2

	/* Avg Aggr should be atleast 1 */
	ni->ni_ald.ald_aggr = ni->ni_ald.ald_aggr > 1 ? ni->ni_ald.ald_aggr : 1;

}
#endif
static void ol_ath_node_reset_ald_stats(struct ieee80211_node *ni)
{
	/* Do not reset ald_avgmax4msaggr and ald_aggr.
	 Past values are used when there is no traffic */
    (OL_ATH_NODE_NET80211(ni))->an_tx_cnt = 0;
    (OL_ATH_NODE_NET80211(ni))->an_tx_rates_used = 0;
    (OL_ATH_NODE_NET80211(ni))->an_tx_bytes = 0;
    (OL_ATH_NODE_NET80211(ni))->an_tx_ratecount = 0;
	ni->ni_ald.ald_txcount = 0;
	ni->ni_ald.ald_max4msframelen = 0;
	ni->ni_ald.ald_phyerr = 0;
	ni->ni_ald.ald_msdusize = 0;
	ni->ni_ald.ald_retries = 0;
	ni->ni_ald.ald_capacity = 0;
	ni->ni_ald.ald_lastper = 0;
	OS_MEMZERO(&ni->ni_ald.ald_ac_excretries, sizeof(ni->ni_ald.ald_ac_excretries));
	OS_MEMZERO(&ni->ni_ald.ald_ac_nobufs, sizeof(ni->ni_ald.ald_ac_nobufs));
	OS_MEMZERO(&ni->ni_ald.ald_ac_txpktcnt, sizeof(ni->ni_ald.ald_ac_txpktcnt));

}

static int
ol_ath_node_dump_wds_table(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    return wmi_unified_send_dump_wds_table_cmd(scn->wmi_handle);
}

static int
ol_ath_node_use_4addr(struct ieee80211_node *ni)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(ni->ni_vap);

    return ol_ath_node_set_param(scn, ni->ni_macaddr, WMI_HOST_PEER_USE_4ADDR, 1, avn->av_if_id);
}

#endif /* #if ATH_SUPPORT_HYFI_ENHANCEMENTS */

static void
ol_ath_node_authorize(struct ieee80211_node *ni, u_int32_t authorize)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(ni->ni_vap);

    qdf_spin_lock_bh(&scn->scn_lock);

    /* Authorize/unauthorize the peer */
    ol_txrx_peer_authorize((OL_ATH_NODE_NET80211(ni))->an_txrx_handle, authorize);

    qdf_spin_unlock_bh(&scn->scn_lock);

   /*FIXME Currently UMAC authorizes PAE on assoc and supplicant driver
    * interface fails to unauthorize before 4-way handshake and authorize
    * on completing 4-way handshake. WAR is to suppress authorizations
    * for all AUTH modes that need 4-way handshake and authorize on install
    * key cmd.
    * Need to check for WAPI case
    * safemode bypass the normal process
    */
#if MESH_MODE_SUPPORT
    if(!ni->ni_vap->iv_mesh_vap_mode) {
#endif
    if(authorize && (RSN_AUTH_IS_WPA(&ni->ni_rsn) ||
            RSN_AUTH_IS_WPA2(&ni->ni_rsn) ||
            RSN_AUTH_IS_8021X(&ni->ni_rsn)||
            RSN_AUTH_IS_WAI(&ni->ni_rsn)) && !IEEE80211_VAP_IS_SAFEMODE_ENABLED(ni->ni_vap)) {
       return;
    }
#if MESH_MODE_SUPPORT
    }
#endif

    if(ol_ath_node_set_param(scn,ni->ni_macaddr,WMI_HOST_PEER_AUTHORIZE,
            authorize,avn->av_if_id)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:Unable to authorize peer\n", __func__);
    }
}

void
ol_ath_node_update(struct ieee80211_node *ni)
{
}

static void
ol_ath_node_smps_update(
        struct ieee80211_node *ni,
        int smen,
        int dyn,
        int ratechg)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(ni->ni_vap);
    A_UINT32 value;

    if (smen) {
        value = WMI_HOST_PEER_MIMO_PS_NONE;
    } else if (dyn) {
        value = WMI_HOST_PEER_MIMO_PS_DYNAMIC;
    } else {
        value = WMI_HOST_PEER_MIMO_PS_STATIC;
    }

    (void)ol_ath_node_set_param(scn, ni->ni_macaddr,
            WMI_HOST_PEER_MIMO_PS_STATE, value, avn->av_if_id);
}


#if UMAC_SUPPORT_ADMCTL
static void
ol_ath_node_update_dyn_uapsd(struct ieee80211_node *ni, uint8_t ac, int8_t ac_delivery, int8_t ac_trigger)
{
	uint8_t i;
	uint8_t uapsd=0;
	struct ieee80211vap *vap = ni->ni_vap;

	if (ac_delivery <= WME_UAPSD_AC_MAX_VAL) {
		ni->ni_uapsd_dyn_delivena[ac] = ac_delivery;
	}

	if (ac_trigger <= WME_UAPSD_AC_MAX_VAL) {
		ni->ni_uapsd_dyn_trigena[ac] = ac_trigger;
	}
	for (i=0;i<WME_NUM_AC;i++) {
		if (ni->ni_uapsd_dyn_trigena[i] == -1) {
			if (ni->ni_uapsd_ac_trigena[i]) {
				uapsd |= WMI_HOST_UAPSD_AC_BIT_MASK(i,WMI_HOST_UAPSD_AC_TYPE_TRIG);
			}
		} else {
			if (ni->ni_uapsd_dyn_trigena[i]) {
				uapsd |= WMI_HOST_UAPSD_AC_BIT_MASK(i,WMI_HOST_UAPSD_AC_TYPE_TRIG);
			}
		}
	}

	for (i=0;i<WME_NUM_AC;i++) {
		if (ni->ni_uapsd_dyn_delivena[i] == -1) {
			if (ni->ni_uapsd_ac_delivena[i]) {
				uapsd |= WMI_HOST_UAPSD_AC_BIT_MASK(i,WMI_HOST_UAPSD_AC_TYPE_DELI);
			}
		} else {
			if (ni->ni_uapsd_dyn_delivena[i]) {
				uapsd |= WMI_HOST_UAPSD_AC_BIT_MASK(i,WMI_HOST_UAPSD_AC_TYPE_DELI);
			}
		}
	}

	(void)wmi_unified_set_ap_ps_param(OL_ATH_VAP_NET80211(vap),
             OL_ATH_NODE_NET80211(ni), WMI_HOST_AP_PS_PEER_PARAM_UAPSD, uapsd);
	return;
}
#endif /* UMAC_SUPPORT_ADMCTL */

static int
ol_peer_sta_ps_state_change_handler(ol_scn_t scn, u_int8_t *data, u_int16_t datalen)
{
    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211_node *ni;
    unsigned long diff_time;
    wmi_host_peer_sta_ps_statechange_event event;

    if(wmi_extract_peer_sta_ps_statechange_ev(scn->wmi_handle, data, &event)) {
        qdf_print("Failed to fetch peer PS state change\n");
        return -1;
    }
    ni = ieee80211_find_node(&ic->ic_sta, event.peer_macaddr);
    if (!ni) {
        return -1;
    }
    ni->ps_state = event.peer_ps_state;
    diff_time = qdf_get_system_timestamp() - ni->previous_ps_time;
    ni->previous_ps_time = diff_time;
    if (ni->ps_state == 0)
    {
        ni->ps_time += diff_time;
    }
    else if (ni->ps_state == 1)
    {
        ni->awake_time += diff_time;
    }
    ieee80211_free_node(ni);
    return 0;
}

#ifdef ATH_SUPPORT_QUICK_KICKOUT
int peer_sta_kickout(struct ol_ath_softc_net80211 *scn, A_UINT8 *peer_macaddr)
{
    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211_node *ni;
#if UMAC_SUPPORT_ACFG
    acfg_event_data_t *acfg_event = NULL;
#endif

    ni = ieee80211_find_node(&ic->ic_sta, peer_macaddr);
    if (!ni) {
        return -1;
    }
    ieee80211_kick_node(ni);
#if UMAC_SUPPORT_ACFG
    acfg_event = (acfg_event_data_t *)qdf_mem_malloc( sizeof(acfg_event_data_t));
    if (acfg_event == NULL){
        ieee80211_free_node(ni);
        return 0;
    }

    if(ni){
        memcpy(acfg_event->kick_node_mac, ni->ni_macaddr, IEEE80211_ADDR_LEN);
    }
    acfg_send_event(scn->sc_osdev->netdev, scn->sc_osdev, WL_EVENT_TYPE_QUICK_KICKOUT, acfg_event);
    qdf_mem_free(acfg_event);
#endif

    ieee80211_free_node(ni);

    return 0;
}
static int
ol_peer_sta_kickout_event_handler(ol_scn_t scn, u_int8_t *data, u_int16_t datalen)
{
    /*if ATH_SUPPORT_QUICK_KICKOUT defined, once got kickout event from fw,
     do kickout the node, and send acfg event up
    */

    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211_node *ni;
    wmi_host_peer_sta_kickout_event kickout_event;
#if UMAC_SUPPORT_ACFG
    acfg_event_data_t *acfg_event = NULL;
#endif

    if(wmi_extract_peer_sta_kickout_ev(scn->wmi_handle, data, &kickout_event)) {
        qdf_print("Unable to extract kickout ev\n");
        return -1;
    }

    ni = ieee80211_find_node(&ic->ic_sta, kickout_event.peer_macaddr);
    if (!ni) {
        return -1;
    }
    ieee80211_kick_node(ni);
#if UMAC_SUPPORT_ACFG
    acfg_event = (acfg_event_data_t *)qdf_mem_malloc( sizeof(acfg_event_data_t));
    if (acfg_event == NULL){
        ieee80211_free_node(ni);
        return 0;
    }

    if(ni){
        memcpy(acfg_event->kick_node_mac, ni->ni_macaddr, IEEE80211_ADDR_LEN);
    }
    acfg_send_event(scn->sc_osdev->netdev, scn->sc_osdev, WL_EVENT_TYPE_QUICK_KICKOUT, acfg_event);
    qdf_mem_free(acfg_event);
#endif

    ieee80211_free_node(ni);

    return 0;
}
#else
static int
ol_peer_sta_kickout_event_handler(ol_scn_t scn, u_int8_t *data, u_int16_t datalen)
{
    /*if ATH_SUPPORT_QUICK_KICKOUT not defined, once got kickout event from fw,
     send acfg event up, let upper layer to decide what to do.
    */
    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211_node *ni;
    wmi_host_peer_sta_kickout_event kickout_event;
#if UMAC_SUPPORT_ACFG
    acfg_event_data_t *acfg_event = NULL;
#endif

    if(wmi_extract_peer_sta_kickout_ev(scn->wmi_handle, data, &kickout_event)) {
        qdf_print("Unable to extract kickout ev\n");
        return -1;
    }

    ni = ieee80211_find_node(&ic->ic_sta, kickout_event.peer_macaddr);
    if (!ni) {
        return -1;
    }
#if UMAC_SUPPORT_ACFG
    acfg_event = (acfg_event_data_t *)qdf_mem_malloc( sizeof(acfg_event_data_t));
    if (acfg_event == NULL){
        ieee80211_free_node(ni);
        return 0;
    }

    if(ni){
        memcpy(acfg_event->kick_node_mac, ni->ni_macaddr, IEEE80211_ADDR_LEN);
    }
    acfg_send_event(scn->sc_osdev->netdev, scn->sc_osdev, WL_EVENT_TYPE_QUICK_KICKOUT, acfg_event);
    qdf_mem_free(acfg_event);
#endif

    ieee80211_free_node(ni);

    return 0;
}
#endif /* ATH_SUPPORT_QUICK_KICKOUT */

#if ATH_BAND_STEERING
static bool
ol_ath_node_is_inact(struct ieee80211_node *ni)
{
    return ol_txrx_peer_is_inact(OL_ATH_NODE_NET80211(ni)->an_txrx_handle);
}
#endif /* ATH_BAND_STEERING */

/* Intialization functions */
int
ol_ath_node_attach(struct ol_ath_softc_net80211 *scn, struct ieee80211com *ic)
{
    /* Register the umac callback functions */
    scn->net80211_node_free = ic->ic_node_free;
    scn->net80211_node_cleanup = ic->ic_node_cleanup;

    /* Register the node specific offload interface functions */
    ic->ic_node_alloc = ol_ath_node_alloc;
    ic->ic_node_free = ol_ath_node_free;
    ic->ic_node_cleanup = ol_ath_node_cleanup;
    ic->ic_node_getrssi = ol_ath_node_getrssi;
    ic->ic_node_getrate = ol_ath_node_getrate;
    ic->ic_node_psupdate = ol_ath_node_psupdate;
    ic->ic_get_maxphyrate = ol_ath_node_get_maxphyrate;
    ic->ic_node_add_wds_entry = ol_ath_node_add_wds_entry;
    ic->ic_node_del_wds_entry = ol_ath_node_del_wds_entry;
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
    ic->ic_node_update_wds_entry = ol_ath_node_update_wds_entry;
    ic->ic_node_ext_stats_enable = ol_ath_node_ext_stats_enable;
    ic->ic_reset_ald_stats = ol_ath_node_reset_ald_stats;
	ic->ic_collect_stats = ol_ath_node_collect_stats;
#endif
    ic->ic_node_authorize = ol_ath_node_authorize;
    ic->ic_sm_pwrsave_update = ol_ath_node_smps_update;
#if UMAC_SUPPORT_ADMCTL
    ic->ic_node_update_dyn_uapsd = ol_ath_node_update_dyn_uapsd;
#endif
#if ATH_BAND_STEERING
    ic->ic_node_isinact = ol_ath_node_is_inact;
#endif
#if QCA_AIRTIME_FAIRNESS
    ic->ic_node_getairtime = ol_ath_node_getairtime;
#endif
    ic->ic_node_get_last_txpower = ol_ath_node_get_last_txpower;
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
    ic->ic_node_dump_wds_table = ol_ath_node_dump_wds_table;
    ic->ic_node_use_4addr = ol_ath_node_use_4addr;
#endif
    /* register for STA kickout function */
    wmi_unified_register_event_handler(scn->wmi_handle, wmi_peer_sta_kickout_event_id,
            ol_peer_sta_kickout_event_handler, WMI_RX_UMAC_CTX);
    wmi_unified_register_event_handler(scn->wmi_handle, wmi_peer_sta_ps_statechg_event_id,
            ol_peer_sta_ps_state_change_handler, WMI_RX_UMAC_CTX);

    return 0;
}

void
ol_rx_err(
    ol_pdev_handle pdev,
    u_int8_t vdev_id,
    u_int8_t *peer_mac_addr,
    int tid,
    u_int32_t tsf32,
    enum ol_rx_err_type err_type,
    qdf_nbuf_t rx_frame)
{
    struct ieee80211_frame wh;
    struct ether_header *eh;
    struct ol_ath_softc_net80211 *scn ;
    struct ieee80211vap *vap;
    enum ieee80211_opmode opmode;
    A_BOOL notify = TRUE;

    eh = (struct ether_header *)qdf_nbuf_data(rx_frame);
    scn = (struct ol_ath_softc_net80211 *)pdev;
    vap = ol_ath_vap_get(scn, vdev_id);
    if(vap == NULL) {
       QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: vap is NULL \n", __func__);
       return;
    }
#ifdef QVIT
    if (vap == NULL)
    {
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "QVIT: Error %d\n", err_type);
       return;
    }
#endif

    opmode = ieee80211_vap_get_opmode(vap);

    if (err_type == OL_RX_ERR_TKIP_MIC) {
        /*TODO: Reconstructing the WLAN header for now from ether header
         * since WLAN header is not available for HL case.
         */
        wh.i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_DATA;
        wh.i_dur[0] = wh.i_dur[1] = 0;
        wh.i_seq[0] = wh.i_seq[1] = 0;

        qdf_mem_copy(&wh.i_addr1, &vap->iv_myaddr, IEEE80211_ADDR_LEN);
        qdf_mem_copy(&wh.i_addr2, peer_mac_addr, IEEE80211_ADDR_LEN);

        if (opmode == IEEE80211_M_HOSTAP || opmode == IEEE80211_M_WDS) {
            wh.i_fc[1] = IEEE80211_FC1_DIR_TODS;
            qdf_mem_copy(&wh.i_addr3, &eh->ether_dhost , IEEE80211_ADDR_LEN);
        } else if (opmode == IEEE80211_M_STA) {
            wh.i_fc[1] = IEEE80211_FC1_DIR_FROMDS;
            qdf_mem_copy(&wh.i_addr3, &eh->ether_shost , IEEE80211_ADDR_LEN);
        } else {
            /*TODO: Handle other cases*/
            notify = FALSE;
        }

        if (notify) {
            ieee80211_notify_michael_failure(vap,(const struct ieee80211_frame *)&wh,0);
        }
    }
}

int
ol_rx_notify(
    ol_pdev_handle pdev,
    u_int8_t vdev_id,
    u_int8_t *peer_mac_addr,
    int tid,
    u_int32_t tsf32,
    enum ol_rx_notify_type notify_type,
    qdf_nbuf_t rx_frame)
{
    struct ieee80211vap *vap = NULL;
    struct ieee80211_node *ni;
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)pdev;
	struct ieee80211com *ic;
    int discard = 0;
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
    int igmp_type = 0;
#endif
    vap = ol_ath_vap_get(scn, vdev_id);
    if(!vap) {
        return discard;
    }
    ic = vap->iv_ic;
    ni = ieee80211_vap_find_node(vap, peer_mac_addr);
    if(!ni) {
        return discard;
    }
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
    if ( vap->iv_ique_ops.me_inspect && vap->iv_me->me_hifi_enable == 0) {
        igmp_type = vap->iv_ique_ops.me_inspect(vap, ni, rx_frame);
    }

    if(igmp_type == IEEE80211_QUERY_FROM_STA && ic->ic_dropstaquery)
        discard = 1;
    if(igmp_type == IEEE80211_REPORT_FROM_STA && ic->ic_blkreportflood)
        discard = 1;
#else
    if ( vap->iv_ique_ops.me_inspect ) {
	       vap->iv_ique_ops.me_inspect(vap, ni, rx_frame);
    }
#endif
    /* remove extra node ref count added by find_node above */
    ieee80211_free_node(ni);
    return discard;
}

int
ol_rx_intrabss_fwd_check(
        ol_pdev_handle pdev,
        u_int8_t vdev_id,
        u_int8_t *peer_mac_addr)
{
    struct ieee80211vap *vap = NULL;
    struct ieee80211_node *ni;
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)pdev;
    struct ieee80211com *ic;
    int result = 0;

    vap = ol_ath_vap_get(scn, vdev_id);
    if(!vap) {
        return 0;
    }
    ic = vap->iv_ic;
    ni = ieee80211_vap_find_node(vap, peer_mac_addr);

    if(ni != NULL) {
        if (ni->ni_vap == vap &&
                ieee80211_node_is_authorized(ni) &&
                ni != vap->iv_bss)
        {
            result =1;
        }

    }
    else
        return 0;

    ieee80211_free_node(ni);

    return result;
}

#if ATH_MCAST_HOST_INSPECT
int ol_mcast_notify( ol_pdev_handle pdev,
        u_int8_t vdev_id, qdf_nbuf_t msdu )
{
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)pdev;
    struct ieee80211vap *vap = NULL;

    vap = ol_ath_vap_get(scn, vdev_id);

    /* TODO: take care of HYFI */
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
    if (vap->iv_me->me_hifi_enable && vap->iv_ique_ops.me_hifi_convert) {
        if (!vap->iv_ique_ops.me_hifi_convert(vap, msdu))
            return 1;
    } else
#endif
    {
        if (vap->iv_ique_ops.me_convert) {
            return vap->iv_ique_ops.me_convert(vap, msdu);
        }
    }
    return 0;
}
#endif /*ATH_MCAST_HOST_INSPECT*/
#endif
