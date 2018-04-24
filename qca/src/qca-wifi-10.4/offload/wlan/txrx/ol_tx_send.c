/*
 * Copyright (c) 2011-2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <qdf_atomic.h>   /* qdf_atomic_inc, etc. */
#include <qdf_lock.h>     /* qdf_spinlock */
#include <qdf_nbuf.h>        /* qdf_nbuf_t */
#include <net.h>
#include <queue.h>           /* TAILQ */

#include <cdp_txrx_cmn.h>     /* ol_txrx_vdev_handle, etc. */
#include <ol_htt_tx_api.h>   /* htt_tx_compl_desc_id */
#include <ol_txrx_htt_api.h> /* htt_tx_status */

#include <ol_txrx_types.h>   /* ol_txrx_vdev_t, etc */
#include <ol_tx_desc.h>      /* ol_tx_desc_find, ol_tx_desc_frame_free */
#include <ol_txrx_internal.h>
#include <ol_if_athvar.h>
#include <ol_rawmode_txrx_api.h> /* OL_RAW_TX_CHAINED_NBUF_UNMAP */

#include <ol_cfg.h>          /* ol_cfg_is_high_latency */
#if QCA_OL_TX_CACHEDHDR
#include "htt_internal.h"
#endif


#if QCA_PARTNER_DIRECTLINK_TX
#define QCA_PARTNER_DIRECTLINK_OL_TX_SEND 1
#include "ath_carr_pltfrm.h"
#undef QCA_PARTNER_DIRECTLINK_OL_TX_SEND
#endif /* QCA_PARTNER_DIRECTLINK_TX */

#if MESH_MODE_SUPPORT
#include "if_meta_hdr.h"
#endif

void
ol_tx_send(
    struct ol_txrx_vdev_t *vdev,
    struct ol_tx_desc_t *tx_desc,
    qdf_nbuf_t msdu)
{
    struct ol_txrx_pdev_t *pdev = vdev->pdev;
    u_int16_t id;

    qdf_atomic_dec(&pdev->target_tx_credit);

    /*
     * When the tx frame is downloaded to the target, there are two
     * outstanding references:
     * 1.  The host download SW (HTT, HTC, HIF)
     *     This reference is cleared by the ol_tx_send_done callback
     *     functions.
     * 2.  The target FW
     *     This reference is cleared by the ol_tx_completion_handler
     *     function.
     * It is extremely probable that the download completion is processed
     * before the tx completion message.  However, under exceptional
     * conditions the tx completion may be processed first.  Thus, rather
     * that assuming that reference (1) is done before reference (2),
     * explicit reference tracking is needed.
     * Double-increment the ref count to account for both references
     * described above.
     */

#if !ATH_11AC_TXCOMPACT
    qdf_atomic_init(&tx_desc->ref_cnt);
    qdf_atomic_inc(&tx_desc->ref_cnt);
    qdf_atomic_inc(&tx_desc->ref_cnt);
#endif

    id = ol_tx_desc_id(pdev, tx_desc);
    if (htt_tx_send_std(pdev->htt_pdev, tx_desc->htt_tx_desc, msdu, id)) {
/* TBD:
 * Would it be better to just free the descriptor, and return the netbuf
 * to the OS shim, rather than freeing both the descriptor and the
 * netbuf here?
 */
        qdf_atomic_inc(&pdev->target_tx_credit);
        ol_tx_desc_frame_free_nonstd(pdev, tx_desc, 1 /* had error */);
    }
}

static inline void
ol_tx_download_done_base(
    struct ol_txrx_pdev_t *pdev,
    A_STATUS status,
    qdf_nbuf_t msdu,
    u_int16_t msdu_id)
{
    struct ol_tx_desc_t *tx_desc;

    tx_desc = ol_tx_desc_find(pdev, msdu_id);
    qdf_assert(tx_desc);
    if (status != A_OK) {
        ol_tx_desc_frame_free_nonstd(pdev, tx_desc, 1 /* download err */);
    } else {
#if !ATH_11AC_TXCOMPACT
        if (qdf_atomic_dec_and_test(&tx_desc->ref_cnt))
#endif
        {
            /*
             * The decremented value was zero - free the frame.
             * Use the tx status recorded previously during
             * tx completion handling.
             */
            ol_tx_desc_frame_free_nonstd(
                pdev, tx_desc, tx_desc->status != htt_tx_status_ok);
        }
    }
}

void
ol_tx_download_done_ll(
    void *pdev,
    A_STATUS status,
    qdf_nbuf_t msdu,
    u_int16_t msdu_id)
{
    ol_tx_download_done_base(
        (struct ol_txrx_pdev_t *) pdev, status, msdu, msdu_id);
}

void
ol_tx_download_done_hl_retain(
    void *txrx_pdev,
    A_STATUS status,
    qdf_nbuf_t msdu,
    u_int16_t msdu_id)
{
    struct ol_txrx_pdev_t *pdev = txrx_pdev;
    ol_tx_download_done_base(pdev, status, msdu, msdu_id);
#if 0 /* TODO: Advanced feature */
    //ol_tx_dwl_sched(pdev, OL_TX_HL_SCHED_DOWNLOAD_DONE);
qdf_assert(0);
#endif
}

void
ol_tx_download_done_hl_free(
    void *txrx_pdev,
    A_STATUS status,
    qdf_nbuf_t msdu,
    u_int16_t msdu_id)
{
    struct ol_txrx_pdev_t *pdev = txrx_pdev;
    struct ol_tx_desc_t *tx_desc;

    tx_desc = ol_tx_desc_find(pdev, msdu_id);
    qdf_assert(tx_desc);
    ol_tx_desc_frame_free_nonstd(pdev, tx_desc, status != A_OK);
#if 0 /* TODO: Advanced feature */
    //ol_tx_dwl_sched(pdev, OL_TX_HL_SCHED_DOWNLOAD_DONE);
qdf_assert(0);
#endif
}

/*
 * The following macros could have been inline functions too.
 * The only rationale for choosing macros, is to force the compiler to inline
 * the implementation, which cannot be controlled for actual "inline" functions,
 * since "inline" is only a hint to the compiler.
 * In the performance path, we choose to force the inlining, in preference to
 * type-checking offered by the actual inlined functions.
 */
#define ol_tx_msdu_complete_batch(_pdev, _tx_desc, _tx_descs, _status)                         \
        do {                                                                                    \
                TAILQ_INSERT_TAIL(&(_tx_descs), (_tx_desc), tx_desc_list_elem);                 \
        } while (0)
#if !ATH_11AC_TXCOMPACT
#if MESH_MODE_SUPPORT
#define ol_tx_msdu_complete_single(_pdev, _tx_desc, _netbuf, _lcl_freelist, _tx_desc_last)      \
        do {                                                                                    \
                qdf_atomic_init(&(_tx_desc)->ref_cnt); /* clear the ref cnt */                  \
                qdf_nbuf_unmap((_pdev)->osdev, (_netbuf), QDF_DMA_TO_DEVICE);                   \
                if ((_pdev->tx_cap_hdr) && (_pdev->htt_pdev->htt_process_tx_data_frames)) {     \
                    (_pdev->htt_pdev->htt_process_tx_data_frames) ((_netbuf));                  \
                } else if (tx_desc->extnd_desc) {                                               \
                    os_if_tx_free_ext((_netbuf));                                               \
                } else {                                                                        \
                    qdf_nbuf_free((_netbuf));                                                   \
                }                                                                               \
                _tx_desc->allocated = 0;                                                        \
                ((union ol_tx_desc_list_elem_t *)(_tx_desc))->next = (_lcl_freelist);           \
                if (qdf_unlikely(!lcl_freelist)) {                                              \
                    (_tx_desc_last) = (union ol_tx_desc_list_elem_t *)(_tx_desc);               \
                }                                                                               \
                (_lcl_freelist) = (union ol_tx_desc_list_elem_t *)(_tx_desc);                   \
        } while (0)
#else
#define ol_tx_msdu_complete_single(_pdev, _tx_desc, _netbuf, _lcl_freelist, _tx_desc_last)      \
        do {                                                                                    \
                qdf_atomic_init(&(_tx_desc)->ref_cnt); /* clear the ref cnt */                  \
                qdf_nbuf_unmap((_pdev)->osdev, (_netbuf), QDF_DMA_TO_DEVICE);                   \
                if ((_pdev->tx_cap_hdr) && (_pdev->htt_pdev->htt_process_tx_data_frames)) {     \
                    (_pdev->htt_pdev->htt_process_tx_data_frames) ((_netbuf));                  \
                } else {                                                                        \
                    qdf_nbuf_free((_netbuf));                                                   \
                }                                                                               \
                _tx_desc->allocated = 0;                                                        \
                ((union ol_tx_desc_list_elem_t *)(_tx_desc))->next = (_lcl_freelist);           \
                if (qdf_unlikely(!lcl_freelist)) {                                              \
                    (_tx_desc_last) = (union ol_tx_desc_list_elem_t *)(_tx_desc);               \
                }                                                                               \
                (_lcl_freelist) = (union ol_tx_desc_list_elem_t *)(_tx_desc);                   \
        } while (0)
#endif
#else  /*!ATH_11AC_TXCOMPACT*/

#if MESH_MODE_SUPPORT
#define ol_tx_msdu_complete_single(_pdev, _tx_desc, _netbuf, _lcl_freelist, _tx_desc_last)      \
        do {                                                                                    \
                qdf_nbuf_unmap((_pdev)->osdev, (_netbuf), QDF_DMA_TO_DEVICE);                   \
                if ((_pdev->tx_cap_hdr) && (_pdev->htt_pdev->htt_process_tx_data_frames)) {     \
                    (_pdev->htt_pdev->htt_process_tx_data_frames) ((_netbuf));                  \
                } else if (tx_desc->extnd_desc) {                                               \
                    os_if_tx_free_ext((_netbuf));                                               \
                } else {                                                                        \
                    qdf_nbuf_free((_netbuf));                                                   \
                }                                                                               \
                _tx_desc->allocated = 0;                                                        \
                ((union ol_tx_desc_list_elem_t *)(_tx_desc))->next = (_lcl_freelist);           \
                if (qdf_unlikely(!lcl_freelist)) {                                              \
                    (_tx_desc_last) = (union ol_tx_desc_list_elem_t *)(_tx_desc);               \
                }                                                                               \
                (_lcl_freelist) = (union ol_tx_desc_list_elem_t *)(_tx_desc);                   \
        } while (0)
#else
#define ol_tx_msdu_complete_single(_pdev, _tx_desc, _netbuf, _lcl_freelist, _tx_desc_last)      \
        do {                                                                                    \
                qdf_nbuf_unmap((_pdev)->osdev, (_netbuf), QDF_DMA_TO_DEVICE);                   \
                if ((_pdev->tx_cap_hdr) && (_pdev->htt_pdev->htt_process_tx_data_frames)) {     \
                    (_pdev->htt_pdev->htt_process_tx_data_frames) ((_netbuf));                  \
                } else {                                                                        \
                    qdf_nbuf_free((_netbuf));                                                   \
                }                                                                               \
                _tx_desc->allocated = 0;                                                        \
                ((union ol_tx_desc_list_elem_t *)(_tx_desc))->next = (_lcl_freelist);           \
                if (qdf_unlikely(!lcl_freelist)) {                                              \
                    (_tx_desc_last) = (union ol_tx_desc_list_elem_t *)(_tx_desc);               \
                }                                                                               \
                (_lcl_freelist) = (union ol_tx_desc_list_elem_t *)(_tx_desc);                   \
        } while (0)

#endif

#endif /*!ATH_11AC_TXCOMPACT*/

#if QCA_TX_SINGLE_COMPLETIONS
    #if QCA_TX_STD_PATH_ONLY
        #define ol_tx_msdu_complete(_pdev, _tx_desc, _tx_descs, _netbuf, _lcl_freelist,         \
                                        _tx_desc_last, _status, _num_htt_cmpls)                 \
            ol_tx_msdu_complete_single((_pdev), (_tx_desc), (_netbuf), (_lcl_freelist),         \
                                             _tx_desc_last)
    #else   /* !QCA_TX_STD_PATH_ONLY */
        #define ol_tx_msdu_complete(_pdev, _tx_desc, _tx_descs, _netbuf, _lcl_freelist,         \
                                        _tx_desc_last, _status, _num_htt_cmpls)                 \
        do {                                                                                    \
            if (qdf_likely((_tx_desc)->pkt_type == ol_tx_frm_std)) {                         \
                ol_tx_msdu_complete_single((_pdev), (_tx_desc), (_netbuf), (_lcl_freelist),     \
                                             (_tx_desc_last));                                  \
            } else {                                                                            \
                (_num_htt_cmpls) = (_num_htt_cmpls) + 1;                                        \
                ol_tx_desc_frame_free_nonstd(                                                   \
                    (_pdev), (_tx_desc), (_status) != htt_tx_status_ok);                        \
            }                                                                                   \
        } while (0)
    #endif  /* !QCA_TX_STD_PATH_ONLY */
#else  /* !QCA_TX_SINGLE_COMPLETIONS */
    #if (QCA_TX_STD_PATH_ONLY)
        #define ol_tx_msdu_complete(_pdev, _tx_desc, _tx_descs, _netbuf, _lcl_freelist,         \
                                        _tx_desc_last, _status, _num_htt_cmpls)                 \
            ol_tx_msdus_complete_batch((_pdev), (_tx_desc), (_tx_descs), (_status))
    #else   /* !QCA_TX_STD_PATH_ONLY */
        #define ol_tx_msdu_complete(_pdev, _tx_desc, _tx_descs, _netbuf, _lcl_freelist,         \
                                        _tx_desc_last, _status, _num_htt_cmpls)                 \
        do {                                                                                    \
            if (qdf_likely((_tx_desc)->pkt_type == ol_tx_frm_std)) {                         \
                ol_tx_msdu_complete_batch((_pdev), (_tx_desc), (_tx_descs), (_status));         \
            } else {                                                                            \
                (_num_htt_cmpls) = (_num_htt_cmpls) + 1;                                        \
                ol_tx_desc_frame_free_nonstd(                                                   \
                    (_pdev), (_tx_desc), (_status) != htt_tx_status_ok);                        \
            }                                                                                   \
        } while (0)
    #endif  /* !QCA_TX_STD_PATH_ONLY */
#endif /* QCA_TX_SINGLE_COMPLETIONS */

#if ATH_DATA_TX_INFO_EN
static void print_bitmap(struct ieee80211com *ic, uint64_t bitmap_value)
{

    uint64_t mask = UNSIGNED_LONG_LONG_ONE << ((sizeof(uint64_t)) * BITS_PER_BYTE - 1);
    uint8_t index = 0;

    while (mask) {
        if ( index++ % 4 == 0) {
            IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_ANY, " ");
        }
        IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_ANY, "%u", (bitmap_value & mask) ? 1 : 0);
        mask >>= 1;
    }
}

static void tx_info_dump(struct ieee80211com *ic, struct ieee80211_tx_status *ts, uint8_t *dest_addr)
{
    struct net_device *n_dev = ic->ic_osdev->netdev;

    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "==radio=%s, STA=%s\n", n_dev->name, ether_sprintf((const uint8_t *)dest_addr));
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "==ts->ppdu_rate=0x%x preamble=%d, nss=%d, mcs=%d \n",ts->ppdu_rate,
                    HTT_GET_HW_RATECODE_PREAM(ts->ppdu_rate),
                    HTT_GET_HW_RATECODE_NSS(ts->ppdu_rate),
                    HTT_GET_HW_RATECODE_RATE(ts->ppdu_rate));
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "==ts->ppdu_num_mpdus_success=0x%x\n",ts->ppdu_num_mpdus_success);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "==ts->ppdu_num_mpdus_fail=0x%x\n",ts->ppdu_num_mpdus_fail);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "==ts->ppdu_num_msdus_success=0x%x\n",ts->ppdu_num_msdus_success);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "==ts->ppdu_bytes_success=0x%x\n",ts->ppdu_bytes_success);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "==ts->ppdu_duration=0x%x\n",ts->ppdu_duration);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "==ts->ppdu_retries=0x%x\n",ts->ppdu_retries);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "==ts->ppdu_is_aggregate=0x%x\n",ts->ppdu_is_aggregate);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "==ts->ts_flags=0x%x\n",ts->ts_flags);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "==ts->msdu_length=%d\n",ts->msdu_length);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "==ts->msdu_priority=%d\n",ts->msdu_priority);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "==ts->ch_width=%d\n",ts->ch_width);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "==ts->msdu_q_time=%d ms\n",(int)(ts->msdu_q_time));
    if (ts->version == PPDU_STATS_VERSION_3) {
        IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_ANY, "==ts->ppdu_ack_timestamp=%u usec\n", ts->ppdu_ack_timestamp);
        IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_ANY, "==ts->starting seq_number=%u\n", ts->start_seq_num);
        IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_ANY, "Bitmap of packets enqued to HW, sent OTA and packets failed (%d...%d)\n",ts->start_seq_num + 63,ts->start_seq_num);
        IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_ANY, "==ts->ppdu_bitmap_enqueued\n");
        print_bitmap(ic, ts->ppdu_bmap_enqueued_hi);
        print_bitmap(ic, ts->ppdu_bmap_enqueued_lo);
        IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_ANY, "\n==ts->ppdu_bitmap_tried\n");
        print_bitmap(ic, ts->ppdu_bmap_tried_hi);
        print_bitmap(ic, ts->ppdu_bmap_tried_lo);
        IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_ANY, "\n==ts->ppdu_bitmap_failed\n");
        print_bitmap(ic, ts->ppdu_bmap_failed_hi);
        print_bitmap(ic, ts->ppdu_bmap_failed_lo);
    }
}

void populate_tx_info(struct ol_ath_softc_net80211 *scn, qdf_nbuf_t  netbuf,  int i, int num_msdus, enum htt_tx_status status, struct ieee80211_tx_status  *ts, uint8_t mhdr_len, bool is_raw)
{
    struct ieee80211com *ic = &(scn->sc_ic);
    struct ethhdr * eh = NULL;
    uint64_t tx_submit_time;
    uint64_t current_time;
    int is_mcast;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    struct ol_txrx_pdev_t *pdev = NULL;
#endif
    struct ieee80211_frame *mac_hdr = NULL;
    uint8_t *dest_addr = NULL;

/* Access MAC header at offset of mhdr_len since we expect meta header
 * of size mhdr_len incase of mesh vap mode.
 */
    if (is_raw){
    mac_hdr = (struct ieee80211_frame *)(netbuf->data + mhdr_len);
    dest_addr = mac_hdr->i_addr1;
    } else {
    eh = (struct ethhdr *)(netbuf->data + mhdr_len);
    dest_addr = eh->h_dest;
    }

    is_mcast = (IS_MULTICAST(dest_addr)) ? 1 : 0;

    if (qdf_likely(!is_mcast)) {
        if (qdf_likely(status == htt_tx_status_ok)){
            ts->ts_flags |= IEEE80211_TX_SUCCESS;
        } else if(status == htt_tx_status_discard) {
            ts->ts_flags |= IEEE80211_TX_DROP;
        } else if(status == htt_tx_status_no_ack) {
            ts->ts_flags |= IEEE80211_TX_XRETRY;
        } else {
            ts->ts_flags |= IEEE80211_TX_ERROR;
        }
        ts->msdu_length = qdf_nbuf_len(netbuf);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        pdev = (struct ol_txrx_pdev_t *) scn->pdev_txrx_handle;
        if (pdev && pdev->nss_wifiol_ctx) {
            ts->msdu_q_time = QDF_NBUF_CB_TX_SUBMIT_TS(netbuf);
        } else
#endif
        {
            tx_submit_time = QDF_NBUF_CB_TX_SUBMIT_TS(netbuf);
            current_time = OS_GET_TIMESTAMP();
            if (qdf_likely((tx_submit_time != 0) && (current_time > tx_submit_time))){
                ts->msdu_q_time = jiffies_to_msecs(current_time - tx_submit_time);
            }
        }

        ts->msdu_priority = qdf_nbuf_get_priority(netbuf);
        ts->ch_width = ic->ic_cwm_get_width(ic);
        if (i == 0){
            ts->ts_flags |= IEEE80211_TX_FIRST_MSDU;
        }
        if (i == (num_msdus-1)) {
            ts->ts_flags |= IEEE80211_TX_LAST_MSDU;
        }

        /* replace tx_info_dump() with callback here */
        tx_info_dump(ic, ts, dest_addr);

        /*reset the tx info*/
        ts->ts_flags = 0;
    }
}
#endif  /*end of ATH_DATA_TX_INFO_EN*/

/* WARNING: ol_tx_inspect_handler()'s bahavior is similar to that of ol_tx_completion_handler().
 * any change in ol_tx_completion_handler() must be mirrored in ol_tx_inspect_handler().
 */
void
ol_tx_completion_handler(
    ol_txrx_pdev_handle pdev,
    int num_msdus,
    enum htt_tx_status status,
    int ack_rssi_filled,
    int ppdu_peer_id_filled,
    void *tx_desc_id_iterator,
    int *num_htt_compl)
{
    int i;
    u_int16_t *desc_ids = (u_int16_t *)tx_desc_id_iterator;
    u_int16_t *ack_rssi = desc_ids;
    u_int16_t *ppdu_peer_id_ptr = ack_rssi;
    uint8_t mhdr_len = 0;
    u_int16_t tx_desc_id, ppdu_id = 0, peer_id = 0;
    struct ol_tx_desc_t *tx_desc;
    struct ol_ath_softc_net80211 *scn =
                            (struct ol_ath_softc_net80211 *)pdev->ctrl_pdev;
    uint32_t   byte_cnt = 0;
    union ol_tx_desc_list_elem_t *td_array = pdev->tx_desc.array;
    qdf_nbuf_t  netbuf;

    union ol_tx_desc_list_elem_t *lcl_freelist = NULL;
    union ol_tx_desc_list_elem_t *tx_desc_last = NULL;
    ol_tx_desc_list tx_descs;
    uint32_t bcastcnt=0;
    struct ieee80211_mac_stats *mac_stats;
    struct ieee80211vap *vap = NULL;
    struct ethhdr * eh;
    struct ol_txrx_peer_t *peer = NULL;
    struct ol_txrx_peer_t *txcap_peer = NULL;
#if ATH_DATA_TX_INFO_EN || QCA_OL_TX_CACHEDHDR
    struct ol_txrx_vdev_t *vdev = NULL;
#endif
    bool is_raw = false;

    TAILQ_INIT(&tx_descs);

#if MESH_MODE_SUPPORT
    if (ack_rssi_filled) {
        ack_rssi += num_msdus;
        if(num_msdus & 1) {
            ack_rssi++;
        }
        /*
         * If ack_rssi is filled, ppdu_id follows it
         */
        ppdu_peer_id_ptr = ack_rssi;
    }
#endif

    if (ppdu_peer_id_filled) {
        ppdu_peer_id_ptr += num_msdus;

        /*
         * MSDU'id is 16-bits and the data filled by
         * f/w is 32-bit alligned.
         */
        if(num_msdus & 1) {
            ppdu_peer_id_ptr++;
        }
        ppdu_id = *ppdu_peer_id_ptr;
        peer_id = *(ppdu_peer_id_ptr + 1);
    }

    peer = (pdev->tx_stats.peer_id == HTT_INVALID_PEER) ?
            NULL : pdev->peer_id_to_obj_map[pdev->tx_stats.peer_id];

    if (qdf_likely(peer)) {
        vap = ol_ath_vap_get(scn, peer->vdev->vdev_id);
    }

    if (qdf_likely(vap)) {
      mhdr_len = vap->mhdr_len;
    }

    for (i = 0; i < num_msdus; i++) {
        tx_desc_id = desc_ids[i];
        tx_desc = &td_array[tx_desc_id].tx_desc;
        tx_desc->status = status;
        netbuf = tx_desc->netbuf;

        if (!tx_desc->allocated) {
           QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: MSDU is not allocated  MSDU ID is %d \n", __func__, tx_desc_id);
           continue;
        }
#if MESH_MODE_SUPPORT
        if (ack_rssi_filled && tx_desc->extnd_desc) {
            struct meta_hdr_s *mhdr;
            struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)pdev->ctrl_pdev;
            struct ieee80211com *ic = &scn->sc_ic;

            u_int8_t mhdr_pos = 0;
            if (tx_desc->extnd_desc == ext_desc_fp) {
                qdf_nbuf_push_head(netbuf, sizeof(struct meta_hdr_s));
            } else {
                mhdr_pos = ((HTC_HTT_TRANSFER_HDRSIZE + HTT_EXTND_DESC_SIZE) > sizeof(struct meta_hdr_s)) ?
                    ((HTC_HTT_TRANSFER_HDRSIZE + HTT_EXTND_DESC_SIZE) - sizeof(struct meta_hdr_s)) : 0;
                qdf_nbuf_pull_head(netbuf,mhdr_pos);
            }

            mhdr = (struct meta_hdr_s *)qdf_nbuf_data(netbuf);
            mhdr->rssi = ack_rssi[i];
            mhdr->channel = ol_ath_mhz2ieee(ic, pdev->rx_mon_recv_status->rs_freq, 0);
        }
#endif

    /* Remove htc_htt header incase of non-mesh mode, so that MAC header can be
     * accessed at offset zero.
     * Meta header of size mhdr_len is expected before MAC header in case of mesh
     * vap mode, so do not do anything incase of mesh vap.
     */
#if QCA_OL_TX_CACHEDHDR
    if (qdf_likely(peer)) {
        vdev = peer->vdev;
        if (!mhdr_len) {
             HTT_REMOVE_CACHED_HDR(netbuf, vdev->htc_htt_hdr_size);
        }
    }
#endif
        /* Per SDU update of byte count */
        byte_cnt += qdf_nbuf_len(netbuf);
        if (scn->scn_stats.ap_stats_tx_cal_enable) {
            if (tx_desc->tx_encap_type == htt_pkt_type_ethernet) {
                eh = (struct ethhdr *)(netbuf->data + mhdr_len);
                if (IEEE80211_IS_BROADCAST(eh->h_dest))
                    bcastcnt++;
            }
        }
#if !WLAN_FEATURE_FASTPATH && !ATH_11AC_TXCOMPACT
        if (qdf_os_atomic_dec_and_test(&tx_desc->ref_cnt))
#endif /* WLAN_FEATURE_FASTPATH */
        {
            if (OL_CFG_RAW_TX_LIKELINESS(tx_desc->tx_encap_type ==
                        htt_pkt_type_raw)) {
                is_raw = true;
                if (qdf_nbuf_next(netbuf) != NULL) {
                    OL_RAW_TX_CHAINED_NBUF_UNMAP(pdev, netbuf);
                }
            }

#if ATH_DATA_TX_INFO_EN
            if(scn->enable_perpkt_txstats) {
                populate_tx_info(scn, netbuf, i, num_msdus, status, scn->tx_status_buf, mhdr_len, is_raw);
            }
#endif
            if (ppdu_peer_id_filled) {
                /*
                 * Time to push the tx capture hdr.
                 * In case of non-mesh, the cached_hdr has been already removed.
                 * For mesh, we will add it before the mesh meta-hdr.
                 */
                struct tx_capture_hdr *tcaphdr;
                uint8_t *newdata_ptr;

                eh = (struct ethhdr *)(netbuf->data + mhdr_len);
                newdata_ptr = qdf_nbuf_push_head(netbuf,sizeof(struct tx_capture_hdr));
                if (newdata_ptr) {
                    tcaphdr = (struct tx_capture_hdr *)qdf_nbuf_data(netbuf);
                    qdf_mem_copy(tcaphdr->ta, (eh->h_dest), IEEE80211_ADDR_LEN);
                    tcaphdr->ppdu_id = *ppdu_peer_id_ptr;
                    txcap_peer = pdev->peer_id_to_obj_map[peer_id];
                    qdf_mem_copy(tcaphdr->ra, peer->mac_addr.raw, IEEE80211_ADDR_LEN);
                    pdev->tx_cap_hdr = 1;
                }
            }
            ol_tx_msdu_complete(pdev, tx_desc, tx_descs, netbuf, lcl_freelist,
                                    tx_desc_last, status, *num_htt_compl);
        }
    }

    if (scn->scn_stats.ap_stats_tx_cal_enable) {
        switch (status) {
        case htt_tx_status_ok:
            if (peer) {
            /* TODO: Right now the data packets and bytes are not truly
            *  the success packets and bytes the host driver assumes that
            *  the Firmware gave the successful packets count, on that assumption
            *  I am incrementing the counter. Inorder to have a correct
            *  count on the number of packets sent there has to be some
            *  code modification in the Firmware therefore,"TODO".
            */
                peer->peer_data_stats.data_packets = num_msdus;
                peer->peer_data_stats.data_bytes = byte_cnt;
                peer->peer_data_stats.thrup_bytes = byte_cnt;
                vap = ol_ath_vap_get(scn, peer->vdev->vdev_id);
                if (qdf_likely(vap != NULL)) {
                    mac_stats =&vap->iv_multicast_stats;
                    mac_stats->ims_tx_bcast_data_packets += bcastcnt;
                }
            }
            pdev->tx_stats.peer_id = HTT_INVALID_PEER;
            break;
        case htt_tx_status_discard:
            if (peer) {
                peer->peer_data_stats.discard_cnt = num_msdus;
            }
            break;
        default:
            break;
        }
    }
    /* One shot protected access to pdev freelist, when setup */
    if (lcl_freelist) {
        OL_TX_DESC_LOCK(&pdev->tx_mutex);
        tx_desc_last->next = pdev->tx_desc.freelist;
        pdev->tx_desc.freelist = lcl_freelist;
#if PEER_FLOW_CONTROL
        pdev->pflow_ctl_desc_count--;
#endif
        OL_TX_DESC_UNLOCK(&pdev->tx_mutex);
        TXRX_STATS_SUB(pdev, pub.tx.desc_in_use, num_msdus);
    } else {
        ol_tx_desc_frame_list_free(pdev, &tx_descs, status != htt_tx_status_ok);
    }

    qdf_atomic_add(num_msdus, &pdev->target_tx_credit);

#if OL_ATH_SUPPORT_LED
    {
        struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)pdev->ctrl_pdev;
        scn->scn_led_byte_cnt += byte_cnt;
        ol_ath_led_event(scn, OL_ATH_LED_TX);
    }
#endif

    /* Do one shot statistics */
    TXRX_STATS_UPDATE_TX_STATS(pdev, status, num_msdus, byte_cnt);
}

/* WARNING: ol_tx_inspect_handler()'s bahavior is similar to that of
 * ol_tx_completion_handler(). any change in ol_tx_completion_handler() must be
 * mirrored here.
 */
void
ol_tx_inspect_handler(
    ol_txrx_pdev_handle pdev,
    int num_msdus,
    void *tx_desc_id_iterator)
{
    u_int16_t vdev_id, i;
    struct ol_txrx_vdev_t *vdev;
    u_int16_t *desc_ids = (u_int16_t *)tx_desc_id_iterator;
    u_int16_t tx_desc_id;
    struct ol_tx_desc_t *tx_desc;
    union ol_tx_desc_list_elem_t *td_array = pdev->tx_desc.array;
    union ol_tx_desc_list_elem_t *lcl_freelist = NULL;
    union ol_tx_desc_list_elem_t *tx_desc_last = NULL;
    qdf_nbuf_t  netbuf;
#if OL_ATH_SUPPORT_LED
    uint32_t   byte_cnt = 0;
#endif
    ol_tx_desc_list tx_descs;
    TAILQ_INIT(&tx_descs);

    for (i = 0; i < num_msdus; i++) {
        tx_desc_id = desc_ids[i];
        tx_desc = &td_array[tx_desc_id].tx_desc;
        netbuf = tx_desc->netbuf;

        if(!tx_desc->allocated)  {
           QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: MSDU is not allocated  MSDU ID is %d \n", __func__, tx_desc_id);
           continue;
        }

#if OL_ATH_SUPPORT_LED
        byte_cnt += qdf_nbuf_len(netbuf);
#endif

        /* find the "vdev" this tx_desc belongs to */
#if !QCA_OL_TX_CACHEDHDR
        vdev_id = HTT_TX_DESC_VDEV_ID_GET(*((u_int32_t *)(tx_desc->htt_tx_desc)));
#else
        qdf_nbuf_unmap((pdev)->osdev, (netbuf), QDF_DMA_TO_DEVICE);
        vdev_id = htt_data_get_vdev_id(netbuf->data);
#endif
        TAILQ_FOREACH(vdev, &pdev->vdev_list, vdev_list_elem) {
            if (vdev->vdev_id == vdev_id)
                break;
        }
#if QCA_OL_TX_CACHEDHDR
        HTT_REMOVE_CACHED_HDR(netbuf,vdev->htc_htt_hdr_size);
#endif

        /* vdev now points to the vdev for this descriptor. */

#if UMAC_SUPPORT_PROXY_ARP || UMAC_SUPPORT_NAWDS || WDS_VENDOR_EXTENSION
        {
            struct ol_txrx_peer_t *peer;
            qdf_nbuf_t  netbuf_copy;
            int is_mcast = 0, is_ucast = 0;
            struct ether_header *eth_hdr = (struct ether_header *)(qdf_nbuf_data(netbuf));
            struct ieee80211_frame_addr4 *wh = (struct ieee80211_frame_addr4 *)(qdf_nbuf_data(netbuf));
#if WDS_VENDOR_EXTENSION
	    int num_peers_3addr = 0;
#endif

            if (OL_CFG_RAW_RX_LIKELINESS(vdev->tx_encap_type == htt_pkt_type_raw)) {
                is_mcast = (IS_MULTICAST(wh->i_addr1)) ? 1 : 0;
            } else {
                is_mcast = (IS_MULTICAST(eth_hdr->ether_dhost)) ? 1 : 0;
            }
            is_ucast = !is_mcast;

#if ATH_MCAST_HOST_INSPECT
            if( is_mcast ) {

                if( ol_mcast_notify( pdev->ctrl_pdev, vdev->vdev_id, netbuf ) > 0 ) {
                    ((union ol_tx_desc_list_elem_t *)(tx_desc))->next = (lcl_freelist);
                    if (qdf_unlikely(!lcl_freelist)) {
                        (tx_desc_last) = (union ol_tx_desc_list_elem_t *)(tx_desc);
                    }
                    (lcl_freelist) = (union ol_tx_desc_list_elem_t *)(tx_desc);
                    continue;
                }
            }
#endif /*ATH_MCAST_HOST_INSPECT*/
#if WDS_VENDOR_EXTENSION
            TAILQ_FOREACH(peer, &vdev->peer_list, peer_list_elem) {
                if (peer->bss_peer || (peer->peer_ids[0] == HTT_INVALID_PEER))
                    continue;

                /* count wds peers that use 3-addr framing for mcast.
                 * if there are any, the bss_peer is used to send the
                 * the mcast frame using 3-addr format. all wds enabled
                 * peers that use 4-addr framing for mcast frames will
                 * be duplicated and sent as 4-addr frames below.
                 */
                if (!peer->wds_enabled || !peer->wds_tx_mcast_4addr)
                    num_peers_3addr ++;
            }
#endif
            TAILQ_FOREACH(peer, &vdev->peer_list, peer_list_elem) {
                if (peer) {
                    /*
                     * osif_proxy_arp should always return true for NAWDS to work properly.
                     */
                    if((peer->peer_ids[0] != HTT_INVALID_PEER) &&
#if WDS_VENDOR_EXTENSION
                            ((peer->bss_peer && num_peers_3addr && is_mcast) ||
                             (peer->wds_enabled &&
                              ((is_mcast && peer->wds_tx_mcast_4addr) ||
                               (is_ucast && peer->wds_tx_ucast_4addr))))
#else
                            (peer->bss_peer || peer->nawds_enabled)
#endif
#if UMAC_SUPPORT_PROXY_ARP
                            && !(vdev->osif_proxy_arp(vdev->osif_vdev, netbuf))
#endif
                      ) {
                        /* re-inject multicast packet back to target by copying.
                         * get a new descriptor and send this packet.
                         * TODO: optimize this code to not use skb_copy
                         */
                        netbuf_copy = qdf_nbuf_copy(netbuf);
                        if (netbuf_copy) {
                            qdf_nbuf_reset_ctxt(netbuf_copy);
#if PEER_FLOW_CONTROL
                            if (peer->nawds_enabled) {
                                OL_TX_REINJECT(vdev->pdev, vdev, netbuf_copy, peer->peer_ids[0]);
                            } else {
                                OL_TX_REINJECT(vdev->pdev, vdev, netbuf_copy, HTT_INVALID_PEER);
                            }
#else
                            OL_TX_REINJECT(vdev->pdev, vdev, netbuf_copy, peer->peer_ids[0]);
#endif
                        }
                    }//proxy arp or nawds_enabled if check
                }//peer NULL check
            }//TAILQ_FOREACH
        }
#endif // PROXY_ARP or NAWDS or WDS_VENDOR_EXTENSION
#if !WLAN_FEATURE_FASTPATH && !ATH_11AC_TXCOMPACT
        /* save this multicast packet to local free list */
        if (qdf_atomic_dec_and_test(&tx_desc->ref_cnt))
#endif
        {
            if (OL_CFG_RAW_TX_LIKELINESS(tx_desc->tx_encap_type ==
                        htt_pkt_type_raw)
                && (qdf_nbuf_next(netbuf) != NULL)) {
                OL_RAW_TX_CHAINED_NBUF_UNMAP(pdev, netbuf);
            }

            /* for this function only, force htt status to be "htt_tx_status_ok"
             * for graceful freeing of this multicast frame
             */
#if !QCA_OL_TX_CACHEDHDR
            ol_tx_msdu_complete(pdev, tx_desc, tx_descs, netbuf, lcl_freelist,
                                    tx_desc_last, htt_tx_status_ok);
#else
	    qdf_nbuf_free((netbuf));
	    ((union ol_tx_desc_list_elem_t *)(tx_desc))->next = (lcl_freelist);
	    if (qdf_unlikely(!lcl_freelist)) {
		    (tx_desc_last) = (union ol_tx_desc_list_elem_t *)(tx_desc);
	    }
	    (lcl_freelist) = (union ol_tx_desc_list_elem_t *)(tx_desc);
#endif
        }
    }

    OL_TX_PDEV_LOCK(&pdev->tx_lock);
    if (lcl_freelist) {
        OL_TX_DESC_LOCK(&pdev->tx_mutex);
        tx_desc_last->next = pdev->tx_desc.freelist;
        pdev->tx_desc.freelist = lcl_freelist;
#if PEER_FLOW_CONTROL
        pdev->pflow_ctl_desc_count--;
#endif
        OL_TX_DESC_UNLOCK(&pdev->tx_mutex);
        TXRX_STATS_SUB(pdev, pub.tx.desc_in_use, num_msdus);
    } else {
        ol_tx_desc_frame_list_free(pdev, &tx_descs, htt_tx_status_discard);
    }

    OL_TX_PDEV_UNLOCK(&pdev->tx_lock);
    qdf_atomic_add(num_msdus, &pdev->target_tx_credit);

#if OL_ATH_SUPPORT_LED
    {
        struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)pdev->ctrl_pdev;
        scn->scn_led_byte_cnt += byte_cnt;
        ol_ath_led_event(scn, OL_ATH_LED_TX);
    }
#endif

    return;
}

