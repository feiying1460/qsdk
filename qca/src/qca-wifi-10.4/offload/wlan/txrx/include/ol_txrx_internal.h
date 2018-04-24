/*
 * Copyright (c) 2011, 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef _OL_TXRX_INTERNAL__H_
#define _OL_TXRX_INTERNAL__H_

#include <qdf_util.h>   /* qdf_assert */
#include <qdf_nbuf.h>      /* qdf_nbuf_t */
#include <qdf_mem.h>    /* qdf_mem_set */

#include <ol_htt_rx_api.h> /* htt_rx_msdu_desc_completes_mpdu, etc. */

#include <ol_txrx_types.h>

#include <ol_txrx_dbg.h>
#include <ol_txrx_api.h>

#ifndef TXRX_ASSERT_LEVEL
#define TXRX_ASSERT_LEVEL 3
#endif

#if TXRX_ASSERT_LEVEL > 0
#define TXRX_ASSERT1(condition) qdf_assert((condition))
#else
#define TXRX_ASSERT1(condition)
#endif

#if TXRX_ASSERT_LEVEL > 1
#define TXRX_ASSERT2(condition) qdf_assert((condition))
#else
#define TXRX_ASSERT2(condition)
#endif

enum {
    /* FATAL_ERR - print only irrecoverable error messages */
    TXRX_PRINT_LEVEL_FATAL_ERR,

    /* ERR - include non-fatal err messages */
    TXRX_PRINT_LEVEL_ERR,

    /* WARN - include warnings */
    TXRX_PRINT_LEVEL_WARN,

    /* INFO1 - include fundamental, infrequent events */
    TXRX_PRINT_LEVEL_INFO1,

    /* INFO2 - include non-fundamental but infrequent events */
    TXRX_PRINT_LEVEL_INFO2,

    /* INFO3 - include frequent events */
    /* to avoid performance impact, don't use INFO3 unless explicitly enabled */
#if TXRX_PRINT_VERBOSE_ENABLE
    TXRX_PRINT_LEVEL_INFO3,
#endif /* TXRX_PRINT_VERBOSE_ENABLE */
};

extern unsigned g_txrx_print_level;

#if TXRX_PRINT_ENABLE
#include <stdarg.h>       /* va_list */
#include <qdf_types.h> /* qdf_vprint */

#define ol_txrx_print(level, fmt, ...) \
    if(level <= g_txrx_print_level) qdf_print(fmt, ## __VA_ARGS__)
#define TXRX_PRINT(level, fmt, ...) \
    ol_txrx_print(level, "TXRX: " fmt, ## __VA_ARGS__)

#if TXRX_PRINT_VERBOSE_ENABLE

#define ol_txrx_print_verbose(fmt, ...) \
    if(TXRX_PRINT_LEVEL_INFO3 <= g_txrx_print_level) qdf_print(fmt, ## __VA_ARGS__)
#define TXRX_PRINT_VERBOSE(fmt, ...) \
    ol_txrx_print_verbose("TXRX: " fmt, ## __VA_ARGS__)
#else
#define TXRX_PRINT_VERBOSE(fmt, ...)
#endif /* TXRX_PRINT_VERBOSE_ENABLE */

#else
#define TXRX_PRINT(level, fmt, ...)
#define TXRX_PRINT_VERBOSE(fmt, ...)
#endif /* TXRX_PRINT_ENABLE */
#if MESH_MODE_SUPPORT
void ol_rx_mesh_mode_per_pkt_rx_info(qdf_nbuf_t nbuf, struct ol_txrx_peer_t *peer, struct ol_txrx_vdev_t *vdev);
#endif

#define OL_TXRX_LIST_APPEND(head, tail, elem) \
do {                                            \
    if (!(head)) {                              \
        (head) = (elem);                        \
    } else {                                    \
        qdf_nbuf_set_next((tail), (elem));      \
    }                                           \
    (tail) = (elem);                            \
} while (0)

static inline void
ol_rx_mpdu_list_next(
    struct ol_txrx_pdev_t *pdev,
    void *mpdu_list,
    qdf_nbuf_t *mpdu_tail,
    qdf_nbuf_t *next_mpdu)
{
    htt_pdev_handle htt_pdev = pdev->htt_pdev;
    qdf_nbuf_t msdu;
    struct ol_ath_softc_net80211 *scn = NULL;

    /*
     * For now, we use a simply flat list of MSDUs.
     * So, traverse the list until we reach the last MSDU within the MPDU.
     */
    TXRX_ASSERT2(mpdu_list);
    msdu = mpdu_list;
    while (!htt_rx_msdu_desc_completes_mpdu(
                htt_pdev, htt_rx_msdu_desc_retrieve(htt_pdev, msdu)))
    {
        /* WAR: If LAST MSDU is not set, but next_msdu is NULL, then break the loop */
        if(qdf_nbuf_next(msdu) == NULL) {
           scn = (struct ol_ath_softc_net80211 *)pdev->ctrl_pdev;
           scn->scn_stats.rx_last_msdu_unset_cnt++;
           break;
        }

        msdu = qdf_nbuf_next(msdu);
        TXRX_ASSERT2(msdu);
    }
    /* msdu now points to the last MSDU within the first MPDU */
    *mpdu_tail = msdu;
    *next_mpdu = qdf_nbuf_next(msdu);
}


/*--- txrx stats macros ---*/


/* unconditional defs */
#define TXRX_STATS_INCR(pdev, field) TXRX_STATS_ADD(pdev, field, 1)

/* default conditional defs (may be undefed below) */

#define TXRX_STATS_INIT(_pdev) \
    qdf_mem_set(&((_pdev)->stats), sizeof((_pdev)->stats), 0x0)
#define TXRX_STATS_ADD(_pdev, _field, _delta) \
    _pdev->stats._field += _delta
#define TXRX_STATS_SUB(_pdev, _field, _delta) \
    _pdev->stats._field -= _delta
#define TXRX_STATS_MSDU_INCR(pdev, field, netbuf) \
    do { \
        TXRX_STATS_INCR((pdev), pub.field.pkts); \
        TXRX_STATS_ADD((pdev), pub.field.bytes, qdf_nbuf_len(netbuf)); \
    } while (0)

/* conditional defs based on verbosity level */

#if /*---*/ TXRX_STATS_LEVEL == TXRX_STATS_LEVEL_FULL

#define TXRX_STATS_MSDU_LIST_INCR(pdev, field, netbuf_list) \
    do { \
        qdf_nbuf_t tmp_list = netbuf_list; \
        while (tmp_list) { \
            TXRX_STATS_MSDU_INCR(pdev, field, tmp_list); \
            tmp_list = qdf_nbuf_next(tmp_list); \
        } \
    } while (0)

#define TXRX_STATS_MSDU_INCR_TX_STATUS(status, pdev, netbuf) \
    switch (status) { \
    case htt_tx_status_ok: \
        TXRX_STATS_MSDU_INCR(pdev, tx.delivered, netbuf); \
        break; \
    case htt_tx_status_discard: \
        TXRX_STATS_MSDU_INCR(pdev, tx.dropped.target_discard, netbuf); \
        break; \
    case htt_tx_status_no_ack: \
        TXRX_STATS_MSDU_INCR(pdev, tx.dropped.no_ack, netbuf); \
        break; \
    case htt_tx_status_download_fail: \
        TXRX_STATS_MSDU_INCR(pdev, tx.dropped.download_fail, netbuf); \
        break; \
    default: \
        break; \
    }

#define TXRX_STATS_UPDATE_TX_STATS(_pdev, _status, _p_cntrs, _b_cntrs)          \
do {                                                                            \
    switch (status) {                                                           \
    case htt_tx_status_ok:                                                      \
       TXRX_STATS_ADD(_pdev, pub.tx.delivered.pkts, _p_cntrs);                  \
       TXRX_STATS_ADD(_pdev, pub.tx.delivered.bytes, _b_cntrs);                 \
        break;                                                                  \
    case htt_tx_status_discard:                                                 \
       TXRX_STATS_ADD(_pdev, pub.tx.dropped.target_discard.pkts, _p_cntrs);     \
       TXRX_STATS_ADD(_pdev, pub.tx.dropped.target_discard.bytes, _b_cntrs);    \
        break;                                                                  \
    case htt_tx_status_no_ack:                                                  \
       TXRX_STATS_ADD(_pdev, pub.tx.dropped.no_ack.pkts, _p_cntrs);             \
       TXRX_STATS_ADD(_pdev, pub.tx.dropped.no_ack.bytes, _b_cntrs);            \
        break;                                                                  \
    case htt_tx_status_download_fail:                                           \
       TXRX_STATS_ADD(_pdev, pub.tx.dropped.download_fail.pkts, _p_cntrs);      \
       TXRX_STATS_ADD(_pdev, pub.tx.dropped.download_fail.bytes, _b_cntrs);     \
        break;                                                                  \
    default:                                                                    \
        break;                                                                  \
    }                                                                           \
} while (0)

#elif /*---*/ TXRX_STATS_LEVEL == TXRX_STATS_LEVEL_BASIC

#define TXRX_STATS_MSDU_LIST_INCR(pdev, field, netbuf_list)

#define TXRX_STATS_MSDU_INCR_TX_STATUS(status, pdev, netbuf) \
    do { \
        if (status == htt_tx_status_ok) { \
            TXRX_STATS_MSDU_INCR(pdev, tx.delivered, netbuf); \
        } \
    } while (0)

#define TXRX_STATS_INIT(_pdev) \
    qdf_mem_set(&((_pdev)->stats), sizeof((_pdev)->stats), 0x0)

#define TXRX_STATS_UPDATE_TX_STATS(_pdev, _status, _p_cntrs, _b_cntrs)          \
do {                                                                            \
    if (qdf_likely(_status == htt_tx_status_ok)) {                           \
       TXRX_STATS_ADD(_pdev, pub.tx.delivered.pkts, _p_cntrs);                  \
       TXRX_STATS_ADD(_pdev, pub.tx.delivered.bytes, _b_cntrs);                 \
    }                                                                           \
} while (0)

#else /*---*/ /* stats off */

#undef  TXRX_STATS_INIT
#define TXRX_STATS_INIT(_pdev)

#undef  TXRX_STATS_ADD
#define TXRX_STATS_ADD(_pdev, _field, _delta)
#define TXRX_STATS_SUB(_pdev, _field, _delta)

#undef  TXRX_STATS_MSDU_INCR
#define TXRX_STATS_MSDU_INCR(pdev, field, netbuf)

#define TXRX_STATS_MSDU_LIST_INCR(pdev, field, netbuf_list)

#define TXRX_STATS_MSDU_INCR_TX_STATUS(status, pdev, netbuf)

#define TXRX_STATS_UPDATE_TX_STATS(_pdev, _status, _p_cntrs, _b_cntrs)

#endif /*---*/ /* TXRX_STATS_LEVEL */


/*--- txrx sequence number trace macros ---*/


#define TXRX_SEQ_NUM_ERR(_status) (0xffff - _status)

#if defined(ENABLE_RX_REORDER_TRACE)

A_STATUS ol_rx_reorder_trace_attach(ol_txrx_pdev_handle pdev);
void ol_rx_reorder_trace_detach(ol_txrx_pdev_handle pdev);
void ol_rx_reorder_trace_add(
    ol_txrx_pdev_handle pdev,
    u_int8_t tid,
    u_int16_t seq_num,
    int num_mpdus);

#define OL_RX_REORDER_TRACE_ATTACH ol_rx_reorder_trace_attach
#define OL_RX_REORDER_TRACE_DETACH ol_rx_reorder_trace_detach
#define OL_RX_REORDER_TRACE_ADD    ol_rx_reorder_trace_add

#else

#define OL_RX_REORDER_TRACE_ATTACH(_pdev) A_OK
#define OL_RX_REORDER_TRACE_DETACH(_pdev)
#define OL_RX_REORDER_TRACE_ADD(pdev, tid, seq_num, num_mpdus)

#endif /* ENABLE_RX_REORDER_TRACE */


/*--- txrx packet number trace macros ---*/


#if defined(ENABLE_RX_PN_TRACE)

A_STATUS ol_rx_pn_trace_attach(ol_txrx_pdev_handle pdev);
void ol_rx_pn_trace_detach(ol_txrx_pdev_handle pdev);
void ol_rx_pn_trace_add(
    struct ol_txrx_pdev_t *pdev,
    struct ol_txrx_peer_t *peer,
    u_int16_t tid,
    void *rx_desc);

#define OL_RX_PN_TRACE_ATTACH ol_rx_pn_trace_attach
#define OL_RX_PN_TRACE_DETACH ol_rx_pn_trace_detach
#define OL_RX_PN_TRACE_ADD    ol_rx_pn_trace_add

#else

#define OL_RX_PN_TRACE_ATTACH(_pdev) A_OK
#define OL_RX_PN_TRACE_DETACH(_pdev)
#define OL_RX_PN_TRACE_ADD(pdev, peer, tid, rx_desc)

#endif /* ENABLE_RX_PN_TRACE */

#if WLAN_FEATURE_FASTPATH && QCA_OL_TX_CACHEDHDR
extern void ol_vap_tx_lock(void *);
extern void ol_vap_tx_unlock(void *);

qdf_nbuf_t ol_tx_reinject_cachedhdr(
        struct ol_txrx_vdev_t *vdev,
        qdf_nbuf_t msdu, uint32_t peer_id);

#if !QCA_OL_TX_PDEV_LOCK
#define OL_TX_REINJECT(_pdev, _vdev, _msdu, peer_id)  \
{ \
	ol_vap_tx_lock(_vdev->osif_vdev); \
	ol_tx_reinject_cachedhdr(_vdev, _msdu, peer_id); \
	ol_vap_tx_unlock(_vdev->osif_vdev);\
}
#else

#define OL_TX_REINJECT(_pdev, _vdev, _msdu, peer_id)  \
{ \
	OL_TX_LOCK(_vdev); \
	ol_tx_reinject_cachedhdr(_vdev, _msdu, peer_id); \
	OL_TX_UNLOCK(_vdev);\
}
#endif


#define  HTT_REMOVE_CACHED_HDR(_msdu,_size) 	        qdf_nbuf_pull_head(_msdu, _size);

#elif WLAN_FEATURE_FASTPATH

qdf_nbuf_t ol_tx_reinject_fast(
        struct ol_txrx_vdev_t *vdev,
        qdf_nbuf_t msdu, uint32_t peer_id);
#define OL_TX_REINJECT(_pdev, _vdev, _msdu, peer_id)  \
	qdf_nbuf_map_single(_pdev->osdev, _msdu, QDF_DMA_TO_DEVICE); \
	ol_tx_reinject_fast(_vdev, _msdu, peer_id)

#define  HTT_REMOVE_CACHED_HDR(_msdu,_size)
#else

qdf_nbuf_t
ol_tx_reinject(
        struct ol_txrx_vdev_t *vdev,
        qdf_nbuf_t msdu, uint32_t peer_id);
#define OL_TX_REINJECT(_pdev, _vdev, _msdu, peer_id)  \
	qdf_nbuf_map_single(_pdev->osdev, _msdu, QDF_DMA_TO_DEVICE); \
        ol_tx_reinject(_vdev, _msdu, peer_id)

#define  HTT_REMOVE_CACHED_HDR(_msdu,_size)

#endif /*WLAN_FEATURE_FASTPATH && QCA_OL_TX_CACHEDHDR*/

#if WLAN_FEATURE_FASTPATH && QCA_OL_TX_CACHEDHDR

extern void ol_vap_tx_lock(void *);
#if !QCA_OL_TX_PDEV_LOCK
#define OL_VDEV_TX(_vdev, _msdu, _oshandle) \
{ \
    ol_vap_tx_lock(_vdev->osif_vdev); \
    OL_TX_LL_WRAPPER(_vdev, _msdu, _oshandle); \
    ol_vap_tx_unlock(_vdev->osif_vdev); \
}
#else
#define OL_VDEV_TX(_vdev, _msdu, _oshandle) \
{ \
    OL_TX_LOCK(_vdev); \
    OL_TX_LL_WRAPPER(_vdev, _msdu, _oshandle); \
    OL_TX_UNLOCK(_vdev); \
}
#endif

#elif WLAN_FEATURE_FASTPATH

#define OL_VDEV_TX(_vdev, _msdu, _oshandle) \
           OL_TX_LL_WRAPPER(_vdev, _msdu, _oshandle);

#else
#define OL_VDEV_TX(_vdev, _msdu, _oshandle) \
{\
    qdf_nbuf_map_single(_oshandle, _msdu, QDF_DMA_TO_DEVICE);\
    if (vdev->tx(_vdev, _msdu))  { \
        qdf_nbuf_unmap_single(_oshandle, _msdu, QDF_DMA_TO_DEVICE);\
        qdf_nbuf_free(_msdu); \
    }\
}

#endif /* WLAN_FEATURE_FASTPATH */

#if WLAN_FEATURE_FASTPATH
#if !QCA_OL_TX_PDEV_LOCK
#define OL_VDEV_TX_MCAST_ENHANCE(_vdev, _msdu, _vap) \
{ \
        ol_vap_tx_lock(_vdev->osif_vdev); \
        if( ol_tx_mcast_enhance_process(_vap, _msdu) > 0 ) { \
            ol_vap_tx_unlock(_vdev->osif_vdev); \
            return; \
        } \
        ol_vap_tx_unlock(_vdev->osif_vdev); \
}
#else
#define OL_VDEV_TX_MCAST_ENHANCE(_vdev, _msdu, _vap) \
{ \
        OL_TX_LOCK(_vdev); \
        if( ol_tx_mcast_enhance_process(_vap, _msdu) > 0 ) { \
            OL_TX_UNLOCK(_vdev); \
            return; \
        } \
        OL_TX_UNLOCK(_vdev); \
}
#endif
#endif

void ol_vap_txdiscard_stats_update(void *vosdev, qdf_nbuf_t nbuf);


#endif /* _OL_TXRX_INTERNAL__H_ */
