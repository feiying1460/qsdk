/*
 * Copyright (c) 2011, 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */
/**
 * @file ol_txrx_api.h
 * @brief Definitions used in multiple external interfaces to the txrx SW.
 */

#ifndef _OL_TXRX_API__H_
#define _OL_TXRX_API__H_

#include <cdp_txrx_cmn.h>

struct ieee80211vap;
#if !ATH_SUPPORT_ME_FW_BASED
uint16_t
ol_tx_me_init(struct ol_txrx_pdev_t *pdev);
void
ol_tx_me_exit(struct ol_txrx_pdev_t *pdev);

int
ol_tx_mcast_enhance_process(struct ieee80211vap *vap, qdf_nbuf_t skb);
#endif

#if HOST_SW_TSO_ENABLE
int ol_tx_tso_process_skb(ol_txrx_vdev_handle vdev,qdf_nbuf_t msdu);
#endif /* HOST_SW_TSO_ENABLE */

#if HOST_SW_TSO_SG_ENABLE
int ol_tx_tso_sg_process_skb(ol_txrx_vdev_handle vdev,qdf_nbuf_t msdu);
#endif /* HOST_SW_TSO_SG_ENABLE */

#if HOST_SW_SG_ENABLE
int ol_tx_sg_process_skb(ol_txrx_vdev_handle vdev,qdf_nbuf_t msdu);
#endif /* HOST_SW_SG_ENABLE */

#if WLAN_FEATURE_FASTPATH && QCA_OL_TX_CACHEDHDR

#if PEER_FLOW_CONTROL
int
ol_tx_ll_cachedhdr(ol_txrx_vdev_handle vdev,  qdf_nbuf_t msdu, uint16_t peer_id, uint8_t tid);
#else
int
ol_tx_ll_cachedhdr(ol_txrx_vdev_handle vdev,  qdf_nbuf_t msdu);
#endif

#if PEER_FLOW_CONTROL

void
ol_tx_flush_tid_queue_pflow_ctrl(struct ol_txrx_pdev_t *pdev, u_int16_t peer_id, u_int8_t tid);


void
ol_tx_pflow_ctrl_cong_ctrl_timer(void *arg);

void
ol_tx_pflow_ctrl_stats_timer(void *arg);

void
ol_tx_pflow_ctrl_host_sched(void *arg);

void
ol_tx_pflow_ctrl_ttl(struct ol_txrx_pdev_t *pdev, u_int32_t peerid, u_int8_t tid);

int
ol_tx_ll_pflow_ctrl(ol_txrx_vdev_handle vdev, qdf_nbuf_t netbuf);

uint32_t
ol_tx_ll_pflow_ctrl_list(ol_txrx_vdev_handle vdev,
        qdf_nbuf_t *nbuf_arr,
        uint32_t num_msdus);

void
ol_tx_flush_buffers_pflow_ctrl(struct ol_txrx_vdev_t *vdev);


void
ol_tx_flush_peer_queue_pflow_ctrl(struct ol_txrx_pdev_t *pdev, u_int16_t peer_id);

void
ol_tx_switch_mode_flush_buffers(struct ol_txrx_pdev_t *pdev);

#define OL_TX_LL_FORWARD_PACKET(_vdev, _msdu, _num_msdus) ol_tx_ll_pflow_ctrl(_vdev, _msdu)

#define OL_TX_LL_WRAPPER(_vdev, _msdu, _oshandle) ol_tx_ll_pflow_ctrl(_vdev, _msdu);
#else
#define OL_TX_LL_WRAPPER(_vdev, _msdu, _oshandle) ol_tx_ll_cachedhdr(_vdev, _msdu)
#define OL_TX_LL_FORWARD_PACKET(_vdev, _msdu, _num_msdus) ol_tx_ll_fast(vdev, &_msdu, _num_msdus)
#endif

#elif WLAN_FEATURE_FASTPATH

void
ol_tx_stats_inc_map_error(ol_txrx_vdev_handle vdev,
                             uint32_t num_map_error);
#define OL_TX_LL_WRAPPER(_vdev, _msdu, _oshandle) \
{\
    if(QDF_STATUS_E_FAILURE == qdf_nbuf_map_single( _oshandle , _msdu, QDF_DMA_TO_DEVICE)){;\
        ol_tx_stats_inc_map_error(_vdev, 1); \
        qdf_nbuf_free(_msdu); \
    }else{ \
        if (qdf_unlikely(ol_tx_ll_fast(_vdev, &_msdu, 1 ))){ \
            qdf_nbuf_unmap_single( _oshandle, _msdu, QDF_DMA_TO_DEVICE); \
            qdf_nbuf_free(_msdu); \
        } \
    } \
}

#endif /* WLAN_FEATURE_FASTPATH && QCA_OL_TX_CACHEDHDR*/

#endif /* _OL_TXRX_API__H_ */
