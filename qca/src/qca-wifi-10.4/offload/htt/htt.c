/*
 * Copyright (c) 2011-2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */
/**
 * @file htt.c
 * @brief Provide functions to create+init and destroy a HTT instance.
 * @details
 *  This file contains functions for creating a HTT instance; initializing
 *  the HTT instance, e.g. by allocating a pool of HTT tx descriptors and
 *  connecting the HTT service with HTC; and deleting a HTT instance.
 */

#include <qdf_mem.h>      /* qdf_mem_malloc */
#include <qdf_types.h>    /* qdf_device_t, qdf_print */

#include <htt.h>             /* htt_tx_msdu_desc_t */
#include <ol_cfg.h>
#include <ol_txrx_htt_api.h> /* ol_tx_dowload_done_ll, etc. */
#include <ol_htt_api.h>

#include <htt_internal.h>
#include <ol_txrx_types.h>

#if QCA_PARTNER_DIRECTLINK_TX
#include <ol_txrx_types.h>
#define QCA_PARTNER_DIRECTLINK_HTT 1
#include "ath_carr_pltfrm.h"
#undef QCA_PARTNER_DIRECTLINK_HTT
#endif /* QCA_PARTNER_DIRECTLINK_TX */
#include <hif.h>
#define HTT_HTC_PKT_POOL_INIT_SIZE 100 /* enough for a large A-MPDU */

int
htt_alloc_peer_map_mem(struct htt_pdev_t *pdev, int desc_pool_elems);

A_STATUS
htt_h2t_rx_ring_cfg_msg_ll(struct htt_pdev_t *pdev);

A_STATUS
htt_h2t_rx_ring_cfg_msg_hl(struct htt_pdev_t *pdev);

A_STATUS (*htt_h2t_rx_ring_cfg_msg)(
        struct htt_pdev_t *pdev);

struct htt_htc_pkt *
htt_htc_pkt_alloc(struct htt_pdev_t *pdev)
{
    struct htt_htc_pkt_union *pkt = NULL;

    HTT_TX_MUTEX_ACQUIRE(&pdev->htt_tx_mutex);
    if (pdev->htt_htc_pkt_freelist) {
        pkt = pdev->htt_htc_pkt_freelist;
        pdev->htt_htc_pkt_freelist = pdev->htt_htc_pkt_freelist->u.next;
    }
    HTT_TX_MUTEX_RELEASE(&pdev->htt_tx_mutex);

    if (pkt == NULL) {
        pkt = qdf_mem_malloc( sizeof(*pkt));
    }
    return &pkt->u.pkt; /* not actually a dereference */
}

void
htt_htc_pkt_free(struct htt_pdev_t *pdev, struct htt_htc_pkt *pkt)
{
    struct htt_htc_pkt_union *u_pkt = (struct htt_htc_pkt_union *) pkt;

    HTT_TX_MUTEX_ACQUIRE(&pdev->htt_tx_mutex);
    u_pkt->u.next = pdev->htt_htc_pkt_freelist;
    pdev->htt_htc_pkt_freelist = u_pkt;
    HTT_TX_MUTEX_RELEASE(&pdev->htt_tx_mutex);
}

void
htt_htc_pkt_pool_free(struct htt_pdev_t *pdev)
{
    struct htt_htc_pkt_union *pkt, *next;
    pkt = pdev->htt_htc_pkt_freelist;
    while (pkt) {
        next = pkt->u.next;
        qdf_mem_free(pkt);
        pkt = next;
    }
    pdev->htt_htc_pkt_freelist = NULL;
}
void htt_pkt_buf_list_add(struct htt_pdev_t *pdev, void *buf, u_int64_t cookie,void *htt_htc_packet)
{
	struct htt_pdev_buf_entry *ep = NULL;

	ep = qdf_mem_malloc( sizeof(struct htt_pdev_buf_entry));
    if (!ep) {
        qdf_print("%s,line:%d alloc failed\n",__func__,__LINE__);
		return ;
    }
	ep->buf = buf;
	ep->cookie = cookie;
    ep->htt_htc_packet = htt_htc_packet;

	qdf_spin_lock_bh(&pdev->htt_buf_list_lock);
    LIST_INSERT_HEAD((&pdev->buf_list_head), ep, buf_list);
	qdf_spin_unlock_bh(&pdev->htt_buf_list_lock);
}

void htt_pkt_buf_list_del(struct htt_pdev_t *pdev, u_int64_t cookie)
{
	struct htt_pdev_buf_entry *ep = NULL;
    struct ol_ath_softc_net80211 *scn =
            (struct ol_ath_softc_net80211 *) pdev->ctrl_pdev;

	qdf_spin_lock_bh(&pdev->htt_buf_list_lock);
	LIST_FOREACH(ep, &(pdev->buf_list_head), buf_list){
        if (ep->cookie == cookie) {
			if(ep->buf){
				qdf_nbuf_free((qdf_nbuf_t)ep->buf);
				ep->buf = NULL;
			}
            if(ep->htt_htc_packet) {
                htt_htc_pkt_free(pdev, ep->htt_htc_packet);
                ep->htt_htc_packet = NULL;
            }
            LIST_REMOVE(ep, buf_list);
            qdf_mem_free(ep);
	        qdf_spin_unlock_bh(&pdev->htt_buf_list_lock);
            return;
        }
    }
    qdf_spin_unlock_bh(&pdev->htt_buf_list_lock);

    if (scn->is_ar900b) {
        qdf_assert_always(ep) ;
    } else {
    qdf_print("pdev 0x%p from %s called without node element\n", pdev, __func__);
    }

}
/*---*/

u_int32_t
htt_pkt_dl_len_get(htt_pdev_handle htt_pdev)
{
    enum htt_pkt_type frm_type;
    u_int32_t pkt_dl_len = 0;
    struct htt_pdev_t *pdev = htt_pdev;

    /* account for the 802.3 or 802.11 header */
    frm_type = ol_cfg_pkt_type((ol_pdev_handle)pdev);
    if (frm_type == htt_pkt_type_native_wifi) {
        pkt_dl_len = HTT_TX_HDR_SIZE_NATIVE_WIFI;
    } else if (frm_type == htt_pkt_type_ethernet) {
        pkt_dl_len = HTT_TX_HDR_SIZE_ETHERNET;
    } else if (frm_type == htt_pkt_type_raw) {
        /* Note that in practice, this won't be used for now. The level of
         * deep inspection in FW for Raw Mode is limited and download sizes
         * without accounting for additional bytes due to Raw Mode are
         * sufficient.
         * We provide this option only for completeness.
         */
        pkt_dl_len = HTT_TX_HDR_SIZE_802_11_RAW;
    } else {
        qdf_print("Unexpected frame type spec: %d\n", frm_type);
        HTT_ASSERT0(0);
    }
    /*
     * Account for the optional L2 / ethernet header fields:
     * 802.1Q, LLC/SNAP
     */
    pkt_dl_len +=
        HTT_TX_HDR_SIZE_802_1Q + HTT_TX_HDR_SIZE_LLC_SNAP;

    /*
     * Account for the portion of the L3 (IP) payload that the
     * target needs for its tx classification.
     */
    pkt_dl_len += ol_cfg_tx_download_size(pdev->ctrl_pdev);

    return pkt_dl_len;
}

htt_pdev_handle
htt_attach(
    ol_txrx_pdev_handle txrx_pdev,
    ol_pdev_handle ctrl_pdev,
    struct hif_opaque_softc *osc,
    HTC_HANDLE htc_pdev,
    ar_handle_t arh,
    qdf_device_t osdev,
    int desc_pool_size)
{
    struct htt_pdev_t *pdev;
    int i;

    pdev = qdf_mem_malloc(sizeof(*pdev));

    if (!pdev) {
        goto fail1;
    }
    pdev->osdev = osdev;
    pdev->ctrl_pdev = ctrl_pdev;
    pdev->osc = osc;
    pdev->txrx_pdev = txrx_pdev;
    pdev->htc_pdev = htc_pdev;
    pdev->arh = arh;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    pdev->nss_wifiol_id = txrx_pdev->nss_wifiol_id;
    pdev->nss_wifiol_ctx = txrx_pdev->nss_wifiol_ctx;
#endif


#if defined(CONFIG_AR9888_SUPPORT) || defined(CONFIG_AR900B_SUPPORT)
    if (!txrx_pdev->is_ar900b) {
        HTT_SET_WIFI_IP(pdev,1,0);
    } else {
        HTT_SET_WIFI_IP(pdev,2,0);
    }
#elif defined(CONFIG_AR6320_SUPPORT)
    HTT_SET_WIFI_IP(pdev,1,5);
#endif

    qdf_mem_set(&pdev->stats, sizeof(pdev->stats), 0);
    pdev->htt_htc_pkt_freelist = NULL;

    /* for efficiency, store a local copy of the is_high_latency flag */
    pdev->cfg.is_high_latency = ol_cfg_is_high_latency(pdev->ctrl_pdev);

    /*
     * Connect to HTC service.
     * This has to be done before calling htt_rx_attach,
     * since htt_rx_attach involves sending a rx ring configure
     * message to the target.
     */
//AR6004 don't need HTT layer.
#ifndef AR6004_HW
    if (htt_htc_attach(pdev)) {
        goto fail2;
    }
#endif

#if QCA_PARTNER_DIRECTLINK_RX
    /* register device for Direct Link RX */
    if (CE_is_directlink(((struct ol_txrx_pdev_t*)pdev->txrx_pdev)->ce_tx_hdl)) {
        if(htt_attach_partner((void *)pdev)) {
            goto fail2;
        }
    }
#endif /* QCA_PARTNER_DIRECTLINK_RX */

    if (htt_tx_attach(pdev, desc_pool_size)) {
        goto fail2;
    }

    if (htt_rx_attach(pdev)) {
        goto fail3;
    }

    hif_ce_fastpath_cb_register(pdev->osc ,htt_t2h_msg_handler_fast , pdev);

#if QCA_PARTNER_DIRECTLINK_TX
    if (CE_is_directlink(((struct ol_txrx_pdev_t*)pdev->txrx_pdev)->ce_tx_hdl)) {
        htt_directlink_manage();
    }
#endif

    HTT_TX_MUTEX_INIT(&pdev->htt_tx_mutex);
    HTT_TX_NBUF_QUEUE_MUTEX_INIT(pdev);

    /* pre-allocate some HTC_PACKET objects */
    for (i = 0; i < HTT_HTC_PKT_POOL_INIT_SIZE; i++) {
        struct htt_htc_pkt_union *pkt;
        pkt = qdf_mem_malloc( sizeof(*pkt));
        if (! pkt) {
            break;
        }
        htt_htc_pkt_free(pdev, &pkt->u.pkt);
    }

    if (pdev->cfg.is_high_latency) {
        /*
         * HL - download the whole frame.
         * Specify a download length greater than the max MSDU size,
         * so the downloads will be limited by the actual frame sizes.
         */
        pdev->download_len = 5000;
        if (ol_cfg_tx_free_at_download(pdev->ctrl_pdev)) {
            pdev->tx_send_complete_part2 = ol_tx_download_done_hl_free;
        } else {
            pdev->tx_send_complete_part2 = ol_tx_download_done_hl_retain;
        }

        /*
         * For LL, the FW rx desc directly referenced at its location
         * inside the rx indication message.
         */
/*
 * CHECK THIS LATER: does the HL HTT version of htt_rx_mpdu_desc_list_next
 * (which is not currently implemented) present the qdf_nbuf_data(rx_ind_msg)
 * as the abstract rx descriptor?
 * If not, the rx_fw_desc_offset initialization here will have to be
 * adjusted accordingly.
 * NOTE: for HL, because fw rx desc is in ind msg, not in rx desc, so the
 * offset should be negtive value
 */
        pdev->rx_fw_desc_offset =
            HTT_ENDIAN_BYTE_IDX_SWAP(
                    HTT_RX_IND_FW_RX_DESC_BYTE_OFFSET
                    - HTT_RX_IND_HL_BYTES);

        htt_h2t_rx_ring_cfg_msg = htt_h2t_rx_ring_cfg_msg_hl;
    } else {
        /*
         * LL - download just the initial portion of the frame.
         * Download enough to cover the encapsulation headers checked
         * by the target's tx classification descriptor engine.
         */
        /* Get the packet download length */
        pdev->download_len = htt_pkt_dl_len_get(pdev);

        /*
         * Account for the HTT tx descriptor, including the
         * HTC header + alignment padding.
         */
        pdev->download_len += sizeof(struct htt_host_tx_desc_t);

        pdev->tx_send_complete_part2 = ol_tx_download_done_ll;

        /*
         * For LL, the FW rx desc is alongside the HW rx desc fields in
         * the htt_host_rx_desc_base struct/.
         */
        pdev->rx_fw_desc_offset = pdev->ar_rx_ops->offsetof_fw_desc();

        htt_h2t_rx_ring_cfg_msg = htt_h2t_rx_ring_cfg_msg_ll;
    }

    return pdev;

fail3:
    htt_tx_detach(pdev);

fail2:
    qdf_mem_free(pdev);

fail1:
    return NULL;
}

A_STATUS
htt_attach_target(htt_pdev_handle htt_pdev)
{
    A_STATUS status;
    struct htt_pdev_t *pdev = (struct htt_pdev_t *)htt_pdev;

    preempt_disable();
    status = htt_h2t_ver_req_msg(pdev);
    if (status != A_OK) {
        preempt_enable();
        return status;
    }
    /**
     * Send the frag_desc info to target.
     */
    status = htt_h2t_frag_desc_bank_cfg_msg(pdev);
    if (status != A_OK) {
        preempt_enable();
        return status;
    }

    /*
     * If applicable, send the rx ring config message to the target.
     * The host could wait for the HTT version number confirmation message
     * from the target before sending any further HTT messages, but it's
     * reasonable to assume that the host and target HTT version numbers
     * match, and proceed immediately with the remaining configuration
     * handshaking.
     */

    status =  htt_h2t_rx_ring_cfg_msg(pdev);
    preempt_enable();
#if WLAN_FEATURE_FASTPATH
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (!pdev->nss_wifiol_ctx)
#endif
    {
        qdf_mdelay(5);
        htc_ctrl_msg_cmpl(pdev->htc_pdev, pdev->htc_endpoint);
    }
#endif

    return status;
}

void
htt_detach(htt_pdev_handle pdev)
{
    struct ol_ath_softc_net80211 *scn = NULL;
    scn = (struct ol_ath_softc_net80211 *)(pdev->ctrl_pdev);

    htt_rx_detach(pdev);
    htt_tx_detach(pdev);

#if QCA_PARTNER_DIRECTLINK_RX
    /* de-register device for Direct Link RX */
    if (CE_is_directlink(((struct ol_txrx_pdev_t*)((struct htt_pdev_t *)pdev)->txrx_pdev)->ce_tx_hdl)) {
        htt_detach_partner((void *)pdev);
    }
#endif /* QCA_PARTNER_DIRECTLINK_RX */

    htt_htc_pkt_pool_free(pdev);
    HTT_TX_MUTEX_DESTROY(&pdev->htt_tx_mutex);
    HTT_TX_NBUF_QUEUE_MUTEX_DESTROY(pdev);

    pdev->txrx_pdev = NULL;
    scn->htt_pdev = NULL;
    qdf_mem_free(pdev);

}

int
htt_htc_attach(struct htt_pdev_t *pdev)
{
    HTC_SERVICE_CONNECT_REQ connect;
    HTC_SERVICE_CONNECT_RESP response;
    A_STATUS status;

    qdf_mem_set(&connect, sizeof(connect), 0);
    qdf_mem_set(&response, sizeof(response), 0);

    connect.pMetaData = NULL;
    connect.MetaDataLength = 0;
    connect.EpCallbacks.pContext = pdev;
    connect.EpCallbacks.EpTxComplete = htt_h2t_send_complete;
    connect.EpCallbacks.EpTxCompleteMultiple = NULL;
    connect.EpCallbacks.EpRecv = htt_t2h_msg_handler;

    /* rx buffers currently are provided by HIF, not by EpRecvRefill */
    connect.EpCallbacks.EpRecvRefill = NULL;
    connect.EpCallbacks.RecvRefillWaterMark = 1; /* N/A, fill is done by HIF */

    connect.EpCallbacks.EpSendFull = htt_h2t_full;
    /*
     * Specify how deep to let a queue get before htc_send_pkt will
     * call the EpSendFull function due to excessive send queue depth.
     */
    connect.MaxSendQueueDepth = HTT_MAX_SEND_QUEUE_DEPTH;

    /* disable flow control for HTT data message service */
    connect.ConnectionFlags |= HTC_CONNECT_FLAGS_DISABLE_CREDIT_FLOW_CTRL;

    /* connect to control service */
    connect.service_id = HTT_DATA_MSG_SVC;

    status = htc_connect_service(pdev->htc_pdev, &connect, &response);

    if (status != A_OK) {
        return 1; /* failure */
    }
    pdev->htc_endpoint = response.Endpoint;

    return 0; /* success */
}

#if HTT_DEBUG_LEVEL > 5
void
htt_display(htt_pdev_handle pdev, int indent)
{
    qdf_print("%*s%s:\n", indent, " ", "HTT");
    qdf_print(
        "%*stx desc pool: %d elems of %d bytes, "
        "%d currently allocated\n", indent+4, " ",
        pdev->tx_descs.pool_elems,
        pdev->tx_descs.size,
        pdev->tx_descs.alloc_cnt);
    qdf_print(
        "%*srx ring: space for %d elems, filled with %d buffers\n",
        indent+4, " ",
        pdev->rx_ring.size,
        pdev->rx_ring.fill_level);
    qdf_print("%*sat %p (%#x paddr)\n", indent+8, " ",
        pdev->rx_ring.buf.paddrs_ring,
        pdev->rx_ring.base_paddr);
    qdf_print("%*snetbuf ring @ %p\n", indent+8, " ",
        pdev->rx_ring.buf.netbufs_ring);
    qdf_print("%*sFW_IDX shadow register: vaddr = %p, paddr = %#x\n",
        indent+8, " ",
        pdev->rx_ring.alloc_idx.vaddr,
        pdev->rx_ring.alloc_idx.paddr);
    qdf_print(
        "%*sSW enqueue index = %d, SW dequeue index: desc = %d, buf = %d\n",
        indent+8, " ",
        *pdev->rx_ring.alloc_idx.vaddr,
        pdev->rx_ring.sw_rd_idx.msdu_desc,
        pdev->rx_ring.sw_rd_idx.msdu_payld);
}
#endif
