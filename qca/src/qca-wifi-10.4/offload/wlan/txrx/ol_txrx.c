/*
 * Copyright (c) 2011-2017 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * 2011-2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

/*=== includes ===*/
/* header files for OS primitives */
#include <osdep.h>         /* u_int32_t, etc. */
#include <qdf_mem.h>    /* qdf_mem_malloc,free */
#include <qdf_types.h>  /* qdf_device_t, qdf_print */
#include <qdf_lock.h>   /* qdf_spinlock */
#include <qdf_atomic.h> /* qdf_atomic_read */
#include "osif_private.h"

#if WLAN_FEATURE_FASTPATH
#include <hif.h> /* struct hif_softc */
#endif

/* header files for utilities */
#include <queue.h>         /* TAILQ */

/* header files for configuration API */
#include <ol_cfg.h>        /* ol_cfg_is_high_latency */
#include <ol_if_athvar.h>

/* header files for HTT API */
#include <ol_htt_api.h>
#include <ol_htt_tx_api.h>

/* header files for our own APIs */
#include <cdp_txrx_cmn.h>
#include <ol_txrx_dbg.h>
#include <ol_txrx_ctrl_api.h>
#include <ol_txrx_osif_api.h>

/* header files for our internal definitions */
#include <ol_txrx_internal.h>  /* TXRX_ASSERT, etc. */
#include <ol_txrx_types.h>     /* ol_txrx_pdev_t, etc. */
#include <ol_tx.h>             /* ol_tx_hl, ol_tx_ll */
#include <ol_rx.h>             /* ol_rx_deliver */
#include <ol_txrx_peer_find.h> /* ol_txrx_peer_find_attach, etc. */
#include <ol_rx_pn.h>          /* ol_rx_pn_check, etc. */
#include <ol_rx_fwd.h>         /* ol_rx_fwd_check, etc. */
#include <ol_tx_desc.h>        /* ol_tx_desc_frame_free */
#include <wdi_event.h>         /* WDI events */
#include <ol_ratectrl_11ac_if.h>    /* attaching/freeing rate-control contexts */
#if QCA_OL_TX_CACHEDHDR
#include <htt.h>              /* HTT_TX_EXT_TID_MGMT */
#include <htt_internal.h>     /* */
#include <htt_types.h>        /* htc_endpoint */
#endif
/*=== local definitions ===*/
#ifndef OL_TX_AVG_FRM_BYTES
#define OL_TX_AVG_FRM_BYTES 1000
#endif

#ifndef OL_TX_DESC_POOL_SIZE_MIN
#define OL_TX_DESC_POOL_SIZE_MIN 500
#endif

#ifndef OL_TX_DESC_POOL_SIZE_MAX
#define OL_TX_DESC_POOL_SIZE_MAX 5000
#endif

#if QCA_PARTNER_DIRECTLINK_RX
#define QCA_PARTNER_DIRECTLINK_OL_TXRX 1
#include "ath_carr_pltfrm.h"
#undef QCA_PARTNER_DIRECTLINK_OL_TXRX
#endif

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_private.h>
#include <osif_nss_wifiol_if.h>
#include <osif_nss_wifiol_vdev_if.h>
#endif

/*=== function definitions ===*/

static int
ol_tx_desc_pool_size(ol_pdev_handle ctrl_pdev)
{
    int desc_pool_size;
    int steady_state_tx_lifetime_ms;
    int safety_factor;

    /*
     * Steady-state tx latency:
     *     roughly 1-2 ms flight time
     *   + roughly 1-2 ms prep time,
     *   + roughly 1-2 ms target->host notification time.
     * = roughly 6 ms total
     * Thus, steady state number of frames =
     * steady state max throughput / frame size * tx latency, e.g.
     * 1 Gbps / 1500 bytes * 6 ms = 500
     *
     */
    steady_state_tx_lifetime_ms = 6;

    safety_factor = 8;

    desc_pool_size =
        ol_cfg_max_thruput_mbps(ctrl_pdev) *
        1000 /* 1e6 bps/mbps / 1e3 ms per sec = 1000 */ /
        (8 * OL_TX_AVG_FRM_BYTES) *
        steady_state_tx_lifetime_ms *
        safety_factor;

    /* minimum */
    if (desc_pool_size < OL_TX_DESC_POOL_SIZE_MIN) {
        desc_pool_size = OL_TX_DESC_POOL_SIZE_MIN;
    }
    /* maximum */
    if (desc_pool_size > OL_TX_DESC_POOL_SIZE_MAX) {
        desc_pool_size = OL_TX_DESC_POOL_SIZE_MAX;
    }
    return desc_pool_size;
}

static ol_txrx_prot_an_handle
ol_txrx_prot_an_attach(struct ol_txrx_pdev_t *pdev, const char *name)
{
    ol_txrx_prot_an_handle base;

    base = OL_TXRX_PROT_AN_CREATE_802_3(pdev, name);
    if (base) {
        ol_txrx_prot_an_handle ipv4;
        ol_txrx_prot_an_handle ipv6;
        ol_txrx_prot_an_handle arp;

        arp = OL_TXRX_PROT_AN_ADD_ARP(pdev, base);
        ipv6 = OL_TXRX_PROT_AN_ADD_IPV6(pdev, base);
        ipv4 = OL_TXRX_PROT_AN_ADD_IPV4(pdev, base);

        if (ipv4) {
            /* limit TCP printouts to once per 5 sec */
            OL_TXRX_PROT_AN_ADD_TCP(
                pdev, ipv4, TXRX_PROT_ANALYZE_PERIOD_TIME, 0x0, 5000);
            /* limit UDP printouts to once per 5 sec */
            OL_TXRX_PROT_AN_ADD_UDP(
                pdev, ipv4, TXRX_PROT_ANALYZE_PERIOD_TIME, 0x3, 5000);
            /* limit ICMP printouts to two per sec */
            OL_TXRX_PROT_AN_ADD_ICMP(
                pdev, ipv4, TXRX_PROT_ANALYZE_PERIOD_TIME, 0x0, 500);
        }
        /* could add TCP, UDP, and ICMP for IPv6 too */
    }
    return base;
}

#if PEER_FLOW_CONTROL
int
ol_tx_pflow_ctrl_init(struct ol_txrx_pdev_t *pdev)
{
    int i, tid;
    struct ol_ath_softc_net80211 *scn =
                (struct ol_ath_softc_net80211 *)pdev->ctrl_pdev;

    /* Peer / TID Q related members */
    pdev->pflow_ctl_min_threshold = OL_TX_PFLOW_CTRL_MIN_THRESHOLD;
    if (scn->target_type == TARGET_TYPE_IPQ4019){
        pdev->pflow_ctl_min_queue_len = OL_TX_PFLOW_CTRL_MIN_QUEUE_LEN_IPQ4019;
        pdev->pflow_ctl_max_queue_len = OL_TX_PFLOW_CTRL_MAX_QUEUE_LEN_IPQ4019;
        pdev->pflow_ctl_max_buf_global = OL_TX_PFLOW_CTRL_MAX_BUF_GLOBAL_IPQ4019;
    } else {
        pdev->pflow_ctl_min_queue_len = OL_TX_PFLOW_CTRL_MIN_QUEUE_LEN;
        pdev->pflow_ctl_max_queue_len = OL_TX_PFLOW_CTRL_MAX_QUEUE_LEN;
#if MIPS_LOW_PERF_SUPPORT
        pdev->pflow_ctl_max_buf_global = OL_TX_PFLOW_CTRL_MAX_BUF_GLOBAL;
#else
        /* Initialize with the lowest level */
        pdev->pflow_ctl_max_buf_global = OL_TX_PFLOW_CTRL_MAX_BUF_0;
#endif
    }
    pdev->pflow_cong_ctrl_timer_interval = OL_TX_PFLOW_CTRL_CONG_CTRL_TIMER_MS;
    pdev->pflow_ctl_stats_timer_interval = OL_TX_PFLOW_CTRL_STATS_TIMER_MS;

    pdev->pflow_ctl_global_queue_cnt = 0;
    pdev->pflow_ctl_total_dequeue_cnt = 0;
    pdev->pflow_ctl_total_dequeue_byte_cnt  = 0;
    pdev->pflow_ctl_desc_count = 0;

#if PEER_FLOW_CONTROL_HOST_SCHED
    qdf_mem_zero(pdev->pflow_ctl_next_peer_idx, 4 * OL_TX_PFLOW_CTRL_MAX_TIDS);
#endif
    qdf_mem_zero(pdev->pflow_ctl_active_peer_map,
                        4 * (OL_TX_PFLOW_CTRL_MAX_TIDS * (OL_TXRX_MAX_PEER_IDS >> 5)));

    for (i = 0; i < OL_TXRX_MAX_PEER_IDS; i++) {

        for (tid = 0; tid < OL_TX_PFLOW_CTRL_MAX_TIDS; tid++) {
                pdev->pflow_ctl_queue_max_len[i][tid] = pdev->pflow_ctl_max_queue_len;
        }

    }

    qdf_timer_init(pdev->osdev, &pdev->pflow_ctl_cong_timer,
            ol_tx_pflow_ctrl_cong_ctrl_timer, (void *)pdev, QDF_TIMER_TYPE_WAKE_APPS);

    qdf_timer_mod(&pdev->pflow_ctl_cong_timer,
            OL_TX_PFLOW_CTRL_CONG_CTRL_TIMER_MS);

    qdf_timer_init(pdev->osdev, &pdev->pflow_ctl_stats_timer,
            ol_tx_pflow_ctrl_stats_timer, (void *)pdev, QDF_TIMER_TYPE_WAKE_APPS);

    /* Qmap related members */
    pdev->pmap_qdepth_flush_interval  = OL_TX_PFLOW_CTRL_QDEPTH_FLUSH_INTERVAL;
    pdev->pmap_rotting_timer_interval = OL_TX_PFLOW_CTRL_ROT_TIMER_MS;
    pdev->pmap_qdepth_flush_count     = 0;
    /* Default Mode 0 ON */
    pdev->pflow_ctrl_mode             = HTT_TX_MODE_PUSH_NO_CLASSIFY;
    qdf_print("Startup Mode-%d set\n", pdev->pflow_ctrl_mode);
    pdev->pflow_msdu_ttl              = OL_MSDU_DEFAULT_TTL/OL_TX_PFLOW_CTRL_CONG_CTRL_TIMER_MS;
    pdev->pflow_msdu_ttl_cnt          = 0;
    pdev->pflow_ttl_cntr              = 0;

    return 0;
}

void
ol_tx_pflow_ctrl_clean(struct ol_txrx_pdev_t *pdev)
{
    qdf_timer_stop(&pdev->pflow_ctl_cong_timer);
    qdf_timer_free(&pdev->pflow_ctl_cong_timer);
    qdf_timer_free(&pdev->pflow_ctl_stats_timer);
}

#endif

#define BUF_PEER_ENTRIES	32

int
ol_txrx_mempools_attach(ol_pdev_handle ctrl_pdev)
{
    struct ol_ath_softc_net80211 *scn =
                (struct ol_ath_softc_net80211 *)ctrl_pdev;

    if (qdf_mempool_init(scn->qdf_dev, &scn->mempool_ol_ath_peer,
        (BUF_PEER_ENTRIES +  scn->max_vaps + scn->max_clients), sizeof(struct ol_txrx_peer_t), 0)) {
        scn->mempool_ol_ath_peer = NULL;
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: ol_ath_peer memory pool init failed\n", __func__);
        return -ENOMEM;
    }

    return 0;
}

ol_txrx_pdev_handle
ol_txrx_pdev_attach(
    ol_pdev_handle ctrl_pdev,
    HTC_HANDLE htc_pdev,
    qdf_device_t osdev)
{
    int i, desc_pool_size, j;
    struct ol_txrx_pdev_t *pdev;
    A_STATUS ret;
    struct ol_ath_softc_net80211 *scn =
                (struct ol_ath_softc_net80211 *)ctrl_pdev;
    struct hif_opaque_softc *sc = ( struct hif_opaque_softc *) scn->hif_hdl;

    pdev = qdf_mem_malloc(sizeof(*pdev));
    if (!pdev) {
        goto fail0;
    }
    qdf_mem_zero(pdev, sizeof(*pdev));

    qdf_nbuf_queue_init(&pdev->acnbufq);
    qdf_spinlock_create(&pdev->acnbufqlock);

    pdev->acqcnt_len = OL_TX_FLOW_CTRL_QUEUE_LEN;
    pdev->acqcnt = 0;
    pdev->ctrl_pdev = ctrl_pdev;
    pdev->targetdef = scn->targetdef;

#if PEER_FLOW_CONTROL
    ol_tx_pflow_ctrl_init(pdev);
#endif

    /* init LL/HL cfg here */
    pdev->cfg.is_high_latency = ol_cfg_is_high_latency(ctrl_pdev);

    /* store provided params */
    pdev->osdev = osdev;

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "pdev attach %p %d \n",scn->nss_wifiol_ctx,scn->nss_wifiol_id);
    if (scn->nss_wifiol_ctx){
        pdev->nss_wifiol_id = scn->nss_wifiol_id;
        pdev->nss_wifiol_ctx = scn->nss_wifiol_ctx;
	pdev->nss_ifnum = scn->nss_ifnum;
	pdev->nss_wifiol_htc_flush_done = 0;
        osif_nss_ol_set_msdu_ttl(pdev);
    }else {
        pdev->nss_wifiol_id = -1;
        pdev->nss_wifiol_ctx = NULL;
    }
#endif

    TXRX_STATS_INIT(pdev);

    TAILQ_INIT(&pdev->vdev_list);

    /* do initial set up of the peer ID -> peer object lookup map */
    if (ol_txrx_peer_find_attach(pdev)) {
        goto fail1;
    }

    if (ol_cfg_is_high_latency(ctrl_pdev)) {
        desc_pool_size = ol_tx_desc_pool_size(ctrl_pdev);
    } else {
        /* In LL data path having more descriptors than target raises a
         * race condition with the current target credit implememntation.
         */
        desc_pool_size = ol_cfg_target_tx_credit(ctrl_pdev);
    }
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
	scn->buff_thresh.pool_size = desc_pool_size;
	scn->buff_thresh.ald_buffull_wrn = 0;
#endif

    if (scn->target_type)
        pdev->is_ar900b = scn->is_ar900b;

    pdev->htt_pdev = htt_attach(
        pdev, ctrl_pdev, sc, htc_pdev, scn->arh, osdev, desc_pool_size);
    if (!pdev->htt_pdev) {
        goto fail2;
    }

#if WLAN_FEATURE_FASTPATH
    scn->htt_pdev = pdev->htt_pdev;
    pdev->htt_pdev->osc = sc;
#endif /* WLAN_FEATURE_FASTPATH */

    pdev->tx_desc.array = qdf_mem_malloc(
        desc_pool_size * sizeof(union ol_tx_desc_list_elem_t));
    if (!pdev->tx_desc.array) {
        goto fail3;
    }
    qdf_mem_set(
        pdev->tx_desc.array,
        desc_pool_size * sizeof(union ol_tx_desc_list_elem_t), 0);

    qdf_print(KERN_INFO"%s: %d tx desc's allocated ; range starts from %p\n",
		    __func__, desc_pool_size, pdev->tx_desc.array );
    /*
     * Each SW tx desc (used only within the tx datapath SW) has a
     * matching HTT tx desc (used for downloading tx meta-data to FW/HW).
     * Go ahead and allocate the HTT tx desc and link it with the SW tx
     * desc now, to avoid doing it during time-critical transmit.
     */
    pdev->tx_desc.pool_size = desc_pool_size;
    for (i = 0; i < desc_pool_size; i++) {
        void *htt_tx_desc;
        void *htt_frag_desc;
        u_int32_t paddr_lo;

        htt_tx_desc = htt_tx_desc_assign(pdev->htt_pdev, i, &paddr_lo);
        if (! htt_tx_desc) {
            qdf_print("%s: failed to alloc HTT tx desc (%d of %d)\n",
                __func__, i, desc_pool_size);
            goto fail4;
            }
        pdev->tx_desc.array[i].tx_desc.htt_tx_desc = htt_tx_desc;

        htt_frag_desc = htt_tx_frag_assign(pdev->htt_pdev, i);
        if (! htt_frag_desc) {
            qdf_print("%s: failed to alloc HTT frag desc (%d of %d)\n",
                    __func__, i, desc_pool_size);
            goto fail4;
        }

        pdev->tx_desc.array[i].tx_desc.htt_frag_desc = htt_frag_desc;
        pdev->tx_desc.array[i].tx_desc.htt_tx_desc_paddr = paddr_lo;

#if WLAN_FEATURE_FASTPATH
        /* Initialize ID once for all */
        pdev->tx_desc.array[i].tx_desc.id = i;
        qdf_atomic_init(&pdev->tx_desc.array[i].tx_desc.ref_cnt);
#endif /* WLAN_FEATURE_FASTPATH */
    }

    /* link SW tx descs into a freelist */
    pdev->tx_desc.freelist = &pdev->tx_desc.array[0];
    for (i = 0; i < desc_pool_size-1; i++) {
        pdev->tx_desc.array[i].next = &pdev->tx_desc.array[i+1];
    }
    pdev->tx_desc.array[i].next = NULL;

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (pdev->nss_wifiol_ctx) {
        uint32_t htt_tx_desc_base_paddr;
        uint32_t htt_tx_desc_base_vaddr = (uint32_t)htt_tx_desc_assign(pdev->htt_pdev, 0, &htt_tx_desc_base_paddr);
        uint32_t htt_tx_desc_offset = sizeof(struct htt_host_tx_desc_t) ;
        if (osif_nss_ol_pdev_attach(scn, pdev->nss_wifiol_ctx, pdev->nss_wifiol_id,
                desc_pool_size, (uint32_t *)pdev->tx_desc.array,
                (uint32_t)htt_tx_desc_pool_paddr(pdev->htt_pdev),
                htt_tx_desc_frag_desc_size(pdev->htt_pdev),
                htt_tx_desc_base_vaddr, htt_tx_desc_base_paddr , htt_tx_desc_offset, pdev->htt_pdev->host_q_mem.pool_paddr)){
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NSS: Pdev attach failed");
            goto fail4;
        }
    }
#endif

#if (HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE)

    /* Allocating TSO desc pool of desc_pool_size/2, since only one TSO desc required per Jumbo frame
     *      * and each jumbo frame leads to a minimim of 2 TX data packets consuming 2 TX descriptors */
    pdev->tx_tso_desc.array = qdf_mem_malloc(
		    (desc_pool_size/2) * sizeof(union ol_tx_tso_desc_list_elem_t));
    if (!pdev->tx_tso_desc.array) {
	    goto fail4;
    }

    qdf_mem_set(
		    pdev->tx_tso_desc.array,
		    (desc_pool_size/2) * sizeof(union ol_tx_tso_desc_list_elem_t), 0);

    pdev->tx_tso_desc.pool_size = desc_pool_size/2;

    /* link SW tx tso descs into a freelist */
    pdev->tx_tso_desc.freelist = &pdev->tx_tso_desc.array[0];
    for (i = 0; i < pdev->tx_tso_desc.pool_size-1; i++) {
	    pdev->tx_tso_desc.array[i].next = &pdev->tx_tso_desc.array[i+1];
    }

    pdev->tx_tso_desc.array[i].next = NULL;
#endif /* HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE */

#if HOST_SW_SG_ENABLE

    /* Allocating SG desc pool of desc_pool_size */
    pdev->tx_sg_desc.array = qdf_mem_malloc(
		    (desc_pool_size) * sizeof(union ol_tx_sg_desc_list_elem_t));
    if (!pdev->tx_sg_desc.array) {
	    goto fail4;
    }

    qdf_mem_set(
		    pdev->tx_sg_desc.array,
		    (desc_pool_size) * sizeof(union ol_tx_sg_desc_list_elem_t), 0);

    pdev->tx_sg_desc.pool_size = desc_pool_size;

    /* link SW tx tso descs into a freelist */
    pdev->tx_sg_desc.freelist = &pdev->tx_sg_desc.array[0];
    for (i = 0; i < pdev->tx_sg_desc.pool_size-1; i++) {
	    pdev->tx_sg_desc.array[i].next = &pdev->tx_sg_desc.array[i+1];
    }

    pdev->tx_sg_desc.array[i].next = NULL;
#endif /* HOST_SW_SG_ENABLE */

    /* initialize the counter of the target's tx buffer availability */
    qdf_atomic_init(&pdev->target_tx_credit);
    qdf_atomic_add(
        ol_cfg_target_tx_credit(pdev->ctrl_pdev), &pdev->target_tx_credit);

    /* check what format of frames are expected to be delivered by the OS */
    pdev->rx_decap_mode = ol_cfg_pkt_type((ol_pdev_handle)pdev);

    /* Header Cache Initialization for LL cached  path*/
    HTT_FF_CACHE_INIT(pdev->htt_pdev, ol_cfg_pkt_type((ol_pdev_handle)pdev));

    /* setup the global rx defrag waitlist */
    TAILQ_INIT(&pdev->rx.defrag.waitlist);

    /* configure where defrag timeout and duplicate detection is handled */
    pdev->rx.flags.defrag_timeout_check = ol_cfg_rx_host_defrag_timeout_duplicate_check(ctrl_pdev);
    pdev->rx.flags.dup_check = ol_cfg_rx_host_defrag_timeout_duplicate_check(ctrl_pdev);

    /*
     * Determine what rx processing steps are done within the host.
     * Possibilities:
     * 1.  Nothing - rx->tx forwarding and rx PN entirely within target.
     *     (This is unlikely; even if the target is doing rx->tx forwarding,
     *     the host should be doing rx->tx forwarding too, as a back up for
     *     the target's rx->tx forwarding, in case the target runs short on
     *     memory, and can't store rx->tx frames that are waiting for missing
     *     prior rx frames to arrive.)
     * 2.  Just rx -> tx forwarding.
     *     This is the typical configuration for HL, and a likely
     *     configuration for LL STA or small APs (e.g. retail APs).
     * 3.  Both PN check and rx -> tx forwarding.
     *     This is the typical configuration for large LL APs.
     * Host-side PN check without rx->tx forwarding is not a valid
     * configuration, since the PN check needs to be done prior to
     * the rx->tx forwarding.
     */
    if (ol_cfg_rx_pn_check(pdev->ctrl_pdev)) {
        if (ol_cfg_rx_fwd_check(pdev->ctrl_pdev)) {
            /*
             * Both PN check and rx->tx forwarding done on host.
             */
            pdev->rx_opt_proc = ol_rx_pn_check;
        } else {
            qdf_print(
                "%s: invalid config: if rx PN check is on the host,"
                "rx->tx forwarding check needs to also be on the host.\n",
                __func__);
            goto fail5;
        }
    } else {
        /* PN check done on target */
        if (ol_cfg_rx_fwd_check(pdev->ctrl_pdev)) {
            /*
             * rx->tx forwarding done on host (possibly as
             * back-up for target-side primary rx->tx forwarding)
             */
            pdev->rx_opt_proc = ol_rx_fwd_check;
        } else {
            pdev->rx_opt_proc = ol_rx_deliver;
        }
    }

    /* Allocate space for holding monitor mode status for RX packets */
    pdev->monitor_vdev = NULL;
    pdev->rx_mon_recv_status = qdf_mem_malloc(
        sizeof(struct ieee80211_rx_status));
    if (pdev->rx_mon_recv_status == NULL) {
        goto fail5;
    }

    /* initialize mutexes for tx desc alloc and peer lookup */
    qdf_spinlock_create(&pdev->tx_mutex);
    qdf_spinlock_create(&pdev->peer_ref_mutex);
    qdf_spinlock_create(&pdev->mon_mutex);

    pdev->prot_an_tx_sent = ol_txrx_prot_an_attach(pdev, "xmit 802.3");
    pdev->prot_an_rx_sent = ol_txrx_prot_an_attach(pdev, "recv 802.3");

    if (OL_RX_REORDER_TRACE_ATTACH(pdev) != A_OK) {
        goto fail6;
    }

    if (OL_RX_PN_TRACE_ATTACH(pdev) != A_OK) {
        goto fail7;
    }

    if (scn->host_80211_enable)
    pdev->host_80211_enable = ol_scn_host_80211_enable_get(pdev->ctrl_pdev);

    if (scn->nss_nwifi_offload)
        pdev->nss_nwifi_offload = ol_scn_nss_nwifi_offload_get(pdev->ctrl_pdev);


    /*
     * WDI event attach
     */
    if ((ret = wdi_event_attach(pdev)) == A_ERROR) {
        qdf_print("WDI event attach unsuccessful\n");
    }

    /*
     * pktlog pdev initialization
     */
#ifndef REMOVE_PKT_LOG
     pdev->pl_dev = scn->pl_dev;
#endif
    /*
     * Initialize rx PN check characteristics for different security types.
     */
    qdf_mem_set(&pdev->rx_pn[0],sizeof(pdev->rx_pn), 0);

    /* TKIP: 48-bit TSC, CCMP: 48-bit PN */
    pdev->rx_pn[htt_sec_type_tkip].len =
        pdev->rx_pn[htt_sec_type_tkip_nomic].len =
        pdev->rx_pn[htt_sec_type_aes_ccmp].len =
        pdev->rx_pn[htt_sec_type_aes_ccmp_256].len =
        pdev->rx_pn[htt_sec_type_aes_gcmp].len =
        pdev->rx_pn[htt_sec_type_aes_gcmp_256].len = 48;

    pdev->rx_pn[htt_sec_type_tkip].cmp =
        pdev->rx_pn[htt_sec_type_tkip_nomic].cmp =
        pdev->rx_pn[htt_sec_type_aes_ccmp].cmp =
        pdev->rx_pn[htt_sec_type_aes_ccmp_256].cmp =
        pdev->rx_pn[htt_sec_type_aes_gcmp].cmp =
        pdev->rx_pn[htt_sec_type_aes_gcmp_256].cmp = ol_rx_pn_cmp48;

    /* WAPI: 128-bit PN */
    pdev->rx_pn[htt_sec_type_wapi].len = 128;
    pdev->rx_pn[htt_sec_type_wapi].cmp = ol_rx_pn_wapi_cmp;


#if ATH_SUPPORT_ME_FW_BASED
    /* Allocate mcast desc */
    if (!(scn->vow_config >> 16)) {
        pdev->max_mcast_desc = MAX_BLOCKED_MCAST_DESC;
    } else {
        pdev->max_mcast_desc =  ((scn->vow_config >> 16)* (MIN( scn->vow_config & 0xFFFF, MAX_BLOCKED_MCAST_VOW_DESC_PER_NODE)));
    }

    pdev->mcast_tx_desc = qdf_mem_malloc((pdev->max_mcast_desc * (sizeof(struct ol_tx_desc_t *))));
    if (!pdev->mcast_tx_desc) {
        goto fail7;
    }
#endif /*ATH_SUPPORT_ME_FW_BASED*/
    atomic_set(&pdev->mc_num_vap_attached,0);

    for (j=0; j<MAX_NUM_TXPOW_MGT_ENTRY ; j++)
        pdev->txpow_mgt_frm[j] = 0xFF;

    pdev->tid_override_queue_mapping = 0;
    pdev->fw_supported_enh_stats_version = HTT_T2H_EN_STATS_MAX_VER;
    TXRX_PRINT(TXRX_PRINT_LEVEL_INFO1, "Created pdev %p\n", pdev);
    TXRX_PRINT(TXRX_PRINT_LEVEL_INFO1, "TX stats version supported in FW %d\n", pdev->fw_supported_enh_stats_version);

    return pdev; /* success */

fail7:
    OL_RX_REORDER_TRACE_DETACH(pdev);

fail6:
    qdf_spinlock_destroy(&pdev->tx_mutex);
    qdf_spinlock_destroy(&pdev->peer_ref_mutex);
    qdf_spinlock_destroy(&pdev->mon_mutex);

    qdf_mem_free(pdev->rx_mon_recv_status);

fail5:
#if (HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE)
        qdf_mem_free(pdev->tx_tso_desc.array);
#endif /* HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE */
#if HOST_SW_SG_ENABLE
        qdf_mem_free(pdev->tx_sg_desc.array);
#endif /* HOST_SW_SG_ENABLE */

fail4:
    qdf_mem_free(pdev->tx_desc.array);

fail3:
    htt_detach(pdev->htt_pdev);

fail2:
    ol_txrx_peer_find_detach(pdev);

fail1:
    qdf_spinlock_destroy(&pdev->acnbufqlock);
#if PEER_FLOW_CONTROL
    ol_tx_pflow_ctrl_clean(pdev);
#endif
    qdf_mem_free(pdev);

fail0:
    return NULL; /* fail */
}

A_STATUS
ol_txrx_pdev_attach_target(ol_txrx_pdev_handle pdev)
{
    return htt_attach_target(pdev->htt_pdev);
}



void
ol_txrx_pdev_detach(ol_txrx_pdev_handle pdev, int force)
{
    int i;
    A_STATUS ret;
    /* preconditions */
    TXRX_ASSERT2(pdev);

    /* check that the pdev has no vdevs allocated */
    TXRX_ASSERT1(TAILQ_EMPTY(&pdev->vdev_list));

    if (force) {
        /*
         * The assertion above confirms that all vdevs within this pdev
         * were detached.  However, they may not have actually been deleted.
         * If the vdev had peers which never received a PEER_UNMAP message
         * from the target, then there are still zombie peer objects, and
         * the vdev parents of the zombie peers are also zombies, hanging
         * around until their final peer gets deleted.
         * Go through the peer hash table and delete any peers left in it.
         * As a side effect, this will complete the deletion of any vdevs
         * that are waiting for their peers to finish deletion.
         */
        TXRX_PRINT(TXRX_PRINT_LEVEL_INFO1, "Force delete for pdev %p\n", pdev);
        ol_txrx_peer_find_hash_erase(pdev);
    }

#if PEER_FLOW_CONTROL
    pdev->pflow_cong_ctrl_timer_interval = 0;
    qdf_timer_stop(&pdev->pflow_ctl_cong_timer);

    if(pdev->pflow_ctl_stats_timer_interval) {
        qdf_timer_stop(&pdev->pflow_ctl_stats_timer);
    }

    qdf_timer_free(&pdev->pflow_ctl_cong_timer);
    qdf_timer_free(&pdev->pflow_ctl_stats_timer);
#if PEER_FLOW_CONTROL_HOST_SCHED
    qdf_timer_stop(&pdev->pflow_ctl_dequeue_timer);
    qdf_timer_free(&pdev->pflow_ctl_dequeue_timer);
#endif
#endif

#if ATH_SUPPORT_ME_FW_BASED
    qdf_mem_free(pdev->mcast_tx_desc);
#endif /*ATH_SUPPORT_ME_FW_BASED*/

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (!pdev->nss_wifiol_ctx)
#endif
    {
        for (i = 0; i < pdev->tx_desc.pool_size; i++) {
            //void *htt_tx_desc;

            /*
             * Confirm that each tx descriptor is "empty", i.e. it has
             * no tx frame attached.
             * In particular, check that there are no frames that have
             * been given to the target to transmit, for which the
             * target has never provided a response.
             */
            if (qdf_atomic_read(&pdev->tx_desc.array[i].tx_desc.ref_cnt)) {
                TXRX_PRINT(TXRX_PRINT_LEVEL_WARN,
                        "Warning: freeing tx frame "
                        "(no tx completion from the target)\n");
                ol_tx_desc_frame_free_nonstd(
                        pdev, &pdev->tx_desc.array[i].tx_desc, 1);
            }

        }
    }

    qdf_spinlock_destroy(&pdev->acnbufqlock);

    qdf_mem_free(pdev->tx_desc.array);
#if (HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE)
    qdf_mem_free(pdev->tx_tso_desc.array);
#endif /* HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE */

#if HOST_SW_SG_ENABLE
    qdf_mem_free(pdev->tx_sg_desc.array);
#endif /* HOST_SW_SG_ENABLE */

#if ATH_SUPPORT_IQUE
    ol_tx_me_exit(pdev);
#endif /*ATH_SUPPORT_IQUE*/

    htt_detach(pdev->htt_pdev);

    ol_txrx_peer_find_detach(pdev);

    qdf_spinlock_destroy(&pdev->tx_mutex);
    qdf_spinlock_destroy(&pdev->peer_ref_mutex);
    qdf_spinlock_destroy(&pdev->mon_mutex);

    qdf_mem_free(pdev->rx_mon_recv_status);

    OL_TXRX_PROT_AN_FREE(pdev->prot_an_tx_sent);
    OL_TXRX_PROT_AN_FREE(pdev->prot_an_rx_sent);

    OL_RX_REORDER_TRACE_DETACH(pdev);
    OL_RX_PN_TRACE_DETACH(pdev);
    /*
     * WDI event detach
     */
    if ((ret = wdi_event_detach(pdev)) == A_ERROR) {
        qdf_print("WDI detach unsuccessful\n");
    }

    qdf_mem_free(pdev);
}

ol_txrx_vdev_handle
ol_txrx_vdev_attach(
    ol_txrx_pdev_handle pdev,
    u_int8_t *vdev_mac_addr,
    u_int8_t vdev_id,
    enum wlan_op_mode op_mode)
{
    struct ol_txrx_vdev_t *vdev;

    /* preconditions */
    TXRX_ASSERT2(pdev);
    TXRX_ASSERT2(vdev_mac_addr);

    vdev = qdf_mem_malloc(sizeof(*vdev));
    if (!vdev) {
        return NULL; /* failure */
    }

    /* store provided params */
    vdev->pdev = pdev;
    vdev->vdev_id = vdev_id;
    vdev->opmode = op_mode;

    vdev->osif_rx =     NULL;
    vdev->osif_rx_mon = NULL;
    vdev->osif_vdev =   NULL;

    vdev->delete.pending = 0;
    vdev->safemode = 0;
    vdev->drop_unenc = 1;
    vdev->filters_num = 0;
    vdev->htc_htt_hdr_size = HTC_HTT_TRANSFER_HDRSIZE;

    qdf_mem_copy(
        &vdev->mac_addr.raw[0], vdev_mac_addr, OL_TXRX_MAC_ADDR_LEN);

    vdev->tx_encap_type = ol_cfg_pkt_type((ol_pdev_handle)pdev);
    vdev->rx_decap_type = ol_cfg_pkt_type((ol_pdev_handle)pdev);
  /* Header cache update for each vdev */
    HTT_HDRCACHE_UPDATE(pdev, vdev);

#if 0 // BEELINER Specific
    if(vdev->opmode != wlan_op_mode_monitor) {
        vdev->pRateCtrl = NULL;

        if(pdev->ratectrl.is_ratectrl_on_host) {
            /* Attach the context for rate-control. */
            vdev->pRateCtrl = ol_ratectrl_vdev_ctxt_attach(pdev, vdev);

            if (!(vdev->pRateCtrl)) {
                /* failure case */
                qdf_mem_free(vdev);
                vdev = NULL;
                return NULL;
            }
        }

    }
#endif

    OS_MEMSET(vdev->txpow_mgt_frm, 0xff, sizeof(vdev->txpow_mgt_frm));
    TAILQ_INIT(&vdev->peer_list);

    /* add this vdev into the pdev's list */
    TAILQ_INSERT_TAIL(&pdev->vdev_list, vdev, vdev_list_elem);

    TXRX_PRINT(TXRX_PRINT_LEVEL_INFO1,
        "Created vdev %p (%02x:%02x:%02x:%02x:%02x:%02x)\n",
        vdev,
        vdev->mac_addr.raw[0], vdev->mac_addr.raw[1], vdev->mac_addr.raw[2],
        vdev->mac_addr.raw[3], vdev->mac_addr.raw[4], vdev->mac_addr.raw[5]);

    pdev->vdev_count = ((struct ol_ath_softc_net80211 *)(pdev->ctrl_pdev))->vdev_count;

    return vdev;
}

void
ol_txrx_vdev_register(
    ol_txrx_vdev_handle vdev,
    void *osif_vdev,
    struct ol_txrx_ops *txrx_ops)
{
    vdev->osif_vdev = osif_vdev;
    vdev->osif_rx = txrx_ops->rx.rx;
#if ATH_SUPPORT_WAPI
    vdev->osif_check_wai = txrx_ops->rx.wai_check;
#endif
    vdev->osif_rx_mon = txrx_ops->rx.mon;
#if UMAC_SUPPORT_PROXY_ARP
    vdev->osif_proxy_arp = txrx_ops->proxy_arp;
#endif
    if (ol_cfg_is_high_latency(vdev->pdev->ctrl_pdev)) {
        txrx_ops->tx.tx = vdev->tx = ol_tx_hl;
    } else {
        txrx_ops->tx.tx = vdev->tx = ol_tx_ll;
    }
}

int
ol_txrx_get_nwifi_mode(
    ol_txrx_vdev_handle vdev)
{
    ol_txrx_pdev_handle pdev = vdev->pdev;
    return pdev->nss_nwifi_offload;
}

int
ol_txrx_is_target_ar900b(
    ol_txrx_vdev_handle vdev)
{
    ol_txrx_pdev_handle pdev = vdev->pdev;
    return pdev->is_ar900b;
}


int
ol_txrx_set_monitor_mode(
    ol_txrx_vdev_handle vdev)
{
    /* Many monitor VAPs can exists in a system but only one can be up at
     * anytime
     */
    ol_txrx_pdev_handle pdev = vdev->pdev;
    ol_txrx_vdev_handle mon_vdev = pdev->monitor_vdev;
    wlan_if_t vap = NULL;

    /*Check if current pdev's monitor_vdev exists, and if it's already up*/
    if(mon_vdev){
        vap = ((osif_dev *)(mon_vdev->osif_vdev))->os_if;
        TXRX_ASSERT2(vap);
        if(ieee80211_vap_ready_is_set(vap)){
            qdf_print("Monitor mode VAP already up\n");
            return -1;
        }
    }

    qdf_spin_lock_bh(&pdev->mon_mutex);
    pdev->monitor_vdev = vdev;
    qdf_spin_unlock_bh(&pdev->mon_mutex);
    return 0;
}

int
ol_txrx_reset_monitor_mode(ol_txrx_pdev_handle pdev)
{
    /* Many monitor VAPs can exists in a system but only one can be up at
     * anytime
     */
    qdf_spin_lock_bh(&pdev->mon_mutex);
    pdev->monitor_vdev = NULL;
    qdf_spin_unlock_bh(&pdev->mon_mutex);
    return 0;
}

void ol_txrx_monitor_set_filter_ucast_data(ol_txrx_pdev_handle pdev, u_int8_t val)
{
   pdev->mon_filter_ucast_data = val;
}

void ol_txrx_monitor_set_filter_mcast_data(ol_txrx_pdev_handle pdev, u_int8_t val)
{
   pdev->mon_filter_mcast_data = val;
}

void ol_txrx_monitor_set_filter_non_data(ol_txrx_pdev_handle pdev, u_int8_t val)
{
   pdev->mon_filter_non_data = val;
}


u_int8_t ol_txrx_monitor_get_filter_ucast_data(ol_txrx_vdev_handle vdev)
{
   return vdev->pdev->mon_filter_ucast_data;
}

u_int8_t ol_txrx_monitor_get_filter_mcast_data(ol_txrx_vdev_handle vdev)
{
   return vdev->pdev->mon_filter_mcast_data;
}


u_int8_t ol_txrx_monitor_get_filter_non_data(ol_txrx_vdev_handle vdev)
{
   return vdev->pdev->mon_filter_non_data;
}

int
ol_txrx_set_filter_neighbour_peers(
    ol_txrx_pdev_handle pdev,
    u_int32_t val)
{
    pdev->filter_neighbour_peers = val;
    return 0;
}

void
ol_txrx_set_curchan(
    ol_txrx_pdev_handle pdev,
    u_int32_t chan_mhz)
{
    pdev->rx_mon_recv_status->rs_freq = chan_mhz;
    return;
}

void
ol_txrx_set_safemode(
    ol_txrx_vdev_handle vdev,
    u_int32_t val)
{
    vdev->safemode = val;
}

void
ol_txrx_set_tx_encap_type(ol_txrx_vdev_handle vdev, enum htt_pkt_type val)
{
#if QCA_OL_TX_CACHEDHDR
    u_int8_t sub_type = 0;
#endif /* QCA_OL_TX_CACHEDHDR */

    vdev->tx_encap_type = val;

#if QCA_OL_TX_CACHEDHDR
    HTT_HDRCACHE_UPDATE_PKTTYPE(vdev, val);

    if (val == htt_pkt_type_raw) {
        /* 802.11 MAC Header present. */
        sub_type |= 0x1 << HTT_TX_MSDU_DESC_RAW_SUBTYPE_80211_HDR_S;

        /* Don't allow aggregation. */
        sub_type |= 0x1 << HTT_TX_MSDU_DESC_RAW_SUBTYPE_NO_AGGR_S;

        /* Important note for end system integrators: The following encryption
         * related flag needs to be set, or kept clear, according to the desired
         * configuration.
         *
         * The flag is being kept clear in this code base since the reference
         * code does not interact with any external entity that could carry out
         * the requisite encryption.
         */
#if 0
        /* Illustration only. */
        if (condition) {
            /*  Don't perform encryption */
            sub_type |= 0x1 << HTT_TX_MSDU_DESC_RAW_SUBTYPE_NO_ENCRYPT_S;
        }
#endif /* 0 */
    }

    HTT_HDRCACHE_UPDATE_PKTSUBTYPE(vdev, sub_type);
#endif /* QCA_OL_TX_CACHEDHDR */
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    osif_nss_ol_vdev_set_cfg(vdev, OSIF_NSS_VDEV_ENCAP_TYPE);
    osif_nss_ol_vap_updchdhdr(vdev);
#endif

}

inline enum htt_pkt_type
ol_txrx_get_tx_encap_type(ol_txrx_vdev_handle vdev)
{
    return vdev->tx_encap_type;
}

void
ol_txrx_set_vdev_rx_decap_type(ol_txrx_vdev_handle vdev, enum htt_pkt_type val)
{
    vdev->rx_decap_type = val;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    osif_nss_ol_vdev_set_cfg(vdev, OSIF_NSS_VDEV_DECAP_TYPE);
    osif_nss_ol_vap_updchdhdr(vdev);
#endif
}

inline enum htt_pkt_type
ol_txrx_get_vdev_rx_decap_type(ol_txrx_vdev_handle vdev)
{
    return vdev->rx_decap_type;
}

#if MESH_MODE_SUPPORT
void
ol_txrx_set_mesh_mode(ol_txrx_vdev_handle vdev, u_int32_t val)
{
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s val %d \n",__func__,val);
    vdev->mesh_vdev = val;
    vdev->htc_htt_hdr_size = HTC_HTT_TRANSFER_HDRSIZE + HTT_EXTND_DESC_SIZE;
}
#endif

#if WDS_VENDOR_EXTENSION
void
ol_txrx_set_wds_rx_policy(
    ol_txrx_vdev_handle vdev,
    u_int32_t val)
{
    struct ol_txrx_peer_t *peer;
    if (vdev->opmode == wlan_op_mode_ap) {
        /* for ap, set it on bss_peer */
        TAILQ_FOREACH(peer, &vdev->peer_list, peer_list_elem) {
            if (peer->bss_peer) {
                peer->wds_rx_filter = 1;
                peer->wds_rx_ucast_4addr = (val & WDS_POLICY_RX_UCAST_4ADDR) ? 1:0;
                peer->wds_rx_mcast_4addr = (val & WDS_POLICY_RX_MCAST_4ADDR) ? 1:0;
                break;
            }
        }
    }
    else if (vdev->opmode == wlan_op_mode_sta) {
        peer = TAILQ_FIRST(&vdev->peer_list);
        peer->wds_rx_filter = 1;
        peer->wds_rx_ucast_4addr = (val & WDS_POLICY_RX_UCAST_4ADDR) ? 1:0;
        peer->wds_rx_mcast_4addr = (val & WDS_POLICY_RX_MCAST_4ADDR) ? 1:0;
    }
}
#endif

void
ol_txrx_set_privacy_filters(
    ol_txrx_vdev_handle vdev,
    void *filters,
    u_int32_t num)
{
     qdf_mem_copy(vdev->privacy_filters, filters, num*sizeof(privacy_exemption));
     vdev->filters_num = num;
}

void
ol_txrx_set_drop_unenc(
    ol_txrx_vdev_handle vdev,
    u_int32_t val)
{
    vdev->drop_unenc = val;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    osif_nss_ol_vdev_set_cfg(vdev, OSIF_NSS_VDEV_DROP_UNENC);
#endif

}

void
ol_txrx_vdev_detach(
    ol_txrx_vdev_handle vdev,
    ol_txrx_vdev_delete_cb callback,
    void *context)
{
    struct ol_txrx_pdev_t *pdev = vdev->pdev;

    /* preconditions */
    TXRX_ASSERT2(vdev);

    /* remove the vdev from its parent pdev's list */
    TAILQ_REMOVE(&pdev->vdev_list, vdev, vdev_list_elem);

    /*
     * Use peer_ref_mutex while accessing peer_list, in case
     * a peer is in the process of being removed from the list.
     */
    qdf_spin_lock_bh(&pdev->peer_ref_mutex);
    /* check that the vdev has no peers allocated */
    if (!TAILQ_EMPTY(&vdev->peer_list)) {
        /* debug print - will be removed later */
        TXRX_PRINT(TXRX_PRINT_LEVEL_INFO1,
            "%s: not deleting vdev object %p (%02x:%02x:%02x:%02x:%02x:%02x)"
            "until deletion finishes for all its peers\n",
            __func__, vdev,
            vdev->mac_addr.raw[0], vdev->mac_addr.raw[1],
            vdev->mac_addr.raw[2], vdev->mac_addr.raw[3],
            vdev->mac_addr.raw[4], vdev->mac_addr.raw[5]);
        /* indicate that the vdev needs to be deleted */
        vdev->delete.pending = 1;
        vdev->delete.callback = callback;
        vdev->delete.context = context;
        qdf_spin_unlock_bh(&pdev->peer_ref_mutex);
        return;
    }
    qdf_spin_unlock_bh(&pdev->peer_ref_mutex);

    TXRX_PRINT(TXRX_PRINT_LEVEL_INFO1,
        "%s: deleting vdev object %p (%02x:%02x:%02x:%02x:%02x:%02x)\n",
        __func__, vdev,
        vdev->mac_addr.raw[0], vdev->mac_addr.raw[1], vdev->mac_addr.raw[2],
        vdev->mac_addr.raw[3], vdev->mac_addr.raw[4], vdev->mac_addr.raw[5]);

#if 0 // BEELINER COMMENTED THIS
    /* Free the rate-control context. */
    ol_ratectrl_vdev_ctxt_detach(vdev->pRateCtrl);
#endif

    /*
     * Doesn't matter if there are outstanding tx frames -
     * they will be freed once the target sends a tx completion
     * message for them.
     */

    qdf_mem_free(vdev);
    if (callback) {
        callback(context);
    }
}

ol_txrx_peer_handle
ol_txrx_peer_attach(
    ol_txrx_vdev_handle vdev,
    u_int8_t *peer_mac_addr)
{
    struct ol_txrx_peer_t *peer;
    int i;
    ol_txrx_pdev_handle pdev;
    struct ol_ath_softc_net80211 *scn;

    /* preconditions */
    TXRX_ASSERT2(vdev);
    TXRX_ASSERT2(peer_mac_addr);

    pdev = vdev->pdev;
    scn = (struct ol_ath_softc_net80211 *)(pdev->ctrl_pdev);
/* CHECK CFG TO DETERMINE WHETHER TO ALLOCATE BASE OR EXTENDED PEER STRUCT */
/* USE vdev->pdev->osdev, AND REMOVE PDEV FUNCTION ARG? */
    peer = (struct ol_txrx_peer_t *)qdf_mempool_alloc(scn->qdf_dev, scn->mempool_ol_ath_peer);

    if (!peer) {
        return NULL; /* failure */
    }
    OS_MEMZERO(peer, sizeof(struct ol_txrx_peer_t));
    /* store provided params */
    peer->vdev = vdev;
    qdf_mem_copy(
        &peer->mac_addr.raw[0], peer_mac_addr, OL_TXRX_MAC_ADDR_LEN );

#if 0
    if(vdev->opmode != wlan_op_mode_monitor) {
        peer->rc_node = NULL;

        if(pdev->ratectrl.is_ratectrl_on_host) {
            /* Attach the context for rate-control. */
            peer->rc_node = ol_ratectrl_peer_ctxt_attach(pdev, vdev, peer);

            if (!(peer->rc_node)) {
                /* failure case */
                qdf_mem_free(peer);
                peer = NULL;
                return NULL;
            }
        }

    }
#endif

    peer->rx_opt_proc = pdev->rx_opt_proc;

    ol_rx_peer_init(pdev, peer);

    //ol_tx_peer_init(pdev, peer);

    /* initialize the peer_id */
    for (i = 0; i < MAX_NUM_PEER_ID_PER_PEER; i++) {
        peer->peer_ids[i] = HTT_INVALID_PEER;
    }

#if PEER_FLOW_CONTROL
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if(!pdev->nss_wifiol_ctx)
#endif
    {
        for (i = 0; i < OL_TX_PFLOW_CTRL_HOST_MAX_TIDS; i++) {
            peer->tidq[i].dequeue_cnt = 0;
            peer->tidq[i].byte_count = 0;
            qdf_nbuf_queue_init(&peer->tidq[i].nbufq);
        }
    }
#endif

    qdf_spin_lock_bh(&pdev->peer_ref_mutex);
    qdf_atomic_init(&peer->ref_cnt);

    /* keep one reference for attach */
    qdf_atomic_inc(&peer->ref_cnt);

    /* add this peer into the vdev's list */
    TAILQ_INSERT_TAIL(&vdev->peer_list, peer, peer_list_elem);
    qdf_spin_unlock_bh(&pdev->peer_ref_mutex);

    ol_txrx_peer_find_hash_add(pdev, peer);

    TXRX_PRINT(TXRX_PRINT_LEVEL_INFO2,
        "vdev %p created peer %p (%02x:%02x:%02x:%02x:%02x:%02x)\n",
        vdev, peer,
        peer->mac_addr.raw[0], peer->mac_addr.raw[1], peer->mac_addr.raw[2],
        peer->mac_addr.raw[3], peer->mac_addr.raw[4], peer->mac_addr.raw[5]);
    /*
     * For every peer MAp message search and set if bss_peer
     */
    if (memcmp(peer->mac_addr.raw, vdev->mac_addr.raw, 6) == 0){
        TXRX_PRINT(TXRX_PRINT_LEVEL_INFO2, "vdev bss_peer!!!! \n");
        peer->bss_peer = 1;
        vdev->vap_bss_peer = peer;
    }

    return peer;
}

void
ol_txrx_peer_authorize(struct ol_txrx_peer_t *peer, uint32_t authorize)
{
    struct ol_txrx_vdev_t *vdev = NULL;
    struct ol_txrx_pdev_t *pdev = NULL;

    if(peer!=NULL)
    {
        vdev = peer->vdev;
        pdev = vdev->pdev;

        qdf_spin_lock_bh(&pdev->peer_ref_mutex);
        peer->authorize = authorize ? 1 : 0;
#if ATH_BAND_STEERING
        peer->peer_bs_inact_flag = 0;
        peer->peer_bs_inact = pdev->pdev_bs_inact_reload;
#endif
        qdf_spin_unlock_bh(&pdev->peer_ref_mutex);
    }
}

void
ol_txrx_peer_update(struct ol_txrx_peer_t *peer,
        struct peer_ratectrl_params_t *peer_ratectrl_params)
{
}

#if WDS_VENDOR_EXTENSION
void
ol_txrx_peer_wds_tx_policy_update(struct ol_txrx_peer_t *peer,
        int wds_tx_ucast, int wds_tx_mcast)
{
    if (wds_tx_ucast || wds_tx_mcast) {
        peer->wds_enabled = 1;
        peer->wds_tx_ucast_4addr = wds_tx_ucast;
        peer->wds_tx_mcast_4addr = wds_tx_mcast;
    }
    else {
        peer->wds_enabled = 0;
        peer->wds_tx_ucast_4addr = 0;
        peer->wds_tx_mcast_4addr = 0;
    }
    return;
}
#endif

void
ol_txrx_peer_unref_delete(ol_txrx_peer_handle peer)
{
    struct ol_txrx_vdev_t *vdev;
    struct ol_txrx_pdev_t *pdev;
    struct ol_ath_softc_net80211 *scn;
    struct ol_txrx_peer_t *tmppeer;
    int found = 0;

    u_int16_t peer_id;

    /* preconditions */
    TXRX_ASSERT2(peer);

    vdev = peer->vdev;
    pdev = vdev->pdev;
    scn = (struct ol_ath_softc_net80211 *)(pdev->ctrl_pdev);

    /*
     * Hold the lock all the way from checking if the peer ref count
     * is zero until the peer references are removed from the hash
     * table and vdev list (if the peer ref count is zero).
     * This protects against a new HL tx operation starting to use the
     * peer object just after this function concludes it's done being used.
     * Furthermore, the lock needs to be held while checking whether the
     * vdev's list of peers is empty, to make sure that list is not modified
     * concurrently with the empty check.
     */
    qdf_spin_lock_bh(&pdev->peer_ref_mutex);
    if (qdf_atomic_dec_and_test(&peer->ref_cnt)) {
        peer_id = peer->peer_ids[0];

        /*
         * Make sure that the reference to the peer in
         * peer object map is removed
         */
        if (peer_id != HTT_INVALID_PEER) {
            /*
             * Use a PDEV Tx Lock here, because peer used in Tx path for peer/TID enqueue and dequeu
             */
            OL_TX_PEER_UPDATE_LOCK(pdev, peer_id);
            pdev->peer_id_to_obj_map[peer_id] = NULL;
            OL_TX_PEER_UPDATE_UNLOCK(pdev, peer_id);
        }

        TXRX_PRINT(TXRX_PRINT_LEVEL_INFO2,
            "Deleting peer %p (%02x:%02x:%02x:%02x:%02x:%02x)\n",
            peer,
            peer->mac_addr.raw[0], peer->mac_addr.raw[1],
            peer->mac_addr.raw[2], peer->mac_addr.raw[3],
            peer->mac_addr.raw[4], peer->mac_addr.raw[5]);

#if QCA_PARTNER_DIRECTLINK_RX
            /* provide peer unref delete information to partner side */
            if (CE_is_directlink(pdev->ce_tx_hdl)) {
                ol_txrx_peer_unref_delete_partner(peer);
            }
#endif /* QCA_PARTNER_DIRECTLINK_RX */

        /* remove the reference to the peer from the hash table */
        ol_txrx_peer_find_hash_remove(pdev, peer);

        TAILQ_FOREACH(tmppeer, &peer->vdev->peer_list, peer_list_elem) {
                if (tmppeer == peer) {
                        found = 1;
                        break;
                }
        }
        if (found) {
             TAILQ_REMOVE(&peer->vdev->peer_list, peer, peer_list_elem);
        } else {
             /*Ignoring the remove operation as peer not found*/
             QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WARN peer %p not found in vdev (%p)->peer_list:%p\n", peer, vdev,
                        &peer->vdev->peer_list);
        }

        /* cleanup the Rx reorder queues for this peer */
        ol_rx_peer_cleanup(vdev, peer);

        /* check whether the parent vdev has no peers left */
        if (TAILQ_EMPTY(&vdev->peer_list)) {
            /*
             * Now that there are no references to the peer, we can
             * release the peer reference lock.
             */
            qdf_spin_unlock_bh(&pdev->peer_ref_mutex);
            /*
             * Check if the parent vdev was waiting for its peers to be
             * deleted, in order for it to be deleted too.
             */
            if (vdev->delete.pending) {
                ol_txrx_vdev_delete_cb vdev_delete_cb = vdev->delete.callback;
                void *vdev_delete_context = vdev->delete.context;

                TXRX_PRINT(TXRX_PRINT_LEVEL_INFO1,
                    "%s: deleting vdev object %p "
                    "(%02x:%02x:%02x:%02x:%02x:%02x)"
                    " - its last peer is done\n",
                    __func__, vdev,
                    vdev->mac_addr.raw[0], vdev->mac_addr.raw[1],
                    vdev->mac_addr.raw[2], vdev->mac_addr.raw[3],
                    vdev->mac_addr.raw[4], vdev->mac_addr.raw[5]);
                /* all peers are gone, go ahead and delete it */
                qdf_mem_free(vdev);
                if (vdev_delete_cb) {
                    vdev_delete_cb(vdev_delete_context);
                }
            }
        } else {
            qdf_spin_unlock_bh(&pdev->peer_ref_mutex);
        }
        qdf_mempool_free(scn->qdf_dev, scn->mempool_ol_ath_peer, peer);

        qdf_atomic_inc(&scn->peer_count);
    } else {
        qdf_spin_unlock_bh(&pdev->peer_ref_mutex);
    }
}

void
ol_txrx_peer_detach(ol_txrx_peer_handle peer)
{

    /* redirect the peer's rx delivery function to point to a discard func */
    peer->rx_opt_proc = ol_rx_discard;

    TXRX_PRINT(TXRX_PRINT_LEVEL_INFO2,
        "%s:peer %p (%02x:%02x:%02x:%02x:%02x:%02x)\n",
          __func__, peer,
          peer->mac_addr.raw[0], peer->mac_addr.raw[1],
          peer->mac_addr.raw[2], peer->mac_addr.raw[3],
          peer->mac_addr.raw[4], peer->mac_addr.raw[5]);

#if 0 // BEELINER COMMENTED THIS
    /* Free the rate-control context. */
    ol_ratectrl_peer_ctxt_detach(peer->rc_node);
#endif

    /*
     * Remove the reference added during peer_attach.
     * The peer will still be left allocated until the
     * PEER_UNMAP message arrives to remove the other
     * reference, added by the PEER_MAP message.
     */
    ol_txrx_peer_unref_delete(peer);
}

int
ol_txrx_get_tx_pending(ol_txrx_pdev_handle pdev_handle)
{
    struct ol_txrx_pdev_t *pdev = (ol_txrx_pdev_handle)pdev_handle;
    union ol_tx_desc_list_elem_t *p_tx_desc;
    int total;
    int unused = 0;

    total = ol_cfg_target_tx_credit(pdev->ctrl_pdev);

    /*
    * Iterate over the tx descriptor freelist to see how many are available,
    * and thus by inference, how many are in use.
    * This iteration is inefficient, but this code is called during
    * cleanup, when performance is not paramount.  It is preferable
    * to do have a large inefficiency during this non-critical
    * cleanup stage than to have lots of little inefficiencies of
    * updating counters during the performance-critical tx "fast path".
    *
    * Use the lock to ensure there are no new allocations made while
    * we're trying to count the number of allocations.
    * This function is expected to be used only during cleanup, at which
    * time there should be no new allocations made, but just to be safe...
    */
    qdf_spin_lock_bh(&pdev->tx_mutex);
    p_tx_desc = pdev->tx_desc.freelist;
    while (p_tx_desc) {
        p_tx_desc = p_tx_desc->next;
        unused++;
    }
    qdf_spin_unlock_bh(&pdev->tx_mutex);

    return (total - unused);

}

/*--- debug features --------------------------------------------------------*/

unsigned g_txrx_print_level = TXRX_PRINT_LEVEL_INFO1; /* default */

void ol_txrx_print_level_set(unsigned level)
{
#if !TXRX_PRINT_ENABLE
    qdf_print(
        "The driver is compiled without TXRX prints enabled.\n"
        "To enable them, recompile with TXRX_PRINT_ENABLE defined.\n");
#else
    qdf_print("TXRX printout level changed from %d to %d\n",
        g_txrx_print_level, level);
    g_txrx_print_level = level;
#endif
}

static inline
u_int64_t OL_TXRX_STATS_PTR_TO_U64(struct ol_txrx_stats_req_internal *req)
{
    return (u_int64_t) ((size_t) req);
}

static inline
struct ol_txrx_stats_req_internal * OL_TXRX_U64_TO_STATS_PTR(u_int64_t cookie)
{
    return (struct ol_txrx_stats_req_internal *) ((size_t) cookie);
}

void
ol_txrx_fw_stats_cfg(
    ol_txrx_vdev_handle vdev,
    u_int8_t cfg_stats_type,
    u_int32_t cfg_val)
{
    u_int64_t dummy_cookie = 0;
    htt_h2t_dbg_stats_get(
        vdev->pdev->htt_pdev,
        0 /* upload mask */,
        0 /* reset mask */,
        cfg_stats_type,
        cfg_val,
        dummy_cookie,
        0 /* vdevid */);
}

A_STATUS
ol_txrx_fw_stats_get(
    ol_txrx_vdev_handle vdev,
    struct ol_txrx_stats_req *req,
    bool per_vdev,
    bool response_expected)
{
    struct ol_txrx_pdev_t *pdev = vdev->pdev;
    u_int64_t cookie;
    struct ol_txrx_stats_req_internal *non_volatile_req;
    struct ol_ath_softc_net80211 *scn = NULL;
    int32_t mutex_ret = 0;
    u_int8_t vdev_id;

    if (!pdev ||
        req->stats_type_upload_mask >= 1 << HTT_DBG_NUM_STATS ||
        req->stats_type_reset_mask >= 1 << HTT_DBG_NUM_STATS )
    {
        return A_ERROR;
    }

/*
 * If per vap stats is requested send vdev+1 as vdevid to FW.
 * Since FW sends consolidated radio stats on vdevid 0
 * For example if stats is requested for vdev 1, send 2 to FW.
 * This logic need to be fixed and 1->1 mapping to be introduced.
 */
    if (per_vdev){
       vdev_id = vdev->vdev_id + 1;
    } else {
       vdev_id = 0;
    }
    scn = (struct ol_ath_softc_net80211 *) pdev->ctrl_pdev;
    /*
     * Allocate a non-transient stats request object.
     * (The one provided as an argument is likely allocated on the stack.)
     */
    non_volatile_req = qdf_mem_malloc(sizeof(*non_volatile_req));
    if (! non_volatile_req) {
        return A_NO_MEMORY;
    }
    /* copy the caller's specifications */
    non_volatile_req->base = *req;
    non_volatile_req->serviced = 0;
    non_volatile_req->offset = 0;

    /* use the non-volatile request object's address as the cookie */
    cookie = OL_TXRX_STATS_PTR_TO_U64(non_volatile_req);
    if (htt_h2t_dbg_stats_get(
            pdev->htt_pdev,
            req->stats_type_upload_mask,
            req->stats_type_reset_mask,
            HTT_H2T_STATS_REQ_CFG_STAT_TYPE_INVALID, 0,
            cookie, (u_int32_t)vdev_id))
    {
        qdf_mem_free(non_volatile_req);
        return A_ERROR;
    }

    if (req->wait.blocking) {
        /* if fw hang, apps e.g. athstats will totally hang the whole AP, user has to power cycle the AP,
           mutex acquire here should timeout in 3000ms */
        mutex_ret = qdf_semaphore_acquire_timeout(&scn->scn_stats_sem, 3000);
    }

    if (!req->stats_type_upload_mask) {
        qdf_mem_free(non_volatile_req);
    }

    if (mutex_ret){
        return A_EBUSY;
    }else{
        return A_OK;
    }
}

#if WLAN_FEATURE_FASTPATH

#if PEER_FLOW_CONTROL
A_STATUS
ol_txrx_host_msdu_ttl_stats(
    ol_txrx_vdev_handle vdev,
    struct ol_txrx_stats_req *req)
{
    struct ol_txrx_pdev_t *pdev = vdev->pdev;

    if(pdev) {
        /* Display MSDU TTL counter */
        qdf_print("### HOST MSDU TTL Stats ###\nHost_msdu_ttl     :\t%d\n",pdev->pflow_msdu_ttl_cnt);
    }
    return 0;
}
#endif

A_STATUS
ol_txrx_host_stats_get(
    ol_txrx_vdev_handle vdev,
    struct ol_txrx_stats_req *req)
{
    struct ol_txrx_pdev_t *pdev = vdev->pdev;
    struct ol_txrx_stats *stats = &pdev->stats.pub;
    u_int8_t i;
    struct ol_ath_softc_net80211 *scn =
                (struct ol_ath_softc_net80211 *) pdev->ctrl_pdev;

    if(!stats)
	    return -1;

    qdf_print("++++++++++ CE STATISTICS +++++++++++\n");
    for (i=0;i<STATS_MAX_RX_CES;i++) {
       /* print only 8 CE stats for Peregrine */
       if ((scn->target_type == TARGET_TYPE_AR9888) &&
                      (i >= STATS_MAX_RX_CES_PEREGRINE)) {
           break;
       }
       qdf_print("CE%d Host sw_index (dst_ring):     %d\n",i, scn->pkt_stats.sw_index[i]);
       qdf_print("CE%d Host write_index (dst_ring):  %d\n",i, scn->pkt_stats.write_index[i]);
    }

    /* HACK */
    qdf_print("++++++++++ HOST TX STATISTICS +++++++++++\n");
    qdf_print("Ol Tx Desc In Use\t:  %u\n", stats->tx.desc_in_use);
    qdf_print("Ol Tx Desc Failed\t:  %u\n", stats->tx.desc_alloc_fails);
    qdf_print("CE Ring (4) Full \t:  %u\n", stats->tx.ce_ring_full);
    qdf_print("DMA Map Error    \t:  %u\n", stats->tx.dma_map_error);
    qdf_print("Tx pkts completed\t:  %llu\n", stats->tx.delivered.pkts);
    qdf_print("Tx bytes completed\t:  %llu\n", stats->tx.delivered.bytes);
    qdf_print("Tx pkts from stack\t:  %llu\n", stats->tx.from_stack.pkts);

    qdf_print("\n");
    qdf_print("++++++++++ HOST RX STATISTICS +++++++++++\n");
    qdf_print("Rx pkts completed\t:  %llu\n", stats->rx.delivered.pkts);
    qdf_print("Rx bytes completed\t:  %llu\n", stats->rx.delivered.bytes);

    qdf_print("++++++++++ HOST FLOW CONTROL STATISTICS +++++++++++\n");
    qdf_print("Receive from stack count: %llu\n", stats->tx.from_stack.pkts);
    qdf_print("non queued pkt count: %u\n", stats->tx.fl_ctrl.fl_ctrl_avoid);
    qdf_print("queued pkt count: %u\n", stats->tx.fl_ctrl.fl_ctrl_enqueue);
    qdf_print("queue overflow count: %u\n", stats->tx.fl_ctrl.fl_ctrl_discard);
    return 0;
}
void
ol_txrx_host_stats_clr(ol_txrx_vdev_handle vdev)
{
    struct ol_txrx_pdev_t *pdev = vdev->pdev;
    struct ol_txrx_stats *stats = &pdev->stats.pub;

    /* Tx */
    stats->tx.desc_in_use = 0;
    stats->tx.desc_alloc_fails = 0;
    stats->tx.ce_ring_full = 0;
    stats->tx.dma_map_error = 0;
    stats->tx.delivered.pkts = 0;
    stats->tx.delivered.bytes = 0;
    stats->tx.from_stack.pkts = 0;
    stats->tx.from_stack.bytes = 0;

    /* Rx */
    stats->rx.delivered.pkts = 0;
    stats->rx.delivered.bytes = 0;
    stats->tx.fl_ctrl.fl_ctrl_avoid = 0;
    stats->tx.fl_ctrl.fl_ctrl_enqueue = 0;
    stats->tx.fl_ctrl.fl_ctrl_discard = 0;
#if PEER_FLOW_CONTROL
    pdev->pflow_msdu_ttl_cnt = 0;
#endif
}


void
ol_txrx_host_ce_stats(ol_txrx_vdev_handle vdev)
{
}

#if ATH_SUPPORT_IQUE
A_STATUS
ol_txrx_host_me_stats(
    ol_txrx_vdev_handle vdev)
{
    struct ol_txrx_pdev_t *pdev = vdev->pdev;
    struct ol_txrx_stats *stats = &pdev->stats.pub;

    if(stats) {
        /* HACK */
        qdf_print("++++++++++ HOST MCAST Ehance STATISTICS +++++++++++\n");
        qdf_print("Mcast recieved\t: %d\n", stats->mcast_enhance.num_me_rcvd);
        qdf_print("ME converted\t: %d\n", stats->mcast_enhance.num_me_ucast);
        qdf_print("ME dropped (Map)\t: %d\n", stats->mcast_enhance.num_me_dropped_m);
        qdf_print("ME dropped (alloc)\t: %d\n", stats->mcast_enhance.num_me_dropped_a);
        qdf_print("ME dropped(internal)\t: %d\n", stats->mcast_enhance.num_me_dropped_i);
        qdf_print("ME dropped(own address)\t: %d\n", stats->mcast_enhance.num_me_dropped_s);
        qdf_print("ME bufs in use\t: %d\n", stats->mcast_enhance.num_me_buf);
        qdf_print("ME bufs in non pool allocation in use\t: %d\n", stats->mcast_enhance.num_me_nonpool);
        qdf_print("ME bufs in non pool allocation\t: %d\n", stats->mcast_enhance. num_me_nonpool_count);
        qdf_print("\n");
    }

    return 0;
}
#endif
#endif

int
ol_txrx_fw_stats_handler(
    ol_txrx_pdev_handle pdev,
    u_int64_t cookie,
    u_int8_t *stats_info_list,
    u_int32_t vdev_id)
{
    enum htt_dbg_stats_type type;
    enum htt_dbg_stats_status status;
    int length;
    u_int8_t *stats_data;
#if OL_STATS_WORK_QUEUE
    void *stats_buffer = NULL, *stats_wqp = NULL;
#endif
    struct ol_txrx_stats_req_internal *req;
    int more = 0;
    struct ol_ath_softc_net80211 *scn =
                (struct ol_ath_softc_net80211 *) pdev->ctrl_pdev;

    req = OL_TXRX_U64_TO_STATS_PTR(cookie);
    do {
        htt_t2h_dbg_stats_hdr_parse(
            stats_info_list, &type, &status, &length, &stats_data);
        if (status == HTT_DBG_STATS_STATUS_SERIES_DONE) {
            break;
        }
        if (status == HTT_DBG_STATS_STATUS_PRESENT ||
            status == HTT_DBG_STATS_STATUS_PARTIAL)
        {
            u_int8_t *buf;
            int bytes = 0;

            if (status == HTT_DBG_STATS_STATUS_PARTIAL) {
                more = 1;
            }

            if ((status != HTT_DBG_STATS_STATUS_PARTIAL) &&
                (req->base.print.verbose || req->base.print.concise)) {
                /* provide the header along with the data */
#if OL_STATS_WORK_QUEUE
#define STATS_LENGTH (4 * 1024)
                {
                    stats_wqp = qdf_mem_malloc(sizeof(qdf_work_t));
                    if(!stats_wqp) {
                        htt_t2h_stats_print(stats_info_list, req->base.print.concise, scn->target_type, vdev_id);
                        break;
                    }
                    stats_buffer = qdf_mem_malloc(STATS_LENGTH);
                    if(!stats_buffer) {
                        htt_t2h_stats_print(stats_info_list, req->base.print.concise, scn->target_type, vdev_id);
                        qdf_mem_free(stats_wqp);
                        break;
                    }

                    *(uint32_t *)stats_buffer       = (uint32_t)stats_wqp;
                    *(uint32_t *)((uint8_t *)stats_buffer + 4) = (uint32_t)scn;
                    *(uint32_t *)((uint8_t *)stats_buffer + 8) = (uint32_t)vdev_id;
                    qdf_create_work(pdev->osdev, stats_wqp,
                            stats_deferred_work, stats_buffer);
                    qdf_mem_copy(((uint8_t *)stats_buffer + 12), stats_info_list, length);
                    qdf_sched_work(pdev->osdev, stats_wqp);
                }
#else
                htt_t2h_stats_print(stats_info_list, req->base.print.concise, scn->target_type, vdev_id);
#endif
            }
            switch (type) {
            case HTT_DBG_STATS_WAL_PDEV_TXRX:
                bytes = sizeof(struct wlan_dbg_stats);
                if (req->base.copy.buf) {
                    int limit;

                    limit = sizeof(struct wlan_dbg_stats);
                    if (req->base.copy.byte_limit < limit) {
                        limit = req->base.copy.byte_limit;
                    }
                    buf = req->base.copy.buf + req->offset;
                    qdf_mem_copy(buf, stats_data, limit);
                }
                break;
            case HTT_DBG_STATS_RX_REORDER:
                bytes = sizeof(struct rx_reorder_stats);
                if (req->base.copy.buf) {
                    int limit;

                    limit = sizeof(struct rx_reorder_stats);
                    if (req->base.copy.byte_limit < limit) {
                        limit = req->base.copy.byte_limit;
                    }
                    buf = req->base.copy.buf + req->offset;
                    qdf_mem_copy(buf, stats_data, limit);
                }
                break;
            case HTT_DBG_STATS_RX_RATE_INFO:
                bytes = sizeof(wlan_dbg_rx_rate_info_t);
                if (req->base.copy.buf) {
                    int limit;

                    limit = sizeof(wlan_dbg_rx_rate_info_t);
                    if (req->base.copy.byte_limit < limit) {
                        limit = req->base.copy.byte_limit;
                    }
                    buf = req->base.copy.buf + req->offset;
                    qdf_mem_copy(buf, stats_data, limit);
                }
                break;

            case HTT_DBG_STATS_TX_RATE_INFO:
                bytes = sizeof(wlan_dbg_tx_rate_info_t);
                if (req->base.copy.buf) {
                    int limit;

                    limit = sizeof(wlan_dbg_tx_rate_info_t);
                    if (req->base.copy.byte_limit < limit) {
                        limit = req->base.copy.byte_limit;
                    }
                    buf = req->base.copy.buf + req->offset;
                    qdf_mem_copy(buf, stats_data, limit);
                }
                break;
	     case HTT_DBG_STATS_TIDQ:
                bytes = sizeof(struct wlan_dbg_tidq_stats);
                if (req->base.copy.buf) {
#ifdef BIG_ENDIAN_HOST
                    struct wlan_dbg_tidq_stats *tidq_stats = NULL;
                    int *tmp_word = NULL;
                    int *tmp_word1 = NULL;
                    u_int16_t *tmp_short = NULL;
                    int i;
#endif
                    int limit;

                    limit = sizeof(struct wlan_dbg_tidq_stats);
                    if (req->base.copy.byte_limit < limit) {
                        limit = req->base.copy.byte_limit;
                    }
                    buf = req->base.copy.buf + req->offset;
                    qdf_mem_copy(buf, stats_data, limit);
#ifdef BIG_ENDIAN_HOST
                    tidq_stats = (struct wlan_dbg_tidq_stats *)buf;

                    tmp_word = (int *)&tidq_stats->txq_st.num_pkts_queued[0];
                    for(i = 0; i < DBG_STATS_MAX_HWQ_NUM/sizeof(u_int16_t); i++)
                    {
                        *tmp_word = __le32_to_cpu(*tmp_word);
                        tmp_short = (u_int16_t *)tmp_word;
                        *tmp_short = __le16_to_cpu(*tmp_short);
                        tmp_short++;
                        *tmp_short = __le16_to_cpu(*tmp_short);

                        tmp_word++;
                    }

                    tmp_word = (int *)&tidq_stats->txq_st.tid_sw_qdepth[0];
                    tmp_word1 = (int *)&tidq_stats->txq_st.tid_hw_qdepth[0];
                    for(i = 0; i < DBG_STATS_MAX_TID_NUM/sizeof(u_int16_t); i++)
                    {
                        *tmp_word = __le32_to_cpu(*tmp_word);
                        tmp_short = (u_int16_t *)tmp_word;
                        *tmp_short = __le16_to_cpu(*tmp_short);
                        tmp_short++;
                        *tmp_short = __le16_to_cpu(*tmp_short);

                        *tmp_word1 = __le32_to_cpu(*tmp_word1);
                        tmp_short = (u_int16_t *)tmp_word1;
                        *tmp_short = __le16_to_cpu(*tmp_short);
                        tmp_short++;
                        *tmp_short = __le16_to_cpu(*tmp_short);

                        tmp_word++;
                        tmp_word1++;
                    }
#endif
                }
                break;

             case HTT_DBG_STATS_TXBF_INFO:
                bytes = sizeof(struct wlan_dbg_txbf_data_stats);
                if (req->base.copy.buf) {
                    int limit;

                    limit = sizeof(struct wlan_dbg_txbf_data_stats);
                    if (req->base.copy.byte_limit < limit) {
                        limit = req->base.copy.byte_limit;
                    }
                    buf = req->base.copy.buf + req->offset;
                    qdf_mem_copy(buf, stats_data, limit);
                }
                break;

             case HTT_DBG_STATS_SND_INFO:
                bytes = sizeof(struct wlan_dbg_txbf_snd_stats);
                if (req->base.copy.buf) {
                    int limit;

                    limit = sizeof(struct wlan_dbg_txbf_snd_stats);
                    if (req->base.copy.byte_limit < limit) {
                        limit = req->base.copy.byte_limit;
                    }
                    buf = req->base.copy.buf + req->offset;
                    qdf_mem_copy(buf, stats_data, limit);
                }
                break;

             case HTT_DBG_STATS_TX_SELFGEN_INFO:
                bytes = sizeof(struct wlan_dbg_tx_selfgen_stats);
                if (req->base.copy.buf) {
                    int limit;

                    limit = sizeof(struct wlan_dbg_tx_selfgen_stats);
                    if (req->base.copy.byte_limit < limit) {
                        limit = req->base.copy.byte_limit;
                    }
                    buf = req->base.copy.buf + req->offset;
                    qdf_mem_copy(buf, stats_data, limit);
                }
                break;

             case HTT_DBG_STATS_TX_MU_INFO:
                bytes = sizeof(struct wlan_dbg_tx_mu_stats);
                if (req->base.copy.buf) {
                    int limit;

                    limit = sizeof(struct wlan_dbg_tx_mu_stats);
                    if (req->base.copy.byte_limit < limit) {
                        limit = req->base.copy.byte_limit;
                    }
                    buf = req->base.copy.buf + req->offset;
                    qdf_mem_copy(buf, stats_data, limit);
                }
                break;

             case HTT_DBG_STATS_SIFS_RESP_INFO:
                bytes = sizeof(wlan_dgb_sifs_resp_stats_t);
                if (req->base.copy.buf) {
                    int limit;

                    limit = sizeof(wlan_dgb_sifs_resp_stats_t);
                    if (req->base.copy.byte_limit < limit) {
                        limit = req->base.copy.byte_limit;
                    }
                    buf = req->base.copy.buf + req->offset;
                    qdf_mem_copy(buf, stats_data, limit);
                }
                break;

             case HTT_DBG_STATS_TX_PPDU_LOG:
                bytes = 0; /* TO DO: specify how many bytes are present */
                /* TO DO: add copying to the requestor's buffer */
                break;

             case HTT_DBG_STATS_ERROR_INFO:
                bytes = sizeof(wlan_dbg_wifi2_error_stats_t);
                if (req->base.copy.buf) {
                    int limit;

                    limit = sizeof(wlan_dbg_wifi2_error_stats_t);
                    if (req->base.copy.byte_limit < limit) {
                        limit = req->base.copy.byte_limit;
                    }
                    buf = req->base.copy.buf + req->offset;
                    qdf_mem_copy(buf, stats_data, limit);
                }
                break;

             case HTT_DBG_STATS_RESET_INFO:
                bytes = sizeof(wlan_dbg_reset_stats_t);
                if (req->base.copy.buf) {
                    int limit;

                    limit = sizeof(wlan_dbg_reset_stats_t);
                    if (req->base.copy.byte_limit < limit) {
                        limit = req->base.copy.byte_limit;
                    }
                    buf = req->base.copy.buf + req->offset;
                    qdf_mem_copy(buf, stats_data, limit);
                }
                break;

             case HTT_DBG_STATS_MAC_WDOG_INFO:
                bytes = sizeof(wlan_dbg_mac_wdog_stats_t);
                if (req->base.copy.buf) {
                    int limit;

                    limit = sizeof(wlan_dbg_mac_wdog_stats_t);
                    if (req->base.copy.byte_limit < limit) {
                        limit = req->base.copy.byte_limit;
                    }
                    buf = req->base.copy.buf + req->offset;
                    qdf_mem_copy(buf, stats_data, limit);
                }
                break;

             case HTT_DBG_STATS_TX_DESC_INFO:
                bytes = sizeof(wlan_dbg_tx_desc_stats_t);
                if (req->base.copy.buf) {
                    int limit;

                    limit = sizeof(wlan_dbg_tx_desc_stats_t);
                    if (req->base.copy.byte_limit < limit) {
                        limit = req->base.copy.byte_limit;
                    }
                    buf = req->base.copy.buf + req->offset;
                    qdf_mem_copy(buf, stats_data, limit);
                }
                break;

             case HTT_DBG_STATS_TX_FETCH_MGR_INFO:
                bytes = sizeof(wlan_dbg_tx_fetch_mgr_stats_t);
                if (req->base.copy.buf) {
                    int limit;

                    limit = sizeof(wlan_dbg_tx_fetch_mgr_stats_t);
                    if (req->base.copy.byte_limit < limit) {
                        limit = req->base.copy.byte_limit;
                    }
                    buf = req->base.copy.buf + req->offset;
                    qdf_mem_copy(buf, stats_data, limit);
                }
                break;

             case HTT_DBG_STATS_TX_PFSCHED_INFO:
                bytes = sizeof(wlan_dbg_tx_pf_sched_stats_t);
                if (req->base.copy.buf) {
                    int limit;

                    limit = sizeof(wlan_dbg_tx_pf_sched_stats_t);
                    if (req->base.copy.byte_limit < limit) {
                        limit = req->base.copy.byte_limit;
                    }
                    buf = req->base.copy.buf + req->offset;
                    qdf_mem_copy(buf, stats_data, limit);
                }
                break;

             case HTT_DBG_STATS_TX_PATH_STATS_INFO:
                bytes = sizeof(wlan_dbg_tx_path_stats_t);
                if (req->base.copy.buf) {
                    int limit;

                    limit = sizeof(wlan_dbg_tx_path_stats_t);
                    if (req->base.copy.byte_limit < limit) {
                        limit = req->base.copy.byte_limit;
                    }
                    buf = req->base.copy.buf + req->offset;
                    qdf_mem_copy(buf, stats_data, limit);
                }
                break;

            case HTT_DBG_STATS_HALPHY_INFO:
               bytes = sizeof(wlan_halphy_dbg_stats_t);
               if (req->base.copy.buf) {
                   int limit;

                   limit = sizeof(wlan_halphy_dbg_stats_t);
                   if (req->base.copy.byte_limit < limit) {
                       limit = req->base.copy.byte_limit;
                   }
                   buf = req->base.copy.buf + req->offset;
                   qdf_mem_copy(buf, stats_data, limit);
               }
               break;

            default:
                break;
            }
            buf = req->base.copy.buf ? req->base.copy.buf : stats_data;
            if (req->base.callback.fp) {
                req->base.callback.fp(
                    req->base.callback.ctxt, type, buf, bytes);
            }
        }
        stats_info_list += length;
    } while (1);

    if (! more) {
        if (req->base.wait.blocking) {
            qdf_semaphore_release(&scn->scn_stats_sem);
        }
        qdf_mem_free(req);
    }

    return more;
}

int ol_txrx_debug(ol_txrx_vdev_handle vdev, int debug_specs)
{
    if (debug_specs & TXRX_DBG_MASK_OBJS) {
        #if TXRX_DEBUG_LEVEL > 5
            ol_txrx_pdev_display(vdev->pdev, 0);
        #else
            qdf_print(
                "The pdev,vdev,peer display functions are disabled.\n"
                "To enable them, recompile with TXRX_DEBUG_LEVEL > 5.\n");
        #endif
    }
    if (debug_specs & TXRX_DBG_MASK_STATS) {
        #if TXRX_STATS_LEVEL != TXRX_STATS_LEVEL_OFF
            ol_txrx_stats_display(vdev->pdev);
        #else
            qdf_print(
                "txrx stats collection is disabled.\n"
                "To enable it, recompile with TXRX_STATS_LEVEL on.\n");
        #endif
    }
    if (debug_specs & TXRX_DBG_MASK_PROT_ANALYZE) {
        #if defined(ENABLE_TXRX_PROT_ANALYZE)
            ol_txrx_prot_ans_display(vdev->pdev);
        #else
            qdf_print(
                "txrx protocol analysis is disabled.\n"
                "To enable it, recompile with "
                "ENABLE_TXRX_PROT_ANALYZE defined.\n");
        #endif
    }
    if (debug_specs & TXRX_DBG_MASK_RX_REORDER_TRACE) {
        #if defined(ENABLE_RX_REORDER_TRACE)
            ol_rx_reorder_trace_display(vdev->pdev, 0, 0);
        #else
            qdf_print(
                "rx reorder seq num trace is disabled.\n"
                "To enable it, recompile with "
                "ENABLE_RX_REORDER_TRACE defined.\n");
        #endif

    }
    return 0;
}

int ol_txrx_aggr_cfg(ol_txrx_vdev_handle vdev,
                     int max_subfrms_ampdu,
                     int max_subfrms_amsdu)
{
    return htt_h2t_aggr_cfg_msg(vdev->pdev->htt_pdev,
                                max_subfrms_ampdu,
                                max_subfrms_amsdu);
}

#if TXRX_DEBUG_LEVEL > 5
void
ol_txrx_pdev_display(ol_txrx_pdev_handle pdev, int indent)
{
    struct ol_txrx_vdev_t *vdev;

    qdf_print("%*s%s:\n", indent, " ", "txrx pdev");
    qdf_print("%*spdev object: %p\n", indent+4, " ", pdev);
    qdf_print("%*svdev list:\n", indent+4, " ");
    TAILQ_FOREACH(vdev, &pdev->vdev_list, vdev_list_elem) {
        ol_txrx_vdev_display(vdev, indent+8);
    }
    ol_txrx_peer_find_display(pdev, indent+4);
    qdf_print("%*stx desc pool: %d elems @ %p\n", indent+4, " ",
        pdev->tx_desc.pool_size, pdev->tx_desc.array);
    qdf_print("\n");
    htt_display(pdev->htt_pdev, indent);
}

void
ol_txrx_vdev_display(ol_txrx_vdev_handle vdev, int indent)
{
    struct ol_txrx_peer_t *peer;

    qdf_print("%*stxrx vdev: %p\n", indent, " ", vdev);
    qdf_print("%*sID: %d\n", indent+4, " ", vdev->vdev_id);
    qdf_print("%*sMAC addr: %d:%d:%d:%d:%d:%d\n",
        indent+4, " ",
        vdev->mac_addr.raw[0], vdev->mac_addr.raw[1], vdev->mac_addr.raw[2],
        vdev->mac_addr.raw[3], vdev->mac_addr.raw[4], vdev->mac_addr.raw[5]);
    qdf_print("%*speer list:\n", indent+4, " ");
    TAILQ_FOREACH(peer, &vdev->peer_list, peer_list_elem) {
        ol_txrx_peer_display(peer, indent+8);
    }
}

void
ol_txrx_peer_display(ol_txrx_peer_handle peer, int indent)
{
    int i;

    qdf_print("%*stxrx peer: %p\n", indent, " ", peer);
    for (i = 0; i < MAX_NUM_PEER_ID_PER_PEER; i++) {
        if (peer->peer_ids[i] != HTT_INVALID_PEER) {
            qdf_print("%*sID: %d\n", indent+4, " ", peer->peer_ids[i]);
        }
    }
}

#endif /* TXRX_DEBUG_LEVEL */

#if TXRX_STATS_LEVEL != TXRX_STATS_LEVEL_OFF
void
ol_txrx_stats_display(ol_txrx_pdev_handle pdev)
{
    qdf_print("txrx stats:\n");
    if (TXRX_STATS_LEVEL == TXRX_STATS_LEVEL_BASIC) {
        qdf_print("  tx: %llu msdus (%llu B)\n",
            pdev->stats.pub.tx.delivered.pkts,
            pdev->stats.pub.tx.delivered.bytes);
    } else { /* full */
        qdf_print(
            "  tx: sent %llu msdus (%llu B), "
            "rejected %llu (%llu B), dropped %llu (%llu B)\n",
            pdev->stats.pub.tx.delivered.pkts,
            pdev->stats.pub.tx.delivered.bytes,
            pdev->stats.pub.tx.dropped.host_reject.pkts,
            pdev->stats.pub.tx.dropped.host_reject.bytes,
            pdev->stats.pub.tx.dropped.download_fail.pkts
              + pdev->stats.pub.tx.dropped.target_discard.pkts
              + pdev->stats.pub.tx.dropped.no_ack.pkts,
            pdev->stats.pub.tx.dropped.download_fail.bytes
              + pdev->stats.pub.tx.dropped.target_discard.bytes
              + pdev->stats.pub.tx.dropped.no_ack.bytes);
        qdf_print(
            "    download fail: %llu (%llu B), "
            "target discard: %llu (%llu B), "
            "no ack: %llu (%llu B)\n",
            pdev->stats.pub.tx.dropped.download_fail.pkts,
            pdev->stats.pub.tx.dropped.download_fail.bytes,
            pdev->stats.pub.tx.dropped.target_discard.pkts,
            pdev->stats.pub.tx.dropped.target_discard.bytes,
            pdev->stats.pub.tx.dropped.no_ack.pkts,
            pdev->stats.pub.tx.dropped.no_ack.bytes);
    }
    qdf_print(
        "  rx: %lld ppdus, %lld mpdus, %llu msdus, %llu bytes, %lld errs\n",
        pdev->stats.priv.rx.normal.ppdus,
        pdev->stats.priv.rx.normal.mpdus,
        pdev->stats.pub.rx.delivered.pkts,
        pdev->stats.pub.rx.delivered.bytes,
        pdev->stats.priv.rx.err.mpdu_bad);
    if (TXRX_STATS_LEVEL == TXRX_STATS_LEVEL_FULL) {
        qdf_print(
            "    forwarded %llu msdus, %llu bytes\n",
            pdev->stats.pub.rx.forwarded.pkts,
            pdev->stats.pub.rx.forwarded.bytes);
    }
}

int
ol_txrx_stats_publish(ol_txrx_pdev_handle pdev, struct ol_txrx_stats *buf)
{
    qdf_assert(buf);
    qdf_assert(pdev);
    qdf_mem_copy(buf, &pdev->stats.pub, sizeof(pdev->stats.pub));
    return TXRX_STATS_LEVEL;
}

#endif /* TXRX_STATS_LEVEL */

#if RX_CHECKSUM_OFFLOAD
void
ol_print_rx_cksum_stats(
		ol_txrx_vdev_handle vdev)
{
	struct ol_txrx_pdev_t *pdev = vdev->pdev;
	struct ol_txrx_stats *stats = &pdev->stats.pub;

    if(!stats)
        return;
	qdf_print("++++++++++ RX Checksum Error STATISTICS +++++++++++\n");
	qdf_print(
			"    ipv4_cksum_err %llu msdus, %llu bytes\n",
			stats->rx.ipv4_cksum_err.pkts,
			stats->rx.ipv4_cksum_err.bytes);
	qdf_print(
			"    tcp_ipv4_cksum_err %llu msdus, %llu bytes\n",
			stats->rx.tcp_ipv4_cksum_err.pkts,
			stats->rx.tcp_ipv4_cksum_err.bytes);
	qdf_print(
			"    tcp_ipv6_cksum_err %llu msdus, %llu bytes\n",
			stats->rx.tcp_ipv6_cksum_err.pkts,
			stats->rx.tcp_ipv6_cksum_err.bytes);
	qdf_print(
			"    udp_ipv4_cksum_err %llu msdus, %llu bytes\n",
			stats->rx.udp_ipv4_cksum_err.pkts,
			stats->rx.udp_ipv4_cksum_err.bytes);
	qdf_print(
			"    udp_ipv6_cksum_err %llu msdus, %llu bytes\n",
			stats->rx.udp_ipv6_cksum_err.pkts,
			stats->rx.udp_ipv6_cksum_err.bytes);
}

void
ol_rst_rx_cksum_stats(ol_txrx_vdev_handle vdev)
{
	struct ol_txrx_pdev_t *pdev = vdev->pdev;
	struct ol_txrx_stats *stats = &pdev->stats.pub;

	qdf_print(".....Resetting RX Checksum Error Stats \n");
	/* Rx */
	stats->rx.ipv4_cksum_err.pkts = 0;
	stats->rx.ipv4_cksum_err.bytes = 0;
	stats->rx.tcp_ipv4_cksum_err.pkts = 0;
	stats->rx.tcp_ipv4_cksum_err.bytes = 0;
	stats->rx.tcp_ipv6_cksum_err.pkts = 0;
	stats->rx.tcp_ipv6_cksum_err.bytes = 0;
	stats->rx.udp_ipv4_cksum_err.pkts = 0;
	stats->rx.udp_ipv4_cksum_err.bytes = 0;
	stats->rx.udp_ipv6_cksum_err.pkts = 0;
	stats->rx.udp_ipv6_cksum_err.bytes = 0;
}
#endif /* RX_CHECKSUM_OFFLOAD */

#if defined(ENABLE_TXRX_PROT_ANALYZE)

void
ol_txrx_prot_ans_display(ol_txrx_pdev_handle pdev)
{
    ol_txrx_prot_an_display(pdev->prot_an_tx_sent);
    ol_txrx_prot_an_display(pdev->prot_an_rx_sent);
}

#endif /* ENABLE_TXRX_PROT_ANALYZE */

void
ol_txrx_enable_enhanced_stats(ol_txrx_pdev_handle pdev)
{
    pdev->ap_stats_tx_cal_enable = 1;
}

void
ol_txrx_disable_enhanced_stats(ol_txrx_pdev_handle pdev)
{
    pdev->ap_stats_tx_cal_enable = 0;
}

#if ATH_BAND_STEERING
/**
 * @brief Update the physical device's inactivity threshold.
 * @details
 *   It will also update the inactivity count of all nodes associated
 *   on this radio. It will check node's remaining inactivity count,
 *   and mark the node as inactive if it has been idle longer than the
 *   new threshold.
 *
 * @pre pdev is valid
 *
 * @param pdev - the data physical device object
 * @param new_threshold - the new inactivity threshold
 */
static void
ol_txrx_update_inact_threshold(ol_txrx_pdev_handle pdev,
                               u_int16_t new_threshold)
{
    struct ol_txrx_vdev_t *vdev;
    struct ol_txrx_peer_t *peer;
    u_int16_t old_threshold = pdev->pdev_bs_inact_reload;

    if (old_threshold == new_threshold) {
        return;
    }

    pdev->pdev_bs_inact_reload = new_threshold;

    qdf_spin_lock_bh(&pdev->peer_ref_mutex);
    TAILQ_FOREACH(vdev, &pdev->vdev_list, vdev_list_elem) {
        if (vdev->opmode != wlan_op_mode_ap) {
            continue;
        }
        TAILQ_FOREACH(peer, &vdev->peer_list, peer_list_elem) {
            if (!peer->authorize) {
                continue;
            }
            if (old_threshold - peer->peer_bs_inact >=
                new_threshold) {
                ol_txrx_mark_peer_inact(peer, true);
                peer->peer_bs_inact = 0;
            } else {
                peer->peer_bs_inact = new_threshold -
                    (old_threshold - peer->peer_bs_inact);
            }
        }
    }
    qdf_spin_unlock_bh(&pdev->peer_ref_mutex);
}

/**
 * @brief Reset all nodes' inactvity count to reload value
 * @details
 *   For all nodes associated on this radio, reset the inactivity count
 *   to the reload value.
 *
 * @pre pdev is valid
 *
 * @param pdev - the data physical device object
 */
static void
ol_txrx_reset_inact_count(ol_txrx_pdev_handle pdev)
{
    struct ol_txrx_vdev_t *vdev = NULL;
    struct ol_txrx_peer_t *peer = NULL;

    qdf_spin_lock_bh(&pdev->peer_ref_mutex);
    TAILQ_FOREACH(vdev, &pdev->vdev_list, vdev_list_elem) {
        if (vdev->opmode != wlan_op_mode_ap) {
            continue;
        }
        TAILQ_FOREACH(peer, &vdev->peer_list, peer_list_elem) {
            if (!peer->authorize) {
                continue;
            }
            peer->peer_bs_inact = pdev->pdev_bs_inact_reload;
        }
    }
    qdf_spin_unlock_bh(&pdev->peer_ref_mutex);
}

void
ol_txrx_set_overload(ol_txrx_pdev_handle pdev,
                     bool overload)
{
    if (!pdev) {
        return;
    }
    ol_txrx_update_inact_threshold(pdev, overload ? pdev->pdev_bs_inact_overload :
                                                    pdev->pdev_bs_inact_normal);
}

bool
ol_txrx_start_inact_timer(ol_txrx_pdev_handle pdev,
                          bool enable)
{
    if (!pdev) {
        return false;
    }

    if (enable) {
        ol_txrx_reset_inact_count(pdev);
        OS_SET_TIMER(&(pdev->pdev_bs_inact_timer),
                     pdev->pdev_bs_inact_interval * 1000);
    } else {
        OS_CANCEL_TIMER(&(pdev->pdev_bs_inact_timer));
    }

    return true;
}

bool
ol_txrx_set_inact_params(ol_txrx_pdev_handle pdev,
                         u_int16_t inact_check_interval,
                         u_int16_t inact_normal,
                         u_int16_t inact_overload)
{
    if (!pdev) {
        return false;
    }

    pdev->pdev_bs_inact_interval = inact_check_interval;
    pdev->pdev_bs_inact_normal = inact_normal;
    pdev->pdev_bs_inact_overload = inact_overload;

    ol_txrx_update_inact_threshold(pdev, pdev->pdev_bs_inact_normal);

    return true;
}

void
ol_txrx_mark_peer_inact(ol_txrx_peer_handle peer,
                        bool inactive)
{
    struct ol_txrx_pdev_t *pdev;
    bool inactive_old;

    if (peer == NULL) {
        return;
    }

    pdev = peer->vdev->pdev;
    inactive_old = peer->peer_bs_inact_flag == 1;
    if (!inactive) {
        peer->peer_bs_inact = pdev->pdev_bs_inact_reload;
    }
    peer->peer_bs_inact_flag = inactive ? 1 : 0;
    if (inactive_old != inactive) {
        struct ieee80211com *ic;
        struct ol_ath_softc_net80211 * scn;
        scn = (struct ol_ath_softc_net80211 *)pdev->ctrl_pdev;
        ic = &scn->sc_ic;
        // Note: a node lookup can happen in RX datapath context when a node changes
        // from inactive to active (at most once per inactivity timeout threshold).
        ieee80211_bsteering_record_act_change(ic, peer->mac_addr.raw, !inactive);
    }
}

bool
ol_txrx_peer_is_inact(ol_txrx_peer_handle peer)
{
    if (peer == NULL) {
        return false;
    }
    return peer->peer_bs_inact_flag == 1;
}
#endif /* ATH_BAND_STEERING */

#if ENHANCED_STATS
uint32_t* ol_txrx_get_en_stats_base(ol_txrx_pdev_handle txrx_pdev, uint32_t* stats_base, uint32_t msg_len, enum htt_t2h_en_stats_type *type,  enum htt_t2h_en_stats_status *status)
{
    htt_t2h_dbg_enh_stats_hdr_parse(stats_base, type, status);
    return (ol_txrx_get_stats_base(txrx_pdev, stats_base, msg_len, *type));
}

uint32_t* ol_txrx_get_stats_base(ol_txrx_pdev_handle txrx_pdev, uint32_t* stats_base, uint32_t msg_len, uint8_t type)
{
    int len = msg_len;
    uint8_t stat_type, status;
    uint16_t stat_len;
    uint32_t *msg_word;
    int found = 0;
    msg_word = stats_base;

#define EN_ST_ROUND_UP_TO_4(val) (((val) + 3) & ~0x3)

    /*Convert it to DWORD */
    len = len>>2;

    /*skip first word. It is already checked by the caller*/
    msg_word = msg_word + 1;

    stat_type = HTT_T2H_EN_STATS_CONF_TLV_TYPE_GET(*msg_word);
    status = HTT_T2H_EN_STATS_CONF_TLV_STATUS_GET(*msg_word);
    stat_len = HTT_T2H_EN_STATS_CONF_TLV_LENGTH_GET(*msg_word);


    while( status != HTT_T2H_EN_STATS_STATUS_SERIES_DONE ) {

        if (type == stat_type) {
            found = 1;
            break;
        }

        len  = EN_ST_ROUND_UP_TO_4(stat_len);
        len = len >> 2;
        msg_word = (msg_word + 1 + len);

        stat_type = HTT_T2H_EN_STATS_CONF_TLV_TYPE_GET(*msg_word);
        status = HTT_T2H_EN_STATS_CONF_TLV_STATUS_GET(*msg_word);
        stat_len = HTT_T2H_EN_STATS_CONF_TLV_LENGTH_GET(*msg_word);
    }

    if (found) {
        return (msg_word+1);
    } else {
        return NULL;
    }
}
#endif

