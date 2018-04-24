/*
 * Copyright (c) 2012-2017 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc
 */

/*
 * 2012, 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef REMOVE_PKT_LOG
#include "qdf_mem.h"
#include "athdefs.h"
#include "hif.h"
#include "ath_pci.h"
#include "a_debug.h"
#include <pktlog_ac_i.h>
#include <linux_remote_pktlog.h>
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include "osif_nss_wifiol_if.h"
#endif
static struct ath_pktlog_info *g_pktlog_info = NULL;
static int g_pktlog_mode = PKTLOG_MODE_SYSTEM;
extern int ol_ath_target_start(struct ol_ath_softc_net80211 *scn);

void pktlog_init(struct ol_ath_softc_net80211 *scn);
int pktlog_enable(struct ol_ath_softc_net80211 *scn, int32_t log_state);
int pktlog_setsize(struct ol_ath_softc_net80211 *scn, int32_t log_state);
int pktlog_disable(struct ol_ath_softc_net80211 *scn);
void pktlog_deinit(struct ol_ath_softc_net80211 *scn);
int pktlog_text(struct ol_ath_softc_net80211 *scn, char *text);
//extern void pktlog_disable_adapter_logging(void);
//extern void pktlog_disable_adapter_logging(void);
//extern int pktlog_alloc_buf(ol_ath_generic_softc_handle sc,
 //                                struct ath_pktlog_info *pl_info);
//void pktlog_release_buf(struct ath_pktlog_info *pl_info);
//extern void pktlog_release_buf(void *pinfo);
#ifdef CONFIG_AR900B_SUPPORT
static QDF_STATUS pktlog_hif_callback(void *pdev, wbuf_t wbuf, u_int8_t pipeID);
#endif
#ifdef CONFIG_AR900B_SUPPORT
struct hif_msg_callbacks hif_pipe_callbacks;
#endif

struct ol_pl_arch_dep_funcs ol_pl_funcs = {
    .pktlog_init = pktlog_init,
    .pktlog_enable = pktlog_enable,
    .pktlog_setsize = pktlog_setsize,
    .pktlog_disable = pktlog_disable, //valid for f/w disable
    .pktlog_deinit = pktlog_deinit,
    .pktlog_text = pktlog_text,
    /*.pktlog_start = pktlog_start,
    .pktlog_readhdr = pktlog_read_hdr,
    .pktlog_readbuf = pktlog_read_buf,*/
};

struct ol_pktlog_dev_t ol_pl_dev = {
    .pl_funcs = &ol_pl_funcs,
};

void ol_pl_sethandle(ol_pktlog_dev_t **pl_handle,
                    struct ol_ath_softc_net80211 *scn)
{
    *pl_handle = (ol_pktlog_dev_t *)qdf_mem_malloc(sizeof(ol_pktlog_dev_t));
    if (*pl_handle == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: pktlog initialization failed\n", __func__);
        return;
    }
    (*pl_handle)->scn = (struct ol_ath_generic_softc_t*)scn;
    (*pl_handle)->sc_osdev = scn->sc_osdev;
    (*pl_handle)->pl_funcs = &ol_pl_funcs;
}

void ol_pl_freehandle(ol_pktlog_dev_t *pl_handle)
{
    if (pl_handle) {
         qdf_mem_free(pl_handle);
    }
}

static inline A_STATUS pktlog_enable_tgt(
        struct ol_ath_softc_net80211 *_scn,
        uint32_t log_state)
{
    uint32_t types = 0;
    if (log_state & ATH_PKTLOG_TX) {
        types |= WMI_HOST_PKTLOG_EVENT_TX;
    }
    if (log_state & ATH_PKTLOG_RX) {
        types |= WMI_HOST_PKTLOG_EVENT_RX;
    }
    if (log_state & ATH_PKTLOG_RCFIND) {
        types |= WMI_HOST_PKTLOG_EVENT_RCF;
    }
    if (log_state & ATH_PKTLOG_RCUPDATE) {
        types |= WMI_HOST_PKTLOG_EVENT_RCU;
    }
#if 0
    if(log_state & ATH_PKTLOG_DBG_PRINT) {
        /* Debuglog buffer size is 1500 bytes. This exceeds the 512 bytes size limit when transferred via HTT.
         * Disable this to avoid target assert.
         */
        types |= WMI_HOST_PKTLOG_EVENT_DBG_PRINT;
    }
#endif
    if (log_state & ATH_PKTLOG_TX_CAPTURE_ENABLE) {
        types |= WMI_HOST_PKTLOG_EVENT_TX_DATA_CAPTURE;
    }

    if (_scn->is_ar900b) {

        if (log_state & ATH_PKTLOG_CBF) {
            types |= WMI_HOST_PKTLOG_EVENT_RX;
        }
        if (log_state & ATH_PKTLOG_H_INFO) {
            types |= WMI_HOST_PKTLOG_EVENT_H_INFO;
        }
        if (log_state & ATH_PKTLOG_STEERING) {
            types |= WMI_HOST_PKTLOG_EVENT_STEERING;
        }
    }

    if (pktlog_wmi_send_enable_cmd(_scn, types)) {
            return A_ERROR;
    }

    return A_OK;
}

static inline A_STATUS wdi_pktlog_subscribe(
        struct ol_txrx_pdev_t *txrx_pdev, int32_t log_state)
{
    struct ol_pktlog_dev_t *pl_dev = NULL;

    if (!txrx_pdev) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Invalid pdev in %s\n", __FUNCTION__);
        return A_ERROR;
    }

    pl_dev = txrx_pdev->pl_dev;
    if (!pl_dev) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Invalid pl_dev in %s\n", __FUNCTION__);
        return A_ERROR;
    }


    if((log_state & ATH_PKTLOG_TX)            ||
            (log_state & ATH_PKTLOG_RCFIND)   ||
            (log_state & ATH_PKTLOG_RCUPDATE) ||
            (log_state & ATH_PKTLOG_RX)       ||
            (log_state & ATH_PKTLOG_TX_CAPTURE_ENABLE)) {
        if(wdi_event_sub(txrx_pdev,
                    &(pl_dev->PKTLOG_OFFLOAD_SUBSCRIBER),
                    WDI_EVENT_OFFLOAD_ALL)) {
            return A_ERROR;
        }
    }

    if(log_state & ATH_PKTLOG_RX) {
        if(wdi_event_sub(txrx_pdev,
                    &(pl_dev->PKTLOG_RX_REMOTE_SUBSCRIBER),
                    WDI_EVENT_RX_DESC_REMOTE)) {
            return A_ERROR;
        }

        if (txrx_pdev->is_ar900b) {
        if ((log_state & ATH_PKTLOG_CBF)      ||
            (log_state & ATH_PKTLOG_H_INFO)   ||
            (log_state & ATH_PKTLOG_STEERING))
        {
               if(wdi_event_sub(txrx_pdev,
                            &(pl_dev->PKTLOG_RX_CBF_SUBSCRIBER),
                       WDI_EVENT_RX_CBF_REMOTE)) {
                      return A_ERROR;
               }
        }
        }

    }
    return A_OK;
}

#ifdef CONFIG_AR900B_SUPPORT
#define CE_PKTLOG_PIPE 8
static inline A_STATUS hif_pktlog_subscribe(
                struct ol_ath_softc_net80211 *scn)
{
    struct hif_opaque_softc *sc = ( struct hif_opaque_softc *) scn->hif_hdl;
    struct ol_txrx_pdev_t *txrx_pdev = scn->pdev_txrx_handle;

    if(!sc) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Invalid sc in %s\n", __FUNCTION__);
        return A_ERROR;
    }

    hif_pipe_callbacks.rxCompletionHandler = pktlog_hif_callback;
    hif_pipe_callbacks.Context = txrx_pdev;
    hif_update_pipe_callback(sc, CE_PKTLOG_PIPE, &hif_pipe_callbacks);

    return A_OK;
}
#endif

int pktlog_text(struct ol_ath_softc_net80211 *scn, char *text)
{
    struct ol_txrx_pdev_t *txrx_pdev = NULL;
    txrx_pdev = scn->pdev_txrx_handle;

    if(process_text_info((void *)txrx_pdev, text))  {
        return A_ERROR;
    }

    return A_OK;
}

void
pktlog_callback(void *pdev, enum WDI_EVENT event, void *log_data, u_int16_t peer_id, enum htt_rx_status status)
{
    switch(event) {
        case WDI_EVENT_RX_DESC_REMOTE:
        {
             /*
              * process RX message for remote frames
              */
            if(process_rx_info_remote(pdev, log_data)) {
                AR_DEBUG_PRINTF(ATH_DEBUG_TRC, (" Unable to process RX info \n"));
                return;
            }
           break;
        }
        case WDI_EVENT_OFFLOAD_ALL:
        {
            /*
             * process all offload pktlog
             */
            if(process_offload_pktlog(pdev, log_data)) {
                AR_DEBUG_PRINTF(ATH_DEBUG_TRC, (" Unable to process offload pktlog \n"));
                return;
            }
            break;
        }
        case WDI_EVENT_RX_CBF_REMOTE:
        {
             /*
              * process RX message for remote frames
              */
            if(process_rx_cbf_remote(pdev, log_data)) {
                AR_DEBUG_PRINTF(ATH_DEBUG_TRC, (" Unable to process RX cbf \n"));
                return;
            }
           break;
        }

        default:
            break;
    }
}


#ifdef CONFIG_AR900B_SUPPORT
static QDF_STATUS
pktlog_hif_callback(void *pdev, qdf_nbuf_t netbuf, u_int8_t pipeID)
{
    uint8_t       *netdata;
    uint32_t      netlen;
    A_STATUS rc = A_OK;
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)
                                        ((struct ol_txrx_pdev_t *) pdev)->ctrl_pdev;
    ol_pktlog_dev_t *pl_dev = scn->pl_dev;

    ASSERT(pipeID == CE_PKTLOG_PIPE);

    netdata = qdf_nbuf_data(netbuf);
    netlen = qdf_nbuf_len(netbuf);
    if( pl_dev->tgt_pktlog_enabled == true ) {
        rc = process_offload_pktlog(pdev, netdata);
    }
    if (rc != A_CONSUMED) {
        qdf_nbuf_free(netbuf);
    }
    return rc;
}
#endif

static inline A_STATUS
wdi_pktlog_unsubscribe(struct ol_txrx_pdev_t *txrx_pdev, uint32_t log_state)
{
    struct ol_pktlog_dev_t *pl_dev = NULL;

    pl_dev = txrx_pdev ? txrx_pdev->pl_dev : NULL;
    if (!pl_dev) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Invalid pl_dev in %s\n", __FUNCTION__);
        return A_ERROR;
    }

    if((log_state & ATH_PKTLOG_TX)       ||
            (log_state & ATH_PKTLOG_RCFIND)   ||
            (log_state & ATH_PKTLOG_RCUPDATE) ||
            (log_state & ATH_PKTLOG_RX)) {
        if(wdi_event_unsub(txrx_pdev,
                    &(pl_dev->PKTLOG_OFFLOAD_SUBSCRIBER),
                    WDI_EVENT_OFFLOAD_ALL)) {
            return A_ERROR;
        }
    }
    if(log_state & ATH_PKTLOG_RX) {
        if(wdi_event_unsub(
                    txrx_pdev,
                    &(pl_dev->PKTLOG_RX_REMOTE_SUBSCRIBER),
                    WDI_EVENT_RX_DESC_REMOTE)) {
            return A_ERROR;
        }

        if (txrx_pdev->is_ar900b) {
        if ((log_state & ATH_PKTLOG_CBF)      ||
            (log_state & ATH_PKTLOG_H_INFO)   ||
                    (log_state & ATH_PKTLOG_STEERING)) {
               if(wdi_event_unsub(
                       txrx_pdev,
                            &(pl_dev->PKTLOG_RX_CBF_SUBSCRIBER),
                       WDI_EVENT_RX_CBF_REMOTE)) {
                   return A_ERROR;
               }
        }
    }
    }
    return A_OK;
}

int
pktlog_wmi_send_enable_cmd(struct ol_ath_softc_net80211 *scn,
        uint32_t types)
{
    if(!wmi_unified_packet_log_enable_send(scn->wmi_handle, types)) {
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        osif_nss_ol_pktlog_cfg(scn, 1);
#endif
        return 0;
    }
    return -1;
}

int
pktlog_wmi_send_disable_cmd(struct ol_ath_softc_net80211 *scn)
{
#if UNIFIED_SMARTANTENNA
#if !defined(CONFIG_AR900B_SUPPORT)
    /* Smart Antenna uses packet log frame work, So when smart antenna is enabled disabling packet log
       in firmware is not allowed */
    if (ol_smart_ant_tx_feedback_enabled(scn)) {
        qdf_print("%s: As Smart Antenna is enabled, Packet log is not disabled \n", __FUNCTION__);
        return -1;
    }
#endif
#endif
    if(!wmi_unified_packet_log_disable_send(scn->wmi_handle)) {
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        osif_nss_ol_pktlog_cfg(scn, 0);
#endif
        return 0;
    }
    return -1;
}

int
pktlog_disable(struct ol_ath_softc_net80211 *scn)
{
#if UNIFIED_SMARTANTENNA

#if !defined(CONFIG_AR900B_SUPPORT)
    /* Smart Antenna uses packet log frame work, So when smart antenna is enabled disabling packet log
       in firmware is not allowed */
    if (ol_smart_ant_tx_feedback_enabled(scn)) {
        qdf_print("%s: As Smart Antenna is enabled, Packet log is not disabled \n", __FUNCTION__);
        return -1;
    }
#endif
#endif
    return PKTLOG_DISABLE(scn);
}

void
pktlog_deinit(struct ol_ath_softc_net80211 *scn)
{
#if REMOTE_PKTLOG_SUPPORT
    ol_pktlog_dev_t *pl_dev = NULL;
    struct pktlog_remote_service *service = NULL;

    pl_dev = scn->pl_dev;
    if (!pl_dev) {
        return;
    }

    service = &pl_dev->rpktlog_svc;
    if (!service) {
        return;
    }

    qdf_destroy_work(scn->qdf_dev, &service->connection_service);
    qdf_destroy_work(scn->qdf_dev, &service->accept_service);
    qdf_destroy_work(scn->qdf_dev, &service->send_service);
#endif
}

void
pktlog_init(struct ol_ath_softc_net80211 *scn)
{
    struct ath_pktlog_info *pl_info = NULL;
    struct ol_pktlog_dev_t *pl_dev = NULL;
#if REMOTE_PKTLOG_SUPPORT
    struct pktlog_remote_service *service = NULL;
#endif
    if ((scn == NULL) || (scn->pl_dev == NULL)) {
        return;
    }

    pl_dev = scn->pl_dev;
    pl_info = pl_dev->pl_info;

    if(pl_info) {
#if REMOTE_PKTLOG_SUPPORT
        service = &pl_dev->rpktlog_svc;
#endif
        OS_MEMZERO(pl_info, sizeof(*pl_info));
        PKTLOG_LOCK_INIT(pl_info);

        pl_info->buf_size = PKTLOG_DEFAULT_BUFSIZE;
        pl_info->buf = NULL;
        pl_info->log_state = 0;
        pl_info->sack_thr = PKTLOG_DEFAULT_SACK_THR;
        pl_info->tail_length = PKTLOG_DEFAULT_TAIL_LENGTH;
        pl_info->thruput_thresh = PKTLOG_DEFAULT_THRUPUT_THRESH;
        pl_info->per_thresh = PKTLOG_DEFAULT_PER_THRESH;
        pl_info->phyerr_thresh = PKTLOG_DEFAULT_PHYERR_THRESH;
        pl_info->trigger_interval = PKTLOG_DEFAULT_TRIGGER_INTERVAL;
        pl_info->pktlen = 0;
        pl_info->start_time_thruput = 0;
        pl_info->start_time_per = 0;
        pl_info->scn = (ol_ath_generic_softc_handle) scn;
        pl_info->remote_port = 0;
        pl_info->tx_capture_enabled = 0;

        if (pl_dev) {
            pl_dev->target_type = scn->target_type;
            pl_dev->PKTLOG_RX_REMOTE_SUBSCRIBER.callback = pktlog_callback;
            pl_dev->PKTLOG_OFFLOAD_SUBSCRIBER.callback = pktlog_callback;
            pl_dev->PKTLOG_RX_CBF_SUBSCRIBER.callback = pktlog_callback;

            if (scn->is_ar900b) {
                struct ath_pktlog_msdu_info_ar900b pl_msdu_info;
                pl_dev->pktlog_hdr_size = sizeof(struct ath_pktlog_hdr_ar900b);
                pl_dev->msdu_id_offset = MSDU_ID_INFO_ID_OFFSET_AR900B;
                pl_dev->msdu_info_priv_size =  sizeof(pl_msdu_info.priv);
                pl_dev->process_tx_msdu_info = process_tx_msdu_info_ar900b;
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %s: Initializing Pktlog for AR900B, pktlog_hdr_size = %d\n", __func__, pl_dev->pktlog_hdr_size);
            } else if (scn->target_type == TARGET_TYPE_AR9888) {
                struct ath_pktlog_msdu_info_ar9888 pl_msdu_info;
                pl_dev->pktlog_hdr_size = sizeof(struct ath_pktlog_hdr_ar9888);
                pl_dev->msdu_id_offset = MSDU_ID_INFO_ID_OFFSET_AR9888;
                pl_dev->msdu_info_priv_size =  sizeof(pl_msdu_info.priv);
                pl_dev->process_tx_msdu_info = process_tx_msdu_info_ar9888;
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %s: Initializing Pktlog for AR9888, pktlog_hdr_size = %d\n", __func__, pl_dev->pktlog_hdr_size);
            } else {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: WARNING: Pktlog enabled for offload target type %d\n", __func__, scn->target_type);
            }
            pl_info->pktlog_hdr_size = pl_dev->pktlog_hdr_size;
        } else {
            qdf_assert_always(0);
        }

#if REMOTE_PKTLOG_SUPPORT
        service->port = DEFAULT_REMOTE_PKTLOG_PORT;
        qdf_create_work(scn->qdf_dev, &service->connection_service, pktlog_start_remote_service, scn);
        qdf_create_work(scn->qdf_dev, &service->accept_service, pktlog_start_accept_service, scn);
        qdf_create_work(scn->qdf_dev, &service->send_service, pktlog_run_send_service, scn);
#endif
        /*
         * Add the WDI subscribe command
         * Might be moved to enable function because,
         * it is not consuming the WDI unless we really need it.
         */
#ifdef CONFIG_AR900B_SUPPORT
        if (scn->is_ar900b) {
            /* HIF subscribe */
            if (hif_pktlog_subscribe(scn)) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Unable to subscribe to the HIF %s\n",
                        __FUNCTION__);
                return;
            }
        }
#endif
    }
}

int
pktlog_enable(struct ol_ath_softc_net80211 *scn, int32_t log_state)
{
    ol_pktlog_dev_t *pl_dev = NULL;
    struct ath_pktlog_info *pl_info = NULL;
    struct ol_txrx_pdev_t *txrx_pdev = NULL;
    int error;

    if(scn == NULL) {
        return -1;
    }

    if (ol_ath_target_start(scn)) {
        qdf_print("failed to start the target\n");
        return -1;
    }

    pl_dev = scn->pl_dev;
    pl_info = pl_dev->pl_info;

    txrx_pdev = scn->pdev_txrx_handle;
    pl_dev->sc_osdev = scn->sc_osdev;

    if (!pl_info) {
        return 0;
    }

    if (log_state != 0 && !pl_dev->tgt_pktlog_enabled) {
        if (!scn) {
            if (g_pktlog_mode == PKTLOG_MODE_ADAPTER) {
                pktlog_disable_adapter_logging();
                g_pktlog_mode = PKTLOG_MODE_SYSTEM;
            }
        }
        else {
            if (g_pktlog_mode == PKTLOG_MODE_SYSTEM) {
                g_pktlog_mode = PKTLOG_MODE_ADAPTER;
            }
        }

        if (pl_info->buf == NULL) {
            error = pktlog_alloc_buf(scn);
            if (error != 0)
                return error;

            pl_info->buf->bufhdr.version = CUR_PKTLOG_VER;
            pl_info->buf->bufhdr.magic_num = PKTLOG_MAGIC_NUM;
            pl_info->buf->wr_offset = 0;
            pl_info->buf->rd_offset = -1;
        }
        pl_info->start_time_thruput = OS_GET_TIMESTAMP();
        pl_info->start_time_per = pl_info->start_time_thruput;

        /* WDI subscribe */
        if (wdi_pktlog_subscribe(txrx_pdev, log_state)) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Unable to subscribe to the WDI %s\n",
                    __FUNCTION__);
            return -1;
        }

        /* WMI command to enable pktlog on the firmware */
        if (pktlog_enable_tgt(scn, log_state)) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Device cannot be enabled, %s\n", __FUNCTION__);
            return -1;
        }
        else {
            pl_dev->tgt_pktlog_enabled = true;
#if REMOTE_PKTLOG_SUPPORT
            if (log_state & ATH_PKTLOG_REMOTE_LOGGING_ENABLE) {
                /* enable remote packet logging */
                pktlog_remote_enable(scn, 1);
            }
#endif
        }
    }
    else if (!log_state && pl_dev->tgt_pktlog_enabled) {
        pl_dev->pl_funcs->pktlog_disable(scn);
        pl_dev->tgt_pktlog_enabled = false;
#if REMOTE_PKTLOG_SUPPORT
        /* disable remote packet logging */
        pktlog_remote_enable(scn, 0);
#endif
        if (wdi_pktlog_unsubscribe(txrx_pdev, pl_info->log_state)) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Cannot unsubscribe pktlog from the WDI\n");
            return -1;
        }
    }

    pl_info->log_state = log_state;
    return 0;
}

int
pktlog_setsize(struct ol_ath_softc_net80211 *scn, int32_t size)
{
    ol_pktlog_dev_t *pl_dev = NULL;
    struct ath_pktlog_info *pl_info = NULL;

    if(scn == NULL)
        return -EINVAL;

    pl_dev  = scn->pl_dev;
    pl_info = (scn) ? pl_dev->pl_info : g_pktlog_info;

    if(pl_info == NULL)
        return -EINVAL;

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "I am setting the size of the pktlog buffer:%s\n", __FUNCTION__);
    if (size < 0)
        return -EINVAL;

    if (size == pl_info->buf_size)
        return 0;

    if (pl_info->log_state) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Logging should be disabled before changing bufer size\n");
        return -EINVAL;
    }

    if (pl_info->buf != NULL)
        pktlog_release_buf(scn);

    if (size != 0)
        pl_info->buf_size = size;

    return 0;
}

#endif /* REMOVE_PKT_LOG */
