/*
 * Copyright (c) 2012 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */
#ifndef _PKTLOG_AC_I_
#define _PKTLOG_AC_I_
#ifndef REMOVE_PKT_LOG

#include <ol_txrx_internal.h>
#include <pktlog_ac.h>

#define PKTLOG_DEFAULT_BUFSIZE (1024 * 1024)
#define PKTLOG_DEFAULT_SACK_THR 3
#define PKTLOG_DEFAULT_TAIL_LENGTH 100
#define PKTLOG_DEFAULT_THRUPUT_THRESH   (64 * 1024)
#define PKTLOG_DEFAULT_PER_THRESH   30
#define PKTLOG_DEFAULT_PHYERR_THRESH   300
#define PKTLOG_DEFAULT_TRIGGER_INTERVAL 500
struct ath_pktlog_arg {
    struct ath_pktlog_info *pl_info;
    u_int32_t flags;
    u_int16_t missed_cnt;
    u_int16_t log_type;
    size_t log_size;
#if PEER_FLOW_CONTROL    
    u_int32_t timestamp;
#else
    u_int16_t timestamp;
#endif
    size_t pktlog_hdr_size;
#ifdef CONFIG_AR900B_SUPPORT
    u_int32_t type_specific_data;
#endif
    char *buf;
};

void pktlog_getbuf_intsafe(struct ath_pktlog_arg *plarg);
char *pktlog_getbuf(ol_pktlog_dev_t *pl_dev,
                    struct ath_pktlog_info *pl_info,
                    size_t log_size,
                    ath_pktlog_hdr_t *pl_hdr);
A_STATUS process_rx_cbf_remote(void *pdev, qdf_nbuf_t amsdu);
A_STATUS process_rx_info_remote(void *pdev, qdf_nbuf_t amsdu);
A_STATUS process_dbg_print(void *pdev, void *data);/*TODO*/
A_STATUS process_offload_pktlog(void *pdev, void *data);
A_STATUS process_text_info(void *pdev, char *text);
A_STATUS process_tx_msdu_info_ar900b (struct ol_txrx_pdev_t *txrx_pdev,
                                 void *data, ath_pktlog_hdr_t *pl_hdr);
A_STATUS process_tx_msdu_info_ar9888 (struct ol_txrx_pdev_t *txrx_pdev,
                                 void *data, ath_pktlog_hdr_t *pl_hdr);
#endif  /* REMOVE_PKT_LOG */
#endif
