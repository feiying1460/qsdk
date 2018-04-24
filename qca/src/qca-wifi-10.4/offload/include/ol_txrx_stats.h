/*
 * Copyright (c) 2012 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */
/**
 * @file ol_txrx_status.h
 * @brief Functions provided for visibility and debugging.
 * NOTE: This file is used by both kernel driver SW and userspace SW.
 * Thus, do not reference use any kernel header files or defs in this file!
 */
#ifndef _OL_TXRX_STATS__H_
#define _OL_TXRX_STATS__H_

#include <athdefs.h>       /* u_int64_t */
#include "wlan_defs.h" /* for wlan statst definitions */



/*
 * Structure to consolidate host stats
 */
struct ieee80211req_ol_ath_host_stats {
    struct ol_txrx_stats txrx_stats;
    struct {
        int pkt_q_fail_count;
        int pkt_q_empty_count;
        int send_q_empty_count;
    } htc;
    struct {
        int pipe_no_resrc_count;
        int ce_ring_delta_fail_count;
    } hif;
};


#endif /* _OL_TXRX_STATS__H_ */
