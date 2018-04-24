/*
 * Copyright (c) 2010, Atheros Communications Inc. 
 * All Rights Reserved.
 * 
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */

#ifndef _SPECTRAL_IOCTL_H_
#define _SPECTRAL_IOCTL_H_

#include "dfs_ioctl.h"

/*
 * ioctl defines
 */

#define SPECTRAL_SET_CONFIG              (DFS_LAST_IOCTL + 1)
#define SPECTRAL_GET_CONFIG              (DFS_LAST_IOCTL + 2)
#define SPECTRAL_SHOW_INTERFERENCE       (DFS_LAST_IOCTL + 3) 
#define SPECTRAL_ENABLE_SCAN             (DFS_LAST_IOCTL + 4) 
#define SPECTRAL_DISABLE_SCAN            (DFS_LAST_IOCTL + 5) 
#define SPECTRAL_ACTIVATE_SCAN           (DFS_LAST_IOCTL + 6) 
#define SPECTRAL_STOP_SCAN               (DFS_LAST_IOCTL + 7) 
#define SPECTRAL_SET_DEBUG_LEVEL         (DFS_LAST_IOCTL + 8) 
#define SPECTRAL_IS_ACTIVE               (DFS_LAST_IOCTL + 9) 
#define SPECTRAL_IS_ENABLED              (DFS_LAST_IOCTL + 10) 
#define SPECTRAL_CLASSIFY_SCAN           (DFS_LAST_IOCTL + 11) 
#define SPECTRAL_GET_CLASSIFIER_CONFIG   (DFS_LAST_IOCTL + 12)
#define SPECTRAL_EACS                    (DFS_LAST_IOCTL + 13)
#define SPECTRAL_ACTIVATE_FULL_SCAN      (DFS_LAST_IOCTL + 14)
#define SPECTRAL_STOP_FULL_SCAN          (DFS_LAST_IOCTL + 15)
#define SPECTRAL_GET_CAPABILITY_INFO     (DFS_LAST_IOCTL + 16)
#define SPECTRAL_GET_DIAG_STATS          (DFS_LAST_IOCTL + 17)
#define SPECTRAL_GET_CHAN_WIDTH          (DFS_LAST_IOCTL + 18)
#define SPECTRAL_GET_CHANINFO            (DFS_LAST_IOCTL + 19)
#define SPECTRAL_CLEAR_CHANINFO          (DFS_LAST_IOCTL + 20)
#define SPECTRAL_SET_ICM_ACTIVE          (DFS_LAST_IOCTL + 21) 
#define SPECTRAL_GET_NOMINAL_NOISEFLOOR  (DFS_LAST_IOCTL + 22)

/* 
 * ioctl parameter types
 */

#define SPECTRAL_PARAM_FFT_PERIOD        (1)
#define SPECTRAL_PARAM_SCAN_PERIOD       (2)
#define SPECTRAL_PARAM_SCAN_COUNT        (3)
#define SPECTRAL_PARAM_SHORT_REPORT      (4)
#define SPECTRAL_PARAM_SPECT_PRI         (5)
#define SPECTRAL_PARAM_FFT_SIZE          (6)
#define SPECTRAL_PARAM_GC_ENA            (7)
#define SPECTRAL_PARAM_RESTART_ENA       (8)
#define SPECTRAL_PARAM_NOISE_FLOOR_REF   (9)
#define SPECTRAL_PARAM_INIT_DELAY        (10)
#define SPECTRAL_PARAM_NB_TONE_THR       (11)
#define SPECTRAL_PARAM_STR_BIN_THR       (12)
#define SPECTRAL_PARAM_WB_RPT_MODE       (13)
#define SPECTRAL_PARAM_RSSI_RPT_MODE     (14)
#define SPECTRAL_PARAM_RSSI_THR          (15)
#define SPECTRAL_PARAM_PWR_FORMAT        (16)
#define SPECTRAL_PARAM_RPT_MODE          (17)
#define SPECTRAL_PARAM_BIN_SCALE         (18)
#define SPECTRAL_PARAM_DBM_ADJ           (19)
#define SPECTRAL_PARAM_CHN_MASK          (20)
#define SPECTRAL_PARAM_ACTIVE            (21)
#define SPECTRAL_PARAM_STOP              (22)
#define SPECTRAL_PARAM_ENABLE            (23)

struct spectral_ioctl_params {
	int16_t		spectral_fft_period;
	int16_t		spectral_period;
	int16_t		spectral_count;	
	u_int16_t	spectral_short_report;
    u_int16_t   spectral_pri;
};

struct ath_spectral_caps {
    u_int8_t phydiag_cap;
    u_int8_t radar_cap;
    u_int8_t spectral_cap;
    u_int8_t advncd_spectral_cap;
};

struct spectral_diag_stats {
    u_int64_t spectral_mismatch;             /* Spectral TLV signature
                                                mismatches */
    u_int64_t spectral_sec80_sfft_insufflen; /* Insufficient length when parsing
                                                for Secondary 80 Search FFT
                                                report */
    u_int64_t spectral_no_sec80_sfft;        /* Secondary 80 Search FFT report
                                                TLV not found */
    u_int64_t spectral_vhtseg1id_mismatch;   /* VHT Operation Segment 1 ID
                                                mismatches in Search FFT
                                                report */
    u_int64_t spectral_vhtseg2id_mismatch;   /* VHT Operation Segment 2 ID
                                                mismatches in Search FFT
                                                report */
    /* Add other future dev diagnostic stats here */
};

#define	SPECTRAL_IOCTL_PARAM_NOVAL	-65535

#endif
