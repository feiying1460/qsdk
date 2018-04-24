/*
 * Copyright (c) 2010, Atheros Communications Inc. 
 * All Rights Reserved.
 * 
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */

/*
 * ioctl defines
 */

#ifndef _DFS_IOCTL_H_
#define _DFS_IOCTL_H_

#define	DFS_MUTE_TIME		1
#define	DFS_SET_THRESH		2
#define	DFS_GET_THRESH		3
#define	DFS_GET_USENOL		4
#define DFS_SET_USENOL		5
#define DFS_RADARDETECTS	6
#define	DFS_BANGRADAR		7 
#define	DFS_SHOW_NOL		8 
#define	DFS_DISABLE_DETECT	9 
#define	DFS_ENABLE_DETECT	10 
#define	DFS_DISABLE_FFT	        11 
#define	DFS_ENABLE_FFT  	12 
#define	DFS_SET_DEBUG_LEVEL  	13
#define DFS_GET_NOL		14
#define DFS_SET_NOL		15 

#define DFS_SET_FALSE_RSSI_THRES 16
#define DFS_SET_PEAK_MAG         17
#define DFS_IGNORE_CAC		18
#define DFS_SET_NOL_TIMEOUT	19
#define DFS_GET_CAC_VALID_TIME	20
#define DFS_SET_CAC_VALID_TIME	21
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
#define DFS_SHOW_NOLHISTORY 22
#endif

#if ATH_SUPPORT_ZERO_CAC_DFS
#define DFS_SECOND_SEGMENT_BANGRADAR  23
#define DFS_SHOW_PRECAC_LISTS	24
#define DFS_RESET_PRECAC_LISTS	25
#endif

/* Spectral IOCTLs use DFS_LAST_IOCTL as the base.
 * This must always be the last IOCTL in DFS and have
 * the highest value.
 */
#define DFS_LAST_IOCTL 26

#ifndef IEEE80211_CHAN_MAX
#define IEEE80211_CHAN_MAX	1023
#endif

struct dfsreq_nolelem {
    u_int16_t	     nol_freq; 	        /* NOL channel frequency */
    u_int16_t        nol_chwidth;
    unsigned long    nol_start_ticks; 	/* OS ticks when the NOL timer started */
    u_int32_t        nol_timeout_ms; 	/* Nol timeout value in msec */
};

struct dfsreq_nolinfo {
    u_int32_t	ic_nchans;
    struct 	dfsreq_nolelem dfs_nol[IEEE80211_CHAN_MAX];
};

/* 
 * ioctl parameter types
 */

#define	DFS_PARAM_FIRPWR	1
#define	DFS_PARAM_RRSSI		2
#define	DFS_PARAM_HEIGHT	3
#define	DFS_PARAM_PRSSI		4
#define	DFS_PARAM_INBAND	5
//5413 specific parameters
#define DFS_PARAM_RELPWR        7
#define DFS_PARAM_RELSTEP       8
#define DFS_PARAM_MAXLEN        9

struct dfs_ioctl_params {
	int32_t		dfs_firpwr;	/* FIR pwr out threshold */
	int32_t		dfs_rrssi;	/* Radar rssi thresh */
	int32_t		dfs_height;	/* Pulse height thresh */
	int32_t		dfs_prssi;	/* Pulse rssi thresh */
	int32_t		dfs_inband;	/* Inband thresh */
	int32_t		dfs_relpwr;	/* pulse relative pwr thresh */
	int32_t		dfs_relstep;	/* pulse relative step thresh */
	int32_t		dfs_maxlen;	/* pulse max duration */
};

/*
 * XXX keep these in sync with ath_dfs_phyerr_param!
 */
#define	DFS_IOCTL_PARAM_NOVAL	65535
#define	DFS_IOCTL_PARAM_ENABLE	0x8000

#endif  /* _DFS_IOCTL_H_ */
