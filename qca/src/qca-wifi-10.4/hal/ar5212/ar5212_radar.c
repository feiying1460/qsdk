/*
 * Copyright (c) 2002-2005 Atheros Communications, Inc.
 * Copyright (c) 2008-2010, Atheros Communications Inc. 
 * All Rights Reserved.
 *  
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */


#include "opt_ah.h"

#ifdef AH_SUPPORT_AR5212
#include "ah.h"
#include "ah_internal.h"

#include "ar5212/ar5212.h"
#include "ar5212/ar5212reg.h"
#include "ar5212/ar5212desc.h"
#include "ar5212/ar5212phy.h"

#define HAL_RADAR_WAIT_TIME		60*1000000	/* 1 minute in usecs */

/* 
 * Default 5212/5312 radar phy parameters
 */
#define AR5212_DFS_FIRPWR	-41
#define AR5212_DFS_RRSSI	12
#define AR5212_DFS_HEIGHT	20
#define AR5212_DFS_PRSSI	22
#define AR5212_DFS_INBAND	6

#ifdef ATH_SUPPORT_DFS

struct dfs_pulse ar5212_etsi_radars[] = {
        /* TYPE 1 */
        {10, 2,   750,  0, 24, 50,  0,  2, 22,  0, 3, 0, 0},
                                                                                               
        /* TYPE 2 */
        {7,  2,   200,  0, 24, 50,  0,  2, 22,  0, 3, 0, 1},
        {7,  2,   300,  0, 24, 50,  0,  2, 22,  0, 3, 0, 2},
        {7,  2,   500,  0, 24, 50,  0,  2, 22,  1, 3, 0, 3},
        {7,  2,   800,  0, 24, 50,  0,  2, 22,  1, 3, 0, 4},
        {7,  2,  1001,  0, 24, 50,  0,  2, 22,  0, 3, 0, 5},
        {7,  8,   200,  0, 24, 50,  6,  9, 22,  8, 3, 0, 6},
        {7,  8,   300,  0, 24, 50,  6,  9, 22,  8, 3, 0, 7},
        {7,  8,   502,  0, 24, 50,  6,  9, 22,  0, 3, 0, 8},
        {7,  8,   805,  0, 24, 50,  6,  9, 22,  0, 3, 0, 9},
        {7,  8,  1008,  0, 24, 50,  6,  9, 22,  0, 3, 0, 10},
                                                                                               
        /* TYPE 3 */
        {10, 14,  200,  0, 24, 50, 12, 15, 22, 14, 3, 0, 11},
        {10, 14,  300,  0, 24, 50, 12, 15, 22, 14, 3, 0, 12},
        {10, 14,  503,  0, 24, 50, 12, 15, 22,  2, 3, 0, 13},
        {10, 14,  809,  0, 24, 50, 12, 15, 22,  0, 3, 0, 14},
        {10, 14, 1014,  0, 24, 50, 12, 15, 22,  0, 3, 0, 15},
        {10, 18,  200,  0, 24, 50, 15, 19, 22, 18, 3, 0, 16},
        {10, 18,  301,  0, 24, 50, 15, 19, 22,  7, 3, 0, 17},
        {10, 18,  504,  0, 24, 50, 15, 19, 22,  2, 3, 0, 18},
        {10, 18,  811,  0, 24, 50, 15, 19, 22,  0, 3, 0, 19},
        {10, 18, 1018,  0, 24, 50, 15, 19, 22,  0, 3, 0, 20},
        
        /* TYPE 4 */
        {10, 2,  1200,  0, 24, 50,  0,  2, 22,  0, 3, 0, 21},
        {10, 2,  1500,  0, 24, 50,  0,  2, 22,  0, 3, 0, 22},
        {10, 2,  1600,  0, 24, 50,  0,  2, 22,  0, 3, 0, 23},
        {10, 8,  1212,  0, 24, 50,  6,  9, 22,  0, 3, 0, 24},
        {10, 8,  1517,  0, 24, 50,  6,  9, 22,  0, 3, 0, 25},
        {10, 8,  1620,  0, 24, 50,  6,  9, 22,  0, 3, 0, 26},
        {10, 14, 1221,  0, 24, 50, 12, 15, 22,  0, 3, 0, 27},
        {10, 14, 1531,  0, 24, 50, 12, 15, 22,  0, 3, 0, 28},
        {10, 14, 1636,  0, 24, 50, 12, 15, 22,  0, 3, 0, 29},
        {10, 18, 1226,  0, 24, 50, 15, 19, 22,  0, 3, 0, 30},
        {10, 18, 1540,  0, 24, 50, 15, 19, 22,  0, 3, 0, 31},
        {10, 18, 1647,  0, 24, 50, 15, 19, 22,  0, 3, 0, 32},
        
        /* TYPE 5 */
        {17, 2,  2305,  0, 24, 50,  0,  2, 22,  0, 3, 0, 33},
        {17, 2,  3009,  0, 24, 50,  0,  2, 22,  0, 3, 0, 34},
        {17, 2,  3512,  0, 24, 50,  0,  2, 22,  0, 3, 0, 35},
        {17, 2,  4016,  0, 24, 50,  0,  2, 22,  0, 3, 0, 36},
        {17, 8,  2343,  0, 24, 50,  6,  9, 22,  0, 3, 0, 37},
        {17, 8,  3073,  0, 24, 50,  6,  9, 22,  0, 3, 0, 38},
        {17, 8,  3601,  0, 24, 50,  6,  9, 22,  0, 3, 0, 39},
        {17, 8,  4132,  0, 24, 50,  6,  9, 22,  0, 3, 0, 40},
        {17, 14, 2376,  0, 24, 50, 12, 15, 22,  0, 3, 0, 41},
        {17, 14, 3131,  0, 24, 50, 12, 15, 22,  0, 3, 0, 42},
        {17, 14, 3680,  0, 24, 50, 12, 15, 22,  0, 3, 0, 43},
        {17, 14, 4237,  0, 24, 50, 12, 15, 22,  0, 3, 0, 44},
        {17, 18, 2399,  0, 24, 50, 15, 19, 22,  0, 3, 0, 45},
        {17, 18, 3171,  0, 24, 50, 15, 19, 22,  0, 3, 0, 46},
        {17, 18, 3735,  0, 24, 50, 15, 19, 22,  0, 3, 0, 47},
        {17, 18, 4310,  0, 24, 50, 15, 19, 22,  0, 3, 0, 48},
        
        /* TYPE 6 */
        {14, 22, 2096,  0, 24, 50, 21, 24, 22,  0, 3, 0, 49},
        {14, 22, 3222,  0, 24, 50, 21, 24, 22,  0, 3, 0, 50},
        {14, 22, 4405,  0, 24, 50, 21, 24, 22,  0, 3, 0, 51},
        {14, 32, 2146,  0, 24, 50, 30, 35, 22,  0, 3, 0, 52},
        {14, 32, 3340,  0, 24, 50, 30, 35, 22,  0, 3, 0, 53},
        {14, 32, 4629,  0, 24, 50, 30, 35, 22,  0, 3, 0, 54},
};

/* The following are for FCC Bin 1-4 pulses */
struct dfs_pulse ar5212_fcc_radars[] = {
        /* following two filters are specific to Japan/MKK4 */
        {16,   2,  720,  6, 40,  0,  2, 18,  0, 3, 0, 30},
        {16,   3,  260,  6, 40,  0,  5, 18,  0, 3, 0, 31},
                                                                                               
        /* following filters are common to both FCC and JAPAN */
        {9,   2, 3003,   6, 50,  0,  2, 18,  0, 0, 0, 29},
        {16,  2,  700,   6, 35,  0,  2, 18,  0, 3, 0, 28},
                                                                                               
        {10,  3, 6666,  10, 90,  2,  3, 22,  0, 3,  0, 0},
        {10,  3, 5900,  10, 90,  2,  3, 22,  0, 3,  0, 1},
        {10,  3, 5200,  10, 90,  2,  3, 22,  0, 3,  0, 2},
        {10,  3, 4800,  10, 90,  2,  3, 22,  0, 3,  0, 3},
        {10,  3, 4400,  10, 90,  2,  3, 22,  0, 3,  0, 4},
        {10,  5, 6666,  50, 30,  3, 10, 22,  0, 3,  0, 5},
        {10,  5, 5900,  70, 30,  3, 10, 22,  0, 3,  0, 6},
        {10,  5, 5200,  70, 30,  3, 10, 22,  0, 3,  0, 7},
        {10,  5, 4800,  70, 30,  3, 10, 22,  0, 3,  0, 8},
        {10,  5, 4400,  50, 30,  3,  9, 22,  0, 3,  0, 9},
                                                                                               
        {8,  10, 5000, 100, 40,  7, 17, 22,  0, 3, 0, 10},
        {8,  10, 3000, 100, 40,  7, 17, 22,  0, 3, 0, 11},
        {8,  10, 2000,  40, 40,  9, 17, 22,  0, 3, 0, 12},
        {8,  14, 5000, 100, 40, 13, 16, 22,  0, 3, 0, 13},
        {8,  14, 3000, 100, 40, 13, 16, 22,  0, 3, 0, 14},
        {8,  14, 2000,  40, 40, 13, 16, 22,  0, 3, 0, 15},
                                                                                               
        {6,  10, 5000,  80, 40, 10, 15, 22,  0, 3, 0, 16},
        {6,  10, 3000,  80, 40, 10, 15, 22,  0, 3, 0, 17},
        {6,  10, 2000,  40, 40, 10, 15, 22,  0, 3, 0, 18},
        {6,  10, 5000,  80, 40, 10, 12, 22,  0, 3, 0, 19},
        {6,  10, 3000,  80, 40, 10, 12, 22,  0, 3, 0, 20},
        {6,  10, 2000,  40, 40, 10, 12, 22,  0, 3, 0, 21},
                                                                                               
        {6,  18, 5000,  80, 40, 16, 25, 22,  0, 3, 0, 22},
        {6,  18, 3000,  80, 40, 16, 25, 22,  0, 3, 0, 23},
        {6,  18, 2000,  40, 40, 16, 25, 22,  0, 3, 0, 24},
                                                                                               
        {6,  21, 5000,  80, 40, 12, 25, 22,  0, 3, 0, 25},
        {6,  21, 3000,  80, 40, 12, 25, 22,  0, 3, 0, 26},
        {6,  21, 2000,  40, 40, 12, 25, 22,  0, 3, 0, 27},
                                                                                               
};
struct dfs_bin5pulse ar5212_bin5pulses[] = {
        {5, 52, 100, 12, 22, 3},
};
                                                                                               


/*
 * Find the internal HAL channel corresponding to the
 * public HAL channel specified in c
 */

static HAL_CHANNEL_INTERNAL *
getchannel(struct ath_hal *ah, const HAL_CHANNEL *c)
{
#define CHAN_FLAGS	(CHANNEL_ALL|CHANNEL_HALF|CHANNEL_QUARTER)
	HAL_CHANNEL_INTERNAL *base, *cc;
	int flags = c->channel_flags & CHAN_FLAGS;
	int n, lim;

	/*
	 * Check current channel to avoid the lookup.
	 */
	cc = AH_PRIVATE(ah)->ah_curchan;
	if (cc != AH_NULL && cc->channel == c->channel &&
	    (cc->channel_flags & CHAN_FLAGS) == flags) {
			return cc;
	}

	/* binary search based on known sorting order */
	base = AH_TABLES(ah)->ah_channels;
	n = AH_PRIVATE(ah)->ah_nchan;
	/* binary search based on known sorting order */
	for (lim = n; lim != 0; lim >>= 1) {
		int d;
		cc = &base[lim>>1];
		d = c->channel - cc->channel;
		if (d == 0) {
			if ((cc->channel_flags & CHAN_FLAGS) == flags) {
					return cc;
			}
			d = flags - (cc->channel_flags & CHAN_FLAGS);
		}
		HDPRINTF(ah, HAL_DBG_DFS, "%s: channel %u/0x%x d %d\n", __func__,
			cc->channel, cc->channel_flags, d);
		if (d > 0) {
			base = cc + 1;
			lim--;
		}
	}
	HDPRINTF(ah, HAL_DBG_DFS, "%s: no match for %u/0x%x\n",
		__func__, c->channel, c->channel_flags);
	return AH_NULL;
#undef CHAN_FLAGS
}

/* Check the internal channel list to see if the desired channel
 * is ok to release from the NOL.  If not, then do nothing.  If so,
 * mark the channel as clear and reset the internal tsf time
 */

void
ar5212CheckDfs(struct ath_hal *ah, HAL_CHANNEL *chan)
{
	HAL_CHANNEL_INTERNAL *ichan=AH_NULL;
	u_int64_t tsf;

	ichan = getchannel(ah, chan);
	if (ichan == AH_NULL)
		return;
	if (!(ichan->priv_flags & CHANNEL_INTERFERENCE))
		return;
	tsf = ar5212GetTsf64(ah);
	if (tsf >= ichan->dfs_tsf) {
		ichan->priv_flags &= ~CHANNEL_INTERFERENCE;
		ichan->dfs_tsf = 0;
		chan->priv_flags &= ~CHANNEL_INTERFERENCE;
	}
}

/*
 * This function marks the channel as having found a dfs event
 * It also marks the end time that the dfs event should be cleared
 * If the channel is already marked, then tsf end time can only
 * be increased
 */

void
ar5212DfsFound(struct ath_hal *ah, HAL_CHANNEL *chan, u_int64_t nolTime)
{
	HAL_CHANNEL_INTERNAL *ichan;

	ichan = getchannel(ah, chan);
	if (ichan == AH_NULL)
		return;
	if (!(ichan->priv_flags & CHANNEL_INTERFERENCE))
		ichan->dfs_tsf = ar5212GetTsf64(ah);
	ichan->dfs_tsf += nolTime;
	ichan->priv_flags |= CHANNEL_INTERFERENCE;
	chan->priv_flags |= CHANNEL_INTERFERENCE;
}


void
ar5212EnableDfs(struct ath_hal *ah, HAL_PHYERR_PARAM *pe)
{
	u_int32_t val;
	val = OS_REG_READ(ah, AR_PHY_RADAR_0);
	
	if (pe->pe_firpwr != HAL_PHYERR_PARAM_NOVAL) {
		val &= ~AR_PHY_RADAR_0_FIRPWR;
		val |= SM(pe->pe_firpwr, AR_PHY_RADAR_0_FIRPWR);
	}
	if (pe->pe_rrssi != HAL_PHYERR_PARAM_NOVAL) {
		val &= ~AR_PHY_RADAR_0_RRSSI;
		val |= SM(pe->pe_rrssi, AR_PHY_RADAR_0_RRSSI);
	}
	if (pe->pe_height != HAL_PHYERR_PARAM_NOVAL) {
		val &= ~AR_PHY_RADAR_0_HEIGHT;
		val |= SM(pe->pe_height, AR_PHY_RADAR_0_HEIGHT);
	}
	if (pe->pe_prssi != HAL_PHYERR_PARAM_NOVAL) {
		val &= ~AR_PHY_RADAR_0_PRSSI;
		val |= SM(pe->pe_prssi, AR_PHY_RADAR_0_PRSSI);
	}
	if (pe->pe_inband != HAL_PHYERR_PARAM_NOVAL) {
		val &= ~AR_PHY_RADAR_0_INBAND;
		val |= SM(pe->pe_inband, AR_PHY_RADAR_0_INBAND);
	}
	OS_REG_WRITE(ah, AR_PHY_RADAR_0, val | AR_PHY_RADAR_0_ENA);

}

void
ar5212GetDfsThresh(struct ath_hal *ah, HAL_PHYERR_PARAM *pe)
{
	u_int32_t val,temp;

	val = OS_REG_READ(ah, AR_PHY_RADAR_0);

	temp = MS(val,AR_PHY_RADAR_0_FIRPWR);
	temp |= 0xFFFFFF80;
	pe->pe_firpwr = temp;
	pe->pe_rrssi = MS(val, AR_PHY_RADAR_0_RRSSI);
	pe->pe_height =  MS(val, AR_PHY_RADAR_0_HEIGHT);
	pe->pe_prssi = MS(val, AR_PHY_RADAR_0_PRSSI);
	pe->pe_inband = MS(val, AR_PHY_RADAR_0_INBAND);

	pe->pe_relpwr = 0;
	pe->pe_relstep = 0;
	pe->pe_maxlen = 0;
}

struct dfs_pulse *
ar5212GetDfsRadars(struct ath_hal *ah, u_int32_t dfsdomain, int *numradars,
               struct dfs_bin5pulse **bin5pulses, int *numb5radars, HAL_PHYERR_PARAM *pe)
{
#define N(a)    (sizeof(a)/sizeof(a[0]))
        struct dfs_pulse *dfs_radars = AH_NULL;

        switch (dfsdomain) {
        case DFS_FCC_DOMAIN:
                        dfs_radars = &ar5212_fcc_radars[2];
                        *numradars= N(ar5212_fcc_radars)-2;
                        *bin5pulses = &ar5212_bin5pulses[0];
                        *numb5radars = N(ar5212_bin5pulses);
                         HDPRINTF(ah, HAL_DBG_DFS, "%s: DFS_FCC_DOMAIN_5212\n", __func__);
                break;
        case DFS_ETSI_DOMAIN:
                        dfs_radars = &ar5212_etsi_radars[0];
                        *numradars = N(ar5212_etsi_radars);
                        *bin5pulses = &ar5212_bin5pulses[0];
                        *numb5radars = N(ar5212_bin5pulses);
                         HDPRINTF(ah, HAL_DBG_DFS, "%s: DFS_ETSI_DOMAIN_5212\n", __func__);
                         break;
        case DFS_MKK4_DOMAIN:
                        dfs_radars = &ar5212_fcc_radars[0];
                        *numradars = N(ar5212_fcc_radars);
                        *bin5pulses = &ar5212_bin5pulses[0];
                        *numb5radars = N(ar5212_bin5pulses);
                         HDPRINTF(ah, HAL_DBG_DFS, "%s: DFS_MKK4_DOMAIN_5212\n", __func__);
                        break;
        default:
                HDPRINTF(ah, HAL_DBG_DFS, "%s: no domain\n", __func__);
                return AH_NULL;
        }
        /* Set the default phy parameters per chip */
                pe->pe_firpwr = AR5212_DFS_FIRPWR;
                pe->pe_rrssi = AR5212_DFS_RRSSI;
                pe->pe_height = AR5212_DFS_HEIGHT;
                pe->pe_prssi = AR5212_DFS_PRSSI;
                pe->pe_inband = AR5212_DFS_INBAND;

                return dfs_radars;
#undef N
}

void ar5212_adjust_difs(struct ath_hal *ah, u_int32_t val)
{
}

u_int32_t ar5212_dfs_config_fft(struct ath_hal *ah, bool is_enable)
{
    return 0;
}

void
ar5212_dfs_cac_war(struct ath_hal *ah, u_int32_t start)
{
}
#endif /* ATH_SUPPORT_DFS */

HAL_BOOL
ar5212RadarWait(struct ath_hal *ah, HAL_CHANNEL *chan)
{
	struct ath_hal_private *ahp= AH_PRIVATE(ah);
#ifdef AH_SUPPORT_DFS
	u_int64_t tsf;

	if(!ahp->ah_curchan) return AH_TRUE;
	tsf = ar5212GetTsf64(ah);
	ahp->ah_curchan->ah_channel_time  += (tsf - ahp->ah_curchan->ah_tsf_last);
	ahp->ah_curchan->ah_tsf_last = tsf;
	chan->channel = ahp->ah_curchan->channel;
	chan->channel_flags = ahp->ah_curchan->channel_flags;
	chan->priv_flags  = ahp->ah_curchan->priv_flags;
	chan->max_reg_tx_power = ahp->ah_curchan->max_reg_tx_power;
	if (ahp->ah_curchan->ah_channel_time > (HAL_RADAR_WAIT_TIME)) {
		ahp->ah_curchan->priv_flags |= CHANNEL_DFS_CLEAR;
		chan->priv_flags  = ahp->ah_curchan->priv_flags;
		ar5212TxEnable(ah,AH_TRUE);
		return AH_FALSE;
	} 
	return AH_TRUE;
#else
	chan->channel = ahp->ah_curchan->channel;
	ahp->ah_curchan->priv_flags |= CHANNEL_DFS_CLEAR;
	chan->channel_flags = ahp->ah_curchan->channel_flags;
	chan->priv_flags  = ahp->ah_curchan->priv_flags;
	chan->max_reg_tx_power = ahp->ah_curchan->max_reg_tx_power;
	return AH_FALSE;
#endif /* AH_SUPPORT_DFS */
}

HAL_CHANNEL *ar5212GetExtensionChannel(struct ath_hal *ah)
{
    return AH_NULL;
}

HAL_BOOL ar5212IsFastClockEnabled(struct ath_hal *ah)
{
    return AH_FALSE;
}

#endif /* AH_SUPPORT_AR5212 */

