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

#ifdef AH_SUPPORT_AR5416

#include "ah.h"
#include "ah_desc.h"
#include "ah_internal.h"

#include "ar5416/ar5416phy.h"
#include "ar5416/ar5416.h"
#include "ar5416/ar5416reg.h"

#ifdef ATH_SUPPORT_DFS
/*
 * Default 5413/5416 radar phy parameters
 */
#define AR5416_DFS_FIRPWR	-33
#define AR5416_DFS_RRSSI	20
#define AR5416_DFS_HEIGHT	10
#define AR5416_DFS_PRSSI	15
#define AR5416_DFS_INBAND	15
#define AR5416_DFS_RELPWR   8
#define AR5416_DFS_RELSTEP  12
#define AR5416_DFS_MAXLEN   255

#define AR5416_DEFAULT_DIFS     0x002ffc0f

struct dfs_pulse ar5416_etsi_radars[] = {
    /* TYPE staggered pulse */
    /* 0.8-2us, 2-3 bursts,300-400 PRF, 10 pulses each */
    {20,  2,  300,  400, 2, 30,  4,  0,  2, 15, 0,   0, 0, 31},
    /* 0.8-2us, 2-3 bursts, 400-1200 PRF, 15 pulses each */
    {30,  2,  400, 1200, 2, 30,  7,  0,  2, 15, 0,   0, 0, 32},

    /* constant PRF based */
    /* 0.8-5us, 200  300 PRF, 10 pulses */

    {10, 5,   200,  400, 0, 24,  5,  0,  8, 18, 0,   0, 0, 33},
    {10, 5,   400,  600, 0, 24,  5,  0,  8, 18, 0,   0, 0, 37},
    {10, 5,   600,  800, 0, 24,  5,  0,  8, 18, 0,   0, 0, 38},
    {10, 5,   800, 1000, 0, 24,  5,  0,  8, 18, 0,   0, 0, 39},
    //{10, 5,   200, 1000, 0, 24,  5,  0,  8, 18, 0,   0, 0, 33},

    /* 0.8-15us, 200-1600 PRF, 15 pulses */
    {15, 15,  200, 1600, 0, 24, 6,  0, 18, 15, 0,   0, 0, 34},

    /* 0.8-15us, 2300-4000 PRF, 25 pulses*/
    {25, 15, 2300, 4000,  0, 24, 8, 0, 18, 15, 0,   0, 0, 35},

    /* 20-30us, 2000-4000 PRF, 20 pulses*/
    {20, 30, 2000, 4000, 0, 24, 8, 19, 33, 15, 0,   0, 0, 36},
};

/* The following are for FCC Bin 1-4 pulses */
struct dfs_pulse ar5416_fcc_radars[] = {
    /* following two filters are specific to Japan/MKK4 */
//    {18,  1,  720,  720, 1,  6,  6,  0,  1, 18,  0, 3, 0, 17}, // 1389 +/- 6 us
//    {18,  4,  250,  250, 1, 10,  5,  1,  6, 18,  0, 3, 0, 18}, // 4000 +/- 6 us
//    {18,  5,  260,  260, 1, 10,  6,  1,  6, 18,  0, 3, 0, 19}, // 3846 +/- 7 us
    {18,  1,  720,  720, 0,  6,  6,  0,  1, 18,  0, 3, 0, 17}, // 1389 +/- 6 us
    {18,  4,  250,  250, 0, 10,  5,  1,  6, 18,  0, 3, 0, 18}, // 4000 +/- 6 us
    {18,  5,  260,  260, 0, 10,  6,  1,  6, 18,  0, 3, 0, 19}, // 3846 +/- 7 us


    /* following filters are common to both FCC and JAPAN */

    // FCC TYPE 1
    // {18,  1,  325, 1930, 0,  6,  7,  0,  1, 18,  0, 3,  0, 0}, // 518 to 3066
    {18,  1,  700, 700, 0,  6,  5,  0,  1, 18,  0, 3,  0, 0}, 
    {18,  1,  350, 350, 0,  6,  5,  0,  1, 18,  0, 3,  0, 0}, 


    // FCC TYPE 6
    // {9,   1, 3003, 3003, 1,  7,  5,  0,  1, 18,  0, 0,  0, 1}, // 333 +/- 7 us
    {9,   1, 3003, 3003, 1,  7,  5,  0,  1, 18,  0, 0,  0, 1},

    // FCC TYPE 2
    {23, 5, 4347, 6666, 0, 18, 11,  0,  7, 20,  0, 3,  0, 2}, 

    // FCC TYPE 3
    {18, 10, 2000, 5000, 0, 23,  8,  6, 13, 20,  0, 3, 0, 5},

    // FCC TYPE 4
    {16, 15, 2000, 5000, 0, 25,  7, 11, 23, 20,  0, 3, 0, 11}, 

};

struct dfs_bin5pulse ar5416_bin5pulses[] = {
        {2, 28, 105, 12, 22, 5},
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
ar5416CheckDfs(struct ath_hal *ah, HAL_CHANNEL *chan)
{
    HAL_CHANNEL_INTERNAL *ichan=AH_NULL;

    ichan = getchannel(ah, chan);
    if (ichan == AH_NULL) {
        return;
    }
    if (!(ichan->priv_flags & CHANNEL_INTERFERENCE)) {
        return;
    }

    ichan->priv_flags &= ~CHANNEL_INTERFERENCE;
    ichan->dfs_tsf = 0;
}

/*
 * This function marks the channel as having found a dfs event
 * It also marks the end time that the dfs event should be cleared
 * If the channel is already marked, then tsf end time can only
 * be increased
 */

void
ar5416DfsFound(struct ath_hal *ah, HAL_CHANNEL *chan, u_int64_t nolTime)
{
    HAL_CHANNEL_INTERNAL *ichan;

    ichan = getchannel(ah, chan);
    if (ichan == AH_NULL) {
        return;
    }
    if (!(ichan->priv_flags & CHANNEL_INTERFERENCE)) {
        ichan->dfs_tsf = ar5416GetTsf64(ah);
    }
    ichan->dfs_tsf += nolTime;
    ichan->priv_flags |= CHANNEL_INTERFERENCE;
    chan->priv_flags |= CHANNEL_INTERFERENCE;
}

/*
 * Enable radar detection and set the radar parameters per the
 * values in pe
 */

void
ar5416EnableDfs(struct ath_hal *ah, HAL_PHYERR_PARAM *pe)
{
    u_int32_t val;
    struct ath_hal_private  *ahp = AH_PRIVATE(ah);
    HAL_CHANNEL_INTERNAL *ichan=ahp->ah_curchan;

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
    
    /*Enable FFT data*/
    val |= AR_PHY_RADAR_0_FFT_ENA;

    OS_REG_WRITE(ah, AR_PHY_RADAR_0, val | AR_PHY_RADAR_0_ENA);
    
    val = OS_REG_READ(ah, AR_PHY_RADAR_1);
    val |=( AR_PHY_RADAR_1_MAX_RRSSI |
            AR_PHY_RADAR_1_BLOCK_CHECK );

    if (pe->pe_maxlen != HAL_PHYERR_PARAM_NOVAL) {
        val &= ~AR_PHY_RADAR_1_MAXLEN;
        val |= SM(pe->pe_maxlen, AR_PHY_RADAR_1_MAXLEN);
    }

    OS_REG_WRITE(ah, AR_PHY_RADAR_1, val);
            
    if (ath_hal_getcapability(ah, HAL_CAP_EXT_CHAN_DFS, 0, 0) == HAL_OK) {
        if (IS_CHAN_HT40(ichan)) {
            /*Enable extension channel radar detection*/
            val = OS_REG_READ(ah, AR_PHY_RADAR_EXT);
            OS_REG_WRITE(ah, AR_PHY_RADAR_EXT, val | AR_PHY_RADAR_EXT_ENA);
        } else {
            /*HT20 mode, disable extension channel radar detect*/
            val = OS_REG_READ(ah, AR_PHY_RADAR_EXT);
            OS_REG_WRITE(ah, AR_PHY_RADAR_EXT, val & ~AR_PHY_RADAR_EXT_ENA);
        }
    }

    if (pe->pe_relstep != HAL_PHYERR_PARAM_NOVAL) {
        val = OS_REG_READ(ah, AR_PHY_RADAR_1);
        val &= ~AR_PHY_RADAR_1_RELSTEP_THRESH;
        val |= SM(pe->pe_relstep, AR_PHY_RADAR_1_RELSTEP_THRESH);
        OS_REG_WRITE(ah, AR_PHY_RADAR_1, val);
    }
    if (pe->pe_relpwr != HAL_PHYERR_PARAM_NOVAL) {
        val = OS_REG_READ(ah, AR_PHY_RADAR_1);
        val &= ~AR_PHY_RADAR_1_RELPWR_THRESH;
        val |= SM(pe->pe_relpwr, AR_PHY_RADAR_1_RELPWR_THRESH);
        OS_REG_WRITE(ah, AR_PHY_RADAR_1, val);
    }
}

/*
 * Get the radar parameter values and return them in the pe
 * structure
 */

void
ar5416GetDfsThresh(struct ath_hal *ah, HAL_PHYERR_PARAM *pe)
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

    val = OS_REG_READ(ah, AR_PHY_RADAR_1);
    temp = val & AR_PHY_RADAR_1_RELPWR_ENA;
    pe->pe_relpwr = MS(val, AR_PHY_RADAR_1_RELPWR_THRESH);
    if (temp)
        pe->pe_relpwr |= HAL_PHYERR_PARAM_ENABLE;
    temp = val & AR_PHY_RADAR_1_RELSTEP_CHECK;
    pe->pe_relstep = MS(val, AR_PHY_RADAR_1_RELSTEP_THRESH);
    if (temp)
        pe->pe_relstep |= HAL_PHYERR_PARAM_ENABLE;
    pe->pe_maxlen = MS(val, AR_PHY_RADAR_1_MAXLEN);
}

HAL_BOOL
ar5416RadarWait(struct ath_hal *ah, HAL_CHANNEL *chan)
{
    struct ath_hal_private *ahp= AH_PRIVATE(ah);

    if(!ahp->ah_curchan) {
        return AH_TRUE;
    }

    /* Rely on the upper layers to determine that we have spent enough time waiting */
    chan->channel = ahp->ah_curchan->channel;
    chan->channel_flags = ahp->ah_curchan->channel_flags;
    chan->max_reg_tx_power = ahp->ah_curchan->max_reg_tx_power;

    ahp->ah_curchan->priv_flags |= CHANNEL_DFS_CLEAR;
    chan->priv_flags  = ahp->ah_curchan->priv_flags;
    return AH_FALSE;

}

struct dfs_pulse *
ar5416GetDfsRadars(struct ath_hal *ah, u_int32_t dfsdomain, int *numradars,
               struct dfs_bin5pulse **bin5pulses, int *numb5radars, HAL_PHYERR_PARAM *pe)
{
#define N(a)    (sizeof(a)/sizeof(a[0]))
        struct dfs_pulse *dfs_radars = AH_NULL;
        switch (dfsdomain) {
        case DFS_FCC_DOMAIN:
                        dfs_radars = &ar5416_fcc_radars[3];
                        *numradars= N(ar5416_fcc_radars)-3;
                        *bin5pulses = &ar5416_bin5pulses[0];
                        *numb5radars = N(ar5416_bin5pulses);
                         HDPRINTF(ah, HAL_DBG_DFS, "%s: DFS_FCC_DOMAIN_5416\n", __func__);
                break;
        case DFS_ETSI_DOMAIN:
                        dfs_radars = &ar5416_etsi_radars[0];
                        *numradars = N(ar5416_etsi_radars);
                        *bin5pulses = &ar5416_bin5pulses[0];
                        *numb5radars = N(ar5416_bin5pulses);
                         HDPRINTF(ah, HAL_DBG_DFS, "%s: DFS_ETSI_DOMAIN_5416\n", __func__);
                         break;
        case DFS_MKK4_DOMAIN:
                        dfs_radars = &ar5416_fcc_radars[0];
                        *numradars = N(ar5416_fcc_radars);
                        *bin5pulses = &ar5416_bin5pulses[0];
                        *numb5radars = N(ar5416_bin5pulses);
                         HDPRINTF(ah, HAL_DBG_DFS, "%s: DFS_MKK4_DOMAIN_5416\n", __func__);
                        break;
        default:
                HDPRINTF(ah, HAL_DBG_DFS, "%s: no domain\n", __func__);
                return AH_NULL;
        }
        /* Set the default phy parameters per chip */
                pe->pe_firpwr = AR5416_DFS_FIRPWR;
                pe->pe_rrssi = AR5416_DFS_RRSSI;
                pe->pe_height = AR5416_DFS_HEIGHT;
                pe->pe_prssi = AR5416_DFS_PRSSI;
                pe->pe_inband = AR5416_DFS_INBAND;
                pe->pe_relpwr = AR5416_DFS_RELPWR;
                pe->pe_relstep = AR5416_DFS_RELSTEP;
                pe->pe_maxlen = AR5416_DFS_MAXLEN;
                return dfs_radars;
#undef N
}

void ar5416_adjust_difs(struct ath_hal *ah, u_int32_t val)
{
    if (val == 0) {
        /*
         * EV 116936:
         * Restore the register values with that of the HAL structure.
         *
         */
        struct ath_hal_5416 *ahp = AH5416(ah);
        HAL_TX_QUEUE_INFO *qi;
        int q;

        HDPRINTF(ah, HAL_DBG_DFS, "%s: restore DIFS \n", __func__);
        for (q = 0; q < 4; q++) {
            qi = &ahp->ah_txq[q];
            OS_REG_WRITE(ah, AR_DLCL_IFS(q),
                    SM(qi->tqi_cwmin, AR_D_LCL_IFS_CWMIN)
                    | SM(qi->tqi_cwmax, AR_D_LCL_IFS_CWMAX)
                    | SM(qi->tqi_aifs, AR_D_LCL_IFS_AIFS));
        }
    } else {
        /*
         * These are values from George Lai and are specific to
         * FCC domain. They are yet to be determined for other domains. 
         */

        HDPRINTF(ah, HAL_DBG_DFS, "%s: set DIFS to default\n", __func__);
        
        OS_REG_WRITE(ah, AR_DLCL_IFS(0), 0x05fffc0f);
        OS_REG_WRITE(ah, AR_DLCL_IFS(1), 0x05f0fc0f);
        OS_REG_WRITE(ah, AR_DLCL_IFS(2), 0x05f03c07);
        OS_REG_WRITE(ah, AR_DLCL_IFS(3), 0x05f01c03);
    }
}

u_int32_t ar5416_dfs_config_fft(struct ath_hal *ah, bool is_enable)
{
    u_int32_t val;

    val = OS_REG_READ(ah, AR_PHY_RADAR_0);

    if (is_enable) {
        val |= AR_PHY_RADAR_0_FFT_ENA;
    } else {
        val &= ~AR_PHY_RADAR_0_FFT_ENA;
    }

    OS_REG_WRITE(ah, AR_PHY_RADAR_0, val);
    val = OS_REG_READ(ah, AR_PHY_RADAR_0);
    return val;
}

void
ar5416_dfs_cac_war(struct ath_hal *ah, u_int32_t start)
{
}
#endif /* ATH_SUPPORT_DFS */

HAL_CHANNEL *ar5416GetExtensionChannel(struct ath_hal *ah)
{
    struct ath_hal_private  *ahp = AH_PRIVATE(ah);
    struct ath_hal_private_tables  *aht = AH_TABLES(ah);
    int i=0;

    HAL_CHANNEL_INTERNAL *ichan=AH_NULL;
    CHAN_CENTERS centers;

    ichan = ahp->ah_curchan;
    ar5416GetChannelCenters(ah, ichan, &centers);
    if (centers.ctl_center == centers.ext_center) {
        return AH_NULL;
    }
    for (i = 0; i < ahp->ah_nchan; i++) {
        ichan = &aht->ah_channels[i];
        if (ichan->channel == centers.ext_center) {
            return (HAL_CHANNEL*)ichan;
        }
    }
    return AH_NULL;
}


HAL_BOOL ar5416IsFastClockEnabled(struct ath_hal *ah)
{
    struct ath_hal_private *ahp= AH_PRIVATE(ah);

    if (AR_SREV_MERLIN_20(ah) && IS_5GHZ_FAST_CLOCK_EN(ah, ahp->ah_curchan)) {
        return AH_TRUE;
    }
    return AH_FALSE;
}

#endif
