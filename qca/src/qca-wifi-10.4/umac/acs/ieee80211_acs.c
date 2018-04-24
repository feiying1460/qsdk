/*
 * Copyright (c) 2011, 2016-2017 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * Copyright (c) 2008 Atheros Communications Inc.
 * All Rights Reserved.
 *
 * 2011, 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#include <osdep.h>

#include <ieee80211_var.h>
#include <ieee80211_scan.h>
#include <ieee80211_channel.h>
#include <ieee80211_acs.h>
#include <ieee80211_acs_internal.h>
#include <ol_if_athvar.h>

unsigned int  eacs_dbg_mask = 0;



#if UMAC_SUPPORT_ACS

static void ieee80211_free_ht40intol_scan_resource(ieee80211_acs_t acs);

static void ieee80211_acs_free_scan_resource(ieee80211_acs_t acs);

static void ieee80211_acs_scan_report_internal(struct ieee80211com *ic);
static int ieee80211_get_chan_neighbor_list(void *arg, wlan_scan_entry_t se);

static int ieee80211_acs_derive_sec_chans_with_mode(u_int8_t phymode,
        u_int8_t vht_center_freq, u_int8_t channel_ieee_se,
        u_int8_t *sec_chan_20, u_int8_t *sec_chan_40_1, u_int8_t *sec_chan_40_2);

int ieee80211_check_and_execute_pending_acsreport(wlan_if_t vap);
#if ATH_ACS_SUPPORT_SPECTRAL && ATH_SUPPORT_SPECTRAL
int get_eacs_control_duty_cycle(ieee80211_acs_t acs);
int get_eacs_extension_duty_cycle(ieee80211_acs_t acs);
#endif
static INLINE u_int8_t ieee80211_acs_in_progress(ieee80211_acs_t acs)
{
    return atomic_read(&(acs->acs_in_progress));
}


/*
 * Check for channel interference.
 */
static int
ieee80211_acs_channel_is_set(struct ieee80211vap *vap)
{
    struct ieee80211_channel    *chan = NULL;

    chan =  vap->iv_des_chan[vap->iv_des_mode];

    if ((chan == NULL) || (chan == IEEE80211_CHAN_ANYC)) {
        return (0);
    } else {
        return (1);
    }
}

/*
 * Check for channel interference.
 */
static int
ieee80211_acs_check_interference(struct ieee80211_channel *chan, struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;

    /*
     * (1) skip static turbo channel as it will require STA to be in
     * static turbo to work.
     * (2) skip channel which's marked with radar detection
     * (3) WAR: we allow user to config not to use any DFS channel
     * (4) skip excluded 11D channels. See bug 31246
     */
    if ( IEEE80211_IS_CHAN_STURBO(chan) ||
            IEEE80211_IS_CHAN_RADAR(chan) ||
            (IEEE80211_IS_CHAN_DFSFLAG(chan) && ieee80211_ic_block_dfschan_is_set(ic)) ||
            IEEE80211_IS_CHAN_11D_EXCLUDED(chan) ||
            ( ic->ic_no_weather_radar_chan &&
                (ieee80211_check_weather_radar_channel(chan)) &&
                (DFS_ETSI_DOMAIN == ic->ic_get_dfsdomain(ic))
            )) {
        return (1);
    } else {
        return (0);
    }
}

static void ieee80211_acs_get_adj_ch_stats(ieee80211_acs_t acs, struct ieee80211_channel *channel,
        struct ieee80211_acs_adj_chan_stats *adj_chan_stats )
{
#define ADJ_CHANS 8
    u_int8_t ieee_chan = ieee80211_chan2ieee(acs->acs_ic, channel);
    int k;
    u_int8_t sec_chan, first_adj_chan, last_adj_chan;
    u_int8_t sec_chan_40_1 = 0;
    u_int8_t sec_chan_40_2 = 0;
    u_int8_t sec_chan_80_1 = 0;
    u_int8_t sec_chan_80_2 = 0;
    u_int8_t sec_chan_80_3 = 0;
    u_int8_t sec_chan_80_4 = 0;
    int8_t pri_center_ch_diff, pri_center_ch;
    int8_t sec_level;

    int32_t mode_mask = (IEEE80211_CHAN_11NA_HT20 |
            IEEE80211_CHAN_11NA_HT40PLUS |
            IEEE80211_CHAN_11NA_HT40MINUS |
            IEEE80211_CHAN_11AC_VHT20 |
            IEEE80211_CHAN_11AC_VHT40PLUS |
            IEEE80211_CHAN_11AC_VHT40MINUS |
            IEEE80211_CHAN_11AC_VHT80 |
            IEEE80211_CHAN_11AC_VHT160 |
            IEEE80211_CHAN_11AC_VHT80_80);

    adj_chan_stats->if_valid_stats = 1;
    adj_chan_stats->adj_chan_load = 0;
    adj_chan_stats->adj_chan_rssi = 0;
    adj_chan_stats->adj_chan_idx = 0;

    switch (channel->ic_flags & mode_mask)
    {
        case IEEE80211_CHAN_11NA_HT40PLUS:
        case IEEE80211_CHAN_11AC_VHT40PLUS:
            sec_chan = ieee_chan+4;
            first_adj_chan = ieee_chan - ADJ_CHANS;
            last_adj_chan = sec_chan + ADJ_CHANS;
            break;
        case IEEE80211_CHAN_11NA_HT40MINUS:
        case IEEE80211_CHAN_11AC_VHT40MINUS:
            sec_chan = ieee_chan-4;
            first_adj_chan = sec_chan - ADJ_CHANS;
            last_adj_chan = ieee_chan + ADJ_CHANS;
            break;
        case IEEE80211_CHAN_11AC_VHT80:
        case IEEE80211_CHAN_11AC_VHT80_80:

            ieee80211_acs_derive_sec_chans_with_mode(ieee80211_chan2mode(channel),
                    channel->ic_vhtop_ch_freq_seg1, ieee_chan, &sec_chan,
                                               &sec_chan_40_1, &sec_chan_40_2);

           /* Adjacent channels are 4 channels before the band and 4 channels are
               after the band */
            first_adj_chan = (channel->ic_vhtop_ch_freq_seg1 - 6) - 2*ADJ_CHANS;
            last_adj_chan =  (channel->ic_vhtop_ch_freq_seg1 + 6) + 2*ADJ_CHANS;
            break;
        case IEEE80211_CHAN_11AC_VHT160:
            pri_center_ch_diff = ieee_chan - channel->ic_vhtop_ch_freq_seg2;

            /* Secondary 20 channel would be less(2 or 6) or more (2 or 6)
             * than center frequency based on primary channel
             */
            if(pri_center_ch_diff > 0) {
                sec_level = LOWER_FREQ_SLOT;
                sec_chan_80_1 = channel->ic_vhtop_ch_freq_seg2 - SEC_80_4;
                sec_chan_80_2 = channel->ic_vhtop_ch_freq_seg2 - SEC_80_3;
                sec_chan_80_3 = channel->ic_vhtop_ch_freq_seg2 - SEC_80_2;
                sec_chan_80_4 = channel->ic_vhtop_ch_freq_seg2 - SEC_80_1;
            }
            else {
                sec_level = UPPER_FREQ_SLOT;
                sec_chan_80_1 = channel->ic_vhtop_ch_freq_seg2 + SEC_80_1;
                sec_chan_80_2 = channel->ic_vhtop_ch_freq_seg2 + SEC_80_2;
                sec_chan_80_3 = channel->ic_vhtop_ch_freq_seg2 + SEC_80_3;
                sec_chan_80_4 = channel->ic_vhtop_ch_freq_seg2 + SEC_80_4;
            }
            /* Derive Secondary 20, 40 from Primary 80 */
            pri_center_ch = channel->ic_vhtop_ch_freq_seg2 - PRI_80_CENTER*sec_level;

            ieee80211_acs_derive_sec_chans_with_mode(ieee80211_chan2mode(channel),
                                              pri_center_ch, ieee_chan, &sec_chan,
                                               &sec_chan_40_1, &sec_chan_40_2);
            /* Adjacent channels are 4 channels before the band and 4 channels are
               after the band */
            first_adj_chan = (channel->ic_vhtop_ch_freq_seg2 - 14) - 2*ADJ_CHANS;
            last_adj_chan =  (channel->ic_vhtop_ch_freq_seg2 + 14) + 2*ADJ_CHANS;

            break;
        case IEEE80211_CHAN_11NA_HT20:
        case IEEE80211_CHAN_11AC_VHT20:
        default: /* neither HT40+ nor HT40-, finish this call */
            sec_chan = ieee_chan;
            first_adj_chan = sec_chan - ADJ_CHANS;
            last_adj_chan = ieee_chan + ADJ_CHANS;
            break;
    }
    if((sec_chan != ieee_chan) && (sec_chan >= 0)) {

        if( (acs->acs_noisefloor[sec_chan] != NF_INVALID)
                && ( acs->acs_noisefloor[sec_chan] >= NOISE_FLOOR_THRESH) ) {
            adj_chan_stats->adj_chan_flag |= ADJ_CHAN_SEC_NF_FLAG;
        }
    }

    if(sec_chan_40_1 & sec_chan_40_2) {

       if (sec_chan_40_1 >= 0) {
           if( (acs->acs_noisefloor[sec_chan_40_1] != NF_INVALID)
                    && (acs->acs_noisefloor[sec_chan_40_1] >= NOISE_FLOOR_THRESH )) {
               adj_chan_stats->adj_chan_flag |= ADJ_CHAN_SEC1_NF_FLAG;
           }
       }

       if (sec_chan_40_2 >= 0) {
           if( (acs->acs_noisefloor[sec_chan_40_2] !=NF_INVALID)
                   && (acs->acs_noisefloor[sec_chan_40_2] >= NOISE_FLOOR_THRESH )) {
               adj_chan_stats->adj_chan_flag |= ADJ_CHAN_SEC2_NF_FLAG;
           }
       }
    }

    if(sec_chan_80_1 && sec_chan_80_2 && sec_chan_80_3 && sec_chan_80_4) {
        if (sec_chan_80_1 >= 0) {
            if( (acs->acs_noisefloor[sec_chan_80_1] != NF_INVALID)
                     && (acs->acs_noisefloor[sec_chan_80_1] >= NOISE_FLOOR_THRESH )) {
                adj_chan_stats->adj_chan_flag |= ADJ_CHAN_SEC3_NF_FLAG;
            }
        }

        if (sec_chan_80_2 >= 0) {
            if( (acs->acs_noisefloor[sec_chan_80_2] !=NF_INVALID)
                    && (acs->acs_noisefloor[sec_chan_80_2] >= NOISE_FLOOR_THRESH )) {
                adj_chan_stats->adj_chan_flag |= ADJ_CHAN_SEC4_NF_FLAG;
            }
        }

        if (sec_chan_80_3 >= 0) {
            if( (acs->acs_noisefloor[sec_chan_80_3] !=NF_INVALID)
                    && (acs->acs_noisefloor[sec_chan_80_3] >= NOISE_FLOOR_THRESH )) {
                adj_chan_stats->adj_chan_flag |= ADJ_CHAN_SEC5_NF_FLAG;
            }
        }

        if (sec_chan_80_4 >= 0) {
            if( (acs->acs_noisefloor[sec_chan_80_4] !=NF_INVALID)
                    && (acs->acs_noisefloor[sec_chan_80_4] >= NOISE_FLOOR_THRESH )) {
                adj_chan_stats->adj_chan_flag |= ADJ_CHAN_SEC6_NF_FLAG;
            }
        }


    }

    eacs_trace(EACS_DBG_ADJCH,("ieee_chan %d sec_chan %d first_adj_chan %d last_adj_chan %d \n",
                ieee_chan, sec_chan, first_adj_chan, last_adj_chan));
    eacs_trace(EACS_DBG_ADJCH,("sec_chan_40_1  %d sec_chan_40_2 %d  FLAG %x\n",
                sec_chan_40_1, sec_chan_40_2, adj_chan_stats->adj_chan_flag));




    /*Update EACS plus parameter */
    adj_chan_stats->adj_chan_loadsum = 0;
    adj_chan_stats->adj_chan_rssisum = 0;

    for (k = first_adj_chan ; (k <= last_adj_chan) && (k > 0); k += 2) {
        int effchfactor;

        if (k == ieee_chan)  continue;

        effchfactor =  k - ieee_chan;

        if(effchfactor < 0)
            effchfactor = 0 - effchfactor;

        effchfactor = effchfactor >> 1;
        if(effchfactor == 0)  effchfactor =1;

        if((acs->acs_noisefloor[k] != NF_INVALID) && (acs->acs_noisefloor[k] >= NOISE_FLOOR_THRESH )){

            eacs_trace(EACS_DBG_ADJCH,("ADJ NF exceeded add 100 each to rssi and load %d \n",acs->acs_noisefloor[k]));
            adj_chan_stats->adj_chan_loadsum += 100 / effchfactor;
            adj_chan_stats->adj_chan_rssisum += 100 / effchfactor ;
        }
        else{
            adj_chan_stats->adj_chan_loadsum += (acs->acs_chan_load[k] / effchfactor) ;
            adj_chan_stats->adj_chan_rssisum += (acs->acs_chan_rssi[k] / effchfactor) ;
        }
        eacs_trace(EACS_DBG_ADJCH,("ADJ: chan %d sec %d Adj ch: %d ch load: %d rssi: %d effchfactor  %d loadsum %d rssisum %d \n",
                    ieee_chan,sec_chan, k, acs->acs_chan_load[k], acs->acs_chan_rssi[k], effchfactor,
                    adj_chan_stats->adj_chan_loadsum,adj_chan_stats->adj_chan_rssisum ));




    }

    eacs_trace(EACS_DBG_ADJCH,("Chan %d : ADJ rssi %d ADJ load %d \n",
                ieee_chan,adj_chan_stats->adj_chan_rssisum,adj_chan_stats->adj_chan_loadsum));


    eacs_trace(EACS_DBG_ADJCH, ("%s: Adj ch stats valid: %d ind: %d rssi: %d load: %d\n",__func__,
                adj_chan_stats->if_valid_stats, adj_chan_stats->adj_chan_idx,
                adj_chan_stats->adj_chan_rssi, adj_chan_stats->adj_chan_load ));

#undef ADJ_CHANS
}

int
eacs_plus_filter(
        ieee80211_acs_t acs,
        const char *pristr,
        int *primparam,
        const char *secstr,
        int *secparam,
        int primin,
        int privar,
        unsigned int rejflag,
        int *minval
        )
{
    int minix, i, cur_chan, priparamval, secparamval;
    struct ieee80211_channel *channel;
    int findmin = 1, rejhigher = 1;

    eacs_trace(EACS_DBG_LVL1,(" %s \n",__func__));
    minix = -1;
    if(*minval == 0)
        findmin = 0;
    if(*minval == 1){
        rejhigher =0;
        *minval = 0xFFF;
    }



    for(i = 0; i < acs->acs_nchans ; i++)
    {
        channel =  acs->acs_chans[i];
        cur_chan =  ieee80211_chan2ieee(acs->acs_ic, channel);

         /* WAR to handle channel 5,6,7 for HT40 mode (2 entries of channel are present) */
        if(((cur_chan >= 5) &&  (cur_chan <= 7))&& IEEE80211_IS_CHAN_11NG_HT40MINUS(channel)) {
            cur_chan = 15 + (cur_chan - 5);
        }
        if(acs->acs_channelrejflag[cur_chan])
            continue;
        priparamval = primparam[cur_chan];
        secparamval = secparam [cur_chan];


        if(rejhigher){

            if(  ( priparamval - primin)  > privar ){
                acs->acs_channelrejflag[cur_chan] |= rejflag;
                eacs_trace(EACS_DBG_RSSI,("Filter Rej %s Param Over %s ---Chan %d   Rej cur %d min %d delta %d  allowed %d \n "
                            ,secstr, pristr, cur_chan, priparamval, primin, (priparamval- primin), privar ));
            }
        }else{
            if(  ( priparamval - primin) <  privar ){
                acs->acs_channelrejflag[cur_chan] |= rejflag;
                eacs_trace(EACS_DBG_RSSI,("Filter Rej %s Param Over %s ---Chan %d   Rej cur %d min %d delta %d  allowed %d \n "
                            ,secstr, pristr, cur_chan, priparamval, primin, (priparamval- primin)*100/(primin+1), privar ));
            }
        }
        if(!(acs->acs_channelrejflag[cur_chan] & rejflag))
            eacs_trace(EACS_DBG_RSSI,("Filter Accept %s Param Over %s ---Chan %d    cur %d min %d delta %d  allowed %d \n "
                        ,secstr, pristr, cur_chan, priparamval, primin, (priparamval- primin), privar ));

        if(!acs->acs_channelrejflag[cur_chan] ){
            if(findmin ){
                if(  secparamval  <  *minval ){
                    minix = i;
                    *minval = secparamval;
                }
            }
            else{
                if(  secparamval  >  *minval ){
                    minix = i;
                    *minval = secparamval;
                }
            }
        }
    }
    return minix;
}

static int acs_find_secondary_80mhz_chan(ieee80211_acs_t acs, u_int8_t prichan)
{
    u_int8_t flag = 0;
    u_int16_t i;
    u_int8_t chan;
    struct ieee80211_channel *channel;

    do {
       for (i = 0; i < acs->acs_nchans; i++) {
           channel = acs->acs_chans[i];
           chan = ieee80211_chan2ieee(acs->acs_ic, channel);
           /* skip Primary 80 mhz channel */
           if((acs->acs_channelrejflag[chan] & ACS_REJFLAG_PRIMARY_80_80) ||
              (acs->acs_channelrejflag[chan] & ACS_REJFLAG_NO_SEC_80_80)) {
               continue;
           }
            /* Skip channels, if high NF is seen in its primary and secondary channels */
           if(!flag && (acs->acs_channelrejflag[chan] & ACS_REJFLAG_HIGHNOISE)) {
               continue;
           }
           if(!flag && acs->acs_adjchan_flag[chan]) {
               continue;
           }
           return i;
       }
       flag++;
    } while(flag < 2); /* loop for two iterations only */
    /* It should not reach here */
    return -1;
}

/**
 * @brief: EMIWAR to Skip the Secondary channel based on the EMIWAR Value
 *
 * @param acs
 * @param primary_channel
 *
 */
static
void acs_emiwar80p80_skip_secondary_80mhz_chan(ieee80211_acs_t acs,struct ieee80211_channel *primary_channel) {

    struct ieee80211com *ic = NULL;

    if((NULL == acs) || (NULL == primary_channel) || (NULL == acs->acs_ic))
        return;

    ic = acs->acs_ic;

    if(ic->ic_emiwar_80p80 == EMIWAR_80P80_FC1GTFC2) {
        /* WAR to skip all secondary 80 whose channel center freq ie less than primary channel center freq*/
        u_int8_t sec_channelrej_list[] = {36,40,44,48 /*1st 80MHz Band*/
                                          ,52,56,60,64 /*2nd 80MHz Band*/
                                          ,100,104,108,112/*3rd 80MHz Band*/
                                          ,116,120,124,128/*4th 80MHz Band*/
                                          ,132,136,140,144/*5th 80MHz Band*/};
        u_int8_t channelrej_num = 0;
        u_int8_t chan_i;

        switch(primary_channel->ic_vhtop_ch_freq_seg1) {
            case 58:
                channelrej_num = 4; /*Ignore the 1st 80MHz Band*/
                break;
            case 106:
                channelrej_num = 8; /*Ignore the 1st,2nd 80MHz Band*/
                break;
            case 122:
                channelrej_num = 12; /*Ignore the 1st,2nd and 3rd 80MHz Band*/
                break;
            case 138:
                channelrej_num = 16; /*Ignore the 1st,2nd,3rd and 4th 80MHz Band*/
                break;
            case 155:
                channelrej_num = 20; /*Ignore the 1st,2nd,3rd,4th and 5th 80MHz Band*/
                break;
            default:
                channelrej_num = 0;
                break;
        }

        for(chan_i=0;chan_i < channelrej_num;chan_i++)
            acs->acs_channelrejflag[sec_channelrej_list[chan_i]] |= ACS_REJFLAG_NO_SEC_80_80;

    }else if((ic->ic_emiwar_80p80 == EMIWAR_80P80_BANDEDGE) && (primary_channel->ic_vhtop_ch_freq_seg1 == 155)) {
        /* WAR to skip 42 as secondary 80, if 155 as primary 80 center freq */
        acs->acs_channelrejflag[36] |= ACS_REJFLAG_NO_SEC_80_80;
        acs->acs_channelrejflag[40] |= ACS_REJFLAG_NO_SEC_80_80;
        acs->acs_channelrejflag[44] |= ACS_REJFLAG_NO_SEC_80_80;
        acs->acs_channelrejflag[48] |= ACS_REJFLAG_NO_SEC_80_80;
    }
}

/**
 * @brief: Select the channel with least nbss
 *
 * @param ic
 *
 */
static INLINE struct ieee80211_channel *
ieee80211_acs_select_min_nbss(struct ieee80211com *ic)
{
#define ADJ_CHANS 8
#define NUM_CHANNELS_2G     11
#define CHANNEL_2G_FIRST    1
#define CHANNEL_2G_LAST     14
#define CHANNEL_5G_FIRST  36

    ieee80211_acs_t acs = ic->ic_acs;
    struct ieee80211_channel *channel = NULL, *best_channel = NULL, *channel_sec80 = NULL;
    u_int8_t i, ieee_chan, min_bss_count = 0xFF;
    u_int8_t acs_2gchannels[NUM_CHANNELS_2G] = {1, 2, 3, 4, 5, 6, 7, 8, 9 ,10, 11};
    u_int8_t channel_num = 0;
    int bestix = -1, bestix_sec80 = -1;
    u_int8_t pri20 = 0;
    u_int8_t sec_20 = 0;
    u_int8_t sec40_1 = 0;
    u_int8_t sec40_2 = 0;
    u_int8_t chan_i, first_adj_chan, last_adj_chan;

    channel = ieee80211_find_dot11_channel(ic, 0, 0, acs->acs_vap->iv_des_mode);
    channel_num = ieee80211_chan2ieee(acs->acs_ic, channel);

    if( (channel_num >= CHANNEL_2G_FIRST) && (channel_num <= CHANNEL_2G_LAST) ) {
        /* mode is 2.4 G */
        for(i = 0; i < NUM_CHANNELS_2G; i++)
        {
            ieee_chan = acs_2gchannels[i];
            if(acs->acs_2g_allchan == 0) {
                if((ieee_chan != 1) && (ieee_chan != 6) && (ieee_chan != 11)) {
                  continue;
                }
            }
            if (min_bss_count > acs->acs_chan_nbss[ieee_chan])
            {
                min_bss_count = acs->acs_chan_nbss[ieee_chan];
                best_channel = acs->acs_chans[ieee_chan -1];
            }
            eacs_trace(EACS_DBG_DEFAULT,("%s: select  channel %d and Bss counter is %d\r\n",
                        __func__,ieee80211_chan2ieee(acs->acs_ic, best_channel),min_bss_count));
        }
    } else if(channel_num >= CHANNEL_5G_FIRST) {
        /* mode is 5 G */
        for (i = 0; i < acs->acs_nchans; i++) {
            channel = acs->acs_chans[i];
            if (ieee80211_acs_check_interference(channel, acs->acs_vap) &&
                (ieee80211_find_dot11_channel(acs->acs_ic,
                          ieee80211_chan2ieee(acs->acs_ic, channel), channel->ic_vhtop_ch_freq_seg2,
                             acs->acs_vap->iv_des_mode) != NULL)) {
                    continue;
            }
            ieee_chan = ieee80211_chan2ieee(acs->acs_ic, channel);
            if(acs->acs_channelrejflag[ieee_chan] & ACS_REJFLAG_NO_PRIMARY_80_80)
                    continue;

            if (min_bss_count > acs->acs_chan_nbss[ieee_chan])
            {
                min_bss_count = acs->acs_chan_nbss[ieee_chan];
                best_channel = acs->acs_chans[i];
                bestix = i;
            }
        }
        if((best_channel) && (acs->acs_vap->iv_des_mode == IEEE80211_MODE_11AC_VHT80_80)) {
           channel = acs->acs_chans[bestix];
           pri20 = ieee80211_chan2ieee(acs->acs_ic, channel);
           ieee80211_acs_derive_sec_chans_with_mode(acs->acs_vap->iv_des_mode,
                                channel->ic_vhtop_ch_freq_seg1,
                                 pri20, &sec_20, &sec40_1, &sec40_2);

           acs->acs_channelrejflag[pri20] |= ACS_REJFLAG_PRIMARY_80_80;
           acs->acs_channelrejflag[sec_20] |= ACS_REJFLAG_PRIMARY_80_80;
           acs->acs_channelrejflag[sec40_1] |= ACS_REJFLAG_PRIMARY_80_80;
           acs->acs_channelrejflag[sec40_2] |= ACS_REJFLAG_PRIMARY_80_80;

           /* EMIWAR 80P80 to skip secondary 80 */
           if(ic->ic_emiwar_80p80) {
               acs_emiwar80p80_skip_secondary_80mhz_chan(acs,channel);
               /*
               * WAR clear the Primary Reject channle flag
               * So channel can be chose best secondary 80 mhz channel
               */

               for (i = 0; i < acs->acs_nchans; i++) {
                   ieee_chan = ieee80211_chan2ieee(acs->acs_ic, acs->acs_chans[i]);
                   acs->acs_channelrejflag[ieee_chan] &= ~ACS_REJFLAG_NO_PRIMARY_80_80;
               }
           }
           /* mark channels as unusable for secondary 80 */
           first_adj_chan = (channel->ic_vhtop_ch_freq_seg1 - 6) - 2*ADJ_CHANS;
           last_adj_chan =  (channel->ic_vhtop_ch_freq_seg1 + 6) + 2*ADJ_CHANS;
           for(chan_i=first_adj_chan;chan_i <= last_adj_chan; chan_i += 4) {
              if ((chan_i >= (channel->ic_vhtop_ch_freq_seg1 -6)) && (chan_i <= (channel->ic_vhtop_ch_freq_seg1 +6))) {
                 continue;
              }
              acs->acs_channelrejflag[chan_i] |= ACS_REJFLAG_NO_SEC_80_80;
           }
           bestix_sec80 = acs_find_secondary_80mhz_chan(acs, bestix);
           if(bestix_sec80 == -1) {
              QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Issue in Random secondary 80mhz channel selection \n");
           }
           else {
              channel_sec80 = acs->acs_chans[bestix_sec80];
              best_channel->ic_vhtop_ch_freq_seg2 = channel_sec80->ic_vhtop_ch_freq_seg1;
           }
        }
        eacs_trace(EACS_DBG_DEFAULT,("%s: select  channel %d and Bss counter is %d\r\n",
                     __func__,ieee80211_chan2ieee(acs->acs_ic, best_channel),min_bss_count));
    }
#undef NUM_CHANNELS_2G
#undef CHANNEL_2G_FIRST
#undef CHANNEL_2G_LAST
#undef CHANNEL_5G_FIRST
#undef ADJ_CHANS
    return best_channel;
}

/*  This function finds the best channe using ACS parameters */
static int acs_find_best_channel_ix(ieee80211_acs_t acs, int rssivarcor,
                                       int rssimin)
{
    int rssimix,minload,minloadix,maxregpower,maxregpowerindex;
    /*Find Best Channel load channel out of Best RSSI Channel with variation of 20%*/
    minload = 0xFFFF;
    minloadix  = eacs_plus_filter(acs,"RSSI",acs->acs_chan_rssitotal, "CHLOAD",
                             acs->acs_chan_loadsum, rssimin,
                             acs->acs_rssivar + rssivarcor, ACS_REJFLAG_RSSI,
                             &minload );

    if ((minloadix > 0) && (minloadix < IEEE80211_ACS_CHAN_MAX))
        eacs_trace(EACS_DBG_CHLOAD,("Minimum Ch load Channel %d \n",
                 ieee80211_chan2ieee(acs->acs_ic, acs->acs_chans[minloadix])));

    eacs_trace(EACS_DBG_DEFAULT,("Regulatory Filter \n"));
    maxregpower =0;
    maxregpowerindex  = eacs_plus_filter(acs,"CH LOAD",acs->acs_chan_loadsum,
                                          "REGPOWER", acs->acs_chan_regpower,
                                          minload, acs->acs_chloadvar,
                                          ACS_REJFLAG_CHANLOAD, &maxregpower );

    if ((maxregpowerindex > 0) && (maxregpowerindex < IEEE80211_ACS_CHAN_MAX))
        eacs_trace(EACS_DBG_REGPOWER,("Max Power of Channel %d \n",
          ieee80211_chan2ieee(acs->acs_ic, acs->acs_chans[maxregpowerindex])));


    rssimin = 1;
    rssimix  = eacs_plus_filter(acs,"REG POWER",acs->acs_chan_regpower,
                                  "RSSI TOTOAL", acs->acs_chan_rssitotal,
                        maxregpower, 0 ,  ACS_REJFLAG_REGPOWER, &rssimin );
    return rssimix;
}

/*
 * In 5 GHz, if the channel is unoccupied the max rssi
 * should be zero; just take it.Otherwise
 * track the channel with the lowest rssi and
 * use that when all channels appear occupied.
 */
static INLINE struct ieee80211_channel *
ieee80211_acs_find_best_11na_centerchan(ieee80211_acs_t acs)
{
#define ADJ_CHANS 8
    struct ieee80211_channel *channel, *channel_sec80;
    struct ieee80211_channel *tmpchannel;
    int i;
    int cur_chan;
    struct ieee80211_acs_adj_chan_stats *adj_chan_stats;
    int minnf,nfmix,rssimin,rssimix,bestix, bestix_sec80;
    int tmprssimix = 0;
    int rssivarcor=0,prinfclean = 0, secnfclean = 0;
    int reg_tx_power;
    u_int8_t pri20, sec_20, sec40_1, sec40_2;
    u_int8_t vht_center_freq;
    u_int8_t chan_i, first_adj_chan, last_adj_chan;
    struct ieee80211com *ic = acs->acs_ic;
#if ATH_SUPPORT_VOW_DCS
    u_int32_t nowms =  (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());
    u_int8_t ieee_chan, intr_chan_cnt = 0;

#define DCS_AGING_TIME 300000 /* 5 mins */
#define DCS_PENALTY    30     /* channel utilization in % */
#define DCS_DISABLE_THRESH 3  /* disable dcs, after these many channel change triggers */
    for (i = 0; i < acs->acs_nchans; i++) {
        channel = acs->acs_chans[i];
        if (ieee80211_acs_check_interference(channel, acs->acs_vap)) {
            continue;
        }
        ieee_chan = ieee80211_chan2ieee(acs->acs_ic, channel);
        if ( acs->acs_intr_status[ieee_chan] ){
            if ((nowms >= acs->acs_intr_ts[ieee_chan]) &&
                    ((nowms - acs->acs_intr_ts[ieee_chan]) <= DCS_AGING_TIME)){
                acs->acs_chan_load[ieee_chan] += DCS_PENALTY;
                intr_chan_cnt = acs->acs_intr_status[ieee_chan];
            }
            else{
                acs->acs_intr_status[ieee_chan] = 0;
            }
        }
    }
    if ( intr_chan_cnt >= DCS_DISABLE_THRESH ){
        /* To avoid frequent channel change,if channel change is
         * triggered three times in last 5 mins, disable dcs.
         */
        ic->ic_disable_dcsim(ic);
        /* Setting DCS Enable timer to enable DCS after a defined time interval
         * Flag used to check if timer is already set as DCS is still running for
         * CW interference mitigation. Avoids repeated setting of timer.
         */
        if(!acs->is_dcs_enable_timer_set) {
            OS_SET_TIMER(&acs->dcs_enable_timer, acs->dcs_enable_time*1000);
            acs->is_dcs_enable_timer_set = TRUE;
        }
    }
#undef DCS_AGING_TIME
#undef DCS_PENALTY
#undef DCS_DISABLE_THRESH
#endif



    eacs_trace(EACS_DBG_LVL1,(" %s \n",__func__));
    adj_chan_stats = (struct ieee80211_acs_adj_chan_stats *) OS_MALLOC(acs->acs_osdev,
            IEEE80211_CHAN_MAX * sizeof(struct ieee80211_acs_adj_chan_stats), 0);

    if (adj_chan_stats) {
        OS_MEMZERO(adj_chan_stats, sizeof(struct ieee80211_acs_adj_chan_stats)*IEEE80211_CHAN_MAX);
    }
    else {
        qdf_print("%s: malloc failed \n",__func__);
        return NULL;//ENOMEM;
    }


    acs->acs_minrssi_11na = 0xffffffff; /* Some large value */

    /* Scan through the channel list to find the best channel */
    minnf = 0xFFFF; /*Find max NF*/
    nfmix = -1;

    rssimin = 0xFFFF;
    rssimix= -1;

    if((acs->acs_vap->iv_des_mode == IEEE80211_MODE_11AC_VHT80_80) && \
          (acs->acs_ic->ic_emiwar_80p80 == EMIWAR_80P80_FC1GTFC2)) {
          /*
          * When EMIWAR is EMIWAR_80P80_FC1GTFC2
          * there will be no 80_80 channel combination for 149,153,157,161,
          * as we forcefully added the 80MHz channel to acs_chan list
          * mark those channle as NO Primary Select so acs will consider as primary channel
          * but can consider these channel as secondary channel.
          */
          for (i = 0; i < acs->acs_nchans; i++) {
              if(IEEE80211_MODE_11AC_VHT80_80 != ieee80211_chan2mode(acs->acs_chans[i])) {
                  cur_chan = ieee80211_chan2ieee(acs->acs_ic, acs->acs_chans[i]);
                  acs->acs_channelrejflag[cur_chan] |= ACS_REJFLAG_NO_PRIMARY_80_80;
              }
          }
    }

    for (i = 0; i < acs->acs_nchans; i++) {
        channel = acs->acs_chans[i];
        cur_chan = ieee80211_chan2ieee(acs->acs_ic, channel);

        /* The BLACKLIST flag need to be preserved for each channel till all
         * the channels are looped, since it is used rejecting the already
         * Ranked channels in the ACS ranking feature */
        if ((acs->acs_ranking) && (acs->acs_channelrejflag[cur_chan] & ACS_REJFLAG_BLACKLIST))
        {
            acs->acs_channelrejflag[cur_chan] &= ACS_REJFLAG_NO_PRIMARY_80_80;
            acs->acs_channelrejflag[cur_chan] |= ACS_REJFLAG_BLACKLIST;
        }
        else {
        /*Clear all the reject flag except ACS_REJFLAG_NO_PRIMARY_80_80*/
            acs->acs_channelrejflag[cur_chan] &= ACS_REJFLAG_NO_PRIMARY_80_80;
        }

        /* Check if it is 5GHz channel  */
        if (!IEEE80211_IS_CHAN_5GHZ(channel)){
            acs->acs_channelrejflag[cur_chan] |= ACS_FLAG_NON5G;
            continue;
        }
        /* Best Channel for VHT BSS shouldn't be the secondary channel of other BSS
         * Do not consider this channel for best channel selection
         */
        if((acs->acs_vap->iv_des_mode == IEEE80211_MODE_AUTO) ||
                (acs->acs_vap->iv_des_mode >= IEEE80211_MODE_11AC_VHT20)) {
            if(acs->acs_sec_chan[cur_chan] == true) {
                eacs_trace(EACS_DBG_DEFAULT, ("Skipping the chan %d for best channel selection If desired mode is AUTO/VHT\n",cur_chan));
                acs->acs_channelrejflag[cur_chan] |= ACS_REJFLAG_SECCHAN ;
            }
        }
        if(acs->acs_ic->ic_no_weather_radar_chan) {
            if(ieee80211_check_weather_radar_channel(channel)
                    && (acs->acs_ic->ic_get_dfsdomain(acs->acs_ic) == DFS_ETSI_DOMAIN)) {
                acs->acs_channelrejflag[cur_chan] |= ACS_REJFLAG_WEATHER_RADAR ;
                eacs_trace(EACS_DBG_DEFAULT,("Channel rej %d  Weather Radar Flag %x \n",cur_chan,acs->acs_channelrejflag[cur_chan]));
                continue;
            }
        }
        /* Check of DFS and other modes where we do not want to use the
         * channel
         */
        if (ieee80211_acs_check_interference(channel, acs->acs_vap)) {
            acs->acs_channelrejflag[cur_chan] |= ACS_REJFLAG_DFS ;
            eacs_trace(EACS_DBG_DEFAULT,("Channel rej %d  DFS  %x \n",cur_chan,acs->acs_channelrejflag[cur_chan]));

            continue;
        }

        /* Check if the noise floor value is very high. If so, it indicates
         * presence of CW interference (Video Bridge etc). This channel
         * should not be used
         */

        if ((minnf > acs->acs_noisefloor[cur_chan]) &&
             ((acs->acs_channelrejflag[cur_chan] & ACS_REJFLAG_SECCHAN) == 0) &&
             ((acs->acs_channelrejflag[cur_chan] & ACS_REJFLAG_NO_PRIMARY_80_80) == 0))
        {
            minnf = acs->acs_noisefloor[cur_chan];
            nfmix = i;
        }


        if ((acs->acs_noisefloor[cur_chan] != NF_INVALID) && (acs->acs_noisefloor[cur_chan] >= NOISE_FLOOR_THRESH) ) {
            eacs_trace(EACS_DBG_NF, ( "NF Rej Chan chan: %d maxrssi: %d, nf: %d\n",
                        cur_chan, acs->acs_chan_rssi[cur_chan], acs->acs_noisefloor[cur_chan] ));

            acs->acs_channelrejflag[cur_chan] |= ACS_REJFLAG_HIGHNOISE;
            acs->acs_chan_loadsum[cur_chan] = 100;
            if(acs->acs_chan_rssi[cur_chan] < 100) {
               acs->acs_chan_rssi[cur_chan] = 100;
            }

        }else{
            prinfclean++;
            acs->acs_chan_loadsum[cur_chan] = acs->acs_chan_load[cur_chan];
        }

        acs->acs_chan_rssitotal[cur_chan] = acs->acs_chan_rssi[cur_chan];

        if( !adj_chan_stats[i].if_valid_stats){
            ieee80211_acs_get_adj_ch_stats(acs, channel, &adj_chan_stats[i]);
            eacs_trace(EACS_DBG_RSSI,("Chan:%d  Channel RSSI %d adj RSSI %d \n",
                    cur_chan,acs->acs_chan_rssitotal[cur_chan] ,adj_chan_stats[i].adj_chan_rssisum));
            eacs_trace(EACS_DBG_CHLOAD,("Chan:%d  Channel Load %d  adj load %d \n",
                    cur_chan,acs->acs_chan_loadsum[cur_chan] ,adj_chan_stats[i].adj_chan_loadsum ));



            acs->acs_adjchan_load[cur_chan]    =  adj_chan_stats[i].adj_chan_load;
            acs->acs_chan_loadsum[cur_chan]   +=  adj_chan_stats[i].adj_chan_loadsum;
            acs->acs_chan_rssitotal[cur_chan] +=  adj_chan_stats[i].adj_chan_rssisum;
            acs->acs_adjchan_flag[cur_chan]       =  adj_chan_stats[i].adj_chan_flag;

            if(! acs->acs_adjchan_flag[cur_chan])
                secnfclean++;


        }


        if(!acs->acs_channelrejflag[cur_chan]){
            if(rssimin > acs->acs_chan_rssitotal[cur_chan]){
                rssimin = acs->acs_chan_rssitotal[cur_chan];
                rssimix = i;
            }
        }

        /*
         * ETSI UNII-II Ext band has different limits for STA and AP.
         * The software reg domain table contains the STA limits(23dBm).
         * For AP we adjust the max power(30dBm) dynamically
         */
        if (UNII_II_EXT_BAND(ieee80211_chan2freq(acs->acs_ic, channel))
                && (acs->acs_ic->ic_get_dfsdomain(acs->acs_ic) == DFS_ETSI_DOMAIN)){
            reg_tx_power = MIN( 30, channel->ic_maxregpower+7 );
        }
        else {
            reg_tx_power  = channel->ic_maxregpower;
        }
        eacs_trace(EACS_DBG_REGPOWER,("chan:%d received Tx power is %d: reg tx power is %d \n",
                                       cur_chan, acs->acs_chan_regpower[cur_chan], reg_tx_power));
        acs->acs_chan_regpower[cur_chan] = MIN( acs->acs_chan_regpower[cur_chan], reg_tx_power);

        /* check neighboring channel load
         * pending - first check the operating mode from beacon( 20MHz/40 MHz) and
         * based on that find the interfering channel
         */
        eacs_trace(EACS_DBG_RSSI,("Channel %d Rssi %d RssiTotal %d nf %d RegPower %d Load %d adjload %d weighted load %d   \n",
                    cur_chan,acs->acs_chan_rssi[cur_chan],acs->acs_chan_rssitotal[cur_chan],acs->acs_noisefloor[cur_chan],
                    acs->acs_chan_regpower[cur_chan], acs->acs_chan_load[cur_chan],
                    acs->acs_adjchan_load[cur_chan], acs->acs_chan_loadsum[cur_chan]));

    }

    if(prinfclean == 0){
        eacs_trace(EACS_DBG_DEFAULT, ( "Extreme Exceptional case all Channels flooded with NF\n"));
        eacs_trace(EACS_DBG_DEFAULT, ( "selecting minnfchang \n"));
        bestix = nfmix;
        goto selectchan;
    }

    if(secnfclean > 0){
        rssimix =-1;
        rssimin = 0xFFFF;

        /*apply adj channel nf free filter to main rej flag i recalculate rssimin*/
        for (i = 0; i < acs->acs_nchans; i++) {

            channel = acs->acs_chans[i];
            cur_chan = ieee80211_chan2ieee(acs->acs_ic, channel);
            acs->acs_channelrejflag[cur_chan] |= acs->acs_adjchan_flag[cur_chan];
            if(!acs->acs_channelrejflag[cur_chan]){
                if(rssimin > acs->acs_chan_rssitotal[cur_chan]){
                    rssimin = acs->acs_chan_rssitotal[cur_chan];
                    tmprssimix = i;
                }
            }
        }
        /*
        * Don't update the rssimix if all the secondary channels are rejected
        * and Clear the rejection flag
        */
        if(tmprssimix == -1) {
            for (i = 0; i < acs->acs_nchans; i++) {
               channel = acs->acs_chans[i];
               cur_chan = ieee80211_chan2ieee(acs->acs_ic, channel);
               acs->acs_channelrejflag[cur_chan] &= ~acs->acs_adjchan_flag[cur_chan];
            }
        } else {
            rssimix = tmprssimix;
        }

    }else{
        /*Non of the secondary are clean */
        /*Ignor the RSSI use only channle load */
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Rare Scenario All the channel has NF at the secondary channel \n");
        eacs_trace(EACS_DBG_DEFAULT, ( "ignore RSSI metric ,  increase variance to 1000  \n"));
        rssivarcor=1000;

    }



    if (rssimix > 0) {
        eacs_trace(EACS_DBG_RSSI,("Minimum Rssi Channel %d \n",ieee80211_chan2ieee(acs->acs_ic, acs->acs_chans[rssimix])));
    }

    bestix = rssimix;

    bestix = acs_find_best_channel_ix(acs, rssivarcor, rssimin);

selectchan :

    acs->acs_11nabestchan = bestix;
    if ((bestix >= 0) && (bestix < IEEE80211_ACS_CHAN_MAX)) {
        channel = acs->acs_chans[bestix];
#if ATH_SUPPORT_VOW_DCS
        ic->ic_eacs_done = 1;
#endif

        eacs_trace(EACS_DBG_DEFAULT,("80mhz index is %d ieee is %d \n",bestix, channel->ic_ieee));
        if(acs->acs_vap->iv_des_mode == IEEE80211_MODE_11AC_VHT80_80) {
            /* dervice primary and secondary channels from the channel */
           pri20 = channel->ic_ieee;
            /* Derive secondary channels */
           vht_center_freq = channel->ic_vhtop_ch_freq_seg1;
           ieee80211_acs_derive_sec_chans_with_mode(acs->acs_vap->iv_des_mode,
                                vht_center_freq, pri20, &sec_20, &sec40_1,
                                                         &sec40_2);
            /* Mark Primary 80Mhz channels for not selecting as secondary 80Mhz */
           acs->acs_channelrejflag[pri20] |= ACS_REJFLAG_PRIMARY_80_80;
           acs->acs_channelrejflag[sec_20] |= ACS_REJFLAG_PRIMARY_80_80;
           acs->acs_channelrejflag[sec40_1] |= ACS_REJFLAG_PRIMARY_80_80;
           acs->acs_channelrejflag[sec40_2] |= ACS_REJFLAG_PRIMARY_80_80;

           /* EMIWAR 80P80 to skip secondary 80 */
           if(ic->ic_emiwar_80p80)
               acs_emiwar80p80_skip_secondary_80mhz_chan(acs,channel);
           /* mark channels as unusable for secondary 80 */
           first_adj_chan = (vht_center_freq - 6) - 2*ADJ_CHANS;
           last_adj_chan =  (vht_center_freq + 6) + 2*ADJ_CHANS;
           for(chan_i=first_adj_chan;chan_i <= last_adj_chan; chan_i += 4) {
              if ((chan_i >= (vht_center_freq -6)) && (chan_i <= (vht_center_freq +6))) {
                 continue;
              }
              acs->acs_channelrejflag[chan_i] |= ACS_REJFLAG_NO_SEC_80_80;
           }

           tmprssimix = -1;
           for (i = 0; i < acs->acs_nchans; i++) {
               tmpchannel = acs->acs_chans[i];
               cur_chan = ieee80211_chan2ieee(acs->acs_ic, tmpchannel);
               rssimin = 0xFFFF;
               /*
               *  reset RSSI, CHANLOAD, REGPOWER, NO_PRIMARY_80_80 flags,
               *  to allow it chose best secondary 80 mhz channel
               */
               acs->acs_channelrejflag[cur_chan] = acs->acs_channelrejflag[cur_chan] &
                                                   (~(ACS_REJFLAG_RSSI | ACS_REJFLAG_CHANLOAD
                                                        | ACS_REJFLAG_REGPOWER | ACS_REJFLAG_SECCHAN
                                                        | ACS_REJFLAG_NO_PRIMARY_80_80));
               if(!acs->acs_channelrejflag[cur_chan]){
                   if(rssimin > acs->acs_chan_rssitotal[cur_chan]){
                       rssimin = acs->acs_chan_rssitotal[cur_chan];
                       tmprssimix = i;
                   }
               }
           }
           if(tmprssimix != -1) {
              bestix_sec80 = tmprssimix;
           }
            /* how to handle DFS channels XXX*/
           bestix_sec80 = acs_find_best_channel_ix(acs, rssivarcor, rssimin);
           eacs_trace(EACS_DBG_DEFAULT,("bestix_sec80 index is %d \n",bestix_sec80));
            /* Could not find the secondary 80mhz channel, pick random channel as
               secondary 80mhz channel */
           if (!((bestix_sec80 >= 0) && (bestix_sec80 < IEEE80211_ACS_CHAN_MAX))) {
              bestix_sec80 = acs_find_secondary_80mhz_chan(acs, bestix);
              QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Random channel is selected for secondary 80Mhz, index is %d \n",bestix_sec80);
           }
           if(bestix_sec80 == -1) {
              QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Issue in Random secondary 80mhz channel selection \n");
           }
           else {
              channel_sec80 = acs->acs_chans[bestix_sec80];
              eacs_trace(EACS_DBG_DEFAULT,("secondary 80mhz index is %d ieee is %d \n",bestix_sec80, channel_sec80->ic_ieee));
              channel = ieee80211_find_dot11_channel(acs->acs_ic, channel->ic_ieee, channel_sec80->ic_vhtop_ch_freq_seg1, IEEE80211_MODE_11AC_VHT80_80);
           }
        }
    } else {
        /* If no channel is derived, then pick the random channel(least BSS) for operation */
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ACS failed to derive the channel. So,selecting channel with least BSS \n");
        channel = ieee80211_acs_select_min_nbss(acs->acs_ic);
        if (channel == NULL) {
            if(acs->acs_vap->iv_des_mode == IEEE80211_MODE_11AC_VHT80_80) {
                acs->acs_ic->ic_curchan->ic_vhtop_ch_freq_seg2 = ieee80211_mhz2ieee(acs->acs_ic, 5775, acs->acs_ic->ic_curchan->ic_flags);
            }
            channel = ieee80211_find_dot11_channel(acs->acs_ic, 0, 0, acs->acs_vap->iv_des_mode);
            eacs_trace(EACS_DBG_DEFAULT,("Func = %s Selected dot11 channel %d  \n",__func__, ieee80211_chan2ieee(acs->acs_ic, channel)));
        }
        if(channel) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "random channel is %d \n",channel->ic_ieee);
        }

        /* In case of ACS ranking this is called multiple times and creates
		 * lot of logs on console */
        if (!acs->acs_ranking) {
            ieee80211_acs_scan_report_internal(acs->acs_ic);
        }
    }
    OS_FREE(adj_chan_stats);
    return channel;
#undef ADJ_CHANS
}



static int32_t ieee80211_acs_find_channel_totalrssi(ieee80211_acs_t acs, const int *chanlist, int chancount, u_int8_t centChan)
{
    u_int8_t chan;
    int i;
    u_int32_t totalrssi = 0; /* total rssi for all channels so far */
    int effchfactor;

    if (chancount <= 0) {
        /* return a large enough number for not to choose this channel */
        return 0xffffffff;
    }


    for (i = 0; i < chancount; i++) {
        chan = chanlist[i];

        effchfactor = chan - centChan;

        if(effchfactor < 0)
            effchfactor = 0 - effchfactor;

        effchfactor += 1;

        totalrssi += acs->acs_chan_rssi[chan]/effchfactor;
        eacs_trace(EACS_DBG_RSSI,( "chan: %d  effrssi: %d factor %d centr %d ",  chan, acs->acs_chan_rssi[chan],effchfactor,centChan));
    }
    acs->acs_chan_rssitotal[centChan] = totalrssi;
    eacs_trace(EACS_DBG_RSSI,( "chan: %d final rssi: %d ",  centChan, acs->acs_chan_rssitotal[centChan]));
    return totalrssi;
}


static INLINE struct ieee80211_channel *
ieee80211_acs_find_best_11ng_centerchan(ieee80211_acs_t acs)
{
    struct ieee80211_channel *channel;
    int i;
    u_int8_t chan;
#if 0
    u_int8_t band;
#endif
    unsigned int   totalrssi = 0;
    int            bestix,nfmin , nfmix, loadmin,rssimin,rssimix;
    int            minloadix, maxregpower, maxregpowerindex = 0;
    int            extchan,ht40minus_chan ;
    int rssivarcor=0;
    int32_t mode_mask = (IEEE80211_CHAN_11NG_HT40PLUS |
            IEEE80211_CHAN_11NG_HT40MINUS);

#if ATH_SUPPORT_VOW_DCS
    struct ieee80211com *ic = acs->acs_ic;
#endif


    /*
     * The following center chan data structures are used to calculare the
     * the Total RSSI of beacon seen in the center chan and overlapping channel
     * The channle with minimum Rssi gets piccked up as best channel
     * The channel with 20% Rssi variance with minimum will go for next phase of
     * filteration for channel load.
     */

    static const u_int center1[]   =   { 1, 2, 3 };
    static const u_int center2[]   =   { 1, 2, 3, 4};
    static const u_int center3[]   =   { 1, 2, 3, 4, 5};
    static const u_int center4[]   =   { 2, 3, 4, 5, 6};
    static const u_int center5[]   =   { 3, 4, 5, 6, 7};
    static const u_int center6[]   =   { 4, 5, 6, 7, 8 };
    static const u_int center7[]   =   { 5, 6, 7, 8, 9 };
    static const u_int center8[]   =   { 6, 7, 8, 9, 10 };
    static const u_int center9[]   =   { 7, 8, 9, 10, 11 };
    static const u_int center10[]   =  { 8, 9, 10, 11};
    static const u_int center11[]   = { 9, 10, 11 };

    struct centerchan {
        int count;               /* number of chans to average the rssi */
        const u_int *chanlist;   /* the possible beacon channels around center chan */
    };

#define X(a)    sizeof(a)/sizeof(a[0]), a

    struct centerchan centerchans[] = {
        { X(center1) },
        { X(center2) },
        { X(center3) },
        { X(center4) },
        { X(center5) },
        { X(center6) },
        { X(center7) },
        { X(center8) },
        { X(center9) },
        { X(center10) },
        { X(center11) }
    };
    acs->acs_minrssisum_11ng = 0xffffffff;

    bestix  = -1;
    nfmin   = 0xFFFF;
    nfmix   = -1;
    rssimin = 0xFFFF;
    rssimix = -1;

    for (i = 0; i < acs->acs_nchans; i++) {
        channel = acs->acs_chans[i];
        chan = ieee80211_chan2ieee(acs->acs_ic, channel);

        /* The BLACKLIST flag need to be preserved for each channel till all
         * the channels are looped, since it is used rejecting the already
         * Ranked channels in the ACS ranking feature */
        if ((acs->acs_ranking) && (acs->acs_channelrejflag[chan] & ACS_REJFLAG_BLACKLIST)) {
            acs->acs_channelrejflag[chan] = 0;
            acs->acs_channelrejflag[chan] |= ACS_REJFLAG_BLACKLIST;
        }
        else {
            acs->acs_channelrejflag[chan] = 0;
        }
        if(chan > 11)
        {
            acs->acs_channelrejflag[chan] |= ACS_REJFLAG_NON2G;
            continue;
        }
        if(acs->acs_2g_allchan == 0) {
            if ((chan != 1) && (chan != 6) && (chan != 11)) {
                /* Don't bother with other center channels except for 1, 6 & 11 */
                acs->acs_channelrejflag[chan] |= ACS_REJFLAG_NON2G;
                continue;
            }
        }
        eacs_trace(EACS_DBG_REGPOWER,("chan:%d received Tx power is %d: reg tx power is %d \n", chan,
                                      acs->acs_chan_regpower[chan], channel->ic_maxregpower));
        acs->acs_chan_regpower[chan] = MIN(acs->acs_chan_regpower[chan],
                                                           channel->ic_maxregpower);
        if (acs->acs_ch_hopping.ch_max_hop_cnt < ACS_CH_HOPPING_MAX_HOP_COUNT &&
                ieee80211com_has_cap_ext(acs->acs_ic,IEEE80211_ACS_CHANNEL_HOPPING)) {
            if(IEEE80211_CH_HOPPING_IS_CHAN_BLOCKED(channel)) {
                acs->acs_channelrejflag[chan] |= ACS_REJFLAG_NON2G;
                continue;
            }
        }
        /* find the Total rssi for this 40Mhz band */
        totalrssi = ieee80211_acs_find_channel_totalrssi(acs, centerchans[chan-1].chanlist, centerchans[chan-1].count, chan);

        /*OBSS check */

        switch (channel->ic_flags & mode_mask)
        {
            case IEEE80211_CHAN_11NG_HT40PLUS:
                extchan = chan + 4;
                eacs_trace(EACS_DBG_CHLOAD,("IEEE80211_CHAN_11NG_HT40PLUS   ext %d \n",extchan));
                break;
            case IEEE80211_CHAN_11NG_HT40MINUS:
                extchan = chan - 4;
                eacs_trace(EACS_DBG_CHLOAD,(" IEEE80211_CHAN_11NG_HT40MINUS  ext %d \n",extchan));
                break;
            default: /* neither HT40+ nor HT40-, finish this call */
                extchan =0;
                eacs_trace(EACS_DBG_CHLOAD,("Error \n"));
                break;
        }
        if((extchan > 0) && (extchan < IEEE80211_ACS_CHAN_MAX))	{
            eacs_trace(EACS_DBG_CHLOAD,( "Chan Load%d =%d ext_chan%d = %d \n",
                         chan, acs->acs_chan_load[chan], extchan, acs->acs_chan_load[extchan]));
        }
        eacs_trace(EACS_DBG_RSSI,( " chan: %d beacon RSSI %di Noise FLoor %d ",  chan,
                                      totalrssi,acs->acs_noisefloor[chan]));
         /* WAR to handle channel 6 for HT40 mode (2 entries of channel 6 are present) */
        if(((chan >= 5)&& (chan <= 7)) && IEEE80211_IS_CHAN_11NG_HT40MINUS(channel)) {

            ht40minus_chan = 15 + (chan-5);
            acs->acs_chan_loadsum[ht40minus_chan] = acs->acs_chan_load[chan];
            acs->acs_chan_regpower[ht40minus_chan] = acs->acs_chan_regpower[chan];
            acs->acs_chan_rssitotal[ht40minus_chan] = acs->acs_chan_rssitotal[chan];
            acs->acs_channelrejflag[ht40minus_chan] = acs->acs_channelrejflag[chan];
            acs->acs_noisefloor[ht40minus_chan] = acs->acs_noisefloor[chan];
            chan = ht40minus_chan;
        }
        else {
            acs->acs_chan_loadsum[chan] = acs->acs_chan_load[chan];
        }
        if((extchan > 0) && (extchan < IEEE80211_ACS_CHAN_MAX))	{
            if ((acs->acs_noisefloor[extchan] !=NF_INVALID) && (acs->acs_noisefloor[extchan] < ACS_11NG_NOISE_FLOOR_REJ))
                acs->acs_chan_loadsum[chan] += acs->acs_chan_load[extchan]/2;
            else
                acs->acs_chan_loadsum[chan] += 50;
        }

        if( nfmin > acs->acs_noisefloor[chan]){
            nfmin = acs->acs_noisefloor[chan];
            nfmix = i;
        }


        if ( (acs->acs_noisefloor[chan] !=NF_INVALID) && (acs->acs_noisefloor[chan] > ACS_11NG_NOISE_FLOOR_REJ)){
            eacs_trace(EACS_DBG_NF,("NF Skipping Channel %d : NF %d  ",chan,acs->acs_noisefloor[chan]));
            acs->acs_channelrejflag[chan]|= ACS_REJFLAG_HIGHNOISE;
            acs->acs_chan_loadsum[chan] += 100;
            continue;
        }
        if( rssimin > totalrssi){
            rssimin = totalrssi;
            rssimix = i;

        }

    }

    if(rssimin == -1){
        eacs_trace(EACS_DBG_DEFAULT, ("Unlikely scenario where all channels are heaving high noise"));
        bestix =nfmix;
        goto selectchan;

    }

    bestix = rssimix;


    /*Find Best Channel load channel out of Best RSSI Channel with variation of 20%*/
    loadmin = 0xFFFF;
    minloadix  = eacs_plus_filter(acs,"RSSI",acs->acs_chan_rssitotal, "CHLOAD",	acs->acs_chan_loadsum,
            rssimin, acs->acs_rssivar + rssivarcor, ACS_REJFLAG_RSSI, &loadmin);

    if ((minloadix > 0) && (minloadix < IEEE80211_ACS_CHAN_MAX))
        eacs_trace(EACS_DBG_CHLOAD,("Minimum Ch load Channel %d \n",ieee80211_chan2ieee(acs->acs_ic, acs->acs_chans[minloadix])));

    eacs_trace(EACS_DBG_DEFAULT,("Regulatory Filter \n"));
    maxregpower =0;
    maxregpowerindex  = eacs_plus_filter(acs,"CH LOAD",acs->acs_chan_loadsum, "REGPOWER", acs->acs_chan_regpower,
            loadmin, acs->acs_chloadvar,  ACS_REJFLAG_CHANLOAD, &maxregpower );


    if ((maxregpowerindex > 0) && (maxregpowerindex < IEEE80211_ACS_CHAN_MAX))
        eacs_trace(EACS_DBG_REGPOWER,("Max Power of Channel %d \n",ieee80211_chan2ieee(acs->acs_ic, acs->acs_chans[maxregpowerindex])));


    rssimin = 1;
    rssimix  = eacs_plus_filter(acs,"REG POWER",acs->acs_chan_regpower, "RSSI TOTOAL", acs->acs_chan_rssitotal,
            maxregpower, 0 ,  ACS_REJFLAG_REGPOWER, &rssimin );


    bestix = rssimix;

selectchan:


    acs->acs_11ngbestchan = bestix;
    if ((bestix >= 0) && (bestix < IEEE80211_ACS_CHAN_MAX)) {
        channel = acs->acs_chans[bestix];

#if ATH_SUPPORT_VOW_DCS
        ic->ic_eacs_done = 1;
#endif
        eacs_trace(EACS_DBG_CHLOAD,("Best Channel Selected %d rssi %d nf %d ",
                ieee80211_chan2ieee(acs->acs_ic, channel),rssimin,
                acs->acs_noisefloor[ieee80211_chan2ieee(acs->acs_ic, channel)] ));
    } else {
         /* If no channel is derived, then pick the random channel(least BSS) for operation */
        channel = ieee80211_acs_select_min_nbss(acs->acs_ic);
        if (channel == NULL) {
            channel = ieee80211_find_dot11_channel(acs->acs_ic, 0, 0, acs->acs_vap->iv_des_mode);
            eacs_trace(EACS_DBG_DEFAULT,("Func = %s Selected dot11 channel %d  \n",__func__, ieee80211_chan2ieee(acs->acs_ic, channel)));
        }
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ACS failed to derive the channel. So,selecting random channel \n");

       /* In case of ACS ranking this is called multiple times and creates lot of logs on console */
       if (!acs->acs_ranking) {
            ieee80211_acs_scan_report_internal(acs->acs_ic);
       }
    }

    return channel ;


}

static INLINE struct ieee80211_channel *
ieee80211_acs_find_best_auto_centerchan(ieee80211_acs_t acs)
{
    struct ieee80211_channel *channel_11na, *channel_11ng;

    u_int32_t ieee_chan_11na, ieee_chan_11ng;

    eacs_trace(EACS_DBG_LVL1,(" %s \n",__func__));
    channel_11na = ieee80211_acs_find_best_11na_centerchan(acs);
    channel_11ng = ieee80211_acs_find_best_11ng_centerchan(acs);

    ieee_chan_11ng = ieee80211_chan2ieee(acs->acs_ic, channel_11ng);
    ieee_chan_11na = ieee80211_chan2ieee(acs->acs_ic, channel_11na);
    eacs_trace(EACS_DBG_LVL0, ( "11na chan: %d rssi: %d, 11ng chan: %d rssi: %d",
                ieee80211_chan2ieee(acs->acs_ic, channel_11na), acs->acs_minrssi_11na,
                ieee80211_chan2ieee(acs->acs_ic, channel_11ng), acs->acs_minrssisum_11ng));


    /* Do channel load comparison only if radio supports both 11ng and 11na */
    if ((ieee_chan_11ng != 0) && (ieee_chan_11na != 0)) {
    /* Check which of them have the minimum channel load. If both have the same,
     * choose the 5GHz channel
     */
        if (acs->acs_chan_load[ieee_chan_11ng] < acs->acs_chan_load[ieee_chan_11na]) {
            return channel_11ng;
        } else {
            return channel_11na;
        }
    } else if (ieee_chan_11na != 0) {
            return channel_11na;
    } else if (ieee_chan_11ng != 0) {
            return channel_11ng;
    } else {
            return IEEE80211_CHAN_ANYC;
    }
}

static INLINE struct ieee80211_channel *
ieee80211_acs_find_best_centerchan(ieee80211_acs_t acs)
{
    struct ieee80211_channel *channel;

    eacs_trace(EACS_DBG_LVL1,(" %s \n",__func__));
    switch (acs->acs_vap->iv_des_mode)
    {
        case IEEE80211_MODE_11A:
        case IEEE80211_MODE_TURBO_A:
        case IEEE80211_MODE_11NA_HT20:
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
        case IEEE80211_MODE_11NA_HT40:
        case IEEE80211_MODE_11AC_VHT20:
        case IEEE80211_MODE_11AC_VHT40PLUS:
        case IEEE80211_MODE_11AC_VHT40MINUS:
        case IEEE80211_MODE_11AC_VHT40:
        case IEEE80211_MODE_11AC_VHT80:
        case IEEE80211_MODE_11AC_VHT160:
        case IEEE80211_MODE_11AC_VHT80_80:
            channel = ieee80211_acs_find_best_11na_centerchan(acs);
            break;

        case IEEE80211_MODE_11B:
        case IEEE80211_MODE_11G:
        case IEEE80211_MODE_TURBO_G:
        case IEEE80211_MODE_11NG_HT20:
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40:
            channel = ieee80211_acs_find_best_11ng_centerchan(acs);
            break;

        default:
            if (acs->acs_scan_2ghz_only) {
                channel = ieee80211_acs_find_best_11ng_centerchan(acs);
            } else {
                channel = ieee80211_acs_find_best_auto_centerchan(acs);
            }
            break;
    }
#if ATH_ACS_SUPPORT_SPECTRAL && ATH_SUPPORT_SPECTRAL
    acs->acs_ic->ic_stop_spectral_scan(acs->acs_ic);
#endif

    return channel;
}

/*
 * Find all channels with active AP's.
 */
static int
ieee80211_mark_ht40intol(void *arg, wlan_scan_entry_t se)
{
    struct ieee80211_channel *scan_chan = ieee80211_scan_entry_channel(se);

    struct acs_obsscheck *ochk = (struct acs_obsscheck *) arg ;

    int i, sechan;
    ieee80211_acs_t acs = NULL;
    struct ieee80211com *ic = NULL;
    struct ieee80211_channel *channel = NULL;
    u_int8_t obss_rssi = 0;

    if ((ochk == NULL) || (ochk->acs == NULL) || (ochk->acs->acs_ic == NULL)) {
        eacs_trace(EACS_DBG_OBSS,("vap/acs/ic is null\n"));
        return EINVAL;
    }

    acs = ochk->acs;
    ic = acs->acs_ic;
    channel = ochk->channel;

    sechan = ieee80211_chan2ieee(acs->acs_ic, scan_chan);
    eacs_trace(EACS_DBG_OBSS, ("Scan entry ssid %s rssi %d channel %d \n", ieee80211_scan_entry_ssid(se,(u_int8_t *)&i),ieee80211_scan_entry_rssi(se), sechan));


    /* If we see any beacon with some RSSI mark that channel as intolaraent */
    obss_rssi = ieee80211_scan_entry_rssi(se);

    if(obss_rssi <= ic->obss_rssi_threshold ) {
        eacs_trace(EACS_DBG_OBSS, ("rejecting scan entry for %d rssi < less than threshold value: %d > \n", obss_rssi, ic->obss_rssi_threshold));
        return EOK;
    }

    if (ochk->onlyextcheck){
        if ( ochk->extchan == sechan){
            eacs_trace(EACS_DBG_OBSS,("Found Scan entry on Ext chan %d   marking overlap detected for Chan %d  \n",
                        ochk->extchan, ieee80211_chan2ieee(acs->acs_ic, channel)));
            channel->ic_flags |= IEEE80211_CHAN_HT40INTOL;
        }
    }else{
        /* In case of primary channel we should not consider for OBSS */
        if (sechan == ieee80211_chan2ieee(acs->acs_ic, channel)) {
            eacs_trace(EACS_DBG_OBSS,("Found Scan entry on Primary chan %d reject scan entry \n",
                        ieee80211_chan2ieee(acs->acs_ic, channel)));

            return EOK;
        }

        if ((sechan >= ochk->olminlimit) && (sechan <= ochk->olmaxlimit)){
            eacs_trace(EACS_DBG_OBSS,("Scan entry Chan %d within overlap range ( %d - %d ) -Marking chan %d \n",
                        sechan, ochk->olminlimit, ochk->olmaxlimit,
                        ieee80211_chan2ieee(acs->acs_ic, channel)));
            channel->ic_flags |= IEEE80211_CHAN_HT40INTOL;
        }
    }
    return EOK;
}

static void
ieee80211_find_ht40intol_overlap(ieee80211_acs_t acs,
        struct ieee80211_channel *channel)
{
#define CEILING 12
#define FLOOR    1
#define HT40_NUM_CHANS 4
    u_int8_t ieee_chan = ieee80211_chan2ieee(acs->acs_ic, channel);


    int mean_chan,extchan;

    int32_t mode_mask = (IEEE80211_CHAN_11NG_HT40PLUS |
            IEEE80211_CHAN_11NG_HT40MINUS);
    struct acs_obsscheck obsschk;

    eacs_trace(EACS_DBG_OBSS,(" %s \n",__func__));

    if (!channel)
        return;

    switch (channel->ic_flags & mode_mask)
    {
        case IEEE80211_CHAN_11NG_HT40PLUS:
            mean_chan = ieee_chan + 2;
            extchan = mean_chan + 2;
            eacs_trace(EACS_DBG_OBSS,("IEEE80211_CHAN_11NG_HT40PLUS  mean %d ext %d \n",mean_chan,extchan));
            break;
        case IEEE80211_CHAN_11NG_HT40MINUS:
            mean_chan = ieee_chan - 2;
            extchan = mean_chan - 2;
            eacs_trace(EACS_DBG_OBSS,(" IEEE80211_CHAN_11NG_HT40MINUS  mean %d ext %d \n",mean_chan,extchan));
            break;
        default: /* neither HT40+ nor HT40-, finish this call */
            eacs_trace(EACS_DBG_OBSS,("Eroor \n"));
            return;
    }


    /* We should mark the intended channel as IEEE80211_CHAN_HTINTOL
       if the intended frequency overlaps the iterated channel partially */

    /* According to 802.11n 2009, affected channel = [mean_chan-5, mean_chan+5] */
    obsschk.acs = acs;
    obsschk.channel = channel;
    obsschk.onlyextcheck = acs->acs_limitedbsschk;
    obsschk.extchan = extchan;
    obsschk.olminlimit = MAX(mean_chan-HT40_NUM_CHANS, FLOOR);
    obsschk.olmaxlimit  = MIN(CEILING,mean_chan+HT40_NUM_CHANS);

    wlan_scan_table_iterate(acs->acs_vap, ieee80211_mark_ht40intol, (void *)&obsschk);

    if ((extchan > 0) &&(( acs->acs_noisefloor[extchan] != NF_INVALID) && (acs->acs_noisefloor[extchan] > ACS_11NG_NOISE_FLOOR_REJ) )){
        eacs_trace(EACS_DBG_OBSS, (" Reject extension channel: %d  noise is: %d ",extchan,acs->acs_noisefloor[extchan]));
        channel->ic_flags |= IEEE80211_CHAN_HT40INTOL;
    }

    eacs_trace(EACS_DBG_OBSS, (" selected chan %d  overlap %x ",ieee_chan,(channel->ic_flags & IEEE80211_CHAN_HT40INTOL)));

#undef CEILING
#undef FLOOR
#undef HT40_NUM_CHANS
}

static int
ieee80211_get_chan_neighbor_list(void *arg, wlan_scan_entry_t se)
{
    ieee80211_chan_neighbor_list *chan_neighbor_list = (ieee80211_chan_neighbor_list *) arg ;
    struct ieee80211_channel *channel_se = NULL;
    u_int8_t channel_ieee_se;
    int nbss;
    u_int8_t ssid_len;
    u_int8_t *ssid = NULL;
    u_int8_t *bssid = NULL;
    u_int8_t  rssi = 0;
    u_int32_t phymode = 0;
    ieee80211_acs_t acs = NULL;
    struct ieee80211com *ic = NULL;

    /* sanity check */
    if ((chan_neighbor_list == NULL) || (chan_neighbor_list->acs == NULL) || (chan_neighbor_list->acs->acs_ic == NULL) ) {
        eacs_trace(EACS_DBG_OBSS,("vap/acs/ic/ssid is null\n"));
        return EINVAL;
    }

    ssid = (char *)ieee80211_scan_entry_ssid(se, &ssid_len);
    bssid = (char *)ieee80211_scan_entry_bssid(se);
    rssi = ieee80211_scan_entry_rssi(se);
    phymode = ieee80211_scan_entry_phymode(se);

    if ((ssid == NULL) || (bssid == NULL)) {
        eacs_trace(EACS_DBG_OBSS,("ssid/bssid is null\n"));
        return EINVAL;
    }

    acs = chan_neighbor_list->acs;
    ic = acs->acs_ic;
    nbss = chan_neighbor_list->nbss;
    channel_se = ieee80211_scan_entry_channel(se);
    channel_ieee_se = ieee80211_chan2ieee(acs->acs_ic, channel_se);

    /* Only copy the SSID if it in current channel scan entry */
    if ((channel_ieee_se == chan_neighbor_list->chan) && (nbss < IEEE80211_MAX_NEIGHBOURS)) {
        memcpy(chan_neighbor_list->neighbor_list[nbss].ssid, ssid, ssid_len);
        if (ssid_len < IEEE80211_NWID_LEN) {
            chan_neighbor_list->neighbor_list[nbss].ssid[ssid_len] = '\0';
        }
        else {
            chan_neighbor_list->neighbor_list[nbss].ssid[IEEE80211_NWID_LEN] = '\0';
        }
        memcpy(chan_neighbor_list->neighbor_list[nbss].bssid, bssid, IEEE80211_ADDR_LEN);
        chan_neighbor_list->neighbor_list[nbss].rssi = rssi;
        chan_neighbor_list->neighbor_list[nbss].phymode = phymode;
        chan_neighbor_list->nbss++;
    }

    return EOK;

}

static int ieee80211_acs_derive_sec_chans_with_mode(u_int8_t phymode,
        u_int8_t vht_center_freq, u_int8_t channel_ieee_se,
        u_int8_t *sec_chan_20, u_int8_t *sec_chan_40_1, u_int8_t *sec_chan_40_2)
{
    int8_t pri_center_ch_diff;
    int8_t sec_level;


    switch (phymode)
    {
        /*secondary channel for VHT40MINUS and NAHT40MINUS is same */
        case IEEE80211_MODE_11NA_HT40MINUS:
        case IEEE80211_MODE_11AC_VHT40MINUS:
            *sec_chan_20 = channel_ieee_se - 4;
            break;
            /*secondary channel for VHT40PLUS and NAHT40PLUS is same */
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11AC_VHT40PLUS:
            *sec_chan_20 = channel_ieee_se + 4;
            break;
        case IEEE80211_MODE_11AC_VHT80:
        case IEEE80211_MODE_11AC_VHT80_80:

            /* For VHT mode, The center frequency is given in VHT OP IE
             * For example: 42 is center freq and 36 is primary channel
             * then secondary 20 channel would be 40 and secondary 40 channel
             * would be 44
             */
            pri_center_ch_diff = channel_ieee_se - vht_center_freq;

            /* Secondary 20 channel would be less(2 or 6) or more (2 or 6)
             * than center frequency based on primary channel
             */
            if(pri_center_ch_diff > 0) {
                sec_level = LOWER_FREQ_SLOT;
                *sec_chan_40_1 = vht_center_freq + SEC_40_LOWER;
            }
            else {
                sec_level = UPPER_FREQ_SLOT;
                *sec_chan_40_1 = vht_center_freq - SEC_40_UPPER;
            }
            *sec_chan_40_2 = *sec_chan_40_1 + 4;
            if((sec_level*pri_center_ch_diff) < -2)
                *sec_chan_20 = vht_center_freq - (sec_level* SEC20_OFF_2);
            else
                *sec_chan_20 = vht_center_freq - (sec_level* SEC20_OFF_6);

            break;

        case IEEE80211_MODE_11AC_VHT160:

            /* For VHT mode, The center frequency is given in VHT OP IE
             * For example: 42 is center freq and 36 is primary channel
             * then secondary 20 channel would be 40 and secondary 40 channel
             * would be 44
             */
            pri_center_ch_diff = channel_ieee_se - vht_center_freq;

            /* Secondary 20 channel would be less(2 or 6) or more (2 or 6)
             * than center frequency based on primary channel
             */
            if(pri_center_ch_diff > 0) {
                sec_level = LOWER_FREQ_SLOT;
                *sec_chan_40_1 = vht_center_freq + SEC_40_LOWER;
            }
            else {
                sec_level = UPPER_FREQ_SLOT;
                *sec_chan_40_1 = vht_center_freq - SEC_40_UPPER;
            }
            *sec_chan_40_2 = *sec_chan_40_1 + 4;
            if((sec_level*pri_center_ch_diff) < -2)
                *sec_chan_20 = vht_center_freq - (sec_level* SEC20_OFF_2);
            else
                *sec_chan_20 = vht_center_freq - (sec_level* SEC20_OFF_6);

            break;
    }

    return EOK;
}


/*
 * Derive secondary channels based on the phy mode of the scan entry
 */
static int ieee80211_acs_derive_sec_chan(wlan_scan_entry_t se,
        u_int8_t channel_ieee_se, u_int8_t *sec_chan_20,
        u_int8_t *sec_chan_40_1, u_int8_t *sec_chan_40_2, struct ieee80211vap *vap)
{
    u_int8_t vht_center_freq = 0;
    u_int8_t phymode_se;
    struct ieee80211_ie_vhtop *vhtop = NULL;
    struct ieee80211_ie_htinfo_cmn *htinfo = NULL;
    struct ieee80211_ie_vhtcap *vhtinfo = NULL;
    u_int32_t vhtcap = 0;


    phymode_se = wlan_scan_entry_phymode(se);

    switch (phymode_se)
    {
        case IEEE80211_MODE_11AC_VHT80:
        case IEEE80211_MODE_11AC_VHT80_80:
        case IEEE80211_MODE_11AC_VHT160:
            vhtop = (struct ieee80211_ie_vhtop *)ieee80211_scan_entry_vhtop(se);
            htinfo = (struct ieee80211_ie_htinfo_cmn *)ieee80211_scan_entry_htinfo(se);
            vhtinfo = (struct ieee80211_ie_vhtcap *)ieee80211_scan_entry_htinfo(se);
            vhtcap = le32toh(vhtinfo->vht_cap_info);
            if (peer_ext_nss_capable(vhtinfo) && vap->iv_ext_nss_capable) {
               vht_center_freq = retrieve_seg2_for_extnss_80p80(&vhtcap, vhtop, htinfo);
            } else if (IS_REVSIG_VHT160(vhtop)) {
                vht_center_freq = vhtop->vht_op_ch_freq_seg2;
            } else {
                vht_center_freq = vhtop->vht_op_ch_freq_seg1;
            }

            break;
    }
    ieee80211_acs_derive_sec_chans_with_mode(phymode_se,vht_center_freq,
                                     channel_ieee_se,sec_chan_20,sec_chan_40_1, sec_chan_40_2);
    return EOK;
}

/*
 * Trace all entries to record the max rssi found for every channel.
 */
static int
ieee80211_acs_get_channel_maxrssi_n_secondary_ch(void *arg, wlan_scan_entry_t se)
{
    ieee80211_acs_t acs = (ieee80211_acs_t) arg;
    struct ieee80211_channel *channel_se = ieee80211_scan_entry_channel(se);
    u_int8_t rssi_se = ieee80211_scan_entry_rssi(se);
    u_int8_t channel_ieee_se = ieee80211_chan2ieee(acs->acs_ic, channel_se);
    u_int8_t sec_chan_20 = 0;
    u_int8_t sec_chan_40_1 = 0;
    u_int8_t sec_chan_40_2 = 0;
    u_int8_t len;
    struct ieee80211vap *vap = (struct ieee80211vap *)acs->acs_vap;

    eacs_trace(EACS_DBG_RSSI, ( "ssid %s ", (char *)ieee80211_scan_entry_ssid(se, &len)));

    eacs_trace(EACS_DBG_RSSI, ( "chan %d rssi %d noise: %d \n", (int)channel_ieee_se, rssi_se, acs->acs_noisefloor[channel_ieee_se]));
    if (rssi_se > acs->acs_chan_maxrssi[channel_ieee_se]) {
        acs->acs_chan_maxrssi[channel_ieee_se] = rssi_se;
    }
    acs->acs_chan_rssi[channel_ieee_se] +=rssi_se;
    eacs_trace(EACS_DBG_RSSI, ( "chan %d Total rssi  %d \n", (int)channel_ieee_se, acs->acs_chan_rssi[channel_ieee_se]));
    /* This support is for stats */
    if ((acs->acs_chan_minrssi[channel_ieee_se] == 0) ||
            (rssi_se < acs->acs_chan_maxrssi[channel_ieee_se])) {
        acs->acs_chan_minrssi[channel_ieee_se] = rssi_se;
    }
    acs->acs_chan_nbss[channel_ieee_se] += 1;

    if(!ieee80211_acs_derive_sec_chan(se, channel_ieee_se, &sec_chan_20, &sec_chan_40_1, &sec_chan_40_2, vap)) {
        acs->acs_sec_chan[sec_chan_20] = true;
        eacs_trace(EACS_DBG_LVL0, ("secondary 20 channel is %d and secondary 40 channel is %d\n",sec_chan_20,sec_chan_40_1));
        /* Secondary 40 would be enabled for 80+80 Mhz channel or
         * 160 Mhz channel
         */
        if ((sec_chan_40_1 != 0) && (sec_chan_40_2 != 0)) {
            acs->acs_sec_chan[sec_chan_40_1] = true;
            acs->acs_sec_chan[sec_chan_40_2] = true;
        }
    }

    return EOK;
}

static INLINE void ieee80211_acs_check_2ghz_only(ieee80211_acs_t acs, u_int16_t nchans_2ghz)
{
    /* No 5 GHz channels available, skip 5 GHz scan */
    if ((nchans_2ghz) && (acs->acs_nchans == nchans_2ghz)) {
        eacs_trace(EACS_DBG_LVL0,( "No 5 GHz channels available, skip 5 GHz scan" ));
    }
}


/**
 * @brief whether a channel is blocked/unblocked
 *
 * @param acs
 * @param channel
 * @return true if channel is unblocked otheriwse false
 */
static inline int acs_is_channel_blocked(ieee80211_acs_t acs,u_int8_t chnum)
{
    acs_bchan_list_t * bchan = NULL ;
    u_int16_t i = 0;

    if(acs == NULL)
        return EPERM;

    bchan = &(acs->acs_bchan_list);
    for(i = 0;i < bchan->uchan_cnt;i++)
    {
        if(bchan->uchan[i] == chnum) {
            /* Non zero values means ignore this channel */
            return true;
        }
    }
    return false;
}

static INLINE void ieee80211_acs_get_phymode_channels(ieee80211_acs_t acs, enum ieee80211_phymode mode)
{
    struct ieee80211_channel *channel;
    int i, extchan, skipchanextinvalid;
    struct ieee80211_channel_list chan_info;

    eacs_trace(EACS_DBG_LVL1,( " get channels with phy mode=%d",  mode));
    ieee80211_enumerate_channels(channel, acs->acs_ic, i) {
        eacs_trace(EACS_DBG_LVL0,(" ic_freq: %d ic_ieee: %d ic_flags: %x ", channel->ic_freq, channel->ic_ieee, channel->ic_flags));
        /*reset overlap bits */

        if(channel->ic_flags & ( IEEE80211_CHAN_HT40INTOLMARK | IEEE80211_CHAN_HT40INTOL)){
            channel->ic_flags &= ~( IEEE80211_CHAN_HT40INTOLMARK | IEEE80211_CHAN_HT40INTOL);
        }

        if (mode == ieee80211_chan2mode(channel)) {
            u_int8_t ieee_chan_num = ieee80211_chan2ieee(acs->acs_ic, channel);
#if ATH_CHANNEL_BLOCKING
            u_int8_t ieee_ext_chan_num;
#endif
            /*
            * When EMIWAR is EMIWAR_80P80_FC1GTFC2 for some channel 80_80MHZ channel combination is not allowed
            * this code will allowed the 80MHz combination to add in to acs_channel list
            * so that these can be used as secondary channel
            */
            if((acs->acs_ic->ic_emiwar_80p80 == EMIWAR_80P80_FC1GTFC2) &&
                (mode == IEEE80211_MODE_11AC_VHT80) &&
                (acs->acs_vap->iv_des_mode == IEEE80211_MODE_11AC_VHT80_80) &&
                (acs->acs_chan_maps[ieee_chan_num] != 0xff)) {
                eacs_trace(EACS_DBG_LVL0,( " Duplicate channel freq %d",  channel->ic_freq));
                continue;
            }
             /* VHT80_80, channel list has duplicate entries, since ACS picks both primary and secondary 80 mhz channels
                single entry in ACS would be sufficient */
            if(acs->acs_nchans &&
                (ieee80211_chan2ieee(acs->acs_ic, acs->acs_chans[acs->acs_nchans-1]) == ieee_chan_num))
            {
                eacs_trace(EACS_DBG_LVL0,( " Duplicate channel freq %d",  channel->ic_freq));
                continue;
            }
#if ATH_SUPPORT_IBSS_ACS
            /*
             * ACS : filter out DFS channels for IBSS mode
             */
            if((wlan_vap_get_opmode(acs->acs_vap) == IEEE80211_M_IBSS) && IEEE80211_IS_CHAN_DISALLOW_ADHOC(channel)) {
                eacs_trace(EACS_DBG_LVL0,( "skip DFS-check channel %d",  channel->ic_freq));
                continue;
            }
#endif
            eacs_trace(EACS_DBG_LVL0,(" adding channel %d %d %d to list",
                        channel->ic_freq, channel->ic_flags, channel->ic_ieee));

            if ((wlan_vap_get_opmode(acs->acs_vap) == IEEE80211_M_HOSTAP) && IEEE80211_IS_CHAN_DISALLOW_HOSTAP(channel)) {
                eacs_trace(EACS_DBG_LVL0,( "%s skip Station only channel %d\n", __func__, channel->ic_freq));
                continue;
            }

            /*channel is blocked as per user setting */
            if(acs_is_channel_blocked(acs,ieee_chan_num)) {
                eacs_trace(EACS_DBG_BLOCK, ("Channel %d is blocked, in mode %d\n", ieee_chan_num, mode));
                continue;
            }

            ieee80211_get_extchaninfo(acs->acs_ic, channel, &chan_info);

            skipchanextinvalid = 0;

            for (extchan = 0; extchan < chan_info.cl_nchans ; extchan++) {
                if (chan_info.cl_channels[extchan] == NULL) {
                    if(ieee80211_is_extchan_144(acs->acs_ic, channel, extchan)) {
                         continue;
                    }
                    eacs_trace(EACS_DBG_LVL0, ("Rejecting Channel for ext channel found null "
                                "channel number %d EXT channel %d found %d\n", ieee_chan_num, extchan,
                                (int)chan_info.cl_channels[extchan]));
                    skipchanextinvalid = 1;
                    break;
                }
            }

#if ATH_CHANNEL_BLOCKING
            if (acs->acs_block_mode & ACS_BLOCK_EXTENSION) {
                /* extension channel (in NAHT40/ACVHT40/ACVHT80 mode) is blocked as per user setting */
                for (extchan = 0; (skipchanextinvalid == 0) && (extchan < chan_info.cl_nchans); extchan++) {
                    ieee_ext_chan_num = ieee80211_chan2ieee(acs->acs_ic, chan_info.cl_channels[extchan]);
                    if (acs_is_channel_blocked(acs, ieee_ext_chan_num)) {
                        eacs_trace(EACS_DBG_BLOCK, ("Channel %d can't be used, as ext channel %d "
                                    "is blocked, in mode %d\n", ieee_chan_num, ieee_ext_chan_num, mode));
                        skipchanextinvalid = 1; /* break */
                    }
                }

                /* in 2.4GHz band checking channels overlapping with primary,
                 * or if required with secondary too (NGHT40 mode) */
                if (!skipchanextinvalid && IEEE80211_IS_CHAN_2GHZ(channel)) {
                    struct ieee80211_channel *ext_chan;
                    int start = channel->ic_freq - 15, end = channel->ic_freq + 15, f;
                    if (IEEE80211_IS_CHAN_11NG_HT40PLUS(channel))
                        end = channel->ic_freq + 35;
                    if (IEEE80211_IS_CHAN_11NG_HT40MINUS(channel))
                        start = channel->ic_freq - 35;
                    for (f = start; f <= end; f += 5) {
                        ext_chan = acs->acs_ic->ic_find_channel(acs->acs_ic, f, 0, IEEE80211_CHAN_B);
                        if (ext_chan) {
                            ieee_ext_chan_num = ieee80211_chan2ieee(acs->acs_ic, ext_chan);
                            if (acs_is_channel_blocked(acs, ieee_ext_chan_num)) {
                                eacs_trace(EACS_DBG_BLOCK, ("Channel %d can't be used, as ext "
                                            "or overlapping channel %d is blocked, in mode %d\n",
                                            ieee_chan_num, ieee_ext_chan_num, mode));
                                skipchanextinvalid = 1;
                                break;
                            }
                        }
                    }
                }
            }
#endif

            if ( skipchanextinvalid ) {
                eacs_trace(EACS_DBG_LVL0, ("skip channel %d -> %d due to ext channel "
                            "invalid or blocked\n", channel->ic_ieee, channel->ic_freq));
                continue;
            }

            eacs_trace(EACS_DBG_LVL0,("%s adding channel %d %08x %d to list\n", __func__,
                        channel->ic_freq, channel->ic_flags, channel->ic_ieee));

            if (ieee_chan_num != (u_int8_t) IEEE80211_CHAN_ANY) {
                acs->acs_chan_maps[ieee_chan_num] = acs->acs_nchans;
            }
            acs->acs_chans[acs->acs_nchans++] = channel;
            if (acs->acs_nchans >= IEEE80211_ACS_CHAN_MAX) {
                eacs_trace(EACS_DBG_LVL0,("acs number of channels are more than"
                            "MAXIMUM channels \n"));
                break;
            }
        }
    }
}

/*
 * construct the available channel list
 */
static void ieee80211_acs_construct_chan_list(ieee80211_acs_t acs, enum ieee80211_phymode mode)
{
    u_int16_t nchans_2ghz = 0;

    eacs_trace(EACS_DBG_LVL0,(" %s \n",__func__));
    /* reset channel mapping array */
    OS_MEMSET(&acs->acs_chan_maps, 0xff, sizeof(acs->acs_chan_maps));
    acs->acs_nchans = 0;

    if (mode == IEEE80211_MODE_AUTO) {
        /* HT20 only if IEEE80211_MODE_AUTO */
        ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11NG_HT20);
        nchans_2ghz = acs->acs_nchans;
        ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11NA_HT20);
        ieee80211_acs_check_2ghz_only(acs, nchans_2ghz);

        /* If no any HT channel available */
        if (acs->acs_nchans == 0) {
            ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11G);
            nchans_2ghz = acs->acs_nchans;
            ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11A);
            ieee80211_acs_check_2ghz_only(acs, nchans_2ghz);
        }

        /* If still no channel available */
        if (acs->acs_nchans == 0) {
            ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11B);
            acs->acs_scan_2ghz_only = 1;
        }
    } else if (mode == IEEE80211_MODE_11NG_HT40){
        /* if PHY mode is not AUTO, get channel list by PHY mode directly */
        ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11NG_HT40PLUS);
        ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11NG_HT40MINUS);
        acs->acs_scan_2ghz_only = 1;
        eacs_trace(EACS_DBG_LVL0,( " get channels with phy mode 11ng HT40PLUS AND HT40MINUS"));
    } else if (mode == IEEE80211_MODE_11NA_HT40){

        eacs_trace(EACS_DBG_LVL0,( " get channels with phy mode HT40PLUS AND HT40MINUTE"));
        /* if PHY mode is not AUTO, get channel list by PHY mode directly */
        ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11NA_HT40PLUS);
        ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11NA_HT40MINUS);
    } else if (mode == IEEE80211_MODE_11AC_VHT40) {

        eacs_trace(EACS_DBG_LVL0,( " get channels with phy mode VHT40 plus and minuse"));
        /* if PHY mode is not AUTO, get channel list by PHY mode directly */
        ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AC_VHT40PLUS);
        ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AC_VHT40MINUS);
    } else if (mode == IEEE80211_MODE_11AC_VHT80) {

        eacs_trace(EACS_DBG_LVL0,( " get channels with phy mode VHT80 "));
        /* if PHY mode is not AUTO, get channel list by PHY mode directly */
        ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AC_VHT80);
    } else if (mode == IEEE80211_MODE_11AC_VHT80_80) {

        eacs_trace(EACS_DBG_LVL0,( " get channels with phy mode VHT80_80 "));
        /* if PHY mode is not AUTO, get channel list by PHY mode directly */
        ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AC_VHT80_80);
        if(acs->acs_ic->ic_emiwar_80p80 == EMIWAR_80P80_FC1GTFC2) {
          /*
          * When EMIWAR is EMIWAR_80P80_FC1GTFC2
          * there will be no 80_80 channel combination for 149,153,157,161,
          * because of which these channel will not be added to acs_chan list
          * in which case acs will not even consider as these channel as secondary channel.
          * So in this case add 149,153,157,161 80MHz channels to acs channel list
          * and force acs not to select these channel as primary
          * but can consider these channel as secondary channel.
          */
          ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AC_VHT80);
        }
    } else if (mode == IEEE80211_MODE_11AC_VHT160) {

        eacs_trace(EACS_DBG_LVL0,( " get channels with phy mode VHT160"));
        /* if PHY mode is not AUTO, get channel list by PHY mode directly */
        ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AC_VHT160);

    } else {
        /* if PHY mode is not AUTO, get channel list by PHY mode directly */
        ieee80211_acs_get_phymode_channels(acs, mode);
    }
}

static OS_TIMER_FUNC(acs_bk_scan_timer)
{

    ieee80211_acs_t acs ;

    OS_GET_TIMER_ARG(acs, ieee80211_acs_t );
    eacs_trace(EACS_DBG_LVL1,("Scan timer  handler \n"));

    if(acs->acs_scantimer_handler)
        acs->acs_scantimer_handler(acs->acs_scantimer_arg);

    OS_SET_TIMER(&acs->acs_bk_scantimer, acs->acs_bk_scantime*1000);

}

#if ATH_SUPPORT_VOW_DCS
static OS_TIMER_FUNC(dcs_enable)
{
    struct ieee80211com *ic = NULL;
    ieee80211_acs_t acs;
    OS_GET_TIMER_ARG(acs, ieee80211_acs_t);
    ic = acs->acs_ic;
    /* Enable DCS WLAN_IM functionality */
    ic->ic_enable_dcsim(ic);
    /* Deleting DCS enable timer and resetting timer flag to 0 once DCS WLAN_IM is enabled */
    OS_CANCEL_TIMER(&acs->dcs_enable_timer);
    acs->is_dcs_enable_timer_set = 0;
}
#endif

int ieee80211_acs_init(ieee80211_acs_t *acs, wlan_dev_t devhandle, osdev_t osdev)
{
    OS_MEMZERO(*acs, sizeof(struct ieee80211_acs));

    /* Save handles to required objects.*/
    (*acs)->acs_ic     = devhandle;
    (*acs)->acs_osdev  = osdev;

    spin_lock_init(&((*acs)->acs_lock));
    spin_lock_init(&((*acs)->acs_ev_lock));
    (*acs)->acs_rssivar   = ACS_ALLOWED_RSSIVARAINCE ;
    (*acs)->acs_chloadvar = ACS_ALLOWED_CHANLOADVARAINCE;
    (*acs)->acs_bk_scantime  = ATH_ACS_DEFAULT_SCANTIME;
    (*acs)->acs_bkscantimer_en = 0;
    (*acs)->acs_ic->ic_acs_ctrlflags = 0;
    (*acs)->acs_limitedbsschk = 0;
    /* By default report to user space is disabled  */
    (*acs)->acs_scan_req_param.acs_scan_report_active = false;
    (*acs)->acs_scan_req_param.acs_scan_report_pending = false;
    eacs_dbg_mask = 0;
#ifdef ATH_SUPPORT_VOW_DCS
    (*acs)->dcs_enable_time = DCS_ENABLE_TIME;
    (*acs)->is_dcs_enable_timer_set = 0;
#endif
    (*acs)->acs_ch_hopping.param.nohop_dur = CHANNEL_HOPPING_NOHOP_TIMER ; /* one minute*/
    /* 15 minutes */
    (*acs)->acs_ch_hopping.param.long_dur =  CHANNEL_HOPPING_LONG_DURATION_TIMER;
    (*acs)->acs_ch_hopping.param.cnt_dur = CHANNEL_HOPPING_CNTWIN_TIMER ; /* 5 sec */
    /* switch channel if out of total time 75 % idetects noise */
    (*acs)->acs_ch_hopping.param.cnt_thresh = 75;
    /* INIT value will increment at each channel selection*/
    (*acs)->acs_ch_hopping.ch_max_hop_cnt = 0;
    /*video bridge Detection threshold */
    (*acs)->acs_ch_hopping.param.noise_thresh = CHANNEL_HOPPING_VIDEO_BRIDGE_THRESHOLD;
    (*acs)->acs_ch_hopping.ch_nohop_timer_active = false ; /*HOPPING TIMER ACTIVE  */
    /*Default channel change will happen through usual ways not by channel hopping */
    (*acs)->acs_ch_hopping.ch_hop_triggered = false;
    /* Init these values will help us in reporting user
       the values being used in case he wants to enquire
       even before setting these values */
    (*acs)->acs_scan_req_param.mindwell = MIN_DWELL_TIME         ;
    (*acs)->acs_scan_req_param.maxdwell = MAX_DWELL_TIME ;
    atomic_set(&(*acs)->acs_in_progress,false);
    (*acs)->acs_run_incomplete = false;
    (*acs)->acs_tx_power_type = ACS_TX_POWER_OPTION_TPUT;
    (*acs)->acs_2g_allchan = 0;

    OS_INIT_TIMER(osdev, & (*acs)->acs_bk_scantimer, acs_bk_scan_timer, (void * )(*acs), QDF_TIMER_TYPE_WAKE_APPS);

    OS_INIT_TIMER((*acs)->acs_ic->ic_osdev,
            &((*acs)->acs_ch_hopping.ch_long_timer), ieee80211_ch_long_timer, (void *) ((*acs)->acs_ic), QDF_TIMER_TYPE_WAKE_APPS);

    OS_INIT_TIMER((*acs)->acs_ic->ic_osdev,
            &((*acs)->acs_ch_hopping.ch_nohop_timer), ieee80211_ch_nohop_timer,
            (void *) (*acs)->acs_ic, QDF_TIMER_TYPE_WAKE_APPS);

    OS_INIT_TIMER((*acs)->acs_ic->ic_osdev,
            &((*acs)->acs_ch_hopping.ch_cntwin_timer), ieee80211_ch_cntwin_timer,
            (void *) (*acs)->acs_ic, QDF_TIMER_TYPE_WAKE_APPS);
#ifdef ATH_SUPPORT_VOW_DCS
    /* Initializing DCS Enable timer */
    OS_INIT_TIMER((*acs)->acs_ic->ic_osdev, & (*acs)->dcs_enable_timer, dcs_enable, (void *)(*acs), QDF_TIMER_TYPE_WAKE_APPS);
#endif

    TAILQ_INIT(&(*acs)->in_network_table_2g);

    return 0;
}

int ieee80211_acs_attach(ieee80211_acs_t *acs,
        wlan_dev_t          devhandle,
        osdev_t             osdev)
{
    if (*acs)
        return -EINPROGRESS; /* already attached ? */

    *acs = (ieee80211_acs_t) OS_MALLOC(osdev, sizeof(struct ieee80211_acs), 0);
    if (*acs) {
        ieee80211_acs_init(&(*acs), devhandle, osdev);
        return EOK;
    }

    return -ENOMEM;
}

int ieee80211_acs_set_param(ieee80211_acs_t acs, int param , int val)
{

    switch(param){
        case  IEEE80211_ACS_ENABLE_BK_SCANTIMER:
            acs->acs_bkscantimer_en = val ;
            if(val == 1){
                OS_SET_TIMER(&acs->acs_bk_scantimer, acs->acs_bk_scantime *1000);
            }else{
                OS_CANCEL_TIMER(&acs->acs_bk_scantimer);
            }
            break;
        case  IEEE80211_ACS_SCANTIME:
            acs->acs_bk_scantime = val;
            break;
        case  IEEE80211_ACS_RSSIVAR:
            acs->acs_rssivar = val ;
            break;
        case  IEEE80211_ACS_CHLOADVAR:
            acs->acs_chloadvar = val;
            break;
        case  IEEE80211_ACS_LIMITEDOBSS:
            acs->acs_limitedbsschk = val;
            break;
        case IEEE80211_ACS_CTRLFLAG:
            acs->acs_ic->ic_acs_ctrlflags =val;
            break;
        case IEEE80211_ACS_DEBUGTRACE:
            eacs_dbg_mask = val;
            break;
#if ATH_CHANNEL_BLOCKING
        case IEEE80211_ACS_BLOCK_MODE:
            acs->acs_block_mode = val & 0x3;
            break;
#endif

        case IEEE80211_ACS_TX_POWER_OPTION:
            if((val == ACS_TX_POWER_OPTION_TPUT) || (val == ACS_TX_POWER_OPTION_RANGE)) {
               acs->acs_tx_power_type = val;
            }
            else {
               QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Invalid tx power type %d (Throughput 1, Range 2)\n",val);
            }
            break;

        case IEEE80211_ACS_2G_ALL_CHAN:
           acs->acs_2g_allchan = val;
           break;

        case IEEE80211_ACS_RANK:
            acs->acs_ranking = !!val;
            break;

        default :
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Invalid param req %d \n",param);
            return -1;

    }

    return 0;

}

int ieee80211_acs_get_param(ieee80211_acs_t acs, int param )
{
    int val =0;
    switch(param){
        case IEEE80211_ACS_ENABLE_BK_SCANTIMER:
            val = acs->acs_bkscantimer_en ;
            break;
        case IEEE80211_ACS_SCANTIME:
            val = acs->acs_bk_scantime ;
            break;
        case IEEE80211_ACS_RSSIVAR:
            val = acs->acs_rssivar ;
            break;
        case  IEEE80211_ACS_CHLOADVAR:
            val = acs->acs_chloadvar ;
            break;
        case IEEE80211_ACS_LIMITEDOBSS:
            val = acs->acs_limitedbsschk ;
            break;
        case IEEE80211_ACS_CTRLFLAG:
            val = acs->acs_ic->ic_acs_ctrlflags ;
            break;
        case IEEE80211_ACS_DEBUGTRACE:
            val = eacs_dbg_mask ;
            break;
#if ATH_CHANNEL_BLOCKING
        case IEEE80211_ACS_BLOCK_MODE:
            val = acs->acs_block_mode;
            break;
#endif
        case IEEE80211_ACS_TX_POWER_OPTION:
            val = acs->acs_tx_power_type ;
            break;
        case IEEE80211_ACS_2G_ALL_CHAN:
           val = acs->acs_2g_allchan;
           break;
        case IEEE80211_ACS_RANK:
           val = acs->acs_ranking;
           break;

        default :
            val = -1;
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Invalid param req %d \n",param);
            return -1;

    }
    return val ;
}


/**
 * @brief to get in network information
 *
 * @param ic
 * @param databuffer
 * @param workflow
 * @return EOK in case of success
 */
int wlan_acs_get_innetwork_2g(struct ieee80211com *ic,void *data,int workflow)
{
    ieee80211_acs_t acs;
    struct in_network_table *tmpnode;
    int index=0;
    struct in_network_2G_table *in_network_2g_data = (struct in_network_2G_table *)data;

    if (ic == NULL)
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s ic is null\r\n",__func__);
        return -EINVAL;
    }

    if (IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan))
    {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "channel is not 2.4G return faile\r\n");
        return -EINVAL;
    }

    acs=ic->ic_acs;

    if (acs == NULL)
    {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s acs is null\r\n",__func__);
        return -EINVAL;
    }

    if (!workflow)
    {
        TAILQ_FOREACH(tmpnode, &acs->in_network_table_2g, table_list) {
            index++;
        }

        in_network_2g_data->total_index = index;
        return 0;
    }
    else
    {
        TAILQ_FOREACH(tmpnode, &acs->in_network_table_2g, table_list) {
            if (index == in_network_2g_data->total_index)
                break;
            memcpy(in_network_2g_data[index].macaddr, tmpnode->macaddr, IEEE80211_ADDR_LEN);
            in_network_2g_data[index].ch = tmpnode->channel;
            index++;
        }

        in_network_2g_data->total_index=index;
    }

    return 0;
}


/**
 * @brief to set in network information
 *
 * @param ic
 * @param mac
 * @param channel
 * @return EOK in case of success
 */
int wlan_acs_set_innetwork_2g(struct ieee80211com *ic,const u_int8_t *macaddr,int channel)
{
    ieee80211_acs_t acs;
    struct in_network_table *tmpnode;

    if (ic==NULL)
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s ic is null\r\n",__func__);
        return -EINVAL;
    }

    if (IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan))
    {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "channel is not 2.4G return faile\r\n");
        return -EINVAL;
    }

    acs=ic->ic_acs;

    if (acs==NULL)
    {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s acs is null\r\n",__func__);
        return -EINVAL;
    }

    if (channel==0x00) //delete all list
    {
        tmpnode = TAILQ_FIRST(&acs->in_network_table_2g);
        while (tmpnode)
        {
            TAILQ_REMOVE(&acs->in_network_table_2g,tmpnode,table_list);
            OS_FREE(tmpnode);
            tmpnode = TAILQ_FIRST(&acs->in_network_table_2g);
        }
    }
    else
    {
        if (TAILQ_EMPTY(&acs->in_network_table_2g))
        {
            tmpnode=OS_MALLOC(ic->ic_osdev, sizeof(struct in_network_table), GFP_KERNEL);
            if (tmpnode==NULL)
            {
                return -EINVAL;;
            }
            OS_MEMCPY(tmpnode->macaddr, macaddr, IEEE80211_ADDR_LEN);
            tmpnode->channel = channel;
            TAILQ_INSERT_TAIL(&acs->in_network_table_2g, tmpnode, table_list);
        }
        else
        {
            tmpnode = NULL;
            TAILQ_FOREACH(tmpnode, &acs->in_network_table_2g, table_list) {
                if (OS_MEMCMP(tmpnode->macaddr, macaddr, IEEE80211_ADDR_LEN) == 0)
                {
                    tmpnode->channel = channel;
                    break;
                }
            }
            if (tmpnode == NULL)
            {
                tmpnode=OS_MALLOC(ic->ic_osdev, sizeof(struct in_network_table), GFP_KERNEL);
                if (tmpnode==NULL)
                {
                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s memory allocate failed \r\n",__func__);
                    return -EINVAL;;
                }
                OS_MEMCPY(tmpnode->macaddr, macaddr, IEEE80211_ADDR_LEN);
                tmpnode->channel = channel;
                TAILQ_INSERT_TAIL(&acs->in_network_table_2g, tmpnode, table_list);
            }
        }
    }
    return 0;
}



void ieee80211_acs_deinit(ieee80211_acs_t *acs)
{
    struct acs_ch_hopping_t *ch = NULL;

    /*remove the in network information when deinit*/
    wlan_acs_set_innetwork_2g((*acs)->acs_ic,NULL,0x00);

    ch = &((*acs)->acs_ch_hopping);
    /*
     * Free synchronization objects
     */

    OS_FREE_TIMER(&(*acs)->acs_bk_scantimer);
    OS_FREE_TIMER(&ch->ch_cntwin_timer);
    OS_FREE_TIMER(&ch->ch_nohop_timer);
    OS_FREE_TIMER(&ch->ch_long_timer);
#if ATH_SUPPORT_VOW_DCS
    OS_FREE_TIMER(&(*acs)->dcs_enable_timer);
#endif
    spin_lock_destroy(&((*acs)->acs_lock));
    spin_lock_destroy(&((*acs)->acs_ev_lock));
}

int ieee80211_acs_detach(ieee80211_acs_t *acs)
{
    if (*acs == NULL)
        return EINPROGRESS; /* already detached ? */

    ieee80211_acs_deinit(&(*acs));
    OS_FREE(*acs);

    *acs = NULL;

    return EOK;
}

static void
ieee80211_acs_post_event(ieee80211_acs_t                 acs,
        struct ieee80211_channel       *channel)
{
    int                                 i,num_handlers;
    ieee80211_acs_event_handler         acs_event_handlers[IEEE80211_MAX_ACS_EVENT_HANDLERS];
    void                                *acs_event_handler_arg[IEEE80211_MAX_ACS_EVENT_HANDLERS];

    eacs_trace(EACS_DBG_LVL1,(" %s \n",__func__));
    /*
     * make a local copy of event handlers list to avoid
     * the call back modifying the list while we are traversing it.
     */
    spin_lock(&acs->acs_lock);
    num_handlers=acs->acs_num_handlers;
    for (i=0; i < num_handlers; ++i) {
        acs_event_handlers[i] = acs->acs_event_handlers[i];
        acs_event_handler_arg[i] = acs->acs_event_handler_arg[i];
    }
    spin_unlock(&acs->acs_lock);
    for (i = 0; i < num_handlers; ++i) {
        (acs_event_handlers[i]) (acs_event_handler_arg[i], channel);
    }
}

/*
 * scan handler used for scan complete
 */
static void ieee80211_ht40intol_evhandler(struct ieee80211vap *originator,
        ieee80211_scan_event *event,
        void *arg)
{
    ieee80211_acs_t acs = NULL;
    struct ieee80211vap *vap = NULL;
    int i = 0;

    if (arg == NULL) {
        eacs_trace(EACS_DBG_LVL0,("acs is null"));
        return;
    }
    acs = (ieee80211_acs_t) arg;
    vap = acs->acs_vap;

    /*
     * we don't need lock in evhandler since
     * 1. scan module would guarantee that event handlers won't get called simultaneously
     * 2. acs_in_progress prevent furher access to ACS module
     */
#if 0
#if DEBUG_EACS
    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,  "%s scan_id %08X event %d reason %d \n", __func__, event->scan_id, event->type, event->reason);
#endif
#endif

#if ATH_SUPPORT_MULTIPLE_SCANS
    /*
     * Ignore notifications received due to scans requested by other modules
     * and handle new event IEEE80211_SCAN_DEQUEUED.
     */
    ASSERT(0);
    /* Ignore events reported by scans requested by other modules */
    if (acs->acs_scan_id != event->scan_id) {
        return;
    }

#endif    /* ATH_SUPPORT_MULTIPLE_SCANS */
    if( event->type == IEEE80211_SCAN_FOREIGN_CHANNEL_GET_NF ) {
        struct ieee80211com *ic = originator->iv_ic;
        /* Get the noise floor value */
        acs->acs_noisefloor[ieee80211_chan2ieee(originator->iv_ic,event->chan)] = ic->ic_get_cur_chan_nf(ic);
        eacs_trace(EACS_DBG_LVL0,("Updating Noise fllor chan %d value %d\n",ieee80211_chan2ieee(originator->iv_ic,event->chan),acs->acs_noisefloor[ieee80211_chan2ieee(originator->iv_ic,event->chan)]));
    }

    if ((event->type != IEEE80211_SCAN_COMPLETED) &&
            (event->type != IEEE80211_SCAN_DEQUEUED)) {
        return;
    }
    spin_lock(&acs->acs_ev_lock);
    /* If ACS is not in progress, then return, since ACS cancel was called before this*/
    if (!ieee80211_acs_in_progress(acs)) {
        spin_unlock(&acs->acs_ev_lock);
        return;
    }


    if (event->reason != IEEE80211_REASON_COMPLETED) {
        eacs_trace(EACS_DBG_LVL0,( "Scan not totally complete. Should not occur normally! Investigate" ));
        goto scan_done;
    }
    ieee80211_find_ht40intol_overlap(acs, vap->iv_des_chan[vap->iv_des_mode]);

    for(i=0; i<IEEE80211_CHAN_MAX ;i++) {
        acs->acs_chan_rssitotal[i]= 0;
        acs->acs_chan_rssi[i] = 0;
    }

    wlan_scan_table_iterate(acs->acs_vap, ieee80211_acs_get_channel_maxrssi_n_secondary_ch, acs);

scan_done:
    ieee80211_free_ht40intol_scan_resource(acs);
    ieee80211_acs_post_event(acs, vap->iv_des_chan[vap->iv_des_mode]);

    /*Comparing to true and setting it false return value is
	true in case comparison is successfull */

    if(!OS_ATOMIC_CMPXCHG(&(acs->acs_in_progress),true,false))
     {
         eacs_trace(EACS_DBG_LVL0,("Wrong locking in ACS --investigate -- \n"));
         eacs_trace(EACS_DBG_LVL0,(" %s \n",__func__));
         atomic_set(&(acs->acs_in_progress),false);
     }

    ieee80211_check_and_execute_pending_acsreport(vap);

    spin_unlock(&acs->acs_ev_lock);
    return;
}

struct ieee80211_channel *
ieee80211_acs_check_altext_channel(
        ieee80211_acs_t acs,
        struct ieee80211_channel *channel )
{
    int i;
    struct ieee80211_channel *altchannel =NULL;


    if(channel->ic_flags & IEEE80211_CHAN_11NG_HT40PLUS ){
        /*find the HT40minu channle */
        for (i = 0; i < acs->acs_nchans; i++) {
            if(channel->ic_ieee == acs->acs_chans[i]->ic_ieee ){
                if(channel == acs->acs_chans[i])
                    continue;
                if(channel->ic_flags & IEEE80211_CHAN_11NG_HT40MINUS ){
                    altchannel = acs->acs_chans[i];

                }

            }
        }

    }else{
        /*find the HT40minu channle */
        for (i = 0; i < acs->acs_nchans; i++) {

            if(channel->ic_ieee == acs->acs_chans[i]->ic_ieee){
                if(channel == acs->acs_chans[i])
                    continue;

                if(channel->ic_flags & IEEE80211_CHAN_11NG_HT40PLUS){
                    altchannel = acs->acs_chans[i];
                }

            }
        }

    }

    if(altchannel !=NULL){
        ieee80211_find_ht40intol_overlap(acs, altchannel);
        if(!(altchannel->ic_flags & IEEE80211_CHAN_HT40INTOLMARK)){
            channel = altchannel;
        }
    }
    return channel;
}


/**
 * @brief to used internally to acs to set/get value to ath layer
 *
 * @param ic
 * @param cmd
 * @param param
 * @param val
 *
 * @return
 */
static int acs_noise_detection_param(struct ieee80211com *ic ,int cmd ,int param,int *val)
{
    int err = EOK;

    if(!ieee80211com_has_cap_ext(ic,IEEE80211_ACS_CHANNEL_HOPPING))
        return EINVAL;

    if(cmd) {
        if(ic->ic_set_noise_detection_param) {
            if(param == IEEE80211_ENABLE_NOISE_DETECTION ||
                    param == IEEE80211_NOISE_THRESHOLD) /*Rest param are not supported */
                ic->ic_set_noise_detection_param(ic,param,*val);
            else {
                err = EINVAL;
            }
        }
        else { /* SET Noise detection in ath layer not enabled */
            err = EINVAL;
        }
    } else { /* GET part */
        if(ic->ic_get_noise_detection_param) {
            if(IEEE80211_GET_COUNTER_VALUE == param)
                ic->ic_get_noise_detection_param(ic,param,val);
            else  { /* in get path we dont need to get it from ath layer*/
                err = EINVAL;
            }
        } else
                err = EINVAL;
    }
    return err;
}
/*
 * scan handler used for scan complete
 */
static void ieee80211_acs_scan_evhandler(struct ieee80211vap *originator, ieee80211_scan_event *event, void *arg)
{
    struct ieee80211_channel *channel = IEEE80211_CHAN_ANYC;
    int i;
    u_int8_t flags;
    struct ieee80211com *ic;
    ieee80211_acs_t acs;
    struct acs_ch_hopping_t *ch = NULL;
    int val = 0,retval = 0;
    u_int32_t now = 0;
    u_int8_t ieee_chan_num = 0;
    u_int32_t random_chan = 0;
    u_int32_t ht40minus_chan = 0;

    ic = originator->iv_ic;
    acs = (ieee80211_acs_t) arg;
    ch = &(acs->acs_ch_hopping);
    /*
     * we don't need lock in evhandler since
     * 1. scan module would guarantee that event handlers won't get called simultaneously
     * 2. acs_in_progress prevent furher access to ACS module
     */
    eacs_trace(EACS_DBG_SCAN,( "scan_id %08X event %d reason %d ",
                event->scan_id, event->type, event->reason));

#if ATH_SUPPORT_MULTIPLE_SCANS
    /*
     * Ignore notifications received due to scans requested by other modules
     * and handle new event IEEE80211_SCAN_DEQUEUED.
     */
    ASSERT(0);

    /* Ignore events reported by scans requested by other modules */
    if (acs->acs_scan_id != event->scan_id) {
        return;
    }
#endif    /* ATH_SUPPORT_MULTIPLE_SCANS */

    /*
     * Retrieve the Noise floor information and channel load
     * in case of channel change and restart the noise floor
     * computation for the next channel
     */
    if( event->type == IEEE80211_SCAN_FOREIGN_CHANNEL_GET_NF ) {
        now = (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());
        flags = ACS_CHAN_STATS_NF;
        /* Get the noise floor value */
        acs->acs_noisefloor[ieee80211_chan2ieee(originator->iv_ic,event->chan)] = ic->ic_get_cur_chan_nf(ic);

        eacs_trace(EACS_DBG_SCAN,("Requesting for CHAN STATS and NF from Target \n"));
        eacs_trace(EACS_DBG_SCAN,("%d.%03d | %s:request stats and nf \n",  now / 1000, now % 1000, __func__));
        ic->ic_hal_get_chan_info(ic, flags);
    }
    if ( event->type == IEEE80211_SCAN_FOREIGN_CHANNEL ) {
        /* get initial chan stats for the current channel */
        flags = ACS_CHAN_STATS;
        ic->ic_hal_get_chan_info(ic, flags);
    }
    if (event->type != IEEE80211_SCAN_COMPLETED) {
        return;
    }

    spin_lock(&acs->acs_ev_lock);
    /* If ACS is not in progress, then return, since ACS cancel was callled before this*/
    if (!ieee80211_acs_in_progress(acs)) {
        spin_unlock(&acs->acs_ev_lock);
        return;
    }

    if (event->reason != IEEE80211_REASON_COMPLETED) {
        eacs_trace(EACS_DBG_SCAN,( " Scan not totally complete. Should not occur normally! Investigate." ));
        /* If scan is cancelled, ACS should invoke the scan again*/
        channel = IEEE80211_CHAN_ANYC;
        goto scan_done;
    }
    for(i=0; i<IEEE80211_CHAN_MAX ;i++) {
        acs->acs_chan_rssitotal[i]= 0;
        acs->acs_chan_rssi[i] = 0;
    }

    wlan_scan_table_iterate(acs->acs_vap, ieee80211_acs_get_channel_maxrssi_n_secondary_ch, acs);

    /* For ACS channel ranking, get best channel repeatedly after blacklisting
     * the gotten channel and rank them in order */
    if (acs->acs_ranking) {

        OS_MEMSET(acs->acs_rank, 0x0, sizeof(acs_rank_t)*IEEE80211_ACS_CHAN_MAX);
        /* Allot Rank for the returned best channel and mark it as blacklisted
         * channel so that it wont be considered for selection of best channel
         * in the next iteration.
         * A random channel is returned when all the channels are unusable
         * in which case its noted*/

        for (i = 0; i < acs->acs_nchans; i++) {
            channel = ieee80211_acs_find_best_centerchan(acs);
            switch (acs->acs_vap->iv_des_mode) {
                case IEEE80211_MODE_11NG_HT40PLUS:
                case IEEE80211_MODE_11NG_HT40MINUS:
                case IEEE80211_MODE_11NG_HT40:
                    ieee80211_find_ht40intol_overlap(acs, channel);
                default:
                    break;
            }

            ieee_chan_num = ieee80211_chan2ieee(ic, channel);
            if ((acs->acs_channelrejflag[ieee_chan_num]) & (ACS_REJFLAG_BLACKLIST)){
                random_chan = ieee_chan_num;
            }
            else {
                if (ieee_chan_num != 0) {
                    acs->acs_channelrejflag[ieee_chan_num] |= ACS_REJFLAG_BLACKLIST;
                    acs->acs_rank[ieee_chan_num].rank = (i+1);
                }
            }
        }

        /* Mark a Reason code in the channel rank description for the all other
         * channels which have been Rejected for use */
        for (i = 0; i < acs->acs_nchans; i++) {
            channel = acs->acs_chans[i];
            ieee_chan_num = ieee80211_chan2ieee(ic, channel);

            /* WAR to handle channel 5,6,7 for HT40 mode
             * (2 entries of channel are present) one for HT40PLUS and
             * another for HT40MINUS, the HT40MINUS channel flags are
             * stored in ht40minus_chan index of the acs flags array */
            if (((ieee_chan_num >= 5)&& (ieee_chan_num <= 7)) &&
                            IEEE80211_IS_CHAN_11NG_HT40MINUS(channel)) {

                ht40minus_chan = 15 + (ieee_chan_num - 5);

                snprintf(acs->acs_rank[ieee_chan_num].desc, ACS_RANK_DESC_LEN,
                        "(%s%s%s%s%s%s%s%s%s%s%s%s%s)",
                        (ieee_chan_num == random_chan)? "Random ":"",
                        ((acs->acs_channelrejflag[ht40minus_chan] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_SECCHAN))? "SC ":"",
                        ((acs->acs_channelrejflag[ht40minus_chan] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_WEATHER_RADAR))? "WR ":"",
                        ((acs->acs_channelrejflag[ht40minus_chan] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_DFS))? "DF ":"",
                        ((acs->acs_channelrejflag[ht40minus_chan] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_HIGHNOISE))? "HN ":"",
                        ((acs->acs_channelrejflag[ht40minus_chan] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_RSSI))? "RS ":"",
                        ((acs->acs_channelrejflag[ht40minus_chan] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_CHANLOAD))? "CL ":"",
                        ((acs->acs_channelrejflag[ht40minus_chan] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_REGPOWER))? "RP ":"",
                        ((acs->acs_channelrejflag[ht40minus_chan] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_NON2G))? "N2G ":"",
                        ((acs->acs_channelrejflag[ht40minus_chan] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_PRIMARY_80_80))? "P80X ":"",
                        ((acs->acs_channelrejflag[ht40minus_chan] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_NO_SEC_80_80))? "NS80X ":"",
                        ((acs->acs_channelrejflag[ht40minus_chan] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_NO_PRIMARY_80_80))? "NP80X ":"",
                        ((acs->acs_channelrejflag[ht40minus_chan] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_FLAG_NON5G))? "N5G ":"");

                        acs->acs_channelrejflag[ht40minus_chan] &= ~ACS_REJFLAG_BLACKLIST;
            }
            else
            {
                snprintf(acs->acs_rank[ieee_chan_num].desc, ACS_RANK_DESC_LEN,
                        "(%s%s%s%s%s%s%s%s%s%s%s%s%s)",
                        (ieee_chan_num == random_chan)? "Random ":"",
                        ((acs->acs_channelrejflag[ieee_chan_num] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_SECCHAN))? "SC ":"",
                        ((acs->acs_channelrejflag[ieee_chan_num] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_WEATHER_RADAR))? "WR ":"",
                        ((acs->acs_channelrejflag[ieee_chan_num] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_DFS))? "DF ":"",
                        ((acs->acs_channelrejflag[ieee_chan_num] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_HIGHNOISE))? "HN ":"",
                        ((acs->acs_channelrejflag[ieee_chan_num] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_RSSI))? "RS ":"",
                        ((acs->acs_channelrejflag[ieee_chan_num] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_CHANLOAD))? "CL ":"",
                        ((acs->acs_channelrejflag[ieee_chan_num] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_REGPOWER))? "RP ":"",
                        ((acs->acs_channelrejflag[ieee_chan_num] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_NON2G))? "N2G ":"",
                        ((acs->acs_channelrejflag[ieee_chan_num] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_PRIMARY_80_80))? "P80X ":"",
                        ((acs->acs_channelrejflag[ieee_chan_num] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_NO_SEC_80_80))? "NS80X ":"",
                        ((acs->acs_channelrejflag[ieee_chan_num] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_NO_PRIMARY_80_80))? "NP80X ":"",
                        ((acs->acs_channelrejflag[ieee_chan_num] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_FLAG_NON5G))? "N5G ":"");

                        acs->acs_channelrejflag[ieee_chan_num] &= ~ACS_REJFLAG_BLACKLIST;
            }
        }
    }
    else {
        /* To prevent channel selection when acs report is active */
        if (!acs->acs_scan_req_param.acs_scan_report_active) {
            channel = ieee80211_acs_find_best_centerchan(acs);
            switch (acs->acs_vap->iv_des_mode) {
                case IEEE80211_MODE_11NG_HT40PLUS:
                case IEEE80211_MODE_11NG_HT40MINUS:
                case IEEE80211_MODE_11NG_HT40:
                    ieee80211_find_ht40intol_overlap(acs, channel);
                default:
                    break;
            }
        }
    }
scan_done:
    ieee80211_acs_free_scan_resource(acs);
    /*ACS scan report is going on no need to take any decision for
      channel hopping timers */
    if(!acs->acs_scan_req_param.acs_scan_report_active) {
        if(ieee80211com_has_cap_ext(ic,IEEE80211_ACS_CHANNEL_HOPPING)) {

            if(!acs->acs_ch_hopping.ch_max_hop_cnt) {
                retval = acs_noise_detection_param(ic,true,IEEE80211_NOISE_THRESHOLD,
                        &ch->param.noise_thresh);
                if(retval == EOK ) {
                    OS_SET_TIMER(&ch->ch_long_timer, SEC_TO_MSEC(ch->param.long_dur));
                } else {
                    goto out;
                }
            }
            if(acs->acs_ch_hopping.ch_max_hop_cnt < ACS_CH_HOPPING_MAX_HOP_COUNT) {
                /* API to intimate sc that no hop is going on so should
                 * not calculate the noise floor */
                retval = acs_noise_detection_param(ic,true,IEEE80211_ENABLE_NOISE_DETECTION,&val);
                if(retval == EOK) {
                    OS_SET_TIMER(&ch->ch_nohop_timer, SEC_TO_MSEC(ch->param.nohop_dur)); /*In sec*/
                    acs->acs_ch_hopping.ch_nohop_timer_active = true;
                }
                else {
                    goto out;
                }
            }
        }
    }
out:
    /* To prevent channel selection when channel load report is active */
    if(!acs->acs_scan_req_param.acs_scan_report_active) {
        ieee80211_acs_post_event(acs, channel);
    }
#if ATH_BAND_STEERING
    else {
        u_int32_t i = 0;
        for (i = 0; i < acs->acs_uchan_list.uchan_cnt; i++) {
            u_int ieee_chan_num = acs->acs_uchan_list.uchan[i];

            /* Inform the band steering module of the channel utilization. It will
             * ignore it if it is not for the right channel or it was not
             * currently requesting it.
             */
            ieee80211_bsteering_record_utilization(acs->acs_vap, ieee_chan_num, acs->acs_chan_load[ieee_chan_num]);
        }
    }
#endif

    if(!OS_ATOMIC_CMPXCHG(&(acs->acs_in_progress),true,false))
    {
        eacs_trace(EACS_DBG_LVL0,("Wrong locking in ACS --investigate -- \n"));
        eacs_trace(EACS_DBG_LVL0,(" %s \n",__func__));
        atomic_set(&(acs->acs_in_progress),false);
    }

    acs->acs_scan_req_param.acs_scan_report_active = false;
    ieee80211_check_and_execute_pending_acsreport(acs->acs_vap);

    /*as per requirement we need to send event both for DCS as well as channel hop*/

    if (ch->ch_hop_triggered || ic->cw_inter_found) {
        if(channel != IEEE80211_CHAN_ANYC) {
            eacs_trace(EACS_DBG_LVL0,("Changed Channel Due to Channel Hopping %d \n",
                        ieee80211_chan2ieee(acs->acs_ic, channel)));
            IEEE80211_DELIVER_EVENT_CH_HOP_CHANNEL_CHANGE(acs->acs_vap,ieee80211_chan2ieee(acs->acs_ic, channel));
        }
    }
    ch->ch_hop_triggered = false;

    spin_unlock(&acs->acs_ev_lock);
    return;
}

static void ieee80211_acs_free_scan_resource(ieee80211_acs_t acs)
{
    int    rc;

    /* unregister scan event handler */
    rc = wlan_scan_unregister_event_handler(acs->acs_vap,
            ieee80211_acs_scan_evhandler,
            (void *) acs);
    if (rc != EOK) {
        IEEE80211_DPRINTF(acs->acs_vap, IEEE80211_MSG_ACS,
                "%s: wlan_scan_unregister_event_handler() failed handler=%08p,%08p rc=%08X\n",
                __func__, ieee80211_acs_scan_evhandler, acs, rc);
    }
    wlan_scan_clear_requestor_id(acs->acs_vap, acs->acs_scan_requestor);
}

static void ieee80211_free_ht40intol_scan_resource(ieee80211_acs_t acs)
{
    int    rc;

    /* unregister scan event handler */
    rc = wlan_scan_unregister_event_handler(acs->acs_vap,
            ieee80211_ht40intol_evhandler,
            (void *) acs);
    if (rc != EOK) {
        IEEE80211_DPRINTF(acs->acs_vap, IEEE80211_MSG_ACS,
                "%s: wlan_scan_unregister_event_handler() failed handler=%08p,%08p rc=%08X\n",
                __func__, ieee80211_ht40intol_evhandler, acs, rc);
    }
    wlan_scan_clear_requestor_id(acs->acs_vap, acs->acs_scan_requestor);
}

static INLINE void
ieee80211_acs_iter_vap_channel(void *arg, struct ieee80211vap *vap, bool is_last_vap)
{
    struct ieee80211vap *current_vap = (struct ieee80211vap *) arg;
    struct ieee80211_channel *channel;

    if (wlan_vap_get_opmode(vap) != IEEE80211_M_HOSTAP) {
        return;
    }
    if (ieee80211_acs_channel_is_set(current_vap)) {
        return;
    }
    if (vap == current_vap) {
        return;
    }

    if (ieee80211_acs_channel_is_set(vap)) {
        channel =  vap->iv_des_chan[vap->iv_des_mode];
        current_vap->iv_ic->ic_acs->acs_channel = channel;
    }

}
static void ieee80211_acs_flush_olddata(ieee80211_acs_t acs)
{
    int i;

    eacs_trace(EACS_DBG_LVL0,( " Flush old data \n" ));
    acs->acs_minrssi_11na = 0xffffffff ;
    acs->acs_minrssisum_11ng = 0xffffffff;
    OS_MEMSET(acs->acs_chan_nbss, 0x0, sizeof(acs->acs_chan_nbss));
    OS_MEMSET(acs->acs_chan_rssitotal, 0x0, sizeof(acs->acs_chan_rssitotal));
    OS_MEMSET(acs->acs_chan_rssi,      0x0, sizeof(acs->acs_chan_rssi));
    OS_MEMSET(acs->acs_chan_maxrssi,   0x0, sizeof(acs->acs_chan_maxrssi));
    OS_MEMSET(acs->acs_chan_minrssi,   0x0, sizeof(acs->acs_chan_minrssi));
    OS_MEMSET(acs->acs_chan_load,      0x0, sizeof(acs->acs_chan_load));
    OS_MEMSET(acs->acs_cycle_count,    0x0, sizeof(acs->acs_cycle_count));
    OS_MEMSET(acs->acs_adjchan_load,   0x0, sizeof(acs->acs_adjchan_load));
    OS_MEMSET(acs->acs_chan_loadsum,   0x0, sizeof(acs->acs_chan_loadsum));
    OS_MEMSET(acs->acs_chan_regpower,  0x0, sizeof(acs->acs_chan_regpower));
    OS_MEMSET(acs->acs_channelrejflag, 0x0, sizeof(acs->acs_channelrejflag));
    OS_MEMSET(acs->acs_adjchan_flag,   0x0, sizeof(acs->acs_adjchan_flag));
    OS_MEMSET(acs->acs_adjchan_load,   0x0, sizeof(acs->acs_adjchan_load));
    for(i = 0 ; i < IEEE80211_CHAN_MAX ; i++) {
         acs->acs_noisefloor[i] = NF_INVALID;
         acs->acs_sec_chan[i] = false;
    }




}


static int ieee80211_find_ht40intol_bss(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = NULL;
    ieee80211_acs_t acs = NULL;
    ieee80211_scan_params scan_params;
    struct ieee80211_channel *chan;
    int rc;
    int ret = EOK;
    u_int8_t chan_list_allocated = false;
    u_int8_t i;

    if ((vap == NULL) || (vap->iv_ic == NULL) || (vap->iv_ic->ic_acs == NULL)) {
        eacs_trace(EACS_DBG_LVL0,("vap/ic/acs is null\n" ));
        return EINVAL;
    }

    ic = vap->iv_ic;
    acs = ic->ic_acs;

    eacs_trace(EACS_DBG_LVL0,(" %s \n",__func__));
    spin_lock(&acs->acs_lock);

    if(OS_ATOMIC_CMPXCHG(&(acs->acs_in_progress),false,true)) {
        /* Just wait for acs done */
        spin_unlock(&acs->acs_lock);
        return EINPROGRESS;
    }

    acs->acs_run_incomplete = false;
    spin_unlock(&acs->acs_lock);

    /* acs_in_progress prevents others from reaching here so unlocking is OK */

    acs->acs_vap = vap;

    /* reset channel mapping array */
    OS_MEMSET(&acs->acs_chan_maps, 0xff, sizeof(acs->acs_chan_maps));
    acs->acs_nchans = 0;
    /* Get 11NG HT20 channels */
    ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11NG_HT20);

    if (acs->acs_nchans == 0) {
        eacs_trace(EACS_DBG_LVL0,("Cannot construct the available channel list." ));
        goto err;
    }

    /* register scan event handler */
    rc = wlan_scan_register_event_handler(vap, ieee80211_ht40intol_evhandler, (void *) acs);
    if (rc != EOK) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
                "%s: wlan_scan_register_event_handler() failed handler=%08p,%08p rc=%08X\n",
                __func__, ieee80211_ht40intol_evhandler, acs, rc);
    }
    wlan_scan_get_requestor_id(vap, (u_int8_t*)"acs", &acs->acs_scan_requestor);

    /* Fill scan parameter */
    OS_MEMZERO(&scan_params, sizeof(ieee80211_scan_params));
    wlan_set_default_scan_parameters(vap,&scan_params,IEEE80211_M_HOSTAP,
            false,true,false,true,0,NULL,0);

    scan_params.type = IEEE80211_SCAN_FOREGROUND;
    scan_params.flags = IEEE80211_SCAN_PASSIVE;
    scan_params.min_dwell_time_passive = MIN_DWELL_TIME;
    scan_params.max_dwell_time_passive = MAX_DWELL_TIME;
    scan_params.min_dwell_time_active  = MIN_DWELL_TIME;
    scan_params.max_dwell_time_active  = MAX_DWELL_TIME;

    scan_params.flags |= IEEE80211_SCAN_2GHZ;

    if(scan_params.chan_list == NULL) {
        scan_params.chan_list = (u_int32_t *) OS_MALLOC(acs->acs_osdev, sizeof(u_int32_t)*acs->acs_nchans, 0);
        chan_list_allocated = true;
        /* scan needs to be done on 2GHz  channels */
        scan_params.num_channels = 0;

        for (i = 0; i < acs->acs_nchans; i++) {
            chan = acs->acs_chans[i];
            if (IEEE80211_IS_CHAN_2GHZ(chan)) {
                scan_params.chan_list[scan_params.num_channels++] = chan->ic_freq;
            }
        }
    }


    /* If scan is invoked from ACS, Channel event notification should be
     * enabled  This is must for offload architecture
     */
    scan_params.flags |= IEEE80211_SCAN_CHAN_EVENT;

    /*Flush scan table before starting scan */
    wlan_scan_table_flush(vap);
    ieee80211_acs_flush_olddata(acs);

    /* Try to issue a scan */
    if ((ret = wlan_scan_start(vap,
                &scan_params,
                acs->acs_scan_requestor,
                IEEE80211_SCAN_PRIORITY_HIGH,
                &(acs->acs_scan_id))) != EOK) {
        eacs_trace(EACS_DBG_LVL0,( " Issue a scan fail."  ));
        goto err;
    }

    goto end;

err:
    ieee80211_free_ht40intol_scan_resource(acs);

    if(!OS_ATOMIC_CMPXCHG(&(acs->acs_in_progress),true,false))
     {
         eacs_trace(EACS_DBG_LVL0,("Wrong locking in ACS --investigate -- \n"));
         eacs_trace(EACS_DBG_LVL0,(" %s \n",__func__));
         atomic_set(&(acs->acs_in_progress),false);
      }

    ieee80211_acs_post_event(acs, vap->iv_des_chan[vap->iv_des_mode]);
end:
    if(chan_list_allocated == true) {
        OS_FREE(scan_params.chan_list);
    }
    return ret;
}


static int ieee80211_autoselect_infra_bss_channel(struct ieee80211vap *vap, bool is_scan_report)
{
    struct ieee80211com *ic = vap->iv_ic;
    ieee80211_acs_t acs = ic->ic_acs;
    struct ieee80211_channel *channel;
    ieee80211_scan_params scan_params;
    u_int32_t num_vaps;
    int rc;
    int ret = EOK;
    u_int8_t chan_list_allocated = false;
    struct acs_ch_hopping_t *ch = NULL;

    eacs_trace(EACS_DBG_LVL0,("Invoking ACS module for Best channel selection \n"));
    spin_lock(&acs->acs_lock);

    if(OS_ATOMIC_CMPXCHG(&(acs->acs_in_progress),false,true)) {
        /* Just wait for acs done */
        spin_unlock(&acs->acs_lock);
        return EINPROGRESS;
    }
    acs->acs_run_incomplete = false;
    /* check if any VAP already set channel */
    acs->acs_channel = NULL;
    ch = &(acs->acs_ch_hopping);
    ieee80211_iterate_vap_list_internal(ic, ieee80211_acs_iter_vap_channel,vap,num_vaps);


    spin_unlock(&acs->acs_lock);

    acs->acs_scan_req_param.acs_scan_report_active = is_scan_report;

    /* acs_in_progress prevents others from reaching here so unlocking is OK */
    /* Report active means we dont want to select channel so its okay to go beyond */
    /* if channel change triggered by channel hopping then go ahead */
    if (acs->acs_channel && (!ic->cw_inter_found)
            &&  (!acs->acs_scan_req_param.acs_scan_report_active)
            &&  (!ch->ch_hop_triggered)) {
        /* wlan scanner not yet started so acs_in_progress = true is OK */
        ieee80211_acs_post_event(acs, acs->acs_channel);
        atomic_set(&acs->acs_in_progress,false);
        return EOK;
    }
    acs->acs_vap = vap;
    /*  when report is active we dont want to depend on des mode as des mode will
        give channel list only for paricular mode in acsreport so choosing AUTO instead  */
    if(acs->acs_scan_req_param.acs_scan_report_active) {
        ieee80211_acs_construct_chan_list(acs, IEEE80211_MODE_AUTO);
    }
    else {
        ieee80211_acs_construct_chan_list(acs,acs->acs_vap->iv_des_mode);
    }

    if (acs->acs_nchans == 0) {
        eacs_trace(EACS_DBG_DEFAULT,( " Cannot construct the available channel list." ));
        ret = -EINVAL;
        goto err;
    }
#if ATH_SUPPORT_VOW_DCS
    /* update dcs information */
    if(ic->cw_inter_found && ic->ic_curchan){
        acs->acs_intr_status[ieee80211_chan2ieee(ic, ic->ic_curchan)] += 1;
        acs->acs_intr_ts[ieee80211_chan2ieee(ic, ic->ic_curchan)] =
            (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());
    }
#endif

    /* register scan event handler */
    rc = wlan_scan_register_event_handler(vap, ieee80211_acs_scan_evhandler, (void *) acs);
    if (rc != EOK) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACS,
                "%s: wlan_scan_register_event_handler() failed handler=%08p,%08p rc=%08X\n",
                __func__, ieee80211_acs_scan_evhandler, (void *) acs, rc);
    }
    wlan_scan_get_requestor_id(vap,(u_int8_t*)"acs", &acs->acs_scan_requestor);

    /* Fill scan parameter */
    OS_MEMZERO(&scan_params,sizeof(ieee80211_scan_params));
    wlan_set_default_scan_parameters(vap,&scan_params,IEEE80211_M_HOSTAP,false,true,false,true,0,NULL,0);

    scan_params.type = IEEE80211_SCAN_FOREGROUND;
    scan_params.flags = IEEE80211_SCAN_PASSIVE;
    scan_params.min_dwell_time_passive = MIN_DWELL_TIME;
    scan_params.max_dwell_time_passive = MAX_DWELL_TIME;
    scan_params.min_dwell_time_active  = MIN_DWELL_TIME;
    scan_params.max_dwell_time_active  = MAX_DWELL_TIME;

    /* giving priority to user configured param when report is active  */
    if(acs->acs_scan_req_param.acs_scan_report_active) {
        if(acs->acs_scan_req_param.mindwell) {
            scan_params.min_dwell_time_active  = acs->acs_scan_req_param.mindwell;
            scan_params.min_dwell_time_passive = acs->acs_scan_req_param.mindwell;
        }

        if(acs->acs_scan_req_param.maxdwell) {
            scan_params.max_dwell_time_active  = acs->acs_scan_req_param.maxdwell;
            scan_params.max_dwell_time_passive = acs->acs_scan_req_param.maxdwell;
        }
        if(acs->acs_scan_req_param.rest_time) {
            /* rest time only valid for background scan */
            scan_params.min_rest_time  = acs->acs_scan_req_param.rest_time;
            scan_params.max_rest_time = acs->acs_scan_req_param.rest_time;
            scan_params.type = IEEE80211_SCAN_BACKGROUND;
        }
        if(acs->acs_scan_req_param.scan_mode) {
            /* Enabeling promise mode to get 11b stats */
            scan_params.flags =  acs->acs_scan_req_param.scan_mode | IEEE80211_SCAN_PROM_MODE;
        }
    }

    /* If scan is invoked from ACS, Channel event notification should be
     * enabled  This is must for offload architecture
     */
    scan_params.flags |= IEEE80211_SCAN_CHAN_EVENT;

    switch (vap->iv_des_mode)
    {
        case IEEE80211_MODE_11A:
        case IEEE80211_MODE_TURBO_A:
        case IEEE80211_MODE_11NA_HT20:
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
        case IEEE80211_MODE_11NA_HT40:
        case IEEE80211_MODE_11AC_VHT20:
        case IEEE80211_MODE_11AC_VHT40PLUS:
        case IEEE80211_MODE_11AC_VHT40MINUS:
        case IEEE80211_MODE_11AC_VHT40:
        case IEEE80211_MODE_11AC_VHT80:
        case IEEE80211_MODE_11AC_VHT160:
        case IEEE80211_MODE_11AC_VHT80_80:
            scan_params.flags |= IEEE80211_SCAN_5GHZ;
            break;

        case IEEE80211_MODE_11B:
        case IEEE80211_MODE_11G:
        case IEEE80211_MODE_TURBO_G:
        case IEEE80211_MODE_11NG_HT20:
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40:
            scan_params.flags |= IEEE80211_SCAN_2GHZ;
            break;

        default:
            if (acs->acs_scan_2ghz_only) {
                scan_params.flags |= IEEE80211_SCAN_2GHZ;
            } else {
                scan_params.flags |= IEEE80211_SCAN_ALLBANDS;
            }
            break;
    }

    acs->acs_nchans_scan = 0;
    /* giving priority to user configured param when report is active  */
    if(acs->acs_uchan_list.uchan_cnt &&
            (acs->acs_scan_req_param.acs_scan_report_active)) {
        scan_params.num_channels = acs->acs_uchan_list.uchan_cnt;
        scan_params.chan_list = &(acs->acs_uchan_list.uchan[0]);
    } else {
        /* If scan needs to be done on specific band or specific set of channels */
        if ((scan_params.flags & (IEEE80211_SCAN_ALLBANDS)) != IEEE80211_SCAN_ALLBANDS) {
            wlan_chan_t *chans;
            u_int16_t nchans = 0;
            u_int8_t i;


            chans = (wlan_chan_t *)OS_MALLOC(acs->acs_osdev,
                            sizeof(wlan_chan_t) * IEEE80211_CHAN_MAX, 0);
            if (chans == NULL) {
                ret = -ENOMEM;
                goto err2;
            }
            /* HT20 only if IEEE80211_MODE_AUTO */

            if (scan_params.flags & IEEE80211_SCAN_2GHZ) {
                nchans = wlan_get_channel_list(ic, IEEE80211_MODE_11NG_HT20,
                                                chans, IEEE80211_CHAN_MAX);
                /* If no any HT channel available */
                if (nchans == 0) {
                     nchans = wlan_get_channel_list(ic, IEEE80211_MODE_11G,
                                                chans, IEEE80211_CHAN_MAX);
                }
            } else {
                nchans = wlan_get_channel_list(ic, IEEE80211_MODE_11NA_HT20,
                                                chans, IEEE80211_CHAN_MAX);
                /* If no any HT channel available */
                if (nchans == 0) {
                     nchans = wlan_get_channel_list(ic, IEEE80211_MODE_11A,
                                                chans, IEEE80211_CHAN_MAX);
                }
            }
            /* If still no channel available */
            if (nchans == 0) {
                nchans = wlan_get_channel_list(ic, IEEE80211_MODE_11B,
                                            chans, IEEE80211_CHAN_MAX);
            }


            if(scan_params.chan_list == NULL) {
                scan_params.chan_list = (u_int32_t *) OS_MALLOC(acs->acs_osdev, sizeof(u_int32_t)*nchans, 0);
                chan_list_allocated = true;
            }
            for (i = 0; i < nchans; i++)
            {
                const wlan_chan_t chan = chans[i];
                if ((scan_params.flags & IEEE80211_SCAN_2GHZ) ?
                    IEEE80211_IS_CHAN_2GHZ(chan) : IEEE80211_IS_CHAN_5GHZ(chan)) {
                    scan_params.chan_list[scan_params.num_channels++] = chan->ic_freq;
                    acs->acs_ieee_chan[i] = ieee80211_chan2ieee(ic, chan);
                 }
            }
            acs->acs_nchans_scan = nchans;
            OS_FREE(chans);
        }
    }

    /* Try to issue a scan */
#if ATH_ACS_SUPPORT_SPECTRAL && ATH_SUPPORT_SPECTRAL
    /* For ACS spectral sample indication priority should be
       low (0) to indicate scan entries to mgmt layer */
    /* Only reporting is going on so no spectral */
    if(!acs->acs_scan_req_param.acs_scan_report_active) {
        ic->ic_start_spectral_scan(ic,0);
    }
#endif

    /*Flush scan table before starting scan */
    wlan_scan_table_flush(vap);
    ieee80211_acs_flush_olddata(acs);
    if ((ret = wlan_scan_start(vap,
                &scan_params,
                acs->acs_scan_requestor,
                IEEE80211_SCAN_PRIORITY_HIGH,
                &(acs->acs_scan_id))) != EOK) {

        eacs_trace(EACS_DBG_DEFAULT,( " Issue a scan fail."
                    ));
        goto err2;
    }
    acs->acs_startscantime = OS_GET_TIMESTAMP();
    goto end;

err2:
    ieee80211_acs_free_scan_resource(acs);
err:
    /* select the first available channel to start */
    if(!acs->acs_scan_req_param.acs_scan_report_active) {
        channel = ieee80211_find_dot11_channel(ic, 0, 0, vap->iv_des_mode);
        ieee80211_acs_post_event(acs, channel);
        eacs_trace(EACS_DBG_DEFAULT,( "Use the first available channel=%d to start"
                , ieee80211_chan2ieee(ic, channel)));
    }

#if ATH_ACS_SUPPORT_SPECTRAL && ATH_SUPPORT_SPECTRAL
    /* Only reporting is going on so no spectral */
    if(!acs->acs_scan_req_param.acs_scan_report_active) {
        ic->ic_stop_spectral_scan(ic);
    }
#endif
    atomic_set(&acs->acs_in_progress,false);
    ch->ch_hop_triggered = false;
    if(chan_list_allocated == true)
        OS_FREE(scan_params.chan_list);
    return ret;
end:
    if(chan_list_allocated == true)
        OS_FREE(scan_params.chan_list);
    return ret;
}

int ieee80211_acs_startscantime(struct ieee80211com *ic)
{
    ieee80211_acs_t acs = ic->ic_acs;
    return(acs->acs_startscantime);
}

int ieee80211_acs_state(struct ieee80211_acs *acs)
{
    if(acs->acs_startscantime == 0){

        /*
         * Scan never initiated
         */

        return EINVAL;
    }
   if(ieee80211_acs_in_progress(acs)) {

       /*
        * Scan is in progress
        */

       return EINPROGRESS;
   }
   else{

        /*
         * Scan has been completed
         */
        return EOK;

    }
    return -1;
}

static int ieee80211_acs_register_scantimer_handler(void *arg,
        ieee80211_acs_scantimer_handler evhandler,
        void                         *arg2)
{

    struct ieee80211com *ic = (struct ieee80211com *)arg;
    ieee80211_acs_t          acs = ic->ic_acs;

    eacs_trace(EACS_DBG_LVL1,(" %s \n",__func__));
    spin_lock(&acs->acs_lock);
    acs->acs_scantimer_handler= evhandler;
    acs->acs_scantimer_arg = arg2;
    spin_unlock(&acs->acs_lock);

    return EOK;
}
static int ieee80211_acs_register_event_handler(ieee80211_acs_t          acs,
        ieee80211_acs_event_handler evhandler,
        void                         *arg)
{
    int    i;

    for (i = 0; i < IEEE80211_MAX_ACS_EVENT_HANDLERS; ++i) {
        if ((acs->acs_event_handlers[i] == evhandler) &&
                (acs->acs_event_handler_arg[i] == arg)) {
            return EEXIST; /* already exists */
        }
    }

    if (acs->acs_num_handlers >= IEEE80211_MAX_ACS_EVENT_HANDLERS) {
        return ENOSPC;
    }

    spin_lock(&acs->acs_lock);
    acs->acs_event_handlers[acs->acs_num_handlers] = evhandler;
    acs->acs_event_handler_arg[acs->acs_num_handlers++] = arg;
    spin_unlock(&acs->acs_lock);

    return EOK;
}

static int ieee80211_acs_unregister_event_handler(ieee80211_acs_t          acs,
        ieee80211_acs_event_handler evhandler,
        void                         *arg)
{
    int    i;

    spin_lock(&acs->acs_lock);
    for (i = 0; i < IEEE80211_MAX_ACS_EVENT_HANDLERS; ++i) {
        if ((acs->acs_event_handlers[i] == evhandler) &&
                (acs->acs_event_handler_arg[i] == arg)) {
            /* replace event handler being deleted with the last one in the list */
            acs->acs_event_handlers[i]    = acs->acs_event_handlers[acs->acs_num_handlers - 1];
            acs->acs_event_handler_arg[i] = acs->acs_event_handler_arg[acs->acs_num_handlers - 1];

            /* clear last event handler in the list */
            acs->acs_event_handlers[acs->acs_num_handlers - 1]    = NULL;
            acs->acs_event_handler_arg[acs->acs_num_handlers - 1] = NULL;
            acs->acs_num_handlers--;

            spin_unlock(&acs->acs_lock);

            return EOK;
        }
    }
    spin_unlock(&acs->acs_lock);

    return ENXIO;

}

/**
 * @brief  Cancel the scan
 *
 * @param vap
 *
 * @return
 */
static int ieee80211_acs_cancel(struct ieee80211vap *vap)
{
    struct ieee80211com *ic;
    ieee80211_acs_t acs;

    /* If vap is NULL return here */
    if(vap == NULL) {
       return 0;
    }

    ic = vap->iv_ic;
    acs = ic->ic_acs;

    /* If ACS is not initiated from this vap, so
       don't unregister scan handlers */
    if(vap != acs->acs_vap) {
       return 0;
    }
    spin_lock(&acs->acs_ev_lock);
    /* If ACS is not in progress, then return, since the ACS handling must have completed before
     acquiring the lock*/
    if (!ieee80211_acs_in_progress(acs)) {
        spin_unlock(&acs->acs_ev_lock);
        return 0;
    }

       /* Unregister scan event handler */
    ieee80211_acs_free_scan_resource(acs);
    ieee80211_free_ht40intol_scan_resource(acs);
     /* Post ACS event with NULL channel to report cancel scan */
    ieee80211_acs_post_event(acs, IEEE80211_CHAN_ANYC);
     /*Reset ACS in progress flag */
    atomic_set(&acs->acs_in_progress,false);
    acs->acs_ch_hopping.ch_hop_triggered = false;
    spin_unlock(&acs->acs_ev_lock);
    return 1;
}


int wlan_autoselect_register_scantimer_handler(void * arg ,
        ieee80211_acs_scantimer_handler  evhandler,
        void                          *arg2)
{
    return ieee80211_acs_register_scantimer_handler(arg ,
            evhandler,
            arg2);
}


int wlan_autoselect_register_event_handler(wlan_if_t                    vaphandle,
        ieee80211_acs_event_handler evhandler,
        void                         *arg)
{
    return ieee80211_acs_register_event_handler(vaphandle->iv_ic->ic_acs,
            evhandler,
            arg);
}

int wlan_autoselect_unregister_event_handler(wlan_if_t                    vaphandle,
        ieee80211_acs_event_handler evhandler,
        void                         *arg)
{
    return ieee80211_acs_unregister_event_handler(vaphandle->iv_ic->ic_acs, evhandler, arg);
}

int wlan_autoselect_in_progress(wlan_if_t vaphandle)
{
    if (!vaphandle->iv_ic->ic_acs) return 0;
    return ieee80211_acs_in_progress(vaphandle->iv_ic->ic_acs);
}


int wlan_autoselect_find_infra_bss_channel(wlan_if_t             vaphandle)
{
    return ieee80211_autoselect_infra_bss_channel(vaphandle, false /* is_scan_report */);
}

int wlan_attempt_ht40_bss(wlan_if_t             vaphandle)
{
    return ieee80211_find_ht40intol_bss(vaphandle);
}

int wlan_autoselect_cancel_selection(wlan_if_t vaphandle)
{
   return ieee80211_acs_cancel(vaphandle);
}

int wlan_acs_find_best_channel(struct ieee80211vap *vap, int *bestfreq, int num)
{

    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_channel *best_11na = NULL;
    struct ieee80211_channel *best_11ng = NULL;
    struct ieee80211_channel *best_overall = NULL;
    //struct ieee80211_acs myacs;
    int retv = 0,i=0;

    ieee80211_acs_t acs = ic->ic_acs;
    ieee80211_acs_t temp_acs;

    eacs_trace(EACS_DBG_LVL1,(" %s \n",__func__));

    //temp_acs = &myacs;

    //temp_acs = (ieee80211_acs_t) kmalloc(sizeof(struct ieee80211_acs), GFP_KERNEL);
    temp_acs = (ieee80211_acs_t) OS_MALLOC(acs->acs_osdev, sizeof(struct ieee80211_acs), 0);

    if (temp_acs) {
        OS_MEMZERO(temp_acs, sizeof(struct ieee80211_acs));
    }
    else {
        qdf_print("%s: malloc failed \n",__func__);
        return ENOMEM;
    }

    temp_acs->acs_ic = ic;
    temp_acs->acs_vap = vap;
    temp_acs->acs_osdev = acs->acs_osdev;
    temp_acs->acs_num_handlers = 0;
    atomic_set(&(temp_acs->acs_in_progress),true);
    temp_acs->acs_scan_2ghz_only = 0;
    temp_acs->acs_channel = NULL;
    temp_acs->acs_nchans = 0;



    ieee80211_acs_construct_chan_list(temp_acs,IEEE80211_MODE_AUTO);
    if (temp_acs->acs_nchans == 0) {
        eacs_trace(EACS_DBG_LVL0,( "Cannot construct the available channel list." ));
        retv = -1;
        goto err;
    }

    for(i=0; i<IEEE80211_CHAN_MAX ;i++) {
        acs->acs_chan_rssitotal[i]= 0;
        acs->acs_chan_rssi[i] = 0;
    }

    wlan_scan_table_iterate(temp_acs->acs_vap, ieee80211_acs_get_channel_maxrssi_n_secondary_ch, temp_acs);

    best_11na = ieee80211_acs_find_best_11na_centerchan(temp_acs);
    best_11ng = ieee80211_acs_find_best_11ng_centerchan(temp_acs);

    if (temp_acs->acs_minrssi_11na > temp_acs->acs_minrssisum_11ng) {
        best_overall = best_11ng;
    } else {
        best_overall = best_11na;
    }

    if( best_11na==NULL || best_11ng==NULL || best_overall==NULL) {
        eacs_trace(EACS_DBG_LVL1, ("  channel "));
        retv = -1;
        goto err;
    }

    bestfreq[0] = (int) best_11na->ic_freq;
    bestfreq[1] = (int) best_11ng->ic_freq;
    bestfreq[2] = (int) best_overall->ic_freq;

err:
    OS_FREE(temp_acs);
    //kfree(temp_acs);
    return retv;

}
/*
 * Update NF and Channel Load upon WMI event
 */

#define MIN_CLEAR_CNT_DIFF 1000
void ieee80211_acs_stats_update(ieee80211_acs_t acs,
        u_int8_t flags,
        u_int ieee_chan_num,
        int16_t noisefloor,
        struct ieee80211_chan_stats *chan_stats)
{
    u_int32_t temp = 0,cycles_cnt = 0;
    u_int32_t now = (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());
    struct ieee80211com *ic = NULL;
    struct ol_ath_softc_net80211 *scn = NULL;

    eacs_trace(EACS_DBG_LVL1,("%d.%03d | %s: \n",  now / 1000, now % 1000, __func__));
    if(acs == NULL) {
        eacs_trace(EACS_DBG_LVL0,("ERROR: ACS is not initialized \n"));
        return;
    }

    if (!ieee80211_acs_in_progress(acs)) {
        acs->acs_run_incomplete = true;
        return;
    }

    ic = acs->acs_ic;
    scn = OL_ATH_SOFTC_NET80211(ic);

    if(flags == ACS_CHAN_STATS_NF) {

        /* if initial counters are not recorded, return */

        if(acs->acs_cycle_count[ieee_chan_num] == 0)
        {
            eacs_trace(EACS_DBG_LVL0,
                ("%s: NF and Channel Load can't be updated\n", __func__));
            return;
        }

        if (ieee_chan_num != IEEE80211_CHAN_ANY) {
            acs->acs_noisefloor[ieee_chan_num] = noisefloor;
            eacs_trace(EACS_DBG_NF,("Noise floor chan %d  NF %d \n",ieee_chan_num,noisefloor));
        }

        /* For Beeliner family of chipsets, hardware counters cycle_cnt and chan_clr_cnt wrap
         * around independently. After reaching max value of 0xffffffff they become 0x7fffffff.
         *
         * For Peregrine and Direct attach chipsets, once cycle_cnt reaches 0xffffffff, both
         * cycle_cnt and chan_clr_cnt are right shifted by one bit. Because of this right
         * shifting we can't calculate correct channel utilization when wrap around happens.
         */

        if (acs->acs_cycle_count[ieee_chan_num] > chan_stats->cycle_cnt) {
            acs->acs_cycle_count[ieee_chan_num] = (MAX_32BIT_UNSIGNED_VALUE - acs->acs_cycle_count[ieee_chan_num])
                + (chan_stats->cycle_cnt - (MAX_32BIT_UNSIGNED_VALUE >> 1));
        } else {
            acs->acs_cycle_count[ieee_chan_num] = chan_stats->cycle_cnt - acs->acs_cycle_count[ieee_chan_num] ;
        }

        if (ic->ic_is_mode_offload(ic) && scn->is_ar900b) {
            /* Beeliner family */
            if (acs->acs_chan_load[ieee_chan_num] > chan_stats->chan_clr_cnt) {
                acs->acs_chan_load[ieee_chan_num] = (MAX_32BIT_UNSIGNED_VALUE - acs->acs_chan_load[ieee_chan_num])
                    + (chan_stats->chan_clr_cnt - (MAX_32BIT_UNSIGNED_VALUE >> 1));
            } else {
                acs->acs_chan_load[ieee_chan_num] = chan_stats->chan_clr_cnt - acs->acs_chan_load[ieee_chan_num] ;
            }
        } else {
            /* Peregrine and Diretc attach family */
            if (acs->acs_cycle_count[ieee_chan_num] > chan_stats->cycle_cnt) {
                acs->acs_chan_load[ieee_chan_num] = chan_stats->chan_clr_cnt - (acs->acs_chan_load[ieee_chan_num] >> 1);
            } else {
                acs->acs_chan_load[ieee_chan_num] = chan_stats->chan_clr_cnt - acs->acs_chan_load[ieee_chan_num] ;
            }
        }

        if(acs->acs_80211_b_duration[ieee_chan_num] > chan_stats->duration_11b_data) {
             acs->acs_80211_b_duration[ieee_chan_num] = (MAX_32BIT_UNSIGNED_VALUE - acs->acs_80211_b_duration[ieee_chan_num])
                                                      + chan_stats->duration_11b_data;
        } else {
             acs->acs_80211_b_duration[ieee_chan_num] = chan_stats->duration_11b_data - acs->acs_80211_b_duration[ieee_chan_num] ;
        }

        eacs_trace(EACS_DBG_CHLOAD ,("CH:%d End Clr cnt %u cycle cnt %u diff %u \n",
                    ieee_chan_num,chan_stats->chan_clr_cnt,chan_stats->cycle_cnt ,
                    acs->acs_chan_load[ieee_chan_num]));
        if((chan_stats->chan_tx_power_range > 0) || (chan_stats->chan_tx_power_tput > 0)) {
            if(acs->acs_tx_power_type == ACS_TX_POWER_OPTION_TPUT) {
               acs->acs_chan_regpower[ieee_chan_num] = chan_stats->chan_tx_power_tput;
            } else if(acs->acs_tx_power_type == ACS_TX_POWER_OPTION_RANGE)  {
               acs->acs_chan_regpower[ieee_chan_num] = chan_stats->chan_tx_power_range;
            }
        }

        /* make sure when new clr_cnt is more than old clr cnt, ch utilization is non-zero */
        if ( (acs->acs_chan_load[ieee_chan_num] > MIN_CLEAR_CNT_DIFF) &&
             (acs->acs_cycle_count[ieee_chan_num] != 0) ){
            temp = (u_int32_t)(acs->acs_chan_load[ieee_chan_num]);
            cycles_cnt = (u_int32_t) acs->acs_cycle_count[ieee_chan_num]/100;/*divide it instead multiply temp */
            temp = (u_int32_t)(temp/cycles_cnt);
            /* Some results greater than 100% have been seen. The reason for
             * this is unknown, so for now just floor the results to 100.
             */
            acs->acs_chan_load[ieee_chan_num] = MIN(MAX( 1,temp), 100);
            eacs_trace(EACS_DBG_CHLOAD, ("CH:%u Ch load %u \n",ieee_chan_num,acs->acs_chan_load[ieee_chan_num]));
        } else {
            eacs_trace(EACS_DBG_CHLOAD,("CH:%u Ch load  %u(diff is less then min) or cycle count is zero \n",ieee_chan_num,acs->acs_chan_load[ieee_chan_num]));
            acs->acs_chan_load[ieee_chan_num] = 0;
        }

#if ATH_ACS_SUPPORT_SPECTRAL && ATH_SUPPORT_SPECTRAL
        acs->acs_channel_loading[ieee_chan_num] = get_eacs_control_duty_cycle(acs);
#endif
    }
    else if(flags == ACS_CHAN_STATS) {
        eacs_trace(EACS_DBG_CHLOAD ,("CH:%d Initial chan_clr_cnt %u cycle_cnt %u \n",
                    ieee_chan_num, 	chan_stats->chan_clr_cnt,chan_stats->cycle_cnt));
        acs->acs_chan_load[ieee_chan_num] = chan_stats->chan_clr_cnt;
        acs->acs_cycle_count[ieee_chan_num] = chan_stats->cycle_cnt;
        acs->acs_80211_b_duration[ieee_chan_num] = chan_stats->duration_11b_data;

#if ATH_ACS_SUPPORT_SPECTRAL && ATH_SUPPORT_SPECTRAL
        /*If spectral ACS stats are not reset on channel change, they will be reset here */
        ieee80211_init_spectral_chan_loading(acs->acs_ic,
                ieee80211_ieee2mhz(acs->acs_ic, ieee_chan_num, 0),0);
#endif
    }
}

int wlan_acs_get_user_chanlist(wlan_if_t vaphandle, u_int8_t *chanlist)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    ieee80211_acs_t acs = ic->ic_acs;
    u_int32_t i=0;

    for(i=0;i<acs->acs_uchan_list.uchan_cnt;i++)
    {
        chanlist[i] = acs->acs_uchan_list.uchan[i];
    }
    return i;
}

int wlan_acs_set_user_chanlist(struct ieee80211vap *vap, u_int8_t *extra)
{
#define APPEND_LIST 0xff
    struct ieee80211com *ic = vap->iv_ic;
    ieee80211_acs_t acs = ic->ic_acs;
    u_int32_t i = 0;
    int *ptr = NULL,append = 0,dup = false;

    if(*extra == APPEND_LIST) {
        /*append list*/
        ptr = (int *)(&(acs->acs_uchan_list.uchan[acs->acs_uchan_list.uchan_cnt]));
        extra++; /*Trim apend byte */
        append = 1;
    }
    else {
        /*Flush list and start copying */
        OS_MEMZERO(acs->acs_uchan_list.uchan,IEEE80211_ACS_CHAN_MAX);
        ptr =(int *)(&(acs->acs_uchan_list.uchan[0]));
        acs->acs_uchan_list.uchan_cnt = 0;
    }

    while(*extra) {
        if(append) /*duplicate detection */
        {
            for(i = 0;i < acs->acs_uchan_list.uchan_cnt; i++) {
                if(*extra == acs->acs_uchan_list.uchan[i]) {
                    dup = true;
                    extra++;
                    break;
                } else {
                    dup = false;
                }
            }
        }
        if(!dup) {
            *ptr++ = *extra++;
            acs->acs_uchan_list.uchan_cnt++;
        }
    }
#undef APPEND_LIST
    return 0;
}


/**
 * @brief channel change for channel hopping
 *
 * @param vap
 */
static void ieee80211_acs_channel_hopping_change_channel(struct ieee80211vap *vap)
{
    struct ieee80211com *ic;
    ieee80211_acs_t acs;
    struct acs_ch_hopping_t *ch;

    ASSERT(vap);
    ic = vap->iv_ic;
    acs = ic->ic_acs;

    if(acs == NULL)
        return;

    ch = &(acs->acs_ch_hopping);

    if (ch->ch_hop_triggered)
        return ;  /* channel change is already active  */

    spin_lock(&ic->ic_lock);
    ch->ch_hop_triggered = true; /* To bail out acs in multivap scenarios */
    spin_unlock(&ic->ic_lock);

    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
            if (!wlan_set_channel(vap, IEEE80211_CHAN_ANY, 0)) {
                /* ACS is done on per radio, so calling it once is
                 * good enough
                 */
                goto done;
            }
        }
    }
done:
    return;
}

/**
 * @brief timer to keep track of noise detection
 *
 * @param ieee80211_ch_cntwin_timer
 */
static OS_TIMER_FUNC(ieee80211_ch_cntwin_timer)
{
    struct ieee80211com *ic = NULL;
    ieee80211_acs_t acs = NULL;
    struct acs_ch_hopping_t *ch = NULL;
    struct ieee80211_channel *channel = NULL,*ichan = NULL;
    struct ieee80211vap *vap = NULL;
    int32_t i = 0,flag = 0,retval = 0, val = 0;
    u_int16_t cur_freq = 0;

    OS_GET_TIMER_ARG(ic, struct ieee80211com *);

    ASSERT(ic);

    acs = ic->ic_acs;

    if(acs == NULL)
        return;

    ch = &(acs->acs_ch_hopping);

    vap = acs->acs_vap;

    if(vap == NULL)
        return;

    if(ieee80211_vap_deleted_is_clear(vap)) {
        /*Stopping noise detection To collect stats */
        val = false;
        retval = acs_noise_detection_param(ic,true,IEEE80211_ENABLE_NOISE_DETECTION,&val);

        if(retval == EOK) {
            retval = acs_noise_detection_param(ic,false,IEEE80211_GET_COUNTER_VALUE,&val);
            if(val > acs->acs_ch_hopping.param.cnt_thresh)
            {
                if (ieee80211_acs_channel_is_set(vap)) {
                    channel =  vap->iv_des_chan[vap->iv_des_mode];
                    if(channel) {
                        cur_freq = ieee80211_chan2freq(ic,channel);
                        ieee80211_enumerate_channels(ichan, ic, i)
                        {
                            if (cur_freq == ieee80211_chan2freq(ic, ichan))
                            {
                                eacs_trace(EACS_DBG_LVL0,("%d  \n",ieee80211_chan2freq(ic, ichan)));
                                IEEE80211_CH_HOPPING_SET_CHAN_BLOCKED(ichan);
                                flag = true;
                            }
                        }
                    }
                }
            }
        } /*retval == EOK*/
        else
            return;


        if(flag) {
            acs->acs_ch_hopping.ch_max_hop_cnt++;
            ieee80211_acs_channel_hopping_change_channel(vap);
            return; /*Donot fire timer */
        }

        if(acs->acs_ch_hopping.ch_max_hop_cnt < ACS_CH_HOPPING_MAX_HOP_COUNT ) { /*Three hops are enough */
            /*Resting time over should enable noise detection now */
            val = true;
            retval = acs_noise_detection_param(ic,true,IEEE80211_ENABLE_NOISE_DETECTION,&val);
            if(EOK == retval ) {
                /*Restarting noise detection again */
                OS_SET_TIMER(&ch->ch_cntwin_timer, SEC_TO_MSEC(ch->param.cnt_dur)); /*in sec */
            }
        }
    }/*vap deleted is clear */
    else {
        return; /*Do not fire timer return */
    }
}

/**
 * @brief Long duration timer for keeping track of history
 *
 * @param ieee80211_ch_long_timer
 */
static OS_TIMER_FUNC(ieee80211_ch_long_timer)
{
    struct ieee80211com *ic = NULL;
    ieee80211_acs_t acs = NULL;
    struct acs_ch_hopping_t *ch = NULL;
    struct ieee80211_channel *ichan = NULL;
    int i=0,retval = 0;

    OS_GET_TIMER_ARG(ic, struct ieee80211com *);

    ASSERT(ic);

    acs = ic->ic_acs;

    if(acs == NULL) /*vap delete may be in process */
        return;

    ch = &(acs->acs_ch_hopping);
    ieee80211_enumerate_channels(ichan, ic, i) {
        IEEE80211_CH_HOPPING_CLEAR_CHAN_BLOCKED(ichan);
    }

    if(acs->acs_ch_hopping.ch_max_hop_cnt >= ACS_CH_HOPPING_MAX_HOP_COUNT) {

        /*Restarting noise detection again */
        i = true;
        retval = acs_noise_detection_param(ic,true,IEEE80211_ENABLE_NOISE_DETECTION,&i);
        if(retval == EOK)
            OS_SET_TIMER(&ch->ch_cntwin_timer, SEC_TO_MSEC(ch->param.cnt_dur)); /*in sec */
    }

    acs->acs_ch_hopping.ch_max_hop_cnt = 0;
    eacs_trace(EACS_DBG_LVL0,("%s %d LONG DURATION  EXPIRES SET itself  \n",__func__,__LINE__));
    if(retval == EOK )
        OS_SET_TIMER(&ch->ch_long_timer, SEC_TO_MSEC(ch->param.long_dur)); /*in sec */
}

/**
 * @brief NO hopping timer , cannot change channel till it is active
 *
 * @param ieee80211_ch_nohop_timer
 */
static OS_TIMER_FUNC(ieee80211_ch_nohop_timer)
{
    struct ieee80211com *ic = NULL;
    int val = true,retval = 0;
    ieee80211_acs_t acs = NULL;
    struct acs_ch_hopping_t *ch = NULL;

    OS_GET_TIMER_ARG(ic, struct ieee80211com *);
    ASSERT(ic);

    acs = ic->ic_acs;
    ch = &(acs->acs_ch_hopping);
    eacs_trace(EACS_DBG_LVL0,("%s %d NOHOP EXPIRES SET CNTWIN \n",__func__,__LINE__));
    acs->acs_ch_hopping.ch_nohop_timer_active = false;
    retval = acs_noise_detection_param(ic,true,IEEE80211_ENABLE_NOISE_DETECTION,&val);

    if(retval == EOK)
        OS_SET_TIMER(&ch->ch_cntwin_timer, SEC_TO_MSEC(ch->param.cnt_dur)); /*in sec */
    /* Any thing for else ?*/
    return;
}

/**
 * @brief Setting long duration timer from user land
 *
 * @param acs
 * @param val
 *
 * @return Zero in case of succes
 */
int ieee80211_acs_ch_long_dur(ieee80211_acs_t acs,int val)
{
    struct acs_ch_hopping_t *ch = &(acs->acs_ch_hopping);
    /* Long duration  in minutes */
    if(val)
    {
        if(val < ch->param.nohop_dur)
            return EINVAL;

        /* start timer */
        ch->param.long_dur = val;
        OS_SET_TIMER(&ch->ch_long_timer, SEC_TO_MSEC(ch->param.long_dur)); /*in sec */
    } else {
        /* stop timer */
        OS_CANCEL_TIMER(&ch->ch_long_timer);
    }
    return EOK;
}

/**
 * @brief No hopping timer triggered from user land
 *
 * @param acs
 * @param val
 *
 * @return EOK if successfull
 */

int ieee80211_acs_ch_nohop_dur(ieee80211_acs_t acs,int val)
{
    struct acs_ch_hopping_t *ch = &(acs->acs_ch_hopping);

    /*channel hopping in seconds */
    if(val)
    {
        /* Do not restart timer,its for
           next evalutaion of no hopping */
        ch->param.nohop_dur = val;
    } else {
        /* stop timer */
        OS_CANCEL_TIMER(&ch->ch_nohop_timer);
    }
    return EOK;
}

/**
 * @brief api from os specific files
 *
 * @param vap
 * @param param
 * @param cmd
 * @param val
 *
 * @return EOK in case of success
 */
int wlan_acs_param_ch_hopping(wlan_if_t vap, int param, int cmd,int *val)
{
    struct ieee80211com *ic = vap->iv_ic;
    ieee80211_acs_t acs = ic->ic_acs;
    int error = EOK,retval = EOK;
#define NOISE_FLOOR_MAX -60
#define NOISE_FLOOR_MIN -128
#define MAX_COUNTER_THRESH  100
    switch (param)
    {
        case true: /*SET */
            switch(cmd)
            {
                case IEEE80211_ACS_ENABLE_CH_HOP:
                    if(*val) {
                        ieee80211com_set_cap_ext(ic,IEEE80211_ACS_CHANNEL_HOPPING);
                        /*See if we want to init timer used in attached function */
                    }else {
                        ieee80211com_clear_cap_ext (ic,IEEE80211_ACS_CHANNEL_HOPPING);
                    }
                    break;
                case IEEE80211_ACS_CH_HOP_LONG_DUR:
                    ieee80211_acs_ch_long_dur(acs,*val);
                    break;
                case IEEE80211_ACS_CH_HOP_NO_HOP_DUR:
                    ieee80211_acs_ch_nohop_dur(acs,*val);
                    break;
                case IEEE80211_ACS_CH_HOP_CNT_WIN_DUR:
                    if(*val) {
                        acs->acs_ch_hopping.param.cnt_dur = *val;
                        if( acs->acs_ch_hopping.ch_nohop_timer_active == false) {
                            /*Timer not working*/
                            OS_CANCEL_TIMER(&acs->acs_ch_hopping.ch_cntwin_timer);
                            OS_SET_TIMER(&(acs->acs_ch_hopping.ch_cntwin_timer),
                                    SEC_TO_MSEC(acs->acs_ch_hopping.param.cnt_dur));
                        } else {
                            error = -EINVAL;
                        }

                    }
                    break;
                case IEEE80211_ACS_CH_HOP_NOISE_TH:
                    if((*val > NOISE_FLOOR_MIN) && (*val < NOISE_FLOOR_MAX)) {
                        acs->acs_ch_hopping.param.noise_thresh = *val;
                        retval = acs_noise_detection_param(ic,true,IEEE80211_NOISE_THRESHOLD,
                                &acs->acs_ch_hopping.param.noise_thresh);
                        if((acs->acs_ch_hopping.ch_nohop_timer_active == false)
                                && EOK == retval) {
                            /*Timer not working*/
                            OS_CANCEL_TIMER(&acs->acs_ch_hopping.ch_cntwin_timer);
                            OS_SET_TIMER(&(acs->acs_ch_hopping.ch_cntwin_timer),
                                    SEC_TO_MSEC(acs->acs_ch_hopping.param.cnt_dur));
                        }
                    } else {
                        error = -EINVAL;
                    }
                    break;
                case IEEE80211_ACS_CH_HOP_CNT_TH:
                    if(*val && *val <= MAX_COUNTER_THRESH) /*value is in percentage */
                        acs->acs_ch_hopping.param.cnt_thresh = *val;
                    else {
                        error = -EINVAL;
                    }
                    break;
                default:
                    eacs_trace(EACS_DBG_LVL0,
                            (" %s %d should bot happen INVESTIGATE \n",
                             __func__,__LINE__));
                    error = -EINVAL;
                    break;
            }
            break;
        case false: /*GET */
            switch(cmd)
            {
                case IEEE80211_ACS_ENABLE_CH_HOP:
                    *val = ieee80211com_has_cap_ext(ic,IEEE80211_ACS_CHANNEL_HOPPING);
                    break;
                case IEEE80211_ACS_CH_HOP_LONG_DUR:
                    *val = acs->acs_ch_hopping.param.long_dur;
                    break;
                case IEEE80211_ACS_CH_HOP_NO_HOP_DUR:
                    *val = acs->acs_ch_hopping.param.nohop_dur;
                    break;
                case IEEE80211_ACS_CH_HOP_CNT_WIN_DUR:
                    *val = acs->acs_ch_hopping.param.cnt_dur;
                    break;
                case IEEE80211_ACS_CH_HOP_NOISE_TH:
                    *val = acs->acs_ch_hopping.param.noise_thresh;
                    break;

                case IEEE80211_ACS_CH_HOP_CNT_TH:
                    *val = acs->acs_ch_hopping.param.cnt_thresh;
                    break;

                default:
                    eacs_trace(EACS_DBG_LVL0,(" %s %d should bot happen INVESTIGATE \n",__func__,__LINE__));
                    error = -EINVAL;
                    break;
            }
            break;
        default:
            eacs_trace(EACS_DBG_LVL0,(" %s %d should bot happen INVESTIGATE \n",__func__,__LINE__));
                error = -EINVAL;
                break;
    }
#undef NOISE_FLOOR_MAX
#undef NOISE_FLOOR_MIN
#undef MAX_COUNTER_THRESH
    return error;
}

int ieee80211_check_and_execute_pending_acsreport(wlan_if_t vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    ieee80211_acs_t acs = ic->ic_acs;
    u_int32_t status = EOK;

    if(true == acs->acs_scan_req_param.acs_scan_report_pending) {
        status = ieee80211_autoselect_infra_bss_channel(vap, true /* is_scan_report */);
        if(status!= EOK) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s %d Acs is active ,Can not execute acs report.\n",
                    __func__,__LINE__);
        }
    }
    acs->acs_scan_req_param.acs_scan_report_pending = false;
    return status;
}
/**
 * @brief to start acs scan report
 *
 * @param vap
 * @param set
 * @param cmd
 * @param val
 *
 * @return EOK in case of success
 */
int wlan_acs_start_scan_report(wlan_if_t vap, int set, int cmd, int val)
{
/* XXX tunables */
/* values used in scan state machines  HW_DEFAULT_REPEAT_PROBE_REQUEST_INTVAL*/
#define IEEE80211_MIN_DWELL 50
#define IEEE80211_MAX_DWELL 10000 /* values used in scan state machines in msec */
#define CHANNEL_LOAD_REQUESTED 2
    struct ieee80211com *ic = vap->iv_ic;
    unsigned int status = EOK;
    ieee80211_acs_t acs = ic->ic_acs;
    eacs_trace(EACS_DBG_LVL0,("Invoking ACS module for ACS report \n"));
    if(set) {
        switch(cmd)
        {
            case IEEE80211_START_ACS_REPORT:
                if(val)
                {
                    status = ieee80211_autoselect_infra_bss_channel(vap, true /* is_scan_report */);

                    if(status!= EOK) {
                        /* Bypassing failure for direct attach hardware as for direct
                           attach we are taking channel load directly from hardware

                           for failure cases */
                        if(val != CHANNEL_LOAD_REQUESTED) {
                        acs->acs_scan_req_param.acs_scan_report_pending = true;
                        eacs_trace(EACS_DBG_LVL0,("Acs is active ,acs report will be processed after acs is done \n"));
                     }
                    }
                    return status;
                }
                else
                    return -EINVAL;
                break;
            case IEEE80211_MIN_DWELL_ACS_REPORT:
                if(val > IEEE80211_MIN_DWELL)
                {
                    acs->acs_scan_req_param.mindwell = val;
                    return EOK;
                } else {
                    eacs_trace(EACS_DBG_LVL0,("Mindwell time must be greater than %dms \n",
					    IEEE80211_MIN_DWELL));
                    return -EINVAL;
		}
                break;
            case IEEE80211_MAX_DWELL_ACS_REPORT:
                if(val < IEEE80211_MAX_DWELL)
                {
                    if(acs->acs_scan_req_param.mindwell) {
                        if(val < acs->acs_scan_req_param.mindwell) {
                            eacs_trace(EACS_DBG_LVL0,("max dwell time %d less than min dwell %d\n",
						    val, acs->acs_scan_req_param.mindwell));
                            return -EINVAL;
                        }
                    }
                    acs->acs_scan_req_param.maxdwell = val;
                    return EOK;
                } else {
                    eacs_trace(EACS_DBG_LVL0,("max dwell time %d greater than %d\n", val,
					    IEEE80211_MAX_DWELL));
                    return -EINVAL;
                }
                break;
            case IEEE80211_SCAN_REST_TIME:
                if (val > 0) {
                    acs->acs_scan_req_param.rest_time = val;
                    return EOK;
                } else {
                    return -EINVAL;
                }
                break;
            case IEEE80211_SCAN_MODE:
                if ((val == IEEE80211_SCAN_PASSIVE) || (val == IEEE80211_SCAN_ACTIVE)) {
                    acs->acs_scan_req_param.scan_mode = val;
                    return EOK;
                } else {
                    return -EINVAL;
                }
                break;
            default :
                IEEE80211_DPRINTF(acs->acs_vap, IEEE80211_MSG_ACS,"Invalid parameter");
                return -EINVAL;
        }
    } else /*get part */
    {
        switch(cmd) {
            case IEEE80211_START_ACS_REPORT:
                val = acs->acs_scan_req_param.acs_scan_report_active;
                break;
            case IEEE80211_MIN_DWELL_ACS_REPORT:
                val = acs->acs_scan_req_param.mindwell;
                break;
            case IEEE80211_MAX_DWELL_ACS_REPORT:
                val = acs->acs_scan_req_param.maxdwell;
                break;
            default :
                IEEE80211_DPRINTF(acs->acs_vap, IEEE80211_MSG_ACS,"Invalid parameter");
                return -EINVAL;
        }
        return val;
    }
#undef IEEE80211_MIN_DWELL
#undef IEEE80211_MAX_DWELL
#undef CHANNEL_LOAD_REQUESTED
}

/**
 * @brief: Generates EACS report on request
 *
 * @param ic,
 *
 * @param acs_r, entry of debug stats
 *
 * @param internal, to know whether report is requested by EACS or other module
 *
 */
int ieee80211_acs_scan_report(struct ieee80211com *ic, struct ieee80211vap *vap, struct ieee80211_acs_dbg *acs_r, u_int8_t internal)
{
    ieee80211_acs_t acs = ic->ic_acs;
    struct ieee80211_channel *channel = NULL;
    u_int8_t i, ieee_chan;
    u_int16_t nchans;
    u_int16_t count;
    u_int8_t ssid_len;
    u_int8_t *ssid;
    u_int8_t *bssid;
    ieee80211_chan_neighbor_list *acs_neighbor_list = NULL;

    if(ieee80211_acs_in_progress(acs) && !internal) {
        eacs_trace(EACS_DBG_LVL0,("ACS scan is in progress, Please request for the report after a while... \n"));
        acs_r->nchans = 0;
        return 0;
    }

    if(acs->acs_run_incomplete) {
        eacs_trace(EACS_DBG_LVL0,("ACS run is cancelled, could be due to ICM or someother reason \n"));
        acs_r->nchans = 0;
        return 0;
    }

    acs_neighbor_list = (ieee80211_chan_neighbor_list*) OS_MALLOC(acs->acs_osdev,
            sizeof(ieee80211_chan_neighbor_list), 0);

    if (acs_neighbor_list) {
        OS_MEMZERO(acs_neighbor_list, sizeof(ieee80211_chan_neighbor_list));
    }
    else {
        qdf_print("%s: malloc failed \n",__func__);
        acs_r->nchans = 0;
        return 0;
    }

    nchans = (acs->acs_nchans_scan)?(acs->acs_nchans_scan):(acs->acs_nchans);

    /* For ACS Ranking, we need only the channels which have been analysed when
     * selecting the best channel */
    if (acs->acs_ranking) {
        nchans = acs->acs_nchans;
    }

    i = acs_r->entry_id;
    if(i >= nchans) {
        acs_r->nchans = 0;
        OS_FREE(acs_neighbor_list);
        return 0;
    }

    acs_r->nchans = nchans;
     /* If scan channel list is not generated by ACS,
         acs_chans[i] have all channels */
    if(acs->acs_nchans_scan == 0) {
       channel = acs->acs_chans[i];
       ieee_chan = ieee80211_chan2ieee(acs->acs_ic, channel);
       acs_r->chan_freq = ieee80211_chan2freq(acs->acs_ic, channel);
    } else {
       ieee_chan = acs->acs_ieee_chan[i];
       acs_r->chan_freq = ieee80211_ieee2mhz(ic, ieee_chan,0);
    }

    /* For ACS Ranking, we need only the channels which have been analysed when
     * selecting the best channel */
    if (acs->acs_ranking) {
       channel = acs->acs_chans[i];
       ieee_chan = ieee80211_chan2ieee(acs->acs_ic, channel);
       acs_r->chan_freq = ieee80211_chan2freq(acs->acs_ic, channel);
    }

    acs_r->ieee_chan = ieee_chan;
    acs_r->chan_nbss = acs->acs_chan_nbss[ieee_chan];
    acs_r->chan_maxrssi = acs->acs_chan_maxrssi[ieee_chan];
    acs_r->chan_minrssi = acs->acs_chan_minrssi[ieee_chan];
    acs_r->noisefloor = acs->acs_noisefloor[ieee_chan];
    acs_r->channel_loading = 0;   /*Spectral dependency from ACS is removed*/
    acs_r->chan_load = acs->acs_chan_load[ieee_chan];
    acs_r->sec_chan = acs->acs_sec_chan[ieee_chan];
    acs_r->chan_80211_b_duration = acs->acs_80211_b_duration[ieee_chan];

    /* For ACS channel Ranking, copy the rank and description */
    if (acs->acs_ranking) {
        acs_r->acs_rank.rank = acs->acs_rank[ieee_chan].rank;
        memcpy(acs_r->acs_rank.desc, acs->acs_rank[ieee_chan].desc, ACS_RANK_DESC_LEN);
    }

    acs_neighbor_list->acs = acs;
    acs_neighbor_list->chan = ieee_chan;

    wlan_scan_table_iterate(vap, ieee80211_get_chan_neighbor_list, (void *)acs_neighbor_list);

    /* coping the list of SSID in the channel */
    for (count = 0; count < acs_neighbor_list->nbss; count++) {
        ssid = acs_neighbor_list->neighbor_list[count].ssid;
        bssid = acs_neighbor_list->neighbor_list[count].bssid;
        ssid_len = strlen(ssid);
        memcpy(acs_r->neighbor_list[count].ssid, ssid, ssid_len+1);
        acs_r->neighbor_list[count].ssid_len = ssid_len;
        memcpy(acs_r->neighbor_list[count].bssid, bssid, IEEE80211_ADDR_LEN);
        acs_r->neighbor_list[count].rssi = acs_neighbor_list->neighbor_list[count].rssi;
        acs_r->neighbor_list[count].phymode = acs_neighbor_list->neighbor_list[count].phymode;
    }

    OS_FREE(acs_neighbor_list);
    return 0;
}

/**
 * @brief: Displays ACS statistics
 *
 * @param ic
 *
 */
static void ieee80211_acs_scan_report_internal(struct ieee80211com *ic)
{
    struct ieee80211_acs_dbg *acs_dbg;
    ieee80211_acs_t acs = ic->ic_acs;
    u_int8_t i;

    acs_dbg = (struct ieee80211_acs_dbg *) OS_MALLOC(acs->acs_osdev,
                        sizeof(struct ieee80211_acs_dbg), 0);

    if (acs_dbg) {
        OS_MEMZERO(acs_dbg, sizeof(struct ieee80211_acs_dbg));
    }
    else {
        qdf_print("%s: malloc failed \n",__func__);
        return;
    }

    /* output the current configuration */
    i = 0;
    do {
        acs_dbg->entry_id = i;

        ieee80211_acs_scan_report(ic, acs->acs_vap, acs_dbg, 1);
        if((acs_dbg->nchans) && (i == 0)) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "******** ACS report ******** \n");
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " Channel | BSS  | minrssi | maxrssi | NF | Ch load | spect load | sec_chan \n");
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "---------------------------------------------------------------------\n");
        } else if(acs_dbg->nchans == 0) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Failed to print ACS scan report\n");
            break;
        }
        /*To make sure we are not getting more than 100 %*/
        if(acs_dbg->chan_load  > 100)
            acs_dbg->chan_load = 100;

        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %4d(%3d) %4d     %4d      %4d   %4d    %4d        %4d       %4d   \n",
                acs_dbg->chan_freq,
                acs_dbg->ieee_chan,
                acs_dbg->chan_nbss,
                acs_dbg->chan_minrssi,
                acs_dbg->chan_maxrssi,
                acs_dbg->noisefloor,
                acs_dbg->chan_load,
                acs_dbg->channel_loading,
                acs_dbg->sec_chan);
       i++;
    } while(i < acs_dbg->nchans);
    OS_FREE(acs_dbg);

}

/**
 * @brief: Invoke EACS report handler, it acts as inteface for other modules
 *
 * @param vap,
 *
 * @param acs_rp, entry of debug stats
 *
 */
int wlan_acs_scan_report(wlan_if_t vaphandle,void *acs_rp)
{
    struct ieee80211_acs_dbg *acs_r = (struct ieee80211_acs_dbg *)acs_rp;
    return ieee80211_acs_scan_report(vaphandle->iv_ic, vaphandle, acs_r, 0);
}


/**
 * @brief api to set blocked channel list
 *
 * @param vap
 * @param param :- channel to block
 * @param number of channels
 * @return status code
 */
int wlan_acs_block_channel_list(wlan_if_t vap,u_int8_t *chan,u_int8_t nchan)
{
#define FLUSH_LIST 0
    int i = 0;
    acs_bchan_list_t *bchan = NULL;
    struct ieee80211com *ic = vap->iv_ic;
    ieee80211_acs_t acs = ic->ic_acs;

    if(NULL == chan)
        return -ENOSPC;

    bchan = &(acs->acs_bchan_list);

    if(FLUSH_LIST == chan[0])
    {
        OS_MEMZERO(&(bchan->uchan[0]),bchan->uchan_cnt);
        bchan->uchan_cnt = 0;
        return 0;
    }
    else {
        while(i < nchan) {
            bchan->uchan[bchan->uchan_cnt] = chan[i];
            bchan->uchan_cnt++;
            i++;
        }
    }

    bchan->uchan_cnt %= IEEE80211_CHAN_MAX;
    return 0;
#undef FLUSH_LIST
}

#if ATH_CHANNEL_BLOCKING
struct ieee80211_channel *
wlan_acs_channel_allowed(wlan_if_t vap, struct ieee80211_channel *c, enum ieee80211_phymode mode)
{
    struct ieee80211com *ic = vap->iv_ic;
    ieee80211_acs_t acs = ic->ic_acs;
    struct ieee80211_channel *channel;
    int i, j, n_modes, extchan, blocked;
    struct ieee80211_channel_list chan_info;
    enum ieee80211_phymode modes[6];

    if (!(acs->acs_block_mode & ACS_BLOCK_MANUAL))
        return c;

    /* real phymode */
    if (mode == IEEE80211_MODE_AUTO) {
        modes[0] = IEEE80211_MODE_11AC_VHT20;
        modes[1] = IEEE80211_MODE_11NG_HT20;
        modes[2] = IEEE80211_MODE_11NA_HT20;
        modes[3] = IEEE80211_MODE_11G;
        modes[4] = IEEE80211_MODE_11A;
        modes[5] = IEEE80211_MODE_11B;
        n_modes = 6;
    } else if (mode == IEEE80211_MODE_11NG_HT40) {
        modes[0] = IEEE80211_MODE_11NG_HT40PLUS;
        modes[1] = IEEE80211_MODE_11NG_HT40MINUS;
        n_modes = 2;
    } else if (mode == IEEE80211_MODE_11NA_HT40) {
        modes[0] = IEEE80211_MODE_11NA_HT40PLUS;
        modes[1] = IEEE80211_MODE_11NA_HT40MINUS;
        n_modes = 2;
    } else if (mode == IEEE80211_MODE_11AC_VHT40) {
        modes[0] = IEEE80211_MODE_11AC_VHT40PLUS;
        modes[1] = IEEE80211_MODE_11AC_VHT40MINUS;
        n_modes = 2;
    } else {
        modes[0] = mode;
        n_modes = 1;
    }

    for (j = 0; j < n_modes; j++) {
        blocked = 0;
        ieee80211_enumerate_channels(channel, ic, i) {
            u_int8_t ieee_chan_num = ieee80211_chan2ieee(ic, channel);
            u_int8_t ieee_ext_chan_num;

            if (ieee80211_chan2mode(channel) != modes[j]) {
                eacs_trace(EACS_DBG_LVL0, ("channel %d mode %d not equal mode %d\n",
                            ieee_chan_num, ieee80211_chan2mode(channel), modes[j]));
                continue; /* next channel */
            }

            if (ieee_chan_num != ieee80211_chan2ieee(ic, c)) {
                eacs_trace(EACS_DBG_LVL0, ("channel %d mode %d not equal "
                            "channel %d\n", ieee_chan_num, modes[j], ieee80211_chan2ieee(ic, c)));
                continue; /* next channel */
            }

            /* channel is blocked as per user setting */
            if (acs_is_channel_blocked(acs, ieee_chan_num)) {
                eacs_trace(EACS_DBG_BLOCK, ("Channel %d is blocked, in mode %d\n", ieee_chan_num, modes[j]));
                blocked = 1;
                break; /* next phymode */
            }

            ieee80211_get_extchaninfo(ic, channel, &chan_info);

            for (extchan = 0; extchan < chan_info.cl_nchans; extchan++) {
                if (chan_info.cl_channels[extchan] == NULL) {
                    if(ieee80211_is_extchan_144(acs->acs_ic,channel, extchan)) {
                         continue;
                    }
                    eacs_trace(EACS_DBG_LVL0, ("Rejecting Channel for ext channel found null "
                                "channel number %d EXT channel %d found %d\n", ieee_chan_num, extchan,
                                (int)chan_info.cl_channels[extchan]));
                    blocked = 1;
                    break;
                }

                /* extension channel (in NAHT40/ACVHT40/ACVHT80 mode) is blocked as per user setting */
                if (acs->acs_block_mode & ACS_BLOCK_EXTENSION) {
                    ieee_ext_chan_num = ieee80211_chan2ieee(ic, chan_info.cl_channels[extchan]);
                    if (acs_is_channel_blocked(acs, ieee_ext_chan_num)) {
                        eacs_trace(EACS_DBG_BLOCK, ("Channel %d can't be used, as ext channel %d "
                                    "is blocked, in mode %d\n", ieee_chan_num, ieee_ext_chan_num, modes[j]));
                        blocked = 1;
                        break;
                    }
                }
            }

            if (blocked)
                break; /* next phymode */

            /* in 2.4GHz band checking channels overlapping with primary,
             * or if required with secondary too (NGHT40 mode) */
            if ((acs->acs_block_mode & ACS_BLOCK_EXTENSION) && IEEE80211_IS_CHAN_2GHZ(channel)) {
                struct ieee80211_channel *ext_chan;
                int start = channel->ic_freq - 15, end = channel->ic_freq + 15, f;
                if (IEEE80211_IS_CHAN_11NG_HT40PLUS(channel))
                    end = channel->ic_freq + 35;
                if (IEEE80211_IS_CHAN_11NG_HT40MINUS(channel))
                    start = channel->ic_freq - 35;
                for (f = start; f <= end; f += 5) {
                    ext_chan = ic->ic_find_channel(ic, f, 0, IEEE80211_CHAN_B);
                    if (ext_chan) {
                        ieee_ext_chan_num = ieee80211_chan2ieee(ic, ext_chan);
                        if (acs_is_channel_blocked(acs, ieee_ext_chan_num)) {
                            eacs_trace(EACS_DBG_BLOCK, ("Channel %d can't be used, as ext "
                                        "or overlapping channel %d is blocked, in mode %d\n",
                                        ieee_chan_num, ieee_ext_chan_num, modes[j]));
                            blocked = 1;
                            break;
                        }
                    }
                }
            }

            if (blocked)
                break; /* next phymode */

            /* channel is allowed in this phymode */
            if (c != channel) {
                eacs_trace(EACS_DBG_BLOCK, ("channel %d phymode %d instead of channel %d phymode %d\n",
                            ieee80211_chan2ieee(ic, channel), ieee80211_chan2mode(channel),
                            ieee80211_chan2ieee(ic, c), ieee80211_chan2mode(c)));
            }
            return channel;
        }
    }

    return NULL;
}
#endif

#if ATH_ACS_SUPPORT_SPECTRAL && ATH_SUPPORT_SPECTRAL

/*
 * Function     : update_eacs_avg_rssi
 * Description  : Update average RSSI
 * Input        : Pointer to acs struct
                   nfc_ctl_rssi  - control chan rssi
                   nfc_ext_rssi  - extension chan rssi
 * Output       : Noisefloor
 *
 */
static void update_eacs_avg_rssi(ieee80211_acs_t acs, int8_t nfc_ctl_rssi, int8_t nfc_ext_rssi)
{
    int temp=0;

    if(acs->acs_ic->ic_cwm_get_width(acs->acs_ic) == IEEE80211_CWM_WIDTH40) {
        // HT40 mode
        temp = (acs->ext_eacs_avg_rssi * (acs->ext_eacs_spectral_reports));
        temp += nfc_ext_rssi;
        acs->ext_eacs_spectral_reports++;
        acs->ext_eacs_avg_rssi = (temp / acs->ext_eacs_spectral_reports);
    }


    temp = (acs->ctl_eacs_avg_rssi * (acs->ctl_eacs_spectral_reports));
    temp += nfc_ctl_rssi;

    acs->ctl_eacs_spectral_reports++;
    acs->ctl_eacs_avg_rssi = (temp / acs->ctl_eacs_spectral_reports);
}


/*
 * Function     : update EACS Thresholds
 * Description  : Updates EACS Thresholds
 * Input        : Pointer to acs struct
                  ctl_nf - control chan nf
                  ext_nf  - extension chan rs
 * Output       : void
 *
 */
void update_eacs_thresholds(ieee80211_acs_t acs,int8_t ctrl_nf,int8_t ext_nf)
{

    acs->ctl_eacs_rssi_thresh = ctrl_nf + 10;

    if (acs->acs_ic->ic_cwm_get_width(acs->acs_ic) == IEEE80211_CWM_WIDTH40) {
        acs->ext_eacs_rssi_thresh = ext_nf + 10;
    }

    acs->ctl_eacs_rssi_thresh = 32;
    acs->ext_eacs_rssi_thresh = 32;
}

/*
 * Function     : ieee80211_update_eacs_counters
 * Description  : Update EACS counters
 * Input        : Pointer to ic struct
                  nfc_ctl_rssi  - control chan rssi
                  nfc_ext_rssi  - extension chan rssi
                  ctl_nf - control chan nf
                  ext_nf  - extension chan rs
 * Output       : Noisefloor
 *
 */
void ieee80211_update_eacs_counters(struct ieee80211com *ic, int8_t nfc_ctl_rssi,
        int8_t nfc_ext_rssi,int8_t ctrl_nf, int8_t ext_nf)
{
    ieee80211_acs_t acs = ic->ic_acs;


    if(!ieee80211_acs_in_progress(acs)) {
        return;
    }
    acs->eacs_this_scan_spectral_data++;
    update_eacs_thresholds(acs,ctrl_nf,ext_nf);
    update_eacs_avg_rssi(acs, nfc_ctl_rssi, nfc_ext_rssi);

    if (ic->ic_cwm_get_width(ic) == IEEE80211_CWM_WIDTH40) {
        // HT40 mode
        if (nfc_ext_rssi > acs->ext_eacs_rssi_thresh){
            acs->ext_eacs_interf_count++;
        }
        acs->ext_eacs_duty_cycle=((acs->ext_eacs_interf_count * 100)/acs->eacs_this_scan_spectral_data);
    }
    if (nfc_ctl_rssi > acs->ctl_eacs_rssi_thresh){
        acs->ctl_eacs_interf_count++;
    }

    acs->ctl_eacs_duty_cycle=((acs->ctl_eacs_interf_count * 100)/acs->eacs_this_scan_spectral_data);
#if DEBUG_EACS
    if(acs->ctl_eacs_interf_count > acs->eacs_this_scan_spectral_data) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "eacs interf count is greater than spectral samples %d:%d \n",
                acs->ctl_eacs_interf_count,acs->eacs_this_scan_spectral_data);
    }
#endif
}

/*
 * Function     : get_eacs_control_duty_cycle
 * Description  : Get EACS control duty cycle
 * Input        : Pointer to acs Struct
 * Output       : Duty Cycle
 *
 */
int get_eacs_control_duty_cycle(ieee80211_acs_t acs)
{
    return acs->ctl_eacs_duty_cycle;
}

/* Function     : get_eacs_extension_duty_cycle
 * Description  : Get EACS extension duty cycle
 * Input        : Pointer to  acs struct
 * Output       : Duty Cycle
 *
 */
int get_eacs_extension_duty_cycle(ieee80211_acs_t acs)
{
    return acs->ext_eacs_duty_cycle;
}

/*
 * Function     : print_chan_loading_details
 * Description  : Debug function to print channel loading information
 * Input        : Pointer to ic
 * Output       : void
 *
 */
static void print_chan_loading_details(struct ieee80211com *ic)
{
    ieee80211_acs_t acs = ic->ic_acs;
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ctl_chan_freq       = %d\n",acs->ctl_chan_frequency);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ctl_interf_count    = %d\n",acs->ctl_eacs_interf_count);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ctl_duty_cycle      = %d\n",acs->ctl_eacs_duty_cycle);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ctl_chan_loading    = %d\n",acs->ctl_chan_loading);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ctl_nf              = %d\n",acs->ctl_chan_noise_floor);

    if (ic->ic_cwm_get_width(ic) == IEEE80211_CWM_WIDTH40) {
        // HT40 mode
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ext_chan_freq       = %d\n",acs->ext_chan_frequency);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ext_interf_count    = %d\n",acs->ext_eacs_interf_count);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ext_duty_cycle      = %d\n",acs->ext_eacs_duty_cycle);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ext_chan_loading    = %d\n",acs->ext_chan_loading);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ext_nf              = %d\n",acs->ext_chan_noise_floor);
    }

    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s this_scan_spectral_data count = %d\n", __func__, acs->eacs_this_scan_spectral_data);
}



/*
 * Function     : ieee80211_init_spectral_chan_loading
 * Description  : Initializes Channel loading information
 * Input        : Pointer to ic
                  current_channel - control channel freq
                  ext_channel - extension channel freq
 * Output       : void
 *
 */
void ieee80211_init_spectral_chan_loading(struct ieee80211com *ic,
        int current_channel, int ext_channel)
{

    ieee80211_acs_t acs = ic->ic_acs;

    if(!ieee80211_acs_in_progress(acs)) {
        return;
    }
    if ((current_channel == 0) && (ext_channel == 0)) {
        return;
    }
    /* Check if channel change has happened in this reset */
    if(acs->ctl_chan_frequency != current_channel) {
        /* If needed, check the channel loading details
        * print_chan_loading_details(spectral);
         */
        acs->eacs_this_scan_spectral_data = 0;

        if (ic->ic_cwm_get_width(ic) == IEEE80211_CWM_WIDTH40) {
            // HT40 mode
            acs->ext_eacs_interf_count = 0;
            acs->ext_eacs_duty_cycle   = 0;
            acs->ext_chan_loading      = 0;
            acs->ext_chan_noise_floor  = 0;
            acs->ext_chan_frequency    = ext_channel;
        }

        acs->ctl_eacs_interf_count = 0;
        acs->ctl_eacs_duty_cycle   = 0;
        acs->ctl_chan_loading      = 0;
        acs->ctl_chan_noise_floor  = 0;
        acs->ctl_chan_frequency    = current_channel;

        acs->ctl_eacs_rssi_thresh = SPECTRAL_EACS_RSSI_THRESH;
        acs->ext_eacs_rssi_thresh = SPECTRAL_EACS_RSSI_THRESH;

        acs->ctl_eacs_avg_rssi = SPECTRAL_EACS_RSSI_THRESH;
        acs->ext_eacs_avg_rssi = SPECTRAL_EACS_RSSI_THRESH;

        acs->ctl_eacs_spectral_reports = 0;
        acs->ext_eacs_spectral_reports = 0;

    }

}

/*
 * Function     : ieee80211_get_spectral_freq_loading
 * Description  : Get EACS control duty cycle
 * Input        : Pointer to ic
 * Output       : Duty Cycle
 *
 */

int ieee80211_get_spectral_freq_loading(struct ieee80211com *ic)
{
    ieee80211_acs_t acs = ic->ic_acs;
    int duty_cycles;
    duty_cycles = ((acs->ctl_eacs_duty_cycle > acs->ext_eacs_duty_cycle) ?
            acs->ctl_eacs_duty_cycle :
            acs->ext_eacs_duty_cycle);
    return duty_cycles;
}
#endif

#else
int wlan_autoselect_register_event_handler(wlan_if_t                    vaphandle,
        ieee80211_acs_event_handler evhandler,
        void                         *arg)
{
    return EPERM;
}

int wlan_autoselect_unregister_event_handler(wlan_if_t                    vaphandle,
        ieee80211_acs_event_handler evhandler,
        void                         *arg)
{
    return EPERM;
}

int wlan_autoselect_in_progress(wlan_if_t vaphandle)
{
    return 0;
}

int wlan_autoselect_find_infra_bss_channel(wlan_if_t             vaphandle)
{
    return EPERM;
}

int wlan_attempt_ht40_bss(wlan_if_t             vaphandle)
{
    return EPERM;
}

int wlan_acs_find_best_channel(struct ieee80211vap *vap, int *bestfreq, int num){

    return EINVAL;
}

int wlan_autoselect_cancel_selection(wlan_if_t vaphandle)
{
   return 0;
}
/**
 * @brief api to set blocked channel list
 *
 * @param vap
 * @param param :- channel to block
 * @param number of channels
 *
 * @return 0 for all cases
 */
int wlan_acs_block_channel_list(wlan_if_t vap,u_int8_t *chan,u_int8_t nchan)
{
    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ACS is not enabled\n");
    return EPERM;
}

#if ATH_CHANNEL_BLOCKING
struct ieee80211_channel *
wlan_acs_channel_allowed(wlan_if_t vap, struct ieee80211_channel * c, enum ieee80211_phymode mode)
{
    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ACS is not enabled\n");
    return c;
}
#endif

int wlan_acs_scan_report(wlan_if_t vaphandle, void *acs_rp)
{
    struct ieee80211_acs_dbg *acs_r = (struct ieee80211_acs_dbg *)acs_rp;
    acs_r->nchans = 0;
    QDF_PRINT_INFO(vaphandle->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ACS is not enabled\n");
    return EPERM;
}
int wlan_autoselect_register_scantimer_handler(void * arg ,
        ieee80211_acs_scantimer_handler  evhandler,
        void                          *arg2)
    QDF_PRINT_INFO(vaphandle->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ACS not enabled \n");
    return EINVAL;
    }
#undef DEBUG_EACS
#endif

