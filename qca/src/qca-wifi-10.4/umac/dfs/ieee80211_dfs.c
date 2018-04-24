/*-
 * Copyright (c) 2007-2008 Sam Leffler, Errno Consulting
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

//#include <sys/cdefs.h>

#include <ieee80211_var.h>
#include <ieee80211_regdmn.h>
#include "ieee80211_sme_api.h"
#include <ieee80211_channel.h>
#include <ath_internal.h>
#include "if_athvar.h"
#include <dfs.h>

#if ATH_SUPPORT_DFS
static	int ieee80211_nol_timeout = 30*60;		/* 30 minutes */
#define	NOL_TIMEOUT	(ieee80211_nol_timeout*1000)
#define IS_CHANNEL_WEATHER_RADAR(freq) ((freq >= 5600) && (freq <= 5650))
#define ADJACENT_WEATHER_RADAR_CHANNEL   5580
#define CH100_START_FREQ                 5490
#define CH100                            100

static	int ieee80211_cac_timeout = 62;		/* 60+2 seconds. Extra 2 Second to take care of external test house setup issue*/

/* CAC in weather channel is 600 sec. However there are times when we boot up 12 sec faster in weather channel */

static	int ieee80211_cac_weather_timeout = 612;	/* 10 minutes plus 12 sec */

static int
null_set_quiet(struct ieee80211_node *ni, u_int8_t *quiet_elm)
{
	return -1;
}

/*
 * Override the default CAC timeout.
 *
 * A cac_timeout of -1 means "don't override the default".
 *
 * This is primarily for debugging.
 */
int
ieee80211_dfs_override_cac_timeout(struct ieee80211com *ic, int cac_timeout)
{
	struct ieee80211_dfs_state *dfs = &ic->ic_dfs_state;

	if (dfs == NULL)
		return (-EIO);

	dfs->cac_timeout_override = cac_timeout;
	qdf_print("%s: CAC timeout is now %s (%d)\n",
	    __func__,
	    (cac_timeout == -1) ? "default" : "overridden",
	    cac_timeout);

	return (0);
}

#if ATH_SUPPORT_ZERO_CAC_DFS
/*
 * Override the default PreCAC timeout.
 *
 * A precac_timeout of -1 means "don't override the default".
 *
 * This is primarily for debugging.
 */
/* TODO XXX: change precac_timeout variable name */
int
ieee80211_dfs_override_precac_timeout(struct ieee80211com *ic, int precac_timeout)
{
	struct ieee80211_dfs_state *dfs = &ic->ic_dfs_state;

	if (dfs == NULL)
		return (-EIO);

	dfs->precac_timeout_override = precac_timeout;
	qdf_print("%s: PreCAC timeout is now %s (%d)\n",
	    __func__,
	    (precac_timeout == -1) ? "default" : "overridden",
	    precac_timeout);

	return (0);
}
#endif

int
ieee80211_dfs_get_override_cac_timeout(struct ieee80211com *ic,
    int *cac_timeout)
{
	struct ieee80211_dfs_state *dfs = &ic->ic_dfs_state;

	if (dfs == NULL)
		return (-EIO);

	(*cac_timeout) = dfs->cac_timeout_override;

	return (0);
}

#if ATH_SUPPORT_ZERO_CAC_DFS
int
ieee80211_dfs_get_override_precac_timeout(struct ieee80211com *ic,
    int *precac_timeout)
{
	struct ieee80211_dfs_state *dfs = &ic->ic_dfs_state;

	if (dfs == NULL)
		return (-EIO);

	(*precac_timeout) = dfs->precac_timeout_override;

	return (0);
}

#define VHT80_OFFSET 6
#define IS_WITHIN_RANGE(_A,_B,_C)  (((_A)>=((_B)-(_C))) && ((_A)<=((_B)+(_C))))
bool
ieee80211_dfs_is_ht20_40_80_chan_in_precac_done_list(struct ieee80211com *ic)
{
    struct ieee80211_dfs_state *dfs = &ic->ic_dfs_state;
    struct ieee80211_precac_entry *precac_entry;
    bool ret_val = 0;

    /*  A is within B-C and B+C
     *  (B-C) <= A <= (B+C)
     */
    PRECAC_LIST_LOCK(ic);
    if (!TAILQ_EMPTY(&dfs->precac_done_list))
        TAILQ_FOREACH(precac_entry,&dfs->precac_done_list,pe_list) {
            /* Find if the VHT80 freq1 is in Pre-CAC done list */
            /* TODO xxx need to replace 6 by a macro */
            if(IS_WITHIN_RANGE(ic->ic_curchan->ic_ieee,precac_entry->vht80_freq,VHT80_OFFSET)) {
                ret_val = 1;
                break;
            }
        }
    PRECAC_LIST_UNLOCK(ic);

    IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_DFS,
            "%s : %d vht80_freq = %u ret_val = %d\n", __func__,__LINE__,ic->ic_curchan->ic_ieee, ret_val);
    return ret_val;
}

bool
ieee80211_dfs_is_ht80_80_chan_in_precac_done_list(struct ieee80211com *ic)
{
    struct ieee80211_dfs_state *dfs = &ic->ic_dfs_state;
    struct ieee80211_precac_entry *precac_entry;
    bool ret_val = 0;

    PRECAC_LIST_LOCK(ic);
    if (!TAILQ_EMPTY(&dfs->precac_done_list)) {
        bool primary_found = 0;
        /* Check if primary is DFS then search */
        if (IEEE80211_IS_CHAN_DFS(ic->ic_curchan)) {
            TAILQ_FOREACH(precac_entry,&dfs->precac_done_list,pe_list) {
                if(ic->ic_curchan->ic_vhtop_ch_freq_seg1 == precac_entry->vht80_freq) {
                    primary_found = 1;
                    break;
                }
            }
        } else {
            primary_found = 1;
        }

        /* Check if secondary DFS then search */
        if(IEEE80211_IS_CHAN_DFS_CFREQ2(ic->ic_curchan) && primary_found) {
            TAILQ_FOREACH(precac_entry,&dfs->precac_done_list,pe_list) {
                if(ic->ic_curchan->ic_vhtop_ch_freq_seg2 == precac_entry->vht80_freq) {
                    /* Now secondary also found */
                    ret_val = 1;
                    break;
                }
            }
        } else {
            if (primary_found) {
                ret_val = 1;
            }
        }
    }
    PRECAC_LIST_UNLOCK(ic);

    IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_DFS, "%s : %d freq_seg1 = %u "
            "freq_seq2 = %u ret_val = %d\n", __func__,__LINE__,
            ic->ic_curchan->ic_vhtop_ch_freq_seg1,ic->ic_curchan->ic_vhtop_ch_freq_seg2);
    return ret_val;
}

bool
ieee80211_dfs_is_precac_done(struct ieee80211com *ic)
{
    bool ret_val = 0;

    if(IEEE80211_IS_CHAN_11AC_VHT20(ic->ic_curchan) ||
            IEEE80211_IS_CHAN_11AC_VHT40(ic->ic_curchan) ||
            IEEE80211_IS_CHAN_11AC_VHT80(ic->ic_curchan)) {
        ret_val = ieee80211_dfs_is_ht20_40_80_chan_in_precac_done_list(ic);
    }
    else if(IEEE80211_IS_CHAN_11AC_VHT80_80(ic->ic_curchan) || IEEE80211_IS_CHAN_11AC_VHT160(ic->ic_curchan)) {
        ret_val = ieee80211_dfs_is_ht80_80_chan_in_precac_done_list(ic);
    }

    IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_DFS, "%s : %d ret_val = %d\n", __func__,__LINE__, ret_val);
    return ret_val;
}
#endif

/*
 * Return the CAC timeout for the given channel.
 */
int
ieee80211_get_cac_timeout(struct ieee80211com *ic,
    struct ieee80211_channel *chan)
{
    struct ieee80211_dfs_state *dfs = &ic->ic_dfs_state;

    if (dfs == NULL)
    	return (0);

    if (dfs->cac_timeout_override != -1)
	return (dfs->cac_timeout_override);

    if (ic->ic_get_dfsdomain(ic) == DFS_ETSI_DOMAIN) {
        struct ieee80211_channel_list chan_info;
        int i;
        ic->ic_get_ext_chan_info (ic, chan, &chan_info);
        for (i = 0; i < chan_info.cl_nchans; i++) {
            if((NULL != chan_info.cl_channels[i])&&(ieee80211_check_weather_radar_channel(chan_info.cl_channels[i]))) {
                return (ieee80211_cac_weather_timeout);
            }
        }
    }
    return (ieee80211_cac_timeout);
}

void
ieee80211_dfs_detach(struct ieee80211com *ic)
{
    struct ieee80211_dfs_state *dfs = &ic->ic_dfs_state;

    if (!dfs->enable)
        return;
    dfs->enable = 0;

	/* NB: we assume no locking is needed */
	ieee80211_dfs_reset(ic);
#if ATH_SUPPORT_ZERO_CAC_DFS
	ieee80211_dfs_deinit_precac_list(ic);
#endif
}


/*
 * This function is supposed to be called only on detach and regulatory
 * domain changes.  It isn't a generic state machine change.
 * In particular, the CAC timer should be reset via another method.
 */
void
ieee80211_dfs_reset(struct ieee80211com *ic)
{
	struct ieee80211_dfs_state *dfs = &ic->ic_dfs_state;

	/* NB: we assume no locking is needed */
	/* NB: cac_timer should be cleared by the state machine */
	OS_CANCEL_TIMER(&dfs->cac_timer);
    qdf_flush_work(NULL,&ic->dfs_cac_timer_start_work);
    qdf_disable_work(NULL,&ic->dfs_cac_timer_start_work);
	/* XXX clear the NOL timer? */
#if 0 /* AP: Not needed */
	for (i = 0; i < ic->ic_nchans; i++)
		ic->ic_channels[i].ic_state = 0;
#endif
    dfs->lastchan = NULL;
    dfs->cac_timeout_override = -1;
#if ATH_SUPPORT_ZERO_CAC_DFS
    dfs->precac_timeout_override = -1;
    OS_CANCEL_TIMER(&dfs->precac_timer);
    ic->ic_precac_primary_freq = 0;
    ic->ic_precac_secondary_freq = 0;
#endif
}
static void
ath_vap_iter_cac(void *arg, wlan_if_t vap)
{
    //struct ieee80211vap *vap = arg;
    struct ieee80211com *ic = vap->iv_ic;
    if (vap->iv_state_info.iv_state != IEEE80211_S_DFS_WAIT)
		return;

    if (ic->ic_nl_handle)
        return;

    /* Radar Detected */
    if (IEEE80211_IS_CHAN_RADAR(ic->ic_curchan)) {
        ieee80211_state_event(vap, IEEE80211_STATE_EVENT_UP);
    } else {
        ieee80211_state_event(vap, IEEE80211_STATE_EVENT_DFS_CLEAR);
    }
}

static void
ieee80211_dfs_proc_cac(struct ieee80211com *ic)
{

    wlan_iterate_vap_list(ic, ath_vap_iter_cac, NULL);
}

/* This function resets 'cac_valid' bit.
 * Incase of change in channel attributes or channel number,
 * CAC need to be performed unconditionally & hence the reset.
 * Skip the logic if cac_valid_time is not set by the user.
 */
void
ieee80211_dfs_cac_valid_reset(struct ieee80211com *ic)
{
    	struct ieee80211_dfs_state *dfs = &ic->ic_dfs_state;

	if (dfs->curchan && (dfs->curchan->ic_ieee == ic->ic_curchan->ic_ieee)) {
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, 
                       "dfs : already in same channel , bypassing CAC %d \n", dfs->curchan->ic_ieee);
		dfs->cac_valid = 1;
		dfs->curchan = NULL;
		return;
	}

    	if(dfs->cac_valid_time && ic->ic_prevchan && ic->ic_curchan)
    	{
    		if( (ic->ic_prevchan->ic_ieee !=ic->ic_curchan->ic_ieee) ||
		    (ic->ic_prevchan->ic_flags !=ic->ic_curchan->ic_flags) ) {
			QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Cancelling timer & clearing cac_valid\n\r");
			OS_CANCEL_TIMER(&dfs->cac_valid_timer);
			dfs->cac_valid = 0;
		}
	}

	/*
	 * if cac_valid_time was not configured by user,
	 * reset the cac_valid, previously set because of returning from recovery
	 */
	if(!dfs->cac_valid_time)  {
		dfs->cac_valid = 0;
	}
}

/*update the bss channel info on all vaps */
static void ieee80211_vap_iter_update_bss_chan(void *arg, struct ieee80211vap *vap)
{
      struct ieee80211_channel *bsschan = (struct ieee80211_channel *) arg;

      vap->iv_bsschan = bsschan;

      /* we may change from VHT160 to VHT80_80 under some condition */
      /* ias we have only two channels and both are DFS.            */
      /* for HT80_80 mode we may switch to VHT80 mode when we have  */
      /* two 5G radios in a sysems and to avoid interfernce we may  */
      /* confine them to a limited number of channels.              */

      if (IEEE80211_IS_CHAN_11AC_VHT160(bsschan)) {
          vap->iv_des_mode   = IEEE80211_MODE_11AC_VHT160;
      } else if (IEEE80211_IS_CHAN_11AC_VHT80_80(bsschan)) {
          vap->iv_des_mode   = IEEE80211_MODE_11AC_VHT80_80;
          vap->iv_des_cfreq2 =  bsschan->ic_vhtop_ch_freq_seg2;
      } else if (IEEE80211_IS_CHAN_11AC_VHT80(bsschan)) {
          vap->iv_des_mode   = IEEE80211_MODE_11AC_VHT80;
      }


      if(vap->iv_bss)
      {
          vap->iv_bss->ni_chan = bsschan;
          vap->iv_des_chan[vap->iv_des_mode] = bsschan;
      }
}

/*
 * Fetch a mute test channel which matches the operational mode/flags of the
 * current channel.
 *
 * Simply returning '36' when the AP is in HT40D mode will fail; the channel
 * lookup will be done with the channel flags requiring HT40D and said lookup
 * won't find a channel.
 *
 * XXX TODO: figure out the correct mute channel to return for VHT operation.
 *   It may be that we instead have to return the actual full VHT channel
 *   configuration (freq1, freq2, legacy ctl/ext info) when it's time to do
 *   this.
 */
static int
ieee80211_get_test_mute_chan(struct ieee80211com *ic,
  const struct ieee80211_channel *chan)
{
    if (chan == NULL)
        return IEEE80211_RADAR_TEST_MUTE_CHAN_11A;

    if (IEEE80211_IS_CHAN_VHT(chan))
        qdf_print("%s: VHT not yet supported here (please fix); "
          "freq=%d, flags=0x%08x, "
          "falling through\n",
          __func__, chan->ic_freq, chan->ic_flags);

    if (IEEE80211_IS_CHAN_11N_HT40MINUS(chan))
        return IEEE80211_RADAR_TEST_MUTE_CHAN_11NHT40D;
    else if (IEEE80211_IS_CHAN_11N_HT40PLUS(chan))
        return IEEE80211_RADAR_TEST_MUTE_CHAN_11NHT40U;
    else if (IEEE80211_IS_CHAN_11N_HT20(chan))
        return IEEE80211_RADAR_TEST_MUTE_CHAN_11NHT20;
    else if (IEEE80211_IS_CHAN_A(chan))
        return IEEE80211_RADAR_TEST_MUTE_CHAN_11A;
    else {
        qdf_print("%s: unknown channel mode, freq=%d, flags=0x%08x\n",
          __func__, chan->ic_freq, chan->ic_flags);
        return IEEE80211_RADAR_TEST_MUTE_CHAN_11A;
    }
}

#if ATH_SUPPORT_IBSS_DFS
void ieee80211_ibss_beacon_update_start(struct ieee80211com *ic)
{
    if (!ic->ic_is_mode_offload(ic)) {
        struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
        scn->sc_ops->ath_ibss_beacon_update_start(scn->sc_dev);
    } else {
        /* TBD */
    }

}

void ieee80211_ibss_beacon_update_stop(struct ieee80211com *ic)
{
    if (!ic->ic_is_mode_offload(ic)) {
        struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
        scn->sc_ops->ath_ibss_beacon_update_stop(scn->sc_dev);
    } else {
        /* TBD */
    }

}

#define IEEE80211_MODE_TURBO_STATIC_A   IEEE80211_MODE_MAX
static int
ieee80211_check_mode_consistency(struct ieee80211com *ic,int mode,struct ieee80211_channel *c)
{
    if (c == IEEE80211_CHAN_ANYC) return 0;
    switch (mode)
    {
    case IEEE80211_MODE_11B:
        if(IEEE80211_IS_CHAN_B(c))
            return 0;
        else
            return 1;
        break;

    case IEEE80211_MODE_11G:
        if(IEEE80211_IS_CHAN_ANYG(c))
            return 0;
        else
            return 1;
        break;

    case IEEE80211_MODE_11A:
        if(IEEE80211_IS_CHAN_A(c))
            return 0;
        else
            return 1;
        break;

    case IEEE80211_MODE_TURBO_STATIC_A:
        if(IEEE80211_IS_CHAN_A(c) && IEEE80211_IS_CHAN_STURBO(c) )
            return 0;
        else
            return 1;
        break;

    case IEEE80211_MODE_AUTO:
        return 0;
        break;

    case IEEE80211_MODE_11NG_HT20:
        if(IEEE80211_IS_CHAN_11NG_HT20(c))
            return 0;
        else
            return 1;
        break;

    case IEEE80211_MODE_11NG_HT40PLUS:
        if(IEEE80211_IS_CHAN_11NG_HT40PLUS(c))
            return 0;
        else
            return 1;
        break;

    case IEEE80211_MODE_11NG_HT40MINUS:
        if(IEEE80211_IS_CHAN_11NG_HT40MINUS(c))
            return 0;
        else
            return 1;
        break;

    case IEEE80211_MODE_11NG_HT40:
        if(IEEE80211_IS_CHAN_11NG_HT40MINUS(c) || IEEE80211_IS_CHAN_11NG_HT40PLUS(c))
            return 0;
        else
            return 1;
        break;

    case IEEE80211_MODE_11NA_HT20:
        if(IEEE80211_IS_CHAN_11NA_HT20(c))
            return 0;
        else
            return 1;
        break;

    case IEEE80211_MODE_11NA_HT40PLUS:
        if(IEEE80211_IS_CHAN_11NA_HT40PLUS(c))
            return 0;
        else
            return 1;
        break;

    case IEEE80211_MODE_11NA_HT40MINUS:
        if(IEEE80211_IS_CHAN_11NA_HT40MINUS(c))
            return 0;
        else
            return 1;
        break;

    case IEEE80211_MODE_11NA_HT40:
        if(IEEE80211_IS_CHAN_11NA_HT40MINUS(c) || IEEE80211_IS_CHAN_11NA_HT40PLUS(c))
            return 0;
        else
            return 1;
        break;
    }
    return 1;

}
#undef  IEEE80211_MODE_TURBO_STATIC_A

#if ATH_SUPPORT_IBSS_DFS
/*
 * Check with our own IBSS DFS list and see if this channel is radar free.
 * return 1 if it is radar free.
 */
static int ieee80211_checkDFS_free(struct ieee80211vap *vap, struct ieee80211_channel *pchannel)
{
    int isradarfree = 1;
    u_int   i = 0;

    for (i = (vap->iv_ibssdfs_ie_data.len - IBSS_DFS_ZERO_MAP_SIZE)/sizeof(struct channel_map_field); i > 0; i--) {
        if (vap->iv_ibssdfs_ie_data.ch_map_list[i-1].ch_num == pchannel->ic_ieee) {
            if (vap->iv_ibssdfs_ie_data.ch_map_list[i-1].ch_map.radar) {
                isradarfree = 0;
            }
            break;
        }
    }

    return isradarfree;
}
/*
 * Found next DFS free channel for ibss. Noted that this function currently only used for ibss dfs.
 */
static void *
ieee80211_next_channel(struct ieee80211vap *vap, struct ieee80211_channel *pchannel)
{
    int target_channel = 0;
    struct ieee80211_channel *ptarget_channel = pchannel;
    u_int i;
    u_int8_t startfromhead = 0;
    u_int8_t foundfitchan = 0;
    struct ieee80211com *ic = vap->iv_ic;

    for (i = 0; i < ic->ic_nchans; i++) {
        if(!ieee80211_check_mode_consistency(ic, ic->ic_curmode, &ic->ic_channels[i])) {
           if(ic->ic_channels[i].ic_ieee == pchannel->ic_ieee) {
               break;
           }
        }
    }

    target_channel = i + 1;
    if (target_channel >= ic->ic_nchans) {
        target_channel = 0;
        startfromhead = 1;
    }

    for (; target_channel < ic->ic_nchans; target_channel++) {
        if(!ieee80211_check_mode_consistency(ic, ic->ic_curmode, &ic->ic_channels[target_channel]) &&
           ieee80211_checkDFS_free(vap, &ic->ic_channels[target_channel])){
            foundfitchan = 1;
            ptarget_channel = &ic->ic_channels[target_channel];
            break;
        } else if ((target_channel >= ic->ic_nchans - 1) && !startfromhead) {
            /* if we could not find next in the trail. restart from head once */
            target_channel = 0;
            startfromhead = 1;
        } else if (ic->ic_channels[target_channel].ic_ieee == pchannel->ic_ieee &&
                   ic->ic_channels[target_channel].ic_flags == pchannel->ic_flags &&
                   startfromhead) {
            /* we already restart to find channel from head but could not find a proper one , just jump to a random one  */
            target_channel = ieee80211_random_channel(ic,IEEE80211_SELECT_NONDFS_AND_DFS, IEEE80211_SELECT_NXT_CH_POST_RADAR_DETECT);
            if ( target_channel != -1) {
                ptarget_channel = &ic->ic_channels[target_channel];
            } else {
                ptarget_channel = pchannel;
            }
            break;
        }
    }

        return ptarget_channel;
}
#endif /* ATH_SUPPORT_IBSS_DFS */

/*
 * Build the ibss DFS element.
 */
u_int
ieee80211_create_dfs_channel_list(struct ieee80211vap *vap, struct channel_map_field *ch_map_list)
{
    u_int i, dfs_ch_count = 0;
    struct ieee80211com *ic = vap->iv_ic;

    for (i = 0; i < ic->ic_nchans; i++) {
        if((ic->ic_channels[i].ic_flagext & IEEE80211_CHAN_DFS) &&
            !ieee80211_check_mode_consistency(ic, ic->ic_curmode, &ic->ic_channels[i]))
        {
            ch_map_list[dfs_ch_count].ch_num = ic->ic_channels[i].ic_ieee;
            ch_map_list[dfs_ch_count].ch_map.bss = 0;
            ch_map_list[dfs_ch_count].ch_map.ofdem_preamble = 0;
            ch_map_list[dfs_ch_count].ch_map.und_signal = 0;
            ch_map_list[dfs_ch_count].ch_map.radar = 0;
            ch_map_list[dfs_ch_count].ch_map.unmeasured = 1;
            ch_map_list[dfs_ch_count].ch_map.reserved = 0;
            if (ic->ic_channels[i].ic_flags & IEEE80211_CHAN_RADAR) {
                ch_map_list[dfs_ch_count].ch_map.unmeasured = 0;
                ch_map_list[dfs_ch_count].ch_map.radar = 1;
            } else if (ic->ic_channels[i].ic_flagext & IEEE80211_CHAN_DFS_CLEAR) {
                ch_map_list[dfs_ch_count].ch_map.unmeasured = 0;
            }
            dfs_ch_count ++;
        }
    }
    return dfs_ch_count;
}

/*
* initialize a IBSS dfs ie
*/
void
ieee80211_build_ibss_dfs_ie(struct ieee80211vap *vap)
{
    u_int ch_count;
    struct ieee80211com *ic = vap->iv_ic;
    if (vap->iv_ibss_dfs_enter_recovery_threshold_in_tbtt == 0) {
        vap->iv_ibss_dfs_enter_recovery_threshold_in_tbtt = INIT_IBSS_DFS_OWNER_RECOVERY_TIME_IN_TBTT;
        vap->iv_ibss_dfs_csa_measrep_limit = DEFAULT_MAX_CSA_MEASREP_ACTION_PER_TBTT;
        vap->iv_ibss_dfs_csa_threshold     = ic->ic_chan_switch_cnt;
    }
    OS_MEMZERO(vap->iv_ibssdfs_ie_data.ch_map_list, sizeof(struct channel_map_field) * (IEEE80211_CHAN_MAX + 1));
    vap->iv_ibssdfs_ie_data.ie = IEEE80211_ELEMID_IBSSDFS;
    vap->iv_ibssdfs_ie_data.rec_interval = vap->iv_ibss_dfs_enter_recovery_threshold_in_tbtt;
    ch_count = ieee80211_create_dfs_channel_list(vap, vap->iv_ibssdfs_ie_data.ch_map_list);
    vap->iv_ibssdfs_ie_data.len = IBSS_DFS_ZERO_MAP_SIZE + (sizeof(struct channel_map_field) * ch_count);
    vap->iv_measrep_action_count_per_tbtt = 0;
    vap->iv_csa_action_count_per_tbtt = 0;
    vap->iv_ibssdfs_recovery_count = vap->iv_ibss_dfs_enter_recovery_threshold_in_tbtt;
}

#endif

/*
 * Execute radar channel change. This is called when a radar/dfs
 * signal is detected.  AP mode only.  Return 1 on success, 0 on
 * failure
 */
int
ieee80211_dfs_action(struct ieee80211vap *vap, struct ieee80211_channelswitch_ie *pcsaie)
{
    struct ieee80211com *ic = vap->iv_ic;
    int target_channel = -1;
    struct ieee80211_channel *ptarget_channel = NULL;
    struct ieee80211vap *tmp_vap = NULL;
    if (vap->iv_opmode != IEEE80211_M_HOSTAP &&
        vap->iv_opmode != IEEE80211_M_IBSS) {
        return 0;
    }

#if ATH_SUPPORT_IBSS_DFS
    if (vap->iv_opmode == IEEE80211_M_IBSS) {

        if (pcsaie) {
            ptarget_channel = ieee80211_doth_findchan(vap, pcsaie->newchannel);
        } else if(ic->ic_flags & IEEE80211_F_CHANSWITCH) {
            ptarget_channel = ieee80211_doth_findchan(vap, ic->ic_chanchange_chan);
        } else {
            target_channel = ieee80211_random_channel(ic, IEEE80211_SELECT_NONDFS_AND_DFS, IEEE80211_SELECT_NXT_CH_POST_RADAR_DETECT);
            if ( target_channel != -1) {
                ptarget_channel = &ic->ic_channels[target_channel];
            } else {
                ptarget_channel = NULL;
                ic->no_chans_available = 1;
                qdf_print("%s: vap-%d(%s) channel is not available, bringdown all the AP vaps\n",
                        __func__,vap->iv_unit,vap->iv_netdev_name);
                vap->iv_evtable->wlan_bringdown_ap_vaps(vap->iv_ifp);
            }
        }
    }
#endif /* ATH_SUPPORT_IBSS_DFS */

    if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
        if(IEEE80211_IS_CSH_OPT_APRIORI_NEXT_CHANNEL_ENABLED(ic) && ic->ic_tx_next_ch)
        {
            ptarget_channel = ic->ic_tx_next_ch;
        } else {
            /*
             *  1) If nonDFS random is requested then first try selecting a nonDFS
             *     channel, if not found try selecting a DFS channel.
             *  2) By default the random selection from both DFS and nonDFS set.
             */

            if (IEEE80211_IS_CSH_NONDFS_RANDOM_ENABLED(ic)) {
                target_channel = ieee80211_random_channel(ic,IEEE80211_SELECT_NONDFS_ONLY, IEEE80211_SELECT_NXT_CH_POST_RADAR_DETECT);
            }
            if (target_channel == -1) {
                target_channel = ieee80211_random_channel(ic,IEEE80211_SELECT_NONDFS_AND_DFS, IEEE80211_SELECT_NXT_CH_POST_RADAR_DETECT);
            }
            if ( target_channel != -1) {
                    ptarget_channel = &ic->ic_channels[target_channel];
            } else {
                    ptarget_channel = NULL;
                    ic->no_chans_available = 1;
                    qdf_print("%s: vap-%d(%s) channel is not available, bringdown all the AP vaps\n",
                            __func__,vap->iv_unit,vap->iv_netdev_name);
                    vap->iv_evtable->wlan_bringdown_ap_vaps(vap->iv_ifp);
            }
        }
    }

    /* If we do have a scan entry, make sure its not an excluded 11D channel.
       See bug 31246 */
    /* No channel was found via scan module, means no good scanlist
       was found */

        if (ptarget_channel)
		{
                if (IEEE80211_IS_CHAN_11AC_VHT160 (ptarget_channel)) {
                    qdf_print("Changing to HT160 %s channel %d (%d MHz)\n",
                        IEEE80211_IS_CHAN_DFS(ptarget_channel) ? "DFS" : "non-DFS",
                        ptarget_channel->ic_ieee,
                        ptarget_channel->ic_freq);
                } else if (IEEE80211_IS_CHAN_11AC_VHT80_80(ptarget_channel)) {
                    qdf_print("Changing to HT80_80 Primary %s channel %d (%d MHz) secondary %s chan %d (center freq %d)\n",
                        IEEE80211_IS_CHAN_DFS(ptarget_channel) ? "DFS" : "non-DFS",
                        ptarget_channel->ic_ieee,
                        ptarget_channel->ic_freq,
                        IEEE80211_IS_CHAN_DFS_CFREQ2(ptarget_channel) ? "DFS" : "non-DFS",
                        ptarget_channel->ic_vhtop_ch_freq_seg2,
                        ieee80211_ieee2mhz(ic, ptarget_channel->ic_vhtop_ch_freq_seg2, ptarget_channel->ic_flags));
                } else if (IEEE80211_IS_CHAN_11AC_VHT80(ptarget_channel)) {
                    qdf_print("Changing to HT80 %s channel %d (%d MHz)\n",
                        IEEE80211_IS_CHAN_DFS(ptarget_channel) ? "DFS" : "non-DFS",
                        ptarget_channel->ic_ieee,
                        ptarget_channel->ic_freq);
                } else if (IEEE80211_IS_CHAN_11AC_VHT40(ptarget_channel)) {
                    qdf_print("Changing to HT40 %s channel %d (%d MHz)\n",
                        IEEE80211_IS_CHAN_DFS(ptarget_channel) ? "DFS" : "non-DFS",
                        ptarget_channel->ic_ieee,
                        ptarget_channel->ic_freq);
                } else if (IEEE80211_IS_CHAN_11AC_VHT20(ptarget_channel)) {
                    qdf_print("Changing to HT20 %s channel %d (%d MHz)\n",
                        IEEE80211_IS_CHAN_DFS(ptarget_channel) ? "DFS" : "non-DFS",
                        ptarget_channel->ic_ieee,
                        ptarget_channel->ic_freq);
                }

		    if (vap->iv_state_info.iv_state == IEEE80211_S_RUN)
            {
                if (pcsaie) {
                    ic->ic_chanchange_chan = pcsaie->newchannel;
                    ic->ic_chanchange_tbtt = pcsaie->tbttcount;
                } else {
                    ic->ic_chanchange_channel = ptarget_channel;
                    ic->ic_chanchange_secoffset =
                        ieee80211_sec_chan_offset(ic->ic_chanchange_channel);
                    ic->ic_chanchange_chwidth =
                        ieee80211_get_chan_width(ic->ic_chanchange_channel);
                    ic->ic_chanchange_chan = ptarget_channel->ic_ieee;
                    ic->ic_chanchange_tbtt = ic->ic_chan_switch_cnt;
                }

                if (IEEE80211_IS_CHAN_11AC_VHT160(ptarget_channel)) {
                    vap->iv_des_mode   = IEEE80211_MODE_11AC_VHT160;
                }
                if (IEEE80211_IS_CHAN_11AC_VHT80_80(ptarget_channel)) {
                    vap->iv_des_cfreq2 =  ptarget_channel->ic_vhtop_ch_freq_seg2;
                    vap->iv_des_mode   = IEEE80211_MODE_11AC_VHT80_80;
                }
                if (IEEE80211_IS_CHAN_11AC_VHT80(ptarget_channel)) {
                    vap->iv_des_mode   = IEEE80211_MODE_11AC_VHT80;
                }

#ifdef MAGPIE_HIF_GMAC
                TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
                    ic->ic_chanchange_cnt += ic->ic_chanchange_tbtt;
                }
#endif
                ic->ic_flags |= IEEE80211_F_CHANSWITCH;

#if ATH_SUPPORT_IBSS_DFS
            if (vap->iv_opmode == IEEE80211_M_IBSS) {
                struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
                struct ieee80211_action_mgt_args *actionargs;
                /* overwirte with our own value if we are DFS owner */
                if ( pcsaie == NULL &&
                    vap->iv_ibssdfs_state == IEEE80211_IBSSDFS_OWNER) {
                    ic->ic_chanchange_tbtt = vap->iv_ibss_dfs_csa_threshold;
                }

                vap->iv_ibssdfs_state = IEEE80211_IBSSDFS_CHANNEL_SWITCH;

                if(vap->iv_csa_action_count_per_tbtt > vap->iv_ibss_dfs_csa_measrep_limit) {
                    return 1;
                }
                vap->iv_csa_action_count_per_tbtt++;

                ieee80211_ic_doth_set(ic);

                vap->iv_channelswitch_ie_data.newchannel = ic->ic_chanchange_chan;

                /* use beacon_update function to do real channel switch */
                scn->sc_ops->ath_ibss_beacon_update_start(scn->sc_dev);

                if(IEEE80211_ADDR_EQ(vap->iv_ibssdfs_ie_data.owner, vap->iv_myaddr))
                {
                    actionargs = OS_MALLOC(vap->iv_ic->ic_osdev, sizeof(struct ieee80211_action_mgt_args) , GFP_KERNEL);
                    if (actionargs == NULL) {
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY, "%s: Unable to alloc arg buf. Size=%d\n",
                                                    __func__, sizeof(struct ieee80211_action_mgt_args));
                        return 0;
                    }
                    OS_MEMZERO(actionargs, sizeof(struct ieee80211_action_mgt_args));

                    actionargs->category = IEEE80211_ACTION_CAT_SPECTRUM;
                    actionargs->action   = IEEE80211_ACTION_CHAN_SWITCH;
                    actionargs->arg1     = 1;   /* mode? no use for now */
                    actionargs->arg2     = ic->ic_chanchange_chan;
                    ieee80211_send_action(vap->iv_bss, actionargs, NULL);
                    OS_FREE(actionargs);
                }
            }
#endif /* ATH_SUPPORT_IBSS_DFS */
            }
            else
			{
			    /*
			     * vap is not in run  state yet. so
			     * change the channel here.
			     */
                ic->ic_chanchange_chan = ptarget_channel->ic_ieee;

                /* update the bss channel of all the vaps */
                wlan_iterate_vap_list(ic, ieee80211_vap_iter_update_bss_chan, ptarget_channel);
                ic->ic_prevchan = ic->ic_curchan;
                ic->ic_curchan = ptarget_channel;
                TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
                    if (tmp_vap->iv_opmode == IEEE80211_M_MONITOR || (tmp_vap->iv_opmode == IEEE80211_M_HOSTAP &&
                                (tmp_vap->iv_state_info.iv_state == IEEE80211_S_DFS_WAIT || tmp_vap->iv_state_info.iv_state == IEEE80211_S_RUN))) {
                            channel_switch_set_channel(tmp_vap, ic);
                    }
                }

			}
		}
	    else
		{
		    /* should never come here? */
		    qdf_print("Cannot change to any channel\n");
		    return 0;
		}
    return 1;
}
void ieee80211_bringup_ap_vaps(struct ieee80211com *ic)
{
    struct ieee80211vap *vap;
    vap = TAILQ_FIRST(&ic->ic_vaps);
    vap->iv_evtable->wlan_bringup_ap_vaps(vap->iv_ifp);
    return;
}

void ieee80211_send_rcsa(struct ieee80211com *ic, struct ieee80211vap *vap, u_int8_t rcsa_count, u_int8_t ieee_freq)
{
    struct ieee80211_action_mgt_args *actionargs;
    struct ath_dfs *dfs = (struct ath_dfs *)ic->ic_dfs;

    if( NULL != vap) {
        actionargs = OS_MALLOC(vap->iv_ic->ic_osdev, sizeof(struct ieee80211_action_mgt_args) , GFP_KERNEL);
        if (actionargs == NULL) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY, "%s: Unable to alloc arg buf. Size=%d\n",
                                        __func__, sizeof(struct ieee80211_action_mgt_args));
            return ;
        }
        OS_MEMZERO(actionargs, sizeof(struct ieee80211_action_mgt_args));

        actionargs->category = IEEE80211_ACTION_CAT_VENDOR;
        actionargs->action   = IEEE80211_ACTION_CHAN_SWITCH;
        DFS_DPRINTK(dfs, ATH_DEBUG_DFS,
               "%s: seding action frame category=%d action=%d chan=%d\n",
               __func__,actionargs->category,actionargs->action,ic->ic_chanchange_chan);
        ieee80211_send_action(vap->iv_bss, actionargs, NULL);
        OS_FREE(actionargs);
    }
}

void
ieee80211_mark_dfs(struct ieee80211com *ic, struct ieee80211_channel *ichan)
{
     struct ieee80211_channel *c=NULL;
     struct ieee80211vap *vap;
#ifdef MAGPIE_HIF_GMAC
     struct ieee80211vap* tmp_vap = NULL;
#endif

     if (ic->ic_opmode == IEEE80211_M_HOSTAP ||
         ic->ic_opmode == IEEE80211_M_IBSS)
     {
         ieee80211_dfs_cac_cancel(ic);
         /* Mark the channel in the ic_chan list */
         /*
          * XXX TODO: this isn't exactly correct.
          * Specifically - it only marks the channels that match
          * the given centre frequency as having DFS, rather than
          * actually checking for channel overlap.  So it's not
          * entirely correct behaviour for VHT or HT40 operation.
          *
          * In any case, it should eventually be taught to just
          * use the channel centre and channel overlap code
          * that now exists in umac/base/ieee80211_channel.c
          * and flag them all.
          *
          * In actual reality, this also gets set correctly by
          * the NOL dfs channel list update method.
          */
         if ((ic->ic_flags_ext & IEEE80211_FEXT_MARKDFS) &&
             (ic->ic_dfs_usenol(ic) == 1))
         {
            /*
               IR: 115114 -- Primary Non-DFS channel is excluded
               from channel slection in HT80_80 mode

               The code that was used previously to set channel flag
               to indicate radar was found in the channel is discarded
               because of the following:

               1. Redundant -- as flags are already set (marked) by combination
               of dfs_channel_mark_radar/dfs_nol_update/ic_dfs_clist_update
               functions.

               2. The code does not work where we can mix DFS/Non-DFS channels
               and channel marking of radar. This can happen specially in
               in ht80_80 mode and ht160. The code (erroneously) prvents
               use of non-DFS primary 20 MHz control channel if radar is
               found.
            */

             c = ieee80211_find_channel(ic, ichan->ic_freq, ichan->ic_vhtop_ch_freq_seg2, ichan->ic_flags);

             if (c == NULL)
             {
                 return;
             }

             /*
              * If the reported event is on the current channel centre
              * frequency, begin the process of moving to another
              * channel.
              *
              * Unfortunately for now, this is not entirely correct -
              * If we report a radar event on a subchannel of the current
              * channel, this test will fail and we'll end up not
              * starting a CSA.
              *
              * XXX TODO: this API needs to change to take a radar event
              * frequency/width, instead of a channel.  It's then up
              * to the alternative umac implementations to write glue
              * to correctly handle things.
              */
             if  (ic->ic_curchan->ic_freq == c->ic_freq)
             {
                 /* get an AP vap */
                 vap = TAILQ_FIRST(&ic->ic_vaps);
                 while ((vap != NULL) && (vap->iv_state_info.iv_state != IEEE80211_S_RUN)  &&
                     (vap->iv_ic != ic))
                 {
                     vap = TAILQ_NEXT(vap, iv_next);
                 }
                 if (vap == NULL)
                 {
                     /*
                      * No running VAP was found, check
                      * any one is scanning.
                      */
                     vap = TAILQ_FIRST(&ic->ic_vaps);
                     while ((vap != NULL) && (vap->iv_ic != ic) &&
                            (vap->iv_state_info.iv_state != IEEE80211_S_SCAN))
                     {
                         vap = TAILQ_NEXT(vap, iv_next);
                     }
                     /*
                     * No running/scanning VAP was found, so they're all in
                     * INIT state, no channel change needed
                     */
                     if(!vap) return;
                     /* is it really Scanning */
                     /* XXX race condition ?? */
                     if(ic->ic_flags & IEEE80211_F_SCAN) return;
                     /* it is not scanning , but waiting for ath driver to move he vap to RUN */
                 }
#if ATH_SUPPORT_IBSS_DFS
               /* call the dfs action */
               if (vap->iv_opmode == IEEE80211_M_IBSS) {
                    u_int8_t index;
                    /* mark ibss dfs element, only support radar for now */
                    for (index = (vap->iv_ibssdfs_ie_data.len - IBSS_DFS_ZERO_MAP_SIZE)/sizeof(struct channel_map_field); index >0; index--) {
                        if (vap->iv_ibssdfs_ie_data.ch_map_list[index-1].ch_num == ichan->ic_ieee) {
                            vap->iv_ibssdfs_ie_data.ch_map_list[index-1].ch_map.radar = 1;
                            vap->iv_ibssdfs_ie_data.ch_map_list[index-1].ch_map.unmeasured = 0;
                            break;
                        }
                    }

                   if(IEEE80211_ADDR_EQ(vap->iv_myaddr, vap->iv_ibssdfs_ie_data.owner)) {
                        ieee80211_dfs_action(vap, NULL);
                   } else {
                        /* send out measurement report in this case */
                        ieee80211_measurement_report_action(vap, NULL);
                        if (vap->iv_ibssdfs_state == IEEE80211_IBSSDFS_JOINER) {
                            vap->iv_ibssdfs_state = IEEE80211_IBSSDFS_WAIT_RECOVERY;
                        }
                   }
               }
#endif /* ATH_SUPPORT_IBSS_DFS */
                if (vap->iv_opmode == IEEE80211_M_HOSTAP)
                    ieee80211_dfs_action(vap, NULL);
             }
           else
           {
           }
         }
         else
         {
             /* Change to a radar free 11a channel for dfstesttime seconds */
             ic->ic_chanchange_chan = ieee80211_get_test_mute_chan(ic,
               ic->ic_curchan);
             ic->ic_chanchange_tbtt = ic->ic_chan_switch_cnt;
#ifdef MAGPIE_HIF_GMAC
             TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
                 ic->ic_chanchange_cnt += ic->ic_chanchange_tbtt;
             }
#endif
             ic->ic_flags |= IEEE80211_F_CHANSWITCH;
             /* A timer is setup in the radar task if markdfs is not set and
              * we are in hostap mode.
              */
         }
     }
     else
     {
         /* Are we in sta mode? If so, send an action msg to ap saying we found  radar? */
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
         if (ic->ic_opmode == IEEE80211_M_STA) {
             ieee80211_dfs_stacac_cancel(ic);
             /* Mark the channel in the ic_chan list */
             /*
              * XXX TODO: this isn't exactly correct.
              * Specifically - it only marks the channels that match
              * the given centre frequency as having DFS, rather than
              * actually checking for channel overlap.  So it's not
              * entirely correct behaviour for VHT or HT40 operation.
              *
              * In any case, it should eventually be taught to just
              * use the channel centre and channel overlap code
              * that now exists in umac/base/ieee80211_channel.c
              * and flag them all.
              *
              * In actual reality, this also gets set correctly by
              * the NOL dfs channel list update method.
              */
             if ((ic->ic_flags_ext & IEEE80211_FEXT_MARKDFS) &&
                 (ic->ic_dfs_usenol(ic) == 1)) {
                 c = ieee80211_find_channel(ic, ichan->ic_freq, ichan->ic_vhtop_ch_freq_seg2, ichan->ic_flags);

                 if (c == NULL) {
                     return;
                 }
             }
             vap = TAILQ_FIRST(&ic->ic_vaps);
             while (vap != NULL) {
                 if(vap->iv_opmode == IEEE80211_M_STA) {
                     wlan_scan_table_flush(vap);
                     mlme_indicate_sta_radar_detect(vap->iv_bss);
                     break;
                 }
                 vap = TAILQ_NEXT(vap, iv_next);
             }
             if (vap == NULL) {
             }
             return;
         }
#endif
     } /* End of else for STA mode */
}

#if ATH_SUPPORT_ZERO_CAC_DFS

void channel_change_by_precac(struct ieee80211com *ic)
{
    struct ieee80211vap *tmp_vap = NULL;

    TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
        if (ieee80211_vap_ready_is_set(tmp_vap)){
            ic->ic_defer_precac_channel_change = 0;
            tmp_vap->iv_pre_cac_timeout_channel_change = 1;
            channel_switch_set_channel(tmp_vap, ic);
        }
        else
            ic->ic_defer_precac_channel_change = 1;
    }
}

#define VHT80_IEEE_FREQ_OFFSET 6
void
ieee80211_mark_precac_dfs(struct ieee80211com *ic, uint8_t is_radar_found_on_secondary_seg)
{
	struct ieee80211_dfs_state *dfs = &ic->ic_dfs_state;
	struct ieee80211_precac_entry *precac_entry = NULL, *tmp_precac_entry = NULL;
    uint8_t found = 0;

    IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_DFS, "%s : %d is_radar_found_on_secondary_seg = %u "
            "secondary_freq = %u primary_freq = %u\n",__func__,__LINE__,
            is_radar_found_on_secondary_seg, ic->ic_precac_secondary_freq, ic->ic_precac_primary_freq);

    /*
     * Even if radar found on primary, we need to move the channel from
     * precac-required-list and precac-done-list to precac-nol-list.
     */
    PRECAC_LIST_LOCK(ic);
    if(!TAILQ_EMPTY(&dfs->precac_required_list)) {
        TAILQ_FOREACH_SAFE(precac_entry,&dfs->precac_required_list,pe_list,tmp_precac_entry) {
            /* If on primary then use IS_WITHIN_RANGE else use equality directly */
            if (is_radar_found_on_secondary_seg ?
                    (ic->ic_precac_secondary_freq == precac_entry->vht80_freq) :
                    IS_WITHIN_RANGE(ic->ic_curchan->ic_ieee,precac_entry->vht80_freq,VHT80_IEEE_FREQ_OFFSET)) {
                TAILQ_REMOVE(&dfs->precac_required_list,precac_entry,pe_list);
                IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_DFS, "%s : %d removing the the freq=%u from "
                        "required list and adding to NOL list\n",__func__,__LINE__,precac_entry->vht80_freq);
                TAILQ_INSERT_TAIL(&dfs->precac_nol_list,precac_entry,pe_list);
                OS_SET_TIMER(&precac_entry->precac_nol_timer, ic->ic_get_nol_timeout(ic)*1000);
                found = 1;
                break;
            }
        }
    }

    /* if not found in precac-required-list remove from precac-done-list */
    if(!found && !TAILQ_EMPTY(&dfs->precac_done_list)) {
        TAILQ_FOREACH_SAFE(precac_entry,&dfs->precac_done_list,pe_list,tmp_precac_entry) {
            /* If on primary then use IS_WITHIN_RANGE else use equality directly */
            if (is_radar_found_on_secondary_seg ?
                    (ic->ic_precac_secondary_freq == precac_entry->vht80_freq) :
                    IS_WITHIN_RANGE(ic->ic_curchan->ic_ieee,precac_entry->vht80_freq,6)) {
                TAILQ_REMOVE(&dfs->precac_done_list,precac_entry,pe_list);
                IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_DFS, "%s : %d removing the the freq=%u from done list "
                        "and adding to NOL list\n",__func__,__LINE__,precac_entry->vht80_freq);
                TAILQ_INSERT_TAIL(&dfs->precac_nol_list,precac_entry,pe_list);
                OS_SET_TIMER(&precac_entry->precac_nol_timer, ic->ic_get_nol_timeout(ic)*1000);
                break;
            }
        }
    }
    PRECAC_LIST_UNLOCK(ic);

    /* TODO xxx:- Need to lock the channel change */
    /*
     * If radar Found on Primary no need to do restart VAP's channels
     * Since channel change will happen after RANDOM channel
     * selection anyway.
     */

    if(ic->ic_precac_timer_running ) {
        /* Cancel the PreCAC timer */
        OS_CANCEL_TIMER(&dfs->precac_timer);
        ic->ic_precac_timer_running = 0;

        /*
         * Change the channel
         * case 1:-  No  VHT80 channel for precac is available so bring it back to VHT80
         * case 2:-  pick a new VHT80 channel for precac
         */
        if(is_radar_found_on_secondary_seg) {
            if(ieee80211_dfs_is_ap_cac_timer_running(ic)) {
                ic->ic_defer_precac_channel_change = 1;
                IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_DFS,
                        "%s : Primary CAC is running, defer the channel change\n", __func__);
            } else {
                channel_change_by_precac(ic);
            }
        }
    }
}

bool ieee80211_is_precac_timer_running(struct ieee80211com *ic)
{
    return ic->ic_precac_timer_running ? true:false;
}

#define VHT80_IEEE_FREQ_OFFSET 6

/* Get a VHT80 channel with the precac primary center frequency */
struct ieee80211_channel *
ieee80211_dfs_find_precac_secondary_vht80_chan(struct ieee80211com *ic)
{
    uint8_t first_primary_ic_ieee;

    first_primary_ic_ieee = ic->ic_precac_secondary_freq - VHT80_IEEE_FREQ_OFFSET;
    return ieee80211_find_dot11_channel(ic, first_primary_ic_ieee, 0, IEEE80211_MODE_11AC_VHT80);
}
#endif

/* Timeout fn for cac_valid_timer
 * cac_valid bit will be reset in this function.
 *
 */
static
OS_TIMER_FUNC(cac_valid_timeout)
{
        struct ieee80211com *ic ;
	struct ieee80211_dfs_state *dfs;

	OS_GET_TIMER_ARG(ic, struct ieee80211com *);
	dfs = &ic->ic_dfs_state;
	dfs->cac_valid = 0;
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s. Timed out!! \n\r",__func__);
}

static
OS_TIMER_FUNC(cac_timeout)
{
	struct ieee80211com *ic;
	struct ieee80211_dfs_state *dfs;

	OS_GET_TIMER_ARG(ic, struct ieee80211com *);
	dfs = &ic->ic_dfs_state;
        dfs->cac_timer_running = 0;

	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s cac expired, chan %d curr time %d\n",
	    __func__, ic->ic_curchan->ic_freq,
	    (qdf_system_ticks_to_msecs(qdf_system_ticks()) / 1000));
	/*
	 * When radar is detected during a CAC we are woken
	 * up prematurely to switch to a new channel.
	 * Check the channel to decide how to act.
	 */
	if (IEEE80211_IS_CHAN_RADAR(ic->ic_curchan)) {
        ieee80211_mark_dfs(ic, ic->ic_curchan);

		IEEE80211_DPRINTF_IC(ic,
		    IEEE80211_VERBOSE_LOUD, IEEE80211_MSG_DFS,
		    "CAC timer on channel %u (%u MHz) stopped due to radar\n",
		    ic->ic_curchan->ic_ieee, ic->ic_curchan->ic_freq);

	} else {
		IEEE80211_DPRINTF_IC(ic,
		    IEEE80211_VERBOSE_LOUD,IEEE80211_MSG_DFS,
		    "CAC timer on channel %u (%u MHz) expired; "
		    "no radar detected\n",
		    ic->ic_curchan->ic_ieee, ic->ic_curchan->ic_freq);

                /* On CAC completion, set the bit 'cac_valid'.
                 * CAC will not be re-done if this bit is reset.
                 * The flag will be reset when cac_valid_timer timesout
                 */
                if(dfs->cac_valid_time) {
		    	dfs->cac_valid = 1;
                    	OS_SET_TIMER(&dfs->cac_valid_timer, dfs->cac_valid_time * 1000);
                }
	}

	/*
	 * Iterate over the nodes, processing the CAC completion event.
	 */
	ieee80211_dfs_proc_cac(ic);


    /*Send a CAC timeout, VAP up event to user space*/
    OSIF_RADIO_DELIVER_EVENT_UP_AFTER_CAC(ic);

#if ATH_SUPPORT_ZERO_CAC_DFS
    if(ic->ic_defer_precac_channel_change == 1) {
        channel_change_by_precac(ic);
        ic->ic_defer_precac_channel_change = 0;
    }
#endif
}

#if ATH_SUPPORT_ZERO_CAC_DFS
static
OS_TIMER_FUNC(precac_timeout)
{
	struct ieee80211com *ic;
	struct ieee80211_dfs_state *dfs;
    struct ieee80211_precac_entry *precac_entry, *tmp_precac_entry;
	OS_GET_TIMER_ARG(ic, struct ieee80211com *);

	ic->ic_precac_timer_running = 0;
	dfs = &ic->ic_dfs_state;

    /*
     * Remove the HVT80 freq from the precac-required-list
     * and add it to the precac-done-list
     */

    PRECAC_LIST_LOCK(ic);
    if(!TAILQ_EMPTY(&dfs->precac_required_list)) {
        TAILQ_FOREACH_SAFE(precac_entry,&dfs->precac_required_list,pe_list,tmp_precac_entry) {
            if (ic->ic_precac_secondary_freq == precac_entry->vht80_freq) {
                TAILQ_REMOVE(&dfs->precac_required_list,precac_entry,pe_list);
                IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_DFS, "%s : %d removing the the freq = %u "
                        "from required list and adding to done list\n",__func__,__LINE__,precac_entry->vht80_freq);
                TAILQ_INSERT_TAIL(&dfs->precac_done_list,precac_entry,pe_list);
                break;
            }
        }
    }
    PRECAC_LIST_UNLOCK(ic);

    /*
	 * Do vdev restart so that we can change the
	 * secondary VHT80 channel
	 */
    IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_DFS, "%s : %d Pre-cac expired, Precac Secondary chan %u curr time %d\n",
            __func__,__LINE__, ic->ic_precac_secondary_freq,(qdf_system_ticks_to_msecs(qdf_system_ticks()) / 1000));

    /* TODO xxx : Need to lock the channel change */
    channel_change_by_precac(ic);
}
#endif

int
ieee80211_dfs_cac_cancel(struct ieee80211com *ic)
{
    struct ieee80211vap *vap = NULL;
    struct ieee80211vap *stavap = NULL;

    if(ieee80211_dfs_is_ap_cac_timer_running(ic)) {
        STA_VAP_DOWNUP_LOCK(ic);
        stavap = ic->ic_sta_vap;
        if(stavap) {
            int val = 0;
            wlan_mlme_sm_get_curstate(stavap,IEEE80211_PARAM_CONNECTION_SM_STATE,&val);
            if(val == WLAN_ASSOC_STATE_REPEATER_CAC) {
                IEEE80211_DELIVER_EVENT_MLME_REPEATER_CAC_COMPLETE(stavap,1);
            }
        }
        STA_VAP_DOWNUP_UNLOCK(ic);
    }
    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
	if (vap->iv_state_info.iv_state != IEEE80211_S_DFS_WAIT) {
		continue;
        }
        ieee80211_dfs_cac_stop(vap, 1);
    }
    return 0;
}

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
int
ieee80211_dfs_stacac_cancel(struct ieee80211com *ic)
{

	struct ieee80211vap *vap;

	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if (vap->iv_opmode == IEEE80211_M_STA && ieee80211com_has_cap_ext(ic,IEEE80211_CEXT_STADFS)) {
            ieee80211_dfs_stacac_stop(vap);
            break;
        }
    }
    return 0;
}
#endif
int ieee80211_dfs_is_ap_cac_timer_running(struct ieee80211com * ic)
{
	struct ieee80211_dfs_state *dfs;

	dfs = &ic->ic_dfs_state;
	return dfs->cac_timer_running;
}

static int
ieee80211_dfs_send_dfs_wait(struct ieee80211com *ic)
{

    struct ieee80211vap *vap;
    int set_dfs_wait_mesg = 0;
    IEEE80211_COMM_LOCK(ic);
    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if (vap->iv_opmode != IEEE80211_M_HOSTAP && vap->iv_opmode != IEEE80211_M_IBSS) {
            IEEE80211_DPRINTF_IC(ic,
            IEEE80211_VERBOSE_FORCE,
            IEEE80211_MSG_DFS,"%s[%d] NOT A HOSTAP/IBSS VAP , skip DFS (iv_opmode %d, iv_bsschan %d,  ic_freq %d)\n",
                    __func__, __LINE__, vap->iv_opmode, vap->iv_bsschan->ic_freq, ic->ic_curchan->ic_freq);
            continue;
        }
        if (vap->iv_bsschan != ic->ic_curchan) {
           IEEE80211_DPRINTF_IC(ic,
           IEEE80211_VERBOSE_FORCE,
           IEEE80211_MSG_DFS,"%s[%d] VAP chan mismatch vap %d ic %d\n", __func__, __LINE__,
            vap->iv_bsschan->ic_freq, ic->ic_curchan->ic_freq);
            continue;
        }
#if ATH_SUPPORT_IBSS_DFS
	/* Don't send DFS wait for joining IBSS vaps */
	if(vap->iv_ibssdfs_state == IEEE80211_IBSSDFS_JOINER && vap->iv_state_info.iv_state != IEEE80211_S_RUN &&
           vap->iv_opmode == IEEE80211_M_IBSS)
	{
           IEEE80211_DPRINTF_IC(ic,
           IEEE80211_VERBOSE_FORCE,
           IEEE80211_MSG_DFS,"%s[%d] DONT send DFS_WAIT event for joining vaps\n", __func__, __LINE__);
	    continue;
	}
#endif
        if (vap->iv_state_info.iv_state < IEEE80211_S_JOIN && vap->iv_opmode != IEEE80211_M_IBSS) {
           IEEE80211_DPRINTF_IC(ic,
           IEEE80211_VERBOSE_FORCE,
           IEEE80211_MSG_DFS,"%s[%d] DONT send DFS_WAIT event to vap state %d \n", __func__, __LINE__,
                    vap->iv_state_info.iv_state);
            continue;
        }
		IEEE80211_COMM_UNLOCK(ic);
        ieee80211_state_event(vap, IEEE80211_STATE_EVENT_DFS_WAIT);
        set_dfs_wait_mesg++;
		IEEE80211_COMM_LOCK(ic);
    }
	IEEE80211_COMM_UNLOCK(ic);
    return set_dfs_wait_mesg;
}

/* Get VAPS in DFS_WAIT state */
static int
ieee80211_vaps_in_dfs_wait(struct ieee80211com *ic, struct ieee80211vap *curr_vap)
{

    struct ieee80211vap *vap;
    int dfs_wait_cnt = 0;
    IEEE80211_COMM_LOCK(ic);
    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if(vap == curr_vap) {
            continue;
        }
        if (vap->iv_opmode != IEEE80211_M_HOSTAP && vap->iv_opmode != IEEE80211_M_IBSS) {
            continue;
        }

        if (vap->iv_state_info.iv_state == IEEE80211_S_DFS_WAIT) {
            dfs_wait_cnt++;
        }
    }
    IEEE80211_COMM_UNLOCK(ic);
    return dfs_wait_cnt;
}

/*
 * Initiate the CAC timer.  The driver is responsible
 * for setting up the hardware to scan for radar on the
 * channnel, we just handle timing things out.
 */
int
ieee80211_dfs_cac_start(struct ieee80211com *ic)
{
	struct ieee80211_dfs_state *dfs = &ic->ic_dfs_state;
	bool check_if_vap_is_running = TRUE;

    if (ic->ic_flags_ext2 & IEEE80211_FEXT2_CSA_WAIT) {
        /* CSA from chanswitch ioctl case */
        ic->ic_flags_ext2 &= ~IEEE80211_FEXT2_CSA_WAIT;
        check_if_vap_is_running = FALSE;
    }

	if (!(IEEE80211_IS_CHAN_DFS(ic->ic_curchan) ||
              ((IEEE80211_IS_CHAN_11AC_VHT160(ic->ic_curchan) || IEEE80211_IS_CHAN_11AC_VHT80_80(ic->ic_curchan))
               && IEEE80211_IS_CHAN_DFS_CFREQ2(ic->ic_curchan)))) {
		/*
		 * Iterate over the nodes, processing the CAC completion event.
		 */
		ieee80211_dfs_proc_cac(ic);
		return 1;
	}

    /* If any VAP is in active and running, then no need to start cac
     * timer as all the VAPs will be using same channel and currently
     * running VAP has already done cac and actively monitoring channel */
    if(check_if_vap_is_running) {
        if(ieee80211_vap_is_any_running(ic)){
            return 1;
        }
    }

	if (ic->ic_dfs_state.ignore_dfs) {
		QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s ignore dfs by user %d \n",
			__func__, ic->ic_dfs_state.ignore_dfs);
		return 1;
	}

        if (ic->ic_dfs_state.cac_valid) {
	   QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s CAC Still Valid. Skip CAC\n",__func__);
		return 1;
        }

        if (ic->ic_dfs_state.ignore_cac) {
	   QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s ignore CAC by user %d \n",
	    __func__, ic->ic_dfs_state.ignore_cac);
		return 1;
        }

#if ATH_SUPPORT_ZERO_CAC_DFS
        /* IF the channel has completed PRE-CAC then
         * CAC can be skipped here
         */
        if (ieee80211_dfs_is_precac_done(ic)) {
            IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_DFS, "%s : %d PRE-CAC alreay done on this channel %d\n",
                    __func__,__LINE__, ic->ic_curchan->ic_ieee);
            return 1;
        }
#endif

	OS_CANCEL_TIMER(&dfs->cac_timer);
	if (ieee80211_dfs_send_dfs_wait(ic)) {
            if (IEEE80211_IS_CHAN_11AC_VHT80_80(ic->ic_curchan)) {
               IEEE80211_DPRINTF_IC(ic,
               IEEE80211_VERBOSE_FORCE,
               IEEE80211_MSG_DFS,"cac_start HT80_80 Primary %s chan %d, Ext %s chan %d timeout %d sec, curr time: %d sec\n",
                    IEEE80211_IS_CHAN_DFS(ic->ic_curchan) ? "DFS" : "non-DFS",
                    ic->ic_curchan->ic_ieee,
                    IEEE80211_IS_CHAN_DFS_CFREQ2(ic->ic_curchan) ? "DFS" : "non-DFS",
                    ic->ic_curchan->ic_vhtop_ch_freq_seg2,
                    ieee80211_get_cac_timeout(ic, ic->ic_curchan),
                    (qdf_system_ticks_to_msecs(qdf_system_ticks()) / 1000));
            } else {
               IEEE80211_DPRINTF_IC(ic,
               IEEE80211_VERBOSE_FORCE,
               IEEE80211_MSG_DFS,"cac_start chan %d timeout %d sec, curr time: %d sec\n",
                    ic->ic_curchan->ic_ieee,
                    ieee80211_get_cac_timeout(ic, ic->ic_curchan),
                    (qdf_system_ticks_to_msecs(qdf_system_ticks()) / 1000));
            }
            STA_VAP_DOWNUP_LOCK(ic);
            dfs->cac_timer_running = 1;
            STA_VAP_DOWNUP_UNLOCK(ic);
            qdf_sched_work(NULL,&ic->dfs_cac_timer_start_work);
	}
	return 0;
}

/*
 * Clear the CAC timer.
 */
void
ieee80211_dfs_cac_stop(struct ieee80211vap *vap, int force)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_dfs_state *dfs = &ic->ic_dfs_state;
    u_int32_t phyerr;

    if(!force &&
      (!dfs->cac_timer_running || ieee80211_vaps_in_dfs_wait(ic, vap))) {
        return;
    }

    ic->ic_dfs_debug(ic, 0, (void *)&phyerr);

       IEEE80211_DPRINTF_IC(ic,
               IEEE80211_VERBOSE_NORMAL,
               IEEE80211_MSG_DFS,"%s[%d] Stopping CAC Timer %d procphyerr 0x%08x\n",
               __func__, __LINE__, ic->ic_curchan->ic_freq, phyerr);


	OS_CANCEL_TIMER(&dfs->cac_timer);
        dfs->cac_timer_running = 0;
}

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
/*
 * Clear the STA CAC timer.
 */
void
ieee80211_dfs_stacac_stop(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;
	u_int32_t phyerr;

	ic->ic_dfs_debug(ic, 0, (void *)&phyerr);

    IEEE80211_DPRINTF_IC(ic,
               IEEE80211_VERBOSE_NORMAL,
               IEEE80211_MSG_DFS,"%s[%d] Stopping STA CAC Timer %d procphyerr 0x%08x\n",
               __func__, __LINE__, ic->ic_curchan->ic_freq, phyerr);

    mlme_cancel_stacac_timer(vap);
    mlme_reset_mlme_req(vap);
    mlme_set_stacac_running(vap,0);
    mlme_set_stacac_valid(vap,1);

}
#endif

/*
 * Unmark all channels whose frequencies match 'chan'.
 *
 * This matches the same logic used by ieee80211_mark_dfs (in if_lmac)
 * and ieee80211_notify_radar (here) which only mark channels whose
 * frequencies match the given detection channel.
 *
 * This doesn't at all reset or clear NOL handling for the channel.
 * It just updates the channel flags.
 *
 * This may need adjusting for 802.11n HT/40 channels and 802.11ac channels.
 */
void
ieee80211_unmark_radar(struct ieee80211com *ic, struct ieee80211_channel *chan)
{
	struct ieee80211_channel *c;
	int i;

	for (i = 0; i < ic->ic_nchans; i++) {
		c = &ic->ic_channels[i];
		if (chan->ic_freq == c->ic_freq) {
			/* XXX are both of these correct? */
			c->ic_flagext &= ~IEEE80211_CHAN_RADAR_FOUND;
			c->ic_flags &= ~IEEE80211_CHAN_RADAR;
		}
	}
}

static
OS_TIMER_FUNC(nol_timeout)
{
	struct ieee80211com *ic ;
	struct ieee80211_dfs_state *dfs;
	struct ieee80211_channel *c;
	int i;
	unsigned long oldest, now;

//	IEEE80211_LOCK_ASSERT(ic);
    OS_GET_TIMER_ARG(ic, struct ieee80211com *);
    dfs = &ic->ic_dfs_state;

	now = oldest = qdf_system_ticks();
	for (i = 0; i < ic->ic_nchans; i++) {
		c = &ic->ic_channels[i];
		if (IEEE80211_IS_CHAN_RADAR(c)) {
			if (qdf_system_time_after_eq(now, dfs->nol_event[i]+NOL_TIMEOUT)) {
				c->ic_flagext &= ~IEEE80211_CHAN_RADAR_FOUND;
				if (c->ic_flags & IEEE80211_CHAN_RADAR) {
					/*
					 * NB: do this here so we get only one
					 * msg instead of one for every channel
					 * table entry.
					 */
					IEEE80211_DPRINTF_IC(ic,
					    IEEE80211_VERBOSE_LOUD,
					    IEEE80211_MSG_DFS,
					    "radar on channel"
					    " %u (%u MHz) cleared after "
					    "timeout\n",
					    c->ic_ieee, c->ic_freq);
				}
			} else if (dfs->nol_event[i] < oldest)
				oldest = dfs->nol_event[i];
		}
	}
	if (oldest != now) {
		/* arrange to process next channel up for a status change */
		//callout_schedule(&dfs->nol_timer, oldest + NOL_TIMEOUT - now);
		OS_SET_TIMER(&dfs->nol_timer,
		    NOL_TIMEOUT - qdf_system_ticks_to_msecs(qdf_system_ticks()));
	}
}

#if ATH_SUPPORT_ZERO_CAC_DFS
static
OS_TIMER_FUNC(precac_nol_timeout)
{
	struct ieee80211_precac_entry *precac_entry;
	struct ieee80211com *ic;
	struct ieee80211_dfs_state *dfs;
	OS_GET_TIMER_ARG(precac_entry, struct ieee80211_precac_entry *);
	ic = precac_entry->ic;
	dfs = &ic->ic_dfs_state;


	PRECAC_LIST_LOCK(ic);
	if(!TAILQ_EMPTY(&dfs->precac_nol_list)) {
		/* Move the channel from precac-NOL to precac-required-list */
		TAILQ_REMOVE(&dfs->precac_nol_list,precac_entry,pe_list);
        IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_DFS, "%s : %d removing the the freq=%u from PreCAC NOL-list "
                "and adding Precac-required list\n",__func__,__LINE__,precac_entry->vht80_freq);
        TAILQ_INSERT_TAIL(&dfs->precac_required_list,precac_entry,pe_list);
	}
	PRECAC_LIST_UNLOCK(ic);

	/* TODO xxx : Need to lock the channel change */
	/* Do a channel change */
	channel_change_by_precac(ic);
}
#endif

static void
announce_radar(struct ieee80211com *ic, const struct ieee80211_channel *curchan,
	const struct ieee80211_channel *newchan)
{
	if (newchan == NULL)
		IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD,
		    IEEE80211_MSG_DFS,
		    "radar detected on channel %u (%u MHz)\n",
		    curchan->ic_ieee, curchan->ic_freq);
	else
		IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD,
		    IEEE80211_MSG_DFS,
		    "radar detected on channel %u (%u MHz), "
		    "moving to channel %u (%u MHz)\n",
		    curchan->ic_ieee, curchan->ic_freq,
		    newchan->ic_ieee, newchan->ic_freq);
}


/*
 * Handle scan-cancel in process-context
 * so that any scheduling, like sleep, can
 * happen in scan cancel without any panic.
 * After scan cancel start the timer.
 */
void
ieee80211_dfs_cac_timer_start_async(void *data)
{
    struct ieee80211com *ic = (struct ieee80211com *) data;
    struct ieee80211_dfs_state *dfs = &ic->ic_dfs_state;
    struct ieee80211vap * tmpvap ;

    if (ic->ic_sta_vap) {
        tmpvap = ic->ic_sta_vap;
        tmpvap->iv_evtable->wlan_vap_scan_cancel(tmpvap->iv_ifp);
    }
    OS_SET_TIMER(&dfs->cac_timer, ieee80211_get_cac_timeout(ic,
                ic->ic_curchan) * 1000);

    /*Send a CAC start event to user space*/
    OSIF_RADIO_DELIVER_EVENT_CAC_START(ic);
}

void
ieee80211_dfs_attach(struct ieee80211com *ic)
{
	struct ieee80211_dfs_state *dfs = &ic->ic_dfs_state;

	dfs->enable = 1;
	dfs->cac_timeout_override = -1;
#if ATH_SUPPORT_ZERO_CAC_DFS
	dfs->precac_timeout_override = -1;
	ieee80211_dfs_init_precac_list(ic);
	OS_INIT_TIMER(ic->ic_osdev, &(dfs->precac_timer), precac_timeout,
	    (void *) (ic), QDF_TIMER_TYPE_WAKE_APPS);
#endif
	OS_INIT_TIMER(ic->ic_osdev, &(dfs->cac_timer), cac_timeout,
	    (void *) (ic), QDF_TIMER_TYPE_WAKE_APPS);
	OS_INIT_TIMER(ic->ic_osdev, &(dfs->nol_timer), nol_timeout,
	    (void *) (ic), QDF_TIMER_TYPE_WAKE_APPS);
        OS_INIT_TIMER(ic->ic_osdev, &(dfs->cac_valid_timer), cac_valid_timeout,
            (void *) (ic), QDF_TIMER_TYPE_WAKE_APPS);
	ATH_CREATE_WORK(&ic->dfs_cac_timer_start_work,ieee80211_dfs_cac_timer_start_async,(void *)ic);

	ic->ic_set_quiet = null_set_quiet;
}

/*
 * Handle a radar detection event on a channel. The channel is
 * added to the NOL list and we record the time of the event.
 * Entries are aged out after NOL_TIMEOUT.  If radar was
 * detected while doing CAC we force a state/channel change.
 * Otherwise radar triggers a channel switch using the CSA
 * mechanism (when the channel is the bss channel).
 */
void
ieee80211_dfs_notify_radar(struct ieee80211com *ic,
    struct ieee80211_channel *chan)
{
	struct ieee80211_dfs_state *dfs = &ic->ic_dfs_state;
	int i;
	unsigned long now;

	//IEEE80211_LOCK_ASSERT(ic);

	/*
	 * Mark all entries with this frequency.  Notify user
	 * space and arrange for notification when the radar
	 * indication is cleared.  Then kick the NOL processing
	 * thread if not already running.
	 */
	now = qdf_system_ticks();
	for (i = 0; i < ic->ic_nchans; i++) {
		struct ieee80211_channel *c = &ic->ic_channels[i];
		if (c->ic_freq == chan->ic_freq) {
#if 0
			c->ic_state &= ~IEEE80211_CHANSTATE_CACDONE;
			c->ic_state |= IEEE80211_CHANSTATE_RADAR;
#endif
			/* XXX should I do this for all channels at that freq? */
			c->ic_flags |= IEEE80211_CHAN_RADAR;
			c->ic_flagext |= IEEE80211_CHAN_RADAR_FOUND;
			dfs->nol_event[i] = now;
		}
	}

#if 0
	ieee80211_notify_radar(ic, chan);
	chan->ic_state |= IEEE80211_CHANSTATE_NORADAR;
	if (!callout_pending(&dfs->nol_timer))
		callout_reset(&dfs->nol_timer, NOL_TIMEOUT, dfs_timeout, ic);
#endif
	/* Immediately do a NOL check */
	OS_CANCEL_TIMER(&dfs->nol_timer);
	OS_SET_TIMER(&dfs->nol_timer, 1);

#if 0
	/*
	 * If radar is detected on the bss channel while
	 * doing CAC; force a state change by scheduling the
	 * callout to be dispatched asap.  Otherwise, if this
	 * event is for the bss channel then we must quiet
	 * traffic and schedule a channel switch.
	 *
	 * Note this allows us to receive notification about
	 * channels other than the bss channel; not sure
	 * that can/will happen but it's simple to support.
	 */
	if (chan == ic->ic_bsschan) {
		/* XXX need a way to defer to user app */
		dfs->newchan = ieee80211_dfs_pickchannel(ic);

		announce_radar(ic->ic_ifp, chan, dfs->newchan);

		if (callout_pending(&dfs->cac_timer))
			callout_schedule(&dfs->cac_timer, 0);
		else if (dfs->newchan != NULL) {
			/* XXX mode 1, switch count 2 */
			/* XXX calculate switch count based on max
			  switch time and beacon interval? */
			ieee80211_csa_startswitch(ic, dfs->newchan, 1, 2);
		} else {
			/*
			 * Spec says to stop all transmissions and
			 * wait on the current channel for an entry
			 * on the NOL to expire.
			 */
			/*XXX*/
			IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD,IEEE80211_MSG_DFS, "%s: No free channels; waiting for entry "
			    "on NOL to expire\n", __func__);
		}
	} else {
		/*
		 * Issue rate-limited console msgs.
		 */
		if (dfs->lastchan != chan) {
			dfs->lastchan = chan;
			dfs->cureps = 0;
			announce_radar(ic->ic_ifp, chan, NULL);
		} else if (ppsratecheck(&dfs->lastevent, &dfs->cureps, 1)) {
			announce_radar(ic->ic_ifp, chan, NULL);
		}
	}
#endif
}

void ieee80211_update_dfs_next_channel(struct ieee80211com *ic)
{
    int target_channel = -1;
    struct ieee80211_channel *ptarget_channel = NULL;

    if (IEEE80211_IS_CSH_NONDFS_RANDOM_ENABLED(ic)) {
        target_channel = ieee80211_random_channel(ic,IEEE80211_SELECT_NONDFS_ONLY, IEEE80211_SELECT_APRIORI_NXT_CH);
    }
    if (target_channel == -1) {
        target_channel = ieee80211_random_channel(ic,IEEE80211_SELECT_NONDFS_AND_DFS, IEEE80211_SELECT_APRIORI_NXT_CH);
    }
    if ( target_channel != -1) {
         ptarget_channel = &ic->ic_channels[target_channel];
    } else {
         ptarget_channel = NULL;
    }
    if(ptarget_channel == NULL) {
        /* should never come here? */
        qdf_print("Cannot change to any channel\n");
        ic->ic_tx_next_ch = NULL;
    } else {
        ic->ic_tx_next_ch = ptarget_channel;
    }
}

#if ATH_SUPPORT_ZERO_CAC_DFS

void ieee80211_dfs_init_precac_list(struct ieee80211com *ic)
{
    u_int i;
    struct ieee80211_dfs_state *dfs = &ic->ic_dfs_state;
    u_int8_t found;
    struct ieee80211_precac_entry *tmp_precac_entry;

    /*
     * We need to prepare list of uniq VHT80 center frequencies.
     * But at the beginning we do not know how many uniq frequencies
     * are present. Therefore, we calculate the MAX size and allocate
     * a temporary list/array. However we fill the temporary array
     * with uniq frequencies and copy the uniq list of frequencies to
     * the final list with exact size.
     */
    TAILQ_INIT(&dfs->precac_required_list);
    TAILQ_INIT(&dfs->precac_done_list);
    TAILQ_INIT(&dfs->precac_nol_list);

    PRECAC_LIST_LOCK(ic);
    /* Fill the  precac-required-list with unique elements */
    for (i = 0; i < ic->ic_nchans; i++) {
        struct ieee80211_channel *ichan = &ic->ic_channels[i];
        if(IEEE80211_IS_CHAN_11AC_VHT80(ichan) && IEEE80211_IS_CHAN_DFS(ichan)) {
            found = 0;
            TAILQ_FOREACH(tmp_precac_entry,&dfs->precac_required_list,pe_list) {
                if(tmp_precac_entry->vht80_freq == ichan->ic_vhtop_ch_freq_seg1) {
                    found = 1;
                    break;
                }
            }
            if(!found) {
                struct ieee80211_precac_entry *precac_entry;
                precac_entry = OS_MALLOC(ic->ic_osdev,sizeof(*precac_entry),GFP_KERNEL);
                precac_entry->vht80_freq = ichan->ic_vhtop_ch_freq_seg1;
                precac_entry->ic = ic;

                /*
                 * Initialize per entry timer. Shall be used when the entry moves to
                 * precac_nol_list
                 */
                OS_INIT_TIMER(ic->ic_osdev, &(precac_entry->precac_nol_timer), precac_nol_timeout,
                        (void *) (precac_entry), QDF_TIMER_TYPE_WAKE_APPS);
                TAILQ_INSERT_TAIL(&dfs->precac_required_list,precac_entry,pe_list);
            }
        }
    }
    PRECAC_LIST_UNLOCK(ic);

    IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_DFS,
            "%s : %d Print the list of VHT80 frequencies from linked list\n",__func__,__LINE__);
    TAILQ_FOREACH(tmp_precac_entry,&dfs->precac_required_list,pe_list) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "freq=%u \n",tmp_precac_entry->vht80_freq);
    }
}

void ieee80211_dfs_deinit_precac_list(struct ieee80211com *ic)
{
    struct ieee80211_dfs_state *dfs = &ic->ic_dfs_state;
    struct ieee80211_precac_entry *tmp_precac_entry, *precac_entry;

    IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_DFS,
            "%s : %d Free the list of VHT80 frequencies from linked list(precac_required)\n",__func__,__LINE__);
    PRECAC_LIST_LOCK(ic);
    if (!TAILQ_EMPTY(&dfs->precac_required_list))
        TAILQ_FOREACH_SAFE(precac_entry,&dfs->precac_required_list,pe_list,tmp_precac_entry) {
            TAILQ_REMOVE(&dfs->precac_required_list,precac_entry,pe_list);
            OS_FREE(precac_entry);
        }

    IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_DFS,
            "%s : %d Free the list of VHT80 frequencies from linked list(precac_done)\n",__func__,__LINE__);
    if (!TAILQ_EMPTY(&dfs->precac_done_list))
        TAILQ_FOREACH_SAFE(precac_entry,&dfs->precac_done_list,pe_list,tmp_precac_entry) {
            TAILQ_REMOVE(&dfs->precac_required_list,precac_entry,pe_list);
            OS_FREE(precac_entry);
        }

    IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_DFS,
            "%s : %d Free the list of VHT80 frequencies from linked list(precac_nol)\n",__func__,__LINE__);
    if (!TAILQ_EMPTY(&dfs->precac_nol_list))
        TAILQ_FOREACH_SAFE(precac_entry,&dfs->precac_nol_list,pe_list,tmp_precac_entry) {
            OS_CANCEL_TIMER(&precac_entry->precac_nol_timer);
            TAILQ_REMOVE(&dfs->precac_required_list,precac_entry,pe_list);
            OS_FREE(precac_entry);
        }
    PRECAC_LIST_UNLOCK(ic);

}

/* Find a VHT80 freqency that is not equal to exclude_ieee_freq */
uint8_t ieee80211_dfs_get_freq_from_precac_required_list(struct ieee80211com *ic,uint8_t exclude_ieee_freq)
{
    struct ieee80211_dfs_state *dfs = &ic->ic_dfs_state;
    struct ieee80211_precac_entry *precac_entry;
    uint8_t ieee_freq = 0;

    IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_DFS,
            "%s : %d exclude_ieee_freq=%u\n",__func__,__LINE__,exclude_ieee_freq);

    PRECAC_LIST_LOCK(ic);
    if (!TAILQ_EMPTY(&dfs->precac_required_list)) {
        TAILQ_FOREACH(precac_entry,&dfs->precac_required_list,pe_list) {
            if(precac_entry->vht80_freq != exclude_ieee_freq) {
                ieee_freq = precac_entry->vht80_freq;
                break;
            }
        }
    }
    PRECAC_LIST_UNLOCK(ic);
    IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_DFS,
            "%s : %d ieee_freq=%u\n",__func__,__LINE__,ieee_freq);
    return ieee_freq;
}

void ieee80211_dfs_cancel_precac_timer(struct ieee80211com *ic)
{
    struct ieee80211_dfs_state *dfs = &ic->ic_dfs_state;

    OS_CANCEL_TIMER(&dfs->precac_timer);
    ic->ic_precac_timer_running = 0;
}

void ieee80211_dfs_start_precac_timer(struct ieee80211com *ic,uint8_t precac_chan)
{
    struct ieee80211_dfs_state *dfs = &ic->ic_dfs_state;
    struct ieee80211_channel *ichan;
    uint8_t first_primary_ic_ieee;
    int primary_cac_timeout;
    int secondary_cac_timeout;
    int precac_timeout;

#define EXTRA_TIME_IN_SEC 5
    ic->ic_precac_timer_running = 1;

    /* Get the first primary ieee chan in the HT80 band and find the channel pointer */
    first_primary_ic_ieee = precac_chan - VHT80_IEEE_FREQ_OFFSET;

    primary_cac_timeout = ieee80211_get_cac_timeout(ic,ic->ic_curchan);

    ichan = ieee80211_find_dot11_channel(ic, first_primary_ic_ieee, 0, IEEE80211_MODE_11AC_VHT80);
    secondary_cac_timeout = (dfs->precac_timeout_override != -1) ?
                                 dfs->precac_timeout_override :
                                 ieee80211_get_cac_timeout(ic,ichan);

    /*
     * EXTRA time is needed so that if CAC and PreCAC is running simultaneously,
     * PreCAC expiry function may be called before CAC expiry and PreCAC expiry
     * does a channel change (vdev_restart) the restart response calls CAC_start
     * function(ieee80211_dfs_cac_start) which cancels any previous CAC timer and
     * starts a new CAC again. So CAC expiry does not happen and moreover a new CAC
     * is started. Therefore do not disturb the CAC by channel restart (vdev_restart).
     */
    precac_timeout = MAX(primary_cac_timeout,secondary_cac_timeout)+ EXTRA_TIME_IN_SEC;
    IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_DFS,
            "%s : %d precactimeout=%d\n",__func__,__LINE__,(precac_timeout)*1000);
    OS_SET_TIMER(&dfs->precac_timer, (precac_timeout) * 1000);
}

void
ieee80211_print_precaclists(struct ieee80211com *ic)
{
    struct ieee80211_dfs_state *dfs = &ic->ic_dfs_state;
    struct ieee80211_precac_entry *tmp_precac_entry;

    PRECAC_LIST_LOCK(ic);

    /* Print the Pre-CAC required List */
    qdf_print("Pre-cac-required list of VHT80 frequencies\n");
    TAILQ_FOREACH(tmp_precac_entry,&dfs->precac_required_list,pe_list) {
        qdf_print("freq=%u \n",tmp_precac_entry->vht80_freq);
    }

    /* Print the Pre-CAC done List */
    qdf_print("Pre-cac-done list of VHT80 frequencies\n");
    TAILQ_FOREACH(tmp_precac_entry,&dfs->precac_done_list,pe_list) {
        qdf_print("freq=%u \n",tmp_precac_entry->vht80_freq);
    }

    /* Print the Pre-CAC NOL List */
    qdf_print("Pre-cac-NOL list of VHT80 frequencies\n");
    TAILQ_FOREACH(tmp_precac_entry,&dfs->precac_nol_list,pe_list) {
        qdf_print("freq=%u \n",tmp_precac_entry->vht80_freq);
    }

    PRECAC_LIST_UNLOCK(ic);
    return;
}
void
ieee80211_reset_precaclists(struct ieee80211com *ic)
{
    IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_DFS, "%s : %d Reset precaclist of VHT80 frequencies\n",__func__,__LINE__);
    ieee80211_dfs_deinit_precac_list(ic);
    ieee80211_dfs_init_precac_list(ic);
}
#endif
#else
int
ieee80211_dfs_cac_cancel(struct ieee80211com *ic)
{
	return 1; /* NON DFS mode */
}

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
int
ieee80211_dfs_stacac_cancel(struct ieee80211com *ic)
{
	return 1; /* NON DFS mode */
}
#endif

int
ieee80211_dfs_cac_start(struct ieee80211com *ic)
{

	return 1; /* NON DFS mode */
}

void
ieee80211_dfs_cac_stop(struct ieee80211vap *vap, int force)
{
}

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
void
ieee80211_dfs_stacac_stop(struct ieee80211vap *vap)
{
}
#endif

void
ieee80211_unmark_radar(struct ieee80211com *ic, struct ieee80211_channel *chan)
{

	/* XXX nothing to do here */
}

void ieee80211_bringup_ap_vaps(struct ieee80211com *ic)
{
}

#endif /* ATH_SUPPORT_DFS */
