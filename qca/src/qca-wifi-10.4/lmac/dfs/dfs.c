/*
 * Copyright (c) 2002-2006, Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <osdep.h>
#ifdef ATH_SUPPORT_DFS
#include "sys/queue.h"


#include "if_athioctl.h"
#include "if_athvar.h"
#include "dfs_ioctl.h"
#include "dfs.h"

int domainoverride=DFS_UNINIT_DOMAIN;

/*
 ** channel switch announcement (CSA)
 ** usenol=1 (default) make CSA and switch to a new channel on radar detect
 ** usenol=0, make CSA with next channel same as current on radar detect
 ** usenol=2, no CSA and stay on the same channel on radar detect
 **/

int usenol=1;
u_int32_t dfs_debug_level=ATH_DEBUG_DFS;

/*
 * Mark a channel as having interference detected upon it.
 *
 * This adds the interference marker to both the primary and
 * extension channel.
 *
 * XXX TODO: make the NOL and channel interference logic a bit smarter
 * so only the channel with the radar event is marked, rather than
 * both the primary and extension.
 */
static void
dfs_channel_mark_radar(struct ath_dfs *dfs, struct ieee80211_channel *chan)
{
    struct ieee80211_channel_list chan_info;
    int i;

    //chan->ic_flagext |= CHANNEL_INTERFERENCE;

    /*
     * If radar is detected in 40MHz mode, add both the primary and the
     * extension channels to the NOL. chan is the channel data we return
     * to the ath_dev layer which passes it on to the 80211 layer.
     * As we want the AP to change channels and send out a CSA,
     * we always pass back the primary channel data to the ath_dev layer.
     */
    if ((dfs->dfs_rinfo.rn_use_nol == 1) &&
      (dfs->ic->ic_opmode == IEEE80211_M_HOSTAP ||
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
       dfs->ic->ic_opmode == IEEE80211_M_IBSS ||
       ((dfs->ic->ic_opmode == IEEE80211_M_STA) &&
        (ieee80211com_has_cap_ext(dfs->ic,IEEE80211_CEXT_STADFS)))))
#else
        dfs->ic->ic_opmode == IEEE80211_M_IBSS))
#endif
    {
        chan_info.cl_nchans= 0;
        dfs->ic->ic_get_ext_chan_info (dfs->ic, chan, &chan_info);
        for (i = 0; i < chan_info.cl_nchans; i++)
        {
            if (chan_info.cl_channels[i] == NULL) {
                DFS_PRINTK("%s: NULL channel\n", __func__);
            } else {
                /* do not add non-DFS segment of current channel to NOL */
                if (IEEE80211_IS_CHAN_DFS(chan_info.cl_channels[i])) {
                    chan_info.cl_channels[i]->ic_flagext |= CHANNEL_INTERFERENCE;
                    ATH_DFSNOL_LOCK(dfs);
                    dfs_nol_addchan(dfs, chan_info.cl_channels[i], dfs->ath_dfs_nol_timeout);
                    ATH_DFSNOL_UNLOCK(dfs);
                } else {
                    DFS_DPRINTK(dfs, ATH_DEBUG_DFS_NOL,
                        "%s: Will not add non-DFS channel (freq=%d) to NOL\n",
                        __func__,  chan_info.cl_channels[i]->ic_freq);
                }
            }
        }


        /*
         * Update the umac/driver channels with the new NOL information.
         */
        ATH_DFSNOL_LOCK(dfs);
        dfs_nol_update(dfs);
        ATH_DFSNOL_UNLOCK(dfs);
    }
}

/* Timer function to wait for CSA from uplink after sending RCSA */
static OS_TIMER_FUNC(dfs_waitfor_csa_task)
{
    struct ieee80211com *ic;
    struct ath_dfs *dfs = NULL;

    OS_GET_TIMER_ARG(ic, struct ieee80211com *);
    dfs = (struct ath_dfs *)ic->ic_dfs;

    DFS_DPRINTK(dfs, ATH_DEBUG_DFS,
            "%s: waited long enough now change the channel\n",__func__);
    ic->ic_dfs_notify_radar(ic, ic->ic_curchan);
    dfs->ath_dfs_waitfor_csa_sched = 0;
}

/* Send 5 RCSAs to uplink every DFS_RCSA_INTVAL */
static OS_TIMER_FUNC(dfs_tx_rcsa_task)
{
    struct ieee80211com *ic;
    struct ieee80211vap *stavap = NULL;
    struct ath_dfs *dfs = NULL;

    OS_GET_TIMER_ARG(ic, struct ieee80211com *);
    dfs = (struct ath_dfs *)ic->ic_dfs;

    STA_VAP_DOWNUP_LOCK(ic);
    stavap = ic->ic_sta_vap;
    if(stavap && ieee80211_vap_ready_is_set(stavap) && ic->ic_rcsa_count) {
        DFS_DPRINTK(dfs, ATH_DEBUG_DFS,
                "%s: sending action frame, rcsa_count=%d\n", __func__,ic->ic_rcsa_count);
        ic->ic_dfs_send_rcsa(ic,stavap,ic->ic_rcsa_count,ic->ic_curchan->ic_ieee);
        OS_SET_TIMER(&dfs->ath_dfs_tx_rcsa_timer, DFS_RCSA_INTVAL);
        ic->ic_rcsa_count--;
        if (ic->ic_rcsa_count == 0) {
            dfs->update_nol = false;
        }
    }
    STA_VAP_DOWNUP_UNLOCK(ic);
}

static OS_TIMER_FUNC(dfs_task)
{
    struct ieee80211com *ic;
    struct ath_dfs *dfs = NULL;

    OS_GET_TIMER_ARG(ic, struct ieee80211com *);
    dfs = (struct ath_dfs *)ic->ic_dfs;
    /*
     * XXX no locking?!
     */
    if (dfs_process_radarevent(dfs, ic->ic_curchan)) {
#ifndef ATH_DFS_RADAR_DETECTION_ONLY

        /*
         * This marks the channel (and the extension channel, if HT40) as
         * having seen a radar event.  It marks CHAN_INTERFERENCE and
         * will add it to the local NOL implementation.
         *
         * This is only done for 'usenol=1', as the other two modes
         * don't do radar notification or CAC/CSA/NOL; it just notes
         * there was a radar.
         */
        if (dfs->dfs_rinfo.rn_use_nol == 1) {
#if ATH_SUPPORT_ZERO_CAC_DFS
            /*
             * If precac is running and the radar found in secondary VHT80
             * mark the channel as radar and add to NOL list. Otherwise
             * random channel selection can choose this channel.
             */
            DFS_DPRINTK(dfs, ATH_DEBUG_DFS, "%s : %d found_on_second=%d "
                    "is_pre=%d\n",__func__, __LINE__, dfs->is_radar_found_on_secondary_seg,
                    ic->ic_dfs_is_precac_timer_running(ic));

            if(dfs->is_radar_found_on_secondary_seg && ic->ic_dfs_is_precac_timer_running(ic)) {
                /* Get a VHT80 channel and mark it */
                struct ieee80211_channel *ichan = ic->ic_dfs_find_precac_secondary_vht80_chan(ic);
                dfs_channel_mark_radar(dfs,ichan);
            } else
#endif
            {
                dfs_channel_mark_radar(dfs, ic->ic_curchan);
            }
        }
#endif /* ATH_DFS_RADAR_DETECTION_ONLY */
        IEEE80211_CHANCHANGE_MARKRADAR_CLEAR(ic);

#if ATH_SUPPORT_ZERO_CAC_DFS
        /*
         * Even if radar found on primary, we need to move the channel from
         * precac-required-list and precac-done-list to precac-nol-list.
         */
        if (dfs->dfs_rinfo.rn_use_nol == 1) {
            ic->ic_dfs_notify_precac_radar(ic, dfs->is_radar_found_on_secondary_seg);
        }

        if (dfs->is_radar_found_on_secondary_seg) {
            if (dfs->dfs_rinfo.rn_use_nol == 1) {
                dfs_second_segment_radar_disable(ic);
            }
            dfs->is_radar_found_on_secondary_seg = 0;
            if(dfs->is_radar_during_precac){
                dfs->is_radar_during_precac = 0;
                goto radar_process_end;
            }
        }
#endif

        /*
         * This calls into the umac DFS code, which sets the umac related
         * radar flags and begins the channel change machinery.
         *
         * XXX TODO: the umac NOL code isn't used, but IEEE80211_CHAN_RADAR
         * still gets set.  Since the umac NOL code isn't used, that flag
         * is never cleared.  This needs to be fixed. See EV 105776.
         */
        if (dfs->dfs_rinfo.rn_use_nol == 1)  {
            if(IEEE80211_IS_CSH_RCSA_TO_UPLINK_ENABLED(ic)) {
                /* Do not handle the radar detect here the Repeater sends RCSA
                 * to its parent Repeater/Root and wait for CSA. The Radar
                 * detect is handled after receiveing the CSA or wait for CSA
                 * timer expires.
                 */
                struct ieee80211vap *stavap = NULL;

                STA_VAP_DOWNUP_LOCK(ic);
                stavap = ic->ic_sta_vap;
                if(stavap && ieee80211_vap_ready_is_set(stavap)) {
                    dfs_radar_disable(ic);
#if ATH_SUPPORT_ZERO_CAC_DFS
                    dfs_second_segment_radar_disable(ic);
#endif
                    dfs_start_tx_rcsa_and_waitfor_rx_csa(ic);
                    STA_VAP_DOWNUP_UNLOCK(ic);
                    return;
                } else {
                    DFS_DPRINTK(dfs, ATH_DEBUG_DFS,
                            "%s: No uplink found so handle RADAR as before\n",__func__);
                }
                STA_VAP_DOWNUP_UNLOCK(ic);
            }

            ic->ic_dfs_notify_radar(ic, ic->ic_curchan);
            /*
                EV 129487 :
                we have detected radar in the channel, stop processing
                PHY error data as this can cause false detect in the new
                channel while channel change is in progress
            */

            dfs_radar_disable(ic);
#if ATH_SUPPORT_ZERO_CAC_DFS
            dfs_second_segment_radar_disable(ic);
#endif
        } else if (dfs->dfs_rinfo.rn_use_nol == 0) {
            /*
             * For the test mode, don't do a CSA here; but setup the
             * test timer so we get a CSA _back_ to the original channel.
             */
            OS_CANCEL_TIMER(&dfs->ath_dfstesttimer);
            dfs->ath_dfstest = 1;
            dfs->ath_dfstest_ieeechan = ic->ic_curchan->ic_ieee;
            dfs->ath_dfstesttime = 1;   /* 1ms */
            OS_SET_TIMER(&dfs->ath_dfstesttimer, dfs->ath_dfstesttime);
        }
    }
#if ATH_SUPPORT_ZERO_CAC_DFS
radar_process_end:
#endif
    dfs->ath_radar_tasksched = 0;
}

static
OS_TIMER_FUNC(dfs_testtimer_task)
{
    struct ieee80211com *ic;
    struct ath_dfs *dfs = NULL;

    OS_GET_TIMER_ARG(ic, struct ieee80211com *);
    dfs = (struct ath_dfs *)ic->ic_dfs;

    /* XXX no locking? */
    dfs->ath_dfstest = 0;

    /*
     * Flip the channel back to the original channel.
     * Make sure this is done properly with a CSA.
     */
    DFS_PRINTK("%s: go back to channel %d\n",
        __func__,
        dfs->ath_dfstest_ieeechan);

    /*
     * XXX The mere existence of this method indirection
     *     to a umac function means this code belongs in
     *     the driver, _not_ here.  Please fix this!
     */
    ic->ic_start_csa(ic, dfs->ath_dfstest_ieeechan);
}


static int dfs_get_debug_info(struct ieee80211com *ic, int type, void *data)
{
	struct ath_dfs                 *dfs=(struct ath_dfs *)ic->ic_dfs;
    if (data) {
        *(u_int32_t *)data = dfs->dfs_proc_phyerr;
    }
    return (int)dfs->dfs_proc_phyerr;
}

int
dfs_attach(struct ieee80211com *ic)
{
    int i, n;
    struct ath_dfs *dfs = (struct ath_dfs *)ic->ic_dfs;
    struct ath_dfs_radar_tab_info radar_info;
#define	N(a)	(sizeof(a)/sizeof(a[0]))

    if (dfs != NULL) {
        DFS_DPRINTK(dfs, ATH_DEBUG_DFS1,
          "%s: ic_dfs was not NULL\n",
          __func__);
        return 1;
    }
    if (ic->ic_dfs_state.ignore_dfs) {
        DFS_DPRINTK(dfs, ATH_DEBUG_DFS1,
          "%s: ignoring dfs\n",
          __func__);
        return 0;
    }
    dfs = (struct ath_dfs *)OS_MALLOC(ic->ic_osdev, sizeof(struct ath_dfs), GFP_ATOMIC);
    if (dfs == NULL) {
        DFS_DPRINTK(dfs, ATH_DEBUG_DFS1,
          "%s: ath_dfs allocation failed\n", __func__);
        return 1;
    }
    OS_MEMZERO(dfs, sizeof (struct ath_dfs));
    ic->ic_dfs = (void *)dfs;
    dfs->ic = ic;
    ic->ic_dfs_debug = dfs_get_debug_info;
#ifndef ATH_DFS_RADAR_DETECTION_ONLY
    dfs->dfs_nol = NULL;
#endif

    /*
     * Zero out radar_info.  It's possible that the attach function won't
     * fetch an initial regulatory configuration; you really do want to
     * ensure that the contents indicates there aren't any filters.
     */
    OS_MEMZERO(&radar_info, sizeof(radar_info));
    ic->ic_dfs_attach(ic, &dfs->dfs_caps, &radar_info);
    dfs_clear_stats(ic);
    dfs->dfs_event_log_on = 1;
    DFS_PRINTK("%s: event log enabled by default\n", __func__);
    /* qdf_timer_init(ic->ic_osdev, &(dfs->ath_dfs_task_timer), dfs_task, (void *) (ic)); */

    OS_INIT_TIMER(ic->ic_osdev, &(dfs->ath_dfs_task_timer), dfs_task, (void *) (ic), QDF_TIMER_TYPE_WAKE_APPS);
    OS_INIT_TIMER(ic->ic_osdev, &(dfs->ath_dfs_tx_rcsa_timer), dfs_tx_rcsa_task, (void *) (ic), QDF_TIMER_TYPE_WAKE_APPS);
    OS_INIT_TIMER(ic->ic_osdev, &(dfs->ath_dfs_waitfor_csa_timer), dfs_waitfor_csa_task, (void *) (ic), QDF_TIMER_TYPE_WAKE_APPS);
#ifndef ATH_DFS_RADAR_DETECTION_ONLY
    OS_INIT_TIMER(ic->ic_osdev, &(dfs->ath_dfstesttimer), dfs_testtimer_task, (void *) ic, QDF_TIMER_TYPE_WAKE_APPS);
    dfs->ath_dfs_cac_time = ATH_DFS_WAIT_MS;
    dfs->ath_dfstesttime = ATH_DFS_TEST_RETURN_PERIOD_MS;
#endif
    ATH_DFSQ_LOCK_INIT(dfs);
    STAILQ_INIT(&dfs->dfs_radarq);
    ATH_ARQ_LOCK_INIT(dfs);
    STAILQ_INIT(&dfs->dfs_arq);
    STAILQ_INIT(&(dfs->dfs_eventq));
    ATH_DFSEVENTQ_LOCK_INIT(dfs);
    ATH_DFSNOL_LOCK_CREATE(dfs);

    dfs->events = (struct dfs_event *)OS_MALLOC(ic->ic_osdev,
                   sizeof(struct dfs_event)*DFS_MAX_EVENTS,
                   GFP_ATOMIC);
    if (dfs->events == NULL) {
        OS_FREE(dfs);
        ic->ic_dfs = NULL;
        DFS_PRINTK("%s: events allocation failed\n", __func__);
        return 1;
    }
    for (i = 0; i < DFS_MAX_EVENTS; i++) {
        STAILQ_INSERT_TAIL(&(dfs->dfs_eventq), &dfs->events[i], re_list);
    }

    dfs->pulses = (struct dfs_pulseline *)OS_MALLOC(ic->ic_osdev, sizeof(struct dfs_pulseline), GFP_ATOMIC);
    if (dfs->pulses == NULL) {
            OS_FREE(dfs->events);
            dfs->events = NULL;
            OS_FREE(dfs);
            ic->ic_dfs = NULL;
            DFS_PRINTK("%s: pulse buffer allocation failed\n", __func__);
            return 1;
    }

    dfs->pulses->pl_lastelem = DFS_MAX_PULSE_BUFFER_MASK;

            /* Allocate memory for radar filters */
    for (n=0; n<DFS_MAX_RADAR_TYPES; n++) {
    	dfs->dfs_radarf[n] = (struct dfs_filtertype *)OS_MALLOC(ic->ic_osdev, sizeof(struct dfs_filtertype),GFP_ATOMIC);
    	if (dfs->dfs_radarf[n] == NULL) {
    		DFS_PRINTK("%s: cannot allocate memory for radar filter types\n",
    			__func__);
    		goto bad1;
    	}
    	OS_MEMZERO(dfs->dfs_radarf[n], sizeof(struct dfs_filtertype));
    }
            /* Allocate memory for radar table */
    dfs->dfs_radartable = (int8_t **)OS_MALLOC(ic->ic_osdev, 256*sizeof(int8_t *), GFP_ATOMIC);
    if (dfs->dfs_radartable == NULL) {
    	DFS_PRINTK("%s: cannot allocate memory for radar table\n",
    		__func__);
    	goto bad1;
    }
    for (n=0; n<256; n++) {
    	dfs->dfs_radartable[n] = OS_MALLOC(ic->ic_osdev, DFS_MAX_RADAR_OVERLAP*sizeof(int8_t),
    					 GFP_ATOMIC);
    	if (dfs->dfs_radartable[n] == NULL) {
    		DFS_PRINTK("%s: cannot allocate memory for radar table entry\n",
    			__func__);
    		goto bad2;
    	}
    }

    if (usenol == 0)
        DFS_PRINTK("%s: NOL disabled\n", __func__);
    else if (usenol == 2)
        DFS_PRINTK("%s: NOL disabled; no CSA\n", __func__);

    dfs->dfs_rinfo.rn_use_nol = usenol;

    /* Init the cached extension channel busy for false alarm reduction */
    dfs->dfs_rinfo.ext_chan_busy_ts = ic->ic_get_TSF64(ic);
    dfs->dfs_rinfo.dfs_ext_chan_busy = 0;
    /* Init the Bin5 chirping related data */
    dfs->dfs_rinfo.dfs_bin5_chirp_ts = dfs->dfs_rinfo.ext_chan_busy_ts;
    dfs->dfs_rinfo.dfs_last_bin5_dur = MAX_BIN5_DUR;
    dfs->dfs_b5radars = NULL;

    /*
     * If dfs_init_radar_filters() fails, we can abort here and
     * reconfigure when the first valid channel + radar config
     * is available.
     */
    if ( dfs_init_radar_filters( ic,  &radar_info) ) {
        DFS_PRINTK(" %s: Radar Filter Intialization Failed \n",
                    __func__);
            return 1;
    }

    dfs->ath_dfs_false_rssi_thres = RSSI_POSSIBLY_FALSE;
    dfs->ath_dfs_peak_mag = SEARCH_FFT_REPORT_PEAK_MAG_THRSH;
    dfs->dfs_phyerr_freq_min     = 0x7fffffff;
    dfs->dfs_phyerr_freq_max     = 0;
    dfs->dfs_phyerr_queued_count = 0;
    dfs->dfs_phyerr_w53_counter  = 0;
    dfs->dfs_pri_multiplier      = 2;

    dfs->ath_dfs_nol_timeout = DFS_NOL_TIMEOUT_S;

    return 0;

bad2:
    OS_FREE(dfs->dfs_radartable);
    dfs->dfs_radartable = NULL;
bad1:
    for (n=0; n<DFS_MAX_RADAR_TYPES; n++) {
        if (dfs->dfs_radarf[n] != NULL) {
        	OS_FREE(dfs->dfs_radarf[n]);
        	dfs->dfs_radarf[n] = NULL;
        }
    }
    if (dfs->pulses) {
        OS_FREE(dfs->pulses);
        dfs->pulses = NULL;
    }
    if (dfs->events) {
        OS_FREE(dfs->events);
        dfs->events = NULL;
    }

    if (ic->ic_dfs) {
        OS_FREE(ic->ic_dfs);
        ic->ic_dfs = NULL;
    }
    return 1;
#undef N
}

void dfs_reset(struct ieee80211com *ic)
{
    struct ath_dfs *dfs = (struct ath_dfs *)ic->ic_dfs;

    if (dfs == NULL) {
        DFS_DPRINTK(dfs, ATH_DEBUG_DFS_NOL, "%s: sc_dfs is NULL\n", __func__);
        return;
    }

    if (dfs->ath_radar_tasksched) {
        OS_CANCEL_TIMER(&dfs->ath_dfs_task_timer);
        dfs->ath_radar_tasksched = 0;
    }

    if (dfs->ath_dfstest) {
        OS_CANCEL_TIMER(&dfs->ath_dfstesttimer);
        dfs->ath_dfstest = 0;
    }

    dfs_nol_timer_cleanup(dfs);
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
    ic->ic_dfs_clear_nolhistory(ic);
#endif
}
EXPORT_SYMBOL(dfs_reset);

void
dfs_detach(struct ieee80211com *ic)
{
	struct ath_dfs *dfs = (struct ath_dfs *)ic->ic_dfs;
	int n, empty;

	if (dfs == NULL) {
	        DFS_DPRINTK(dfs, ATH_DEBUG_DFS1, "%s: ic_dfs is NULL\n", __func__);
		return;
	}

        /* Bug 29099 make sure all outstanding timers are cancelled*/

        if (dfs->ath_radar_tasksched) {
            OS_CANCEL_TIMER(&dfs->ath_dfs_task_timer);
            dfs->ath_radar_tasksched = 0;
        }

        OS_CANCEL_TIMER(&dfs->ath_dfs_tx_rcsa_timer);
        if(dfs->ath_dfs_waitfor_csa_sched) {
            OS_CANCEL_TIMER(&dfs->ath_dfs_waitfor_csa_timer);
            dfs->ath_dfs_waitfor_csa_sched = 0;
        }

	if (dfs->ath_dfstest) {
		OS_CANCEL_TIMER(&dfs->ath_dfstesttimer);
		dfs->ath_dfstest = 0;
	}

#if 0
#ifndef ATH_DFS_RADAR_DETECTION_ONLY
        if (dfs->ic_dfswait) {
            OS_CANCEL_TIMER(&dfs->ic_dfswaittimer);
            dfs->ath_dfswait = 0;
        }

 		OS_CANCEL_TIMER(&dfs->sc_dfs_war_timer);
	if (dfs->dfs_nol != NULL) {
	    struct dfs_nolelem *nol, *next;
	    nol = dfs->dfs_nol;
                /* Bug 29099 - each NOL element has its own timer, cancel it and
                   free the element*/
		while (nol != NULL) {
                       OS_CANCEL_TIMER(&nol->nol_timer);
		       next = nol->nol_next;
		       OS_FREE(nol);
		       nol = next;
		}
		dfs->dfs_nol = NULL;
	}
#endif
#endif
        /* Return radar events to free q*/
        dfs_reset_radarq(dfs);
	dfs_reset_alldelaylines(dfs);

        /* Free up pulse log*/
        if (dfs->pulses != NULL) {
                OS_FREE(dfs->pulses);
                dfs->pulses = NULL;
        }

	for (n=0; n<DFS_MAX_RADAR_TYPES;n++) {
		if (dfs->dfs_radarf[n] != NULL) {
			OS_FREE(dfs->dfs_radarf[n]);
			dfs->dfs_radarf[n] = NULL;
		}
	}


	if (dfs->dfs_radartable != NULL) {
		for (n=0; n<256; n++) {
			if (dfs->dfs_radartable[n] != NULL) {
				OS_FREE(dfs->dfs_radartable[n]);
				dfs->dfs_radartable[n] = NULL;
			}
		}
		OS_FREE(dfs->dfs_radartable);
		dfs->dfs_radartable = NULL;
#ifndef ATH_DFS_RADAR_DETECTION_ONLY
		dfs->ath_dfs_isdfsregdomain = 0;
#endif
	}

	if (dfs->dfs_b5radars != NULL) {
		OS_FREE(dfs->dfs_b5radars);
		dfs->dfs_b5radars=NULL;
	}

	dfs_reset_ar(dfs);

	ATH_ARQ_LOCK(dfs);
	empty = STAILQ_EMPTY(&(dfs->dfs_arq));
	ATH_ARQ_UNLOCK(dfs);
	if (!empty) {
		dfs_reset_arq(dfs);
	}
    if (dfs->events != NULL) {
        OS_FREE(dfs->events);
        dfs->events = NULL;
    }
    dfs_nol_timer_cleanup(dfs);

    ATH_DFSNOL_LOCK_DESTROY(dfs);

	OS_FREE(dfs);

	/* XXX? */
        ic->ic_dfs = NULL;
}
/*
 * This is called each time a channel change occurs, to (potentially) enable
 * the radar code.
 */
int dfs_radar_disable(struct ieee80211com *ic)
{
    struct ath_dfs                 *dfs=(struct ath_dfs *)ic->ic_dfs;
#ifdef ATH_ENABLE_AR
    dfs->dfs_proc_phyerr &= ~DFS_AR_EN;
#endif
    dfs->dfs_proc_phyerr &= ~DFS_RADAR_EN;
    return 0;
}

#if ATH_SUPPORT_ZERO_CAC_DFS
int dfs_second_segment_radar_disable(struct ieee80211com *ic)
{
    struct ath_dfs *dfs=(struct ath_dfs *)ic->ic_dfs;
    dfs->dfs_proc_phyerr &= ~DFS_SECOND_SEGMENT_RADAR_EN;
    return 0;
}
#endif

/*
 * This is called each time a channel change occurs, to (potentially) enable
 * the radar code.
 */
int dfs_radar_enable(struct ieee80211com *ic,
    struct ath_dfs_radar_tab_info *radar_info, int no_cac)
{
    int                                 is_ext_ch=IEEE80211_IS_CHAN_11N_HT40(ic->ic_curchan);
    int                                 is_fastclk = 0;
    //u_int32_t                        rfilt;
    struct ath_dfs                 *dfs=(struct ath_dfs *)ic->ic_dfs;
    struct ieee80211_channel *chan=ic->ic_curchan, *ext_ch = NULL;

	if (dfs == NULL) {
		DFS_DPRINTK(dfs, ATH_DEBUG_DFS, "%s: ic_dfs is NULL\n",
			__func__);
		return -EIO;
	}
	ic->ic_dfs_disable(ic, no_cac);

	/*
	 * Setting country code might change the DFS domain
	 * so initialize the DFS Radar filters
	 */
	dfs_init_radar_filters(ic, radar_info);
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
	if ((ic->ic_opmode == IEEE80211_M_HOSTAP || ic->ic_opmode == IEEE80211_M_IBSS ||
                (ic->ic_opmode == IEEE80211_M_STA && ieee80211com_has_cap_ext(dfs->ic,IEEE80211_CEXT_STADFS)))) {
#else
	if ((ic->ic_opmode == IEEE80211_M_HOSTAP || ic->ic_opmode == IEEE80211_M_IBSS)) {
#endif
                /*
                    In all modes, if the primary is DFS then we have to enable radar detection.
                    In HT80_80, we can have primary non-DFS 80MHz with  extension 80MHz DFS
                */
        if ((IEEE80211_IS_CHAN_DFS(chan) ||
                    ((IEEE80211_IS_CHAN_11AC_VHT160(chan) || IEEE80211_IS_CHAN_11AC_VHT80_80(chan)) &&
                     IEEE80211_IS_CHAN_DFS_CFREQ2(chan))) ||
                (ic->ic_dfs_is_precac_timer_running(ic))) {
			struct dfs_state *rs_pri=NULL, *rs_ext=NULL;
			u_int8_t index_pri, index_ext;
#ifdef ATH_ENABLE_AR
    dfs->dfs_proc_phyerr |= DFS_AR_EN;
#endif
    dfs->dfs_proc_phyerr |= DFS_RADAR_EN;
#if ATH_SUPPORT_ZERO_CAC_DFS
    dfs->dfs_proc_phyerr |= DFS_SECOND_SEGMENT_RADAR_EN;
#endif
    //printk( "%s[%d]: ==== 0x%08x\n", __func__, __LINE__, dfs->dfs_proc_phyerr);


                   if (is_ext_ch) {
                       ext_ch = ieee80211_get_extchan(ic);
                   }
			dfs_reset_alldelaylines(dfs);

			rs_pri = dfs_getchanstate(dfs, &index_pri, 0);
			if (ext_ch) {
                            rs_ext = dfs_getchanstate(dfs, &index_ext, 1);
                   }
    			if (rs_pri != NULL && ((ext_ch==NULL)||(rs_ext != NULL))) {
				struct ath_dfs_phyerr_param pe;

				OS_MEMSET(&pe, '\0', sizeof(pe));

				if (index_pri != dfs->dfs_curchan_radindex)
					dfs_reset_alldelaylines(dfs);

				dfs->dfs_curchan_radindex = (int16_t) index_pri;

                                if (rs_ext)
			            dfs->dfs_extchan_radindex = (int16_t) index_ext;

				ath_dfs_phyerr_param_copy(&pe,
				    &rs_pri->rs_param);
				DFS_DPRINTK(dfs, ATH_DEBUG_DFS3,
				    "%s: firpwr=%d, rssi=%d, height=%d, "
				    "prssi=%d, inband=%d, relpwr=%d, "
				    "relstep=%d, maxlen=%d\n",
				    __func__,
				    pe.pe_firpwr,
				    pe.pe_rrssi,
				    pe.pe_height,
				    pe.pe_prssi,
				    pe.pe_inband,
				    pe.pe_relpwr,
				    pe.pe_relstep,
				    pe.pe_maxlen
				    );

#if 0 //Not needed
				/* Disable strong signal fast antenna diversity */
				ath_hal_setcapability(ah, HAL_CAP_DIVERSITY,
						      HAL_CAP_STRONG_DIV, 1, NULL);
#endif
	                    ic->ic_dfs_enable(ic, &is_fastclk, &pe);
				DFS_DPRINTK(dfs, ATH_DEBUG_DFS, "Enabled radar detection on channel %d\n",
					chan->ic_freq);

                                dfs->dur_multiplier =  is_fastclk ? DFS_FAST_CLOCK_MULTIPLIER : DFS_NO_FAST_CLOCK_MULTIPLIER;
                    	DFS_DPRINTK(dfs, ATH_DEBUG_DFS3,
			"%s: duration multiplier is %d\n", __func__, dfs->dur_multiplier);

			} else
				DFS_DPRINTK(dfs, ATH_DEBUG_DFS, "%s: No more radar states left\n",
					__func__);
		}
	}
	return 0;
}

int
dfs_control(struct ieee80211com *ic, u_int id,
                void *indata, u_int32_t insize,
                void *outdata, u_int32_t *outsize)
{
	int error = 0;
	struct ath_dfs_phyerr_param peout;
	struct ath_dfs *dfs = (struct ath_dfs *)ic->ic_dfs;
	struct dfs_ioctl_params *dfsparams;
    u_int32_t val=0;
#ifndef ATH_DFS_RADAR_DETECTION_ONLY
    struct dfsreq_nolinfo *nol;
    u_int32_t *data = NULL;
#endif /* ATH_DFS_RADAR_DETECTION_ONLY */
    int i;

	if (dfs == NULL) {
                DFS_DPRINTK(dfs, ATH_DEBUG_DFS1, "%s DFS is null\n", __func__);
                /* Enable/Disable DFS can be done prior to attach, So handle here */
	switch (id) {
        case DFS_DISABLE_DETECT:
                ic->ic_dfs_state.ignore_dfs = 1;
                DFS_PRINTK("%s enable detects, ignore_dfs %d\n",
                    __func__,
		   ic->ic_dfs_state.ignore_dfs ? 1:0);
                break;
        case DFS_ENABLE_DETECT:
                ic->ic_dfs_state.ignore_dfs = 0;
                DFS_PRINTK("%s enable detects, ignore_dfs %d\n",
                    __func__,
		    ic->ic_dfs_state.ignore_dfs ? 1:0);
                break;
        default:
            error = -EINVAL;
            break;
       }
		goto bad;
	}

      //printk("%s[%d] id =%d\n", __func__, __LINE__, id);
	switch (id) {
	case DFS_SET_THRESH:
		if (insize < sizeof(struct dfs_ioctl_params) || !indata) {
			DFS_DPRINTK(dfs, ATH_DEBUG_DFS1,
			    "%s: insize=%d, expected=%d bytes, indata=%p\n",
			    __func__, insize, sizeof(struct dfs_ioctl_params),
			    indata);
			error = -EINVAL;
			break;
		}
		dfsparams = (struct dfs_ioctl_params *) indata;
		if (!dfs_set_thresholds(ic, DFS_PARAM_FIRPWR, dfsparams->dfs_firpwr))
			error = -EINVAL;
		if (!dfs_set_thresholds(ic, DFS_PARAM_RRSSI, dfsparams->dfs_rrssi))
			error = -EINVAL;
		if (!dfs_set_thresholds(ic, DFS_PARAM_HEIGHT, dfsparams->dfs_height))
			error = -EINVAL;
		if (!dfs_set_thresholds(ic, DFS_PARAM_PRSSI, dfsparams->dfs_prssi))
			error = -EINVAL;
		if (!dfs_set_thresholds(ic, DFS_PARAM_INBAND, dfsparams->dfs_inband))
			error = -EINVAL;
		/* 5413 speicfic */
		if (!dfs_set_thresholds(ic, DFS_PARAM_RELPWR, dfsparams->dfs_relpwr))
			error = -EINVAL;
		if (!dfs_set_thresholds(ic, DFS_PARAM_RELSTEP, dfsparams->dfs_relstep))
			error = -EINVAL;
		if (!dfs_set_thresholds(ic, DFS_PARAM_MAXLEN, dfsparams->dfs_maxlen))
			error = -EINVAL;
		break;
	case DFS_GET_THRESH:
		if (!outdata || !outsize || *outsize <sizeof(struct dfs_ioctl_params)) {
			error = -EINVAL;
			break;
		}
		*outsize = sizeof(struct dfs_ioctl_params);
		dfsparams = (struct dfs_ioctl_params *) outdata;

		/*
		 * Fetch the DFS thresholds using the internal representation.
		 */
		(void) dfs_get_thresholds(ic, &peout);

		/*
		 * Convert them to the dfs IOCTL representation.
		 */
		ath_dfs_dfsparam_to_ioctlparam(&peout, dfsparams);
                break;
	case DFS_RADARDETECTS:
		if (!outdata || !outsize || *outsize < sizeof(u_int32_t)) {
			error = -EINVAL;
			break;
		}
		*outsize = sizeof (u_int32_t);
		*((u_int32_t *)outdata) = dfs->ath_dfs_stats.num_radar_detects;
		break;
        case DFS_DISABLE_DETECT:
                dfs->dfs_proc_phyerr &= ~DFS_RADAR_EN;
#if ATH_SUPPORT_ZERO_CAC_DFS
                dfs->dfs_proc_phyerr &= ~DFS_SECOND_SEGMENT_RADAR_EN;
#endif
                dfs->ic->ic_dfs_state.ignore_dfs = 1;
                DFS_PRINTK("%s enable detects, ignore_dfs %d\n",
                    __func__,
		    dfs->ic->ic_dfs_state.ignore_dfs ? 1:0);
                break;
        case DFS_ENABLE_DETECT:
                dfs->dfs_proc_phyerr |= DFS_RADAR_EN;
#if ATH_SUPPORT_ZERO_CAC_DFS
                dfs->dfs_proc_phyerr |= DFS_SECOND_SEGMENT_RADAR_EN;
#endif
                dfs->ic->ic_dfs_state.ignore_dfs = 0;
                DFS_PRINTK("%s enable detects, ignore_dfs %d\n",
                    __func__,
		    dfs->ic->ic_dfs_state.ignore_dfs ? 1:0);
                break;
        case DFS_DISABLE_FFT:
                //UMACDFS: TODO: val = ath_hal_dfs_config_fft(sc->sc_ah, false);
                DFS_PRINTK("%s TODO disable FFT val=0x%x \n", __func__, val);
                break;
        case DFS_ENABLE_FFT:
                //UMACDFS TODO: val = ath_hal_dfs_config_fft(sc->sc_ah, true);
                DFS_PRINTK("%s TODO enable FFT val=0x%x \n", __func__, val);
                break;
        case DFS_SET_DEBUG_LEVEL:
		if (insize < sizeof(u_int32_t) || !indata) {
			error = -EINVAL;
			break;
		}
		dfs->dfs_debug_mask= *(u_int32_t *)indata;
		DFS_PRINTK("%s debug level now = 0x%x \n",
		    __func__,
		    dfs->dfs_debug_mask);
                if (dfs->dfs_debug_mask & ATH_DEBUG_DFS3) {
                    /* Enable debug Radar Event */
                    dfs->dfs_event_log_on = 1;
                } else {
                    dfs->dfs_event_log_on = 0;
                }
                break;
        case DFS_SET_FALSE_RSSI_THRES:
		if (insize < sizeof(u_int32_t) || !indata) {
			error = -EINVAL;
			break;
		}
		dfs->ath_dfs_false_rssi_thres= *(u_int32_t *)indata;
		DFS_PRINTK("%s false RSSI threshold now = 0x%x \n",
		    __func__,
		    dfs->ath_dfs_false_rssi_thres);
                break;
        case DFS_SET_PEAK_MAG:
		if (insize < sizeof(u_int32_t) || !indata) {
			error = -EINVAL;
			break;
		}
		dfs->ath_dfs_peak_mag= *(u_int32_t *)indata;
		DFS_PRINTK("%s peak_mag now = 0x%x \n",
		    __func__,
		    dfs->ath_dfs_peak_mag);
                break;
	case DFS_GET_CAC_VALID_TIME:
		if (!outdata || !outsize || *outsize < sizeof(u_int32_t)) {
			error = -EINVAL;
			break;
		}
		*outsize = sizeof (u_int32_t);
		*((u_int32_t *)outdata) = dfs->ic->ic_dfs_state.cac_valid_time;
		break;
        case DFS_SET_CAC_VALID_TIME:
		if (insize < sizeof(u_int32_t) || !indata) {
			error = -EINVAL;
			break;
		}
		dfs->ic->ic_dfs_state.cac_valid_time = *(u_int32_t *)indata;
		DFS_PRINTK("%s dfs timeout = %d \n",
		    __func__,
		    dfs->ic->ic_dfs_state.cac_valid_time);
                break;
        case DFS_IGNORE_CAC:
		if (insize < sizeof(u_int32_t) || !indata) {
			error = -EINVAL;
			break;
		}
             if (*(u_int32_t *)indata) {
                 dfs->ic->ic_dfs_state.ignore_cac= 1;
             } else {
                 dfs->ic->ic_dfs_state.ignore_cac= 0;
             }
		DFS_PRINTK("%s ignore cac = 0x%x \n",
		    __func__,
		    dfs->ic->ic_dfs_state.ignore_cac);
                break;
        case DFS_SET_NOL_TIMEOUT:
		if (insize < sizeof(u_int32_t) || !indata) {
			error = -EINVAL;
			break;
		}
             if (*(int *)indata) {
                 dfs->ath_dfs_nol_timeout= *(int *)indata;
             } else {
                 dfs->ath_dfs_nol_timeout= DFS_NOL_TIMEOUT_S;
             }
		DFS_PRINTK("%s nol timeout = %d sec \n",
		    __func__,
		    dfs->ath_dfs_nol_timeout);
                break;
#ifndef ATH_DFS_RADAR_DETECTION_ONLY
    case DFS_MUTE_TIME:
        if (insize < sizeof(u_int32_t) || !indata) {
            error = -EINVAL;
            break;
        }
        data = (u_int32_t *) indata;
        dfs->ath_dfstesttime = *data;
        dfs->ath_dfstesttime *= (1000); //convert sec into ms
        break;
	case DFS_GET_USENOL:
		if (!outdata || !outsize || *outsize < sizeof(u_int32_t)) {
			error = -EINVAL;
			break;
		}
		*outsize = sizeof(u_int32_t);
		*((u_int32_t *)outdata) = dfs->dfs_rinfo.rn_use_nol;
                 QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:#Phyerr=%d, #false detect=%d, #queued=%d\n", __func__,dfs->dfs_phyerr_count, dfs->dfs_phyerr_reject_count, dfs->dfs_phyerr_queued_count);
                 QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:dfs_phyerr_freq_min=%d, dfs_phyerr_freq_max=%d\n", __func__,dfs->dfs_phyerr_freq_min, dfs->dfs_phyerr_freq_max);
                 QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:Total radar events detected=%d, entries in the radar queue follows:\n",  __func__,dfs->dfs_event_log_count);
                 for (i = 0; (i < DFS_EVENT_LOG_SIZE) && (i < dfs->dfs_event_log_count); i++) {
                     DFS_DPRINTK(dfs, ATH_DEBUG_DFS, "ts=%llu diff_ts=%u rssi=%u dur=%u, is_chirp=%d, seg_id=%d, sidx=%d, freq_offset=%d.%dMHz, peak_mag=%d, total_gain=%d, mb_gain=%d, relpwr_db=%d\n",
                                dfs->radar_log[i].ts, dfs->radar_log[i].diff_ts, dfs->radar_log[i].rssi, dfs->radar_log[i].dur, dfs->radar_log[i].is_chirp,
                                dfs->radar_log[i].seg_id, dfs->radar_log[i].sidx, (int) dfs->radar_log[i].freq_offset_khz/1000,
                                (int) abs(dfs->radar_log[i].freq_offset_khz)%1000, dfs->radar_log[i].peak_mag,
                                dfs->radar_log[i].total_gain, dfs->radar_log[i].mb_gain, dfs->radar_log[i].relpwr_db);
                 }
                 dfs->dfs_event_log_count     = 0;
                 dfs->dfs_phyerr_count        = 0;
                 dfs->dfs_phyerr_reject_count = 0;
                 dfs->dfs_phyerr_queued_count = 0;
                dfs->dfs_phyerr_freq_min     = 0x7fffffff;
                dfs->dfs_phyerr_freq_max     = 0;
		break;
	case DFS_SET_USENOL:
		if (insize < sizeof(u_int32_t) || !indata) {
			error = -EINVAL;
			break;
		}
		dfs->dfs_rinfo.rn_use_nol = *(u_int32_t *)indata;
		/* iwpriv markdfs in linux can do the same thing... */
		break;
	case DFS_GET_NOL:
		if (!outdata || !outsize || *outsize < sizeof(struct dfsreq_nolinfo)) {
			error = -EINVAL;
			break;
		}
		*outsize = sizeof(struct dfsreq_nolinfo);
		nol = (struct dfsreq_nolinfo *)outdata;
		ATH_DFSNOL_LOCK(dfs);
		dfs_get_nol(dfs, (struct dfsreq_nolelem *)nol->dfs_nol, &nol->ic_nchans);
		dfs_print_nol(dfs);
		ATH_DFSNOL_UNLOCK(dfs);
		break;
	case DFS_SET_NOL:
		if (insize < sizeof(struct dfsreq_nolinfo) || !indata) {
                        error = -EINVAL;
                        break;
                }
                nol = (struct dfsreq_nolinfo *) indata;
		ATH_DFSNOL_LOCK(dfs);
		dfs_set_nol(dfs, (struct dfsreq_nolelem *)nol->dfs_nol, nol->ic_nchans);
		ATH_DFSNOL_UNLOCK(dfs);
		break;

    case DFS_SHOW_NOL:
        ATH_DFSNOL_LOCK(dfs);
        dfs_print_nol(dfs);
        ATH_DFSNOL_UNLOCK(dfs);
        break;
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
    case DFS_SHOW_NOLHISTORY:
        dfs_print_nolhistory(ic,dfs);
        break;
#endif
#if ATH_SUPPORT_ZERO_CAC_DFS
    case DFS_SHOW_PRECAC_LISTS:
        dfs_print_precaclists(ic,dfs);
        break;
    case DFS_RESET_PRECAC_LISTS:
        dfs_reset_precaclists(ic,dfs);
        break;
#endif
    case DFS_BANGRADAR:
 #if 0 //MERGE_TBD
        if(sc->sc_nostabeacons)
        {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "No radar detection Enabled \n");
            break;
        }
#endif
        dfs->dfs_bangradar = 1;
        dfs->ath_radar_tasksched = 1;
        OS_SET_TIMER(&dfs->ath_dfs_task_timer, 0);
		error = 0;
        break;
#if ATH_SUPPORT_ZERO_CAC_DFS
    case DFS_SECOND_SEGMENT_BANGRADAR:
        dfs->dfs_second_segment_bangradar = 1;
        dfs->ath_radar_tasksched = 1;
        OS_SET_TIMER(&dfs->ath_dfs_task_timer, 0);
        error = 0;
        break;
#endif
#endif /* ATH_DFS_RADAR_DETECTION_ONLY */
	default:
		error = -EINVAL;
	}
bad:
	return error;
}
int
dfs_set_thresholds(struct ieee80211com *ic, const u_int32_t threshtype,
		   const u_int32_t value)
{
	struct ath_dfs *dfs = (struct ath_dfs *)ic->ic_dfs;
	int16_t chanindex;
	struct dfs_state *rs;
	struct ath_dfs_phyerr_param pe;
	int is_fastclk = 0;	/* XXX throw-away */

	if (dfs == NULL) {
		DFS_DPRINTK(dfs, ATH_DEBUG_DFS1, "%s: ic_dfs is NULL\n",
			__func__);
		return 0;
	}

	chanindex = dfs->dfs_curchan_radindex;
	if ((chanindex <0) || (chanindex >= DFS_NUM_RADAR_STATES)) {
		DFS_DPRINTK(dfs, ATH_DEBUG_DFS1,
		    "%s: chanindex = %d, DFS_NUM_RADAR_STATES=%d\n",
		    __func__,
		    chanindex,
		    DFS_NUM_RADAR_STATES);
		return 0;
	}

	DFS_DPRINTK(dfs, ATH_DEBUG_DFS,
	    "%s: threshtype=%d, value=%d\n", __func__, threshtype, value);

	ath_dfs_phyerr_init_noval(&pe);

	rs = &(dfs->dfs_radar[chanindex]);
	switch (threshtype) {
	case DFS_PARAM_FIRPWR:
		rs->rs_param.pe_firpwr = (int32_t) value;
		pe.pe_firpwr = value;
		break;
	case DFS_PARAM_RRSSI:
		rs->rs_param.pe_rrssi = value;
		pe.pe_rrssi = value;
		break;
	case DFS_PARAM_HEIGHT:
		rs->rs_param.pe_height = value;
		pe.pe_height = value;
		break;
	case DFS_PARAM_PRSSI:
		rs->rs_param.pe_prssi = value;
		pe.pe_prssi = value;
		break;
	case DFS_PARAM_INBAND:
		rs->rs_param.pe_inband = value;
		pe.pe_inband = value;
		break;
	/* 5413 specific */
	case DFS_PARAM_RELPWR:
		rs->rs_param.pe_relpwr = value;
		pe.pe_relpwr = value;
		break;
	case DFS_PARAM_RELSTEP:
		rs->rs_param.pe_relstep = value;
		pe.pe_relstep = value;
		break;
	case DFS_PARAM_MAXLEN:
		rs->rs_param.pe_maxlen = value;
		pe.pe_maxlen = value;
		break;
	default:
		DFS_DPRINTK(dfs, ATH_DEBUG_DFS1,
		    "%s: unknown threshtype (%d)\n",
		    __func__,
		    threshtype);
		break;
	}

	/*
	 * The driver layer dfs_enable routine is tasked with translating
	 * values from the global format to the per-device (HAL, offload)
	 * format.
	 */
	ic->ic_dfs_enable(ic, &is_fastclk, &pe);
	return 1;
}

int
dfs_get_thresholds(struct ieee80211com *ic, struct ath_dfs_phyerr_param *param)
{
	//UMACDFS : TODO:ath_hal_getdfsthresh(sc->sc_ah, param);

	OS_MEMZERO(param, sizeof(*param));

	(void) ic->ic_dfs_get_thresholds(ic, param);

	return 1;
}

u_int16_t   dfs_usenol(struct ieee80211com *ic)
{
    struct ath_dfs *dfs = (struct ath_dfs *)ic->ic_dfs;
    return dfs ? (u_int16_t) dfs->dfs_rinfo.rn_use_nol : 0;
}

void dfs_getnol(struct ieee80211com *ic, void *dfs_nolinfo)
{
    struct ath_dfs *dfs = (struct ath_dfs *)ic->ic_dfs;
    struct dfsreq_nolinfo *nolinfo = (struct dfsreq_nolinfo *)dfs_nolinfo;

    dfs_get_nol(dfs, nolinfo->dfs_nol, &(nolinfo->ic_nchans));
}

void dfs_start_tx_rcsa_and_waitfor_rx_csa(struct ieee80211com *ic)
{
    struct ath_dfs *dfs = NULL;

    dfs = (struct ath_dfs *)ic->ic_dfs;
    if(!dfs->ath_dfs_waitfor_csa_sched) {
        ic->ic_rcsa_count = DFS_RCSA_INIT_COUNT;
        DFS_DPRINTK(dfs, ATH_DEBUG_DFS,
                "%s: start the 0 sec timer, rcsa_count=%d\n",
                __func__, ic->ic_rcsa_count);
        /* Start timer for sending RCSA */
        OS_SET_TIMER(&dfs->ath_dfs_tx_rcsa_timer,0);

        dfs->ath_dfs_waitfor_csa_sched = 1;
        if(IEEE80211_IS_CSH_OPT_APRIORI_NEXT_CHANNEL_ENABLED(ic))
        {
            /* Wait for 5 RCSAs to be propagated(500ms) + 100ms grace period*/
            OS_SET_TIMER(&dfs->ath_dfs_waitfor_csa_timer,DFS_WAIT_FOR_RCSA_COMPLETION);
        }
        else
        {
            /* Assuming a chain of max 5 repeaters and a RCSA interval of 100ms,
             * it will take at most 1sec for the CSA to come back. Also have additional
             * grace period of 1 sec. Total wait period 2 secs.
             * Wait for 2 sec to get back CSA from parent Repeater/Root.
             * If within 2 sec CSA does not come back then call nofity radar
             */
            OS_SET_TIMER(&dfs->ath_dfs_waitfor_csa_timer,DFS_WAIT_FOR_CSA_TIME);
        }
    }
}

void dfs_rx_rcsa(struct ieee80211com *ic)
{
    if(IEEE80211_IS_CSH_PROCESS_RCSA_ENABLED(ic)) {
        struct ath_dfs *dfs = NULL;
        dfs = (struct ath_dfs *)ic->ic_dfs;

        dfs_radar_disable(ic);
#if ATH_SUPPORT_ZERO_CAC_DFS
        dfs_second_segment_radar_disable(ic);
#endif
        /* In Cascaded Mode, when the middle Repeater AP receives the RCSA
         * from it's connected clients, it adds the channels to NOL and then
         * propagates the RCSA to its Root.
         */
        if (dfs->update_nol == false) {
            if (dfs->dfs_rinfo.rn_use_nol == 1) {
                dfs_channel_mark_radar(dfs, ic->ic_curchan);
                dfs->update_nol = true;
            }
        }
        dfs_start_tx_rcsa_and_waitfor_rx_csa(ic);
    }
}

void dfs_cancel_waitfor_csa_timer(struct ieee80211com *ic)
{
    struct ath_dfs *dfs = (struct ath_dfs *)ic->ic_dfs;
    if(dfs->ath_dfs_waitfor_csa_sched) {
        OS_CANCEL_TIMER(&dfs->ath_dfs_waitfor_csa_timer);
        dfs->ath_dfs_waitfor_csa_sched = 0;
    }
}

#if ATH_SUPPORT_ZERO_CAC_DFS
int dfs_get_nol_timeout(struct ieee80211com *ic)
{
    struct ath_dfs *dfs = NULL;
    dfs = (struct ath_dfs *)ic->ic_dfs;

    return dfs->ath_dfs_nol_timeout;
}
#endif

u_int16_t   dfs_isdfsregdomain(struct ieee80211com *ic)
{
    struct ath_dfs *dfs = (struct ath_dfs *)ic->ic_dfs;
    return dfs ? dfs->dfsdomain : 0;
}

#ifdef __linux__
#ifndef ATH_WLAN_COMBINE
/*
 * Linux Module glue.
 */
static char *dev_info = "ath_dfs";

MODULE_AUTHOR("Atheros Communications, Inc.");
MODULE_DESCRIPTION("DFS Support for Atheros 802.11 wireless LAN cards.");
MODULE_SUPPORTED_DEVICE("Atheros WLAN cards");
#ifdef MODULE_LICENSE
MODULE_LICENSE("Proprietary");
#endif

static int __init
init_ath_dfs(void)
{
	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO "%s: Version 2.0.0\n"
		"Copyright (c) 2005-2006 Atheros Communications, Inc. "
		"All Rights Reserved\n",dev_info);
	return 0;
}
module_init(init_ath_dfs);

static void __exit
exit_ath_dfs(void)
{
	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO "%s: driver unloaded\n", dev_info);
}
module_exit(exit_ath_dfs);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,52))
MODULE_PARM(domainoverride, "i");
MODULE_PARM(usenol, "i");
MODULE_PARM_DESC(domainoverride, "Override dfs domain");
MODULE_PARM_DESC(usenol, "Override the use of channel NOL");
#else
#include <linux/moduleparam.h>
module_param(domainoverride, int, 0600);
module_param(usenol, int, 0600);
#endif

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif

EXPORT_SYMBOL(dfs_getchanstate);
EXPORT_SYMBOL(dfs_attach);
EXPORT_SYMBOL(dfs_detach);
EXPORT_SYMBOL(ath_ar_enable);
EXPORT_SYMBOL(dfs_radar_enable);
EXPORT_SYMBOL(ath_ar_disable);
EXPORT_SYMBOL(dfs_process_phyerr);
EXPORT_SYMBOL(dfs_process_ar_event);
EXPORT_SYMBOL(dfs_control);
EXPORT_SYMBOL(dfs_get_thresholds);
EXPORT_SYMBOL(dfs_init_radar_filters);
EXPORT_SYMBOL(dfs_clear_stats);
EXPORT_SYMBOL(dfs_usenol);
EXPORT_SYMBOL(dfs_getnol);
EXPORT_SYMBOL(dfs_rx_rcsa);
EXPORT_SYMBOL(dfs_cancel_waitfor_csa_timer);
EXPORT_SYMBOL(dfs_isdfsregdomain);
#if ATH_SUPPORT_ZERO_CAC_DFS
EXPORT_SYMBOL(dfs_get_nol_timeout);
#endif

#endif /* #ifndef ATH_WLAN_COMBINE */
#endif /* __linux__ */

#endif /* ATH_UPPORT_DFS */
