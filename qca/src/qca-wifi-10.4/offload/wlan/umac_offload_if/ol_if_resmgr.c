/*
 * Copyright (c) 2011, Atheros Communications Inc.
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
/*
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

/*
 * UMAC resmgr specific offload interface functions - for power and performance offload model
 */
#include "ol_if_athvar.h"
#include "ol_if_vap.h"
#include "ieee80211_sm.h"

#if ATH_PERF_PWR_OFFLOAD

/* Resource Manager structure */
struct ieee80211_resmgr {
    /* the function indirection SHALL be the first fileds */
    struct ieee80211_resmgr_func_table              resmgr_func_table;
    struct ieee80211com                             *ic;               /* Back pointer to ic */
    ieee80211_resmgr_mode                           mode;
    qdf_spinlock_t rm_lock;   /* Lock ensures that only one thread runs res mgr at a time */
    /* Add one lock for notif_handler register/deregister operation, notif_handler will be modified by
       wlan_scan_run() call and cause schedule-while-atomic in split driver. */
    qdf_spinlock_t                                      rm_handler_lock;
    ieee80211_hsm_t                                 hsm_handle;        /* HSM Handle */
    ieee80211_resmgr_notification_handler           notif_handler[IEEE80211_MAX_RESMGR_EVENT_HANDLERS];
    void                                            *notif_handler_arg[IEEE80211_MAX_RESMGR_EVENT_HANDLERS];
};

#define IEEE80211_RESMGR_REQID     0x5555
#define IEEE80211_RESMGR_NOTIFICATION(_resmgr,_notif)  do {                 \
        int i;                                                              \
        for(i = 0;i < IEEE80211_MAX_RESMGR_EVENT_HANDLERS; ++i) {                  \
            if (_resmgr->notif_handler[i]) {                                \
                (* _resmgr->notif_handler[i])                               \
                    (_resmgr, _notif, _resmgr->notif_handler_arg[i]);       \
             }                                                              \
        }                                                                   \
    } while(0)


static void _ieee80211_resmgr_create_complete(ieee80211_resmgr_t resmgr)
{
    return;
}

static void _ieee80211_resmgr_delete(ieee80211_resmgr_t resmgr)
{
    struct ieee80211com *ic;
    struct ol_ath_softc_net80211 *scn;

    if (!resmgr)
        return ;

    ic = resmgr->ic;
    scn = OL_ATH_SOFTC_NET80211(ic);

    /* Register WMI event handlers */
    wmi_unified_unregister_event_handler(scn->wmi_handle, wmi_vdev_start_resp_event_id);

    qdf_spinlock_destroy(&resmgr->rm_lock);
    qdf_spinlock_destroy(&resmgr->rm_handler_lock);

    qdf_mem_free(resmgr);

    ic->ic_resmgr = NULL;

    return;
}

static void _ieee80211_resmgr_delete_prepare(ieee80211_resmgr_t resmgr)
{
    return;
}

static int _ieee80211_resmgr_request_offchan(ieee80211_resmgr_t resmgr,
                                     struct ieee80211_channel *chan,
                                     u_int16_t reqid,
                                     u_int16_t max_bss_chan,
                                     u_int32_t max_dwell_time)
{
    return EOK;
}

static int _ieee80211_resmgr_request_bsschan(ieee80211_resmgr_t resmgr,
                                     u_int16_t reqid)
{
    return EOK;
}

static int _ieee80211_resmgr_request_chanswitch(ieee80211_resmgr_t resmgr,
                                        ieee80211_vap_t vap,
                                        struct ieee80211_channel *chan,
                                        u_int16_t reqid)
{
    return EOK;
}

/* Implement wmi_unified_vdev_start_cmd() here */
static int _ieee80211_resmgr_vap_start(ieee80211_resmgr_t resmgr,
                               ieee80211_vap_t vap,
                               struct ieee80211_channel *chan,
                               u_int16_t reqid,
                               u_int16_t max_start_time,
                               u_int8_t restart)
{
    struct ieee80211com *ic = resmgr->ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    u_int32_t freq;
    bool disable_hw_ack= false;
    bool dfs_channel = false;

    if (!ic->ic_nl_handle) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "OL vap_start +\n");
    }

    freq = ieee80211_chan2freq(resmgr->ic, chan);
    if (!freq) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ERROR : INVALID Freq \n");
        return EBUSY;
    }

    dfs_channel = (IEEE80211_IS_CHAN_DFS(chan) ||
        ((IEEE80211_IS_CHAN_11AC_VHT80_80(chan) ||
          IEEE80211_IS_CHAN_11AC_VHT160(chan)) &&
          IEEE80211_IS_CHAN_DFS_CFREQ2(chan)));

    spin_lock_dpc(&vap->init_lock);
    /*Return from here, if VAP init is already in progress*/
    if(qdf_atomic_read(&(vap->init_in_progress)) && !restart ) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Warning:VAP Init in progress! \n");
        spin_unlock_dpc(&vap->init_lock);
        return EBUSY;
    }
#if ATH_SUPPORT_DFS
    if (vap->iv_opmode == IEEE80211_M_HOSTAP &&
        dfs_channel &&
        !ieee80211_vap_is_any_running(ic) && !vap->iv_no_cac) {
        /* Do not set HW no ack bit, if STA vap is present and if it is not in Repeater-ind mode */
        if(scn->sc_nstavaps == 0 ||
          ( scn->sc_nstavaps >=1 && ieee80211_ic_enh_ind_rpt_is_set(vap->iv_ic))) {
           disable_hw_ack = true;
        }
    }
#endif

    /* BUG : Seen on AKronite, VDEV Start event response comes before setting
     * av_ol_resmgr_wait to TRUE, this make VAP not coming up issue.
     * Hence moving below assignment before sending VDEV_START_CMD_ID to target
     */

    /* Interface is up, UMAC is waiting for
     * target response
     */
    avn->av_ol_resmgr_wait = TRUE;

    qdf_atomic_set(&(vap->iv_is_start_sent), 1);

    if(restart == 0) {
       if (ol_ath_vdev_start_send(scn, avn->av_if_id, chan, freq, disable_hw_ack, ic->ic_nl_handle)) {
           QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Unable to bring up the interface for ath_dev.\n");
           avn->av_ol_resmgr_wait = FALSE;
           qdf_atomic_set(&(vap->iv_is_start_sent), 0);
           spin_unlock_dpc(&vap->init_lock);
           return -1;
       }
    }
    else {
        if (ol_ath_vdev_restart_send(scn,
                    avn->av_if_id, chan,
                    chan->ic_freq,
                    dfs_channel)) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ERROR : %s[%d] Unable to bring up the interface for ath_dev.\n", __func__, __LINE__);
            qdf_atomic_set(&(vap->iv_is_start_sent), 0);
        }
    }

    /* The channel configured in target is not same always with the vap desired channel
      due to 20/40 coexistence scenarios, so, channel is saved to configure on VDEV START RESP */
    avn->av_ol_resmgr_chan = chan;
    qdf_atomic_set(&(vap->init_in_progress), 1);
    spin_unlock_dpc(&vap->init_lock);

    if (!ic->ic_nl_handle) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "OL vap_start -\n");
    }

    return EBUSY;
}

static void _ieee80211_resmgr_vattach(ieee80211_resmgr_t resmgr, ieee80211_vap_t vap)
{
    return;
}

static void _ieee80211_resmgr_vdetach(ieee80211_resmgr_t resmgr, ieee80211_vap_t vap)
{
    return;
}

static const char *_ieee80211_resmgr_get_notification_type_name(ieee80211_resmgr_t resmgr, ieee80211_resmgr_notification_type type)
{
    return "unknown";
}

static int _ieee80211_resmgr_register_noa_event_handler(ieee80211_resmgr_t resmgr,
    ieee80211_vap_t vap, ieee80211_resmgr_noa_event_handler handler, void *arg)
{

    return EOK;
}

static int _ieee80211_resmgr_unregister_noa_event_handler(ieee80211_resmgr_t resmgr,
    ieee80211_vap_t vap)
{
    return EOK;
}

static void ieee80211_notify_vap_restart_complete(ieee80211_resmgr_t resmgr,
                             struct ieee80211vap *vap,  ieee80211_resmgr_notification_status status)
{
    ieee80211_resmgr_notification notif;

    /* Intimate start completion to VAP module */
    notif.type = IEEE80211_RESMGR_VAP_RESTART_COMPLETE;
    notif.req_id = IEEE80211_RESMGR_REQID;
    notif.status = status;
    notif.vap = vap;
    vap->iv_rescan = 0;
    IEEE80211_RESMGR_NOTIFICATION(resmgr, &notif);

}

static void ieee80211_notify_vap_start_complete(ieee80211_resmgr_t resmgr,
                             struct ieee80211vap *vap,  ieee80211_resmgr_notification_status status)
{
    ieee80211_resmgr_notification notif;

    /* Intimate start completion to VAP module */
    notif.type = IEEE80211_RESMGR_VAP_START_COMPLETE;
    notif.req_id = IEEE80211_RESMGR_REQID;
    notif.status = status;
    notif.vap = vap;
    vap->iv_rescan = 0;
    IEEE80211_RESMGR_NOTIFICATION(resmgr, &notif);

}


/*
 * Register a resmgr notification handler.
 */
static int
_ieee80211_resmgr_register_notification_handler(ieee80211_resmgr_t resmgr,
                                               ieee80211_resmgr_notification_handler notificationhandler,
                                               void *arg)
{
    int i;

    /* unregister if there exists one already */
    ieee80211_resmgr_unregister_notification_handler(resmgr, notificationhandler,arg);
    qdf_spin_lock(&resmgr->rm_handler_lock);
    for (i=0; i<IEEE80211_MAX_RESMGR_EVENT_HANDLERS; ++i) {
        if (resmgr->notif_handler[i] == NULL) {
            resmgr->notif_handler[i] = notificationhandler;
            resmgr->notif_handler_arg[i] = arg;
            qdf_spin_unlock(&resmgr->rm_handler_lock);
            return 0;
        }
    }
    qdf_spin_unlock(&resmgr->rm_handler_lock);
    return -ENOMEM;
}

/*
 * Unregister a resmgr event handler.
 */
static int _ieee80211_resmgr_unregister_notification_handler(ieee80211_resmgr_t resmgr,
                                                     ieee80211_resmgr_notification_handler handler,
                                                     void  *arg)
{
    int i;
    qdf_spin_lock(&resmgr->rm_handler_lock);
    for (i=0; i<IEEE80211_MAX_RESMGR_EVENT_HANDLERS; ++i) {
        if (resmgr->notif_handler[i] == handler && resmgr->notif_handler_arg[i] == arg ) {
            resmgr->notif_handler[i] = NULL;
            resmgr->notif_handler_arg[i] = NULL;
            qdf_spin_unlock(&resmgr->rm_handler_lock);
            return 0;
        }
    }
    qdf_spin_unlock(&resmgr->rm_handler_lock);
    return -EEXIST;
}


static int _ieee80211_resmgr_off_chan_sched_set_air_time_limit(ieee80211_resmgr_t resmgr,
    ieee80211_vap_t vap,
    u_int32_t scheduled_air_time_limit
    )
{
    return EINVAL;
}

static u_int32_t _ieee80211_resmgr_off_chan_sched_get_air_time_limit(ieee80211_resmgr_t resmgr,
    ieee80211_vap_t vap
    )
{
    return 100;
}

/* Implement wmi_unified_vdev_start_cmd() here */
static int _ieee80211_resmgr_vap_stop(ieee80211_resmgr_t resmgr,
                               ieee80211_vap_t vap,
                               u_int16_t reqid)
{
    struct ieee80211com *ic = resmgr->ic;
    int ret = EOK;

#if 0
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
#endif

    if (!ic->ic_nl_handle) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "OL vap_stop +\n");
    }

    ret = vap->iv_stopping(vap);
    if (ret != EOK)
        ieee80211_vap_deliver_stop_error(vap);

    if (!ic->ic_nl_handle) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "OL vap_stop -\n");
    }
    return ret;
}

static int
ol_vdev_wmi_event_handler(ol_scn_t sc, u_int8_t *data, u_int16_t datalen)
{
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)sc;
    struct ieee80211com  *ic = &scn->sc_ic;
    ieee80211_resmgr_t resmgr = ic->ic_resmgr;
    wmi_host_vdev_start_resp vdev_start_resp;
    wlan_if_t vaphandle;
    struct ieee80211_channel *chan = NULL;
    struct ieee80211_node *ni;
    u_int8_t numvaps_up, actidx = 0;
    struct ol_ath_vap_net80211 *avn;
    bool do_notify = true;
    /* Initialise dummy wme_params structure */
    struct ieee80211_wme_state wme_zero = {0};

    if(wmi_extract_vdev_start_resp(scn->wmi_handle, data, &vdev_start_resp)) {
        qdf_print("Failed to extract vdev start resp\n");
        return 0;
    }

    vaphandle = ol_ath_vap_get(scn, vdev_start_resp.vdev_id);

    if (NULL == vaphandle) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Event received for Invalid/Deleted vap handle\n");
        return 0;
    }

    qdf_atomic_set(&(vaphandle->iv_is_start_sent), 0);

    avn = OL_ATH_VAP_NET80211(vaphandle);
    if (!ic->ic_nl_handle) {
        QDF_PRINT_INFO(vaphandle->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ol_vdev_start_resp_ev for vap %d (%p)\n", vdev_start_resp.vdev_id, scn->wmi_handle);
    }

    spin_lock_dpc(&vaphandle->init_lock);

    switch (vaphandle->iv_opmode) {

        case IEEE80211_M_MONITOR:
               /* Handle same as HOSTAP */
        case IEEE80211_M_HOSTAP:
            /* If vap is not waiting for the WMI event from target
               return here
             */
            if(avn->av_ol_resmgr_wait == FALSE) {
                qdf_atomic_set(&(vaphandle->init_in_progress), 0);
                spin_unlock_dpc(&vaphandle->init_lock);
                return 0;
            }

            if(vdev_start_resp.status == WMI_HOST_VDEV_START_CHAN_INVALID) {

                /* Firmware response the channel in vdev start command is invalid */
                IEEE80211_DPRINTF(vaphandle, IEEE80211_MSG_ANY,
                        "Error %s : failed vdev start vap %d status %d\n",
                        __func__, vdev_start_resp.vdev_id, vdev_start_resp.status);

                qdf_atomic_set(&(vaphandle->init_in_progress), 0);
                ieee80211_notify_vap_start_complete(resmgr, vaphandle, IEEE80211_RESMGR_STATUS_NOT_SUPPORTED);
                spin_unlock_dpc(&vaphandle->init_lock);
                return 0;
            }

             /* Resetting the ol_resmgr_wait flag*/
            avn->av_ol_resmgr_wait = FALSE;

            numvaps_up = ieee80211_get_num_vaps_up(ic);

            chan =  vaphandle->iv_des_chan[vaphandle->iv_des_mode];

            /*
             * if there is a vap already running.
             * ignore the desired channel and use the
             * operating channel of the other vap.
             */
            /* so that cwm can do its own crap. need to untie from state */
            /* vap join is called here to wake up the chip if it is in sleep state */
            ieee80211_vap_join(vaphandle);

            if (numvaps_up == 0) {
                //AP_DFS: ieee80211_set_channel(ic, chan);
                 /* 20/40 Mhz coexistence  handler */
                if ((avn->av_ol_resmgr_chan != NULL) && (chan != avn->av_ol_resmgr_chan)) {
                    chan = avn->av_ol_resmgr_chan;
                }

                ic->ic_prevchan = ic->ic_curchan;
                ic->ic_curchan = chan;
                /*update channel history*/
                actidx = ic->ic_chanidx;
                ic->ic_chanhist[actidx].chanid = (ic->ic_curchan)->ic_ieee;
                ic->ic_chanhist[actidx].chanjiffies = OS_GET_TIMESTAMP();
                ic->ic_chanidx == (IEEE80211_CHAN_MAXHIST - 1) ? ic->ic_chanidx = 0 : ++(ic->ic_chanidx);
                /* update max channel power to max regpower of current channel */
                ieee80211com_set_curchanmaxpwr(ic, chan->ic_maxregpower);

                /* ieee80211 Layer - Default Configuration */
                vaphandle->iv_bsschan = ic->ic_curchan;

		/* This function was being called before "vaphandle->iv_bsschan = ic->ic_curchan" and now moved here.
		 * This fixes a bug where the wme parameters are set to FW before the current channel gets
		 * updated("vaphandle->iv_bsschan"). The "ic_flags" in "iv_bsschan" is used to get the corresponding
		 * phy mode with respect to the channel (ieee80211_chan2mode), and this phy mode is used to set the
		 * wme parameters to FW. IR-088422.
		 */
                ieee80211_wme_initparams(vaphandle);
                /* XXX reset erp state */
                ieee80211_reset_erp(ic, ic->ic_curmode, vaphandle->iv_opmode);
            } else {
                /* Copy the wme params from ic to vap structure if vaps are up for the first time */
               if(memcmp(&wme_zero,&vaphandle->iv_wmestate,sizeof(wme_zero)) == 0){
                     memcpy(&vaphandle->iv_wmestate,&ic->ic_wme,sizeof(ic->ic_wme));
                }
                ieee80211_wme_updateparams_locked(vaphandle);

                /* ieee80211 Layer - Default Configuration */
                vaphandle->iv_bsschan = ic->ic_curchan;
            }

            ic->ic_opmode = IEEE80211_M_HOSTAP;

            /* use the vap bsschan for dfs configure */
            if ((IEEE80211_IS_CHAN_DFS(vaphandle->iv_bsschan) ||
                    ((IEEE80211_IS_CHAN_11AC_VHT160(vaphandle->iv_bsschan) || IEEE80211_IS_CHAN_11AC_VHT80_80(vaphandle->iv_bsschan))
                    && IEEE80211_IS_CHAN_DFS_CFREQ2(vaphandle->iv_bsschan))) ||
                    (ic->ic_dfs_is_precac_timer_running(ic))) {
                   extern void ol_if_dfs_configure(struct ieee80211com *ic);
                   ol_if_dfs_configure(ic);
            }
            if(IEEE80211_IS_CHAN_DFS(ic->ic_curchan))
            {
                /*
                 * When there is radar detect in Repeater, repeater sends RCSAs, CSAs and
                 * switches to new next channel, in ind rpt case repeater AP could start
                 * beaconing before Root comes up, next channel needs to be changed
                 */
                if(!ic->ic_tx_next_ch || ic->ic_curchan == ic->ic_tx_next_ch)
                {
                    ieee80211_update_dfs_next_channel(ic);
                }
            }
            else {
                ic->ic_tx_next_ch = NULL;
            }
            break;
        case IEEE80211_M_STA:

            ni = vaphandle->iv_bss;

            chan = ni->ni_chan;

            vaphandle->iv_bsschan = chan;

            ic->ic_prevchan = ic->ic_curchan;
            ic->ic_curchan = chan;
            /* update max channel power to max regpower of current channel */
            ieee80211com_set_curchanmaxpwr(ic, chan->ic_maxregpower);

            /* ieee80211 Layer - Default Configuration */
            vaphandle->iv_bsschan = ic->ic_curchan;

            /* XXX reset erp state */
            ieee80211_reset_erp(ic, ic->ic_curmode, vaphandle->iv_opmode);
            ieee80211_wme_initparams(vaphandle);

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
            /* use the vap bsschan for dfs configure/enable */
            if (ieee80211com_has_cap_ext(ic,IEEE80211_CEXT_STADFS)) {
                QDF_PRINT_INFO(vaphandle->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: device is capable of station mode DFS\n", __func__);
                if (IEEE80211_IS_CHAN_DFS(vaphandle->iv_bsschan) ||
                    ((IEEE80211_IS_CHAN_11AC_VHT160(vaphandle->iv_bsschan) || IEEE80211_IS_CHAN_11AC_VHT80_80(vaphandle->iv_bsschan))
                    && IEEE80211_IS_CHAN_DFS_CFREQ2(vaphandle->iv_bsschan))) {
                    extern void ol_if_dfs_configure(struct ieee80211com *ic);
                    QDF_PRINT_INFO(vaphandle->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: station mode DFS is enabled\n", __func__);
                    ol_if_dfs_configure(ic);
                }
            }
#endif

            if (vdev_start_resp.resp_type == WMI_HOST_VDEV_RESTART_RESP_EVENT) {
                ieee80211_notify_vap_restart_complete(resmgr, vaphandle, IEEE80211_RESMGR_STATUS_SUCCESS);
                do_notify = false;
            }

            break;
        default:
            break;
    }

    /* WMI incorrect Sequence.  There are multiple CRs opened up.
     * Refer this CR for more details
     */
    spin_unlock_dpc(&vaphandle->init_lock);

    /* Intimate start completion to VAP module */
    /* if STA, bypass notification for RESTERT EVENT */
    if (do_notify){
        ieee80211_notify_vap_start_complete(resmgr, vaphandle, IEEE80211_RESMGR_STATUS_SUCCESS);
    }

    // Tell the vap that the channel change has happened.
#if !ATH_BAND_STEERING
    /* For Band steering enabled:- it will be sent from ieee80211_state_event*/
    IEEE80211_DELIVER_EVENT_CHANNEL_CHANGE(vaphandle, ic->ic_curchan);
#endif
    ic->ic_flags &= ~IEEE80211_F_DFS_CHANSWITCH_PENDING;
    vaphandle->channel_switch_state = 0;
    return 0;
}

ieee80211_resmgr_t ol_resmgr_create(struct ieee80211com *ic, ieee80211_resmgr_mode mode)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    ieee80211_resmgr_t    resmgr;

    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"OL Resmgr Init-ed\n");

    if (ic->ic_resmgr) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : ResMgr already exists \n", __func__);
        return NULL;
    }

    /* Allocate ResMgr data structures */
    resmgr = (ieee80211_resmgr_t) qdf_mem_malloc(sizeof(struct ieee80211_resmgr));
    if (resmgr == NULL) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : ResMgr memory alloction failed\n", __func__);
        return NULL;
    }

    OS_MEMZERO(resmgr, sizeof(struct ieee80211_resmgr));
    resmgr->ic = ic;
    resmgr->mode = mode;
    /* Indicate the device is capable of multi-chan operation*/
    ic->ic_caps_ext |= IEEE80211_CEXT_MULTICHAN;

    /* initialize function pointer table */
    resmgr->resmgr_func_table.resmgr_create_complete = _ieee80211_resmgr_create_complete;
    resmgr->resmgr_func_table.resmgr_delete = _ieee80211_resmgr_delete;
    resmgr->resmgr_func_table.resmgr_delete_prepare = _ieee80211_resmgr_delete_prepare;

    resmgr->resmgr_func_table.resmgr_register_notification_handler = _ieee80211_resmgr_register_notification_handler;
    resmgr->resmgr_func_table.resmgr_unregister_notification_handler = _ieee80211_resmgr_unregister_notification_handler;

    resmgr->resmgr_func_table.resmgr_request_offchan = _ieee80211_resmgr_request_offchan;
    resmgr->resmgr_func_table.resmgr_request_bsschan = _ieee80211_resmgr_request_bsschan;
    resmgr->resmgr_func_table.resmgr_request_chanswitch = _ieee80211_resmgr_request_chanswitch;

    resmgr->resmgr_func_table.resmgr_vap_start = _ieee80211_resmgr_vap_start;

    resmgr->resmgr_func_table.resmgr_vattach = _ieee80211_resmgr_vattach;
    resmgr->resmgr_func_table.resmgr_vdetach = _ieee80211_resmgr_vdetach;
    resmgr->resmgr_func_table.resmgr_get_notification_type_name = _ieee80211_resmgr_get_notification_type_name;
    resmgr->resmgr_func_table.resmgr_register_noa_event_handler = _ieee80211_resmgr_register_noa_event_handler;
    resmgr->resmgr_func_table.resmgr_unregister_noa_event_handler = _ieee80211_resmgr_unregister_noa_event_handler;
    resmgr->resmgr_func_table.resmgr_off_chan_sched_set_air_time_limit = _ieee80211_resmgr_off_chan_sched_set_air_time_limit;
    resmgr->resmgr_func_table.resmgr_off_chan_sched_get_air_time_limit = _ieee80211_resmgr_off_chan_sched_get_air_time_limit;

    resmgr->resmgr_func_table.resmgr_vap_stop = _ieee80211_resmgr_vap_stop;

    qdf_spinlock_create(&resmgr->rm_lock);
    qdf_spinlock_create(&resmgr->rm_handler_lock);

    /* Register WMI event handlers */
    wmi_unified_register_event_handler(scn->wmi_handle, wmi_vdev_start_resp_event_id,
                                        ol_vdev_wmi_event_handler, WMI_RX_UMAC_CTX);

    return resmgr;
}



void
ol_ath_resmgr_attach(struct ieee80211com *ic)
{
    ic->ic_resmgr_create = ol_resmgr_create;
}

#endif /* ATH_PERF_PWR_OFFLOAD */

