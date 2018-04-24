/*
 *  Copyright (c) 2008 Atheros Communications Inc. 
 * All Rights Reserved.
 * 
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */

#include "ieee80211_var.h"
#include "ieee80211_sme_api.h"
#include "ieee80211_sm.h"
#include "ieee80211_connection_private.h"
#include "if_upperproto.h"
#include "ieee80211_api.h"

#if !UMAC_SUPPORT_SCAN
#error connection SM requires SCAN module 
#endif

#if !UMAC_SUPPORT_APLIST
#error connection SM requires APLIST module 
#endif

#define MAX_QUEUED_EVENTS  16
#define   MAX_SCAN_FAIL_COUNT 3   /* number scan failures before bailing out */

/* Opportunistic Roam */
#define BSSID_INVALID           "\x00\x00\x00\x00\x00\x00"
#define BSSID_BROADCAST         "\xFF\xFF\xFF\xFF\xFF\xFF"

/*
** Local Prototypes
*/

static OS_TIMER_FUNC(connection_sm_timer_handler);
static OS_TIMER_FUNC(connection_sm_roam_check_timer_handler);
static void ieee80211_check_2040_coexistinfo(wlan_if_t vaphandle);
static void ieee80211_scan_check_2040_coexistinfo(wlan_if_t vaphandle);
extern struct ieee80211_channel *ieee80211_find_channel(struct ieee80211com *ic, int freq, u_int8_t des_cfreq2, u_int32_t flags);



struct _wlan_connection_sm {

    osdev_t                     os_handle;
    wlan_if_t                   vap_handle;
    ieee80211_hsm_t             hsm_handle; 
    wlan_assoc_sm_t             assoc_sm_handle; 
    wlan_scan_entry_t           cur_scan_entry; /* current bss scan entry */
    u_int8_t                    cur_bssid[IEEE80211_ADDR_LEN];
    wlan_connection_sm_event_handler sm_evhandler;
    u_int8_t                    bgscan_rssi_thresh;
    u_int8_t                    bgscan_rssi_change;
    u_int8_t                    bgscan_rssi_thresh_forced_scan;  /* rssi below which it scan is a forces scan */
    u_int8_t                    roam_threshold;
    struct                      ether_addr roam_bssid; /* BSSID to roam to next roam check, if exists */
    u_int32_t                   bgscan_period; /* in seconds */
    u_int32_t                   scan_cache_valid_time; /* in msec */
    u_int32_t                   roam_check_period; /* in msec */
    u_int32_t                   connect_timeout;   /* connection attempt timeout in msec */
    u_int32_t                   reconnect_timeout; /* after losing connection max re connection attempt timeout */
    u_int32_t                   connection_lost_timeout; /* after losing connection time to wait before sending notification up */
    u_int32_t                   bad_ap_timeout; /* time out before trying out the AP after connection failure */
    u_int32_t                   bgscan_min_dwell_time; /* minimum dwell time for bg scan */
    u_int32_t                   bgscan_max_dwell_time; /* maximum dwell time for bg scan */
    u_int32_t                   bgscan_min_rest_time;  /* minimum rest time for bg scan */
    u_int32_t                   bgscan_max_rest_time;  /* maximum rest time for bg scan */
    wlan_connection_sm_bgscan_policy bgscan_policy;
    os_if_t                     osif;
    os_timer_t                  sm_timer;      /* generic event timer */
    os_timer_t                  sm_roam_check_timer; /* roam check timer */
    u_int8_t                    timeout_event;      /* event to dispacth when timer expires */
    u_int32_t                   is_running:1,       /* SM is running */
                                is_stop_requested:1,      /* SM is being stopped */
                                sync_stop_requested:1,    /* SM is being stopped synchronously */
                                is_aplist_built:1,  /* ap list has been built */
                                is_reconnecting:1, /* connection lost(bmiss, deauth), reconnecting. also called hard roam */
                                lost_notification_sent:1,
                                is_apfound:1,    /* is ap found */
                                is_connected:1;  /* lost connection with an ap reconnecting */
    u_int32_t                   no_stop_disassoc:1; /* do not send disassoc on stop */
    IEEE80211_SCAN_REQUESTOR    scan_requestor;  /* requestor id assigned by scan module */
    IEEE80211_SCAN_ID           scan_id;         /* id assigned by scan scheduler */
    u_int32_t                   candidate_aplist_count;
    u_int32_t                   candidate_aplist_index;
    u_int32_t                   connection_req_time;  /* os time stamp at which connection request is made  */
    u_int32_t                   connection_lost_time; /* os time stamp at which connection is lost  */
    u_int32_t                   last_scan_time;       /* os time stamp when last scan was complete*/
    u_int32_t                   scan_channels[IEEE80211_CHAN_MAX];
    u_int16_t                   num_channels;
    u_int8_t                    last_scan_rssi;       /* last bss rssi at which scan is done  */
    u_int8_t          scan_fail_count;      /* how mainy times scan start has failed  */
    wlan_assoc_sm_event         assoc_event; /* last assoc event */
    wlan_connection_sm_event_disconnect_reason disconnect_reason; /* reason for connection down */
};

/* 20/40Mhz coexistence related macros and structures */
#define IEEE80211_MAX_2GHZ_CHANNEL_NUMBER                      14
#define SCAN_ENTRY_EXPIRE_TIME                                 60000       // 60 seconds

struct ieee80211_2040coexinfoparams {
    struct ieee80211com    *ic;
    systime_t              MaximumScanEntryAge;
    u_int32_t              intolerant40;
    u_int32_t              numLegacyChans;
    u_int8_t               buf[IEEE80211_MAX_2GHZ_CHANNEL_NUMBER];
};

static const char *connection_event_names[] = { "NONE",
                                   "CONNECT_REQUEST",
                                   "DISCONNECT_REQUEST",
                                   "SCAN_END",
                                   "ASSOC_SUCCESS",
                                   "ASSOC_FAILED",
                                   "BGSCAN_START",
                                   "DISCONNECTED",
                                   "SCAN_CANCELLED",
                                   "SCAN_START",
                                   "SCAN_RESTART",
                                   "ROAM_CHECK"
                                     };

static void ieee80211_connection_sm_debug_print (void *ctx,const char *fmt,...) 
{
    char tmp_buf[256];
    va_list ap;
     
    va_start(ap, fmt);
    vsnprintf (tmp_buf,256, fmt, ap);
    va_end(ap);
    IEEE80211_DPRINTF(((wlan_connection_sm_t) ctx)->vap_handle,
        IEEE80211_MSG_STATE, "%s", tmp_buf);
}
static void ieee80211_connection_sm_deliver_event (wlan_connection_sm_t sm, 
                                                  wlan_connection_sm_event_type type,
                                                  wlan_connection_sm_event_disconnect_reason reason)
{
    wlan_connection_sm_event evt;

#ifdef ATH_SUPPORT_HTC
    if (sm == NULL)
        return;
#endif

    evt.event = type;
    evt.disconnect_reason = reason;
    evt.assoc_reason = sm->assoc_event.reason;
    evt.reasoncode = sm->assoc_event.reasoncode;
    evt.roam_ap = sm->cur_scan_entry;

#ifdef ATH_SUPPORT_HTC
    if (sm->sm_evhandler == NULL)
         return;
    else
#endif
        (* sm->sm_evhandler)(sm, sm->osif,&evt);
}

static bool ieee80211_connection_check_timeout(wlan_connection_sm_t sm) 
{
    u_int32_t         timeout;
    u_int32_t         time_elapsed;
    if (sm->is_reconnecting) {
        timeout = sm->reconnect_timeout;
        time_elapsed = CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP() - sm->connection_lost_time);
        /*
         * check if it it time to notify the caller about the lost connection */
        if (time_elapsed > sm->connection_lost_timeout && !sm->lost_notification_sent) {
            ieee80211_connection_sm_deliver_event (sm,WLAN_CONNECTION_SM_EVENT_CONNECTION_LOST, 0);
            sm->lost_notification_sent=1;
        }
    } else {
            timeout = sm->connect_timeout;
            time_elapsed = CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP() - sm->connection_req_time);
    }

    /* timeout of max unit32 will not timeout */
    if (time_elapsed > timeout) {
        /*
         * connect timed out.
         * give up.
         */
         if (sm->is_reconnecting) {
             sm->disconnect_reason = WLAN_CONNECTION_SM_RECONNECT_TIMEDOUT; /* connection timed out */
         } else {
             sm->disconnect_reason = WLAN_CONNECTION_SM_CONNECT_TIMEDOUT; /* connection timed out */
         }
         IEEE80211_DPRINTF(sm->vap_handle, IEEE80211_MSG_STATE, "%s %sconnect time out\n",
                          __func__, sm->is_reconnecting ? "re":" ");
         ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_INIT);
            return true;
     } else {
            IEEE80211_DPRINTF(sm->vap_handle, IEEE80211_MSG_STATE, "%s scan restart \n",__func__);
            ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_SCAN);
            return true;
     }
}

static void rebuild_candidate_list(wlan_connection_sm_t sm)
{
    wlan_scan_entry_t    scan_entry; /* current bss scan entry */
    u_int32_t            i = 0;
    u_int32_t            maximum_scan_entry_age;

    if (sm->is_aplist_built)
        wlan_candidate_list_free(sm->vap_handle);
        
    maximum_scan_entry_age = 
        ieee80211_mlme_maximum_scan_entry_age(sm->vap_handle,
                                              wlan_get_last_full_scan_time(sm->vap_handle));

    wlan_candidate_list_build(sm->vap_handle, TRUE, sm->is_connected ? sm->cur_scan_entry : NULL, maximum_scan_entry_age);

    /*  take a sweep through the candidate list, bubbling the "preferred" BSSID to the top */
    if (wlan_connection_sm_is_opportunistic_roam(sm)) {
        wlan_candidate_list_prioritize_bssid(sm->vap_handle, &sm->roam_bssid);
    }
    sm->candidate_aplist_count = wlan_candidate_list_count(sm->vap_handle);
    /* make sure atleast one good AP exists */
    for (i=0;i< sm->candidate_aplist_count; ++i) {
    	scan_entry = wlan_candidate_list_get(sm->vap_handle,i);
        if(scan_entry != NULL){
            if ((CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP() - wlan_scan_entry_bad_ap_time(scan_entry)) > sm->bad_ap_timeout) ||
                    wlan_scan_entry_bad_ap_time(scan_entry) == 0) {
                break;
            }
        }
    }
    if (i == sm->candidate_aplist_count) {
        wlan_candidate_list_free(sm->vap_handle);
        sm->is_aplist_built = 0;
        sm->candidate_aplist_count = 0;
    } else {
       sm->candidate_aplist_index = 0;
       sm->is_aplist_built = 1;
    }
    
    /* clear the Opp Roam BSSID so we don't thrash on it. */
    memcpy(sm->roam_bssid.octet, BSSID_INVALID, sizeof(sm->roam_bssid.octet));
}

/*
 * 802.11 station connection state machine implementation.
 */

static void ieee80211_connection_sm_scan_evhandler(wlan_if_t vaphandle, ieee80211_scan_event *event, void *arg)  
{
    wlan_connection_sm_t sm = (wlan_connection_sm_t) arg; 

    if (vaphandle) {
        IEEE80211_DPRINTF(vaphandle, IEEE80211_MSG_SCAN,
                          "%s scan_id %d event %d reason %d \n", 
                          __func__, event->scan_id, event->type, event->reason);
    }

#if ATH_SUPPORT_MULTIPLE_SCANS
    /*
     * Ignore notifications received due to scans requested by other modules
     * and handle new event IEEE80211_SCAN_DEQUEUED.
     * Temporarily disable the checking to make the sm move.
    if (sm->scan_id != event->scan_id)
        return;
    */
#endif    /* ATH_SUPPORT_MULTIPLE_SCANS */

    if ((event->type == IEEE80211_SCAN_COMPLETED) || (event->type == IEEE80211_SCAN_DEQUEUED)) {
        if (event->reason == IEEE80211_REASON_COMPLETED) {
            ieee80211_sm_dispatch(sm->hsm_handle,IEEE80211_CONNECTION_EVENT_SCAN_END, 0, NULL); 
        } else {
            ieee80211_sm_dispatch(sm->hsm_handle,IEEE80211_CONNECTION_EVENT_SCAN_CANCELLED, 0, NULL); 
        }
    } else if (event->type == IEEE80211_SCAN_STARTED) {
       ieee80211_sm_dispatch(sm->hsm_handle,IEEE80211_CONNECTION_EVENT_SCAN_START, 0, NULL); 
    }
}


static void ieee80211_connection_sm_assoc_sm_evhandler(wlan_assoc_sm_t smhandle, os_if_t osif, 
                            wlan_assoc_sm_event *smevent)   
{
    wlan_connection_sm_t sm = (wlan_connection_sm_t) osif; 

    IEEE80211_DPRINTF(sm->vap_handle, IEEE80211_MSG_STATE, "%s : event %d reason %d \n",
                      __func__, smevent->event,smevent->reason);

    sm->assoc_event = *smevent;

    switch(smevent->event)
    {
    case WLAN_ASSOC_SM_EVENT_SUCCESS:
        sm->is_connected=1;
        sm->lost_notification_sent=0;
        ieee80211_sm_dispatch(sm->hsm_handle, IEEE80211_CONNECTION_EVENT_ASSOC_SUCCESS, 0, NULL); 
        break;

    case WLAN_ASSOC_SM_EVENT_FAILED:
        sm->is_connected=0;
        ieee80211_sm_dispatch(sm->hsm_handle, IEEE80211_CONNECTION_EVENT_ASSOC_FAILED, 0, NULL); 
        break;

    case WLAN_ASSOC_SM_EVENT_DISCONNECT:
        sm->is_connected=0;
        ieee80211_sm_dispatch(sm->hsm_handle, IEEE80211_CONNECTION_EVENT_DISCONNECTED, 0, NULL); 
        break;
    case WLAN_ASSOC_SM_EVENT_REJOINING:
        /* deliver the event directly to the user . Race ?*/
        ieee80211_connection_sm_deliver_event(sm,
                                   WLAN_CONNECTION_SM_EVENT_REJOINING, 0);
        break;
     
    }


}
/* 
 * different state related functions.
 */


/*
 * INIT
 */
static void ieee80211_connection_state_init_entry(void *ctx) 
{
    wlan_connection_sm_t sm = (wlan_connection_sm_t) ctx;
    /* 
     * force the vap to stop, this will flush the HW and
     * close the ath device if this is the last vap.
     */ 
    wlan_mlme_stop_bss(sm->vap_handle, WLAN_MLME_STOP_BSS_F_FORCE_STOP_RESET);  

    if (sm->is_aplist_built)
        wlan_candidate_list_free(sm->vap_handle);
    sm->candidate_aplist_count = 0;
    sm->candidate_aplist_index = 0;
    sm->is_aplist_built = 0;
    if (sm->cur_scan_entry)
        wlan_scan_entry_remove_reference(sm->cur_scan_entry);
    sm->cur_scan_entry = NULL;
    sm->is_reconnecting=0;
    sm->is_apfound=0;
    sm->is_connected=0;
    sm->is_running=0;
    sm->is_stop_requested=0;
    sm->sync_stop_requested = 0;
    sm->lost_notification_sent=0;
    OS_MEMZERO(sm->cur_bssid,sizeof(sm->cur_bssid));

    /* NOTE: Keep this function call always at the end, to allow
     * connection restart from this event
     */
    ieee80211_connection_sm_deliver_event (sm,
      WLAN_CONNECTION_SM_EVENT_CONNECTION_DOWN, sm->disconnect_reason);
}


static void ieee80211_connection_state_init_exit(void *ctx) 
{
    /* NONE */
}


static bool ieee80211_connection_state_init_event(void *ctx, u_int16_t event, u_int16_t event_data_len, void *event_data) 
{
    wlan_connection_sm_t sm = (wlan_connection_sm_t) ctx;
    systime_t last_scan_time;
    u_int32_t elapsed;
    ieee80211_scan_info last_scan_info;
    bool des_bssid_set=false;
    u_int32_t n_desired_bssid = 0;

    switch(event) {
    case IEEE80211_CONNECTION_EVENT_CONNECT_REQUEST:
        last_scan_time = wlan_get_last_scan_time(sm->vap_handle);
        wlan_get_last_scan_info(sm->vap_handle, &last_scan_info);
        elapsed = CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP() - last_scan_time);

        /*
         * check if at least one desired bssid is set (non broadcast).
         * if so, look for ap in the candidate list in an attempt to
         * move directly to CONNECTING instead of moving to SCAN
         */
        n_desired_bssid = wlan_aplist_get_desired_bssid_count(sm->vap_handle);
        if (n_desired_bssid) {
            int i;
            u_int8_t *des_bssid;
            for (i = 0;i < n_desired_bssid; i++) {
                if (wlan_aplist_get_desired_bssid(sm->vap_handle, i, &des_bssid) == EOK) {
                    if (!IEEE80211_IS_BROADCAST(des_bssid)) {
                        des_bssid_set = true;
                    }
                }
            }
        }
        IEEE80211_DPRINTF(sm->vap_handle, IEEE80211_MSG_STATE,
                          "%s event CONNECT_REQ: n_desired_bssid=%d, des_bssid_set=%d, elapsed=%d, scan_cache_valid_time=%d, last_scan_info.cancelled=%d\n",
                          __func__, n_desired_bssid, des_bssid_set, elapsed, sm->scan_cache_valid_time, last_scan_info.cancelled);

        /*
         * if the scan cache is hot then build the candidate ap list using the scan cache
         * and move to the connecting state (if we've been given an non-broadcast desired
         * bssid entry, then check the cache regardless of time).
         * if the scan cache is stale (or) last scan was cancelled then move to the scan state.
         */
        if ((elapsed > sm->scan_cache_valid_time) && !des_bssid_set) {
            ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_SCAN);
        } else {
            /*
             * build the acandidate ap list.
             */
            rebuild_candidate_list(sm);
            IEEE80211_DPRINTF(sm->vap_handle, IEEE80211_MSG_STATE,
                              "%s event CONNECT_REQ: sm->candidate_aplist_count=%d\n",
                              __func__, sm->candidate_aplist_count);
            if (sm->candidate_aplist_count) {
                ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_CONNECTING);
            } else {
                ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_SCAN);
            }
        }
        return true;
        break;
    default:
        return false;
        break;
    }
}


/*
 * SCAN
 */
static void ieee80211_connection_state_scan_entry(void *ctx) 
{
    wlan_connection_sm_t sm = (wlan_connection_sm_t) ctx;
    struct ieee80211com *ic = sm->vap_handle->iv_ic;
    ieee80211_scan_params *scan_params;
    ieee80211_ssid    ssid_list[IEEE80211_SCAN_MAX_SSID];
    int               n_ssid;
    u_int8_t          opt_ie[IEEE80211_OPTIE_MAX];
    u_int32_t         length;
    IEEE80211_SCAN_PRIORITY priority;

    /*
     * if there is a bg scan in progress.
     * convert it into an fg scan (TO-DO).
     */
    scan_params = (ieee80211_scan_params *) OS_MALLOC(sm->os_handle,
						      sizeof(*scan_params), 0);
    if (scan_params == NULL)
	    return;
    OS_MEMZERO(scan_params,sizeof(ieee80211_scan_params));
    n_ssid = ieee80211_get_desired_ssidlist(sm->vap_handle, ssid_list, IEEE80211_SCAN_MAX_SSID);
    wlan_set_default_scan_parameters(sm->vap_handle,scan_params,IEEE80211_M_STA,true,true,false,true,n_ssid,ssid_list,0);
    scan_params->min_dwell_time_active = scan_params->max_dwell_time_active = 100;
    if (wlan_mlme_get_optie(sm->vap_handle, opt_ie, &length, IEEE80211_OPTIE_MAX)) {
        scan_params->ie_data = opt_ie;
        scan_params->ie_len = length;
    }
    priority = IEEE80211_SCAN_PRIORITY_LOW;
    scan_params->flags = IEEE80211_SCAN_ALLBANDS | IEEE80211_SCAN_ACTIVE;
    scan_params->flags |= IEEE80211_SCAN_ADD_BCAST_PROBE;

    /* If half/quarter rates are set, scan half or quarter channels */

    if (ic->ic_chanbwflag & IEEE80211_CHAN_HALF) {
        scan_params->flags |= IEEE80211_SCAN_HALF_RATE;
    } else if (ic->ic_chanbwflag & IEEE80211_CHAN_QUARTER) {
        scan_params->flags |= IEEE80211_SCAN_QUARTER_RATE;
    }

    scan_params->num_channels = sm->num_channels;
    scan_params->chan_list = sm->scan_channels;
     if (ieee80211_ic_enh_ind_rpt_is_set(sm->vap_handle->iv_ic)) {
        /* Flushing all the scan cache */
        wlan_scan_table_flush(sm->vap_handle);
        scan_params->flags |= IEEE80211_SCAN_FORCED;
        scan_params->num_channels = 0;
        scan_params->chan_list = NULL;
        scan_params->min_rest_time = MIN_REST_TIME ;
        scan_params->max_rest_time = MAX_REST_TIME ;
        scan_params->min_dwell_time_active = MIN_DWELL_TIME_ACTIVE ;
        scan_params->max_dwell_time_active = MAX_DWELL_TIME_ACTIVE ;

        scan_params->type=IEEE80211_SCAN_BACKGROUND;
        scan_params->check_termination_context = sm->vap_handle;
        scan_params->check_termination_function = scanner_check_for_bssid_entry;
        scan_params->init_rest_time = INIT_REST_TIME;
        if (sm->vap_handle->iv_ic->ic_is_mode_offload(ic)) {
            priority = IEEE80211_SCAN_PRIORITY_HIGH;
        }
    } else {
        scan_params->type = IEEE80211_SCAN_FOREGROUND;
    }

    if (wlan_scan_start(sm->vap_handle, 
                        scan_params, 
                        sm->scan_requestor,
                        priority,
                        &(sm->scan_id)) != EOK) {
        IEEE80211_DPRINTF(sm->vap_handle, IEEE80211_MSG_STATE, "%s scan_start failed\n",__func__);
        /* 
         * scan start failed.
         * we will restart the scan when the timer fires.
         */
         sm->timeout_event = IEEE80211_CONNECTION_EVENT_SCAN_RESTART;
         OS_SET_TIMER(&sm->sm_timer,SCAN_RESTART_TIME);
         sm->scan_fail_count++;
    } else {
         sm->scan_fail_count =0; /* scan start success, reset the fail  count */
    }
    OS_FREE(scan_params);
}


static void ieee80211_connection_state_scan_exit(void *ctx) 
{
    /* NONE */
}

static bool ieee80211_connection_state_scan_event(void *ctx, u_int16_t event, u_int16_t event_data_len, void *event_data) 
{
    wlan_connection_sm_t sm = (wlan_connection_sm_t) ctx;
    switch(event) {
    case IEEE80211_CONNECTION_EVENT_SCAN_END:
        /* build the candidate list from the scanned entries */
        rebuild_candidate_list(sm);
        if (sm->vap_handle->iv_ic->ic_roaming != IEEE80211_ROAMING_MANUAL && sm->candidate_aplist_count) {
                /*
                 * there is atleast one AP in the list.
                 * try connecting.
                 */
                IEEE80211_DPRINTF(sm->vap_handle, IEEE80211_MSG_STATE, "%s: found %d candidate APs\n",__func__,
                                  sm->candidate_aplist_count);
                ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_CONNECTING); 
                return true;
        } 

        /*
         * No candidate APs found.
         */
        IEEE80211_DPRINTF(sm->vap_handle, IEEE80211_MSG_STATE, "%s no candidate APs found\n",__func__);

        return ieee80211_connection_check_timeout(sm); 
        break;

         case IEEE80211_CONNECTION_EVENT_SCAN_TERMCHK :
            /*
             * scan has seen a new entry to scan cache,
             * make sure to check if it is your candidate and cancel scan if yes.
             */
            sm->is_apfound = 0;
            rebuild_candidate_list(sm);
            if (sm->candidate_aplist_count) {
                if (wlan_scan_cancel(sm->vap_handle,
                            sm->scan_requestor,
                            IEEE80211_VAP_SCAN,
                            sm->sync_stop_requested ? IEEE80211_SCAN_CANCEL_SYNC : IEEE80211_SCAN_CANCEL_ASYNC) == EOK) {
                    /* cancel is succenfully initiated */
                    sm->is_apfound = 1;
                    ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_SCAN_CANCELLING);

                    /* candidate is found ; cancel the scan */
                }
                return true;
            }
            break;

    case IEEE80211_CONNECTION_EVENT_DISCONNECT_REQUEST: 
        if (wlan_scan_cancel(sm->vap_handle, 
                             sm->scan_requestor,
                             IEEE80211_VAP_SCAN,
                             sm->sync_stop_requested ? IEEE80211_SCAN_CANCEL_SYNC : IEEE80211_SCAN_CANCEL_ASYNC) == EOK) {
	       /* cancel is succenfully initiated */
           ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_SCAN_CANCELLING); 
        } else {
	   /* already cancelled  */
           ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_INIT); 
        }
        return true;
        break;

    case IEEE80211_CONNECTION_EVENT_SCAN_CANCELLED:
        /* 
         * somebody  else has cancelled our scan.
         * strt a timer if nobody restarts the scan , 
         * we will restart the scan when the timer fires.
         */
         sm->timeout_event = IEEE80211_CONNECTION_EVENT_SCAN_RESTART;
         OS_SET_TIMER(&sm->sm_timer,SCAN_RESTART_TIME);
        return true;
        break;

    case IEEE80211_CONNECTION_EVENT_SCAN_START:
        /*
         * clear the restart timer. the timer may have been armed if
         * we received CANCELLED event before.
         */
         sm->timeout_event = IEEE80211_CONNECTION_EVENT_CONNECT_NONE;
         OS_CANCEL_TIMER(&sm->sm_timer);
        return true;
        break;

    case IEEE80211_CONNECTION_EVENT_SCAN_RESTART:
        /*
         * nobody has restarted the scan after cancelling our scan.
         * lests restart.
         */
        if (sm->scan_fail_count >= MAX_SCAN_FAIL_COUNT) {
      	   ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_INIT); 
        } else {
           ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_SCAN); 
        }
        return true;
        break;

    default:
        return false;
        break;
    }
    return false;
}


/*
 * CONNECTING 
 */
static void ieee80211_connection_state_connecting_entry(void *ctx)
{
    wlan_connection_sm_t sm = (wlan_connection_sm_t) ctx;
    wlan_scan_entry_t scan_entry; /* current bss scan entry */
    struct ieee80211_channel *scan_chan;
    bool roaming=false;
    struct ieee80211com *ic = sm->vap_handle->iv_ic;

    scan_entry = wlan_candidate_list_get(sm->vap_handle, sm->candidate_aplist_index);
    /*
     * the previous state need to make sure that there is 
     * at least one roam candidate.
     */
    ASSERT(scan_entry != NULL);

    if(scan_entry == NULL)
        return;
    scan_chan = ieee80211_scan_entry_channel(scan_entry);

    /*
     * If WDS is enabled in STA VAP, we are most likely a repeater with another
     * AP VAP (pending to be up). Set the PHY/Radio in a super mode
     * (11ng is a supermode for 11g), so that, the AP VAP can be in 11n mode,
     * though the STA VAP is connected to 11g rootAP
     */
    if (ieee80211_ic_enh_ind_rpt_is_set(sm->vap_handle->iv_ic)) {
#if ATH_SUPPORT_WRAP
        if (!sm->vap_handle->iv_ic->ic_mpsta_vap || (sm->vap_handle->iv_ic->ic_mpsta_vap && sm->vap_handle->iv_mpsta)) {
#endif
            struct ieee80211_channel *phychan = NULL;
            struct ieee80211_channel chan;
            chan.ic_ieee = scan_chan->ic_ieee;
            chan.ic_freq = scan_chan->ic_freq;
            chan.ic_flags = scan_chan->ic_flags;
            chan.ic_vhtop_ch_freq_seg2 = scan_chan->ic_vhtop_ch_freq_seg2;

            phychan = ieee80211_find_channel(sm->vap_handle->iv_ic, chan.ic_freq, chan.ic_vhtop_ch_freq_seg2, chan.ic_flags);

            if (phychan == NULL)
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: not able to locate channel with freq+flags.\n", __func__);

            /* check if the chosen channel is the same as the curchan */
            if (phychan && (sm->vap_handle->iv_ic->ic_curchan != phychan)) {
                /* Do not bring down the AP VAPS instead try a channel switch */
                if(!wlan_mlme_is_txcsa_set(sm->vap_handle)) {
                    if (!ic->ic_is_mode_offload(ic)) {
                        ieee80211_connection_sm_deliver_event(sm, WLAN_CONNECTION_SM_EVENT_ENH_IND_STOP, 0);
                    }
                }
            }
#if ATH_SUPPORT_WRAP
        }
        else {
            struct ieee80211vap *mpstavap = sm->vap_handle->iv_ic->ic_mpsta_vap;
            if (ieee80211_channel_ieee(ieee80211_scan_entry_channel(scan_entry)) != ieee80211_channel_ieee(mpstavap->iv_bsschan)) {
                IEEE80211_DPRINTF(sm->vap_handle, IEEE80211_MSG_STATE,"%s: scan_entry chan %u, ivbss_chan %u\n",
                                    __func__,ieee80211_channel_ieee(ieee80211_scan_entry_channel(scan_entry)),
                                    ieee80211_channel_ieee(mpstavap->iv_bsschan));
                return;
            }
        }
#endif
    }

    if (wlan_assoc_sm_start(sm->assoc_sm_handle, scan_entry, sm->cur_scan_entry ? sm->cur_bssid:NULL) != 0) {
         IEEE80211_DPRINTF(sm->vap_handle, IEEE80211_MSG_STATE, "%s wlan_assoc_sm_start failed\n",__func__,
                               sm->candidate_aplist_count);
         /*
          * generate a connection failed event asynchronosly.
          * we can not issue stat transitions form entry/exit 
          * action handlers.
          */
         sm->timeout_event = IEEE80211_CONNECTION_EVENT_ASSOC_FAILED;
         OS_SET_TIMER(&sm->sm_timer, 0);
    }
    if (sm->cur_scan_entry) {
        if (sm->cur_scan_entry != scan_entry) {
            roaming=true; /* roaming from current AP to a different AP */
        }
        wlan_scan_entry_remove_reference(sm->cur_scan_entry);
    }
    sm->cur_scan_entry = scan_entry;
    wlan_scan_entry_add_reference(sm->cur_scan_entry);
    if (roaming) {
        ieee80211_connection_sm_deliver_event(sm, WLAN_CONNECTION_SM_EVENT_ROAMING, 0);
    }
}


static void ieee80211_connection_state_connecting_exit(void *ctx) 
{
    /* NONE */
}

static bool ieee80211_connection_state_connecting_event(void *ctx, u_int16_t event, u_int16_t event_data_len, void *event_data) 
{
    wlan_connection_sm_t sm = (wlan_connection_sm_t) ctx;
    u_int8_t connection_reset=0;
    u_int8_t cur_bssid[IEEE80211_ADDR_LEN];
    switch(event) {
    case IEEE80211_CONNECTION_EVENT_ASSOC_SUCCESS: 
        sm->lost_notification_sent = 0;
        wlan_scan_entry_set_status(sm->cur_scan_entry,0); /* association success */
        wlan_scan_entry_set_lastassoc(sm->cur_scan_entry, OS_GET_TIMESTAMP()) ;
        /* 
         * this compare needs to be done before changing the state to CONNECTED.
         * the CONNECTED state will copy the current bssid to cur_bssid and the
         * follwing comparison is always tru after transitioning to CONNECTED state.
         */
        wlan_vap_get_bssid(sm->vap_handle, cur_bssid) ;
        if (IEEE80211_ADDR_EQ(sm->cur_bssid,cur_bssid)) {
            connection_reset=1;
        }
        sm->last_scan_rssi = 0; 
        ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_CONNECTED); 
        if (connection_reset) {
            ieee80211_connection_sm_deliver_event(sm,
                                   WLAN_CONNECTION_SM_EVENT_CONNECTION_RESET, 0 );
        } else {
            if (sm->is_reconnecting) {
                ieee80211_connection_sm_deliver_event(sm,
                                                      WLAN_CONNECTION_SM_EVENT_ROAM, 0);
            } else {
                ieee80211_connection_sm_deliver_event(sm,
                                                      WLAN_CONNECTION_SM_EVENT_CONNECTION_UP, 0);
            }
        }
        return true;
        break;

    case IEEE80211_CONNECTION_EVENT_ASSOC_FAILED: 
#if ATH_SUPPORT_WRAP
        if (!sm->vap_handle->iv_psta) {
#endif
            wlan_scan_entry_set_status(sm->cur_scan_entry, AP_STATE_BAD); /* association failed */
            wlan_scan_entry_set_bad_ap_time(sm->cur_scan_entry, OS_GET_TIMESTAMP()) ;
            sm->candidate_aplist_index++;

        /*
         * check if there any more good APs, if more good APs in the canddate AP list, try the next one.
         */
        while (sm->candidate_aplist_index < sm->candidate_aplist_count) {
            wlan_scan_entry_t scan_entry; 
            scan_entry = wlan_candidate_list_get(sm->vap_handle,sm->candidate_aplist_index);
            if(scan_entry != NULL){
                if ((CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP() - wlan_scan_entry_bad_ap_time(scan_entry)) > sm->bad_ap_timeout) ||
                        (wlan_scan_entry_bad_ap_time(scan_entry) == 0)) {
                    break;
                }
            }
            sm->candidate_aplist_index++;
        }
#if ATH_SUPPORT_WRAP
        }
#endif

        /* Issue : Bangradar at QWRAP Repeater AP during CAC,  REPEATER_CAC=>INIT state change
         * loops forever  beacuse candidate_aplist_index is 0 and candidate_aplist_count is 1.
         * Fix : If Radar found on current chan then AP moves from REPEATER_CAC state to INIT state
         */
        if (sm->candidate_aplist_index < sm->candidate_aplist_count) {
            if (!wlan_mlme_is_chan_radar(sm->cur_scan_entry)) {
                ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_CONNECTING);
            } else {
                return ieee80211_connection_check_timeout(sm);
            }
        } else {
            /*
             * no more in the list. go back to scanning.
             */
            return ieee80211_connection_check_timeout(sm); 
        }
        
        return true;
        break;

    case IEEE80211_CONNECTION_EVENT_DISCONNECT_REQUEST: 
        ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_DISCONNECTING); 
        return true;
        break;


    default:
        return false;
        break;
    }
}

/*
 * functions for handling 20/40Mhz coexistence
 */

static int
ieee80211_get2040coexinfo(void *arg, wlan_scan_entry_t scan_entry)
{
    struct ieee80211_ie_htcap_cmn    *pHtcap;
    u_int16_t                        htcap;
    struct ieee80211_2040coexinfoparams *pInfoParam =
                                        (struct ieee80211_2040coexinfoparams *) arg;
    int i;

    // Lock scan entry
    wlan_scan_entry_lock(scan_entry);

    //
    // Ignore stale entries
    //
    if (wlan_scan_entry_age(scan_entry) < pInfoParam->MaximumScanEntryAge)
    {
        pHtcap = (struct ieee80211_ie_htcap_cmn *)ieee80211_scan_entry_htcap(scan_entry);

            // Find if threre is any HT40 intolerant station and count number of legacy channels
            if (pHtcap) {
                htcap  = le16toh(pHtcap->hc_cap);
                if (htcap & IEEE80211_HTCAP_C_INTOLERANT40) {
                    pInfoParam->intolerant40++;
                }
            } else if (IEEE80211_IS_CHAN_2GHZ(wlan_scan_entry_channel(scan_entry))) {
                for (i = 0; i < pInfoParam->numLegacyChans; i++) {
                    if (wlan_channel_ieee(wlan_scan_entry_channel(scan_entry)) == pInfoParam->buf[i]) {
                        break;
                    }
                }

                if (i == pInfoParam->numLegacyChans) {// not found, add it to the buffer
                    ASSERT(pInfoParam->numLegacyChans <= IEEE80211_MAX_2GHZ_CHANNEL_NUMBER);
                    pInfoParam->buf[pInfoParam->numLegacyChans++] = wlan_channel_ieee(wlan_scan_entry_channel(scan_entry));
                }
            }
    }

    // Unlock scan entry
    wlan_scan_entry_unlock(scan_entry);

    return EOK;
}

static void ieee80211_check_2040_coexistinfo(wlan_if_t vaphandle)
{
    struct ieee80211_action_mgt_args actionargs;
    struct ieee80211_action_mgt_buf  actionbuf;
    struct ieee80211_2040coexinfoparams get2040infoparam;
    systime_t CurrentTime = OS_GET_TIMESTAMP();

    OS_MEMZERO(&actionargs, sizeof(struct ieee80211_action_mgt_args));
    OS_MEMZERO(&get2040infoparam, sizeof(get2040infoparam));
    get2040infoparam.ic                  = vaphandle->iv_ic;
    get2040infoparam.MaximumScanEntryAge = 
        CONVERT_SYSTEM_TIME_TO_MS(CurrentTime - wlan_get_last_full_scan_time(vaphandle)) +
        SCAN_ENTRY_EXPIRE_TIME;

    wlan_scan_table_iterate(vaphandle, ieee80211_get2040coexinfo, &get2040infoparam);

    if (get2040infoparam.numLegacyChans || get2040infoparam.intolerant40) {
        actionargs.category = IEEE80211_ACTION_CAT_PUBLIC;
        actionargs.action   = 0;
        actionargs.arg1     = get2040infoparam.intolerant40 ? 1 : 0;
        actionargs.arg3     = get2040infoparam.numLegacyChans; // number of channel
        OS_MEMCPY(actionbuf.buf, get2040infoparam.buf, get2040infoparam.numLegacyChans);

        ieee80211_send_action(vaphandle->iv_bss, (void *)&actionargs, (void *)&actionbuf);
    }
}

static void ieee80211_scan_check_2040_coexistinfo(wlan_if_t vaphandle)
{
    if (!(vaphandle->iv_ic->ic_flags & IEEE80211_F_COEXT_DISABLE) && 
        !IEEE80211_IS_CHAN_5GHZ(vaphandle->iv_ic->ic_curchan) &&
        IEEE80211_IS_CHAN_11N(vaphandle->iv_ic->ic_curchan)) {

        ieee80211_check_2040_coexistinfo(vaphandle);
    }
}

/*
 * CONNECTED
 */
static void ieee80211_connection_state_connected_entry(void *ctx) 
{
    wlan_connection_sm_t sm = (wlan_connection_sm_t) ctx;
    /* start roam check timer */ 
    OS_SET_TIMER(&sm->sm_roam_check_timer, sm->roam_check_period);
    wlan_vap_get_bssid(sm->vap_handle, sm->cur_bssid);
    sm->is_reconnecting = 0; /* not reconnecting any more */
}


static void ieee80211_connection_state_connected_exit(void *ctx) 
{
    wlan_connection_sm_t sm = (wlan_connection_sm_t) ctx;
    /* stop roam check timer */ 
    OS_CANCEL_TIMER(&sm->sm_roam_check_timer);
}

static bool ieee80211_connection_state_connected_event(void *ctx, u_int16_t event, u_int16_t event_data_len, void *event_data) 
{
    wlan_connection_sm_t sm = (wlan_connection_sm_t) ctx;
    wlan_if_t vap = sm->vap_handle;

    switch(event) {

    case IEEE80211_CONNECTION_EVENT_ASSOC_FAILED: 
        sm->connection_lost_time = OS_GET_TIMESTAMP();
#if ATH_SUPPORT_WRAP
        if (!sm->vap_handle->iv_psta) {
#endif
            wlan_scan_entry_set_bad_ap_time(sm->cur_scan_entry, sm->connection_lost_time);
            wlan_scan_entry_set_status(sm->cur_scan_entry, AP_STATE_BAD); /* association failed */
#if ATH_SUPPORT_WRAP
        }
#endif
        /*
         * if it was due to becon miss.
         * reset the time stamp on the current AP so that
         * it will not be on the top of the list.
         */
        if (sm->assoc_event.reason == WLAN_ASSOC_SM_REASON_AUTH_FAILED) {
            /* we were deauthed and reauth failed,  we need to demerit the current AP */ 
            /* scan entry API needs needs to add an API to demerit a scan entry */
            /* TO-DO */
        }
        if (sm->assoc_event.reason == WLAN_ASSOC_SM_REASON_BEACON_MISS) {
            /* 
             * reset the stamp to 0, so that we will not use the entry untill
             * we really seen a beacon from the bss.
             */
           wlan_scan_entry_reset_timestamp(sm->cur_scan_entry);
        }
        if (vap->auto_assoc) {
            sm->is_reconnecting = 1; /* set the reconnecting to 1 */
            rebuild_candidate_list(sm);
            if (sm->candidate_aplist_count) {
                ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_CONNECTING); 
            } else {
                ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_SCAN); 
            }
        } else {
            sm->is_reconnecting = 0; /* set the reconnecting to 0 */
            ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_INIT);
        }
        return true;
        break;

    case IEEE80211_CONNECTION_EVENT_ASSOC_SUCCESS: 
        /* assoc state machine reconnected to the AP */
        ieee80211_connection_sm_deliver_event(sm,
                                   WLAN_CONNECTION_SM_EVENT_CONNECTION_RESET, 0);
        return true;
        break;

    case IEEE80211_CONNECTION_EVENT_ROAM_CHECK: 
        rebuild_candidate_list(sm);
        if (sm->candidate_aplist_count) {
            if (sm->cur_scan_entry == wlan_candidate_list_get(sm->vap_handle,sm->candidate_aplist_index)) {
                /* there is no better AP, the current one is still the best */ 
                return true;
            }
            /* there is a better AP, roam to the new AP */
            ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_ROAM); 
        }
        return true;
        break;

    case IEEE80211_CONNECTION_EVENT_DISCONNECT_REQUEST: 
        ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_DISCONNECTING); 
        return true;
        break;

    case IEEE80211_CONNECTION_EVENT_BGSCAN_START: 
        ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_BGSCAN); 
        return true;
        break;

    case IEEE80211_CONNECTION_EVENT_SCAN_END:
        /* add for 20/40 Coexistence check */
        ieee80211_scan_check_2040_coexistinfo(sm->vap_handle);
        return false;
        break;
    default:
        return false;
        break;
    }
}


/*
 * BGSCAN
 */
static void ieee80211_connection_state_bgscan_entry(void *ctx) 
{
    wlan_connection_sm_t sm = (wlan_connection_sm_t) ctx;
    struct ieee80211com *ic = sm->vap_handle->iv_ic;
    ieee80211_scan_params *scan_params = NULL;
    ieee80211_ssid    ssid_list[IEEE80211_SCAN_MAX_SSID];
    int               n_ssid;
    bool              forced_scan=false;
    u_int8_t          opt_ie[IEEE80211_OPTIE_MAX];
    u_int32_t         length;

    scan_params = (ieee80211_scan_params *) OS_MALLOC(sm->os_handle,
						      sizeof(*scan_params), 0);
    if (scan_params == NULL)
	    return;
    OS_MEMZERO(scan_params,sizeof(ieee80211_scan_params));
    n_ssid = ieee80211_get_desired_ssidlist(sm->vap_handle, ssid_list, IEEE80211_SCAN_MAX_SSID);
    if (wlan_scan_entry_rssi(sm->cur_scan_entry) <= sm->bgscan_rssi_thresh_forced_scan) {
       forced_scan=true;
    }
    wlan_set_default_scan_parameters(sm->vap_handle,scan_params,IEEE80211_M_STA,true,forced_scan,true,true,n_ssid,ssid_list,1);
    scan_params->min_dwell_time_active = sm->bgscan_min_dwell_time;
    scan_params->max_dwell_time_active = sm->bgscan_max_dwell_time;
    scan_params->repeat_probe_time = 0; 
    if (wlan_mlme_get_optie(sm->vap_handle, opt_ie, &length, IEEE80211_OPTIE_MAX)) {
        scan_params->ie_data = opt_ie;
        scan_params->ie_len = length;
    }
    scan_params->min_rest_time = sm->bgscan_min_rest_time;
    scan_params->max_rest_time = sm->bgscan_max_rest_time;
    scan_params->type = IEEE80211_SCAN_BACKGROUND;
    scan_params->flags |= IEEE80211_SCAN_ALLBANDS | IEEE80211_SCAN_ACTIVE;
    scan_params->flags |= IEEE80211_SCAN_ADD_BCAST_PROBE;

    /* If half/quarter rates are set, scan half or quarter channels */
    if (ic->ic_chanbwflag & IEEE80211_CHAN_HALF) {
        scan_params->flags |= IEEE80211_SCAN_HALF_RATE;
    } else if (ic->ic_chanbwflag & IEEE80211_CHAN_QUARTER) {
        scan_params->flags |= IEEE80211_SCAN_QUARTER_RATE;
    }

    scan_params->min_beacon_count = 0;
    scan_params->num_channels = sm->num_channels;
    scan_params->chan_list = sm->scan_channels;
    if (wlan_scan_start(sm->vap_handle, 
                        scan_params,
                        sm->scan_requestor,
                        IEEE80211_SCAN_PRIORITY_LOW,
                        &(sm->scan_id)) != EOK) {
        IEEE80211_DPRINTF(sm->vap_handle, IEEE80211_MSG_STATE, "%s scan_start failed\n",__func__);
    }
    OS_FREE(scan_params);
}


static void ieee80211_connection_state_bgscan_exit(void *ctx) 
{
    wlan_connection_sm_t sm = (wlan_connection_sm_t) ctx;
    /* stop roam check timer */ 
    OS_CANCEL_TIMER(&sm->sm_roam_check_timer);
}

static bool ieee80211_connection_state_bgscan_event(void *ctx, u_int16_t event, u_int16_t event_data_len, void *event_data) 
{
    wlan_connection_sm_t sm = (wlan_connection_sm_t) ctx;
    switch(event) {

    case IEEE80211_CONNECTION_EVENT_ASSOC_FAILED: 
        sm->connection_lost_time = OS_GET_TIMESTAMP();
#if ATH_SUPPORT_WRAP
        if (!sm->vap_handle->iv_psta) {
#endif
            wlan_scan_entry_set_bad_ap_time(sm->cur_scan_entry, sm->connection_lost_time);
            wlan_scan_entry_set_status(sm->cur_scan_entry, AP_STATE_BAD); /* association failed */
#if ATH_SUPPORT_WRAP
        }
#endif
        /*
         * if it was due to becon miss.
         * reset the time stamp on the current AP so that
         * it will not be on the top of the list.
         */
        if (sm->assoc_event.reason == WLAN_ASSOC_SM_REASON_BEACON_MISS) {
           wlan_scan_entry_reset_timestamp(sm->cur_scan_entry);
        }
        sm->is_reconnecting = 1; /* set the reconnecting to 1 */
        if (wlan_scan_cancel(sm->vap_handle,
                             sm->scan_requestor,
                             IEEE80211_VAP_SCAN,
                             sm->sync_stop_requested ? IEEE80211_SCAN_CANCEL_SYNC : IEEE80211_SCAN_CANCEL_ASYNC) == EOK) {
            ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_SCAN_CANCELLING); 
        } else {
            /* 
             * no scan in progres. try connecting back 
             */
            rebuild_candidate_list(sm);
            if (sm->candidate_aplist_count) {
                ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_CONNECTING); 
            } else {
                ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_SCAN); 
            }
        }
        return true;
        break;

    case IEEE80211_CONNECTION_EVENT_SCAN_START:
        return true;
        break;

    case IEEE80211_CONNECTION_EVENT_SCAN_END:
        sm->last_scan_rssi = wlan_scan_entry_rssi(sm->cur_scan_entry);
        sm->last_scan_time = OS_GET_TIMESTAMP(); 
        /* Opportunistic Roam - add wlan_connection_sm_is_opportunistic_roam() */
        if ((wlan_scan_entry_rssi(sm->cur_scan_entry) > sm->roam_threshold) &&
                !(wlan_connection_sm_is_opportunistic_roam(sm)))
        {
            /* if rssi is above the roam threshold , go back to connected state */
            ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_CONNECTED); 
            return true;
        }
        /*
         * rssi < roam_threshold. try roaming.
         * build the acandidate ap list first.
         */
        rebuild_candidate_list(sm);
        if (sm->candidate_aplist_count) {
            if (sm->cur_scan_entry == wlan_candidate_list_get(sm->vap_handle,sm->candidate_aplist_index)) {
                /* there is no better AP */ 
                ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_CONNECTED); 
                return true;
            }
            /* roam to new AP */
            ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_ROAM); 
        }
        return true;
        break;

    case IEEE80211_CONNECTION_EVENT_SCAN_CANCELLED:
        /* 
         * scan is cancelled by somebody(mostly likely by user),
         * go back to CONNECTED.
         */
         ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_CONNECTED); 
        return true;
        break;

    case IEEE80211_CONNECTION_EVENT_DISCONNECT_REQUEST: 
        if (wlan_scan_cancel(sm->vap_handle,
                             sm->scan_requestor,
                             IEEE80211_VAP_SCAN,
                             sm->sync_stop_requested ? IEEE80211_SCAN_CANCEL_SYNC : IEEE80211_SCAN_CANCEL_ASYNC) == EOK) {
            ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_SCAN_CANCELLING); 
        } else {
            ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_DISCONNECTING); 
        }
        return true;


    default:
        return false;
        break;
    }
}

/*
 * DISCONNECTING
 */
static void ieee80211_connection_state_disconnecting_entry(void *ctx) 
{
    u_int32_t flags = IEEE80211_ASSOC_SM_STOP_DISASSOC ;
    wlan_connection_sm_t sm = (wlan_connection_sm_t) ctx;
    if (sm->sync_stop_requested) {
         flags |= IEEE80211_ASSOC_SM_STOP_SYNC ;
    }
    if (sm->no_stop_disassoc)
	    flags &= ~IEEE80211_ASSOC_SM_STOP_DISASSOC;
    wlan_assoc_sm_stop(sm->assoc_sm_handle,flags );
}


static void ieee80211_connection_state_disconnecting_exit(void *ctx) 
{
}

static bool ieee80211_connection_state_disconnecting_event(void *ctx, u_int16_t event, u_int16_t event_data_len, void *event_data) 
{
    wlan_connection_sm_t sm = (wlan_connection_sm_t) ctx;
    switch(event) {
    case IEEE80211_CONNECTION_EVENT_DISCONNECTED:
    case IEEE80211_CONNECTION_EVENT_ASSOC_FAILED: 
        ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_INIT); 
        return true;
        break;
    default:
        return false;
        break;
    }
}

/*
 * ROAM
 */
static void ieee80211_connection_state_roam_entry(void *ctx) 
{
    wlan_connection_sm_t sm = (wlan_connection_sm_t) ctx;
    /*
     * stop the current BSS, do not send dis assoc.
     */
    wlan_assoc_sm_stop(sm->assoc_sm_handle, false);
}

static void ieee80211_connection_state_roam_exit(void *ctx) 
{
}

static bool ieee80211_connection_state_roam_event(void *ctx, u_int16_t event, u_int16_t event_data_len, void *event_data) 
{
    wlan_connection_sm_t sm = (wlan_connection_sm_t) ctx;
    switch(event) {

    case IEEE80211_CONNECTION_EVENT_DISCONNECTED: 
        /* disconnected fom previous bss */
        ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_CONNECTING); 
        return true;
        break;

    case IEEE80211_CONNECTION_EVENT_DISCONNECT_REQUEST: 
        ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_DISCONNECTING); 
        return true;

    default:
        return false;
        break;
    }
}

/*
 * SCAN CANCELLING 
 */
static void ieee80211_connection_state_scan_cancelling_entry(void *ctx) 
{
}

static void ieee80211_connection_state_scan_cancelling_exit(void *ctx) 
{
}

static bool ieee80211_connection_state_scan_cancelling_event(void *ctx, u_int16_t event, u_int16_t event_data_len, void *event_data) 
{
    wlan_connection_sm_t sm = (wlan_connection_sm_t) ctx;
    switch(event) {

    case IEEE80211_CONNECTION_EVENT_SCAN_END: 
    case IEEE80211_CONNECTION_EVENT_SCAN_CANCELLED:
     if ((!sm->is_stop_requested && sm->is_reconnecting) ||(!sm->is_stop_requested && sm->is_apfound )) {
           /*
            * if the connection is lost while we were scanning 
            * (BG scanning while in BGSCAN, FG scan while in SCAN state).
            */
             sm->is_apfound = 0;
            rebuild_candidate_list(sm);
            if (sm->candidate_aplist_count) {
                ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_CONNECTING); 
            } else {
                ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_SCAN); 
            }
        } else {
            if (sm->is_connected) {
                ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_DISCONNECTING); 
            } else {
                ieee80211_sm_transition_to(sm->hsm_handle,IEEE80211_CONNECTION_STATE_INIT); 
            }
        }
        return true;
        break;
    case IEEE80211_CONNECTION_EVENT_DISCONNECT_REQUEST: 
        if (sm->sync_stop_requested) {
            /*
             * synchronous stop requested. A scan cancel request is in progress and scanner is trying to
             * cancel scan asynchronously.  
             * do not wait for scan async thread to complete scan,issue
             * a sync cancel request.
             */ 

            wlan_scan_cancel(sm->vap_handle,
                             sm->scan_requestor,
                             IEEE80211_VAP_SCAN,
                             IEEE80211_SCAN_CANCEL_SYNC); 
        }
        break;
    default:
        return false;
        break;
    }
    return false;
}


ieee80211_state_info ieee80211_connection_sm_info[] = {
    { 
        (u_int8_t) IEEE80211_CONNECTION_STATE_INIT, 
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        false,
        "INIT",
        ieee80211_connection_state_init_entry,
        ieee80211_connection_state_init_exit,
        ieee80211_connection_state_init_event
    },
    { 
        (u_int8_t) IEEE80211_CONNECTION_STATE_SCAN, 
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        false,
        "SCAN",
        ieee80211_connection_state_scan_entry,
        ieee80211_connection_state_scan_exit,
        ieee80211_connection_state_scan_event
    },
    { 
        (u_int8_t) IEEE80211_CONNECTION_STATE_CONNECTING, 
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        false,
        "CONNECTING",
        ieee80211_connection_state_connecting_entry,
        ieee80211_connection_state_connecting_exit,
        ieee80211_connection_state_connecting_event
    },
    { 
        (u_int8_t) IEEE80211_CONNECTION_STATE_CONNECTED, 
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        false,
        "CONNECTED",
        ieee80211_connection_state_connected_entry,
        ieee80211_connection_state_connected_exit,
        ieee80211_connection_state_connected_event
    },
    { 
        (u_int8_t) IEEE80211_CONNECTION_STATE_BGSCAN, 
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        false,
        "BGSCAN",
        ieee80211_connection_state_bgscan_entry,
        ieee80211_connection_state_bgscan_exit,
        ieee80211_connection_state_bgscan_event
    },
    { 
        (u_int8_t) IEEE80211_CONNECTION_STATE_DISCONNECTING, 
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        false,
        "DISCONNECTING",
        ieee80211_connection_state_disconnecting_entry,
        ieee80211_connection_state_disconnecting_exit,
        ieee80211_connection_state_disconnecting_event
    },
    { 
        (u_int8_t) IEEE80211_CONNECTION_STATE_ROAM, 
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        false,
        "ROAM",
        ieee80211_connection_state_roam_entry,
        ieee80211_connection_state_roam_exit,
        ieee80211_connection_state_roam_event
    },
    { 
        (u_int8_t) IEEE80211_CONNECTION_STATE_SCAN_CANCELLING, 
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        false,
        "SCAN_CANCELLING",
        ieee80211_connection_state_scan_cancelling_entry,
        ieee80211_connection_state_scan_cancelling_exit,
        ieee80211_connection_state_scan_cancelling_event
    }
};


static OS_TIMER_FUNC(connection_sm_timer_handler)
{
    wlan_connection_sm_t sm;

    OS_GET_TIMER_ARG(sm, wlan_connection_sm_t);
    IEEE80211_DPRINTF(sm->vap_handle,IEEE80211_MSG_STATE,"%s: timed out cur state %s \n",
                      __func__, ieee80211_connection_sm_info[ieee80211_sm_get_curstate(sm->hsm_handle)].name);
    ieee80211_sm_dispatch(sm->hsm_handle, sm->timeout_event, 0, NULL); 
}

#define SM_DIFF(a,b) ((a)>(b) ? ((a)-(b)) :((b)-(a)))

static OS_TIMER_FUNC(connection_sm_roam_check_timer_handler)
{
    wlan_connection_sm_t sm;
    u_int8_t start_scan=0;
    u_int8_t cur_rssi;
    u_int32_t msec_from_lastscan;
    u_int8_t ignore_thresholds; /* Opportunistic Roam */

    OS_GET_TIMER_ARG(sm, wlan_connection_sm_t);
    OS_SET_TIMER(&sm->sm_roam_check_timer, sm->roam_check_period); /* restart the timer */

    /* Opportunistic Roam */
    if (wlan_connection_sm_is_opportunistic_roam(sm)) {
        ignore_thresholds = 1;
    }
    else {
        ignore_thresholds = 0;
    }
    
    /*
     * no BG Scan policy in place.
     */
    if (sm->bgscan_policy ==  WLAN_CONNECTION_BGSCAN_POLICY_NONE) {
	return;
    }
    if (wlan_scan_in_progress(sm->vap_handle)) {
        IEEE80211_DPRINTF(sm->vap_handle,IEEE80211_MSG_STATE,"%s: roam check  scan in progress , just return \n", __func__);
        return;
    }
    if (sm->is_connected == 0 ) {
        /* should ever happen ? */
        IEEE80211_DPRINTF(sm->vap_handle,IEEE80211_MSG_STATE,"%s: roam check  while not connected !!! \n", __func__);
        return;
    }
    cur_rssi = wlan_scan_entry_rssi(sm->cur_scan_entry);
    /*
     * if the rssi is above the bg scan threshold by certain fudge then
     * clear the last_scan_rssi so that when the rssi falls below threshold
     * we will trigger bg scan.
     */ 
    if (cur_rssi  > (sm->bgscan_rssi_thresh + WLAN_CLEAR_LAST_SCAN_RSSI_DELTA)) {
        sm->last_scan_rssi=0;
    }
    /* Opportunistic Roam - add ignore_thresholds */
    if ((cur_rssi > sm->bgscan_rssi_thresh) && (ignore_thresholds == 0)) {
        return;
    }
    IEEE80211_DPRINTF(sm->vap_handle,IEEE80211_MSG_STATE,"%s: roam check cur rssi %d rssi thresh %d policy %d last_scan_rssi %d rssi_change_thresh %d \n", 
                      __func__, cur_rssi, sm->bgscan_rssi_thresh, sm->bgscan_policy, sm->last_scan_rssi, sm->bgscan_rssi_change);
    msec_from_lastscan = CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP() - sm->last_scan_time);
    if (sm->bgscan_policy ==  WLAN_CONNECTION_BGSCAN_POLICY_PERIODIC ||
        sm->bgscan_policy ==  WLAN_CONNECTION_BGSCAN_POLICY_BOTH) {
        if (msec_from_lastscan > sm->bgscan_period) {
            start_scan=1;
        }
    }
    if (sm->bgscan_policy ==  WLAN_CONNECTION_BGSCAN_POLICY_RSSI_CHANGE ||
        sm->bgscan_policy ==  WLAN_CONNECTION_BGSCAN_POLICY_BOTH) {
        if (!sm->last_scan_rssi ||  ((SM_DIFF(cur_rssi ,  sm->last_scan_rssi) > sm->bgscan_rssi_change)  
             && (msec_from_lastscan > MIN_BGSCAN_PERIOD))) {
            start_scan=1;
        }
    }
    if (start_scan) {
        ieee80211_sm_dispatch(sm->hsm_handle, IEEE80211_CONNECTION_EVENT_BGSCAN_START, 0, NULL); 
    }
    /* Opportunistic Roam - add ignore_thresholds */
    if ((wlan_scan_entry_rssi(sm->cur_scan_entry) < sm->roam_threshold) || ignore_thresholds) 
    {
       /* if rssi is below the roam threshold , generate a roam check event */
       ieee80211_sm_dispatch(sm->hsm_handle, IEEE80211_CONNECTION_EVENT_ROAM_CHECK, 0, NULL); 
    }
}


wlan_connection_sm_t wlan_connection_sm_create(osdev_t oshandle, wlan_if_t vaphandle)
{
    wlan_connection_sm_t    sm;
    int                     rc;
    u_int8_t module_name[]="connection_sm";
    
    sm = (wlan_connection_sm_t) OS_MALLOC(oshandle,sizeof(struct _wlan_connection_sm),0);
    if (!sm) {
        return NULL;
    }
    OS_MEMZERO(sm, sizeof(struct _wlan_connection_sm));
    sm->os_handle = oshandle;
    sm->vap_handle = vaphandle;
    sm->hsm_handle = ieee80211_sm_create(oshandle, 
                                         "connection", 
                                         (void *) sm, 
                                         IEEE80211_CONNECTION_STATE_INIT,
                                         ieee80211_connection_sm_info, 
                                         sizeof(ieee80211_connection_sm_info)/sizeof(ieee80211_state_info), 
                                         MAX_QUEUED_EVENTS, 
                                         0 /* no event data */, 
                                         MESGQ_PRIORITY_HIGH,
                                         IEEE80211_HSM_ASYNCHRONOUS, /* run the SM asynchronously */
                                         ieee80211_connection_sm_debug_print,
                                         connection_event_names,
                                         IEEE80211_N(connection_event_names)
                                         ); 
    if (!sm->hsm_handle) {
        OS_FREE(sm);
        IEEE80211_DPRINTF(vaphandle, IEEE80211_MSG_STATE,
            "%s : ieee80211_sm_create failed\n", __func__); 
        return NULL;
    }

    sm->assoc_sm_handle = wlan_assoc_sm_create(oshandle,vaphandle);
    if (!sm->assoc_sm_handle) {
        ieee80211_sm_delete(sm->hsm_handle);
        OS_FREE(sm);
        IEEE80211_DPRINTF(vaphandle, IEEE80211_MSG_STATE,
            "%s : wlan_assoc_sm_create failed\n", __func__); 
        return NULL;
    }

    wlan_assoc_sm_register_event_handlers(sm->assoc_sm_handle,(os_if_t)sm,
					           ieee80211_connection_sm_assoc_sm_evhandler); 

    wlan_scan_get_requestor_id(vaphandle, module_name, &sm->scan_requestor); 
    sm->bgscan_rssi_thresh =   DEFAULT_RSSI_THRESH;
    sm->bgscan_rssi_thresh_forced_scan = DEFAULT_RSSI_THRESH;
    sm->bgscan_rssi_change =   DEFAULT_RSSI_CHANGE;
    sm->bgscan_period      =   DEFAULT_BGSCAN_PERIOD;
    sm->bgscan_policy      =   DEFAULT_BGSCAN_POLICY;
    sm->roam_threshold     =   DEFAULT_ROAM_THRESH;
    sm->roam_check_period  =   DEFAULT_ROAM_CHECK_PERIOD;
    sm->scan_cache_valid_time  =   DEFAULT_SCAN_CACHE_VALID_TIME;
    sm->connect_timeout    =   DEFAULT_CONNECT_TIMEOUT;
    sm->reconnect_timeout  =   DEFAULT_RECONNECT_TIMEOUT;
    sm->bad_ap_timeout  =   DEFAULT_BAD_AP_TIMEOUT;
    sm->bgscan_min_dwell_time  =   DEFAULT_BGSCAN_MIN_DWELL_TIME;
    sm->bgscan_max_dwell_time  =   DEFAULT_BGSCAN_MAX_DWELL_TIME;
    sm->bgscan_min_rest_time  =   DEFAULT_BGSCAN_MIN_REST_TIME;
    sm->bgscan_max_rest_time  =   DEFAULT_BGSCAN_MAX_REST_TIME;
    sm->connection_lost_timeout = DEFAULT_CONNECTION_LOST_TIMEOUT;
    OS_INIT_TIMER(oshandle, &(sm->sm_timer), connection_sm_timer_handler, (void *)sm, QDF_TIMER_TYPE_WAKE_APPS);
    OS_INIT_TIMER(oshandle, &(sm->sm_roam_check_timer), connection_sm_roam_check_timer_handler, (void *)sm, QDF_TIMER_TYPE_WAKE_APPS);

    rc = wlan_scan_register_event_handler(sm->vap_handle, ieee80211_connection_sm_scan_evhandler, sm);
    if (rc != EOK) {
        IEEE80211_DPRINTF(sm->vap_handle, IEEE80211_MSG_ANY,
                          "%s: wlan_scan_register_event_handler() failed handler=%08p,%08p rc=%08X\n",
                          __func__, ieee80211_connection_sm_scan_evhandler, sm, rc);
    }
    return sm;                                   
}


void  wlan_connection_sm_delete(wlan_connection_sm_t smhandle)
{
    if (smhandle->is_running) {
        IEEE80211_DPRINTF(smhandle->vap_handle,IEEE80211_MSG_STATE,"%s : can not delete while still runing \n", __func__); 
    }
    if (wlan_scan_unregister_event_handler(smhandle->vap_handle, ieee80211_connection_sm_scan_evhandler, smhandle) != EOK) {
        IEEE80211_DPRINTF(smhandle->vap_handle,IEEE80211_MSG_STATE,"%s : cannot unregister scan event handler (%p,%p)\n", 
            __func__, ieee80211_connection_sm_scan_evhandler, smhandle); 
    }
    wlan_scan_clear_requestor_id(smhandle->vap_handle, smhandle->scan_requestor);
    wlan_assoc_sm_delete(smhandle->assoc_sm_handle);
    OS_CANCEL_TIMER(&(smhandle->sm_timer));
    OS_CANCEL_TIMER(&(smhandle->sm_roam_check_timer));
    ieee80211_sm_delete(smhandle->hsm_handle);
    OS_FREE_TIMER(&(smhandle->sm_timer));
    OS_FREE_TIMER(&(smhandle->sm_roam_check_timer));
    OS_FREE(smhandle);
}

void wlan_connection_sm_register_event_handlers(wlan_connection_sm_t smhandle, os_if_t osif,
                                            wlan_connection_sm_event_handler sm_evhandler)
{
    smhandle->osif = osif;
    smhandle->sm_evhandler = sm_evhandler;
}

/*
 * start the state machine and handling the events.
 */
int wlan_connection_sm_start(wlan_connection_sm_t smhandle)
{
    /*
     * is already running (or) processing a request to run
     * just ignore the request.
     * should we allow multiple processes to start SM (locking ?) ? 
     */
    if (smhandle->is_running) {
        IEEE80211_DPRINTF(smhandle->vap_handle,IEEE80211_MSG_STATE,"%s: connection SM is already running!!  \n", __func__);
        return -EINPROGRESS;
    }
    /* Reset HSM to INIT state. */
    ieee80211_sm_reset(smhandle->hsm_handle, IEEE80211_CONNECTION_STATE_INIT, NULL);
    smhandle->is_running = 1;
    smhandle->connection_req_time = OS_GET_TIMESTAMP();

    ieee80211_sm_dispatch(smhandle->hsm_handle,
                              IEEE80211_CONNECTION_EVENT_CONNECT_REQUEST, 0, NULL); 
    return EOK;
}

/*
 * stop handling the events.
 */
int wlan_connection_sm_stop(wlan_connection_sm_t smhandle, u_int32_t flags)
{
    /*
     * return an error if it is already stopped (or)
     * there is a stop request is pending.
     */
    if (!smhandle->is_running ) {
        IEEE80211_DPRINTF(smhandle->vap_handle,IEEE80211_MSG_STATE,"%s: connection SM is already stopped !!  \n",__func__);
        return -EALREADY;
    }
    if ( smhandle->is_stop_requested) {
        IEEE80211_DPRINTF(smhandle->vap_handle,IEEE80211_MSG_STATE,"%s: connection SM is already being stopped !!  \n",__func__);
        return -EALREADY;
    }
    smhandle->is_stop_requested = 1;
    if (flags & IEEE80211_CONNECTION_SM_STOP_NO_DISASSOC)
        smhandle->no_stop_disassoc = 1;
    else
        smhandle->no_stop_disassoc = 0;
#ifdef DELAY_DISCONNECT_REQ /* for debugging/testing only */ 
    smhandle->timeout_event = IEEE80211_CONNECTION_EVENT_DISCONNECT_REQUEST;
    OS_SET_TIMER(&smhandle->sm_timer,3000);
#else
    smhandle->disconnect_reason = WLAN_CONNECTION_SM_DISCONNECT_REQUEST; /* connection timed out */ 
    if (flags & IEEE80211_CONNECTION_SM_STOP_SYNC) {
        smhandle->sync_stop_requested=1;
        /*
         * flush any pending events and dispatch the mesg synchronously.
         */
        ieee80211_sm_dispatch_sync(smhandle->hsm_handle,
                                   IEEE80211_CONNECTION_EVENT_DISCONNECT_REQUEST, 0, NULL, true); 
    }  else {
        ieee80211_sm_dispatch(smhandle->hsm_handle,
                              IEEE80211_CONNECTION_EVENT_DISCONNECT_REQUEST, 0, NULL); 
    }
#endif
    return EOK;
}

/*
 * return the running state of the SM..
 */
bool wlan_connection_sm_is_running(wlan_connection_sm_t smhandle)
{
    return (smhandle->is_running);
}


/*
 * return the current state of opportunistic roam
 */
bool wlan_connection_sm_is_opportunistic_roam(wlan_connection_sm_t smhandle)
{
    return (memcmp(smhandle->roam_bssid.octet, BSSID_INVALID, sizeof(smhandle->roam_bssid.octet)) != 0);
}


/*
 * set a connection sm param.
 */
int wlan_connection_sm_set_param(wlan_connection_sm_t smhandle, wlan_connection_sm_param param,u_int32_t val)
{

    switch(param) {
    case WLAN_CONNECTION_PARAM_BGSCAN_RSSI_THRESH:
        smhandle->bgscan_rssi_thresh = (u_int8_t) val;
        break;
    case WLAN_CONNECTION_PARAM_BGSCAN_RSSI_FORCED_SCAN:  
        /* rssi below which the scan is a forces scan */
        smhandle->bgscan_rssi_thresh_forced_scan = (u_int8_t) val;
        break;

    case WLAN_CONNECTION_PARAM_BGSCAN_POLICY:      
        if (val >= WLAN_CONNECTION_BGSCAN_POLICY_MAX)
            return -EINVAL;
        smhandle->bgscan_policy = (wlan_connection_sm_bgscan_policy) val;
        break;

    case WLAN_CONNECTION_PARAM_BGSCAN_PERIOD:     
        if (val < MIN_BGSCAN_PERIOD)
            return -EINVAL;
        smhandle->bgscan_period = val;
        break;

    case WLAN_CONNECTION_PARAM_BGSCAN_RSSI_CHANGE_THRESH:
        smhandle->bgscan_rssi_change = (u_int8_t) val;
        break;

    case WLAN_CONNECTION_PARAM_ROAM_THRESH:        
        smhandle->roam_threshold = (u_int8_t) val;
        break;

    case WLAN_CONNECTION_PARAM_ROAM_CHECK_PERIOD: 
        if (val < MIN_ROAM_CHECK_PERIOD)
            return -EINVAL;
        smhandle->roam_check_period = val;
        break;

    case WLAN_CONNECTION_PARAM_SCAN_CACHE_VALID_TIME: 
        if (val < MIN_SCAN_CACHE_VALID_TIME)
            return -EINVAL;
        smhandle->scan_cache_valid_time = val;
        break;

    case WLAN_CONNECTION_PARAM_CONNECT_TIMEOUT: 
        /* This check is meaningless when MIN_CONNECT_TIMEOUT=0
        if (val < MIN_CONNECT_TIMEOUT)
            return -EINVAL;
        */
        smhandle->connect_timeout = val;
        break;

    case WLAN_CONNECTION_PARAM_RECONNECT_TIMEOUT: 
        /* This check is meaningless when MIN_RECONNECT_TIMEOUT=0
        if (val < MIN_RECONNECT_TIMEOUT)
            return -EINVAL;
        */
        smhandle->reconnect_timeout = val;
        break;

    case WLAN_CONNECTION_PARAM_CONNECTION_LOST_TIMEOUT: 
        /* This check is meaningless when MIN_CONNECTION_LOST_TIMEOUT=0
        if (val < MIN_CONNECTION_LOST_TIMEOUT)
            return -EINVAL;
        */
        smhandle->connection_lost_timeout = val;
        break;
    case WLAN_CONNECTION_PARAM_CURRENT_STATE:
            return -EINVAL;
        break;
    case WLAN_CONNECTION_PARAM_BAD_AP_TIMEOUT:
        smhandle->bad_ap_timeout  =   val;
        break;
    case WLAN_CONNECTION_PARAM_BGSCAN_MIN_DWELL_TIME:
        smhandle->bgscan_min_dwell_time  =   val;
        break;
    case WLAN_CONNECTION_PARAM_BGSCAN_MAX_DWELL_TIME:
        smhandle->bgscan_max_dwell_time  =   val;
        break;
    case WLAN_CONNECTION_PARAM_BGSCAN_MIN_REST_TIME:
        smhandle->bgscan_min_rest_time  =   val;
        break;
    case WLAN_CONNECTION_PARAM_BGSCAN_MAX_REST_TIME:
        smhandle->bgscan_max_rest_time  =   val;
        break;
    default:
        break;

    }
    return EOK;
}

/*
 * get connection sm param.
 */
u_int32_t wlan_connection_sm_get_param(wlan_connection_sm_t smhandle, wlan_connection_sm_param param)
{

    switch(param) {
    case WLAN_CONNECTION_PARAM_BGSCAN_RSSI_THRESH:
        return smhandle->bgscan_rssi_thresh;
        break;

    case WLAN_CONNECTION_PARAM_BGSCAN_RSSI_FORCED_SCAN:  
        /* rssi below which the bg scan is a forces scan */
        return smhandle->bgscan_rssi_thresh_forced_scan;
        break;

    case WLAN_CONNECTION_PARAM_BGSCAN_POLICY:      
        return smhandle->bgscan_policy;
        break;

    case WLAN_CONNECTION_PARAM_BGSCAN_PERIOD:     
        return smhandle->bgscan_period;
        break;

    case WLAN_CONNECTION_PARAM_BGSCAN_RSSI_CHANGE_THRESH:
        return smhandle->bgscan_rssi_change;
        break;

    case WLAN_CONNECTION_PARAM_ROAM_THRESH:        
        return smhandle->roam_threshold;
        break;

    case WLAN_CONNECTION_PARAM_ROAM_CHECK_PERIOD: 
        return smhandle->roam_check_period;
        break;

    case WLAN_CONNECTION_PARAM_SCAN_CACHE_VALID_TIME: 
        return smhandle->scan_cache_valid_time;
        break;

    case WLAN_CONNECTION_PARAM_CONNECT_TIMEOUT: 
        return smhandle->connect_timeout;
        break;

    case WLAN_CONNECTION_PARAM_RECONNECT_TIMEOUT: 
        return smhandle->reconnect_timeout;
        break;

    case WLAN_CONNECTION_PARAM_CONNECTION_LOST_TIMEOUT: 
        return smhandle->connection_lost_timeout;
        break;
    case WLAN_CONNECTION_PARAM_CURRENT_STATE:
	if ((ieee80211_connection_state)ieee80211_sm_get_curstate(smhandle->hsm_handle) == IEEE80211_CONNECTION_STATE_SCAN) {
           return WLAN_ASSOC_STATE_SCAN;
        } 
        else {
           return wlan_assoc_sm_get_param(smhandle->assoc_sm_handle, PARAM_CURRENT_STATE); 
        }
        break;
    case WLAN_CONNECTION_PARAM_BAD_AP_TIMEOUT:
        return smhandle->bad_ap_timeout;
        break;
    case WLAN_CONNECTION_PARAM_BGSCAN_MIN_DWELL_TIME:
        return smhandle->bgscan_min_dwell_time;
        break;
    case WLAN_CONNECTION_PARAM_BGSCAN_MAX_DWELL_TIME:
        return smhandle->bgscan_max_dwell_time;
        break;
    case WLAN_CONNECTION_PARAM_BGSCAN_MIN_REST_TIME:
        return smhandle->bgscan_min_rest_time;
        break;
    case WLAN_CONNECTION_PARAM_BGSCAN_MAX_REST_TIME:
        return smhandle->bgscan_max_rest_time;
        break;
    default:
        break;

    }

    return EOK;
}
bool wlan_connection_sm_is_connected(wlan_connection_sm_t smhandle)
{
	switch ((ieee80211_connection_state)ieee80211_sm_get_curstate(smhandle->hsm_handle)) {
         case IEEE80211_CONNECTION_STATE_CONNECTED:
         case IEEE80211_CONNECTION_STATE_BGSCAN:
         case IEEE80211_CONNECTION_STATE_ROAM: 
             return true;  
         default:
             return false;  
         }
}

wlan_assoc_sm_t	    wlan_connection_sm_get_assoc_sm_handle(wlan_connection_sm_t smhandle)
{
           return smhandle->assoc_sm_handle; 
}

int wlan_connection_sm_set_scan_channels(wlan_connection_sm_t smhandle, u_int32_t num_channels, u_int32_t *channels)
{
    if (num_channels >= IEEE80211_CHAN_MAX) {
        return EINVAL;
    }
    OS_MEMCPY(smhandle->scan_channels, channels, num_channels * sizeof(u_int32_t));
    smhandle->num_channels=num_channels;
    return EOK;
}
               
/* Opportunistic Roam - add ignore_thresholds */
int wlan_connection_sm_set_roam_bssid(wlan_connection_sm_t smhandle, struct ether_addr *bssid)
{
    OS_CANCEL_TIMER(&smhandle->sm_roam_check_timer);
    
    memcpy(smhandle->roam_bssid.octet, bssid->octet, sizeof(smhandle->roam_bssid.octet));
           
    OS_SET_TIMER(&smhandle->sm_roam_check_timer, 0);
    
    return EOK;
}
