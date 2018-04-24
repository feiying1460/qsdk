/*
 *  Copyright (c) 2008 Atheros Communications Inc.
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

#include <ieee80211_scan_priv.h>
#include "ieee80211_dfs.h"

#if UMAC_SUPPORT_SCAN


int wlan_scan_set_priority(wlan_if_t                vaphandle,
                           IEEE80211_SCAN_REQUESTOR requestor,
                           IEEE80211_SCAN_ID        scan_id_mask,
                           IEEE80211_SCAN_PRIORITY  scanPriority)
{
    return ieee80211_scan_set_priority(vaphandle->iv_ic->ic_scanner, vaphandle,
                                        requestor,
                                        scan_id_mask, 
                                        scanPriority);
}

int wlan_scan_set_forced_flag(wlan_if_t                vaphandle, 
                              IEEE80211_SCAN_REQUESTOR requestor,
                              IEEE80211_SCAN_ID        scan_id_mask,
                              bool                     forced_flag)
{
    return ieee80211_scan_set_forced_flag(vaphandle->iv_ic->ic_scanner,
                                           requestor,
                                           scan_id_mask, 
                                           forced_flag);
}

int wlan_scan_cancel(wlan_if_t                vaphandle, 
                     IEEE80211_SCAN_REQUESTOR requestor, 
                     IEEE80211_SCAN_ID        scan_id_mask,
                     u_int32_t                flags)
{
    return ieee80211_scan_cancel(vaphandle->iv_ic->ic_scanner,vaphandle,requestor,scan_id_mask,flags);
}

int wlan_scan_start(wlan_if_t                vaphandle, 
                    ieee80211_scan_params    *params, 
                    IEEE80211_SCAN_REQUESTOR requestor,
                    IEEE80211_SCAN_PRIORITY  priority,
                    IEEE80211_SCAN_ID        *scan_id)
{
#if ATH_SUPPORT_DFS
    STA_VAP_DOWNUP_LOCK(vaphandle->iv_ic);
    if(ieee80211_dfs_is_ap_cac_timer_running(vaphandle->iv_ic)) {
        IEEE80211_DPRINTF(vaphandle, IEEE80211_MSG_SCAN,"%s do not start_scan because cac is on \n",__func__);
        IEEE80211_DPRINTF(vaphandle, IEEE80211_MSG_MLME,"%s do not start_scan because cac is on \n",__func__);
        STA_VAP_DOWNUP_UNLOCK(vaphandle->iv_ic);
        return -EINVAL;
    }
    STA_VAP_DOWNUP_UNLOCK(vaphandle->iv_ic);
#endif
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
    if(wlan_mlme_is_stacac_running(vaphandle)) {
        IEEE80211_DPRINTF(vaphandle, IEEE80211_MSG_SCAN,"%s do not start_scan because cac is on \n",__func__);
        return -EINVAL;
    } else {
        return ieee80211_scan_start(vaphandle->iv_ic->ic_scanner,vaphandle,params,requestor,priority,scan_id);
    }
#else
    return ieee80211_scan_start(vaphandle->iv_ic->ic_scanner,vaphandle,params,requestor,priority,scan_id); 
#endif

}

int wlan_scan_register_event_handler(wlan_if_t                    vaphandle, 
                                     ieee80211_scan_event_handler evhandler, 
                                     void                         *arg)
{
    return ieee80211_scan_register_event_handler(vaphandle->iv_ic->ic_scanner,
                                                 evhandler, 
                                                 arg);
}

int wlan_scan_unregister_event_handler(wlan_if_t                    vaphandle, 
                                       ieee80211_scan_event_handler evhandler,
                                       void                         *arg)
{
    return ieee80211_scan_unregister_event_handler(vaphandle->iv_ic->ic_scanner, evhandler, arg);
}

systime_t wlan_get_last_scan_time(wlan_if_t vaphandle)
{
    return ieee80211_get_last_scan_time(vaphandle->iv_ic->ic_scanner);
}

systime_t wlan_get_last_full_scan_time(wlan_if_t vaphandle)
{
    return ieee80211_get_last_full_scan_time(vaphandle->iv_ic->ic_scanner);
}

int wlan_get_last_scan_info(wlan_if_t           vaphandle, 
                            ieee80211_scan_info *info)
{
    return ieee80211_get_last_scan_info(vaphandle->iv_ic->ic_scanner, info);
}

int wlan_get_scan_info(wlan_if_t           vaphandle, 
                       IEEE80211_SCAN_ID   scan_id,
                       ieee80211_scan_info *info)
{
#if ATH_SUPPORT_MULTIPLE_SCANS
    return ieee80211_scan_scheduler_get_request_info(vaphandle->iv_ic->ic_scanner->ss_scheduler, scan_id, info);
#else
    return ieee80211_get_last_scan_info(vaphandle->iv_ic->ic_scanner, info);
#endif
}

int wlan_print_scan_config(wlan_if_t vaphandle, struct seq_file *m)
{
    return ieee80211_print_scan_config(vaphandle->iv_ic->ic_scanner, m);
}
EXPORT_SYMBOL(wlan_print_scan_config);

int wlan_scan_scheduler_get_requests(wlan_if_t                   vaphandle, 
                                     ieee80211_scan_request_info *scan_request_info,
                                     int                         *total_requests,
                                     int                         *returned_requests)
{
    return ieee80211_scan_scheduler_get_requests(vaphandle->iv_ic->ic_scanner,
                                                 scan_request_info,
                                                 total_requests,
                                                 returned_requests);
}

int wlan_scan_can_transmit(wlan_if_t vaphandle)
{
    return ieee80211_scan_can_transmit(vaphandle->iv_ic->ic_scanner);
}

int wlan_scan_in_progress_ic(wlan_dev_t ic)
{
#if ATH_SUPPORT_MULTIPLE_SCANS
    /*
     * To speed up the routine, first check whether a scan is currently active.
     * If not, then check with the scheduler whether one is scheduled.
     */
	if (((struct ieee80211_scanner_common*)ic->ic_scanner)->ss_info.si_scan_in_progress) {
        return true;
    }
    else {
        return ieee80211_scan_scheduler_scan_in_progress(ic->ic_scanner->ss_scheduler);
    }
#else
    return (((struct ieee80211_scanner_common*)ic->ic_scanner)->ss_info.si_scan_in_progress);
#endif
}

int wlan_scan_in_progress(wlan_if_t vaphandle)
{
    return wlan_scan_in_progress_ic(vaphandle->iv_ic);
}

void wlan_scan_connection_lost(wlan_if_t vaphandle)
{
    ieee80211_scan_connection_lost(vaphandle->iv_ic->ic_scanner);
}

int wlan_scan_update_channel_list(wlan_if_t vaphandle)
{
    return ieee80211_scan_update_channel_list(vaphandle->iv_ic->ic_scanner);
}

int wlan_scan_channel_list_length(wlan_if_t vaphandle)
{
    return ieee80211_scan_channel_list_length(vaphandle->iv_ic->ic_scanner);
}

void wlan_set_default_scan_parameters(wlan_if_t             vaphandle, 
                                      ieee80211_scan_params *scan_params, 
                                      enum ieee80211_opmode opmode,
                                      bool                  active_scan_flag, 
                                      bool                  high_priority_flag,
                                      bool                  connected_flag,
                                      bool                  external_scan_flag,
                                      u_int32_t             num_ssid,
                                      ieee80211_ssid        *ssid_list,
                                      int                   peer_count)
{
     ieee80211_set_default_scan_parameters(vaphandle->iv_ic->ic_scanner,vaphandle,
                                           scan_params, 
                                           opmode,
                                           active_scan_flag, 
                                           high_priority_flag,
                                           connected_flag,
                                           external_scan_flag,
                                           num_ssid,
                                           ssid_list,
                                           peer_count);
}

int 
wlan_scan_set_priority_table(wlan_dev_t                 devhandle,
                             enum ieee80211_opmode      opmode,
                             int                        number_rows,
                             IEEE80211_PRIORITY_MAPPING *p_mapping_table)
{
    /* 
     * Typecast parameter devhandle to ic.
     * Defining a variable causes compilation errors (unreferenced variable)
     * in some platforms.
     */
    return ieee80211_scan_set_priority_table(devhandle->ic_scanner,
        opmode,
        number_rows,
        p_mapping_table);
}

int 
wlan_scan_get_priority_table(wlan_dev_t                 devhandle,
                             enum ieee80211_opmode      opmode,
                             int                        *p_number_rows,
                             IEEE80211_PRIORITY_MAPPING **p_mapping_table)
{
    return ieee80211_scan_get_priority_table(devhandle->ic_scanner,
                             opmode,p_number_rows,
                                     p_mapping_table);
}

int wlan_enable_scan_scheduler(wlan_dev_t               devhandle,
                               IEEE80211_SCAN_REQUESTOR requestor)
{
    /* 
     * Typecast parameter devhandle to ic.
     * Defining a variable causes compilation errors (unreferenced variable)
     * in some platforms.
     */
    return ieee80211_enable_scan_scheduler(
        ((struct ieee80211com *) devhandle)->ic_scanner,
        requestor);
}

int wlan_disable_scan_scheduler(wlan_dev_t               devhandle,
                                IEEE80211_SCAN_REQUESTOR requestor,
                                u_int32_t                max_suspend_time)
{
    /* 
     * Typecast parameter devhandle to ic.
     * Defining a variable causes compilation errors (unreferenced variable)
     * in some platforms.
     */
    return ieee80211_disable_scan_scheduler(
        ((struct ieee80211com *) devhandle)->ic_scanner,
        requestor,
        max_suspend_time);
}

const char* wlan_scan_notification_event_name(ieee80211_scan_event_type event)
{
    static const char*    event_name[] = {
        /* IEEE80211_SCAN_STARTED                */ "STARTED",
        /* IEEE80211_SCAN_COMPLETED              */ "COMPLETED",
        /* IEEE80211_SCAN_RADIO_MEASUREMENT_START*/ "RADIO_MEASUREMENT_START",
        /* IEEE80211_SCAN_RADIO_MEASUREMENT_END  */ "RADIO_MEASUREMENT_END",
        /* IEEE80211_SCAN_RESTARTED              */ "RESTARTED",
        /* IEEE80211_SCAN_HOME_CHANNEL           */ "HOME_CHANNEL",
        /* IEEE80211_SCAN_FOREIGN_CHANNEL        */ "FOREIGN_CHANNEL",
        /* IEEE80211_SCAN_BSSID_MATCH            */ "BSSID_MATCH",
        /* IEEE80211_SCAN_FOREIGN_CHANNEL_GET_NF */ "FOREIGN_CHANNEL_GET_NF",
        /* IEEE80211_SCAN_DEQUEUED               */ "DEQUEUED",
        /* IEEE80211_SCAN_PREEMPTED              */ "PREEMPTED"
    };

    ASSERT(IEEE80211_SCAN_EVENT_COUNT == IEEE80211_N(event_name));
    ASSERT(event < IEEE80211_N(event_name));

    return (event_name[event]);
}

const char* wlan_scan_notification_reason_name(ieee80211_scan_completion_reason reason)
{
    static const char*    reason_name[] = {
        /* IEEE80211_REASON_NONE                 */ "NONE",
        /* IEEE80211_REASON_COMPLETED            */ "COMPLETED",
        /* IEEE80211_REASON_CANCELLED            */ "CANCELLED",
        /* IEEE80211_REASON_TIMEDOUT             */ "TIMEDOUT",
        /* IEEE80211_REASON_TERMINATION_FUNCTION */ "TERMINATION_FUNCTION",
        /* IEEE80211_REASON_MAX_OFFCHAN_RETRIES  */ "MAX_OFFCHAN_RETRIES",
        /* IEEE80211_REASON_PREEMPTED            */ "PREEMPTED",
        /* IEEE80211_REASON_RUN_FAILED           */ "RUN_FAILED",
        /* IEEE80211_REASON_INTERNAL_STOP        */ "INTERNAL_STOP"
    };

    ASSERT(IEEE80211_REASON_COUNT == IEEE80211_N(reason_name));
    ASSERT(reason < IEEE80211_N(reason_name));

    return (reason_name[reason]);
}

int wlan_scan_get_requestor_id(wlan_if_t vaphandle, u_int8_t *module_name, IEEE80211_SCAN_REQUESTOR *requestor)
{
    return ieee80211_scan_get_requestor_id(vaphandle->iv_ic->ic_scanner, module_name, requestor);
} 

void wlan_scan_clear_requestor_id(wlan_if_t vaphandle, IEEE80211_SCAN_REQUESTOR requestor)
{
    if (vaphandle) {
        ieee80211_scan_clear_requestor_id(vaphandle->iv_ic->ic_scanner, requestor);
    }
} 

u_int8_t *wlan_scan_requestor_name(wlan_if_t vaphandle, IEEE80211_SCAN_REQUESTOR requestor)
{
    return ieee80211_scan_get_requestor_name(vaphandle->iv_ic->ic_scanner, requestor);
}
#endif
