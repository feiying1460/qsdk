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
 * UMAC beacon specific offload interface functions - for power and performance offload model
 */
#include "ol_if_athvar.h"
#include "qdf_mem.h"

#if ATH_PERF_PWR_OFFLOAD

#define IEEE80211_SCAN_PRINTF(_ss, _cat, _fmt, ...)           \
    if (ieee80211_msg_ic((_ss)->ss_ic, _cat)) {               \
        ieee80211com_note((_ss)->ss_ic, _cat, _fmt, __VA_ARGS__);   \
    }
#define IEEE80211_SCAN_REQUESTOR_MAX_MODULE_NAME       64

/* Qwrap currently need approx 2 max requestors per sta vap
 * to get all max psta successfully connected to Root. This
 * total 66 count is adjusted/derived based on various test
 * experiments with max 29 wired psta clients and offchan scan.
 */
#if ATH_SUPPORT_WRAP
#define IEEE80211_MAX_REQUESTORS                       66
#else
#define IEEE80211_MAX_REQUESTORS                       34
#endif

#define IEEE80211_REQ_ID_PREFIX   WMI_HOST_P_SCAN_REQUESTOR_ID_PREFIX
#if QCA_LTEU_SUPPORT
#define LTEU_TIME_AT_END_OF_SCAN_INTERVAL              10
#endif
typedef struct scanner_requestor_info {
    IEEE80211_SCAN_REQUESTOR    requestor;
    u_int8_t                    module_name[IEEE80211_SCAN_REQUESTOR_MAX_MODULE_NAME];
} scanner_requestor_info_t;

/* Qwrap currently need atleast 5 scan event handlers for each
 * sta vap to get all max psta successfully connected to Root
 * This 5 count should be adjusted/derived based on no of modules
 * which are intrested in scan events. Total 31 sta * 5 = 155 handlers
 */
#if ATH_SUPPORT_WRAP
#define IEEE80211_MAX_SCAN_EVENT_HANDLERS 155
#else
#define IEEE80211_MAX_SCAN_EVENT_HANDLERS 40
#endif

struct ieee80211_scanner {
    struct ieee80211_scanner_common    ss_common; /* public data.  always need to be at the top */

    /* Driver-wide data structures */
    wlan_dev_t                          ss_ic;
    wlan_if_t                           ss_vap;
    osdev_t                             ss_osdev;

    spinlock_t                          ss_lock;
    u_int16_t                           ss_id_generator;
    ieee80211_scan_type                 ss_type;
    u_int16_t                           ss_flags;
    IEEE80211_SCAN_REQUESTOR            ss_requestor;
    IEEE80211_SCAN_ID                   ss_scan_id;
    IEEE80211_SCAN_PRIORITY             ss_priority;
    systime_t                           ss_scan_start_time;
    systime_t                           ss_last_full_scan_time;
    u_int32_t                           ss_min_dwell_active;     /* min dwell time on an active channel */
    u_int32_t                           ss_max_dwell_active;     /* max dwell time on an active channel */
    u_int32_t                           ss_min_dwell_passive;    /* min dwell time on a passive channel */
    u_int32_t                           ss_max_dwell_passive;    /* max dwell time on a passive channel */
    u_int32_t                           ss_min_rest_time;        /* minimum rest time on channel */
    u_int32_t                           ss_max_rest_time;        /* maximum rest time on channel */
    u_int16_t                           ss_nchans;                         /* # chan's to scan */
    u_int16_t                           ss_next;                           /* index of next chan to scan */
    u_int32_t                           ss_repeat_probe_time;    /* time delay before sending subsequent probe requests */
    u_int32_t                           ss_max_offchannel_time;  /* maximum time to spend off-channel (cumulative for several consecutive foreign channels) */
    u_int16_t                           ss_nallchans;                      /* # all chans's to scan */
    struct ieee80211_channel            *ss_all_chans[IEEE80211_CHAN_MAX];

    /* termination reason */
    ieee80211_scan_completion_reason    ss_termination_reason;
    u_int32_t                           ss_restricted                     : 1; /* perform restricted scan */
    u_int32_t                           ss_min_beacon_count;     /* number of home AP beacons to receive before leaving the home channel */

    scanner_requestor_info_t            ss_requestors[IEEE80211_MAX_REQUESTORS];

    /* List of clients to be notified about scan events */
    u_int16_t                           ss_num_handlers;
    ieee80211_scan_event_handler        ss_event_handlers[IEEE80211_MAX_SCAN_EVENT_HANDLERS];
    void                                *ss_event_handler_arg[IEEE80211_MAX_SCAN_EVENT_HANDLERS];
};

static int
ol_scan_wmi_event_handler(ol_scn_t scn, u_int8_t *data, u_int16_t datalen);
static int
ol_scan_process_event(ol_scn_t scn, wmi_host_scan_event *wmi_scn_event);

/*
 * Verify presence of active VAPs besides the one requesting the scan.
 */
static bool
ol_count_active_ports(struct ieee80211com    *ic,
                             struct ieee80211vap    *vap)
{
    struct ieee80211_vap_opmode_count    vap_opmode_count;

    OS_MEMZERO(&(vap_opmode_count), sizeof(vap_opmode_count));

    /*
     * Get total number of VAPs of each type supported by the IC.
     */
    wlan_get_vap_opmode_count(ic, &vap_opmode_count);

    /*
     * Subtract the current VAP since its connection state is already checked
     * by a callback function specified in the scan request.
     */
    switch(ieee80211vap_get_opmode(vap)) {
    case IEEE80211_M_IBSS:
        vap_opmode_count.ibss_count--;
        break;

    case IEEE80211_M_STA:
        vap_opmode_count.sta_count--;
        break;

    case IEEE80211_M_WDS:
        vap_opmode_count.wds_count--;
        break;

    case IEEE80211_M_AHDEMO:
        vap_opmode_count.ahdemo_count--;
        break;

    case IEEE80211_M_HOSTAP:
        vap_opmode_count.ap_count--;
        break;

    case IEEE80211_M_MONITOR:
        vap_opmode_count.monitor_count--;
        break;

    case IEEE80211_M_BTAMP:
        vap_opmode_count.btamp_count--;
        break;

    default:
        vap_opmode_count.unknown_count--;
        break;
    }

    if ((vap_opmode_count.ibss_count > 0) ||
        (vap_opmode_count.sta_count > 0)  ||
        (vap_opmode_count.ap_count > 0)   ||
        (vap_opmode_count.btamp_count > 0)) {
        return true;
    }
    else {
        return false;
    }
}

static int ol_scan_register_event_handler(ieee80211_scanner_t          ss,
                                          ieee80211_scan_event_handler evhandler,
                                          void                         *arg)
{
    int    i;

    spin_lock(&ss->ss_lock);

    /*
     * Verify that event handler is not yet registered.
     */
    for (i = 0; i < IEEE80211_MAX_SCAN_EVENT_HANDLERS; ++i) {
        if ((ss->ss_event_handlers[i] == evhandler) &&
            (ss->ss_event_handler_arg[i] == arg)) {
            IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: evhandler=%08p arg=%08p already registered\n",
                                  __func__,
                                  evhandler,
                                  arg);

            spin_unlock(&ss->ss_lock);
            return EEXIST;    /* already exists */
        }
    }

    /*
     * Verify that the list of event handlers is not full.
     */
    ASSERT(ss->ss_num_handlers < IEEE80211_MAX_SCAN_EVENT_HANDLERS);
    if (ss->ss_num_handlers >= IEEE80211_MAX_SCAN_EVENT_HANDLERS) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY, "%s: ERROR: No more space: evhandler=%08p arg=%08p\n",
                              __func__,
                              evhandler,
                              arg);
        spin_unlock(&ss->ss_lock);
        return ENOSPC;
    }

    /*
     * Add new handler and increment number of registered handlers.
     * Registered event handlers are guaranteed to occupy entries 0..(n-1) in
     * the table, so we can safely assume entry 'n' is available.
     */
    ss->ss_event_handlers[ss->ss_num_handlers] = evhandler;
    ss->ss_event_handler_arg[ss->ss_num_handlers++] = arg;

    spin_unlock(&ss->ss_lock);
    return EOK;
}

static systime_t ol_scan_get_last_scan_time(ieee80211_scanner_t ss)
{
    return ss->ss_scan_start_time;
}

static systime_t ol_scan_get_last_full_scan_time(ieee80211_scanner_t ss)
{
    return ss->ss_last_full_scan_time;
}

static int ol_scan_get_last_scan_info(ieee80211_scanner_t ss, ieee80211_scan_info *info)
{
    if (ss->ss_scan_start_time == 0)
        return ENXIO;

    if (info) {
        info->type                        = ss->ss_type;
        info->requestor                   = ss->ss_requestor;
        info->scan_id                     = ss->ss_scan_id;
        info->priority                    = ss->ss_priority;
        info->min_dwell_time_active       = ss->ss_min_dwell_active;
        info->max_dwell_time_active       = ss->ss_max_dwell_active;
        info->min_dwell_time_passive      = ss->ss_min_dwell_active;
        info->max_dwell_time_passive      = ss->ss_max_dwell_active;
        info->min_rest_time               = ss->ss_min_rest_time;
        info->max_rest_time               = ss->ss_max_rest_time;
        info->max_offchannel_time         = ss->ss_max_offchannel_time;
        info->repeat_probe_time           = ss->ss_repeat_probe_time;
        info->min_beacon_count            = ss->ss_min_beacon_count;
        info->flags                       = ss->ss_flags;
        info->scan_start_time             = ss->ss_scan_start_time;
        info->cancelled                   = (ss->ss_termination_reason == IEEE80211_REASON_CANCELLED);
        info->preempted                   = (ss->ss_termination_reason == IEEE80211_REASON_PREEMPTED);
        info->scanned_channels            = ss->ss_next;
        info->default_channel_list_length = ss->ss_nallchans;
        info->channel_list_length         = ss->ss_nchans;
        info->restricted                  = ss->ss_restricted;

        if (ss->ss_common.ss_info.si_scan_in_progress) {
            info->scheduling_status      = IEEE80211_SCAN_STATUS_RUNNING;
            info->in_progress            = true;
        }
        else {
            info->scheduling_status      = IEEE80211_SCAN_STATUS_COMPLETED;
            info->in_progress            = false;
        }
    }

    return EOK;
}

static int ol_scan_unregister_event_handler(ieee80211_scanner_t          ss,
                                            ieee80211_scan_event_handler evhandler,
                                            void                         *arg)
{
    int    i;

    spin_lock(&ss->ss_lock);
    for (i = 0; i < IEEE80211_MAX_SCAN_EVENT_HANDLERS; ++i) {
        if ((ss->ss_event_handlers[i] == evhandler) &&
            (ss->ss_event_handler_arg[i] == arg)) {
            /*
             * Replace event handler being deleted with the last one in the list
             */
            ss->ss_event_handlers[i]    = ss->ss_event_handlers[ss->ss_num_handlers - 1];
            ss->ss_event_handler_arg[i] = ss->ss_event_handler_arg[ss->ss_num_handlers - 1];

            /*
             * Clear last event handler in the list
             */
            ss->ss_event_handlers[ss->ss_num_handlers - 1]    = NULL;
            ss->ss_event_handler_arg[ss->ss_num_handlers - 1] = NULL;
            ss->ss_num_handlers--;

            spin_unlock(&ss->ss_lock);

            return EOK;
        }
    }
    spin_unlock(&ss->ss_lock);

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY, "%s: Failed to unregister evhandler=%08p arg=%08p\n",
                          __func__,
                          evhandler,
                          arg);
    return ENXIO;
}

static int ol_scan_channel_list_length(ieee80211_scanner_t ss)
{
    return 0;
}

static int ol_scan_scanentry_received(ieee80211_scanner_t ss, bool bssid_match)
{
    return EOK;
}

static void ol_scan_attach_complete(ieee80211_scanner_t ss)
{

}

static int ol_scan_detach(ieee80211_scanner_t *ss)
{
    int i;

    /*
     * Verify that all event handlers have been unregistered.
     */
    if ((*ss)->ss_num_handlers > 0) {
        IEEE80211_SCAN_PRINTF((*ss), IEEE80211_MSG_ANY, "%s: Event handler table not empty: %d entries\n",
                              __func__,
                              (*ss)->ss_num_handlers);

        spin_lock(&(*ss)->ss_lock);
        for (i = 0; i < IEEE80211_MAX_SCAN_EVENT_HANDLERS; ++i) {
            if ((*ss)->ss_event_handlers[i] != NULL) {
                IEEE80211_SCAN_PRINTF((*ss), IEEE80211_MSG_ANY, "%s: evhandler=%08p arg=%08p not unregistered\n",
                                      __func__,
                                      (*ss)->ss_event_handlers[i],
                                      (*ss)->ss_event_handler_arg[i]);
            }
        }
        spin_unlock(&(*ss)->ss_lock);
    }
    ASSERT((*ss)->ss_num_handlers == 0);
    /*
     * Free synchronization objects
     */
    spin_lock_destroy(&((*ss)->ss_lock));

    OS_FREE(*ss);

    *ss = NULL;

    return EINVAL;
}

static void ol_scan_detach_prepare(ieee80211_scanner_t ss)
{

}

static void ol_scan_connection_lost(ieee80211_scanner_t ss)
{

}

static void ol_scan_set_default_scan_parameters(ieee80211_scanner_t ss,
                                           struct ieee80211vap   *vap,
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
/* All times in milliseconds */
#define HW_DEFAULT_SCAN_MIN_BEACON_COUNT_INFRA                           1
#define HW_DEFAULT_SCAN_MIN_BEACON_COUNT_IBSS                            3
#define HW_DEFAULT_SCAN_MIN_DWELL_TIME_ACTIVE                          105
#define HW_DEFAULT_SCAN_MIN_DWELL_TIME_PASSIVE                         130
#define HW_DEFAULT_SCAN_MAX_DWELL_TIME_ACTIVE                          105
#define HW_DEFAULT_SCAN_MAX_DWELL_TIME_PASSIVE                         300
#define HW_DEFAULT_SCAN_MIN_REST_TIME_INFRA                             50
#define HW_DEFAULT_SCAN_MIN_REST_TIME_IBSS                             250
#define HW_DEFAULT_SCAN_MAX_REST_TIME                                  500
#define HW_DEFAULT_SCAN_MAX_OFFCHANNEL_TIME                              0
#define HW_DEFAULT_REPEAT_PROBE_REQUEST_INTVAL                          50
#define HW_DEFAULT_SCAN_NETWORK_IDLE_TIMEOUT                           200
#define HW_DEFAULT_SCAN_BEACON_TIMEOUT                                1000
#define HW_DEFAULT_SCAN_MAX_DURATION                                 50000
#define HW_DEFAULT_SCAN_MAX_START_DELAY                               5000
#define HW_DEFAULT_SCAN_FAKESLEEP_TIMEOUT                             1000
#define HW_DEFAULT_SCAN_PROBE_DELAY                                      0
#define HW_DEFAULT_OFFCHAN_RETRY_DELAY                                 100
#define HW_DEFAULT_MAX_OFFCHAN_RETRIES                                   3
#define HW_NOT_CONNECTED_DWELL_TIME_FACTOR                               2

    struct ieee80211_aplist_config    *pconfig = ieee80211_vap_get_aplist_config(vap);
    int                               i;
    u_int8_t                          *bssid = NULL;

    OS_MEMZERO(scan_params, sizeof(*scan_params));
    scan_params->min_dwell_time_active  = active_scan_flag ? HW_DEFAULT_SCAN_MIN_DWELL_TIME_ACTIVE : HW_DEFAULT_SCAN_MIN_DWELL_TIME_PASSIVE;
    scan_params->max_dwell_time_active  = HW_DEFAULT_SCAN_MAX_DWELL_TIME_ACTIVE;
    scan_params->min_dwell_time_passive = HW_DEFAULT_SCAN_MIN_DWELL_TIME_PASSIVE;
    scan_params->max_dwell_time_passive = HW_DEFAULT_SCAN_MAX_DWELL_TIME_PASSIVE;
    scan_params->max_rest_time          = high_priority_flag ?
        HW_DEFAULT_SCAN_MAX_REST_TIME : 0;
    scan_params->idle_time              = HW_DEFAULT_SCAN_NETWORK_IDLE_TIMEOUT;
    scan_params->repeat_probe_time      = HW_DEFAULT_REPEAT_PROBE_REQUEST_INTVAL;
    scan_params->offchan_retry_delay    = HW_DEFAULT_OFFCHAN_RETRY_DELAY;
    scan_params->max_offchannel_time    = HW_DEFAULT_SCAN_MAX_OFFCHANNEL_TIME;

    if (opmode == IEEE80211_M_IBSS) {
        scan_params->min_rest_time    = HW_DEFAULT_SCAN_MIN_REST_TIME_IBSS;
        scan_params->min_beacon_count = (peer_count > 0) ?
            HW_DEFAULT_SCAN_MIN_BEACON_COUNT_IBSS : 0;
        scan_params->type             = (peer_count > 0) ? IEEE80211_SCAN_BACKGROUND : IEEE80211_SCAN_FOREGROUND;
    }
    else {
        scan_params->min_rest_time    = HW_DEFAULT_SCAN_MIN_REST_TIME_INFRA;
        scan_params->min_beacon_count = connected_flag ? HW_DEFAULT_SCAN_MIN_BEACON_COUNT_INFRA : 0;
        scan_params->type             = connected_flag ? IEEE80211_SCAN_BACKGROUND : IEEE80211_SCAN_FOREGROUND;
    }

    scan_params->max_offchan_retries        = HW_DEFAULT_MAX_OFFCHAN_RETRIES;
    scan_params->beacon_timeout             = HW_DEFAULT_SCAN_BEACON_TIMEOUT;
    scan_params->max_scan_time              = HW_DEFAULT_SCAN_MAX_DURATION;
    scan_params->probe_delay                = HW_DEFAULT_SCAN_PROBE_DELAY;
    scan_params->flags                      = (active_scan_flag   ? IEEE80211_SCAN_ACTIVE : IEEE80211_SCAN_PASSIVE) |
                                              (high_priority_flag ? IEEE80211_SCAN_FORCED : 0)                      |
                                              (external_scan_flag ? IEEE80211_SCAN_EXTERNAL : 0)                    |
                                              IEEE80211_SCAN_ALLBANDS;
    scan_params->num_channels               = 0;
    scan_params->chan_list                  = NULL;
    scan_params->num_ssid                   = 0;
    scan_params->ie_len                     = 0;
    scan_params->ie_data                    = NULL;
    scan_params->check_termination_function = NULL;
    scan_params->check_termination_context  = NULL;
    scan_params->restricted_scan            = false;
    scan_params->multiple_ports_active      = ol_count_active_ports(vap->iv_ic, vap);

    /*
     * Validate time before sending second probe request. A value of 0 is valid
     * and means a single probe request must be transmitted.
     */
    ASSERT(scan_params->repeat_probe_time < scan_params->min_dwell_time_active);

    /* Double the dwell time if not connected */
    if (! connected_flag)
    {
        scan_params->min_dwell_time_active *= HW_NOT_CONNECTED_DWELL_TIME_FACTOR;
    }

    /*
     * SSID list must be received as an argument instead of retrieved from
     * the configuration parameters
     */
    scan_params->num_ssid = num_ssid;
    if (scan_params->num_ssid > IEEE80211_N(scan_params->ssid_list)) {
        scan_params->num_ssid = IEEE80211_N(scan_params->ssid_list);
    }
    for (i = 0; i < scan_params->num_ssid; i++) {
        scan_params->ssid_list[i] = ssid_list[i];

        /* Validate SSID length */
        if (scan_params->ssid_list[i].len > sizeof(scan_params->ssid_list[i].ssid)) {
            scan_params->ssid_list[i].len = 0;
        }
    }

    scan_params->num_bssid = ieee80211_aplist_get_desired_bssid_count(pconfig);
    if (scan_params->num_bssid > IEEE80211_N(scan_params->bssid_list)) {
        scan_params->num_bssid = IEEE80211_N(scan_params->bssid_list);
    }

    for (i = 0; i < scan_params->num_bssid; i++) {
        ieee80211_aplist_get_desired_bssid(pconfig, i, &bssid);
        OS_MEMCPY(scan_params->bssid_list[i],
            bssid,
            IEEE80211_N(scan_params->bssid_list[i]));
    }
}


static int ol_scan_get_requestor_id(ieee80211_scanner_t ss, u_int8_t *module_name, IEEE80211_SCAN_REQUESTOR *requestor)
{
        int    i, j;

    if (!module_name) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: missing module name\n",
            __func__);

        return EINVAL;
    }

    /*
     * Examine each enty in the requestor table looking for an unused ID.
     */
    for (i = 0; i < IEEE80211_MAX_REQUESTORS; ++i) {
        if (ss->ss_requestors[i].requestor == 0) {
            ss->ss_requestors[i].requestor = IEEE80211_REQ_ID_PREFIX | i;

            /*
             * Copy the module name into the requestors table.
             */
            j = 0;
            while (module_name[j] && (j < (IEEE80211_SCAN_REQUESTOR_MAX_MODULE_NAME - 1))) {
                ss->ss_requestors[i].module_name[j] = module_name[j];
                ++j;
            }
            ss->ss_requestors[i].module_name[j] = 0;

            /*
             * Return the requestor ID.
             */
            *requestor = ss->ss_requestors[i].requestor;

            IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: module=%s requestor=%X\n",
                __func__,
                module_name,
                ss->ss_requestors[i].requestor);

            return EOK;
        }
    }

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: No IDs left module=%s\n",
        __func__, module_name);

    /*
     * Could not find an unused ID.
     */
    return ENOMEM;
}

static void ol_scan_clear_requestor_id(ieee80211_scanner_t ss, IEEE80211_SCAN_REQUESTOR requestor)
{
    int    index = requestor & ~IEEE80211_REQ_ID_PREFIX;

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: requestor=%X\n",
        __func__,
        requestor);

    /* Clear fields */
    ss->ss_requestors[index].requestor      = 0;
    ss->ss_requestors[index].module_name[0] = 0;
}

static u_int8_t *ol_scan_get_requestor_name(ieee80211_scanner_t ss, IEEE80211_SCAN_REQUESTOR requestor)
{
    int    i;

    /*
     * Use requestor to index table directly
     */
    i = (requestor & ~IEEE80211_REQ_ID_PREFIX);
    if ((i < IEEE80211_MAX_REQUESTORS) && (ss->ss_requestors[i].requestor == requestor)) {
        return ss->ss_requestors[i].module_name;
    } else {
        return (u_int8_t *)"unknown";
    }

}

/* WMI interface functions */
int
ol_ath_scan_start_send(struct ol_ath_softc_net80211 *scn,
                    u_int8_t if_id,
                    ieee80211_scan_params    *params,
                    bool add_cck_rates,
                    IEEE80211_SCAN_REQUESTOR requestor,
                    IEEE80211_SCAN_PRIORITY  priority,
                    IEEE80211_SCAN_ID        scan_id)
{
    struct scan_start_params scan_param;
    ieee80211_scanner_t ss;
    int i, ret;
    uint32_t *channel_list = NULL;

    ss = scn->sc_ic.ic_scanner;
    qdf_mem_set(&scan_param, sizeof(scan_param), 0);
    scan_param.num_chan = params->num_channels;
    scan_param.num_ssids = params->num_ssid;
    scan_param.num_bssid = params->num_bssid;
    scan_param.ie_len = params->ie_len;

    scan_param.vdev_id = if_id;
    scan_param.scan_priority = priority;
    scan_param.scan_id = scan_id;
    scan_param.scan_req_id = requestor;

    /** Max. active channel dwell time */
    scan_param.dwell_time_active = params->max_dwell_time_active ;
    /** Passive channel dwell time */
    scan_param.dwell_time_passive = params->max_dwell_time_passive;

    /** Scan control flags */
    scan_param.passive_flag = (params->flags & IEEE80211_SCAN_PASSIVE);

    if (scn->sc_ic.ic_strict_pscan_enable) {
        scan_param.is_strict_pscan_en = TRUE;
    }

    if (params->flags & IEEE80211_SCAN_PROM_MODE) {
        scan_param.is_promiscous_mode = TRUE;
    }

    if (params->flags & IEEE80211_SCAN_PHY_ERR) {
        scan_param.is_phy_error = TRUE;
    }

    /** send multiple braodcast probe req with this delay in between */
    scan_param.repeat_probe_time = params->repeat_probe_time;
#if QCA_LTEU_SUPPORT
    /** time in msec between 2 probe requests */
    if (params->probe_spacing_time)
        scan_param.probe_spacing_time = params->probe_spacing_time;
#endif
    /** delay between channel change and first probe request */
    scan_param.probe_delay = params->probe_delay;
    /** idle time on channel for which if no traffic is seen
        then scanner can switch to off channel */
    scan_param.idle_time = params->idle_time;
    scan_param.min_rest_time = params->min_rest_time;
    /** maximum rest time allowed on bss channel, overwrites
     *  other conditions and changes channel to off channel
     *   even if min beacon count, idle time requirements are not met.
     */
    scan_param.max_rest_time = params->max_rest_time;
    /** maxmimum scan time allowed */
#if IPQ4019_EMU
    scan_param.max_scan_time = 0xffffffff;
#else
    scan_param.max_scan_time = params->max_scan_time;
#endif
    /* add cck rates if required */
    if (add_cck_rates) {
        scan_param.add_cck_rates = TRUE;
    }
    /** It enables the Channel stat event indication to host */
    if (params->flags & IEEE80211_SCAN_CHAN_EVENT)
        scan_param.chan_stat_enable = TRUE;
    if (params->flags & IEEE80211_SCAN_ADD_BCAST_PROBE) {
        scan_param.add_bcast_probe_reqd = TRUE;
    }
    /* off channel TX control */
    if (params->flags & IEEE80211_SCAN_OFFCHAN_MGMT_TX) {
        scan_param.offchan_tx_mgmt = TRUE;
    }
    if (params->flags & IEEE80211_SCAN_OFFCHAN_DATA_TX) {
        scan_param.offchan_tx_data = TRUE;
    }

    /* Half/Quarter channel scan control*/
    if (params->flags & IEEE80211_SCAN_HALF_RATE) {
	scan_param.half_rate = TRUE;
    } else if (params->flags & IEEE80211_SCAN_QUARTER_RATE) {
	scan_param.quarter_rate = TRUE;
    }

#ifndef TEST_CODE
#define FREQUENCY_THRESH        1000
    if (params->num_channels) {
        channel_list =(uint32_t *)kmalloc(params->num_channels *
            sizeof(uint32_t),GFP_ATOMIC);
	if (!channel_list) {
	    qdf_print("%s, Unable to allocate temporary copy of channel list,"
			" Dropping scan start cmd\n", __func__);
	    return -1;
	}
        ss->ss_nchans = 0;
        for (i=0;i<params->num_channels; ++i) {
            if (params->chan_list[i] < FREQUENCY_THRESH) {
                channel_list[i]=ieee80211_ieee2mhz(&scn->sc_ic, params->chan_list[i], 0);
            } else {
                A_UINT16 chan_mode, chan;
                chan_mode = (params->chan_list[i] >> IEEE80211_SCAN_CHAN_MODE_SHIFT) & IEEE80211_SCAN_CHAN_MODE_MASK;
                switch (chan_mode) {
                    case IEEE80211_SCAN_CHAN_MODE_11NA_HT20:
                        chan_mode = MODE_11NA_HT20;
                    break;
                    case IEEE80211_SCAN_CHAN_MODE_11NG_HT20:
                        chan_mode = MODE_11NG_HT20;
                    break;
                    case IEEE80211_SCAN_CHAN_MODE_11NA_HT40:
                        chan_mode = MODE_11NA_HT40;
                    break;
                    case IEEE80211_SCAN_CHAN_MODE_11NG_HT40:
                        chan_mode = MODE_11NG_HT40;
                    break;
                    case IEEE80211_SCAN_CHAN_MODE_11AC_VHT20:
                        chan_mode = MODE_11AC_VHT20;
                    break;
                    case IEEE80211_SCAN_CHAN_MODE_11AC_VHT40:
                        chan_mode = MODE_11AC_VHT40;
                    break;
                    case IEEE80211_SCAN_CHAN_MODE_11AC_VHT80:
                        chan_mode = MODE_11AC_VHT80;
                    break;
                    case IEEE80211_SCAN_CHAN_MODE_11AC_VHT160:
                        chan_mode = MODE_11AC_VHT160;
                    break;
                    case IEEE80211_SCAN_CHAN_MODE_11AC_VHT80_80:
                        chan_mode = MODE_11AC_VHT80_80;
                    break;
                    case IEEE80211_SCAN_CHAN_MODE_11AC_VHT20_2G:
                        chan_mode = MODE_11AC_VHT20_2G;
                    break;
                    case IEEE80211_SCAN_CHAN_MODE_11AC_VHT40_2G:
                        chan_mode = MODE_11AC_VHT40_2G;
                    break;
                    case IEEE80211_SCAN_CHAN_MODE_11AC_VHT80_2G:
                        chan_mode = MODE_11AC_VHT80_2G;
                    break;
                    default:
                        chan_mode = 0;
                    break;
                }
                channel_list[i] = 0;
                channel_list[i] |= (chan_mode & WMI_HOST_SCAN_CHAN_MODE_MASK) << WMI_HOST_SCAN_CHAN_MODE_SHIFT ;
                chan = (params->chan_list[i] >> IEEE80211_SCAN_CHAN_SHIFT) & IEEE80211_SCAN_CHAN_MASK;
                channel_list[i] |= (chan & WMI_HOST_SCAN_CHAN_FREQ_MASK) << WMI_HOST_SCAN_CHAN_FREQ_SHIFT;
            }
            ss->ss_nchans++;
        }
        scan_param.chan_list = channel_list;
    }
#endif
    for (i = 0; i < params->num_ssid; ++i) {
        scan_param.ssid[i].length=params->ssid_list[i].len;
        OS_MEMCPY(scan_param.ssid[i].mac_ssid, params->ssid_list[i].ssid, params->ssid_list[i].len);
    }

    if (params->num_bssid) {
        OS_MEMCPY(scan_param.bssid_list, params->bssid_list, params->num_bssid * IEEE80211_ADDR_LEN);
    }

    scan_param.ie_data = params->ie_data;
    ret = wmi_unified_scan_start_cmd_send(scn->wmi_handle, &scan_param);

    if (channel_list) {
        kfree(channel_list);
    }
    return ret;
}

static int ol_scan_start(ieee80211_scanner_t       ss, wlan_if_t                vap,
                    ieee80211_scan_params    *params,
                    IEEE80211_SCAN_REQUESTOR requestor,
                    IEEE80211_SCAN_PRIORITY  priority,
                    IEEE80211_SCAN_ID        *scan_id)
{

    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    struct ieee80211_rateset rs;
    bool add_cck_rates = FALSE;
    u_int32_t i = 0;
    ol_ath_set_ht_vht_ies(vap->iv_bss); /* set ht and vht ies in FW */
    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: Requestor: %s- requestor id=%x, scan_id =%x\n",
                          __func__,
                          ol_scan_get_requestor_name(ss, requestor), requestor, *scan_id);

    spin_lock(&ss->ss_lock);
    if (ss->ss_common.ss_info.si_scan_in_progress) {
        spin_unlock(&ss->ss_lock);
        return EINPROGRESS;
     }
    ss->ss_scan_start_time                = OS_GET_TIMESTAMP();
    ss->ss_common.ss_info.si_scan_in_progress = TRUE;
    *scan_id =  (++ss->ss_id_generator) & ~(IEEE80211_SCAN_CLASS_MASK | IEEE80211_HOST_SCAN) ;
    spin_unlock(&ss->ss_lock);

    ol_scan_update_channel_list(ic->ic_scanner);

    *scan_id =  *scan_id | WMI_HOST_P_SCAN_REQ_ID_PREFIX ;
    /* check if vaps operational rates contain CCK , only then add CCK rates to probe request */
    /* p2p vaps do not include CCK rates in operations rate set */

    OS_MEMZERO(&rs, sizeof(struct ieee80211_rateset));
    wlan_get_operational_rates(vap,IEEE80211_MODE_11G, rs.rs_rates, IEEE80211_RATE_MAXSIZE, &i);
    rs.rs_nrates = i;
    for (i = 0; i < rs.rs_nrates; i++) {
            if (rs.rs_rates[i] == 0x2 || rs.rs_rates[i] == 0x4 ||
                   rs.rs_rates[i] == 0xb || rs.rs_rates[i] == 0x16) {
                             add_cck_rates = TRUE;
            }
    }
    ss->ss_flags                      = params->flags;
    ss->ss_min_dwell_active           = params->min_dwell_time_active;
    ss->ss_max_dwell_active           = params->max_dwell_time_active;
    ss->ss_min_dwell_passive          = params->min_dwell_time_passive;
    ss->ss_max_dwell_passive          = params->max_dwell_time_passive;
    ss->ss_min_rest_time              = params->min_rest_time;
    ss->ss_max_rest_time              = params->max_rest_time;
    ss->ss_repeat_probe_time          = params->repeat_probe_time;
    ss->ss_min_beacon_count           = params->min_beacon_count;
    ss->ss_max_offchannel_time        = params->max_offchannel_time;
    ss->ss_type                       = params->type;
    ss->ss_requestor                  = requestor;
    ss->ss_scan_id                    = *scan_id;
    ss->ss_priority                   = priority;
    ss->ss_restricted                 = params->restricted_scan;
    ss->ss_termination_reason         = IEEE80211_REASON_NONE;

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: issue scan request Requestor: %s, scan id 0x%x \n",
                          __func__,
                          ol_scan_get_requestor_name(ss, requestor), *scan_id);
    if (vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBEREQ].length) {
        params->ie_data = vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBEREQ].ie;
        params->ie_len = vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBEREQ].length;
    }
#if QCA_LTEU_SUPPORT
    if (ic->ic_nl_handle) {
        if (params->max_dwell_time_active <= LTEU_TIME_AT_END_OF_SCAN_INTERVAL)
            params->probe_spacing_time = 0;
        else
            params->probe_spacing_time = (params->max_dwell_time_active
                                          - LTEU_TIME_AT_END_OF_SCAN_INTERVAL)/(vap->scan_probe_spacing_interval);
    }
    else {
        params->probe_spacing_time = 0;
    }
#endif
    /* Reset offchan scan requestor */
    if(requestor != vap->offchan_requestor) {
       vap->offchan_requestor = 0;
    }

    /* Since HW is going to scan, channel stats counters will not be accurate.
     * invalidate current channel stats by setting them 0.
     */
    ol_ath_invalidate_channel_stats(ic);

    return ol_ath_scan_start_send(scn,
                                      avn->av_if_id, params, add_cck_rates, requestor, priority, *scan_id);
}


static int ol_scan_cancel(ieee80211_scanner_t       ss,
                     wlan_if_t                vap,
                     IEEE80211_SCAN_REQUESTOR requestor,
                     IEEE80211_SCAN_ID        scan_id_mask,
                     u_int32_t                flags)
{
    struct ieee80211com         *ic = ss->ss_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn;
    struct scan_stop_params param;
    int ret;

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: Requestor: %s\n",
                          __func__,
                          ol_scan_get_requestor_name(ss, requestor));
    spin_lock(&ss->ss_lock);

    if (!ss->ss_common.ss_info.si_scan_in_progress) {
             spin_unlock(&ss->ss_lock);
             return EPERM;
    }
    spin_unlock(&ss->ss_lock);


    /* scan scheduler is not supportd yet */
    qdf_mem_set(&param, sizeof(param), 0);
    param.scan_id = (scan_id_mask & ~IEEE80211_SCAN_CLASS_MASK);
    param.requestor = requestor;
    avn = OL_ATH_VAP_NET80211(vap);
    param.vdev_id = avn->av_if_id;

    if ((scan_id_mask & IEEE80211_SCAN_CLASS_MASK) == IEEE80211_ALL_SCANS) {
        /* Cancelling all scans - always match scan id */
        param.all_scans = TRUE;
    }
    else if ((scan_id_mask & IEEE80211_SCAN_CLASS_MASK) == IEEE80211_VAP_SCAN) {
        /*
         * Cancelling VAP scans - report a match if scan was requested by the
         * same VAP trying to cancel it.
         */
        param.vap_scans = TRUE;
    }
    else if ((scan_id_mask & IEEE80211_SCAN_CLASS_MASK) == IEEE80211_SPECIFIC_SCAN) {
        /*
         * Cancelling specific scan - report a match if specified scan id
         * matches the request's scan id.
         */
        param.specific_scan = TRUE;
    }

    /*
     send a synchronous cancel command */
    if (flags & IEEE80211_SCAN_CANCEL_SYNC) {
        wmi_host_scan_event wmi_scn_event;

        OS_MEMZERO(&wmi_scn_event, sizeof(wmi_scn_event));
        wmi_scn_event.event = WMI_HOST_SCAN_EVENT_COMPLETED;
        wmi_scn_event.reason = WMI_HOST_SCAN_REASON_CANCELLED;
        wmi_scn_event.requestor = requestor;
        wmi_scn_event.scan_id = ss->ss_scan_id;

        ol_scan_process_event(scn, &wmi_scn_event);
    }
    param.flags = flags & IEEE80211_SCAN_CANCEL_SYNC;
    ret = wmi_unified_scan_stop_cmd_send(scn->wmi_handle, &param);
    return ret;
}

static int ol_scan_set_priority(ieee80211_scanner_t       ss,
                           IEEE80211_SCAN_REQUESTOR requestor,
                           IEEE80211_SCAN_ID        scan_id_mask,
                           IEEE80211_SCAN_PRIORITY  scanPriority)
{
    return EINVAL;

}


static int ol_scan_set_forced_flag(ieee80211_scanner_t       ss,
                              IEEE80211_SCAN_REQUESTOR requestor,
                              IEEE80211_SCAN_ID        scan_id_mask,
                              bool                     forced_flag)
{
    return EINVAL;
}

static int
ol_scan_get_priority_table(ieee80211_scanner_t       ss,
                             enum ieee80211_opmode      opmode,
                             int                        *p_number_rows,
                             IEEE80211_PRIORITY_MAPPING **p_mapping_table)
{
    return EINVAL;
}

static int
ol_scan_set_priority_table(ieee80211_scanner_t       ss,
                             enum ieee80211_opmode      opmode,
                             int                        number_rows,
                             IEEE80211_PRIORITY_MAPPING *p_mapping_table)
{
    return EINVAL;

}

static int ol_scan_scheduler_get_requests(ieee80211_scanner_t       ss,
                                     ieee80211_scan_request_info *scan_request_info,
                                     int                         *total_requests,
                                     int                         *returned_requests)
{
    return EINVAL;
}

static int ol_scan_enable_scan_scheduler(ieee80211_scanner_t       ss,
                               IEEE80211_SCAN_REQUESTOR requestor)
{
    return EINVAL;
}

static int ol_scan_disable_scan_scheduler(ieee80211_scanner_t       ss,
                                IEEE80211_SCAN_REQUESTOR requestor,
                                u_int32_t                max_suspend_time)
{
    return EINVAL;

}

static const u_int16_t default_scan_order[] = {
    /* 2.4Ghz ch: 1,6,11,7,13 */
    2412, 2437, 2462, 2442, 2472,
    /* 8 FCC channel: 52, 56, 60, 64, 36, 40, 44, 48 */
    5260, 5280, 5300, 5320, 5180, 5200, 5220, 5240,
    /* 4 MKK channels: 34, 38, 42, 46 */
    5170, 5190, 5210, 5230,
    /* 2.4Ghz ch: 2,3,4,5,8,9,10,12 */
    2417, 2422, 2427, 2432, 2447, 2452, 2457, 2467,
    /* 2.4Ghz ch: 14 */
    2484,
    /* 6 FCC channel: 144, 149, 153, 157, 161, 165 */
    5720, 5745, 5765, 5785, 5805, 5825,
    /* 11 ETSI channel: 100,104,108,112,116,120,124,128,132,136,140 */
    5500, 5520, 5540, 5560, 5580, 5600, 5620, 5640, 5660, 5680, 5700,
    /* Added Korean channels 2312-2372 */
    2312, 2317, 2322, 2327, 2332, 2337, 2342, 2347, 2352, 2357, 2362, 2367,
    2372 ,
    /* Added Japan channels in 4.9/5.0 spectrum */
    5040, 5060, 5080, 4920, 4940, 4960, 4980,
    /* FCC4 channels */
    4950, 4955, 4965, 4970, 4975, 4985,
    /* Added MKK2 half-rates */
    4915, 4920, 4925, 4935, 4940, 4945, 5035, 5040, 5045, 5055,
    /* Added FCC4 quarter-rates */
    4942, 4947, 4952, 4957, 4962, 4967, 4972, 4977, 4982, 4987,
    /* Add MKK quarter-rates */
    4912, 4917, 4922, 4927, 4932, 4937, 5032, 5037, 5042, 5047, 5052, 5057,
};

/*
 * get all the channels to scan .
 * can be called whenever the set of supported channels are changed.
 * send the updated channel list to target.
 */
int ol_scan_update_channel_list(ieee80211_scanner_t ss)
{
#define IEEE80211_2GHZ_FREQUENCY_THRESHOLD    3000            // in kHz
    struct ieee80211com         *ic = ss->ss_ic;
    struct ieee80211_channel    *c;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    u_int16_t *scan_order = (u_int16_t *)default_scan_order;
    u_int32_t scan_order_size = IEEE80211_N(default_scan_order);
    int i = 0;
    struct scan_chan_list_params *param;

    param = (struct scan_chan_list_params *)
        kmalloc((sizeof(struct scan_chan_list_params) +
                    ((MAX_CHANS - 1) * sizeof(struct channel_param)) ), GFP_ATOMIC);
    if (!param) {
	qdf_print("%s Unable to create memory to hold channel list param,"
			" Dropping scan chan list update\n", __func__);
	return -1;
    }

    ss->ss_nallchans = 0;
    ss->ss_nchans = 0;

    if (ic->ic_custom_scan_order_size > 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Using custom scan order\n"),
            scan_order = ic->ic_custom_scan_order;
        scan_order_size = ic->ic_custom_scan_order_size;
    }

    spin_lock(&ss->ss_lock);

    for (i = 0; i < scan_order_size; ++i) {
        c = ol_ath_find_full_channel(ic,scan_order[i]);

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
        if (c != NULL && !IEEE80211_IS_CHAN_RADAR(c)) {
#else
        if (c != NULL) {
#endif
            ss->ss_all_chans[ss->ss_nallchans++] = c;
        }

    }

    /* Iterate again adding half-rate and quarter-rate channels */
    for (i = 0; i < scan_order_size; ++i) {

        if (scan_order[i] < IEEE80211_2GHZ_FREQUENCY_THRESHOLD)
            continue;

        c = NULL;
        c = ieee80211_find_channel(ic, scan_order[i], 0,
                                   (IEEE80211_CHAN_A | IEEE80211_CHAN_HALF));
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
        if (c != NULL && !IEEE80211_IS_CHAN_RADAR(c)) {
#else
        if (c != NULL) {
#endif
            ss->ss_all_chans[ss->ss_nallchans++] = c;
        }

        c = NULL;
        c = ieee80211_find_channel(ic, scan_order[i], 0,
                                   (IEEE80211_CHAN_A | IEEE80211_CHAN_QUARTER));

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
        if (c != NULL && !IEEE80211_IS_CHAN_RADAR(c)) {
#else
        if (c != NULL) {
#endif
            ss->ss_all_chans[ss->ss_nallchans++] = c;
        }
    }

    if (ss->ss_flags & IEEE80211_SCAN_80MHZ) {
        /* Iterate again adding VHT40 & VHT80 channels */
        for (i = 0,c = NULL; i < scan_order_size; ++i) {

            if (scan_order[i] < IEEE80211_2GHZ_FREQUENCY_THRESHOLD)
                continue;

            if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT40PLUS)) {
                c = NULL;
                c = ieee80211_find_channel(ic, scan_order[i], 0, IEEE80211_CHAN_11AC_VHT40PLUS);
            }

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
            if (c != NULL && !IEEE80211_IS_CHAN_RADAR(c)) {
#else
            if (c != NULL) {
#endif
                ss->ss_all_chans[ss->ss_nallchans++] = c;
            }

            if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT80)) {
                c = NULL;
                c = ieee80211_find_channel(ic, scan_order[i], 0, IEEE80211_CHAN_11AC_VHT80);
            }
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
            if (c != NULL && !IEEE80211_IS_CHAN_RADAR(c)) {
#else
            if (c != NULL) {
#endif
                ss->ss_all_chans[ss->ss_nallchans++] = c;
            }

            if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT160)) {
                c = NULL;
                c = ieee80211_find_channel(ic, scan_order[i], 0, IEEE80211_CHAN_11AC_VHT160);
            }
            if (c != NULL) {
                ss->ss_all_chans[ss->ss_nallchans++] = c;
            }

            if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT80_80)) {
                c = NULL;
                c = ieee80211_find_channel(ic, scan_order[i], 0, IEEE80211_CHAN_11AC_VHT80_80);
            }
            if (c != NULL) {
                ss->ss_all_chans[ss->ss_nallchans++] = c;
            }
        }
    }

    spin_unlock(&ss->ss_lock);

    ss->ss_nchans = ss->ss_nallchans;
    param->nallchans = ss->ss_nallchans;

    for(i=0;i<ss->ss_nallchans;++i) {
         c = ss->ss_all_chans[i];
         param->ch_param[i].mhz = c->ic_freq;
         param->ch_param[i].cfreq1 = c->ic_freq;
         param->ch_param[i].cfreq2 = 0;
         /* fill in mode. use 11G for 2G and 11A for 5G */

         if (c->ic_freq < 3000) {
             param->ch_param[i].phy_mode = WMI_HOST_MODE_11G;
         } else {
             param->ch_param[i].phy_mode = WMI_HOST_MODE_11A;
         }

         if (IEEE80211_IS_CHAN_PASSIVE(c)) {
             param->ch_param[i].is_chan_passive = TRUE;
         }

         if ( ieee80211_find_channel(ic, c->ic_freq, 0, IEEE80211_CHAN_11AC_VHT20)) {
             param->ch_param[i].allow_vht = TRUE;
             param->ch_param[i].allow_ht = TRUE;
         } else  if ( ieee80211_find_channel(ic, c->ic_freq, 0, IEEE80211_CHAN_HT20)) {
                param->ch_param[i].allow_ht = TRUE;
            if(ic->ic_vhtcap && ieee80211_find_channel(ic, c->ic_freq, 0,IEEE80211_CHAN_HT20)
               && IEEE80211_IS_CHAN_2GHZ(ieee80211_find_channel(ic, c->ic_freq, 0,
                                                        IEEE80211_CHAN_HT20)))  {
                param->ch_param[i].allow_vht = TRUE;
            }
         }

         if (IEEE80211_IS_CHAN_11AC_VHT80_80(c)) {
            param->ch_param[i].allow_vht = TRUE;
            param->ch_param[i].allow_ht = TRUE;
            param->ch_param[i].phy_mode = WMI_HOST_MODE_11AC_VHT80_80;
            param->ch_param[i].cfreq1 = ieee80211_ieee2mhz(ic, c->ic_vhtop_ch_freq_seg1,c->ic_flags);
            param->ch_param[i].cfreq2 = ieee80211_ieee2mhz(ic, c->ic_vhtop_ch_freq_seg2,c->ic_flags);
         }
         if (IEEE80211_IS_CHAN_11AC_VHT160(c)) {
            param->ch_param[i].allow_vht = TRUE;
            param->ch_param[i].allow_ht = TRUE;
            param->ch_param[i].phy_mode = WMI_HOST_MODE_11AC_VHT160;
            param->ch_param[i].cfreq1 = ieee80211_ieee2mhz(ic, c->ic_vhtop_ch_freq_seg1,c->ic_flags);
            param->ch_param[i].cfreq2 = ieee80211_ieee2mhz(ic, c->ic_vhtop_ch_freq_seg2,c->ic_flags);
         }
         if (IEEE80211_IS_CHAN_11AC_VHT80(c)) {
            param->ch_param[i].allow_vht = TRUE;
            param->ch_param[i].allow_ht = TRUE;
            param->ch_param[i].phy_mode = WMI_HOST_MODE_11AC_VHT80;
            param->ch_param[i].cfreq1 = ieee80211_get_chan_centre_freq(ic,c);
            param->ch_param[i].cfreq2 = 0;
         }

         if (IEEE80211_IS_CHAN_11AC_VHT40PLUS(c)) {
            param->ch_param[i].allow_vht = TRUE;
            param->ch_param[i].allow_ht = TRUE;
            param->ch_param[i].phy_mode = WMI_HOST_MODE_11AC_VHT40;
            param->ch_param[i].cfreq1 = ieee80211_get_chan_centre_freq(ic,c);
            param->ch_param[i].cfreq2 = 0;
         }

         if (IEEE80211_IS_CHAN_HALF(c))
            param->ch_param[i].half_rate = TRUE;
         if (IEEE80211_IS_CHAN_QUARTER(c))
            param->ch_param[i].quarter_rate = TRUE;

         /* also fill in power information */
        param->ch_param[i].minpower = c->ic_minpower;
        param->ch_param[i].maxpower = c->ic_maxpower;
        param->ch_param[i].maxregpower = c->ic_maxregpower;
        param->ch_param[i].antennamax = c->ic_antennamax;
        param->ch_param[i].reg_class_id = c->ic_regClassId;
    }

    wmi_unified_scan_chan_list_cmd_send(scn->wmi_handle, param);

    kfree(param);
    return EOK;
}

static int
ol_scan_process_event(ol_scn_t scn, wmi_host_scan_event *wmi_scn_event)
{
    struct ieee80211com *ic = &scn->sc_ic;
    ieee80211_scanner_t ss = ic->ic_scanner;
    ieee80211_scan_event            scan_event;
    int                             i, num_handlers;
    ieee80211_scan_event_handler    *ss_event_handlers = NULL;
    void                            **ss_event_handler_arg = NULL;
    wlan_if_t                       vaphandle;
    bool                            unknown_event=FALSE;
    struct ieee80211_channel *chan;
    u_int32_t freq;

    if ( wmi_scn_event->scan_id !=  ss->ss_scan_id ) {
            IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY,
                                      "%s: ignore scan event %d scan id  0x%x expected 0x%x \n",
                                       __func__,wmi_scn_event->event,
                                       wmi_scn_event->scan_id,ss->ss_scan_id ) ;
            return 0;
    }
    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN,
                                      "%s: %s: Accept scan event %d scan id  0x%x expected 0x%x\n",
                                       __func__,ol_scan_get_requestor_name(ss,wmi_scn_event->requestor),
                                       wmi_scn_event->event, wmi_scn_event->scan_id,ss->ss_scan_id);

    vaphandle = ol_ath_vap_get(scn,wmi_scn_event->vdev_id);
    /* If vaphandle is NULL means, vap is deleted after scan start, ignore the event */
    if(vaphandle == NULL) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY,
                        "%s: ignore scan event %d since vap is not available scan id 0x%x and vap id 0x%x \n",
                         __func__,wmi_scn_event->event, wmi_scn_event->scan_id,wmi_scn_event->vdev_id);
        return 0;
    }

    ss_event_handlers = (ieee80211_scan_event_handler *)
        kmalloc((sizeof(ieee80211_scan_event_handler) * IEEE80211_MAX_SCAN_EVENT_HANDLERS), GFP_ATOMIC);
    if (!ss_event_handlers) {
        qdf_print("%s: unable to allocate temporary copy of event handlers,"
               " Dropping scan event\n", __func__);
        return -1;
    }

    ss_event_handler_arg = (void **)
         kmalloc((sizeof(void *) * IEEE80211_MAX_SCAN_EVENT_HANDLERS), GFP_ATOMIC);

    if (!ss_event_handler_arg) {
        qdf_print( "%s: unable to allocate temporary copy of event handlers argument,"
                " Dropping scan event\n", __func__);
        kfree(ss_event_handlers);
        return -1;
    }

    OS_MEMZERO(&scan_event, sizeof(scan_event));
    switch(wmi_scn_event->event) {
    case WMI_HOST_SCAN_EVENT_STARTED:
        scan_event.type      =  IEEE80211_SCAN_STARTED;
        break;
#if QCA_LTEU_SUPPORT
    case WMI_HOST_SCAN_EVENT_GPIO_TIMEOUT:
        ieee80211_scan_table_flush(ieee80211_vap_get_scan_table(vaphandle));
        /* Fall through */
#endif
    case WMI_HOST_SCAN_EVENT_COMPLETED:
        scan_event.type      =  IEEE80211_SCAN_COMPLETED;
        chan = ieee80211_get_current_channel(ic);

        freq = ieee80211_chan2freq(ic, chan);
        if (!freq) {
           QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ERROR : INVALID Freq \n");
        } else {
           /* Update the channel for monitor mode path */
           ol_txrx_set_curchan(scn->pdev_txrx_handle, freq);
        }

        spin_lock(&ss->ss_lock);
        ss->ss_common.ss_info.si_scan_in_progress = FALSE;
        ss->ss_scan_id  = 0;
        spin_unlock(&ss->ss_lock);

        break;
    case WMI_HOST_SCAN_EVENT_BSS_CHANNEL:
        scan_event.type      =  IEEE80211_SCAN_HOME_CHANNEL;
        chan = ieee80211_get_current_channel(ic);

        freq = ieee80211_chan2freq(ic, chan);
        if (!freq) {
           QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ERROR : INVALID Freq \n");
        } else {
           /* Update the channel for monitor mode path */
           ol_txrx_set_curchan(scn->pdev_txrx_handle, freq);
        }

        break;
    case WMI_HOST_SCAN_EVENT_FOREIGN_CHANNEL:
        scan_event.type      =  IEEE80211_SCAN_FOREIGN_CHANNEL;
        ol_txrx_set_curchan(scn->pdev_txrx_handle, wmi_scn_event->channel_freq);
        break;
    case WMI_HOST_SCAN_EVENT_DEQUEUED:
        scan_event.type      =  IEEE80211_SCAN_DEQUEUED;
        break;
    case WMI_HOST_SCAN_EVENT_START_FAILED:
        /* FW could not start the scan, busy (or) do not have enough resources */
        /* send started, stopped events back to back */
        scan_event.type      =  IEEE80211_SCAN_STARTED;
        ieee80211com_note(ss->ss_ic, IEEE80211_MSG_SCAN, "%s: scan start "
             "failed scan id  0x%x, send start, completed events back to back\n",
             __func__, ss->ss_scan_id);
        spin_lock(&ss->ss_lock);
        ss->ss_common.ss_info.si_scan_in_progress = FALSE;
        ss->ss_scan_id  = 0;
        spin_unlock(&ss->ss_lock);
        break;
    default:
        unknown_event=TRUE;
        break;
    }

    if (unknown_event) {
        kfree(ss_event_handlers);
        kfree(ss_event_handler_arg);
        return 0;
    }
    switch(wmi_scn_event->reason) {
     case WMI_HOST_SCAN_REASON_COMPLETED:
        scan_event.reason      =  IEEE80211_REASON_COMPLETED;
        break;
     case WMI_HOST_SCAN_REASON_CANCELLED:
        scan_event.reason      =  IEEE80211_REASON_CANCELLED;
        break;
     case WMI_HOST_SCAN_REASON_PREEMPTED:
        scan_event.reason      =  IEEE80211_REASON_PREEMPTED;
        break;
     case WMI_HOST_SCAN_REASON_TIMEDOUT:
        scan_event.reason      =  IEEE80211_REASON_TIMEDOUT;
        break;
    }
#if QCA_LTEU_SUPPORT
    if (wmi_scn_event->event == WMI_HOST_SCAN_EVENT_GPIO_TIMEOUT)
        scan_event.reason = IEEE80211_REASON_RUN_FAILED;
#endif
    scan_event.chan      = ol_ath_find_full_channel(ic, wmi_scn_event->channel_freq);
    scan_event.requestor = wmi_scn_event->requestor;
    scan_event.scan_id   = wmi_scn_event->scan_id;
    spin_lock(&ss->ss_lock);
    if (wmi_scn_event->event == WMI_HOST_SCAN_EVENT_COMPLETED) {
        if (wmi_scn_event->reason == WMI_HOST_SCAN_REASON_COMPLETED)
             ss->ss_last_full_scan_time = ss->ss_scan_start_time;
        ss->ss_termination_reason = scan_event.reason;
    }

    /*
     * make a local copy of event handlers list to avoid
     * the call back modifying the list while we are traversing it.
     */
    num_handlers = ss->ss_num_handlers;
    for (i = 0; i < num_handlers; ++i) {
        ss_event_handlers[i] = ss->ss_event_handlers[i];
        ss_event_handler_arg[i] = ss->ss_event_handler_arg[i];
    }

    for (i = 0; i < num_handlers; ++i) {
        if ((ss_event_handlers[i] != ss->ss_event_handlers[i]) ||
            (ss_event_handler_arg[i] != ss->ss_event_handler_arg[i]))
        {
            /*
             * There is a change in the event list.
             * Traverse the original list to see this event is still valid.
             */
            int     k;
            bool    found = false;
            for (k = 0; k < ss->ss_num_handlers; k++) {
                if ((ss_event_handlers[i] == ss->ss_event_handlers[k]) &&
                    (ss_event_handler_arg[i] == ss->ss_event_handler_arg[k]))
                {
                    /* Found a match */
                    found = true;
                    break;
                }
            }
            if (!found) {
                /* Did not find a match. Skip this event call back. */
                IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY,
                                      "%s: Skip event handler since it is unreg. Type=%d. cb=0x%x, arg=0x%x\n",
                                      __func__, scan_event.type, ss_event_handlers[i], ss_event_handler_arg[i]);
                continue;
            }
        }

        if (ss_event_handlers[i] == NULL) {
            IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY,
                                  "%s: ss_event_handlers[%d]==NULL arg=%08p num_handlers=%d/%d\n",
                                  __func__,
                                  i, ss_event_handler_arg[i],
                                  num_handlers, ss->ss_num_handlers);
            continue;
        }

        /* Calling the event handler without the lock */
        spin_unlock(&ss->ss_lock);

        (ss_event_handlers[i]) (vaphandle, &scan_event, ss_event_handler_arg[i]);

        if (wmi_scn_event->event == WMI_HOST_SCAN_EVENT_START_FAILED ) {
            scan_event.type      =  IEEE80211_SCAN_COMPLETED;
            (ss_event_handlers[i]) (vaphandle, &scan_event, ss_event_handler_arg[i]);
        }

        /* Reacquire lock to check next event handler */
        spin_lock(&ss->ss_lock);
    }

    /* Calling the event handler without the lock */
    spin_unlock(&ss->ss_lock);
    kfree(ss_event_handlers);
    kfree(ss_event_handler_arg);

    return 0;

}

static int
ol_scan_wmi_event_handler(ol_scn_t scn, u_int8_t *data, u_int16_t datalen)
{
    struct ieee80211com *ic = &scn->sc_ic;
    ieee80211_scanner_t ss = ic->ic_scanner;
    wmi_host_scan_event wmi_scn_event;

    if ( wmi_extract_vdev_scan_ev_param(scn->wmi_handle, data, &wmi_scn_event)) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY,
                "%s: Failed to extract wmi scan event\n", __func__);
        return 0;
    }

    return ol_scan_process_event(scn, &wmi_scn_event);
}

int ol_print_scan_config(wlan_if_t vaphandle, struct seq_file *m)
{
    ieee80211_scanner_t ss = vaphandle->iv_ic->ic_scanner;
    ieee80211_scan_info info;
    const char*sep;
    int i;

    OS_MEMZERO(&info, sizeof(ieee80211_scan_info));

    ol_scan_get_last_scan_info(ss, &info);

    seq_printf(m, "scanning: %d\n", info.in_progress ? 1 : 0);
    seq_printf(m, "channels: ");
    sep = "";

    for (i = 0; i < info.channel_list_length; i++) {
        wlan_chan_t c = ss->ss_all_chans[i];

        seq_printf(m, "%s%u%c", sep, wlan_channel_ieee(c),
                   channel_type(c));
        sep = " ";
    }
    seq_printf(m, "\n");

    seq_printf(m, "flags: %s%s%s%s%s%s%s%s%s%s%s\n",
               (info.flags & IEEE80211_SCAN_PASSIVE) ? "passive " : "",
               (info.flags & IEEE80211_SCAN_ACTIVE) ? "active " : "",
               (info.flags & IEEE80211_SCAN_2GHZ) ? "2GHz " : "",
               (info.flags & IEEE80211_SCAN_5GHZ) ? "5GHz " : "",
               (info.flags & IEEE80211_SCAN_ALLBANDS) == IEEE80211_SCAN_ALLBANDS ? "allbands " : "",
               (info.flags & IEEE80211_SCAN_CONTINUOUS) ? "continuous " : "",
               (info.flags & IEEE80211_SCAN_FORCED) ? "forced " : "",
               (info.flags & IEEE80211_SCAN_NOW) ? "now " : "",
               (info.flags & IEEE80211_SCAN_ADD_BCAST_PROBE) ? "bcast_probe " : "",
               (info.flags & IEEE80211_SCAN_EXTERNAL) ? "external " : "",
               (info.flags & IEEE80211_SCAN_BURST) ? "burst " : "");


    seq_printf(m,
               "next: %u\n"
               "nchans: %u\n"
               "mindwell on active: %u\n"
               "maxdwell on active: %u\n"
               "mindwell on passive: %u\n"
               "maxdwell on passive: %u\n",
               info.scanned_channels,
               info.channel_list_length,
               info.min_dwell_time_active,
               info.max_dwell_time_active,
               info.min_dwell_time_passive,
               info.max_dwell_time_passive);


    return 0;
}

int ol_scan_attach(ieee80211_scanner_t        *ss,
                          wlan_dev_t                 devhandle,
                          osdev_t                    osdev,
                          bool (*is_connected)       (wlan_if_t),
                          bool (*is_txq_empty)       (wlan_dev_t),
                          bool (*is_sw_txq_empty)    (wlan_dev_t))
{
    struct ol_ath_softc_net80211 *scn;

    if (*ss) {
        return EINPROGRESS; /* already attached ? */
    }

    *ss = (ieee80211_scanner_t) OS_MALLOC(osdev, sizeof(struct ieee80211_scanner), 0);
    if (*ss) {
        OS_MEMZERO(*ss, sizeof(struct ieee80211_scanner));

        /*
         * Save handles to required objects.
         * Resource manager may not be initialized at this time.
         */
        (*ss)->ss_ic     = devhandle;
        (*ss)->ss_osdev  = osdev;
                /* initialize the function pointer table */
        (*ss)->ss_common.scan_attach_complete = ol_scan_attach_complete;
        (*ss)->ss_common.scan_detach = ol_scan_detach;
        (*ss)->ss_common.scan_detach_prepare = ol_scan_detach_prepare;
        (*ss)->ss_common.scan_start = ol_scan_start;
        (*ss)->ss_common.scan_cancel = ol_scan_cancel;
        (*ss)->ss_common.scan_register_event_handler = ol_scan_register_event_handler;
        (*ss)->ss_common.scan_unregister_event_handler = ol_scan_unregister_event_handler;
        (*ss)->ss_common.scan_get_last_scan_info = ol_scan_get_last_scan_info;
        (*ss)->ss_common.scan_channel_list_length = ol_scan_channel_list_length;
        (*ss)->ss_common.scan_update_channel_list = ol_scan_update_channel_list;
        (*ss)->ss_common.scan_scanentry_received = ol_scan_scanentry_received;
        (*ss)->ss_common.scan_get_last_scan_time = ol_scan_get_last_scan_time;
        (*ss)->ss_common.scan_get_last_full_scan_time = ol_scan_get_last_full_scan_time;
        (*ss)->ss_common.scan_connection_lost = ol_scan_connection_lost;
        (*ss)->ss_common.scan_set_default_scan_parameters = ol_scan_set_default_scan_parameters;
        (*ss)->ss_common.scan_get_requestor_id = ol_scan_get_requestor_id;
        (*ss)->ss_common.scan_clear_requestor_id = ol_scan_clear_requestor_id;
        (*ss)->ss_common.scan_get_requestor_name = ol_scan_get_requestor_name;
        (*ss)->ss_common.scan_set_priority = ol_scan_set_priority;
        (*ss)->ss_common.scan_set_forced_flag = ol_scan_set_forced_flag;
        (*ss)->ss_common.scan_get_priority_table = ol_scan_get_priority_table;
        (*ss)->ss_common.scan_set_priority_table = ol_scan_set_priority_table;
        (*ss)->ss_common.scan_enable_scan_scheduler = ol_scan_enable_scan_scheduler;
        (*ss)->ss_common.scan_disable_scan_scheduler = ol_scan_disable_scan_scheduler;
        (*ss)->ss_common.scan_scheduler_get_requests = ol_scan_scheduler_get_requests;

        (*ss)->ss_common.ss_info.si_allow_transmit     = true;
        (*ss)->ss_common.ss_info.si_in_home_channel    = true;

        scn = OL_ATH_SOFTC_NET80211(devhandle);
         /* Register WMI event handlers */
        wmi_unified_register_event_handler(scn->wmi_handle, wmi_scan_event_id,
                                            ol_scan_wmi_event_handler, WMI_RX_UMAC_CTX);
        spin_lock_init(&((*ss)->ss_lock));

        return EOK;

    }

    return ENOMEM;

}

void
ol_ath_scan_attach(struct ieee80211com *ic)
{
    ic->ic_scan_attach = ol_scan_attach;
}

#endif
