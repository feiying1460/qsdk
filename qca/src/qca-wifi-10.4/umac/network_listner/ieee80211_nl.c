/*
 * Copyright (c) 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#if QCA_LTEU_SUPPORT

#include <ieee80211.h>
#include <ieee80211_var.h>
#include <ieee80211_nl.h>

int
ieee80211_init_mu_scan(struct ieee80211com *ic, ieee80211req_mu_scan_t *reqptr)
{
    struct ieee80211_nl_handle *nl_handle = ic->ic_nl_handle;
    int mu_in_progress, scan_in_progress;

    if (!ic->ic_nl_handle) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: MU supported only on NL radio\n", __func__);
        return -EINVAL;
    }

    spin_lock_bh(&nl_handle->mu_lock);
    mu_in_progress = atomic_read(&nl_handle->mu_in_progress);
    scan_in_progress = atomic_read(&nl_handle->scan_in_progress);
    if (mu_in_progress || scan_in_progress) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Currently doing %s %d\n", __func__,
               mu_in_progress ? "MU" : "scan", mu_in_progress ?
               nl_handle->mu_id : nl_handle->scan_id);
        spin_unlock_bh(&nl_handle->mu_lock);
        return -EBUSY;
    }

    atomic_set(&nl_handle->mu_in_progress, 1);
    nl_handle->mu_id = reqptr->mu_req_id;
    nl_handle->mu_channel = reqptr->mu_channel;
    nl_handle->mu_duration = reqptr->mu_duration;
    spin_unlock_bh(&nl_handle->mu_lock);

    return 0;
}

int
ieee80211_mu_scan(struct ieee80211com *ic, ieee80211req_mu_scan_t *reqptr)
{
    struct ieee80211_nl_handle *nl_handle = ic->ic_nl_handle;
    u_int8_t mu_algo_max_val = (1 << MU_MAX_ALGO)-1;
    int retv;

    if ( (reqptr->mu_type == 0) || (reqptr->mu_type > mu_algo_max_val) ||
         (reqptr->mu_duration == 0) ) {
        if ( (reqptr->mu_type == 0) || (reqptr->mu_type > mu_algo_max_val) )
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Invalid value entered for MU algo type %u \n",
                    __func__,reqptr->mu_type);
        else if (reqptr->mu_duration == 0)
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Invalid value entered for MU scan duration %u \n",
                    __func__,reqptr->mu_duration);
        return -EINVAL;
    }

    retv = nl_handle->mu_scan(ic, reqptr->mu_req_id, reqptr->mu_duration,
                              reqptr->mu_type, reqptr->lteu_tx_power,
                              reqptr->mu_rssi_thr_bssid, reqptr->mu_rssi_thr_sta,
                              reqptr->mu_rssi_thr_sc, reqptr->home_plmnid, reqptr->alpha_num_bssid);
    if (retv == -1)
        return -ENOMEM;
    else
        return retv;
}

void
ieee80211_mu_scan_fail(struct ieee80211com *ic)
{
    struct ieee80211_nl_handle *nl_handle = ic->ic_nl_handle;
    atomic_set(&nl_handle->mu_in_progress, 0);
}

int
ieee80211_lteu_config(struct ieee80211com *ic,
                      ieee80211req_lteu_cfg_t *reqptr, u_int32_t wifi_tx_power)
{
    struct ieee80211_nl_handle *nl_handle = ic->ic_nl_handle;

    if (!ic->ic_nl_handle) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: LTEu config supported only on NL radio\n", __func__);
        return -EINVAL;
    }

    if (atomic_read(&nl_handle->mu_in_progress) ||
        atomic_read(&nl_handle->scan_in_progress)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: LTEu config while doing MU/scan\n", __func__);
    }

    if (reqptr->lteu_num_bins >= LTEU_MAX_BINS)
        reqptr->lteu_num_bins = LTEU_MAX_BINS;

    nl_handle->use_gpio_start = reqptr->lteu_gpio_start;

    return nl_handle->lteu_config(ic, reqptr, wifi_tx_power);
}

void
ieee80211_nl_register_handler(struct ieee80211vap *vap,
             void (*mu_handler)(wlan_if_t, struct event_data_mu_rpt *),
             void (*scan_handler)(wlan_if_t, ieee80211_scan_event *, void *))
{
    struct ieee80211_nl_handle *nl_handle = vap->iv_ic->ic_nl_handle;

    spin_lock_bh(&nl_handle->mu_lock);

    if (wlan_scan_register_event_handler(vap, scan_handler, (void *)nl_handle)) {
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: can't register scan handler\n", __func__);
    }
    if (wlan_scan_get_requestor_id(vap, (u_int8_t *)"network_listner", &nl_handle->scanreq)) {
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: can't get scan id\n", __func__);
    }

    if (nl_handle->mu_cb == NULL && nl_handle->mu_cb_arg == NULL) {
        nl_handle->mu_cb = mu_handler;
        nl_handle->mu_cb_arg = vap;
    } else
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: can't register MU handler\n", __func__);

    spin_unlock_bh(&nl_handle->mu_lock);
}

void
ieee80211_nl_unregister_handler(struct ieee80211vap *vap,
             void (*mu_handler)(wlan_if_t, struct event_data_mu_rpt *),
             void (*scan_handler)(wlan_if_t, ieee80211_scan_event *, void *))
{
    struct ieee80211_nl_handle *nl_handle = vap->iv_ic->ic_nl_handle;

    spin_lock_bh(&nl_handle->mu_lock);

    if (nl_handle->mu_cb == mu_handler && nl_handle->mu_cb_arg == vap) {
        nl_handle->mu_cb = NULL;
        nl_handle->mu_cb_arg = NULL;
    } else
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: can't unregister MU handler\n", __func__);

    if (wlan_scan_unregister_event_handler(vap, scan_handler, (void *)nl_handle)) {
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: can't unregister scan handler\n", __func__);
    }
    wlan_scan_clear_requestor_id(vap, nl_handle->scanreq);

    spin_unlock_bh(&nl_handle->mu_lock);
}

int
ieee80211_ap_scan(struct ieee80211com *ic,
                  struct ieee80211vap *vap, ieee80211req_ap_scan_t *reqptr)
{
    struct ieee80211_nl_handle *nl_handle = ic->ic_nl_handle;
    int n_ssid, i;
    ieee80211_ssid ssid_list[IEEE80211_SCAN_MAX_SSID];
    IEEE80211_SCAN_PRIORITY scan_priority;
    u_int32_t channel_list[MAX_SCAN_CHANS];
    ieee80211_scan_params *scan_params;
    int mu_in_progress, scan_in_progress;

    if (!ic->ic_nl_handle) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Scan supported only on NL radio\n", __func__);
        return -EINVAL;
    }

    spin_lock_bh(&nl_handle->mu_lock);
    mu_in_progress = atomic_read(&nl_handle->mu_in_progress);
    scan_in_progress = atomic_read(&nl_handle->scan_in_progress);
    if (mu_in_progress || scan_in_progress) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Currently doing %s %d\n", __func__,
               mu_in_progress ? "MU" : "scan", mu_in_progress ?
               nl_handle->mu_id : nl_handle->scan_id);
        spin_unlock_bh(&nl_handle->mu_lock);
        return -EBUSY;
    }

    atomic_set(&nl_handle->scan_in_progress, 1);
    nl_handle->scan_id = reqptr->scan_req_id;
    spin_unlock_bh(&nl_handle->mu_lock);
    nl_handle->force_vdev_restart = 1;

    scan_params = (ieee80211_scan_params *)OS_MALLOC(ic->ic_osdev,
                                             sizeof(*scan_params), GFP_KERNEL);
    if (scan_params == NULL) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Can't alloc memory for scan id=%d\n", __func__, reqptr->scan_req_id);
        atomic_set(&nl_handle->scan_in_progress, 0);
        return -ENOMEM;
    }
    OS_MEMZERO(scan_params, sizeof(ieee80211_scan_params));
    if (ic->ic_nl_handle) {
        /*
         * Following parameters hard coded to ensure probe requests sent during
         * AP scan are sent with wildcard SSIDs and not with the AP's own SSID
         */
        n_ssid = 1;
        ssid_list[0].len = 0;
    }
    else {
        n_ssid = wlan_get_desired_ssidlist(vap, ssid_list, IEEE80211_SCAN_MAX_SSID);
    }

    wlan_set_default_scan_parameters(vap, scan_params, IEEE80211_M_HOSTAP,
                          true, true, true, true, n_ssid, ssid_list, 0);

    if (reqptr->scan_type == SCAN_ACTIVE)
        scan_params->flags = IEEE80211_SCAN_ACTIVE;
    else
        scan_params->flags = IEEE80211_SCAN_PASSIVE;

    if (reqptr->scan_num_chan) {
        if (reqptr->scan_num_chan > MAX_SCAN_CHANS)
            reqptr->scan_num_chan = MAX_SCAN_CHANS;
        scan_params->num_channels = reqptr->scan_num_chan;
        for (i = 0; i < reqptr->scan_num_chan; i++)
            channel_list[i] = reqptr->scan_channel_list[i];
        scan_params->chan_list = channel_list;
    } else {
        scan_params->flags |= IEEE80211_SCAN_ALLBANDS;
    }

    scan_params->type = IEEE80211_SCAN_FOREGROUND;

    if (reqptr->scan_duration) {
        if (reqptr->scan_type == SCAN_ACTIVE) {
            scan_params->min_dwell_time_active =
                 scan_params->max_dwell_time_active = reqptr->scan_duration;
        } else {
            scan_params->min_dwell_time_passive =
                 scan_params->max_dwell_time_passive = reqptr->scan_duration;
        }
    } else {
        scan_params->min_dwell_time_passive = vap->min_dwell_time_passive;
        scan_params->max_dwell_time_passive = vap->max_dwell_time_passive;
    }

    if (reqptr->scan_repeat_probe_time != (u_int32_t)-1)
        scan_params->repeat_probe_time = reqptr->scan_repeat_probe_time;

    if (reqptr->scan_rest_time != (u_int32_t)-1) {
        scan_params->min_rest_time =
             scan_params->max_rest_time = reqptr->scan_rest_time;
    }

    if (reqptr->scan_idle_time != (u_int32_t)-1)
        scan_params->idle_time = reqptr->scan_idle_time;

    if (reqptr->scan_probe_delay != (u_int32_t)-1)
        scan_params->probe_delay = reqptr->scan_probe_delay;

    scan_priority = IEEE80211_SCAN_PRIORITY_HIGH;

    wlan_scan_table_flush(vap);

    if (wlan_scan_start(vap, scan_params,
        nl_handle->scanreq, scan_priority, &nl_handle->scanid) != 0 ) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Unable to start scan id=%d\n", __func__, reqptr->scan_req_id);
    } else {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Scan started id %d, duration %d, num channels %d, repeat probe %d, "
               "rest %d, idle %d, scan probe %d, channels -", __func__, nl_handle->scan_id,
               reqptr->scan_duration, reqptr->scan_num_chan, reqptr->scan_repeat_probe_time,
               reqptr->scan_rest_time, reqptr->scan_idle_time, reqptr->scan_probe_delay);
        for (i = 0; i < reqptr->scan_num_chan; i++)
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %d", reqptr->scan_channel_list[i]);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ", type %s\n", reqptr->scan_type == SCAN_ACTIVE ? "active" : "passive");
    }

    OS_FREE(scan_params);

    return 0;
}

#endif /* QCA_LTEU_SUPPORT */
