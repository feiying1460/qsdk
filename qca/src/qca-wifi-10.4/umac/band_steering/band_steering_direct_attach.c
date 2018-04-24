/*
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 */

/*
 Band steering module
*/

#include "band_steering_priv.h"
#include <ieee80211_ioctl.h>  /* for ieee80211req_athdbg */
#include <ieee80211_var.h>

#if ATH_BAND_STEERING

#define BS_STA_STATS_UPDATE_INTVL_DEF    500 /* Unit is msecs */

#if !UMAC_SUPPORT_ACL
#error "ACL support must be enabled when band steering is enabled"
#endif /* !UMAC_SUPPORT_ACL */

void ieee80211_bsteering_direct_attach_txrate_update(struct ieee80211com *ic, u_int8_t *macaddress,
                                                     u_int8_t status,
                                                     u_int32_t txrateKbps)
{
    struct ieee80211_node *ni = NULL;
    ni = ieee80211_find_node(&ic->ic_sta, macaddress);
    if(!ni) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Requested STA %02x:%02x:%02x:%02x:%02x:%02x is not "
                "associated\n", __func__, macaddress[0], macaddress[1],
                macaddress[1], macaddress[3], macaddress[4], macaddress[5]);
        return;
    }
    if (ni->ni_stats.ns_last_tx_rate) {
        if (txrateKbps != ni->ni_stats.ns_last_tx_rate) {
            ni->ni_stats.ns_last_tx_rate = txrateKbps;
            ieee80211_bsteering_update_rate(ni, ni->ni_stats.ns_last_tx_rate);
        }
    }
    else {
        ni->ni_stats.ns_last_tx_rate = txrateKbps;
        ieee80211_bsteering_update_rate(ni, ni->ni_stats.ns_last_tx_rate);
    }
    ieee80211_free_node(ni);
    return;
}

/* TBD:- header */
void ieee80211_bsteering_direct_attach_rssi_update(struct ieee80211com *ic, u_int8_t *macaddress,u_int8_t status,int8_t rssi,u_int8_t subtype)
{
    struct ieee80211_node *ni = NULL;

    ni = ieee80211_find_node(&ic->ic_sta, macaddress);

    if(!ni) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Requested STA %02x:%02x:%02x:%02x:%02x:%02x is not "
               "associated\n", __func__, macaddress[0], macaddress[1],
               macaddress[1], macaddress[3], macaddress[4], macaddress[5]);
        return ;
    }
    if ((subtype != IEEE80211_FC0_SUBTYPE_NODATA) && (subtype != IEEE80211_FC0_SUBTYPE_QOS_NULL)){
        ieee80211_bsteering_record_rssi(ni,rssi);
    }else{
        if(status) /* is it okay to differntiate based on status ? TBD :test to find out */
            ieee80211_bsteering_record_inst_rssi(ni,rssi);
        else
            ieee80211_bsteering_record_inst_rssi_err(ni);
    }
    ieee80211_free_node(ni);
    return;
}
void wlan_bsteering_send_null(struct ieee80211com *ic,u_int8_t *macaddr,struct ieee80211vap *vap)
{
    struct ieee80211_node *ni;

    ni = ieee80211_find_node(&ic->ic_sta, macaddr);

    if(!ni || ni->ni_ic->ic_is_mode_offload(ni->ni_ic))
        return;

    ni->ni_ext_flags |= IEEE80211_NODE_BSTEERING_CAPABLE;
    if((ni->ni_flags & IEEE80211_NODE_QOS))
        ieee80211_send_qosnulldata(ni,WME_AC_VI,false);
    else
        ieee80211_send_nulldata(ni,false);

    ni->ni_ext_flags &= ~IEEE80211_NODE_BSTEERING_CAPABLE;
    ieee80211_free_node(ni);

    return;

}
/**
 * @brief Timeout handler for inactivity timer. Decrease node's inactivity count by 1.
 *        If any node's inactivity count reaches 0, generate an event
 *
 * @param [in] arg  ieee80211com
 *
 */
static OS_TIMER_FUNC(wlan_bsteering_inact_timeout_handler)
{
    struct ieee80211com *ic;
    struct ieee80211_node *ni;
    OS_GET_TIMER_ARG(ic, struct ieee80211com *);

    OS_RWLOCK_READ_LOCK(&ic->ic_sta.nt_nodelock, &lock_state);
    TAILQ_FOREACH(ni, &ic->ic_sta.nt_node, ni_list) {
        if (!(ni->ni_flags & IEEE80211_NODE_AUTH) ||
            !ieee80211_bsteering_is_vap_enabled(ni->ni_vap)) {
            /* Inactivity check only interested in connected node */
            continue;
        }
        if (ni->ni_bs_inact > ni->ni_bs_inact_reload) {
            /* This check ensures we do not wait extra long
               due to the potential race condition */
            ni->ni_bs_inact = ni->ni_bs_inact_reload;
        }
        if (ni->ni_bs_inact > 0) {
            /* Do not let it go negative */
            ni->ni_bs_inact--;
        }
        if (ni->ni_bs_inact == 0) {
            /* Mark the node as inactive */
            ieee80211_bsteering_mark_node_bs_inact(ni, true);
        }
    }
    OS_RWLOCK_READ_UNLOCK(&ic->ic_sta.nt_nodelock, &lock_state);
    OS_SET_TIMER(&(ic->ic_bsteering->bs_inact_timer),
                 ic->ic_bsteering->bs_config_params.inactivity_check_period * 1000);
}

static OS_TIMER_FUNC(wlan_bsteering_interference_stats_event_handler)
{
    struct ieee80211com *ic;
    struct ieee80211_node *ni;
    u_int32_t txrate;
    struct bs_sta_stats_ind sta_stats;
    struct ieee80211vap *current_vap = NULL;
    bool rssi_changed = false;
    sta_stats.peer_count = 0;

    OS_GET_TIMER_ARG(ic, struct ieee80211com *);
    OS_RWLOCK_READ_LOCK(&ic->ic_sta.nt_nodelock, &lock_state);

    TAILQ_FOREACH(ni, &ic->ic_sta.nt_node, ni_list) {
        rssi_changed = false;
        if (!(ni->ni_flags & IEEE80211_NODE_AUTH) ||
            !ieee80211_bsteering_is_vap_enabled(ni->ni_vap)) {
            continue;
        }
        txrate = ni->ni_ic->ic_node_getrate(ni, IEEE80211_LASTRATE_TX);
        if (!(ni->ni_last_rssi))
            ni->ni_last_rssi = ni->ni_rssi;

        if (ni->ni_rssi != ni->ni_last_rssi) {
            ni->ni_last_rssi = ni->ni_rssi;
            rssi_changed = true;
        }
        /* TBD: Why ni->ni_stats.ns_last_tx_rate is not equal to value retrieved from an */
        if (ni->ni_stats.ns_last_tx_rate != txrate)
            ni->ni_stats.ns_last_tx_rate = txrate;

        if (rssi_changed && ni->ni_stats.ns_last_tx_rate) {
            if (ieee80211_bsteering_update_sta_stats(ni, current_vap, &sta_stats)) {
                current_vap = ni->ni_vap;
            }
        }
    }
    if (current_vap && (sta_stats.peer_count != 0)) {
        ieee80211_bsteering_send_sta_stats(current_vap, &sta_stats);
    }
    OS_RWLOCK_READ_UNLOCK(&ic->ic_sta.nt_nodelock, &lock_state);

    OS_SET_TIMER(&(ic->ic_bsteering->bs_interference_stats_timer),
                   ic->ic_bsteering->sta_stats_update_interval_da);
}

void wlan_bsteering_set_overload_param(struct ieee80211com *ic,bool overload)
{
    ieee80211_bsteering_t bsteering = NULL;

    bsteering = ic->ic_bsteering;

    wlan_bsteering_update_inact_threshold(ic, bsteering->bs_vap_overload ?
                                              bsteering->bs_inact_overload :
                                              bsteering->bs_inact);
    /* overload is unused to silence compiler */
    overload = overload ;
    return;
}
bool wlan_bsteering_direct_attach_enable(struct ieee80211com *ic,bool enable)
{
    ieee80211_bsteering_t bsteering = NULL;

    if(!ic)
        return false;

    if(ic->ic_is_mode_offload(ic))
        return false;

    bsteering = ic->ic_bsteering;
    if (!(bsteering->sta_stats_update_interval_da))
        bsteering->sta_stats_update_interval_da = BS_STA_STATS_UPDATE_INTVL_DEF;

    if(enable) {
        wlan_bsteering_reset_inact_count(ic);
        /* Start inactivity timer */
        OS_SET_TIMER(&bsteering->bs_inact_timer,
                     bsteering->bs_config_params.inactivity_check_period * 1000);
        OS_SET_TIMER(&bsteering->bs_interference_stats_timer,
                      bsteering->sta_stats_update_interval_da);
    } else {
        OS_CANCEL_TIMER(&bsteering->bs_inact_timer);
        OS_CANCEL_TIMER(&bsteering->bs_interference_stats_timer);
    }

    return true;
}

bool
wlan_bsteering_set_inact_params(struct ieee80211com *ic,
                                u_int16_t inact_check_interval,
                                u_int16_t inact_normal,
                                u_int16_t inact_overload)
{
    ieee80211_bsteering_t bsteering = NULL;

    bsteering = ic->ic_bsteering;

    bsteering->bs_inact = (bsteering->bs_config_params.inactivity_timeout_normal /
                           bsteering->bs_config_params.inactivity_check_period);

    bsteering->bs_inact_overload = (bsteering->bs_config_params.inactivity_timeout_overload /
                                    bsteering->bs_config_params.inactivity_check_period);

    return (wlan_bsteering_update_inact_threshold(ic, bsteering->bs_inact));

}

 /**
  * @brief Update the VAP's inactivity threshold. It will also update the
  *        inactivity count of all nodes associated with AP VAPs on this radio
  *        where band steering is enabled.
  *
  * When this is done during bsteering is enabled, it will check the remaining
  * inactivity count, and generate an event if it has been inactive longer than
  * the new threshold. When bsteering is not enabled, it will just update
  * threshold.
  *
  * @pre vap is valid and the band steering handle has already been validated
  *
  * @param [inout] vap  the VAP to be updated
  * @param [in] new_threshold  the new inactivity threshold
  */

bool wlan_bsteering_update_inact_threshold(struct ieee80211com *ic,
                                           u_int32_t new_threshold)
{
    struct ieee80211_node *ni;

    u_int16_t old_threshold;

    if(!ic)
        return false;


    old_threshold = ic->ic_bs_inact;

    if (old_threshold == new_threshold) {
        return true;
    }

    ic->ic_bs_inact = new_threshold;

    OS_RWLOCK_READ_LOCK(&ic->ic_sta.nt_nodelock, &lock_state);
    TAILQ_FOREACH(ni, &ic->ic_sta.nt_node, ni_list) {
        if (!(ni->ni_flags & IEEE80211_NODE_AUTH) ||
            !ieee80211_bsteering_is_vap_enabled(ni->ni_vap)) {
            /* Inactivity check only interested in connected node where band
               steering is enabled on the VAP. */
            continue;
        }

        if (ieee80211_bsteering_is_enabled(ic)) {
            if (ni->ni_bs_inact_reload - ni->ni_bs_inact >= ic->ic_bs_inact) {
                ieee80211_bsteering_mark_node_bs_inact(ni, true /* inactive */);
                ni->ni_bs_inact = 0;
            } else {
                ni->ni_bs_inact = ic->ic_bs_inact -
                    (ni->ni_bs_inact_reload - ni->ni_bs_inact);
            }
        }
        ni->ni_bs_inact_reload = ic->ic_bs_inact;
    }
    OS_RWLOCK_READ_UNLOCK(&ic->ic_sta.nt_nodelock, &lock_state);

    return true;
}

/**
 * @brief Reset the inactivity count of all nodes on a band steering enabled
 *        VAP on the provided radio.
 *
 * @pre ic is valid and the band steering handle has already been validated
 *
 * @param [in] ic  the radio whose associated nodes to be updated
 */

void wlan_bsteering_reset_inact_count(struct ieee80211com *ic)
{
    struct ieee80211_node *ni;

    OS_RWLOCK_READ_LOCK(&ic->ic_sta.nt_nodelock, &lock_state);
    TAILQ_FOREACH(ni, &ic->ic_sta.nt_node, ni_list) {
        if (!(ni->ni_flags & IEEE80211_NODE_AUTH) ||
            !ieee80211_bsteering_is_vap_enabled(ni->ni_vap)) {
            /* Inactivity check only interested in connected node on VAPs
               where band steering is enabled.*/
            continue;
        }
        ni->ni_bs_inact = ni->ni_bs_inact_reload;
    }
    OS_RWLOCK_READ_UNLOCK(&ic->ic_sta.nt_nodelock, &lock_state);
}

int ieee80211_bsteering_direct_attach_create(struct ieee80211com *ic)
{

    ieee80211_bsteering_t bsteering = NULL;

    if(!ic)
        return ENOMEM;

    bsteering = ic->ic_bsteering;

    if(!ic->ic_is_mode_offload(ic)) {
        /* Initialize inactivity timer */
        OS_INIT_TIMER(bsteering->bs_osdev, &bsteering->bs_inact_timer,
                      wlan_bsteering_inact_timeout_handler, (void *) ic, QDF_TIMER_TYPE_WAKE_APPS);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "band steering initialized for direct attach hardware \n");
        OS_INIT_TIMER(bsteering->bs_osdev, &bsteering->bs_interference_stats_timer,
                      wlan_bsteering_interference_stats_event_handler, (void *) ic, QDF_TIMER_TYPE_WAKE_APPS);
    }
    return EOK;
}

int ieee80211_bsteering_direct_attach_destroy(struct ieee80211com *ic)
{
    ieee80211_bsteering_t bsteering = NULL;

   if(!ic)
        return ENOMEM;

    bsteering = ic->ic_bsteering;

    if(!ic->ic_is_mode_offload(ic)) {
        OS_FREE_TIMER(&bsteering->bs_inact_timer);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "band steering terminated  for direct attach hardware \n");
        OS_FREE_TIMER(&bsteering->bs_interference_stats_timer);
    }

    return EOK;

}

/**
 * @brief to send inactive event per node to user space daemon
 *
 * @param
 *
 * @return void
 *
 */

void ieee80211_bsteering_mark_node_bs_inact(struct ieee80211_node *ni, bool inactive)
{
    bool inactive_old = ni->ni_bs_inact_flag;

    if (!ieee80211_bsteering_is_enabled(ni->ni_ic)) {
        return;
    }

    if(!ieee80211_bsteering_is_vap_enabled(ni->ni_vap)) {
        return ;
    }

    if (!inactive) {
        ni->ni_bs_inact = ni->ni_bs_inact_reload;
    }

    ni->ni_bs_inact_flag = inactive;

    if (inactive_old != inactive) {
        ieee80211_bsteering_send_activity_change_event(ni->ni_vap,
                                                       ni->ni_macaddr, !inactive);
    }
}

/**
 * @brief Module to get instant channel laod for direct attach architecture
 * @note This is used only for direct attach hardware as failure frequency is high on direct attach
 *
 * @param [in] vap  the current VAP being considered
 */

void wlan_instant_channel_load(struct ieee80211vap *vap)
{
    struct ieee80211_chan_stats chan_stats;
    u_int32_t tmpcnt = 0,load = 0;
    ieee80211_bsteering_t bsteering = NULL;

    if (!ieee80211_bsteering_is_enabled(vap->iv_ic)) {
        return;
    }

    if(!ieee80211_bsteering_is_vap_enabled(vap)) {
        return ;
    }

    bsteering = vap->iv_ic->ic_bsteering;

    vap->iv_ic->ic_get_cur_chan_stats(vap->iv_ic, &chan_stats);
    tmpcnt = chan_stats.cycle_cnt/100;

    if(tmpcnt)
        load = chan_stats.chan_clr_cnt/tmpcnt;

    load = MIN(MAX(1,load),100);
    bsteering->bs_chan_util_requested = true;
    ieee80211_bsteering_record_utilization(vap, bsteering->bs_active_ieee_chan_num ,load);
    return;
}
#endif
