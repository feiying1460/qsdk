/*
 *  Copyright (c) 2008 Atheros Communications Inc.
 * All Rights Reserved.
 *
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#include <osdep.h>

#include <ieee80211_var.h>
#include <ieee80211_api.h>
#include <ieee80211_channel.h>
#include <ieee80211_rateset.h>
#include <ieee80211_dfs.h>
#include <ieee80211_defines.h>
#ifdef ATH_HTC_MII_RXIN_TASKLET
#include "htc_thread.h"
#endif
#include <if_smart_ant.h>
#include "ieee80211_sme_api.h"


/* XXX tunables */
#define AGGRESSIVE_MODE_SWITCH_HYSTERESIS   3   /* pkts / 100ms */
#define HIGH_PRI_SWITCH_THRESH              10  /* pkts / 100ms */

#define IEEE80211_VAP_STATE_LOCK_INIT(_vap)       spin_lock_init(&(_vap)->iv_state_info.iv_state_lock)
#define IEEE80211_VAP_STATE_LOCK(_vap)            spin_lock(&(_vap)->iv_state_info.iv_state_lock)
#define IEEE80211_VAP_STATE_UNLOCK(_vap)          spin_unlock(&(_vap)->iv_state_info.iv_state_lock)
#define IEEE80211_VAP_STATE_LOCK_DESTROY(_vap)         spin_lock_destroy(&(_vap)->iv_state_info.iv_state_lock)

const char *ieee80211_state_name[IEEE80211_S_MAX] = {
    "INIT",     /* IEEE80211_S_INIT */
    "SCAN",
    "JOIN",     /* IEEE80211_S_JOIN */
    "AUTH",
    "ASSOC",
    "RUN",       /* IEEE80211_S_RUN */
    "DFS_WAIT",
    "WAIT_TXDONE", /* IEEE80211_S_WAIT_TXDONE */
    "STOPPING",
    "STANDBY"
};

const char *ieee80211_mgt_subtype_name[] = {
    "assoc_req",    "assoc_resp",   "reassoc_req",  "reassoc_resp",
    "probe_req",    "probe_resp",   "reserved#6",   "reserved#7",
    "beacon",       "atim",         "disassoc",     "auth",
    "deauth",       "action",       "reserved#14",  "reserved#15"
};


const char *ieee80211_wme_acnames[] = {
    "WME_AC_BE",
    "WME_AC_BK",
    "WME_AC_VI",
    "WME_AC_VO",
    "WME_UPSD"
};

int ieee80211_state_event(struct ieee80211vap *vap, enum ieee80211_state_event event);

static void ieee80211_vap_scan_event_handler(struct ieee80211vap *originator, ieee80211_scan_event *event, void *arg)
{
    struct ieee80211vap *vap = (struct ieee80211vap *) arg;

    /*
     * Ignore notifications received due to scans requested by other modules.
     */
    if (vap != originator) {
        return;
    }
    /* Ignore offchan scan as it doesn't change the state */
    if(vap->offchan_requestor == event->requestor) {
        return;
    }
    /* Ignore acs scan report */
    if(wlan_get_param(vap, IEEE80211_START_ACS_REPORT)) {
        return;
    }

    switch(event->type) {
     case IEEE80211_SCAN_STARTED:
         IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE,
                           "%s: orig=%08p vap=%08p scan_id %d event %d reason %d\n",
                           __func__,
                           originator, vap,
                           event->scan_id, event->type, event->reason);

         ieee80211_state_event(vap, IEEE80211_STATE_EVENT_SCAN_START);
         break;
     case IEEE80211_SCAN_COMPLETED:
     case IEEE80211_SCAN_DEQUEUED:
         IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE,
                           "%s: orig=%08p vap=%08p scan_id %d event %d reason %d\n",
                           __func__,
                           originator, vap,
                           event->scan_id, event->type, event->reason);
#ifdef QCA_PARTNER_PLATFORM		 
         vap->iv_list_scanning = 0;
#endif
         ieee80211_state_event(vap, IEEE80211_STATE_EVENT_SCAN_END);
         break;
    default:
         break;
    }
}


void
ieee80211_proto_attach(struct ieee80211com *ic)
{
    ic->ic_protmode = IEEE80211_PROT_CTSONLY;

    ic->ic_wme.wme_hipri_switch_hysteresis =
        AGGRESSIVE_MODE_SWITCH_HYSTERESIS;

    ATH_HTC_NETDEFERFN_INIT(ic);


#if 0  /* XXX TODO */
    ieee80211_auth_setup();
#endif
}

void
ieee80211_proto_detach(struct ieee80211com *ic)
{

    ATH_HTC_NETDEFERFN_CLEANUP(ic);
}

void ieee80211_proto_vattach(struct ieee80211vap *vap)
{
    int    rc;

    vap->iv_rtsthreshold = IEEE80211_RTS_MAX;
    vap->iv_fragthreshold = IEEE80211_FRAGMT_THRESHOLD_MAX;
    vap->iv_fixed_rate.mode = IEEE80211_FIXED_RATE_NONE;

    IEEE80211_VAP_STATE_LOCK_INIT(vap);

    vap->iv_state_info.iv_state = IEEE80211_S_INIT;
    rc = wlan_scan_register_event_handler(vap, ieee80211_vap_scan_event_handler,(void *) vap);
    if (rc != EOK) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
                          "%s: wlan_scan_register_event_handler() failed handler=%08p,%08p rc=%08X\n",
                          __func__, ieee80211_vap_scan_event_handler, vap, rc);
    }
}

void
ieee80211_proto_vdetach(struct ieee80211vap *vap)
{
    int    rc;

    rc = wlan_scan_unregister_event_handler(vap, ieee80211_vap_scan_event_handler,(void *) vap);
    if (rc != EOK) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
                          "%s: wlan_scan_unregister_event_handler() failed handler=%08p,%08p rc=%08X\n",
                          __func__, ieee80211_vap_scan_event_handler, vap, rc);
    }
    IEEE80211_VAP_STATE_LOCK_DESTROY(vap);
}

void get_sta_mode_vap(void *arg, struct ieee80211vap *vap)
{
    ieee80211_vap_t *ppvap=(ieee80211_vap_t *)arg;

    if (IEEE80211_M_STA == vap->iv_opmode) {
        *ppvap = vap;
    }
}

/*
 * event handler for the vap state machine.
 */
int
ieee80211_state_event(struct ieee80211vap *vap, enum ieee80211_state_event event)
{
    enum ieee80211_state cur_state;
    enum ieee80211_state nstate;
    struct ieee80211com *ic = vap->iv_ic;
    ieee80211_vap_event evt;
    u_int32_t           vap_node_count = 0;
    bool                deleteVap = FALSE;
    bool                deliver_stop_event = TRUE;
#if UNIFIED_SMARTANTENNA
    int                 nacvaps = 0;
#endif
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE,
                      "%s: VAP state event %d, cur_state=%d, vap_deleted_is_set=%d\n",
                      __func__, event, vap->iv_state_info.iv_state, ieee80211_vap_deleted_is_set(vap));

    /*
     * Provide synchronization on vap state change.
     * Cannot guarantee the final vap state to be requested state.
     * Caller is responsible for state change serialization.
     */

    /*
     * Temp workaround before resource manager control ic state change.
     * For now, ic/sc state is also being changed in this thread context.
     * We need to synchronize ic/sc state change across vaps.
     * TBD: resource manager should keep its own vap states and flags
     * (active, ready ...etc) and change ic/sc state accordingly.
     * Restore IEEE80211_VAP_STATE_LOCK after it is done.
     */
    //IEEE80211_VAP_STATE_LOCK(vap);
    IEEE80211_STATE_LOCK(ic);
    /*
     * reentrancy check to catch any cases of reentrancy.
    */
    if(vap->iv_state_info.iv_sm_running) {
      ieee80211com_note(ic, IEEE80211_MSG_STATE,
           "Warning: Can not reenter VAP State Machine vap %d \n", vap->iv_unit);
    }
    vap->iv_state_info.iv_sm_running = true;

    cur_state =(enum ieee80211_state)vap->iv_state_info.iv_state;
    nstate = cur_state;

    /*
     * Preprocess of the event.
     */
    switch(event) {
        case IEEE80211_STATE_EVENT_RESUME:
            if (cur_state != IEEE80211_S_STANDBY) {
                evt.type = IEEE80211_VAP_RESUMED;
                ieee80211_vap_deliver_event(vap, &evt);
            }
            break;

        case IEEE80211_STATE_EVENT_FORCE_STOP:
            /*
             * Caller is responsible for cleaning up node and data queues.
             */
            nstate = IEEE80211_S_INIT;
            break;

        case IEEE80211_STATE_EVENT_BSS_NODE_FREED:
            /* Multiple threads can try to remove the node count. */
            IEEE80211_VAP_LOCK(vap);
            vap_node_count = (--vap->iv_node_count);
            IEEE80211_VAP_UNLOCK(vap);
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE,
           "%s: VAP EVENT_NODE_FREED node count %d \n", __func__,vap_node_count);
            break;

        default:
            break;
    }

#if ATH_ANT_DIV_COMB
    vap->iv_sa_normal_scan_handle(vap, event);
#endif

    /*
     * main event handler switch statement.
     */

    switch(cur_state) {

    case IEEE80211_S_INIT:
        switch(event) {
           case IEEE80211_STATE_EVENT_JOIN:
               nstate = IEEE80211_S_JOIN;
               break;
           case IEEE80211_STATE_EVENT_SCAN_START:
               nstate = IEEE80211_S_SCAN;
               break;
           case IEEE80211_STATE_EVENT_BSS_NODE_FREED:
                if (vap_node_count == 1 &&
                    (!ieee80211_vap_deleted_is_set(vap))) {
                    if (ieee80211_vap_standby_is_set(vap)) {
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE,
                                "ieee80211_vap_standby_is_set is true\n");
                        vap->iv_state_info.iv_sm_running = false;
                        IEEE80211_STATE_UNLOCK(ic);
                        ASSERT(0);
                        return -1;
                    }
                    IEEE80211COM_DELIVER_VAP_EVENT(vap->iv_ic, vap->iv_ifp, IEEE80211_VAP_STOPPED);
                } else if (vap_node_count == 0) {

                    if (ieee80211_vap_deleted_is_clear(vap)) {
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE,
                                "ieee80211_vap_deleted_is_clear is true\n");
                        vap->iv_state_info.iv_sm_running = false;
                        IEEE80211_STATE_UNLOCK(ic);
                        ASSERT(0);
                        return -1;
                    }
                    /* Last node, delete vap. */
                    deleteVap = TRUE;
                }
                break;
           case IEEE80211_STATE_EVENT_DFS_WAIT:
             nstate = IEEE80211_S_DFS_WAIT;
             break;
	   case IEEE80211_STATE_EVENT_CHAN_SET:
              vap->iv_state_info.iv_sm_running = false;
              IEEE80211_STATE_UNLOCK(ic);
               return 0;
               break;
           default:
               break;
        }
        break;
    case IEEE80211_S_SCAN:
        switch(event) {
           case IEEE80211_STATE_EVENT_UP:
               nstate = IEEE80211_S_RUN;
               break;
           case IEEE80211_STATE_EVENT_JOIN:
               nstate = IEEE80211_S_JOIN;
               break;
           case IEEE80211_STATE_EVENT_SCAN_END:
               nstate = IEEE80211_S_INIT;
               break;
           case IEEE80211_STATE_EVENT_DFS_CLEAR:
               nstate = IEEE80211_S_RUN;
             break;
           case IEEE80211_STATE_EVENT_DFS_WAIT:
             nstate = IEEE80211_S_DFS_WAIT;
             break;
	   case IEEE80211_STATE_EVENT_CHAN_SET:
               vap->iv_state_info.iv_sm_running = false;
               IEEE80211_STATE_UNLOCK(ic);
               return 0;
               break;
           default:
               break;
        }
        break;
    /*
     * If the caller is not blocked and waiting for bss to be stopped,
     * this state can be viewed as INIT state by the caller.
     * We should allow caller to put VAP in any state.
     */
    case IEEE80211_S_STOPPING:
        switch(event) {
           case IEEE80211_STATE_EVENT_UP:
               if (!ieee80211_vap_standby_is_set(vap))
                   nstate = IEEE80211_S_RUN;
               break;
           case IEEE80211_STATE_EVENT_JOIN:
               if (!ieee80211_vap_standby_is_set(vap))
                   nstate = IEEE80211_S_JOIN;
               break;
           case IEEE80211_STATE_EVENT_SCAN_START:
               if (!ieee80211_vap_standby_is_set(vap))
                   nstate = IEEE80211_S_SCAN;
               break;
           case IEEE80211_STATE_EVENT_DOWN:
               ieee80211_vap_standby_clear(vap);
               break;
           case IEEE80211_STATE_EVENT_BSS_NODE_FREED:
                if (vap_node_count == 1 &&
                    (!ieee80211_vap_deleted_is_set(vap))) {
                    if (ieee80211_vap_standby_is_set(vap)) {
                        nstate = IEEE80211_S_STANDBY;
                    } else {
                        nstate = IEEE80211_S_INIT;
                    }
                } else if (vap_node_count == 0) {
                    if (ieee80211_vap_deleted_is_clear(vap)) {
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE,
                                "ieee80211_vap_deleted_is_clear is true \n");
                        vap->iv_state_info.iv_sm_running = false;
                        IEEE80211_STATE_UNLOCK(ic);
                        ASSERT(0);
                        return -1;
                    }
                    /* Last node, delete vap. */
                    deleteVap = TRUE;
                    nstate = IEEE80211_S_INIT;
                }
                break;
           case IEEE80211_STATE_EVENT_CHAN_SET:
               vap->iv_state_info.iv_sm_running = false;
               IEEE80211_STATE_UNLOCK(ic);
               return 0;
               break;
           default:
               break;
        }
        break;
    case IEEE80211_S_JOIN:
        switch(event) {
           case IEEE80211_STATE_EVENT_UP:
               nstate = IEEE80211_S_RUN;
               break;
           case IEEE80211_STATE_EVENT_DOWN:
               nstate = IEEE80211_S_STOPPING;
               break;
           case IEEE80211_STATE_EVENT_DFS_CLEAR:
               nstate = IEEE80211_S_RUN;
             break;
           case IEEE80211_STATE_EVENT_DFS_WAIT:
             nstate = IEEE80211_S_DFS_WAIT;
             break;
	   case IEEE80211_STATE_EVENT_CHAN_SET:
               vap->iv_state_info.iv_sm_running = false;
               IEEE80211_STATE_UNLOCK(ic);
               return 0;
               break;
           case IEEE80211_STATE_EVENT_RESTART_REQ:
               nstate = IEEE80211_S_INIT;
               break;
           default:
               break;
        }
        break;
    case IEEE80211_S_RUN:
        switch(event) {
           case IEEE80211_STATE_EVENT_JOIN:
               nstate = IEEE80211_S_JOIN;
               break;
           case IEEE80211_STATE_EVENT_STANDBY:
               ieee80211_vap_standby_set(vap);
               nstate = IEEE80211_S_STOPPING;
               break;
           case IEEE80211_STATE_EVENT_DOWN:
               nstate = IEEE80211_S_STOPPING;
               break;
           case IEEE80211_STATE_EVENT_DFS_WAIT:
               nstate = IEEE80211_S_DFS_WAIT;
               break;
           case IEEE80211_STATE_EVENT_DFS_CLEAR:
               nstate = IEEE80211_S_RUN;
               break;
           case IEEE80211_STATE_EVENT_CHAN_SET:
               vap->iv_state_info.iv_sm_running = false;
               IEEE80211_STATE_UNLOCK(ic);
               return 0;
               break;
           case IEEE80211_STATE_EVENT_SCAN_END:
           case IEEE80211_STATE_EVENT_SCAN_START:
               vap->iv_state_info.iv_sm_running = false;
               IEEE80211_STATE_UNLOCK(ic);
               return 0;
               break;
#if UMAC_REPEATER_DELAYED_BRINGUP
           case IEEE80211_STATE_EVENT_HANDSHAKE_FINISH:
               if (!wlan_get_param(vap, IEEE80211_FEATURE_VAP_ENHIND))
               {
                   wlan_dev_t comhandle = wlan_vap_get_devhandle(vap);
                   /*it would be better handled by adding one more state in sta state machine
                   but right now to avoid it we are calling this directly from here
                   */
                   osif_check_pending_ap_vaps(comhandle, vap);
                   vap->iv_state_info.iv_sm_running = false;
                   IEEE80211_STATE_UNLOCK(ic);
                   return 0;
               }
               break;
#endif			
           case IEEE80211_STATE_EVENT_RESTART_REQ:
                   nstate = IEEE80211_S_INIT;
               break;
           default:
               break;
        }
	break;
    case IEEE80211_S_DFS_WAIT:
	switch(event) {
	case IEEE80211_STATE_EVENT_JOIN:
	    nstate = cur_state;
	    break;
	case IEEE80211_STATE_EVENT_UP:
	    nstate = IEEE80211_S_RUN;
	    break;
	case IEEE80211_STATE_EVENT_DFS_CLEAR:
	    nstate = IEEE80211_S_RUN;
	    break;
	case IEEE80211_STATE_EVENT_DOWN:
	    nstate = IEEE80211_S_STOPPING;
	    break;
	case IEEE80211_STATE_EVENT_CHAN_SET:
	    nstate = IEEE80211_S_INIT;
	    break;
        case IEEE80211_STATE_EVENT_RESTART_REQ:
            nstate = IEEE80211_S_INIT;
            break;
	default:
	    break;
        }
	break;

    case IEEE80211_S_AUTH:
    case IEEE80211_S_ASSOC:
        break;
    case IEEE80211_S_STANDBY:
        switch(event) {
           case IEEE80211_STATE_EVENT_UP:
               nstate = IEEE80211_S_RUN;
               break;
           case IEEE80211_STATE_EVENT_DOWN:
               nstate = IEEE80211_S_INIT;
               break;
	   case IEEE80211_STATE_EVENT_CHAN_SET:
               vap->iv_state_info.iv_sm_running = false;
               IEEE80211_STATE_UNLOCK(ic);
               return 0;
               break;
           case IEEE80211_STATE_EVENT_RESTART_REQ:
               nstate = IEEE80211_S_INIT;
               break;
           default:
               break;
        }
        break;
    default:
        break;
    }
#if ATH_BAND_STEERING
    if(nstate == IEEE80211_S_DFS_WAIT) {
        IEEE80211_DELIVER_EVENT_CHANNEL_CHANGE(vap, vap->iv_ic->ic_curchan);
    } else if((cur_state != IEEE80211_S_DFS_WAIT ) && (nstate == IEEE80211_S_RUN)) {
        IEEE80211_DELIVER_EVENT_CHANNEL_CHANGE(vap, vap->iv_ic->ic_curchan);
    }
#endif
    /*
     * allow RUN to RUN state transition for IBSS mode .
     */
    if ( nstate == cur_state && !(ic->ic_opmode == IEEE80211_M_IBSS && nstate == IEEE80211_S_RUN)) {
        vap->iv_state_info.iv_sm_running = false;
        IEEE80211_STATE_UNLOCK(ic);
        if (deleteVap) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE, "%s: VAP state transition %s -> %s vap_free \n", __func__,
                      ieee80211_state_name[cur_state],
                      ieee80211_state_name[nstate]);
            ieee80211_vap_free(vap);
        }
        return 0;
    }

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE,
                      "%s: VAP state transition %s -> %s \n", __func__,
                      ieee80211_state_name[cur_state],
                      ieee80211_state_name[nstate]);

    /*
     * exit action for the current state.
     */
    switch(cur_state) {
        /*
         * send vap power  state info to the resource  manager and other registred handlers.
         * if resource manager is not compiled in, then directly change the chip power state.
         * from INIT --> * we need to generrate events before we handle the action for each state.
         *  so that resource manager can enable th HW before vap executes.
         */
    case IEEE80211_S_INIT:
        evt.type = IEEE80211_VAP_ACTIVE;
        ieee80211_vap_deliver_event(vap, &evt);
        break;
    case IEEE80211_S_RUN:
        if ((nstate != IEEE80211_S_RUN) && (event != IEEE80211_STATE_EVENT_RESTART_REQ)) {
            /* from RUN -> others , back to active*/
            ieee80211_vap_ready_clear(vap);
            evt.type = IEEE80211_VAP_DOWN;
            ieee80211_vap_deliver_event(vap, &evt);
#if UMAC_SUPPORT_VAP_PAUSE
            ieee80211_vap_pause_reset(vap);    /* Reset VAP pause counters/state */
#endif
        }
        break;
    default:
        break;

    }

    /*
     * entry action for each state .
     */
    switch(nstate) {
    case IEEE80211_S_STANDBY:
        ieee80211_vap_standby_clear(vap);
        if (ieee80211_vap_dfswait_is_set(vap))
            ieee80211_dfs_cac_stop(vap, 0);
        ieee80211_vap_dfswait_clear(vap);
        /*
         * fall through.
         * ready, active, scanning...etc flags need to be cleared
         * iv_down needs to be called.
         */
    case IEEE80211_S_INIT:
        if (event == IEEE80211_STATE_EVENT_FORCE_STOP &&
            cur_state != IEEE80211_S_STOPPING) {
            /*
             * This is a forced stop. We need to call stopping first
             * to release beacon resource.
             */
            IEEE80211_STATE_UNLOCK(ic);
            if (vap->iv_stopping(vap) != EOK) {
              IEEE80211COM_DELIVER_VAP_EVENT(vap->iv_ic, vap->iv_ifp, IEEE80211_VAP_STOP_ERROR);
            }
            IEEE80211_STATE_LOCK(ic);
            /*
             * Deliver the event in non-offload(direct-attach) case.
             * For offload driver, the event is given after the firmware's response.
             */
            deliver_stop_event = IEEE80211COM_IS_SYNCRONOUS(ic);
        }

        if (cur_state != IEEE80211_S_STANDBY) {
            if (ieee80211_vap_standby_is_set(vap)) {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE,
                        "ieee80211_vap_standby_is_set is true\n");
                    vap->iv_state_info.iv_sm_running = false;
                    IEEE80211_STATE_UNLOCK(ic);
                    ASSERT(0);
                    return -1;
                    }
            ieee80211_vap_ready_clear(vap);
            ieee80211_vap_active_clear(vap);
            ieee80211_vap_scanning_clear(vap);
            if(event != IEEE80211_STATE_EVENT_RESTART_REQ) {
                vap->iv_down(vap);
            }
#if UNIFIED_SMARTANTENNA
            if ((vap->iv_opmode == IEEE80211_M_STA) && (ic->vap_down_in_progress == FALSE) &&
                       (ic->sta_not_connected_cfg == FALSE)) {
                /* When STA disconnects from AP, Re initialise smart antenna with default
                 * settings to help scanning. If vap down is already in progress, no need to
                 * Re initialize smart antenna here. It will be de initialized in
                 * osif_vap_stop().
                 */
                ieee80211_smart_ant_deinit(ic, vap, SMART_ANT_RECONFIGURE);
                ieee80211_smart_ant_init(ic, vap, SMART_ANT_STA_NOT_CONNECTED | SMART_ANT_RECONFIGURE);
                ic->sta_not_connected_cfg = TRUE;
            }
#endif
        }

        /*
         * from *(Active) --> INIT we need to generrate events after we handle the action for INIT state.
         * so that resource monager will disable HW as the  last operation.
         */
        if (nstate == IEEE80211_S_STANDBY) {
            evt.type = IEEE80211_VAP_STANDBY;
            ieee80211_vap_deliver_event(vap, &evt);
        } else {
            evt.type = IEEE80211_VAP_FULL_SLEEP;
            ieee80211_vap_deliver_event(vap, &evt);

            if(deliver_stop_event)
              IEEE80211COM_DELIVER_VAP_EVENT(vap->iv_ic, vap->iv_ifp, IEEE80211_VAP_STOPPED);
        }
        if (ieee80211_vap_dfswait_is_set(vap))
            ieee80211_dfs_cac_stop(vap, 0);
        ieee80211_vap_dfswait_clear(vap);

        IEEE80211_VAP_LOCK(vap);
        if (vap->iv_node_count == 0) {
            // IEEE80211_STATE_EVENT_BSS_NODE_FREED event has been received.
            if (ieee80211_vap_deleted_is_clear(vap)) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE,
                        "ieee80211_vap_deleted_is_clear is true\n");
                vap->iv_state_info.iv_sm_running = false;
                IEEE80211_STATE_UNLOCK(ic);
                ASSERT(0);
                return -1;
            }
            deleteVap = TRUE;
        }
        IEEE80211_VAP_UNLOCK(vap);
        break;
     case IEEE80211_S_STOPPING:
         IEEE80211_STATE_UNLOCK(ic);
         if (vap->iv_stopping(vap) != EOK) {
             IEEE80211COM_DELIVER_VAP_EVENT(vap->iv_ic, vap->iv_ifp, IEEE80211_VAP_STOP_ERROR);
         }
         IEEE80211_STATE_LOCK(ic);
         ieee80211_vap_ready_clear(vap);
         ieee80211_vap_active_clear(vap);
         ieee80211_vap_scanning_clear(vap);
         if (ieee80211_vap_dfswait_is_set(vap))
             ieee80211_dfs_cac_stop(vap, 0);
         ieee80211_vap_dfswait_clear(vap);
         if (!ieee80211_vap_standby_is_set(vap)) {
             /*
              * Note: if standby flag is set, then this is not really
              * "Stopping" but "waiting to go to Standby". Therefore,
              * only send VAP_STOPPING if standby flag unset.
              */
             evt.type = IEEE80211_VAP_STOPPING;
             ieee80211_vap_deliver_event(vap, &evt);
         }
         break;
     case IEEE80211_S_SCAN:
         ieee80211_vap_active_set(vap);
         ieee80211_vap_ready_clear(vap);
         ieee80211_vap_scanning_set(vap);
         vap->iv_listen(vap);
         if (ieee80211_vap_dfswait_is_set(vap))
             ieee80211_dfs_cac_stop(vap, 0);
         ieee80211_vap_dfswait_clear(vap);
         break;
     case IEEE80211_S_JOIN:
         ieee80211_vap_scanning_clear(vap);
         ieee80211_vap_ready_clear(vap);
         vap->iv_join(vap);
         ieee80211_vap_active_set(vap);
         if (ieee80211_vap_dfswait_is_set(vap))
             ieee80211_dfs_cac_stop(vap, 0);
         ieee80211_vap_dfswait_clear(vap);
         break;
     case IEEE80211_S_RUN:
         /*
          * to avoid the race, set the ready  flag after bringing the vap
          * up.
          */
         ieee80211_vap_scanning_clear(vap);
         ieee80211_vap_active_set(vap);
         if (ieee80211_vap_dfswait_is_set(vap))
             ieee80211_dfs_cac_stop(vap, 0);
         ieee80211_vap_dfswait_clear(vap);

#if UNIFIED_SMARTANTENNA
         if (vap->iv_opmode == IEEE80211_M_STA) {
             if (ic->radio_id == RADIO_ID_OFF_LOAD) {
                 /* Reinit smart antenna with correct Channel */
                 ieee80211_smart_ant_deinit(ic, vap, SMART_ANT_RECONFIGURE);
                 ieee80211_smart_ant_init(ic, vap, SMART_ANT_RECONFIGURE);
                 ic->sta_not_connected_cfg = FALSE;
             }
         }
#endif
#if DYNAMIC_BEACON_SUPPORT
         if(vap->iv_dbeacon) {
             IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "ic_ieee:%u  freq:%u \n",
                     ic->ic_curchan->ic_ieee,ic->ic_curchan->ic_freq);
             /* Do not suspend beacon for DFS channels */
             if (IEEE80211_IS_CHAN_DFS(ic->ic_curchan)) {
                 ieee80211_mlme_set_dynamic_beacon_suspend(vap,false);
             } else {
                 ieee80211_mlme_set_dynamic_beacon_suspend(vap,true);
             }
         }
#endif
         vap->iv_up(vap);
         /* Send the CAC Complete Event to the stavap if it is waiting
          * in state REPEATER_CAC
          */
         {
             struct ieee80211vap *stavap = NULL;
             STA_VAP_DOWNUP_LOCK(ic);
             stavap = ic->ic_sta_vap;
             if(stavap) {
                 int val=0;
                 wlan_mlme_sm_get_curstate(stavap,IEEE80211_PARAM_CONNECTION_SM_STATE,&val);
                 if(val == WLAN_ASSOC_STATE_REPEATER_CAC) {
                     IEEE80211_DELIVER_EVENT_MLME_REPEATER_CAC_COMPLETE(stavap,0);
                 }
             }
             STA_VAP_DOWNUP_UNLOCK(ic);
         }
#if UNIFIED_SMARTANTENNA
	 nacvaps = ieee80211_get_num_active_vaps(ic);
         if ((vap->iv_opmode == IEEE80211_M_HOSTAP) && (nacvaps == 1) ) {
             ieee80211_smart_ant_deinit(ic, vap, SMART_ANT_RECONFIGURE);
             ieee80211_smart_ant_init(ic, vap, SMART_ANT_RECONFIGURE);
         }
#endif
         ieee80211_vap_ready_set(vap);

         /* Set default mcast rate */
         ieee80211_set_mcast_rate(vap);


         if (cur_state != IEEE80211_S_RUN) {

             if (cur_state == IEEE80211_S_STANDBY) {
                evt.type = IEEE80211_VAP_RESUMED;
                ieee80211_vap_deliver_event(vap, &evt);
            } else {
                /* from other -> RUN */
                evt.type = IEEE80211_VAP_UP;
                ieee80211_vap_deliver_event(vap, &evt);
             }
         }
         break;
    case IEEE80211_S_DFS_WAIT:
             vap->iv_dfs_cac(vap);
             ieee80211_vap_dfswait_set(vap);
             ieee80211_vap_active_clear(vap);
             ieee80211_vap_ready_clear(vap);
             ieee80211_vap_scanning_clear(vap);
        break;
    default:
        break;
    }

    vap->iv_state_info.iv_state = (u_int32_t)nstate;

    vap->iv_state_info.iv_sm_running = false;
    IEEE80211_STATE_UNLOCK(ic);

    if (deleteVap) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE, "%s: vap_free \n", __func__);
        ieee80211_vap_free(vap);
    }

    return 0;
}

int
ieee80211_vap_start(struct ieee80211vap *vap)
{
  return  ieee80211_state_event(vap,IEEE80211_STATE_EVENT_UP);
}
#if UMAC_REPEATER_DELAYED_BRINGUP
void 
ieee80211_vap_handshake_finish(struct ieee80211vap *vap)
{
	if (vap->iv_opmode == IEEE80211_M_STA)
		ieee80211_state_event(vap, IEEE80211_STATE_EVENT_HANDSHAKE_FINISH);
}
#endif
void
ieee80211_vap_stop(struct ieee80211vap *vap, bool force)
{
    if (force) {
        ieee80211_state_event(vap, IEEE80211_STATE_EVENT_FORCE_STOP);
    } else {
        ieee80211_state_event(vap, IEEE80211_STATE_EVENT_DOWN);
    }
}

void
ieee80211_vap_restart(struct ieee80211vap *vap)
{
    ieee80211_state_event(vap, IEEE80211_STATE_EVENT_RESTART_REQ);
}

void
ieee80211_vap_standby(struct ieee80211vap *vap)
{
    ieee80211_state_event(vap, IEEE80211_STATE_EVENT_STANDBY);
}

/*
 * temp WAR for windows hang (dead lock). It can be removed when VAP SM is re-written (bug 65137).
 */
static void
ieee80211_vap_bss_node_freed_handle(struct ieee80211vap *vap, void* workItemHandle)
{
    ieee80211_state_event(vap, IEEE80211_STATE_EVENT_BSS_NODE_FREED);
    OS_FREE_ROUTING(workItemHandle);
}

void
ieee80211_vap_bss_node_freed(struct ieee80211vap *vap)
{
    /*
     * ieee80211_vap_bss_node_freed_handle takes a "struct ieee80211vap *"
     * pointer as its initial arg, rather than the "void *" pointer
     * specified by os_tasklet_routine_t, so a typecast is needed.
     */
    OS_SCHEDULE_ROUTING(
        vap->iv_ic->ic_osdev,
        (os_tasklet_routine_t) ieee80211_vap_bss_node_freed_handle,
        vap);
}

int
ieee80211_vap_join(struct ieee80211vap *vap)
{
  return  ieee80211_state_event(vap,IEEE80211_STATE_EVENT_JOIN);
}

/*
 * Reset 11g-related state.
 */
void
ieee80211_reset_erp(struct ieee80211com *ic,
                    enum ieee80211_phymode mode,
                    enum ieee80211_opmode opmode)
{
#define IS_11G(m) \
    ((m) == IEEE80211_MODE_11G || (m) == IEEE80211_MODE_TURBO_G)

    struct ieee80211_channel *chan = ieee80211_get_current_channel(ic);

    IEEE80211_DISABLE_PROTECTION(ic);

    /*
     * Preserve the long slot and nonerp station count if
     * switching between 11g and turboG. Otherwise, inactivity
     * will cause the turbo station to disassociate and possibly
     * try to leave the network.
     * XXX not right if really trying to reset state
     */
    if (IS_11G(mode) ^ IS_11G(ic->ic_curmode)) {
        ic->ic_nonerpsta = 0;
        ic->ic_longslotsta = 0;
    }

    /*
     * Short slot time is enabled only when operating in 11g
     * and not in an IBSS.  We must also honor whether or not
     * the driver is capable of doing it.
     */
    if(opmode == IEEE80211_M_IBSS){
        ieee80211_set_shortslottime(ic, 0);
    }else{
        ieee80211_set_shortslottime(
            ic,
            IEEE80211_IS_CHAN_A(chan) ||
            IEEE80211_IS_CHAN_11NA(chan) ||
	    IEEE80211_IS_CHAN_11AC(chan) ||
            ((IEEE80211_IS_CHAN_ANYG(chan) || IEEE80211_IS_CHAN_11NG(chan)) &&
             (opmode == IEEE80211_M_HOSTAP || opmode == IEEE80211_M_BTAMP) &&
             (ic->ic_caps & IEEE80211_C_SHSLOT)));
	}

    /*
     * Set short preamble and ERP barker-preamble flags.
     */
    if (IEEE80211_IS_CHAN_A(chan) ||
        IEEE80211_IS_CHAN_11NA(chan) ||
        (ic->ic_caps & IEEE80211_C_SHPREAMBLE)) {
        IEEE80211_ENABLE_SHPREAMBLE(ic);
        IEEE80211_DISABLE_BARKER(ic);
    } else {
        IEEE80211_DISABLE_SHPREAMBLE(ic);
        IEEE80211_ENABLE_BARKER(ic);
    }
#undef IS_11G
}

/*
 * Set the short slot time state and notify the driver.
 */
void
ieee80211_set_shortslottime(struct ieee80211com *ic, int onoff)
{
    if (onoff)
        IEEE80211_ENABLE_SHSLOT(ic);
    else
        IEEE80211_DISABLE_SHSLOT(ic);

    if (ic->ic_updateslot != NULL)
        ic->ic_updateslot(ic);
}

void
ieee80211_wme_initparams(struct ieee80211vap *vap)
{
    if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
        /*
         * For AP, we need to synchronize with SWBA interrupt.
         * So we need to lock out interrupt.
         */
    //    OS_EXEC_INTSAFE(vap->iv_ic->ic_osdev, ieee80211_wme_initparams_locked, vap);
	if(vap->iv_rescan)
		return;
        ieee80211_wme_initparams_locked(vap);
    } else {
        ieee80211_wme_initparams_locked(vap);
    }
}

void
ieee80211_wme_initparams_locked(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_wme_state *wme = &ic->ic_wme;
    enum ieee80211_phymode mode;
    const wmeParamType *pPhyParam, *pBssPhyParam;
    int i;

    //IEEE80211_BEACON_LOCK_ASSERT(ic);

    if ((ic->ic_caps & IEEE80211_C_WME) == 0)
        return;

    /*
     * Select mode; we can be called early in which case we
     * always use auto mode.  We know we'll be called when
     * entering the RUN state with bsschan setup properly
     * so state will eventually get set correctly
     */
    if (vap->iv_bsschan != IEEE80211_CHAN_ANYC)
        mode = ieee80211_chan2mode(vap->iv_bsschan);
    else
        mode = IEEE80211_MODE_AUTO;
    for (i = 0; i < WME_NUM_AC; i++) {
        switch (i) {
        case WME_AC_BK:
            pPhyParam = &ic->phyParamForAC[WME_AC_BK][mode];
            pBssPhyParam = &ic->phyParamForAC[WME_AC_BK][mode];
            break;
        case WME_AC_VI:
            pPhyParam = &ic->phyParamForAC[WME_AC_VI][mode];
            pBssPhyParam = &ic->bssPhyParamForAC[WME_AC_VI][mode];
            break;
        case WME_AC_VO:
            pPhyParam = &ic->phyParamForAC[WME_AC_VO][mode];
            pBssPhyParam = &ic->bssPhyParamForAC[WME_AC_VO][mode];
            break;
        case WME_AC_BE:
        default:
            pPhyParam = &ic->phyParamForAC[WME_AC_BE][mode];
            pBssPhyParam = &ic->bssPhyParamForAC[WME_AC_BE][mode];
            break;
        }

        if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
            wme->wme_wmeChanParams.cap_wmeParams[i].wmep_acm = pPhyParam->acm;
            wme->wme_wmeChanParams.cap_wmeParams[i].wmep_aifsn = pPhyParam->aifsn;
            wme->wme_wmeChanParams.cap_wmeParams[i].wmep_logcwmin = pPhyParam->logcwmin;
            wme->wme_wmeChanParams.cap_wmeParams[i].wmep_logcwmax = pPhyParam->logcwmax;
            wme->wme_wmeChanParams.cap_wmeParams[i].wmep_txopLimit = pPhyParam->txopLimit;
        } else {
            wme->wme_wmeChanParams.cap_wmeParams[i].wmep_acm = pBssPhyParam->acm;
            wme->wme_wmeChanParams.cap_wmeParams[i].wmep_aifsn = pBssPhyParam->aifsn;
            wme->wme_wmeChanParams.cap_wmeParams[i].wmep_logcwmin = pBssPhyParam->logcwmin;
            wme->wme_wmeChanParams.cap_wmeParams[i].wmep_logcwmax = pBssPhyParam->logcwmax;
            wme->wme_wmeChanParams.cap_wmeParams[i].wmep_txopLimit = pBssPhyParam->txopLimit;
        }
        wme->wme_wmeBssChanParams.cap_wmeParams[i].wmep_acm = pBssPhyParam->acm;
        wme->wme_wmeBssChanParams.cap_wmeParams[i].wmep_aifsn = pBssPhyParam->aifsn;
        wme->wme_wmeBssChanParams.cap_wmeParams[i].wmep_logcwmin = pBssPhyParam->logcwmin;
        wme->wme_wmeBssChanParams.cap_wmeParams[i].wmep_logcwmax = pBssPhyParam->logcwmax;
        wme->wme_wmeBssChanParams.cap_wmeParams[i].wmep_txopLimit = pBssPhyParam->txopLimit;
    }
    /* NB: check ic_bss to avoid NULL deref on initial attach */
    if (vap->iv_bss != NULL) {
        /*
         * Calculate agressive mode switching threshold based
         * on beacon interval.
         */
        wme->wme_hipri_switch_thresh =
            (HIGH_PRI_SWITCH_THRESH * ieee80211_node_get_beacon_interval(vap->iv_bss)) / 100;
        memcpy(&vap->iv_wmestate,&ic->ic_wme,sizeof(ic->ic_wme));

        ieee80211_wme_updateparams_locked(vap);
    }
}

void
ieee80211_wme_initglobalparams(struct ieee80211com *ic)
{
    int i;
    static const struct wme_phyParamType phyParamForAC_BE[IEEE80211_MODE_MAX] = {
        /* IEEE80211_MODE_AUTO           */ {          3,                4,                6,                  0,              0 },
        /* IEEE80211_MODE_11A            */ {          3,                4,                6,                  0,              0 },
        /* IEEE80211_MODE_11B            */ {          3,                5,                7,                  0,              0 },
        /* IEEE80211_MODE_11G            */ {          3,                4,                6,                  0,              0 },
        /* IEEE80211_MODE_FH             */ {          3,                5,                7,                  0,              0 },
        /* IEEE80211_MODE_TURBO          */ {          2,                3,                5,                  0,              0 },
        /* IEEE80211_MODE_TURBO          */ {          2,                3,                5,                  0,              0 },
        /* IEEE80211_MODE_11NA_HT20      */ {          3,                4,                6,                  0,              0 },
        /* IEEE80211_MODE_11NG_HT20      */ {          3,                4,                6,                  0,              0 },
        /* IEEE80211_MODE_11NA_HT40PLUS  */ {          3,                4,                6,                  0,              0 },
        /* IEEE80211_MODE_11NA_HT40MINUS */ {          3,                4,                6,                  0,              0 },
        /* IEEE80211_MODE_11NG_HT40PLUS  */ {          3,                4,                6,                  0,              0 },
        /* IEEE80211_MODE_11NG_HT40MINUS */ {          3,                4,                6,                  0,              0 },
        /* IEEE80211_MODE_11NG_HT40      */ {          3,                4,                6,                  0,              0 },
        /* IEEE80211_MODE_11NA_HT40      */ {          3,                4,                6,                  0,              0 },
        /* IEEE80211_MODE_11AC_VHT20     */ {          3,                4,                6,                  0,              0 },
        /* IEEE80211_MODE_11AC_VHT40PLUS */ {          3,                4,                6,                  0,              0 },
        /* IEEE80211_MODE_11AC_VHT40MINUS*/ {          3,                4,                6,                  0,              0 },
        /* IEEE80211_MODE_11AC_VHT40     */ {          3,                4,                6,                  0,              0 },
        /* IEEE80211_MODE_11AC_VHT80     */ {          3,                4,                6,                  0,              0 },
        /* IEEE80211_MODE_11AC_VHT160    */ {          3,                4,                6,                  0,              0 },
        /* IEEE80211_MODE_11AC_VHT80_80  */ {          3,                4,                6,                  0,              0 }};
     static const struct wme_phyParamType phyParamForAC_BK[IEEE80211_MODE_MAX] = {
        /* IEEE80211_MODE_AUTO           */ {          7,                4,               10,                  0,              0 },
        /* IEEE80211_MODE_11A            */ {          7,                4,               10,                  0,              0 },
        /* IEEE80211_MODE_11B            */ {          7,                5,               10,                  0,              0 },
        /* IEEE80211_MODE_11G            */ {          7,                4,               10,                  0,              0 },
        /* IEEE80211_MODE_FH             */ {          7,                5,               10,                  0,              0 },
        /* IEEE80211_MODE_TURBO          */ {          7,                3,               10,                  0,              0 },
        /* IEEE80211_MODE_TURBO          */ {          7,                3,               10,                  0,              0 },
        /* IEEE80211_MODE_11NA_HT20      */ {          7,                4,               10,                  0,              0 },
        /* IEEE80211_MODE_11NG_HT20      */ {          7,                4,               10,                  0,              0 },
        /* IEEE80211_MODE_11NA_HT40PLUS  */ {          7,                4,               10,                  0,              0 },
        /* IEEE80211_MODE_11NA_HT40MINUS */ {          7,                4,               10,                  0,              0 },
        /* IEEE80211_MODE_11NG_HT40PLUS  */ {          7,                4,               10,                  0,              0 },
        /* IEEE80211_MODE_11NG_HT40MINUS */ {          7,                4,               10,                  0,              0 },
        /* IEEE80211_MODE_11NG_HT40      */ {          7,                4,               10,                  0,              0 },
        /* IEEE80211_MODE_11NA_HT40      */ {          7,                4,               10,                  0,              0 },
        /* IEEE80211_MODE_11AC_VHT20     */ {          7,                4,               10,                  0,              0 },
        /* IEEE80211_MODE_11AC_VHT40PLUS */ {          7,                4,               10,                  0,              0 },
        /* IEEE80211_MODE_11AC_VHT40MINUS*/ {          7,                4,               10,                  0,              0 },
        /* IEEE80211_MODE_11AC_VHT40     */ {          7,                4,               10,                  0,              0 },
        /* IEEE80211_MODE_11AC_VHT80     */ {          7,                4,               10,                  0,              0 },
        /* IEEE80211_MODE_11AC_VHT160    */ {          7,                4,               10,                  0,              0 },
        /* IEEE80211_MODE_11AC_VHT80_80  */ {          7,                4,               10,                  0,              0 }};
     static const struct wme_phyParamType phyParamForAC_VI[IEEE80211_MODE_MAX] = {
        /* IEEE80211_MODE_AUTO           */ {          1,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11A            */ {          1,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11B            */ {          1,                4,               5,                 188,              0 },
        /* IEEE80211_MODE_11G            */ {          1,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_FH             */ {          1,                4,               5,                 188,              0 },
        /* IEEE80211_MODE_TURBO          */ {          1,                2,               3,                  94,              0 },
        /* IEEE80211_MODE_TURBO          */ {          1,                2,               3,                  94,              0 },
        /* IEEE80211_MODE_11NA_HT20      */ {          1,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11NG_HT20      */ {          1,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11NA_HT40PLUS  */ {          1,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11NA_HT40MINUS */ {          1,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11NG_HT40PLUS  */ {          1,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11NG_HT40MINUS */ {          1,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11NG_HT40      */ {          1,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11NA_HT40      */ {          1,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11AC_VHT20     */ {          1,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11AC_VHT40PLUS */ {          1,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11AC_VHT40MINUS*/ {          1,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11AC_VHT40     */ {          1,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11AC_VHT80     */ {          1,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11AC_VHT160    */ {          1,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11AC_VHT80_80  */ {          1,                3,               4,                  94,              0 }};
     static const struct wme_phyParamType phyParamForAC_VO[IEEE80211_MODE_MAX] = {
        /* IEEE80211_MODE_AUTO           */ {          1,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11A            */ {          1,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11B            */ {          1,                3,               4,                 102,              0 },
        /* IEEE80211_MODE_11G            */ {          1,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_FH             */ {          1,                3,               4,                 102,              0 },
        /* IEEE80211_MODE_TURBO          */ {          1,                2,               2,                  47,              0 },
        /* IEEE80211_MODE_TURBO          */ {          1,                2,               2,                  47,              0 },
        /* IEEE80211_MODE_11NA_HT20      */ {          1,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11NG_HT20      */ {          1,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11NA_HT40PLUS  */ {          1,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11NA_HT40MINUS */ {          1,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11NG_HT40PLUS  */ {          1,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11NG_HT40MINUS */ {          1,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11NG_HT40      */ {          1,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11NA_HT40      */ {          1,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11AC_VHT20     */ {          1,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11AC_VHT40PLUS */ {          1,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11AC_VHT40MINUS*/ {          1,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11AC_VHT40     */ {          1,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11AC_VHT80     */ {          1,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11AC_VHT160    */ {          1,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11AC_VHT80_80  */ {          1,                2,               3,                  47,              0 }};
     static const struct wme_phyParamType bssPhyParamForAC_BE[IEEE80211_MODE_MAX] = {
        /* IEEE80211_MODE_AUTO           */ {          3,                4,              10,                   0,              0 },
        /* IEEE80211_MODE_11A            */ {          3,                4,              10,                   0,              0 },
        /* IEEE80211_MODE_11B            */ {          3,                5,              10,                   0,              0 },
        /* IEEE80211_MODE_11G            */ {          3,                4,              10,                   0,              0 },
        /* IEEE80211_MODE_FH             */ {          3,                5,              10,                   0,              0 },
        /* IEEE80211_MODE_TURBO          */ {          2,                3,              10,                   0,              0 },
        /* IEEE80211_MODE_TURBO          */ {          2,                3,              10,                   0,              0 },
        /* IEEE80211_MODE_11NA_HT20      */ {          3,                4,              10,                   0,              0 },
        /* IEEE80211_MODE_11NG_HT20      */ {          3,                4,              10,                   0,              0 },
        /* IEEE80211_MODE_11NA_HT40PLUS  */ {          3,                4,              10,                   0,              0 },
        /* IEEE80211_MODE_11NA_HT40MINUS */ {          3,                4,              10,                   0,              0 },
        /* IEEE80211_MODE_11NG_HT40PLUS  */ {          3,                4,              10,                   0,              0 },
        /* IEEE80211_MODE_11NG_HT40MINUS */ {          3,                4,              10,                   0,              0 },
        /* IEEE80211_MODE_11NG_HT40      */ {          3,                4,              10,                   0,              0 },
        /* IEEE80211_MODE_11NA_HT40      */ {          3,                4,              10,                   0,              0 },
        /* IEEE80211_MODE_11AC_VHT20     */ {          3,                4,              10,                   0,              0 },
        /* IEEE80211_MODE_11AC_VHT40PLUS */ {          3,                4,              10,                   0,              0 },
        /* IEEE80211_MODE_11AC_VHT40MINUS*/ {          3,                4,              10,                   0,              0 },
        /* IEEE80211_MODE_11AC_VHT40     */ {          3,                4,              10,                   0,              0 },
        /* IEEE80211_MODE_11AC_VHT80     */ {          3,                4,              10,                   0,              0 },
        /* IEEE80211_MODE_11AC_VHT160    */ {          3,                4,              10,                   0,              0 },
        /* IEEE80211_MODE_11AC_VHT80_80  */ {          3,                4,              10,                   0,              0 }};
     static const struct wme_phyParamType bssPhyParamForAC_VI[IEEE80211_MODE_MAX] = {
        /* IEEE80211_MODE_AUTO           */ {          2,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11A            */ {          2,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11B            */ {          2,                4,               5,                 188,              0 },
        /* IEEE80211_MODE_11G            */ {          2,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_FH             */ {          2,                4,               5,                 188,              0 },
        /* IEEE80211_MODE_TURBO          */ {          2,                2,               3,                  94,              0 },
        /* IEEE80211_MODE_TURBO          */ {          2,                2,               3,                  94,              0 },
        /* IEEE80211_MODE_11NA_HT20      */ {          2,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11NG_HT20      */ {          2,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11NA_HT40PLUS  */ {          2,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11NA_HT40MINUS */ {          2,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11NG_HT40PLUS  */ {          2,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11NG_HT40MINUS */ {          2,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11NG_HT40      */ {          2,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11NA_HT40      */ {          2,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11AC_VHT20     */ {          2,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11AC_VHT40PLUS */ {          2,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11AC_VHT40MINUS*/ {          2,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11AC_VHT40     */ {          2,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11AC_VHT80     */ {          2,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11AC_VHT160    */ {          2,                3,               4,                  94,              0 },
        /* IEEE80211_MODE_11AC_VHT80_80  */ {          2,                3,               4,                  94,              0 }};
     static const struct wme_phyParamType bssPhyParamForAC_VO[IEEE80211_MODE_MAX] = {
        /* IEEE80211_MODE_AUTO           */ {          2,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11A            */ {          2,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11B            */ {          2,                3,               4,                 102,              0 },
        /* IEEE80211_MODE_11G            */ {          2,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_FH             */ {          2,                3,               4,                 102,              0 },
        /* IEEE80211_MODE_TURBO          */ {          1,                2,               2,                  47,              0 },
        /* IEEE80211_MODE_TURBO          */ {          1,                2,               2,                  47,              0 },
        /* IEEE80211_MODE_11NA_HT20      */ {          2,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11NG_HT20      */ {          2,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11NA_HT40PLUS  */ {          2,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11NA_HT40MINUS */ {          2,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11NG_HT40PLUS  */ {          2,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11NG_HT40MINUS */ {          2,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11NG_HT40      */ {          2,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11NA_HT40      */ {          2,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11AC_VHT20     */ {          2,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11AC_VHT40PLUS */ {          2,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11AC_VHT40MINUS*/ {          2,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11AC_VHT40     */ {          2,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11AC_VHT80     */ {          2,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11AC_VHT160    */ {          2,                2,               3,                  47,              0 },
        /* IEEE80211_MODE_11AC_VHT80_80  */ {          2,                2,               3,                  47,              0 }};

    for (i = 0; i < WME_NUM_AC; i++) {
        switch (i) {
        case WME_AC_BK:
            qdf_mem_copy(ic->phyParamForAC[WME_AC_BK], phyParamForAC_BK,
                    sizeof(phyParamForAC_BK));
            qdf_mem_copy(ic->bssPhyParamForAC[WME_AC_BK], phyParamForAC_BK,
                    sizeof(phyParamForAC_BK));
            break;
        case WME_AC_VI:
            qdf_mem_copy(ic->phyParamForAC[WME_AC_VI], phyParamForAC_VI,
                    sizeof(phyParamForAC_VI));
            qdf_mem_copy(ic->bssPhyParamForAC[WME_AC_VI], bssPhyParamForAC_VI,
                    sizeof(bssPhyParamForAC_VI));
            break;
        case WME_AC_VO:
            qdf_mem_copy(ic->phyParamForAC[WME_AC_VO], phyParamForAC_VO,
                    sizeof(phyParamForAC_VO));
            qdf_mem_copy(ic->bssPhyParamForAC[WME_AC_VO], bssPhyParamForAC_VO,
                    sizeof(bssPhyParamForAC_VO));
            break;
        case WME_AC_BE:
        default:
            qdf_mem_copy(ic->phyParamForAC[WME_AC_BE], phyParamForAC_BE,
                    sizeof(phyParamForAC_BE));
            qdf_mem_copy(ic->bssPhyParamForAC[WME_AC_BE], bssPhyParamForAC_BE,
                    sizeof(bssPhyParamForAC_BE));
            break;
        }
    }
}

static void
ieee80211_vap_iter_check_burst(void *arg, wlan_if_t vap)
{
    u_int8_t *pburstEnabled= (u_int8_t *) arg;
    if (vap->iv_ath_cap & IEEE80211_ATHC_BURST) {
        *pburstEnabled=1;
    }

}

void
ieee80211_wme_amp_overloadparams_locked(struct ieee80211com *ic)
{
    struct ieee80211_wme_state *wme = &ic->ic_wme;

    wme->wme_chanParams.cap_wmeParams[WME_AC_BE].wmep_txopLimit
        = ic->ic_reg_parm.ampTxopLimit;
    wme->wme_bssChanParams.cap_wmeParams[WME_AC_BE].wmep_txopLimit
        = ic->ic_reg_parm.ampTxopLimit;

    wme->wme_update(ic);
}

/*
 * Update WME parameters for ourself and the BSS.
 */
void
ieee80211_wme_updateparams_locked(struct ieee80211vap *vap)
{
    static const struct { u_int8_t aifsn; u_int8_t logcwmin; u_int8_t logcwmax; u_int16_t txopLimit;}
    phyParam[IEEE80211_MODE_MAX] = {
        /* IEEE80211_MODE_AUTO           */ {          2,                4,               10,           64 },
        /* IEEE80211_MODE_11A            */ {          2,                4,               10,           64 },
        /* IEEE80211_MODE_11B            */ {          2,                5,               10,           64 },
        /* IEEE80211_MODE_11G            */ {          2,                4,               10,           64 },
        /* IEEE80211_MODE_FH             */ {          2,                5,               10,           64 },
        /* IEEE80211_MODE_TURBO_A        */ {          1,                3,               10,           64 },
        /* IEEE80211_MODE_TURBO_G        */ {          1,                3,               10,           64 },
        /* IEEE80211_MODE_11NA_HT20      */ {          2,                4,               10,           64 },
        /* IEEE80211_MODE_11NG_HT20      */ {          2,                4,               10,           64 },
        /* IEEE80211_MODE_11NA_HT40PLUS  */ {          2,                4,               10,           64 },
        /* IEEE80211_MODE_11NA_HT40MINUS */ {          2,                4,               10,           64 },
        /* IEEE80211_MODE_11NG_HT40PLUS  */ {          2,                4,               10,           64 },
        /* IEEE80211_MODE_11NG_HT40MINUS */ {          2,                4,               10,           64 },
        /* IEEE80211_MODE_11NG_HT40      */ {          2,                4,               10,           64 },
        /* IEEE80211_MODE_11NA_HT40      */ {          2,                4,               10,           64 },
        /* IEEE80211_MODE_11AC_VHT20     */ {          2,                4,               10,           64 },
        /* IEEE80211_MODE_11AC_VHT40PLUS */ {          2,                4,               10,           64 },
        /* IEEE80211_MODE_11AC_VHT40MINUS*/ {          2,                4,               10,           64 },
        /* IEEE80211_MODE_11AC_VHT40     */ {          2,                4,               10,           64 },
        /* IEEE80211_MODE_11AC_VHT80     */ {          2,                4,               10,           64 }};
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_wme_state *wme = &vap->iv_wmestate;
    enum ieee80211_phymode mode;
    int i;

    /* set up the channel access parameters for the physical device */
    for (i = 0; i < WME_NUM_AC; i++) {
        wme->wme_chanParams.cap_wmeParams[i].wmep_acm
            = wme->wme_wmeChanParams.cap_wmeParams[i].wmep_acm;
        wme->wme_chanParams.cap_wmeParams[i].wmep_aifsn
            = wme->wme_wmeChanParams.cap_wmeParams[i].wmep_aifsn;
        wme->wme_chanParams.cap_wmeParams[i].wmep_logcwmin
            = wme->wme_wmeChanParams.cap_wmeParams[i].wmep_logcwmin;
        wme->wme_chanParams.cap_wmeParams[i].wmep_logcwmax
            = wme->wme_wmeChanParams.cap_wmeParams[i].wmep_logcwmax;
        wme->wme_chanParams.cap_wmeParams[i].wmep_txopLimit
            = wme->wme_wmeChanParams.cap_wmeParams[i].wmep_txopLimit;
        wme->wme_bssChanParams.cap_wmeParams[i].wmep_acm
            = wme->wme_wmeBssChanParams.cap_wmeParams[i].wmep_acm;
        wme->wme_bssChanParams.cap_wmeParams[i].wmep_aifsn
            = wme->wme_wmeBssChanParams.cap_wmeParams[i].wmep_aifsn;
        wme->wme_bssChanParams.cap_wmeParams[i].wmep_logcwmin
            = wme->wme_wmeBssChanParams.cap_wmeParams[i].wmep_logcwmin;
        wme->wme_bssChanParams.cap_wmeParams[i].wmep_logcwmax
            = wme->wme_wmeBssChanParams.cap_wmeParams[i].wmep_logcwmax;
        wme->wme_bssChanParams.cap_wmeParams[i].wmep_txopLimit
            = wme->wme_wmeBssChanParams.cap_wmeParams[i].wmep_txopLimit;
    }

    /*
     * Select mode; we can be called early in which case we
     * always use auto mode.  We know we'll be called when
     * entering the RUN state with bsschan setup properly
     * so state will eventually get set correctly
     */
    if (vap->iv_bsschan != IEEE80211_CHAN_ANYC)
        mode = ieee80211_chan2mode(vap->iv_bsschan);
    else
        mode = IEEE80211_MODE_AUTO;

    if ((vap->iv_opmode == IEEE80211_M_HOSTAP &&
        ((wme->wme_flags & WME_F_AGGRMODE) != 0)) ||
        ((vap->iv_opmode == IEEE80211_M_STA || vap->iv_opmode == IEEE80211_M_IBSS) &&
         (vap->iv_bss->ni_flags & IEEE80211_NODE_QOS) == 0) ||
         ieee80211_vap_wme_is_clear(vap)) {
        u_int8_t burstEnabled=0;
        /* check if bursting  enabled on at least one vap */
        wlan_iterate_vap_list(ic,ieee80211_vap_iter_check_burst,(void *) &burstEnabled);
        wme->wme_chanParams.cap_wmeParams[WME_AC_BE].wmep_aifsn = phyParam[mode].aifsn;
        wme->wme_chanParams.cap_wmeParams[WME_AC_BE].wmep_logcwmin = phyParam[mode].logcwmin;
        wme->wme_chanParams.cap_wmeParams[WME_AC_BE].wmep_logcwmax = phyParam[mode].logcwmax;
        wme->wme_chanParams.cap_wmeParams[WME_AC_BE].wmep_txopLimit
            = burstEnabled ? phyParam[mode].txopLimit : 0;
        wme->wme_bssChanParams.cap_wmeParams[WME_AC_BE].wmep_aifsn = phyParam[mode].aifsn;
        wme->wme_bssChanParams.cap_wmeParams[WME_AC_BE].wmep_logcwmin = phyParam[mode].logcwmin;
        wme->wme_bssChanParams.cap_wmeParams[WME_AC_BE].wmep_logcwmax = phyParam[mode].logcwmax;
        wme->wme_bssChanParams.cap_wmeParams[WME_AC_BE].wmep_txopLimit
            = burstEnabled ? phyParam[mode].txopLimit : 0;
    }

    if (ic->ic_opmode == IEEE80211_M_HOSTAP &&
        ic->ic_sta_assoc < 2 &&
        (wme->wme_flags & WME_F_AGGRMODE) != 0) {
        static const u_int8_t logCwMin[IEEE80211_MODE_MAX] = {
            /* IEEE80211_MODE_AUTO           */   3,
            /* IEEE80211_MODE_11A            */   3,
            /* IEEE80211_MODE_11B            */   4,
            /* IEEE80211_MODE_11G            */   3,
            /* IEEE80211_MODE_FH             */   4,
            /* IEEE80211_MODE_TURBO_A        */   3,
            /* IEEE80211_MODE_TURBO_G        */   3,
            /* IEEE80211_MODE_11NA_HT20      */   3,
            /* IEEE80211_MODE_11NG_HT20      */   3,
            /* IEEE80211_MODE_11NA_HT40PLUS  */   3,
            /* IEEE80211_MODE_11NA_HT40MINUS */   3,
            /* IEEE80211_MODE_11NG_HT40PLUS  */   3,
            /* IEEE80211_MODE_11NG_HT40MINUS */   3,
            /* IEEE80211_MODE_11NG_HT40      */   3,
            /* IEEE80211_MODE_11NA_HT40      */   3,
            /* IEEE80211_MODE_11AC_VHT20     */   3,
            /* IEEE80211_MODE_11AC_VHT40PLUS */   3,
            /* IEEE80211_MODE_11AC_VHT40MINUS*/   3,
            /* IEEE80211_MODE_11AC_VHT40     */   3,
            /* IEEE80211_MODE_11AC_VHT80     */   3
        };

        wme->wme_chanParams.cap_wmeParams[WME_AC_BE].wmep_logcwmin
            = wme->wme_bssChanParams.cap_wmeParams[WME_AC_BE].wmep_logcwmin
            = logCwMin[mode];
    }
    if (vap->iv_opmode == IEEE80211_M_HOSTAP) {   /* XXX ibss? */
        u_int8_t    temp_cap_info   = wme->wme_bssChanParams.cap_info;
        u_int8_t    temp_info_count = temp_cap_info & WME_QOSINFO_COUNT;
        /*
         * Arrange for a beacon update and bump the parameter
         * set number so associated stations load the new values.
         */
        if (wme->wme_flags & WME_F_BSSPARAM_UPDATED) {
            temp_info_count++;
            wme->wme_flags &= ~(WME_F_BSSPARAM_UPDATED);
        }

        wme->wme_bssChanParams.cap_info =
            (temp_cap_info & WME_QOSINFO_UAPSD) |
            (temp_info_count & WME_QOSINFO_COUNT);
        vap->iv_flags |= IEEE80211_F_WMEUPDATE;
    }

    /* Override txOpLimit for video stream for now.
     * else WMM failures are observed in 11N testbed
     * Refer to bug #22594 and 31082
     */
    /* NOTE: The above overriding behavior causes new VHT test cases to
     * break. As this is common code retaining behavior for pre-VHT cards
     * modes and overriding the setting only for 11N cards
     */
    if (!(ic->ic_flags_ext & IEEE80211_CEXT_11AC) &&
            (vap->iv_opmode == IEEE80211_M_STA)) {
        if (VAP_NEED_CWMIN_WORKAROUND(vap)) {
             /* For UB9x, override CWmin for video stream for now
             * else WMM failures are observed in 11N testbed
             * Refer to bug #70038 ,#70039 and #70041
             */
            if (wme->wme_chanParams.cap_wmeParams[WME_AC_VI].wmep_logcwmin == 3) {
                wme->wme_chanParams.cap_wmeParams[WME_AC_VI].wmep_logcwmin = 4;
            }
        }
        wme->wme_chanParams.cap_wmeParams[WME_AC_VI].wmep_txopLimit = 0;
    }

#if ATH_SUPPORT_IBSS_WMM
    if (vap->iv_opmode == IEEE80211_M_IBSS) {
        wme->wme_chanParams.cap_wmeParams[WME_AC_BE].wmep_txopLimit = 0;
        wme->wme_chanParams.cap_wmeParams[WME_AC_VI].wmep_txopLimit = 0;
    }
#endif
    /* Copy wme params from vap to ic to avoid inconsistency */
    memcpy(&ic->ic_wme,&vap->iv_wmestate,sizeof(ic->ic_wme));

    if (wme->wme_update)
        wme->wme_update(ic);
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_WME,
                      "%s: WME params updated, cap_info 0x%x\n", __func__,
                      vap->iv_opmode == IEEE80211_M_STA ?
                      wme->wme_wmeChanParams.cap_info :
                      wme->wme_bssChanParams.cap_info);
}

/*
 * Update WME parameters for ourself and the BSS.
 */
void
ieee80211_wme_updateinfo_locked(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_wme_state *wme = &ic->ic_wme;

    if (vap->iv_opmode == IEEE80211_M_HOSTAP) {   /* XXX ibss? */
        u_int8_t    temp_cap_info   = wme->wme_bssChanParams.cap_info;
        u_int8_t    temp_info_count = temp_cap_info & WME_QOSINFO_COUNT;
        /*
         * Arrange for a beacon update and bump the parameter
         * set number so associated stations load the new values.
         */
        wme->wme_bssChanParams.cap_info =
            (temp_cap_info & WME_QOSINFO_UAPSD) |
            ((temp_info_count + 1) & WME_QOSINFO_COUNT);
        vap->iv_flags |= IEEE80211_F_WMEUPDATE;
    }

    wme->wme_update(ic);

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_WME,
                      "%s: WME info updated, cap_info 0x%x\n", __func__,
                      vap->iv_opmode == IEEE80211_M_STA ?
                      wme->wme_wmeChanParams.cap_info :
                      wme->wme_bssChanParams.cap_info);
}

void
ieee80211_wme_updateparams(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;

    if (ic->ic_caps & IEEE80211_C_WME) {
        if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
            /*
             * For AP, we need to synchronize with SWBA interrupt.
             * So we need to lock out interrupt.
             */
            OS_EXEC_INTSAFE(ic->ic_osdev, ieee80211_wme_updateparams_locked, vap);
        } else {
            ieee80211_wme_updateparams_locked(vap);
        }
    }
}

void
ieee80211_wme_updateinfo(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;

    if (ic->ic_caps & IEEE80211_C_WME) {
        if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
            /*
             * For AP, we need to synchronize with SWBA interrupt.
             * So we need to lock out interrupt.
             */
            OS_EXEC_INTSAFE(ic->ic_osdev, ieee80211_wme_updateinfo_locked, vap);
        } else {
            ieee80211_wme_updateinfo_locked(vap);
        }
    }
}

void
ieee80211_dump_pkt(struct ieee80211com *ic,
                   const u_int8_t *buf, int len, int rate, int rssi)
{
    const struct ieee80211_frame *wh;
    int type, subtype;
    int i;

    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%8p (%lu): \n", buf, (unsigned long) OS_GET_TIMESTAMP());

    wh = (const struct ieee80211_frame *)buf;
    type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    subtype = (wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) >> IEEE80211_FC0_SUBTYPE_SHIFT;

    switch (wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) {
    case IEEE80211_FC1_DIR_NODS:
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "NODS %s", ether_sprintf(wh->i_addr2));
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "->%s", ether_sprintf(wh->i_addr1));
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "(%s)", ether_sprintf(wh->i_addr3));
        break;
    case IEEE80211_FC1_DIR_TODS:
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "TODS %s", ether_sprintf(wh->i_addr2));
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "->%s", ether_sprintf(wh->i_addr3));
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "(%s)", ether_sprintf(wh->i_addr1));
        break;
    case IEEE80211_FC1_DIR_FROMDS:
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "FRDS %s", ether_sprintf(wh->i_addr3));
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "->%s", ether_sprintf(wh->i_addr1));
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "(%s)", ether_sprintf(wh->i_addr2));
        break;
    case IEEE80211_FC1_DIR_DSTODS:
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "DSDS %s", ether_sprintf((const u_int8_t *)&wh[1]));
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "->%s", ether_sprintf(wh->i_addr3));
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "(%s", ether_sprintf(wh->i_addr2));
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "->%s)", ether_sprintf(wh->i_addr1));
        break;
    }
    switch (type) {
    case IEEE80211_FC0_TYPE_DATA:
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " data");
        break;
    case IEEE80211_FC0_TYPE_MGT:
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %s", ieee80211_mgt_subtype_name[subtype]);
        break;
    default:
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " type#%d", type);
        break;
    }
    if (IEEE80211_QOS_HAS_SEQ(wh)) {
        const struct ieee80211_qosframe *qwh =
            (const struct ieee80211_qosframe *)buf;
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " QoS [TID %u%s]", qwh->i_qos[0] & IEEE80211_QOS_TID,
               qwh->i_qos[0] & IEEE80211_QOS_ACKPOLICY ? " ACM" : "");
    }

    if (wh->i_fc[1] & IEEE80211_FC1_WEP) {
        int off;

        off = ieee80211_anyhdrspace(ic, wh);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " WEP [IV %.02x %.02x %.02x",
               buf[off+0], buf[off+1], buf[off+2]);
        if (buf[off+IEEE80211_WEP_IVLEN] & IEEE80211_WEP_EXTIV)
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %.02x %.02x %.02x",
                   buf[off+4], buf[off+5], buf[off+6]);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " KID %u]", buf[off+IEEE80211_WEP_IVLEN] >> 6);
    }
    if (rate >= 0)
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %dM", rate / 1000);
    if (rssi >= 0)
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " +%d", rssi);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n");
    if (len > 0) {
        for (i = 0; i < len; i++) {
            if ((i & 1) == 0)
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " ");
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%02x", buf[i]);
        }
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n");
    }
}

static void
get_ht20_only(void *arg, struct ieee80211_node *ni)
{
    u_int32_t *num_sta = arg;

    if (!ni->ni_associd)
        return;

    if ((ni->ni_flags & IEEE80211_NODE_HT) &&
        ((ni->ni_flags & IEEE80211_NODE_40_INTOLERANT) ||
         (ni->ni_flags & IEEE80211_NODE_REQ_HT20))) {
        (*num_sta)++;
    }
}

void
ieee80211_change_cw(struct ieee80211com *ic)
{
    enum ieee80211_cwm_width cw_width = ic->ic_cwm_get_width(ic);
    u_int32_t num_ht20_only = 0;

    if (ic->ic_flags & IEEE80211_F_COEXT_DISABLE)
        return;

    ieee80211_iterate_node(ic, get_ht20_only, &num_ht20_only);

    if (cw_width == IEEE80211_CWM_WIDTH40) {
        if (num_ht20_only) {
            ic->ic_bss_to20(ic);
        }
    } else if (cw_width == IEEE80211_CWM_WIDTH20) {
        if (num_ht20_only == 0) {
            ic->ic_bss_to40(ic);
        }
    }
}
