/*
 * Copyright (c) 2010, Atheros Communications Inc.
 * All Rights Reserved.
 *
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#include "ieee80211_mlme_priv.h"    /* Private to MLME module */
#include <ieee80211_target.h>
#include <if_smart_ant.h>
#include "ald_netlink.h"

#define IEEE80211_PSPOLL_KICKOUT_THR 30000
#define RX_DECAP_TYPE_RAW            0

#if UMAC_SUPPORT_AP || UMAC_SUPPORT_BTAMP
void ieee80211_mlme_recv_assoc_request(struct ieee80211_node *ni,
                                       u_int8_t reassoc,u_int8_t *vendor_ie, wbuf_t wbuf)
{
    struct ieee80211vap           *vap = ni->ni_vap;
    struct ieee80211com           *ic = ni->ni_ic;
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;
    struct ieee80211_key          *k = &ni->ni_ucastkey;
    u_int8_t                      newassoc = (ni->ni_associd == 0);
    wbuf_t                        resp_wbuf;
    u_int16_t                     assocstatus;
    ieee80211_mlme_event          event;
    u_int8_t                      flag=0;
    u_int8_t                      node_leave = 0,isvht;

    /* AP  must be up and running */
    if (!mlme_priv->im_connection_up || ieee80211_vap_ready_is_clear(vap)) {
        return;
    }
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s\n", __func__);

    if (ieee80211_node_join(ni)) {
        /* Association Failure */
        assocstatus = IEEE80211_REASON_ASSOC_TOOMANY;
    } else {
        assocstatus = IEEE80211_STATUS_SUCCESS;
        if (!reassoc) {
            ieee80211_admctl_node_leave(vap, ni);
        }

        /* Indicate that a new node has associated */
        event.type = IEEE80211_MLME_EVENT_STA_JOIN;
        event.u.event_sta.sta_count= vap->iv_sta_assoc;
        event.u.event_sta.sta_ps_count= vap->iv_ps_sta;
        event.u.event_sta.ni = ni;
        ieee80211_mlme_deliver_event(mlme_priv,&event);
    }

    /* clear the last auth seq number */
    ni->ni_last_rxauth_seq = 0xfff;
    ni->ni_last_auth_rx_time = 0;

    /* Clear any previously cached status */
    ni->ni_assocstatus = assocstatus;

    /* Setup association response frame before indication */
    resp_wbuf = ieee80211_setup_assocresp(ni, NULL, reassoc, assocstatus, NULL);
    if (!resp_wbuf)
        assocstatus = IEEE80211_REASON_UNSPECIFIED;

    /* Move this down after sending the Assoc resp, so that the EAPOL
     * frame that is sent as consequence of this event, doesn't go OTA
     * before the Assoc Resp frame on some partial offload platforms. */

    /* Windows Platform have to call indication first to update ni->assocstatus
    * value, Keep original alg for Windows Platform.
    */
    /* Memory allocation failure, no point continuing */
    if (!resp_wbuf)
        return;

    /* Association rejection from above */
    if (ni->ni_assocstatus != IEEE80211_STATUS_SUCCESS) {

        /* Update already formed association response and send it out */
        ieee80211_setup_assocresp(ni, resp_wbuf, reassoc, ni->ni_assocstatus, NULL);
        ieee80211_send_mgmt(vap,ni, resp_wbuf,false);

        /* Flag to remove the node from node table */
        node_leave = 1;
    } else {
        if(ieee80211node_has_whc_apinfo_flag(ni, IEEE80211_NODE_WHC_APINFO_SON))
        {
            IEEE80211_VAP_WHC_AP_INFO_UPDATE_ENABLE(vap);
        }
        /* Wait for application to trigger mlme response for assoc */
        if (ieee80211_vap_trigger_mlme_resp_is_set(vap)) {
            wbuf_complete(resp_wbuf);
        }
        else {
            flag = TRUE;
        }

        ni->ni_assocuptime = OS_GET_TICKS();
#if UMAC_SUPPORT_WNM
        ni->ni_wnm->last_rcvpkt_tstamp =  ni->ni_assocuptime;
#endif

        /* If null/dummy key plumbing for WEP is configured, set the appropriate
         * flag in key structure and call handler to plumb keys for all
         * 4 key indexes
         */
        if ((vap->iv_cfg_raw_dwep_ind) && (vap->iv_rx_decap_type ==
            RX_DECAP_TYPE_RAW)) {

            ieee80211_crypto_wep_setdummykey(vap, ni, k);
        }

        isvht = (ni->ni_flags & IEEE80211_NODE_VHT);
        IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC | IEEE80211_MSG_DEBUG, ni,
            "station %sassociated at aid %d: %s preamble, %s slot time"
            "%s%s%s%s cap 0x%x\n"
            , newassoc ? "" : "re"
            , IEEE80211_NODE_AID(ni)
            , ic->ic_flags & IEEE80211_F_SHPREAMBLE ? "short" : "long"
            , ic->ic_flags & IEEE80211_F_SHSLOT ? "short" : "long"
            , ic->ic_flags & IEEE80211_F_USEPROT ? ", protection" : ""
            , ni->ni_flags & IEEE80211_NODE_QOS ? ", QoS" : ""
            , isvht ? "VHT" : (ni->ni_flags & IEEE80211_NODE_HT ? ", HT" : "")
            , (ni->ni_flags & IEEE80211_NODE_HT)  ?
                       (ni->ni_htcap & IEEE80211_HTCAP_C_CHWIDTH40 ? "40" : "20") : ""
            , ni->ni_capinfo
        );

        /* give driver a chance to setup state like ni_txrate */
        if(!(ieee80211_is_pmf_enabled(vap, ni)) ||  !(ni->ni_flags & IEEE80211_NODE_AUTH)){
            if (ic->ic_newassoc != NULL){
                ic->ic_newassoc(ni, newassoc);
            }
        }
	 /* We  are limiting the client connection for open mode,by checking the keyix NONE then allow the node to leave.
           This is only for direct attach path, offload taken care in Firmware itself*/
         if ( !ic->ic_is_mode_offload(ic) && !IEEE80211_VAP_IS_PRIVACY_ENABLED(vap)  &&  (ni->ni_ucastkey.wk_keyix == IEEE80211_KEYIX_NONE) && !(vap->iv_wps_mode) ) {
           if (!RSN_AUTH_IS_WPA(&ni->ni_rsn) &&
                !RSN_AUTH_IS_WPA2(&ni->ni_rsn) &&
                !RSN_AUTH_IS_WAI(&ni->ni_rsn) &&
                !RSN_AUTH_IS_8021X(&ni->ni_rsn)) {
                        assocstatus  = IEEE80211_REASON_ASSOC_TOOMANY;
                        ni->ni_assocstatus = assocstatus;
                        ieee80211_setup_assocresp(ni, resp_wbuf, reassoc, ni->ni_assocstatus, NULL);
                        ieee80211_send_mgmt(vap,ni, resp_wbuf,false);
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n IEEE80211_KEYIX_NONE  set the node to leave ");
                        /* Flag to remove the node from node table */
                        node_leave = 1;
                        goto end;
                }
        }

        if(flag) {
            ieee80211_send_mgmt(vap,ni,resp_wbuf,false);
        }
        if((ni->ni_capinfo & IEEE80211_CAPINFO_RADIOMEAS)
                && ieee80211_vap_rrm_is_set(vap))
        {
            ieee80211_set_node_rrm(ni,TRUE);
        }
        else {
            ieee80211_set_node_rrm(ni,FALSE);
        }

        /* To take care of shared wep condition,
           after challenge text success we are setting node to authorized
           so checking it here should be fine.*/
        if (ieee80211_node_is_authorized(ni)) {
#if ATH_BAND_STEERING
            ieee80211_bsteering_send_node_associated_event(vap, ni);
#endif

#if ATH_SUPPORT_HYFI_ENHANCEMENTS
            ald_assoc_notify(vap, ni->ni_macaddr, ALD_ACTION_ASSOC);
#endif
            }
        /*
         * Authorize the node when configured in open mode.
         * Node authorizations for other modes are initiated by hostapd.
         * Security modes configured at node & vap should match.
         */
        if((ni->ni_authmode != IEEE80211_AUTH_8021X) &&
           (RSN_AUTH_MATCH(&ni->ni_rsn, &vap->iv_rsn)) &&
           (!(RSN_AUTH_IS_WPA(&ni->ni_rsn) || RSN_AUTH_IS_WPA2(&ni->ni_rsn) ||
            RSN_AUTH_IS_8021X(&ni->ni_rsn) || RSN_AUTH_IS_WAI(&ni->ni_rsn))) &&
           (!RSN_AUTH_IS_SHARED_KEY(&vap->iv_rsn) || (ni->ni_authmode != IEEE80211_AUTH_SHARED)))
        {
#if ATH_BAND_STEERING
            ieee80211_bsteering_send_node_associated_event(vap, ni);
#endif

#if ATH_SUPPORT_HYFI_ENHANCEMENTS
            ald_assoc_notify(vap, ni->ni_macaddr, ALD_ACTION_ASSOC);
#endif
            ieee80211_node_authorize(ni);
        }

        /* Update MIMO powersave flags and node rates */
        ieee80211_update_noderates(ni);
#if UNIFIED_SMARTANTENNA
        if (!IEEE80211_VAP_IS_PRIVACY_ENABLED(vap) && !(ni->ni_capinfo & IEEE80211_CAPINFO_PRIVACY)) {
            if (ic->radio_id == RADIO_ID_DIRECT_ATTACH) { /* for direct attach */
                ieee80211_smart_ant_node_connect(ni, NULL);
            }
        }
#endif
        /* need to add a station join notification */

        if (!(ni->ni_capinfo & IEEE80211_CAPINFO_SPECTRUM_MGMT)) {
            /* Spectrum managemnt is not supported by this node */
            if (!(ni->ni_ext_flags & IEEE80211_NODE_NON_DOTH_STA)) {
                /* Non spectrum managemnt node associated for forst time */
                ic->ic_non_doth_sta_cnt++;
                ni->ni_ext_flags |= IEEE80211_NODE_NON_DOTH_STA;
            }
        } else {
            /* Spectrum managemnt supported by this node */
            if ((ni->ni_ext_flags & IEEE80211_NODE_NON_DOTH_STA)) {
                /* Already associated sta (without spectrum management
                 * capability) reassociated with spectrum management
                 * capability.
                 * Mark this STA now supports sepectrum managemnet.
                 */
                ni->ni_ext_flags &= ~IEEE80211_NODE_NON_DOTH_STA;
                ic->ic_non_doth_sta_cnt--;
            }
        }
    }

end:
    /* Now send the notification and remove the node if needed */
    if (reassoc) {
	IEEE80211_DELIVER_EVENT_MLME_REASSOC_INDICATION(vap, ni->ni_macaddr,
							assocstatus, wbuf, resp_wbuf);
    } else {
	IEEE80211_DELIVER_EVENT_MLME_ASSOC_INDICATION(vap, ni->ni_macaddr,
						      assocstatus, wbuf, resp_wbuf);
#if ATH_SSID_STEERING
    if(vap->iv_vap_ssid_config == 1){
        IEEE80211_DELIVER_SSID_EVENT(vap, ni->ni_macaddr);
    }
#endif
    }

#if DYNAMIC_BEACON_SUPPORT
    /*
     * STA assoc successfully,
     * resume beacon and trigger suspend beacon timer for iv_dbeacon_timeout.
     */
    if (vap->iv_dbeacon && vap->iv_dbeacon_runtime && assocstatus == IEEE80211_STATUS_SUCCESS) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "STA assoc successfully. Resume beacon \n");
        qdf_spin_lock_bh(&vap->iv_dbeacon_lock);
        if (ieee80211_mlme_beacon_suspend_state(vap)) {
            ieee80211_mlme_set_beacon_suspend_state(vap, false);
        }
        OS_SET_TIMER(&vap->iv_dbeacon_suspend_beacon, vap->iv_dbeacon_timeout*1000);
        qdf_spin_unlock_bh(&vap->iv_dbeacon_lock);
    }
#endif

    if (node_leave) {
	IEEE80211_NODE_LEAVE(ni);
    }
}

/*
 *  create a insfra structure network (Host AP mode).
 */

static void ieee80211_mlme_create_infra_continue(struct ieee80211vap *vap)
{
    struct ieee80211com         *ic = vap->iv_ic;
    bool skip_dfs_cac = false;
    struct ieee80211_vap_opmode_count    vap_opmode_count;

    /* Update channel and rates of the node */
    ieee80211_node_set_chan(vap->iv_bss);
    vap->iv_cur_mode = ieee80211_chan2mode(vap->iv_bss->ni_chan);

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s \n", __func__);
#if UMAC_SUPPORT_BTAMP
    /*
     * For BTAMP vap, HT may be disabled based on iv_des_mode.
     *
     * TBD: Other phy properties are not controllable, such as preamble, slot, ERP,
     *      because ic is referenced to set the above properties.
     */
    if (IEEE80211_IS_CHAN_11N(vap->iv_bss->ni_chan)) {
        if (vap->iv_opmode == IEEE80211_M_BTAMP)
            vap->iv_cur_mode = vap->iv_des_mode;
    }
#endif

#ifdef ATH_SUPPORT_DFS
    if (ic->recovery_in_progress == 0) {
	    ieee80211_dfs_cac_valid_reset(ic);
    } else {
	    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, 
                       "%s : recovery in progress, not resetting dfs cac \n", __FUNCTION__);
    }
#endif

    OS_MEMZERO(&(vap_opmode_count), sizeof(vap_opmode_count));
    /*
     * Get total number of VAPs of each type supported by the IC.
     */
    ieee80211_get_vap_opmode_count(ic, &vap_opmode_count);
    /* if station vap is present and in connected state, then skip DFS CAC timer */
    if (ic->ic_sta_vap && wlan_is_connected(ic->ic_sta_vap)) {
	skip_dfs_cac = true;
    }

#if ATH_SUPPORT_ZERO_CAC_DFS
    /*
     * If precac required timer expires it does a vdev_restart of all the active vaps
     * so that precac algorithm can pick the next channel. However vdev_restart response
     * also calls this function and tries to start the CAC. We do not want CAC for
     * vdev_restart by precac.
     */
    if(vap->iv_pre_cac_timeout_channel_change == 1) {
        vap->iv_pre_cac_timeout_channel_change = 0;
        IEEE80211_DPRINTF(vap,IEEE80211_MSG_DFS, "%s pre_cac channel change so skip cac\n",__func__);
        skip_dfs_cac = true;
    }
#endif

    if(vap->iv_no_cac) {
        skip_dfs_cac = true;
        vap->iv_no_cac = 0;
    }

    if (IEEE80211_IS_CSH_OPT_AVOID_DUAL_CAC_ENABLED(ic)) {
        if ((vap_opmode_count.sta_count >= 1) && IEEE80211_IS_PRIMARY_OR_SECONDARY_CHAN_DFS(ic)) {
            skip_dfs_cac = is_subset_channel(ic, ic->ic_curchan, ic->ic_prevchan);
        }
    }

    qdf_atomic_set(&(vap->init_in_progress), 0);

    IEEE80211_STATE_CHECK_LOCK(ic);
    if (skip_dfs_cac || ieee80211_dfs_cac_start(vap->iv_ic)) {
        if (!ic->ic_nl_handle) {
            /* NON DFS channel, Start host ap */
            ieee80211_vap_start(vap);
        } else {
            ieee80211_state_event(vap, IEEE80211_STATE_EVENT_DFS_WAIT);
        }
    }
    IEEE80211_STATE_CHECK_UNLOCK(ic);
}

int
mlme_create_infra_bss(struct ieee80211vap *vap, u_int8_t restart)
{
    struct ieee80211com         *ic = vap->iv_ic;
    struct ieee80211_channel    *chan = NULL;
    ieee80211_ssid              *ssid = NULL;
    int                         n_ssid;
    int                         error = 0;
    int                         coex_enabled;
    u_int8_t numvaps_up = 0;
    u_int8_t acs_report_scan_active = 0;

    n_ssid = ieee80211_get_desired_ssid(vap, 0,&ssid);

    if (ssid == NULL)
        return EINVAL;

    /*
     * if there is a scan in progress.
     * then there is a vap currently scanning and the chip
     * is off on a different channel. we can not bring up
     * vap at this point.  Scan can be in progress for
     * independant repeater vaps, since they do not change channels.
     */
   /*
    * When the resmgr is active, do not fail vap creation even if a scan is in progress
    */
    acs_report_scan_active = wlan_get_param(vap, IEEE80211_START_ACS_REPORT);
    if (!ieee80211_resmgr_active(ic) &&
           (wlan_scan_in_progress(vap) &&
             !(ieee80211_ic_offchanscan_is_set(ic) || acs_report_scan_active))
        && !ieee80211_ic_enh_ind_rpt_is_set(ic)) {
        return EAGAIN;
    }

    /* create BSS node for infra network */
    error = ieee80211_create_infra_bss(vap,ssid->ssid, ssid->len);

    if (error) {
        goto err;
    }

    /*
     * at this point the bss node (vap->iv_bss) has 2 references.
     * one for the fact that it is part of the node table.
     * the second one for being a bss node and being referred from
     * vap->iv_bss.
     */

    numvaps_up = ieee80211_get_num_vaps_up(ic);
    /* if num active vaps is not 0
     * make the vap to follow the current channel instead of desired
     * channel
     */
    if (numvaps_up){
        chan =  ic->ic_curchan;
    }
    else {
        chan =  vap->iv_des_chan[vap->iv_des_mode];
    }

    if (chan == NULL || chan == IEEE80211_CHAN_ANYC) {
        return EINVAL;
    }

    /* EV130162 -- AP picking up channel from NOL when VAP restarts */


    /* don't allow to change to channel with radar and possibly in NOL */
    if (IEEE80211_IS_CHAN_RADAR(chan)) {

        /*
         *  channel has radar, so look for another channel
         */
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s: channel at freq=%d has radar\n", __func__, chan->ic_freq);
        chan = ieee80211_find_dot11_channel(ic, 0, 0, vap->iv_des_mode | ic->ic_chanbwflag);
        if (chan == NULL) {
                return -EINVAL;
        } else {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s: picking channel at freq=%d\n", __func__, chan->ic_freq);
            ic->ic_curchan = chan;
            vap->iv_des_chan[vap->iv_des_mode] = chan;
        }
    }

    coex_enabled = !(ic->ic_flags & IEEE80211_F_COEXT_DISABLE);

    if (coex_enabled && chan->ic_flags & (IEEE80211_CHAN_11NG_HT40PLUS | IEEE80211_CHAN_11NG_HT40MINUS)) {
        /*
         *          * We are in HT40+ or HT40- mode,  if channel intolerant bit is set
         *                   * then its better to use HT20 mode, because HT40 PhyMode would be
         *                            * cause a performance drop as PHY has to monitor Ext channel too.
         *                                     */

        if (chan->ic_flags & IEEE80211_CHAN_HT40INTOL) {
            struct ieee80211_channel    *ht20chan = NULL;

            /* Find the HT20 channel info */
            ht20chan = ieee80211_find_dot11_channel(ic, chan->ic_ieee, 0, IEEE80211_MODE_11NG_HT20);
            if (ht20chan) {
                QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : Overriding HT40 channel with HT20 channel\n", __func__);
                chan = ht20chan;
            }
            else {
                QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : Unable to find HT20 channel\n", __func__);
            }
        }
    }

    if (IEEE80211_IS_CHAN_DISALLOW_HOSTAP(chan)) {
        return EINVAL;
    }

    if(IEEE80211_IS_CHAN_2GHZ(chan)) {
        ieee80211_vap_doth_clear(vap);
    }

    /*
     * issue a vap start request to resource manager.
     * if the function returns EOK (0) then its ok to change the channel synchronously
     * if the function returns EBUSY  then resource manager will
     * switch channel asynchronously and post an event event handler registred by vap and
     * vap handler will intern call the wlan_mlme_join_infra_continue .
     */
    error = ieee80211_resmgr_vap_start(ic->ic_resmgr,vap,chan,MLME_REQ_ID,0,restart);
    if (error == EOK) { /* no resource manager in place */
        /*
         * if there is a vap already running.
         * ignore the desired channel and use the
         * operating channel of the other vap.
         */
        /* so that cwm can do its own crap. need to untie from state */
        /* vap join is called here to wake up the chip if it is in sleep state */
        ieee80211_vap_join(vap);

        if (numvaps_up == 0) {
            if (error == EOK ) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s: Setting channel number %d\n", __func__, chan->ic_ieee);
                ieee80211_set_channel(ic, chan);
                vap->iv_bsschan = ic->ic_curchan;   /* ieee80211 Layer - Default Configuration */
            }

            /* XXX reset erp state */
            ieee80211_reset_erp(ic, ic->ic_curmode, vap->iv_opmode);
            ieee80211_wme_initparams(vap);
        } else {
           /* Copy wme params from ic to vap for the first time when vaps are up and update them */
           struct ieee80211_wme_state wme_zero = {0};
           if(memcmp(&wme_zero,&vap->iv_wmestate,sizeof(wme_zero)) == 0)
           {
               memcpy(&vap->iv_wmestate,&ic->ic_wme,sizeof(ic->ic_wme));
           }
           ieee80211_wme_updateparams_locked(vap);
           vap->iv_bsschan = ic->ic_curchan;    /* get the current channel */
        }
        ieee80211_mlme_create_infra_continue(vap);
    }

err:
    return error;
}
void ieee80211_mlme_create_infra_continue_async(struct ieee80211vap *vap, int32_t status)
{
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s: status %d\n", __func__,status);
    if (status == EOK) {
        ieee80211_mlme_create_infra_continue(vap);
    }

    IEEE80211_DELIVER_EVENT_MLME_JOIN_COMPLETE_INFRA(vap, (status == EOK) ? IEEE80211_STATUS_SUCCESS : IEEE80211_STATUS_REFUSED);
}

/*
 * function to handle shared auth in HOST AP mode.
 */

u_int16_t
mlme_auth_shared(struct ieee80211_node *ni, u_int16_t seq, u_int16_t status,
                 u_int8_t *challenge,u_int16_t challenge_len)
{
    struct ieee80211vap    *vap = ni->ni_vap;
    struct ieee80211com    *ic = ni->ni_ic;
    u_int16_t              estatus = IEEE80211_STATUS_SUCCESS;

    /*
     * NB: this can happen as we allow pre-shared key
     * authentication to be enabled w/o wep being turned
     * on so that configuration of these can be done
     * in any order.  It may be better to enforce the
     * ordering in which case this check would just be
     * for sanity/consistency.
     */
    estatus = 0;            /* NB: silence compiler */
    if (!IEEE80211_VAP_IS_PRIVACY_ENABLED(vap)) {
        IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH,
                           ni->ni_macaddr, "shared key auth",
                           "%s", " PRIVACY is disabled");
        estatus = IEEE80211_STATUS_ALG;
    }

    if (estatus == IEEE80211_STATUS_SUCCESS) {
        switch (seq) {
        case IEEE80211_AUTH_SHARED_CHALLENGE:
        case IEEE80211_AUTH_SHARED_RESPONSE:
            if (challenge == NULL) {
                IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH,
                                   ni->ni_macaddr, "%s\n", "shared key auth no challenge");
                vap->iv_stats.is_rx_bad_auth++;
                estatus = IEEE80211_STATUS_CHALLENGE;
            } else if (challenge_len != IEEE80211_CHALLENGE_LEN) {
                IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH, ni->ni_macaddr,
                                   "shared key auth bad challenge len %d", challenge_len);
                vap->iv_stats.is_rx_bad_auth++;
                estatus = IEEE80211_STATUS_CHALLENGE;
            }
        default:
            break;
        }
    }

    if (estatus == IEEE80211_STATUS_SUCCESS) {
        switch (seq) {
        case IEEE80211_AUTH_SHARED_REQUEST:
            if (ni->ni_challenge == NULL)
                ni->ni_challenge = (u_int32_t *)OS_MALLOC(ic->ic_osdev ,IEEE80211_CHALLENGE_LEN,0);
            if (ni->ni_challenge == NULL) {
                IEEE80211_NOTE(ni->ni_vap,
                               IEEE80211_MSG_DEBUG | IEEE80211_MSG_AUTH, ni,
                               "%s", "shared key challenge alloc failed");
                /* XXX statistic */
                estatus = IEEE80211_STATUS_UNSPECIFIED;
            } else {
                /*
                 * get random bytes for challenge text.
                 */

                OS_GET_RANDOM_BYTES(ni->ni_challenge,
                                    IEEE80211_CHALLENGE_LEN);
                IEEE80211_NOTE(vap,
                               IEEE80211_MSG_DEBUG | IEEE80211_MSG_AUTH, ni,
                               "%s", "shared key auth request \n");
                ieee80211_send_auth(ni,(seq + 1),0,(u_int8_t *)ni->ni_challenge,IEEE80211_CHALLENGE_LEN,NULL);
            }
            break;
        case IEEE80211_AUTH_SHARED_RESPONSE:
            if (ni->ni_challenge == NULL) {
                IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH,
                                   ni->ni_macaddr, "shared key response",
                                   "%s", "no challenge recorded");
                vap->iv_stats.is_rx_bad_auth++;
                estatus = IEEE80211_STATUS_CHALLENGE;
            } else if (memcmp(ni->ni_challenge, challenge,
                              challenge_len) != 0) {
                IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH,
                                   ni->ni_macaddr, "shared key response",
                                   "%s", "challenge mismatch");
                vap->iv_stats.is_rx_auth_fail++;
                estatus = IEEE80211_STATUS_CHALLENGE;
            } else {
                IEEE80211_NOTE(vap, IEEE80211_MSG_DEBUG | IEEE80211_MSG_AUTH, ni,
                               "station authenticated (%s)\n", "shared key");
                ieee80211_node_authorize(ni);
                /*
                 * shared auth success.
                 */
                ieee80211_send_auth(ni,(seq + 1),0, NULL,0,NULL);
            }
            break;
        default:
            IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH,
                               ni->ni_macaddr, "shared key auth ",
                               "bad seq %d \n", seq);
            vap->iv_stats.is_rx_bad_auth++;
            estatus = IEEE80211_STATUS_SEQUENCE;
            break;
        }
    }

    /*
     * Send an error response.
     */
    if (estatus != IEEE80211_STATUS_SUCCESS) {
        ieee80211_send_auth(ni,(seq + 1),estatus, NULL,0,NULL);
    }

    return estatus;
}

static int mlme_recv_auth_ap_handle_duplicate(struct ieee80211_node *ni,
                                            u_int16_t algo, u_int16_t seq, u_int16_t frame_seq,
                                            bool* create_new_node)
{
    struct ieee80211vap           *vap = ni->ni_vap;
    struct ieee80211com *ic = vap->iv_ic;
    u_int16_t associd = 0;
    /*
     * Check is frame is duplicate frame or not.
     * check the received sequence number and compare previous seq number of auth frame.
     */
    if(ni->ni_last_rxauth_seq == frame_seq){
        IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH, ni->ni_macaddr,
                    "recv duplicate auth frame seq num %d\n",frame_seq);
        return -1;
    } else if (ni->ni_last_auth_rx_time != 0
        && seq != IEEE80211_AUTH_SHARED_RESPONSE){
        /*
         * Check is auth frame is recevied before a valid assoc request is given
         * ni_last_auth_rx_time is made as '0' on receving assoc request to node.
         * if ni_last_auth_rx_time is not '0' then already auth is in progress.
         * if frame is recevied within nominal auth + assoc req time,
         * then drop this auth. As already one more frame in progress.
         */
        systime_t now;
        now = OS_GET_TIMESTAMP();
        if(CONVERT_SYSTEM_TIME_TO_MS(now - ni->ni_last_auth_rx_time) < 100){
            IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH, ni->ni_macaddr,
                "recv another auth frame when previous is in progress\n");
            return -1;
        }
    }

    ni->ni_last_auth_rx_time = OS_GET_TIMESTAMP();
    ni->ni_last_rxauth_seq = frame_seq;

    if ((seq == IEEE80211_AUTH_OPEN_REQUEST ||
         seq == IEEE80211_AUTH_SHARED_REQUEST) &&
         (algo != IEEE80211_AUTH_ALG_FT)) {
        /* if receive the re-auth frame without any disassoc check if node is at power save mode
            let the sta leave the power save state. */
        if ((ni->ni_flags & IEEE80211_NODE_PWR_MGT) == IEEE80211_NODE_PWR_MGT)
        {
            ieee80211_mlme_node_pwrsave_ap(ni,0);
        }
        /* Leave the node only if PMF not enabled */
        if (!ieee80211_is_pmf_enabled(vap, ni)) {
            if(!ieee80211_vap_trigger_mlme_resp_is_set(vap)) {
                ieee80211_ref_node(ni);
                associd = ni->ni_associd;
                if(IEEE80211_NODE_LEAVE(ni)) {
                    IEEE80211_DELIVER_EVENT_MLME_DISASSOC_INDICATION(vap,
                        ni->ni_macaddr, associd, IEEE80211_REASON_ASSOC_LEAVE);
                }
                ieee80211_free_node(ni);
            } else {
                if(ic && ic->ic_is_mode_offload(ic)) {
                    ni->ni_flags |= IEEE80211_NODE_DELAYED_CLEANUP;
                }
                wlan_mlme_disassoc_request(vap,ni->ni_macaddr,IEEE80211_REASON_ASSOC_LEAVE);
                IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH, ni->ni_macaddr,
                                "recv auth when valid node is present ignore auth and disconnect sta\n");
                return -1;
            }
        } else {
            /* PMF is enabled so don't create new node */
            *create_new_node = FALSE;
        }
    } else if (seq == IEEE80211_AUTH_SHARED_RESPONSE || algo == IEEE80211_AUTH_ALG_FT){
        /*
         * Second auth in AUTH_ALG_SHARED or
         * Auth request with FT as algo for roaming
         */
        *create_new_node = FALSE;
    } else {
        /*
         * Invalid auth frame in AP mode.
         */
        IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH, ni->ni_macaddr,
                   "Invalid auth frame with algo %d AuthSeq %d \n",algo,seq);
        return -1;
    }

  return 0;
}


int mlme_recv_auth_ap(struct ieee80211_node *ni,
                       u_int16_t algo, u_int16_t seq, u_int16_t status_code,
                       u_int8_t *challenge, u_int8_t challenge_length, wbuf_t wbuf,
                       const struct ieee80211_rx_status *rs)
{

    struct ieee80211vap           *vap = ni->ni_vap;
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;
    struct ieee80211_frame        *wh;
    u_int16_t                     frame_seq;
    u_int16_t                     indication_status = IEEE80211_STATUS_SUCCESS,response_status = IEEE80211_STATUS_SUCCESS ;
    bool                          send_auth_response=true,indicate=true;

    wh = (struct ieee80211_frame *) wbuf_header(wbuf);

    /* AP must be up and running */
    if (!mlme_priv->im_connection_up || ieee80211_vap_ready_is_clear(vap)) {
        return -1;
    }


    IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH, wh->i_addr2,
                       "recv auth frame with algorithm %d seq %d \n", algo, seq);
    frame_seq = ((le16toh(*(u_int16_t *)wh->i_seq)) & IEEE80211_SEQ_SEQ_MASK) >> IEEE80211_SEQ_SEQ_SHIFT;

    do {
        bool create_new_node = TRUE;

        /* Always remove the old client node. Otherwise, station count can be wrong */
        if (ni != vap->iv_bss)  {
#if ATH_SUPPORT_SPLITMAC
            if (vap->iv_splitmac) {
                IEEE80211_NODE_STATE_LOCK(ni);
                if(ni->splitmac_state == IEEE80211_SPLITMAC_ASSOC_RESP_START) {
                    IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH, wh->i_addr2,
                       "recv auth frame when assoc is in progress %d\n",frame_seq);
                    IEEE80211_NODE_STATE_UNLOCK(ni);
                    return -1;
                }
                IEEE80211_NODE_STATE_UNLOCK(ni);
            }
#endif
            if(mlme_recv_auth_ap_handle_duplicate(ni, algo, seq, frame_seq, &create_new_node))
                return -1;
        }

        if (create_new_node) {
            /* create a node for the station */

            /*
             * If the VAP is in forced paused state, then we cannot create
             * a new node because of synchronization issues. i.e. the vap is
             * in forced paused state but this new node is in unpause state.
             * But the P2P station client should not be sending packets during
             * NOA sleep anyway. So, refused this connection.
             * If the VAP is in paused state, then we also cannot create
             * a new node because of sync. issues. i.e. there may be another thread
             * that is unpausing this VAP and our new node creation may be
             * corrupted since these 2 threads are not synchronized.
             */
            if ((ieee80211_vap_is_force_paused(vap)) ||
                (ieee80211_vap_is_paused(vap)))
            {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s: Reject this Auth since VAP is in pause or forced paused.\n",
                                  __func__);
                indication_status = IEEE80211_STATUS_OTHER;
                return -1;
            }

            ni = ieee80211_dup_bss(vap, wh->i_addr2);
            if (ni == NULL) {
                indication_status = IEEE80211_STATUS_OTHER;
                return -1;
            }

            /* update the last auth frame sequence number */
            ni->ni_last_rxauth_seq = frame_seq;
            ni->ni_last_auth_rx_time = OS_GET_TIMESTAMP();

            /* override bss authmode for shared auth request algorithm*/
            if (algo  == IEEE80211_AUTH_ALG_SHARED)
                ni->ni_authmode = IEEE80211_AUTH_SHARED;
        } else {
           ieee80211_ref_node(ni);
        }

        /* Validate algo */
        if (algo == IEEE80211_AUTH_ALG_SHARED && !RSN_AUTH_IS_SHARED_KEY(&vap->iv_rsn)) {
            response_status = IEEE80211_STATUS_ALG;
            indication_status = IEEE80211_STATUS_ALG;
            break;
        }

        if (algo == IEEE80211_AUTH_ALG_OPEN && RSN_AUTH_IS_SHARED_KEY(&vap->iv_rsn) &&
            !RSN_AUTH_IS_OPEN(&vap->iv_rsn)) {
            response_status = IEEE80211_STATUS_ALG;
            indication_status = IEEE80211_STATUS_ALG;
            break;
        }

        /*
         * Consult the ACL policy module if setup.
         */
        if (!ieee80211_acl_check(vap, wh->i_addr2)) {
#if ATH_BAND_STEERING
            if(!(ieee80211_acl_flag_check(vap, wh->i_addr2, IEEE80211_ACL_FLAG_AUTH_ALLOW))) {
#endif /* ATH_BAND_STEERING */
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACL,
                        "[%s] auth: disallowed by ACL \n",ether_sprintf(wh->i_addr2));
                response_status = IEEE80211_STATUS_REFUSED;
                indication_status = IEEE80211_STATUS_REFUSED;
                IEEE80211_DELIVER_EVENT_BLKLST_STA_AUTH_INDICATION(vap, wh->i_addr2, indication_status); 
                vap->iv_stats.is_rx_acl++;
                break;
#if ATH_BAND_STEERING
            } else {
                ieee80211_bsteering_send_auth_allow_event(vap, wh->i_addr2, rs->rs_rssi);
            }
#endif /* ATH_BAND_STEERING */
        }
        if (IEEE80211_VAP_IS_COUNTERM_ENABLED(vap)) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH | IEEE80211_MSG_CRYPTO,
                              "[%s] auth: TKIP countermeasures enabled \n",ether_sprintf(wh->i_addr2));
            vap->iv_stats.is_rx_auth_countermeasures++;
            response_status = IEEE80211_REASON_MIC_FAILURE;
            indication_status = IEEE80211_STATUS_REFUSED;
            break;
        }
        /*
         * reject auth if there are too many STAs already associated.
         */
        if (vap->iv_sta_assoc >= vap->iv_max_aid) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
                              "[%s] num auth'd STAs is %d, max is %d, rejecting "
                              "new auth\n", ether_sprintf(wh->i_addr2),
                              vap->iv_sta_assoc, vap->iv_max_aid);

            response_status = IEEE80211_STATUS_TOOMANY;
            indication_status = IEEE80211_STATUS_TOOMANY;
            break;
        }
        if (algo == IEEE80211_AUTH_ALG_OPEN) {
            if (seq != IEEE80211_AUTH_OPEN_REQUEST) {
                response_status = IEEE80211_STATUS_SEQUENCE;
                indication_status = IEEE80211_STATUS_SEQUENCE;
                break;
            }
        } else if (algo == IEEE80211_AUTH_ALG_SHARED) {
            response_status = indication_status = mlme_auth_shared(ni,seq,status_code,challenge,challenge_length);
            send_auth_response=false;
            if (seq == IEEE80211_AUTH_SHARED_REQUEST && response_status == IEEE80211_STATUS_SUCCESS)
                indicate=false;
            break;
        } else if(algo == IEEE80211_AUTH_ALG_FT) {
                /* TODO: decide what all need to be done for FT frame */
                /*response_status =;
                  indication_status = ;
                  send_auth_response=;
                  indicate=;
                  vap->iv_stats.xxxx++*/
            break;
        }
#if UMAC_SUPPORT_FILS
        else if(algo == IEEE80211_AUTH_ALG_FILS_SK ||
                  algo == IEEE80211_AUTH_ALG_FILS_SK_PFS ||
                  algo == IEEE80211_AUTH_ALG_FILS_PK) {
            /* Any specific handling required for FILS Auth */
            break;
        }
#endif
        else {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH | IEEE80211_MSG_CRYPTO,
                              "[%s] auth: unsupported algorithm %d \n",ether_sprintf(wh->i_addr2),algo);
            vap->iv_stats.is_rx_auth_unsupported++;
            response_status = IEEE80211_STATUS_ALG;
            indication_status = IEEE80211_STATUS_ALG;
            break;
        }
    } while (FALSE);

    if (indicate ) {
        IEEE80211_DELIVER_EVENT_MLME_AUTH_INDICATION(vap, ni->ni_macaddr,
                                                         indication_status);
    }

#if ATH_BAND_STEERING
    if (response_status != IEEE80211_STATUS_SUCCESS) {
        ieee80211_bsteering_send_auth_fail_event(vap, wh->i_addr2, rs->rs_rssi);
    }
#else
    // To silence compiler warning about unused variable.
    (void) rs;
#endif /* ATH_BAND_STEERING */

    if (ieee80211_vap_trigger_mlme_resp_is_set(vap)) {
        /* Wait for application to trigger mlme response for auth */
        ni->ni_authalg = algo;
        ni->ni_authstatus = response_status;
    } else {
        if (send_auth_response) {
            ieee80211_send_auth(ni, seq + 1, response_status, NULL, 0, NULL);
        }

        IEEE80211_DELETE_NODE_TARGET(ni, ni->ni_ic, vap, 0);
        if (indication_status != IEEE80211_STATUS_SUCCESS ){
            /* auth is not success, remove the node from node table*/
            IEEE80211_NODE_LEAVE(ni);
        }
    }

#if UMAC_SUPPORT_ACL
    if ((response_status == IEEE80211_STATUS_REFUSED) && (vap->iv_assoc_denial_notify)){
            IEEE80211_DELIVER_ASSOC_DENIAL_EVENT(vap, ni->ni_macaddr);
    }
#endif /*UMAC_SUPPORT_ACL*/
    /*
     * release the reference created at the begining of the case above
     * either by alloc_node or ref_node.
     */
    ieee80211_free_node(ni);
    return 0;
}

void
ieee80211_mlme_node_leave_ap(struct ieee80211_node *ni)
{
    struct ieee80211vap         *vap = ni->ni_vap;
    struct ieee80211_mlme_priv  *mlme_priv;
    ieee80211_mlme_event          event;

    ASSERT(vap != NULL);
    ASSERT(vap->iv_opmode != IEEE80211_M_STA);

    mlme_priv = vap->iv_mlme_priv;
    event.u.event_sta.sta_count= vap->iv_sta_assoc;
    event.u.event_sta.sta_ps_count= vap->iv_ps_sta;
    event.u.event_sta.ni = ni;

    event.type = IEEE80211_MLME_EVENT_STA_LEAVE;
    ieee80211_mlme_deliver_event(mlme_priv,&event);

    /* NB: preserve ni_table */
    if (ieee80211node_has_flag(ni, IEEE80211_NODE_PWR_MGT)) {

        vap->iv_ps_sta--;
        ieee80211node_clear_flag(ni, IEEE80211_NODE_PWR_MGT);

        event.u.event_sta.sta_ps_count= vap->iv_ps_sta;
        event.type = IEEE80211_MLME_EVENT_STA_EXIT_PS;
        ieee80211_mlme_deliver_event(mlme_priv,&event);
    }


}

void
ieee80211_mlme_node_pwrsave_ap(struct ieee80211_node *ni, int enable)
{
    struct ieee80211vap *vap = ni->ni_vap;

    struct ieee80211com *ic = ni->ni_ic;

    ieee80211_mlme_event          event;

    if  ( ((ni->ni_flags & IEEE80211_NODE_PWR_MGT) != 0) ^ enable) {
        struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;

        if (enable) {
            vap->iv_ps_sta++;
            ni->ni_flags |= IEEE80211_NODE_PWR_MGT;
#ifdef ATH_SWRETRY
            if (ic->ic_node_psupdate) {
                ic->ic_node_psupdate(ni, 1, 1);
                IEEE80211_NOTE(vap, IEEE80211_MSG_POWER, ni, "%s", "pause LMAC node\n");
            }
#endif
            IEEE80211_NOTE(vap, IEEE80211_MSG_POWER, ni,
                           "power save mode on, %u sta's in ps mode\n", vap->iv_ps_sta);
            ieee80211node_pause(ni);
            event.type = IEEE80211_MLME_EVENT_STA_ENTER_PS;
        } else {

            vap->iv_ps_sta--;
            ni->ni_flags &= ~IEEE80211_NODE_PWR_MGT;
#ifdef ATH_SWRETRY
            if (ic->ic_node_psupdate) {
                ic->ic_node_psupdate(ni, 0, 1);
                IEEE80211_NOTE(vap, IEEE80211_MSG_POWER, ni, "%s", "unpause LMAC node\n");
            }
#endif
            ieee80211node_unpause(ni);
            IEEE80211_NOTE(vap, IEEE80211_MSG_POWER, ni,
                           "power save mode off, %u sta's in ps mode\n", vap->iv_ps_sta);
            event.type = IEEE80211_MLME_EVENT_STA_EXIT_PS;

			/*
			 * Enable aggregation back after the client exit from power-save
			 */
			if(ni && ni->ni_pspoll) {
				systime_t current_time = OS_GET_TIMESTAMP();
				ic->ic_node_pspoll(ni, 0);
#ifdef ATH_SUPPORT_QUICK_KICKOUT
				if (CONVERT_SYSTEM_TIME_TO_MS(current_time - ni->ni_pspoll_time) > (IEEE80211_PSPOLL_KICKOUT_THR)) {
                    ni->ni_kickout = true;
				}
                /* Revisit later, this reset of ni_pspoll_time to be moved to inactivity phase */
#endif
				ni->ni_pspoll_time = 0;
			}


        }

        event.u.event_sta.sta_count= vap->iv_sta_assoc;
        event.u.event_sta.sta_ps_count= vap->iv_ps_sta;
        event.u.event_sta.ni = ni;
        ieee80211_mlme_deliver_event(mlme_priv,&event);
    }
}


#endif /* UMAC_SUPPORT_AP */
