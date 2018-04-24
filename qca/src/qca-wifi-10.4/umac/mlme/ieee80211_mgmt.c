/*
 * Copyright (c) 2011, 2017 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * Copyright (c) 2008 Atheros Communications Inc.
 * All Rights Reserved.
 *
 * 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 *
 *  management processing code common for all opmodes.
 */
#include "ieee80211_mlme_priv.h"
#include "ieee80211_wds.h"
#include <ieee80211_admctl.h>
#include "osif_private.h"
#if ATH_SUPPORT_WIFIPOS
#include <ath_dev.h>
#include "ieee80211_wifipos_pvt.h"
#endif
#ifdef ATH_SUPPORT_HTC
#include <ieee80211_target.h>
#endif
#include "dfs_ioctl.h"
/*
 * xmit management processing code.
 */

/*
 * Set the direction field and address fields of an outgoing
 * non-QoS frame.  Note this should be called early on in
 * constructing a frame as it sets i_fc[1]; other bits can
 * then be or'd in.
 */
void
ieee80211_send_setup(
    struct ieee80211vap *vap,
    struct ieee80211_node *ni,
    struct ieee80211_frame *wh,
    u_int8_t type,
    const u_int8_t *sa,
    const u_int8_t *da,
    const u_int8_t *bssid)
{
#define WH4(wh)((struct ieee80211_frame_addr4 *)wh)

    wh->i_fc[0] = IEEE80211_FC0_VERSION_0 | type;
    if ((type & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_DATA) {
        switch (vap->iv_opmode) {
        case IEEE80211_M_STA:
            wh->i_fc[1] = IEEE80211_FC1_DIR_TODS;
            IEEE80211_ADDR_COPY(wh->i_addr1, bssid);
            IEEE80211_ADDR_COPY(wh->i_addr2, sa);
            IEEE80211_ADDR_COPY(wh->i_addr3, da);
            break;
        case IEEE80211_M_IBSS:
        case IEEE80211_M_AHDEMO:
            wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
            IEEE80211_ADDR_COPY(wh->i_addr1, da);
            IEEE80211_ADDR_COPY(wh->i_addr2, sa);
            IEEE80211_ADDR_COPY(wh->i_addr3, bssid);
            break;
        case IEEE80211_M_HOSTAP:
            wh->i_fc[1] = IEEE80211_FC1_DIR_FROMDS;
            IEEE80211_ADDR_COPY(wh->i_addr1, da);
            IEEE80211_ADDR_COPY(wh->i_addr2, bssid);
            IEEE80211_ADDR_COPY(wh->i_addr3, sa);
            break;
        case IEEE80211_M_WDS:
            wh->i_fc[1] = IEEE80211_FC1_DIR_DSTODS;
            /* XXX cheat, bssid holds RA */
            IEEE80211_ADDR_COPY(wh->i_addr1, bssid);
            IEEE80211_ADDR_COPY(wh->i_addr2, vap->iv_myaddr);
            IEEE80211_ADDR_COPY(wh->i_addr3, da);
            IEEE80211_ADDR_COPY(WH4(wh)->i_addr4, sa);
            break;
        default:/* NB: to quiet compiler */
            break;
        }
    } else {
        wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
        IEEE80211_ADDR_COPY(wh->i_addr1, da);
        IEEE80211_ADDR_COPY(wh->i_addr2, sa);
        IEEE80211_ADDR_COPY(wh->i_addr3, bssid);
    }
    *(u_int16_t *)&wh->i_dur[0] = 0;
    /* NB: use non-QoS tid */
    /* to avoid sw generated frame sequence the same as H/W generated frame,
     * the value lower than min_sw_seq is reserved for HW generated frame */
    if ((ni->ni_txseqs[IEEE80211_NON_QOS_SEQ]& IEEE80211_SEQ_MASK) < MIN_SW_SEQ){
        ni->ni_txseqs[IEEE80211_NON_QOS_SEQ] = MIN_SW_SEQ;
    }
    *(u_int16_t *)&wh->i_seq[0] =
        htole16(ni->ni_txseqs[IEEE80211_NON_QOS_SEQ] << IEEE80211_SEQ_SEQ_SHIFT);
    ni->ni_txseqs[IEEE80211_NON_QOS_SEQ]++;
#undef WH4
}

/* If there is an uplink connection then propagate the RCSA
 * else behave as if radar is detected and send CSA
 */
void
ieee80211_process_external_radar_detect(struct ieee80211_node *ni)
{
    struct ieee80211com  *ic = ni->ni_ic;

    if (!IEEE80211_IS_CHAN_SWITCH_STARTED(ic))
    {
        struct ieee80211vap *stavap = NULL;
        IEEE80211_CHAN_SWITCH_START(ic);
        STA_VAP_DOWNUP_LOCK(ic);
        stavap = ic->ic_sta_vap;
        if(stavap && ieee80211_vap_ready_is_set(stavap)) {
            /* Propagate RCSA */
            IEEE80211_DPRINTF(stavap, IEEE80211_MSG_MLME,
                    "%s: Uplink is present so sent it to uplink\n",__func__);
            ic->ic_dfs_rx_rcsa(ic);
        } else {
            /* Simulate RADAR and send CSA */
            IEEE80211_DPRINTF(stavap, IEEE80211_MSG_MLME,
                    "%s: Uplink NOT  present This must be a root simulate a local radar detect\n",__func__);
            ic->ic_dfs_control(ic,DFS_BANGRADAR,NULL,0,NULL,NULL);
        }
        STA_VAP_DOWNUP_UNLOCK(ic);
    }
}

wbuf_t
ieee80211_getmgtframe(struct ieee80211_node *ni, int subtype, u_int8_t **frm, u_int8_t isboardcast)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf;
    struct ieee80211_frame *wh;
    u_int8_t broadcast_addr[IEEE80211_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);
    if (wbuf == NULL)
        return NULL;

    /* setup the wireless header */
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    if (isboardcast) {
        subtype = IEEE80211_FC0_SUBTYPE_ACTION;
        ieee80211_send_setup(vap, ni, wh, IEEE80211_FC0_TYPE_MGT | subtype,
                             vap->iv_myaddr, broadcast_addr, ni->ni_bssid);
    } else {
        ieee80211_send_setup(vap, ni, wh, IEEE80211_FC0_TYPE_MGT | subtype,
                             vap->iv_myaddr, ni->ni_macaddr, ni->ni_bssid);
    }
    *frm = (u_int8_t *)&wh[1];
    return wbuf;
}

int
ieee80211_send_mgmt(struct ieee80211vap *vap,struct ieee80211_node *ni, wbuf_t wbuf, bool force_send)
{
    struct ieee80211com      *ic = vap->iv_ic;
    u_int8_t  subtype;
    int retval;
    struct ieee80211_frame *wh;

    wbuf_set_node(wbuf, ieee80211_ref_node(ni));
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);

    /*
     * if forced sleep is set then turn on the powersave
     * bit on all management except for the probe request.
     */
    if (ieee80211_vap_forced_sleep_is_set(vap)) {
        subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

        if (subtype != IEEE80211_FC0_SUBTYPE_PROBE_REQ) {
            wh->i_fc[1] |= IEEE80211_FC1_PWR_MGT;
            wbuf_set_pwrsaveframe(wbuf);
        }
    }

    /*
     * call registered function to add any additional IEs.
     */
    if (vap->iv_output_mgmt_filter) {
        if (vap->iv_output_mgmt_filter(wbuf)) {
            /*
             * filtered out and freed by the filter function,
             * nothing to do, just return.
             */
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_POWER,
                              "[%s] frame filtered out; do not send\n",
                              __func__);
            return EOK;
        }
    }
    vap->iv_lastdata = OS_GET_TIMESTAMP();

    ieee80211_sta_power_tx_start(vap);
#if 0
if (wbuf_is_keepalive(wbuf)){
        if (force_send)
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n the force_send is set\n");
        if(ieee80211node_has_flag(ni,IEEE80211_NODE_PWR_MGT)){
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n powersave node\n");
            for (int i = 0; i < 6; i++) {
                QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%02x:", ni->ni_macaddr[i]);
            }

            }
    }
#endif
    /*
     * do not sent the frame is node is in power save (or) if the vap is paused
     * and the frame is is not marked as special force_send frame, and if the node
     * is temporary, don't do pwrsave
     */
    if (!force_send &&
          (ieee80211node_is_paused(ni)) &&
          !ieee80211node_has_flag(ni, IEEE80211_NODE_TEMP)) {
#if !LMAC_SUPPORT_POWERSAVE_QUEUE
        wbuf_set_node(wbuf, NULL);
#endif
        ieee80211node_pause(ni); /* pause it to make sure that no one else unpaused it after the node_is_paused check above, pause operation is ref counted */
        ieee80211_node_saveq_queue(ni,wbuf,IEEE80211_FC0_TYPE_MGT);
        ieee80211node_unpause(ni); /* unpause it if we are the last one, the frame will be flushed out */
#if !LMAC_SUPPORT_POWERSAVE_QUEUE
        ieee80211_free_node(ni);
#endif
        ieee80211_sta_power_tx_end(vap);
#if !LMAC_SUPPORT_POWERSAVE_QUEUE
        return EOK;
#endif
    }
    /*
     * if the vap is not ready drop the frame.
     */
    if (!ieee80211_vap_active_is_set(vap) && !vap->iv_special_vap_mode) {
        struct ieee80211_tx_status ts;
        ts.ts_flags = IEEE80211_TX_ERROR;
        ts.ts_retries=0;
        /*
         * complete buf will decrement the pending count.
         */
        ieee80211_complete_wbuf(wbuf,&ts);
        ieee80211_sta_power_tx_end(vap);
        return EOK;
    }

    retval = ic->ic_mgtstart(ic, wbuf);
    ieee80211_sta_power_tx_end(vap);

    return retval;
}

/*
 * Send a null data frame to the specified node.
 */
#if ATH_SUPPORT_WIFIPOS
int ieee80211_send_nulldata(struct ieee80211_node *ni, int pwr_save)
{
    return ieee80211_send_nulldata_keepalive(ni, pwr_save, 0);
}
int ieee80211_send_nulldata_keepalive(struct ieee80211_node *ni, int pwr_save, int keepalive)
#else
int ieee80211_send_nulldata(struct ieee80211_node *ni, int pwr_save)
#endif
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf;
    struct ieee80211_frame *wh;
    if(ieee80211_chan2ieee(ic,ieee80211_get_home_channel(vap)) !=
          ieee80211_chan2ieee(ic,ieee80211_get_current_channel(ic)))
	{

		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
				  "%s[%d] cur chan %d flags 0x%x  is not same as home chan %d flags 0x%x \n",
				  __func__, __LINE__,
                          ieee80211_chan2ieee(ic, ic->ic_curchan),ieee80211_chan_flags(ic->ic_curchan),
                          ieee80211_chan2ieee(ic, vap->iv_bsschan), ieee80211_chan_flags(vap->iv_bsschan));
		return EOK;
	}

    /*
     * XXX: It's the same as a management frame in the sense that
     * both are self-generated frames.
     */
    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, sizeof(struct ieee80211_frame));
    if (wbuf == NULL)
        return -ENOMEM;

    /* setup the wireless header */
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    ieee80211_send_setup(vap, ni, wh,
                         IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_NODATA,
                         vap->iv_myaddr, ieee80211_node_get_macaddr(ni),
                         ieee80211_node_get_bssid(ni));
    wbuf_set_qosnull(wbuf);
    /* NB: power management bit is never sent by an AP */
    if (pwr_save &&
        (vap->iv_opmode == IEEE80211_M_STA ||
         vap->iv_opmode == IEEE80211_M_IBSS)) {
        wh->i_fc[1] |= IEEE80211_FC1_PWR_MGT;
        wbuf_set_pwrsaveframe(wbuf);
    }

    if (vap->iv_ccx_evtable && vap->iv_ccx_evtable->wlan_ccx_vperf_pause){
        vap->iv_ccx_evtable->wlan_ccx_vperf_pause(vap->iv_ccx_arg, pwr_save);
    }

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG | IEEE80211_MSG_DUMPPKTS,
                      "[%s] send null data frame on channel %u, pwr mgt %s\n",
                      ether_sprintf(ni->ni_macaddr),
                      ieee80211_chan2ieee(ic, ic->ic_curchan),
                      wh->i_fc[1] & IEEE80211_FC1_PWR_MGT ? "ena" : "dis");

#if ATH_SUPPORT_WIFIPOS
    if(keepalive) {
        if(vap->iv_wakeup & 0x4)
            wh->i_fc[1] |= IEEE80211_FC1_MORE_DATA;
        wbuf_set_keepalive(wbuf);
    }
#endif
#if ATH_BAND_STEERING
    if(ni->ni_ext_flags & IEEE80211_NODE_BSTEERING_CAPABLE) {
        wbuf_set_bsteering(wbuf);
    }
#endif
    wbuf_set_pktlen(wbuf, sizeof(struct ieee80211_frame));
    wbuf_set_priority(wbuf, WME_AC_VO);
    wbuf_set_tid(wbuf, WME_AC_TO_TID(WME_AC_VO));

    vap->iv_lastdata = OS_GET_TIMESTAMP();
    /* null data  can not go out if the vap is in forced pause state */
    if (ieee80211_vap_is_force_paused(vap)) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_POWER,
                          "[%s] queue null data frame the vap is in forced pause state\n",__func__);
        ieee80211_node_saveq_queue(ni,wbuf,IEEE80211_FC0_TYPE_MGT);
#if LMAC_SUPPORT_POWERSAVE_QUEUE
        /* force the frame to reach LMAC pwrsaveq */
        return ieee80211_send_mgmt(vap,ni, wbuf, true);
#endif
        return EOK;
    } else {
       if (vap->iv_opmode == IEEE80211_M_STA ||
           vap->iv_opmode == IEEE80211_M_IBSS) {
           /* force send null data */
           return ieee80211_send_mgmt(vap,ni, wbuf, true);
       }
       else {
           /* allow power save for null data */
#if ATH_SUPPORT_WIFIPOS
        if(keepalive) {
                return ieee80211_send_mgmt(vap,ni, wbuf, true);
            } else {
                return ieee80211_send_mgmt(vap,ni, wbuf, false);
            }
#else
           return ieee80211_send_mgmt(vap,ni, wbuf, false);
#endif
       }
    }
}


/*
 * Send a probe request frame with the specified ssid
 * and any optional information element data.
 */
int
ieee80211_send_probereq(
    struct ieee80211_node *ni,
    const u_int8_t        *sa,
    const u_int8_t        *da,
    const u_int8_t        *bssid,
    const u_int8_t        *ssid,
    const u_int32_t       ssidlen,
    const void            *optie,
    const size_t          optielen)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf;
    enum ieee80211_phymode mode;
    struct ieee80211_frame *wh;
    struct ieee80211_bwnss_map nssmap;
    u_int8_t *frm;
    u_int8_t rx_chainmask = ieee80211com_get_rx_chainmask(ic);

    qdf_mem_zero(&nssmap, sizeof(nssmap));

    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);
    if (wbuf == NULL)
        return -ENOMEM;

    /* setup the wireless header */
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    ieee80211_send_setup(vap, ni, wh,
                         IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_PROBE_REQ,
                         sa, da, bssid);
    frm = (u_int8_t *)&wh[1];

    /*
     * prreq frame format
     *[tlv] ssid
     *[tlv] supported rates
     *[tlv] extended supported rates
     *[tlv] HT Capabilities
     *[tlv] VHT Capabilities
     *[tlv] user-specified ie's
     */
    frm = ieee80211_add_ssid(frm, ssid, ssidlen);
    mode = ieee80211_get_current_phymode(ic);
    /* XXX: supported rates or operational rates? */
    frm = ieee80211_add_rates(frm, &vap->iv_op_rates[mode]);
    frm = ieee80211_add_xrates(frm, &vap->iv_op_rates[mode]);

     /* 11ac or  11n  and ht allowed for this vap */
    if ((IEEE80211_IS_CHAN_11AC(ic->ic_curchan) ||
        IEEE80211_IS_CHAN_11N(ic->ic_curchan)) &&
        ieee80211vap_htallowed(vap)) {

        frm = ieee80211_add_htcap(frm, ni, IEEE80211_FC0_SUBTYPE_PROBE_REQ);

        if (IEEE80211_IS_HTVIE_ENABLED(ic)) {
            frm = ieee80211_add_htcap_vendor_specific(frm, ni, IEEE80211_FC0_SUBTYPE_PROBE_REQ);
        }

        frm = ieee80211_add_extcap(frm, ni);
    }
    if ((IEEE80211_IS_CHAN_11AC(ic->ic_curchan) || IEEE80211_IS_CHAN_11NG(ic->ic_curchan)) &&
                           ieee80211vap_vhtallowed(vap)) {
        /* Add VHT capabilities IE */
        frm = ieee80211_add_vhtcap(frm, ni, ic, IEEE80211_FC0_SUBTYPE_PROBE_REQ, NULL, NULL);
    }
    /* Add Bandwidth-NSS Mapping in Probe*/
    if (!(vap->iv_ext_nss_support) && !(ic->ic_disable_bwnss_adv) && !ieee80211_get_bw_nss_mapping(vap, &nssmap, rx_chainmask)) {
        frm = ieee80211_add_bw_nss_maping(frm, &nssmap);
    }

    if (optie != NULL) {
        OS_MEMCPY(frm, optie, optielen);
        frm += optielen;
    }

    IEEE80211_VAP_LOCK(vap);
    if (vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBEREQ].length) {
        OS_MEMCPY(frm, vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBEREQ].ie,
                  vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBEREQ].length);
        frm += vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBEREQ].length;
    }
    /* Add the Application IE's */
    frm = ieee80211_mlme_app_ie_append(vap, IEEE80211_FRAME_TYPE_PROBEREQ, frm);
    IEEE80211_VAP_UNLOCK(vap);

    wbuf_set_pktlen(wbuf, (frm - (u_int8_t *)wbuf_header(wbuf)));
    /*
     * send the frame out even if the vap is opaused.
     */
    return ieee80211_send_mgmt(vap,ni, wbuf,true);
}

#define AUTH_TX_XRETRY_THRESHOLD 10
static void ieee80211_mgmt_frame_complete_handler(wlan_if_t vap, wbuf_t wbuf,void *arg,
        u_int8_t *dst_addr, u_int8_t *src_addr, u_int8_t *bssid,
        ieee80211_xmit_status *ts)
{
    struct ieee80211_node *ni = (struct ieee80211_node *)arg;
    struct ieee80211_frame *wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    int subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;;

    if (ni &&(vap->iv_opmode == IEEE80211_M_HOSTAP) &&
            ((subtype == IEEE80211_FC0_SUBTYPE_AUTH) && (ts->ts_flags == IEEE80211_TX_XRETRY)) &&
            !(ni->ni_flags & IEEE80211_NODE_LEAVE_ONGOING)){
        if(vap->iv_ic->ic_auth_tx_xretry  < AUTH_TX_XRETRY_THRESHOLD) {
            vap->iv_ic->ic_auth_tx_xretry++;
            ni->ni_node_esc = true;
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH, "%s : ni = 0x%p ni->ni_macaddr = %s ic_auth_tx_xretry = %d\n",
                    __func__, ni, ether_sprintf(ni->ni_macaddr), vap->iv_ic->ic_auth_tx_xretry);
        } else {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH, "%s : ni = 0x%p ni_macaddr = %s ic_auth_tx_xretry = %d\n",
                    __func__, ni, ether_sprintf(ni->ni_macaddr), vap->iv_ic->ic_auth_tx_xretry);
            IEEE80211_NODE_LEAVE(ni);
        }
    }
    return;
}


/*
 * Send a authentication frame
 */
int
ieee80211_send_auth(
    struct ieee80211_node *ni,
    u_int16_t seq,
    u_int16_t status,
    u_int8_t *challenge_txt,
    u_int8_t challenge_len,
    struct ieee80211_app_ie_t* optie
    )
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211_rsnparms *rsn;
    wbuf_t wbuf;
    struct ieee80211_frame *wh;
    u_int8_t *frm;

    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);
    if (wbuf == NULL)
        return -ENOMEM;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
                          "[%s] send auth frmae \n ", ether_sprintf(ni->ni_macaddr));

    /* setup the wireless header */
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    ieee80211_send_setup(vap, ni, wh,
                         IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_AUTH,
                         vap->iv_myaddr, ni->ni_macaddr, ni->ni_bssid);
    frm = (u_int8_t *)&wh[1];

    /*
     * auth frame format
     *[2] algorithm
     *[2] sequence
     *[2] status
     *[tlv*] challenge
     */
    // MP
    // Regardless of iv_opmode, we should always take iv_rsn
    // because of iv_rsn is our configuration. so commenting
    // below line and correct code in next line
    // rsn = (vap->iv_opmode == IEEE80211_M_STA) ? &vap->iv_rsn : &vap->iv_bss->ni_rsn;
    rsn = &vap->iv_rsn;

    /* when auto auth is set in ap dont send shared auth response
     * for open auth request. In sta mode send shared auth response
     *  only mode is shared and ni == vap->iv_bss
     */

    if (RSN_AUTH_IS_SHARED_KEY(rsn) && (ni == vap->iv_bss || ni->ni_authmode == IEEE80211_AUTH_SHARED)) {
        *((u_int16_t *)frm) = htole16(IEEE80211_AUTH_ALG_SHARED);
        frm += 2;
    } else {
        *((u_int16_t *)frm) = htole16(ni->ni_authalg);
        frm += 2;
    }
    *((u_int16_t *)frm) = htole16(seq); frm += 2;
    *((u_int16_t *)frm) = htole16(status); frm += 2;
    if (challenge_txt != NULL && challenge_len != 0) {
        ASSERT(RSN_AUTH_IS_SHARED_KEY(rsn));

        *((u_int16_t *)frm) = htole16((challenge_len << 8) | IEEE80211_ELEMID_CHALLENGE);
        frm += 2;
        OS_MEMCPY(frm, challenge_txt, challenge_len);
        frm += challenge_len;

        if (seq == IEEE80211_AUTH_SHARED_RESPONSE) {
            /* We also need to turn on WEP bit of the frame */
            wh->i_fc[1] |= IEEE80211_FC1_WEP;
        }
    }

    IEEE80211_VAP_LOCK(vap);
    if (vap->iv_app_ie[IEEE80211_FRAME_TYPE_AUTH].length) {
        OS_MEMCPY(frm, vap->iv_app_ie[IEEE80211_FRAME_TYPE_AUTH].ie,
                  vap->iv_app_ie[IEEE80211_FRAME_TYPE_AUTH].length);
        frm += vap->iv_app_ie[IEEE80211_FRAME_TYPE_AUTH].length;
    }
    IEEE80211_VAP_UNLOCK(vap);

    /*
     * Add the optional IE passed to  AP
     */
    if ((optie != NULL) && optie->length) {
        OS_MEMCPY(frm, optie->ie,
                  optie->length);
        frm += optie->length;
    }

    wbuf_set_pktlen(wbuf, (frm - (u_int8_t *)wbuf_header(wbuf)));
    if (ic->ic_is_mode_offload(ic)) {
        /* register complete handler for offload alone as ts argument can be null for DA callback */
        ieee80211_vap_set_complete_buf_handler(wbuf,ieee80211_mgmt_frame_complete_handler,(void *)ni);
    }

    return ieee80211_send_mgmt(vap,ni, wbuf,false);
}

/*
 * Send a deauth frame
 */
int
ieee80211_send_deauth(struct ieee80211_node *ni, u_int16_t reason)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf;
    struct ieee80211_frame *wh;
    u_int8_t *frm, *da;
    u_int8_t broadcast_addr[IEEE80211_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    u_int32_t   frlen=0;

    if (OS_MEMCMP(ni->ni_macaddr, vap->iv_myaddr, IEEE80211_ADDR_LEN) != 0) {
        da = ni->ni_macaddr;
    } else {
        da = broadcast_addr;
    }

    if (ieee80211_is_pmf_enabled(vap, ni)) {
        frlen = sizeof(struct ieee80211_mmie);
    }

    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, (sizeof(struct ieee80211_frame)+frlen));
    if (wbuf == NULL)
        return -ENOMEM;

#if ATH_SUPPORT_WAPI
    if (vap->iv_opmode == IEEE80211_M_STA) {
        if (ieee80211_vap_wapi_is_set(vap)) {
            /* clear the WAPI flag in vap */
            ieee80211_vap_wapi_clear(vap);
        }
    }
#endif

    /* setup the wireless header */
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    ieee80211_send_setup(vap, ni, wh,
                         IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_DEAUTH,
                         vap->iv_myaddr, da, ni->ni_bssid);

    if ((vap->iv_ccx_evtable && vap->iv_ccx_evtable->wlan_ccx_is_mfp &&
        vap->iv_ccx_evtable->wlan_ccx_is_mfp(vap->iv_ifp)) ||
        ((ieee80211_vap_mfp_test_is_set(vap) ||
          ieee80211_is_pmf_enabled(vap, ni)) && ni->ni_ucastkey.wk_valid)){
        if (!(IEEE80211_IS_BROADCAST(wh->i_addr1) || IEEE80211_IS_MULTICAST(wh->i_addr1))) {
            /* MFP is enabled and a key is established. */
            /* We need to turn on WEP bit of the frame */
            wh->i_fc[1] |= IEEE80211_FC1_WEP;
        }
    }

    frm = (u_int8_t *)&wh[1];
    *(u_int16_t *)frm = htole16(reason);
    frm += 2;

    if ((IEEE80211_IS_BROADCAST(wh->i_addr1) || IEEE80211_IS_MULTICAST(wh->i_addr1)) &&
                                             ieee80211_is_pmf_enabled(vap, ni)) {
        u8 *res;
        /* This is a broadcast/Multicast Deauth pkt and MFP is enabled so insert MMIE */
        res = ieee80211_add_mmie(vap,
                           (u_int8_t *)wbuf_header(wbuf),
                           (frm - (u_int8_t *)wbuf_header(wbuf)));
        if (res != NULL) {
            frm = res;
            frlen = (frm - (u_int8_t *)wbuf_header(wbuf));
        }
    } else {
        frlen = (frm - (u_int8_t *)wbuf_header(wbuf));
    }

    frlen = (frm - (u_int8_t *)wbuf_header(wbuf));
    wbuf_set_pktlen(wbuf, frlen);

    if (vap->iv_vap_is_down)
        return ieee80211_send_mgmt(vap, ni, wbuf, true);
    else
        return ieee80211_send_mgmt(vap, ni, wbuf, false);
}

/*
 * Send a disassociate frame
 */
int
ieee80211_send_disassoc(struct ieee80211_node *ni, u_int16_t reason)
{
    int retval;
    retval = ieee80211_send_disassoc_with_callback(ni, reason, NULL, NULL);
    return retval;
}

int ieee80211_send_disassoc_with_callback(struct ieee80211_node *ni, u_int16_t reason,
                                          wlan_vap_complete_buf_handler handler,
                                          void *arg)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf;
    struct ieee80211_frame *wh;
    u_int8_t *frm, *da;
    u_int8_t broadcast_addr[IEEE80211_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    u_int32_t   frlen=0;

    if (OS_MEMCMP(ni->ni_macaddr, vap->iv_myaddr, IEEE80211_ADDR_LEN) != 0) {
        da = ni->ni_macaddr;
    } else {
        da = broadcast_addr;
        if (ieee80211_is_pmf_enabled(vap, ni)) {
            frlen = sizeof(struct ieee80211_mmie);
        }
    }
    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);
    if (wbuf == NULL)
        return -ENOMEM;

#if ATH_SUPPORT_WAPI
    if (vap->iv_opmode == IEEE80211_M_STA) {
        if (ieee80211_vap_wapi_is_set(vap)) {
            /* clear the WAPI flag in vap */
            ieee80211_vap_wapi_clear(vap);
        }
    }
#endif

    /* setup the wireless header */
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    ieee80211_send_setup(vap, ni, wh,
                         IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_DISASSOC,
                         vap->iv_myaddr, da, ni->ni_bssid);

    if ((vap->iv_ccx_evtable && vap->iv_ccx_evtable->wlan_ccx_is_mfp &&
        vap->iv_ccx_evtable->wlan_ccx_is_mfp(vap->iv_ifp)) ||
        ((ieee80211_vap_mfp_test_is_set(vap) ||
              ieee80211_is_pmf_enabled(vap, ni)) && ni->ni_ucastkey.wk_valid)){
        if (!(IEEE80211_IS_BROADCAST(wh->i_addr1) || IEEE80211_IS_MULTICAST(wh->i_addr1))) {
            /* MFP is enabled and a key is established. */
            /* We need to turn on WEP bit of the frame */
            wh->i_fc[1] |= IEEE80211_FC1_WEP;
        }
    }
    frm = (u_int8_t *)&wh[1];
    *(u_int16_t *)frm = htole16(reason);
    frm += 2;

    if ((IEEE80211_IS_BROADCAST(wh->i_addr1) || IEEE80211_IS_MULTICAST(wh->i_addr1)) &&
         (vap->iv_rsn.rsn_caps & RSN_CAP_MFP_ENABLED)){
        u8 *res;
        // This is a broadcast/Multicast Deauth pkt and MFP is enabled so insert MMIE
        res = ieee80211_add_mmie(vap,
                           (u_int8_t *)wbuf_header(wbuf),
                           (frm - (u_int8_t *)wbuf_header(wbuf)));
        if (res != NULL) {
            frm = res;
        }
    }

    if (vap->iv_mesh_mgmt_txsend_config == 0)
    {
        wbuf_set_pktlen(wbuf, (frm - (u_int8_t *)wbuf_header(wbuf)));
         if (handler) {
            ieee80211_vap_set_complete_buf_handler(wbuf, handler, arg);
         }
        if (vap->iv_vap_is_down)
            return ieee80211_send_mgmt(vap, ni, wbuf, true);
        else
            return ieee80211_send_mgmt(vap, ni, wbuf, false);
    } else {
        wbuf_set_pktlen(wbuf, 0);
        if (handler) {
            ieee80211_vap_set_complete_buf_handler(wbuf, handler, arg);
        }
        return ieee80211_send_mgmt(vap, ni, wbuf, false);
    }
}

static int ieee80211_is_robust_action_frame(u_int8_t category)
{
    switch (category) {
        case IEEE80211_ACTION_CAT_SPECTRUM:          /* Spectrum management */
        case IEEE80211_ACTION_CAT_QOS:               /* IEEE QoS  */
        case IEEE80211_ACTION_CAT_DLS:               /* DLS */
        case IEEE80211_ACTION_CAT_BA:                /* BA */
        case IEEE80211_ACTION_CAT_SA_QUERY:          /* SA Query per IEEE802.11w, PMF */
        case IEEE80211_ACTION_CAT_WNM:               /* WNM */
        case IEEE80211_ACTION_CAT_WMM_QOS:           /* QoS from WMM specification */
        case IEEE80211_ACTION_CAT_PROT_DUAL:         /* Protected Dual of Public Action Frames */
        /* TODO: add all robust action categories */
            return 1;
        default:
            return 0;
    }
}

int
ieee80211_send_action(
    struct ieee80211_node *ni,
    struct ieee80211_action_mgt_args *actionargs,
    struct ieee80211_action_mgt_buf  *actionbuf
    )
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf = NULL;
    u_int8_t *frm = NULL;
    int error = EOK;

    switch (actionargs->category) {
#if ATH_SUPPORT_IBSS_DFS
    case IEEE80211_ACTION_CAT_SPECTRUM: {
        struct ieee80211_action_spectrum_channel_switch *csaaction;
        struct ieee80211_action_measrep_header *measrep_header;
        struct ieee80211_measurement_report_ie *measrep_ie;
        struct ieee80211_measurement_report_ie *fill_in_measrep_ie;
        switch(actionargs->action) {
        case IEEE80211_ACTION_CHAN_SWITCH:
            wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 1);
            if (wbuf == NULL) {
                error = -ENOMEM;
                break;
            }

            csaaction = (struct ieee80211_action_spectrum_channel_switch *)frm;
            frm += sizeof(struct ieee80211_action_spectrum_channel_switch);
            csaaction->csa_header.ia_category     = IEEE80211_ACTION_CAT_SPECTRUM;
            csaaction->csa_header.ia_action       = actionargs->action;
            csaaction->csa_element.ie             = IEEE80211_ELEMID_CHANSWITCHANN;
            csaaction->csa_element.len            = IEEE80211_CHANSWITCHANN_BYTES - sizeof(struct ieee80211_ie_header);
            csaaction->csa_element.switchmode     = 1;
            csaaction->csa_element.newchannel     = ic->ic_chanchange_chan;
            csaaction->csa_element.tbttcount      = ic->ic_chanchange_tbtt;

            break;
        case IEEE80211_ACTION_MEAS_REPORT:
            wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 1);
            if (wbuf == NULL) {
                error = -ENOMEM;
                break;
            }

            /* fill header */
            measrep_header = (struct ieee80211_action_measrep_header *)frm;
            frm += sizeof(struct ieee80211_action_measrep_header);
            measrep_header->action_header.ia_category = IEEE80211_ACTION_CAT_SPECTRUM;
            measrep_header->action_header.ia_action   = IEEE80211_ACTION_MEAS_REPORT;
            measrep_header->dialog_token              = actionargs->arg1;  /* always 0 for now */

            /* fill IE */
            if (actionargs->arg4 == NULL) {
                error = -EINVAL;
                break;
            }
            fill_in_measrep_ie = (struct ieee80211_measurement_report_ie *)actionargs->arg4;
            measrep_ie = (struct ieee80211_measurement_report_ie *)frm;
            frm += sizeof(struct ieee80211_measurement_report_ie);
            OS_MEMCPY(measrep_ie, fill_in_measrep_ie, (fill_in_measrep_ie->len + sizeof(struct ieee80211_ie_header)));

        break;
        default:
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: invalid spectrum action mgt frame", __func__);
            error = -EINVAL;
            break;
        }

        break;
    }
#endif /* ATH_SUPPORT_IBSS_DFS */

    case IEEE80211_ACTION_CAT_QOS:
        IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                       "%s: QoS action mgt frames not supported", __func__);
        error = -EINVAL;
        break;

    case IEEE80211_ACTION_CAT_BA: {
        struct ieee80211_action_ba_addbarequest *addbarequest;
        struct ieee80211_action_ba_addbaresponse *addbaresponse;
        struct ieee80211_action_ba_delba *delba;
        struct ieee80211_ba_parameterset baparamset;
        struct ieee80211_ba_seqctrl basequencectrl;
        struct ieee80211_delba_parameterset delbaparamset;
        u_int16_t batimeout;
        u_int16_t statuscode;
        u_int16_t reasoncode;
        u_int16_t buffersize;
        u_int8_t tidno;
        u_int16_t temp;

        /* extract TID */
        tidno = actionargs->arg1;
        switch (actionargs->action) {
        case IEEE80211_ACTION_BA_ADDBA_REQUEST:
            wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
            if (wbuf == NULL) {
                error = -ENOMEM;
                break;
            }

            addbarequest = (struct ieee80211_action_ba_addbarequest *)frm;
            frm += sizeof(struct ieee80211_action_ba_addbarequest);

            addbarequest->rq_header.ia_category     = IEEE80211_ACTION_CAT_BA;
            addbarequest->rq_header.ia_action       = actionargs->action;
            addbarequest->rq_dialogtoken            = tidno + 1;
            buffersize                              = actionargs->arg2;

            ic->ic_addba_requestsetup(ni, tidno,
                                      &baparamset,
                                      &batimeout,
                                      &basequencectrl,
                                      buffersize);
            /* "struct ieee80211_action_ba_addbarequest" is annotated __packed,
               if accessing fields, like rq_baparamset or rq_basequencectrl,
               by using u_int16_t* directly, it will cause byte alignment issue.
               Some platform that cannot handle this issue will cause exception.
               Use OS_MEMCPY to move data byte by byte */
            temp = htole16(*(u_int16_t *)&baparamset);
            OS_MEMCPY(&addbarequest->rq_baparamset, &temp, sizeof(u_int16_t));
            addbarequest->rq_batimeout = htole16(batimeout);
            temp =htole16(*(u_int16_t *)&basequencectrl);
            OS_MEMCPY(&addbarequest->rq_basequencectrl, &temp, sizeof(u_int16_t));

            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: ADDBA request action mgt frame. TID %d, buffer size %d",
                           __func__, tidno, baparamset.buffersize);
            break;

        case IEEE80211_ACTION_BA_ADDBA_RESPONSE:
            wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
            if (wbuf == NULL) {
                error = -ENOMEM;
                break;
            }

            addbaresponse = (struct ieee80211_action_ba_addbaresponse *)frm;
            frm += sizeof(struct ieee80211_action_ba_addbaresponse);

            addbaresponse->rs_header.ia_category    = IEEE80211_ACTION_CAT_BA;
            addbaresponse->rs_header.ia_action      = actionargs->action;

            ic->ic_addba_responsesetup(ni, tidno,
                                       &addbaresponse->rs_dialogtoken,
                                       &statuscode,
                                       &baparamset,
                                       &batimeout);
            /* "struct ieee80211_action_ba_addbaresponse" is annotated __packed,
               if accessing fields, like rs_baparamset, by using u_int16_t* directly,
               it will cause byte alignment issue.
               Some platform that cannot handle this issue will cause exception.
               Use OS_MEMCPY to move data byte by byte */
            temp = htole16(*(u_int16_t *)&baparamset);
            OS_MEMCPY(&addbaresponse->rs_baparamset, &temp, sizeof(u_int16_t));
            addbaresponse->rs_batimeout  = htole16(batimeout);
            addbaresponse->rs_statuscode = htole16(statuscode);

            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: ADDBA response action mgt frame. TID %d, buffer size %d, status %d",
                           __func__, tidno, baparamset.buffersize, statuscode);
            break;

        case IEEE80211_ACTION_BA_DELBA:
            wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
            if (wbuf == NULL) {
                error = -ENOMEM;
                break;
            }

            delba = (struct ieee80211_action_ba_delba *)frm;
            frm += sizeof(struct ieee80211_action_ba_delba);

            delba->dl_header.ia_category = IEEE80211_ACTION_CAT_BA;
            delba->dl_header.ia_action = actionargs->action;

            delbaparamset.reserved0 = 0;
            delbaparamset.initiator = actionargs->arg2;
            delbaparamset.tid = tidno;
            reasoncode = actionargs->arg3;
            /* "struct ieee80211_action_ba_delba" is annotated __packed,
               if accessing fields, like dl_delbaparamset, by using u_int16_t* directly,
               it will cause byte alignment issue.
               Some platform that cannot handle this issue will cause exception.
               Use OS_MEMCPY to move data byte by byte */
            temp = htole16(*(u_int16_t *)&delbaparamset);
            OS_MEMCPY(&delba->dl_delbaparamset, &temp, sizeof(u_int16_t));
            delba->dl_reasoncode = htole16(reasoncode);

            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: DELBA action mgt frame. TID %d, initiator %d, reason %d",
                           __func__, tidno, delbaparamset.initiator, reasoncode);
            break;

        default:
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: invalid BA action mgt frame", __func__);
            error = -EINVAL;
            break;
        }
        break;
    }
    case IEEE80211_ACTION_CAT_HT: {
        struct ieee80211_action_ht_txchwidth *txchwidth;
        struct ieee80211_action_ht_smpowersave *smpsframe;
        switch (actionargs->action) {
        case IEEE80211_ACTION_HT_TXCHWIDTH:
            {
                enum ieee80211_cwm_width cw_width = ic->ic_cwm_get_width(ic);
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: HT txchwidth action mgt frame. Width %d",
                        __func__, cw_width);

            wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
            if (wbuf == NULL) {
                error = -ENOMEM;
                break;
            }
            txchwidth = (struct ieee80211_action_ht_txchwidth *)frm;
            frm += sizeof(struct ieee80211_action_ht_txchwidth);

            txchwidth->at_header.ia_category = IEEE80211_ACTION_CAT_HT;
            txchwidth->at_header.ia_action  = IEEE80211_ACTION_HT_TXCHWIDTH;
                txchwidth->at_chwidth =  (cw_width == IEEE80211_CWM_WIDTH40) ?
                IEEE80211_A_HT_TXCHWIDTH_2040 : IEEE80211_A_HT_TXCHWIDTH_20;
            }
            break;
        case IEEE80211_ACTION_HT_SMPOWERSAVE:
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: HT mimo pwr save action mgt frame", __func__);

            wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
            if (wbuf == NULL) {
                error = -ENOMEM;
                break;
            }
            smpsframe = (struct ieee80211_action_ht_smpowersave *)frm;
            frm += sizeof(struct ieee80211_action_ht_smpowersave);

            smpsframe->as_header.ia_category = IEEE80211_ACTION_CAT_HT;
            smpsframe->as_header.ia_action 	 = IEEE80211_ACTION_HT_SMPOWERSAVE;
            smpsframe->as_control =  (actionargs->arg1 << 0) | (actionargs->arg2 << 1);

            /* Mark frame for appropriate action on completion */
            wbuf_set_smpsactframe(wbuf);
            break;

        default:
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: invalid HT action mgt frame", __func__);
            error = -EINVAL;
            break;
        }
    }
    break;

    case IEEE80211_ACTION_CAT_VHT: {
        struct ieee80211_action_vht_opmode *opmode_frame;
        enum ieee80211_cwm_width cw_width = ic->ic_cwm_get_width(ic);
        IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: VHT Op Mode Notify action frame. Width %d Nss = %d",
                            __func__, cw_width, vap->iv_nss);
        wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
        if (wbuf == NULL) {
            error = -ENOMEM;
            break;
        }
        opmode_frame = (struct ieee80211_action_vht_opmode *)frm;
        opmode_frame->at_header.ia_category = IEEE80211_ACTION_CAT_VHT;
        opmode_frame->at_header.ia_action  = IEEE80211_ACTION_VHT_OPMODE;
        ieee80211_add_opmode((u_int8_t *)&opmode_frame->at_op_mode, ni, ic, IEEE80211_ACTION_CAT_VHT);
        frm += sizeof(struct ieee80211_action_vht_opmode);
    }
    break;

    case IEEE80211_ACTION_CAT_WMM_QOS: {
        struct ieee80211_action_wmm_qos *tsframe;
        struct ieee80211_wme_tspec *tsdata = (struct ieee80211_wme_tspec *) &actionbuf->buf;
        struct ieee80211_frame *wh;
        u_int8_t    tsrsiev[16];
        u_int8_t    tsrsvlen = 0;
        u_int32_t   minphyrate;

        /* TSPEC action mamangement frames */
        switch (actionargs->action) {
        case IEEE80211_WMM_QOS_ACTION_SETUP_REQ:
        case IEEE80211_WMM_QOS_ACTION_SETUP_RESP:
        case IEEE80211_WMM_QOS_ACTION_TEARDOWN:
            wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
            if (wbuf == NULL) {
                error = -ENOMEM;
                break;
            }
            wh = (struct ieee80211_frame*)wbuf_header(wbuf);

            tsframe = (struct ieee80211_action_wmm_qos *)frm;
            tsframe->ts_header.ia_category = actionargs->category;
            tsframe->ts_header.ia_action = actionargs->action;
            tsframe->ts_dialogtoken = actionargs->arg1;
            tsframe->ts_statuscode = actionargs->arg2;
            /* fill in the basic structure for tspec IE */
            frm = ieee80211_add_wmeinfo((u_int8_t *) &tsframe->ts_tspecie, ni,
                                        WME_TSPEC_OUI_SUBTYPE, (u_int8_t *) &tsdata->ts_tsinfo,
                                        sizeof (struct ieee80211_wme_tspec) - offsetof(struct ieee80211_wme_tspec, ts_tsinfo));
            if (vap->iv_opmode != IEEE80211_M_STA) {
                break;
            }
            if (actionargs->action == IEEE80211_WMM_QOS_ACTION_SETUP_REQ) {
                /* Save the tspec to be used in next assoc request */
                if (((struct ieee80211_tsinfo_bitmap *)(&tsdata->ts_tsinfo))->tid == IEEE80211_WMM_QOS_TSID_SIG_TSPEC)
                    OS_MEMCPY(&ic->ic_sigtspec, (u_int8_t *) &tsframe->ts_tspecie, sizeof(struct ieee80211_wme_tspec));
                else
                    OS_MEMCPY(&ic->ic_datatspec, (u_int8_t *) &tsframe->ts_tspecie, sizeof(struct ieee80211_wme_tspec));
#if AH_UNALIGNED_SUPPORTED
                /*
                 * Get unaligned data
                 */
                minphyrate = __get32(&tsdata->ts_min_phy[0]);
#else
                minphyrate = *((u_int32_t *) &tsdata->ts_min_phy[0]);
#endif
                if (vap->iv_ccx_evtable && vap->iv_ccx_evtable->wlan_ccx_fill_tsrsie) {
                    vap->iv_ccx_evtable->wlan_ccx_fill_tsrsie(vap->iv_ccx_arg,
                         ((struct ieee80211_tsinfo_bitmap *) &tsdata->ts_tsinfo[0])->tid,
                         minphyrate, &tsrsiev[0], &tsrsvlen);
                }
                if (tsrsvlen > 0) {
                    *frm++ = IEEE80211_ELEMID_VENDOR;
                    *frm++ = tsrsvlen;
                    OS_MEMCPY(frm, &tsrsiev[0], tsrsvlen);
                    frm += tsrsvlen;
                }
            } else if (actionargs->action == IEEE80211_WMM_QOS_ACTION_TEARDOWN) {
                /* if sending DELTS, wipeout stored TSPECs unconditionally */
                OS_MEMZERO(&ic->ic_sigtspec, sizeof(struct ieee80211_wme_tspec));
                OS_MEMZERO(&ic->ic_datatspec, sizeof(struct ieee80211_wme_tspec));
                /* Disable QoS handling internally */
                wlan_set_tspecActive(vap, 0);
                if (vap->iv_ccx_evtable && vap->iv_ccx_evtable->wlan_ccx_set_vperf) {
                    vap->iv_ccx_evtable->wlan_ccx_set_vperf(vap->iv_ccx_arg, 0);
                }
            }
            break;

        default:
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: invalid WMM QOS action mgt frame", __func__);
            error = -EINVAL;
            break;
        }
    }
        break;

    case IEEE80211_ACTION_CAT_PUBLIC: {
        if (vap->iv_opmode == IEEE80211_M_STA)
        {
            switch(actionargs->action)
            {
            case 0:
                if (!(ic->ic_flags & IEEE80211_F_COEXT_DISABLE)) {
                    IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: HT 2040 coexist action mgt frame.",__func__);

                    do {
                        struct ieee80211_action *header;
                        struct ieee80211_ie_bss_coex *coexist;
                        struct ieee80211_ie_intolerant_report *intolerantchanreport;
                        u_int8_t *p;
                        u_int32_t i;

                        wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
                        if (wbuf == NULL) {
                            error = -ENOMEM;
                            break;
                        }

                        header = (struct ieee80211_action *)frm;
                        header->ia_category = IEEE80211_ACTION_CAT_PUBLIC;
                        header->ia_action = actionargs->action;

                        frm += sizeof(struct ieee80211_action);

                        coexist = (struct ieee80211_ie_bss_coex *)frm;
                        OS_MEMZERO(coexist, sizeof(struct ieee80211_ie_bss_coex));
                        coexist->elem_id = IEEE80211_ELEMID_2040_COEXT;
                        coexist->elem_len = 1;
                        coexist->ht20_width_req = actionargs->arg1;

                        frm += sizeof(struct ieee80211_ie_bss_coex);

                        intolerantchanreport = (struct ieee80211_ie_intolerant_report*)frm;

                        intolerantchanreport->elem_id = IEEE80211_ELEMID_2040_INTOL;
                        intolerantchanreport->elem_len = actionargs->arg3 + 1;
                        intolerantchanreport->reg_class = actionargs->arg2;
                        p = intolerantchanreport->chan_list;
                        for (i=0; i<actionargs->arg3; i++) {
                            *p++ = actionbuf->buf[i];
                        }

                        frm += intolerantchanreport->elem_len + 2;
                    } while (FALSE);

                } else {
                    error = -EINVAL;
                }
                break;
            default:
                IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                   "%s: action mgt frame has invalid action %d", __func__, actionargs->action);
                error = -EINVAL;
                break;
            }
        } else {
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
               "%s: action mgt frame has Invalid opmode %d", __func__, actionargs->action);
            error = -EINVAL;
        }
    }
    break;

    case IEEE80211_ACTION_CAT_SA_QUERY: {
        struct ieee80211_action_sa_query    *saQuery;
        wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
        if (wbuf == NULL) {
            error = -ENOMEM;
            break;
        }

        saQuery = (struct ieee80211_action_sa_query*)frm;
        frm += sizeof(*saQuery);
        saQuery->sa_header.ia_category = actionargs->category;
        saQuery->sa_header.ia_action = actionargs->action;
        saQuery->sa_transId = actionargs->arg1;

    }
    break;

    case IEEE80211_ACTION_CAT_VENDOR: {
        struct ieee80211_action_vendor_specific *ven;
        wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
        if (wbuf == NULL) {
            error = -ENOMEM;
            break;
        }
        ven = (struct ieee80211_action_vendor_specific*)frm;
        ven->ia_category = actionargs->category;
        ven->vendor_oui[0] = 0x00;
        ven->vendor_oui[1] = 0x03;
        ven->vendor_oui[2] = 0x7f;
        frm += sizeof(struct ieee80211_action_vendor_specific);

        switch(actionargs->action) {
        case IEEE80211_ACTION_CHAN_SWITCH: {
            struct ieee80211_channelswitch_ie   *csa_element;
            csa_element = (struct ieee80211_channelswitch_ie *) frm;
            csa_element->ie             = IEEE80211_ELEMID_CHANSWITCHANN;
            csa_element->len            = sizeof(struct ieee80211_channelswitch_ie)
                                         - sizeof(struct ieee80211_ie_header);
            csa_element->switchmode     = 1;
            csa_element->newchannel     = 36; /* ic->ic_chanchange_chan; */
            csa_element->tbttcount      = ic->ic_rcsa_count;
        }
        frm += sizeof(struct ieee80211_channelswitch_ie);
        break;

        default:
        IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                       "%s: vendor specifi action mgt frame has invalid type %d", __func__, actionargs->category);
        error = -EINVAL;
        break;
        }
    }
    break;

    default:
        IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                       "%s: action mgt frame has invalid category %d", __func__, actionargs->category);
        error = -EINVAL;
        break;
    }

    if (error == EOK) {
        ASSERT(wbuf != NULL);
        ASSERT(frm != NULL);

        if (ieee80211_is_robust_action_frame(actionargs->category) &&
            ((vap->iv_ccx_evtable && vap->iv_ccx_evtable->wlan_ccx_is_mfp &&
              vap->iv_ccx_evtable->wlan_ccx_is_mfp(vap->iv_ifp)) ||
             ((ieee80211_vap_mfp_test_is_set(vap) ||
               ieee80211_is_pmf_enabled(vap, ni)) && ni->ni_ucastkey.wk_valid))) {
            struct ieee80211_frame *wh;
            wh = (struct ieee80211_frame*)wbuf_header(wbuf);
            wh->i_fc[1] |= IEEE80211_FC1_WEP;
        }

        wbuf_set_pktlen(wbuf, (frm - (u_int8_t*)wbuf_header(wbuf)));

        error = ieee80211_send_mgmt(vap,ni, wbuf,false);
    }

    return error;
}

#ifdef ATH_SUPPORT_TxBF
int
ieee80211_send_v_cv_action(struct ieee80211_node *ni, u_int8_t *data_buf, u_int16_t buf_len)
{
    struct ieee80211vap *vap = ni->ni_vap;
    wbuf_t wbuf = NULL;
    u_int8_t *frm = NULL;
    int error = 0;

    wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
    if (wbuf == NULL) {
        return -ENOMEM;
    }
    ASSERT(frm != NULL);

    /*Copy V/CV Report*/
    OS_MEMCPY(frm, data_buf, buf_len);
    frm += buf_len;

    wbuf_set_pktlen(wbuf, (frm - (u_int8_t*)wbuf_header(wbuf)));
    error = ieee80211_send_mgmt(vap, ni, wbuf, false);

    return error;
}
#endif

/*
 * Send a BAR frame
 */
int
ieee80211_send_bar(struct ieee80211_node *ni, u_int8_t tidno, u_int16_t seqno)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf;
    struct ieee80211_frame_bar *bar;

    /*
     * XXX: It's the same as a management frame in the sense that
     * both are self-generated frames.
     */
    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);
    if (wbuf == NULL)
        return -ENOMEM;


    /* setup the wireless header */
    bar = (struct ieee80211_frame_bar *)wbuf_header(wbuf);
    bar->i_fc[1] = IEEE80211_FC1_DIR_NODS;
    bar->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_CTL | IEEE80211_FC0_SUBTYPE_BAR;
    bar->i_ctl = htole16((tidno << IEEE80211_BAR_CTL_TID_S) | IEEE80211_BAR_CTL_COMBA);
    bar->i_seq = htole16(seqno << IEEE80211_SEQ_SEQ_SHIFT);
    IEEE80211_ADDR_COPY(bar->i_ra, ni->ni_macaddr);
    IEEE80211_ADDR_COPY(bar->i_ta, vap->iv_myaddr);

    wbuf_set_pktlen(wbuf, sizeof(struct ieee80211_frame_bar));
    wbuf_set_tid(wbuf, tidno);

    return ieee80211_send_mgmt(vap,ni, wbuf,false);
}

/*
 * Send a PS-POLL to the specified node.
 */
int
ieee80211_send_pspoll(struct ieee80211_node *ni)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf;
    struct ieee80211_frame_pspoll *pspoll;

    /*
     * XXX: It's the same as a management frame in the sense that
     * both are self-generated frames.
     */
    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);
    if (wbuf == NULL)
        return -ENOMEM;


    /* setup the wireless header */
    pspoll = (struct ieee80211_frame_pspoll *)wbuf_header(wbuf);
    pspoll->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_CTL | IEEE80211_FC0_SUBTYPE_PS_POLL;
    pspoll->i_fc[1] = IEEE80211_FC1_DIR_NODS | IEEE80211_FC1_PWR_MGT;
    /* Set bits 14 and 15 to 1 when duration field carries Association ID */
    *(u_int16_t *)pspoll->i_aid = htole16(ni->ni_associd | IEEE80211_FIELD_TYPE_AID);
    IEEE80211_ADDR_COPY(pspoll->i_bssid, ni->ni_bssid);
    IEEE80211_ADDR_COPY(pspoll->i_ta, vap->iv_myaddr);

    wbuf_set_pwrsaveframe(wbuf);
    wbuf_set_pktlen(wbuf, sizeof(struct ieee80211_frame_pspoll));

    vap->iv_lastdata = OS_GET_TIMESTAMP();

    /* pspoll can not go out if the vap is in forced pause state */
    if (ieee80211_vap_is_force_paused(vap)) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_POWER,
                          "[%s] queue null data frame the vap is in forced pause state\n",__func__);
        ieee80211_node_saveq_queue(ni,wbuf,IEEE80211_FC0_TYPE_MGT);
#if LMAC_SUPPORT_POWERSAVE_QUEUE
        /* force the frame to reach LMAC pwrsaveq */
        return ieee80211_send_mgmt(vap,ni, wbuf, true);
#endif
        return EOK;
    } else {
       return ieee80211_send_mgmt(vap,ni, wbuf,true);
    }
}

#if ATH_SUPPORT_WIFIPOS
/*
 * Send cts-to-self with given duration. Copy from the below
 */

int
ieee80211_send_cts_to_self_dur(struct ieee80211_node *ni, u_int32_t dur)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf;
    struct ieee80211_frame_cts *cts;
    u_int16_t *durPtr;


    /*
     * It's the same as a management frame in the sense that
     * both are self-generated frames.
     */
    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);
    if (wbuf == NULL)
        return -ENOMEM;

    /* setup the wireless header */
    cts = (struct ieee80211_frame_cts *)wbuf_header(wbuf);
    memset(cts,0,sizeof(struct ieee80211_frame_cts));
    cts->i_fc[1] = IEEE80211_FC1_DIR_NODS;
    cts->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_CTL | IEEE80211_FC0_SUBTYPE_CTS;
    IEEE80211_ADDR_COPY(cts->i_ra, ni->ni_macaddr);
    durPtr = (u_int16_t *) &cts->i_dur[0];
//    *(u_int16_t *) cts->i_dur = dur; /* Copying the duration field */
    // Need to be changed later
    cts->i_dur[0] = 0x6D;
    cts->i_dur[1] = 0x00;
    /* This flag is set so tell the HW not to update the duration field */
    wbuf_set_cts_frame(wbuf);
    wbuf_set_pktlen(wbuf, sizeof(struct ieee80211_frame_cts));
    return ieee80211_send_mgmt(vap, ni, wbuf, true);
}
#endif

/*
 * Send a self-CTS frame
 */
int
ieee80211_send_cts(struct ieee80211_node *ni, int flags)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf;
    struct ieee80211_frame_cts *cts;

    /*
     * It's the same as a management frame in the sense that
     * both are self-generated frames.
     */
    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);
    if (wbuf == NULL)
        return -ENOMEM;

    /* setup the wireless header */
    cts = (struct ieee80211_frame_cts *)wbuf_header(wbuf);
    cts->i_fc[1] = IEEE80211_FC1_DIR_NODS;
    cts->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_CTL | IEEE80211_FC0_SUBTYPE_CTS;
    IEEE80211_ADDR_COPY(cts->i_ra, ni->ni_macaddr);

    wbuf_set_pktlen(wbuf, sizeof(struct ieee80211_frame_cts));

#if ATH_SUPPORT_WIFIPOS
    if (flags & IEEE80211_CTS_WIFIPOS) {
        /* put CTS to self frame duration to 15 milliseconds */
        //cts->i_dur[0] = 0x40;
        //cts->i_dur[1] = 0x01;
        *(u_int16_t *)cts->i_dur = (MAX_CTS_TO_SELF_TIME_USEC);
        wbuf_set_cts_frame(wbuf);
    }
#endif
    if (flags & IEEE80211_CTS_SMPS)
        wbuf_set_smpsframe(wbuf);

    return ieee80211_send_mgmt(vap, ni, wbuf, true);
}

/*
 * Return a prepared QoS NULL frame.
 */
void
ieee80211_prepare_qosnulldata(struct ieee80211_node *ni, wbuf_t wbuf, int ac)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211_qosframe *qwh;
    int tid;

    qwh = (struct ieee80211_qosframe *)wbuf_header(wbuf);

    ieee80211_send_setup(vap, ni, (struct ieee80211_frame *)qwh,
        IEEE80211_FC0_TYPE_DATA,
        vap->iv_myaddr, /* SA */
        ni->ni_macaddr, /* DA */
        ni->ni_bssid);

    qwh->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_DATA |
        IEEE80211_FC0_SUBTYPE_QOS_NULL;

    if (IEEE80211_VAP_IS_SLEEPING(ni->ni_vap) || ieee80211_vap_forced_sleep_is_set(vap)) {
        wbuf_set_pwrsaveframe(wbuf);
        qwh->i_fc[1] |= IEEE80211_FC1_PWR_MGT;
    }

    /* map from access class/queue to 11e header priority value */
    tid = WME_AC_TO_TID(ac);
    qwh->i_qos[0] = tid & IEEE80211_QOS_TID;
    if ((vap->iv_opmode != IEEE80211_M_STA &&
            vap->iv_opmode != IEEE80211_M_IBSS)) {
#if ATH_SUPPORT_WIFIPOS
            if (!(ni->ni_flags & IEEE80211_NODE_WAKEUP))
#endif
                qwh->i_qos[0] |= IEEE80211_QOS_EOSP;
    }

    if (wbuf_is_offchan_tx(wbuf))
    {
        qwh->i_qos[0] |= (1 << IEEE80211_QOS_ACKPOLICY_S) & IEEE80211_QOS_ACKPOLICY;
    }

    if (ic->ic_wme.wme_wmeChanParams.cap_wmeParams[ac].wmep_noackPolicy)
    {
        qwh->i_qos[0] |= (1 << IEEE80211_QOS_ACKPOLICY_S) & IEEE80211_QOS_ACKPOLICY;
    }

    qwh->i_qos[1] = 0;
    if (vap->iv_ique_ops.hbr_set_probing)
        vap->iv_ique_ops.hbr_set_probing(vap, ni, wbuf, (u_int8_t)tid);
}

#if ATH_SUPPORT_WIFIPOS
int ieee80211_send_null_probe(struct ieee80211_node *ni, int vmf, void *wifiposdata)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf;
    struct ieee80211_frame *wh;
    if(ieee80211_chan2ieee(ic,ieee80211_get_home_channel(vap)) !=
          ieee80211_chan2ieee(ic,ieee80211_get_current_channel(ic)))
	{

		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
				  "%s[%d] cur chan %d flags 0x%x  is not same as home chan %d flags 0x%x \n",
				  __func__, __LINE__,
                          ieee80211_chan2ieee(ic, ic->ic_curchan),ieee80211_chan_flags(ic->ic_curchan),
                          ieee80211_chan2ieee(ic, vap->iv_bsschan), ieee80211_chan_flags(vap->iv_bsschan));
		return EOK;
	}

    /*
     * XXX: It's the same as a management frame in the sense that
     * both are self-generated frames.
     */
    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, sizeof(struct ieee80211_frame));
    if (wbuf == NULL)
        return -ENOMEM;

    wbuf_set_pos(wbuf);
    wbuf_set_wifipos(wbuf, wifiposdata);
    wbuf_set_wifipos_req_id(wbuf, ((ieee80211_wifipos_reqdata_t *)wifiposdata)->request_id);
    if(vmf)
        wbuf_set_vmf(wbuf);

    /* setup the wireless header */
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    ieee80211_send_setup(vap, ni, wh,
                         IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_NODATA,
                         vap->iv_myaddr, ieee80211_node_get_macaddr(ni),
                         ieee80211_node_get_bssid(ni));
    wh->i_fc[1] |= IEEE80211_FC1_MORE_DATA;


    IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG | IEEE80211_MSG_DUMPPKTS,
                      "[%s] send null data frame on channel %u, pwr mgt %s\n",
                      ether_sprintf(ni->ni_macaddr),
                      ieee80211_chan2ieee(ic, ic->ic_curchan),
                      wh->i_fc[1] & IEEE80211_FC1_PWR_MGT ? "ena" : "dis");

    wbuf_set_pktlen(wbuf, sizeof(struct ieee80211_frame));
    // this should be VIDEO AC, asked by NBP server team. originally
    // dsigned for VOICE AC
    wbuf_set_priority(wbuf, WME_AC_VI);

    vap->iv_lastdata = OS_GET_TIMESTAMP();
    /* null data  can not go out if the vap is in forced pause state */
    if (ieee80211_vap_is_force_paused(vap)) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_POWER,
                          "[%s] queue null data frame the vap is in forced pause state\n",__func__);
      ieee80211_node_saveq_queue(ni,wbuf,IEEE80211_FC0_TYPE_MGT);
      return EOK;
    } else {
       if (vap->iv_opmode == IEEE80211_M_STA ||
           vap->iv_opmode == IEEE80211_M_IBSS) {
           /* force send null data */
           return ieee80211_send_mgmt(vap,ni, wbuf, true);
       }
       else {
           /* allow power save for null data */
           return ieee80211_send_mgmt(vap,ni, wbuf, true);
       }
    }
}

/*
 * send a QoSNull frame
 */
int ieee80211_send_qosnull_probe(struct ieee80211_node *ni, int ac, int vmf, void *wifiposdata)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf;
    struct ieee80211_qosframe *qwh;

    if (ieee80211_get_home_channel(vap) !=
        ieee80211_get_current_channel(ic))
    {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
                          "%s[%d] cur chan %d is not same as home chan %d\n",
                          __func__, __LINE__,
                          ieee80211_chan2ieee(ic, ic->ic_curchan),ieee80211_chan2ieee(ic, vap->iv_bsschan));
        return EOK;
    }

    /*
     * XXX: It's the same as a management frame in the sense that
     * both are self-generated frames.
     */
    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, sizeof(struct ieee80211_qosframe));
    if (wbuf == NULL)
        return -ENOMEM;

    wbuf_set_pos(wbuf);
    wbuf_set_wifipos(wbuf, wifiposdata);
    wbuf_set_wifipos_req_id(wbuf, ((ieee80211_wifipos_reqdata_t *)wifiposdata)->request_id);
    if(vmf)
        wbuf_set_vmf(wbuf);
    ieee80211_prepare_qosnulldata(ni, wbuf, ac);

    qwh = (struct ieee80211_qosframe *)wbuf_header(wbuf);

    qwh->i_fc[1] |= IEEE80211_FC1_MORE_DATA;
    qwh->i_qos[0] &= ~IEEE80211_QOS_EOSP;

    wbuf_set_pktlen(wbuf, sizeof(struct ieee80211_qosframe));

    vap->iv_lastdata = OS_GET_TIMESTAMP();

    /* qos null data  can not go out if the vap is in forced pause state */
    if (ieee80211_vap_is_force_paused(vap)) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_POWER,
                          "[%s] queue null data frame the vap is in forced pause state\n",__func__);
      ieee80211_node_saveq_queue(ni,wbuf,IEEE80211_FC0_TYPE_MGT);
      return EOK;
    } else {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_POWER,
                          "[%s] send qos null data frame \n",__func__);
       return ieee80211_send_mgmt(vap,ni, wbuf,true);
    }
}
#endif
/*this is clone to send a QoSNull frame added to
differentiate offchan_tx
*/
int ieee80211_send_qosnulldata_offchan_tx_test(struct ieee80211_node *ni, int ac, int pwr_save)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf;
    struct ieee80211_qosframe *qwh;
    u_int32_t   hdrsize;

    /*
     * XXX: It's the same as a management frame in the sense that
     * both are self-generated frames.
     */
    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, sizeof(struct ieee80211_qosframe));
    if (wbuf == NULL)
        return -ENOMEM;
    wbuf_set_offchan_tx(wbuf);
    ieee80211_prepare_qosnulldata(ni, wbuf, ac);

    qwh = (struct ieee80211_qosframe *)wbuf_header(wbuf);

    hdrsize = sizeof(struct ieee80211_qosframe);

    if (ic->ic_flags & IEEE80211_F_DATAPAD) {
        /* add padding if required and zero out the padding */
        u_int8_t pad = roundup(hdrsize, sizeof(u_int32_t)) - hdrsize;
        OS_MEMZERO( (u_int8_t *) ((u_int8_t *) qwh + hdrsize), pad);
        hdrsize += pad;
    }

    wbuf_set_pktlen(wbuf, hdrsize);

    vap->iv_lastdata = OS_GET_TIMESTAMP();
    /* qos null data  can not go out if the vap is in forced pause state */
    if (ieee80211_vap_is_force_paused(vap)) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_POWER,
                          "[%s] queue null data frame the vap is in forced pause state\n",__func__);
        ieee80211_node_saveq_queue(ni,wbuf,IEEE80211_FC0_TYPE_MGT);
#if LMAC_SUPPORT_POWERSAVE_QUEUE
        /* force the frame to reach LMAC pwrsaveq */
        return ieee80211_send_mgmt(vap,ni, wbuf, true);
#endif
        return EOK;
    } else {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_POWER,
                          "[%s] send qos null data frame \n",__func__);
       return ieee80211_send_mgmt(vap,ni, wbuf,true);
    }
}

/*
 * send a QoSNull frame
 */
#if ATH_SUPPORT_WIFIPOS
int ieee80211_send_qosnulldata(struct ieee80211_node *ni, int ac, int pwr_save)
{
    return ieee80211_send_qosnulldata_keepalive(ni, ac, pwr_save, 0);
}

int ieee80211_send_qosnulldata_keepalive(struct ieee80211_node *ni, int ac, int pwr_save, int keepalive)
#else
int ieee80211_send_qosnulldata(struct ieee80211_node *ni, int ac, int pwr_save)
#endif
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf;
    struct ieee80211_qosframe *qwh;
    u_int32_t   hdrsize;

    if (ieee80211_get_home_channel(vap) !=
           ieee80211_get_current_channel(ic))
	{
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
				  "%s[%d] cur chan %d is not same as home chan %d\n",
				  __func__, __LINE__,
				  ieee80211_chan2ieee(ic, ic->ic_curchan),ieee80211_chan2ieee(ic, vap->iv_bsschan));
		return EOK;
	}

    /*
     * XXX: It's the same as a management frame in the sense that
     * both are self-generated frames.
     */
    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, sizeof(struct ieee80211_qosframe));
    if (wbuf == NULL)
        return -ENOMEM;

    ieee80211_prepare_qosnulldata(ni, wbuf, ac);

    qwh = (struct ieee80211_qosframe *)wbuf_header(wbuf);

    hdrsize = sizeof(struct ieee80211_qosframe);

    if (ic->ic_flags & IEEE80211_F_DATAPAD) {
        /* add padding if required and zero out the padding */
        u_int8_t pad = roundup(hdrsize, sizeof(u_int32_t)) - hdrsize;
        OS_MEMZERO( (u_int8_t *) ((u_int8_t *) qwh + hdrsize), pad);
        hdrsize += pad;
    }
    wbuf_set_pktlen(wbuf, hdrsize);

#if ATH_SUPPORT_WIFIPOS
    if(keepalive) {
        if(vap->iv_wakeup & 0x4)
            qwh->i_fc[1] |= IEEE80211_FC1_MORE_DATA;
        qwh->i_qos[0] &= ~IEEE80211_QOS_EOSP;
        wbuf_set_keepalive(wbuf);
    }
#endif

#if ATH_BAND_STEERING
    if(ni->ni_ext_flags & IEEE80211_NODE_BSTEERING_CAPABLE) {
        wbuf_set_bsteering(wbuf);
    }
#endif

    vap->iv_lastdata = OS_GET_TIMESTAMP();
    /* qos null data  can not go out if the vap is in forced pause state */
    if (ieee80211_vap_is_force_paused(vap)) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_POWER,
                          "[%s] queue null data frame the vap is in forced pause state\n",__func__);
        ieee80211_node_saveq_queue(ni,wbuf,IEEE80211_FC0_TYPE_MGT);
#if LMAC_SUPPORT_POWERSAVE_QUEUE
        /* force the frame to reach LMAC pwrsaveq */
        return ieee80211_send_mgmt(vap,ni, wbuf, true);
#endif
        return EOK;
    } else {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_POWER,
                          "[%s] send qos null data frame \n",__func__);
       return ieee80211_send_mgmt(vap,ni, wbuf,true);
    }
}

/*
 * receive management processing code.
 */


static enum ieee80211_phymode
ieee80211_get_phy_type (
    struct ieee80211com               *ic,
    struct ieee80211vap               *vap,
    u_int8_t                          *rates,
    u_int8_t                          *xrates,
    struct ieee80211_ie_htcap_cmn     *htcap,
    struct ieee80211_ie_htinfo_cmn    *htinfo,
    struct ieee80211_ie_vhtcap        *vhtcap,
    struct ieee80211_ie_vhtop         *vhtop,
    struct ieee80211_channel          *bcn_recv_chan
    )
{
    enum ieee80211_phymode phymode = IEEE80211_MODE_AUTO;
    u_int16_t    htcapabilities = 0;
    u_int32_t    vhtcapinfo = 0;
    struct ieee80211_channel  *nc = NULL;

    /*
     * Determine BSS phyType
     */
    if (htcap != NULL) {
        htcapabilities = le16toh(htcap->hc_cap);
    }
    if (vhtcap != NULL) {
        vhtcapinfo = le32toh(vhtcap->vht_cap_info);
    }

    if (IEEE80211_IS_CHAN_5GHZ(bcn_recv_chan)) {
        if (htcap && htinfo) {
            /* See section 10.39.1 of the VHT specification Table 10-19a */
            if (vhtcap && vhtop &&
                 (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT20) ||
                  IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT40) ||
                  IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT40PLUS) ||
                  IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT40MINUS) ||
                  IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT80) ||
                  IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT160) ||
                  IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT80_80))) {

                switch (vhtop->vht_op_chwidth) {
                    case IEEE80211_VHTOP_CHWIDTH_2040 :
                        if ((htcapabilities & IEEE80211_HTCAP_C_CHWIDTH40) &&
                            (htinfo->hi_extchoff == IEEE80211_HTINFO_EXTOFFSET_ABOVE) &&
                            (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT40PLUS) ||
                             IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT40)) &&
                            (((nc = ieee80211_find_channel(ic, bcn_recv_chan->ic_freq, 0, IEEE80211_CHAN_11AC_VHT40)) != NULL) ||
                             ((nc = ieee80211_find_channel(ic, bcn_recv_chan->ic_freq, 0, IEEE80211_CHAN_11AC_VHT40PLUS)) != NULL))) {
                                phymode = IEEE80211_MODE_11AC_VHT40PLUS;
                        } else if ((htcapabilities & IEEE80211_HTCAP_C_CHWIDTH40) &&
                            (htinfo->hi_extchoff == IEEE80211_HTINFO_EXTOFFSET_BELOW) &&
                            (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT40MINUS) ||
                             IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT40)) &&
                            (((nc = ieee80211_find_channel(ic, bcn_recv_chan->ic_freq, 0, IEEE80211_CHAN_11AC_VHT40)) != NULL) ||
                             ((nc = ieee80211_find_channel(ic, bcn_recv_chan->ic_freq, 0, IEEE80211_CHAN_11AC_VHT40MINUS)) != NULL))) {
                                phymode = IEEE80211_MODE_11AC_VHT40MINUS;
                        } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT20) &&
                                ((nc = ieee80211_find_channel(ic, bcn_recv_chan->ic_freq, 0, IEEE80211_CHAN_11AC_VHT20)) != NULL)) {
                            phymode = IEEE80211_MODE_11AC_VHT20;
                        }
                    break;
                    case IEEE80211_VHTOP_CHWIDTH_80 :
                    if ((peer_ext_nss_capable(vhtcap) && vap->iv_ext_nss_capable && extnss_80p80_validate_and_seg2_indicate((&vhtcapinfo), vhtop, htinfo))
                            || IS_REVSIG_VHT80_80(vhtop)){
                        if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT80_80)) {
                            phymode = IEEE80211_MODE_11AC_VHT80_80;
                        } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT160)) {
                            phymode = IEEE80211_MODE_11AC_VHT160;
                        } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT80)) {
                            phymode = IEEE80211_MODE_11AC_VHT80;
                        } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT40)) {
                            phymode = IEEE80211_MODE_11AC_VHT40;
                        } else {
                            phymode = IEEE80211_MODE_11AC_VHT20;
                        }
                    } else if (peer_ext_nss_capable(vhtcap) && vap->iv_ext_nss_capable && extnss_160_validate_and_seg2_indicate((&vhtcapinfo), vhtop, htinfo)) {
                            phymode = IEEE80211_MODE_11AC_VHT160;
                    } else if (IS_REVSIG_VHT160(vhtop) && IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT160)) {
                            phymode = IEEE80211_MODE_11AC_VHT160;
                        } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT80)) {
                            phymode = IEEE80211_MODE_11AC_VHT80;
                        } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT40)) {
                            phymode = IEEE80211_MODE_11AC_VHT40;
                        } else {
                            phymode = IEEE80211_MODE_11AC_VHT20;
                        }
                    break;
                    case IEEE80211_VHTOP_CHWIDTH_160 :
                         if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT160)) {
                             phymode = IEEE80211_MODE_11AC_VHT160;
                         } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT80)) {
                             phymode = IEEE80211_MODE_11AC_VHT80;
                         } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT40)) {
                             phymode = IEEE80211_MODE_11AC_VHT40;
                         } else {
                             phymode = IEEE80211_MODE_11AC_VHT20;
                         }
                    break;
                    case IEEE80211_VHTOP_CHWIDTH_80_80 :
                         if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT80_80)) {
                             phymode = IEEE80211_MODE_11AC_VHT80_80;
                         } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT160)) {
                             phymode = IEEE80211_MODE_11AC_VHT160;
                         } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT80)) {
                             phymode = IEEE80211_MODE_11AC_VHT80;
                         } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT40)) {
                             phymode = IEEE80211_MODE_11AC_VHT40;
                         } else {
                             phymode = IEEE80211_MODE_11AC_VHT20;
                         }
                    break;
                    default:
                        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD, IEEE80211_MSG_DEBUG,
                               "%s : Received Bad Chwidth", __func__);
                    break;
                }
            } else if ((htcapabilities & IEEE80211_HTCAP_C_CHWIDTH40) &&
                (htinfo->hi_extchoff == IEEE80211_HTINFO_EXTOFFSET_ABOVE) &&
                IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NA_HT40PLUS)) {
                phymode = IEEE80211_MODE_11NA_HT40PLUS;
            } else if ((htcapabilities & IEEE80211_HTCAP_C_CHWIDTH40) &&
                       (htinfo->hi_extchoff == IEEE80211_HTINFO_EXTOFFSET_BELOW) &&
                       IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NA_HT40MINUS)) {
                phymode = IEEE80211_MODE_11NA_HT40MINUS;
            } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NA_HT20)) {
                phymode = IEEE80211_MODE_11NA_HT20;
            } else {
                phymode = IEEE80211_MODE_11A;
            }
        } else {
            phymode = IEEE80211_MODE_11A;
        }
    } else {

        /* Check for HT capability only if we as well support HT mode */
        if (htcap && htinfo && IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NG_HT20)) {
            if ((htcapabilities & IEEE80211_HTCAP_C_CHWIDTH40) &&
                (htinfo->hi_extchoff == IEEE80211_HTINFO_EXTOFFSET_ABOVE) &&
                IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NG_HT40PLUS)) {
                phymode = IEEE80211_MODE_11NG_HT40PLUS;
            } else if ((htcapabilities & IEEE80211_HTCAP_C_CHWIDTH40) &&
                       (htinfo->hi_extchoff == IEEE80211_HTINFO_EXTOFFSET_BELOW) &&
                       IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NG_HT40MINUS)) {
                phymode = IEEE80211_MODE_11NG_HT40MINUS;
            } else {
                phymode = IEEE80211_MODE_11NG_HT20;
            }
        } else if (xrates != NULL) {
            /*
             * XXX: This is probably the most reliable way to tell the difference
             * between 11g and 11b beacons.
             */
            if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11G)) {
                phymode = IEEE80211_MODE_11G;
            } else {
                phymode = IEEE80211_MODE_11B;
            }
        }
        else {
            /* Some mischievous g-only APs do not set extended rates */
            if (rates != NULL) {
                u_int8_t    *tmpPtr  = rates + 2;
                u_int8_t    tmpSize = rates[1];
                u_int8_t    *tmpPtrTail = tmpPtr + tmpSize;
                int         found11g = 0;

                for (; tmpPtr < tmpPtrTail; tmpPtr++) {
                    found11g = ieee80211_find_puregrate(*tmpPtr);
                    if (found11g)
                        break;
                }

                if (found11g) {
                    if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11G)) {
                        phymode = IEEE80211_MODE_11G;
                    } else {
                        phymode = IEEE80211_MODE_11B;
                    }
                } else {
                    phymode = IEEE80211_MODE_11B;
                }
            } else {
                phymode = IEEE80211_MODE_11B;
            }
        }
    }

    return phymode;
}

static int
bss_intol_channel_check(struct ieee80211_node *ni,
                        struct ieee80211_ie_intolerant_report *intol_ie)
{
    struct ieee80211com *ic = ni->ni_ic;
    int i, j;
    u_int8_t intol_chan  = 0;
    u_int8_t *chan_list = &intol_ie->chan_list[0];
    u_int8_t myBand;

    /*
    ** Determine the band the node is operating in currently
    */

    if( ni->ni_chan->ic_ieee > 15 )
        myBand = 5;
    else
        myBand = 2;

    if (intol_ie->elem_len <= 1)
        return 0;

    /*
    ** Check the report against the channel list.
    */

    for (i = 0; i < intol_ie->elem_len-1; i++) {
        intol_chan = *chan_list++;

        /*
        ** If the intolarant channel is not in my band, ignore
        */

        if( (intol_chan > 15 && myBand == 2) || (intol_chan < 16 && myBand == 5))
            continue;

        /*
        ** Check against the channels supported by the "device"
        ** (note: Should this be limited by "WIRELESS_MODE"
        */

        for (j = 0; j < ic->ic_nchans; j++) {
            if (intol_chan == ic->ic_channels[j].ic_ieee) {
                IEEE80211_NOTE(ni->ni_vap, IEEE80211_MSG_ACTION, ni,
                               "%s: Found intolerant channel %d",
                               __func__, intol_chan);
                return 1;
            }
        }
    }
    return 0;
}
struct ieee80211_channel* parse_next_channel_vendor_ie(struct ieee80211vap * vap, struct ieee80211_ie_header *info_element)
{
    struct ieee80211_ie_header       *sub_info_element;
    u_int32_t                         sub_remaining_ie_length;
    struct ieee80211_channelswitch_ie            *chanie = NULL;
    struct ieee80211_ie_wide_bw_switch           *widebwie = NULL;
    struct ieee80211_ie_sec_chan_offset          *secchanoffie = NULL;
    struct ieee80211_channel *chan = NULL;
    struct ieee80211_node *ni = vap->iv_bss;

    /* Go to next sub IE */
    sub_info_element = (struct ieee80211_ie_header *)
        (((u_int8_t *) info_element) + 6 + sizeof(struct ieee80211_ie_header));

    sub_remaining_ie_length = info_element->length - 6;

    /* Walk through to check nothing is malformed */
    while (sub_remaining_ie_length >= sizeof(struct ieee80211_ie_header)) {
        /* At least one more header is present */
        sub_remaining_ie_length -= sizeof(struct ieee80211_ie_header);
        if (sub_info_element->length == 0) {
            sub_info_element += 1;   /* Next sub IE */
            continue;
        }
        if (sub_remaining_ie_length < sub_info_element->length) {
            /* Incomplete/bad info element */
            QDF_PRINT_INFO( vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Incomplete corrupted IE:%x\n",IEEE80211_ELEMID_VENDOR);
            return NULL;
        }
        switch (sub_info_element->element_id) {
            case IEEE80211_ELEMID_WIDE_BAND_CHAN_SWITCH:
                widebwie  = (struct ieee80211_ie_wide_bw_switch*)sub_info_element;
                break;
            case IEEE80211_ELEMID_SECCHANOFFSET:
                secchanoffie = (struct ieee80211_ie_sec_chan_offset*)sub_info_element;
                break;
            case IEEE80211_ELEMID_CHANSWITCHANN:
                chanie = (struct ieee80211_channelswitch_ie*)sub_info_element;
                break;
        }
        /* Consume sub info element */
        sub_remaining_ie_length -= sub_info_element->length;
        /* go to next Sub IE */
        sub_info_element = (struct ieee80211_ie_header *)
            (((u_int8_t *) sub_info_element) + sizeof(struct ieee80211_ie_header) + sub_info_element->length);
    }
    chan = ieee80211_get_new_sw_chan (ni, chanie, NULL, secchanoffie, widebwie, NULL);
    return chan;
}
int
ieee80211_parse_beacon(struct ieee80211vap                  *vap,
                       struct ieee80211_beacon_frame        *beacon_frame,
                       const struct ieee80211_frame         *wh,
                       u_int32_t                            beacon_frame_length,
                       int                                  subtype,
                       struct ieee80211_channel             *bcn_recv_chan,
                       struct ieee80211_scanentry_params    *scan_entry_parameters)
{
/*
 * Offset of IE's in beacon frames: header size plus timestamp, beacon_interval and capability.
 */
#define BEACON_INFO_ELEMENT_OFFSET    (offsetof(struct ieee80211_beacon_frame, info_elements))

    struct ieee80211com              *ic = vap->iv_ic;
    struct ieee80211_ie_header       *info_element;
    u_int32_t                        remaining_ie_length, halfquarter;
    u_int8_t                         bchan, sig_vht_op_ch_freq_seg2 = 0;
    struct ieee80211_ie_vhtop        *ap_vhtop = NULL;
    struct ieee80211_ie_htinfo_cmn   *ap_htinfo = NULL;
    struct ieee80211_ie_vhtcap        *ap_vhtinfo = NULL;
    struct ieee80211_channel         *chan = NULL;
    u_int32_t vhtcap = 0;

    /*
     * beacon/probe response frame format
     *  [8] time stamp
     *  [2] beacon interval
     *  [2] capability information
     *  [tlv] ssid
     *  [tlv] supported rates
     *  [tlv] country information
     *  [tlv] parameter set (FH/DS)
     *  [tlv] erp information
     *  [tlv] extended supported rates
     *  [tlv] WME
     *  [tlv] WPA or RSN
     *  [tlv] Atheros Advanced Capabilities
     */
    IEEE80211_VERIFY_LENGTH(beacon_frame_length, BEACON_INFO_ELEMENT_OFFSET);

    info_element = &(beacon_frame->info_elements);
    remaining_ie_length = beacon_frame_length - BEACON_INFO_ELEMENT_OFFSET;

    OS_MEMZERO(scan_entry_parameters, sizeof(*scan_entry_parameters));

    if(bcn_recv_chan == NULL) {
       bcn_recv_chan = ic->ic_curchan;
    }
    bchan = ieee80211_chan2ieee(ic, bcn_recv_chan);

    scan_entry_parameters->tsf              = (u_int8_t *) &(beacon_frame->timestamp);
    scan_entry_parameters->bintval          = le16toh(beacon_frame->beacon_interval);
    scan_entry_parameters->capinfo          = le16toh(beacon_frame->capability.value);
    scan_entry_parameters->chan             = bcn_recv_chan;
    scan_entry_parameters->channel_mismatch = false;
#if QCA_LTEU_SUPPORT
    scan_entry_parameters->sequence_num     = (le16toh(*(u_int16_t *)wh->i_seq) >> IEEE80211_SEQ_SEQ_SHIFT);
#endif
    if (!((IEEE80211_BINTVAL_MIN <= scan_entry_parameters->bintval) &&
          (scan_entry_parameters->bintval <= IEEE80211_BINTVAL_MAX))) {
          IEEE80211_DISCARD(vap, IEEE80211_MSG_SCAN,
                            wh, "beacon", "invalid beacon interval (%u)",
                            scan_entry_parameters->bintval);
          return -EINVAL;
    }
    /*
     * initialize erp with a value as if  the beacon is received from a 11B AP
     * the following code will parse and update the erp with the actual value if
     * found.
     */
    scan_entry_parameters->erp = IEEE80211_ERP_NON_ERP_PRESENT;

    /* Walk through to check nothing is malformed */
    while (remaining_ie_length >= sizeof(struct ieee80211_ie_header)) {
        /* At least one more header is present */
        remaining_ie_length -= sizeof(struct ieee80211_ie_header);

        if (info_element->length == 0) {
            info_element += 1;    /* next IE */
            continue;
        }

        if (remaining_ie_length < info_element->length) {
            /* Incomplete/bad info element */
            return -EINVAL;
        }

        /* New info_element needs also be added in ieee80211_scan_entry_update */
        switch (info_element->element_id) {
        case IEEE80211_ELEMID_SSID:
            scan_entry_parameters->ie_list.ssid = (u_int8_t *) info_element;
            break;
        case IEEE80211_ELEMID_RATES:
            scan_entry_parameters->ie_list.rates = (u_int8_t *) info_element;
            break;
        case IEEE80211_ELEMID_FHPARMS:
            if (ic->ic_phytype == IEEE80211_T_FH) {
                struct ieee80211_fh_ie    *fh_parms = (struct ieee80211_fh_ie *) info_element;
                u_int                     channel;
                u_int                     freq;

                channel = IEEE80211_FH_CHAN(fh_parms->hop_set, fh_parms->hop_pattern);
                freq    = ieee80211_ieee2mhz(ic, channel, IEEE80211_CHAN_FHSS);

                scan_entry_parameters->fhdwell = fh_parms->dwell_time;
                scan_entry_parameters->chan    = ieee80211_find_channel(ic, freq, 0, IEEE80211_CHAN_FHSS);
                scan_entry_parameters->fhindex = fh_parms->hop_index;
            }
            break;
        case IEEE80211_ELEMID_DSPARMS:
            /*
             * XXX hack this since depending on phytype
             * is problematic for multi-mode devices.
             */
            if (ic->ic_phytype != IEEE80211_T_FH) {
                struct ieee80211_ds_ie    *ds_parms = (struct ieee80211_ds_ie *) info_element;

                bchan = ds_parms->current_channel;
            }
            break;
        case IEEE80211_ELEMID_TIM: {
                struct ieee80211_tim_ie    *tim = (struct ieee80211_tim_ie *) info_element;

                /* XXX ATIM? */
                scan_entry_parameters->ie_list.tim = (u_int8_t *) info_element;
                scan_entry_parameters->timoff      = (tim->tim_bitctl >> 1);
            }
            break;
        case IEEE80211_ELEMID_IBSSPARMS:
            break;
        case IEEE80211_ELEMID_COUNTRY:
            scan_entry_parameters->ie_list.country = (u_int8_t *) info_element;
            break;
        case IEEE80211_ELEMID_QBSS_LOAD:
            scan_entry_parameters->ie_list.qbssload = (u_int8_t *) info_element;
            break;
        case IEEE80211_ELEMID_PWRCNSTR:
            break;
        case IEEE80211_ELEMID_CHANSWITCHANN:
            scan_entry_parameters->ie_list.csa = (u_int8_t *) info_element;
            break;
#if ATH_SUPPORT_IBSS_DFS
        case IEEE80211_ELEMID_IBSSDFS:
            scan_entry_parameters->ie_list.ibssdfs = (u_int8_t *) info_element;
            break;
#endif /* ATH_SUPPORT_IBSS_DFS */
        case IEEE80211_ELEMID_QUIET:
            scan_entry_parameters->ie_list.quiet = (u_int8_t *) info_element;
            break;
        case IEEE80211_ELEMID_ERP:
            scan_entry_parameters->erp = ((struct ieee80211_erp_ie *) info_element)->value;
            break;
        case IEEE80211_ELEMID_HTCAP_ANA:
            scan_entry_parameters->ie_list.htcap = (u_int8_t *) &(((struct ieee80211_ie_htcap *) info_element)->hc_ie);
            break;
        case IEEE80211_ELEMID_RESERVED_47:
            break;
        case IEEE80211_ELEMID_RSN:
            scan_entry_parameters->ie_list.rsn = (u_int8_t *) info_element;
            break;
        case IEEE80211_ELEMID_XRATES:
            scan_entry_parameters->ie_list.xrates = (u_int8_t *) info_element;
            break;
        case IEEE80211_ELEMID_EXTCHANSWITCHANN:
            scan_entry_parameters->ie_list.xcsa = (u_int8_t *) info_element;
            break;
        case IEEE80211_ELEMID_SECCHANOFFSET:
            scan_entry_parameters->ie_list.secchanoff = (u_int8_t *) info_element;
            break;
        case IEEE80211_ELEMID_HTINFO_ANA: {
            scan_entry_parameters->ie_list.htinfo = (u_int8_t *) &(((struct ieee80211_ie_htinfo *) info_element)->hi_ie);
            /*
             * XXX hack this since depending on phytype
             * is problematic for multi-mode devices.
             */
            bchan = ((struct ieee80211_ie_htinfo_cmn *) (scan_entry_parameters->ie_list.htinfo))->hi_ctrlchannel;
            break;
        }
#if ATH_SUPPORT_WAPI
        case IEEE80211_ELEMID_WAPI:
            scan_entry_parameters->ie_list.wapi = (u_int8_t *) info_element;
            break;
#endif
        case IEEE80211_ELEMID_XCAPS:
            scan_entry_parameters->ie_list.extcaps = (u_int8_t *) info_element;
            break;
        case IEEE80211_ELEMID_RESERVED_133:
            break;
        case IEEE80211_ELEMID_TPC:
            break;
        case IEEE80211_ELEMID_VHTCAP:
            if (scan_entry_parameters->ie_list.vhtcap == NULL) {
                scan_entry_parameters->ie_list.vhtcap = (u_int8_t *) info_element;
            }
            break;
        case IEEE80211_ELEMID_VHTOP:
            if (scan_entry_parameters->ie_list.vhtop == NULL) {
                scan_entry_parameters->ie_list.vhtop = (u_int8_t *) info_element;
            }
            break;
        case IEEE80211_ELEMID_OP_MODE_NOTIFY:
            if (scan_entry_parameters->ie_list.opmode == NULL) {
                scan_entry_parameters->ie_list.opmode = (u_int8_t *) info_element;
            }
            break;
        case IEEE80211_ELEMID_VENDOR:
            if (scan_entry_parameters->ie_list.vendor == NULL) {
                scan_entry_parameters->ie_list.vendor = (u_int8_t *) info_element;
            }

            if (iswpaoui((u_int8_t *) info_element))
                scan_entry_parameters->ie_list.wpa = (u_int8_t *) info_element;
            else if (iswpsoui((u_int8_t *) info_element)) {
                scan_entry_parameters->ie_list.wps = (u_int8_t *) info_element;
                /* WCN IE should be a subset of WPS IE */
                if (iswcnoui((u_int8_t *) info_element)) {
                    scan_entry_parameters->ie_list.wcn = (u_int8_t *) info_element;
                }
            }
            else if (iswmeparam((u_int8_t *) info_element))
                scan_entry_parameters->ie_list.wmeparam = (u_int8_t *) info_element;
            else if (iswmeinfo((u_int8_t *) info_element))
                scan_entry_parameters->ie_list.wmeinfo = (u_int8_t *) info_element;
            else if (isatherosoui((u_int8_t *) info_element))
                scan_entry_parameters->ie_list.athcaps = (u_int8_t *) info_element;
            else if (isatheros_extcap_oui((u_int8_t *) info_element))
                scan_entry_parameters->ie_list.athextcaps = (u_int8_t *) info_element;
            else if (issfaoui((u_int8_t *) info_element))
                scan_entry_parameters->ie_list.sfa = (u_int8_t *) info_element;
            else if (isp2poui((u_int8_t *) info_element)) {
                /* Note: P2P IE can be fragmented and the last fragment will overwrite the previous ones.
                 * Therefore, this field will only point to the last fragment. */
                scan_entry_parameters->ie_list.p2p = (u_int8_t *) info_element;
            }
            else if (isqca_whc_oui((u_int8_t *) info_element, QCA_OUI_WHC_AP_INFO_SUBTYPE)) {
                scan_entry_parameters->ie_list.sonadv = (u_int8_t *) info_element;
            }
            else if (IEEE80211_IS_HTVIE_ENABLED(ic)) {
                /*  we only care if there isn't already an HT IE (ANA) */
                if (ishtcap((u_int8_t *) info_element)) {
                    if (scan_entry_parameters->ie_list.htcap == NULL) {
                        scan_entry_parameters->ie_list.htcap = (u_int8_t *) &(((struct vendor_ie_htcap *) info_element)->hc_ie);
                    }
                }
                else if (ishtinfo((u_int8_t *) info_element)) {
                    /*  we only care if there isn't already an HT IE (ANA) */
                    if (scan_entry_parameters->ie_list.htinfo == NULL) {
                        scan_entry_parameters->ie_list.htinfo = (u_int8_t *) &(((struct vendor_ie_htinfo *) info_element)->hi_ie);
                    }
                }
            }
            else if (isinterop_vht((u_int8_t *)info_element) && !(scan_entry_parameters->ie_list.vhtop)) {
                 /* location where Interop Vht Cap IE and VHT OP IE Present */
                 scan_entry_parameters->ie_list.vhtcap = (u_int8_t *)(((u_int8_t *)(info_element)) + 7);
                 scan_entry_parameters->ie_list.vhtop = (u_int8_t *)(((u_int8_t *)(info_element)) + 21);
            }
            else if (isbwnss_oui((u_int8_t *)info_element)) {
                /*Bandwidth-NSS map has sub-type & version. hence copy data just after version byte*/
                scan_entry_parameters->ie_list.bwnss_map = (u_int8_t *)(((u_int8_t *)info_element) + 8);
            }
            else if(IEEE80211_IS_CSH_OPT_APRIORI_NEXT_CHANNEL_ENABLED(ic) && \
                    (ic->ic_sta_vap == vap) && is_next_channel_oui((u_int8_t *)info_element)) {
                chan = parse_next_channel_vendor_ie(vap, info_element);
                if(chan)
                    ic->ic_tx_next_ch = chan;
            }
            break;
        case IEEE80211_ELEMID_OBSS_SCAN:
            break;

        case IEEE80211_ELEMID_VHT_TX_PWR_ENVLP:
            break;

        case IEEE80211_ELEMID_CHAN_SWITCH_WRAP:
            {
                struct ieee80211_ie_header       *sub_info_element;
                u_int32_t   sub_remaining_ie_length;

                scan_entry_parameters->ie_list.cswrp = (u_int8_t*)info_element;

                /* Go to next sub IE */
                sub_info_element = (struct ieee80211_ie_header *)
                    (((u_int8_t *) info_element) + sizeof(struct ieee80211_ie_header));

                sub_remaining_ie_length = info_element->length;

                /* Walk through to check nothing is malformed */
                while (sub_remaining_ie_length >= sizeof(struct ieee80211_ie_header)) {
                    /* At least one more header is present */
                    sub_remaining_ie_length -= sizeof(struct ieee80211_ie_header);
                    if (sub_info_element->length == 0) {
                        sub_info_element += 1;   /* Next sub IE */
                        continue;
                    }
                    if (sub_remaining_ie_length < sub_info_element->length) {
                        /* Incomplete/bad info element */
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Incomplete corrupted IE:%x\n",IEEE80211_ELEMID_CHAN_SWITCH_WRAP);
                        return -EINVAL;
                    }
                    switch (sub_info_element->element_id) {
                        case IEEE80211_ELEMID_COUNTRY:
                            scan_entry_parameters->ie_list.country = (u_int8_t *)sub_info_element;
                        break;

                        case IEEE80211_ELEMID_WIDE_BAND_CHAN_SWITCH:
                            scan_entry_parameters->ie_list.widebw = (u_int8_t*)sub_info_element;
                        break;

                        case IEEE80211_ELEMID_VHT_TX_PWR_ENVLP:
                            scan_entry_parameters->ie_list.txpwrenvlp = (u_int8_t*)sub_info_element;
                            break;
                    }
                    /* Consume sub info element */
                    sub_remaining_ie_length -= sub_info_element->length;
                    /* go to next Sub IE */
                    sub_info_element = (struct ieee80211_ie_header *)
                        (((u_int8_t *) sub_info_element) + sizeof(struct ieee80211_ie_header) + sub_info_element->length);
                }

                break;
            }
        default:
            IEEE80211_DISCARD_IE(vap, IEEE80211_MSG_ELEMID,
                                 "unhandled",
                                 "id %u, len %u",
                                 info_element->element_id,
                                 info_element->length);
            break;
        }

        /* Consume info element */
        remaining_ie_length -= info_element->length;

        /* Go to next IE */
        info_element = (struct ieee80211_ie_header *)
            (((u_int8_t *) info_element) + sizeof(struct ieee80211_ie_header) + info_element->length);
    }



    IEEE80211_VERIFY_ELEMENT(scan_entry_parameters->ie_list.rates, IEEE80211_RATE_MAXSIZE);

    if (scan_entry_parameters->ie_list.ssid != NULL) {
        bool hidden_ssid = FALSE;
        IEEE80211_VERIFY_ELEMENT(scan_entry_parameters->ie_list.ssid, IEEE80211_NWID_LEN);
        IEEE80211_CHECK_SSID(scan_entry_parameters->ie_list.ssid, hidden_ssid);
        if (TRUE == hidden_ssid) {
            scan_entry_parameters->ie_list.ssid = NULL;
        }
    }

    if (scan_entry_parameters->ie_list.xrates != NULL)
        IEEE80211_VERIFY_ELEMENT(scan_entry_parameters->ie_list.xrates, IEEE80211_RATE_MAXSIZE);

    scan_entry_parameters->phy_mode =
        ieee80211_get_phy_type(
            ic, vap,
            scan_entry_parameters->ie_list.rates,
            scan_entry_parameters->ie_list.xrates,
            (struct ieee80211_ie_htcap_cmn  *) scan_entry_parameters->ie_list.htcap,
            (struct ieee80211_ie_htinfo_cmn *) scan_entry_parameters->ie_list.htinfo,
            ( struct ieee80211_ie_vhtcap *) scan_entry_parameters->ie_list.vhtcap,
            ( struct ieee80211_ie_vhtop *) scan_entry_parameters->ie_list.vhtop,
            bcn_recv_chan);

    if (bchan != 0) {
        if (bchan != ieee80211_chan2ieee(ic, scan_entry_parameters->chan)) {
#if ATH_SUPPORT_WRAP
            if (!(wlan_is_mpsta(vap)))
#endif
            /* Incorrect channel, probably because of leakage */
            scan_entry_parameters->channel_mismatch = true;
        }


        /*
         * Assign the right channel.
         * This is necessary for two reasons:
         *     -update channel flags which may have changed even if the channel
         *      number did not change
         *     -we may have received a beacon from an adjacent channel which is not
         *      supported by our regulatory domain. In this case we want
         *      scan_entry_parameters->chan to be set to NULL so that we know it is
         *      an invalid channel.
         */
        if (scan_entry_parameters->chan != NULL) {
            halfquarter = scan_entry_parameters->chan->ic_flags &
                (IEEE80211_CHAN_HALF | IEEE80211_CHAN_QUARTER);

            if ((scan_entry_parameters->ie_list.vhtop != NULL) && (scan_entry_parameters->ie_list.vhtcap != NULL)
                      && (scan_entry_parameters->ie_list.htinfo != NULL)) {
                ap_vhtop = (struct ieee80211_ie_vhtop *)(scan_entry_parameters->ie_list.vhtop);
                ap_htinfo = (struct ieee80211_ie_htinfo_cmn *)(scan_entry_parameters->ie_list.htinfo);
                ap_vhtinfo = (struct ieee80211_ie_vhtcap *)(scan_entry_parameters->ie_list.vhtcap);
                vhtcap = le32toh(ap_vhtinfo->vht_cap_info);

                if (vap->iv_ext_nss_capable && peer_ext_nss_capable(ap_vhtinfo)) {
                    if (extnss_80p80_validate_and_seg2_indicate(&vhtcap, ap_vhtop, ap_htinfo)
                          && !(sig_vht_op_ch_freq_seg2 = retrieve_seg2_for_extnss_80p80(&vhtcap, ap_vhtop, ap_htinfo))) {
                         IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "Invalid EXT NSS info in beacon\n");
                         return -EINVAL;
                    }
                } else if ((IS_REVSIG_VHT80_80(ap_vhtop)) || (ap_vhtop->vht_op_chwidth == IEEE80211_VHTOP_CHWIDTH_REVSIG_80_80)) {
                    sig_vht_op_ch_freq_seg2 = ap_vhtop->vht_op_ch_freq_seg2;
                }

                scan_entry_parameters->chan = ieee80211_find_dot11_channel(ic, bchan, sig_vht_op_ch_freq_seg2, scan_entry_parameters->phy_mode | halfquarter);
                if((!scan_entry_parameters->chan) && ic->ic_emiwar_80p80 && \
                    (scan_entry_parameters->phy_mode == IEEE80211_MODE_11AC_VHT80_80)) {
                    /*
                     * When EMIWAR is FC1>FC2 Some 80_80 MHz channle combination will not be available
                     * When EMIWAR is BandEdge channle 149,153,157,161 with secondary Frq 42 80_80 Mhz channel
                     * combination will not be available
                     * In which case STA need to fall back to 80MHz for Optimal purpose instead of 11NA_HT20
                     */
                     scan_entry_parameters->chan = ieee80211_find_dot11_channel(ic, bchan,
                                     sig_vht_op_ch_freq_seg2, IEEE80211_MODE_11AC_VHT80 | halfquarter);
               }
            }
            else {
                scan_entry_parameters->chan = ieee80211_find_dot11_channel(ic, bchan, 0, scan_entry_parameters->phy_mode | halfquarter);
                if((!scan_entry_parameters->chan) && ic->ic_emiwar_80p80 && \
                    (scan_entry_parameters->phy_mode == IEEE80211_MODE_11AC_VHT80_80)) {
                    /*
                     * When EMIWAR is FC1>FC2 Some 80_80 MHz channle combination will not be available
                     * In which case STA need to fall back to 80MHz for Optimal purpose instead of 11NA_HT20
                     */
                     scan_entry_parameters->chan = ieee80211_find_dot11_channel(ic, bchan, 0, IEEE80211_MODE_11AC_VHT80 | halfquarter);
               }
            }
         }

        /*
         * The most common reasons why ieee80211_find_dot11_channel can't find
         * a channel are:
         *     -Channel is not allowed for the current RegDomain
         *     -Channel flags do not match
         *
         * For the second case, *if* there beacon was transmitted in the
         * current channel (channel_mismatch is false), then it is OK to use
         * the current IC channel as the beacon channel.
         * The underlying assumption is that the Station will *not* scan
         * channels not allowed by the current regulatory domain/11d settings.
         */
        if ((scan_entry_parameters->chan == NULL) && !scan_entry_parameters->channel_mismatch) {
            scan_entry_parameters->chan = bcn_recv_chan;
        }
   }

    return EOK;
}

static int
ieee80211_add_ssid_to_hiddenssid_beacon(struct ieee80211_node *ni, wbuf_t wbuf, int subtype)
{

    struct ieee80211vap         *vap = ni->ni_vap;
    struct ieee80211_frame      *wh;
    u_int8_t                    *pbeacon_frame;
    u_int32_t                   beacon_length;
    u_int32_t                   frame_length;

    frame_length =  wbuf_get_pktlen(wbuf);
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);

#define BEACON_INFO_ELEMENT_OFFSET    (offsetof(struct ieee80211_beacon_frame, info_elements))
    /* check beacon bssid is the  configured bssid */
    if (IEEE80211_ADDR_IS_VALID(vap->iv_conf_des_bssid) &&
            !OS_MEMCMP(wh->i_addr3,vap->iv_conf_des_bssid,IEEE80211_ADDR_LEN)) {

        struct ieee80211_beacon_frame   *beacon_frame = (struct ieee80211_beacon_frame *)&(wh[1]);
        struct ieee80211_ie_header      *info_element;
        u_int32_t                       copy_length=0;
        u_int32_t                       pos_ssid,tmp_pos_ssid=0;
        u_int32_t                       remaining_ie_length;
        u_int16_t                       hdrsize;
        u_int8_t                        hdden_ssid_flag = 0;

        pbeacon_frame  = (u_int8_t *)&(wh[1]);
        beacon_length = frame_length - sizeof(struct ieee80211_frame);
        hdrsize = ieee80211_hdrsize(wh);
        IEEE80211_VERIFY_LENGTH(beacon_length, BEACON_INFO_ELEMENT_OFFSET);
        info_element = &(beacon_frame->info_elements);
        remaining_ie_length = beacon_length - BEACON_INFO_ELEMENT_OFFSET;

        /* Initialize ssid position by beacon offset */
        pos_ssid = BEACON_INFO_ELEMENT_OFFSET;

        /* Walk through to check nothing is malformed */
        while(remaining_ie_length >= sizeof(struct ieee80211_ie_header))
        {
            /* At least one more header is present */
            remaining_ie_length -= sizeof(struct ieee80211_ie_header);

            /* Increment the ssid position by ie length */
            pos_ssid += sizeof(struct ieee80211_ie_header);

            if (info_element->element_id == IEEE80211_ELEMID_SSID && info_element->length == 0 ) {
                hdden_ssid_flag = 1;
                tmp_pos_ssid = pos_ssid;
            } else {
                break;
            }
            if (info_element->element_id == IEEE80211_ELEMID_VENDOR && iswpsoui((u_int8_t *) info_element)) {
                hdden_ssid_flag = 0;
                break;
            }

            if (info_element->length == 0) {
                info_element += 1;    /* next IE */
                continue;
            }
            if (remaining_ie_length < info_element->length) {
                /* Incomplete/bad info element */
                return -EINVAL;
            }
            /* Consume info element */
            remaining_ie_length -= info_element->length;
            /* Go to next IE */
            info_element = (struct ieee80211_ie_header *)
                (((u_int8_t *) info_element) + sizeof(struct ieee80211_ie_header) + info_element->length);
        }
        if ( hdden_ssid_flag == 1)
        {
            /* reloading the ssid length if ssid is not NULL */
            if (vap->iv_des_ssid[0].len == 0 && vap->iv_des_ssid[0].ssid != '\0' ) {
                vap->iv_des_ssid[0].len = strlen(vap->iv_des_ssid[0].ssid);
                qdf_print("%s %d ssid.len:%d  ssid.ssid:%s",
                      __func__,__LINE__,vap->iv_des_ssid[0].len,vap->iv_des_ssid[0].ssid);
            }

	    if ((wbuf_get_pktlen(wbuf) + vap->iv_des_ssid[0].len) < MAX_TX_RX_PACKET_SIZE ) {
		u_int8_t                        *tmp = NULL;
		/* determine the length of the buffer to be copied */
		copy_length = beacon_length - tmp_pos_ssid;

		/* allocate temp memory to copy the beacon info after ssid info */
		tmp =(u_int8_t *)OS_MALLOC(vap->iv_ic->ic_osdev,copy_length * sizeof(u_int8_t),GFP_KERNEL);
		if (tmp == NULL) {
		    qdf_print("%s:%d memory alloc failed \n",__func__,__LINE__);
		    return  -ENOMEM;
		}
		/* Copy the remaining beacon data to temp location */
		qdf_nbuf_copy_bits(wbuf,(sizeof(struct ieee80211_frame) + tmp_pos_ssid),copy_length,tmp);
		/* Fix the SSID Element Length */
		*(u_int8_t *)(pbeacon_frame + (tmp_pos_ssid - 1)) =  vap->iv_des_ssid[0].len;
		/* increase the taillength by length of ssid */
		if (qdf_nbuf_put_tail(wbuf,vap->iv_des_ssid[0].len) == NULL) {
		    qdf_print("No enough tailroom for wbuf \n");
		    OS_FREE(tmp);
		    tmp  = NULL;
		    return  -ENOMEM;
		}
		/* Insert the  SSID string */
		qdf_mem_copy(( pbeacon_frame + tmp_pos_ssid),vap->iv_des_ssid[0].ssid,vap->iv_des_ssid[0].len);
		/* Copy rest of the Beacon data */
		qdf_mem_copy(( pbeacon_frame + tmp_pos_ssid + vap->iv_des_ssid[0].len),tmp,copy_length);
		OS_FREE(tmp);
		tmp  = NULL;
	    } else {
		qdf_print("Require size is more than allocated \n");
		return  -ENOMEM;
	    }
        }
    }
    return EOK;
}

ieee80211_scan_entry_t
ieee80211_update_beacon(struct ieee80211_node      *ni,
                        wbuf_t                     wbuf,
                        struct ieee80211_frame     *wh,
                        int                        subtype,
                        struct ieee80211_rx_status *rs)
{
    struct ieee80211com       *ic = ni->ni_ic;
    ieee80211_scan_entry_t    scan_entry;
    struct ieee80211vap       *vap = ni->ni_vap;

    if (vap->iv_opmode== IEEE80211_M_STA && ic->ic_strict_pscan_enable == 1
            && subtype == IEEE80211_FC0_SUBTYPE_BEACON )
    {
        ieee80211_add_ssid_to_hiddenssid_beacon(ni, wbuf, subtype);
    }

    scan_entry = ieee80211_scan_table_update(ni->ni_vap,
                                             wh,
                                             wbuf_get_pktlen(wbuf),
                                             subtype,
                                             rs->rs_rssi,
                                             rs->rs_full_chan);

    if (scan_entry != NULL) {
        u_int8_t    *bssid = ieee80211_scan_entry_bssid(scan_entry);
        bool        bssid_match = false;

        if (bssid != NULL) {
            if (IEEE80211_ADDR_EQ(ni->ni_bssid, bssid)) {
                bssid_match = true;
            }
        }

        ieee80211_scan_scanentry_received(ic->ic_scanner, bssid_match);
    }

    return scan_entry;
}

static int
ieee80211_recv_beacon(struct ieee80211_node *ni, wbuf_t wbuf, int subtype, struct ieee80211_rx_status *rs)
{
    struct ieee80211vap                          *vap = ni->ni_vap;
    struct ieee80211_frame                       *wh;
    ieee80211_scan_entry_t                       scan_entry;
    u_int8_t                                     *ssid;
    u_int8_t nullbssid[IEEE80211_ADDR_LEN] = {0x00,0x00,0x00,0x00,0x00,0x00};
    struct ieee80211_mlme_priv                   *mlme_priv = vap->iv_mlme_priv;

    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    if((IEEE80211_FC0_SUBTYPE_BEACON == subtype) && (unlikely(!IEEE80211_IS_BROADCAST(wh->i_addr1))))
        return EOK;
    /*If bssid is NULL drop the frame*/
    if(!OS_MEMCMP(wh->i_addr3,nullbssid,IEEE80211_ADDR_LEN))
    {
        return -EINVAL;
    }

    if ((subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP) && (IEEE80211_M_STA == vap->iv_opmode)
            && (mlme_priv->im_request_type == MLME_REQ_JOIN_INFRA)) {

	if (( ni == vap->iv_bss ) && ( 0 == ni->ni_associd ) && (!IEEE80211_ADDR_EQ(wh->i_addr3, ieee80211_node_get_bssid(ni)))) {

	    IEEE80211_DPRINTF(vap,IEEE80211_MSG_MLME,
		"%s Unmatch Proberesp during STA join,skip scan entry update addr3:%02X:%02X:%02X:%02X:%02X:%02X\n",__func__,
		wh->i_addr3[0],wh->i_addr3[1],wh->i_addr3[2],wh->i_addr3[3],wh->i_addr3[4],wh->i_addr3[5]);
	    return EOK;
	}
    }

    scan_entry = ieee80211_update_beacon(ni, wbuf, wh, subtype, rs);
    if (scan_entry != NULL)
    {
        ssid = ieee80211_scan_entry_ssid(scan_entry, &vap->iv_esslen);
        if (ssid != NULL) {
            if(vap->iv_esslen < sizeof(vap->iv_essid)) {
                OS_MEMCPY(vap->iv_essid, ssid, vap->iv_esslen);
            }
        }
    }
    /*
     * The following code MUST be SSID independant.
     *
     * RefCount of scan_entry = 1.
     */
    if (scan_entry != NULL) {

        switch (vap->iv_opmode) {
        case IEEE80211_M_STA:
            ieee80211_recv_beacon_sta(ni,wbuf,subtype,rs,scan_entry);
            break;

        case IEEE80211_M_IBSS:
            ieee80211_recv_beacon_ibss(ni,wbuf,subtype,rs,scan_entry);
            break;

        case IEEE80211_M_HOSTAP:
            ieee80211_recv_beacon_ap(ni,wbuf,subtype,rs,scan_entry);
            break;

        case IEEE80211_M_BTAMP:
            ieee80211_recv_beacon_btamp(ni,wbuf,subtype,rs,scan_entry);
            break;

        default:
            break;
        }
    } /* scan_entry != NULL */

    return EOK;
}


static int
ieee80211_recv_auth(struct ieee80211_node *ni, wbuf_t wbuf, int subtype,
                    struct ieee80211_rx_status *rs)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211_frame *wh;
    u_int8_t *frm, *efrm;
    u_int16_t algo, seq, status;
    u_int8_t *challenge = NULL, challenge_len = 0;
    int deref_reqd = 0;
    int ret_val = EOK;
    u_int16_t associd = 0;

    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    /*
     * can only happen for HOST AP mode .
     */
    if (wh->i_fc[1] & IEEE80211_FC1_WEP) {
        struct ieee80211_key *key;

        key = ieee80211_crypto_decap(ni, wbuf, ieee80211_hdrspace(ni->ni_ic,wh), rs);
        if (key) {
            wh = (struct ieee80211_frame *) wbuf_header(wbuf);
            wh->i_fc[1] &= ~IEEE80211_FC1_WEP;
        }
        /*
         * if crypto decap fails (key == null) let the
         * ieee80211_mlme_recv_auth will discard the request(algo and/or
         * auth seq # is going to be bogus) and also handle any stattion
         * ref count.
         */
    }

    frm = (u_int8_t *)&wh[1];
    efrm = wbuf_header(wbuf) + wbuf_get_pktlen(wbuf);
    /*
     * XXX bug fix 89056: Station Entry exists in the node table,
     * But the node is associated with the other vap, so we are
     * deleting that node and creating the new node
     *
     */
    if (!IEEE80211_ADDR_EQ(wh->i_addr1, vap->iv_myaddr)) {

        struct ieee80211vap *tmpvap;
        struct ieee80211com *ic = ni->ni_ic;

        TAILQ_FOREACH(tmpvap, &(ic)->ic_vaps, iv_next) {

           if(IEEE80211_ADDR_EQ(wh->i_addr1, tmpvap->iv_myaddr) &&
              (tmpvap->iv_opmode == IEEE80211_M_HOSTAP)) {

               if (ni != vap->iv_bss) {
                  IEEE80211_NOTE(vap, IEEE80211_MSG_MLME, ni,
                            "%s", "Removing the node from the station node list\n");
                  ieee80211_ref_node(ni);
                  associd = ni->ni_associd;
                  if(_ieee80211_node_leave(ni)) {
                     /* Call MLME indication handler if node is in associated state */
                     IEEE80211_DELIVER_EVENT_MLME_DISASSOC_INDICATION(vap,
                                                                          ni->ni_macaddr, associd,
                                                                          IEEE80211_REASON_ASSOC_LEAVE);
                  }
                  ieee80211_free_node(ni);

                  if(tmpvap->iv_vap_is_down) {
                      ret_val = -EINVAL;
                      goto exit;
                  }

                  /* Referencing the BSS node */
                  ni = ieee80211_ref_bss_node(tmpvap);

                  /* Note that ieee80211_ref_bss_node must have a */
                  /* corresponding ieee80211_free_bss_node        */

                  if(ni != NULL) {
                    deref_reqd = 1;
                    vap = ni->ni_vap;
                  } else {
                    ret_val = -EINVAL;
                    goto exit;
                  }
              }
              break;
           }
        }
    }


    /*
     * XXX: when we're scanning, we may receive auth frames
     * of other stations in the same BSS.
     */
    if (!IEEE80211_ADDR_EQ(wh->i_addr1, vap->iv_myaddr) ||
        !IEEE80211_ADDR_EQ(wh->i_addr3, (ni)->ni_bssid)) {
        IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
        wh, ieee80211_mgt_subtype_name[subtype >>
        IEEE80211_FC0_SUBTYPE_SHIFT],
        "%s", "frame not for me");
        ret_val = -EINVAL;
        goto exit;
    }

    /*
     * auth frame format
     *  [2] algorithm
     *  [2] sequence
     *  [2] status
     *  [tlv*] challenge
     */
    if ((efrm - frm) < 6) {
        IEEE80211_DISCARD(vap, IEEE80211_MSG_ELEMID,
        wh, ieee80211_mgt_subtype_name[subtype >>
        IEEE80211_FC0_SUBTYPE_SHIFT],
        "%s", "ie too short\n");
        vap->iv_stats.is_rx_mgtdiscard++;
        ret_val = -EINVAL;
        goto exit;
    }

    algo = le16toh(*(u_int16_t *)frm); frm += 2;
    seq = le16toh(*(u_int16_t *)frm); frm += 2;
    status = le16toh(*(u_int16_t *)frm); frm += 2;

    /* Validate challenge TLV if any */
    if (algo == IEEE80211_AUTH_ALG_SHARED) {
        if (frm + 1 < efrm) {
            if ((frm[1] + 2) > (efrm - frm)) {
                IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_AUTH,
                                      ni->ni_macaddr, "shared key auth",
                                      "ie %d/%d too long",
                                      frm[0], (frm[1] + 2) - (efrm - frm));
                vap->iv_stats.is_rx_bad_auth++;
                ret_val = -EINVAL;
                goto exit;
            }
            if (frm[0] == IEEE80211_ELEMID_CHALLENGE) {
                challenge = frm + 2;
                challenge_len = frm[1];
            }
        }

        if (seq == IEEE80211_AUTH_SHARED_CHALLENGE ||
            seq == IEEE80211_AUTH_SHARED_RESPONSE) {
            if ((challenge == NULL || challenge_len == 0) && (status == 0)) {
                IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_AUTH,
                                      ni->ni_macaddr, "shared key auth",
                                      "%s", "no challenge");
                vap->iv_stats.is_rx_bad_auth++;
                ret_val = -EINVAL;
                goto exit;
            }
        }
    }

    ret_val = ieee80211_mlme_recv_auth(ni, algo, seq, status, challenge, challenge_len,wbuf,rs);
exit:
    /* Note that ieee80211_ref_bss_node must have a */
    /* corresponding ieee80211_free_bss_node        */

    if (deref_reqd)
        ieee80211_free_node(ni);
    return ret_val;
}

static int
ieee80211_recv_deauth(struct ieee80211_node *ni, wbuf_t wbuf, int subtype)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211_frame *wh;
    u_int8_t *frm, *efrm;
    u_int16_t reason;

    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    frm = (u_int8_t *)&wh[1];
    efrm = wbuf_header(wbuf) + wbuf_get_pktlen(wbuf);

    if (!(IEEE80211_IS_BROADCAST(wh->i_addr1) || IEEE80211_IS_MULTICAST(wh->i_addr1))) {
        IEEE80211_VERIFY_ADDR(ni);

        /*
         * deauth frame format
         *  [2] reason
         */
        IEEE80211_VERIFY_LENGTH(efrm - frm, 2);
    }
    reason = le16toh(*(u_int16_t *)frm);

    if (((ieee80211_is_pmf_enabled(vap, ni) && ni->ni_ucastkey.wk_valid )||
        (vap->iv_ccx_evtable && vap->iv_ccx_evtable->wlan_ccx_is_mfp &&
            vap->iv_ccx_evtable->wlan_ccx_is_mfp(vap->iv_ifp))) &&
        !(wh->i_fc[1] & IEEE80211_FC1_WEP)) {
        if (!(IEEE80211_IS_BROADCAST(wh->i_addr1) || IEEE80211_IS_MULTICAST(wh->i_addr1)) ||
            !ieee80211_is_mmie_valid(vap, ni, (u_int8_t *)wh, efrm)) {
            /*
             * Check if MFP is enabled for connection.
             */
            IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
                              wh, ieee80211_mgt_subtype_name[
                                  subtype >> IEEE80211_FC0_SUBTYPE_SHIFT],
                              "%s", "deauth frame is not encrypted");
            IEEE80211_DELIVER_EVENT_MLME_UNPROTECTED_DEAUTH_INDICATION(ni->ni_vap,
                                   (wh->i_addr2), ni->ni_associd, reason);
            return -EINVAL;
        }
    }

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "Received Deauth with reason %d\n", reason);

    ieee80211_mlme_recv_deauth(ni, reason);

    return EOK;
}

static int
ieee80211_recv_disassoc(struct ieee80211_node *ni, wbuf_t wbuf, int subtype)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211_frame *wh;
    u_int8_t *frm, *efrm;
    u_int16_t reason;

    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    frm = (u_int8_t *)&wh[1];
    efrm = wbuf_header(wbuf) + wbuf_get_pktlen(wbuf);

    if (!(IEEE80211_IS_BROADCAST(wh->i_addr1) || IEEE80211_IS_MULTICAST(wh->i_addr1))) {
        IEEE80211_VERIFY_ADDR(ni);

        /*
         * disassoc frame format
         *  [2] reason
         */
        IEEE80211_VERIFY_LENGTH(efrm - frm, 2);
    }
    reason = le16toh(*(u_int16_t *)frm);

    if (((ieee80211_is_pmf_enabled(vap, ni) && ni->ni_ucastkey.wk_valid) ||
        (vap->iv_ccx_evtable && vap->iv_ccx_evtable->wlan_ccx_is_mfp &&
            vap->iv_ccx_evtable->wlan_ccx_is_mfp(vap->iv_ifp))) &&
        !(wh->i_fc[1] & IEEE80211_FC1_WEP)) {
        if (!(IEEE80211_IS_BROADCAST(wh->i_addr1) || IEEE80211_IS_MULTICAST(wh->i_addr1)) ||
            !ieee80211_is_mmie_valid(vap, ni, (u_int8_t *)wh, efrm)) {
            /*
             * Check if MFP is enabled for connection.
             */
            IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
                              wh, ieee80211_mgt_subtype_name[
                                  subtype >> IEEE80211_FC0_SUBTYPE_SHIFT],
                              "%s", "disassoc frame is not encrypted");
            return -EINVAL;
        }
    }

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "Received Disassoc with reason %d\n", reason);

    ieee80211_mlme_recv_disassoc(ni, reason);

    return EOK;
}

static int
ieee80211_recv_action(struct ieee80211_node *ni, wbuf_t wbuf, int subtype, struct ieee80211_rx_status *rs)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211_frame *wh;
    u_int8_t *frm, *efrm;
    struct ieee80211_action *ia;
    bool fgActionForMe = FALSE, fgBCast = FALSE, fgMcast = FALSE;
    bool action_taken = TRUE;

    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    frm = (u_int8_t *)&wh[1];
    efrm = wbuf_header(wbuf) + wbuf_get_pktlen(wbuf);
    ia = (struct ieee80211_action *) frm;

    /* Do not filter public action frame when Addr3 matches BSSID or WildCard */
    if (ia->ia_category == IEEE80211_ACTION_CAT_PUBLIC &&
       (IEEE80211_ADDR_EQ(wh->i_addr3, ni->ni_bssid) ||
       IEEE80211_IS_BROADCAST(wh->i_addr3)) &&
       !((ni->ni_flags & IEEE80211_NODE_NAWDS))) {
        IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
            "%s: action mgt frame (cat %d, act %d addr3 %s)\n",
            __func__, ia->ia_category, ia->ia_action, ether_sprintf(wh->i_addr3));
    }
    else if (!(IEEE80211_ADDR_EQ(wh->i_addr3, ni->ni_bssid)) &&
        !((ni->ni_flags & IEEE80211_NODE_NAWDS))) {
        IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
                          wh, ieee80211_mgt_subtype_name[
                              IEEE80211_FC0_SUBTYPE_ACTION >> IEEE80211_FC0_SUBTYPE_SHIFT],
                          "%s", "action frame not in same BSS");
       return -EINVAL;
    }

    if (!ieee80211_vap_ready_is_set(vap)) {
        vap->iv_stats.is_rx_mgtdiscard++;
        return -EINVAL;
    }

    if (IEEE80211_ADDR_EQ(wh->i_addr1, vap->iv_myaddr)) {
        fgActionForMe = TRUE;
    }
    else if(IEEE80211_ADDR_EQ(wh->i_addr1, IEEE80211_GET_BCAST_ADDR(ic)))
    {
        fgBCast = TRUE;
    }
    else if(IEEE80211_IS_MULTICAST(wh->i_addr1)) {
        fgMcast = TRUE;
    }

    IEEE80211_VERIFY_LENGTH(efrm - frm, sizeof(struct ieee80211_action));
    vap->iv_stats.is_rx_action++;
    IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                   "%s: action mgt frame (cat %d, act %d)\n",__func__, ia->ia_category, ia->ia_action);
    if (ia->ia_category == IEEE80211_ACTION_CAT_WNM &&
            (ia->ia_action == IEEE80211_ACTION_FMS_RESP)) {
        /* FMS unsolicited responses are sent to multicast group addr */
        if (!(fgMcast || fgActionForMe)) {
            return -EINVAL;
        }
    }
    else if ((ia->ia_category == IEEE80211_ACTION_CAT_SPECTRUM &&
         (ia->ia_action == IEEE80211_ACTION_CHAN_SWITCH ||
          ia->ia_action == IEEE80211_ACTION_MEAS_REPORT)) ||
         (ia->ia_category == IEEE80211_ACTION_CAT_VHT) ||
         (ia->ia_category == IEEE80211_ACTION_CAT_HT)
       ) {
        if (!(fgBCast || fgActionForMe)) {
            /* CSA action frame and VHT OP mode notify could be broadcast */
            return -EINVAL;
        }
    }
    else{

        if (!fgActionForMe) {
            return -EINVAL;
        }
    }

    switch (ia->ia_category) {
    case IEEE80211_ACTION_CAT_SPECTRUM:
        switch (ia->ia_action) {
            case IEEE80211_ACTION_CHAN_SWITCH:
                if (ieee80211_process_csa_ecsa_ie(ni,  ia) != EOK) {
                    /*
                     * If failed to switch the channel, mark the AP as radar detected and disconnect from the AP.
                     */
                    ieee80211_mlme_recv_csa(ni, IEEE80211_RADAR_DETECT_DEFAULT_DELAY,true);
                }
#if ATH_SUPPORT_SPLITMAC
                if (vap->iv_splitmac) {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH, "Forward chan switch action mgt "\
                        "frame with category 0x%2X type 0x%2X\n", ia->ia_category, ia->ia_action );
                    action_taken = FALSE;
                }
#endif
                break;
#if ATH_SUPPORT_IBSS_DFS
            case IEEE80211_ACTION_MEAS_REPORT:
                ieee80211_process_meas_report_ie(ni, ia);
#if ATH_SUPPORT_SPLITMAC
                if (vap->iv_splitmac) {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH, "Forward meas rpt action mgt "\
                        "frame with category 0x%2X type 0x%2X\n", ia->ia_category, ia->ia_action );
                    action_taken = FALSE;
                }
#endif
                break;
#endif /* ATH_SUPPORT_IBSS_DFS */

            default:
                action_taken = FALSE;
                break;
        }
 	break;
    case IEEE80211_ACTION_CAT_RM:
#if QCA_LTEU_SUPPORT
        /* Check if radio is in LTEu mode */
        if (ic->ic_nl_handle) {
            ieee80211_rrm_recv_action(vap, ni, ia->ia_action, frm, (efrm - frm));
            action_taken = FALSE; // libaplink : action_taken set to false so that frame can be forwarded to user space.
        } else {
            if (ieee80211_rrm_recv_action(vap, ni, ia->ia_action, frm, (efrm - frm)) != EOK)
                action_taken = FALSE;
        }
#else
        if (ieee80211_rrm_recv_action(vap, ni, ia->ia_action, frm, (efrm - frm)) != EOK)
            action_taken = FALSE;
#endif
        break;
#if UMAC_SUPPORT_WNM
    case IEEE80211_ACTION_CAT_WNM:
        /* Currently, AP and STA use different ways to report action frames to app */
        if (vap->iv_opmode == IEEE80211_M_STA)
            ieee80211_wnm_forward_action_app(vap, ni, wbuf, subtype, rs);

        if (ieee80211_wnm_recv_action(vap, ni, ia->ia_action, frm, (efrm - frm)) != EOK)
            action_taken = FALSE;
        break;
#endif /* UMAC_SUPPORT_WNM */
    case IEEE80211_ACTION_CAT_QOS:
        IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                       "%s: QoS action mgt frames not supported", __func__);
        vap->iv_stats.is_rx_mgtdiscard++;
        action_taken = FALSE;
        break;

    case IEEE80211_ACTION_CAT_WMM_QOS:
        /* WiFi WMM QoS TSPEC action management frames */
        IEEE80211_VERIFY_LENGTH(efrm - frm, sizeof(struct ieee80211_action_wmm_qos));
        switch (ia->ia_action) {
        case IEEE80211_WMM_QOS_ACTION_SETUP_REQ:
            /* ADDTS received by AP */
            ieee80211_recv_addts_req(ni, &((struct ieee80211_action_wmm_qos *)ia)->ts_tspecie,
                ((struct ieee80211_action_wmm_qos *)ia)->ts_dialogtoken);
            break;

        case IEEE80211_WMM_QOS_ACTION_SETUP_RESP: {
            /* ADDTS response from AP */
            struct ieee80211_wme_tspec *tspecie;
            if ((vap->iv_opmode == IEEE80211_M_STA) &&
                (vap->iv_ccx_evtable && vap->iv_ccx_evtable->wlan_ccx_is_mfp &&
                    vap->iv_ccx_evtable->wlan_ccx_is_mfp(vap->iv_ifp)) &&
                !(wh->i_fc[1] & IEEE80211_FC1_WEP)) {
                /*
                 * Check if MFP is enabled for connection.
                 */
                IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                               "%s: QoS action mgt frame is not encrypted", __func__);
                vap->iv_stats.is_rx_mgtdiscard++;
                break;
            }

            if (((struct ieee80211_action_wmm_qos *)ia)->ts_statuscode != 0) {
                /* tspec was not accepted */
                /* Indicate to CCX and break. */
                /* AP will send us a disassoc anyway if we try assoc */
                wlan_set_tspecActive(vap, 0);
                if (vap->iv_ccx_evtable && vap->iv_ccx_evtable->wlan_ccx_set_vperf) {
                    vap->iv_ccx_evtable->wlan_ccx_set_vperf(vap->iv_ccx_arg, 0);
                }
                /* Trigger Roam for unspecified QOS-related reason. */
                //Sta11DeauthIndication(vap->iv_mlme_arg, ni->ni_macaddr, IEEE80211_REASON_QOS);
                //StaCcxTriggerRoam(vap->iv_mlme_arg, IEEE80211_REASON_QOS);
                if (vap->iv_ccx_evtable && vap->iv_ccx_evtable->wlan_ccx_trigger_roam) {
                    vap->iv_ccx_evtable->wlan_ccx_trigger_roam(vap->iv_ccx_arg, IEEE80211_REASON_QOS);
                }
                break;
            }
            tspecie = &((struct ieee80211_action_wmm_qos *)ia)->ts_tspecie;
            ieee80211_parse_tspecparams(vap, (u_int8_t *) tspecie);
            wlan_set_tspecActive(vap, 1);
            if (vap->iv_ccx_evtable && vap->iv_ccx_evtable->wlan_ccx_set_vperf) {
                vap->iv_ccx_evtable->wlan_ccx_set_vperf(vap->iv_ccx_arg, 1);
            }
            break;
        }

        case IEEE80211_WMM_QOS_ACTION_TEARDOWN: {
            ieee80211_recv_delts_req(ni, &((struct ieee80211_action_wmm_qos *)ia)->ts_tspecie);
			break;
	    }

        default:
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: invalid WME action mgt frame", __func__);
            vap->iv_stats.is_rx_mgtdiscard++;
            action_taken = FALSE;
        }
        break;

#if UMAC_SUPPORT_HS20_L2TIF
    case IEEE80211_ACTION_CAT_DLS:
        switch (ia->ia_action) {
        case IEEE80211_ACTION_DLS_REQUEST:
            if (IEEE80211_VAP_IS_NOBRIDGE_ENABLED(vap)) {
                struct ieee80211_dls_response *resp;
                struct ieee80211_dls_request *req = (struct ieee80211_dls_request *)ia;
                char dhost[32];
                wbuf_t wbuf;
                u_int8_t *frm1 = NULL;
                struct ieee80211_frame *wh1;

                wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm1, 1);
                if (wbuf == NULL)
                    return -ENOMEM;

                wh1 = (struct ieee80211_frame *)wbuf_header(wbuf);
                memcpy(wh1->i_addr1, wh->i_addr2, IEEE80211_ADDR_LEN);

                /* Send DLS response w/ status code: not allowed by policy */
                resp = (struct ieee80211_dls_response *)frm1;
                resp->hdr.ia_category   = IEEE80211_ACTION_CAT_DLS;
                resp->hdr.ia_action     = IEEE80211_ACTION_DLS_RESPONSE;
                resp->statuscode        = htole16(IEEE80211_STATUS_DLS_NOT_ALLOWED);
                memcpy(resp->dst_addr, req->src_addr, IEEE80211_ADDR_LEN);
                memcpy(resp->src_addr, req->dst_addr, IEEE80211_ADDR_LEN);
                wbuf_set_pktlen(wbuf, sizeof(struct ieee80211_frame) +
                                      sizeof(struct ieee80211_dls_response));

                if (ieee80211_is_pmf_enabled(vap, ni) && ni->ni_ucastkey.wk_valid) {
                    /* MFP is enabled, so we need to set Privacy bit */
                    wh1->i_fc[1] |= IEEE80211_FC1_WEP;
                }

                memcpy(dhost, ether_sprintf(req->dst_addr), 32);
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_L2TIF, "HS20 L2TIF: "
                        "DLS request %s -> %s is not allowed by local policy\n",
                        ether_sprintf(req->src_addr), dhost);

                if (ieee80211_send_mgmt(ni->ni_vap, ni, wbuf, false) != EOK)
                    action_taken = FALSE;
            }
            break;

        case IEEE80211_ACTION_DLS_RESPONSE:
        case IEEE80211_ACTION_DLS_TEARDOWN:
        default:
            action_taken = FALSE;
            break;
        }
        break;
#endif

    case IEEE80211_ACTION_CAT_BA: {
        struct ieee80211_action_ba_addbarequest *addbarequest;
        struct ieee80211_action_ba_addbaresponse *addbaresponse;
        struct ieee80211_action_ba_delba *delba;
        struct ieee80211_ba_seqctrl basequencectrl;
        struct ieee80211_ba_parameterset baparamset;
        struct ieee80211_delba_parameterset delbaparamset;
        struct ieee80211_action_mgt_args actionargs;
        u_int16_t statuscode;
        u_int16_t batimeout;
        u_int16_t reasoncode;

        switch (ia->ia_action) {
        case IEEE80211_ACTION_BA_ADDBA_REQUEST:
            IEEE80211_VERIFY_LENGTH(efrm - frm, sizeof(struct ieee80211_action_ba_addbarequest));
            addbarequest = (struct ieee80211_action_ba_addbarequest *) frm;

            /* "struct ieee80211_action_ba_addbarequest" is annotated __packed,
               if accessing fields, like rq_baparamset or rq_basequencectrl,
               by using u_int16_t* directly, it will cause byte alignment issue.
               Some platform that cannot handle this issue will cause exception.
               Use OS_MEMCPY to move data byte by byte */
            OS_MEMCPY(&baparamset, &addbarequest->rq_baparamset, sizeof(baparamset));
            *(u_int16_t *)&baparamset = le16toh(*(u_int16_t*)&baparamset);
            batimeout = le16toh(addbarequest->rq_batimeout);
            OS_MEMCPY(&basequencectrl, &addbarequest->rq_basequencectrl, sizeof(basequencectrl));
            *(u_int16_t *)&basequencectrl = le16toh(*(u_int16_t*)&basequencectrl);

            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: ADDBA request action mgt frame. TID %d, buffer size %d",
                           __func__, baparamset.tid, baparamset.buffersize);

            /*
             * NB: The user defined ADDBA response status code is overloaded for
             * non HT capable node and WDS node
             */
            if (!IEEE80211_NODE_ISAMPDU(ni)) {
                /* The node is not HT capable - set the ADDBA status to refused */
                ic->ic_addba_setresponse(ni, baparamset.tid, IEEE80211_STATUS_REFUSED);
            } else if (IEEE80211_VAP_IS_WDS_ENABLED(ni->ni_vap)) {
                /* The node is WDS and HT capable */
                if (ieee80211_node_wdswar_isaggrdeny(ni)) {
                    /*Aggr is denied for WDS - set the addba response to REFUSED*/
                    ic->ic_addba_setresponse(ni, baparamset.tid, IEEE80211_STATUS_REFUSED);
                } else {
                    /*Aggr is allowed for WDS - set the addba response to SUCCESS*/
                    ic->ic_addba_setresponse(ni, baparamset.tid, IEEE80211_STATUS_SUCCESS);
                }
            }

            /* Process ADDBA request and save response in per TID data structure */
            if (ic->ic_addba_requestprocess &&
                ic->ic_addba_requestprocess(ni, addbarequest->rq_dialogtoken,
                                         &baparamset, batimeout, basequencectrl) == 0) {
                /* Send ADDBA response */
                actionargs.category     = IEEE80211_ACTION_CAT_BA;
                actionargs.action       = IEEE80211_ACTION_BA_ADDBA_RESPONSE;
                actionargs.arg1         = baparamset.tid;
                actionargs.arg2         = 0;
                actionargs.arg3         = 0;

                ieee80211_send_action(ni, &actionargs, NULL);
            }
            break;

        case IEEE80211_ACTION_BA_ADDBA_RESPONSE:
            if (!IEEE80211_NODE_USE_HT(ni)) {
                IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                               "%s: ADDBA response frame ignored for non-HT association)", __func__);
                break;
            }
            IEEE80211_VERIFY_LENGTH(efrm - frm, sizeof(struct ieee80211_action_ba_addbaresponse));
            addbaresponse = (struct ieee80211_action_ba_addbaresponse *) frm;

            statuscode = le16toh(addbaresponse->rs_statuscode);
            /* "struct ieee80211_action_ba_addbaresponse" is annotated __packed,
               if accessing fields, like rs_baparamset, by using u_int16_t* directly,
               it will cause byte alignment issue.
               Some platform that cannot handle this issue will cause exception.
               Use OS_MEMCPY to move data byte by byte */
            OS_MEMCPY(&baparamset, &addbaresponse->rs_baparamset, sizeof(baparamset));
            *(u_int16_t *)&baparamset = le16toh(*(u_int16_t*)&baparamset);
            batimeout = le16toh(addbaresponse->rs_batimeout);

            spin_lock(&ic->ic_addba_lock);
            if (ic->ic_addba_responseprocess)
                ic->ic_addba_responseprocess(ni, statuscode, &baparamset, batimeout);
            spin_unlock(&ic->ic_addba_lock);

            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: ADDBA response action mgt frame. TID %d, buffer size %d",
                           __func__, baparamset.tid, baparamset.buffersize);
            break;

        case IEEE80211_ACTION_BA_DELBA:
            if (!IEEE80211_NODE_USE_HT(ni)) {
                IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                               "%s: DELBA frame ignored for non-HT association)", __func__);
                break;
            }
            IEEE80211_VERIFY_LENGTH(efrm - frm, sizeof(struct ieee80211_action_ba_delba));

            delba = (struct ieee80211_action_ba_delba *) frm;
            /* "struct ieee80211_action_ba_delba" is annotated __packed,
               if accessing fields, like dl_delbaparamset, by using u_int16_t* directly,
               it will cause byte alignment issue.
               Some platform that cannot handle this issue will cause exception.
               Use OS_MEMCPY to move data byte by byte */
            OS_MEMCPY(&delbaparamset, &delba->dl_delbaparamset, sizeof(delbaparamset));
            *(u_int16_t *)&delbaparamset= le16toh(*(u_int16_t*)&delbaparamset);
            reasoncode = le16toh(delba->dl_reasoncode);

            spin_lock(&ic->ic_addba_lock);
            if (ic->ic_delba_process)
                ic->ic_delba_process(ni, &delbaparamset, reasoncode);
            spin_unlock(&ic->ic_addba_lock);

            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: DELBA action mgt frame. TID %d, initiator %d, reason code %d",
                           __func__, delbaparamset.tid, delbaparamset.initiator, reasoncode);
            break;

        default:
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: invalid BA action mgt frame", __func__);
            vap->iv_stats.is_rx_mgtdiscard++;
            break;
        }
        break;
    }

    case IEEE80211_ACTION_CAT_PUBLIC: {
         struct ieee80211_action_bss_coex_frame *iabsscoex;

         IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                        "%s: Received Coex Category, action %d\n",
                       __func__, ia->ia_action);

         /* Only process coex action frame if this VAP is in AP and the associated node is in HT mode */
         if (vap->iv_opmode == IEEE80211_M_HOSTAP && (ni->ni_flags & IEEE80211_NODE_HT)) {
             switch(ia->ia_action)
             {
                 case 0:
                      /* Check frame length for mandatory fields only */
                     IEEE80211_VERIFY_LENGTH(efrm - frm, (sizeof(struct ieee80211_action_bss_coex_frame) - sizeof(struct ieee80211_ie_intolerant_report)));
                     iabsscoex = (struct ieee80211_action_bss_coex_frame *) frm;
                     IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                               "%s: Element 0\n"
                               "inf request = %d\t"
                               "40 intolerant = %d\t"
                               "20 width req = %d\t"
                               "obss exempt req = %d\t"
                               "obss exempt grant = %d\n", __func__,
                               iabsscoex->coex.inf_request,
                               iabsscoex->coex.ht40_intolerant,
                               iabsscoex->coex.ht20_width_req,
                               iabsscoex->coex.obss_exempt_req,
                               iabsscoex->coex.obss_exempt_grant);

                     if ((((efrm - frm) >= sizeof(struct ieee80211_action_bss_coex_frame)) && bss_intol_channel_check(ni, &iabsscoex->chan_report)) ||
                         iabsscoex->coex.ht40_intolerant ||
                         iabsscoex->coex.ht20_width_req) {

                         /* If RSSI greater than/equal threshold then only do CW change */
                         if (rs->rs_rssi >= ic->obss_rx_rssi_threshold) {
                             ni->ni_flags |= IEEE80211_NODE_REQ_HT20;
                         }
                     } else {
                         ni->ni_flags &= ~IEEE80211_NODE_REQ_HT20;
                     }

                     ieee80211_change_cw(ic);

                     break;
                default:
                    IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                                   "%s: invalid Coex action mgt frame", __func__);
                    vap->iv_stats.is_rx_mgtdiscard++;
                    action_taken = FALSE;
            }
         } else {
             action_taken = FALSE;
         }
        break;
    }

    case IEEE80211_ACTION_CAT_HT: {
        struct ieee80211_action_ht_txchwidth *iachwidth;
        enum ieee80211_cwm_width  chwidth;
        struct ieee80211_action_ht_smpowersave *iasmpowersave;

        if (!IEEE80211_NODE_ISAMPDU(ni)) {
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: HT action mgt frame ignored for non-HT association)", __func__);
            break;
        }
        switch (ia->ia_action) {
        case IEEE80211_ACTION_HT_TXCHWIDTH:
            IEEE80211_VERIFY_LENGTH(efrm - frm, sizeof(struct ieee80211_action_ht_txchwidth));

            iachwidth = (struct ieee80211_action_ht_txchwidth *) frm;
            chwidth = (iachwidth->at_chwidth == IEEE80211_A_HT_TXCHWIDTH_2040) ?
                IEEE80211_CWM_WIDTH40 : IEEE80211_CWM_WIDTH20;

            /* Check for channel width change */
            if (chwidth != ni->ni_chwidth) {
                u_int32_t  rxlinkspeed, txlinkspeed; /* bits/sec */

                 /* update node's recommended tx channel width */
                ni->ni_chwidth = chwidth;
                ic->ic_chwidth_change(ni);

                mlme_get_linkrate(ni, &rxlinkspeed, &txlinkspeed);
                IEEE80211_DELIVER_EVENT_LINK_SPEED(vap, rxlinkspeed, txlinkspeed);
            }

            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: HT txchwidth action mgt frame. Width %d (%s)",
                           __func__, chwidth, ni->ni_newchwidth? "new" : "no change");
            break;

        case IEEE80211_ACTION_HT_SMPOWERSAVE:
            if (vap->iv_opmode != IEEE80211_M_HOSTAP) {
                IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                               "%s: HT SM pwrsave request ignored for non-AP)", __func__);
                break;
            }
            IEEE80211_VERIFY_LENGTH(efrm - frm, sizeof(struct ieee80211_action_ht_smpowersave));

            iasmpowersave = (struct ieee80211_action_ht_smpowersave *) frm;

            if (iasmpowersave->as_control & IEEE80211_A_HT_SMPOWERSAVE_ENABLED) {
                if (iasmpowersave->as_control & IEEE80211_A_HT_SMPOWERSAVE_MODE) {
                    if ((ni->ni_htcap & IEEE80211_HTCAP_C_SM_MASK) !=
                        IEEE80211_HTCAP_C_SMPOWERSAVE_DYNAMIC) {
                        /*
                         * Station just enabled dynamic SM power save therefore
                         * we should precede each packet we send to it with an RTS.
                         */
                        ni->ni_htcap &= (~IEEE80211_HTCAP_C_SM_MASK);
                        ni->ni_htcap |= IEEE80211_HTCAP_C_SMPOWERSAVE_DYNAMIC;
                        ni->ni_updaterates = IEEE80211_NODE_SM_PWRSAV_DYN;
                    }
                } else {
                    if ((ni->ni_htcap & IEEE80211_HTCAP_C_SM_MASK) !=
                        IEEE80211_HTCAP_C_SMPOWERSAVE_STATIC) {
                        /*
                         * Station just enabled static SM power save therefore
                         * we can only send to it at single-stream rates.
                         */
                        ni->ni_htcap &= (~IEEE80211_HTCAP_C_SM_MASK);
                        ni->ni_htcap |= IEEE80211_HTCAP_C_SMPOWERSAVE_STATIC;
                        ni->ni_updaterates = IEEE80211_NODE_SM_PWRSAV_STAT;
                    }
                }
            } else {
                if ((ni->ni_htcap & IEEE80211_HTCAP_C_SM_MASK) !=
                    IEEE80211_HTCAP_C_SMPOWERSAVE_DISABLED) {
                    /*
                     * Station just disabled SM Power Save therefore we can
                     * send to it at full SM/MIMO.
                     */
                    ni->ni_htcap &= (~IEEE80211_HTCAP_C_SM_MASK);
                    ni->ni_htcap |= IEEE80211_HTCAP_C_SMPOWERSAVE_DISABLED;
                    ni->ni_updaterates = IEEE80211_NODE_SM_EN;
                }
            }
            if (ni->ni_updaterates) {
                ni->ni_updaterates |= IEEE80211_NODE_RATECHG;
            }
            /* Update MIMO powersave flags and node rates */
            ieee80211_update_noderates(ni);

#ifdef ATH_SUPPORT_HTC
            /* Update target node's HT flags. */
            ieee80211_update_node_target(ni, ni->ni_vap);
#endif
            break;
#ifdef ATH_SUPPORT_TxBF
    case IEEE80211_ACTION_HT_NONCOMP_BF:
    case IEEE80211_ACTION_HT_COMP_BF:
#ifdef TXBF_DEBUG
        ic->ic_txbf_check_cvcache(ic, ni);
#endif
        /* report received , cancel timer */
        OS_CANCEL_TIMER(&ni->ni_report_timer);

        ni->ni_cvtstamp = rs->rs_rpttstamp;
        ic->ic_txbf_set_rpt_received(ic, ni);
        ic->ic_txbf_stats_rpt_inc(ic, ni);

        /* skip action header and mimo control field*/
        frm += sizeof(struct ieee80211_action_ht_txbf_rpt);

        /* EV 78384 CV/V report generated by osprey will be zero at some case,
        when it happens , it should get another c/cv report immediately to overwrite
        wrong one*/
        if ((frm[0] == 0) && (frm[1] ==0) && (frm[2]==0)){
            ni->ni_bf_update_cv = 1;    // request to update CV cache
        }
        break;
#endif
        default:
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                           "%s: invalid HT action mgt frame", __func__);
            vap->iv_stats.is_rx_mgtdiscard++;
            break;
        }
        action_taken = FALSE; // set to false so that it is forwarded to hostapd
        break;
    }

    case IEEE80211_ACTION_CAT_VHT: {

        switch (ia->ia_action) {
            case IEEE80211_ACTION_VHT_OPMODE:
                {
                    struct ieee80211_action_vht_opmode *ia_opmode = (struct ieee80211_action_vht_opmode *)frm;

                    ieee80211_parse_opmode(ni, (u_int8_t *)&ia_opmode->at_op_mode, subtype);
                }
                break;
            default:
                IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                        "%s: Unhandled OR invalid VHT action code - %d", __func__, ia->ia_action);
                break;
        }
        action_taken = FALSE; // set to false so that it is forwarded to hostapd
        break;
    }

    case IEEE80211_ACTION_CAT_SA_QUERY: {
        struct ieee80211_action_sa_query *saQuery;
        saQuery = (struct ieee80211_action_sa_query *)frm;
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACTION, "Received SA_Query action "\
            "frame with action 0x%2X id 0x%2X\n", saQuery->sa_header.ia_action, saQuery->sa_transId);

        /* Hostapd takes care of Req/Resp for SA_QUERY in AP mode */

        if ((vap->iv_opmode == IEEE80211_M_STA) &&
            (saQuery->sa_header.ia_action == IEEE80211_ACTION_SA_QUERY_REQUEST)) {
            struct ieee80211_action_mgt_args actionargs;
            actionargs.category     = IEEE80211_ACTION_CAT_SA_QUERY;
            actionargs.action       = IEEE80211_ACTION_SA_QUERY_RESPONSE;
            actionargs.arg1         = saQuery->sa_transId;
            actionargs.arg2         = 0;
            actionargs.arg3         = 0;

            ieee80211_send_action(ni, &actionargs, NULL);
        } else {
            action_taken = FALSE;
        }
        break;
    }

    case IEEE80211_ACTION_CAT_VENDOR: {
        struct ieee80211_action_vendor_specific *ven;
        ven = (struct ieee80211_action_vendor_specific*)frm;

        /* Check if the vendor_OUI is Atheros */
        if(ven->vendor_oui[0] == 0x00
           && ven->vendor_oui[1] == 0x03
           && ven->vendor_oui[2] == 0x7f) {
            struct ieee80211_ie_header  *info_element;
            frm += sizeof(struct ieee80211_action_vendor_specific);
            info_element = (struct ieee80211_ie_header *)frm;
            switch(info_element->element_id) {
                case IEEE80211_ELEMID_CHANSWITCHANN:
                    /* The STA has (probably) detected RADAR and
                     * wants the AP to move to a different channel.
                     */

                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                            "%s: Received vendor-chanswitch action frame\n",__func__);
                    if(IEEE80211_IS_CSH_PROCESS_RCSA_ENABLED(ic)) {
                        ieee80211_process_external_radar_detect(ni);
                    }
                break;

                case IEEE80211_ELEMID_VENDOR:
                    action_taken = FALSE;
                    break;
                default:
                    IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                       "%s: Vendor Specific Action frame has unknown IE id=%02X", __func__,info_element->element_id);
                break;
            }

        } else {
            IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                       "%s: Action mgt frame has non-Atheros OUI %d", __func__, ia->ia_category);
        }
    }
    break;

    default:
        IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                       "%s: action mgt frame has invalid category %d", __func__, ia->ia_category);
        vap->iv_stats.is_rx_mgtdiscard++;
        action_taken = FALSE;
        break;
    }

    return action_taken ? EOK : -EINVAL;
}

int
ieee80211_recv_mgmt(struct ieee80211_node *ni,
                    wbuf_t wbuf,
                    int subtype,
                    struct ieee80211_rx_status *rs)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211_mac_stats *mac_stats;
    struct ieee80211_frame *wh;
    int    is_bcast, forward_to_filter = 1;
    int    i;
    int    eq=0, ret = 0;
    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    /* check for ACL policy if smart mesh is enabled */
    if ((vap->iv_smart_mesh_cfg & SMART_MESH_ACL_ENHANCEMENT)) {

        if (!ieee80211_acl_check(vap, wh->i_addr2)) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACL,
                    "[%s] MGMT subtype:%d, disallowed by ACL \n", ether_sprintf(ni->ni_macaddr), subtype);
            vap->iv_stats.is_rx_acl++;
            return -EINVAL;
        }
    }

#if UMAC_SUPPORT_WNM
    {
        int update_timer = 0;
        int mfp, is_pmf_set;
        u_int8_t wep_bit ;
        if (ieee80211_vap_wnm_is_set(vap) && ieee80211_wnm_bss_is_set(vap->wnm) && ni != ni->ni_bss_node) {
            wep_bit = (wh->i_fc[1] & IEEE80211_FC1_WEP) ? 1 : 0 ;
            mfp = IEEE80211_IS_MFP_FRAME(wh);
            is_pmf_set = ieee80211_is_pmf_enabled(vap, ni);
            update_timer = ( is_pmf_set && mfp ) ? wep_bit : !wep_bit ;
            ieee80211_wnm_bssmax_updaterx(ni, update_timer);
        }
    }
#endif

    if(subtype ==  IEEE80211_FC0_SUBTYPE_AUTH ||
       subtype ==  IEEE80211_FC0_SUBTYPE_ASSOC_REQ||
       subtype ==  IEEE80211_FC0_SUBTYPE_REASSOC_REQ) {
        if (ni != ni->ni_vap->iv_bss) {
            wds_clear_wds_table(ni,&ic->ic_sta, wbuf);
        }
    }
    if (IEEE80211_IS_MFP_FRAME(wh)) {
       is_bcast = IEEE80211_IS_BROADCAST(wh->i_addr1);
       mac_stats = is_bcast ? &vap->iv_multicast_stats : &vap->iv_unicast_stats;
       IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "Received MFP frame with Subtype 0x%2X\n", subtype);
       /*
       * There are two reasons that a received MFP frame must be dropped:
       * 1) decryption error
       * 2) MFP is not negociated
       */
       if ((NULL == ieee80211_crypto_decap(ni, wbuf, ieee80211_hdrspace(ic, wbuf_header(wbuf)), rs))
                    || (!ieee80211_is_pmf_enabled(vap, ni))){
            mac_stats->ims_rx_decryptcrc++;
            IEEE80211_NODE_STAT(ni, rx_decryptcrc);
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "Decrypt Error MFP frame with Subtype 0x%2X\n", subtype);
            return -EINVAL;
        } else {
            mac_stats->ims_rx_decryptok++;
        }
        /* recalculate wh pointer, header may shift after decap */
        wh = (struct ieee80211_frame *) wbuf_header(wbuf);
        /* NB: We clear the Protected bit later */
    }
    else {
        u_int8_t *frm = (u_int8_t *)&wh[1];
        u_int8_t *efrm = wbuf_header(wbuf) + wbuf_get_pktlen(wbuf);
        struct ieee80211_action *ia;

        IEEE80211_VERIFY_LENGTH(efrm - frm, sizeof(struct ieee80211_action));
        ia = (struct ieee80211_action *)frm;

        if (ieee80211_is_pmf_enabled(vap, ni) &&
            (subtype == IEEE80211_FC0_SUBTYPE_ACTION &&
             ia->ia_category == IEEE80211_ACTION_CAT_SA_QUERY)) {
            /* unprotected SA query frame that must be protected, drop it */
            IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
                          wh, ieee80211_mgt_subtype_name[
                              subtype >> IEEE80211_FC0_SUBTYPE_SHIFT],
                          "%s", "mfp frame is not protected");
            return -EINVAL;
        }
    }

    switch (subtype) {
    case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
    case IEEE80211_FC0_SUBTYPE_BEACON:
        ieee80211_recv_beacon(ni, wbuf, subtype, rs);
        /*store all received beacon info*/
        if(vap->iv_beacon_info_count>=100)
        {
            vap->iv_beacon_info_count=0;
        }
        eq=0;
        if(vap->iv_beacon_info_count)
        {
            for(i=0;i<vap->iv_beacon_info_count;i++)
            {
                if(!OS_MEMCMP(vap->iv_beacon_info[i].essid,vap->iv_essid,vap->iv_esslen))
                {
                    eq=1;
                    vap->iv_beacon_info[i].rssi_ctl_0=rs->rs_rssictl[0];
                    vap->iv_beacon_info[i].rssi_ctl_1=rs->rs_rssictl[1];
                    vap->iv_beacon_info[i].rssi_ctl_2=rs->rs_rssictl[2];
                    break;
                }
            }
            if(!eq)
            {
                OS_MEMCPY(vap->iv_beacon_info[vap->iv_beacon_info_count].essid, vap->iv_essid,vap->iv_esslen);
                vap->iv_beacon_info[vap->iv_beacon_info_count].esslen = vap->iv_esslen;
                vap->iv_beacon_info[vap->iv_beacon_info_count].rssi_ctl_0=rs->rs_rssictl[0];
                vap->iv_beacon_info[vap->iv_beacon_info_count].rssi_ctl_1=rs->rs_rssictl[1];
                vap->iv_beacon_info[vap->iv_beacon_info_count].rssi_ctl_2=rs->rs_rssictl[2];
                vap->iv_beacon_info[vap->iv_beacon_info_count].numchains=rs->rs_numchains;
                vap->iv_beacon_info_count++;
            }
        }
        else
        {
            OS_MEMCPY(vap->iv_beacon_info[vap->iv_beacon_info_count].essid, vap->iv_essid,vap->iv_esslen);
            vap->iv_beacon_info[vap->iv_beacon_info_count].esslen = vap->iv_esslen;
            vap->iv_beacon_info[vap->iv_beacon_info_count].rssi_ctl_0=rs->rs_rssictl[0];
            vap->iv_beacon_info[vap->iv_beacon_info_count].rssi_ctl_1=rs->rs_rssictl[1];
            vap->iv_beacon_info[vap->iv_beacon_info_count].rssi_ctl_2=rs->rs_rssictl[2];
            vap->iv_beacon_info[vap->iv_beacon_info_count].numchains=rs->rs_numchains;
            vap->iv_beacon_info_count++;
         }

        /*store ibss peer info*/
        if(!OS_MEMCMP(vap->iv_essid, vap->iv_des_ssid[0].ssid,vap->iv_des_ssid[0].len))
        {
            if(vap->iv_ibss_peer_count>=8)
            {
                vap->iv_ibss_peer_count=0;
            }
            eq=0;
            if(vap->iv_ibss_peer_count)
            {
                for(i=0;i<vap->iv_ibss_peer_count;i++)
                {
                    if(IEEE80211_ADDR_EQ(vap->iv_ibss_peer[i].bssid,wh->i_addr2))
                    {
                        eq=1;
                        break;
                    }
                }
                if(!eq)
                {
                    IEEE80211_ADDR_COPY(vap->iv_ibss_peer[vap->iv_ibss_peer_count].bssid, wh->i_addr2);
                    vap->iv_ibss_peer_count++;
                }
                break;
            }
            else
            {
                IEEE80211_ADDR_COPY(vap->iv_ibss_peer[vap->iv_ibss_peer_count].bssid, wh->i_addr2);
                vap->iv_ibss_peer_count++;
                break;
            }
        }

        break;

    case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
#if ATH_NON_BEACON_AP
        if(IEEE80211_VAP_IS_NON_BEACON_ENABLED(vap)){
            /*Don't response to probe req for non-beaconing AP VAP*/
            ret = -EINVAL;
            forward_to_filter = 0;
            break;
        }
#endif
        ieee80211_recv_probereq(ni, wbuf, subtype, rs);
        break;

    case IEEE80211_FC0_SUBTYPE_AUTH:
#if ATH_NON_BEACON_AP
        if(IEEE80211_VAP_IS_NON_BEACON_ENABLED(vap)){
            /*Don't response to auth for non-beaconing AP VAP*/
            ret = -EINVAL;
            forward_to_filter = 0;
            break;
        }
#endif
        if(ieee80211_recv_auth(ni, wbuf, subtype, rs ) < 0)
           forward_to_filter = 0;
        break;

    case IEEE80211_FC0_SUBTYPE_ASSOC_RESP:
    case IEEE80211_FC0_SUBTYPE_REASSOC_RESP:
        ieee80211_recv_asresp(ni, wbuf, subtype);
        break;

    case IEEE80211_FC0_SUBTYPE_ASSOC_REQ:
    case IEEE80211_FC0_SUBTYPE_REASSOC_REQ:
#if ATH_NON_BEACON_AP
        if(IEEE80211_VAP_IS_NON_BEACON_ENABLED(vap)){
            /*Don't response to auth for non-beaconing AP VAP*/
            ret = -EINVAL;
            forward_to_filter = 0;
            break;
        }
#endif
        /*
         *  Update RSSI information for mgmt frame also
         *  This will be used in OBSS coexistance improvements
         */
        ni->ni_rssi = rs->rs_rssi;
        ni->ni_rssi_min = rs->rs_rssi;
        ni->ni_rssi_max = rs->rs_rssi;

#if UMAC_SUPPORT_FILS
        /* decrypt the Assoc Request Frame */
        /* TO DO : Decision on when to call decrypt function */
        if(IEEE80211_VAP_IS_FILS_ENABLED(vap) && ni->ni_fils_aead_set &&
           (ni->ni_authalg == IEEE80211_AUTH_ALG_FILS_SK ||
            ni->ni_authalg == IEEE80211_AUTH_ALG_FILS_SK_PFS ||
            ni->ni_authalg == IEEE80211_AUTH_ALG_FILS_PK)) {
            u_int16_t hdrspace;
            struct ieee80211_key *key;

            hdrspace = ieee80211_hdrspace(ic, wbuf_header(wbuf));
            if (unlikely(wbuf_get_pktlen(wbuf) < hdrspace)) {
                qdf_print("%s error \n",__func__);
                ret = -EINVAL;
                break;
            }

            key = ieee80211_crypto_decap(ni, wbuf, hdrspace, rs);
            if (unlikely(key == NULL)) {
                qdf_print("%s FILS decap returned NULL check!! \n",__func__);
                ret = -EINVAL;
                break;
            }
        }
#endif
        if (ieee80211_recv_asreq(ni, wbuf, subtype) == -EBUSY)
            forward_to_filter = 0;
        break;

    case IEEE80211_FC0_SUBTYPE_DEAUTH:
        ieee80211_recv_deauth(ni, wbuf, subtype);
        break;

    case IEEE80211_FC0_SUBTYPE_DISASSOC:
        ret = ieee80211_recv_disassoc(ni, wbuf, subtype);
        if(ret){
            /*Something wrong, don't fwd to filter*/
           forward_to_filter = 0;
        }
        break;

    case IEEE80211_FC0_SUBTYPE_ACTION:
    case IEEE80211_FCO_SUBTYPE_ACTION_NO_ACK:
        forward_to_filter = ieee80211_recv_action(ni, wbuf, subtype, rs);
        break;

    default:
        break;
    }

    /*
     * deliver 802.11 frame if the OS is interested in it and
     * we have decided to forward it. (Some processed Action frames are not forwarded
     * to hostapd to avoid getting another response)
     */
    if (forward_to_filter && vap->iv_evtable && vap->iv_evtable->wlan_receive_filter_80211) {
        vap->iv_evtable->wlan_receive_filter_80211(vap->iv_ifp, wbuf, IEEE80211_FC0_TYPE_MGT, subtype, rs);
    }

    return ret;
}

int
ieee80211_recv_ctrl(struct ieee80211_node *ni,
                    wbuf_t wbuf,
                    int subtype,
                    struct ieee80211_rx_status *rs)
{
     struct ieee80211vap    *vap = ni->ni_vap;
     switch (vap->iv_opmode) {
     case IEEE80211_M_HOSTAP:
          ieee80211_recv_ctrl_ap(ni,wbuf,subtype);
          break;
     default:
          break;
     }
    return EOK;
}

/*
 * send an action frame.
 * @param vap      : vap pointer.
 * @param dst_addr : destination address.
 * @param src_addr : source address.(most of the cases vap mac address).
 * @param bssid    : BSSID or %NULL to use default
 * @param data     : data buffer conataining the action frame including action category  and type.
 * @param data_len : length of the data buffer.
 * @param handler  : hanlder called when the frame transmission completes.
 * @param arg      : opaque pointer passed back via the handler.
 * @ returns 0 if success, -ve if failed.
 */
int ieee80211_vap_send_action_frame(struct ieee80211vap *vap,const u_int8_t *dst_addr,const  u_int8_t *src_addr, const u_int8_t *bssid,
                                    const u_int8_t *data, u_int32_t data_len, ieee80211_vap_complete_buf_handler handler, void *arg)
{
    wbuf_t wbuf = NULL;
    u_int8_t *frm = NULL;
    struct ieee80211_frame *wh;
    struct ieee80211_node *ni=NULL;
    struct ieee80211com *ic = vap->iv_ic;

    /*
     * sanity check the data length.
     */
    if ( (data_len + sizeof(struct ieee80211_frame)) >= MAX_TX_RX_PACKET_SIZE) {
        return  -ENOMEM;
    }

#ifdef ATH_SUPPORT_HTC
    /* check if vap is deleted */
    if (ieee80211_vap_deleted_is_set(vap)) {
        /* if vap is deleted then return an error */
        return  -EINVAL;
    }

    ieee80211_vap_active_set(vap);
#endif
    if (!ieee80211_vap_active_is_set(vap)) {
        /* if vap is not active then return an error */
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,"%s: Error: vap is not set\n", __func__);
        return  -EINVAL;
    }

    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);

    if (wbuf == NULL) {
        return  -ENOMEM;
    }

    /*
     * if a node exist with the given address already , use it.
     * if not use bss node.
     */
    ni = ieee80211_find_txnode(vap, dst_addr);
    if (ni == NULL) {
        ni = ieee80211_ref_node(vap->iv_bss);
    }
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);

    ieee80211_send_setup(vap, vap->iv_bss, wh,
                         IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_ACTION,
                         src_addr, dst_addr, bssid ? bssid : ni->ni_bssid);
    frm = (u_int8_t *)&wh[1];
    /*
     * copy the data part into the data area.
     */
    OS_MEMCPY(frm,data,data_len);

    if (ieee80211_is_robust_action_frame(*data) &&
           ((vap->iv_ccx_evtable && vap->iv_ccx_evtable->wlan_ccx_is_mfp &&
              vap->iv_ccx_evtable->wlan_ccx_is_mfp(vap->iv_ifp)) ||
             ((ieee80211_vap_mfp_test_is_set(vap) ||
               ieee80211_is_pmf_enabled(vap, ni)) && ni->ni_ucastkey.wk_valid))) {
        struct ieee80211_frame *wh;
        wh = (struct ieee80211_frame*)wbuf_header(wbuf);
        wh->i_fc[1] |= IEEE80211_FC1_WEP;
    }
    wbuf_set_pktlen(wbuf, data_len + (u_int32_t)sizeof(struct ieee80211_frame));
    if (handler) {
        ieee80211_vap_set_complete_buf_handler(wbuf,handler,arg);
    }

    /* management action frame can not go out if the vap is in forced pause state */
    if (ieee80211_vap_is_force_paused(vap)) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_POWER,
                          "[%s] queue action management frame, the vap is in forced pause state\n",__func__);
        ieee80211_node_saveq_queue(ni,wbuf,IEEE80211_FC0_TYPE_MGT);
#if LMAC_SUPPORT_POWERSAVE_QUEUE
        /* force the frame to reach LMAC pwrsaveq */
        return ieee80211_send_mgmt(vap,ni, wbuf, true);
#endif
    } else {
#if UMAC_SUPPORT_WNM
        /* force the WNMSLEEP_RESP action frame to be send even when sta is in ps mode */
        bool force_send = false;
	  if (ieee80211_is_robust_action_frame(*data) &&
            ieee80211_is_pmf_enabled(vap, ni) && ni->ni_ucastkey.wk_valid) {
            /* MFP is enabled, so we need to set Privacy bit */
            wh->i_fc[1] |= IEEE80211_FC1_WEP;
        }

    if (*data == IEEE80211_ACTION_CAT_WNM && *(data+1) == IEEE80211_ACTION_WNMSLEEP_RESP)
            force_send = true;
        if (ieee80211_send_mgmt(vap,ni, wbuf,force_send) != EOK) {
#else
        if (ieee80211_send_mgmt(vap,ni, wbuf,false) != EOK) {
#endif
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_OUTPUT,
                              "[%s] failed to send management frame\n",__func__);
        }
    }
    ieee80211_free_node(ni);

    return EOK;
}

bool
ieee80211_is_mmie_valid(struct ieee80211vap *vap, struct ieee80211_node *ni, u_int8_t* frm, u_int8_t* efrm)
{
    struct ieee80211_mmie   *mmie = NULL;
    u_int8_t *ipn, aad[20], mic[16], nounce[12];
    struct ieee80211_key *key = &vap->iv_igtk_key;
    struct ieee80211_frame *wh;
    u_int8_t mic_length;

    /*
    * Two conditions:
    * 1) PMF required is not set
    * 2) Either peer is not enbale PMF
    * then no need to validate MMIE
    */
    if (!ieee80211_is_pmf_enabled(vap, ni)) {
        return true;
    }

    /* check if frame is illegal length */
    if ((efrm < frm) || ((efrm - frm) < sizeof(*wh))) {
        return false;
    }

    if((RSN_CIPHER_IS_CMAC(&vap->iv_rsn)) || RSN_CIPHER_IS_CMAC256(&vap->iv_rsn))
        mmie = (struct ieee80211_mmie *)(efrm - sizeof(*mmie) + 8);
    else if ((RSN_CIPHER_IS_GMAC(&vap->iv_rsn)) || RSN_CIPHER_IS_GMAC256(&vap->iv_rsn))
        mmie = (struct ieee80211_mmie *)(efrm - sizeof(*mmie));

    /* check Elem ID*/
    if ((mmie == NULL) || (mmie->element_id != IEEE80211_ELEMID_MMIE)){
        /* IE is not Mgmt MIC IE */
        return false;
    }

    /* validate ipn */
    ipn = mmie->sequence_number;
    if (OS_MEMCMP(ipn, key->wk_keyrsc, 6) <= 0) {
        u_int8_t *dipn = (u_int8_t*)key->wk_keyrsc;
        /* replay error */
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "BC/MC MGMT frame Replay Counter Failed"\
                          " mmie ipn %02X %02X %02X %02X %02X %02X"\
                          " drvr ipn %02X %02X %02X %02X %02X %02X\n",
                           ipn[0], ipn[1], ipn[2], ipn[3], ipn[4], ipn[5],
                           dipn[0], dipn[1], dipn[2], dipn[3], dipn[4], dipn[5]);
        return false;
    }

    /* construct AAD */
    wh = (struct ieee80211_frame *)frm;

    /* generate BIP AAD: FC(masked) || A1 || A2 || A3 */

    /* FC type/subtype */
    aad[0] = wh->i_fc[0];
    /* Mask FC Retry, PwrMgt, MoreData flags to zero */
    aad[1] = wh->i_fc[1] & ~(IEEE80211_FC1_RETRY | IEEE80211_FC1_PWR_MGT | IEEE80211_FC1_MORE_DATA);
    /* A1 || A2 || A3 */
    OS_MEMCPY(aad + 2, wh->i_addr_all, 3 * IEEE80211_ADDR_LEN);

    /*
     * MIC = AES-128-CMAC(IGTK, AAD || Management Frame Body || MMIE, 64)
     */
    if((RSN_CIPHER_IS_CMAC(&vap->iv_rsn)) || RSN_CIPHER_IS_CMAC256(&vap->iv_rsn)){
        mic_length = 8;
        ieee80211_cmac_calc_mic(key, aad, (u_int8_t*)(wh+1), (efrm - (u_int8_t*)(wh+1)), mic);
    } else if ((RSN_CIPHER_IS_GMAC(&vap->iv_rsn)) || RSN_CIPHER_IS_GMAC256(&vap->iv_rsn)){
        mic_length = 16;
        memcpy(nounce, wh->i_addr2, IEEE80211_ADDR_LEN);
        memcpy(nounce + 6, ipn, 6);
        ieee80211_gmac_calc_mic(key, aad,  (u_int8_t*)(wh+1), 20, mic, nounce);
    } else {
        return false;
    }
    if (OS_MEMCMP(mic, mmie->mic, mic_length) != 0) {
        /* MMIE MIC mismatch */
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "BC/MC MGMT frame MMIE MIC check Failed"\
                          " rmic %02X %02X %02X %02X %02X %02X %02X %02X"\
                          " cmic %02X %02X %02X %02X %02X %02X %02X %02X\n",
                          mmie->mic[0], mmie->mic[1], mmie->mic[2], mmie->mic[3],
                          mmie->mic[4], mmie->mic[5], mmie->mic[6], mmie->mic[7],
                          mic[0], mic[1], mic[2], mic[3], mic[4], mic[5], mic[6], mic[7]);
        return false;
    }

    /* Update the receive sequence number */
    OS_MEMCPY(key->wk_keyrsc, ipn, 6);

    return true;
}

/**
* send action management frame.
* @param freq     : channel to send on (only to validate/match with current channel)
* @param arg      : arg (will be used in the mlme_action_send_complete)
* @param dst_addr : destination mac address
* @param src_addr : source mac address
* @param bssid    : bssid
* @param data     : includes total payload of the action management frame.
* @param data_len : data len.
* @returns 0 if succesful and -ve if failed.
* if the radio is not on the passedf in freq then it will return an error.
* if returns 0 then mlme_action_send_complete will be called with the status of
* the frame transmission.
*/
int wlan_vap_send_action_frame(wlan_if_t vap_handle, u_int32_t freq,
                               wlan_action_frame_complete_handler handler, void *arg,const u_int8_t *dst_addr,
                               const u_int8_t *src_addr, const u_int8_t *bssid, const u_int8_t *data, u_int32_t data_len)
{
    struct ieee80211com *ic = vap_handle->iv_ic;
    /* send action frame */
    if (freq) {
        if(freq !=  ieee80211_chan2freq(ic,ic->ic_curchan)) {
            /* frequency does not match */
            IEEE80211_DPRINTF(vap_handle, IEEE80211_MSG_ANY,
                              "%s: Error: frequency does not match. req=%d, curr=%d\n",
                              __func__, freq, ieee80211_chan2freq(ic,ic->ic_curchan));
            return -EINVAL;
        }
    }
    return ieee80211_vap_send_action_frame(vap_handle,dst_addr,src_addr,bssid,data,data_len,
                    handler,arg);
}

#if ATH_SUPPORT_CFEND
/*
 *  Allocate a CF-END frame and fillin the appropriate bits.
 *  */
wbuf_t
ieee80211_cfend_alloc(struct ieee80211com *ic)
{
    wbuf_t cfendbuf;
    struct ieee80211_ctlframe_addr2 *wh;
    const u_int8_t macAddr[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

    cfendbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_CTL, sizeof(struct ieee80211_ctlframe_addr2));
    if (cfendbuf == NULL) {
        return cfendbuf;
    }

    wbuf_append(cfendbuf, sizeof(struct ieee80211_ctlframe_addr2));
    wh = (struct ieee80211_ctlframe_addr2*) wbuf_header(cfendbuf);

    *(u_int16_t *)(&wh->i_aidordur) = htole16(0x0000);
    wh->i_fc[0] = 0;
    wh->i_fc[1] = 0;
    wh->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_CTL |
        IEEE80211_FC0_SUBTYPE_CF_END;

    IEEE80211_ADDR_COPY(wh->i_addr1, macAddr);
    IEEE80211_ADDR_COPY(wh->i_addr2, ic->ic_my_hwaddr);

    /*if( vap->iv_opmode == IEEE80211_M_HOSTAP ) {
        wh->i_fc[1] = IEEE80211_FC1_DIR_FROMDS;
    } else {
        wh->i_fc[1] = IEEE80211_FC1_DIR_TODS;
    }*/
    return cfendbuf;
}
#endif

void
wlan_addba_request_handler(void *arg, wlan_node_t node)
{
    struct ieee80211_addba_delba_request *ad = arg;
    struct ieee80211_node *ni = node;
    struct ieee80211com *ic = ad->ic;
    int ret;

    if (ni->ni_associd == 0 ||
        IEEE80211_AID(ni->ni_associd) != ad->aid) {
        return;
    }

    switch (ad->action)
    {
    default:
        return;
    case ADDBA_SEND:
        ret = ic->ic_addba_send(ni, ad->tid, ad->arg1);
        if (ret != 0)  {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ADDBA send failed: recipient is not a 11n node\n");
        }
        break;
    case ADDBA_STATUS:
        ic->ic_addba_status(ni, ad->tid, &(ad->status));
        break;
    case DELBA_SEND:
        ic->ic_delba_send(ni, ad->tid, ad->arg1, ad->arg2);
        break;
    case ADDBA_RESP:
        ic->ic_addba_setresponse(ni, ad->tid, ad->arg1);
        break;
    case SINGLE_AMSDU:
        ic->ic_send_singleamsdu(ni, ad->tid);
        break;
    }
}

int
wlan_send_delts(wlan_if_t vaphandle, u_int8_t *macaddr, ieee80211_tspec_info *tsinfo)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211_node *ni;
    struct ieee80211_action_mgt_args delts_args;
    struct ieee80211_action_mgt_buf  delts_buf;
    struct ieee80211_tsinfo_bitmap *tsflags;
    struct ieee80211_wme_tspec *tspec;

    ni = ieee80211_find_txnode(vap, macaddr);
    if (ni == NULL) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_OUTPUT,
                          "%s: could not send DELTS, no node found for %s\n",
                          __func__, ether_sprintf(macaddr));
        return -EINVAL;
    }

    /*
     * ieee80211_action_mgt_args is a generic structure. TSPEC IE
     * is filled in the buf area.
     */
    delts_args.category = IEEE80211_ACTION_CAT_WMM_QOS;
    delts_args.action   = IEEE80211_WMM_QOS_ACTION_TEARDOWN;
    delts_args.arg1     = IEEE80211_WMM_QOS_DIALOG_TEARDOWN; /* dialogtoken */
    delts_args.arg2     = 0; /* status code */
    delts_args.arg3     = sizeof(struct ieee80211_wme_tspec);

    tspec = (struct ieee80211_wme_tspec *) &delts_buf.buf;
    tsflags = (struct ieee80211_tsinfo_bitmap *) &(tspec->ts_tsinfo);
    tsflags->direction = tsinfo->direction;
    tsflags->psb = tsinfo->psb;
    tsflags->dot1Dtag = tsinfo->dot1Dtag;
    tsflags->tid = tsinfo->tid;
    tsflags->reserved3 = tsinfo->aggregation;
    tsflags->one = tsinfo->acc_policy_edca;
    tsflags->zero = tsinfo->acc_policy_hcca;
    tsflags->reserved1 = tsinfo->traffic_type;
    tsflags->reserved2 = tsinfo->ack_policy;

    *((u_int16_t *) &tspec->ts_nom_msdu) = htole16(tsinfo->norminal_msdu_size);
    *((u_int16_t *) &tspec->ts_max_msdu) = htole16(tsinfo->max_msdu_size);
    *((u_int32_t *) &tspec->ts_min_svc) = htole32(tsinfo->min_srv_interval);
    *((u_int32_t *) &tspec->ts_max_svc) = htole32(tsinfo->max_srv_interval);
    *((u_int32_t *) &tspec->ts_inactv_intv) = htole32(tsinfo->inactivity_interval);
    *((u_int32_t *) &tspec->ts_susp_intv) = htole32(tsinfo->suspension_interval);
    *((u_int32_t *) &tspec->ts_start_svc) = htole32(tsinfo->srv_start_time);
    *((u_int32_t *) &tspec->ts_min_rate) = htole32(tsinfo->min_data_rate);
    *((u_int32_t *) &tspec->ts_mean_rate) = htole32(tsinfo->mean_data_rate);
    *((u_int32_t *) &tspec->ts_max_burst) = htole32(tsinfo->max_burst_size);
    *((u_int32_t *) &tspec->ts_min_phy) = htole32(tsinfo->min_phy_rate);
    *((u_int32_t *) &tspec->ts_peak_rate) = htole32(tsinfo->peak_data_rate);
    *((u_int32_t *) &tspec->ts_delay) = htole32(tsinfo->delay_bound);
    *((u_int16_t *) &tspec->ts_surplus) = htole16(tsinfo->surplus_bw);
    *((u_int16_t *) &tspec->ts_medium_time) = htole16(tsinfo->medium_time);

    ieee80211_send_action(ni, &delts_args, &delts_buf);
    ieee80211_free_node(ni);    /* reclaim node */
    return 0;
}

/* Update HT-VHT Phymode  */
void
ieee80211_update_ht_vht_phymode(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    if (IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan)) {
        if (ni->ni_flags & IEEE80211_NODE_VHT) {
            switch (ni->ni_chwidth) {
                case IEEE80211_CWM_WIDTH20:
                    ni->ni_phymode = IEEE80211_MODE_11AC_VHT20;
                break;

                case IEEE80211_CWM_WIDTH40:
                    ni->ni_phymode = IEEE80211_MODE_11AC_VHT40;
                break;

                case IEEE80211_CWM_WIDTH80:
                    ni->ni_phymode = IEEE80211_MODE_11AC_VHT80;
                break;
                case IEEE80211_CWM_WIDTH160:
                    ni->ni_phymode = ni->ni_vap->iv_cur_mode;
                break;
                default:
                   /* Do nothing */
                break;
            }
        } else if (ni->ni_flags & IEEE80211_NODE_HT) {
            switch (ni->ni_chwidth) {
                case IEEE80211_CWM_WIDTH20:
                    ni->ni_phymode = IEEE80211_MODE_11NA_HT20;
                break;

                case IEEE80211_CWM_WIDTH40:
                    ni->ni_phymode = IEEE80211_MODE_11NA_HT40;
                break;

                default:
                   /* Do nothing */
                break;
           }
        }
    } else {
        if (ni->ni_flags & IEEE80211_NODE_HT) {
            switch (ni->ni_chwidth) {
                case IEEE80211_CWM_WIDTH20 :
                    ni->ni_phymode = IEEE80211_MODE_11NG_HT20;
                break;

                case IEEE80211_CWM_WIDTH40 :
                    ni->ni_phymode = IEEE80211_MODE_11NG_HT40;
                break;

                default:
                   /* Do nothing */
                break;
           }
        }
    }

}

