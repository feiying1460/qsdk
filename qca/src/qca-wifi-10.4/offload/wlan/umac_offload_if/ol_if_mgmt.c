/*
 * Copyright (c) 2017 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 * Notifications and licenses are retained for attribution purposes only
 *
 * Copyright (c) 2011, 2015, Atheros Communications Inc.
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
 * UMAC management specific offload interface functions - for power and performance offload model
 */
#include "ol_if_athvar.h"
#include "ol_if_ath_api.h"
#include "qdf_mem.h"

#include <ol_txrx_types.h>
#include <wdi_event_api.h>
#include <enet.h>
#include "ol_helper.h"
#if ATH_SUPPORT_GREEN_AP
#include "ath_green_ap.h"
#endif  /* ATH_SUPPORT_GREEN_AP */
#include "a_debug.h"

#include "bmi_msg.h"      /* TARGET_TYPE_ */
#include "ol_if_athvar.h"
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_private.h>
#include <osif_nss_wifiol_if.h>
#include <osif_nss_wifiol_vdev_if.h>
#endif

#if ATH_PERF_PWR_OFFLOAD

/* Disable this when the HT data transport is ready */
#define OL_MGMT_TX_WMI  1
#if defined (CONFIG_AR900B_SUPPORT) || defined (CONFIG_AR9888_SUPPORT)
#define MGMT_HTT_ENABLE 1
#endif
#define NDIS_SOFTAP_SSID  "NDISTEST_SOFTAP"
#define NDIS_SOFTAP_SSID_LEN  15
#define OFFCHAN_EXT_TID_NONPAUSE    19
static u_int32_t
ol_ath_net80211_rate_node_update(struct ieee80211com *ic,
                                 struct ieee80211_node *ni,
                                 int isnew);

/*
 *  WMI API for 802.11 management frame processing
 */
static uint32_t
ol_map_phymode_to_wmimode(struct ieee80211_node *ni)
{
    uint32_t phymode;

    phymode = ni->ni_phymode;
    if(ieee80211_vap_256qam_is_set(ni->ni_vap) &&
             (ni->ni_flags & IEEE80211_NODE_VHT)) {
       switch(phymode) {
          case IEEE80211_MODE_11NG_HT20:
              return WMI_HOST_MODE_11AC_VHT20;
          break;
          case IEEE80211_MODE_11NG_HT40PLUS:
          case IEEE80211_MODE_11NG_HT40MINUS:
          case IEEE80211_MODE_11NG_HT40:
              return WMI_HOST_MODE_11AC_VHT40;
          break;
          default:
          break;
       }
    }

    return(ol_get_phymode_info(phymode));
}

/*
 *  WMI API for 802.11 management frame processing
 */
int
ol_ath_send_peer_assoc(struct ol_ath_softc_net80211 *scn, struct ieee80211com *ic,
                            struct ieee80211_node *ni, int isnew )
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct peer_assoc_params param;
    u_int8_t rx_nss160 = 0;
    u_int8_t rx_nss80p80 = 0;
    bool is_prop_ie_used = false;
    bool is_ext_nss_used = false;
    bool same_nss_for_all_bw = false;

    if (vap->iv_ext_nss_capable && ni->ni_ext_nss_support) {
        is_ext_nss_used = true;
    } else if ((ni->ni_bwnss_map & IEEE80211_BW_NSS_FWCONF_MAP_ENABLE) && !(ic->ic_disable_bwnss_adv)) {
        is_prop_ie_used = true;
    }

    qdf_mem_set(&param, sizeof(param), 0);

    IEEE80211_ADDR_COPY(param.peer_mac, ni->ni_macaddr);
    param.vdev_id = (OL_ATH_VAP_NET80211(vap))->av_if_id;
    param.peer_new_assoc = isnew;
    param.peer_associd = IEEE80211_AID(ni->ni_associd);
    param.peer_bw_rxnss_override = 0;

    if(ieee80211_is_pmf_enabled(vap, ni)) {
        param.is_pmf_enabled = TRUE;
    }

    /*
     * Do not enable HT/VHT if WMM/wme is disabled for vap.
     */
    if (ieee80211_vap_wme_is_set(vap)) {
        param.is_wme_set = TRUE;

        if ((ni->ni_flags & IEEE80211_NODE_QOS) || (ni->ni_flags & IEEE80211_NODE_HT) ||
                (ni->ni_flags & IEEE80211_NODE_VHT)) {
            param.qos_flag = TRUE;
        }
        if (ni->ni_flags & IEEE80211_NODE_UAPSD ) {
            param.apsd_flag = TRUE;
        }
        if (ni->ni_flags & IEEE80211_NODE_HT) {
            param.ht_flag = TRUE;
        }
        if ((ni->ni_chwidth == IEEE80211_CWM_WIDTH40) || (ni->ni_chwidth == IEEE80211_CWM_WIDTH80) ||
                (ni->ni_chwidth == IEEE80211_CWM_WIDTH160)){
            param.bw_40 = TRUE;
        }
        if ((ni->ni_chwidth == IEEE80211_CWM_WIDTH80) || (ni->ni_chwidth == IEEE80211_CWM_WIDTH160)) {
            param.bw_80 = TRUE;
        }
        if ((ni->ni_chwidth == IEEE80211_CWM_WIDTH160)) {
            param.bw_160 = TRUE;
        }

        /* Typically if STBC is enabled for VHT it should be enabled for HT as well */
        if ((ni->ni_htcap & IEEE80211_HTCAP_C_RXSTBC) && (ni->ni_vhtcap & IEEE80211_VHTCAP_RX_STBC)) {
            param.stbc_flag = TRUE;
        }

        /* Typically if LDPC is enabled for VHT it should be enabled for HT as well */
        if ((ni->ni_htcap & IEEE80211_HTCAP_C_ADVCODING) && (ni->ni_vhtcap & IEEE80211_VHTCAP_RX_LDPC)) {
            param.ldpc_flag = TRUE;
        }

        if ((ni->ni_htcap & IEEE80211_HTCAP_C_SM_MASK) == IEEE80211_HTCAP_C_SMPOWERSAVE_STATIC) {
            param.static_mimops_flag = TRUE;
        }
        if ((ni->ni_htcap & IEEE80211_HTCAP_C_SM_MASK) == IEEE80211_HTCAP_C_SMPOWERSAVE_DYNAMIC) {
            param.dynamic_mimops_flag = TRUE;
        }
        if ((ni->ni_htcap & IEEE80211_HTCAP_C_SM_MASK) == IEEE80211_HTCAP_C_SMPOWERSAVE_DISABLED) {
            param.spatial_mux_flag = TRUE;
        }
        if (ni->ni_flags & IEEE80211_NODE_VHT) {
            param.vht_flag = TRUE;
        }
        if ((ni->ni_flags & IEEE80211_NODE_VHT) &&
             (ieee80211_vap_256qam_is_set(ni->ni_vap)) &&
              IEEE80211_IS_CHAN_11NG(ic->ic_curchan)) {
            param.vht_ng_flag = TRUE;
        }
    }
    /*
     * Suppress authorization for all AUTH modes that need 4-way handshake (during re-association).
     * Authorization will be done for these modes on key installation.
     */
    if ((ni->ni_flags & IEEE80211_NODE_AUTH) &&
        (RSN_AUTH_MATCH(&ni->ni_rsn, &vap->iv_rsn)) &&
        ((!(RSN_AUTH_IS_WPA(&ni->ni_rsn) ||
            RSN_AUTH_IS_WPA2(&ni->ni_rsn) ||
            RSN_AUTH_IS_8021X(&ni->ni_rsn)||
            RSN_AUTH_IS_WAI(&ni->ni_rsn))) ||
            IEEE80211_VAP_IS_SAFEMODE_ENABLED(ni->ni_vap))) {
        param.auth_flag = TRUE;
        ol_txrx_peer_authorize((OL_ATH_NODE_NET80211(ni))->an_txrx_handle, 1);
    } else {
        ol_txrx_peer_authorize((OL_ATH_NODE_NET80211(ni))->an_txrx_handle, 0);
    }
    if (RSN_AUTH_IS_WPA(&ni->ni_rsn) ||
            RSN_AUTH_IS_WPA2(&ni->ni_rsn) ||
            RSN_AUTH_IS_WAI(&ni->ni_rsn)) {
		/*
		 *  In WHCK NDIS Test, 4-way handshake is not mandatory in WPA TKIP/CCMP mode.
		 *  Check the SSID, if the SSID is NDIS softAP ssid, the function will unset WMI_PEER_NEED_PTK_4_WAY flag.
		 *  This will bypass the check and set the ALLOW_DATA in fw to let the data packet sent out.
		 */
		if (OS_MEMCMP(ni->ni_essid, NDIS_SOFTAP_SSID, NDIS_SOFTAP_SSID_LEN) == 0) {
            param.need_ptk_4_way = FALSE;
		} else {
            param.need_ptk_4_way = TRUE;
		}
    }
    if (RSN_AUTH_IS_WPA(&ni->ni_rsn)) {
        param.need_gtk_2_way = TRUE;
    }
    /* safe mode bypass the 4-way handshake */
    if (IEEE80211_VAP_IS_SAFEMODE_ENABLED(ni->ni_vap)) {
        param.safe_mode_enabled = TRUE;
    }
      /* Disable AMSDU for station transmit, if user configures it */
    if ((vap->iv_opmode == IEEE80211_M_STA) && (ic->ic_sta_vap_amsdu_disable) &&
        !(ni->ni_flags & IEEE80211_NODE_VHT)) {
        param.amsdu_disable = TRUE;
    }
      /* Disable AMSDU for AP transmit to 11n Stations, if user configures it */
    if ((vap->iv_opmode == IEEE80211_M_HOSTAP) && (vap->iv_disable_ht_tx_amsdu) &&
        (ni->ni_flags & IEEE80211_NODE_HT) && (!(IEEE80211_NODE_USE_VHT(ni))) ) {
        param.amsdu_disable = TRUE;
    }
    param.peer_caps = ni->ni_capinfo;
    param.peer_listen_intval = ni->ni_lintval;
    param.peer_ht_caps = ni->ni_htcap;
    param.peer_max_mpdu = ni->ni_maxampdu;
    param.peer_mpdu_density = ni->ni_mpdudensity;
    param.peer_vht_caps = ni->ni_vhtcap;

    /* Update peer rate information */
    param.peer_rate_caps = ol_ath_net80211_rate_node_update(ic, ni, isnew);
    param.peer_legacy_rates.num_rates = ni->ni_rates.rs_nrates;
    /* NOTE: cmd->peer_legacy_rates.rates is of type A_UINT32 */
    /* ni->ni_rates.rs_rates is of type u_int8_t */
    /**
     * for cmd->peer_legacy_rates.rates:
     * rates (each 8bit value) packed into a 32 bit word.
     * the rates are filled from least significant byte to most
     * significant byte.
     */
    OS_MEMCPY( param.peer_legacy_rates.rates, ni->ni_rates.rs_rates, ni->ni_rates.rs_nrates);

    param.peer_ht_rates.num_rates = ni->ni_htrates.rs_nrates;
    OS_MEMCPY( param.peer_ht_rates.rates, ni->ni_htrates.rs_rates, ni->ni_htrates.rs_nrates);

    param.peer_nss = (ni->ni_streams==0)?1:ni->ni_streams;

    /* set the default vht max rate info */
    if (ni->ni_vhtcap) {
        if((ni->ni_maxrate_vht != 0xff) && (!isnew)) {
	        u_int8_t user_max_nss = (ni->ni_maxrate_vht >> VHT_MAXRATE_IDX_SHIFT) & 0XF;
            param.peer_nss = (param.peer_nss > user_max_nss) ? user_max_nss : param.peer_nss;
        } else {
            ni->ni_maxrate_vht = 0xff;
        }
    } else {
        ni->ni_maxrate_vht = 0;
    }

    if (ni->ni_vhtcap) {
        param.vht_capable = TRUE;
        param.rx_max_rate = ni->ni_rx_max_rate;
        param.rx_mcs_set = ni->ni_rx_vhtrates;
        param.tx_max_rate = ni->ni_tx_max_rate;
        param.tx_mcs_set = ni->ni_tx_vhtrates;
        param.tx_max_mcs_nss = ni->ni_maxrate_vht;
    }

    /* In very exceptional  conditions it is observed  that
     * firmware was receiving phymode as 0 for peer from host, and resulting in Target Assert
     * Changing the phymode to desired mode
     */
    if(ni->ni_phymode == 0) {
        ni->ni_phymode = vap->iv_des_mode;
    }
    param.peer_phymode = ol_map_phymode_to_wmimode(ni);


    /*Send bandwidth-NSS mapping to FW*/
    if(scn->target_type == TARGET_TYPE_QCA9984 || scn->target_type == TARGET_TYPE_QCA9888){
        if (ni->ni_bwnss_map & IEEE80211_BW_NSS_FWCONF_MAP_ENABLE) {
            if (is_prop_ie_used) {
                 /* NS values for 160MHz and 80+80MHz is expected to be the same incase of prop IE */
                 rx_nss160 = IEEE80211_GET_BW_NSS_FWCONF_160(ni->ni_bwnss_map) + 1;
                 rx_nss80p80 = IEEE80211_GET_BW_NSS_FWCONF_160(ni->ni_bwnss_map) + 1;
            } else if (is_ext_nss_used) {
                 rx_nss160 = IEEE80211_GET_BW_NSS_FWCONF_160(ni->ni_bwnss_map) + 1;
                 rx_nss80p80 = IEEE80211_GET_BW_NSS_FWCONF_80_80(ni->ni_bwnss_map) + 1;
            }
        }
        else
        {
            if ((param.peer_phymode == WMI_HOST_MODE_11AC_VHT160) || (param.peer_phymode == WMI_HOST_MODE_11AC_VHT80_80))
            {
                if (param.peer_phymode == WMI_HOST_MODE_11AC_VHT80_80)
                {
                    rx_nss80p80 = param.peer_nss;
                }
                rx_nss160 = param.peer_nss;
                same_nss_for_all_bw = true;
            }
        }

        if (!ic-> ic_fw_ext_nss_capable) {
            if (rx_nss160) {
                param.peer_bw_rxnss_override = IEEE80211_BW_NSS_FWCONF_160(rx_nss160 - 1);
            }
        } else {
            /* Irrespective of whether vap supports EXT NSS or not populate into FW in same manner
             * since rx_nss values are to be populated appropriately into thge local variables by
             * this point
             */
            if (rx_nss160) {
                param.peer_bw_rxnss_override = IEEE80211_BW_NSS_FWCONF_160(rx_nss160 - 1);
            }
            if (rx_nss80p80) {
                param.peer_bw_rxnss_override |= IEEE80211_BW_NSS_FWCONF_80_80(rx_nss80p80 - 1);
            }
        }

        /* In very exceptional  conditions it is observed  that
         * firmware was receiving bw_rxnss_override as 0 for peer from host, and resulting in Target Assert.
         * Changing the rxnss_override to minimum nss. This is a temporary WAR. Needs to be fixed
         * properly.
         */
        if (((param.peer_phymode == WMI_HOST_MODE_11AC_VHT160) || (param.peer_phymode == WMI_HOST_MODE_11AC_VHT80_80))
               && (!ni->ni_bwnss_map) && !same_nss_for_all_bw) {
            ni->ni_bwnss_map |= IEEE80211_BW_NSS_FWCONF_MAP_ENABLE;
            param.peer_bw_rxnss_override = ni->ni_bwnss_map;
        }
    }
    return wmi_unified_peer_assoc_send(scn->wmi_handle, &param);
}

int
ol_ath_mgmt_send(struct ol_ath_softc_net80211 *scn,
                      struct ieee80211_node *ni,
                      int vif_id,
                      wbuf_t wbuf)
{
    struct ieee80211_tx_status ts;
    struct ieee80211com *ic = ni->ni_ic;
    struct wmi_mgmt_params param;

    qdf_mem_set(&param, sizeof(param), 0);
#ifdef MGMT_HTT_ENABLE
    IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD, IEEE80211_MSG_ANY, "WARNING!!! Mgmt frames being sent through WMI path\n");
#endif
    param.tx_frame = wbuf;
    param.pdata = qdf_nbuf_data(wbuf);
    param.frm_len = wbuf_get_pktlen(wbuf);
    param.vdev_id = vif_id;

#ifdef MGMT_DEBUG
     {
       struct ieee80211_frame *wh;
       u_int8_t subtype;

        wh = (struct ieee80211_frame *)wbuf_header(wbuf);
        subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s  frame type %d length %d  \n ", __func__,subtype,wbuf_get_pktlen(wbuf));
     }
#endif
    /* complete the original wbuf */
    do {
        ts.ts_flags = 0;
        ts.ts_retries=0;
        /*
         * complete buf will decrement the pending count.
         */
        ieee80211_complete_wbuf(wbuf,&ts);
     } while(0);


    param.macaddr = ni->ni_macaddr;
    /* Send the management frame buffer to the target */
    if (wmi_mgmt_unified_cmd_send(scn->wmi_handle, &param)) {
        ts.ts_flags = IEEE80211_TX_ERROR;
        ts.ts_retries = 0;
        ieee80211_complete_wbuf(wbuf, &ts);
    }
    return 0;
}

int
ol_ath_send_addba_clearresponse(struct ol_ath_softc_net80211 *scn, struct ieee80211_node *ni)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct addba_clearresponse_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.vdev_id = (OL_ATH_VAP_NET80211(vap))->av_if_id;

    /* Send the management frame buffer to the target */
    return wmi_unified_addba_clearresponse_cmd_send(scn->wmi_handle, ni->ni_macaddr, &param);
}

int
ol_ath_send_addba_send(struct ol_ath_softc_net80211 *scn,
                            struct ieee80211_node *ni,
                            u_int8_t tidno,
                            u_int16_t buffersize)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct addba_send_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.vdev_id = (OL_ATH_VAP_NET80211(vap))->av_if_id;
    param.tidno = tidno;
    param.buffersize = buffersize;

    /* Send the management frame buffer to the target */
    return wmi_unified_addba_send_cmd_send(scn->wmi_handle, ni->ni_macaddr, &param);

}

void
ol_ath_delba_send(struct ol_ath_softc_net80211 *scn,
                    struct ieee80211_node *ni,
                    u_int8_t tidno,
                    u_int8_t initiator,
                    u_int16_t reasoncode)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct delba_send_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.vdev_id = (OL_ATH_VAP_NET80211(vap))->av_if_id;
    param.tidno = tidno;
    param.initiator = initiator;
    param.reasoncode = reasoncode;

    /* send the management frame buffer to the target */
    wmi_unified_delba_send_cmd_send(scn->wmi_handle, ni->ni_macaddr, &param);
}

void
ol_ath_addba_setresponse(struct ol_ath_softc_net80211 *scn,
                        struct ieee80211_node *ni,
                        u_int8_t tidno,
                        u_int16_t statuscode)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct addba_setresponse_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.vdev_id = (OL_ATH_VAP_NET80211(vap))->av_if_id;
    param.tidno = tidno;
    param.statuscode = statuscode;

    /* send the management frame buffer to the target */
    wmi_unified_addba_setresponse_cmd_send(scn->wmi_handle, ni->ni_macaddr, &param);
}

void
ol_ath_send_singleamsdu(struct ol_ath_softc_net80211 *scn,
                        struct ieee80211_node *ni,
                        u_int8_t tidno)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct singleamsdu_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.vdev_id = (OL_ATH_VAP_NET80211(vap))->av_if_id;
    param.tidno = tidno;

    /* send the management frame buffer to the target */
    wmi_unified_singleamsdu_cmd_send(scn->wmi_handle, ni->ni_macaddr, &param);
}

/*
 * Clean ADDBA response status
 */
static void
ol_ath_net80211_addba_clearresponse(struct ieee80211_node *ni)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    /* Notify target of the association/reassociation */
    ol_ath_send_addba_clearresponse(scn, ni);
}
/*
 * Send out ADDBA request
 */
static int
ol_ath_net80211_addba_send(struct ieee80211_node *ni,
                        u_int8_t tidno,
                        u_int16_t buffersize)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    return ol_ath_send_addba_send(scn,ni,tidno,buffersize);
}

/*
 * Send out DELBA request
 */
static void
ol_ath_net80211_delba_send(struct ieee80211_node *ni,
                        u_int8_t tidno,
                        u_int8_t initiator,
                        u_int16_t reasoncode)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    ol_ath_delba_send(scn,ni,tidno,initiator,reasoncode);
}

/*
 * Set ADDBA response
 */
static void
ol_ath_net80211_addba_setresponse(struct ieee80211_node *ni,
                        u_int8_t tidno,
                        u_int16_t statuscode)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    ol_ath_addba_setresponse(scn,ni,tidno,statuscode);
}

/*
 * Send single VHT MPDU AMSDUs
 */
static void
ol_ath_net80211_send_singleamsdu(struct ieee80211_node *ni,
                        u_int8_t tidno)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    ol_ath_send_singleamsdu(scn,ni,tidno);
}

/*
 * Determine the capabilities of the peer for use by the rate control module
 * residing in the target
 */
static u_int32_t
ol_ath_set_ratecap(struct ol_ath_softc_net80211 *scn, struct ieee80211_node *ni,
        struct ieee80211vap *vap)
{
    u_int32_t ratecap = 0;

    /* peer can support 3 streams */
    if (ni->ni_streams == 3)
    {
        ratecap |= WMI_HOST_RC_TS_FLAG;
    }

    /* peer can support 2 streams */
    if (ni->ni_streams >= 2)
    {
        ratecap |= WMI_HOST_RC_DS_FLAG;
    }

    /*
     * With SM power save, only singe stream rates can be used for static MIMOPS.
     * In dynamic SM power save mode, a STA enables its multiple receive chains
     * when it receives the start of a frame sequence addressed to it.
     * The receiver switches to the multiple receive chain mode when it receives the
     * RTS addressed to it and switches back immediately when the frame sequence ends.
     */
    if((ni->ni_htcap & IEEE80211_HTCAP_C_SM_MASK) == IEEE80211_HTCAP_C_SMPOWERSAVE_STATIC) {
        ratecap &= ~(WMI_HOST_RC_TS_FLAG|WMI_HOST_RC_DS_FLAG);
    }

    return ratecap;
}

static u_int32_t
ol_ath_net80211_rate_node_update(struct ieee80211com *ic,
                                 struct ieee80211_node *ni, int isnew)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ieee80211vap *vap = ieee80211_node_get_vap(ni);
    enum ieee80211_cwm_width ic_cw_width = ic->ic_cwm_get_width(ic);
    u_int32_t capflag = 0;

    if (ni->ni_flags & IEEE80211_NODE_HT) {
        capflag |=  WMI_HOST_RC_HT_FLAG;
        if ((ni->ni_chwidth == IEEE80211_CWM_WIDTH40) &&
            (ic_cw_width == IEEE80211_CWM_WIDTH40))
        {
            capflag |=  WMI_HOST_RC_CW40_FLAG;
        }
        if (((ni->ni_htcap & IEEE80211_HTCAP_C_SHORTGI40) &&
             (ic_cw_width == IEEE80211_CWM_WIDTH40)) ||
            ((ni->ni_htcap & IEEE80211_HTCAP_C_SHORTGI20) &&
             (ic_cw_width == IEEE80211_CWM_WIDTH20))) {
            capflag |= WMI_HOST_RC_SGI_FLAG;
        }

        /* Rx STBC is a 2-bit mask. Needs to convert from ieee definition to ath definition. */
        capflag |= (((ni->ni_htcap & IEEE80211_HTCAP_C_RXSTBC) >> IEEE80211_HTCAP_C_RXSTBC_S)
                    << WMI_HOST_RC_RX_STBC_FLAG_S);
        capflag |= ol_ath_set_ratecap(scn, ni, vap);

#if 0
        /* TODO: Security mode related adjustments */

        /* TODO: TxBF related adjustments */
#endif
    }

    if (ni->ni_flags & IEEE80211_NODE_UAPSD) {
        capflag |= WMI_HOST_RC_UAPSD_FLAG;
    }

    return capflag;
}


/*
 *  WMI API for 802.11 management frame processing
 */
static void
ol_ath_send_peer_update(struct ol_ath_softc_net80211 *scn, struct ieee80211com *ic,
                            struct ieee80211_node *ni, uint32_t val)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    const u_int32_t min_idle_inactive_time_secs = 256;
    const u_int32_t max_idle_inactive_time_secs = 256 * 2;
    const u_int32_t max_unresponsive_time_secs  = (256 * 2) + 5;

    if(ol_ath_node_set_param(scn, ni->ni_macaddr,
                WMI_HOST_PEER_USE_4ADDR, val,
                (OL_ATH_VAP_NET80211(vap))->av_if_id)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:Unable to change peer Next Hop setting\n", __func__);
    }

    if(ol_ath_wmi_send_vdev_param(scn,
                avn->av_if_id, wmi_vdev_param_ap_enable_nawds,
                min_idle_inactive_time_secs)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Enable NAWDS Failed\n", __func__);
    }

    if(ol_ath_wmi_send_vdev_param(scn,
                avn->av_if_id, wmi_vdev_param_ap_keepalive_min_idle_inactive_time_secs,
                min_idle_inactive_time_secs)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: MIN INACT Failed\n", __func__);
    }
    if(ol_ath_wmi_send_vdev_param(scn,
                avn->av_if_id, wmi_vdev_param_ap_keepalive_max_idle_inactive_time_secs,
                max_idle_inactive_time_secs)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: MAX INACT Failed\n", __func__);
    }
    if(ol_ath_wmi_send_vdev_param(scn,
                avn->av_if_id, wmi_vdev_param_ap_keepalive_max_unresponsive_time_secs,
                max_unresponsive_time_secs)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: INACT Failed\n", __func__);
    }


}

int
wmi_unified_set_qboost_param(
		struct ol_ath_vap_net80211 *avn,
		struct ol_ath_node_net80211 *anode,
		A_UINT32 value)
{
    struct ol_ath_softc_net80211 *svn = avn->av_sc;
    struct set_qboost_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.vdev_id = avn->av_if_id;
    param.value = value;
    return wmi_unified_set_qboost_param_cmd_send(svn->wmi_handle,
	anode->an_node.ni_macaddr, &param);
}

void
qboost_config(struct ieee80211vap *vap, struct ieee80211_node *ni, bool qboost_cfg)
{
#define QBOOST_ENABLE  1
#define QBOOST_DISABLE 0
	if(qboost_cfg) {
		(void)wmi_unified_set_qboost_param(OL_ATH_VAP_NET80211(vap),
				OL_ATH_NODE_NET80211(ni), QBOOST_ENABLE);
	}else
		(void)wmi_unified_set_qboost_param(OL_ATH_VAP_NET80211(vap),
				OL_ATH_NODE_NET80211(ni), QBOOST_DISABLE);
}

void
ol_ath_net80211_newassoc(struct ieee80211_node *ni, int isnew)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    A_UINT32 uapsd, max_sp, trigger_tid = 0;
    struct ol_txrx_peer_t *peer;

#define USE_4ADDR 1
#if WDS_VENDOR_EXTENSION
    struct ol_txrx_vdev_t *vdev = (struct ol_txrx_vdev_t *)vap->iv_txrx_handle;
    struct ol_txrx_pdev_t *pdev = scn->pdev_txrx_handle;
    if (!(ni->ni_flags & IEEE80211_NODE_NAWDS) && (ni->ni_flags & IEEE80211_NODE_WDS)) {
        int wds_tx_policy_ucast = 0, wds_tx_policy_mcast = 0;

        if (ni->ni_wds_tx_policy) {
            wds_tx_policy_ucast = (ni->ni_wds_tx_policy & WDS_POLICY_TX_UCAST_4ADDR) ? 1: 0;
            wds_tx_policy_mcast = (ni->ni_wds_tx_policy & WDS_POLICY_TX_MCAST_4ADDR) ? 1: 0;
            ol_txrx_peer_wds_tx_policy_update(
                    (OL_ATH_NODE_NET80211(ni))->an_txrx_handle,
                    wds_tx_policy_ucast, wds_tx_policy_mcast);
        }
        else {
            /* if tx_policy is not set, and node is WDS, ucast/mcast frames will be sent as 4ADDR */
            wds_tx_policy_ucast = wds_tx_policy_mcast = 1;
            ol_txrx_peer_wds_tx_policy_update(
                    (OL_ATH_NODE_NET80211(ni))->an_txrx_handle,
                    wds_tx_policy_ucast, wds_tx_policy_mcast);
        }
        if (ieee80211vap_get_opmode(vap) == IEEE80211_M_HOSTAP) {
            if (wds_tx_policy_mcast) {
                struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
                /* turn on MCAST_INDICATE so that multicast/broadcast frames
                 * can be cloned and sent as 4-addr directed frames to clients
                 * that want them in 4-addr format
                 */
                ol_ath_wmi_send_vdev_param(scn,avn->av_if_id,
                                     wmi_vdev_param_mcast_indicate, 1);
                /* turn on UNKNOWN_DEST_INDICATE so that unciast frames to
                 * unknown destinations are indicated to host which can then
                 * send to all connected WDS clients
                 */
                ol_ath_wmi_send_vdev_param(scn,avn->av_if_id,
                                     wmi_vdev_param_unknown_dest_indicate, 1);
            }
            if (wds_tx_policy_ucast || wds_tx_policy_mcast) {
                /* turn on 4-addr framing for this node */
                ol_ath_node_set_param(scn, ni->ni_macaddr,
                                     WMI_HOST_PEER_USE_4ADDR, USE_4ADDR,
                                     (OL_ATH_VAP_NET80211(vap))->av_if_id);
            }
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            if (pdev->nss_wifiol_ctx) {
                /*
                 * Enable WDS Vendor Extension in NSS FW
                 */
                vdev->wds_ext_enabled = 1;
                osif_nss_ol_vdev_set_cfg(vap->iv_txrx_handle, OSIF_NSS_WIFI_VDEV_WDS_EXT_ENABLE);
                peer = (OL_ATH_NODE_NET80211(ni))->an_txrx_handle;
                osif_nss_ol_wds_extn_peer_cfg_send(pdev, peer);
            }
#endif //QCA_NSS_WIFI_OFFLOAD_SUPPORT
        }
    }
#endif //WDS_VENDOR_EXTENSION

    /*
     * 1. Check NAWDS or not
     * 2. Do not Pass PHY MODE 0 as association not allowed in NAWDS.
     *     rc_mask will be NULL and Tgt will assert
     */

    if (ni->ni_flags & IEEE80211_NODE_NAWDS ) {
        IEEE80211_DPRINTF( vap, IEEE80211_MSG_ASSOC, "\n NODE %p is NAWDS ENABLED\n",ni);
        peer = (OL_ATH_NODE_NET80211(ni))->an_txrx_handle;

        if(ni->ni_phymode == 0){
            ni->ni_phymode = vap->iv_des_mode;
        }
        /* Update Host Peer Table */
        peer->nawds_enabled = 1;
        /* Vdev nawds enabling is required only
         * to differentiate Normal/Nawds path
         * But NAWDS is per peer not per vdev
         */
        peer->vdev->nawds_enabled = 1;

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        osif_nss_ol_vdev_set_cfg(vap->iv_txrx_handle, OSIF_NSS_WIFI_VDEV_NAWDS_MODE);
#endif

	ol_ath_send_peer_update(scn, ic, ni, USE_4ADDR);
    }
    /* TODO: Fill in security params */

    /* Notify target of the association/reassociation */
    ol_ath_send_peer_assoc(scn, ic, ni, isnew);

#ifdef ATH_SUPPORT_HYFI_ENHANCEMENTS
    ol_ath_node_ext_stats_enable(ni, 1); // Enable Peer Ext Stats Collection
#endif

    /* XXX must be sent _after_ new assoc */
    switch (vap->iv_opmode) {
    case IEEE80211_M_HOSTAP:
        if (ni->ni_flags & IEEE80211_NODE_UAPSD) {
            if(isnew){
                uapsd = 0;
                if (WME_UAPSD_AC_ENABLED(0, ni->ni_uapsd)) {
                    uapsd |= WMI_HOST_AP_PS_UAPSD_AC0_DELIVERY_EN |
                        WMI_HOST_AP_PS_UAPSD_AC0_TRIGGER_EN;
                }
                if (WME_UAPSD_AC_ENABLED(1, ni->ni_uapsd)) {
                    uapsd |= WMI_HOST_AP_PS_UAPSD_AC1_DELIVERY_EN |
                        WMI_HOST_AP_PS_UAPSD_AC1_TRIGGER_EN;
                }
                if (WME_UAPSD_AC_ENABLED(2, ni->ni_uapsd)) {
                    uapsd |= WMI_HOST_AP_PS_UAPSD_AC2_DELIVERY_EN |
                        WMI_HOST_AP_PS_UAPSD_AC2_TRIGGER_EN;
                }
                if (WME_UAPSD_AC_ENABLED(3, ni->ni_uapsd)) {
                    uapsd |= WMI_HOST_AP_PS_UAPSD_AC3_DELIVERY_EN |
                        WMI_HOST_AP_PS_UAPSD_AC3_TRIGGER_EN;
                }
                (void)wmi_unified_set_ap_ps_param(OL_ATH_VAP_NET80211(vap),
                     OL_ATH_NODE_NET80211(ni), WMI_HOST_AP_PS_PEER_PARAM_UAPSD, uapsd);
            } else {
#if UMAC_SUPPORT_ADMCTL
                ic->ic_node_update_dyn_uapsd(ni,0,WME_UAPSD_AC_INVAL,WME_UAPSD_AC_INVAL);
#endif
            }
            switch (ni->ni_uapsd_maxsp) {
            case 2:
                max_sp = WMI_HOST_AP_PS_PEER_PARAM_MAX_SP_2;
                break;
            case 4:
                max_sp = WMI_HOST_AP_PS_PEER_PARAM_MAX_SP_4;
                break;
            case 6:
                max_sp = WMI_HOST_AP_PS_PEER_PARAM_MAX_SP_6;
                break;
            default:
                max_sp = WMI_HOST_AP_PS_PEER_PARAM_MAX_SP_UNLIMITED;
                break;
            }
        } else {
            uapsd = 0;
            max_sp = 0;
            (void)wmi_unified_set_ap_ps_param(OL_ATH_VAP_NET80211(vap),
                 OL_ATH_NODE_NET80211(ni), WMI_HOST_AP_PS_PEER_PARAM_UAPSD, uapsd);
        }
        (void)wmi_unified_set_ap_ps_param(OL_ATH_VAP_NET80211(vap),
                OL_ATH_NODE_NET80211(ni), WMI_HOST_AP_PS_PEER_PARAM_MAX_SP, max_sp);

	qboost_config(vap, ni, scn->scn_qboost_enable);

	if(scn->scn_sifs_frmtype) {
		(void)wmi_unified_set_ap_ps_param(OL_ATH_VAP_NET80211(vap),
				OL_ATH_NODE_NET80211(ni), WMI_HOST_AP_PS_PEER_PARAM_SIFS_RESP_FRMTYPE, scn->scn_sifs_frmtype);

#define BE_AC_MASK 0x1
#define BK_AC_MASK 0x2
#define VI_AC_MASK 0x4
#define VO_AC_MASK 0x8

#define TRIGGER_BE_TIDS 0x9
#define TRIGGER_BK_TIDS 0x6
#define TRIGGER_VI_TIDS 0x30
#define TRIGGER_VO_TIDS 0xC0
		if(scn->scn_sifs_uapsd & BE_AC_MASK)
			trigger_tid = TRIGGER_BE_TIDS;
		if(scn->scn_sifs_uapsd & BK_AC_MASK)
			trigger_tid |= TRIGGER_BK_TIDS;
		if(scn->scn_sifs_uapsd & VI_AC_MASK)
			trigger_tid |= TRIGGER_VI_TIDS;
		if(scn->scn_sifs_uapsd & VO_AC_MASK)
			trigger_tid |= TRIGGER_VO_TIDS;

		(void)wmi_unified_set_ap_ps_param(OL_ATH_VAP_NET80211(vap),
				OL_ATH_NODE_NET80211(ni), WMI_HOST_AP_PS_PEER_PARAM_SIFS_RESP_UAPSD, trigger_tid);
	} else {
		/*
		 * No meaning to enable trigger too. Disable this too
		 */
		AR_DEBUG_PRINTF(ATH_DEBUG_INFO,("\n Disabling Both SIFS RESP and UAPSD TRIGGER\n"));
#define DISABLE_SIFS_RESP_TRIGGER 0x0
		(void)wmi_unified_set_ap_ps_param(OL_ATH_VAP_NET80211(vap),
				OL_ATH_NODE_NET80211(ni), WMI_HOST_AP_PS_PEER_PARAM_SIFS_RESP_FRMTYPE, DISABLE_SIFS_RESP_TRIGGER);
		(void)wmi_unified_set_ap_ps_param(OL_ATH_VAP_NET80211(vap),
				OL_ATH_NODE_NET80211(ni), WMI_HOST_AP_PS_PEER_PARAM_SIFS_RESP_UAPSD, DISABLE_SIFS_RESP_TRIGGER);
	}
#if ATH_SUPPORT_GREEN_AP
        ath_green_ap_state_mc(ic, ATH_PS_EVENT_INC_STA);
#endif  /* ATH_SUPPORT_GREEN_AP */
        break;
    case IEEE80211_M_STA:
	qboost_config(vap, ni, scn->scn_qboost_enable);
	break;
    default:
        break;
    }
}

typedef struct {
    int8_t          rssi;       /* RSSI (noise floor ajusted) */
    u_int16_t       channel;    /* Channel */
    int             rateKbps;   /* data rate received (Kbps) */
    WLAN_PHY_MODE   phy_mode;   /* phy mode */
    u_int8_t        status;     /* rx descriptor status */
} ol_ath_ieee80211_rx_status_t;

static INLINE void
ol_ath_rxstat2ieee(struct ieee80211com *ic,
                ol_ath_ieee80211_rx_status_t *rx_status,
                struct ieee80211_rx_status *rs)
{
    uint32_t phy_mode = (uint32_t) rx_status->phy_mode;
    /* TBD: More fields to be updated later */
    rs->rs_rssi     = rx_status->rssi;
    rs->rs_datarate = rx_status->rateKbps;
    rs->rs_channel  = rx_status->channel;
    rs->rs_flags  = 0;
    if (rx_status->status & WMI_HOST_RXERR_CRC)
        rs->rs_flags  |= IEEE80211_RX_FCS_ERROR;
    if (rx_status->status & WMI_HOST_RXERR_DECRYPT)
        rs->rs_flags  |= IEEE80211_RX_DECRYPT_ERROR;
    if (rx_status->status & WMI_HOST_RXERR_MIC)
        rs->rs_flags  |= IEEE80211_RX_MIC_ERROR;
    if (rx_status->status & WMI_HOST_RXERR_KEY_CACHE_MISS)
        rs->rs_flags  |= IEEE80211_RX_KEYMISS;
    /* TBD: whalGetNf in firmware is fixed to-96. Maybe firmware should calculate it based on whalGetChanNf? */
    rs->rs_abs_rssi = rx_status->rssi - 96;
    switch (phy_mode)
    {
    case MODE_11A:
        rs->rs_phymode = IEEE80211_MODE_11A;
        break;
    case MODE_11B:
        rs->rs_phymode = IEEE80211_MODE_11B;
        break;
    case MODE_11G:
        rs->rs_phymode = IEEE80211_MODE_11G;
        break;
    case MODE_11NA_HT20:
        rs->rs_phymode = IEEE80211_MODE_11NA_HT20;
        break;
    case MODE_11NA_HT40:
        if (ic->ic_cwm_get_extoffset(ic) == 1)
            rs->rs_phymode = IEEE80211_MODE_11NA_HT40PLUS;
        else
            rs->rs_phymode = IEEE80211_MODE_11NA_HT40MINUS;
        break;
    case MODE_11NG_HT20:
        rs->rs_phymode = IEEE80211_MODE_11NG_HT20;
        break;
    case MODE_11NG_HT40:
        if (ic->ic_cwm_get_extoffset(ic) == 1)
            rs->rs_phymode = IEEE80211_MODE_11NG_HT40PLUS;
        else
            rs->rs_phymode = IEEE80211_MODE_11NG_HT40MINUS;
        break;
    case MODE_11AC_VHT20:
        rs->rs_phymode = IEEE80211_MODE_11AC_VHT20;
        break;
    case MODE_11AC_VHT40:
        if (ic->ic_cwm_get_extoffset(ic) == 1)
            rs->rs_phymode = IEEE80211_MODE_11AC_VHT40PLUS;
        else
            rs->rs_phymode = IEEE80211_MODE_11AC_VHT40MINUS;
        break;
    case MODE_11AC_VHT80:
        rs->rs_phymode = IEEE80211_MODE_11AC_VHT80;
        break;
    case MODE_11AC_VHT160:
        rs->rs_phymode = IEEE80211_MODE_11AC_VHT160;
        break;
    case MODE_11AC_VHT80_80:
        rs->rs_phymode = IEEE80211_MODE_11AC_VHT80_80;
        break;
    default:
        break;
    }
    rs->rs_freq = ieee80211_ieee2mhz(ic, rs->rs_channel, 0);
#ifdef HOST_SUPPORT_BEELINER_MPHYR
#define DEFAULT_MPHYR_FREQ 5200
        rs->rs_freq = DEFAULT_MPHYR_FREQ;
#endif
    rs->rs_full_chan = ol_ath_find_full_channel(ic, rs->rs_freq);
}

#ifndef REMOVE_PKT_LOG
void
chk_vht_groupid_action_frame(ol_scn_t scn,struct ieee80211_node *ni, wbuf_t wbuf)
{
    struct ol_txrx_pdev_t *txrx_pdev = scn->pdev_txrx_handle;
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211_frame *wh;
    struct ieee80211_action_vht_gid_mgmt  *gid_mgmt_frm;
    int type, subtype;
    u_int8_t action_category;
    u_int8_t vht_action;

    wbuf_set_node(wbuf, ni);

    if (wbuf_get_pktlen(wbuf) < ic->ic_minframesize) {
        goto endtortn;
    }
    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    if ((wh->i_fc[0] & IEEE80211_FC0_VERSION_MASK) != IEEE80211_FC0_VERSION_0) {
        goto endtortn;
    }
    type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
    if((type == IEEE80211_FC0_TYPE_MGT)&&(subtype == IEEE80211_FC0_SUBTYPE_ACTION))
    {
        action_category = ((struct ieee80211_action *)(&wh[1]))->ia_category;
        vht_action = ((struct ieee80211_action *)(&wh[1]))->ia_action;
        if((action_category == IEEE80211_ACTION_CAT_VHT)&&(vht_action == IEEE80211_ACTION_VHT_GROUP_ID))
        {
           /* Save the group ID managemnt information so dump themn into log file in rx_info_remote of pktlog*/
           gid_mgmt_frm = (struct ieee80211_action_vht_gid_mgmt *)(&wh[1]);
           txrx_pdev->gid_flag = 1;

           qdf_mem_copy((void *)&(txrx_pdev->gid_mgmt.member_status[0]),
                          (void *)&(gid_mgmt_frm->member_status[0]),
                   sizeof(txrx_pdev->gid_mgmt.member_status));
           qdf_mem_copy((void *)&(txrx_pdev->gid_mgmt.user_position[0]),
                   (void *)&(gid_mgmt_frm->user_position[0]),
                   sizeof(txrx_pdev->gid_mgmt.user_position));

        }
    }

endtortn:
    return;

}
#endif

/*
 * WMI RX event handler for management frames
 */
static int
ol_ath_mgmt_rx_event_handler(ol_scn_t scn, u_int8_t *data, u_int16_t datalen)
{
    struct ieee80211com *ic = &scn->sc_ic;
    wmi_host_mgmt_rx_hdr rx_event;
    ol_ath_ieee80211_rx_status_t rx_status;
    struct ieee80211_rx_status rs;
    struct ieee80211_node *ni;
    struct ieee80211_frame *wh;
    uint8_t *bufp;
    uint32_t len;
    wbuf_t wbuf;

    if(wmi_extract_mgmt_rx_params(scn->wmi_handle, data, &rx_event, &bufp)) {
        qdf_print("Failed to extract mgmt frame\n");
        return 0;
    }

    /* Update RX status */
    rx_status.channel = rx_event.channel;
    rx_status.rssi = rx_event.snr;
    rx_status.rateKbps = rx_event.rate;
    rx_status.phy_mode = rx_event.phy_mode;
    rx_status.status = rx_event.status;

    if (!ic) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ic is NULL\n");
        return 0;
    }

    len = roundup(rx_event.buf_len, sizeof(u_int32_t));
    wbuf =  wbuf_alloc(ic->ic_osdev, WBUF_RX_INTERNAL,
                       len);

    if (wbuf == NULL) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "wbuf alloc failed\n");
        return 0;
    }

#ifdef DEBUG_RX_FRAME
   {
    int i;
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s wbuf 0x%x frame length %d  \n ",
                 __func__,(unsigned int) wbuf, rx_event.buf_len);
    for (i=0;i<rx_event.buf_len; ++i ) {
      QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%x ", bufp[i]);
      if (i%16 == 0) printk("\n");
    }
   }
   QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s rx frame type 0x%x frame length %d  \n ",
                 __func__,bufp[0], rx_event.buf_len);
#endif

    wbuf_init(wbuf, rx_event.buf_len);
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
#ifdef BIG_ENDIAN_HOST
    {
        /* for big endian host, copy engine byte_swap is enabled
         * But the rx mgmt frame buffer content is in network byte order
         * Need to byte swap the mgmt frame buffer content - so when copy engine
         * does byte_swap - host gets buffer content in the correct byte order
         */
        int i;
        u_int32_t *destp, *srcp;
        destp = (u_int32_t *)wh;
        srcp =  (u_int32_t *)bufp;
        for(i=0; i < (len/4); i++) {
            *destp = cpu_to_le32(*srcp);
            destp++; srcp++;
        }
    }
#else
    OS_MEMCPY(wh, bufp, rx_event.buf_len);
#endif

#if ATH_SUPPORT_IWSPY
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    ieee80211_input_iwspy_update_rssi(ic, wh->i_addr2, rx_status.rssi);
#endif

    /*
     * From this point on we assume the frame is at least
     * as large as ieee80211_frame_min; verify that.
     */
    if (wbuf_get_pktlen(wbuf) < ic->ic_minframesize) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: short packet %d\n", __func__, wbuf_get_pktlen(wbuf));
        wbuf_free(wbuf);
        return 0;
    }

    memset(&rs, 0, sizeof(rs));

    /*
     * Locate the node for sender, track state, and then
     * pass the (referenced) node up to the 802.11 layer
     * for its use.  If the sender is unknown spam the
     * frame; it'll be dropped where it's not wanted.
     */
    ni = ieee80211_find_rxnode(ic, (struct ieee80211_frame_min *)
                               wbuf_header(wbuf));
    /* If we receive a probereq with broadcast bssid which is usually
     * sent by sender to discover new networks, all the vaps should send reply */
    if (ni == NULL || (IEEE80211_IS_PROBEREQ(wh) && IEEE80211_IS_BROADCAST(wh->i_addr3))) {
        ol_ath_rxstat2ieee(ic, &rx_status, &rs);
        if (ni) {
            ieee80211_free_node(ni);
        }
        ieee80211_input_all(ic, wbuf, &rs);
    } else {
        ol_ath_rxstat2ieee(ni->ni_ic, &rx_status, &rs);

        ni->ni_stats.ns_last_rx_mgmt_rate = rx_status.rateKbps;
        ni->ni_stats.ns_rx_mgmt_rssi = rx_status.rssi;
#ifndef REMOVE_PKT_LOG
        if(scn->pl_dev)
            chk_vht_groupid_action_frame(scn, ni, wbuf);
#endif
        ieee80211_input(ni, wbuf, &rs);
        ieee80211_free_node(ni);
    }

    return 0;
}

static void
mgmt_crypto_encap(wbuf_t wbuf)
{
    struct ieee80211_frame *wh;
    struct ieee80211_node *ni = wbuf_get_node(wbuf);
    int tid;
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);

    /* encap only incase of WEP bit set */
    if (wh->i_fc[1] & IEEE80211_FC1_WEP) {

        struct ieee80211_key *k;

        tid = wbuf_get_tid(wbuf);
        /* construct iv header */
        if (tid == OFFCHAN_EXT_TID_NONPAUSE) {
            k = ieee80211_crypto_encap_mon(ni, wbuf);
        }
        else {
            k = ieee80211_crypto_encap(ni, wbuf);
        }

        if (k == NULL) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Mgmt encap Failed \n");
            return;
        }
        if (tid != OFFCHAN_EXT_TID_NONPAUSE) {
            /* OFFCHAN_EXT_TID_NONPAUSE tid is used for offchan raw mode TX,
              encrypt trailer already added in e.g. __wep_encrypt()*/
	        wbuf_append(wbuf, k->wk_cipher->ic_trailer);
        }

    }
}


/*
 * Send Mgmt frames via WMI
 */
int
ol_ath_tx_mgmt_wmi_send(struct ieee80211com *ic, wbuf_t wbuf)
{

    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ieee80211_node *ni = wbuf_get_node(wbuf);
    struct ieee80211vap *vap = ni->ni_vap;
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    struct ieee80211_frame *wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    struct ieee80211_tx_status ts;
    int ret = 0;

    /**********************************************************************
     * TODO: Once we have the HTT framework for sending management frames
     * this function will  be unused
     **********************************************************************/

    switch (wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) {
    case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
        {
            u_int64_t adjusted_tsf_le;
            struct ol_ath_cookie *scn_cookie = &scn->scn_cookie;

            if (scn_cookie->cookie_count < (MAX_COOKIE_NUM * 1 / 4)) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC, "Dropping probe resp (cookies: %d)", scn_cookie->cookie_count);
                ts.ts_flags = IEEE80211_TX_ERROR;
                ts.ts_retries = 0;
                ieee80211_complete_wbuf(wbuf, &ts);
                return -ENOMEM;
            }
            /*
             * Make the TSF offset negative to match TSF in beacons
             */
            adjusted_tsf_le = cpu_to_le64(0ULL - avn->av_tsfadjust);

            OS_MEMCPY(&wh[1], &adjusted_tsf_le, sizeof(adjusted_tsf_le));
        }
        break;
    }

    /*Encap crypto header and trailer
     *Needed in case od shared WEP authentication
     */
    mgmt_crypto_encap(wbuf);
#ifdef MGMT_HTT_ENABLE
    ret = ol_txrx_mgmt_send(vap->iv_txrx_handle, wbuf, OL_TXRX_MGMT_TYPE_BASE);
    if(ret < 0) {
        ts.ts_flags = IEEE80211_TX_ERROR;
        ts.ts_retries = 0;
        ieee80211_complete_wbuf(wbuf, &ts);
    }
    return ret;
#else
    ret = ol_mgmt_send(ic, (OL_ATH_VAP_NET80211(vap))->av_if_id, wbuf);
    if( ret < 0 ) {
        ts.ts_flags = IEEE80211_TX_ERROR;
        ts.ts_retries = 0;
        ieee80211_complete_wbuf(wbuf, &ts);
    }
    return ret;

#if 0
    return ol_ath_mgmt_send(scn, ni,
            (OL_ATH_VAP_NET80211(vap))->av_if_id, wbuf);
#endif
#endif

}




#if WDI_EVENT_ENABLE
void rx_peer_invalid(void *pdev, enum WDI_EVENT event, void *data, u_int16_t peer_id, enum htt_rx_status status)
{
#define MIN_DEAUTH_INTERVAL 10 /* in msec */
    ol_txrx_pdev_handle txrx_pdev = (ol_txrx_pdev_handle)pdev;
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)txrx_pdev->ctrl_pdev;
    struct ieee80211com *ic = &scn->sc_ic;
    struct wdi_event_rx_peer_invalid_msg *msg = (struct wdi_event_rx_peer_invalid_msg *)data;
    qdf_nbuf_t msdu = msg->msdu;
    struct ieee80211_frame *wh = msg->wh;
    u_int8_t vdev_id = msg->vdev_id;
    struct ieee80211vap *vap;
    ol_ath_ieee80211_rx_status_t rx_status;
    struct ieee80211_rx_status rs;
    wbuf_t wbuf;
    int wbuf_len;
    qdf_time_t now = 0,elasped_time = 0,max;
    struct ieee80211_node *ni;

    vap = ol_ath_vap_get(scn, vdev_id);
    if (vap == NULL) {
        /* No active vap */
        return;
    }
    max = (qdf_time_t)(-1); /*Max value 0xffffffffffffffff*/

    now = qdf_system_ticks_to_msecs(qdf_system_ticks());
    /* Wrap around condition */
    if(now < scn->scn_last_peer_invalid_time) {
        elasped_time = qdf_system_ticks_to_msecs(max) - scn->scn_last_peer_invalid_time + now + 1;
    } else
        elasped_time = now - scn->scn_last_peer_invalid_time;

    if(((elasped_time < MIN_DEAUTH_INTERVAL) &&
                scn->scn_last_peer_invalid_time) &&
            scn->scn_peer_invalid_cnt >= scn->scn_user_peer_invalid_cnt) {
        return;
    }
    if(elasped_time >= MIN_DEAUTH_INTERVAL)
        scn->scn_peer_invalid_cnt = 0;

    scn->scn_last_peer_invalid_time = qdf_system_ticks_to_msecs(qdf_system_ticks());

    scn->scn_peer_invalid_cnt++;

    /* Some times host gets peer_invalid frames
	 * for already associated node
	 * Not sending such frames to UMAC if the node
	 * is already associated
	 * to prevent UMAC sending Deauth to such associated
	 * nodes.
	 */
    ni = ieee80211_find_rxnode(ic, (struct ieee80211_frame_min *)wh);
    if (ni != NULL) {
       ieee80211_free_node(ni);
       return;
    }

    ni = ieee80211_ref_bss_node(vap);
    if (ni == NULL) {
       /* BSS node is already got deleted */
       return;
    }

    /* the msdu is already encapped with eth hdr */
    wbuf_len = qdf_nbuf_len(msdu) + sizeof(struct ieee80211_frame) - sizeof(struct ethernet_hdr_t);

    wbuf =  wbuf_alloc(ic->ic_osdev, WBUF_RX_INTERNAL, wbuf_len);
    if (wbuf == NULL) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: wbuf alloc failed\n", __func__);
        goto done; /* to free bss node ref */
    }
    wbuf_init(wbuf, wbuf_len);
    OS_MEMCPY(wbuf_header(wbuf), wh, sizeof(struct ieee80211_frame));
    OS_MEMCPY(wbuf_header(wbuf) + sizeof(struct ieee80211_frame),
              qdf_nbuf_data(msdu) + sizeof(struct ethernet_hdr_t),
              wbuf_len - sizeof(struct ieee80211_frame));
    OS_MEMZERO(&rx_status, sizeof(rx_status));
    /* we received this message because there is no entry for the peer in the key table */
    rx_status.status |= WMI_HOST_RXERR_KEY_CACHE_MISS;
    ol_ath_rxstat2ieee(ic, &rx_status, &rs);
    ieee80211_input(ni, wbuf, &rs);

done:
    ieee80211_free_node(ni);
#undef MIN_DEAUTH_INTERVAL
}
#endif

/*
 * Management related attach functions for offload solutions
 */
void
ol_txrx_mgmt_tx_complete(void *ctxt, wbuf_t wbuf, int err)
{
    struct ieee80211_tx_status ts;
    uint32_t cleanup_flag = 0;
    struct ieee80211_frame *wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    int subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

    if (err & IEEE80211_SKB_FREE_ONLY) {
        wbuf_complete_any(wbuf);
        return;
    } else if (err & IEEE80211_TX_ERROR_NO_SKB_FREE) {
        cleanup_flag = IEEE80211_TX_ERROR_NO_SKB_FREE;
    }

    if (!err) {
        ts.ts_flags = 0;
    } else {
        if (err == 3) { /* 1 = drop due to wal resoure, 3 = retry  */
			ts.ts_flags = IEEE80211_TX_XRETRY;
        } else {
			ts.ts_flags = IEEE80211_TX_ERROR;
        }
    }
    ts.ts_flags |= cleanup_flag;
    ts.ts_retries=0;
    KASSERT((wbuf_get_node(wbuf) != NULL),("ni can not be null"));
    KASSERT((wbuf_get_node(wbuf)->ni_vap != NULL),("vap can not be null"));
	//ol_tx_statistics(pdev->ctrl_pdev, wbuf_get_node(wbuf)->ni_vap->iv_unit,
	//	ts.ts_flags == IEEE80211_TX_XRETRY);
    if (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP) {
        struct ieee80211_node *ni = wbuf_get_node(wbuf);
        ni->ni_last_assoc_rx_time = 0;
    }
    /*
     * complete buf will decrement the pending count.
     */
    ieee80211_complete_wbuf(wbuf,&ts);
}
void
ol_ath_mgmt_attach(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    ol_txrx_pdev_handle txrx_pdev = scn->pdev_txrx_handle;

    /* TODO:
     * Disable this WMI xmit logic once we have the transport ready
     * for management frames
     */
#ifdef OL_MGMT_TX_WMI
    ic->ic_mgtstart = ol_ath_tx_mgmt_wmi_send;
#else
    ic->ic_mgtstart = ol_ath_tx_mgmt_send;
#endif
    ic->ic_newassoc = ol_ath_net80211_newassoc;
    ic->ic_addba_clearresponse = ol_ath_net80211_addba_clearresponse;
    ic->ic_addba_send = ol_ath_net80211_addba_send;
    ic->ic_delba_send = ol_ath_net80211_delba_send;
    ic->ic_addba_setresponse = ol_ath_net80211_addba_setresponse;
    ic->ic_send_singleamsdu = ol_ath_net80211_send_singleamsdu;

    /* Register WMI event handlers */
    wmi_unified_register_event_handler(scn->wmi_handle, wmi_mgmt_rx_event_id,
                                            ol_ath_mgmt_rx_event_handler, WMI_RX_UMAC_CTX);

#if WDI_EVENT_ENABLE
    scn->scn_rx_peer_invalid_subscriber.callback = rx_peer_invalid;
    wdi_event_sub(txrx_pdev, &scn->scn_rx_peer_invalid_subscriber, WDI_EVENT_RX_PEER_INVALID);
    scn->scn_last_peer_invalid_time = 0;
    scn->scn_peer_invalid_cnt = 0;
    scn->scn_user_peer_invalid_cnt = 1 ;/* By default we will send one deauth in 10 msec in response to rx_peer_invalid */
#endif
    /* should always be equal to define DEFAULT_LOWEST_RATE_IN_5GHZ 0x03  6 Mbps  in firmware */
    scn->ol_rts_cts_rate = 0x03;
    /* register txmgmt completion call back */
    ol_txrx_mgmt_tx_cb_set(txrx_pdev,
                          (OL_TXRX_MGMT_NUM_TYPES-1),
			   NULL,
                           ol_txrx_mgmt_tx_complete,
                           txrx_pdev);

}
#endif
