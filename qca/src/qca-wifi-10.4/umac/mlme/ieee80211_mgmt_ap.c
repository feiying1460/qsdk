/*
 * Copyright (c) 2011, 2017 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * Copyright (c) 2010, Atheros Communications Inc.
 * All Rights Reserved.
 *
 * 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#include "ieee80211_mlme_priv.h"
#include <acfg_event.h>
#include <acfg_drv_event.h>
#if ATH_SUPPORT_WIFIPOS
#include <ieee80211_wifipos.h>
#endif
#if UMAC_SUPPORT_AP || UMAC_SUPPORT_BTAMP
#if UMAC_SUPPORT_RRM
#include "rrm/ieee80211_rrm_priv.h"
#endif
#include <ieee80211_mbo.h>

static void
ieee80211_saveie(osdev_t osdev, u_int8_t **iep, const u_int8_t *ie)
{
    u_int ielen = ie[1]+2;
    /*
     * Record information element for later use.
     */
    if (*iep == NULL || (*iep)[1] != ie[1]) {
        if (*iep != NULL)
            OS_FREE(*iep);
        *iep = OS_MALLOC(osdev,ielen,0);
    }
    if (*iep != NULL)
        OS_MEMCPY(*iep, ie, ielen);
}

int ieee80211_ht_nss_mcs_valid(struct ieee80211_node *ni, u_int8_t *hcap)
{
    struct ieee80211_ie_htcap_cmn *htcap = (struct ieee80211_ie_htcap_cmn *)hcap;
    struct ieee80211vap *vap = ni->ni_vap;
    u_int32_t r_rx_mcs = 0;

    if(!vap->iv_ht_ratemasklower32)
        return 0;

    r_rx_mcs = ((htcap->hc_mcsset[IEEE80211_RX_MCS_1_STREAM_BYTE_OFFSET] & 0xFF) |
               ((htcap->hc_mcsset[IEEE80211_RX_MCS_2_STREAM_BYTE_OFFSET] << 8) & 0xFF00) |
               ((htcap->hc_mcsset[IEEE80211_RX_MCS_3_STREAM_BYTE_OFFSET] << 16) & 0xFF0000) |
               ((htcap->hc_mcsset[IEEE80211_RX_MCS_4_STREAM_BYTE_OFFSET] << 24) & 0xFF000000));

    if(r_rx_mcs & vap->iv_ht_ratemasklower32)
	return 0;
    else
	return -1;
}

int ieee80211_vht_nss_mcs_valid(struct ieee80211_node *ni, u_int8_t *vcap)
{
    u_int8_t rnss_mcs,mcs_range;
    u_int8_t nss_index = 0;
    u_int8_t i,j=0;
    u_int32_t r_vht_ratemasklower32 = 0;
    u_int32_t r_vht_ratemaskhigher32 = 0;
    struct ieee80211_ie_vhtcap *vhtcap = (struct ieee80211_ie_vhtcap *)vcap;
    int rx_vhtrates = qdf_le16_to_cpu(vhtcap->rx_mcs_map);
    struct ieee80211vap *vap = ni->ni_vap;


    if ((vap->iv_vht_ratemaskhigher32 == 0) && (vap->iv_vht_ratemasklower32 == 0)) {
        return 0;
    }
    /* iwpriv setrcparams uses 1-1 format to set the MCS for each NSS
     * For each NSS 10 bits are used to represent max MCS0-9. In these 10 bits, bit 0 for MCS0, bit 1 for MCS1 etc
     * Convert the received rx mcs in vht cap IE of assoc req into format of 'iwpriv setrcparams' */

    while(nss_index < VHT_MAX_NSS)
    {
	rnss_mcs=rx_vhtrates & VHT_CAP_IE_NSS_MCS_MASK;
	if( rnss_mcs < VHT_CAP_IE_NSS_MCS_RES) {
	    switch(rnss_mcs) {
		case VHT_CAP_IE_NSS_MCS_0_9:
		    mcs_range=9;
		    break;
		case VHT_CAP_IE_NSS_MCS_0_8:
		    mcs_range=8;
		    break;
		default:
		    mcs_range=7;
	    }
            /* Conver MCS_range to 1-1 mapping i.e bit 0 for MCS0, bit 1 for MCS1 etc*/
	    for(i=0;i<=mcs_range;i++){
		if((i+j) < 32) {
		    r_vht_ratemasklower32 |= 1<<(i+j);
		}
		else
		    r_vht_ratemaskhigher32 |= 1<<((i+j) - 32);

	    }/* End of for loop */
	} /* End of if */
	rx_vhtrates = rx_vhtrates >> 2;
	nss_index++;
	j += 10;
    }/* End of while loop */

    /* Check receivd vs fw configured rates */
    if((r_vht_ratemasklower32 & vap->iv_vht_ratemasklower32) ||
       (r_vht_ratemaskhigher32 & vap->iv_vht_ratemaskhigher32)){
	return 0;
    }

    return -1;
}

int
ieee80211_recv_asreq(struct ieee80211_node *ni, wbuf_t wbuf, int subtype)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211_frame *wh;
    u_int8_t *frm, *efrm;
    u_int16_t capinfo, bintval;
    struct ieee80211_rsnparms rsn;
    u_int8_t reason;
    int reassoc, resp;
    u_int8_t *ssid, *rates, *xrates, *wpa, *wme, *ath, *htcap,*vendor_ie, *wps, *vhtcap, *mbo = NULL;
    u_int8_t *athextcap, *opmode, *xcaps, *bwnss_oui, *supp_op_cl = NULL, *whc_rept_info = NULL;
    u_int8_t dedicated_client = 0;
#if ATH_BAND_STEERING
    u_int8_t *pwrcap = NULL;
#endif
#if UMAC_SUPPORT_RRM
    u_int8_t *rrmcap = NULL;
#endif
# if QCN_IE
    u_int8_t *qcn = NULL;
#endif

#define ADD_NI_RATES_NUM 8
    IEEE80211_COUNTRY_ENTRY country;
    u_int8_t temp_ni_rates[ADD_NI_RATES_NUM] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7};

#if UMAC_SUPPORT_WNM

	u_int8_t *timbcast;
	timbcast = NULL;

#endif

    if (vap->iv_opmode != IEEE80211_M_HOSTAP && \
        vap->iv_opmode != IEEE80211_M_BTAMP &&  \
        vap->iv_opmode != IEEE80211_M_IBSS) {
        vap->iv_stats.is_rx_mgtdiscard++;
        return -EINVAL;
    }
    else if(vap->iv_opmode == IEEE80211_M_IBSS && !ic->ic_softap_enable){
        vap->iv_stats.is_rx_mgtdiscard++;
        return -EINVAL;
    }
    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    frm = (u_int8_t *)&wh[1];
    efrm = wbuf_header(wbuf) + wbuf_get_pktlen(wbuf);

    if (subtype == IEEE80211_FC0_SUBTYPE_REASSOC_REQ) {
        reassoc = 1;
        resp = IEEE80211_FC0_SUBTYPE_REASSOC_RESP;
    } else {
        reassoc = 0;
        resp = IEEE80211_FC0_SUBTYPE_ASSOC_RESP;
    }
    /*
     * asreq frame format
     *    [2] capability information
     *    [2] listen interval
     *    [6*] current AP address (reassoc only)
     *    [tlv] ssid
     *    [tlv] supported rates
     *    [tlv] extended supported rates
     *    [tlv] WPA or RSN
     *    [tlv] WME
     *    [tlv] HT Capabilities
     *    [tlv] VHT Capabilities
     *    [tlv] Atheros capabilities
     *    [tlv] Bandwidth NSS mapping
     */
    IEEE80211_VERIFY_LENGTH(efrm - frm, (reassoc ? 10 : 4));
    if (!IEEE80211_ADDR_EQ(wh->i_addr3, vap->iv_bss->ni_bssid)) {
        IEEE80211_DISCARD(vap, IEEE80211_MSG_ASSOC,
                          wh, ieee80211_mgt_subtype_name[subtype >>
                                                         IEEE80211_FC0_SUBTYPE_SHIFT],
                          "%s\n", "wrong bssid");
        vap->iv_stats.is_rx_assoc_bss++;
        return -EBUSY;
    }

    vendor_ie = NULL;
    capinfo = le16toh(*(u_int16_t *)frm);    frm += 2;
    bintval = le16toh(*(u_int16_t *)frm);    frm += 2;
    if (reassoc)
        frm += 6;    /* ignore current AP info */
    ssid = rates = xrates = wpa = wme = ath = htcap = wps = vhtcap = opmode = mbo = NULL;
    athextcap = xcaps = bwnss_oui = supp_op_cl = NULL;

    while (((frm + 1) < efrm) && (frm + frm[1] + 1) < efrm) {
        switch (*frm) {
        case IEEE80211_ELEMID_SSID:
            ssid = frm;
            break;
        case IEEE80211_ELEMID_RATES:
            rates = frm;
            break;
        case IEEE80211_ELEMID_XRATES:
            xrates = frm;
            break;
            /* XXX verify only one of RSN and WPA ie's? */
        case IEEE80211_ELEMID_RSN:
#if ATH_SUPPORT_WAPI
        case IEEE80211_ELEMID_WAPI:
#endif
            wpa = frm;
            break;
        case IEEE80211_ELEMID_HTCAP_ANA:
            htcap = (u_int8_t *)&((struct ieee80211_ie_htcap *)frm)->hc_ie;
            break;
#if UMAC_SUPPORT_WNM
        case IEEE80211_ELEMID_TIM_BCAST_REQUEST:
            if(timbcast == NULL)
                timbcast = frm;
            break;
#endif
#if ATH_SUPPORT_HS20
        case IEEE80211_ELEMID_XCAPS:
            xcaps = frm;
            break;
#endif
        case IEEE80211_ELEMID_SUPP_OP_CLASS:
            supp_op_cl = frm;
            break;
        case IEEE80211_ELEMID_VHTCAP:
            if(vhtcap == NULL)
                vhtcap = (u_int8_t *)(struct ieee80211_ie_vhtcap *)frm;
            break;
        case IEEE80211_ELEMID_OP_MODE_NOTIFY:
            if(opmode == NULL)
                opmode = (u_int8_t *)(struct ieee80211_ie_op_mode_ntfy *)frm;
            break;
#if ATH_BAND_STEERING
        case IEEE80211_ELEMID_PWRCAP:
            pwrcap = frm;
            break;
#endif
#if UMAC_SUPPORT_RRM
        case IEEE80211_ELEMID_RRM:
            rrmcap = frm;
            break;
#endif
        case IEEE80211_ELEMID_VENDOR:
            if (iswpaoui(frm)) {
                if (RSN_AUTH_IS_WPA(&vap->iv_bss->ni_rsn))
                    wpa = frm;
            } else if (iswmeinfo(frm))
                wme = frm;
            else if (isatherosoui(frm))
                ath = frm;
            else if (ismbooui(frm))
                mbo = frm;
            else if(ishtcap(frm)){
                if(htcap == NULL)
                    htcap = (u_int8_t *)&((struct vendor_ie_htcap *)frm)->hc_ie;
            }
            else if (isatheros_extcap_oui(frm))
                 athextcap = frm;
            else if (isdedicated_cap_oui(frm))
                 dedicated_client = 1;
            else if (isqca_whc_rept_oui(frm, QCA_OUI_WHC_REPT_INFO_SUBTYPE)) {
                whc_rept_info = frm;
            }
            else if (isbwnss_oui(frm))
                 bwnss_oui = frm;
            else if (iswpsoui(frm))
                 wps = frm;
            else if (isinterop_vht(frm) && (!vhtcap) && ieee80211vap_11ng_vht_interopallowed(vap)) {
                 /* frm+7 is the location , where 2.4G Interop VHT IE starts */
                 vhtcap = (u_int8_t *)(struct ieee80211_ie_vhtcap *) (frm + 7);
                 ni->ni_vhtintop_subtype = (u_int8_t)(*(frm + 6));
                 ni->ni_flags |= IEEE80211_NODE_11NG_VHT_INTEROP_AMSDU_DISABLE;
            }
            else if(isqca_whc_oui(frm, QCA_OUI_WHC_AP_INFO_SUBTYPE))
            {
                u_int16_t whcCaps;
                struct ieee80211_ie_whc_apinfo *whcAPInfoIE = (struct ieee80211_ie_whc_apinfo *)frm;

                whcCaps = LE_READ_2(&whcAPInfoIE->whc_apinfo_capabilities);
                if (whcCaps & QCA_OUI_WHC_AP_INFO_CAP_WDS) {
                    ieee80211node_set_whc_apinfo_flag(ni, IEEE80211_NODE_WHC_APINFO_WDS);
                }

                if (whcCaps & QCA_OUI_WHC_AP_INFO_CAP_SON) {
                    ieee80211node_set_whc_apinfo_flag(ni, IEEE80211_NODE_WHC_APINFO_SON);
                    vap->iv_connected_REs++;
                }
            }
#if QCN_IE
            else if(isqcn_oui(frm)) {
                qcn = frm;
            }
#endif
            if (!iswpaoui(frm) && !iswmeinfo(frm)) {
                vendor_ie = frm;
            }

            break;
        }
        frm += frm[1] + 2;
    }

    if (frm > efrm) {
        IEEE80211_DISCARD(vap, IEEE80211_MSG_ELEMID,
                          wh, ieee80211_mgt_subtype_name[subtype >>
                                                         IEEE80211_FC0_SUBTYPE_SHIFT],
                          "%s\n", "reached the end of frame");
        vap->iv_stats.is_rx_badchan++;
        return -EINVAL;
    }

    IEEE80211_VERIFY_ELEMENT(rates, IEEE80211_RATE_MAXSIZE);
    IEEE80211_VERIFY_ELEMENT(ssid, IEEE80211_NWID_LEN);
    IEEE80211_VERIFY_SSID(vap->iv_bss, ssid);

    if(ni->ni_node_esc == true) {
        ni->ni_node_esc = false;
        vap->iv_ic->ic_auth_tx_xretry--;
        IEEE80211_DPRINTF(vap,  IEEE80211_MSG_AUTH, "%s : ni = 0x%p ni->ni_macaddr = %s ic_auth_tx_xretry = %d\n",
                __func__, ni, ether_sprintf(ni->ni_macaddr), vap->iv_ic->ic_auth_tx_xretry);
    }

    if (ni == vap->iv_bss) {
        IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ASSOC, wh->i_addr2,
                           "%s: deny %s request, sta %s not authenticated\n", __func__,
                           reassoc ? "reassoc" : "assoc", ether_sprintf(wh->i_addr2));
        ni = ieee80211_tmp_node(vap,wh->i_addr2);
        if (ni) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH, "%s: sending DEAUTH to %s, reason %d\n",
                    __func__, ether_sprintf(wh->i_addr2), IEEE80211_REASON_ASSOC_NOT_AUTHED);
            ieee80211_send_deauth(ni, IEEE80211_REASON_ASSOC_NOT_AUTHED);
            IEEE80211_DELIVER_EVENT_MLME_DEAUTH_INDICATION(vap, (wh->i_addr2), 0,
                                           IEEE80211_REASON_NOT_AUTHED);

            ieee80211_free_node(ni);
            vap->iv_stats.is_rx_assoc_notauth++;
        }
        return -EBUSY;
    }

    /*
     * Check if assoc req frame is recevied before a valid assoc resp is given
     * if frame is recevied within sending a assoc resp frame, then drop this
     * assoc. As already one more frame in progress.
     */
    if (ic->ic_is_mode_offload(ic)) {
        if (ni->ni_last_assoc_rx_time != 0) {
            systime_t now;
            now = OS_GET_TIMESTAMP();
            if(CONVERT_SYSTEM_TIME_TO_MS(now - ni->ni_last_assoc_rx_time) < 650) {
                IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ASSOC, ni->ni_macaddr,
                        "recv another assoc frame when previous is in progress\n");
                return -EBUSY;
            }
        }
    }


#if ATH_SUPPORT_HS20
    if (xcaps) {
        struct ieee80211_ie_ext_cap *extcaps =
            (struct ieee80211_ie_ext_cap *)xcaps;

        if (extcaps->elem_len > 4 &&
            ((le32toh(extcaps->ext_capflags2)) & IEEE80211_EXTCAPIE_QOS_MAP))
            ni->ni_qosmap_enabled = 1;
        else
            ni->ni_qosmap_enabled = 0;

        /* Copy first word only to node structure, only part used at the moment */
        ni->ni_ext_capabilities = le32toh(extcaps->ext_capflags);
    }
    else {
        /* No extended capabilities present */
        ni->ni_ext_capabilities = 0;
    }
#endif
#if UMAC_SUPPORT_RRM
    if(rrmcap) {
        /* Check if FTMRR (bit34) is enabled in RM capability of this node */
        struct ieee80211_rrm_cap_ie *rrm_caps = (struct ieee80211_rrm_cap_ie *) rrmcap;
        ni->ni_is_rrm_ftmrr = (rrm_caps->ftm_range_report) ? 1 : 0;
    }
#endif

#if ATH_SUPPORT_HS20
    if ((wpa == NULL) && (RSN_AUTH_IS_WPA(&vap->iv_bss->ni_rsn) ||
        RSN_AUTH_IS_RSNA(&vap->iv_bss->ni_rsn)) && !vap->iv_osen) {
#else
    if ((wpa == NULL) && (RSN_AUTH_IS_WPA(&vap->iv_bss->ni_rsn) || RSN_AUTH_IS_RSNA(&vap->iv_bss->ni_rsn))) {
#endif
        if (vap->iv_wps_mode) {

            /* WPS Mode - Node auth mode and cipher setting need to be updated */
            RSN_RESET_AUTHMODE(&ni->ni_rsn);
            RSN_RESET_UCAST_CIPHERS(&ni->ni_rsn);
            RSN_RESET_MCAST_CIPHERS(&ni->ni_rsn);

            RSN_SET_AUTHMODE(&ni->ni_rsn, IEEE80211_AUTH_OPEN);
            if (capinfo & IEEE80211_CAPINFO_PRIVACY) {
                RSN_SET_MCAST_CIPHER(&ni->ni_rsn, IEEE80211_CIPHER_WEP);
                RSN_SET_UCAST_CIPHER(&ni->ni_rsn, IEEE80211_CIPHER_WEP);
            } else {
                RSN_SET_MCAST_CIPHER(&ni->ni_rsn, IEEE80211_CIPHER_NONE);
                RSN_SET_UCAST_CIPHER(&ni->ni_rsn, IEEE80211_CIPHER_NONE);
            }

            IEEE80211_NOTE_MAC(vap,
                               IEEE80211_MSG_ASSOC | IEEE80211_MSG_WPA,
                               wh->i_addr2,
                              "WPS: allow STA with no WPA/RSN IE on in order to do WPS EAPOL, caps 0x%x\n", capinfo);
        } else {
#if ATH_SUPPORT_SPLITMAC
            /*
             * In splitmac mode, driver doesn't send response to STA in any cases(including negative).
             * Send an event up, WLAN controller will make the decision.
             */
            if (vap->iv_splitmac) {
                IEEE80211_DELIVER_EVENT_MLME_DEAUTH_INDICATION(vap, (wh->i_addr2), 0,
                                               IEEE80211_REASON_RSN_REQUIRED);
                vap->iv_stats.is_rx_assoc_badwpaie++;
                return -EINVAL;
            } else
#endif
             {
                /*
                 * When operating with WPA/RSN, there must be
                 * proper security credentials.
                 */
                IEEE80211_NOTE_MAC(vap,
                                   IEEE80211_MSG_ASSOC | IEEE80211_MSG_WPA,
                                   wh->i_addr2,
                                   "deny %s request, no WPA/RSN ie\n",
                                   reassoc ? "reassoc" : "assoc");
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH, "%s: sending DEAUTH to %s, reason %d\n",
                        __func__, ether_sprintf(wh->i_addr2), IEEE80211_REASON_RSN_REQUIRED);
                ieee80211_send_deauth(ni, IEEE80211_REASON_RSN_REQUIRED);
                IEEE80211_DELIVER_EVENT_MLME_DEAUTH_INDICATION(vap, (wh->i_addr2), 0,
                                               IEEE80211_REASON_RSN_REQUIRED);
                IEEE80211_NODE_LEAVE(ni);
                vap->iv_stats.is_rx_assoc_badwpaie++;    /*XXX*/
                return -EINVAL;
             }
        }
    }
    OS_MEMZERO(&rsn, sizeof(struct ieee80211_rsnparms));
    if (wpa != NULL) {
        /*
         * Parse WPA information element.  Note that
         * we initialize the param block from the node
         * state so that information in the IE overrides
         * our defaults.  The resulting parameters are
         * installed below after the association is assured.
         */
        rsn = ni->ni_rsn;
            /*support for WAPI: parse WAPI information element*/
#if ATH_SUPPORT_WAPI
        if (wpa[0] == IEEE80211_ELEMID_WAPI) {
            reason = ieee80211_parse_wapi(vap, wpa, &rsn);
        } else
#endif
        {
            if (wpa[0] != IEEE80211_ELEMID_RSN) {
                reason = ieee80211_parse_wpa(vap, wpa, &rsn);
            } else {
                reason = ieee80211_parse_rsn(vap, wpa, &rsn);
            }
            if ((reason == IEEE80211_STATUS_SUCCESS) &&
                 ((((vap->iv_rsn.rsn_caps & RSN_CAP_MFP_REQUIRED) == RSN_CAP_MFP_REQUIRED) &&
                   ((rsn.rsn_caps & RSN_CAP_MFP_ENABLED) != RSN_CAP_MFP_ENABLED)) ||
                   (((rsn.rsn_caps & RSN_CAP_MFP_REQUIRED) == RSN_CAP_MFP_REQUIRED) &&
                   ((rsn.rsn_caps & RSN_CAP_MFP_ENABLED) != RSN_CAP_MFP_ENABLED)))) {
                reason = IEEE80211_STATUS_MFP_VIOLATION;
            }
        }
        if (reason != 0) {
#if ATH_SUPPORT_SPLITMAC
            /*
             * In splitmac mode, driver doesn't send response to STA in any cases(including negative).
             * Send an event up, WLAN controller will make the decision.
             */
            if (vap->iv_splitmac) {
#if UMAC_SUPPORT_ACFG
                acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                               IEEE80211_REASON_RSN_REQUIRED);
#endif
                vap->iv_stats.is_rx_assoc_badwpaie++;
                return -EINVAL;
            } else
#endif
             {
                ieee80211_send_assocresp(ni, reassoc, reason, NULL);
#if UMAC_SUPPORT_ACFG
                acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                               IEEE80211_REASON_RSN_REQUIRED);
#endif
                IEEE80211_NODE_LEAVE(ni);
                vap->iv_stats.is_rx_assoc_badwpaie++;
                return -EINVAL;
             }
        }

        /*
         * Conditionally determine whether to check for WAPI or not.
         * This can't be done inside the call to IEEE80211_NOTE_MAC,
         * because IEEE80211_NOTE_MAC is itself a macro.
         * (Well, technically it could, as long as the conditional
         * compilation part were carefully done within a single
         * macro argument.)
         */
        #if ATH_SUPPORT_WAPI
        #define LOCAL_ELEMID_TYPE_CHECK \
            wpa[0] != IEEE80211_ELEMID_WAPI ?  "WPA or RSN" : "WAPI"
        #else
        #define LOCAL_ELEMID_TYPE_CHECK \
            wpa[0] != IEEE80211_ELEMID_RSN ?  "WPA" : "RSN"
        #endif
        IEEE80211_NOTE_MAC(vap,
                           IEEE80211_MSG_ASSOC | IEEE80211_MSG_WPA,
                           wh->i_addr2,
                           "%s ie: mc %u/%u uc %u/%u key %u caps 0x%x\n",
                           LOCAL_ELEMID_TYPE_CHECK,
                           rsn.rsn_mcastcipherset, rsn.rsn_mcastkeylen,
                           rsn.rsn_ucastcipherset, rsn.rsn_ucastkeylen,
                           rsn.rsn_keymgmtset, rsn.rsn_caps);
        #undef LOCAL_ELEMID_TYPE_CHECK
    }
    /* discard challenge after association */
    if (ni->ni_challenge != NULL) {
        OS_FREE(ni->ni_challenge);
        ni->ni_challenge = NULL;
    }
    /* 802.11 spec says to ignore station's privacy bit */
    if ((capinfo & IEEE80211_CAPINFO_ESS) == 0) {
#if ATH_SUPPORT_SPLITMAC
        /*
         * In splitmac mode, driver doesn't send response to STA in any cases(including negative).
         * Send an event up, WLAN controller will make the decision.
         */
        if (vap->iv_splitmac) {
#if UMAC_SUPPORT_ACFG
            acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                               ACFG_REASON_ASSOC_CAP_MISMATCH);
#endif
            vap->iv_stats.is_rx_assoc_capmismatch++;
            return -EINVAL;
        } else
#endif
        {
            IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ANY, wh->i_addr2,
                               "deny %s request, capability mismatch 0x%x",
                               reassoc ? "reassoc" : "assoc", capinfo);
            ieee80211_send_assocresp(ni,reassoc,IEEE80211_STATUS_CAPINFO,NULL);
#if UMAC_SUPPORT_ACFG
            acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                               ACFG_REASON_ASSOC_CAP_MISMATCH);
#endif
            IEEE80211_NODE_LEAVE(ni);
            vap->iv_stats.is_rx_assoc_capmismatch++;
            return -EINVAL;
        }
    }

    if ( !ieee80211_setup_rates(ni, rates, xrates,
                    IEEE80211_F_DOSORT | IEEE80211_F_DOFRATE |
                    IEEE80211_F_DOXSECT | IEEE80211_F_DOBRS) ||
        (IEEE80211_VAP_IS_PUREG_ENABLED(vap) &&
          (ni->ni_rates.rs_rates[ni->ni_rates.rs_nrates-1] & IEEE80211_RATE_VAL) < 48)) {
#if ATH_SUPPORT_SPLITMAC
        /*
         * In splitmac mode, driver doesn't send response to STA in any cases(including negative).
         * Send an event up, WLAN controller will make the decision.
         */
        if (vap->iv_splitmac) {
#if UMAC_SUPPORT_ACFG
            acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                               ACFG_REASON_ASSOC_RATE_MISMATCH);
#endif
            vap->iv_stats.is_rx_assoc_norate++;
            return -EINVAL;
        } else
#endif
        {
            IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ANY, wh->i_addr2,
                               "deny %s request, rate set mismatch",
                               reassoc ? "reassoc" : "assoc");
            ieee80211_send_assocresp(ni,reassoc,IEEE80211_STATUS_BASIC_RATE,NULL);
#if UMAC_SUPPORT_ACFG
            acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                               ACFG_REASON_ASSOC_RATE_MISMATCH);
#endif
            IEEE80211_NODE_LEAVE(ni);
            vap->iv_stats.is_rx_assoc_norate++;
            return -EINVAL;
        }
    }

    if (ni->ni_associd != 0 &&
        IEEE80211_IS_CHAN_ANYG(vap->iv_bsschan)) {
        if ((ni->ni_capinfo & IEEE80211_CAPINFO_SHORT_SLOTTIME)
            != (capinfo & IEEE80211_CAPINFO_SHORT_SLOTTIME))
        {
#if ATH_SUPPORT_SPLITMAC
            /*
             * In splitmac mode, driver doesn't send response to STA in any cases(including negative).
             * Send an event up, WLAN controller will make the decision.
             */
            if (vap->iv_splitmac) {
#if UMAC_SUPPORT_ACFG
                acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                               ACFG_REASON_ASSOC_CAP_MISMATCH);
#endif
                vap->iv_stats.is_rx_assoc_capmismatch++;
                return -EINVAL;
            } else
#endif
            {
                IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ANY,
                                   wh->i_addr2, "deny %s request, short slot time\
                    capability mismatch 0x%x", reassoc ? "reassoc"
                                   : "assoc", capinfo);
                ieee80211_send_assocresp(ni,reassoc,IEEE80211_STATUS_CAPINFO,NULL);
#if UMAC_SUPPORT_ACFG
                acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                               ACFG_REASON_ASSOC_CAP_MISMATCH);
#endif
                IEEE80211_NODE_LEAVE(ni);
                vap->iv_stats.is_rx_assoc_capmismatch++;
                return -EINVAL;
            }
        }
    }
    LIMIT_BEACON_PERIOD(bintval);
    ni->ni_intval = bintval;
    ni->ni_capinfo = capinfo;
    ni->ni_chan = ic->ic_curchan;
    if (wpa != NULL) {
        /*
         * Record WPA/RSN parameters for station, mark
         * node as using WPA and record information element
         * for applications that require it.
         */
        ni->ni_rsn = rsn;
        ieee80211_saveie(ic->ic_osdev,&ni->ni_wpa_ie, wpa);
    } else if (ni->ni_wpa_ie != NULL) {
        /*
         * Flush any state from a previous association.
         */
        OS_FREE(ni->ni_wpa_ie);
        ni->ni_wpa_ie = NULL;
    }

    if (wps != NULL) {
        /*
         * Record WPS parameters for station, mark
         * node as using WPS and record information element
         * for applications that require it.
         */
        ieee80211_saveie(ic->ic_osdev, &ni->ni_wps_ie, wps);
    } else if (ni->ni_wps_ie != NULL) {
        /*
         * Flush any state from a previous association.
         */
        OS_FREE(ni->ni_wps_ie);
        ni->ni_wps_ie = NULL;
    }
#if UMAC_SUPPORT_WNM
    if (ieee80211_vap_wnm_is_set(vap) && timbcast) {
        int status;

        status = ieee80211_parse_timreq_ie(timbcast,
                    timbcast + timbcast[1] + 2, ni);
        if (status == 0) {
            ieee80211_saveie(ic->ic_osdev, &ni->ni_wnm->timbcast_ie, timbcast);
        }

    } else if (ni->ni_wnm->timbcast_ie != NULL) {
        /*
         * Flush any state from a previous association.
         */
        ni->ni_wnm->timbcast_status = IEEE80211_WNM_TIMREQUEST_DENIED;
        OS_FREE(ni->ni_wnm->timbcast_ie);
        ni->ni_wnm->timbcast_ie = NULL;
    }
#endif
    if (ath != NULL) {
        /*
         * Record ATH parameters for station, mark
         * node as using ATH and record information element
         * for applications that require it.
         */
        ieee80211_saveie(ic->ic_osdev, &ni->ni_ath_ie, ath);
    } else if (ni->ni_ath_ie != NULL) {
        /*
         * Flush any state from a previous association.
         */
        OS_FREE(ni->ni_ath_ie);
        ni->ni_ath_ie = NULL;
    }
    if (mbo != NULL) {
        /*
         * Record MBO parameters for station, mark
         * node as using MBO and record information element
         * for applications that require it.
         */
        ieee80211_saveie(ic->ic_osdev, &ni->ni_mbo_ie, mbo);
        ieee80211_parse_mboie(mbo, ni);
    } else if (ni->ni_mbo_ie != NULL) {
        /*
         * Flush any state from a previous association.
         */
        OS_FREE(ni->ni_mbo_ie);
        ni->ni_mbo_ie = NULL;
    }
#if QCN_IE
    if (qcn != NULL) {
        /*
         * Record qcn parameters for station, mark
         * node as using qcn and record information element
         * for applications that require it.
         */
        ieee80211_saveie(ic->ic_osdev, &ni->ni_qcn_ie, qcn);
        ieee80211_parse_qcnie(qcn, wh, ni,NULL);
    } else if (ni->ni_qcn_ie != NULL) {
        /*
         * Flush any state from a previous association.
         */
        OS_FREE(ni->ni_qcn_ie);
        ni->ni_qcn_ie = NULL;
    }
#endif
    if (supp_op_cl != NULL) {
        /*
         * Record operating classes supported by the STA
         * so that we don't steer the STA towards a channel
         * not supported by it
         */
        ic->ic_get_currentCountry(ic, &country);
        ieee80211_saveie(ic->ic_osdev, &ni->ni_supp_op_class_ie, supp_op_cl);
        ieee80211_parse_op_class_ie(supp_op_cl, wh, ni, country.countryCode);
        ni->ni_operating_bands = regdmn_get_band_cap_from_op_class(vap->iv_ic,
                ni->ni_supp_op_cl.num_of_supp_class, ni->ni_supp_op_cl.supp_class);
     }
     else if (ni->ni_supp_op_class_ie != NULL) {
        /*
         * Flush any state from a pre vious association.
         */
        OS_FREE(ni->ni_supp_op_class_ie);
        ni->ni_supp_op_class_ie = NULL;
    }

    if (wme != NULL) {
        /*
         * Record WME parameters for station, mark
         * node as using WME and record information element
         * for applications that require it.
         */
        ieee80211_saveie(ic->ic_osdev, &ni->ni_wme_ie, wme);
    } else if (ni->ni_wme_ie != NULL) {
        /*
         * Flush any state from a previous association.
         */
        OS_FREE(ni->ni_wme_ie);
        ni->ni_wme_ie = NULL;
    }

    if ((wme != NULL) && ieee80211_parse_wmeie(wme, wh, ni) > 0) {
        ieee80211node_set_flag(ni, IEEE80211_NODE_QOS);
    } else {
        ieee80211node_clear_flag(ni, IEEE80211_NODE_QOS);
    }

    /*
     * if doing pure 802.11n mode, don't
     * accept stas who don't have HT caps.
     */
    if (IEEE80211_VAP_IS_PURE11N_ENABLED(vap) && (htcap == NULL)) {
#if ATH_SUPPORT_SPLITMAC
        /*
         * In splitmac mode, driver doesn't send response to STA in any cases(including negative).
         * Send an event up, WLAN controller will make the decision.
         */
        if (vap->iv_splitmac) {
#if UMAC_SUPPORT_ACFG
            acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                               ACFG_REASON_ASSOC_PUREN_NOHT);
#endif
            return -EINVAL;
        } else
#endif
        {
            IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ANY, wh->i_addr2,
                               "deny %s request, no ht caps in pure 802.11n mode",
                               reassoc ? "reassoc" : "assoc");
            ieee80211_send_assocresp(ni, reassoc, IEEE80211_STATUS_NO_HT,NULL);
#if UMAC_SUPPORT_ACFG
            acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                               ACFG_REASON_ASSOC_PUREN_NOHT);
#endif
            IEEE80211_NODE_LEAVE(ni);
            return -EINVAL;
        }
    }

    /*
     * if doing pure 802.11ac mode, don't
     * accept STAs without VHT capabilities.
     */
    if ((ieee80211vap_vhtallowed(vap)) &&
        IEEE80211_VAP_IS_PURE11AC_ENABLED(vap) && (vhtcap == NULL)) {
#if ATH_SUPPORT_SPLITMAC
        /*
         * In splitmac mode, driver doesn't send response to STA in any cases(including negative).
         * Send an event up, WLAN controller will make the decision.
         */
        if (vap->iv_splitmac) {
#if UMAC_SUPPORT_ACFG
            acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                               ACFG_REASON_ASSOC_PUREAC_NOVHT);
#endif
            return -EINVAL;
        } else
#endif
        {
            IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ANY, wh->i_addr2,
                               "deny %s request, no vht caps in pure 802.11ac mode",
                               reassoc ? "reassoc" : "assoc");
            ieee80211_send_assocresp(ni, reassoc, IEEE80211_STATUS_NO_VHT,NULL);
#if UMAC_SUPPORT_ACFG
            acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                               ACFG_REASON_ASSOC_PUREAC_NOVHT);
#endif
            IEEE80211_NODE_LEAVE(ni);
            return -EINVAL;
        }
    }

    if (IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan)) {
        ni->ni_phymode = IEEE80211_MODE_11A;
    }else if(ieee80211_node_has_11g_rate(ni) &&
            IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11G)){
        /*if 11g rate exists, use 11G mode*/
        ni->ni_phymode = IEEE80211_MODE_11G;
    }else{
        ni->ni_phymode = IEEE80211_MODE_11B;
    }

    /*
     * Channel width and Nss will get adjusted with HT parse and VHT parse
     * if those modes are enabled
     */
    ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
    ni->ni_streams = 1;
    /* 11ac or 11n and ht allowed for this vap */
    if ((IEEE80211_IS_CHAN_11AC(ic->ic_curchan) ||
        IEEE80211_IS_CHAN_11N(ic->ic_curchan)) &&
        ieee80211vap_htallowed(vap)) {
        /* For AP in mixed mode, ignore the htcap from remote node,
         * if ht rate is not allowed in TKIP.
         */
        if (!ieee80211_ic_wep_tkip_htrate_is_set(ic)  &&
            RSN_CIPHER_IS_TKIP(&ni->ni_rsn))
        {
            htcap = NULL;
        }
        if (htcap != NULL) {
	    if (ieee80211_ht_nss_mcs_valid(ni,htcap) < 0) {
		qdf_print("****** FW configured HT rate control params(iwpriv setrcparams) and STA Rx MCS dont match \n");
		return -EINVAL;
	    }
            /* record capabilities, mark node as capable of HT */
            if (!ieee80211_parse_htcap(ni, htcap)) {
#if ATH_SUPPORT_SPLITMAC
                /*
                 * In splitmac mode, driver doesn't send response to STA in any cases(including negative).
                 * Send an event up, WLAN controller will make the decision.
                 */
                if (vap->iv_splitmac) {
#if UMAC_SUPPORT_ACFG
                    acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                               ACFG_REASON_ASSOC_RATE_MISMATCH);
#endif
                    vap->iv_stats.is_rx_assoc_norate++;
                    return -EINVAL;
                } else
#endif
                {
                    IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ANY, wh->i_addr2,
                                       "deny %s request, Rx MCS set mismatch",
                                        reassoc ? "reassoc" : "assoc");
                    ieee80211_send_assocresp(ni, reassoc, IEEE80211_STATUS_BASIC_RATE,NULL);
#if UMAC_SUPPORT_ACFG
                    acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                               ACFG_REASON_ASSOC_RATE_MISMATCH);
#endif
                    IEEE80211_NODE_LEAVE(ni);
                    vap->iv_stats.is_rx_assoc_norate++;
                    return -EINVAL;
                }
            }
            if((ni->ni_htcap & IEEE80211_HTCAP_C_ADVCODING) && (vhtcap == NULL)
                    && IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan) && ic->ic_is_mode_offload(ic)) {
                ni->ni_htcap &= ~IEEE80211_HTCAP_C_ADVCODING;
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "%s Disabling LDPC for better performance\n",__func__);
            }
#ifdef ATH_SUPPORT_TxBF
            ieee80211_init_txbf(ic, ni);
#endif
        } else {
            /*
             * Flush any state from a previous association.
             */
            ni->ni_flags &= ~IEEE80211_NODE_HT;
            ni->ni_htcap = 0;
        }
        if (!ieee80211_setup_ht_rates(ni, htcap,
                                      IEEE80211_F_DOFRATE | IEEE80211_F_DOXSECT | IEEE80211_F_DOBRS)) {
#if ATH_SUPPORT_SPLITMAC
            /*
             * In splitmac mode, driver doesn't send response to STA in any cases(including negative).
             * Send an event up, WLAN controller will make the decision.
             */
            if (vap->iv_splitmac) {
#if UMAC_SUPPORT_ACFG
                acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                                            ACFG_REASON_ASSOC_RATE_MISMATCH);
#endif
                vap->iv_stats.is_rx_assoc_norate++;
                return -EINVAL;
            } else
#endif
            {
                IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ANY, wh->i_addr2,
                                   "deny %s request, ht rate set mismatch",
                                    reassoc ? "reassoc" : "assoc");
                ieee80211_send_assocresp(ni, reassoc, IEEE80211_STATUS_BASIC_RATE,NULL);
#if UMAC_SUPPORT_ACFG
                acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                                            ACFG_REASON_ASSOC_RATE_MISMATCH);
#endif
                IEEE80211_NODE_LEAVE(ni);
                vap->iv_stats.is_rx_assoc_norate++;
                return -EINVAL;
            }
        }

        if ((ni->ni_flags & IEEE80211_NODE_HT) &&
                    ((ni->ni_htrates.rs_nrates < ADD_NI_RATES_NUM) ||
                     OS_MEMCMP(temp_ni_rates, ni->ni_htrates.rs_rates, ADD_NI_RATES_NUM ))) {

            u_int8_t *p = (u_int8_t *) &ni->ni_htrates.rs_rates[ADD_NI_RATES_NUM];
            u_int8_t i = 0,j=0;
            u_int8_t rs_nrates = ni->ni_htrates.rs_nrates;
            u_int8_t temp_rs_rates[IEEE80211_RATE_MAXSIZE];

            IEEE80211_NOTE_MAC(vap,
                               IEEE80211_MSG_ASSOC,
                               wh->i_addr2,
                               "Node is marked HT - but RX MCS 0-7 not supported, Number of Rates supported %d",
                               ni->ni_htrates.rs_nrates);

            /* Re-initialize ni->ni_htrates.rs_rates[] adding MCS:0-7 & appending existing rates */
            OS_MEMCPY(temp_rs_rates, ni->ni_htrates.rs_rates, ni->ni_htrates.rs_nrates);
            OS_MEMZERO(ni->ni_htrates.rs_rates, ni->ni_htrates.rs_nrates);
            if(vap->iv_disable_htmcs) {
                for (i = 0; i < ADD_NI_RATES_NUM; i++) {
                    /* if any mcs between 0 - 7 is not disabled, then add it */
                    if(!(vap->iv_disabled_ht_mcsset[0] & (1<<i))) {
                        ni->ni_htrates.rs_rates[j++] = i;
                    }
                }
                ni->ni_htrates.rs_nrates = j;
                p =  &ni->ni_htrates.rs_rates[j];
            } else {
               OS_MEMCPY(ni->ni_htrates.rs_rates, temp_ni_rates, ADD_NI_RATES_NUM); /* Fill MCS 0-7 */
               ni->ni_htrates.rs_nrates = ADD_NI_RATES_NUM;
            }
            /* Add any other MCS (other than 0-7), if supported */
            for (i = 0; i < rs_nrates; i++) {
                if (temp_rs_rates[i] >=  ADD_NI_RATES_NUM) {
                    *p++ = temp_rs_rates[i];
                    ni->ni_htrates.rs_nrates++;
                }
            }
        } /* Add MCS 0-7 if not present */

    }
      /* Add vht cap for 2.4G mode, if 256QAM is enabled */

    if ((IEEE80211_IS_CHAN_11AC(ic->ic_curchan) || (IEEE80211_IS_CHAN_11NG(ic->ic_curchan))) &&
                           ieee80211vap_vhtallowed(vap)) {

        if(bwnss_oui != NULL){
            /*Bandwidth-NSS map has sub-type & version. hence copy data after version */
            ni->ni_bwnss_map = IEEE80211_BW_NSS_FWCONF_160(*(bwnss_oui+8));
        } else {
            ni->ni_bwnss_map = 0;
        }

        if (vhtcap != NULL) {
	    if(ieee80211_vht_nss_mcs_valid(ni,vhtcap) < 0){
		qdf_print("********** FW VHT rate control paramters(iwpriv setrcparams) and STA rx mcs dont match\n");
		return -EINVAL;
	    }
            /* Disallow TKIP with VHT  Section 11.5.3 of the P802.11ac/D5.0 */
            if (RSN_CIPHER_IS_TKIP(&ni->ni_rsn)) {
#if ATH_SUPPORT_SPLITMAC
                /*
                 * In splitmac mode, driver doesn't send response to STA in any cases(including negative).
                 * Send an event up, WLAN controller will make the decision.
                 */
                if (vap->iv_splitmac) {
#if UMAC_SUPPORT_ACFG
                    acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                                            ACFG_REASON_ASSOC_11AC_TKIP_USED);
#endif
                    vap->iv_stats.is_rx_assoc_norate++;
                    return -EINVAL;
                } else
#endif
                {
                    IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ANY, wh->i_addr2,
                                   "deny %s request, vht rate set mismatch",
                                    reassoc ? "reassoc" : "assoc");
                    ieee80211_send_assocresp(ni,reassoc,IEEE80211_STATUS_BASIC_RATE,NULL);
#if UMAC_SUPPORT_ACFG
                    acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                                            ACFG_REASON_ASSOC_11AC_TKIP_USED);
#endif
                    IEEE80211_NODE_LEAVE(ni);
                    vap->iv_stats.is_rx_assoc_norate++;
                    return -EINVAL;
                }
            }

            /* record capabilities, mark node as capable of VHT */
            if(ieee80211_check_mu_client_cap(ni,vhtcap))
            {
                if(!dedicated_client)
                {
                    /*It is not dedicated client*/
                   ni->ni_mu_dedicated =0;
                }else{
                    /*This dedicated client */
                   ni->ni_mu_dedicated =1;
                }
            }
            ieee80211_parse_vhtcap(ni, vhtcap);

            if (vap->iv_ext_nss_capable && ni->ni_ext_nss_support &&
                    !validate_extnss_vhtcap(&ni->ni_vhtcap)) {
#if ATH_SUPPORT_SPLITMAC
                /*
                 * In splitmac mode, driver doesn't send response to STA in any cases(including negative).
                 * Send an event up, WLAN controller will make the decision.
                 */
                if (vap->iv_splitmac) {
#if UMAC_SUPPORT_ACFG
                    acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                                            ACFG_REASON_ASSOC_CAP_MISMATCH);
#endif
                    vap->iv_stats.is_rx_assoc_capmismatch++;
                    return -EINVAL;
                } else
#endif
                {
                    IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ANY, wh->i_addr2,
                                   "deny %s request, Invalid supported ch width and ext nss combination",
                                    reassoc ? "reassoc" : "assoc");
                    ieee80211_send_assocresp(ni, reassoc, IEEE80211_STATUS_BASIC_RATE,NULL);
#if UMAC_SUPPORT_ACFG
                    acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                                            ACFG_REASON_ASSOC_CAP_MISMATCH);
#endif
                    IEEE80211_NODE_LEAVE(ni);
                    vap->iv_stats.is_rx_assoc_capmismatch++;
                    return -EINVAL;
                }
            }

            if (!ieee80211_setup_vht_rates(ni, vhtcap,
                                      IEEE80211_F_DOFRATE | IEEE80211_F_DOXSECT | IEEE80211_F_DOBRS)) {
#if ATH_SUPPORT_SPLITMAC
                /*
                 * In splitmac mode, driver doesn't send response to STA in any cases(including negative).
                 * Send an event up, WLAN controller will make the decision.
                 */
                if (vap->iv_splitmac) {
#if UMAC_SUPPORT_ACFG
                    acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                                            ACFG_REASON_ASSOC_RATE_MISMATCH);
#endif
                    vap->iv_stats.is_rx_assoc_norate++;
                    return -EINVAL;
                } else
#endif
                {
                    IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ANY, wh->i_addr2,
                                   "deny %s request, vht rate set mismatch",
                                    reassoc ? "reassoc" : "assoc");
                    ieee80211_send_assocresp(ni, reassoc, IEEE80211_STATUS_BASIC_RATE,NULL);
#if UMAC_SUPPORT_ACFG
                    acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                                            ACFG_REASON_ASSOC_RATE_MISMATCH);
#endif
                    IEEE80211_NODE_LEAVE(ni);
                    vap->iv_stats.is_rx_assoc_norate++;
                    return -EINVAL;
                }
            }
        } else {
            /*
             * Flush any state from a previous association.
             */
            ni->ni_flags &= ~IEEE80211_NODE_VHT;
            ni->ni_vhtcap = 0;
        }

        /* Op mode Notification element can be present is assoc/reassoc request as well */
        if ((opmode != NULL) && (ni->ni_flags & IEEE80211_NODE_VHT)) {
            ieee80211_parse_opmode_notify(ni, opmode, subtype);
        }

    }

    if((IEEE80211_VAP_IS_STRICT_BW_ENABLED(vap)) &&
        ((IEEE80211_VAP_IS_PURE11AC_ENABLED(vap) && ieee80211vap_vhtallowed(vap)) ||
         (IEEE80211_VAP_IS_PURE11N_ENABLED(vap) && !ieee80211vap_vhtallowed(vap)))) {
        enum ieee80211_cwm_width ic_cw_width = ic->ic_cwm_get_width(ic);
        u_int8_t chwidth = 0;

        /* Get the current chwidth */
        if (vap->iv_chwidth != IEEE80211_CWM_WIDTHINVALID) {
            chwidth = vap->iv_chwidth;
        } else {
            chwidth = ic_cw_width;
        }
        if(ni->ni_chwidth != chwidth) {
#if ATH_SUPPORT_SPLITMAC
            /*
             * In splitmac mode, driver doesn't send response to STA in any cases(including negative).
             * Send an event up, WLAN controller will make the decision.
             */
            if (vap->iv_splitmac) {
#if UMAC_SUPPORT_ACFG
                acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                             ACFG_REASON_ASSOC_CHANWIDTH_MISMATCH);
#endif
                return -EINVAL;
            } else
#endif
            {
                IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ANY, wh->i_addr2,
                        "deny %s request, station bw doesnt match",
                        reassoc ? "reassoc" : "assoc");
                ieee80211_send_assocresp(ni, reassoc,
                                    IEEE80211_STATUS_UNSPECIFIED,NULL);
#if UMAC_SUPPORT_ACFG
                acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                              ACFG_REASON_ASSOC_CHANWIDTH_MISMATCH);
#endif
                IEEE80211_NODE_LEAVE(ni);
                return -EINVAL;
            }
        }
    }
    ni->ni_maxrate_legacy = ni->ni_rates.rs_nrates;
    ni->ni_maxrate_ht = ni->ni_htrates.rs_nrates;
    ni->ni_maxrate_vht = 0xff; /* use all valid vht rates */
    /* Update the PHY mode */
    ieee80211_update_ht_vht_phymode(ic, ni);

    if (athextcap != NULL) {
        ieee80211_process_athextcap_ie(ni, athextcap);
    }

#if ATH_BAND_STEERING
    if (pwrcap) {
        ieee80211_process_pwrcap_ie(ni, pwrcap);
    }
#endif

    ieee80211node_clear_whc_rept_info(ni);
    if (whc_rept_info != NULL) {
        ieee80211_process_whc_rept_info_ie(ni, whc_rept_info);
    }

#if ATH_SUPPORT_SPLITMAC
    /*
     * Don't pass to mlme layer, if splitmac is enabled.
     */
    if (vap->iv_splitmac) {
        IEEE80211_NODE_STATE_LOCK(ni);
        ni->splitmac_state = IEEE80211_SPLITMAC_IN_ASSOC_REQ;
        IEEE80211_NODE_STATE_UNLOCK(ni);
        return 0;
	}
#endif

    if (ic->ic_is_mode_offload(ic)) {
        ni->ni_last_assoc_rx_time = OS_GET_TIMESTAMP();
    }
    ieee80211_mlme_recv_assoc_request(ni, reassoc,vendor_ie, wbuf);

    return 0;
}

/*
 * Send a assoc resp frame
 */
int
ieee80211_send_assocresp(struct ieee80211_node *ni, u_int8_t reassoc, u_int16_t reason,
                         struct ieee80211_app_ie_t* optie)
{
    struct ieee80211vap *vap = ni->ni_vap;
    wbuf_t wbuf;

    wbuf = ieee80211_setup_assocresp(ni, NULL, reassoc, reason, optie);
    if (!wbuf)
        return ENOMEM;

#if UMAC_SUPPORT_FILS
    /* Encrypt the packet using FILS Key */
    if(IEEE80211_VAP_IS_FILS_ENABLED(vap) && ni->ni_fils_aead_set &&
       (ni->ni_authalg == IEEE80211_AUTH_ALG_FILS_SK ||
        ni->ni_authalg == IEEE80211_AUTH_ALG_FILS_SK_PFS ||
        ni->ni_authalg == IEEE80211_AUTH_ALG_FILS_PK)) {
        struct ieee80211_key *k = NULL;

        wbuf_set_node(wbuf, ieee80211_ref_node(ni));
        k = ieee80211_crypto_encap(ni, wbuf);
        ieee80211_free_node(ni);
        ni->ni_fils_aead_set = 0;
        ieee80211_crypto_freekey(vap, &ni->ni_ucastkey);
        if (k == NULL) {
            qdf_print("%s FILS Encryption Failed \n",__func__);
            qdf_nbuf_free(wbuf);
            return EINVAL;
        }
    }
#endif

    return ieee80211_send_mgmt(vap,ni, wbuf,false);
}

/* Determine whether (re)association response needs modification towards 160 MHz
 * width association WAR.
 */
static bool
is_assocwar160_reqd_assocresp(struct ieee80211vap *vap,
        struct ieee80211_node *ni)
{
    int is_sta_any160cap = 0;

    qdf_assert_always(vap != NULL);
    qdf_assert_always(ni != NULL);

    if (((vap->iv_cur_mode != IEEE80211_MODE_11AC_VHT160) &&
                (vap->iv_cur_mode != IEEE80211_MODE_11AC_VHT80_80)) ||
        !vap->iv_cfg_assoc_war_160w) {
        return false;
    }

    /* The WAR is required only for STAs not having any 160/80+80 MHz
     * capability. */

    if (!(ni->ni_flags & IEEE80211_NODE_VHT))
     {
         return true;
     }

    is_sta_any160cap =
        ((ni->ni_vhtcap &
            (IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160 |
             IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160 |
             IEEE80211_VHTCAP_SHORTGI_160)) != 0);

    if (is_sta_any160cap) {
        return false;
    }

    return true;
}

/*
 * Setup assoc resp frame
 */
wbuf_t
ieee80211_setup_assocresp(struct ieee80211_node *ni, wbuf_t wbuf, u_int8_t reassoc, u_int16_t reason,
                          struct ieee80211_app_ie_t* optie)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211_frame *wh;
    u_int8_t *frm;
    u_int8_t *mbo_status_change;
    u_int16_t capinfo;
    int enable_htrates;
    struct ieee80211_bwnss_map nssmap;
    u_int8_t rx_chainmask = ieee80211com_get_rx_chainmask(ic);
    struct ieee80211_framing_extractx extractx;
#if QCN_IE
    u_int16_t ie_len;
#endif

    qdf_mem_zero(&nssmap, sizeof(nssmap));
    qdf_mem_zero(&extractx, sizeof(extractx));

    if (!wbuf) {
        wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);
        if (!wbuf)
            return NULL;
    }

    /* setup the wireless header */
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    ieee80211_send_setup(vap, ni, wh,
                         IEEE80211_FC0_TYPE_MGT |
                         (reassoc ? IEEE80211_FC0_SUBTYPE_REASSOC_RESP : IEEE80211_FC0_SUBTYPE_ASSOC_RESP),
                         vap->iv_myaddr, ni->ni_macaddr, ni->ni_bssid);

    frm = (u_int8_t *)&wh[1];

    capinfo = IEEE80211_CAPINFO_ESS;
    if (IEEE80211_VAP_IS_PRIVACY_ENABLED(vap))
        capinfo |= IEEE80211_CAPINFO_PRIVACY;
    if ((ic->ic_flags & IEEE80211_F_SHPREAMBLE) &&
        IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan))
        capinfo |= IEEE80211_CAPINFO_SHORT_PREAMBLE;
    if (ic->ic_flags & IEEE80211_F_SHSLOT)
        capinfo |= IEEE80211_CAPINFO_SHORT_SLOTTIME;
    /* set rrm capbabilities, if supported */
    if (ieee80211_vap_rrm_is_set(vap)) {
        capinfo |= IEEE80211_CAPINFO_RADIOMEAS;
    }
    if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap))
        capinfo |= IEEE80211_CAPINFO_SPECTRUM_MGMT;

    *(u_int16_t *)frm = htole16(capinfo);
    frm += 2;

    *(u_int16_t *)frm = htole16(reason);
    mbo_status_change = frm;
    frm += 2;

    if (reason == IEEE80211_STATUS_SUCCESS) {
        *(u_int16_t *)frm = htole16(ni->ni_associd);
        IEEE80211_NODE_STAT(ni, tx_assoc);
    } else {
        IEEE80211_NODE_STAT(ni, tx_assoc_fail);
    }
    frm += 2;

    if (reason != IEEE80211_STATUS_SUCCESS) {
        frm = ieee80211_add_rates(frm, &vap->iv_bss->ni_rates);
        frm = ieee80211_add_xrates(frm, &vap->iv_bss->ni_rates);
    } else {
        frm = ieee80211_add_rates(frm, &ni->ni_rates);
        frm = ieee80211_add_xrates(frm, &ni->ni_rates);
    }

    /* Add rrm capbabilities, if supported */
    frm = ieee80211_add_rrm_cap_ie(frm, ni);

    /* XXX ht caps */
    /* enable htrate if ht allowed for this vap and remote node is ht capbable */
    enable_htrates = (ieee80211vap_htallowed(vap) && (ni->ni_flags & IEEE80211_NODE_HT));
    if (ieee80211_vap_wme_is_set(vap) &&
        (IEEE80211_IS_CHAN_11AC(ic->ic_curchan) || IEEE80211_IS_CHAN_11N(ic->ic_curchan)) &&
        enable_htrates) {
        frm = ieee80211_add_htcap(frm, ni, IEEE80211_FC0_SUBTYPE_ASSOC_RESP);
        frm = ieee80211_add_htinfo(frm, ni);

        if (!(ic->ic_flags & IEEE80211_F_COEXT_DISABLE)) {
            frm = ieee80211_add_obss_scan(frm, ni);
        }
    }

    /* Add extended capbabilities, if applicable */
    frm = ieee80211_add_extcap(frm, ni);

#if UMAC_SUPPORT_WNM
    if(ieee80211_vap_wnm_is_set(vap) && (vap->wnm) && (ieee80211_wnm_bss_is_set(vap->wnm))) {
        frm = ieee80211_add_bssmax(frm, vap);
    }
#endif
#if ATH_SUPPORT_HS20
    frm = ieee80211_add_qosmapset(frm, ni);
#endif
    if (ieee80211_vap_wme_is_set(vap) &&
        ni->ni_flags & IEEE80211_NODE_VHT &&
        (IEEE80211_IS_CHAN_11AC(ic->ic_curchan) || IEEE80211_IS_CHAN_11NG(ic->ic_curchan)) &&
        ieee80211vap_vhtallowed(vap)) {

        extractx.fectx_assocwar160_reqd = is_assocwar160_reqd_assocresp(vap, ni);
        extractx.fectx_nstscapwar_reqd  = ((vap->iv_cfg_nstscap_war > 0) ? 1:0);

        if (extractx.fectx_assocwar160_reqd == true) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                              "%s: Applying 160MHz assoc WAR: (re)assoc resp "
                              "to STA %s\n",
                              __func__, ether_sprintf(ni->ni_macaddr));
        }

        /* Add VHT capabilities IE */
        if (ASSOCWAR160_IS_VHT_CAP_CHANGE(vap->iv_cfg_assoc_war_160w) ||
                NSTSWAR_IS_VHTCAP_CHANGE(vap->iv_cfg_nstscap_war) )
            frm = ieee80211_add_vhtcap(frm, ni, ic,
                    IEEE80211_FC0_SUBTYPE_ASSOC_RESP, &extractx, NULL);
        else
            frm = ieee80211_add_vhtcap(frm, ni, ic,
                    IEEE80211_FC0_SUBTYPE_ASSOC_RESP, NULL, NULL);

        /* Add VHT Operation IE */
        frm = ieee80211_add_vhtop(frm, ni, ic, IEEE80211_FC0_SUBTYPE_ASSOC_RESP, &extractx);
    }

    if (ieee80211_vap_wme_is_set(vap) &&
       (ni->ni_flags & IEEE80211_NODE_11NG_VHT_INTEROP_AMSDU_DISABLE) && IEEE80211_IS_CHAN_11NG(ic->ic_curchan) &&
        ieee80211vap_vhtallowed(vap) && ieee80211vap_11ng_vht_interopallowed(vap)) {

        /* Add VHT interop capabilities IE with Vht cap and Vht Op IE*/
        frm = ieee80211_add_interop_vhtcap(frm, ni, ic, IEEE80211_FC0_SUBTYPE_ASSOC_RESP);

    }

    if (ieee80211_vap_wme_is_set(vap) && ieee80211node_has_flag(ni,IEEE80211_NODE_QOS))
        frm = ieee80211_add_wme_param(frm, &vap->iv_wmestate, IEEE80211_VAP_IS_UAPSD_ENABLED(vap));

    if (ieee80211_vap_wme_is_set(vap) &&
        (IEEE80211_IS_CHAN_11AC(ic->ic_curchan) || IEEE80211_IS_CHAN_11N(ic->ic_curchan)) &&
        (IEEE80211_IS_HTVIE_ENABLED(ic)) && enable_htrates) {
        frm = ieee80211_add_htcap_vendor_specific(frm, ni, IEEE80211_FC0_SUBTYPE_ASSOC_RESP);
        frm = ieee80211_add_htinfo_vendor_specific(frm, ni);
    }

    /* Insert ieee80211_ie_ath_extcap IE to Association Response */
    if ((ni->ni_flags & IEEE80211_NODE_ATH) &&
        ic->ic_ath_extcap) {
        u_int16_t ath_extcap = 0;
        u_int8_t  ath_rxdelim = 0;

        if (ieee80211_has_weptkipaggr(ni)) {
            ath_extcap |= IEEE80211_ATHEC_WEPTKIPAGGR;
            ath_rxdelim = ic->ic_weptkipaggr_rxdelim;
        }

        if ((ni->ni_flags & IEEE80211_NODE_OWL_WDSWAR) &&
            (ic->ic_ath_extcap & IEEE80211_ATHEC_OWLWDSWAR)) {
                ath_extcap |= IEEE80211_ATHEC_OWLWDSWAR;
        }

        /*
         * If we are Osprey 1.0 or earlier we require other end
         * to manage extra deimiters while TX, in Assoc response
         * add EXTRADELIMWAR bit
         */
        if (ieee80211com_has_extradelimwar(ic))
            ath_extcap |= IEEE80211_ATHEC_EXTRADELIMWAR;

        if (ath_extcap) {
            frm = ieee80211_add_athextcap(frm, ath_extcap, ath_rxdelim);
        }
    }

#if UMAC_SUPPORT_WNM
    if (ieee80211_vap_wnm_is_set(vap) && ni->ni_wnm->timbcast_ie) {
        frm = ieee80211_add_timresp_ie(vap, ni, frm);
    }
#endif

    /*
     * When WDS is enabled, indicate that in a vendor specific IE so that
     * a QCA range extender running automatic configuration logic can use
     * this to decide which mode to operate in.
     */
    if (IEEE80211_VAP_IS_WDS_ENABLED(vap)) {
        u_int16_t whcCaps = QCA_OUI_WHC_AP_INFO_CAP_WDS;
        u_int16_t ie_len;

        /* SON mode requires WDS as a prereq */
        if (IEEE80211_VAP_IS_SON_ENABLED(vap)) {
            whcCaps |= QCA_OUI_WHC_AP_INFO_CAP_SON;
        }

        frm = ieee80211_add_whc_ap_info_ie(frm, whcCaps, vap, &ie_len);
    }
#if QCN_IE
    /*Add QCN IE for the feature set*/
    frm = ieee80211_add_qcn_info_ie(frm, vap, &ie_len, NULL);
#endif
   /*
    * app_ie...
    */
    IEEE80211_VAP_LOCK(vap);
    if(vap->iv_app_ie[IEEE80211_FRAME_TYPE_ASSOCRESP].length){
        memcpy(frm, vap->iv_app_ie[IEEE80211_FRAME_TYPE_ASSOCRESP].ie,
               vap->iv_app_ie[IEEE80211_FRAME_TYPE_ASSOCRESP].length);
        frm += vap->iv_app_ie[IEEE80211_FRAME_TYPE_ASSOCRESP].length;
    }
    /* Add the Application IE's */
    frm = ieee80211_mlme_app_ie_append(vap, IEEE80211_FRAME_TYPE_ASSOCRESP, frm);

    /* Add Bandwidth-NSS Mapping Vendor IE*/
    if(!(vap->iv_ext_nss_support) && !(ic->ic_disable_bwnss_adv) && !ieee80211_get_bw_nss_mapping(vap, &nssmap, rx_chainmask)) {
        frm = ieee80211_add_bw_nss_maping(frm, &nssmap);
    }

    /* Add the addtional ies passed */
    if((optie != NULL) && (optie->length)) {
        memcpy(frm, optie->ie,
               optie->length);
        frm += optie->length;
    }
    IEEE80211_VAP_UNLOCK(vap);

    if (ieee80211_vap_mbo_check(vap) || ieee80211_vap_oce_check(vap)) {
        frm = ieee80211_setup_mbo_ie(IEEE80211_FC0_SUBTYPE_ASSOC_RESP, vap, frm, ni);

        /* Check against MBO assoc disallow condition */
        if (ieee80211_vap_mbo_check(vap) && ieee80211_vap_mbo_assoc_status(vap)) {
            *mbo_status_change = IEEE80211_STATUS_REJECT_TEMP;
        }

        /* Check against OCE RSSI-based assoc reject condition */
        if (ieee80211_vap_oce_check(vap) && ieee80211_vap_oce_assoc_reject(vap, ni)) {
            *mbo_status_change = IEEE80211_STATUS_POOR_CHAN_CONDITION;
        }
    }

    wbuf_set_pktlen(wbuf, (frm - (u_int8_t *)wbuf_header(wbuf)));

    return wbuf;
}

void ieee80211_recv_beacon_ap(struct ieee80211_node *ni, wbuf_t wbuf, int subtype,
                              struct ieee80211_rx_status *rs, ieee80211_scan_entry_t  scan_entry)
{
    struct ieee80211com                          *ic = ni->ni_ic;
    struct ieee80211_frame                       *wh;
    u_int8_t                                     erp = ieee80211_scan_entry_erpinfo(scan_entry);
    bool                                         has_ht;
#if ATH_SUPPORT_WIFIPOS
    struct ieee80211vap                          *vap = ni->ni_vap;
    u_int8_t                                     source_addr[ETH_ALEN];
#endif
    bool                                         update_beacon = false;

    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
#if ATH_SUPPORT_WIFIPOS
    if (subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP) {
        if (IEEE80211_ADDR_EQ(wh->i_addr1, vap->iv_myaddr)) {
            if((vap->iv_wifipos) && (!(ic->ic_is_mode_offload(ic)))){
                OS_MEMCPY((u_int8_t *)&vap->iv_tsf_sync, ieee80211_scan_entry_tsf(scan_entry), sizeof(vap->iv_tsf_sync));
                vap->iv_local_tsf_tstamp = ieee80211_get_tsftstamp(ic);
                OS_MEMCPY(source_addr, wh->i_addr2, sizeof(source_addr));
                vap->iv_wifipos->nlsend_tsf_update(vap, source_addr);
            }
        }
    }
#endif
    /* Update AP protection mode when in 11G mode */
    if (IEEE80211_IS_CHAN_ANYG(ic->ic_curchan) ||
        IEEE80211_IS_CHAN_11NG(ic->ic_curchan)) {
        wlan_chan_t channel = ieee80211_scan_entry_channel(scan_entry);
        if (ic->ic_protmode != IEEE80211_PROT_NONE && (erp & IEEE80211_ERP_NON_ERP_PRESENT) && (channel->ic_freq==ic->ic_curchan->ic_freq)) {
            if (!IEEE80211_IS_PROTECTION_ENABLED(ic)) {
                struct ieee80211vap *tmpvap;
                IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_INPUT,
                                  "setting protection bit "
                                  "(beacon from %s)\n",
                                  ether_sprintf(wh->i_addr2));
                IEEE80211_ENABLE_PROTECTION(ic);
		        TAILQ_FOREACH(tmpvap, &(ic)->ic_vaps, iv_next)
		            ieee80211_vap_erpupdate_set(tmpvap);

                ic->ic_update_protmode(ic);
                if(ic->ic_consider_obss_long_slot) {
                    ieee80211_set_shortslottime(ic, 0);
                }
                update_beacon = true;
            }
            ic->ic_last_nonerp_present = OS_GET_TIMESTAMP();
        }
    }

  /*
   * 802.11n HT Protection: We've detected a non-HT AP.
   * We must enable protection and schedule the setting of the
   * HT info IE to advertise this to associated stations.
   */
    has_ht = (ieee80211_scan_entry_htinfo(scan_entry)  != NULL ||
              ieee80211_scan_entry_htcap(scan_entry)  != NULL );

    if (IEEE80211_IS_CHAN_11AC(ic->ic_curchan) ||
         IEEE80211_IS_CHAN_11N(ic->ic_curchan)) {
        if (!has_ht) {
            wlan_chan_t					  channel		= ieee80211_scan_entry_channel(scan_entry);
            if (ieee80211_ic_non_ht_ap_is_clear(ic) && (channel->ic_freq==ic->ic_curchan->ic_freq)) {
                IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_INPUT,
                                  "setting F_NONHT_AP protection bit "
                                  "(beacon from %s)\n",
                                  ether_sprintf(wh->i_addr2));
                ieee80211_ic_non_ht_ap_set(ic);
                update_beacon = true;
            }
            else
            {
                if (channel->ic_freq==ic->ic_curchan->ic_freq)
                    ic->ic_last_non_ht_sta = OS_GET_TIMESTAMP();
            }
        } else {
            struct ieee80211_ie_htinfo_cmn  *htinfo;
            htinfo = (struct ieee80211_ie_htinfo_cmn *) ieee80211_scan_entry_htinfo(scan_entry);
            if (htinfo) {
                if ((htinfo->hi_opmode & IEEE80211_HTINFO_OPMODE_MIXED_PROT_ALL) == IEEE80211_HTINFO_OPMODE_MIXED_PROT_ALL) {
                    wlan_chan_t					  channel		= ieee80211_scan_entry_channel(scan_entry);
                    if (ieee80211_ic_non_ht_ap_is_clear(ic) && (channel->ic_freq==ic->ic_curchan->ic_freq)) {
                        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_INPUT,
                                          "Setting HT protection bit "
                                           "(beacon from %s)\n",
                                           ether_sprintf(wh->i_addr2));
                        ieee80211_ic_non_ht_ap_set(ic);
                        update_beacon = true;
                    }
                    else
                    {
                        if (channel->ic_freq==ic->ic_curchan->ic_freq)
                            ic->ic_last_non_ht_sta = OS_GET_TIMESTAMP();
                    }
                }
            }
        }
    }


    /* Trigger beacon template update if necessary */
    if ((update_beacon == true) && (ic->ic_beacon_probe_template_update)) {
        ic->ic_beacon_probe_template_update(ni);
    }
}

/*
 * Process a received ps-poll frame.
 */
static void
ieee80211_recv_pspoll(struct ieee80211_node *ni, wbuf_t wbuf)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211_frame_min *wh;
    u_int16_t aid;
    wh = (struct ieee80211_frame_min *)wbuf_header(wbuf);
    if (ni->ni_associd == 0) {
        IEEE80211_DISCARD(vap,
                IEEE80211_MSG_POWER | IEEE80211_MSG_DEBUG,
                (struct ieee80211_frame *) wh, "ps-poll",
                "%s", "unassociated station");
        vap->iv_stats.is_ps_unassoc++;
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH, "%s: sending DEAUTH to %s, reason %d\n",
                __func__, ether_sprintf(wh->i_addr2), IEEE80211_REASON_NOT_ASSOCED);

        /* NB: caller deals with reference */
        if (ieee80211_vap_ready_is_set(vap)) {
            struct ieee80211_node *temp_node;
            temp_node = ieee80211_tmp_node(vap, wh->i_addr2);
            if (temp_node != NULL) {
                ieee80211_send_deauth(temp_node, IEEE80211_REASON_NOT_ASSOCED);
                IEEE80211_DELIVER_EVENT_MLME_DEAUTH_INDICATION(vap, (wh->i_addr2), 0,
                        IEEE80211_REASON_NOT_ASSOCED);

                /* claim node immediately */
                ieee80211_free_node(temp_node);
            }
        }
        return;
    }

    aid = le16toh(*(u_int16_t *)wh->i_dur);
    if (aid != ni->ni_associd) {
        IEEE80211_DISCARD(vap,
                IEEE80211_MSG_POWER | IEEE80211_MSG_DEBUG,
                (struct ieee80211_frame *) wh, "ps-poll",
                "aid mismatch: sta aid 0x%x poll aid 0x%x",
                ni->ni_associd, aid);
        vap->iv_stats.is_ps_badaid++;
    }
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_POWER,
            "%s: received pspoll from %#x \n", __func__, aid);

    /* After receiving pspoll frame, send only legacy packet
     */
    if( !ni->ni_pspoll )
    {
        ic->ic_node_pspoll(ni, 1);
        ni->ni_pspoll_time = OS_GET_TIMESTAMP();
    }

#ifdef ATH_SWRETRY
    /*
     * Check the aggregation Queue.
     * if there are frames queued in aggr queue in the ath layer,
     * they should go out before the frames in PS queue
     */
    if (ic->ic_handle_pspoll) {
        if (ic->ic_handle_pspoll(ic, ni) == 0)
            return;
    }
#endif

#if LMAC_SUPPORT_POWERSAVE_QUEUE

    if ( ic->ic_node_pwrsaveq_send && ic->ic_get_lmac_pwrsaveq_len ) {
        if (!ic->ic_node_pwrsaveq_send(ic, ni, IEEE80211_FC0_TYPE_MGT)) {
            ic->ic_node_pwrsaveq_send(ic, ni, IEEE80211_FC0_TYPE_DATA);
        }

        if (ic->ic_get_lmac_pwrsaveq_len(ic, ni, 0) == 0
#ifdef ATH_SWRETRY
                && ic->ic_exist_pendingfrm_tidq(ni->ni_ic, ni) != 0
#endif
                && vap->iv_set_tim != NULL) {
            vap->iv_set_tim(ni, 0, false);
        }

        return;
    }
#endif

    /*
     * Send Queued mgmt frames first.
     */
    if (ieee80211_node_saveq_send(ni,IEEE80211_FC0_TYPE_MGT)) {
        return;
    }

    if (!ieee80211_node_saveq_send(ni,IEEE80211_FC0_TYPE_DATA)) {
        /*
         * no frame was sent in response to ps-poll frame.
         * send a null  frame.
         */
        IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_POWER, wh->i_addr2,
                "%s", "recv ps-poll, but queue empty");
        ieee80211_send_nulldata(ni, 0);
    }
}

void ieee80211_recv_ctrl_ap(struct ieee80211_node *ni, wbuf_t wbuf,
						int subtype)
{
    if (subtype ==  IEEE80211_FC0_SUBTYPE_PS_POLL) {
        ieee80211_recv_pspoll(ni, wbuf);
    }
}


void ieee80211_update_erp_info(struct ieee80211vap *vap)
{
    struct ieee80211com                          *ic = vap->iv_ic;
    /* check if the erp present is timed out */
    if( IEEE80211_IS_PROTECTION_ENABLED(ic) && ic->ic_nonerpsta == 0 &&
        CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP() - ic->ic_last_nonerp_present) >= (IEEE80211_INACT_NONERP * 1000)) {
	struct ieee80211vap                          *tmpvap;
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_INPUT,
                              "%s: disable use of protection\n", __func__);
        ic->ic_last_nonerp_present = 0;
        IEEE80211_DISABLE_PROTECTION(ic);
	TAILQ_FOREACH(tmpvap, &(ic)->ic_vaps, iv_next)
	    ieee80211_vap_erpupdate_set(tmpvap);
        ic->ic_update_protmode(ic);
        ieee80211_set_shortslottime(ic, 1);
    }

    /* check if the non ht present is timed out */
    if (ieee80211_ic_non_ht_ap_is_set(ic) &&
        (CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP() - ic->ic_last_non_ht_sta) >= (IEEE80211_INACT_HT * 1000))){
        ieee80211_ic_non_ht_ap_clear(ic);
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_INPUT,
                              "%s: clear non ht ap present \n", __func__);
    }

}

void ieee80211_inact_timeout_ap(struct ieee80211vap *vap)
{
    ieee80211_update_erp_info(vap);
}

/*
 * Update node MIMO power save state and update valid rates
 */
void ieee80211_update_noderates(struct ieee80211_node *ni)
{
    struct ieee80211com *ic = ni->ni_ic;
    int smen, dyn, ratechg;
#if ATH_DEBUG
    struct ieee80211vap *vap = ni->ni_vap;
#endif

    if (ni->ni_updaterates) {

        smen = (ni->ni_updaterates & IEEE80211_NODE_SM_EN) ? 1:0;
        dyn = (!smen && (ni->ni_updaterates & IEEE80211_NODE_SM_PWRSAV_DYN)) ? 1:0;
        ratechg = (ni->ni_updaterates & IEEE80211_NODE_RATECHG) ? 1:0;

        IEEE80211_DPRINTF(vap,IEEE80211_MSG_POWER,"%s: updating"
            " rates: smen %d dyn %d ratechg %d \n", __func__, smen, dyn, ratechg);
        if (ic->ic_sm_pwrsave_update) {
            (*ic->ic_sm_pwrsave_update)(ni, smen, dyn, ratechg);
        }
#if ATH_BAND_STEERING
        ieee80211_bsteering_send_node_smps_update_event(ni->ni_vap, ni,
             (!smen && (ni->ni_updaterates & IEEE80211_NODE_SM_PWRSAV_STAT)) ? 1 : 0);
#endif
        ni->ni_updaterates = 0;
    }
}

int ieee80211_recv_addts_req(struct ieee80211_node *ni, struct ieee80211_wme_tspec *tspec, int dialog_token)
{
    struct ieee80211_tsinfo_bitmap *tsflags;
    ieee80211_tspec_info tsinfo;

    OS_MEMZERO(&tsinfo, sizeof(ieee80211_tspec_info));
    tsflags = (struct ieee80211_tsinfo_bitmap *) &(tspec->ts_tsinfo);

    tsinfo.direction = tsflags->direction;
    tsinfo.psb = tsflags->psb;
    tsinfo.dot1Dtag = tsflags->dot1Dtag;
    tsinfo.tid = tsflags->tid;
    tsinfo.aggregation = tsflags->reserved3;
    tsinfo.acc_policy_edca = tsflags->one;
    tsinfo.acc_policy_hcca = tsflags->zero;
    tsinfo.traffic_type = tsflags->reserved1;
    tsinfo.ack_policy = tsflags->reserved2;
    tsinfo.norminal_msdu_size = le16toh(*((u_int16_t *) &tspec->ts_nom_msdu[0]));
    tsinfo.max_msdu_size = le16toh(*((u_int16_t *) &tspec->ts_max_msdu[0]));
    tsinfo.min_srv_interval = le32toh(*((u_int32_t *) &tspec->ts_min_svc[0]));
    tsinfo.max_srv_interval = le32toh(*((u_int32_t *) &tspec->ts_max_svc[0]));
    tsinfo.inactivity_interval = le32toh(*((u_int32_t *) &tspec->ts_inactv_intv[0]));
    tsinfo.suspension_interval = le32toh(*((u_int32_t *) &tspec->ts_susp_intv[0]));
    tsinfo.srv_start_time = le32toh(*((u_int32_t *) &tspec->ts_start_svc[0]));
    tsinfo.min_data_rate = le32toh(*((u_int32_t *) &tspec->ts_min_rate[0]));
    tsinfo.mean_data_rate = le32toh(*((u_int32_t *) &tspec->ts_mean_rate[0]));
    tsinfo.max_burst_size = le32toh(*((u_int32_t *) &tspec->ts_max_burst[0]));
    tsinfo.min_phy_rate = le32toh(*((u_int32_t *) &tspec->ts_min_phy[0]));
    tsinfo.peak_data_rate = le32toh(*((u_int32_t *) &tspec->ts_peak_rate[0]));
    tsinfo.delay_bound = le32toh(*((u_int32_t *) &tspec->ts_delay[0]));
    tsinfo.surplus_bw = le16toh(*((u_int16_t *) &tspec->ts_surplus[0]));
    tsinfo.medium_time = le16toh(*((u_int16_t *) &tspec->ts_medium_time[0]));

    return ieee80211_admctl_process_addts_req(ni, &tsinfo, dialog_token);

}

int
wlan_send_addts_resp(wlan_if_t vaphandle, u_int8_t *macaddr, ieee80211_tspec_info *tsinfo, u_int8_t status, int dialog_token)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211_node *ni;
    struct ieee80211_action_mgt_args addts_args;
    struct ieee80211_action_mgt_buf  addts_buf;
    struct ieee80211_tsinfo_bitmap *tsflags;
    struct ieee80211_wme_tspec *tspec;

    ni = ieee80211_find_txnode(vap, macaddr);
    if (ni == NULL) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_OUTPUT,
                          "%s: could not send ADDTS, no node found for %s\n",
                          __func__, ether_sprintf(macaddr));
        return -EINVAL;
    }

    /*
     * ieee80211_action_mgt_args is a generic structure. TSPEC IE
     * is filled in the buf area.
     */
    addts_args.category = IEEE80211_ACTION_CAT_WMM_QOS;
    addts_args.action   = IEEE80211_WMM_QOS_ACTION_SETUP_RESP;
    addts_args.arg1     = dialog_token;
    addts_args.arg2     = status; /* status code */
    addts_args.arg3     = sizeof(struct ieee80211_wme_tspec);

    tspec = (struct ieee80211_wme_tspec *) &addts_buf.buf;
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

    ieee80211_send_action(ni, &addts_args, &addts_buf);
    ieee80211_free_node(ni);    /* reclaim node */
    return 0;
}

int
wlan_send_mgmt(wlan_if_t vaphandle, u_int8_t *macaddr, u_int8_t *mgmt_frm, u_int32_t len)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_node *ni;
    wbuf_t wbuf = NULL;
    u_int8_t *frm = NULL;
    int rc = 0;
    int type = -1, subtype;
    struct ieee80211_frame *wh;
    ni = ieee80211_find_txnode(vap, macaddr);
    if (ni == NULL) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_OUTPUT,
                          "%s: could not send mgmt found for %s\n",
                          __func__, ether_sprintf(macaddr));
        return -EINVAL;
    }
    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);
    if (wbuf == NULL) {
        ieee80211_free_node(ni);    /* reclaim node */
        return -EINVAL;
    }
    frm = (u_int8_t *)wbuf_header(wbuf);

    OS_MEMCPY(frm, mgmt_frm, len);
    wbuf_set_pktlen(wbuf, len);


    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

    ieee80211_send_setup(vap, vap->iv_bss, wh,
                         type | subtype,
                         vap->iv_myaddr, ieee80211_node_get_macaddr(ni),
                         ieee80211_node_get_bssid(ni));

    if ((type == IEEE80211_FC0_TYPE_MGT) && (subtype == IEEE80211_FC0_SUBTYPE_ACTION)) {
        /* protect if PMF is enabled, Turn ON Privacy bit in FC */
        if (ieee80211_is_pmf_enabled(vap, ni) && ni->ni_ucastkey.wk_valid) {
            /* MFP is enabled, so we need to set Privacy bit */
            wh->i_fc[1] |= IEEE80211_FC1_WEP;
        }
    }
    rc = ieee80211_send_mgmt(vap, ni, wbuf, true);

    ieee80211_free_node(ni);    /* reclaim node */
    return rc;
}

int ieee80211_recv_delts_req(struct ieee80211_node *ni, struct ieee80211_wme_tspec *tspec)
{
    struct ieee80211_tsinfo_bitmap *tsflags;
    ieee80211_tspec_info tsinfo;

    OS_MEMZERO(&tsinfo, sizeof(ieee80211_tspec_info));
    tsflags = (struct ieee80211_tsinfo_bitmap *) &(tspec->ts_tsinfo);

    tsinfo.direction = tsflags->direction;
    tsinfo.psb = tsflags->psb;
    tsinfo.dot1Dtag = tsflags->dot1Dtag;
    tsinfo.tid = tsflags->tid;
    tsinfo.aggregation = tsflags->reserved3;
    tsinfo.acc_policy_edca = tsflags->one;
    tsinfo.acc_policy_hcca = tsflags->zero;
    tsinfo.traffic_type = tsflags->reserved1;
    tsinfo.ack_policy = tsflags->reserved2;

    tsinfo.norminal_msdu_size = le16toh(*((u_int16_t *) &tspec->ts_nom_msdu[0]));
    tsinfo.max_msdu_size = le16toh(*((u_int16_t *) &tspec->ts_max_msdu[0]));
    tsinfo.min_srv_interval = le32toh(*((u_int32_t *) &tspec->ts_min_svc[0]));
    tsinfo.max_srv_interval = le32toh(*((u_int32_t *) &tspec->ts_max_svc[0]));
    tsinfo.inactivity_interval = le32toh(*((u_int32_t *) &tspec->ts_inactv_intv[0]));
    tsinfo.suspension_interval = le32toh(*((u_int32_t *) &tspec->ts_susp_intv[0]));
    tsinfo.srv_start_time = le32toh(*((u_int32_t *) &tspec->ts_start_svc[0]));
    tsinfo.min_data_rate = le32toh(*((u_int32_t *) &tspec->ts_min_rate[0]));
    tsinfo.mean_data_rate = le32toh(*((u_int32_t *) &tspec->ts_mean_rate[0]));
    tsinfo.max_burst_size = le32toh(*((u_int32_t *) &tspec->ts_max_burst[0]));
    tsinfo.min_phy_rate = le32toh(*((u_int32_t *) &tspec->ts_min_phy[0]));
    tsinfo.peak_data_rate = le32toh(*((u_int32_t *) &tspec->ts_peak_rate[0]));
    tsinfo.delay_bound = le32toh(*((u_int32_t *) &tspec->ts_delay[0]));
    tsinfo.surplus_bw = le16toh(*((u_int16_t *) &tspec->ts_surplus[0]));
    tsinfo.medium_time = le16toh(*((u_int16_t *) &tspec->ts_medium_time[0]));

    return ieee80211_admctl_process_delts_req(ni, &tsinfo);
}

#if MESH_MODE_SUPPORT
#if MESH_PEER_DYNAMIC_UPDATE
/*
  Do periodical capability intersection based on updated info in new beacon,
  between current ni and updated beacon.
  It's basically same function as ieee80211_recv_asreq, but instead of assoc-req, it processes beacon.
*/
int ieee80211_beacon_intersect(struct ieee80211_node *ni, u_int8_t *bcn_frm_body, u_int16_t bcn_body_len, struct ieee80211_frame *wh)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;
    u_int8_t *frm, *efrm;
    u_int16_t capinfo, bintval;
    struct ieee80211_rsnparms rsn;
    u_int8_t reason;
    u_int8_t *ssid, *rates, *xrates, *wpa, *wme, *ath, *htcap,*vendor_ie, *vhtcap, *mbo = NULL;
    u_int8_t *athextcap, *opmode, *xcaps, *bwnss_oui, *supp_op_cl = NULL;
    IEEE80211_COUNTRY_ENTRY country;

#define ADD_NI_RATES_NUM 8
    u_int8_t temp_ni_rates[ADD_NI_RATES_NUM] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7};
    int subtype = 8;

    ssid = rates = xrates = wpa = wme = ath = htcap = vhtcap = opmode = mbo = NULL;
    athextcap = xcaps = bwnss_oui = supp_op_cl = NULL;
    vendor_ie = NULL;

    frm = bcn_frm_body;
    efrm = frm + bcn_body_len;

    /*
     * Beacon frame format
     *    [8] timestamp
     *    [2] beacon interval
     *    [2] capability information
     *****tagged IEs, e.g.
     *    ssid
     *    supported rates
     *    extended supported rates
     *    DS param
     *    TIM
     *    Country info
     *    Power constraint
     *    HT Capabilities
     *    HT info
     *    VHT Capabilities
     *    VHT operation
     *    Vendor IEs
     *    RSN info
     */
    frm += 8;
    bintval = le16toh(*(u_int16_t *)frm);    frm += 2;
    capinfo = le16toh(*(u_int16_t *)frm);    frm += 2;

    while (((frm + 1) < efrm) && (frm + frm[1] + 1) < efrm) {
        switch (*frm) {
        case IEEE80211_ELEMID_SSID:
            ssid = frm;
            break;
        case IEEE80211_ELEMID_RATES:
            rates = frm;
            break;
        case IEEE80211_ELEMID_XRATES:
            xrates = frm;
            break;
            /* XXX verify only one of RSN and WPA ie's? */
        case IEEE80211_ELEMID_RSN:
            wpa = frm;
            break;
        case IEEE80211_ELEMID_HTCAP_ANA:
            htcap = (u_int8_t *)&((struct ieee80211_ie_htcap *)frm)->hc_ie;
            break;
        case IEEE80211_ELEMID_SUPP_OP_CLASS:
            supp_op_cl = frm;
            break;
        case IEEE80211_ELEMID_VHTCAP:
            if(vhtcap == NULL)
                vhtcap = (u_int8_t *)(struct ieee80211_ie_vhtcap *)frm;
            break;
        case IEEE80211_ELEMID_OP_MODE_NOTIFY:
            if(opmode == NULL)
                opmode = (u_int8_t *)(struct ieee80211_ie_op_mode_ntfy *)frm;
            break;
        case IEEE80211_ELEMID_VENDOR:
            if (iswpaoui(frm)) {
                if (RSN_AUTH_IS_WPA(&vap->iv_bss->ni_rsn))
                    wpa = frm;
            } else if (iswmeinfo(frm))
                wme = frm;
            else if (isatherosoui(frm))
                ath = frm;
            else if (ismbooui(frm))
                mbo = frm;
            else if(ishtcap(frm)){
                if(htcap == NULL)
                    htcap = (u_int8_t *)&((struct vendor_ie_htcap *)frm)->hc_ie;
            }
            else if (isatheros_extcap_oui(frm))
                 athextcap = frm;
            else if (isbwnss_oui(frm))
                 bwnss_oui = frm;
            else if (isinterop_vht(frm) && (!vhtcap) && ieee80211vap_11ng_vht_interopallowed(vap)) {
                 /* frm+7 is the location , where 2.4G Interop VHT IE starts */
                 vhtcap = (u_int8_t *)(struct ieee80211_ie_vhtcap *) (frm + 7);
                 ni->ni_flags |= IEEE80211_NODE_11NG_VHT_INTEROP_AMSDU_DISABLE;
            }

            if (!iswpaoui(frm) && !iswmeinfo(frm)) {
                vendor_ie = frm;
            }

            break;
        }
        frm += frm[1] + 2;
    }

    if (frm > efrm) {
        IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ASSOC, ni->ni_macaddr,
                "error, end of the frame\n");
        vap->iv_stats.is_rx_badchan++;
        return -EINVAL;
    }

    IEEE80211_VERIFY_ELEMENT(rates, IEEE80211_RATE_MAXSIZE);

    if (ni == vap->iv_bss) {
        IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ANY, wh->i_addr2,
                           "%s: deny request, sta %s not authenticated\n", __func__,
                           ether_sprintf(wh->i_addr2));
        IEEE80211_DELIVER_EVENT_MLME_DEAUTH_INDICATION(vap, (wh->i_addr2), 0,
                                       IEEE80211_REASON_NOT_AUTHED);
        vap->iv_stats.is_rx_assoc_notauth++;
        return -EINVAL;
    }

    if ((wpa == NULL) && (RSN_AUTH_IS_WPA(&vap->iv_bss->ni_rsn) || RSN_AUTH_IS_RSNA(&vap->iv_bss->ni_rsn))) {
        /*
         * When operating with WPA/RSN, there must be
         * proper security credentials.
         */
        IEEE80211_NOTE_MAC(vap,
                           IEEE80211_MSG_ASSOC | IEEE80211_MSG_WPA,
                           wh->i_addr2,
                           "deny request, no WPA/RSN ie\n");
        IEEE80211_DELIVER_EVENT_MLME_DEAUTH_INDICATION(vap, (wh->i_addr2), 0,
                                       IEEE80211_REASON_RSN_REQUIRED);
        vap->iv_stats.is_rx_assoc_badwpaie++;    /*XXX*/
        return -EINVAL;
    }
    OS_MEMZERO(&rsn, sizeof(struct ieee80211_rsnparms));
    if (wpa != NULL) {
        /*
         * Parse WPA information element.  Note that
         * we initialize the param block from the node
         * state so that information in the IE overrides
         * our defaults.  The resulting parameters are
         * installed below after the association is assured.
         */
        rsn = ni->ni_rsn;
            /*support for WAPI: parse WAPI information element*/
        {
            if (wpa[0] != IEEE80211_ELEMID_RSN) {
                reason = ieee80211_parse_wpa(vap, wpa, &rsn);
            } else {
                reason = ieee80211_parse_rsn(vap, wpa, &rsn);
            }
            if ((reason == IEEE80211_STATUS_SUCCESS) &&
                 ((((vap->iv_rsn.rsn_caps & RSN_CAP_MFP_REQUIRED) == RSN_CAP_MFP_REQUIRED) &&
                   ((rsn.rsn_caps & RSN_CAP_MFP_ENABLED) != RSN_CAP_MFP_ENABLED)) ||
                   (((rsn.rsn_caps & RSN_CAP_MFP_REQUIRED) == RSN_CAP_MFP_REQUIRED) &&
                   ((rsn.rsn_caps & RSN_CAP_MFP_ENABLED) != RSN_CAP_MFP_ENABLED)))) {
                reason = IEEE80211_STATUS_MFP_VIOLATION;
            }
        }
        if (reason != 0) {
            vap->iv_stats.is_rx_assoc_badwpaie++;
            return -EINVAL;
        }

        /*
         * Conditionally determine whether to check for WAPI or not.
         * This can't be done inside the call to IEEE80211_NOTE_MAC,
         * because IEEE80211_NOTE_MAC is itself a macro.
         * (Well, technically it could, as long as the conditional
         * compilation part were carefully done within a single
         * macro argument.)
         */
        #define LOCAL_ELEMID_TYPE_CHECK \
            wpa[0] != IEEE80211_ELEMID_RSN ?  "WPA" : "RSN"
        IEEE80211_NOTE_MAC(vap,
                           IEEE80211_MSG_ASSOC | IEEE80211_MSG_WPA,
                           wh->i_addr2,
                           "%s ie: mc %u/%u uc %u/%u key %u caps 0x%x\n",
                           LOCAL_ELEMID_TYPE_CHECK,
                           rsn.rsn_mcastcipherset, rsn.rsn_mcastkeylen,
                           rsn.rsn_ucastcipherset, rsn.rsn_ucastkeylen,
                           rsn.rsn_keymgmtset, rsn.rsn_caps);
        #undef LOCAL_ELEMID_TYPE_CHECK
    }
    /* 802.11 spec says to ignore station's privacy bit */
    if ((capinfo & IEEE80211_CAPINFO_ESS) == 0) {
        IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ANY, wh->i_addr2,
                           "deny request, capability mismatch 0x%x",
                           capinfo);
#if UMAC_SUPPORT_ACFG
        acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                           ACFG_REASON_ASSOC_CAP_MISMATCH);
#endif
        vap->iv_stats.is_rx_assoc_capmismatch++;
        return -EINVAL;
    }

    if ( !ieee80211_setup_rates(ni, rates, xrates,
                    IEEE80211_F_DOSORT | IEEE80211_F_DOFRATE |
                    IEEE80211_F_DOXSECT | IEEE80211_F_DOBRS) ||
        (IEEE80211_VAP_IS_PUREG_ENABLED(vap) &&
          (ni->ni_rates.rs_rates[ni->ni_rates.rs_nrates-1] & IEEE80211_RATE_VAL) < 48)) {
        IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ANY, wh->i_addr2,
                           "deny request, rate set mismatch");
#if UMAC_SUPPORT_ACFG
        acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                           ACFG_REASON_ASSOC_RATE_MISMATCH);
#endif
        vap->iv_stats.is_rx_assoc_norate++;
        return -EINVAL;
    }

    if (ni->ni_associd != 0 &&
        IEEE80211_IS_CHAN_ANYG(vap->iv_bsschan)) {
        if ((ni->ni_capinfo & IEEE80211_CAPINFO_SHORT_SLOTTIME)
            != (capinfo & IEEE80211_CAPINFO_SHORT_SLOTTIME))
        {
            IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ANY,
                               wh->i_addr2, "deny request, short slot time\
                capability mismatch 0x%x", capinfo);
#if UMAC_SUPPORT_ACFG
            acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                           ACFG_REASON_ASSOC_CAP_MISMATCH);
#endif
            vap->iv_stats.is_rx_assoc_capmismatch++;
            return -EINVAL;
        }
    }
    LIMIT_BEACON_PERIOD(bintval);
    ni->ni_intval = bintval;
    ni->ni_capinfo = capinfo;
    ni->ni_chan = ic->ic_curchan;
    if (wpa != NULL) {
        /*
         * Record WPA/RSN parameters for station, mark
         * node as using WPA and record information element
         * for applications that require it.
         */
        ni->ni_rsn = rsn;
        ieee80211_saveie(ic->ic_osdev,&ni->ni_wpa_ie, wpa);
    } else if (ni->ni_wpa_ie != NULL) {
        /*
         * Flush any state from a previous association.
         */
        OS_FREE(ni->ni_wpa_ie);
        ni->ni_wpa_ie = NULL;
    }

    if (supp_op_cl != NULL) {
        /*
         * Record operating classes supported by the STA
         * so that we don't steer the STA towards a channel
         * not supported by it
         */
        ic->ic_get_currentCountry(ic, &country);
        ieee80211_saveie(ic->ic_osdev, &ni->ni_supp_op_class_ie, supp_op_cl);
        ieee80211_parse_op_class_ie(supp_op_cl, wh, ni, country.countryCode);
    }
    else if (ni->ni_supp_op_class_ie != NULL) {
        /*
         * Flush any state from a previous association.
         */
        OS_FREE(ni->ni_supp_op_class_ie);
        ni->ni_supp_op_class_ie = NULL;
    }

    if (wme != NULL) {
        /*
         * Record WME parameters for station, mark
         * node as using WME and record information element
         * for applications that require it.
         */
        ieee80211_saveie(ic->ic_osdev, &ni->ni_wme_ie, wme);
    } else if (ni->ni_wme_ie != NULL) {
        /*
         * Flush any state from a previous association.
         */
        OS_FREE(ni->ni_wme_ie);
        ni->ni_wme_ie = NULL;
    }

    if ((wme != NULL) && ieee80211_parse_wmeie(wme, wh, ni) > 0) {
        ieee80211node_set_flag(ni, IEEE80211_NODE_QOS);
    } else {
        ieee80211node_clear_flag(ni, IEEE80211_NODE_QOS);
    }

    /*
     * if doing pure 802.11n mode, don't
     * accept stas who don't have HT caps.
     */
    if (IEEE80211_VAP_IS_PURE11N_ENABLED(vap) && (htcap == NULL)) {
        IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ANY, wh->i_addr2,
                           "deny request, no ht caps in pure 802.11n mode");
#if UMAC_SUPPORT_ACFG
        acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                           ACFG_REASON_ASSOC_PUREN_NOHT);
#endif
        return -EINVAL;
    }

    /*
     * if doing pure 802.11ac mode, don't
     * accept STAs without VHT capabilities.
     */
    if ((ieee80211vap_vhtallowed(vap)) &&
        IEEE80211_VAP_IS_PURE11AC_ENABLED(vap) && (vhtcap == NULL)) {
        IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ANY, wh->i_addr2,
                           "deny request, no vht caps in pure 802.11ac mode");
#if UMAC_SUPPORT_ACFG
        acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                           ACFG_REASON_ASSOC_PUREAC_NOVHT);
#endif
        return -EINVAL;
    }

    if (IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan)) {
        ni->ni_phymode = IEEE80211_MODE_11A;
    }else if(ieee80211_node_has_11g_rate(ni) &&
            IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11G)){
        /*if 11g rate exists, use 11G mode*/
        ni->ni_phymode = IEEE80211_MODE_11G;
    }else{
        ni->ni_phymode = IEEE80211_MODE_11B;
    }

    /*
     * Channel width and Nss will get adjusted with HT parse and VHT parse
     * if those modes are enabled
     */
    ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
    ni->ni_streams = 1;
    /* 11ac or 11n and ht allowed for this vap */
    if ((IEEE80211_IS_CHAN_11AC(ic->ic_curchan) ||
        IEEE80211_IS_CHAN_11N(ic->ic_curchan)) &&
        ieee80211vap_htallowed(vap)) {
        /* For AP in mixed mode, ignore the htcap from remote node,
         * if ht rate is not allowed in TKIP.
         */
        if (!ieee80211_ic_wep_tkip_htrate_is_set(ic)  &&
            RSN_CIPHER_IS_TKIP(&ni->ni_rsn))
        {
            htcap = NULL;
        }
        if (htcap != NULL) {
            if (ieee80211_ht_nss_mcs_valid(ni,htcap) < 0) {
                qdf_print("****** FW configured HT rate control params(iwpriv setrcparams) and STA Rx MCS dont match \n");
                return -EINVAL;
            }
            /* record capabilities, mark node as capable of HT */
            if (!ieee80211_parse_htcap(ni, htcap)) {
                IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ANY, wh->i_addr2,
                                   "deny request, Rx MCS set mismatch");
#if UMAC_SUPPORT_ACFG
                acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                           ACFG_REASON_ASSOC_RATE_MISMATCH);
#endif
                vap->iv_stats.is_rx_assoc_norate++;
                return -EINVAL;
            }
#ifdef ATH_SUPPORT_TxBF
            ieee80211_init_txbf(ic, ni);
#endif
        } else {
            /*
             * Flush any state from a previous association.
             */
            ni->ni_flags &= ~IEEE80211_NODE_HT;
            ni->ni_htcap = 0;
        }
        if (!ieee80211_setup_ht_rates(ni, htcap,
                                      IEEE80211_F_DOFRATE | IEEE80211_F_DOXSECT | IEEE80211_F_DOBRS)) {
            IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ANY, wh->i_addr2,
                               "deny request, ht rate set mismatch");
#if UMAC_SUPPORT_ACFG
            acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                                        ACFG_REASON_ASSOC_RATE_MISMATCH);
#endif
            vap->iv_stats.is_rx_assoc_norate++;
            return -EINVAL;
        }

        if ((ni->ni_flags & IEEE80211_NODE_HT) &&
                    ((ni->ni_htrates.rs_nrates < ADD_NI_RATES_NUM) ||
                     OS_MEMCMP(temp_ni_rates, ni->ni_htrates.rs_rates, ADD_NI_RATES_NUM ))) {

            u_int8_t *p = (u_int8_t *) &ni->ni_htrates.rs_rates[ADD_NI_RATES_NUM];
            u_int8_t i = 0,j=0;
            u_int8_t rs_nrates = ni->ni_htrates.rs_nrates;
            u_int8_t temp_rs_rates[IEEE80211_RATE_MAXSIZE];

            IEEE80211_NOTE_MAC(vap,
                               IEEE80211_MSG_ASSOC,
                               wh->i_addr2,
                               "Node is marked HT - but RX MCS 0-7 not supported, Number of Rates supported %d",
                               ni->ni_htrates.rs_nrates);

            /* Re-initialize ni->ni_htrates.rs_rates[] adding MCS:0-7 & appending existing rates */
            OS_MEMCPY(temp_rs_rates, ni->ni_htrates.rs_rates, ni->ni_htrates.rs_nrates);
            OS_MEMZERO(ni->ni_htrates.rs_rates, ni->ni_htrates.rs_nrates);
            if(vap->iv_disable_htmcs) {
                for (i = 0; i < ADD_NI_RATES_NUM; i++) {
                    /* if any mcs between 0 - 7 is not disabled, then add it */
                    if(!(vap->iv_disabled_ht_mcsset[0] & (1<<i))) {
                        ni->ni_htrates.rs_rates[j++] = i;
                    }
                }
                ni->ni_htrates.rs_nrates = j;
                p =  &ni->ni_htrates.rs_rates[j];
            } else {
               OS_MEMCPY(ni->ni_htrates.rs_rates, temp_ni_rates, ADD_NI_RATES_NUM); /* Fill MCS 0-7 */
               ni->ni_htrates.rs_nrates = ADD_NI_RATES_NUM;
            }
            /* Add any other MCS (other than 0-7), if supported */
            for (i = 0; i < rs_nrates; i++) {
                if (temp_rs_rates[i] >=  ADD_NI_RATES_NUM) {
                    *p++ = temp_rs_rates[i];
                    ni->ni_htrates.rs_nrates++;
                }
            }
        } /* Add MCS 0-7 if not present */

    }

    /* Add vht cap for 2.4G mode, if 256QAM is enabled */
    if ((IEEE80211_IS_CHAN_11AC(ic->ic_curchan) || (IEEE80211_IS_CHAN_11NG(ic->ic_curchan))) &&
                           ieee80211vap_vhtallowed(vap)) {

        if(bwnss_oui != NULL){
            /*Bandwidth-NSS map has sub-type & version. hence copy data after version */
            ni->ni_bwnss_map = IEEE80211_BW_NSS_FWCONF_160(*(bwnss_oui+8));
        } else {
            ni->ni_bwnss_map = 0;
        }

        if (vhtcap != NULL) {
            if(ieee80211_vht_nss_mcs_valid(ni,vhtcap) < 0){
                qdf_print("********** FW VHT rate control paramters(iwpriv setrcparams) and STA rx mcs dont match\n");
                return -EINVAL;
            }
            /* Disallow TKIP with VHT  Section 11.5.3 of the P802.11ac/D5.0 */
            if (RSN_CIPHER_IS_TKIP(&ni->ni_rsn)) {
                IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ANY, wh->i_addr2,
                               "deny request, vht rate set mismatch");
#if UMAC_SUPPORT_ACFG
                acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                                        ACFG_REASON_ASSOC_11AC_TKIP_USED);
#endif
                vap->iv_stats.is_rx_assoc_norate++;
                return -EINVAL;
            }

            /* record capabilities, mark node as capable of VHT */
            ieee80211_parse_vhtcap(ni, vhtcap);
            if (vap->iv_ext_nss_capable && ni->ni_ext_nss_support
                && !validate_extnss_vhtcap(&ni->ni_vhtcap)) {
                    IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ANY, wh->i_addr2,
                                   "deny %s request, Invalid supported ch width and ext nss combination");
#if UMAC_SUPPORT_ACFG
                    acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                                            ACFG_REASON_ASSOC_CAP_MISMATCH);
#endif
                    vap->iv_stats.is_rx_assoc_capmismatch++;
                    return -EINVAL;
            }

            if (!ieee80211_setup_vht_rates(ni, vhtcap,
                                      IEEE80211_F_DOFRATE | IEEE80211_F_DOXSECT | IEEE80211_F_DOBRS)) {
                IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ANY, wh->i_addr2,
                               "deny request, vht rate set mismatch");
#if UMAC_SUPPORT_ACFG
                acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                                        ACFG_REASON_ASSOC_RATE_MISMATCH);
#endif
                vap->iv_stats.is_rx_assoc_norate++;
                return -EINVAL;
            }
        } else {
            /*
             * Flush any state from a previous association.
             */
            ni->ni_flags &= ~IEEE80211_NODE_VHT;
            ni->ni_vhtcap = 0;
        }
    }

    if((IEEE80211_VAP_IS_STRICT_BW_ENABLED(vap)) &&
        ((IEEE80211_VAP_IS_PURE11AC_ENABLED(vap) && ieee80211vap_vhtallowed(vap)) ||
         (IEEE80211_VAP_IS_PURE11N_ENABLED(vap) && !ieee80211vap_vhtallowed(vap)))) {
        enum ieee80211_cwm_width ic_cw_width = ic->ic_cwm_get_width(ic);
        u_int8_t chwidth = 0;

        /* Get the current chwidth */
        if (vap->iv_chwidth != IEEE80211_CWM_WIDTHINVALID) {
            chwidth = vap->iv_chwidth;
        } else {
            chwidth = ic_cw_width;
        }
        if(ni->ni_chwidth != chwidth) {
            IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ANY, wh->i_addr2,
                    "deny request, station bw doesnt match");
#if UMAC_SUPPORT_ACFG
            acfg_assoc_failure_indication_event(vap, (wh->i_addr2),
                                          ACFG_REASON_ASSOC_CHANWIDTH_MISMATCH);
#endif
            return -EINVAL;
        }
    }
    ni->ni_maxrate_legacy = ni->ni_rates.rs_nrates;
    ni->ni_maxrate_ht = ni->ni_htrates.rs_nrates;
    ni->ni_maxrate_vht = 0xff; /* use all valid vht rates */
    /* Update the PHY mode */
    ieee80211_update_ht_vht_phymode(ic, ni);

    if (ic->ic_newassoc != NULL)
        ic->ic_newassoc(ni, 1);

    if (IEEE80211_VAP_IS_PRIVACY_ENABLED(vap)) {
        if (ni->ni_flags & IEEE80211_NODE_AUTH) {
            wlan_authorise_local_peer(vap, ni->ni_macaddr);
        } else {
            IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ASSOC, ni->ni_macaddr,
                                   "Node not authorized!");
            return -EINVAL;
        }
    }

    return 0;
}
#endif /* MESH_PEER_DYNAMIC_UPDATE */
#endif /* MESH_MODE_SUPPORT */

#endif /* UMAC_SUPPORT_AP */
