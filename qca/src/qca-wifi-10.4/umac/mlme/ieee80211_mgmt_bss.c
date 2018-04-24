/*
 * Copyright (c) 2011,2017 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * Copyright (c) 2008, Atheros Communications Inc.
 *
 * 2011 Qualcomm Atheros, Inc.
 * Qualcomm Atheros, Inc. has chosen to take madwifi subject to the BSD license and terms.
 *
 */

#include "ieee80211_mlme_priv.h"
#include "ieee80211_bssload.h"
#include "ieee80211_quiet_priv.h"
#include "htt.h"                    /* HTT_TX_EXT_TID_NONPAUSE */
#include "osif_private.h"

#if UMAC_SUPPORT_AP || UMAC_SUPPORT_IBSS || UMAC_SUPPORT_BTAMP
/*
 * Send a probe response frame.
 * NB: for probe response, the node may not represent the peer STA.
 * We could use BSS node to reduce the memory usage from temporary node.
 */
int
ieee80211_send_proberesp(struct ieee80211_node *ni, u_int8_t *macaddr,
                         const void *optie, const size_t  optielen,
                         struct ieee80211_framing_extractx *extractx)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211_rsnparms *rsn = &vap->iv_rsn;
    wbuf_t wbuf;
    struct ieee80211_frame *wh;
    u_int8_t *frm;
    u_int16_t capinfo;
    int enable_htrates;
    bool add_wpa_ie = true;
    struct ieee80211_bwnss_map nssmap;
    u_int8_t rx_chainmask = ieee80211com_get_rx_chainmask(ic);
#if QCN_IE
    u_int16_t ie_len;
#endif

    qdf_mem_zero(&nssmap, sizeof(nssmap));

    ASSERT(vap->iv_opmode == IEEE80211_M_HOSTAP || vap->iv_opmode == IEEE80211_M_IBSS ||
           vap->iv_opmode == IEEE80211_M_BTAMP);

    /*
     * XXX : This section needs more testing with P2P
     */
    if (!vap->iv_bss) {
        return 0;
    }

    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);
    if (wbuf == NULL) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                          "%s: Error: unable to alloc wbuf of type WBUF_TX_MGMT.\n",
                          __func__);
        return -ENOMEM;
    }

    /* setup the wireless header */
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    ieee80211_send_setup(vap, ni, wh,
                         IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_PROBE_RESP,
                         vap->iv_myaddr, macaddr,
                         ieee80211_node_get_bssid(ni));
    frm = (u_int8_t *)&wh[1];

    /*
     * probe response frame format
     *  [8] time stamp
     *  [2] beacon interval
     *  [2] cabability information
     *  [tlv] ssid
     *  [tlv] supported rates
     *  [tlv] parameter set (FH/DS)
     *  [tlv] parameter set (QUIET)
     *  [tlv] parameter set (IBSS)
     *  [tlv] extended rate phy (ERP)
     *  [tlv] extended supported rates
     *  [tlv] country (if present)
     *  [3] power constraint
     *  [tlv] WPA
     *  [tlv] WME
     *  [tlv] HT Capabilities
     *  [tlv] HT Information
     *      [tlv] Atheros Advanced Capabilities
     */
    OS_MEMZERO(frm, 8);  /* timestamp should be filled later */
    frm += 8;
    *(u_int16_t *)frm = htole16(vap->iv_bss->ni_intval);
    frm += 2;
    if (vap->iv_opmode == IEEE80211_M_IBSS){
        if(ic->ic_softap_enable)
            capinfo = IEEE80211_CAPINFO_ESS;
        else
            capinfo = IEEE80211_CAPINFO_IBSS;
	}
    else
        capinfo = IEEE80211_CAPINFO_ESS;
    if (IEEE80211_VAP_IS_PRIVACY_ENABLED(vap))
        capinfo |= IEEE80211_CAPINFO_PRIVACY;
    if ((ic->ic_flags & IEEE80211_F_SHPREAMBLE) &&
        IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan))
        capinfo |= IEEE80211_CAPINFO_SHORT_PREAMBLE;
    if (ic->ic_flags & IEEE80211_F_SHSLOT)
        capinfo |= IEEE80211_CAPINFO_SHORT_SLOTTIME;
    if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap))
        capinfo |= IEEE80211_CAPINFO_SPECTRUM_MGMT;
    if (ieee80211_vap_rrm_is_set(vap)) {
        capinfo |= IEEE80211_CAPINFO_RADIOMEAS;
    }
    *(u_int16_t *)frm = htole16(capinfo);
    frm += 2;

    frm = ieee80211_add_ssid(frm, vap->iv_bss->ni_essid,
                             vap->iv_bss->ni_esslen);
    frm = ieee80211_add_rates(frm, &vap->iv_bss->ni_rates);

    if (!IEEE80211_IS_CHAN_FHSS(vap->iv_bsschan)) {
        *frm++ = IEEE80211_ELEMID_DSPARMS;
        *frm++ = 1;
        *frm++ = ieee80211_chan2ieee(ic, ic->ic_curchan);
    }

    if (vap->iv_opmode == IEEE80211_M_IBSS) {
        *frm++ = IEEE80211_ELEMID_IBSSPARMS;
        *frm++ = 2;
        *frm++ = 0; *frm++ = 0;     /* TODO: ATIM window */
    }

    if (IEEE80211_IS_COUNTRYIE_ENABLED(ic)) {
        frm = ieee80211_add_country(frm, vap);
    }

    if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap) &&
	(IEEE80211_IS_CHAN_DFS(ic->ic_curchan) ||
          ((IEEE80211_IS_CHAN_11AC_VHT160(ic->ic_curchan) || IEEE80211_IS_CHAN_11AC_VHT80_80(ic->ic_curchan))
                        && IEEE80211_IS_CHAN_DFS_CFREQ2(ic->ic_curchan)))) {
        *frm++ = IEEE80211_ELEMID_PWRCNSTR;
        *frm++ = 1;
        *frm++ = IEEE80211_PWRCONSTRAINT_VAL(vap);
    }

    frm = ieee80211_add_quiet(vap, ic, frm);

#if ATH_SUPPORT_IBSS_DFS
    if (vap->iv_opmode == IEEE80211_M_IBSS) {
        frm =  ieee80211_add_ibss_dfs(frm,vap);
    }
#endif

    if (IEEE80211_IS_CHAN_ANYG(ic->ic_curchan) ||
        IEEE80211_IS_CHAN_11NG(ic->ic_curchan)) {
        frm = ieee80211_add_erp(frm, ic);
    }

    /*
     * check if os shim has setup RSN IE it self.
     */
    IEEE80211_VAP_LOCK(vap);
    if (vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBERESP].length) {
        add_wpa_ie = ieee80211_check_wpaie(vap, vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBERESP].ie,
                                           vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBERESP].length);
    }
    /*
     * Check if RSN ie is present in probe response frame. Traverse the linked list
     * and check for RSN IE.
     * If not present, add it in the driver
     */
    add_wpa_ie=ieee80211_mlme_app_ie_check_wpaie(vap,IEEE80211_FRAME_TYPE_PROBERESP);
    if (vap->iv_opt_ie.length) {
        add_wpa_ie = ieee80211_check_wpaie(vap, vap->iv_opt_ie.ie,
                                           vap->iv_opt_ie.length);
    }
    IEEE80211_VAP_UNLOCK(vap);

#if ATH_SUPPORT_HS20
    if (add_wpa_ie && !vap->iv_osen) {
#else
    if (add_wpa_ie) {
#endif
        if (RSN_AUTH_IS_RSNA(rsn))
            frm = ieee80211_setup_rsn_ie(vap, frm);
    }

#if ATH_SUPPORT_WAPI
    if (RSN_AUTH_IS_WAI(rsn))
        frm = ieee80211_setup_wapi_ie(vap, frm);
#endif

    frm = ieee80211_add_xrates(frm, &vap->iv_bss->ni_rates);

    frm = ieee80211_add_bssload(frm, ni);

    /* Add rrm capbabilities, if supported */
    frm = ieee80211_add_rrm_cap_ie(frm, ni);

    enable_htrates = ieee80211vap_htallowed(vap);

    if (ieee80211_vap_wme_is_set(vap) &&
        (IEEE80211_IS_CHAN_11AC(ic->ic_curchan) || IEEE80211_IS_CHAN_11N(ic->ic_curchan)) &&
        enable_htrates) {
        frm = ieee80211_add_htcap(frm, ni, IEEE80211_FC0_SUBTYPE_PROBE_RESP);

        frm = ieee80211_add_htinfo(frm, ni);

        if (!(ic->ic_flags & IEEE80211_F_COEXT_DISABLE)) {
            frm = ieee80211_add_obss_scan(frm, ni);
        }
    }

    /* Add extended capbabilities, if applicable */
    frm = ieee80211_add_extcap(frm, ni);

    /*  VHT capable  */
      /* Add vht cap for 2.4G mode, if 256QAM is enabled */
    if (ieee80211_vap_wme_is_set(vap) &&
        (IEEE80211_IS_CHAN_11AC(ic->ic_curchan) || IEEE80211_IS_CHAN_11NG(ic->ic_curchan)) &&
        ieee80211vap_vhtallowed(vap)) {

        /* Add VHT capabilities IE */
        if (ASSOCWAR160_IS_VHT_CAP_CHANGE(vap->iv_cfg_assoc_war_160w))
            frm = ieee80211_add_vhtcap(frm, ni, ic,
                    IEEE80211_FC0_SUBTYPE_PROBE_RESP, extractx, macaddr);
        else
            frm = ieee80211_add_vhtcap(frm, ni, ic,
                    IEEE80211_FC0_SUBTYPE_PROBE_RESP, NULL, macaddr);

        /* Add VHT Operation IE */
        frm = ieee80211_add_vhtop(frm, ni, ic, IEEE80211_FC0_SUBTYPE_PROBE_RESP, extractx);

        /* Add VHT TX power Envelope IE */
        if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap)) {
            frm = ieee80211_add_vht_txpwr_envlp(frm, ni, ic, IEEE80211_FC0_SUBTYPE_PROBE_RESP,
                                                         !IEEE80211_VHT_TXPWR_IS_SUB_ELEMENT);
            /* If iv_chanchange_count is non zero and ic_chanchange_channel is not null,
               it means vap is in chan/ch_width switch period */
            if(vap->iv_chanchange_count && (ic->ic_chanchange_channel != NULL)) {
                frm = ieee80211_add_chan_switch_wrp(frm, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON,
                                                                  IEEE80211_VHT_EXTCH_SWITCH);
            }
        }
    }

    if (add_wpa_ie) {
        if (RSN_AUTH_IS_WPA(rsn))
            frm = ieee80211_setup_wpa_ie(vap, frm);
    }

    if (ieee80211_vap_wme_is_set(vap) &&
        (vap->iv_opmode == IEEE80211_M_HOSTAP || vap->iv_opmode == IEEE80211_M_BTAMP)) /* don't support WMM in ad-hoc for now */
        frm = ieee80211_add_wme_param(frm, &vap->iv_wmestate, IEEE80211_VAP_IS_UAPSD_ENABLED(vap));

    if (ieee80211_vap_wme_is_set(vap) &&
        (IEEE80211_IS_CHAN_11AC(ic->ic_curchan) || IEEE80211_IS_CHAN_11N(ic->ic_curchan)) &&
        (IEEE80211_IS_HTVIE_ENABLED(ic)) && enable_htrates) {
        frm = ieee80211_add_htcap_vendor_specific(frm, ni, IEEE80211_FC0_SUBTYPE_PROBE_RESP);
        frm = ieee80211_add_htinfo_vendor_specific(frm, ni);
    }
    if (vap->iv_ena_vendor_ie == 1) {
	    if (vap->iv_bss->ni_ath_flags) {
		    frm = ieee80211_add_athAdvCap(frm, vap->iv_bss->ni_ath_flags,
				    vap->iv_bss->ni_ath_defkeyindex);
	    } else {
		    frm = ieee80211_add_athAdvCap(frm, 0, IEEE80211_INVAL_DEFKEY);
	    }
    }
    /* Insert ieee80211_ie_ath_extcap IE to beacon */
    if (ic->ic_ath_extcap)
        frm = ieee80211_add_athextcap(frm, ic->ic_ath_extcap, ic->ic_weptkipaggr_rxdelim);

    if(!(vap->iv_ext_nss_support) && !(ic->ic_disable_bwnss_adv) && !ieee80211_get_bw_nss_mapping(vap, &nssmap, rx_chainmask))  {
        frm = ieee80211_add_bw_nss_maping(frm, &nssmap);
    }


    IEEE80211_VAP_LOCK(vap);
    if (vap->iv_opt_ie.length) {
        OS_MEMCPY(frm, vap->iv_opt_ie.ie,
                  vap->iv_opt_ie.length);
        frm += vap->iv_opt_ie.length;
    }

    if (vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBERESP].length) {
        OS_MEMCPY(frm, vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBERESP].ie,
                  vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBERESP].length);
        frm += vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBERESP].length;
    }

    /* Add the Application IE's */
    frm = ieee80211_mlme_app_ie_append(vap, IEEE80211_FRAME_TYPE_PROBERESP, frm);
    IEEE80211_VAP_UNLOCK(vap);

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



    if (ieee80211_vap_mbo_check(vap) || ieee80211_vap_oce_check(vap)) {
        frm = ieee80211_setup_mbo_ie(IEEE80211_FC0_SUBTYPE_PROBE_RESP, vap, frm, ni);
    }

    if (optie != NULL && optielen != 0) {
        OS_MEMCPY(frm, optie, optielen);
        frm += optielen;
    }

    wbuf_set_pktlen(wbuf, (frm - (u_int8_t *)wbuf_header(wbuf)));
    if (extractx->datarate) {
        if (extractx->datarate == 6000)       /* 6 Mbps */
            wbuf_set_tx_rate(wbuf, 0, RATECODE_PREAM_OFDM, 3);
        else if (extractx->datarate == 5500)  /* 5.5 Mbps */
            wbuf_set_tx_rate(wbuf, 0, RATECODE_PREAM_CCK, 1);
        else if (extractx->datarate == 2000)  /* 2 Mbps */
            wbuf_set_tx_rate(wbuf, 0, RATECODE_PREAM_CCK, 2);
        else                                  /* 1 Mbps */
            wbuf_set_tx_rate(wbuf, 0, RATECODE_PREAM_CCK, 3);

		/* tid should be set to HTT_TX_EXT_TID_NONPAUSE to apply tx_rate */
        wbuf_set_tid(wbuf, HTT_TX_EXT_TID_NONPAUSE/*19*/);
    }

    return ieee80211_send_mgmt(vap,ni, wbuf,true);
}

/* Determine whether probe response needs modification towards 160 MHz width
   association WAR.
 */
static bool
is_assocwar160_reqd_proberesp(struct ieee80211vap *vap,
        struct ieee80211_ie_ssid *probereq_ssid_ie,
        struct ieee80211_ie_vhtcap *sta_vhtcap)
{
    int is_sta_any160cap = 0;

    qdf_assert_always(vap != NULL);
    qdf_assert_always(probereq_ssid_ie != NULL);

    if (((vap->iv_cur_mode != IEEE80211_MODE_11AC_VHT160) &&
                (vap->iv_cur_mode != IEEE80211_MODE_11AC_VHT80_80)) ||
        !vap->iv_cfg_assoc_war_160w) {
        return false;
    }

    /* The WAR is required only for STAs not having any 160/80+80 MHz
     * capability. */
    if (sta_vhtcap == NULL) {
        return true;
    }

    is_sta_any160cap =
        ((sta_vhtcap->vht_cap_info &
            (IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160 |
             IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160 |
             IEEE80211_VHTCAP_SHORTGI_160)) != 0);

    if (is_sta_any160cap) {
        return false;
    }

    return true;
}

int
ieee80211_recv_probereq(struct ieee80211_node *ni, wbuf_t wbuf, int subtype,
                        struct ieee80211_rx_status *rs)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211_frame *wh;
    unsigned int found_vap  = 0;
    unsigned int found_null_bssid = 0;
    int ret = -EINVAL;
    u_int8_t *frm, *efrm;
    u_int8_t *ssid, *rates, *ven;
#if ATH_SUPPORT_HS20
    u_int8_t *iw = NULL, *xcaps = NULL;
    uint8_t empty[IEEE80211_ADDR_LEN] = {0x00,0x00,0x00,0x00,0x00,0x00};
#endif
    u_int8_t nullbssid[IEEE80211_ADDR_LEN] = {0x00,0x00,0x00,0x00,0x00,0x00};
    int snd_prb_resp = 0;
    struct ieee80211_ie_vhtcap *vhtcap = NULL;
    struct ieee80211_framing_extractx extractx;
    u_int8_t dedicated_oui_present = 0;
#if QCN_IE
    u_int8_t *qcn = NULL;

    /*
     * Max-ChannelTime parameter represented in units of TUs
     * 255 used to indicate any duration of more than 254 TUs, or an
     * unspecified or unknown duration.
     */
    u_int8_t channel_time = 0;
    /* Index 0 has version and index 1 has subversion of QCN IE*/
    u_int8_t data[2] = {0};
    u_int8_t is_fils_req = false;
    ktime_t eff_chan_time, bpr_delay;
    struct tasklet_hrtimer *t_bpr_timer = &vap->bpr_timer;
    struct hrtimer *bpr_timer = &t_bpr_timer->timer;
#endif

    OS_MEMZERO(&extractx, sizeof(extractx));
#if ATH_SUPPORT_AP_WDS_COMBO
    if (vap->iv_opmode == IEEE80211_M_STA || !ieee80211_vap_ready_is_set(vap) || vap->iv_no_beacon) {
#else
    if (vap->iv_opmode == IEEE80211_M_STA || !ieee80211_vap_ready_is_set(vap)) {
#endif
        vap->iv_stats.is_rx_mgtdiscard++;   /* XXX stat */
        return -EINVAL;
    }

    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    frm = (u_int8_t *)&wh[1];
    efrm = wbuf_header(wbuf) + wbuf_get_pktlen(wbuf);

    if (IEEE80211_IS_MULTICAST(wh->i_addr2)) {
        /* frame must be directed */
        vap->iv_stats.is_rx_mgtdiscard++;   /* XXX stat */
        return -EINVAL;
    }

    /* Drop mcast Probe requests if Tx buffers availability goes low */
    if ((IEEE80211_IS_MULTICAST(wh->i_addr1)) &&
            (!ic->ic_is_mode_offload(ic)) &&
            (IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan)) &&
            (vap->iv_opmode == IEEE80211_M_HOSTAP))
    {
        u_int32_t txbuf_free_count = 0, nvaps = 0, drop_threshold = 0;

        nvaps = ieee80211_get_num_active_vaps(ic);
        txbuf_free_count = ic->ic_get_txbuf_free(ic);
        if (nvaps > 8)
            drop_threshold = ATH_TXBUF/3;
        else
            drop_threshold = ATH_TXBUF/4;

        if (txbuf_free_count <= drop_threshold)
            goto exit;
    }

#if UMAC_SUPPORT_NAWDS
    /* Skip probe request if configured as NAWDS bridge */
    if(vap->iv_nawds.mode == IEEE80211_NAWDS_STATIC_BRIDGE
		  || vap->iv_nawds.mode == IEEE80211_NAWDS_LEARNING_BRIDGE) {
        return -EINVAL;
    }
#endif
    /*Update node if ni->bssid is NULL*/
    if(!OS_MEMCMP(ni->ni_bssid,nullbssid,IEEE80211_ADDR_LEN))
    {
        ni = ieee80211_ref_bss_node(vap);
        if(ni == NULL) {
            return -EINVAL;
        }

        found_null_bssid = 1;
    }
#if ATH_BAND_STEERING
    ieee80211_bsteering_send_probereq_event(vap, wh->i_addr2, rs->rs_rssi);

    /* If band steering is withholding probes (due to steering being in
     * progress), return here so that the response is not sent.
     */
    if (ieee80211_bsteering_is_probe_resp_wh(vap, wh->i_addr2)) {
        return 0;
    }

    /* If band steering wants to withhold the probe response for configured timeout/count,
     * to force association with 5G band, check and return without sending probe response.
     */
    if (ieee80211_bsteering_is_probe_resp_wh_24g(vap, wh->i_addr2, rs->rs_rssi))
    {
        return 0;
    }
#else
    // To silence compiler warning about unused variable.
    (void) rs;
#endif
    /*
     * prreq frame format
     *  [tlv] ssid
     *  [tlv] supported rates
     *  [tlv] extended supported rates
     *  [tlv] Atheros Advanced Capabilities
     */
    ssid = rates = NULL;
    while (((frm+1) < efrm) && (frm + frm[1] + 1 < efrm)) {
        switch (*frm) {
        case IEEE80211_ELEMID_SSID:
            ssid = frm;
            break;
        case IEEE80211_ELEMID_RATES:
            rates = frm;
            break;
#if ATH_SUPPORT_HS20
        case IEEE80211_ELEMID_XCAPS:
            xcaps = frm;
            break;
        case IEEE80211_ELEMID_INTERWORKING:
            iw = frm;
            break;
#endif
        case IEEE80211_ELEMID_VENDOR:
            if (vap->iv_venie && vap->iv_venie->ven_oui_set) {
                ven = frm;
                if (ven[2] == vap->iv_venie->ven_oui[0] &&
                    ven[3] == vap->iv_venie->ven_oui[1] &&
                    ven[4] == vap->iv_venie->ven_oui[2]) {
                    vap->iv_venie->ven_ie_len = MIN(ven[1] + 2, IEEE80211_MAX_IE_LEN);
                    OS_MEMCPY(vap->iv_venie->ven_ie, ven, vap->iv_venie->ven_ie_len);
                }
            }
            if (isdedicated_cap_oui(frm)) {
                dedicated_oui_present = 1;
            }
            else if ((vhtcap == NULL) &&
                    /*
                     * Standalone-VHT CAP IE outside
                     * of Interop IE
                     * will obviously supercede
                     * VHT CAP inside interop IE
                     */
                    ieee80211vap_11ng_vht_interopallowed(vap) &&
                    isinterop_vht(frm)) {
                /* frm+7 is the location , where 2.4G Interop VHT IE starts */
                vhtcap = (struct ieee80211_ie_vhtcap *) (frm + 7);
            }
#if QCN_IE
            else if(isqcn_oui(frm)) {
                    qcn = frm;
            }
#endif

            if ( snd_prb_resp == 0 ) {
                snd_prb_resp = isorbi_ie(vap, frm);
              }
            break;
        case IEEE80211_ELEMID_VHTCAP:
            vhtcap = (struct ieee80211_ie_vhtcap *)frm;
            break;
#if QCN_IE
        case IEEE80211_ELEMID_EXTENSION:
            if(isfils_req_parm(frm)) {
                is_fils_req = true;
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,"FILS STA found mac[%s] \n",ether_sprintf(wh->i_addr2));
                /* Get the Channel time |IE|LEN|EXT|BITMAP|CHANNEL TIME|..| skip Parameter Control Bitmap */
                if(frm[4]) {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,"FILS Max channel time : %uTU\n",frm[4]);
                    channel_time = frm[4];
                    eff_chan_time = ns_to_ktime(NSEC_PER_MSEC *
                                EFF_CHAN_TIME((channel_time * 1024)/1000, ic->ic_bpr_latency_comp));
                }
                else {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,"FILS STA with invalid IE Ignoring \n");
                }
            }
            break;
#endif
        }
        frm += frm[1] + 2;
    }

    if (frm > efrm) {
        ret = -EINVAL;
        goto exit;
    }

    if (dedicated_oui_present &&
        (vhtcap != NULL) &&
        (le32toh(vhtcap->vht_cap_info) & IEEE80211_VHTCAP_MU_BFORMEE)) {

        ni->dedicated_client = 1;
    }


    IEEE80211_VERIFY_ELEMENT(rates, IEEE80211_RATE_MAXSIZE);
    IEEE80211_VERIFY_ELEMENT(ssid, IEEE80211_NWID_LEN);

    /* update rate and rssi information */
    ni->ni_stats.ns_last_rx_mgmt_rate = rs->rs_datarate;
    ni->ni_stats.ns_rx_mgmt_rssi = rs->rs_rssi;

    IEEE80211_DELIVER_EVENT_RECV_PROBE_REQ(vap, wh->i_addr2, ssid);
    /*
     * XXX bug fix 107944: STA Entry exists in the node table,
     * But the STA want to associate with the other vap,  vap should
     * send the correct proble response to Station.
     *
     */

    if(IEEE80211_MATCH_SSID(vap->iv_bss, ssid)  == 1)  //ssid not match
    {
        struct ieee80211vap *tmpvap = NULL;
        if(ni != vap->iv_bss)
        {
            TAILQ_FOREACH(tmpvap, &(ic)->ic_vaps, iv_next)
            {
                if((tmpvap->iv_opmode == IEEE80211_M_HOSTAP) && (!IEEE80211_MATCH_SSID(tmpvap->iv_bss, ssid)))
                {
                        found_vap = 1;
                        break;
                }
            }
        }
        if(found_vap  == 1)
        {
            ni = ieee80211_ref_bss_node(tmpvap);
            if ( ni ) {
                vap = ni->ni_vap;
            }
        }
        else
        {
            vap->iv_stats.is_rx_ssidmismatch++;
            goto exit;
        }

    }

    if (IEEE80211_VAP_IS_HIDESSID_ENABLED(vap) && (ssid[1] == 0) && !(IEEE80211_VAP_IS_BACKHAUL_ENABLED(vap))) {
        IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
                          wh, ieee80211_mgt_subtype_name[
                              subtype >> IEEE80211_FC0_SUBTYPE_SHIFT],
                          "%s", "no ssid with ssid suppression enabled");
        vap->iv_stats.is_rx_ssidmismatch++; /*XXX*/
        goto exit;
    }

#if DYNAMIC_BEACON_SUPPORT
    /*
     * If probe req received from non associated STA,
     * check the rssi and send probe resp.
     */
    if (vap->iv_dbeacon == 1 && vap->iv_dbeacon_runtime == 1) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "node(%s): rs_rssi %d, iv_dbeacon_rssi_thr: %d \n",
                ether_sprintf(wh->i_addr2),rs->rs_rssi, vap->iv_dbeacon_rssi_thr);
        if (rs->rs_rssi < vap->iv_dbeacon_rssi_thr) {
            /* don't send probe resp if rssi is low. */
            vap->iv_stats.is_rx_mgtdiscard++;
            goto exit;
        }
    }
#endif

#if ATH_SUPPORT_HS20
    if (!IEEE80211_ADDR_EQ(vap->iv_hessid, &empty)) {
        if (iw && !xcaps)
            goto exit;
        if (iw && (xcaps[5] & 0x80)) {
            /* hessid match ? */
            if (iw[1] == 9 && !IEEE80211_ADDR_EQ(iw+5, vap->iv_hessid) && !IEEE80211_ADDR_EQ(iw+5, IEEE80211_GET_BCAST_ADDR(ic)))
                goto exit;
            if (iw[1] == 7 && !IEEE80211_ADDR_EQ(iw+3, vap->iv_hessid) && !IEEE80211_ADDR_EQ(iw+3, IEEE80211_GET_BCAST_ADDR(ic)))
                goto exit;
            /* access_network_type match ? */
            if ((iw[2] & 0xF) != vap->iv_access_network_type && (iw[2] & 0xF) != 0xF)
                goto exit;
        }
    }
#endif

#if QCN_IE
    if (qcn && ni) {
        /*
         * Record qcn parameters for station, mark
         * node as using qcn and record information element
         * for applications that require it.
         */
          ieee80211_parse_qcnie(qcn, wh, ni,data);
    }
#endif
    /*
     * Skip Probe Requests received while the scan algorithm is setting a new
     * channel, or while in a foreign channel.
     * Trying to transmit a frame (Probe Response) during a channel change
     * (which includes a channel reset) can cause a NMI due to invalid HW
     * addresses.
     * Trying to transmit the Probe Response while in a foreign channel
     * wouldn't do us any good either.
     */
    if (ieee80211_scan_can_transmit(ic->ic_scanner) && !vap->iv_special_vap_mode) {
        if (likely(ic->ic_curchan == vap->iv_bsschan)) {
            snd_prb_resp = 1;
        }
#if MESH_MODE_SUPPORT
        if (vap->iv_mesh_vap_mode) {
            snd_prb_resp = 0;
        }
#endif
    }
    if (snd_prb_resp) {
        extractx.fectx_assocwar160_reqd = is_assocwar160_reqd_proberesp(vap,
                (struct ieee80211_ie_ssid *)ssid, vhtcap);

        if (extractx.fectx_assocwar160_reqd) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                              "%s: Applying 160MHz assoc WAR: probe resp to "
                              "STA %s\n",
                              __func__, ether_sprintf(wh->i_addr2));
        }

        if (IEEE80211_IS_CHAN_2GHZ(vap->iv_bsschan) && ieee80211_vap_oce_check(vap)) {
            if (ni && ni->ni_mbo.oce_sta &&
                !IEEE80211_IS_MULTICAST(wh->i_addr1) &&
                (rs->rs_datarate < vap->iv_mgt_rate)) {
                extractx.datarate = rs->rs_datarate;
            }
        }

        if (ni) {
#if QCN_IE
        /* If channel time is not present then send the unicast response immediately */
        if ((is_fils_req || ni->ni_mbo.oce_sta) && channel_time && vap->iv_bpr_enable &&
                IEEE80211_IS_BROADCAST(wh->i_addr1) && IEEE80211_IS_BROADCAST(wh->i_addr3)) {

            if (!hrtimer_active(bpr_timer)) {
                /* If its the first STA sending broadcast probe request, start the timer with
                 * the minimum of user configured delay and the channel time.
                 */
                bpr_delay = ns_to_ktime(NSEC_PER_MSEC * vap->iv_bpr_delay);

                /* Set the bpr_delay to be the minimum of channel time and user configured value */
                if (ktime_to_ns(eff_chan_time) < ktime_to_ns(bpr_delay)) {
                    bpr_delay = eff_chan_time;
                }

                tasklet_hrtimer_start(t_bpr_timer, bpr_delay, HRTIMER_MODE_REL);
                vap->iv_bpr_timer_start_count++;

                IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                    "Start timer: %s | %d | Delay: %d | Beacon: %lld | effchantime: %lld | "
                    " Timer expires: %lld | Timer cb: %d | Enqueued: %d \n", \
                    __func__, __LINE__, vap->iv_bpr_delay, ktime_to_ns(vap->iv_next_beacon_tstamp), \
                    eff_chan_time, ktime_to_ns(ktime_add(ktime_get(),hrtimer_get_remaining(bpr_timer))),
                    hrtimer_callback_running(bpr_timer), hrtimer_is_queued(bpr_timer));
            } else {

                /* For rest of the STA sending broadcast probe requests, if the
                 * timer callback is not running and channel time is less than the remaining
                 * time in the timer, resize the timer to the channel time. Ignore if timer callback
                 * is running as it will be served by the broadcast probe response.
                 */
                if(!hrtimer_callback_running(bpr_timer) &&
                   ktime_to_ns(hrtimer_get_remaining(bpr_timer)) > ktime_to_ns(eff_chan_time)) {

                    hrtimer_forward(bpr_timer, hrtimer_cb_get_time(bpr_timer), eff_chan_time);
                    vap->iv_bpr_timer_resize_count++;

                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                        "Resize timer: %s| %d | Delay: %d | Next beacon tstamp: %lld | effchantime: %lld | "
                        "Timer expires in: %lld | Timer cb: %d | Enqueued: %d\n", \
                        __func__, __LINE__, vap->iv_bpr_delay, ktime_to_ns(vap->iv_next_beacon_tstamp), \
                        eff_chan_time, ktime_to_ns(ktime_add(ktime_get(),hrtimer_get_remaining(bpr_timer))),
                        hrtimer_callback_running(bpr_timer), hrtimer_is_queued(bpr_timer));
                }

            }

        } else if ((is_fils_req || ni->ni_mbo.oce_sta) && channel_time &&
                   (IEEE80211_ADDR_EQ(wh->i_addr1, vap->iv_myaddr) || IEEE80211_ADDR_EQ(wh->i_addr3, vap->iv_myaddr))) {

            /* If STA sends a probe request to the VAP with some channel time, then send unicast
             * response only if there is no beacon to be scheduled before the channel time expires.
             * Otherwise, the beacon will be sent.
             */
            if ((ktime_to_ns(vap->iv_next_beacon_tstamp) - NSEC_PER_MSEC * ic->ic_bcn_latency_comp) >  ktime_to_ns(eff_chan_time)) {
                ieee80211_send_proberesp(ni, wh->i_addr2, NULL, 0, &extractx);

                IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                    "Unicast response sent: %s | %d | Delay: %d | Next beacon tstamp: %lld | effchantime: %lld | "
                    "beacon interval: %d ms | Timer expires in: %lld | Timer cb running: %d\n", \
                    __func__, __LINE__, vap->iv_bpr_delay, ktime_to_ns(vap->iv_next_beacon_tstamp), \
                    eff_chan_time, ic->ic_intval, ktime_to_ns(ktime_add(ktime_get(),hrtimer_get_remaining(bpr_timer))),
                    hrtimer_callback_running(bpr_timer));

            }
        } else
#endif
            {
                ieee80211_send_proberesp(ni, wh->i_addr2, NULL, 0, &extractx);
            }
        }
    }
    else {
        goto exit;
    }

    ret = 0;
exit:
    if(found_vap == 1 || found_null_bssid == 1)
        ieee80211_free_node(ni);

    return ret;
}

#endif
