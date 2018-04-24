/*
 * Copyright (c) 2011,2017 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 *  Copyright (c) 2008 Atheros Communications Inc.
 * All Rights Reserved.
 *
 * 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */
#include <osdep.h>

#include <ieee80211_var.h>
#include <ieee80211_proto.h>
#include <ieee80211_channel.h>
#include <ieee80211_rateset.h>
#include "ieee80211_mlme_priv.h"
#include "ieee80211_bssload.h"
#include "ieee80211_quiet_priv.h"
#include "ieee80211_ucfg.h"
#include "ieee80211_sme_api.h"


#if UMAC_SUPPORT_AP || UMAC_SUPPORT_IBSS || UMAC_SUPPORT_BTAMP
#ifndef NUM_MILLISEC_PER_SEC
#define NUM_MILLISEC_PER_SEC 1000
#endif
/*
 *  XXX: Because OID_DOT11_ENUM_BSS_LIST is queried every 30 seconds,
 *       set the interval of Beacon Store to 30.
 *       This is to make sure the AP(GO)'s own scan_entry always exsits in the scan table.
 *       This is a workaround, a better solution is to add reference counter,
 *       to prevent its own scan_entry been flushed out.
 */
#define INTERVAL_STORE_BEACON 30

#define IEEE80211_TSF_LEN       (8)
/*
 *  XXX: Include an intra-module function from ieee80211_input.c.
 *       When we move regdomain code out to separate .h/.c files
 *       this should go to that .h file.
 */
#if ATH_SUPPORT_IBSS_DFS
static u_int8_t
ieee80211_ibss_dfs_element_enable(struct ieee80211vap *vap, struct ieee80211com *ic)
{
    u_int8_t enable_ibssdfs = 1;

    if (ic->ic_flags & IEEE80211_F_CHANSWITCH) {
        if (!(vap->iv_bsschan->ic_flagext & IEEE80211_CHAN_DFS)) {
            enable_ibssdfs = 0;
        }
    } else {
        if (!(ic->ic_curchan->ic_flagext & IEEE80211_CHAN_DFS)) {
            enable_ibssdfs = 0;
        }
    }

    return enable_ibssdfs;
}
#endif

#if QCN_IE
static void
ieee80211_flag_beacon_sent(struct ieee80211vap *vap) {
    struct ieee80211com *ic = vap->iv_ic;
    struct hrtimer *bpr_hrtimer = &vap->bpr_timer.timer;

    /* If there is a beacon to be scheduled within the timer window,
     * drop the response and cancel the timer. If timer is not active,
     * hrtimer_get_remaining will return a negative value, so the timer
     * expiry will be less than beacon timestamp and timer won't be cancelled.
     * If timer expiry is greater than the beacon timestamp, then timer will
     * be cancelled.
     */

    if (ktime_to_ns(ktime_add(hrtimer_get_remaining(bpr_hrtimer), ktime_get())) >
        ktime_to_ns(vap->iv_next_beacon_tstamp) + ic->ic_bcn_latency_comp * NSEC_PER_MSEC) {

        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
            "Cancel timer: %s| %d | Delay: %d | Next beacon tstamp: %lld | "
            "beacon interval: %d ms | Timer expires in: %lld | Timer cb: %d | Enqueued: %d\n", \
            __func__, __LINE__, vap->iv_bpr_delay, ktime_to_ns(vap->iv_next_beacon_tstamp), \
            ic->ic_intval, ktime_to_ns(ktime_add(ktime_get(), hrtimer_get_remaining(bpr_hrtimer))), \
            hrtimer_callback_running(bpr_hrtimer), hrtimer_is_queued(bpr_hrtimer));

        /* Cancel the timer as beacon is sent instead of a broadcast response */
        hrtimer_cancel(bpr_hrtimer);
        vap->iv_bpr_timer_cancel_count++;
    }

    /* Calculate the next beacon timestamp */
    vap->iv_next_beacon_tstamp = ktime_add_ns(ktime_get(), ic->ic_intval * NSEC_PER_MSEC);

}
#endif /* QCN_IE */

static u_int8_t *
ieee80211_beacon_init(struct ieee80211_node *ni, struct ieee80211_beacon_offsets *bo,
                      u_int8_t *frm)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    u_int16_t capinfo;
    struct ieee80211_rateset *rs = &ni->ni_rates;
    struct ieee80211_rsnparms *rsn = &vap->iv_rsn;
    int enable_htrates;
    bool add_wpa_ie = true, add_ht_ie = false;
    struct ieee80211_bwnss_map nssmap;
#if UMAC_SUPPORT_WNM
    u_int8_t *fmsie = NULL;
    u_int32_t fms_counter_mask = 0;
    u_int8_t fmsie_len = 0;
#endif /* UMAC_SUPPORT_WNM */
    int num_of_rates = 0, num_of_xrates = 0;
    enum ieee80211_phymode mode = wlan_get_desired_phymode(vap);
    struct ieee80211_rateset *rs_op = &(vap->iv_op_rates[mode]);
    u_int8_t rx_chainmask = ieee80211com_get_rx_chainmask(ic);

    qdf_mem_zero(&nssmap, sizeof(nssmap));

    KASSERT(vap->iv_bsschan != IEEE80211_CHAN_ANYC, ("no bss chan"));

    frm += IEEE80211_TSF_LEN; /* Skip TSF field */
    *(u_int16_t *)frm = htole16(ieee80211_node_get_beacon_interval(ni));
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
        IEEE80211_IS_CHAN_2GHZ(vap->iv_bsschan))
        capinfo |= IEEE80211_CAPINFO_SHORT_PREAMBLE;
    if (ic->ic_flags & IEEE80211_F_SHSLOT)
        capinfo |= IEEE80211_CAPINFO_SHORT_SLOTTIME;
    if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap))
        capinfo |= IEEE80211_CAPINFO_SPECTRUM_MGMT;

    if (IEEE80211_VAP_IS_PUREB_ENABLED(vap)) {
        capinfo &= ~IEEE80211_CAPINFO_SHORT_SLOTTIME;
        rs = &ic->ic_sup_rates[IEEE80211_MODE_11B];
    } else if (IEEE80211_VAP_IS_PUREG_ENABLED(vap)) {
        ieee80211_setpuregbasicrates(rs);
    }
    /* set rrm capbabilities, if supported */
    if (ieee80211_vap_rrm_is_set(vap)) {
        capinfo |= IEEE80211_CAPINFO_RADIOMEAS;
    }

    bo->bo_caps = (u_int16_t *)frm;
    *(u_int16_t *)frm = htole16(capinfo);
    frm += 2;
    *frm++ = IEEE80211_ELEMID_SSID;
    if (IEEE80211_VAP_IS_HIDESSID_ENABLED(vap)) {
        *frm++ = 0;
    } else {
        *frm++ = ni->ni_esslen;
        OS_MEMCPY(frm, ni->ni_essid, ni->ni_esslen);
        frm += ni->ni_esslen;
    }

    bo->bo_rates = frm;
    if (vap->iv_flags_ext2 & IEEE80211_FEXT2_BR_UPDATE) {
        frm = ieee80211_add_rates(frm, rs_op);
    }else{
        frm = ieee80211_add_rates(frm, rs);
    }

    /* XXX better way to check this? */
    if (!IEEE80211_IS_CHAN_FHSS(vap->iv_bsschan)) {
        *frm++ = IEEE80211_ELEMID_DSPARMS;
        *frm++ = 1;
        *frm++ = ieee80211_chan2ieee(ic, vap->iv_bsschan);
    }
    bo->bo_tim = frm;

    if (vap->iv_opmode == IEEE80211_M_IBSS) {
        *frm++ = IEEE80211_ELEMID_IBSSPARMS;
        *frm++ = 2;
        *frm++ = 0; *frm++ = 0;        /* TODO: ATIM window */
        bo->bo_tim_len = 0;
	} else {
        struct ieee80211_tim_ie *tie = (struct ieee80211_tim_ie *) frm;

        tie->tim_ie = IEEE80211_ELEMID_TIM;
        tie->tim_len = 4;    /* length */
        tie->tim_count = 0;    /* DTIM count */
        tie->tim_period = vap->iv_dtim_period;    /* DTIM period */
        tie->tim_bitctl = 0;    /* bitmap control */
        tie->tim_bitmap[0] = 0;    /* Partial Virtual Bitmap */
        frm += sizeof(struct ieee80211_tim_ie);
        bo->bo_tim_len = 1;
    }
    bo->bo_tim_trailer = frm;

    if (IEEE80211_IS_COUNTRYIE_ENABLED(ic)) {
        frm = ieee80211_add_country(frm, vap);
    }

    // EV 98655 : PWRCNSTR is after channel switch

    bo->bo_chanswitch = frm;

#if ATH_SUPPORT_IBSS_DFS
    if(vap->iv_ibssdfs_state == IEEE80211_IBSSDFS_CHANNEL_SWITCH)
    {
        frm = ieee80211_add_ibss_csa(frm, vap); /* Add the csa ie when we are in CSA mode */
        ((struct ieee80211_channelswitch_ie *)(bo->bo_chanswitch))->tbttcount =
                                 ic->ic_chanchange_tbtt - vap->iv_chanchange_count;  /* decrement TBTT count */
    }
#endif

    if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap) &&
	 (IEEE80211_IS_CHAN_DFS(vap->iv_bsschan) ||
          ((IEEE80211_IS_CHAN_11AC_VHT160(vap->iv_bsschan) || IEEE80211_IS_CHAN_11AC_VHT80_80(vap->iv_bsschan))
               		&& IEEE80211_IS_CHAN_DFS_CFREQ2(vap->iv_bsschan)))) {
        bo->bo_pwrcnstr = frm;
        *frm++ = IEEE80211_ELEMID_PWRCNSTR;
        *frm++ = 1;
        *frm++ = IEEE80211_PWRCONSTRAINT_VAL(vap);
    }
    else {
         bo->bo_pwrcnstr = 0;
    }

#if ATH_SUPPORT_IBSS_DFS
    if (vap->iv_opmode == IEEE80211_M_IBSS) {
        if (ieee80211_ibss_dfs_element_enable(vap, ic)) {
            ieee80211_build_ibss_dfs_ie(vap);
            bo->bo_ibssdfs = frm;
            frm = ieee80211_add_ibss_dfs(frm, vap);
        } else {
            bo->bo_ibssdfs = NULL;
            OS_MEMZERO(&vap->iv_ibssdfs_ie_data, sizeof(struct ieee80211_ibssdfs_ie));
        }
    }
#endif /* ATH_SUPPORT_IBSS_DFS */

    frm = ieee80211_quiet_beacon_setup(vap, ic, bo, frm);

    enable_htrates = ieee80211vap_htallowed(vap);

    if (IEEE80211_IS_CHAN_ANYG(vap->iv_bsschan) ||
        IEEE80211_IS_CHAN_11NG(vap->iv_bsschan)) {
        bo->bo_erp = frm;
        frm = ieee80211_add_erp(frm, ic);
    } else {
        bo->bo_erp = NULL;
    }

    /*
     * check if os shim has setup RSN IE it self.
     */
    IEEE80211_VAP_LOCK(vap);
    if (vap->iv_app_ie[IEEE80211_FRAME_TYPE_BEACON].length) {
        add_wpa_ie = ieee80211_check_wpaie(vap, vap->iv_app_ie[IEEE80211_FRAME_TYPE_BEACON].ie,
                                           vap->iv_app_ie[IEEE80211_FRAME_TYPE_BEACON].length);
    }
    /*
     * Check if RSN ie is present in the beacon frame. Traverse the linked list
     * and check for RSN IE.
     * If not present, add it in the driver
     */
    add_wpa_ie=ieee80211_mlme_app_ie_check_wpaie(vap,IEEE80211_FRAME_TYPE_BEACON);
    if (vap->iv_opt_ie.length) {
        add_wpa_ie = ieee80211_check_wpaie(vap, vap->iv_opt_ie.ie,
                                           vap->iv_opt_ie.length);
    }
    IEEE80211_VAP_UNLOCK(vap);

    /* XXX: put IEs in the order of element IDs. */
    bo->bo_xrates = frm;
    if (vap->iv_flags_ext2 & IEEE80211_FEXT2_BR_UPDATE) {
        num_of_rates = rs_op->rs_nrates;
        if (num_of_rates > IEEE80211_RATE_SIZE) {
            num_of_xrates = num_of_rates - IEEE80211_RATE_SIZE;
        }
        if(num_of_xrates > 0){
            frm = ieee80211_add_xrates(frm, rs_op);
        }
    }else{
        frm = ieee80211_add_xrates(frm, rs);
    }

    frm = ieee80211_bssload_beacon_setup(vap, ni, bo, frm);

    /* Add rrm capbabilities, if supported */
    frm = ieee80211_add_rrm_cap_ie(frm, ni);

    /*
     * HT cap. check for vap is done in ieee80211vap_htallowed.
     * TBD: remove iv_bsschan check to support multiple channel operation.
     */
    if (ieee80211_vap_wme_is_set(vap) &&
        (IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) || IEEE80211_IS_CHAN_11N(vap->iv_bsschan)) &&
        enable_htrates) {
        add_ht_ie = true;
    }

    if (add_ht_ie) {
        bo->bo_htcap = frm;
        frm = ieee80211_add_htcap(frm, ni, IEEE80211_FC0_SUBTYPE_BEACON);
    }

#if ATH_SUPPORT_HS20
    if (add_wpa_ie && !vap->iv_osen) {
#else
    if (add_wpa_ie) {
#endif
        if (RSN_AUTH_IS_RSNA(rsn))
            frm = ieee80211_setup_rsn_ie(vap, frm);
    }

    if (add_ht_ie) {
        bo->bo_htinfo = frm;
        frm = ieee80211_add_htinfo(frm, ni);
    }

#if ATH_SUPPORT_WAPI
    if (RSN_AUTH_IS_WAI(rsn))
        frm = ieee80211_setup_wapi_ie(vap, frm);
#endif

    if (add_ht_ie) {
        if (!(ic->ic_flags & IEEE80211_F_COEXT_DISABLE)) {
            bo->bo_obss_scan = frm;
            frm = ieee80211_add_obss_scan(frm, ni);
        } else {
            bo->bo_obss_scan = NULL;
        }
    }
    else
    {
        bo->bo_htcap = NULL;
        bo->bo_htinfo = NULL;
        bo->bo_obss_scan = NULL;
    }

    /* Add secondary channel offset element here */
    bo->bo_secchanoffset = frm;

#if UMAC_SUPPORT_WNM
    /* Add WNM specific IEs (like FMS desc...), if supported */
    if (ieee80211_vap_wnm_is_set(vap) && ieee80211_wnm_fms_is_set(vap->wnm)) {
        bo->bo_fms_desc = frm;
        ieee80211_wnm_setup_fmsdesc_ie(ni, 0, &fmsie, &fmsie_len, &fms_counter_mask);
        if (fmsie_len)
            OS_MEMCPY(frm, fmsie, fmsie_len);
        frm += fmsie_len;
        bo->bo_fms_trailer = frm;
        bo->bo_fms_len = (u_int16_t)(frm - bo->bo_fms_desc);
    }
    else
    {
        bo->bo_fms_desc = NULL;
        bo->bo_fms_len = 0;
        bo->bo_fms_trailer = NULL;
    }
#endif /* UMAC_SUPPORT_WNM */

     /* Add extended capbabilities, if applicable */
        bo->bo_extcap = frm;
        frm = ieee80211_add_extcap(frm, ni);

    /*
     * VHT capable :
     */
    /* Add VHT cap if device is in 11ac operating mode (or)
	256QAM is enabled in 2.4G */
    if (ieee80211_vap_wme_is_set(vap) &&
        (IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) || IEEE80211_IS_CHAN_11NG(vap->iv_bsschan)) &&
            ieee80211vap_vhtallowed(vap)) {
        /* Add VHT capabilities IE */
        bo->bo_vhtcap = frm;
        frm = ieee80211_add_vhtcap(frm, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON, NULL, NULL);

        /* Add VHT Operation IE */
        bo->bo_vhtop = frm;
        frm = ieee80211_add_vhtop(frm, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON, NULL);

        /* Add VHT Tx Power Envelope */
        if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap)) {
            bo->bo_vhttxpwr = frm;
            frm = ieee80211_add_vht_txpwr_envlp(frm, ni, ic,
                                        IEEE80211_FC0_SUBTYPE_BEACON,
                                        !IEEE80211_VHT_TXPWR_IS_SUB_ELEMENT);
            bo->bo_vhtchnsw = frm;
        } else {
            bo->bo_vhttxpwr = NULL;
            bo->bo_vhtchnsw = NULL;
        }
    }
    else
    {
        bo->bo_vhtcap = NULL;
        bo->bo_vhtop = NULL;
        bo->bo_vhttxpwr = NULL;
        bo->bo_vhtchnsw = NULL;
    }

    /* Add VHT Vendor specific IE for
        256QAM support in 2.4G Interop */
    if ((ieee80211_vap_wme_is_set(vap) &&
         IEEE80211_IS_CHAN_11NG(vap->iv_bsschan)) && ieee80211vap_vhtallowed(vap) &&
                                                  ieee80211vap_11ng_vht_interopallowed(vap)) {
        /* Add VHT capabilities IE and VHT OP IE in Vendor specific IE*/
        bo->bo_interop_vhtcap = frm;
        frm = ieee80211_add_interop_vhtcap(frm, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON);
    }
    else
    {
        bo->bo_interop_vhtcap = NULL;
    }

    if (add_wpa_ie) {
        if (RSN_AUTH_IS_WPA(rsn))
            frm = ieee80211_setup_wpa_ie(vap, frm);
    }

    if (ieee80211_vap_wme_is_set(vap) &&
        (vap->iv_opmode == IEEE80211_M_HOSTAP ||
#if ATH_SUPPORT_IBSS_WMM
         vap->iv_opmode == IEEE80211_M_IBSS ||
#endif
         vap->iv_opmode == IEEE80211_M_BTAMP)) {

        bo->bo_wme = frm;
        frm = ieee80211_add_wme_param(frm, &vap->iv_wmestate, IEEE80211_VAP_IS_UAPSD_ENABLED(vap));
        vap->iv_flags &= ~IEEE80211_F_WMEUPDATE;
    }
    else
    {
        bo->bo_wme = NULL;
    }

    if ((IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) ||
         IEEE80211_IS_CHAN_11N(vap->iv_bsschan)) && IEEE80211_IS_HTVIE_ENABLED(ic) && enable_htrates) {
        frm = ieee80211_add_htcap_vendor_specific(frm, ni,IEEE80211_FC0_SUBTYPE_BEACON);

        bo->bo_htinfo_vendor_specific = frm;
        frm = ieee80211_add_htinfo_vendor_specific(frm, ni);
    }
    else
    {
        bo->bo_htinfo_vendor_specific = NULL;
    }

    bo->bo_ath_caps = frm;
    if (vap->iv_ena_vendor_ie == 1) {
	    if (vap->iv_bss && vap->iv_bss->ni_ath_flags) {
		    frm = ieee80211_add_athAdvCap(frm, vap->iv_bss->ni_ath_flags,
				    vap->iv_bss->ni_ath_defkeyindex);
	    } else {
		    frm = ieee80211_add_athAdvCap(frm, 0, IEEE80211_INVAL_DEFKEY);
	    }
	vap->iv_update_vendor_ie = 0;
    }

#if QCN_IE
    /* Add QCN IE for the feature set */
    bo->bo_qcn_ie = frm;
    frm = ieee80211_add_qcn_info_ie(frm, vap, &bo->bo_qcn_ie_len, NULL);
#endif

    if(IEEE80211_IS_CSH_OPT_APRIORI_NEXT_CHANNEL_ENABLED(ic) && IEEE80211_IS_CHAN_DFS(ic->ic_curchan) && ic->ic_tx_next_ch)
    {
        bo->bo_apriori_next_channel = frm;
        frm = ieee80211_add_next_channel(frm, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON);
    }
    else
    {
        bo->bo_apriori_next_channel = NULL;
    }

    /* Insert ieee80211_ie_ath_extcap IE to beacon */
    if (ic->ic_ath_extcap)
        frm = ieee80211_add_athextcap(frm, ic->ic_ath_extcap, ic->ic_weptkipaggr_rxdelim);

    /* Send prop IE if EXT NSS is not supported */
    if (!(vap->iv_ext_nss_support) && !(ic->ic_disable_bcn_bwnss_map) && !(ic->ic_disable_bwnss_adv) && !ieee80211_get_bw_nss_mapping(vap, &nssmap, rx_chainmask)) {
        bo->bo_bwnss_map = frm;
        frm = ieee80211_add_bw_nss_maping(frm, &nssmap);
    } else {
        bo->bo_bwnss_map = NULL;
    }

    if (ieee80211_vap_mbo_check(vap) || ieee80211_vap_oce_check(vap)) {
        bo->bo_mbo_cap = frm;
        frm = ieee80211_setup_mbo_ie(IEEE80211_FC0_SUBTYPE_BEACON, vap, frm, ni);
    } else {
        bo->bo_mbo_cap = NULL;
    }

    bo->bo_xr = frm;

    bo->bo_appie_buf = frm;
    bo->bo_appie_buf_len = 0;

    IEEE80211_VAP_LOCK(vap);
    if (vap->iv_opt_ie.length) {
        OS_MEMCPY(frm, vap->iv_opt_ie.ie,
                  vap->iv_opt_ie.length);
        frm += vap->iv_opt_ie.length;
    }

    if (vap->iv_app_ie[IEEE80211_FRAME_TYPE_BEACON].length > 0) {
        OS_MEMCPY(frm,vap->iv_app_ie[IEEE80211_FRAME_TYPE_BEACON].ie,
                  vap->iv_app_ie[IEEE80211_FRAME_TYPE_BEACON].length);
        frm += vap->iv_app_ie[IEEE80211_FRAME_TYPE_BEACON].length;
        bo->bo_appie_buf_len = vap->iv_app_ie[IEEE80211_FRAME_TYPE_BEACON].length;
    }
    else
    {
        bo->bo_appie_buf_len = 0;
    }

    /* Add the Application IE's */
    frm = ieee80211_mlme_app_ie_append(vap, IEEE80211_FRAME_TYPE_BEACON, frm);
    bo->bo_appie_buf_len += vap->iv_app_ie_list[IEEE80211_FRAME_TYPE_BEACON].total_ie_len;
    IEEE80211_VAP_UNLOCK(vap);

    if (IEEE80211_VAP_IS_WDS_ENABLED(vap))
    {
        u_int16_t whcCaps = QCA_OUI_WHC_AP_INFO_CAP_WDS;

        bo->bo_whc_apinfo = frm;

        /* SON mode requires WDS as a prereq */
        if (IEEE80211_VAP_IS_SON_ENABLED(vap)) {
            whcCaps |= QCA_OUI_WHC_AP_INFO_CAP_SON;
        }

        frm = ieee80211_add_whc_ap_info_ie(frm, whcCaps, vap, &bo->bo_whc_apinfo_len);
    }
    bo->bo_tim_trailerlen = frm - bo->bo_tim_trailer;
    bo->bo_chanswitch_trailerlen = frm - bo->bo_chanswitch;
    bo->bo_vhtchnsw_trailerlen = frm - bo->bo_vhtchnsw;
    bo->bo_secchanoffset_trailerlen = frm - bo->bo_secchanoffset;
#if ATH_SUPPORT_IBSS_DFS
    if (vap->iv_opmode == IEEE80211_M_IBSS &&
        (bo->bo_ibssdfs != NULL)) {
        struct ieee80211_ibssdfs_ie * ibss_dfs_ie = (struct ieee80211_ibssdfs_ie *)bo->bo_ibssdfs;
        bo->bo_ibssdfs_trailerlen = frm - (bo->bo_ibssdfs + 2 + ibss_dfs_ie->len);
    }
    else
    {
        bo->bo_ibssdfs_trailerlen = 0;
    }
#endif /* ATH_SUPPORT_IBSS_DFS */
#if UMAC_SUPPORT_WNM
    bo->bo_fms_trailerlen = frm - bo->bo_fms_trailer;
#endif /* UMAC_SUPPORT_WNM */
    return frm;
}

/*
 * Make a copy of the Beacon Frame store for this VAP. NOTE: this copy is not the
 * most recent and is only updated when certain information (listed below) changes.
 *
 * The frame includes the beacon frame header and all the IEs, does not include the 802.11
 * MAC header. Beacon frame format is defined in ISO/IEC 8802-11. The beacon frame
 * should be the up-to-date one used by the driver except that real-time parameters or
 * information elements that vary with data frame flow control or client association status,
 * such as timestamp, radio parameters, TIM, ERP and HT information elements do not
 * need to be accurate.
 *
 */
static void
store_beacon_frame(struct ieee80211vap *vap, u_int8_t *wh, int frame_len)
{

    if (ieee80211_vap_copy_beacon_is_clear(vap)) {
        ASSERT(0);
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
                "ieee80211_vap_copy_beacon_is_clear is true\n");
        return;
    }

    if (vap->iv_beacon_copy_buf == NULL) {
        /* The beacon copy buffer is not allocated yet. */

        vap->iv_beacon_copy_buf = OS_MALLOC(vap->iv_ic->ic_osdev, IEEE80211_RTS_MAX, GFP_KERNEL);
        if (vap->iv_beacon_copy_buf == NULL) {
            /* Unable to allocate the memory */
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY, "%s: Unable to alloc beacon copy buf. Size=%d\n",
                              __func__, IEEE80211_RTS_MAX);
            return;
        }
    }

    ASSERT(frame_len <= IEEE80211_RTS_MAX);
    OS_MEMCPY(vap->iv_beacon_copy_buf, wh, frame_len);
    vap->iv_beacon_copy_len = frame_len;
/*
 *  XXX: When P2P connect, the wireless connection icon will be changed to Red-X,
 *       while the connection is OK.
 *       It is because of the query of OID_DOT11_ENUM_BSS_LIST.
 *       By putting AP(GO)'s own beacon information into the scan table,
 *       that problem can be solved.
 */
    ieee80211_scan_table_update(vap,
                                (struct ieee80211_frame*)wh,
                                frame_len,
                                IEEE80211_FC0_SUBTYPE_BEACON,
                                0,
                                ieee80211_get_current_channel(vap->iv_ic));
}

/*
 * Allocate a beacon frame and fillin the appropriate bits.
 */
wbuf_t
ieee80211_beacon_alloc(struct ieee80211_node *ni,
                       struct ieee80211_beacon_offsets *bo)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf;
    struct ieee80211_frame *wh;
    u_int8_t *frm;

    if (ic && ic->ic_osdev) {
        wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_BEACON, MAX_TX_RX_PACKET_SIZE);
    } else {
        return NULL;
    }

    if (wbuf == NULL)
        return NULL;

    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    wh->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT |
        IEEE80211_FC0_SUBTYPE_BEACON;
    wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
    *(u_int16_t *)wh->i_dur = 0;
    if(ic->ic_softap_enable){
		IEEE80211_ADDR_COPY(ni->ni_bssid, vap->iv_myaddr);
	}
    IEEE80211_ADDR_COPY(wh->i_addr1, IEEE80211_GET_BCAST_ADDR(ic));
    IEEE80211_ADDR_COPY(wh->i_addr2, vap->iv_myaddr);
    IEEE80211_ADDR_COPY(wh->i_addr3, ni->ni_bssid);
    *(u_int16_t *)wh->i_seq = 0;

    frm = (u_int8_t *)&wh[1];

    OS_MEMZERO(frm, IEEE80211_TSF_LEN); /* Clear TSF field */
    frm = ieee80211_beacon_init(ni, bo, frm);

    if (ieee80211_vap_copy_beacon_is_set(vap)) {
        store_beacon_frame(vap, (u_int8_t *)wh, (frm - (u_int8_t *)wh));
    }

    wbuf_set_pktlen(wbuf, (frm - (u_int8_t *) wbuf_header(wbuf)));
    wbuf_set_node(wbuf, ieee80211_ref_node(ni));

    IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_MLME, vap->iv_myaddr,
                       "%s \n", __func__);
    return wbuf;
}


/*
 * Suspend or Resume the transmission of beacon for this SoftAP VAP.
 * @param vap           : vap pointer.
 * @param en_suspend    : boolean flag to enable or disable suspension.
 * @ returns 0 if success, others if failed.
 */
int
ieee80211_mlme_set_beacon_suspend_state(
    struct ieee80211vap *vap,
    bool en_suspend)
{
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;

    ASSERT(mlme_priv != NULL);
    if (en_suspend) {
        mlme_priv->im_beacon_tx_suspend++;
    }
    else {
        mlme_priv->im_beacon_tx_suspend--;
    }
    return 0;
}

bool
ieee80211_mlme_beacon_suspend_state(
    struct ieee80211vap *vap)
{
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;

    ASSERT(mlme_priv != NULL);
    return (mlme_priv->im_beacon_tx_suspend != 0);
}
#if DYNAMIC_BEACON_SUPPORT
void ieee80211_mlme_set_dynamic_beacon_suspend(struct ieee80211vap *vap, bool suspend_beacon)
{
    if (vap->iv_dbeacon_runtime != suspend_beacon) {
        wlan_deauth_all_stas(vap); /* dissociating all associated stations */
    }
    if (!suspend_beacon ) { /* DFS channels */
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "Resume beacon \n");
        qdf_spin_lock_bh(&vap->iv_dbeacon_lock);
        OS_CANCEL_TIMER(&vap->iv_dbeacon_suspend_beacon);
        if (ieee80211_mlme_beacon_suspend_state(vap)) {
            ieee80211_mlme_set_beacon_suspend_state(vap, false);
        }
        vap->iv_dbeacon_runtime = suspend_beacon;
        qdf_spin_unlock_bh(&vap->iv_dbeacon_lock);
    } else { /* non DFS channels */
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "Suspend beacon \n");
        qdf_spin_lock_bh(&vap->iv_dbeacon_lock);
        if (!ieee80211_mlme_beacon_suspend_state(vap)) {
            ieee80211_mlme_set_beacon_suspend_state(vap, true);
        }
        vap->iv_dbeacon_runtime = suspend_beacon;
        qdf_spin_unlock_bh(&vap->iv_dbeacon_lock);
    }
}
#endif
int
ieee80211_bcn_prb_template_update(struct ieee80211_node *ni,
                                   struct ieee80211_bcn_prb_info *templ)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;

    /* If Beacon Tx is suspended, then don't send this beacon */
    if (ieee80211_mlme_beacon_suspend_state(vap)) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
            "%s: skip Tx beacon during to suspend.\n", __func__);
        return -1;
    }

    /* if vap is paused do not send any beacons */
    if (ieee80211_vap_is_paused(vap)) {
        return -1;
    }
    /* Update capabilities bit */
    if (vap->iv_opmode == IEEE80211_M_IBSS)
        templ->caps = IEEE80211_CAPINFO_IBSS;
    else
        templ->caps = IEEE80211_CAPINFO_ESS;
    if (IEEE80211_VAP_IS_PRIVACY_ENABLED(vap))
        templ->caps |= IEEE80211_CAPINFO_PRIVACY;
    if ((ic->ic_flags & IEEE80211_F_SHPREAMBLE) &&
        IEEE80211_IS_CHAN_2GHZ(vap->iv_bsschan))
        templ->caps |= IEEE80211_CAPINFO_SHORT_PREAMBLE;
    if (ic->ic_flags & IEEE80211_F_SHSLOT)
        templ->caps |= IEEE80211_CAPINFO_SHORT_SLOTTIME;
    if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap))
        templ->caps |= IEEE80211_CAPINFO_SPECTRUM_MGMT;

    if (IEEE80211_VAP_IS_PUREB_ENABLED(vap)){
        templ->caps &= ~IEEE80211_CAPINFO_SHORT_SLOTTIME;
    }
    /* set rrm capbabilities, if supported */
    if (ieee80211_vap_rrm_is_set(vap)) {
        templ->caps |= IEEE80211_CAPINFO_RADIOMEAS;
    }

    /* Update ERP Info */
    if (vap->iv_opmode == IEEE80211_M_HOSTAP ||
        vap->iv_opmode == IEEE80211_M_BTAMP) { /* No IBSS Support */
        if (ieee80211_vap_erpupdate_is_set(vap)) {
            if (ic->ic_nonerpsta != 0 )
                templ->erp |= IEEE80211_ERP_NON_ERP_PRESENT;
            if (ic->ic_flags & IEEE80211_F_USEPROT)
                templ->erp |= IEEE80211_ERP_USE_PROTECTION;
            if (ic->ic_flags & IEEE80211_F_USEBARKER)
                templ->erp |= IEEE80211_ERP_LONG_PREAMBLE;
        }
    }

    /* TBD:
     * There are some more elements to be passed from the host
     * HT caps, HT info, Advanced caps, IBSS DFS, WPA, RSN, RRM
     * APP IEs
     */
    return 0;
}

/*
 * Update the dynamic parts of a beacon frame based on the current state.
 */
#if UMAC_SUPPORT_WNM
int
ieee80211_beacon_update(struct ieee80211_node *ni,
                        struct ieee80211_beacon_offsets *bo, wbuf_t wbuf,
                        int mcast, u_int32_t nfmsq_mask)
#else
int
ieee80211_beacon_update(struct ieee80211_node *ni,
                        struct ieee80211_beacon_offsets *bo, wbuf_t wbuf, int mcast)
#endif
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    int len_changed = 0;
    u_int16_t capinfo;
    struct ieee80211_frame *wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    int enable_htrates;
    bool update_beacon_copy = false;
    struct ieee80211_tim_ie *tie = NULL;
	systime_t curr_time = OS_GET_TIMESTAMP();
    static systime_t prev_store_beacon_time;
#if UMAC_SUPPORT_WNM
    u_int32_t fms_counter_mask = 0;
    u_int8_t *fmsie = NULL;
    u_int8_t fmsie_len = 0;
    int is_dtim = 0;
#endif /* UMAC_SUPPORT_WNM */
#if ATH_SUPPORT_IBSS_DFS
    struct ieee80211_ibssdfs_ie *ibss_ie = NULL;
#endif /* ATH_SUPPORT_IBSS_DFS */
    u_int8_t *frm = NULL;
    struct ieee80211vap *tmp_vap = NULL;

	if((curr_time - prev_store_beacon_time)>=INTERVAL_STORE_BEACON * NUM_MILLISEC_PER_SEC){
		update_beacon_copy = true;
		prev_store_beacon_time = curr_time;
	}

#if QCN_IE
    /* If broadcast probe response feature is enabled then flag the current
     * beacon as sent and calculate the next beacon timestamp.
     */
    if (vap->iv_bpr_enable) {
       ieee80211_flag_beacon_sent(vap);
    }
#endif

    /* If Beacon Tx is suspended, then don't send this beacon */
    if (ieee80211_mlme_beacon_suspend_state(vap)) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                          "%s: skip Tx beacon during to suspend.\n", __func__);
        return -1;
    }

    /*
     * if vap is paused do not send any beacons to prevent transmitting beacons on wrong channel.
     */
    if (ieee80211_vap_is_paused(vap)) return -1;

    /* use the non-QoS sequence number space for BSS node */
    /* to avoid sw generated frame sequence the same as H/W generated frame,
     * the value lower than min_sw_seq is reserved for HW generated frame */
    if ((ni->ni_txseqs[IEEE80211_NON_QOS_SEQ]& IEEE80211_SEQ_MASK) < MIN_SW_SEQ){
        ni->ni_txseqs[IEEE80211_NON_QOS_SEQ] = MIN_SW_SEQ;
    }

    *(u_int16_t *)&wh->i_seq[0] =
        htole16(ni->ni_txseqs[IEEE80211_NON_QOS_SEQ] << IEEE80211_SEQ_SEQ_SHIFT);
    ni->ni_txseqs[IEEE80211_NON_QOS_SEQ]++;

    /* If vendor ie enable configuration changed, then reinit the beacon */
    if (vap->iv_update_vendor_ie ) {
        qdf_print("%s reinit beacon as vndor ie confguration chnaged \n",__func__);
        frm = (u_int8_t *) wbuf_header(wbuf) + sizeof(struct ieee80211_frame);
	frm = ieee80211_beacon_init(ni, bo, frm);
	update_beacon_copy = true;
	wbuf_set_pktlen(wbuf, (frm - (u_int8_t *)wbuf_header(wbuf)));
	len_changed = 1;
	vap->iv_update_vendor_ie = 0;
    }

    /* Check if channel change due to CW interference needs to be done.
     * Since this is a drastic channel change, we do not wait for the TBTT interval to expair and
     * do not send Channel change flag in beacon
    */
    if (vap->channel_change_done || vap->appie_buf_updated || vap->iv_doth_updated) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH, "%s: reinit beacon\n", __func__);

        /*
        * NB: iv_bsschan is in the DSPARMS beacon IE, so must set this
        *     prior to the beacon re-init, below.
        */
        frm = (u_int8_t *) wbuf_header(wbuf) + sizeof(struct ieee80211_frame);
        frm = ieee80211_beacon_init(ni, bo, frm);
        update_beacon_copy = true;
        wbuf_set_pktlen(wbuf, (frm - (u_int8_t *)wbuf_header(wbuf)));

        len_changed = 1;
        vap->channel_change_done = 0;
        vap->appie_buf_updated = 0;
        vap->iv_doth_updated = 0;
        if ( ic->cw_inter_found) ic->cw_inter_found = 0;
    }

    IEEE80211_CHAN_CHANGE_LOCK(ic);
    if (!IEEE80211_CHANCHANGE_STARTED_IS_SET(ic) && (ic->ic_flags & IEEE80211_F_CHANSWITCH)) {
        IEEE80211_CHANCHANGE_STARTED_SET(ic);
        IEEE80211_CHANCHANGE_BY_BEACONUPDATE_SET(ic);
    }
    IEEE80211_CHAN_CHANGE_UNLOCK(ic);

    if ((vap->iv_flags & IEEE80211_F_CHANSWITCH) && (vap->iv_chanchange_count == ic->ic_chanchange_tbtt) &&
            IEEE80211_CHANCHANGE_BY_BEACONUPDATE_IS_SET(ic)
#ifdef MAGPIE_HIF_GMAC
        && !ic->ic_chanchange_cnt) {
#else
        ) {
#endif
        u_int8_t *frm;
        struct ieee80211_channel *c;

        vap->iv_chanchange_count = 0;

        IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH, "%s: reinit beacon\n", __func__);

        /*
         * NB: iv_bsschan is in the DSPARMS beacon IE, so must set this
         *     prior to the beacon re-init, below.
         */
        if(!ic->ic_chanchange_channel) {
            c = ieee80211_doth_findchan(vap, ic->ic_chanchange_chan);
            if (c == NULL) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH, "%s: find channel failure\n", __func__);
                return 0;
            }
        }
        else {
            c = ic->ic_chanchange_channel;
        }
        vap->iv_bsschan = c;

#if ATH_SUPPORT_IBSS_DFS
        if(vap->iv_opmode == IEEE80211_M_IBSS) {
            if (IEEE80211_ADDR_EQ(vap->iv_ibssdfs_ie_data.owner, vap->iv_myaddr)) {
                vap->iv_ibssdfs_state = IEEE80211_IBSSDFS_OWNER;
            } else {
                vap->iv_ibssdfs_state = IEEE80211_IBSSDFS_JOINER;
            }
        }
#endif
        frm = (u_int8_t *) wbuf_header(wbuf) + sizeof(struct ieee80211_frame);
        frm = ieee80211_beacon_init(ni, bo, frm);
        update_beacon_copy = true;
        wbuf_set_pktlen(wbuf, (frm - (u_int8_t *)wbuf_header(wbuf)));

        vap->iv_flags &= ~IEEE80211_F_CHANSWITCH;

#ifdef MAGPIE_HIF_GMAC
        vap->iv_chanswitch = 0;
#endif
        ic->ic_flags &= ~IEEE80211_F_CHANSWITCH;
        if(ic->ic_chanchange_chwidth != 0){
            /*Wide Bandwidth Channel Switch for VHT only*/
            /*In this case need to update phymode*/
            u_int32_t chan_flag = ic->ic_chanchange_chanflag;
            enum ieee80211_phymode mode = 0;

            /*Get phymode from chan_flag value */
            if(IEEE80211_IS_CHAN_VHT(ic->ic_curchan)){
                switch(chan_flag){
                case IEEE80211_CHAN_11AC_VHT20:
                    mode = IEEE80211_MODE_11AC_VHT20;
                    break;
                case IEEE80211_CHAN_11AC_VHT40PLUS:
                    mode = IEEE80211_MODE_11AC_VHT40PLUS;
                    break;
                case IEEE80211_CHAN_11AC_VHT40MINUS:
                    mode = IEEE80211_MODE_11AC_VHT40MINUS;
                    break;
                case IEEE80211_CHAN_11AC_VHT80:
                    mode = IEEE80211_MODE_11AC_VHT80;
                    break;
                case IEEE80211_CHAN_11AC_VHT80_80:
                    mode = IEEE80211_MODE_11AC_VHT80_80;
                    break;
                case IEEE80211_CHAN_11AC_VHT160:
                    mode = IEEE80211_MODE_11AC_VHT160;
                    break;
                default:
                    mode = 0;
                }
            }
#if ATH_SUPPORT_11N_CHANWIDTH_SWITCH
            else if(IEEE80211_IS_CHAN_11N(ic->ic_curchan)){
                switch(chan_flag){
                case IEEE80211_CHAN_11NA_HT20:
                    mode = IEEE80211_MODE_11NA_HT20;
                    break;
                case IEEE80211_CHAN_11NA_HT40PLUS:
                    mode = IEEE80211_MODE_11NA_HT40PLUS;
                    break;
                case IEEE80211_CHAN_11NA_HT40MINUS:
                    mode = IEEE80211_MODE_11NA_HT40MINUS;
                    break;
                case IEEE80211_CHAN_11NG_HT20:
                    mode = IEEE80211_MODE_11NG_HT20;
                    break;
                case IEEE80211_CHAN_11NG_HT40PLUS:
                    mode = IEEE80211_MODE_11NG_HT40PLUS;
                    break;
                case IEEE80211_CHAN_11NG_HT40MINUS:
                    mode = IEEE80211_MODE_11NG_HT40MINUS;
                    break;
                default:
                    mode = 0;
                    break;
                }
            }
#endif

            if(mode != 0 && (ic->ic_opmode == IEEE80211_M_HOSTAP)){
                ieee80211_setmode(ic, mode, IEEE80211_M_HOSTAP);
            }
        }

        if (ic->ic_curchan != c) {

            struct ieee80211vap *stavap = NULL;
            enum ieee80211_cwm_width ic_cw_width_prev = ic->ic_cwm_get_width(ic);
            enum ieee80211_cwm_width ic_cw_width;
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                    "%s: Prev Chan=%u New Chan=%u mainsta=%p enh_ind=%u\n",
                    __func__,ic->ic_curchan->ic_ieee,
                    c->ic_ieee,ic->ic_sta_vap,
                    ieee80211_ic_enh_ind_rpt_is_set(ic)
                    );

            /* **** Channel Switch Algorithm **** *
             * New channel Non-DFS:-
             * 1)Do instant channel change for all vaps.
             *
             * New channel DFS:-
             * 1)Bring down the main STA VAP if present. In dependent mode the STA
             *   brings down the AP VAP(s) and, when re-connected, it brings up AP
             *   VAP(s).
             * 2)If main STA is not present or in independent mode, then
             *   do instant channel change for all VAPs. The channel change
             *   takes care of the CAC automatically.
             */

            if(!(IEEE80211_IS_CHAN_DFS(c) ||
                        ((IEEE80211_IS_CHAN_11AC_VHT160(c) || IEEE80211_IS_CHAN_11AC_VHT80_80(c))
                         && IEEE80211_IS_CHAN_DFS_CFREQ2(c)))) {
                /* In Non-DFS case, do instant channel change in both
                 * dependent and Idependent mode
                 */
                ic->ic_prevchan = ic->ic_curchan;
                ic->ic_curchan = c;
                ic_cw_width = ic->ic_cwm_get_width(ic);

		TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
		    if((tmp_vap->iv_opmode == IEEE80211_M_STA) && !ieee80211_vap_ready_is_set(tmp_vap)) {
			STA_VAP_DOWNUP_LOCK(ic);
			/* Only for main STA send the chanswitch complete event */
			if(ic->ic_sta_vap == tmp_vap) {
			    int val=0;
			    wlan_mlme_sm_get_curstate(tmp_vap,IEEE80211_PARAM_CONNECTION_SM_STATE,&val);
			    if(val == WLAN_ASSOC_STATE_TXCHANSWITCH) {
				IEEE80211_DELIVER_EVENT_MLME_TXCHANSWITCH_COMPLETE(tmp_vap,IEEE80211_STATUS_SUCCESS);
			    }
			}
			STA_VAP_DOWNUP_UNLOCK(ic);

		    } else if(tmp_vap->iv_opmode == IEEE80211_M_HOSTAP ||
			    tmp_vap->iv_opmode == IEEE80211_M_STA  ||
			    tmp_vap->iv_opmode == IEEE80211_M_MONITOR) {
			tmp_vap->iv_bsschan = c;
			tmp_vap->iv_des_chan[tmp_vap->iv_des_mode] = c;
			tmp_vap->iv_chanchange_count = 0;
			tmp_vap->iv_flags &= ~IEEE80211_F_CHANSWITCH;
			if (tmp_vap->iv_opmode == IEEE80211_M_STA) {
			    ieee80211_node_set_chan(tmp_vap->iv_bss);
			}

			if (ieee80211_vap_ready_is_set(tmp_vap)) {
			    channel_switch_set_channel(tmp_vap, ic);
			}
			if ((tmp_vap->iv_opmode == IEEE80211_M_HOSTAP) && vap->iv_unit != tmp_vap->iv_unit) {
			    tmp_vap->channel_change_done = 1;
			}
			/* Channel width changed. Update BSS node with the new channel width */
			if((ic_cw_width_prev != ic_cw_width) && (tmp_vap->iv_bss != NULL)) {
			    tmp_vap->iv_bss->ni_chwidth = ic->ic_cwm_get_width(ic);
			    ic->ic_chwidth_change(tmp_vap->iv_bss);
			}
			/* Update new channel and width for associated STA's */
			if (tmp_vap->iv_opmode == IEEE80211_M_HOSTAP) {
			    wlan_iterate_station_list(tmp_vap,
				    ieee80211_node_update_chan_and_phymode, NULL);
			}
		    }
		}
		tmp_vap = NULL;
            } else {
                STA_VAP_DOWNUP_LOCK(ic);
                stavap = ic->ic_sta_vap;
                if(stavap) {
                    int val=0;
                    wlan_mlme_sm_get_curstate(stavap,IEEE80211_PARAM_CONNECTION_SM_STATE,&val);
                    if(val == WLAN_ASSOC_STATE_TXCHANSWITCH) {
                        /* If Channel change is initiated by STAVAP then do not indicate mlme sta
                         * radar detect (in other words do not disconnect the STA) since STA VAP is
                         * trying to come up in a different channel and is doing the Channel Switch,
                         * STA is yet to do CAC+ send probe req+ AUTH to the Root AP.
                         */
                    }
                    else {
                        if (!(ic->ic_repeater_move.state == REPEATER_MOVE_START)) {
                            wlan_scan_table_flush(stavap);
                            /* Disconnect the main sta vap form RootAP, so that in Dependent mode
                             * AP vap(s) automatically goes down. Main sta vap scans and connects
                             * to the RootAP in the new channel.
                             */
                            mlme_indicate_sta_radar_detect(stavap->iv_bss);
                        }
                    }
                }
                if(ieee80211_ic_enh_ind_rpt_is_set(ic) || !stavap || (ic->ic_repeater_move.state == REPEATER_MOVE_START)) {
                    STA_VAP_DOWNUP_UNLOCK(ic);
                    /* In Enh_Independent mode or AP only case, do instant channel change */
                    ic->ic_prevchan = ic->ic_curchan;
                    ic->ic_curchan = c;
                    ic_cw_width = ic->ic_cwm_get_width(ic);

                    TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
                        if(tmp_vap->iv_opmode == IEEE80211_M_HOSTAP ||
                                tmp_vap->iv_opmode == IEEE80211_M_MONITOR ||
                                tmp_vap->iv_opmode == IEEE80211_M_STA) {
                                tmp_vap->iv_bsschan = c;
                                tmp_vap->iv_des_chan[tmp_vap->iv_des_mode] = c;
                                tmp_vap->iv_chanchange_count = 0;
                                tmp_vap->iv_flags &= ~IEEE80211_F_CHANSWITCH;
                                if (ieee80211_vap_ready_is_set(tmp_vap)){
                                    channel_switch_set_channel(tmp_vap, ic);
                                }
                                if ((tmp_vap->iv_opmode == IEEE80211_M_HOSTAP) && vap->iv_unit != tmp_vap->iv_unit) {
                                    tmp_vap->channel_change_done = 1;
                                }
                                /* Channel width changed. Update BSS node with the new channel width */
                                if((ic_cw_width_prev != ic_cw_width) && (tmp_vap->iv_bss != NULL)) {
                                    tmp_vap->iv_bss->ni_chwidth = ic->ic_cwm_get_width(ic);
                                    ic->ic_chwidth_change(tmp_vap->iv_bss);
                                }
                                /* Update new channel and width for associated STA's */
                                if (tmp_vap->iv_opmode == IEEE80211_M_HOSTAP) {
                                    wlan_iterate_station_list(tmp_vap,
                                            ieee80211_node_update_chan_and_phymode, NULL);
                                }
                        }
                    }
                    tmp_vap = NULL;
                } else {
                    STA_VAP_DOWNUP_UNLOCK(ic);
                }

                STA_VAP_DOWNUP_LOCK(ic);
                stavap = ic->ic_sta_vap;
                if(stavap) {
                    /* Only for main STA send the chanswitch complete event */
                    int val=0;
                    wlan_mlme_sm_get_curstate(stavap,IEEE80211_PARAM_CONNECTION_SM_STATE,&val);
                    if(val == WLAN_ASSOC_STATE_TXCHANSWITCH) {
                        IEEE80211_DELIVER_EVENT_MLME_TXCHANSWITCH_COMPLETE(stavap,IEEE80211_STATUS_SUCCESS);
                    }
                }
                STA_VAP_DOWNUP_UNLOCK(ic);
            }
        }

        /* Resetting VHT channel change variables */
        ic->ic_chanchange_channel = NULL;
        ic->ic_chanchange_chwidth = 0;
        IEEE80211_CHAN_SWITCH_END(ic);

        IEEE80211_CHANCHANGE_STARTED_CLEAR(ic);
        IEEE80211_CHANCHANGE_BY_BEACONUPDATE_CLEAR(ic);

        len_changed = 1;
    }

    /* XXX faster to recalculate entirely or just changes? */
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
        IEEE80211_IS_CHAN_2GHZ(vap->iv_bsschan))
        capinfo |= IEEE80211_CAPINFO_SHORT_PREAMBLE;
    if (ic->ic_flags & IEEE80211_F_SHSLOT)
        capinfo |= IEEE80211_CAPINFO_SHORT_SLOTTIME;
    if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap))
        capinfo |= IEEE80211_CAPINFO_SPECTRUM_MGMT;

    if (IEEE80211_VAP_IS_PUREB_ENABLED(vap)){
        capinfo &= ~IEEE80211_CAPINFO_SHORT_SLOTTIME;
    }
    /* set rrm capbabilities, if supported */
    if (ieee80211_vap_rrm_is_set(vap)) {
        capinfo |= IEEE80211_CAPINFO_RADIOMEAS;
    }
    *bo->bo_caps = htole16(capinfo);

    /* update basic rates if changed */
    if (vap->iv_flags_ext2 & IEEE80211_FEXT2_BR_UPDATE) {
        frm = (u_int8_t *) wbuf_header(wbuf) + sizeof(struct ieee80211_frame);
        frm = ieee80211_beacon_init(ni, bo, frm);
        update_beacon_copy = true;
        wbuf_set_pktlen(wbuf, (frm - (u_int8_t *)wbuf_header(wbuf)));

        len_changed = 1;

        vap->iv_flags_ext2 &= ~IEEE80211_FEXT2_BR_UPDATE;
    }
	if(vap->iv_flags_ext2 & IEEE80211_FEXT2_MBO)
	{
		frm = (u_int8_t *) wbuf_header(wbuf) + sizeof(struct ieee80211_frame);
		frm = ieee80211_beacon_init(ni, bo, frm);
		update_beacon_copy = true;
		wbuf_set_pktlen(wbuf, (frm - (u_int8_t *)wbuf_header(wbuf)));
		len_changed = 1;
		vap->iv_flags_ext2 &= ~IEEE80211_FEXT2_MBO;
	}

    if (ieee80211_vap_wme_is_set(vap) &&
#if ATH_SUPPORT_IBSS_WMM
        (vap->iv_opmode == IEEE80211_M_HOSTAP || vap->iv_opmode == IEEE80211_M_IBSS)) {
#else
        vap->iv_opmode == IEEE80211_M_HOSTAP) {
#endif
        struct ieee80211_wme_state *wme = &vap->iv_wmestate;

        /* XXX multi-bss */
        if ((vap->iv_flags & IEEE80211_F_WMEUPDATE) && (bo->bo_wme)) {
            (void) ieee80211_add_wme_param(bo->bo_wme, wme, IEEE80211_VAP_IS_UAPSD_ENABLED(vap));
            update_beacon_copy = true;
            vap->iv_flags &= ~IEEE80211_F_WMEUPDATE;
        }
    }

    if (bo->bo_pwrcnstr &&
        ieee80211_ic_doth_is_set(ic) &&
        ieee80211_vap_doth_is_set(vap) &&
	(IEEE80211_IS_CHAN_DFS(vap->iv_bsschan) ||
          ((IEEE80211_IS_CHAN_11AC_VHT160(vap->iv_bsschan) || IEEE80211_IS_CHAN_11AC_VHT80_80(vap->iv_bsschan))
                        && IEEE80211_IS_CHAN_DFS_CFREQ2(vap->iv_bsschan)))) {
        u_int8_t *pwrcnstr = bo->bo_pwrcnstr;
        *pwrcnstr++ = IEEE80211_ELEMID_PWRCNSTR;
        *pwrcnstr++ = 1;
        *pwrcnstr++ = IEEE80211_PWRCONSTRAINT_VAL(vap);
    }

    ieee80211_quiet_beacon_update(vap, ic, bo);

    /* Update channel utilization information */
#if UMAC_SUPPORT_BSSLOAD
    ieee80211_beacon_chanutil_update(vap);
#elif UMAC_SUPPORT_CHANUTIL_MEASUREMENT
    if (vap->iv_chanutil_enab) {
        ieee80211_beacon_chanutil_update(vap);
    }
#endif /* UMAC_SUPPORT_BSSLOAD */

    ieee80211_bssload_beacon_update(vap, ni, bo);

    enable_htrates = ieee80211vap_htallowed(vap);

    /*
     * HT cap. check for vap is done in ieee80211vap_htallowed.
     * TBD: remove iv_bsschan check to support multiple channel operation.
     */
    if (ieee80211_vap_wme_is_set(vap) &&
        (IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) || IEEE80211_IS_CHAN_11N(vap->iv_bsschan)) &&
        enable_htrates && bo->bo_htinfo != NULL && bo->bo_htcap != NULL) {
        struct ieee80211_ie_htinfo_cmn *htinfo;
        struct ieee80211_ie_obss_scan *obss_scan;
#if IEEE80211_BEACON_NOISY
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_11N,
                          "%s: AP: updating HT Info IE (ANA) for %s\n",
                          __func__, ether_sprintf(ni->ni_macaddr));
		if (bo->bo_htinfo[0] != IEEE80211_ELEMID_HTINFO_ANA) {
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_11N,
                              "%s: AP: HT Info IE (ANA) beacon offset askew %s "
                              "expected 0x%02x, found 0x%02x\n",
                              __func__, ether_sprintf(ni->ni_macaddr),
                              IEEE80211_ELEMID_HTINFO_ANA, bo->bo_htinfo[0] );
		}
#endif
        htinfo = &((struct ieee80211_ie_htinfo *)bo->bo_htinfo)->hi_ie;
        ieee80211_update_htinfo_cmn(htinfo, ni);

        ieee80211_add_htcap(bo->bo_htcap, ni, IEEE80211_FC0_SUBTYPE_BEACON);

        if (!(ic->ic_flags & IEEE80211_F_COEXT_DISABLE)) {
            obss_scan = (struct ieee80211_ie_obss_scan *)bo->bo_obss_scan;
             if(obss_scan)
                ieee80211_update_obss_scan(obss_scan, ni);
        }

        if (IEEE80211_IS_HTVIE_ENABLED(ic) && (bo->bo_htinfo_vendor_specific)) {
#if IEEE80211_BEACON_NOISY
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_11N,
                              "%s: AP: updating HT Info IE (Vendor Specific) for %s\n",
                              __func__, ether_sprintf(ni->ni_macaddr));
			if (bo->bo_htinfo_vendor_specific[5] != IEEE80211_ELEMID_HTINFO_VENDOR) {
				IEEE80211_DPRINTF(vap, IEEE80211_MSG_11N,
                                  "%s: AP: HT Info IE (Vendor Specific) beacon offset askew %s ",
                                  "expected 0x%02x, found 0x%02x\n",
                                  __func__, ether_sprintf(ni->ni_macaddr),
                                  IEEE80211_ELEMID_HTINFO_ANA, bo->bo_htinfo_vendor_specific[5] );
			}
#endif
            htinfo = &((struct vendor_ie_htinfo *)bo->bo_htinfo_vendor_specific)->hi_ie;
            ieee80211_update_htinfo_cmn(htinfo, ni);
        }
    }

    /*
     * VHT capable
     */
    /* Add VHT cap if device is in 11ac operating mode (or)
	256QAM is enabled in 2.4G */
    if (ieee80211_vap_wme_is_set(vap) &&
        (IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) || IEEE80211_IS_CHAN_11NG(vap->iv_bsschan)) &&
        ieee80211vap_vhtallowed(vap) &&
        (bo->bo_vhtcap != NULL) && (bo->bo_vhtop != NULL)) {

        /* Add VHT capabilities IE */
        ieee80211_add_vhtcap(bo->bo_vhtcap, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON, NULL, NULL);

        /* Add VHT Operation IE */
        ieee80211_add_vhtop(bo->bo_vhtop, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON, NULL);

        /* Add VHT Tx POwer Envelope IE */
        if ( bo->bo_vhttxpwr && ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap)) {
            ieee80211_add_vht_txpwr_envlp(bo->bo_vhttxpwr, ni, ic,
                                            IEEE80211_FC0_SUBTYPE_BEACON,
                                            !IEEE80211_VHT_TXPWR_IS_SUB_ELEMENT);
        }
    }

    /* Add VHT Vendor specific IE for
        256QAM support in 2.4G Interop */
    if (ieee80211_vap_wme_is_set(vap) &&
        (IEEE80211_IS_CHAN_11NG(vap->iv_bsschan) || IEEE80211_IS_CHAN_11NG(vap->iv_bsschan))&&
        ieee80211vap_vhtallowed(vap) && ieee80211vap_11ng_vht_interopallowed(vap) &&
        (bo->bo_interop_vhtcap != NULL)) {
        /* Add VHT capabilities IE  and VHT OP IE */
        ieee80211_add_interop_vhtcap(bo->bo_interop_vhtcap, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON);
    }

    if (vap->iv_opmode == IEEE80211_M_HOSTAP || vap->iv_opmode == IEEE80211_M_IBSS) {
        tie = (struct ieee80211_tim_ie *) bo->bo_tim;
        if (IEEE80211_VAP_IS_TIMUPDATE_ENABLED(vap) && vap->iv_opmode == IEEE80211_M_HOSTAP) {
            u_int timlen = 0, timoff = 0, i = 0;
            /*
             * ATIM/DTIM needs updating.  If it fits in the
             * current space allocated then just copy in the
             * new bits.  Otherwise we need to move any trailing
             * data to make room.  Note that we know there is
             * contiguous space because ieee80211_beacon_allocate
             * insures there is space in the wbuf to write a
             * maximal-size virtual bitmap (based on ic_max_aid).
             */
            /*
             * Calculate the bitmap size and offset, copy any
             * trailer out of the way, and then copy in the
             * new bitmap and update the information element.
             * Note that the tim bitmap must contain at least
             * one byte and any offset must be even.
             */
            if (vap->iv_ps_pending != 0) {
                timoff = 128;        /* impossibly large */
                for (i = 0; i < vap->iv_tim_len; i++) {
                    if (vap->iv_tim_bitmap[i]) {
                        timoff = i &~ 1;
                        break;
                    }
                }
                /* remove the assert and do a recovery */
                /* KASSERT(timoff != 128, ("tim bitmap empty!")); */
                if (timoff == 128) {
                    timoff = 0;
                    timlen = 1;
                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Recover in TIM update\n");
                } else {
                    for (i = vap->iv_tim_len-1; i >= timoff; i--) {
                        if (vap->iv_tim_bitmap[i])
                            break;
                    }

                    if (i < timoff) {
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Corrupted tim ie, recover in TIM update, tim_len = %d, i = %d, timoff = %d\n",
                              vap->iv_tim_len, i, timoff);
                        timoff = 0;
                        timlen = 1;
                    } else {
                        timlen = 1 + (i - timoff);
                        /* Resetting the timlen if it goes beyond 68 limit
                           (64 + 4 The 64 is to support 512 client 4 is a gaurd band */
                        if (timlen > 68) {
                            timoff = 0;
                            timlen = 1;
                            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Recover in TIM update Invalid TIM length\n");
                        }
                    }
                }
            } else {
                timoff = 0;
                timlen = 1;
            }
            tie->tim_bitctl = timoff;
            if (timlen != bo->bo_tim_len) {
                int trailer_adjust = (tie->tim_bitmap+timlen) - bo->bo_tim_trailer;
                /* copy up/down trailer */
                OS_MEMMOVE(tie->tim_bitmap+timlen, bo->bo_tim_trailer,
                          bo->bo_tim_trailerlen);
                bo->bo_tim_trailer = tie->tim_bitmap+timlen;
                bo->bo_chanswitch += trailer_adjust;
                if (bo->bo_pwrcnstr) {
                    bo->bo_pwrcnstr += trailer_adjust;
                }
                bo->bo_quiet += trailer_adjust;
                if (bo->bo_wme) {
                    bo->bo_wme += trailer_adjust;
                }
                if (bo->bo_erp) {
                    bo->bo_erp += trailer_adjust;
                }
                bo->bo_ath_caps += trailer_adjust;

                if (bo->bo_apriori_next_channel) {
                    bo->bo_apriori_next_channel += trailer_adjust;
                }

                bo->bo_appie_buf += trailer_adjust;
                if(bo->bo_whc_apinfo) {
                    bo->bo_whc_apinfo += trailer_adjust;
                }
#if QCN_IE
                if(bo->bo_qcn_ie) {
                    bo->bo_qcn_ie += trailer_adjust;
                }
#endif
                bo->bo_xr += trailer_adjust;
                bo->bo_secchanoffset += trailer_adjust;
#if ATH_SUPPORT_IBSS_DFS
                bo->bo_ibssdfs += trailer_adjust;
#endif /* ATH_SUPPORT_IBSS_DFS */
                if(bo->bo_htinfo != NULL && bo->bo_htcap != NULL)
                {
                    bo->bo_htinfo += trailer_adjust;
                    bo->bo_htcap += trailer_adjust;
                }
                bo->bo_htinfo_pre_ana += trailer_adjust;
                if (bo->bo_htinfo_vendor_specific) {
                    bo->bo_htinfo_vendor_specific += trailer_adjust;
                }
                bo->bo_extcap += trailer_adjust;
                if(bo->bo_obss_scan)
                    bo->bo_obss_scan += trailer_adjust;
                bo->bo_bssload += trailer_adjust;
#if UMAC_SUPPORT_WNM
                if (bo->bo_fms_desc) {
                    bo->bo_fms_desc += trailer_adjust;
                }
                if (bo->bo_fms_trailer) {
                    bo->bo_fms_trailer += trailer_adjust;
                }
#endif /* UMAC_SUPPORT_WNM */
                if(bo->bo_vhtcap != NULL && bo->bo_vhtop != NULL)
                {
                    bo->bo_vhtcap += trailer_adjust;
                    bo->bo_vhtop += trailer_adjust;
                }
                if(bo->bo_vhttxpwr != NULL)
                    bo->bo_vhttxpwr += trailer_adjust;
                if(bo->bo_vhtchnsw != NULL)
                    bo->bo_vhtchnsw += trailer_adjust;
                if(bo->bo_interop_vhtcap != NULL)
                {
                    bo->bo_interop_vhtcap += trailer_adjust;
                }
                if ( ieee80211_vap_mbo_check(vap) && (bo->bo_mbo_cap) ) {
                    bo->bo_mbo_cap += trailer_adjust;
                }
                if (timlen > bo->bo_tim_len)
                    wbuf_append(wbuf, timlen - bo->bo_tim_len);
                else
                    wbuf_trim(wbuf, bo->bo_tim_len - timlen);
                bo->bo_tim_len = timlen;

                /* update information element */
                tie->tim_len = 3 + timlen;
                len_changed = 1;
			}
            OS_MEMCPY(tie->tim_bitmap, vap->iv_tim_bitmap + timoff,
                      bo->bo_tim_len);

            IEEE80211_VAP_TIMUPDATE_DISABLE(vap);

            IEEE80211_NOTE(vap, IEEE80211_MSG_POWER, ni,
                           "%s: TIM updated, pending %u, off %u, len %u\n",
                           __func__, vap->iv_ps_pending, timoff, timlen);
        }
        if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
        /* count down DTIM period */
        if (tie->tim_count == 0)
            tie->tim_count = tie->tim_period - 1;
        else
            tie->tim_count--;
        /* update state for buffered multicast frames on DTIM */
        if (mcast && (tie->tim_count == 0 || tie->tim_period == 1))
            tie->tim_bitctl |= 1;
        else
            tie->tim_bitctl &= ~1;
#if ATH_SUPPORT_WIFIPOS
        //Enable MCAST bit to wake the station
        if (vap->iv_wakeup & 0x2)
            tie->tim_bitctl |= 1;
#endif
        }
#if UMAC_SUPPORT_WNM
        is_dtim = (tie->tim_count == 0 || tie->tim_period == 1);
#endif /* UMAC_SUPPORT_WNM */
        if (ieee80211_ic_doth_is_set(ic) && (ic->ic_flags & IEEE80211_F_CHANSWITCH) && IEEE80211_CHANCHANGE_BY_BEACONUPDATE_IS_SET(ic)
#ifdef MAGPIE_HIF_GMAC
                && (!vap->iv_chanswitch)) {
#else
        ) {
#endif
            /* Find the new channel if it's not known already */
            if (!(ic->ic_chanchange_channel)) {
                ic->ic_chanchange_channel =
                    ieee80211_doth_findchan(vap, ic->ic_chanchange_chan);
                if(!(ic->ic_chanchange_channel)) {
                    /* Ideally we should not be here, Only reason is that we have a corrupt chan */
                    qdf_print("%s : Error chanchange is NULL: VAP = %d  chan = %d cfreq = %d flags = %d\n",__func__,vap->iv_unit,ic->ic_chanchange_chan,vap->iv_des_cfreq2,(vap->iv_bsschan->ic_flags & IEEE80211_CHAN_ALL));
                }
                else {
                    /* Find secondary 20 offset to advertise in beacon */
                    ic->ic_chanchange_secoffset =
                        ieee80211_sec_chan_offset(ic->ic_chanchange_channel);
                    /* Find destination channel width */
                    ic->ic_chanchange_chwidth =
                        ieee80211_get_chan_width(ic->ic_chanchange_channel);
               }
            }
          }

        if (ieee80211_ic_doth_is_set(ic) && (ic->ic_flags & IEEE80211_F_CHANSWITCH) && (ic->ic_chanchange_channel) &&
                IEEE80211_CHANCHANGE_BY_BEACONUPDATE_IS_SET(ic)
#ifdef MAGPIE_HIF_GMAC
                && (!vap->iv_chanswitch)) {
#else
        ) {
#endif

            struct ieee80211_extendedchannelswitch_ie *ecsa_ie = NULL;
            if (!vap->iv_chanchange_count) {

                u_int8_t* tempbuf;
                u_int8_t csmode = IEEE80211_CSA_MODE_STA_TX_ALLOWED;
                u_int8_t csa_ecsa_len = IEEE80211_CHANSWITCHANN_BYTES;

                vap->iv_flags |= IEEE80211_F_CHANSWITCH;
                vap->channel_switch_state = 1;
                if (bo->bo_chanswitch[0] != IEEE80211_ELEMID_CHANSWITCHANN)
                {
                    if (vap->iv_csmode == IEEE80211_CSA_MODE_AUTO) {
                        /* No user preference for csmode. Use default behavior.
                         * If chan swith is triggered because of radar found,
                         * ask associated stations to stop transmission by
                         * sending csmode as 1 else let them transmit as usual
                         * by sending csmode as 0.
                         */
                        if (ic->ic_flags & IEEE80211_F_DFS_CHANSWITCH_PENDING) {
                            /* Request STA's to stop transmission */
                            csmode = IEEE80211_CSA_MODE_STA_TX_RESTRICTED;
                        }
                    } else {
                        /* User preference for csmode is configured.
                         * Use user preference.
                         */
                        csmode = vap->iv_csmode;
                    }

                    /* check if ecsa IE has to be added.
                     * If yes, adjust csa_ecsa_len to include CSA IE len
                     * and ECSA IE len.
                     */
                    if (vap->iv_enable_ecsaie) {
                        csa_ecsa_len += IEEE80211_EXTCHANSWITCHANN_BYTES;
                        ecsa_ie = (struct ieee80211_extendedchannelswitch_ie *)
                                  ((u_int8_t*) bo->bo_chanswitch + IEEE80211_CHANSWITCHANN_BYTES);
                    }
                /* copy out trailer to open up a slot */
                tempbuf = OS_MALLOC(vap->iv_ic->ic_osdev, bo->bo_chanswitch_trailerlen , GFP_KERNEL);
                OS_MEMCPY(tempbuf,bo->bo_chanswitch, bo->bo_chanswitch_trailerlen);

                OS_MEMCPY(bo->bo_chanswitch + csa_ecsa_len,
                          tempbuf, bo->bo_chanswitch_trailerlen);
                OS_FREE(tempbuf);

                /* add ie in opened slot */
                bo->bo_chanswitch[0] = IEEE80211_ELEMID_CHANSWITCHANN;
                bo->bo_chanswitch[1] = 3; /* fixed length */
                bo->bo_chanswitch[2] = csmode;
                bo->bo_chanswitch[3] = ic->ic_chanchange_chan;
                bo->bo_chanswitch[4] = ic->ic_chanchange_tbtt;

                /* Check for ecsa_ie pointer instead of ic->ic_ecsaie flag
                 * to avoid ic->ic_ecsaie being updated in between from IOCTL
                 * context.
                 */
                if (ecsa_ie) {
                    ecsa_ie->ie = IEEE80211_ELEMID_EXTCHANSWITCHANN;
                    ecsa_ie->len = 4;
                    ecsa_ie->switchmode = csmode;
                    /* If user configured opClass is set, use it else
                     * calculate new opClass from destination channel.
                     */
                    if (vap->iv_ecsa_opclass) {
                        ecsa_ie->newClass = vap->iv_ecsa_opclass;
                    } else {
                        ecsa_ie->newClass =
                            regdmn_get_new_opclass_from_channel(ic, ic->ic_chanchange_channel);
                    }
                    ecsa_ie->newchannel = ic->ic_chanchange_chan;
                    ecsa_ie->tbttcount = ic->ic_chanchange_tbtt;
                }

                /* update the trailer lens */
                bo->bo_chanswitch_trailerlen += csa_ecsa_len;
                bo->bo_quiet += csa_ecsa_len;
#if ATH_SUPPORT_IBSS_DFS
                bo->bo_ibssdfs += csa_ecsa_len;
#endif /* ATH_SUPPORT_IBSS_DFS */
                bo->bo_tim_trailerlen += csa_ecsa_len;
                if (bo->bo_pwrcnstr) {
                    bo->bo_pwrcnstr += csa_ecsa_len;
                }
                bo->bo_quiet += csa_ecsa_len;
                if (bo->bo_wme) {
                    bo->bo_wme += csa_ecsa_len;
                }
                if (bo->bo_erp) {
                    bo->bo_erp += csa_ecsa_len;
                }
                bo->bo_ath_caps += csa_ecsa_len;
                if (bo->bo_apriori_next_channel) {
                    bo->bo_apriori_next_channel += csa_ecsa_len;
                }
                bo->bo_appie_buf += csa_ecsa_len;
                if(bo->bo_whc_apinfo) {
                    bo->bo_whc_apinfo += csa_ecsa_len;
                }
#if QCN_IE
                if(bo->bo_qcn_ie) {
                    bo->bo_qcn_ie += csa_ecsa_len;
                }
#endif

                bo->bo_xr += csa_ecsa_len;
                bo->bo_secchanoffset += csa_ecsa_len;
                if(bo->bo_htinfo != NULL && bo->bo_htcap != NULL)
                {
                    bo->bo_htinfo += csa_ecsa_len;
                    bo->bo_htcap += csa_ecsa_len;
                }
                bo->bo_htinfo_pre_ana += csa_ecsa_len;
                if (bo->bo_htinfo_vendor_specific) {
                    bo->bo_htinfo_vendor_specific += csa_ecsa_len;
                }
                bo->bo_extcap += csa_ecsa_len;
                if(bo->bo_obss_scan)
                    bo->bo_obss_scan += csa_ecsa_len;
                bo->bo_bssload += csa_ecsa_len;
#if UMAC_SUPPORT_WNM
                if (bo->bo_fms_desc) {
                    bo->bo_fms_desc += csa_ecsa_len;
                }
                if (bo->bo_fms_trailer) {
                    bo->bo_fms_trailer += csa_ecsa_len;
                }
#endif /* UMAC_SUPPORT_WNM */
                if(bo->bo_vhtcap != NULL && bo->bo_vhtop != NULL)
                {
                    bo->bo_vhtcap += csa_ecsa_len;
                    bo->bo_vhtop += csa_ecsa_len;
                }
                if(bo->bo_vhttxpwr != NULL)
                    bo->bo_vhttxpwr += csa_ecsa_len;
                if(bo->bo_vhtchnsw != NULL)
                    bo->bo_vhtchnsw += csa_ecsa_len;
                if(bo->bo_interop_vhtcap != NULL )
                {
                    bo->bo_interop_vhtcap += csa_ecsa_len;
                }
                if ( ieee80211_vap_mbo_check(vap) && (bo->bo_mbo_cap) ) {
                    bo->bo_mbo_cap += csa_ecsa_len;
                }

                /* indicate new beacon length so other layers may manage memory */
                wbuf_append(wbuf, csa_ecsa_len);
                    /* indicate new beacon length so other layers may manage memory */
                    len_changed = 1;
                }

                /* Add secondary channel offset element if new channel has
                 * secondary 20 MHz channel
                 */
                if (((IEEE80211_IS_CHAN_11N(vap->iv_bsschan) ||
                    IEEE80211_IS_CHAN_11AC(vap->iv_bsschan)) &&
                    (ic->ic_chanchange_secoffset)) && ic->ic_sec_offsetie) {

                    /* Add secondary channel offset element */
                    struct ieee80211_ie_sec_chan_offset *sec_chan_offset_ie = NULL;
                    tempbuf = OS_MALLOC(vap->iv_ic->ic_osdev, bo->bo_secchanoffset_trailerlen, GFP_KERNEL);

                    if(tempbuf) {
                        OS_MEMCPY(tempbuf,bo->bo_secchanoffset, bo->bo_secchanoffset_trailerlen);
                        OS_MEMCPY(bo->bo_secchanoffset + IEEE80211_SEC_CHAN_OFFSET_BYTES,
                                tempbuf, bo->bo_secchanoffset_trailerlen);
                        OS_FREE(tempbuf);

                        sec_chan_offset_ie = (struct ieee80211_ie_sec_chan_offset *)bo->bo_secchanoffset;
                        sec_chan_offset_ie->elem_id = IEEE80211_ELEMID_SECCHANOFFSET;
                        sec_chan_offset_ie->len = 1;  /* element has only one octet of info */
                        sec_chan_offset_ie->sec_chan_offset = ic->ic_chanchange_secoffset;

                        /* update the pointers following this element and also trailer length */
                        bo->bo_secchanoffset_trailerlen += IEEE80211_SEC_CHAN_OFFSET_BYTES;

                        bo->bo_chanswitch_trailerlen += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                        bo->bo_quiet += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                        bo->bo_tim_trailerlen += IEEE80211_SEC_CHAN_OFFSET_BYTES;
#if ATH_SUPPORT_IBSS_DFS
                        bo->bo_ibssdfs_trailerlen += IEEE80211_SEC_CHAN_OFFSET_BYTES;
#endif /* ATH_SUPPORT_IBSS_DFS */
                        bo->bo_htinfo_pre_ana += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                        if(bo->bo_obss_scan)
                            bo->bo_obss_scan += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                        bo->bo_bssload += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                        bo->bo_extcap += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                        if(bo->bo_vhtcap != NULL && bo->bo_vhtop != NULL)
                        {
                            bo->bo_vhtcap += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                            bo->bo_vhtop += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                        }
                        if(bo->bo_vhttxpwr != NULL)
                            bo->bo_vhttxpwr += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                        if(bo->bo_vhtchnsw != NULL)
                            bo->bo_vhtchnsw += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                        if(bo->bo_interop_vhtcap != NULL )
                        {
                            bo->bo_interop_vhtcap += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                        }
                        if (bo->bo_wme)
                        {
                            bo->bo_wme += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                        }
                        if (bo->bo_htinfo_vendor_specific)
                        {
                            bo->bo_htinfo_vendor_specific += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                        }
                        if (bo->bo_bwnss_map != NULL) {
                            bo->bo_bwnss_map += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                        }
                        bo->bo_ath_caps += IEEE80211_SEC_CHAN_OFFSET_BYTES;

                        if (bo->bo_apriori_next_channel) {
                            bo->bo_apriori_next_channel += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                        }

                        bo->bo_xr += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                        bo->bo_appie_buf += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                        if(bo->bo_whc_apinfo) {
                            bo->bo_whc_apinfo += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                        }
#if QCN_IE
                        if(bo->bo_qcn_ie) {
                            bo->bo_qcn_ie += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                        }
#endif

#if ATH_SUPPORT_IBSS_DFS
                        bo->bo_ibssdfs_trailerlen += IEEE80211_SEC_CHAN_OFFSET_BYTES;
#endif
#if UMAC_SUPPORT_WNM
                        if (bo->bo_fms_desc) {
                            bo->bo_fms_desc += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                        }
                        if (bo->bo_fms_trailer) {
                            bo->bo_fms_trailer += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                        }
#endif /* UMAC_SUPPORT_WNM */
                        /* indicate new beacon length so other layers may manage memory */
                        wbuf_append(wbuf, IEEE80211_SEC_CHAN_OFFSET_BYTES);
                        /* indicate new beacon length so other layers may manage memory */
                        len_changed = 1;
                    }
                } /* end of if IEEE80211_IS_CHAN_11N(vap->iv_bsschan) */

                /* filling channel switch wrapper element */
                if (IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) && ieee80211vap_vhtallowed(vap)
                                             && (ic->ic_chanchange_channel != NULL) && (bo->bo_vhtchnsw != NULL)) {

                      u_int8_t *vhtchnsw_ie, vhtchnsw_ielen;
                      /* copy out trailer to open up a slot */
	                  tempbuf = OS_MALLOC(vap->iv_ic->ic_osdev, bo->bo_vhtchnsw_trailerlen, GFP_KERNEL);

                      if(tempbuf != NULL) {
	                      OS_MEMCPY(tempbuf,bo->bo_vhtchnsw, bo->bo_vhtchnsw_trailerlen);
	                      /* Adding channel switch wrapper element */
                          vhtchnsw_ie = ieee80211_add_chan_switch_wrp(bo->bo_vhtchnsw, ni, ic,
                                            IEEE80211_FC0_SUBTYPE_BEACON,
                                            /* When switching to new country by sending ECSA IE,
                                             * new country IE should be also be added.
                                             * As of now we dont support switching to new country
                                             * without bringing down vaps so new country IE is not required.
                                             */
                                            (/*ecsa_ie ? IEEE80211_VHT_EXTCH_SWITCH :*/ !IEEE80211_VHT_EXTCH_SWITCH));
                          vhtchnsw_ielen = vhtchnsw_ie - bo->bo_vhtchnsw;
                          /* Copying the rest of beacon buffer */
                          OS_MEMCPY(vhtchnsw_ie, tempbuf, bo->bo_vhtchnsw_trailerlen);
	                      OS_FREE(tempbuf);

                          if(vhtchnsw_ielen) {
                               if (bo->bo_wme) {
                                   bo->bo_wme += vhtchnsw_ielen;
                               }
                               bo->bo_ath_caps += vhtchnsw_ielen;
                               if(bo->bo_apriori_next_channel)
                                   bo->bo_apriori_next_channel += vhtchnsw_ielen;
                               bo->bo_appie_buf += vhtchnsw_ielen;
                               if(bo->bo_whc_apinfo) {
                                   bo->bo_whc_apinfo += vhtchnsw_ielen;
                               }
#if QCN_IE
                               if(bo->bo_qcn_ie) {
                                  bo->bo_qcn_ie += vhtchnsw_ielen;
                               }
#endif

                               bo->bo_xr += vhtchnsw_ielen;
                               if (bo->bo_htinfo_vendor_specific)
                                   bo->bo_htinfo_vendor_specific += vhtchnsw_ielen;
                               bo->bo_tim_trailerlen += vhtchnsw_ielen;
                               bo->bo_chanswitch_trailerlen += vhtchnsw_ielen;
                               bo->bo_vhtchnsw_trailerlen += vhtchnsw_ielen;
                               bo->bo_secchanoffset_trailerlen += vhtchnsw_ielen;
#if UMAC_SUPPORT_WNM
                               if (bo->bo_fms_trailer) {
                                   bo->bo_fms_trailerlen += vhtchnsw_ielen;
                               }
#endif /* UMAC_SUPPOT_WNM */

                              /* indicate new beacon length so other layers may manage memory */
                               wbuf_append(wbuf, vhtchnsw_ielen);
                              /* indicate new beacon length so other layers may manage memory */
                               len_changed = 1;
                          }
                      }
                }
            }
            else {
#ifdef MAGPIE_HIF_GMAC
                if(vap->iv_chanchange_count != ic->ic_chanchange_tbtt)
                    bo->bo_chanswitch[4] = ic->ic_chanchange_tbtt - vap->iv_chanchange_count;
#else
                 bo->bo_chanswitch[4] = ic->ic_chanchange_tbtt - vap->iv_chanchange_count;
#endif
                 /* ECSA IE is added just afer CSA IE.
                  * Update tbtt count in ECSA IE to same as CSA IE.
                  */
                 ecsa_ie = (struct ieee80211_extendedchannelswitch_ie *)
                     ((uint8_t *)bo->bo_chanswitch + IEEE80211_CHANSWITCHANN_BYTES);
                 if (ecsa_ie->ie == IEEE80211_ELEMID_EXTCHANSWITCHANN) {
                     /* ECSA is inserted, so update tbttcount */
                     ecsa_ie->tbttcount = bo->bo_chanswitch[4];
                 }
            }
#ifdef MAGPIE_HIF_GMAC
            if(vap->iv_chanchange_count != ic->ic_chanchange_tbtt) {
                vap->iv_chanchange_count++;
                ic->ic_chanchange_cnt--;
            }

            if(vap->iv_chanchange_count == ic->ic_chanchange_tbtt)
               vap->iv_chanswitch = 1;
#else
            vap->iv_chanchange_count++;

            /* In case of repeater move, send deauth to old root AP one count
             * before channel switch happens
             */
            if (bo->bo_chanswitch[4] == 1 && ic->ic_repeater_move.state == REPEATER_MOVE_START) {
                struct ieee80211vap *rep_sta_vap = ic->ic_sta_vap;
                struct ieee80211_node *ni = ieee80211_vap_find_node(rep_sta_vap, rep_sta_vap->iv_bss->ni_bssid);
                if (ni != NULL) {
                    ieee80211_send_deauth(ni, IEEE80211_REASON_AUTH_LEAVE);
                    ieee80211_free_node(ni);
                }
            }
#endif
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH, "%s: CHANSWITCH IE, change in %d \n",
                              __func__, bo->bo_chanswitch[4]);
        }
    }
#if ATH_SUPPORT_IBSS_DFS
    if (vap->iv_opmode == IEEE80211_M_IBSS &&
        (ic->ic_curchan->ic_flagext & IEEE80211_CHAN_DFS)) {
        /*reset action frames counts for measrep and csa action */
        vap->iv_measrep_action_count_per_tbtt = 0;
        vap->iv_csa_action_count_per_tbtt = 0;

        if(vap->iv_ibssdfs_state == IEEE80211_IBSSDFS_OWNER) {
            vap->iv_ibssdfs_ie_data.rec_interval = vap->iv_ibss_dfs_enter_recovery_threshold_in_tbtt;
        }

        ibss_ie =(struct ieee80211_ibssdfs_ie *) bo->bo_ibssdfs;
        if(ibss_ie) {
            if (OS_MEMCMP(bo->bo_ibssdfs, &vap->iv_ibssdfs_ie_data, ibss_ie->len + sizeof(struct ieee80211_ie_header))) {
                int trailer_adjust = vap->iv_ibssdfs_ie_data.len - ibss_ie->len;

                /* copy up/down trailer */
                if(trailer_adjust > 0) {
                    u_int8_t	* tempbuf;
            		tempbuf = OS_MALLOC(vap->iv_ic->ic_osdev, bo->bo_ibssdfs_trailerlen , GFP_KERNEL);
            		if (tempbuf == NULL) {
            		   IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY, "%s: Unable to alloc ibssdfs copy buf. Size=%d\n",
                                        __func__, bo->bo_ibssdfs_trailerlen);
                        return -1;
            		}
            		OS_MEMCPY(tempbuf,bo->bo_ibssdfs + sizeof(struct ieee80211_ie_header) + ibss_ie->len, bo->bo_ibssdfs_trailerlen);
                    OS_MEMCPY(bo->bo_ibssdfs + sizeof(struct ieee80211_ie_header) + vap->iv_ibssdfs_ie_data.len,
                              tempbuf,
                              bo->bo_ibssdfs_trailerlen);
            		OS_FREE(tempbuf);
        		} else {

                    OS_MEMCPY(bo->bo_ibssdfs + sizeof(struct ieee80211_ie_header) + vap->iv_ibssdfs_ie_data.len ,
                              bo->bo_ibssdfs + sizeof(struct ieee80211_ie_header) + ibss_ie->len,
                              bo->bo_ibssdfs_trailerlen);
                }

                bo->bo_tim_trailerlen += trailer_adjust;
                bo->bo_chanswitch_trailerlen += trailer_adjust;
                bo->bo_quiet += trailer_adjust;
                if (bo->bo_wme) {
                    bo->bo_wme += trailer_adjust;
                }
                if (bo->bo_erp) {
                    bo->bo_erp += trailer_adjust;
                }
                bo->bo_ath_caps += trailer_adjust;
                if (bo->bo_apriori_next_channel) {
                    bo->bo_apriori_next_channel += trailer_adjust;
                }
                bo->bo_appie_buf += trailer_adjust;
                if(bo->bo_whc_apinfo) {
                    bo->bo_whc_apinfo += trailer_adjust;
                }
#if QCN_IE
                if(bo->bo_qcn_ie) {
                    bo->bo_qcn_ie += trailer_adjust;
                }
#endif

                bo->bo_xr += trailer_adjust;
                bo->bo_secchanoffset += trailer_adjust;
                if(bo->bo_htinfo != NULL && bo->bo_htcap != NULL)
                {
                    bo->bo_htinfo += trailer_adjust;
                    bo->bo_htcap += trailer_adjust;
                }
                bo->bo_htinfo_pre_ana += trailer_adjust;
                if (bo->bo_htinfo_vendor_specific) {
                    bo->bo_htinfo_vendor_specific += trailer_adjust;
                }
                bo->bo_extcap += trailer_adjust;
                if(bo->bo_obss_scan)
                    bo->bo_obss_scan += trailer_adjust;
                bo->bo_bssload += trailer_adjust;
#if UMAC_SUPPORT_WNM
                if (bo->bo_fms_desc)
                    bo->bo_fms_desc += trailer_adjust;
                if (bo->bo_fms_trailer)
                    bo->bo_fms_trailer += trailer_adjust;
#endif /* UMAC_SUPPORT_WNM */
                if(bo->bo_vhtcap != NULL && bo->bo_vhtop != NULL)
                {
                    bo->bo_vhtcap += trailer_adjust;
                    bo->bo_vhtop += trailer_adjust;
                }
                if(bo->bo_vhttxpwr != NULL)
                    bo->bo_vhttxpwr += trailer_adjust;
                if(bo->bo_vhtchnsw != NULL)
                    bo->bo_vhtchnsw += trailer_adjust;

                if(bo->bo_interop_vhtcap != NULL)
                {
                    bo->bo_interop_vhtcap += trailer_adjust;
                }

                if ( ieee80211_vap_mbo_check(vap) && (bo->bo_mbo_cap) ) {
                    bo->bo_mbo_cap += trailer_adjust;
                }

                if (trailer_adjust >  0) {
                    wbuf_append(wbuf, trailer_adjust);
                }
                else {
                    wbuf_trim(wbuf, -trailer_adjust);
                }
                OS_MEMCPY(bo->bo_ibssdfs, &vap->iv_ibssdfs_ie_data, sizeof(struct ieee80211_ie_header) + vap->iv_ibssdfs_ie_data.len);
                len_changed = 1;
            }
        }
        if (vap->iv_ibssdfs_state == IEEE80211_IBSSDFS_JOINER ||
            vap->iv_ibssdfs_state == IEEE80211_IBSSDFS_OWNER) {
            vap->iv_ibssdfs_recovery_count = vap->iv_ibssdfs_ie_data.rec_interval;
            ieee80211_ibss_beacon_update_stop(ic);
         } else if (vap->iv_ibssdfs_state == IEEE80211_IBSSDFS_WAIT_RECOVERY) {
            vap->iv_ibssdfs_recovery_count --;
            if(vap->iv_ibssdfs_recovery_count == 0) {
               IEEE80211_ADDR_COPY(vap->iv_ibssdfs_ie_data.owner, vap->iv_myaddr);
               vap->iv_ibssdfs_state = IEEE80211_IBSSDFS_OWNER;
               vap->iv_ibssdfs_recovery_count = vap->iv_ibssdfs_ie_data.rec_interval;
               if(!vap->iv_ibss_dfs_no_channel_switch)
                   ieee80211_dfs_action(vap, NULL);
               vap->iv_ibss_dfs_no_channel_switch = false;
            }
         }
    }
#endif /* ATH_SUPPORT_IBSS_DFS */
    if (((vap->iv_opmode == IEEE80211_M_HOSTAP) &&  (IEEE80211_IS_CHAN_ANYG(vap->iv_bsschan) ||
        IEEE80211_IS_CHAN_11NG(vap->iv_bsschan))) ||
        vap->iv_opmode == IEEE80211_M_BTAMP) { /* No IBSS Support */
        if (ieee80211_vap_erpupdate_is_set(vap) && bo->bo_erp) {
            (void) ieee80211_add_erp(bo->bo_erp, ic);
	        ieee80211_vap_erpupdate_clear(vap);
        }
    }

#if UMAC_SUPPORT_WNM
    /* Add WNM specific IEs (like FMS desc...), if supported */
    if (ieee80211_vap_wnm_is_set(vap) &&
        ieee80211_wnm_fms_is_set(vap->wnm) &&
        vap->iv_opmode == IEEE80211_M_HOSTAP && (bo->bo_fms_desc) && (bo->bo_fms_trailer)) {
        ieee80211_wnm_setup_fmsdesc_ie(ni, is_dtim, &fmsie, &fmsie_len, &fms_counter_mask);
        if (fmsie_len != bo->bo_fms_len) {
            u_int8_t *new_fms_trailer = (bo->bo_fms_desc + fmsie_len);
            int trailer_adjust =  new_fms_trailer - bo->bo_fms_trailer;
            /* copy up/down trailer */
            if(trailer_adjust > 0) {
                u_int8_t *tempbuf;
               tempbuf = OS_MALLOC(vap->iv_ic->ic_osdev,
                                bo->bo_fms_trailerlen , GFP_KERNEL);
               if (tempbuf == NULL) {
                   IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
                           "%s: Unable to alloc FMS copy buf. Size=%d\n",
                           __func__, bo->bo_fms_trailerlen);
                   return -1;
               }
               OS_MEMCPY(tempbuf, bo->bo_fms_trailer, bo->bo_fms_trailerlen);
               OS_MEMCPY(new_fms_trailer, tempbuf, bo->bo_fms_trailerlen);
               OS_FREE(tempbuf);
            } else {
                OS_MEMCPY(new_fms_trailer, bo->bo_fms_trailer,
                        bo->bo_fms_trailerlen);
            }

            bo->bo_fms_trailer = new_fms_trailer;
            bo->bo_extcap += trailer_adjust;
            if (bo->bo_wme) {
                bo->bo_wme += trailer_adjust;
            }
            if (bo->bo_htinfo_vendor_specific) {
                bo->bo_htinfo_vendor_specific += trailer_adjust;
            }
            bo->bo_ath_caps += trailer_adjust;
            if (bo->bo_apriori_next_channel) {
                bo->bo_apriori_next_channel += trailer_adjust;
            }
            if (bo->bo_bwnss_map != NULL) {
                bo->bo_bwnss_map += trailer_adjust;
            }
            bo->bo_xr += trailer_adjust;
            bo->bo_appie_buf += trailer_adjust;
            if(bo->bo_whc_apinfo) {
                bo->bo_whc_apinfo += trailer_adjust;
            }
#if QCN_IE
            if(bo->bo_qcn_ie) {
                bo->bo_qcn_ie += trailer_adjust;
            }
#endif

            if (fmsie_len > bo->bo_fms_len)
                wbuf_append(wbuf, fmsie_len - bo->bo_fms_len);
            else
                wbuf_trim(wbuf, bo->bo_fms_len - fmsie_len);
            bo->bo_fms_len = fmsie_len;
        }

        if (fmsie_len &&  (bo->bo_fms_desc) && (bo->bo_fms_trailer))
        {
            OS_MEMCPY(bo->bo_fms_desc, fmsie, fmsie_len);

            bo->bo_fms_trailer = bo->bo_fms_desc + fmsie_len;
            bo->bo_fms_len = fmsie_len;
        }

        if (tie != NULL) {
            /* update state for buffered multicast frames on DTIM */
            if (nfmsq_mask & fms_counter_mask) {
                tie->tim_bitctl |= 1;
            }
        }
    }
#endif /* UMAC_SUPPORT_WNM */

    if(IEEE80211_IS_CSH_OPT_APRIORI_NEXT_CHANNEL_ENABLED(ic) && IEEE80211_IS_CHAN_DFS(ic->ic_curchan))
    {
        if(bo->bo_apriori_next_channel && ic->ic_tx_next_ch)
            ieee80211_add_next_channel(bo->bo_apriori_next_channel, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON);
    }
    /* add APP_IE buffer if app updated it */
#ifdef ATH_BEACON_DEFERRED_PROC
    IEEE80211_VAP_LOCK(vap);
#endif
    if (IEEE80211_VAP_IS_APPIE_UPDATE_ENABLED(vap)) {
        /* adjust the buffer size if the size is changed */
        u_int32_t newlen = vap->iv_app_ie[IEEE80211_FRAME_TYPE_BEACON].length;

        /* Also add the length from the new App IE module */
        newlen += vap->iv_app_ie_list[IEEE80211_FRAME_TYPE_BEACON].total_ie_len;

        if (newlen != bo->bo_appie_buf_len) {
            int diff_len;
            diff_len = newlen - bo->bo_appie_buf_len;
            bo->bo_appie_buf_len = (u_int16_t) newlen;
            /* update the trailer lens */
            bo->bo_chanswitch_trailerlen += diff_len;
            bo->bo_tim_trailerlen += diff_len;
            bo->bo_secchanoffset_trailerlen += diff_len;
#if ATH_SUPPORT_IBSS_DFS
            bo->bo_ibssdfs_trailerlen += diff_len;
#endif
            if (bo->bo_whc_apinfo) {
                bo->bo_whc_apinfo += diff_len;
            }
            if (diff_len > 0)
                wbuf_append(wbuf, diff_len);
            else
                wbuf_trim(wbuf, -(diff_len));
            len_changed = 1;
        }

        if (vap->iv_app_ie[IEEE80211_FRAME_TYPE_BEACON].length) {
            OS_MEMCPY(bo->bo_appie_buf, vap->iv_app_ie[IEEE80211_FRAME_TYPE_BEACON].ie,
                      vap->iv_app_ie[IEEE80211_FRAME_TYPE_BEACON].length);
        }

        /* Add the Application IE's */
        if (vap->iv_app_ie_list[IEEE80211_FRAME_TYPE_BEACON].total_ie_len) {
            frm = bo->bo_appie_buf + vap->iv_app_ie[IEEE80211_FRAME_TYPE_BEACON].length;
            frm = ieee80211_mlme_app_ie_append(vap, IEEE80211_FRAME_TYPE_BEACON, frm);
        }

        IEEE80211_VAP_APPIE_UPDATE_DISABLE(vap);

        update_beacon_copy = true;
    }
#ifdef ATH_BEACON_DEFERRED_PROC
    IEEE80211_VAP_UNLOCK(vap);
#endif
    if (IEEE80211_VAP_IS_WDS_ENABLED(vap) &&
            IEEE80211_VAP_IS_WHC_AP_INFO_UPDATE_ENABLED(vap)) {
        u_int16_t whcCaps = QCA_OUI_WHC_AP_INFO_CAP_WDS;
        u_int16_t newlen;
        u_int8_t *tempbuf = NULL;

        tempbuf = OS_MALLOC(vap->iv_ic->ic_osdev,
                sizeof(struct ieee80211_ie_whc_apinfo),
                GFP_KERNEL);
        if(tempbuf == NULL)
            return -1;

        /* SON mode requires WDS as a prereq */
        if (IEEE80211_VAP_IS_SON_ENABLED(vap)) {
            whcCaps |= QCA_OUI_WHC_AP_INFO_CAP_SON;
        }

        ieee80211_add_whc_ap_info_ie(tempbuf, whcCaps, vap, &newlen);

        if(newlen != bo->bo_whc_apinfo_len)
        {
            int diff_len = newlen - bo->bo_whc_apinfo_len;
            bo->bo_whc_apinfo_len = newlen;

            /* update the trailer lens */
            bo->bo_chanswitch_trailerlen += diff_len;
            bo->bo_tim_trailerlen += diff_len;
            bo->bo_secchanoffset_trailerlen += diff_len;
#if ATH_SUPPORT_IBSS_DFS
            bo->bo_ibssdfs_trailerlen += diff_len;
#endif
            if (diff_len > 0)
                wbuf_append(wbuf, diff_len);
            else
                wbuf_trim(wbuf, -(diff_len));
            len_changed = 1;
        }

        if ( bo->bo_whc_apinfo )
        {
            OS_MEMCPY(bo->bo_whc_apinfo, tempbuf, bo->bo_whc_apinfo_len);
            frm = bo->bo_whc_apinfo + bo->bo_whc_apinfo_len;
            IEEE80211_VAP_WHC_AP_INFO_UPDATE_DISABLE(vap);
        }

        OS_FREE(tempbuf);
        update_beacon_copy = true;
    }
#if UMAC_SUPPORT_WNM
    if (update_beacon_copy) {
        ieee80211_wnm_tim_incr_checkbeacon(vap);
    }
#endif
    if (update_beacon_copy && ieee80211_vap_copy_beacon_is_set(vap)) {
        store_beacon_frame(vap, (u_int8_t *)wbuf_header(wbuf), wbuf_get_pktlen(wbuf));
    }

    return len_changed;
}

int
wlan_copy_ap_beacon_frame(wlan_if_t vaphandle, u_int32_t in_buf_size, u_int32_t *required_buf_size, void *buffer)
{
    struct ieee80211vap *vap = vaphandle;
    void *beacon_buf;

    *required_buf_size = 0;

    /* Make sure that this VAP is SoftAP */
    if (vap->iv_opmode != IEEE80211_M_HOSTAP) {
        return EPERM ;
    }

    if (!vap->iv_beacon_copy_buf) {
        /* Error: no beacon buffer */
        return EPERM ;
    }

    if (in_buf_size < vap->iv_beacon_copy_len) {
        /* Input buffer too small */
        *required_buf_size = vap->iv_beacon_copy_len;
        return ENOMEM ;
    }
    *required_buf_size = vap->iv_beacon_copy_len;

    beacon_buf = (void *)vap->iv_beacon_copy_buf;

    OS_MEMCPY(buffer, beacon_buf, vap->iv_beacon_copy_len);

    return EOK;
}

#endif
