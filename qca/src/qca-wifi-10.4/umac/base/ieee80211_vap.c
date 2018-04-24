/*
 *  Copyright (c) 2008 Atheros Communications Inc.
 * All Rights Reserved.
 *
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#include <ieee80211_var.h>
#include <ieee80211_channel.h>
#include <ieee80211_mlme.h>
#include <ieee80211_target.h>
#include <ieee80211_rateset.h>
#include <ieee80211_wds.h>
#include <if_smart_ant.h>
#if QCA_LTEU_SUPPORT
#include <ieee80211_nl.h>
#endif
#include <qdf_lock.h>
#if ATH_PERF_PWR_OFFLOAD
#include <ol_if_athvar.h>
#endif
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_if.h>
#include <osif_nss_wifiol_vdev_if.h>
#endif
#include <ieee80211_rate_estimate.h>

#if ACFG_NETLINK_TX
void acfg_clean(struct ieee80211com *ic);
#endif

#if DYNAMIC_BEACON_SUPPORT
static OS_TIMER_FUNC(ieee80211_dbeacon_suspend_beacon)
{
    struct ieee80211vap  *vap = NULL;
    OS_GET_TIMER_ARG(vap, struct ieee80211vap *);

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "Enter timer:%s, Kickout all sta under this VAP \n", __FUNCTION__);
    wlan_deauth_all_stas(vap);

    qdf_spin_lock_bh(&vap->iv_dbeacon_lock);
    if (!ieee80211_mlme_beacon_suspend_state(vap)) {
        ieee80211_mlme_set_beacon_suspend_state(vap, true);
    }
    qdf_spin_unlock_bh(&vap->iv_dbeacon_lock);

}
#endif

#if QCN_IE
/*
 * Callback function that will be called at the expiration of bpr_timer.
 */
static enum hrtimer_restart ieee80211_send_bcast_resp_handler(struct hrtimer *arg)
{
    struct tasklet_hrtimer *thr = container_of(arg, struct tasklet_hrtimer, timer);
    struct ieee80211vap *vap = container_of(thr, struct ieee80211vap, bpr_timer);
    struct ieee80211_framing_extractx extractx;

    OS_MEMZERO(&extractx, sizeof(extractx));

    if ((!vap) || (ieee80211_vap_deleted_is_set(vap))) {
       return HRTIMER_NORESTART;
    }

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
        "Callback running : %s | %d | Delay: %d | Next beacon tstamp: %lld | "
        "beacon interval: %d ms \n",
        __func__, __LINE__, vap->iv_bpr_delay, \
        ktime_to_ns(vap->iv_next_beacon_tstamp), vap->iv_ic->ic_intval);

    /* Set the rate to vap management rate */
    extractx.datarate = vap->iv_mgt_rate;

    /* Send the broadcast probe response and reset the state to default */
    ieee80211_send_proberesp(vap->iv_bss, IEEE80211_GET_BCAST_ADDR(vap->iv_ic), NULL, 0, &extractx);
    vap->iv_bpr_callback_count++;

    return HRTIMER_NORESTART;
}
#endif

int
ieee80211_vap_setup(struct ieee80211com *ic, struct ieee80211vap *vap,
                    int opmode, int scan_priority_base, u_int32_t flags,
                    const u_int8_t bssid[IEEE80211_ADDR_LEN])
{
#define IEEE80211_C_OPMODE                                              \
    (IEEE80211_C_IBSS | IEEE80211_C_HOSTAP | IEEE80211_C_AHDEMO |       \
     IEEE80211_C_MONITOR)

    int i;
#define DEFAULT_WATERMARK_THRESHOLD 50
#if UMAC_SUPPORT_APONLY
    struct ieee80211_vap_opmode_count vap_opmode_count;
#endif

#if 1 /* DISABLE_FOR_PLUGFEST_GSTANTON */
    vap->iv_debug |= (IEEE80211_MSG_POWER | IEEE80211_MSG_STATE);
#endif

    vap->iv_ic = ic;
    vap->iv_create_flags=flags;
    vap->iv_flags = ic->ic_flags;       /* propagate common flags */
    vap->iv_flags_ext = ic->ic_flags_ext;
    vap->iv_ath_cap = ic->ic_ath_cap;
    vap->iv_htflags = ic->ic_htflags;
    /* Default Multicast traffic to lowest rate of 1000 Kbps*/
    vap->iv_mcast_fixedrate = 0;
    vap->iv_caps = ic->ic_caps &~ IEEE80211_C_OPMODE;
    vap->iv_ath_cap &= ~IEEE80211_ATHC_WME;
    vap->iv_node_count = 0;
    vap->iv_ccmpsw_seldec = 1;
    vap->iv_vap_ssid_config = 0xff; /* In ssid steering Default is 0xff private is 1 public is 0 */
#if UMAC_SUPPORT_ACFG
    if (opmode == IEEE80211_M_HOSTAP) {
        vap->iv_diag_warn_threshold = 65; /* default 65Mbps */
        vap->iv_diag_err_threshold = 26; /* default 26Mbps */
    }
#endif
    atomic_set(&vap->iv_rx_gate,0);

    for (i = 0; i < IEEE80211_APPIE_MAX_FRAMES; i++) {
        LIST_INIT(&vap->iv_app_ie_list[i]);
    }

    /*
     * By default, supports sending our Country IE and 802.11h
     * informations (but also depends on the lower ic flags).
     */
    ieee80211_vap_country_ie_set(vap);
    ieee80211_vap_doth_set(vap);
    ieee80211_vap_off_channel_support_set(vap);
    switch (opmode) {
    case IEEE80211_M_STA:
        /* turn on sw bmiss timer by default */
        ieee80211_vap_sw_bmiss_set(vap);
        vap->iv_whc_scaling_factor = WHC_DEFAULT_SFACTOR;
        break;
    case IEEE80211_M_IBSS:
        vap->iv_caps |= IEEE80211_C_IBSS;
        vap->iv_ath_cap &= ~IEEE80211_ATHC_XR;
        break;
    case IEEE80211_M_AHDEMO:
        vap->iv_caps |= IEEE80211_C_AHDEMO;
        vap->iv_ath_cap &= ~IEEE80211_ATHC_XR;
        break;
    case IEEE80211_M_HOSTAP:
        vap->iv_caps |= IEEE80211_C_HOSTAP;
        vap->iv_ath_cap &= ~(IEEE80211_ATHC_XR | IEEE80211_ATHC_TURBOP);
        break;
    case IEEE80211_M_MONITOR:
        vap->iv_caps |= IEEE80211_C_MONITOR;
        vap->iv_ath_cap &= ~(IEEE80211_ATHC_XR | IEEE80211_ATHC_TURBOP);
        break;
    case IEEE80211_M_WDS:
        vap->iv_caps |= IEEE80211_C_WDS;
        vap->iv_ath_cap &= ~(IEEE80211_ATHC_XR | IEEE80211_ATHC_TURBOP);
        IEEE80211_VAP_WDS_ENABLE(vap);
        break;
    }
    vap->iv_opmode = opmode;
#ifdef ATH_SUPPORT_TxBF
    vap->iv_txbfmode = 1;
#endif
    vap->iv_scan_priority_base = scan_priority_base;

    vap->iv_chanchange_count = 0;
    vap->channel_change_done = 0;
    vap->appie_buf_updated = 0;
    #ifdef ATH_SUPPORT_QUICK_KICKOUT
    vap->iv_sko_th = ATH_TX_MAX_CONSECUTIVE_XRETRIES;
    #endif

    qdf_atomic_set(&(vap->init_in_progress), 0);
    spin_lock_init(&vap->iv_lock);
    spin_lock_init(&vap->init_lock);

    vap->iv_bsschan = ic->ic_curchan; /* initialize bss chan to cur chan */
    /*
     * Enable various functionality by default if we're capable.
     */

    /* NB: bg scanning only makes sense for station mode right now */
    if ((ic->ic_opmode == IEEE80211_M_STA) &&
        (vap->iv_caps & IEEE80211_C_BGSCAN))
        vap->iv_flags |= IEEE80211_F_BGSCAN;
    /* If lp_iot_mode we want to ensure DTIM is 4x beacon interval use IEEE80211_DTIM_DEFAULT_LP_IOT */
    if (vap->iv_create_flags & IEEE80211_LP_IOT_VAP)
       vap->iv_dtim_period = IEEE80211_DTIM_DEFAULT_LP_IOT;
    else
       vap->iv_dtim_period = IEEE80211_DTIM_DEFAULT;
    vap->iv_bmiss_count_for_reset = IEEE80211_DEFAULT_BMISS_COUNT_RESET;
    vap->iv_bmiss_count_max = IEEE80211_DEFAULT_BMISS_COUNT_MAX;

    vap->iv_des_mode = IEEE80211_MODE_AUTO;
    vap->iv_cur_mode = IEEE80211_MODE_AUTO;
    vap->iv_des_modecaps = (1 << IEEE80211_MODE_AUTO);
    vap->iv_des_chan[IEEE80211_MODE_AUTO]           = IEEE80211_CHAN_ANYC;
#if UMAC_SUPPORT_ACS
    if (opmode != IEEE80211_M_HOSTAP)
#endif
    {
       vap->iv_des_chan[IEEE80211_MODE_11A]            = ieee80211_find_dot11_channel(ic, 0, 0, IEEE80211_MODE_11A);
       vap->iv_des_chan[IEEE80211_MODE_11B]            = ieee80211_find_dot11_channel(ic, 0, 0, IEEE80211_MODE_11B);
       vap->iv_des_chan[IEEE80211_MODE_11G]            = ieee80211_find_dot11_channel(ic, 0, 0, IEEE80211_MODE_11G);
       vap->iv_des_chan[IEEE80211_MODE_11NA_HT20]      = ieee80211_find_dot11_channel(ic, 0, 0, IEEE80211_MODE_11NA_HT20);
       vap->iv_des_chan[IEEE80211_MODE_11NG_HT20]      = ieee80211_find_dot11_channel(ic, 0, 0, IEEE80211_MODE_11NG_HT20);
       vap->iv_des_chan[IEEE80211_MODE_11NA_HT40PLUS]  = ieee80211_find_dot11_channel(ic, 0, 0, IEEE80211_MODE_11NA_HT40PLUS);
       vap->iv_des_chan[IEEE80211_MODE_11NA_HT40MINUS] = ieee80211_find_dot11_channel(ic, 0, 0, IEEE80211_MODE_11NA_HT40MINUS);
       vap->iv_des_chan[IEEE80211_MODE_11NG_HT40PLUS]  = ieee80211_find_dot11_channel(ic, 0, 0, IEEE80211_MODE_11NG_HT40PLUS);
       vap->iv_des_chan[IEEE80211_MODE_11NG_HT40MINUS] = ieee80211_find_dot11_channel(ic, 0, 0, IEEE80211_MODE_11NG_HT40MINUS);
       vap->iv_des_chan[IEEE80211_MODE_11NG_HT40]      = ieee80211_find_dot11_channel(ic, 0, 0, IEEE80211_MODE_11NG_HT40);
       vap->iv_des_chan[IEEE80211_MODE_11NA_HT40]      = ieee80211_find_dot11_channel(ic, 0, 0, IEEE80211_MODE_11NA_HT40);
       vap->iv_des_chan[IEEE80211_MODE_11AC_VHT20]     = ieee80211_find_dot11_channel(ic, 0, 0, IEEE80211_MODE_11AC_VHT20);
       vap->iv_des_chan[IEEE80211_MODE_11AC_VHT40]     = ieee80211_find_dot11_channel(ic, 0, 0, IEEE80211_MODE_11AC_VHT40);
       vap->iv_des_chan[IEEE80211_MODE_11AC_VHT40PLUS] = ieee80211_find_dot11_channel(ic, 0, 0, IEEE80211_MODE_11AC_VHT40PLUS);
       vap->iv_des_chan[IEEE80211_MODE_11AC_VHT40MINUS]  = ieee80211_find_dot11_channel(ic, 0, 0, IEEE80211_MODE_11AC_VHT40MINUS);
       vap->iv_des_chan[IEEE80211_MODE_11AC_VHT80]     = ieee80211_find_dot11_channel(ic, 0, 0, IEEE80211_MODE_11AC_VHT80);
       vap->iv_des_chan[IEEE80211_MODE_11AC_VHT160]    = ieee80211_find_dot11_channel(ic, 0, 0, IEEE80211_MODE_11AC_VHT160);
       vap->iv_des_chan[IEEE80211_MODE_11AC_VHT80_80]  = ieee80211_find_dot11_channel(ic, 0, 0, IEEE80211_MODE_11AC_VHT80_80);
    }
#if UMAC_SUPPORT_ACS
    else {
       vap->iv_des_chan[IEEE80211_MODE_11A]            = IEEE80211_CHAN_ANYC;
       vap->iv_des_chan[IEEE80211_MODE_11B]            = IEEE80211_CHAN_ANYC;
       vap->iv_des_chan[IEEE80211_MODE_11G]            = IEEE80211_CHAN_ANYC;
       vap->iv_des_chan[IEEE80211_MODE_11NA_HT20]      = IEEE80211_CHAN_ANYC;
       vap->iv_des_chan[IEEE80211_MODE_11NG_HT20]      = IEEE80211_CHAN_ANYC;
       vap->iv_des_chan[IEEE80211_MODE_11NA_HT40PLUS]  = IEEE80211_CHAN_ANYC;
       vap->iv_des_chan[IEEE80211_MODE_11NA_HT40MINUS] = IEEE80211_CHAN_ANYC;
       vap->iv_des_chan[IEEE80211_MODE_11NG_HT40PLUS]  = IEEE80211_CHAN_ANYC;
       vap->iv_des_chan[IEEE80211_MODE_11NG_HT40MINUS] = IEEE80211_CHAN_ANYC;
       vap->iv_des_chan[IEEE80211_MODE_11NG_HT40]      = IEEE80211_CHAN_ANYC;
       vap->iv_des_chan[IEEE80211_MODE_11NA_HT40]      = IEEE80211_CHAN_ANYC;
       vap->iv_des_chan[IEEE80211_MODE_11AC_VHT20]     = IEEE80211_CHAN_ANYC;
       vap->iv_des_chan[IEEE80211_MODE_11AC_VHT40]     = IEEE80211_CHAN_ANYC;
       vap->iv_des_chan[IEEE80211_MODE_11AC_VHT40PLUS] = IEEE80211_CHAN_ANYC;
       vap->iv_des_chan[IEEE80211_MODE_11AC_VHT40MINUS]  = IEEE80211_CHAN_ANYC;
       vap->iv_des_chan[IEEE80211_MODE_11AC_VHT80]     = IEEE80211_CHAN_ANYC;
       vap->iv_des_chan[IEEE80211_MODE_11AC_VHT160]    = IEEE80211_CHAN_ANYC;
       vap->iv_des_chan[IEEE80211_MODE_11AC_VHT80_80]  = IEEE80211_CHAN_ANYC;
    }
#endif
    /* apply registry settings */
    vap->iv_des_ibss_chan     = ic->ic_reg_parm.defaultIbssChannel;
    vap->iv_rateCtrlEnable    = ic->ic_reg_parm.rateCtrlEnable;
    if (opmode == IEEE80211_M_STA)
       vap->iv_rc_txrate_fast_drop_en  = ic->ic_reg_parm.rc_txrate_fast_drop_en;

    vap->iv_fixed_rateset     = ic->ic_reg_parm.transmitRateSet;
    vap->iv_fixed_retryset    = ic->ic_reg_parm.transmitRetrySet;
    vap->iv_max_aid = ic->ic_num_clients; /* default max aid(should be a config param ?) */
    vap->iv_keep_alive_timeout  =  IEEE80211_DEFULT_KEEP_ALIVE_TIMEOUT;       /* keep alive time out */
    vap->iv_inact_count =  (vap->iv_keep_alive_timeout + IEEE80211_INACT_WAIT -1)/IEEE80211_INACT_WAIT;
    vap->watermark_threshold = vap->iv_max_aid;
    vap->watermark_threshold_flag = true ;

    if(vap->iv_max_aid == 0) {
        vap->watermark_threshold = DEFAULT_WATERMARK_THRESHOLD; /* Default threshold value is 50 when the maximum number of clients is 0 */
    }
#ifdef ATH_SUPPORT_TxBF
    vap->iv_autocvupdate      = ic->ic_reg_parm.autocvupdate;
    vap->iv_cvupdateper    = ic->ic_reg_parm.cvupdateper;
#endif

    /* set WMM-related parameters */
    vap->iv_wmm_enable        = ic->ic_reg_parm.wmeEnabled;
    if (ieee80211com_has_cap(ic, IEEE80211_C_WME)) {
        if (vap->iv_wmm_enable) {
            ieee80211_vap_wme_set(vap);
        } else  {
            ieee80211_vap_wme_clear(vap);
        }
    } else {
        ieee80211_vap_wme_clear(vap);
    }

    vap->iv_wmm_power_save    = 0;
    vap->iv_smps_rssithresh   = ic->ic_reg_parm.smpsRssiThreshold;
    vap->iv_smps_datathresh   = ic->ic_reg_parm.smpsDataThreshold;

    {
        u_int8_t    uapsd_flag;

        uapsd_flag = (ic->ic_reg_parm.uapsd.vo ? WME_CAPINFO_UAPSD_VO : 0) |
                     (ic->ic_reg_parm.uapsd.vi ? WME_CAPINFO_UAPSD_VI : 0) |
                     (ic->ic_reg_parm.uapsd.bk ? WME_CAPINFO_UAPSD_BK : 0) |
                     (ic->ic_reg_parm.uapsd.be ? WME_CAPINFO_UAPSD_BE : 0);

        ieee80211_set_uapsd_flags(vap, uapsd_flag);
    }

    OS_RWLOCK_INIT(&vap->iv_tim_update_lock);

    IEEE80211_ADDR_COPY(vap->iv_myaddr, ic->ic_myaddr);
    IEEE80211_ADDR_COPY(vap->iv_my_hwaddr, ic->ic_my_hwaddr);

    for(i=0;i<IEEE80211_MAX_VAP_EVENT_HANDLERS; ++i) {
        vap->iv_event_handler[i] = NULL;
    }

    vap->iv_nss = ieee80211_getstreams(ic, ic->ic_tx_chainmask);

    /* Set the SGI if the hardware supports SGI for any of the modes. Note that the hardware will
     * support this for all modes or none at all */
    vap->iv_sgi = 0;
    vap->iv_data_sgi = 0;

     /* Initialize to 0, it should be set to 1 on vap up */
    vap->iv_needs_up_on_acs = 0;

#if QCA_AIRTIME_FAIRNESS
    vap->iv_block_tx_traffic = 0;
    vap->tx_blk_cnt = 0;
    vap->iv_vap_atf_sched = 0;
#endif
    vap->ald_pid = WLAN_DEFAULT_NETLINK_PID;
    vap->lbd_pid = WLAN_DEFAULT_NETLINK_PID;
    vap->iv_whc_rept_multi_special = 0;

    /* Default VHT SGI mask is enabled for high stream MCS 7, 8, 9 */
    vap->iv_vht_sgimask = 0x380;

    /* Default VHT80 rate mask support all MCS rates except NSS=3 MCS=6 */
    vap->iv_vht80_ratemask = MAX_VHT80_RATE_MASK;

#if ATH_SUPPORT_WRAP
    if (ic->ic_htcap) {
        if ((vap->iv_ic->ic_wrap_vap_sgi_cap) && !(vap->iv_mpsta)&&(vap->iv_psta))
           vap->iv_sgi = vap->iv_ic->ic_wrap_vap_sgi_cap;
    }
#endif

    if (ic->ic_vhtcap) {
#if ATH_SUPPORT_WRAP
        if ((vap->iv_ic->ic_wrap_vap_sgi_cap) && !(vap->iv_mpsta)&&(vap->iv_psta))
           vap->iv_sgi = vap->iv_ic->ic_wrap_vap_sgi_cap;
#endif

#if ATH_PERF_PWR_OFFLOAD
        /* If lp_iot_mode vap then skip turning on BF */
        if ((opmode == IEEE80211_M_HOSTAP) && (vap->iv_ic->ic_implicitbf) && !(vap->iv_create_flags & IEEE80211_LP_IOT_VAP)){
             wlan_set_param(vap, IEEE80211_SUPPORT_IMPLICITBF, 1);
        }
#endif
        if (!(vap->iv_create_flags & IEEE80211_LP_IOT_VAP)) {
            vap->iv_vhtsubfer = ((ic->ic_vhtcap & IEEE80211_VHTCAP_SU_BFORMER) >> IEEE80211_VHTCAP_SU_BFORMER_S);
            vap->iv_vhtsubfee = ((ic->ic_vhtcap & IEEE80211_VHTCAP_SU_BFORMEE) >> IEEE80211_VHTCAP_SU_BFORMEE_S);
            vap->iv_vhtmubfer = (opmode == IEEE80211_M_HOSTAP) ? ((ic->ic_vhtcap & IEEE80211_VHTCAP_MU_BFORMER) >> IEEE80211_VHTCAP_MU_BFORMER_S) : 0;
            vap->iv_vhtmubfee = (opmode == IEEE80211_M_STA) ? ((ic->ic_vhtcap & IEEE80211_VHTCAP_MU_BFORMEE) >> IEEE80211_VHTCAP_MU_BFORMEE_S) : 0;
            vap->iv_vhtbfeestscap = (ic->ic_vhtcap >> IEEE80211_VHTCAP_STS_CAP_S) & IEEE80211_VHTCAP_STS_CAP_M;
            vap->iv_vhtbfsoundingdim = (ic->ic_vhtcap & IEEE80211_VHTCAP_SOUND_DIM) >> IEEE80211_VHTCAP_SOUND_DIM_S;
        }
    }

    /* LDPC, TX_STBC, RX_STBC : With VHT, HT will be set as well. Just use that */
    vap->iv_ldpc = ieee80211com_get_ldpccap(ic);

    /* Enabling  LDPC by default */
    if (ic->ic_vap_set_param) {
        ic->ic_vap_set_param(vap, IEEE80211_SUPPORT_LDPC , vap->iv_ldpc);
    }

    if (ic->ic_htcap) {
        vap->iv_tx_stbc = ((ic->ic_htcap & IEEE80211_HTCAP_C_TXSTBC) >> IEEE80211_HTCAP_C_TXSTBC_S);
        vap->iv_rx_stbc = ((ic->ic_htcap & IEEE80211_HTCAP_C_RXSTBC) >> IEEE80211_HTCAP_C_RXSTBC_S);
    }

    vap->iv_tsf_offset.offset = 0;
    vap->iv_tsf_offset.offset_negative = false;

    /*by defualt wep key cache will not be allocated in first four slots */
    vap->iv_wep_keycache = 0;
#if ATH_SUPPORT_WPA_SUPPLICANT_CHECK_TIME
    vap->iv_rejoint_attemp_time = 20;
#endif
    /* by defualt we will send disassoc while doing ath0 down */
    vap->iv_send_deauth= 0;

#if UMAC_SUPPORT_APONLY
    vap->iv_aponly = true;
    OS_MEMZERO(&vap_opmode_count, sizeof(vap_opmode_count));
    ieee80211_get_vap_opmode_count(ic, &vap_opmode_count);
    if (vap->iv_opmode == IEEE80211_M_IBSS &&
        vap_opmode_count.total_vaps == 0) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Disabling aponly path for ad-hoc mode\n");
        vap->iv_aponly = false;
        ic->ic_aponly = false;
    }
#else
    vap->iv_aponly = false;
#endif

    /*initialization for ratemask*/
    vap->iv_ratemask_default = 0;
    vap->iv_legacy_ratemasklower32 = 0;
    vap->iv_ht_ratemasklower32 = 0;
    vap->iv_vht_ratemasklower32 = 0;
    vap->iv_vht_ratemaskhigher32 = 0;
    vap->min_dwell_time_passive = 200;
    vap->max_dwell_time_passive = 300;
#if QCA_LTEU_SUPPORT
    vap->scan_repeat_probe_time =
                vap->scan_rest_time =
                vap->scan_idle_time =
                vap->scan_probe_delay = (u_int32_t)-1;
    vap->scan_probe_spacing_interval = LTEU_DEFAULT_PRB_SPC_INT;
    vap->mu_start_delay = 5000;
    vap->wifi_tx_power = 22;
#endif
    vap->iv_ena_vendor_ie = 1;	/* Enable vendoe Ie by default */
    vap->iv_update_vendor_ie = 0;  /* configure for the default value */
    vap->iv_force_onetxchain = false;
    vap->iv_mesh_mgmt_txsend_config  = 0;
#if UMAC_SUPPORT_ACL
    vap->iv_assoc_denial_notify = 1; /* Enable assoc denial notification by default*/
#endif /*UMAC_SUPPORT_ACL */

    /* attach other modules */
    ieee80211_rateset_vattach(vap);
    ieee80211_proto_vattach(vap);
    ieee80211_node_vattach(vap);
    ieee80211_crypto_vattach(vap);
    ieee80211_vap_pause_vattach(ic,vap);
    ieee80211_rrm_vattach(ic,vap);
    ieee80211_wnm_vattach(ic,vap);
    ieee80211_power_vattach(vap,
                            1,  /* enable full sleep */
                            ic->ic_reg_parm.sleepTimePwrSaveMax,
                            ic->ic_reg_parm.sleepTimePwrSave,
                            ic->ic_reg_parm.sleepTimePerf,
                            ic->ic_reg_parm.inactivityTimePwrSaveMax,
                            ic->ic_reg_parm.inactivityTimePwrSave,
                            ic->ic_reg_parm.inactivityTimePerf,
                            ic->ic_reg_parm.smpsDynamic,
                            ic->ic_reg_parm.psPollEnabled);
    ieee80211_mlme_vattach(vap);
    ieee80211_scan_table_vattach(vap, &(vap->iv_scan_table), ic->ic_osdev);
    ieee80211_aplist_vattach(&(vap->iv_candidate_aplist),
                             vap,
                             ieee80211_vap_get_scan_table(vap),
                             vap->iv_ic->ic_scanner,
                             vap->iv_ic->ic_osdev);
    ieee80211_aplist_config_vattach(&(vap->iv_aplist_config), vap->iv_ic->ic_osdev);
    ieee80211_acl_attach(vap);
    ieee80211_scs_vattach(vap);
    ieee80211_ald_vattach(vap);
    /*MBO & OCE functionality init */
    ieee80211_mbo_vattach(vap);
    ieee80211_oce_vattach(vap);
#if ATH_SUPPORT_WIFIPOS && !(ATH_SUPPORT_LOWI)
    if (wifiposenable)
    {
#if ATH_SUPPORT_WIFIPOS_ONE_VAP
{
        struct ieee80211vap *first_vap;
        first_vap = TAILQ_FIRST(&ic->ic_vaps);
        if ( NULL == first_vap ){
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "In %s, line:%d, wifi-pos enabled vap:%d\n", __func__, __LINE__, vap->iv_unit );
            ieee80211_wifipos_vattach(vap);
        }
	else {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "In %s, line:%d, wifi-pos disabled vap:%d\n", __func__, __LINE__, vap->iv_unit );
        }
}
#else
        ieee80211_wifipos_vattach(vap);
#endif
    }
    else
    {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:%d: wifipos disabled\n", __func__,__LINE__);
    }
#endif

#if DYNAMIC_BEACON_SUPPORT
        vap->iv_dbeacon = 0;
        vap->iv_dbeacon_runtime = 0;
        vap->iv_dbeacon_rssi_thr = DEFAULT_DBEACON_RSSI_THRESHOLD;
        vap->iv_dbeacon_timeout = DEFAULT_DBEACON_TIMEOUT;
        OS_INIT_TIMER(ic->ic_osdev, &vap->iv_dbeacon_suspend_beacon, ieee80211_dbeacon_suspend_beacon, vap,QDF_TIMER_TYPE_WAKE_APPS);
        qdf_spinlock_create(&vap->iv_dbeacon_lock);
#endif
#if QCN_IE
        vap->iv_bpr_delay = DEFAULT_BCAST_PROBE_RESP_DELAY;
        ic->ic_bpr_latency_comp = DEFAULT_BCAST_PROBE_RESP_LATENCY_COMPENSATION;
        ic->ic_bcn_latency_comp = DEFAULT_BEACON_LATENCY_COMPENSATION;
        if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
            tasklet_hrtimer_init(&vap->bpr_timer, ieee80211_send_bcast_resp_handler, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
        }
#endif

    vap->offchan_requestor = 0;
    vap->iv_csmode = IEEE80211_CSA_MODE_AUTO; /* csmode will be calculated dynamically */
    vap->iv_enable_ecsaie = true; /* Extended channel switch ie is enabled by default */

    OS_MEMSET(vap->iv_txpow_mgt_frm, 0xff, sizeof(vap->iv_txpow_mgt_frm));
    return 1;
#undef  IEEE80211_C_OPMODE
}

int
ieee80211_vap_attach(struct ieee80211vap *vap)
{
    int ret;

    IEEE80211_ADD_VAP_TARGET(vap);

    /*
     * XXX: It looks like we always need a bss node around
     * for transmit before association (e.g., probe request
     * in scan operation). When we actually join a BSS, we'll
     * create a new node and free the old one.
     */
    ret = ieee80211_node_latevattach(vap);

    if (ret == 0) {
        IEEE80211_UPDATE_TARGET_IC(vap->iv_bss);
    }

    /*
     * If IQUE is NOT enabled at compiling, ieee80211_me_attach attaches
     * the empty op table to vap->iv_me_ops;
     * If IQUE is enabled, the initialization is done by the following
     * function, and the op table is correctly attached.
     */
    if(ret == 0){
        ieee80211_ique_attach(ret,vap);
    }
    if(ret == 0)
    {
        ieee80211_nawds_attach(vap);
        vap->iv_vap_ath_info_handle = ieee80211_vap_ath_info_attach(vap);
        ieee80211_quiet_vattach(vap);
    }
    return ret;
}

void
ieee80211_vap_detach(struct ieee80211vap *vap)
{
    int i;

    ieee80211_quiet_vdetach(vap);
    ieee80211_vap_ath_info_detach(vap->iv_vap_ath_info_handle);
    ieee80211_node_latevdetach(vap);
    ieee80211_proto_vdetach(vap);
    ieee80211_power_vdetach(vap);
    ieee80211_mlme_vdetach(vap);
    ieee80211_vap_pause_vdetach(vap->iv_ic, vap);
    ieee80211_crypto_vdetach(vap);
    ieee80211_ald_vdetach(vap);
    ieee80211_scs_vdetach(vap);
    ieee80211_rrm_vdetach(vap);
    ieee80211_wnm_vdetach(vap);
    /*
     * detach ique features/functions
     */
    if (vap->iv_ique_ops.me_detach) {
        vap->iv_ique_ops.me_detach(vap);
    }
    if (vap->iv_ique_ops.hbr_detach) {
        vap->iv_ique_ops.hbr_detach(vap);
    }
    ieee80211_aplist_vdetach(&(vap->iv_candidate_aplist));
    ieee80211_aplist_config_vdetach(&(vap->iv_aplist_config));
    ieee80211_resmgr_vdetach(vap->iv_ic->ic_resmgr, vap);
    ieee80211_acl_detach(vap);
    ieee80211_scan_table_vdetach(&(vap->iv_scan_table));
    ieee80211_acl_detach(vap);
    /*MBO & OCE functionality deinit */
    ieee80211_mbo_vdetach(vap);
    ieee80211_oce_vdetach(vap);
#if ATH_SUPPORT_WIFIPOS && !(ATH_SUPPORT_LOWI)
    ieee80211_wifipos_vdetach(vap);
#endif
    for (i = 0; i < IEEE80211_WEP_NKID; i++) {
        ieee80211_crypto_freekey(vap, &vap->iv_nw_keys[i]);
    }
    ieee80211_vendorie_vdetach(vap);
#if DYNAMIC_BEACON_SUPPORT
    OS_FREE_TIMER(&vap->iv_dbeacon_suspend_beacon);
    qdf_spinlock_destroy(&vap->iv_dbeacon_lock);
#endif

    spin_lock_destroy(&vap->iv_lock);
    spin_lock_destroy(&vap->init_lock);
}

int
ieee80211_vap_register_events(struct ieee80211vap *vap, wlan_event_handler_table *evtab)
{
    vap->iv_evtable = evtab;
    return 0;
}

int
ieee80211_vap_register_mlme_events(struct ieee80211vap *vap, os_handle_t oshandle, wlan_mlme_event_handler_table *evtab)
{
    int i;
    /* unregister if there exists one already */
    ieee80211_vap_unregister_mlme_events(vap,oshandle,evtab);
    IEEE80211_VAP_LOCK(vap);
    for (i=0;i<IEEE80211_MAX_VAP_MLME_EVENT_HANDLERS; ++i) {
        if ( vap->iv_mlme_evtable[i] == NULL) {
            vap->iv_mlme_evtable[i] = evtab;
            vap->iv_mlme_arg[i] = oshandle;
            IEEE80211_VAP_UNLOCK(vap);
            return 0;
        }
    }
    IEEE80211_VAP_UNLOCK(vap);
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s mlme evtable is full.\n", __func__);
    return ENOMEM;
}

int
ieee80211_vap_unregister_mlme_events(struct ieee80211vap *vap,os_handle_t oshandle, wlan_mlme_event_handler_table *evtab)
{
    int i;
    IEEE80211_VAP_LOCK(vap);
    for (i=0;i<IEEE80211_MAX_VAP_MLME_EVENT_HANDLERS; ++i) {
        if ( vap->iv_mlme_evtable[i] == evtab && vap->iv_mlme_arg[i] == oshandle) {
            vap->iv_mlme_evtable[i] = NULL;
            vap->iv_mlme_arg[i] = NULL;
            IEEE80211_VAP_UNLOCK(vap);
            return 0;
        }
    }
    IEEE80211_VAP_UNLOCK(vap);
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s The handler is not in the evtable.\n", __func__);
    return EEXIST;
}

int
ieee80211_vap_register_misc_events(struct ieee80211vap *vap, os_handle_t oshandle, wlan_misc_event_handler_table *evtab)
{
    int i;
    /* unregister if there exists one already */
    ieee80211_vap_unregister_misc_events(vap,oshandle,evtab);
    IEEE80211_VAP_LOCK(vap);
    for (i=0;i<IEEE80211_MAX_MISC_EVENT_HANDLERS; ++i) {
        if ( vap->iv_misc_evtable[i] == NULL) {
            vap->iv_misc_evtable[i] = evtab;
            vap->iv_misc_arg[i] = oshandle;
            IEEE80211_VAP_UNLOCK(vap);
            return 0;
        }
    }
    IEEE80211_VAP_UNLOCK(vap);
    return ENOMEM;
}

int
ieee80211_vap_unregister_misc_events(struct ieee80211vap *vap,os_handle_t oshandle, wlan_misc_event_handler_table *evtab)
{
    int i;
    IEEE80211_VAP_LOCK(vap);
    for (i=0;i<IEEE80211_MAX_MISC_EVENT_HANDLERS; ++i) {
        if ( vap->iv_misc_evtable[i] == evtab && vap->iv_misc_arg[i] == oshandle) {
            vap->iv_misc_evtable[i] = NULL;
            vap->iv_misc_arg[i] = NULL;
            IEEE80211_VAP_UNLOCK(vap);
            return 0;
        }
    }
    IEEE80211_VAP_UNLOCK(vap);
    return EEXIST;
}

int ieee80211_vap_register_ccx_events(struct ieee80211vap *vap, os_if_t osif, wlan_ccx_handler_table *evtab)
{
    vap->iv_ccx_arg = osif;
    vap->iv_ccx_evtable = evtab;
    return 0;
}

int
ieee80211_vap_match_ssid(struct ieee80211vap *vap, const u_int8_t *ssid, u_int8_t ssidlen)
{
    int i;

    for (i = 0; i < vap->iv_des_nssid; i++) {
        if ((vap->iv_des_ssid[i].len == ssidlen) &&
            (OS_MEMCMP(vap->iv_des_ssid[i].ssid, ssid, ssidlen) == 0)) {
            /* find a matching entry */
            return 1;
        }
    }

    return 0;
}

/*
 * free the vap and deliver event.
 */
void ieee80211_vap_free(struct ieee80211vap *vap)
{
    struct ieee80211com *ic  = vap->iv_ic;
    os_if_t             osif = vap->iv_ifp;

    ic->ic_vap_delete(vap);
    IEEE80211COM_DELIVER_VAP_EVENT(ic, osif, IEEE80211_VAP_DELETED);
}

/*
 * deliver the stop event to osif layer.
 */
void ieee80211_vap_deliver_stop(struct ieee80211vap *vap)
{
    struct ieee80211com *ic;
    os_if_t             osif;

    if (vap) {
        ic = vap->iv_ic;
        osif = vap->iv_ifp;

        IEEE80211COM_DELIVER_VAP_EVENT(ic, osif, IEEE80211_VAP_STOPPED);
    }
}

/*
 * deliver the error event to osif layer.
 */
void ieee80211_vap_deliver_stop_error(struct ieee80211vap *vap)
{
    struct ieee80211com *ic;
    os_if_t             osif;

    if (vap) {
        ic = vap->iv_ic;
        osif = vap->iv_ifp;

        IEEE80211COM_DELIVER_VAP_EVENT(ic, osif, IEEE80211_VAP_STOP_ERROR);
    }
}

/**
 * @register a vap event handler.
 * ARGS :
 *  ieee80211_vap_event_handler : vap event handler
 *  arg                         : argument passed back via the evnt handler
 * RETURNS:
 *  on success returns 0.
 *  on failure returns a negative value.
 * allows more than one event handler to be registered.
 */
int ieee80211_vap_unregister_event_handler(ieee80211_vap_t vap,ieee80211_vap_event_handler evhandler, void *arg)
{
    int i;
    IEEE80211_VAP_LOCK(vap);
    for (i=0;i<IEEE80211_MAX_VAP_EVENT_HANDLERS; ++i) {
        if ( vap->iv_event_handler[i] == evhandler &&  vap->iv_event_handler_arg[i] == arg ) {
            vap->iv_event_handler[i] = NULL;
            vap->iv_event_handler_arg[i] = NULL;
            IEEE80211_VAP_UNLOCK(vap);
            return 0;
        }
    }
    IEEE80211_VAP_UNLOCK(vap);
    return EEXIST;

}

/**
 * @unregister a vap event handler.
 * ARGS :
 *  ieee80211_vap_event_handler : vap event handler
 *  arg                         : argument passed back via the evnt handler
 * RETURNS:
 *  on success returns 0.
 *  on failure returns a negative value.
 */
int ieee80211_vap_register_event_handler(ieee80211_vap_t vap,ieee80211_vap_event_handler evhandler, void *arg)
{
    int i;
    /* unregister if there exists one already */
    ieee80211_vap_unregister_event_handler(vap,evhandler,arg);

    IEEE80211_VAP_LOCK(vap);
    for (i=0;i<IEEE80211_MAX_VAP_EVENT_HANDLERS; ++i) {
        if ( vap->iv_event_handler[i] == NULL) {
            vap->iv_event_handler[i] = evhandler;
            vap->iv_event_handler_arg[i] = arg;
            IEEE80211_VAP_UNLOCK(vap);
            return 0;
        }
    }
    IEEE80211_VAP_UNLOCK(vap);
    return ENOMEM;
}

void ieee80211_vap_deliver_event(struct ieee80211vap *vap, ieee80211_vap_event *event)
{
    int i;
    void *arg;
    ieee80211_vap_event_handler evhandler;
    IEEE80211_VAP_LOCK(vap);
    for(i=0;i<IEEE80211_MAX_VAP_EVENT_HANDLERS; ++i) {
        if (vap->iv_event_handler[i]) {
            evhandler =  vap->iv_event_handler[i];
            arg = vap->iv_event_handler_arg[i];
            IEEE80211_VAP_UNLOCK(vap);
            (* evhandler) (vap, event,arg);
            IEEE80211_VAP_LOCK(vap);
        }
    }
    IEEE80211_VAP_UNLOCK(vap);
}

/* Return true if any VAP is in RUNNING state */
int
ieee80211_vap_is_any_running(struct ieee80211com *ic)
{

    struct ieee80211vap *vap;
    int running = 0;
    IEEE80211_COMM_LOCK(ic);
    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if (vap->iv_opmode != IEEE80211_M_HOSTAP && vap->iv_opmode != IEEE80211_M_IBSS) {
            continue;
        }
        if (vap->channel_switch_state) {
            continue;
        }
        if (vap->iv_state_info.iv_state == IEEE80211_S_RUN) {
            running++;
            break;
        }
    }
    IEEE80211_COMM_UNLOCK(ic);
    return running;
}

int
ieee80211_num_apvap_running(struct ieee80211com *ic)
{

    struct ieee80211vap *vap;
    int running = 0;
    IEEE80211_COMM_LOCK(ic);
    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if ((vap->iv_state_info.iv_state == IEEE80211_S_RUN) &&
                vap->iv_opmode == IEEE80211_M_HOSTAP) {
            running++;
        }
    }
    IEEE80211_COMM_UNLOCK(ic);
    return running;
}

/**
 * @ get opmode
 * ARGS:
 *  vap    : handle to vap.
 * RETURNS: returns opmode of the vap.
 */
enum ieee80211_opmode ieee80211_vap_get_opmode(ieee80211_vap_t vap)
{
    return  vap->iv_opmode;
}

const char* ieee80211_opmode2string( enum ieee80211_opmode opmode)
{
    switch ( opmode )
    {
    case IEEE80211_M_STA:
         return "IEEE80211_M_STA";
    case IEEE80211_M_IBSS:
     return "IEEE80211_M_IBSS";
    case IEEE80211_M_AHDEMO:
     return "IEEE80211_M_AHDEMO";
    case IEEE80211_M_HOSTAP:
         return "IEEE80211_M_HOSTAP";
    case IEEE80211_M_MONITOR:
     return "IEEE80211_M_MONITOR";
    case IEEE80211_M_WDS:
     return "IEEE80211_M_WDS";
    case IEEE80211_M_BTAMP:
     return "IEEE80211_M_BTAMP";
    case IEEE80211_M_ANY:
     return "IEEE80211_M_ANY";

    default:
     return "Unknown ieee80211_opmode";
    }
};


void wlan_vap_up_check_beacon_interval(struct ieee80211vap *vap, enum ieee80211_opmode opmode)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ieee80211vap *tmpvap;

    IEEE80211_COMM_LOCK_BH(ic);

    if (opmode == IEEE80211_M_HOSTAP) {
        ic->ic_num_ap_vaps++;
        /* Increment lp_iot_mode vap count if flags indicate. */
        if (vap->iv_create_flags & IEEE80211_LP_IOT_VAP)  {
            if (!ic->ic_num_lp_iot_vaps) {
                ic->ic_num_lp_iot_vaps=1;
            } else {
                 IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD, IEEE80211_MSG_DEBUG,
                         "Only one Low power vap is supported \n");
            };
        }
#if ATH_PERF_PWR_OFFLOAD
        if (MBSSID_BINTVAL_CHECK(ic->ic_intval, ic->ic_num_ap_vaps, scn->bcn_mode)) {
            ic->ic_need_vap_reinit = 0;
        }
        else {
            /*
             * If a new VAP is created on runtime , we need to ensure that beacon interval is atleast 50 when NoOfVAPS<=2 ,
             *  100 when NoOfVAPS<=8 and 200 when NoOfVAPS<=16
             */
            if(ic->ic_num_ap_vaps <= IEEE80211_BINTVAL_VAPCOUNT1){
                ic->ic_intval = IEEE80211_OL_BINTVAL_MINVAL_RANGE1;
                ic->ic_need_vap_reinit = 1;
            }
            else if(ic->ic_num_ap_vaps <= IEEE80211_BINTVAL_VAPCOUNT2) {
                ic->ic_intval = IEEE80211_BINTVAL_MINVAL_RANGE2;
                ic->ic_need_vap_reinit = 1;

            }
            else {
                if(scn->bcn_mode == 1) { //burst mode enabled so limit the beacon interval value to 100
                    ic->ic_intval = IEEE80211_BINTVAL_MINVAL_RANGE2;
                }
                else { // burst mode disabled (staggered) , limit the beacon interval to 200
                    ic->ic_intval = IEEE80211_BINTVAL_MINVAL_RANGE3;
                }

                ic->ic_need_vap_reinit = 1;

            }


        }
#endif
        /* There is a need to upconvert all vap's bintval to a factor of the LP IOT vap's beacon intval */
        if (vap->iv_create_flags & IEEE80211_LP_IOT_VAP)  {
            u_int8_t lp_vap_is_present=0;
            u_int16_t lp_bintval = ic->ic_intval;

            /* Iterate to find if a LP IOT vap is there */
            TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
                if (tmpvap->iv_create_flags & IEEE80211_LP_IOT_VAP) {
                    lp_vap_is_present = 1;
                    /* If multiple lp iot vaps are present pick the least */
                    if (lp_bintval > tmpvap->iv_bss->ni_intval)  {
                        lp_bintval = tmpvap->iv_bss->ni_intval;
                    }
                }
            }

            /* up convert beacon interval in ic to a factor of LP vap */
            if (lp_vap_is_present)  {
                UP_CONVERT_TO_FACTOR_OF(ic->ic_intval, lp_bintval);
            }

            TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
                if (lp_vap_is_present)  {
                    if (!(tmpvap->iv_create_flags & IEEE80211_LP_IOT_VAP)) {
                        /* up convert vap beacon interval in ni to a factor of LP vap */
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                                "Current beacon interval %d: Checking if up conversion is needed as lp_iot vap is present. ", ic->ic_intval);
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                                "New beacon interval  %d \n", ic->ic_intval);
                    }
                    UP_CONVERT_TO_FACTOR_OF(tmpvap->iv_bss->ni_intval, lp_bintval);
                }
            }
            ic->ic_need_vap_reinit = 1;  /* Better to reinit */
        }

        if (!(ic->ic_is_mode_offload(ic))) {
            /*TODO SRK: Direct Attach? Increment lp_iot_mode vap count if flags indicate. */
            LIMIT_BEACON_PERIOD(ic->ic_intval);
            ic->ic_set_beacon_interval(ic);
        }
    }

    IEEE80211_COMM_UNLOCK_BH(ic);
}

void wlan_vap_down_check_beacon_interval(struct ieee80211vap *vap, enum ieee80211_opmode opmode)
{
    struct ieee80211com *ic = vap->iv_ic;

    IEEE80211_COMM_LOCK_BH(ic);

    if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
        if (vap->iv_create_flags & IEEE80211_LP_IOT_VAP)  {
            /* Even though it is not expected we do see multiple down calls which ends up in wrapround
               So resetting instead of downcount.  */
            ic->ic_num_lp_iot_vaps=0;
        }
        if ((ic->ic_is_mode_offload(ic)) && ic->ic_num_ap_vaps) {
            ic->ic_need_vap_reinit = 0;
        }
        if (ic->ic_num_ap_vaps)
        {
            ic->ic_num_ap_vaps--;
        }

    }

    IEEE80211_COMM_UNLOCK_BH(ic);
}


/*
 * @ check if vap is in running state
 * ARGS:
 *  vap    : handle to vap.
 * RETURNS:
 *  TRUE if current state of the vap is IEE80211_S_RUN.
 *  FALSE otherwise.
 */
bool ieee80211_is_vap_state_running(ieee80211_vap_t vap)
{
    return (vap->iv_state_info.iv_state == IEEE80211_S_RUN ? TRUE : FALSE);
}

/*
 * External UMAC Interface
 */
wlan_if_t
wlan_vap_create(wlan_dev_t            devhandle,
                enum ieee80211_opmode opmode,
                int                   scan_priority_base,
                u_int32_t             flags,
                u_int8_t              *bssid,
                u_int8_t              *mataddr,
                void                   *osifp_handle)
{
    struct ieee80211com *ic = devhandle;
    struct ieee80211vap *vap;

    IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD, IEEE80211_MSG_DEBUG,
                         "%s : enter. devhandle=0x%x, opmode=%s, flags=0x%x\n",
             __func__,
             devhandle,
             ieee80211_opmode2string(opmode),
             flags
             );

    /* For now restrict lp_iot vaps to just 1 */
    if ((opmode == IEEE80211_M_HOSTAP) && (flags & IEEE80211_LP_IOT_VAP) && (ic->ic_num_lp_iot_vaps)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: cant create more than 1 lp_iot mode vap object \n", __func__);
        return NULL;
    }

    vap = ic->ic_vap_create(ic, opmode, scan_priority_base, flags, bssid, mataddr, osifp_handle);
    if (vap == NULL) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: failed to create a vap object\n", __func__);
        return NULL;
    }

    ieee80211_vap_pause_late_vattach(ic,vap);
    ieee80211_resmgr_vattach(ic->ic_resmgr, vap);

    ieee80211_vap_deleted_clear(vap); /* clear the deleted */

    /* when all  done,  add vap to queue */
    IEEE80211_COMM_LOCK_BH(ic);
    TAILQ_INSERT_TAIL(&ic->ic_vaps, vap, iv_next);

    /*
     * Ensure that beacon interval is atleast 50 when NoOfVAPS<=2 , 100 when NoOfVAPS<=8 and 200 when NoOfVAPS<=16
     *
     */
    IEEE80211_COMM_UNLOCK_BH(ic);

    IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD, IEEE80211_MSG_DEBUG,
             "%s : exit. devhandle=0x%x, vap=0x%x, opmode=%s, flags=0x%x.\n",
             __func__,
             devhandle,
             vap,
             ieee80211_opmode2string(opmode),
             flags
             );
#if ATH_SUPPORT_FLOWMAC_MODULE
    /*
     * Due to platform dependency the flow control need to check the status
     * of the lmac layer before enabling the flow mac at vap layer.
     *
     * Enabling of the flowmac happens after creating the wifi interface
     */
    vap->iv_flowmac = ic->ic_get_flowmac_enabled_State(ic);
#endif
#if ATH_PERF_PWR_OFFLOAD
#if ATH_SUPPORT_DSCP_OVERRIDE
    OS_MEMCPY(vap->iv_dscp_tid_map, dscp_tid_map, sizeof(A_UINT32) * WMI_HOST_DSCP_MAP_MAX);
    vap->iv_override_dscp = 0x00;
#endif
#endif
#if UNIFIED_SMARTANTENNA
    ic->sta_not_connected_cfg = TRUE;
    ieee80211_smart_ant_init(ic, vap, SMART_ANT_STA_NOT_CONNECTED | SMART_ANT_NEW_CONFIGURATION);
#endif
    return vap;
}

void ic_mon_vap_update(struct ieee80211com *ic, struct ieee80211vap *vap)
{
    if(vap->iv_opmode == IEEE80211_M_MONITOR)
        ic->ic_mon_vap = vap;
}

void ic_sta_vap_update(struct ieee80211com *ic, struct ieee80211vap *vap)
{
    STA_VAP_DOWNUP_LOCK(ic);
    if(vap->iv_opmode == IEEE80211_M_STA) {
        /*
         * In QWRAP mode remember the main proxy STA
         * In non QWRAP mode remember the only STA
         */
#if ATH_SUPPORT_WRAP
    if(wlan_is_psta(vap)) {
        if(wlan_is_mpsta(vap))
            ic->ic_sta_vap = vap;
    } else  {
            ic->ic_sta_vap = vap;
    }
#else
    ic->ic_sta_vap = vap;
#endif
    }
    STA_VAP_DOWNUP_UNLOCK(ic);
}

void ic_reset_params(struct ieee80211com *ic)
{

    if (ic->ic_acs) {
        ieee80211_acs_deinit(&(ic->ic_acs));
        ieee80211_acs_init(&(ic->ic_acs), ic, ic->ic_osdev);
    }
    ieee80211_scan_reset_flags(ic);
    ieee80211_scan_table_flush(ic->ic_scan_table);
#if ACFG_NETLINK_TX
    acfg_clean(ic);
#endif

#if ATH_SUPPORT_DSCP_OVERRIDE
    ic->ic_override_hmmc_dscp               = 0;
    ic->ic_dscp_hmmc_tid                    = 0;
    ic->ic_dscp_igmp_tid                    = 0;
    ic->ic_override_igmp_dscp               = 0;
#endif
#if UMAC_SUPPORT_PERIODIC_PERFSTATS
    ic->ic_thrput.is_enab                   = 0;
    ic->ic_thrput.histogram_size            = 15;
    ic->ic_per.is_enab                      = 0;
    ic->ic_per.histogram_size               = 300;
#endif
    ic->ic_blkreportflood                   = 0;
    ic->ic_dropstaquery                     = 0;
    ic->ic_consider_obss_long_slot          = CONSIDER_OBSS_LONG_SLOT_DEFAULT;
    ic->ic_sta_vap_amsdu_disable            = 0;
#if QCA_AIRTIME_FAIRNESS
    ic->atf_txbuf_max                       = -1;
    ic->atf_txbuf_min                       = -1;
    ic->atf_txbuf_share                     =  0;
    ic->ic_atf_sched                        = 0;    /*reset*/
    ic->ic_atf_sched &= ~IEEE80211_ATF_SCHED_STRICT;    /*Disable Strict queue*/
    ic->ic_atf_sched |= IEEE80211_ATF_SCHED_OBSS;    /*Enable OBSS*/
#endif

    ieee80211com_set_cap(ic,
                        IEEE80211_C_WEP
                        | IEEE80211_C_AES
                        | IEEE80211_C_AES_CCM
                        | IEEE80211_C_CKIP
                        | IEEE80211_C_TKIP
                        | IEEE80211_C_TKIPMIC
#if ATH_SUPPORT_WAPI
                        | IEEE80211_C_WAPI
#endif
                        | IEEE80211_C_WME);

    ieee80211com_clear_cap_ext(ic,-1);
    ieee80211com_set_cap_ext(ic,
                            IEEE80211_CEXT_PERF_PWR_OFLD
                            | IEEE80211_CEXT_MULTICHAN
                            | IEEE80211_CEXT_11AC);
    /* ic_flags */
    ieee80211com_clear_flags(ic,-1);
    IEEE80211_ENABLE_SHPREAMBLE(ic);
    IEEE80211_ENABLE_SHSLOT(ic);
    IEEE80211_ENABLE_DATAPAD(ic);
    IEEE80211_COEXT_DISABLE(ic);

    /* ic_flags_ext */
    ieee80211com_clear_flags_ext(ic,-1);
    IEEE80211_ENABLE_COUNTRYIE(ic);
    IEEE80211_UAPSD_ENABLE(ic);
    IEEE80211_FEXT_MARKDFS_ENABLE(ic);
    IEEE80211_SET_DESIRED_COUNTRY(ic);
    IEEE80211_ENABLE_11D(ic);
    IEEE80211_ENABLE_AMPDU(ic);
    IEEE80211_ENABLE_IGNORE_11D_BEACON(ic);
    /* ic_flags_ext2 */
    ic->ic_flags_ext2 &= ~IEEE80211_FEXT2_CSA_WAIT;

    ieee80211_ic_wep_tkip_htrate_clear(ic);
    ieee80211_ic_non_ht_ap_clear(ic);
    ieee80211_ic_block_dfschan_clear(ic);
    ieee80211_ic_doth_set(ic);             /* Default 11h to start enabled  */
    ieee80211_ic_off_channel_support_clear(ic);
    ieee80211_ic_ht20Adhoc_clear(ic);
    ieee80211_ic_ht40Adhoc_clear(ic);
    ieee80211_ic_htAdhocAggr_clear(ic);
    ieee80211_ic_disallowAutoCCchange_clear(ic);
    ieee80211_ic_p2pDevEnable_clear(ic);
    ieee80211_ic_ignoreDynamicHalt_clear(ic);
    ieee80211_ic_override_proberesp_ie_set(ic);
    ieee80211_ic_wnm_set(ic);
    ieee80211_ic_2g_csa_clear(ic);
    ieee80211_ic_offchanscan_clear(ic);
    ieee80211_ic_enh_ind_rpt_clear(ic);
    ieee80211com_clear_htflags(ic, IEEE80211_HTF_SHORTGI40 | IEEE80211_HTF_SHORTGI20);
    ieee80211com_set_htflags(ic, IEEE80211_HTF_SHORTGI40 | IEEE80211_HTF_SHORTGI20);
    ieee80211com_set_maxampdu(ic, IEEE80211_HTCAP_MAXRXAMPDU_65536);
    /*Default wradar channel filtering is disabled  */
    ic->ic_no_weather_radar_chan = 0;
    ic->ic_intval = IEEE80211_BINTVAL_DEFAULT; /* beacon interval */
    ic->ic_lintval = 1;         /* listen interval */
    ic->ic_lintval_assoc = IEEE80211_LINTVAL_MAX; /* listen interval to use in association */
    ic->ic_bmisstimeout = IEEE80211_BMISS_LIMIT * ic->ic_intval;
    ic->ic_txpowlimit = IEEE80211_TXPOWER_MAX;
    ic->ic_multiDomainEnabled = 0;

#if UMAC_SUPPORT_ACFG
    ic->ic_diag_enable=0;
#endif
    ic->ic_chan_stats_th = IEEE80211_CHAN_STATS_THRESOLD;
    ic->ic_strict_pscan_enable = 0;
    ic->ic_min_rssi_enable = false;
    ic->ic_min_rssi = 0;
    ic->ic_tx_next_ch = NULL;
    ic->ic_strict_doth = 0;
    ic->ic_non_doth_sta_cnt = 0;
#if DBDC_REPEATER_SUPPORT
    ic->fast_lane = 0;
    ic->fast_lane_ic = NULL;
#endif
    ic->ic_auth_tx_xretry = 0;
#if ATH_SUPPORT_NR_SYNC
    ic->ic_nr_share_radio_flag = 0xff;
#endif
}

void global_ic_list_reset_params(struct ieee80211com *ic) {

    GLOBAL_IC_LOCK(ic->ic_global_list);
    ic->ic_global_list->dbdc_process_enable = 1;
    ic->ic_global_list->force_client_mcast_traffic = 0;
    ic->ic_global_list->delay_stavap_connection = 0;
    ic->ic_global_list->num_stavaps_up = 0;
    ic->ic_global_list->is_dbdc_rootAP = 0;
    ic->ic_global_list->iface_mgr_up = 0;
    ic->ic_global_list->disconnect_timeout = 10;
    ic->ic_global_list->reconfiguration_timeout = 60;
    ic->ic_global_list->always_primary = 0;
    ic->ic_global_list->num_fast_lane_ic = 0;
    ic->ic_global_list->max_priority_stavap_up = NULL;
    GLOBAL_IC_UNLOCK(ic->ic_global_list);
}

int
wlan_vap_delete_remove(struct ieee80211vap *vap, int stop)
{
    struct ieee80211com *ic = vap->iv_ic;

    IEEE80211_COMM_LOCK_BH(ic);

    if (ieee80211_vap_deleted_is_clear(vap)) /* if not deleted then it is on the list */
        {
            TAILQ_REMOVE(&ic->ic_vaps, vap, iv_next);
            if (TAILQ_EMPTY(&ic->ic_vaps))      /* reset to supported mode */
                ic->ic_opmode = IEEE80211_M_STA;
            ieee80211_vap_deleted_set(vap); /* mark it as deleted */

            IEEE80211_COMM_UNLOCK_BH(ic);

            if (stop) {
                if (vap->iv_opmode == IEEE80211_M_MONITOR) {

                    wlan_mlme_stop_bss(vap,
                                       WLAN_MLME_STOP_BSS_F_FORCE_STOP_RESET   |
                                       WLAN_MLME_STOP_BSS_F_NO_RESET);

                } else {

                    /*
                     * In case iv_bss was not stopped or is in scanning.
                     * TBD: BSS should have been stopped now. We can save the time for stop bss again.
                     */
                    wlan_mlme_stop_bss(vap,
                                       WLAN_MLME_STOP_BSS_F_SEND_DEAUTH        |
                                       WLAN_MLME_STOP_BSS_F_CLEAR_ASSOC_STATE  |
                                       WLAN_MLME_STOP_BSS_F_WAIT_RX_DONE       |
                                       WLAN_MLME_STOP_BSS_F_NO_RESET);

                }
            }

            if (vap->iv_bss) {
                ieee80211_sta_leave(vap->iv_bss);
            }
            ieee80211_node_vdetach(vap);
        } else {
        IEEE80211_COMM_UNLOCK_BH(ic);
    }

    return 0;
}

int
wlan_vap_delete_start(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;

    ieee80211_vap_pause_vdetach(ic,vap);

    return 0;
}

int
wlan_vap_delete_complete(struct ieee80211vap *vap)
{
#if UNIFIED_SMARTANTENNA
    struct ieee80211com *ic = vap->iv_ic;
    int nacvaps = 0;
    u_int32_t osif_get_num_active_vaps( wlan_dev_t  comhandle);

    nacvaps = osif_get_num_active_vaps(ic);
    if (nacvaps == 0) {
        ieee80211_smart_ant_deinit(ic, vap, SMART_ANT_NEW_CONFIGURATION);
    }
#endif
    return 0;
}

int
wlan_vap_recover(wlan_if_t vap)
{
    wlan_vap_delete_start(vap);

    wlan_vap_delete_remove(vap, 0);

    wlan_vap_delete_complete(vap);

    return 0;
}

int
wlan_vap_delete(wlan_if_t vap)
{
    wlan_vap_delete_start(vap);

    wlan_vap_delete_remove(vap, 1);

    wlan_vap_delete_complete(vap);

    return 0;
}

void wlan_stop(struct ieee80211com *ic)
{
    ic->ic_stop(ic);
    ic_reset_params(ic);
    global_ic_list_reset_params(ic);
}


int wlan_vap_allocate_mac_addr(wlan_dev_t devhandle, u_int8_t *bssid)
{
    struct ieee80211com *ic = devhandle;
    return ic->ic_vap_alloc_macaddr(ic,bssid);
}

int wlan_vap_free_mac_addr(wlan_dev_t devhandle, u_int8_t *bssid)
{
    struct ieee80211com *ic = devhandle;
    return ic->ic_vap_free_macaddr(ic,bssid);
}
int
wlan_vap_register_event_handlers(wlan_if_t vaphandle,
                                 wlan_event_handler_table *evtable)
{
    return ieee80211_vap_register_events(vaphandle,evtable);
}
int
wlan_vap_register_mlme_event_handlers(wlan_if_t vaphandle,
                                 os_handle_t oshandle,
                                 wlan_mlme_event_handler_table *evtable)
{
    return ieee80211_vap_register_mlme_events(vaphandle, oshandle, evtable);
}

int
wlan_vap_unregister_mlme_event_handlers(wlan_if_t vaphandle,
                                 os_handle_t oshandle,
                                 wlan_mlme_event_handler_table *evtable)
{
    return ieee80211_vap_unregister_mlme_events(vaphandle, oshandle, evtable);
}

int
wlan_vap_register_misc_event_handlers(wlan_if_t vaphandle,
                                 os_handle_t oshandle,
                                 wlan_misc_event_handler_table *evtable)
{
    return ieee80211_vap_register_misc_events(vaphandle, oshandle, evtable);
}

int
wlan_vap_unregister_misc_event_handlers(wlan_if_t vaphandle,
                                 os_handle_t oshandle,
                                 wlan_misc_event_handler_table *evtable)
{
    return ieee80211_vap_unregister_misc_events(vaphandle, oshandle, evtable);
}

int
wlan_vap_register_ccx_event_handlers(wlan_if_t vaphandle,
                                 os_if_t osif,
                                 wlan_ccx_handler_table *evtable)
{
    return ieee80211_vap_register_ccx_events(vaphandle, osif, evtable);
}

os_if_t
wlan_vap_get_registered_handle(wlan_if_t vap)
{
    return (os_if_t)vap->iv_ifp;
}

void
wlan_vap_set_registered_handle(wlan_if_t vap, os_if_t osif)
{
    vap->iv_ifp = osif;
}

void *wlan_vap_get_ol_data_handle(wlan_if_t vap)
{
   if (vap->iv_vap_get_ol_data_handle) {
      return vap->iv_vap_get_ol_data_handle(vap);
   }
   return NULL;
}
EXPORT_SYMBOL(wlan_vap_get_ol_data_handle);

wlan_dev_t
wlan_vap_get_devhandle(wlan_if_t vap)
{
    return (wlan_dev_t)vap->iv_ic;
}

struct wlan_iter_func_arg {
    ieee80211_vap_iter_func iter_func;
    void  *iter_arg;
};

static INLINE void
wlan_iter_func(void *arg, struct ieee80211vap *vap, bool is_last_vap)
{
    struct wlan_iter_func_arg *params =  (struct wlan_iter_func_arg *) arg;
    if (params->iter_func) {
        params->iter_func(params->iter_arg,vap);
    }
}

u_int32_t wlan_iterate_vap_list(wlan_dev_t ic,ieee80211_vap_iter_func iter_func,void *arg)
{
    u_int32_t num_vaps=0;
    struct wlan_iter_func_arg params;

    params.iter_func = iter_func;
    params.iter_arg = arg;
    ieee80211_iterate_vap_list_internal(ic,wlan_iter_func,(void *) &params,num_vaps);
    return num_vaps;
}

enum ieee80211_opmode
wlan_vap_get_opmode(wlan_if_t vaphandle)
{
    return vaphandle->iv_opmode;
}

u_int8_t *
wlan_vap_get_macaddr(wlan_if_t vaphandle)
{
    return vaphandle->iv_myaddr;
}

u_int8_t *
wlan_vap_get_hw_macaddr(wlan_if_t vaphandle)
{
    return vaphandle->iv_my_hwaddr;
}

ieee80211_aplist_config_t
ieee80211_vap_get_aplist_config(struct ieee80211vap *vap)
{
    return vap->iv_aplist_config;
}

ieee80211_candidate_aplist_t
ieee80211_vap_get_aplist(struct ieee80211vap *vap)
{
    return vap->iv_candidate_aplist;
}

ieee80211_scan_table_t
ieee80211_vap_get_scan_table(struct ieee80211vap *vap)
{
    /*
     * If multiple-VAP scan is enabled, each VAP holds a scan table which is
     * created during VAP initialization.
     * If multiple-VAP scan is disabled, the scan table is kept by the IC and
     * shared by VAPs.
     */
#if ATH_SUPPORT_MULTIPLE_SCANS
    return vap->iv_scan_table;
#else
    return vap->iv_ic->ic_scan_table;
#endif
}

static void
ieee80211_reset_stats(struct ieee80211vap *vap, int reset_hw)
{
#if !ATH_SUPPORT_STATS_APONLY
    struct ieee80211com *ic = vap->iv_ic;
#endif

    OS_MEMZERO(&vap->iv_unicast_stats, sizeof(struct ieee80211_mac_stats));
    OS_MEMZERO(&vap->iv_multicast_stats, sizeof(struct ieee80211_mac_stats));
#if !ATH_SUPPORT_STATS_APONLY

    if (reset_hw) {
        OS_MEMZERO(&ic->ic_phy_stats[0],
                   sizeof(struct ieee80211_phy_stats) * IEEE80211_MODE_MAX);

        /* clear H/W phy counters */
        ic->ic_clear_phystats(ic);
    }
#endif
}

const struct ieee80211_stats *
wlan_gen_stats(wlan_if_t vaphandle)
{
    return &vaphandle->iv_stats;
}

const struct ieee80211_mac_stats *
wlan_mac_stats(wlan_if_t vaphandle, int is_mcast)
{
    if (is_mcast)
        return &vaphandle->iv_multicast_stats;
    else
        return &vaphandle->iv_unicast_stats;
}

#if !ATH_SUPPORT_STATS_APONLY
const struct ieee80211_phy_stats *
wlan_phy_stats(wlan_dev_t devhandle, enum ieee80211_phymode mode)
{
    struct ieee80211com *ic = devhandle;

    KASSERT(mode != IEEE80211_MODE_AUTO && mode < IEEE80211_MODE_MAX,
            ("Invalid PHY mode\n"));

    if (ic->ic_update_phystats) {
    ic->ic_update_phystats(ic, mode);
	}
    return &ic->ic_phy_stats[mode];
}
#endif

systime_t ieee80211_get_last_data_timestamp(wlan_if_t vaphandle)
{
    return vaphandle->iv_lastdata;
}

systime_t ieee80211_get_directed_frame_timestamp(wlan_if_t vaphandle)
{
    /*
     * Now that we have an API it's a good opportunity to synchronize access
     * to this field.
     */
    return vaphandle->iv_last_directed_frame;
}

systime_t ieee80211_get_last_ap_frame_timestamp(wlan_if_t vaphandle)
{
    /*
     * Now that we have an API it's a good opportunity to synchronize access
     * to this field.
     */
    return vaphandle->iv_last_ap_frame;
}

systime_t wlan_get_directed_frame_timestamp(wlan_if_t vaphandle)
{
    return ieee80211_get_directed_frame_timestamp(vaphandle);
}

systime_t wlan_get_last_ap_frame_timestamp(wlan_if_t vaphandle)
{
    return ieee80211_get_last_ap_frame_timestamp(vaphandle);
}

systime_t ieee80211_get_traffic_indication_timestamp(wlan_if_t vaphandle)
{
    return vaphandle->iv_last_traffic_indication;
}

systime_t wlan_get_traffic_indication_timestamp(wlan_if_t vaphandle)
{
    return ieee80211_get_traffic_indication_timestamp(vaphandle);
}

bool ieee80211_is_connected(wlan_if_t vaphandle)
{
    return (ieee80211_vap_ready_is_set(vaphandle));
}

bool wlan_is_connected(wlan_if_t vaphandle)
{
    return (ieee80211_vap_ready_is_set(vaphandle));
}

static void ieee80211_get_active_vap_iter_func(void *arg, wlan_if_t vap)
{

    u_int16_t *active_vaps = (u_int16_t *) arg;

    if (ieee80211_vap_active_is_set(vap)) {
        ++(*active_vaps);
    }
}

u_int32_t  ieee80211_get_num_active_vaps(wlan_dev_t  comhandle) {

    u_int16_t num_active_vaps=0;
    wlan_iterate_vap_list(comhandle,ieee80211_get_active_vap_iter_func,(void *)&num_active_vaps);
    return num_active_vaps;

}

#if ATH_SUPPORT_WRAP
bool wlan_is_psta(wlan_if_t vaphandle)
{
    return (ieee80211_vap_psta_is_set(vaphandle));
}
EXPORT_SYMBOL(wlan_is_psta);

bool wlan_is_mpsta(wlan_if_t vaphandle)
{
    return (ieee80211_vap_mpsta_is_set(vaphandle));
}
EXPORT_SYMBOL(wlan_is_mpsta);

bool wlan_is_wrap(wlan_if_t vaphandle)
{
    return (ieee80211_vap_wrap_is_set(vaphandle));
}

static INLINE void ieee80211_wrap_iter_func(void *arg, wlan_if_t vap)
{
   u_int16_t *num_wraps = (u_int16_t *) arg;

   if (ieee80211_vap_wrap_is_set(vap))
       ++(*num_wraps);
}

int wlan_vap_get_num_wraps(wlan_dev_t  comhandle)
{
    u_int16_t num_wraps=0;
    wlan_iterate_vap_list(comhandle,ieee80211_wrap_iter_func,(void *)&num_wraps);
    return num_wraps;
}

#endif

int wlan_vap_get_bssid(wlan_if_t vaphandle, u_int8_t *bssid)
{
    /* need locking to prevent changing the iv_bss */
    IEEE80211_VAP_LOCK(vaphandle);
    if (vaphandle->iv_bss) {
        IEEE80211_ADDR_COPY(bssid, vaphandle->iv_bss->ni_bssid);
        IEEE80211_VAP_UNLOCK(vaphandle);
        return EOK;
    }
    IEEE80211_VAP_UNLOCK(vaphandle);
    return -EINVAL;
}

int wlan_reset_start(wlan_if_t vaphandle, ieee80211_reset_request *reset_req)
{
    struct ieee80211com *ic = vaphandle->iv_ic;

    /*
     * TBD: Flush data queues only for vaphandle if
     * IEEE80211_RESET_TYPE_DOT11_INTF is set.
     */
    return ic->ic_reset_start(ic, reset_req->no_flush);
}
#if ATH_SUPPORT_WRAP
int wlan_wrap_set_key(wlan_if_t vaphandle)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;

    return ic->ic_wrap_set_key(vap);
}

int wlan_wrap_del_key(wlan_if_t vaphandle)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;

    return ic->ic_wrap_del_key(vap);
}
#endif

static int
ieee80211_vap_reset(struct ieee80211vap *vap, ieee80211_reset_request *reset_req)
{
    struct ieee80211com *ic = vap->iv_ic;

    /* Cancel pending MLME requests */
    wlan_mlme_cancel(vap);

    /*
     * Reset node table include all nodes.
     * NB: pairwise keys will be deleted during node cleanup.
     */
    ieee80211_reset_bss(vap);

    /* Reset aplist configuration parameters */
    ieee80211_aplist_config_init(ieee80211_vap_get_aplist_config(vap));

    /* Reset RSN settings */
    ieee80211_rsn_reset(vap);

    /* Reset statistics */
    ieee80211_reset_stats(vap, reset_req->reset_hw);

    /* Reset some of the misc. vap settings */
    vap->iv_des_modecaps = (1 << IEEE80211_MODE_AUTO);
    vap->iv_des_nssid = 0;
    OS_MEMZERO(&vap->iv_des_ssid[0], (sizeof(ieee80211_ssid) * IEEE80211_SCAN_MAX_SSID));

    /* Because reset_start has graspped a mutex which chan_set
     *will also try to grasp, so don't call ieee80211_set_channel here.
     */
#if !ATH_RESET_SERIAL
    /* Reset some MIB variables if required */
    if (reset_req->set_default_mib) {
        /*
         * NB: Only IEEE80211_RESET_TYPE_DOT11_INTF can reset MIB variables
         */
        KASSERT(reset_req->type == IEEE80211_RESET_TYPE_DOT11_INTF, ("invalid reset request\n"));

        if (reset_req->reset_mac) {
            /* reset regdmn module */
            ieee80211_regdmn_reset(ic);
        }

        if (reset_req->reset_phy) {
            /* set the desired PHY mode to 11b */
            vap->iv_des_mode = reset_req->phy_mode;

            /* change to the default PHY mode if required */
            /* set wireless mode */
            ieee80211_setmode(ic, vap->iv_des_mode, vap->iv_opmode);

            /* set default channel */
            ASSERT(vap->iv_des_chan[vap->iv_des_mode] != IEEE80211_CHAN_ANYC);
            ieee80211_set_channel(ic, vap->iv_des_chan[vap->iv_des_mode]);
            vap->iv_bsschan = ic->ic_curchan;
        }
    }
#endif

    return 0;
}

struct ieee80211_vap_iter_reset_arg {
    ieee80211_reset_request *reset_req;
    int  err;
};

static INLINE void ieee80211_vap_iter_reset(void *arg, wlan_if_t vap, bool is_last_vap)
{
    struct ieee80211_vap_iter_reset_arg *params= (struct ieee80211_vap_iter_reset_arg *) arg;
    /*
     * In case iv_bss was not stopped.
     */
    wlan_mlme_stop_bss(vap,
                       WLAN_MLME_STOP_BSS_F_FORCE_STOP_RESET |
                       WLAN_MLME_STOP_BSS_F_WAIT_RX_DONE);

    params->err = ieee80211_vap_reset(vap, params->reset_req);
}

int
wlan_reset(wlan_if_t vaphandle, ieee80211_reset_request *reset_req)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    int err = 0;

    /* NB: must set H/W MAC address before chip reset */
    if (reset_req->reset_mac && IEEE80211_ADDR_IS_VALID(reset_req->macaddr) &&
        !IEEE80211_ADDR_EQ(reset_req->macaddr, ic->ic_myaddr)) {

        IEEE80211_ADDR_COPY(ic->ic_myaddr, reset_req->macaddr);
        ic->ic_set_macaddr(ic, reset_req->macaddr);
        IEEE80211_ADDR_COPY(vap->iv_myaddr, ic->ic_myaddr);
        /*
         * TBD: if OS tries to set mac addr when multiple VAP co-exist,
         * we need to notify other VAPs and the corresponding ports
         * so that the port owner can change source address!!
         */
    }

    /* reset UMAC software states */
    if (reset_req->type == IEEE80211_RESET_TYPE_DOT11_INTF) {
        /*
         * In case iv_bss was not stopped.
         */
        wlan_mlme_stop_bss(vap,
                           WLAN_MLME_STOP_BSS_F_FORCE_STOP_RESET |
                           WLAN_MLME_STOP_BSS_F_WAIT_RX_DONE);

        err = ieee80211_vap_reset(vap, reset_req);
    } else if (reset_req->type == IEEE80211_RESET_TYPE_DEVICE) {
        u_int32_t num_vaps;
        struct ieee80211_vap_iter_reset_arg params;
        params.err=0;
        params.reset_req = reset_req;
        ieee80211_iterate_vap_list_internal(ic,ieee80211_vap_iter_reset,((void *) &params),num_vaps);
        err = params.err;
    }

    /* TBD: Always reset the hardware? */
    err = ic->ic_reset(ic);
    if (err)
        return err;

    return err;
}

int wlan_reset_end(wlan_if_t vaphandle, ieee80211_reset_request *reset_req)
{
    struct ieee80211com *ic = vaphandle->iv_ic;
    int ret;

    ret = ic->ic_reset_end(ic, reset_req->no_flush);
#if ATH_RESET_SERIAL
    /* Reset some MIB variables if required */
    if (reset_req->set_default_mib) {
        struct ieee80211vap *vap = vaphandle;
        /*
         * NB: Only IEEE80211_RESET_TYPE_DOT11_INTF can reset MIB variables
         */
        KASSERT(reset_req->type == IEEE80211_RESET_TYPE_DOT11_INTF, ("invalid reset request\n"));

        if (reset_req->reset_mac) {
            /* reset regdmn module */
            ieee80211_regdmn_reset(ic);
        }

        if (reset_req->reset_phy) {
            /* set the desired PHY mode to 11b */
            vap->iv_des_mode = reset_req->phy_mode;

            /* change to the default PHY mode if required */
            /* set wireless mode */
            ieee80211_setmode(ic, vap->iv_des_mode, vap->iv_opmode);

            /* set default channel */
            ASSERT(vap->iv_des_chan[vap->iv_des_mode] != IEEE80211_CHAN_ANYC);
            ieee80211_set_channel(ic, vap->iv_des_chan[vap->iv_des_mode]);
            vap->iv_bsschan = ic->ic_curchan;
        }
    }
#endif

    return ret;

}

int wlan_getrssi(wlan_if_t vaphandle, wlan_rssi_info *rssi_info, u_int32_t flags)
{
    struct ieee80211vap   *vap = vaphandle;
    struct ieee80211_node *bss_node = NULL;
    int err = ENXIO;

    bss_node = ieee80211_ref_bss_node(vap);
    if (bss_node) {
        err =  wlan_node_getrssi(bss_node,rssi_info,flags);
        ieee80211_free_node(bss_node);
    }
    return err;
}

u_int16_t wlan_get_uplinkrate(wlan_if_t vaphandle, u_int8_t snr)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    u_int8_t rx_chainmask = ieee80211com_get_rx_chainmask(ic);
    struct ieee80211_bwnss_map nssmap;
    int nss, serving_ap_nss;
    wlan_phymode_e phymode;
    wlan_chwidth_e chwidth;

    if(vap->iv_cur_mode == IEEE80211_MODE_AUTO)
    {
        if(ic->ic_modecaps & ((1 << IEEE80211_MODE_11AC_VHT20) |
                              (1 << IEEE80211_MODE_11AC_VHT40PLUS) |
                              (1 << IEEE80211_MODE_11AC_VHT40MINUS) |
                              (1 << IEEE80211_MODE_11AC_VHT40) |
                              (1 << IEEE80211_MODE_11AC_VHT80) |
                              (1 << IEEE80211_MODE_11AC_VHT160) |
                              (1 << IEEE80211_MODE_11AC_VHT80_80)))
            phymode = wlan_phymode_vht;
        else if(ic->ic_modecaps & ((1 << IEEE80211_MODE_11NA_HT20) |
                                   (1 << IEEE80211_MODE_11NG_HT20) |
                                   (1 << IEEE80211_MODE_11NA_HT40PLUS) |
                                   (1 << IEEE80211_MODE_11NA_HT40MINUS) |
                                   (1 << IEEE80211_MODE_11NG_HT40PLUS) |
                                   (1 << IEEE80211_MODE_11NG_HT40MINUS) |
                                   (1 << IEEE80211_MODE_11NG_HT40) |
                                   (1 << IEEE80211_MODE_11NA_HT40)))
            phymode = wlan_phymode_ht;
        else
            phymode = wlan_phymode_basic;
    }
    else {
        phymode = convert_phymode(vap->iv_cur_mode);
    }

    chwidth = convert_chwidth(ic->ic_cwm_get_width(ic));

    if((chwidth == wlan_chwidth_160) &&
           !ieee80211_get_bw_nss_mapping(vap, &nssmap, rx_chainmask)) {
        nss = nssmap.bw_nss_160 + 1;

        if(vap->iv_bss->ni_ext_nss_support && vap->iv_bss->ni_bwnss_map)
            serving_ap_nss = IEEE80211_GET_BW_NSS_FWCONF_160(vap->iv_bss->ni_bwnss_map) + 1;
        else
            serving_ap_nss = vap->iv_bss->ni_txstreams;
    }
    else {
        nss = ieee80211_get_rxstreams(ic, vap);
        serving_ap_nss = vap->iv_bss->ni_txstreams;
    }

    return ieee80211_SNRToPhyRateTablePerformLookup(vap, snr, QDF_MIN(serving_ap_nss, nss), phymode, chwidth);
}

int wlan_send_probereq(
    wlan_if_t       vaphandle,
    const u_int8_t  *destination,
    const u_int8_t  *bssid,
    const u_int8_t  *ssid,
    const u_int32_t ssidlen,
    const void      *optie,
    const size_t    optielen)
{
    struct ieee80211vap     *vap = vaphandle;
    struct ieee80211_node   *bss_node = NULL;
    int                     err = ENXIO;

    bss_node = ieee80211_ref_bss_node(vap);
    if (bss_node) {
        err = ieee80211_send_probereq(bss_node,
                                      vaphandle->iv_myaddr,
                                      destination,
                                      bssid,
                                      ssid,
                                      ssidlen,
                                      optie,
                                      optielen);

        ieee80211_free_node(bss_node);
    }
    return err;
}

int wlan_get_txrate_info(wlan_if_t vaphandle, ieee80211_rate_info *rate_info)
{
    struct ieee80211vap     *vap = vaphandle;
    struct ieee80211_node   *bss_node = NULL;
    int err = ENXIO;

    bss_node = ieee80211_ref_bss_node(vap);
    if (bss_node) {
        err =  wlan_node_txrate_info(bss_node,rate_info);
        ieee80211_free_node(bss_node);
    }
    return err;
}

int wlan_vap_create_flags(wlan_if_t vaphandle)
{
    return vaphandle->iv_create_flags;
}


ieee80211_resmgr_vap_priv_t
ieee80211vap_get_resmgr(ieee80211_vap_t vap)
{
    return vap->iv_resmgr_priv;
}

void
ieee80211vap_set_resmgr(ieee80211_vap_t vap, ieee80211_resmgr_vap_priv_t resmgr_priv)
{
    vap->iv_resmgr_priv = resmgr_priv;
}

/**
 * @set vap beacon interval.
 * ARGS :
 *  ieee80211_vap_event_handler : vap event handler
 *  intval                      : beacon interval.
 * RETURNS:
 *  on success returns 0.
 */
int ieee80211_vap_set_beacon_interval(ieee80211_vap_t vap, u_int16_t intval)
{
  ieee80211_node_set_beacon_interval(vap->iv_bss,intval);
  return 0;
}

/**
 * @get vap beacon interval.
 * ARGS :
 *  ieee80211_vap_event_handler : vap event handler
 * RETURNS:
 *   returns beacon interval.
 */
u_int16_t ieee80211_vap_get_beacon_interval(ieee80211_vap_t vap)
{
  return ieee80211_node_get_beacon_interval(vap->iv_bss);
}


/*
 * @Set station tspec.
 * ARGS :
 *  wlan_if_t           : vap handle
 *  u_int_8             : value of tspec state
 * RETURNS:             : void.
 */
void wlan_set_tspecActive(wlan_if_t vaphandle, u_int8_t val)
{
    struct ieee80211com *ic = vaphandle->iv_ic;
    ieee80211_set_tspecActive(ic, val);
}

/*
 * @Indicates whether station tspec is negotiated or not.
 * ARGS :
 *  wlan_if_t           : vap handle
 * RETURNS:             : value of tspec state.
 */
int wlan_is_tspecActive(wlan_if_t vaphandle)
{
    struct ieee80211com *ic = vaphandle->iv_ic;
    return ieee80211_is_tspecActive(ic);
}

u_int32_t wlan_get_tsf32(wlan_if_t vaphandle)
{
    struct ieee80211com *ic = vaphandle->iv_ic;
    return ieee80211_get_tsf32(ic);
}

int wlan_is_proxysta(wlan_if_t vaphandle)
{
     struct ieee80211vap     *vap = vaphandle;
     return vap->iv_proxySTA;
}

int wlan_set_proxysta(wlan_if_t vaphandle, int enable)
{
    struct ieee80211vap     *vap = vaphandle;
    return (vap->iv_set_proxysta(vap, enable));
}

int wlan_vap_get_tsf_offset(wlan_if_t vaphandle, u_int64_t *tsf_offset)
{
    *tsf_offset = vaphandle->iv_tsf_offset.offset;
    return EOK;
}

void wlan_deauth_all_stas(wlan_if_t vaphandle)
{
    struct ieee80211vap             *vap = vaphandle;
    struct ieee80211_mlme_priv      *mlme_priv;
    extern void sta_deauth (void *arg, struct ieee80211_node *ni);
	if ( vap == NULL ) {
		return;
	}
	mlme_priv = vap->iv_mlme_priv;

    switch(vap->iv_opmode) {
    case IEEE80211_M_HOSTAP:
            wlan_iterate_station_list(vap, sta_deauth, NULL);
        break;
    case IEEE80211_M_ANY:
    case IEEE80211_OPMODE_MAX:
    case IEEE80211_M_P2P_DEVICE:
    case IEEE80211_M_P2P_CLIENT:
    case IEEE80211_M_P2P_GO:
    case IEEE80211_M_WDS:
    case IEEE80211_M_MONITOR:
    case IEEE80211_M_AHDEMO:
    case IEEE80211_M_IBSS:
    case IEEE80211_M_STA:
    default:
       break;
    }
return;
}



#if ATH_WOW_OFFLOAD
int wlan_update_protocol_offload(wlan_if_t vaphandle)
{
    struct ieee80211_node *iv_bss = vaphandle->iv_bss;
    struct ieee80211_key *k = &iv_bss->ni_ucastkey;
    u_int32_t tid_num;

    if (iv_bss->ni_flags & IEEE80211_NODE_QOS) {
        /* Use TID 0 by default */
        tid_num = 0;
    }
    else {
        tid_num = IEEE80211_NON_QOS_SEQ;
    }

    vaphandle->iv_vap_wow_offload_info_get(vaphandle->iv_ic, &k->wk_keytsc, WOW_OFFLOAD_KEY_TSC);
    vaphandle->iv_vap_wow_offload_info_get(vaphandle->iv_ic, &iv_bss->ni_txseqs[tid_num], WOW_OFFLOAD_TX_SEQNUM);
    /* Update seq num in ATH layer as well. Not sure why, but seqnum
     * from UMAC layer are over-written with ATH layer seq num for HT
     * stations. */
    vaphandle->iv_vap_wow_offload_txseqnum_update(vaphandle->iv_ic, iv_bss, tid_num, iv_bss->ni_txseqs[tid_num]);
    return 0;
}

int wlan_vap_prep_wow_offload_info(wlan_if_t vaphandle)
{
    struct ieee80211_node *iv_bss = vaphandle->iv_bss;
    struct ieee80211_key *k = &iv_bss->ni_ucastkey;
    struct wow_offload_misc_info wo_info;
    u_int32_t tid_num;

    wo_info.flags = 0;
    OS_MEMCPY(wo_info.myaddr, vaphandle->iv_myaddr, IEEE80211_ADDR_LEN);
    OS_MEMCPY(wo_info.bssid, iv_bss->ni_macaddr, IEEE80211_ADDR_LEN);
    if (iv_bss->ni_flags & IEEE80211_NODE_QOS) {
        /* Use TID 0 by default */
        tid_num = 0;
        wo_info.flags |= WOW_NODE_QOS;
    }
    else {
        tid_num = IEEE80211_NON_QOS_SEQ;
    }
    wo_info.tx_seqnum = iv_bss->ni_txseqs[tid_num];
    wo_info.ucast_keyix = k->wk_keyix;
    if (k->wk_cipher->ic_cipher == IEEE80211_CIPHER_AES_CCM) {
        wo_info.cipher = WOW_CIPHER_AES;
    }
    else if (k->wk_cipher->ic_cipher == IEEE80211_CIPHER_TKIP) {
        wo_info.cipher = WOW_CIPHER_TKIP;
    }
    else if (k->wk_cipher->ic_cipher == IEEE80211_CIPHER_WEP) {
        wo_info.cipher = WOW_CIPHER_WEP;
    }
    else {
        wo_info.cipher = WOW_CIPHER_NONE;
    }
    wo_info.keytsc = k->wk_keytsc;

    vaphandle->iv_vap_wow_offload_rekey_misc_info_set(vaphandle->iv_ic, &wo_info);

    return EOK;
}
#endif /* ATH_WOW_OFFLOAD */

int ieee80211_vendorie_vdetach(wlan_if_t vap)
{
    if(vap && vap->vie_handle != NULL) {
        wlan_mlme_remove_ie_list(vap->vie_handle);
        vap->vie_handle = NULL;
    }
    return 0;
}

struct ieee80211_iter_new_opmode_arg {
    struct ieee80211vap *vap;
    u_int8_t num_sta_vaps_active;
    u_int8_t num_ibss_vaps_active;
    u_int8_t num_ap_vaps_active;
    u_int8_t num_ap_vaps_dfswait;
    u_int8_t num_ap_sleep_vaps_active; /* ap vaps that can sleep (P2P GO) */
    u_int8_t num_sta_nobeacon_vaps_active; /* sta vap for repeater application */
    u_int8_t num_btamp_vaps_active;
    bool     vap_active;
};


static void ieee80211_vap_iter_new_opmode(void *arg, wlan_if_t vap)
{
    struct ieee80211_iter_new_opmode_arg *params = (struct ieee80211_iter_new_opmode_arg *) arg;
    bool vap_active = false;

        if ( vap == NULL ) {
            return;
        }

        if (vap != params->vap) {
            if (ieee80211_vap_active_is_set(vap) || ieee80211_vap_dfswait_is_set(vap)) {
                vap_active = true;
            }
        } else {
            vap_active = params->vap_active;
        }
        if (vap_active) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: vap %p tmpvap %p opmode %d\n", __func__,
                        params->vap, vap, ieee80211vap_get_opmode(vap));

            switch(ieee80211vap_get_opmode(vap)) {
            case IEEE80211_M_HOSTAP:
            case IEEE80211_M_BTAMP:
                if (ieee80211_vap_cansleep_is_set(vap)) {
                   params->num_ap_sleep_vaps_active++;
                } else {
                   if (ieee80211vap_get_opmode(vap) == IEEE80211_M_BTAMP) {
                       params->num_btamp_vaps_active++;
                   }
                }
                if(ieee80211_vap_dfswait_is_set(vap)){
                    params->num_ap_vaps_dfswait++;
                } else {
                   params->num_ap_vaps_active++;
                }
                break;
            case IEEE80211_M_IBSS:
                params->num_ibss_vaps_active++;
                break;

            case IEEE80211_M_STA:
                if (vap->iv_create_flags & IEEE80211_NO_STABEACONS) {
                    params->num_sta_nobeacon_vaps_active++;
                }
                else {
                    params->num_sta_vaps_active++;
                }
                break;

            default:
                break;

            }
        }
}

/*
 * determine the new opmode whhen one of the vaps
 * changes its state.
 */
enum ieee80211_opmode
ieee80211_new_opmode(struct ieee80211vap *vap, bool vap_active)
{
    struct ieee80211com *ic = vap->iv_ic;
    enum ieee80211_opmode opmode;
    struct ieee80211_iter_new_opmode_arg params;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: active state %d\n", __func__, vap_active);

    params.num_sta_vaps_active = params.num_ibss_vaps_active = 0;
    params.num_ap_vaps_active = params.num_ap_sleep_vaps_active = 0;
    params.num_ap_vaps_dfswait = 0;
    params.num_sta_nobeacon_vaps_active = 0;
    params.vap = vap;
    params.vap_active = vap_active;
    wlan_iterate_vap_list(ic,ieee80211_vap_iter_new_opmode,(void *) &params);
    /*
     * we cant support all 3 vap types active at the same time.
     */
    ASSERT(!(params.num_ap_vaps_active && params.num_sta_vaps_active && params.num_ibss_vaps_active));

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: ibss %d, ap %d, sta %d sta_nobeacon %d \n", __func__, params.num_ibss_vaps_active, params.num_ap_vaps_active, params.num_sta_vaps_active, params.num_sta_nobeacon_vaps_active);


    if (params.num_ibss_vaps_active) {
        opmode = IEEE80211_M_IBSS;
        return opmode;
    }
    if (params.num_ap_vaps_active) {
        opmode = IEEE80211_M_HOSTAP;
        return opmode;
    }
    if (params.num_ap_vaps_dfswait) {
        opmode = IEEE80211_M_HOSTAP;
        return opmode;
    }
    if (params.num_sta_nobeacon_vaps_active) {
        opmode = IEEE80211_M_HOSTAP;
        return opmode;
    }
    opmode = ieee80211vap_get_opmode(vap);
    if ((opmode != IEEE80211_M_MONITOR) && (params.num_sta_vaps_active ||
                                            params.num_ap_sleep_vaps_active)) {
        opmode = IEEE80211_M_STA;
    }
    return opmode;
}

enum ieee80211_cwm_width ieee80211_get_vap_max_chwidth (struct ieee80211vap *vap)
{
    enum ieee80211_phymode phymode = vap->iv_des_mode;
    enum ieee80211_cwm_width width = IEEE80211_CWM_WIDTHINVALID;

    if (phymode == IEEE80211_MODE_AUTO) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG,
            "%s: VAP(0x%p) dest Phymode is AUTO\n", __func__, vap);
        return IEEE80211_CWM_WIDTHINVALID;
    }

    switch (phymode) {
        case IEEE80211_MODE_11A:
        case IEEE80211_MODE_11B:
        case IEEE80211_MODE_11G:
        case IEEE80211_MODE_FH:
        case IEEE80211_MODE_TURBO_A:
        case IEEE80211_MODE_TURBO_G:
        case IEEE80211_MODE_11NA_HT20:
        case IEEE80211_MODE_11NG_HT20:
        case IEEE80211_MODE_11AC_VHT20:
            {
                width = IEEE80211_CWM_WIDTH20;
                break;
            }
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NA_HT40:
        case IEEE80211_MODE_11NG_HT40:
        case IEEE80211_MODE_11AC_VHT40PLUS:
        case IEEE80211_MODE_11AC_VHT40MINUS:
        case IEEE80211_MODE_11AC_VHT40:
            {
                width = IEEE80211_CWM_WIDTH40;
                break;
            }
        case IEEE80211_MODE_11AC_VHT80:
            {
                width = IEEE80211_CWM_WIDTH80;
                break;
            }
        case IEEE80211_MODE_11AC_VHT160:
            {
                width = IEEE80211_CWM_WIDTH160;
                break;
            }
        case IEEE80211_MODE_11AC_VHT80_80:
            {
                width = IEEE80211_CWM_WIDTH80_80;
                break;
            }
        default:
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG,
                "%s: Invalid phymode received: %d\n", __func__, phymode);
            break;
    }

    return width;
}

/*
 * Upon some parameter changes, vap will be restartd, then fw will reset some paramters to default.
 * This function will restore the needed parameters.
*/
void wlan_restore_vap_params(wlan_if_t vap)
{
    if (IEEE80211_M_HOSTAP == vap->iv_opmode) {
        /* If rates set, use previous rates */
        /* After vdev restart, fw will reset rates to default */
        if(vap->iv_mgt_rate){
            wlan_set_param(vap, IEEE80211_MGMT_RATE, vap->iv_mgt_rate);
        }
        if (vap->iv_disabled_legacy_rate_set) {
            wlan_set_param(vap, IEEE80211_RTSCTS_RATE, vap->iv_mgt_rate);
        }
        if(vap->iv_bcast_fixedrate){
            wlan_set_param(vap, IEEE80211_BCAST_RATE, vap->iv_bcast_fixedrate);
        }
        if(vap->iv_mcast_fixedrate){
            wlan_set_param(vap, IEEE80211_MCAST_RATE, vap->iv_mcast_fixedrate);
        }
        if(vap->iv_bcn_rate) {
            wlan_set_param(vap, IEEE80211_BEACON_RATE_FOR_VAP, vap->iv_bcn_rate);
        }
    }
}

#if DBDC_REPEATER_SUPPORT
void
wlan_update_radio_priorities(struct ieee80211com *ic)
{
    struct ieee80211com *tmp_ic = NULL;
    struct ieee80211com *primary_fast_lane_ic = NULL;
    struct ieee80211com *fast_lane_ic = NULL;
    struct ieee80211vap *tmpvap = NULL, *maxpriority_stavap_up = NULL;
    int i=0,k=2;
    int max_radio_priority = MAX_RADIO_CNT+1;

    for (i=0; i < MAX_RADIO_CNT; i++) {
        GLOBAL_IC_LOCK(ic->ic_global_list);
        tmp_ic = ic->ic_global_list->global_ic[i];
        GLOBAL_IC_UNLOCK(ic->ic_global_list);
        if (tmp_ic) {
            spin_lock(&tmp_ic->ic_lock);
            if (tmp_ic->ic_primary_radio) {
                tmp_ic->ic_radio_priority = 1;
                /*update primary radio fast lane ic*/
                primary_fast_lane_ic = tmp_ic->fast_lane_ic;
            } else {
                tmp_ic->ic_radio_priority = 0;
            }
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            if (tmp_ic->nss_funcs) {
                tmp_ic->nss_funcs->ic_osif_nss_ol_store_other_pdev_stavap(tmp_ic);
                tmp_ic->nss_funcs->ic_osif_nss_ol_enable_dbdc_process(tmp_ic, tmp_ic->ic_global_list->dbdc_process_enable);
            }
#endif

            spin_unlock(&tmp_ic->ic_lock);
        }
    }
    for (i=0; i < MAX_RADIO_CNT; i++) {
        GLOBAL_IC_LOCK(ic->ic_global_list);
        tmp_ic = ic->ic_global_list->global_ic[i];
        GLOBAL_IC_UNLOCK(ic->ic_global_list);
        if (tmp_ic && (tmp_ic->ic_radio_priority == 0)) {
            if (tmp_ic == primary_fast_lane_ic) {
                spin_lock(&tmp_ic->ic_lock);
                tmp_ic->ic_radio_priority = 1;
                spin_unlock(&tmp_ic->ic_lock);
            } else {
                spin_lock(&tmp_ic->ic_lock);
                tmp_ic->ic_radio_priority = k;
                spin_unlock(&tmp_ic->ic_lock);

                /*update same priority for fast lane ic*/
                fast_lane_ic = tmp_ic->fast_lane_ic;
                if (fast_lane_ic) {
                    spin_lock(&fast_lane_ic->ic_lock);
                    fast_lane_ic->ic_radio_priority = k;
                    spin_unlock(&fast_lane_ic->ic_lock);
                }
                k++;
            }
        }
	if (tmp_ic) {
	    qdf_print("radio mac:%s priority:%d\n",ether_sprintf(tmp_ic->ic_my_hwaddr),tmp_ic->ic_radio_priority);
	    if (max_radio_priority > tmp_ic->ic_radio_priority) {
		if (tmp_ic->ic_sta_vap && ieee80211_vap_ready_is_set(tmp_ic->ic_sta_vap)) {
		    tmpvap = tmp_ic->ic_sta_vap;
		    maxpriority_stavap_up = tmp_ic->ic_sta_vap;
		    max_radio_priority = tmp_ic->ic_radio_priority;
		}
	    }
	}
    }
    GLOBAL_IC_LOCK(ic->ic_global_list);
    if (maxpriority_stavap_up && (maxpriority_stavap_up != ic->ic_global_list->max_priority_stavap_up)) {
	ic->ic_global_list->max_priority_stavap_up = maxpriority_stavap_up;
    }
    GLOBAL_IC_UNLOCK(ic->ic_global_list);
    return;
}
#endif

static void find_ap_mode_vap(void *arg, struct ieee80211vap *vap)
{
    ieee80211_vap_t *ptr_apvap=(ieee80211_vap_t *)arg;

    if (IEEE80211_M_HOSTAP == vap->iv_opmode) {
        *ptr_apvap = vap;
    }

    return;
}

struct ieee80211vap *
wlan_get_ap_mode_vap (struct ieee80211com *ic) {

    ieee80211_vap_t vap = NULL;

    wlan_iterate_vap_list(ic, find_ap_mode_vap ,(void *)&vap );

    return vap;

}
