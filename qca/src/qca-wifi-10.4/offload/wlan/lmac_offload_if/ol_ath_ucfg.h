/*
 * Copyright (c) 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef OL_ATH_UCFG_H_
#define OL_ATH_UCFG_H_
/*
 ** "split" of config param values, since they are all combined
 ** into the same table.  This value is a "shift" value for ATH parameters
 */
#define OL_ATH_PARAM_SHIFT     0x1000
#define OL_SPECIAL_PARAM_SHIFT 0x2000
#define OL_MGMT_RETRY_LIMIT_MIN (1)
#define OL_MGMT_RETRY_LIMIT_MAX (15)

enum {
    OL_SPECIAL_PARAM_COUNTRY_ID,
    OL_SPECIAL_PARAM_ASF_AMEM_PRINT,
    OL_SPECIAL_DBGLOG_REPORT_SIZE,
    OL_SPECIAL_DBGLOG_TSTAMP_RESOLUTION,
    OL_SPECIAL_DBGLOG_REPORTING_ENABLED,
    OL_SPECIAL_DBGLOG_LOG_LEVEL,
    OL_SPECIAL_DBGLOG_VAP_ENABLE,
    OL_SPECIAL_DBGLOG_VAP_DISABLE,
    OL_SPECIAL_DBGLOG_MODULE_ENABLE,
    OL_SPECIAL_DBGLOG_MODULE_DISABLE,
    OL_SPECIAL_PARAM_DISP_TPC,
    OL_SPECIAL_PARAM_ENABLE_CH_144,
    OL_SPECIAL_PARAM_REGDOMAIN,
    OL_SPECIAL_PARAM_ENABLE_OL_STATS,
    OL_SPECIAL_PARAM_ENABLE_MAC_REQ,
    OL_SPECIAL_PARAM_ENABLE_SHPREAMBLE,
    OL_SPECIAL_PARAM_ENABLE_SHSLOT,
    OL_SPECIAL_PARAM_RADIO_MGMT_RETRY_LIMIT,
    OL_SPECIAL_PARAM_SENS_LEVEL,
    OL_SPECIAL_PARAM_TX_POWER_5G,
    OL_SPECIAL_PARAM_TX_POWER_2G,
    OL_SPECIAL_PARAM_CCA_THRESHOLD,
    OL_SPECIAL_PARAM_WLAN_PROFILE_ID_ENABLE,
    OL_SPECIAL_PARAM_WLAN_PROFILE_TRIGGER,
    OL_SPECIAL_PARAM_ENABLE_CH144_EPPR_OVRD,
    OL_SPECIAL_PARAM_ENABLE_PERPKT_TXSTATS,
};

int ol_ath_ucfg_setparam(struct ol_ath_softc_net80211 *scn, int param, int value);
int ol_ath_ucfg_getparam(struct ol_ath_softc_net80211 *scn, int param, int *val);
int ol_ath_ucfg_set_country(struct ol_ath_softc_net80211 *scn, char *cntry);
int ol_ath_ucfg_get_country(struct ol_ath_softc_net80211 *scn, char *str);
int ol_ath_ucfg_set_mac_address(struct ol_ath_softc_net80211 *scn, char *addr);
int ol_ath_ucfg_gpio_config(struct ol_ath_softc_net80211 *scn,
        int gpionum,
        int input,
        int pulltype,
        int intrmode);
int ol_ath_ucfg_gpio_output(struct ol_ath_softc_net80211 *scn, int gpionum, int set);
int ol_ath_ucfg_set_smart_antenna_param(struct ol_ath_softc_net80211 *scn, char *val);
int ol_ath_ucfg_get_smart_antenna_param(struct ol_ath_softc_net80211 *scn, char *val);
void ol_ath_ucfg_txrx_peer_stats(struct ol_ath_softc_net80211 *scn, char *addr);
int ol_ath_ucfg_create_vap(struct ol_ath_softc_net80211 *scn, struct ieee80211_clone_params *cp, char *dev_name);
int ol_ath_ucfg_utf_unified_cmd(struct ol_ath_softc_net80211 *scn, int cmd, char *userdata);
int ol_ath_ucfg_get_ath_stats(struct ol_ath_softc_net80211 *scn, struct ath_stats_container *asc);
int ol_ath_ucfg_get_vap_info(struct ol_ath_softc_net80211 *scn, struct ieee80211_profile *profile);
int ol_ath_ucfg_get_nf_dbr_dbm_info(struct ol_ath_softc_net80211 *scn);
int ol_ath_ucfg_get_packet_power_info(struct ol_ath_softc_net80211 *scn,
    u_int16_t rate_flags,
    u_int16_t nss,
    u_int16_t preamble,
    u_int16_t hw_rate);
int ol_ath_ucfg_phyerr(struct ol_ath_softc_net80211 *scn, struct ath_diag *ad);
int ol_ath_ucfg_ctl_set(struct ol_ath_softc_net80211 *scn, ath_ctl_table_t *ptr);
int ol_ath_ucfg_set_op_support_rates(struct ol_ath_softc_net80211 *scn, struct ieee80211_rateset *target_rs);
int ol_ath_ucfg_btcoex_duty_cycle(struct ol_ath_softc_net80211 *scn,
        u_int32_t period, u_int32_t duration);

int ol_ath_ucfg_get_radio_supported_rates(struct ol_ath_softc_net80211 *scn,
    enum ieee80211_phymode mode,
    struct ieee80211_rateset *target_rs);
#endif //OL_ATH_UCFG_H_
