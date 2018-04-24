/*
 * Copyright (c) 2016-2017 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * Copyright (c) 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/utsname.h>
#include <linux/if_arp.h>       /* XXX for ARPHRD_ETHER */

#include <asm/uaccess.h>

#include <osif_private.h>
#include <wlan_opts.h>

#include "qdf_mem.h"
#include "ieee80211_var.h"
#include "ol_if_athvar.h"
#include "if_athioctl.h"
#include "asf_amem.h"
#include "dbglog_host.h"
#include "ol_regdomain.h"
#include "ol_txrx_dbg.h"
#include <if_smart_ant.h>
#include <acfg_api_types.h>

//#include <adf_os_types_pvt.h>

#include "ol_ath_ucfg.h"
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_if.h>
#endif

#define ATH_XIOCTL_UNIFIED_UTF_CMD  0x1000
#define ATH_XIOCTL_UNIFIED_UTF_RSP  0x1001
#define MAX_UTF_LENGTH 2048

extern void acfg_convert_to_acfgprofile (struct ieee80211_profile *profile,
                acfg_radio_vap_info_t *acfg_profile);
extern int ol_ath_utf_cmd(ol_scn_t scn, u_int8_t *data, u_int16_t len);
extern int ol_ath_utf_rsp(ol_scn_t scn, u_int8_t *payload);
extern int wlan_get_vap_info(struct ieee80211vap *vap,
                struct ieee80211vap_profile *vap_profile,
                void *handle);
extern int ol_ath_target_start(struct ol_ath_softc_net80211 *scn);
extern int osif_ol_ll_vap_hardstart(struct sk_buff *skb, struct net_device *dev);

int ol_ath_ucfg_setparam(struct ol_ath_softc_net80211 *scn, int param, int value)
{
    struct ieee80211com *ic = &scn->sc_ic;
    bool restart_vaps = FALSE;
    int retval = 0;

    if (atomic_read(&scn->reset_in_progress)) {
        qdf_print("Reset in progress, return\n");
        return -1;
    }

    if (scn->down_complete) {
        qdf_print("Starting the target before sending the command\n");
        if (ol_ath_target_start(scn)) {
            qdf_print("failed to start the target\n");
            return -1;
        }
    }

    /*
     ** Code Begins
     ** Since the parameter passed is the value of the parameter ID, we can call directly
     */
    if ( param & OL_ATH_PARAM_SHIFT )
    {
        /*
         ** It's an ATH value.  Call the  ATH configuration interface
         */

        param -= OL_ATH_PARAM_SHIFT;
        retval = ol_ath_set_config_param(scn, (ol_ath_param_t)param,
                &value, &restart_vaps);
    }
    else if ( param & OL_SPECIAL_PARAM_SHIFT )
    {
        param -= OL_SPECIAL_PARAM_SHIFT;

        switch (param) {
            case OL_SPECIAL_PARAM_COUNTRY_ID:
                retval = wlan_set_countrycode(&scn->sc_ic, NULL, value, CLIST_NEW_COUNTRY);
                if (retval) {
                    IEEE80211_COUNTRY_ENTRY    cval;

                    qdf_print("%s: Unable to set country code \n",__func__);
                    ic->ic_get_currentCountry(ic, &cval);
                    retval = wlan_set_countrycode(&scn->sc_ic, NULL,
                                    cval.countryCode, CLIST_NEW_COUNTRY);
                }
                break;
            case OL_SPECIAL_PARAM_ASF_AMEM_PRINT:
                asf_amem_status_print();
                if ( value ) {
                    asf_amem_allocs_print(asf_amem_alloc_all, value == 1);
                }
                break;
            case OL_SPECIAL_DBGLOG_REPORT_SIZE:
                dbglog_set_report_size(scn, value);
                break;
            case OL_SPECIAL_DBGLOG_TSTAMP_RESOLUTION:
                dbglog_set_timestamp_resolution(scn, value);
                break;
            case OL_SPECIAL_DBGLOG_REPORTING_ENABLED:
                dbglog_reporting_enable(scn, value);
                break;
            case OL_SPECIAL_DBGLOG_LOG_LEVEL:
                dbglog_set_log_lvl(scn, value);
                break;
            case OL_SPECIAL_DBGLOG_VAP_ENABLE:
                dbglog_vap_log_enable(scn, value, TRUE);
                break;
            case OL_SPECIAL_DBGLOG_VAP_DISABLE:
                dbglog_vap_log_enable(scn, value, FALSE);
                break;
            case OL_SPECIAL_DBGLOG_MODULE_ENABLE:
                dbglog_module_log_enable(scn, value, TRUE);
                break;
            case OL_SPECIAL_DBGLOG_MODULE_DISABLE:
                dbglog_module_log_enable(scn, value, FALSE);
                break;
            case OL_SPECIAL_PARAM_DISP_TPC:
                wmi_unified_pdev_get_tpc_config_cmd_send(scn->wmi_handle, value);
                break;
            case OL_SPECIAL_PARAM_ENABLE_CH_144:
                ol_regdmn_set_ch144(scn->ol_regdmn_handle, value);
                retval = wlan_set_countrycode(&scn->sc_ic, NULL, scn->ol_regdmn_handle->ol_regdmn_countryCode, CLIST_NEW_COUNTRY);
                break;
            case OL_SPECIAL_PARAM_ENABLE_CH144_EPPR_OVRD:
                ol_regdmn_set_ch144_eppovrd(scn->ol_regdmn_handle, value);
                retval = wlan_set_countrycode(&scn->sc_ic, NULL, scn->ol_regdmn_handle->ol_regdmn_countryCode, CLIST_NEW_COUNTRY);
                break;
            case OL_SPECIAL_PARAM_REGDOMAIN:
                {
                    struct ieee80211_channel *chan = ieee80211_get_current_channel(&scn->sc_ic);
                    u_int16_t freq = ieee80211_chan2freq(&scn->sc_ic, chan);
                    u_int32_t flags = chan->ic_flags;
                    u_int8_t cfreq2 = chan->ic_vhtop_ch_freq_seg2;
                    u_int32_t mode = ieee80211_chan2mode(chan);

                    /*
                     * After this command, the channel list would change.
                     * must set ic_curchan properly.
                     */
                    retval = wlan_set_regdomain(&scn->sc_ic, value);

                    chan = ieee80211_find_channel(&scn->sc_ic, freq, cfreq2, flags); /* cfreq2 arguement will be ignored for non VHT80+80 mode */
                    if (chan == NULL) {
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Current channel not supported in new RD. Configuring to a random channel\n");
                        chan = ieee80211_find_dot11_channel(&scn->sc_ic, 0, 0, mode);
                        if (chan == NULL) {
                            chan = ieee80211_find_dot11_channel(&scn->sc_ic, 0, 0, 0);
                            if(chan == NULL)
                                return -1;
                        }
                    }
                    scn->sc_ic.ic_curchan = chan;
                    scn->sc_ic.ic_set_channel(&scn->sc_ic);
                }
                break;
            case OL_SPECIAL_PARAM_ENABLE_OL_STATS:
                if (scn->sc_ic.ic_ath_enable_ap_stats) {
                    retval = scn->sc_ic.ic_ath_enable_ap_stats(&scn->sc_ic, value);
                }
                break;
            case OL_SPECIAL_PARAM_ENABLE_MAC_REQ:
                /*
                 * The Mesh mode has a limitation in OL FW, where the VAP ID
                 * should be between 0-7. Since Static MAC request feature
                 * can send a VAP ID more than 7, we stop this by returning
                 * an error to the user
                 */
                if (scn->sc_ic.ic_mesh_vap_support) {
                    retval = -EINVAL;
                    break;
                }
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: mac req feature %d \n", __func__, value);
                scn->macreq_enabled = value;
                break;
            case OL_SPECIAL_PARAM_WLAN_PROFILE_ID_ENABLE:
                {
                    struct wlan_profile_params param;
		    qdf_mem_set(&param, sizeof(param), 0);
                    param.profile_id = value;
                    param.enable = 1;
                    return wmi_unified_wlan_profile_enable_cmd_send(
                                                scn->wmi_handle, &param);
                }
            case OL_SPECIAL_PARAM_WLAN_PROFILE_TRIGGER:
                {
                    struct wlan_profile_params param;
		    qdf_mem_set(&param, sizeof(param), 0);
                    param.enable = value;

                    return wmi_unified_wlan_profile_trigger_cmd_send(
                                               scn->wmi_handle, &param);
                }

#if ATH_DATA_TX_INFO_EN
            case OL_SPECIAL_PARAM_ENABLE_PERPKT_TXSTATS:
                if(value == 1){
                    scn->enable_perpkt_txstats = 1;
                }else{
                    scn->enable_perpkt_txstats = 0;
                }

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
                osif_nss_ol_set_perpkt_txstats(scn);
#endif
                break;
#endif
            case OL_SPECIAL_PARAM_ENABLE_SHPREAMBLE:
                if (value) {
                    scn->sc_ic.ic_caps |= IEEE80211_C_SHPREAMBLE;
                } else {
                    scn->sc_ic.ic_caps &= ~IEEE80211_C_SHPREAMBLE;
                }
                break;
            case OL_SPECIAL_PARAM_ENABLE_SHSLOT:
                if (value)
                    ieee80211_set_shortslottime(&scn->sc_ic, 1);
                else
                    ieee80211_set_shortslottime(&scn->sc_ic, 0);
                break;
            case OL_SPECIAL_PARAM_RADIO_MGMT_RETRY_LIMIT:
                /* mgmt retry limit 1-15 */
                if( value < OL_MGMT_RETRY_LIMIT_MIN || value > OL_MGMT_RETRY_LIMIT_MAX ){
                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "mgmt retry limit invalid, should be in (1-15)\n");
                    retval = -EINVAL;
                }else{
                    retval = ic->ic_set_mgmt_retry_limit(&scn->sc_ic, value);
                }
                break;
            case OL_SPECIAL_PARAM_SENS_LEVEL:
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s[%d] PARAM_SENS_LEVEL \n", __func__,__LINE__);
                retval = ol_ath_pdev_set_param(scn,
                        wmi_pdev_param_sensitivity_level, value, 0);
                break;
            case OL_SPECIAL_PARAM_TX_POWER_5G:
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s[%d] OL_SPECIAL_PARAM_TX_POWER_5G \n", __func__,__LINE__);
                retval = ol_ath_pdev_set_param(scn,
                        wmi_pdev_param_signed_txpower_5g, value, 0);
                break;
            case OL_SPECIAL_PARAM_TX_POWER_2G:
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s[%d] OL_SPECIAL_PARAM_TX_POWER_2G \n", __func__,__LINE__);
                retval = ol_ath_pdev_set_param(scn,
                        wmi_pdev_param_signed_txpower_2g, value, 0);
                break;
            case OL_SPECIAL_PARAM_CCA_THRESHOLD:
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s[%d] PARAM_CCA_THRESHOLD \n", __func__,__LINE__);
                retval = ol_ath_pdev_set_param(scn,
                        wmi_pdev_param_cca_threshold, value, 0);
                break;
            default:
                retval = -EOPNOTSUPP;
                break;
        }
    }
    else
    {
        retval = (int) ol_hal_set_config_param(scn, (ol_hal_param_t)param, &value);
    }

    if (restart_vaps == TRUE) {
        retval = osif_restart_vaps(&scn->sc_ic);
    }

    return retval;
}

int ol_ath_ucfg_getparam(struct ol_ath_softc_net80211 *scn, int param, int *val)
{
    struct ieee80211com *ic;
    int retval = 0;


    if (scn->down_complete) {
        qdf_print("Starting the target before sending the command\n");
        if (ol_ath_target_start(scn)) {
            qdf_print("failed to start the target\n");
            return -1;
        }
    }

    /*
     ** Code Begins
     ** Since the parameter passed is the value of the parameter ID, we can call directly
     */
    ic = &scn->sc_ic;

    if ( param & OL_ATH_PARAM_SHIFT )
    {
        /*
         ** It's an ATH value.  Call the  ATH configuration interface
         */

        param -= OL_ATH_PARAM_SHIFT;
        if (ol_ath_get_config_param(scn, (ol_ath_param_t)param, (void *)val))
        {
            retval = -EOPNOTSUPP;
        }
    }
    else if ( param & OL_SPECIAL_PARAM_SHIFT )
    {
        if ( param == (OL_SPECIAL_PARAM_SHIFT | OL_SPECIAL_PARAM_COUNTRY_ID) ) {
            IEEE80211_COUNTRY_ENTRY    cval;

            ic->ic_get_currentCountry(ic, &cval);
            val[0] = cval.countryCode;
        } else if ( param == (OL_SPECIAL_PARAM_SHIFT | OL_SPECIAL_PARAM_ENABLE_CH_144) ) {
            ol_regdmn_get_ch144(scn->ol_regdmn_handle, &val[0]);
        } else if ( param == (OL_SPECIAL_PARAM_SHIFT | OL_SPECIAL_PARAM_REGDOMAIN) ) {
            REGDMN_REG_DOMAIN regd_val;
            ol_regdmn_get_regdomain(scn->ol_regdmn_handle, &regd_val);
            *val = (int)regd_val;

        } else if ( param == (OL_SPECIAL_PARAM_SHIFT | OL_SPECIAL_PARAM_ENABLE_SHPREAMBLE) ) {
            val[0] = (scn->sc_ic.ic_caps & IEEE80211_C_SHPREAMBLE) != 0;
        } else if ( param == (OL_SPECIAL_PARAM_SHIFT | OL_SPECIAL_PARAM_ENABLE_SHSLOT) ) {
            val[0] = IEEE80211_IS_SHSLOT_ENABLED(&scn->sc_ic) ? 1 : 0;
        } else if ( param == (OL_SPECIAL_PARAM_SHIFT | OL_SPECIAL_PARAM_RADIO_MGMT_RETRY_LIMIT) ) {
            val[0] = ic->ic_get_mgmt_retry_limit(ic);
        } else if ( param == (OL_SPECIAL_PARAM_SHIFT | OL_SPECIAL_PARAM_ENABLE_OL_STATS) ) {
            *val = scn->scn_stats.ap_stats_tx_cal_enable;
        }
#if ATH_DATA_TX_INFO_EN
        else if ( param == (OL_SPECIAL_PARAM_SHIFT | OL_SPECIAL_PARAM_ENABLE_PERPKT_TXSTATS) ) {
            *val = scn->enable_perpkt_txstats;
        }
#endif
        else {
            retval = -EOPNOTSUPP;
        }
    }
    else
    {
        if ( ol_hal_get_config_param(scn, (ol_hal_param_t)param, (void *)val))
        {
            retval = -EOPNOTSUPP;
        }
    }

    return retval;
}

/* Validate if AID exists */
static bool ol_ath_ucfg_validate_aid(wlan_if_t vaphandle, u_int32_t value)
{
    struct ieee80211_node *node = NULL;
    struct ieee80211_node_table *nt = &vaphandle->iv_ic->ic_sta;
    u_int16_t aid;

    TAILQ_FOREACH(node, &nt->nt_node, ni_list) {
        ieee80211_ref_node(node);
        aid = IEEE80211_AID(node->ni_associd);
        ieee80211_free_node(node);
        if (aid == value ) {
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * Function to send WMI command to request for user position of a
 * peer in different MU-MIMO group
 */
int ol_ath_ucfg_get_user_postion(wlan_if_t vaphandle, u_int32_t value)
{
    int status = 0;
    struct ieee80211com *ic;
    struct ol_ath_softc_net80211 *scn;

    if (!vaphandle) {
        qdf_print("get_user_pos:vap not available\n");
        return A_ERROR;
    }

    ic = vaphandle->iv_ic;
    scn = OL_ATH_SOFTC_NET80211(ic);
    if (ol_ath_ucfg_validate_aid(vaphandle, value)){
    	status = wmi_send_get_user_position_cmd(scn->wmi_handle, value);
    } else {
         qdf_print("Invalid AID value.\n");
    }

    return status;
}

/* Function to send WMI command to FW to reset MU-MIMO tx count for a peer */
int ol_ath_ucfg_reset_peer_mumimo_tx_count(wlan_if_t vaphandle, u_int32_t value)
{
    int status = 0;
    struct ieee80211com *ic;
    struct ol_ath_softc_net80211 *scn;

    if (!vaphandle) {
        qdf_print("reset_peer_mumimo_tx_count:vap not available\n");
        return A_ERROR;
    }

    ic = vaphandle->iv_ic;
    scn = OL_ATH_SOFTC_NET80211(ic);

    if (ol_ath_ucfg_validate_aid(vaphandle, value)){
    	status = wmi_send_reset_peer_mumimo_tx_count_cmd(scn->wmi_handle, value);
    } else {
         qdf_print("Invalid AID value.\n");
    }

    return status;
}

/*
 * Function to send WMI command to FW to request for Mu-MIMO packets
 * transmitted for a peer
 */
int ol_ath_ucfg_get_peer_mumimo_tx_count(wlan_if_t vaphandle, u_int32_t value)
{
    int status = 0;
    struct ieee80211com *ic;
    struct ol_ath_softc_net80211 *scn;

    if (!vaphandle) {
        qdf_print("mumimo_tx_count:vap not available\n");
        return A_ERROR;
    }

    ic = vaphandle->iv_ic;
    scn = OL_ATH_SOFTC_NET80211(ic);
    if (ol_ath_ucfg_validate_aid(vaphandle, value)){
    	status = wmi_send_get_peer_mumimo_tx_count_cmd(scn->wmi_handle, value);
    } else {
         qdf_print("Invalid AID value.\n");
    }
    return status;
}

int ol_ath_ucfg_set_country(struct ol_ath_softc_net80211 *scn, char *cntry)
{
    int retval;

    if (ol_ath_target_start(scn)) {
        qdf_print("failed to start the target\n");
        return -1;
    }

    if (&scn->sc_ic) {
        retval=  wlan_set_countrycode(&scn->sc_ic, cntry, 0, CLIST_NEW_COUNTRY);
    } else {
        retval = -EOPNOTSUPP;
    }

    return retval;
}

int ol_ath_ucfg_get_country(struct ol_ath_softc_net80211 *scn, char *str)
{
    int retval = 0;
    struct ieee80211com *ic = &scn->sc_ic;
    IEEE80211_COUNTRY_ENTRY    cval;

    ic->ic_get_currentCountry(ic, &cval);

    /* In case of setting regdomain only, country is CTRY_DEFAULT */
    if (cval.countryCode == 0) {
        str[0] = cval.iso[0];
        str[1] = cval.iso[1];
        str[2] = cval.iso[2];
        str[3] = 0;
    } else
        retval= wlan_get_countrycode(&scn->sc_ic, str);

    return retval;
}

int ol_ath_ucfg_set_mac_address(struct ol_ath_softc_net80211 *scn, char *addr)
{
    struct net_device *dev = scn->sc_osdev->netdev;
    struct ieee80211com *ic = &scn->sc_ic;
    struct sockaddr sa;
    int retval;

    if (ol_ath_target_start(scn)) {
        qdf_print("failed to start the target\n");
        return -1;
    }

    if ( !TAILQ_EMPTY(&ic->ic_vaps) ) {
        retval = -EBUSY; //We do not set the MAC address if there are VAPs present
    } else {
        IEEE80211_ADDR_COPY(&sa.sa_data, addr);
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
        retval = dev->netdev_ops->ndo_set_mac_address(dev, &sa);
#else
        retval = dev->set_mac_address(dev, &sa);
#endif
    }

    return retval;
}

int ol_ath_ucfg_gpio_config(struct ol_ath_softc_net80211 *scn,
        int gpionum,
        int input,
        int pulltype,
        int intrmode)
{
    if (ol_ath_target_start(scn)) {
        qdf_print("failed to start the target\n");
        return -1;
    }

    return ol_gpio_config(scn, gpionum, input, pulltype, intrmode);
}

int ol_ath_ucfg_gpio_output(struct ol_ath_softc_net80211 *scn, int gpionum, int set)
{
    if (ol_ath_target_start(scn)) {
        qdf_print("failed to start the target\n");
        return -1;
    }

    return ol_ath_gpio_output(scn, gpionum, set);
}
#define BTCOEX_MAX_PERIOD   2000   /* 2000 msec */
int ol_ath_ucfg_btcoex_duty_cycle(struct ol_ath_softc_net80211 *scn,
        u_int32_t bt_period, u_int32_t bt_duration)
{
    int period,duration;
    if (ol_ath_target_start(scn)) {
        qdf_print("failed to start the target\n");
        return -1;
    }
    period = (int)bt_period;
    duration = (int)bt_duration;
    if (scn->btcoex_support && scn->btcoex_duty_cycle) {
        if ( period  > BTCOEX_MAX_PERIOD ) {
            qdf_print("Invalid period : %d \n",period);
            qdf_print("Allowed max period is 2000ms \n");
            return -EINVAL;
        }
        if ( period < 0 || duration < 0) {
            qdf_print("Invalid values. Both period and must be +ve values \n");
            return -EINVAL;
        }
        if( period < duration ) { /* period must be >= duration */
            qdf_print("Invalid values. period must be >= duration. period:%d duration:%d \n",
                    period, duration);
            return -EINVAL;
        }

        if (period == 0 && duration == 0) {
            qdf_print("Both period and duration set to 0. Disabling this feature. \n");
        }
        if (ol_ath_btcoex_duty_cycle(scn, bt_period, bt_duration) == EOK ) {
            scn->btcoex_duration = duration;
            scn->btcoex_period = period;
        } else {
            qdf_print("BTCOEX Duty Cycle configuration is not success. \n");
        }
    } else {
        qdf_print("btcoex_duty_cycle service not started. btcoex_support:%d btcoex_duty_cycle:%d \n",
                scn->btcoex_support, scn->btcoex_duty_cycle);
        return -EPERM;
    }
    return 0;
}

#if UNIFIED_SMARTANTENNA
int ol_ath_ucfg_set_smart_antenna_param(struct ol_ath_softc_net80211 *scn, char *val)
{
    struct ieee80211com *ic = &scn->sc_ic;
    if (ol_ath_target_start(scn)) {
        qdf_print("failed to start the target\n");
        return -1;
    }

    return ieee80211_smart_ant_set_param(ic, val);
}

int ol_ath_ucfg_get_smart_antenna_param(struct ol_ath_softc_net80211 *scn, char *val)
{
    struct ieee80211com *ic = &scn->sc_ic;

    return ieee80211_smart_ant_get_param(ic, val);
}
#endif

#if PEER_FLOW_CONTROL
extern void ol_txrx_per_peer_stats(struct ol_txrx_pdev_t *pdev, char *addr);
void ol_ath_ucfg_txrx_peer_stats(struct ol_ath_softc_net80211 *scn, char *addr)
{
    ol_txrx_per_peer_stats(scn->pdev_txrx_handle, addr);
}
#endif

int ol_ath_ucfg_create_vap(struct ol_ath_softc_net80211 *scn, struct ieee80211_clone_params *cp, char *dev_name)
{
    struct net_device *dev = scn->sc_osdev->netdev;
    struct ifreq ifr;
    int status;

    if (scn->sc_in_delete) {
        return -ENODEV;
    }
    if (ol_ath_target_start(scn)) {
        qdf_print("failed to start the target\n");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_data = (void *) cp;

    /*
     * If the driver is compiled with FAST_PATH option
     * and the driver mode is offload, we override the
     * fast path entry point for Tx
     */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if(scn->nss_wifiol_ctx) {
        scn->sc_osdev->vap_hardstart = osif_nss_ol_vap_hardstart;
    } else
#endif
    {
        scn->sc_osdev->vap_hardstart = osif_ol_ll_vap_hardstart;
    }
#endif
    status = osif_ioctl_create_vap(dev, &ifr, cp, scn->sc_osdev);

    /* return final device name */
    strlcpy(dev_name, ifr.ifr_name, IFNAMSIZ);

    return status;
}

int ol_ath_ucfg_utf_unified_cmd(struct ol_ath_softc_net80211 *scn, int cmd, char *userdata)
{
    int error = 0;
    unsigned int length = 0;
    unsigned char *buffer;

    if (ol_ath_target_start(scn)) {
        qdf_print("failed to start the target\n");
        return -1;
    }

    switch (cmd)
    {
        case ATH_XIOCTL_UNIFIED_UTF_CMD:
        {
            get_user(length, (unsigned int *)userdata);

            if ( length > MAX_UTF_LENGTH )
                return -EFAULT;

            buffer = (unsigned char*)OS_MALLOC((void*)scn->sc_osdev, length, GFP_KERNEL);
            if (buffer != NULL)
            {
                OS_MEMZERO(buffer, length);

                if (copy_from_user(buffer, &userdata[sizeof(length)], length))
                {
                    error = -EFAULT;
                }
                else
                {
                    error = ol_ath_utf_cmd(scn,(u_int8_t*)buffer,(u_int16_t)length);
                }

                OS_FREE(buffer);
             }
             else
                error = -ENOMEM;
         }
         break;
         case ATH_XIOCTL_UNIFIED_UTF_RSP:
         {
             length = MAX_UTF_LENGTH + sizeof(u_int32_t);
             buffer = (unsigned char*)OS_MALLOC((void*)scn->sc_osdev, length, GFP_KERNEL);

             if (buffer != NULL) {
                 error = ol_ath_utf_rsp(scn,(u_int8_t*)buffer);
            if ( !error )
            {
                     error = copy_to_user((userdata - sizeof(cmd)), buffer, length);
            }
            else
                 {
                error = -EAGAIN;
         }
                 OS_FREE(buffer);
             }
         }
         break;
    }

    return error;
}

int ol_ath_ucfg_get_ath_stats(struct ol_ath_softc_net80211 *scn, struct ath_stats_container *asc)
{
    struct net_device *dev = scn->sc_osdev->netdev;
    struct ol_stats *stats;
    int error=0;

    if(((dev->flags & IFF_UP) == 0)){
        return -ENXIO;
    }
    stats = OS_MALLOC(&scn->sc_osdev,
            sizeof(struct ol_stats), GFP_KERNEL);
    if (stats == NULL)
        return -ENOMEM;

    if(asc->size == 0 || asc->address == NULL) {
        error = -EFAULT;
    }else {
        stats->txrx_stats_level =
            ol_txrx_stats_publish(scn->pdev_txrx_handle,
                    &stats->txrx_stats);
        ol_get_wlan_dbg_stats(scn,&stats->stats);
        ol_get_radio_stats(scn,&stats->interface_stats);

        if(asc->flag_ext & EXT_TXRX_FW_STATS) {  /* fw stats */
            struct ieee80211vap *vap = NULL;
            struct ol_txrx_stats_req req = {0};

            vap = ol_ath_vap_get(scn, 0);
            if (vap == NULL) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s, vap not found!\n", __func__);
                return -ENXIO;
            }

            req.wait.blocking = 1;
            req.stats_type_upload_mask = 1 << (TXRX_FW_STATS_TID_STATE - 2);
            req.copy.byte_limit = sizeof(struct wlan_dbg_tidq_stats);
            req.copy.buf = OS_MALLOC(&scn->sc_osdev,
                    sizeof(struct wlan_dbg_tidq_stats), GFP_KERNEL);
            if(req.copy.buf == NULL) {
                QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s, no memory available!\n", __func__);
                return -ENOMEM;
            }

            if (ol_txrx_fw_stats_get(vap->iv_txrx_handle, &req, PER_RADIO_FW_STATS_REQUEST, 0) != 0) {
                OS_FREE(req.copy.buf);
                return -EIO;
            }

            OS_MEMCPY(&stats->tidq_stats, req.copy.buf,
                    sizeof(struct wlan_dbg_tidq_stats));
            OS_FREE(req.copy.buf);
        } /* fw stats */

        if (_copy_to_user(asc->address, stats,
                    sizeof(struct ol_stats)))
            error = -EFAULT;
        else
            error = 0;
    }
    asc->offload_if = 1;
    asc->size = sizeof(struct ol_stats);
    OS_FREE(stats);

    return error;
}

int ol_ath_ucfg_get_vap_info(struct ol_ath_softc_net80211 *scn,
                                struct ieee80211_profile *profile)
{
    struct net_device *dev = scn->sc_osdev->netdev;
    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211vap *vap = NULL;
    struct ieee80211vap_profile *vap_profile;
    wlan_chan_t chan;

    strlcpy(profile->radio_name, dev->name, IFNAMSIZ);
    wlan_get_device_mac_addr(ic, profile->radio_mac);
    profile->cc = (u_int16_t)wlan_get_device_param(ic,
                                IEEE80211_DEVICE_COUNTRYCODE);
    chan = wlan_get_dev_current_channel(ic);
    if (chan != NULL) {
        profile->channel = chan->ic_ieee;
        profile->freq = chan->ic_freq;
    }
    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        vap_profile = &profile->vap_profile[profile->num_vaps];
        wlan_get_vap_info(vap, vap_profile, (void *)scn->sc_osdev);
        profile->num_vaps++;
    }
    return 0;
}

int ol_ath_ucfg_get_nf_dbr_dbm_info(struct ol_ath_softc_net80211 *scn)
{
    if(wmi_unified_nf_dbr_dbm_info_get_cmd_send(scn->wmi_handle)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:Unable to send request to get NF dbr dbm info\n", __func__);
        return -1;
    }
    return 0;
}

int ol_ath_ucfg_get_packet_power_info(struct ol_ath_softc_net80211 *scn,
        u_int16_t rate_flags,
        u_int16_t nss,
        u_int16_t preamble,
        u_int16_t hw_rate)
{
    if(ol_ath_packet_power_info_get(scn, rate_flags, nss, preamble, hw_rate)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:Unable to send request to get packet power info\n", __func__);
        return -1;
    }
    return 0;
}

#if defined(ATH_SUPPORT_DFS) || defined(ATH_SUPPORT_SPECTRAL)
int ol_ath_ucfg_phyerr(struct ol_ath_softc_net80211 *scn, struct ath_diag *ad)
{
    struct ieee80211com *ic = &scn->sc_ic;
    void *indata=NULL;
    void *outdata=NULL;
    int error = -EINVAL;
    u_int32_t insize = ad->ad_in_size;
    u_int32_t outsize = ad->ad_out_size;
    u_int id= ad->ad_id & ATH_DIAG_ID;

    if (ad->ad_id & ATH_DIAG_IN) {
        /*
         * Copy in data.
         */
        indata = OS_MALLOC(scn->sc_osdev,insize, GFP_KERNEL);
        if (indata == NULL) {
            error = -ENOMEM;
            goto bad;
        }
        if (__xcopy_from_user(indata, ad->ad_in_data, insize)) {
            error = -EFAULT;
            goto bad;
        }
        id = id & ~ATH_DIAG_IN;
    }
    if (ad->ad_id & ATH_DIAG_DYN) {
        /*
         * Allocate a buffer for the results (otherwise the HAL
         * returns a pointer to a buffer where we can read the
         * results).  Note that we depend on the HAL leaving this
         * pointer for us to use below in reclaiming the buffer;
         * may want to be more defensive.
         */
        outdata = OS_MALLOC(scn->sc_osdev, outsize, GFP_KERNEL);
        if (outdata == NULL) {
            error = -ENOMEM;
            goto bad;
        }
        id = id & ~ATH_DIAG_DYN;
    }

#if ATH_SUPPORT_DFS
    error = ic->ic_dfs_control(ic, id, indata, insize, outdata, &outsize);
#endif

#if ATH_SUPPORT_SPECTRAL
    if (error ==  -EINVAL ) {
        error = ic->ic_spectral_control(ic, id, indata, insize, outdata, &outsize);
    }
#endif

    if (outsize < ad->ad_out_size)
        ad->ad_out_size = outsize;

    if (outdata &&
            _copy_to_user(ad->ad_out_data, outdata, ad->ad_out_size))
        error = -EFAULT;
bad:
    if ((ad->ad_id & ATH_DIAG_IN) && indata != NULL)
        OS_FREE(indata);
    if ((ad->ad_id & ATH_DIAG_DYN) && outdata != NULL)
        OS_FREE(outdata);

    return error;
}
#endif

int ol_ath_ucfg_ctl_set(struct ol_ath_softc_net80211 *scn, ath_ctl_table_t *ptr)
{
	struct ctl_table_params param;
	uint8_t retval = 0;
	struct ieee80211com *ic = &scn->sc_ic;

	qdf_mem_set(&param, sizeof(param), 0);
	qdf_print("%s[%d] Mode %d CTL table length %d\n", __func__,__LINE__, ptr->band, ptr->len);
	if (ol_ath_target_start(scn)) {
        	qdf_print("failed to start the target\n");
		return -1;
	}

	param.ctl_band = ptr->band;
	param.ctl_array = &ptr->ctl_tbl[0];
	param.ctl_cmd_len = ptr->len + sizeof(uint32_t);
	param.target_type = scn->target_type;
	if (IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan)) {
		param.is_2g = TRUE;
	} else {
		param.is_2g = FALSE;
	}

	retval = wmi_unified_set_ctl_table_cmd_send(scn->wmi_handle, &param);

	return retval;
}

/*
 * @brief set basic & supported rates in beacon,
 * and use lowest basic rate as mgmt mgmt/bcast/mcast rates by default.
 * target_rates: an array of supported rates with bit7 set for basic rates.
 */
static int
ol_ath_ucfg_set_vap_op_support_rates(wlan_if_t vap, struct ieee80211_rateset *target_rs)
{
    struct ieee80211_node *bss_ni = vap->iv_bss;
    enum ieee80211_phymode mode = wlan_get_desired_phymode(vap);
    struct ieee80211_rateset *bss_rs = &(bss_ni->ni_rates);
    struct ieee80211_rateset *op_rs = &(vap->iv_op_rates[mode]);
    struct ieee80211_rateset *ic_supported_rs = &(vap->iv_ic->ic_sup_rates[mode]);
    uint8_t num_of_rates, num_of_basic_rates, i, j, rate_found=0;
    uint8_t basic_rates[IEEE80211_RATE_MAXSIZE];
    int32_t retv=0, min_rate=0;

    if (vap->iv_disabled_legacy_rate_set) {
        qdf_print("%s: need to unset iv_disabled_legacy_rate_set!\n",__FUNCTION__);
        return -EINVAL;
    }

    num_of_rates = target_rs->rs_nrates;
    if(num_of_rates > ACFG_MAX_RATE_SIZE){
        num_of_rates = ACFG_MAX_RATE_SIZE;
    }

    /* Check if the new rates are supported by the IC */
    for (i=0; i < num_of_rates; i++) {
        rate_found = 0;
        for (j=0; j < (ic_supported_rs->rs_nrates); j++) {
            if((target_rs->rs_rates[i]&IEEE80211_RATE_VAL) ==
                    (ic_supported_rs->rs_rates[j]&IEEE80211_RATE_VAL)){
                rate_found  = 1;
                break;
            }
        }
        if(!rate_found){
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Error: rate %d not supported in phymode %s !\n",
                    (target_rs->rs_rates[i]&IEEE80211_RATE_VAL)/2,ieee80211_phymode_name[mode]);
            return EINVAL;
        }
    }

    /* Update BSS rates and VAP supported rates with the new rates */
    for (i=0; i < num_of_rates; i++) {
        bss_rs->rs_rates[i] = target_rs->rs_rates[i];
        op_rs->rs_rates[i] = target_rs->rs_rates[i];
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "rate %d (%d kbps) added\n",
                target_rs->rs_rates[i], (target_rs->rs_rates[i]&IEEE80211_RATE_VAL)*1000/2);
    }
    bss_rs->rs_nrates = num_of_rates;
    op_rs->rs_nrates = num_of_rates;

    if (IEEE80211_VAP_IS_PUREG_ENABLED(vap)) {
        /*For pureg mode, all 11g rates are marked as Basic*/
        ieee80211_setpuregbasicrates(op_rs);
    }

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG,
            "%s Mark flag so that new rates will be used in next beacon update\n",__func__);
    vap->iv_flags_ext2 |= IEEE80211_FEXT2_BR_UPDATE;

    /* Find all basic rates */
    num_of_basic_rates = 0;
    for (i=0; i < bss_rs->rs_nrates; i++) {
        if(bss_rs->rs_rates[i] & IEEE80211_RATE_BASIC){
            basic_rates[num_of_basic_rates] = bss_rs->rs_rates[i];
            num_of_basic_rates++;
        }
    }
    if(!num_of_basic_rates){
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Error, no basic rates set. \n",__FUNCTION__);
        return EINVAL;
    }

    /* Find lowest basic rate */
    min_rate = basic_rates[0];
    for (i=0; i < num_of_basic_rates; i++) {
        if ( min_rate > basic_rates[i] ) {
            min_rate = basic_rates[i];
        }
    }

    /*
     * wlan_set_param supports actual rate in unit of kbps
     * min: 1000 kbps max: 300000 kbps
     */
    min_rate = ((min_rate&IEEE80211_RATE_VAL)*1000)/2;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG,
            "%s Set default mgmt/bcast/mcast rates to %d Kbps\n",__func__,min_rate);

    /* Use lowest basic rate as mgmt mgmt/bcast/mcast rates by default */
    retv = wlan_set_param(vap, IEEE80211_MGMT_RATE, min_rate);
    if(retv){
        return retv;
    }

    retv = wlan_set_param(vap, IEEE80211_BCAST_RATE, min_rate);
    if(retv){
        return retv;
    }

    retv = wlan_set_param(vap, IEEE80211_MCAST_RATE, min_rate);
    if(retv){
        return retv;
    }

    /* Use the lowest basic rate as RTS and CTS rates by default */
    retv = wlan_set_param(vap, IEEE80211_RTSCTS_RATE, min_rate);

    return retv;
}

int ol_ath_ucfg_set_op_support_rates(struct ol_ath_softc_net80211 *scn, struct ieee80211_rateset *target_rs)
{
    struct ieee80211com *ic = &scn->sc_ic;
    wlan_if_t tmpvap=NULL;
    int32_t retv = -EINVAL;

    TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
        if(!tmpvap){
            return retv;
        }
        retv = ol_ath_ucfg_set_vap_op_support_rates(tmpvap, target_rs);
        if(retv){
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Set VAP basic rates failed, retv=%d\n",__FUNCTION__,retv);
            return retv;
        }
    }

    return 0;
}

int ol_ath_ucfg_get_radio_supported_rates(struct ol_ath_softc_net80211 *scn,
        enum ieee80211_phymode mode,
        struct ieee80211_rateset *target_rs)
{
    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211_rateset *rs = NULL;
    uint8_t j=0;

    if (!IEEE80211_SUPPORT_PHY_MODE(ic, mode)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: The radio doesn't support this phymode: %d\n",__FUNCTION__,mode);
        return -EINVAL;
    }

    rs = &ic->ic_sup_rates[mode];
    if(!rs){
        return -EINVAL;
    }

    for (j=0; j<(rs->rs_nrates); j++) {
        target_rs->rs_rates[j] = rs->rs_rates[j];
    }
    target_rs->rs_nrates = rs->rs_nrates;

    return 0;
}
