/*
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 */

/*
 Band steering module
*/

#include "band_steering_priv.h"
#include <ieee80211_ioctl.h>  /* for ieee80211req_athdbg */
#include <ieee80211_var.h>
#include <ieee80211_acl.h>
#include <ieee80211_rateset.h>

#if ATH_BAND_STEERING

#if !UMAC_SUPPORT_ACL
#error "ACL support must be enabled when band steering is enabled"
#endif /* !UMAC_SUPPORT_ACL */

/* Number of seconds to wait for instaneous RSSI report */
#define INST_RSSI_TIMEOUT 5

/* An invalid RSSI threshold that RSSI measurement can never go above.
 * It is same as U8_MAX, which is not supported in current kernel header. */
#define BSTEER_INVALID_RSSI_HIGH_THRESHOLD ((u8)~0U)

/* forward declaration */
static OS_TIMER_FUNC(wlan_bsteering_chan_util_timeout_handler);
static void ieee80211_bsteering_reset_chan_utilization(ieee80211_bsteering_t bsteering);
static void ieee80211_bsteering_send_rssi_measurement_event(struct ieee80211vap *vap,
                                                            const u_int8_t *mac_addr,
                                                            u_int8_t rssi, bool is_debug);
static OS_TIMER_FUNC(wlan_bsteering_inst_rssi_timeout_handler);
static void ieee80211_bsteering_send_rrm_report_event(
    struct ieee80211vap *vap, const struct bs_rrm_report_ind *report);
static int ieee80211_bsteering_get_node_max_MCS(const struct ieee80211_node *ni);
static int ieee80211_bsteering_get_max_MCS(enum ieee80211_phymode phymode,
                                           u_int16_t rx_vht_mcs_map, u_int16_t tx_vht_mcs_map,
                                           const struct ieee80211_rateset *htrates,
                                           const struct ieee80211_rateset *basic_rates);
static void ieee80211_bsteering_probe_resp_find_and_add_allow_entry(struct ieee80211vap *vap,
                                                                    const u_int8_t *mac_addr);
static void ieee80211_bsteering_probe_resp_allow_entry_remove(struct ieee80211vap *vap,
                                                              const u_int8_t *mac_addr);

/**
 * @brief Verify that the band steering handle is valid within the
 *        struct ieee80211com provided.
 *
 * @param [in] ic  the handle to the radio where the band steering state
 *                 resides
 *
 * @return true if handle is valid; otherwise false
 */

static INLINE bool ieee80211_bsteering_is_valid(const struct ieee80211com *ic)
{
    return ic && ic->ic_bsteering;
}

/**
 * @brief Determine whether the band steering module is enabled or not.
 *
 * @param [in] ic  the handle to the radio where the band steering state
 *                 resides
 *
 * @return non-zero if it is enabled; otherwise 0
 */

u_int8_t ieee80211_bsteering_is_enabled(const struct ieee80211com *ic)
{
    return ieee80211_bsteering_is_valid(ic) &&
           atomic_read(&ic->ic_bsteering->bs_enabled);
}

/**
 * @brief Determine whether band steering events are enabled on
 *        a VAP.
 *
 * @param [in] vap  VAP to check
 *
 * @return non-zero if it is enabled; otherwise 0
 */

u_int8_t ieee80211_bsteering_is_event_enabled(const struct ieee80211vap *vap)
{
    return atomic_read(&vap->iv_bs_enabled);
}

/**
 * @brief Determine whether the VAP handle is valid, has a valid band
 *        steering handle, is operating in a mode where band steering
 *        is relevant, and is not in the process of being deleted.
 *
 * @return true if the VAP is valid; otherwise false
 */

bool ieee80211_bsteering_is_vap_valid(const struct ieee80211vap *vap)
{
    /* Unfortunately these functions being used do not take a const pointer
       even though they do not modify the VAP. Thus, we have to cast away
       the const-ness in order to call them.*/
    struct ieee80211vap *nonconst_vap = (struct ieee80211vap *) vap;
    return vap && wlan_vap_get_opmode(nonconst_vap) == IEEE80211_M_HOSTAP &&
           !ieee80211_vap_deleted_is_set(nonconst_vap);
}

/**
 * @brief Determine whether the VAP has band steering enabled.
 *
 * Validate that the VAP has a valid band steering handle, that
 * it is operating in the right mode (AP mode), and that band steering has been
 * enabled on the VAP.
 *
 * @param [in] vap  the VAP to check
 *
 * @return true if the VAP is valid and has band steering enabled; otherwise
 *         false
 */
bool ieee80211_bsteering_is_vap_enabled(const struct ieee80211vap *vap)
{
    return (ieee80211_bsteering_is_vap_valid(vap) &&
            ieee80211_bsteering_is_event_enabled(vap));
}

/**
 * @brief Determine whether an ioctl request is valid or not, along with the
 *        associated parameters.
 *
 * @param [in] vap  the VAP on which the ioctl was made
 * @param [in] req  the parameters provided in the ioctl
 *
 * @return true if all parameters are valid; otherwise false
 */

static bool ieee80211_bsteering_is_req_valid(const struct ieee80211vap *vap,
                                                    const struct ieee80211req_athdbg *req)
{
    return ieee80211_bsteering_is_vap_valid(vap) &&
        ieee80211_bsteering_is_valid(vap->iv_ic) && NULL != req;
}

/**
 * @brief Set the band steering parameters from user space.
 *
 * This can only be done when band steering is disabled. The parameters
 * include timer values and thresholds for RSSI reporting.
 *
 * @param [in] vap  the VAP on which the set operation was done
 * @param [in] req  the parameters to be set
 *
 * @return EOK on success, EBUSY if band steering is currently enabled,
 *         or EINVAL if a parameter is invalid
 */

int wlan_bsteering_set_params(struct ieee80211vap *vap,
                              struct ieee80211req_athdbg *req)
{
    ieee80211_bsteering_t bsteering = NULL;
    int retval = -EINVAL;
    ieee80211_bsteering_lmac_param_t lmac_params;
    uint32_t conf_average_period = 0;
    /* for throughput constraints we are not supporting Sample period less than 30*/
#define MIN_SAMPLE_PERIOD_DIRECT_ATTACH 30
    /* Sanity check the values provided. If any are invalid, error out
       with EINVAL (per the default retval).*/
    if (!ieee80211_bsteering_is_req_valid(vap, req) ||
        !req->data.bsteering_param.inactivity_check_period ||
        (req->data.bsteering_param.utilization_sample_period &&
         !req->data.bsteering_param.utilization_average_num_samples) ||
        (req->data.bsteering_param.inactivity_timeout_normal <=
         req->data.bsteering_param.inactivity_check_period) ||
        (req->data.bsteering_param.inactivity_timeout_overload <=
         req->data.bsteering_param.inactivity_check_period) ||
        (req->data.bsteering_param.high_tx_rate_crossing_threshold <=
         req->data.bsteering_param.low_tx_rate_crossing_threshold)) {
        return -EINVAL;
    }

    if (req->data.bsteering_param.utilization_sample_period) {
        /*Due to Throughput Hit for direct attach hardware
          we are not permitting less than 30 sec*/
        if(!vap->iv_ic->ic_is_mode_offload(vap->iv_ic) &&
                req->data.bsteering_param.utilization_sample_period < MIN_SAMPLE_PERIOD_DIRECT_ATTACH) {
            conf_average_period = req->data.bsteering_param.utilization_sample_period * req->data.bsteering_param.utilization_average_num_samples;
            req->data.bsteering_param.utilization_sample_period = MIN_SAMPLE_PERIOD_DIRECT_ATTACH;

            if ((conf_average_period % req->data.bsteering_param.utilization_sample_period)!= 0)
            {
                QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "For direct Attach:Incompatible Sample Period and average number of samples \n");
                return -EINVAL;
            }

            req->data.bsteering_param.utilization_average_num_samples = conf_average_period /req->data.bsteering_param.utilization_sample_period;
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "For direct Attach:Changing sampling period to %d \n",MIN_SAMPLE_PERIOD_DIRECT_ATTACH);
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "For direct Attach:Changing Average number of sample to %d \n",req->data.bsteering_param.utilization_average_num_samples);
        }
    }

    bsteering = vap->iv_ic->ic_bsteering;

    do {
        spin_lock_bh(&bsteering->bs_lock);
        if (ieee80211_bsteering_is_enabled(vap->iv_ic)) {
            retval = -EBUSY;
            break;
        }

        bsteering->bs_config_params = req->data.bsteering_param;

        lmac_params.inactivity_check_period =
            bsteering->bs_config_params.inactivity_check_period;
        lmac_params.inactivity_threshold_normal =
            bsteering->bs_config_params.inactivity_timeout_normal /
            bsteering->bs_config_params.inactivity_check_period;
        lmac_params.inactivity_threshold_overload =
            bsteering->bs_config_params.inactivity_timeout_overload /
            bsteering->bs_config_params.inactivity_check_period;

        retval = EOK;
    } while (0);

    if (retval == EOK) {
        /* Note: To avoid a possible deadlock, the lower layer should never
           call a band steering function that grabs the band steering
           spinlock while holding the peer lock.*/
        retval = vap->iv_ic->ic_bs_set_params(vap->iv_ic, &lmac_params) ?
            EOK : -EINVAL;
    }
    spin_unlock_bh(&bsteering->bs_lock);
#undef MIN_SAMPLE_PERIOD_DIRECT_ATTACH
    return retval;
}

/**
 * @brief Get the band steering parameters from user space.
 *
 * The parameters include timer values and thresholds for RSSI reporting.
 *
 * @param [in] vap  the VAP on which the get operation was done
 * @param [in] req  the parameters to be retrieved
 *
 * @return EOK for success and EINVAL for error cases
 */

int wlan_bsteering_get_params(const struct ieee80211vap *vap,
                              struct ieee80211req_athdbg *req)
{
    ieee80211_bsteering_t bsteering = NULL;

    if (!ieee80211_bsteering_is_req_valid(vap, req)) {
        return -EINVAL;
    }

    bsteering = vap->iv_ic->ic_bsteering;
    spin_lock_bh(&bsteering->bs_lock);
    req->data.bsteering_param = bsteering->bs_config_params;
    spin_unlock_bh(&bsteering->bs_lock);

    return EOK;
}

/**
 * @brief Set the parameters that control whether debugging events are
 *        generated or not.
 *
 * This may be done even when band steering is enabled.
 *
 * @param [in] vap  the VAP on which the request came in
 * @param [in] req  the actual request parameters containing the new values
 *
 * @return EOK for success and EINVAL for error cases
 */

int wlan_bsteering_set_dbg_params(struct ieee80211vap *vap,
                                  const struct ieee80211req_athdbg *req)
{
    ieee80211_bsteering_t bsteering = NULL;

    if (!ieee80211_bsteering_is_req_valid(vap, req)) {
        return -EINVAL;
    }

    bsteering = vap->iv_ic->ic_bsteering;

    spin_lock_bh(&bsteering->bs_lock);

    /* These parameters can be changed while band steering is enabled,
       hence no safety check here that it is disabled.*/
    bsteering->bs_dbg_config_params = req->data.bsteering_dbg_param;

    spin_unlock_bh(&bsteering->bs_lock);
    return EOK;
}

/**
 * @brief Get the parameters that control whether debugging events are
 *        generated or not.
 *
 * @param [in] vap  the VAP on which the request came in
 * @param [out] req  the object to update with the current debugging parameters
 *
 * @return EOK for success and EINVAL for error cases
 */

int wlan_bsteering_get_dbg_params(const struct ieee80211vap *vap,
                                  struct ieee80211req_athdbg *req)
{
    ieee80211_bsteering_t bsteering = NULL;

    if (!ieee80211_bsteering_is_req_valid(vap, req)) {
        return -EINVAL;
    }

    bsteering = vap->iv_ic->ic_bsteering;

    spin_lock_bh(&bsteering->bs_lock);
    req->data.bsteering_dbg_param = bsteering->bs_dbg_config_params;
    spin_unlock_bh(&bsteering->bs_lock);

    return EOK;
}

/**
 * @brief Toggle a VAP's overloaded status.
 *
 * This primarily determines whether the normal or overload inactivity timer
 * is used.
 *
 * @param [inout] vap  the VAP whose overload status changes
 * @param [in] req  request from user space containing the flag indicating overload or not
 *
 * @return EOK if overload status is set, otherwise return EINVAL
 */

int wlan_bsteering_set_overload(struct ieee80211vap *vap,
                                const struct ieee80211req_athdbg *req)
{
    ieee80211_bsteering_t bsteering = NULL;

    if (!ieee80211_bsteering_is_req_valid(vap, req)) {
        return -EINVAL;
    }

    bsteering = vap->iv_ic->ic_bsteering;
    spin_lock_bh(&bsteering->bs_lock);
    bsteering->bs_vap_overload = req->data.bsteering_overload ? true : false;

    /* Note: To avoid a possible deadlock, the lower layer should never
       call a band steering function that grabs the band steering
       spinlock while holding the peer lock. */
    vap->iv_ic->ic_bs_set_overload(vap->iv_ic, bsteering->bs_vap_overload);

    spin_unlock_bh(&bsteering->bs_lock);

    return EOK;
}

/**
 * @brief Retrieve a VAP's overloaded status.
 *
 * This can be used as an indication of which inactivity timer is in use
 * (normal or overload).
 *
 * @param [in] vap  the VAP whose overload status to retrieve
 * @param [out] req  the object to update with the current overload status
 *
 * @return EOK if overload status is retrieved successfully, otherwise return EINVAL
 */

int wlan_bsteering_get_overload(const struct ieee80211vap *vap,
                                struct ieee80211req_athdbg *req)
{
    ieee80211_bsteering_t bsteering = NULL;

    if (!ieee80211_bsteering_is_req_valid(vap, req)) {
        return -EINVAL;
    }

    bsteering = vap->iv_ic->ic_bsteering;

    spin_lock_bh(&bsteering->bs_lock);
    req->data.bsteering_overload = bsteering->bs_vap_overload ? 1 : 0;
    spin_unlock_bh(&bsteering->bs_lock);

    return EOK;
}

/**
 * @brief Start RSSI measurement on a specific station.
 *
 * This is called from user space when an instantaneous RSSI measurement is
 * desired.
 *
 * @param [in] vap  the VAP to start RSSI measurement
 * @param [in] req  request from user space containing the station MAC address and
 *                  number of measurements to average before reporting back
 *
 * @return EINVAL if band steering not initialized; EBUSY if the previous measurement is not done;
 *         otherwise return EOK
 */

int wlan_bsteering_trigger_rssi_measurement(struct ieee80211vap *vap,
                                            const struct ieee80211req_athdbg *req)
{
    struct ieee80211com *ic = NULL;
    ieee80211_bsteering_t bsteering = NULL;
    struct ieee80211_node *ni = NULL;
    int retVal = EOK;

    if (!ieee80211_bsteering_is_req_valid(vap, req)) {
        return -EINVAL;
    }

    ic = vap->iv_ic;
    bsteering = ic->ic_bsteering;

    ni = ieee80211_find_node(&ic->ic_sta, req->dstmac);
    if (!ni) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Requested STA %02x:%02x:%02x:%02x:%02x:%02x is not "
               "associated\n", __func__, req->dstmac[0], req->dstmac[1],
               req->dstmac[2], req->dstmac[3], req->dstmac[4], req->dstmac[5]);
        return -EINVAL;
    }

    spin_lock_bh(&bsteering->bs_lock);
    do {
        if (!ieee80211_bsteering_is_enabled(ic)) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Band steering is not enabled when measuring RSSI for "
                   "STA %02x:%02x:%02x:%02x:%02x:%02x\n",
                   __func__, req->dstmac[0], req->dstmac[1], req->dstmac[2],
                   req->dstmac[3], req->dstmac[4], req->dstmac[5]);
            retVal = -EINVAL;
            break;
        }

        if (bsteering->bs_inst_rssi_inprogress) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Ignore RSSI measurement request for STA "
                   "%02x:%02x:%02x:%02x:%02x:%02x, since another "
                   "RSSI measurement is in progress (count=%u) for "
                   "STA %02x:%02x:%02x:%02x:%02x:%02x\n",
                   __func__, req->dstmac[0], req->dstmac[1], req->dstmac[2],
                   req->dstmac[3], req->dstmac[4], req->dstmac[5],
                   bsteering->bs_inst_rssi_count,
                   bsteering->bs_inst_rssi_macaddr[0],
                   bsteering->bs_inst_rssi_macaddr[1],
                   bsteering->bs_inst_rssi_macaddr[2],
                   bsteering->bs_inst_rssi_macaddr[3],
                   bsteering->bs_inst_rssi_macaddr[4],
                   bsteering->bs_inst_rssi_macaddr[5]);
            break;
        }

        bsteering->bs_inst_rssi_num_samples = req->data.bsteering_rssi_num_samples;
        bsteering->bs_inst_rssi_count = 0;
        bsteering->bs_inst_rssi_err_count = 0;
        memcpy(bsteering->bs_inst_rssi_macaddr, req->dstmac, IEEE80211_ADDR_LEN);
        OS_SET_TIMER(&bsteering->bs_inst_rssi_timer, INST_RSSI_TIMEOUT * 1000);
        bsteering->bs_inst_rssi_inprogress = true;

        wlan_send_rssi(ni->ni_vap, ni->ni_macaddr);
    } while (0);

    spin_unlock_bh(&bsteering->bs_lock);

    ieee80211_free_node(ni);

    return retVal;
}

/**
 * @brief Enable/Disable band steering channel utilzation
 *        rssi measurement and inacitivity timer
 *
 * @pre  wlan_bsteering_enable must be called
 *
 * @param [in] bstering  ic band steering instance.
 * @param [in] enable  flag to enable or disable.
 *
 * @return EOK if starting or stopping timer is successfull
 *         EINVAL in case timer starting or stopping fails.
 */

u_int32_t wlan_bsteering_start_stop_timer(ieee80211_bsteering_t bsteering, bool enable)
{
    u_int32_t retval=EOK;

    if(!atomic_read(&bsteering->bs_enabled)) {
        if (enable) {
            if (bsteering->bs_config_params.utilization_sample_period) {
                ieee80211_bsteering_reset_chan_utilization(bsteering);
                OS_SET_TIMER(&bsteering->bs_chan_util_timer,
                             bsteering->bs_config_params.utilization_sample_period * 1000);
            }
        } else {
            OS_CANCEL_TIMER(&bsteering->bs_chan_util_timer);
            OS_CANCEL_TIMER(&bsteering->bs_inst_rssi_timer);
        }
        /* Note: To avoid a possible deadlock, the lower layer should never
           call a band steering function that grabs the band steering
           spinlock while holding the peer lock.*/
        if(!bsteering->bs_ic->ic_bs_enable(bsteering->bs_ic, enable))
            retval = EINVAL;
    }

    return retval;
}

/**
 * @brief Enable/Disable band steering on a VAP
 *
 * @pre  wlan_bsteering_set_params must be called
 *
 * @note although this operates on a VAP, it currently enables band steering
 *       on all VAPs on the radio
 *
 * @param [inout] vap  the VAP whose band steering status changes
 * @param [in] req  request from user space containing the flag indicating enable or disable
 *
 * @return EINVAL if band steering not initialized, otherwise
 *         return EOK
 */

int wlan_bsteering_enable(struct ieee80211vap *vap, const struct ieee80211req_athdbg *req)
{
    ieee80211_bsteering_t bsteering = NULL;
    int retval = -EINVAL;

    if (!ieee80211_bsteering_is_req_valid(vap, req)) {
        return -EINVAL;
    }

    bsteering = vap->iv_ic->ic_bsteering;

    do {
        spin_lock_bh(&bsteering->bs_lock);

        if (req->data.bsteering_enable) {  /* enable */

            if (ieee80211_bsteering_is_enabled(vap->iv_ic)) {
                atomic_inc(&bsteering->bs_enabled);
                retval = EOK;
                break;
            }
            /* Sanity check to make sure valid config parameters have been set */
            if (!bsteering->bs_config_params.inactivity_check_period ||
                (bsteering->bs_config_params.utilization_sample_period &&
                 !bsteering->bs_config_params.utilization_average_num_samples)) {
                retval = -EINVAL;
                break;
            }

            retval = wlan_bsteering_start_stop_timer(bsteering, true);

            if(retval == EOK) {
                atomic_inc(&bsteering->bs_enabled);
                /* Remember the VAP for later, as we need one to trigger the
                   channel utilization. */
                bsteering->bs_iv = vap;
            }
        } else {  /* disable */
            /* Ensure it is not a double disable.*/
            if (!ieee80211_bsteering_is_enabled(vap->iv_ic)) {
                retval = -EALREADY;
                break;
            }
            atomic_dec(&bsteering->bs_enabled);
            if (wlan_bsteering_start_stop_timer(bsteering, false) !=EOK)
                break;
        }

        retval = EOK;
    } while (0);

    spin_unlock_bh(&bsteering->bs_lock);
    return retval;
}

/**
 * @brief Enable/Disable band steering events on a VAP
 *
 * @pre  wlan_bsteering_enable must be called
 *
 * @param [inout] vap  the VAP whose band steering status
 *                     changes
 * @param [in] req  request from user space containing the flag indicating enable or disable
 *
 * @return EINVAL if band steering not initialized or enabled on
 *         the radio, EALREADY if band steering on the VAP is
 *         already in the requested state, otherwise return EOK
 */
int wlan_bsteering_enable_events(struct ieee80211vap *vap, const struct ieee80211req_athdbg *req)
{
    bool enabled;
    if (!ieee80211_bsteering_is_req_valid(vap, req)) {
        return -EINVAL;
    }

    /* Make sure band steering is enabled at the radio level first */
    if (!(ieee80211_bsteering_is_enabled(vap->iv_ic))) {
        return -EINVAL;
    }

    /* Make sure this isn't a set to the same state we are already in */
    enabled = ieee80211_bsteering_is_event_enabled(vap);
    if ((req->data.bsteering_enable && enabled) ||
        (!req->data.bsteering_enable && !enabled)) {
        return -EALREADY;
    }

    /* Set the state */
    atomic_set(&vap->iv_bs_enabled, req->data.bsteering_enable);

    return EOK;
}

/**
 * @brief Update whether probe responses should be withheld for a given
 *        MAC or not.
 *
 * Responses are only actually withheld if band steering is enabled.
 *
 * @pre The MAC must currently be in the ACL list for this to succeed.
 *
 * @param [in] vap  the VAP for which to change the value
 * @param [in] req  request from user space containing the station MAC
 *                  address and whether to enable or disable probe
 *                  response withholding
 *
 * @return EINVAL if the request is malformed; ENOENT if the MAC is not
 *         currently in the ACL; otherwise EOK
 */

int wlan_bsteering_set_probe_resp_wh(struct ieee80211vap *vap,
                                     const struct ieee80211req_athdbg *req)
{
    if (!ieee80211_bsteering_is_req_valid(vap, req)) {
        return -EINVAL;
    }

    if (req->data.bsteering_probe_resp_wh) {
        return ieee80211_acl_set_flag(vap, req->dstmac,
                                      IEEE80211_ACL_FLAG_PROBE_RESP_WH);
    } else {
        return ieee80211_acl_clr_flag(vap, req->dstmac,
                                      IEEE80211_ACL_FLAG_PROBE_RESP_WH);
    }
}

/**
 * @brief Update whether authentication should be allowed for a given
 *        MAC or not.
 *
 * Auth is allowed/disallowed only if Auth_allow flag is set/cleared.
 *
 * @pre The MAC must currently be in the ACL list for this to succeed.
 *
 * @param [in] vap  the VAP for which to change the value
 * @param [in] req  request from user space containing the station MAC
 *                  address and whether to allow or disallow
 *                  authentication
 *
 * @return EINVAL if the request is malformed; ENOENT if the MAC is not
 *         currently in the ACL; otherwise EOK
 */

int wlan_bsteering_set_auth_allow(struct ieee80211vap *vap,
        const struct ieee80211req_athdbg *req)
{
    ieee80211_bsteering_t bsteering = NULL;
    bsteering = vap->iv_ic->ic_bsteering;

    if (!ieee80211_bsteering_is_req_valid(vap, req)) {
        return -EINVAL;
    }

    if (req->data.bsteering_auth_allow) {
        return ieee80211_acl_set_flag(vap, req->dstmac,
                IEEE80211_ACL_FLAG_AUTH_ALLOW);
    } else {
        return ieee80211_acl_clr_flag(vap, req->dstmac,
                IEEE80211_ACL_FLAG_AUTH_ALLOW);
    }
}

/**
 * @brief Query whether probe responses are being withheld for a given
 *        MAC or not.
 *
 * @pre The MAC must currently be in the ACL list for this to succeed.
 *
 * @param [in] vap  the VAP for which to get the value
 * @param [inout] req  request from user space containing the station MAC
 *                     address for which to read the probe response
 *                     withholding value
 *
 * @return EINVAL if the request is malformed; otherwise EOK
 */

int wlan_bsteering_get_probe_resp_wh(struct ieee80211vap *vap,
                                     struct ieee80211req_athdbg *req)
{
    if (!ieee80211_bsteering_is_req_valid(vap, req)) {
        return -EINVAL;
    }

    /* Note that a lookup failure (no entry in the ACL) will also indicate
     * that probe responses are not being withheld.
     */
    req->data.bsteering_probe_resp_wh =
        ieee80211_acl_flag_check(vap, req->dstmac,
                                 IEEE80211_ACL_FLAG_PROBE_RESP_WH);
    return EOK;
}

/**
 * @brief Update whether probe responses should be allowed for a given
 *        MAC or not in 2.4G band.
 *
 * Responses are only actually withheld if band steering is enabled.
 *
 *
 * @param [in] vap  the VAP for which to change the value
 * @param [in] req  request from user space containing the station MAC
 *                  address and whether to enable or disable probe
 *                  response withholding
 *
 * @return EINVAL if the request is malformed; otherwise EOK
 */

int wlan_bsteering_set_probe_resp_allow_24g(struct ieee80211vap *vap,
                                     const struct ieee80211req_athdbg *req)
{
    struct ieee80211com *ic = NULL;
    ieee80211_bsteering_t bsteering = NULL;

    if (!ieee80211_bsteering_is_req_valid(vap, req)) {
        return -EINVAL;
    }

    ic = vap->iv_ic;
    bsteering = ic->ic_bsteering;

    spin_lock_bh(&bsteering->bs_lock);
    if (req->data.bsteering_probe_resp_allow_24g) {
        ieee80211_bsteering_probe_resp_find_and_add_allow_entry(vap, req->dstmac);
    } else {
        ieee80211_bsteering_probe_resp_allow_entry_remove(vap, req->dstmac);
    }
    spin_unlock_bh(&bsteering->bs_lock);

    return EOK;
}

/**
 * @brief Update whether a given STA has steering in progress or not.
 *
 * The flag will only be updated if band steering is enabled.
 *
 * @param [in] vap  the VAP for which to change the value
 * @param [in] req  request from user space containing the station MAC
 *                  address and whether the steering is in progress or not
 *
 * @return EINVAL if the request is malformed; otherwise EOK
 */

int wlan_bsteering_set_steering(struct ieee80211vap *vap,
                                struct ieee80211req_athdbg *req)
{
    struct ieee80211com *ic = NULL;
    ieee80211_bsteering_t bsteering = NULL;
    struct ieee80211_node *ni = NULL;
    int retval = EOK;

    if (!ieee80211_bsteering_is_req_valid(vap, req)) {
        return -EINVAL;
    }

    ic = vap->iv_ic;
    bsteering = ic->ic_bsteering;

    ni = ieee80211_find_node(&ic->ic_sta, req->dstmac);
    if (!ni) {
        if (req->data.bsteering_steering_in_progress) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Requested STA %02x:%02x:%02x:%02x:%02x:%02x is not "
                   "associated\n", __func__, req->dstmac[0], req->dstmac[1],
                   req->dstmac[2], req->dstmac[3], req->dstmac[4], req->dstmac[5]);
            return -EINVAL;
        } else {
            /* It is allowed to unset steering flag after the STA has been steered
               to another AP. */
            return EOK;
        }
    }

    spin_lock_bh(&bsteering->bs_lock);
    if (!ieee80211_bsteering_is_enabled(ic)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Band steering is not enabled when updating steering flag for "
               "STA %02x:%02x:%02x:%02x:%02x:%02x\n",
               __func__, req->dstmac[0], req->dstmac[1], req->dstmac[2],
               req->dstmac[3], req->dstmac[4], req->dstmac[5]);
        retval = -EINVAL;
    } else {
        ni->ni_bs_steering_flag = req->data.bsteering_steering_in_progress;
    }
    spin_unlock_bh(&bsteering->bs_lock);

    ieee80211_free_node(ni);

    return retval;
}

/**
 * @brief Update the timer interval duration for DA stats
 *
 * @param [in] vap  the VAP for which to change the value
 * @param [in] req  request from user space containing the parameters
 *
 * @return EINVAL if the request is malformed; otherwise EOK
 */

int wlan_bsteering_set_sta_stats_interval_da(struct ieee80211vap *vap,
                                             struct ieee80211req_athdbg *req)
{
    struct ieee80211com *ic = NULL;
    ieee80211_bsteering_t bsteering = NULL;

    ic = vap->iv_ic;
    bsteering = ic->ic_bsteering;

    bsteering->sta_stats_update_interval_da = req->data.bsteering_sta_stats_update_interval_da;
    return EOK;
}

/**
 * @brief Get the maximum MCS supported by the client
 *
 * @param [in] ni  the STA to check for maximum MCS supported
 *
 * @return the maximum MCS supported by this client on success;
 *         otherwise return -1
 */
static int ieee80211_bsteering_get_node_max_MCS(const struct ieee80211_node *ni) {
    return ieee80211_bsteering_get_max_MCS(ni->ni_phymode, ni->ni_rx_vhtrates,
                                           ni->ni_tx_vhtrates, &ni->ni_htrates,
                                           &ni->ni_rates);
}

/**
 * @brief Get the maximum MCS supported based on PHY mode and rate
 *        information provided
 *
 * @param [in] phymode  the PHY mode the VAP/client is operating on
 * @param [in] rx_vht_mcs_map  the VHT RX rate map if supported
 * @param [in] tx_vht_mcs_map  the VHT TX rate map if supported
 * @param [in] htrates  the HT rates supported
 * @param [in] basic_rates  all other rates supported
 *
 * @return the maximum MCS supported on success; otherwise return -1
 */
static int ieee80211_bsteering_get_max_MCS(enum ieee80211_phymode phymode,
                                           u_int16_t rx_vht_mcs_map, u_int16_t tx_vht_mcs_map,
                                           const struct ieee80211_rateset *htrates,
                                           const struct ieee80211_rateset *basic_rates) {
    u_int8_t rx_max_MCS, tx_max_MCS, max_MCS;
    switch (phymode) {
        case IEEE80211_MODE_11AC_VHT20:
        case IEEE80211_MODE_11AC_VHT40PLUS:
        case IEEE80211_MODE_11AC_VHT40MINUS:
        case IEEE80211_MODE_11AC_VHT40:
        case IEEE80211_MODE_11AC_VHT80:
        case IEEE80211_MODE_11AC_VHT160:
        case IEEE80211_MODE_11AC_VHT80_80:
            if (rx_vht_mcs_map && tx_vht_mcs_map) {
                /* Refer to IEEE P802.11ac/D7.0 Figure 8-401bs for VHT MCS Map definition */
                rx_max_MCS = rx_vht_mcs_map & 0x03;
                tx_max_MCS = tx_vht_mcs_map & 0x03;
                max_MCS = rx_max_MCS < tx_max_MCS ? rx_max_MCS : tx_max_MCS;
                if (max_MCS < 0x03) {
                   return 7 + max_MCS;
                }
            }
            /* Invalid 11ac MCS, fallback to report 11n MCS */
        case IEEE80211_MODE_11NA_HT20:
        case IEEE80211_MODE_11NG_HT20:
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40:
        case IEEE80211_MODE_11NA_HT40:
            if (htrates && htrates->rs_nrates && (htrates->rs_nrates <= IEEE80211_RATE_MAXSIZE)) {
                return htrates->rs_rates[htrates->rs_nrates - 1];
            }
            /* Invalid 11n MCS, fallback to basic rates */
        default:
            if (basic_rates && basic_rates->rs_nrates && (basic_rates->rs_nrates <= IEEE80211_RATE_MAXSIZE)) {
                return basic_rates->rs_rates[basic_rates->rs_nrates - 1] & IEEE80211_RATE_VAL;
            }
    }

    return -1;
}

/**
 * @brief Query the data rate related information of the VAP or client
 *        as specified by the MAC address
 *
 * @param [in] vap  the VAP for which to get the value
 * @param [inout] req  request from user space containing the VAP/station MAC
 *                     address for which to get the data rate related info
 *
 * @return EINVAL if the request is malformed; otherwise EOK
 */

int wlan_bsteering_get_datarate_info(struct ieee80211vap *vap,
                                     struct ieee80211req_athdbg *req)
{
    int max_MCS = 0;
    struct ieee80211_node *ni = NULL;

    if (!ieee80211_bsteering_is_req_valid(vap, req)) {
        return -EINVAL;
    }

    if (IEEE80211_ADDR_EQ(vap->iv_myaddr, req->dstmac)) {
        struct ieee80211com *ic = vap->iv_ic;
        req->data.bsteering_datarate_info.max_chwidth = ic->ic_cwm_get_width(ic);
        req->data.bsteering_datarate_info.num_streams =
                ieee80211_getstreams(ic, ic->ic_tx_chainmask);
        req->data.bsteering_datarate_info.phymode = vap->iv_cur_mode;
        /* Tx power is stored in half dBm */
        req->data.bsteering_datarate_info.max_txpower = vap->iv_bss->ni_txpower / 2;
        max_MCS = ieee80211_bsteering_get_max_MCS(vap->iv_cur_mode,
                                                      vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map,
                                                      vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map,
                                                      &ic->ic_sup_ht_rates[vap->iv_cur_mode],
                                                      &ic->ic_sup_rates[vap->iv_cur_mode]);
        if (max_MCS < 0) {
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Requested VAP %02x:%02x:%02x:%02x:%02x:%02x has no valid rate info.",
                   __func__, req->dstmac[0], req->dstmac[1], req->dstmac[2],
                   req->dstmac[3], req->dstmac[4], req->dstmac[5]);
            return -EINVAL;
        } else {
            req->data.bsteering_datarate_info.max_MCS = max_MCS;
        }
    } else {
        ni = ieee80211_find_node(&vap->iv_ic->ic_sta, req->dstmac);
        if (!ni) {
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Requested STA %02x:%02x:%02x:%02x:%02x:%02x is not "
                   "associated\n", __func__, req->dstmac[0], req->dstmac[1],
                   req->dstmac[2], req->dstmac[3], req->dstmac[4], req->dstmac[5]);
            return -EINVAL;
        }

        req->data.bsteering_datarate_info.max_chwidth = ni->ni_chwidth;
        req->data.bsteering_datarate_info.num_streams = ni->ni_streams;
        req->data.bsteering_datarate_info.phymode = ni->ni_phymode;
        req->data.bsteering_datarate_info.max_txpower = ni->ni_max_txpower;
        req->data.bsteering_datarate_info.is_mu_mimo_supported =
            (bool)(ni->ni_vhtcap & IEEE80211_VHTCAP_MU_BFORMEE);
        max_MCS = ieee80211_bsteering_get_node_max_MCS(ni);
        if (max_MCS < 0) {
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Requested STA %02x:%02x:%02x:%02x:%02x:%02x has no valid rate info.",
                   __func__, req->dstmac[0], req->dstmac[1], req->dstmac[2],
                   req->dstmac[3], req->dstmac[4], req->dstmac[5]);
            ieee80211_free_node(ni);
            return -EINVAL;
        } else {
            req->data.bsteering_datarate_info.max_MCS = max_MCS;
        }
        req->data.bsteering_datarate_info.is_static_smps =
                ((ni->ni_htcap & IEEE80211_HTCAP_C_SM_MASK) ==
                     IEEE80211_HTCAP_C_SMPOWERSAVE_STATIC);

        ieee80211_free_node(ni);
    }
    return EOK;
}

/**
 * @brief Query the band steering module for whether it is withholding
 *        probe responses for the given MAC address on this VAP.
 *
 * @param [in] vap  the VAP on which the probe request was received
 * @param [in] mac_addr  the MAC address of the client that sent the probe
 *                       request
 *
 * @return true if the response should be withheld; otherwise false
 */

bool ieee80211_bsteering_is_probe_resp_wh(struct ieee80211vap *vap,
                                          const u_int8_t *mac_addr)
{
    if(!ieee80211_bsteering_is_vap_enabled(vap) ||
       !ieee80211_bsteering_is_enabled(vap->iv_ic)) {
        return false;
    }

    return ieee80211_acl_flag_check(vap, mac_addr,
                                    IEEE80211_ACL_FLAG_PROBE_RESP_WH);
}

/**
 * @brief Find a STA entry in probe response allow table
 *
 * @param [in] vap  the VAP on which probe reponse allow check is done
 * @param [in] mac_addr  the MAC address of the client that sent the probe
 *                       request
 *
 * @return reference to entry if found; otherwise NULL.
 */
ieee80211_bsteering_probe_resp_allow_entry_t*
ieee80211_bsteering_probe_resp_allow_entry_find(struct ieee80211vap *vap,
        const u_int8_t *mac_addr)
{
    int i;
    ieee80211_bsteering_probe_resp_allow_entry_t *entry;

    for(i = 0; i < IEEE80211_BS_MAX_STA_WH_24G; i++)
    {
        entry = &vap->iv_bs_prb_resp_allow_table[i];
        if(entry->valid && IEEE80211_ADDR_EQ(mac_addr, entry->mac_addr))
        {
            return entry;
        }
    }

    return NULL;
}

/**
 * @brief Find an empty slot or free an older STA entry in allow table
 *
 * @param [in] vap  the VAP on which we need a free allow entry
 *
 * @return void
 */
static ieee80211_bsteering_probe_resp_allow_entry_t*
ieee80211_bsteering_probe_resp_get_free_allow_entry(struct ieee80211vap *vap)
{
    int i;
    unsigned long jiffies_older = OS_GET_TICKS();
    ieee80211_bsteering_probe_resp_allow_entry_t *entry = NULL;
    ieee80211_bsteering_probe_resp_allow_entry_t *older_entry;

    for(i = 0; i < IEEE80211_BS_MAX_STA_WH_24G; i++)
    {
        entry = &vap->iv_bs_prb_resp_allow_table[i];
        if(!entry->valid)
        {
            return entry;
        }
    }

    older_entry = &vap->iv_bs_prb_resp_allow_table[0];
    /* No empty slot, find an older entry */
    for(i = 0; i < IEEE80211_BS_MAX_STA_WH_24G; i++)
    {
        entry = &vap->iv_bs_prb_resp_allow_table[i];
        if(time_before(entry->create_time_jiffies, jiffies_older))
        {
            older_entry = entry;
            jiffies_older = entry->create_time_jiffies;
        }
    }

    return older_entry;
}

/**
 * @brief Find and Add a STA entry in probe response allow table
 *
 * @param [in] vap  the VAP on which probe reponse to be allowed
 * @param [in] mac_addr  the MAC address of the client that may send probe
 *                       request
 *
 * @return void
 */
static void
ieee80211_bsteering_probe_resp_find_and_add_allow_entry(struct ieee80211vap *vap,
        const u_int8_t *mac_addr)
{
    ieee80211_bsteering_probe_resp_allow_entry_t *entry;

    entry = ieee80211_bsteering_probe_resp_allow_entry_find(vap, mac_addr);
    if(entry == NULL)
    {
        entry = ieee80211_bsteering_probe_resp_get_free_allow_entry(vap);
        IEEE80211_ADDR_COPY(entry->mac_addr, mac_addr);
        entry->valid=1;
    }

    entry->create_time_jiffies = OS_GET_TICKS();
}

/**
 * @brief Find and remove a STA entry in probe response allow table
 *
 * @param [in] vap  the VAP on which probe reponse allow entry to be removed
 * @param [in] mac_addr  the MAC address of the client that needs to be removed
 *
 * @return void
 */
static void
ieee80211_bsteering_probe_resp_allow_entry_remove(struct ieee80211vap *vap,
        const u_int8_t *mac_addr)
{
    ieee80211_bsteering_probe_resp_allow_entry_t *entry = NULL;

    entry = ieee80211_bsteering_probe_resp_allow_entry_find(vap, mac_addr);
    if(entry)
        entry->valid=0;
}

/**
 * @brief Add a STA entry in probe response withheld table
 *
 * @param [in] entry the STA entry to be updated
 * @param [in] mac_addr  the MAC address of the client that may send probe
 *                       request
 *
 * @return void
 */
static void ieee80211_bsteering_probe_resp_wh_entry_add(
        ieee80211_bsteering_probe_resp_wh_entry_t *entry,
        const u_int8_t *mac_addr)
{
    entry->initial_prb_req_jiffies = OS_GET_TICKS();
    entry->prb_resp_wh_count = 1;
    entry->valid = 1;
    IEEE80211_ADDR_COPY(entry->mac_addr, mac_addr);
}

/**
 * @brief Reset a STA entry in probe response withheld table
 *
 * @param [in] entry  the STA entry to be reseted
 * @param [in] mac_addr  the MAC address of the client that may send probe
 *                       request
 *
 * @return void
 */
static void ieee80211_bsteering_probe_resp_wh_entry_reset(
        ieee80211_bsteering_probe_resp_wh_entry_t *entry)
{
    entry->valid = 1;
    entry->prb_resp_wh_count = 1;
    entry->initial_prb_req_jiffies = OS_GET_TICKS();
}

/**
 * @brief Remove a STA entry in probe response withheld table
 *
 * @param [in] entry  the STA entry to be removed
 * @param [in] mac_addr  the MAC address of the client that may send probe
 *                       request
 *
 * @return void
 */
static void ieee80211_bsteering_probe_resp_wh_entry_remove(
        ieee80211_bsteering_probe_resp_wh_entry_t *entry)
{
    entry->valid = 0;
    entry->prb_resp_wh_count = 0;
    entry->initial_prb_req_jiffies = 0;
}

/**
 * @brief Update a STA entry in probe response withheld table and check for
 * whether probe response allowed or not.
 *
 * @param [in] entry  the STA entry to be updated and checked
 * @param [in] mac_addr  the MAC address of the client that may send probe
 *                       request
 *
 * @return [out] true if probe response should be withheld; otherwise false
 */
static bool ieee80211_bsteering_probe_resp_wh_entry_update_and_check(
        struct ieee80211vap *vap,
        ieee80211_bsteering_probe_resp_wh_entry_t *entry)
{
    struct ieee80211com *ic = vap->iv_ic;
    ieee80211_bsteering_t bsteering = ic->ic_bsteering;
    unsigned long jiffies_now = OS_GET_TICKS();

    if(time_before_eq(jiffies_now, ((unsigned long)bsteering->bs_config_params.delay_24g_probe_time_window * HZ)))
    {
        entry->prb_resp_wh_count++;

        if(entry->prb_resp_wh_count > bsteering->bs_config_params.delay_24g_probe_min_req_count)
            return false;
    }
    else
    {
        ieee80211_bsteering_probe_resp_wh_entry_reset(entry);
    }
    return true;
}

/**
 * @brief Query the band steering module for whether it is withholding
 *        probe responses on 2.4G for the given MAC address on this VAP.
 *
 * @param [in] vap  the VAP on which the probe request was received
 * @param [in] mac_addr  the MAC address of the client that sent the probe
 *                       request
 * @param [in] sta_rssi  the RSSI of the received probe request
 *
 * @return true if the response should be withheld; otherwise false
 */
bool ieee80211_bsteering_is_probe_resp_wh_24g(struct ieee80211vap *vap,
                                          const u_int8_t *mac_addr,
                                          u_int8_t sta_rssi)
{
    struct ieee80211_node *ni = NULL;
    struct ieee80211com *ic = vap->iv_ic;
    ieee80211_bsteering_t bsteering = ic->ic_bsteering;
    ieee80211_bsteering_probe_resp_allow_entry_t* allow_entry = NULL;

    if(!ieee80211_bsteering_is_vap_enabled(vap) ||
            !ieee80211_bsteering_is_enabled(vap->iv_ic)) {
        return false;
    }

    /* If VAP is not 2.4G or station 2.4G RSSI is less than threshold
     * or config parameters are not valid, send probe responses */
    if(!IEEE80211_IS_CHAN_2GHZ(vap->iv_bsschan) ||
            sta_rssi < bsteering->bs_config_params.delay_24g_probe_rssi_threshold ||
            bsteering->bs_config_params.delay_24g_probe_time_window == 0 ||
            bsteering->bs_config_params.delay_24g_probe_min_req_count == 0)
        return false;

    ni = ieee80211_find_node(&ic->ic_sta, mac_addr);
    if (ni && (ni->ni_vap == vap))
    {
        /* node is already in node table, send the probe response */
        ieee80211_free_node(ni);
        return false;
    }

    spin_lock(&bsteering->bs_lock);
    allow_entry = ieee80211_bsteering_probe_resp_allow_entry_find(vap, mac_addr);
    spin_unlock(&bsteering->bs_lock);

    if(allow_entry != NULL)
    {
        /* This client is being steered to 2.4G band, allow probe responses */
        return false;
    }
    else
    {
        ieee80211_bsteering_probe_resp_wh_entry_t *sta_entry = NULL;
        int i;
        u_int8_t entry_idx = 0;
        bool free_entry_found = false;

        /* Find whether the provided MAC is eligible for probe response in 2.4G band */
        for(i = 0; i < IEEE80211_BS_MAX_STA_WH_24G; i++)
        {
            sta_entry = &vap->iv_bs_prb_resp_wh_table[i];
            if(sta_entry->valid && IEEE80211_ADDR_EQ(mac_addr, sta_entry->mac_addr))
                return ieee80211_bsteering_probe_resp_wh_entry_update_and_check(vap, sta_entry);
        }

        /* No entry found, try finding empty slot for this STA */
        for(i = 0; i < IEEE80211_BS_MAX_STA_WH_24G; i++)
        {
            sta_entry = &vap->iv_bs_prb_resp_wh_table[i];
            if(!sta_entry->valid)
            {
                free_entry_found = true;
                entry_idx = i;
                break;
            }
        }

        /* No empty slot, free an older entry and use it */
        if(!free_entry_found)
        {
            unsigned long jiffies_older = OS_GET_TICKS();

            for(i = 0; i < IEEE80211_BS_MAX_STA_WH_24G; i++)
            {
                sta_entry = &vap->iv_bs_prb_resp_wh_table[i];
                if(time_before(sta_entry->initial_prb_req_jiffies, jiffies_older))
                {
                    entry_idx = i;
                    jiffies_older = sta_entry->initial_prb_req_jiffies;
                    free_entry_found = true;
                }
            }
        }

        if(free_entry_found)
        {
            ieee80211_bsteering_probe_resp_wh_entry_add(&vap->iv_bs_prb_resp_wh_table[entry_idx], mac_addr);
            return true;
        }
    }
    /* It should not land here. Failed to find/get an entry,
     * send probe response for this STA*/
    return false;
}

/**
 * @brief Initialize the band steering infrastructure.
 *
 * @param [in] ic  the radio on which to initialize
 *
 * @return EOK on success; EINPROGRESS if band steering is already initialized
 *         or ENOMEM on a memory allocation failure
 */

int ieee80211_bsteering_attach(struct ieee80211com *ic)
{
    ieee80211_bsteering_t bsteering = NULL;

    if (ic->ic_bsteering) {
        return -EINPROGRESS;
    }
    bsteering = (ieee80211_bsteering_t )
        OS_MALLOC(ic->ic_osdev, sizeof(struct ieee80211_bsteering), 0);
    if(NULL == bsteering) {
        return -ENOMEM;
    }

    OS_MEMZERO(bsteering,sizeof(struct ieee80211_bsteering));
    ic->ic_bsteering = bsteering;
    bsteering->bs_osdev = ic->ic_osdev;
    bsteering->bs_ic = ic;

    spin_lock_init(&bsteering->bs_lock);
    atomic_set(&bsteering->bs_enabled, false);
    bsteering->bs_chan_util_requested = false;

    OS_INIT_TIMER(bsteering->bs_osdev, &bsteering->bs_chan_util_timer,
                  wlan_bsteering_chan_util_timeout_handler, (void *) ic, QDF_TIMER_TYPE_WAKE_APPS);

    OS_INIT_TIMER(bsteering->bs_osdev, &bsteering->bs_inst_rssi_timer,
                  wlan_bsteering_inst_rssi_timeout_handler, (void *) ic, QDF_TIMER_TYPE_WAKE_APPS);

    ieee80211_bsteering_direct_attach_create(ic);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"%s: Band steering initialized\n", __func__);
    return EOK;
}

/**
 * @brief Destroy the band steering infrastructure.
 *
 * @param [in] ic  the radio for which to destroy
 *
 * @return EOK on success; any other value for an error
 */

int ieee80211_bsteering_detach(struct ieee80211com *ic)
{
    ieee80211_bsteering_t bsteering = ic->ic_bsteering;

    if(NULL == bsteering) {
        return EOK;
    }

    OS_FREE_TIMER(&bsteering->bs_chan_util_timer);
    OS_FREE_TIMER(&bsteering->bs_inst_rssi_timer);
    ieee80211_bsteering_direct_attach_destroy(ic);
    spin_lock_destroy(&bsteering->bs_lock);

    OS_FREE(bsteering);
    bsteering = NULL;
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"%s: Band steering terminated\n", __func__);
    return EOK;
}

/**
 * @brief Record a node's activity status change
 *
 * @param [in] ic  the radio on which the node is associated
 * @param [in] mac_addr  the MAC address of the node
 * @param [in] active  true if the node becomes active;
 *                     false if it becomes inactive
 */

void
ieee80211_bsteering_record_act_change(struct ieee80211com *ic,
                                      const u_int8_t *mac_addr,
                                      bool active)
{
    struct ieee80211_node *ni;

    if (!ieee80211_bsteering_is_enabled(ic) || !mac_addr) {
        return;
    }

    ni = ieee80211_find_node(&ic->ic_sta, mac_addr);

    if (!ni) {
        return;
    }

    if ((ni->ni_flags & IEEE80211_NODE_AUTH) &&
            ieee80211_bsteering_is_vap_enabled(ni->ni_vap)) {
        ieee80211_bsteering_send_activity_change_event(
                                                       ni->ni_vap, ni->ni_macaddr, active);
    }

    ieee80211_free_node(ni);
}

/**
 * @brief Generate an event indicating that a probe request was received.
 *
 * This is used by user space to determine which nodes are dual band
 * capable.
 *
 * @param [in] vap  the VAP on which the probe was received
 * @param [in] mac_addr  the MAC address of the client that sent the probe
 *                       request
 * @param [in] rssi  the RSSI of the received probe request
 */

void ieee80211_bsteering_send_probereq_event(struct ieee80211vap *vap,
                                             const u_int8_t *mac_addr,
                                             u_int8_t rssi)
{
    struct bs_probe_req_ind probe;

    if(!ieee80211_bsteering_is_vap_enabled(vap) ||
       !ieee80211_bsteering_is_enabled(vap->iv_ic)) {
        return;
    }

    OS_MEMCPY(probe.sender_addr, mac_addr, IEEE80211_ADDR_LEN);
    probe.rssi = rssi;
    IEEE80211_DELIVER_BSTEERING_EVENT(vap, ATH_EVENT_BSTEERING_PROBE_REQ,
                                      sizeof(probe),
                                      (const char *) &probe);
}

/**
 * @brief Generate an event indicating that an authentication message
 *        was sent with a failure code.
 *
 * @param [in] vap  the VAP on which the message was sent
 * @param [in] mac_addr  the MAC address of the client to which the
 *                       message was sent
 * @param [in] rssi  the RSSI of the received authentication message which
 *                   caused the rejection
 */

void ieee80211_bsteering_send_auth_fail_event(struct ieee80211vap *vap,
                                              const u_int8_t *mac_addr,
                                              u_int8_t rssi)
{
    struct bs_auth_reject_ind auth;

    if(!ieee80211_bsteering_is_vap_enabled(vap) ||
       !ieee80211_bsteering_is_enabled(vap->iv_ic)) {
        return;
    }

    OS_MEMCPY(auth.client_addr, mac_addr, IEEE80211_ADDR_LEN);
    auth.rssi = rssi;
    IEEE80211_DELIVER_BSTEERING_EVENT(vap,
                                      ATH_EVENT_BSTEERING_TX_AUTH_FAIL,
                                      sizeof(auth),
                                      (const char *) &auth);
}

/**
 * @brief Generate an event indicating that an authentication is
 *        allowed even if the client is present in the blacklist
 *        due to auth allow flag set.
 *
 * @param [in] vap  the VAP on which the message was sent
 * @param [in] mac_addr  the MAC address of the client to which the
 *                       message was sent
 * @param [in] rssi  the RSSI of the received authentication message which
 *                   caused the association
 */

void ieee80211_bsteering_send_auth_allow_event(struct ieee80211vap *vap,
        const u_int8_t *mac_addr,
        u_int8_t rssi)
{
    struct bs_auth_reject_ind auth;

    if(!ieee80211_bsteering_is_vap_enabled(vap) ||
            !ieee80211_bsteering_is_enabled(vap->iv_ic)) {
        return;
    }

    OS_MEMCPY(auth.client_addr, mac_addr, IEEE80211_ADDR_LEN);
    auth.rssi = rssi;
    IEEE80211_DELIVER_BSTEERING_EVENT(vap,
            ATH_EVENT_BSTEERING_DBG_TX_AUTH_ALLOW,
            sizeof(auth),
            (const char *) &auth);
}

/**
 * @brief Inform the band steering module that a node is now 
 *        associated
 *
 * @param [in] vap  the VAP on which the change occurred
 * @param [in] mac_addr  the MAC address of the client who
 *                       associated
 * @param [in] isBTMSupported  set to true if BSS Transition
 *                             Management is supported by this
 *                             STA (as indicated in the
 *                             association request frame)
 */

void ieee80211_bsteering_send_node_associated_event(struct ieee80211vap *vap,
                                                    const struct ieee80211_node *ni)
{
    struct bs_node_associated_ind assoc;
    int max_MCS = 0;

    if(!ieee80211_bsteering_is_vap_enabled(vap) ||
       !ieee80211_bsteering_is_enabled(vap->iv_ic) || !ni) {
        return;
    }

    OS_MEMCPY(assoc.client_addr, ni->ni_macaddr, IEEE80211_ADDR_LEN);
    assoc.isBTMSupported = (bool)(ni->ni_ext_capabilities & IEEE80211_EXTCAPIE_BSSTRANSITION);
    assoc.isRRMSupported = (bool)(ni->ni_flags & IEEE80211_NODE_RRM);
    assoc.datarate_info.max_chwidth = ni->ni_chwidth;
    assoc.datarate_info.num_streams = ni->ni_streams;
    assoc.datarate_info.phymode = ni->ni_phymode;
    assoc.datarate_info.max_txpower = ni->ni_max_txpower;
    max_MCS = ieee80211_bsteering_get_node_max_MCS(ni);
    assoc.datarate_info.max_MCS = max_MCS < 0 ? 0 : max_MCS;
    assoc.datarate_info.is_static_smps =
        ((ni->ni_htcap & IEEE80211_HTCAP_C_SM_MASK) ==
             IEEE80211_HTCAP_C_SMPOWERSAVE_STATIC);
    assoc.datarate_info.is_mu_mimo_supported =
        (bool)(ni->ni_vhtcap & IEEE80211_VHTCAP_MU_BFORMEE);
    assoc.band_cap = ni->ni_operating_bands;

    IEEE80211_DELIVER_BSTEERING_EVENT(vap,
                                      ATH_EVENT_BSTEERING_NODE_ASSOCIATED,
                                      sizeof(assoc),
                                      (const char *) &assoc);
}

/**
 * @brief Notify band steering when an error RRM beacon report response is received
 *
 * It will generate a netlink event with error status if band steering is enabled.
 *
 * @param [in] vap  the VAP on which the report is received
 * @param [1n] token  the dialog token matching the one provided in the request
 * @param [in] macaddr  the MAC address of the reporter station
 * @param [1n] mode  the measurement report mode contained in the response
 */
void ieee80211_bsteering_send_rrm_bcnrpt_error_event(
        struct ieee80211vap *vap, u_int32_t token, u_int8_t *macaddr,
        u_int8_t mode)
{
    struct bs_rrm_report_ind event = {0};

    if(!ieee80211_bsteering_is_vap_enabled(vap) ||
       !ieee80211_bsteering_is_enabled(vap->iv_ic)) {
        return;
    }

    event.rrm_type = BSTEERING_RRM_TYPE_BCNRPT;
    event.measrpt_mode = mode;
    event.dialog_token = token;
    IEEE80211_ADDR_COPY(event.macaddr, macaddr);

    ieee80211_bsteering_send_rrm_report_event(vap, &event);
}

/**
 * @brief Allocate memory to be filled with RRM beacon reports received
 *
 * The caller is responsible to call ieee80211_bsteering_dealloc_rrm_bcnrpt
 * to free the allocated memory.
 *
 * @param [in] vap  the VAP on which the report is received
 * @param [inout] reports  memory allocated enough to hold the requested
 *                         number of beacon reports on success
 * @return maximum number of beacon reports should be filled on success;
 *         0 for error cases
 */
u_int8_t ieee80211_bsteering_alloc_rrm_bcnrpt(struct ieee80211vap *vap,
                                              ieee80211_bcnrpt_t **reports)
{
    if (!reports) {
        return 0;
    }
    *reports = NULL;

    if(!ieee80211_bsteering_is_vap_enabled(vap) ||
       !ieee80211_bsteering_is_enabled(vap->iv_ic)) {
        return 0;
    }

    *reports = (ieee80211_bcnrpt_t *)OS_MALLOC(
            vap->iv_ic->ic_osdev,
            IEEE80211_BSTEERING_RRM_NUM_BCNRPT_MAX * sizeof(ieee80211_bcnrpt_t),
            0);

    if (*reports) {
        OS_MEMZERO(*reports,
                   IEEE80211_BSTEERING_RRM_NUM_BCNRPT_MAX * sizeof(ieee80211_bcnrpt_t));
        return IEEE80211_BSTEERING_RRM_NUM_BCNRPT_MAX;
    } else {
        return 0;
    }
}

/**
 * @brief Free the allocated memory for RRM beacon reports
 *
 * @param [inout] reports  the memory to be freed
 */
void ieee80211_bsteering_dealloc_rrm_bcnrpt(ieee80211_bcnrpt_t **reports) {
    if (reports) {
        OS_FREE(*reports);
        *reports = NULL;
    }
}

/**
 * @brief Generate an event when beacon report response is received
 *
 * It will generate a netlink event if at lease one report is received, and
 * the beacon report memory will be wiped out for further reports.
 *
 * @param [in] vap  the VAP on which the report is received
 * @param [1n] token  the dialog token matching the one provided in the request
 * @param [in] macaddr  the MAC address of the reporter station
 * @param [1nout] bcnrpt  the beacon report(s) received
 * @param [1n] num_bcnrpt  number of the beacon report(s) to send
 */
void ieee80211_bsteering_send_rrm_bcnrpt_event(
    struct ieee80211vap *vap, u_int32_t token, u_int8_t *macaddr,
    ieee80211_bcnrpt_t *bcnrpt, u_int8_t num_bcnrpt) {
    struct bs_rrm_report_ind event = {0};

    if(!ieee80211_bsteering_is_vap_enabled(vap) ||
       !ieee80211_bsteering_is_enabled(vap->iv_ic)) {
        return;
    }

    event.rrm_type = BSTEERING_RRM_TYPE_BCNRPT;
    event.measrpt_mode = IEEE80211_RRM_MEASRPT_MODE_SUCCESS;
    event.dialog_token = token;
    IEEE80211_ADDR_COPY(event.macaddr, macaddr);
    OS_MEMCPY(&event.data, bcnrpt,
              (num_bcnrpt <= IEEE80211_BSTEERING_RRM_NUM_BCNRPT_MAX ?
                   num_bcnrpt : IEEE80211_BSTEERING_RRM_NUM_BCNRPT_MAX) *
                  sizeof(ieee80211_bcnrpt_t));

    ieee80211_bsteering_send_rrm_report_event(vap, &event);

    OS_MEMZERO(bcnrpt,
               IEEE80211_BSTEERING_RRM_NUM_BCNRPT_MAX * sizeof(ieee80211_bcnrpt_t));
}

/**
 * @brief Generate an event indicating a Radio Resource Management report
 *        is received
 *
 * @param [in] vap  the VAP on which the rrm report was received
 * @param [in] report  the report to put in the event
 */
static void ieee80211_bsteering_send_rrm_report_event(
    struct ieee80211vap *vap, const struct bs_rrm_report_ind *report) {

    IEEE80211_DELIVER_BSTEERING_EVENT(vap, ATH_EVENT_BSTEERING_RRM_REPORT,
                                      sizeof(*report), (const char*)report);
}

/**
 * @brief Generate an event when a BSS Transition Management
 *        response frame is received
 *
 * @param [in] vap  the VAP on which the frame is received
 * @param [in] token  the dialog token matching the one provided in
 *                    the request
 * @param [in] macaddr  the MAC address of the sending station
 * @param [in] bstm_resp  response frame information
 */
void ieee80211_bsteering_send_wnm_bstm_resp_event(struct ieee80211vap *vap, u_int32_t token,
                                                  u_int8_t *macaddr,
                                                  struct bs_wnm_bstm_resp *bstm_resp) {
    struct bs_wnm_event_ind event = {0};

    if(!ieee80211_bsteering_is_vap_enabled(vap) ||
       !ieee80211_bsteering_is_enabled(vap->iv_ic)) {
        return;
    }

    event.wnm_type = BSTEERING_WNM_TYPE_BSTM_RESPONSE;
    event.dialog_token = token;
    IEEE80211_ADDR_COPY(event.macaddr, macaddr);
    OS_MEMCPY(&event.data, bstm_resp, sizeof(struct bs_wnm_bstm_resp));

    IEEE80211_DELIVER_BSTEERING_EVENT(vap, ATH_EVENT_BSTEERING_WNM_EVENT,
                                      sizeof(struct bs_wnm_event_ind), (const char*)&event);
}

/**
 * @brief Generate an event when Tx power change on a VAP
 *
 * @param [in] vap  the VAP on which Tx power changes
 * @param [in] tx_power  the new Tx power
 */
void ieee80211_bsteering_send_txpower_change_event(struct ieee80211vap *vap,
                                                   u_int16_t tx_power) {
    struct bs_tx_power_change_ind event = {0};

    if(!ieee80211_bsteering_is_vap_enabled(vap) ||
       !ieee80211_bsteering_is_enabled(vap->iv_ic)) {
        return;
    }

    /* Tx power is stored in half dBm */
    event.tx_power = tx_power / 2;
    IEEE80211_DELIVER_BSTEERING_EVENT(vap, ATH_EVENT_BSTEERING_TX_POWER_CHANGE,
                                      sizeof(struct bs_tx_power_change_ind),
                                      (const char *)&event);
}

/**
 * @brief Send an event to user space on activity status change
 *
 * @pre vap has already been checked and confirmed to be valid
 *
 * @param [in] vap  the VAP that the activity status change client associated to
 * @param [in] mac_addr  the MAC address of the client
 * @param [in] activity  flag indicating active or not
 */
void ieee80211_bsteering_send_activity_change_event(struct ieee80211vap *vap,
                                                           const u_int8_t *mac_addr,
                                                           bool activity)
{
    struct bs_activity_change_ind ind;

    if(!ieee80211_bsteering_is_enabled(vap->iv_ic)) {
        return;
    }

    OS_MEMCPY(ind.client_addr, mac_addr, IEEE80211_ADDR_LEN);
    ind.activity = activity ? 1 : 0;

    IEEE80211_DELIVER_BSTEERING_EVENT(vap, ATH_EVENT_BSTEERING_CLIENT_ACTIVITY_CHANGE,
                                      sizeof(struct bs_activity_change_ind),
                                      (const char *) &ind);
}

/**
 * @brief Generate an event with the provided channel utilization measurement.
 *
 * @pre vap has already been checked and confirmed to be valid and band
 *      steering has been confirmed to be enabled
 *
 * @param [in] vap  the VAP that was used for the sampling
 * @param [in] chan_utilization  the utilization in percent
 * @param [in] is_debug  whether the log generated should be a debug event
 *                       or a regular event; debug events represent an
 *                       instantaneous measurement whereas normal (non-debug)
 *                       represent a filtered/averaged measurement
 */
static void ieee80211_bsteering_send_utilization_event(struct ieee80211vap *vap,
                                                       u_int8_t chan_utilization,
                                                       bool is_debug)
{
    struct bs_chan_utilization_ind ind;
    ATH_BSTEERING_EVENT event = ATH_EVENT_BSTEERING_CHAN_UTIL;

    ind.utilization = chan_utilization;

    if (is_debug) {
        event = ATH_EVENT_BSTEERING_DBG_CHAN_UTIL;
    }

    IEEE80211_DELIVER_BSTEERING_EVENT(vap, event, sizeof(ind),
                                      (const char *) &ind);
}

/**
 * @brief Send an event to user space on RSSI measurement crossed threshold
 *
 * @pre vap has already been checked and confirmed to be valid and band
 *      steering has confirmed to be enabled
 *
 * @param [in] vap  the VAP that the client whose RSSI is measured associated to
 * @param [in] mac_addr  the MAC address of the client
 * @param [in] rssi  the measured RSSI
 * @param [in] inact_xing  flag indicating if the RSSI crossed inactivity RSSI threshold.
 * @param [in] low_xing  flag indicating if the RSSI crossed low RSSI threshold
 * @param [in] rate_xing  flag indicating if the RSSI crossed
 *                        the rate RSSI threshold
 * @param [in] ap_xing  flag indicating if the RSSI crossed the AP steering RSSI threshold
 */
static void ieee80211_bsteering_send_rssi_xing_event(struct ieee80211vap *vap,
                                                     const u_int8_t *mac_addr,
                                                     u_int8_t rssi,
                                                     BSTEERING_XING_DIRECTION inact_xing,
                                                     BSTEERING_XING_DIRECTION low_xing,
                                                     BSTEERING_XING_DIRECTION rate_xing,
                                                     BSTEERING_XING_DIRECTION ap_xing)
{
    struct bs_rssi_xing_threshold_ind ind;
    ATH_BSTEERING_EVENT event = ATH_EVENT_BSTEERING_CLIENT_RSSI_CROSSING;

    OS_MEMCPY(ind.client_addr, mac_addr, IEEE80211_ADDR_LEN);
    ind.rssi = rssi;
    ind.inact_rssi_xing = inact_xing;
    ind.low_rssi_xing = low_xing;
    ind.rate_rssi_xing = rate_xing;
    ind.ap_rssi_xing = ap_xing;

    IEEE80211_DELIVER_BSTEERING_EVENT(vap, event, sizeof(ind),
                                      (const char *) &ind);
}

/**
 * @brief Send an event to user space if the Tx rate crossed a
 *        threshold
 *
 * @pre vap has already been checked and confirmed to be valid
 *      and band steering has confirmed to be enabled
 *
 * @param [in] vap  the VAP that the client whose Tx rate is
 *                  measured associated to
 * @param [in] mac_addr  the MAC address of the client
 * @param [in] tx_rate  the Tx rate
 * @param [in] xing  flag indicating the direction of the Tx
 *                   rate crossing.
 */
static void ieee80211_bsteering_send_tx_rate_xing_event(
    struct ieee80211vap *vap,
    const u_int8_t *mac_addr,
    u_int32_t tx_rate,
    BSTEERING_XING_DIRECTION xing)
{
    struct bs_tx_rate_xing_threshold_ind ind;
    ATH_BSTEERING_EVENT event = ATH_EVENT_BSTEERING_CLIENT_TX_RATE_CROSSING;

    OS_MEMCPY(ind.client_addr, mac_addr, IEEE80211_ADDR_LEN);
    ind.tx_rate = tx_rate;
    ind.xing = xing;

    IEEE80211_DELIVER_BSTEERING_EVENT(vap, event, sizeof(ind),
                                      (const char *) &ind);
}

/**
 * @brief Send an event to user space when requested RSSI measurement is available
 *
 * @pre vap has already been checked and confirmed to be valid and band
 *      steering has already been confirmed to be enabled
 *
 * @param [in] vap  the VAP that the client whose RSSI is measured associated to
 * @param [in] mac_addr  the MAC address of the client
 * @param [in] rssi  the measured RSSI
 * @param [in] is_debug  whether the log generated should be a debug event
 *                       or a regular event; debug events represent an
 *                       instantaneous (but averaged by firmware already) RSSI
 *                       measurement whereas normal (non-debug) represent the
 *                       RSSI measured by sending NDPs
 */
static void ieee80211_bsteering_send_rssi_measurement_event(struct ieee80211vap *vap,
                                                            const u_int8_t *mac_addr,
                                                            u_int8_t rssi,
                                                            bool is_debug)
{
    struct bs_rssi_measurement_ind ind;
    ATH_BSTEERING_EVENT event = ATH_EVENT_BSTEERING_CLIENT_RSSI_MEASUREMENT;

    OS_MEMCPY(ind.client_addr, mac_addr, IEEE80211_ADDR_LEN);
    ind.rssi = rssi;

    if (is_debug) {
        event = ATH_EVENT_BSTEERING_DBG_RSSI;
    }

    IEEE80211_DELIVER_BSTEERING_EVENT(vap, event, sizeof(ind),
                                      (const char *) &ind);
}

/**
 * @brief Send an event to user space when the Tx rate changes.
 *        Note this is a debug only message.
 *
 * @pre vap has already been checked and confirmed to be valid and band
 *      steering has already been confirmed to be enabled
 *
 * @param [in] vap  the VAP that the client whose RSSI is measured associated to
 * @param [in] mac_addr  the MAC address of the client
 * @param [in] tx_rate  the latest Tx rate
 */
static void ieee80211_bsteering_send_tx_rate_measurement_event(struct ieee80211vap *vap,
                                                               const u_int8_t *mac_addr,
                                                               u_int32_t tx_rate)
{
    struct bs_tx_rate_measurement_ind ind;
    ATH_BSTEERING_EVENT event = ATH_EVENT_BSTEERING_DBG_TX_RATE;

    OS_MEMCPY(ind.client_addr, mac_addr, IEEE80211_ADDR_LEN);
    ind.tx_rate = tx_rate;

    IEEE80211_DELIVER_BSTEERING_EVENT(vap, event, sizeof(ind),
                                      (const char *) &ind);
}

/**
 * @brief VAP iteration callback that measures the channel utilization
 *        on the provided VAP if it is the VAP that was used to enable
 *        band steering.
 *
 * If the VAP is not the one used to enable band steering, this does nothing.
 *
 * @note This must be called with the band steering lock held.
 *
 * @param [in] arg  the band steering handle
 * @param [in] vap  the current VAP being considered
 */
static void wlan_bsteering_measure_chan_util(void *arg, wlan_if_t vap)
{
#define CHANNEL_LOAD_REQUESTED 2
    ieee80211_bsteering_t bsteering = (ieee80211_bsteering_t) arg;
    int val = 1;

    /* Check whether the VAP still exists and is in AP mode */
    if (vap == bsteering->bs_iv && ieee80211_bsteering_is_vap_valid(vap)) {

        /* This check that the VAP is ready should be sufficient to ensure we do
           not trigger a scan while in DFS wait state.

           Note that there is still a small possibility that the channel or state
           will change after we check this flag. I do not know how to avoid this
           at this time.*/
        if (ieee80211_vap_ready_is_set(vap) &&
            !bsteering->bs_chan_util_requested && vap->iv_bsschan) {
            /* Remember the channel so we can ignore any callbacks that are
               not for our channel. */
            u_int8_t chanlist[2] = { 0 };

            if (vap->iv_bsschan->ic_ieee != bsteering->bs_active_ieee_chan_num) {
                /* Channel changed, so invalidate everything. The utilization
                   is not expected to be correlated across channels. */
                ieee80211_bsteering_reset_chan_utilization(bsteering);
            }

            bsteering->bs_active_ieee_chan_num = vap->iv_bsschan->ic_ieee;

            chanlist[0] = bsteering->bs_active_ieee_chan_num;

            if(!vap->iv_ic->ic_is_mode_offload(vap->iv_ic)) {
                val = CHANNEL_LOAD_REQUESTED;
            }

            if (wlan_acs_set_user_chanlist(vap, chanlist) == EOK) {
                if (wlan_acs_start_scan_report(vap, 1, IEEE80211_START_ACS_REPORT,
                                               val) == EOK) {
                    bsteering->bs_chan_util_requested = true;
                } else {
                        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Failed to start scan report on interface "
                               "%02x:%02x:%02x:%02x:%02x:%02x; "
                               "will retry in next timer expiry\n",
                               __func__, vap->iv_myaddr[0], vap->iv_myaddr[1],
                               vap->iv_myaddr[2], vap->iv_myaddr[3],
                               vap->iv_myaddr[4], vap->iv_myaddr[5]);
                }
            } else {
                QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Failed to set channel list on interface "
                       " %02x:%02x:%02x:%02x:%02x:%02x; "
                       "will retry in next timer expiry\n",
                       __func__, vap->iv_myaddr[0], vap->iv_myaddr[1],
                       vap->iv_myaddr[2], vap->iv_myaddr[3],
                       vap->iv_myaddr[4], vap->iv_myaddr[5]);
            }
        } else {
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Already waiting for utilization, VAP is not ready, "
                   "or bsschan is invalid on interface "
                   "%02x:%02x:%02x:%02x:%02x:%02x: %p\n",
                   __func__, vap->iv_myaddr[0], vap->iv_myaddr[1],
                   vap->iv_myaddr[2], vap->iv_myaddr[3],
                   vap->iv_myaddr[4], vap->iv_myaddr[5], vap->iv_bsschan);
        }

        OS_SET_TIMER(&bsteering->bs_chan_util_timer,
                     bsteering->bs_config_params.utilization_sample_period * 1000);
    }
#undef CHANNEL_LOAD_REQUESTED
}


/**
 * @brief Timeout handler for periodic channel utilization measurements.
 *
 * This will trigger the utilization measurement (assuming one is not already
 * in progress) and reschedule the timer for the next measurement. The
 * assumption is that the measurement will be complete prior to the next
 * timer expiry, but if it is not, this is guarded against and the next
 * measurement will just be delayed.
 *
 * @param [in] arg  ieee80211com
 *
 */
static OS_TIMER_FUNC(wlan_bsteering_chan_util_timeout_handler)
{
    struct ieee80211com *ic;
    ieee80211_bsteering_t bsteering = NULL;
    OS_GET_TIMER_ARG(ic, struct ieee80211com *);

    if (!ieee80211_bsteering_is_valid(ic)) {
        return;
    }

    bsteering = ic->ic_bsteering;
    spin_lock_bh(&bsteering->bs_lock);
    if (!ieee80211_bsteering_is_enabled(ic)) {
        spin_unlock_bh(&bsteering->bs_lock);
        return;
    }
    wlan_iterate_vap_list(ic, wlan_bsteering_measure_chan_util, bsteering);

    spin_unlock_bh(&bsteering->bs_lock);
}

/**
 * @brief Reset the utilization measurements for the next round of samples.
 *
 * @pre the caller should be holding the band steering spinlock
 *
 * @param [in] bsteering  the object to use for the reset
 */
static void ieee80211_bsteering_reset_chan_utilization(ieee80211_bsteering_t bsteering)
{
    bsteering->bs_chan_util_samples_sum = 0;
    bsteering->bs_chan_util_num_samples = 0;
    bsteering->bs_chan_util_requested = false;
}

/**
 * @brief Inform the band steering module of a channel utilization measurement.
 *
 * If the necessary number of utilization measurements have been obtained,
 * this will result in an event being generated.
 *
 * @param [in] vap  the VAP for which the utilization report occurred
 * @param [in] ieee_chan_num  the channel on which the utilization measurement
 *                            took place
 * @param [in] chan_utilization  the actual utilization measurement
 */

void ieee80211_bsteering_record_utilization(struct ieee80211vap *vap,
                                            u_int ieee_chan_num,
                                            u_int32_t chan_utilization)
{
#define MAX_CHANNEL_UTILIZATION 100
    ieee80211_bsteering_t bsteering = NULL;

    if (!ieee80211_bsteering_is_vap_enabled(vap) ||
        !ieee80211_bsteering_is_valid(vap->iv_ic)) {
        return;
    }

    bsteering = vap->iv_ic->ic_bsteering;

    do {
        spin_lock_bh(&bsteering->bs_lock);

        if (!ieee80211_bsteering_is_enabled(vap->iv_ic) ||
            !bsteering->bs_chan_util_requested ||
            !bsteering->bs_iv || bsteering->bs_iv != vap) {
            break;
        }

        if (ieee_chan_num == bsteering->bs_active_ieee_chan_num) {
            /* We have sometimes seen a channel utilization value greater than
               100%. The current suspicion is that the ACS module did not
               complete the scan properly and thus when it calls back into band
               steering, it is only providing a raw channel clear count instead
               of the computed percentage. This is possible because both the
               intermediate result and the final value are stored in the same
               value and by the time the scan event handler is called
               indicating completion, ACS does not know whether the value is
               the intermediate or final result.

               By checking for this, we force a new measurement to be taken
               in the off chance that this occurs. The real fix will be of
               course to determine why this is happening in ACS. */
            if (chan_utilization <= MAX_CHANNEL_UTILIZATION) {
                bsteering->bs_chan_util_samples_sum += chan_utilization;
                bsteering->bs_chan_util_num_samples++;

                if (bsteering->bs_dbg_config_params.raw_chan_util_log_enable) {
                    ieee80211_bsteering_send_utilization_event(vap,
                                                               chan_utilization,
                                                               true /* isDebug */);
                }

                /* If we have reached our desired number of samples, generate an
                   event with the average.*/
                if (bsteering->bs_chan_util_num_samples ==
                    bsteering->bs_config_params.utilization_average_num_samples) {
                    u_int8_t average = bsteering->bs_chan_util_samples_sum /
                        bsteering->bs_chan_util_num_samples;
                    ieee80211_bsteering_send_utilization_event(vap, average,
                                                               false /* isDebug */);

                    ieee80211_bsteering_reset_chan_utilization(bsteering);
                }
            } else {
                QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Ignoring invalid utilization %u on channel %u\n",
                       __func__, chan_utilization, ieee_chan_num);
            }

            bsteering->bs_chan_util_requested = false;
        }
    } while (0);

    spin_unlock_bh(&bsteering->bs_lock);
#undef MAX_CHANNEL_UTILIZATION
}

/**
 * @brief Called by the lower layer to inform the band steering module of an
 *        instantaneous RSSI measurement obtained by sending a Null Data
 *        Packet.
 *
 * If the necessary number of inst RSSI measurements have been obtained,
 * this will result in an event being generated.
 *
 * @param [in] ni  the node for which the RSSI measurement occurred
 * @param [in] rssi  the measured RSSI
 */

void ieee80211_bsteering_record_inst_rssi(struct ieee80211_node *ni, u_int8_t rssi)
{
    ieee80211_bsteering_t bsteering = NULL;
    bool generate_event = false;
    u_int8_t report_rssi = BSTEERING_INVALID_RSSI;

    if (!ni || !ieee80211_bsteering_is_vap_enabled(ni->ni_vap) ||
        !ieee80211_bsteering_is_valid(ni->ni_vap->iv_ic)) {
        return;
    }

    bsteering = ni->ni_vap->iv_ic->ic_bsteering;

    do {
        spin_lock_bh(&bsteering->bs_lock);
        if (!ieee80211_bsteering_is_enabled(ni->ni_vap->iv_ic)) {
            break;
        }

        if (!bsteering->bs_inst_rssi_inprogress ||
            memcmp(bsteering->bs_inst_rssi_macaddr, ni->ni_macaddr, IEEE80211_ADDR_LEN)) {
            /* The RSSI measurement is not for the one requested */
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Inst RSSI measurement for [%x] [%x] [%x] [%x] [%x] [%x] is %d \n",
                   bsteering->bs_inst_rssi_macaddr[0],bsteering->bs_inst_rssi_macaddr[1],bsteering->bs_inst_rssi_macaddr[2],
                   bsteering->bs_inst_rssi_macaddr[3],bsteering->bs_inst_rssi_macaddr[4],bsteering->bs_inst_rssi_macaddr[5],rssi);
            break;
        }

        if (BSTEERING_INVALID_RSSI != rssi) {
            bsteering->bs_avg_inst_rssi =
                ((bsteering->bs_avg_inst_rssi * bsteering->bs_inst_rssi_count) + rssi) /
                (bsteering->bs_inst_rssi_count + 1);
            ++bsteering->bs_inst_rssi_count;
            if (bsteering->bs_inst_rssi_count >= bsteering->bs_inst_rssi_num_samples) {
                generate_event = true;
                report_rssi = bsteering->bs_avg_inst_rssi;
            }
            /* It is important to update the value here as otherwise the threshold
               crossing logic will not work properly.
               The example scenario is:
               1. STA is active and average RSSI is above the crossing threshold.
               2. STA becomes inactive which triggers an instantaneous RSSI measuremnt,
               and the triggered measurement is below the threshold.
               3. Further updates to the average RSSI are above the threshold
               In this scenario, we want the RSSI update in step 3 to generate an RSSI
               crossing event. */
            ni->ni_bs_rssi = rssi;
        } else {
            ++bsteering->bs_inst_rssi_err_count;
            /* If we get twice as many failed samples as the number of samples
               requested, just give up and indicate a failure to measure the
               RSSI. */
            if (bsteering->bs_inst_rssi_err_count >= 2 * bsteering->bs_inst_rssi_num_samples) {
                generate_event = true;
            }
        }

        if (generate_event) {
            ieee80211_bsteering_send_rssi_measurement_event(ni->ni_vap, ni->ni_macaddr,
                                                            report_rssi, false /* is_debug */);
            OS_CANCEL_TIMER(&bsteering->bs_inst_rssi_timer);
            bsteering->bs_inst_rssi_inprogress = false;
            break;
        }

        /* More measurements are needed */
        wlan_send_rssi(ni->ni_vap, ni->ni_macaddr);

    } while (0);

    spin_unlock_bh(&bsteering->bs_lock);
}

/**
 * @brief Called by the lower layer to inform the band steering module of an
 *        invalid RSSI measurement when no ACK is received for the Null Data
 *        Packet.
 *
 * If the error count reaches the limit, an event will be generated with
 * rssi of BSTEERING_INVALID RSSI,
 *
 * @param [in] ni  the node for which the RSSI measurement occurred
 */

void ieee80211_bsteering_record_inst_rssi_err(struct ieee80211_node *ni)
{
    ieee80211_bsteering_record_inst_rssi(ni, BSTEERING_INVALID_RSSI);
}

/**
 * @brief Check if an RSSI measurement crossed the threshold
 *
 * @param [in] ni  the node for which the RSSI measurement occurred
 * @param [in] rssi  the measured RSSI
 * @param [in] low_threshold  the lower threshold to compare with
 * @param [in] high_threshold  the upper threshold to compare with
 *
 * @return the crossing direction as enumerated in BSTEERING_XING_DIRECTION
 */
static BSTEERING_XING_DIRECTION ieee80211_bsteering_check_rssi_cross_threshold(
    struct ieee80211_node *ni, u_int8_t rssi, u_int32_t low_threshold,
    u_int32_t high_threshold) {
    struct ieee80211com *ic = ni->ni_ic;
    u_int8_t delta;
    if (ic->ic_is_mode_offload(ic)){
        delta = 0; /* In offload the averaging of RSSI value is taken care of. So delta value is 0 */
    }else{
        delta = 2; /* The RSSI value at a particular position keeps toggling and the approx window size is 6.So the delta value is 2 */
    }
    if ((rssi < low_threshold && ni->ni_bs_rssi >= low_threshold) ||
        (rssi < high_threshold - delta && ni->ni_bs_rssi >= high_threshold - delta)) {
        return BSTEERING_XING_DOWN;
    } else if ((rssi > high_threshold + delta && ni->ni_bs_rssi <= high_threshold + delta) ||
               (rssi > low_threshold + delta && ni->ni_bs_rssi <= low_threshold + delta)) {
        return BSTEERING_XING_UP;
    }
    return BSTEERING_XING_UNCHANGED;
}

/**
 * @brief Called by the lower layer to inform the band steering module of an
 *        updated average RSSI measurement.
 *
 * If the RSSI measurement crossed the threshold, this will result in an event
 * being generated.
 *
 * @param [in] ni  the node for which the RSSI measurement occurred
 * @param [in] rssi  the measured RSSI
 */

void ieee80211_bsteering_record_rssi(struct ieee80211_node *ni, u_int8_t rssi)
{
    ieee80211_bsteering_t bsteering = NULL;
    BSTEERING_XING_DIRECTION inact_xing = BSTEERING_XING_UNCHANGED;
    BSTEERING_XING_DIRECTION low_xing = BSTEERING_XING_UNCHANGED;
    BSTEERING_XING_DIRECTION rate_xing = BSTEERING_XING_UNCHANGED;
    BSTEERING_XING_DIRECTION ap_xing = BSTEERING_XING_UNCHANGED;
    u_int32_t low_rate_rssi_threshold = 0;
    u_int32_t high_rate_rssi_threshold = 0;

    if (!ni || !ieee80211_bsteering_is_vap_enabled(ni->ni_vap) ||
        !ieee80211_bsteering_is_valid(ni->ni_vap->iv_ic)) {
        return;
    }

    bsteering = ni->ni_vap->iv_ic->ic_bsteering;

    do {
        spin_lock_bh(&bsteering->bs_lock);

        if (!ieee80211_bsteering_is_enabled(ni->ni_vap->iv_ic)) {
            break;
        }

        if (bsteering->bs_dbg_config_params.raw_rssi_log_enable) {
            ieee80211_bsteering_send_rssi_measurement_event(ni->ni_vap, ni->ni_macaddr,
                                                            rssi, true /* is_debug */);
        }

        low_rate_rssi_threshold =
            bsteering->bs_config_params.low_rate_rssi_crossing_threshold;

        high_rate_rssi_threshold =
            bsteering->bs_config_params.high_rate_rssi_crossing_threshold;

        if (!ni->ni_bs_rssi) {
            /* First RSSI measurement */
            /* Check if the RSSI starts above or below the rate threshold
               (STA will always be considered active at startup) */
            if (rssi < low_rate_rssi_threshold) {
                rate_xing = BSTEERING_XING_DOWN;
            } else if (rssi > high_rate_rssi_threshold) {
                rate_xing = BSTEERING_XING_UP;
            }
            break;
        }

        if (ni->ni_vap->iv_ic->ic_node_isinact(ni)) {
            /* Check inactivity rssi threshold crossing */
            inact_xing = ieee80211_bsteering_check_rssi_cross_threshold(
                             ni, rssi,
                             bsteering->bs_config_params.inactive_rssi_xing_low_threshold,
                             bsteering->bs_config_params.inactive_rssi_xing_high_threshold);
        } else {
            /* Check rate rssi thresold crossing */
            rate_xing = ieee80211_bsteering_check_rssi_cross_threshold(
                            ni, rssi, low_rate_rssi_threshold,
                            high_rate_rssi_threshold);
        }

        /* Check low rssi thresold crossing */
        low_xing = ieee80211_bsteering_check_rssi_cross_threshold(
                       ni, rssi, bsteering->bs_config_params.low_rssi_crossing_threshold,
                       BSTEER_INVALID_RSSI_HIGH_THRESHOLD);

        /* Check AP rssi threshold crossing */
        ap_xing = ieee80211_bsteering_check_rssi_cross_threshold(
                      ni, rssi,
                      bsteering->bs_config_params.ap_steer_rssi_xing_low_threshold,
                      BSTEER_INVALID_RSSI_HIGH_THRESHOLD);

    } while (0);

    if (inact_xing != BSTEERING_XING_UNCHANGED || low_xing != BSTEERING_XING_UNCHANGED ||
        rate_xing != BSTEERING_XING_UNCHANGED || ap_xing != BSTEERING_XING_UNCHANGED) {
        ieee80211_bsteering_send_rssi_xing_event(ni->ni_vap, ni->ni_macaddr, rssi,
                                                 inact_xing, low_xing, rate_xing, ap_xing);
    }

    ni->ni_bs_rssi = rssi;

    spin_unlock_bh(&bsteering->bs_lock);
}

/**
 * @brief Called when the Tx rate has changed, and determines if
 *        it has crossed a threshold.
 *
 * @param [in] ni  the node for which the Tx rate has changed
 * @param [in] tx_rate  the new Tx rate
 */
void ieee80211_bsteering_update_rate(struct ieee80211_node *ni,
                                     u_int32_t tx_rate) {
    ieee80211_bsteering_t bsteering = NULL;
    u_int32_t high_threshold, low_threshold;
    BSTEERING_XING_DIRECTION xing = BSTEERING_XING_UNCHANGED;

    if (!ni || !ieee80211_bsteering_is_vap_enabled(ni->ni_vap) ||
        !ieee80211_bsteering_is_valid(ni->ni_vap->iv_ic)) {
        return;
    }

    bsteering = ni->ni_vap->iv_ic->ic_bsteering;

    do {
        spin_lock_bh(&bsteering->bs_lock);

        if (!ieee80211_bsteering_is_enabled(ni->ni_vap->iv_ic)) {
            break;
        }

        if (bsteering->bs_dbg_config_params.raw_tx_rate_log_enable) {
            ieee80211_bsteering_send_tx_rate_measurement_event(ni->ni_vap, ni->ni_macaddr,
                                                               tx_rate);
        }

        low_threshold = bsteering->bs_config_params.low_tx_rate_crossing_threshold;
        high_threshold = bsteering->bs_config_params.high_tx_rate_crossing_threshold;

        if (!ni->ni_stats.ns_last_tx_rate) {
            /* First Tx rate measurement.  In this case, generate an event if
               the rate is above / below the threshold (since there is no history
               to check).  */
            if (tx_rate < low_threshold) {
                xing = BSTEERING_XING_DOWN;
            } else if (tx_rate > high_threshold) {
                xing = BSTEERING_XING_UP;
            }
            break;
        }

        /* Check thresold crossings */
        if (tx_rate < low_threshold &&
            ni->ni_stats.ns_last_tx_rate >= low_threshold) {
            xing = BSTEERING_XING_DOWN;
        } else if (tx_rate > high_threshold &&
                   ni->ni_stats.ns_last_tx_rate <= high_threshold) {
            xing = BSTEERING_XING_UP;
        }
    } while (0);

    if (xing != BSTEERING_XING_UNCHANGED) {
        ieee80211_bsteering_send_tx_rate_xing_event(ni->ni_vap, ni->ni_macaddr, tx_rate,
                                                    xing);
    }

    spin_unlock_bh(&bsteering->bs_lock);
}

/**
 * @brief Called when firmware stats are updated for a STA, with
 *        RSSI changed and a valid Tx rate
 *
 * @param [in] ni  the node for which the stats are updated
 * @param [in] current_vap  VAP for which stats up to this point
 *                          have been collected.  If it does not
 *                          match the VAP the current node is
 *                          on, should start message over so
 *                          each message is only STAs on a
 *                          particular VAP
 * @param [inout] sta_stats  the structure to update with STA
 *                           stats
 *
 * @return true if stats are updated, interference detection is
 *         enabled on the radio, and band steering is enabled on
 *         the VAP; false otherwise
 */
bool ieee80211_bsteering_update_sta_stats(
    const struct ieee80211_node *ni, const struct ieee80211vap *current_vap,
    struct bs_sta_stats_ind *sta_stats) {

    ieee80211_bsteering_t bsteering = NULL;
    bool updated_stats = false;

    if (!ni || !sta_stats ||
        !ieee80211_bsteering_is_vap_enabled(ni->ni_vap) ||
        !ieee80211_bsteering_is_valid(ni->ni_vap->iv_ic)) {
        return false;
    }

    bsteering = ni->ni_vap->iv_ic->ic_bsteering;

    do {
        spin_lock_bh(&bsteering->bs_lock);

        /* Interference detection must be enabled on the radio */
        if (!ieee80211_bsteering_is_enabled(ni->ni_vap->iv_ic) ||
            !bsteering->bs_config_params.interference_detection_enable) {
            break;
        }

        if ((current_vap && current_vap != ni->ni_vap) ||
            sta_stats->peer_count >= BSTEERING_MAX_PEERS_PER_EVENT) {
            /* Send the current message immediately, then start over */
            ieee80211_bsteering_send_sta_stats(current_vap, sta_stats);
            sta_stats->peer_count = 0;
        }

        OS_MEMCPY(sta_stats->peer_stats[sta_stats->peer_count].client_addr,
                  ni->ni_macaddr, IEEE80211_ADDR_LEN);
        sta_stats->peer_stats[sta_stats->peer_count].tx_rate =
            ni->ni_stats.ns_last_tx_rate;
        sta_stats->peer_stats[sta_stats->peer_count].tx_packet_count =
            ni->ni_stats.ns_tx_ucast;
        sta_stats->peer_stats[sta_stats->peer_count].rx_packet_count =
            ni->ni_stats.ns_rx_data;
        sta_stats->peer_stats[sta_stats->peer_count].tx_byte_count =
            ni->ni_stats.ns_tx_bytes_success;
        sta_stats->peer_stats[sta_stats->peer_count].rx_byte_count =
            ni->ni_stats.ns_rx_bytes;
        sta_stats->peer_stats[sta_stats->peer_count].rssi = ni->ni_rssi;
        sta_stats->peer_stats[sta_stats->peer_count].per = ni->ni_ald.ald_lastper;

        sta_stats->peer_count++;
        updated_stats = true;
    } while (0);

    spin_unlock_bh(&bsteering->bs_lock);

    return updated_stats;
}

/**
 * @brief Send STA stats to userspace via netlink message
 *
 * @param [in] vap  the first VAP on the radio for which STA
 *                  stats were updated
 * @param [in] sta_stats  the STA stats to send
 */
void ieee80211_bsteering_send_sta_stats(const struct ieee80211vap *vap,
                                        const struct bs_sta_stats_ind *sta_stats) {
    ATH_BSTEERING_EVENT event = ATH_EVENT_BSTEERING_STA_STATS;
    ieee80211_bsteering_t bsteering;

    if (!sta_stats || !sta_stats->peer_count || !vap) {
        /* No stats collected, nothing to send */
        return;
    }

    bsteering = vap->iv_ic->ic_bsteering;

    /* No need to do any checks here - should not have any updated stats unless
       band steering and interference detection are enabled */
    IEEE80211_DELIVER_BSTEERING_EVENT(vap, event, sizeof(struct bs_sta_stats_ind),
                                      (const char *)sta_stats);
}

/**
 * @brief Called when a VAP is stopped (this is only seen on a
 *        RE when the uplink STA interface is disassociated)
 *
 * @param [in] vap  VAP that has stopped
 */
void ieee80211_bsteering_send_vap_stop_event(struct ieee80211vap *vap) {
    ieee80211_bsteering_t bsteering = NULL;

    if (!ieee80211_bsteering_is_vap_enabled(vap) ||
        !ieee80211_bsteering_is_valid(vap->iv_ic)) {
        return;
    }

    bsteering = vap->iv_ic->ic_bsteering;

    spin_lock_bh(&bsteering->bs_lock);

    if (ieee80211_bsteering_is_enabled(vap->iv_ic)) {
        ATH_BSTEERING_EVENT event = ATH_EVENT_BSTEERING_VAP_STOP;

        /* No data to send with this event */
        IEEE80211_DELIVER_BSTEERING_EVENT(vap, event, 0, NULL);
    }

    spin_unlock_bh(&bsteering->bs_lock);
}

/**
 * @brief Generate an event when SM Power Save mode is updated for the given node
 *
 * @param [in] vap  the VAP on which the change occurred
 * @param [in] ni  the node whose SM Power Save mode changes
 * @param [in] is_static  whether the node is operating in Static SMPS mode
 */
void ieee80211_bsteering_send_node_smps_update_event(struct ieee80211vap *vap,
                                                     const struct ieee80211_node *ni,
                                                     u_int8_t is_static)
{
    ATH_BSTEERING_EVENT event = ATH_EVENT_BSTEERING_SMPS_UPDATE;
    struct bs_node_smps_update_ind smps_update;

    if(!ieee80211_bsteering_is_vap_enabled(vap) ||
       !ieee80211_bsteering_is_enabled(vap->iv_ic) || !ni) {
        return;
    }

    OS_MEMCPY(smps_update.client_addr, ni->ni_macaddr, IEEE80211_ADDR_LEN);
    smps_update.is_static = is_static;

    IEEE80211_DELIVER_BSTEERING_EVENT(vap, event, sizeof(struct bs_node_smps_update_ind),
                                      (const char *) &smps_update);
}

/**
 * @brief Generate an event when PHY capabilities are updated from OP_MODE IE
 *
 * @param [in] vap  the VAP on which the change occured
 * @param [in] ni  the node whose PHY capabilities are updated
 */
void ieee80211_bsteering_send_opmode_update_event(struct ieee80211vap *vap,
                                                  const struct ieee80211_node *ni) {
    ATH_BSTEERING_EVENT event = ATH_EVENT_BSTEERING_OPMODE_UPDATE;
    struct bs_node_opmode_update_ind opmode_update;

    if(!ieee80211_bsteering_is_vap_enabled(vap) ||
       !ieee80211_bsteering_is_enabled(vap->iv_ic) || !ni) {
        return;
    }

    OS_MEMCPY(opmode_update.client_addr, ni->ni_macaddr, IEEE80211_ADDR_LEN);
    /* Only channel width and number of spatial stream will be changed. */
    opmode_update.datarate_info.max_chwidth = ni->ni_chwidth;
    opmode_update.datarate_info.num_streams = ni->ni_streams;

    IEEE80211_DELIVER_BSTEERING_EVENT(vap, event, sizeof(struct bs_node_opmode_update_ind),
                                      (const char *) &opmode_update);
}

/**
 * @brief Timeout handler for inst RSSI measurement timer.
 *
 * Inst RSSI measurement has timed out at this point, should generate
 * an event with invalid RSSI value.
 *
 * @param [in] arg  ieee80211com
 *
 */

static OS_TIMER_FUNC(wlan_bsteering_inst_rssi_timeout_handler)
{
    struct ieee80211com *ic;
    ieee80211_bsteering_t bsteering = NULL;
    struct ieee80211_node *ni = NULL;
    OS_GET_TIMER_ARG(ic, struct ieee80211com *);

    if (!ieee80211_bsteering_is_valid(ic)) {
        return;
    }

    bsteering = ic->ic_bsteering;
    spin_lock_bh(&bsteering->bs_lock);

    do {
        if (!ieee80211_bsteering_is_enabled(ic)) {
            break;
        }

        if (!bsteering->bs_inst_rssi_inprogress) {
            break;
        }

        ni = ieee80211_find_node(&ic->ic_sta, bsteering->bs_inst_rssi_macaddr);
        if (ni) {
            ieee80211_bsteering_send_rssi_measurement_event(ni->ni_vap, ni->ni_macaddr,
                                                            BSTEERING_INVALID_RSSI,
                                                            false /* is_debug */);
            ieee80211_free_node(ni);
        } else {
            /* In case the node is deleted from node table before timeout,
               we still want to notify LBD of invalid RSSI.
               Send the event with first VAP on this radio. */
            struct ieee80211vap *_vap;
            struct ieee80211_node *bss_node = NULL;
            IEEE80211_COMM_LOCK(ic);
            TAILQ_FOREACH(_vap, &ic->ic_vaps, iv_next) {
                if (ieee80211_bsteering_is_vap_enabled(_vap)) {
                    bss_node = ieee80211_ref_bss_node(_vap);
                    break;
                }
            }
            IEEE80211_COMM_UNLOCK(ic);
            if (bss_node) {
                ieee80211_bsteering_send_rssi_measurement_event(
                                                                bss_node->ni_vap, bsteering->bs_inst_rssi_macaddr,
                                                                BSTEERING_INVALID_RSSI, false /* is_debug */);
                ieee80211_free_node(bss_node);
            }
            /* If no VAP is band steering enabled on this band, it probably means
               band steering feature has been disabled. So we can live with not
               sending an RSSI measurement event since no one will be interested. */
        }

        bsteering->bs_inst_rssi_inprogress = false;

        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Inst RSSI measurement request for STA "
               "%02x:%02x:%02x:%02x:%02x:%02x timeout.\n",
               __func__, bsteering->bs_inst_rssi_macaddr[0],
               bsteering->bs_inst_rssi_macaddr[1],
               bsteering->bs_inst_rssi_macaddr[2],
               bsteering->bs_inst_rssi_macaddr[3],
               bsteering->bs_inst_rssi_macaddr[4],
               bsteering->bs_inst_rssi_macaddr[5]);
    } while (0);

    spin_unlock_bh(&bsteering->bs_lock);
}
#endif
