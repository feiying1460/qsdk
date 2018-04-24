/*
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 */

#ifndef _UMAC_IEEE80211_BAND_STEERING__
#define _UMAC_IEEE80211_BAND_STEERING__

/*opaque handle in ic structure */
typedef struct ieee80211_bsteering    *ieee80211_bsteering_t;

// forward decls
struct ieee80211vap;
struct ieee80211com;
struct ieee80211req_athdbg;
typedef struct ieee80211_bcnrpt_s ieee80211_bcnrpt_t;

#if ATH_BAND_STEERING
#define INST_STATS_INVALID_RSSI 0
#define INST_STATS_VALID_RSSI_MAX 127

/**
 * @brief Initialize the band steering infrastructure.
 *
 * @param [in] ic  the radio on which to initialize
 *
 * @return EOK on success; EINPROGRESS if band steering is already initialized
 *         or ENOMEM on a memory allocation failure
 */
int ieee80211_bsteering_attach(struct ieee80211com *ic);

/**
 * @brief Destroy the band steering infrastructure.
 *
 * @param [in] ic  the radio for which to destroy
 *
 * @return EOK on success; any other value for an error
 */
int ieee80211_bsteering_detach(struct ieee80211com *ic);

/**
 * @brief Set the band steering parameters.
 *
 * This can only be done when band steering is disabled. The parameters
 * include timer values and thresholds for RSSI reporting.
 *
 * @param [in] vap  the VAP on which the set operation was done
 * @param [in] req  the parameters to be set
 *
 * @return EOK for success and EINVAL for error cases
 */
int wlan_bsteering_set_params(struct ieee80211vap *vap,
                              struct ieee80211req_athdbg *req);

/**
 * @brief Get the band steering parameters.
 *
 * The parameters include timer values and thresholds for RSSI reporting.
 *
 * @param [in] vap  the VAP on which the get operation was done
 * @param [in] req  the parameters to be retrieved
 *
 * @return EOK for success and EINVAL for error cases
 */
int wlan_bsteering_get_params(const struct ieee80211vap *vap,
                              struct ieee80211req_athdbg *req);

/**
 * @brief Set the parameters that control whether debugging events are
 *        generated or not.
 *
 * @param [in] vap  the VAP on which the request came in
 * @param [in] req  the actual request parameters containing the new values
 *
 * @return EOK for success and EINVAL for error cases
 */
int wlan_bsteering_set_dbg_params(struct ieee80211vap *vap,
                                  const struct ieee80211req_athdbg *req);

/**
 * @brief Get the parameters that control whether debugging events are
 *        generated or not.
 *
 * @param [in] vap  the VAP on which the request came in
 * @param [out] req  the object to update with the current debugging parameters
 */
int wlan_bsteering_get_dbg_params(const struct ieee80211vap *vap,
                                  struct ieee80211req_athdbg *req);

/**
 * @brief Generate an event indicating that a probe request was received.
 *
 * @param [in] vap  the VAP on which the probe was received
 * @param [in] mac_addr  the MAC address of the client that sent the probe
 *                       request
 * @param [in] rssi  the RSSI of the received probe request
 */
void ieee80211_bsteering_send_probereq_event(
                                             struct ieee80211vap *vap, const u_int8_t *mac_addr, u_int8_t rssi);

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
                                          const u_int8_t *mac_addr);

/**
 * @brief Query the band steering module for whether it is withholding
 *        probe responses for the given MAC address on this 2.4G VAP.
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
                                          u_int8_t sta_rssi);

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
void ieee80211_bsteering_send_auth_fail_event(
                                              struct ieee80211vap *vap, const u_int8_t *mac_addr, u_int8_t rssi);

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
void ieee80211_bsteering_send_auth_allow_event(
                                               struct ieee80211vap *vap, const u_int8_t *mac_addr, u_int8_t rssi);

/**
 * @brief Inform the band steering module that a node is now 
 *        associated.
 *
 * @param [in] vap  the VAP on which the change occurred
 * @param [in] ni  the node who associated
 */
void ieee80211_bsteering_send_node_associated_event(struct ieee80211vap *vap,
                                                    const struct ieee80211_node *ni);

/**
 * @brief Toggle a VAP's overloaded status
 *
 * @param [inout] vap  the VAP whose overload status changes
 * @param [in] req  request from user space containing the flag indicating overload or not
 *
 * @return EOK if overload status is set, otherwise return EINVAL
 */
int wlan_bsteering_set_overload(struct ieee80211vap *vap,
                                const struct ieee80211req_athdbg *req);

/**
 * @brief Retrieve a VAP's overloaded status
 *
 * @param [in] vap  the VAP whose overload status to retrieve
 * @param [out] req  the object to update with the current overload status
 *
 * @return EOK if overload status is retrieved successfully, otherwise return EINVAL
 */
int wlan_bsteering_get_overload(const struct ieee80211vap *vap,
                                struct ieee80211req_athdbg *req);

/**
 * @brief Enable/Disable band steering on a VAP
 *
 * @pre  wlan_bsteering_set_params must be called
 *
 * @param [inout] vap  the VAP whose band steering status changes
 * @param [in] req  request from user space containing the flag indicating enable or disable
 *
 * @return EINVAL if band steering not initialized, otherwise
 *         return EOK
 */
int wlan_bsteering_enable(struct ieee80211vap *vap,
                          const struct ieee80211req_athdbg *req);

/**
 * @brief Enable/Disable band steering events on a VAP
 *
 * @pre  wlan_bsteering_enable must be called
 *
 * @param [inout] vap  the VAP whose band steering status
 *                     changes
 * @param [in] req request from user space containing the flag
 *                 indicating enable or disable
 *
 * @return EINVAL if band steering not initialized or enabled on
 *         the radio, EALREADY if band steering on the VAP is
 *         already in the requested state, otherwise return EOK
 */
int wlan_bsteering_enable_events(struct ieee80211vap *vap,
                                 const struct ieee80211req_athdbg *req);

/**
 * @brief Start RSSI measurement on a specific station
 *
 * @param [in] vap  the VAP to start RSSI measurement
 * @param [in] req  request from user space containing the station MAC address and
 *                  number of measurements to average before reporting back
 *
 * @return EINVAL if band steering not initialized; EBUSY if the previous measurement is not done;
 *         otherwise return EOK
 */
int wlan_bsteering_trigger_rssi_measurement(struct ieee80211vap *vap,
                                            const struct ieee80211req_athdbg *req);

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
                                     const struct ieee80211req_athdbg *req);

/**
 * @brief Query whether probe responses are being withheld for a given
 *        MAC or not.
 *
 * Even if this indicates that responses are being withheld for this MAC,
 * they will only actually be withheld if band steering is enabled.
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
                                     struct ieee80211req_athdbg *req);

/**
 * @brief Update whether authentication should be allowed for a given
 *        MAC or not.
 *
 * Auth is allowed/disallowed only if Auth_allow flag is set/cleared.
 *
 * @pre The MAC must currently be in the ACL list for this to succeed.
 *
 * @param [in] vap  the VAP for which to change the value
 * @param [inout] req  request from user space containing the station MAC
 *                  address and whether to allow or disallow
 *                  authentication
 *
 * @return EINVAL if the request is malformed; otherwise EOK
 */
int wlan_bsteering_set_auth_allow(struct ieee80211vap *vap,
                                          const struct ieee80211req_athdbg *req);

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
                                     const struct ieee80211req_athdbg *req);

/**
 * @brief Mark a node's inactivity status in band steering context
 *
 * @param [inout] ni  The node to update
 * @param [in] inact flag indicating inactive or not
 */

void ieee80211_bsteering_mark_node_bs_inact(struct ieee80211_node *ni, bool inact);

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
                                     struct ieee80211req_athdbg *req);

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
                                struct ieee80211req_athdbg *req);

/**
 * @brief Update the timer interval duration for DA stats
 *
 * @param [in] vap  the VAP for which to change the value
 * @param [in] req  request from user space containing the parameters
 *
 * @return EINVAL if the request is malformed; otherwise EOK
 */
int wlan_bsteering_set_sta_stats_interval_da(struct ieee80211vap *vap,
                                             struct ieee80211req_athdbg *req);

/**
 * @brief Record a node's activity status change
 *
 * @param [in] ic  the radio on which the node is associated
 * @param [in] mac_addr  the MAC address of the node
 * @param [in] active  true if the node becomes active;
 *                     false if it becomes inactive
 */
void ieee80211_bsteering_record_act_change(struct ieee80211com *ic,
                                           const u_int8_t *mac_addr,
                                           bool active);

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
                                            u_int32_t chan_utilization);

/**
 * @brief Inform the band steering module of a RSSI measurement.
 *
 * If the RSSI measurement crossed the threshold, this will result in an event
 * being generated.
 *
 * @param [in] ni  the node for which the RSSI measurement occurred
 * @param [in] rssi  the measured RSSI
 */
void ieee80211_bsteering_record_rssi(struct ieee80211_node *ni,
                                     u_int8_t rssi);

/**
 * @brief Called when the Tx rate has changed, and determines if
 *        it has crossed a threshold.
 *
 * @param [in] ni  the node for which the Tx rate has changed
 * @param [in] tx_rate  the new Tx rate
 */
void ieee80211_bsteering_update_rate(struct ieee80211_node *ni,
                                     u_int32_t tx_rate);

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
    struct bs_sta_stats_ind *sta_stats);

/**
 * @brief Send STA stats to userspace via netlink message
 *
 * @param [in] vap  the first VAP on the radio for which STA
 *                  stats were updated
 * @param [in] sta_stats  the STA stats to send
 */
void ieee80211_bsteering_send_sta_stats(const struct ieee80211vap *vap,
                                        const struct bs_sta_stats_ind *sta_stats);

/**
 * @brief Called when a VAP is stopped (this is only seen on a
 *        RE when the uplink STA interface is disassociated)
 *
 * @param [in] vap  VAP that has stopped
 */
void ieee80211_bsteering_send_vap_stop_event(struct ieee80211vap *vap);

/**
 * @brief Inform the band steering module of an inst RSSI measurement obtained by
 *        sending Null Data Packet
 *
 * If the necessary number of inst RSSI measurements have been obtained,
 * this will result in an event being generated.
 *
 * @param [in] ni  the node for which the RSSI measurement occurred
 * @param [in] rssi  the measured RSSI
 */
void ieee80211_bsteering_record_inst_rssi(struct ieee80211_node *ni,
                                          u_int8_t rssi);
/**
 * @brief Inform the band steering module of an invalid RSSI measurement when
 *        retrying sending Null Data Packet reaches limit
 *
 * If the error count reaches the limit, an event will be generated with
 * rssi of BSTEERING_INVALID RSSI,
 *
 * @param [in] ni  the node for which the RSSI measurement occurred
 */
void ieee80211_bsteering_record_inst_rssi_err(struct ieee80211_node *ni);

/**
 * @brief used for direct attach to inform band steering module for node rssi
 * @param [in] mac address of reporting node
 * @param [in] status , success or failure
 * @param [in] rssi , rssi of node
 */

void ieee80211_bsteering_direct_attach_rssi_update(struct ieee80211com *ic,
                                                   u_int8_t *macaddress,
                                                   u_int8_t status,
                                                   int8_t rssi,
                                                   u_int8_t subtype);
/**
 * @brief used for direct attach to inform band steering module for node rssi
 * @param [in] mac address of reporting node
 * @param [in] status , success or failure
 * @param [in] txrateKbps , rate in Kbps of node
 */

void ieee80211_bsteering_direct_attach_txrate_update(struct ieee80211com *ic,
                                                     u_int8_t *macaddress,
                                                     u_int8_t status,
                                                     u_int32_t txrateKbps);

/**
 * @brief Notify band steering when an error RRM beacon report response is received
 *
 * It will generate a netlink event with error status if band steering is enabled.
 *
 * @param [in] vap  the VAP on which the report is received
 * @param [in] token  the dialog token matching the one provided in the request
 * @param [in] macaddr  the MAC address of the reporter station
 * @param [in] mode  the measurement report mode contained in the response
 */
void ieee80211_bsteering_send_rrm_bcnrpt_error_event(
        struct ieee80211vap *vap, u_int32_t token, u_int8_t *macaddr,
        u_int8_t mode);

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
                                              ieee80211_bcnrpt_t **reports);

/**
 * @brief Free the allocated memory for RRM beacon reports
 *
 * @param [inout] reports  the memory to be freed
 */
void ieee80211_bsteering_dealloc_rrm_bcnrpt(ieee80211_bcnrpt_t **reports);

/**
 * @brief Generate an event when beacon report response is received
 *
 * It will generate a netlink event if at lease one report is received, and
 * the beacon report memory will be wiped out for further reports.
 *
 * @param [in] vap  the VAP on which the report is received
 * @param [in] token  the dialog token matching the one provided in the request
 * @param [in] macaddr  the MAC address of the reporter station
 * @param [inout] bcnrpt  the beacon report(s) received
 * @param [in] num_bcnrpt  number of the beacon report(s) to send
 */
void ieee80211_bsteering_send_rrm_bcnrpt_event(struct ieee80211vap *vap, u_int32_t token,
                                               u_int8_t *macaddr, ieee80211_bcnrpt_t *bcnrpt,
                                               u_int8_t num_bcnrpt);

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
                                                  struct bs_wnm_bstm_resp *bstm_resp);

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
bool ieee80211_bsteering_is_vap_enabled(const struct ieee80211vap *vap);

/**
 * @brief Generate an event when Tx power change on a VAP
 *
 * @param [in] vap  the VAP on which Tx power changes
 * @param [in] tx_power  the new Tx power
 */
void ieee80211_bsteering_send_txpower_change_event(struct ieee80211vap *vap,
                                                   u_int16_t tx_power);

/**
 * @brief Generate an event when SM Power Save mode is updated for the given node
 *
 * @param [in] vap  the VAP on which the change occurred
 * @param [in] ni  the node whose SM Power Save mode changes
 * @param [in] is_static  whether the node is operating in Static SMPS mode
 */
void ieee80211_bsteering_send_node_smps_update_event(struct ieee80211vap *vap,
                                                     const struct ieee80211_node *ni,
                                                     u_int8_t is_static);

/**
 * @brief Generate an event when PHY capabilities are updated from OP_MODE IE
 *
 * @param [in] vap  the VAP on which the change occured
 * @param [in] ni  the node whose PHY capabilities are updated
 */
void ieee80211_bsteering_send_opmode_update_event(struct ieee80211vap *vap,
                                                  const struct ieee80211_node *ni);

#else

// Stub functions that return error codes to the band steering ioctls.

static inline int wlan_bsteering_set_params(struct ieee80211vap *vap,
                                            struct ieee80211req_athdbg *req)
{
    return -EINVAL;
}

static inline int wlan_bsteering_get_params(const struct ieee80211vap *vap,
                                            struct ieee80211req_athdbg *req)
{
    return -EINVAL;
}

static inline int wlan_bsteering_set_dbg_params(struct ieee80211vap *vap,
                                                const struct ieee80211req_athdbg *req)
{
    return -EINVAL;
}

static inline int wlan_bsteering_get_dbg_params(const struct ieee80211vap *vap,
                                                struct ieee80211req_athdbg *req)
{
    return -EINVAL;
}

static inline int wlan_bsteering_set_overload(struct ieee80211vap *vap,
                                              const struct ieee80211req_athdbg *req)
{
    return -EINVAL;
}

static inline int wlan_bsteering_get_overload(const struct ieee80211vap *vap,
                                              struct ieee80211req_athdbg *req)
{
    return -EINVAL;
}

static inline int wlan_bsteering_enable(struct ieee80211vap *vap,
                                        const struct ieee80211req_athdbg *req)
{
    return -EINVAL;
}

static inline int wlan_bsteering_enable_events(struct ieee80211vap *vap,
                                               const struct ieee80211req_athdbg *req)
{
    return -EINVAL;
}

static inline int wlan_bsteering_trigger_rssi_measurement(struct ieee80211vap *vap,
                                                          const struct ieee80211req_athdbg *req)
{
    return -EINVAL;
}

static inline int wlan_bsteering_set_probe_resp_wh(struct ieee80211vap *vap,
                                                   const struct ieee80211req_athdbg *req)
{
    return -EINVAL;
}

static inline int wlan_bsteering_get_probe_resp_wh(struct ieee80211vap *vap,
                                                   struct ieee80211req_athdbg *req)
{
    return -EINVAL;
}

static inline int wlan_bsteering_set_auth_allow(struct ieee80211vap *vap,
                                                const struct ieee80211req_athdbg *req)
{
    return -EINVAL;
}

static inline int wlan_bsteering_set_probe_resp_allow_24g(struct ieee80211vap *vap,
                                                   const struct ieee80211req_athdbg *req)
{
    return -EINVAL;
}

static inline void ieee80211_bsteering_direct_attach_rssi_update(struct ieee80211com *ic,
                                                                 u_int8_t *macaddress,
                                                                 u_int8_t status,int8_t rssi,u_int8_t subtype)
{
    return;
}

static inline void ieee80211_bsteering_direct_attach_txrate_update(struct ieee80211com *ic,
                                                     u_int8_t *macaddress, u_int8_t status,
                                                                          u_int32_t txrateKbps)
{
    return;
}

static inline int wlan_bsteering_get_datarate_info(struct ieee80211vap *vap,
                                                   struct ieee80211req_athdbg *req)
{
    return -EINVAL;
}

static inline int wlan_bsteering_set_steering(struct ieee80211vap *vap,
                                              struct ieee80211req_athdbg *req)
{
    return -EINVAL;
}

static inline int wlan_bsteering_set_sta_stats_interval_da(struct ieee80211vap *vap,
                                                           struct ieee80211req_athdbg *req)
{
    return -EINVAL;
}

static inline bool ieee80211_bsteering_is_vap_enabled(const struct ieee80211vap *vap)
{
    return false;
}

static inline void ieee80211_bsteering_send_vap_stop_event(struct ieee80211vap *vap)
{
    return;
}
#endif /* ATH_BAND_STEERING */

#endif /* _UMAC_IEEE80211_BAND_STEERING__ */
