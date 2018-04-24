/*
 * Copyright (c) 2008, Atheros Communications Inc.
 * All Rights Reserved.
 *
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#ifndef _IEEE80211_API_H_
#define _IEEE80211_API_H_

/*
 * @file ieee80211_api.h
 * Public Interface for Atheros Upper MAC Layer
 */

#include <osdep_internal.h>
#include <wbuf.h>
#include <_ieee80211.h>
#include <ieee80211_defines.h>
#include <ieee80211_ioctl.h>

typedef void (* ieee80211_vap_iter_func) (void *, wlan_if_t);

typedef wlan_action_frame_complete_handler wlan_vap_complete_buf_handler;

/**
 * iterates through the list of vaps.
 * @param  devhandle  : handle to the dev.
 * @param  iter_func  : iterator function called for each vap. can be NULL.
 * @param  arg        : arg to be passed back to iterator function.
 *
 * @return       number of  vaps.
 */
u_int32_t wlan_iterate_vap_list(wlan_dev_t vaphandle,ieee80211_vap_iter_func iter_func,void *arg);


/**
 * get the HW capabilities
 * @param devhandle : device handle
 * @param cap       : HW capability.
 * @return the value of HW capabily
 */
u_int32_t wlan_get_HWcapabilities(wlan_dev_t devhandle, ieee80211_cap cap);

/**
 * register event handler table with device
 *
 *  @param devhandle      : handle to th dev.
 *  @param event_arg      : opaque pointer delivered back via the event handlers.
 *  @param evtable        : event handler table.
 *  @return 0  on success and -ve on failure.
 */
int wlan_device_register_event_handlers(wlan_dev_t devhandle,
                                     void *event_arg,
                                     wlan_dev_event_handler_table *evtable);

/**
 * unregister event handler table with device
 *
 * @param devhandle       : handle to th dev.
 * @param event_arg       : opaque pointer delivered back via the event handlers.
 * @param evtable         : event handler table.
 * @return  0  on success and -ve on failure.
 */
int wlan_device_unregister_event_handlers(wlan_dev_t devhandle,
                                     void *event_arg,
                                     wlan_dev_event_handler_table *evtable);
/**
 * set simple configuration parameter.
 *
 * @param devhandle       : handle to the vap.
 * @param param           : simple config paramaeter.
 * @param val             : value of the parameter.
 * @return 0  on success and -ve on failure.
 */
int wlan_set_device_param(wlan_dev_t devhandle, ieee80211_device_param param, u_int32_t val);

/**
 * get simple configuration parameter.
 *
 * @param devhandle       : handle to the vap.
 * @param param           : simple config paramaeter.
 * @return value of the parameter.
 */
u_int32_t wlan_get_device_param(wlan_dev_t devhandle, ieee80211_device_param param);

/**
 * print a debug message
 *
 * @param devhandle       : handle to the device.
 * @param fmt             : printf format followed by args.
 */
void wlan_device_note(wlan_dev_t devhandle, const char *fmt, ...);

/**
 * count the number of VAPs of each type supported by an IC
 *
 * @param devhandle        : handle to the IC device.
 * @param vap_opmode_count : pointer to data structure where the total number
 *                           of VAPs of each type is returned.
 */
void wlan_get_vap_opmode_count(wlan_dev_t devhandle,
                               struct ieee80211_vap_opmode_count *vap_opmode_count);

/**
 * print a debug message
 *
 * @param vaphandle       : handle to the vap.
 * @param fmt             : printf format followed by args.
 */
void wlan_vap_note(wlan_if_t vaphandle, const char *fmt, ...);

/**
 * print a debug message
 *
 * @param devhandle       : handle to the device.
 * @param fmt             : printf format followed by args.
 */
void wlan_device_note(wlan_dev_t devhandle, const char *fmt, ...);

/**
* return  mac address of the device (also the mac address of the first vap) .
*
* @param devhandle     : handle to the radio .
* @param mac_addr      : address where the mac_addr is copied to (caller owns the memory).
* @returns EOK if successful .
*/
int wlan_get_device_mac_addr(wlan_dev_t devhandle, u_int8_t *bssid);

/**
* preallocate a new mac address to be used for wlan_vap_create as bssid argument.
*
* @param devhandle     : handle to the radio .
* @param bssid         : specific mac address requested by the caller
                        (or) mac address copied by the driver (caller owns the memory).
* @returns EOK if successful .
* if the caller passes a specific mac address (note that caller can not allocate an arbitary mac address,
*  thew address has to match with the internal mac allocation scheme), then driver allocates the specied
* mac address. if the caller passes 00:00:00:00:00:00 mac address then the driver alloactes one that is
* available.
* The caller can later create a VAP with the allocated mac address using wlan_vap_create and passing the
* allocated mac dddress as the bssid argument (last argument).
*/
int wlan_vap_allocate_mac_addr(wlan_dev_t devhandle, u_int8_t *bssid);


/**
* free mac address allocated by the wlan_vap_allocate_mac_addr.
*
* @param devhandle     : handle to the radio .
* @param bssid         : address where the bssid is copied to (caller owns the memory).
* @returns EOK if successful .
* a mac addrees can only be freed if no vap is created with the macaddr.
* once a vap is created with the allocated macaddr the mac address will be freed
* automalically when the vap is deleted.
*/
int wlan_vap_free_mac_addr(wlan_dev_t devhandle, u_int8_t *bssid);

/**
 * creates a new vap with the given mode and flags.
 * @param devhandle          : handle to the radio .
 * @param opmode             : opmode of the vap
 * @param scan_priority_base : Base priority for scans requested by this VAP.
 *                             The scan scheduler uses the VAP type, this base
 *                             priority and the relative priority (low, medium,
 *                             high, etc.) specified in the scan request to
 *                             determine the absolute priority.
 * @param flags              : flags as defined above.
 * @param bssid              : bssid of the new vap created. only valid if opmode is IEEE80211_M_WDS.
 * @param mataddr            : MAT (MAC address translation) addr of the new vap created.
 *                             only valid if flags is IEEE80211_CLONE_MATADDR.
 *
 * @return  on success return an opaque handle to newly created vap.
 *          on failure returns NULL.
 */
wlan_if_t wlan_vap_create(wlan_dev_t            devhandle,
                          enum ieee80211_opmode opmode,
                          int                   scan_priority_base,
                          u_int32_t             flags,
                          u_int8_t              *bssid,
                          u_int8_t              *mataddr,
                          void                  *osifp_handle);

/**
 * delete a vap.
 * @param vaphandle : handle to the vap .
 *
 * @return on success returns 0.
 *         on failure returns a negative value.
 */
int wlan_vap_delete(wlan_if_t vaphandle);

/**
 * recover a vap.
 * @param vaphandle : handle to the vap .
 *
 * @return on success returns 0.
 *         on failure returns a negative value.
 */
int wlan_vap_recover(wlan_if_t vaphandle);

void wlan_stop(struct ieee80211com *ic);

void ic_sta_vap_update(struct ieee80211com *ic, struct ieee80211vap *vap);
void ic_mon_vap_update(struct ieee80211com *ic, struct ieee80211vap *vap);

/**
 * return vap create flags.
 * @param vaphandle : handle to the vap .
 *
 * @return flags passed at creation time.
 */
int wlan_vap_create_flags(wlan_if_t vaphandle);


/**
 * set the os handle to be used for event  handler functions
 *  registreed using wlan_vap_register_event_handlers.
 *
 *  @param vaphandle  : handle to the vap .
 *  @param os_iface   : handle to the os interface .
 */
void wlan_vap_set_registered_handle(wlan_if_t vaphandle, os_if_t os_iface);

/**
 * get the os_if_t handle registered using the
 *    wlan_vap_register_event_handlers function.
 *
 *  @param vaphandle  : handle to the vap .
 *  @return    os interface handle.
 */
os_if_t wlan_vap_get_registered_handle(wlan_if_t vaphandle);

/**
 * register event handler table with a vap.
 *  @param vaphandle        : handle to the vap .
 *  @param evtable          : table of handlers to receive 802.11 events.
 *                            if table is NULL it unregisters the previously registered
 *                            handlers. returns an error if handler table is registered
 *                            already. Note that the caller owns the memory of the even table structure.
 *                            caller should not deallocate memory while it is registered wit the vap.
 * @return  on success return 0.
 *          on failure returns -1.
 */
int wlan_vap_register_event_handlers(wlan_if_t vaphandle,
                                     wlan_event_handler_table *evtable);


/**
 * register mlme event handler table with a vap.
 * @param vaphande          : handle to the vap .
 * @param oshandle          : handle opaque to the implementor.
 * @evtable                 : table of handlers to receive 802.11 mlme events.
 *                            if table is NULL it unregisters the previously registered
 *                            handlers. returns an error if handler table is registered
 *                            already. Note that the caller owns the memory of the even table structure.
 *                            caller should not deallocate memory while it is registered wit the vap.
 * @return on success return 0.
 *         on failure returns -1.
 */
int wlan_vap_register_mlme_event_handlers(wlan_if_t vaphandle,
                                          os_handle_t oshandle,
                                          wlan_mlme_event_handler_table *evtable);

/**
 * unregister a mlme event handler.
 *
 *  @param vaphandle             : handle to the vap .
 *  @param oshandle              : handle opaque to the implementor.
 *  @param evtable               : table of misc handlers to be unregistred.
 *  @return   on success returns 0.
 *            on failure returns a negative value.
 */
int wlan_vap_unregister_mlme_event_handlers(wlan_if_t  vaphandle, os_handle_t oshandle,
                                       wlan_mlme_event_handler_table *evtable);

/**
 * register misc event handler table with a vap.
 * This API allows multiple modules to register thier own event handler tables.

 * @param vaphandle             : handle to the vap .
 * @param oshandle              : handle opaque to the implementor.
 * @param evtable               : table of misc handlers to receive 802.11 misc events.
 *                                Note that the caller owns the memory of the even table structure.
 *                                caller should not deallocate memory while it is registered with the vap.
 * @return
 *  on success return 0.
 *  on failure returns -1.
 *  returns an error if handler table is registered already.
 */
int wlan_vap_register_misc_event_handlers(wlan_if_t vaphandle,
                                          os_handle_t oshandle,
                                          wlan_misc_event_handler_table *evtable);

/**
 * unregister a misc event handler.
 *
 *  @param vaphandle             : handle to the vap .
 *  @param oshandle              : handle opaque to the implementor.
 *  @param evtable               : table of misc handlers to be unregistred.
 *  @return   on success returns 0.
 *            on failure returns a negative value.
 */
int wlan_vap_unregister_misc_event_handlers(wlan_if_t  vaphandle, os_handle_t oshandle,
                                       wlan_misc_event_handler_table *evtable);

/**
 * @register ccx handler table with a vap.
 * ARGS :
 *  wlan_if_t               : handle to the vap .
 *  os_if_t                 : handle opaque to the implementor.
 *  wlan_ccx_handler        : table of ccx handlers to receive notification or service.
 *                            returns an error if handler table is registered
 *                            already. Note that the caller owns the memory of the even table structure.
 *                            caller should not deallocate memory while it is registered with the vap.
 * This API allows multiple modules to register thier own event handler tables.
 * RETURNS:
 *  on success return 0.
 *  on failure returns -1.
 */
int wlan_vap_register_ccx_event_handlers(wlan_if_t vaphandle,
                                          os_if_t,
                                          wlan_ccx_handler_table *evtable);

/**
 * send a data packet on vap.
 *  @param vaphandle : handle to the vap .
 *  @param wbuf      : wbuf to send.
 *
 *  @return
 *  on success returns 0.
 *  on failure returns a negative value.
 *  in case of failure it is the responsibility of the caller to free the wbuf.
 *
 */
int wlan_vap_send(wlan_if_t vaphandle, wbuf_t wbuf);

/**
* send action management frame.
* @param freq     : channel to send on (only to validate/match with current channel)
* @param arg      : arg (will be used in the mlme_action_send_complete)
* @param dst_addr : destination mac address
* @param src_addr : source address.(most of the cases vap mac address).
* @param bssid    : BSSID or %NULL to use default
* @param data     : includes total payload of the action management frame.
* @param data_len : data len.
* @returns 0 if succesful and -ve if failed.
* if the radio is not on the passedf in freq then it will return an error.
* if returns 0 then mlme_action_send_complete will be called with the status of
* the frame transmission.
*/
int wlan_vap_send_action_frame(wlan_if_t vap_handle, u_int32_t freq,
                               wlan_action_frame_complete_handler handler,void *arg,
                               const u_int8_t *dst_addr, const u_int8_t *src_addr,
                               const u_int8_t *bssid,
                               const u_int8_t *data, u_int32_t data_len);

/**
 * check vap bss PMF enabled or not.
 *  @param vaphandle : handle to the vap .
 *
 *  @return
 *   returns 1 if enabled else 0.
 *
 */
bool wlan_vap_is_pmf_enabled(wlan_if_t vaphandle);

/**
 * get offload data handle for vap.
 *  @param vaphandle : handle to the vap .
 *
 *  @return opaque handle to offload data path.
 *   returns NULL if the chip is not offload capable.
 *   the offload capability of the HW can be checked by querying
 *   the capability IEEE80211_CAP_PERF_PWR_OFLD using the
 *   wlan_get_HWcapabilities API.
 *
 *
 */
void *wlan_vap_get_ol_data_handle(wlan_if_t vaphandle);

/**
 * dump all the nodes allocated for Debugging only).
 * @param devhandle                   : dev handle to the com  device .
 */
void wlan_dump_alloc_nodes(wlan_dev_t devhandle);

/**
 * get a unique scan requestor id to identify modules interacting with the scanner.
 *  @param vaphandle         : handle to the vap .
 *  @parma module_name       : name of the module (useful for debugging).
 *  @param requestor         : param to return the unique requestor id.
 * @return
 *  on success returns 0.
 *  on failure returns a negative value.
 */
int wlan_scan_get_requestor_id( wlan_if_t                vaphandle,
                                u_int8_t                 *module_name,
                                IEEE80211_SCAN_REQUESTOR *requestor);

/**
 * clear allocated scan requestor id.
 * @param vaphandle          : handle to the vap.
 * @param requestor          : requestor id to be cleared.
 */
void wlan_scan_clear_requestor_id(wlan_if_t                vaphandle,
                                  IEEE80211_SCAN_REQUESTOR requestor);


/**
 * get a module name from requestor id.
 *  @param vaphandle        : handle to the vap .
 *  @param requestor        : requestor id.
 *  @return on success returns pointer to module na,e.
 *          on failure returns NULL.
 */
u_int8_t *wlan_scan_requestor_name(wlan_if_t                vaphandle,
                                   IEEE80211_SCAN_REQUESTOR requestor);


/**
 * start a scan .
 *  @param vaphandle             : handle to the vap .
 *  @param params                : scan params.
 *  @param requestor             : value to identify the module requesting
 *                                 scan. the value is the requestor id obtained from.
 *                                 from wlan_scan_get_requestor_id.
 *  @param priority              : the scan priority, relative to other scans
 *                                 requested by the same VAP.
 *  @p_scan_id                   : a pointer to a memory location where a
 *                                 unique value identifying the scan request
 *                                 will be stored.
 *
 *
 * @return:
 *  on success returns 0.
 *  on failure returns a negative value.
 *  if succesful
 *  IEEE80211_SCAN_START event is delivered via the event handler.
 *  at the end of the scan IEEE80211_SCAN_DONE event is delivered
 *  via the event handler registered.
 *  if BSSID list is specified then IEEE80211_SCAN_BSSID_MATCH event  is delivered when
 *  ever a new scan entry is added/updated that matches one of the BSSIDs in the list.
 *
 */
int wlan_scan_start(wlan_if_t                vaphandle,
                    ieee80211_scan_params    *params,
                    IEEE80211_SCAN_REQUESTOR requestor,
                    IEEE80211_SCAN_PRIORITY  priority,
                    IEEE80211_SCAN_ID        *scan_id);

/**
 * register a scan event handler.
 *  @param vaphandle          : handle to the vap .
 *  @param evhandler          : scan event handler
 *  @param arg                : argument passed back via the evnt handler
 *  @return
 *  on success returns 0.
 *  on failure returns a negative value.
 *  allows more than one event handler to be registered.
 */
int wlan_scan_register_event_handler(wlan_if_t                    vaphandle,
                                     ieee80211_scan_event_handler evhandler,
                                     void                         *arg);

/**
 * unregister a scan event handler.
 * @param vaphandle           : handle to the vap .
 * @param evhandler           : scan event handler
 * @param arg                : argument passed back via the evnt handler
 * @return
 *  on success returns 0.
 *  on failure returns a negative value.
 */
int wlan_scan_unregister_event_handler(wlan_if_t                    vaphandle,
                                       ieee80211_scan_event_handler evhandler,
                                       void                         *arg);

/**
 * cancel scan.
 *  @param vaphandle             : handle to the vap .
 *  @param requestor             : module requesting the cancellation
 *  @param scan_id               : id of the scan to be cancelled
 *  @flag_sync                   : indicates whether scan should terminate synchronously
 *
 * @return  on success returns 0.
 *  on failure returns a negative value.
 *  when succesfully cancelled the scan, IEEE80211_SCAN_CANCELLED
 *  event is delivered via the event handler registered
 *  event can be delivered in the context of the caller of the thread.
 *  if flag IEEE80211_SCAN_CANCEL_WAIT is set, this function will sleep until scan completes.
 *  Note that setting IEEE80211_SCAN_CANCEL_WAIT flag  on a single threaded driver will cause deadlock.
 *  it only works on multi threaded driver.
 *  if flag IEEE80211_SCAN_CANCEL_SYNC is set, this function will execute the cancel operation(the scan statemachine).
 *  synchronously.
 *  Note that setting IEEE80211_SCAN_CANCEL_SYNC flag  on a multi threaded driver will cause race conditions.
 *  it only works on a single threaded driver.
 */
int wlan_scan_cancel(wlan_if_t                vaphandle,
                     IEEE80211_SCAN_REQUESTOR requestor,
                     IEEE80211_SCAN_ID        scan_id,
                     u_int32_t                flags);

/**
 * returns the time when the last scan started.
 * @param vaphandle       : handle to the vap .
 * @return the time when the last scan started.
 */
systime_t wlan_get_last_scan_time(wlan_if_t vaphandle);

/**
 * returns the time of the last scan that visited all channels.
 * @param vaphandle       : handle to the vap .
 * @return the time when the last complete scan started.
 */
systime_t wlan_get_last_full_scan_time(wlan_if_t vaphandle);

/**
 * returns information about the scan currently in progress or the last
 * completed scan, if one is not in progress.
 * progress
 * @param vaphandle     : handle to the vap .
 * @param info          : if this is non NULL and if there was a last scan
 *                        then implementation would fill the passed scan info structure.
 * @return
 *  returns EOK if there was a scan before.
 *  returns ENXIO if there was no scan before - some returned data may not apply.
 */
int wlan_get_last_scan_info(wlan_if_t           vaphandle,
                            ieee80211_scan_info *info);

/**
 * returns information about the specified scan. Information is only returned
 * if the scan is scheduled to run or currently running. An error code is
 * returned if the scan has already completed or never ran.
 * @param vaphandle     : handle to the vap .
 * @param scan_id       : The ID of the scan for which information is to be
 *                        returned.
 * @param info          : Pointer to structure where information about the
 *                        specified scan will be returned.
 * @return
 *  returns EOK if the specified scan is queued or running
 *  returns ENXIO if there was no scan before - some returned data may not apply.
 */
int wlan_get_scan_info(wlan_if_t           vaphandle,
                       IEEE80211_SCAN_ID   scan_id,
                       ieee80211_scan_info *scan_info);

/**
 * print out scan configuration parameters
 * @param vaphandle     : handle to the vap.
 * @param m             : seq_file for printing /proc handlers
 */
int wlan_print_scan_config(wlan_if_t vaphandle,
                           struct seq_file *m);

/**
 * Returns information about scan scheduler - current scan and queued requests.
 * The caller uses parameter total_requests to specify the maximum of entries
 * the output buffer can hold. The same variable receives the total number of
 * requests currently being managed by the scan scheduler (active or queued).
 * Parameter returned_requests indicates the number of entries actually copied
 * to the output buffer. This value can be less than total_requests.
 *  @param vaphandle      : handle to the vap .
 *  @scan_request_info    : Buffer where information about each running or queued
 *                          scan request will be stored.
 *  @total_requests       : Pointer to a memory location where the total number
 *                          of requests currently running or pending will be
 *                          returned.
 *  @returned_requests    : Pointer to a memory location where the number of
 *                          entries in the output buffer will be returned.
 *  @return
 *   returns EOK if all pending scan requests were copied to the output buffer,
 *   ENOMEM if the output buffer could not hold all current scan request.
 */
int wlan_scan_scheduler_get_requests(wlan_if_t                   vaphandle,
                                     ieee80211_scan_request_info *scan_request_info,
                                     int                         *total_requests,
                                     int                         *returned_requests);

/**
 * Enable scanning in the driver.
 * Scanning is disabled when a port starts an operation that cannot be
 * disturbed by a channel change - for example, connection or roaming.
 *  @param devhandle      : handle to the com device.
 *  @param requestor      : id of the module enabling scanning
 *  @return
 *   returns EOK
 */
int wlan_enable_scan_scheduler(wlan_dev_t               devhandle,
                               IEEE80211_SCAN_REQUESTOR requestor);

/**
 * Disable scanning in the driver.
 * Scanning is disabled when a port starts an operation that cannot be
 * disturbed by a channel change - for example, connection or roaming.
 *  @param devhandle      : handle to the com device.
 *  @param requestor      : id of the module disabling scanning
 *  @disable_duration     : maximum amount of time (in milliseconds) for scans
 *                          to be suspended.
 *                          If disable_duration=0, scans are suspended until
 *                          explicitly reenabled by wlan_enable_scan_scheduler.
 *  @return
 *   returns EOK
 */
int wlan_disable_scan_scheduler(wlan_dev_t               devhandle,
                                IEEE80211_SCAN_REQUESTOR requestor,
                                u_int32_t                disable_duration);

/**
 * indicates whether hw can transmit frames (i.e. we are in the home channel,
 * and not about to switch channels) .
 * @param vaphandle      : handle to the vap .
 * @return
 *  returns 1 if data can be transmitted.
 *  returns 0 otherwise.
 */
int wlan_scan_can_transmit(wlan_if_t vaphandle);

/**
 * indicates whether scan is in progress using ic struct.
 * @param vaphandle  : handle to ic .
 * @return
 *  returns 1 if scan in progress.
 *  returns 0 otherwise.
 */
int wlan_scan_in_progress_ic(wlan_dev_t ic);

/**
 * indicates whether scan is in progress.
 * @param vaphandle  : handle to the vap .
 * @return
 *  returns 1 if scan in progress.
 *  returns 0 otherwise.
 */
int wlan_scan_in_progress(wlan_if_t vaphandle);

/**
 * notifies the scanner that connect has been lost.
 * @param vaphandle            : handle to the vap .
 */
void wlan_scan_connection_lost(wlan_if_t vaphandle);

/**
 * provides the default scan parameters .
 * @param vaphandle            : handle to the vap .
 * @param scan_params          : the data structure to be populated with the default values.
 * @opmode opmode              : operation mode - affects some of the default values.
 * @opmode active_scan_flag    : flag indicating whether the defaults should be for an active scan
 * @opmode high_priority_flag  : flag indicating whether the defaults should be for a high-priority scan
 * @opmode connected_flag      : flag indicating connection state.
 * @opmode external_scan_flag  : flag indicating whether scan request was made by the OS
 * @opmode num_ssid            : number of desired SSIDs specified by the OS
 * @opmode ssid_list           : list of desired SSIDs specified by the OS
 * @opmode peer_count          : IBSS only - number of peers currently in the adhoc network.
 */
void wlan_set_default_scan_parameters(wlan_if_t             vaphandle,
                                      ieee80211_scan_params *scan_params,
                                      enum ieee80211_opmode opmode,
                                      bool                  active_scan_flag,
                                      bool                  high_priority_flag,
                                      bool                  connected_flag,
                                      bool                  external_scan_flag,
                                      u_int32_t             num_ssid,
                                      ieee80211_ssid        *ssid_list,
                                      int                   peer_count);

/**
 * sets the scan's priority parameters.
 * @param vaphandle      : handle to the vap .
 * @param requestor      : id of the module requesting the new priority
 * @param scan_id        : The ID of the scan for which the priority must be adjusted.
 * @param priority       : IEEE80211_SCAN_PRIORITY_HIGH indicates the scan should proceed even
 *                         in the presence of traffic;
 *                         IEEE80211_SCAN_PRIORITY_LOW indicates the scan should proceed
 *                         when no data traffic is present.
 * @return
 *  returns EOK if scan in progress and priority was set.
 *  returns an error indication otherwise.
 */
int wlan_scan_set_priority(wlan_if_t                vaphandle,
                           IEEE80211_SCAN_REQUESTOR requestor,
                           IEEE80211_SCAN_ID        scan_id,
                           IEEE80211_SCAN_PRIORITY  scan_priority);

/**
 * sets the scan's "forced" flag.
 * A forced scan will visit all channels in the list, even in the presence of
 * data traffic. A non-forced scan will defer the off-channel transitions until
 * there has been no data traffic for a certain amount of time, so it may take
 * a long time to complete.
 * @param vaphandle      : handle to the vap .
 * @param requestor      : id of the module requesting the new flag value
 * @param scan_id        : The ID of the scan for which the forced flag must be adjusted.
 * @param forced_flag    : Sets the "forced" flag.
 *                         true indicates the scan should proceed even
 *                         in the presence of traffic;
 *                         false indicates the scan should proceed
 *                         when no data traffic is present.
 * @return
 *  returns EOK if scan in progress and priority was set.
 *  returns an error indication otherwise.
 */
int wlan_scan_set_forced_flag(wlan_if_t                vaphandle,
                              IEEE80211_SCAN_REQUESTOR requestor,
                              IEEE80211_SCAN_ID        scan_id,
                              bool                     forced_flag);

/**
 * rebuild scan channel list. This function is usually called after updating
 * the regulatory domain.
 * @param vaphandle       : handle handle to the vap.
 *
 */
int wlan_scan_update_channel_list(wlan_if_t vaphandle);

/**
 * return number of channels in current scan list.
 * @param vaphandle       : handle to the vap.
 *
 */
int wlan_scan_channel_list_length(wlan_if_t vaphandle);

/**
 * set the absolute priority values for the specified VAP opmode.
 * @param devhandle       : handle to the IC.
 * @param opmode          : type of VAPs that the new table applies to
 * @param number_rows     : number of rows in the mapping table
 * @param p_mapping_table : pointer to mapping table
 *
 */
int wlan_scan_set_priority_table(wlan_dev_t                 devhandle,
                                 enum ieee80211_opmode      opmode,
                                 int                        number_rows,
                                 IEEE80211_PRIORITY_MAPPING *p_mapping_table);

/**
 * Retrieve the absolute priority values for the specified VAP opmode.
 * A pointer to the variable where the pointer to the mapping table will be returned.
 * This table cannot be modified by the caller.
 * @param devhandle       : handle to the IC.
 * @param opmode          : type of VAPs that the new table applies to
 * @param p_number_rows   : pointer to integer containing the number of rows in buffer provided (mapping table).
 *                          The function will overwrite this value with the actual number of rows returned.
 * @param p_mapping_table : pointer to variable where the pointer to the mapping table will be returned.
 *
 */
int wlan_scan_get_priority_table(wlan_dev_t                 devhandle,
                                 enum ieee80211_opmode      opmode,
                                 int                        *p_number_rows,
                                 IEEE80211_PRIORITY_MAPPING **p_mapping_table);

typedef int (* ieee80211_scan_iter_func) (void *, wlan_scan_entry_t);

/**
 * retrieve scan results from scan cache by iterating through
 * scancache based on given MAC address.
 * @param devhandle          : handle to the vap.
 * @param macaddr            : desired mac address.
 * @shandler                 : callback to deliver one scan entry
 * @arg                      : argument to be passed back via the callback.
 *
 * @return
 *  on success returns EOK.
 *  on failure returns a negative value.
 *
 */
int wlan_scan_macaddr_iterate(wlan_if_t vaphandle, u_int8_t *macaddr,
                              ieee80211_scan_iter_func shandler, void *arg);

/**
 * retrieve scan results from scan cache by iterating through scancache.
 * @param devhandle          : handle to the vap.
 * @shandler                 : callback to deliver one scan entry
 * @arg                      : argument to be passed back via the callback.
 *
 * @return
 *  on success returns EOK.
 *  on failure returns a negative value.
 *
 */
int wlan_scan_table_iterate(wlan_if_t vaphandle, ieee80211_scan_iter_func shandler, void *arg);

typedef struct {
    bool        is_p2p;         /* entry is a p2p device */
    wlan_chan_t listen_chan;    /* channel where the last probe response was received */
    u_int8_t    p2p_dev_addr[IEEE80211_ADDR_LEN];   /* P2P Device Address */
} ieee80211_scan_p2p_info;

/**
 * retrieve the p2p information for a scan entry.
 * @scan_entry               : handle to the scan entry.
 * @scan_p2p_info            : pointer to p2p info structure to be filled.
 *
 * @return
 *  on success returns EOK. The scan_p2p_info will be filled appropriately.
 *  on failure returns a negative value.
 *
 */
int wlan_scan_entry_p2p_info(wlan_scan_entry_t scan_entry, ieee80211_scan_p2p_info *scan_p2p_info);

/*
 * Return the age of the specified frame.
 */
u_int32_t wlan_scan_entry_specific_frame_age(wlan_scan_entry_t scan_entry, u_int8_t subtype);

/*
 * Function to return the IE length of specific frame like beacon and probe response frame.
 * The return value is the status code. The actual length length is filled in
 * the ret_ie_len parameter.
 */
int wlan_scan_specific_frame_ie_len(wlan_scan_entry_t scan_entry, u_int8_t subtype, int *ret_ie_len);

/*
 * Function to copy the IE buffer of specific frame like beacon and probe response frame.
 * The return value is the status code. The actual length length is copied in
 * the ie_len parameter.
 */
int wlan_scan_specific_frame_copy_ie_data(wlan_scan_entry_t scan_entry, u_int8_t subtype,
                                          u_int8_t *iebuf, u_int16_t *ie_len);

/**
 * flush scan cache.
 * @param vaphandle       : handle to the vap.
 *
 */
void wlan_scan_table_flush(wlan_if_t vaphandle);

/**
 *
 * @lock access to scan entry
 * ARGS :
 *  wlan_scan_entry_t        : handle to the scan entry .
 */
void wlan_scan_entry_lock(wlan_scan_entry_t scan_entry);

/**
 *
 * @release access to scan entry
 * ARGS :
 *  wlan_scan_entry_t        : handle to the scan entry .
 */
void wlan_scan_entry_unlock(wlan_scan_entry_t scan_entry);

/**
 *
 * get mac address .
 * @param scan_entry        : handle to the scan entry .
 * RETURNS:
 *  mac address of length IEEE80211_ADDR_LEN .
 */
u_int8_t * wlan_scan_entry_macaddr(wlan_scan_entry_t scan_entry);

/**
 *
 * get bssid .
 * @param scan_entry        : handle to the scan entry .
 * RETURNS:
 *  bssid of length IEEE80211_ADDR_LEN .
 */
u_int8_t * wlan_scan_entry_bssid(wlan_scan_entry_t scan_entry);

/**
 *
 * get cap info .
 * @param scan_entry        : handle to the scan entry .
 * @return cap info field .
 */
u_int16_t wlan_scan_entry_capinfo(wlan_scan_entry_t scan_entry);

/**
 *
 * get beacon interval .
 * @param scan_entry        : handle to the scan entry .
 * @return beacon interval in TUs .
 */
u_int16_t wlan_scan_entry_beacon_interval(wlan_scan_entry_t scan_entry);

/**
 * get beacon/prb resp sequence number.
 * @param scan_entry        : handle to the scan entry .
 * @return beacon/prb resp sequence number .
 */
u_int16_t wlan_scan_entry_sequence_number(wlan_scan_entry_t scan_entry);

/**
 * get beacon timestamp (tsf) .
 * @param scan_entry        : handle to the scan entry .
 * @param tsf               : pointer to variable where timestamp will be copied.
 */
void wlan_scan_entry_tsf(wlan_scan_entry_t scan_entry, u_int8_t *tsf);

/**
 *
 * reset "last received beacon" timestamp.
 * @param scan_entry        : handle to the scan entry .
 */
void wlan_scan_entry_reset_timestamp(wlan_scan_entry_t scan_entry);

/**
 *
 * get rssi .
 * @param scan_entry        : handle to the scan entry .
 * @return  average rssi of the scan entry (received beacon/probe response).
 */
u_int8_t wlan_scan_entry_rssi(wlan_scan_entry_t scan_entry);

/**
 * get scan entry ssid .
 *  @param scan_entry     : handle to the scan entry .
 *  @len                  : pointer to variable where the actual ssid length
 *                          will be copied
 * RETURNS:
 *      return phy Mode
 */
u_int32_t wlan_scan_entry_phymode(wlan_scan_entry_t scan_entry);

/**
 * get scan entry phy mode.
 *  @param scan_entry     : handle to the scan entry .
 * RETURNS:
 *      return a pointer to the ssid (NULL if length is 0)
 */
u_int8_t *wlan_scan_entry_ssid(wlan_scan_entry_t scan_entry, u_int8_t *len);

/**
 * get DTIM period .
 * @param scan_entry        : handle to the scan entry .
 * @return   return the DTIM period
 */
u_int8_t wlan_scan_entry_dtimperiod(wlan_scan_entry_t scan_entry);

/**
 * get TIM .
 * @param scan_entry        : handle to the scan entry .
 * RETURNS:
 *      return TIM ie
 */
u_int8_t *wlan_scan_entry_tim(wlan_scan_entry_t scan_entry);

/**
 * copy contents of beacon frame .
 * @param scan_entry         : handle to the scan entry .
 * @param beacon_buf         : buffer passed by the caller for the API to copy the beacon data.
 *                             if this buffer is not specified (set to NULL), the function
 *                             will simply return the total number of bytes used by the beacon.
 * @param ie_len             : caller passes the size of the beacon_buf and API implementation
 *                             returns the actual length of data copied.
 * @return
 *      return 0 on success.
 *      returns -ve value if length of the buffer passed in is insufficient.
 */
int wlan_scan_entry_copy_beacon_data(wlan_scan_entry_t scan_entry, u_int8_t *beacon_buf, u_int16_t *beacon_len);


/**
 * get beacon frame length.
 * @param scan_entry         : handle to the scan entry .
 * @return  return length, in bytes, of the beacon frame.
 */
int wlan_scan_entry_beacon_len(wlan_scan_entry_t scan_entry);

/**
 * copy ie information to the specified buffer.
 * @param scan_entry         : handle to the scan entry .
 * @param iebuf              : buffer passed by the caller for the API to copy the IE data.
 *                             if this buffer is not specified (set to NULL), the function
 *                             will simply return the total number of bytes used by IE
 *                             elements.
 * @param ie_len             : caller passes the size of the iebuf and API implementation
 *                             returns the actual length of data copied.
 * @return
 *      return 0 on success.
 *      returns -ve value if length of the buffer passed in is insufficient.
 */
int wlan_scan_entry_copy_ie_data(wlan_scan_entry_t scan_entry, u_int8_t *iebuf, u_int16_t *ie_len);

/**
 * get ie length.
 * @param scan_entry         : handle to the scan entry .
 * @return  return total byte count used by IEs.
 */
int wlan_scan_entry_ie_len(wlan_scan_entry_t scan_entry);

/**
 * get channel.
 * @param scan_entry         : handle to the scan entry .
 * @return channel of the scan entry .
 */
wlan_chan_t wlan_scan_entry_channel(wlan_scan_entry_t scan_entry);

/**
 *
 * @get erp info.
 * ARGS :
 *  wlan_scan_entry_t        : handle to the scan entry .
 * RETURNS:
 *  erp info of the scan entry .
 */
u_int8_t wlan_scan_entry_erpinfo(wlan_scan_entry_t scan_entry);

/*
 * @get rates .
 * ARGS :
 *  wlan_scan_entry_t        : handle to the scan entry .
 */
u_int8_t *wlan_scan_entry_rates(wlan_scan_entry_t scan_entry);

/**
 * get extended rates .
 * @param scan_entry         : handle to the scan entry .
 */
u_int8_t *wlan_scan_entry_xrates(wlan_scan_entry_t scan_entry);

/**
 * get RSN capability of a scan entry.
 * @param scan_entry         : handle to the scan entry .
 * @return returns 0 if the scan entry has a valid RSN IE, returns -ve otherwise.
 */
int wlan_scan_entry_rsncaps(wlan_if_t vaphandle, wlan_scan_entry_t scan_entry, u_int16_t *rsncaps);

struct ieee80211_rsnparms;
/**
 * get RSN params of a scan entry.
 * @param scan_entry         : handle to the scan entry .
 * @return returns 0 if the scan entry has a valid RSN IE, returns -ve otherwise.
 */
int wlan_scan_entry_rsnparams(wlan_if_t vaphandle, wlan_scan_entry_t scan_entry, struct ieee80211_rsnparms *rsnparams);

/**
 * get RSN info .
 * @param scan_entry         : handle to the scan entry .
 * RETURNS:
 *      pointer to RSN IE.
 */
u_int8_t *wlan_scan_entry_rsn(wlan_scan_entry_t scan_entry);

/**
 * get WPA info .
 * @param scan_entry         : handle to the scan entry .
 * RETURNS:
 *      pointer to WPA IE.
 */
u_int8_t *wlan_scan_entry_wpa(wlan_scan_entry_t scan_entry);


#if ATH_SUPPORT_WAPI
/**
 * get WAPI info .
 * @param scan_entry         : handle to the scan entry .
 * RETURNS:
 *      pointer to WAPI IE.
 */
u_int8_t *wlan_scan_entry_wapi(wlan_scan_entry_t scan_entry);
#endif


/**
 * get WPS info .
 * @param scan_entry         : handle to the scan entry .
 * RETURNS:
 *      pointer to WPS IE.
 */
u_int8_t *wlan_scan_entry_wps(wlan_scan_entry_t scan_entry);

/**
 * get SFA info .
 * @param scan_entry         : handle to the scan entry .
 * RETURNS:
 *      pointer to SFA IE.
 */
u_int8_t *wlan_scan_entry_sfa(wlan_scan_entry_t scan_entry);

/**
 * get Channel Switch Announcement (CSA) info .
 * @param scan_entry         : handle to the scan entry .
 * RETURNS:
 *      pointer to CSA IE.
 */
u_int8_t *wlan_scan_entry_channelswitch(wlan_scan_entry_t scan_entry);

/**
 * get Extended Channel Switch Announcement (XCSA) info .
 * @param scan_entry         : handle to the scan entry .
 * RETURNS:
 *      pointer to XCSA IE.
 */
u_int8_t *wlan_scan_entry_extendedchannelswitch(wlan_scan_entry_t scan_entry);

/**
 * get ht info .
 * @param scan_entry         : handle to the scan entry .
 * RETURNS:
 *      return pointer to htinfo ie
 */
u_int8_t *wlan_scan_entry_htinfo(wlan_scan_entry_t scan_entry);

/*
 * get vht info .
 * @param scan_entry         : handle to the scan entry .
 * RETURNS:
 *      return pointer to vhtop ie
 */
u_int8_t *wlan_scan_entry_vhtop(wlan_scan_entry_t scan_entry);

/**
 * get ht info .
 * @param scan_entry         : handle to the scan entry .
 * RETURNS:
 *      return pointer to htcap ie
 */
u_int8_t *wlan_scan_entry_htcap(wlan_scan_entry_t scan_entry);

/**
 * get quiet info .
 * @param scan_entry         : handle to the scan entry .
 * RETURNS:
 *      return pointer to quiet ie
 */
u_int8_t *wlan_scan_entry_quiet(wlan_scan_entry_t scan_entry);

/**
 * get qbss load ie .
 * @param scan_entry         : handle to the scan entry .
 * RETURNS:
 *      pointer to qbss load ie
 */
u_int8_t *wlan_scan_entry_qbssload(wlan_scan_entry_t scan_entry);

/**
 * get Vendor-specific IE .
 * @param scan_entry         : handle to the scan entry .
 * RETURNS:
 *      pointer to Vendor IE.
 */
u_int8_t *wlan_scan_entry_vendor(wlan_scan_entry_t scan_entry);

/**
 * get ht info .
 * @param scan_entry         : handle to the scan entry .
 * @param country            : char array of size 3 for API to return the
 *                             null terminated 2 char country code.
 * @return
 *      return 0 on success.
 *      returns -ve value if no country code is present.
 */
int wlan_scan_entry_country(wlan_scan_entry_t scan_entry, u_int8_t *country);

/**
 * get wme info .
 * @param scan_entry         : handle to the scan entry .
 * RETURNS:
 *      pointer to WME Information IE.
 */
u_int8_t *wlan_scan_entry_wmeinfo_ie(wlan_scan_entry_t scan_entry);

/**
 * get wme parameter.
 * @param scan_entry         : handle to the scan entry .
 * RETURNS:
 *      pointer to WME Parameter IE.
 */
u_int8_t *wlan_scan_entry_wmeparam_ie(wlan_scan_entry_t scan_entry);

/**
 * get age of the scan entry .
 * @param scan_entry         : handle to the scan entry .
 * @return
 *  age of the scan entry in msec.
 */
u_int32_t wlan_scan_entry_age(wlan_scan_entry_t scan_entry);

/**
 * get status of the scan entry .
 * @param scan_entry         : handle to the scan entry .
 * @return
 *  status of the scan entry.
 *  intial value of the status to 0.
 */
u_int32_t wlan_scan_entry_status(wlan_scan_entry_t scan_entry);

/**
 * get association state of the scan entry .
 * @param scan_entry         : handle to the scan entry .
 * @return
 *  association state of the scan entry in msec.
 *  intial value of the status to 0.
 */
u_int32_t wlan_scan_entry_assoc_state(wlan_scan_entry_t scan_entry);

/**
 * get scan entry bss type .
 * @param scan_entry         : handle to the scan entry .
 * @return
 *      the bss type (infra or adhoc)
 */
enum ieee80211_opmode wlan_scan_entry_bss_type(wlan_scan_entry_t scan_entry);

/**
 * get scan entry privacy .
 * @param scan_entry         : handle to the scan entry .
 * @return
 *      the bss privacy bit (enabled/disabled)
 */
u_int8_t wlan_scan_entry_privacy(wlan_scan_entry_t scan_entry);

/**
 * get Atheros capabilities .
 * @param scan_entry         : handle to the scan entry .
 * @return
 *      pointer to Atheros capabilities ie
 */
u_int8_t *wlan_scan_entry_athcaps(wlan_scan_entry_t scan_entry);

/**
 * get scan entry association cost .
 * @param scan_entry         : handle to the scan entry .
 * @return
 *      the cost of associaton to this AP. This value is used when calculating
 *      the AP's rank.
 */
u_int32_t wlan_scan_entry_assoc_cost(wlan_scan_entry_t scan_entry);

/**
 * get timestamp of the last failed association with the scan entry.
 * @param scan_entry         : handle to the scan entry .
 * @return
 *      the time of the last failed association with the AP.
 */
systime_t wlan_scan_entry_bad_ap_time(wlan_scan_entry_t scan_entry);

/**
 * get timestamp of scan entry's last association .
 * @param scan_entry         : handle to the scan entry .
 * @return
 *   the time when the scan entry last associated to the home AP.
 */
systime_t wlan_scan_entry_lastassoc(wlan_scan_entry_t scan_entry);

/**
 * get timestamp of scan entry's last deauth .
 * @param scan_entry         : handle to the scan entry .
 * @return
 *   the time when the scan entry last deauthed
 */
systime_t wlan_scan_entry_lastdeauth(wlan_scan_entry_t scan_entry);

/**
 * get scan entry channel load
 * @param scan_entry      : handle to the scan entry .
 * @return
 *                        : The channel load of this particular entry (AP),
 *                          used for load-balancing when selecting an AP for
 *                          association.
 */
u_int32_t wlan_scan_entry_chanload(wlan_scan_entry_t scan_entry);

/**
 * get scan entry utility
 * @param scan_entry         : handle to the scan entry .
 * @return
 *  utility               : The utility of this particular entry, used to
 *                          select the preferred AP for association or roaming.
 */
u_int32_t wlan_scan_entry_utility(wlan_scan_entry_t scan_entry);

/*
 * functions to set fields in scan entry
 */

/**
 * set status of the scan entry .
 * @param scan_entry       : handle to the scan entry .
 * @param status           : status word to be stored along with entry.
 *                          the value is not interpreted by the scanner and is opaque to the scanner .
 *                          the caller needs store its own status word and needs to create its own
 *                          interpretation for this status word.
 *                          a simple interpretation would  have 3 values  (0,1,2) for ststus word like
 *                          0: the association to this AP was succesful , 1: the association with AP failed once,
 *                          2: the association failed with this AP multiple times.
 * @return
 *      return 0 on success.
 *      returns -ve value on failure.
 */
void wlan_scan_entry_set_status(wlan_scan_entry_t scan_entry, u_int32_t status);

/**
 * set status of the scan entry .
 * @param scan_entry         : handle to the scan entry .
 * @param state              : Association state.
 *                          the value is not interpreted by the scanner and is opaque to the scanner .
 *                          the caller needs store its own association state and needs to create its own
 *                          interpretation for this state.
 * @return
 *      return 0 on success.
 *      returns -ve value on failure.
 */
void wlan_scan_entry_set_assoc_state(wlan_scan_entry_t scan_entry, u_int32_t state);

/**
 * set association cost of the scan entry .
 * @param scan_entry       : handle to the scan entry .
 * @param cost             : cost of association to this particular entry.
 *                          This is an arbitrary value set by the association
 *                          module, to be used when calculating the AP's rank.
 */
void wlan_scan_entry_set_assoc_cost(wlan_scan_entry_t scan_entry, u_int32_t cost);

/**
 * set timestamp of the last failed association with the scan entry.
 * @param scan_entry         : handle to the scan entry .
 * @param timestamp          : the time of the failed connection with the AP.
 */
void wlan_scan_entry_set_bad_ap_time(wlan_scan_entry_t scan_entry, systime_t timestamp);

/**
 * set timestamp of scan entry's last association .
 * @param scan_entry         : handle to the scan entry .
 * @param timestamp             : the time when the scan entry last associated to the home AP.
 */
void wlan_scan_entry_set_lastassoc(wlan_scan_entry_t scan_entry, systime_t timestamp);

/**
 * set timestamp of scan entry's last deauth .
 * @param scan_entry         : handle to the scan entry .
 * @param timestamp          : the time when the scan entry last deauthed
 */
void wlan_scan_entry_set_lastdeauth(wlan_scan_entry_t scan_entry, systime_t timestamp);

/**
 * set demerit utility for scan entry
 * @param scan_entry         : handle to the scan entry .
 * @param enable             : true/false.
 */
void wlan_scan_entry_set_demerit_utility(wlan_scan_entry_t scan_entry, bool enable);

/*
 * functions to manipulate the scan entry's reference count
 */

/**
 * @get reference count of scan entry .
 * @param scan_entry         : handle to the scan entry .
 * @return
 *      the reference count of scan entry. This value indicates how many
 *      clients are keeping a reference (pointer) to this entry.
 */
u_int8_t wlan_scan_entry_reference_count(wlan_scan_entry_t scan_entry);

/**
 * add a reference count to an scan entry .
 * @param scan_entry         : handle to the scan entry .
 * @param func                  : the caller .
 * @param line                   : at which line it's called
 * @return
 *      the new reference count of scan entry. This value indicates how many
 *      clients are keeping a reference (pointer) to this entry.
 */
u_int8_t wlan_scan_entry_add_reference_dbg(
        wlan_scan_entry_t scan_entry, const char *func, int line);


/**
 * @remove a reference count from an scan entry .
 * @param scan_entry         : handle to the scan entry .
 * @param func                  : the caller .
 * @param line                   : at which line it's called
 * @return
 *      the new reference count of scan entry. This value indicates how many
 *      clients are keeping a reference (pointer) to this entry.
 */
u_int8_t wlan_scan_entry_remove_reference_dbg(
        wlan_scan_entry_t scan_entry, const char *func, int line);

#define wlan_scan_entry_add_reference(scan_entry) \
    wlan_scan_entry_add_reference_dbg(scan_entry, __func__, __LINE__)

#define wlan_scan_entry_remove_reference(scan_entry) \
    wlan_scan_entry_remove_reference_dbg(scan_entry, __func__, __LINE__)

/**
 * print the names of scan notification event.
 * @param event                 : event being notified .
 * @return:
 *      a pointer to a constant string holding the event description.
 */
const char* wlan_scan_notification_event_name(ieee80211_scan_event_type event);

/**
 * print the names of scan notification reason.
 * @param reason                : reason for the event .
 * @return:
 *      a pointer to a constant string holding the reason description.
 */
const char* wlan_scan_notification_reason_name(ieee80211_scan_completion_reason reason);

/*
 * functions to fetch data from channel object
 */

/**
 * returns channel number
 * @param chan                  : handle to channel object
 * @return
 *   the IEEE channel number
 */
u_int32_t wlan_channel_ieee(wlan_chan_t chan);

/**
 * returns channel type
 * @param chan                  : handle to channel object
 * @return
 *   a char denoting channel type
 */
char channel_type(wlan_chan_t);

/**
 * returns channel frequency
 * @param chan                  : handle to channel object
 * @return
 *  the fequency in Mhz
 */
u_int32_t wlan_channel_frequency(wlan_chan_t chan);

/**
 * returns channel phy mode
 * @param chan                  : handle to channel object
 * @return
 *  the PHY mode
 */
enum ieee80211_phymode wlan_channel_phymode(wlan_chan_t chan);

/**
 * returns channel allowed transmit power
 * @param chan                  : handle to channel object
 * @return
 *  maximum allowed transmit power for this channel
 */
int8_t wlan_channel_maxpower(wlan_chan_t chan);

/**
 * returns channel flags
 * @param chan                  : handle to channel object
 * @return
 *  propitiery channel flags
 */
u_int32_t wlan_channel_flags(wlan_chan_t chan);

/**
 * returns channel passive state
 * @param chan                  : handle to channel object
 * @return
 *  returns true if passive channel
 */
bool wlan_channel_is_passive(wlan_chan_t chan);

/**
 * returns channel dfs state
 * @param chan                  : handle to channel object
 * @return
 *  returns true if dfs channel
 */
bool wlan_channel_is_dfs(wlan_chan_t chan, bool flagOnly);

/**
 * returns channel 5GHz odd state
 * @param chan                  : handle to channel object
 * @return
 *  returns true if 5GHz odd channel
 */
bool wlan_channel_is_5GHzOdd(wlan_chan_t chan);

/**
 * helper function to convert from frequency to channel number.
 * @param devhandle       : handle to the radio .
 * @param frequency       : frequency in MHz.
 * @return
 *  returns ieee channel number
 */
u_int32_t wlan_mhz2ieee(wlan_dev_t devhandle, u_int32_t  frequency, u_int32_t flags);

/**
 * helper function to convert  channel number to frequency.
 * @param devhandle       : handle to the radio .
 * @param frequency       : ieee channel number.
 * @return
 *  returns frequency in Mhz.
 */
u_int32_t wlan_ieee2mhz(wlan_dev_t devhandle, int ieeechan);

/* public methods of the VAP object */

/**
 * sets channel.
 *  @param vaphandle      : handle to the vap.
 *  @param chan           : ieee channel #.
 * @return
 *  on success returns 0.
 *  on failure returns a negative value.
 *  on succesfull channel change it posts a channel change event.
 *
 * if the vap is running and if the channel is IEEE80211_CHAN_ANY then
 *    the implementation chooses any appropriate channel
 *    when one of the vaps is brought up. In this case no channel cange event is posted.
 * if the vap is up and running and if the channel is IEEE80211_CHAN_ANY
 *    then the implementation would return ana error.
 * if the vap is running and if the channel is a valid channel then
 *    the implementation would set the channel to be the desired channel for the current phymode.
 *    no channel change event will be posted in this case..
 */
int wlan_set_channel(wlan_if_t vaphandle, int chan, u_int8_t des_cfreq2);
int wlan_set_ieee80211_channel(wlan_if_t vaphandle, struct ieee80211_channel *channel);
#if ATH_SUPPORT_WIFIPOS
int wlan_lean_set_channel(wlan_if_t vaphandle, int chan);
int wlan_pause_node(wlan_if_t vaphandle, struct ieee80211_node *ni,  bool pause);
int wlan_resched_txq(wlan_if_t vaphandle);
#endif

/**
 * returns current channel.
 *  @param vaphandle        : handle to the vap .
 *  @param hwChanbool       : TRUE - Get current hardware channel irrespective of VAP state.
 * @return
 *  on success return current channel.
 *  if no current channel is set it returns 0.
 */
wlan_chan_t wlan_get_current_channel(wlan_if_t vaphandle, bool hwChan);

/**
 * returns current bss channel.
 *  @param vaphandle        : handle to the vap .
 * @return
 *  on success returns bss ieee80211_channel.
 *  returns 0 if no bss channel is present( i.e we are not associated).
 */
wlan_chan_t wlan_get_bss_channel(wlan_if_t vaphandle);

/**
 * returns desired bss channel.
 *  @param vaphandle        : handle to the vap .
 * @return
 *  on success returns desired bss channel set by previous set channel call.
 *  Should be called when not connected.
 */
wlan_chan_t wlan_get_des_channel(wlan_if_t vaphandle);

/**
 * returns current list of channels of a certain wireless mode.
 *  @param devhandle            : handle to the device.
 *  @param phymode              : phy mode.
 *  @param chanlist             : array of channel list to be filled in.
 *  @param nchan                 : length of the chanlist array passed in.
 *  @return
 *    on success returns number of channels filled into the chanlist array.
 *    returns  a -ve value of failure. if nchan is 0 and chanlist is null
 *    then it returns the number of channels.
 */
int wlan_get_channel_list(wlan_dev_t devhandle, enum ieee80211_phymode phymode,
                          wlan_chan_t chanlist[], u_int32_t nchan);

wlan_chan_t
wlan_get_dev_current_channel(wlan_dev_t devhandle);

/**
 * returns set of supported phy modes.
 * @param   devhandle   : device handle
 * @param   modes       : array of supported modes (the caller owns the memory).
 * @param   nmodes      : number of supported modes
 * @param   len         : input array len
 * @return
 *       on success it returns the number of phy modes filled in the modes array..
 *       return -ve value on failure.
 */
int wlan_get_supported_phymodes(wlan_dev_t devhandle,
                                enum ieee80211_phymode *modes,
                                u_int16_t *nmodes,
                                u_int16_t len);

/**
 * returns the desired phy mode of current interface.
 * @param   vaphandle   : vap handle
 * @return  on success it returns the desired phy mode
 */
enum ieee80211_phymode wlan_get_desired_phymode(wlan_if_t vaphandle);

/**
 * set the desired phy mode of current interface.
 * @param      vaphandle   : vap handle
 * @param      mode        : the mode to set
 * @return on suces it returns 0.
 */
int wlan_set_desired_phymode(wlan_if_t vaphandle, enum ieee80211_phymode mode);

/**
 * returns the current phy mode of current interface.
 * @param      vaphandle   : vap handle
 * @return     on success it returns the current phy mode
 */
enum ieee80211_phymode wlan_get_current_phymode(wlan_if_t vaphandle);

/**
 * @returns the BSS phy mode of current associated AP.
 * @param      vaphandle   : vap handle
 * @return
 *       on success it returns the BSS phy mode
 */
enum ieee80211_phymode wlan_get_bss_phymode(wlan_if_t vaphandle);

/**
 * set the desired channel number for ibss.
 * @param      vaphandle   : vap handle
 * @param      channum     : the channel number to set
 * @return on success it returns 0.
 */
int wlan_set_desired_ibsschan(wlan_if_t vaphandle, int channum);

/**
 * sets country code. should allow when the interface is up ?
 * @param  devhandle    : handle to the radio .
 * @param  isoName      : null terminated 2 char country code string.
 * @param  cc           : ISO-3166 country code number.
 * @param  cmd          : operation after country code change
 *
 * @return
 *  on success returns 0.
 *  on failure returns a negative value.
 *  on succesfull country code change it posts a IEEE80211_CC_CHANGED event.
 *  if cmd is CLIST_NEW_COUNTRY, redefines the channel list instead of flag invalid channel as excuded,
 */
int wlan_set_countrycode(wlan_dev_t devhandle, char isoName[3], u_int16_t cc, enum ieee80211_clist_cmd cmd);

/**
 * returns current country code.
 * @param  devhandle    : handle to the radio .
 * @return
 *  on success returns current country code.
 *  if no country code is set it returns NULL.
 *  the returned country code string points to internal memory, if the
 *  caller needs to make a copy if it needs to cache it.
 */
int wlan_get_countrycode(wlan_dev_t devhandle, char cc[3]);

/**
 * sets country code. should allow when the interface is up ?
 * @param  devhandle    : handle to the radio .
 * @param  isoName      : null terminated 2 char country code string.
 * @param  cc           : ISO-3166 country code number.
 * @param  cmd          : operation after country code change
 *
 * @return
 *  on success returns 0.
 *  on failure returns a negative value.
 *  on succesfull country code change it posts a IEEE80211_CC_CHANGED event.
 *  if cmd is CLIST_NEW_COUNTRY, redefines the channel list instead of flag invalid channel as excuded,
 */
int wlan_set_11d_countrycode(wlan_dev_t devhandle, char isoName[3], u_int16_t cc, enum ieee80211_clist_cmd cmd);

/**
 * returns current regulatory domain.
 * @param  devhandle    : handle to the radio .
 * @return
 *  returns current regdomain code.
 */
u_int16_t wlan_get_regdomain(wlan_dev_t devhandle);

/**
 * set regulatory domain.
 * @param  devhandle    : handle to the radio .
 * @param  regdmn       : regdomain code.
 */
int wlan_set_regdomain(wlan_dev_t devhandle, u_int16_t regdmn);

/**
 * gets the interface address (mac address)
 * @param      vaphandle   : vap handle
 * @return
 *       interface MAC address array of length IEEE80211_ADDR_LEN
 */
u_int8_t *wlan_vap_get_macaddr(wlan_if_t vaphandle);

/**
 * gets the hw interface address (mac address defined in EEPROM)
 * @param      vaphandle   : vap handle
 * @return
 *        interface MAC address array of length IEEE80211_ADDR_LEN
 */
u_int8_t *wlan_vap_get_hw_macaddr(wlan_if_t vaphandle);

/** get the BSSID(mac address)
 * @param      vaphandle   : vap handle
 * @return
 *        address array of length IEEE80211_ADDR_LEN
 */
int wlan_vap_get_bssid(wlan_if_t vaphandle, u_int8_t *bssid);

/** get  handle to radio
 * @param      vaphandle   : vap handle
 * @return
 *        return handle to the radio.
 */
wlan_dev_t wlan_vap_get_devhandle(wlan_if_t vaphandle);


/**
 * returns the supproted rates for a certain phymode
 *
 * @param      devhandle: device handle
 * @param      phymode  : the phymode
 * @param      rates    : the rate array
 * @param      len      : array len
 * @param      nrates   : number of supported rates
 * @return
 *       On success the rates array will be filled and nrates set to the number
 *       of supported rates, or -ve otherwise.
 */
int wlan_get_supported_rates(wlan_dev_t devhandle, enum ieee80211_phymode mode,
                             u_int8_t *rates, u_int32_t len, u_int32_t *nrates);

/**
 * returns the current operational rates for a certain phymode
 * @param      vaphandle: vap handle
 * @param      phymode  : the phymode
 * @param      rates    : the rate array
 * @param      len      : array len
 * @param      nrates   : number of operational rates
 *  @return
 *       On success the rates array will be filled and nrates set to the number
 *       of operational rates, or -ve otherwise.
 */
int wlan_get_operational_rates(wlan_if_t vaphandle, enum ieee80211_phymode mode,
                               u_int8_t *rates, u_int32_t len, u_int32_t *nrates);

/**
 * set the current operational rates for a certain phymode
 * @param      vaphandle: vap handle
 * @param      phymode  : the phymode
 * @param      rates    : the rate array
 * @param      nrates   : number of operational rates
 * @return on suces it returns 0.
 */
int wlan_set_operational_rates(wlan_if_t vaphandle, enum ieee80211_phymode mode,
                               u_int8_t *rates, u_int32_t nrates);

/**
 * query the operational mode of a vap.
 * @param      vaphandle   : vap handle
 * @return
 *  the current operational mode of vap.
 */
enum ieee80211_opmode wlan_vap_get_opmode(wlan_if_t vaphandle);

/**
 * get rssi info
 * @param      vaphandle   : vap handle
 * @param      rssi_info   : handle for the return value .
 * @param      rssitype    : type of rssi.
 *
 * @return : 0  on success and -ve on failure.
 *           only valid for STA vaps;
 *
 */
int wlan_getrssi(wlan_if_t vaphandle, wlan_rssi_info *rssi_info, wlan_rssi_type rssitype);

/**
 * get uplink estimated rate
 * @param      vaphandle   : vap handle
 * @param      snr         : rssi value from scan entry
 *
 * @return : estimated rate.
 *           only valid for STA vaps;
 *
 */
u_int16_t wlan_get_uplinkrate(wlan_if_t vaphandle, u_int8_t snr);

/*
 * @send a probe request
 * ARGS :
 *  wlan_if_t            : vap handle.
 *  destination          : the destination address of the probe request
 *  bssid                : the bssid to which the probe request must be transmitted
 *  ssid                 : the ssid to which the probe request must be transmitted
 *  ssidlen              : the length, in bytes, of the ssid field
 *  optie                : pointer to the list of optional IEs to be added to the probe request
 *  optielen             : the length, in bytes, of the list of optional IEs
 *
 *  RETURNS: 0  on success and -ve on failure.
 *           only valid for STA vaps;
 *
 */
int wlan_send_probereq(
    wlan_if_t       vaphandle,
    const u_int8_t  *destination,
    const u_int8_t  *bssid,
    const u_int8_t  *ssid,
    const u_int32_t ssidlen,
    const void      *optie,
    const size_t    optielen);

/**
 * get tx rate info for the bss.
 * @param      vaphandle   : vap handle
 * @param      rate_info   : tx rate info for the bss.
 * @return : 0  on success and -ve on failure.
 *           only valid for STA vaps;
 */
int wlan_get_txrate_info(wlan_if_t vaphandle, ieee80211_rate_info *rate_info);

/**
 * set the current bss rates
 * @param      vaphandle: vap handle
 * @param      rates    : the rate array
 * @param      len      : length of the array.
 * @param      nrates   : number of operational rates.
 * @return : 0  on success and -ve on failure.
 */
int wlan_get_bss_rates(wlan_if_t vaphandle, u_int8_t *rates,
                           u_int32_t len, u_int32_t *nrates);

/**
 * set the current bss ht rates
 * @param      vaphandle: vap handle
 * @param      rates    : the rate array
 * @param      len      : length of the array.
 * @param      nrates   : number of operational rates.
 * @return : 0  on success and -ve on failure.
 */
int wlan_get_bss_ht_rates(wlan_if_t vaphandle, u_int8_t *rates,
                           u_int32_t len, u_int32_t *nrates);

/**
 * get the tsf offset value for the VAP.
 * @param      vaphandle : vap handle
 * @param      tsf_offset: storage to return the tsf offset
 * in a single vap case the value is 0. when multiple Vaps
 * are running then the value is non zero for non primary vaps.
 */
int wlan_vap_get_tsf_offset(wlan_if_t vaphandle, u_int64_t *tsf_offset);

/**
 * Prepare information related to WoW offload to download
 * to embedded CPU
 * @param      vaphandle : vap handle
 * This data is supplied by the WLAN driver
 */
int wlan_vap_prep_wow_offload_info(wlan_if_t vaphandle);

/**
 * Update WLAN driver with information (say, tx seqnum) from the
 * embedded CPU after exiting WoW mode
 * @param      vaphandle : vap handle
 */
int wlan_update_protocol_offload(wlan_if_t vaphandle);

/*
 * public methods to node object
 */

/**
 * get rssi info
 * @param node           : node handle.
 * @param rssitype       : type of rssi.
 * @param rssi_info      : handle for the return value .
 * @return : 0  on success and -ve on failure.
 *
 */
int wlan_node_getrssi(wlan_node_t node, wlan_rssi_info *rssi_info, wlan_rssi_type rssitype);

/**
 * get mac address of a node/station
 * @param node           : node handle.
 * @return  mac address on success  and NULL on failure.
 *
 */
u_int8_t *wlan_node_getmacaddr(wlan_node_t node);

/**
 * get BSSID of BSS that node/station is connected to.
 * @param node           : node handle.
 * @return  returns BSSID.
 *
 */
u_int8_t *wlan_node_getbssid(wlan_node_t node);

/**
 * get capinfo of a node/station
 * @param node           : node handle.
 * @return capinfo.
 */
u_int16_t wlan_node_getcapinfo(wlan_node_t node);

/**
 * get operating bands of a node/station
 * @param node           : node handle.
 * @return operating bands.
 */
u_int8_t wlan_node_get_operating_bands(wlan_node_t node);

/**
 * get extended capabilities of a node/station
 * @param node           : node handle.
 * @return extended capabilities field.
 */
u_int32_t wlan_node_get_extended_capabilities(wlan_node_t node);

/**
 * get tx rate info for the node.
 * @param    node        : node handle.
 * @returntx rate info for the node.
 */
int wlan_node_txrate_info(wlan_node_t node, ieee80211_rate_info *rate_info);

/**
 * get rx rate info for the node.
 * @param  node          : node handle.
 * @return rx rate info for the node.
 */
int wlan_node_rxrate_info(wlan_node_t node, ieee80211_rate_info *rate_info);

/**
 * get wpa ie from a node.
 * @param   vaphandle   : handle to a vap
 * @param   macaddr     : mac address of the node.
 * @param   ie          : ie to return.
 * @param   len         : length of the array paaed in.
 *                        len is in/out param.
 *
 * @return
 *       0 on success and -ve value on failure.
 *       on success the actual length of data copied into
 *       ie structure is returned in len.
 */
int  wlan_node_getwpaie(wlan_if_t vap, u_int8_t *macaddr, u_int8_t *ie, u_int16_t *len);

/**
 * get wps ie from a node.
 * @param   vaphandle   : handle to a vap
 * @param   macaddr     : mac address of the node.
 * @param   ie          : ie to return.
 * @param   len         : length of the array paaed in.
 *                        len is in/out param.
 *
 * @return
 *       0 on success and -ve value on failure.
 *       on success the actual length of data copied into
 *       ie structure is returned in len.
 */
int  wlan_node_getwpsie(wlan_if_t vap, u_int8_t *macaddr, u_int8_t *ie, u_int16_t *len);

/**
 * get ath ie from a node.
 * @param   vaphandle   : handle to a vap
 * @param   macaddr     : mac address of the node.
 * @param   ie          : ie to return.
 * @param   len         : length of the array paaed in.
 *                        len is in/out param.
 *
 * @return
 *       0 on success and -ve value on failure.
 *       on success the actual length of data copied into
 *       ie structure is returned in len.
 */
int  wlan_node_getathie(wlan_if_t vap, u_int8_t *macaddr, u_int8_t *ie, u_int16_t *len);

/**
 * get wme ie from a node.
 * @param   vaphandle   : handle to a vap
 * @param   macaddr     : mac address of the node.
 * @param   ie          : ie to return.
 * @param   len         : length of the array paaed in.
 *                        len is in/out param.
 *
 * @return
 *       0 on success and -ve value on failure.
 *       on success the actual length of data copied into
 *       ie structure is returned in len.
 */
int  wlan_node_getwmeie(wlan_if_t vap, u_int8_t *macaddr, u_int8_t *ie, u_int16_t *len);

/**
 * authorize/unauthorize a node.
 * @param   vaphandle   : handle to a vap
 * @param authirize     : 1 to authorize, 0 to unauthorize
 * @param macaddr       : peer MAC address of the node
 * @return : 0  on success and -ve on failure.
 */
int wlan_node_authorize(wlan_if_t vaphandle, int authorize, u_int8_t *macaddr);

/**
 * get node param.
 * @param node           : node handle.
 * @param param          : node param.
 * @return the value of the param.
 */
u_int32_t wlan_node_param(wlan_node_t node, ieee80211_node_param_type param);

/**
 * set association decision from OS
 * @param   vaphandle   : handle to a vap
 * @param   macaddr     : mac address of the node.
 * @param assoc_status  : association status code to be set
 * @return
 *       0 on success and -ve value on failure.
 */
u_int32_t wlan_node_set_assoc_decision(wlan_if_t vap, u_int8_t *macaddr, u_int16_t assoc_status,
                                       u_int16_t p2p_assoc_status);

/**
 * retrieve cached OS association decision
 * @param   vaphandle   : handle to a vap
 * @param   macaddr     : mac address of the node.
 * @return
 *       Cached association decision.
 */
u_int32_t wlan_node_get_assoc_decision(wlan_if_t vap, u_int8_t *macaddr);

/**
 * get channel of a node/station
 * @param node           : node handle.
 * @return the pointer of the channel.
 */
wlan_chan_t wlan_node_get_chan(wlan_node_t node);

/**
 * get state flag of a node/station
 * @param node           : node handle.
 * @return the value of the flag.
 */
u_int32_t wlan_node_get_state_flag(wlan_node_t node);

/**
 * get authentication algorithm of a node/station
 * @param node           : node handle.
 * @return the value of the authmode.
 */
u_int8_t wlan_node_get_authmode(wlan_node_t node);

/**
 * get Atheros feature flags of a node/station
 * @param node           : node handle.
 * @return the value of the flag.
 */
u_int8_t wlan_node_get_ath_flags(wlan_node_t node);

/**
 * get ERP of a node/station
 * @param node           : node handle.
 * @return the value of the ERP.
 */
u_int8_t wlan_node_get_erp(wlan_node_t node);

/**
 * get association up time of a node/station
 * @param node           : node handle.
 * @return the system tick of the time.
 */
systick_t wlan_node_get_assocuptime(wlan_node_t node);

/**
 * get AID of node/station
 * @param node           : node handle.
 * @return the value of AID.
 */
u_int16_t wlan_node_get_associd(wlan_node_t node);

/**
 * get current transmit power of node/station
 * @param node           : node handle.
 * @return the value of transmit power.
 */
u_int16_t wlan_node_get_txpower(wlan_node_t node);

/**
 * get vlan tag of node/station
 * @param node           : node handle.
 * @return the value of vlan tag.
 */
u_int16_t wlan_node_get_vlan(wlan_node_t node);

/**
 * get unicast cipher types of node/station
 * @param node           : node handle.
 * @param types         :  array for the supported cipher types to be filled in.
 * @param len           :  length of the passed in types array .
 * @return  on success number of elements filled in to types array and -ve on failure.
 *           if len is 0 and types is NULL then it would return the  number of types
 *           stored in the rsn IE internally.
 */
int wlan_node_get_ucast_ciphers(wlan_node_t node, ieee80211_cipher_type types[], u_int len);

/**
 * get tx sequence from a node.
 * @param   node        : node handle.
 * @param   txseqs      : tx sequence array to return.
 * @param   len         : length of the array .
 *
 * @return the actual length of data copied into
 *       txseqs structure is returned.
 */
void  wlan_node_get_txseqs(wlan_node_t node, u_int16_t *txseqs, u_int len);

/**
 * get rx sequence from a node.
 * @param   node        : node handle.
 * @param   rxseqs      : rx sequence array to return.
 * @param   len         : length of the array .
 *
 * @return the actual length of data copied into
 *       rxseqs structure is returned.
 *       It's the raw data which also includes the fragment number of the frame.
 */
void  wlan_node_get_rxseqs(wlan_node_t node, u_int16_t *rxseqs, u_int len);

/**
 * get uAPSD flag of node/station
 * @param node           : node handle.
 * @return the value of uAPSD flag.
 */
u_int8_t wlan_node_get_uapsd(wlan_node_t node);

/**
 * get idle time of node/station
 * @param node           : node handle.
 * @return the value of inactive time (secs).
 */
u_int16_t wlan_node_get_inact(wlan_node_t node);

/**
 * get HT flag of node/station
 * @param node           : node handle.
 * @return the value of HT flag.
 */
u_int16_t wlan_node_get_htcap(wlan_node_t node);

/**
 * get statistics about a node/station
 * @param node           : node handle.
 *
 * @return node statistics  on success  and NULL on failure.
 *
 */
struct ieee80211_nodestats *wlan_node_stats(wlan_node_t node);


typedef void (* ieee80211_sta_iter_func) (void *, wlan_node_t);
/**
 * returns info about list of current of stations.
 * @param   vaphandle   : handle to a vap
 * @param iter_func     : function called for each station in the table..
 * @param arg           : arg passed bak to the iter function.
 * @return
 * it returns the number of stas(nodes). if the iter_func is not null
 * the iter_func is called for each node in the context of the caller thread.
 * for AP mode VAP this API iters through the list of associated stations.
 * for STA mode VAP this API iters through the one node corresponding to AP.
 * for IBSS mode VAP this API iters through the list of neighbors in the IBSS network.
 */
int32_t wlan_iterate_station_list(wlan_if_t vaphandle,ieee80211_sta_iter_func iter_func,void *arg);
/**
 * This API iters through the list of all stations.
 */
int32_t wlan_iterate_all_sta_list(wlan_if_t vaphandle,ieee80211_sta_iter_func iter_func,void *arg);
/**
 * This API iters through the list of unassociated stations.
 */
int32_t wlan_iterate_unassoc_sta_list(wlan_if_t vap,ieee80211_sta_iter_func iter_func,void *arg);

/**
 * set fixed data rate of a node/station
 * @param node           : node handle.
 * @return error status if any.
 */
int wlan_node_set_fixed_rate(wlan_node_t node, u_int8_t rate);

/**
 * get fixed data rate of a node/station
 * @param node           : node handle.
 * @return fixed data rate
 */
u_int8_t wlan_node_get_fixed_rate(wlan_node_t node);

/**
 * get tx and rx streams of a node
 * @param node           : node handle.
 * @return tx and rx NSS.
 */
u_int8_t wlan_node_get_nss(wlan_node_t node);

/**
 * get 256QAM support for a node
 * @param node           : node handle.
 * @return 1 if has 256QAM support else return 0
 */
u_int8_t wlan_node_get_256qam_support(wlan_node_t node);

#if QCA_AIRTIME_FAIRNESS
/**
 * get percentage of airtime for a node
 * @param node           : node handle.
 * @return airtime percentage
 */
u_int32_t wlan_node_get_airtime(wlan_node_t node);
#endif

/**
 * get last data tx power for a node
 * @param node           : node handle.
 * @return last data tx power
 */
u_int32_t wlan_node_get_last_txpower(wlan_node_t node);

/**
 * handler of manual ADDBA/DELBA operations request to the node/station
 * @param arg            : pointer of stucture of ieee80211_addba_delba_request.
 * @param node           : node handle.
 * @return none.
 */
void wlan_addba_request_handler(void *arg, wlan_node_t node);

/**
 * set auth mode.
 * @param   vaphandle   : handle to a vap
 * @param modes         : auth mode array.
 * @param len           : number of auth modes
 * @return 0  on success and -ve on failure.
 */
int wlan_set_authmodes(wlan_if_t vaphandle, ieee80211_auth_mode modes[], u_int len);

/**
 * get auth mode.
 * @param   vaphandle   : handle to a vap
 * @param types         :  array for the supported cipher types to be filled in .
 * @param len           :  length of the passed in types array .
 * @return  on success number of elements filled in to modes array and -ve on failure.
 */
int wlan_get_auth_modes(wlan_if_t vaphandle, ieee80211_auth_mode modes[], u_int len);

/**
 * set unicast cipher set.
 * @param   vaphandle   : handle to a vap
 * @param ctypes        : array of cipher types
 * @param len           : number of cipher types
 * @return 0  on success and -ve on failure.
 */
int wlan_set_ucast_ciphers(wlan_if_t vaphandle, ieee80211_cipher_type types[], u_int len);

/**
 * set multicast cipher set.
 *
 * @param   vaphandle   : handle to a vap
 * @param ctypes        : array of cipher types
 * @param len           : number of cipher types
 * @return 0  on success and -ve on failure.
 */
int wlan_set_mcast_ciphers(wlan_if_t vaphandle, ieee80211_cipher_type types[], u_int len);

/**
 * get unicast cipher types.
 * @param   vaphandle   : handle to a vap
 * @param types         :  array for the supported cipher types to be filled in.
 * @param len           :  length of the passed in types array .
 * @return  on success number of elements filled in to types array and -ve on failure.
 *           if len is 0 and types is NULL then it would return the  number of types
 *           stored in the rsn IE internally.
 */
int wlan_get_ucast_ciphers(wlan_if_t vaphandle, ieee80211_cipher_type types[], u_int len);

/**
 * get multicast cipher types.
 * @param   vaphandle   : handle to a vap
 * @param types         :  array for the supported cipher types to be filled in.
 * @param len           :  length of the passed in types array .
 * @return  on success number of elements filled in to types array and -ve on failure.
 *           if len is 0 and types is NULL then it would return the  number of types
 *           stored in the rsn IE internally.
 */
int wlan_get_mcast_ciphers(wlan_if_t vaphandle, ieee80211_cipher_type types[], u_int len);

/**
 * get active multicast cipher type (STA only).
 * @param   vaphandle   : handle to a vap
 * @return the active (current) multicast cipher.
 */
ieee80211_cipher_type wlan_get_current_mcast_cipher(wlan_if_t vaphandle);


/**
 * get active multicast management frame cipher type (STA only).
 * @param   vaphandle   : handle to a vap
 * @return the active (current) multicast cipher.
 */
ieee80211_cipher_type wlan_get_current_mcastmgmt_cipher(wlan_if_t vaphandle);

/**
 * set cipher params in rsn IE.
 * @param   vaphandle   : handle to a vap
 * @param type          : parameter type.
 * @param val           : value of the parameter.
 * @return  0  on success and -ve on failure.
 */
int wlan_set_rsn_cipher_param(wlan_if_t vaphandle, ieee80211_rsn_param type, u_int32_t val);

/**
 * get cipher params in rsn IE.
 *
 * @param   vaphandle   : handle to a vap
 * @param type          : parameter type.
 * @return parameter  on success and -ve on failure.
 */
int32_t wlan_get_rsn_cipher_param(wlan_if_t vaphandle, ieee80211_rsn_param type);

/**
 * set default WEP Key.
 * @param   vaphandle   : handle to a vap
 * @param   keyindex    : key index. IEEE80211_KEYIX_NONE for keymapping keys, otherwise default keys.
 * @param   key         : key value
 * @return  0  on success and -ve on failure.
 */
int wlan_set_key(wlan_if_t vaphandle, u_int16_t keyix, ieee80211_keyval *key);

/**
 * set default WEP Key ID.
 * @param   vaphandle   : handle to a vap
 * @param   keyindex    : key index.
 * @return  0  on success and -ve on failure.
 */
int wlan_set_default_keyid(wlan_if_t vaphandle, u_int keyix);

/**
 * get default tx Wep Key.
 * @param   vaphandle   : handle to a vap
 * @return  returns key index on success and -ve on failure.
 */
u_int16_t wlan_get_default_keyid(wlan_if_t vaphandle);

/**
 * get encryption key.
 * @param   vaphandle   : handle to a vap
 * @param   wpa key.
 */
int wlan_get_key(wlan_if_t vaphandle, u_int16_t keyix, u_int8_t *macaddr, ieee80211_keyval *key, u_int16_t keybuf_len);

/**
 * delete encryption key.
 *
 *  @param vaphandle     : handle to the vap.
 *  @param keyid         : key id.
 *  @param macaddr       : mac address of the node to delete the key for.
 *                         all bytes are 0xff for  multicast key.
 *  @return 0  on success and -ve on failure.
 */
int wlan_del_key(wlan_if_t vaphandle, u_int16_t keyid, u_int8_t *macaddr);

/**
* clear encryption keys.
 *
 * @param vaphandle     : handle to the vap.
 */
int wlan_clear_vap_key(wlan_if_t vaphandle);
/**
 * restore encryption keys.
 *
 * @param vaphandle      : handle to the vap.
 */
void wlan_restore_keys(wlan_if_t vaphandle);

/**
 * @set Powersave mode .
 *
 *  @param vaphandle     : handle to the vap.
 *  @param mode          : power save mode .
 *  @return 0  on success and -ve on failure.
 */
int wlan_set_powersave(wlan_if_t vaphandle, ieee80211_pwrsave_mode mode);

/**
 * get Powersave mode .
 *
 *  @param vaphandle     : handle to the vap.
 *  @return power save mode.
 */
ieee80211_pwrsave_mode wlan_get_powersave(wlan_if_t vaphandle);

/**
 * @set Powersave mode inactivity time .
 *
 *  @param vaphandle     : handle to the vap.
 *  @param mode          : power save mode .
 *  @param inact_time    : inactivity time in msec to enter powersave.
 *  @return 0  on success and -ve on failure.
 */
int wlan_set_powersave_inactive_time(wlan_if_t vaphandle, ieee80211_pwrsave_mode mode, u_int32_t inactive_time);

/**
 * @get Powersave mode inactivity time .
 *
 *  @param vaphandle     : handle to the vap.
 *  @param mode          : power save mode .
 *  @return iinactive time for the given mode.
 */
u_int32_t wlan_get_powersave_inactive_time(wlan_if_t vaphandle, ieee80211_pwrsave_mode mode);

/**
 * get Atheros application specific powersave state.
 *
 *  @param vaphandle     : handle to the vap.
 *  @return application specific power save stat.
 */
u_int32_t wlan_get_apps_powersave_state(wlan_if_t vaphandle);

/**
 * @force the driver to enter 8021.11 powersave state.
 *  @param vaphandle     : handle to the vap.
 *  @param enable        : enable/disable force sleep.
 *  @return EOK  on success and non zero on failure.
 */
int wlan_pwrsave_force_sleep(wlan_if_t vaphandle, bool enable);

/**
 * Configure the STA to send PS-Poll or wake up to retreive traffic
 *  @param vaphandle     : handle to the vap.
 *  @param pspoll
 *  @return EOK  on success and non zero on failure.
 */
int wlan_sta_power_set_pspoll(wlan_if_t vaphandle, u_int32_t pspoll);

/*
 * Configure the STA to send additional PS-Poll in resposne to more-data bit
 *  @param vaphandle     : handle to the vap.
 *  @param mode (see ieee80211_pspoll_moredata_handling)
 *  @return EOK  on success and non zero on failure.
 */
int wlan_sta_power_set_pspoll_moredata_handling(wlan_if_t vaphandle, ieee80211_pspoll_moredata_handling mode);

/*
 * Get the current PS-Poll configuration
 *  @param vaphandle     : handle to the vap.
 *  @return { 0 => wake up to get data, 1 => use pspoll }
 */
u_int32_t wlan_sta_power_get_pspoll(wlan_if_t vaphandle);

/*
 * Get the current PS-Poll more-data bit configuration
 *  @param vaphandle     : handle to the vap.
 *  @return (see ieee80211_pspoll_moredata_handling)
 */
ieee80211_pspoll_moredata_handling wlan_sta_power_get_pspoll_moredata_handling(wlan_if_t vaphandle);

/**
 * set MIMO powersave mode .
 *
 *  @param vaphandle     : handle to the vap.
 *  @param mode          : mimo power save mode .
 *  @retutn: 0  on success and -ve on failure.
 */
int wlan_set_mimo_powersave(wlan_if_t vaphandle, ieee80211_mimo_powersave_mode mode);

/**
 * get mimo Powersave mode .
 *
 *  @param vaphandle     : handle to the vap.
 *  @retutn: 0  on success and -ve on failure.
 */
ieee80211_mimo_powersave_mode wlan_get_mimo_powersave(wlan_if_t vaphandle);

/**
 * set wapi parameter
 *
 * @param vaphandle      : handle to the vap
 * @param value          : wapi param
 */
int
wlan_setup_wapi(wlan_if_t vaphandle, int value);

/**
 * begin wapi callback
 *
 * @param vaphandle     : handle to the vap
 * @param macaddr       : the mac address
 * @param msg_len       : length of the message
 * @param msg_type      : message type
 */
void *
wlan_wapi_callback_begin(wlan_if_t vaphandle, u_int8_t *macaddr, int *msg_len, int msg_type);

/**
 * end of wapi callback
 */
void
wlan_wapi_callback_end(u_int8_t *);

/**
 * set simple configuration parameter.
 *
 *  @param vaphandle     : handle to the vap.
 *  @param param         : simple config paramaeter.
 *  @param val           : value of the parameter.
 *  @return 0  on success and -ve on failure.
 */
int wlan_set_param(wlan_if_t vaphandle, ieee80211_param param, u_int32_t val);

/**
 * get simple configuration parameter.
 *
 *  @param vaphandle     : handle to the vap.
 *  @param param         : simple config paramaeter.
 *  @return value of the parameter.
 */
u_int32_t wlan_get_param(wlan_if_t vaphandle, ieee80211_param param);

/**
 * set verbose level
 *
 *  @param vaphandle     : handle to the vap.
 *  @param val           : value of the parameter.
 *  @return 0  on success and -ve on failure.
 */
int wlan_set_umac_verbose_level(u_int32_t verbose_level);

/**
 * set net80211 debug flag.
 *
 *  @param vaphandle     : handle to the vap.
 *  @param val           : value of the parameter.
 *  @return 0  on success and -ve on failure.
 */
int wlan_set_debug_flags(wlan_if_t vaphandle, u_int64_t val);

/**
 *  set debug mac filtering flags
 *
 *  @param vaphandle     : handle to the vap.
 *  @param extra         : value of the parameter.
 *  @return 0  on success and -ve on failure.
 */
#if DBG_LVL_MAC_FILTERING
int wlan_set_debug_mac_filtering_flags(wlan_if_t vaphandle, unsigned char* extra);
#endif

/*
*  set enable/disable of CTS2SELF protection for DTIM Beacon for a specific vap.
*  @param vaphandle     : handle to the vap.
*  @param enable : enable/disable.
*/
int wlan_set_vap_cts2self_prot_dtim_bcn(wlan_if_t  vap, u_int8_t enable);

/*
*  set specific dscp to tid map for a specific vap.
*  @param vaphandle     : handle to the vap.
*  @param tos : type of service field or dscp.
*  @param tid : Tid to which the packet should be queued.
*/
int wlan_set_vap_dscp_tid_map(wlan_if_t  vap, u_int8_t tos, u_int8_t tid);

/*
*  set specific dscp to tid map for a specific vap based
*  on priority assigned by user. The default priority value
*  of a vap is 0.
*  @param vaphandle     : handle to the vap.
*  @param priority : priority to be assigned to the vap.
*/
int wlan_set_vap_priority_dscp_tid_map(wlan_if_t  vap, u_int8_t priority);

/**
 * get net80211 debug flag value.
 *
 *  @param vaphandle     : handle to the vap.
 *  @return value of the parameter.
 */
u_int64_t wlan_get_debug_flags(wlan_if_t vaphandle);

/**
 * set fixed rate.
 *
 *  @param vaphandle     : handle to the vap.
 *  @param rate          : simple config paramaeter.
 *  @return 0  on success and -ve on failure.
 *          passing a NULL value for the rate clears fixed rate setting.
 */
int wlan_set_fixed_rate(wlan_if_t vaphandle, ieee80211_rate_info *rate);


/**
 * get fixed rate.
 *
 *  @param vaphandle     : handle to the vap.
 *  @param rate_info     : fixed rate info.
 *  @return 0  on success and -ve on failure.
 *           returns  ENOENT if no fixed rate.
 */
int wlan_get_fixed_rate(wlan_if_t vaphandle, ieee80211_rate_info *rate);

/**
 * get channel info
 * @param vaphandle     : handle to vap
 * @param chans         : channel info
 * @param nchan         : number of channels
 */
int wlan_get_chaninfo(wlan_if_t vaphandle, int flag, struct ieee80211_channel *chans, int *nchan);

/**
 * get channel list
 * @param vaphandle     : handle to vap
 * @param chanlist      : channel list
 */
int wlan_get_chanlist(wlan_if_t vaphandle, u_int8_t *chanlist);

/**
 * set channel switch
 *
 *  @param chan        : the desired channel to switch
 *  @param tbtt        : how many beacon to annouce before switch
 */

int wlan_set_txpowadjust(wlan_if_t vaphandle, int txpow);

/**
 * set clear App/Opt IE
 *
 *  @param vaphandle    : handle to vap
 */
int wlan_set_clr_appopt_ie(wlan_if_t vaphandle);

/**
 * set wmm parameter.
 *
 *  @param vaphandle     : handle to the vap.
 *  @param wmeparam      :  wme parameter .
 *  @param isbss         :  1: bss param 0: local param
 *  @param ac            : access category.
 *  @param  val          :  value of the parameter.
 *  @return 0  on success and -ve on failure.
 */

int wlan_set_wmm_param(wlan_if_t vaphandle,wlan_wme_param wmeparam,
                            u_int8_t isbss, u_int8_t ac,u_int32_t val);

/**
 * get wmm parameter.
 *
 *  @param vaphandle     : handle to the vap.
 *  @param wmeparam      :  wme parameter .
 *  @param isbss         :  1: bss param 0: local param
 *  @param ac            : access category.
 *  @retuen value of the parameter.
 */

u_int32_t wlan_get_wmm_param(wlan_if_t vaphandle,wlan_wme_param wmeparam,
                            u_int8_t isbss, u_int8_t ac);

/**
 * set ampdu mode..
 *
 *  @param vaphandle     : handle to the vap.
 *  @param mode          : ampdu mode.
 *  @return 0  on success and -ve on failure.
 */
int wlan_set_ampdu_mode(wlan_if_t vaphandle, ieee80211_ampdu_mode mode);


/**
 * get ampdu mode..
 *
 *  @param vaphandle     : handle to the vap.
 *  @return ampdu mode.
 */
ieee80211_ampdu_mode wlan_get_ampdu_mode(wlan_if_t vaphandle);

/**
 * get vap ststistics..
 *
 *  @param vaphandle     : handle to the vap.
 *  @return vap stats
 */
struct ieee80211_stats *wlan_get_stats(wlan_if_t vaphandle);


/**
 * send frame.
 *
 *  @param vaphandle     : handle to the vap.
 *  @param macaddr       : destination mac address.
 *  @param frame         :  type of frame to send.
 *  @return 0  on success and -ve on failure.
 */
int wlan_send_frame(wlan_if_t vaphandle,ieee80211_send_frame_type frame);

/**
 * set up privacy filters.
 *
 *  @param vaphandle     : handle to the vap.
 *  @param filters       : array of privacy filters.
 *  @param num_filters   : length of the filters array.
 *  @return 0  on success and -ve on failure.
 *
 */
int wlan_set_privacy_filters(wlan_if_t vaphandle, ieee80211_privacy_exemption *filters, u_int32_t num_filters);

/**
 * query privacy filters.
 *
 *  @param vaphandle     : handle to the vap.
 *  @param filters       : array of privacy filters.
 *  @param num_filters   : length of the filters array.
 *  @len                 : size of the filters array.
 *  @return on success number of elements filled in to filters array and -ve on failure.
 */
int wlan_get_privacy_filters(wlan_if_t vaphandle, ieee80211_privacy_exemption *filters, u_int32_t *num_filters, u_int32_t len);

/**
 * set up PMKID list.
 *
 *  @param vaphandle     : handle to the vap.
 *  @param pmkids        : array of PMKID entries.
 *  @param num           : length of the pmkids array.
 *  @return 0  on success and -ve on failure.
 *
 */
int wlan_set_pmkid_list(wlan_if_t vaphandle, ieee80211_pmkid_entry *pmkids, u_int16_t num);

/**
 * query PMKID list.
 *
 *  @param vaphandle     : handle to the vap.
 *  @param pmkids        : array of PMKID entries.
 *  @param count         : number of the PMKID entries.
 *  @param len           : size of the pmkids array.
 *  @return on success number of elements filled in to pmkids array and -ve on failure.
 */
int wlan_get_pmkid_list(wlan_if_t vaphandle, ieee80211_pmkid_entry *pmkids, u_int16_t *count, u_int16_t len);

/*
 * MLME public methods
 */

/*
 * Function to get the correct mode of the given channel(arg) to be used by the
 * hardware. It iterates through other vaps and returns the channel mode which
 * is a superset of all modes.
 * This is usually used in repeater configuration, where the STA VAP is connected
 * to a 11G rootAP and still we want the AP VAP to be 11N. Here 11N is a superset
 * of 11G.
 *        rootap mode   Repeater-mode
 * case 1    11A         11NAHT40PLUS or 11NAHT40MINUS
 * case 2    11G         11NGHT20
 * case 3    11NGHT20    11NGHT20
 *
 * @param arg           : Channel used by the hardware
 * @param vap           : handle to the vap
 * @return  IEEE80211 status code
 */
void
ieee80211_vap_iter_get_chan(void *arg, wlan_if_t vap);

/**
 * MLME Start tx Channel Switch Announcement Request
 *
 * @param vaphandle       : handle to the vap.
 * @param scan_entry_chan : Bss channel
 * @param timeout         : time out value for Tx CSA (milliseconds)
 * @return  IEEE80211 status code
 */
int wlan_mlme_start_txchanswitch(wlan_if_t vaphandle, struct ieee80211_channel *scan_entry_chan, u_int32_t timeout);

#if ATH_SUPPORT_DFS
/**
 * MLME Start Repeater CAC. The AP VAP(s) do the CAC we just wait until CAC is completed
 *
 * @param vaphandle     : handle to the vap.
 * @param bss_chan      : channel of the desired BSS
 * @return  IEEE80211 status code
 */
int wlan_mlme_start_repeater_cac(wlan_if_t vaphandle, struct ieee80211_channel *bss_chan);
#endif
/**
 * MLME cancel tx channel Switch Announcement timer
 *
 * @param vaphandle     : handle to the vap.
*/
int wlan_mlme_cancel_txchanswitch_timer(wlan_if_t vaphandle);

/**
 * MLME cancel Repeater CAC  timer
 *
 * @param vaphandle     : handle to the vap.
*/
int wlan_mlme_cancel_repeater_cac_timer(wlan_if_t vaphandle);

/**
 * MLME Join Request (Infrastructure)
 *
 * @param vaphandle     : handle to the vap.
 * @param bss_entry     : scan entry of the desired BSS
 * @param timeout       : time out value for join request (milliseconds)
 * @return  IEEE80211 status code
 */
int wlan_mlme_join_infra(wlan_if_t vaphandle, wlan_scan_entry_t bss_entry, u_int32_t timeout);

/**
 * MLME Auth Request with FILS key
 *
 * @param vaphandle     : handle to the vap.
 * @param mlme          : mlme buffer as received from the app
 * @return  IEEE80211 status code
 */
int wlan_mlme_auth_fils(wlan_if_t vaphandle, struct ieee80211req_mlme *mlme);

/**
 * MLME Auth Request
 *
 * @param vaphandle     : handle to the vap.
 * @param timeout       : time out value for auth request (in ms)
 * @return  IEEE80211 status code
 */
int wlan_mlme_auth_request(wlan_if_t vaphandle, u_int32_t timeout);

/**
 * MLME Deauth Request
 *
 * @param vaphandle     : handle to the vap.
 * @param macaddr       : peer MAC address
 * @param reason        : IEEE80211 reason code
 * @return              : IEEE80211 status code
 */
int wlan_mlme_deauth_request(wlan_if_t vaphandle, u_int8_t *macaddr, IEEE80211_REASON_CODE reason);

/**
 * MLME Association Response
 *
 * @param vaphandle     : handle to the vap.
 * @param macaddr       : peer MAC address
 * @param reason        : IEEE80211 reason code
 * @param reassoc       : flag to indicate reassoc
 * @return              : IEEE80211 status code
 */
int wlan_mlme_assoc_resp(wlan_if_t vaphandle, u_int8_t *macaddr,
                         IEEE80211_REASON_CODE reason, int reassoc,
                         struct ieee80211_app_ie_t* optie);

/**
 * MLME Auth
 *
 * @param vaphandle     : handle to the vap.
 * @param macaddr       : peer MAC address
 * @param seq           : auth sequence
 * @param status        : IEEE80211 reason code
 * @param challenge_txt : auth challenge
 * @param challenge_len : auth challenge length
 * @return              : IEEE80211 status code
 */
int wlan_mlme_auth(wlan_if_t vaphandle, u_int8_t *macaddr, u_int16_t seq, u_int16_t status,
                   u_int8_t *challenge_txt, u_int8_t challenge_len,
                   struct ieee80211_app_ie_t* optie);


/**
 * MLME Association Request
 *
 * @param vaphandle     : handle to the vap.
 * @param timeout       : time out value for assoc request (ms)
 * @return              : IEEE80211 status code
 */
int wlan_mlme_assoc_request(wlan_if_t vaphandle, u_int32_t timeout);

/**
 * MLME Reassociation Request
 *
 * @param vaphandle     : handle to the vap.
 * @param prev_bssid           : previous BSSID
 * @param timeout       : time out value for assoc request (ms)
 * @return              : IEEE80211 status code
 */
int wlan_mlme_reassoc_request(wlan_if_t vaphandle, u_int8_t *prev_bssid, u_int32_t timeout);

/**
 * MLME Disassoc Request
 *
 * @param vaphandle     : handle to the vap.
 * @param macaddr       : peer MAC address
 * @param reason        : IEEE80211 reason code
 * @return              : IEEE80211 status code
 */
int wlan_mlme_disassoc_request(wlan_if_t vaphandle, u_int8_t *macaddr, IEEE80211_REASON_CODE reason);

/**
 * MLME Disassoc Request with completion callback
 *
 * @param vaphandle     : handle to the vap.
 * @param macaddr       : peer MAC address
 * @param reason        : IEEE80211 reason code
 * @param handler       : Completion Callback function pointer
 * @param arg           : Callback arguments
 * @return              : IEEE80211 status code
 */
int wlan_mlme_disassoc_request_with_callback(wlan_if_t vaphandle,
                                               u_int8_t *macaddr,
                                               IEEE80211_REASON_CODE reason,
                                               wlan_vap_complete_buf_handler handler,
                                               void *arg
                                               );

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
/**
 * MLME is STA CAC running

 * @param vaphandle     : handle to the vap.
 * @return      IEEE80211 status code
 */
bool wlan_mlme_is_stacac_running(wlan_if_t vaphandle);

/**
 * MLME set STA CAC running
 *
 * @param vaphandle     : handle to the vap.
 * @return      IEEE80211 status code
 */
void wlan_mlme_set_stacac_running(wlan_if_t vaphandle, u_int8_t set);
#endif

/**
 * MLME Join Request (IBSS)
 *
 * @param vaphandle     : handle to the vap.
 * @param node          : node of the desired BSS
 * @param timeout       : time out value for join request
 * @return      IEEE80211 status code
 */
int wlan_mlme_join_adhoc(wlan_if_t vaphandle,  wlan_scan_entry_t bss_entry, u_int32_t timeout);
bool scanner_check_for_bssid_entry(void *arg);

/**
 * MLME Start BSS (AP/IBSS)
 *
 * @param vaphandle     : handle to the vap.
 * @return      IEEE80211 status code
 */
int wlan_mlme_start_bss(wlan_if_t vaphandle, u_int8_t restart);

/**
 * Determine if HT40 coex is enabled (AP/IBSS)
 *
 * @param vap     : handle to the vap.
 * @return      true if coext enabled, false otherwise
 */
bool wlan_coext_enabled(wlan_if_t vaphandle);

/**
 * Determine Channel Width (AP/IBSS)
 *
 * @param vap     : handle to the vap.
 * @param channel : channel pointer.
 * @return      IEEE80211 status code
 */
void wlan_determine_cw(wlan_if_t vaphandle, wlan_chan_t channel);

/**
 * Disassoc the station on BSS
 *
 * @param ni     : node pointer
 */
void sta_disassoc(void *arg, struct ieee80211_node *ni);

/**
 * MLME Stop BSS (AP/IBSS)
 *
 * @param vaphandle     : handle to the vap.
 * @return      IEEE80211 status code
 */
int wlan_mlme_stop_bss(wlan_if_t vaphandle, int flags);

/**
 * MLME Pause BSS (AP/IBSS)
 *
 * @param vaphandle     : handle to the vap.
 * @return      IEEE80211 status code
 */
int wlan_mlme_pause_bss(wlan_if_t vaphandle);

/**
 * MLME Resume BSS (AP/IBSS)
 *
 * @param vaphandle     : handle to the vap.
 * @return      IEEE80211 status code
 */
int wlan_mlme_resume_bss(wlan_if_t vaphandle);

/**
 * MLME stop in Restart case
 *
 * @param vaphandle     : handle to the vap.
 * @return      IEEE80211 status code
 */
int wlan_mlme_restart_stop_bss(wlan_if_t vap);

/**
 * MLME Cancel
 *
 * @param vaphandle     : handle to the vap.
 * @return      IEEE80211 status code
 */
int wlan_mlme_cancel(wlan_if_t vaphandle);

/**
 * MLME Cancel
 *
 * @param vaphandle     : handle to the vap.
 * @return  true if mlme operation is in progress, else false.
 */
bool wlan_mlme_operation_in_progress(wlan_if_t vaphandle);

/**
 * @MLME Start monitoring (monitor mode)
 *
 * @param vaphandle     : handle to the vap.
 * @return      IEEE80211 status code
 */
int wlan_mlme_start_monitor(wlan_if_t vaphandle);

/**
 *Create an instance to Application IE module to append new IE's for various frames.
 *
 * @param vaphandle     : handle to the vap.
 * @returns a handle for this instance to use for subsequent calls.
 */
wlan_mlme_app_ie_t wlan_mlme_app_ie_create(wlan_if_t vaphandle);

/**
 *Detach from Application IE module. Any remaining IE's will be removed and freed.
 *
 * @param vaphandle     : handle to the vap.
 * @returns the instance handle to the App IE module.
 */
int wlan_mlme_app_ie_delete(wlan_mlme_app_ie_t app_ie_handle, ieee80211_frame_type ftype, u_int8_t *app_ie);

/*
Delets all the IEs based on ID used when setting the IE
*/
int wlan_mlme_app_ie_delete_id(wlan_mlme_app_ie_t app_ie_handle, ieee80211_frame_type ftype, u_int8_t identifier);

/*
Remove all the IEs from the list
*/
void wlan_mlme_remove_ie_list(wlan_mlme_app_ie_t app_ie_handle);

/**
 * Deauth all the stations on BSS
 *
 * @param vaphandle     : handle to the vap
 */
void wlan_deauth_all_stas(wlan_if_t vaphandle);

#if ATH_SUPPORT_HS20
/*
 * Parse the appie and add the extended capabilities to driver and
 * remove extended capabilities from appie
 */
int wlan_mlme_parse_appie(
    struct ieee80211vap     *vap,
    ieee80211_frame_type    ftype,
    u_int8_t                *buf,
    u_int16_t               buflen);
#endif

/**
 *To set a new Application IE for a frame type. Any existing IE for this frame and
 * instance of APP IE will be overwritten. However, other IE from other instances
 * will be preserved. When buflen is zero, the existing IE for this instanace and
 * frame type is removed.
 * @param app_ie_handle : instance handle to the App IE module.
 * @param ftype         : frame type.
 * @param buf           : appie buffer.
 * @param buflen        : length of the buffer.
 */

int wlan_mlme_app_ie_set(
    wlan_mlme_app_ie_t      app_ie_handle,
    ieee80211_frame_type    ftype,
    u_int8_t                *buf,
    u_int16_t               buflen,
    u_int8_t                identifier);

/* Wrapper function used to parse the IE buffer and  split the buffer into
 * individual IEs and then add them into the linked list. Also performs a
 * duplicate check to see if the IE is already present. This function dirst deletes
 * all the IEs of the same type and then addds the new IEs.
 */
int wlan_mlme_app_ie_set_check(
    struct ieee80211vap     *vap,
    ieee80211_frame_type    ftype,
    u_int8_t                *app_ie,
    u_int32_t               app_ie_length,
    u_int8_t                identifier);

/*
 *To get the Application IE for this frame type and instance.
 *
 * @param app_ie_handle : instance handle to the App IE module.
 * @param ftype         : frame type.
 * @param buf           : appie buffer.
 * @param buflen        : length of the buffer.
 * @param ielen         : length of the ie data.
 * @return 0 on success and buf is filled in with specific IE and -ve on failure.
 */
int wlan_mlme_app_ie_get(
    wlan_mlme_app_ie_t      app_ie_handle,
    ieee80211_frame_type    ftype,
    u_int8_t                *buf,
    u_int32_t               *ielen,
    u_int32_t               buflen,
    u_int8_t                *temp_buf);

/**
 *set application specific ie buffer for a given frame..
 *
 * @param vaphandle     : handle to the vap.
 * @param ftype         : frame type.
 * @param buf           : appie buffer.
 * @param buflen        : length of the buffer.
 * @return  0  on success and -ve on failure.
 * once the buffer is set for a perticular frame the MLME keep setting up the ie in to the frame
 * every time the frame is sent out. passing 0 value to buflen would remove the appie biffer.
 */
int wlan_mlme_set_appie(wlan_if_t vaphandle, ieee80211_frame_type ftype, u_int8_t *buf, u_int16_t buflen);

/**
 * @get application specific ie buffer for a given frame..
 *
 * @param vaphandle     : handle to the vap.
 * @param ftype         : frame type.
 * @param buf           : appie buffer.
 * @param buflen        : length of the buffer.
 * @param ielen         : length of the ie data.
 * @return 0 on success and buf is filled in with specific IE and -ve on failure.
 */
int wlan_mlme_get_appie(wlan_if_t vaphandle, ieee80211_frame_type ftype, u_int8_t *buf, u_int32_t *ielen, u_int32_t buflen, u_int8_t identifier);

/**
 *set application specific optional ie buffer.
 *
 * @param vaphandle     : handle to the vap.
 * @param buf           : optie buffer.
 * @param buflen        : length of the buffer.
 * @return  0  on success and -ve on failure.
 * once the buffer is set for a perticular frame the MLME keep setting up the ie in to the frame
 * every time the frame is sent out. passing 0 value to buflen would remove the optie buffer.
 */
int wlan_mlme_set_optie(wlan_if_t vaphandle, u_int8_t *buf, u_int16_t buflen);

/**
 * @get application specific optional ie buffer.
 *
 * @param vaphandle     : handle to the vap.
 * @param ftype         : frame type.
 * @param buf           : optie buffer.
 * @param buflen        : length of the buffer.
 * @param ielen         : length of the ie data.
 * @return 0 on success and buf is filled in with specific IE and -ve on failure.
 */
int wlan_mlme_get_optie(wlan_if_t vaphandle, u_int8_t *buf, u_int32_t *ielen, u_int32_t buflen);


/**
 * MLME Get Link Rate
 *
 * @param vaphandle     : handle to the vap.
 * @return link rate (bps)
 */
void wlan_get_linkrate(wlan_if_t vaphandle, u_int32_t* rxlinkspeed, u_int32_t* txlinkspeed);


/**
 * MLME Get rssi (adhoc)
 *
 * @param vaphandle     : handle to the vap.
 * @return  RSSI
 */
int32_t wlan_get_rssi_adhoc(wlan_if_t vaphandle);

/**
 * MLME Set connection state "up"
 *
 * @param vaphandle     : handle to the vap.
 * @return none.             :
 */
void wlan_mlme_connection_up(wlan_if_t vaphandle);

/**
 * MLME Set connection state "down"
 *
 * @param vaphandle     : handle to the vap.
 * @return none.             :
 */
void wlan_mlme_connection_down(wlan_if_t vaphandle);

/**
 * MLME Reset Connection
 *
 * @param vaphandle     : handle to the vap.
 * @return none.             :
 */
int wlan_mlme_connection_reset(wlan_if_t vaphandle);


/**
 * MLME Get timeout in ms for disassociating nodes
 *
 * @param vaphandle     : handle to the vap.
 * @return none.
 */
u_int32_t wlan_get_disassoc_timeout(wlan_if_t vaphandle);

/**
 * MLME Set timeout in ms for disassociating nodes
 *
 * @param vaphandle           : handle to the vap.
 * @param node_age_timeout    : timeout (ms)
 */
void wlan_set_disassoc_timeout(wlan_if_t vaphandle, u_int32_t node_age_timeout);

/**
 * sets the desired ssid list  .
 * @param vaphandle     : handle to the vap.
 * @param nssid         : number of ssids passed in.
 * @param ssidlist      : array of ssids.
 *
 * @return  0 on success and -ve on failure.
 *           after this call is made, the ssid set remains permanent until the next call to the
 *           same function.
 *           it always clears any ssid list set up before setting up new set.
 *           nssid =0 clears the previous setting.
 */
int wlan_set_desired_ssidlist(wlan_if_t vaphandle, u_int16_t nssid, ieee80211_ssid *ssidlist);

/**
 * gets the desired ssid list  .
 *
 * @param vaphandle     : handle to the vap.
 * @param ssidlist      : array of ssids.
 * @param nssid         : array length.
 * @return number of ssids returned in the ssid list
 */
int wlan_get_desired_ssidlist(wlan_if_t vaphandle, ieee80211_ssid *ssidlist, int nssid);

/*
 * Public methods to set/get parameters used to build Candidate AP list.
 */

/**
 * sets the desired ssid list  .
 * :
 * @param vaphandle     : handle to the vap.
 * @param bnssid        : number of bssids passed in.
 * @param bssidlist     : array of bssids.
 * @return  0 on success and -ve on failure.
 *       after this call is made, the bssid set remains permanent until the next call to the
 *       same function.
 *       it always clears any bssid list set up before setting up new set.
 *       nbssid =0 clears the previous setting.
 */
int wlan_aplist_set_desired_bssidlist(wlan_if_t vaphandle, u_int16_t nbssid, u_int8_t (*bssidlist)[IEEE80211_ADDR_LEN]);

/**
 * gets the number of desired bssid.
 *
 * @param vaphandle     : handle to the vap.
 *
 * @return  number of bssids returned in the bssid list
 */
int wlan_aplist_get_desired_bssid_count(wlan_if_t vaphandle);

/**
 * gets the desired bssid list  .
 *
 * @param vaphandle     : handle to the vap.
 * @param bssidlist     : array of bssids.array should have enough lenght to store all the bssids.
 *
 * @param  number of bssids returned in the bssid list
 */
int wlan_aplist_get_desired_bssidlist(wlan_if_t vaphandle, u_int8_t (*bssidlist)[IEEE80211_ADDR_LEN]);

/**
 * gets one item from the desired bssid list  .
 *  :
 * @param vaphandle     : handle to the vap.
 * @param index         : the index of the list item to be returned.
 * @param bssid         : a pointer to the variable where the address of the desired ssid
 *                        will be copied.
 *
 *  @return 0 if the index was valid and an address was returned, -ve otherwise.
 */
int wlan_aplist_get_desired_bssid(wlan_if_t vaphandle, int index, u_int8_t **bssid);

/**
 * sets the max age for entries in the scan list to be considered for association.
 *
 * @param vaphandle     : handle to the vap.
 * @param max_age       : maximum accepted age for scan entries, in ms.
 * @reuturn              IEEE80211 status code
 */
int wlan_aplist_set_max_age(wlan_if_t vaphandle, u_int32_t max_age);

/**
 * @gets the max age for entries in the scan list to be considered for association.
 *
 * @param vaphandle     : handle to the vap.
 * @return max age, in ms.
 */
u_int32_t wlan_aplist_get_max_age(wlan_if_t vaphandle);


/**
 * sets the desired ssid list  .
 *
 * @param vaphandle       : handle to the vap.
 * @param nphy            : number of phy types passed in.
 * @param phylist         : array of phy modes.
 *
 * @return 0 on success and -ve on failure.
 *           after this call is made, the phy list set remains permanent until the next call to the
 *           same function.
 *           it always clears any phy list set up before setting up new set.
 *           nphy =0 clears the previous setting.
 *
 *
 */
int wlan_set_desired_phylist(wlan_if_t vaphandle, enum ieee80211_phymode *phylist, u_int16_t nphy);

/**
 * gets the desired phy list  .
 *
 * @param vaphandle       : handle to the vap.
 * @param phylist         : address of memory location where the address of the
 *                          array of phy modes should be copied.
 * @param nphy            : number of desired phy modes
 * @param len             : passed-in array length
 *
 * @return  number of phy types returned in the phy list
 */

int wlan_get_desired_phylist(wlan_if_t vaphandle, enum ieee80211_phymode *phylist, u_int16_t *nphy, u_int16_t len);

/**
 * sets the desired BSS type
 *
 * @param vaphandle       : handle to the vap.
 * @param bss_type        : desired BSS type.
 * @return   IEEE80211 status code
 */
int wlan_aplist_set_desired_bsstype(wlan_if_t vaphandle, enum ieee80211_opmode bss_type);

/**
 * gets the value of the "accept any bssid" flag .
 *
 * @param vaphandle       : handle to the vap.
 * @param                 : true if the flag is set, false otherwise.
 */
bool wlan_aplist_get_accept_any_bssid(wlan_if_t vaphandle);

/**
 * sets the value of the "ignore all mac addresses" flag. If this flag is set the STA will not
 *  associate to any AP.
 *
 * @param vaphandle       : handle to the vap.
 * @param flag            : true/false
 * @return                : 0 if the flag was set correctly, -ve otherwise.
 */
int wlan_aplist_set_ignore_all_mac_addresses(wlan_if_t vaphandle, bool flag);

/**
 * gets the value of the "ignore all mac addresses" flag. If this flag is set the STA will not
 *  associate to any AP.
 *
 * @param vaphandle       : handle to the vap.
 * @return  true if the flag is set, false otherwise.
 */
bool wlan_aplist_get_ignore_all_mac_addresses(wlan_if_t vaphandle);

/**
 * sets the list of excluded MAC addresses. APs with addresses in this list will not be
 *  considered for association.
 *
 * @param vaphandle       : handle to the vap.
 * @param n_entries       : number of addresses passed in.
 * @parm macaddress       : array of MAC addresses.
 *
 *  @return 0 on success and -ve on failure.
 *           after this call is made, the MAC address list remains permanent until the next call to the
 *           same function. Any addresses previously in the list are removed.
 *           n_entries=0 clears the previous setting.
 */
int wlan_aplist_set_exc_macaddresslist(wlan_if_t vaphandle,
                                       u_int16_t n_entries,
                                       u_int8_t  (*macaddress)[IEEE80211_ADDR_LEN]);

/**
 * gets the list of excluded MAC addresses. APs with addresses in this list will not be
 *  considered for association.
 *
 * @param vaphandle       : handle to the vap.
 * @parm macaddress       : array of MAC addresses.
 *
 * @return  number of entries in the list.
 */
int wlan_aplist_get_exc_macaddresslist(wlan_if_t vaphandle,
                                       u_int8_t  (*macaddress)[IEEE80211_ADDR_LEN]);

/**
 * gets the number of entries in the list of excluded MAC addresses.
 *
 * @param vaphandle       : handle to the vap.
 *
 * @return number of entries in the list.
 */
int wlan_aplist_get_exc_macaddress_count(wlan_if_t vaphandle);

/**
 * gets one entry from the list of excluded MAC addresses.
 *
 * @param vaphandle       : handle to the vap.
 * @param index           : the index of the list item to be returned.
 * @param pmacaddress     : a pointer to the variable where the address will be copied.
 *
 * @return  0 if the index was valid and an address was returned, -ve otherwise.
 */
int wlan_aplist_get_exc_macaddress(wlan_if_t vaphandle, int index, u_int8_t **pmacaddress);

/**
 * get the desired BSS type
 *
 * @param vaphandle       : handle to the vap.
 * @return desired BSS type.
 */
enum ieee80211_opmode wlan_aplist_get_desired_bsstype(wlan_if_t vaphandle);


int wlan_aplist_set_tx_power_delta(wlan_if_t vaphandle, int tx_power_delta);

int wlan_aplist_set_bad_ap_timeout(wlan_if_t vaphandle, u_int32_t bad_ap_timeout);

/**
 * resets all aplist parameters to their default values.
 *
 * @param vaphandle       : handle to the vap.
 */
void wlan_aplist_init(wlan_if_t vaphandle);

typedef bool (* ieee80211_aplist_match_security_func) (void *, wlan_scan_entry_t );
/**
 * register a custom security check function.
 * if a custom security check function is  registred with this API
 * the registed function will be called to check if the security credentials
 * of the candidate match.
 * while building the  list of candidates. if no function
 * is registered then it uses internal security check function.
 * passing NULL for the handler deregisters the handler.
 * the handler function should synchronously return true if the entry
 * is a candidate else it should return false.
 *
 * @param vaphandle              : handle to the vap.
 * @param match_security_func    : handler function to be called back for compare.
 * @param arg                    : argument to bepassed back to the handler function.
 */
void wlan_aplist_register_match_security_func(wlan_if_t vaphandle, ieee80211_aplist_match_security_func match_security_func, void *arg);


/*
 * Public methods to build/free and query Candidate AP list.
 */

/**
 * Find the first candidate AP.
 *
 * @param vaphandle            : handle to the vap.
 * @param strict_filtering     : true indicates entries older than the most recent scan are allowed,
 *                                false indicates otherwise
 * @param candidate_entry      : pointer to memory location where to store the candidate entry.
 * @param maximum_age          : maximum age a scan entry may have to be included in the list.
 *
 * @return returns true if succesful, false otherwise.
 *   This function uses the current list of association parameters to find the first candidate AP
 *     in the AP list. It must not affect the candidate list.
 */
bool wlan_candidate_list_find(
    wlan_if_t            vaphandle,
    bool                 strict_filtering,
    wlan_scan_entry_t    *candidate_entry,
    u_int32_t            maximum_age
    );

/**
 * Build list of candidate APs.
 *
 * @param vaphandle            : handle to the vap.
 * @param strict_filtering     : true indicates entries older than the most recent scan are allowed,
 *                                false indicates otherwise
 * @param active_ap            : pointer to the active (home) AP.
 * @param maximum_age          : maximum age a scan entry may have to be included in the list.
 *
 * @return none    This function uses the current list of association parameters to build the candidate list.
 */
void wlan_candidate_list_build(wlan_if_t            vaphandle,
                               bool                 strict_filtering,
                               wlan_scan_entry_t    active_ap,
                               u_int32_t            maximum_age);

/**
 * Prioritize a particular BSSID in a list of candidate APs.
 *
 * @param vaphandle            : handle to the vap.
 * @param bssid                : pointer to the prioritized BSSID.
 *
 * @return none
 */
void wlan_candidate_list_prioritize_bssid(wlan_if_t         vaphandle,
                                          struct ether_addr *bssid);

/**
 * Clear list candidate APs
 *
 * @param vaphandle            : handle to the vap.
 * @return none.
 */
void wlan_candidate_list_free(wlan_if_t vaphandle);

/**
 * Number of entries in the candidate AP list.
 *
 * @param vaphandle            : handle to the vap.
 * @return  Number of entries in the candidate AP list
 */
int wlan_candidate_list_count(wlan_if_t vaphandle);

typedef int (* ieee80211_candidate_list_compare_func) (void *, wlan_scan_entry_t , wlan_scan_entry_t );

/**
 * register a custom compare function.
 * if a custom compare function is  registred with this API
 * the registed function will be called for comparing 2 candiates
 * while building the sorted list of candidates. if no function
 * is registered then it uses internal compare function.
 * passing NULL for the handler deregisters the handler.
 * the handler function should synchronously return 0 if ap1 is
 * preferred and -1 if ap2 is preferred.
 *
 * @param vaphandle       : handle to the vap.
 * @param compare_func    : handler function to be called back for compare.
 * @param arg             : argument to bepassed back to the handler function.
 */
void wlan_candidate_list_register_compare_func(wlan_if_t vaphandle, ieee80211_candidate_list_compare_func, void *arg);

/**
 * Retrieve a candidate AP.
 *
 * @param vaphandle            : handle to the vap.
 * @param index                : the index of the candidate AP to be returned. Valid values are
 *                               in the range 0-wlan_candidate_list_count().
 * @param                      : A candidate AP.
 *                             The scan entry return is valid until the aplist is freed.
 *                             the scan entry object is invalid once the aplist is freed.
 */
wlan_scan_entry_t wlan_candidate_list_get(wlan_if_t vaphandle, int index);

/**
 * get general statistics
 * @param vaphandle         : handle to the vap.
 * @return                  : pointer to vap statistics.
 */
const struct ieee80211_stats *wlan_gen_stats(wlan_if_t vaphandle);

/**
 * Get MAC statistics
 *
 * @param vaphandle         : handle to the vap.
 * @param is_mcast          : if set, get multicast MAC statistics,
 *                            otherwise, get unicast MAC statistics
 * @return     pointer to MAC statistics.
 */
const struct ieee80211_mac_stats *wlan_mac_stats(wlan_if_t vaphandle, int is_mcast);

/**
 * Get PHY statistics
 *
 * @param vaphandle         : handle to the vap.
 * @para mode               : the intended PHY mode.
 * @return  pointer to PHY statistics of phymode.
 */
const struct ieee80211_phy_stats *wlan_phy_stats(wlan_dev_t devhandle, enum ieee80211_phymode mode);

/**
 * Get timestamp of the last directed frame received or transmitted.
 *
 * @param vaphandle    : handle to the vap.
 * @return             : timestamp of the last directed frame.
 */
systime_t wlan_get_directed_frame_timestamp(wlan_if_t vaphandle);

/*
 * @Get timestamp of the last frame of any kind successfully transmitted or
 * received to/from the home AP.
 * ARGS :
 *  wlan_dev_t          : dev handle
 * RETURNS:             : timestamp of the last frame.
 */
systime_t wlan_get_last_ap_frame_timestamp(wlan_if_t vaphandle);

/**
 * Get timestamp of the data frame containing actual data that was received or
 *      transmitted. Null data frames are not counted. This is necessary for
 *      modules such as SCAN or LED which depend on data load.
 *
 * @param vaphandle    : handle to the vap.
 * @return             : timestamp of the last directed frame.
 */
systime_t wlan_get_traffic_indication_timestamp(wlan_if_t vaphandle);

/**
 * Indicates whether station is in connected state.
 *
 * @param vaphandle    : handle to the vap.
 * @return  true if connected, false otherwise.
 */
bool wlan_is_connected(wlan_if_t vaphandle);

#if ATH_SUPPORT_WRAP
/**
 * Indicates whether VAP is of type PSTA.
 *
 * @param vaphandle    : handle to the vap.
 * @return  true if connected, false otherwise.
 */
bool wlan_is_psta(wlan_if_t vaphandle);

/**
 * Indicates whether VAP is of type MSTA.
 *
 * @param vaphandle    : handle to the vap.
 * @return  true if connected, false otherwise.
 */
bool wlan_is_mpsta(wlan_if_t vaphandle);

/**
 * Indicates whether VAP is of type WRAP.
 *
 * @param vaphandle    : handle to the vap.
 * @return  true if connected, false otherwise.
 */
bool wlan_is_wrap(wlan_if_t vaphandle);

/**
 * Indicates number of WRAP VAP.
 *
 * @param vaphandle    : handle to the vap.
 * @return  number of wrap vaps.
 */
int wlan_vap_get_num_wraps(wlan_dev_t  comhandle);
#endif

/**
 * send ADD TSPEC Request action frame to the destination.
 *
 * @param vaphandle    : handle to the vap.
 * @param macaddr      : peer mac address
 * @param tsinfo       : TSPEC info
 */
int wlan_send_addts(wlan_if_t vaphandle, u_int8_t *macaddr, ieee80211_tspec_info *tsinfo);

/**
 * send ADD TSPEC Response action frame to the destination.
 *
 * @param vaphandle    : handle to the vap.
 * @param macaddr      : peer mac address
 * @param tsinfo       : TSPEC info
 * @param status       : response status code
 * @param dialog_token : response dialog token
 */
int wlan_send_addts_resp(wlan_if_t vaphandle, u_int8_t *macaddr, ieee80211_tspec_info *tsinfo, u_int8_t status, int dialog_token);

/**
 * send DEL TSPEC action frame to the destination.
 *
 * @param vaphandle    : handle to the vap.
 * @param macaddr      : peer mac address
 * @param tsinfo       : TSPEC info
 */
int wlan_send_delts(wlan_if_t vaphandle, u_int8_t *macaddr, ieee80211_tspec_info *tsinfo);

/**
 * send mgmt frame.
 *
 * @param vaphandle    : handle to the vap.
 * @param macaddr      : peer mac address
 * @param mgmt_frm     : mgmr_frm
 * @param len          : frame length
 */
int wlan_send_mgmt(wlan_if_t vaphandle, u_int8_t *macaddr, u_int8_t *mgmt_frm, u_int32_t len);

/*
 * @Set station tspec.
 * ARGS :
 *  wlan_if_t           : vap handle
 *  u_int_8             : value of tspec state
 * RETURNS:             : void.
 */
void wlan_set_tspecActive(wlan_if_t vaphandle, u_int8_t val);

/*
 * @Indicates whether station tspec is negotiated or not.
 * ARGS :
 *  wlan_if_t           : vap handle
 * RETURNS:             : value of tspec state.
 */
int wlan_is_tspecActive(wlan_if_t vaphandle);

/*
 * @start a reset: it will flush all the pending packets, disable the interrupt and put
 * hardware in a safe state for reset.
 *
 * @param vaphandle    : handle to the vap.
 * @param reset_req    : reset request
 */
int wlan_reset_start(wlan_if_t vaphandle, ieee80211_reset_request *reset_req);
#if ATH_SUPPORT_WRAP
/*
 * @set a wrap key: it will install clear key for WRAP-AP in the key cache
 *
 * @param vaphandle    : handle to the vap.
 */
int wlan_wrap_set_key(wlan_if_t vaphandle);

/*
 * @del a wrap key: it will delete key for WRAP-AP in the key cache
 *
 * @param vaphandle    : handle to the vap.
 */
int wlan_wrap_del_key(wlan_if_t vaphandle);
#endif

/*
 * test command for turning various knobs in firmware
 * @param vaphandle  Vap interface handle
 * @param test argument
 * @param test value
 */
int wlan_ar900b_fw_test(wlan_if_t vaphandle, u_int32_t arg, u_int32_t value);

/*
 * Dynamically set the antenna switch
 * @param vaphandle  Vap interface handle
 * @param antenna control common1
 * @param antenna control common2
 */
int wlan_set_antenna_switch(wlan_if_t vaphandle, u_int32_t ctrl_cmd_1, u_int32_t ctrl_cmd_2);

/*
 * set the user defined control table
 * @param vaphandle  Vap interface handle
 * @param table array
 * @param array length
 */
int wlan_set_ctl_table(wlan_if_t vaphandle, u_int8_t *ctl_array, u_int16_t ctl_len);

/**
 * reset
 *
 * @param vaphandle    : handle to the vap.
 * @param reset_req    : reset request
 */
int wlan_reset(wlan_if_t vaphandle, ieee80211_reset_request *reset_req);

/**
 * complete a reset: it will restore the interrupt and put hardware in a good state for tx/rx.
 *
 * @param vaphandle    : handle to the vap.
 * @param reset_req    : reset request
 */
int wlan_reset_end(wlan_if_t vaphandle, ieee80211_reset_request *reset_req);

/**
 * populates chain specific noise floor values.
 *  @param vaphandle   : handle to the vap .
 *  @param nfBuf       : Buffer to store per chain noise floor (optional)
 * @return
 *  returns noise floor.
 */
void
wlan_get_noise_floor(wlan_if_t vaphandle, int16_t *nfBuf);

/**
 * read the noise floor of a specific channel
 *  @param vaphandle   : handle to the vap .
 *  @param freq        : frequency
 *  @param flags       : channel flags;
 * @return
 *  returns noise floor.
 */
int16_t
wlan_get_chan_noise_floor(wlan_if_t vaphandle, u_int16_t freq, u_int32_t flags);

/*
 * copy the beacon frame: to make a copy of the current beacon frame of our SoftAP.
 * ARGS:
 *  @param wlan_if_t           : vap handle, must be a SoftAP.
 *  @param in_buf_size         : size of the input buffer
 *  @param required_buf_size   : pointer to return the required buffer size
 *  @param buffer              : input buffer to store the beacon frame copy.
 *
 */
int wlan_copy_ap_beacon_frame(wlan_if_t vaphandle, u_int32_t in_buf_size, u_int32_t *required_buf_size, void *buffer);

/**
 * register a acs event handler.
 *  @param vaphandle          : handle to the vap .
 *  @param evhandler          : acs event handler
 *  @param arg                : argument passed back via the evnt handler
 *  @return
 *  on success returns 0.
 *  on failure returns a negative value.
 *  allows more than one event handler to be registered.
 */
int wlan_autoselect_register_event_handler(wlan_if_t                    vaphandle,
                                           ieee80211_acs_event_handler evhandler,
                                           void                         *arg);


/**
 * register a acs scan timer  handler.
 *  @param ieeehandle          : handle to the com structure .
 *  @param evhandler          : acs event handler
 *  @param arg                : argument passed back via the evnt handler
 *  @return
 *  on success returns 0.
 *  on failure returns a negative value.
 *  allows more than one event handler to be registered.
 */
int wlan_autoselect_register_scantimer_handler(void *                    ieeehandle,
                                               ieee80211_acs_scantimer_handler  evhandler,
                                               void                         *arg);



/**
 * unregister a acs event handler.
 * @param vaphandle           : handle to the vap .
 * @param evhandler           : acs event handler
 * @param arg                : argument passed back via the evnt handler
 * @return
 *  on success returns 0.
 *  on failure returns a negative value.
 */
int wlan_autoselect_unregister_event_handler(wlan_if_t                    vaphandle,
                                             ieee80211_acs_event_handler evhandler,
                                             void                         *arg);

/**
 * start auto select AP channel
 *
 * @param vaphandle    : handle to the vap.
 * @return:
 *  on success returns 0.
 *  on failure returns a negative value.
 */
int wlan_autoselect_find_infra_bss_channel(wlan_if_t vaphandle);

/**
 * try to start an HT40 BSS
 *
 * @param vaphandle    : handle to the vap.
 * @return:
 *  on success returns 0.
 *  on failure returns a negative value.
 */
int wlan_attempt_ht40_bss(wlan_if_t vaphandle);

/**
 * indicates whether acs is in progress.
 * @param vaphandle  : handle to the vap .
 * @return
 *  returns 1 if acs in progress.
 *  returns 0 otherwise.
 */
int wlan_autoselect_in_progress(wlan_if_t vaphandle);

/**
 * cancel ACS
 *
 * @param vaphandle    : handle to the vap.
 * @return:
 *  on success returns 1.
 *  on failure returns 0.
 */
int wlan_autoselect_cancel_selection(wlan_if_t vaphandle);

/**
 * Generates ACS scan report.
 * @param vaphandle  : handle to the vap .
 * @param acs_r: stores the acs report entry.
 * @return
 *  returns 0 .
 */
int wlan_acs_scan_report(wlan_if_t vaphandle, void *acs_r);

/**
 * @brief block channel list for ACS
 *
 * @param vaphandle
 * @param acs_block_chan_list
 *
 * @return +ve values in case of success
 */
int wlan_acs_block_channel_list(wlan_if_t vap,u_int8_t *chan,u_int8_t nchan);

#if ATH_CHANNEL_BLOCKING
/**
 * @brief find un-blocked channel with same channel number and phymode
 *
 * @param vaphandle
 * @param channel
 * @param phymode
 *
 * @return channel
 */
struct ieee80211_channel *
wlan_acs_channel_allowed(wlan_if_t vap, struct ieee80211_channel *c, enum ieee80211_phymode mode);
#endif

/**
 * @brief channel hopping parameter
 *
 * @param vaphandle
 * @param int param i.e set get
 * @param int cmd i.e type
 * @param int return val in case of get
 *
 * @return status
 */
int wlan_acs_param_ch_hopping(wlan_if_t vap, int param, int cmd, int *val);

/**
 * Check if the mgmt frame has wsc ie.
 * @param   wbuf   : mgmt wbuf
 * @return
 *  returns 1 if wsc ie is present.
 *  returns 0 otherwise.
 */
int wlan_frm_haswscie(wbuf_t wbuf);

/**
 * get essid of vap bss node.
 * @param   vaphandle   : handle to the vap
 * @param   essid   :  pointer to ssid struct
 * @return
 */
void
wlan_get_bss_essid(wlan_if_t vaphandle, ieee80211_ssid *essid);

/**
 * get tsf32 of vap.
 * @param   vaphandle   : handle to the vap
 * @return tsf32
 */
u_int32_t wlan_get_tsf32(wlan_if_t vaphandle);

/**
 * set rate table for ViVo AC - part of IQUE feature set
 * @param   vaphandle   : handle to the vap
 * @param   rt_index    : index to the rate table
 * @param   per         : PER high threshold
 * @param   probe_intvl : interval to send the probing frames
 * @return  0
 */
int wlan_set_rtparams(wlan_if_t vaphandle, u_int8_t rt_index, u_int8_t per, u_int8_t probe_intvl);

/**
 * set AC parameters for IQUE feature set
 * @param   vaphandle   : handle to the cap
 * @param   ac          : AC
 * @param   use_rts     : use RTS or not for this AC
 * @param   aggrsize_scaling    : aggregation scaling for this AC
 * @param   min_kbps    : minimum kbps
 * @return  0
 */
int wlan_set_acparams(wlan_if_t vaphandle, u_int8_t ac, u_int8_t use_rts, u_int8_t aggrsize_scaling, u_int32_t min_kbps);

/**
 * set HBR parameters for IQUE feature set
 * @param   vaphandle   : handle to the vap
 * @param   ac          : AC
 * @param   enable      : enable or disable HBR
 * @param   per_low     : PER low threshold to resume the blocked transmission
 * @return  0
 */
int wlan_set_hbrparams(wlan_if_t vaphandle, u_int8_t ac, u_int8_t enable, u_int8_t per_low);

/**
 * dump the hbr list table with states for each node
 * @param   vaphandle   :  handle to the vap
 * @return  to print out the hbr table with state for each node
 */
void wlan_get_hbrstate(wlan_if_t vaphandle);

/**
 * return hardware beacon processing active state
 * @param   vaphandle   :  handle to the vap
 * @return  1 if hardware beacon processing is active, else 0
 */
int wlan_is_hwbeaconproc_active(wlan_if_t vaphandle);

/**
 * add mcast enhancement deny entry
 * @param   vaphandle   :  handle to the vap
 * @param   deny_address:   IP address and mask of the deny group
 * @return  0
 */
int wlan_set_me_denyentry(wlan_if_t vaphandle, int *deny_address);

/**
 * dump the hbr list table with states for each node
 * @param   vaphandle   :  handle to the vap
 * @param frm           : argument passed back
 * @return:
 *  on success returns 0.
 *  on failure returns a negative value.
 */
int wlan_get_ie(wlan_if_t vaphandle, u_int8_t *frm);

/**
* To find out if VAP is proxySTA VAP
* @param   vaphandle   :  handle to the vap
* @return  1 if proxySTA VAP else 0
*/
int wlan_is_proxysta(wlan_if_t vaphandle);

/**
* Enable/Diable proxySTA VAP
* @param   vaphandle   :  handle to the vap
* @param   enable   :  1 enable proxySTA, 0 disable
* @return   0 if success else non-zero for error.
*/
int wlan_set_proxysta(wlan_if_t vaphandle, int enable);

/**
 * dump the hbr list table with states for each node
 * @param   vaphandle   :  handle to the vap
 * @param   txpowlevel   :  tw power level
 * @param   addr              :  peer mac address
 */
void wlan_node_set_txpwr(wlan_if_t vaphandle, u_int16_t txpowlevel, u_int8_t *addr);

/**
 * returns CTL by country.
 * @param  devhandle    : handle to the radio .
 * @return
 *  on success returns CTL.
 */
u_int8_t wlan_get_ctl_by_country(wlan_dev_t devhandle, u_int8_t *country, bool is2G);

/**
 * Checks if hw txQ is emptry or not.
 *  @param vaphandle   : handle to the vap .
 * @return
 *  returns TRUE if hw TxQ is empty
 *          FALSE else.
 */
bool
wlan_is_txq_empty(wlan_if_t vaphandle);

/*
 * Configure NAWDS peer repeater
 * @param   vaphandle: handle to the vap
 * @param   macaddr  : mac address for the peer NAWDS repeater
 * @param   flags    : capability of the peer NAWDS repeater
 */
int wlan_nawds_config_mac(wlan_if_t vaphandle, char *macaddr, u_int32_t flags);

/*
 * Delete NAWDS peer repeater
 * @param   vaphandle: handle to the vap
 * @param   macaddr  : mac address for the peer NAWDS repeater
 */
int wlan_nawds_delete_mac(wlan_if_t vaphandle, char *macaddr);

/*
 * Get configuration of a specific NAWDS peer repeater
 * @param   vaphandle: handle to the vap
 * @param   num      : index of the specific NAWDS repeater
 * @param   macaddr  : buffer to store the mac address of the peer NAWDS repeater
 * @param   flags    : buffer to store capability flag of the peer NAWDS repeater
 */
int wlan_nawds_get_mac(wlan_if_t vaphandle, int num, char *macaddr, int *flags);

/*
 * Set NAWDS related parameters
 * @param   vaphandle: handle to the vap
 * @param   param    : specify which parameter to set
 * @param   val      : new NAWDS parameter passed as a pointer
 */
int wlan_nawds_set_param(wlan_if_t vaphandle, enum ieee80211_nawds_param param, void *val);

/*
 * Get NAWDS related parameters
 * @param   vaphandle: handle to the vap
 * @param   param    : specify which parameter to get
 * @param   val      : buffer to store current NAWDS parameter
 */
int wlan_nawds_get_param(wlan_if_t vaphandle, enum ieee80211_nawds_param param, void *val);


#if defined (UMAC_SUPPORT_WDS) || (ATH_PERF_PWR_OFFLOAD != 0)
/*
 * Add entry to WDS AST table
 * @param   vaphandle: handle to the vap
 * @param   destmac  : destination mac address
 * @param   peermac  : peer address (next hop)
 */
int wlan_wds_add_entry(wlan_if_t vaphandle, char *destmac, char *peermac);

/*
 * Delete rentry from WDS AST table
 * @param   vaphandle: handle to the vap
 * @param   destmac  : destination mac address
 */
int wlan_wds_del_entry(wlan_if_t vaphandle, char *destmac);
#endif

/*
 * Set TFS Request Params and send TFS Request
 * @param   vaphandle: handle to the vap
 * @param   tfsreq    : tfs request
 */
int wlan_wnm_set_tfs(wlan_if_t vaphandle, void *tfsreq);

/*
 * Check if WNM is enabled. Returns 1 if enabled, otherwise zero.
 * @param   vaphandle: handle to the vap
 */

int wlan_wnm_vap_is_set(wlan_if_t vaphandle);

/*
 * Check if the frame has to be filtered.
 * @param   vaphandle: handle to the vap
 * @param   tfsreq    : tfs request
 */

int wlan_wnm_tfs_filter(wlan_if_t vaphandle, wbuf_t wbuf);


/*
 * Deletes TFS Request Params and send TFS delete Request
 * @param   vaphandle: handle to the vap
 * @param   tfsid   : tfs request id
 */
int wlan_wnm_delete_tfs_req(struct ieee80211_node *ni, u_int8_t tfsid);

/*
 * Free TFS Queue
 * @param   head      : head of the queu
 */
int wlan_wnm_free_tfs(void *head);

/*
 * Free TFS Response Queue
 * @param   head      : head of the queu
 */
int wlan_wnm_free_tfsrsp(void *head);

/*
 * Set FMS Request Params and send TFS Request
 * @param   vaphandle: handle to the vap
 * @param   fmsreq    : fms request
 */
int wlan_wnm_set_fms(wlan_if_t vaphandle, void *fmsreq);

/*
 * Set BSSMaxIdle Params
 * @param   vaphandle: handle to the vap
 * @param   bssmax    : bssmax request
 */
int wlan_wnm_set_bssmax(wlan_if_t vaphandle, void *bssmax);

/*
 * Get BSSMaxIdle Params
 * @param   vaphandle: handle to the vap
 * @param   bssmax    : bssmax params from driver
 */
int wlan_wnm_get_bssmax(wlan_if_t vaphandle, void *bssmax);

/*
 * Set Tim Broadcast Request Params
 * @param   vaphandle: handle to the vap
 * @param   timbcast    : Tim Broadcast params
 */
int wlan_wnm_set_timbcast(wlan_if_t vaphandle, void *timbcast);

/*
 * Get Tim Broadcast Request Params
 * @param   vaphandle: handle to the vap
 * @param   timbcast    : Tim Broadcast Request
 */
int wlan_wnm_get_timbcast(wlan_if_t vaphandle, void *timbcast);

/*
 * Set BSS Termination Request Params
 * @param   vaphandle: handle to the vap
 * @param   bssterm  : BSS Termination Request
 */
int wlan_wnm_set_bssterm(wlan_if_t vaphandle, void *bssterm);


/*
 * Resume host managed WDS address to normal
 * @param   vaphandle: handle to the vap
 * @param   macaddr  : mac address of the WDS station node
 */
int wlan_hmwds_remove_addr(wlan_if_t vaphandle, u_int8_t *macaddr);

/*
 * Add host managed WDS address
 * @param   vaphandle       : handle to the vap
 * @param   wds_ni_macaddr  : mac address of the WDS station node
 * @param   wds_macaddr     : mac address to add
 * @param   wds_macaddr_cnt : number of mac address
 */
int wlan_hmwds_add_addr(wlan_if_t vaphandle, u_int8_t *wds_ni_macaddr, u_int8_t *wds_macaddr, u_int16_t wds_macaddr_cnt);

/*
 * Resume host managed WDS address to normal
 * @param   vaphandle: handle to the vap
 * @param   macaddr  : mac address of the WDS station node or WDS address
 */
int wlan_hmwds_reset_addr(wlan_if_t vaphandle, u_int8_t *macaddr);

/*
 * Resume all host managed WDS address to normal
 * @param   vaphandle: handle to the vap
 */
int wlan_hmwds_reset_table(wlan_if_t vaphandle);

/*
 * Read host managed WDS address behind the WDS node
 * @param   vaphandle       : handle to the vap
 * @param   wds_ni_macaddr  : mac address of the WDS station node
 * @param   buf             : buffer for storing the MAC list.
 * @param   buflen          : buffer length
 */
int wlan_hmwds_read_addr(wlan_if_t vaphandle, u_int8_t *wds_ni_macaddr, u_int8_t *buf, u_int16_t *buflen);

/*
 * Read all WDS entries
 * @param   vaphandle : handle to the vap
 * @param   wds_table : filled in with WDS entries
 */
int wlan_wds_read_table(wlan_if_t vaphandle, struct ieee80211_wlanconfig_wds_table *wds_table);

/*
 * Read all WDS entries
 * @param   vaphandle : handle to the vap
 */
int wlan_wds_dump_wds_addr(wlan_if_t vaphandle);


/*
 * Enable ald statistics for a station with give MAC address
 * @param   vaphandle : handle to the vap
 * @param   macaddr   : Station's MAC address
 * @param   enable    : 1: enable, 2: disable
 */
int wlan_ald_sta_enable(wlan_if_t vaphandle, u_int8_t *macaddr, u_int32_t enable);

/*
 * Get current phytype
 * @param   vaphandle: handle to the vap
 */
int wlan_get_current_phytype(struct ieee80211com *ic);

/*
 * Check for node specific flags and return TRUE or FLASE
 */
bool wlan_node_has_flag(struct ieee80211_node *ni, u_int16_t flag);

/*
 * This will se the tx power limit
 */
void
wlan_setTxPowerLimit(struct ieee80211com *ic, u_int32_t limit, u_int16_t tpcInDb, u_int32_t is2GHz);

#if UMAC_SUPPORT_RRM
/**
 * send beacon measurement report request
 * @param vap       :  handle to the vap
 * @param macaddr   : macaddress of the station
 * @param binfo     : pointer to beacon measurement report request
 *                    information struct
 */
int wlan_send_beacon_measreq(wlan_if_t vap, u_int8_t *macaddr, ieee80211_rrm_beaconreq_info_t *binfo);
/**
 * set generation of rrm stats from sliding window
 * @param vap       :  handle to the vap
 * @param val       :  value of param
 *
 */
/**
 * send channel load request
 * @param vap       :  handle to the vap
 * @param macaddr   : macaddress of the station
 * @param chnfo     : pointer to channel load request
 * 	              information struct
 */
int wlan_send_chload_req(wlan_if_t vap, u_int8_t *macaddr, ieee80211_rrm_chloadreq_info_t *chinfo);

/**
 * clear wmm params
 *
 * @param vap          : vap pointer
 * @param isbss        : 1:bss param 0:local param
 *
 */
void wlan_clear_qos(struct ieee80211vap *vap, u_int32_t isbss);

/**
  * clear node's min and max rssi
  * @param vap  : handle to the vap
  */
void ieee80211_clear_min_max_rssi (wlan_if_t vaphandle);

/**
 *  Set chainmask per sta
 *  @param vaphandle     : handle to the vap.
 *  @param macaddress : mac address of the station
 *  @param nss : nss value. Sets the txchainmask for the node with the macaddress mentioned.
 */
int wlan_set_chainmask_per_sta(wlan_if_t vaphandle, u_int8_t *macaddr,u_int8_t nss);

/**
 * send sta statistics request
 * @param vap       :  handle to the vap
 * @param macaddr   : macaddress of the station
 * @param binfo     : pointer to sta stats request
 *                    information struct
 */

int wlan_send_stastats_req(wlan_if_t vap, u_int8_t *macaddr, ieee80211_rrm_stastats_info_t *stastats);

/**
 * send noise histogram request
 * @param vap       :  handle to the vap
 * @param macaddr   : macaddress of the station
 * @param binfo     : pointer to noise histogram  request
 *                    information struct
 */
int wlan_send_nhist_req(wlan_if_t vap, u_int8_t *macaddr, ieee80211_rrm_nhist_info_t *nhist);

/**
 * send location request
 * @param vap       :  handle to the vap
 * @param macaddr   : macaddress of the station
 * @param binfo     : pointer to lc  request
 *                    information struct
 */
int wlan_send_lci_req(wlan_if_t vap, u_int8_t *macaddr, ieee80211_rrm_lcireq_info_t *lc_info);
/**
 * send frame report request
 * @param vap       :  handle to the vap
 * @param macaddr   : macaddress of the station
 * @param fr_info   : pointer to frame  request
 *                    information struct
 */
int wlan_send_frame_request(wlan_if_t vap, u_int8_t *macaddr, ieee80211_rrm_frame_req_info_t *fr_info);

/**
 * get the RRM stats
 * @param vap       :  handle to the vap
 * @param macaddr   : macaddress of the station
 * @param rrmstats  : pointer to rrmstats
 *                    information struct
 */

int wlan_get_rrmstats(wlan_if_t vaphandle, u_int8_t *macaddr,
                      ieee80211_rrmstats_t *rrmstats);

/**
 * get the MAC address of the RRM capable STA
 * @param vap       : handle to the vap
 * @param macaddr   : macaddress sent from upper layer
 * @param rrmstats  : pointer to store the STA count and address
 *
 */
int wlan_get_rrm_sta_list(wlan_if_t vaphandle, u_int8_t *macaddr, int*param);
/**
 * get the beacon report
 * @param vap       : handle to the vap
 * @param macaddr   : macaddress of the station
 * @index           : index of the beacon table.
 * @param rrmstats  : pointer to bcnrpt information struct
 */
int wlan_get_bcnrpt(wlan_if_t vaphandle, u_int8_t *macaddr, u_int32_t index,
                      ieee80211_bcnrpt_t *bcnrpt);

/**
 * send TSM report request
 * @param vap       :  handle to the vap
 * @param macaddr   : macaddress of the station
 * @param tsminfo   : pointer to TSM measurement report request
 *                    information struct
 */
int wlan_send_tsm_measreq(wlan_if_t vap, u_int8_t *macaddr, ieee80211_rrm_tsmreq_info_t *tsminfo);

/**
 * send neig report
 * @param vap       :  handle to the vap
 * @param macaddr   : macaddress of the station
 * @param neiginfo  : pointer to neigh request info
 *                    information struct
 */
int wlan_send_neig_report(wlan_if_t vap, u_int8_t *macaddr,ieee80211_rrm_nrreq_info_t *neiginfo);

/**
 * send lm req
 * @param vap       :  handle to the vap
 * @param macaddr   : macaddress of the station
 */
int wlan_send_link_measreq(wlan_if_t vap, u_int8_t *macaddr);
/**
 * send bss transition management request
 * @param vap       :  handle to the vap
 * @param macaddr   : macaddress of the station
 * @param neiginfo  : pointer to bstm request info
 *                    information struct
 */

#endif
int wlan_send_bstmreq(wlan_if_t vap, u_int8_t *macaddr,struct ieee80211_bstm_reqinfo *bstmreq);

/**
 * send bss transition management request requesting the STA
 * transition to a BSS on the provided candidate transition list
 * @param vap       :  handle to the vap
 * @param macaddr   : macaddress of the station
 * @param bstmreq  : pointer to bstm request info target
 *                    struct (includes candidate list)
 */
int wlan_send_bstmreq_target(wlan_if_t vap, u_int8_t *macaddr,struct ieee80211_bstm_reqinfo_target *bstmreq);

/**
 * Add traffic stream
 * @param vap         :  handle to the vap
 * @param macaddr     :  macaddress of the station
 * @param tspecie     :  pointer to tspecie
 */
int wlan_admctl_addts(wlan_if_t vap, u_int8_t *macaddr, u_int8_t *tspecie);

/**
 * Delete traffic stream
 * @param vap         :  handle to the vap
 * @param macaddr     :  macaddress of the station
 * @param tid         :  tid for the traffic stream
 */
int wlan_admctl_send_delts(wlan_if_t vap, u_int8_t *macaddr, u_int8_t tid);

/**
 * Add station node
 * @param vap         :  handle to the vap
 * @param macaddr     :  macaddress of the station
 * @param auth_alg    :  auth alg used for this node
 */
int wlan_add_sta_node(wlan_if_t vap, const u_int8_t *macaddr, u_int16_t auth_alg);

/*
 * Set ACL Policy
 * @param   vap           :   handle to the vap
 * @param   policy        :   ACL policy
 * @param   acl_list_id   :   ID of the ACL list
 */
int wlan_set_acl_policy(wlan_if_t vap, int policy, u_int8_t acl_list_id);

/*
 * Get ACL Policy
 * @param   vap           :   handle to the vap
 * @param   policy        :   ACL policy
 * @param   acl_list_id   :   ID of the ACL list
 */
int wlan_get_acl_policy(wlan_if_t vap, u_int8_t acl_list_id);

/*
 * Add a MAC Address to ACL
 * @param   vap           :   handle to the vap
 * @param   mac           :   MAC Address to be added
 * @param   acl_list_id   :   ID of the ACL list
 */
int wlan_set_acl_add(wlan_if_t vap, const u_int8_t mac[IEEE80211_ADDR_LEN], u_int8_t acl_list_id);

/*
 * Delete a MAC Address from ACL
 * @param   vap           :   handle to the vap
 * @param   mac           :   MAC Address to be deleted
 * @param   acl_list_id   :   ID of the ACL list
 */
int wlan_set_acl_remove(wlan_if_t vap, const u_int8_t mac[IEEE80211_ADDR_LEN], u_int8_t acl_list_id);

/*
 * Get ACL
 * @param   vap           :   handle to the vap
 * @param   mac_list      :   buffer
 * @param   len           :   buffer length
 * @param   num_mac       :   Total number of mac addresses in the ACL list
 * @param   acl_list_id   :   ID of the ACL list
 */
int wlan_get_acl_list(wlan_if_t vap, u_int8_t *mac_list, int len, int *num_mac, u_int8_t acl_list_id);

/**
 * @set timeout for pause notification .
 *
 *  @param vaphandle     : handle to the vap
 *  @param inact_time    : inactivity time in msec to enter powersave.
 *  @return 0  on success and -ve on failure.
 */
int wlan_set_ips_pause_notif_timeout(wlan_if_t vaphandle, u_int16_t pause_notif_timeout);

/**
 * @get timeout for pause notification .
 *
 *  @param vaphandle     : handle to the vap.
 *  @return pause notification timeout.
 */
u_int16_t wlan_get_ips_pause_notif_timeout(wlan_if_t vaphandle);

/**
 * get the traffic statistics like the received signal level, max,min and median value of the Station
 * @param vap       : handle to the vap
 * @param macaddr   : macaddress sent from upper layer
 * @param param     : pointer to store the STA count and address and the noise statistics to be sent to the user space
 */
int wlan_get_traffic_stats(wlan_if_t vaphandle, u_int8_t *macaddr, int *param);

#ifdef ATH_SUPPORT_HTC
/*
 * Set vap->iv_bsschan to the one needed.
 * @param   vaphandle: handle to the vap
 * @param   chan     : ieee channel #
 * @return
 *  on success returns 0.
 *  on failure returns a negative value.
 */
int wlan_reset_iv_chan(wlan_if_t vaphandle, int chan);
#endif

/*
 * Find best channels based on (prior) scan results
 * @param   vaphandle: handle to the vap
 * @param   *bestfreq: array of size 3;
 *                   : [0] - best 11na freq
 *                   : [1] - best 11ng freq
 *                   : [2] - best overall freq
 * @return
 *  on success returns 0.
 *  on failure returns a negative value.
 */

int wlan_acs_find_best_channel(wlan_if_t vaphandle,int *bestfreq,int num);

/**
 * get active multicast management frame cipher type (STA only).
 * @param   vaphandle   : handle to a vap
 * @return the active (current) multicast cipher.
 */
ieee80211_cipher_type wlan_get_current_assoc_comeback_time(wlan_if_t vaphandle);

/*
 * Set hardware MFP QOS feature
 * @param   vap: handle to the vap
 * @param   dot11w: the feature to set;
 * @return
 *  None.
 */
void wlan_crypto_set_hwmfpQos(struct ieee80211vap *vap, u_int32_t dot11w);

/*
 * Get the list of BSS channel used by other active VAPs. Note that as VAPs go up and down,
 * this list can change with time.
 * bss_freq_list contains an array of frequencies of the BSS channels used by
 * other active VAPs. On function entry, list_size contains the size of array bss_freq_list.
 * On exit, list_size contains the size of BSS frequency list filled. If there are no active VAPs,
 * then list_size will be zero.
 */
int wlan_get_bss_chan_list(wlan_dev_t devhandle, u_int32_t *bss_freq_list, int *list_size);



/**
 * Start acs scan to generate report.
 * @param vaphandle  : handle to the vap .
 * @param val: start/stop.
 * @param cmd
 * @param set/get
 * @return
 *  returns 0 for success other .
 */
int wlan_acs_start_scan_report(wlan_if_t vap, int set, int cmd, int val);

/**
 * set 2.4G innetwork informaiton
 * @param vaphandle  : handle to the vap .
 * @param mac: mac address.
 * @param channel
 * @return
 *  returns 0 for success other .
 */
int wlan_acs_set_innetwork_2g(struct ieee80211com *ic, const u_int8_t *macaddr, int channel);

/**
 * @brief to get in network information
 *
 * @param ic
 * @param databuffer
 * @param workflow - 0:get the total index 1:to get the data.
 * @return EOK in case of success
 */
int wlan_acs_get_innetwork_2g(struct ieee80211com *ic, void *data, int workflow);


/**
 * @brief
 *
 * @param vaphandle
 * @param extra:- list of channel to set
 *
 * @return 0 if setting is succefull otherwise error code
 */
int wlan_acs_set_user_chanlist(wlan_if_t vaphandle, u_int8_t *extra);

/**
 * @brief get user set channel list for acs scan report
 *
 * @param vaphandle
 * @param chanlist channel list to report
 *
 * @return lenght of channel list
 */
int wlan_acs_get_user_chanlist(wlan_if_t vaphandle, u_int8_t *chanlist);

#if UMAC_SUPPORT_QUIET

/**
 * set vap quiet parameter.
 *
 *  @param vaphandle     : handle to the vap.
 *  @param val           : 0 to disable, 1 to enable
 *  @return 0  on success and -ve on failure.
 */
int wlan_quiet_set_param(wlan_if_t vaphandle, u_int32_t val);

/**
 * get vap quiet parameter.
 *
 *  @param vaphandle     : handle to the vap.
 *  @return value of the parameter.
 */
u_int32_t wlan_quiet_get_param(wlan_if_t vaphandle);

#endif /* UMAC_SUPPORT_QUIET */

void wlan_crypto_set_hwmfpQos(struct ieee80211vap *vap, u_int32_t dot11w);

void wlan_get_vap_addr(wlan_if_t vaphandle, u_int8_t *mac);


int wlan_send_rssi(struct ieee80211vap *vap, u_int8_t *macaddr);

/**
 * get mode of node/station
 * @param node  : node handle.
 * @return mode.
 */
u_int16_t wlan_node_get_mode(wlan_node_t node);

/**
 * get number of vaps for whome iv_active is set
 * @param vaphandle    : handle to the vap.
 * @return  number of active vaps.
 */
u_int32_t  ieee80211_get_num_active_vaps(wlan_dev_t  comhandle);

#if ATH_DEBUG
int wlan_offchan_tx_test(wlan_if_t vaphandle, void *netdev, u_int32_t chan,
                                u_int16_t dwell_time, u_int16_t scan_requestor, u_int32_t *scan_id);
#endif /* ATH_DEBUG */

/**
 * To set fips test mode
 * * @param vaphandle    : handle to the vap.
 * * @param fips_buf     : fips buffer input from application to firmware
 * @return   status.
 */
#if ATH_SUPPORT_FIPS
int wlan_set_fips(wlan_if_t vaphandle, void *fips_buf);
#endif

/**
 * set simple configuration parameter.
 *
 * @param devhandle       : handle to the vap.
 * @param param           : simple config parameter.
 * @param val             : value of the parameter.
 * @return 0  on success and -ve on failure.
 */
int wlan_set_mbo_param(wlan_if_t vap, u_int32_t param, u_int32_t val);

/**
 * set bssidpref
 *
 * @param devhandle       : handle to the vap.
 * @param param           : bssid pref
 * @return 0  on success and -ve on failure.
 */

int wlan_set_bssidpref(wlan_if_t vap, struct ieee80211_user_bssid_pref *userbssidpref);

/**
 * get simple configuration parameter.
 *
 * @param devhandle       : handle to the vap.
 * @param param           : simple config paramaeter.
 * @return value of the parameter.
 */
u_int32_t wlan_get_mbo_param(wlan_if_t vap, u_int32_t param);

#if ATH_SUPPORT_SPLITMAC
int
wlan_mon_addmac(wlan_if_t vaphandle, u_int8_t *mac);

int
wlan_mon_listmac(wlan_if_t vaphandle);

int
wlan_mon_delmac(wlan_if_t vaphandle, u_int8_t *mac);
#endif /* ATH_SUPPORT_SPLITMAC */

int
wlan_set_monitor_filter(struct ieee80211com* ic, u_int32_t filter_type);

#if ATH_SUPPORT_NAC
/*
 * set/get vendor ie related parameters
 * @param   vaphandle: handle to the vap
 * @param   param    : specify which sub parameter to set
 * @param   nac      : new nac mac addr list to add/del
 */
int wlan_set_nac(wlan_if_t vaphandle, enum ieee80211_nac_param param, void *nac);

int wlan_list_nac(wlan_if_t vaphandle, enum ieee80211_nac_param param, void *nac);
#endif

#if ATH_SUPPORT_DYNAMIC_VENDOR_IE
/*
 * set/get vendor ie related parameters
 * @param   vaphandle: handle to the vap
 * @param   param    : specify which sub parameter to set
 * @param   vie      : new NAWDS parameter passed as a pointer
 * @param   ftype    : get vie from specific frame type
 */
int wlan_set_vendorie(wlan_if_t vaphandle, enum ieee80211_vendor_ie_param param, void *vie);

int wlan_get_vendorie(wlan_if_t vaphandle, void *vendor_ie, enum _ieee80211_frame_type ftype, u_int32_t *ie_len, u_int8_t *temp_buf);

#endif

void wlan_vap_down_check_beacon_interval(struct ieee80211vap *vap, enum ieee80211_opmode opmode);

void wlan_vap_up_check_beacon_interval(struct ieee80211vap *vap, enum ieee80211_opmode opmode);

bool tx_pow_mgmt_valid(int frame_subtype,int *tx_power);

/*struct ieee80211_scan_entry se_flag definitions*/
#define IEEE80211_SE_FLAG_IS_MESH               0x1
#define IEEE80211_SE_FLAG_INTERSECT_DONE        0x2
void wlan_scan_entry_set_flags(wlan_scan_entry_t scan_entry, u_int32_t flags);
u_int32_t wlan_scan_entry_get_flags(wlan_scan_entry_t scan_entry);


/*
 * MLME Get current state of the connection state machine.
 *
 * @param  vaphandle    : handle to the vap.
 * @param  param        : Connection SM state.
 * @param  value        : address of a variable to save the current state.
 * @return              : The current connection state.
 */
void wlan_mlme_sm_get_curstate(wlan_if_t vaphandle, int param, int *value);

/*
 * MLME Number of AP vap(s) in RUN state.
 *
 * @param  vaphandle    : handle to the vap.
 * @return              : Number of AP vap(s) in RUN state.
 */
int wlan_mlme_num_apvap_running(wlan_if_t vaphandle);

/*
 * MLME Check is the STA vap is the main STA not the proxy STA vap.
 *
 * @param  vaphandle    : handle to the vap.
 * @return              : Return true if the sta vap is the main STA vap.
 */
bool wlan_mlme_is_vap_main_sta(wlan_if_t vaphandle);

/*
 * MLME TXCSA(IEEE80211_CSH_OPT_CSA_APUP_BYSTA) is set by the User.
 *
 * @param  vaphandle    : handle to the vap.
 * @return              : Return true if the TXCSA bit is set to 1.
 */
bool wlan_mlme_is_txcsa_set(wlan_if_t vaphandle);

/*
 * MLME REPEATER_CAC(IEEE80211_CSH_OPT_CAC_APUP_BYSTA) is set by the User.
 *
 * @param  vaphandle    : handle to the vap.
 * @return              : Return true if the Repeater CAC is set to 1.
 */
bool wlan_mlme_is_repeater_cac_set(wlan_if_t vaphandle);

/*
 * MLME Check if the channel is DFS.
 *
 * @param  scan_entry_chan   : Channel structure.
 * @return                   : Return true if the channel is DFS.
 */
bool wlan_mlme_is_scanentry_dfs(struct ieee80211_channel *scan_entry_chan);

/*
 * MLME check if the chosen channel is the same as the curchan.
 *
 * @param  vaphandle        : handle to the vap.
 * @param  scan_entry_chan  : Channel structure.
 * @return                  : Return true if chosen channel and curchan is different.
 */
bool wlan_mlme_is_chosen_diff_from_curchan(wlan_if_t vaphandle, struct ieee80211_channel *scan_entry_chan);

/*
 * MLME Check if the channel has Radar.
 *
 * @param  scan_entry   : Scan entry structure
 * @return              : Return true if Radar found in the current channel.
 */
bool wlan_mlme_is_chan_radar(struct ieee80211_scan_entry *scan_entry);

/*
 * Upon some parameter changes, vap will be restartd, then fw will reset some paramters to default.
 * This function will restore the needed parameters.
 * @param  vaphandle        : handle to the vap.
*/
void wlan_restore_vap_params(wlan_if_t vaphandle);

#if DBDC_REPEATER_SUPPORT
void wlan_update_radio_priorities(struct ieee80211com *ic);
#endif
#if ATH_SUPPORT_WRAP && DBDC_REPEATER_SUPPORT
void osif_set_primary_radio_event (struct ieee80211com *ic);
#endif

struct ieee80211vap *
wlan_get_ap_mode_vap (struct ieee80211com *ic);

/*
 * Function to modify CSL configuration for VAP
 *
 * @param  vaphandle    : handle to the vap.
 */
void wlan_csl_enable (wlan_if_t, int);

/*
 * Function to get the NSS based on EXT NSS support for VAP
 *
 * @param  vaphandle    : handle to the vap.
 * @param  nss          : reference to the nss <=80MHz.
 * @param  nss_160      : handle to the nss for 160MHz.
 * @param  nss_80p80    : handle to the nss for 80p80MHz.
 */
void wlan_scan_entry_numstreams(wlan_scan_entry_t scan_entry,
        u_int8_t *nss,
        u_int8_t *nss_160,
        u_int8_t *nss_80p80);

#endif /* _IEEE80211_API_H_ */
