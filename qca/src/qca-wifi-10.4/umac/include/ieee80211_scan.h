/*
 *  Copyright (c) 2008 Atheros Communications Inc. 
 * All Rights Reserved.
 * 
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */

#ifndef _IEEE80211_SCAN_H
#define _IEEE80211_SCAN_H

#include <osdep.h>
#include <ieee80211_api.h>
#include <ieee80211_power.h>
#include <ieee80211_vap.h>
#include <ieee80211_resmgr.h>

typedef wlan_scan_entry_t                 ieee80211_scan_entry_t;
typedef struct ieee80211_scanner          *ieee80211_scanner_t;
typedef struct ieee80211_scan_scheduler   *ieee80211_scan_scheduler_t;
typedef struct ieee80211_scan_table       *ieee80211_scan_table_t;
#define IEEE80211_SCAN_MAX_SSID           10
#define IEEE80211_SCAN_MAX_BSSID          10
typedef struct ieee80211_aplist_config    *ieee80211_aplist_config_t;
typedef struct ieee80211_candidate_aplist *ieee80211_candidate_aplist_t;

#if UMAC_SUPPORT_SCAN


struct ieee80211_scanner_info {
    u_int32_t    si_allow_transmit   : 1,
                 si_in_home_channel  : 1,
                 si_scan_in_progress : 1,
		 /* Flag to indicate last scan done is full scan or
			terminated by terminator function */
                 si_last_term_status : 1;
};

struct ieee80211_scanner_common {
    void (* scan_attach_complete) (ieee80211_scanner_t ss);

    int (* scan_detach) (ieee80211_scanner_t *ss);

    void (* scan_detach_prepare) (ieee80211_scanner_t ss);

    int (* scan_start) (ieee80211_scanner_t          ss, 
                             wlan_if_t           vaphandle, 
                             ieee80211_scan_params    *params, 
                             IEEE80211_SCAN_REQUESTOR requestor,
                             IEEE80211_SCAN_PRIORITY  priority,
                             IEEE80211_SCAN_ID        *scan_id);
    int (* scan_cancel) (ieee80211_scanner_t ss,
                             wlan_if_t           vaphandle, 
                             IEEE80211_SCAN_REQUESTOR requestor, 
                             IEEE80211_SCAN_ID        scan_id_mask,
                             u_int32_t                flags);

    int (* scan_register_event_handler) (ieee80211_scanner_t          ss, 
                                              ieee80211_scan_event_handler evhandler, 
                                              void                         *arg);

    int (* scan_unregister_event_handler) (ieee80211_scanner_t          ss, 
                                                ieee80211_scan_event_handler evhandler,
                                                void                         *arg);

    int (* scan_get_last_scan_info) (ieee80211_scanner_t ss, 
                                     ieee80211_scan_info *info);

    int (* scan_update_channel_list) (ieee80211_scanner_t ss);

    int (* scan_channel_list_length) (ieee80211_scanner_t ss);

    int (* scan_scanentry_received) (ieee80211_scanner_t ss, 
                                          bool                bssid_match);

    systime_t (* scan_get_last_scan_time) (ieee80211_scanner_t ss);

    systime_t (* scan_get_last_full_scan_time) (ieee80211_scanner_t ss);

    void (* scan_connection_lost) (ieee80211_scanner_t ss);

    void (* scan_set_default_scan_parameters) (ieee80211_scanner_t          ss, 
                                               wlan_if_t             vaphandle,
                                               ieee80211_scan_params *scan_params,
                                               enum ieee80211_opmode opmode,
                                               bool                  active_scan_flag, 
                                               bool                  high_priority_flag,
                                               bool                  connected_flag,
                                               bool                  external_scan_flag,
                                               u_int32_t             num_ssid,
                                               ieee80211_ssid        *ssid_list,
                                               int                   peer_count);

    int (* scan_get_requestor_id) (ieee80211_scanner_t      ss,
                                        u_int8_t                 *module_name, 
                                        IEEE80211_SCAN_REQUESTOR *p_requestor_id);

    void (* scan_clear_requestor_id) (ieee80211_scanner_t      ss, 
                                           IEEE80211_SCAN_REQUESTOR requestor_id);

    u_int8_t *(* scan_get_requestor_name) (ieee80211_scanner_t      ss, 
                                                IEEE80211_SCAN_REQUESTOR requestor);


    int (* scan_set_priority) (ieee80211_scanner_t          ss, 
                                          IEEE80211_SCAN_REQUESTOR requestor,
                                          IEEE80211_SCAN_ID        scan_id_mask,
                                          IEEE80211_SCAN_PRIORITY  scanPriority);

    int (* scan_set_forced_flag) (ieee80211_scanner_t          ss, 
                                             IEEE80211_SCAN_REQUESTOR requestor,
                                             IEEE80211_SCAN_ID        scan_id_mask,
                                             bool                     forced_flag);
    int 
         (* scan_get_priority_table) (ieee80211_scanner_t          ss, 
                                      enum ieee80211_opmode      opmode,
                                      int                        *p_number_rows,
                                      IEEE80211_PRIORITY_MAPPING **p_mapping_table);
    int  (* scan_set_priority_table) (ieee80211_scanner_t ss,
                             enum ieee80211_opmode      opmode,
                             int                        number_rows,
                             IEEE80211_PRIORITY_MAPPING *p_mapping_table);
    int  (* scan_enable_scan_scheduler) (ieee80211_scanner_t ss,
                                         IEEE80211_SCAN_REQUESTOR requestor);
    int  (* scan_disable_scan_scheduler) (ieee80211_scanner_t ss,
                                          IEEE80211_SCAN_REQUESTOR requestor,
                                          u_int32_t  max_suspend_time);
    int  (* scan_scheduler_get_requests) (ieee80211_scanner_t ss,
                                     ieee80211_scan_request_info *scan_request_info,
                                     int                         *total_requests,
                                     int                         *returned_requests);
    struct ieee80211_scanner_info ss_info;
};

void ieee80211_scan_class_attach(wlan_dev_t devhandle);

void ieee80211_scan_reset_flags(struct ieee80211com *ic);

/* scanner functions */

typedef bool (*ieee80211_dev_status) (wlan_dev_t devhandle);

#define ieee80211_scan_attach(ss,ic,osdev,is_connected,is_txq_empty,has_pending_sends) \
    ic->ic_scan_attach(ss,ic,osdev,is_connected,is_txq_empty,has_pending_sends);

static INLINE void ieee80211_scan_attach_complete(ieee80211_scanner_t ss)
{
    ( (struct ieee80211_scanner_common *)ss)->scan_attach_complete(ss); 
}

static INLINE int ieee80211_scan_detach(ieee80211_scanner_t *ss)
{
    return ((struct ieee80211_scanner_common *) (*ss))->scan_detach(ss); 
}

static INLINE void ieee80211_scan_detach_prepare(ieee80211_scanner_t ss)
{
    ( (struct ieee80211_scanner_common *)ss)->scan_detach_prepare(ss); 
}

static INLINE int ieee80211_scan_start(ieee80211_scanner_t          ss, 
                    wlan_if_t               vaphandle, 
                    ieee80211_scan_params    *params, 
                    IEEE80211_SCAN_REQUESTOR requestor,
                    IEEE80211_SCAN_PRIORITY  priority,
                    IEEE80211_SCAN_ID        *scan_id)
{
    return ( (struct ieee80211_scanner_common *)ss)->scan_start(ss,vaphandle,params,
                             requestor,priority,scan_id); 
}

static INLINE int ieee80211_scan_register_event_handler(ieee80211_scanner_t          ss, 
                                          ieee80211_scan_event_handler evhandler, 
                                          void                         *arg)
{
    return ( (struct ieee80211_scanner_common *)ss)->scan_register_event_handler(ss,evhandler,arg);

}

static INLINE int ieee80211_scan_unregister_event_handler(ieee80211_scanner_t          ss, 
                                            ieee80211_scan_event_handler evhandler,
                                            void                         *arg)
{
    return ( (struct ieee80211_scanner_common *)ss)->scan_unregister_event_handler(ss,evhandler,arg);
}


static INLINE int ieee80211_get_last_scan_info(ieee80211_scanner_t ss, 
                                 ieee80211_scan_info *info)
{
    return ( (struct ieee80211_scanner_common *)ss)->scan_get_last_scan_info(ss,info);
}

static INLINE int ieee80211_scan_update_channel_list(ieee80211_scanner_t ss)
{
    return ( (struct ieee80211_scanner_common *)ss)->scan_update_channel_list(ss); 
}

static INLINE int ieee80211_scan_channel_list_length(ieee80211_scanner_t ss)
{
    return ( (struct ieee80211_scanner_common *)ss)->scan_channel_list_length(ss); 
}

static INLINE int ieee80211_scan_scanentry_received(ieee80211_scanner_t ss, 
                                      bool                bssid_match)
{
    return ( (struct ieee80211_scanner_common *)ss)->scan_scanentry_received(ss,bssid_match); 
}

static INLINE systime_t ieee80211_get_last_scan_time(ieee80211_scanner_t ss)
{
    return ( (struct ieee80211_scanner_common *)ss)->scan_get_last_scan_time(ss); 
}

static INLINE systime_t ieee80211_get_last_full_scan_time(ieee80211_scanner_t ss)
{
    return ( (struct ieee80211_scanner_common *)ss)->scan_get_last_full_scan_time(ss); 
}

static INLINE void ieee80211_scan_connection_lost(ieee80211_scanner_t ss)
{
    ( (struct ieee80211_scanner_common *)ss)->scan_connection_lost(ss); 
}

static INLINE void ieee80211_set_default_scan_parameters(ieee80211_scanner_t ss,
                                           wlan_if_t             vaphandle,
                                           ieee80211_scan_params *scan_params,
                                           enum ieee80211_opmode opmode,
                                           bool                  active_scan_flag, 
                                           bool                  high_priority_flag,
                                           bool                  connected_flag,
                                           bool                  external_scan_flag,
                                           u_int32_t             num_ssid,
                                           ieee80211_ssid        *ssid_list,
                                           int                   peer_count)
{
    ( (struct ieee80211_scanner_common *)ss)->scan_set_default_scan_parameters(ss,vaphandle,
                                           scan_params,
                                           opmode,
                                           active_scan_flag, 
                                           high_priority_flag,
                                           connected_flag,
                                           external_scan_flag,
                                           num_ssid,
                                           ssid_list,
                                           peer_count);
}

static INLINE int ieee80211_scan_get_requestor_id(ieee80211_scanner_t      ss,
                                    u_int8_t                 *module_name, 
                                    IEEE80211_SCAN_REQUESTOR *p_requestor_id)
{
    return ( (struct ieee80211_scanner_common *)ss)->scan_get_requestor_id(ss,module_name,p_requestor_id); 
}

static INLINE void ieee80211_scan_clear_requestor_id(ieee80211_scanner_t      ss, 
                                       IEEE80211_SCAN_REQUESTOR requestor_id)
{
    ( (struct ieee80211_scanner_common *)ss)->scan_clear_requestor_id(ss,requestor_id); 
}

static INLINE u_int8_t *ieee80211_scan_get_requestor_name(ieee80211_scanner_t      ss, 
                                            IEEE80211_SCAN_REQUESTOR requestor)
{
    return ( (struct ieee80211_scanner_common *)ss)->scan_get_requestor_name(ss,requestor); 
}

static INLINE u_int8_t ieee80211_scan_in_home_channel(ieee80211_scanner_t ss) 
{
    return (((struct ieee80211_scanner_common *)ss)->ss_info.si_in_home_channel);
}

static INLINE u_int8_t ieee80211_scan_can_transmit(ieee80211_scanner_t ss) 
{
    return (((struct ieee80211_scanner_common *)ss)->ss_info.si_allow_transmit);
}


static INLINE int ieee80211_scan_set_priority(ieee80211_scanner_t ss,
                           wlan_if_t                vaphandle,
                           IEEE80211_SCAN_REQUESTOR requestor,
                           IEEE80211_SCAN_ID        scan_id_mask,
                           IEEE80211_SCAN_PRIORITY  scanPriority)
{
    return ( (struct ieee80211_scanner_common *)ss)->scan_set_priority(ss, 
                                                                       requestor,
                                                                       scan_id_mask,
                                                                       scanPriority);
}


static INLINE int ieee80211_scan_set_forced_flag(ieee80211_scanner_t ss,
                              IEEE80211_SCAN_REQUESTOR requestor,
                              IEEE80211_SCAN_ID        scan_id_mask,
                                   bool                     forced_flag)
{
    return ( (struct ieee80211_scanner_common *)ss)->scan_set_forced_flag(ss, 
                                                                          requestor,
                                                                          scan_id_mask,
                                                                          forced_flag);

}

static INLINE int 
ieee80211_scan_get_priority_table(ieee80211_scanner_t ss,
                             enum ieee80211_opmode      opmode,
                             int                        *p_number_rows,
                                  IEEE80211_PRIORITY_MAPPING **p_mapping_table)
{
    return ( (struct ieee80211_scanner_common *)ss)->scan_get_priority_table(ss,
                                                                                 opmode,
                                                                                 p_number_rows,
                                                                                 p_mapping_table);

}
static INLINE int 
ieee80211_scan_set_priority_table(ieee80211_scanner_t ss,
                             enum ieee80211_opmode      opmode,
                             int                        number_rows,
                             IEEE80211_PRIORITY_MAPPING *p_mapping_table)
{
    return ( (struct ieee80211_scanner_common *)ss)->scan_set_priority_table(ss,
                                                                                 opmode,
                                                                                 number_rows,
                                                                                 p_mapping_table);

}
static INLINE 
int ieee80211_enable_scan_scheduler(ieee80211_scanner_t ss,
                               IEEE80211_SCAN_REQUESTOR requestor)
{
    return ( (struct ieee80211_scanner_common *)ss)->scan_enable_scan_scheduler(ss,requestor); 
}

static INLINE
int ieee80211_disable_scan_scheduler(ieee80211_scanner_t ss,
                                IEEE80211_SCAN_REQUESTOR requestor,
                                u_int32_t                max_suspend_time)
{
    return ( (struct ieee80211_scanner_common *)ss)->scan_disable_scan_scheduler(ss,requestor,max_suspend_time); 
}
static INLINE
int ieee80211_scan_scheduler_get_requests(ieee80211_scanner_t ss,
                                     ieee80211_scan_request_info *scan_request_info,
                                     int                         *total_requests,
                                     int                         *returned_requests)
{
    return ( (struct ieee80211_scanner_common *)ss)->scan_scheduler_get_requests(ss,scan_request_info,total_requests,returned_requests); 

}
static INLINE  int ieee80211_scan_cancel(ieee80211_scanner_t ss,
                     wlan_if_t           vaphandle, 
                     IEEE80211_SCAN_REQUESTOR requestor, 
                     IEEE80211_SCAN_ID        scan_id_mask,
                     u_int32_t                flags)
{
    return ( (struct ieee80211_scanner_common *)ss)->scan_cancel(ss,vaphandle,requestor,scan_id_mask,flags);

}


/*
 * functions to fetch data from scan entry object
 */

u_int8_t ieee80211_scan_entry_reference_count(ieee80211_scan_entry_t scan_entry);

u_int8_t ieee80211_scan_entry_add_reference_dbg(
        ieee80211_scan_entry_t scan_entry, const char *func, int line);

u_int8_t ieee80211_scan_entry_remove_reference_dbg(
        ieee80211_scan_entry_t scan_entry, const char *func, int line);

#define ieee80211_scan_entry_add_reference(scan_entry) \
    ieee80211_scan_entry_add_reference_dbg(scan_entry, __func__, __LINE__)

#define ieee80211_scan_entry_remove_reference(scan_entry) \
    ieee80211_scan_entry_remove_reference_dbg(scan_entry, __func__, __LINE__)

void ieee80211_release_entry(struct ieee80211com *st_ic, 
        struct ieee80211_scan_entry *scan_entry);


#if UMAC_SUPPORT_P2P_PROT
int ieee80211_scan_entry_p2p_info(wlan_scan_entry_t scan_entry, ieee80211_scan_p2p_info *scan_p2p_info);
int ieee80211_scan_specific_frame_ie_len(wlan_scan_entry_t scan_entry, u_int8_t subtype, int *ret_ie_len);
int ieee80211_scan_specific_frame_copy_ie_data(wlan_scan_entry_t scan_entry, u_int8_t subtype, 
                                          u_int8_t *iebuf, u_int16_t *ie_len);
#else //UMAC_SUPPORT_P2P_PROT
#define ieee80211_scan_entry_p2p_info(scan_entry, scan_p2p_info)                        (-EPERM)
#define ieee80211_scan_specific_frame_ie_len(scan_entry, subtype, ret_ie_len)           (-EPERM)
#define ieee80211_scan_specific_frame_copy_ie_data(scan_entry, subtype, iebuf, ie_len)  (-EPERM)
#define ieee80211_scan_entry_specific_frame_age(scan_entry, subtype) ieee80211_scan_entry_age(scan_entry)
#endif //UMAC_SUPPORT_P2P_PROT

void ieee80211_scan_entry_lock(ieee80211_scan_entry_t scan_entry);

void ieee80211_scan_entry_unlock(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_macaddr(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_bssid(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_sonie(ieee80211_scan_entry_t scan_entry);

u_int32_t ieee80211_scan_entry_timestamp(ieee80211_scan_entry_t scan_entry);

void ieee80211_scan_entry_reset_timestamp(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_tsf(ieee80211_scan_entry_t scan_entry);

systime_t ieee80211_scan_entry_bad_ap_time(ieee80211_scan_entry_t scan_entry);

void ieee80211_scan_entry_set_bad_ap_time(ieee80211_scan_entry_t scan_entry, systime_t timestamp);

bool ieee80211_scan_entry_is_radar_detected_period(ieee80211_scan_entry_t scan_entry);

void ieee80211_scan_entry_set_radar_detected_timestamp(ieee80211_scan_entry_t scan_entry, systime_t timestamp, u_int32_t csa_delay);

systime_t ieee80211_scan_entry_lastassoc(ieee80211_scan_entry_t scan_entry);

void ieee80211_scan_entry_set_lastassoc(ieee80211_scan_entry_t scan_entry, systime_t timestamp);

systime_t ieee80211_scan_entry_lastdeauth(ieee80211_scan_entry_t scan_entry);

void ieee80211_scan_entry_set_lastdeauth(ieee80211_scan_entry_t scan_entry, systime_t timestamp);

u_int16_t ieee80211_scan_entry_capinfo(ieee80211_scan_entry_t scan_entry);

u_int16_t ieee80211_scan_entry_beacon_interval(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_ssid(ieee80211_scan_entry_t scan_entry, u_int8_t *ssidlen);

u_int8_t *ieee80211_scan_entry_beacon_data(ieee80211_scan_entry_t scan_entry, u_int16_t *beacon_len);

u_int16_t ieee80211_scan_entry_beacon_len(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_ie_data(ieee80211_scan_entry_t scan_entry,u_int16_t *ie_len);

u_int16_t ieee80211_scan_entry_ie_len(ieee80211_scan_entry_t scan_entry);

struct ieee80211_channel *ieee80211_scan_entry_channel(ieee80211_scan_entry_t scan_entry);

u_int8_t ieee80211_scan_entry_erpinfo(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_rates(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_xrates(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_rsn(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_wpa(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_wps(ieee80211_scan_entry_t scan_entry);

#if ATH_SUPPORT_WAPI
u_int8_t *ieee80211_scan_entry_wapi(ieee80211_scan_entry_t scan_entry);
#endif

u_int8_t *ieee80211_scan_entry_sfa(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_csa(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_xcsa(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_quiet(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_qbssload(ieee80211_scan_entry_t scan_entry);

u_int32_t ieee80211_scan_entry_age(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_vendor(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_country(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_wmeinfo_ie(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_wmeparam_ie(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_htinfo(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_htcap(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_vhtcap(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_vhtop(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_cswrp(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_widebw(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_secchanoff(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_txpwrenvlp(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_opmode(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_bwnss_map(ieee80211_scan_entry_t scan_entry);

struct ieee80211_ie_athAdvCap *ieee80211_scan_entry_athcaps(ieee80211_scan_entry_t scan_entry);

struct ieee80211_ie_ath_extcap *ieee80211_scan_entry_athextcaps(ieee80211_scan_entry_t scan_entry);
struct ieee80211_ie_ext_cap *ieee80211_scan_entry_extcaps(ieee80211_scan_entry_t scan_entry);

u_int32_t ieee80211_scan_entry_status(ieee80211_scan_entry_t scan_entry );

void ieee80211_scan_entry_set_status(ieee80211_scan_entry_t scan_entry, u_int32_t status);

u_int32_t ieee80211_scan_entry_assoc_state(ieee80211_scan_entry_t scan_entry);

void ieee80211_scan_entry_set_assoc_state(ieee80211_scan_entry_t scan_entry, u_int32_t state);

u_int32_t ieee80211_scan_entry_assoc_cost(ieee80211_scan_entry_t scan_entry);

void ieee80211_scan_entry_set_assoc_cost(ieee80211_scan_entry_t scan_entry, u_int32_t cost);

u_int32_t ieee80211_scan_entry_rank(ieee80211_scan_entry_t scan_entry);

void ieee80211_scan_entry_set_rank(ieee80211_scan_entry_t scan_entry, u_int32_t rank);

u_int32_t ieee80211_scan_entry_pref_bss_rank(ieee80211_scan_entry_t scan_entry);

void ieee80211_scan_entry_set_pref_bss_rank(ieee80211_scan_entry_t scan_entry, u_int32_t rank);

u_int8_t ieee80211_scan_entry_demerit_utility(ieee80211_scan_entry_t scan_entry);

void ieee80211_scan_entry_set_demerit_utility(ieee80211_scan_entry_t scan_entry, u_int8_t enable);

u_int32_t ieee80211_scan_entry_utility(ieee80211_scan_entry_t scan_entry);

void ieee80211_scan_entry_set_utility(ieee80211_scan_entry_t scan_entry, u_int32_t utility);

void ieee80211_scan_set_maxentry(ieee80211_scan_table_t scan_table, u_int16_t val);

u_int16_t ieee80211_scan_get_maxentry(ieee80211_scan_table_t scan_table);

void ieee80211_scan_set_timeout(ieee80211_scan_table_t scan_table, u_int16_t val);

u_int16_t ieee80211_scan_get_timeout(ieee80211_scan_table_t scan_table);

u_int32_t ieee80211_scan_entry_chanload(ieee80211_scan_entry_t scan_entry);

void ieee80211_scan_entry_set_chanload(ieee80211_scan_entry_t scan_entry, u_int32_t load);

enum ieee80211_opmode ieee80211_scan_entry_bss_type(ieee80211_scan_entry_t scan_entry);

u_int8_t ieee80211_scan_entry_privacy(ieee80211_scan_entry_t scan_entry);

u_int32_t ieee80211_scan_entry_phymode(ieee80211_scan_entry_t scan_entry);

u_int8_t ieee80211_scan_entry_dtimperiod(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_tim(ieee80211_scan_entry_t scan_entry);

u_int8_t ieee80211_scan_entry_rssi(ieee80211_scan_entry_t scan_entry);

u_int8_t *ieee80211_scan_entry_wps(ieee80211_scan_entry_t scan_entry);

#if ATH_SUPPORT_IBSS_DFS
u_int8_t *ieee80211_scan_entry_ibssdfs_ie(ieee80211_scan_entry_t scan_entry);
#endif /* ATH_SUPPORT_IBSS_DFS */

u_int32_t ieee80211_channel_frequency(struct ieee80211_channel *chan);

u_int32_t ieee80211_channel_ieee(struct ieee80211_channel *chan);

/*
 * operations on scan table
 */

int ieee80211_scan_table_attach(struct ieee80211com    *ic,
                                ieee80211_scan_table_t *st, 
                                osdev_t                osdev);

int ieee80211_scan_table_detach(ieee80211_scan_table_t *st);

int ieee80211_scan_table_vattach(wlan_if_t              vaphandle,
                                 ieee80211_scan_table_t *st, 
                                 osdev_t                osdev);

int ieee80211_scan_table_vdetach(ieee80211_scan_table_t *st);

struct ieee80211_scan_entry *
ieee80211_scan_table_update(struct ieee80211vap          *vap,
                            struct ieee80211_frame *wh,
                            u_int32_t                    frame_length,
                            int                          subtype, 
                            int                          rssi,
                            struct ieee80211_channel     *bcn_recv_chan);

int ieee80211_scan_macaddr_iterate(ieee80211_scan_table_t scan_table, u_int8_t *macaddr,
                                   ieee80211_scan_iter_func shandler, void *arg);

int ieee80211_scan_table_iterate(ieee80211_scan_table_t scan_table, ieee80211_scan_iter_func shandler, void *arg);

void ieee80211_scan_table_flush(ieee80211_scan_table_t scan_table);

bool ieee80211_count_active_ports(struct ieee80211com  *ic, struct ieee80211vap *vap);

int ieee80211_scan_mempool(struct ieee80211com  *ic);

/* get num of spatial streams from mcs rate */
static INLINE int
ieee80211_mcs_to_numstreams(int mcs)
{
   int numstreams = 0;
   /* single stream mcs rates */
   if ((mcs <= 7) || (mcs == 32))
       numstreams = 1;
   /* two streams mcs rates */
   if (((mcs >= 8) && (mcs <= 15)) || ((mcs >= 33) && (mcs <= 38)))
       numstreams = 2;
   /* three streams mcs rates */
   if (((mcs >= 16) && (mcs <= 23)) || ((mcs >= 39) && (mcs <= 52)))
       numstreams = 3;
   /* four streams mcs rates */
   if (((mcs >= 24) && (mcs <= 31)) || ((mcs >= 53) && (mcs <= 76)))
       numstreams = 4;
   return numstreams;
}

#else /* UMAC_SUPPORT_SCAN */

static INLINE int ieee80211_scan_attach(ieee80211_scanner_t        *ss, 
                                        struct ieee80211com        *ic, 
                                        osdev_t                    osdev,
                                        bool (*is_connected)       (wlan_if_t),
                                        bool (*is_txq_empty)       (wlan_dev_t),
                                        bool (*has_pending_sends)  (wlan_dev_t)) 
{
    return 0;
}

#define ieee80211_scan_attach_complete(ss)                           EOK
#define ieee80211_scan_detach(ss)                                    EOK
#define ieee80211_scan_detach_prepare(ss)                            EOK
#define ieee80211_scan_register_event_handler(ss,evhandler,arg)      EOK
#define ieee80211_scan_unregister_event_handler(ss,evhandler,arg)    EOK
#define ieee80211_scan_table_attach(ic,st,osdev)                     EOK
#define ieee80211_scan_table_detach(st)                              EOK
#define ieee80211_scan_table_vattach(vap,st,osdev)                   EOK
#define ieee80211_scan_table_vdetach(st)                             EOK
#define ieee80211_count_active_ports(ic, vap)                        0      /* Assumed no active vaps */

#endif /* UMAC_SUPPORT_SCAN */

#if UMAC_SUPPORT_APLIST
/*
 * operations on Candidate AP list
 */

int ieee80211_aplist_vattach(ieee80211_candidate_aplist_t *aplist, 
                             wlan_if_t                    vaphandle, 
                             ieee80211_scan_table_t       scan_table,
                             ieee80211_scanner_t          scanner,
                             osdev_t                      osdev);

int ieee80211_aplist_vdetach(ieee80211_candidate_aplist_t *aplist);


bool ieee80211_candidate_list_find(wlan_if_t            vaphandle,
                                   bool                 strict_filtering,
                                   wlan_scan_entry_t    *candidate_list,
                                   u_int32_t            maximum_age);

void ieee80211_candidate_list_build(wlan_if_t            vaphandle,
                                    bool                 strict_filtering,
                                    wlan_scan_entry_t    active_ap,
                                    u_int32_t            maximum_age);

/* Opportunistic Roam  */
void ieee80211_candidate_list_prioritize_bssid(ieee80211_candidate_aplist_t aplist,
                                               struct ether_addr *bssid);

void ieee80211_candidate_list_free(ieee80211_candidate_aplist_t aplist);

int ieee80211_candidate_list_count(ieee80211_candidate_aplist_t aplist);

wlan_scan_entry_t ieee80211_candidate_list_get(ieee80211_candidate_aplist_t aplist, 
                                               int                          index);

void ieee80211_candidate_list_register_compare_func (
    ieee80211_candidate_aplist_t    aplist,
    ieee80211_candidate_list_compare_func compare_func,
    void *arg );
/*
 * operations on AP list config
 */


void ieee80211_aplist_config_init(ieee80211_aplist_config_t aplist_config);

int ieee80211_aplist_set_desired_bssidlist(ieee80211_aplist_config_t pconfig, 
                                           u_int16_t                 nbssid, 
                                           u_int8_t                  (*bssidlist)[IEEE80211_ADDR_LEN]);
                                        
int ieee80211_aplist_get_desired_bssidlist(ieee80211_aplist_config_t pconfig, 
                                           u_int8_t                  (*bssidlist)[IEEE80211_ADDR_LEN]);

int ieee80211_aplist_get_desired_bssid_count(ieee80211_aplist_config_t pconfig);

int ieee80211_aplist_get_desired_bssid(ieee80211_aplist_config_t pconfig,
                                       int                       index, 
                                       u_int8_t                  **bssid);

bool ieee80211_aplist_get_accept_any_bssid(ieee80211_aplist_config_t pconfig);

int ieee80211_aplist_set_max_age(ieee80211_aplist_config_t pconfig, 
                                 u_int32_t                 max_age);

u_int32_t ieee80211_aplist_get_max_age(ieee80211_aplist_config_t pconfig);

int ieee80211_aplist_set_ignore_all_mac_addresses(ieee80211_aplist_config_t pconfig,
                                                  bool                      flag);

bool ieee80211_aplist_get_ignore_all_mac_addresses(ieee80211_aplist_config_t pconfig);

int ieee80211_aplist_set_exc_macaddresslist(ieee80211_aplist_config_t pconfig, 
                                            u_int16_t                 n_entries, 
                                            u_int8_t                  (*macaddress)[IEEE80211_ADDR_LEN]);
                                        
int ieee80211_aplist_get_exc_macaddresslist(ieee80211_aplist_config_t pconfig, 
                                            u_int8_t                  (*macaddress)[IEEE80211_ADDR_LEN]);

int ieee80211_aplist_get_exc_macaddress_count(ieee80211_aplist_config_t pconfig);

int ieee80211_aplist_get_exc_macaddress(ieee80211_aplist_config_t pconfig, 
                                        int                       index, 
                                        u_int8_t                  **pmacaddress);

int ieee80211_aplist_set_desired_bsstype(ieee80211_aplist_config_t pconfig, 
                                         enum ieee80211_opmode     bss_type);

enum ieee80211_opmode ieee80211_aplist_get_desired_bsstype(struct ieee80211_aplist_config *pconfig);

int ieee80211_aplist_set_tx_power_delta(ieee80211_aplist_config_t pconfig, 
                                        int                       tx_power_delta);

int ieee80211_aplist_get_tx_power_delta(ieee80211_aplist_config_t pconfig);

bool ieee80211_candidate_aplist_match_rsn_info(
                                        wlan_if_t                     vap,
                                        struct ieee80211_rsnparms     *rsn_parms);


void ieee80211_aplist_register_match_security_func(
    struct ieee80211_aplist_config    *pconfig,
    ieee80211_aplist_match_security_func match_security_func,
    void *arg);

int ieee80211_aplist_set_bad_ap_timeout(
    struct ieee80211_aplist_config    *pconfig, 
    u_int32_t                         bad_ap_timeout
    );

int ieee80211_aplist_config_vattach(ieee80211_aplist_config_t *pconfig, 
                                    osdev_t                   osdev);

int ieee80211_aplist_config_vdetach(ieee80211_aplist_config_t *pconfig);

#else /* UMAC_SUPPORT_APLIST */

#define ieee80211_aplist_config_vattach(pconfig,osdev)                       /**/ 
#define ieee80211_aplist_config_vdetach(pconfig)                             /**/ 
#define ieee80211_aplist_vattach(aplist, vaphandle,scan_table,scanner,osdev) /**/ 
#define ieee80211_aplist_vdetach(aplist)                                     /**/ 
#define ieee80211_aplist_config_init(aplist_config)                          /**/
#define ieee80211_aplist_get_desired_bssid_count(pconfig)                    0
/* make the compiler  happy */
#define ieee80211_aplist_get_desired_bssid(pconfig,index,bssid)              (pconfig = pconfig)  
#define ieee80211_aplist_get_accept_any_bssid(pconfig)                       true
#define ieee80211_aplist_get_ignore_all_mac_addresses(pconfig)               (pconfig == pconfig)
#define ieee80211_aplist_get_exc_macaddress_count(pconfig)                   0 
#define ieee80211_aplist_get_exc_macaddress(pconfig,index,pmacaddress)       (pconfig = pconfig)

#endif /* UMAC_SUPPORT_APLIST */

#endif
