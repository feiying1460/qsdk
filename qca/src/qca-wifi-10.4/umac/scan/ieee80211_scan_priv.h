/*
 *  Copyright (c) 2008 Atheros Communications Inc. 
 * All Rights Reserved.
 * 
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */

/*
 * private file for scan module. not to be included
 * outside scan module.
 */
#ifndef _IEEE80211_SCAN_PRIV_H
#define _IEEE80211_SCAN_PRIV_H

#include <ieee80211_channel.h>
#include <_ieee80211.h>
#include <ieee80211.h>
#include <ieee80211_var.h>
#include <ieee80211_scan.h>
#include <ieee80211_resmgr.h>

#define IEEE80211_SCAN_MAX         IEEE80211_CHAN_MAX

#define STA_HASHSIZE               32
/* simple hash is enough for variation of macaddr */
#define STA_HASH(addr)                                                  \
    (((const u_int8_t *)(addr))[IEEE80211_ADDR_LEN - 1] % STA_HASHSIZE)

typedef struct scanner_preemption_data {
    bool         preempted;     /* indicate scan was really preempted */
    u_int16_t    nreqchans;     /* requested number of channels */
    u_int16_t    nchans;        /* # chan's to scan */
    u_int16_t    nallchans;     /* # all chans's to scan */
    u_int16_t    next;          /* index of next chan to scan */
} scanner_preemption_data_t;

typedef struct scan_request_data {
    IEEE80211_SCAN_REQUESTOR     requestor;
    IEEE80211_SCAN_PRIORITY      priority;
    IEEE80211_SCAN_ID            scan_id;
    systime_t                    request_timestamp;
    ieee80211_scan_params        *params;
    scanner_preemption_data_t    preemption_data;
} scan_request_data_t;

typedef enum _scanner_stop_mode {
    STOP_MODE_CANCEL,
    STOP_MODE_PREEMPT
} scanner_stop_mode;

int ieee80211_scan_run(ieee80211_scanner_t   ss, 
                       wlan_if_t             vaphandle,
                       scan_request_data_t   *request_data);

int ieee80211_scan_stop(ieee80211_scanner_t      ss, 
                        IEEE80211_SCAN_REQUESTOR requestor,
                        IEEE80211_SCAN_ID        scan_id,
                        scanner_stop_mode        stop_mode,
                        u_int32_t                flags);

int ieee80211_scan_external_event(ieee80211_scanner_t              ss,
                                  wlan_if_t                        vaphandle,
                                  ieee80211_scan_event_type        notification_event,
                                  ieee80211_scan_completion_reason notification_reason,
                                  IEEE80211_SCAN_ID                scan_id,
                                  IEEE80211_SCAN_REQUESTOR         requestor);

int ieee80211_scan_local_set_priority(ieee80211_scanner_t      ss, 
                                IEEE80211_SCAN_REQUESTOR requestor,
                                IEEE80211_SCAN_ID        scan_id,
                                IEEE80211_SCAN_PRIORITY  scan_priority);

int ieee80211_scan_local_set_forced_flag(ieee80211_scanner_t      ss, 
                                   IEEE80211_SCAN_REQUESTOR requestor,
                                   IEEE80211_SCAN_ID        scan_id, 
                                   bool                     forced_flag);

int ieee80211_print_scan_config(ieee80211_scanner_t ss,
                                struct seq_file *m);

#if ATH_SUPPORT_MULTIPLE_SCANS

/*
 * Private interface between Scan Scheduler and Scanner.
 * All other modules, including those in the UMAC, should use 
 * wlan_scan_start/wlan_scan_cancel.
 */
int ieee80211_scan_scheduler_attach(ieee80211_scan_scheduler_t *ssc, 
                                    ieee80211_scanner_t        ss,
                                    wlan_dev_t                 devhandle,
                                    osdev_t                    osdev);

int ieee80211_scan_scheduler_detach(ieee80211_scan_scheduler_t *ssc);

int ieee80211_scan_scheduler_add(ieee80211_scan_scheduler_t ssc,
                                 wlan_if_t                  vaphandle, 
                                 ieee80211_scan_params      *params, 
                                 IEEE80211_SCAN_REQUESTOR   requestor,
                                 IEEE80211_SCAN_PRIORITY    priority,
                                 IEEE80211_SCAN_ID          *p_scan_id);

int ieee80211_scan_scheduler_remove(ieee80211_scan_scheduler_t ssc,
                                    wlan_if_t                  vaphandle, 
                                    IEEE80211_SCAN_REQUESTOR   requestor,
                                    IEEE80211_SCAN_ID          scan_id_mask,
                                    u_int32_t                  flags);

void ieee80211_scan_scheduler_preprocess_event(ieee80211_scan_scheduler_t ssc,
                                               ieee80211_scan_event       *event);

void ieee80211_scan_scheduler_postprocess_event(ieee80211_scan_scheduler_t ssc,
                                                ieee80211_scan_event       *event);

int ieee80211_scan_scheduler_set_priority_table(ieee80211_scan_scheduler_t ssc, 
                                                enum ieee80211_opmode      opmode,
                                                int                        number_rows,
                                                IEEE80211_PRIORITY_MAPPING *p_mapping_table);
                                          
int ieee80211_scan_scheduler_get_priority_table(ieee80211_scan_scheduler_t ssc, 
                                                enum ieee80211_opmode      opmode,
                                                int                        *p_number_rows,
                                                IEEE80211_PRIORITY_MAPPING **p_mapping_table);
                                                
int ieee80211_scan_scheduler_set_priority(ieee80211_scan_scheduler_t ssc, 
                                          wlan_if_t                  vaphandle, 
                                          IEEE80211_SCAN_REQUESTOR   requestor,
                                          IEEE80211_SCAN_ID          scan_id_mask,
                                          IEEE80211_SCAN_PRIORITY    scanPriority);

int ieee80211_scan_scheduler_set_forced_flag(ieee80211_scan_scheduler_t ssc, 
                                             wlan_if_t                  vaphandle, 
                                             IEEE80211_SCAN_REQUESTOR   requestor,
                                             IEEE80211_SCAN_ID          scan_id_mask,
                                             bool                       forced_flag);

int ieee80211_scan_scheduler_get_request_info(ieee80211_scan_scheduler_t ssc, 
                                              IEEE80211_SCAN_ID          scan_id,
                                              ieee80211_scan_info        *scan_info);

int
ieee80211_scan_scheduler_get_requests(ieee80211_scan_scheduler_t ssc, 
                                     ieee80211_scan_request_info *scan_request_info,
                                     int                         *total_requests,
                                     int                         *returned_requests);

int ieee80211_scan_get_preemption_data(ieee80211_scanner_t       ss, 
                                       IEEE80211_SCAN_REQUESTOR  requestor,
                                       IEEE80211_SCAN_ID         scan_id, 
                                       scanner_preemption_data_t *preemption_data);

int ieee80211_enable_scan_scheduler(ieee80211_scan_scheduler_t ssc, 
                                    IEEE80211_SCAN_REQUESTOR   requestor);

int ieee80211_disable_scan_scheduler(ieee80211_scan_scheduler_t ssc, 
                                     IEEE80211_SCAN_REQUESTOR   requestor,
                                     u_int32_t                  disable_duration);

bool ieee80211_scan_scheduler_scan_in_progress(ieee80211_scan_scheduler_t ssc);

#else

#define ieee80211_scan_scheduler_attach(_ssc, _ss, _devhandle, _osdev)                                   EOK

#define ieee80211_scan_scheduler_detach(_ssc)                                                            EOK

#define ieee80211_scan_scheduler_add(_ssc, _vaphandle, _params, _requestor, _priority, _p_scan_id)       ENOENT

#define ieee80211_scan_scheduler_remove(_ssc, _vaphandle, _requestor, _scan_id_mask, _flags)             ENOENT

#define ieee80211_scan_scheduler_preprocess_event(_ssc, _event)                                          /* */

#define ieee80211_scan_scheduler_postprocess_event(_ssc, _event)                                         /* */

#define ieee80211_scan_scheduler_set_priority_table(_ssc, _opmode, _number_rows, _p_mapping_table)       EOK

static INLINE int ieee80211_scan_scheduler_get_priority_table(ieee80211_scan_scheduler_t ssc, 
                                                              enum ieee80211_opmode      opmode,
                                                              int                        *p_number_rows,
                                                              IEEE80211_PRIORITY_MAPPING **p_mapping_table)
{
    *p_number_rows   = 0;
    *p_mapping_table = NULL;
    
    return EOK;
}

#define ieee80211_scan_scheduler_set_priority(_ssc, _vap, _req, _id, _prio)          ieee80211_scan_local_set_priority(_ssc, _req, _id, _prio)

#define ieee80211_scan_scheduler_set_forced_flag(_ssc, _vap, _req, _id, _flag)       ieee80211_scan_local_set_forced_flag(_ssc, _req, _id, _flag)

#define ieee80211_scan_scheduler_get_request_info(_ssc, _scan_id, _scan_info)                            ENOENT

#define ieee80211_scan_scheduler_get_requests(_ssc, _buffer, _total, _returned)                          ENOENT

#define ieee80211_enable_scan_scheduler(_ssc, _req)                                                      EOK

#define ieee80211_disable_scan_scheduler(_ssc, _req, _duration)                                          EOK

#endif    /* ATH_SUPPORT_MULTIPLE_SCANS */

#endif
