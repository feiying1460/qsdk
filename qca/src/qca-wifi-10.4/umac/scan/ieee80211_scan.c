/*
 *  Copyright (c) 2008 Atheros Communications Inc.
 * All Rights Reserved.
 *
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */
#include <ieee80211_scan_priv.h>

#if UMAC_SUPPORT_SCAN
#include "ieee80211_sme_api.h"
#include "ieee80211_sm.h"
#include "ieee80211_vap_pause.h"

#define MAX_QUEUED_EVENTS  16

enum scanner_state {
    SCANNER_STATE_IDLE = 0,           /* idle */
    SCANNER_STATE_SUSPENDING_TRAFFIC, /* waiting for all ports to suspend traffic */
    SCANNER_STATE_FOREIGN_CHANNEL,    /* wait on channel  */
    SCANNER_STATE_RESUMING_TRAFFIC,   /* waiting for all ports to resume traffic */
    SCANNER_STATE_BSS_CHANNEL,        /* on BSS chan for BG scan */
    SCANNER_STATE_RADIO_MEASUREMENT,  /* scanner's radio measurements state */
    SCANNER_STATE_REPEATER_CHANNEL,   /* Wait on repeater AP VAP channel  */
    SCANNER_STATE_TERMINATING,        /* waiting for Resource Manager to complete last request */
};

/*
   SCANER_STATE_IDLE                :  the scanner is idle and ready to accept and handle scan requests.
   SCANNER_STATE_SUSPENDING_TRAFFIC :  scanner made an off-channel request to ResourceManager and is
                                       waiting for response. The ResourceManager will pause all VAPs, requesting
                                       the PowerSave module to enter NetworkSleep if necessary.
   SCANNER_STATE_FOREIGN_CHANNEL    :  scanner had changed to a new channel and collecting all the probe
                                       response/beacon frames from APs on the channel.
                                       information about reception of probe responses/beacons on the new
                                       channel and expiration of min DWELL time are kept in flags and used
                                       when determining whether we can transition to the next channel.
   SCANNER_STATE_RESUMING_TRAFFIC   :  scanner issued a request to return to the BSS channel to ResourceManager
                                       and is waiting for response. The ResourceManager will resume operation
                                       in all VAPs.
   SCANNER_STATE_BSS_CHANNEL        :  the scanner is back on to the BSS chan (this state is only valid for BG scan.)
   SCANNER_STATE_RADIO_MEASUREMENT  :  scanner is in radio measurements.
   SCANNER_STATE_REPEATER_CHANNEL   :  Remain on AP VAP channel
   SCANNER_STATE_TERMINATING        :  Scanner requested return to the BSS channel to ResourceManager after a termination
                                       condition has been detected and is waiting for response.
*/

enum scanner_event {
    SCANNER_EVENT_NONE,                    /* no event */
    SCANNER_EVENT_PROBEDELAY_EXPIRE,       /* probe delay timer expired */
    SCANNER_EVENT_MINDWELL_EXPIRE,         /* min_dwell timer expired */
    SCANNER_EVENT_MAXDWELL_EXPIRE,         /* max_dwell timer expired */
    SCANNER_EVENT_RESTTIME_EXPIRE,         /* rest_time timer expired */
    SCANNER_EVENT_EXIT_CRITERIA_EXPIRE,    /* re-check conditions to leave channel */
    SCANNER_EVENT_FAKESLEEP_ENTERED,       /* fake sleep entered */
    SCANNER_EVENT_FAKESLEEP_FAILED,        /* fake sleep enter failed */
    SCANNER_EVENT_RECEIVED_BEACON,         /* received beacon/probe response on the channel */
    SCANNER_EVENT_SCAN_REQUEST,            /* request to  scan */
    SCANNER_EVENT_CANCEL_REQUEST,          /* request to cancel scan */
    SCANNER_EVENT_RESTART_REQUEST,         /* request to restart scan */
    SCANNER_EVENT_MAXSCANTIME_EXPIRE,      /* max scan time expired */
    SCANNER_EVENT_FAKESLEEP_EXPIRE,        /* fakesleep timeout */
    SCANNER_EVENT_RADIO_MEASUREMENT_EXPIRE,/* radio measurements timeout */
    SCANNER_EVENT_PROBE_REQUEST_TIMER,     /* probe request timer expired */
    SCANNER_EVENT_BSSCHAN_SWITCH_COMPLETE, /* RESMGR completed switch to BSS channel */
    SCANNER_EVENT_OFFCHAN_SWITCH_COMPLETE, /* RESMGR completed switch to foreign channel */
    SCANNER_EVENT_OFFCHAN_SWITCH_FAILED,   /* RESMGR could not complete switch to foreign channel */
    SCANNER_EVENT_OFFCHAN_SWITCH_ABORTED,  /* RESMGR aborted switch to foreign channel - possibly because of VAP UP event */
    SCANNER_EVENT_OFFCHAN_RETRY_EXPIRE,    /* completed delay before retrying a switch to a foreign channel */
    SCANNER_EVENT_CHAN_SWITCH_COMPLETE,    /* RESMGR completed switch to new channel */
    SCANNER_EVENT_SCHEDULE_BSS_COMPLETE,   /* RESMGR completed scheduling new BSS */
    SCANNER_EVENT_TERMINATING_TIMEOUT,     /* timeout waiting for RESMGR event */
    SCANNER_EVENT_EXTERNAL_EVENT,          /* event generated externally (usually by the Scan Scheduler) */
    SCANNER_EVENT_PREEMPT_REQUEST,         /* preemption request */
    SCANNER_EVENT_FATAL_ERROR,             /* fatal error - abort scan */
    SCANNER_EVENT_CAN_PAUSE_WAIT_EXPIRE ,  /* can pause wait timer expiry */
};

static const char*    scanner_event_name[] = {
    /* SCANNER_EVENT_NONE                    */ "NONE",
    /* SCANNER_EVENT_PROBEDELAY_EXPIRE       */ "PROBEDELAY_EXPIRE",
    /* SCANNER_EVENT_MINDWELL_EXPIRE         */ "MINDWELL_EXPIRE",
    /* SCANNER_EVENT_MAXDWELL_EXPIRE         */ "MAXDWELL_EXPIRE",
    /* SCANNER_EVENT_RESTTIME_EXPIRE         */ "RESTTIME_EXPIRE",
    /* SCANNER_EVENT_EXIT_CRITERIA_EXPIRE    */ "EXIT_CRITERIA_EXPIRE",
    /* SCANNER_EVENT_FAKESLEEP_ENTERED       */ "FAKESLEEP_ENTERED",
    /* SCANNER_EVENT_FAKESLEEP_FAILED        */ "FAKESLEEP_FAILED",
    /* SCANNER_EVENT_RECEIVED_BEACON         */ "RECEIVED_BEACON",
    /* SCANNER_EVENT_SCAN_REQUEST            */ "SCAN_REQUEST",
    /* SCANNER_EVENT_CANCEL_REQUEST          */ "CANCEL_REQUEST",
    /* SCANNER_EVENT_RESTART_REQUEST         */ "RESTART_REQUEST",
    /* SCANNER_EVENT_MAXSCANTIME_EXPIRE      */ "MAXSCANTIME_EXPIRE",
    /* SCANNER_EVENT_FAKESLEEP_EXPIRE        */ "FAKESLEEP_EXPIRE",
    /* SCANNER_EVENT_RADIO_MEASUREMENT_EXPIRE*/ "RADIO_MEASUREMENT_EXPIRE",
    /* SCANNER_EVENT_PROBE_REQUEST_TIMER     */ "PROBE_REQUEST_TIMER",
    /* SCANNER_EVENT_BSSCHAN_SWITCH_COMPLETE */ "BSSCHAN_SWITCH_COMPLETE",
    /* SCANNER_EVENT_OFFCHAN_SWITCH_COMPLETE */ "OFFCHAN_SWITCH_COMPLETE",
    /* SCANNER_EVENT_OFFCHAN_SWITCH_FAILED   */ "OFFCHAN_SWITCH_FAILED",
    /* SCANNER_EVENT_OFFCHAN_SWITCH_ABORTED  */ "OFFCHAN_SWITCH_ABORTED",
    /* SCANNER_EVENT_OFFCHAN_RETRY_EXPIRE    */ "OFFCHAN_RETRY_EXPIRE",
    /* SCANNER_EVENT_CHAN_SWITCH_COMPLETE    */ "CHAN_SWITCH_COMPLETE",
    /* SCANNER_EVENT_SCHEDULE_BSS_COMPLETE   */ "SCHEDULE_BSS_COMPLETE",
    /* SCANNER_EVENT_TERMINATING_TIMEOUT     */ "TERMINATING_TIMEOUT",
    /* SCANNER_EVENT_EXTERNAL_EVENT          */ "EXTERNAL_EVENT",
    /* SCANNER_EVENT_PREEMPT_REQUEST         */ "PREEMPT_REQUEST",
    /* SCANNER_EVENT_FATAL_ERROR             */ "FATAL_ERROR",
};

/* State transition table


##For Background Scan
event       curstate -->      IDLE           SUSPENDING        FOREIGN_CHANNEL      BSSCHAN         RESUMING      TERMINATING     RADIO_MEASUREMENT
                                              TRAFFIC                                               TRAFFIC
--------------------------------------------------------------------------------------------------------------------------------------------

NONE                           --              --                   --                --              --             --            --
PROBEDELAY_EXPIRE              --              --             FOREIGN_CHANNEL         --              --             --            --
MINDWELL_EXPIRE                --              --             FOREIGN_CHANNEL         --              --             --            --
MAXDWELL_EXPIRE                --              --                 RESUMING            --              --             --            --
RESTTIME_EXPIRE                --              --                   --            SUSPENDING          --             --            --
EXIT_CRITERIA_EXPIRE           --              --                   --            SUSPENDING          --             --            --
SCAN_REQUEST               SUSPENDING          --                   --                --              --             --            --
FAKESLEEP_ENTERED              --         FOREIGN_CHANNEL           --                --              --             --            --
FAKESLEEP_FAILED               --         FOREIGN_CHANNEL           --                --              --             --            --
RECEIVED_BEACON,               --              --             FOREIGN_CHANNEL         --              --             --            --
CANCEL_REQUEST                 --           TERMINATING         TERMINATING       TERMINATING     TERMINATING        --       TERMINATING
RADIO_MEAS_REQUEST      RADIO_MEAS/SUSPENDING  --                   --                --              --             --            --
RESTART_REQUEST                --              --             FOREIGN_CHANNEL         --              --             --        see Note below
MAXSCANTIME_EXPIRE             --           SUSPENDING          TERMINATING       TERMINATING     TERMINATING        --          RADIO_MEAS
FAKESLEEP_EXPIRE               --         FOREIGN_CHANNEL           --                --              --             --            --
PROBE_REQUEST_TIMER            --              --             FOREIGN_CHANNEL         --              --             --            --
BSSCHAN_SWITCH_COMPLETE        --              --                   --                --   IDLE/BSSCHAN/RADIO_MEAS  IDLE           --
OFFCHAN_SWITCH_COMPLETE        --         FOREIGN_CHANNEL           --                --              --             --            --
OFFCHAN_SWITCH_FAILED          --           SUSPENDING              --                --              --             --            --
OFFCHAN_RETRY_EXPIRE           --           SUSPENDING          TERMINATING       TERMINATING     TERMINATING        --       TERMINATING
SCHEDULE_BSS_COMPLETE          --              --                   --             RESUMING           --             --            --
TERMINATING_TIMEOUT            --              --                   --                --              --             --            --
PREEMPT_REQUEST                --           TERMINATING         TERMINATING       TERMINATING     TERMINATING        --       TERMINATING

BSSCHAN_SWITCH_COMPLETE will take to different states based on whether pause requested/resume requested.
          if Radio Meas and resume requested, then Next state would be BSSCHAN/IDLE based on scan already in progress or not.
          if Radio Meas requested and Pause Request has not yet handled, then Next state would be RADIO_MEAS.
          if Radio Meas not requested, then Next state would be BSSCHAN.

RESUME_REQUEST will resume to a different states based on when it went in to RADIO_MEASUREMENT state.
          if RADIO_MEAS at FAKESLEEP_WAIT then the resume state would be the same .
          if RADIO_MEAS at FOREIGN_CHANNEL then the resume state would be the same .
          if RADIO_MEAS at BSSCHAN or BSSCHAN_RESTTIME or BSSCHAN_CONTINUE then the resume state would be BSSCHAN .
          if RADIO_MEAS at IDLE or TERMINATING then the resume state would be IDLE if no scan request comes in the middle
          else it would be BSSCHAN .

--------------------------------------------------------------------------------------------------------------


##For Foreground Scan
event       curstate -->      IDLE          SUSPENDING         FOREIGN_CHANNEL       TERMINATING        RADIO_MEASUREMENT
                                             TRAFFIC
---------------------------------------------------------------------------------------------------------------------------

NONE                           --               --                  --                   --               --
PROBEDELAY_EXPIRE              --               --             FOREIGN_CHANNEL           --               --
MINDWELL_EXPIRE                --               --             FOREIGN_CHANNEL           --               --
MAXDWELL_EXPIRE                --               --             FOREIGN_CHANNEL           --               --
SCAN_REQUEST               SUSPENDING           --                  --                   --               --
CANCEL_REQUEST                 --               --               TERMINATING         TERMINATING      TERMINATING
RADIO_MEAS_REQUEST             --               --               RADIO_MEAS          RADIO_MEAS           --
RESTART_REQUEST             SUSPENDING          --             FOREIGN_CHANNEL           --              --
MAXSCANTIME_EXPIRE             --               --               TERMINATING         TERMINATING       RADIO_MEAS
BSSCHAN_SWITCH_COMPLETE        --               --                  --                  IDLE             --
OFFCHAN_SWITCH_COMPLETE        --         FOREIGN_CHANNEL           --                   --              --
OFFCHAN_SWITCH_FAILED          --           SUSPENDING              --                   --              --
OFFCHAN_RETRY_EXPIRE           --           TERMINATING          TERMINATING         TERMINATING     TERMINATING
SCHEDULE_BSS_COMPLETE          --              --                   --                RESUMING           --
TERMINATING_TIMEOUT            --              --                   --                   --              --
PREEMPT_REQUEST                --              --                TERMINATING         TERMINATING      TERMINATING

RESUME_REQUEST will resume to a different states based on when it went in to RADIO_MEAS state.
          if RADIO_MEAS at FOREIGN_CHANNEL then the resume state would be the same .

**** Rest of the events are not relevant to Foreground scan.
-----------------------------------------------------------------------------------------------------------------------------------------


##For Repeater Scan
event       curstate -->      IDLE          REPEATER         TERMINATING        RADIO_MEASUREMENT
                                             SCAN
---------------------------------------------------------------------------------------------------

NONE                           --                --                --               --
PROBEDELAY_EXPIRE              --             TERMINATING          --               --
MINDWELL_EXPIRE                --             TERMINATING          --               --
MAXDWELL_EXPIRE                --             TERMINATING          --               --
SCAN_REQUEST               REPEATER_SCAN         --                --               --
CANCEL_REQUEST                 --             TERMINATING      TERMINATING      TERMINATING
RADIO_MEAS_REQUEST             --             RADIO_MEAS       RADIO_MEAS           --
RESTART_REQUEST            REPEATER SCAN      TERMINATING          --               --
MAXSCANTIME_EXPIRE             --             TERMINATING      TERMINATING       RADIO_MEAS
BSSCHAN_SWITCH_COMPLETE        --                --                IDLE             --
OFFCHAN_SWITCH_COMPLETE        --                --                --               --
OFFCHAN_SWITCH_FAILED          --                --                --               --
OFFCHAN_RETRY_EXPIRE           --             TERMINATING      TERMINATING     TERMINATING
SCHEDULE_BSS_COMPLETE          --                --               RESUMING          --
TERMINATING_TIMEOUT            --                --                --               --
PREEMPT_REQUEST                --             TERMINATING      TERMINATING      TERMINATING


**** Rest of the events are not relevant to Foreground scan.
-----------------------------------------------------------------------------------------------------------------------------------------

*/

#define IEEE80211_CHECK_EXIT_CRITERIA_INTVAL           100
#define IEEE80211_RESMGR_MAX_LEAVE_BSS_DELAY           20
#define IEEE80211_SCAN_REQUESTOR_MAX_MODULE_NAME       64
#if ATH_SUPPORT_AP_WDS_COMBO || ATH_SUPPORT_WRAP
/* Qwrap currently need approx 3 max requestors per sta vap
 * to get all max psta successfully connected to Root. This
 * total 95 to connect all psta clients,connection sm and
 * offchan scan.
 */
#define IEEE80211_MAX_REQUESTORS                       95
#else
#define IEEE80211_MAX_REQUESTORS                       34
#endif

#define IEEE80211_REQ_ID_PREFIX                    0x8000

/* Request ID used to communicate to Resource Manager */
#define SCANNER_RESMGR_REQID                           77

#define IEEE80211_MIN_MINDWELL                          0 /* msec */
#define IEEE80211_MAX_MAXDWELL                       5000 /* msec */
#define IEEE80211_FAKESLEEP_WAIT_TIMEOUT             1000 /* msec */
#define IEEE80211_VAP_SUSPEND_DELAY                   100 /* msec */
#define IEEE80211_MIN_OFFCHAN_RETRY_DELAY              50 /* msec */
#define IEEE80211_MAX_OFFCHAN_RETRIES                  20 /* no units */
#define IEEE80211_MAX_OFFCHAN_RETRY_TIME            10000 /* no units */
#define IEEE80211_RESMGR_WAIT_TIMEOUT                1500 /* msec */
#define IEEE80211_CANCEL_RETRY_DELAY                   20 /* msec */
#define IEEE80211_CANCEL_TIMEOUT                     5000 /* msec */
#define IEEE80211_CAN_PAUSE_WAIT_DELAY                 10 /* msec */
typedef struct scanner_requestor_info {
    IEEE80211_SCAN_REQUESTOR    requestor;
    u_int8_t                    module_name[IEEE80211_SCAN_REQUESTOR_MAX_MODULE_NAME];
} scanner_requestor_info_t;

/* Qwrap currently need atleast 5 scan event handlers for each
 * sta vap to get all max psta successfully connected to Root
 * This 5 count should be adjusted/derived based on no of modules
 * which are intrested in scan events. Total 31 sta * 5 = 155 handlers
 */
#if ATH_SUPPORT_AP_WDS_COMBO || ATH_SUPPORT_WRAP
#define IEEE80211_MAX_SCAN_EVENT_HANDLERS              155
#else
#define IEEE80211_MAX_SCAN_EVENT_HANDLERS              64
#endif

struct ieee80211_scanner {
    struct ieee80211_scanner_common    ss_common; /* public data.  always need to be at the top */

    /* Driver-wide data structures */
    wlan_dev_t                          ss_ic;
    wlan_if_t                           ss_vap;
    osdev_t                             ss_osdev;
    ieee80211_resmgr_t                  ss_resmgr;
    ieee80211_scan_scheduler_t          ss_scheduler;

    spinlock_t                          ss_lock;

    u_int32_t                           ss_run_counter; /* number of scans requested */

    /*
     * Scan state machine.
     */
    ieee80211_hsm_t                     ss_hsm_handle;

    /*
     * 2 timers:
     *     -Generic timer controlling the amount of time spent in each state;
     *     -Maximum duration the scan can run.
     *
     * One auxiliary variable to map expiration of the generic timer into
     * different events.
     */
    os_timer_t                          ss_timer;
    os_timer_t                          ss_maxscan_timer;

#if !ATH_SUPPORT_MULTIPLE_SCANS && defined USE_WORKQUEUE_FOR_MESGQ_AND_SCAN
    qdf_work_t                       ss_timer_defered;         /* work queue for scan_timer defered */
    qdf_work_t                       ss_maxscan_timer_defered; /* work queue for max scan timer defered */
#endif

    enum scanner_event                  ss_pending_event;

    /*
     * General scan information - scan type (foreground/background), flags,
     * request id (ID of the client which requested the scan) and start time.
     */
    ieee80211_scan_type                 ss_type;
    u_int16_t                           ss_flags;
    IEEE80211_SCAN_REQUESTOR            ss_requestor;
    IEEE80211_SCAN_ID                   ss_scan_id;
    IEEE80211_SCAN_PRIORITY             ss_priority;
    systime_t                           ss_scan_start_time;
    systime_t                           ss_last_full_scan_time;

    /*
     * Number of off-channel retries and maximum allowed.
     */
    u_int16_t                           ss_offchan_retry_count;
    u_int16_t                           ss_max_offchan_retries;

    /* List of clients to be notified about scan events */
    u_int16_t                           ss_num_handlers;
    ieee80211_scan_event_handler        ss_event_handlers[IEEE80211_MAX_SCAN_EVENT_HANDLERS];
    void                                *ss_event_handler_arg[IEEE80211_MAX_SCAN_EVENT_HANDLERS];

    /*
     * List of SSIDs and BSSIDs:
     * Probe requests are sent to each BSSID in the list (usually the wildcard
     * BSSID), one request for each SSID in the list.
     * The specified IE elements are added to the probe requests.
     */
    u_int8_t                            ss_nssid;                /* # ssid's to probe/match */
    ieee80211_ssid                      ss_ssid[IEEE80211_SCAN_MAX_SSID];
    u_int8_t                            ss_nbssid;               /* # bssid's to probe */
    u_int8_t                            ss_bssid[IEEE80211_SCAN_MAX_BSSID][IEEE80211_ADDR_LEN];
    u_int32_t                           ss_ielen;
    u_int8_t                            *ss_iedata;

    /* List of channels to be scanned, and list containing all channels. */
    u_int16_t                           ss_nreqchans;                      /* requested number of channels */
    u_int32_t                           ss_reqchans[IEEE80211_SCAN_MAX];   /* list of requested channels */
    u_int16_t                           ss_nchans;                         /* # chan's to scan */
    struct ieee80211_channel            *ss_chans[IEEE80211_SCAN_MAX];
    u_int16_t                           ss_nallchans;                      /* # all chans's to scan */
    struct ieee80211_channel            *ss_all_chans[IEEE80211_SCAN_MAX];
    u_int16_t                           ss_next;                           /* index of next chan to scan */

    /* Timing values for each phase of the scan procedure - all in ms */
    u_int32_t                           ss_cur_min_dwell;        /* min dwell time on the current foreign channel */
    u_int32_t                           ss_cur_max_dwell;        /* max dwell time on the current foreign channel */
    u_int32_t                           ss_min_dwell_active;     /* min dwell time on an active channel */
    u_int32_t                           ss_max_dwell_active;     /* max dwell time on an active channel */
    u_int32_t                           ss_min_dwell_passive;    /* min dwell time on a passive channel */
    u_int32_t                           ss_max_dwell_passive;    /* max dwell time on a passive channel */
    u_int32_t                           ss_min_rest_time;        /* minimum rest time on channel */
    u_int32_t                           ss_init_rest_time;       /* initial rest time on channel */
    u_int32_t                           ss_max_rest_time;        /* maximum rest time on channel */
    u_int32_t                           ss_probe_delay;          /* time delay before sending first probe request */
    u_int32_t                           ss_repeat_probe_time;    /* time delay before sending subsequent probe requests */
    u_int32_t                           ss_offchan_retry_delay;  /* delay to wait before retrying off channel switch */
    u_int32_t                           ss_idle_time;            /* idle time on bss channel */
    u_int32_t                           ss_exit_criteria_intval; /* time interval before rechecking conditions to leave channel */
    u_int32_t                           ss_max_scan_time;        /* maximum time to finish scanning */
    u_int32_t                           ss_min_beacon_count;     /* number of home AP beacons to receive before leaving the home channel */
    u_int32_t                           ss_beacons_received;     /* number of beacons received from the home AP */
    u_int32_t                           ss_beacon_timeout;       /* maximum time to wait for beacons */
    u_int32_t                           ss_fakesleep_timeout;    /* maximum time to wait for a notification of transmission of a Null Frame */
    u_int32_t                           ss_max_offchannel_time;  /* maximum time to spend off-channel (cumulative for several consecutive foreign channels) */
    systime_t                           ss_offchannel_time;      /* time scanner first went off-channel - reset on every return to BSS channel */

    /* flags controlling scan's execution */
    u_int32_t                           ss_multiple_ports_active          : 1,
                                        ss_visit_home_channel             : 1,
                                        ss_suspending_traffic             : 1,
                                        ss_completion_indications_pending : 1,
                                        ss_restricted                     : 1, /* perform restricted scan */
                                        ss_scan_start_event_posted        : 1; /* Due to scan pause, scan start will be handled from scan_radio_meas state
                                                                                  This flag tells us whether scan request came after pause request or
                                                                                   before pause request. This flag will be true if scan came first then
                                                                                   pause else it will be false */
    atomic_t                            ss_wait_for_beacon;
    atomic_t                            ss_beacon_event_queued;

    systime_t                           ss_enter_channel_time;
    systime_t                           ss_currscan_home_entry_time;
    /*
     * State information - current state, suspend state (if a scan pause is
     * requested).
     */
    enum scanner_state                  ss_suspend_state;

    scanner_requestor_info_t            ss_requestors[IEEE80211_MAX_REQUESTORS];

    /*
     * Client-specified termination condition.
     * Scan will end if a client-specified terminating condition is found.
     */
    ieee80211_scan_termination_check    ss_check_termination_function;
    void                                *ss_check_termination_context;

    /* termination reason */
    ieee80211_scan_completion_reason    ss_termination_reason;

    /* state in which scan was preempted */
    scanner_preemption_data_t           ss_preemption_data;

    /* callbacks */
    bool (*ss_is_connected) (wlan_if_t);
    bool (*ss_is_txq_empty) (wlan_dev_t);
    bool (*ss_is_sw_txq_empty) (wlan_dev_t);
};

struct ieee80211_scan_event_data {
    wlan_if_t                           vap;
    IEEE80211_SCAN_ID                   scan_id;
    IEEE80211_SCAN_REQUESTOR            requestor;
    ieee80211_scan_event_type           event;
    ieee80211_scan_completion_reason    reason;
};

struct ieee80211_scan_cancel_data {
    wlan_if_t                           vap;
    IEEE80211_SCAN_ID                   scan_id;
    IEEE80211_SCAN_REQUESTOR            requestor;
    u_int32_t                           flags;
};

static const u_int16_t scan_order[] = {
    /* 2.4Ghz ch: 1,6,11,7,13 */
    2412, 2437, 2462, 2442, 2472,
    /* 8 FCC channel: 52, 56, 60, 64, 36, 40, 44, 48 */
    5260, 5280, 5300, 5320, 5180, 5200, 5220, 5240,
    /* 4 MKK channels: 34, 38, 42, 46 */
    5170, 5190, 5210, 5230,
    /* 2.4Ghz ch: 2,3,4,5,8,9,10,12 */
    2417, 2422, 2427, 2432, 2447, 2452, 2457, 2467,
    /* 2.4Ghz ch: 14 */
    2484,
    /* 6 FCC channel:144, 149, 153, 157, 161, 165 */
    5720, 5745, 5765, 5785, 5805, 5825,
    /* 11 ETSI channel: 100,104,108,112,116,120,124,128,132,136,140 */
    5500, 5520, 5540, 5560, 5580, 5600, 5620, 5640, 5660, 5680, 5700,
    /* Added Korean channels 2312-2372 */
    2312, 2317, 2322, 2327, 2332, 2337, 2342, 2347, 2352, 2357, 2362, 2367,
    2372 ,
    /* Added Japan channels in 4.9/5.0 spectrum */
    5040, 5060, 5080, 4920, 4940, 4960, 4980,
    /* FCC4 channels */
    4950, 4955, 4965, 4970, 4975, 4985,
    /* Added MKK2 half-rates */
    4915, 4920, 4925, 4935, 4940, 4945, 5035, 5040, 5045, 5055,
    /* Added FCC4 quarter-rates */
    4942, 4947, 4952, 4957, 4962, 4967, 4972, 4977, 4982, 4987,
    /* Add MKK quarter-rates */
    4912, 4917, 4922, 4927, 4932, 4937, 5032, 5037, 5042, 5047, 5052, 5057,
};

#define IEEE80211_SCAN_PRINTF(_ss, _cat, _fmt, ...)           \
    if (ieee80211_msg_ic((_ss)->ss_ic, _cat)) {               \
        ieee80211com_note((_ss)->ss_ic, _cat, _fmt, __VA_ARGS__);   \
    }

/* Forward declarations */
static bool scanner_leave_bss_channel(ieee80211_scanner_t ss);
static bool scanner_can_leave_home_channel(ieee80211_scanner_t ss);
int ieee80211_scan_get_preemption_data(ieee80211_scanner_t       ss,
                                       IEEE80211_SCAN_REQUESTOR  requestor,
                                       IEEE80211_SCAN_ID         scan_id,
                                       scanner_preemption_data_t *preemption_data);
static int  freqs[IEEE80211_CHAN_MAX];

static void ieee80211_scan_sm_debug_print (void *context, const char *fmt, ...)
{
    ieee80211_scanner_t    ss = context;
    char                   tmp_buf[256];
    va_list                ap;
    u_int32_t              now = (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());

    va_start(ap, fmt);
    vsnprintf(tmp_buf, sizeof(tmp_buf), fmt, ap);
    va_end(ap);
    tmp_buf[sizeof(tmp_buf) - 1] = '\0';

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN_SM, "%d.%03d | %s",
        now / 1000, now % 1000, tmp_buf);
}

static const char* ieee80211_scan_event_name(enum scanner_event event)
{
    ASSERT(event < IEEE80211_N(scanner_event_name));

    return (scanner_event_name[event]);
}

static void*
ieee80211_scan_scheduler_object(ieee80211_scanner_t ss)
{
#if ATH_SUPPORT_MULTIPLE_SCANS
    return ss->ss_scheduler;
#else
    return ss;
#endif    /* ATH_SUPPORT_MULTIPLE_SCANS */
}

static inline bool
is_passive_channel(struct ieee80211_channel *channel,
                   u_int16_t                scan_flags)
{
    return ((scan_flags & IEEE80211_SCAN_PASSIVE) ||
             IEEE80211_IS_CHAN_PASSIVE(channel)   ||
             IEEE80211_IS_CHAN_CSA(channel));
}

static void
scanner_post_event(ieee80211_scanner_t                 ss,
                   wlan_if_t                           vaphandle,
                   ieee80211_scan_event_type           type,
                   ieee80211_scan_completion_reason    reason,
                   IEEE80211_SCAN_ID                   scan_id,
                   IEEE80211_SCAN_REQUESTOR            requestor,
                   wlan_chan_t                         chan)
{
    ieee80211_scan_event            scan_event;
    int                             i, num_handlers;
    ieee80211_scan_event_handler    *ss_event_handlers = NULL;
    void                            **ss_event_handler_arg = NULL;

    ss_event_handlers = (ieee80211_scan_event_handler *)
        OS_MALLOC(ss->ss_osdev,(sizeof(ieee80211_scan_event_handler) * IEEE80211_MAX_SCAN_EVENT_HANDLERS), GFP_ATOMIC);
    if (!ss_event_handlers) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: unable to allocate temporary copy of event handlers,"
                " Dropping scan event\n", __func__);
        return ;
    }

    ss_event_handler_arg = (void **)
        OS_MALLOC(ss->ss_osdev,(sizeof(void *) * IEEE80211_MAX_SCAN_EVENT_HANDLERS), GFP_ATOMIC);

    if (!ss_event_handler_arg) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,  "%s: unable to allocate temporary copy of event handlers argument,"
                " Dropping scan event\n", __func__);
        OS_FREE(ss_event_handlers);
        ss_event_handlers = NULL;
        return ;
    }
    /*
     * Do not use any fields that may be modified by a simultaneous call to
     * ieee80211_scan_run.
     */
    OS_MEMZERO(&scan_event, sizeof(scan_event));
    scan_event.type      = type;
    scan_event.reason    = reason;
    scan_event.chan      = chan;
    scan_event.requestor = requestor;
    scan_event.scan_id   = scan_id;

    /*
    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: vap=%08p scan_id=%d type=%s reason=%s chan=%3d module=%s\n",
        __func__,
        vaphandle,
        ss->ss_scan_id,
        wlan_scan_notification_event_name(scan_event.type),
        wlan_scan_notification_reason_name(scan_event.reason),
        wlan_channel_ieee(scan_event.chan),
        ieee80211_scan_get_requestor_name(ss, scan_event.requestor));
    */

    /*
     * Inform the scheduler that an event notification is about to be sent to
     * registered modules.
     * The scheduler may need to process certain notifications before other
     * modules to ensure any calls to wlan_get_last_scan_info will return
     * consistent data.
     */
    ieee80211_scan_scheduler_preprocess_event(ieee80211_scan_scheduler_object(ss), &scan_event);

    spin_lock(&ss->ss_lock);

    /*
     * make a local copy of event handlers list to avoid
     * the call back modifying the list while we are traversing it.
     */
    num_handlers = ss->ss_num_handlers;
    for (i = 0; i < num_handlers; ++i) {
        ss_event_handlers[i] = ss->ss_event_handlers[i];
        ss_event_handler_arg[i] = ss->ss_event_handler_arg[i];
    }

    for (i = 0; i < num_handlers; ++i) {
        if ((ss_event_handlers[i] != ss->ss_event_handlers[i]) ||
            (ss_event_handler_arg[i] != ss->ss_event_handler_arg[i]))
        {
            /*
             * There is a change in the event list.
             * Traverse the original list to see this event is still valid.
             */
            int     k;
            bool    found = false;
            for (k = 0; k < ss->ss_num_handlers; k++) {
                if ((ss_event_handlers[i] == ss->ss_event_handlers[k]) &&
                    (ss_event_handler_arg[i] == ss->ss_event_handler_arg[k]))
                {
                    /* Found a match */
                    found = true;
                    break;
                }
            }
            if (!found) {
                /* Did not find a match. Skip this event call back. */
                IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY,
                                      "%s: Skip event handler since it is unreg. Type=%d. cb=0x%x, arg=0x%x\n",
                                      __func__, type, ss_event_handlers[i], ss_event_handler_arg[i]);
                continue;
            }
        }

        if (ss_event_handlers[i] == NULL) {
            IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY,
                                  "%s: ss_event_handlers[%d]==NULL arg=%08p num_handlers=%d/%d\n",
                                  __func__,
                                  i, ss_event_handler_arg[i],
                                  num_handlers, ss->ss_num_handlers);
            continue;
        }

        /* Calling the event handler without the lock */
        spin_unlock(&ss->ss_lock);

        (ss_event_handlers[i]) (vaphandle, &scan_event, ss_event_handler_arg[i]);

        /* Reacquire lock to check next event handler */
        spin_lock(&ss->ss_lock);
    }

    /* Calling the event handler without the lock */
    spin_unlock(&ss->ss_lock);

    /*
     * Inform the scheduler that an event notification has been sent to
     * registered modules.
     * The scheduler may need to process certain notifications after other
     * modules to ensure any calls to wlan_get_last_scan_info will return
     * consistent data.
     */
    ieee80211_scan_scheduler_postprocess_event(ieee80211_scan_scheduler_object(ss), &scan_event);

    OS_FREE(ss_event_handlers);
    ss_event_handlers = NULL;
    OS_FREE(ss_event_handler_arg);
    ss_event_handler_arg = NULL;
}

static void scanner_construct_chan_list(ieee80211_scanner_t ss, wlan_if_t vaphandle)
{
#define FREQUENCY_THRESH 1000
    int    i;

    if (vaphandle) {
        if (vaphandle->iv_scan_band == IEEE80211_SCAN_BAND_2G_ONLY)
            ss->ss_flags &= ~IEEE80211_SCAN_5GHZ;
        else if (vaphandle->iv_scan_band == IEEE80211_SCAN_BAND_5G_ONLY)
            ss->ss_flags &= ~IEEE80211_SCAN_2GHZ;
    }

    /*
     * construct channel list from the list of channels passed in
     * if any and the list of channels available.
     */
    if (ss->ss_nreqchans == 0)
    {
        ss->ss_nchans = 0;
        /* scan all supported channels */
        if ((ss->ss_flags & (IEEE80211_SCAN_ALLBANDS)) == IEEE80211_SCAN_ALLBANDS) {

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
            ss->ss_nchans = 0;
            for (i = 0; i < ss->ss_nallchans; ++ i) {
                struct ieee80211_channel *ichan;
                ichan = ss->ss_all_chans[i];
                /* Remove the  channels for NOL is set*/
                if(!IEEE80211_IS_CHAN_RADAR(ichan)) {
                    ss->ss_chans[ss->ss_nchans++] = ss->ss_all_chans[i];
                }
            }
#else
            ss->ss_nchans = ss->ss_nallchans;
            OS_MEMCPY(ss->ss_chans, ss->ss_all_chans, sizeof(struct ieee80211_channel *) * ss->ss_nallchans);
#endif
        } else {
            for (i = 0; i < ss->ss_nallchans; ++ i) {
                if ((ss->ss_flags & IEEE80211_SCAN_2GHZ) ?
                    IEEE80211_IS_CHAN_2GHZ(ss->ss_all_chans[i]) : IEEE80211_IS_CHAN_5GHZ(ss->ss_all_chans[i])) {

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
                    struct ieee80211_channel *ichan;
                    ichan = ss->ss_all_chans[i];
                    if(!IEEE80211_IS_CHAN_RADAR(ichan)) {
                        ss->ss_chans[ss->ss_nchans++] = ss->ss_all_chans[i];
                    }
#else
                    ss->ss_chans[ss->ss_nchans++] = ss->ss_all_chans[i];
#endif
                }
            }
        }
    } else {
        int    j;

        ss->ss_nchans = 0;

        for (i = 0; i < ss->ss_nreqchans; ++i) {
            if (ss->ss_reqchans[i] < FREQUENCY_THRESH) {
                if (ss->ss_reqchans[i] < 20)
                    freqs[i] = ieee80211_ieee2mhz(ss->ss_ic, ss->ss_reqchans[i], IEEE80211_CHAN_2GHZ);
                else
                    freqs[i] = ieee80211_ieee2mhz(ss->ss_ic, ss->ss_reqchans[i], IEEE80211_CHAN_5GHZ);
            } else {
                freqs[i] = ss->ss_reqchans[i];
            }
        }

        //for (i = 0; i < ss->ss_nallchans; ++i) {
        //    for (j = 0; j < ss->ss_nreqchans; ++j) {
        //        if (ieee80211_chan2freq(ss->ss_ic, ss->ss_all_chans[i]) == freqs[j])
        //            break; /* channel found in the list */
        //    }

        //    if (j == ss->ss_nreqchans)
        //        continue; /* channel not found go to next channel */

        //    ss->ss_chans[ss->ss_nchans++] = ss->ss_all_chans[i];
        //}
        for (i = 0; i < ss->ss_nreqchans; ++i) {
            for (j = 0; j < ss->ss_nallchans; ++j) {
                if (freqs[i] == ieee80211_chan2freq(ss->ss_ic, ss->ss_all_chans[j]))
                    break; /* channel found in the list */
            }

            if (j == ss->ss_nallchans)
                continue; /* channel not found go to next channel */

            if(!(ss->ss_flags & IEEE80211_SCAN_2GHZ) &&
                IEEE80211_IS_CHAN_2GHZ(ss->ss_all_chans[j]))
                continue; /* only 5G channel, go to next channel */

            if(!(ss->ss_flags & IEEE80211_SCAN_5GHZ) &&
                IEEE80211_IS_CHAN_5GHZ(ss->ss_all_chans[j]))
                continue; /* only 2G channel, go to next channel */

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
            do {
                struct ieee80211_channel *ichan;
                ichan = ss->ss_all_chans[j];
                if(!IEEE80211_IS_CHAN_RADAR(ichan)) {
                    ss->ss_chans[ss->ss_nchans++] = ss->ss_all_chans[j];
                }
            } while(0);
#else
            ss->ss_chans[ss->ss_nchans++] = ss->ss_all_chans[j];
#endif
        }
    }
#undef FREQUENCY_THRESH
}

static void scanner_clear_preemption_data(ieee80211_scanner_t ss)
{
    OS_MEMZERO(&(ss->ss_preemption_data), sizeof(ss->ss_preemption_data));

    /* After previous statement, (ss->ss_preemption_data.preempted == false) */
}

static void scanner_save_preemption_data(ieee80211_scanner_t ss)
{
    ss->ss_preemption_data.preempted  = true;
    ss->ss_preemption_data.nreqchans  = ss->ss_nreqchans;
    ss->ss_preemption_data.nchans     = ss->ss_nchans;
    ss->ss_preemption_data.nallchans  = ss->ss_nallchans;
    ss->ss_preemption_data.next       = ss->ss_next;

    /* Repeat channel being currently scanner upon resumption */
    if (ss->ss_preemption_data.next > 0) {
        ss->ss_preemption_data.next--;
    }

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: next=%d/%d nreqchans=%d nallchans=%d\n",
        __func__,
        ss->ss_preemption_data.next,
        ss->ss_preemption_data.nchans,
        ss->ss_preemption_data.nreqchans,
        ss->ss_preemption_data.nallchans);
}

static void ieee80211_scan_handle_vap_events(ieee80211_vap_t vap, ieee80211_vap_event *event, void *arg)
{
    ieee80211_scanner_t    ss = (ieee80211_scanner_t) arg;

    switch(event->type)
    {
    case IEEE80211_VAP_FULL_SLEEP:
    case IEEE80211_VAP_DOWN:
        ieee80211_scan_connection_lost(ss);
        break;

    default:
        break;
    }
}

static void ieee80211_scan_handle_sta_power_events(struct ieee80211vap *vap, ieee80211_sta_power_event *event, void *arg)
{
    ieee80211_scanner_t    ss = (ieee80211_scanner_t) arg;
    u_int32_t              now = (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());
    enum scanner_event     event_type;

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%d.%03d | %s: state=%s event=%d\n",
        now / 1000, now % 1000, __func__,
        ieee80211_sm_get_current_state_name(ss->ss_hsm_handle),
        event->type);

    if (ieee80211_resmgr_active(ss->ss_ic)) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: Error: unexpected sta power event: state=%s event=%d\n",
            __func__,
            ieee80211_sm_get_current_state_name(ss->ss_hsm_handle),
            event->type);

        return;
    }

    if (event->type == IEEE80211_POWER_STA_PAUSE_COMPLETE) {
        event_type = (event->status ==  IEEE80211_POWER_STA_STATUS_SUCCESS ?
                      SCANNER_EVENT_FAKESLEEP_ENTERED : SCANNER_EVENT_FAKESLEEP_FAILED);

        ieee80211_sm_dispatch(ss->ss_hsm_handle,
                              event_type,
                              0,
                              NULL);
    }
    else {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: state=%s event=%d not handled\n",
            __func__,
            ieee80211_sm_get_current_state_name(ss->ss_hsm_handle),
            event->type);
    }
}

static void ieee80211_schedule_timed_event(ieee80211_scanner_t ss, int msec, enum scanner_event event)
{
    /*
     * ss->ss_pending_event != SCANNER_EVENT_NONE indicates the generic timer
     * has been set but has not expired yet. Trying to start the timer again
     * indicates a flaw in the scanner's behavior.
     */
    if (ss->ss_pending_event != SCANNER_EVENT_NONE) {
        u_int32_t    now = (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());

        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%d.%03d | %s: Timer already set. Event: current=%d new=%d\n",
                              now / 1000, now % 1000, __func__,
                              ss->ss_pending_event, event);
    }

    ss->ss_pending_event = event;
    OS_SET_TIMER(&ss->ss_timer, msec);
}

static void ieee80211_scan_handle_resmgr_events(ieee80211_resmgr_t            resmgr,
                                                ieee80211_resmgr_notification *notification,
                                                void                          *arg)
{
    ieee80211_scanner_t    ss = (ieee80211_scanner_t) arg;
    u_int32_t              now = (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%d.%03d | %s:%s state=%s event %s (%d) status=%08X\n",
                          now / 1000, now % 1000, __func__,
                          ss->ss_common.ss_info.si_scan_in_progress ? "" : " IGNORED",
                          ieee80211_sm_get_current_state_name(ss->ss_hsm_handle),
                          ieee80211_resmgr_get_notification_type_name(ss->ss_resmgr,notification->type),
                          notification->type,
                          notification->status);

    /* Skip any ResMgr events if scan not running */
    if (! ss->ss_common.ss_info.si_scan_in_progress) {
        return;
    }

    switch (notification->type) {
    case IEEE80211_RESMGR_BSSCHAN_SWITCH_COMPLETE:
        ieee80211_sm_dispatch(ss->ss_hsm_handle,
                              SCANNER_EVENT_BSSCHAN_SWITCH_COMPLETE,
                              0,
                              NULL);
        break;

    case IEEE80211_RESMGR_OFFCHAN_SWITCH_COMPLETE:
        if (notification->status == EOK) {
            ieee80211_sm_dispatch(ss->ss_hsm_handle,
                                  SCANNER_EVENT_OFFCHAN_SWITCH_COMPLETE,
                                  0,
                                  NULL);
        }
        else {
            ieee80211_sm_dispatch(ss->ss_hsm_handle,
                                  SCANNER_EVENT_OFFCHAN_SWITCH_FAILED,
                                  0,
                                  NULL);
        }
        break;

    case IEEE80211_RESMGR_VAP_START_COMPLETE:
        break;

    case IEEE80211_RESMGR_CHAN_SWITCH_COMPLETE:
        ieee80211_sm_dispatch(ss->ss_hsm_handle,
                              SCANNER_EVENT_CHAN_SWITCH_COMPLETE,
                              0,
                              NULL);
        break;

    case IEEE80211_RESMGR_SCHEDULE_BSS_COMPLETE:
        ieee80211_sm_dispatch(ss->ss_hsm_handle,
                              SCANNER_EVENT_SCHEDULE_BSS_COMPLETE,
                              0,
                              NULL);
        break;

    case IEEE80211_RESMGR_OFFCHAN_ABORTED:
        /*
         * Off-channel operation aborted, probably because of VAP UP.
         * Stop scan immediately.
         */
        ieee80211_sm_dispatch(ss->ss_hsm_handle,
                              SCANNER_EVENT_OFFCHAN_SWITCH_ABORTED,
                              0,
                              NULL);
        break;

    default:
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: ignored ResMgr event %s\n",
            __func__,
                              ieee80211_resmgr_get_notification_type_name(ss->ss_resmgr,notification->type));
        break;
    }
}

int ieee80211_scan_run(ieee80211_scanner_t ss,
                       wlan_if_t           vaphandle,
                       scan_request_data_t *request_data)
{
    int                      i;
    systime_t                current_system_time;
    bool                     bcast_bssid = false;
    ieee80211_scan_params    *params = request_data->params;

    /*
     * sanity check all the params.
     */
    if (params->min_dwell_time_active < IEEE80211_MIN_MINDWELL) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY,
            "%s: invalid min dwell time active %d (< MIN %d)\n",
            __func__,
            params->min_dwell_time_active,
            IEEE80211_MIN_MINDWELL);

        return EINVAL;
    }
    if (params->min_dwell_time_active > params->max_dwell_time_active) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY,
            "%s: invalid min dwell time active %d (< max dwell time active %d)\n",
            __func__,
            params->min_dwell_time_active,
            params->max_dwell_time_active);

        return EINVAL;
    }
    if (params->min_dwell_time_active > IEEE80211_MAX_MAXDWELL) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY,
            "%s: invalid min dwell time active %d (> MAX %d)\n",
            __func__,
            params->min_dwell_time_active,
            IEEE80211_MAX_MAXDWELL);

        return EINVAL;
    }
    if (params->min_dwell_time_passive < IEEE80211_MIN_MINDWELL) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY,
            "%s: invalid min dwell time passive %d (< MIN %d)\n",
            __func__,
            params->min_dwell_time_passive, IEEE80211_MIN_MINDWELL);

        return EINVAL;
    }
    if (params->min_dwell_time_passive > params->max_dwell_time_passive) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY,
            "%s: invalid min dwell time passive %d (> max dwell time passive)\n",
            __func__,
            params->min_dwell_time_passive,
            params->max_dwell_time_passive);

        return EINVAL;
    }
    if (params->min_dwell_time_passive > IEEE80211_MAX_MAXDWELL) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY,
            "%s: invalid min dwell time passive %d (> MAX %d)\n",
            __func__,
            params->min_dwell_time_passive,
            IEEE80211_MAX_MAXDWELL);

        return EINVAL;
    }
    if ((params->probe_delay >= params->min_dwell_time_active) &&
        (params->min_dwell_time_active != 0)) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY,
            "%s: invalid probe delay %d (>= min active dwell %d)\n",
            __func__,
            params->probe_delay,
            params->min_dwell_time_active);

        return EINVAL;
    }

    if ((params->flags & IEEE80211_SCAN_BURST) &&
        (params->max_offchannel_time > 0)) {
        if (params->max_offchannel_time < params->min_dwell_time_active) {
            IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY,
                "%s: invalid max_offchannel_time %d (< min active dwell %d)\n",
                __func__,
                params->max_offchannel_time,
                params->min_dwell_time_active);
            /*
             * Print error message but let scan run. It will return to BSS
             * channel after scanning each foreign channel.
             */
        }
        if (params->max_offchannel_time < params->min_dwell_time_passive) {
            IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY,
                "%s: invalid max_offchannel_time %d (>= min passive dwell %d)\n",
                __func__,
                params->max_offchannel_time,
                params->min_dwell_time_passive);
            /*
             * Print error message but let scan run. It will return to BSS
             * channel after scanning each foreign channel.
             */
        }
    }

    /*
     * Validate maximum number of off-channel retries and interval between
     * attempts.
     * Also limit the total time spent trying to go off-channel.
     */
    if (params->offchan_retry_delay < IEEE80211_MIN_OFFCHAN_RETRY_DELAY) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY,
            "%s: invalid offchan retry delay %d (< MIN_OFFCHAN_RETRY %d)\n",
            __func__,
            params->offchan_retry_delay,
            IEEE80211_MIN_OFFCHAN_RETRY_DELAY);

        return EINVAL;
    }
    if (params->max_offchan_retries > IEEE80211_MAX_OFFCHAN_RETRIES) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY,
            "%s: invalid max offchan retries %d (> MAX_OFFCHAN_RETRIES %d)\n",
            __func__,
            params->max_offchan_retries, IEEE80211_MAX_OFFCHAN_RETRIES);

        return EINVAL;
    }
    if ((params->offchan_retry_delay * params->max_offchan_retries) > IEEE80211_MAX_OFFCHAN_RETRY_TIME) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY,
            "%s: invalid (offchan retry delay * retry count) = %d"
            " (> MAX_OFFCHAN_RETRY_TIME %d)\n",
            __func__,
            params->offchan_retry_delay * params->max_offchan_retries,
            IEEE80211_MAX_OFFCHAN_RETRY_TIME);

        return EINVAL;
    }

    /*
     * Validate time before sending second probe request.
     * Range is 0..min_dwell_time_active.
     * A value of 0 indicates Probe Request should not be repeated.
     * A value of min_dwell_time_active currently means that only 1 Probe Request
     * will be sent, but this will probably change in the future.
     */
    if (params->repeat_probe_time < 0) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY,
            "%s: invalid repeat probe time %d (< 0)\n",
            __func__,
            params->repeat_probe_time);

        return EINVAL;
    }
    if (params->repeat_probe_time > params->min_dwell_time_active) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY,
            "%s: invalid repeat probe time %d (> min param dwell %d)\n",
            __func__,
            params->repeat_probe_time,
            params->min_dwell_time_active);

        return EINVAL;
    }

    if (params->num_ssid > IEEE80211_SCAN_MAX_SSID) {
        return EINVAL;
    }
    if (params->num_bssid > IEEE80211_SCAN_MAX_BSSID) {
        return EINVAL;
    }
    if ((params->flags & (IEEE80211_SCAN_ALLBANDS)) == 0) {
        return EINVAL;
    }
    if (params->num_channels > IEEE80211_CHAN_MAX) {
        return EINVAL;
    }

    spin_lock(&ss->ss_lock);
    if (ss->ss_common.ss_info.si_scan_in_progress) {
        spin_unlock(&ss->ss_lock);
        return EINPROGRESS;
    }
    /* Reset offchan scan requestor */
    if(request_data->requestor != vaphandle->offchan_requestor) {
       vaphandle->offchan_requestor = 0;
    }

    /*
     * Read scan parameters
     */
    ss->ss_flags                      = params->flags;
    ss->ss_min_dwell_active           = params->min_dwell_time_active;
    ss->ss_max_dwell_active           = params->max_dwell_time_active;
    ss->ss_min_dwell_passive          = params->min_dwell_time_passive;
    ss->ss_max_dwell_passive          = params->max_dwell_time_passive;
    ss->ss_cur_min_dwell              = params->min_dwell_time_passive;
    ss->ss_cur_max_dwell              = params->max_dwell_time_passive;
    ss->ss_min_rest_time              = params->min_rest_time;
    ss->ss_init_rest_time             = params->init_rest_time;
    ss->ss_max_rest_time              = params->max_rest_time;
    ss->ss_repeat_probe_time          = params->repeat_probe_time;
    ss->ss_offchan_retry_delay        = params->offchan_retry_delay;
    ss->ss_exit_criteria_intval       = IEEE80211_CHECK_EXIT_CRITERIA_INTVAL;
    ss->ss_max_scan_time              = params->max_scan_time;
    ss->ss_idle_time                  = params->idle_time;
    ss->ss_min_beacon_count           = params->min_beacon_count;
    ss->ss_beacon_timeout             = params->beacon_timeout;
    ss->ss_max_offchannel_time        = params->max_offchannel_time;
    ss->ss_type                       = params->type;
    ss->ss_probe_delay                = params->probe_delay;
    ss->ss_requestor                  = request_data->requestor;
    ss->ss_scan_id                    = request_data->scan_id;
    ss->ss_priority                   = request_data->priority;
    ss->ss_multiple_ports_active      = params->multiple_ports_active;
    ss->ss_restricted                 = params->restricted_scan;
    ss->ss_nreqchans                  = params->num_channels;
    ss->ss_termination_reason         = IEEE80211_REASON_NONE;
    ss->ss_check_termination_function = params->check_termination_function;
    ss->ss_check_termination_context  = params->check_termination_context;
    ss->ss_max_offchan_retries        = params->max_offchan_retries;

    if (params->num_channels) {
        ASSERT(params->chan_list != NULL);

        OS_MEMCPY(ss->ss_reqchans, params->chan_list, params->num_channels * sizeof(u_int32_t));
    }

    ss->ss_nssid = params->num_ssid;
    for (i = 0; i < params->num_ssid; ++i) {
        ss->ss_ssid[i].len = params->ssid_list[i].len;
        OS_MEMCPY(ss->ss_ssid[i].ssid, params->ssid_list[i].ssid, ss->ss_ssid[i].len);
    }

    ss->ss_nbssid = params->num_bssid;
    for (i = 0; i < params->num_bssid; ++i) {
        IEEE80211_ADDR_COPY(ss->ss_bssid[i], params->bssid_list[i]);
        if (IEEE80211_IS_BROADCAST(ss->ss_bssid[i])) {
            bcast_bssid = true;
        }
    }
    if (params->flags & IEEE80211_SCAN_ADD_BCAST_PROBE) {
        /* if there are no ssid add a null ssid */
        if (ss->ss_nssid == 0) {
            ss->ss_ssid[ss->ss_nssid].len = 0;
            ss->ss_ssid[ss->ss_nssid].ssid[0] = 0;
            ss->ss_nssid++;
        }
        if (!bcast_bssid && (ss->ss_nbssid < IEEE80211_SCAN_MAX_BSSID)) {
            u_int8_t broadcast_addr[IEEE80211_ADDR_LEN] = {0xff,0xff,0xff,0xff,0xff,0xff};
            IEEE80211_ADDR_COPY(ss->ss_bssid[ss->ss_nbssid],broadcast_addr);
            ss->ss_nbssid++;
        }
    }

    if (params->ie_len > ss->ss_ielen) {
        if (ss->ss_iedata) {
            OS_FREE(ss->ss_iedata);
        }

        ss->ss_iedata = (u_int8_t *) OS_MALLOC(ss->ss_osdev, params->ie_len, 0);
        if (ss->ss_iedata == NULL) {
            spin_unlock(&ss->ss_lock);
            return ENOMEM;
        }
    }

    ss->ss_ielen = params->ie_len;
    if (params->ie_len) {
        OS_MEMCPY(ss->ss_iedata, params->ie_data, params->ie_len);
    }

    scanner_construct_chan_list(ss, vaphandle);
    if (ss->ss_nchans == 0) {
        /* Got empty list of channels. Cannot let scan starts. */
        spin_unlock(&ss->ss_lock);
        return EINVAL;
    }

    /*
     * If scan is being resumed after preemption, verify that number of
     * supported channels has not changed.
     */
    if (request_data->preemption_data.preempted) {
        if (request_data->preemption_data.nallchans != ss->ss_nallchans) {
            /* Total number of channels supported by HW changed. */
            spin_unlock(&ss->ss_lock);
            return EINVAL;
        }

        if (request_data->preemption_data.nchans != ss->ss_nchans) {
            /*
             * Number of channels in the channel list changed, most likely
             * because of changes in regulatory domain.
             */
            spin_unlock(&ss->ss_lock);
            return EINVAL;
        }

        if (request_data->preemption_data.next >= ss->ss_nchans) {
            /*
             * Channel from where to restart scan is past the end of the scan
             * list. One of the two previous tests should have failed, so
             * something went wrong.
             */
            spin_unlock(&ss->ss_lock);
            return EINVAL;
        }
    }

    /*
     * Prioritized scans should not wait for data traffic to cease before
     * going off-channel, so always make medium- and high-priority scans forced
     */
    if (ss->ss_priority >= IEEE80211_SCAN_PRIORITY_MEDIUM) {
        ss->ss_flags |= IEEE80211_SCAN_NOW;
    }

    /* Scan is now in progress */
    ss->ss_common.ss_info.si_scan_in_progress       = true;
    ss->ss_scan_start_time                = request_data->request_timestamp;

    /*
     * If resuming a preempted scan, start from channel where previous scan
     * stopped.
     */
    if (request_data->preemption_data.preempted) {
        ss->ss_next = request_data->preemption_data.next;

        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: resume preempted scan next=%d/%d nreqchans=%d nallchans=%d\n",
            __func__,
            request_data->preemption_data.next,
            request_data->preemption_data.nchans,
            request_data->preemption_data.nreqchans,
            request_data->preemption_data.nallchans);
    }
    else {
        ss->ss_next = 0;

        scanner_clear_preemption_data(ss);
    }

    current_system_time = OS_GET_TIMESTAMP();

    ss->ss_vap                    = vaphandle;
    ss->ss_fakesleep_timeout      = IEEE80211_FAKESLEEP_WAIT_TIMEOUT;
    ss->ss_visit_home_channel     = (ss->ss_multiple_ports_active ||
                                     (ss->ss_type == IEEE80211_SCAN_BACKGROUND) ||
                                     (ss->ss_type == IEEE80211_SCAN_SPECTRAL));
    ss->ss_offchan_retry_count    = 0;
    ss->ss_currscan_home_entry_time = OS_GET_TIMESTAMP();
    /*
     * Do not reset ss_enter_channel_time so that time spent in the home
     * channel between scans is not lost.
     */
    ss->ss_offchannel_time        = 0;
    ss->ss_run_counter++;

    {
        u_int32_t    now = (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(current_system_time);

        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%d.%03d | %s: module=%s ID=%d flag=%08X type=%d elapsed=%d/%d multiple_ports=%d preempted=%d runctr=%d\n",
                              now / 1000, now % 1000, __func__,
                              ieee80211_scan_get_requestor_name(ss, ss->ss_requestor),
                              ss->ss_scan_id,
                              ss->ss_flags,
                              ss->ss_type,
                              (long) CONVERT_SYSTEM_TIME_TO_MS(current_system_time - ss->ss_scan_start_time),
                              ss->ss_max_scan_time,
                              ss->ss_multiple_ports_active,
                              request_data->preemption_data.preempted,
                              ss->ss_run_counter);
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "    nchans=%02d dwell=(%2d,%2d) (%2d,%2d) repeat_probe=%2d max_offchan_time=%d offchan_retry=(%03d,%02d) VAP=%08p\n",
                              ss->ss_nchans,
                              ss->ss_min_dwell_active,
                              ss->ss_max_dwell_active,
                              ss->ss_min_dwell_passive,
                              ss->ss_max_dwell_passive,
                              ss->ss_repeat_probe_time,
                              ss->ss_max_offchannel_time,
                              ss->ss_offchan_retry_delay,
                              ss->ss_max_offchan_retries,
                              vaphandle);
    }

    if (ieee80211_vap_register_event_handler(vaphandle,
                                             ieee80211_scan_handle_vap_events,
                                             (void *)ss) != 0) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: Failed to register event_handler\n", __func__);
    }

    if (! ieee80211_resmgr_active(ss->ss_ic)) {
        ieee80211_sta_power_register_event_handler(vaphandle,
                                                   ieee80211_scan_handle_sta_power_events,
                                                   ss);
    }

    ieee80211_sm_dispatch(ss->ss_hsm_handle,
                          request_data->preemption_data.preempted ?
                              SCANNER_EVENT_RESTART_REQUEST : SCANNER_EVENT_SCAN_REQUEST,
                          0,
                          NULL);

    /*
     * Set maximum duration time after dispatching start/restart request event.
     * Even it the timer fires immediately (remaining time is 0), the timeout
     * event will be queued after the start/restart event, as it should.
     */
    if (ss->ss_max_scan_time != 0) {
        u_int32_t    elapsed_scan_time;
        u_int32_t    remaining_time;

        elapsed_scan_time = CONVERT_SYSTEM_TIME_TO_MS(current_system_time - ss->ss_scan_start_time);
        if (ss->ss_max_scan_time > elapsed_scan_time) {
            remaining_time = ss->ss_max_scan_time - elapsed_scan_time;
        }
        else {
            remaining_time = 0;
        }

        OS_SET_TIMER(&ss->ss_maxscan_timer, remaining_time);
    }
    ss->ss_vap->iv_bsschan = ss->ss_ic->ic_curchan;
    spin_unlock(&ss->ss_lock);
    return EOK;
}

static int _ieee80211_scan_register_event_handler(ieee80211_scanner_t          ss,
                                          ieee80211_scan_event_handler evhandler,
                                          void                         *arg)
{
    int    i;

    spin_lock(&ss->ss_lock);

    /*
     * Verify that event handler is not yet registered.
     */
    for (i = 0; i < IEEE80211_MAX_SCAN_EVENT_HANDLERS; ++i) {
        if ((ss->ss_event_handlers[i] == evhandler) &&
            (ss->ss_event_handler_arg[i] == arg)) {
            IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: evhandler=%08p arg=%08p already registered\n",
                                  __func__,
                                  evhandler,
                                  arg);

            spin_unlock(&ss->ss_lock);
            return EEXIST;    /* already exists */
        }
    }

    /*
     * Verify that the list of event handlers is not full.
     */
    ASSERT(ss->ss_num_handlers < IEEE80211_MAX_SCAN_EVENT_HANDLERS);
    if (ss->ss_num_handlers >= IEEE80211_MAX_SCAN_EVENT_HANDLERS) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY, "%s: ERROR: No more space: evhandler=%08p arg=%08p\n",
                              __func__,
                              evhandler,
                              arg);
        spin_unlock(&ss->ss_lock);
        return ENOSPC;
    }

    /*
     * Add new handler and increment number of registered handlers.
     * Registered event handlers are guaranteed to occupy entries 0..(n-1) in
     * the table, so we can safely assume entry 'n' is available.
     */
    ss->ss_event_handlers[ss->ss_num_handlers] = evhandler;
    ss->ss_event_handler_arg[ss->ss_num_handlers++] = arg;

    spin_unlock(&ss->ss_lock);
    return EOK;
}

static int _ieee80211_scan_unregister_event_handler(ieee80211_scanner_t          ss,
                                            ieee80211_scan_event_handler evhandler,
                                            void                         *arg)
{
    int    i;

    spin_lock(&ss->ss_lock);
    for (i = 0; i < IEEE80211_MAX_SCAN_EVENT_HANDLERS; ++i) {
        if ((ss->ss_event_handlers[i] == evhandler) &&
            (ss->ss_event_handler_arg[i] == arg)) {
            /*
             * Replace event handler being deleted with the last one in the list
             */
            ss->ss_event_handlers[i]    = ss->ss_event_handlers[ss->ss_num_handlers - 1];
            ss->ss_event_handler_arg[i] = ss->ss_event_handler_arg[ss->ss_num_handlers - 1];

            /*
             * Clear last event handler in the list
             */
            ss->ss_event_handlers[ss->ss_num_handlers - 1]    = NULL;
            ss->ss_event_handler_arg[ss->ss_num_handlers - 1] = NULL;
            ss->ss_num_handlers--;

            spin_unlock(&ss->ss_lock);

            return EOK;
        }
    }
    spin_unlock(&ss->ss_lock);

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY, "%s: Failed to unregister evhandler=%08p arg=%08p\n",
                          __func__,
                          evhandler,
                          arg);
    return ENXIO;
}

int ieee80211_scan_local_set_priority(ieee80211_scanner_t      ss,
                                IEEE80211_SCAN_REQUESTOR requestor,
                                IEEE80211_SCAN_ID        scan_id,
                                IEEE80211_SCAN_PRIORITY  scan_priority)
{
    if ((scan_id != 0) && (ss->ss_scan_id != scan_id)) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY, "%s: Invalid scan_id=%d ss_scan_id=%d\n",
                              __func__,
                              scan_id,
                              ss->ss_scan_id);

#if ATH_SUPPORT_MULTIPLE_SCANS
        return EINVAL;
#endif
    }

    if (ss->ss_common.ss_info.si_scan_in_progress) {
        ss->ss_priority = scan_priority;

        /*
         * Prioritized scans should not wait for data traffic to cease before
         * going off-channel, so always make medium- and high-priority scans forced
         */
        if (scan_priority >= IEEE80211_SCAN_PRIORITY_MEDIUM) {
            ss->ss_flags |= IEEE80211_SCAN_NOW;
        }
    }

    return EOK;
}

int ieee80211_scan_local_set_forced_flag(ieee80211_scanner_t      ss,
                                   IEEE80211_SCAN_REQUESTOR requestor,
                                   IEEE80211_SCAN_ID        scan_id,
                                   bool                     forced_flag)
{
    if ((scan_id != 0) && (ss->ss_scan_id != scan_id)) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_ANY, "%s: Invalid scan_id=%d ss_scan_id=%d\n",
                              __func__,
                              scan_id,
                              ss->ss_scan_id);

#if ATH_SUPPORT_MULTIPLE_SCANS
        return EINVAL;
#endif
    }

    if (forced_flag) {
        if (ss->ss_common.ss_info.si_scan_in_progress) {
            ss->ss_flags |= IEEE80211_SCAN_NOW;
        }
    }
    else {
        if (ss->ss_common.ss_info.si_scan_in_progress) {
            ss->ss_flags &= ~IEEE80211_SCAN_NOW;
        }
    }

    return EOK;
}

int ieee80211_scan_stop(ieee80211_scanner_t      ss,
                        IEEE80211_SCAN_REQUESTOR requestor,
                        IEEE80211_SCAN_ID        scan_id,
                        scanner_stop_mode        stop_mode,
                        u_int32_t                flags)
{
    enum scanner_event    event;
    u_int32_t             now = (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());
    u_int32_t             initial_run_counter = ss->ss_run_counter;

    spin_lock(&ss->ss_lock);

    initial_run_counter = ss->ss_run_counter;

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%d.%03d | %s: module %s ID=%d (curr_id=%d) state=%s in_progress=%d mode=%d flags=%08X runctr=%d\n",
                          now / 1000, now % 1000, __func__,
                          ieee80211_scan_get_requestor_name(ss, requestor),
                          scan_id,
                          ss->ss_scan_id,
                          ieee80211_sm_get_current_state_name(ss->ss_hsm_handle),
                          ss->ss_common.ss_info.si_scan_in_progress,
                          stop_mode,
                          flags,
                          ss->ss_run_counter);

    if (!ss->ss_common.ss_info.si_scan_in_progress) {
        spin_unlock(&ss->ss_lock);
        return EPERM;
    }

    /*
     * Verify that scan currently running is the one we want to cancel.
     */
    if ((scan_id != 0) && (ss->ss_scan_id != scan_id)) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: module %s Incorrect scan_id. Requested ID=%d Current ID=%d\n",
                              __func__,
                              ieee80211_scan_get_requestor_name(ss, requestor),
                              scan_id,
                              ss->ss_scan_id);

#if ATH_SUPPORT_MULTIPLE_SCANS
        spin_unlock(&ss->ss_lock);
        return EINVAL;
#endif
    }

    /* Select event to be sent to the state machine */
    event = (stop_mode == STOP_MODE_PREEMPT) ?
        SCANNER_EVENT_PREEMPT_REQUEST : SCANNER_EVENT_CANCEL_REQUEST;

    spin_unlock(&ss->ss_lock);

    if (flags & IEEE80211_SCAN_CANCEL_SYNC) {
        struct ieee80211_scan_cancel_data    scan_cancel_data;

        OS_MEMZERO(&scan_cancel_data, sizeof(scan_cancel_data));
        scan_cancel_data.vap       = NULL;
        scan_cancel_data.scan_id   = scan_id;
        scan_cancel_data.requestor = requestor;
        scan_cancel_data.flags     = flags;

        /*
         * synchronously push the SM to IDLE state.
         */
        ieee80211_sm_dispatch_sync(ss->ss_hsm_handle,
                                   event,
                                   sizeof(scan_cancel_data),
                                   &scan_cancel_data,
                                   true);

    } else {
        ieee80211_sm_dispatch(ss->ss_hsm_handle,
                              event,
                              0,
                              NULL);


        if (flags & IEEE80211_SCAN_CANCEL_WAIT) {
            u_int32_t    elapsed_cancel_wait = 0;

            /* Wait for scan operation to be completed. */
            while (ss->ss_common.ss_info.si_scan_in_progress || ss->ss_completion_indications_pending) {
                /*
                 * If ss_run_counter has changed since the beginning of the
                 * stop operation, it means the scan we were trying to cancel
                 * completed and a new one started.
                 *
                 * The same applies to ss_scan_id and scan_id, but these values
                 * are only reliable if multiple scan support is enabled.
                 *
                 * These 2 conditions cover the case in which a scan completes
                 * and another one is immediately started while this function
                 * is sleeping. In this case this functions wouldn't see
                 * si_scan_in_progress being cleared then set again.
                 */
                if ((ss->ss_run_counter != initial_run_counter) ||
                    ((scan_id != 0) && (ss->ss_scan_id != scan_id)))
                {
                    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: Scan completed, new scan started: run_counter=%d/%d scan_id=%d/%d\n",
                        __func__,
                        initial_run_counter, ss->ss_run_counter,
                        scan_id, ss->ss_scan_id);

                    break;
                }

                IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: Waiting for scan to complete run_counter=%d/%d scan_id=%d/%d flags=%d,%d\n",
                    __func__,
                    initial_run_counter, ss->ss_run_counter,
                    scan_id, ss->ss_scan_id,
                    ss->ss_common.ss_info.si_scan_in_progress, ss->ss_completion_indications_pending);
                OS_SLEEP(IEEE80211_CANCEL_RETRY_DELAY * 1000);

                /*
                 * Keep track of total amount of time spent waiting for scan to
                 * complete and terminate if it is taking too long.
                 */
                elapsed_cancel_wait += IEEE80211_CANCEL_RETRY_DELAY;
                ASSERT(elapsed_cancel_wait <= IEEE80211_CANCEL_TIMEOUT);
                if (elapsed_cancel_wait > IEEE80211_CANCEL_TIMEOUT) {
                    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: Timeout waiting for scan operation to complete %d %d\n",
                        __func__,
                        ss->ss_common.ss_info.si_scan_in_progress, ss->ss_completion_indications_pending);
                    return EOVERFLOW;
                }
            }
        }
    }

    return EOK;
}

/*
 * Completion of scans that are still in the scheduler queue.
 * The completion must be handled by the scanner to ensure the notifications
 */
int ieee80211_scan_external_event(ieee80211_scanner_t              ss,
                                  wlan_if_t                        vaphandle,
                                  ieee80211_scan_event_type        notification_event,
                                  ieee80211_scan_completion_reason notification_reason,
                                  IEEE80211_SCAN_ID                scan_id,
                                  IEEE80211_SCAN_REQUESTOR         requestor)
{
    struct ieee80211_scan_event_data    scan_event;

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: vap=%08p scan_id=%d requestor=%08X event=%s reason=%s\n",
        __func__,
        vaphandle,
        scan_id,
        requestor,
        wlan_scan_notification_event_name(notification_event),
        wlan_scan_notification_reason_name(notification_reason));

    OS_MEMZERO(&scan_event, sizeof(scan_event));
    scan_event.vap       = vaphandle;
    scan_event.scan_id   = scan_id;
    scan_event.requestor = requestor;
    scan_event.event     = notification_event;
    scan_event.reason    = notification_reason;

    ieee80211_sm_dispatch(ss->ss_hsm_handle,
                          SCANNER_EVENT_EXTERNAL_EVENT,
                          sizeof(scan_event),
                          &scan_event);

    return EOK;
}

static bool is_radio_measurement_in_home_channel(ieee80211_scanner_t ss)
{
    if (ss->ss_is_connected(ss->ss_vap)) {
        return (wlan_channel_ieee(ss->ss_chans[ss->ss_next]) == wlan_channel_ieee(ss->ss_vap->iv_bsschan));
    }

    return false;
}

static systime_t _ieee80211_scan_get_last_scan_time(ieee80211_scanner_t ss)
{
    return ss->ss_scan_start_time;
}

static systime_t _ieee80211_scan_get_last_full_scan_time(ieee80211_scanner_t ss)
{
    return ss->ss_last_full_scan_time;
}

static int _ieee80211_scan_get_last_scan_info(ieee80211_scanner_t ss, ieee80211_scan_info *info)
{
    if (ss->ss_scan_start_time == 0)
        return ENXIO;

    if (info) {
        info->type                        = ss->ss_type;
        info->requestor                   = ss->ss_requestor;
        info->scan_id                     = ss->ss_scan_id;
        info->priority                    = ss->ss_priority;
        info->min_dwell_time_active       = ss->ss_min_dwell_active;
        info->max_dwell_time_active       = ss->ss_max_dwell_active;
        info->min_dwell_time_passive      = ss->ss_min_dwell_active;
        info->max_dwell_time_passive      = ss->ss_max_dwell_active;
        info->min_rest_time               = ss->ss_min_rest_time;
        info->max_rest_time               = ss->ss_max_rest_time;
        info->max_offchannel_time         = ss->ss_max_offchannel_time;
        info->repeat_probe_time           = ss->ss_repeat_probe_time;
        info->min_beacon_count            = ss->ss_min_beacon_count;
        info->flags                       = ss->ss_flags;
        info->scan_start_time             = ss->ss_scan_start_time;
        info->cancelled                   = (ss->ss_termination_reason == IEEE80211_REASON_CANCELLED);
        info->preempted                   = (ss->ss_termination_reason == IEEE80211_REASON_PREEMPTED);
        info->scanned_channels            = ss->ss_next;
        info->default_channel_list_length = ss->ss_nallchans;
        info->channel_list_length         = ss->ss_nchans;
        info->restricted                  = ss->ss_restricted;

        if (ss->ss_common.ss_info.si_scan_in_progress) {
            info->scheduling_status      = IEEE80211_SCAN_STATUS_RUNNING;
            info->in_progress            = true;
        }
        else {
            info->scheduling_status      = IEEE80211_SCAN_STATUS_COMPLETED;
            info->in_progress            = false;
        }
    }

    return EOK;
}

int ieee80211_print_scan_config(ieee80211_scanner_t ss, struct seq_file *m)
{
    const char *sep;
    int i = 0;

    seq_printf(m, "scanning: %d\n", ss->ss_common.ss_info.si_scan_in_progress ? 1 : 0);
    seq_printf(m, "channels: ");
    sep = "";
    for (i = 0; i < ss->ss_nchans; i++) {
        wlan_chan_t c = ss->ss_chans[i];

        seq_printf(m, "%s%u%c", sep, wlan_channel_ieee(c),
                   channel_type(c));
        sep = " ";
    }
    seq_printf(m, "\n");

    seq_printf(m, "flags: %s%s%s%s%s%s%s%s%s%s%s\n",
               (ss->ss_flags & IEEE80211_SCAN_PASSIVE) ? "passive " : "",
               (ss->ss_flags & IEEE80211_SCAN_ACTIVE) ? "active " : "",
               (ss->ss_flags & IEEE80211_SCAN_2GHZ) ? "2GHz " : "",
               (ss->ss_flags & IEEE80211_SCAN_5GHZ) ? "5GHz " : "",
               (ss->ss_flags & IEEE80211_SCAN_ALLBANDS) == IEEE80211_SCAN_ALLBANDS ? "allbands " : "",
               (ss->ss_flags & IEEE80211_SCAN_CONTINUOUS) ? "continuous " : "",
               (ss->ss_flags & IEEE80211_SCAN_FORCED) ? "forced " : "",
               (ss->ss_flags & IEEE80211_SCAN_NOW) ? "now " : "",
               (ss->ss_flags & IEEE80211_SCAN_ADD_BCAST_PROBE) ? "bcast_probe " : "",
               (ss->ss_flags & IEEE80211_SCAN_EXTERNAL) ? "external " : "",
               (ss->ss_flags & IEEE80211_SCAN_BURST) ? "burst " : "");
    seq_printf(m,
               "next: %u\n"
               "nchans: %u\n"
               "mindwell: %u\n"
               "maxdwell: %u\n"
               "maxscantime: %u\n",
               ss->ss_next,
               ss->ss_nchans,
               ss->ss_cur_min_dwell,
               ss->ss_cur_max_dwell,
               ss->ss_max_scan_time);

    for (i = 0; i < ss->ss_nssid; i++) {
        seq_printf(m, "ssid%d: \"%s\"\n",
                   i, ss->ss_ssid[i].len ? (char *) ss->ss_ssid[i].ssid : "");
    }
    return 0;
}

/*
 * Send probe requests.
 *
 * This function may be called from any IRQL, so do not acquire scan's
 * synchronization object, which is valid only at IRQL <= APC_LEVEL
 * However, we still need to synchronize access to shared data.
 */
static void scanner_send_probereq(ieee80211_scanner_t ss)
{
    int    i, j;

    for (i = 0; i < ss->ss_nssid; i++) {
        for (j = 0; j < ss->ss_nbssid; j++) {
            wlan_send_probereq(ss->ss_vap,
                               ss->ss_bssid[j],
                               ss->ss_bssid[j],
                               ss->ss_ssid[i].ssid,
                               ss->ss_ssid[i].len,
                               ss->ss_iedata,
                               ss->ss_ielen);
        }
    }
}

/*
 * This function must be called only from idle state.
 */
static void scanner_initiate_radio_measurement(ieee80211_scanner_t ss)
{
    if (! ss->ss_is_connected(ss->ss_vap)) {
        /*
         * Pause request is not expected when we are not connected and so we do not need to process the request.
         * Post the event saying cancelled the pause request.
         */
        scanner_post_event(ss,
                           ss->ss_vap,
                           IEEE80211_SCAN_RADIO_MEASUREMENT_START,
                           IEEE80211_REASON_CANCELLED,
                           ss->ss_scan_id,
                           ss->ss_requestor,
                           ss->ss_ic->ic_curchan);
        return;
    }

    /*
     * If connected we may have to suspend or resume traffic
     * It is guaranteed here that we are in BSSCHANNEL.
     */
    if (is_radio_measurement_in_home_channel(ss)) {
        ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_RADIO_MEASUREMENT);
    }
    else {
        /*
         * We have already verified we're connected, so we need to suspend
         * traffic.
         */
        if (scanner_can_leave_home_channel(ss)) {
            /* Flush any messages from messgae queue and reset HSM to IDLE state. */
            scanner_leave_bss_channel(ss);
        } else {
            /* Not able to process Radio measurement request now, so transition to BSS Channel state to process it later */
            ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_BSS_CHANNEL);
        }
    }
}

static void
scanner_completion_sequence(ieee80211_scanner_t              ss,
                            wlan_if_t                        vaphandle,
                            ieee80211_scan_event_type        event,
                            ieee80211_scan_completion_reason reason)
{
    /*
     * Set si_scan_in_progress to false before scan completion notifications
     * are sent. This covers the case in which the notified modules (including
     * the OS) send another scan request as soon as the completion is
     * received, possibly while scanner is still notifying other modules.
     *
     * ss_completion_indications_pending is set to false only after all
     * indications have been sent, and serves to synchronize scan cancel
     * routine.
     */
    if (ss->ss_common.ss_info.si_scan_in_progress) {
        ss->ss_common.ss_info.si_scan_in_progress       = false;
        scanner_post_event(ss,
                           vaphandle,
                           event,
                           reason,
                           ss->ss_scan_id,
                           ss->ss_requestor,
                           ss->ss_ic->ic_curchan);
        /*
         * The following fields are subject to race conditions.
         * It is possible that clients being notified on scan completion may
         * immediately request another scan, and any values set by
         * ieee80211_scan_run will be overwritten here.
         */
        ss->ss_scan_start_event_posted        = false;
        ss->ss_completion_indications_pending = false;
    }
}

static void scanner_terminate(ieee80211_scanner_t ss, ieee80211_scan_completion_reason reason)
{
    u_int32_t    now = (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%d.%03d | %s: scan_id=%d reason=%s next_chan=%d/%d nreqchans=%d nallchans=%d\n",
        now / 1000, now % 1000, __func__,
        ss->ss_scan_id,
        wlan_scan_notification_reason_name(reason),
        ss->ss_next,
        ss->ss_nchans,
        ss->ss_nreqchans,
        ss->ss_nallchans);

    if (reason == IEEE80211_REASON_TERMINATION_FUNCTION) {
       ss->ss_common.ss_info.si_last_term_status =  true;
    } else {
       ss->ss_common.ss_info.si_last_term_status = false;
    }

    /*
     * Save termination reason if scan is in progress and one has not been set yet.
     */
    if (ss->ss_common.ss_info.si_scan_in_progress) {
        OS_CANCEL_TIMER(&ss->ss_maxscan_timer);

        if (ss->ss_termination_reason == IEEE80211_REASON_NONE) {
            ss->ss_termination_reason = reason;

            /*
             * Save timestamp of last scan in which all channels were scanned.
             * Consider scan completed if repeater scan since only channel to be scanned
             */
            if (reason == IEEE80211_REASON_PREEMPTED) {
                scanner_save_preemption_data(ss);
            }
            else {
                if ((ss->ss_next >= ss->ss_nallchans) || (ss->ss_type == IEEE80211_SCAN_REPEATER_BACKGROUND)
                    || (((ss->ss_flags & (IEEE80211_SCAN_ALLBANDS)) != IEEE80211_SCAN_ALLBANDS)
                        && (ss->ss_next >= ss->ss_nchans))) {
                    ss->ss_last_full_scan_time = ss->ss_scan_start_time;
                }
            }
        }
    }

    OS_CANCEL_TIMER(&ss->ss_timer);

    /*
     * If received an error from the ResourceManager, abort scan and go
     * straight to IDLE state.
     */
    if (reason == IEEE80211_REASON_INTERNAL_STOP) {
        ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_IDLE);
    } else {
    if ((! ss->ss_common.ss_info.si_in_home_channel) || (ss->ss_suspending_traffic)) {
        int    status;

            /*
             * We should always call set_channel even if ic_curchan == ic_bsschan, which happens when
             * last foreign channel is the home channel, so that beacon timer can be synchronized and
             * beacon can be re-started if we are in ad-hoc mode.
             */

            status = ieee80211_resmgr_request_bsschan(ss->ss_resmgr,
                                                      SCANNER_RESMGR_REQID);

            switch (status) {
            case EBUSY:
                /*
                 * Resource Manager is responsible for resuming traffic, changing
                 * channel and sending notification once the operation has completed.
                 */
                ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_TERMINATING);

            /* Set watchdog timer in case ResMgr doesn't send back an event */
            ieee80211_schedule_timed_event(ss, IEEE80211_RESMGR_WAIT_TIMEOUT, SCANNER_EVENT_TERMINATING_TIMEOUT);
            break;

        case EOK:    /* Resource Manager not active. */
        case EINVAL: /* Resource Manager doesn't have BSS channel information (no VAPs active) */
        default:     /* Resource Manager not active. */
            ss->ss_ic->ic_scan_end(ss->ss_ic);
            if (ss->ss_vap->iv_bsschan) {
#if ATH_SUPPORT_VOW_DCS
                if (!(ss->ss_ic->cw_inter_found))
#endif
                {
                    ieee80211_set_channel(ss->ss_ic, ss->ss_vap->iv_bsschan);
                }
#if ATH_VAP_PAUSE_SUPPORT
                if (ieee80211_ic_enh_ind_rpt_is_set(ss->ss_vap->iv_ic)) {
                    ieee80211_ic_unpause(ss->ss_ic);
                    ss->ss_ic->ic_vap_pause_control(ss->ss_ic,ss->ss_vap,false);
                }
#endif
                }
#if ATH_SLOW_ANT_DIV
                ss->ss_ic->ic_antenna_diversity_resume(ss->ss_ic);
#endif
               ss->ss_ic->ic_scan_enable_txq(ss->ss_ic);
#if ATH_SUPPORT_VOW_DCS
            if (!(ss->ss_ic->cw_inter_found))
#endif
            {
                if (ss->ss_is_connected(ss->ss_vap)) {
                    if (ieee80211_sta_power_unpause(ss->ss_vap) != EOK) {
                        /*
                         * No need for a sophisticated error handling here.
                         * If transmission of fake wakeup fails, subsequent traffic sent
                         * with PM bit clear will have the same effect.
                         */
                        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s failed to send fakewakeup\n",
                                    __func__);
                    }
                }
              }

                ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_IDLE);
                break;
            }
        }
        else {
            ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_IDLE);
        }
    }
}

/*
 * spin lock already held
 */
static bool scanner_check_endof_scan(ieee80211_scanner_t ss)
{
    if (ss->ss_type == IEEE80211_SCAN_REPEATER_BACKGROUND) {
        ss->ss_last_full_scan_time = ss->ss_scan_start_time;
        return true;
    }

    if (ss->ss_next >= ss->ss_nchans) {
        if (ss->ss_flags & IEEE80211_SCAN_CONTINUOUS) {
            /* Check whether all channels were scanned */
            if ((ss->ss_next >= ss->ss_nallchans) ||
                (((ss->ss_flags & (IEEE80211_SCAN_ALLBANDS)) != IEEE80211_SCAN_ALLBANDS))) {
                ss->ss_last_full_scan_time = ss->ss_scan_start_time;
            }

            /*
             * Continuous scanning: indicate that scan restarted, and all
             * channels were scanned.
             */
            scanner_post_event(ss,
                               ss->ss_vap,
                               IEEE80211_SCAN_RESTARTED,
                               IEEE80211_REASON_NONE,
                               ss->ss_scan_id,
                               ss->ss_requestor,
                               ss->ss_ic->ic_curchan);

            ss->ss_next = 0;

            return false;
        } else {
            return true;
        }

    } else {
        return false;
    }
}

static bool scanner_can_leave_foreign_channel(ieee80211_scanner_t ss)
{
    systime_t    current_time = OS_GET_TIMESTAMP();
    u_int32_t    elapsed_dwell_time;

    elapsed_dwell_time = CONVERT_SYSTEM_TIME_TO_MS(current_time - ss->ss_enter_channel_time);

    if (elapsed_dwell_time >= ss->ss_cur_min_dwell) {
        return true;
    } else {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN,
            "%s: FALSE: elapsed_dwell_time=%d current_time=%lu enter_channel_time=%lu\n",
            __func__,
            elapsed_dwell_time,
            (unsigned long)CONVERT_SYSTEM_TIME_TO_MS(current_time),
            (unsigned long)CONVERT_SYSTEM_TIME_TO_MS(ss->ss_enter_channel_time));

        return false;
    }
}

static bool scanner_can_leave_home_channel(ieee80211_scanner_t ss)
{
    bool         beacon_requirement;
    systime_t    last_data_time;
    systime_t    current_system_time;
    u_int32_t    elapsed_rest_time;

    /* In the case of enh -ind repeater, we need to wait a
     * initial 14 secs in the home channel.
     * handle that - in the case of non enh ind rpt .. the value is
     * defaulted to 0
     */
    if (ieee80211_ic_enh_ind_rpt_is_set(ss->ss_vap->iv_ic) &&
        ( ss->ss_common.ss_info.si_last_term_status == 0)&& (ss->ss_check_termination_function != NULL)) {
        if(scanner_check_for_bssid_entry((void *)ss->ss_vap)) {
            return true;
        }
    }

    /* Retrieve current system time */
    current_system_time = OS_GET_TIMESTAMP();

    /* Calculate current rest time. */
    elapsed_rest_time = CONVERT_SYSTEM_TIME_TO_MS(current_system_time - ss->ss_currscan_home_entry_time);

    if (elapsed_rest_time < ss->ss_init_rest_time) {
        return false;
    }

    /*
     * Check whether connection was lost.
     */
    if (! ss->ss_is_connected(ss->ss_vap)) {
        ieee80211_scan_connection_lost(ss);

        /*
         * Can leave home channel if no connection and not forced to meet
         * minimum rest time.
         */
        if (! ss->ss_visit_home_channel) {
            return true;
        }
    }

    /* Retrieve current system time */
    current_system_time = OS_GET_TIMESTAMP();

    /* Calculate current rest time. */
    elapsed_rest_time = CONVERT_SYSTEM_TIME_TO_MS(current_system_time - ss->ss_enter_channel_time);

    /*
     * Minimum rest time has been met.
     * Can leave home channel if station is not connected and no other ports
     * are active. Otherwise, check remaining conditions.
     */
    if ((! ss->ss_is_connected(ss->ss_vap)) && (! ss->ss_multiple_ports_active)) {
        return true;
    }

    /*
     * Make sure we stay in the home channel for a minimum amount of time.
     * This includes time spent in the home channel when scan is not running.
     */
    if (elapsed_rest_time < ss->ss_min_rest_time) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN,
            "%s: Under min. rest time. Beacon=%lu Dwell=%lu/%lu Done=0\n",
            __func__,
            ss->ss_beacons_received,
            elapsed_rest_time,
            ss->ss_min_rest_time);

        return false;
    }

    /*
     * Minimum rest time already satisfied; can leave home channel if radio measurement
     * has been requested.
     */
    if (ss->ss_type == IEEE80211_SCAN_RADIO_MEASUREMENTS) {
        ss->ss_common.ss_info.si_allow_transmit = false;
        return true;
    }

    /*
     * If performing a forced scan, do not exceed the maximum amount of time
     * we can spend on the home channel. This time limit trumps all other
     * conditions when deciding whether to leave the home channel.
     * There's no time limit when performing a non-forced scan.
     */
    if ((ss->ss_flags & (IEEE80211_SCAN_FORCED | IEEE80211_SCAN_NOW)) &&
        (elapsed_rest_time >= ss->ss_max_rest_time)) {
#if ATH_BT_COEX
        /*
         * If it's a external scan request and BT is busy, we check the other leave home
         * channel condition before return ok.
         */
        if (!((ss->ss_flags & IEEE80211_SCAN_EXTERNAL) &&
              ss->ss_ic->ic_get_bt_coex_info(ss->ss_ic, IEEE80211_BT_COEX_INFO_BTBUSY))) {
            return true;
        }
#else
        return true;
#endif
    }

    /*
     * Don't leave home channel if there is still data waiting to be
     * transmitted .
     */
    if ((! ss->ss_is_sw_txq_empty(ss->ss_ic)) || (! ss->ss_is_txq_empty(ss->ss_ic))) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: SW txq empty=%d Qempty=%d Done=0\n",
            __func__,
            ss->ss_is_sw_txq_empty(ss->ss_ic),
            ss->ss_is_txq_empty(ss->ss_ic));

        return false;
    }

    /*
     * Traffic indication timestamp can be modified asynchronously during
     * execution of this routine. Therefore, in order to ensure temporality,
     * we must save a copy of it before querying the current system time.
     */
    last_data_time      = ieee80211com_get_traffic_indication_timestamp(ss->ss_ic);
    current_system_time = OS_GET_TIMESTAMP();

    /*
     * Check channel activity; ready to leave channel only if no traffic
     * for a certain amount of time.
     */
    if (CONVERT_SYSTEM_TIME_TO_MS(current_system_time - last_data_time) < ss->ss_idle_time) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: Channel has activity. Beacon=%lu Data (now=%lu last=%lu) Done=0\n",
            __func__,
            ss->ss_beacons_received,
            (unsigned long) CONVERT_SYSTEM_TIME_TO_MS(current_system_time),
            (unsigned long) CONVERT_SYSTEM_TIME_TO_MS(last_data_time));

        return false;
    }

    /*
     * Minimum dwell time and network idle requirements met.
     * Verify whether we have received the required number of beacons.
     */
    beacon_requirement = (ss->ss_beacons_received >= ss->ss_min_beacon_count);

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: Rest=%lu Timeout (MinRest=%lu Beacon=%lu) BeaconCnt=%lu Data (now=%lu last=%lu) Qempty=%2d Done=%d\n",
        __func__,
        (unsigned long) CONVERT_SYSTEM_TIME_TO_MS(elapsed_rest_time),
        ss->ss_min_rest_time,
        ss->ss_beacon_timeout,
        ss->ss_beacons_received,
        (unsigned long) CONVERT_SYSTEM_TIME_TO_MS(current_system_time),
        (unsigned long) CONVERT_SYSTEM_TIME_TO_MS(last_data_time),
        ss->ss_is_txq_empty(ss->ss_ic),
        (beacon_requirement || (elapsed_rest_time >= ss->ss_beacon_timeout)));

    /*
     * Leave home channel if satisfied requirements for minimum dwell time,
     * absence of data traffic and beacon statistics. The latter means we
     * either
     *     a) received the required number of beacons, or
     *     b) reached a time limit without receiving the required beacons
     */
    if (beacon_requirement || (elapsed_rest_time >= ss->ss_beacon_timeout)) {
        return true;
    }

    return false;
}

static bool is_common_event(ieee80211_scanner_t ss,
                            enum scanner_event  event,
                            u_int16_t           event_data_len,
                            void                *event_data)
{
    bool                                common_event;
    ieee80211_scan_completion_reason    termination_reason;
    bool                                synchronous_termination;

    /* External events reported regardless of the scanner's state */
    if (event == SCANNER_EVENT_EXTERNAL_EVENT) {
        struct ieee80211_scan_event_data    *scan_event = (struct ieee80211_scan_event_data *)event_data;

        ASSERT(scan_event);

        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s External Event %s reason %s scan_id=%d requestor=%08X vap=%08p\n",
            __func__,
            wlan_scan_notification_event_name(scan_event->event),
            wlan_scan_notification_reason_name(scan_event->reason),
            scan_event->scan_id,
            scan_event->requestor,
            scan_event->vap);

        scanner_post_event(ss,
                           scan_event->vap,
                           scan_event->event,
                           scan_event->reason,
                           scan_event->scan_id,
                           scan_event->requestor,
                           ss->ss_ic->ic_curchan);

        /* pass-through event; report as already handled */
        return true;
    }

    common_event            = true;
    termination_reason      = IEEE80211_REASON_NONE;
    synchronous_termination = false;

    /*
     * Check termination conditions
     */
    switch (event) {
    case SCANNER_EVENT_CANCEL_REQUEST:
    case SCANNER_EVENT_PREEMPT_REQUEST:
        {
            if (event_data_len > 0) {
                struct ieee80211_scan_cancel_data    *scan_cancel_data = event_data;

            ASSERT(scan_cancel_data);
                synchronous_termination =
                    ((scan_cancel_data->flags & IEEE80211_SCAN_CANCEL_SYNC) != 0);
            }

            /*
             * Select event to be sent to the state machine and the flag to be set
             * depending on whether we want to cancel or preempt scan.
             */
            termination_reason = (event == SCANNER_EVENT_CANCEL_REQUEST) ?
                IEEE80211_REASON_CANCELLED : IEEE80211_REASON_PREEMPTED;
        }
        break;

    case SCANNER_EVENT_MAXSCANTIME_EXPIRE:
        termination_reason = IEEE80211_REASON_TIMEDOUT;
        break;

    case SCANNER_EVENT_FATAL_ERROR:
        /* Stop scan immediately */
        termination_reason = IEEE80211_REASON_INTERNAL_STOP;
        break;

    default:
        /* not a common event */
        common_event = false;
        break;
    }

    if (common_event) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s Common Event Scan state=%s event=%s\n",
            __func__, ieee80211_sm_get_current_state_name(ss->ss_hsm_handle), ieee80211_scan_event_name(event));

        /*
         * Check if scan must be terminated because of the received event
         */
        if (termination_reason != IEEE80211_REASON_NONE) {
            bool    event_ignored = true;

            /*
             * Ignore termination conditions if scan not in progress
             */
            if (ss->ss_common.ss_info.si_scan_in_progress) {
                /*
                 * If scan_start event (IEEE80211_SCAN_STARTED or IEEE80211_SCAN_RESTARTED)
                 * has not been posted yet, only synchronous cancellation
                 * requests are valid after ieee80211_scan_run is called (flag
                 * si_scan_in_progress is * set) but before scan_start event is
                 * posted (flag ss_scan_start_event_posted is false).
                 *
                 * The asynchronous cancellation requests are queued and
                 * handled in the order received. As a result, a cancellation
                 * request received before scan_start event is a leftover from
                 * cancellation of a previous scan and must be ignored
                 */
                if (synchronous_termination || ss->ss_scan_start_event_posted) {
                    scanner_terminate(ss, termination_reason);
                    event_ignored = false;
                }
            }

            if (event_ignored) {
                IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s event=%s IGNORED in_progress=%d start_posted=%d\n",
                    __func__,
                    ieee80211_scan_event_name(event),
                    ss->ss_common.ss_info.si_scan_in_progress,
                    ss->ss_scan_start_event_posted);
            }
        }
    }

    /*
     * Report whether received event was common.
     * It's valid to indicate a common event was received and processed even
     * if no action was taken (like ignoring termination conditions if no scan
     * is in progress).
     */
    return common_event;
}

static bool scanner_leave_bss_channel(ieee80211_scanner_t ss)
{
    int          status;
    u_int32_t    estimated_offchannel_time;

    /*
     * Estimate time to be spent off-channel.
     * If burst scan is enabled, this estimated time is the maximum between
     * the next dwell time and ss_offchannel_time.
     */
    if (is_passive_channel(ss->ss_chans[ss->ss_next], ss->ss_flags)) {
        estimated_offchannel_time = ss->ss_max_dwell_passive;
    }
    else {
        estimated_offchannel_time = ss->ss_max_dwell_active;
    }

    if ((ss->ss_flags & IEEE80211_SCAN_BURST) &&
        (ss->ss_max_offchannel_time > 0)) {

        if (ss->ss_offchannel_time > estimated_offchannel_time) {
            estimated_offchannel_time = ss->ss_offchannel_time;
        }
    }

    /*
     * Conditions necessary to leave BSS channel have already been met, so
     * there's no need for the ResourceManager for the same conditions again.
     */
    status = ieee80211_resmgr_request_offchan(ss->ss_resmgr,
                                              ss->ss_chans[ss->ss_next],
                                              SCANNER_RESMGR_REQID,
                                              IEEE80211_RESMGR_MAX_LEAVE_BSS_DELAY,
                                              estimated_offchannel_time);

    switch (status) {
    case EOK:
        /*
         * Resource Manager not active.
         * Scanner needs to suspend traffic if client is connected.
         */
        if (ss->ss_is_connected(ss->ss_vap)) {
            ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_SUSPENDING_TRAFFIC);
        }
        else {
            ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_FOREIGN_CHANNEL);
        }
        break;

    case EBUSY:
        /*
         * Resource Manager is responsible for suspending traffic, changing
         * channel and sending notification once the operation has completed.
         */
        ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_SUSPENDING_TRAFFIC);
        break;

    default:
        /*
         * Error.
         * Scanner needs to suspend traffic if client is connected.
         */
        if (ss->ss_is_connected(ss->ss_vap)) {
            ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_SUSPENDING_TRAFFIC);
        }
        else {
            ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_FOREIGN_CHANNEL);
        }
        break;
    }

    return true;
}

static void scanner_state_idle_entry(void *context)
{
    ieee80211_scanner_t                 ss = context;
    u_int32_t                           now = (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());
    ieee80211_scan_event_type           notification_event;
    ieee80211_scan_completion_reason    notification_reason;
    wlan_if_t                           notifying_vap;
    bool                                scan_preempted;

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%d.%03d | %s all_channels_scanned=%d\n",
        now / 1000, now % 1000, __func__,
        scanner_check_endof_scan(ss));

    if (ss->ss_vap != NULL) {
        ieee80211_vap_unregister_event_handler(ss->ss_vap,
                                               ieee80211_scan_handle_vap_events,
                                               (void *) ss);

        if (! ieee80211_resmgr_active(ss->ss_ic)) {
            (void)ieee80211_sta_power_unregister_event_handler(ss->ss_vap,
                                                               ieee80211_scan_handle_sta_power_events,
                                                               ss);
        }
    }

    /*
     * Save the current VAP *before* sending notifications to avoid a race
     * condition in which another module requests a scan during the
     * notification. The resulting call to ieee80211_scan_run overwrites
     * ss->ss_vap while it is still being used (error #1). If ss_vap is then
     * cleared after all notifications, it overwrites the new value specified
     * in the call to ieee80211_scan_run (error #2).
     */
    notifying_vap  = ss->ss_vap;
    scan_preempted = (ss->ss_termination_reason == IEEE80211_REASON_PREEMPTED);

    OS_CANCEL_TIMER(&ss->ss_timer);
    OS_CANCEL_TIMER(&ss->ss_maxscan_timer);

    ss->ss_pending_event           = SCANNER_EVENT_NONE;
    ss->ss_suspending_traffic      = false;
    ss->ss_vap                     = NULL;
    atomic_set(&(ss->ss_wait_for_beacon),     false);
    atomic_set(&(ss->ss_beacon_event_queued), false);

    ss->ss_common.ss_info.si_allow_transmit  = true;
    ss->ss_common.ss_info.si_in_home_channel = true;

    /*
     * Execute completion sequence (send notifications and clear flags).
     * Send special notification event if scan has been preempted (i.e. no
     * longer active, but will continue later because there's still work to do).
     */
    if (scan_preempted) {
        notification_event  = IEEE80211_SCAN_PREEMPTED;
        notification_reason = IEEE80211_REASON_PREEMPTED;
    }
    else {
        /*
         * Scanner returning to IDLE state before scan_start event is posted
         * indicates a synchronous cancellation.
         *
         * If ATH_SUPPORT_MULTIPLE_SCANS is enabled, post
         * IEEE80211_SCAN_DEQUEUED since other modules never received
         * IEEE80211_SCAN_STARTED or IEEE80211_SCAN_RESTARTED.
         *
         * If ATH_SUPPORT_MULTIPLE_SCANS is disabled, post
         * IEEE80211_SCAN_COMPLETED since the shim layers for platforms that
         * do not support multiple scans have not been modified to handle
         * IEEE80211_SCAN_DEQUEUED, IEEE80211_SCAN_PREEMPTED, etc.
         */
#if ATH_SUPPORT_MULTIPLE_SCANS
        notification_event = ss->ss_scan_start_event_posted ?
		IEEE80211_SCAN_COMPLETED : IEEE80211_SCAN_DEQUEUED;
#else
        notification_event = IEEE80211_SCAN_COMPLETED;
#endif
        notification_reason = ss->ss_termination_reason;
    }

    scanner_completion_sequence(ss, notifying_vap, notification_event, notification_reason);
}

static bool scanner_state_idle_event(void      *context,
                                     u_int16_t event,
                                     u_int16_t event_data_len,
                                     void      *event_data)
{
    ieee80211_scanner_t                 ss = context;
    ieee80211_scan_event_type           notification_event;
    ieee80211_scan_completion_reason    notification_reason;

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s state=%s event=%s\n",
        __func__, ieee80211_sm_get_current_state_name(ss->ss_hsm_handle), ieee80211_scan_event_name(event));

    if (is_common_event(ss, event, event_data_len, event_data)) {
        return true;
    }

    switch (event) {
    case SCANNER_EVENT_SCAN_REQUEST:
    case SCANNER_EVENT_RESTART_REQUEST:
        if (! ss->ss_common.ss_info.si_scan_in_progress) {
            IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s state=%s event=%s nothing to do\n",
                __func__,
                ieee80211_sm_get_current_state_name(ss->ss_hsm_handle),
                ieee80211_scan_event_name(event));

            return true;
        }

        if (event == SCANNER_EVENT_SCAN_REQUEST) {
            notification_event  = IEEE80211_SCAN_STARTED;
            notification_reason = IEEE80211_REASON_NONE;
        }
        else {
            notification_event  = IEEE80211_SCAN_RESTARTED;
            notification_reason = IEEE80211_REASON_PREEMPTED;
        }
        scanner_post_event(ss,
                           ss->ss_vap,
                           notification_event,
                           notification_reason,
                           ss->ss_scan_id,
                           ss->ss_requestor,
                           ss->ss_ic->ic_curchan);
        /*
         * Scan started and termination indications have not been sent yet.
         */
        ss->ss_scan_start_event_posted        = true;
        ss->ss_completion_indications_pending = true;

        if (ss->ss_type == IEEE80211_SCAN_REPEATER_BACKGROUND) {
            ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_REPEATER_CHANNEL);
        }
        else if(ss->ss_type == IEEE80211_SCAN_RADIO_MEASUREMENTS){
            scanner_initiate_radio_measurement(ss);
        }
        else {
            if (ss->ss_visit_home_channel) {
                if (scanner_can_leave_home_channel(ss)) {
                    scanner_leave_bss_channel(ss);
                }
                else {
                    ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_BSS_CHANNEL);
                }
            }
            else {
                scanner_leave_bss_channel(ss);
            }
        }
        break;

    default:
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s state=%s event=%s in_progress=%d not handled\n",
            __func__,
            ieee80211_sm_get_current_state_name(ss->ss_hsm_handle),
            ieee80211_scan_event_name(event),
            ss->ss_common.ss_info.si_scan_in_progress);

        return false;
    }

    return true;
}

static void scanner_state_suspending_traffic_entry(void *context)
{
    ieee80211_scanner_t    ss = context;
    int                    status;
    u_int32_t              now = (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%d.%03d | %s\n",
        now / 1000, now % 1000, __func__);

    ss->ss_common.ss_info.si_allow_transmit = false;

    /*
     * If resources manager is performing traffic management, wait for it to
     * send us a  notification that we have transitioned off channel.
     */

    if (! ieee80211_resmgr_active(ss->ss_ic)) {
        IEEE80211_VAP_GOTOSLEEP(ss->ss_vap);

        status = ieee80211_sta_power_pause(ss->ss_vap, ss->ss_fakesleep_timeout);
        if (status != EOK)
        {
            IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s fakesleep ignored \n", __func__);
            /* switch to foreign channel immediately */
            ieee80211_schedule_timed_event(ss, 0, SCANNER_EVENT_FAKESLEEP_EXPIRE);
        }
#if UMAC_SUPPORT_VAP_PAUSE
        if (ieee80211_ic_enh_ind_rpt_is_set(ss->ss_vap->iv_ic)) {
          /* call vap-pause -- stop data and beacons if needed */
        if (ieee80211_ic_pause(ss->ss_vap->iv_ic ) == -1)
        ieee80211_schedule_timed_event(ss, IEEE80211_CAN_PAUSE_WAIT_DELAY , SCANNER_EVENT_CAN_PAUSE_WAIT_EXPIRE);
        }
#endif
    }

    /*
     * Remember that we're entering suspending traffic state.
     * This allows the termination routine to resume VAP operation if scan was
     * cancelled while suspending state (or while in a foreign channel.)
     */
    ss->ss_suspending_traffic = true;
}

static bool scanner_state_suspending_traffic_event(void      *context,
                                                   u_int16_t event,
                                                   u_int16_t event_data_len,
                                                   void      *event_data)
{
    ieee80211_scanner_t    ss = context;

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s state=%s event=%s\n",
        __func__, ieee80211_sm_get_current_state_name(ss->ss_hsm_handle), ieee80211_scan_event_name(event));

    if (is_common_event(ss, event, event_data_len, event_data)) {
        return true;
    }

    switch (event) {
    case SCANNER_EVENT_FAKESLEEP_EXPIRE:
    case SCANNER_EVENT_FAKESLEEP_FAILED:
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s state=%s error sending fakesleep event=%s\n",
            __func__, ieee80211_sm_get_current_state_name(ss->ss_hsm_handle), ieee80211_scan_event_name(event));

        ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_FOREIGN_CHANNEL);
        break;

    case SCANNER_EVENT_FAKESLEEP_ENTERED:
        ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_FOREIGN_CHANNEL);
        break;

    case SCANNER_EVENT_OFFCHAN_SWITCH_COMPLETE:
        if (ss->ss_type == IEEE80211_SCAN_RADIO_MEASUREMENTS) {
            ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_RADIO_MEASUREMENT);
        } else {
            ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_FOREIGN_CHANNEL);
        }
        break;

    case SCANNER_EVENT_OFFCHAN_SWITCH_FAILED:
    case SCANNER_EVENT_OFFCHAN_SWITCH_ABORTED:
        /*
         * Off-channel request failed.
         * Cancel scan if we have already exceeded the maximum number of
         * retries. Otherwise wait some time and retry.
         */
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s retries=%02d/%02d\n",
            __func__, ss->ss_offchan_retry_count, ss->ss_max_offchan_retries);

        ss->ss_suspending_traffic = false;
        if (ss->ss_offchan_retry_count < ss->ss_max_offchan_retries) {
            ss->ss_offchan_retry_count++;
            ieee80211_schedule_timed_event(ss, ss->ss_offchan_retry_delay, SCANNER_EVENT_OFFCHAN_RETRY_EXPIRE);
        }
        else {
            scanner_terminate(ss, IEEE80211_REASON_MAX_OFFCHAN_RETRIES);
        }
        break;

    case SCANNER_EVENT_OFFCHAN_RETRY_EXPIRE:
        /*
         * Retry off-channel switch
         */
        scanner_leave_bss_channel(ss);
        break;
        #if UMAC_SUPPORT_VAP_PAUSE
        case SCANNER_EVENT_CAN_PAUSE_WAIT_EXPIRE :
        if (ieee80211_ic_enh_ind_rpt_is_set(ss->ss_vap->iv_ic)) {
        if (ieee80211_ic_pause(ss->ss_vap->iv_ic ) == -1)  {
                 /* check if we can pause AGAIN */
            ieee80211_schedule_timed_event(ss, IEEE80211_CAN_PAUSE_WAIT_DELAY , SCANNER_EVENT_CAN_PAUSE_WAIT_EXPIRE);
            }
            else {
            ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_FOREIGN_CHANNEL);
            }
            }
          break;
      #endif

    default:
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s state=%s event=%s not handled\n",
            __func__, ieee80211_sm_get_current_state_name(ss->ss_hsm_handle), ieee80211_scan_event_name(event));

        return false;
    }

    return true;
}

static void scanner_state_foreign_channel_entry(void *context)
{
    ieee80211_scanner_t    ss = context;
    u_int32_t              now = (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%d.%03d | %s: entering channel=%d passive=%d probe_delay=%d\n",
        now / 1000, now % 1000, __func__,
        wlan_channel_ieee(ss->ss_chans[ss->ss_next]),
        is_passive_channel(ss->ss_chans[ss->ss_next], ss->ss_flags),
        ss->ss_probe_delay);

    ss->ss_common.ss_info.si_allow_transmit  = false;
    ss->ss_common.ss_info.si_in_home_channel = false;

    ss->ss_offchan_retry_count     = 0;
    ss->ss_suspending_traffic      = false;

    /*
     * Need to set the hw to scan mode only if previous state was not
     * a foreign channel
     */
    if (ieee80211_sm_get_curstate(ss->ss_hsm_handle) != SCANNER_STATE_FOREIGN_CHANNEL) {
        if (! ieee80211_resmgr_active(ss->ss_ic)) {
#if ATH_SLOW_ANT_DIV
            ss->ss_ic->ic_antenna_diversity_suspend(ss->ss_ic);
#endif
            ss->ss_ic->ic_scan_start(ss->ss_ic);
        }
    } else {
        /* Finishing scan in one channel. Post the get NF event */
        scanner_post_event(ss,
                           ss->ss_vap,
                           IEEE80211_SCAN_FOREIGN_CHANNEL_GET_NF,
                           IEEE80211_REASON_COMPLETED,
                           ss->ss_scan_id,
                           ss->ss_requestor,
                           ss->ss_ic->ic_curchan);
    }

    if (!ieee80211_resmgr_active(ss->ss_ic) ||
        (ieee80211_sm_get_curstate(ss->ss_hsm_handle) == SCANNER_STATE_FOREIGN_CHANNEL)) {
        ieee80211_set_channel(ss->ss_ic, ss->ss_chans[ss->ss_next]);
#if ATH_SUPPORT_SPECTRAL
        {
            struct ieee80211_chan_stats chan_stats;
            u_int16_t chan_num = wlan_channel_ieee(ss->ss_ic->ic_curchan);
            struct ieee80211com *ic = ss->ss_ic;
            (void) ic->ic_get_cur_chan_stats(ic, &chan_stats);
            ic->chan_clr_cnt = chan_stats.chan_clr_cnt;
            ic->cycle_cnt = chan_stats.cycle_cnt;
            ic->chan_num = chan_num;
        }
#endif
    }

    scanner_post_event(ss,
                       ss->ss_vap,
                       IEEE80211_SCAN_FOREIGN_CHANNEL,
                       IEEE80211_REASON_NONE,
                       ss->ss_scan_id,
                       ss->ss_requestor,
                       ss->ss_ic->ic_curchan);

    if (is_passive_channel(ss->ss_ic->ic_curchan, ss->ss_flags)) {
        /*
         * Monitor beacons received only if we're performing an active scan.
         * If scan is passive, we'll never send a probe request, so there's no
         * need to monitor traffic on the scanned channel.
         */
        if (ss->ss_ic->ic_strict_pscan_enable) {
            atomic_set(&(ss->ss_wait_for_beacon), false);
        } else {
            atomic_set(&(ss->ss_wait_for_beacon), !(ss->ss_flags & IEEE80211_SCAN_PASSIVE));
        }
        atomic_set(&(ss->ss_beacon_event_queued), false);

        ss->ss_cur_min_dwell = ss->ss_min_dwell_passive;
        ss->ss_cur_max_dwell = ss->ss_max_dwell_passive;

        /*
         * In passive channels, start counting dwell time once we enter
         * the channel.
         * If we receive a beacon we then send a probe request and
         * reset the dwell time.
         */
        ss->ss_enter_channel_time = OS_GET_TIMESTAMP();

        /*
         * Schedule timed event after saving current time.
         * This provides more accurate time calculations if there is a
         * significant latency before the timer is armed.
         */
        if (ss->ss_cur_min_dwell == ss->ss_cur_max_dwell) {
            ieee80211_schedule_timed_event(ss, ss->ss_cur_min_dwell, SCANNER_EVENT_MAXDWELL_EXPIRE);
        } else {
            ieee80211_schedule_timed_event(ss, ss->ss_cur_min_dwell, SCANNER_EVENT_MINDWELL_EXPIRE);
        }
    }
    else {
        atomic_set(&(ss->ss_wait_for_beacon), false);
        ss->ss_cur_min_dwell = ss->ss_min_dwell_active;
        ss->ss_cur_max_dwell = ss->ss_max_dwell_active;

        if (ss->ss_probe_delay) {
            /*
             * Do not start counting dwell time until the probe delay
             * elapses and we send a probe request.
             */
            ieee80211_schedule_timed_event(ss, ss->ss_probe_delay, SCANNER_EVENT_PROBEDELAY_EXPIRE);
        }
        else {
            /* Send first probe request */
            scanner_send_probereq(ss);

            /*
             * Start counting dwell time once we send a probe request.
             */
            ss->ss_enter_channel_time = OS_GET_TIMESTAMP();

            /*
             * Schedule timed event after saving current time.
             * This provides more accurate time calculations if there is a
             * significant latency before the timer is armed.
             */
            if (ss->ss_repeat_probe_time > 0) {
                ieee80211_schedule_timed_event(ss, ss->ss_repeat_probe_time, SCANNER_EVENT_PROBE_REQUEST_TIMER);
            }
            else {
                if (ss->ss_cur_min_dwell == ss->ss_cur_max_dwell) {
                    ieee80211_schedule_timed_event(ss, ss->ss_cur_min_dwell, SCANNER_EVENT_MAXDWELL_EXPIRE);
                } else {
                    ieee80211_schedule_timed_event(ss, ss->ss_cur_min_dwell, SCANNER_EVENT_MINDWELL_EXPIRE);
                }
            }
        }
    }

    /*
     * Field ss_enter_channel_time had already been set above, and holds the
     * timestamp corresponding to a channel change.
     *
     * ss_enter_channel_time is updated on *every* channel change (either to
     * a BSS channel or to a Foreign Channel), while ss_offchannel_time is
     * updated only we scanner first enters a foreign channel after leaving
     * the BSS channel. On subsequent changes to other foreign channels,
     * without returning to the BSS channel, ss_offchannel_time is not updated.
     */
    if (ieee80211_sm_get_curstate(ss->ss_hsm_handle) != SCANNER_STATE_FOREIGN_CHANNEL) {
        ss->ss_offchannel_time = ss->ss_enter_channel_time;
    }

    ss->ss_next++;
}

static void scanner_state_foreign_channel_exit(void *context)
{
    ieee80211_scanner_t    ss = context;

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: wait_for_beacon=%d\n",
        __func__,
        ss->ss_wait_for_beacon);

    /* Stop monitoring beacons */
    atomic_set(&(ss->ss_wait_for_beacon), false);
}

static bool scanner_leave_foreign_channel(ieee80211_scanner_t ss)
{
    int    status;

    if ((ss->ss_flags & IEEE80211_SCAN_BURST) &&
        (ss->ss_max_offchannel_time > 0)      &&
        (ss->ss_visit_home_channel)) {
        u_int32_t    min_dwell;
        u_int32_t    future_offchannel_time;
        systime_t    current_time = OS_GET_TIMESTAMP();

        /*
         * Estimate the total amount of time spent off-channel if we scan one
         * more channel before returning to the BSS channel. If this total time
         * is still less than max_offchannel_time, then we can visit one more
         * channel.
         */
        min_dwell =
            is_passive_channel(ss->ss_chans[ss->ss_next], ss->ss_flags) ?
                ss->ss_min_dwell_passive : ss->ss_min_dwell_active;

        /*
         * future_offchannel_time is current amount of time spent off-channel
         * plus the dwell time for the next channel.
         */
        future_offchannel_time =
            ((u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(current_time - ss->ss_offchannel_time)) +
            min_dwell;

        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: current_time=%d ss_offchannel_time=%d min_dwell=%d future_offchannel_time=%d scan_another_channel=%d\n",
            __func__,
            (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(current_time),
            (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(ss->ss_offchannel_time),
            min_dwell,
            future_offchannel_time,
            (future_offchannel_time < ss->ss_max_offchannel_time));

        if (future_offchannel_time < ss->ss_max_offchannel_time) {
            ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_FOREIGN_CHANNEL);
            return true;
        }
    }

#if ATH_SUPPORT_SPECTRAL
    {
        struct ieee80211_chan_stats chan_stats;
        u_int16_t chan_num = wlan_channel_ieee(ss->ss_ic->ic_curchan);
        struct ieee80211com *ic = ss->ss_ic;

        (void) ic->ic_get_cur_chan_stats(ic, &chan_stats);

        ic->ic_record_chan_info(ic,
                                chan_num,
                                true,  /* Whether Channel cycle
                                          counts are valid */
                                chan_stats.chan_clr_cnt,
                                ic->chan_clr_cnt,
                                chan_stats.cycle_cnt,
                                ic->cycle_cnt,
                                false,  /* Whether NF is valid */
                                0,      /* NF */
                                false,  /* Whether PER is valid */
                                0);     /* PER */

    }
#endif


    status = ieee80211_resmgr_request_bsschan(ss->ss_resmgr,
                                              SCANNER_RESMGR_REQID);

    switch (status) {
    case EOK:
        /*
         * Resource Manager not active.
         * Scanner needs to visit home channel if connected or if softAP is
         * running. It should not visit home channel in case of auto channel scan.
         */
        if (ss->ss_visit_home_channel && !(wlan_autoselect_in_progress(ss->ss_vap)) ) {
            ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_BSS_CHANNEL);
        } else {
            ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_FOREIGN_CHANNEL);
        }
        break;

    case EBUSY:
        /*
         * Resource Manager is responsible for resuming traffic, changing
         * channel and sending notification once the operation has completed.
         */
        ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_RESUMING_TRAFFIC);
        break;

    case EINVAL:
        /*
         * No BSS channel (client not connected and no softAP running).
         * Move on to next foreign channel.
         */
        ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_FOREIGN_CHANNEL);
        break;

    default:
        /*
         * Error.
         * Move on to next foreign channel.
         */
        ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_FOREIGN_CHANNEL);
        break;
    }

    return true;
}

static bool scanner_state_foreign_channel_event(void      *context,
                                                u_int16_t event,
                                                u_int16_t event_data_len,
                                                void      *event_data)
{
    ieee80211_scanner_t    ss = context;

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s state=%s event=%s\n",
        __func__, ieee80211_sm_get_current_state_name(ss->ss_hsm_handle), ieee80211_scan_event_name(event));

    if (is_common_event(ss, event, event_data_len, event_data)) {
        return true;
    }

    switch (event) {
    case SCANNER_EVENT_PROBEDELAY_EXPIRE:
        /* Send first probe request */
        scanner_send_probereq(ss);

        /*
         * Start counting dwell time once we send a probe request.
         */
        ss->ss_enter_channel_time = OS_GET_TIMESTAMP();

        /*
         * Schedule timed event after saving current time.
         * This provides more accurate time calculations if there is a
         * significant latency before the timer is armed.
         */
        if (ss->ss_repeat_probe_time > 0) {
            ieee80211_schedule_timed_event(ss, ss->ss_repeat_probe_time, SCANNER_EVENT_PROBE_REQUEST_TIMER);
        }
        else {
            if (ss->ss_cur_min_dwell == ss->ss_cur_max_dwell) {
                ieee80211_schedule_timed_event(ss, ss->ss_cur_min_dwell, SCANNER_EVENT_MAXDWELL_EXPIRE);
            } else {
                ieee80211_schedule_timed_event(ss, ss->ss_cur_min_dwell, SCANNER_EVENT_MINDWELL_EXPIRE);
            }
        }

        /* Stay in the same state */
        break;

    case SCANNER_EVENT_PROBE_REQUEST_TIMER:
        /*
         * Whenever we have completed the dwell time, give the client
         * a chance to indicate scan must terminate.
         * This allows for the scan to run only for the time necessary to
         * meet a desired condition - for example, find a candidate AP.
         */

	if ((ss->ss_common.ss_info.si_last_term_status == 0) &&(ss->ss_check_termination_function != NULL) &&
            (ss->ss_check_termination_function(ss->ss_check_termination_context) == true)) {
            qdf_print("%s %d Scan termination called \n",__func__,__LINE__);
            scanner_terminate(ss, IEEE80211_REASON_TERMINATION_FUNCTION);
        }
        else {
            if (scanner_can_leave_foreign_channel(ss)) {
                if (scanner_check_endof_scan(ss)) {
                    scanner_terminate(ss, IEEE80211_REASON_COMPLETED);
                }
                else {
                    scanner_leave_foreign_channel(ss);
                }
            }
            else {
                /* Send second Probe Request */
                scanner_send_probereq(ss);

                if (ss->ss_cur_min_dwell == ss->ss_cur_max_dwell) {
                    ieee80211_schedule_timed_event(ss, ss->ss_cur_min_dwell - ss->ss_repeat_probe_time, SCANNER_EVENT_MAXDWELL_EXPIRE);
                } else {
                    ieee80211_schedule_timed_event(ss, ss->ss_cur_min_dwell - ss->ss_repeat_probe_time, SCANNER_EVENT_MINDWELL_EXPIRE);
                }
            }
        }
        break;

    case SCANNER_EVENT_MINDWELL_EXPIRE:
        /*
         * Whenever we have completed the dwell time, give the client
         * a chance to indicate scan must terminate.
         * This allows for the scan to run only for the time necessary to
         * meet a desired condition - for example, find a candidate AP.
         */
        if ((ss->ss_common.ss_info.si_last_term_status == 0) && (ss->ss_check_termination_function != NULL) &&
            (ss->ss_check_termination_function(ss->ss_check_termination_context) == true)) {
            qdf_print("%s %d Scan termination called \n",__func__,__LINE__);
            scanner_terminate(ss, IEEE80211_REASON_TERMINATION_FUNCTION);
        }
        else {
            if (scanner_can_leave_foreign_channel(ss)) {
                if (scanner_check_endof_scan(ss)) {
                     /* get noise floor for the last channel scanned */
                     scanner_post_event(ss,
                                       ss->ss_vap,
                                       IEEE80211_SCAN_FOREIGN_CHANNEL_GET_NF,
                                       IEEE80211_REASON_COMPLETED,
                                       ss->ss_scan_id,
                                       ss->ss_requestor,
                                       ss->ss_ic->ic_curchan);

#if ATH_SUPPORT_SPECTRAL
                     {
                         struct ieee80211_chan_stats chan_stats;
                         u_int16_t chan_num = wlan_channel_ieee(ss->ss_ic->ic_curchan);
                         struct ieee80211com *ic = ss->ss_ic;
                         (void) ic->ic_get_cur_chan_stats(ic, &chan_stats);

                         ic->ic_record_chan_info(ic,
                                                 chan_num,
                                                 true,  /* Whether Channel cycle
                                                           counts are valid */
                                                 chan_stats.chan_clr_cnt,
                                                 ic->chan_clr_cnt,
                                                 chan_stats.cycle_cnt,
                                                 ic->cycle_cnt,
                                                 false,  /* Whether NF is valid */
                                                 0,      /* NF */
                                                 false,  /* Whether PER is valid */
                                                 0);     /* PER */

                     }
#endif

                     scanner_terminate(ss, IEEE80211_REASON_COMPLETED);
                }
                else {
                    scanner_leave_foreign_channel(ss);
                }
            }
            else {
                systime_t    enter_channel_time = ss->ss_enter_channel_time;
                u_int32_t    remaining_dwell_time;
                u_int32_t    new_timer_interval;

                /*
                 * Maximum remaining dwell time = cur_max_dwell_time - elapsed_time
                 * Read starting time before current time to avoid
                 * inconsistent timestamps due to preemption.
                 */
                remaining_dwell_time = ss->ss_cur_max_dwell -
                    CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP() - enter_channel_time);

                /*
                 * Set new timer to minimum of min_dwell and maximum
                 * remaining dwell time.
                 */
                new_timer_interval = min(ss->ss_cur_min_dwell, remaining_dwell_time);

                if (ss->ss_cur_min_dwell == ss->ss_cur_max_dwell) {
                    ieee80211_schedule_timed_event(ss, new_timer_interval, SCANNER_EVENT_MAXDWELL_EXPIRE);
                } else {
                    ieee80211_schedule_timed_event(ss, new_timer_interval, SCANNER_EVENT_MINDWELL_EXPIRE);
                }
            }
        }
        break;

    case SCANNER_EVENT_RECEIVED_BEACON:
        /*
         * Should NOT be monitoring beacons if performing passive scan.
         */
        ASSERT(! (ss->ss_flags & IEEE80211_SCAN_PASSIVE));

        /*
         * Received beacon in passive channel. Flag ss_wait_for_beacon is set
         * only if scan is active.
         */
        if (OS_ATOMIC_CMPXCHG(&ss->ss_wait_for_beacon, true, false) == true) {
            /*
             * Received beacon in passive channel, so it's OK to send probe
             * requests now. Cancel max_passive_dwell timer and switch scanning
             * in this channel from passive to active.
             */
            OS_CANCEL_TIMER(&ss->ss_timer);

            ss->ss_cur_min_dwell = ss->ss_min_dwell_active;
            ss->ss_cur_max_dwell = ss->ss_max_dwell_active;

            /* Send first probe request */
            scanner_send_probereq(ss);

            /*
             * Start counting dwell time once we send a probe request.
             */
            ss->ss_enter_channel_time = OS_GET_TIMESTAMP();

            /*
             * Schedule timed event after saving current time.
             * This provides more accurate time calculations if there is a
             * significant latency before the timer is armed.
             */
            if (ss->ss_repeat_probe_time > 0) {
                ieee80211_schedule_timed_event(ss, ss->ss_repeat_probe_time, SCANNER_EVENT_PROBE_REQUEST_TIMER);
            }
            else {
                if (ss->ss_cur_min_dwell == ss->ss_cur_max_dwell) {
                    ieee80211_schedule_timed_event(ss, ss->ss_cur_min_dwell, SCANNER_EVENT_MAXDWELL_EXPIRE);
                } else {
                    ieee80211_schedule_timed_event(ss, ss->ss_cur_min_dwell, SCANNER_EVENT_MINDWELL_EXPIRE);
                }
            }
        }
        break;

    case SCANNER_EVENT_MAXDWELL_EXPIRE:
        /*
         * Whenever we have completed the dwell time, give the client
         * a chance to indicate scan must terminate.
         * This allows for the scan to run only for the time necessary to
         * meet a desired condition - for example, find a candidate AP.
         */
        if ((ss->ss_common.ss_info.si_last_term_status == 0) && (ss->ss_check_termination_function != NULL) &&
            (ss->ss_check_termination_function(ss->ss_check_termination_context) == true)) {
            qdf_print("%s %d Scan termination called \n",__func__,__LINE__);
            scanner_terminate(ss, IEEE80211_REASON_TERMINATION_FUNCTION);
        }
        else {
            if (scanner_check_endof_scan(ss)) {
                    /* Defer scan completion to retrieve chan info from target */
                scanner_terminate(ss, IEEE80211_REASON_COMPLETED);
            }
            else {
                scanner_leave_foreign_channel(ss);
            }
        }
        break;
    default:
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s state=%s event=%s not handled\n",
            __func__, ieee80211_sm_get_current_state_name(ss->ss_hsm_handle), ieee80211_scan_event_name(event));

        return false;
    }

    return true;
}

static void scanner_state_repeater_channel_entry(void *context)
{
    ieee80211_scanner_t    ss = context;
    u_int32_t              now = (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%d.%03d | %s: entering channel=%d passive=%d probe_delay=%d\n",
        now / 1000, now % 1000, __func__,
        wlan_channel_ieee(ss->ss_chans[ss->ss_next]),
        is_passive_channel(ss->ss_chans[ss->ss_next], ss->ss_flags),
        ss->ss_probe_delay);

    /* ss->ss_common.ss_info.si_allow_transmit  = false; */
    /* ss->ss_common.ss_info.si_in_home_channel = false; */

    ss->ss_offchan_retry_count = 0;
    ss->ss_suspending_traffic  = false;

    if (is_passive_channel(ss->ss_ic->ic_curchan, ss->ss_flags)) {
        /*
         * Monitor beacons received only if we're performing an active scan.
         * If scan is passive, we'll never send a probe request, so there's no
         * need to monitor traffic on the scanned channel.
         */
        if (ss->ss_ic->ic_strict_pscan_enable) {
            atomic_set(&(ss->ss_wait_for_beacon), false);
        } else {
            atomic_set(&(ss->ss_wait_for_beacon), !(ss->ss_flags & IEEE80211_SCAN_PASSIVE));
        }
        atomic_set(&(ss->ss_beacon_event_queued), false);

        ss->ss_cur_min_dwell = ss->ss_min_dwell_passive;
        ss->ss_cur_max_dwell = ss->ss_max_dwell_passive;

        /*
         * In passive channels, start counting dwell time once we enter
         * the channel.
         * If we receive a beacon we then send a probe request and
         * reset the dwell time.
         */
        ss->ss_enter_channel_time = OS_GET_TIMESTAMP();

        /*
         * Schedule timed event after saving current time.
         * This provides more accurate time calculations if there is a
         * significant latency before the timer is armed.
         */
        if (ss->ss_cur_min_dwell == ss->ss_cur_max_dwell) {
            ieee80211_schedule_timed_event(ss, ss->ss_cur_min_dwell, SCANNER_EVENT_MAXDWELL_EXPIRE);
        } else {
            ieee80211_schedule_timed_event(ss, ss->ss_cur_min_dwell, SCANNER_EVENT_MINDWELL_EXPIRE);
        }
    }
    else {
        atomic_set(&(ss->ss_wait_for_beacon), false);
        ss->ss_cur_min_dwell = ss->ss_min_dwell_active;
        ss->ss_cur_max_dwell = ss->ss_max_dwell_active;

        if (ss->ss_probe_delay) {
            /*
             * Do not start counting dwell time until the probe delay
             * elapses and we send a probe request.
             */
            ieee80211_schedule_timed_event(ss, ss->ss_probe_delay, SCANNER_EVENT_PROBEDELAY_EXPIRE);
        }
        else {
            /* Send first probe request */
            scanner_send_probereq(ss);

            /*
             * Start counting dwell time once we send a probe request.
             */
            ss->ss_enter_channel_time = OS_GET_TIMESTAMP();

            /*
             * Schedule timed event after saving current time.
             * This provides more accurate time calculations if there is a
             * significant latency before the timer is armed.
             */
            if (ss->ss_repeat_probe_time > 0) {
                ieee80211_schedule_timed_event(ss, ss->ss_repeat_probe_time, SCANNER_EVENT_PROBE_REQUEST_TIMER);
            }
            else {
                if (ss->ss_cur_min_dwell == ss->ss_cur_max_dwell) {
                    ieee80211_schedule_timed_event(ss, ss->ss_cur_min_dwell, SCANNER_EVENT_MAXDWELL_EXPIRE);
                } else {
                    ieee80211_schedule_timed_event(ss, ss->ss_cur_min_dwell, SCANNER_EVENT_MINDWELL_EXPIRE);
                }
            }
        }
    }

    ss->ss_next++;
}


static bool scanner_state_repeater_channel_event(void     *context,
                                                 u_int16_t event,
                                                 u_int16_t event_data_len,
                                                 void      *event_data)
{
    ieee80211_scanner_t    ss = context;

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s state=%s event=%s\n",
        __func__, ieee80211_sm_get_current_state_name(ss->ss_hsm_handle), ieee80211_scan_event_name(event));

    if (is_common_event(ss, event, event_data_len, event_data)) {
        return true;
    }

    switch (event) {
    case SCANNER_EVENT_PROBEDELAY_EXPIRE:
        /* Send first probe request */
        scanner_send_probereq(ss);

        /*
         * Start counting dwell time once we send a probe request.
         */
        ss->ss_enter_channel_time = OS_GET_TIMESTAMP();

        /*
         * Schedule timed event after saving current time.
         * This provides more accurate time calculations if there is a
         * significant latency before the timer is armed.
         */
        if (ss->ss_repeat_probe_time > 0) {
            ieee80211_schedule_timed_event(ss, ss->ss_repeat_probe_time, SCANNER_EVENT_PROBE_REQUEST_TIMER);
        }
        else {
            if (ss->ss_cur_min_dwell == ss->ss_cur_max_dwell) {
                ieee80211_schedule_timed_event(ss, ss->ss_cur_min_dwell, SCANNER_EVENT_MAXDWELL_EXPIRE);
            } else {
                ieee80211_schedule_timed_event(ss, ss->ss_cur_min_dwell, SCANNER_EVENT_MINDWELL_EXPIRE);
            }
        }

        /* Stay in the same state */
        break;

    case SCANNER_EVENT_PROBE_REQUEST_TIMER:
        /*
         * Whenever we have completed the dwell time, give the client
         * a chance to indicate scan must terminate.
         * This allows for the scan to run only for the time necessary to
         * meet a desired condition - for example, find a candidate AP.
         */
        if ((ss->ss_check_termination_function != NULL) &&
            (ss->ss_check_termination_function(ss->ss_check_termination_context) == true)) {
            scanner_terminate(ss, IEEE80211_REASON_TERMINATION_FUNCTION);
        }
        else {
            if (scanner_can_leave_foreign_channel(ss)) {
                if (scanner_check_endof_scan(ss)) {
                    scanner_terminate(ss, IEEE80211_REASON_COMPLETED);
                }
                else {
                    scanner_terminate(ss, IEEE80211_REASON_TERMINATION_FUNCTION);
                }
            }
            else {
                /* Send second Probe Request */
                scanner_send_probereq(ss);

                if (ss->ss_cur_min_dwell == ss->ss_cur_max_dwell) {
                    ieee80211_schedule_timed_event(ss, ss->ss_cur_min_dwell - ss->ss_repeat_probe_time, SCANNER_EVENT_MAXDWELL_EXPIRE);
                } else {
                    ieee80211_schedule_timed_event(ss, ss->ss_cur_min_dwell - ss->ss_repeat_probe_time, SCANNER_EVENT_MINDWELL_EXPIRE);
                }
            }
        }
        break;

    case SCANNER_EVENT_MINDWELL_EXPIRE:
        /*
         * Whenever we have completed the dwell time, give the client
         * a chance to indicate scan must terminate.
         * This allows for the scan to run only for the time necessary to
         * meet a desired condition - for example, find a candidate AP.
         */
        if ((ss->ss_check_termination_function != NULL) &&
            (ss->ss_check_termination_function(ss->ss_check_termination_context) == true)) {
            scanner_terminate(ss, IEEE80211_REASON_TERMINATION_FUNCTION);
        }
        else {
            if (scanner_can_leave_foreign_channel(ss)) {

                if (scanner_check_endof_scan(ss)) {
                    scanner_terminate(ss, IEEE80211_REASON_COMPLETED);
                }
                else {
                    scanner_terminate(ss, IEEE80211_REASON_COMPLETED);
                }
            }
            else {
                systime_t    enter_channel_time = ss->ss_enter_channel_time;
                u_int32_t    remaining_dwell_time;
                u_int32_t    new_timer_interval;

                /*
                 * Maximum remaining dwell time = cur_max_dwell_time - elapsed_time
                 * Read starting time before current time to avoid
                 * inconsistent timestamps due to preemption.
                 */
                remaining_dwell_time = ss->ss_cur_max_dwell -
                    CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP() - enter_channel_time);

                /*
                 * Set new timer to minimum of min_dwell and maximum
                 * remaining dwell time.
                 */
                new_timer_interval = min(ss->ss_cur_min_dwell, remaining_dwell_time);

                if (ss->ss_cur_min_dwell == ss->ss_cur_max_dwell) {
                    ieee80211_schedule_timed_event(ss, new_timer_interval, SCANNER_EVENT_MAXDWELL_EXPIRE);
                } else {
                    ieee80211_schedule_timed_event(ss, new_timer_interval, SCANNER_EVENT_MINDWELL_EXPIRE);
                }
            }
        }
        break;

    case SCANNER_EVENT_RECEIVED_BEACON:
        /*
         * Should NOT be monitoring beacons if performing passive scan.
         */
        ASSERT(! (ss->ss_flags & IEEE80211_SCAN_PASSIVE));

        /*
         * Received beacon in passive channel. Flag ss_wait_for_beacon is set
         * only if scan is active.
         */
        if (OS_ATOMIC_CMPXCHG(&ss->ss_wait_for_beacon, true, false) == true) {
            /*
             * Received beacon in passive channel, so it's OK to send probe
             * requests now. Cancel max_passive_dwell timer and switch scanning
             * in this channel from passive to active.
             */
            OS_CANCEL_TIMER(&ss->ss_timer);

            ss->ss_cur_min_dwell = ss->ss_min_dwell_active;
            ss->ss_cur_max_dwell = ss->ss_max_dwell_active;

            /* Send first probe request */
            scanner_send_probereq(ss);

            /*
             * Start counting dwell time once we send a probe request.
             */
            ss->ss_enter_channel_time = OS_GET_TIMESTAMP();

            /*
             * Schedule timed event after saving current time.
             * This provides more accurate time calculations if there is a
             * significant latency before the timer is armed.
             */
            if (ss->ss_repeat_probe_time > 0) {
                ieee80211_schedule_timed_event(ss, ss->ss_repeat_probe_time, SCANNER_EVENT_PROBE_REQUEST_TIMER);
            }
            else {
                if (ss->ss_cur_min_dwell == ss->ss_cur_max_dwell) {
                    ieee80211_schedule_timed_event(ss, ss->ss_cur_min_dwell, SCANNER_EVENT_MAXDWELL_EXPIRE);
                } else {
                    ieee80211_schedule_timed_event(ss, ss->ss_cur_min_dwell, SCANNER_EVENT_MINDWELL_EXPIRE);
                }
            }
        }
        break;

    case SCANNER_EVENT_MAXDWELL_EXPIRE:
        /*
         * Whenever we have completed the dwell time, give the client
         * a chance to indicate scan must terminate.
         * This allows for the scan to run only for the time necessary to
         * meet a desired condition - for example, find a candidate AP.
         */
        if ((ss->ss_check_termination_function != NULL) &&
            (ss->ss_check_termination_function(ss->ss_check_termination_context) == true)) {
            scanner_terminate(ss, IEEE80211_REASON_TERMINATION_FUNCTION);
        }
        else {
            if (scanner_check_endof_scan(ss)) {
                scanner_terminate(ss, IEEE80211_REASON_COMPLETED);
            }
            else {
                scanner_terminate(ss, IEEE80211_REASON_COMPLETED);
            }
        }
        break;

    default:
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s state=%s event=%s not handled\n",
            __func__, ieee80211_sm_get_current_state_name(ss->ss_hsm_handle), ieee80211_scan_event_name(event));

        return false;
    }

    return true;
}

static bool scanner_state_resuming_traffic_event(void      *context,
                                                 u_int16_t event,
                                                 u_int16_t event_data_len,
                                                 void      *event_data)
{
    ieee80211_scanner_t    ss = context;

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s state=%s event=%s\n",
        __func__, ieee80211_sm_get_current_state_name(ss->ss_hsm_handle), ieee80211_scan_event_name(event));

    if (is_common_event(ss, event, event_data_len, event_data)) {
        return true;
    }

    switch (event) {
    case SCANNER_EVENT_BSSCHAN_SWITCH_COMPLETE:
        /* Go back to BSS channel state part of normal scan */
        ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_BSS_CHANNEL);
        break;

    default:
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s state=%s event=%s not handled\n",
            __func__, ieee80211_sm_get_current_state_name(ss->ss_hsm_handle), ieee80211_scan_event_name(event));

        return false;
    }

    return true;
}

static void scanner_state_bss_channel_entry(void *context)
{
    ieee80211_scanner_t    ss = context;
    u_int32_t              now = (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%d.%03d | %s: \n", now / 1000, now % 1000, __func__);

    /*
     * Need to take the hardware out of "scan" mode only if transitioning
     * from a foreign channel.
     */
    if ((ieee80211_sm_get_curstate(ss->ss_hsm_handle) != SCANNER_STATE_BSS_CHANNEL) &&
        (ieee80211_sm_get_curstate(ss->ss_hsm_handle) != SCANNER_STATE_IDLE) &&
        (ieee80211_sm_get_curstate(ss->ss_hsm_handle) != SCANNER_STATE_SUSPENDING_TRAFFIC)) {
        if (! ieee80211_resmgr_active(ss->ss_ic)) {
            ss->ss_ic->ic_scan_end(ss->ss_ic);
            ieee80211_set_channel (ss->ss_ic, ss->ss_vap->iv_bsschan);
#if ATH_SLOW_ANT_DIV
            ss->ss_ic->ic_antenna_diversity_resume(ss->ss_ic);
#endif
        }
         ss->ss_ic->ic_scan_enable_txq(ss->ss_ic);
        if (! ieee80211_resmgr_active(ss->ss_ic)) {
            IEEE80211_VAP_WAKEUP(ss->ss_vap);
            if (ss->ss_is_connected(ss->ss_vap)) {
                if (ieee80211_sta_power_unpause(ss->ss_vap) != EOK)
                {
                    /*
                     * No need for a sophisticated error handling here.
                     * If transmission of fake wakeup fails, subsequent traffic sent
                     * with PM bit clear will have the same effect.
                     */
                    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s failed to send fakewakeup\n",
                        __func__);
                    // status = EIO;
                }
#if ATH_VAP_PAUSE_SUPPORT
                if (ieee80211_ic_enh_ind_rpt_is_set(ss->ss_vap->iv_ic)) {
                    /* call vap-unpause */
                    ieee80211_ic_unpause(ss->ss_ic);
                }
#endif

            }
#if UMAC_SUPPORT_VAP_PAUSE
            /* call vap-unpause -- resume data and beacons if needed */
            if (ieee80211_ic_enh_ind_rpt_is_set(ss->ss_vap->iv_ic)) {
                ieee80211_ic_unpause(ss->ss_ic);
            }
#endif
        }

        ss->ss_enter_channel_time = OS_GET_TIMESTAMP();
        ss->ss_beacons_received   = 0;
    }

    ieee80211_schedule_timed_event(ss, ss->ss_min_rest_time, SCANNER_EVENT_RESTTIME_EXPIRE);

    atomic_set(&(ss->ss_wait_for_beacon), false);

    ss->ss_common.ss_info.si_allow_transmit  = true;
    ss->ss_common.ss_info.si_in_home_channel = true;

    /*
     * Notify upper layers that we have returned to BSS channel.
     * Notification must be sent in the transition from SCANNER_STATE_SUSPENDING_TRAFFIC
     * to SCANNER_STATE_BSS_CHANNEL since frames may have been queued at upper layers
     * while we attempted to suspend traffic.
     */
    if ((ieee80211_sm_get_curstate(ss->ss_hsm_handle) != SCANNER_STATE_BSS_CHANNEL) &&
        (ieee80211_sm_get_curstate(ss->ss_hsm_handle) != SCANNER_STATE_IDLE)) {
        scanner_post_event(ss,
                           ss->ss_vap,
                           IEEE80211_SCAN_HOME_CHANNEL,
                           IEEE80211_REASON_NONE,
                           ss->ss_scan_id,
                           ss->ss_requestor,
                           ss->ss_ic->ic_curchan);
    }
}

static bool scanner_state_bss_channel_event(void      *context,
                                            u_int16_t event,
                                            u_int16_t event_data_len,
                                            void      *event_data)
{
    ieee80211_scanner_t    ss = context;

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s state=%s event=%s\n",
        __func__, ieee80211_sm_get_current_state_name(ss->ss_hsm_handle), ieee80211_scan_event_name(event));

    ASSERT(event_data);

    if (is_common_event(ss, event, event_data_len, event_data)) {
        return true;
    }

    switch (event) {
    case SCANNER_EVENT_RESTTIME_EXPIRE:
    case SCANNER_EVENT_EXIT_CRITERIA_EXPIRE:
        if (scanner_can_leave_home_channel(ss)) {
            scanner_leave_bss_channel(ss);
        }
        else {
            ieee80211_schedule_timed_event(ss, ss->ss_exit_criteria_intval, SCANNER_EVENT_EXIT_CRITERIA_EXPIRE);
        }
        break;

    default:
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s state=%s event=%s not handled\n",
            __func__, ieee80211_sm_get_current_state_name(ss->ss_hsm_handle), ieee80211_scan_event_name(event));

        return false;
    }

    return true;
}

static void scanner_state_radio_measurement_entry(void *context)
{
    ieee80211_scanner_t    ss = context;

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s Prev state %s\n",
        __func__, ieee80211_sm_get_current_state_name(ss->ss_hsm_handle));

    /* cancel timer */
    OS_CANCEL_TIMER(&ss->ss_timer);

    /*
     * Start a timer to ensure the state machine doesn't dealock in case
     * we never receive a "resume" request. The timer value is the nominal
     * radio measurement duration
     */
    ieee80211_schedule_timed_event(ss,
                                   ss->ss_min_dwell_active,
                                   SCANNER_EVENT_RADIO_MEASUREMENT_EXPIRE);
    scanner_post_event(ss,
                       ss->ss_vap,
                       IEEE80211_SCAN_RADIO_MEASUREMENT_START,
                       IEEE80211_REASON_NONE,
                       ss->ss_scan_id,
                       ss->ss_requestor,
                       ss->ss_ic->ic_curchan);
}

static bool scanner_state_radio_measurement_event(void      *context,
                                                  u_int16_t event,
                                                  u_int16_t event_data_len,
                                                  void      *event_data)
{
    ieee80211_scanner_t    ss = context;

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s state=%s event=%s\n",
        __func__, ieee80211_sm_get_current_state_name(ss->ss_hsm_handle), ieee80211_scan_event_name(event));

    if (is_common_event(ss, event, event_data_len, event_data)) {
        return true;
    }

    switch (event) {

    case SCANNER_EVENT_RADIO_MEASUREMENT_EXPIRE:
        /*
         * End of Radio Measurements
         * Leave Radio measurements state so that scan can be used by others.
         */
        scanner_post_event(ss,
                           ss->ss_vap,
                           IEEE80211_SCAN_RADIO_MEASUREMENT_END,
                           IEEE80211_REASON_NONE,
                           ss->ss_scan_id,
                           ss->ss_requestor,
                           ss->ss_ic->ic_curchan);

        scanner_terminate(ss, IEEE80211_REASON_COMPLETED);
        break;

    case SCANNER_EVENT_SCAN_REQUEST:
        if (! ss->ss_common.ss_info.si_scan_in_progress) {
            IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s state=%s event=%s nothing to do\n",
                __func__,
                ieee80211_sm_get_current_state_name(ss->ss_hsm_handle),
                ieee80211_scan_event_name(event));

            return true;
        }
        break;

    default:
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s state=%s event=%s in_progress=%d not handled\n",
            __func__,
            ieee80211_sm_get_current_state_name(ss->ss_hsm_handle),
            ieee80211_scan_event_name(event),
            ss->ss_common.ss_info.si_scan_in_progress);

        return false;
    }

    return true;
}

static void scanner_state_terminating_entry(void *context)
{
    ieee80211_scanner_t    ss = context;
    u_int32_t              now = (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%d.%03d | %s\n",
        now / 1000, now % 1000, __func__);
}

static bool scanner_state_terminating_event(void      *context,
                                            u_int16_t event,
                                            u_int16_t event_data_len,
                                            void      *event_data)
{
    ieee80211_scanner_t    ss = context;

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s state=%s event=%s\n",
        __func__, ieee80211_sm_get_current_state_name(ss->ss_hsm_handle), ieee80211_scan_event_name(event));

    switch (event) {
    case SCANNER_EVENT_BSSCHAN_SWITCH_COMPLETE:
    case SCANNER_EVENT_OFFCHAN_SWITCH_FAILED:
    case SCANNER_EVENT_OFFCHAN_SWITCH_ABORTED:
        ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_IDLE);
        break;

    case SCANNER_EVENT_TERMINATING_TIMEOUT:
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s state=%s No response from ResMgr\n",
            __func__, ieee80211_sm_get_current_state_name(ss->ss_hsm_handle), ieee80211_scan_event_name(event));

        ASSERT(event != SCANNER_EVENT_TERMINATING_TIMEOUT);
        ieee80211_sm_transition_to(ss->ss_hsm_handle, SCANNER_STATE_IDLE);
        break;

    default:
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s state=%s event=%s not handled\n",
            __func__, ieee80211_sm_get_current_state_name(ss->ss_hsm_handle), ieee80211_scan_event_name(event));
        return false;
    }

    return true;
}

static OS_TIMER_FUNC(scanner_timer_handler)
{
    ieee80211_scanner_t    ss;

    OS_GET_TIMER_ARG(ss, ieee80211_scanner_t);

    if (ss->ss_pending_event == SCANNER_EVENT_TERMINATING_TIMEOUT) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s state=%s posting event=%s\n",
            __func__, ieee80211_sm_get_current_state_name(ss->ss_hsm_handle), ieee80211_scan_event_name(ss->ss_pending_event));
    }

#if !ATH_SUPPORT_MULTIPLE_SCANS && defined USE_WORKQUEUE_FOR_MESGQ_AND_SCAN
    qdf_sched_work(NULL, &ss->ss_timer_defered);
#else
    ieee80211_sm_dispatch(ss->ss_hsm_handle,
                          ss->ss_pending_event,
                          0,
                          NULL);

    /* Clear pending event */
    ss->ss_pending_event = SCANNER_EVENT_NONE;
#endif
}

static OS_TIMER_FUNC(scanner_timer_maxtime_handler)
{
    ieee80211_scanner_t    ss;

    OS_GET_TIMER_ARG(ss, ieee80211_scanner_t);

#if !ATH_SUPPORT_MULTIPLE_SCANS && defined USE_WORKQUEUE_FOR_MESGQ_AND_SCAN
   qdf_sched_work(NULL, &ss->ss_maxscan_timer_defered);
#else
    ieee80211_sm_dispatch(ss->ss_hsm_handle,
                          SCANNER_EVENT_MAXSCANTIME_EXPIRE,
                          0,
                          NULL);
#endif
}

/*
 * get all the channels to scan .
 * can be called whenever the set of supported channels are changed.
 * (ex: when a  beacon with valid country code received )
 */
static int _ieee80211_scan_update_channel_list(ieee80211_scanner_t ss)
{
#define IEEE80211_2GHZ_FREQUENCY_THRESHOLD    3000            // in kHz
    struct ieee80211com         *ic = ss->ss_ic;
    struct ieee80211_channel    *c;
    int                         i;

    ss->ss_nallchans = 0;

    spin_lock(&ss->ss_lock);

    for (i = 0; i < IEEE80211_N(scan_order); ++i) {
        c = NULL;

        if (scan_order[i] < IEEE80211_2GHZ_FREQUENCY_THRESHOLD) { /* 2GHZ channel */
            if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NG_HT20)) {
                c = ieee80211_find_channel(ic, scan_order[i], 0, IEEE80211_CHAN_11NG_HT20);
            }

            if (c == NULL) {
                c = ieee80211_find_channel(ic, scan_order[i], 0, IEEE80211_CHAN_G);
            }

            if (c == NULL) {
                c = ieee80211_find_channel(ic, scan_order[i], 0, IEEE80211_CHAN_PUREG);
            }

            if (c == NULL) {
                c = ieee80211_find_channel(ic, scan_order[i], 0, IEEE80211_CHAN_B);
            }
        } else {
            if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11AC_VHT20)) {
                c = ieee80211_find_channel(ic, scan_order[i], 0, IEEE80211_CHAN_11AC_VHT80);
            } else if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NA_HT20)) {
                c = ieee80211_find_channel(ic, scan_order[i], 0, IEEE80211_CHAN_11NA_HT20);
            }

            if (c == NULL) {
                c = ieee80211_find_channel(ic, scan_order[i], 0, IEEE80211_CHAN_A);
            }
        }

        if (c != NULL) {
            ss->ss_all_chans[ss->ss_nallchans++] = c;
        }

    }

    /* Iterate again adding half-rate and quarter-rate channels */
    for (i = 0; i < IEEE80211_N(scan_order); ++i) {

        if (scan_order[i] < IEEE80211_2GHZ_FREQUENCY_THRESHOLD)
            continue;

        c = NULL;
        c = ieee80211_find_channel(ic, scan_order[i], 0,
                                   (IEEE80211_CHAN_A | IEEE80211_CHAN_HALF));
        if (c != NULL) {
            ss->ss_all_chans[ss->ss_nallchans++] = c;
        }

        c = NULL;
        c = ieee80211_find_channel(ic, scan_order[i], 0,
                                   (IEEE80211_CHAN_A | IEEE80211_CHAN_QUARTER));
        if (c != NULL) {
            ss->ss_all_chans[ss->ss_nallchans++] = c;
        }
    }

    /*
     * The scanner still needs work to support the block below.
     * It modifies the channel list, so a Blue Screen is likely to follow
     * if this is done while a scan is active.
     *
     * There may be other messages currently queued, so SCANNER_EVENT_RESTART_REQUEST
     * may not be the next message processed.
     *
     * A more complex scenario arises when SCANNER_EVENT_RESTART_REQUEST is received
     * while the scanner is trying to suspend traffic.
     *
     * For now, just let an ongoing scan complete. The channel list will be rebuilt
     * when the next scan is requested.
     */

    spin_unlock(&ss->ss_lock);

    return EOK;
}

static int _ieee80211_scan_channel_list_length(ieee80211_scanner_t ss)
{
    return ss->ss_nallchans;
}

static int _ieee80211_scan_scanentry_received(ieee80211_scanner_t ss, bool bssid_match)
{
    switch (ieee80211_sm_get_curstate(ss->ss_hsm_handle)) {
    /* Increment beacon count only if beacon came from our home AP */
    case SCANNER_STATE_BSS_CHANNEL:
        if (bssid_match) {
            ss->ss_beacons_received++;
        }
        break;

    case SCANNER_STATE_RADIO_MEASUREMENT:
        if (bssid_match && is_radio_measurement_in_home_channel(ss)) {
            ss->ss_beacons_received++;
        }
        break;

    /* Check if we were monitoring a passive channel */
    case SCANNER_STATE_FOREIGN_CHANNEL:
    case SCANNER_STATE_REPEATER_CHANNEL:
        if (atomic_read(&(ss->ss_wait_for_beacon))) {
            /*
             * Should NOT be monitoring beacons if performing passive scan.
             */
            ASSERT(! (ss->ss_flags & IEEE80211_SCAN_PASSIVE));

            /*
             * Clear flag indicating beacons must be indicated to the state
             * machine. Reception of a single beacon is enough to determine
             * the scanner can transmit probe requests on the channel.
             */
            if (OS_ATOMIC_CMPXCHG(&ss->ss_beacon_event_queued, false, true) == false) {
                ieee80211_sm_dispatch(ss->ss_hsm_handle,
                                      SCANNER_EVENT_RECEIVED_BEACON,
                                      0,
                                      NULL);
            }
        }
        break;

    default:
        /* Beacons received in other states are ignored */
        break;
    }

    return EOK;
}

ieee80211_state_info ieee80211_scan_sm_info[] = {
    {
        (u_int8_t) SCANNER_STATE_IDLE,
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        false,
        "IDLE",
        scanner_state_idle_entry,
        NULL,
        scanner_state_idle_event
    },
    {
        (u_int8_t) SCANNER_STATE_SUSPENDING_TRAFFIC,
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        false,
        "SUSPENDING_TRAFFIC",
        scanner_state_suspending_traffic_entry,
        NULL,
        scanner_state_suspending_traffic_event
    },
    {
        (u_int8_t) SCANNER_STATE_FOREIGN_CHANNEL,
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        false,
        "FOREIGN_CHANNEL",
        scanner_state_foreign_channel_entry,
        scanner_state_foreign_channel_exit,
        scanner_state_foreign_channel_event
    },
    {
        (u_int8_t) SCANNER_STATE_RESUMING_TRAFFIC,
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        false,
        "RESUMING_TRAFFIC",
        NULL,
        NULL,
        scanner_state_resuming_traffic_event
    },
    {
        (u_int8_t) SCANNER_STATE_BSS_CHANNEL,
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        false,
        "BSS_CHANNEL",
        scanner_state_bss_channel_entry,
        NULL,
        scanner_state_bss_channel_event
    },
    {
        (u_int8_t) SCANNER_STATE_RADIO_MEASUREMENT,
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        false,
        "RADIO_MEASUREMENT",
        scanner_state_radio_measurement_entry,
        NULL,
        scanner_state_radio_measurement_event
    },
    {
        (u_int8_t) SCANNER_STATE_REPEATER_CHANNEL,
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        false,
        "REPEATER_CHANNEL",
        scanner_state_repeater_channel_entry,
        NULL,
        scanner_state_repeater_channel_event
    },
    {
        (u_int8_t) SCANNER_STATE_TERMINATING,
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        (u_int8_t) IEEE80211_HSM_STATE_NONE,
        false,
        "TERMINATING",
        scanner_state_terminating_entry,
        NULL,
        scanner_state_terminating_event
    },
};


/*
 * This function called after all IC objects are already initialized.
 * Resource Manager and Scanner need this so they can register callback
 * functions with each other.
 */
static void _ieee80211_scan_attach_complete(ieee80211_scanner_t ss)
{
    ss->ss_resmgr = ss->ss_ic->ic_resmgr;

    if (ieee80211_resmgr_register_notification_handler(ss->ss_resmgr,
                                                       ieee80211_scan_handle_resmgr_events,
                                                       ss) != EOK) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: Failed to register with resmgr \n", __func__);
    }
}

static int _ieee80211_scan_detach(ieee80211_scanner_t *ss)
{
    int    status;
    int    i;

    if (*ss == NULL) {
        return EINPROGRESS; /* already detached ? */
    }

    /*
     * Terminate scan scheduler
     */
    status = ieee80211_scan_scheduler_detach(&((*ss)->ss_scheduler));

    /*
     * Verify that all event handlers have been unregistered.
     */
    if ((*ss)->ss_num_handlers > 0) {
        IEEE80211_SCAN_PRINTF((*ss), IEEE80211_MSG_ANY, "%s: Event handler table not empty: %d entries\n",
                              __func__,
                              (*ss)->ss_num_handlers);

        spin_lock(&(*ss)->ss_lock);
        for (i = 0; i < IEEE80211_MAX_SCAN_EVENT_HANDLERS; ++i) {
            if ((*ss)->ss_event_handlers[i] != NULL) {
                IEEE80211_SCAN_PRINTF((*ss), IEEE80211_MSG_ANY, "%s: evhandler=%08p arg=%08p not unregistered\n",
                                      __func__,
                                      (*ss)->ss_event_handlers[i],
                                      (*ss)->ss_event_handler_arg[i]);
            }
        }
        spin_unlock(&(*ss)->ss_lock);
    }
    ASSERT((*ss)->ss_num_handlers == 0);

    if ((*ss)->ss_hsm_handle) {
        ieee80211_sm_delete((*ss)->ss_hsm_handle);
    }

    if ((*ss)->ss_iedata) {
        OS_FREE((*ss)->ss_iedata);
    }

    /*
     * Free timer objects
     */
    OS_FREE_TIMER(&((*ss)->ss_timer));
    OS_FREE_TIMER(&((*ss)->ss_maxscan_timer));

    /*
     * Free synchronization objects
     */
    spin_lock_destroy(&((*ss)->ss_lock));

    OS_FREE(*ss);

    *ss = NULL;

    return EOK;
}

/*
 * This function called before IC objects are deleted.
 * Resource Manager and Scanner need this so they can unregister callback
 * functions from each other.
 */
static void _ieee80211_scan_detach_prepare(ieee80211_scanner_t ss)
{
    if (ieee80211_resmgr_active(ss->ss_ic)) {
        if (ieee80211_resmgr_unregister_notification_handler(ss->ss_resmgr,
                                                             ieee80211_scan_handle_resmgr_events,
                                                             ss) != EOK) {
            IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: Failed to unregister from resmgr\n", __func__);
        }
    }
}

static void _ieee80211_scan_connection_lost(ieee80211_scanner_t ss)
{
    if (ss->ss_type == IEEE80211_SCAN_BACKGROUND) {
        if (ss->ss_common.ss_info.si_scan_in_progress) {
            u_int32_t    now = (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());

            IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%d.%03d | %s: Connection lost; converting to foreground scan\n",
                now / 1000, now % 1000, __func__);
        }

        ss->ss_type = IEEE80211_SCAN_FOREGROUND;

        /*
         * We may still need to visit the home channel if there are other ports active.
         */
        ss->ss_visit_home_channel = ss->ss_multiple_ports_active;
    }
}

/*
 * Verify presence of active VAPs besides the one requesting the scan.
 */
bool
ieee80211_count_active_ports(struct ieee80211com    *ic,
                             struct ieee80211vap    *vap)
{
    struct ieee80211_vap_opmode_count    vap_opmode_count;

    OS_MEMZERO(&(vap_opmode_count), sizeof(vap_opmode_count));

    /*
     * Get total number of VAPs of each type supported by the IC.
     */
    wlan_get_vap_opmode_count(ic, &vap_opmode_count);

    /*
     * Subtract the current VAP since its connection state is already checked
     * by a callback function specified in the scan request.
     */
    switch(ieee80211vap_get_opmode(vap)) {
    case IEEE80211_M_IBSS:
        vap_opmode_count.ibss_count--;
        break;

    case IEEE80211_M_STA:
        vap_opmode_count.sta_count--;
        break;

    case IEEE80211_M_WDS:
        vap_opmode_count.wds_count--;
        break;

    case IEEE80211_M_AHDEMO:
        vap_opmode_count.ahdemo_count--;
        break;

    case IEEE80211_M_HOSTAP:
        vap_opmode_count.ap_count--;
        break;

    case IEEE80211_M_MONITOR:
        vap_opmode_count.monitor_count--;
        break;

    case IEEE80211_M_BTAMP:
        vap_opmode_count.btamp_count--;
        break;

    default:
        vap_opmode_count.unknown_count--;
        break;
    }

    if ((vap_opmode_count.ibss_count > 0) ||
        (vap_opmode_count.sta_count > 0)  ||
        (vap_opmode_count.ap_count > 0)   ||
        (vap_opmode_count.btamp_count > 0)) {
        return true;
    }
    else {
        return false;
    }
}

/*
 * Function to populate a structure with the default scan parameters.
 * This function really needs the VAP as input argument, not the scanner.
 *
 * The scanner is not yet initialized because this function is normally
 * called *before* wlan_scan_start, and ss->ss_vap is NULL.
 */
static void _ieee80211_scan_set_default_scan_parameters(ieee80211_scanner_t ss,
                                           struct ieee80211vap   *vap,
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
/* All times in milliseconds */
#define HW_DEFAULT_SCAN_MIN_BEACON_COUNT_INFRA                           1
#define HW_DEFAULT_SCAN_MIN_BEACON_COUNT_IBSS                            3
#define HW_DEFAULT_SCAN_MIN_DWELL_TIME_ACTIVE                          105
#define HW_DEFAULT_SCAN_MIN_DWELL_TIME_PASSIVE                         115
#define HW_DEFAULT_SCAN_MAX_DWELL_TIME                                 500
#define HW_DEFAULT_SCAN_MIN_REST_TIME_INFRA                             50
#define HW_DEFAULT_SCAN_MIN_REST_TIME_IBSS                             250
#define HW_DEFAULT_SCAN_MAX_REST_TIME                                  500
#define HW_DEFAULT_SCAN_MAX_OFFCHANNEL_TIME                              0
#define HW_DEFAULT_REPEAT_PROBE_REQUEST_INTVAL                          50
#define HW_DEFAULT_SCAN_NETWORK_IDLE_TIMEOUT                           200
#define HW_DEFAULT_SCAN_BEACON_TIMEOUT                                1600  /* > (IEEE80211_BMISS_LIMIT * 100) Let BMISS always happened in home channel. */
#define HW_DEFAULT_SCAN_MAX_DURATION                                 50000
#define HW_DEFAULT_SCAN_MAX_START_DELAY                               5000
#define HW_DEFAULT_SCAN_FAKESLEEP_TIMEOUT                             1000
#define HW_DEFAULT_SCAN_PROBE_DELAY                                      0
#define HW_DEFAULT_OFFCHAN_RETRY_DELAY                                 100
#define HW_DEFAULT_MAX_OFFCHAN_RETRIES                                   3
#define HW_NOT_CONNECTED_DWELL_TIME_FACTOR                               2

    struct ieee80211_aplist_config    *pconfig = ieee80211_vap_get_aplist_config(vap);
    int                               i;
    u_int8_t                          *bssid;

    OS_MEMZERO(scan_params, sizeof(*scan_params));
    scan_params->min_dwell_time_active  = active_scan_flag ? HW_DEFAULT_SCAN_MIN_DWELL_TIME_ACTIVE : HW_DEFAULT_SCAN_MIN_DWELL_TIME_PASSIVE;
    scan_params->max_dwell_time_active  = HW_DEFAULT_SCAN_MAX_DWELL_TIME;
    scan_params->min_dwell_time_passive = HW_DEFAULT_SCAN_MIN_DWELL_TIME_PASSIVE;
    scan_params->max_dwell_time_passive = HW_DEFAULT_SCAN_MAX_DWELL_TIME;
    scan_params->max_rest_time          = high_priority_flag ?
        HW_DEFAULT_SCAN_MAX_REST_TIME : 0;
    scan_params->idle_time              = HW_DEFAULT_SCAN_NETWORK_IDLE_TIMEOUT;
    scan_params->repeat_probe_time      = HW_DEFAULT_REPEAT_PROBE_REQUEST_INTVAL;
    scan_params->offchan_retry_delay    = HW_DEFAULT_OFFCHAN_RETRY_DELAY;
    scan_params->max_offchannel_time    = HW_DEFAULT_SCAN_MAX_OFFCHANNEL_TIME;

    if (opmode == IEEE80211_M_IBSS) {
        scan_params->min_rest_time    = HW_DEFAULT_SCAN_MIN_REST_TIME_IBSS;
        scan_params->min_beacon_count = (peer_count > 0) ?
            HW_DEFAULT_SCAN_MIN_BEACON_COUNT_IBSS : 0;
        scan_params->type             = (peer_count > 0) ? IEEE80211_SCAN_BACKGROUND : IEEE80211_SCAN_FOREGROUND;
    }
    else {
        scan_params->min_rest_time    = HW_DEFAULT_SCAN_MIN_REST_TIME_INFRA;
        scan_params->min_beacon_count = connected_flag ? HW_DEFAULT_SCAN_MIN_BEACON_COUNT_INFRA : 0;
        scan_params->type             = connected_flag ? IEEE80211_SCAN_BACKGROUND : IEEE80211_SCAN_FOREGROUND;
    }

    scan_params->max_offchan_retries        = HW_DEFAULT_MAX_OFFCHAN_RETRIES;
    scan_params->beacon_timeout             = HW_DEFAULT_SCAN_BEACON_TIMEOUT;
    scan_params->max_scan_time              = HW_DEFAULT_SCAN_MAX_DURATION;
    scan_params->probe_delay                = HW_DEFAULT_SCAN_PROBE_DELAY;
    scan_params->flags                      = (active_scan_flag   ? IEEE80211_SCAN_ACTIVE : IEEE80211_SCAN_PASSIVE) |
                                              (high_priority_flag ? IEEE80211_SCAN_FORCED : 0)                      |
                                              (external_scan_flag ? IEEE80211_SCAN_EXTERNAL : 0)                    |
                                              IEEE80211_SCAN_ALLBANDS;
    scan_params->num_channels               = 0;
    scan_params->chan_list                  = NULL;
    scan_params->num_ssid                   = 0;
    scan_params->ie_len                     = 0;
    scan_params->ie_data                    = NULL;
    scan_params->check_termination_function = NULL;
    scan_params->check_termination_context  = NULL;
    scan_params->restricted_scan            = false;
    scan_params->multiple_ports_active      = ieee80211_count_active_ports(vap->iv_ic, vap);

    /*
     * Validate time before sending second probe request. A value of 0 is valid
     * and means a single probe request must be transmitted.
     */
    ASSERT(scan_params->repeat_probe_time < scan_params->min_dwell_time_active);

    /* Double the dwell time if not connected */
    if (! connected_flag)
    {
        scan_params->min_dwell_time_active *= HW_NOT_CONNECTED_DWELL_TIME_FACTOR;
    }

    /*
     * SSID list must be received as an argument instead of retrieved from
     * the configuration parameters
     */
    scan_params->num_ssid = num_ssid;
    if (scan_params->num_ssid > IEEE80211_N(scan_params->ssid_list)) {
        scan_params->num_ssid = IEEE80211_N(scan_params->ssid_list);
    }
    for (i = 0; i < scan_params->num_ssid; i++) {
        scan_params->ssid_list[i] = ssid_list[i];

        /* Validate SSID length */
        if (scan_params->ssid_list[i].len > sizeof(scan_params->ssid_list[i].ssid)) {
            scan_params->ssid_list[i].len = 0;
        }
    }

    scan_params->num_bssid = ieee80211_aplist_get_desired_bssid_count(pconfig);
    if (scan_params->num_bssid > IEEE80211_N(scan_params->bssid_list)) {
        scan_params->num_bssid = IEEE80211_N(scan_params->bssid_list);
    }

    for (i = 0; i < scan_params->num_bssid; i++) {
        ieee80211_aplist_get_desired_bssid(pconfig, i, &bssid);
        OS_MEMCPY(scan_params->bssid_list[i],
            bssid,
            IEEE80211_N(scan_params->bssid_list[i]));
    }
}

static int _ieee80211_scan_get_requestor_id(ieee80211_scanner_t ss, u_int8_t *module_name, IEEE80211_SCAN_REQUESTOR *requestor)
{
    int    i, j;

    if (!module_name) {
        IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: missing module name\n",
            __func__);

        return EINVAL;
    }

    /*
     * Examine each enty in the requestor table looking for an unused ID.
     */
    for (i = 0; i < IEEE80211_MAX_REQUESTORS; ++i) {
        if (ss->ss_requestors[i].requestor == 0) {
            ss->ss_requestors[i].requestor = IEEE80211_REQ_ID_PREFIX | i;

            /*
             * Copy the module name into the requestors table.
             */
            j = 0;
            while (module_name[j] && (j < (IEEE80211_SCAN_REQUESTOR_MAX_MODULE_NAME - 1))) {
                ss->ss_requestors[i].module_name[j] = module_name[j];
                ++j;
            }
            ss->ss_requestors[i].module_name[j] = 0;

            /*
             * Return the requestor ID.
             */
            *requestor = ss->ss_requestors[i].requestor;

            IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: module=%s requestor=%X\n",
                __func__,
                module_name,
                ss->ss_requestors[i].requestor);

            return EOK;
        }
    }

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: No IDs left module=%s\n",
        __func__, module_name);

    /*
     * Could not find an unused ID.
     */
    return ENOMEM;
}

static void _ieee80211_scan_clear_requestor_id(ieee80211_scanner_t ss, IEEE80211_SCAN_REQUESTOR requestor)
{
    int    index = requestor & ~IEEE80211_REQ_ID_PREFIX;

    IEEE80211_SCAN_PRINTF(ss, IEEE80211_MSG_SCAN, "%s: requestor=%X\n",
        __func__,
        requestor);

    /* Clear fields */
    ss->ss_requestors[index].requestor      = 0;
    ss->ss_requestors[index].module_name[0] = 0;
}


u_int8_t unknown[]="unknown";
static u_int8_t *_ieee80211_scan_get_requestor_name(ieee80211_scanner_t ss, IEEE80211_SCAN_REQUESTOR requestor)
{
    int    i;

    /*
     * Use requestor to index table directly
     */
    i = (requestor & ~IEEE80211_REQ_ID_PREFIX);
    if ((i < IEEE80211_MAX_REQUESTORS) && (ss->ss_requestors[i].requestor == requestor)) {
        return ss->ss_requestors[i].module_name;
    } else {
        return unknown;
    }
}

int ieee80211_scan_get_preemption_data(ieee80211_scanner_t       ss,
                                       IEEE80211_SCAN_REQUESTOR  requestor,
                                       IEEE80211_SCAN_ID         scan_id,
                                       scanner_preemption_data_t *preemption_data)
{
    preemption_data->preempted  = ss->ss_preemption_data.preempted;
    preemption_data->nreqchans  = ss->ss_preemption_data.nreqchans;
    preemption_data->nchans     = ss->ss_preemption_data.nchans;
    preemption_data->nallchans  = ss->ss_preemption_data.nallchans;
    preemption_data->next       = ss->ss_preemption_data.next;

    /* Repeat channel being currently scanner upon resumption */
    if (ss->ss_preemption_data.next > 0) {
        ss->ss_preemption_data.next--;
    }

    return EOK;
}


static int _ieee80211_scan_start(ieee80211_scanner_t       ss, wlan_if_t                vaphandle,
                    ieee80211_scan_params    *params,
                    IEEE80211_SCAN_REQUESTOR requestor,
                    IEEE80211_SCAN_PRIORITY  priority,
                    IEEE80211_SCAN_ID        *scan_id)
{
#if ATH_SUPPORT_MULTIPLE_SCANS
    return ieee80211_scan_scheduler_add(vaphandle->iv_ic->ic_scanner->ss_scheduler,
                                        vaphandle,
                                        params,
                                        requestor,
                                        priority,
                                        scan_id);
#else
    scan_request_data_t    request_data;

    /* Scan_id always 0 if multiple scan support is not enabled */
    ASSERT(scan_id != NULL);
    *scan_id = 0;

    /* Clear request data. */
    OS_MEMZERO(&request_data, sizeof(request_data));

    request_data.requestor                 = requestor;
    request_data.priority                  = priority;
    request_data.scan_id                   = *scan_id;
    request_data.request_timestamp         = OS_GET_TIMESTAMP();
    request_data.params                    = params;
    request_data.preemption_data.preempted = false;

    return ieee80211_scan_run(vaphandle->iv_ic->ic_scanner,
                              vaphandle,
                              &request_data);

#endif    /* ATH_SUPPORT_MULTIPLE_SCANS */
}

static int _ieee80211_scan_cancel(ieee80211_scanner_t       ss, wlan_if_t                vaphandle,
                     IEEE80211_SCAN_REQUESTOR requestor,
                     IEEE80211_SCAN_ID        scan_id_mask,
                     u_int32_t                flags)
{
#if ATH_SUPPORT_MULTIPLE_SCANS
    return ieee80211_scan_scheduler_remove(ss->ss_scheduler,
                                           vaphandle,
                                           requestor,
                                           scan_id_mask,
                                           flags);
#else
    /*
     * Multiple scans not supported.
     * Don't forget to extract the actual scan_id from the mask.
     * Function ieee80211_scan_stop will verify that the scan_id is 0, so
     * leaving higher bytes present in the mask causes the comparison to fail.
     */
    return ieee80211_scan_stop(ss,
                               requestor,
                               scan_id_mask & ~IEEE80211_SCAN_CLASS_MASK,
                               STOP_MODE_CANCEL,
                               flags);
#endif    /* ATH_SUPPORT_MULTIPLE_SCANS */
}


static int _ieee80211_scan_set_priority(ieee80211_scanner_t       ss,
                           IEEE80211_SCAN_REQUESTOR requestor,
                           IEEE80211_SCAN_ID        scan_id_mask,
                           IEEE80211_SCAN_PRIORITY  scanPriority)
{
    return ieee80211_scan_scheduler_set_priority(ieee80211_scan_scheduler_object(ss),
                                                 vaphandle,
                                                 requestor,
                                                 scan_id_mask,
                                                 scanPriority);
}

static int _ieee80211_scan_set_forced_flag(ieee80211_scanner_t       ss,
                              IEEE80211_SCAN_REQUESTOR requestor,
                              IEEE80211_SCAN_ID        scan_id_mask,
                              bool                     forced_flag)
{
    return ieee80211_scan_scheduler_set_forced_flag(ieee80211_scan_scheduler_object(ss),
                                                    vaphandle,
                                                    requestor,
                                                    scan_id_mask,
                                                    forced_flag);
}


static int
_ieee80211_scan_get_priority_table(ieee80211_scanner_t       ss,
                             enum ieee80211_opmode      opmode,
                             int                        *p_number_rows,
                             IEEE80211_PRIORITY_MAPPING **p_mapping_table)
{
    /*
     * Typecast parameter devhandle to ic.
     * Defining a variable causes compilation errors (unreferenced variable)
     * in some platforms.
     */
    return ieee80211_scan_scheduler_get_priority_table( ss->ss_scheduler,
        opmode,
        p_number_rows,
        p_mapping_table);
}

static int
_ieee80211_scan_set_priority_table(ieee80211_scanner_t       ss,
                             enum ieee80211_opmode      opmode,
                             int                        number_rows,
                             IEEE80211_PRIORITY_MAPPING *p_mapping_table)
{
    /*
     * Typecast parameter devhandle to ic.
     * Defining a variable causes compilation errors (unreferenced variable)
     * in some platforms.
     */
    return ieee80211_scan_scheduler_set_priority_table( ss->ss_scheduler,
        opmode,
        number_rows,
        p_mapping_table);
}

static int _ieee80211_scan_scheduler_get_requests(ieee80211_scanner_t       ss,
                                     ieee80211_scan_request_info *scan_request_info,
                                     int                         *total_requests,
                                     int                         *returned_requests)
{
    return ieee80211_scan_scheduler_get_requests(ss->ss_scheduler,
                                                 scan_request_info,
                                                 total_requests,
                                                 returned_requests);
}

static int _ieee80211_scan_enable_scan_scheduler(ieee80211_scanner_t       ss,
                               IEEE80211_SCAN_REQUESTOR requestor)
{
    /*
     * Typecast parameter devhandle to ic.
     * Defining a variable causes compilation errors (unreferenced variable)
     * in some platforms.
     */
    return ieee80211_enable_scan_scheduler( ss->ss_scheduler,
        requestor);
}

static int _ieee80211_scan_disable_scan_scheduler(ieee80211_scanner_t       ss,
                                IEEE80211_SCAN_REQUESTOR requestor,
                                u_int32_t                max_suspend_time)
{
    /*
     * Typecast parameter devhandle to ic.
     * Defining a variable causes compilation errors (unreferenced variable)
     * in some platforms.
     */
    return ieee80211_disable_scan_scheduler( ss->ss_scheduler,
        requestor,
        max_suspend_time);
}

#if !ATH_SUPPORT_MULTIPLE_SCANS && defined USE_WORKQUEUE_FOR_MESGQ_AND_SCAN
void scan_timer_defered(void *timer_arg)
{
    ieee80211_scanner_t      ss;

    OS_GET_TIMER_ARG(ss, ieee80211_scanner_t);

    ieee80211_sm_dispatch(ss->ss_hsm_handle,
                          ss->ss_pending_event,
                          0,
                          NULL);

    /* Clear pending event */
    ss->ss_pending_event = SCANNER_EVENT_NONE;
}

void scan_max_timer_defered(void *timer_arg)
{
    ieee80211_scanner_t      ss;

    OS_GET_TIMER_ARG(ss, ieee80211_scanner_t);

    ieee80211_sm_dispatch(ss->ss_hsm_handle,
                          SCANNER_EVENT_MAXSCANTIME_EXPIRE,
                          0,
                          NULL);
}
#endif

int _ieee80211_scan_attach(ieee80211_scanner_t        *ss,
                          wlan_dev_t                 devhandle,
                          osdev_t                    osdev,
                          bool (*is_connected)       (wlan_if_t),
                          bool (*is_txq_empty)       (wlan_dev_t),
                          bool (*is_sw_txq_empty)    (wlan_dev_t))
{
    int    status;

    if (*ss) {
        return EINPROGRESS; /* already attached ? */
    }

    *ss = (ieee80211_scanner_t) OS_MALLOC(osdev, sizeof(struct ieee80211_scanner), 0);
    if (*ss) {
        OS_MEMZERO(*ss, sizeof(struct ieee80211_scanner));

        /*
         * Save handles to required objects.
         * Resource manager may not be initialized at this time.
         */
        (*ss)->ss_ic     = devhandle;
        (*ss)->ss_osdev  = osdev;
        (*ss)->ss_resmgr = NULL;

        /*
         * TO-DO: For now treat both the si_allow_transmit and si_in_home_channel flags as the same.
         *        and als do not use atomic operation on these
         *        flags until understand VISTA scanner implementation.
         */

        (*ss)->ss_common.ss_info.si_allow_transmit     = true;
        (*ss)->ss_common.ss_info.si_in_home_channel    = true;
        (*ss)->ss_common.ss_info.si_last_term_status   = false;

        (*ss)->ss_hsm_handle = ieee80211_sm_create(osdev,
                                                   "scan",
                                                   (void *) (*ss),
                                                   SCANNER_STATE_IDLE,
                                                   ieee80211_scan_sm_info,
                                                   sizeof(ieee80211_scan_sm_info) / sizeof(ieee80211_state_info),
                                                   MAX_QUEUED_EVENTS,
                                                   sizeof(struct ieee80211_scan_event_data),
                                                   MESGQ_PRIORITY_LOW,
                                                   IEEE80211_HSM_ASYNCHRONOUS, /* run the SM asynchronously */
                                                   ieee80211_scan_sm_debug_print,
                                                   scanner_event_name,
                                                   IEEE80211_N(scanner_event_name));
        if (! (*ss)->ss_hsm_handle) {
            OS_FREE((*ss));
            qdf_print("%s: ieee80211_sm_create failed\n", __func__);
            return ENOMEM;
        }
        /* initialize the function pointer table */
        (*ss)->ss_common.scan_attach_complete = _ieee80211_scan_attach_complete;
        (*ss)->ss_common.scan_detach = _ieee80211_scan_detach;
        (*ss)->ss_common.scan_detach_prepare = _ieee80211_scan_detach_prepare;
        (*ss)->ss_common.scan_start = _ieee80211_scan_start;
        (*ss)->ss_common.scan_cancel = _ieee80211_scan_cancel;
        (*ss)->ss_common.scan_register_event_handler = _ieee80211_scan_register_event_handler;
        (*ss)->ss_common.scan_unregister_event_handler = _ieee80211_scan_unregister_event_handler;
        (*ss)->ss_common.scan_get_last_scan_info = _ieee80211_scan_get_last_scan_info;
        (*ss)->ss_common.scan_channel_list_length = _ieee80211_scan_channel_list_length;
        (*ss)->ss_common.scan_update_channel_list = _ieee80211_scan_update_channel_list;
        (*ss)->ss_common.scan_scanentry_received = _ieee80211_scan_scanentry_received;
        (*ss)->ss_common.scan_get_last_scan_time = _ieee80211_scan_get_last_scan_time;
        (*ss)->ss_common.scan_get_last_full_scan_time = _ieee80211_scan_get_last_full_scan_time;
        (*ss)->ss_common.scan_connection_lost = _ieee80211_scan_connection_lost;
        (*ss)->ss_common.scan_set_default_scan_parameters = _ieee80211_scan_set_default_scan_parameters;
        (*ss)->ss_common.scan_get_requestor_id = _ieee80211_scan_get_requestor_id;
        (*ss)->ss_common.scan_clear_requestor_id = _ieee80211_scan_clear_requestor_id;
        (*ss)->ss_common.scan_get_requestor_name = _ieee80211_scan_get_requestor_name;
        (*ss)->ss_common.scan_set_priority = _ieee80211_scan_set_priority;
        (*ss)->ss_common.scan_set_forced_flag = _ieee80211_scan_set_forced_flag;
        (*ss)->ss_common.scan_get_priority_table = _ieee80211_scan_get_priority_table;
        (*ss)->ss_common.scan_set_priority_table = _ieee80211_scan_set_priority_table;
        (*ss)->ss_common.scan_enable_scan_scheduler = _ieee80211_scan_enable_scan_scheduler;
        (*ss)->ss_common.scan_disable_scan_scheduler = _ieee80211_scan_disable_scan_scheduler;
        (*ss)->ss_common.scan_scheduler_get_requests = _ieee80211_scan_scheduler_get_requests;

        /*
         * initilize 2 timers.
         * first timer to run the scanner state machine.
         * the second one not to let scanner go beyond max scanner time specified
         */
        OS_INIT_TIMER(osdev, &((*ss)->ss_timer), scanner_timer_handler, (void *) (*ss), QDF_TIMER_TYPE_WAKE_APPS);
        OS_INIT_TIMER(osdev, &((*ss)->ss_maxscan_timer), scanner_timer_maxtime_handler, (void *) (*ss), QDF_TIMER_TYPE_WAKE_APPS);

#if !ATH_SUPPORT_MULTIPLE_SCANS && defined USE_WORKQUEUE_FOR_MESGQ_AND_SCAN
        qdf_create_work(osdev, &((*ss)->ss_timer_defered), scan_timer_defered, (void *)(*ss));
        qdf_create_work(osdev, &((*ss)->ss_maxscan_timer_defered), scan_max_timer_defered, (void *)(*ss));
#endif

        spin_lock_init(&((*ss)->ss_lock));
        (*ss)->ss_is_txq_empty    = is_txq_empty;
        (*ss)->ss_is_sw_txq_empty = is_sw_txq_empty;
        (*ss)->ss_is_connected    = is_connected;
        (*ss)->ss_enter_channel_time = OS_GET_TIMESTAMP();

        ieee80211_scan_update_channel_list(*ss);

        /*
         * Initialize scan scheduler
         */
        status = ieee80211_scan_scheduler_attach(&((*ss)->ss_scheduler), *ss, devhandle, osdev);

        return status;
    }

    return ENOMEM;
}

void ieee80211_scan_class_attach(wlan_dev_t devhandle)
{
  devhandle->ic_scan_attach = _ieee80211_scan_attach;
}

void ieee80211_scan_reset_flags(struct ieee80211com *ic)
{
    ieee80211_scanner_t ss = ic->ic_scanner;

    ss->ss_common.ss_info.si_scan_in_progress = FALSE;
}
#endif
