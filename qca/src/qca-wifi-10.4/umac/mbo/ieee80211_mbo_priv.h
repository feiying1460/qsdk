/*
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 */

/*
 MBO  module
*/


#include <ieee80211_var.h>
#include <ieee80211_ioctl.h>  /* for ieee80211req_athdbg */

#define MBO_ATTRIB_NON_CHANNEL_LEN 3
#define MBO_SUBELM_NON_CHANNEL_LEN 7

/*
 * Structure for id(elem id or attribute id) and
 * len fields.Done to avoid redundancy due to
 * repeated usage of these two fields.
 */
struct ieee80211_mbo_header {
    u_int8_t ie;
    u_int8_t len;
}qdf_packed;

struct ieee80211_mbo_ie {
    struct ieee80211_mbo_header header;
    u_int8_t oui[3];
    u_int8_t oui_type;
    u_int8_t opt_ie[0];
}qdf_packed; /*packing is required */

struct ieee80211_assoc_disallow {
    struct ieee80211_mbo_header header;
    u_int8_t reason_code;
    u_int8_t opt_ie[0];
}qdf_packed;

struct ieee80211_cell_cap {
    struct ieee80211_mbo_header header;
    u_int8_t cell_conn;
    u_int8_t opt_ie[0];
}qdf_packed;

struct ieee80211_mbo_cap {
    struct ieee80211_mbo_header header;
    u_int8_t  reserved6:6;
    u_int8_t  cap_cellular:1;
    u_int8_t  cap_reserved1:1;
    u_int8_t  opt_ie[0];
}qdf_packed;

struct ieee80211_cell_data_conn_pref {
    struct ieee80211_mbo_header header;
    u_int8_t cell_pref;
    u_int8_t opt_ie[0];
}qdf_packed;

struct ieee80211_transit_reason_code {
    struct ieee80211_mbo_header header;
    u_int8_t reason_code;
    u_int8_t opt_ie[0];
}qdf_packed;

struct ieee80211_transit_reject_reason_code {
    struct ieee80211_mbo_header header;
    u_int8_t reason_code;
    u_int8_t opt_ie[0];
}qdf_packed;

struct ieee80211_assoc_retry_delay {
    struct ieee80211_mbo_header header;
    u_int16_t re_auth_delay;
    u_int8_t opt_ie[0];
}qdf_packed;

struct ieee80211_mbo {
    osdev_t        mbo_osdev;
    wlan_dev_t     mbo_ic;
    u_int8_t       usr_assoc_disallow;
    u_int8_t       usr_mbocap_cellular_capable;
    u_int8_t       usr_cell_pref;
    u_int8_t       usr_trans_reason;
    u_int16_t      usr_assoc_retry;
};

#define OCE_CAP_RELEASE_MASK             0x07
#define OCE_CAP_RELEASE_SHIFT            0
#define OCE_CAP_NON_OCE_AP_MASK          0x08
#define OCE_CAP_NON_OCE_AP_SHIFT         3
#define OCE_WAN_METRICS_DL_MASK          0x0F
#define OCE_WAN_METRICS_DL_SHIFT         0
#define OCE_WAN_METRICS_UL_MASK          0xF0
#define OCE_WAN_METRICS_UL_SHIFT         4

#define OCE_CAP_REL_DEFAULT              1
#define OCE_ASSOC_MIN_RSSI_DEFAULT       21     /* -75 dBm */
#define OCE_ASSOC_RETRY_DELAY_DEFAULT    5
#define OCE_WAN_METRICS_CAP_DEFAULT      13     /* 819.2 Mbps */

struct ieee80211_oce_cap {
    struct ieee80211_mbo_header header;
    u_int8_t  ctrl_field;
} qdf_packed;

struct ieee80211_oce_assoc_reject {
    struct ieee80211_mbo_header header;
    u_int8_t  delta_rssi;
    u_int8_t  retry_delay;
} qdf_packed;

struct ieee80211_oce_wan_metrics {
    struct ieee80211_mbo_header header;
    u_int8_t  avail_cap;
} qdf_packed;

struct ieee80211_oce {
    osdev_t        oce_osdev;
    wlan_dev_t     oce_ic;
    u_int8_t       usr_assoc_reject;
    u_int8_t       usr_assoc_min_rssi;
    u_int8_t       usr_assoc_retry_delay;
    u_int8_t       usr_wan_metrics;
};

bool ieee80211_oce_is_vap_valid (struct ieee80211vap *vap);
u_int8_t ieee80211_setup_oce_attrs (int f_type, struct ieee80211vap *vap, u_int8_t *frm, struct ieee80211_node *ni);
