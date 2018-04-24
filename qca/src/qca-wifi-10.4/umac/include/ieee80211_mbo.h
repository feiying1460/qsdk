/*
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 */

#ifndef _UMAC_IEEE80211_MBO__
#define _UMAC_IEEE80211_MBO__

#include <ieee80211_var.h>
#include <ieee80211_node.h>

#define MBO_TRANSITION_REJECTION_UNSPECIFIED         0x00
#define MBO_TRANSITION_REJECTION_FRAME_LOSS          0x01
#define MBO_TRANSITION_REJECTION_EXCESSIVE_DELAY     0x02
#define MBO_TRANSITION_REJECTION_INSUFFICIENT_QOS    0x03
#define MBO_TRANSITION_REJECTION_LOW_RSSI            0x04
#define MBO_TRANSITION_REJECTION_INTERFERENCE        0x05
#define MBO_TRANSITION_REJECTION_GRAY_ZONE           0x06
#define MBO_TRANSITION_REJECTION_SERVICE_UNAVAIL     0x07
/*#define MBO_TRANSITION_REJECTION_8_255 reserved */

#define MBO_TRANSITION_REASON_UNSPECIFIED            0x00
#define MBO_TRANSITION_REASON_FRAME_LOSS             0x01
#define MBO_TRANSITION_REASON_EXCESSIVE_DELAY        0x02
#define MBO_TRANSITION_REASON_INSUFFICIENT_BANDWIDTH 0x03
#define MBO_TRANSITION_REASON_LOAD_BALANCE           0x04
#define MBO_TRANSITION_REASON_LOW_RSSI               0x05
#define MBO_TRANSITION_REASON_RETRANSMISSION         0x06
#define MBO_TRANSITION_REASON_INTERFERENCE           0x07
#define MBO_TRANSITION_REASON_GRAY_ZONE              0x08
#define MBO_TRANSITION_REASON_PREMIUM_AP             0x09
/*#define MBO_TRANSITION_REASON 10 to 255 reserved */

#define MBO_CELLULAR_PREFERENCE_EXCLUDED             0x00
#define MBO_CELLULAR_PREFERENCE_NOT_USE              0x01
#define MBO_CELLULAR_PREFERENCE_USE                  0xFF
/*#define MBO_CELLULAR_PREFERENCE 2 to 254 reserved */

#define MBO_ATTRIB_CAP_INDICATION          0x01
#define MBO_ATTRIB_NON_PREFERRED_CHANNEL   0x02
#define MBO_ATTRIB_CELLULAR                0x03
#define MBO_ATTRIB_ASSOCIATION_DISALLOWED  0x04
#define MBO_ATTRIB_CELLULAR_PREFERENCE     0x05
#define MBO_ATTRIB_TRANSITION_REASON       0x06
#define MBO_ATTRIB_TRANSITION_REJECTION    0x07
#define MBO_ATTRIB_ASSOC_RETRY_DELAY       0x08
/* 9 - 100 : Reserved for MBO */
#define OCE_ATTRIB_CAP_INDICATION          0x65  /* = 101 */
#define OCE_ATTRIB_RSSI_ASSOC_REJECT       0x66
#define OCE_ATTRIB_REDUCED_WAN_METRICS     0x67
/* 104 - 150 : Reserved for OCE */

#define MBO_CAP_AP_CELLULAR                0x40

#define OCE_CAP_RELEASE                    (0x01 << 0)
#define OCE_CAP_NON_OCE_AP_PRESENT         (0x01 << 3)
#define OCE_OOB_RATE_2G                    (5500)  /* kbps */

#define MBO_MBOCAP_INVALID                 0x8f
#define MBO_MBOCAP_ENABLE                  0x01
#define MBO_MBOCAP_DISABLE                 0x00
/*#define MBO_5_7_CAP_RESERVED               1 */

#define MBO_DISASSOC_REASON_RESERVED                0x00
#define MBO_DISASSOC_REASON_UNSPECIFIED             0x01
#define MBO_DISASSOC_REASON_MAX_CLIENT              0x02
#define MBO_DISASSOC_REASON_OVERLOAD                0x03
#define MBO_DISASSOC_REASON_AUTH_SERVER_OVERLOAD    0x04
#define MBO_DISASSOC_REASON_INSUFFICIENT_RSSI       0x05
/*#define MBO_DISASSOC_REASON_6_255_RESERVED */


/*opaque handle in vap structure */
typedef struct ieee80211_mbo    *ieee80211_mbo_t;
typedef struct ieee80211_oce    *ieee80211_oce_t;

// forward decls

/**
 * @brief Initialize the MBO infrastructure.
 *
 * @param [in] vap  to initialize
 *
 * @return EOK on success; EINPROGRESS if band steering is already initialized
 *         or ENOMEM on a memory allocation failure
 */

int ieee80211_mbo_vattach(struct ieee80211vap *vap);

/**
 * @brief deint the MBO infrastructure.
 *
 * @param [in] vap  to deint
 *
 * @return EOK on success;
 */

int ieee80211_mbo_vdetach(struct ieee80211vap *vap);

/**
 * @brief setup MBO ie in Beacon infrastructure.
 *
 * @param [in] Vap to intialize beacon.
 *
 * @return frame pointer;
 *
 */
u_int8_t* ieee80211_setup_mbo_ie(int f_type, struct ieee80211vap *vap, u_int8_t *ie, struct ieee80211_node *ni);

/**
 * To print mbo related values in the
 * mbo IEs of the BSTM req frame
 */
u_int8_t* ieee80211_setup_mbo_ie_bstmreq(struct ieee80211vap *vap, u_int8_t *ie,
                                         struct ieee80211_bstm_reqinfo *bstm_reqinfo,u_int8_t *macaddr);

u_int8_t* ieee80211_setup_mbo_ie_bstmreq_target(struct ieee80211vap *vap, u_int8_t *ie,
                                         struct ieee80211_bstm_reqinfo_target *bstm_reqinfo,u_int8_t *macaddr);

bool ieee80211_vap_mbo_check(struct ieee80211vap *vap);

bool ieee80211_vap_mbo_assoc_status(struct ieee80211vap *vap);
int
ieee80211_parse_mboie(u_int8_t *frm, struct ieee80211_node *ni);

int ieee80211_parse_wnm_mbo_subelem(u_int8_t *frm, struct ieee80211_node *ni);

/**
 * To use info of a node's supported operating
 * class ie to create non-preferred channel list ie
 */
int ieee80211_mbo_supp_op_cl_to_non_pref_chan_rpt(struct ieee80211_node *ni, u_int16_t countryCode);

int ieee80211_parse_op_class_ie(u_int8_t *frm, const struct ieee80211_frame *wh,
                                struct ieee80211_node *ni,
                                u_int16_t countryCode);
bool ieee80211_vap_oce_check (struct ieee80211vap *vap);
bool ieee80211_vap_oce_assoc_reject (struct ieee80211vap *vap, struct ieee80211_node *ni);
int ieee80211_oce_vattach (struct ieee80211vap *vap);
int ieee80211_oce_vdetach (struct ieee80211vap *vap);
int wlan_set_oce_param (wlan_if_t vap, u_int32_t param, u_int32_t val);
u_int32_t wlan_get_oce_param (wlan_if_t vap, u_int32_t param);
#endif
