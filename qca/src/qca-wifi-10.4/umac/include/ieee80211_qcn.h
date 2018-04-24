/*
 *
 * Copyright (c) 2017 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#if QCN_IE
#ifndef _UMAC_IEEE80211_QCN__
#define _UMAC_IEEE80211_QCN__

#include <ieee80211_var.h>
#include <ieee80211_node.h>

typedef enum {
    QCN_TRANSITION_REJECTION_UNSPECIFIED,
    QCN_TRANSITION_REJECTION_FRAME_LOSS,
    QCN_TRANSITION_REJECTION_EXCESSIVE_DELAY,
    QCN_TRANSITION_REJECTION_INSUFFICIENT_QOS,
    QCN_TRANSITION_REJECTION_LOW_RSSI,
    QCN_TRANSITION_REJECTION_INTERFERENCE,
    QCN_TRANSITION_REJECTION_GRAY_ZONE,
    QCN_TRANSITION_REJECTION_SERVICE_UNAVAIL,

/*Reserved values form 8-255 */
    QCN_TRANSITION_REJECTION_MAX = 255
}qcn_transition_rej_code;


typedef enum {
    QCN_TRANSITION_REASON_UNSPECIFIED,
    QCN_TRANSITION_REASON_FRAME_LOSS,
    QCN_TRANSITION_REASON_EXCESSIVE_DELAY,
    QCN_TRANSITION_REASON_INSUFFICIENT_BANDWIDTH,
    QCN_TRANSITION_REASON_LOAD_BALANCE,
    QCN_TRANSITION_REASON_LOW_RSSI,
    QCN_TRANSITION_REASON_RETRANSMISSION,
    QCN_TRANSITION_REASON_INTERFERENCE,
    QCN_TRANSITION_REASON_GRAY_ZONE,
    QCN_TRANSITION_REASON_PREMIUM_AP,

/*Reserved values form 10-255 */
    QCN_TRANSITION_REASON_MAX = 255
}qcn_transition_reason_code;

typedef enum {
    QCN_ATTRIB_VERSION              = 0x01,
    QCN_ATTRIB_TRANSITION_REASON    = 0x06,
    QCN_ATTRIB_TRANSITION_REJECTION = 0x07
}qcn_attribute_id;

#define QCN_VER_ATTR_VER              0x01
#define QCN_VER_ATTR_SUBVERSION       0x00


/*
 * @ieee80211_setup_qcn_ie_bstmreq_target() -  adds QCN  IE in BTM request packet
 * @vap:pointer to vap
 * @ie:location where we need to add ie
 * @bstm_reqinfo:points to structure for transition reason code passing
 * @macaddr:pointer to mac address of the node
 *
 * Return:pointer where next item should be populated
 */
u_int8_t* ieee80211_setup_qcn_ie_bstmreq_target(struct ieee80211vap *vap, u_int8_t *ie,
                                         struct ieee80211_bstm_reqinfo_target *bstm_reqinfo,u_int8_t *macaddr);

/*
 * @ieee80211_parse_qcnie() -  parse QCN  trans_reason sub-attribute
 * @frm:tracks location where to attach next sub-attribute
 * @wh:frame pointer
 * @ni:node pointer
 * @version: pointer for sending the version info to the caller

 * Return:0 on success , -1 on failure
 */
int ieee80211_parse_qcnie(u_int8_t *frm, const struct ieee80211_frame *wh,
                    struct ieee80211_node *ni,u_int8_t * data);


/*
 * @ieee80211_add_qcn_info_ie() - adds QCN IE
 * @ie:ie pointer
 * @vap :pointer to vap struct
 * @ie_len:pointer to length that will be returned
 * @bstm_reqinfo:pointer to bstm request struct

 * Return:New buffer pointer after the added IE
 */
u_int8_t *ieee80211_add_qcn_info_ie(u_int8_t *frm,
        struct ieee80211vap *vap, u_int16_t *ie_len,struct ieee80211_bstm_reqinfo_target *bstm_reqinfo);
#endif
#endif //QCN_IE
