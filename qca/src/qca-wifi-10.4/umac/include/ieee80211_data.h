/*
 *  Copyright (c) 2008 Atheros Communications Inc. 
 * All Rights Reserved.
 * 
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */

#ifndef _IEEE80211_DATA_H
#define _IEEE80211_DATA_H

#include <ieee80211_vap.h>


struct ieee80211_tx_status;

int ieee80211_send_wbuf(struct ieee80211vap *vap,struct ieee80211_node *ni, wbuf_t wbuf);
int ieee80211_input(struct ieee80211_node *ni, wbuf_t wbuf, struct ieee80211_rx_status *rs);
int ieee80211_input_all(struct ieee80211com *ic, wbuf_t wbuf, struct ieee80211_rx_status *rs);
#if UMAC_SUPPORT_OPMODE_APONLY
#define ieee80211_input_monitor(_ic, _wbuf, _rs)
#define ieee80211_input_sta(_ni, _wbuf, _rs)	1
#define ieee80211_input_ibss(_ni, _wbuf, _rs)	1
#define ieee80211_input_wds(_ni, _wbuf, _rs)	1
#define ieee80211_input_data_sta(_ni, _wbuf, _dir, _subtype)	1
#define ieee80211_input_data_ibss(_ni, _wbuf, _dir)				1
#define ieee80211_input_data_wds(_vap, _wbuf, _dir)				1
#else
int ieee80211_input_monitor(struct ieee80211com *ic, wbuf_t wbuf, struct ieee80211_rx_status *rs);
int ieee80211_input_sta(struct ieee80211_node *ni, wbuf_t wbuf,struct ieee80211_rx_status *rs);
int ieee80211_input_ibss(struct ieee80211_node *ni, wbuf_t wbuf,struct ieee80211_rx_status *rs);
int ieee80211_input_wds(struct ieee80211_node *ni, wbuf_t wbuf,struct ieee80211_rx_status *rs);
int ieee80211_input_data_sta(struct ieee80211_node *ni, wbuf_t wbuf, int dir, int subtype);
int ieee80211_input_data_ibss(struct ieee80211_node *ni, wbuf_t wbuf, int dir);
int ieee80211_input_data_wds(struct ieee80211vap *vap, wbuf_t wbuf, int dir);
#endif
#if ATH_SUPPORT_IWSPY
int ieee80211_input_iwspy_update_rssi(struct ieee80211com *ic, u_int8_t *address, int8_t rssi);
#endif
wbuf_t ieee80211_encap(struct ieee80211_node   *ni, wbuf_t   wbuf );
wbuf_t __ieee80211_encap(struct ieee80211_node   *ni, wbuf_t   wbuf );

/* external to the umac */
void ieee80211_complete_wbuf(wbuf_t wbuf, struct ieee80211_tx_status *ts);
/* internal to the umac */
void 
ieee80211_update_stats(struct ieee80211vap *vap, wbuf_t wbuf, struct ieee80211_frame *wh, int type, int subtype, struct ieee80211_tx_status *ts);
void ieee80211_release_wbuf(struct ieee80211_node *ni, wbuf_t wbuf, struct ieee80211_tx_status *ts);
void ieee80211_notify_queue_status(struct ieee80211com *ic, u_int16_t qdepth);
void ieee80211_timeout_fragments(struct ieee80211com *ic, u_int32_t lifetime);
bool ieee80211_is_txq_empty(struct ieee80211com *ic);
int  ieee80211_classify(struct ieee80211_node *ni, wbuf_t wbuf);
int  ieee80211_amsdu_input(struct ieee80211_node *ni, wbuf_t wbuf, struct ieee80211_rx_status *rs,
                      int is_mcast, u_int8_t subtype);

#ifdef ENCAP_OFFLOAD
#define ieee80211_encap( _ni , _wbuf)   (_wbuf)
#define ieee80211_encap_force( _ni , _wbuf)   __ieee80211_encap( _ni, _wbuf)
#else
#define ieee80211_encap( _ni , _wbuf)   __ieee80211_encap( _ni, _wbuf)
#endif

#ifdef ATH_SUPPORT_TxBF

#define IEEE80211_TX_COMPLETE_WITH_ERROR(_wbuf)   do {  \
    struct ieee80211_tx_status ts;                      \
    ts.ts_flags = IEEE80211_TX_ERROR;                   \
    ts.ts_retries = 0;                                  \
    ts.ts_txbfstatus = 0;                               \
    ieee80211_complete_wbuf(_wbuf, &ts);                \
} while (0)

#define IEEE80211_TX_COMPLETE_STATUS_OK(_wbuf)    do {  \
    struct ieee80211_tx_status ts;                      \
    ts.ts_flags = 0;                                    \
    ts.ts_retries = 0;                                  \
    ts.ts_txbfstatus = 0;                               \
    ieee80211_complete_wbuf(_wbuf, &ts);                \
} while (0)

#else

#define IEEE80211_TX_COMPLETE_WITH_ERROR(_wbuf)   do {  \
    struct ieee80211_tx_status ts;                      \
    ts.ts_flags = IEEE80211_TX_ERROR;                   \
    ts.ts_retries = 0;                                  \
    ieee80211_complete_wbuf(_wbuf, &ts);                \
} while (0)

#define IEEE80211_TX_COMPLETE_STATUS_OK(_wbuf)    do {  \
    struct ieee80211_tx_status ts;                      \
    ts.ts_flags = 0;                                    \
    ts.ts_retries = 0;                                  \
    ieee80211_complete_wbuf(_wbuf, &ts);                \
} while (0)

#endif

/*
 * call back to be registered to receive a wbuf completion
 * notification.
 */
typedef wlan_action_frame_complete_handler ieee80211_vap_complete_buf_handler;

/*
 * API to register callback to receive a wbuf completion
 * notification.
 */
int ieee80211_vap_set_complete_buf_handler(wbuf_t wbuf, ieee80211_vap_complete_buf_handler handler, 
                               void *arg1); 

typedef enum {
    IEEE80211_VAP_INPUT_EVENT_NONE=0,                    /* initializer */
    IEEE80211_VAP_INPUT_EVENT_UCAST=0x0001,              /* received unicast packet */
    IEEE80211_VAP_INPUT_EVENT_LAST_MCAST=0x0002,         /* received mcast frame with more bit not set  */
    IEEE80211_VAP_INPUT_EVENT_EOSP=0x0004,               /* received frame with EOSP bit set(UAPSD)  */
    IEEE80211_VAP_INPUT_EVENT_WNMSLEEP_RESP=0x0008,      /* received WNM-Sleep response frame */
    IEEE80211_VAP_OUTPUT_EVENT_DATA=0x0010,             /* need to xmit data */
    IEEE80211_VAP_OUTPUT_EVENT_COMPLETE_PS_NULL=0x0020, /* completed PS null frame */
    IEEE80211_VAP_OUTPUT_EVENT_COMPLETE_SMPS_ACT=0x0040,/* completed action mgmt frame */
    IEEE80211_VAP_OUTPUT_EVENT_COMPLETE_TX=0x0080,      /* completed a non PS null frame */
    IEEE80211_VAP_OUTPUT_EVENT_TXQ_EMPTY=0x0100,        /* txq is empty */
    IEEE80211_VAP_OUTPUT_EVENT_TX_ERROR=0x0200,         /* failed to transmit frame */
    IEEE80211_VAP_OUTPUT_EVENT_TX_SUCCESS=0x0400,       /* successfully tranmitted frame */
    IEEE80211_VAP_INPUT_EVENT_BEACON=0x0800,
} ieee80211_vap_txrx_event_type;

typedef struct _ieee80211_vap_txrx_event {
    ieee80211_vap_txrx_event_type         type;
    struct ieee80211_frame *wh;
    struct ieee80211_node    *ni;
    union {
        int status;
        u_int32_t more_data:1;
    } u;
} ieee80211_vap_txrx_event;

typedef void (*ieee80211_vap_txrx_event_handler) (ieee80211_vap_t, ieee80211_vap_txrx_event *event, void *arg);

/**
 * @register a vap txrx event handler.
 * ARGS :
 *  ieee80211_vap_txrx_event_handler : vap txrx vent handler
 *  arg                               : argument passed back via the evnt handler
 *  event_filter                      : bitmask of interested events 
 * RETURNS:
 *  on success returns 0.
 *  on failure returns a negative value.
 * allows more than one event handler to be registered.
 */
int ieee80211_vap_txrx_register_event_handler(ieee80211_vap_t,ieee80211_vap_txrx_event_handler evhandler, void *arg, u_int32_t event_filter);

/**
 * @unregister a vap txrx event handler.
 * ARGS :
 *  ieee80211_vap_txrx_event_handler : vap event handler
 *  arg                         : argument passed back via the evnt handler
 * RETURNS:
 *  on success returns 0.
 *  on failure returns a negative value.
 */
int ieee80211_vap_txrx_unregister_event_handler(ieee80211_vap_t,ieee80211_vap_txrx_event_handler evhandler, void *arg);

#define IEEE80211_MAX_VAP_TXRX_EVENT_HANDLERS            16

typedef struct _ieee80211_txrx_event_info {
    void*                             iv_txrx_event_handler_arg[IEEE80211_MAX_VAP_TXRX_EVENT_HANDLERS];
    ieee80211_vap_txrx_event_handler  iv_txrx_event_handler[IEEE80211_MAX_VAP_TXRX_EVENT_HANDLERS];
    u_int32_t                         iv_txrx_event_filters[IEEE80211_MAX_VAP_TXRX_EVENT_HANDLERS];
    u_int32_t                         iv_txrx_event_filter;
    u_int8_t                          iv_txrx_event_tx_error_trigger;
} ieee80211_txrx_event_info;


void transcap_dot3_to_eth2(struct sk_buff *skb);

#endif /* _IEEE80211_DATA_H */
