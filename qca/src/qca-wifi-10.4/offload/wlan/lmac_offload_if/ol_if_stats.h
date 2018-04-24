/*
 * Copyright (c) 2011, Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


#ifndef	__OL_IF_STATS_H
#define	__OL_IF_STATS_H

#define PKTLOG_STATS_MAX_TXCTL_WORDS 57 /* +2 words for bitmap */
#define ATH_PKTLOG_STATS_HDR_FLAGS_MASK 0xffff
#define ATH_PKTLOG_STATS_HDR_FLAGS_SHIFT 0
#define ATH_PKTLOG_STATS_HDR_FLAGS_OFFSET 0
#define ATH_PKTLOG_STATS_HDR_MISSED_CNT_MASK 0xffff0000
#define ATH_PKTLOG_STATS_HDR_MISSED_CNT_SHIFT 16
#define ATH_PKTLOG_STATS_HDR_MISSED_CNT_OFFSET 0
#define ATH_PKTLOG_STATS_HDR_LOG_TYPE_MASK 0xffff
#define ATH_PKTLOG_STATS_HDR_LOG_TYPE_SHIFT 0
#define ATH_PKTLOG_STATS_HDR_LOG_TYPE_OFFSET 1
#define ATH_PKTLOG_STATS_HDR_SIZE_MASK 0xffff0000
#define ATH_PKTLOG_STATS_HDR_SIZE_SHIFT 16
#define ATH_PKTLOG_STATS_HDR_SIZE_OFFSET 1
#define ATH_PKTLOG_STATS_HDR_TIMESTAMP_OFFSET 2
#define PKTLOG_STATS_TYPE_TX_CTRL      1
#define PKTLOG_STATS_TYPE_TX_STAT      2
#define PKTLOG_STATS_TYPE_TX_MSDU_ID   3
#define PKTLOG_STATS_TYPE_TX_FRM_HDR   4
#define PKTLOG_STATS_TYPE_RX_STAT      5
#define PKTLOG_STATS_TYPE_RC_FIND      6
#define PKTLOG_STATS_TYPE_RC_UPDATE    7
#define PKTLOG_STATS_TYPE_TX_VIRT_ADDR 8
#define PKTLOG_STATS_TYPE_DBG_PRINT    9
#define PKTLOG_STATS_TYPE_MAX          10

/* Definitions for values of command flag in
   WMI_CHAN_INFO_EVENT */
#define WMI_CHAN_INFO_FLAG_START_RESP  0
#define WMI_CHAN_INFO_FLAG_END_RESP    1
#define WMI_CHAN_INFO_FLAG_BEFORE_END_RESP   2


struct ath_pktlog_stats_hdr {
    u_int16_t flags;
    u_int16_t missed_cnt;
    u_int16_t log_type;
    u_int16_t size;
    u_int32_t timestamp;
#ifdef CONFIG_AR900B_SUPPORT
    u_int32_t type_specific_data;
#endif
}__attribute__ ((packed));

struct txctl_stats_frm_hdr {
    u_int16_t framectrl;       /* frame control field from header */
    u_int16_t seqctrl;         /* frame control field from header */
    u_int16_t bssid_tail;      /* last two octets of bssid */
    u_int16_t sa_tail;         /* last two octets of SA */
    u_int16_t da_tail;         /* last two octets of DA */
    u_int16_t resvd;
};

struct ath_pktlog_stats_txctl {               
    struct ath_pktlog_stats_hdr pl_hdr;
    //struct txctl_frm_hdr frm_hdr;
    void *txdesc_hdr_ctl;   /* frm_hdr + Tx descriptor words */
    struct {
        struct txctl_stats_frm_hdr frm_hdr;
        u_int32_t txdesc_ctl[PKTLOG_STATS_MAX_TXCTL_WORDS];
        //u_int32_t *proto_hdr;   /* protocol header (variable length!) */
        //u_int32_t *misc; /* Can be used for HT specific or other misc info */
        } priv;
}__attribute__ ((packed));


int
ol_ath_wlan_profile_data_event_handler (ol_scn_t scn, u_int8_t *data,
        u_int16_t datalen);

void
ol_ath_chan_info_attach(struct ieee80211com *ic);

void
ol_ath_chan_info_detach(struct ieee80211com *ic);

void
ol_ath_stats_attach(struct ieee80211com *ic);

void
ol_ath_stats_detach(struct ieee80211com *ic);

void 
ol_get_wlan_dbg_stats(struct ol_ath_softc_net80211 *scn,
                            struct wlan_dbg_stats *dbg_stats);
int32_t
ol_ath_request_stats(struct ieee80211com *ic, void *cmd_param);

void
acfg_chan_stats_event(struct ieee80211com *ic,
         u_int8_t self_util, u_int8_t obss_util);

#endif /* OL_IF_STATS_H */

