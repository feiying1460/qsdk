/*
 * Copyright (c) 2011-2012 Qualcomm Atheros, Inc.
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


#ifndef _DFS__INTERFACE_H_
#define _DFS__INTERFACE_H_

/*
 * These are the only functions exported to the upper (device) layer.
 */

/*
 * EXPORT_SYMBOL(dfs_attach);
 * EXPORT_SYMBOL(dfs_detach);
 * EXPORT_SYMBOL(dfs_radar_enable);
 * EXPORT_SYMBOL(dfs_process_phyerr);
 * EXPORT_SYMBOL(dfs_control);
 * EXPORT_SYMBOL(dfs_clear_stats);
 * EXPORT_SYMBOL(dfs_usenol);
 * EXPORT_SYMBOL(dfs_isdfsregdomain);
 */

/*
 * These are exported but not currently defined here; these should be
 * evaluated.
 *
 * EXPORT_SYMBOL(dfs_process_ar_event); -- legacy adaptive radio processing
 * EXPORT_SYMBOL(ath_ar_disable);
 * EXPORT_SYMBOL(ath_ar_enable);
 * EXPORT_SYMBOL(dfs_get_thresholds);
 * EXPORT_SYMBOL(dfs_init_radar_filters);
 * EXPORT_SYMBOL(dfs_getchanstate);
 */

u_int16_t   dfs_usenol(struct ieee80211com *ic);
u_int16_t   dfs_isdfsregdomain(struct ieee80211com *ic);
int         dfs_attach(struct ieee80211com *ic);
void        dfs_detach(struct ieee80211com *ic);
int         dfs_radar_enable(struct ieee80211com *ic,
                struct ath_dfs_radar_tab_info *ri, int no_cac);
int         dfs_radar_disable(struct ieee80211com *ic);
extern void dfs_process_phyerr(struct ieee80211com *ic, void *buf, u_int16_t datalen, u_int8_t rssi, 
                                    u_int8_t ext_rssi, u_int32_t rs_tstamp, u_int64_t fulltsf);
int         dfs_control(struct ieee80211com *ic, u_int id, void *indata, u_int32_t insize,
                            void *outdata, u_int32_t *outsize);
void        dfs_clear_stats(struct ieee80211com *ic);
void        dfs_getnol(struct ieee80211com *ic, void *dfs_nolinfo);
void        dfs_rx_rcsa(struct ieee80211com *ic);
void        dfs_cancel_waitfor_csa_timer(struct ieee80211com *ic);
#if ATH_SUPPORT_ZERO_CAC_DFS
int         dfs_second_segment_radar_disable(struct ieee80211com *ic);
int         dfs_get_nol_timeout(struct ieee80211com *ic);
#endif

#endif  /* _DFS__INTERFACE_H_ */
