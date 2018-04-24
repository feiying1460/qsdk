/*
 *  Copyright (c) 2008 Atheros Communications Inc.
 * All Rights Reserved.
 *
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#ifndef _IEEE80211_ACS_H
#define _IEEE80211_ACS_H

typedef struct ieee80211_acs    *ieee80211_acs_t;

typedef struct _ieee80211_chan_neighbor_list {
    ieee80211_acs_t  acs;        /* acs reference */
    u_int8_t         chan;       /* ieee channel number */
    u_int8_t         nbss;       /*number of bss per channel */
    ieee80211_neighbor_info   neighbor_list[IEEE80211_MAX_NEIGHBOURS]; /* List of Neighbor per channel */
} ieee80211_chan_neighbor_list;

#define IEEE80211_ACS_CTRLFLAG 0x1
#define IEEE80211_ACS_ENABLE_BK_SCANTIMER  0x2
#define IEEE80211_ACS_SCANTIME 0x3
#define IEEE80211_ACS_RSSIVAR  0x4
#define IEEE80211_ACS_CHLOADVAR 0x5
#define IEEE80211_ACS_LIMITEDOBSS 0x6
#define IEEE80211_ACS_DEBUGTRACE 0x7
#define IEEE80211_ACS_BLOCK_MODE 0x8
#define IEEE80211_ACS_TX_POWER_OPTION 0x9
#define IEEE80211_ACS_2G_ALL_CHAN 0xa
#define IEEE80211_ACS_RANK 0xb



#if UMAC_SUPPORT_ACS
#define ACS_CHAN_STATS 0
#define ACS_CHAN_STATS_NF 1
#define IEEE80211_HAL_OFFLOAD_ARCH 0
#define IEEE80211_HAL_DIRECT_ARCH 1
int ieee80211_acs_attach(ieee80211_acs_t *acs,
                          struct ieee80211com *ic,
                          osdev_t             osdev);

int ieee80211_acs_init(ieee80211_acs_t *acs,
                          struct ieee80211com *ic,
                          osdev_t osdev);
void ieee80211_acs_deinit(ieee80211_acs_t *acs);
int ieee80211_acs_detach(ieee80211_acs_t *acs);
int ieee80211_acs_startscantime(struct ieee80211com *ic);
int ieee80211_acs_state(struct ieee80211_acs *acs);

void ieee80211_acs_stats_update(ieee80211_acs_t acs,
                                u_int8_t flags,
                                u_int ieee_chan,
                                int16_t chan_nf,
                                struct ieee80211_chan_stats *chan_stats);

#if ATH_ACS_SUPPORT_SPECTRAL && ATH_SUPPORT_SPECTRAL
void ieee80211_update_eacs_counters(struct ieee80211com *ic, int8_t nfc_ctl_rssi,
                                     int8_t nfc_ext_rssi, int8_t ctrl_nf, int8_t ext_nf);
void ieee80211_init_spectral_chan_loading(struct ieee80211com *ic, int current_channel,
                                                                         int ext_channel);
int ieee80211_get_spectral_freq_loading(struct ieee80211com *ic);
#endif
int ieee80211_acs_set_param(ieee80211_acs_t acs, int param , int val);
int ieee80211_acs_get_param(ieee80211_acs_t acs, int param );

#else /* UMAC_SUPPORT_ACS */

static INLINE int ieee80211_acs_attach(ieee80211_acs_t *acs,
                                        struct ieee80211com *ic,
                                        osdev_t             osdev)
{
    return 0;
}
#define ieee80211_acs_detach(acs) /**/

#define ieee80211_acs_stats_update(acs, \
                                   flags,       \
                                   ieee_chan,   \
                                   chan_nf,      \
                                   chan_stats)
#define ieee80211_acs_set_param(acs, param , val)
#define ieee80211_acs_get_param(acs, param ) 0

#endif /* UMAC_SUPPORT_ACS */

#endif
