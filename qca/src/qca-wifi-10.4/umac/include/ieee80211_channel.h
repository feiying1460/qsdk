/*
 *  Copyright (c) 2008 Atheros Communications Inc.
 * All Rights Reserved.
 *
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#ifndef _NET80211_IEEE80211_CHAN_H
#define _NET80211_IEEE80211_CHAN_H

#include <ieee80211_var.h>

/*
 * Internal API's for channel/freq/PHY_mode handling
 */

enum ieee80211_phymode ieee80211_chan2mode(const struct ieee80211_channel *chan);
u_int ieee80211_mhz2ieee(struct ieee80211com *ic, u_int freq, u_int flags);
u_int ieee80211_ieee2mhz(struct ieee80211com *ic, u_int chan, u_int flags);
struct ieee80211_channel *ieee80211_find_channel(struct ieee80211com *ic, int freq, u_int8_t des_cfreq2, u_int32_t flags);
enum ieee80211_phymode ieee80211_get_phy_mode(struct ieee80211com *ic,
                                        struct ieee80211_channel *bss_chan,
                                        enum ieee80211_phymode des_mode, enum ieee80211_phymode bss_mode);

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
void ieee80211_print_nolhistory(struct ieee80211com *ic);
void ieee80211_clear_nolhistory(struct ieee80211com *ic);
#endif

struct ieee80211_channel *ieee80211_doth_findchan(struct ieee80211vap *vap, u_int8_t chan);
struct ieee80211_channel *ieee80211_find_dot11_channel(struct ieee80211com *ic, int ieee, u_int8_t des_cfreq2, enum ieee80211_phymode mode);
#define IEEE80211_SELECT_NONDFS_AND_DFS 0
#define IEEE80211_SELECT_NONDFS_ONLY    1
#define IEEE80211_SELECT_NXT_CH_POST_RADAR_DETECT   0
#define IEEE80211_SELECT_APRIORI_NXT_CH             1
int ieee80211_random_channel(struct ieee80211com *ic, u_int8_t is_select_nondfs, u_int8_t skip_curchan);
bool ieee80211_is_same_frequency_band(const struct ieee80211_channel *chan1, const struct ieee80211_channel *chan2);
void ieee80211_update_channellist(struct ieee80211com *ic, int exclude_11d);
struct ieee80211_channel *ieee80211_autoselect_adhoc_channel(struct ieee80211com *ic);
int ieee80211_set_channel(struct ieee80211com *ic, struct ieee80211_channel *chan);
int ieee80211_setmode(struct ieee80211com *ic, enum ieee80211_phymode mode, enum ieee80211_opmode opmode);
struct ieee80211_channel * ieee80211_doth_findchan(struct ieee80211vap *vap, u_int8_t chan);
static INLINE u_int32_t
ieee80211_chan2freq(struct ieee80211com *ic, const struct ieee80211_channel *c);

extern int ieee80211_get_chan_width(struct ieee80211_channel *chan);
extern int ieee80211_get_chan_centre_freq(struct ieee80211com *ic,
    struct ieee80211_channel *chan);
extern int ieee80211_check_channel_overlap(struct ieee80211com *ic,
    struct ieee80211_channel *chan, int nolfreq, int nolchwidth);

extern void    ieee80211_get_extchaninfo(struct ieee80211com *ic, struct ieee80211_channel *chan, struct ieee80211_channel_list *chan_info);
int
ieee80211_check_chan_mode_consistency(struct ieee80211com *ic,int mode,struct ieee80211_channel *c);
u_int8_t ieee80211_is_extchan_144(struct ieee80211com *ic,struct ieee80211_channel *chan, u_int8_t extchan);
int8_t ieee80211_secondary20_channel_offset(struct ieee80211_channel *chan);

enum ieee80211_mode ieee80211_get_mode(struct ieee80211com *ic);

enum ieee80211_phymode ieee80211_get_composite_phymode (enum ieee80211_mode mode,
       enum ieee80211_cwm_width chwidth, uint8_t secchanoffset);

enum ieee80211_cwm_width
ieee80211_get_cwm_width_from_channel(struct ieee80211_channel *chan);

INLINE static u_int32_t
ieee80211_chan_flags(struct ieee80211_channel *chan)
{
    return chan->ic_flags;
}

INLINE static u_int8_t
ieee80211_chan_flagext(struct ieee80211_channel *chan)
{
    return chan->ic_flagext;
}

extern const char *ieee80211_phymode_name[];

/*
 * Convert channel to IEEE channel number.
 */
static INLINE u_int8_t
ieee80211_chan2ieee(struct ieee80211com *ic, const struct ieee80211_channel *c)
{
    if (c == NULL) {
        return 0;       /* XXX */
    }
    return (c == IEEE80211_CHAN_ANYC ?
            (u_int8_t)IEEE80211_CHAN_ANY : c->ic_ieee);
}

/*
 * Convert channel to frequency value.
 */
static INLINE u_int
ieee80211_chan2freq(struct ieee80211com *ic, const struct ieee80211_channel *c)
{
    if (c == NULL) {
        return 0;       /* XXX */
    }
    return (c == IEEE80211_CHAN_ANYC ?  IEEE80211_CHAN_ANY : c->ic_freq);
}

const char *ieee80211_phymode_to_name( enum ieee80211_phymode mode);

/*
 * Iterator for channel list
 */
#define ieee80211_enumerate_channels(_c, _ic, _index)    \
    for ((_index) = 0, (_c) = (_ic)->ic_channels;        \
         (_index) < (_ic)->ic_nchans;                    \
         (_index)++, (_c)++)

/*
 * Get channel by channel index
 */
#define ieee80211_get_channel(_ic, _index)  (&((_ic)->ic_channels[(_index)]))

#define ieee80211_get_current_channel(_ic)  ((_ic)->ic_curchan)
#define ieee80211_get_home_channel(_vap)     ((_vap)->iv_bsschan)

/*
 * Get current operating PHY mode
 */
static INLINE enum ieee80211_phymode
ieee80211_get_current_phymode(struct ieee80211com *ic)
{
    return ieee80211_chan2mode(ic->ic_curchan);
}

/*
 * Set number of channels
 */
static INLINE void
ieee80211_set_nchannels(struct ieee80211com *ic, int nchans)
{
    ic->ic_nchans = nchans;
}

/*
 * Set the channel
 */
#define IEEE80211_CHAN_SETUP(_c, _ieee, _freq, _flags, _extflags,  \
                            _maxregp, _maxp, _minp, _id)\
    do {                                                \
        (_c)->ic_freq = (_freq);                        \
        (_c)->ic_ieee = (_ieee);                        \
        (_c)->ic_flags = (_flags);                      \
        (_c)->ic_flagext = (_extflags);                 \
        (_c)->ic_maxregpower = (_maxregp);              \
        (_c)->ic_maxpower = (_maxp);                    \
        (_c)->ic_minpower = (_minp);                    \
        (_c)->ic_regClassId = (_id);                    \
    } while (0)

/*
 * Compare two channels
 */
#define IEEE80211_CHAN_MATCH(_c, _freq, _flags, _mask)      \
    (((_c)->ic_freq == (_freq)) &&                          \
     (((_c)->ic_flags & (_mask)) == ((_flags) & (_mask))))

/*
 * Check whether a phymode is supported
 */
#define IEEE80211_SUPPORT_PHY_MODE(_ic, _mode)  \
    (((_ic)->ic_modecaps & (1 << (_mode))) && \
    (((_ic)->ic_support_phy_mode == NULL) || \
    ((_ic)->ic_support_phy_mode((_ic), (_mode)))))

/*
 * Check whether a phymode is accepted
 */
#define IEEE80211_ACCEPT_PHY_MODE(_vap, _mode)  \
    ((_vap)->iv_des_modecaps & (1 << (_mode)))

#define IEEE80211_ACCEPT_ANY_PHY_MODE(_vap)     \
    ((_vap)->iv_des_modecaps & (1 << IEEE80211_MODE_AUTO))

#define IEEE80211_ACCEPT_PHY_MODE_11G(_vap)     \
    ((_vap)->iv_des_modecaps & (1 << IEEE80211_MODE_11G))

#define IEEE80211_ACCEPT_PHY_MODE_11A(_vap)     \
    ((_vap)->iv_des_modecaps & (1 << IEEE80211_MODE_11A))

#endif /* _NET80211_IEEE80211_CHAN_H */
