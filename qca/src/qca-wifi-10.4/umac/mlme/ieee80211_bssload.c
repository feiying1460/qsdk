/*
 *  Copyright (c) 2008 Atheros Communications Inc.
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

#include <ieee80211_var.h>
#include "ieee80211_bssload.h"

#if UMAC_SUPPORT_BSSLOAD || UMAC_SUPPORT_CHANUTIL_MEASUREMENT

/*
 * Compute the channe utilization
 */
void
ieee80211_beacon_chanutil_update(struct ieee80211vap *vap)
{
#define CHAN_UTIL_BEACON_INTL_DEF (10)
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_mib_cycle_cnts cnts;
    struct ieee80211_chanutil_info *cu = &vap->chanutil_info;
    
    if (cu->cycle_count == 0) {
        /* read the cycle counts and return */
        ic->ic_rmgetcounters(ic, &cnts);
        cu->cycle_count = cnts.cycle_count;
        cu->rx_clear_count = cnts.rx_clear_count;
        return;
    }
    cu->beacon_count++;
    if (cu->beacon_count == CHAN_UTIL_BEACON_INTL_DEF) {
        /* get the counter */
        ic->ic_rmgetcounters(ic, &cnts);
        if ((cnts.cycle_count > cu->cycle_count) &&
            (cnts.rx_clear_count > cu->rx_clear_count)) {
            u_int32_t cc_d = cnts.cycle_count - cu->cycle_count;
            u_int32_t rc_d = cnts.rx_clear_count - cu->rx_clear_count;
            if (cc_d > (0x80000000 >> 8)) {
                cu->value = rc_d / (cc_d >> 8);
            }
            else {
                cu->value = (rc_d << 8) / cc_d;
            }
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
            cu->new_value = 1;
#endif
#if UMAC_SUPPORT_BSSLOAD
            ieee80211_vap_bssload_update_set(vap);
#endif /* UMAC_SUPPORT_BSSLOAD */
        }
        cu->cycle_count = cnts.cycle_count;
        cu->rx_clear_count = cnts.rx_clear_count;
        cu->beacon_count = 0;
    }
    return;
#undef CHAN_UTIL_BEACON_INTL_DEF
}

#endif /* UMAC_SUPPORT_BSSLOAD || UMAC_SUPPORT_CHANUTIL_MEASUREMENT */

#if UMAC_SUPPORT_BSSLOAD

/*
 * Add bss load formation elements to a frame.
 */
static u_int8_t *
ieee80211_add_bssload_ie(struct ieee80211vap *vap, u_int8_t *frm, struct ieee80211_node *ni)
{
    struct ieee80211_ie_qbssload *qbssload = (struct ieee80211_ie_qbssload *) frm;
    /*
    *  qbssload element structure
    */
    memset(qbssload, 0, sizeof(struct ieee80211_ie_qbssload));
    qbssload->elem_id = IEEE80211_ELEMID_QBSS_LOAD;
    qbssload->length = sizeof(struct ieee80211_ie_qbssload) - 2;
    qbssload->station_count = htole16(vap->iv_sta_assoc);
    qbssload->channel_utilization = vap->chanutil_info.value;
    qbssload->aac = 0; /* TBD */
#if ATH_SUPPORT_HS20
    if (vap->iv_hc_bssload) {
        /* override the values with hardcoded values */
        qbssload->station_count = htole16((vap->iv_hc_bssload & 0xFF000000) >> 24);
        qbssload->channel_utilization = (vap->iv_hc_bssload & 0xFF0000) >> 16;
        qbssload->aac = htole16(vap->iv_hc_bssload & 0xFFFF);
    }
#endif
    return frm + sizeof(struct ieee80211_ie_qbssload);
}


/* 
 * Add bss load to the frame if bss load support is enabled
 */
u_int8_t *
ieee80211_add_bssload(u_int8_t *frm, struct ieee80211_node *ni)
{
    struct ieee80211vap       *vap = ni->ni_vap;
    if (ieee80211_vap_bssload_is_set(vap)) {
        frm = ieee80211_add_bssload_ie(vap, frm, ni);
    }
    return frm;
}

/*
 * Add the bss load ie and update beacon offset
 */
u_int8_t *
ieee80211_bssload_beacon_setup(struct ieee80211vap *vap, struct ieee80211_node *ni, 
                        struct ieee80211_beacon_offsets *bo,
                        u_int8_t *frm)
{
    if (ieee80211_vap_bssload_is_set(vap)) {
       bo->bo_bssload = frm;
       frm = ieee80211_add_bssload_ie(vap, frm, ni);
    }
    return frm;
}

/* 
 * update the bss load ie
 */
void ieee80211_bssload_beacon_update(struct ieee80211vap *vap, struct ieee80211_node *ni,
                               struct ieee80211_beacon_offsets *bo)
{
    if (ieee80211_vap_bssload_update_is_set(vap) &&
        ieee80211_vap_bssload_is_set(vap) &&
        bo->bo_bssload) {
       ieee80211_add_bssload_ie(vap, bo->bo_bssload, ni);
       ieee80211_vap_bssload_update_clear(vap);
    }
}

#endif /* UMAC_SUPPORT_BSSLOAD */
