/*
 * Copyright (c) 2014, Qualcomm Atheros Inc.
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

/*
 * LMAC offload interface functions for UMAC - Mcast enhancement feature
 */

#include "ol_if_athvar.h"
#include "ol_if_athpriv.h"
#include "sw_version.h"
#include "cdp_txrx_me.h"
#include "qdf_mem.h"   /* qdf_mem_malloc,free */
#include "qdf_lock.h"  /* qdf_spinlock_* */
#include "qdf_types.h" /* qdf_vprint */
#include "ol_ath.h"

#include "ol_if_stats.h"
#include "ol_ratetable.h"
#include "ol_if_vap.h"

#if ATH_SUPPORT_IQUE

#if ATH_SUPPORT_ME_FW_BASED
/* wrapper func for the inline function in ol_tx_desc.h */
u_int16_t
ol_ath_desc_alloc_and_mark_for_mcast_clone(struct ieee80211com *ic, u_int16_t buf_count)
{
    u_int16_t allocated, cur_alloc;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    /* TODO: Increase of high traffic scenario, there is a possiblity that alloc fails due
     * to lack of free descriptors. Need handle this by grabbing those descriptors while freeing*/
    cur_alloc = ol_tx_get_mcast_buf_allocated_marked(OL_ATH_SOFTC_NET80211(ic)->pdev_txrx_handle);
    /*Wait for FW to complete previous removal before adding any new request*/
    if( scn->pend_desc_removal ) {
        scn->pend_desc_addition += buf_count;
        return cur_alloc;
    }

    allocated = ol_tx_desc_alloc_and_mark_for_mcast_clone(OL_ATH_SOFTC_NET80211(ic)->pdev_txrx_handle, buf_count);

    if( (cur_alloc + buf_count) < allocated ) {
        scn->pend_desc_addition += (cur_alloc + buf_count) - allocated;
    }
    if( allocated > cur_alloc ) {
        ol_ath_pdev_set_param(scn,
                wmi_pdev_param_set_mcast2ucast_buffer, allocated);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: VAP Mcast to Unicast buffer allocated: %u\n", __func__, allocated);
    }

    return allocated;
}

/* wrappers func for the inline function in ol_tx_desc.h */
u_int16_t
ol_ath_desc_free_and_unmark_for_mcast_clone(struct ieee80211com *ic, u_int16_t buf_count)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    scn->pend_desc_removal += buf_count;
    return (ol_ath_pdev_set_param(scn, wmi_pdev_param_remove_mcast2ucast_buffer,
                buf_count));
}

/* function to get the value from txrx structure, instead of accessing directly */
u_int16_t
ol_ath_get_mcast_buf_allocated_marked(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    return(ol_tx_get_mcast_buf_allocated_marked(OL_ATH_SOFTC_NET80211(ic)->pdev_txrx_handle) - scn->pend_desc_removal);
}
#endif /*ATH_SUPPORT_ME_FW_BASED*/
static void
ol_ath_mcast_group_update(
    struct ieee80211com *ic,
    int action,
    int wildcard,
    u_int8_t *mcast_ip_addr,
    int mcast_ip_addr_bytes,
    u_int8_t *ucast_mac_addr,
    u_int8_t filter_mode,
    u_int8_t nsrcs,
    u_int8_t *srcs,
    u_int8_t *mask,
    u_int8_t vap_id)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct mcast_group_update_params param;

    if (scn->is_ar900b)
      return;

    qdf_mem_set(&param, sizeof(param), 0);
    param.action = action;
    param.wildcard = wildcard;
    param.mcast_ip_addr = mcast_ip_addr;
    param.nsrcs = nsrcs;
    param.srcs = srcs;
    param.mask = mask;
    param.vap_id = vap_id;
    param.filter_mode = filter_mode;
    param.mcast_ip_addr_bytes = mcast_ip_addr_bytes;

    if(action == IGMP_ACTION_DELETE_MEMBER && wildcard && !mcast_ip_addr)  {
        param.is_action_delete = TRUE;
    }

    if(mcast_ip_addr_bytes != IGMP_IP_ADDR_LENGTH)
        param.is_mcast_addr_len = TRUE;

    if(filter_mode != IGMP_SNOOP_CMD_ADD_INC_LIST)
        param.is_filter_mode_snoop = TRUE;

    /* now correct for endianness, if necessary */
    /*
     * For Little Endian, N/w Stack gives packets in Network byte order and issue occurs
     * if both Host and Target happens to be in Little Endian. Target when compares IP
     * addresses in packet with MCAST_GROUP_CMDID given IP addresses, it fails. Hence
     * swap only mcast_ip_addr ( 16 bytes ) for now.
     * TODO : filter
     */
/*
#ifdef BIG_ENDIAN_HOST
    ol_bytestream_endian_fix(
            (u_int32_t *)&cmd->ucast_mac_addr, (sizeof(*cmd)-4) / sizeof(u_int32_t));
#else
    ol_bytestream_endian_fix(
            (u_int32_t *)&cmd->mcast_ip_addr, (sizeof(cmd->mcast_ip_addr)) / sizeof(u_int32_t));
#endif  Little Endian */

    wmi_unified_mcast_group_update_cmd_send(
            scn->wmi_handle, &param);
}

extern uint16_t
ol_me_convert_ucast(struct ieee80211vap *vap, qdf_nbuf_t wbuf,
                             u_int8_t newmac[][6], uint8_t new_mac_cnt)
{
    return ol_tx_me_convert_ucast(vap->iv_txrx_handle, wbuf,
                                        newmac, new_mac_cnt);
}
int ol_if_me_setup(struct ieee80211com *ic)
{
    ic->ic_mcast_group_update = ol_ath_mcast_group_update;
#if ATH_SUPPORT_ME_FW_BASED
    ic->ic_desc_alloc_and_mark_for_mcast_clone = ol_ath_desc_alloc_and_mark_for_mcast_clone;
    ic->ic_desc_free_and_unmark_for_mcast_clone = ol_ath_desc_free_and_unmark_for_mcast_clone;
    ic->ic_get_mcast_buf_allocated_marked = ol_ath_get_mcast_buf_allocated_marked;
#else
    ic->ic_me_convert = ol_me_convert_ucast;
#endif /*ATH_SUPPORT_ME_FW_BASED*/
    return 1;
}

#endif /*ATH_SUPPORT_IQUE*/
