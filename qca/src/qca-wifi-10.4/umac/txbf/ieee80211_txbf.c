/*
 *  Copyright (c) 2008 Atheros Communications Inc.  All rights reserved.
 * \brief 802.11n compliant Transmit Beamforming
 */
/*
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <ieee80211_var.h>
#include <ieee80211_channel.h>

#ifdef ATH_SUPPORT_TxBF
extern void ieee80211_send_setup( struct ieee80211vap *vap, struct ieee80211_node *ni,
    struct ieee80211_frame *wh, u_int8_t type, const u_int8_t *sa, const u_int8_t *da,
                           const u_int8_t *bssid);

enum {
    NOT_SUPPORTED         = 0,
    DELAYED_FEEDBACK      = 1,
    IMMEDIATE_FEEDBACK    = 2,
    DELAYED_AND_IMMEDIATE = 3,
};
void 
ieee80211_set_TxBF_keycache(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    //struct ieee80211vap *vap = ni->ni_vap;
	 
    //IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,"==>%s:keyid: %d, cipher %x,flags %x",__func__,ni->ni_ucastkey.wk_keyix
    //        ,ni->ni_ucastkey.wk_cipher->ic_cipher,ni->ni_ucastkey.wk_flags);

    if (ni->ni_ucastkey.wk_keyix == IEEE80211_KEYIX_NONE){  //allocate new key
        ni->ni_ucastkey.wk_keyix=ic->ic_txbf_alloc_key(ic, ni);
    }
    if (( ni->ni_ucastkey.wk_keyix != IEEE80211_KEYIX_NONE)&& 
        (ni->ni_ucastkey.wk_cipher->ic_cipher == IEEE80211_CIPHER_NONE)){ 
        ic->ic_txbf_set_key(ic, ni);   // update staggered sounding ,cec , mmss into key cache.
    }
}

void
ieee80211_match_txbfcapability(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    union ieee80211_hc_txbf *bfer, *bfee;
    bool previous_txbf_active = 0;

    bfer = &ic->ic_txbf;
    bfee = &ni->ni_txbf;

    /* set previous link txbf status*/
    if (ni->ni_explicit_compbf || ni->ni_explicit_noncompbf || ni->ni_implicit_bf){
        previous_txbf_active = 1;
    }
    ni->ni_explicit_compbf = FALSE;
    ni->ni_explicit_noncompbf = FALSE;
    ni->ni_implicit_bf = FALSE;

    /* XXX need multiple chains to do BF?*/
    /* Skipping the TxBF, if single chain is enabled 
     * (chain 0 or chain 1 or chain 2) 
     */ 
    if ((ic->ic_tx_chainmask & (ic->ic_tx_chainmask - 1)) == 0)
        return;
    /*
     * We would prefer to do explicit BF if possible.
     * So the following checks are order sensitive.
     */
     /* suppot both delay report and immediately report*/
     
    if (bfer->explicit_comp_steering && (bfee->explicit_comp_bf != 0)) {
        ni->ni_explicit_compbf = TRUE;
        
        /* re-initial TxBF timer for previous link is not TxBF link*/
        if (previous_txbf_active == 0){
            ieee80211_init_txbf(ic, ni);
        }        
        return;
    }

    if (bfer->explicit_noncomp_steering && (bfee->explicit_noncomp_bf != 0)){
        ni->ni_explicit_noncompbf = TRUE;
        if (previous_txbf_active == 0){
            ieee80211_init_txbf(ic, ni);
        }  
        return;
    }

    if (bfer->implicit_txbf_capable && bfee->implicit_rx_capable) {
        ni->ni_implicit_bf = TRUE;
        if (previous_txbf_active == 0){
            ieee80211_init_txbf(ic, ni);
        }  
        return;
    }
}

u_int8_t *
ieee80211_add_htc(wbuf_t wbuf, int use4addr)
{
    struct ieee80211_frame *wh;
    u_int8_t *htc;

    wh = (struct ieee80211_frame *)wbuf_header(wbuf);

    /* set order bit in frame control to enable HTC field; */
    wh->i_fc[1] |= IEEE80211_FC1_ORDER;	

    if (!use4addr) {
        htc = ((struct ieee80211_qosframe_htc *)wh)->i_htc;
    } else {              					
        htc= ((struct ieee80211_qosframe_htc_addr4 *)wh)->i_htc;
    }

    htc[0] = htc[1] = htc[2] = htc[3] = 0;

    return htc;
}

void
ieee80211_request_cv_update(struct ieee80211com *ic,struct ieee80211_node *ni, wbuf_t wbuf, int use4addr)
{
    u_int8_t *htc;
    /* struct ieee80211vap *vap = ni->ni_vap;
	        
     *IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,"==>%s:\n",__func__);*/

    htc = ieee80211_add_htc(wbuf, use4addr);

    /* clear update flags */
    ni->ni_bf_update_cv = 0;
    if (ni->ni_explicit_compbf) {
        /* set CSI=3 to request compressed ExBF */
        htc[2] = IEEE80211_HTC2_CSI_COMP_BF;
    } else if (ni->ni_explicit_noncompbf) {
        /* set CSI=2 to request non-compressed ExBF */
        htc[2] = IEEE80211_HTC2_CSI_NONCOMP_BF;
    }
    return;
}

//for TxBF RC
/*
 * Send a Crlx frame of Beamforming to the specified node.
	Cal_type : 0	 ==> Cal 1
			   or	 ==> Cal 3

 */

OS_TIMER_FUNC(txbf_cv_timeout)
{
    struct ieee80211_node *ni;
    OS_GET_TIMER_ARG(ni, struct ieee80211_node *);

    ni->ni_allow_cv_update = 1; // time up, allow cv update.
}

OS_TIMER_FUNC(txbf_cv_report_timeout)
{
    struct ieee80211_node *ni;

    OS_GET_TIMER_ARG(ni, struct ieee80211_node *);

    ni->ni_bf_update_cv = 1; // time up, request cv update immediately.

    if (ni->ni_sw_cv_timeout){ 
        // reset sw timer
        OS_CANCEL_TIMER(&(ni->ni_cv_timer));
        OS_SET_TIMER(&ni->ni_cv_timer, ni->ni_sw_cv_timeout);
    }
}

void ieee80211_init_txbf(struct ieee80211com *ic,struct ieee80211_node *ni)
{
    if (ni->ni_explicit_compbf || ni->ni_explicit_noncompbf || ni->ni_implicit_bf) {
        ni->ni_bf_update_cv = 0;
        ni->ni_allow_cv_update = 0;
        ic->ic_init_sw_cv_timeout(ic, ni);
        //IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,"==>%s: this node support TxBF, set initial BF ",__func__);
        if (ni->ni_txbf_timer_initialized){
            OS_FREE_TIMER(&ni->ni_cv_timer);
            OS_FREE_TIMER(&ni->ni_report_timer);
        }        
        OS_INIT_TIMER(ic->ic_osdev, &ni->ni_cv_timer, txbf_cv_timeout, ni, QDF_TIMER_TYPE_WAKE_APPS);
        OS_INIT_TIMER(ic->ic_osdev, &ni->ni_report_timer, txbf_cv_report_timeout, ni, QDF_TIMER_TYPE_WAKE_APPS);
        ni->ni_txbf_timer_initialized = 1;
    }
} 
#endif /* ATH_SUPPORT_TxBF */
