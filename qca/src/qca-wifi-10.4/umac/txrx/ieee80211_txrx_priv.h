/*
 *  Copyright (c) 2005 Atheros Communications Inc.  All rights reserved. 
 * 
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */


#ifndef _IEEE80211_TXRX_PRIV_H
#define _IEEE80211_TXRX_PRIV_H


#include <osdep_internal.h>
#include <if_upperproto.h>
#include <ieee80211_var.h>
#include <ieee80211_channel.h>
#include <ieee80211_rateset.h>
#include <ieee80211_scan.h>
#include <ieee80211_wds.h>

void ieee80211_vap_txrx_deliver_event(ieee80211_vap_t vap,ieee80211_vap_txrx_event *evt);
#if UMAC_SUPPORT_TX_FRAG
int ieee80211_fragment(struct ieee80211vap *vap, wbuf_t wbuf0,
                              u_int hdrsize, u_int ciphdrsize, u_int mtu);
/*
 * checkand if required fragment the frame.
 */
static INLINE bool ieee80211_check_and_fragment(struct ieee80211vap *vap, wbuf_t wbuf,struct ieee80211_frame *wh,
                                                int usecrypto, struct ieee80211_key *key, u_int hdrsize )
{
    int txfrag;
    bool encap = false;
    /*
     * check if xmit fragmentation is required
     */
    txfrag = ((wbuf_get_pktlen(wbuf) > vap->iv_fragthreshold) &&
              !IEEE80211_IS_MULTICAST(wh->i_addr1) &&
              !wbuf_is_fastframe(wbuf));		/* NB: don't fragment ff's */

    if (txfrag) {

        /*
         * When packet arrives here, it is the 802.11 type packet without tkip header.
        * Hence, it should set encap=0 when perform enmic.
        * In some customer platform, the packet is already 802.11 type + tkip header.
        * In such a case, we set encap=1.
         */
#ifdef __CARRIER_PLATFORM__
        if (wbuf_is_encap_done(wbuf)) {
            encap = true;
        }
#endif
        if (usecrypto) {
            /*
             * For tx fragmentation, we have to do software enmic.
             * NB: In fact, it's for TKIP only, but the function will always return
             * success for non-TKIP cipher types.
             */
            if (!ieee80211_crypto_enmic(vap, key, wbuf, txfrag, encap)) {
                IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_OUTPUT,
                                   wh->i_addr1,
                                   "%s", "enmic failed, discard frame");
                vap->iv_stats.is_crypto_enmicfail++;
                return false; 
            }
        }
        
        if (!ieee80211_fragment(vap, wbuf, hdrsize,
                                key != NULL ? key->wk_cipher->ic_header : 0,
                                vap->iv_fragthreshold)) {
            IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_OUTPUT,
                               wh->i_addr1,
                               "%s", "fragmentation failed, discard frame");
            return false; 
        }
    }
  
    return true;
}

#else /* UMAC_SUPPORT_TX_FRAG */

#define ieee80211_check_and_fragment(vap,wbuf,wh,usecrypto,key,hdrsize)  true 

#endif /* UMAC_SUPPORT_TX_FRAG */


#if UMAC_SUPPORT_RX_FRAG

wbuf_t ieee80211_defrag(struct ieee80211_node *ni, wbuf_t wbuf, int hdrlen);

#else/* UMAC_SUPPORT_RX_FRAG */

static INLINE wbuf_t ieee80211_defrag(struct ieee80211_node *ni, wbuf_t wbuf, int hdrlen) 
{
    struct ieee80211_frame *wh;
    u_int8_t more_frag;

    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    more_frag = wh->i_fc[1] & IEEE80211_FC1_MORE_FRAG;
    /* fragments are unexpected, if we receive a fragment then assert */
    KASSERT( (more_frag == 0 ), ("RX fragementation is compiled out\n"));
    return wbuf;

}

#endif/* UMAC_SUPPORT_RX_FRAG */

#if UMAC_SUPPORT_STAFWD
static INLINE  int
ieee80211_apclient_fwd(wlan_if_t  vap, wbuf_t wbuf)
{
    struct ether_header *eh;
    struct ieee80211com * ic = vap->iv_ic;

    eh = (struct ether_header *)wbuf_header(wbuf);


    /* if the vap is configured in 3 address forwarding
     * mode, then clone the MAC address if necessary
     */
    if ((vap->iv_opmode == IEEE80211_M_STA) &&  ieee80211_vap_sta_fwd_is_set(vap))
    {
        if (IEEE80211_ADDR_EQ(eh->ether_shost, vap->iv_my_hwaddr)) {
            /* Station is in forwarding mode - Drop the packets
             * originated from station except EAPOL packets
             */
            if (eh->ether_type == ETHERTYPE_PAE) {
                IEEE80211_ADDR_COPY(eh->ether_shost,vap->iv_myaddr);
                return 1;
            }
            else {
                /* Drop the packet */
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_OUTPUT,
                        "%s: drop data packet, vap is in sta_fwd\n",
                         __func__);
                return 0;
            }
        }
        if (!IEEE80211_ADDR_EQ(eh->ether_shost, vap->iv_myaddr))
        {
            /* Clone the mac address with the mac address end-device */
            if (wlan_mlme_deauth_request((wlan_if_t)vap,
                              vap->iv_bss->ni_bssid, IEEE80211_REASON_ASSOC_LEAVE) !=0 ) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
                        "%s: vap is in sta_fwd , but unable to disconnect \n",
                         __func__);
	}

           // wlan_mlme_connection_reset(vap);
            /* Mac address is cloned - re-associate with the AP 
             * again 
             */

            IEEE80211_ADDR_COPY(vap->iv_myaddr, eh->ether_shost);
            IEEE80211_ADDR_COPY(ic->ic_myaddr, eh->ether_shost);
            ic->ic_set_macaddr(ic, eh->ether_shost);
            IEEE80211_DELIVER_EVENT_STA_CLONEMAC(vap);
            // packet to be dropped 
            return 0;
        }
        else {
            return 1;
        }
    }
    else
    {
        return 1;
    }

}
#else
#define ieee80211_apclient_fwd(_vap, _wbuf) (1)
#endif

#endif /* TXRX_PRIV_H */
