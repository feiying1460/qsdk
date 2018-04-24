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

/* 
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved. 
 * Qualcomm Atheros Confidential and Proprietary. 
 */ 

/*
 * public API for VAP object.
 */
#ifndef _IEEE80211_APONLY_H_
#define _IEEE80211_APONLY_H_

#include <ath_dev.h>
#include <osif_private.h>
#include <if_athvar.h>
#include <ath_internal.h>

#define ATH_SOFTC_NET80211(_ic)         ((struct ath_softc_net80211 *)(_ic))
#define ATH_DEV_TO_SC(_dev)             ((struct ath_softc *)(_dev))
#define ath_handle_intr_generic(_dev)   scn->sc_ops->handle_intr(_dev) 

#if UMAC_SUPPORT_APONLY
#define do_osif_vap_hardstart(_skb,_dev) do{\
   if(likely(umac_run_aponly(_dev)))\
      return osif_vap_hardstart_aponly(_skb,_dev);\
   else \
      return osif_vap_hardstart_generic(_skb,_dev);\
}while(0)
#define do_ath_netdev_hardstart(_skb,_dev) do{\
   if(likely(lmac_run_aponly(_skb,_dev)))\
      return ath_netdev_hardstart_aponly(_skb,_dev);\
   else \
      return ath_netdev_hardstart_generic(_skb,_dev);\
}while(0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
#define do_ath_isr(_irq,_dev_id) do{\
    if(likely(irq_run_aponly(_dev_id)))\
        return ath_isr_aponly(_irq,_dev_id); \
    else \
        return ath_isr_generic(_irq,_dev_id);\
}while(0)
#else
#define do_ath_isr(_irq,_dev_id,_regs) do{\
    if(likely(irq_run_aponly(_dev_id)))\
        return ath_isr_aponly(_irq,_dev_id,_regs); \
    else \
        return ath_isr_generic(_irq,_dev_id,_regs); \
}while(0)
#endif //if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
#define do_ath_handle_intr(_dev) do{ \
    if(likely(tasklet_run_aponly(_dev)))\
        ath_handle_intr_aponly(_dev);\
    else \
        ath_handle_intr_generic(_dev);\
}while(0)

#else //else UMAC_SUPPORT_APONLY


#define do_ath_netdev_hardstart(_skb,_dev) do{ return ath_netdev_hardstart_generic(_skb,_dev);}while(0)
#define do_osif_vap_hardstart(_skb,_dev) do{ return osif_vap_hardstart_generic(_skb,_dev);}while(0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
#define do_ath_isr(_irq,_dev_id) do{ return ath_isr_generic(_irq,_dev_id);}while(0)
#else
#define do_ath_isr(_irq,_dev_id,_regs) do{ return ath_isr_generic(_irq,_dev_id,_regs);}while(0)
#endif //if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
#define do_ath_handle_intr(_dev) do{ ath_handle_intr_generic(_dev);}while(0)

#endif //if UMAC_SUPPORT_APONLY

extern int ath_netdev_hardstart_aponly(struct sk_buff *skb, 
                                       struct net_device *dev);
extern int osif_vap_hardstart_aponly(struct sk_buff *skb, 
                                     struct net_device *dev);
extern void ath_handle_intr_aponly(ath_dev_t dev);
extern int ath_intr_aponly(ath_dev_t dev);
#ifndef ATH_SUPPORT_HTC
extern irqreturn_t
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
ath_isr_aponly(int irq, void *dev_id);
#else
ath_isr_aponly(int irq, void *dev_id, struct pt_regs *regs);
#endif
#endif

static inline
int umac_run_aponly(struct net_device* dev) 
{
    osif_dev  *osdev = ath_netdev_priv(dev);
    wlan_if_t vap = osdev->os_if;
    enum ieee80211_opmode opmode = ieee80211vap_get_opmode(vap);

    if(osdev->osif_is_mode_offload == 1)
        return 0;

    /*
     * Run aponly code --ONLY-- when all the following conditions are true:
     * (0) Running on Linux (aponly is not currently supported on any other OS)
     * (1) NAWDS disabled
     * (2) WDS disabled 
     * (3) vap is an AP (and not IBSS or STA)
     * (4) On Osprey class devices only (sc_enhanceddmasupport==1)
     * (5) vap is not a Q-WRAP AP
     * (1) & (2) are applicable only if ATH_WDS_SUPPORT_APONLY is disabled
     */

    if(opmode == IEEE80211_M_HOSTAP 
#if !(ATH_WDS_SUPPORT_APONLY)
            &&
#if UMAC_SUPPORT_NAWDS
            vap->iv_nawds.mode == IEEE80211_NAWDS_DISABLED && 
#endif
            !IEEE80211_VAP_IS_WDS_ENABLED(vap) 
#endif /*!(ATH_WDS_SUPPORT_APONLY)*/   
#if ATH_SUPPORT_WRAP
            && !(wlan_is_wrap(vap)) 
#endif
      && vap->iv_aponly) {
        return 1;
    }
    return 0;
}


static inline
int lmac_run_aponly(struct sk_buff *skb,struct net_device* dev) 
{
    enum ieee80211_opmode opmode;
    struct ieee80211_node *ni = wbuf_get_node((wbuf_t)skb);
    struct ieee80211vap *vap = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    struct ieee80211_cb *cb = NULL;

    cb = (struct ieee80211_cb *) skb->cb;
    if (cb->_u.context != (void *) cb->ni) {
        ni = (struct ieee80211_node *) cb->_u.context;
        cb->ni = (struct ieee80211_node *)cb->_u.context;
        cb->_u.context = NULL;
    }
#endif

    /*
     * NB: check for valid node in case kernel directly sends packets
     * on wifiX interface (such as anycast/multicast packets generated by ipv6)
     */
    if (unlikely(ni == NULL)) {
        return 0;
    }

    vap = ni->ni_vap;
    opmode = ieee80211vap_get_opmode(vap);
 

    /*
     * Run aponly code --ONLY-- when all the following conditions are true:
     * (0) Running on Linux (aponly is not currently supported on any other OS)
     * (1) NAWDS disabled
     * (2) WDS disabled 
     * (3) vap is an AP (and not IBSS or STA)
     * (4) vap is not a Q-WRAP AP
     * (1) & (2) are applicable only if ATH_WDS_SUPPORT_APONLY is disabled
     */
    if(opmode == IEEE80211_M_HOSTAP 
#if !(ATH_WDS_SUPPORT_APONLY)             
            &&
#if UMAC_SUPPORT_NAWDS
            vap->iv_nawds.mode == IEEE80211_NAWDS_DISABLED && 
#endif
            !IEEE80211_VAP_IS_WDS_ENABLED(vap)
#endif        
#if ATH_SUPPORT_WRAP
            && !(wlan_is_wrap(vap)) 
#endif
      && vap->iv_aponly) {
        return 1;
    } 
    return 0;
}

static inline
bool irq_run_aponly(void *dev_id)
{
    struct net_device *dev = dev_id;
    struct ath_softc_net80211 *scn;
    struct ieee80211com *ic;

    if (unlikely(dev == NULL))
        return false;

    scn = ath_netdev_priv(dev);

    ic = &scn->sc_ic;

    return ic->ic_aponly;
}

static inline
bool tasklet_run_aponly(ath_dev_t sc_dev)
{
    struct ath_softc_net80211 *scn;
    struct ieee80211com *ic;

    if (unlikely(sc_dev == NULL))
        return false;

    scn = ATH_SOFTC_NET80211( ATH_DEV_TO_SC(sc_dev)->sc_ieee );

    ic = &scn->sc_ic;

    return ic->ic_aponly;
}
#endif //_IEEE80211_APONLY_H_


