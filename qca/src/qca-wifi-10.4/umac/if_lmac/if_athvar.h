/*
 * Copyright (c) 2010, Atheros Communications Inc.
 * All Rights Reserved.
 *
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

/*
 * Defintions for the Atheros Wireless LAN controller driver.
 */
#ifndef _DEV_ATH_ATHVAR_H
#define _DEV_ATH_ATHVAR_H

#include <osdep.h>
#include "ieee80211_var.h"
#include "ieee80211_channel.h"
#include "ieee80211_proto.h"
#include "ieee80211_rateset.h"
#include "ieee80211_regdmn.h"
#include "ieee80211_target.h"
#include "ieee80211_wds.h"
#include "ieee80211_resmgr_oc_scheduler.h"

#include "asf_amem.h"
#include "ath_dev.h"
#include "ath_internal.h"
#include "qdf_lock.h"

#if ATH_SUPPORT_WRAP
/* WRAP SKB marks used by the hooks to optimize */
#define WRAP_ATH_MARK              0x8000

#define WRAP_FLOOD                 0x0001  /*don't change see NF_BR_FLOOD netfilter_bridge.h*/
#define WRAP_DROP                  0x0002  /*mark used to drop short circuited pkt*/
#define WRAP_REFLECT               0x0004  /*mark used to identify reflected multicast*/
#define WRAP_ROUTE                 0x0008  /*mark used allow local deliver to the interface*/

#define WRAP_MARK_FLOOD            (WRAP_ATH_MARK | WRAP_FLOOD)
#define WRAP_MARK_DROP             (WRAP_ATH_MARK | WRAP_DROP)
#define WRAP_MARK_REFLECT          (WRAP_ATH_MARK | WRAP_REFLECT)
#define WRAP_MARK_ROUTE            (WRAP_ATH_MARK | WRAP_ROUTE)

#define WRAP_MARK_IS_FLOOD(_mark)  ((_mark & WRAP_ATH_MARK)?((_mark & WRAP_FLOOD)?1:0):0)
#define WRAP_MARK_IS_DROP(_mark)   ((_mark & WRAP_ATH_MARK)?((_mark & WRAP_DROP)?1:0):0)
#define WRAP_MARK_IS_REFLECT(_mark) ((_mark & WRAP_ATH_MARK)?((_mark & WRAP_REFLECT)?1:0):0)
#define WRAP_MARK_IS_ROUTE(_mark)  ((_mark & WRAP_ATH_MARK)?((_mark & WRAP_ROUTE)?1:0):0)
#endif

#ifndef REMOVE_PKT_LOG
#include "pktlog.h"
#endif

#ifdef ATH_SUPPORT_HTC
struct ath_usb_p2p_action_queue {
    wbuf_t  wbuf;
    struct ath_usb_p2p_action_queue *next;
    int deleted;
};

struct ath_swba_data {
    atomic_t                flags;
    uint64_t              currentTsf;
    uint8_t               beaconPendingCount;
};
#endif

struct ath_cwm;
struct ath_softc_net80211 {
    struct ieee80211com     sc_ic;      /* NB: base class, must be first */
    struct pktlog_handle_t *pl_dev;     /* Must be in the second position */
    ath_dev_t               sc_dev;     /* Atheros device handle */
    struct ath_ops          *sc_ops;    /* Atheros device callback table */

    void                    (*sc_node_cleanup)(struct ieee80211_node *);
    void                    (*sc_node_free)(struct ieee80211_node *);

    osdev_t                 sc_osdev;   /* handle to use OS-independent services */
    /*
     * handle for code that uses adf version of OS
     * abstraction primitives
     */
    qdf_device_t   	    qdf_dev;
    u_int8_t                wifi_num;
    int                     sc_nstavaps; /* # of station vaps */
#if ATH_SUPPORT_WRAP
    int                     sc_nwrapvaps; /* # of WRAP vaps */
    int                     sc_npstavaps; /* # of ProxySTA vaps */
    int                     sc_nscanpsta; /* # of scan-able non-Main ProxySTA vaps */
    struct ieee80211vap     *sc_mcast_recv_vap; /* the ProxySTA vap to receive multicast frames */
#endif
    u_int                   sc_syncbeacon:1,    /* sync/resync beacon timers */
                            sc_isscan:1,        /* scanning */
                            sc_splitmic:1,      /* split TKIP MIC keys */
                            sc_mcastkey:1,      /* mcast key cache search */
                            sc_in_delete:1;     /* don't add any more VAPs */
    u_int32_t               sc_prealloc_idmask;   /* preallocated vap id bitmap: can only support 32 vaps */
    u_int32_t               macreq_enabled;     /* user mac request feature enable/disable */
    atomic_t                sc_dev_enabled;    /* dev is enabled */

    int                     sc_ac2q[WME_NUM_AC];/* WMM AC -> h/w qnum */
    int                     sc_uapsd_qnum;      /* UAPSD h/w qnum */
    int                     sc_beacon_qnum;     /* beacon h/w qnum */
    u_int32_t               cached_ic_flags;

    struct ieee80211_node	*sc_keyixmap[ATH_KEYMAX];/* key ix->node map */

    struct ath_cwm          *sc_cwm;            /* Channel Width Management */
    TAILQ_HEAD(ath_amsdu_txq,ath_amsdu_tx)    sc_amsdu_txq;    /* amsdu tx requests */
    struct ath_timer        sc_amsdu_flush_timer; /* amsdu flush timer */
    spinlock_t              amsdu_txq_lock;    /* amsdu spinlock */
    spinlock_t              sc_keyixmap_lock;  /* keyix map spinlock */
    unsigned long           sc_keyixmap_lock_flags;
    u_int                   sc_wow_enabled;
    u_int                   sc_wow_wake_from_wow;
#ifdef ATH_SUPPORT_HTC
    u_int                   sc_htc_wmm_update_enabled;
    struct ath_usb_p2p_action_queue *sc_p2p_action_queue_head;
    struct ath_usb_p2p_action_queue *sc_p2p_action_queue_tail;
    spinlock_t              p2p_action_queue_lock;
    unsigned long           p2p_action_queue_flags;
    struct ath_swba_data    sc_htc_swba_data;
    u_int32_t               sc_htc_nodekickmask;
    u_int32_t               sc_htc_txRateKbps;  /* per-device xmit rate updated by WMI_TXRATE_EVENTID event */
    int                     sc_htc_delete_in_progress; /* flag to indicate delete in progress */
#endif

    struct {
        asf_amem_instance_handle handle;
        qdf_spinlock_t        lock;
    } amem;
#if ATH_SUPPORT_WIFIPOS
    int                     sc_wifipos_oc_qnum;     /* wifipos OC h/w qnum */
    int                     sc_wifipos_hc_qnum;  /* wifipos hc  h/w qnum */
#endif
#if PCI_INTERRUPT_WAR_ENABLE
    os_timer_t int_status_poll_timer;
    u_int32_t int_status_poll_interval;
    u_int32_t int_scheduled_cnt;
    u_int32_t pre_int_scheduled_cnt;
#endif
#if UNIFIED_SMARTANTENNA
    int       enable_smart_antenna_da;        /* Enable Smart antenna for direct attach*/
#endif
};
#define ATH_SOFTC_NET80211(_ic)     ((struct ath_softc_net80211 *)(_ic))

struct ath_vap_net80211 {
    struct ieee80211vap         av_vap;     /* NB: base class, must be first */
    struct ath_softc_net80211   *av_sc;     /* back pointer to softc */
    int                         av_if_id;   /* interface id */
#if ATH_SUPPORT_WRAP
    u_int32_t                   av_is_psta:1,   /* is ProxySTA VAP */
                                av_is_mpsta:1,  /* is Main ProxySTA VAP */
                                av_is_wrap:1,   /* is WRAP VAP */
                                av_use_mat:1;   /* use MAT for this VAP */
    struct ieee80211_key        av_psta_key;    /* ProxySTA or WRAP key */
    u_int8_t                    av_mat_addr[IEEE80211_ADDR_LEN];    /* MAT addr */
#endif

    struct ieee80211_beacon_offsets av_beacon_offsets;

};
#define ATH_VAP_NET80211(_vap)      ((struct ath_vap_net80211 *)(_vap))

#define ATH_P2PDEV_IF_ID 1

/*
 * Units in kbps for the an_lasttxrate and an_lastrxrate fields. These
 * two fields are only 16 bits wide and the max. rate is 600,000 kbps.
 * LAST_RATE_UNITS is used to scale these two fields to fit into 16 bits.
 */
#define LAST_RATE_UNITS     16

struct ath_node_net80211 {
    struct ieee80211_node       an_node;     /* NB: base class, must be first */
    ath_node_t                  an_sta;
    struct ath_ff               *an_ff;       /* fast frame buf */
    struct ath_amsdu            *an_amsdu;    /* AMSDU frame buf */
};

#if event-mechanism
enum ath_event_type {
    ATH_DFS_WAIT_CLEAR_EVENT,
    ATH_END_EVENT,
};

typedef struct ath_net80211_event {

    enum ath_event_type ath_event_id;
    void *ath_event_data;
} ATH_NET80211_EVENT;
#endif

#define ATH_NODE_NET80211(_ni)      ((struct ath_node_net80211 *)(_ni))

#define NET80211_HANDLE(_ieee)      ((struct ieee80211com *)(_ieee))

#define ATH_TSF_TIMER(_tsf_timer)   ((struct ath_gen_timer *)(_tsf_timer))
#define NET80211_TSF_TIMER(_tsf_timer)  \
                                    ((struct ieee80211_tsf_timer *)(_tsf_timer))
#define ATH_TSF_TIMER_FUNC(_tsf_timer_func)  \
                                    ((ath_hwtimer_function)(_tsf_timer_func))

#define ATH_BCN_NOTIFY_FUNC(_tx_beacon_notify_func)  \
                                    ((ath_notify_tx_beacon_function)(_tx_beacon_notify_func))

#define ATH_VAP_NOTIFY_FUNC(_vap_change_notify_func)  \
                                    ((ath_vap_info_notify_func)(_vap_change_notify_func))

int ath_attach(u_int16_t devid, void *base_addr, struct ath_softc_net80211 *scn, osdev_t osdev,
               struct ath_reg_parm *ath_conf_parm, struct hal_reg_parm *hal_conf_parm, IEEE80211_REG_PARAMETERS *ieee80211_conf_parm);
int ath_detach(struct ath_softc_net80211 *scn);
int ath_resume(struct ath_softc_net80211 *scn);
int ath_suspend(struct ath_softc_net80211 *scn);
int ath_vap_down(struct ieee80211vap *vap);
int ath_vap_dfs_cac(struct ieee80211vap *vap);
int ath_vap_stopping(struct ieee80211vap *vap);
int ath_net80211_rx(ieee80211_handle_t ieee, wbuf_t wbuf, ieee80211_rx_status_t *rx_status, u_int16_t keyix);
int ath_get_netif_settings(ieee80211_handle_t);
void ath_mcast_merge(ieee80211_handle_t, u_int32_t mfilt[2]);
int ath_tx_send(wbuf_t wbuf);
int ath_tx_mgt_send(struct ieee80211com *ic, wbuf_t wbuf);
int ath_tx_prepare(struct ath_softc_net80211 *scn, wbuf_t wbuf, int nextfraglen, ieee80211_tx_control_t *txctl);
WIRELESS_MODE ath_ieee2wmode(enum ieee80211_phymode mode);
u_int32_t ath_set_ratecap(struct ath_softc_net80211 *scn, struct ieee80211_node *ni,
                         struct ieee80211vap *vap);
//int16_t ath_net80211_get_noisefloor(struct ieee80211com *ic, struct ieee80211_channel *chan);
void ath_net80211_dfs_test_return(ieee80211_handle_t ieee, u_int8_t ieeeChan);
void ath_net80211_mark_dfs(ieee80211_handle_t, struct ieee80211_channel *);
void ath_net80211_enable_radar_dfs(ieee80211_handle_t ieee);
void ath_net80211_change_channel(ieee80211_handle_t ieee, struct ieee80211_channel *chan);
void ath_net80211_switch_mode_static20(ieee80211_handle_t ieee);
void ath_net80211_switch_mode_dynamic2040(ieee80211_handle_t ieee);
int  ath_net80211_input(ieee80211_node_t node, wbuf_t wbuf, ieee80211_rx_status_t *rx_status);
#if defined(MAGPIE_HIF_GMAC) || defined(MAGPIE_HIF_USB)
u_int32_t ath_net80211_htc_node_getrate(const struct ieee80211_node *ni, u_int8_t type);
#endif

void ath_net80211_bf_rx(struct ieee80211com *ic, wbuf_t wbuf, ieee80211_rx_status_t *status);

int ieee80211_extended_ioctl_chan_switch (struct net_device *dev,
                         struct ieee80211com *ic, caddr_t *param);
int ieee80211_extended_ioctl_chan_scan (struct net_device *dev,
                struct ieee80211com *ic, caddr_t *param);
int ieee80211_extended_ioctl_rep_move (struct net_device *dev,
                struct ieee80211com *ic, caddr_t *param);

static INLINE void
ath_node_set_fixedrate_proc(struct ath_softc_net80211 *scn,
                            const u_int8_t macaddr[IEEE80211_ADDR_LEN],
                            u_int8_t fixed_ratecode)
{
    struct ieee80211_node *ni;
    struct ath_node *an;
    struct ath_softc *sc = ATH_DEV_TO_SC(scn->sc_dev);
    struct ieee80211com *ic = (struct ieee80211com *)sc->sc_ieee;

#if IEEE80211_DEBUG_REFCNT
    if (!(ic->ic_ieee80211_find_node_debug && ic->ic_ieee80211_unref_node)) {
        printk("%s: ic->ic_ieee80211_find_node_debug %p ic->ic_ieee80211_unref_node %p\n",
            __func__, ic->ic_ieee80211_find_node_debug, ic->ic_ieee80211_unref_node);
        return;
    }
    ni = ic->ic_ieee80211_find_node_debug(&ic->ic_sta, macaddr, __func__, __LINE__, __FILE__);
#else
    if (!(ic->ic_ieee80211_find_node && ic->ic_ieee80211_unref_node)) {
        printk("%s: ic->ic_ieee80211_find_node %p ic->ic_ieee80211_unref_node %p\n",
            __func__, ic->ic_ieee80211_find_node, ic->ic_ieee80211_unref_node);
        return;
    }
    ni = IC_IEEE80211_FIND_NODE(ic, &ic->ic_sta, macaddr);
#endif
    if (!ni) {
        printk("%s: No node found!\n", __func__);
        return;
    }

    an = (struct ath_node *)((ATH_NODE_NET80211(ni))->an_sta);
    if (an && sc->sc_ath_ops.node_setfixedrate)
        sc->sc_ath_ops.node_setfixedrate(an, fixed_ratecode);
    /*
     * find_node has incremented the node reference count.
     * take care of that
     */
    ic->ic_ieee80211_unref_node (ni);
    return;
}

#define ATH_DEFINE_TXCTL(_txctl, _wbuf)    \
    ieee80211_tx_control_t ltxctl;         \
    ieee80211_tx_control_t *_txctl = &ltxctl
#if ATH_SUPPORT_CFEND
wbuf_t ath_net80211_cfend_alloc(ieee80211_handle_t ieee);
#endif
#if UMAC_SUPPORT_OPMODE_APONLY
#define ath_net80211_rx_monitor(_ic, _wbuf, _rxs)
#else
void ath_net80211_rx_monitor(struct ieee80211com *ic, wbuf_t wbuf, ieee80211_rx_status_t *rx_status);
#endif

#ifdef ATH_SUPPORT_TxBF
#define ath_update_txbf_tx_status( _ts, _tx_status)         \
        do {                                                \
            (_ts).ts_txbfstatus = (_tx_status)->txbf_status;\
            (_ts).ts_tstamp     = (_tx_status)->tstamp;     \
        } while (0)

#define ath_txbf_update_rx_status( _rs, _rx_status) \
        (_rs)->rs_rpttstamp = (_rx_status)->rpttstamp
#else
#define ath_update_txbf_tx_status(_ts, _tx_status)
#define ath_txbf_update_rx_status(_rs, _rx_status)
#endif

enum ieee80211_opmode ieee80211_new_opmode(struct ieee80211vap *vap, bool vap_active);
int osif_vap_hardstart_generic(struct sk_buff *skb, struct net_device *dev);
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
int ieee80211_add_hmmc(struct ieee80211vap *vap, u_int32_t ip, u_int32_t mask);
int ieee80211_del_hmmc(struct ieee80211vap *vap, u_int32_t ip, u_int32_t mask);
#endif /* ATH_SUPPORT_HYFI_ENHANCEMENTS */

#if ATH_SUPPORT_HYFI_ENHANCEMENTS
void ieee80211_ald_update_phy_error_rate(struct ath_linkdiag *ald,
                                   u_int32_t new_phyerr);
#endif

#endif /* _DEV_ATH_ATHVAR_H  */
