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
 * Definitions for the HTC module
 */
#ifndef ATH_HTC_WMI_H
#define ATH_HTC_WMI_H

#ifdef ATH_SUPPORT_HTC

#include "athdefs.h"
#include "a_osapi.h"
#ifdef A_TYPE_IN_ADF
#include "a_types.h"
#endif
#include "htc_host_api.h"
#include "host_target_interface.h"

/*
 * Data transmit endpoint state. One or more of these exists for each
 * hardware transmit queue. Packets sent to us from above
 * are assigned to queues based on their priority. Not all
 * devices support a complete set of hardware transmit queues.
 * For those devices the array sc_ac2q will map multiple
 * priorities to fewer hardware queues (typically all to one
 * hardware queue).
 */
 
/* Note: We might need to uncomment the mark parts */
struct ath_txep {
    u_int32_t ep_num;                          /* Endpoint number */
    u_int32_t hwq_num;                         /* hardware q number */	
    //asf_tailq_head(,ath_buf) ep_bufq;          /* transmit queue */
    u_int32_t ep_lockcount;
    u_int32_t ep_unlockcount;
    unsigned long ep_lockflags;
    u_int32_t ep_depth;                        /* endpoint queue depth */
#ifdef MAGPIE_HIF_GMAC    
    u_int32_t ep_max;
#endif    
    u_int32_t ep_totalqueued;                  /* total ever queued */
    struct ath_buf *ep_linkbuf;	               /* virtual addr of last buffer*/

    spinlock_t ep_lock;                 /* lock on q and link */
    TAILQ_HEAD(,ath_atx_ac) ep_acq;
    //asf_tailq_head(,ath_atx_ac) ep_acq;
    //asf_tailq_head(,ath_atx_ac) ep_fltrq;
};

struct ath_htc_rx_status {
    u_int64_t   rs_tstamp;    /* h/w assigned timestamp */

    u_int16_t   rs_datalen;    /* rx frame length */
    u_int8_t    rs_status;    /* rx status, 0 => recv ok */
    u_int8_t    rs_phyerr;    /* phy error code */
    u_int8_t    rs_rssi;    /* rx frame RSSI */

    /* Additional receive status */
    u_int8_t      rs_rssi_ctl0;   /* rx frame RSSI [ctl, chain 0] */
    u_int8_t      rs_rssi_ctl1;   /* rx frame RSSI [ctl, chain 1] */
    u_int8_t      rs_rssi_ctl2;   /* rx frame RSSI [ctl, chain 2] */
    u_int8_t      rs_rssi_ext0;   /* rx frame RSSI [ext, chain 0] */
    u_int8_t      rs_rssi_ext1;   /* rx frame RSSI [ext, chain 1] */
    u_int8_t      rs_rssi_ext2;   /* rx frame RSSI [ext, chain 2] */

	u_int8_t	  rs_keyix;	/* key cache index */
    u_int8_t	rs_rate;	/* h/w receive rate index */
	u_int8_t	rs_antenna;	/* antenna information */
	u_int8_t	rs_more;	/* more descriptors follow */
    u_int8_t    rs_isaggr;      /* is part of the aggregate */
    
    u_int8_t    rs_moreaggr;    /* more frames in aggr to follow */
    u_int8_t    rs_num_delims;  /* number of delims in aggr */
    u_int8_t    rs_flags;       /* misc flags */
    
    u_int8_t    rs_dummy;       /* to make memeory alignment, it should be added 
                                                                       one dummy*/
    u_int32_t   evm0;
    u_int32_t   evm1;           /* evm bytes */
    u_int32_t   evm2;
};

typedef enum {
    TX_EP_COMMAND      = 0,
    TX_EP_BEACON       = 1,
    TX_EP_CAB          = 2,
    TX_EP_UAPSD        = 3,
    TX_EP_MGMT         = 4,
    TX_EP_VOICE_DATA   = 5,     /* data xmit q's */
    TX_EP_VIDEO_DATA   = 6,     /* data xmit q's */
    TX_EP_BE_DATA      = 7,     /* data xmit q's */
    TX_EP_BK_DATA      = 7,     /* data xmit q's */
} TX_EP_QUEUE;

enum ath_htc_phymode
{
    ATH_HTC_MODE_AUTO      = 0,
    ATH_HTC_MODE_11A       = 1,
    ATH_HTC_MODE_11B       = 2,
    ATH_HTC_MODE_11G       = 3,
    ATH_HTC_MODE_FH        = 4,
    ATH_HTC_MODE_TURBO_A   = 5,
    ATH_HTC_MODE_TURBO_G   = 6,
    ATH_HTC_MODE_11NA      = 7,
    ATH_HTC_MODE_11NG      = 8
};

#define ATH_HTC_HDRSPACE            (sizeof(HTC_FRAME_HDR))
#define ATH_HTC_RESERVED            4
#define ATH_HTC_TX_FRAME_HDRSPACE   (sizeof(struct __data_header))
#define ATH_HTC_QOSNULL_LEN         28

#define ATH_HTC_WMI_TIMEOUT_DEFAULT 100

#define ATH_HTC_MAX_VAP_NUM         5

#if defined(MAGPIE_HIF_GMAC)
#define ATH_HTC_MAX_NODE_NUM        16

#elif defined(MAGPIE_HIF_USB) && defined(ENCAP_OFFLOAD)
#define ATH_HTC_MAX_NODE_NUM        13
#else
#define ATH_HTC_MAX_NODE_NUM        8
#endif

#define ATH_HTC_WME_NUM_TID         8

#if defined(MAGPIE_HIF_GMAC) || defined(MAGPIE_HIF_USB)
u_int32_t ath_wmi_node_getrate(ath_dev_t dev, void *target, int size);
#endif
void ath_wmi_beacon(ath_dev_t dev, u_int64_t currentTsf, u_int8_t beaconPendingCount, u_int8_t update);
void ath_wmi_bmiss(ath_dev_t dev);
void ath_wmi_add_vap(ath_dev_t dev, void *target, int size);
void ath_wmi_add_node(ath_dev_t dev, void *target, int size);
void ath_wmi_delete_node(ath_dev_t dev, void *target, int size);
void ath_wmi_update_node(ath_dev_t dev, void *target, int size);
#if ATH_K2_PS_BEACON_FILTER
void ath_wmi_beacon_filter_enable(struct ath_softc *sc);
#endif
void ath_wmi_ic_update_target(ath_dev_t dev, void *target, int size);
void ath_htc_rx(ath_dev_t, wbuf_t);
int ath_htc_open(ath_dev_t dev, HAL_CHANNEL *initial_chan);
int ath_htc_initialize_target_q(struct ath_softc *sc);
void ath_htc_host_txep_init(struct ath_softc *sc);
int ath_htc_rx_init(ath_dev_t dev, int nbufs);
#ifdef ATH_HTC_TX_SCHED
int  ath_htc_tx_init(ath_dev_t dev, int nbufs);
void host_htc_sched_next(osdev_t osdev, int epid );
int  ath_htc_tx_cleanup(ath_dev_t dev);
void ath_htc_tx_tasklet(void* data);
void ath_htc_uapsd_creditupdate_tasklet(void* data);
void ath_htc_txep_drain(struct ath_softc *sc, struct ath_txep *txep);
void ath_txep_resume_tid(struct ath_softc *sc, ath_atx_tid_t *tid);
void ath_txep_pause_tid(struct ath_softc *sc, ath_atx_tid_t *tid);
void ath_htc_uapsd_credit_update(ath_dev_t dev, ath_node_t node);
#else
#define ath_htc_tx_init(dev, nbufs)
#define host_htc_sched_next(dev, epid)
#define ath_htc_tx_cleanup(dev)
#define ath_htc_tx_tasklet                      (0)
#define ath_htc_uapsd_creditupdate_tasklet      (0)
#define ath_htc_uapsd_credit_update             (0)
#endif
void ath_wmi_intr_disable(struct ath_softc *sc, u_int32_t mask);
void ath_wmi_abort_txq(struct ath_softc *sc, HAL_BOOL fastcc);
void ath_wmi_rx_link(struct ath_softc *sc);
void ath_wmi_drain_txq(struct ath_softc *sc);
void ath_wmi_stop_recv(struct ath_softc *sc);
void ath_wmi_start_recv(struct ath_softc *sc);
void ath_wmi_intr_enable(struct ath_softc *sc, u_int32_t mask);
void ath_wmi_set_mode(struct ath_softc *sc, u_int16_t phymode);
void ath_wmi_rc_node_update(ath_dev_t dev, struct ath_node *an, int isnew, unsigned int capflag, struct ieee80211_rateset *rates, struct ieee80211_rateset *htrates);
HAL_BOOL ath_wmi_aborttxep(struct ath_softc *sc);
HAL_BOOL ath_wmi_abortrecv(struct ath_softc *sc);
int ath_htc_tx_start(ath_dev_t dev, wbuf_t wbuf, ieee80211_tx_control_t *txctl);
void ath_wmi_get_target_stats(ath_dev_t dev, HTC_HOST_TGT_MIB_STATS * stats);
void ath_htc_tasklet(void* data);
int ath_htc_rx_tasklet(ath_dev_t dev, int flush);
void ath_wmi_aggr_enable(ath_dev_t dev, struct ath_node *an, u_int8_t tidno, u_int8_t aggr_enable);
int ath_htc_startrecv(struct ath_softc *sc);
HAL_BOOL ath_htc_stoprecv(struct ath_softc *sc);
void ath_htc_txq_update(ath_dev_t dev, int qnum, HAL_TXQ_INFO *qi);
void ath_wmi_delete_vap(ath_dev_t dev, void *target, int size);
void ath_schedule_wmm_update(ath_dev_t dev);
void ath_htc_tx_schedule(osdev_t, int epid);
void ath_wmi_set_desc_tpc(ath_dev_t dev, u_int8_t enable);
#if ENCAP_OFFLOAD
void ath_wmi_update_vap(ath_dev_t dev, void *target, int size);
#else
#define ath_wmi_update_vap(_dev, _target, _size)   (0)
#endif
#ifdef ATH_SUPPORT_UAPSD
int ath_htc_process_uapsd_trigger(ath_dev_t dev, ath_node_t node, u_int8_t maxsp, u_int8_t ac, u_int8_t flush,  bool *sent_eosp, u_int8_t maxqdepth);
void ath_htc_tx_uapsd_node_cleanup(struct ath_softc *sc, struct ath_node *an);
#endif
void ath_wmi_generc_timer(ath_dev_t dev, u_int32_t trigger_mask, u_int32_t thresh_mask, u_int32_t curr_tsf);
void ath_wmi_set_generic_timer(struct ath_softc *sc, int index, u_int32_t timer_next, u_int32_t timer_period, int mode);
void ath_wmi_pause_ctrl(ath_dev_t dev, ath_node_t node, u_int32_t pause_status);

#ifdef ATH_HTC_TX_SCHED
#define ATH_HTC_SET_CALLBACK_TABLE(_ath_ar_ops)             \
    {                                                       \
        _ath_ar_ops.open = ath_htc_open;                    \
        _ath_ar_ops.tx = ath_htc_tx_start;                  \
        _ath_ar_ops.rx_init = ath_htc_rx_init;              \
        _ath_ar_ops.tx_init = ath_htc_tx_init;              \
        _ath_ar_ops.tx_cleanup = ath_htc_tx_cleanup;        \
        _ath_ar_ops.process_uapsd_trigger = ath_htc_process_uapsd_trigger; \
    }


/* Host Scheduling function */
#define ATH_AC_2_TXEP(_sc, _ac)      (_sc)->sc_ac2ep[(_ac)]
#define ATH_TID_2_TXEP(_sc, _tidno)   ATH_AC_2_TXEP(_sc, TID_TO_WME_AC(_tidno))

#define ATH_TXEP_LOCK_INIT(_ep)      spin_lock_init(&(_ep)->ep_lock)
#define ATH_TXEP_LOCK(_ep)    do{os_tasklet_lock(&(_ep)->ep_lock, \
        (_ep)->ep_lockflags);}while(0)
#define ATH_TXEP_UNLOCK(_ep)  do{os_tasklet_unlock(&(_ep)->ep_lock, \
        (_ep)->ep_lockflags);}while(0)

#define ATH_TXEP_LOCK_BH(_ep)    spin_lock_dpc(&(_ep)->ep_lock)
#define ATH_TXEP_UNLOCK_BH(_ep)  spin_unlock_dpc(&(_ep)->ep_lock)
#define ATH_MAX_TID_FLUSH 16
#define TID_SWITCH_LOGIC 1
#define ATH_STATUS_TID_EMPTY 1
#define ATH_STATUS_HTC_TXEPQ_FULL 2
#define HTC_TXEP_QUEUE_FULL 2
#define ATH_STATUS_TID_MAXFLUSH  3


#define TAILQ_DEQ(_q, _elm, _field) do {        \
            (_elm) = TAILQ_FIRST((_q));             \
            if (_elm) {                             \
                            TAILQ_REMOVE((_q), (_elm), _field); \
                        }                                       \
        } while (0)
#define TXEP_TAILQ_INIT(_txep) TAILQ_INIT(&(_txep)->ep_acq);



#else
#ifdef ATH_SUPPORT_UAPSD
#define ATH_HTC_SET_CALLBACK_TABLE(_ath_ar_ops)             \
    {                                                       \
        _ath_ar_ops.open = ath_htc_open;                    \
        _ath_ar_ops.tx = ath_htc_tx_start;                  \
        _ath_ar_ops.rx_init = ath_htc_rx_init;              \
        _ath_ar_ops.process_uapsd_trigger = ath_htc_process_uapsd_trigger; \
    }
#else
#define ATH_HTC_SET_CALLBACK_TABLE(_ath_ar_ops)             \
    {                                                       \
        _ath_ar_ops.open = ath_htc_open;                    \
        _ath_ar_ops.tx = ath_htc_tx_start;                  \
        _ath_ar_ops.rx_init = ath_htc_rx_init;              \
    }
#endif /* #ifdef ATH_SUPPORT_UAPSD */

#define ATH_TXEP_LOCK_INIT(_ep)      
#define TXEP_TAILQ_INIT(_txep) 


#endif

#define ATH_HTC_SET_HANDLE(_sc, _osdev)                     \
    {                                                       \
        _sc->sc_host_wmi_handle = _osdev->host_wmi_handle;  \
        _sc->sc_host_htc_handle = _osdev->host_htc_handle;  \
    }
#define ATH_HTC_SET_EPID(_sc, _osdev)                       \
    {                                                       \
        _sc->sc_beacon_ep       = _osdev->beacon_ep;        \
        _sc->sc_cab_ep          = _osdev->cab_ep;           \
        _sc->sc_data_BE_ep      = _osdev->data_BE_ep;       \
        _sc->sc_data_BK_ep      = _osdev->data_BK_ep;       \
        _sc->sc_data_VI_ep      = _osdev->data_VI_ep;       \
        _sc->sc_data_VO_ep      = _osdev->data_VO_ep;       \
        _sc->sc_mgmt_ep         = _osdev->mgmt_ep;          \
        _sc->sc_uapsd_ep        = _osdev->uapsd_ep;         \
    }
    
#define ATH_HTC_SETMODE(_sc, _mode)                                 \
    {                                                               \
        if( _mode == WIRELESS_MODE_11a ||                           \
            _mode == WIRELESS_MODE_108a ||                          \
            _mode == WIRELESS_MODE_11NA_HT20 ||                     \
            _mode == WIRELESS_MODE_11NA_HT40PLUS ||                 \
            _mode == WIRELESS_MODE_11NA_HT40MINUS) {                \
            ath_wmi_set_mode(_sc, cpu_to_be16(ATH_HTC_MODE_11NA));  \
        } else {                                                    \
            ath_wmi_set_mode(_sc, cpu_to_be16(ATH_HTC_MODE_11NG));  \
        }                                                           \
    }

#define ATH_HTC_TXRX_STOP(_sc, _fastcc)         \
    {                                           \
        if (_fastcc == AH_TRUE) {               \
            ath_wmi_aborttxep(_sc);             \
            if (! _sc->sc_invalid) {            \
                ath_wmi_abort_txq(_sc, _fastcc);\
            }                                   \
            ath_wmi_abortrecv(_sc);             \
        } else {                                \
            ath_wmi_drain_txq(_sc);             \
            ath_wmi_stop_recv(_sc);             \
        }                                       \
    }
#define ATH_HTC_ABORTTXQ(_sc)  ath_wmi_abort_txq(_sc, 0)
#define ATH_HTC_SET_BCNQNUM(_sc, _qnum)              (_sc->sc_ep2qnum[TX_EP_BEACON] = _qnum)

#define ATH_HTC_DRAINTXQ(_sc)                   \
    {                                           \
        ath_wmi_drain_txq(_sc);                 \
    }

#else /* ATH_SUPPORT_HTC */

#define ath_wmi_beacon(dev, beaconPendingCount, update)
#define ath_wmi_add_vap(dev, target, size)
#define ath_wmi_add_node(dev, target, size)
#define ath_wmi_delete_node(dev, target, size)
#define ath_wmi_ic_update_target(dev, target, size)
#define ath_htc_rx(dev, wbuf)
#define ath_htc_open(dev, initial_chan)
#define ath_htc_initialize_target_q(sc)
#define ath_htc_host_txep_init(sc)
#define ath_htc_rx_init(dev, nbufs)
#define ath_htc_tx_init(dev, nbufs)
#define host_htc_sched_next(dev, nbufs)
#define ath_htc_tx_cleanup(dev)
#define ath_wmi_intr_disable(sc, mask)
#define ath_wmi_abort_txq(sc, fastcc)
#define ath_wmi_rx_link(sc)
#define ath_wmi_drain_txq(sc)
#define ath_wmi_stop_recv(sc)
#define ath_wmi_start_recv(sc)
#define ath_wmi_intr_enable(sc, mask)
#define ath_wmi_set_mode(sc, phymode)
#define ath_wmi_rc_node_update(dev, an, isnew, capflag, rates, htrates);
#define ath_wmi_aborttxep(sc)                   (AH_TRUE)
#define ath_wmi_abortrecv(sc)                   (AH_TRUE)
#define ath_htc_tx_start(dev, wbuf, txctl)      (0)
#define ath_htc_tx_tasklet                      (0)
#define ath_htc_uapsd_creditupdate_tasklet      (0)
#define ath_htc_uapsd_credit_update             (0)
#define ath_htc_tasklet                         (0)
#define ath_htc_rx_tasklet(dev, flush)          (0)
#define ath_wmi_aggr_enable(dev, an, tidno, aggr_enable)
#define ath_htc_startrecv(sc)                   (0)
#define ath_htc_stoprecv(sc)                    (AH_TRUE)
#define ath_htc_txq_update(dev, qnum, qi)
#define ath_wmi_delete_vap(dev, target, size)
#define ath_wmi_set_desc_tpc(dev, enable)
#define ath_wmi_update_vap(dev, target, size)   (0)
#ifdef ATH_SUPPORT_UAPSD
#define ath_htc_process_uapsd_trigger(dev, node, maxsp, ac, flush, maxqdepth)
#define ath_htc_tx_uapsd_node_cleanup(sc, an)
#endif
#define ath_wmi_generc_timer(dev, trigger_mask, thresh_mask)
#define ath_wmi_set_generic_timer(sc, index, timer_next, timer_period, mode)
#define ath_wmi_pause_ctrl(dev, an, pause_status)

#define ATH_HTC_SET_CALLBACK_TABLE(_ath_ar_ops)
#define ATH_TXEP_LOCK_INIT(_ep)      
#define TXEP_TAILQ_INIT(_txep) 


#define ATH_HTC_SET_HANDLE(_sc, _osdev)
#define ATH_HTC_SET_EPID(_sc, _osdev)
#define ATH_HTC_SETMODE(_sc, _mode)
#define ATH_HTC_TXRX_STOP(_sc, _fastcc)
#define ATH_HTC_SET_BCNQNUM(_sc, _qnum)
#define ATH_HTC_DRAINTXQ(_sc)
#define ATH_HTC_ABORTTXQ(_sc)
#endif /* ATH_SUPPORT_HTC */

#endif /* ATH_HTC_WMI_H */

