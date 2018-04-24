/*
 *  Copyright (c) 2008 Atheros Communications Inc. 
 * All Rights Reserved.
 * 
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */
/*
 * A-MSDU
 */
#include "if_athvar.h"
#include "if_ath_amsdu.h"
#include "if_llc.h"
#include "if_upperproto.h"
#include "ath_timer.h"
#include "if_ath_htc.h"
#include <if_athproto.h>
#ifdef ATH_AMSDU
/*
 * This routine picks an AMSDU buffer, calls the platform specific 802.11 layer for
 * WLAN encapsulation and then dispatches it to hardware for transmit.
 */
void
ath_amsdu_stageq_flush(struct ath_softc_net80211 *scn, struct ath_amsdu_tx *amsdutx)
{
    struct ieee80211_node *ni;
    struct ieee80211com *ic;
    wbuf_t wbuf;
    ATH_AMSDU_TXQ_LOCK(scn);
    wbuf = amsdutx->amsdu_tx_buf;
    if (!wbuf) {
        ATH_AMSDU_TXQ_UNLOCK(scn);
        return;
    }
    amsdutx->amsdu_tx_buf = NULL;
    ATH_AMSDU_TXQ_UNLOCK(scn);
    ni = wbuf_get_node(wbuf);
    ic = ni->ni_ic;
    /*
     * Encapsulate the packet for transmission
     */
    wbuf = ieee80211_encap(ni, wbuf);
    if (wbuf == NULL) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s[%d] : ERROR: ieee80211_encap ret NULL\n", __func__, __LINE__);
        return;
    }
    /* There is only one wbuf to send */
    if (wbuf != NULL) {
        int error = 0;

        ATH_DEFINE_TXCTL(txctl, wbuf);
        HTC_WBUF_TX_DELCARE

        txctl->iseap = 0;			
        /* prepare this frame */
        if (ath_tx_prepare(scn, wbuf, 0, txctl) != 0) {
            goto bad;
        }

        HTC_WBUF_TX_DATA_PREPARE(ic, scn);
        
        if (error == 0) {
            /* send this frame to hardware */
            txctl->an = (ATH_NODE_NET80211(ni))->an_sta;
            if (scn->sc_ops->tx(scn->sc_dev, wbuf, txctl) != 0)
            {
                goto bad;
            } else {
                HTC_WBUF_TX_DATA_COMPLETE_STATUS(ic);
            }
        }
    }
    return;
bad:
    /* drop rest of the un-sent fragments */
    if (wbuf != NULL) {
        IEEE80211_TX_COMPLETE_WITH_ERROR(wbuf);
    }
}
void
ath_amsdu_tx_drain(struct ath_softc_net80211 *scn)
{
    struct ath_amsdu_tx *amsdutx;
    wbuf_t wbuf;
    do {
        ATH_AMSDU_TXQ_LOCK(scn);
        amsdutx = TAILQ_FIRST(&scn->sc_amsdu_txq);
        if (amsdutx == NULL) {
            /* nothing to process */
            ATH_AMSDU_TXQ_UNLOCK(scn);
            break;
        }
        TAILQ_REMOVE(&scn->sc_amsdu_txq, amsdutx, amsdu_qelem);
        amsdutx->sched = 0;
        wbuf = amsdutx->amsdu_tx_buf;
        amsdutx->amsdu_tx_buf = NULL;
        ATH_AMSDU_TXQ_UNLOCK(scn);
        if (wbuf != NULL) {
            IEEE80211_TX_COMPLETE_WITH_ERROR(wbuf);
        }
    } while (!TAILQ_EMPTY(&scn->sc_amsdu_txq));
}
/*
 * This global timer routine checks a queue for posted AMSDU events.
 * For every AMSDU that we started, we add an event to this queue.
 * When the timer expires, it sends out all outstanding AMSDU bufffers.
 * We want to make sure that no buffer is sitting around for too long.
 */
int
ath_amsdu_flush_timer(void *arg)
{
    struct ath_softc_net80211 *scn = (struct ath_softc_net80211 *)arg;
    struct ath_amsdu_tx *amsdutx;
    do {
        ATH_AMSDU_TXQ_LOCK(scn);
        amsdutx = TAILQ_FIRST(&scn->sc_amsdu_txq);
        if (amsdutx == NULL) {
            /* nothing to process */
            ATH_AMSDU_TXQ_UNLOCK(scn);
            break;
        }
        TAILQ_REMOVE(&scn->sc_amsdu_txq, amsdutx, amsdu_qelem);
        amsdutx->sched = 0;
        ATH_AMSDU_TXQ_UNLOCK(scn);
        ath_amsdu_stageq_flush(scn, amsdutx);
    } while (!TAILQ_EMPTY(&scn->sc_amsdu_txq));
    return 1;   /* dont re-schedule */
}
/*
 * If the receive phy rate is lower than the threshold or our transmit queue has at least one
 * frame to work on, we keep building the AMSDU.
 */
int
ath_amsdu_sched_check(struct ath_softc_net80211 *scn, struct ath_node_net80211 *anode,
                      int priority)
{
    if ((scn->sc_ops->get_noderate(anode->an_sta, IEEE80211_RATE_RX) <= 162000) ||
        (scn->sc_ops->txq_depth(scn->sc_dev, scn->sc_ac2q[priority]) >= 1))
    {
        return 1;
    }
    return 0;
}
/*
 * This routine either starts a new AMSDU or it adds data to an existing one.
 * Each buffer is AMSDU encapsulated by our platform specific 802.11 protocol layer.
 * Once we have completed preparing the AMSDU, we call the flush routine to send it
 * out. We can stop filling an AMSDU for the following reasons -
 *    - the 2K AMSDU buffer is full
 *    - the hw transmit queue has only one frame to work on
 *    - we want to transmit a frame that cannot be in an AMSDU. i.e. frame larger than
 *      max subframe limit, EAPOL or multicast frame
 *    - the no activity timer expires and flushes any outstanding AMSDUs.
 */
wbuf_t
ath_amsdu_send(wbuf_t wbuf)
{
    struct ieee80211_node *ni = wbuf_get_node(wbuf);
    struct ieee80211com *ic = ni->ni_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_node_net80211 *anode = (struct ath_node_net80211 *)ni;
    struct ieee80211vap *vap = ni->ni_vap;
    wbuf_t amsdu_wbuf;
    u_int8_t tidno = wbuf_get_tid(wbuf);
    u_int32_t framelen;
    struct ath_amsdu_tx *amsdutx;
    int amsdu_deny;
    struct ieee80211_tx_status ts;
    
    /* AMSDU handling not initialized */
    if (anode->an_amsdu == NULL) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ERROR: ath_amsdu_attach not called\n");
        return wbuf;
    }
    if (ieee80211vap_get_fragthreshold(vap) < 2346 ||
        !(ieee80211vap_get_opmode(vap) == IEEE80211_M_STA ||
        ieee80211vap_get_opmode(vap) == IEEE80211_M_HOSTAP))
    {
        return wbuf;
    }
    framelen = roundup(wbuf_get_pktlen(wbuf), 4);
    amsdu_deny = ieee80211_amsdu_check(vap, wbuf);
    /* Set the tx status flags */
    ts.ts_flags = 0;
    ts.ts_retries = 0;
#ifdef ATH_SUPPORT_TxBF
    ts.ts_txbfstatus=0;
#endif
    ATH_AMSDU_TXQ_LOCK(scn);
    amsdutx = &(anode->an_amsdu->amsdutx[tidno]);
    if (amsdutx->amsdu_tx_buf) {
        /* If AMSDU staging buffer exists, we need to add this wbuf
         * to it.
         */
        amsdu_wbuf = amsdutx->amsdu_tx_buf;
        /*
         * Is there enough room in the AMSDU staging buffer?
         * Is the newly arrived wbuf larger than our amsdu limit?
         * If not, dispatch the AMSDU and return the current wbuf.
         */
        if ((framelen > AMSDU_MAX_SUBFRM_LEN) || amsdu_deny) {
            /* Flush the amsdu q */
            ATH_AMSDU_TXQ_UNLOCK(scn);
            ath_amsdu_stageq_flush(scn, amsdutx);
            return wbuf;
        }
        if (ath_amsdu_sched_check(scn, anode, wbuf_get_priority(amsdu_wbuf)) &&
            (AMSDU_MAX_SUBFRM_LEN + framelen + wbuf_get_pktlen(amsdu_wbuf)) < ic->ic_amsdu_max_size)
        {
            /* We are still building the AMSDU */
            ieee80211_amsdu_encap(vap,amsdu_wbuf, wbuf, framelen, 0);
            ATH_AMSDU_TXQ_UNLOCK(scn);
            /* Free the tx buffer */
            ieee80211_complete_wbuf(wbuf, &ts);
            return NULL;
        } else {
            /*
             * This is the last wbuf to be added to the AMSDU
             * No pad for this frame.
             * Return the AMSDU wbuf back.
             */
            ieee80211_amsdu_encap(vap,amsdu_wbuf, wbuf, wbuf_get_pktlen(wbuf), 0);
            ATH_AMSDU_TXQ_UNLOCK(scn);
            /* Free the tx buffer */
            ieee80211_complete_wbuf(wbuf, &ts);
            ath_amsdu_stageq_flush(scn, amsdutx);
            return NULL;
        }
    } else {
        /* Begin building the AMSDU */
        /* AMSDU for small frames only */
        if ((framelen > AMSDU_MAX_SUBFRM_LEN) || amsdu_deny) {
            ATH_AMSDU_TXQ_UNLOCK(scn);
            return wbuf;
        }
        amsdu_wbuf = wbuf_alloc(scn->sc_osdev, WBUF_TX_DATA, AMSDU_MAX_BUFFER_SIZE);
        /* No AMSDU buffer available */
        if (amsdu_wbuf == NULL) {
            ATH_AMSDU_TXQ_UNLOCK(scn);
            return wbuf;
        }
        /* Perform 802.11 AMSDU encapsulation */
        ieee80211_amsdu_encap(vap,amsdu_wbuf, wbuf, framelen, 1);
        /*
         * Copy information from buffer
         * Bump reference count for the node.
         */
        wbuf_set_priority(amsdu_wbuf, wbuf_get_priority(wbuf));
        wbuf_set_tid(amsdu_wbuf, tidno);
        wbuf_set_node(amsdu_wbuf, ieee80211_ref_node(ni));
        wbuf_set_amsdu(amsdu_wbuf);
        amsdutx->amsdu_tx_buf = amsdu_wbuf;
        if (!amsdutx->sched) {
            amsdutx->sched = 1;
            TAILQ_INSERT_TAIL(&scn->sc_amsdu_txq, amsdutx, amsdu_qelem);
        }
        ATH_AMSDU_TXQ_UNLOCK(scn);
        /* Free the tx buffer */
        ieee80211_complete_wbuf(wbuf, &ts);
        if (!ath_timer_is_active(&scn->sc_amsdu_flush_timer))
            ath_start_timer(&scn->sc_amsdu_flush_timer);
        return NULL;
    }
}
int
ath_amsdu_attach(struct ath_softc_net80211 *scn)
{
    struct ieee80211com *ic = &scn->sc_ic;

    TAILQ_INIT(&scn->sc_amsdu_txq);
    ATH_AMSDU_TXQ_LOCK_INIT(scn);
    /* Setup the default  amsdu size. If a different value is desired, setup at init time via IEEE80211_DEVICE_MAX_AMSDU_SIZE  */
    if (ic->ic_amsdu_max_size == 0) {
        // If not already inited, set the default.
        ic->ic_amsdu_max_size = AMSDU_MAX_LEN;
    }

    /* Initialize the no-activity timer */
    ath_initialize_timer(scn->sc_osdev, &scn->sc_amsdu_flush_timer, AMSDU_TIMEOUT,
                             ath_amsdu_flush_timer, scn);
    return 0;
}
void
ath_amsdu_detach(struct ath_softc_net80211 *scn)
{
    ATH_AMSDU_TXQ_LOCK_DESTROY(scn);
    ath_cancel_timer(&scn->sc_amsdu_flush_timer, CANCEL_NO_SLEEP);
    ath_free_timer(&scn->sc_amsdu_flush_timer);
}
int
ath_amsdu_node_attach(struct ath_softc_net80211 *scn, struct ath_node_net80211 *anode)
{
    int tidno;
    struct ath_amsdu_tx *amsdutx;
    anode->an_amsdu = (struct ath_amsdu *)OS_MALLOC(scn->sc_osdev,
                                               sizeof(struct ath_amsdu),
                                               GFP_ATOMIC);
    if (anode->an_amsdu == NULL) {
		return ENOMEM;
	}
    OS_MEMZERO(anode->an_amsdu, sizeof(struct ath_amsdu));
    for (tidno = 0; tidno < WME_NUM_TID; tidno++) {
        amsdutx = &(anode->an_amsdu->amsdutx[tidno]);
    }
    return 0;
}
void
ath_amsdu_node_detach(struct ath_softc_net80211 *scn, struct ath_node_net80211 *anode)
{
    wbuf_t wbuf;
    int tidno;
    /* Cleanup resources */
    if (anode->an_amsdu) {
        struct ath_amsdu_tx *amsdutx = NULL;
            
        for (tidno = 0; tidno < WME_NUM_TID; tidno++) {
            amsdutx = &(anode->an_amsdu->amsdutx[tidno]);
            /* if the tx queue is scheduled, then remove it from scheduled queue and clean up the buffers */
            if (amsdutx->sched ) {
               ATH_AMSDU_TXQ_LOCK(scn);

               TAILQ_REMOVE(&scn->sc_amsdu_txq, amsdutx, amsdu_qelem);
               amsdutx->sched = 0;

               wbuf = amsdutx->amsdu_tx_buf;
               amsdutx->amsdu_tx_buf = NULL;
               ATH_AMSDU_TXQ_UNLOCK(scn);

              if (wbuf != NULL) {
                 IEEE80211_TX_COMPLETE_WITH_ERROR(wbuf);
              }

            } 
        }
        OS_FREE(anode->an_amsdu);
        anode->an_amsdu = NULL;
    }
}
#endif /* ATH_AMSDU */
