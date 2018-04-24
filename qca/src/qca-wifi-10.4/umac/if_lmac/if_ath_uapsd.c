/*
 *  Copyright (c) 2008 Atheros Communications Inc. 
 * All Rights Reserved.
 * 
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */

#include "if_athvar.h"

#ifdef ATH_SUPPORT_UAPSD
wbuf_t
ath_net80211_uapsd_allocqosnullframe(ieee80211_handle_t ieee)
{
    wbuf_t wbuf;
    struct ieee80211com *ic = NET80211_HANDLE(ieee);

    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, sizeof(struct ieee80211_qosframe));
    if (wbuf != NULL)
        wbuf_push(wbuf, sizeof(struct ieee80211_qosframe));

    return wbuf;
}

wbuf_t
ath_net80211_uapsd_getqosnullframe(ieee80211_node_t node, wbuf_t wbuf, int ac)
{
    struct ieee80211_node *ni;

    ni = (struct ieee80211_node *)node;

    ieee80211_prepare_qosnulldata(ni, wbuf, ac);

    /* Add a refcnt to the node so that it remains until this QosNull frame 
       completion in ath_net80211_uapsd_retqosnullframe() */
    ieee80211_ref_node(ni);

    return wbuf;
}

void ath_net80211_uapsd_retqosnullframe(ieee80211_node_t node, wbuf_t wbuf)
{
    struct ieee80211_node *ni;

    ni = (struct ieee80211_node *)node;

    /* Release the node refcnt that was acquired in ath_net80211_uapsd_getqosnullframe() */
    ieee80211_free_node(ni);
}

/*
 * This function is called when we have successsfully transmitted EOSP.
 * It clears the SP flag so that we are ready to accept more triggers
 * from this node.
 */
void
ath_net80211_uapsd_eospindicate(ieee80211_node_t node, wbuf_t wbuf, int txok, int force_eosp)
{
    struct ieee80211_qosframe *qwh;
    struct ieee80211_node *ni;
    struct ath_softc_net80211 *scn;

    if (node == NULL)
        return;
    qwh = (struct ieee80211_qosframe *)wbuf_header(wbuf);
    ni = (struct ieee80211_node *)node;
    scn = ATH_SOFTC_NET80211(ni->ni_ic);

    if (node == NULL)
        return;

    if ((qwh->i_fc[0] == (IEEE80211_FC0_SUBTYPE_QOS|IEEE80211_FC0_TYPE_DATA)) ||
        (qwh->i_fc[0] == (IEEE80211_FC0_SUBTYPE_QOS_NULL|IEEE80211_FC0_TYPE_DATA)) ||
        force_eosp)
    {
        if (
#if ATH_SUPPORT_WIFIPOS
            (ni->ni_flags & IEEE80211_NODE_WAKEUP) ||
#endif      
            (qwh->i_qos[0] & IEEE80211_QOS_EOSP) || force_eosp) {
            struct ieee80211com         *ic     = ni->ni_ic;
            struct ath_softc_net80211   *scn    = ATH_SOFTC_NET80211(ic);
            ni->ni_flags &= ~IEEE80211_NODE_UAPSD_SP;
            DPRINTF(scn, ATH_DEBUG_UAPSD, "%s : End SP\n", __func__);
            if (!txok)
                ni->ni_stats.ns_tx_eosplost++;
        }
    }
    if ((qwh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_MGT) {
        /* clear the SP for node */
        ni->ni_flags &= ~IEEE80211_NODE_UAPSD_SP;
    }

    return;
}

/*
 * This function determines whether the received frame is a valid UAPSD trigger.
 * Called from interrupt context or DPC context depending on parameter isr_context.
 */
bool
ath_net80211_check_uapsdtrigger(ieee80211_handle_t ieee, struct ieee80211_qosframe *qwh, u_int16_t keyix, bool isr_context)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ieee80211_node *ni;
    int tid, ac;
    u_int16_t frame_seq;
    int queue_depth;
    bool sent_eosp = false;
    bool isapsd = false;

    /*
     * Locate the node for sender
     */
    IEEE80211_KEYMAP_LOCK(scn);
    ni = (keyix != HAL_RXKEYIX_INVALID) ? scn->sc_keyixmap[keyix] : NULL;
    if (ni == NULL) {
        IEEE80211_KEYMAP_UNLOCK(scn);
        /*
         * No key index or no entry, do a lookup
         */
        if (isr_context) {
            ni = ieee80211_find_rxnode_nolock(ic, (struct ieee80211_frame_min *)qwh);
        }
        else {
            ni = ieee80211_find_rxnode(ic, (struct ieee80211_frame_min *)qwh);
        }
        if (ni == NULL) {
            return isapsd;
        }
    } else {
        ieee80211_ref_node(ni);
        IEEE80211_KEYMAP_UNLOCK(scn);
    }

    if (!(ni->ni_flags & IEEE80211_NODE_UAPSD))
        goto end;

    if (ni->ni_flags & IEEE80211_NODE_UAPSD_SP)
        goto end;    

    /* Ignore probe request frame */
    if (((qwh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_MGT) &&
        ((qwh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) == IEEE80211_FC0_SUBTYPE_PROBE_REQ))
        goto end;
    /*
     * Must deal with change of state here, since otherwise there would
     * be a race (on two quick frames from STA) between this code and the
     * tasklet where we would:
     *   - miss a trigger on entry to PS if we're already trigger hunting
     *   - generate spurious SP on exit (due to frame following exit frame)
     */
    if ((((qwh->i_fc[1] & IEEE80211_FC1_PWR_MGT) == IEEE80211_FC1_PWR_MGT) ^
        ((ni->ni_flags & IEEE80211_NODE_UAPSD_TRIG) == IEEE80211_NODE_UAPSD_TRIG)))
    {
        ni->ni_flags &= ~IEEE80211_NODE_UAPSD_SP;

        if (qwh->i_fc[1] & IEEE80211_FC1_PWR_MGT) {
            WME_UAPSD_NODE_TRIGSEQINIT(ni);
            ni->ni_stats.ns_uapsd_triggerenabled++;
            ni->ni_flags |= IEEE80211_NODE_UAPSD_TRIG;
        } else {
            /*
             * Node transitioned from UAPSD -> Active state. Flush out UAPSD frames
             */
            ni->ni_stats.ns_uapsd_active++;
            ni->ni_flags &= ~IEEE80211_NODE_UAPSD_TRIG;
            queue_depth = scn->sc_ops->process_uapsd_trigger(scn->sc_dev,
                    ATH_NODE_NET80211(ni)->an_sta,
                    WME_UAPSD_NODE_MAXQDEPTH, 0, 1, &sent_eosp, WME_UAPSD_NODE_MAXQDEPTH);

            if (!queue_depth &&
                (ni->ni_vap->iv_set_tim != NULL) &&
                IEEE80211_NODE_UAPSD_USETIM(ni))
            {
                ni->ni_vap->iv_set_tim(ni, 0, isr_context);
            }
            
      }

        goto end;
    }


    /*
     * Check for a valid trigger frame i.e. QoS Data or QoS NULL
     */
      if ( ((qwh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) !=
              IEEE80211_FC0_TYPE_DATA ) ||
             !(qwh->i_fc[0] & IEEE80211_FC0_SUBTYPE_QOS) ) {
          goto end;
      }

    if (((qwh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_DATA) &&
       (((qwh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) == IEEE80211_FC0_SUBTYPE_QOS) ||
        ((qwh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) == IEEE80211_FC0_SUBTYPE_QOS_NULL)))
    {
        tid = qwh->i_qos[0] & IEEE80211_QOS_TID;
        ac = TID_TO_WME_AC(tid);

        isapsd = true;

        if (WME_UAPSD_AC_CAN_TRIGGER(ac, ni)) {
            /*
             * Detect duplicate triggers and drop if so.
             */
            frame_seq = le16toh(*(u_int16_t *)qwh->i_seq);
            if ((qwh->i_fc[1] & IEEE80211_FC1_RETRY) &&
                frame_seq == ni->ni_uapsd_trigseq[ac])
            {
                ni->ni_stats.ns_uapsd_duptriggers++;
                DPRINTF(scn, ATH_DEBUG_UAPSD, "%s : Drop duplicate trigger\n", __func__);
                goto end;
            }

            /*
             * SP in progress for this node, discard trigger.
             */
            if (ni->ni_flags & IEEE80211_NODE_UAPSD_SP) {
                ni->ni_stats.ns_uapsd_ignoretriggers++;
                DPRINTF(scn, ATH_DEBUG_UAPSD, "%s : SP in-progress; ignore trigger\n", __func__);
                goto end;
            }

            ni->ni_stats.ns_uapsd_triggers++;

            

            queue_depth = scn->sc_ops->process_uapsd_trigger(scn->sc_dev,
                                               ATH_NODE_NET80211(ni)->an_sta,
                                               ni->ni_uapsd_maxsp, ac, 0, &sent_eosp, WME_UAPSD_NODE_MAXQDEPTH);

            if (queue_depth == -1)
                goto end;

            /* start the SP */
            ni->ni_flags |= IEEE80211_NODE_UAPSD_SP;
            ni->ni_uapsd_trigseq[ac] = frame_seq;

            DPRINTF(scn, ATH_DEBUG_UAPSD, "%s : Start SP\n", __func__);
#if ATH_SUPPORT_WIFIPOS
            if ((ni->ni_flags & IEEE80211_NODE_WAKEUP) &&  ni->ni_vap->iv_set_tim ) {
                ni->ni_vap->iv_set_tim(ni, 1,isr_context);
            }
#endif

            if (!queue_depth && (ni->ni_vap->iv_set_tim != NULL) &&
                IEEE80211_NODE_UAPSD_USETIM(ni))
            {
                ni->ni_vap->iv_set_tim(ni, 0, isr_context);
            }
        }
    }
end:
    ieee80211_free_node(ni);
    return isapsd;
}

/*
 * This function is called for each frame received on the high priority queue.
 * If the hardware has classified this frame as a UAPSD trigger, we locate the node
 * and deliver data.
 * For non-trigger frames, we check for PM transition.
 * Called from interrupt context.
 */
void
ath_net80211_uapsd_deliverdata(ieee80211_handle_t        ieee,
                               struct ieee80211_qosframe *qwh,
                               u_int16_t                 keyix,
                               u_int8_t                  is_trig,
                               bool                      isr_context)
{
    struct ieee80211com          *ic = NET80211_HANDLE(ieee);
    struct ath_softc_net80211    *scn = ATH_SOFTC_NET80211(ic);
    struct ieee80211_node        *ni;
    int                          tid, ac;
    u_int16_t                    frame_seq;
    int                          queue_depth;
    bool                         sent_eosp = false;

    UNREFERENCED_PARAMETER(isr_context);

    /*
     * Locate the node for sender
     */
    IEEE80211_KEYMAP_LOCK(scn);
    ni = (keyix != HAL_RXKEYIX_INVALID) ? scn->sc_keyixmap[keyix] : NULL;
    IEEE80211_KEYMAP_UNLOCK(scn);
    if (ni == NULL) {
        /*
         * No key index or no entry, do a lookup
         */
        ni = ieee80211_find_rxnode(ic, (struct ieee80211_frame_min *)qwh);
        if (ni == NULL) {
            return;
        }
    } else {
        ieee80211_ref_node(ni);
    }

    if (!(ni->ni_flags & IEEE80211_NODE_UAPSD) || (ni->ni_flags & IEEE80211_NODE_ATH_PAUSED))
        goto end;

    /* We cannot have a PM state change if this is a trigger frame */
    if (!is_trig)
    {
        /*
         * Must deal with change of state here, since otherwise there would
         * be a race (on two quick frames from STA) between this code and the
         * tasklet where we would:
         *   - miss a trigger on entry to PS if we're already trigger hunting
         *   - generate spurious SP on exit (due to frame following exit frame)
         */
        if ((((qwh->i_fc[1] & IEEE80211_FC1_PWR_MGT) == IEEE80211_FC1_PWR_MGT) ^
            ((ni->ni_flags & IEEE80211_NODE_UAPSD_TRIG) == IEEE80211_NODE_UAPSD_TRIG)))
        {
            ni->ni_flags &= ~IEEE80211_NODE_UAPSD_SP;

            if (qwh->i_fc[1] & IEEE80211_FC1_PWR_MGT) {
                WME_UAPSD_NODE_TRIGSEQINIT(ni);
                ni->ni_stats.ns_uapsd_triggerenabled++;
                ni->ni_flags |= IEEE80211_NODE_UAPSD_TRIG;
            } else {
                /*
                 * Node transitioned from UAPSD -> Active state. Flush out UAPSD frames
                 */
                ni->ni_stats.ns_uapsd_active++;
                ni->ni_flags &= ~IEEE80211_NODE_UAPSD_TRIG;
                scn->sc_ops->process_uapsd_trigger(scn->sc_dev,
                                                   ATH_NODE_NET80211(ni)->an_sta,
                                                   WME_UAPSD_NODE_MAXQDEPTH, 0, 1, &sent_eosp, WME_UAPSD_NODE_MAXQDEPTH);
            }

            goto end;
        }
    } else {  /* Is UAPSD trigger */
        tid = qwh->i_qos[0] & IEEE80211_QOS_TID;
        ac = TID_TO_WME_AC(tid);

        if (WME_UAPSD_AC_CAN_TRIGGER(ac, ni)) {
            /*
             * Detect duplicate triggers and drop if so.
             */
            frame_seq = le16toh(*(u_int16_t *)qwh->i_seq);
            if ((qwh->i_fc[1] & IEEE80211_FC1_RETRY) &&
                frame_seq == ni->ni_uapsd_trigseq[ac])
            {
                ni->ni_stats.ns_uapsd_duptriggers++;
                DPRINTF(scn, ATH_DEBUG_UAPSD, "%s : Drop duplicate trigger\n", __func__);
                goto end;
            }

            /*
             * SP in progress for this node, discard trigger.
             */
            if (ni->ni_flags & IEEE80211_NODE_UAPSD_SP) {
                ni->ni_stats.ns_uapsd_ignoretriggers++;
                DPRINTF(scn, ATH_DEBUG_UAPSD, "%s : SP in-progress; ignore trigger\n", __func__);
                goto end;
            }

            ni->ni_stats.ns_uapsd_triggers++;

            DPRINTF(scn, ATH_DEBUG_UAPSD, "%s : Start SP\n", __func__);

            queue_depth = scn->sc_ops->process_uapsd_trigger(scn->sc_dev,
                                               ATH_NODE_NET80211(ni)->an_sta,
                                               ni->ni_uapsd_maxsp, ac, 0, &sent_eosp, WME_UAPSD_NODE_MAXQDEPTH);
            if (queue_depth == -1)
                goto end;

            /* start the SP */
            ni->ni_flags |= IEEE80211_NODE_UAPSD_SP;
            ni->ni_uapsd_trigseq[ac] = frame_seq;

            if (!queue_depth &&
                (ni->ni_vap->iv_set_tim != NULL) &&
                IEEE80211_NODE_UAPSD_USETIM(ni))
            {
                ni->ni_vap->iv_set_tim(ni, 0, isr_context);
            }
        }
    }
end:
    ieee80211_free_node(ni);
    return;
}

/*
 * This function pauses/unpauses uapsd operation used by p2p protocol when the GO enters absent period.
 * Called from tasket context.
 */
void
ath_net80211_uapsd_pause_control(struct ieee80211_node *ni, bool pause)
{
    /* need to disable irq */
    if (!(ni->ni_flags & IEEE80211_NODE_UAPSD))
        return;
    if (pause) {
       ni->ni_flags &= ~IEEE80211_NODE_UAPSD_SP;
    }
}

void
ath_net80211_uapsd_process_uapsd_trigger(ieee80211_handle_t ieee, struct ieee80211_node *ni, bool enforce_max_sp, bool *sent_eosp)
{
    struct ieee80211com          *ic = NET80211_HANDLE(ieee);
    struct ath_softc_net80211    *scn = ATH_SOFTC_NET80211(ic);

    if (enforce_max_sp) {
        scn->sc_ops->process_uapsd_trigger(scn->sc_dev,
                                           ATH_NODE_NET80211(ni)->an_sta,
                                           ni->ni_uapsd_maxsp, 0, 0, sent_eosp, WME_UAPSD_NODE_MAXQDEPTH);
    }
    else {
        scn->sc_ops->process_uapsd_trigger(scn->sc_dev,
                                           ATH_NODE_NET80211(ni)->an_sta,
                                           WME_UAPSD_NODE_MAXQDEPTH, 0, 1, sent_eosp, WME_UAPSD_NODE_MAXQDEPTH);
    }

    return;
}

#endif /*ATH_SUPPORT_UAPSD */

