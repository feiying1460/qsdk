/*
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 */

/*
 LMAC - Air Time Fairness module
*/
#if QCA_AIRTIME_FAIRNESS

#include <osdep.h>
#include "ath_internal.h"
#include "ath_dev.h"
#include "ieee80211_var.h"
#include "ath_airtime_fairness.h"

/* definitions */
#define OFDM_SIFS_TIME  16
#define OFDM_SLOT_TIME  9
#define OFDM_DIFS_TIME  34 /*(16+2*9)*/
#define ACK_LENGTH  14

#define BACKOFF_SLOT_MAX 1024
#define BACKOFF_SLOT_MIN_OFFSET 5


/*
 * Function     : ath_atf_sc_set_clear
 * Description  : enable/disable ATF
 * Input        : Pointer to sc, enable/disable
 * Output       : Void
 *
 */
void ath_atf_sc_set_clear(struct ath_softc *sc, u_int32_t enable_disable)
{
    sc->sc_atf_enable = enable_disable;
}

/*
 * Function     : ath_atf_debug_nodestate
 * Description  : Debug the node state - tid paused/unpaused
 * Input        : Pointer to node
 * Output       : Bitfield value indicating tid's paused
 *
 */
u_int32_t ath_atf_debug_node_state(struct ath_node *an)
{
    u_int32_t nodestate = 0;
    int tidno;
    struct ath_atx_tid *tid;

    for (tidno = 0, tid = &an->an_tx_tid[tidno]; tidno < WME_NUM_TID;
                      tidno++, tid++)
    {
        nodestate |= (tid->paused << tidno);
    }

    return nodestate;
}

/*
 * Function     : ath_atf_all_tokens_used
 * Description  : whether we used all tokens in last atf cycle
 * Input        : Pointer to node
 * Output       : 1 if we used all tokens in last atf cycle
 *
 */
u_int8_t ath_atf_all_tokens_used(struct ath_node *an)
{
    return an->an_atf_nomore_tokens_show ? 1 : 0;
}

/*
 * Function     : ath_atf_sc_get_unused_txtoken
 * Description  : get unused tokens
 * Input        : Pointer to node, unused tokens
 * Output       : Void
 *
 */
void ath_atf_sc_get_unused_txtoken(struct ath_node *an, u_int32_t *unused_token )
{
    *unused_token = an->an_atf_txtoken;
}

/*
 * Function     : ath_atf_sc_node_resume
 * Description  : Resume node, if paused
 * Input        : Pointer to node
 * Output       : Void
 *
 */
void ath_atf_sc_node_resume(struct ath_node *an)
{
    /* Resume the node, if paused */
    if (atomic_read(&an->an_atf_nodepaused))
    {
        ath_tx_node_atf_resume(an->an_sc, an);

        // set atf_nodepaused to 0
        atomic_set(&an->an_atf_nodepaused, AH_FALSE);
    }
}

void ath_atf_sc_tokens_unassigned(struct ath_softc *sc, u_int32_t tokens_unassigned)
{
    sc->sc_atf_tokens_unassigned = tokens_unassigned;
}

/*
 * Function     : ath_atf_sc_capable_node
 * Description  : Mark ATF Capable node,
 *                Nodes for which there is an ATF table entry
 * Input        : Pointer to node
 * Output       : Void
 *
 */
void ath_atf_sc_capable_node(struct ath_node *an, u_int8_t val, u_int8_t atfstate_change)
{
    struct ath_softc *sc = an->an_sc;

    an->an_atf_capable = val;
    if(atfstate_change)
    {
        if ( (an->an_num_buf_held_sc) &&
             (sc->sc_num_buf_held >= an->an_num_buf_held_sc) ) {

            sc->sc_num_buf_held -= an->an_num_buf_held_sc;
            an->an_num_buf_held_sc = 0;

            if( atomic_read(&an->an_atf_nodepaused) )
            {
                ath_tx_node_atf_resume(an->an_sc, an);
                atomic_set(&an->an_atf_nodepaused, AH_FALSE);
            }
        }
    }

}

/*
 * Function     : ath_atf_sc_update_node
 * Description  : Update atf_units in the node structure
                  Any excess air time consumed (actual tx time > estimated tx duration),
                  will be deducted during the update
 * Input        : Pointer to node, atf_unit
 * Output       : Void
 *
 */
void ath_atf_sc_update_node_txtoken(struct ath_node *an, u_int32_t txtoken, struct atf_stats *stats)
{
    struct ath_softc *sc = NULL;

    if(an == NULL)
    {
        return;
    }

    sc = an->an_sc;

    an->an_atf_nomore_tokens_show = an->an_atf_nomore_tokens;
    an->an_atf_nomore_tokens = 0;

    ATH_NODE_ATF_TOKEN_LOCK(an);

    if (!an->an_atf_capable) {
        txtoken = sc->sc_atf_tokens_unassigned;
    }

    if (an->an_atf_less_consumed) {
        /* TO DO - limit the number of such consecutive attempts.
           If not, the other nodes might not get its due airtime */
        txtoken += an->an_atf_less_consumed;
        an->an_atf_less_consumed = 0;
    }

    if (an->an_atf_excess_consumed) {
        if (an->an_atf_excess_consumed  <= txtoken) {
            __11nstatsn(sc, tx_deducted_tokens, an->an_atf_excess_consumed);
            txtoken = txtoken - an->an_atf_excess_consumed;
            an->an_atf_excess_consumed = 0;
        } else {
            __11nstatsn(sc, tx_deducted_tokens, txtoken);
            an->an_atf_excess_consumed -= txtoken;
            txtoken = 0;
        }
    }

    if (an->an_atf_capable) {
        an->an_atf_txtoken = txtoken;
    } else {
        sc->sc_atf_tokens_unassigned = txtoken;
    }

    stats->max_num_buf_held = an->an_max_num_buf_held;
    stats->min_num_buf_held = an->an_min_num_buf_held;
    stats->pkt_drop_nobuf = an->an_pkt_drop_nobuf;
    stats->allowed_bufs = an->an_allowed_bufs;
    stats->act_tokens = an->an_shadow_atf_txtoken;
    stats->act_tokens_common = sc->sc_atf_tokens_unassigned_adj;
    stats->num_tx_bufs = an->an_num_bufs_sent;
    stats->num_tx_bytes = an->an_num_bytes_sent;

    if (an->an_atf_capable)
        an->an_shadow_atf_txtoken = txtoken;
    else
        an->an_shadow_atf_txtoken = 0;
    sc->sc_atf_tokens_unassigned_adj = sc->sc_atf_tokens_unassigned;

    an->an_min_num_buf_held = an->an_num_buf_held;
    an->an_max_num_buf_held = an->an_num_buf_held;
    an->an_pkt_drop_nobuf = 0;
    an->an_allowed_bufs = 0;
    an->an_allowed_buf_updated = 0;
    an->an_num_bufs_sent = 0;
    an->an_num_bytes_sent = 0;

    an->an_tx_unusable_tokens_updated = 0;
    ATH_NODE_ATF_TOKEN_UNLOCK(an);

    /* Resume the node, if paused */
    if( atomic_read(&an->an_atf_nodepaused) && txtoken )
    {
        ath_tx_node_atf_resume(an->an_sc, an);

        atomic_set(&an->an_atf_nodepaused, AH_FALSE);
    }
}

/*
 * Function     : ath_atf_bypass_frame
 * Description  : Check if the frame should be excluded out of ATF scheduling logic
                  Management packets, Highpriority packets & self bss packets are excluded.
 * Input        : Pointer to tid, ath_buf
 * Output       : 1 - if ATF sched logic is to be bypassed
                  0 - if ATF sched logic should not be bypassed
 */
int ath_atf_bypass_frame(ath_atx_tid_t *tid, struct ath_buf *bf )
{
    struct ieee80211_node *ni;
    struct ath_node   *node = NULL;

    node = tid->an;
    ni = (struct ieee80211_node *)node->an_node;

    if (bf == NULL)
        return 1;

    if( (tid->tidno == WME_MGMT_TID)  || (ni == ni->ni_bss_node) ||
         wbuf_is_highpriority(bf->bf_mpdu) )
    {
        return 1;
    }

    return 0;
}

/*
 * Function     : ath_atf_check_txtokens
 * Description  : Estimate the tx packet duration.
                  Transmit the packet if the estimated duration < txtokens
                  Queue the packet back to tidq otherwise
 * Input        : Pointer to node, ath_buf, tid
 * Output       : 0 or 1
 */
int
ath_atf_check_txtokens(struct ath_softc *sc, struct ath_buf *bf, ath_atx_tid_t *tid)
{
    struct ath_node   *node = NULL;
    u_int32_t  pkt_duration = 0, i, txtokens=0, ack_duration = 0, pkt_overhead = 0;
    u_int8_t rix = 0, cix = 0;
    struct ieee80211_node *ni;
    HAL_TXQ_INFO qi;
    const HAL_RATE_TABLE *rt;

    rt = sc->sc_currates;

    node = tid->an;
    ni = (struct ieee80211_node *)node->an_node;

    bf->bf_tx_airtime = 0;

    /* Check token availability
       Exclude Management & high priority packets (EAPOL, ARP, DHCP) from
       ATF scheduler
    */
    if( (tid->tidno != WME_MGMT_TID)  && (ni != ni->ni_bss_node) &&
         !wbuf_is_highpriority(bf->bf_mpdu) )
    {

        /* For ATF capable clients, tokens available in Node structure
           For non-ATF clients, use unassigned tokens from the common pool */
        ATH_NODE_ATF_TOKEN_LOCK(tid->an);
        if( node->an_atf_capable) {
            txtokens = node->an_atf_txtoken;
        } else {
            txtokens = sc->sc_atf_tokens_unassigned;
        }
        ATH_NODE_ATF_TOKEN_UNLOCK(tid->an);
        if( txtokens )
        {
            for (i = 0; i < 4; i++) {
                if (bf->bf_rcs[i].tries) {
                    rix = bf->bf_rcs[i].rix;
                    break;
                }
            }
            /* Highly unlikely case, where 'tries' for all mcs rates are set to '0'*/
            if(i == 4) {
                return 1;
            }

            pkt_duration = ath_pkt_duration( sc, rix, bf,
                                            (bf->bf_rcs[i].flags & ATH_RC_CW40_FLAG) != 0,
                                            (bf->bf_rcs[i].flags & ATH_RC_SGI_FLAG),
                                            bf->bf_shpreamble);
            cix = rt->info[rix].controlRate;
            ath_hal_gettxqueueprops(sc->sc_ah, bf->bf_qnum, &qi);
            if( bf->bf_isaggr )
            {
                ack_duration = ath_buf_get_ba_period(sc, bf);
            }
            else
            {
                ack_duration = ath_calc_ack_duration(sc, cix);
            }

            pkt_overhead = OFDM_SIFS_TIME + (qi.tqi_aifs * OFDM_SLOT_TIME) + ((qi.tqi_cwmin/2) * OFDM_SLOT_TIME) + ack_duration;
            pkt_duration += pkt_overhead;

            if(pkt_duration <= txtokens)
            {

                txtokens -= pkt_duration;

                ATH_NODE_ATF_TOKEN_LOCK(tid->an);
                if( node->an_atf_capable) {
                    node->an_atf_txtoken = txtokens;
                } else {
                    sc->sc_atf_tokens_unassigned = txtokens;
                    //printk("%s()#%d non-atf client - txtokens : %d \n\r",__func__, __LINE__, txtokens);
                }
                ATH_NODE_ATF_TOKEN_UNLOCK(tid->an);

                /*  Update ath_buf with the estimated packet duration.
                    This will be compared with the actual packet duration in txcompletion path
                 */
                bf->bf_tx_airtime = pkt_duration;

                return 0;
            }
            else
            {
                if (!tid->an->an_tx_unusable_tokens_updated) {
                    __11nstatsn(sc, tx_unusable_tokens, txtokens);
                    tid->an->an_tx_unusable_tokens_updated = 1;
                }
                /* Pause node & set atf falg */
                if( !atomic_read(&tid->an->an_atf_nodepaused))
                {
                    ath_tx_node_atf_pause_nolock(sc, tid->an);
                    atomic_set(&tid->an->an_atf_nodepaused, AH_TRUE);
                }
                return 1;
            }
        }
        else
        {
            /* Pause node & set atf flag */
            if( !atomic_read(&tid->an->an_atf_nodepaused))
            {
                ath_tx_node_atf_pause_nolock(sc, tid->an);
                atomic_set(&tid->an->an_atf_nodepaused, AH_TRUE);
            }
            return 1;
        }
    }
    return 0;
}

/*
 * Function     : ath_atf_node_airtime_consumed
 * Description  : Calculate actual airtime used
                  Compare with the duration estimated during transmit
                  If 'actual airtime > estimated duration', update node_deficit.
                  node_deficit will be deducted from the node tokens at the next token update cycle
 * Input        : Pointer to sc, ath_buf, tid, txstatus, status
 * Output       : 0 or 1
 */
int
ath_atf_node_airtime_consumed( struct ath_softc *sc, struct ath_buf *bf, struct ath_tx_status *ts, int txok)
{
    u_int32_t actual_pkt_duration=0, duration_per_try = 0, ack_duration = 0, pkt_overhead = 0;
    u_int32_t rateindex=0, tries = 0, totalretries = 0, backoff = 0, backoff_duration = 0;
    int32_t i=0;
    u_int8_t rix = 0, cix = 0;
    struct ieee80211_node *ni;
    struct ath_node *an = bf->bf_node;
    const HAL_RATE_TABLE    *rt = sc->sc_currates;
    HAL_TXQ_INFO qi;
    u_int32_t txtoken;

    ni = (struct ieee80211_node *)an->an_node;
    if( (bf->bf_tidno != WME_MGMT_TID)  && (ni != ni->ni_bss_node) )// Hack to identify Data packet
    {
        /* get the actual transmission rate & retries from the descriptor
           calculate packet duration
           Compare with the estimated packet duration
        */
        rateindex = ts->ts_rateindex;
        tries = ts->ts_longretry;
        i = rateindex;
        /*Compute the actual packet duration based on the rateindex & tries */
        for( ;i>=0 && i<4; i--)
        {
            rix = bf->bf_rcs[i].rix;
            duration_per_try = ath_pkt_duration( sc, rix, bf,
                                        (bf->bf_rcs[i].flags & ATH_RC_CW40_FLAG) != 0,
                                        (bf->bf_rcs[i].flags & ATH_RC_SGI_FLAG),
                                        bf->bf_shpreamble);
            if(i == rateindex)
            {
                cix = rt->info[rix].controlRate;
                ath_hal_gettxqueueprops(sc->sc_ah, bf->bf_qnum, &qi);
                if( bf->bf_isaggr )
                {
                    ack_duration = ath_buf_get_ba_period(sc, bf);
                }
                else
                {
                    ack_duration = ath_calc_ack_duration(sc, cix);
                }

                pkt_overhead = OFDM_SIFS_TIME + (qi.tqi_aifs * OFDM_SLOT_TIME) + ((qi.tqi_cwmin/2) * OFDM_SLOT_TIME) + ack_duration;

                /* account for retries in the final transmission series
                   account the duration for successful transmission also */
                actual_pkt_duration += ( duration_per_try + pkt_overhead + ((duration_per_try + OFDM_SIFS_TIME ) * tries));
            }
            else
            {
                /* failed rate series */
                actual_pkt_duration += ( (duration_per_try + OFDM_SIFS_TIME) * bf->bf_rcs[i].tries) ;
            }
        }

        /* If there were retries, account backoff time for each retry */
        totalretries = ath_get_retries_num(bf, rateindex, tries);
        if(totalretries)
        {
            for(i=0; i < totalretries; i++)
            {
                backoff = ((1 << (BACKOFF_SLOT_MIN_OFFSET + i)) - 1);
                if(backoff >= (BACKOFF_SLOT_MAX - 1) )
                    backoff = (BACKOFF_SLOT_MAX - 1);

                backoff = backoff * OFDM_SLOT_TIME;
                backoff_duration += backoff;
            }
            actual_pkt_duration += backoff_duration;
        }

        ATH_NODE_ATF_TOKEN_LOCK(an);

        if (an->an_atf_capable) {
            txtoken = an->an_atf_txtoken;
        } else {
            txtoken = sc->sc_atf_tokens_unassigned;
        }

        if ( actual_pkt_duration > bf->bf_tx_airtime && bf->bf_tx_airtime )
        {
            if (txtoken > (actual_pkt_duration - bf->bf_tx_airtime)) {
                txtoken -= (actual_pkt_duration - bf->bf_tx_airtime);
                if (an->an_atf_capable) {
                    an->an_atf_txtoken = txtoken;
                } else {
                    sc->sc_atf_tokens_unassigned = txtoken;
                }
            } else {
                an->an_atf_excess_consumed += (actual_pkt_duration - bf->bf_tx_airtime );
            }
        }
        else if( actual_pkt_duration < bf->bf_tx_airtime && bf->bf_tx_airtime )
        {
            an->an_atf_less_consumed += ( bf->bf_tx_airtime - actual_pkt_duration );
        }
        ATH_NODE_ATF_TOKEN_UNLOCK(an);
    }
    return 0;
}

/*
 * Function     : ath_atf_ath_calc_ack_duration
 * Description  : Calculate airtime for ACK
                  Note that ACKs will be sent at the legacy rate.
 * Input        : Pointer to sc, control rate index
 * Output       : duration
 */
u_int32_t ath_calc_ack_duration(struct ath_softc *sc, u_int8_t cix)
{
#define CCK_PREAMBLE_BITS   144
#define CCK_PLCP_BITS        48

    const HAL_RATE_TABLE *rt;
    u_int32_t ack_len = ACK_LENGTH;
    u_int32_t nsymbits = 0, nbits = 0, nsymbols = 0, duration = 0, phyTime = 0;

    rt = sc->sc_currates;
    switch (rt->info[cix].rate_code) {
    case 0x0b: /* 6 Mb OFDM */
        nsymbits = 24 ;
        break;
    case 0x0a: /* 12 Mb OFDM */
        nsymbits = 48;
        break;
    case 0x09: /* 24 Mb OFDM */
        nsymbits = 96;
        break;
    case 0x1b: /* 1 Mb CCK */
    case 0x1a: /* 2 Mb CCK */
    case 0x19: /* 5.5 Mb CCK */
    case 0x18: /* 11 Mb CCK */
        phyTime  = CCK_PREAMBLE_BITS + CCK_PLCP_BITS;
        nbits    = ack_len << 3;
        duration =  phyTime + (( nbits * 1000) / rt->info[cix].rateKbps);
#undef CCK_PREAMBLE_BITS
#undef CCK_PLCP_BITS
        return duration;
    default:
        QDF_PRINT_INFO(sc->sc_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s() - Invalid ratecode %d \n\r",__func__, rt->info[cix].rate_code);
        return 0;
    }

    /*
     * find number of symbols: PLCP + data
     */
    nbits = (ack_len << 3) + OFDM_PLCP_BITS;
    nsymbols = nbits / nsymbits;

    duration = SYMBOL_TIME(nsymbols);

    duration += L_STF + L_LTF + L_SIG;

    return duration;
}

u_int32_t ath_get_retries_num(struct ath_buf *bf, u_int32_t rateindex, u_int32_t retries)
{
    u_int32_t totalretries = 0;
    switch (rateindex)
    {
        case 0:
            totalretries = retries;
            break;
        case 1:
            totalretries = retries + bf->bf_rcs[0].tries;
            break;
        case 2:
            totalretries = retries + bf->bf_rcs[1].tries +
                          bf->bf_rcs[0].tries;
            break;
        case 3:
            totalretries = retries + bf->bf_rcs[2].tries +
                          bf->bf_rcs[1].tries + bf->bf_rcs[0].tries;
            break;
        default:
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Invalid rateindex \n\r");
    }
    return totalretries;
}

OS_EXPORT_SYMBOL(ath_atf_node_airtime_consumed);
#endif

