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
 Air Time Fairness module
*/
#if QCA_AIRTIME_FAIRNESS

#include <ieee80211_var.h>
#include <ieee80211_airtime_fairness.h>
#include <osif_private.h>

/* Definition */
#define IEEE80211_INVALID_MAC(addr) \
    ((!addr[0]) && (!addr[1]) && (!addr[2]) && \
     (!addr[3]) && (!addr[4]) && (!addr[5]))

/**
 * @brief For every entry in the atf structure, find the corresponding node & update the
    per node atf_unit.
 *
 * @param [in] ic  the handle to the radio
 *
 * @return true if handle is valid; otherwise false
 */
int
update_atf_nodetable(struct ieee80211com *ic)
{
    struct     ieee80211_node *ni = NULL;
    int32_t i;
    u_int8_t node_atf_state_prev = 0, atfstate_change = 0;

    /* For each entry in atfcfg structure, find corresponding entry in the node table */
    if(ic->atfcfg_set.peer_num_cal != 0)
    {
        for (i = 0; i < ATF_ACTIVED_MAX_CLIENTS; i++)
        {
            if((ic->atfcfg_set.peer_id[i].index_vap != 0)&&(ic->atfcfg_set.peer_id[i].sta_assoc_status == 1))
            {
                ni = ieee80211_find_node(&ic->ic_sta, ic->atfcfg_set.peer_id[i].sta_mac);
                if(ni == NULL) {
                    continue;
                } else {
                    /* getting the previous node state */
                    node_atf_state_prev =  ni->ni_atfcapable;
                    atfstate_change = 0;

                    /* Update atf_units in the node table entry */
                    ni->atf_units =  ic->atfcfg_set.peer_id[i].sta_cal_value;

                    /* Mark atf capable clients - if there is a corresponding VAP entry
                       or STA based config */
                    if(ic->ic_atf_maxclient)
                    {
                        if( (ic->atfcfg_set.peer_id[i].index_vap !=0xFF) ||
                            (ic->atfcfg_set.peer_id[i].cfg_flag !=0) )
                        {
                            ni->ni_atfcapable = 1;
                        } else {
                            ni->ni_atfcapable = 0;
                        }
                    } else {
                            ni->ni_atfcapable = 1;
                    }

                    /* Node ATF state changed */
                    if(node_atf_state_prev != ni->ni_atfcapable)
                    {
                        atfstate_change = 1;
                    }
                    ic->ic_atf_capable_node(ic, ni, ni->ni_atfcapable, atfstate_change);

                    ieee80211_free_node(ni);
                }
            }
        }
    }
    return EOK;
}

/**
 * @brief Derive txtokens based on the airtime assigned for the node.
 *
 * @param [in] node table, airtime, token distribution timer interval.
 *
 * @return None
 */
u_int32_t ieee80211_atf_compute_txtokens(struct ieee80211com *ic,
                             u_int32_t atf_units, u_int32_t token_interval_ms)
{
    u_int32_t tx_tokens;

    if (!atf_units) {
        return 0;
    }

    if (ic->ic_atf_sched & IEEE80211_ATF_SCHED_OBSS) {
        /* If OBSS scheduling is enabled, use the actual availabe tokens */
        token_interval_ms = ic->atf_avail_tokens;
    }

    /* if token interval is 1 sec & atf_units assigned is 100 %,
       tx_tokens = 1000000
     */
    tx_tokens = token_interval_ms * 1000; /* Convert total token time to uses. */
    /* Derive tx_tokens for this peer, w.r.t. ATF denomination and scheduler token_units */
    tx_tokens = (atf_units * tx_tokens) / WMI_ATF_DENOMINATION;
    return tx_tokens;
}


/**
 * @brief Check if the peer if valid
 *
 * @param [in] node table
 *
 * @return node table entry
 */
struct ieee80211_node *ieee80211_atf_valid_peer(struct ieee80211_node *ni)
{
    /* uninitialized peer */
    if( IEEE80211_INVALID_MAC(ni->ni_macaddr) ) {
        goto peer_invalid;
    }

    /* skip peers that aren't attached to a VDEV */
    if( ni->ni_vap ==NULL ) {
        goto peer_invalid;
    }

    /* skip non-AP vdevs */
    if( ni->ni_vap->iv_opmode != IEEE80211_M_HOSTAP ) {
        goto peer_invalid;
    }

    /* skip NAWDS-AP vdevs */

    /* skip AP BSS peer */
    if( ni == ni->ni_bss_node ) {
        goto peer_invalid;
    }

    return ni;

peer_invalid:
    return NULL;
}

u_int32_t ieee80211_atf_avail_tokens(struct ieee80211com *ic)
{
    u_int8_t ctlrxc, extrxc, rfcnt, tfcnt, obss;
    u_int32_t avail = ATF_TOKEN_INTVL_MS;
    
    /* get individual percentages */
    ctlrxc = ic->ic_atf_chbusy & 0xff;
    extrxc = (ic->ic_atf_chbusy & 0xff00) >> 8;
    rfcnt = (ic->ic_atf_chbusy & 0xff0000) >> 16;
    tfcnt = (ic->ic_atf_chbusy & 0xff000000) >> 24;
    
    if ((ctlrxc == 255) || (extrxc == 255) || (rfcnt == 255) || (tfcnt == 255))
        return ic->atf_avail_tokens;
    
    if (ic->ic_curchan->ic_flags & IEEE80211_CHAN_HT20)
        obss = ctlrxc - tfcnt;
    else
        obss = (ctlrxc + extrxc) - tfcnt;
    
    /* availabe % is 100 minus obss usage */
    avail = (100 - obss);
    
    /* Add a scaling factor and calculate the tokens*/
    if (ic->atf_obss_scale) {
        avail += avail * ic->atf_obss_scale / 100;
        avail = (avail * ATF_TOKEN_INTVL_MS / 100);
    }
    else {
        avail = (avail * ATF_TOKEN_INTVL_MS / 100) + 15;
    }    

    /* Keep a min of 30 tokens */
    if (avail < 30)
        avail = 30;
    
    return (avail < ATF_TOKEN_INTVL_MS) ? avail : ATF_TOKEN_INTVL_MS;
}

/**
 * @brief If the peer is valid, update txtokens to the lmac layer
 * Txtokens will be used for Tx scheduling
 *
 * @param [in] ic  the handle to the radio
 *
 * @return true if handle is valid; otherwise false
 */
void ieee80211_node_iter_dist_txtokens_strictq(void *arg, struct ieee80211_node *ni)
{
    u_int32_t atf_units = 0, node_unusedtokens = 0;
    struct ieee80211com *ic = (struct ieee80211com *)arg;

    if (!ni->ni_associd) {
        return;
    }

    if(!ni->ni_atfcapable)
        return;

    /* Check for Valid peer*/
    if(ieee80211_atf_valid_peer(ni) == NULL) {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ATF,
       "%s invalid peer \n\r",__func__);
        /* Assign max atf units if node is AP Self node (ni->ni_bss_node)
           or if the opmode is STA
         */
        if ( (ni == ni->ni_bss_node) ||
             (ni->ni_vap->iv_opmode == IEEE80211_M_STA) )
        {
            atf_units = WMI_ATF_DENOMINATION;
        }
    }

    ic->ic_atf_get_unused_txtoken(ic, ni, &node_unusedtokens);
    ni->ni_atf_stats.tot_contribution = 0;
    ni->ni_atf_stats.contribution = 0;
    ni->ni_atf_stats.borrow = 0;
    ni->ni_atf_stats.unused = node_unusedtokens;
    ni->ni_atf_stats.tokens = ni->shadow_tx_tokens;
    ni->ni_atf_stats.total = ic->ic_shadow_alloted_tx_tokens;
    ni->ni_atf_stats.timestamp = OS_GET_TIMESTAMP();
    if ( (ni->ni_atf_stats.act_tokens > node_unusedtokens) && (ni->ni_atf_stats.total > 0)) {
        // Note the math: 200k tokens every 200 ms => 1000k tokens / second => 1 token = 1 us.
        ni->ni_atf_stats.total_used_tokens += (ni->ni_atf_stats.act_tokens - node_unusedtokens);
        if (ic->ic_atf_logging) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "client %s is currently using %d usecs which is %d%% of available airtime\n",
                    ether_sprintf(ni->ni_macaddr),
                    (ni->ni_atf_stats.act_tokens - node_unusedtokens),
                    (((ni->ni_atf_stats.act_tokens - node_unusedtokens)*100) / ni->ni_atf_stats.total) );
        }
    }
    ni->ni_atf_stats.throughput = ni->ni_throughput;
    atf_units = ni->atf_units;
    ni->tx_tokens = ieee80211_atf_compute_txtokens(ic, atf_units, ATF_TOKEN_INTVL_MS);
    ni->shadow_tx_tokens = ni->tx_tokens;
    ic->ic_atf_update_node_txtoken(ic, ni, &ni->ni_atf_stats);

    ni->ni_atf_stats.tokens_common = ic->ic_txtokens_common;
    ic->ic_alloted_tx_tokens += ni->tx_tokens;

    /* Don't want to take the lock if logging to history buffer isn't enabled */
    if (ni->ni_atf_debug) {
        IEEE80211_NODE_STATE_LOCK(ni);
        /* Make sure that the history bufer didn't get freed while taking the lock */
        if (ni->ni_atf_debug) {
            ni->ni_atf_debug[ni->ni_atf_debug_id++] = ni->ni_atf_stats;
            ni->ni_atf_debug_id &= ni->ni_atf_debug_mask;
        }
        IEEE80211_NODE_STATE_UNLOCK(ni);
    }
}

/**
 * @brief Iterates through the node table.
 *        Nodes with the borrow flag set will get be alloted its share
 *        from the contributable token pool
 *
 * @param [in] arg  the handle to the radio
               ni   pointer to the node table
 *
 * @return none
 */
void ieee80211_node_iter_dist_txtokens_fairq(void *arg, struct ieee80211_node *ni)
{
    u_int32_t contributabletokens_perclient = 0, contributabletokens_per_group = 0;
    struct ieee80211com *ic = (struct ieee80211com *)arg;
    u_int32_t i =0, num = 0;

    if ( (!ni->ni_associd) || (!ni->ni_atfcapable) ) {
        return;
    }

    for (i = 0; i < ATF_ACTIVED_MAX_CLIENTS; i++) {
        if (ic->atfcfg_set.peer_id[i].sta_assoc_status == 1) {
            if(!ni->ni_vap->iv_vap_atf_sched) {
                num++;
            }
        }
    }
    if( !(ic->ic_atf_sched & IEEE80211_ATF_GROUP_SCHED_POLICY) &&
        ic->atfcfg_set.grp_num_cfg )
    {
        /* Fair-queue sched across groups */
        if( !ic->atf_total_num_clients_borrow )
        {
            /* No Clients looking to borrow, distribute unassigned tokens */
            if(!ni->ni_vap->iv_vap_atf_sched) {
                if (num)
                    ni->ni_borrowedtokens = ic->atf_tokens_unassigned / num;
                else
                    ni->ni_borrowedtokens = 0;
                ni->tx_tokens += ni->ni_borrowedtokens;

                /* No clients looking to borrow; Distribute contributable tokens to all clients equally */
                contributabletokens_perclient =  ic->atf_total_contributable_tokens / num;

                ni->tx_tokens += contributabletokens_perclient;
                ni->ni_atf_group->atf_contributabletokens -= contributabletokens_perclient;
                ni->ni_contributedtokens = 0;
            }
        } else if(ni->ni_atfborrow) {
            /* For clients looking to borrow:
                Distribute any unassigned tokens (if any) equally
                Distribute tokens from global contributable pool equally */
            contributabletokens_perclient = (ic->atf_total_contributable_tokens + ic->atf_tokens_unassigned)/ ic->atf_total_num_clients_borrow;
            //Update borrowed tokens for this node.
            ni->ni_borrowedtokens = contributabletokens_perclient;
            ni->tx_tokens += contributabletokens_perclient;
        }
    } else {
        /* Strict-queue across groups or Groups not configured */
        if(!ni->ni_atf_group->atf_num_clients_borrow) {
            /* No groups looking to borrow, distribute unassigned tokens */
            if(!ni->ni_vap->iv_vap_atf_sched) {
                if(!ic->atf_groups_borrow) {
                    if (num)
                        ni->ni_borrowedtokens = ic->atf_tokens_unassigned / num;
                    else
                        ni->ni_borrowedtokens = 0;
                    ni->tx_tokens += ni->ni_borrowedtokens;
                }

                /* In the group, If there are'nt  clients looking to borrow,
                   distribute contributable tokens to all connected clients in the group*/
                if(ni->ni_atf_group->atf_num_clients) {
                    contributabletokens_perclient =  ni->ni_atf_group->atf_contributabletokens / ni->ni_atf_group->atf_num_clients;
                }
                ni->tx_tokens += contributabletokens_perclient;
                ni->ni_atf_group->atf_contributabletokens -= contributabletokens_perclient;
                ni->ni_contributedtokens = 0;
            }
        } else if(ni->ni_atfborrow) {
            /* For nodes with 'borrow' enabled, allocate additional tokens from contributable token pool */

            /* Distribute any unassigned tokens (if any) equally to groups looking to borrow*/
            contributabletokens_per_group = ic->atf_tokens_unassigned / ic->atf_groups_borrow;
            contributabletokens_perclient = (ni->ni_atf_group->atf_contributabletokens + contributabletokens_per_group)/ni->ni_atf_group->atf_num_clients_borrow;

            //Update borrowed tokens for this node.
            ni->ni_borrowedtokens = contributabletokens_perclient;
            IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ATF,
                "%s() Node : %s atf_num_clients_borrow : %d tot atf_contributabletokens %d cont per client : %d  tokens : %d --> %d  \n\r",
                __func__, ether_sprintf(ni->ni_macaddr), ni->ni_atf_group->atf_num_clients_borrow,
                ni->ni_atf_group->atf_contributabletokens, contributabletokens_perclient,
                ni->tx_tokens, (ni->tx_tokens + contributabletokens_perclient));

            ni->tx_tokens += contributabletokens_perclient;
        }
    }

    ni->shadow_tx_tokens = ni->tx_tokens;
    ic->ic_atf_update_node_txtoken(ic, ni, &ni->ni_atf_stats);
    ni->ni_atf_stats.tokens_common = ic->ic_txtokens_common;
    ic->ic_alloted_tx_tokens += ni->tx_tokens;

    /* Don't want to take the lock if logging to history buffer isn't enabled */
    if (ni->ni_atf_debug) {
        IEEE80211_NODE_STATE_LOCK(ni);
        /* Make sure that the history bufer didn't get freed while taking the lock */
        if (ni->ni_atf_debug) {
            ni->ni_atf_debug[ni->ni_atf_debug_id++] = ni->ni_atf_stats;
            ni->ni_atf_debug_id &= ni->ni_atf_debug_mask;
        }
        IEEE80211_NODE_STATE_UNLOCK(ni);
    }
}

/**
 * @brief Iterates through the node table.
 *        Identifies clients looking to borrow & contribute tokens
 *        Computes total tokens available for contribution
 *
 * @param [in] arg  the handle to the radio
               ni   pointer to the node table
 *
 * @return none
 */
void ieee80211_node_iter_fairq_algo(void *arg, struct ieee80211_node *ni)
{
    u_int32_t atf_units = 0, weighted_unusedtokens_percent = 0, node_unusedtokens = 0;
    int32_t i = 0, j = 0, node_index = 0;
    struct ieee80211com *ic = (struct ieee80211com *)arg;
    int32_t unusedairtime_weights[ATF_DATA_LOG_SIZE] = {60, 30, 10};

    if (!ni->ni_associd)
    {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ATF,
                            "Node(%s) not associated. Returning \n\r", ether_sprintf(ni->ni_macaddr));
        return;
    }

    if(!ni->ni_atfcapable)
        return;

    /* Check for Valid peer*/
    if(ieee80211_atf_valid_peer(ni) == NULL) {

        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ATF,
                           "%s invalid peer %s \n\r",__func__, ether_sprintf(ni->ni_macaddr));

        /* Assign max atf units if node is AP Self node (ni->ni_bss_node)
           or if the opmode is STA
         */
        if ( (ni == ni->ni_bss_node) ||
             (ni->ni_vap->iv_opmode == IEEE80211_M_STA) )

        {
            atf_units = WMI_ATF_DENOMINATION;
        }
    }

    /* convert user %(atf_units) to txtokens (ni->txtokens) */
    atf_units = ni->atf_units;
    ni->tx_tokens = ieee80211_atf_compute_txtokens(ic, atf_units, ATF_TOKEN_INTVL_MS);

    /* Get unused tokens from the previous iteration */
    ic->ic_atf_get_unused_txtoken(ic, ni, &node_unusedtokens);
    IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ATF,
                       "%s() - Node MAC:%s, atf_units: %d ni->tx_tokens: %d unused tokens: %d INTVL: %d\n\r",
                          __func__,ether_sprintf(ni->ni_macaddr),atf_units, ni->tx_tokens,
                            node_unusedtokens,ATF_TOKEN_INTVL_MS);

    if(!ni->ni_vap->iv_vap_atf_sched)
        ni->ni_atf_stats.tot_contribution = ni->ni_atf_group->shadow_atf_contributabletokens;
    else
        ni->ni_atf_stats.tot_contribution = 0;
    ni->ni_atf_stats.contribution = ni->ni_contributedtokens;
    ni->ni_atf_stats.borrow = ni->ni_borrowedtokens;
    ni->ni_atf_stats.unused = node_unusedtokens;
    ni->ni_atf_stats.tokens = ni->shadow_tx_tokens;
    ni->ni_atf_stats.raw_tx_tokens = ni->raw_tx_tokens;
    ni->ni_atf_stats.total = ic->ic_shadow_alloted_tx_tokens;
    ni->ni_atf_stats.timestamp = OS_GET_TIMESTAMP();
    if ( (ni->ni_atf_stats.act_tokens > node_unusedtokens) && (ni->ni_atf_stats.total > 0)) {
        // Note the math: 200k tokens every 200 ms => 1000k tokens / second => 1 token = 1 us.
        ni->ni_atf_stats.total_used_tokens += (ni->ni_atf_stats.act_tokens - node_unusedtokens);
        if (ic->ic_atf_logging) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "client %s is currently using %d usecs which is %d%% of available airtime\n",
                    ether_sprintf(ni->ni_macaddr),
                    (ni->ni_atf_stats.act_tokens - node_unusedtokens),
                    (((ni->ni_atf_stats.act_tokens - node_unusedtokens)*100) / ni->ni_atf_stats.total) );
        }
    }
    ni->ni_atf_stats.throughput = ni->ni_throughput;

    /* If atfdata history not available for the node */
    if(ni->ni_atfdata_logged < ATF_DATA_LOG_SIZE)
    {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ATF,
           "%s - Node History not available \n\r", ether_sprintf(ni->ni_macaddr));
        if(ni->ni_atfindex)
        {
            /* tx_tokens will be zero until atfcfg_timer updates atf_units */
            if( (node_unusedtokens <= ni->raw_tx_tokens) && (ni->raw_tx_tokens) )
            {
                    ni->ni_unusedtokenpercent[ni->ni_atfindex -1 ] = ((node_unusedtokens/ni->raw_tx_tokens) * 100);
            }
            else
            {
                ni->ni_unusedtokenpercent[ni->ni_atfindex -1 ] = 0;
            }
        }

        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ATF,
           "(node %s) atfdata_logged : %d ni_atfindex : %d \n\r",
                ether_sprintf(ni->ni_macaddr), ni->ni_atfdata_logged, ni->ni_atfindex);
        ni->ni_atfdata_logged++;
        ni->ni_atfindex++;

        if (ni->ni_atfindex >= ATF_DATA_LOG_SIZE)
        {
            IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ATF,
               "%s ni_atfindex > %d . reset to 0 \n\r",ether_sprintf(ni->ni_macaddr), ATF_DATA_LOG_SIZE);
            ni->ni_atfindex = 0;
        }
        return;
    }

    /*  Compute unused tokens.
        If this node had borrowed tokens in the previous iteration,
        do not account borrowed tokens in unusedtoken compuation.
     */
    if(ni->ni_atfborrow)
    {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ATF,
                           "%s -  Borrow set  : unused : %d borrowed : %d\n\r",
                            ether_sprintf(ni->ni_macaddr), node_unusedtokens,
                            ni->ni_borrowedtokens);
        node_unusedtokens = (node_unusedtokens > ni->ni_borrowedtokens) ? (node_unusedtokens - ni->ni_borrowedtokens): 0;
    }

    switch(ni->ni_atfindex)
    {
        case 0:
            node_index = (ATF_DATA_LOG_SIZE - 1);
            break;
        case ATF_DATA_LOG_SIZE:
            node_index = 0;
            break;
        default:
            node_index = (ni->ni_atfindex - 1);
    }

    /* Update unused token percentage */
    /* tx_tokens will be zero until atfcfg_timer updates atf_units */
    if( (node_unusedtokens <= (ni->raw_tx_tokens - ni->ni_contributedtokens)) && (ni->raw_tx_tokens) )
    {
        ni->ni_unusedtokenpercent[ node_index ] =
            ((node_unusedtokens * 100)/ (ni->raw_tx_tokens - ni->ni_contributedtokens));
    }
    else
    {
        ni->ni_unusedtokenpercent[ node_index ] = 100;
    }
    IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ATF,
                       "%s - unusedtoken percent[%d]: %d \n\r",
                        ether_sprintf(ni->ni_macaddr), (node_index),
                        ni->ni_unusedtokenpercent[node_index]);

    /* Calculate avg unused tokens */
    for(j = node_index, i =0 ; i < ATF_DATA_LOG_SIZE; i++)
    {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ATF,
                              "i: %d index : %d weight : %d , unusedtokenpercent : %d weighted_cal : %d \n\r",
                              i, j, unusedairtime_weights[i], ni->ni_unusedtokenpercent[j],
                              ((ni->ni_unusedtokenpercent[j] * unusedairtime_weights[i]) / 100) );
        weighted_unusedtokens_percent += ((ni->ni_unusedtokenpercent[j] * unusedairtime_weights[i]) / 100);
        j++;
        if (j == ATF_DATA_LOG_SIZE)
        {
            j = 0;
        }
    }
    ni->ni_contributedtokens = 0;
    ni->raw_tx_tokens = ni->tx_tokens;
    ni->ni_atf_stats.weighted_unusedtokens_percent = weighted_unusedtokens_percent;
    if(!ni->ni_vap->iv_vap_atf_sched) {
        if(weighted_unusedtokens_percent > ATF_UNUSEDTOKENS_CONTRIBUTE_THRESHOLD)
        {
            /* Compute the node tokens that can be contributed and deduct it from node tokens */
            ni->ni_atfborrow = 0;
            ni->ni_atf_group->atf_num_clients++;
            /* tx_tokens will be zero until atfcfg_timer updates atf_units */
            if(ni->tx_tokens)
            {
                ni->ni_contributedtokens = ( ((weighted_unusedtokens_percent - ATF_RESERVERD_TOKEN_PERCENT) * ni->tx_tokens) / 100 );
                ni->tx_tokens -= ni->ni_contributedtokens;

                /* set a lower threshold for ni->tx_tokens */
                if (ni->tx_tokens < (ATF_RESERVERD_TOKEN_PERCENT * ATF_TOKEN_INTVL_MS * 10) && ic->ic_node_buf_held(ni)) { /* 2% of airtime */
                    u_int32_t compensation = (ATF_RESERVERD_TOKEN_PERCENT * ATF_TOKEN_INTVL_MS * 10) - ni->tx_tokens;
                    /* can compensate back upto a max of what the node was contributing */
                    if (compensation > ni->ni_contributedtokens) {
                        compensation = ni->ni_contributedtokens;
                    }
                    ni->tx_tokens += compensation;
                    ni->ni_contributedtokens -= compensation;
                }
            }
            else
            {
                 ni->ni_contributedtokens = ni->tx_tokens = 0;
            }
            ni->ni_atf_group->atf_contributabletokens += ni->ni_contributedtokens;
            IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ATF,
                                "%s, Tokens to contribute : %d total_contributable tokens : %d tx_tokens : %d\n\r",
                                ether_sprintf(ni->ni_macaddr), ni->ni_contributedtokens,
                                ni->ni_atf_group->atf_contributabletokens, ni->tx_tokens);
        } else {
            /* If average unused tokens percentage is less than a min threshold, set borrow flag */
            ni->ni_atfborrow = 1;

            ni->ni_atf_group->atf_num_clients_borrow++;
            ni->ni_atf_group->atf_num_clients++;
            IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ATF,
                                 "Node MAC:%s, borrow enabled! atf_num_clients_borrow : %d tx_tokens : %d \n\r",
                                 ether_sprintf(ni->ni_macaddr), ni->ni_atf_group->atf_num_clients_borrow, ni->tx_tokens);
        }
    } else {
        ni->ni_borrowedtokens = 0;
        ni->ni_atfborrow = 0;
    }

    /* Increment node index */
    ni->ni_atfindex++;
    if (ni->ni_atfindex >= ATF_DATA_LOG_SIZE)
        ni->ni_atfindex = 0;
}

/**
 * @brief Iterate atf peer table, get the total atf_units alloted.
 *        convert unalloted atf_units to tokens and add to the
 *        contributable token pool
 * @param [in] ic  the handle to the radio
 *
 * @return unalloted tokens
 */
u_int32_t ieee80211_atf_airtime_unassigned(struct ieee80211com *ic)
{
    u_int32_t i = 0, airtime_assigned = 0, airtime_unassigned = 0;

    if(ic->atfcfg_set.grp_num_cfg)
    {
        for (i = 0; i < ic->atfcfg_set.grp_num_cfg; i++) {
            airtime_assigned += ic->atfcfg_set.atfgroup[i].grp_cfg_value;
        }
    } else if (ic->atfcfg_set.vap_num_cfg) {
        for (i = 0; i < ic->atfcfg_set.vap_num_cfg; i++) {
            airtime_assigned += ic->atfcfg_set.vap[i].vap_cfg_value;
        }
    } else if (ic->atfcfg_set.peer_num_cfg) {
        for (i = 0; i < ATF_ACTIVED_MAX_CLIENTS; i++) {
            if (ic->atfcfg_set.peer_id[i].sta_assoc_status == 1)
                /* Consider global percentage for the peer */
                airtime_assigned += ic->atfcfg_set.peer_id[i].sta_cfg_value[ATF_CFG_GLOBAL_INDEX];
        }
    }

    airtime_unassigned = WMI_ATF_DENOMINATION - airtime_assigned;
    return airtime_unassigned;
}

int32_t ieee80211_atf_set(struct ieee80211vap *vap, u_int8_t enable)
{

    struct ieee80211com *ic = vap->iv_ic;
    int32_t retv = EOK;

    if(!ic->ic_is_mode_offload(ic))
    {
        /* If atf_maxclient, set max client limit to IEEE80211_512_AID */
        if( (ic->ic_atf_maxclient) &&  (ic->ic_num_clients != IEEE80211_128_AID) )
        {
            retv = IEEE80211_128_AID;
        }

        /* if atf_maxclient is not enabled, set max client limit to IEEE80211_ATF_AID_DEF */
        if( (!ic->ic_atf_maxclient) &&  (ic->ic_num_clients != IEEE80211_ATF_AID_DEF) )
        {
            retv = IEEE80211_ATF_AID_DEF;
        }

        if (ic->ic_atf_tput_tbl_num && !ic->ic_atf_maxclient) {
            ic->ic_atf_set_enable_disable(ic, ATF_TPUT_BASED);
            if (!ic->ic_atf_tput_based)
                retv = IEEE80211_ATF_AID_DEF;
        } else {
            ic->ic_atf_set_enable_disable(ic, ATF_AIRTIME_BASED);
        }
    }

    ic->atf_commit = !!enable;
    if (ic->ic_atf_tput_tbl_num && !ic->ic_atf_maxclient) {
        ic->ic_atf_tput_based = 1;
    } else if (ic->ic_atf_tput_tbl_num) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "can't enable tput based atf as maxclients is enabled\n");
    }

    if((ic->atf_fmcap)&&(ic->atf_mode))
    {
        spin_lock(&ic->atf_lock);
        if (ic->atf_tasksched == 0)
        {
            ic->atf_tasksched = 1;
            ic->atf_vap_handler = vap;
            OS_SET_TIMER(&ic->atfcfg_timer, IEEE80211_ATF_WAIT*1000);
        }
        spin_unlock(&ic->atf_lock);

        if(!ic->ic_is_mode_offload(ic))
            OS_SET_TIMER(&ic->atf_tokenalloc_timer, ATF_TOKEN_INTVL_MS);

        /* send wmi command to target */
        if ( ic->ic_is_mode_offload(ic) && ic->atf_vap_handler ) {
            ic->ic_vap_set_param(ic->atf_vap_handler, IEEE80211_ATF_DYNAMIC_ENABLE, 1);
        }
    } else {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Either firmware capability or host ATF configuration not support!!\n");
    }
    return retv;
}

static void ieee80211_node_atf_node_resume(void *arg, struct ieee80211_node *ni)
{
    struct ieee80211com *ic = (struct ieee80211com *) arg;
    if(ni)
    {
        ic->ic_atf_node_resume(ic, ni);
    }
}

int32_t ieee80211_atf_clear(struct ieee80211vap *vap, u_int8_t val)
{
    struct ieee80211com *ic = vap->iv_ic;
    int32_t retv = EOK;

    if(!ic->ic_is_mode_offload(ic))
    {
        /* When ATF is disabled, set ic_num_clients to default value */
        if ( ic->ic_num_clients != IEEE80211_128_AID) {
            retv = IEEE80211_128_AID;
        }

        /* Before disabling ATF, resume any paused nodes */
        ieee80211_iterate_node(ic,ieee80211_node_atf_node_resume,ic);
        ic->ic_atf_set_enable_disable(ic, ATF_DISABLED);
    } else {
        /* Send WMI command to target */
        if(ic->atf_vap_handler) {
            ic->ic_vap_set_param(ic->atf_vap_handler, IEEE80211_ATF_DYNAMIC_ENABLE, 0);
        }
    }

    ic->atf_commit = !!val;
    if (ic->ic_atf_tput_based && ic->ic_atf_maxclient) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "tput based atf as well as maxclients was enabled\n");
    }
    ic->ic_atf_tput_based = 0;

    spin_lock(&ic->atf_lock);
    if (ic->atf_tasksched == 1)
    {
        ic->atf_tasksched = 0;
        ic->atf_vap_handler = NULL;
    }
    spin_unlock(&ic->atf_lock);

    return retv;
}

int ieee80211_atf_used_all_tokens(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    if (ic->atf_commit) {
        return (ic->ic_atf_sched & IEEE80211_ATF_SCHED_STRICT) ?
                ic->ic_atf_tokens_used(ic, ni) : !!ni->ni_atfborrow;
    }
    return 0;
}

int ieee80211_atf_get_debug_nodestate(struct ieee80211com *ic, struct ieee80211_node *ni, u_int32_t *nodestate)
{
    if(ni)
    {
        *nodestate = ic->ic_atf_debug_nodestate(ic, ni);
    }

    return 0;
}

int ieee80211_atf_get_debug_dump(struct ieee80211_node *ni,
                                 void **buf, u_int32_t *buf_sz, u_int32_t *id)
{
    struct atf_stats *ptr = NULL;
    int size;

    IEEE80211_NODE_STATE_LOCK_BH(ni);
    /* Locking may not be required here actually */
    size = ni->ni_atf_debug_mask + 1;
    IEEE80211_NODE_STATE_UNLOCK_BH(ni);

    if (size == 1)
        ptr = NULL;
    else
        ptr = OS_MALLOC(ni->ni_ic->ic_osdev, size * sizeof(struct atf_stats), GFP_KERNEL);

    if (ptr) {
        IEEE80211_NODE_STATE_LOCK_BH(ni);
        *buf = ni->ni_atf_debug;
        *buf_sz = size * sizeof(struct atf_stats);
        *id = ni->ni_atf_debug_id;

        ni->ni_atf_debug = ptr;
        ni->ni_atf_debug_id = 0;
        IEEE80211_NODE_STATE_UNLOCK_BH(ni);
    }

    return 0;
}

int ieee80211_atf_set_debug_size(struct ieee80211_node *ni, int size)
{
    struct atf_stats *ptr = NULL;

    IEEE80211_NODE_STATE_LOCK_BH(ni);
    if (ni->ni_atf_debug) {
        ptr = ni->ni_atf_debug;
        ni->ni_atf_debug = NULL;
    }
    ni->ni_atf_debug_mask = 0;
    ni->ni_atf_debug_id = 0;
    IEEE80211_NODE_STATE_UNLOCK_BH(ni);

    if (ptr) {
        /* Free old history */
        OS_FREE(ptr);
        ptr = NULL;
    }

    if (size > 0) {
        if (size <= 16)
            size = 16;
        else if (size <= 32)
            size = 32;
        else if (size <= 64)
            size = 64;
        else if (size <= 128)
            size = 128;
        else if (size <= 256)
            size = 256;
        else if (size <= 512)
            size = 512;
        else
            size = 1024;

        /* Allocate new history */
        ptr = OS_MALLOC(ni->ni_ic->ic_osdev, size * sizeof(struct atf_stats), GFP_KERNEL);

        if (ptr) {
            IEEE80211_NODE_STATE_LOCK_BH(ni);
            ni->ni_atf_debug = ptr;
            ni->ni_atf_debug_mask = size - 1;
            ni->ni_atf_debug_id = 0;
            IEEE80211_NODE_STATE_UNLOCK_BH(ni);
        }
    }

    return 0;
}

static void
atf_notify_aitime(struct ieee80211vap *vap, u_int8_t macaddr[], int config)
{
    osif_dev *osifp = NULL;
    struct net_device *dev = NULL;
    union iwreq_data wreq;
    struct event_data_atf_config ev;

    if (vap) {
        osifp = (osif_dev *)vap->iv_ifp;
        if (osifp) {
            dev = osifp->netdev;
        }
    }

    if (dev) {
        ev.config = config;
        memcpy(ev.macaddr, macaddr, IEEE80211_ADDR_LEN);
        memset(&wreq, 0, sizeof(wreq));
        wreq.data.flags = IEEE80211_EV_ATF_CONFIG;
        wreq.data.length = sizeof(struct event_data_atf_config);
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wreq, (void *)&ev);
    }
}

void ieee80211_atf_distribute_airtime(struct ieee80211com *ic)
{
    struct ieee80211_node_table *nt = &ic->ic_sta;
    struct ieee80211_node *ni, *next;
    struct ieee80211_node *rev_ni, *rev_next;
    rwlock_state_t lock_state;
    u_int32_t configured_airtime, airtime, associated_sta, airtime_limit, airtime_resv, configured_sta;

    OS_BEACON_DECLARE_AND_RESET_VAR(flags);
    OS_BEACON_READ_LOCK(&nt->nt_nodelock, &lock_state, flags);

    airtime_resv = ic->ic_atf_resv_airtime * (WMI_ATF_DENOMINATION / 100);

    /*
     * For each station having a throughput requirement, we find
     * out the airtime needed. If the new airtime needed is less than
     * or equal to what was previously needed, we configure the airtime
     * now itself. Else we record how much extra airtime is needed. Also,
     * we keep track of the total allotted airtime.
     */
    configured_airtime = 0;
    ni = next = NULL;
    TAILQ_FOREACH_SAFE(ni, &nt->nt_node, ni_list, next) {
        ieee80211_ref_node(ni);
        if (ni->ni_atf_tput) {
            ni->ni_atf_airtime_new = ic->ic_atf_airtime_estimate(ic,
                                                        ni, ni->ni_atf_tput, &ni->ni_throughput);
            ni->ni_atf_airtime_new *= WMI_ATF_DENOMINATION / 100;
            if (ic->ic_atf_airtime_override &&
                ic->ic_atf_airtime_override < (WMI_ATF_DENOMINATION - airtime_resv)) {
                ni->ni_atf_airtime_new = ic->ic_atf_airtime_override;
            }
            //printk("-- %u airtime required %u, max throughput %u --\n",
                     //ni->ni_associd, ni->ni_atf_airtime_new, ni->ni_throughput);
            airtime_limit = ni->ni_atf_airtime_cap * (WMI_ATF_DENOMINATION / 100);
            if (airtime_limit && (ni->ni_atf_airtime_new > airtime_limit)) {
                ni->ni_atf_airtime_new = airtime_limit;
                //printk("-- %u airtime required after capping %u --\n",
                         //ni->ni_associd, ni->ni_atf_airtime_new);
            }
            ni->ni_atf_airtime_subseq = 0;
            if (ni->ni_atf_airtime_new <= ni->ni_atf_airtime) {
                ni->ni_atf_airtime = ni->ni_atf_airtime_new;
                ni->ni_atf_airtime_more = 0;
            } else {
                ni->ni_atf_airtime_more = ni->ni_atf_airtime_new - ni->ni_atf_airtime;
            }
            configured_airtime += ni->ni_atf_airtime;
            //printk("-- %u airtime %u/%u/%u %u --\n",
                     //ni->ni_associd, ni->ni_atf_airtime, ni->ni_atf_airtime_new,
                     //ni->ni_atf_airtime_more, configured_airtime);
        } else {
            ni->ni_throughput = 0;
        }
        ieee80211_free_node(ni);
    }

    if (configured_airtime > (WMI_ATF_DENOMINATION - airtime_resv)) {
        /* Something wrong, as we only gave lesser airtimes compared to prev cycle */
        rev_ni = rev_next = NULL;
        TAILQ_FOREACH_REVERSE_SAFE(rev_ni, &nt->nt_node, node_list, ni_list, rev_next) {
            ieee80211_ref_node(rev_ni);
            if (configured_airtime <= (WMI_ATF_DENOMINATION - airtime_resv)) {
                ieee80211_free_node(rev_ni);
                break;
            }
            if (rev_ni->ni_atf_tput) {
                configured_airtime -= rev_ni->ni_atf_airtime;
                rev_ni->ni_atf_airtime = 0;
                rev_ni->ni_atf_airtime_more = rev_ni->ni_atf_airtime_new;
                //printk("-- %u deconfig as we gave more, airtime %u/%u/%u %u --\n",
                         //rev_ni->ni_associd, rev_ni->ni_atf_airtime, rev_ni->ni_atf_airtime_new,
                         // rev_ni->ni_atf_airtime_more, configured_airtime);
            }
            ieee80211_free_node(rev_ni);
        }
    }

    /*
     * For each station having a throughput requirement, we find out the
     * sum of airtimes allotted to stations newer than that station.
     */
    airtime = 0;
    rev_ni = rev_next = NULL;
    TAILQ_FOREACH_REVERSE_SAFE(rev_ni, &nt->nt_node, node_list, ni_list, rev_next) {
        ieee80211_ref_node(rev_ni);
        if (rev_ni->ni_atf_tput) {
            rev_ni->ni_atf_airtime_subseq = airtime;
            airtime += rev_ni->ni_atf_airtime;
            //printk("-- %u subsequent airtime %u --\n",
                     //rev_ni->ni_associd, rev_ni->ni_atf_airtime_subseq);
        }
        ieee80211_free_node(rev_ni);
    }

    /*
     * Starting with oldest station, go one by one and check which all have
     * extra airtime requirement. Either we give the extra airtime needed
     * or deconfigure the station.
     */
    airtime = 0;
    associated_sta = 0;
    configured_sta = 0;
    ni = next = NULL;
    TAILQ_FOREACH_SAFE(ni, &nt->nt_node, ni_list, next) {
        ieee80211_ref_node(ni);
        if (ni->ni_atf_airtime_more) {
            //printk("-- %u adjusted subsequent airtime %u --\n",
                     //ni->ni_associd, ni->ni_atf_airtime_subseq);
            if (ni->ni_atf_airtime_more <
                (WMI_ATF_DENOMINATION - configured_airtime - airtime_resv)) {
                /*
                 * There is enough unconfigured airtime to meet this extra requirement.
                 * So, we configure this station with it's new requirement.
                 */
                ni->ni_atf_airtime = ni->ni_atf_airtime_new;
                configured_airtime += ni->ni_atf_airtime_more;
                ni->ni_atf_airtime_more = 0;
                //printk("-- %u we had unconfigured airtime, airtime %u/%u/%u %u --\n",
                         //ni->ni_associd, ni->ni_atf_airtime, ni->ni_atf_airtime_new,
                         //ni->ni_atf_airtime_more, configured_airtime);
            } else {
                /* Adjust subsequent configured airtime for newer deconfigured stations */
                ni->ni_atf_airtime_subseq -=
                           airtime > ni->ni_atf_airtime_subseq ? ni->ni_atf_airtime_subseq : airtime;

                if (ni->ni_atf_airtime_subseq < ni->ni_atf_airtime_more) {
                    /*
                     * There isn't enough unconfigured airtime but at the same time
                     * deconfiguring newer stations won't help either. So, we just deconfigure
                     * the current station.
                     */
                    configured_airtime -= ni->ni_atf_airtime;
                    ni->ni_atf_airtime = 0;
                    ni->ni_atf_airtime_more = ni->ni_atf_airtime_new;
                    //printk("-- %u we don't have enough subsequent airtime, airtime %u/%u/%u %u --\n",
                             //ni->ni_associd, ni->ni_atf_airtime, ni->ni_atf_airtime_new,
                             //ni->ni_atf_airtime_more, configured_airtime);
                } else {
                    /*
                     * There isn't enough unconfigured airtime but we can deconfigure some
                     * newer stations to meet this station's extra requirement. So, we go from
                     * the newest station to the current station, deconfiguring newer stations
                     * one by one, till the current station's extra requirement can be met.
                     */

                    rev_ni = rev_next = NULL;
                    TAILQ_FOREACH_REVERSE_SAFE(rev_ni, &nt->nt_node, node_list, ni_list, rev_next) {
                        ieee80211_ref_node(rev_ni);
                        if (ni->ni_atf_airtime_more <
                            (WMI_ATF_DENOMINATION - configured_airtime - airtime_resv)) {
                            /* If we have enough airtime, configure the current station */
                            ni->ni_atf_airtime = ni->ni_atf_airtime_new;
                            configured_airtime += ni->ni_atf_airtime_more;
                            ni->ni_atf_airtime_more = 0;
                            //printk("-- %u we got enough from subsequent airtime(s), airtime %u/%u/%u %u --\n",
                                     //ni->ni_associd, ni->ni_atf_airtime, ni->ni_atf_airtime_new,
                                     //ni->ni_atf_airtime_more, configured_airtime);
                            ieee80211_free_node(rev_ni);
                            break;
                        }

                        if (rev_ni == ni) {
                            /* Something is wrong, we should have got enough airtime by now */
                            configured_airtime -= ni->ni_atf_airtime;
                            ni->ni_atf_airtime = 0;
                            ni->ni_atf_airtime_more = ni->ni_atf_airtime_new;
                            //printk("-- %u we didn't get enough subsequent airtime, airtime %u/%u/%u %u --\n",
                                     //ni->ni_associd, ni->ni_atf_airtime, ni->ni_atf_airtime_new,
                                     //ni->ni_atf_airtime_more, configured_airtime);
                            ieee80211_free_node(rev_ni);
                            break;
                        }

                        /* Try to deconfigure a newer station */
                        if (rev_ni->ni_atf_tput) {
                            airtime += rev_ni->ni_atf_airtime;
                            configured_airtime -= rev_ni->ni_atf_airtime;
                            rev_ni->ni_atf_airtime = 0;
                            rev_ni->ni_atf_airtime_more = rev_ni->ni_atf_airtime_new;
                            //printk("-- %u deconfig this, airtime %u/%u/%u %u --\n",
                                     //rev_ni->ni_associd, rev_ni->ni_atf_airtime, rev_ni->ni_atf_airtime_new,
                                     //rev_ni->ni_atf_airtime_more, configured_airtime);
                        }
                        ieee80211_free_node(rev_ni);
                    }
                }
            }
        }
        if (ni->ni_associd) {
            associated_sta++;
            if (ni->ni_atf_airtime)
                configured_sta++;
        }
        ieee80211_free_node(ni);
    }
    //printk("-- associated sta's %u and configured sta's %u --\n",
             //associated_sta, configured_sta);

    ni = next = NULL;
    TAILQ_FOREACH_SAFE(ni, &nt->nt_node, ni_list, next) {
        ieee80211_ref_node(ni);
        if (ni->ni_atf_tput && ni->ni_atf_airtime) {
            ni->atf_units = ni->ni_atf_airtime;
            if (!ni->ni_atf_airtime_configured) {
                atf_notify_aitime(ni->ni_vap, ni->ni_macaddr, 1);
            }
            ni->ni_atf_airtime_configured = 1;
        } else if (associated_sta > configured_sta) {
            ni->atf_units = (WMI_ATF_DENOMINATION - configured_airtime) / (associated_sta - configured_sta);
            if (ni->ni_atf_airtime_configured) {
                atf_notify_aitime(ni->ni_vap, ni->ni_macaddr, 0);
            }
            ni->ni_atf_airtime_configured = 0;
        } else {
            ni->atf_units = 0;
            if (ni->ni_atf_airtime_configured) {
                atf_notify_aitime(ni->ni_vap, ni->ni_macaddr, 0);
            }
            ni->ni_atf_airtime_configured = 0;
        }
        //printk("Result :: associd:%u max_throughput:%u throughput:%u max_airtime:%u "
                 //"airtime:%u atf_units:%u configured_airtime:%u reserved_airtime:%u\n",
                 //ni->ni_associd, ni->ni_throughput, ni->ni_atf_tput, ni->ni_atf_airtime_cap,
                 //ni->ni_atf_airtime, ni->atf_units, configured_airtime, airtime_resv);
        ieee80211_free_node(ni);
    }

    OS_BEACON_READ_UNLOCK(&nt->nt_nodelock, &lock_state, flags);
}

#endif

