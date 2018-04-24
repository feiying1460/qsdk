/*
 *  Copyright (c) 2008 Atheros Communications Inc.
 * All Rights Reserved.
 *
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#include <ieee80211_var.h>
#include <ieee80211_channel.h>
#include <ieee80211_rateset.h>
#include <ieee80211_config.h>
#include <ieee80211_scan.h>
#include <ieee80211_tsftimer.h>
#include <ieee80211_notify_tx_bcn.h>
#include <ieee80211P2P_api.h>
#include <ieee80211_wnm_proto.h>
#include "ieee80211_vi_dbg.h"
#include "if_athvar.h"
#if ATH_SUPPORT_EXT_STAT
#include "ol_if_athvar.h"
#endif
#include <qdf_lock.h>
#if QCA_AIRTIME_FAIRNESS
#include "ieee80211_airtime_fairness.h"

/* declaration */
unsigned int atf_mode = 0;
module_param(atf_mode, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(atf_mode,
                 "Do ATF Mode Configuration");

unsigned int atf_msdu_desc = 0;
module_param(atf_msdu_desc, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(atf_msdu_desc,
                "Controls MSDU desc in ATF Mode");

unsigned int atf_peers = 0;
module_param(atf_peers, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(atf_peers,
                "Controls peers in ATF mode");

unsigned int atf_max_vdevs = 0;
module_param(atf_max_vdevs, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(atf_max_vdevs,
                "Controls max vdevs in ATF mode");

u_int32_t ieee80211_atf_avail_tokens(struct ieee80211com *ic);
#endif

/* Support for runtime pktlog enable/disable */
unsigned int enable_pktlog_support = 1; /*Enable By Default*/
module_param(enable_pktlog_support, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(enable_pktlog_support,
        "Runtime pktlog enable/disable Support");

#if ACFG_NETLINK_TX
extern int acfg_attach(struct ieee80211com *ic);
extern void acfg_detach(struct ieee80211com *ic);
#endif

#if UMAC_SUPPORT_ACFG
extern int acfg_diag_attach(struct ieee80211com *ic);
extern int acfg_diag_detach(struct ieee80211com *ic);
#endif


int module_init_wlan(void);
void module_exit_wlan(void);


void print_vap_msg(struct ieee80211vap *vap, unsigned category, const char *fmt, ...)
{
     va_list ap;
     va_start(ap, fmt);
     if (vap) {
        asf_vprint_category(&vap->iv_print, category, fmt, ap);
     } else {
        qdf_vprint(fmt, ap);
     }
     va_end(ap);
}

void print_vap_verbose_msg(struct ieee80211vap *vap, unsigned verbose, unsigned category, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    if (vap) {
        asf_vprint(&vap->iv_print, category, verbose, fmt, args);
    } else {
        qdf_vprint(fmt, args);
    }
    va_end(args);
}

/**
* ASF print support function to print based on category for vap print control object
* @param vap - object of struct ieee80211vap in which asf print control object is declared
* @param category - category of the print message
*/
void IEEE80211_DPRINTF(struct ieee80211vap *vap, unsigned category, const char *fmt, ...)
{
     char                   tmp_buf[OS_TEMP_BUF_SIZE], *tmp;
     va_list                ap;
     struct ieee80211com    *ic = NULL;

     if ((vap) && ieee80211_msg(vap, category)) {
         ic = vap->iv_ic;
         tmp = tmp_buf + snprintf(tmp_buf,OS_TEMP_BUF_SIZE, "[%s] vap-%d(%s):",
                             msg_type_to_str(category), vap->iv_unit, vap->iv_netdev_name);
#if DBG_LVL_MAC_FILTERING
        if (!vap->iv_print.dbgLVLmac_on) {
#endif
             va_start(ap, fmt);
             vsnprintf (tmp,(OS_TEMP_BUF_SIZE - (tmp - tmp_buf)), fmt, ap);
             va_end(ap);
             print_vap_msg(vap, category, (const char *)tmp_buf, ap);
             ic->ic_log_text(ic,tmp_buf);
             OS_LOG_DBGPRINT("%s\n", tmp_buf);
#if DBG_LVL_MAC_FILTERING
        }
#endif
    }

}


/**
* ASF print support function to print based on category for vap print control object
* @param vap - object of struct ieee80211vap in which asf print control object is declared
* @param verbose - verbose level of the print message
* @param category - category of the print message
*/
void IEEE80211_DPRINTF_VB(struct ieee80211vap *vap, unsigned verbose, unsigned category, const char *fmt, ...)
{
     char                   tmp_buf[OS_TEMP_BUF_SIZE], *tmp;
     va_list                ap;
     struct ieee80211com    *ic = NULL;

     if ((vap) && (verbose <= vap->iv_print.verb_threshold) && ieee80211_msg(vap, category)) {
         ic = vap->iv_ic;
         tmp = tmp_buf + snprintf(tmp_buf,OS_TEMP_BUF_SIZE, "[%s] vap-%d(%s):",
                             msg_type_to_str(category), vap->iv_unit, vap->iv_netdev_name);
         va_start(ap, fmt);
         vsnprintf (tmp,(OS_TEMP_BUF_SIZE - (tmp - tmp_buf)), fmt, ap);
         va_end(ap);
         print_vap_verbose_msg(vap, verbose, category, (const char *)tmp_buf, ap);
         ic->ic_log_text(ic,tmp_buf);
         OS_LOG_DBGPRINT("%s\n", tmp_buf);
    }

}

/**
* ASF print support function tp print based on category for ic print control object
* @param ic - object of struct ieee80211com in which asf print control object is declared
* @param category - category of the print message
*/
void IEEE80211_DPRINTF_IC_CATEGORY(struct ieee80211com *ic, unsigned category, const char *fmt, ...)
{
    va_list args;

    if ( (ic) && ieee80211_msg_ic(ic, category)) {
        va_start(args, fmt);
        if (ic) {
            asf_vprint_category(&ic->ic_print, category, fmt, args);
        } else {
            qdf_vprint(fmt, args);
        }
        va_end(args);
    }

}

/**
* ASF print support function tp print based on category and verbose for ic print control object
* @param ic - object of struct ieee80211com in which asf print control object is declared
* @param verbose - verbose level of the print message
* @param category - category of the print message
*/
void IEEE80211_DPRINTF_IC(struct ieee80211com *ic, unsigned verbose, unsigned category, const char *fmt, ...)
{
    va_list args;

    if ((ic) && (verbose <= ic->ic_print.verb_threshold) && ieee80211_msg_ic(ic, category)) {
        va_start(args, fmt);
        if (ic) {
            asf_vprint(&(ic)->ic_print, category, verbose, fmt, args);
        } else {
            qdf_vprint(fmt, args);
        }
        va_end(args);
    }

}

static bool ieee80211_is_sw_txq_empty(struct ieee80211com *ic)
{
    return true;
}

static void ieee80211_vap_iter_mlme_inact_timeout(void *arg, struct ieee80211vap *vap)
{
    mlme_inact_timeout(vap);
}

void ieee80211_vap_mlme_inact_erp_timeout(struct ieee80211com *ic)
{
    wlan_iterate_vap_list(ic, ieee80211_vap_iter_mlme_inact_timeout, NULL);
}
/*
 * Per-ieee80211com inactivity timer callback.
 * used for checking any kind of inactivity in the
 * COM device.
 */
static OS_TIMER_FUNC(ieee80211_inact_timeout)
{
    struct ieee80211com *ic;

    OS_GET_TIMER_ARG(ic, struct ieee80211com *);
    ieee80211_timeout_stations(&ic->ic_sta);
    ieee80211_timeout_fragments(ic, IEEE80211_FRAG_TIMEOUT * 1000);
    wlan_iterate_vap_list(ic, ieee80211_vap_iter_mlme_inact_timeout, NULL);
    if (ic->ic_initialized == 1) {
        OS_SET_TIMER(&ic->ic_inact_timer, IEEE80211_INACT_WAIT * 1000);
    }
}

#if ATH_SUPPORT_EXT_STAT
static void reset_client_stat(void *arg, wlan_node_t node)
{
    /* Update statistics for next time calculation */
    IEEE80211_NODE_STAT_SET(node, rx_bytes_last, node->ni_stats.ns_rx_bytes);
    IEEE80211_NODE_STAT_SET(node, rx_data_last, node->ni_stats.ns_rx_data);
    IEEE80211_NODE_STAT_SET(node, tx_bytes_success_last, node->ni_stats.ns_tx_bytes_success);
    IEEE80211_NODE_STAT_SET(node, tx_data_success_last, node->ni_stats.ns_tx_data_success);
}

void ieee80211_reset_client_rt_rate(struct ieee80211com *ic)
{
    ieee80211_iterate_node(ic, reset_client_stat, NULL);
}

static void cal_client_stat(void *arg, wlan_node_t node)
{
    unsigned int rx_bytes_rate, rx_data_rate, tx_bytes_rate, tx_data_rate;
    /* Add temporary variables to guarantee using coherent values for calculation on SMP */
    unsigned int tmp_ns_rx_bytes = node->ni_stats.ns_rx_bytes;
    unsigned int tmp_ns_rx_data  = node->ni_stats.ns_rx_data;
    unsigned int tmp_ns_tx_bytes = node->ni_stats.ns_tx_bytes_success;
    unsigned int tmp_ns_tx_data  = node->ni_stats.ns_tx_data_success;

    /* Calculate the real-time rate */
    rx_bytes_rate = tmp_ns_rx_bytes - node->ni_stats.ns_rx_bytes_last;
    rx_data_rate  = tmp_ns_rx_data - node->ni_stats.ns_rx_data_last;
    tx_bytes_rate = tmp_ns_tx_bytes - node->ni_stats.ns_tx_bytes_success_last;
    tx_data_rate  = tmp_ns_tx_data - node->ni_stats.ns_tx_data_success_last;

    /* Update rx/tx bytes/packets for last one second */
    IEEE80211_NODE_STAT_SET(node, rx_bytes_rate, rx_bytes_rate);
    IEEE80211_NODE_STAT_SET(node, rx_data_rate, rx_data_rate);
    IEEE80211_NODE_STAT_SET(node, tx_bytes_rate, tx_bytes_rate);
    IEEE80211_NODE_STAT_SET(node, tx_data_rate, tx_data_rate);

    /* Update statistics for next time calculation */
    IEEE80211_NODE_STAT_SET(node, rx_bytes_last, tmp_ns_rx_bytes);
    IEEE80211_NODE_STAT_SET(node, rx_data_last, tmp_ns_rx_data);
    IEEE80211_NODE_STAT_SET(node, tx_bytes_success_last, tmp_ns_tx_bytes);
    IEEE80211_NODE_STAT_SET(node, tx_data_success_last, tmp_ns_tx_data);
}

static bool dbg_stat_enabled(struct ieee80211com *ic)
{
    if (ic->ic_is_mode_offload(ic)) {
        /* offload mode */
        struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
        if(scn->scn_stats.ap_stats_tx_cal_enable)
            return true;
    } else {
        struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
        struct ath_softc *sc           = ATH_DEV_TO_SC(scn->sc_dev);
        if(!sc->sc_nodebug)
            return true;
    }
    return false;
}

static OS_TIMER_FUNC(ieee80211_client_stat_timeout)
{
    struct ieee80211com *ic;
    OS_GET_TIMER_ARG(ic, struct ieee80211com *);

    /* Iterate all the associated stations per vap for the radio and call cal_client_stat() */
    ieee80211_iterate_node(ic, cal_client_stat, NULL);

    /* Restart the timer */
    if (dbg_stat_enabled(ic)) {
        OS_SET_TIMER (&ic->ic_client_stat_timer, 1000);
    }
}
#endif

#if QCA_AIRTIME_FAIRNESS
int build_bwf_for_fm(struct ieee80211com *ic)
{
    struct wmi_pdev_bwf_req *wmi_bwf = &(ic->wmi_bwfreq);
    int32_t retv = 0;
    u_int8_t i,j = 0;

    if (ic->ic_atf_tput_order_max){
        for(i = 0; i < ATF_TPUT_MAX_STA; i++)
        {
            if (ic->ic_atf_tput_tbl[i].order){
                wmi_bwf->bwf_peer_info[(ic->ic_atf_tput_tbl[i].order)-1].peer_macaddr.mac_addr31to0 = 0;
                wmi_bwf->bwf_peer_info[(ic->ic_atf_tput_tbl[i].order)-1].peer_macaddr.mac_addr47to32 = 0;
                wmi_bwf->bwf_peer_info[(ic->ic_atf_tput_tbl[i].order)-1].peer_macaddr.mac_addr31to0 |= (ic->ic_atf_tput_tbl[i].mac_addr[0] & 0xff);
                wmi_bwf->bwf_peer_info[(ic->ic_atf_tput_tbl[i].order)-1].peer_macaddr.mac_addr31to0 |= ic->ic_atf_tput_tbl[i].mac_addr[1]<<8;
                wmi_bwf->bwf_peer_info[(ic->ic_atf_tput_tbl[i].order)-1].peer_macaddr.mac_addr31to0 |= ic->ic_atf_tput_tbl[i].mac_addr[2]<<16;
                wmi_bwf->bwf_peer_info[(ic->ic_atf_tput_tbl[i].order)-1].peer_macaddr.mac_addr31to0 |= ic->ic_atf_tput_tbl[i].mac_addr[3]<<24;
                wmi_bwf->bwf_peer_info[(ic->ic_atf_tput_tbl[i].order)-1].peer_macaddr.mac_addr47to32 |= (ic->ic_atf_tput_tbl[i].mac_addr[4] & 0xff);
                wmi_bwf->bwf_peer_info[(ic->ic_atf_tput_tbl[i].order)-1].peer_macaddr.mac_addr47to32 |= ic->ic_atf_tput_tbl[i].mac_addr[5]<<8;
                wmi_bwf->bwf_peer_info[(ic->ic_atf_tput_tbl[i].order)-1].throughput = ic->ic_atf_tput_tbl[i].tput;
                wmi_bwf->bwf_peer_info[(ic->ic_atf_tput_tbl[i].order)-1].max_airtime = ic->ic_atf_tput_tbl[i].airtime;
                wmi_bwf->bwf_peer_info[(ic->ic_atf_tput_tbl[i].order)-1].priority = ic->ic_atf_tput_tbl[i].order;
                j++;
            }
        }
    }
    wmi_bwf->bwf_peer_info[j].peer_macaddr.mac_addr31to0 = 0xffffffff;
    wmi_bwf->bwf_peer_info[j].peer_macaddr.mac_addr47to32 = 0xffffffff;
    wmi_bwf->bwf_peer_info[j].throughput = 0;
    wmi_bwf->bwf_peer_info[j].max_airtime = ic->ic_atf_resv_airtime;
    wmi_bwf->bwf_peer_info[j].priority = j+1;
    wmi_bwf->num_peers = ic->ic_atf_tput_order_max + 1;
    ic->ic_set_bwf(ic);
    return retv;
}

int
build_atf_for_fm(struct ieee80211com *ic)
{
    struct     wmi_pdev_atf_req  *wmi_req = &(ic->wmi_atfreq);
    struct     wmi_pdev_atf_peer_ext_request *wmi_peer_ext_req = &(ic->wmi_atf_peer_req);
    struct     wmi_pdev_atf_ssid_group_req *wmi_group_req = &(ic->wmi_atf_group_req);

    int32_t    retv = 0;

    u_int8_t   i,j;


/*    printk("build_atf_for_fm: ic->atfcfg_set.peer_num_cal=%d\n",ic->atfcfg_set.peer_num_cal);*/
    if(ic->atfcfg_set.peer_num_cal != 0)
    {
       wmi_req->percentage_uint = ic->atfcfg_set.percentage_unit;
       wmi_req->num_peers = ic->atfcfg_set.peer_num_cal;
       wmi_peer_ext_req->num_peers = ic->atfcfg_set.peer_num_cal;
       for (i = 0, j = 0; (i < ATF_ACTIVED_MAX_CLIENTS)&&(j < ic->atfcfg_set.peer_num_cal); i++)
       {
            if(ic->atfcfg_set.peer_id[i].sta_assoc_status == 1)
            {
                if (ic->atfcfg_set.peer_id[i].index_group == 0xff)
                    wmi_peer_ext_req->atf_peer_ext_info[j].group_index = ic->atfcfg_set.peer_id[i].index_group;
                else
                    wmi_peer_ext_req->atf_peer_ext_info[j].group_index = (ic->atfcfg_set.peer_id[i].index_group - 1);
                wmi_peer_ext_req->atf_peer_ext_info[j].atf_units_reserved = 0xff;
                wmi_peer_ext_req->atf_peer_ext_info[j].peer_macaddr.mac_addr31to0 = 0;
                wmi_peer_ext_req->atf_peer_ext_info[j].peer_macaddr.mac_addr47to32 = 0;
                wmi_peer_ext_req->atf_peer_ext_info[j].peer_macaddr.mac_addr31to0 |= (ic->atfcfg_set.peer_id[i].sta_mac[0] & 0xff);
                wmi_peer_ext_req->atf_peer_ext_info[j].peer_macaddr.mac_addr31to0 |= ic->atfcfg_set.peer_id[i].sta_mac[1]<<8;
                wmi_peer_ext_req->atf_peer_ext_info[j].peer_macaddr.mac_addr31to0 |= ic->atfcfg_set.peer_id[i].sta_mac[2]<<16;
                wmi_peer_ext_req->atf_peer_ext_info[j].peer_macaddr.mac_addr31to0 |= ic->atfcfg_set.peer_id[i].sta_mac[3]<<24;
                wmi_peer_ext_req->atf_peer_ext_info[j].peer_macaddr.mac_addr47to32 |= (ic->atfcfg_set.peer_id[i].sta_mac[4] & 0xff);
                wmi_peer_ext_req->atf_peer_ext_info[j].peer_macaddr.mac_addr47to32 |= ic->atfcfg_set.peer_id[i].sta_mac[5]<<8;

                wmi_req->atf_peer_info[j].percentage_peer = ic->atfcfg_set.peer_id[i].sta_cal_value;
                wmi_req->atf_peer_info[j].peer_macaddr.mac_addr31to0 = 0;
                wmi_req->atf_peer_info[j].peer_macaddr.mac_addr47to32 = 0;
                wmi_req->atf_peer_info[j].peer_macaddr.mac_addr31to0 |= ic->atfcfg_set.peer_id[i].sta_mac[0];
                wmi_req->atf_peer_info[j].peer_macaddr.mac_addr31to0 |= ic->atfcfg_set.peer_id[i].sta_mac[1]<<8;
                wmi_req->atf_peer_info[j].peer_macaddr.mac_addr31to0 |= ic->atfcfg_set.peer_id[i].sta_mac[2]<<16;
                wmi_req->atf_peer_info[j].peer_macaddr.mac_addr31to0 |= ic->atfcfg_set.peer_id[i].sta_mac[3]<<24;
                wmi_req->atf_peer_info[j].peer_macaddr.mac_addr47to32 |= ic->atfcfg_set.peer_id[i].sta_mac[4];
                wmi_req->atf_peer_info[j].peer_macaddr.mac_addr47to32 |= ic->atfcfg_set.peer_id[i].sta_mac[5]<<8;
                j++;
            }
       }
    }
    else{
       retv = -1;
       QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "No peer in allocation table, no action to firmware!\n");
    }
    wmi_group_req->num_groups =  ic->atfcfg_set.grp_num_cfg;
    for (i = 0; (i < ATF_ACTIVED_MAX_ATFGROUPS) && (i < ic->atfcfg_set.grp_num_cfg); i++)
    {
        wmi_group_req->atf_group_info[i].percentage_group = ic->atfcfg_set.atfgroup[i].grp_cfg_value;
        wmi_group_req->atf_group_info[i].atf_group_units_reserved = 0xff;
    }

    return retv;
}

int
build_atf_alloc_tbl(struct ieee80211com *ic)
{
    struct     ieee80211_node_table *nt = &ic->ic_sta;
    struct     ieee80211vap *vap = NULL;
    struct     ieee80211_node *ni;
    int32_t    retv = 0;
    u_int8_t   i,vap_index = 0, k=0;
    u_int32_t  group_index = 0xFF;
    struct group_list *group = NULL;

    /* Peer by Peer look up vap in alloc table, then program peer table*/
    for (i = 0, ic->atfcfg_set.peer_num_cal = 0; i < ATF_ACTIVED_MAX_CLIENTS; i++)
    {
       if((ic->atfcfg_set.peer_id[i].index_vap != 0)&&(ic->atfcfg_set.peer_id[i].sta_assoc_status == 1))
           ic->atfcfg_set.peer_num_cal++;
    }

    if (ic->atfcfg_set.percentage_unit == 0)
       ic->atfcfg_set.percentage_unit = PER_UNIT_1000;

    /* 1. Check vap is in alloc table.
          yes-->save vap (index+1) from vap table for peer table
          no--->save 0xff as vap_index for peer table.
       2. loop peer table and find match peer mac or new peer,
          put vap_index and new peer mac addr.
    */
    if(ic->atfcfg_set.peer_num_cal!= 0)
    {
        TAILQ_FOREACH(ni, &nt->nt_node, ni_list) {
            vap = ni->ni_vap;
            /* Skip managed node so that we don't consider it as peer node */
            if(ni->ni_vap->iv_opmode == IEEE80211_M_STA){
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s ATF: managed node %s ,don't add in alloc table \n",__func__,ether_sprintf(ni->ni_macaddr));
                continue;
            }

            if(ic->ic_atf_ssidgroup)
            {
                /*
                  Search for this vap in the atfgroup table & find the group id
                */
                group_index = 0xFF;
                for (i = 0; i < ic->atfcfg_set.grp_num_cfg; i++)
                {
                    for (k = 0; k < ic->atfcfg_set.atfgroup[i].grp_num_ssid; k++)
                    {
                        if (strncmp(ic->atfcfg_set.atfgroup[i].grp_ssid[k], vap->iv_bss->ni_essid, IEEE80211_NWID_LEN) == 0)
                        {
                            group_index = i + 1;
                            break;
                        }
                    }
                }
            }

            for (i = 0, vap_index = 0xff; i < ic->atfcfg_set.vap_num_cfg; i++)
            {

                if ((OS_MEMCMP(ic->atfcfg_set.vap[i].essid,vap->iv_bss->ni_essid,vap->iv_bss->ni_esslen) == 0)&&
                    (strlen(ic->atfcfg_set.vap[i].essid) == strlen(vap->iv_bss->ni_essid)))

                {
                    vap_index = i+1;
                    break;
                }
            }

            if (ni->ni_associd != 0)
            {
                 /* Fill peer alloc table */
                 for (i = 0; i < ATF_ACTIVED_MAX_CLIENTS; i++)
                 {
                    if(ic->atfcfg_set.peer_id[i].index_vap != 0)
                    {
                        if(OS_MEMCMP(ic->atfcfg_set.peer_id[i].sta_mac,ni->ni_macaddr,IEEE80211_ADDR_LEN) == 0)
                        {
                            ic->atfcfg_set.peer_id[i].index_vap = vap_index;

                             /* update the peer group index
                                group_index = 0xFF, if vap not part of any ATF groups
                                group_index = 1 - 32(index), if vap part of an ATF group
                              */
                            ic->atfcfg_set.peer_id[i].index_group = group_index;
                            if(!ic->ic_is_mode_offload(ic))
                            {
                                if(group_index == 0xFF)
                                {
                                    group = TAILQ_FIRST(&ic->ic_atfgroups);
                                    /* Point to the default group */
                                    ni->ni_atf_group = group;
                                } else {
                                    ni->ni_atf_group = ic->atfcfg_set.atfgroup[group_index - 1].grplist_entry;
                                }
                            }

                            if(ic->atfcfg_set.peer_id[i].sta_cfg_mark)
                               ic->atfcfg_set.peer_id[i].sta_cfg_mark = 0;
                                    /* printk("build_atf_alloc_tbl--found station---suceessful!!  \n"); */
                            break;
                        }else{
                                /* printk("Continue to look up empty alloc table entry,current index entry=%d\n",i); */
                            /* This will appear each time until a non used index is found. So commenting it */
                        }
                    }else{
                        if(OS_MEMCMP(vap->iv_myaddr,ni->ni_macaddr,IEEE80211_ADDR_LEN) !=0 )
                        {
                            OS_MEMCPY(&(ic->atfcfg_set.peer_id[i].sta_mac[0]),&(ni->ni_macaddr[0]),IEEE80211_ADDR_LEN);
                            ic->atfcfg_set.peer_id[i].index_vap = vap_index;

                            /* update the peer group index
                               group_index = 0xFF, if vap not part of any ATF groups
                               group_index = 1 - 32(index), if vap part of an ATF group
                             */
                            ic->atfcfg_set.peer_id[i].index_group = group_index;
                            if(!ic->ic_is_mode_offload(ic))
                            {
                                if(group_index == 0xFF)
                                {
                                    /* Point to the default group */
                                    group = TAILQ_FIRST(&ic->ic_atfgroups);
                                    ni->ni_atf_group = group;
                                } else {
                                    ni->ni_atf_group = ic->atfcfg_set.atfgroup[group_index - 1].grplist_entry;
                                }
                            }
                        }
                        break;
                    }
                 }
                 if(i == ATF_ACTIVED_MAX_CLIENTS)
                 {
                     /*printk("allocate table is full, not have pos to fill in new peer, there's something wrong!\n");
                     for (i = 0; i < ATF_ACTIVED_MAX_CLIENTS; i++)
                     {
                        if(ic->atfcfg_set.peer_id[i].sta_cfg_mark)
                          printk("Wrong input peer macaddr-- 0x%2x:0x%2x:0x%2x:0x%2x:0x%2x:0x%2x \n",
                                  ic->atfcfg_set.peer_id[i].sta_mac[0],ic->atfcfg_set.peer_id[i].sta_mac[1],
                                  ic->atfcfg_set.peer_id[i].sta_mac[2],ic->atfcfg_set.peer_id[i].sta_mac[3],
                                  ic->atfcfg_set.peer_id[i].sta_mac[4],ic->atfcfg_set.peer_id[i].sta_mac[5]);
                     }*/
                     break;
                 }
            }
        }
    }else{
        /* printk("Empty table,no para setting to pass firmware! \n"); */
       retv = -1;
    }

    return retv;
}

int
vrf_atf_cfg_value(struct ieee80211com *ic)
{
    int32_t    retv = 0;
    u_int32_t  vap_cfg_added = 0;
    u_int32_t  peer_cfg_added = 0;
    u_int32_t  sta_value_cfg = 0;
    u_int32_t  sta_value_global = 0;
    u_int32_t  per_others = 0;
    u_int8_t   vap_num = 0;
    u_int8_t   i = 0, j =0;

    vap_num = ic->atfcfg_set.vap_num_cfg;
    for (i = 0; (i< ATF_CFG_NUM_VDEV)&&(vap_num != 0); i++)
    {
        if(ic->atfcfg_set.vap[i].cfg_flag)
        {
             vap_cfg_added += ic->atfcfg_set.vap[i].vap_cfg_value;
             vap_num--;
        }
    }

    if(vap_cfg_added > ic->atfcfg_set.percentage_unit)
    {
        retv = -1;
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n VAPs configuration value assigment wrong!!\n");
        goto end_vrf_atf_cfg;
    }else {
        per_others = (ic->atfcfg_set.percentage_unit - vap_cfg_added);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n VAPs percentage for other :%d\n",(per_others/10));
    }

    vap_num = ic->atfcfg_set.vap_num_cfg;
    for (i = 0, peer_cfg_added = 0; (i< ATF_CFG_NUM_VDEV)&&(vap_num != 0); i++)
    {
        if(ic->atfcfg_set.vap[i].cfg_flag)
        {
             vap_num--;
             peer_cfg_added = 0;
             for ( j = 0; j<ATF_ACTIVED_MAX_CLIENTS; j++)
             {
                  if(ic->atfcfg_set.peer_id[j].index_vap == (i+1))
                  {
                      if(ic->atfcfg_set.peer_id[j].cfg_flag)
                      {
                          sta_value_cfg = ic->atfcfg_set.peer_id[j].sta_cfg_value[ic->atfcfg_set.peer_id[j].index_vap];
                          peer_cfg_added += ((ic->atfcfg_set.vap[i].vap_cfg_value * sta_value_cfg) / ic->atfcfg_set.percentage_unit);
                          /* Check for the global percentage for the sta as we will use gloabal if per ssid config in not done */
                          if(!sta_value_cfg)
                          {
                              sta_value_global = ((ic->atfcfg_set.vap[i].vap_cfg_value * ic->atfcfg_set.peer_id[j].sta_cfg_value[ATF_CFG_GLOBAL_INDEX]) / ic->atfcfg_set.percentage_unit);
                              peer_cfg_added += sta_value_global;

                          }
                      }
                  }

             }

             if(peer_cfg_added > ic->atfcfg_set.vap[i].vap_cfg_value)
             {
                retv = -1;
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n Peers configuration value assignment wrong!! Reassign the values \n");
                goto end_vrf_atf_cfg;
             }
        }
    }

    peer_cfg_added = 0;
    sta_value_global = 0;
    for ( j = 0; j<ATF_ACTIVED_MAX_CLIENTS; j++)
    {
      if(ic->atfcfg_set.peer_id[j].index_vap == 0xFF)
      {
          if(ic->atfcfg_set.peer_id[j].cfg_flag)
          {
              sta_value_global = ic->atfcfg_set.peer_id[j].sta_cfg_value[ATF_CFG_GLOBAL_INDEX];
              peer_cfg_added += ((per_others * sta_value_global) / ic->atfcfg_set.percentage_unit);
          }
      }
    }
    if(peer_cfg_added > per_others)
    {
        retv = -1;
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n Peers configuration Global value assignment wrong!! Reassign the values \n");
        goto end_vrf_atf_cfg;
    }



end_vrf_atf_cfg:
    return retv;
}

int
vrf_atf_peer_value(struct ieee80211com *ic)
{
    int32_t    retv = 0;
    u_int32_t  peer_cfg_added = 0;
    u_int32_t  sta_value_cfg = 0;
    u_int32_t  sta_value_global = 0;
    u_int8_t   i = 0;

    for (i=0; i<ATF_ACTIVED_MAX_CLIENTS; i++)
    {
        if(ic->atfcfg_set.peer_id[i].cfg_flag)
        {
            sta_value_cfg = ic->atfcfg_set.peer_id[i].sta_cfg_value[ic->atfcfg_set.peer_id[i].index_vap];
            peer_cfg_added += sta_value_cfg;
            /* Check for the global percentage for the sta as we will use gloabal if per ssid config in not done */
            if(!sta_value_cfg)
            {
                sta_value_global = ic->atfcfg_set.peer_id[i].sta_cfg_value[ATF_CFG_GLOBAL_INDEX];
                peer_cfg_added += sta_value_global;
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n%s Verifying global percentage %d of peer_id[%d]\n",__func__,(sta_value_global/10),i);
            }
        }
    }
    if(peer_cfg_added > ic->atfcfg_set.percentage_unit)
    {
       retv = -1;
       QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n Peers configuration value assignment wrong!! Reassign the Values \n");
    }
    return retv;
}

int
cal_atf_alloc_tbl(struct ieee80211com *ic)
{
    int32_t    retv = 0;
    u_int8_t   calcnt,stacnt,j,i = 0;
    u_int8_t   vap_num = 0, grp_num = 0;
    u_int8_t   peer_total_cnt = 0;
    u_int8_t   un_assoc_cfg_peer = 0;
    u_int8_t   peer_cfg_cnt = 0;
    u_int8_t   peer_with_zero_val = 0;
    u_int32_t  calavgval = 0;
    u_int32_t  peer_global_per = 0;
    u_int32_t  grp_per_unit = 0;
    u_int32_t  peerunits_others = 0;
    u_int32_t  per_unit = 0;
    u_int32_t  vap_per_unit = 0;
    u_int64_t  peerbitmap,calbitmap;

    struct group_list *tmpgroup = NULL, *tmpgroup_next = NULL;

    if (ic->ic_atf_ssidgroup) {
        if(!ic->ic_is_mode_offload(ic))
        {
            /* Parse the group list and remove any group marked for deletion */
            TAILQ_FOREACH_SAFE(tmpgroup, &ic->ic_atfgroups, group_next, tmpgroup_next) {
                if(tmpgroup->group_del == 1)
                {
                    TAILQ_REMOVE(&ic->ic_atfgroups, tmpgroup, group_next);
                    OS_FREE(tmpgroup);
                    tmpgroup = NULL;
                }
            }
        }

        peer_total_cnt = ic->atfcfg_set.peer_num_cal;
        grp_num = ic->atfcfg_set.grp_num_cfg;
        per_unit = ic->atfcfg_set.percentage_unit;
        for (i = 0; (i< ATF_ACTIVED_MAX_ATFGROUPS)&&(grp_num != 0); i++)
        {
            grp_per_unit = ic->atfcfg_set.atfgroup[i].grp_cfg_value;
            per_unit -= grp_per_unit;
            grp_num--;
            for ( j = 0, stacnt=0, peerbitmap = 0, calbitmap=1; j<ATF_ACTIVED_MAX_CLIENTS; j++)
            {
                if(ic->atfcfg_set.peer_id[j].index_group == (i+1))
                {
                    peerbitmap |= (calbitmap<<j);
                    stacnt++;
                }
            }
            if (stacnt)
            {
                calavgval = grp_per_unit/stacnt;
                for ( j = 0, calbitmap = 1; j<ATF_ACTIVED_MAX_CLIENTS; j++)
                {
                    if(peerbitmap &(calbitmap<<j))
                        ic->atfcfg_set.peer_id[j].sta_cal_value = calavgval;
                }
                peer_total_cnt -= stacnt;
            }
        } /*End of loop*/
        /*Handle left stations that do not include in config vap*/
        /*  printk("VAP host config mode--cal left sta Units stacnt=%d lefttotalcnt=%d\n",stacnt,peer_total_cnt);*/
        if(peer_total_cnt != 0)
        {
            calavgval = per_unit/peer_total_cnt;
            for ( j = 0; j<ATF_ACTIVED_MAX_CLIENTS; j++)
            {
                if (ic->atfcfg_set.peer_id[j].index_group == 0xFF)
                {
                    if (ic->atfcfg_set.peer_id[j].sta_assoc_status == 1)
                        ic->atfcfg_set.peer_id[j].sta_cal_value = calavgval;
                    else{
                        ic->atfcfg_set.peer_id[j].sta_cal_value = 0;
                        un_assoc_cfg_peer++;
                    }
                }
            }
        }
    } else if(ic->atfcfg_set.vap_num_cfg) {
         if(!ic->ic_is_mode_offload(ic)) {
             TAILQ_FOREACH(tmpgroup, &ic->ic_atfgroups, group_next) {
                 tmpgroup->group_unused_airtime = 0;
             }
         }

         retv = vrf_atf_cfg_value(ic);
         if(retv != 0)
         goto end_cal_atf;

         peer_total_cnt = ic->atfcfg_set.peer_num_cal;
         vap_num = ic->atfcfg_set.vap_num_cfg;
         per_unit = ic->atfcfg_set.percentage_unit;
         peer_cfg_cnt = ic->atfcfg_set.peer_num_cfg;

         for (i = 0; (i< ATF_CFG_NUM_VDEV)&&(vap_num != 0); i++)
         {
             if(ic->atfcfg_set.vap[i].cfg_flag)
             {
                  vap_per_unit = ic->atfcfg_set.vap[i].vap_cfg_value;
                  per_unit -= vap_per_unit;
                  vap_num--;
                  for ( j = 0, stacnt=0, peerbitmap = 0, calbitmap=1; j<ATF_ACTIVED_MAX_CLIENTS; j++)
                  {
                      if(ic->atfcfg_set.peer_id[j].index_vap == (i+1))
                      {
                         if(ic->atfcfg_set.peer_id[j].cfg_flag)
                         {
                            if (ic->atfcfg_set.peer_id[j].sta_assoc_status == 1)
                            {
                                 ic->atfcfg_set.peer_id[j].sta_cal_value = (ic->atfcfg_set.vap[i].vap_cfg_value*ic->atfcfg_set.peer_id[j].sta_cfg_value[ic->atfcfg_set.peer_id[j].index_vap])/ic->atfcfg_set.percentage_unit;
                                 /* Get the global  percentage for this SSID if present */
                                 peer_global_per = ic->atfcfg_set.peer_id[j].sta_cfg_value[ATF_CFG_GLOBAL_INDEX];
                                 if(ic->atfcfg_set.peer_id[j].sta_cal_value)
                                 {
                                     vap_per_unit -= ic->atfcfg_set.peer_id[j].sta_cal_value;
                                     peer_total_cnt--;
                                 }else if(peer_global_per){
                                     ic->atfcfg_set.peer_id[j].sta_cal_value = (ic->atfcfg_set.vap[i].vap_cfg_value*peer_global_per)/ic->atfcfg_set.percentage_unit;
                                     vap_per_unit -= ic->atfcfg_set.peer_id[j].sta_cal_value;
                                     peer_total_cnt--;

                                 }else{
                                    /* Treat these as unconfigured peers for this ssid */
                                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,"\n%s ATF:Peer has no specific percentage for this SSID neither global \n",__func__);
                                    peerbitmap |= (calbitmap<<j);
                                    stacnt++;
                                 }

                            }else{
                                 ic->atfcfg_set.peer_id[j].sta_cal_value = 0;
                                 un_assoc_cfg_peer++;
                            }
                            peer_cfg_cnt--;
                         }else{
                            peerbitmap |= (calbitmap<<j);
                            stacnt++;
                         }
                      }

                  }
                  if (stacnt)
                  {
                     calavgval = vap_per_unit/stacnt;
                     for ( j = 0, calbitmap = 1; j<ATF_ACTIVED_MAX_CLIENTS; j++)
                     {
                        if(peerbitmap & (calbitmap<<j))
                        {
                           ic->atfcfg_set.peer_id[j].sta_cal_value = calavgval;
                           /* Decrease the net vap percentage */
                           vap_per_unit -= ic->atfcfg_set.peer_id[j].sta_cal_value;
                        }
                     }
                     peer_total_cnt -= stacnt;
                  }
                  if(!ic->ic_is_mode_offload(ic))
                  {
                      u_int8_t peer_flg = 0;
                      u_int32_t group_index = 0;
                      /* update unused tokens in the group table
                       * An SSID with 100% airtime & only 1 peer with 20% airtime associated,
                       * 80% of airtime will be marked unused.
                       * If the same SSID has another peer without a peer based ATF allocation,
                       * peer 2 will be assigned 80% of airtime & unused airtime will be 0
                       */
                      for ( j = 0; j<ATF_ACTIVED_MAX_CLIENTS; j++)
                      {
                          if(ic->atfcfg_set.peer_id[j].index_vap == (i+1))
                          {
                              peer_flg = 1;
                              group_index = ic->atfcfg_set.peer_id[j].index_group;
                              if(group_index == 0xFF)
                              {
                                  /* Point to the default group */
                                  tmpgroup = TAILQ_FIRST(&ic->ic_atfgroups);
                              } else{
                                  tmpgroup = ic->atfcfg_set.atfgroup[group_index - 1].grplist_entry;
                              }
                              /* SSID has one or more peers with peer based ATF configured
                                 unusedairtime = SSID airtime - peer airtime  */
                              if( (!stacnt) && (tmpgroup != NULL) ) {
                                  tmpgroup->group_unused_airtime += vap_per_unit;
                              }
                          }
                      }
                      /* If no peers in an SSID, add it's airtime to unused pool */
                      if(peer_flg == 0)
                      {
                        /* Only default group in SSID based configuration
                           Add unused airtime to the default group */
                        tmpgroup = TAILQ_FIRST(&ic->ic_atfgroups);
                        tmpgroup->group_unused_airtime += ic->atfcfg_set.vap[i].vap_cfg_value;
                      }
                 }
             }
         } /*End of loop*/
         /*Handle left stations that do not include in config vap*/
          /* printk("VAP host config mode--cal left sta Units stacnt=%d lefttotalcnt=%d\n",stacnt,peer_total_cnt);*/
         if(peer_total_cnt != 0)
         {
             if (peer_cfg_cnt > 0)
             {
                 for ( j = 0; j<ATF_ACTIVED_MAX_CLIENTS; j++)
                 {
                     if ((ic->atfcfg_set.peer_id[j].index_vap == 0xff) && (ic->atfcfg_set.peer_id[j].cfg_flag == 1))
                     {
                         if (ic->atfcfg_set.peer_id[j].sta_assoc_status == 1)
                         {
                             /* Apply global percentage for this peer */
                             ic->atfcfg_set.peer_id[j].sta_cal_value = (per_unit*ic->atfcfg_set.peer_id[j].sta_cfg_value[ATF_CFG_GLOBAL_INDEX])/ic->atfcfg_set.percentage_unit;
                             /* Total Airtime assigned to peers in 'Others' category */
                             if(ic->atfcfg_set.peer_id[j].sta_cal_value)
                             {
                                peerunits_others += ic->atfcfg_set.peer_id[j].sta_cal_value;
                                peer_total_cnt--;
                             }else{
                                peer_with_zero_val++;
                             }
                         }else{
                             ic->atfcfg_set.peer_id[j].sta_cal_value = 0;
                             un_assoc_cfg_peer++;
                         }
                         peer_cfg_cnt--;
                     }
                 }
                 per_unit -= peerunits_others;
                 peerunits_others = 0;
                 /* split equally among peer with zero value as these have been configured but no %age for this vap */
                 if(peer_with_zero_val)
                 {
                    calavgval = per_unit/peer_total_cnt;
                    for ( j = 0; j<ATF_ACTIVED_MAX_CLIENTS; j++)
                    {
                        if ((ic->atfcfg_set.peer_id[j].index_vap == 0xff) && (ic->atfcfg_set.peer_id[j].cfg_flag == 1) && !(ic->atfcfg_set.peer_id[j].sta_cal_value))
                        {
                            if (ic->atfcfg_set.peer_id[j].sta_assoc_status == 1)
                            {
                                ic->atfcfg_set.peer_id[j].sta_cal_value = calavgval;
                                peerunits_others += ic->atfcfg_set.peer_id[j].sta_cal_value;
                                peer_total_cnt--;
                            }else{
                                ic->atfcfg_set.peer_id[j].sta_cal_value = 0;
                                un_assoc_cfg_peer++;
                            }
                        }
                    }

                 }
             }

             per_unit -= peerunits_others;
             if(peer_total_cnt > 0)
             {
                calavgval = per_unit/peer_total_cnt;
                for ( j = 0; j<ATF_ACTIVED_MAX_CLIENTS; j++)
                {
                    if ((ic->atfcfg_set.peer_id[j].index_vap == 0xff) && (ic->atfcfg_set.peer_id[j].cfg_flag == 0))
                    {
                        if (ic->atfcfg_set.peer_id[j].sta_assoc_status == 1)
                        {
                            ic->atfcfg_set.peer_id[j].sta_cal_value = calavgval;
                            peer_total_cnt--;
                        }else{
                            ic->atfcfg_set.peer_id[j].sta_cal_value = 0;
                            un_assoc_cfg_peer++;
                        }
                    }
                }
             }
/*         }else{
              printk("There's not left stas in allocate table\n");*/
         }
    }else{
        /* printk("cal_atf_alloc_tbl -- NO VAP host config mode\n"); */
         if(ic->atfcfg_set.peer_num_cfg)
         {
           retv = vrf_atf_peer_value(ic);
           if(retv != 0)
           goto end_cal_atf;
           per_unit = ic->atfcfg_set.percentage_unit;
           for (i=0, calcnt=ic->atfcfg_set.peer_num_cfg, calbitmap = 1; ((i<ATF_ACTIVED_MAX_CLIENTS)&& (calcnt!=0)); i++)
           {
              if(ic->atfcfg_set.peer_id[i].cfg_flag)
              {
                 if(ic->atfcfg_set.peer_id[i].sta_cfg_value[ATF_CFG_GLOBAL_INDEX] <= per_unit )
                 {
                     if (ic->atfcfg_set.peer_id[i].sta_assoc_status == 1)
                     {
                         /* This is when we are in no vap host config mode so will use global config if set for a  peer*/
                         ic->atfcfg_set.peer_id[i].sta_cal_value = ic->atfcfg_set.peer_id[i].sta_cfg_value[ATF_CFG_GLOBAL_INDEX];
                         per_unit -=ic->atfcfg_set.peer_id[i].sta_cfg_value[ATF_CFG_GLOBAL_INDEX];
                      }else{
                          ic->atfcfg_set.peer_id[i].sta_cal_value = 0;
                          un_assoc_cfg_peer++;
                      }
                      calcnt--;
                 }else{
                      QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Wrong input percentage value for peer!!\n");
                      retv = -1;
                      break;
                 }
              }
           }
           if (ic->atfcfg_set.peer_num_cal >= (ic->atfcfg_set.peer_num_cfg - un_assoc_cfg_peer))
           {
              calcnt = ic->atfcfg_set.peer_num_cal - (ic->atfcfg_set.peer_num_cfg - un_assoc_cfg_peer);
              if(calcnt)
              {
                  calavgval = per_unit/calcnt;
                  for (i=0, calbitmap = 1; i<ATF_ACTIVED_MAX_CLIENTS ; i++)
                  {
                     if(ic->atfcfg_set.peer_id[i].cfg_flag == 0)
                     {
                          if(ic->atfcfg_set.peer_cal_bitmap & (calbitmap<<i))
                          {
                               ic->atfcfg_set.peer_id[i].sta_cal_value = calavgval;
                               /*printk("calavgval=%d i=%d sta_cal_value=%d\n",calavgval,i,ic->atfcfg_set.peer_id[i].sta_cal_value);*/
                          }
                     }
                  }
              }
           }else{
              QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Wrong input percentage value for peer!\n");
              retv = -1;
           }
         }else{
          if(ic->atfcfg_set.peer_num_cal)
          {
             calavgval = ic->atfcfg_set.percentage_unit/ic->atfcfg_set.peer_num_cal;
             for (i=0, calbitmap = 1; i<ATF_ACTIVED_MAX_CLIENTS; i++)
             {
                 if(ic->atfcfg_set.peer_cal_bitmap &(calbitmap<<i))
                 {
                     ic->atfcfg_set.peer_id[i].sta_cal_value = calavgval;
                 }
             }
          }else{
             QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Empty table, no para setting to pass firmware!\n");
             retv = -1;
          }
       }
    }

end_cal_atf:
    return retv;
}

void log_atf_alloc(struct ieee80211com *ic)
{
    u_int8_t  i=0, j=0, group_index=0xFF, vap_index=0xFF;
    u_int8_t* ssid_name = NULL;

    // only need to log atf while commitatf 1
    if (!(ic->atf_commit)) { return; }

    /* Peer by Peer look up vap in alloc table, then program peer table*/
    for (i=0, j=0; (i < ATF_ACTIVED_MAX_CLIENTS) && (j < ic->atfcfg_set.peer_num_cal); i++)
    {
        if(ic->atfcfg_set.peer_id[i].sta_assoc_status == 1)
        {
            // Determine ssid_name:
            group_index = ic->atfcfg_set.peer_id[i].index_group;
            vap_index   = ic->atfcfg_set.peer_id[i].index_vap;
            ssid_name = "Others";
            if (group_index != 0xFF ) {
                // Not using group name (ssid_name = ic->atfcfg_set.atfgroup[group_index - 1].grpname; )
                ssid_name = ic->atfcfg_set.atfgroup[group_index - 1].grp_ssid[0]; // First SSID in group
            }
            else if ( vap_index != 0xFF)
            {
                ssid_name = ic->atfcfg_set.vap[vap_index - 1].essid;
            }

            // Log output:
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "client %s connected to SSID %s has %d%% airtime\n",
                    ether_sprintf(ic->atfcfg_set.peer_id[i].sta_mac),
                    ssid_name,
                    (ic->atfcfg_set.peer_id[i].sta_cal_value / 10)
                  );
            j++;
        }
    }
}

OS_TIMER_FUNC(ieee80211_atfcfg_timer)
{
    struct ieee80211com *ic;
    int32_t   retv = 0;

    OS_GET_TIMER_ARG(ic, struct ieee80211com *);

    spin_lock(&ic->atf_lock);

    /*1.build atf table ic-->vap<-->ic_sta*/
    retv = build_atf_alloc_tbl(ic);
    if(retv != 0)
       goto exit_atf_timer;

    /*2.cal vpa and sta % for whole table*/
    retv = cal_atf_alloc_tbl(ic);
    if(retv != 0)
       goto exit_atf_timer;

    log_atf_alloc(ic);

    if(!ic->ic_is_mode_offload(ic))
    {
        retv= update_atf_nodetable(ic);
    } else {
        /*3.copy contents from table to structure for fm*/
        retv = build_atf_for_fm(ic);
        if(retv != 0) {
            goto exit_atf_timer;
        }
        ic->ic_set_atf(ic);
        ic->ic_send_atf_peer_request(ic);
        ic->ic_set_atf_grouping(ic);
    }
exit_atf_timer:

    ic->atf_tasksched = 0;

    spin_unlock(&ic->atf_lock);

}

/**
 * @brief Timer that Iterates the node table & distribute tokens
 *  atf_units is updated in node table by update_atf_nodetable routine
 *
 * @param [in] ic  the handle to the radio
 *
 * @return true if handle is valid; otherwise false
 */
static OS_TIMER_FUNC(wlan_atf_token_allocate_timeout_handler)
{
    struct ieee80211com *ic;
    struct ath_softc_net80211 *scn;
    u_int32_t airtime_unassigned = 0;
    u_int32_t txtokens_unassigned = 0, group_noclients_txtokens = 0;
    struct group_list *tmpgroup = NULL;

    OS_GET_TIMER_ARG(ic, struct ieee80211com *);

    scn = ATH_SOFTC_NET80211(ic);

    if (ic->ic_atf_tput_based) {
        /*
         * Instead of using airtimes configured by user, we
         * try to determine the airtimes for different nodes.
         */
        ieee80211_atf_distribute_airtime(ic);
    }

    /* Calculate 'Unassigned airtime' (1000 - Total configured airtime for VAPS)
       & update lmac layer */
    if (!ic->ic_atf_tput_based) {
        airtime_unassigned = ieee80211_atf_airtime_unassigned(ic);
        txtokens_unassigned = ieee80211_atf_compute_txtokens(ic, airtime_unassigned, ATF_TOKEN_INTVL_MS);
    }

    /* Is OBSS scheduling enabled */
    if (ic->ic_atf_sched & IEEE80211_ATF_SCHED_OBSS) {
        /* get the channel busy stats percentage */
        ic->ic_atf_chbusy = scn->sc_ops->get_chbusyper(scn->sc_dev);
        /* calculate the actual available tokens based on channel busy percentage */
        ic->atf_avail_tokens = ieee80211_atf_avail_tokens(ic);
    } else {
        /* Just use the total tokens */
        ic->atf_avail_tokens = ATF_TOKEN_INTVL_MS;
    }

    if (ic->ic_atf_sched & IEEE80211_ATF_SCHED_STRICT) {
        /* ATF - strictq algorithm
           Parse Node table , Derive txtokens & update node structure
         */
        ic->ic_alloted_tx_tokens = 0;

        if (ic->ic_atf_maxclient)
            ic->ic_atf_tokens_unassigned(ic, txtokens_unassigned);

        ieee80211_iterate_node(ic, ieee80211_node_iter_dist_txtokens_strictq, ic);
        if (ic->ic_atf_maxclient) {
            ic->ic_alloted_tx_tokens += txtokens_unassigned;
            ic->ic_txtokens_common = txtokens_unassigned;
         } else
            ic->ic_txtokens_common = 0;
        ic->ic_shadow_alloted_tx_tokens = ic->ic_alloted_tx_tokens;
    } else {
        /* ATF - fairq alogrithm */

        /* Reset the atf_ic variables at the start*/
        ic->atf_groups_borrow = 0;  // set if there are clients looking to borrow
        /* Parse through the group list and reset variables */
        TAILQ_FOREACH(tmpgroup, &ic->ic_atfgroups, group_next) {
            tmpgroup->shadow_atf_contributabletokens = tmpgroup->atf_contributabletokens;
            tmpgroup->atf_num_clients_borrow = 0;
            tmpgroup->atf_num_clients = 0;
            tmpgroup->atf_contributabletokens = 0;
        }

        /* Loop1 : Iterates through node table,
                   Identifies clients looking to borrow & Contribute tokens
                   Computes total tokens available for contribution
         */
        ieee80211_iterate_node(ic, ieee80211_node_iter_fairq_algo, ic);

        ic->atf_total_num_clients_borrow = 0;
        ic->atf_total_contributable_tokens = 0;
        /* Loop through the group list & find number of groups looking to borrow */
        TAILQ_FOREACH(tmpgroup, &ic->ic_atfgroups, group_next) {
            /* add group unused airtime to contributable pool */
            if(tmpgroup->group_unused_airtime) {
                tmpgroup->atf_contributabletokens += ieee80211_atf_compute_txtokens(ic, tmpgroup->group_unused_airtime, ATF_TOKEN_INTVL_MS);
            }

            if( !(ic->ic_atf_sched & IEEE80211_ATF_GROUP_SCHED_POLICY) &&
                ic->atfcfg_set.grp_num_cfg )
            {
                ic->atf_total_num_clients_borrow += tmpgroup->atf_num_clients_borrow;
                ic->atf_total_contributable_tokens += tmpgroup->atf_contributabletokens;

                /* If there aren't any clients in the group, add group's airtime
                   to the common contributable pool */
                if( !tmpgroup->atf_num_clients)
                {
                    group_noclients_txtokens = ieee80211_atf_compute_txtokens(ic, tmpgroup->group_airtime, ATF_TOKEN_INTVL_MS);
                    ic->atf_total_contributable_tokens += (group_noclients_txtokens - ( (ATF_RESERVERD_TOKEN_PERCENT * group_noclients_txtokens) / 100) );
                }
            }

            if( tmpgroup->atf_num_clients_borrow ) {
                ic->atf_groups_borrow++;
            }
        }

        /* If max client support is enabled & if the total number of clients
           exceeds the number supported in ATF, do not contribute unalloted tokens.
           Unalloted tokens will be used by non-atf capable clients */
        if (ic->ic_atf_maxclient) {
            ic->ic_atf_tokens_unassigned(ic, txtokens_unassigned);
            /* With Maxclient feature enabled, unassigned tokens are used by non-atf clients
               Hence, do not add unassigned tokens to node tokens */
            ic->atf_tokens_unassigned = 0;
        } else {
            /* Add unassigned tokens to the contributable token pool*/
            if (txtokens_unassigned) {
                txtokens_unassigned -= ((ATF_RESERVED_UNALLOTED_TOKEN_PERCENT * txtokens_unassigned) / 100);
            }
            /* Unassigned tokens will be added to node tokens */
            ic->atf_tokens_unassigned = txtokens_unassigned;
        }

        /* Loop2 :  Distributes tokens
                    Nodes looking to borrow tokens will get its share
                    from the contributable token pool*/
        ic->ic_alloted_tx_tokens = 0;

        ieee80211_iterate_node(ic, ieee80211_node_iter_dist_txtokens_fairq, ic);

        if (ic->ic_atf_maxclient) {
            ic->ic_alloted_tx_tokens += txtokens_unassigned;
            ic->ic_txtokens_common = txtokens_unassigned;
        } else
            ic->ic_txtokens_common = 0;

        ic->ic_shadow_alloted_tx_tokens = ic->ic_alloted_tx_tokens;
    }
    update_atf_nodetable(ic);

    if(ic->atf_commit) {
        OS_SET_TIMER(&ic->atf_tokenalloc_timer, ATF_TOKEN_INTVL_MS);
    }
}
#endif

#if UMAC_SUPPORT_WNM
static OS_TIMER_FUNC(ieee80211_bssload_timeout)
{
    struct ieee80211com *ic;
    OS_GET_TIMER_ARG(ic, struct ieee80211com *);
    ieee80211_wnm_bss_validate_inactivity(ic);
    OS_SET_TIMER(&ic->ic_bssload_timer, IEEE80211_BSSLOAD_WAIT);
}
#endif

/*
 * @brief description
 *  function executed from the timer context to update the noise stats
 *  like noise value min value, max value and median value
 *  at the end of each traffic rate.
 *
 */
void update_noise_stats(struct ieee80211com *ic)
{
    struct     ieee80211_node_table *nt = &ic->ic_sta;
    struct     ieee80211_node *ni;
    u_int8_t   *median_array;
    u_int8_t   bin_index, median_index, temp_variable;

    median_array = (u_int8_t *)OS_MALLOC(ic->ic_osdev, (ic->bin_number + 1) * sizeof(u_int8_t), GFP_KERNEL);
    if (median_array == NULL){
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Memory allocation for median array failed \n");
        return;
    }

    OS_RWLOCK_READ_LOCK(&ic->ic_sta.nt_nodelock, &lock_state);
    TAILQ_FOREACH(ni, &nt->nt_node, ni_list) {
        if (ni->ni_associd != 0){
            if (ic->bin_number != 0)
            {
                ni->ni_noise_stats[ic->bin_number].noise_value = ni->ni_rssi;
                for(bin_index = 0;bin_index <= ic->bin_number;bin_index++){
                    median_array[bin_index] = ni->ni_noise_stats[bin_index].noise_value;
                }
                for(bin_index = 0;bin_index <= ic->bin_number;bin_index++){
                    for (median_index = 0;median_index < (ic->bin_number - bin_index); median_index++){
                        if (median_array[median_index] >= median_array[median_index+1])
                        {
                            temp_variable = median_array[median_index];
                            median_array[median_index] = median_array[median_index+1];
                            median_array[median_index+1] = temp_variable;
                        }
                    }
                }
                if ((ic->bin_number) %2 == 0)
                {
                    ni->ni_noise_stats[ic->bin_number].median_value = median_array[ic->bin_number/2];
                } else{
                    ni->ni_noise_stats[ic->bin_number].median_value = median_array[(ic->bin_number/2) + 1];
                }

                if(ni->ni_noise_stats[ic->bin_number].noise_value <= ni->ni_noise_stats[ic->bin_number-1].min_value){
                    ni->ni_noise_stats[ic->bin_number].min_value = ni->ni_noise_stats[ic->bin_number].noise_value;
                } else{
                    ni->ni_noise_stats[ic->bin_number].min_value = ni->ni_noise_stats[ic->bin_number-1].min_value;
                }
                if(ni->ni_noise_stats[ic->bin_number].noise_value >= ni->ni_noise_stats[ic->bin_number-1].max_value){
                    ni->ni_noise_stats[ic->bin_number].max_value = ni->ni_noise_stats[ic->bin_number].noise_value;
                } else{
                    ni->ni_noise_stats[ic->bin_number].max_value = ni->ni_noise_stats[ic->bin_number-1].max_value;
                }
            }

            else {
                ni->ni_noise_stats[ic->bin_number].noise_value = ni->ni_rssi;
                ni->ni_noise_stats[ic->bin_number].min_value = ni->ni_noise_stats[ic->bin_number].noise_value;
                ni->ni_noise_stats[ic->bin_number].max_value = ni->ni_noise_stats[ic->bin_number].noise_value;
                ni->ni_noise_stats[ic->bin_number].median_value = ni->ni_noise_stats[ic->bin_number].noise_value;
            }
        }
    }
    OS_RWLOCK_READ_UNLOCK(&ic->ic_sta.nt_nodelock, &lock_state);
    OS_FREE(median_array);
}

/*
 * brief description
 * Timer function which is used to record the noise statistics of each node
 * timer is called ath the end of each traffic rate and is measured until
 * the end of traffic interval
 */
static OS_TIMER_FUNC(ieee80211_noise_stats_update)
{
    struct ieee80211com *ic;
    OS_GET_TIMER_ARG(ic, struct ieee80211com *);
    update_noise_stats(ic);
    ic->bin_number++;
    if(ic->bin_number < ic->traf_bins){
        OS_SET_TIMER(&ic->ic_noise_stats,ic->traf_rate * 1000);
    }
}

int
ieee80211_ifattach(struct ieee80211com *ic, IEEE80211_REG_PARAMETERS *ieee80211_reg_parm)
{
    u_int8_t bcast[IEEE80211_ADDR_LEN] = {0xff,0xff,0xff,0xff,0xff,0xff};
    int error = 0;
#define DEFAULT_TRAFFIC_INTERVAL 1800
#define DEFAULT_TRAFFIC_RATE     300
#if QCA_AIRTIME_FAIRNESS
    struct group_list *group = NULL;
#endif


    ic->ic_reg_parm = *ieee80211_reg_parm;
    /* set up broadcast address */
    IEEE80211_ADDR_COPY(ic->ic_broadcast, bcast);

    /* initialize channel list */
    ieee80211_update_channellist(ic, 0);

    /* initialize rate set */
    ieee80211_init_rateset(ic);

    /* validate ic->ic_curmode */
    if (!IEEE80211_SUPPORT_PHY_MODE(ic, ic->ic_curmode))
        ic->ic_curmode = IEEE80211_MODE_AUTO;

    /* setup initial channel settings */
    ic->ic_curchan = ieee80211_get_channel(ic, 0); /* arbitrarily pick the first channel */

    /* Enable marking of dfs by default */
    IEEE80211_FEXT_MARKDFS_ENABLE(ic);

    if (ic->ic_reg_parm.htEnableWepTkip) {
        ieee80211_ic_wep_tkip_htrate_set(ic);
    } else {
        ieee80211_ic_wep_tkip_htrate_clear(ic);
    }

    if (ic->ic_reg_parm.htVendorIeEnable)
        IEEE80211_ENABLE_HTVIE(ic);

    /* whether to ignore 11d beacon */
    if (ic->ic_reg_parm.ignore11dBeacon)
        IEEE80211_ENABLE_IGNORE_11D_BEACON(ic);

    if (ic->ic_reg_parm.disallowAutoCCchange) {
        ieee80211_ic_disallowAutoCCchange_set(ic);
    }
    else {
        ieee80211_ic_disallowAutoCCchange_clear(ic);
    }

    (void) ieee80211_setmode(ic, ic->ic_curmode, ic->ic_opmode);

    ic->ic_intval = IEEE80211_BINTVAL_DEFAULT; /* beacon interval */
    ic->ic_set_beacon_interval(ic);

    ic->ic_lintval = 1;         /* listen interval */
    ic->ic_lintval_assoc = IEEE80211_LINTVAL_MAX; /* listen interval to use in association */
    ic->ic_bmisstimeout = IEEE80211_BMISS_LIMIT * ic->ic_intval;
    TAILQ_INIT(&ic->ic_vaps);

    ic->ic_txpowlimit = IEEE80211_TXPOWER_MAX;

    /* Intialize WDS Auto Detect mode */
    ic->ic_flags_ext |= IEEE80211_FEXT_WDS_AUTODETECT;

	/*
	** Enable the 11d country code IE by default
	*/

	ic->ic_flags_ext |= IEEE80211_FEXT_COUNTRYIE;

    /* setup CWM configuration */
    ic->ic_cwm_set_mode(ic, ic->ic_reg_parm.cwmMode);
    ic->ic_cwm_set_extoffset(ic, ic->ic_reg_parm.cwmExtOffset);
    ic->ic_cwm_set_extprotmode(ic, ic->ic_reg_parm.cwmExtProtMode);
    ic->ic_cwm_set_extprotspacing(ic, ic->ic_reg_parm.cwmExtProtSpacing);

    ic->ic_cwm_set_enable(ic, ic->ic_reg_parm.cwmEnable);
    ic->ic_cwm_set_extbusythreshold(ic, ic->ic_reg_parm.cwmExtBusyThreshold);

    ic->ic_enable2GHzHt40Cap = ic->ic_reg_parm.enable2GHzHt40Cap;

#ifdef ATH_COALESCING
    ic->ic_tx_coalescing     = ic->ic_reg_parm.txCoalescingEnable;
#endif
    ic->ic_ignoreDynamicHalt = ic->ic_reg_parm.ignoreDynamicHalt;

    /* default to auto ADDBA mode */
    ic->ic_addba_mode = ADDBA_MODE_AUTO;

    if (ic->ic_reg_parm.ht20AdhocEnable) {
        /*
         * Support HT rates in Ad hoc connections.
         */
        if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NA_HT20) ||
            IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NG_HT20)) {
            ieee80211_ic_ht20Adhoc_set(ic);

            if (ic->ic_reg_parm.htAdhocAggrEnable) {
                ieee80211_ic_htAdhocAggr_set(ic);
            }
        }
    }

    if (ic->ic_reg_parm.ht40AdhocEnable) {
        /*
         * Support HT rates in Ad hoc connections.
         */
        if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NA_HT40PLUS) ||
            IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NA_HT40MINUS) ||
            IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NG_HT40PLUS) ||
            IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NG_HT40MINUS)) {
            ieee80211_ic_ht40Adhoc_set(ic);

            if (ic->ic_reg_parm.htAdhocAggrEnable) {
                ieee80211_ic_htAdhocAggr_set(ic);
            }
        }
    }

    OS_INIT_TIMER(ic->ic_osdev, &(ic->ic_inact_timer), ieee80211_inact_timeout, (void *) (ic), QDF_TIMER_TYPE_WAKE_APPS);
#if UMAC_SUPPORT_WNM
    OS_INIT_TIMER(ic->ic_osdev, &(ic->ic_bssload_timer), ieee80211_bssload_timeout, (void *) (ic), QDF_TIMER_TYPE_WAKE_APPS);
#endif
#if ATH_SUPPORT_EXT_STAT
    OS_INIT_TIMER(ic->ic_osdev, &ic->ic_client_stat_timer, ieee80211_client_stat_timeout, (void *) (ic), QDF_TIMER_TYPE_WAKE_APPS);
#endif

#if QCA_AIRTIME_FAIRNESS
    spin_lock_init(&ic->atf_lock);

    ic->ic_atf_ssidgroup = 0;
    if(!ic->ic_is_mode_offload(ic))
    {
        //Inter group default policy - strict sched across groups
        ic->ic_atf_sched |= IEEE80211_ATF_GROUP_SCHED_POLICY;

        /* Enable ATF by default - for DA
	       ATF scheduling can be enabled/disabled using commitatf command */
	    ic->atf_mode = 1;
	    ic->atf_fmcap = 1;

        /* Creating Default group */
        TAILQ_INIT(&ic->ic_atfgroups);
        group = (struct group_list *)OS_MALLOC(ic->ic_osdev, sizeof(struct group_list), GFP_KERNEL);
        if (strlcpy(group->group_name, DEFAULT_GROUPNAME, sizeof(DEFAULT_GROUPNAME) + 1) >= sizeof(DEFAULT_GROUPNAME)) {
            qdf_print("source too long\n");
            return -1;
        }
        group->atf_num_clients_borrow = 0;
        group->atf_num_clients = 0;
        group->atf_contributabletokens = 0;
        group->shadow_atf_contributabletokens = 0;
        TAILQ_INSERT_TAIL(&ic->ic_atfgroups, group, group_next);
    }

    /* Fair queue and OBSS scheduling enabled by default.
     * To change default behaviour to strictq, set the variable accordingly */
    ic->ic_atf_sched = 0; /* reset */
    ic->ic_atf_sched &= ~IEEE80211_ATF_SCHED_STRICT; /* disable strict queue */
    ic->ic_atf_sched |= IEEE80211_ATF_SCHED_OBSS; /* enable OBSS */

    OS_INIT_TIMER(ic->ic_osdev, &(ic->atfcfg_timer), ieee80211_atfcfg_timer, (void *) (ic), QDF_TIMER_TYPE_WAKE_APPS);
    OS_INIT_TIMER(ic->ic_osdev, &ic->atf_tokenalloc_timer, wlan_atf_token_allocate_timeout_handler, (void *) ic, QDF_TIMER_TYPE_WAKE_APPS);
#endif
    OS_INIT_TIMER(ic->ic_osdev, &(ic->ic_noise_stats), ieee80211_noise_stats_update, (void *) (ic), QDF_TIMER_TYPE_WAKE_APPS);
    /* Initialization of traffic interval and traffic rate is 1800 and 300 seconds respectively */
    ic->traf_interval = DEFAULT_TRAFFIC_INTERVAL;
    ic->traf_rate = DEFAULT_TRAFFIC_RATE;
    ic->traf_bins = ic->traf_interval/ic->traf_rate;
    if (ic->ic_reg_parm.disable2040Coexist) {
        ic->ic_flags |= IEEE80211_F_COEXT_DISABLE;
    } else {
        ic->ic_flags &= ~IEEE80211_F_COEXT_DISABLE;
    }

    /* setup other modules */

    /* The TSF Timer module is required when P2P or Off-channel support are required */
    ic->ic_tsf_timer = ieee80211_tsf_timer_attach(ic);

    ieee80211_ic_off_channel_support_clear(ic);

    ieee80211_p2p_attach(ic);
    ieee80211_crypto_attach(ic);
    ieee80211_node_attach(ic);
    ieee80211_proto_attach(ic);
    ieee80211_power_attach(ic);
    ieee80211_mlme_attach(ic);
#if ATH_SUPPORT_DFS
    ieee80211_dfs_attach(ic);
#endif /* ATH_SUPPORT_DFS */

    error = ieee80211_scan_table_attach(ic, &(ic->ic_scan_table), ic->ic_osdev);
    if (error) {
        ieee80211_node_detach(ic);
        return error;
    }

    /*
     * By default overwrite probe response with beacon IE in scan entry.
     */
    ieee80211_ic_override_proberesp_ie_set(ic);
    error = ieee80211_scan_attach(&(ic->ic_scanner),
                          ic,
                          ic->ic_osdev,
                          ieee80211_is_connected,
                          ieee80211_is_txq_empty,
                          ieee80211_is_sw_txq_empty);
    if (error) {
        /* detach and free already allocated memory for scan */
        ieee80211_node_detach(ic);
        ieee80211_scan_table_detach(&(ic->ic_scan_table));
        return error;
    }
    error = ieee80211_scan_mempool(ic);

    if (error) {
        /* detach and free already allocated memory for scan */
        ieee80211_node_detach(ic);
        ieee80211_scan_table_detach(&(ic->ic_scan_table));
        ieee80211_scan_detach(&(ic->ic_scanner));
        return error;
    }

    ic->ic_resmgr = ieee80211_resmgr_create(ic, IEEE80211_RESMGR_MODE_SINGLE_CHANNEL);

    error = ieee80211_acs_attach(&(ic->ic_acs),
                          ic,
                          ic->ic_osdev);
    if (error) {
        /* detach and free already allocated memory for scan */
        ieee80211_node_detach(ic);
        ieee80211_scan_table_detach(&(ic->ic_scan_table));
        ieee80211_scan_detach(&(ic->ic_scanner));
        return error;
    }

    ic->ic_notify_tx_bcn_mgr = ieee80211_notify_tx_bcn_attach(ic);
#if UMAC_SUPPORT_VI_DBG
    ieee80211_vi_dbg_attach(ic);
#endif
    ieee80211_quiet_attach(ic);
	ieee80211_admctl_attach(ic);

    /*
     * Perform steps that require multiple objects to be initialized.
     * For example, cross references between objects such as ResMgr and Scanner.
     */
    ieee80211_scan_attach_complete(ic->ic_scanner);
    ieee80211_resmgr_create_complete(ic->ic_resmgr);

#if ATH_BAND_STEERING
    if ( EOK != ieee80211_bsteering_attach(ic)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "band steering attach failed __investigate__");
    }
#endif
    ic->ic_get_ext_chan_info = ieee80211_get_extchaninfo;

#if ACFG_NETLINK_TX
    acfg_attach(ic);
#endif
#if UMAC_SUPPORT_ACFG
    acfg_diag_attach(ic);
#endif

    if(!ic->ic_is_mode_offload(ic)) {
#ifdef QCA_LOWMEM_PLATFORM
        ic->ic_num_clients = IEEE80211_33_AID;
#else
        ic->ic_num_clients = IEEE80211_128_AID;
#endif
    }
    ic->ic_chan_stats_th = IEEE80211_CHAN_STATS_THRESOLD;
    ic->ic_chan_switch_cnt = IEEE80211_RADAR_11HCOUNT;
    ic->ic_wb_subelem = 1;
    ic->ic_sec_offsetie = 1;

    /* initialization complete */
    ic->ic_initialized = 1;

#if ATH_SUPPORT_NR_SYNC
    ic->ic_nr_share_radio_flag = 0xff;
#endif

    return 0;
#undef DEFAULT_TRAFFIC_INTERVAL
#undef DEFAULT_TRAFFIC_RATE
}

void
ieee80211_ifdetach(struct ieee80211com *ic)
{
#if QCA_AIRTIME_FAIRNESS
    struct group_list *tmpgroup = NULL ;
#endif
    if (!ic->ic_initialized) {
        return;
    }

    /* Setting zero to aviod re-arming of ic_inact_timer timer */
    ic->ic_initialized = 0;

    /*
     * Preparation for detaching objects.
     * For example, remove and cross references between objects such as those
     * between ResMgr and Scanner.
     */
    ieee80211_scan_detach_prepare(ic->ic_scanner);
    ieee80211_resmgr_delete_prepare(ic->ic_resmgr);

    OS_FREE_TIMER(&ic->ic_inact_timer);
#if UMAC_SUPPORT_WNM
    OS_FREE_TIMER(&ic->ic_bssload_timer);
#endif
#if ATH_SUPPORT_EXT_STAT
    /* Free the timer when radio dettached */
    OS_FREE_TIMER (&ic->ic_client_stat_timer);
#endif

     OS_FREE_TIMER(&ic->ic_noise_stats);
    /* all the vaps should have been deleted now */
    ASSERT(TAILQ_FIRST(&ic->ic_vaps) == NULL);

    ieee80211_scan_table_detach(&(ic->ic_scan_table));
    ieee80211_node_detach(ic);
    ieee80211_quiet_detach(ic);
	ieee80211_admctl_detach(ic);

    qdf_mempool_destroy(ic->ic_qdf_dev, ic->mempool_net80211_scan_entry);
#if ATH_SUPPORT_DFS
    ieee80211_dfs_detach(ic);
#endif /* ATH_SUPPORT_DFS */
    ieee80211_proto_detach(ic);
    ieee80211_crypto_detach(ic);
    ieee80211_power_detach(ic);
    ieee80211_mlme_detach(ic);
    ieee80211_notify_tx_bcn_detach(ic->ic_notify_tx_bcn_mgr);
    ieee80211_resmgr_delete(ic->ic_resmgr);
    ieee80211_scan_detach(&(ic->ic_scanner));
    ieee80211_p2p_detach(ic);
    ieee80211_acs_detach(&(ic->ic_acs));
#if UMAC_SUPPORT_VI_DBG
    ieee80211_vi_dbg_detach(ic);
#endif

#if ATH_BAND_STEERING
    if( EOK != ieee80211_bsteering_detach(ic)){
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "band steering detach failed __investigate __");
    }
#endif
#if UMAC_SUPPORT_ACFG
    acfg_diag_detach(ic);
#endif

#if ACFG_NETLINK_TX
    acfg_detach(ic);
#endif
    /* Detach TSF timer at the end to avoid assertion */
    if (ic->ic_tsf_timer) {
        ieee80211_tsf_timer_detach(ic->ic_tsf_timer);
        ic->ic_tsf_timer = NULL;
    }
#if QCA_AIRTIME_FAIRNESS
    spin_lock(&ic->atf_lock);
    if (ic->atf_tasksched) {
        ic->atf_tasksched = 0;
    }
    spin_unlock(&ic->atf_lock);
    while (!TAILQ_EMPTY(&ic->ic_atfgroups)) {
        tmpgroup = TAILQ_FIRST(&ic->ic_atfgroups);
        TAILQ_REMOVE(&ic->ic_atfgroups,tmpgroup,group_next);
        OS_FREE(tmpgroup);
        tmpgroup = NULL;
    }

    OS_FREE_TIMER(&ic->atfcfg_timer);

    OS_FREE_TIMER(&ic->atf_tokenalloc_timer);
    spin_lock_destroy(&ic->atf_lock);

    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"%s: ATF terminated\n", __func__);
#endif
    spin_lock_destroy(&ic->ic_lock);
    spin_lock_destroy(&ic->ic_main_sta_lock);
    spin_lock_destroy(&ic->ic_addba_lock);
    IEEE80211_STATE_LOCK_DESTROY(ic);
    spin_lock_destroy(&ic->ic_beacon_alloc_lock);
}

/*
 * Start this IC
 */
void ieee80211_start_running(struct ieee80211com *ic)
{
    OS_SET_TIMER(&ic->ic_inact_timer, IEEE80211_INACT_WAIT*1000);
}

/*
 * Stop this IC
 */
void ieee80211_stop_running(struct ieee80211com *ic)
{
    OS_CANCEL_TIMER(&ic->ic_inact_timer);
}

int ieee80211com_register_event_handlers(struct ieee80211com *ic,
                                     void *event_arg,
                                     wlan_dev_event_handler_table *evtable)
{
    int i;
    /* unregister if there exists one already */
    ieee80211com_unregister_event_handlers(ic,event_arg,evtable);
    IEEE80211_COMM_LOCK(ic);
    for (i=0;i<IEEE80211_MAX_DEVICE_EVENT_HANDLERS; ++i) {
        if ( ic->ic_evtable[i] == NULL) {
            ic->ic_evtable[i] = evtable;
            ic->ic_event_arg[i] = event_arg;
            IEEE80211_COMM_UNLOCK(ic);
            return 0;
        }
    }
    IEEE80211_COMM_UNLOCK(ic);
    return -ENOMEM;


}

int ieee80211com_unregister_event_handlers(struct ieee80211com *ic,
                                     void *event_arg,
                                     wlan_dev_event_handler_table *evtable)
{
    int i;
    IEEE80211_COMM_LOCK(ic);
    for (i=0;i<IEEE80211_MAX_DEVICE_EVENT_HANDLERS; ++i) {
        if ( ic->ic_evtable[i] == evtable &&  ic->ic_event_arg[i] == event_arg) {
            ic->ic_evtable[i] = NULL;
            ic->ic_event_arg[i] = NULL;
            IEEE80211_COMM_UNLOCK(ic);
            return 0;
        }
    }
    IEEE80211_COMM_UNLOCK(ic);
    return -EEXIST;
}

/* Clear user defined ADDBA response codes for all nodes. */
static void
ieee80211_addba_clearresponse(void *arg, struct ieee80211_node *ni)
{
    struct ieee80211com *ic = (struct ieee80211com *) arg;
    ic->ic_addba_clearresponse(ni);
}

int wlan_device_register_event_handlers(wlan_dev_t devhandle,
                                     void *event_arg,
                                     wlan_dev_event_handler_table *evtable)
{

    return ieee80211com_register_event_handlers(devhandle,event_arg,evtable);
}


int wlan_device_unregister_event_handlers(wlan_dev_t devhandle,
                                     void *event_arg,
                                     wlan_dev_event_handler_table *evtable)
{
    return ieee80211com_unregister_event_handlers(devhandle,event_arg,evtable);
}


int wlan_set_device_param(wlan_dev_t ic, ieee80211_device_param param, u_int32_t val)
{
    int retval=EOK;
    switch(param) {
    case IEEE80211_DEVICE_TX_CHAIN_MASK:
    case IEEE80211_DEVICE_TX_CHAIN_MASK_LEGACY:
	if(ic->ic_set_chain_mask(ic,param,val) == 0) {
            ic->ic_tx_chainmask = val;
        } else {
            retval=EINVAL;
        }
        break;
    case IEEE80211_DEVICE_RX_CHAIN_MASK:
    case IEEE80211_DEVICE_RX_CHAIN_MASK_LEGACY:
	if(ic->ic_set_chain_mask(ic,param,val) == 0) {
            ic->ic_rx_chainmask = val;
        } else {
            retval=EINVAL;
        }
        break;

    case IEEE80211_DEVICE_PROTECTION_MODE:
        if (val > IEEE80211_PROT_RTSCTS) {
	    retval=EINVAL;
        } else {
	   ic->ic_protmode = val;
        }
        break;
    case IEEE80211_DEVICE_NUM_TX_CHAIN:
    case IEEE80211_DEVICE_NUM_RX_CHAIN:
    case IEEE80211_DEVICE_COUNTRYCODE:
       /* read only */
	retval=EINVAL;
        break;
    case IEEE80211_DEVICE_BMISS_LIMIT:
    	ic->ic_bmisstimeout = val * ic->ic_intval;
        break;
    case IEEE80211_DEVICE_BLKDFSCHAN:
        if (val == 0) {
            ieee80211_ic_block_dfschan_clear(ic);
        } else {
            ieee80211_ic_block_dfschan_set(ic);
        }
        break;
    case IEEE80211_DEVICE_GREEN_AP_PS_ENABLE:
        ic->ic_green_ap_set_enable(ic, val);
        break;
    case IEEE80211_DEVICE_GREEN_AP_PS_TIMEOUT:
        ic->ic_green_ap_set_transition_time(ic, val);
        break;
    case IEEE80211_DEVICE_GREEN_AP_PS_ON_TIME:
        ic->ic_green_ap_set_on_time(ic, val);
        break;
    case IEEE80211_DEVICE_GREEN_AP_ENABLE_PRINT:
        ic->ic_green_ap_set_print_level(ic, val);
        break;
    case IEEE80211_DEVICE_CWM_EXTPROTMODE:
        if (val < IEEE80211_CWM_EXTPROTMAX) {
            ic->ic_cwm_set_extprotmode(ic, val);
        } else {
            retval = EINVAL;
        }
        break;
    case IEEE80211_DEVICE_CWM_EXTPROTSPACING:
        if (val < IEEE80211_CWM_EXTPROTSPACINGMAX) {
            ic->ic_cwm_set_extprotspacing(ic, val);
        } else {
            retval = EINVAL;
        }
        break;
    case IEEE80211_DEVICE_CWM_ENABLE:
        ic->ic_cwm_set_enable(ic, val);
        break;
    case IEEE80211_DEVICE_CWM_EXTBUSYTHRESHOLD:
        ic->ic_cwm_set_extbusythreshold(ic, val);
        break;
    case IEEE80211_DEVICE_DOTH:
        if (val == 0) {
            ieee80211_ic_doth_clear(ic);
        } else {
            ieee80211_ic_doth_set(ic);
        }
        break;
    case IEEE80211_DEVICE_ADDBA_MODE:
        ic->ic_addba_mode = val;
        /*
        * Clear any user defined ADDBA response codes before switching modes.
        */
        ieee80211_iterate_node(ic, ieee80211_addba_clearresponse, ic);
        break;
    case IEEE80211_DEVICE_MULTI_CHANNEL:
        if (!val) {
            /* Disable Multi-Channel */
            retval = ieee80211_resmgr_setmode(ic->ic_resmgr, IEEE80211_RESMGR_MODE_SINGLE_CHANNEL);
        }
        else if (ic->ic_caps_ext & IEEE80211_CEXT_MULTICHAN) {
            retval = ieee80211_resmgr_setmode(ic->ic_resmgr, IEEE80211_RESMGR_MODE_MULTI_CHANNEL);
        }
        else {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Unable to enable Multi-Channel Scheduling since device/driver don't support it.\n", __func__);
            retval = EINVAL;
        }
        break;
    case IEEE80211_DEVICE_MAX_AMSDU_SIZE:
        ic->ic_amsdu_max_size = val;
        break;
#if ATH_SUPPORT_IBSS_HT
    case IEEE80211_DEVICE_HT20ADHOC:
        if (val == 0) {
            ieee80211_ic_ht20Adhoc_clear(ic);
        } else {
            ieee80211_ic_ht20Adhoc_set(ic);
        }
        break;
    case IEEE80211_DEVICE_HT40ADHOC:
        if (val == 0) {
            ieee80211_ic_ht40Adhoc_clear(ic);
        } else {
            ieee80211_ic_ht40Adhoc_set(ic);
        }
        break;
    case IEEE80211_DEVICE_HTADHOCAGGR:
        if (val == 0) {
            ieee80211_ic_htAdhocAggr_clear(ic);
        } else {
            ieee80211_ic_htAdhocAggr_set(ic);
        }
        break;
#endif /* end of #if ATH_SUPPORT_IBSS_HT */
    case IEEE80211_DEVICE_PWRTARGET:
        ieee80211com_set_curchanmaxpwr(ic, val);
        break;
    case IEEE80211_DEVICE_P2P:
        if (val == 0) {
            ieee80211_ic_p2pDevEnable_clear(ic);
        }
        else if (ic->ic_caps_ext & IEEE80211_CEXT_P2P) {
            ieee80211_ic_p2pDevEnable_set(ic);
        }
        else {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Unable to enable P2P since device/driver don't support it.\n", __func__);
            retval = EINVAL;
        }
        break;

    case IEEE80211_DEVICE_OVERRIDE_SCAN_PROBERESPONSE_IE:
      if (val) {
          ieee80211_ic_override_proberesp_ie_set(ic);
      } else {
          ieee80211_ic_override_proberesp_ie_clear(ic);
      }
      break;
    case IEEE80211_DEVICE_2G_CSA:
        if (val == 0) {
            ieee80211_ic_2g_csa_clear(ic);
        } else {
            ieee80211_ic_2g_csa_set(ic);
        }
        break;

    default:
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Error: invalid param=%d.\n", __func__, param);
    }
    return retval;

}

u_int32_t wlan_get_device_param(wlan_dev_t ic, ieee80211_device_param param)
{

    switch(param) {
    case IEEE80211_DEVICE_NUM_TX_CHAIN:
        return (ic->ic_num_tx_chain);
        break;
    case IEEE80211_DEVICE_NUM_RX_CHAIN:
        return (ic->ic_num_rx_chain);
        break;
    case IEEE80211_DEVICE_TX_CHAIN_MASK:
        return (ic->ic_tx_chainmask);
        break;
    case IEEE80211_DEVICE_RX_CHAIN_MASK:
        return (ic->ic_rx_chainmask);
        break;
    case IEEE80211_DEVICE_PROTECTION_MODE:
	return (ic->ic_protmode );
        break;
    case IEEE80211_DEVICE_BMISS_LIMIT:
    	return (ic->ic_bmisstimeout / ic->ic_intval);
        break;
    case IEEE80211_DEVICE_BLKDFSCHAN:
        return (ieee80211_ic_block_dfschan_is_set(ic));
        break;
    case IEEE80211_DEVICE_GREEN_AP_PS_ENABLE:
        return ic->ic_green_ap_get_enable(ic);
        break;
    case IEEE80211_DEVICE_GREEN_AP_PS_TIMEOUT:
        return ic->ic_green_ap_get_transition_time(ic);
        break;
    case IEEE80211_DEVICE_GREEN_AP_PS_ON_TIME:
        return ic->ic_green_ap_get_on_time(ic);
        break;
    case IEEE80211_DEVICE_GREEN_AP_ENABLE_PRINT:
        return ic->ic_green_ap_get_print_level(ic);
        break;
    case IEEE80211_DEVICE_CWM_EXTPROTMODE:
        return ic->ic_cwm_get_extprotmode(ic);
        break;
    case IEEE80211_DEVICE_CWM_EXTPROTSPACING:
        return ic->ic_cwm_get_extprotspacing(ic);
        break;
    case IEEE80211_DEVICE_CWM_ENABLE:
        return ic->ic_cwm_get_enable(ic);
        break;
    case IEEE80211_DEVICE_CWM_EXTBUSYTHRESHOLD:
        return ic->ic_cwm_get_extbusythreshold(ic);
        break;
    case IEEE80211_DEVICE_DOTH:
        return (ieee80211_ic_doth_is_set(ic));
        break;
    case IEEE80211_DEVICE_ADDBA_MODE:
        return ic->ic_addba_mode;
        break;
    case IEEE80211_DEVICE_COUNTRYCODE:
        ic->ic_get_currentCountry(ic, &ic->ic_country);
        return ic->ic_country.countryCode;
        break;
    case IEEE80211_DEVICE_MULTI_CHANNEL:
        return (ieee80211_resmgr_getmode(ic->ic_resmgr)
                == IEEE80211_RESMGR_MODE_MULTI_CHANNEL);
        break;
    case IEEE80211_DEVICE_MAX_AMSDU_SIZE:
        return(ic->ic_amsdu_max_size);
        break;
#if ATH_SUPPORT_IBSS_HT
    case IEEE80211_DEVICE_HT20ADHOC:
        return (ieee80211_ic_ht20Adhoc_is_set(ic));
        break;
    case IEEE80211_DEVICE_HT40ADHOC:
        return (ieee80211_ic_ht40Adhoc_is_set(ic));
        break;
    case IEEE80211_DEVICE_HTADHOCAGGR:
        return (ieee80211_ic_htAdhocAggr_is_set(ic));
        break;
#endif /* end of #if ATH_SUPPORT_IBSS_HT */
    case IEEE80211_DEVICE_PWRTARGET:
        return (ieee80211com_get_curchanmaxpwr(ic));
        break;
    case IEEE80211_DEVICE_P2P:
        return (ieee80211_ic_p2pDevEnable_is_set(ic));
        break;
    case IEEE80211_DEVICE_OVERRIDE_SCAN_PROBERESPONSE_IE:
        return  ieee80211_ic_override_proberesp_ie_is_set(ic);
        break;
    case IEEE80211_DEVICE_2G_CSA:
        return (ieee80211_ic_2g_csa_is_set(ic));
        break;
    default:
        return 0;
    }
}

int wlan_get_device_mac_addr(wlan_dev_t ic, u_int8_t *mac_addr)
{
   IEEE80211_ADDR_COPY(mac_addr, ic->ic_myaddr);
   return EOK;
}

struct ieee80211_stats *
wlan_get_stats(wlan_if_t vaphandle)
{
    struct ieee80211vap *vap = vaphandle;
    return &vap->iv_stats;
}

void wlan_device_note(struct ieee80211com *ic, const char *fmt, ...)
{
     char                   tmp_buf[OS_TEMP_BUF_SIZE];
     va_list                ap;
     va_start(ap, fmt);
     vsnprintf (tmp_buf,OS_TEMP_BUF_SIZE, fmt, ap);
     va_end(ap);
     QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s",tmp_buf);
     ic->ic_log_text(ic,tmp_buf);
}

void wlan_get_vap_opmode_count(wlan_dev_t ic,
                               struct ieee80211_vap_opmode_count *vap_opmode_count)
{
    ieee80211_get_vap_opmode_count(ic, vap_opmode_count);
}

static void ieee80211_vap_iter_active_vaps(void *arg, struct ieee80211vap *vap)
{
    u_int16_t *pnactive = (u_int16_t *)arg;
       /* active vap check is used for assigning/updating vap channel with ic_curchan
	 so, it considers active vaps, and Vaps which are in CAC period */
    if ((ieee80211_vap_active_is_set(vap))|| (ieee80211_vap_dfswait_is_set(vap)))
        ++(*pnactive);

}

static void ieee80211_vap_iter_vaps_up(void *arg, struct ieee80211vap *vap)
{
    u_int8_t *pnvaps_up = (u_int8_t *)arg;
    /* active vap check is used for assigning/updating vap channel with ic_curchan
       so, it considers active vaps, and Vaps which are in CAC period */
    if (ieee80211_vap_active_is_set(vap) || (ieee80211_vap_dfswait_is_set(vap))) {
        if (vap->iv_opmode == IEEE80211_M_STA){
            if((vap->iv_state_info.iv_state >= IEEE80211_S_JOIN) && (vap->iv_state_info.iv_state <= IEEE80211_S_RUN)) {
                ++(*pnvaps_up);
            }
        } else {
            ++(*pnvaps_up);
        }
    }
}

/*
 * returns number of vaps active.
 */
u_int16_t
ieee80211_vaps_active(struct ieee80211com *ic)
{
    u_int16_t nactive=0;
    wlan_iterate_vap_list(ic,ieee80211_vap_iter_active_vaps,(void *) &nactive);
    return nactive;
}

/*
 * returns number of vaps active and up.
 */
u_int8_t
ieee80211_get_num_vaps_up(struct ieee80211com *ic)
{
    u_int8_t nvaps_up=0;
    wlan_iterate_vap_list(ic,ieee80211_vap_iter_vaps_up,(void *) &nvaps_up);
    return nvaps_up;
}

static void
ieee80211_iter_vap_opmode(void *arg, struct ieee80211vap *vaphandle)
{
    struct ieee80211_vap_opmode_count    *vap_opmode_count = arg;
    enum ieee80211_opmode                opmode = ieee80211vap_get_opmode(vaphandle);

    vap_opmode_count->total_vaps++;

    switch (opmode) {
    case IEEE80211_M_IBSS:
        vap_opmode_count->ibss_count++;
        break;

    case IEEE80211_M_STA:
        vap_opmode_count->sta_count++;
        break;

    case IEEE80211_M_WDS:
        vap_opmode_count->wds_count++;
        break;

    case IEEE80211_M_AHDEMO:
        vap_opmode_count->ahdemo_count++;
        break;

    case IEEE80211_M_HOSTAP:
        vap_opmode_count->ap_count++;
        break;

    case IEEE80211_M_MONITOR:
        vap_opmode_count->monitor_count++;
        break;

    case IEEE80211_M_BTAMP:
        vap_opmode_count->btamp_count++;
        break;

    default:
        vap_opmode_count->unknown_count++;

        QDF_PRINT_INFO(vaphandle->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s vap=%p unknown opmode=%d\n",
            __func__, vaphandle, opmode);
        break;
    }
}

void
ieee80211_get_vap_opmode_count(struct ieee80211com *ic,
                               struct ieee80211_vap_opmode_count *vap_opmode_count)
{
    wlan_iterate_vap_list(ic, ieee80211_iter_vap_opmode, (void *) vap_opmode_count);
}

static void
ieee80211_vap_iter_last_traffic_timestamp(void *arg, struct ieee80211vap *vap)
{
    systime_t    *p_last_traffic_timestamp = arg;
    systime_t    current_traffic_timestamp = ieee80211_get_traffic_indication_timestamp(vap);

    if (current_traffic_timestamp > *p_last_traffic_timestamp) {
        *p_last_traffic_timestamp = current_traffic_timestamp;
    }
}

systime_t
ieee80211com_get_traffic_indication_timestamp(struct ieee80211com *ic)
{
    systime_t    traffic_timestamp = 0;

    wlan_iterate_vap_list(ic, ieee80211_vap_iter_last_traffic_timestamp,(void *) &traffic_timestamp);

    return traffic_timestamp;
}

struct ieee80211_iter_vaps_ready_arg {
    u_int8_t num_sta_vaps_ready;
    u_int8_t num_ibss_vaps_ready;
    u_int8_t num_ap_vaps_ready;
};

static void ieee80211_vap_iter_ready_vaps(void *arg, wlan_if_t vap)
{
    struct ieee80211_iter_vaps_ready_arg *params = (struct ieee80211_iter_vaps_ready_arg *) arg;
    if (ieee80211_vap_ready_is_set(vap)) {
        switch(ieee80211vap_get_opmode(vap)) {
        case IEEE80211_M_HOSTAP:
        case IEEE80211_M_BTAMP:
            params->num_ap_vaps_ready++;
            break;

        case IEEE80211_M_IBSS:
            params->num_ibss_vaps_ready++;
            break;

        case IEEE80211_M_STA:
            params->num_sta_vaps_ready++;
            break;

        default:
            break;

        }
    }
}

/*
 * returns number of vaps ready.
 */
u_int16_t
ieee80211_vaps_ready(struct ieee80211com *ic, enum ieee80211_opmode opmode)
{
    struct ieee80211_iter_vaps_ready_arg params;
    u_int16_t nready = 0;
    OS_MEMZERO(&params, sizeof(params));
    wlan_iterate_vap_list(ic,ieee80211_vap_iter_ready_vaps,(void *) &params);
    switch(opmode) {
        case IEEE80211_M_HOSTAP:
        case IEEE80211_M_BTAMP:
            nready = params.num_ap_vaps_ready;
            break;

        case IEEE80211_M_IBSS:
            nready = params.num_ibss_vaps_ready;
            break;

        case IEEE80211_M_STA:
            nready = params.num_sta_vaps_ready;
            break;

        default:
            break;
    }
    return nready;
}

#if ATH_SUPPORT_FIPS
int wlan_set_fips(wlan_if_t vap, void *args)
{

    struct ath_fips_cmd *fips_buf = (struct ath_fips_cmd *)args;
    struct ieee80211com *ic = vap->iv_ic;
    int retval = -1;

    u_int8_t default_key[] =  { 0x2b, 0x7e, 0x15, 0x16,
                                0x28, 0xae, 0xd2, 0xa6,
                                0xab, 0xf7, 0x15, 0x88,
                                0x09, 0xcf, 0x4f, 0x3c
                              };
    u_int8_t default_data[] = { 0xf0, 0xf1, 0xf2, 0xf3,
            0xf4, 0xf5, 0xf6, 0xf7,
            0xf8, 0xf9, 0xfa, 0xfb,
            0xfc, 0xfd, 0xfe, 0xff
    };
    u_int8_t default_iv[] =   { 0xf0, 0xf1, 0xf2, 0xf3,
            0xf4, 0xf5, 0xf6, 0xf7,
            0xf8, 0xf9, 0xfa, 0xfb,
            0xfc, 0xfd, 0xfe, 0xff
    };

    if (!ic || !ic->ic_fips_test) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n %s:%d fips_test function not supported", __func__, __LINE__);
        return -EINVAL;
    }
    if(fips_buf != NULL) {

        if (fips_buf->key == NULL) {
            fips_buf->key_len = sizeof(default_key);
            memcpy(fips_buf->key, default_key, sizeof(default_key));
        }

        if (fips_buf->data == NULL) {
            fips_buf->data_len = sizeof(default_data);
            memcpy(fips_buf->data, default_data, sizeof(default_data));
        }

        if (fips_buf->iv == NULL) {
            memcpy(fips_buf->iv, default_iv, sizeof(default_iv));
        }
        retval = ic->ic_fips_test(ic, fips_buf);
    }
    return retval;
}
#endif

#if ATH_DEBUG

#define OFFCHAN_EXT_TID_NONPAUSE    19
#define OFFCHAN_EXT_TID_INVALID    31
/* TODO: only support linux for now */
void wlan_offchan_send_data_frame(struct ieee80211_node *ni, struct net_device *netdev)
{
#if defined(LINUX) || defined(__linux__)
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf;
    struct ieee80211_qosframe *qwh;
    /*Setting both source and destination MAC addresses to random addresses*/
    const u_int8_t src[6] = {0x00, 0x02, 0x03, 0x06, 0x02, 0x01};
    const u_int8_t dst[6] = {0x00, 0x02, 0x03, 0x04, 0x05, 0x06};
    struct sk_buff *skb;

    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_DATA, 1000);
    if (wbuf == NULL)
    {
        return ;
    }
    ieee80211_prepare_qosnulldata(ni, wbuf, WME_AC_VO);

    qwh = (struct ieee80211_qosframe *)wbuf_header(wbuf);
    ieee80211_send_setup(vap, ni, (struct ieee80211_frame *)qwh,
        IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_QOS,
        src, /* SA */
        dst,            /* DA */
        ni->ni_bssid);

    wbuf_set_pktlen(wbuf, 1000);
    /* force with NONPAUSE_TID */
    wbuf_set_tid(wbuf, OFFCHAN_EXT_TID_NONPAUSE);
    if (IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan)) {
	    wbuf_set_tx_rate(wbuf, 0, RATECODE_PREAM_OFDM, 3);
    } else {
	    wbuf_set_tx_rate(wbuf, 0, RATECODE_PREAM_CCK, 3);
    }
    /* Set tx ctrl params */
    wbuf_set_tx_ctrl(wbuf, 0, 63, -1);
    skb = (struct sk_buff *)wbuf;
    skb->dev = netdev;

    /* Since data queues are paused during offchan, use mgmt queue to transmit
     * frame immediately */
    ieee80211_send_mgmt(vap,ni, wbuf,true);
#endif
}

static
void wlan_offchan_tx_scan_event_handler(struct ieee80211vap *orig_vap,
                                ieee80211_scan_event *event, void *arg)
{
    struct ieee80211vap *vap = (struct ieee80211vap *)orig_vap;
    struct ieee80211_node *ni;
    int rc;

    switch(event->type) {
    case IEEE80211_SCAN_FOREIGN_CHANNEL:
        /*
         * Send out a frame during offchan
         * NONPAUSED_TID exists in offload case, no need to create a tmp node
         */
        ni = ieee80211_ref_node(vap->iv_bss);
        if (ni) {
            ieee80211_send_qosnulldata(ni, WME_AC_VI, 0);

            wlan_offchan_send_data_frame(ni, arg);
            ieee80211_free_node(ni);
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "sent mgmt & data frames during offchan\n");
        }

        break;
    case IEEE80211_SCAN_COMPLETED:
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "scan complete event\n");
        rc = wlan_scan_unregister_event_handler(vap, &wlan_offchan_tx_scan_event_handler,(void *)arg);
        ieee80211_ic_offchanscan_clear(vap->iv_ic);
        if (rc != EOK) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
                          "%s: wlan_scan_unregister_event_handler() failed handler=%08p,%08p rc=%08X\n",
                          __func__, &wlan_offchan_tx_scan_event_handler, vap, rc);
        }
        break;
    default:
        break;
    }
}


static
int wlan_offchan_tx_test_offload(wlan_if_t vaphandle, void *netdev, u_int32_t chan,
                                u_int16_t dwell_time, u_int16_t scan_requestor, u_int32_t *scan_id)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    IEEE80211_SCAN_PRIORITY scan_priority;
    ieee80211_scan_params *scan_params;
    enum ieee80211_opmode opmode = wlan_vap_get_opmode(vap);
    int rc;

    scan_params = (ieee80211_scan_params *)
                OS_MALLOC(ic->ic_osdev,  sizeof(*scan_params), GFP_KERNEL);
    if (scan_params == NULL)
        return -ENOMEM;
    OS_MEMZERO(scan_params,sizeof(ieee80211_scan_params));

    wlan_set_default_scan_parameters(vap,scan_params,opmode,true,true,true,true,0,NULL,0);

    scan_params->flags = IEEE80211_SCAN_PASSIVE | IEEE80211_SCAN_ALLBANDS;
    /* allow off channel TX on both data and mgmt */
    scan_params->flags |= IEEE80211_SCAN_OFFCHAN_MGMT_TX | IEEE80211_SCAN_OFFCHAN_DATA_TX;
    scan_params->type = IEEE80211_SCAN_FOREGROUND;
    scan_params->min_dwell_time_passive = dwell_time;
    scan_params->max_dwell_time_passive = dwell_time;

    /* Configuring these values based on FW recommendation */
    scan_priority = IEEE80211_SCAN_PRIORITY_MEDIUM;
    scan_params->max_rest_time = 100;
    scan_params->min_rest_time = 25;

    /* channel to scan */
    scan_params->num_channels = 1;
    scan_params->chan_list = &chan;

    rc = wlan_scan_register_event_handler(vap, &wlan_offchan_tx_scan_event_handler,(void *)netdev);
    if (rc != EOK) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
                          "%s: wlan_scan_register_event_handler() failed handler=%08p,%08p rc=%08X\n",
                          __func__, &wlan_offchan_tx_scan_event_handler, vap, rc);
        OS_FREE(scan_params);
        return -1;
    }

    if (wlan_scan_start(vap, scan_params, scan_requestor, scan_priority, scan_id) != 0 ) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
            "%s: Issue a scan fail.\n",
            __func__);
        OS_FREE(scan_params);
        wlan_scan_unregister_event_handler(vap, &wlan_offchan_tx_scan_event_handler,(void *)netdev);
        return -1;
    }

    vap->offchan_requestor = scan_requestor;
    ieee80211_ic_offchanscan_set(ic);
    OS_FREE(scan_params);

    return 0;
}

int wlan_offchan_tx_test(wlan_if_t vaphandle, void *netdev, u_int32_t chan,
                        u_int16_t dwell_time, u_int16_t scan_requestor, u_int32_t *scan_id)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_channel *channel;
    struct ieee80211_node *ni;
    const u_int8_t dst[6] = {0x00, 0x02, 0x03, 0x04, 0x05, 0x06};
    int error;
    u_int32_t tsf1, tsf2;
    bool is_mode_offload = ic->ic_is_mode_offload(vap->iv_ic);
    /* check channel is supported */
    channel = ieee80211_find_dot11_channel(ic, chan, vap->iv_des_cfreq2, vap->iv_des_mode | ic->ic_chanbwflag);
    if (channel == NULL) {
        channel = ieee80211_find_dot11_channel(ic, chan, 0, IEEE80211_MODE_AUTO);

        if (channel == NULL) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Invalid Channel\n");
            return -EINVAL;
        }
    }

    if(IEEE80211_IS_CHAN_RADAR(channel))
    {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Radar detected on channel %d.So, no Tx is allowed till the nol expiry\n",channel->ic_ieee);
        return -EINVAL;
    }

    if(!((dwell_time > 0) && (dwell_time < ieee80211_vap_get_beacon_interval(vap)))) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Dwell time is more than Beacon interval, Offchan scan duration is"
                 " not allowed more than Beacon interval \n");
        return -EINVAL;
    }
    if (is_mode_offload)
        return wlan_offchan_tx_test_offload(vap, netdev, chan, dwell_time, scan_requestor, scan_id);

    channel = ieee80211_find_dot11_channel(ic, chan, vap->iv_des_cfreq2, vap->iv_des_mode | ic->ic_chanbwflag);
    if (channel == NULL) {
        channel = ieee80211_find_dot11_channel(ic, chan, 0, IEEE80211_MODE_AUTO);
        if (channel == NULL) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: channel %u not found \n", __func__, chan);
            return -EINVAL;
        }
    }


    if (!ic->ic_vap_pause_control) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "vap_pause_control not supported\n");
        return -EINVAL;
    }
    local_bh_disable();
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ic_vap_pause_control\n");
    /*
     * It performs the following operations:
     * It first pauses all nodes associated with the specified vap, including the iv_bss node.
     * This essentially pauses the UAPSD queue and all TID queues for each node.
     * However, the per vap mcastq is not paused. Any frames in vap's mcastq will be
     * transmitted immediately after its beacon transmission. If there is no beacon
     * transmission, frame holds there in vap's mcastq.
     * It then requeues frames related to the specified vap back to per node
     * TID queue (for unicast), per node UAPSD queue, or per vap mcastq (for multicast).
     */
    ic->ic_vap_pause_control(ic, vap, true);
    local_bh_enable();
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ic_scan_start\n");
    /* Beacon will not be sent out after scan_start */
    ic->ic_scan_start(ic);

    ic->ic_curchan = channel;
    tsf1 = ieee80211_get_tsf32(ic);
    error = ic->ic_set_channel(ic);
    tsf2 = ieee80211_get_tsf32(ic);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_EMERG "%u - %u = delta = %u\n", tsf2, tsf1, tsf2-tsf1);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "error = %d, channel now is %d\n", error, ic->ic_curchan->ic_freq);

    /*
     * For testing purposes, a tmp node is alloc in UMAC not paused now.
     * Can also be done via alloc a global tmp node for off chan transmission.
     * In such a case, tmp node should not be paused when ic_vap_pause_control
     * is called
     */
    ni = ieee80211_tmp_node(vap, dst);
    if (ni) {
        /* unicast frame will be sent out since the tmp node is not paused */
        ieee80211_send_qosnulldata_offchan_tx_test(ni, WME_AC_BE, 0);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "send a mgmt frame during offchan\n");
        /*
         * mcast frame can also use this ni for transmission. In scanning mode,
         * the mcast frame goes to normal TID of the tmp node, instead of
         * going to per vap mcastq.
         */
    }

    /* during off channel */
    mdelay(dwell_time);

    if (ni)
        ieee80211_free_node(ni);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ic_scan_end\n");
    ic->ic_scan_end(ic);
    if (ic->ic_curchan != vap->iv_bsschan)
        ic->ic_curchan = vap->iv_bsschan;
    error = ic->ic_set_channel(ic);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "error = %d, channel now is %d\n", error, ic->ic_curchan->ic_freq);

    local_bh_disable();
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ic_vap_unpause_control\n");
    ic->ic_vap_pause_control(ic, vap, false);
    local_bh_enable();

    return EOK;
}
#endif  /* ATH_DEBUG */


int
module_init_wlan(void)
{
    return 0;
}

void
module_exit_wlan(void)
{
}
