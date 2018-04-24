/*
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 */
#if QCA_AIRTIME_FAIRNESS
#ifndef _UMAC_AIRTIME_FAIRNESS_PRIV__
#define _UMAC_AIRTIME_FAIRNESS_PRIV__

#define ATF_TOKEN_INTVL_MS      200 /* 200 msec */
#define WMI_ATF_DENOMINATION    1000
#define ATF_CFG_GLOBAL_INDEX    0

#define DEFAULT_GROUPNAME   "QC-DeFaUlT-AtFgRoUp\0"/* SSID group name created & maintained in the driver by default */
#define ATF_DATA_LOG_SIZE                       3  /* Minimum Data log (history) required for ATF Fairqueuing algo */
#define ATF_UNUSEDTOKENS_CONTRIBUTE_THRESHOLD   45 /* Any node with ununsed token percent (avg) greater than this value can contribute */
#define ATF_RESERVERD_TOKEN_PERCENT             2  /* Minimum token (percent) reserved for a node even when it is idle */
#define ATF_RESERVED_UNALLOTED_TOKEN_PERCENT    10 /* Minimum unalloted token (percent) reserved */

struct ieee80211com;
struct ieee80211vap;

int32_t ieee80211_atf_set(struct ieee80211vap *vap, u_int8_t enable);
int32_t ieee80211_atf_clear(struct ieee80211vap *vap, u_int8_t enable);
int ieee80211_atf_used_all_tokens(struct ieee80211com *ic, struct ieee80211_node *ni);
int ieee80211_atf_get_debug_dump(struct ieee80211_node *ni,
                                 void **buf, u_int32_t *buf_sz, u_int32_t *id);
int ieee80211_atf_set_debug_size(struct ieee80211_node *ni, int size);

void ieee80211_node_iter_dist_txtokens_strictq(void *arg, struct ieee80211_node *ni);
void ieee80211_node_iter_dist_txtokens_fairq(void *arg, struct ieee80211_node *ni);
void ieee80211_node_iter_dist_txtokens_fairq_noborrow(void *arg, struct ieee80211_node *ni);
void ieee80211_node_iter_fairq_algo(void *arg, struct ieee80211_node *ni);
uint32_t ieee80211_atf_compute_unalloted_txtokens(struct ieee80211com *ic);
int update_atf_nodetable(struct ieee80211com *ic);
u_int32_t ieee80211_atf_compute_txtokens(struct ieee80211com *ic, u_int32_t atf_units, u_int32_t token_interval_ms);
u_int32_t ieee80211_atf_airtime_unassigned(struct ieee80211com *ic);
void ieee80211_atf_distribute_airtime(struct ieee80211com *ic);
int ieee80211_atf_get_debug_nodestate(struct ieee80211com *ic, struct ieee80211_node *ni, u_int32_t *nodestate);
#endif
#endif
