/*
 *  Copyright (c) 2008 Atheros Communications Inc. 
 * All Rights Reserved.
 * 
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */

#ifndef _IEEE80211_TARGET_H_
#define _IEEE80211_TARGET_H_

#ifdef ATH_SUPPORT_HTC
void ieee80211_add_vap_target(struct ieee80211vap *vap);
int  ieee80211_chk_vap_target(struct ieee80211com *ic);
int ieee80211_chk_node_target(struct ieee80211com *ic);

void ieee80211_add_node_target(struct ieee80211_node *ni, struct ieee80211vap *vap,
    u_int8_t is_vap_node);
void ieee80211_delete_vap_target(struct ieee80211vap *vap);
void ieee80211_delete_node_target(struct ieee80211_node *ni, struct ieee80211com *ic,
    struct ieee80211vap *vap, u_int8_t is_reset_bss);
void ieee80211_update_node_target(struct ieee80211_node *ni, struct ieee80211vap *vap);
#if ENCAP_OFFLOAD
void ieee80211_update_vap_target(struct ieee80211vap *vap);
#else
#define ieee80211_update_vap_target(_vap)    
#endif
void ieee80211_update_target_ic(struct ieee80211_node *ni);

#define IEEE80211_CHK_VAP_TARGET(_ic)                   ieee80211_chk_vap_target(_ic)
#define IEEE80211_CHK_NODE_TARGET(_ic)                   ieee80211_chk_node_target(_ic)

#define IEEE80211_ADD_VAP_TARGET(vap)                   ieee80211_add_vap_target(vap);
#define IEEE80211_ADD_NODE_TARGET(ni, vap, is_vap_node) ieee80211_add_node_target(ni, vap, is_vap_node);
#define IEEE80211_DELETE_VAP_TARGET(vap)                ieee80211_delete_vap_target(vap)
#define IEEE80211_DELETE_NODE_TARGET(ni, ic, vap, is_reset_bss)                   \
                                                        ieee80211_delete_node_target(ni, ic, vap, is_reset_bss);
#define IEEE80211_UPDATE_TARGET_IC(ni)                  ieee80211_update_target_ic(ni);
#else
#define IEEE80211_CHK_VAP_TARGET(_ic)                   0
#define IEEE80211_CHK_NODE_TARGET(_ic)                  0

#define IEEE80211_ADD_VAP_TARGET(vap)
#define IEEE80211_ADD_NODE_TARGET(ni, vap, is_vap_node)
#define IEEE80211_DELETE_VAP_TARGET(vap)
#define IEEE80211_DELETE_NODE_TARGET(ni, ic, vap, is_reset_bss)
#define IEEE80211_UPDATE_TARGET_IC(ni)
#define ieee80211_update_vap_target(_vap)                 
#endif /* #ifdef ATH_SUPPORT_HTC */

#endif /* #ifndef _IEEE80211_TARGET_H_ */
