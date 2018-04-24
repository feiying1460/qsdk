/*
 *  Copyright (c) 2008 Atheros Communications Inc. 
 * All Rights Reserved.
 * 
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */

#ifndef _IEEE80211_ACL_H
#define _IEEE80211_ACL_H

#if UMAC_SUPPORT_ACL

typedef struct ieee80211_acl    *ieee80211_acl_t;

int ieee80211_acl_attach(wlan_if_t vap);
int ieee80211_acl_detach(wlan_if_t vap);
int ieee80211_acl_add(wlan_if_t vap, const u_int8_t mac[IEEE80211_ADDR_LEN], u_int8_t acl_list_id);
int ieee80211_acl_remove(wlan_if_t vap, const u_int8_t mac[IEEE80211_ADDR_LEN], u_int8_t acl_list_id);
int ieee80211_acl_get(wlan_if_t vap, u_int8_t *mac_list, int len, int *num_mac, u_int8_t acl_list_id);
int ieee80211_acl_check(wlan_if_t vap, const u_int8_t mac[IEEE80211_ADDR_LEN]);
int ieee80211_acl_flush(wlan_if_t vap, u_int8_t acl_list_id);
int ieee80211_acl_setpolicy(wlan_if_t vap, int policy, u_int8_t acl_list_id);
int ieee80211_acl_getpolicy(wlan_if_t vap, u_int8_t acl_list_id);

/**
 * @brief Special flags that can be set by the band steering module (and
 *        potentially others in the future) on individual ACL entries.
 */
enum ieee80211_acl_flag {
    IEEE80211_ACL_FLAG_PROBE_RESP_WH = 1 << 0,  /* withhold probe responses */
    IEEE80211_ACL_FLAG_ACL_LIST_1    = 1 << 1,  /* Denotes ACL list 1 */
    IEEE80211_ACL_FLAG_ACL_LIST_2    = 1 << 2,  /* Denotes ACL list 2 */
    IEEE80211_ACL_FLAG_AUTH_ALLOW    = 1 << 3,  /* Denotes Auth Allow */
};

#if ATH_BAND_STEERING
int
ieee80211_acl_flag_check(wlan_if_t vap, const u_int8_t mac[IEEE80211_ADDR_LEN],
                         enum ieee80211_acl_flag flag);
int
ieee80211_acl_set_flag(wlan_if_t vap, const u_int8_t mac[IEEE80211_ADDR_LEN],
                       enum ieee80211_acl_flag flag);
int
ieee80211_acl_clr_flag(wlan_if_t vap, const u_int8_t mac[IEEE80211_ADDR_LEN],
                       enum ieee80211_acl_flag flag);
#endif

#else /* UMAC_SUPPORT_ACL */

typedef void    *ieee80211_acl_t;

#define ieee80211_acl_attach(vap)            /**/
#define ieee80211_acl_detach(vap)            /**/
/* 
 * defined this way to get rid of compiler warning about unused var 
 */
#define ieee80211_acl_add(vap, mac, acl_list_id)          (EINVAL)
#define ieee80211_acl_remove(vap, mac, acl_list_id)       (EINVAL)
#define ieee80211_acl_get(vap, mac_list, len, num_mac) (EINVAL)
#define ieee80211_acl_check(vap, mac)        (1)
#define ieee80211_acl_flush(vap, acl_list_id)             /**/
#define ieee80211_acl_setpolicy(vap, policy, acl_list_id) /**/
#define ieee80211_acl_getpolicy(vap, acl_list_id)         (IEEE80211_MACCMD_POLICY_OPEN)

#if ATH_BAND_STEERING
/*
 * In reality, this should never happen as band steering and ACL must
 * both be enabled in order for band steering to work. This is just placed
 * here for consistency.
 */
#define ieee80211_acl_flag_check             (0)
#define ieee80211_acl_set_flag               (-EINVAL)
#define ieee80211_acl_clr_flag               (-EINVAL)
#endif /* ATH_BAND_STEERING */

#endif /* UMAC_SUPPORT_ACL */

#endif



