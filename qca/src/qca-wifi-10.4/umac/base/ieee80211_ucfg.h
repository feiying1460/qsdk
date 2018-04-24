/*
 * Copyright (c) 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef IEEE80211_UCFG_H_
#define IEEE80211_UCFG_H_
int ieee80211_ucfg_set_essid(wlan_if_t vap, ieee80211_ssid *data);
int ieee80211_ucfg_get_essid(wlan_if_t vap, ieee80211_ssid *data, int *nssid);
int ieee80211_ucfg_set_freq(wlan_if_t vap, int ieeechannel);
int ieee80211_ucfg_set_freq_internal(wlan_if_t vap, int ieeechannel);
int ieee80211_ucfg_set_chanswitch(wlan_if_t vaphandle, u_int8_t chan, u_int8_t tbtt, u_int16_t ch_width);
wlan_chan_t ieee80211_ucfg_get_current_channel(wlan_if_t vaphandle, bool hwChan);
wlan_chan_t ieee80211_ucfg_get_bss_channel(wlan_if_t vaphandle);
int ieee80211_ucfg_delete_vap(wlan_if_t vap);
int ieee80211_ucfg_set_rts(wlan_if_t vap, u_int32_t val);
int ieee80211_ucfg_set_frag(wlan_if_t vap, u_int32_t val);
int ieee80211_ucfg_set_txpow(wlan_if_t vaphandle, int txpow);
int ieee80211_ucfg_get_txpow(wlan_if_t vaphandle, int *txpow, int *fixed);
int ieee80211_ucfg_get_txpow_fraction(wlan_if_t vaphandle, int *txpow, int *fixed);
int ieee80211_ucfg_set_ap(wlan_if_t vap, u_int8_t (*des_bssid)[IEEE80211_ADDR_LEN]);
int ieee80211_ucfg_get_ap(wlan_if_t vap, u_int8_t *addr);
int ieee80211_ucfg_setparam(wlan_if_t vap, int param, int value, char *extra);
int ieee80211_ucfg_getparam(wlan_if_t vap, int param, int *value);
int ieee80211_ucfg_get_maxphyrate(wlan_if_t vaphandle);
int ieee80211_ucfg_set_phymode(wlan_if_t vap, char *modestr, int len);
int ieee80211_ucfg_set_encode(wlan_if_t vap, u_int16_t length, u_int16_t flags, void *keybuf);
int ieee80211_ucfg_set_rate(wlan_if_t vap, int value);
int ieee80211_ucfg_get_phymode(wlan_if_t vap, char *modestr, u_int16_t *length);
int ieee80211_ucfg_splitmac_add_client(wlan_if_t vap, u_int8_t *stamac, u_int16_t associd,
        u_int8_t qos, struct ieee80211_rateset lrates,
        struct ieee80211_rateset htrates, u_int16_t vhtrates);
int ieee80211_ucfg_splitmac_del_client(wlan_if_t vap, u_int8_t *stamac);
int ieee80211_ucfg_splitmac_authorize_client(wlan_if_t vap, u_int8_t *stamac, u_int32_t authorize);
int ieee80211_ucfg_splitmac_set_key(wlan_if_t vap, u_int8_t *macaddr, u_int8_t cipher,
        u_int16_t keyix, u_int32_t keylen, u_int8_t *keydata);
int ieee80211_ucfg_splitmac_del_key(wlan_if_t vap, u_int8_t *macaddr, u_int16_t keyix);
int ieee80211_ucfg_getstainfo(wlan_if_t vap, struct ieee80211req_sta_info *si, uint32_t *len);
int ieee80211_ucfg_getstaspace(wlan_if_t vap);
#if ATH_SUPPORT_IQUE
int ieee80211_ucfg_rcparams_setrtparams(wlan_if_t vap, uint8_t rt_index, uint8_t per, uint8_t probe_intvl);
int ieee80211_ucfg_rcparams_setratemask(wlan_if_t vap, uint8_t preamble, uint32_t mask_lower32, uint32_t mask_higher32);
#endif
#if QCA_AIRTIME_FAIRNESS
int ieee80211_ucfg_setatfssid(wlan_if_t vap, struct ssid_val *val);
int ieee80211_ucfg_delatfssid(wlan_if_t vap, struct ssid_val *val);
int ieee80211_ucfg_setatfsta(wlan_if_t vap, struct sta_val *val);
int ieee80211_ucfg_delatfsta(wlan_if_t vap, struct sta_val *val);
#endif
int ieee80211_ucfg_find_best_uplink_bssid(wlan_if_t vap, char *bssid);
int ieee80211_ucfg_find_cap_bssid(wlan_if_t vap, char *bssid);
int ieee80211_ucfg_get_best_otherband_uplink_bssid(wlan_if_t vap, char *bssid);
int ieee80211_ucfg_get_otherband_uplink_bssid(wlan_if_t vap, char *bssid);
int ieee80211_ucfg_set_otherband_bssid(wlan_if_t vap, int *val);
int ieee80211_ucfg_send_probereq(wlan_if_t vap, int val);
int ieee80211_ucfg_get_cap_snr(wlan_if_t vap, int *cap_snr);
#endif //IEEE80211_UCFG_H_
