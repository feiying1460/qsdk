/*
 * Copyright (c) 2015-2016 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef _IEEE80211_RATE_ESTIMATE_H
#define _IEEE80211_RATE_ESTIMATE_H

/**
 * @brief Enumerations for bandwidth (MHz) supported by STA
 */
typedef enum wlan_chwidth_e {
    wlan_chwidth_20,
    wlan_chwidth_40,
    wlan_chwidth_80,
    wlan_chwidth_160,

    wlan_chwidth_invalid
} wlan_chwidth_e;

/**
 * @brief Enumerations for IEEE802.11 PHY mode
 */
typedef enum wlan_phymode_e {
    wlan_phymode_basic,
    wlan_phymode_ht,
    wlan_phymode_vht,

    wlan_phymode_invalid
} wlan_phymode_e;

/* global functions */
extern u_int16_t ieee80211_SNRToPhyRateTablePerformLookup(
                struct ieee80211vap *vap,
                u_int8_t snr, int nss,
                wlan_phymode_e phyMode,
                wlan_chwidth_e chwidth);

/* Inline functions */
static inline wlan_phymode_e convert_phymode(enum ieee80211_phymode ieee_phymode)
{
    switch(ieee_phymode)
    {
        case IEEE80211_MODE_11AC_VHT20:
        case IEEE80211_MODE_11AC_VHT40PLUS:
        case IEEE80211_MODE_11AC_VHT40MINUS:
        case IEEE80211_MODE_11AC_VHT40:
        case IEEE80211_MODE_11AC_VHT80:
        case IEEE80211_MODE_11AC_VHT160:
        case IEEE80211_MODE_11AC_VHT80_80:
            return wlan_phymode_vht;
        case IEEE80211_MODE_11NA_HT20:
        case IEEE80211_MODE_11NG_HT20:
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40:
        case IEEE80211_MODE_11NA_HT40:
            return wlan_phymode_ht;
        case IEEE80211_MODE_11A:
        case IEEE80211_MODE_11B:
        case IEEE80211_MODE_11G:
        case IEEE80211_MODE_FH:
        case IEEE80211_MODE_TURBO_A:
        case IEEE80211_MODE_TURBO_G:
            return wlan_phymode_basic;
        case IEEE80211_MODE_AUTO:
        default:
            return wlan_phymode_invalid;

    }
}

static inline wlan_chwidth_e convert_chwidth(enum ieee80211_cwm_width ieee_chwidth)
{
    switch(ieee_chwidth)
    {
        case IEEE80211_CWM_WIDTH20:
        case IEEE80211_CWM_WIDTH40:
        case IEEE80211_CWM_WIDTH80:
            return (wlan_chwidth_e)ieee_chwidth;
        case IEEE80211_CWM_WIDTH160:
        case IEEE80211_CWM_WIDTH80_80:
            return wlan_chwidth_160;
        default:
            return wlan_chwidth_invalid;
    }
}

static inline enum ieee80211_cwm_width convert_ieee_phymode_to_chwidth(enum ieee80211_phymode ieee_phymode)
{
    switch(ieee_phymode)
    {
        case IEEE80211_MODE_11A:
        case IEEE80211_MODE_11B:
        case IEEE80211_MODE_11G:
        case IEEE80211_MODE_FH:
        case IEEE80211_MODE_TURBO_A:
        case IEEE80211_MODE_TURBO_G:
        case IEEE80211_MODE_11NA_HT20:
        case IEEE80211_MODE_11NG_HT20:
        case IEEE80211_MODE_11AC_VHT20:
            return IEEE80211_CWM_WIDTH20;
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40:
        case IEEE80211_MODE_11NA_HT40:
        case IEEE80211_MODE_11AC_VHT40PLUS:
        case IEEE80211_MODE_11AC_VHT40MINUS:
        case IEEE80211_MODE_11AC_VHT40:
            return IEEE80211_CWM_WIDTH40;
        case IEEE80211_MODE_11AC_VHT80:
            return IEEE80211_CWM_WIDTH80;
        case IEEE80211_MODE_11AC_VHT160:
            return IEEE80211_CWM_WIDTH160;
        case IEEE80211_MODE_11AC_VHT80_80:
            return IEEE80211_CWM_WIDTH80_80;
        case IEEE80211_MODE_AUTO:
        default:
            return IEEE80211_CWM_WIDTHINVALID;
    }
}

#endif //_IEEE80211_RATE_ESTIMATE_H
