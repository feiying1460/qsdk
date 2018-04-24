/*
 * Copyright (c) 2017 Qualcomm Innovation Center, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 */

#include <osdep.h>
#include <ieee80211_var.h>
#include "rijndael.h"

struct fils_ctx {
    struct ieee80211vap *fc_vap;    /* for diagnostics + statistics */
    struct ieee80211com *fc_ic;
    u_int8_t    ANonce[IEEE80211_FILS_NONCE_LEN];
    u_int8_t    SNonce[IEEE80211_FILS_NONCE_LEN];
    u_int8_t    kek[IEEE80211_MAX_WPA_KEK_LEN];
    u_int32_t   kek_len;
    rijndael_ctx cc_aes;
};

