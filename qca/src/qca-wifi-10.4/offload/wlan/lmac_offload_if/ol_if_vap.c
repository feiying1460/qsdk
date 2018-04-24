/*
 * Copyright (c) 2017 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 * Notifications and licenses are retained for attribution purposes only
 *
 * Copyright (c) 2011-2014, Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * LMAC VAP specific offload interface functions for UMAC - for power and performance offload model
 */
#include "ol_if_athvar.h"
#include "ol_if_athpriv.h"
#include "wmi_unified_api.h"
#include "ieee80211_api.h"
#include "umac_lmac_common.h"
#include "osif_private.h"
#include "qdf_mem.h"
#if ATH_SUPPORT_GREEN_AP
#include "ath_green_ap.h"
#endif

#define DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MAX_UNRESPONSIVE_TIME_SECS  (IEEE80211_INACT_RUN * IEEE80211_INACT_WAIT)
#define DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MAX_IDLE_TIME_SECS          (DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MAX_UNRESPONSIVE_TIME_SECS - 5)
#define DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MIN_IDLE_TIME_SECS          (DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MAX_IDLE_TIME_SECS/2)
#if ATH_SUPPORT_WRAP
#include "ol_if_mat.h"
#endif

#if MESH_MODE_SUPPORT
#include <if_meta_hdr.h>
#endif

#include <cdp_txrx_cmn.h>
#include <ol_txrx_types.h>

#include "ieee80211_band_steering.h"

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_if.h>
#include <osif_nss_wifiol_vdev_if.h>
#endif

#define RC_2_RATE_IDX(_rc)        ((_rc) & 0x7)
#ifndef HT_RC_2_STREAMS
#define HT_RC_2_STREAMS(_rc)    ((((_rc) & 0x78) >> 3) + 1)
#endif

#define ONEMBPS 1000
#define MIN_IDLE_INACTIVE_TIME_SECS(val)          ((val - 5)/2)
#define MAX_IDLE_INACTIVE_TIME_SECS(val)          (val - 5)
#define MAX_UNRESPONSIVE_TIME_MIN_THRESHOLD_SECS  5
#define MAX_UNRESPONSIVE_TIME_MAX_THRESHOLD_SECS  (u_int16_t)~0

extern int ol_ath_set_vap_dscp_tid_map(struct ieee80211vap *vap);
extern int ol_ath_ucfg_get_peer_mumimo_tx_count(wlan_if_t vaphandle, u_int32_t aid);
static int wlan_get_peer_mumimo_tx_count(wlan_if_t vaphandle, u_int32_t aid)
{
    return ol_ath_ucfg_get_peer_mumimo_tx_count(vaphandle, aid);
}
extern int ol_ath_ucfg_get_user_postion(wlan_if_t vaphandle, u_int32_t aid);
static int wlan_get_user_postion(wlan_if_t vaphandle, u_int32_t aid)
{
    return ol_ath_ucfg_get_user_postion(vaphandle, aid);
}
extern int ieee80211_rate_is_valid_basic(struct ieee80211vap *, u_int32_t);

extern void ieee80211_vi_dbg_print_stats(struct ieee80211vap *vap);
extern int ol_ath_ucfg_reset_peer_mumimo_tx_count(wlan_if_t vaphandle, u_int32_t aid);
extern int ol_ath_net80211_get_vap_stats(struct ieee80211vap *vap);
extern void ol_ath_set_vap_cts2self_prot_dtim_bcn(struct ieee80211vap *vap);
#if MESH_MODE_SUPPORT
extern void ol_txrx_set_mesh_mode(ol_txrx_vdev_handle vdev, u_int32_t val);
#endif
extern int ol_ath_target_start(struct ol_ath_softc_net80211 *scn);
#if ATH_SUPPORT_WRAP
extern unsigned int qwrap_enable;
#endif
extern void ol_wlan_txpow_mgmt(struct ieee80211vap *vap,u_int8_t val);
#if ATH_PERF_PWR_OFFLOAD
extern void osif_vap_setup_ol (struct ieee80211vap *vap, osif_dev *osifp);
static int ol_ath_vap_stopped_event(struct ol_ath_softc_net80211 *scn, u_int8_t if_id);

/*
+legacy rate table for the MCAST/BCAST rate. This table is specific to peregrine
+chip, so its implemented here in the ol layer instead of the ieee layer.

+This table is created according to the discription mentioned in the
+wmi_unified.h file.

+Here the left hand side specify the rate and the right hand side specify the
+respective values which the target understands.
+*/

static const int legacy_11b_rate_ol[][2] = {
    {1000, 0x43},
    {2000, 0x42},
    {5500, 0x41},
    {11000, 0x40},
};

static const int legacy_11a_rate_ol[][2] = {
    {6000, 0x03},
    {9000, 0x07},
    {12000, 0x02},
    {18000, 0x06},
    {24000, 0x01},
    {36000, 0x05},
    {48000, 0x00},
    {54000, 0x04},
};

static const int legacy_11bg_rate_ol[][2] = {
    {1000, 0x43},
    {2000, 0x42},
    {5500, 0x41},
    {6000, 0x03},
    {9000, 0x07},
    {11000, 0x40},
    {12000, 0x02},
    {18000, 0x06},
    {24000, 0x01},
    {36000, 0x05},
    {48000, 0x00},
    {54000, 0x04},
};

static const int ht20_11n_rate_ol[][2] = {
    {6500,  0x80},
    {13000, 0x81},
    {19500, 0x82},
    {26000, 0x83},
    {39000, 0x84},
    {52000, 0x85},
    {58500, 0x86},
    {65000, 0x87},

    {13000,  0x90},
    {26000,  0x91},
    {39000,  0x92},
    {52000,  0x93},
    {78000,  0x94},
    {104000, 0x95},
    {117000, 0x96},
    {130000, 0x97},

    {19500,  0xa0},
    {39000,  0xa1},
    {58500,  0xa2},
    {78000,  0xa3},
    {117000, 0xa4},
    {156000, 0xa5},
    {175500, 0xa6},
    {195000, 0xa7},

    {26000,  0xb0},
    {52000,  0xb1},
    {78000,  0xb2},
    {104000, 0xb3},
    {156000, 0xb4},
    {208000, 0xb5},
    {234000, 0xb6},
    {260000, 0xb7},
};

static const int ht20_11ac_rate_ol[][2] = {
/* VHT MCS0-9 NSS 1 20 MHz */
    { 6500, 0xc0},
    {13000, 0xc1},
    {19500, 0xc2},
    {26000, 0xc3},
    {39000, 0xc4},
    {52000, 0xc5},
    {58500, 0xc6},
    {65000, 0xc7},
    {78000, 0xc8},
    {86500, 0xc9},

/* VHT MCS0-9 NSS 2 20 MHz */
    { 13000, 0xd0},
    { 26000, 0xd1},
    { 39000, 0xd2},
    { 52000, 0xd3},
    { 78000, 0xd4},
    {104000, 0xd5},
    {117000, 0xd6},
    {130000, 0xd7},
    {156000, 0xd8},
    {173000, 0xd9},

 /* HT MCS0-9 NSS 3 20 MHz */
    { 19500, 0xe0},
    { 39000, 0xe1},
    { 58500, 0xe2},
    { 78000, 0xe3},
    {117000, 0xe4},
    {156000, 0xe5},
    {175500, 0xe6},
    {195000, 0xe7},
    {234000, 0xe8},
    {260000, 0xe9},

 /* HT MCS0-9 NSS 4 20 MHz */
    { 26000, 0xf0},
    { 52000, 0xf1},
    { 78000, 0xf2},
    {104000, 0xf3},
    {156000, 0xf4},
    {208000, 0xf5},
    {234000, 0xf6},
    {260000, 0xf7},
    {312000, 0xf8},
    {344000, 0xf9},
};


/* WMI command interface functions */
void
ol_ath_vdev_create_start_cmd(struct ol_ath_softc_net80211 *scn,
     u_int8_t if_id, struct ieee80211_channel *chan, u_int32_t freq,
     struct vdev_start_params *param)
{
    u_int32_t chan_mode;

    chan_mode = ieee80211_chan2mode(chan);
    param->vdev_id = if_id;
    param->channel.mhz = freq;
    param->channel.phy_mode = ol_get_phymode_info(chan_mode);

    if((chan_mode == IEEE80211_MODE_11AC_VHT80)|| (chan_mode == IEEE80211_MODE_11AC_VHT160) || (chan_mode == IEEE80211_MODE_11AC_VHT80_80)) {
        if (chan->ic_ieee < 20)
            param->channel.cfreq1 = ieee80211_ieee2mhz(&scn->sc_ic,
                    chan->ic_vhtop_ch_freq_seg1, IEEE80211_CHAN_2GHZ);
        else
            param->channel.cfreq1 = ieee80211_ieee2mhz(&scn->sc_ic,
                    chan->ic_vhtop_ch_freq_seg1, IEEE80211_CHAN_5GHZ);

        if (chan_mode == IEEE80211_MODE_11AC_VHT80_80 || chan_mode == IEEE80211_MODE_11AC_VHT160)
            param->channel.cfreq2 = ieee80211_ieee2mhz(&scn->sc_ic,
                    chan->ic_vhtop_ch_freq_seg2, IEEE80211_CHAN_5GHZ);
#if ATH_SUPPORT_ZERO_CAC_DFS
#define VHT160_IEEE_FREQ_DIFF 16
        /*
         * Zero-CAC-DFS algorithm:-
         * Zero-CAC-DFS algorithm works in stealth mode.
         * 1) When any channel change happens in VHT80 mode the algorithm
         * changes the HW channel mode to VHT80_80/VHT160 mode and adds a
         * new channel in the secondary VHT80 to perform precac and a
         * precac timer is started. However the upper layer/UMAC is unaware
         * of this change.
         * 2) When the precac timer expires without being interrupted by
         * any channel change the secondary VHT80 channel is moved from
         * precac-required-list to precac-done-list.
         * 3) If there is a radar detect at any time in any segment
         * (segment-1 is preimary VHT80 and segment-2 is VHT80)then the
         * channel is searched in both precac-reuired-list and precac-done-list
         * and moved to precac-nol-list.
         * 4) Whenever channel change happens if the new channel is a DFS
         * channel then precac-done-list is searched and if the channel is
         * found in the precac-done-list then the CAC is skipped.
         * 5) The precac expiry timer makes a vedv_restart(channel change
         * with current-upper-layer-channel-mode which is VHT80). In channel
         * change the algorithm tries to pick a new channel from the
         * precac-required list. If none found then channel mode remains same.
         * Which means when all the channels in precac-required-list are
         * exhausted the VHT80_80/VHT160 comes back to VHT80 mode.
         */
        else if(chan_mode == IEEE80211_MODE_11AC_VHT80) {
            /*
             * If
             * 1) The chip is CASCADE
             * 2) The user phy_mode is VHT80 and
             * 3) The user has enabled Pre-CAC and
             * 4) The regdomain the ETSI
             * then find a center frequency for the secondary VHT80 and Change the mode
             * to VHT80_80 or VHT160
             */
            struct ieee80211com *ic = &scn->sc_ic;
            uint8_t  ieee_freq;

            IEEE80211_DPRINTF_IC_CATEGORY(ic,IEEE80211_MSG_DFS, "%s : %d freq_seg1 = %u freq_seg2 = %u "
                    "precac_secondary_freq = %u precac_running = %u target_type = %u domain = %u\n",
                    __func__,__LINE__, chan->ic_vhtop_ch_freq_seg1, chan->ic_vhtop_ch_freq_seg2,
                    ic->ic_precac_secondary_freq, ic->ic_precac_timer_running, scn->target_type,
                    ic->ic_get_dfsdomain(ic));

            if(ic->ic_precac_enable &&
                    (scn->target_type == TARGET_TYPE_QCA9984) &&
                    (ic->ic_get_dfsdomain(ic) == DFS_ETSI_DOMAIN)) {
                /*
                 * If precac timer is running then do not change the secondary
                 * channel use the old secondary VHT80 channel.
                 * If precac timer is not running then try to find a new channel
                 * from precac-required-list.
                 */
                if(ic->ic_precac_timer_running) {
                    /*
                     * Primary and secondary VHT80 cannot be the same. Therefore exclude
                     * the primary frequency while getting new channel from
                     * precac-required-list.
                     */
                    if(chan->ic_vhtop_ch_freq_seg1 == ic->ic_precac_secondary_freq)
                        ieee_freq = ieee80211_dfs_get_freq_from_precac_required_list(ic,chan->ic_vhtop_ch_freq_seg1);
                    else
                        ieee_freq = ic->ic_precac_secondary_freq;
                }
                else {
                    ieee_freq = ieee80211_dfs_get_freq_from_precac_required_list(ic,chan->ic_vhtop_ch_freq_seg1);
                }

                if(ieee_freq) {
                    if(ieee_freq == (chan->ic_vhtop_ch_freq_seg1 + VHT160_IEEE_FREQ_DIFF)) {
                        /* Override the HW channel mode to VHT160 */
                        uint8_t  ieee_160_cfreq;
                        ieee_160_cfreq = (ieee_freq + chan->ic_vhtop_ch_freq_seg1)/2;
                        chan_mode = IEEE80211_MODE_11AC_VHT160;
                        param->channel.cfreq1 = ieee80211_ieee2mhz(&scn->sc_ic,
                                chan->ic_vhtop_ch_freq_seg1 ,IEEE80211_CHAN_5GHZ);
                        param->channel.cfreq2 = ieee80211_ieee2mhz(&scn->sc_ic,
                                ieee_160_cfreq,IEEE80211_CHAN_5GHZ);
                    } else {
                        /* Override the HW channel mode to VHT80_80 */
                        chan_mode = IEEE80211_MODE_11AC_VHT80_80;
                        param->channel.cfreq2 = ieee80211_ieee2mhz(&scn->sc_ic,
                                ieee_freq,IEEE80211_CHAN_5GHZ);
                    }
                    param->channel.phy_mode = ol_get_phymode_info(chan_mode);
                    param->channel.dfs_set_cfreq2 = TRUE;

                    /*
                     * Finally set the agile flag.
                     * When we want a full calibration of both primary VHT80 and secondary VHT80
                     * the agile flag is set to FALSE else set to TRUE.
                     * When a channel is being set for the first time this flag must be FALSE
                     * because first time the entire channel must be calibrated.
                     * All subsequent times the flag must be set to TRUE if we are changing only
                     * the secondary VHT80.
                     */
                    if (ic->ic_precac_primary_freq == chan->ic_vhtop_ch_freq_seg1) {
                        param->channel.set_agile = TRUE;
                    } else {
                        param->channel.set_agile = FALSE;
                    }

                    IEEE80211_DPRINTF_IC_CATEGORY(ic,IEEE80211_MSG_DFS, "%s : %d cfreq1 = %u cfreq2 = %u "
                            "ieee_freq = %u seg1 = %u mode = %u set_agile = %d\n",__func__,__LINE__,
                            param->channel.cfreq1, param->channel.cfreq2, ieee_freq,
                            chan->ic_vhtop_ch_freq_seg1, chan_mode, param->channel.set_agile);

                    ic->ic_precac_secondary_freq = ieee_freq;
                    ic->ic_precac_primary_freq = chan->ic_vhtop_ch_freq_seg1;

                    /* Start the pre_cac_timer */
                    ieee80211_dfs_start_precac_timer(ic,ic->ic_precac_secondary_freq);
                } /* End of if(ieee_freq) */
            } /* End of if(ic->ic_precac_enable) */
        }
#endif
    } else if((chan_mode == IEEE80211_MODE_11NA_HT40PLUS) || (chan_mode == IEEE80211_MODE_11NG_HT40PLUS) ||
            (chan_mode == IEEE80211_MODE_11AC_VHT40PLUS)) {
        param->channel.cfreq1 = freq + 10;
    } else if((chan_mode == IEEE80211_MODE_11NA_HT40MINUS) || (chan_mode == IEEE80211_MODE_11NG_HT40MINUS) ||
            (chan_mode == IEEE80211_MODE_11AC_VHT40MINUS)) {
        param->channel.cfreq1 = freq - 10;
    } else {
        param->channel.cfreq1 = freq;
    }

 /*
     * If the channel has DFS set, flip on radar reporting.
     *
     * It may be that this should only be done for IBSS/hostap operation
     * as this flag may be interpreted (at some point in the future)
     * by the firmware as "oh, and please do radar DETECTION."
     *
     * If that is ever the case we would insert the decision whether to
     * enable the firmware flag here.
     */
    if (IEEE80211_IS_CHAN_DFS(chan)) {
        param->channel.dfs_set = TRUE;
    }

    if ((chan_mode == IEEE80211_MODE_11AC_VHT80_80) || ( chan_mode == IEEE80211_MODE_11AC_VHT160)) {
        if (IEEE80211_IS_CHAN_DFS_CFREQ2(chan)) {
            param->channel.dfs_set_cfreq2 = TRUE;
        }
    }
    if (IEEE80211_IS_CHAN_HALF(chan)) {
        param->channel.half_rate = TRUE;
    }
    if (IEEE80211_IS_CHAN_QUARTER(chan)) {
        param->channel.quarter_rate = TRUE;
    }

    param->channel.minpower = chan->ic_minpower;
    param->channel.maxpower = chan->ic_maxpower;
    param->channel.maxregpower = chan->ic_maxregpower;
    param->channel.antennamax = chan->ic_antennamax;
    param->channel.reg_class_id = chan->ic_regClassId;
}

int
ol_ath_vdev_start_send(struct ol_ath_softc_net80211 *scn, u_int8_t if_id,
        struct ieee80211_channel *chan, u_int32_t freq, bool disable_hw_ack,
        void *nl_handle)
{
    struct vdev_start_params param;
    qdf_mem_set(&param, sizeof(param), 0);
    ol_ath_vdev_create_start_cmd(scn, if_id, chan, freq, &param);
    param.disable_hw_ack = disable_hw_ack;

    return wmi_unified_vdev_start_send(scn->wmi_handle, &param);
}
int
ol_ath_vdev_restart_send(struct ol_ath_softc_net80211 *scn, u_int8_t if_id,
        struct ieee80211_channel *chan, u_int32_t freq, bool disable_hw_ack)
{
    struct vdev_start_params param;
    qdf_mem_set(&param, sizeof(param), 0);
    param.vdev_id = if_id;
    param.disable_hw_ack = disable_hw_ack;
    param.channel.mhz = freq;
    param.is_restart = TRUE;
    ol_ath_vdev_create_start_cmd(scn, if_id, chan, freq, &param);

    return wmi_unified_vdev_start_send(scn->wmi_handle, &param);
}
#if QCA_AIRTIME_FAIRNESS
int
ol_ath_vdev_atf_request_send(struct ol_ath_softc_net80211 *scn, u_int32_t param_value)
{
    /* Will be implemented when it is decided how to use it*/
    /* While implementing, please Move this API to WMI layer. */
    return EOK;
}
#endif

int ol_get_rate_code(struct ieee80211_channel *chan, int val)
{
    uint32_t chan_mode;
    int i = 0, j = 0, found = 0, array_size = 0;
    int *rate_code = NULL;

    struct ol_rate_table {
        int *table;
        int size;
    } rate_table [3];

    if(chan == NULL)
        return EINVAL;

    OS_MEMZERO(&rate_table[0], sizeof(rate_table));

    chan_mode = ieee80211_chan2mode(chan);

    switch (chan_mode)
    {
        case IEEE80211_MODE_11B:
            {
                /* convert rate to index */
                rate_table[2].size = sizeof(legacy_11b_rate_ol)/sizeof(legacy_11b_rate_ol[0]);
                rate_table[2].table = (int *)&legacy_11b_rate_ol;
            }
            break;

        case IEEE80211_MODE_11G:
        case IEEE80211_MODE_TURBO_G:
            {
                /* convert rate to index */
                rate_table[2].size = sizeof(legacy_11bg_rate_ol)/sizeof(legacy_11bg_rate_ol[0]);
                rate_table[2].table = (int *)&legacy_11bg_rate_ol;
            }
            break;

        case IEEE80211_MODE_11A:
        case IEEE80211_MODE_TURBO_A:
            {
                /* convert rate to index */
                rate_table[2].size = sizeof(legacy_11a_rate_ol)/sizeof(legacy_11a_rate_ol[0]);
                rate_table[2].table = (int *)&legacy_11a_rate_ol;
            }
            break;

        case IEEE80211_MODE_11AC_VHT20:
        case IEEE80211_MODE_11AC_VHT40PLUS:
        case IEEE80211_MODE_11AC_VHT40MINUS:
        case IEEE80211_MODE_11AC_VHT40:
        case IEEE80211_MODE_11AC_VHT80:
        case IEEE80211_MODE_11AC_VHT160:
        case IEEE80211_MODE_11AC_VHT80_80:
            {
                rate_table[0].size = sizeof(ht20_11ac_rate_ol)/sizeof(ht20_11ac_rate_ol[0]);
                rate_table[0].table = (int *)&ht20_11ac_rate_ol;
            }

        case IEEE80211_MODE_11NG_HT20:
        case IEEE80211_MODE_11NG_HT40:
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NA_HT20:
        case IEEE80211_MODE_11NA_HT40:
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
            {
                rate_table[1].size = sizeof(ht20_11n_rate_ol)/sizeof(ht20_11n_rate_ol[0]);
                rate_table[1].table = (int *)&ht20_11n_rate_ol;
            }

            if (IEEE80211_IS_CHAN_5GHZ(chan)) {
                rate_table[2].size = sizeof(legacy_11a_rate_ol)/sizeof(legacy_11a_rate_ol[0]);
                rate_table[2].table = (int *)&legacy_11a_rate_ol;
            } else {
                rate_table[2].size = sizeof(legacy_11bg_rate_ol)/sizeof(legacy_11bg_rate_ol[0]);
                rate_table[2].table = (int *)&legacy_11bg_rate_ol;
            }

            break;

        default:
        {
            qdf_print("%s Invalid channel mode. \n\r",__func__);
            break;
        }
    }

    for (j = 2; ((j >= 0) && !found) && rate_table[j].table; j--) {
        array_size = rate_table[j].size;
        rate_code = rate_table[j].table;
        for (i = 0; i < array_size; i++) {
            /* Array Index 0 has the rate and 1 has the rate code.
               The variable rate has the rate code which must be converted to actual rate*/
            if (val == *rate_code) {
                val = *(rate_code + 1);
                found = 1;
                break;
            }
            rate_code += 2;
        }
    }

    if(!found) {
        return EINVAL;
    }
    return val;
}

static int
ol_ath_validate_tx_encap_type(struct ol_ath_softc_net80211 *scn,
        struct ieee80211vap *vap, u_int32_t val)
{
    struct ieee80211com *ic = vap->iv_ic;
    if (!ic->ic_rawmode_support)
    {
        qdf_print("Configuration capability not provided for this chipset\n");
        return 0;
    }

    if (wlan_vap_get_opmode(vap) != IEEE80211_M_HOSTAP)
    {
        qdf_print("Configuration capability available only for AP mode\n");
        return 0;
    }

#if !QCA_OL_SUPPORT_RAWMODE_TXRX
    if (val == 0) {
        qdf_print("Valid values: 1 - Native Wi-Fi, 2 - Ethernet\n"
               "0 - RAW is unavailable\n");
        return 0;
    }
#endif

    if (val <= 2) {
        return 1;
    } else {
        qdf_print("Valid values: 0 - RAW, 1 - Native Wi-Fi, 2 - Ethernet, "
               "%d is invalid\n", val);
        return 0;
    }
}

static int
ol_ath_validate_rx_decap_type(struct ol_ath_softc_net80211 *scn,
        struct ieee80211vap *vap, u_int32_t val)
{
    /* Though the body of this function is the same as
     * ol_ath_validate_tx_encap_type(), it is kept separate for future
     * flexibility.
     */

    struct ieee80211com *ic = vap->iv_ic;
    if (!ic->ic_rawmode_support)
    {
        qdf_print("Configuration capability not provided for this chipset\n");
        return 0;
    }

    if (wlan_vap_get_opmode(vap) != IEEE80211_M_HOSTAP)
    {
        qdf_print("Configuration capability available only for AP mode\n");
        return 0;
    }

#if !QCA_OL_SUPPORT_RAWMODE_TXRX
    if (val == 0) {
        qdf_print("Valid values: 1 - Native Wi-Fi, 2 - Ethernet\n"
               "0 - RAW is unavailable\n");
        return 0;
    }
#endif

    if (val <= 2) {
        return 1;
    } else {
        qdf_print("Valid values: 0 - RAW, 1 - Native Wi-Fi, 2 - Ethernet, "
               "%d is invalid\n", val);
        return 0;
    }
}


int ol_ath_wmi_send_sifs_trigger(struct ol_ath_softc_net80211 *scn,
           uint8_t if_id, uint32_t param_value)
{
    struct sifs_trigger_param sparam;

    qdf_mem_set(&sparam, sizeof(sparam), 0);
    sparam.if_id = if_id;
    sparam.param_value = param_value;

    return wmi_unified_sifs_trigger_send(scn->wmi_handle, &sparam);
}

int ol_ath_wmi_send_vdev_param(struct ol_ath_softc_net80211 *scn, uint8_t if_id,
        uint32_t param_id, uint32_t param_value)
{
    struct vdev_set_params vparam;

    qdf_mem_set(&vparam, sizeof(vparam), 0);
    vparam.if_id = if_id;
    vparam.param_id = param_id;
    vparam.param_value = param_value;

    return wmi_unified_vdev_set_param_send(scn->wmi_handle, &vparam);
}

static int
ol_ath_vap_sifs_trigger(struct ieee80211vap *vap, u_int32_t val)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    int retval = 0;

    retval = ol_ath_wmi_send_sifs_trigger(scn, avn->av_if_id, val);

    return(retval);
}

/* Vap interface functions */
static int
ol_ath_vap_set_param(struct ieee80211vap *vap,
              ieee80211_param param, u_int32_t val)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    int retval = 0;
#if UMAC_VOW_DEBUG
    int ii;
#endif

    /* Set the VAP param in the target */
    switch (param) {

        case IEEE80211_RTS_THRESHOLD:
            retval = ol_ath_wmi_send_vdev_param(scn,avn->av_if_id,
                         wmi_vdev_param_rts_threshold, val);
        break;

        case IEEE80211_FRAG_THRESHOLD:
            retval = ol_ath_wmi_send_vdev_param(scn,avn->av_if_id,
                         wmi_vdev_param_fragmentation_threshold, val);
        break;


        case IEEE80211_BEACON_INTVAL:
            retval = ol_ath_wmi_send_vdev_param(scn,avn->av_if_id,
                         wmi_vdev_param_beacon_interval, val);
        break;

        case IEEE80211_LISTEN_INTVAL:
            retval = ol_ath_wmi_send_vdev_param(scn,avn->av_if_id,
                         wmi_vdev_param_listen_interval, val);
        break;

        case IEEE80211_ATIM_WINDOW:
            retval = ol_ath_wmi_send_vdev_param(scn,avn->av_if_id,
                         wmi_vdev_param_atim_window, val);
        break;

        case IEEE80211_DTIM_INTVAL:
            retval = ol_ath_wmi_send_vdev_param(scn,avn->av_if_id,
                         wmi_vdev_param_dtim_period, val);
        break;

        case IEEE80211_BMISS_COUNT_RESET:
         /* this is mainly under assumsion that if this number of  */
         /* beacons are not received then HW is hung anf HW need to be resett */
         /* target will use its own method to detect and reset the chip if required. */
            retval = 0;
        break;

        case IEEE80211_BMISS_COUNT_MAX:
            retval = ol_ath_wmi_send_vdev_param(scn,avn->av_if_id,
                         wmi_vdev_param_bmiss_count_max, val);
        break;

        case IEEE80211_FEATURE_WMM:
            retval = ol_ath_wmi_send_vdev_param(scn,avn->av_if_id,
                         wmi_vdev_param_feature_wmm, val);
        break;

        case IEEE80211_FEATURE_WDS:
            retval = ol_ath_wmi_send_vdev_param(scn,avn->av_if_id,
                         wmi_vdev_param_wds, val);
        break;

        case IEEE80211_CHWIDTH:
            retval = ol_ath_wmi_send_vdev_param(
                         scn, avn->av_if_id,
                         wmi_vdev_param_chwidth, val);
        break;

        case IEEE80211_FIXED_NSS:
             ol_ath_wmi_send_vdev_param( scn, avn->av_if_id,
                         wmi_vdev_param_nss, vap->iv_nss);
        break;

        case IEEE80211_SIFS_TRIGGER_RATE:
             ol_ath_wmi_send_vdev_param( scn, avn->av_if_id,
                         wmi_vdev_param_sifs_trigger_rate, val);
        break;

        case IEEE80211_FIXED_RATE:
           {
                u_int8_t preamble, nss, rix;
                /* Note: Event though val is 32 bits, only the lower 8 bits matter */
                if (vap->iv_fixed_rate.mode == IEEE80211_FIXED_RATE_NONE) {
                    val = WMI_HOST_FIXED_RATE_NONE;
                }
                else {
                    rix = RC_2_RATE_IDX(vap->iv_fixed_rateset);
                    if (vap->iv_fixed_rate.mode == IEEE80211_FIXED_RATE_MCS) {
                        preamble = WMI_HOST_RATE_PREAMBLE_HT;
                        nss = HT_RC_2_STREAMS(vap->iv_fixed_rateset) -1;
                    }
                    else {
                        nss = 0;
                        rix = RC_2_RATE_IDX(vap->iv_fixed_rateset);

                        if(scn->burst_enable)
                        {
                            retval = ol_ath_pdev_set_param(scn,
                                                                wmi_pdev_param_burst_enable, 0, 0);

                            if (retval == EOK) {
                                scn->burst_enable = 0;
                            }
                        }

			if (vap->iv_fixed_rateset & 0x10) {
                            preamble = WMI_HOST_RATE_PREAMBLE_CCK;
			    if(rix != 0x3)
			    /* Enable Short preamble always for CCK except 1mbps*/
			    rix |= 0x4;
                        }
                        else {
                            preamble = WMI_HOST_RATE_PREAMBLE_OFDM;
                        }
                    }
                    val = (preamble << 6) | (nss << 4) | rix;
                }
                retval = ol_ath_wmi_send_vdev_param(scn,avn->av_if_id,
                                              wmi_vdev_param_fixed_rate, val);
           }
        break;
        case IEEE80211_FIXED_VHT_MCS:
           {
                if (vap->iv_fixed_rate.mode == IEEE80211_FIXED_RATE_VHT) {
                    val = (WMI_HOST_RATE_PREAMBLE_VHT << 6) | ((vap->iv_nss -1) << 4) | vap->iv_vht_fixed_mcs;
                }
                else {
                    /* Note: Event though val is 32 bits, only the lower 8 bits matter */
                    val = WMI_HOST_FIXED_RATE_NONE;
                }
                retval = ol_ath_wmi_send_vdev_param(scn,avn->av_if_id,
                                              wmi_vdev_param_fixed_rate, val);
           }
        break;
        case IEEE80211_FEATURE_APBRIDGE:
            retval = ol_ath_wmi_send_vdev_param(scn,avn->av_if_id,
                                              wmi_vdev_param_intra_bss_fwd, val);
        break;

        case IEEE80211_SHORT_GI:
            retval = ol_ath_wmi_send_vdev_param(scn,avn->av_if_id,
                                              wmi_vdev_param_sgi, val);
        break;

        case IEEE80211_SECOND_CENTER_FREQ :
        if (scn->target_type == TARGET_TYPE_QCA9984 || scn->target_type == TARGET_TYPE_QCA9888) {

            if( vap->iv_des_mode == IEEE80211_MODE_11AC_VHT80_80) {
                if(val > 5170) {
                    vap->iv_des_cfreq2 = ieee80211_mhz2ieee(ic,val,0);
                }
                else {
                    vap->iv_des_cfreq2 = val;
                }

                qdf_print("Desired cfreq2 is %d. Please set primary 20 MHz channel for cfreq2 setting to take effect \n", vap->iv_des_cfreq2);
            }
            else {
                qdf_print("command not applicable for this mode \n");
                return -EINVAL;
            }
        }
        else {
            qdf_print(" Command not applicable for this chip \n");
            return -EINVAL;
        }

        break;

        case IEEE80211_SUPPORT_LDPC:
        {
            retval = ol_ath_wmi_send_vdev_param(scn,avn->av_if_id,
                                              wmi_vdev_param_ldpc, val);
        }
            break;

        case IEEE80211_SUPPORT_TX_STBC:
            retval = ol_ath_wmi_send_vdev_param(scn,avn->av_if_id,
                                              wmi_vdev_param_tx_stbc, val);
        break;

        case IEEE80211_SUPPORT_RX_STBC:
            retval = ol_ath_wmi_send_vdev_param(scn,avn->av_if_id,
                                          wmi_vdev_param_rx_stbc, val);
        break;
        case IEEE80211_DEFAULT_KEYID:
            retval = ol_ath_wmi_send_vdev_param(scn,avn->av_if_id,
                                          wmi_vdev_param_def_keyid, val);
        break;
#if UMAC_SUPPORT_PROXY_ARP
        case IEEE80211_PROXYARP_CAP:
            retval = ol_ath_wmi_send_vdev_param(scn,avn->av_if_id,
                                          wmi_vdev_param_mcast_indicate, val);
            retval |= ol_ath_wmi_send_vdev_param(scn,avn->av_if_id,
                                          wmi_vdev_param_dhcp_indicate, val);
        break;
#endif /* UMAC_SUPPORT_PROXY_ARP */
        case IEEE80211_RUN_INACT_TIMEOUT:
        {
            if (val >= MAX_UNRESPONSIVE_TIME_MIN_THRESHOLD_SECS && val <= MAX_UNRESPONSIVE_TIME_MAX_THRESHOLD_SECS)
            {
                u_int16_t  max_unresponsive_time_secs = val;
                u_int16_t  max_idle_inactive_time_secs = MAX_IDLE_INACTIVE_TIME_SECS(val);
                u_int16_t  min_idle_inactive_time_secs = MIN_IDLE_INACTIVE_TIME_SECS(val);
                /* Setting iv_inact_run, for retrieval using iwpriv get_inact command */
                vap->iv_inact_run = max_unresponsive_time_secs;
                retval = ol_ath_wmi_send_vdev_param(scn,
                        avn->av_if_id, wmi_vdev_param_ap_keepalive_min_idle_inactive_time_secs,
                        min_idle_inactive_time_secs);
                retval |= ol_ath_wmi_send_vdev_param(scn,
                        avn->av_if_id, wmi_vdev_param_ap_keepalive_max_idle_inactive_time_secs,
                        max_idle_inactive_time_secs);
                retval |= ol_ath_wmi_send_vdev_param(scn,
                        avn->av_if_id, wmi_vdev_param_ap_keepalive_max_unresponsive_time_secs,
                        max_unresponsive_time_secs);
            }
            else
            {
                qdf_print("\nRange allowed is : %d to %d",MAX_UNRESPONSIVE_TIME_MIN_THRESHOLD_SECS, MAX_UNRESPONSIVE_TIME_MAX_THRESHOLD_SECS);
            }
        }
        break;
	    case IEEE80211_MCAST_RATE:
        {
            struct ieee80211_channel *chan = vap->iv_des_chan[vap->iv_des_mode];
            int value;

            if ((!chan) || (chan == IEEE80211_CHAN_ANYC)) {
                vap->iv_mcast_rate_config_defered = TRUE;
                qdf_print("Configuring MCAST RATE is deffered as channel is not yet set for VAP \n");
                break;
            }
            if(IEEE80211_IS_CHAN_5GHZ(chan)&&val<6000){
                qdf_print("%s: MCAST RATE should be at least 6000(kbps) for 5G\n",__func__);
                retval = -EINVAL;
                break;
            }

            value = ol_get_rate_code(chan, val);
            if(value == EINVAL) {
                retval = -EINVAL;
                break;
            }
            retval = ol_ath_wmi_send_vdev_param(scn, avn->av_if_id,
                    wmi_vdev_param_mcast_data_rate, value);
            if(retval == 0 ) {
                vap->iv_mcast_rate_config_defered = FALSE;
                qdf_print("%s: Now supported MCAST RATE is %d(kbps) and rate code: 0x%x\n",
                        __func__, val, value);
            }
        }
        break;
        case IEEE80211_BCAST_RATE:
        {
            struct ieee80211_channel *chan = vap->iv_des_chan[vap->iv_des_mode];
            int value;

            if ((!chan) || (chan == IEEE80211_CHAN_ANYC)) {
                vap->iv_bcast_rate_config_defered = TRUE;
                qdf_print("Configuring BCAST RATE is deffered as channel is not yet set for VAP \n");
                break;
            }
            if(IEEE80211_IS_CHAN_5GHZ(chan)&&val<6000){
                qdf_print("%s: BCAST RATE should be at least 6000(kbps) for 5G\n",__func__);
                retval = -EINVAL;
                break;
            }

            value = ol_get_rate_code(chan, val);
            if(value == EINVAL) {
                retval = -EINVAL;
                break;
            }
            retval = ol_ath_wmi_send_vdev_param(scn, avn->av_if_id,
                     wmi_vdev_param_bcast_data_rate, value);
            if (retval == 0) {
                vap->iv_bcast_rate_config_defered = FALSE;
                qdf_print("%s: Now supported BCAST RATE is %d(kbps) and rate code: 0x%x\n",
                        __func__, val, value);
            }
        }
        break;
        case IEEE80211_MGMT_RATE:
        {
            struct ieee80211_channel *chan = vap->iv_des_chan[vap->iv_des_mode];
            int value;

            if ((!chan) || (chan == IEEE80211_CHAN_ANYC)) {
                vap->iv_mgt_rate_config_defered = TRUE;
                qdf_print("Configuring MGMT RATE is deffered as channel is not yet set for VAP \n");
                break;
            }
            if(IEEE80211_IS_CHAN_5GHZ(chan)&&val<6000){
                qdf_print("%s: MGMT RATE should be at least 6000(kbps) for 5G\n",__func__);
                retval = EINVAL;
                break;
            }
            if(!ieee80211_rate_is_valid_basic(vap,val)){
                qdf_print("%s: rate %d is not valid. \n",__func__,val);
                retval = EINVAL;
                break;
            }
            value = ol_get_rate_code(chan, val);
            if(value == EINVAL) {
                retval = EINVAL;
                break;
            }
            retval = ol_ath_wmi_send_vdev_param(scn, avn->av_if_id,
                     wmi_vdev_param_mgmt_rate, value);
            if (retval == 0){
                vap->iv_mgt_rate_config_defered = FALSE;
                qdf_print("%s: Now supported MGMT RATE is %d(kbps) and rate code: 0x%x\n",
                     __func__, val, value);
            }
        }
        break;
        case IEEE80211_RTSCTS_RATE:
        {
            struct ieee80211_channel *chan = vap->iv_des_chan[vap->iv_des_mode];
            int rtscts_rate;

            if ((!chan) || (chan == IEEE80211_CHAN_ANYC)) {
                qdf_print("Configuring  RATE for RTS and CTS is deffered as channel is not yet set for VAP \n");
                break;
            }

            if(!ieee80211_rate_is_valid_basic(vap,val)){
                qdf_print("%s: Rate %d is not valid. \n",__func__,val);
                retval = EINVAL;
                break;
            }
            rtscts_rate = ol_get_rate_code(chan, val);
            if(rtscts_rate == EINVAL) {
               retval = EINVAL;
                break;
            }
            retval = ol_ath_wmi_send_vdev_param(scn, avn->av_if_id,
                        wmi_vdev_param_rts_fixed_rate, rtscts_rate);
            if (retval == 0)
                qdf_print("%s:Now supported CTRL RATE is : %d kbps and rate code : 0x%x\n",__func__,val,rtscts_rate);
        }
        break;
        case IEEE80211_BEACON_RATE_FOR_VAP:
        {
            struct ieee80211_channel *chan = vap->iv_bsschan;
            int beacon_rate;

            if ((!chan) || (chan == IEEE80211_CHAN_ANYC)) {
                qdf_print("Configuring Beacon Rate is deffered as channel is not yet set for VAP \n");
                retval = EINVAL;
                break;
            }

            beacon_rate = ol_get_rate_code(chan, val);
            if(beacon_rate == EINVAL) {
                retval = EINVAL;
                break;
            }

            retval = ol_ath_wmi_send_vdev_param(scn, avn->av_if_id,
                       wmi_vdev_param_beacon_rate, beacon_rate);
        }
        break;

        case IEEE80211_MAX_AMPDU:
        /*should be moved to vap in future & add wmi cmd to update vdev*/
            retval = 0;
		break;
        case IEEE80211_VHT_MAX_AMPDU:
        /*should be moved to vap in future & add wmi cmd to update vdev*/
            retval = 0;
        break;

        case IEEE80211_VHT_SUBFEE:
        case IEEE80211_VHT_MUBFEE:
        case IEEE80211_VHT_SUBFER:
        case IEEE80211_VHT_MUBFER:
        case IEEE80211_VHT_BF_STS_CAP:
        case IEEE80211_SUPPORT_IMPLICITBF:
        case IEEE80211_VHT_BF_SOUNDING_DIM:
        {
            uint32_t txbf_cap;
            txbf_cap = 0;
            WMI_HOST_TXBF_CONF_SU_TX_BFEE_SET(txbf_cap,vap->iv_vhtsubfee);
            WMI_HOST_TXBF_CONF_MU_TX_BFEE_SET(txbf_cap,vap->iv_vhtmubfee);
            WMI_HOST_TXBF_CONF_SU_TX_BFER_SET(txbf_cap,vap->iv_vhtsubfer);
            WMI_HOST_TXBF_CONF_MU_TX_BFER_SET(txbf_cap,vap->iv_vhtmubfer);
            WMI_HOST_TXBF_CONF_STS_CAP_SET(txbf_cap,vap->iv_vhtbfeestscap);
            WMI_HOST_TXBF_CONF_IMPLICIT_BF_SET(txbf_cap,  vap->iv_implicitbf);
            WMI_HOST_TXBF_CONF_BF_SND_DIM_SET(txbf_cap, vap->iv_vhtbfsoundingdim);

            qdf_print("su bfee %d mu bfee %d su bfer %d mu bfer %d impl bf %d sounding dim %d\n",
               WMI_HOST_TXBF_CONF_SU_TX_BFEE_GET(txbf_cap), WMI_HOST_TXBF_CONF_MU_TX_BFEE_GET(txbf_cap),
               WMI_HOST_TXBF_CONF_SU_TX_BFER_GET(txbf_cap), WMI_HOST_TXBF_CONF_MU_TX_BFER_GET(txbf_cap),
               WMI_HOST_TXBF_CONF_IMPLICIT_BF_GET(txbf_cap),WMI_HOST_TXBF_CONF_BF_SND_DIM_GET(txbf_cap));

            retval = ol_ath_wmi_send_vdev_param(scn, avn->av_if_id,
                                             wmi_vdev_param_txbf, txbf_cap);
        }
        break;
#if QCA_AIRTIME_FAIRNESS
        case  IEEE80211_ATF_OPT:
        retval = ol_ath_set_atf(ic);
        break;
        case IEEE80211_ATF_PEER_REQUEST:
        retval = ol_ath_send_atf_peer_request(ic);
        break;
        case IEEE80211_ATF_PER_UNIT:
        retval = ol_ath_vdev_atf_request_send(scn, val);
        break;
        case IEEE80211_ATF_DYNAMIC_ENABLE:
        if (!val)
            retval = ol_ath_pdev_set_param(scn, wmi_pdev_param_atf_peer_stats, WMI_HOST_ATF_PEER_STATS_DISABLED, 0);
        retval = ol_ath_pdev_set_param(scn,
                wmi_pdev_param_atf_dynamic_enable, val, 0);
        if (val)
            retval = ol_ath_pdev_set_param(scn, wmi_pdev_param_atf_peer_stats, WMI_HOST_ATF_PEER_STATS_ENABLED, 0);
        break;
        case  IEEE80211_ATF_GROUPING:
        retval = ol_ath_set_atf_grouping(ic);
        break;
        case IEEE80211_BWF_PEER_REQUEST:
        retval = ol_ath_set_bwf(ic);
        break;
        case IEEE80211_ATF_SSID_SCHED_POLICY:
        retval = ol_ath_wmi_send_vdev_param(scn, avn->av_if_id, wmi_vdev_param_atf_ssid_sched_policy, val);
        break;

#endif

#if ATH_SUPPORT_IQUE
        case IEEE80211_ME:
#if ATH_SUPPORT_ME_FW_BASED
	{
            struct ol_txrx_pdev_t *pdev;
            u_int16_t allocated;

	    /* On DA, mode 5 represents hifi, target has no special mode for hifi.
	       In target, mode 1 drops the frame if no mcast group is found.
	       Mode 1 need to be set in fw for hyfi, as hyfi needs igmp src filtering */
	    if(val == 5) {
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
                ic->ic_mcast_group_update(ic, IGMP_ACTION_ADD_MEMBER, IGMP_WILDCARD_SINGLE, (u_int8_t *)&ic->ic_hmmcs[0].ip,
                                              IGMP_IP_ADDR_LENGTH, NULL, 0, 0, NULL, (u_int8_t *)&ic->ic_hmmcs[0].mask, vap->iv_unit);
                ic->ic_mcast_group_update(ic, IGMP_ACTION_ADD_MEMBER, IGMP_WILDCARD_SINGLE, (u_int8_t *)&ic->ic_hmmcs[1].ip,
                                              IGMP_IP_ADDR_LENGTH, NULL, 0, 0, NULL, (u_int8_t *)&ic->ic_hmmcs[1].mask, vap->iv_unit);
                ic->ic_mcast_group_update(ic, IGMP_ACTION_ADD_MEMBER, IGMP_WILDCARD_SINGLE, (u_int8_t *)&ic->ic_hmmcs[2].ip,
                                              IGMP_IP_ADDR_LENGTH, NULL, 0, 0, NULL, (u_int8_t *)&ic->ic_hmmcs[2].mask, vap->iv_unit);
#endif/*ATH_SUPPORT_HYFI_ENHANCEMENTS*/
                val = 1;
	    }

            /* get the pdev from the vap handle */
	    pdev = scn->pdev_txrx_handle;

	    /* Allocate the buffers for Mcast to unicast enhancement valid values 0,1,2; 0-disabled*/
        if (val != 0) {
            /* Allocate buffers only when VoW is not enabled.
             * Incase of VoW, it is allocated dynamically when the group gets added
             */
            if( !(scn->vow_config >> 16) ) {
                /* Mcast enhancement enabled, so allocate buffers */
                ic->ic_desc_alloc_and_mark_for_mcast_clone(ic, MAX_BLOCKED_MCAST_DESC);
            }
	    } else {
                /* Mcast enhancement disabled, remove allocated buffer only in the event handler,
                 * but inform target to send event back once the target buffers are released.
                 * This is done to avoid host sending more packet before target releases the buffers
                 * used for mcast cloning.
                 */
                allocated = ic->ic_get_mcast_buf_allocated_marked(ic);
                /* We are cleaning up. No need to allocate any pending desc requests*/
                scn->pend_desc_addition = 0;
                ic->ic_desc_free_and_unmark_for_mcast_clone(ic, allocated);
                qdf_print("%s: VAP Mcast to Unicast buffer release (cmd): %u\n", __func__, allocated);
            }

            vap->iv_me->mc_mcast_enable = val;
	    retval = ol_ath_wmi_send_vdev_param(scn,avn->av_if_id,
			    wmi_vdev_param_mcast2ucast_set, !!val);

            retval = ol_ath_pdev_set_param(scn,
				    wmi_pdev_param_set_mcast2ucast_mode, val, 0);
	    qdf_print("%s: VAP param is now supported param:%u value:%u\n", __func__, param, val);
	}
#else
    {
        if( val != 0 ) {
            ol_tx_me_alloc_descriptor(scn->pdev_txrx_handle);
        } else {
            vap->iv_me->mc_mcast_enable = 0;
	    ol_tx_me_free_descriptor(scn->pdev_txrx_handle);
        }
#if ATH_MCAST_HOST_INSPECT
        retval = ol_ath_wmi_send_vdev_param(scn,avn->av_if_id,
                                      wmi_vdev_param_mcast_indicate, val);
#endif/*ATH_MCAST_HOST_INSPECT*/
    }
#endif /*ATH_SUPPORT_ME_FW_BASED*/
	break;
#endif /* ATH_SUPPORT_IQUE */

	case IEEE80211_FEATURE_AMPDU:
    {
        /*
         * Disable or Enable with size limits A-MPDU per VDEV per AC
         * bits 7:0 -> Access Category (0x0=BE, 0x1=BK, 0x2=VI, 0x3=VO, 0xFF=All AC)
         * bits 31:8 -> Max number of subframes
         *
         * If the size is zero, A-MPDU is disabled for the VAP for the given AC.
         * Else, A-MPDU is enabled for the VAP for the given AC, but is limited
         * to the specified max number of sub frames.
         *
         * If Access Category is 0xff, the specified max number of subframes will
         * be applied for all the Access Categories. If not, max subframes
         * have to be applied per AC.
         *
         * This is only for TX subframe size. In RX path this new VDEV param shall
         * only be used to check, wherever needed, to see if AMPDU is enabled or
         * disabled for a given VAP.
         */

        uint32_t ampdu_param;
        ampdu_param = (val << 8) + 0xFF;
        //WMI_VDEV_PARAM_AC_SET(ampdu_param, 0xFF);
        //WMI_VDEV_PARAM_MAX_SUBFRM_SET(ampdu_param, val);
        ol_ath_wmi_send_vdev_param(scn, avn->av_if_id,
                wmi_vdev_param_ampdu_subframe_size_per_ac, ampdu_param);
    }
    break;
        case IEEE80211_ENABLE_RTSCTS:
             ol_ath_wmi_send_vdev_param(scn, avn->av_if_id,
                     wmi_vdev_param_enable_rtscts, val);
        break;
        case IEEE80211_RC_NUM_RETRIES:
            ol_ath_wmi_send_vdev_param( scn, avn->av_if_id,
                    wmi_vdev_param_rc_num_retries, vap->iv_rc_num_retries);
        break;
#if WDS_VENDOR_EXTENSION
        case IEEE80211_WDS_RX_POLICY:
            if ((ieee80211vap_get_opmode(vap) == IEEE80211_M_HOSTAP) ||
                (ieee80211vap_get_opmode(vap) == IEEE80211_M_STA)) {
                ol_txrx_set_wds_rx_policy(vap->iv_txrx_handle, val & WDS_POLICY_RX_MASK);
            }
        break;
#endif
        case IEEE80211_FEATURE_HIDE_SSID:
             if(val) {
                 if(!IEEE80211_VAP_IS_HIDESSID_ENABLED(vap)) {
                     IEEE80211_VAP_HIDESSID_ENABLE(vap);
                 }
             } else {
                 if(IEEE80211_VAP_IS_HIDESSID_ENABLED(vap)) {
                     IEEE80211_VAP_HIDESSID_DISABLE(vap);
                 }
             }
             retval = 0;
             break;
        case IEEE80211_FEATURE_PRIVACY:
             if(val) {
                 if(!IEEE80211_VAP_IS_PRIVACY_ENABLED(vap)) {
                     IEEE80211_VAP_PRIVACY_ENABLE(vap);
                 }
             } else {
                 if(IEEE80211_VAP_IS_PRIVACY_ENABLED(vap)) {
                     IEEE80211_VAP_PRIVACY_DISABLE(vap);
                 }
             }
             retval = 0;
             break;
        case IEEE80211_FEATURE_DROP_UNENC:
             if(val) {
                if(!IEEE80211_VAP_IS_DROP_UNENC(vap)) {
                    IEEE80211_VAP_DROP_UNENC_ENABLE(vap);
                }
             } else {
                if(IEEE80211_VAP_IS_DROP_UNENC(vap)) {
                    IEEE80211_VAP_DROP_UNENC_DISABLE(vap);
                }
             }
             ic->ic_set_dropunenc(vap, val);
             retval = 0;
             break;
        case IEEE80211_SHORT_PREAMBLE:
             if(val) {
                 if(!IEEE80211_IS_SHPREAMBLE_ENABLED(ic)) {
                     IEEE80211_ENABLE_SHPREAMBLE(ic);
                 }
             } else {
                 if(IEEE80211_IS_SHPREAMBLE_ENABLED(ic)) {
                     IEEE80211_DISABLE_SHPREAMBLE(ic);
                 }
             }
             ol_ath_wmi_send_vdev_param(scn, avn->av_if_id,
                    wmi_vdev_param_preamble,
                    (val) ? WMI_HOST_VDEV_PREAMBLE_SHORT : WMI_HOST_VDEV_PREAMBLE_LONG);
             retval = 0;
             break;
        case IEEE80211_PROTECTION_MODE:
            if(val)
                IEEE80211_ENABLE_PROTECTION(ic);
            else
                IEEE80211_DISABLE_PROTECTION(ic);
            ic->ic_protmode = val;
            ic->ic_update_protmode(ic);
            retval = 0;
            break;
        case IEEE80211_SHORT_SLOT:
            if (val) {
                ieee80211_set_shortslottime(ic, 1);
            } else {
                ieee80211_set_shortslottime(ic, 0);
            }
            retval = 0;
            break;

        case IEEE80211_SET_CABQ_MAXDUR:
            ol_ath_wmi_send_vdev_param(scn, avn->av_if_id,
                    wmi_vdev_param_cabq_maxdur, val);
        break;

        case IEEE80211_FEATURE_MFP_TEST:
            ol_ath_wmi_send_vdev_param(scn, avn->av_if_id,
                    wmi_vdev_param_mfptest_set, val);
        break;

        case IEEE80211_VHT_SGIMASK:
             ol_ath_wmi_send_vdev_param(scn, avn->av_if_id,
                         wmi_vdev_param_vht_sgimask, val);
        break;

        case IEEE80211_VHT80_RATEMASK:
             ol_ath_wmi_send_vdev_param(scn, avn->av_if_id,
                         wmi_vdev_param_vht80_ratemask, val);
        break;

        case IEEE80211_VAP_RX_DECAP_TYPE:
        {
            enum htt_pkt_type pkt_type;

            if (!ol_ath_validate_rx_decap_type(scn, vap, val)) {
                retval = EINVAL;
            } else {
                retval = ol_ath_wmi_send_vdev_param(scn,
                            avn->av_if_id,
                            wmi_vdev_param_rx_decap_type, val);

                if (retval == 0) {
                    vap->iv_rx_decap_type = val;

                    if(val == 0) {
                        pkt_type = htt_pkt_type_raw;
                        qdf_print("Setting Rx Decap type to 0 (Raw)\n");
                    } else if(val == 1) {
                        pkt_type = htt_pkt_type_native_wifi;
                        qdf_print("Setting Rx Decap type to 1 (Native Wi-Fi)\n");
                    } else {
                        pkt_type = htt_pkt_type_ethernet;
                        qdf_print("Setting Rx Decap type to 2 (Ethernet)\n");
                    }

                    ol_txrx_set_vdev_rx_decap_type(vap->iv_txrx_handle, pkt_type);
               } else
                    qdf_print("Error %d setting param "
                           "WMI_VDEV_PARAM_RX_DECAP_TYPE with val %u\n",
                           retval,
                           val);
                }
        }
        break;

        case IEEE80211_VAP_TX_ENCAP_TYPE:
        {
            enum htt_pkt_type pkt_type;

            if (!ol_ath_validate_tx_encap_type(scn, vap, val)) {
                retval = EINVAL;
            } else {
                retval = ol_ath_wmi_send_vdev_param(scn,
                            avn->av_if_id,
                            wmi_vdev_param_tx_encap_type, val);

                if (retval == 0) {
                    vap->iv_tx_encap_type = val;

                    if (val == 0) {
                        pkt_type = htt_pkt_type_raw;
                        qdf_print("Setting Tx Encap type to 0 (Raw)\n");
                    } else if (val == 1) {
                        pkt_type = htt_pkt_type_native_wifi;
                        qdf_print("Setting Tx Encap type to 1 (Native Wi-Fi)\n");
                    } else {
                        pkt_type = htt_pkt_type_ethernet;
                        qdf_print("Setting Tx Encap type to 2 (Ethernet)\n");
                    }

                    ol_txrx_set_tx_encap_type(vap->iv_txrx_handle, pkt_type);
                } else {
                    qdf_print("Error %d setting param "
                           "WMI_VDEV_PARAM_TX_ENCAP_TYPE with val %u\n",
                           retval,
                           val);
                }
            }
        }
        break;

        case IEEE80211_BW_NSS_RATEMASK:
             ol_ath_wmi_send_vdev_param(scn, avn->av_if_id,
                         wmi_vdev_param_bw_nss_ratemask, val);
        break;

        case IEEE80211_RX_FILTER_MONITOR:
             if(ic->ic_is_mode_offload(ic)) {
                 ol_txrx_monitor_set_filter_ucast_data(scn->pdev_txrx_handle,
                                          ic->mon_filter_ucast_data);
                 ol_txrx_monitor_set_filter_mcast_data(scn->pdev_txrx_handle,
                                          ic->mon_filter_mcast_data);
                 ol_txrx_monitor_set_filter_non_data(scn->pdev_txrx_handle,
                                          ic->mon_filter_non_data);
             }
        break;

#if ATH_SUPPORT_NAC
        case IEEE80211_RX_FILTER_NEIGHBOUR_PEERS_MONITOR:
            ol_txrx_set_filter_neighbour_peers(scn->pdev_txrx_handle, val);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            osif_nss_ol_set_cfg(scn->pdev_txrx_handle, OSIF_NSS_WIFI_FILTER_NEIGH_PEERS_CMD);
#endif
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_NAC, "%s: Monitor Invalid Peers Filter Set Val=%d \n", __func__, val);
        break;
#endif
	case IEEE80211_TXRX_VAP_STATS:
        {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Get vap stats\n");
            ol_ath_net80211_get_vap_stats(vap);
            break;
        }
#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
    case IEEE80211_CLR_RAWMODE_PKT_SIM_STATS:
	ol_txrx_clear_rawmode_pkt_sim_stats(vap->iv_txrx_handle);
	break;
#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */
    case IEEE80211_TXRX_DBG_SET:
	ol_txrx_debug(vap->iv_txrx_handle, val);
        break;
    case IEEE80211_PEER_MUMIMO_TX_COUNT_RESET_SET:
        if (val <= 0) {
            qdf_print("Invalid AID value.\n");
            return -EINVAL;
        }
        retval = ol_ath_ucfg_reset_peer_mumimo_tx_count(vap, val);
        break;
#if defined(TEMP_AGGR_CFG)
    case IEEE80211_AMSDU_SET:
        {
            /* configure the max amsdu subframes */
            if (val >= 0 && val < 32) {
                u_int32_t amsdu_param;
                vap->iv_vht_amsdu = val;
            /* Default as of now: All AC (0x0=BE, 0x1=BK, 0x2=VI, 0x3=VO, 0xFF-All AC) */
                amsdu_param = (val << 8) + 0xFF;
                retval = ol_ath_wmi_send_vdev_param(scn, avn->av_if_id,
                                   wmi_vdev_param_amsdu_subframe_size_per_ac, amsdu_param);
            } else {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
                                           KERN_ERR "### failed to enable or disable AMSDU\n");
                retval = -EINVAL;
            }
        }
        break;
#endif /* defined(TEMP_AGGR_CFG) */
    case IEEE80211_TX_PPDU_LOG_CFG_SET:
        ol_txrx_fw_stats_cfg(vap->iv_txrx_handle, HTT_DBG_STATS_TX_PPDU_LOG, val);
        break;
    case IEEE80211_TXRX_FW_STATS:
        {
            struct ol_txrx_stats_req req = {0};
            wlan_dev_t ic = vap->iv_ic;
            struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
            osif_dev  *osifp = (osif_dev *)vap->iv_ifp;
            if ((osifp->is_ar900b == false) && (val > TXRX_FW_STATS_VOW_UMAC_COUNTER)) { /*Dont pass to avoid TA */
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Not supported.\n");
                return -EINVAL;
            }
#if ATH_PERF_PWR_OFFLOAD
            if (!vap->iv_txrx_handle)
                break;
#endif

            req.print.verbose = 1; /* default */

            /*
             * Backwards compatibility: use the same old input values, but
             * translate from the old values to the corresponding new bitmask
             * value.
             */
            if (val <= TXRX_FW_STATS_RX_RATE_INFO) {
                req.stats_type_upload_mask = 1 << (val - 1);
                if (val == TXRX_FW_STATS_TXSTATS) {
                    /* mask 17th bit as well to get extended tx stats */
                    req.stats_type_upload_mask |= (1 << 17);
                }
            } else if (val == TXRX_FW_STATS_PHYSTATS) {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Value 4 for txrx_fw_stats is obsolete \n");
                break;
            } else if (val == TXRX_FW_STATS_PHYSTATS_CONCISE) {
                /*
                 * Stats request 5 is the same as stats request 4,
                 * but with only a concise printout.
                 */
                req.print.concise = 1;
                req.stats_type_upload_mask = 1 << (TXRX_FW_STATS_PHYSTATS - 1);
            }
            else if (val == TXRX_FW_STATS_TX_RATE_INFO) {
                req.stats_type_upload_mask = 1 << (TXRX_FW_STATS_TX_RATE_INFO - 2);
            }
            else if (val == TXRX_FW_STATS_TID_STATE) { /* for TID queue stats*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_STATS_TID_STATE - 2);
            }
            else if (val == TXRX_FW_STATS_TXBF_INFO) { /* for TxBF stats*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_STATS_TXBF_INFO - 7);
            }
            else if (val == TXRX_FW_STATS_SND_INFO) { /* for TxBF Snd stats*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_STATS_SND_INFO - 7);
            }
            else if (val == TXRX_FW_STATS_ERROR_INFO) { /* for TxRx error stats*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_STATS_ERROR_INFO - 7);
            }
            else if (val == TXRX_FW_STATS_TX_SELFGEN_INFO) { /* for SelfGen stats*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_STATS_TX_SELFGEN_INFO - 7);
            }
            else if (val == TXRX_FW_STATS_TX_MU_INFO) { /* for TX MU stats*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_STATS_TX_MU_INFO - 7);
            }
            else if (val == TXRX_FW_SIFS_RESP_INFO) { /* for SIFS RESP stats*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_SIFS_RESP_INFO - 7);
            }
            else if (val == TXRX_FW_RESET_STATS) { /*for  Reset stats info*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_RESET_STATS - 7);
            }
            else if (val == TXRX_FW_MAC_WDOG_STATS) { /*for  wdog stats info*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_MAC_WDOG_STATS - 7);
            }
            else if (val == TXRX_FW_MAC_DESC_STATS) { /*for fw desc stats*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_MAC_DESC_STATS - 7);
            }
            else if (val == TXRX_FW_MAC_FETCH_MGR_STATS) { /*for fetch mgr stats*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_MAC_FETCH_MGR_STATS - 7);
            }
            else if (val == TXRX_FW_MAC_PREFETCH_MGR_STATS) { /*for prefetch mgr stats*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_MAC_PREFETCH_MGR_STATS - 7);
            }
            else if (val == TXRX_FW_HALPHY_STATS) { /*for fetch halphy stats*/
                req.stats_type_upload_mask = 1 << (TXRX_FW_HALPHY_STATS - 8);
            }


#if WLAN_FEATURE_FASTPATH
            /* Get some host stats */
            /* Piggy back on to fw stats command */
            /* TODO : Separate host / fw commands out */
            if (val == TXRX_FW_STATS_HOST_STATS) {
                ol_txrx_host_stats_get(vap->iv_txrx_handle, &req);
            } else if (val == TXRX_FW_STATS_CLEAR_HOST_STATS) {
                ol_txrx_host_stats_clr(vap->iv_txrx_handle);
            } else if (val == TXRX_FW_STATS_CE_STATS) {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Value 10 for txrx_fw_stats is obsolete \n");
                break;
#if ATH_SUPPORT_IQUE
            } else if (val == TXRX_FW_STATS_ME_STATS) {
                ol_txrx_host_me_stats(vap->iv_txrx_handle);
#endif

            } else if (val <= TXRX_FW_MAC_PREFETCH_MGR_STATS || val == TXRX_FW_HALPHY_STATS)
#endif /* WLAN_FEATURE_FASTPATH */
                {
                    ol_txrx_fw_stats_get(vap->iv_txrx_handle, &req, PER_RADIO_FW_STATS_REQUEST, 0);
#if PEER_FLOW_CONTROL
                    /* MSDU TTL host display */
                    if(val == 1) {
                        ol_txrx_host_msdu_ttl_stats(vap->iv_txrx_handle, &req);
                    }
#endif
                }

            if (val == TXRX_FW_STATS_DURATION_INFO) {
               scn->tx_rx_time_info_flag = 1;
               ic->ic_ath_bss_chan_info_stats(ic, 1);
               break;
            }

            if (val == TXRX_FW_STATS_DURATION_INFO_RESET) {
               scn->tx_rx_time_info_flag = 1;
               ic->ic_ath_bss_chan_info_stats(ic, 2);
               break;
            }

#if UMAC_SUPPORT_VI_DBG
            if( osifp->vi_dbg) {
                if(val == TXRX_FW_STATS_VOW_UMAC_COUNTER)
                    {
                        ieee80211_vi_dbg_print_stats(vap);
                    }
            }
#elif UMAC_VOW_DEBUG

            if( osifp->vow_dbg_en) {
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
                osif_nss_vdev_get_vow_dbg_stats(vap->iv_txrx_handle);
#endif
                if(val == TXRX_FW_STATS_RXSTATS)
                    {
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %lu VI/mpeg streamer pkt Count recieved at umac\n", osifp->umac_vow_counter);
                    }
                else if( val == TXRX_FW_STATS_VOW_UMAC_COUNTER ) {

                    for( ii = 0; ii < MAX_VOW_CLIENTS_DBG_MONITOR; ii++ )
                        {
                            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %lu VI/mpeg stream pkt txed at umac for peer %d[%02X:%02X]\n",
                                   osifp->tx_dbg_vow_counter[ii], ii, osifp->tx_dbg_vow_peer[ii][0], osifp->tx_dbg_vow_peer[ii][1]);
                        }

                }
            }
#endif
            break;
        }
    case IEEE80211_PEER_TX_COUNT_SET:
        if (val <= 0){
            qdf_print("Invalid AID value.\n");
            return -EINVAL;
	}
	    retval = wlan_get_peer_mumimo_tx_count(vap, val);
	    break;
    case IEEE80211_CTSPROT_DTIM_BCN_SET:
	    ol_ath_set_vap_cts2self_prot_dtim_bcn(vap);
	    break;
    case IEEE80211_PEER_POSITION_SET:
	    if (val <= 0) {
            qdf_print("Invalid AID value.\n");
            return -EINVAL;
        }
	    retval = wlan_get_user_postion(vap, (u_int32_t)val);
	    break;
    case IEEE80211_VAP_TXRX_FW_STATS:
    {
        struct ol_txrx_stats_req req = {0};
        osif_dev  *osifp = (osif_dev *)vap->iv_ifp;
        if ((osifp->is_ar900b == false) && (val > TXRX_FW_STATS_VOW_UMAC_COUNTER)) { /* Wlan F/W doesnt like this */
              qdf_print("Not supported.\n");
              return -EINVAL;
        }
#if ATH_PERF_PWR_OFFLOAD
        if (!vap->iv_txrx_handle)
            return -EINVAL;
#endif
        req.print.verbose = 1; /* default */
        if (val == TXRX_FW_STATS_SND_INFO) { /* for TxBF Snd stats*/
            req.stats_type_upload_mask = 1 << (TXRX_FW_STATS_SND_INFO - 7);
        } else if (val == TXRX_FW_STATS_TX_SELFGEN_INFO) { /* for SelfGen stats*/
            req.stats_type_upload_mask = 1 << (TXRX_FW_STATS_TX_SELFGEN_INFO - 7);
        } else if (val == TXRX_FW_STATS_TX_MU_INFO) { /* for TX MU stats*/
            req.stats_type_upload_mask = 1 << (TXRX_FW_STATS_TX_MU_INFO - 7);
        } else {
            /*
             * The command iwpriv athN vap_txrx_stats is used to get per vap
             * sounding info, selfgen info and tx mu stats only.
             */
            qdf_print("Vap specific stats is implemented only for stats type 14 16 and 17\n");
            return -EINVAL;
        }
        ol_txrx_fw_stats_get(vap->iv_txrx_handle, &req, PER_VDEV_FW_STATS_REQUEST, 0);
    break;
    }
    case IEEE80211_TXRX_FW_MSTATS:
    {
        struct ol_txrx_stats_req req = {0};
        req.print.verbose = 1;
        req.stats_type_upload_mask = val;
        ol_txrx_fw_stats_get(vap->iv_txrx_handle, &req, PER_RADIO_FW_STATS_REQUEST, 0);
        break;
    }

   case IEEE80211_VAP_TXRX_FW_STATS_RESET:
    {
        struct ol_txrx_stats_req req = {0};
#if UMAC_VOW_DEBUG
        osif_dev  *osifp = (osif_dev *)vap->iv_ifp;
#endif
        if (val == TXRX_FW_STATS_SND_INFO) { /* for TxBF Snd stats*/
            req.stats_type_reset_mask = 1 << (TXRX_FW_STATS_SND_INFO - 7);
        } else if (val == TXRX_FW_STATS_TX_SELFGEN_INFO) { /* for SelfGen stats*/
            req.stats_type_reset_mask = 1 << (TXRX_FW_STATS_TX_SELFGEN_INFO - 7);
        } else if (val == TXRX_FW_STATS_TX_MU_INFO) { /* for TX MU stats*/
            req.stats_type_reset_mask = 1 << (TXRX_FW_STATS_TX_MU_INFO - 7);
        } else {
            /*
             * The command iwpriv athN vap_txrx_st_rst is used to reset per vap
             * sounding info, selfgen info and tx mu stats only.
             */
            qdf_print("Vap specific stats reset is implemented only for stats type 14 16 and 17\n");
            return -EINVAL;
        }
        ol_txrx_fw_stats_get(vap->iv_txrx_handle, &req, PER_VDEV_FW_STATS_REQUEST, 0);
#if UMAC_VOW_DEBUG
        if(osifp->vow_dbg_en)
        {
            for( ii = 0; ii < MAX_VOW_CLIENTS_DBG_MONITOR; ii++ )
            {
                 osifp->tx_dbg_vow_counter[ii] = 0;
            }
            osifp->umac_vow_counter = 0;
        }
#endif
        break;
    }

    case IEEE80211_TXRX_FW_STATS_RESET:
    {
        struct ol_txrx_stats_req req = {0};
#if UMAC_VOW_DEBUG
        osif_dev  *osifp = (osif_dev *)vap->iv_ifp;
#endif
        req.stats_type_reset_mask = val;
        ol_txrx_fw_stats_get(vap->iv_txrx_handle, &req, PER_RADIO_FW_STATS_REQUEST, 0);
#if UMAC_VOW_DEBUG
        if(osifp->vow_dbg_en)
        {
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            osif_nss_ol_vdev_set_cfg(vap->iv_txrx_handle, OSIF_NSS_WIFI_VDEV_VOW_DBG_RST_STATS);
#endif
            for( ii = 0; ii < MAX_VOW_CLIENTS_DBG_MONITOR; ii++ )
            {
                 osifp->tx_dbg_vow_counter[ii] = 0;
            }
            osifp->umac_vow_counter = 0;

        }
#endif
        break;
    }
#if ATH_SUPPORT_DSCP_OVERRIDE
    case IEEE80211_DSCP_OVERRIDE:
    {
        if(ic->ic_is_mode_offload(ic)) {
            ol_ath_set_vap_dscp_tid_map(vap);
        }
        break;
    }
#endif /* ATH_SUPPORT_DSCP_OVERRIDE */

    case IEEE80211_CONFIG_VAP_TXPOW_MGMT:
    {
        ol_wlan_txpow_mgmt(vap,(u_int8_t)val);
    }
    break;

    case IEEE80211_CONFIG_TX_CAPTURE:
    {
#if ATH_PERF_PWR_OFFLOAD
        struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
#endif
        retval = ol_ath_set_tx_capture(scn, val);
    }
    break;

    case IEEE80211_FEATURE_DISABLE_CABQ:
        retval = ol_ath_wmi_send_vdev_param(scn,avn->av_if_id, wmi_vdev_param_disable_cabq, val);
    break;

    default:
        /*qdf_print("%s: VAP param unsupported param:%u value:%u\n", __func__,
                     param, val);*/
    break;
    }

    return(retval);
}

static int16_t ol_ath_vap_dyn_bw_rts(struct ieee80211vap *vap, int param)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    int retval = 0;

    retval = ol_ath_wmi_send_vdev_param(scn,avn->av_if_id,
			wmi_vdev_param_disable_dyn_bw_rts, param);
    return retval;
}



/* Vap interface functions */
static int
ol_ath_vap_get_param(struct ieee80211vap *vap,
                              ieee80211_param param)
{
    int retval = 0;

    /* Set the VAP param in the target */
    switch (param) {
        case IEEE80211_RAWMODE_PKT_SIM_STATS:
            ol_txrx_print_rawmode_pkt_sim_stats(vap->iv_txrx_handle);
            break;
#if (HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE)
        case IEEE80211_TSO_STATS_RESET_GET:
            ol_tx_rst_tso_stats(vap->iv_txrx_handle);
            break;

        case IEEE80211_TSO_STATS_GET:
            ol_tx_print_tso_stats(vap->iv_txrx_handle);
            break;
#endif /* HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE */
#if HOST_SW_SG_ENABLE
        case IEEE80211_SG_STATS_GET:
            ol_tx_print_sg_stats(vap->iv_txrx_handle);
            break;
        case IEEE80211_SG_STATS_RESET_GET:
            ol_tx_rst_sg_stats(vap->iv_txrx_handle);
            break;
#endif /* HOST_SW_SG_ENABLE */
#if RX_CHECKSUM_OFFLOAD
        case IEEE80211_RX_CKSUM_ERR_STATS_GET:
            ol_print_rx_cksum_stats(vap->iv_txrx_handle);
	    break;
        case IEEE80211_RX_CKSUM_ERR_RESET_GET:
            ol_rst_rx_cksum_stats(vap->iv_txrx_handle);
            break;
#endif /* RX_CHECKSUM_OFFLOAD */
        case IEEE80211_RX_FILTER_MONITOR:
           retval = ol_txrx_monitor_get_filter_ucast_data(vap->iv_txrx_handle) |
                       ol_txrx_monitor_get_filter_mcast_data(vap->iv_txrx_handle) |
                       ol_txrx_monitor_get_filter_non_data(vap->iv_txrx_handle);
           IEEE80211_DPRINTF_IC(vap->iv_ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_IOCTL,
                     "ucast data filter=%d\n",
                      ol_txrx_monitor_get_filter_ucast_data(vap->iv_txrx_handle));
           IEEE80211_DPRINTF_IC(vap->iv_ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_IOCTL,
                      "mcast data filter=%d\n",
                      ol_txrx_monitor_get_filter_mcast_data(vap->iv_txrx_handle));
           IEEE80211_DPRINTF_IC(vap->iv_ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_IOCTL,
                     "Non data(mgmt/action etc.) filter=%d\n",
                     ol_txrx_monitor_get_filter_non_data(vap->iv_txrx_handle));

        default:
            /*printk("%s: VAP param unsupported param:%u value:%u\n", __func__,
                    param, val);*/
            break;
    }

    return(retval);
}

int
ol_ath_vdev_config_ratemask(struct ol_ath_softc_net80211 *scn, u_int8_t if_id,
                             u_int8_t type, u_int32_t lower32, u_int32_t higher32)
{
    struct config_ratemask_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.vdev_id = if_id;
    param.type = type;
    param.lower32 = lower32;
    param.higher32 = higher32;

    return wmi_unified_vdev_config_ratemask_cmd_send(scn->wmi_handle, &param);
}

static int
ol_ath_vap_set_ratemask(struct ieee80211vap *vap,
            			u_int8_t preamble, u_int32_t mask_lower32, u_int32_t mask_higher32)
{
    /* higher 32 bit is reserved for beeliner*/
    switch (preamble) {
        case 0:
            vap->iv_ratemask_default = 0;
            vap->iv_legacy_ratemasklower32 = mask_lower32;
            break;
        case 1:
            vap->iv_ratemask_default = 0;
            vap->iv_ht_ratemasklower32 = mask_lower32;
            break;
        case 2:
            vap->iv_ratemask_default = 0;
            vap->iv_vht_ratemasklower32 = mask_lower32;
            vap->iv_vht_ratemaskhigher32 = mask_higher32;
            break;
        default:
            return EINVAL;
            break;
    }
    return ENETRESET;
}

int
ol_ath_vdev_install_key_send(struct ol_ath_softc_net80211 *scn, u_int8_t if_id,
                             struct ieee80211_key *ieee_key,
                             u_int8_t macaddr[IEEE80211_ADDR_LEN],
                             u_int8_t def_keyid, u_int8_t force_none)
{
    struct vdev_install_key_params param;
    const struct ieee80211_cipher *ieee_cip = ieee_key->wk_cipher;

    qdf_mem_set(&param, sizeof(param), 0);
    param.wk_keylen = ieee_key->wk_keylen;
    param.ic_cipher = ieee_cip->ic_cipher;
    param.force_none = force_none;
    param.wk_keyix = ieee_key->wk_keyix;
    param.def_keyid = def_keyid;
    param.wk_keyrsc = ieee_key->wk_keyrsc;
    param.wk_keytsc = ieee_key->wk_keytsc;
    param.wk_recviv = ieee_key->wk_recviv;
    param.wk_txiv = ieee_key->wk_txiv;
    param.key_data = ieee_key->wk_key;

    if ((ieee_key->wk_flags & IEEE80211_KEY_SWCRYPT) == 0) {
        param.is_host_based_crypt = FALSE;
    }

    param.if_id = if_id;

    /* Mapping ieee key flags to WMI key flags */
    if(ieee_key->wk_flags & IEEE80211_KEY_GROUP) {
        param.is_group_key = TRUE;
    }

    if(ieee_key->wk_flags & (IEEE80211_KEY_RECV | IEEE80211_KEY_XMIT)) {
        param.is_xmit_or_recv_key = TRUE;
    }

#if 0
    qdf_print("%s Setting Key for Macaddress:0x%x%x \n",__func__,cmd->peer_macaddr.mac_addr47to32,cmd->peer_macaddr.mac_addr31to0);
    qdf_print("Keyix=%d Keylen=%d Keyflags=%x Cipher=%x \n Keydata=",cmd->key_ix,cmd->key_len,cmd->key_flags,cmd->key_cipher);

    for(i=0; i<cmd->key_len; i++)
       qdf_print("0x%x ",cmd->key_data[i]);
       qdf_print("\n");
#endif
    return wmi_unified_vdev_install_key_cmd_send(scn->wmi_handle, macaddr, &param);
}

static int
ol_ath_vap_listen(struct ieee80211vap *vap)
{
    /* Target vdev will be in listen state once it is created
     * No need to send any command to target
     */
    return 0;
}

static int ol_ath_vap_join(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    enum ieee80211_opmode opmode = ieee80211vap_get_opmode(vap);
    struct ieee80211_channel *chan = vap->iv_bsschan;
    u_int32_t freq;

    freq = ieee80211_chan2freq(ic, chan);
    if (!freq) {
        qdf_print("ERROR : INVALID Freq \n");
        return 0;
    }

    if (opmode != IEEE80211_M_STA && opmode != IEEE80211_M_IBSS) {
        /* join operation is only for STA/IBSS mode */
        return 0;
    }

    return 0;
}

/* No Op for Perf offload */
static int ol_ath_vap_dfs_cac(struct ieee80211vap *vap)
{
#if OL_ATH_SUPPORT_LED
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
#if QCA_LTEU_SUPPORT
    if (!scn->lteu_support) {
#endif
#if OL_ATH_SUPPORT_LED_POLL
        if (scn->scn_led_blink_rate_table) {
            OS_SET_TIMER(&scn->scn_led_poll_timer, 500);
        }
#else
        OS_CANCEL_TIMER(&scn->scn_led_blink_timer);
        OS_CANCEL_TIMER(&scn->scn_led_poll_timer);
        scn->scn_blinking = OL_BLINK_ON_START;
        if(scn->target_type == TARGET_TYPE_IPQ4019) {
            ipq4019_wifi_led(scn, LED_OFF);
        } else {
            ol_ath_gpio_output(scn, scn->scn_led_gpio, 0);
        }
        if (scn->scn_led_blink_rate_table) {
            OS_SET_TIMER(&scn->scn_led_blink_timer, 10);
        }
#endif
#if QCA_LTEU_SUPPORT
    }
#endif
#endif /* OL_ATH_SUPPORT_LED */
    return 0;
}

static int ol_ath_root_authorize(struct ieee80211vap *vap, u_int32_t authorize)
{
    struct ol_ath_softc_net80211 *scn = NULL;
    struct ol_ath_vap_net80211 *avn = NULL;
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_node *ni = vap->iv_bss;
    if(!ic || !ni) {
        return -EINVAL;
    }
    scn = OL_ATH_SOFTC_NET80211(ic);
    avn = OL_ATH_VAP_NET80211(ni->ni_vap);

    if(!scn || !avn) {
        return -EINVAL;
    }
    ol_txrx_peer_authorize((OL_ATH_NODE_NET80211(ni)->an_txrx_handle), authorize);
    return ol_ath_node_set_param(scn, ni->ni_macaddr, WMI_HOST_PEER_AUTHORIZE, authorize, avn->av_if_id);
}

enum ieee80211_opmode ieee80211_new_opmode(struct ieee80211vap *vap, bool vap_active);
static int
ol_ath_vap_up(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    enum ieee80211_opmode opmode = ieee80211vap_get_opmode(vap);
    struct ieee80211_node *ni = vap->iv_bss;
    struct vdev_up_params param;
    u_int8_t bssid_null[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    u_int32_t aid = 0;
    u_int32_t value = 0;
    wlan_if_t vaphandle;
    vaphandle = ol_ath_vap_get(scn, avn->av_if_id);

    qdf_mem_set(&param, sizeof(param), 0);
    switch (opmode) {
        case IEEE80211_M_STA:
            ol_ath_vap_set_param(vap, IEEE80211_VHT_SUBFEE, 0);
            /* Send the assoc id, negotiated capabilities & rateset to the target */
            aid = IEEE80211_AID(ni->ni_associd);
            ol_ath_net80211_newassoc(ni, 1);

            /* Set the beacon interval of the bss */
            ol_ath_vap_set_param(vap, IEEE80211_BEACON_INTVAL, ni->ni_intval);

            if (ieee80211_vap_wme_is_set(vap) &&
                    (ni->ni_ext_caps & IEEE80211_NODE_C_UAPSD)) {
                value = 0;
                if (vap->iv_uapsd & WME_CAPINFO_UAPSD_VO) {
                    value |= WMI_HOST_STA_PS_UAPSD_AC3_DELIVERY_EN |
                        WMI_HOST_STA_PS_UAPSD_AC3_TRIGGER_EN;
                }
                if (vap->iv_uapsd & WME_CAPINFO_UAPSD_VI) {
                    value |= WMI_HOST_STA_PS_UAPSD_AC2_DELIVERY_EN |
                        WMI_HOST_STA_PS_UAPSD_AC2_TRIGGER_EN;
                }
                if (vap->iv_uapsd & WME_CAPINFO_UAPSD_BK) {
                    value |= WMI_HOST_STA_PS_UAPSD_AC1_DELIVERY_EN |
                        WMI_HOST_STA_PS_UAPSD_AC1_TRIGGER_EN;
                }
                if (vap->iv_uapsd & WME_CAPINFO_UAPSD_BE) {
                    value |= WMI_HOST_STA_PS_UAPSD_AC0_DELIVERY_EN |
                        WMI_HOST_STA_PS_UAPSD_AC0_TRIGGER_EN;
                }
            }

            (void)wmi_unified_set_sta_ps_param(OL_ATH_VAP_NET80211(vap),
                    WMI_HOST_STA_PS_PARAM_UAPSD, value);
            break;
        case IEEE80211_M_HOSTAP:
        case IEEE80211_M_IBSS:
            if (vap->iv_special_vap_mode) {
                if (ol_txrx_set_monitor_mode(
                            avn->av_txrx_handle)) {
                    qdf_print("Unable to bring up in special vap interface\n");
                    return -1;
                }
                /*Already up, return with correct status*/
                if (vaphandle) {
                    qdf_atomic_set(&(vaphandle->init_in_progress), 0);
                }

                if(!vap->iv_smart_monitor_vap && scn->target_type == TARGET_TYPE_AR9888) {
                    /* Set Rx decap to RAW mode */
                    vap->iv_rx_decap_type = htt_pkt_type_raw;
                    ol_txrx_set_vdev_rx_decap_type(vap->iv_txrx_handle, htt_pkt_type_raw);
                    if (ol_ath_pdev_set_param(scn,
                        wmi_pdev_param_rx_decap_mode, htt_pkt_type_raw, 0) != EOK)
                                qdf_print("Error setting rx decap mode to RAW\n");
                }

                vap->iv_special_vap_is_monitor = 1;
                return 0;
            }

            value = (vap->iv_enable_vsp)?WMI_HOST_VDEV_VOW_ENABLED:0;
#if MESH_MODE_SUPPORT
            /* If this is a mesh vap and Beacon is enabled for it, send WMI capabiltiy to FW to enable Beacon */
            if((vap->iv_mesh_vap_mode) && (vap->iv_mesh_cap & MESH_CAP_BEACON_ENABLED)) {
                qdf_print("%s, Enabling Beacon on Mesh Vap (vdev id: %d)\n", __func__, (OL_ATH_VAP_NET80211(vap))->av_if_id);
                value |= WMI_HOST_VDEV_BEACON_SUPPORT;
            }
#endif

            ol_ath_wmi_send_vdev_param(scn,(OL_ATH_VAP_NET80211(vap))->av_if_id,
						wmi_vdev_param_capabilities, value);
            /* allocate beacon buffer */
            ol_ath_beacon_alloc(ic, avn->av_if_id);
            ol_ath_vap_set_param(vap, IEEE80211_BEACON_INTVAL, ni->ni_intval);
            ol_ath_vap_set_param(vap, IEEE80211_VHT_SUBFEE, 0);

        /*currently ratemask has to be set before vap is up*/
        if (!vap->iv_ratemask_default) {
            /*ratemask higher 32 bit is reserved for beeliner, use 0x0 for peregrine*/
            if (vap->iv_legacy_ratemasklower32 != 0) {
                ol_ath_vdev_config_ratemask(scn, avn->av_if_id, 0,
                                                vap->iv_legacy_ratemasklower32 , 0x0);
            }
            if (vap->iv_ht_ratemasklower32 != 0) {
                ol_ath_vdev_config_ratemask(scn, avn->av_if_id, 1,
                                                vap->iv_ht_ratemasklower32 , 0x0);
            }
            if (vap->iv_vht_ratemasklower32 != 0 || vap->iv_vht_ratemaskhigher32 != 0) {
                ol_ath_vdev_config_ratemask(scn, avn->av_if_id, 2,
                                                  vap->iv_vht_ratemasklower32,
                                                  vap->iv_vht_ratemaskhigher32);
            }
        }

        break;
    case IEEE80211_M_MONITOR:
        if (ol_txrx_set_monitor_mode(
                    avn->av_txrx_handle)) {
            /*Already up, return with correct status*/
            avn->av_restart_in_progress = FALSE;
            if (vaphandle) {
                qdf_atomic_set(&(vaphandle->init_in_progress), 0);
            }
            return -1;
        }
    default:
        break;
    }

    ic->ic_opmode = ieee80211_new_opmode(vap,true);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    osif_nss_ol_vap_up((osif_dev *)vap->iv_ifp);
#endif

    /* bring up vdev in target */
    param.vdev_id = avn->av_if_id;
    param.assoc_id = aid;
    if (wmi_unified_vdev_up_send(scn->wmi_handle,
            ((opmode == IEEE80211_M_MONITOR) ? bssid_null : ni->ni_bssid), &param)) {
        qdf_print("Unable to bring up the interface for ath_dev.\n");
        return -1;
    }
    avn->av_restart_in_progress = FALSE;

    if (vaphandle) {
        qdf_atomic_set(&(vaphandle->init_in_progress), 0);
    }

#if QCA_LTEU_SUPPORT
    if (!scn->lteu_support) {
#endif
#if OL_ATH_SUPPORT_LED
#if OL_ATH_SUPPORT_LED_POLL
        if (scn->scn_led_blink_rate_table) {
            OS_SET_TIMER(&scn->scn_led_poll_timer, 500);
        }
#else
        OS_CANCEL_TIMER(&scn->scn_led_blink_timer);
        OS_CANCEL_TIMER(&scn->scn_led_poll_timer);
        scn->scn_blinking = OL_BLINK_ON_START;
        if(scn->target_type == TARGET_TYPE_IPQ4019) {
            ipq4019_wifi_led(scn, LED_OFF);
        } else {
            ol_ath_gpio_output(scn, scn->scn_led_gpio, 0);
        }
        if (scn->scn_led_blink_rate_table) {
            OS_SET_TIMER(&scn->scn_led_blink_timer, 10);
        }
#endif
#endif /* OL_ATH_SUPPORT_LED */
#if QCA_LTEU_SUPPORT
    }
#endif

    return 0;
}

static int ol_ath_vap_down(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);

    ic->ic_opmode = ieee80211_new_opmode(vap,false);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
     osif_nss_ol_vap_down((osif_dev *)vap->iv_ifp);
#endif

     /* Resetting ol_resmgr_wait and init_in_progress flags */
     /* In vap deletion case, we are not triggering vap_stop */
    avn->av_ol_resmgr_wait = FALSE;
    qdf_atomic_set(&(vap->init_in_progress), 0);

#if ATH_SUPPORT_ZERO_CAC_DFS
    if (ieee80211_vaps_active(ic) == 0) {
        /* Cancel the precac timer */
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_DFS, "%s : %d Cancel the precac timer\n",__func__,__LINE__);
        ieee80211_dfs_cancel_precac_timer(ic);
    }
#endif

    /* bring down vdev in target */
    if (wmi_unified_vdev_down_send(scn->wmi_handle, avn->av_if_id)) {
        qdf_print("Unable to bring down the interface for ath_dev.\n");
        return -1;
    }
    ieee80211_vap_deliver_stop(vap);

    return 0;
}


static int ol_ath_vap_stopping(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    enum ieee80211_opmode opmode = ieee80211vap_get_opmode(vap);
    u_int32_t peer_tid_bitmap = 0xffffffff; /* TBD : fill with all valid TIDs */
    struct ieee80211_node *ni;
    struct peer_flush_params param;

    switch (opmode) {
    case IEEE80211_M_MONITOR:
        ol_txrx_reset_monitor_mode(scn->pdev_txrx_handle);
        break;
    case IEEE80211_M_HOSTAP:
        if (vap->iv_special_vap_mode && vap->iv_special_vap_is_monitor) {
            ol_txrx_reset_monitor_mode(scn->pdev_txrx_handle);
            vap->iv_special_vap_is_monitor = 0;
        }
        if (vap->iv_mu_cap_war.mu_cap_war == 1)
        {
            MU_CAP_WAR *war = &vap->iv_mu_cap_war;
            qdf_spin_lock_bh(&war->iv_mu_cap_lock);
            if (war->iv_mu_timer_state == MU_TIMER_PENDING)
                war->iv_mu_timer_state = MU_TIMER_STOP;
            OS_CANCEL_TIMER(&war->iv_mu_cap_timer);
            qdf_spin_unlock_bh(&war->iv_mu_cap_lock);
        }
        break;
   case IEEE80211_M_STA:
        OS_CANCEL_TIMER(&vap->iv_cswitch_timer);
        OS_CANCEL_TIMER(&vap->iv_disconnect_sta_timer);
        break;
    default:
        break;
    }

    /*Return from here, if VAP init is already in progress*/
    if(qdf_atomic_read(&(vap->init_in_progress)) && !ieee80211_vap_dfswait_is_set(vap)){
        qdf_print("Warning:Stop during VAP Init ! \n");
        return EBUSY;
    }

    spin_lock_dpc(&vap->init_lock);

    /* Interface is brought down, So UMAC is not waiting for
     * target response
     */
    avn->av_ol_resmgr_wait = FALSE;

    /*
     * free any pending nbufs in the flow control queue
     */
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if(!scn->pdev_txrx_handle->nss_wifiol_ctx)
#endif
    {
        ol_tx_flush_buffers(vap->iv_txrx_handle);
    }

    /* Flush all TIDs for bss node - to cleanup
     * pending traffic in bssnode
     */
    ni = ieee80211_ref_bss_node(vap);
    if (ni != NULL) {
        param.peer_tid_bitmap = peer_tid_bitmap;
        param.vdev_id = avn->av_if_id;
        if (wmi_unified_peer_flush_tids_send(scn->wmi_handle,
                    ni->ni_macaddr, &param)) {
            qdf_print("%s : Unable to Flush tids peer in Target \n", __func__);
        }
        ieee80211_free_node(ni);
    }


    /* NOTE: Call the ol_ath_beacon_stop always before sending vdev_stop
     * to Target. ol_ath_beacon_stop puts the beacon buffer to
     * deferred_bcn_list and this beacon buffer gets freed,
     * when stopped event recieved from target. If the ol_ath_beacon_stop
     * called after wmi_unified_vdev_stop_send, then Target could
     * respond with vdev stopped event immidiately and deferred_bcn_list
     * is still be empty and the beacon buffer is not freed.
     */
    ol_ath_beacon_stop(scn, avn);

    /*
     * Start the timer for vap stopped event after ol_ath_beacon_stop
     * puts the beacon buffer in to deferred_bcn_list
     */
    if ((scn->target_status == OL_TRGET_STATUS_EJECT) ||
        (scn->target_status == OL_TRGET_STATUS_RESET)) {
        /* target ejected/reset,  so generate the stopped event */
        ol_ath_vap_stopped_event(avn->av_sc, avn->av_if_id);
        ieee80211_vap_deliver_stop(vap);
        spin_unlock_dpc(&vap->init_lock);
        return 0;
    }

#if QCA_LTEU_SUPPORT
    if (!scn->lteu_support) {
#endif
#if OL_ATH_SUPPORT_LED
        OS_CANCEL_TIMER(&scn->scn_led_blink_timer);
        OS_CANCEL_TIMER(&scn->scn_led_poll_timer);
        scn->scn_blinking = OL_BLINK_STOP;
        if (scn->scn_led_blink_rate_table) {
            OS_SET_TIMER(&scn->scn_led_blink_timer, 10);
        }
#endif
#if QCA_LTEU_SUPPORT
    }
#endif

    /* bring down vdev in target */
    if (wmi_unified_vdev_stop_send(scn->wmi_handle, avn->av_if_id)) {
        qdf_print("Unable to bring up the interface for ath_dev.\n");
        spin_unlock_dpc(&vap->init_lock);
        return -1;
    }

    /* Reset init_in_progress flag, as host is invoking stopping */
    qdf_atomic_set(&(vap->init_in_progress), 0);

    spin_unlock_dpc(&vap->init_lock);

    return 0;
}

static int
ol_ath_key_alloc(struct ieee80211vap *vap, struct ieee80211_key *k)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    if (scn != NULL) {
        if (k->wk_flags & IEEE80211_KEY_GROUP) {
#if 0
            qdf_print(" Group Keyidx set=%d \n ",k - vap->iv_nw_keys);
#endif
            return k - vap->iv_nw_keys;
        }

        /* target handles key index fetch, host
           returns a key index value which is
           always greater than 0-3 (wep index) */

        if(k->wk_keyix == IEEE80211_KEYIX_NONE) {
            k->wk_keyix= IEEE80211_WEP_NKID + 1;
#if 0
            qdf_print(" Unicast Keyidx set=%d \n ",k->wk_keyix);
#endif
            return k->wk_keyix;
        }

    }

    return -1;
}

/* set the key in the target */
static int
ol_ath_key_set(struct ieee80211vap *vap, struct ieee80211_key *k,
                       const u_int8_t peermac[IEEE80211_ADDR_LEN])
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    const struct ieee80211_cipher *cip = k->wk_cipher;
    u_int8_t gmac[IEEE80211_ADDR_LEN];
    int opmode, force_cipher_none = 0;
    u_int8_t def_kid_enable = 0;

    ASSERT(cip != NULL);

    if (cip == NULL)
        return 0;

    if (k->wk_keyix == IEEE80211_KEYIX_NONE) {
        qdf_print("%s Not setting Key, keyidx=%u \n",__func__,k->wk_keyix);
        return 0;
    }

    IEEE80211_ADDR_COPY(gmac, peermac);

    opmode = ieee80211vap_get_opmode(vap);

    if (k->wk_flags & IEEE80211_KEY_GROUP) {

        switch (opmode) {

        case IEEE80211_M_STA:
#if ATH_SUPPORT_WRAP
            if (avn->av_is_psta && !(avn->av_is_mpsta)){
                qdf_print("%s:Ignore set group key for psta\n",__func__);
                return 1;
            }
#endif
            /* Setting the multicast key in sta bss (AP) peer entry */
            if (IEEE80211_IS_BROADCAST(gmac)) {
                IEEE80211_ADDR_COPY(gmac,&(vap->iv_bss->ni_macaddr));
            }
            break;

        case IEEE80211_M_HOSTAP:
             /* Setting the multicast key in self i.e AP peer entry */
            IEEE80211_ADDR_COPY(gmac,&vap->iv_myaddr);
            break;
        }

    }
    /* If the key id matches with default tx keyid or privacy is not enabled
     * (First key to be loaded) Then consider this key as the default tx key
     */
    if((cip->ic_cipher == IEEE80211_CIPHER_WEP) &&
           ((vap->iv_def_txkey == k->wk_keyix)
                  || (wlan_get_param(vap,IEEE80211_FEATURE_PRIVACY) == 0)))
    {
       def_kid_enable = 1;
    }
    /* Force Cipher to NONE if the vap is configured in RAW mode with cipher as
     * dynamic WEP. For dynamic WEP, null/dummy keys are to be plumbed into the
     * firmware with cipher set to NONE
     */
    if (k->wk_flags & IEEE80211_KEY_DUMMY) {
        force_cipher_none = 1;
    }
   /* send the key to wmi layer  */
   if (ol_ath_vdev_install_key_send(scn, avn->av_if_id, k, gmac, def_kid_enable,0)) {
       qdf_print("Unable to send the key to target \n");
       return -1;
   }
   /* assuming wmi will be always success */
   return 1;
}

static int
ol_ath_key_delete(struct ieee80211vap *vap, const struct ieee80211_key *k,
                  struct ieee80211_node *ni)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    struct ieee80211_key tmp_key;
    u_int8_t gmac[IEEE80211_ADDR_LEN];

    if (k->wk_keyix == IEEE80211_KEYIX_NONE) {
        qdf_print("%s: Not deleting key, keyidx=%u \n",__func__,k->wk_keyix);
        return 0;
    }

    memset(&tmp_key,0,sizeof(struct ieee80211_key));
    tmp_key.wk_valid = k->wk_valid;
    tmp_key.wk_flags = k->wk_flags;
    tmp_key.wk_keyix = k->wk_keyix;
    tmp_key.wk_cipher = k->wk_cipher;
    tmp_key.wk_private = k->wk_private;
    tmp_key.wk_clearkeyix = k->wk_clearkeyix;
    tmp_key.wk_keylen=k->wk_keylen;

    if (ni == NULL) {
        IEEE80211_ADDR_COPY(gmac,&(vap->iv_myaddr));
    } else{
        IEEE80211_ADDR_COPY(gmac, &(ni->ni_macaddr));
    }

    /* send the key to wmi layer  */
    if (ol_ath_vdev_install_key_send(scn, avn->av_if_id, (struct ieee80211_key*)(&tmp_key), gmac, 0, 1)) {
       qdf_print("Unable to send the key to target\n");
       return -1;
    }

    /* assuming wmi will be always success */
    return 1;
}


/* Vdev event handlers from target */
static int
ol_ath_vap_stopped_event(struct ol_ath_softc_net80211 *scn, u_int8_t if_id)
{
    /* Free the beacon buffer */
    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211vap *vap;

    vap = ol_ath_vap_get(scn, if_id);
    ol_ath_beacon_free(ic, if_id);

    if(vap)
    {
        ieee80211_bsteering_send_vap_stop_event(vap);
    }
    return 0;
}

#if ATH_SUPPORT_ME_FW_BASED
/* WMI Mcast buffer release Event APIs */
static int
ol_ath_mcast_buf_release_handler(ol_scn_t scn, u_int8_t *data, u_int16_t datalen)
{
#define FW_RESERVE_DESC 16
    struct ieee80211com *ic = (struct ieee80211com *) &scn->sc_ic;
    struct ol_txrx_pdev_t *pdev = scn->pdev_txrx_handle;
    u_int16_t released, allocated;
    wmi_mcast_buf_release_event *ev = (wmi_mcast_buf_release_event *)data;

    /*Get the current allocated count*/
    allocated = ol_tx_get_mcast_buf_allocated_marked(scn->pdev_txrx_handle);
    /*Target gives current count after decreasing the released count*/
    released = allocated - ((u_int16_t)ev->max_tgt_msdu_cloned - FW_RESERVE_DESC);
    /* Free the Mcast buffers allocated for target */
    released = ol_tx_desc_free_and_unmark_for_mcast_clone(pdev, released);

    scn->pend_desc_removal -= released;
    if(scn->pend_desc_addition) {
        u_int16_t pend_desc_to_alloc = scn->pend_desc_addition;
        scn->pend_desc_addition = 0;
        ic->ic_desc_alloc_and_mark_for_mcast_clone(ic, pend_desc_to_alloc);
    }
    qdf_print("%s: VAP Mcast to Unicast buffer released:%u\n", __func__, released);

    return 0;
}
#endif /*ATH_SUPPORT_ME_FW_BASED*/

/* WMI event handler functions */
static int
ol_ath_vdev_stopped_event_handler(ol_scn_t scn,
                                       u_int8_t *data, u_int16_t datalen)
{
    struct ieee80211com *ic = &scn->sc_ic;
    uint32_t vdev_id;

    if (wmi_extract_vdev_stopped_param(scn->wmi_handle, data, &vdev_id)) {
        qdf_print("Failed to extract vdev stopped param\n");
        return -1;
    }

    if (!ic->ic_nl_handle) {
        qdf_print("STOPPED EVENT for vap %d (%p)\n",vdev_id, scn->wmi_handle);
    }

    return ol_ath_vap_stopped_event(scn, vdev_id);
}

/* WMI event handler for Roam events */
static int
ol_ath_vdev_roam_event_handler(
    ol_scn_t scn, u_int8_t *data, u_int16_t datalen)
{
    wmi_host_roam_event evt;
    struct ieee80211vap *vap;

    if(wmi_extract_vdev_roam_param(scn->wmi_handle, data, &evt)) {
        return -1;
    }
    vap = ol_ath_vap_get(scn, evt.vdev_id);
    if (vap) {
        switch (evt.reason) {
            case WMI_HOST_ROAM_REASON_BMISS:
                ASSERT(vap->iv_opmode == IEEE80211_M_STA);
                ieee80211_mlme_sta_bmiss_ind(vap);
                break;
            case WMI_HOST_ROAM_REASON_BETTER_AP:
                /* FIX THIS */
            default:
                break;
        }
    }

    return 0;
}

/* Device Interface functions */
static void ol_ath_vap_iter_vap_create(void *arg, wlan_if_t vap)
{

    struct ieee80211com *ic = vap->iv_ic;
    u_int32_t *pid_mask = (u_int32_t *) arg;
    u_int8_t myaddr[IEEE80211_ADDR_LEN];
    u_int8_t id = 0;
#if ATH_SUPPORT_WRAP
    /* Proxy STA VAP has its own mac address */
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    if (avn->av_is_psta)
        return;
#endif
    ieee80211vap_get_macaddr(vap, myaddr);
    ATH_GET_VAP_ID(myaddr, ic->ic_myaddr, id);
    (*pid_mask) |= (1 << id);
}

void *ol_ath_vap_get_ol_data_handle(struct ieee80211vap *vap)
{
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    return (void *) avn->av_txrx_handle;
}

#if ATH_SUPPORT_NAC
int
ol_ath_neighbour_rx(struct ieee80211vap *vap, u_int32_t idx,
                   enum ieee80211_nac_param nac_cmd , enum ieee80211_nac_mactype nac_type ,
                   u_int8_t macaddr[IEEE80211_ADDR_LEN])
{

    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    u_int32_t action = nac_cmd;
    u_int32_t type = nac_type;
    struct set_neighbour_rx_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.vdev_id = avn->av_if_id;
    param.idx = idx;
    param.action = action;
    param.type = type;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_NAC,
            "%s :vdev =%x, idx=%x, action=%x, macaddr[0][5]=%2x%2x",
            __func__, param.vdev_id, idx, action, macaddr[0],macaddr[5]);

    if(wmi_unified_vdev_set_neighbour_rx_cmd_send(scn->wmi_handle, macaddr, &param)) {
        qdf_print("Unable to send neighbor rx command to target\n");
        return -1;
    }

    /* assuming wmi will be always success */
    return 1;
}
#endif
#if ATH_SUPPORT_WRAP
static inline int ol_ath_get_qwrap_num_vdevs(struct ol_ath_softc_net80211 *scn)
{
    if (qwrap_enable){
        if (scn->target_type == TARGET_TYPE_AR9888)
            return CFG_TGT_NUM_WRAP_VDEV_AR988X;
        else if (scn->target_type == TARGET_TYPE_QCA9984)
            return CFG_TGT_NUM_WRAP_VDEV_QCA9984;
        else if (scn->target_type == TARGET_TYPE_IPQ4019)
            return CFG_TGT_NUM_WRAP_VDEV_IPQ4019;
        else
            return CFG_TGT_NUM_WRAP_VDEV_AR900B;

    } else {
        if (scn->target_type == TARGET_TYPE_QCA9984) {
            return CFG_TGT_NUM_VDEV_AR900B;
        } else if (scn->target_type == TARGET_TYPE_IPQ4019) {
            return CFG_TGT_NUM_VDEV_AR900B;
        } else if (scn->target_type == TARGET_TYPE_AR900B) {
            return CFG_TGT_NUM_VDEV_AR900B;
        } else if (scn->target_type == TARGET_TYPE_QCA9888) {
            return CFG_TGT_NUM_VDEV_AR900B;
        } else {
            return CFG_TGT_NUM_VDEV_AR988X;
        }
    }
}
#endif

wlan_if_t osif_get_vap(osif_dev *osifp);
/*
 * VAP create
 */
static struct ieee80211vap *
ol_ath_vap_create(struct ieee80211com *ic,
                  int                 opmode,
                  int                 scan_priority_base,
                  int                 flags,
                  const u_int8_t      bssid[IEEE80211_ADDR_LEN],
                  const u_int8_t      mataddr[IEEE80211_ADDR_LEN],
                  void                *osifp_handle)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ieee80211vap *vap = NULL;
    struct ol_ath_vap_net80211* avn = NULL;
    int id = 0;
    u_int16_t type;
    u_int16_t sub_type = 0;
    u_int8_t vap_addr[IEEE80211_ADDR_LEN] = { 0 };
    int nvaps = 0, nactivevaps = 0;
    u_int32_t id_mask = 0;
    enum wlan_op_mode txrx_opmode;
    struct vdev_create_params param;
    u_int32_t retval;
    uint8_t vlimit_exceeded = false;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    int32_t nss_if = -1;
#endif
#if ATH_SUPPORT_WRAP
    int num_vdevs = 0;
#endif
    u_int8_t id_used = 0, tgt_vdev_created = 0;

    if (!(scn->vdev_count) && scn->down_complete) {
        if (ol_ath_target_start(scn)) {
            qdf_print("failed to start the firmware\n");
            return NULL;
        }
    }

    qdf_spin_lock_bh(&scn->scn_lock);
    if (opmode == IEEE80211_M_MONITOR) {
        scn->mon_vdev_count++;
        if (scn->mon_vdev_count > CFG_TGT_MAX_MONITOR_VDEV) {
            qdf_spin_unlock_bh(&scn->scn_lock);
            qdf_print("%s: the ap_monitor vdev count exceeds the supported number %d\n",
                    __func__, CFG_TGT_MAX_MONITOR_VDEV);
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: devhandle (%p) the ap_monitor vdev count exceeds the supported number %d\n",
                    __func__, ic, CFG_TGT_MAX_MONITOR_VDEV);

            goto err_vap_create;
        }
    } else {
        if (scn->special_ap_vap && !(scn->smart_ap_monitor)) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s() devhandle (%p) Radio is configured in Special ap monitor mode we can't create any other vap except 1 stavap or ap smart monitor\n",
                 __func__, ic);
            /* incrementing vdev_count here to sync with error path. It will get decremented before exiting the function */
            scn->vdev_count++;
            qdf_spin_unlock_bh(&scn->scn_lock);
            goto err_vap_create;
        } else {
            if (flags & IEEE80211_SPECIAL_VAP) {

                if ((flags & IEEE80211_SMART_MONITOR_VAP) && !(scn->smart_ap_monitor)) {
                    scn->smart_ap_monitor = 1;
                } else if ((scn->vdev_count != 0) ||(scn->mon_vdev_count != 0) ) {
                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s() devhandle (%p) Already radio having  Normal AP or STA vaps we can't create ap monitor vap\n",
                         __func__, ic);

                    /* incrementing vdev_count here. It will get decremented before exiting the function */
                    scn->vdev_count++;
                    qdf_spin_unlock_bh(&scn->scn_lock);
                    goto err_vap_create;
                }
                scn->special_ap_vap = 1;
            }
        }
        scn->vdev_count++;
    }
    qdf_spin_unlock_bh(&scn->scn_lock);

    /* AR988X supports at max 16 vaps and all these can be in AP mode */
    if (scn->target_type == TARGET_TYPE_AR9888) {
        if ((scn->vdev_count + scn->mon_vdev_count) > scn->wlan_resource_config.num_vdevs) {
            vlimit_exceeded = true;
        }
    } else if (scn->vdev_count > (scn->wlan_resource_config.num_vdevs - CFG_TGT_MAX_MONITOR_VDEV)) {
        vlimit_exceeded = true;
    }

    if (vlimit_exceeded) {
        qdf_print("%s: No more VAP's allowed. vdev_count: %d, mon_vdev_count: %d, num_vdevs: %d\n",
            __func__, scn->vdev_count, scn->mon_vdev_count, scn->wlan_resource_config.num_vdevs);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: No more VAP's allowed. devhandle (%p) scn (%p) vdev_count: %d, mon_vdev_count: %d, num_vdevs: %d\n",
            __func__, ic, scn, scn->vdev_count, scn->mon_vdev_count, scn->wlan_resource_config.num_vdevs);
        goto err_vap_create;
    }

    if ((opmode == IEEE80211_M_STA) && (scn->sc_nstavaps >0)) {
       if (!(flags & IEEE80211_WRAP_WIRED_STA) && !(flags & IEEE80211_CLONE_MATADDR )) {
           qdf_print("\n\n A STA is already created on this radio. Not creating this STA\n\n");
           QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n\n %s() devhandle (%p) A STA is already created on this radio. Not creating this STA\n\n",
               __func__, ic);
           goto err_vap_create;
       }
    }

    /* do a full search to mark all the allocated vaps */
    nvaps = wlan_iterate_vap_list(ic,ol_ath_vap_iter_vap_create,(void *) &id_mask);
    id_mask |= scn->sc_prealloc_idmask; /* or in allocated ids */
    IEEE80211_ADDR_COPY(vap_addr,ic->ic_myaddr);


    if (flags & IEEE80211_P2PDEV_VAP) {
        id = 1;
    } else if ((flags & IEEE80211_CLONE_BSSID) &&
        opmode != IEEE80211_M_WDS) {
        /*nvaps != 0 && opmode != IEEE80211_M_WDS) { */
        /*nvaps can be zero if vap delete in progress but the index may still be valid so we should check for available index based on sc_prealloc_mask*/

        /*
         * Hardware supports the bssid mask and a unique bssid was
         * requested.  Assign a new mac address and expand our bssid
         * mask to cover the active virtual ap's with distinct
         * addresses.
         */
        if (nvaps == ATH_BCBUF) {
            qdf_print("Vap count exceeds the supported value \n");
            goto err_vap_create;
        }
        for (id = 0; id < ATH_BCBUF; id++) {
            /* get the first available slot */
            if ((id_mask & (1 << id)) == 0)
                break;

        }
    }
#if ATH_SUPPORT_WRAP
    if (flags & IEEE80211_CLONE_MACADDR) {
        num_vdevs = ol_ath_get_qwrap_num_vdevs (scn);
        for (id = 0; id < num_vdevs; id++) {
            /* get the first available slot */
            if ((id_mask & (1 << id)) == 0)
                break;
        }
    } else
#endif
    if ((flags & IEEE80211_CLONE_BSSID) == 0) {
        if (ic->ic_is_macreq_enabled(ic)) {
            /*
             * Pre-allocated VAP id is used to generate MAC address,
             * this id is retrieved during VAP delete time
             * extract the id from the bssid
             */
            ATH_GET_VAP_ID(bssid, ic->ic_myaddr, id);
            if ( (scn->sc_prealloc_idmask & (1 << id)) == 0) {
                /* the mac address was not pre allocated with ath_vap_alloc_macaddr */
                qdf_print("%s: the vap mac address was not pre allocated \n",__func__);
                goto err_vap_create;
            }

            /*
             * Generate the mac address from id and sanity check
             */
            ATH_SET_VAP_BSSID(vap_addr,ic->ic_myaddr, id);
        } else {
            /* do not clone use the one passed in */
            qdf_print("No cloning\n");
            /*
             * Added proper logic to get vap id and bssid value.
             * when user pass BSSID MAC value through commandline using -bssid option, The
             * exsiting logic won't work to get proper vap id to create VAP
             */

            for (id = 0; id < ATH_BCBUF; id++) {
                /* get the first available slot */
                if ((id_mask & (1 << id)) == 0) {
                    break;
                }
            }
            /* Update user passed BSSID value */
            IEEE80211_ADDR_COPY(vap_addr, bssid);
        }
    }

#if ATH_SUPPORT_WRAP
    if (flags & IEEE80211_CLONE_MACADDR) {
        if(id >= num_vdevs) {
            qdf_print("%s: VAP (%d) exceeding limit of maximum allowed VAPSIZE \n",
                __func__, id);
            goto err_vap_create;
        }
    } else if (id >= ATH_BCBUF) {
        /* check if VAP id is exceeding max beacon buffers supported for VAPs */
        qdf_print("%s: VAP (%d) exceeding limit of maximum allowed (%d) \n",
            __func__, id, ATH_BCBUF);
        goto err_vap_create;
    }
#else
    if (id >= ATH_BCBUF) {
        qdf_print("%s: VAP (%d) exceeding limit of maximum allowed (%d)\n",
            __func__, id, ATH_BCBUF);
        goto err_vap_create;
    }
#endif

    /* check if we are recovering or creating the VAP */
    vap = osif_get_vap(osifp_handle);
    if(vap == NULL) {
        /* create the corresponding VAP */
        avn = (struct ol_ath_vap_net80211 *)qdf_mempool_alloc(scn->qdf_dev, scn->mempool_ol_ath_vap);
        if (avn == NULL) {
            qdf_print("Can't allocate memory for ath_vap.\n");
            goto err_vap_create;
        }
    } else {
        avn = OL_ATH_VAP_NET80211(vap);
    }
    OS_MEMZERO(avn, sizeof(struct ol_ath_vap_net80211));

    switch (opmode) {
    case IEEE80211_M_STA:
        type = WMI_HOST_VDEV_TYPE_STA;
        break;
    case IEEE80211_M_IBSS:
        type = WMI_HOST_VDEV_TYPE_IBSS;
        break;
    case IEEE80211_M_MONITOR:
        type = WMI_HOST_VDEV_TYPE_MONITOR;
        break;
    case IEEE80211_M_HOSTAP:
    case IEEE80211_M_WDS:
    case IEEE80211_M_BTAMP:
        type = WMI_HOST_VDEV_TYPE_AP;
        break;
    default:
        goto err_alloc_mempool;
    }

    if ((flags & IEEE80211_CLONE_BSSID) == 0 && !ic->ic_is_macreq_enabled(ic)) {
        IEEE80211_ADDR_COPY(vap_addr, bssid);
    } else {
        /* set up MAC address */
        ATH_SET_VAP_BSSID(vap_addr, ic->ic_myaddr, id);
    }

    avn->av_sc = scn;
    avn->av_if_id = id;
    avn->av_restart_in_progress = FALSE;
    qdf_spinlock_create(&avn->avn_lock);
    TAILQ_INIT(&avn->deferred_bcn_list);

    vap = &avn->av_vap;

    if (flags & IEEE80211_P2PDEV_VAP) {
        sub_type = WMI_HOST_VDEV_SUBTYPE_P2P_DEVICE;
    }else if (flags & IEEE80211_P2PCLI_VAP) {
        sub_type = WMI_HOST_VDEV_SUBTYPE_P2P_CLIENT;
    }else if (flags & IEEE80211_P2PGO_VAP) {
        sub_type = WMI_HOST_VDEV_SUBTYPE_P2P_GO;
    }

    if (flags & IEEE80211_SPECIAL_VAP) {
        vap->iv_special_vap_mode = 1;
    }

#if ATH_SUPPORT_NAC
    if (flags & IEEE80211_SMART_MONITOR_VAP) {
        vap->iv_smart_monitor_vap =1;
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_NAC, "%s : Smart Monitor Set to %d \n", __func__, vap->iv_smart_monitor_vap);
    }
#endif

    vap->mhdr_len = 0;
#if MESH_MODE_SUPPORT
    if (flags & IEEE80211_MESH_VAP) {
        if (!ic->ic_mesh_vap_support) {
            qdf_print("Mesh vap not supported by this radio!!\n");
            qdf_spinlock_destroy(&avn->avn_lock);
            goto err_alloc_mempool;
        }
        vap->iv_mesh_vap_mode =1;
        sub_type = WMI_HOST_VDEV_SUBTYPE_MESH;
        vap->mhdr_len = sizeof(struct meta_hdr_s);
        vap->mhdr = 0;
    }
#endif

    scn->sc_prealloc_idmask |= (1 << id);
    id_used = 1;
#if ATH_SUPPORT_WRAP
    if ((opmode == IEEE80211_M_HOSTAP) && (flags & IEEE80211_WRAP_VAP)) {

        avn->av_is_wrap = 1;
        vap->iv_wrap =1;
        ic->ic_nwrapvaps++;
        scn->sc_nwrapvaps++;
    } else if ((opmode == IEEE80211_M_STA) && (flags & IEEE80211_CLONE_MACADDR)) {
        if (!bssid[0] && !bssid[1] && !bssid[2] &&
            !bssid[3] && !bssid[4] && !bssid[5])
        {
            /*
             * Main ProxySTA VAP for uplink WPS PBC and
             * downlink multicast receive.
             */
            avn->av_is_mpsta = 1;
            vap->iv_mpsta = 1;

            qdf_spin_lock_bh(&scn->sc_mpsta_vap_lock);
            scn->sc_mcast_recv_vap = vap;
            qdf_spin_unlock_bh(&scn->sc_mpsta_vap_lock);

            IEEE80211_ADDR_COPY(vap_addr,ic->ic_myaddr);
            ATH_SET_VAP_BSSID(vap_addr, ic->ic_myaddr, id);
        } else {
            /*
             * Generally, non-Main ProxySTA VAP's don't need to
             * register umac event handlers. We can save some memory
             * space by doing so. This is required to be done before
             * ieee80211_vap_setup. However we still give the scan
             * capability to the first ATH_NSCAN_PSTA_VAPS non-Main
             * PSTA VAP's. This optimizes the association speed for
             * the first several PSTA VAP's (common case).
             */
#define ATH_NSCAN_PSTA_VAPS 0
            if (scn->sc_nscanpsta >= ATH_NSCAN_PSTA_VAPS)
                vap->iv_no_event_handler = 1;
            else
                scn->sc_nscanpsta++;
        }
        avn->av_is_psta = 1;
        vap->iv_psta = 1;
        scn->sc_npstavaps++;
    }

    if (flags & IEEE80211_CLONE_MATADDR) {
        avn->av_use_mat = 1;
        vap->iv_mat = 1;
        OS_MEMCPY(avn->av_mat_addr, mataddr, IEEE80211_ADDR_LEN);
        OS_MEMCPY(vap->iv_mat_addr, mataddr, IEEE80211_ADDR_LEN);
    }

    if (flags & IEEE80211_WRAP_WIRED_STA) {
        vap->iv_wired_pvap = 1;
    }
    if (avn->av_is_psta) {
        if (avn->av_is_mpsta) {
            /*
             * Main ProxySTA VAP also handles the downlink multicast receive
             * on behalf of all the ProxySTA VAP's.
             */
            OS_MEMCPY(avn->av_mat_addr, vap->iv_myaddr, IEEE80211_ADDR_LEN);
        } else {
            sub_type = WMI_HOST_VDEV_SUBTYPE_PROXY_STA;
            OS_MEMCPY(vap_addr, bssid, IEEE80211_ADDR_LEN);
        }
    }

    /*
     * This is only needed for Peregrine, remove this once we have HW CAP bit added
     * for enhanced ProxySTA support.
     */
    if (scn->target_type == TARGET_TYPE_AR9888) {
	    /* enter ProxySTA mode when the first WRAP or PSTA VAP is created */
	    if (scn->sc_nwrapvaps + scn->sc_npstavaps == 1)
		(void)ol_ath_pdev_set_param(scn, wmi_pdev_param_proxy_sta_mode, 1, 0);
    }
#endif

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    nss_if = osif_nss_vdev_alloc(scn->pdev_txrx_handle, vap);
    if ( nss_if == -1) {
        qdf_print("NSS WiFi Offload unable to allocate VAP %d\n", id);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s() devhandle (%p) NSS WiFi Offload unable to allocate VAP %d\n",
             __func__, ic, id);
        goto err_nss_vdev;
    }
#endif

    /* Create a vdev in target */
    qdf_mem_set(&param, sizeof(param), 0);
    param.if_id = id;
    param.type = type;
    param.subtype = sub_type;

    if (wmi_unified_vdev_create_send(scn->wmi_handle, vap_addr, &param)) {
        qdf_print("Unable to create vdev in target\n");
        goto err_vdev_create;
    }
    tgt_vdev_created = 1;
    vap->iv_unit = id;

    ieee80211_mucap_vattach(vap);
    ieee80211_vap_setup(ic, vap, opmode, scan_priority_base, flags, bssid);
    vap->iv_ampdu = IEEE80211_AMPDU_SUBFRAME_MAX;
    vap->iv_vht_amsdu = 4;            /* By default amsdu is enable and set to max */

#if ATH_SUPPORT_WIFIPOS && !(ATH_SUPPORT_LOWI)
    vap->iv_wifipos->xmitprobe          =       ol_ieee80211_wifipos_xmitprobe;
    vap->iv_wifipos->xmitrtt3           =       ol_ieee80211_wifipos_xmitrtt3;
    vap->iv_wifipos->ol_wakeup_request  =       ol_ath_rtt_keepalive_req;
    vap->iv_wifipos->lci_set            =       ol_ieee80211_lci_set;
    vap->iv_wifipos->lcr_set            =       ol_ieee80211_lcr_set;
#endif
    /*  Enable MU-BFER & SU-BFER if the Tx chain number is 0x2, 0x3 and 0x4 and not otherwise.   */
    if(ieee80211_get_txstreams(ic, vap) < 2) {
	    vap->iv_vhtsubfer = 0;
	    vap->iv_vhtmubfer = 0;
    }
#if ATH_SUPPORT_WRAP
    if (vap->iv_mpsta) {
        vap->iv_ic->ic_mpsta_vap = vap;
    }
    if (vap->iv_wrap) {
         vap->iv_ic->ic_wrap_vap = vap;
    }
#if ATH_PROXY_NOACK_WAR
    if (vap->iv_mpsta || vap->iv_wrap) {
        wmi_unified_register_event_handler(scn->wmi_handle, wmi_pdev_reserve_ast_entry_event_id,
                                    ol_ath_pdev_proxy_ast_reserve_event_handler, WMI_RX_UMAC_CTX);

        ic->proxy_ast_reserve_wait.blocking = 1;
        qdf_semaphore_init(&(ic->proxy_ast_reserve_wait.sem_ptr));
        qdf_semaphore_acquire(&(ic->proxy_ast_reserve_wait.sem_ptr));
    }
#endif
#endif
    ieee80211vap_set_macaddr(vap, vap_addr);

#if ATH_SUPPORT_WRAP
    if (avn->av_is_wrap || avn->av_is_psta) {
        if (scn->sc_nwrapvaps) {
            ieee80211_ic_enh_ind_rpt_set(vap->iv_ic);
        }
    }
    vap->iv_wrap_mat_tx = ol_if_wrap_mat_tx;
    vap->iv_wrap_mat_rx = ol_if_wrap_mat_rx;
#endif

     /*
     * If BMISS offload is supported, we disable the SW Bmiss timer on host for STA vaps.
     * The timer is initialised only for STA vaps.
     */
    if (wmi_service_enabled(scn->wmi_handle,
                               wmi_service_bcn_miss_offload) && (opmode == IEEE80211_M_STA)) {
        u_int32_t tmp_id;
        int8_t tmp_name[] = "tmp";

        tmp_id = ieee80211_mlme_sta_swbmiss_timer_alloc_id(vap, tmp_name);
        ieee80211_mlme_sta_swbmiss_timer_disable(vap, tmp_id);
    }

    /* set user selected channel width to an invalid value by default */
    vap->iv_chwidth = IEEE80211_CWM_WIDTHINVALID;

    /* Enable 256 QAM by default */
    vap->iv_256qam = 1;

    vap->iv_no_cac = 0;

    /* Intialize VAP interface functions */
    vap->iv_up = ol_ath_vap_up;
    vap->iv_join = ol_ath_vap_join;
    vap->iv_down = ol_ath_vap_down;
    vap->iv_listen = ol_ath_vap_listen;
    vap->iv_stopping = ol_ath_vap_stopping;
    vap->iv_dfs_cac = ol_ath_vap_dfs_cac;
    vap->iv_key_alloc = ol_ath_key_alloc;
    vap->iv_key_delete = ol_ath_key_delete;
    vap->iv_key_set = ol_ath_key_set;
    vap->iv_root_authorize = ol_ath_root_authorize;
#if ATH_SUPPORT_NAC
    vap->iv_neighbour_rx = ol_ath_neighbour_rx;
#endif
#if 0
    vap->iv_key_map    = ol_ath_key_map;
    vap->iv_key_update_begin = ol_ath_key_update_begin;
    vap->iv_key_update_end = ol_ath_key_update_end;
    vap->iv_reg_vap_ath_info_notify = ol_ath_net80211_reg_vap_info_notify;
    vap->iv_vap_ath_info_update_notify = ol_ath_net80211_vap_info_update_notify;
    vap->iv_dereg_vap_ath_info_notify = ol_ath_net80211_dereg_vap_info_notify;
    vap->iv_vap_ath_info_get = ol_ath_net80211_vap_info_get;
    vap->iv_update_ps_mode = ol_ath_update_ps_mode;
    vap->iv_update_node_txpow = ol_ath_net80211_update_node_txpow;
#endif

#if  0 //ATH_SUPPORT_WIFIPOS
    vap->iv_wifipos->status_request =       ieee80211_wifipos_status_request;
    vap->iv_wifipos->cap_request =          ieee80211_wifipos_cap_request;
    vap->iv_wifipos->sleep_request =        ieee80211_wifipos_sleep_request;
    vap->iv_wifipos->wakeup_request =       ol_ath_wifipos_wakeup_request;

    vap->iv_wifipos->nlsend_status_resp =   ieee80211_wifipos_nlsend_status_resp;
    vap->iv_wifipos->nlsend_cap_resp =      ieee80211_wifipos_nlsend_cap_resp;
    vap->iv_wifipos->nlsend_tsf_resp =      ieee80211_wifipos_nlsend_tsf_resp;
    vap->iv_wifipos->nlsend_sleep_resp =    ieee80211_wifipos_nlsend_sleep_resp;
    vap->iv_wifipos->nlsend_wakeup_resp =   ol_ath_wifipos_nlsend_wakeup_resp;
    vap->iv_wifipos->nlsend_empty_resp  =   ieee80211_wifipos_nlsend_empty_resp;
    vap->iv_wifipos->nlsend_probe_resp =    ieee80211_wifipos_nlsend_probe_resp;
    vap->iv_wifipos->nlsend_tsf_update =    ieee80211_wifipos_nlsend_tsf_update;

    vap->iv_wifipos->fsm =                  ieee80211_ol_wifipos_fsm;

    vap->iv_wifipos->xmittsfrequest =       ieee80211_wifipos_xmittsfrequest;
    vap->iv_wifipos->xmitprobe      =       ol_ieee80211_wifipos_xmitprobe;
#endif

     /*
      * init IEEE80211_DPRINTF control object
      * Register with asf.
      */

    ieee80211_dprintf_init(vap);

#if DBG_LVL_MAC_FILTERING
    vap->iv_print.dbgLVLmac_on = 0; /*initialize dbgLVLmac flag*/
#endif

    vap->iv_unit = id;

    nactivevaps = ieee80211_vaps_active(ic);
    if (nactivevaps==0) {
        ic->ic_opmode = opmode;
    }

    /* translate the opmode into the enum expected by the txrx module */
    switch (opmode) {
    case IEEE80211_M_STA:
        txrx_opmode = wlan_op_mode_sta;
        break;
    case IEEE80211_M_HOSTAP:
        txrx_opmode = wlan_op_mode_ap;
        break;
    case IEEE80211_M_IBSS:
        txrx_opmode = wlan_op_mode_ibss;
        break;
    case IEEE80211_M_MONITOR:
        txrx_opmode = wlan_op_mode_monitor;
        break;
    default:
        txrx_opmode = wlan_op_mode_unknown;
    };
    avn->av_txrx_handle = ol_txrx_vdev_attach(
        scn->pdev_txrx_handle, vap_addr, id, txrx_opmode);
    if (avn->av_txrx_handle == NULL ) {
        qdf_print("%s: Unable to attach ol txrx module.\n",__func__);
        goto err_txrx_attach;
    }
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (osif_nss_ol_vap_create(avn->av_txrx_handle, vap, osifp_handle, nss_if) == -1) {
        qdf_print("%s: NSS WiFi Offload Unabled to attach vap \n",__func__);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: NSS WiFi Offload Unable to attach vap \n",__func__);
        ol_txrx_vdev_detach(avn->av_txrx_handle, NULL, NULL);
        goto err_txrx_attach;
    }
#endif
    vap->iv_txrx_handle = avn->av_txrx_handle;
    vap->iv_vap_get_ol_data_handle = ol_ath_vap_get_ol_data_handle;
    /* Setting default value to be retrieved when iwpriv get_inact command is used */
    vap->iv_inact_run = DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MAX_UNRESPONSIVE_TIME_SECS;

    /* Send Param indicating LP IOT vap as requested by FW */
    if (opmode == IEEE80211_M_HOSTAP) {
        if  (flags & IEEE80211_LP_IOT_VAP) {
            if(ol_ath_wmi_send_vdev_param(scn,
                 avn->av_if_id, wmi_vdev_param_sensor_ap,
                 1)) {
                 qdf_print("%s:Unable to send param LP IOT VAP mode to target\n",__func__);
            }

#ifndef WMI_BEACON_RATE_2M
#define WMI_BEACON_RATE_2M   0x42
#endif
#ifndef WMI_BEACON_RATE_6M
#define WMI_BEACON_RATE_6M   0x03
#endif
            /* Beacon rate for arlo vap on 2.4G radio is 2M */
            if (IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan)) {
                if(ol_ath_wmi_send_vdev_param(scn,
                     avn->av_if_id, wmi_vdev_param_beacon_rate,
                     WMI_BEACON_RATE_2M)) {
                     qdf_print("%s:Unable to send param beacon rate 2Mbps to target\n",__func__);
                }
            } else {
                if(ol_ath_wmi_send_vdev_param(scn,
                     avn->av_if_id, wmi_vdev_param_beacon_rate,
                     WMI_BEACON_RATE_6M)) {
                     qdf_print("%s:Unable to send param beacon rate 6Mbps to target\n",__func__);
                }
            }
        }
    }
    if(ol_ath_wmi_send_vdev_param(scn,
        avn->av_if_id, wmi_vdev_param_ap_keepalive_min_idle_inactive_time_secs,
        DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MIN_IDLE_TIME_SECS)) {
        qdf_print("Unable to send param AP MIN_Keepalive\n");
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s() Unable to send param AP MIN_Keepalive\n", __func__);
    }
    if(ol_ath_wmi_send_vdev_param(scn,
        avn->av_if_id, wmi_vdev_param_ap_keepalive_max_idle_inactive_time_secs,
        DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MAX_IDLE_TIME_SECS)) {
        qdf_print("Unable to send parami AP MAX_Keepalive\n");
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s() Unable to send param AP MAX_Keepalive\n", __func__);
    }
    if(ol_ath_wmi_send_vdev_param(scn,
        avn->av_if_id, wmi_vdev_param_ap_keepalive_max_unresponsive_time_secs,
        DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MAX_UNRESPONSIVE_TIME_SECS)) {
        qdf_print("Unable to send param AP MAX_Unresponsive\n");
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s() Unable to send param AP MAX_Unresponsive\n", __func__);
    }

    /*
     * Don't set promiscuous bit in smart monitor vap
     * Smar monitor vap - filters specific to other
     * configured neighbour AP BSSID & its associated clients
     */
    if (vap->iv_special_vap_mode && !vap->iv_smart_monitor_vap) {
        qdf_print("enabling promiscuos bit\n");
        retval = ol_ath_pdev_set_param(scn,
                            wmi_pdev_param_set_promisc_mode_cmdid, 1, 0);
        if (retval) {
            qdf_print("Unable to send param promisc_mode\n");
        }
    }

#if ATH_SUPPORT_DSCP_OVERRIDE
    if (vap->iv_override_dscp) {
        ol_ath_set_vap_dscp_tid_map(vap);
    }
#endif

#if UMAC_SUPPORT_WNM
    /* configure wnm default settings */
    ieee80211_vap_wnm_set(vap);
#endif

#if MESH_MODE_SUPPORT
    if (vap->iv_mesh_vap_mode) {
        ol_txrx_set_mesh_mode(vap->iv_txrx_handle,1);
    }
#endif
#ifndef ATH_WIN_NWF
    vap->iv_tx_encap_type = htt_pkt_type_ethernet;
    vap->iv_rx_decap_type = htt_pkt_type_ethernet;
#else
    vap->iv_tx_encap_type = htt_pkt_type_native_wifi;
    vap->iv_rx_decap_type = htt_pkt_type_native_wifi;
#endif
    /* disable RTT by default. WFA requirement */
    vap->rtt_enable=0;

    /* Enable EXT NSS support on vap by default if FW provides support */
    if (ic-> ic_fw_ext_nss_capable) {
        vap->iv_ext_nss_capable = 1;
        vap->iv_ext_nss_support = 1;
    }

    if (opmode == IEEE80211_M_HOSTAP)
        vap->iv_rev_sig_160w = DEFAULT_REV_SIG_160_STATUS;

    (void) ieee80211_vap_attach(vap);

    if (opmode == IEEE80211_M_STA)
        scn->sc_nstavaps++;

    /*
     * Register the vap setup functions for offload
     * functions here.
     */
    osif_vap_setup_ol(vap, osifp_handle);
    return vap;

err_txrx_attach:
   /*
    * Unregister with asf.
    * Need to make sure vap is proper if there is a wrong jump to here
    */
    if (vap) {
        ieee80211_dprintf_deregister(vap);
    }

    /*
     * Delete the interface in target
     */
    if (tgt_vdev_created
        && (wmi_unified_vdev_delete_send(scn->wmi_handle, avn->av_if_id))) {
        qdf_print("%s() Unable to remove interface in Target vdev_id %d address: %02x:%02x:%02x:%02x:%02x:%02x:\n",
                __func__, id, vap_addr[0], vap_addr[1], vap_addr[2], vap_addr[3], vap_addr[4], vap_addr[5]);
    }
err_vdev_create:
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (nss_if && (nss_if != -1) && (nss_if != NSS_PROXY_VAP_IF_NUMBER)) {
        osif_nss_vdev_dealloc(osifp_handle, nss_if);
    }
err_nss_vdev:
#endif
    if (id_used) {
        scn->sc_prealloc_idmask &= ~(1 << id);
    }
    qdf_spinlock_destroy(&avn->avn_lock);
err_alloc_mempool:
    if (avn) {
        qdf_mempool_free(scn->qdf_dev, scn->mempool_ol_ath_vap, avn);
    }
err_vap_create:
    qdf_spin_lock_bh(&scn->scn_lock);
    if (opmode == IEEE80211_M_MONITOR) {
        scn->mon_vdev_count--;
    } else {
        scn->vdev_count--;
    }
    qdf_spin_unlock_bh(&scn->scn_lock);
    return NULL;

}

/*
 * VAP free
 */
static void
ol_ath_vap_free(struct ieee80211vap *vap)
{
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    struct ol_ath_softc_net80211 *scn = avn->av_sc;

    qdf_mempool_free(scn->qdf_dev, scn->mempool_ol_ath_vap, avn);
}

/*
 * VAP delete
 */
static void
ol_ath_vap_delete(struct ieee80211vap *vap)
{
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    struct ol_ath_softc_net80211 *scn = avn->av_sc;

    if (!vap) {
        qdf_print("VAP is NULL!!!\n");
        return;
    }

    /* delete key before vdev delete */
    delete_default_vap_keys(vap);

#if ATH_SUPPORT_WRAP
    /*
     * Both WRAP and ProxySTA VAP's populate keycache slot with
     * vap->iv_myaddr even when security is not used.
     */
    if (avn->av_is_wrap) {
        scn->sc_nwrapvaps--;
    } else if (avn->av_is_psta) {
        qdf_spin_lock_bh(&scn->sc_mpsta_vap_lock);
        if (scn->sc_mcast_recv_vap == vap) {
            scn->sc_mcast_recv_vap = NULL;
        }
        qdf_spin_unlock_bh(&scn->sc_mpsta_vap_lock);

        if (!avn->av_is_mpsta) {
            if (vap->iv_no_event_handler == 0)
                scn->sc_nscanpsta--;
        }
    scn->sc_npstavaps--;
    }
    /* exit ProxySTA mode when the last WRAP or PSTA VAP is deleted */
    if (scn->target_type == TARGET_TYPE_AR9888) {
	/* Only needed for Peregrine */
		if (avn->av_is_wrap || avn->av_is_psta) {
			if (scn->sc_nwrapvaps + scn->sc_npstavaps == 0) {
				(void)ol_ath_pdev_set_param(scn, wmi_pdev_param_proxy_sta_mode, 0, 0);
			}
		}
	}
#endif

    scn->sc_prealloc_idmask &= ~(1 << avn->av_if_id);

    /* remove the interface from ath_dev */
    if (wmi_unified_vdev_delete_send(scn->wmi_handle, avn->av_if_id)) {
        qdf_print("Unable to remove an interface for ath_dev.\n");
        ASSERT(0);
    }
    qdf_print("%s: wmi_unified_vdev_delete_send done ID = %d vap (%p) VAP Addr = %02x:%02x:%02x:%02x:%02x:%02x:\n",
                __func__, avn->av_if_id, vap,
               vap->iv_myaddr[0], vap->iv_myaddr[1], vap->iv_myaddr[2],
               vap->iv_myaddr[3], vap->iv_myaddr[4], vap->iv_myaddr[5]);

    if(ieee80211vap_get_opmode(vap) == IEEE80211_M_STA)
        scn->sc_nstavaps--;

    if(vap->iv_special_vap_mode) {
        vap->iv_special_vap_mode = 0;
        scn->special_ap_vap = 0;
    }

#if ATH_SUPPORT_NAC
    if (vap->iv_smart_monitor_vap) {
        vap->iv_smart_monitor_vap = 0;
        scn->smart_ap_monitor = 0;
    }
#endif

    /* deregister IEEE80211_DPRINTF control object */
    ieee80211_dprintf_deregister(vap);

    /* detach VAP from the procotol stack */
    ieee80211_mucap_vdetach(vap);
    ieee80211_vap_detach(vap);

    /* TBD:
     * Should a callback be provided for notification once the
     * txrx vdev object has actually been deleted?
     */
    ol_txrx_vdev_detach(avn->av_txrx_handle, NULL, NULL);

#if ATH_SUPPORT_WRAP
    if (vap->iv_mpsta) {
        vap->iv_ic->ic_mpsta_vap = NULL;
    }
    if (vap->iv_wrap) {
         vap->iv_ic->ic_wrap_vap = NULL;
    }
#endif

    qdf_spinlock_destroy(&avn->avn_lock);

    qdf_spin_lock(&scn->scn_lock);
    if (ieee80211vap_get_opmode(vap) == IEEE80211_M_MONITOR) {
        scn->mon_vdev_count--;
    } else {
        scn->vdev_count--;
    }
    qdf_spin_unlock(&scn->scn_lock);

}

/*
 * pre allocate a mac address and return it in bssid
 */
static int
ol_ath_vap_alloc_macaddr(struct ieee80211com *ic, u_int8_t *bssid)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    int id = 0, id_mask = 0;
    int nvaps = 0;
   //  DPRINTF(scn, ATH_DEBUG_STATE, "%s \n", __func__);
    /* do a full search to mark all the allocated vaps */
    nvaps = wlan_iterate_vap_list(ic,ol_ath_vap_iter_vap_create,(void *) &id_mask);

    id_mask |= scn->sc_prealloc_idmask; /* or in allocated ids */


    if (IEEE80211_ADDR_IS_VALID(bssid) ) {
        /* request to preallocate a specific address */
        /* check if it is valid and it is available */
        u_int8_t tmp_mac2[IEEE80211_ADDR_LEN];
        u_int8_t tmp_mac1[IEEE80211_ADDR_LEN];
        IEEE80211_ADDR_COPY(tmp_mac1, ic->ic_my_hwaddr);
        IEEE80211_ADDR_COPY(tmp_mac2, bssid);

        if (ic->ic_is_macreq_enabled(ic)) {
            /* Ignore locally/globally administered bits */
            ATH_SET_VAP_BSSID_MASK_ALTER(tmp_mac1);
            ATH_SET_VAP_BSSID_MASK_ALTER(tmp_mac2);
        } else {
            tmp_mac1[ATH_VAP_ID_INDEX] &= ~(ATH_VAP_ID_MASK >> ATH_VAP_ID_SHIFT);
            if (ATH_VAP_ID_INDEX < (IEEE80211_ADDR_LEN - 1))
                tmp_mac1[ATH_VAP_ID_INDEX+1] &= ~( ATH_VAP_ID_MASK << ( OCTET-ATH_VAP_ID_SHIFT ) );

            tmp_mac1[0] |= IEEE802_MAC_LOCAL_ADMBIT ;
            tmp_mac2[ATH_VAP_ID_INDEX] &= ~(ATH_VAP_ID_MASK >> ATH_VAP_ID_SHIFT);
            if (ATH_VAP_ID_INDEX < (IEEE80211_ADDR_LEN - 1))
                tmp_mac2[ATH_VAP_ID_INDEX+1] &= ~( ATH_VAP_ID_MASK << ( OCTET-ATH_VAP_ID_SHIFT ) );
        }
        if (!IEEE80211_ADDR_EQ(tmp_mac1,tmp_mac2) ) {
            qdf_print("%s[%d]: Invalid mac address requested %s  \n",__func__,__LINE__,ether_sprintf(bssid));
            return -1;
        }
        ATH_GET_VAP_ID(bssid, ic->ic_my_hwaddr, id);

        if ((id_mask & (1 << id)) != 0) {
            qdf_print("%s[%d]:mac address already allocated %s\n",__func__,__LINE__,ether_sprintf(bssid));
            return -1;
        }
     }
     else {

        for (id = 0; id < ATH_BCBUF; id++) {
             /* get the first available slot */
             if ((id_mask & (1 << id)) == 0)
                 break;
        }
        if (id == ATH_BCBUF) {
           /* no more ids left */
          qdf_print("%s[%d]:No more free slots left \n",__func__,__LINE__);
          // DPRINTF(scn, ATH_DEBUG_STATE, "%s No more free slots left \n", __func__);
           return -1;
        }

    }


    /* set the allocated id in to the mask */
    scn->sc_prealloc_idmask |= (1 << id);

    return 0;
}

/*
 * free a  pre allocateed  mac addresses.
 */
static int
ol_ath_vap_free_macaddr(struct ieee80211com *ic, u_int8_t *bssid)
{
    /* TBD */
    return 0;
}

/* Intialization functions */
void
ol_ath_vap_attach(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    ic->ic_vap_create = ol_ath_vap_create;
    ic->ic_vap_delete = ol_ath_vap_delete;
    ic->ic_vap_free = ol_ath_vap_free;
    ic->ic_vap_alloc_macaddr = ol_ath_vap_alloc_macaddr;
    ic->ic_vap_free_macaddr = ol_ath_vap_free_macaddr;
    ic->ic_vap_set_param = ol_ath_vap_set_param;
    ic->ic_vap_sifs_trigger = ol_ath_vap_sifs_trigger;
    ic->ic_vap_set_ratemask = ol_ath_vap_set_ratemask;
    ic->ic_vap_dyn_bw_rts = ol_ath_vap_dyn_bw_rts;
    ic->ic_ol_net80211_set_mu_whtlist = ol_net80211_set_mu_whtlist;
    ic->ic_vap_get_param = ol_ath_vap_get_param;

    /* Register WMI event handlers */
    wmi_unified_register_event_handler(scn->wmi_handle, wmi_vdev_stopped_event_id,
                                       ol_ath_vdev_stopped_event_handler, WMI_RX_UMAC_CTX);
    wmi_unified_register_event_handler(scn->wmi_handle, wmi_roam_event_id,
                                       ol_ath_vdev_roam_event_handler, WMI_RX_UMAC_CTX);

#if ATH_SUPPORT_ME_FW_BASED
    /* Register event handler for releasing the mcast buffers allocated once target
     * confirms it. This is done to sync host and target buffer allocations
     */
    wmi_unified_register_event_handler(scn->wmi_handle, wmi_mcast_buf_release_event_id,
		                       ol_ath_mcast_buf_release_handler, WMI_RX_UMAC_CTX);
#endif /*ATH_SUPPORT_ME_FW_BASED*/

#if ATH_SUPPORT_GREEN_AP
    if (ic->ic_opmode == IEEE80211_M_HOSTAP) {
        /* If the mode is HOSTAP, Start the Green-AP feature */
        ath_green_ap_start(ic);
    }
#endif  /* ATH_SUPPORT_GREEN_AP */

}


struct vap_id_map {
    struct ieee80211vap *vap;
    u_int8_t vdev_id;
};

void
ol_ath_vap_iter_id(void *arg, struct ieee80211vap *vap)
{
    struct vap_id_map *v_id_map = arg;

    if (vap->iv_unit == v_id_map->vdev_id) {
       v_id_map->vap = vap;
    }
}

struct ieee80211vap *
ol_ath_vap_get(struct ol_ath_softc_net80211 *scn, u_int8_t vdev_id)
{
    struct vap_id_map v_id_map;

    v_id_map.vap = NULL;
    v_id_map.vdev_id = vdev_id;

    //  Get a vap given the vdev_id : iterate through the vap list and get the vap. The ic maintains a list of vaps.
    wlan_iterate_vap_list(&scn->sc_ic, ol_ath_vap_iter_id, &v_id_map);
    return v_id_map.vap;
}

/*
 * Returns the corresponding vap based on vdev
 * Doest not involve looping through vap list to compare the vdevid to get the vap and doesnt
 * consume more CPU cycles.
 * TODO: Try to avoid using ol_ath_vap_get and switch over to ol_ath_getvap to get the vap information.
 */

struct ieee80211vap *
ol_ath_getvap(struct ol_txrx_vdev_t *vdev)
{
    ol_osif_vdev_handle osif = vdev->osif_vdev;
    osif_dev  *osdev = (osif_dev *)osif;

    return osdev->os_if;
}

u_int8_t *
ol_ath_vap_get_myaddr(struct ol_ath_softc_net80211 *scn, u_int8_t vdev_id)
{
    struct vap_id_map v_id_map;

    v_id_map.vap = NULL;
    v_id_map.vdev_id = vdev_id;

    //  Get a vap given the vdev_id : iterate through the vap list and get the vap. The ic maintains a list of vaps.
    wlan_iterate_vap_list(&scn->sc_ic, ol_ath_vap_iter_id, &v_id_map);

    if (v_id_map.vap) {
        return v_id_map.vap->iv_myaddr;
    } else {
        return NULL;
    }
}

void  ol_ath_vap_tx_lock(void *ptr)
{
    osif_dev *osdev = (osif_dev *) ptr;
    struct ol_txrx_vdev_t* vdev = (struct ol_txrx_vdev_t*) (osdev->iv_txrx_handle);
    struct ol_txrx_pdev_t *pdev = vdev->pdev;
    qdf_spin_lock_bh(&pdev->tx_lock);
}

void  ol_ath_vap_tx_unlock(void *ptr)
{
    osif_dev *osdev = (osif_dev *) ptr;
    struct ol_txrx_vdev_t* vdev = (struct ol_txrx_vdev_t*) (osdev->iv_txrx_handle);
    struct ol_txrx_pdev_t *pdev = vdev->pdev;
    qdf_spin_unlock_bh(&pdev->tx_lock);
}

#endif
