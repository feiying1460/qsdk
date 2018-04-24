/*
 * Copyright (c) 2013-2015, 2017 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * 2013-2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * Copyright (c) 2010 Atheros Communications Inc.
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
 * Wireless extensions support for 802.11 common code.
 */
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/utsname.h>
#include <linux/if_arp.h>       /* XXX for ARPHRD_ETHER */
#include <net/iw_handler.h>

#include <asm/uaccess.h>
#if ATH_SUPPORT_FIPS
#include <qdf_atomic.h>
#endif
#include <a_types.h>
#include "if_media.h"
#include "_ieee80211.h"
#include <osif_private.h>
#include <wlan_opts.h>
#include <ieee80211_var.h>
#include "ieee80211_rateset.h"
#include "ieee80211_vi_dbg.h"
#include "ieee80211_channel.h"
#if ATH_SUPPORT_IBSS_DFS
#include <ieee80211_regdmn.h>
#endif
#include "ieee80211_power_priv.h"
#include "ald_netlink.h"
#if ATH_SUPPORT_WIFIPOS
#include <ieee80211_wifipos.h>
#endif
#include <if_smart_ant.h>
#include <ieee80211_nl.h>
#include <ieee80211_airtime_fairness.h>
#include "ieee80211_ioctl_acfg.h"
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_vdev_if.h>
#endif
#include "if_athvar.h"
#include "ol_if_athvar.h"

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_private.h>
#include <osif_nss_wifiol_if.h>
#include <osif_nss_wifiol_vdev_if.h>
#endif

#include "ieee80211_ucfg.h"

#define ONEMBPS 1000
#define THREE_HUNDRED_FIFTY_MBPS 350000

extern unsigned long ath_ioctl_debug;       /* defined in ah_osdep.c  */

#define IOCTL_DPRINTF(_fmt, ...) do {   \
    if ((ath_ioctl_debug))          \
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, _fmt, __VA_ARGS__); \
    } while (0)

#if IEEE80211_DEBUG_NODELEAK
void wlan_debug_dump_nodes_tgt(void);
#endif

#ifdef ATH_SUPPORT_HTC
static int ieee80211_ioctl_wrapper(struct net_device *dev,
                                   struct iw_request_info *info,
                                   union iwreq_data *wrqu, char *extra);
#endif
static char *find_ieee_priv_ioctl_name(int param, int set_flag);  /* for debugging use */
static void debug_print_ioctl(char *dev_name, int ioctl, char *ioctl_name) ;  /* for debugging */

#ifdef QCA_PARTNER_PLATFORM
extern int wlan_pltfrm_set_param(wlan_if_t vaphandle, u_int32_t val);
extern int wlan_pltfrm_get_param(wlan_if_t vaphandle);
#endif

#if MESH_MODE_SUPPORT
int ieee80211_add_localpeer(wlan_if_t vap, char *params);
int ieee80211_authorise_local_peer(wlan_if_t vap, char *params);
#endif

#if 0
/*
 * Common folder is coming from qca_main and
 * below function definitions are present
 * only on 10.2 and hence commenting this until
 * CL integration happens
 */
//int whal_kbps_to_mcs(int, int, int, int);
//int whal_mcs_to_kbps(int, int, int);
#endif

static const u_int mopts[] = {
        IFM_AUTO,
        IFM_IEEE80211_11A,
        IFM_IEEE80211_11B,
        IFM_IEEE80211_11G,
        IFM_IEEE80211_FH,
        IFM_IEEE80211_11A | IFM_IEEE80211_TURBO,
        IFM_IEEE80211_11G | IFM_IEEE80211_TURBO,
        IFM_IEEE80211_11NA,
        IFM_IEEE80211_11NG,
};

#define PREEMPT_SCAN_MAX_GRACE (100) /* units in msec */
#define PREEMPT_SCAN_MAX_WAIT  (100) /* units in msec */
static void
preempt_scan(struct net_device *dev, int max_grace, int max_wait)
{

#define PREEMPT_SCAN_DELAY ((CONVERT_SEC_TO_SYSTEM_TIME(1)/1000) + 1) /* 1 msec */
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    int total_delay = 0;
    int canceled = 0, ready = 0;

    while (!ready && total_delay < max_grace + max_wait) {
    if (!wlan_scan_in_progress(vap)) {
        ready = 1;
    } else {
        if (!canceled && total_delay > max_grace) {
        /*
        Cancel any existing active scan, so that any new parameters
        in this scan ioctl (or the defaults) can be honored, then
        wait around a while to see if the scan cancels properly.
        */
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
                "%s: cancel pending scan request\n", __func__);
        wlan_scan_cancel(vap, osifp->scan_requestor, IEEE80211_ALL_SCANS, true);
        canceled = 1;
        }

        schedule_timeout_interruptible(PREEMPT_SCAN_DELAY);
        total_delay += 1;
    }
    }
    if (!ready) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
                "%s: Timeout canceling current scan.\n",
                __func__);
    }
}

static const int legacy_rate_idx[][2] = {
    {1000, 0x1b},
    {2000, 0x1a},
    {5500, 0x19},
    {6000, 0xb},
    {9000, 0xf},
    {11000, 0x18},
    {12000, 0xa},
    {18000, 0xe},
    {24000, 0x9},
    {36000, 0xd},
    {48000, 0x8},
    {54000, 0xc},
};
static int
ieee80211_ioctl_siwrate(struct net_device *dev,
    struct iw_request_info *info,
    struct iw_param *rrq, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    int value;

    if (rrq->fixed) {
        unsigned int rate = rrq->value;
        if (rate >= 1000) {
            /* convert rate to index */
            int i;
            int array_size = sizeof(legacy_rate_idx)/sizeof(legacy_rate_idx[0]);
            rate /= 1000;
            for (i = 0; i < array_size; i++) {
            /* Array Index 0 has the rate and 1 has the rate code.
               The variable rate has the rate code which must be converted to actual rate*/

                if (rate == legacy_rate_idx[i][0]) {
                    rate = legacy_rate_idx[i][1];
                    break;
                }
            }
            if (i == array_size) return -EINVAL;
        }
        value = rate;
    } else {
        value = IEEE80211_FIXED_RATE_NONE;
    }

    return ieee80211_ucfg_set_rate(vap, value);
}

static int
ieee80211_ioctl_giwrate(struct net_device *dev,
    struct iw_request_info *info,
    struct iw_param *rrq, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = NETDEV_TO_VAP(dev);
    struct ifmediareq imr;
    int args[2];

    args[0] = IEEE80211_FIXED_RATE;

    memset(&imr, 0, sizeof(imr));
    osifp->os_media.ifm_status(dev, &imr);

    rrq->fixed = IFM_SUBTYPE(imr.ifm_active) != IFM_AUTO;
    rrq->value = ieee80211_ucfg_get_maxphyrate(vap);
    return 0;
}


static int
ieee80211_ioctl_siwfrag(struct net_device *dev,
    struct iw_request_info *info,
    struct iw_param *param, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    u_int32_t val, curval;

    debug_print_ioctl(dev->name, SIOCSIWFRAG, "siwfrag") ;
    if (param->disabled)
        val = IEEE80211_FRAGMT_THRESHOLD_MAX;
    else if (param->value < 256 || param->value > IEEE80211_FRAGMT_THRESHOLD_MAX)
        return -EINVAL;
    else
        val = (param->value & ~0x1);

    /* EV [121246] Chip::Peregrine RD::CUS223 SW::qca_main NP::SPE_Testplans
     * [PVT-CHN][Generic]AP allows to set fragmentation when AUTO mode is selected and
     * comes up in one of the HT modes
     * If AUTO, Disallow Frag Threshold setting
     * If Non-HT, Allow Frag Threshold Setting
     */
    if((wlan_get_desired_phymode(vap) != IEEE80211_MODE_AUTO) &&
            (wlan_get_desired_phymode(vap) < IEEE80211_MODE_11NA_HT20))
    {
        curval = wlan_get_param(vap, IEEE80211_FRAG_THRESHOLD);
        if (val != curval)
        {
            wlan_set_param(vap, IEEE80211_FRAG_THRESHOLD, val);
            if (IS_UP(dev))
                return -osif_vap_init(dev, RESCAN);
        }
    }
    else
    {
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WARNING: Fragmentation with HT mode NOT ALLOWED!!\n");
        return -EINVAL;
    }
    return 0;
}

static int
ieee80211_ioctl_giwfrag(struct net_device *dev,
    struct iw_request_info *info,
    struct iw_param *param, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;

    debug_print_ioctl(dev->name, SIOCGIWFRAG, "giwfrag") ;
    param->value = wlan_get_param(vap, IEEE80211_FRAG_THRESHOLD);
    param->disabled = (param->value == IEEE80211_FRAGMT_THRESHOLD_MAX);
    param->fixed = 1;

    return 0;
}

static int
ieee80211_ioctl_siwrts(struct net_device *dev,
    struct iw_request_info *info,
    struct iw_param *rts, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    u_int32_t val, curval;

    debug_print_ioctl(dev->name, SIOCSIWRTS, "siwrts") ;
    if (rts->disabled)
        val = IEEE80211_RTS_MAX;
    else if (IEEE80211_RTS_MIN <= rts->value &&
        rts->value <= IEEE80211_RTS_MAX)
        val = rts->value;
    else
        return -EINVAL;

    curval = wlan_get_param(vap, IEEE80211_RTS_THRESHOLD);
    if (val != curval)
    {
        wlan_set_param(vap, IEEE80211_RTS_THRESHOLD, rts->value);
        if (IS_UP(dev) && (vap->iv_novap_reset == 0)) {
            return osif_vap_init(dev, RESCAN);
        }
    }
    return 0;
}

static int
ieee80211_ioctl_giwrts(struct net_device *dev,
    struct iw_request_info *info,
    struct iw_param *rts, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;

    debug_print_ioctl(dev->name, SIOCGIWRTS, "giwrts") ;
    rts->value = wlan_get_param(vap, IEEE80211_RTS_THRESHOLD);
    rts->disabled = (rts->value == IEEE80211_RTS_MAX);
    rts->fixed = 1;

    return 0;
}

static int
ieee80211_ioctl_giwap(struct net_device *dev,
    struct iw_request_info *info,
    struct sockaddr *ap_addr, char *extra)
{
    osif_dev *osnetdev = ath_netdev_priv(dev);
    wlan_if_t vap = osnetdev->os_if;
    u_int8_t bssid[IEEE80211_ADDR_LEN];

    debug_print_ioctl(dev->name, SIOCGIWAP, "giwap") ;
    {
        static const u_int8_t zero_bssid[IEEE80211_ADDR_LEN];
        if(osnetdev->is_up) {
            wlan_vap_get_bssid(vap, bssid);
            IEEE80211_ADDR_COPY(&ap_addr->sa_data, bssid);
        } else {
            IEEE80211_ADDR_COPY(&ap_addr->sa_data, zero_bssid);
        }
    }
    ap_addr->sa_family = ARPHRD_ETHER;
    return 0;
}

static int
ieee80211_ioctl_siwap(struct net_device *dev,
    struct iw_request_info *info,
    struct sockaddr *ap_addr, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    u_int8_t des_bssid[IEEE80211_ADDR_LEN];

    debug_print_ioctl(dev->name, SIOCSIWAP, "siwap") ;

    /* NB: should only be set when in STA mode */
    if (wlan_vap_get_opmode(vap) != IEEE80211_M_STA &&
        osifp->os_opmode != IEEE80211_M_P2P_DEVICE &&
        osifp->os_opmode != IEEE80211_M_P2P_CLIENT) {
        return -EINVAL;
    }

    IEEE80211_ADDR_COPY(des_bssid, &ap_addr->sa_data);
    if (IS_NULL_ADDR(des_bssid)) {
        /* Desired bssid is set to NULL - to clear the AP list */
        wlan_aplist_init(vap);
    }
    else {
        wlan_aplist_set_desired_bssidlist(vap, 1, &des_bssid);
    }

    if (IS_UP(dev))
        return osif_vap_init(dev, RESCAN);
    return 0;
}

static int
ieee80211_ioctl_giwname(struct net_device *dev,
    struct iw_request_info *info,
    char *name, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    wlan_chan_t c = wlan_get_bss_channel(vap);
#if ATH_SUPPORT_WRAP
    if (wlan_is_wrap(vap))
        c = vap->iv_des_chan[vap->iv_des_mode];
#endif

    debug_print_ioctl(dev->name, SIOCGIWNAME, "giwname") ;

    if ((c == NULL) || (c == IEEE80211_CHAN_ANYC)) {
        strlcpy(name, "IEEE 802.11", IFNAMSIZ);
        return 0;
    }

    if (IEEE80211_IS_CHAN_108G(c))
        strlcpy(name, "IEEE 802.11Tg", IFNAMSIZ);
    else if (IEEE80211_IS_CHAN_108A(c))
        strlcpy(name, "IEEE 802.11Ta", IFNAMSIZ);
    else if (IEEE80211_IS_CHAN_TURBO(c))
        strlcpy(name, "IEEE 802.11T", IFNAMSIZ);
    else if (IEEE80211_IS_CHAN_ANYG(c)) {
        if (wlan_get_param(vap, IEEE80211_FEATURE_PUREG))
            strlcpy(name, "IEEE802.11g only", IFNAMSIZ);
        else
            strlcpy(name, "IEEE 802.11g", IFNAMSIZ);
    }
    else if (IEEE80211_IS_CHAN_A(c))
        strlcpy(name, "IEEE 802.11a", IFNAMSIZ);
    else if (IEEE80211_IS_CHAN_B(c))
        strlcpy(name, "IEEE 802.11b", IFNAMSIZ);
    else if (IEEE80211_IS_CHAN_11NG(c))
        strlcpy(name, "IEEE 802.11ng", IFNAMSIZ);
    else if (IEEE80211_IS_CHAN_11NA(c))
        strlcpy(name, "IEEE 802.11na", IFNAMSIZ);
    else if (IEEE80211_IS_CHAN_11AC(c))
        strlcpy(name, "IEEE 802.11ac", IFNAMSIZ);
    else
        strlcpy(name, "IEEE 802.11", IFNAMSIZ);
    /* XXX FHSS */
    return 0;
}

/*
* Units are in db above the noise floor. That means the
* rssi values reported in the tx/rx descriptors in the
* driver are the SNR expressed in db.
*
* If you assume that the noise floor is -95, which is an
* excellent assumption 99.5 % of the time, then you can
* derive the absolute signal level (i.e. -95 + rssi).
* There are some other slight factors to take into account
* depending on whether the rssi measurement is from 11b,
* 11g, or 11a.   These differences are at most 2db and
* can be documented.
*
* NB: various calculations are based on the orinoco/wavelan
*     drivers for compatibility
*/
static void
set_quality(struct iw_quality *iq, u_int rssi)
{
    if(rssi >= 42)
        iq->qual = 94 ;
    else if(rssi >= 30)
        iq->qual = 85 + ((94-85)*(rssi-30) + (42-30)/2) / (42-30) ;
    else if(rssi >= 5)
        iq->qual = 5 + ((rssi - 5) * (85-5) + (30-5)/2) / (30-5) ;
    else if(rssi >= 1)
        iq->qual = rssi ;
    else
        iq->qual = 0 ;

    iq->noise = 161;        /* -95dBm */
    iq->level = iq->noise + rssi ;
    iq->updated = 0xf;
}

static struct iw_statistics *
    ieee80211_iw_getstats(struct net_device *dev)
{
    osif_dev *osnetdev = ath_netdev_priv(dev);
    wlan_if_t vap = osnetdev->os_if;
    struct iw_statistics *is = &osnetdev->os_iwstats;
    wlan_rssi_info rssi_info;
    struct ieee80211_stats *iv_stats = wlan_get_stats(vap);
    const struct ieee80211_mac_stats *iv_mac_stats = wlan_mac_stats(vap, 0);

#ifdef ATH_SUPPORT_HTC
    struct ieee80211com *ic = vap->iv_ic;

    if ((!ic) ||
        (ic && ic->ic_delete_in_progress)){
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : #### delete is in progress, ic %p \n", __func__, ic);

        if (ic)
            return is;
        else
            return NULL;
    }
#endif

    wlan_getrssi(vap, &rssi_info, WLAN_RSSI_RX);
    set_quality(&is->qual, rssi_info.avg_rssi);
    is->status = osnetdev->is_up;
    is->discard.nwid = iv_stats->is_rx_wrongbss
        + iv_stats->is_rx_ssidmismatch;
    is->discard.code = iv_mac_stats->ims_rx_wepfail
        + iv_mac_stats->ims_rx_decryptcrc;
    is->discard.fragment = 0;
    is->discard.retries = 0;
    is->discard.misc = 0;

    is->miss.beacon = 0;

    return is;
}


/******************************************************************************/
/*!
**  \brief Set Operating mode and frequency
**
**  -- Enter Detailed Description --
**
**  \param param1 Describe Parameter 1
**  \param param2 Describe Parameter 2
**  \return Describe return value, or N/A for void
*/

static int
ieee80211_ioctl_siwfreq(struct net_device *dev,
    struct iw_request_info *info,
    struct iw_freq *freq, char *extra)
{
    osif_dev *osnetdev = ath_netdev_priv(dev);
    wlan_if_t vap = osnetdev->os_if;
    int i;

    debug_print_ioctl(dev->name, SIOCSIWFREQ, "siwfreq") ;
    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "siwfreq\n");

    if (freq->e > 1)
        return -EINVAL;
    /*
    * Necessary to cast, to properly interpret negative channel numbers
    */
    if (freq->e == 1)
        i = (u_int8_t)wlan_mhz2ieee(osnetdev->os_devhandle, freq->m / 100000, 0);
    else
        i = freq->m;

    return ieee80211_ucfg_set_freq(vap, i);
}

static int
ieee80211_ioctl_giwfreq(struct net_device *dev,
    struct iw_request_info *info,
    struct iw_freq *freq, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    wlan_chan_t chan;

    debug_print_ioctl(dev->name, SIOCGIWFREQ, "giwfreq") ;
    if (dev->flags & (IFF_UP | IFF_RUNNING)) {
        chan = wlan_get_bss_channel(vap);
    } else {
        chan = wlan_get_current_channel(vap, true);
    }

    if (chan != IEEE80211_CHAN_ANYC) {
        freq->m = chan->ic_freq * 100000;
    } else {
        freq->m = 0;
    }
    freq->e = 1;


    return 0;
}

static int
ieee80211_ioctl_siwessid(struct net_device *dev,
    struct iw_request_info *info,
    struct iw_point *data, char *ssid)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    ieee80211_ssid   tmpssid;

    debug_print_ioctl(dev->name, SIOCSIWESSID, "siwessid") ;

    OS_MEMZERO(&tmpssid, sizeof(ieee80211_ssid));

    if (data->flags == 0)
    {     /* ANY */
        tmpssid.ssid[0] = '\0';
        tmpssid.len = 0;
    }
    else
    {
        if (data->length > IEEE80211_NWID_LEN)
            data->length = IEEE80211_NWID_LEN;

        tmpssid.len = data->length;
        OS_MEMCPY(tmpssid.ssid, ssid, data->length);
    }

    return ieee80211_ucfg_set_essid(vap, &tmpssid);
}

static int
ieee80211_ioctl_giwessid(struct net_device *dev,
    struct iw_request_info *info,
    struct iw_point *data, char *essid)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    ieee80211_ssid ssidlist[1];
    int des_nssid;
    int error = 0;

    debug_print_ioctl(dev->name, SIOCGIWESSID, "giwessid");

    error = ieee80211_ucfg_get_essid(vap, ssidlist, &des_nssid);

    if(error)
        return error;

    data->flags = 1;        /* active */
    if ((des_nssid > 0) || (ssidlist[0].len > 0))
    {
        data->length = ssidlist[0].len;
        OS_MEMCPY(essid, ssidlist[0].ssid, ssidlist[0].len);
    }

    return 0;
}

/*
* Get a key index from a request.  If nothing is
* specified in the request we use the current xmit
* key index.  Otherwise we just convert the index
* to be base zero.
*/
static int
getiwkeyix(wlan_if_t vap, const struct iw_point* erq, u_int16_t *kix)
{
    int kid;

    kid = erq->flags & IW_ENCODE_INDEX;
    if (kid < 1 || kid > IEEE80211_WEP_NKID)
    {
        kid = wlan_get_default_keyid(vap);
        if (kid == IEEE80211_KEYIX_NONE)
            kid = 0;
    }
    else
        --kid;
    if (0 <= kid && kid < IEEE80211_WEP_NKID)
    {
        *kix = kid;
        return 0;
    }
    else
        return -EINVAL;
}

static const u_int8_t ieee80211broadcastaddr[IEEE80211_ADDR_LEN] =
{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/*
 * If authmode = IEEE80211_AUTH_OPEN, script apup would skip authmode setup.
 * Do default authmode setup here for OPEN mode.
 */
static int siwencode_wep(struct net_device *dev)
{
    osif_dev            *osifp = ath_netdev_priv(dev);
    wlan_if_t           vap    = osifp->os_if;
    int                 error  = 0;
    u_int               nmodes = 1;
    ieee80211_auth_mode modes[1];

    osifp->authmode = IEEE80211_AUTH_OPEN;

    modes[0] = IEEE80211_AUTH_OPEN;
    error = wlan_set_authmodes(vap, modes, nmodes);
    if (error == 0 ) {
        error = wlan_set_param(vap, IEEE80211_FEATURE_PRIVACY, 0);
        osifp->uciphers[0] = osifp->mciphers[0] = IEEE80211_CIPHER_NONE;
        osifp->u_count = osifp->m_count = 1;
    }

    return IS_UP(dev) ? -osif_vap_init(dev, RESCAN) : 0;
}

static int
ieee80211_ioctl_siwencode(struct net_device *dev,
    struct iw_request_info *info,
    struct iw_point *erq, char *keybuf)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;

    debug_print_ioctl(dev->name, SIOCSIWENCODE, "siwencode") ;

    return ieee80211_ucfg_set_encode(vap, erq->length, erq->flags, keybuf);
}

static int
ieee80211_ioctl_giwencode(struct net_device *dev,
    struct iw_request_info *info,
    struct iw_point *erq, char *key)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    ieee80211_keyval k;
    u_int16_t kid;
    int error;
    u_int8_t *macaddr;
    debug_print_ioctl(dev->name, SIOCGIWENCODE, "giwencode") ;
    if (wlan_get_param(vap,IEEE80211_FEATURE_PRIVACY))
    {
        error = getiwkeyix(vap, erq, &kid);
        if (error != 0)
            return error;
        macaddr = (u_int8_t *)ieee80211broadcastaddr;
        k.keydata = key;
        error = wlan_get_key(vap, kid, macaddr, &k, erq->length);
        if (error != 0)
            return error;
        /* XXX no way to return cipher/key type */

        erq->flags = kid + 1;           /* NB: base 1 */
        if (erq->length > k.keylen)
            erq->length = k.keylen;
        erq->flags |= IW_ENCODE_ENABLED;
    }
    else
    {
        erq->length = 0;
        erq->flags = IW_ENCODE_DISABLED;
    }
    if (wlan_get_param(vap,IEEE80211_FEATURE_DROP_UNENC))
        erq->flags |= IW_ENCODE_RESTRICTED;
    else
        erq->flags |= IW_ENCODE_OPEN;
    return 0;
}

static int
ieee80211_ioctl_giwrange(struct net_device *dev,
    struct iw_request_info *info,
    struct iw_point *data, char *extra)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    wlan_dev_t ic = wlan_vap_get_devhandle(vap);
    struct iw_range *range = (struct iw_range *) extra;
    wlan_chan_t *chans;
    int nchans,  nrates;
    u_int8_t reported[IEEE80211_CHAN_BYTES];    /* XXX stack usage? */
    u_int8_t *rates;
    int i;
    int step = 0;
    u_int32_t txpowlimit;

    debug_print_ioctl(dev->name, SIOCGIWRANGE, "giwrange") ;
    data->length = sizeof(struct iw_range);
    memset(range, 0, sizeof(struct iw_range));

    /* TODO: could fill num_txpower and txpower array with
    * something; however, there are 128 different values.. */
    /* txpower (128 values, but will print out only IW_MAX_TXPOWER) */
#if WIRELESS_EXT >= 10
        txpowlimit = wlan_get_param(vap, IEEE80211_TXPOWER);
    range->num_txpower = (txpowlimit >= 8) ? IW_MAX_TXPOWER : txpowlimit;
    step = txpowlimit / (2 * (IW_MAX_TXPOWER - 1));

    range->txpower[0] = 0;
    for (i = 1; i < IW_MAX_TXPOWER; i++)
        range->txpower[i] = (txpowlimit/2)
            - (IW_MAX_TXPOWER - i - 1) * step;
#endif


    range->txpower_capa = IW_TXPOW_DBM;

    if (osifp->os_opmode == IEEE80211_M_STA ||
        osifp->os_opmode == IEEE80211_M_IBSS ||
        osifp->os_opmode == IEEE80211_M_P2P_CLIENT) {
        range->min_pmp = 1 * 1024;
        range->max_pmp = 65535 * 1024;
        range->min_pmt = 1 * 1024;
        range->max_pmt = 1000 * 1024;
        range->pmp_flags = IW_POWER_PERIOD;
        range->pmt_flags = IW_POWER_TIMEOUT;
        range->pm_capa = IW_POWER_PERIOD | IW_POWER_TIMEOUT |
            IW_POWER_UNICAST_R | IW_POWER_ALL_R;
    }

    range->we_version_compiled = WIRELESS_EXT;
    range->we_version_source = 13;

    range->retry_capa = IW_RETRY_LIMIT;
    range->retry_flags = IW_RETRY_LIMIT;
    range->min_retry = 0;
    range->max_retry = 255;

    chans = (wlan_chan_t *)OS_MALLOC(osifp->os_handle,
                        sizeof(wlan_chan_t) * IEEE80211_CHAN_MAX, GFP_KERNEL);
    if (chans == NULL)
        return ENOMEM;
    nchans = wlan_get_channel_list(ic, IEEE80211_MODE_AUTO,
                                    chans, IEEE80211_CHAN_MAX);
    range->num_channels = nchans;
    range->num_frequency = 0;

    memset(reported, 0, sizeof(reported));
    for (i = 0; i < nchans; i++)
    {
        const wlan_chan_t c = chans[i];
        /* discard if previously reported (e.g. b/g) */
        if (isclr(reported, c->ic_ieee))
        {
            setbit(reported, c->ic_ieee);
            range->freq[range->num_frequency].i = c->ic_ieee;
            range->freq[range->num_frequency].m =
                c->ic_freq * 100000;
            range->freq[range->num_frequency].e = 1;
            if (++range->num_frequency == IW_MAX_FREQUENCIES) {
                break;
            }
        }
    }
    OS_FREE(chans);

    /* Max quality is max field value minus noise floor */
    range->max_qual.qual  = 0xff - 161;
#if WIRELESS_EXT >= 19
    /* XXX: This should be updated to use the current noise floor. */
    /* These are negative full bytes.
    * Min. quality is noise + 1 */
    range->max_qual.updated |= IW_QUAL_DBM;
    range->max_qual.level = -95 + 1;
    range->max_qual.noise = -95;
#else
    /* Values larger than the maximum are assumed to be absolute */
    range->max_qual.level = 0;
    range->max_qual.noise = 0;
#endif
    range->sensitivity = 3;

    range->max_encoding_tokens = IEEE80211_WEP_NKID;
    /* XXX query driver to find out supported key sizes */
    range->num_encoding_sizes = 3;
    range->encoding_size[0] = 5;        /* 40-bit */
    range->encoding_size[1] = 13;       /* 104-bit */
    range->encoding_size[2] = 16;       /* 128-bit */

    rates = (u_int8_t *)OS_MALLOC(osifp->os_handle, IEEE80211_RATE_MAXSIZE, GFP_KERNEL);
    if (rates == NULL)
        return ENOMEM;
    /* XXX this only works for station mode */
    if (wlan_get_bss_rates(vap, rates, IEEE80211_RATE_MAXSIZE, &nrates) == 0) {
        range->num_bitrates = nrates;
        if (range->num_bitrates > IW_MAX_BITRATES)
            range->num_bitrates = IW_MAX_BITRATES;
        for (i = 0; i < range->num_bitrates; i++)
        {
            range->bitrate[i] = (rates[i] * 1000000) / 2;
        }
    }
    OS_FREE(rates);


    /* estimated maximum TCP throughput values (bps) */
    range->throughput = 5500000;

    range->min_rts = 0;
    range->max_rts = 2347;
    range->min_frag = 256;
    range->max_frag = IEEE80211_FRAGMT_THRESHOLD_MAX;

#if WIRELESS_EXT >= 17
    /* Event capability (kernel) */
    IW_EVENT_CAPA_SET_KERNEL(range->event_capa);

    /* Event capability (driver) */
    if (osifp->os_opmode == IEEE80211_M_STA ||
        osifp->os_opmode == IEEE80211_M_IBSS ||
        osifp->os_opmode == IEEE80211_M_AHDEMO ||
        osifp->os_opmode == IEEE80211_M_P2P_CLIENT) {
        /* for now, only ibss, ahdemo, sta has this cap */
        IW_EVENT_CAPA_SET(range->event_capa, SIOCGIWSCAN);
    }

    if (osifp->os_opmode == IEEE80211_M_STA ||
        osifp->os_opmode == IEEE80211_M_P2P_CLIENT) {
        /* for sta only */
        IW_EVENT_CAPA_SET(range->event_capa, SIOCGIWAP);
        IW_EVENT_CAPA_SET(range->event_capa, IWEVREGISTERED);
        IW_EVENT_CAPA_SET(range->event_capa, IWEVEXPIRED);
    }

    /* this is used for reporting replay failure, which is used by the different encoding schemes */
    IW_EVENT_CAPA_SET(range->event_capa, IWEVCUSTOM);
#endif

#if WIRELESS_EXT >= 18
    /* report supported WPA/WPA2 capabilities to userspace */
    range->enc_capa = IW_ENC_CAPA_WPA | IW_ENC_CAPA_WPA2 |
                IW_ENC_CAPA_CIPHER_TKIP | IW_ENC_CAPA_CIPHER_CCMP;
#endif

    return 0;
}

#if ATH_SUPPORT_IWSPY
/* Add handler for SIOCSIWSPY/SIOCGIWSPY */
/*
 * Return the pointer to the spy data in the driver.
 * Because this is called on the Rx path via wireless_spy_update(),
 * we want it to be efficient...
 */
static struct iw_spy_data *ieee80211_get_spydata(struct net_device *dev)
{
	osif_dev  *osifp = ath_netdev_priv(dev);

	return &osifp->spy_data;
}

static int
ieee80211_ioctl_siwspy(struct net_device *dev,
		       struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct iw_spy_data  *spydata = ieee80211_get_spydata(dev);
	struct sockaddr     *address = (struct sockaddr *) extra;

	/* Make sure driver is not buggy or using the old API */
	if(!spydata)
		return -EOPNOTSUPP;

	/* Disable spy collection while we copy the addresses.
	 * While we copy addresses, any call to wireless_spy_update()
	 * will NOP. This is OK, as anyway the addresses are changing. */
	spydata->spy_number = 0;

	/* Are there are addresses to copy? */
	if(wrqu->data.length > 0) {
		int i;

		/* Copy addresses */
		for(i = 0; i < wrqu->data.length; i++)
			memcpy(spydata->spy_address[i], address[i].sa_data,
			       ETH_ALEN);
		/* Reset stats */
		memset(spydata->spy_stat, 0,
		       sizeof(struct iw_quality) * IW_MAX_SPY);

#if 0
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s() spydata %p, num %d\n", __func__, spydata, wrqu->data.length);
		for (i = 0; i < wrqu->data.length; i++)
			QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_DEBUG
			       "%02X:%02X:%02X:%02X:%02X:%02X \n",
			       spydata->spy_address[i][0],
			       spydata->spy_address[i][1],
			       spydata->spy_address[i][2],
			       spydata->spy_address[i][3],
			       spydata->spy_address[i][4],
			       spydata->spy_address[i][5]);
#endif
	}

	/* Enable addresses */
	spydata->spy_number = wrqu->data.length;

	return 0;
}

static int
ieee80211_ioctl_giwspy(struct net_device *dev,
		       struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
    struct iw_spy_data  *spydata = ieee80211_get_spydata(dev);
	struct sockaddr     *address = (struct sockaddr *) extra;
	int			        i;

	/* Make sure driver is not buggy or using the old API */
	if(!spydata)
		return -EOPNOTSUPP;

	wrqu->data.length = spydata->spy_number;

	/* Copy addresses. */
	for(i = 0; i < spydata->spy_number; i++) 	{
		memcpy(address[i].sa_data, spydata->spy_address[i], ETH_ALEN);
		address[i].sa_family = AF_UNIX;
	}
	/* Copy stats to the user buffer (just after). */
	if(spydata->spy_number > 0)
		memcpy(extra  + (sizeof(struct sockaddr) *spydata->spy_number),
		       spydata->spy_stat,
		       sizeof(struct iw_quality) * spydata->spy_number);
	/* Reset updated flags. */
	for(i = 0; i < spydata->spy_number; i++)
		spydata->spy_stat[i].updated &= ~IW_QUAL_ALL_UPDATED;
	return 0;
}
#endif

static int
ieee80211_ioctl_siwmode(struct net_device *dev,
    struct iw_request_info *info,
    __u32 *mode, char *extra)
{
    osif_dev *osnetdev = ath_netdev_priv(dev);
    struct ifmediareq imr;
    int valid = 0;

	if (osnetdev->is_delete_in_progress)
		return -EINVAL;

    debug_print_ioctl(dev->name, SIOCSIWMODE, "siwmode") ;
    memset(&imr, 0, sizeof(imr));
    osnetdev->os_media.ifm_status(dev, &imr);

    if (imr.ifm_active & IFM_IEEE80211_HOSTAP)
        valid = (*mode == IW_MODE_MASTER);
#if WIRELESS_EXT >= 15
    else if (imr.ifm_active & IFM_IEEE80211_MONITOR)
        valid = (*mode == IW_MODE_MONITOR);
#endif
    else if (imr.ifm_active & IFM_IEEE80211_ADHOC)
        valid = (*mode == IW_MODE_ADHOC);
    else if (imr.ifm_active & IFM_IEEE80211_WDS)
        valid = (*mode == IW_MODE_REPEAT);
    else
        valid = (*mode == IW_MODE_INFRA);

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %s: imr.ifm_active=%d, new mode=%d, valid=%d \n",
            __func__, imr.ifm_active, *mode, valid);

    return valid ? 0 : -EINVAL;
}

static int
ieee80211_ioctl_giwmode(struct net_device *dev,
    struct iw_request_info *info,
    __u32 *mode, char *extra)
{
    struct ifmediareq imr;
    osif_dev *osnetdev = ath_netdev_priv(dev);

    debug_print_ioctl(dev->name, SIOCGIWMODE, "giwmode") ;
    memset(&imr, 0, sizeof(imr));
    osnetdev->os_media.ifm_status(dev, &imr);

    if (imr.ifm_active & IFM_IEEE80211_HOSTAP)
        *mode = IW_MODE_MASTER;
#if WIRELESS_EXT >= 15
    else if (imr.ifm_active & IFM_IEEE80211_MONITOR)
        *mode = IW_MODE_MONITOR;
#endif
    else if (imr.ifm_active & IFM_IEEE80211_ADHOC)
        *mode = IW_MODE_ADHOC;
    else if (imr.ifm_active & IFM_IEEE80211_WDS)
        *mode = IW_MODE_REPEAT;
    else
        *mode = IW_MODE_INFRA;
    return 0;
}

static int
ieee80211_ioctl_siwpower(struct net_device *dev,
    struct iw_request_info *info,
    struct iw_param *wrq, char *extra)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    struct ieee80211com *ic = vap->iv_ic;
    int ret;

    if (wrq->disabled)
    {
        if (ic->ic_flags & IEEE80211_F_PMGTON)
        {
            ic->ic_flags &= ~IEEE80211_F_PMGTON;
            goto done;
        }
        return 0;
    }

    if ((ic->ic_caps & IEEE80211_C_PMGT) == 0)
        return -EOPNOTSUPP;
    switch (wrq->flags & IW_POWER_MODE)
    {
    case IW_POWER_UNICAST_R:
    case IW_POWER_ALL_R:
    case IW_POWER_ON:
        ic->ic_flags |= IEEE80211_F_PMGTON;
        break;
    default:
        return -EINVAL;
    }
    if (wrq->flags & IW_POWER_TIMEOUT)
    {
        ic->ic_holdover = IEEE80211_MS_TO_TU(wrq->value);
        ic->ic_flags |= IEEE80211_F_PMGTON;
    }
    if (wrq->flags & IW_POWER_PERIOD)
    {
        ic->ic_lintval = IEEE80211_MS_TO_TU(wrq->value);
        ic->ic_flags |= IEEE80211_F_PMGTON;
    }
done:
    if (IS_UP(dev)) {
        ic->ic_reset_start(ic, 0);
        ret = ic->ic_reset(ic);
        ic->ic_reset_end(ic, 0);
        return -ret;
    }
    return 0;
}

static int
ieee80211_ioctl_giwpower(struct net_device *dev,
    struct iw_request_info *info,
    struct iw_param *rrq, char *extra)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    struct ieee80211com *ic = vap->iv_ic;

    rrq->disabled = (ic->ic_flags & IEEE80211_F_PMGTON) == 0;
    if (!rrq->disabled)
    {
        switch (rrq->flags & IW_POWER_TYPE)
        {
        case IW_POWER_TIMEOUT:
            rrq->flags = IW_POWER_TIMEOUT;
            rrq->value = IEEE80211_TU_TO_MS(ic->ic_holdover);
            break;
        case IW_POWER_PERIOD:
            rrq->flags = IW_POWER_PERIOD;
            rrq->value = IEEE80211_TU_TO_MS(ic->ic_lintval);
            break;
        }
        rrq->flags |= IW_POWER_ALL_R;
    }
    return 0;
}



struct waplistreq
{
    wlan_if_t vap;
    struct sockaddr addr[IW_MAX_AP];
    struct iw_quality qual[IW_MAX_AP];
    int i;
};

static int
waplist_cb(void *arg, wlan_scan_entry_t se)
{
    struct waplistreq *req = arg;
    int i = req->i;
    wlan_if_t vap = req->vap;
    enum ieee80211_opmode opmode = wlan_vap_get_opmode(vap);
    u_int8_t *se_macaddr = wlan_scan_entry_macaddr(se);
    u_int8_t *se_bssid = wlan_scan_entry_bssid(se);
    u_int8_t se_rssi = wlan_scan_entry_rssi(se);

    if (i >= IW_MAX_AP)
        return 0;
    req->addr[i].sa_family = ARPHRD_ETHER;
    if (opmode == IEEE80211_M_HOSTAP)
        IEEE80211_ADDR_COPY(req->addr[i].sa_data, se_macaddr);
    else
        IEEE80211_ADDR_COPY(req->addr[i].sa_data, se_bssid);

    set_quality(&req->qual[i], se_rssi);

    req->i = i+1;

    return 0;
}

static int
ieee80211_ioctl_iwaplist(struct net_device *dev,
    struct iw_request_info *info,
    struct iw_point *data, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct waplistreq *req;
    debug_print_ioctl(dev->name, SIOCGIWAPLIST, "iwaplist") ;

    req = (struct waplistreq *)OS_MALLOC(osifp->os_handle, sizeof(*req), GFP_KERNEL);
    if (req == NULL)
        return -ENOMEM;
    req->vap = vap;
    req->i = 0;
    wlan_scan_table_iterate(vap, waplist_cb, req);

    data->length = req->i;
    OS_MEMCPY(extra, &req->addr, req->i*sizeof(req->addr[0]));
    data->flags = 1;        /* signal quality present (sort of) */
    OS_MEMCPY(extra + req->i*sizeof(req->addr[0]), &req->qual,
        req->i*sizeof(req->qual[0]));
    OS_FREE(req);

    return 0;

}

#ifdef SIOCGIWSCAN
static int
ieee80211_ioctl_siwscan(struct net_device *dev,
    struct iw_request_info *info,
    struct iw_point *data, char *extra)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    ieee80211_scan_params *scan_params;
    IEEE80211_SCAN_PRIORITY scan_priority = IEEE80211_SCAN_PRIORITY_LOW;
#ifdef ATH_SUPPORT_P2P
    enum ieee80211_opmode opmode = osifp->os_opmode;
#else
    enum ieee80211_opmode opmode = wlan_vap_get_opmode(vap);
#endif
    ieee80211_ssid    *ssid_list;
    int               n_ssid;
    u_int8_t          *opt_ie;
    u_int32_t         length=0;
    struct ieee80211com *ic = vap->iv_ic;
#if QCA_LTEU_SUPPORT
    u_int8_t scan_type = IEEE80211_SCAN_PASSIVE;
    int scan_num_channels = 0;
    u_int32_t scan_chan_list[IW_MAX_FREQUENCIES] = {0};
    int min_channel_time = 0;
    int max_channel_time = 0;
    int mu_in_progress, scan_in_progress;
#endif
    struct ieee80211_node   *ni = NULL;
    int time_elapsed = OS_SIWSCAN_TIMEOUT;

    debug_print_ioctl(dev->name, SIOCSIWSCAN, "siwscan") ;
    /*
    * XXX don't permit a scan to be started unless we
    * know the device is ready.  For the moment this means
    * the device is marked up as this is the required to
    * initialize the hardware.  It would be better to permit
    * scanning prior to being up but that'll require some
    * changes to the infrastructure.
    */
    if (!(dev->flags & IFF_UP)
#ifdef QCA_PARTNER_PLATFORM
        || (vap->iv_list_scanning)
#endif
        ) {
        return -EINVAL;     /* XXX */
    }

    /* Scan is not supported in monitor mode */
    if (IEEE80211_M_MONITOR == opmode)
        return -EINVAL;

    opt_ie = OS_MALLOC(osifp->os_handle, sizeof(u_int8_t) * IEEE80211_MAX_OPT_IE,
                       GFP_KERNEL);
    if (opt_ie == NULL)
        return -ENOMEM;

    ssid_list = OS_MALLOC(osifp->os_handle, sizeof(ieee80211_ssid) * IEEE80211_SCAN_MAX_SSID,
                          GFP_KERNEL);
    if (ssid_list == NULL) {
        OS_FREE (opt_ie);
        return -ENOMEM;
    }

#if QCA_LTEU_SUPPORT
    if (ic->ic_nl_handle) {
        spin_lock_bh(&ic->ic_nl_handle->mu_lock);
        mu_in_progress = atomic_read(&ic->ic_nl_handle->mu_in_progress);
        scan_in_progress = atomic_read(&ic->ic_nl_handle->scan_in_progress);
        if (mu_in_progress || scan_in_progress) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Currently doing %s %d\n", __func__,
                   mu_in_progress ? "MU" : "scan", mu_in_progress ?
                   ic->ic_nl_handle->mu_id : ic->ic_nl_handle->scan_id);
            spin_unlock_bh(&ic->ic_nl_handle->mu_lock);
            OS_FREE(opt_ie);
            OS_FREE(ssid_list);
            return -EBUSY;
        }

        atomic_set(&ic->ic_nl_handle->scan_in_progress, 1);
        ic->ic_nl_handle->scan_id = 0;
        spin_unlock_bh(&ic->ic_nl_handle->mu_lock);
        ic->ic_nl_handle->force_vdev_restart = 1;
    }
#endif

#ifdef QCA_PARTNER_PLATFORM
    vap->iv_list_scanning = 1;
#endif
    /* XXX always manual... */
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
        "%s: active scan request\n", __func__);
    preempt_scan(dev, PREEMPT_SCAN_MAX_GRACE, PREEMPT_SCAN_MAX_WAIT);

    /* Increase timeout value for EIR since a rpt scan itself takes 12 seconds */
    if(ieee80211_ic_enh_ind_rpt_is_set(vap->iv_ic)) {
        if (ic->ic_is_mode_offload(ic)) {
            scan_priority = IEEE80211_SCAN_PRIORITY_HIGH;
        }
        time_elapsed = OS_SIWSCAN_TIMEOUT * SIWSCAN_TIME_ENH_IND_RPT;
    }
    if ((time_after(OS_GET_TICKS(), osifp->os_last_siwscan + time_elapsed)) && (osifp->os_giwscan_count == 0)) {
        osifp->os_last_siwscan = OS_GET_TICKS();
    }

#if WIRELESS_EXT > 17
    if (data) {
        struct iw_scan_req req;
        int copyLength;
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
            "%s: SCAN_THIS_ESSID requested\n", __func__);
        if (data->length > sizeof req) {
            copyLength = sizeof req;
        } else {
            copyLength = data->length;
        }
        OS_MEMZERO(&req, sizeof req);
        if (__xcopy_from_user(&req, data->pointer, copyLength))
        {
#ifdef QCA_PARTNER_PLATFORM
            vap->iv_list_scanning = 0;
#endif
            OS_FREE(opt_ie);
            OS_FREE(ssid_list);
#if QCA_LTEU_SUPPORT
            if (ic->ic_nl_handle) {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Unable to start scan\n", __func__);
                atomic_set(&ic->ic_nl_handle->scan_in_progress, 0);
            }
#endif
            return -EFAULT;
        }

        if (data->flags & IW_SCAN_THIS_ESSID) {
            OS_MEMCPY(&ssid_list[0].ssid, req.essid, sizeof(req.essid));
            ssid_list[0].len = req.essid_len;
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
                    "%s: requesting scan of essid '%s'\n", __func__, ssid_list[0].ssid);
            n_ssid = 1;
        }

#if QCA_LTEU_SUPPORT
        if (data->flags & IW_SCAN_THIS_FREQ) {
            int i, j;
            scan_num_channels = req.num_channels;
            if (scan_num_channels > IW_MAX_FREQUENCIES)
                scan_num_channels = IW_MAX_FREQUENCIES;
            for (i = 0, j = 0; i < scan_num_channels; i++) {
                if (req.channel_list[i].e > 1)
                    continue;
                if (req.channel_list[i].e == 1)
                    scan_chan_list[j] = (u_int8_t)wlan_mhz2ieee(osifp->os_devhandle,
                                                       req.channel_list[i].m / 100000, 0);
                else
                    scan_chan_list[j] = req.channel_list[i].m;
                if (scan_chan_list[j] > 0)
                    j++;
            }
            scan_num_channels = j;
        }
        scan_type = req.scan_type == IW_SCAN_TYPE_ACTIVE ?
                                         IEEE80211_SCAN_ACTIVE : IEEE80211_SCAN_PASSIVE;
#define TU_TO_MS(_tu)        (((_tu) * 1024) / 1000)
        if (scan_num_channels) {
            min_channel_time = TU_TO_MS(req.min_channel_time);
            max_channel_time = TU_TO_MS(req.max_channel_time);
        }
#endif
    }
#endif

    if (!data || !(data->flags & IW_SCAN_THIS_ESSID)) {
#if QCA_LTEU_SUPPORT
        if (ic->ic_nl_handle) {
            /**
             * Following parameters hard coded to ensure that during AP scan
             * initiated in lteu mode, the probe requests are broadcasted with
             * wildcard SSIDs and not the AP's own SSID.
             */
            n_ssid = 1;
            ssid_list[0].len = 0;
        }
        else {
#endif
            n_ssid = wlan_get_desired_ssidlist(vap, ssid_list, IEEE80211_SCAN_MAX_SSID);
#if QCA_LTEU_SUPPORT
        }
#endif
    }

    /* Fill scan parameter */
    scan_params = (ieee80211_scan_params *)
    OS_MALLOC(osifp->os_handle, sizeof(*scan_params), GFP_KERNEL);
    if (scan_params == NULL)
    {
#ifdef QCA_PARTNER_PLATFORM
    	vap->iv_list_scanning = 0;
#endif
        OS_FREE(opt_ie);
        OS_FREE(ssid_list);
#if QCA_LTEU_SUPPORT
        if (ic->ic_nl_handle) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Unable to start scan\n", __func__);
            atomic_set(&ic->ic_nl_handle->scan_in_progress, 0);
        }
#endif
        return -ENOMEM;
    }
    OS_MEMZERO(scan_params,sizeof(ieee80211_scan_params));
#if defined(UMAC_SUPPORT_RESMGR) && defined(ATH_SUPPORT_P2P) && defined(ATH_SUPPORT_HTC)
    /* If resource management intervene scan behavior in P2P concurrent and will force back to home
       channel even in disconnect state and have large scan time for split driver. Force beacon
       check count to 0 to pass beacon count check to reduce total scan time. */
    {
        bool connected_flag = false;

        if(osifp->sm_handle && wlan_connection_sm_is_connected(osifp->sm_handle))
            connected_flag = true;
        wlan_set_default_scan_parameters(vap,scan_params,opmode,true,true,
                                         connected_flag,true,n_ssid,ssid_list,0);
    }
#else
    wlan_set_default_scan_parameters(vap,scan_params,opmode,true,true,true,true,n_ssid,ssid_list,0);
#endif

    switch (opmode)
    {
    case IEEE80211_M_HOSTAP:
#if QCA_LTEU_SUPPORT
        if (scan_type == IEEE80211_SCAN_PASSIVE) {
            scan_params->flags = IEEE80211_SCAN_PASSIVE | IEEE80211_SCAN_ALLBANDS;
            /* XXX tunables */
            if (min_channel_time && max_channel_time) {
                scan_params->min_dwell_time_passive = min_channel_time;
                scan_params->max_dwell_time_passive = max_channel_time;
                scan_params->min_dwell_time_active = min_channel_time;
                scan_params->max_dwell_time_active = max_channel_time;
            } else {
                scan_params->min_dwell_time_passive = vap->min_dwell_time_passive;
                scan_params->max_dwell_time_passive = vap->max_dwell_time_passive;
            }
        } else {
            scan_params->flags = IEEE80211_SCAN_ACTIVE | IEEE80211_SCAN_ALLBANDS;
            /* XXX tunables */
            if (min_channel_time && max_channel_time) {
                scan_params->min_dwell_time_passive = min_channel_time;
                scan_params->max_dwell_time_passive = max_channel_time;
                scan_params->min_dwell_time_active = min_channel_time;
                scan_params->max_dwell_time_active = max_channel_time;
            }
        }
#else
        scan_params->flags = IEEE80211_SCAN_PASSIVE | IEEE80211_SCAN_ALLBANDS;
        /* XXX tunables */
        scan_params->min_dwell_time_passive = vap->min_dwell_time_passive;

#endif

        if (osifp->is_scan_chevent) {
            scan_params->flags |= IEEE80211_SCAN_CHAN_EVENT;
        }

        scan_params->type = IEEE80211_SCAN_FOREGROUND;
	scan_params->max_dwell_time_passive  = (vap->max_dwell_time_passive > MAX_DWELL_TIME_PASSIVE ) ? MAX_DWELL_TIME_PASSIVE : vap->max_dwell_time_passive ;
#if QCA_LTEU_SUPPORT
        if (scan_num_channels > 0) {
            scan_params->num_channels = scan_num_channels;
            scan_params->chan_list = scan_chan_list;
        }

        if (vap->scan_repeat_probe_time != (u_int32_t)-1)
            scan_params->repeat_probe_time = vap->scan_repeat_probe_time;
        if (vap->scan_rest_time != (u_int32_t)-1)
            scan_params->min_rest_time = scan_params->max_rest_time = vap->scan_rest_time;
        if (vap->scan_idle_time != (u_int32_t)-1)
            scan_params->idle_time = vap->scan_idle_time;
        if (vap->scan_probe_delay != (u_int32_t)-1)
            scan_params->probe_delay = vap->scan_probe_delay;
#endif

        /* For 11ac offload - if the passive scan dwell time is
         * greater than beacon interval target reduces
         * passive dwell time. To avoid that increasing scan
         * priority to high so that both TBTT won't override
         * passive scan priority in this case.
         */
        scan_priority = IEEE80211_SCAN_PRIORITY_HIGH;

#if QCA_LTEU_SUPPORT
        if (ic->ic_nl_handle) {
            wlan_scan_table_flush(vap);
        }
#endif
        break;

    /* TODO:properly scan parameter depend on opmode */
    case IEEE80211_M_P2P_DEVICE:
    default:
        if (opmode == IEEE80211_M_P2P_CLIENT) {
            scan_params->min_dwell_time_active = scan_params->max_dwell_time_active = 104;
            scan_params->repeat_probe_time =  30;
        } else {
            scan_params->min_dwell_time_active = scan_params->max_dwell_time_active = 100;
        }

         if (ieee80211_ic_enh_ind_rpt_is_set(vap->iv_ic)) {
            scan_params->flags |= IEEE80211_SCAN_FORCED;
            scan_params->min_rest_time = MIN_REST_TIME ;
            scan_params->max_rest_time = MAX_REST_TIME ;
            scan_params->min_dwell_time_active = MIN_DWELL_TIME_ACTIVE ;
            scan_params->max_dwell_time_active = MAX_DWELL_TIME_ACTIVE ;
            scan_params->type = IEEE80211_SCAN_BACKGROUND;
        } else if (osifp->sm_handle && wlan_connection_sm_is_connected(osifp->sm_handle)) {
            scan_params->type = IEEE80211_SCAN_BACKGROUND;
        } else {
            scan_params->type = IEEE80211_SCAN_FOREGROUND;
        }
        scan_params->flags &= ~IEEE80211_SCAN_ACTIVE;
        scan_params->flags |= IEEE80211_SCAN_ALLBANDS | IEEE80211_SCAN_PASSIVE;
        if (!wlan_mlme_get_optie(vap, opt_ie, &length, IEEE80211_MAX_OPT_IE)) {
            scan_params->ie_data = opt_ie;
            scan_params->ie_len = length;
        }
        break;
    }

    if (osifp->os_scan_band != OSIF_SCAN_BAND_ALL) {
        scan_params->flags &= ~IEEE80211_SCAN_ALLBANDS;
        if (osifp->os_scan_band == OSIF_SCAN_BAND_2G_ONLY)
            scan_params->flags |= IEEE80211_SCAN_2GHZ;
        else if (osifp->os_scan_band == OSIF_SCAN_BAND_5G_ONLY)
            scan_params->flags |= IEEE80211_SCAN_5GHZ;
        else {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
                                "%s: unknow scan band, scan all bands.\n", __func__);
            scan_params->flags |= IEEE80211_SCAN_ALLBANDS;
        }
    }

    /* Enable Half / Quarter rate scan for STA vap if enabled */
    if (opmode == IEEE80211_M_STA) {
       if (scan_type == IEEE80211_SCAN_ACTIVE) {
                scan_params->flags |= IEEE80211_SCAN_ACTIVE;
                scan_params->flags &= ~IEEE80211_SCAN_PASSIVE;
        }
        else if (scan_type == IEEE80211_SCAN_PASSIVE) {
                scan_params->flags |= IEEE80211_SCAN_PASSIVE;
                scan_params->flags &= ~IEEE80211_SCAN_ACTIVE;
        }
        if (ic->ic_chanbwflag & IEEE80211_CHAN_HALF) {
            scan_params->flags |= IEEE80211_SCAN_HALF_RATE;
        } else if (ic->ic_chanbwflag & IEEE80211_CHAN_QUARTER) {
            scan_params->flags |= IEEE80211_SCAN_QUARTER_RATE;
        }
    }

    if (wlan_get_param(vap, IEEE80211_FEATURE_WDS) && !ieee80211_ic_enh_ind_rpt_is_set(vap->iv_ic)) {
        /* For WDS station - always set the multiple_ports_active to false,
         * so that scanner won't come back to home channel for every foreign
         * channel change. Otherwise the scanning time is considerably increases
         * in case of Repeater case. In Repater case - AP vap always follows STA vap
         * channel - so no need to come back to home channel during scanning
         */
        scan_params->multiple_ports_active = false;
    }
    osifp->os_last_siwscan = OS_GET_TICKS();
    /* If active scan, then probe response should be given more weight than beacon.
     * Disable IEs in beacon from overriding IEs in probe response */
    if(scan_params->flags & IEEE80211_SCAN_ACTIVE) {
        /* If active scan and no SSID is provided, enable BCAST_PROBE to send probe
         * req with bcast ssid */
        if(scan_params->num_ssid == 0) {
            scan_params->flags |= IEEE80211_SCAN_ADD_BCAST_PROBE;
        }
        wlan_set_device_param(ic, IEEE80211_DEVICE_OVERRIDE_SCAN_PROBERESPONSE_IE, 0);
    }


    if(vap->iv_bss)
    {
        ni = vap->iv_bss;
    }

    if(ic->ic_use_custom_chan_list !=0 && vap->iv_opmode == IEEE80211_M_STA)
    {
        /*Use ic_custom_chan_list when vap is associated*/
        if(ni && ni->ni_associd >0 && ic->ic_custom_chanlist_assoc_size)
        {
            scan_params->chan_list = (u_int32_t *)ic->ic_custom_chan_list_associated;
            scan_params->num_channels = ic->ic_custom_chanlist_assoc_size;
        }
        else
        {
            if(ic->ic_custom_chanlist_nonassoc_size)
            {
                scan_params->chan_list = (u_int32_t *)ic->ic_custom_chan_list_nonassociated;
                scan_params->num_channels = ic->ic_custom_chanlist_nonassoc_size;
            }
        }
        /*flush the old scan results*/
        wlan_scan_table_flush(vap);
    }

    if (wlan_scan_start(vap, scan_params, osifp->scan_requestor, scan_priority, &(osifp->scan_id)) != 0 ) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
                "%s: Issue a scan fail.\n",
                __func__);
        wlan_set_device_param(ic, IEEE80211_DEVICE_OVERRIDE_SCAN_PROBERESPONSE_IE, 1);
#ifdef QCA_PARTNER_PLATFORM
        vap->iv_list_scanning = 0;
#endif
#if QCA_LTEU_SUPPORT
        if (ic->ic_nl_handle) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Unable to start scan\n", __func__);
            atomic_set(&ic->ic_nl_handle->scan_in_progress, 0);
        }
#endif
    } else {
#if QCA_LTEU_SUPPORT
        if (ic->ic_nl_handle) {
            int i;
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Scan started, min duration %d, max duration %d, num channels %d, "
                   "repeat probe %d, rest %d, idle %d, scan probe %d, channels -", __func__,
                    min_channel_time, max_channel_time, scan_num_channels, vap->scan_repeat_probe_time,
                    vap->scan_rest_time, vap->scan_idle_time, vap->scan_probe_delay);
            for (i = 0; i < scan_num_channels; i++)
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %d", scan_chan_list[i]);
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ", type %s\n", scan_type == IW_SCAN_TYPE_ACTIVE ? "active" : "passive");
        }
#endif
    }

    OS_FREE(opt_ie);
    OS_FREE(ssid_list);
    OS_FREE(scan_params);

    return 0;
}
#if ATH_SUPPORT_WAPI
static const char wapi_leader[] = "wapi_ie=";
#endif

#if WIRELESS_EXT > 14
/*
* Encode a WPA or RSN information element as a custom
* element using the hostap format.
*/
static u_int
encode_ie(void *buf, size_t bufsize,
    const u_int8_t *ie, size_t ielen,
    const char *leader, size_t leader_len)
{
    u_int8_t *p;
    int i;

    if (bufsize < leader_len)
        return 0;
    p = buf;
    OS_MEMCPY(p, leader, leader_len);
    bufsize -= leader_len;
    p += leader_len;
    for (i = 0; i < ielen && bufsize > 2; i++) {
        /* %02x might not be exactly 2 chars but could be 3 or more.
         * Use snprintf instead. */
        p += snprintf(p, 3, "%02x", ie[i]);
        bufsize -= 2;
    }
    return (i == ielen ? p - (u_int8_t *)buf : 0);
}
#endif /* WIRELESS_EXT > 14 */

#ifdef ATH_SUPPORT_P2P
#define WLAN_EID_VENDOR_SPECIFIC 221
#define P2P_IE_VENDOR_TYPE 0x506f9a09
#define WPA_GET_BE32(a) ((((u32) (a)[0]) << 24) | (((u32) (a)[1]) << 16) | \
                        (((u32) (a)[2]) << 8) | ((u32) (a)[3]))

int get_p2p_ie(const u8 *ies, u_int16_t ies_len, u_int8_t *buf,
                u_int16_t *buf_len)
{
    const u8 *end, *pos, *ie;

    *buf_len = 0;
    pos = ies;
    end = ies + ies_len;
    ie = NULL;

    while (pos + 1 < end) {
        if (pos + 2 + pos[1] > end)
            return -1;
        if (pos[0] == WLAN_EID_VENDOR_SPECIFIC && pos[1] >= 4 &&
            WPA_GET_BE32(&pos[2]) == P2P_IE_VENDOR_TYPE) {
            ie = pos;
            break;
        }
        pos += 2 + pos[1];
    }

    if (ie == NULL)
        return -1; /* No specified vendor IE found */

    /*
    * There may be multiple vendor IEs in the message, so need to
    * concatenate their data fields.
    */
    while (pos + 1 < end) {
        if (pos + 2 + pos[1] > end)
            break;
        if (pos[0] == WLAN_EID_VENDOR_SPECIFIC && pos[1] >= 4 &&
            WPA_GET_BE32(&pos[2]) == P2P_IE_VENDOR_TYPE) {
            OS_MEMCPY(buf,  pos, pos[1]);
            *buf_len += pos[1];
            buf += pos[1];
        }
        pos += 2 + pos[1];
    }

    return 0;
}


#endif /* ATH_SUPPORT_P2P */
#endif  /* SIOCGIWSCAN */

struct iwscanreq
{
    struct net_device *dev;
    char            *current_ev;
    char            *end_buf;
    char            *start_ev;
    int         mode;
    struct iw_request_info *info;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,27)
#define CURRENT_EV info, current_ev
#else
#define CURRENT_EV current_ev
#endif

typedef struct chan_occupancy {
    int val1;
    int val2;
    int val3;
}CHAN_OCCUPANCY_T;

static int
giwscan_cb(void *arg, wlan_scan_entry_t se)
{
    struct iwscanreq *req = arg;
    struct net_device *dev = req->dev;
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    char *current_ev = req->current_ev;
    char *end_buf = req->end_buf;
#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,27)
    struct iw_request_info *info = req->info;
#endif

#if WIRELESS_EXT > 14
#define MAX_IE_LENGTH 30 + 255 * 2 /* "xxx_ie=" + encoded IE */
    char buf[MAX_IE_LENGTH];
#ifndef IWEVGENIE
    static const char rsn_leader[] = "rsn_ie=";
    static const char wpa_leader[] = "wpa_ie=";
#endif /* IWEVGENIE */
#endif  /* WIRELESS_EXT > 14 */

#ifdef ATH_WPS_IE
#if WIRELESS_EXT <= 20
    static const char wps_leader[] = "wps_ie=";
#endif /* WIRELESS_EXT <= 20 */

#ifdef ATH_SUPPORT_P2P
    static const char p2p_ie_leader[] = "p2p_ie=";
    u_int8_t *p2p_buf, *ie_buf=NULL;
    u_int16_t p2p_buf_len = 0, ie_buf_len=0;
#endif /* ATH_SUPPORT_P2P */
    u_int8_t *se_wps_ie = wlan_scan_entry_wps(se);
#endif /* ATH_WPS_IE */

    char *last_ev;
    struct iw_event iwe;
    char *current_val;
    int j;
    u_int8_t *se_wpa_ie = wlan_scan_entry_wpa(se);
#if ATH_SUPPORT_WAPI
    u_int8_t *se_wapi_ie = wlan_scan_entry_wapi(se);
#endif /* ATH_SUPPORT_WAPI */
    u_int8_t *se_rsn_ie = wlan_scan_entry_rsn(se);
    u_int8_t *se_macaddr = wlan_scan_entry_macaddr(se);
    u_int8_t *se_bssid = wlan_scan_entry_bssid(se);
    enum ieee80211_opmode opmode = wlan_vap_get_opmode(vap);
    u_int8_t se_ssid_len;
    u_int8_t *se_ssid = wlan_scan_entry_ssid(se, &se_ssid_len);
    enum ieee80211_opmode se_opmode = wlan_scan_entry_bss_type(se);
    wlan_chan_t se_chan = wlan_scan_entry_channel(se);
    u_int8_t se_rssi = wlan_scan_entry_rssi(se);
    u_int8_t se_privacy = wlan_scan_entry_privacy(se);
    u_int8_t *se_rates = wlan_scan_entry_rates(se);
    u_int8_t *se_xrates = wlan_scan_entry_xrates(se);
    u_int16_t se_intval = wlan_scan_entry_beacon_interval(se);
    u_int32_t se_dtimperiod = wlan_scan_entry_dtimperiod(se);
#if QCA_LTEU_SUPPORT
    u_int16_t se_sequencenum = 0;
    u_int64_t tsf = 0;
    u_int8_t  se_tsf_timestamp[8];
#endif
    u_int8_t *se_wmeparam = wlan_scan_entry_wmeparam_ie(se);
    u_int8_t *se_wmeinfo = wlan_scan_entry_wmeinfo_ie(se);
    u_int8_t *se_ath_ie = wlan_scan_entry_athcaps(se);
    struct ieee80211_ie_htinfo htinfo;
    struct ieee80211_ie_htinfo_cmn *pie;
    u_int8_t *se_htinfo = wlan_scan_entry_htinfo(se);
    u_int8_t *se_vhtop = wlan_scan_entry_vhtop(se);
	u_int32_t se_phymode = wlan_scan_entry_phymode(se);
#if QCA_LTEU_SUPPORT
    OS_MEMSET(se_tsf_timestamp,0,8);
    if (vap->iv_ic->ic_nl_handle) {
        se_sequencenum = wlan_scan_entry_sequence_number(se);
        wlan_scan_entry_tsf(se,se_tsf_timestamp);
        tsf =  (   ((u_int64_t)se_tsf_timestamp[0])     | ((u_int64_t)se_tsf_timestamp[1]<<8)
                 | ((u_int64_t)se_tsf_timestamp[2]<<16) | ((u_int64_t)se_tsf_timestamp[3]<<24)
                 | ((u_int64_t)se_tsf_timestamp[4]<<32) | ((u_int64_t)se_tsf_timestamp[5]<<40)
                 | ((u_int64_t)se_tsf_timestamp[6]<<48) | ((u_int64_t)se_tsf_timestamp[7]<<56) );
    }
#endif
    req->start_ev = current_ev;

    if (current_ev >= end_buf) {
        return E2BIG;
    }
    /* WPA/!WPA sort criteria */


#if ATH_SUPPORT_WAPI
    if ((req->mode != 0) ^ ((se_wpa_ie != NULL) || (se_rsn_ie != NULL) || (se_wapi_ie != NULL))) {
        return 0;
    }
#else   /* ATH_SUPPORT_WAPI */
    if ((req->mode != 0) ^ ((se_wpa_ie != NULL) || (se_rsn_ie != NULL) )) {
        return 0;
    }
#endif /* ATH_SUPPORT_WAPI */

    OS_MEMZERO(&iwe, sizeof(iwe));
    last_ev = current_ev;
    iwe.cmd = SIOCGIWAP;
    iwe.u.ap_addr.sa_family = ARPHRD_ETHER;
    if (opmode == IEEE80211_M_HOSTAP) {
        IEEE80211_ADDR_COPY(iwe.u.ap_addr.sa_data, se_macaddr);
    } else {
        IEEE80211_ADDR_COPY(iwe.u.ap_addr.sa_data, se_bssid);
    }
    current_ev = iwe_stream_add_event(CURRENT_EV,
        end_buf, &iwe, IW_EV_ADDR_LEN);

    /* We ran out of space in the buffer. */
    if (last_ev == current_ev) {
        return E2BIG;
    }

    OS_MEMZERO(&iwe, sizeof(iwe));
    last_ev = current_ev;
    iwe.cmd = SIOCGIWESSID;
    iwe.u.data.flags = 1;
    {
        iwe.u.data.length = se_ssid_len;
        if (se_ssid != NULL) {
            current_ev = iwe_stream_add_point(CURRENT_EV,
               end_buf, &iwe, (char *) se_ssid);
        }
    }

    /* We ran out of space in the buffer. */
    if (last_ev == current_ev) {
        return E2BIG;
    }

    if ((se_opmode == IEEE80211_M_STA) || (se_opmode == IEEE80211_M_IBSS)) {
        OS_MEMZERO(&iwe, sizeof(iwe));
        last_ev = current_ev;
        iwe.cmd = SIOCGIWMODE;
        iwe.u.mode = se_opmode == IEEE80211_M_STA ?
            IW_MODE_MASTER : IW_MODE_ADHOC;
        current_ev = iwe_stream_add_event(CURRENT_EV,
            end_buf, &iwe, IW_EV_UINT_LEN);
        /* We ran out of space in the buffer. */
        if (last_ev == current_ev) {
            return E2BIG;
        }
    }

    OS_MEMZERO(&iwe, sizeof(iwe));
    last_ev = current_ev;
    iwe.cmd = SIOCGIWFREQ;
    iwe.u.freq.m = wlan_channel_frequency(se_chan) * 100000;
    iwe.u.freq.e = 1;
    current_ev = iwe_stream_add_event(CURRENT_EV,
        end_buf, &iwe, IW_EV_FREQ_LEN);

    /* We ran out of space in the buffer. */
    if (last_ev == current_ev) {
        return E2BIG;
    }

    OS_MEMZERO(&iwe, sizeof(iwe));
    last_ev = current_ev;
    iwe.cmd = IWEVQUAL;
    set_quality(&iwe.u.qual, se_rssi);
    current_ev = iwe_stream_add_event(CURRENT_EV,
        end_buf, &iwe, IW_EV_QUAL_LEN);

    /* We ran out of space in the buffer. */
    if (last_ev == current_ev) {
        return E2BIG;
    }

    OS_MEMZERO(&iwe, sizeof(iwe));
    last_ev = current_ev;
    iwe.cmd = SIOCGIWENCODE;
    if (se_privacy) {
        iwe.u.data.flags = IW_ENCODE_ENABLED | IW_ENCODE_NOKEY;
    } else {
        iwe.u.data.flags = IW_ENCODE_DISABLED;
    }
    iwe.u.data.length = 0;
    current_ev = iwe_stream_add_point(CURRENT_EV, end_buf, &iwe, "");

    /* We ran out of space in the buffer. */
    if (last_ev == current_ev) {
        return E2BIG;
    }

    OS_MEMZERO(&iwe, sizeof(iwe));
    last_ev = current_ev;
    iwe.cmd = SIOCGIWRATE;
    current_val = current_ev + IW_EV_LCP_LEN;
    /* NB: not sorted, does it matter? */
    if (se_rates != NULL) {
        for (j = 0; j < se_rates[1]; j++) {
            int r = se_rates[2+j] & IEEE80211_RATE_VAL;
            if (r != 0) {
                iwe.u.bitrate.value = r * (1000000 / 2);
                current_val = iwe_stream_add_value(CURRENT_EV,
                    current_val, end_buf, &iwe,
                    IW_EV_PARAM_LEN);
            }
        }
    }
    if (se_xrates != NULL) {
        for (j = 0; j < se_xrates[1]; j++) {
            int r = se_xrates[2+j] & IEEE80211_RATE_VAL;
            if (r != 0) {
                iwe.u.bitrate.value = r * (1000000 / 2);
                current_val = iwe_stream_add_value(CURRENT_EV,
                    current_val, end_buf, &iwe,
                    IW_EV_PARAM_LEN);
            }
        }
    }
    /* remove fixed header if no rates were added */
    if ((current_val - current_ev) > IW_EV_LCP_LEN) {
        current_ev = current_val;
    } else {
        /* We ran out of space in the buffer. */
        if (last_ev == current_ev)
            return E2BIG;
    }

#if WIRELESS_EXT > 14
    OS_MEMZERO(&iwe, sizeof(iwe));
    last_ev = current_ev;
    iwe.cmd = IWEVCUSTOM;
    snprintf(buf, sizeof(buf), "bcn_int=%d", se_intval);
    iwe.u.data.length = strlen(buf);
    current_ev = iwe_stream_add_point(CURRENT_EV, end_buf, &iwe, buf);

    /* We ran out of space in the buffer. */
    if (last_ev == current_ev) {
        return E2BIG;
    }

    if (se_rsn_ie != NULL) {
    last_ev = current_ev;

#ifdef IWEVGENIE

        OS_MEMZERO(&iwe, sizeof(iwe));
        if ((se_rsn_ie[1] + 2) > MAX_IE_LENGTH) {
            return E2BIG;
        }
        OS_MEMCPY(buf, se_rsn_ie, se_rsn_ie[1] + 2);
        iwe.cmd = IWEVGENIE;
        iwe.u.data.length = se_rsn_ie[1] + 2;

#else /* IWEVGENIE */
        OS_MEMZERO(&iwe, sizeof(iwe));
        iwe.cmd = IWEVCUSTOM;
        if (se_rsn_ie[0] == IEEE80211_ELEMID_RSN) {
            iwe.u.data.length = encode_ie(buf, sizeof(buf),
                se_rsn_ie, se_rsn_ie[1] + 2,
                rsn_leader, sizeof(rsn_leader)-1);
        }
#endif  /* IWEVGENIE */
        if (iwe.u.data.length != 0) {
            current_ev = iwe_stream_add_point(CURRENT_EV, end_buf,
                &iwe, buf);

            /* We ran out of space in the buffer */
            if (last_ev == current_ev) {
            return E2BIG;
            }
        }

    }
#ifdef ATH_SUPPORT_WAPI
    if (se_wapi_ie != NULL) {
      last_ev = current_ev;

        OS_MEMZERO(&iwe, sizeof(iwe));
        iwe.cmd = IWEVCUSTOM;
        iwe.u.data.length = encode_ie(buf, sizeof(buf), se_wapi_ie, se_wapi_ie[1] + 2, wapi_leader, sizeof(wapi_leader)-1);

        if (iwe.u.data.length != 0) {
            current_ev = iwe_stream_add_point(CURRENT_EV, end_buf,
                &iwe, buf);

            /* We ran out of space in the buffer */
            if (last_ev == current_ev) {
              return E2BIG;
            }
        }

    }
#endif /*ATH_SUPPORT_WAPI*/

    if (se_wpa_ie != NULL) {
    last_ev = current_ev;
#ifdef IWEVGENIE
        OS_MEMZERO(&iwe, sizeof(iwe));
        if ((se_wpa_ie[1] + 2) > MAX_IE_LENGTH) {
            return E2BIG;
        }
        OS_MEMCPY(buf, se_wpa_ie, se_wpa_ie[1] + 2);
        iwe.cmd = IWEVGENIE;
        iwe.u.data.length = se_wpa_ie[1] + 2;
#else   /* IWEVGENIE */
        OS_MEMZERO(&iwe, sizeof(iwe));
        iwe.cmd = IWEVCUSTOM;

            iwe.u.data.length = encode_ie(buf, sizeof(buf),
                se_wpa_ie, se_wpa_ie[1]+2,
                wpa_leader, sizeof(wpa_leader)-1);
#endif /* IWEVGENIE */
        if (iwe.u.data.length != 0) {
            current_ev = iwe_stream_add_point(CURRENT_EV, end_buf,
                &iwe, buf);

            /* We ran out of space in the buffer. */
            if (last_ev == current_ev) {
            return E2BIG;
            }
        }

    }
    if (se_wmeparam != NULL) {
        static const char wme_leader[] = "wme_ie=";

        OS_MEMZERO(&iwe, sizeof(iwe));
        last_ev = current_ev;
        iwe.cmd = IWEVCUSTOM;
        iwe.u.data.length = encode_ie(buf, sizeof(buf),
            se_wmeparam, se_wmeparam[1]+2,
            wme_leader, sizeof(wme_leader)-1);
        if (iwe.u.data.length != 0) {
            current_ev = iwe_stream_add_point(CURRENT_EV, end_buf,
                &iwe, buf);
        }

        /* We ran out of space in the buffer. */
        if (last_ev == current_ev) {
            return E2BIG;
        }
    } else if (se_wmeinfo != NULL) {
        static const char wme_leader[] = "wme_ie=";

        OS_MEMZERO(&iwe, sizeof(iwe));
        last_ev = current_ev;
        iwe.cmd = IWEVCUSTOM;
        iwe.u.data.length = encode_ie(buf, sizeof(buf),
            se_wmeinfo, se_wmeinfo[1]+2,
            wme_leader, sizeof(wme_leader)-1);
        if (iwe.u.data.length != 0) {
            current_ev = iwe_stream_add_point(CURRENT_EV, end_buf,
                &iwe, buf);
        }

        /* We ran out of space in the buffer. */
        if (last_ev == current_ev) {
            return E2BIG;
        }
    }
	if (se_phymode != 0) {

	char *ieee80211_phymode_str[23] =  {
		"IEEE80211_MODE_AUTO",
		"IEEE80211_MODE_11A",
		"IEEE80211_MODE_11B",
		"IEEE80211_MODE_11G",
		"IEEE80211_MODE_FH",
		"IEEE80211_MODE_TURBO_A",
		"IEEE80211_MODE_TURBO_G",
		"IEEE80211_MODE_11NA_HT20",
		"IEEE80211_MODE_11NG_HT20",
		"IEEE80211_MODE_11NA_HT40PLUS",
		"IEEE80211_MODE_11NA_HT40MINUS",
		"IEEE80211_MODE_11NG_HT40PLUS",
		"IEEE80211_MODE_11NG_HT40MINUS",
		"IEEE80211_MODE_11NG_HT40",
		"IEEE80211_MODE_11NA_HT40",
		"IEEE80211_MODE_11AC_VHT20",
		"IEEE80211_MODE_11AC_VHT40PLUS",
		"IEEE80211_MODE_11AC_VHT40MINUS",
		"IEEE80211_MODE_11AC_VHT40",
		"IEEE80211_MODE_11AC_VHT80",
		"IEEE80211_MODE_11AC_VHT160",
		"IEEE80211_MODE_11AC_VHT80_80",
		(char *)NULL,
	};


	 OS_MEMZERO(&iwe, sizeof(iwe));
	 last_ev = current_ev;
	 iwe.cmd = IWEVCUSTOM;
	 snprintf(buf, sizeof(buf), "phy_mode=%s", (se_phymode<22)?ieee80211_phymode_str[se_phymode]:"IEEE80211_MODE_11B");
	 iwe.u.data.length = strlen(buf);
	 current_ev = iwe_stream_add_point(CURRENT_EV, end_buf, &iwe, buf);


	 /* We ran out of space in the buffer. */
	 if (last_ev == current_ev) {
		 return E2BIG;
	 }
	}
    if (se_ath_ie != NULL) {
        static const char ath_leader[] = "ath_ie=";

        OS_MEMZERO(&iwe, sizeof(iwe));
        last_ev = current_ev;
        iwe.cmd = IWEVCUSTOM;
        iwe.u.data.length = encode_ie(buf, sizeof(buf),
            se_ath_ie, se_ath_ie[1]+2,
            ath_leader, sizeof(ath_leader)-1);
        if (iwe.u.data.length != 0) {
            current_ev = iwe_stream_add_point(CURRENT_EV, end_buf,
                &iwe, buf);
        }

        /* We ran out of space in the buffer. */
        if (last_ev == current_ev) {
            return E2BIG;
        }
    }
    if (se_dtimperiod != 0) {
        OS_MEMZERO(&iwe, sizeof(iwe));
        last_ev = current_ev;
        iwe.cmd = IWEVCUSTOM;
        snprintf(buf, sizeof(buf), "dtim_period=%d", se_dtimperiod);
        iwe.u.data.length = strlen(buf);
        current_ev = iwe_stream_add_point(CURRENT_EV, end_buf, &iwe, buf);

        /* We ran out of space in the buffer. */
        if (last_ev == current_ev) {
            return E2BIG;
        }
    }

#ifdef ATH_WPS_IE
    if (se_wps_ie != NULL) {
        last_ev = current_ev;
#if WIRELESS_EXT > 20
        OS_MEMZERO(&iwe, sizeof(iwe));
        if ((se_wps_ie[1] + 2) > MAX_IE_LENGTH) {
            return E2BIG;
        }
        OS_MEMCPY(buf, se_wps_ie, se_wps_ie[1] + 2);
        iwe.cmd = IWEVGENIE;
        iwe.u.data.length = se_wps_ie[1] + 2;
#else   /* WIRELESS_EXT > 20 */
        OS_MEMZERO(&iwe, sizeof(iwe));
        iwe.cmd = IWEVCUSTOM;
        iwe.u.data.length = encode_ie(buf, sizeof(buf),
        se_wps_ie, se_wps_ie[1] + 2,
        wps_leader, sizeof(wps_leader) - 1);
#endif  /* WIRELESS_EXT > 20 */
        if (iwe.u.data.length != 0) {
            current_ev = iwe_stream_add_point(CURRENT_EV, end_buf,
                &iwe, buf);

            /* We ran out of space in the buffer */
            if (last_ev == current_ev) {
                return E2BIG;
            }
        }
    }

#endif /* ATH_WPS_IE */

#ifdef ATH_SUPPORT_P2P
        ie_buf_len = wlan_scan_entry_ie_len(se);

        if (ie_buf_len)
            ie_buf = OS_MALLOC(osifp->os_handle, ie_buf_len,GFP_KERNEL);

        if (ie_buf_len &&
            wlan_scan_entry_copy_ie_data(se, ie_buf, &ie_buf_len) == EOK) {
            p2p_buf = OS_MALLOC(osifp->os_handle, MAX_IE_LENGTH, GFP_KERNEL);
            if (p2p_buf == NULL) {
                if (ie_buf_len)
                    OS_FREE(ie_buf);
                return ENOMEM;
            }
            if (get_p2p_ie(ie_buf, ie_buf_len, p2p_buf, &p2p_buf_len) == 0) {

                last_ev = current_ev;
                OS_MEMZERO(&iwe, sizeof(iwe));
                iwe.cmd = IWEVCUSTOM;
                iwe.u.data.length = encode_ie(buf, sizeof(buf),
                                            p2p_buf, p2p_buf_len,
                                            p2p_ie_leader,
                                            sizeof(p2p_ie_leader) - 1);
                if (iwe.u.data.length != 0) {

                    current_ev = iwe_stream_add_point(CURRENT_EV, end_buf,
                                                    &iwe, buf);

                    if (last_ev == current_ev) {
                        if (ie_buf_len)
                            OS_FREE(ie_buf);
                        OS_FREE(p2p_buf);
                        return E2BIG;
                    }
                }
            }
            OS_FREE(p2p_buf);
        }

        if (ie_buf_len)
            OS_FREE(ie_buf);


#endif /* ATH_SUPPORT_P2P */

        /* Send these IEs only if configured to to do */
        if (vap->iv_send_additional_ies) {
            /*
             * External channel managers such as ICM require the HT Operation
             * Element (stored under HTINFO by the rest of the scan framework)
             * and the VHT Operation Element to gather information about
             * HT/VHT OBSSs and make channel selection decisions.
             *
             * For the HT Operation IE, the Element ID and Length have not
             * been stored by the rest of the existing scan framework. For
             * applications in the upper layer to identify the IE, we need
             * to add these explicitly.
             */
            if (se_htinfo != NULL) {
                htinfo.hi_id = IEEE80211_ELEMID_HTINFO_ANA;
                htinfo.hi_len = sizeof(htinfo) - 2;

                pie = &htinfo.hi_ie;

                OS_MEMCPY(pie, se_htinfo, sizeof(struct ieee80211_ie_htinfo_cmn));
                OS_MEMZERO(&iwe, sizeof(iwe));
                last_ev = current_ev;

#ifdef  IWEVGENIE
                if ((htinfo.hi_len + 2) > MAX_IE_LENGTH) {
                    return E2BIG;
                }

                OS_MEMCPY(buf, &htinfo, sizeof(htinfo));
                iwe.cmd = IWEVGENIE;
                iwe.u.data.length = sizeof(htinfo);

                if (iwe.u.data.length != 0) {
                    current_ev = iwe_stream_add_point(CURRENT_EV, end_buf, &iwe, buf);
                }

                if (last_ev == current_ev) {
                    return E2BIG;
                }
            }
#else       /* IWEVGENIE */
            /* XXX: Add support for shipping HTOP IE without IWEVGENIE if
               required in future */
#error      "Shipping of HTOP IE without IWEVGENIE not currently supported."
#endif      /* IWEVGENIE */

            if (se_vhtop != NULL) {
                last_ev = current_ev;
                OS_MEMZERO(&iwe, sizeof(iwe));

#ifdef  IWEVGENIE
                if ((se_vhtop[1] + 2) > MAX_IE_LENGTH) {
                    return E2BIG;
                }

                OS_MEMCPY(buf, se_vhtop, se_vhtop[1] + 2);
                iwe.cmd = IWEVGENIE;
                iwe.u.data.length = se_vhtop[1] + 2;

                if (iwe.u.data.length != 0) {
                    current_ev = iwe_stream_add_point(CURRENT_EV, end_buf, &iwe, buf);
                }

                if (last_ev == current_ev) {
                    return E2BIG;
                }
            }

#else       /* IWEVGENIE */
            /* XXX: Add support for shipping VHTOP IE without IWEVGENIE if
               required in future */
#error      "Shipping of VHTOP IE without IWEVGENIE not currently supported."
#endif      /* IWEVGENIE */
        }
#if QCA_LTEU_SUPPORT
    if (vap->iv_ic->ic_nl_handle) {
        OS_MEMZERO(&iwe, sizeof(iwe));
        last_ev = current_ev;
        iwe.cmd = IWEVCUSTOM;
        snprintf(buf, sizeof(buf), "timestamp=%llu",tsf);
        iwe.u.data.length = strlen(buf);
        current_ev = iwe_stream_add_point(CURRENT_EV, end_buf, &iwe, buf);

        /* We ran out of space in the buffer. */
        if (last_ev == current_ev) {
            return E2BIG;
        }
        OS_MEMZERO(&iwe, sizeof(iwe));
        last_ev = current_ev;
        iwe.cmd = IWEVCUSTOM;
        snprintf(buf, sizeof(buf), "sequence=%u", se_sequencenum);
        iwe.u.data.length = strlen(buf);
        current_ev = iwe_stream_add_point(CURRENT_EV, end_buf, &iwe, buf);

        /* We ran out of space in the buffer. */
        if (last_ev == current_ev) {
            return E2BIG;
        }
    }
#endif
    req->current_ev = current_ev;

    return 0;
}

static int
ieee80211_ioctl_giwscan(struct net_device *dev,
    struct iw_request_info *info,
    struct iw_point *data, char *extra)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct iwscanreq req;
    int res = 0;
    ieee80211_auth_mode modes[IEEE80211_AUTH_MAX];
    int count, i;
    int time_elapsed = OS_SIWSCAN_TIMEOUT;


    /* Increase timeout value for EIR since a rpt scan itself takes 12 seconds */
    if (ieee80211_ic_enh_ind_rpt_is_set(vap->iv_ic))
        time_elapsed = OS_SIWSCAN_TIMEOUT * SIWSCAN_TIME_ENH_IND_RPT;
    debug_print_ioctl(dev->name, SIOCGIWSCAN, "giwscan") ;

    if (!(osifp->os_opmode == IEEE80211_M_STA ||
        osifp->os_opmode == IEEE80211_M_P2P_DEVICE ||
        osifp->os_opmode == IEEE80211_M_P2P_CLIENT)) {
        /* For station mode - umac connection sm always runs SCAN */
        if (wlan_scan_in_progress(vap) &&
            (time_after(osifp->os_last_siwscan + time_elapsed, OS_GET_TICKS()))) {
	     osifp->os_giwscan_count++;
            return -EAGAIN;
        }
    }

    req.dev = dev;
    req.current_ev = extra;
    req.info = info;
    req.mode = 0;
    if (data->length == 0) {
        req.end_buf = extra + IW_SCAN_MAX_DATA;
    } else {
        req.end_buf = extra + data->length;
    }

    /*
    * Do two passes to insure WPA/non-WPA scan candidates
    * are sorted to the front.  This is a hack to deal with
    * the wireless extensions capping scan results at
    * IW_SCAN_MAX_DATA bytes.  In densely populated environments
    * it's easy to overflow this buffer (especially with WPA/RSN
    * information elements).  Note this sorting hack does not
    * guarantee we won't overflow anyway.
    */
       count = wlan_get_auth_modes(vap, modes, IEEE80211_AUTH_MAX);
    for (i = 0; i < count; i++) {
        if (modes[i] == IEEE80211_AUTH_WPA) {
            req.mode |= 0x1;
        }
        if (modes[i] == IEEE80211_AUTH_RSNA) {
            req.mode |= 0x2;
        }
    }
    res = wlan_scan_table_iterate(vap, giwscan_cb, &req);

    if (res == 0) {
        req.mode = req.mode ? 0 : 0x3;
        res = wlan_scan_table_iterate(vap, giwscan_cb, &req);
    }

    /* if data->length(16-bit) field is 0 then scan results buffer will be capped at 4kb.
     * in normal case where length field usually takes value such as 4kb,8kb..so on the
     * scan results buffer will be capped at 32kb. This is workaround to overcome
     * overflow of length field when allocated memory size crosses 16bit capacity*/
    if (E2BIG == res) {
        if ((2 == sizeof(data->length)) &&
            (!data->length || data->length >= (1U << 15))) {
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Restricting scan results..");
            req.current_ev = req.start_ev;
            res = 0;
       }
    }
    data->length = req.current_ev - extra;

    if (res != 0) {
        return -res;
    }

    osifp->os_giwscan_count = 0;

    return res;
}
#endif /* SIOCGIWSCAN */


/*
    * Convert mode to a media specification.
    */
static int
mode2media(enum ieee80211_phymode mode)
{
        static const u_int media[] = {
            IFM_AUTO,       /* IEEE80211_MODE_AUTO    */
            IFM_IEEE80211_11A,  /* IEEE80211_MODE_11A     */
            IFM_IEEE80211_11B,  /* IEEE80211_MODE_11B     */
            IFM_IEEE80211_11G,  /* IEEE80211_MODE_11G     */
            IFM_IEEE80211_FH,       /* IEEE80211_MODE_FH      */
            0,          /* IEEE80211_MODE_TURBO_A */
            0,          /* IEEE80211_MODE_TURBO_G */
            IFM_IEEE80211_11NA, /* IEEE80211_MODE_11NA_HT20        */
            IFM_IEEE80211_11NG, /* IEEE80211_MODE_11NG_HT20        */
            IFM_IEEE80211_11NA, /* IEEE80211_MODE_11NA_HT40PLUS    */
            IFM_IEEE80211_11NA, /* IEEE80211_MODE_11NA_HT40MINUS   */
            IFM_IEEE80211_11NG, /* IEEE80211_MODE_11NG_HT40PLUS    */
            IFM_IEEE80211_11NG, /* IEEE80211_MODE_11NG_HT40MINUS   */
            };
            return media[mode];
}

/******************************************************************************/
/*!
**  \brief Set operating mode
**
**  -- Enter Detailed Description --
**
**  \param param1 Describe Parameter 1
**  \param param2 Describe Parameter 2
**  \return Describe return value, or N/A for void
*/


/**
 * @brief
 *     - Function description:\n
 *     - iwpriv description:\n
 *         - iwpriv cmd: iwpriv athN mode desired_mode\n
 *           This command will set the current operating mode of the interface.
 *           The argument is a string that defines the desired mode of operation.  The
 *           mode will also affect the configuration of the Radio layer, so this command
 *           should be used when modifying the operating mode of the VAP.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:\n
 *                 -# 11A: Legacy operations in the 802.11a (5 GHz) band
 *                 -# 11B: Legacy operations in the 802.11b (2.4 GHz) band
 *                 -# 11G: 802.11g
 *                 -# 11NAHT20: 802.11n A-band 20 MHz channels
 *                 -# 11NGHT20:	802.11n G-band 20 MHz channels
 *                 -# 11NAHT40PLUS: Select frequency channels higher than the primary
 *                    control channel as the extension channel
 *                 -# 11NAHT40MINUS: Select frequency channels lower than the primary
 *                    control channel as the extension channel
 *                 -# 11NGHT40PLUS: Select frequency channels higher than the primary
 *                    control channel as the extension channel
 *                 -# 11NGHT40MINUS: Select frequency channels lower than the primary
 *                    control channel as the extension channel
 *                 -# 11ACVHT20: 802.11ac A-band 20 MHz
 *                 -# 11ACVHT40: 802.11ac A-Band 40MHz
 *                 -# 11ACVHT80: 802.11ac A-Band 80MHz
 *             - iwpriv restart needed?
 *               Not sure
 *             - iwpriv default value:
 *               Not sure
 */
static int
ieee80211_ioctl_setmode(struct net_device *dev, struct iw_request_info *info,
    void *w, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct iw_point *wri;
    char s[30];      /* big enough */

    debug_print_ioctl(dev->name, IEEE80211_IOCTL_SETMODE, "setmode") ;
    wri = (struct iw_point *) w;
    if (wri->length > sizeof(s))        /* silently truncate */
        wri->length = sizeof(s);
    if (__xcopy_from_user(s, wri->pointer, wri->length))
        return -EFAULT;
    s[sizeof(s)-1] = '\0';          /* insure null termination */

    return ieee80211_ucfg_set_phymode(vap, s, wri->length);
}
#undef IEEE80211_MODE_TURBO_STATIC_A

struct mlmeop {
    struct ieee80211req_mlme *mlme;
    wlan_if_t vap;
};

static void
domlme(void *arg, wlan_node_t node)
{
    struct mlmeop *op = arg;
    switch (op->mlme->im_op) {
    case IEEE80211_MLME_DISASSOC:
        wlan_mlme_disassoc_request(op->vap,wlan_node_getmacaddr(node),op->mlme->im_reason);
        break;
    case IEEE80211_MLME_DEAUTH:
        IEEE80211_DPRINTF(op->vap, IEEE80211_MSG_AUTH, "%s: sending DEAUTH to %s, domlme deauth reason %d\n",
                __func__, ether_sprintf(wlan_node_getmacaddr(node)), op->mlme->im_reason);
        wlan_mlme_deauth_request(op->vap,wlan_node_getmacaddr(node),op->mlme->im_reason);
        break;
    case IEEE80211_MLME_ASSOC:
         wlan_mlme_assoc_resp(op->vap,wlan_node_getmacaddr(node),op->mlme->im_reason, 0, NULL);
         break;
    case IEEE80211_MLME_REASSOC:
         wlan_mlme_assoc_resp(op->vap,wlan_node_getmacaddr(node),op->mlme->im_reason, 1, NULL);
         break;
    default:
        break;
    }
}

/**
 * @brief
 *     - Function description:\n
 *     - iwpriv description:\n
 *         - iwpriv cmd: setmlme\n
 *         Another of the host_apd support commands, this command is used
 *           to perform direct access to the MLME layer in the driver.
 *            This allows an application to start or terminate a specific
 *           association. Note that the MLME_ASSOC sub command only makes
 *           sense for a station (AP wont start an association).  This
 *           command will pass the ieee80211req_mlme structure:\n
 *         struct ieee80211req_mlme {\n
 *         u_int8_t	im_op;		// operation to perform \n
 *          #define	IEEE80211_MLME_ASSOC		1	// associate station\n
 *          #define	IEEE80211_MLME_DISASSOC	    2	// disassociate station\n
 *          #define	IEEE80211_MLME_DEAUTH		3	// deauthenticate station\n
 *          #define	IEEE80211_MLME_AUTHORIZE	4	// authorize station\n
 *          #define	IEEE80211_MLME_UNAUTHORIZE	5	// unauthorize station\n
 *         u_int16_t	im_reason;	// 802.11 reason code\n
 *         u_int8_t	im_macaddr[IEEE80211_ADDR_LEN];\n
 *          };\n
 *          This command has no command line equivalent.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 */
static int
ieee80211_ioctl_setmlme(struct net_device *dev, struct iw_request_info *info,
    void *w, char *extra)
{
    struct ieee80211req_mlme *mlme = (struct ieee80211req_mlme *)extra;
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211com *ic = NULL;
    struct ieee80211_app_ie_t optie;
    struct ieee80211_node *ni = NULL;

    //int force_scan = 0;
    debug_print_ioctl(dev->name, IEEE80211_IOCTL_SETMLME, "setmlme") ;
    ni = ni ; /* to silence compiler */
    if (vap == NULL ) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n %s:%d VAP instance is NULL ifname=%s\n", __func__, __LINE__, dev->name);
        return -EINVAL;
    }

    ic = vap->iv_ic;

    if (!(dev->flags & IFF_UP)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " DEVICE IS DOWN ifname=%s\n", dev->name);
        return -EINVAL;     /* XXX */
    }
    optie.ie = &mlme->im_optie[0];
    optie.length = mlme->im_optie_len;

    switch (mlme->im_op) {
    case IEEE80211_MLME_ASSOC:
	if (ieee80211_dfs_is_ap_cac_timer_running(ic) && (wlan_vap_get_opmode(vap) == IEEE80211_M_STA)) {
	    return -EINVAL;
	}
        /* set dessired bssid when in STA mode accordingly */
        if (wlan_vap_get_opmode(vap) != IEEE80211_M_STA &&
            osifp->os_opmode != IEEE80211_M_P2P_DEVICE &&
            osifp->os_opmode != IEEE80211_M_P2P_CLIENT) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                    "[%s] non sta mode, skip to set bssid\n", __func__);
        } else {
            u_int8_t des_bssid[IEEE80211_ADDR_LEN];

            if (!IS_NULL_ADDR(mlme->im_macaddr)) {
                IEEE80211_ADDR_COPY(des_bssid, &mlme->im_macaddr[0]);
                wlan_aplist_set_desired_bssidlist(vap, 1, &des_bssid);
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "[%s] set desired bssid %02x:%02x:%02x:%02x:%02x:%02x\n",__func__,des_bssid[0],
                        des_bssid[1],des_bssid[2],des_bssid[3],des_bssid[4],des_bssid[5]);
            }
        }

        if (osifp->os_opmode == IEEE80211_M_STA ||
            (u_int8_t)osifp->os_opmode == IEEE80211_M_P2P_GO ||
            (u_int8_t)osifp->os_opmode == IEEE80211_M_P2P_CLIENT ||
	    osifp->os_opmode == IEEE80211_M_IBSS) {
            vap->iv_mlmeconnect=1;
            osif_vap_init(dev, 0);
        }
        else if (osifp->os_opmode ==  IEEE80211_M_HOSTAP) {
            /* NB: the broadcast address means do 'em all */
    	    if (!IEEE80211_ADDR_EQ(mlme->im_macaddr, ieee80211broadcastaddr)) {
                    wlan_mlme_assoc_resp(vap,mlme->im_macaddr,mlme->im_reason, 0, &optie);
    	    } else {
                struct mlmeop iter_arg;
                iter_arg.mlme = mlme;
                iter_arg.vap = vap;
                wlan_iterate_station_list(vap,domlme,&iter_arg);
            }
        }
        else
            return -EINVAL;
        break;
    case IEEE80211_MLME_REASSOC:
        if (osifp->os_opmode == IEEE80211_M_STA ||
            osifp->os_opmode == IEEE80211_M_P2P_GO ||
            osifp->os_opmode == IEEE80211_M_P2P_CLIENT) {
            osif_vap_init(dev, 0);
        }
        else if (osifp->os_opmode ==  IEEE80211_M_HOSTAP) {
            /* NB: the broadcast address means do 'em all */
	    if (!IEEE80211_ADDR_EQ(mlme->im_macaddr, ieee80211broadcastaddr)) {
             wlan_mlme_assoc_resp(vap,mlme->im_macaddr,mlme->im_reason, 1, &optie);
	    } else {
                struct mlmeop iter_arg;
                iter_arg.mlme = mlme;
                iter_arg.vap = vap;
                wlan_iterate_station_list(vap,domlme,&iter_arg);
            }
        }
        else
            return -EINVAL;
        break;
    case IEEE80211_MLME_AUTH_FILS:
    case IEEE80211_MLME_AUTH:
        if (osifp->os_opmode != IEEE80211_M_HOSTAP) {
            return -EINVAL;
        }
        /* NB: ignore the broadcast address */
        if (!IEEE80211_ADDR_EQ(mlme->im_macaddr, ieee80211broadcastaddr)) {
#if UMAC_SUPPORT_FILS
            if(mlme->im_op == IEEE80211_MLME_AUTH_FILS &&
               IEEE80211_VAP_IS_FILS_ENABLED(vap)) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_FILS,
                                  "%s op : 0x%x ie.len : %d mac %s\n",
                                  __func__, mlme->im_op, optie.length,
                                  ether_sprintf(mlme->im_macaddr));
                if(wlan_mlme_auth_fils(vap, mlme)) {
                    qdf_print("%s FILS crypto registeration failed\n",__func__);
                } else {
                    qdf_print("%s FILS crypto registered successfully\n",__func__);
                }
            }
#endif
            wlan_mlme_auth(vap,mlme->im_macaddr,mlme->im_seq,mlme->im_reason, NULL, 0, &optie);
        }
        break;
    case IEEE80211_MLME_DISASSOC:
    case IEEE80211_MLME_DEAUTH:
        switch (osifp->os_opmode) {
            case IEEE80211_M_STA:
            case IEEE80211_M_P2P_CLIENT:
                //    if (mlme->im_op == IEEE80211_MLME_DISASSOC && !osifp->is_p2p_interface) {
                //        return -EINVAL; /*fixme darwin does this, but linux did not before? */
                //    }

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
                if(wlan_mlme_is_stacac_running(vap)) {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "Do not stop the BSS STA CAC is on\n");
                    return -EINVAL;
                } else if (wlan_vap_is_pmf_enabled(vap)) {
                    if (mlme->im_op == IEEE80211_MLME_DEAUTH) {
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH, "%s: sending DEAUTH to %s, mlme deauth reason %d\n",
                                __func__, ether_sprintf(mlme->im_macaddr), mlme->im_reason);
                        wlan_mlme_deauth_request(vap,mlme->im_macaddr,mlme->im_reason);
                    }
                    if (mlme->im_op == IEEE80211_MLME_DISASSOC) {
                        wlan_mlme_disassoc_request(vap,mlme->im_macaddr,mlme->im_reason);
                    }
                } else {
                    osif_vap_stop(dev);
                }
#else
                osif_vap_stop(dev);
#endif
                break;
        case IEEE80211_M_HOSTAP:
        case IEEE80211_M_IBSS:
#if ATH_SUPPORT_DEFERRED_NODE_CLEANUP
            if ( ic && ic->ic_is_mode_offload(ic)){
                /*No need to put  any check for Broadcast as for braodcast ni == NULL */
                if (IEEE80211_ADDR_EQ(mlme->im_macaddr, vap->iv_myaddr)) {
                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Cannot send Disassoc to self \n");
                    return -EINVAL;
                }
                ni = ieee80211_vap_find_node(vap, mlme->im_macaddr);
                if ( ni && (ni != ni->ni_bss_node)) {
                    ni->ni_flags |= IEEE80211_NODE_DELAYED_CLEANUP;
                    /* claim node immediately */
                    ieee80211_free_node(ni);
                }
            }
#endif
            /* the 'break' statement for this case is intentionally removed, to make sure that this fall through next statement */
        case IEEE80211_M_P2P_GO:
            /* NB: the broadcast address means do 'em all */
            if (!IEEE80211_ADDR_EQ(mlme->im_macaddr, ieee80211broadcastaddr)) {
                    wlan_mlme_disassoc_request(vap,mlme->im_macaddr,mlme->im_reason);
            } else {
                if (wlan_vap_is_pmf_enabled(vap)) {
                    if (mlme->im_op == IEEE80211_MLME_DEAUTH) {
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH, "%s: sending DEAUTH to %s, mlme deauth reason %d\n",
                                __func__, ether_sprintf(mlme->im_macaddr), mlme->im_reason);
                        wlan_mlme_deauth_request(vap,mlme->im_macaddr,mlme->im_reason);
                    }
                    if (mlme->im_op == IEEE80211_MLME_DISASSOC) {
                        wlan_mlme_disassoc_request(vap,mlme->im_macaddr,mlme->im_reason);
                    }
                } else {
                    struct mlmeop iter_arg;
                    iter_arg.mlme = mlme;
                    iter_arg.vap = vap;
                    wlan_iterate_station_list(vap,domlme,&iter_arg);
                }
            }
            break;
        default:
            return -EINVAL;
        }
        break;
    case IEEE80211_MLME_AUTHORIZE:
    case IEEE80211_MLME_UNAUTHORIZE:
        if (osifp->os_opmode != IEEE80211_M_HOSTAP &&
            osifp->os_opmode != IEEE80211_M_P2P_GO) {
            return -EINVAL;
        }
        if (mlme->im_op == IEEE80211_MLME_AUTHORIZE) {
            wlan_node_authorize(vap, 1, mlme->im_macaddr);
#if UNIFIED_SMARTANTENNA
            ni = ieee80211_find_node(&vap->iv_ic->ic_sta, mlme->im_macaddr);
            if (ni) {
                if (ni->ni_ic->radio_id == RADIO_ID_DIRECT_ATTACH) { /* for direct attach */
                    ieee80211_smart_ant_node_connect(ni, NULL);
                }
                ieee80211_free_node(ni);
            }
#endif

#if ATH_BAND_STEERING
            ni = ieee80211_find_node(&vap->iv_ic->ic_sta, mlme->im_macaddr);
            if (ni) {
                ieee80211_bsteering_send_node_associated_event(vap, ni);
                ieee80211_free_node(ni);
            }
#endif

#if ATH_SUPPORT_HYFI_ENHANCEMENTS
            /* send node authorized event */
            ni = ieee80211_find_node(&vap->iv_ic->ic_sta, mlme->im_macaddr);
            if (ni) {
                ald_assoc_notify(vap, mlme->im_macaddr, ALD_ACTION_ASSOC);
                ieee80211_free_node(ni);
            }
#endif

        } else {
            wlan_node_authorize(vap, 0, mlme->im_macaddr);
        }
        break;
    case IEEE80211_MLME_CLEAR_STATS:
        break;

    case IEEE80211_MLME_STOP_BSS:
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
        if(wlan_mlme_is_stacac_running(vap)) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "Do not stop the BSS STA CAC is on\n");
            return -EINVAL;
        } else {
            osif_vap_stop(dev);
        }
#else
        osif_vap_stop(dev);
#endif
        break;
    default:
        return -EINVAL;
    }
    return 0;
}

void ieee80211_ioctl_send_action_frame_cb(wlan_if_t vaphandle, wbuf_t wbuf,
        void *arg, u_int8_t *dst_addr,
        u_int8_t *src_addr, u_int8_t *bssid, ieee80211_xmit_status *ts)
{
    osif_dev *osifp = (void *) arg;
    struct net_device *dev = osifp->netdev;
    wlan_if_t vap = osifp->os_if;
    u_int8_t *buf;

    struct ieee80211_send_action_cb *act_cb;
    u_int8_t *frm;
    u_int16_t frm_len;
    size_t tlen;
    union iwreq_data wrqu;

    (void) vap; //if IEEE80211_DPRINTF is not defined, shut up errors.

    frm = wbuf_header(wbuf);
    frm_len = wbuf_get_pktlen(wbuf);
    tlen = frm_len + sizeof(*act_cb);

    buf = OS_MALLOC(osifp->os_handle, tlen, GFP_KERNEL);
    if (!buf) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                              "%s - cb alloc failed\n", __func__);
        return;
    }
    act_cb = (void *) buf;

    memcpy(act_cb->dst_addr, dst_addr, IEEE80211_ADDR_LEN);
    memcpy(act_cb->src_addr, src_addr, IEEE80211_ADDR_LEN);
    memcpy(act_cb->bssid, bssid, IEEE80211_ADDR_LEN);
    act_cb->ack = (NULL == ts) ? 1 : (ts->ts_flags == 0);

    memcpy(&buf[sizeof(*act_cb)], frm, frm_len);

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s len=%d ack=%d dst=%s",
                      __func__, tlen,act_cb->ack, ether_sprintf(dst_addr));
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                              "src=%s ",ether_sprintf(src_addr));
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                              "bssid=%s \n ",ether_sprintf(bssid));
    /*
     * here we queue the data for later user delivery
     */
    {
        wlan_p2p_event event;
        event.u.rx_frame.frame_len = tlen;
        event.u.rx_frame.frame_buf = buf;
        osif_p2p_rx_frame_handler(osifp, &event, IEEE80211_EV_P2P_SEND_ACTION_CB);
    }
    memset(&wrqu, 0, sizeof(wrqu));
    wrqu.data.flags = IEEE80211_EV_P2P_SEND_ACTION_CB;

    WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wrqu, buf);
    OS_FREE(buf);
}


/**
 * @brief
 *     - Function description: Set parameters
 *     - iwpriv description:
 *         - iwpriv cmd: iwpriv athN chwidth ChannelWidth\n
 *           This command sets the Channel Width field in the AP beacons
 *           High Throughput Information Element (HT IE) or
 *           Very High Throughput IE when applicable.
 *             - iwpriv category: ht40/20 coexistence
 *             - iwpriv arguments: \n
 * 0 - Use the device settings\n
 * 1 - 20 MHz\n
 * 2 - 20/40 MHz\n
 * 3 - 20/40/80 MHz\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 0
 *             .
 *         - iwpriv cmd: iwpriv athN chextoffset ExtensionChannelOffset\n
 *           This command sets the Extension (Secondary) Channel Offset
 *           field in the APs beacon's High Throughput Information Element
 *           (HT IE).
 *             - iwpriv category: ht40/20 coexistence
 *             - iwpriv arguments:\n
 * 0: Use the device settings\n
 * 1: None\n
 * 2: Extension (Secondary) channel is above the control (Primary) channel\n
 * 3: Extension (Secondary) channel is below the control (Primary) channel\n
 *             - iwpriv restart needed? No
 *             - iwpriv default value: 0
 *             .
 *         - iwpriv cmd: iwpriv athN blockdfschan 1|0\n
 *           This command will disable the selection of dfs channels when the
 *           802.11h channel switch processing is selecting a new channel.
 *           Typically, when a radar is detected on a channel, a new channel
 *           is picked randomly from the list.  DFS channels are normally
 *           included in the list, so if there are several radars in the area
 *           another hit is possible.  Setting this selection to 0 disables the
 *           use of DFS channels in the selection process, while a value of 1
 *           enables DFS channels.  The default value is 1..  This limits the
 *           number of available channels.  This command does not have a
 *           corresponding get command.
 *             - iwpriv category: N/A
 *             - iwpriv arguments: 1 (enable) or 0 (disable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 1
 *             .
 *         - iwpriv cmd: iwpriv athN extprotmode protectionMode\n
 *           Sets the protection mode used on the extension (secondary)
 *           channel when using 40 MHz channels
 *             - iwpriv category: CWM mode
 *             - iwpriv arguments: \n
 * 0: None, no protection\n
 * 1: CTS to self\n
 * 2: RTS/CTS\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: No protection
 *             .
 *         - iwpriv cmd: iwpriv athN extprotspac channelSpacing\n
 *           Sets the channel spacing for protection frames sent on the
 *           extension (secondary) channel when using 40 MHz channels
 *             - iwpriv category: CWM mode
 *             - iwpriv arguments: \n
 * 1: 20 MHz\n
 * 2: 25 MHz\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 20 MHz
 *             .
 *         - iwpriv cmd: iwpriv athN cwmenable 1|0\n
 *           This command will enable or disable automatic channel width
 *           management.  If set to 0, the CWM state machine is disabled
 *           (1 enables the state machine).  This is used when static rates
 *           and channel widths are desired.  The command has a corresponding
 *           get command, and its default value is 1.
 *             - iwpriv category: N/A
 *             - iwpriv arguments: 0 (disable) or 1(enabl)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 1
 *             .
 *         - iwpriv cmd: iwpriv athN shortgi 1|0\n
 *           This command will enable/disable the short Gating Interval
 *           (shortgi) when transmitting HT 40 frames.  This effectively
 *           increases the PHY rate by 25%.  This is a manual control typically
 *           used for testing.  This command has a corresponding get command,
 *           and its default value is 1.
 *             - iwpriv category: N/A
 *             - iwpriv arguments: 0 (disable) or 1(enabl)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 1
 *             .
 *         - iwpriv cmd: iwpriv athN tx_chainmask mask\n
 *           These commands are identical to those commands in the radio layer,
 *           and have the same effect.  These parameters set the transmit and
 *           receive chainmask values.  For MIMO devices, the chainmask
 *           indicates how many streams are transmitted/received, and which
 *           chains are used.  For some Atheros devices up to 3 chains can be
 *           used, while others are restricted to 2 or 1 chain.  Its important
 *           to note that the maximum number of chains available for the device
 *           being used.  For dual chain devices, chain 2 is not available.
 *           Similarly, single chain devices will only support chain 0.
 *           Selection of chainmask can affect several performance factors.
 *           For a 3 chain device, most of the time an RX chainmask of 0x05
 *           (or 0x03 for two chain devices) is used for 2x2 stream reception.
 *           For near range operations, a TX chainmask of 0x05 (or 0x03 for two
 *           chain devices) is used to minimize near range effects.  For far
 *           range, a mask of 0x07 is used for transmit. It is recommended to
 *           use the radio version of these commands, since they may become
 *           deprecated in the future through this interface.  These setting
 *           affect ALL VAPS, not just the VAP that is being set. The default
 *           chainmask values are stored in EEPROM.  This iwpriv command will
 *           override the current chainmask settings.  These commands have
 *           corresponding get commands.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:\n
 *               The chains are represented in the bit mask as follows:
 *                 - Chain 0	0x01\n
 *                 - Chain 1	0x02\n
 *                 - Chain 2	0x04\n
 *                 .
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN tx_cm_legacy chainmask\n
 *           This command sets the chainmask used to transmit legacy frames
 *           (CCK and legacy OFDM)
 *             - iwpriv category: chain mask
 *             - iwpriv arguments: chainmask
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *         - iwpriv cmd: iwpriv athN rx_chainmask mask\n
 *           See description of tx_chainmask
 *             - iwpriv category: N/A
 *             - iwpriv arguments: See description of tx_chainmask
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN noedgech\n
 *           This command forces the AP to avoid band edge channels when
 *           selecting a channel
 *             - iwpriv category: Mcast enhancement (IQUE)
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN maccmd cmd\n
 *           The maccmd value indicates how to use the ACL to limit access
 *           the AP.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:\n
 *               0	Disable ACL checking\n
 *               1	Only ALLOW association with MAC addresses on the list\n
 *               2	DENY association with any MAC address on the list\n
 *               3	Flush the current ACL list\n
 *               4	Suspend current ACL policies.  Re-enable with a 1 or 2
 *                  command\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 0
 *             .
 *         - iwpriv cmd: iwpriv athN protmode 0|1\n
 *           This command will enable or disable 802.11g protection mode.
 *           This will cause RTS/CTS sequence (or CTS to Self) to be sent
 *           when 802.11b devices are detected on the 802.11g network.
 *           This is used to protect against transmission by devices that
 *           do not recognize OFDM modulated frames.  This command has a
 *           corresponding get command, and its default value is 0.
 *             - iwpriv category: N/A
 *             - iwpriv arguments: 0 (disable) or 1(enable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 0
 *             .
 *         - iwpriv cmd: iwpriv athN hide_ssid 0|1\n
 *           This will hide the SSID, disabling it in the transmitted
 *           beacon, when enabled.  This is used for secure situations where
 *           the AP does not want to advertise the SSID name.  A value of 0
 *           will enable the SSID in the transmitted beacon.  This command
 *           has a corresponding get command, and its default value is 0.
 *             - iwpriv category: N/A
 *             - iwpriv arguments: 0 (disable) or 1(enable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 0
 *             .
 *         - iwpriv cmd: iwpriv athN ap_bridge mode\n
 *           This command will enable or disable bridging within the AP driver.
 *           This has the effect of now allowing a station associated to the
 *           AP to access any other station associated to the AP.  This
 *           eliminates bridging between clients.  This command has a
 *           corresponding get command.  Its default value is 0.
 *             - iwpriv category: N/A
 *             - iwpriv arguments: 0 (disable) or 1(enable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 0
 *             .
 *         - iwpriv cmd: iwpriv athN dtim_period delivery period\n
 *           This is used to set the Delivery Traffic Indication Map (DTIM)
 *             period.  The DTIM is an interval specified by the AP to
 *             the station indicating when multicast traffic may be available
 *             for the station, requiring the STA to be awake to receive
 *             the messages.  This command will set the APs DTIM period,
 *             in milliseconds.  A longer DTIM will provide for a greater
 *             power savings, but will increase multicast latency.  This
 *             parameter has a default value of 1 millisecond.  There is
 *             a corresponding get command.
 *             - iwpriv category: N/A
 *             - iwpriv arguments: time (milisecond)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 1
 *             .
 *         - iwpriv cmd: iwpriv athN bintval beacon interval\n
 *           This command will set the APs beacon interval value, in
 *             milliseconds.  This value determines the number of milliseconds
 *             between beacon transmissions.  For the multiple VAP case,
 *             the beacons are transmitted evenly within this interval.
 *              Thus, if 4 VAPs are created and the beacon interval is
 *             200 milliseconds, a beacon will be transmitted from the
 *             radio portion every 50 milliseconds, from each VAP in a
 *             round-robin fashion.  The default value of the interval
 *             is 100 milliseconds.  This command has a corresponding get
 *             command.
 *             - iwpriv category: N/A
 *             - iwpriv arguments: time (milisecond)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 200
 *             .
 *         - iwpriv cmd: iwpriv athN doth 0|1\n
 *             selection.  For the AP, this enables or disables transmission
 *             of country IE information in the beacon.  Stations supporting
 *             802.11h will configure their regulatory information according
 *             to the information in the country IE.  The default value
 *             is 1 (enabled).    This command has a corresponding get command.
 *             - iwpriv category: N/A
 *             - iwpriv arguments: 0 (disable) or 1(enable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 1
 *             .
 *         - iwpriv cmd: iwpriv athN pureg 1|0\n
 *           This command enables or disables pure G mode.  This mode does
 *             not allow 802.11b rates, and only used OFDM modulation.
 *              This command has a corresponding get command, and its default
 *             value is 0.
 *             - iwpriv category: N/A
 *             - iwpriv arguments: 0 (disable) or 1(enable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 0
 *             .
 *         - iwpriv cmd: iwpriv athN countryie 1|0\n
 *           This is an enable/disable control that determines if the country
 *             IE is to be sent out as part of the beacon.  The country
 *             their regulatory tables to the country they are in.  Sending
 *             this IE will configure all such stations to the country
 *             the AP is configured to.  This command has a corresponding
 *             get command, and its default value is 1 (enabled).
 *             - iwpriv category: N/A
 *             - iwpriv arguments: 0 (disable) or 1(enable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 1
 *             .
 *         - iwpriv cmd: iwpriv wifiN AMPDU 1|0\n
 *           This is used to enable/disable transmit AMPDU aggregation
 *             for the entire interface.  Receiving of aggregate frames
 *             will still be performed, but no aggregate frames will be
 *             transmitted if this is disabled.  This has a corresponding
 *             get command, and the default value is 1 (enabled).
 *             - iwpriv category: N/A
 *             - iwpriv arguments: 0 (disable) or 1(enable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 1
 *             .
 *         - iwpriv cmd: iwpriv athN ampdulimit Byte Limit\n
 *           This is the same command as used in the Radio layer; it affects
 *             ALL VAPs that are attached to the same radio.  This parameter
 *             limits the number of bytes included in an AMPDU aggregate
 *             frame.  Frames add to an aggregate until either the transmit
 *             duration is exceeded, the number of subframes is exceeded,
 *             the maximum number of bytes is exceeded, or the corresponding
 *             queue is empty.  The subframe causing excess conditions
 *             is not included in the aggregate frame, but queues up to
 *             be transmitted with the next aggregate frame.  The default
 *             get command.
 *             - iwpriv category: N/A
 *             - iwpriv arguments: Number of bytes
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 50000
 *             .
 *         - iwpriv cmd: iwpriv athN ampdusframes numFrames\n
 *           This is the same command as used in the Radio layer.  This
 *             command will affect ALL VAPs that are attached to the same
 *             radio.  This command will set the maximum number of subframes
 *             to place into an AMPDU aggregate frame.  Frames are added
 *             to an aggregate until either a) the transmit duration is
 *             exceeded, b) the number of subframes is exceeded, c) the
 *             maximum number of bytes is exceeded, or d) the corresponding
 *             queue is empty.  The subframe that causes excess conditions
 *             is not included in the aggregate frame, but will be queued
 *             up to be transmitted with the next aggregate frame. The
 *             default value is 32.  This command has a corresponding get
 *             command.
 *             - iwpriv category: N/A
 *             - iwpriv arguments: Number of frames
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 32
 *             .
 *         - iwpriv cmd: iwpriv athN amsdu isEnable\n
 *           Reception of ASMDU is supported by default. Transmission and
 *           reception of AMPDU is also supported by default.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:\n
 * 0 - Disable AMSDU transmission\n
 * 1 - Enable AMSDU transmission\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: True
 *             .
 *         - iwpriv cmd: iwpriv athN wmm 1|0\n
 *           This command will enable or disable WMM capabilities in the
 *             driver.  The WMM capabilities perform special processing
 *             for multimedia stream data including voice and video data.
 *              This command has a corresponding get command, and its default
 *             value is 1 (WMM enabled).
 *             - iwpriv category: N/A
 *             - iwpriv arguments: 0 (disable) or 1(enable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 1
 *             .
 *         - iwpriv cmd: iwpriv athN uapsd 1|0\n
 *           This command sets the corresponding bit in the capabilities
 *             field of the beacon and probe response messages.  This has
 *             no other effect.  This command has a corresponding get command,
 *             and its default value is 0.
 *             - iwpriv category: N/A
 *             - iwpriv arguments: 0 (disable) or 1(enable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 0
 *             .
 *         - iwpriv cmd: iwpriv athN dbgLVL Bitmask\n
 *           Another debug control.  This parameter controls the debug
 *             level of the VAP based debug print statements.  Its normally
 *             set to zero, eliminating all prints.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:\n
 * Symbolic name            Bit Value   Description\n
 * IEEE80211_MSG_11N	    0x80000000	11n mode debug\n
 * IEEE80211_MSG_DEBUG	    0x40000000	IFF_DEBUG equivalent\n
 * IEEE80211_MSG_DUMPPKTS	0x20000000	IFF_LINK2 equivalent\n
 * IEE80211_MSG_CRYPTO	    0x10000000	crypto work\n
 * IEE80211_MSG_INPUT	    0x08000000	input handling\n
 * IEEE80211_MSG_XRATE	    0x04000000	rate set handling\n
 * IEEE80211_MSG_ELEMID	    0x02000000	element id parsing\n
 * IEEE80211_MSG_NODE	    0x01000000	node handling\n
 * IEEE80211_MSG_ASSOC	    0x00800000	association handling\n
 * IEEE80211_MSG_AUTH	    0x00400000	authentication handling\n
 * IEEE80211_MSG_SCAN	    0x00200000	Scanning\n
 * IEEE80211_MSG_OUTPUT	    0x00100000	output handling\n
 * IEEE80211_MSG_STATE	    0x00080000	state machine\n
 * IEEE80211_MSG_POWER	    0x00040000	power save handling\n
 * IEEE80211_MSG_DOT1X	    0x00020000	802.1x authenticator\n
 * IEEE80211_MSG_DOT1XSM	0x00010000	802.1x state machine\n
 * IEEE80211_MSG_RADIUS	    0x00008000	802.1x radius client\n
 * IEEE80211_MSG_RADDUMP	0x00004000	dump 802.1x radius packets\n
 * IEEE80211_MSG_RADKEYS	0x00002000	dump 802.1x keys\n
 * IEEE80211_MSG_WPA	    0x00001000	WPA/RSN protocol\n
 * IEEE80211_MSG_ACL	    0x00000800	ACL handling\n
 * IEEE80211_MSG_WME	    0x00000400	WME protocol\n
 * IEEE80211_MSG_SUPG	    0x00000200	SUPERG\n
 * IEEE80211_MSG_DOTH	    0x00000100	11.h\n
 * IEEE80211_MSG_INACT	    0x00000080	inactivity handling\n
 * IEEE80211_MSG_ROAM	    0x00000040	sta-mode roaming\n
 * IEEE80211_MSG_ACTION	    0x00000020	action management frames\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 0
 *             .
 *         - iwpriv cmd: iwpriv athN rtscts_rcode\n
 *           This command set/get RTS rate code
 *             - iwpriv category: chain mask
 *             - iwpriv arguments: rate code value
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN htprot 1|0\n
 *           HT protection modes are defined in the 802.11n specification,
 *           paragraph 9.13.  Depending on conditions, various protection
 *           modes are implemented.  This command will override automatic
 *           protection settings and enable protection for ALL modes.
 *           A value of 1 indicates all protection enabled, while a value
 *           of 0 indicates dynamically calculated protection levels.
 *           This command has a corresponding get command, and its default
 *           value is 0.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: mcastenhance\n
 *           Cannot find in AP Manual
 *             - iwpriv category: Mcast enhancement (IQUE)
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: medebug\n
 *           Cannot find in AP Manual
 *             - iwpriv category: Mcast enhancement (IQUE)
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: me_length\n
 *           Cannot find in AP Manual
 *             - iwpriv category: Mcast enhancement (IQUE)
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: metimer\n
 *           Cannot find in AP Manual
 *             - iwpriv category: Mcast enhancement (IQUE)
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: metimeout\n
 *           Cannot find in AP Manual
 *             - iwpriv category: Mcast enhancement (IQUE)
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: medropmcast\n
 *           Cannot find in AP Manual
 *             - iwpriv category: Mcast enhancement (IQUE)
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: me_showdeny\n
 *           Cannot find in AP Manual
 *             - iwpriv category: Mcast enhancement (IQUE)
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: me_cleardeny\n
 *           Cannot find in AP Manual
 *             - iwpriv category: Mcast enhancement (IQUE)
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: hbrtimer\n
 *           Cannot find in AP Manual
 *             - iwpriv category: Headline block removal(IQUE)
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN vap_contryie isEnable\n
 *           enable/disable Country IE support of this VAP.
 *             - iwpriv category: COMMON
 *             - iwpriv arguments:\n
 * 1 - enable feature\n
 * 0 - disable feature\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN vap_doth isEnable\n
 *           enable/disable 802.11h support of this VAP.
 *             - iwpriv category: COMMON
 *             - iwpriv arguments:\n
 * 1 - enable feature\n
 * 0 - disable feature\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN sko maxXretries\n
 *           This command set STA quick kickout max consecutive xretries
 *           value. If the node is not a NAWDS repeater and failed count
 *           reaches this value, kick out the node.
 *             - iwpriv category: STA Quick Kickout
 *             - iwpriv arguments: max consecutive xretries value
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 50
 *             .
 *         - iwpriv cmd: iwpriv athN disablecoext isEnable\n
 *           This command set support for 20/40 Coexistence support
 *             - iwpriv category: ht40/20 coexistence
 *             - iwpriv arguments:
 * 1 (disable coexistence) or 0 (enable coexistence)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN ht40intol isEnable\n
 *           This command set support for 20/40 Coexistence Management frame support
 *             - iwpriv category: ht40/20 coexistence
 *             - iwpriv arguments: 1 (enable) or 0 (disable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 0
 *             .
 *         - iwpriv cmd: iwpriv athN ant_ps_on isEnable\n
 *           This command set support for GreenAP Power Save to enable/disable
 *           the power save logic.
 *             - iwpriv category: GREEN AP
 *             - iwpriv arguments: 1 (enable) or 0 (disable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN ps_timeout transtime\n
 *           This command sets the transition time between power save off
 *           to power save on mode
 *             - iwpriv category: GREEN AP
 *             - iwpriv arguments: transtime value
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 20
 *             .
 *         - iwpriv cmd: iwpriv athN wds 1|0\n
 *           This command enables (1) or disables (0) 4-address frame format
 *           for this VAP.  Used for WDS configurations (see section 3.5
 *           for details).  This command has a corresponding get command,
 *           and its default value is 0.
 *             - iwpriv category: N/A
 *             - iwpriv arguments: 0 (disable) or 1(enable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 0
 *             .
 *         - iwpriv cmd: iwpriv athN wdsdetect 1|0\n
 *           Due to a hardware bug in early 11n chips, a workaround for
 *           WDS frames was implemented between Atheros stations.  For
 *           ar9000 series or later 802.11n products, this workaround is
 *           not required.  This value enables (1) or disables (0) the
 *           AR5416 workaround for WDS.  When the workaround is enabled
 *           aggregation is not enabled for the WDS link.  This command
 *           has a corresponding get command, and its default value is 1.
 *             - iwpriv category: N/A
 *             - iwpriv arguments: 0 (disable) or 1(enable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 1
 *             .
 *         - iwpriv cmd: iwpriv athN extap support\n
 *           This command set support for Extender AP support
 *             - iwpriv category: EXT AP
 *             - iwpriv arguments:\n
 * 0 - Disable Extender AP support\n
 * 1 - Enable Extender AP support\n
 * 2 - Enable Extender AP support with DEBUG\n
 * 3 - Enable Extender AP support with DEBUG\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 0
 *             .
 *         - iwpriv cmd: setparam\n
 *           Its for sub-ioctl handlers, usually we would not use it directly.
 *           For example: "iwpriv ath0 ampdu 0" should be equivalent to\n
 *           "iwpriv ath0 setparam 73 0" IEEE80211_PARAM_AMPDU\n
 *           = 73,	// 11n a-mpdu support
 *             - iwpriv category: COMMON
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN reset\n
 *           This command will force a reset on the VAP and its underlying
 *           radio layer.  Note that any VAP connected to the same radio
 *           in mBSSID configuration will be affected.  This is an action
 *           command that has no get command or default value.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN authmode mode\n
 *           This command selects the specific authentication mode to configure
 *           the driver for.  This command is also used by host_apd to
 *           configure the driver when host_apd is used as an authenticator.
 *           The user will normally not use these commands.  These commands
 *           have an associated get command, and its default value is 0.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:\n
 *               Value	Description\n
 *               0	None specified\n
 *               1	Open Authentication\n
 *               2	Shared Key (WEP) Authentication\n
 *               3	802.1x Authentication\n
 *               4	Auto Select/accept authentication (used by host_apd)\n
 *               5	WPA PSK with 802.1x PSK\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 0
 *             .
 *         - iwpriv cmd: iwpriv athN mcastcipher cipher\n
 *           Used mainly by the hostapd daemon, this command will set the
 *           cipher used for multicast.
 *           The iwpriv command sets the cipher type for the VAP.  This
 *           is required to support operation of the host_apd authenticator.
 *            It has no default value, and the command has a corresponding
 *           get command.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:\n
 *               The value of cipher is one of the following:\n
 *               Value	Cipher Type\n
 *               0	IEEE80211_CIPHER_WEP\n
 *               1	IEEE80211_CIPHER_TKIP\n
 *               2	IEEE80211_CIPHER_AES_OCB\n
 *               3	IEEE80211_CIPHER_AES_CCM\n
 *               5	IEEE80211_CIPHER_CKIP\n
 *               6	IEEE80211_CIPHER_NONE\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN mcastkeylen length\n
 *           This is only valid for WEP operations.  This command is used
 *           to set the key length of the WEP key.  Key lengths of 5 (40
 *           bits) or 13 (104 bits) are the only valid values, corresponding
 *           to 64 or 128 bit WEP encoding, respectively.  This command
 *           has no default value.  This command has a corresponding get
 *           command.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN ucastciphers cipherTypes\n
 *           This command set support for cipher types. The values are
 *           preserved here to maintain binary compatibility with applications
 *           like wpa_supplicant and hostapd.
 *             - iwpriv category: Crypto
 *             - iwpriv arguments: Cipher types
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 7
 *             .
 *         - iwpriv cmd: iwpriv athN ucastcipher\n
 *           This command is used mainly by the host_apd authenticator,
 *           and sets the unicast cipher type to the indicated value.
 *           See the mcastcipher command for the definition of the values.
 *            This command has a corresponding get command, but no default
 *           value.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN ucastkeylen length\n
 *           This is only valid for WEP operations.  This command is used
 *           to set the key length of the WEP key for unicast frames.
 *           Key lengths of 5 (40 bits) or 13 (104 bits) are the only valid
 *           values, corresponding to 64 or 128 bit WEP encoding, respectively.
 *           get command.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN keymgtalgs algs\n
 *           This command is used by host_apd in managing WPA keys.  This
 *           is essentially the same as the WPA command, which is a combination
 *           of bits indicating different capabilities.
 *           The command is a combination of the above, so a value of 3
 *           indicates both unspec and PSK support.  The command has a
 *           corresponding get command.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:\n
 *               The algs supported are as follows:\n
 *               Value	Alg\n
 *               0	WPA_ASE_NONE\n
 *               1	WPA_ASE_8021X_UNSPEC\n
 *               2	WPA_ASE_8021X_PSK\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN rsncaps flags\n
 *           This command sets the RSN capabilities flags.  The only valid
 *           capability flag is 0x01, RSN_CAP_PREAUTH, which is used to
 *           configure the AP for preauthorization functionality.  This
 *           is normally used only by host_apd when configuring the VAP.
 *            This command has a corresponding get command.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN privacy 1|0\n
 *           The privacy flag is used to indicate WEP operations.  This
 *           is not normally used by an application other than host_apd.
 *            WEP operations are normally configured through the appropriate
 *           iwconfig command.  This command has a corresponding get command,
 *           and its default value is 0.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN countermeasures 1|0\n
 *           Enables or disables WPA/WPA2 countermeasures.  Countermeasures
 *           perform additional processing on incoming authentication requests
 *           to detect spoof attempts, such as repeating authentication
 *           packets.  A value of 1 enables countermeasures, and 0 disables
 *           them.  This command has a corresponding get command.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN dropunencrypted 0|1\n
 *           This command enables or disables dropping of unencrypted non-PAE
 *           frames received. Passing a value of 1 enables dropping of
 *           unencrypted non-PAE frames. Passing a value of 0 disables
 *           dropping of unencrypted non-PAE frames.  This command has
 *           a corresponding get command, and its default value is zero.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN wpa WPA Mode\n
 *           This command will set the desired WPA modes.  The value of
 *           WPA Mode indicates the level of support;
             This command is typically overridden by the setting in the
 *           hostapd configuration file, which uses the same interface
 *           to set the WPA mode, so this command is nor normally used
 *           during configuration.  This command has a corresponding get
 *           command.  The default value is 0.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:\n
 *               0 = No WPA support\n
 *               1 = WPA Support\n
 *               2 = WPA2 Support\n
 *               3 = Both WPA and WPA2 support.\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN driver_caps caps\n
 *           This command is used to manually set the driver capabilities
 *           flags.  This is normally used for testing, since the driver
 *           itself will fill in the proper capability flags.
 *           This command has a corresponding get command.  It has no default value.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:\n
 * The flags are defined as follows:\n
 * 0x00000001	WEP	0x00000200	Power Management	0x01000000	WPA 2\n
 * 0x00000002	TKIP	0x00000400	Host AP	0x00800000	WPA 1\n
 * 0x00000004	AES	0x00000800	Ad hoc Demo	0x02000000	Burst\n
 * 0x00000008	AES_CCM	0x00001000	Software Retry	0x04000000	WME\n
 * 0x00000010	HT Rates	0x00002000	TX Power Mgmt	0x08000000	WDS\n
 * 0x00000020	CKIP	0x00004000	Short Slot time	0x10000000	WME TKIP MIC\n
 * 0x00000040	Fast Frame	0x00008000	Short Preamble	0x20000000	Background Scan\n
 * 0x00000080	Turbo	0x00010000	Monitor Mode	0x40000000	UAPSD\n
 * 0x00000100	IBSS	0x00020000	TKIP MIC	0x80000000	Fast Channel Change\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN wps support\n
 *           This command set support for WPS mode support.
 *             - iwpriv category: WPS IE
 *             - iwpriv arguments:\n
 * 0 - Disable WPS mode\n
 * 1 - Enable WPS mode\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 0
 *             .
 *         - iwpriv cmd: iwpriv athN mcast_rate rate\n
 *           This command is used to set multicast to a fixed rate.  The
 *           rate value is specified in units of KBPS.  This allows the
 *           user to limit the impact of multicast on the overall performance
 *           of the system.  The command has a corresponding get command,
 *           and has no default value.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN scanvalid period\n
 *           This command sets the period that scan data is considered
 *           value for roaming purposes.  If scan data is older than this
 *           period, a scan will be forced to determine if roaming is required.
 *           get command, and has a default value of 60 seconds.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 60
 *             .
 *         - iwpriv cmd: iwpriv athN rssi11a rssiThreshold\n
 *           set Roaming rssi threshold for 11a bss.
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: RSSI threshold (dBm)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN rssi11b\n
 *           These commands set the RSSI threshold for roaming in 11g and
 *           11b modes.  These thresholds are used to make roaming decisions
 *           based on signal strength from the current set of APs available.
 *            The values are provided in units of db.  These commands have
 *           corresponding get commands.  The default value for both is 24 dBm.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 24
 *             .
 *         - iwpriv cmd: iwpriv athN rssi11g\n
 *           These commands set the RSSI threshold for roaming in 11g and
 *           11b modes.  These thresholds are used to make roaming decisions
 *           based on signal strength from the current set of APs available.
 *            The values are provided in units of db.  These commands have
 *           corresponding get commands.  The default value for both is 24 dBm.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 24
 *             .
 *         - iwpriv cmd: iwpriv athN rate11a\n
 *           These commands set the roaming rate for each band usage.
 *           These rates are used to determine if a new AP is required.
 *            If the data rate on the link drops below these values, the
 *           scan module will determine if a better AP on the same ESS
 *           can be used.  Values are specified in 500kbps increments,
 *           so a value of 48 indicates a rate of 24 Mbps.  This command
 *           has a corresponding get command, and its default value is
 *           48 for A band and 18 for B/G band.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN rate11b\n
 *           See description of rate11a
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN rate11g\n
 *           See description of rate11a
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN chanbw\n
 *           This command sets manual channel bandwidth.  The values indicate
 *           which channel bandwidth to use.  Note that this command only
 *           applies to legacy rates V HT rates are controlled with the
 *           corresponding 11n commands. This command has a corresponding
 *           get command, and its default value is 0.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:\n
 *               Value	Description\n
 *               0	Full channel bandwidth\n
 *	             1  Half channel bandwidth\n
 *               2	Quarter channel bandwidth\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN extbusythres pctBusy\n
 *           This is used as part of the channel width management state
 *           machine.  This threshold is used to determine when to command
 *           the channel back down to HT 20 mode when operating at HT 40
 *           mode.  If the extension channel is busy more often then the
 *           specified threshold (in percent of total time), then CWM will
 *           shut down the extension channel and set the channel width
 *           to HT 20.  This command has a corresponding get command, and
 *           its default value is 30%.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 30
 *             .
 *         - iwpriv cmd: iwpriv athN fastcc 1|0\n
 *           This enables fast channel change.  A value of 1 indicates
 *           that channel changes within band will be done without resetting
 *           the chip.  A value of 0 indicates that any channel change
 *           will require a chip reset.  This command has a corresponding
 *           get command, and its default value is 0
 *             - iwpriv category: N/A
 *             - iwpriv arguments: 0 (disable) or 1(enable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 0
 *             .
 *         - iwpriv cmd: iwpriv athN set11NRates rate_series\n
 *           When performing tests at fixed data rates, this command is
 *           used to specify the data rate.  The rate_series value is specified
 *           as a group of 4 bytes in a 32 bit word.  Each byte represents
 *           the MCS rate to use for each of 4 rate fallback values.  If
 *           the hardware does not receive an ACK when transmitting at
 *           the first rate, it will fall back to the second rate and retry,
 *           and so on through the 4th rate.  As a convention, the high
 *           bit in the rate byte is always set, so for a rate of MCS-15
 *           the rate value would be 0x8F.  This command has a corresponding
 *           get command.  It has no default value
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN set11NRetries\n
 *           set Retry of Fix Rate series
 *             - iwpriv category: COMMON
 *             - iwpriv arguments:\nset Retry of Fix Rate series
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN chscaninit bIntvalValue\n
 *           This command set the overlapping bss scan interval value
 *             - iwpriv category: ht40/20 coexistence
 *             - iwpriv arguments: interval value
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN inact inactivity period\n
 *           This sets the TSPEC inactivity period for the AP RUN state.
 *            This is an 802.11e mechanism that allows for allocating QoS
 *           priority to certain traffic types.  The inactivity period
 *           is a timer that counts the seconds that a QoS stream is inactive
 *           during RUN state.  This timer will delete a traffic stream
 *           after the indicated number of seconds elapse.  The default
 *           value is 300 seconds, and this command has a corresponding
 *           get command.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 300
 *             .
 *         - iwpriv cmd: iwpriv athN inact_auth inactivity period\n
 *           This sets the TSPEC inactivity period for the AP AUTH state.
 *            This is an 802.11e mechanism that allows for allocating QoS
 *           priority to certain traffic types.  The inactivity period
 *           is a timer that counts the seconds that a QoS stream is inactive
 *           during AUTH state.  This timer will delete a traffic stream
 *           after the indicated number of seconds elapse.  The default
 *           value is 180 seconds, and this command has a corresponding
 *           get command.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 180
 *             .
 *         - iwpriv cmd: iwpriv athN inact inactivity period\n
 *           This sets the TSPEC inactivity period for the AP INIT state.
 *            This is an 802.11e mechanism that allows for allocating QoS
 *           priority to certain traffic types.  The inactivity period
 *           is a timer that counts the seconds that a QoS stream is inactive
 *           during INIT state.  This timer will delete a traffic stream
 *           after the indicated number of seconds elapse.  The default
 *           value is 30 seconds, and this command has a corresponding
 *           get command.

 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN coverageclass class\n
 *           The coverage class is used to determine the air propagation
 *           time used in BSS operations.  This command will set the coverage
 *           class to a value between 0 and 31.  This value is part of
 *           the country IE transmitted, and the values can be found in
 *           the IEEE 802.11 Handbook, Table 13-1.  Generally, the higher
 *           the number, the longer distance that is allowed for coverage.
 *            This command has a corresponding get command.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN regclass 1|0\n
 *           This command enables or disables the addition of the regulatory
 *           triplets into the country IE sent in the beacon.  A value
 *           of 1 will enable the regulatory triplets.  This command has
 *           a corresponding get command, and its default value is 1.
 *             - iwpriv category: N/A
 *             - iwpriv arguments: 0 (disable) or 1(enable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 1
 *             .
 *         - iwpriv cmd: iwpriv athN sleep 1|0\n
 *           This test command will force a STA VAP into (1) or out of
 *           (0) sleep mode.  This is useful only for station mode.  When
 *           coming out of sleep, a null data frame will be sent.  This
 *           command has a corresponding get command that returns the power
 *           management state (1 enabled 0 disabled).  This has no default
 *           value.
 *             - iwpriv category: N/A
 *             - iwpriv arguments: 0 (disable) or 1(enable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: osnull\n
 *           Cannot find in AP Manual
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN shpreamble 1|0\n
 *           This command will enable (1) or disable (0) short preamble.
 *            Short preamble will disable the use of a barker code at the
 *           start of the preamble.  This command affects ALL VAPs connected
 *           to the same radio.  This command has a corresponding get command,
 *           and its default value is 0.
 *             - iwpriv category: N/A
 *             - iwpriv arguments: 0 (disable) or 1(enable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 0
 *             .
 *         - iwpriv cmd: iwpriv athN markdfs 1|0\n
 *           This command will enable or disable the marking of DFS
 *           channels.  A channel is marked if a radar is detected
 *           on the channel, and it is put in the Non-Occupancy List (NOL).
 *            This is only used for testing, and should not be used in
 *           an operational environment.  This command has a corresponding
 *           get command, and its default value is 1.
 *             - iwpriv category: N/A
 *             - iwpriv arguments: 0 (disable) or 1(enable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 1
 *             .
 *         - iwpriv cmd: iwpriv athN ampdudensity mpduDensity\n
 *           This command set the value of MPDU density.
 *             - iwpriv category: 11n A-MPDU, A-MSDU support
 *             - iwpriv arguments:\n
 *	0 - No time restriction\n
 *	1 - 1/4 usec\n
 *	2 - 1/2 usec\n
 *	3 - 1 usec\n
 *	4 -  2 usec\n
 *	5 - 4 usec\n
 *	6 - 8 usec\n
 *	7 - 16 usec\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 6
 *             .
 *         - iwpriv cmd: iwpriv athN amsdulimit ampduLimit\n
 *           This command set the value of 11n A-MPDU limits.
 *             - iwpriv category: 11n A-MPDU, A-MSDU support
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN setaddbaoper 1|0\n
 *           This command will enable or disable automatic processing for
 *           aggregation/block ACK setup frames.  To use the manual addba/delba
 *           commands this must be set to 0 (off) to keep the driver from
 *           also responding.  This command has a corresponding get command,
 *           and its default value is 1 (enabled).
 *             - iwpriv category: N/A
 *             - iwpriv arguments: 0 (disable) or 1(enable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 1
 *             .
 *         - iwpriv cmd: iwpriv athN puren isEnable\n
 *           enable/disable Pure 11N mode. Which would not accept Stas
 *           who dont have HT caps in AP mode.
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: 0 (disable) or 1(enable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN stafwd 1|0\n
 *           This command enables/disables station forwarding mode.  In
 *           this mode, a client VAP will act as a surrogate interface
 *           as an Ethernet device, using the MAC address of the surrogate
 *           as its own, allowing a non-WiFi device to use a dongle
 *           to provide WiFi access without modification to the non-WiFi
 *           device.  Setting to 1 will enable this mode, where setting
 *           to 0 will disable this mode.  Note that the proper wlanconfig
 *           command must be used to set up the VAP in the first place.
 *            This command has a corresponding get command, and its default
 *           value is 0.
 *             - iwpriv category: N/A
 *             - iwpriv arguments: 0 (disable) or 1(enable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 0
 *             .
 *         - iwpriv cmd: iwpriv athN compression isEnable\n
 *           enable/disable Data Compression support Atheros supper G.
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: 0 (disable) or 1(enable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN ff isEnable\n
 *           enable/disable Fast Frames support of Atheros supper G.
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: 0 (disable) or 1(enable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN turbo isEnable\n
 *           enable/disable Turbo Prime support. Which is related to Dynamic
 *           Turbo of Atheros supper G.
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: 0 (disable) or 1(enable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN burst 1|0\n
 *           This command enables (1) or disables (0) Atheros Super A/G
 *           bursting support in the driver. Passing a value of 1 to the
 *           driver enables SuperG bursting. Passing a value of 0 to the
 *           driver disables Super A/G bursting.  This is nor normally
 *           used when using 802.11n devices.  This command has a corresponding
 *           get command, and its default value is 0.
 *             - iwpriv category: N/A
 *             - iwpriv arguments: 0 (disable) or 1(enable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 0
 *             .
 *         - iwpriv cmd: iwpriv athN bgscan 1|0\n
 *           This command will enable or disable background scanning.
 *           Background scanning occurs on a specified interval to update
 *           the list of known APs.  This command is only valid when
 *           get command, and its default value is 1.
 *             - iwpriv category: N/A
 *             - iwpriv arguments: 0 (disable) or 1(enable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 1
 *             .
 *         - iwpriv cmd: iwpriv athN bgscanidle idlePeriod\n
 *           This command sets the amount of time the background scan must
 *           be idle before it is restarted.  This is different from the
 *           background scan interval, in that if the background scan is
 *           delayed for a long period, when it is complete it will be
 *           idle for this period even if the scan interval times out.
 *           get command, and its default value is 250 seconds.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 250
 *             .
 *         - iwpriv cmd: iwpriv athN bgscanintvl interval\n
 *           This sets the interval to perform background scans.  A scan
 *           is started each time the interval times out, or if the idle
 *           interval is not timed out when the idle interval is complete.
 *            The interval timer is started when the scan is started, so
 *            The interval value is specified in seconds.  This command
 *           has a corresponding get command, and its default value is 300.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 300
 *             .
 *         - iwpriv cmd: iwpriv athN eospdrop isEnable\n
 *           This command set support for forcing uapsd EOSP drop (ap only)
 *             - iwpriv category: PS
 *             - iwpriv arguments:\n
 * 0 - Disable forcing uapsd EOSP drop\n
 * 1 - Enable forcing uapsd EOSP drop\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN powersave powersaveMode\n
 *           This command set support for sta power save mode
 *             - iwpriv category: PS
 *             - iwpriv arguments:\n
 * 0 - STA power save none\n
 * 1 - STA power save low\n
 * 2 - STA power save normal\n
 * 3 - STA power save maximum\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN roaming mode\n
 *           The roaming mode defines how state transitions are controlled
 *           in the AP, and what will cause a scan to happen.
 *           The default value is ROAMING_AUTO when in STA mode.  This
 *           parameter has no meaning when operating in AP mode.  The command
 *           has a corresponding get command.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:\n
 *           The roaming mode can take the following values:\n
 *           Value	Definition\n
 *           0	ROAMING_DEVICE.  Scans are started in response to management
 *           frames coming in from the WLAN interface, and the driver starts
 *           the scan without intervention\n
 *           1	ROAMING_AUTO.  Scan algorithm is controlled by the 802.11
 *           layer in the AP.  Similar to ROAMING_DEVICE, additional algorithms
 *           are applied to the decision of when to scan/reassociate/roam.\n
 *           2	ROAMING_MANUAL:  Roaming decisions will be driven by IOCTL
 *           calls by external applications, such as the wpa_supplicant.\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN ar isEnable\n
 *           enable/disable Advanced Radar support. Which is related to Dynamic Turbo.
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: 1 (enable) or 0 (disable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN vap_ind isEnable\n
 *           This command set support for vap wds independance set.
 *             - iwpriv category: Unassociated power consumpion improve
 *             - iwpriv arguments:\n
 * 0 - Disable wds independance set\n
 * 1 - Enable wds independance set\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: 0
 *             .
 *         - iwpriv cmd: iwpriv athN htweptkip isEnable\n
 *           enable/disable 11n support in WEP or TKIP mode
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: 1 (enable) or 0 (disable)
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN scanprsleep value\n
 *           This command set the value of scan pre sleep.
 *             - iwpriv category: Unassociated power consumpion improve
 *             - iwpriv arguments: value of scan pre sleep.
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN sleepprscan value\n
 *           This command set the value of sleep pre scan.
 *             - iwpriv category: Unassociated power consumpion improve
 *             - iwpriv arguments: value of sleep pre scan
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN basicrates basicRates\n
 *           Mark the certain rates as basic rates per user request
 *             - iwpriv category: COMMON
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN ignore11d isEnable\n
 *           This command set support for dont process 11d beacon.
 *             - iwpriv category: 11d Beacon processing
 *             - iwpriv arguments:\n
 * 0 - Disable dont process 11d beacon\n
 * 1 - Enable dont process 11d beacon\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN periodicScan value\n
 *           This command sets support of sta periodic scan supprot. 0
 *           is disable and other value is enable. If the value is less
 *           than 30000, it will be set to 30000.
 *             - iwpriv category: ATHEROS_LINUX_PERIODIC_SCAN
 *             - iwpriv arguments:
 * 0 - Disable periodic scan\n
 * value - Enable periodic scan and set the periodic scan period\n
 *             - iwpriv restart needed? No
 *             - iwpriv default value: 0
 *             .
 *         - iwpriv cmd: iwpriv athN qosnull\n
 *           This command forces a QoS Null for testing.
 *             - iwpriv category: PS
 *             - iwpriv arguments: AC value
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN vhtmcs <mcsindex> \n
 *           This command specifies the VHT MCS Index to be used with
 *           data frame transmissions. Note that invoking this command
 *           with valid MCS Index (0-9) enables "fixed rate" and Invalid
 *           index disables fixed rate setting. Make sure the chwidth
 *           and nss params are set properly prior to invoking this command.
 *             - iwpriv category: VHT
 *             - iwpriv arguments: MCS Index
 * <0-9> - Valid Index Enables Fixed Rate
 * ( >9) - Invalid index Disables Fixed Rate
 *             - iwpriv restart needed? Yes
 *             - iwpriv default value: 0
 *             .
 *         - iwpriv cmd: iwpriv athN nss <spatial_streams> \n
 *           This command specifies the number of Spatial Streams
 *           to be enabled.
 *             - iwpriv category: HT/VHT
 *             - iwpriv arguments: Spatial Stream Count <1-3>
 *             - iwpriv restart needed? No
 *             - iwpriv default value: 3
 *             .
 *         - iwpriv cmd: iwpriv athN ldpc <0|1> \n
 *           This command allows enabling/disabling of LDPC.
 *             - iwpriv category: HT/VHT
 *             - iwpriv arguments:
 * 0 - Disable LDPC
 * 1 - Enable LDPC
 *             - iwpriv restart needed? Yes
 *             - iwpriv default value: 1
 *             .
 *         - iwpriv cmd: iwpriv athN tx_stbc <0|1> \n
 *           This command allows enabling/disabling of TX STBC
 *             - iwpriv category: HT/VHT
 *             - iwpriv arguments:
 * 0 - Disable Xmit STBC
 * 1 - Enable Xmit STBC
 *             - iwpriv restart needed? Yes
 *             - iwpriv default value: 1
 *             .
 *         - iwpriv cmd: iwpriv athN rx_stbc <0|1|2|3> \n
 *           This command allows enabling/disabling of RX STBC
 *             - iwpriv category: HT/VHT
 *             - iwpriv arguments:
 *             .
 * 0 - Disable RecvSTBC
 * 1 - Enable Recv STBC (1)
 * 2 - Enable Recv STBC (2)
 * 3 - Enable Recv STBC (3)
 *             - iwpriv restart needed? Yes
 *             - iwpriv default value: 1
 *         - iwpriv cmd: iwpriv athN vht_txmcsmap <mcsmap> \n
 *           This command specifies the VHT TX MCS map to be used with
 *           VHT CAP advertisements. The 16 bits used to represent the
 *           map should be consistent with the Draft 3.1 11ac specification
 *           (Section 8.4.2.160.3 Figure 8.401bu-RX MCS MAP and TX MCS MAP)
 *             - iwpriv category: VHT
 *             - iwpriv arguments: TX MCS Map
 *         - iwpriv cmd: iwpriv athN vht_rxmcsmap <mcsmap> \n
 *           This command specifies the VHT RX MCS map to be used with
 *           VHT CAP advertisements. The 16 bits used to represent the
 *           map should be consistent with the Draft 3.1 11ac specification
 *           (Section 8.4.2.160.3 Figure 8.401bu-RX MCS MAP and TX MCS MAP)
 *             - iwpriv category: VHT
 *             - iwpriv arguments: RX MCS Map
 * 0xfffc: NSS=1 MCS 0-7, NSS=2 not supported, NSS=3 not supported
 * 0xfff0: NSS=1 MCS 0-7, NSS=2       MCS 0-7, NSS=3 not supported
 * 0xffc0: NSS=1 MCS 0-7, NSS=2       MCS 0-7, NSS=3       MCS 0-7
 * 0xfffd: NSS=1 MCS 0-8, NSS=2 not supported, NSS=3 not supported
 * 0xfff5: NSS=1 MCS 0-8, NSS=2       MCS 0-8, NSS=3 not supported
 * 0xffd5: NSS=1 MCS 0-8, NSS=2       MCS 0-8, NSS=3       MCS 0-8
 * 0xfffe: NSS=1 MCS 0-9, NSS=2 not supported, NSS=3 not supported
 * 0xfffa: NSS=1 MCS 0-9, NSS=2       MCS 0-9, NSS=3 not supported
 * 0xffea: NSS=1 MCS 0-9, NSS=2       MCS 0-9, NSS=3       MCS 0-9
 * 0xffda: NSS=1 MCS 0-9, NSS=2       MCS 0-9, NSS=3       MCS 0-8
 * 0xffca: NSS=1 MCS 0-9, NSS=2       MCS 0-9, NSS=3
 *             .
 */

static int ieee80211_ioctl_setparam(struct net_device *dev, struct iw_request_info *info,
    void *w, char *extra)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    int *i = (int *) extra;
    int param = i[0];       /* parameter id is 1st */
    int value = i[1];       /* NB: most values are TYPE_INT */

    debug_print_ioctl(dev->name, param, find_ieee_priv_ioctl_name(param, 1));

    return ieee80211_ucfg_setparam(vap, param, value, extra);
}

#if DBG_LVL_MAC_FILTERING
int
wlan_set_debug_mac_filtering_flags(wlan_if_t vaphandle, unsigned char* extra)
{
    uint8_t dbgLVLmac_on, ni_dbgLVLmac_on;
    unsigned char *macaddr;
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211_node *ni = NULL;

    /* extra has 0-11 fields  */
    /* 0-3:sub-ioctl, 4:ni_dbgLVLmac_on, 5-10:macaddr, 11:dbgLVLmac enabled/disabled */
    ni_dbgLVLmac_on = (uint8_t) extra[4];
    dbgLVLmac_on = (uint8_t) extra[11];
    macaddr = (unsigned char*) &extra[5];
    /* Perform input validation for enable/disable values */
    if ((dbgLVLmac_on > 1) || (ni_dbgLVLmac_on > 1)){
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Incorrect input! Use 1 or 0 for set/clear or enable/disable, dbgLVLmac <set/clear><mac><enable/disable>\n");
        return 0;
    }
    /* Enable/disable dbgLVLmac filtering feature */
    vap->iv_print.dbgLVLmac_on = dbgLVLmac_on;
    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "dbgLVLmac feature: %s\n", ((dbgLVLmac_on)? "Enabled": "Disabled"));
    /* Find this mac address in node table and set mac_filtering enabled */
    ni = ieee80211_find_node(&vap->iv_ic->ic_sta, macaddr);
    if (ni) {
        ni->ni_dbgLVLmac_on = ni_dbgLVLmac_on;
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "dbgLVLmac filter for node (%s): %s \n", ether_sprintf(macaddr), ((ni_dbgLVLmac_on)?"Set":"Cleared"));
         /* find node would increment the ref count, if
         * node is identified make sure that is unrefed again
         */
        ieee80211_free_node(ni);
    }
    else {
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "dbgLVLmac: Node (%s): Not found\n", ether_sprintf(macaddr));
    }

    return 0;
}
#endif

int
ieee80211_ioctl_getmode(struct net_device *dev, struct iw_request_info *info,
        void *w, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct iw_point *wri = (struct iw_point *)w;

    debug_print_ioctl(dev->name, IEEE80211_IOCTL_GETMODE, "getmode") ;

    return ieee80211_ucfg_get_phymode(vap, extra, &wri->length);
}


static int
ieee80211_ioctl_p2p_big_param(struct net_device *dev, struct iwreq *iwr)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    enum ieee80211_opmode opmode = 0;
    union iwreq_data *iwd = &iwr->u;
    int retv = 0; /* default to success */
    ieee80211_scan_params scan_params;
    struct ieee80211_scan_req *scan_extra;
    bool scan_pause;
    struct ieee80211_node *ni =NULL;
    struct ieee80211com *ic;
    IEEE80211_SCAN_PRIORITY priority;

    if(vap == NULL)
    {
        return -EINVAL;
    }

    ic = vap->iv_ic;
    opmode = wlan_vap_get_opmode(vap);

    switch(iwr->u.data.flags)
    {

    case IEEE80211_IOC_P2P_FETCH_FRAME:
    {
        struct pending_rx_frames_list *pending = osif_fetch_p2p_mgmt(dev);

        if (!pending) {
            return -ENOSPC; /* no more messages are queued */
        }
        /* all the caller wants is the raw frame data, except it needs freq */
        iwr->u.data.length =
                MIN(iwr->u.data.length,
                    (pending->rx_frame.frame_len + sizeof(pending->freq) +
                                               sizeof(pending->frame_type)));

        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                "%s: IEEE80211_IOC_P2P_FETCH_FRAME size=%d frame_len=%d\n",
                __func__, iwr->u.data.length, pending->rx_frame.frame_len);
        pending->freq = pending->rx_frame.freq;

        retv = _copy_to_user(iwr->u.data.pointer, &pending->freq,
                            iwr->u.data.length);

        kfree(pending);
    }
    break;

    case IEEE80211_IOC_P2P_SEND_ACTION:
    {
        struct ieee80211_p2p_send_action *sa;

        if (iwr->u.data.length > MAX_TX_RX_PACKET_SIZE + sizeof(*sa))
                return -EFAULT;

        sa = (struct ieee80211_p2p_send_action *)OS_MALLOC(osifp->os_handle,
                                                iwr->u.data.length, GFP_KERNEL);
        if (!sa)
            return -ENOMEM;

        if (__xcopy_from_user(sa, iwr->u.data.pointer, iwr->u.data.length)) {
            OS_FREE(sa);
            return -EFAULT;
        }

        if (vap) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                          "%s: IEEE80211_IOC_P2P_SEND_ACTION size=%d \n", __func__,
                          iwr->u.data.length);
            if(wlan_vap_send_action_frame(vap, sa->freq,
    #if UMAC_SUPPORT_WNM
                                ieee80211_ioctl_send_action_frame_cb,
    #else
                                NULL,
    #endif
                                osifp, sa->dst_addr, sa->src_addr,
                                sa->bssid, (u_int8_t *) (sa + 1),
                                iwd->data.length - sizeof(*sa)) == 0) {

                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                              "%s: IEEE80211_IOC_P2P_SEND_ACTION freq=%d dest=%s ",
                              __func__, sa->freq,ether_sprintf(sa->dst_addr));
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                                  "src=%s ",ether_sprintf(sa->src_addr));
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                                  "bssid=%s \n ",ether_sprintf(sa->bssid));
                        retv = 0;
             } else {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                        "%s: IEEE80211_IOC_P2P_SEND_ACTION FAILED \n", __func__);
                        retv = -EINVAL;
             }
        }
        OS_FREE(sa);
    }
    break;

    case IEEE80211_IOC_SCAN_REQ:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                "set IEEE80211_IOC_SCAN_REQ, len=%d \n", iwd->data.length);
        if (!(dev->flags & IFF_UP)) {
            return -EINVAL;
        }

        /* fixme I have no clue how big this could be, I want to validate it */
        if (iwr->u.data.length > 8192 + sizeof(*scan_extra))
            return -EFAULT;

        scan_extra = (struct ieee80211_scan_req *)OS_MALLOC(osifp->os_handle, iwr->u.data.length, GFP_KERNEL);
        if (!scan_extra)
            return -ENOMEM;

        if (__xcopy_from_user(scan_extra, iwr->u.data.pointer, iwr->u.data.length)) {
            OS_FREE(scan_extra);
            return -EFAULT;
        }

#if ATH_SUPPORT_WRAP
        /* Indicate SIOCGIWSCAN directly for VAP's not able to scan */
        if (vap->iv_no_event_handler) {
            osif_notify_scan_done(dev, IEEE80211_REASON_NONE);
            retv = 0;
            goto scanreq_fail;
        }
#endif

        OS_MEMZERO(&scan_params,sizeof(scan_params));
#if defined(UMAC_SUPPORT_RESMGR) && defined(ATH_SUPPORT_P2P) && defined(ATH_SUPPORT_HTC)
        {
            bool connected_flag = false;

            if (osifp->sm_handle && wlan_connection_sm_is_connected(osifp->sm_handle))
                connected_flag = true;
            wlan_set_default_scan_parameters(vap, &scan_params,
                                            wlan_vap_get_opmode(vap),
                                            true, true, connected_flag, true, 0, NULL, 0);
        }
#else
        wlan_set_default_scan_parameters(vap, &scan_params,
                                        wlan_vap_get_opmode(vap),
                                        true, true, true, true, 0, NULL, 0);
#endif
        scan_params.min_dwell_time_active = scan_params.max_dwell_time_active
                                          = 100;
        if (osifp->sm_handle &&
                        wlan_connection_sm_is_connected(osifp->sm_handle)) {
            scan_params.type = IEEE80211_SCAN_BACKGROUND;
        } else {
            scan_params.type = IEEE80211_SCAN_FOREGROUND;
        }
        scan_params.flags = IEEE80211_SCAN_ALLBANDS | IEEE80211_SCAN_ACTIVE;
        scan_params.flags |= IEEE80211_SCAN_ADD_BCAST_PROBE;

        if (wlan_scan_in_progress(vap)) {
   /*
    * In general, if driver has started a scan, then the supplicant will
    * cancel it and start a new scan. But in QWRAP, this has been exempted
    * for MPSTA; due to which the driver was not posting notify scan done
    * event resulting a 45 seconds delay.
    */
#if 0
#if ATH_SUPPORT_WRAP
            if (wlan_is_mpsta(vap)) {
                retv = 0;
                goto scanreq_fail;
            }
#endif
#endif
             preempt_scan(dev, PREEMPT_SCAN_MAX_GRACE, PREEMPT_SCAN_MAX_WAIT);
        }

        if (iwd->data.length) {
            int i;

            if ((int) sizeof(*scan_extra) + scan_extra->ie_len > iwd->data.length) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %s: scan data is greater than passed \n", __func__);
                retv = EINVAL;
                goto scanreq_fail;
            }

            if (scan_extra->ie_len) {
                scan_params.ie_len = scan_extra->ie_len;
                scan_params.ie_data = (u_int8_t *) (scan_extra + 1);
            }

            if (scan_extra->num_ssid > MAX_SCANREQ_SSID ||
                scan_extra->num_ssid > IEEE80211_SCAN_PARAMS_MAX_SSID) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %s: num_ssid is greater:%d \n", __func__, scan_extra->num_ssid);
                retv = EINVAL;
                goto scanreq_fail;
            }

            /* In case of repeater move, the scan request from supplicant is
             * modified -
             *
             * 1. To hold a single entry corresponding to the SSID of target root AP
             *    in the case when BSSID information is not provided by user
             *
             * 2. To hold single entries of SSID and BSSID information corresponding
             *    to that of the target AP. This will be used in the case of
             *    repeater move between two Root APs having the exact same
             *    configuration but only differentiated by their BSSID
             */
            if (vap->iv_ic->ic_repeater_move.state == REPEATER_MOVE_IN_PROGRESS) {
                scan_params.num_ssid = 1;
                scan_params.ssid_list[0].len = vap->iv_ic->ic_repeater_move.ssid.len;
                memcpy(scan_params.ssid_list[0].ssid, vap->iv_ic->ic_repeater_move.ssid.ssid,
                       vap->iv_ic->ic_repeater_move.ssid.len);
                if (IEEE80211_ADDR_IS_VALID(vap->iv_ic->ic_repeater_move.bssid)) {
                    scan_params.num_bssid = 1;
                    memcpy(scan_params.bssid_list[0], vap->iv_ic->ic_repeater_move.bssid,
                           sizeof(vap->iv_ic->ic_repeater_move.bssid));
                }
            } else {
                scan_params.num_ssid = scan_extra->num_ssid;
                for (i = 0; i < scan_extra->num_ssid; i++) {
                    if (scan_extra->ssid_len[i] > 32) {
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %s: ssid is large:%d \n", __func__, scan_extra->ssid_len[i]);
                        retv = EINVAL;
                        goto scanreq_fail;
                    }
                    scan_params.ssid_list[i].len = scan_extra->ssid_len[i];
                    memcpy(scan_params.ssid_list[i].ssid,
                    scan_extra->ssid[i], scan_extra->ssid_len[i]);
                }
            }

            if (scan_extra->num_freq > MAX_SCANREQ_FREQ) {
                retv = EINVAL;
                goto scanreq_fail;
            }

            /* In case of repeater move, the scan request from supplicant is
             * modified to hold scan only the home channel.
             *
             * Channel list for scan request under repeater move state will contain
             * only single entry that corresponds to the channel of the new Root AP
             */
            if (vap->iv_ic->ic_repeater_move.state == REPEATER_MOVE_IN_PROGRESS) {
                scan_params.num_channels = 1;
                scan_params.chan_list = &(ic->ic_repeater_move.chan);
            }
            else if (scan_extra->num_freq) {
                scan_params.num_channels = scan_extra->num_freq;
                scan_params.chan_list = scan_extra->freq;
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s frequency list ", __func__);
                for (i = 0; i < scan_extra->num_freq; i++) {
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%d  ", scan_extra->freq[i]);
                }
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n");
            }
        }

        if (osifp->os_scan_band != OSIF_SCAN_BAND_ALL) {
            scan_params.flags &= ~IEEE80211_SCAN_ALLBANDS;
            if (osifp->os_scan_band == OSIF_SCAN_BAND_2G_ONLY)
                scan_params.flags |= IEEE80211_SCAN_2GHZ;
            else if (osifp->os_scan_band == OSIF_SCAN_BAND_5G_ONLY)
                scan_params.flags |= IEEE80211_SCAN_5GHZ;
            else {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                                    "%s: unknow scan band, scan all bands.\n", __func__);
                scan_params.flags |= IEEE80211_SCAN_ALLBANDS;
            }
        }

        priority = IEEE80211_SCAN_PRIORITY_LOW;
        /* start a scan */
        if (ieee80211_ic_enh_ind_rpt_is_set(vap->iv_ic)) {
                scan_params.flags |= IEEE80211_SCAN_FORCED;
                scan_params.min_rest_time = MIN_REST_TIME ;
                scan_params.max_rest_time = MAX_REST_TIME ;
                scan_params.min_dwell_time_active = MIN_DWELL_TIME_ACTIVE ;
                scan_params.max_dwell_time_active = MAX_DWELL_TIME_ACTIVE ;
                scan_params.init_rest_time = INIT_REST_TIME;
                scan_params.type = IEEE80211_SCAN_BACKGROUND;
                scan_params.check_termination_context = vap;
                scan_params.check_termination_function = scanner_check_for_bssid_entry;
                if (ic->ic_is_mode_offload(ic)) {
                    priority = IEEE80211_SCAN_PRIORITY_HIGH;
                }
        }
        if (wlan_get_param(vap, IEEE80211_FEATURE_WDS) && !ieee80211_ic_enh_ind_rpt_is_set(vap->iv_ic)) {
            /* For WDS station - always set the multiple_ports_active to false,
             * so that scanner won't come back to home channel for every foreign
             * channel change. Otherwise the scanning time is considerably increases
             * in case of Repeater case. In Repater case - AP vap always follows STA vap
             * channel - so no need to come back to home channel during scanning
             */
            scan_params.multiple_ports_active = false;
        }
        if(vap->iv_bss)
        {
            ni = vap->iv_bss;
        }
        if(ic->ic_use_custom_chan_list !=0 && vap->iv_opmode == IEEE80211_M_STA)
        {
            /*Use ic_custom_chan_list when vap is associated*/
            if(ni && ni->ni_associd >0 && ic->ic_custom_chanlist_assoc_size)

            {
                scan_params.chan_list = (u_int32_t *)ic->ic_custom_chan_list_associated;
                scan_params.num_channels = ic->ic_custom_chanlist_assoc_size;
            }
            else
            {
                if(ic->ic_custom_chanlist_nonassoc_size)
                {
                    scan_params.chan_list = (u_int32_t *)ic->ic_custom_chan_list_nonassociated;
                    scan_params.num_channels = ic->ic_custom_chanlist_nonassoc_size;
                }
            }
            /*flush the old scan results*/
            wlan_scan_table_flush(vap);
        }

        /* Enable Half / Quarter rate scan for STA vap if enabled */
        if (opmode == IEEE80211_M_STA) {
            if (ic->ic_chanbwflag & IEEE80211_CHAN_HALF) {
                scan_params.flags |= IEEE80211_SCAN_HALF_RATE;
            } else if (ic->ic_chanbwflag & IEEE80211_CHAN_QUARTER) {
                scan_params.flags |= IEEE80211_SCAN_QUARTER_RATE;
            }
        }

        scan_pause =  (ieee80211_ic_enh_ind_rpt_is_set(vap->iv_ic)) ?(vap->iv_pause_scan  ) : 0;
        if (!scan_pause) {
            osifp->os_last_siwscan = OS_GET_TICKS();
            retv = wlan_scan_start(vap, &scan_params, osifp->scan_requestor, priority, &(osifp->scan_id));
        }

scanreq_fail:
        OS_FREE(scan_extra);

        break;


    case IEEE80211_IOC_CANCEL_SCAN:
        if (wlan_scan_in_progress(vap)) {
            wlan_scan_cancel(vap, osifp->scan_requestor, IEEE80211_ALL_SCANS, IEEE80211_SCAN_CANCEL_WAIT);
        }
    	break;
    default:
        retv = -EINVAL;
    }
    return retv;
}

/**
 * @brief
 *     - Function description: Get parameter\n
 *     - iwpriv description:\n
 *         - iwpriv cmd: iwpriv athN get_countrycode\n
 *             This command will return the current setting of the country
 *             code.  The country code values are listed in AP manual Appendix
 *             A.
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_chwidth\n
 *           This command retrieves the current channel width setting.  This is
 *           not necessarily the value set by cwmode, because it can be
 *           automatically overridden.  The value returned is either 0 (HT 20),
 *           1 (20), or 2 (20/40) or 3 (20/40/80) .
 *             - iwpriv category: HT/VHT
 *             - iwpriv arguments: None
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_chextoffset\n
 *           Get function for chextoffset
 *             - iwpriv category: ht40/20 coexistence
 *             - iwpriv arguments:
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_extprotmode\n
 *           Get function for extprotmode
 *             - iwpriv category: CWM mode
 *             - iwpriv arguments: Not in AP Man\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN get_extprotspac\n
 *           Get function for extprotspac
 *             - iwpriv category: CWM mode
 *             - iwpriv arguments: Not in AP Man\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN get_cwmenable\n
 *           Get function for cwmenable
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_shortgi\n
 *           Get function for shortgi
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_protmode\n
 *           Get function for protmode
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_hide_ssid\n
 *           Get function for hide_ssid
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_ap_bridge\n
 *           Get function for ap_bridge
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_dtim_period\n
 *           Get function for dtim_period
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_bintval\n
 *           Get function for bintval
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_doth\n
 *           Get function for doth
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_pureg\n
 *           Get function for pureg
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_countryie\n
 *           Get function for get_countryie
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_wmm\n
 *           Get function for wmm
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_uapsd\n
 *           Get function for uapsd
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN getdbgLVL\n
 *           Get function for dbgLVL
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_authmode\n
 *           Get function for authmode
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_mode\n
 *           Get function for mode
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_tx_chainmask\n
 *           Get function for tx_chainmask
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_tx_cm_legacy\n
 *           Get function for tx_cm_legacy
 *             - iwpriv category: chain mask
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_rx_chainmask\n
 *           Get function for rx_chainmask
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_ampdu\n
 *           Get function for ampdu
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_ampdulimit\n
 *           Get function for ampdulimit
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_ampdudensity\n
 *           Cannot find in AP Man
 *             - iwpriv category: 11n A-MPDU, A-MSDU support
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_ampdusframes\n
 *           Get function for ampdusframes
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_roaming\n
 *           Get function for roaming
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_inact\n
 *           Get function for inact
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_inact_auth\n
 *           Get function for inact_auth
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_inact_init\n
 *           Get function for inact_init
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_doth_pwrtgt\n
 *           Get function for doth_pwrtgt
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_compression\n
 *           Get function for compression
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_ff\n
 *           Get function for ff
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_turbe\n
 *           Get function for turbo
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_burst\n
 *           Get function for burst
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_ar\n
 *           Get function for ar
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_bgscan\n
 *           Get function for bgscan
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_bgscanidle\n
 *           Get function for bgscanidle
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_bgscanintvl\n
 *           Get function for bgscanintvl
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_coveragecls\n
 *           Get function for coveragecls
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_scanvalid\n
 *           Get function for scanvalid
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *
 *         - iwpriv cmd: iwpriv athN get_regclass\n
 *           Get function for regclass
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_rssi11a\n
 *           Get function for rssi11a
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_rssi11b\n
 *           Get function for rssi11b
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_rssi11g\n
 *           Get function for rssi11g
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_rate11a\n
 *           Get function for rate11a
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_rate11b\n
 *           Get function for rate11b
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_rate11g\n
 *           Get function for rate11g
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_sleep\n
 *           Get function for sleep
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_eospdrop\n
 *           Get function for eospdrop
 *             - iwpriv category: PS
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_markdfs\n
 *           Get function for markdfs
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_dfsdomain\n
 *           Get DFS Domain. 0 indicates uninitialized DFS domain,
 *           1 indicates FCC3, 2 indicates ETSI, 3 indicates Japan.
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_fastcc\n
 *           Get function for fastcc
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_rtscts_rcode\n
 *           Get function for rtscts_rcode
 *             - iwpriv category: chain mask
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_amsdu\n
 *           Get function for amsdu
 *             - iwpriv category: 11n A-MPDU, A-MSDU support
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_amsdulimit\n
 *           Get function for amsdulimit
 *             - iwpriv category: 11n A-MPDU, A-MSDU support
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_htprot\n
 *           Get function for htprot
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_wdsdetect\n
 *           Get function for wdsdetect
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_noedgech\n
 *           Get function for noedgech
 *             - iwpriv category: Mcast enhancement (IQUE)
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_htweptkip\n
 *           Get function for get_htweptkip
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN getRadio\n
 *           For dual concurrent operations, it is desirable to be able
 *           to determine which radio a particular VAP is attached to.
 *            This command will return the index of the associated radio
 *           object (wifiN, where N is the radio number).
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_ignore11d\n
 *           Get function for ignore11d
 *             - iwpriv category: 11d Beacon processing
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_scanprsleep\n
 *           Get function for scanprsleep
 *             - iwpriv category: Unassociated power consumpion improve
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_sleepprscan\n
 *           Get function for sleepprscan
 *             - iwpriv category: Unassociated power consumpion improve
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN getwmmparams\n
 *           Cannot find in AP Manual
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN get_cwmin\n
 *           Get function of cwmin
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_cwmax\n
 *           Get function of cwmax
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_aifs\n
 *           Get function of aifs
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_txoplimit\n
 *           Get function of txoplimit
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_acm\n
 *           Get function of acm
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN g_mcastenhance\n
 *           Cannot find in AP Manual
 *             - iwpriv category: Mcast enhancement (IQUE)
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN get_medebug\n
 *           Cannot find in AP Manual
 *             - iwpriv category: Mcast enhancement (IQUE)
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN get_me_length\n
 *           Cannot find in AP Manual
 *             - iwpriv category: Mcast enhancement (IQUE)
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN get_metimer\n
 *           Cannot find in AP Manual
 *             - iwpriv category: Mcast enhancement (IQUE)
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN get_metimeout\n
 *           Cannot find in AP Manual
 *             - iwpriv category: Mcast enhancement (IQUE)
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN get_medropmcast\n
 *           Cannot find in AP Manual
 *             - iwpriv category: Headline block removal(IQUE)
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN get_hbrtimer\n
 *           Cannot find in AP Manual
 *             - iwpriv category: Headline block removal(IQUE)
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN get_hbrstate\n
 *           Cannot find in AP Manual
 *             - iwpriv category: Headline block removal(IQUE)
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN get_iqueconfig\n
 *           Cannot find in AP Manual
 *             - iwpriv category: rate control / AC parameters (IQUE)
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN get_vapcontryie\n
 *           Get function for vap_contryie
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_vap_doth\n
 *           Get function for vap_doth
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_sko\n
 *           Get function for sko
 *             - iwpriv category: STA Quick Kickout
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN g_disablecoext\n
 *           Get function for disablecoext
 *             - iwpriv category: ht40/20 coexistence
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN get_ht40intol\n
 *           Get function for ht40intol
 *             - iwpriv category: ht40/20 coexistence
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN get_ant_ps_on\n
 *           Get function for ant_ps_on
 *             - iwpriv category: GREEN AP
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_ps_timeout\n
 *           Get function for ps_timeout
 *             - iwpriv category: GREEN AP
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_wds\n
 *           Get function of wds
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_extap\n
 *           Get function of extap
 *             - iwpriv category: EXT AP
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN getparam\n
 *           Its for sub-ioctl handlers, usually we would not use it directly.
 *           For example: "iwpriv ath0 get_ampdu" should be equivalent
 *           to "iwpriv ath0 getparam 73"
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN get_mcastcipher\n
 *           Get function of mcastcipher
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_mcastkeylen\n
 *           Get function of mcastkeylen
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_uciphers\n
 *           Cannot find in AP Manual
 *             - iwpriv category: Crypto
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN get_ucastcipher\n
 *           Get function of ucastcipher
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_ucastkeylen\n
 *           Get function of ucastkeylen
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_keymgtalgs\n
 *           Get function of keymgtalgs
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_rsncaps\n
 *           Get function of rsncaps
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_privacy\n
 *           Get function of privacy
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_countermeas\n
 *           check if TKIP countermeasures or not. Which would disallow
 *           auth and Discard all Tx/Rx TKIP frame.
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_dropunencry\n
 *           check if drop unencrypted recieve frame or not
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_wpa\n
 *           Get function of wpa
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_driver_caps\n
 *           Get function of driver_caps
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_wps\n
 *           Get function of wps
 *             - iwpriv category: WPS IE
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN getchanlist\n
 *           Get function of setchanlist
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN get_mcast_rate\n
 *           Get function of mcast_rate
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_chanbw\n
 *           Get function of chanbw
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN g_extbusythres\n
 *           Get function of extbusythres
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get11NRates\n
 *           Get function of 11NRates
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN get11NRetries\n
 *           Get function of 11NRetries
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN get_chscaninit\n
 *           Get function of chscaninit
 *             - iwpriv category: ht40/20 coexistence
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN getoptie\n
 *           get application specific optional ie buffer.
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_noackpolicy\n
 *           Get function of noackpolicy
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_shpreamble\n
 *           Get function of shpreamble
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN getiebuf\n
 *           Get function of setiebuf
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN get_maccmd\n
 *           Get function of maccmd
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN getaddbastatus\n
 *           Cannot find in AP Manual
 *             - iwpriv category: 11n A-MPDU, A-MSDU support
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN get_puren\n
 *           Get function for puren
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_stafwd\n
 *           Get function of stafwd
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_powersave\n
 *           Get function of powersave
 *             - iwpriv category: PS
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN get_autoassoc\n
 *           Get function of auto-association
 *             - iwpriv category: Others
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: 0
 *             .
 *         - iwpriv cmd: iwpriv athN get_vap_ind\n
 *           Get function of vap_ind
 *             - iwpriv category: Unassociated power consumpion improve
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN g_periodicScan\n
 *           Get function of periodicScan
 *             - iwpriv category: ATHEROS_LINUX_PERIODIC_SCAN
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: medump_dummy\n
 *           Cannot find in AP Manual
 *             - iwpriv category: Mcast enhancement (IQUE)
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: medump\n
 *           Cannot find in AP Manual
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *           This command retrieves the current VHT mcs rates supported. This is
 *           a bitmap of UINT16 with 2 bits representing ithe Max MCS supported by
 *           each Nss. The Nss can range from 1-8 and the values indicate
 *           0= MCS 0-7, 1=MCS 0-8 2 = MCS 0-9 3 = Nss not supported.
 *             - iwpriv arguments: None
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_deschan\n
 *           Get desired channel corresponding to desired PHY mode. A return
 *           value of 0 corresponds to IEEE80211_CHAN_ANYC (Any Channel). This
 *           is primarily intended for use by external channel selection
 *           applications.
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 *         - iwpriv cmd: iwpriv athN get_desmode\n
 *           Get integer enumerated value for desired PHY mode. This is
 *           primarily intended for use by external channel selection
 *           applications and the return values are defined accordingly, to be
 *           in sync with driver enumeration for PHY mode.
 *           The values are 0 (autoselect),
 *           1 (5GHz, OFDM),  2 (2.4GHz, CCK), 3 (2.4GHz, OFDM),
 *           4 (2.4GHz, GFSK), 5 (5GHz, OFDM, 2x clock dynamic turbo),
 *           6 (2.4GHz, OFDM, 2x clock dynamic turbo), 7 (5GHz, HT20),
 *           8 (2.4GHz, HT20), 9 (5GHz, HT40, ext ch +1),
 *           10 (5GHz, HT40, ext ch -1), 11 (2.4GHz, HT40, ext ch +1),
 *           12 (2.4GHz, HT40, ext ch -1), 13 (2.4GHz, Auto HT40),
 *           14 (5GHz, Auto HT40), 15 (5GHz, VHT20),
 *           16 (5GHz, VHT40, ext ch +1), 17 (5GHz, VHT40, ext ch -1),
 *           18 (5GHz, VHT40), 19 (5GHz, VHT80)
 *             - iwpriv category: N/A
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 */

int ieee80211_ioctl_getparam(struct net_device *dev, struct iw_request_info *info,
    void *w, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    int *param = (int *) extra;

    debug_print_ioctl(dev->name, param[0], find_ieee_priv_ioctl_name(param[0], 0));
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
            "%s parameter is 0x%x\n", __func__, param[0]);

    return ieee80211_ucfg_getparam(vap, *param, param);
}

/**
 * @brief
 *     - Function description:\n
 *     - iwpriv description:\n
 *         - iwpriv cmd: setoptie\n
 *           set application specific optional ie buffer.
 *             - iwpriv category: COMMON
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 */
static int
ieee80211_ioctl_setoptie(struct net_device *dev, struct iw_request_info *info,
    void *w, char *extra)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    union iwreq_data *u = w;
    void *ie;

    debug_print_ioctl(dev->name, IEEE80211_IOCTL_SETOPTIE, "setoptie") ;
    /*
    * NB: Doing this for ap operation could be useful (e.g. for
    *     WPA and/or WME) except that it typically is worthless
    *     without being able to intervene when processing
    *     association response frames--so disallow it for now.
    */
#ifndef ATH_SUPPORT_P2P
    if (osifp->os_opmode != IEEE80211_M_STA && osifp->os_opmode != IEEE80211_M_IBSS)
        return -EINVAL;
#endif

    /* NB: data.length is validated by the wireless extensions code */
    ie = OS_MALLOC(osifp->os_handle, u->data.length, GFP_KERNEL);
    if (ie == NULL)
        return -ENOMEM;
    memcpy(ie, extra, u->data.length);
    wlan_mlme_set_optie(vap, ie, u->data.length);
    OS_FREE(ie);
    return 0;
}

static int
ieee80211_ioctl_getoptie(struct net_device *dev, struct iw_request_info *info,
    void *w, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    u_int32_t opt_ielen;
    union iwreq_data *u = w;
    int rc = 0;
    debug_print_ioctl(dev->name, IEEE80211_IOCTL_GETOPTIE, "getoptie") ;
    opt_ielen = u->data.length;
    rc = wlan_mlme_get_optie(vap, (u_int8_t *)extra, &opt_ielen, opt_ielen);
    if (!rc) {
        u->data.length = opt_ielen;
    }
    return rc;
}

/**
 * @brief
 *     - Function description:\n
 *     - iwpriv description:\n
 *         - iwpriv cmd: setiebuf\n
 *           These commands are used by an application to set/get application
 *           structure is passed as an argument to the ioctl.  There is
 *           no command line equivalent for these commands, but the command
 *           does show up as a valid iwpriv command.  The definition of
 *           the required data structure is as follows:\n
 *           struct ieee80211req_getset_appiebuf {\n
 *           u_int32_t app_frmtype; //management frame type for which buffer is added\n
 *           u_int32_t app_buflen;  //pplication supplied buffer length\n
 *           u_int8_t  app_buf[];\n
 *           };
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 */
static int
ieee80211_ioctl_setappiebuf(struct net_device *dev,
    struct iw_request_info *info,
    void *w, char *extra)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211req_getset_appiebuf *iebuf =      \
            ( struct ieee80211req_getset_appiebuf *)extra;
    int rc = 0;

    struct ieee80211vap *vap_handle = vap;

    debug_print_ioctl(dev->name, IEEE80211_IOCTL_SET_APPIEBUF, "setappiebuf") ;

    if (iebuf->app_buflen > IEEE80211_APPIE_MAX) {
        return -EINVAL;
    }
    switch(iebuf->app_frmtype)
    {
    case IEEE80211_APPIE_FRAME_BEACON:
        rc = wlan_mlme_app_ie_set_check(vap_handle, IEEE80211_FRAME_TYPE_BEACON, iebuf->app_buf, iebuf->app_buflen, iebuf->identifier);
        /*currently hostapd does not support
        * multiple ie's in application buffer
        */
        if (iebuf->app_buflen && iswpsoui(iebuf->app_buf))
            wlan_set_param(vap,IEEE80211_WPS_MODE,1);
        /* EV : 89216 :
         * WPS2.0 : Reset back WPS Mode value to handle
         * hostapd abort, termination Ignore MAC Address
         * Filtering if WPS Enabled
         * return 1 to report success
         */
        else if((iebuf->app_buflen == 0) && vap->iv_wps_mode)
            wlan_set_param(vap,IEEE80211_WPS_MODE,0);
        break;
    case IEEE80211_APPIE_FRAME_PROBE_REQ:
#ifndef ATH_SUPPORT_P2P
        if (osifp->os_opmode != IEEE80211_M_STA &&
            osifp->os_opmode != IEEE80211_M_P2P_DEVICE)
            return -EINVAL;
#endif
        rc = wlan_mlme_app_ie_set_check(vap_handle, IEEE80211_FRAME_TYPE_PROBEREQ, iebuf->app_buf, iebuf->app_buflen, iebuf->identifier);
        break;
    case IEEE80211_APPIE_FRAME_PROBE_RESP:
#ifndef ATH_SUPPORT_P2P
        if (osifp->os_opmode != IEEE80211_M_HOSTAP  &&
            osifp->os_opmode != IEEE80211_M_P2P_DEVICE)
            return -EINVAL;
#endif

#ifdef ATH_SUPPORT_P2P
        if (osifp->os_opmode == IEEE80211_M_P2P_GO){
            wlan_p2p_GO_parse_appie(osifp->p2p_go_handle, IEEE80211_FRAME_TYPE_PROBERESP, iebuf->app_buf, iebuf->app_buflen);
            rc = wlan_p2p_GO_set_appie(osifp->p2p_go_handle, IEEE80211_FRAME_TYPE_PROBERESP, iebuf->app_buf, iebuf->app_buflen, iebuf->identifier);
        }else if (osifp->os_opmode == IEEE80211_M_P2P_DEVICE){
            wlan_p2p_parse_appie(osifp->p2p_handle, IEEE80211_FRAME_TYPE_PROBERESP, iebuf->app_buf, iebuf->app_buflen);
            rc = wlan_mlme_app_ie_set_check(vap_handle, IEEE80211_FRAME_TYPE_PROBERESP, iebuf->app_buf, iebuf->app_buflen, iebuf->identifier);
        }else
#endif
            rc = wlan_mlme_app_ie_set_check(vap_handle, IEEE80211_FRAME_TYPE_PROBERESP, iebuf->app_buf, iebuf->app_buflen, iebuf->identifier);
        break;
    case IEEE80211_APPIE_FRAME_ASSOC_REQ:
#ifndef ATH_SUPPORT_P2P
        if(osifp->os_opmode != IEEE80211_M_STA)
            return -EINVAL;
#endif
        rc = wlan_mlme_app_ie_set_check(vap_handle, IEEE80211_FRAME_TYPE_ASSOCREQ, iebuf->app_buf, iebuf->app_buflen, iebuf->identifier);
        break;
    case IEEE80211_APPIE_FRAME_ASSOC_RESP:
#ifndef ATH_SUPPORT_P2P
        if(osifp->os_opmode != IEEE80211_M_HOSTAP)
            return -EINVAL;
#endif
        rc = wlan_mlme_app_ie_set_check(vap_handle, IEEE80211_FRAME_TYPE_ASSOCRESP, iebuf->app_buf, iebuf->app_buflen, iebuf->identifier);
        break;
#if UMAC_SUPPORT_WNM
    case IEEE80211_APPIE_FRAME_WNM:
        rc = ieee80211_wnm_set_appie(vap, iebuf->app_buf, iebuf->app_buflen);
        break;
#endif /* UMAC_SUPPORT_WNM */
    case IEEE80211_APPIE_FRAME_AUTH:
        rc = wlan_mlme_app_ie_set_check(vap_handle, IEEE80211_FRAME_TYPE_AUTH, iebuf->app_buf, iebuf->app_buflen, iebuf->identifier);
        break;
    default:
        return -EINVAL;

    }
    vap->appie_buf_updated = 1;
    return rc;
}

static int
ieee80211_ioctl_getappiebuf(struct net_device *dev, struct iw_request_info *info,
    void *w, char *extra)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211req_getset_appiebuf *iebuf = \
            ( struct ieee80211req_getset_appiebuf *)extra;
    int rc = 0;

    /*
     * Looks like the iebuf should be pointing to w rather than extra
     *
     */
    struct iw_point *data = (struct iw_point*)w;
    int max_iebuf_len;

    max_iebuf_len = data->length - sizeof(struct
    ieee80211req_getset_appiebuf);

    if (max_iebuf_len < 0)
        return -EINVAL;

    if (__xcopy_from_user(iebuf, data->pointer, sizeof(struct ieee80211req_getset_appiebuf)))
        return -EFAULT;

    if (iebuf->app_buflen > max_iebuf_len)
        iebuf->app_buflen = max_iebuf_len;

    debug_print_ioctl(dev->name, IEEE80211_IOCTL_GET_APPIEBUF, "getappiebuf") ;


    switch(iebuf->app_frmtype)
    {
    case IEEE80211_APPIE_FRAME_BEACON:
#ifndef ATH_SUPPORT_P2P
        if(osifp->os_opmode == IEEE80211_M_STA)
            return -EINVAL;
#endif
        rc = wlan_mlme_get_appie(vap, IEEE80211_FRAME_TYPE_BEACON, iebuf->app_buf, &iebuf->app_buflen, iebuf->app_buflen, iebuf->identifier);
        break;
    case IEEE80211_APPIE_FRAME_PROBE_REQ:
#ifndef ATH_SUPPORT_P2P
        if(osifp->os_opmode != IEEE80211_M_STA)
            return -EINVAL;
#endif
        rc = wlan_mlme_get_appie(vap, IEEE80211_FRAME_TYPE_PROBEREQ, iebuf->app_buf, &iebuf->app_buflen, iebuf->app_buflen, iebuf->identifier);
        break;
    case IEEE80211_APPIE_FRAME_PROBE_RESP:
#ifndef ATH_SUPPORT_P2P
        if(osifp->os_opmode == IEEE80211_M_STA &&
            osifp->os_opmode != IEEE80211_M_P2P_DEVICE)
            return -EINVAL;
#endif
        rc = wlan_mlme_get_appie(vap, IEEE80211_FRAME_TYPE_PROBERESP, iebuf->app_buf, &iebuf->app_buflen, iebuf->app_buflen, iebuf->identifier);
        break;
    case IEEE80211_APPIE_FRAME_ASSOC_REQ:
#ifndef ATH_SUPPORT_P2P
        if(osifp->os_opmode != IEEE80211_M_STA)
            return -EINVAL;
#endif
        rc = wlan_mlme_get_appie(vap, IEEE80211_FRAME_TYPE_ASSOCREQ, iebuf->app_buf, &iebuf->app_buflen, iebuf->app_buflen, iebuf->identifier);
        break;
    case IEEE80211_APPIE_FRAME_ASSOC_RESP:
#ifndef ATH_SUPPORT_P2P
        if(osifp->os_opmode == IEEE80211_M_STA)
            return -EINVAL;
#endif
        rc = wlan_mlme_get_appie(vap, IEEE80211_FRAME_TYPE_ASSOCRESP, iebuf->app_buf, &iebuf->app_buflen, iebuf->app_buflen, iebuf->identifier);
        break;

    case IEEE80211_APPIE_FRAME_AUTH:
#ifndef ATH_SUPPORT_P2P
        if (osifp->os_opmode == IEEE80211_M_STA)
            return -EINVAL;
#endif
        rc = wlan_mlme_get_appie(vap, IEEE80211_FRAME_TYPE_ASSOCRESP, iebuf->app_buf, &iebuf->app_buflen, iebuf->app_buflen, iebuf->identifier);
        break;
#if UMAC_SUPPORT_WNM
    case IEEE80211_APPIE_FRAME_WNM:
        /* copy the common header */
        if (__xcopy_from_user(&(iebuf->app_buf[0]),
                            (u8 *)data->pointer+sizeof(struct ieee80211req_getset_appiebuf),
                            ETH_ALEN + 2 + 2))
            return -EFAULT;
        rc = ieee80211_wnm_get_appie(vap, iebuf->app_buf, &iebuf->app_buflen, iebuf->app_buflen);
        break;
#endif
    default:
        return -EINVAL;
    }

    data->length = sizeof(struct ieee80211req_getset_appiebuf) +
    iebuf->app_buflen;
    return rc;
}

/**
 * @brief
 *     - Function description:\n
 *     - iwpriv description:\n
 *         - iwpriv cmd: iwpriv athN setfilter filter\n
 *           This command allows an application to specify which management
 *           frames it wants to receive from the VAP.  This will cause
 *           the VAP to forward the indicated frames to the networking
 *           stack.  This command is normally used by host_apd for configuring
 *           the VAP. It does NOT have a corresponding get command.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:\n
 * The filter is a set of bits with the following values:\n
 * Bit	Frame type to forward\n
 * 0x01	Beacon\n
 * 0x02	Probe Request\n
 * 0x04	Probe Response\n
 * 0x08	Association Request\n
 * 0x10	Association Response\n
 * 0x20	Authentication\n
 * 0x40	Deauthentication\n
 * 0x80	Disassociation\n
 * 0xff	ALL\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 */

void static
wlan_sta_send_mgmt(void *arg, struct ieee80211_node *ni)
{
    struct ieee80211vap    *vap = ni->ni_vap;
    struct ieee80211req_mgmtbuf *mgmt_frm =      \
            ( struct ieee80211req_mgmtbuf *)arg;
    int rc =0;

    if (ni != vap->iv_bss)
    {
        rc = wlan_send_mgmt(vap, ni->ni_macaddr, mgmt_frm->buf, mgmt_frm->buflen);
    }
}

static int
ieee80211_ioctl_sendmgmt(struct net_device *dev,
    struct iw_request_info *info,
    void *w, char *extra)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211req_mgmtbuf *mgmt_frm =      \
            ( struct ieee80211req_mgmtbuf *)extra;
    int rc = 0;

    debug_print_ioctl(dev->name, IEEE80211_IOCTL_SEND_MGMT, "sendmgmt");
    if(mgmt_frm->buflen >= 37 && mgmt_frm->buf[24] == 0xff)
        {
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "unknown action frame\n");
            return 1; //drop unknown action frame type seen in hostapd
        }

   if(IEEE80211_IS_BROADCAST(mgmt_frm->macaddr))
    {
        rc = wlan_iterate_station_list(vap, wlan_sta_send_mgmt, mgmt_frm);
    }
    else
    {
        rc = wlan_send_mgmt(vap, mgmt_frm->macaddr, mgmt_frm->buf, mgmt_frm->buflen);
    }
    return rc;
}

static int
ieee80211_ioctl_setfilter(struct net_device *dev, struct iw_request_info *info,
    void *w, char *extra)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211req_set_filter *app_filter = ( struct ieee80211req_set_filter *)extra;

    debug_print_ioctl(dev->name, IEEE80211_IOCTL_FILTERFRAME, "setfilter") ;
    if ((extra == NULL) || (app_filter->app_filterype & ~IEEE80211_FILTER_TYPE_ALL))
        return -EINVAL;
    osifp->app_filter =  app_filter->app_filterype;

    if (osifp->app_filter &
           (IEEE80211_FILTER_TYPE_ASSOC_REQ | IEEE80211_FILTER_TYPE_AUTH)) {
        wlan_set_param(vap, IEEE80211_TRIGGER_MLME_RESP, 1);
    }

   if (osifp->app_filter == 0) {
        wlan_set_param(vap, IEEE80211_TRIGGER_MLME_RESP, 0);
   }

    return 0;
}

#if ATH_SUPPORT_IQUE
static int
ieee80211_ioctl_setrcparams(struct net_device *dev, struct iw_request_info *info,
    void *w, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    int *param = (int *) extra;
    int retv = -1;
    debug_print_ioctl(dev->name, IEEE80211_IOCTL_SET_RTPARAMS, "setrtparams") ;
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                  "%s: type %d  param[1] %d param[2] %d param[3] %d\n",
                 __func__, param[0], param[1], param[2], param[3]);
    switch(param[0])
    {
        case IEEE80211_IOCTL_RCPARAMS_RTPARAM:
            retv = ieee80211_ucfg_rcparams_setrtparams(vap, param[1], param[2], param[3]);
            break;
        case IEEE80211_IOCTL_RCPARAMS_RTMASK:
            retv = ieee80211_ucfg_rcparams_setratemask(vap, param[1], param[2], param[3]);
            break;
        default:
            break;
    }
    return retv;
}
/**
 * @brief
 *     - Function description:\n
 *     - iwpriv description:\n
 *         - iwpriv cmd: acparams\n
 *           Cannot find in AP Manual
 *             - iwpriv category: rate control / AC parameters (IQUE)
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 */
static int
ieee80211_ioctl_setacparams(struct net_device *dev, struct iw_request_info *info,
    void *w, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    u_int8_t ac, use_rts, aggrsize_scaling;
    u_int32_t min_kbps;
    int *param = (int *) extra;

    debug_print_ioctl(dev->name, IEEE80211_IOCTL_SET_ACPARAMS, "setacparams") ;
    ac  = (u_int8_t)param[0];
    use_rts = (u_int8_t)param[1];
    aggrsize_scaling = (u_int8_t)param[2];
    min_kbps = ((u_int8_t)param[3]) * 1000;

    if (ac > 3 || (use_rts != 0 && use_rts != 1) ||
        aggrsize_scaling > 4 || min_kbps > 250000)
    {
        goto error;
    }

    wlan_set_acparams(vap, ac, use_rts, aggrsize_scaling, min_kbps);
    return 0;

error:
    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "usage: acparams ac <0|3> RTS <0|1> aggr scaling <0..4> min mbps <0..250>\n");
    return -EINVAL;
}

/**
 * @brief
 *     - Function description:\n
 *     - iwpriv description:\n
 *         - iwpriv cmd: hbrparams\n
 *           Cannot find in AP Manual
 *             - iwpriv category: rate control / AC parameters (IQUE)
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 */
static int
ieee80211_ioctl_sethbrparams(struct net_device *dev, struct iw_request_info *info,
    void *w, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    u_int8_t ac, enable, per_low;
    int *param = (int *)extra;

    debug_print_ioctl(dev->name, IEEE80211_IOCTL_SET_HBRPARAMS, "sethbrparams") ;
    ac = (u_int8_t)param[0];
    enable = (u_int8_t)param[1];
    per_low = (u_int8_t)param[2];

    if (ac != 2 || (enable != 0 && enable != 1) || per_low > 49)
    {
        goto hbr_error;
    }
    wlan_set_hbrparams(vap, ac, enable, per_low);
    return 0;

hbr_error:
    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "usage: hbrparams ac <2> enable <0|1> per_low <0..49>\n");
    return -EINVAL;
}

/**
 * @brief
 *     - Function description:\n
 *     - iwpriv description:\n
 *         - iwpriv cmd: me_adddeny\n
 *           Cannot find in AP Manual
 *             - iwpriv category: rate control / AC parameters (IQUE)
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 */
static int
ieee80211_ioctl_setmedenyentry(struct net_device *dev, struct iw_request_info *info,
    void *w, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    int *param = (int *)extra;

    debug_print_ioctl(dev->name, IEEE80211_IOCTL_SET_MEDENYENTRY, "set_me_denyentry") ;
    if(!wlan_set_me_denyentry(vap, param)) {
        return 0;
    } else {
        return -EINVAL;
    }
}

#endif /* ATH_SUPPORT_IQUE */


/**
 * @brief
 *     - Function description: Function to handle FIPS test mode from application.
 *     Used with wifitool application
 *     - wifitool description:\
 *     - wifitool <interface> <cmd> <input file>
 *     cmd to be given fips
 *     eg: wifitool ath0 fips input_file
 *
 */
#if ATH_SUPPORT_FIPS
static int
ieee80211_ioctl_fips(struct net_device *dev, void *arg, int length)
{
    struct ath_fips_cmd *fips_buf = NULL;
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    int retval = 0;
    if (arg != NULL && length < MAX_FIPS_BUFFER_SIZE) {
        fips_buf = (struct ath_fips_cmd *) OS_MALLOC (osifp->os_handle, length, GFP_KERNEL);
        if (fips_buf != NULL) {
            if (copy_from_user(fips_buf, (struct ath_fips_cmd* )arg, length)) {
                QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n %s:%d Copy from user failed! \t ", __func__, __LINE__);
                retval = -EFAULT;
                goto done;
            }
            retval = wlan_set_fips(vap, fips_buf);
        }
        else {
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n %s:%d Malloc failed", __func__, __LINE__);
            return -ENOMEM;
        }
    }
    else {
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n %s:%d Input Data is NULL \t", __func__, __LINE__);
        retval = -EINVAL;
    }
done:
    if (fips_buf != NULL)
        OS_FREE(fips_buf);
    return retval;
}
#endif

#if MESH_MODE_SUPPORT
int
ieee80211_add_localpeer(wlan_if_t vap, char *params)
{
    uint8_t mac[IEEE80211_ADDR_LEN];
    uint32_t *config = (uint32_t *) params;
    int status = 0;

    uint32_t caps;
    uint32_t mac1 = config[1];
    uint32_t mac2 = config[2];

    caps = (mac1 & 0xff000000) >> 16;
    caps = ((mac1 & 0x00ff0000) >> 16) | caps;

    mac[0] = (uint8_t)((mac1 & 0x0000ff00) >> 8);
    mac[1] = (uint8_t)((mac1 & 0x000000ff) >> 0);
    mac[2] = (uint8_t)((mac2 & 0xff000000) >> 24);
    mac[3] = (uint8_t)((mac2 & 0x00ff0000) >> 16);
    mac[4] = (uint8_t)((mac2 & 0x0000ff00) >> 8);
    mac[5] = (uint8_t)((mac2 & 0x000000ff) >> 0);

    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "local peer mac addr %x:%x:%x:%x:%x:%x caps %x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],caps);
    IEEE80211_ADDR_COPY(vap->bssid_mesh,mac);

    if (ieee80211_vap_ready_is_set(vap)) {
        status = wlan_add_localpeer(vap, mac, caps);
    }
    return status;
}

int
ieee80211_authorise_local_peer(wlan_if_t vap, char *params)
{
    uint8_t mac[IEEE80211_ADDR_LEN];
    uint32_t *config = (uint32_t *) params;
    int status = 0;

    uint32_t mac1 = config[1];
    uint32_t mac2 = config[2];

    mac[0] = (uint8_t)((mac1 & 0x0000ff00) >> 8);
    mac[1] = (uint8_t)((mac1 & 0x000000ff) >> 0);
    mac[2] = (uint8_t)((mac2 & 0xff000000) >> 24);
    mac[3] = (uint8_t)((mac2 & 0x00ff0000) >> 16);
    mac[4] = (uint8_t)((mac2 & 0x0000ff00) >> 8);
    mac[5] = (uint8_t)((mac2 & 0x000000ff) >> 0);

    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "local peer mac addr %x:%x:%x:%x:%x:%x \n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

    status = wlan_authorise_local_peer(vap, mac);

    return status;
}
#endif

#if UMAC_SUPPORT_NAWDS
static int
ieee80211_ioctl_nawds(struct net_device *dev, struct iwreq *iwr)
{
    wlan_if_t vap = NETDEV_TO_VAP(dev);
    struct ieee80211_wlanconfig config;
    struct ieee80211_wlanconfig_nawds *nawds;

    if (iwr->u.data.length < sizeof(struct ieee80211_wlanconfig))
        return -EFAULT;

    if (__xcopy_from_user(&config, iwr->u.data.pointer, sizeof(struct ieee80211_wlanconfig))) {
        return -EFAULT;
    }
    nawds = &config.data.nawds;

    switch (config.cmdtype) {
        case IEEE80211_WLANCONFIG_NAWDS_SET_MODE:
            return wlan_nawds_set_param(vap, IEEE80211_NAWDS_PARAM_MODE, &nawds->mode);
        case IEEE80211_WLANCONFIG_NAWDS_SET_DEFCAPS:
            return wlan_nawds_set_param(vap, IEEE80211_NAWDS_PARAM_DEFCAPS, &nawds->defcaps);
        case IEEE80211_WLANCONFIG_NAWDS_SET_OVERRIDE:
            return wlan_nawds_set_param(vap, IEEE80211_NAWDS_PARAM_OVERRIDE, &nawds->override);
        case IEEE80211_WLANCONFIG_NAWDS_SET_ADDR:
            {
                int status;
                status = wlan_nawds_config_mac(vap, nawds->mac, nawds->caps);
                if( status == 0 ) {
                    OS_SLEEP(250000);
                }
                return status;
            }

        case IEEE80211_WLANCONFIG_NAWDS_CLR_ADDR:
            return wlan_nawds_delete_mac(vap, nawds->mac);
        case IEEE80211_WLANCONFIG_NAWDS_GET:
            wlan_nawds_get_param(vap, IEEE80211_NAWDS_PARAM_MODE, &nawds->mode);
            wlan_nawds_get_param(vap, IEEE80211_NAWDS_PARAM_DEFCAPS, &nawds->defcaps);
            wlan_nawds_get_param(vap, IEEE80211_NAWDS_PARAM_OVERRIDE, &nawds->override);
            if (wlan_nawds_get_mac(vap, nawds->num, &nawds->mac[0], &nawds->caps)) {
                QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "failed to get NAWDS entry %d\n", nawds->num);
            }
            wlan_nawds_get_param(vap, IEEE80211_NAWDS_PARAM_NUM, &nawds->num);
            config.status = IEEE80211_WLANCONFIG_OK;
            if (_copy_to_user(iwr->u.data.pointer, &config, sizeof(struct ieee80211_wlanconfig))) {
                return -EFAULT;
            }
            break;
        default:
            return -ENXIO;
    }
    return 0;
}
#endif

#if defined (ATH_SUPPORT_HYFI_ENHANCEMENTS)
static int
ieee80211_ioctl_hmwds(struct net_device *dev, struct iwreq *iwr)
{
    int ret = 0;
    wlan_if_t vap = NETDEV_TO_VAP(dev);
    struct ieee80211_wlanconfig *config;
    struct ieee80211_wlanconfig_hmwds *hmwds;
    struct ieee80211_wlanconfig_wds_table *wds_table;
    osif_dev *osifp = ath_netdev_priv(dev);


    if (iwr->u.data.length < sizeof(struct ieee80211_wlanconfig)){
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Bad length\n", __func__);
        return -EFAULT;
    }

    config = (struct ieee80211_wlanconfig *)OS_MALLOC(
            osifp->os_handle, iwr->u.data.length, GFP_KERNEL);
    if (!config)
        return -ENOMEM;

    if (__xcopy_from_user(config, iwr->u.data.pointer, iwr->u.data.length)) {
        OS_FREE(config);
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Copy from user failed\n", __func__);
        return -EFAULT;
    }

    hmwds = &config->data.hmwds;

    switch (config->cmdtype) {
        case IEEE80211_WLANCONFIG_HMWDS_ADD_ADDR:
            ret = wlan_hmwds_add_addr(vap, hmwds->wds_ni_macaddr, hmwds->wds_macaddr, hmwds->wds_macaddr_cnt);
            break;
        case IEEE80211_WLANCONFIG_HMWDS_RESET_ADDR:
            ret = wlan_hmwds_reset_addr(vap, hmwds->wds_ni_macaddr);
            break;
        case IEEE80211_WLANCONFIG_HMWDS_RESET_TABLE:
            ret = wlan_hmwds_reset_table(vap);
            break;
        case IEEE80211_WLANCONFIG_HMWDS_READ_ADDR:
            hmwds->wds_macaddr_cnt = iwr->u.data.length - sizeof (*config);
            ret = wlan_hmwds_read_addr(vap, hmwds->wds_ni_macaddr, hmwds->wds_macaddr, &hmwds->wds_macaddr_cnt);
            if (ret)
                hmwds->wds_macaddr_cnt = 0;
            copy_to_user(iwr->u.data.pointer, config, iwr->u.data.length);
            break;
        case IEEE80211_WLANCONFIG_HMWDS_READ_TABLE:
            wds_table = &config->data.wds_table;
            wds_table->wds_entry_cnt = iwr->u.data.length - sizeof (*config);
            ret = wlan_wds_read_table(vap, wds_table);
            if (ret)
                wds_table->wds_entry_cnt = 0;
            copy_to_user(iwr->u.data.pointer, config, iwr->u.data.length);
            break;
        case IEEE80211_WLANCONFIG_HMWDS_REMOVE_ADDR:
            ret = wlan_hmwds_remove_addr(vap, hmwds->wds_macaddr);
            break;
        case IEEE80211_WLANCONFIG_HMWDS_DUMP_WDS_ADDR:
             ret = wlan_wds_dump_wds_addr(vap);
             break;
        default:
            OS_FREE(config);
            return -ENXIO;
    }

    OS_FREE(config);
    return ret;
}

/* Handles HyFi ALD ioctls */
static int
ieee80211_ioctl_ald(struct net_device *dev, struct iwreq *iwr)
{
    int ret = 0;
    wlan_if_t vap = NETDEV_TO_VAP(dev);
    struct ieee80211_wlanconfig *config;
    struct ieee80211_wlanconfig_ald *config_ald;
    osif_dev *osifp = ath_netdev_priv(dev);


    if (iwr->u.data.length < sizeof(struct ieee80211_wlanconfig)){
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Bad length\n", __func__);
        return -EFAULT;
    }

    config = (struct ieee80211_wlanconfig *)OS_MALLOC(
            osifp->os_handle, iwr->u.data.length, GFP_KERNEL);
    if (!config)
        return -ENOMEM;

    if (__xcopy_from_user(config, iwr->u.data.pointer, iwr->u.data.length)) {
        OS_FREE(config);
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Copy from user failed\n", __func__);
        return -EFAULT;
    }

    config_ald = &config->data.ald;

    switch (config->cmdtype) {
        case IEEE80211_WLANCONFIG_ALD_STA_ENABLE:
            ret = wlan_ald_sta_enable(vap, config_ald->data.ald_sta.macaddr, config_ald->data.ald_sta.enable);
            break;
        default:
            OS_FREE(config);
            return -ENXIO;
    }

    OS_FREE(config);
    return ret;
}
#endif

static int
ieee80211_ioctl_getchaninfo_160(struct net_device *dev,
        struct iwreq *iwr)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211req_chaninfo *channel;
    struct ieee80211req_chaninfo *buf;
    int nchans_max = ((IEEE80211_CHANINFO_MAX - 1) * sizeof(__u32))/
        sizeof(struct ieee80211_channel);

    channel = (struct ieee80211req_chaninfo *)OS_MALLOC(osifp->os_handle, sizeof(*channel), GFP_KERNEL);
    if (channel == NULL)
        return -ENOMEM;
    buf = (struct ieee80211req_chaninfo *)iwr->u.data.pointer;

    wlan_get_chaninfo(vap, 1, channel->ic_chans, &channel->ic_nchans);

    if (channel->ic_nchans > nchans_max) {
        channel->ic_nchans = nchans_max;
    }
    if(copy_to_user(buf, channel, channel->ic_nchans *
            sizeof(struct ieee80211_channel) + sizeof(__u32))){
       QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: copy_to_user error\n", __func__);
       return -EFAULT;
    }

    OS_FREE(channel);
    return EOK;
}

#if ATH_SUPPORT_HYFI_ENHANCEMENTS
static int
ieee80211_ioctl_hmmc_dump(struct ieee80211com *ic)
{
    int i;

    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\nMULTICAST RANGE:\n");
    for (i = 0; i < ic->ic_hmmc_cnt; i++)
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\t%d of %d: %08x/%08x\n",
                i+1,
                ic->ic_hmmc_cnt,
                ic->ic_hmmcs[i].ip,
                ic->ic_hmmcs[i].mask);
    return 0;
}

static int
ieee80211_ioctl_hmmc(struct net_device *dev, struct iwreq *iwr)
{
    int ret = 0;
    wlan_if_t vap = NETDEV_TO_VAP(dev);
    struct ieee80211_wlanconfig *config;
    struct ieee80211_wlanconfig_hmmc *hmmc;
    osif_dev *osifp = ath_netdev_priv(dev);
    struct ieee80211com *ic = vap->iv_ic;


    if (iwr->u.data.length < sizeof(struct ieee80211_wlanconfig))
        return -EFAULT;

    config = (struct ieee80211_wlanconfig *)OS_MALLOC(
            osifp->os_handle, iwr->u.data.length, GFP_KERNEL);
    if (!config)
        return -ENOMEM;

    if (__xcopy_from_user(config, iwr->u.data.pointer, iwr->u.data.length)) {
        OS_FREE(config);
        return -EFAULT;
    }

    hmmc = &config->data.hmmc;

    switch (config->cmdtype) {
        case IEEE80211_WLANCONFIG_HMMC_ADD:
            ret = ieee80211_add_hmmc(vap, hmmc->ip, hmmc->mask);
            break;
        case IEEE80211_WLANCONFIG_HMMC_DEL:
            ret = ieee80211_del_hmmc(vap, hmmc->ip, hmmc->mask);
            break;
        case IEEE80211_WLANCONFIG_HMMC_DUMP:
            ret = ieee80211_ioctl_hmmc_dump(ic);
            break;
        default:
            ret = -EOPNOTSUPP;
    }

    OS_FREE(config);
    return ret;
}
#endif

#if UMAC_SUPPORT_WNM
static int
ieee80211_ioctl_wnm(struct net_device *dev, struct iwreq *iwr)
{
    struct ieee80211_wlanconfig config;
    struct ieee80211_wlanconfig_wnm *wnm;
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211com *ic = vap->iv_ic;
    int      status = 0;

    if (iwr->u.data.length < sizeof(struct ieee80211_wlanconfig))
        return -EFAULT;

    if (__xcopy_from_user(&config, iwr->u.data.pointer,
                sizeof(struct ieee80211_wlanconfig))) {
        return -EFAULT;
    }
	if (!wlan_wnm_vap_is_set(vap))
            return -EFAULT;

    wnm = &config.data.wnm;
    switch (config.cmdtype) {
        case IEEE80211_WLANCONFIG_WNM_SET_BSSMAX:
            status = wlan_wnm_set_bssmax(vap, &wnm->data.bssmax);
            if (status == 0) {
                status = IS_UP(dev) ? -osif_vap_init(dev, RESCAN) : 0;
            } else {
                return -EFAULT;
            }
        break;
        case IEEE80211_WLANCONFIG_WNM_GET_BSSMAX:
            status = wlan_wnm_get_bssmax(vap, &wnm->data.bssmax);
            config.status = (status == 0) ? IEEE80211_WLANCONFIG_OK : IEEE80211_WLANCONFIG_FAIL;
            if (_copy_to_user(iwr->u.data.pointer, &config,
                        sizeof(struct ieee80211_wlanconfig))) {
                return -EFAULT;
            }
            break;
        break;
        case IEEE80211_WLANCONFIG_WNM_TFS_ADD: {
            status = wlan_wnm_set_tfs(vap, &wnm->data.tfs);
            return status;
        }
        case IEEE80211_WLANCONFIG_WNM_TFS_DELETE: {
            /* since there is no tfs request elements its send the
               TFS requestion action frame with NULL elements which
               will delete the existing request on AP as per specification */
            status = wlan_wnm_set_tfs(vap, &wnm->data.tfs);
            return status;
        }
        case IEEE80211_WLANCONFIG_WNM_FMS_ADD_MODIFY: {
            status = wlan_wnm_set_fms(vap, &wnm->data.fms);
            return status;
        }
        case IEEE80211_WLANCONFIG_WNM_SET_TIMBCAST: {
            status = wlan_wnm_set_timbcast(vap, &wnm->data.tim);
            return status;
        }
        case IEEE80211_WLANCONFIG_WNM_GET_TIMBCAST: {
            status = wlan_wnm_get_timbcast(vap, &wnm->data.tim);
            config.status = (status == 0) ? IEEE80211_WLANCONFIG_OK : IEEE80211_WLANCONFIG_FAIL;
            if (_copy_to_user(iwr->u.data.pointer, &config,
                        sizeof(struct ieee80211_wlanconfig))) {
                return -EFAULT;
            }
            break;
        }
        case IEEE80211_WLANCONFIG_WNM_BSS_TERMINATION:
        {
            /*
             * For offload Architecture we have no way to get the MAC TSF as of now.
             * Disabling this feature for offload untill we have a way to
             * get the TSF.
             */
            if (ic->ic_is_mode_offload(ic)) {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Disabled for Offload Architecture\n");
                return -EINVAL;
            }
            status = wlan_wnm_set_bssterm(vap, &wnm->data.bssterm);
            return status;
        }
        default:
            break;
    }

    return 0;
}
#endif

#if ATH_SUPPORT_DYNAMIC_VENDOR_IE
static int
ieee80211_ioctl_vendorie(struct net_device *dev, struct iwreq *iwr)
{
    wlan_if_t vap = NETDEV_TO_VAP(dev);
    osif_dev *osifp = ath_netdev_priv(dev);
    struct ieee80211_wlanconfig_vendorie *vie;
    u_int8_t *ie_buf;
    u_int8_t *vie_buf;
    ieee80211_frame_type ftype;
    u_int32_t ie_len = 0;
    u_int8_t temp_buf[6];
    int error;
    if ((iwr->u.data.length < sizeof(struct ieee80211_wlanconfig_vendorie)))
        return -EFAULT;
    vie_buf = OS_MALLOC(osifp->os_handle, iwr->u.data.length + 1, 0);
    if(vie_buf == NULL)
    {
        return -ENOMEM;
    }
    if (__xcopy_from_user(vie_buf, iwr->u.data.pointer, iwr->u.data.length)) {
        return -EFAULT;
    }
    vie = (struct ieee80211_wlanconfig_vendorie *) vie_buf;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s :Cmd_type=%d vie.id=%d vie.len=%d vie.oui=%2x:%2x:%2x vie.cap_info=%02x:%02x:%02x:%02x\n"
                                 , __func__, vie->cmdtype, vie->ie.id, vie->ie.len, vie->ie.oui[0], vie->ie.oui[1], vie->ie.oui[2],
                                  vie->ie.cap_info[0],vie->ie.cap_info[1],vie->ie.cap_info[2],vie->ie.cap_info[3]);
    switch (vie->cmdtype) {
        case IEEE80211_WLANCONFIG_VENDOR_IE_ADD:
            error = wlan_set_vendorie(vap, IEEE80211_VENDOR_IE_PARAM_ADD, vie);
            break;

        case IEEE80211_WLANCONFIG_VENDOR_IE_UPDATE:
            error = wlan_set_vendorie(vap, IEEE80211_VENDOR_IE_PARAM_UPDATE, vie);
            break;

        case IEEE80211_WLANCONFIG_VENDOR_IE_REMOVE:
            error = wlan_set_vendorie(vap, IEEE80211_VENDOR_IE_PARAM_REMOVE, vie);
            break;

        case IEEE80211_WLANCONFIG_VENDOR_IE_LIST:
            /*
             * List command searches all the frames and returns the IEs matching
             * the given OUI type. A simple list command will return all the IEs
             * whereas a list command followed by the OUI type will return only those
             * IEs matching the OUI. A temp_buf is used to store the OUI type recieved
             * as the iwr.u.data.pointer will be written with IE data to be returned.
             */
            ie_buf = (u_int8_t *)&vie->ie;
            memcpy(temp_buf, ie_buf, 5);
            for (ftype = 0; ftype < IEEE80211_FRAME_TYPE_MAX; ftype++)
            {
                error = wlan_get_vendorie(vap, vie, ftype, &ie_len, temp_buf);
            }
            iwr->u.data.length = ie_len + 12;
            if (_copy_to_user(iwr->u.data.pointer, vie_buf, iwr->u.data.length)) {
                return -EFAULT;
            }
            break;

        default:
            error = -ENXIO;
    }
    return error;
}
#endif

static int
ieee80211_get_atf_stats(struct net_device *dev, struct iwreq *iwr)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    struct ieee80211_wlanconfig config;
    struct ieee80211_node *ni = NULL;

    if (iwr->u.data.length < sizeof(struct ieee80211_wlanconfig)){
        return -EFAULT;
    }

    if (__xcopy_from_user(&config, iwr->u.data.pointer, sizeof(struct ieee80211_wlanconfig))) {
        return -EFAULT;
    }

    if ( (ni = ieee80211_vap_find_node(vap, config.data.atf.macaddr)) == NULL) {
        return -EINVAL;
    }

#if QCA_AIRTIME_FAIRNESS
    /* copy the node's atf statistics */
    if ( (ni->ni_atf_stats.act_tokens > ni->ni_atf_stats.unused) && (ni->ni_atf_stats.total > 0) ) {
        // avg used in the last 200ms
        config.data.atf.short_avg = (((ni->ni_atf_stats.act_tokens - ni->ni_atf_stats.unused)*100) / ni->ni_atf_stats.total);
    } else {
        config.data.atf.short_avg = 0;
    }
    config.data.atf.total_used_tokens = ni->ni_atf_stats.total_used_tokens;                        // us used total
#endif

    ieee80211_free_node(ni);

    if (_copy_to_user(iwr->u.data.pointer, &config, sizeof(struct ieee80211_wlanconfig))) {
        return -EFAULT;
    }

    return 0;
}

#if ATH_SUPPORT_NAC
static int
ieee80211_ioctl_nac(struct net_device *dev, struct iwreq *iwr)
{
    wlan_if_t vap = NETDEV_TO_VAP(dev);
    struct ieee80211_wlanconfig config;
    struct ieee80211_wlanconfig_nac *nac;

    if(!vap->iv_smart_monitor_vap) {
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Nac commands not supported in non smart monitor vap!\n");
        return -EPERM;
    }

    if (iwr->u.data.length < sizeof(struct ieee80211_wlanconfig))
        return -EFAULT;

    if (__xcopy_from_user(&config, iwr->u.data.pointer, sizeof(struct ieee80211_wlanconfig))) {
        return -EFAULT;
    }

    nac = &config.data.nac;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"%s:Cmd_type=%d mac_type=%2x nac[0][0][5]:%2x:%2x,nac[2][0][5]:%2x:%2x \n",
                                        __func__,config.cmdtype,nac->mac_type,nac->mac_list[0][0],nac->mac_list[0][5],
                                        nac->mac_list[2][0],nac->mac_list[2][5]);

    switch (config.cmdtype) {
        case IEEE80211_WLANCONFIG_NAC_ADDR_ADD:
            return wlan_set_nac(vap, IEEE80211_NAC_PARAM_ADD, nac);

        case IEEE80211_WLANCONFIG_NAC_ADDR_DEL:
            return wlan_set_nac(vap, IEEE80211_NAC_PARAM_DEL, nac);

        case IEEE80211_WLANCONFIG_NAC_ADDR_LIST:
             wlan_list_nac(vap, IEEE80211_NAC_PARAM_LIST, nac);

            if (_copy_to_user(iwr->u.data.pointer, &config, sizeof(struct ieee80211_wlanconfig))) {
                return -EFAULT;
            }
            break;

        default:
            return -ENXIO;
    }
    return 0;
}
#endif

void setmaxrate_per_client(void *arg, wlan_node_t node)
{
    struct ieee80211_wlanconfig_setmaxrate *smr =
                                (struct ieee80211_wlanconfig_setmaxrate *)arg;
    struct ieee80211_node *ni = node;
    struct ieee80211com *ic = ni->ni_ic;
    int i, rate_updated = 0;

    if (IEEE80211_ADDR_EQ(ni->ni_macaddr, smr->mac)) {
        ni->ni_maxrate = smr->maxrate;
        if (ni->ni_maxrate == 0xff) {
            ni->ni_rates.rs_nrates = ni->ni_maxrate_legacy;
            ni->ni_htrates.rs_nrates = ni->ni_maxrate_ht;
            /* set the default vht max rate info */
            ni->ni_maxrate_vht = 0xff;
            rate_updated = 1;
            goto end;
        }
        /* legacy rate */
        if (!(ni->ni_maxrate & 0x80)) {

            /* For VHT/HT capable station, do not allow user to set legacy rate as max rate */
            if ((ni->ni_vhtcap) || (ni->ni_htcap))
                return;

            for (i = 0; i < ni->ni_rates.rs_nrates; i++) {
                if ((ni->ni_maxrate & IEEE80211_RATE_VAL)
                           <= (ni->ni_rates.rs_rates[i] & IEEE80211_RATE_VAL))
                {
                    rate_updated = 1;
                    ni->ni_rates.rs_nrates = i + 1;
                    ni->ni_htrates.rs_nrates = 0;
                    ni->ni_maxrate_vht = 0;
                    break;
                }
            }
        }
        /* HT rate */
        else if (ni->ni_maxrate < 0xc0) {
            if (!ni->ni_htcap)
                return;
            /* For VHT capable station, do not allow user to set HT rate as max rate */
            if (ni->ni_vhtcap)
                return;
            for (i = 0; i < ni->ni_htrates.rs_nrates; i++) {
                if ((ni->ni_maxrate & 0x7f) <= ni->ni_htrates.rs_rates[i]) {
                    rate_updated = 1;
                    ni->ni_htrates.rs_nrates = i + 1;
                    ni->ni_maxrate_vht = 0;
                    break;
                }
            }
        }
        /* VHT rate */
        else if (ni->ni_maxrate >= 0xc0 && ni->ni_maxrate <= 0xf9) {
#define VHT_MAXRATE_IDX_MASK    0x0F
#define VHT_MAXRATE_IDX_SHIFT   4
            u_int8_t maxrate_vht_idx = (ni->ni_maxrate & VHT_MAXRATE_IDX_MASK) + 1;
            u_int8_t maxrate_vht_stream = (((ni->ni_maxrate & ~VHT_MAXRATE_IDX_MASK) - 0xc0)
                                            >> VHT_MAXRATE_IDX_SHIFT) + 1;
            if (!ni->ni_vhtcap)
                return;
            /* b0-b3: vht rate idx; b4-b7: # stream */
            ni->ni_maxrate_vht = (maxrate_vht_stream << VHT_MAXRATE_IDX_SHIFT) | maxrate_vht_idx;
            rate_updated = 1;
#undef VHT_MAXRATE_IDX_MASK
#undef VHT_MAXRATE_IDX_SHIFT
        }
        else {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Unknown max rate 0x%x\n", ni->ni_maxrate);
            return;
        }

end:
        /* Calling ath_net80211_rate_node_update() for Updating the node rate */
        if (rate_updated) {
            ic->ic_rate_node_update(ic, ni, 0);
        }

        if (ni->ni_maxrate == 0xff)
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "rateset initialized to negotiated rates\n");
     }
}

static int
ieee80211_ioctl_setmaxrate(struct net_device *dev, struct iwreq *iwr)
{
    wlan_if_t vap = NETDEV_TO_VAP(dev);
    struct ieee80211_wlanconfig config;
    struct ieee80211_wlanconfig_setmaxrate *smr;
    struct ieee80211com *ic = vap->iv_ic;

    if (!ic->ic_rate_node_update)
        return -EOPNOTSUPP;

    if (iwr->u.data.length < sizeof(struct ieee80211_wlanconfig))
        return -EFAULT;

    if (__xcopy_from_user(&config, iwr->u.data.pointer, sizeof(struct ieee80211_wlanconfig))) {
        return -EFAULT;
    }

    smr = &config.smr;

    /* Now iterate through the node table */
    wlan_iterate_station_list(vap, setmaxrate_per_client, (void *)smr);

    return 0;
}



static int
ieee80211_ioctl_config_generic(struct net_device *dev, struct iwreq *iwr)
{
    IEEE80211_WLANCONFIG_CMDTYPE cmdtype;

    /* retrieve sub-command first */
    if (iwr->u.data.length < sizeof(IEEE80211_WLANCONFIG_CMDTYPE))
    {
        return -EFAULT;
    }
    if (__xcopy_from_user(&cmdtype, iwr->u.data.pointer, sizeof(IEEE80211_WLANCONFIG_CMDTYPE))) {
        return -EFAULT;
    }

    switch (cmdtype) {
#if UMAC_SUPPORT_NAWDS
        case IEEE80211_WLANCONFIG_NAWDS_SET_MODE:
        case IEEE80211_WLANCONFIG_NAWDS_SET_DEFCAPS:
        case IEEE80211_WLANCONFIG_NAWDS_SET_OVERRIDE:
        case IEEE80211_WLANCONFIG_NAWDS_SET_ADDR:
        case IEEE80211_WLANCONFIG_NAWDS_CLR_ADDR:
        case IEEE80211_WLANCONFIG_NAWDS_GET:
            return ieee80211_ioctl_nawds(dev, iwr);
#endif
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
        case IEEE80211_WLANCONFIG_HMWDS_ADD_ADDR:
        case IEEE80211_WLANCONFIG_HMWDS_RESET_ADDR:
        case IEEE80211_WLANCONFIG_HMWDS_RESET_TABLE:
        case IEEE80211_WLANCONFIG_HMWDS_READ_ADDR:
        case IEEE80211_WLANCONFIG_HMWDS_READ_TABLE:
        case IEEE80211_WLANCONFIG_HMWDS_REMOVE_ADDR:
        case IEEE80211_WLANCONFIG_HMWDS_DUMP_WDS_ADDR:
            return ieee80211_ioctl_hmwds(dev, iwr);
#endif
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
        case IEEE80211_WLANCONFIG_HMMC_ADD:
        case IEEE80211_WLANCONFIG_HMMC_DEL:
        case IEEE80211_WLANCONFIG_HMMC_DUMP:
            return ieee80211_ioctl_hmmc(dev, iwr);
#endif
#if UMAC_SUPPORT_WNM
        case IEEE80211_WLANCONFIG_WNM_SET_BSSMAX:
        case IEEE80211_WLANCONFIG_WNM_GET_BSSMAX:
        case IEEE80211_WLANCONFIG_WNM_TFS_ADD:
        case IEEE80211_WLANCONFIG_WNM_TFS_DELETE:
        case IEEE80211_WLANCONFIG_WNM_SET_TIMBCAST:
        case IEEE80211_WLANCONFIG_WNM_GET_TIMBCAST:
	case IEEE80211_WLANCONFIG_WNM_FMS_ADD_MODIFY:
	case IEEE80211_WLANCONFIG_WNM_BSS_TERMINATION:
	    return ieee80211_ioctl_wnm(dev, iwr);
#endif
	case IEEE80211_WLANCONFIG_SET_MAX_RATE:
            return ieee80211_ioctl_setmaxrate(dev, iwr);
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
        case IEEE80211_WLANCONFIG_ALD_STA_ENABLE:
            return ieee80211_ioctl_ald(dev, iwr);
#endif
        case IEEE80211_WLANCONFIG_GETCHANINFO_160:
            return ieee80211_ioctl_getchaninfo_160(dev, iwr);

#if ATH_SUPPORT_DYNAMIC_VENDOR_IE
        case IEEE80211_WLANCONFIG_VENDOR_IE_ADD:
        case IEEE80211_WLANCONFIG_VENDOR_IE_UPDATE:
        case IEEE80211_WLANCONFIG_VENDOR_IE_REMOVE:
        case IEEE80211_WLANCONFIG_VENDOR_IE_LIST:
            return ieee80211_ioctl_vendorie(dev, iwr);
#endif

#if ATH_SUPPORT_NAC
        case IEEE80211_WLANCONFIG_NAC_ADDR_ADD:
        case IEEE80211_WLANCONFIG_NAC_ADDR_DEL:
        case IEEE80211_WLANCONFIG_NAC_ADDR_LIST:
            return ieee80211_ioctl_nac(dev, iwr);
#endif

        case IEEE80211_PARAM_STA_ATF_STAT:
            return ieee80211_get_atf_stats(dev, iwr);

        default:
            return -EOPNOTSUPP;
    }

    return -EOPNOTSUPP;
}

/**
 * @brief
 *     - Function description:\n
 *     - iwpriv description:\n
 *         - iwpriv cmd: iwpriv athN addba AID AC BufSize\n
 *           These test commands are used to manually add or delete Block
 *           Acknowledge Aggregation streams.  Note that automatic addba/delba
 *           processing must be turned off prior to using these commands
 *           (see setaddbaoper).  Both commands require the AID (association
 *           ID) and the AC specified.  The Association ID is the value
 *           shown when using the wlanconfig list command.  When adding
 *           an aggregation link with addba, the BufSize parameter must
 *           be set to the maximum number of subframes that will be sent
 *           in an aggregate.  When deleting an aggregation link, the initiator
 *           field indicates whether this link was initiated by the AP
 *           (1) or the remote station (0).  The reason code is an 8-bit
 *           value indicating the reason the link was shut down.  These
 *           commands have no corresponding get commands, nor do they have
 *           default values.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 */
static int
ieee80211dbg_sendaddba(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    wlan_dev_t ic = wlan_vap_get_devhandle(vap);
    struct ieee80211_addba_delba_request ad;

    if (wlan_get_device_param(ic, IEEE80211_DEVICE_ADDBA_MODE) == ADDBA_MODE_AUTO) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s(): ADDBA mode is AUTO\n", __func__);
        return -EINVAL;
    }

    /* Valid TID values are 0 through 15 */
    if (req->data.param[1] < 0 || req->data.param[1] > (IEEE80211_TID_SIZE - 2)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s(): Invalid TID value\n", __func__);
        return -EINVAL;
    }
    ad.action = ADDBA_SEND;
    ad.ic = ic;
    ad.aid  = req->data.param[0];
    ad.tid  = req->data.param[1];
    ad.arg1 = req->data.param[2];

    wlan_iterate_station_list(vap, wlan_addba_request_handler, &ad);

    return 0;
}

/**
 * @brief
 *     - Function description:\n
 *     - iwpriv description:\n
 *         - iwpriv cmd: iwpriv athN delba AID AC initiator reason\n
 *           These test commands are used to manually add or delete Block
 *           Acknowledge Aggregation streams.  Note that automatic addba/delba
 *           processing must be turned off prior to using these commands
 *           (see setaddbaoper).  Both commands require the AID (association
 *           ID) and the AC specified.  The Association ID is the value
 *           shown when using the wlanconfig list command.  When adding
 *           an aggregation link with addba, the BufSize parameter must
 *           be set to the maximum number of subframes that will be sent
 *           in an aggregate.  When deleting an aggregation link, the initiator
 *           field indicates whether this link was initiated by the AP
 *           (1) or the remote station (0).  The reason code is an 8-bit
 *           value indicating the reason the link was shut down.  These
 *           commands have no corresponding get commands, nor do they have
 *           default values.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 */
static int
ieee80211dbg_senddelba(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    wlan_dev_t ic = wlan_vap_get_devhandle(vap);
    struct ieee80211_addba_delba_request ad;

    if ((req->data.param[2] != 1) && (req->data.param[2] != 0)) {
        return -EINVAL;
    }

    if (wlan_get_device_param(ic, IEEE80211_DEVICE_ADDBA_MODE) == ADDBA_MODE_AUTO) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s(): ADDBA mode is AUTO\n", __func__);
        return -EINVAL;
    }

    /* Valid TID values are 0 through 15 */
    if (req->data.param[1] < 0 || req->data.param[1] > (IEEE80211_TID_SIZE - 2)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s(): Invalid TID value\n", __func__);
        return -EINVAL;
    }
    ad.action = DELBA_SEND;
    ad.ic = ic;
    ad.aid = req->data.param[0];
    ad.tid  = req->data.param[1];
    ad.arg1 = req->data.param[2];
    ad.arg2 = req->data.param[3];

    wlan_iterate_station_list(vap, wlan_addba_request_handler, &ad);

    return 0;
}

/**
 * @brief
 *     - Function description:\n
 *     - iwpriv description:\n
 *         - iwpriv cmd: getaddbastatus\n
 *           Get for the addba status for aid and tid.
 *             - iwpriv category: 11n A-MPDU, A-MSDU support
 *             - iwpriv arguments:\n
 * aid - the associated id of sta\n
 * tid - tid number between 0-15\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 */
static int
ieee80211dbg_getaddbastatus(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    wlan_dev_t ic = wlan_vap_get_devhandle(vap);
    struct ieee80211_addba_delba_request ad;

    /* Valid TID values are 0 through 15 */
    if (req->data.param[1] < 0 || req->data.param[1] > (IEEE80211_TID_SIZE - 2)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s(): Invalid TID value\n", __func__);
        return -EINVAL;
    }
    memset(&ad, 0, sizeof(ad));

    ad.action = ADDBA_STATUS;
    ad.ic = ic;
    ad.aid = req->data.param[0];
    ad.tid = req->data.param[1];

    wlan_iterate_station_list(vap, wlan_addba_request_handler, &ad);

    req->data.param[0] = ad.status;
    if (ad.status == 0xFFFF) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Addba status IDLE\n");
    }

    return 0;
}

/**
 * @brief
 *     - Function description:\n
 *     - iwpriv description:\n
 *         - iwpriv cmd: iwpriv athN addbaresp AID AC status\n
 *           This command will send an addba response frame on the indicated
 *           association ID (AID) and AC.  The Association ID is the value
 *           shown under the AID column when using the wlanconfig list
 *           command.  The status value is an 8 bit value indicating the
 *           status field of the response.  This is normally used only
 *           during testing of the aggregation interface.  The command
 *           does not have a corresponding get command, nor does it have
 *           a default value.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 */
static int
ieee80211dbg_setaddbaresponse(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    wlan_dev_t ic = wlan_vap_get_devhandle(vap);
    struct ieee80211_addba_delba_request ad;

    if (wlan_get_device_param(ic, IEEE80211_DEVICE_ADDBA_MODE) == ADDBA_MODE_AUTO) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s(): ADDBA mode is AUTO\n", __func__);
        return -EINVAL;
    }

    /* Valid TID values are 0 through 15 */
    if (req->data.param[1] < 0 || req->data.param[1] > (IEEE80211_TID_SIZE - 2)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s(): Invalid TID value\n", __func__);
        return -EINVAL;
    }

    ad.action = ADDBA_RESP;
    ad.ic = ic;
    ad.aid = req->data.param[0];
    ad.tid  = req->data.param[1];
    ad.arg1 = req->data.param[2];

    wlan_iterate_station_list(vap, wlan_addba_request_handler, &ad);
    return 0;
}

/**
 * @brief
 *     - Function description:\n
 *     - iwpriv description:\n
 *         - iwpriv cmd: iwpriv athN addbaresp AID AC
 *           This command is used to configure to send single VHT MPDU AMSDUs
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 */
static int
ieee80211dbg_sendsingleamsdu(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    wlan_dev_t ic = wlan_vap_get_devhandle(vap);
    struct ieee80211_addba_delba_request ad;

    if (wlan_get_device_param(ic, IEEE80211_DEVICE_ADDBA_MODE) == ADDBA_MODE_AUTO) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s(): ADDBA mode is AUTO\n", __func__);
        return -EINVAL;
    }

    /* Valid TID values are 0 through 15 */
    if (req->data.param[1] < 0 || req->data.param[1] > (IEEE80211_TID_SIZE - 2)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s(): Invalid TID value\n", __func__);
        return -EINVAL;
    }

    ad.action = SINGLE_AMSDU;
    ad.ic = ic;
    ad.aid = req->data.param[0];
    ad.tid  = req->data.param[1];

    wlan_iterate_station_list(vap, wlan_addba_request_handler, &ad);
    return 0;
}

#if UMAC_SUPPORT_WNM
static int
ieee80211dbg_sendbstmreq(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    wlan_if_t vap = NETDEV_TO_VAP(dev);
    struct ieee80211_bstm_reqinfo *bstmreq = &req->data.bstmreq;

    return wlan_send_bstmreq(vap, req->dstmac, bstmreq);
}

static int
ieee80211dbg_sendbstmreq_target(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    wlan_if_t vap = NETDEV_TO_VAP(dev);
    struct ieee80211_bstm_reqinfo_target *bstmreq = &req->data.bstmreq_target;

    return wlan_send_bstmreq_target(vap, req->dstmac, bstmreq);
}


#endif

#if UMAC_SUPPORT_ADMCTL
int ieee80211dbg_senddelts(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    wlan_if_t vap = NETDEV_TO_VAP(dev);
    return wlan_admctl_send_delts(vap, req->dstmac, req->data.param[0]);
}

static int
ieee80211dbg_sendaddtsreq(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    wlan_if_t vap = NETDEV_TO_VAP(dev);
    ieee80211_tspec_info *tsinfo =
         (ieee80211_tspec_info *)(&req->data.tsinfo);
    return wlan_send_addts(vap, req->dstmac, tsinfo);
}
#endif

static int
ieee80211_ioctl_getstarssi(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    wlan_send_rssi(vap, req->dstmac);

    return 0;
}

#if ATH_SUPPORT_WIFIPOS
static int
ieee80211_ioctl_initrtt3(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
#if !ATH_SUPPORT_LOWI
    if ((!wifiposenable) || (NULL == vap->iv_wifipos))
    {
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "wifipos not supported\n");
        return 0;
    }
    if(vap->iv_wifipos->xmitrtt3)
        vap->iv_wifipos->xmitrtt3(vap, req->dstmac, req->data.param[0]);
#else
    if(vap->iv_ic->ic_xmitrtt3)
        vap->iv_ic->ic_xmitrtt3(vap, req->dstmac, req->data.param[0]);
#endif
    return 0;

}
#endif

static int
ieee80211acs_ioctl_getchanlist(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);

    ieee80211_user_chanlist_t *list  =(ieee80211_user_chanlist_t *) req->data.param[0];
    list->n_chan = wlan_acs_get_user_chanlist(vap,list->chan);
    return 0;
}


static int
ieee80211acs_ioctl_setchanlist(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);

    ieee80211_user_chanlist_t *list  = (ieee80211_user_chanlist_t *)req->data.param[0];
    wlan_acs_set_user_chanlist(vap,list->chan);
    return 0;
}

static int
ieee80211dbg_ioctl_acs(struct net_device *dev, struct ieee80211req_athdbg *req)
{

    wlan_if_t vap = NETDEV_TO_VAP(dev);

    return wlan_acs_scan_report(vap, (void *)req->data.acs_rep.data_addr);
}
static int
ieee80211dbg_ioctl_acs_block_channel(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    wlan_if_t vap = NETDEV_TO_VAP(dev);
    ieee80211_user_chanlist_t *list  = (ieee80211_user_chanlist_t *)req->data.param[0];
    return wlan_acs_block_channel_list(vap,list->chan,list->n_chan);
}
static int
ieee80211dbg_ioctl_ctrl_table(wlan_if_t vap, struct ieee80211req_athdbg *req)
{
    ieee80211_user_ctrl_tbl_t *ctrl_tbl  = (ieee80211_user_ctrl_tbl_t *)req->data.param[0];
    return wlan_set_ctl_table(vap, ctrl_tbl->ctrl_array, ctrl_tbl->ctrl_len);
}


static int
ieee80211tr69_getpowlimit(struct net_device *dev)
{
	int txpowlimit, value, txpowlimit_value;
	struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
	osif_dev  *osdev = ath_netdev_priv(dev);

	/*
	 * The txpower limit should be set to a high value momentarily only when the VAP is down
	 * if the Vap is up then  return -1
	 */

	if (osdev->is_up) {
		return -1;
	}

	value = (int)TR69MAX_RATE_POWER / 2;

	/* Setting the txpower to a high value momentarily inorder to
	 * read the power limit
	 */

	ieee80211_ucfg_set_txpow(vap, value);

	/*
	 * It takes time for the txpower value to be set and the powerlimit to get updated
	 * So there is a time delay introduced for that
	 */

	msleep (1500);
	txpowlimit = wlan_get_param(vap, IEEE80211_TXPOWER);
	txpowlimit_value = (int) txpowlimit / 2;

	return txpowlimit_value;
}

static void
ieee80211tr69_ioctl_getpowerrange(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    int txpower, i, fixed, retval, min_value, txpowlimit, range_value, txpower_then;
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
	ieee80211req_tr069_t * reqptr = &req->data.tr069_req;
    ieee80211_tr069_txpower_range *powerrange  =(ieee80211_tr069_txpower_range *) reqptr->data_addr;

    /*
     * Getting the present configured txpower value
     */

    retval = ieee80211_ucfg_get_txpow(vap,&txpower, &fixed);
    txpower_then = txpower;

    /*
     * Getting the power limit inorder to calculate the range of supported power values
     */

    txpowlimit = ieee80211tr69_getpowlimit(dev);
	if (txpowlimit == -1) {
		powerrange->value = -1;
		return ;
	}
    range_value = (txpowlimit-TR69MINTXPOWER);
    powerrange->value = range_value;
    min_value = TR69MINTXPOWER;

    /*
     * Converting absolute power values to percentage range
     */

    for(i = 0; i <= range_value; i++) {
	    powerrange->value_array[i] = (int)(((100 * min_value) / txpowlimit) + 1);
	    min_value++;
	    if(powerrange->value_array[i] > 100)
		    powerrange->value_array[i] = 100;

    }

    /*
     *  Setting the txpower back to the previously stored value on the VAP
     */

    ieee80211_ucfg_set_txpow(vap,txpower_then);
    msleep(1500);

    return ;
}

static int
ieee80211tr69_ioctl_settxpower(struct net_device *dev, struct ieee80211req_athdbg *req)
{
	struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
	int value, txpowlimit;
	int *power_value;
	ieee80211req_tr069_t * reqptr = &req->data.tr069_req;

    power_value = reqptr->data_addr;

	/*
	 *  Configure the tx power to a high value momentarily in order to get the txpower limit
	 */

	txpowlimit =  ieee80211tr69_getpowlimit(dev);
	if (txpowlimit == -1) {
		*power_value = -1;
		return 0;
	}

	/*
	 * Using the txpower limit to convert percentage value to absolute value in db
	 */

	value = (int)((req->data.param[0] * txpowlimit) / 100);

	/*
	 * Setting the txpower back to the old configured value
	 */

	ieee80211_ucfg_set_txpow(vap, value);
	msleep(1500);
	return 0;
}

static void
ieee80211tr69_ioctl_gettxpower(struct net_device *dev, struct ieee80211req_athdbg *req)
{
	int txpower, fixed, retval, value, txpowlimit, txpower_then;
	struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
	int *power_value;
	ieee80211req_tr069_t * reqptr = &req->data.tr069_req;

	power_value = reqptr->data_addr;

	/*
	 * Get the present configured txpower value
	 */

	retval = ieee80211_ucfg_get_txpow(vap, &txpower, &fixed);
	txpower_then = txpower;

	/*
	 * Configure the txpower to a high value momentarily in order to get the txpower limit
	 */

	txpowlimit =  ieee80211tr69_getpowlimit(dev);
	if (txpowlimit == -1) {
		*power_value = -1;
		return;
	}

	/*
	 * Converting absolute value to percentage as per TR069 requirement
	 */

	value = (int)(((txpower * 100) / txpowlimit) + 1);
	if (value > 100){
		value = 100;
	}
	*power_value = value;

	/*
	 * Setting the txpower back to the previously configured value on the VAP
	 */

	ieee80211_ucfg_set_txpow(vap, txpower_then);
	msleep(1500);
	return ;
}

static int
ieee80211tr69_ioctl_set_guardintv(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    int value;
    if (req->data.param[0] == 800)
        value = 0;
    else if(req->data.param[0] == 0)
        value = 1;
    else
        return -EINVAL;
    wlan_set_param(vap, IEEE80211_SHORT_GI, value);
    return 0;
}

static void
ieee80211tr69_ioctl_get_guardintv(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    int value;
	ieee80211req_tr069_t * reqptr = &req->data.tr069_req;
  	int *shortgi;

	shortgi = reqptr->data_addr;
    value =  wlan_get_param(vap, IEEE80211_SHORT_GI);
    if(value == 0){
       *shortgi = 800;
   	} else if (value == 1){
      *shortgi = 0;
	}
    return ;
}

static void
ieee80211tr69_ioctl_getassocsta_cnt(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
	ieee80211req_tr069_t * reqptr = &req->data.tr069_req;
	int *sta_count;
	sta_count = reqptr->data_addr;
    if(osifp->os_opmode == IEEE80211_M_STA)
    return ;
    *sta_count = wlan_iterate_station_list(vap, NULL, NULL);
    return;
}

static void
ieee80211tr69_ioctl_acs_scan_timestamp(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    wlan_if_t vap = NETDEV_TO_VAP(dev);
    ieee80211req_tr069_t * reqptr = &req->data.tr069_req;
    struct ieee80211com *ic = vap->iv_ic;
    struct timespec timenow;
    uint32_t jiffies_now = 0 , jiffies_delta = 0, jiffies_then;
    struct timespec *data = reqptr->data_addr;

    jiffies_then = ieee80211_acs_startscantime(ic);
    jiffies_now = OS_GET_TIMESTAMP();
    jiffies_delta = jiffies_now - jiffies_then;
    jiffies_to_timespec(jiffies_delta, &timenow);
    data->tv_sec = timenow.tv_sec;
	data->tv_nsec = timenow.tv_nsec;
	return;
}

static int
ieee80211_ioctl_supported_freq_band(struct net_device *dev,struct ieee80211req_athdbg *req)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    u_int16_t nmodes,support_2g, support_5g, i;
    ieee80211req_tr069_t * reqptr = &req->data.tr069_req;
    enum ieee80211_phymode modes[IEEE80211_MODE_MAX];
    char *value = NULL;
    value = reqptr->data_addr;
    support_2g = support_5g = 0;
    if (wlan_get_supported_phymodes(osifp->os_devhandle,modes,
                &nmodes,IEEE80211_MODE_MAX) != 0 ) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : get_supported_phymodes failed \n", __func__);
        return -EINVAL;
    }
    for (i=0; i < nmodes; i++) {
        if (modes[i] == IEEE80211_MODE_11G)
            support_2g = 1;
        if (modes[i] == IEEE80211_MODE_11A)
            support_5g = 1;
    }
    if ( support_2g == 1 && support_5g == 0 ) {
        strlcpy(value,"2.4GHz",IFNAMSIZ);
    }
    if ( support_2g == 0 && support_5g == 1 ) {
        strlcpy(value,"5GHz",IFNAMSIZ);
    }
    if ( support_2g == 1 && support_5g == 1 ) {
        strlcpy(value,"2.4GHz ,5GHz",IFNAMSIZ);
     }
     return 0;
}
static void
ieee80211tr69_ioctl_getacsscan(struct net_device *dev, struct ieee80211req_athdbg *req)
{
	osif_dev  *osifp = ath_netdev_priv(dev);
	wlan_if_t vap = osifp->os_if;
	ieee80211req_tr069_t * reqptr = &req->data.tr069_req;
	struct ieee80211com *ic = vap->iv_ic;
	char *value = NULL;
	int retv,retv1;
	u_int32_t size = reqptr->data_size;

	value = reqptr->data_addr;

	/*
	 * User has requested for a scan
	 */

	if(req->data.param[3] == 1) {
		retv = wlan_acs_start_scan_report(vap, true, IEEE80211_START_ACS_REPORT, 1);
		if(retv == EOK){
			strlcpy(value, "COMPLETED", size);
		}else if (retv == EINPROGRESS){
			strlcpy(value, "IN PROGRESS", size);
		}else{
			strlcpy(value, "ERROR_INTERNAL", size);
		}

	}

	/*
	 * User has queried for the status of the scan report
	 */

	else if (req->data.param[3] == 0){
		retv1 = ieee80211_acs_state(ic->ic_acs);
		if(retv1 == EOK) {
			strlcpy(value, "COMPLETED", size);
		}else if (retv1 == EINPROGRESS){
			strlcpy(value, "IN PROGRESS", size);
		}else if (retv1 == EINVAL){
			strlcpy(value, "SCAN_NOT_INITIATIED", size);
		}else{
			strlcpy(value, "ERROR_OTHER", size);
		}
	}
	return;
}

static void
ieee80211tr69_ioctl_perstastatscount(struct net_device *dev, struct ieee80211req_athdbg *req)
{
	ieee80211req_tr069_t * reqptr = &req->data.tr069_req;
	int *stats_count;

    stats_count = reqptr->data_addr;

	/*
	 * The number of entries in the statistics table maintainted per STA is 7
	 * The number of entries include RSSI, PacketsTransmitted,
	 * PacketsReceived, PacketsQueued, PacketsDropped,
	 * LastDataDownlinkRate,LastDataUplinkRate
	 */

#define PERSTASTATSCOUNT 7;
	*stats_count = PERSTASTATSCOUNT;
	return;
}

static void
ieee80211tr69_ioctl_get11hsupported(struct net_device *dev, struct ieee80211req_athdbg *req)
{
	osif_dev *osifp = ath_netdev_priv(dev);
	wlan_if_t vap = osifp->os_if;
	u_int16_t nmodes;
	int i;
	int *supported;
	ieee80211req_tr069_t * reqptr = &req->data.tr069_req;
	enum ieee80211_phymode modes[IEEE80211_MODE_MAX];

	supported = reqptr->data_addr;
	if (wlan_get_supported_phymodes(osifp->os_devhandle, modes,
				&nmodes, IEEE80211_MODE_MAX) != 0 ) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : get_supported_phymodes failed \n", __func__);
		return ;
	}

	/* According to tr069 a radio supports 802.11h functionality if
	 * 802.11a or 802.11na or 802.11ac standard is supported
	 */

	for (i = 0; i < nmodes; i++) {
		if ((modes[i] == IEEE80211_MODE_11A) || (modes[i] == IEEE80211_MODE_11NA_HT20) || (modes[i] == IEEE80211_MODE_11NA_HT40PLUS) ||
				(modes[i] == IEEE80211_MODE_11NA_HT40MINUS) || (modes[i] == IEEE80211_MODE_11NA_HT40) || (modes[i] == IEEE80211_MODE_11AC_VHT20)||
				(modes[i] == IEEE80211_MODE_11AC_VHT40PLUS) || (modes[i] == IEEE80211_MODE_11AC_VHT40MINUS) ||
                (modes[i] == IEEE80211_MODE_11AC_VHT40) || (modes[i] == IEEE80211_MODE_11AC_VHT80) ||
                (modes[i] == IEEE80211_MODE_11AC_VHT160 || (modes[i] == IEEE80211_MODE_11AC_VHT80_80) )) {
			*supported = 1;
			return;
		}else
			*supported = 0;
	}
	return;
}

static int
kbps_to_mcs(int rate, int gintval, int *mcs, int htflag)
{

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n kbps_to_mcs is not implemented\n");
#if 0
/*
 * Common folder is coming from qca_main and
 * below function definitions are present
 * only on 10.2 and hence commenting this until
 * CL integration happens
 */
    int i;
    for (i=3; i>0; i--) {
        *mcs = whal_kbps_to_mcs(rate, gintval, htflag, i);
	    if (*mcs != -1)
            return 0;
    }
#endif
    return -1;
}

static int
phymode_to_htflag(enum ieee80211_phymode phymode)
{
    int retv = -1;

    switch (phymode) {
        case IEEE80211_MODE_11A:
        case IEEE80211_MODE_11B:
        case IEEE80211_MODE_11G:
        case IEEE80211_MODE_TURBO_A:
        case IEEE80211_MODE_TURBO_G:
            /*
             *CCK/OFDM rates will be applicable
             */
            retv = 1;
            break;
        case IEEE80211_MODE_11NA_HT20:
        case IEEE80211_MODE_11NG_HT20:
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40:
        case IEEE80211_MODE_11NA_HT40:
            /*
	     *HT rates will be applicable
             */
	    retv = 2;
            break;
        case IEEE80211_MODE_11AC_VHT20:
        case IEEE80211_MODE_11AC_VHT40PLUS:
        case IEEE80211_MODE_11AC_VHT40MINUS:
        case IEEE80211_MODE_11AC_VHT40:
        case IEEE80211_MODE_11AC_VHT80:
        case IEEE80211_MODE_11AC_VHT160:
        case IEEE80211_MODE_11AC_VHT80_80:
            /*
	     *VHT rates will be applicable
             */
	    retv = 3;
            break;
        default:
            break;
    }

    return retv;
}

static int
ieee80211tr69_ioctl_set_oper_rate(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    ieee80211req_tr069_t * reqptr = &req->data.tr069_req;
    char *token = NULL, *strp = NULL;
    int oprate,mcs,htflag,gintval,retv;
    int leg_rtmask, ht_rtmask,vht_rtmask;
    enum ieee80211_phymode phymode;
    oprate = mcs = htflag = leg_rtmask = ht_rtmask = vht_rtmask = 0;
    retv = -EINVAL;

    gintval = wlan_get_param(vap, IEEE80211_SHORT_GI);

    phymode = wlan_get_desired_phymode(vap);
    htflag = phymode_to_htflag(phymode);

    if (htflag < 0 || htflag > 3)
        return retv;

    strp = reqptr->data_addr;
    /*
     * keep a copy for get opration
     */
    strlcpy(vap->iv_oper_rates,strp,sizeof(vap->iv_oper_rates));

    while ((token = strsep(&strp, ",")) != NULL && *token != '\0') {
        sscanf(token,"%d",&oprate);
        if (!kbps_to_mcs(oprate,gintval,&mcs,htflag)) {
            switch (htflag) {
                case 1:
                    leg_rtmask |= (0x1 << mcs);
                    break;
                case 2:
                    ht_rtmask |= (0x1 << mcs);
                    break;
            case 3:
                    /* * b20:b29 for 3x3 */
                    vht_rtmask |= (0x1 << (mcs + 20));
                    break;
                default:
                    break;
            }
        }
    }

    if (!leg_rtmask && (!ht_rtmask) && (!vht_rtmask))
        return retv;
                else
        retv = 0;

    if (leg_rtmask)
        vap->iv_legacy_ratemasklower32 = leg_rtmask;
    if (ht_rtmask)
        vap->iv_ht_ratemasklower32 = ht_rtmask;
    if (vht_rtmask)
        vap->iv_vht_ratemasklower32 = vht_rtmask;

    return retv;
}

static int
ieee80211tr69_ioctl_get_oper_rate(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    ieee80211req_tr069_t * reqptr = &req->data.tr069_req;
    char *ratelist = (char *)reqptr->data_addr;
    u_int32_t size = reqptr->data_size;
    strlcpy(ratelist,vap->iv_oper_rates,size);
    return 0;
}

static int
ieee80211tr69_ioctl_get_posiblrate(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    ieee80211req_tr069_t * reqptr = &req->data.tr069_req;
    char *ratelist = (char *)reqptr->data_addr;
    int gintval,bitmask,htflag,minidx,maxidx;
    enum ieee80211_phymode phymode;

    gintval = wlan_get_param(vap, IEEE80211_SHORT_GI);
    phymode = wlan_get_desired_phymode(vap);
    htflag = phymode_to_htflag(phymode);

    if(htflag < 1 || htflag > 3)
        return -1;

    switch (htflag) {
        case 1:
            bitmask = vap->iv_legacy_ratemasklower32;
            minidx = 0;
            maxidx = 12;
            break;
        case 2:
            bitmask = vap->iv_ht_ratemasklower32;
            minidx = 0;
            maxidx = 24;
            break;
    case 3:
            bitmask = vap->iv_vht_ratemasklower32;
            minidx = 20;
            maxidx = 30;
            break;
    }

    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n whal_mcs_to_kbps is not implemented\n");
#if 0
/*
 * Common folder is coming from qca_main and
 * below function definitions are present
 * only on 10.2 and hence commenting this until
 * CL integration happens
 */
    for (i=minidx; i<maxidx; i++) {
        if ((1<<i & bitmask)) {
            if ( (oprate = whal_mcs_to_kbps(i,htflag,gintval)) ) {
                snprintf(temp,sizeof(temp),"%d,",oprate);
                strncat(ratelist,temp,strlen(temp));
            }
        }
    }
#endif
    ratelist[strlen(ratelist) - 1] = '\0';
    return 0;
}

static int
ieee80211tr69_ioctl_set_bsrate(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    ieee80211req_tr069_t * reqptr = &req->data.tr069_req;
    char *token = NULL, *strp = NULL;
    int retv = -EINVAL;
    unsigned int rate_max = 0, rate = 0;

    strp = reqptr->data_addr;
    strlcpy(vap->iv_basic_rates, strp, sizeof(vap->iv_basic_rates));
    vap->iv_basic_rates[strlen(strp)] = '\0';

    while((token = strsep(&strp, ",")) != NULL && *token != '\0') {
        sscanf(token,"%u",&rate);
        rate_max = (rate > rate_max) ? rate : rate_max;
    }

    if (rate_max < ONEMBPS || rate_max > THREE_HUNDRED_FIFTY_MBPS)
        retv = EINVAL;
    else if((retv = wlan_set_param(vap, IEEE80211_BCAST_RATE, rate_max)) >= 0)
        retv = wlan_set_param(vap, IEEE80211_MCAST_RATE, rate_max);

    return retv;
}

static int
ieee80211tr69_ioctl_get_bsrate(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    ieee80211req_tr069_t * reqptr = &req->data.tr069_req;
    char *ratelist = (char *)reqptr->data_addr;
    u_int32_t size = reqptr->data_size;
    strlcpy(ratelist,vap->iv_basic_rates,size);
    return 0;
}

static int
ieee80211dbg_ioctl_tr069(struct net_device *dev, struct ieee80211req_athdbg *req)
{
	struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
	ieee80211req_tr069_t * reqptr = &req->data.tr069_req;
	struct ieee80211com *ic = vap->iv_ic;
	ieee80211_channelhist_t* chan_data=reqptr->data_addr;
	int retv = 0;
	ieee80211_tr069_cmd cmdid = reqptr->cmdid;
	uint8_t i = 0, idx = 0;
	struct timespec timenow;
	uint32_t jiffies_now = 0 , jiffies_delta = 0;

	switch(cmdid){
		case TR069_CHANHIST:
			idx = ic->ic_chanidx;
			idx ? (chan_data->act_index=(idx-1)) : (chan_data->act_index = (IEEE80211_CHAN_MAXHIST - 1)) ;
			for(; i < IEEE80211_CHAN_MAXHIST; i++){
				jiffies_now = OS_GET_TIMESTAMP();
				jiffies_delta = jiffies_now - ic->ic_chanhist[i].chanjiffies;
				jiffies_to_timespec(jiffies_delta,&timenow);
				chan_data->chanlhist[i].chanid = ic->ic_chanhist[i].chanid;
				chan_data->chanlhist[i].chan_time.tv_sec = timenow.tv_sec;
				chan_data->chanlhist[i].chan_time.tv_nsec = timenow.tv_nsec;
			}
			break;
		case TR069_TXPOWER:
			retv = ieee80211tr69_ioctl_settxpower(dev, req);
			break;
		case TR069_GETTXPOWER:
			ieee80211tr69_ioctl_gettxpower(dev, req);
			break;
		case TR069_GUARDINTV:
			retv = ieee80211tr69_ioctl_set_guardintv(dev, req);
			break;
		case TR069_GET_GUARDINTV:
			ieee80211tr69_ioctl_get_guardintv(dev, req);
			break;
		case TR069_GETASSOCSTA_CNT:
			ieee80211tr69_ioctl_getassocsta_cnt(dev,req);
			break;
		case TR069_GETTIMESTAMP:
			ieee80211tr69_ioctl_acs_scan_timestamp(dev, req);
			break;
		case TR069_GETDIAGNOSTICSTATE:
			ieee80211tr69_ioctl_getacsscan(dev, req);
			break;
		case TR069_GETNUMBEROFENTRIES:
			ieee80211tr69_ioctl_perstastatscount(dev, req);
			break;
		case TR069_GET11HSUPPORTED:
			ieee80211tr69_ioctl_get11hsupported(dev, req);
			break;
		case TR069_GETPOWERRANGE:
			ieee80211tr69_ioctl_getpowerrange(dev, req);
			break;
		case TR069_SET_OPER_RATE:
			ieee80211tr69_ioctl_set_oper_rate(dev, req);
			break;
		case TR069_GET_OPER_RATE:
			ieee80211tr69_ioctl_get_oper_rate(dev, req);
			break;
		case TR069_GET_POSIBLRATE:
			ieee80211tr69_ioctl_get_posiblrate(dev, req);
			break;
		case TR069_SET_BSRATE:
			ieee80211tr69_ioctl_set_bsrate(dev, req);
			break;
		case TR069_GET_BSRATE:
			ieee80211tr69_ioctl_get_bsrate(dev, req);
			break;
        case TR069_GETSUPPORTEDFREQUENCY:
            ieee80211_ioctl_supported_freq_band(dev,req);
            break;
        case TR069_GET_PLCP_ERR_CNT: /* notice fall through */
        case TR069_GET_FCS_ERR_CNT:
        case TR069_GET_PKTS_OTHER_RCVD:
        case TR069_GET_FAIL_RETRANS_CNT:
        case TR069_GET_RETRY_CNT:
        case TR069_GET_MUL_RETRY_CNT:
        case TR069_GET_ACK_FAIL_CNT:
        case TR069_GET_AGGR_PKT_CNT:
        case TR069_GET_STA_BYTES_SENT:
        case TR069_GET_STA_BYTES_RCVD:
        case TR069_GET_DATA_SENT_ACK:
        case TR069_GET_DATA_SENT_NOACK:
        case TR069_GET_CHAN_UTIL:
        case TR069_GET_RETRANS_CNT:
            if (ic->ic_tr69_request_process) {
              ic->ic_tr69_request_process(vap, (int) cmdid, (void *)reqptr->data_addr, (void *)req->dstmac);
            }
            break;
        default:
			break;
	}

    return retv;
}
static int
ieee80211dbg_bsteering_set_params(struct net_device *dev,
                                  struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    return wlan_bsteering_set_params(vap, req);
}

static int
ieee80211dbg_bsteering_get_params(const struct net_device *dev,
                                  struct ieee80211req_athdbg *req)
{
    const struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    return wlan_bsteering_get_params(vap, req);
}

static int
ieee80211dbg_bsteering_set_dbg_params(struct net_device *dev,
                                      const struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    return wlan_bsteering_set_dbg_params(vap, req);
}

static int
ieee80211dbg_bsteering_get_dbg_params(const struct net_device *dev,
                                      struct ieee80211req_athdbg *req)
{
    const struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    return wlan_bsteering_get_dbg_params(vap, req);
}

static int
ieee80211dbg_bsteering_enable(struct net_device *dev,
                              struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    return wlan_bsteering_enable(vap, req);
}

static int
ieee80211dbg_bsteering_enable_events(struct net_device *dev,
                                     struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    return wlan_bsteering_enable_events(vap, req);
}

static int
ieee80211dbg_bsteering_set_overload(struct net_device *dev,
                                    struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    return wlan_bsteering_set_overload(vap, req);
}

static int
ieee80211dbg_bsteering_get_overload(const struct net_device *dev,
                                    struct ieee80211req_athdbg *req)
{
    const struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    return wlan_bsteering_get_overload(vap, req);
}
static int
ieee80211dbg_bsteering_get_rssi(struct net_device *dev,
                                const struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    return wlan_bsteering_trigger_rssi_measurement(vap, req);
}
static int
ieee80211dbg_bsteering_set_probe_resp_wh(const struct net_device *dev,
                                         struct ieee80211req_athdbg *req)
{
    const struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    return wlan_bsteering_set_probe_resp_wh((struct ieee80211vap *)vap, req);
}
static int
ieee80211dbg_bsteering_get_probe_resp_wh(const struct net_device *dev,
                                         struct ieee80211req_athdbg *req)
{
    const struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    return wlan_bsteering_get_probe_resp_wh((struct ieee80211vap *)vap, req);
}

static int
ieee80211dbg_bsteering_set_auth_allow(const struct net_device *dev,
        struct ieee80211req_athdbg *req)
{
    const struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    return wlan_bsteering_set_auth_allow((struct ieee80211vap *)vap, req);
}

static int
ieee80211dbg_bsteering_set_probe_resp_allow_24g(const struct net_device *dev,
                                         struct ieee80211req_athdbg *req)
{
    const struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    return wlan_bsteering_set_probe_resp_allow_24g((struct ieee80211vap *)vap, req);
}

static int
ieee80211dbg_bsteering_get_datarate_info(const struct net_device *dev,
                                         struct ieee80211req_athdbg *req)
{
    const struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    return wlan_bsteering_get_datarate_info((struct ieee80211vap *)vap, req);
}

static int
ieee80211dbg_bsteering_local_disassoc(const struct net_device *dev,
                                      struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);

    struct ieee80211_node *ni = ieee80211_vap_find_node(vap, req->dstmac);
    if (!ni) {
        /* Couldn't find node to remove */
        return -1;
    }

    IEEE80211_NODE_LEAVE(ni);
    IEEE80211_DELIVER_EVENT_MLME_DISASSOC_COMPLETE(vap, req->dstmac,
                                                   IEEE80211_REASON_LOCAL,
                                                   IEEE80211_STATUS_SUCCESS);
    ieee80211_free_node(ni);
    return 0;
}

static int
ieee80211dbg_bsteering_set_steering(struct net_device *dev,
                                    struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    return wlan_bsteering_set_steering(vap, req);
}

static int
ieee80211dbg_bsteering_set_sta_stats_interval_da(struct net_device *dev,
                                                 struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    return wlan_bsteering_set_sta_stats_interval_da(vap, req);
}

static int
ieee80211dbg_acs_set_innetwork_2g(const struct net_device *dev, struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    return wlan_acs_set_innetwork_2g(vap->iv_ic, req->dstmac, req->data.param[0]);
}
static int
ieee80211dbg_acs_get_innetwork_2g(const struct net_device *dev, struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    return wlan_acs_get_innetwork_2g(vap->iv_ic, (void *)req->data.acs_rep.data_addr, req->data.acs_rep.index);
}


/*
 * brief description
 * Function to get the time when the max number of devices has been associated
 *
 */
static void
ieee80211dbg_get_assoc_watermark_time(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    wlan_if_t vap = NETDEV_TO_VAP(dev);
    struct timespec timenow;
    uint32_t jiffies_now = 0 , jiffies_delta = 0, jiffies_then;
    struct timespec *data =(struct timespec *)req->data.param[0];

    jiffies_then = vap->assoc_high_watermark_time;
    jiffies_now = OS_GET_TIMESTAMP();
    jiffies_delta = jiffies_now - jiffies_then;
    jiffies_to_timespec(jiffies_delta, &timenow);
    data->tv_sec = timenow.tv_sec;
    data->tv_nsec = timenow.tv_nsec;
    return;
}

#if UMAC_SUPPORT_VI_DBG
static int
ieee80211dbg_vow_debug_param_perstream(struct net_device *dev,
		struct ieee80211req_athdbg *req)
{
	struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
	return ieee80211_vi_dbg_set_marker(vap, req);
}


static int
ieee80211dbg_vow_debug_param(struct net_device *dev,
		struct ieee80211req_athdbg *req)
{
	struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
	return ieee80211_vi_dbg_param(vap, req);
}
#endif
#if ATH_SUPPORT_HS20
static int ieee80211dbg_setqosmapconf(struct net_device *dev,
                                      struct ieee80211req_athdbg *req)
{
    wlan_if_t vap = NETDEV_TO_VAP(dev);
    osif_dev *osifp = ath_netdev_priv(dev);

    OS_MEMCPY(&vap->iv_qos_map, &req->data.qos_map, sizeof(struct ieee80211_qos_map));

#ifdef ATH_SUPPORT_DSCP_OVERRIDE
    if(osifp->osif_is_mode_offload) {
#define WMI_DSCP_MAP_MAX    (64)
	    struct ieee80211com *ic = vap->iv_ic;
	    A_UINT32 dscp, i;
	    struct ieee80211_qos_map *qos_map = &vap->iv_qos_map;

        for (dscp = 0 ; dscp < WMI_DSCP_MAP_MAX; dscp++) {
		    for (i = 0; i < IEEE80211_MAX_QOS_UP_RANGE; i++)
			    if (qos_map->up[i].low <= dscp &&
					    qos_map->up[i].high >= dscp) {
				    ic->ic_dscp_tid_map[dscp] = i;
				    break;
			    }

		    for (i = 0; i < qos_map->num_dscp_except; i++) {
			    if (qos_map->dscp_exception[i].dscp == dscp) {
				    ic->ic_dscp_tid_map[dscp] = qos_map->dscp_exception[i].up;
				    break;
			    }
		    }
	    }
	    ic->ic_override_dscp = 1;
            if(ic->ic_vap_set_param)
                ic->ic_vap_set_param(vap, IEEE80211_DSCP_OVERRIDE, 0);
 }
#endif
 return 0;
}
#endif

int ieee80211_custom_chan_list(struct ieee80211com *ic,
        struct ieee80211vap *vap, ieee80211req_custom_chan_t *reqptr)
{
    int i;
    struct ieee80211_node   *ni = NULL;
    struct ieee80211_channel *channel;

    if(vap->iv_opmode != IEEE80211_M_STA)
    {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "valid only in STA mode\n");
        return -EINVAL;
    }
    if(vap->iv_bss)
    {
        ni = vap->iv_bss;
    }
    if((reqptr->scan_numchan_nonassociated > IEEE80211_CUSTOM_SCAN_ORDER_MAXSIZE) || (reqptr->scan_numchan_associated > IEEE80211_CUSTOM_SCAN_ORDER_MAXSIZE))
    {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "List is bigger than supported %d",MAX_SCAN_CHANS);
        return -EINVAL;
    }
    if (reqptr->scan_numchan_nonassociated) {
        for (i = 0; i < reqptr->scan_numchan_nonassociated; i++)
        {
            channel = ieee80211_find_dot11_channel(ic, reqptr->scan_channel_list_nonassociated[i], 0, vap->iv_des_mode | ic->ic_chanbwflag);
            if(channel==NULL)
            {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " invalid  Channel list channel %d not valid\n",reqptr->scan_channel_list_nonassociated[i]);
                return -EINVAL;
            }
        }

        for (i = 0; i < reqptr->scan_numchan_nonassociated; i++)
        {
            ic->ic_custom_chan_list_nonassociated[i] = reqptr->scan_channel_list_nonassociated[i];
        }

        ic->ic_custom_chanlist_nonassoc_size = reqptr->scan_numchan_nonassociated;
        ic->ic_use_custom_chan_list=1;
    }

    if (reqptr->scan_numchan_associated) {
        for (i = 0; i < reqptr->scan_numchan_associated; i++)
        {
            channel = ieee80211_find_dot11_channel(ic, reqptr->scan_channel_list_associated[i], 0, vap->iv_des_mode | ic->ic_chanbwflag);
            if(channel==NULL)
            {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " invalid  Channel list channel %d not valid\n",reqptr->scan_channel_list_associated[i]);
                return -EINVAL;
            }
        }

        for (i = 0; i < reqptr->scan_numchan_associated; i++)
        {
            ic->ic_custom_chan_list_associated[i] = reqptr->scan_channel_list_associated[i];
        }

        ic->ic_custom_chanlist_assoc_size = reqptr->scan_numchan_associated;
        ic->ic_use_custom_chan_list=1;
    }

    return 0;
}
static int
ieee80211dbg_ioctl_custom_chan_list(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    ieee80211req_custom_chan_t *reqptr = &req->data.custom_chan_req;
    struct ieee80211com *ic = vap->iv_ic;

    if (!(dev->flags & IFF_UP))
        return -EINVAL;

    return ieee80211_custom_chan_list(ic, vap, reqptr);
}
static int
ieee80211dbg_offchan_tx_test(const struct net_device *dev,
                                struct ieee80211req_athdbg *req)
{
    wlan_if_t vap = NETDEV_TO_VAP(dev);
    osif_dev *osifp = (osif_dev *)vap->iv_ifp;
    ieee80211_offchan_tx_test_t *offchan_test = (ieee80211_offchan_tx_test_t *)&req->data.offchan_req;

#if ATH_DEBUG
    if (vap->iv_special_vap_mode || (vap->iv_opmode == IEEE80211_M_MONITOR)) {
        /*
         * special_vap_mode is simlar to monitor mode
         * which doesnt need to support the offchan scan
         */
        return -EINVAL;
    }
    if (!ieee80211_is_vap_state_running(vap)) {
        return -EINVAL;
    }
    /* for offchan TX testing */
    return wlan_offchan_tx_test(vap, osifp->netdev, offchan_test->ieee_chan,
		    offchan_test->dwell_time, osifp->offchan_scan_requestor,
		    &(osifp->offchan_scan_id));
#else
    return -EINVAL;
#endif

}

#if QCA_LTEU_SUPPORT

static int
ieee80211dbg_ioctl_ap_scan(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    ieee80211req_ap_scan_t *reqptr = &req->data.ap_scan_req;
    struct ieee80211com *ic = vap->iv_ic;

    if (!(dev->flags & IFF_UP))
        return -EINVAL;

    return ieee80211_ap_scan(ic, vap, reqptr);
}

static int
ieee80211dbg_ioctl_mu_scan(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    ieee80211req_mu_scan_t *reqptr = &req->data.mu_scan_req;
    struct ieee80211com *ic = vap->iv_ic;
    int retv = 0, waitcnt;
    struct ieee80211_channel *channel;
    struct ieee80211vap *tmpvap = NULL;
    osif_dev *tmp_osnetdev = NULL;
    struct net_device *tmpdev = NULL;
    int i;
    enum ieee80211_phymode old_mode, modes[] = { IEEE80211_MODE_11AC_VHT80,
                                       IEEE80211_MODE_11AC_VHT40PLUS,
                                       IEEE80211_MODE_11AC_VHT40MINUS,
                                       IEEE80211_MODE_11AC_VHT20 };

    if (!(dev->flags & IFF_UP))
        return -EINVAL;

    retv = ieee80211_init_mu_scan(ic, reqptr);
    if (retv)
        goto out;

    if (reqptr->mu_channel == 0 || reqptr->mu_channel == IEEE80211_CHAN_ANY) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Invalid channel specified "
               "for MU id=%d\n", __func__, reqptr->mu_req_id);
        retv = -EINVAL;
        goto out_fail;
    }

    old_mode = wlan_get_desired_phymode(vap);

    for (i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_NL, "%s: Changing phymode from %d to "
                 "%d for MU\n", __func__, wlan_get_desired_phymode(vap), modes[i]);
        retv = wlan_set_desired_phymode(vap, modes[i]);
        if (retv) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_NL, "%s: Can't set phymode "
                   "for MU id=%d\n", __func__, reqptr->mu_req_id);
            continue;
        }

        IEEE80211_DPRINTF(vap, IEEE80211_MSG_NL, "%s: Changing channel "
                 "from %d to %d for MU\n", __func__, ic->ic_curchan ?
                 ic->ic_curchan->ic_ieee : 0, reqptr->mu_channel);
        channel = ieee80211_find_dot11_channel(ic, reqptr->mu_channel, 0,
                                               vap->iv_des_mode | ic->ic_chanbwflag);
        if (channel == NULL) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_NL, "%s: Can't set channel "
                   "for MU id=%d\n", __func__, reqptr->mu_req_id);
            retv = -EINVAL;
            continue;
        }

        if (ieee80211_check_chan_mode_consistency(ic, vap->iv_des_mode, channel)) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_NL, "%s: Channel mode consistency "
                   "failed for MU id=%d, mode %d channel %d\n", __func__,
                   reqptr->mu_req_id, vap->iv_des_mode, reqptr->mu_channel);
            retv = -EINVAL;
            continue;
        }

        if (!ic->ic_nl_handle->force_vdev_restart && ic->ic_curchan) {
            if (old_mode == vap->iv_des_mode &&
                channel->ic_ieee == ic->ic_curchan->ic_ieee) {
                break;
            }
        } else if (ic->ic_nl_handle->force_vdev_restart) {
            ic->ic_nl_handle->force_vdev_restart = 0;
        }

        TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
            tmp_osnetdev = (osif_dev *)tmpvap->iv_ifp;

            waitcnt = 0;
            while ((qdf_atomic_read(&(tmpvap->init_in_progress)) &&
                   tmpvap->iv_state_info.iv_state != IEEE80211_S_DFS_WAIT) &&
                   waitcnt < OSIF_MAX_STOP_VAP_TIMEOUT_CNT) {
                schedule_timeout_interruptible(OSIF_STOP_VAP_TIMEOUT);
                waitcnt++;
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                                  "%s: WAITING FOR VAP INIT COMPLETE\n", __func__);
            }

            tmp_osnetdev->is_stop_event_pending = 1;
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_NL, "Set freq vap stop send + %p\n", tmpvap);
            wlan_mlme_stop_bss(tmpvap, 0);
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_NL, "Set freq vap stop send - %p\n", tmpvap);

            waitcnt = 0;
            while (tmp_osnetdev->is_stop_event_pending &&
                   waitcnt < OSIF_MAX_STOP_VAP_TIMEOUT_CNT) {
                schedule_timeout_interruptible((CONVERT_SEC_TO_SYSTEM_TIME(1)/200) + 1);
                waitcnt++;
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                                  "%s: WAITING FOR STOP EVENT\n", __func__);
            }

            if (tmp_osnetdev->is_stop_event_pending) {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Timeout waiting for %s vap %d to stop...returning\n", __func__,
                        tmp_osnetdev->osif_is_mode_offload ? "OL" : "DA",
                        tmpvap->iv_unit);
#if IEEE80211_DEBUG_NODELEAK
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n%s: ############ INVOKING NODELEAK DEBUG DUMP ############\n", __func__);
                wlan_debug_dump_nodes_tgt();
#endif
                wlan_set_desired_phymode(vap, old_mode);
                retv = -EINVAL;
                goto out_fail;
            }

            IEEE80211_DPRINTF(vap, IEEE80211_MSG_NL, "Set wait done -- %p\n", tmpvap);
            tmp_osnetdev->is_stop_event_pending = 0;
        }

        retv = wlan_set_channel(vap, reqptr->mu_channel, 0);
        if (!retv) {
            TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
                tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
                retv = IS_UP(tmpdev) ? -osif_vap_init(tmpdev, RESCAN) : 0;
            }
        } else {
            wlan_set_desired_phymode(vap, old_mode);
        }

        break;
    }

    if (i == sizeof(modes) / sizeof(modes[0]))
        wlan_set_desired_phymode(vap, old_mode);

    if (!retv) {
        if (vap->mu_start_delay && !ic->ic_nl_handle->use_gpio_start) {
            OS_DELAY(vap->mu_start_delay);
        }
        retv = ieee80211_mu_scan(ic, reqptr);
    }

    if (retv) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Unable to start MU id=%d on channel %d\n",
               __func__, reqptr->mu_req_id, reqptr->mu_channel);
    } else {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: MU started id %d, channel %d, phymode %d, duration %d, "
               "type %#x, lteu txpower %d, alpha %d, thresholds (bssid/sta/sc) %d/%d/%d\n",
               __func__, ic->ic_nl_handle->mu_id, ic->ic_curchan->ic_ieee,
               vap->iv_des_mode, reqptr->mu_duration, reqptr->mu_type, reqptr->lteu_tx_power,
               reqptr->alpha_num_bssid, reqptr->mu_rssi_thr_bssid, reqptr->mu_rssi_thr_sta, reqptr->mu_rssi_thr_sc);
        goto out;
    }

out_fail:
    ieee80211_mu_scan_fail(ic);

out:
    return retv;
}

static int
ieee80211dbg_ioctl_lteu_config(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    ieee80211req_lteu_cfg_t *reqptr = &req->data.lteu_cfg;
    struct ieee80211com *ic = vap->iv_ic;
    int i;

    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: LTEu config, wifi txpower %d, num bins %d, GPIO start %d, actual NF %d, "
           "timeout %d, weights -", __func__, vap->wifi_tx_power, reqptr->lteu_num_bins,
           reqptr->lteu_gpio_start, reqptr->use_actual_nf, reqptr->lteu_scan_timeout);
    for (i = 0; i < LTEU_MAX_BINS; i++)
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %d", reqptr->lteu_weight[i]);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ", thresholds -");
    for (i = 0; i < LTEU_MAX_BINS; i++)
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %d", reqptr->lteu_thresh[i]);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ", gammas -");
    for (i = 0; i < LTEU_MAX_BINS; i++)
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %d", reqptr->lteu_gamma[i]);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n");

    return ieee80211_lteu_config(ic, reqptr, vap->wifi_tx_power);
}

#endif /* QCA_LTEU_SUPPORT */

static int
ieee80211dbg_ioctl_atf_debug_size(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    int ret = -EINVAL;
#if QCA_AIRTIME_FAIRNESS
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_node *ni = NULL;

    ni = ieee80211_find_node(&ic->ic_sta, req->dstmac);
    if (ni) {
        ret = ieee80211_atf_set_debug_size(ni, req->data.param[0]);
        ieee80211_free_node(ni);
    } else {
        ret = -ENOENT;
    }
#endif
    return ret;
}

static int
ieee80211dbg_ioctl_atf_dump_nodestate(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    int ret = -EINVAL;
#if QCA_AIRTIME_FAIRNESS
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_node *ni = NULL;
    u_int32_t nodestate = 0;

    ni = ieee80211_find_node(&ic->ic_sta, req->dstmac);
    if (ni) {
        ret = ieee80211_atf_get_debug_nodestate(ic, ni, &nodestate);
        if (copy_to_user(req->data.atf_dbg_req.ptr, &nodestate, sizeof(nodestate))) {
                ret = -EFAULT;
        }
        ieee80211_free_node(ni);
    } else {
        ret = -ENOENT;
    }
#endif
    return ret;
}

static int
ieee80211dbg_ioctl_atf_dump_debug(struct net_device *dev, struct ieee80211req_athdbg *req)
{
    int ret = -EINVAL;

#if QCA_AIRTIME_FAIRNESS
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_node *ni = NULL;
    void *ptr = NULL;
    u_int32_t size = 0, id = 0;
    u_int32_t buf[2];

    ni = ieee80211_find_node(&ic->ic_sta, req->dstmac);
    if (ni) {
        ret = ieee80211_atf_get_debug_dump(ni, &ptr, &size, &id);
        if (ptr && req->data.atf_dbg_req.ptr &&
            (size + (2 * sizeof(u_int32_t))) <= req->data.atf_dbg_req.size) {
            buf[0] = size;
            buf[1] = id;
            if (copy_to_user(req->data.atf_dbg_req.ptr, buf, sizeof(buf))) {
                ret = -EFAULT;
            } else if (copy_to_user((u_int8_t *)(req->data.atf_dbg_req.ptr) + sizeof(buf), ptr, size)) {
                ret = -EFAULT;
            }
        } else {
            ret = -EINVAL;
        }
        ieee80211_free_node(ni);
    } else {
        ret = -ENOENT;
    }

    if (ptr)
        OS_FREE(ptr);
#endif

    return ret;
}

static int
ieee80211_ioctl_dbgreq(struct net_device *dev, struct iw_request_info *info,
    void *w, char *extra)
{
    int retv = 0;
    struct ieee80211req_athdbg *req = (struct ieee80211req_athdbg *) extra;
#if ATH_SUPPORT_FIPS
	osif_dev *osifp = ath_netdev_priv(dev);
#endif
#if defined QCA_NSS_WIFI_OFFLOAD_SUPPORT || UMAC_SUPPORT_RRM || QCA_LTEU_SUPPORT
    wlan_if_t vap = NETDEV_TO_VAP(dev);
#endif
#if defined QCA_NSS_WIFI_OFFLOAD_SUPPORT && ATH_BAND_STEERING
    struct ieee80211com *ic = vap->iv_ic;
#endif
    struct iw_point *wri = (struct iw_point *)w;
    debug_print_ioctl(dev->name, IEEE80211_IOCTL_DBGREQ, "dbgreq");

    switch (req->cmd) {
        case IEEE80211_DBGREQ_SENDADDBA:
            retv = ieee80211dbg_sendaddba(dev, req);
            break;
        case IEEE80211_DBGREQ_SENDDELBA:
            retv = ieee80211dbg_senddelba(dev, req);
            break;
        case IEEE80211_DBGREQ_GETADDBASTATS:
            retv = ieee80211dbg_getaddbastatus(dev, req);
            break;
        case IEEE80211_DBGREQ_SETADDBARESP:
            retv = ieee80211dbg_setaddbaresponse(dev, req);
            break;
        case IEEE80211_DBGREQ_SENDSINGLEAMSDU:
            retv = ieee80211dbg_sendsingleamsdu(dev, req);
            break;

#if UMAC_SUPPORT_RRM
        case IEEE80211_DBGREQ_FW_TEST:
            retv = wlan_ar900b_fw_test(vap, req->data.param[0], req->data.param[1]);
            break;
        case IEEE80211_DBGREQ_SET_ANTENNA_SWITCH:
            retv = wlan_set_antenna_switch(vap, req->data.param[0], req->data.param[1]);
            break;
        case IEEE80211_DBGREQ_SETSUSERCTRLTBL:
            retv = ieee80211dbg_ioctl_ctrl_table(vap, req);
            break;
        case IEEE80211_DBGREQ_CHMASKPERSTA:
            retv = wlan_set_chainmask_per_sta(vap, req->dstmac, req->data.param[0]);
            break;
        case IEEE80211_DBGREQ_SENDBCNRPT:
            retv =  wlan_send_beacon_measreq(vap, req->dstmac, &req->data.bcnrpt);
            break;
        case IEEE80211_DBGREQ_SENDTSMRPT:
            retv = wlan_send_tsm_measreq(vap, req->dstmac, &req->data.tsmrpt);
            break;
        case IEEE80211_DBGREQ_SENDNEIGRPT:
            retv = wlan_send_neig_report(vap, req->dstmac, &req->data.neigrpt);
            break;
        case IEEE80211_DBGREQ_SENDLMREQ:
            retv = wlan_send_link_measreq(vap, req->dstmac);
            break;
        case IEEE80211_DBGREQ_SENDCHLOADREQ:
            retv = wlan_send_chload_req(vap, req->dstmac, &req->data.chloadrpt);
            break;
        case IEEE80211_DBGREQ_SENDSTASTATSREQ:
            retv = wlan_send_stastats_req(vap, req->dstmac, &req->data.stastats);
            break;
        case IEEE80211_DBGREQ_SENDNHIST:
            retv = wlan_send_nhist_req(vap, req->dstmac, &req->data.nhist);
            break;
        case IEEE80211_DBGREQ_SENDLCIREQ:
            retv = wlan_send_lci_req(vap, req->dstmac, &req->data.lci_req);
            break;
        case IEEE80211_DBGREQ_GETRRMSTATS:
            {
                ieee80211req_rrmstats_t *req_stats = (ieee80211req_rrmstats_t *)&req->data.rrmstats_req;
                retv = wlan_get_rrmstats(vap, req->dstmac, (ieee80211_rrmstats_t *)req_stats->data_addr);
            }
            break;
        case IEEE80211_DBGREQ_SENDFRMREQ:
            retv = wlan_send_frame_request(vap, req->dstmac, &req->data.frm_req);
            break;
        case IEEE80211_DBGREQ_GETBCNRPT:
            {
                ieee80211req_rrmstats_t *req_stats = (ieee80211req_rrmstats_t *)&req->data.rrmstats_req;
                retv = wlan_get_bcnrpt(vap, req->dstmac, req_stats->index, (ieee80211_bcnrpt_t *)req_stats->data_addr);
            }
            break;
        case IEEE80211_DBGREQ_GET_RRM_STA_LIST:
            {
                ieee80211_rrm_sta_info_t *rrm_info  = (ieee80211_rrm_sta_info_t *) req->data.param[0];
                unsigned char *addr_list = (unsigned char *)req->data.param[1];
                retv = wlan_get_rrm_sta_list(vap, req->dstmac, req->data.param);
                rrm_info->count = req->data.param[0];
                addr_list = (unsigned char *)req->data.param[1];
            }
            break;
#endif
      case IEEE80211_DBGREQ_DISPLAY_TRAFFIC_STATISTICS:
            {
                ieee80211_node_info_t *node_info = (ieee80211_node_info_t *)req->data.param[0];
                unsigned char *addr_list = (unsigned char *)req->data.param[1];
                ieee80211_noise_stats_t *noise_info = (ieee80211_noise_stats_t *)req->data.param[3];

                retv = wlan_get_traffic_stats(vap, req->dstmac, req->data.param);
                node_info->count = req->data.param[0];
                node_info->bin_number = req->data.param[2];
                node_info->traf_rate = req->data.param[1];
                addr_list = (unsigned char *)req->data.param[1];
                noise_info = (ieee80211_noise_stats_t *)req->data.param[3];
            }
            break;
#if UMAC_SUPPORT_WNM
        case IEEE80211_DBGREQ_SENDBSTMREQ:
            retv = ieee80211dbg_sendbstmreq(dev, req);
            break;
        case IEEE80211_DBGREQ_SENDBSTMREQ_TARGET:
            retv = ieee80211dbg_sendbstmreq_target(dev, req);
            break;
#endif
        case IEEE80211_DBGREQ_MBO_BSSIDPREF:
            retv = wlan_set_bssidpref(vap,&req->data.bssidpref);
        break;
#if UMAC_SUPPORT_ADMCTL
        case IEEE80211_DBGREQ_SENDDELTS:
            retv = ieee80211dbg_senddelts(dev, req);
            break;
        case IEEE80211_DBGREQ_SENDADDTSREQ:
            retv = ieee80211dbg_sendaddtsreq(dev, req);
            break;
#endif
#if ATH_SUPPORT_HS20
        case IEEE80211_DBGREQ_SETQOSMAPCONF:
            retv = ieee80211dbg_setqosmapconf(dev, req);
            break;
#endif
        case IEEE80211_DBGREQ_GETRRSSI:
            ieee80211_ioctl_getstarssi(dev, req);
            return 0;
            break;
#if ATH_SUPPORT_WIFIPOS
        case IEEE80211_DBGREQ_INITRTT3:
            retv = ieee80211_ioctl_initrtt3(dev,req);
            break;
#endif
        case IEEE80211_DBGREQ_GETACSREPORT:
            retv = ieee80211dbg_ioctl_acs(dev, req);
            break;
        case IEEE80211_DBGREQ_BLOCK_ACS_CHANNEL:
            retv = ieee80211dbg_ioctl_acs_block_channel(dev, req);
            break;
        case IEEE80211_DBGREQ_SETACSUSERCHANLIST:
            retv = ieee80211acs_ioctl_setchanlist(dev, req);
            break;
        case IEEE80211_DBGREQ_GETACSUSERCHANLIST:
            retv = ieee80211acs_ioctl_getchanlist(dev, req);
            break;
        case IEEE80211_DBGREQ_TR069:
            retv = ieee80211dbg_ioctl_tr069(dev, req);
            break;

#if ATH_SUPPORT_FIPS
        case IEEE80211_DBGREQ_FIPS:
	    {
			wlan_if_t vap = osifp->os_if;
			struct ieee80211com *ic = vap->iv_ic;
		    int length;
            retv = 0;
	        if (ic == NULL) {
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n %s:%d ieee80211com pointer is NULL \n",
                            __func__, __LINE__);
	            return -EINVAL;
	        }
            /* Check for already ongoing FIPS test*/
            if (qdf_atomic_read(&(ic->ic_fips_event)) != 1 &&
                    (qdf_atomic_read(&(ic->ic_fips_event)) != 2)) {
                /* Incrementing to one to denote an ongoing event */
                qdf_atomic_init(&(ic->ic_fips_event));
                qdf_atomic_inc(&(ic->ic_fips_event));

                vap->iv_stopping(vap);

                retv = ieee80211_ioctl_fips(dev,
                            (void *)req->data.fips_req.data_addr,
                            req->data.fips_req.data_size);
#define ATH_FIPS_TIMEOUT ((CONVERT_SEC_TO_SYSTEM_TIME(1)/10) + 1) /* 100 ms*/
                /* give enough delay to get the result */
                schedule_timeout_interruptible(ATH_FIPS_TIMEOUT);

                /*ic->fips_event would be set to 2 when wmi event is completed*/
                if(ic->ic_output_fips) {
                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s received fips event %d %p length %d\n", __func__,
                       qdf_atomic_read(&(ic->ic_fips_event)), ic->ic_output_fips,
                        ic->ic_output_fips->data_len);
                } else {
                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n %s:%d WMI FIPS Event not completed \n",
                            __func__, __LINE__);
                    /* probably this event failed, log this, and set to execute
                     * next event
                     */
                    qdf_atomic_init(&(ic->ic_fips_event));
                    return -EFAULT;
                }

                if (ic && (qdf_atomic_read(&(ic->ic_fips_event)) == 2)) {
                    length = sizeof(struct ath_fips_output) +
                                    (ic->ic_output_fips->data_len);
		    if (copy_to_user(req->data.fips_req.data_addr,ic->ic_output_fips, length)) {
			QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: copy_to_user error\n", __func__);
			retv = -EFAULT;
		    }
                    OS_FREE(ic->ic_output_fips);
                    ic->ic_output_fips = NULL;
                    qdf_atomic_dec(&(ic->ic_fips_event));
                } else {
                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n %s:%d WMI FIPS Event not completed \n",
                            __func__, __LINE__);
                    /* probably this event failed, log this, and set to execute
                     * next event
                     */
                    qdf_atomic_init(&(ic->ic_fips_event));
                    retv = -EFAULT;
                }
                /* Decrementing back to zero */
                qdf_atomic_dec(&(ic->ic_fips_event));
                vap->iv_up(vap);
            }
            else {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n FIPS test is on progress");
                retv = -EFAULT;
            }
	    }
            break;
#endif
    case IEEE80211_DBGREQ_BSTEERING_SET_PARAMS:
        retv = ieee80211dbg_bsteering_set_params(dev, req);
        break;
    case IEEE80211_DBGREQ_BSTEERING_GET_DATARATE_INFO:
        retv = ieee80211dbg_bsteering_get_datarate_info(dev, req);
        if (EOK == retv) {
            retv = (copy_to_user(wri->pointer, req, sizeof(*req))) ?
                    -EFAULT : 0;
        }
        break;

    case IEEE80211_DBGREQ_BSTEERING_GET_PARAMS:
        retv = ieee80211dbg_bsteering_get_params(dev, req);
        if (EOK == retv) {
            retv = (copy_to_user(wri->pointer, req, sizeof(*req))) ?
                -EFAULT : 0;
        }
        break;

    case IEEE80211_DBGREQ_BSTEERING_SET_DBG_PARAMS:
        retv = ieee80211dbg_bsteering_set_dbg_params(dev, req);
        break;

    case IEEE80211_DBGREQ_BSTEERING_GET_DBG_PARAMS:
        retv = ieee80211dbg_bsteering_get_dbg_params(dev, req);
        if (EOK == retv) {
            retv = (copy_to_user(wri->pointer, req, sizeof(*req))) ?
                -EFAULT : 0;
        }
        break;

    case IEEE80211_DBGREQ_BSTEERING_ENABLE:
        retv = ieee80211dbg_bsteering_enable(dev, req);
        break;

    case IEEE80211_DBGREQ_BSTEERING_ENABLE_EVENTS:
        retv = ieee80211dbg_bsteering_enable_events(dev, req);
#if defined QCA_NSS_WIFI_OFFLOAD_SUPPORT && ATH_BAND_STEERING
        if (EOK == retv) {
            if (ic->nss_funcs)
                ic->nss_funcs->ic_osif_nss_ol_vdev_set_cfg(vap->iv_txrx_handle, OSIF_NSS_WIFI_VDEV_CFG_BSTEER);
        }
#endif
        break;

    case IEEE80211_DBGREQ_BSTEERING_SET_OVERLOAD:
        retv = ieee80211dbg_bsteering_set_overload(dev, req);
        break;

    case IEEE80211_DBGREQ_BSTEERING_GET_OVERLOAD:
        retv = ieee80211dbg_bsteering_get_overload(dev, req);
        if (EOK == retv) {
            retv = (copy_to_user(wri->pointer, req, sizeof(*req))) ?
                -EFAULT : 0;
        }
        break;

    case IEEE80211_DBGREQ_BSTEERING_GET_RSSI:
        retv = ieee80211dbg_bsteering_get_rssi(dev, req);
        break;

#if QCA_LTEU_SUPPORT
    case IEEE80211_DBGREQ_MU_SCAN:
        retv = ieee80211dbg_ioctl_mu_scan(dev, req);
        break;

    case IEEE80211_DBGREQ_LTEU_CFG:
        retv = ieee80211dbg_ioctl_lteu_config(dev, req);
        break;

    case IEEE80211_DBGREQ_AP_SCAN:
        retv = ieee80211dbg_ioctl_ap_scan(dev, req);
        break;

    case IEEE80211_DBGREQ_SCAN_REPEAT_PROBE_TIME:
        if (req->data.param[0]) {
            retv = wlan_set_param(vap, IEEE80211_SCAN_REPEAT_PROBE_TIME, req->data.param[1]);
        } else {
            req->data.param[1] = wlan_get_param(vap, IEEE80211_SCAN_REPEAT_PROBE_TIME);
            retv = 0;
        }
        break;
    case IEEE80211_DBGREQ_SCAN_REST_TIME:
        if (req->data.param[0]) {
            retv = wlan_set_param(vap, IEEE80211_SCAN_REST_TIME, req->data.param[1]);
        } else {
            req->data.param[1] = wlan_get_param(vap, IEEE80211_SCAN_REST_TIME);
            retv = 0;
        }
        break;
    case IEEE80211_DBGREQ_SCAN_IDLE_TIME:
        if (req->data.param[0]) {
            retv = wlan_set_param(vap, IEEE80211_SCAN_IDLE_TIME, req->data.param[1]);
        } else {
            req->data.param[1] = wlan_get_param(vap, IEEE80211_SCAN_IDLE_TIME);
            retv = 0;
        }
        break;
    case IEEE80211_DBGREQ_SCAN_PROBE_DELAY:
        if (req->data.param[0]) {
            retv = wlan_set_param(vap, IEEE80211_SCAN_PROBE_DELAY, req->data.param[1]);
        } else {
            req->data.param[1] = wlan_get_param(vap, IEEE80211_SCAN_PROBE_DELAY);
            retv = 0;
        }
        break;

    case IEEE80211_DBGREQ_MU_DELAY:
        if (req->data.param[0]) {
            retv = wlan_set_param(vap, IEEE80211_MU_DELAY, req->data.param[1]);
        } else {
            req->data.param[1] = wlan_get_param(vap, IEEE80211_MU_DELAY);
            retv = 0;
        }
        break;
    case IEEE80211_DBGREQ_WIFI_TX_POWER:
        if (req->data.param[0]) {
            retv = wlan_set_param(vap, IEEE80211_WIFI_TX_POWER, req->data.param[1]);
        } else {
            req->data.param[1] = wlan_get_param(vap, IEEE80211_WIFI_TX_POWER);
            retv = 0;
        }
        break;
#endif /* QCA_LTEU_SUPPORT */


    case IEEE80211_DBGREQ_CHAN_LIST:
        retv = ieee80211dbg_ioctl_custom_chan_list(dev,req);
        break;

    case IEEE80211_DBGREQ_ATF_DEBUG_SIZE:
        retv = ieee80211dbg_ioctl_atf_debug_size(dev, req);
        break;
    case IEEE80211_DBGREQ_ATF_DUMP_DEBUG:
        retv = ieee80211dbg_ioctl_atf_dump_debug(dev, req);
        break;
    case IEEE80211_DBGREQ_ATF_DUMP_NODESTATE:
        retv = ieee80211dbg_ioctl_atf_dump_nodestate(dev, req);
        break;
    case IEEE80211_DBGREQ_OFFCHAN_TX:
        retv = ieee80211dbg_offchan_tx_test(dev, req);
        break;

        case IEEE80211_DBGREQ_BSTEERING_SET_PROBE_RESP_WH:
            retv = ieee80211dbg_bsteering_set_probe_resp_wh(dev, req);
            break;

        case IEEE80211_DBGREQ_BSTEERING_GET_PROBE_RESP_WH:
            retv = ieee80211dbg_bsteering_get_probe_resp_wh(dev, req);
            if (EOK == retv) {
                retv = (copy_to_user(wri->pointer, req, sizeof(*req))) ?
                    -EFAULT : 0;
            }
            break;
        case IEEE80211_DBGREQ_BSTEERING_SET_AUTH_ALLOW:
            retv = ieee80211dbg_bsteering_set_auth_allow(dev, req);
            break;
        case IEEE80211_DBGREQ_BSTEERING_LOCAL_DISASSOCIATION:
            retv = ieee80211dbg_bsteering_local_disassoc(dev, req);
            break;
        case IEEE80211_DBGREQ_BSTEERING_SET_STEERING:
            retv = ieee80211dbg_bsteering_set_steering(dev, req);
            break;
        case IEEE80211_DBGREQ_BSTEERING_SET_DA_STAT_INTVL:
            retv = ieee80211dbg_bsteering_set_sta_stats_interval_da(dev, req);
            break;
        case IEEE80211_DBGREQ_BSTEERING_SET_PROBE_RESP_ALLOW_24G:
            retv = ieee80211dbg_bsteering_set_probe_resp_allow_24g(dev, req);
            break;
#if QCA_LTEU_SUPPORT
    case IEEE80211_DBGREQ_SCAN_PROBE_SPACE_INTERVAL:
            if (req->data.param[0]) {
                retv = wlan_set_param(vap, IEEE80211_SCAN_PROBE_SPACE_INTERVAL, req->data.param[1]);
            } else {
                req->data.param[1] = wlan_get_param(vap, IEEE80211_SCAN_PROBE_SPACE_INTERVAL);
                retv = 0;
            }
         break;
#endif
#if UMAC_SUPPORT_VI_DBG
	case IEEE80211_DBGREQ_VOW_DEBUG_PARAM_PERSTREAM:
	    retv = ieee80211dbg_vow_debug_param_perstream(dev,req);
	    break;
	case IEEE80211_DBGREQ_VOW_DEBUG_PARAM:
	    retv = ieee80211dbg_vow_debug_param(dev,req);
	    break;
#endif
    case IEEE80211_DBGREQ_ASSOC_WATERMARK_TIME:
        ieee80211dbg_get_assoc_watermark_time(dev, req);
        retv = (copy_to_user(wri->pointer, req, sizeof(*req))) ?
            -EFAULT : 0;
        break;

    case IEEE80211_DBGREQ_SETINNETWORK_2G:
        ieee80211dbg_acs_set_innetwork_2g(dev,req);
    break;
    case IEEE80211_DBGREQ_GETINNETWORK_2G:
        ieee80211dbg_acs_get_innetwork_2g(dev,req);
    break;
    default:
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : Dbg command %d is not supported \n", __func__, req->cmd);
        break;
    }


    return retv;
}

/**
 * @brief Node iterate func which will copy the node's address and the noise statistics information
 * like rssi,min,max and median from the ni_noise_stats structure
 *
 * @param arg  pointer to the node info structure
 * @param node poinetr to node
 *
 */
void wlan_noise_info(void *arg, wlan_node_t node)
{
    ieee80211_node_info_t *node_info = (ieee80211_node_info_t *)arg;

    if(node->ni_flags){
       IEEE80211_ADDR_COPY((node_info->dest_addr + (node_info->count * IEEE80211_ADDR_LEN)),node->ni_macaddr);
       OS_MEMCPY(node_info->noise_stats + (node_info->count*node_info->bin_number),node->ni_noise_stats,sizeof(struct ieee80211_noise_stats)*node_info->bin_number);
       node_info->count++;
    }
}

/**
 * @brief to send the MAC address of the connected STA and the traffic statistics of each node to the user space
 *
 * @param vaphandle handle to the vap
 * @param macaddr Mac address sent from the upper layer
 * @param param pointer to store the STA count and the MAC address
 *
 * @return MAC address and the noise statistics
 */
int wlan_get_traffic_stats(wlan_if_t vap, u_int8_t *macaddr, int *param)
{
    struct ieee80211com *ic = vap->iv_ic;
    ieee80211_node_info_t node_info;

    /* MAC address is set to broadcast address in the user space to measure the count */
    if(IEEE80211_ADDR_EQ(macaddr, IEEE80211_GET_BCAST_ADDR(vap->iv_ic)))
    {
        param[0] = wlan_iterate_station_list(vap, NULL, NULL);
        param[2] = ic->bin_number;
        param[1] = ic->traf_rate;
        return 0;
    } else {
        node_info.dest_addr = (u_int8_t *)param[1];
        node_info.noise_stats = (ieee80211_noise_stats_t *)param[3];
        node_info.count = 0;
        node_info.bin_number = ic->bin_number;
        wlan_iterate_station_list(vap, wlan_noise_info, &node_info);
    }
    return 0;
}

/**
 * @brief
 *     - Function description:\n
 *     - iwpriv description:\n
 *         - iwpriv cmd: setkey\n
 *           The host_apd application is required to do periodic rekeying
 *           of the various connections.  These commands allow for management
 *           structure as an argument.  This structure is defined as follows:\n
 *           struct ieee80211req_key {\n
 *           u_int8_t	ik_type;	// key/cipher type\n
 *           u_int8_t	ik_pad;\n   //
 *           u_int16_t	ik_keyix;	// key index\n
 *           u_int8_t	ik_keylen;	// key length in bytes\n
 *           u_int8_t	ik_flags;\n
 *           u_int8_t	ik_macaddr[IEEE80211_ADDR_LEN];\n
 *           u_int64_t	ik_keyrsc;	// key receive sequence counter\n
 *           u_int64_t	ik_keytsc;	// key transmit sequence counter\n
 *           u_int8_t	ik_keydata[IEEE80211_KEYBUF_SIZE+IEEE80211_MICBUF_SIZE];\n
 *           };\n
 *           The delkey command will pass the structure ieee80211req_del_key,
 *           as follows:\n
 *           struct ieee80211req_del_key {\n
 *           u_int8_t	idk_keyix;	// key index\n
 *           u_int8_t	idk_macaddr[IEEE80211_ADDR_LEN];\n
 *           };\n
 *           Neither of these commands have any corresponding command line equivalents.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 */
static int
ieee80211_ioctl_setkey(struct net_device *dev, struct iw_request_info *info,
    void *w, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211req_key *ik = (struct ieee80211req_key *)extra;
    ieee80211_keyval key_val;
    u_int16_t kid;
    int error, i;
#if DBDC_REPEATER_SUPPORT
    struct global_ic_list *ic_list = vap->iv_ic->ic_global_list;
    struct ieee80211com *tmp_ic = NULL;
    struct ieee80211vap *tmp_stavap = NULL;
#endif

    debug_print_ioctl(dev->name, IEEE80211_IOCTL_SETKEY, "setkey") ;

    /* NB: cipher support is verified by ieee80211_crypt_newkey */
    if (ik->ik_keylen > sizeof(ik->ik_keydata))
    {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"%s: KeyLen too Big\n", __func__);
        return -E2BIG;
    }
    if (ik->ik_keylen == 0) {
        /* zero length keys will only set default key id if flags are set*/
        if ((ik->ik_flags & IEEE80211_KEY_DEFAULT) && (ik->ik_keyix != IEEE80211_KEYIX_NONE)) {
            /* default xmit key */
            wlan_set_default_keyid(vap, ik->ik_keyix);
            return 0;
        }
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"%s: Zero length key\n", __func__);
        return -EINVAL;
    }
    kid = ik->ik_keyix;
    if (kid == IEEE80211_KEYIX_NONE)
    {
        /* XXX unicast keys currently must be tx/rx */
        if (ik->ik_flags != (IEEE80211_KEY_XMIT | IEEE80211_KEY_RECV))
        {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"%s: Too Many Flags: %x\n",
                                    __func__,
                                    ik->ik_flags);
			ik->ik_flags = (IEEE80211_KEY_XMIT | IEEE80211_KEY_RECV);
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"%s: Too Many Flags: %x\n",
                                   __func__,
                                   ik->ik_flags);
            //return -EINVAL;
        }

        if (osifp->os_opmode == IEEE80211_M_STA ||
            osifp->os_opmode == IEEE80211_M_P2P_CLIENT)
        {
            for (i = 0; i < IEEE80211_ADDR_LEN; i++) {
                if (ik->ik_macaddr[i] != 0) {
                    break;
                }
            }
            if (i == IEEE80211_ADDR_LEN) {
                memset(ik->ik_macaddr, 0xFF, IEEE80211_ADDR_LEN);
            }
        }
    }
    else
    {
        if ((kid >= IEEE80211_WEP_NKID)
             && (ik->ik_type != IEEE80211_CIPHER_AES_CMAC)
             && (ik->ik_type != IEEE80211_CIPHER_AES_CMAC_256)
             && (ik->ik_type != IEEE80211_CIPHER_AES_GMAC)
             && (ik->ik_type != IEEE80211_CIPHER_AES_GMAC_256)) {
            return -EINVAL;
        }

        /* XXX auto-add group key flag until applications are updated */
        if ((ik->ik_flags & IEEE80211_KEY_XMIT) == 0)   /* XXX */ {
            ik->ik_flags |= IEEE80211_KEY_GROUP;    /* XXX */
        }
        else {
            if (!IEEE80211_IS_MULTICAST(ik->ik_macaddr) &&
                ((ik->ik_type == IEEE80211_CIPHER_TKIP) ||
                (ik->ik_type == IEEE80211_CIPHER_AES_CCM) ||
                (ik->ik_type == IEEE80211_CIPHER_AES_CCM_256) ||
                (ik->ik_type == IEEE80211_CIPHER_AES_GCM) ||
                (ik->ik_type == IEEE80211_CIPHER_AES_GCM_256) )) {
            kid = IEEE80211_KEYIX_NONE;
            }
        }
    }
    memset(&key_val,0, sizeof(ieee80211_keyval));


    if ( (ik->ik_flags & (IEEE80211_KEY_XMIT | IEEE80211_KEY_RECV))
        == (IEEE80211_KEY_XMIT | IEEE80211_KEY_RECV)) {
        key_val.keydir = IEEE80211_KEY_DIR_BOTH;
    } else if (ik->ik_flags & IEEE80211_KEY_XMIT) {
        key_val.keydir = IEEE80211_KEY_DIR_TX;
    } else if (ik->ik_flags & IEEE80211_KEY_RECV) {
        key_val.keydir = IEEE80211_KEY_DIR_RX;
    }
    key_val.keylen  = ik->ik_keylen;
    if (key_val.keylen > IEEE80211_KEYBUF_SIZE)
        key_val.keylen  = IEEE80211_KEYBUF_SIZE;
    key_val.rxmic_offset = IEEE80211_KEYBUF_SIZE + 8;
    key_val.txmic_offset =  IEEE80211_KEYBUF_SIZE;
    key_val.keytype = ik->ik_type;
    key_val.macaddr = ik->ik_macaddr;
    key_val.keydata = ik->ik_keydata;
    key_val.keyrsc  = ik->ik_keyrsc;
    key_val.keytsc  = ik->ik_keytsc;
#if ATH_SUPPORT_WAPI
    key_val.key_used = ik->ik_pad & 0x01;
#endif
    key_val.keyindex = ik->ik_keyix;

   if((key_val.keytype == IEEE80211_CIPHER_TKIP) || (key_val.keytype == IEEE80211_CIPHER_WAPI)) {
       key_val.rxmic_offset = 24;
       key_val.txmic_offset =  16;
   }

   if(key_val.keytype == IEEE80211_CIPHER_WEP
            && vap->iv_wep_keycache) {
        wlan_set_param(vap, IEEE80211_WEP_MBSSID, 0);
        /* only static wep keys will allocate index 0-3 in keycache
         *if we are using 802.1x with WEP then it should go to else part
         *to mandate this new iwpriv commnad wepkaycache is used
         */
    }
    else {
        wlan_set_param(vap, IEEE80211_WEP_MBSSID, 1);
        /* allow keys to allocate anywhere in key cache */
    }

    error = wlan_set_key(vap,kid,&key_val);

    if (kid == IEEE80211_KEYIX_NONE){// TKIP and AES unicast key
        IEEE80211_DELIVER_EVENT_KEYSET_DONE_INDICATION(vap,ik->ik_macaddr,error);
    }
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
            "\n\n%s: ******** SETKEY : error: %d , key_idx= %d, key_type=%d, macaddr=%s, key_len=%d\n\n",
                      __func__, error, kid, key_val.keytype, ether_sprintf(key_val.macaddr), key_val.keylen);

    wlan_set_param(vap, IEEE80211_WEP_MBSSID, 0);  /* put it back to default */

    if ((ik->ik_flags & IEEE80211_KEY_DEFAULT) && (kid != IEEE80211_KEYIX_NONE) &&
        (ik->ik_type != IEEE80211_CIPHER_AES_CMAC) && (ik->ik_type != IEEE80211_CIPHER_AES_CMAC_256) &&
        (ik->ik_type != IEEE80211_CIPHER_AES_GMAC) && (ik->ik_type != IEEE80211_CIPHER_AES_GMAC_256)) {
        /* default xmit key */
        wlan_set_default_keyid(vap,kid);
    }

#if (UMAC_REPEATER_DELAYED_BRINGUP || DBDC_REPEATER_SUPPORT)
    /*Hostaps will set the multicast key after unicast key set with kid != IEEE80211_KEYIX_NONE
      Here we wakeup AP VAP interface and set the iv_key_flag = 0 to avoid Group Key re-key that
      it will call multiple time. P.S Unicast key will only set once
    */
    if ((vap->iv_key_flag) && (kid != IEEE80211_KEYIX_NONE))
    {
#if UMAC_REPEATER_DELAYED_BRINGUP
        ieee80211_vap_handshake_finish(vap);
#endif
        vap->iv_key_flag = 0;
#if DBDC_REPEATER_SUPPORT
        if ((ic_list->dbdc_process_enable) && (ic_list->num_stavaps_up > 1)) {
            /* Send L2UF frame to detect loop after key handshake finished, or
               else packet will be dropped because of no keys */
            IEEE80211_DELIVER_EVENT_STA_VAP_CONNECTION_UPDATE(vap);
	    for (i = 0; i < MAX_RADIO_CNT; i++) {
                GLOBAL_IC_LOCK(ic_list);
                tmp_ic = ic_list->global_ic[i];
                GLOBAL_IC_UNLOCK(ic_list);
		if(tmp_ic && tmp_ic->ic_sta_vap) {
                    tmp_stavap = tmp_ic->ic_sta_vap;
                    if (tmp_stavap && wlan_is_connected(tmp_stavap)) {
		        IEEE80211_DELIVER_EVENT_STA_VAP_CONNECTION_UPDATE(tmp_stavap);
                    }
                }
	    }
        }
#endif
    }
    /*Hostaps will set the unicast key first with kid=IEEE80211_KEYIX_NONE
      Here we set the iv_key_flag=1 and wait for hostapd to set the multicast key
      to wakeup AP VAP interface. P.S Unicast key will only set once
    */
    if (kid == IEEE80211_KEYIX_NONE)
        vap->iv_key_flag = 1;
#endif

    return error;
}

static int
ieee80211_ioctl_getkey(struct net_device *dev, struct iwreq *iwr)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211req_key ik;
    ieee80211_keyval kval;
    u_int16_t kid;

    debug_print_ioctl(dev->name, IEEE80211_IOCTL_GETKEY, "getkey") ;

    if (iwr->u.data.length != sizeof(ik))
        return -EINVAL;
    if (__xcopy_from_user(&ik, iwr->u.data.pointer, sizeof(ik)))
        return -EFAULT;
    kid = ik.ik_keyix;
    kval.keydata = ik.ik_keydata;
    if (kid != IEEE80211_KEYIX_NONE)
    {
        if (kid >= IEEE80211_WEP_NKID)
            return -EINVAL;
    }
    if (wlan_get_key(vap,kid,ik.ik_macaddr, &kval, IEEE80211_KEYBUF_SIZE+IEEE80211_MICBUF_SIZE) != 0)
        return EINVAL;

    ik.ik_type = kval.keytype;
    ik.ik_keylen = kval.keylen;
    if (kval.keydir == IEEE80211_KEY_DIR_BOTH)
        ik.ik_flags =  (IEEE80211_KEY_XMIT | IEEE80211_KEY_RECV);
    else if (kval.keydir == IEEE80211_KEY_DIR_TX)
        ik.ik_flags =  IEEE80211_KEY_XMIT ;
    else if (kval.keydir == IEEE80211_KEY_DIR_RX)
        ik.ik_flags =  IEEE80211_KEY_RECV;

    if (wlan_get_default_keyid(vap) == kid)
        ik.ik_flags |= IEEE80211_KEY_DEFAULT;
    if (capable(CAP_NET_ADMIN))
    {
        /* NB: only root can read key data */
        ik.ik_keyrsc = kval.keyrsc;
        ik.ik_keytsc = kval.keytsc;
        if (kval.keytype == IEEE80211_CIPHER_TKIP)
        {
            ik.ik_keylen += IEEE80211_MICBUF_SIZE;
        }
    }
    else
    {
        ik.ik_keyrsc = 0;
        ik.ik_keytsc = 0;
        memset(ik.ik_keydata, 0, sizeof(ik.ik_keydata));
    }
    return (_copy_to_user(iwr->u.data.pointer, &ik, sizeof(ik)) ?
        -EFAULT : 0);
}

/**
 * @brief
 *     - Function description:\n
 *     - iwpriv description:\n
 *         - iwpriv cmd: delkey\n
 *           See description of setkey
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 */
static int
ieee80211_ioctl_delkey(struct net_device *dev, struct iw_request_info *info,
    void *w, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap;
    struct ieee80211req_del_key *dk = (struct ieee80211req_del_key *)extra;
    debug_print_ioctl(dev->name, IEEE80211_IOCTL_DELKEY, "delkey") ;
    if (osifp == NULL) {
        return 0;
    }
    if (osifp->os_if == NULL) {
        return 0;
    }
    vap = osifp->os_if;
    if (osifp->authmode == IEEE80211_AUTH_AUTO) {
        /* Fix for CR#586870
         * If the auth mode is set to AUTO,
         * while switching between SHARED and OPEN
         * mode, the delkey should not happen;
         * If the delkey happens when the assoc goes
         * thru in OPEN mode, the ping will not pass.
         * This piece of code could have been put inside
         * wlan_del_key() function, but that could create
         * problems for other callers of that function.
         */
        ieee80211_auth_mode modes[IEEE80211_AUTH_MAX];
        uint8_t nmodes=0;
        nmodes=wlan_get_auth_modes(vap,modes,IEEE80211_AUTH_MAX);
        if (nmodes && ((modes[0] == IEEE80211_AUTH_SHARED)
                       || (modes[0] == IEEE80211_AUTH_OPEN))) {
            return 0;
        }
    }

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"DELETE CRYPTO KEY index %d, addr %s\n",
                    dk->idk_keyix, ether_sprintf(dk->idk_macaddr));
    if (dk->idk_keyix == 255) {
        wlan_del_key(vap,IEEE80211_KEYIX_NONE,dk->idk_macaddr);
    } else {
        wlan_del_key(vap,dk->idk_keyix,dk->idk_macaddr);
    }
    return 0;
}

static int
ieee80211_ioctl_getchanlist(struct net_device *dev,
    struct iw_request_info *info, void *w, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    debug_print_ioctl(dev->name, IEEE80211_IOCTL_GETCHANLIST, "getchanlist") ;
    return wlan_get_chanlist(vap, extra);
}

/**
 * @brief
 *     - Function description:\n
 *     - iwpriv description:\n
 *         - iwpriv cmd: iwpriv athN getchaninfo\n
 *           Cannot find in AP Manual
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 */
static int
ieee80211_ioctl_getchaninfo(struct net_device *dev,
    struct iw_request_info *info, void *w, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211req_chaninfo *channel;
    int nchans_max = ((IEEE80211_CHANINFO_MAX - 1) * sizeof(__u32))/
                                         sizeof(struct ieee80211_channel);

    debug_print_ioctl(dev->name, IEEE80211_IOCTL_GETCHANINFO, "getchaninfo") ;
    channel = (struct ieee80211req_chaninfo *)OS_MALLOC(osifp->os_handle, sizeof(*channel), GFP_KERNEL);
    if (channel == NULL)
        return -ENOMEM;

    wlan_get_chaninfo(vap, 0, channel->ic_chans, &channel->ic_nchans);

    if (channel->ic_nchans > nchans_max) {
        channel->ic_nchans = nchans_max;
    }
    OS_MEMCPY(extra, channel, channel->ic_nchans *
                            sizeof(struct ieee80211_channel) + sizeof(__u32));

    OS_FREE(channel);
    return EOK;
}

static int
ieee80211_ioctl_giwtxpow(struct net_device *dev,
    struct iw_request_info *info,
    struct iw_param *rrq, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    int txpow, fixed;
    debug_print_ioctl(dev->name, SIOCGIWTXPOW, "giwtxpow") ;
    if(rrq->flags == 1) {
        rrq->flags = 0;
        ieee80211_ucfg_get_txpow_fraction(vap, &txpow, &fixed);
    } else {
        ieee80211_ucfg_get_txpow(vap, &txpow, &fixed);
    }
    rrq->value = txpow;
    rrq->fixed = fixed;
    rrq->disabled = (rrq->fixed && rrq->value == 0);
    rrq->flags = IW_TXPOW_DBM;
    return 0;
}

static int
ieee80211_ioctl_siwtxpow(struct net_device *dev,
    struct iw_request_info *info,
    struct iw_param *rrq, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    int fixed, txpow, retv = EOK;
    debug_print_ioctl(dev->name, SIOCSIWTXPOW, "siwtxpow") ;

    ieee80211_ucfg_get_txpow(vap, &txpow, &fixed);

    /*
    * for AP operation, we don't allow radio to be turned off.
    * for STA, /proc/sys/dev/wifiN/radio_on may be used.
    * see ath_hw_phystate_change(...)
    */
    if (rrq->disabled) {
        return -EOPNOTSUPP;
    }

    if (rrq->fixed) {
        if (rrq->flags != IW_TXPOW_DBM)
            return -EOPNOTSUPP;
        retv = ieee80211_ucfg_set_txpow(vap, rrq->value);
    }
    else {
        retv = ieee80211_ucfg_set_txpow(vap, 0);
    }
    return (retv != EOK) ? -EOPNOTSUPP : EOK;
}

/**
 * @brief
 *     - Function description:\n
 *     - iwpriv description:\n
 *         - iwpriv cmd: iwpriv athN addmac mac_addr\n
 *           These commands are used to setup and modify the MAC filtering list.
 *           MAC filtering allows the user to either limit specific MAC
 *           addresses from associating with the AP, or specifically indicates
 *           which MAC addresses can associate with the AP.  The addmac and
 *           delmac will add specific MAC addresses to the Access Control List
 *           (ACL).
 *             - iwpriv category: N/A
 *             - iwpriv arguments: MAC address
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 */
static int
ieee80211_ioctl_addmac(struct net_device *dev, struct iw_request_info *info,
    void *w, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct sockaddr *sa = (struct sockaddr *)extra;
    int rc;

    debug_print_ioctl(dev->name, IEEE80211_IOCTL_ADDMAC, "addmac") ;

    rc = wlan_set_acl_add(vap, sa->sa_data, IEEE80211_ACL_FLAG_ACL_LIST_1);
    return rc;
}

/**
 * @brief
 *     - Function description:\n
 *     - iwpriv description:\n
 *         - iwpriv cmd: iwpriv athN delmac mac_addr\n
 *           These commands are used to setup and modify the MAC filtering list.
 *           MAC filtering allows the user to either limit specific MAC
 *           addresses from associating with the AP, or specifically indicates
 *           which MAC addresses can associate with the AP.  The addmac and
 *           delmac will add specific MAC addresses to the Access Control List
 *           (ACL).
 *             - iwpriv category: N/A
 *             - iwpriv arguments: MAC address
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 */
static int
ieee80211_ioctl_delmac(struct net_device *dev, struct iw_request_info *info,
    void *w, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct sockaddr *sa = (struct sockaddr *)extra;
    int rc;

    debug_print_ioctl(dev->name, IEEE80211_IOCTL_DELMAC, "delmac") ;

    rc = wlan_set_acl_remove(vap, sa->sa_data, IEEE80211_ACL_FLAG_ACL_LIST_1);
    return rc;
}
#if UMAC_SUPPORT_WDS
/*
 * for ipv6 ready logo test, EV#74677
 * need to parse the NS package, because LinklayerAddress
 * may be NOT equal to Source MAC Address.
 */
extern struct ieee80211_node *
ieee80211_find_wds_node(struct ieee80211_node_table *nt, const u_int8_t *macaddr);
extern int
ieee80211_add_wds_addr(struct ieee80211_node_table *nt,
                       struct ieee80211_node *ni, const u_int8_t *macaddr,
                                      u_int32_t flags);

int ieee80211_add_wdsaddr(wlan_if_t vap, union iwreq_data *u)
{
    struct ieee80211_node_table *nt;
    struct ieee80211com *ic;
    struct ieee80211_node *ni;
    struct ieee80211_node *ni_wds;
    struct sockaddr *sa = (struct sockaddr *)u->data.pointer;
    int rc = 0;

    ic = vap->iv_ic;
    nt = &ic->ic_sta;
    ni = NULL;
    ni_wds = NULL;

    if(vap->iv_opmode == IEEE80211_M_HOSTAP)
    {
        struct sockaddr *sa = ((struct sockaddr *)u->data.pointer)+1;
        ni = ieee80211_find_wds_node(nt, sa->sa_data);
        if(ni)
            ieee80211_free_node(ni);
        else
            return rc = 1;
    }
    else
    {
        ni = vap->iv_bss;
    }

    ni_wds = ieee80211_find_wds_node(nt, sa->sa_data);
    if(ni_wds)
    {
        ieee80211_free_node(ni_wds); /* Decr ref count */
    }
    else
    {
        rc = ieee80211_add_wds_addr(nt, ni, sa->sa_data, IEEE80211_NODE_F_WDS_BEHIND);
    }

    return rc;
}
#endif

/**
 * @brief
 *     - Function description:\n
 *     - iwpriv description:\n
 *         - iwpriv cmd: iwpriv athN sendwowpkt macAddr\n
 *             This command is used for sending Wake-On-Wireless
 *             magic packet to a STA that is associated to the AP.
 *             - iwpriv category: COMMON
 *             - iwpriv arguments:\n
 *               Mac address of the STA  in 6 byte
 *           form E.g iwpriv ath0 sendwowpkt 00:03:7f:12:34:b2
 *             .
 */

static int
ieee80211_ioctl_sendwowpkt(struct net_device *dev, union iwreq_data *u)
{

    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    struct ieee80211com *ic = vap->iv_ic;
    struct ether_header *eh;
    struct ieee80211_node *ni = NULL;
    struct net_device *netd;
    u_int8_t   src_mac_address[IEEE80211_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    u_int8_t   dst_mac_address[IEEE80211_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    u_int8_t   macaddr[IEEE80211_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    u_int  msg_len;
    wbuf_t mywbuf;
    u_int8_t *payload = NULL;
    int index = 0, i = 0;
    struct sockaddr *sa = (struct sockaddr *)u->data.pointer;

    if (sa->sa_family != ARPHRD_ETHER) {
        return -EINVAL;
     }

    /* copy mac address */
    IEEE80211_ADDR_COPY(&(macaddr), sa->sa_data);

    ni = ieee80211_vap_find_node(vap, macaddr);
    if (ni == NULL) {
        return -EINVAL;
    }

    if (vap != ni->ni_vap) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: is not assocated for this VAP \n" ,ether_sprintf(ni->ni_macaddr));
        return -EINVAL;
    }
    netd = (struct net_device *) wlan_vap_get_registered_handle(vap);

    msg_len = WOW_CUSTOM_PKT_LEN;

    mywbuf = wbuf_alloc(ic->ic_osdev,  WBUF_TX_DATA, msg_len);
    if (!mywbuf) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "wbuf allocation failed in %s \n", __func__);
        ieee80211_free_node(ni);
        return -ENOMEM;
    }

    IEEE80211_ADDR_COPY(dst_mac_address, ni->ni_macaddr);

    if ((vap->iv_opmode == IEEE80211_M_HOSTAP)) {
        /* In AP Mode */
        IEEE80211_ADDR_COPY(src_mac_address, ni->ni_bssid);
    } else if ((vap->iv_opmode == IEEE80211_M_STA)) {
        /* In STA Mode */
        IEEE80211_ADDR_COPY(src_mac_address, vap->iv_myaddr);
    }


    /* Initialize */
    wbuf_append(mywbuf, msg_len);
    memset((u_int8_t *)wbuf_raw_data(mywbuf), 0, msg_len);

    /* Prepare Payload */
    payload = (u_int8_t *)wbuf_raw_data(mywbuf);

    /* Copy sync pattern*/
    for (index = 0; index < WOW_SYNC_LEN ; index++) {
        payload[index] = WOW_SYNC_PATTERN;
    }

    /* copy STA macaddr 16 times in data payload */
    for (i = 0; i < WOW_MAC_ADDR_COUNT; i++) {
        IEEE80211_ADDR_COPY(&payload[index], &macaddr);
        index +=6;
    }

    /* Prepare ethernet packet */
    eh = (struct ether_header *) wbuf_push(mywbuf, sizeof(struct ether_header));
    IEEE80211_ADDR_COPY(&eh->ether_shost[0], src_mac_address);
    IEEE80211_ADDR_COPY(&eh->ether_dhost[0], macaddr);
    eh->ether_type = htons(ETH_TYPE_WOW);

    /* Prepare wbuf for sending */
    wbuf_set_priority(mywbuf,WME_AC_BE);
    wbuf_set_tid(mywbuf, WME_AC_TO_TID(WME_AC_BE));
    mywbuf->dev = dev;
    dev_queue_xmit(mywbuf);

    ieee80211_free_node(ni);

    return 0;
}


static int
ieee80211_ioctl_getaclmac(struct net_device *dev, struct iw_request_info *info,
    void *w, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    union iwreq_data *u = w;
    int rc = 0;
    u_int8_t *mac_list;
    struct sockaddr *sa = (struct sockaddr *)extra;
    int i, num_mac;

    switch(u->data.flags)
    {
#if UMAC_SUPPORT_WDS
        case IEEE80211_PARAM_ADD_WDS_ADDR:
            rc = ieee80211_add_wdsaddr(vap, u);
            if(rc)
                rc = EFAULT;
            break;
#endif
        case IEEE80211_PARAM_SEND_WOWPKT:
            ieee80211_ioctl_sendwowpkt(dev, u);
            break;

        case IEEE80211_PARAM_ADD_MAC_LIST_SEC:
            sa = (struct sockaddr *)u->data.pointer;
            rc = wlan_set_acl_add(vap, sa->sa_data, IEEE80211_ACL_FLAG_ACL_LIST_2);
            if (rc)
                return EFAULT;
            break;

        case IEEE80211_PARAM_DEL_MAC_LIST_SEC:
            sa = (struct sockaddr *)u->data.pointer;
            rc = wlan_set_acl_remove(vap, sa->sa_data, IEEE80211_ACL_FLAG_ACL_LIST_2);
            if (rc)
                return EFAULT;
            break;

        case IEEE80211_PARAM_GET_MAC_LIST_SEC:
            mac_list = (u_int8_t *)OS_MALLOC(osifp->os_handle, (IEEE80211_ADDR_LEN * 256), GFP_KERNEL);

            if (!mac_list) {
                return EFAULT;
            }
            rc = wlan_get_acl_list(vap, mac_list, (IEEE80211_ADDR_LEN * 256),
                                                &num_mac, IEEE80211_ACL_FLAG_ACL_LIST_2);
            if(rc) {
                OS_FREE(mac_list);
                return EFAULT;
            }
            for (i = 0; i < num_mac; i++) {
                memcpy(&(sa[i]).sa_data, &mac_list[i * IEEE80211_ADDR_LEN], IEEE80211_ADDR_LEN);
                sa[i].sa_family = ARPHRD_ETHER;
            }
            u->data.length = num_mac;
            OS_FREE(mac_list);
            break;

        case IEEE80211_PARAM_CONFIG_BSSID:
            sa = (struct sockaddr *)u->data.pointer;
            OS_MEMCPY(vap->iv_conf_des_bssid,sa->sa_data,IEEE80211_ADDR_LEN);
            qdf_print("Configured Hidden AP's BSSID: %s \n",ether_sprintf(vap->iv_conf_des_bssid));
            break;

        case IEEE80211_PARAM_GET_CONFIG_BSSID:
            memcpy(sa->sa_data,vap->iv_conf_des_bssid, IEEE80211_ADDR_LEN);
            u->data.length = 1; /* num_mac to get is 1*/
            break;

        default:
            debug_print_ioctl(dev->name, IEEE80211_IOCTL_GET_MACADDR, "getmac");
            mac_list = (u_int8_t *)OS_MALLOC(osifp->os_handle,
                                           (IEEE80211_ADDR_LEN * 256), GFP_KERNEL);
            if (!mac_list) {
                return EFAULT;
            }
            rc = wlan_get_acl_list(vap, mac_list, (IEEE80211_ADDR_LEN * 256),
                                                &num_mac, IEEE80211_ACL_FLAG_ACL_LIST_1);
            if(rc) {
                OS_FREE(mac_list);
                return EFAULT;
            }

            for (i = 0; i < num_mac; i++) {
                memcpy(&(sa[i]).sa_data, &mac_list[i * IEEE80211_ADDR_LEN], IEEE80211_ADDR_LEN);
                sa[i].sa_family = ARPHRD_ETHER;
            }
            u->data.length = num_mac;
            OS_FREE(mac_list);
    }

    return rc;
}

/**
 * @brief
 *     - Function description:\n
 *     - iwpriv description:\n
 *         - iwpriv cmd: iwpriv athN kickmac macAddr\n
 *             This command forces the AP to disassociate a STA that is
 *           associated to the AP.
 *             - iwpriv category: COMMON
 *             - iwpriv arguments:\n
 *               Ethernet address of the STA to be disassociated in 6 byte
 *           form E.g iwpriv ath0 kickmac 00:18:41:9b:c8:87
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 */
static int
ieee80211_ioctl_kickmac(struct net_device *dev, struct iw_request_info *info,
    void *w, char *extra)
{
    struct sockaddr *sa = (struct sockaddr *)extra;
    struct ieee80211req_mlme mlme;
    debug_print_ioctl(dev->name, IEEE80211_IOCTL_KICKMAC, "kickmac") ;
QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %s[%d] \n",__func__,__LINE__);
    if (sa->sa_family != ARPHRD_ETHER)
        return -EINVAL;

    /* Setup a MLME request for disassociation of the given MAC */
    mlme.im_op = IEEE80211_MLME_DISASSOC;
    mlme.im_reason = IEEE80211_REASON_UNSPECIFIED;
    IEEE80211_ADDR_COPY(&(mlme.im_macaddr), sa->sa_data);

    /* Send the MLME request and return the result. */
    return ieee80211_ioctl_setmlme(dev, info, w, (char *)&mlme);
}

/**
 * @brief
 *     - Function description:\n
 *     - iwpriv description:\n
 *         - iwpriv cmd: iwpriv athN setchanlist chanlist\n
 *           This command is used by an application to set the channel
 *           list manually.  Channels that are not valid from a regulatory
 *           perspective will be ignored.  This command is passed a byte
 *           array 255 bytes long that contains the list of channels required.
 *            A value of 0 indicates no channel, but all 255 bytes
 *           must be provided.  The getchanlist will receive this array
 *           from the driver in a 255 byte array that contains the valid
 *           channel list.  The response is a binary array that WLAN tools
 *           cannot parse; therefore this cannot be used on the command line.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 */
static int
ieee80211_ioctl_setchanlist(struct net_device *dev,
    struct iw_request_info *info, void *w, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap;

    vap = osifp->os_if;
    (void) extra;
    debug_print_ioctl(dev->name, IEEE80211_IOCTL_SETCHANLIST, "setchanlist") ;
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"%s: Not yet supported \n", __func__);
    return 0;
}

/**
 * @brief
 *     - Function description:\n
 *     - iwpriv description:\n
 *         - iwpriv cmd: iwpriv athN setwmmparams arg1 arg2 arg3\n
 *           set wmm parameter.
 *             - iwpriv category: COMMON
 *             - iwpriv arguments:\n
 * Argument 1: WME parameter\n
 * 1 - CWMIN\n
 * 2 - CWMAX\n
 * 3 - AIFS\n
 * 4 - TXOPLIMIT\n
 * 5 - ACM\n
 * 6 - NOACKPOLICY\n
 * Argument 2: access category\n
 * 0 - best effort\n
 * 1 - background\n
 * 2 - video\n
 * 3 - voice\n
 * Argument 3:\n
 * 1 - bss parameter \n
 * 0 - local parameter\n
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN cwmin AC Mode value\n
 *           This command sets the CWmin WMM parameter for either the AP
 *           or station parameter set. The cwmax command is a WMM command
 *           that must have the AC and Mode specified.  The value is CWmin
 *           in units as described in Table 9 Access Categories and Modes
 *           This command has a corresponding get command which requires the AC and
 *           Mode to be specified.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN cwmax AC Mode value\n
 *           This command sets the CWmax WMM parameter for either the AP
 *           or station parameter set. The cwmax command is a WMM command
 *           that must have the AC and Mode specified.  The value is CWmax
 *           in units as described in Table 9 Access Categories and Modes.
 *           This command has a corresponding get command.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN aifs AC Mode Value\n
 *           This WMM command sets the AIFSN WMM parameter for either the
 *           AP or Station parameter set.  This parameter controls the
 *           frame spacing in WMM operations.  The command takes 3 parameters:
 *           The first value, AC, is the access class value.  The second
 *           value indicates whether the command is to be applied to the
 *           AP or Station tables, which are kept separately.  Finally,
 *           the third parameter is the AIFSN value (see Table 9 Access
 *           Categories and Modes).
 *           This parameter has a corresponding get command, which requires the
 *           AC and Mode as arguments.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN txoplimit AC Mode limit\n
 *           This command will set the TXOP limit, described in Table 9
 *           Access Categories and Modes.
 *           The AC and Mode is as described at the beginning of this section.  This
 *           command has a corresponding get command.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN acm AC Mode value\n
 *           The ACM value for each access category is set using the acm
 *           command.  The AC and Mode values must be set for this command.
 *            The value is the ACM value (see Table 9 Access Categories
 *           and Modes) for the specific access category.  This command has
 *           a corresponding get
 *           command that returns the current setting for the indicated
 *           AC and mode.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 *         - iwpriv cmd: iwpriv athN noackpolicy AC Mode 0|1\n
 *           This command sets the No ACK policy bit in the WMM parameter
 *           set for either the AP or station. The noackpolicy command
 *           is a WMM command that must have the AC and Mode specified.
 *            The value either sets the policy to no ACK sent (1) or
 *           send ACK (0).  This command has a corresponding get command.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 */
static int
ieee80211_ioctl_setwmmparams(struct net_device *dev,
    struct iw_request_info *info, void *w, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    int *param = (int *) extra;
    int ac = (param[1] < WME_NUM_AC) ? param[1] : WME_AC_BE;
    int bss = param[2];
    int retv = 0;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    struct ieee80211com *ic = vap->iv_ic;
#endif
    debug_print_ioctl(dev->name, IEEE80211_IOCTL_SETWMMPARAMS, "setwmmparams") ;
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                    "%s: param %d ac %d bss %d val %d\n",
                    __func__, param[0], ac, bss, param[3]);
    switch (param[0])
    {
    case IEEE80211_WMMPARAMS_CWMIN:
        if (param[3] < 0 ||  param[3] > 15) {
            retv = -EINVAL;
        }
        else {
            retv = wlan_set_wmm_param(vap, WLAN_WME_CWMIN,
                                        bss, ac, param[3]);
        }
        break;
    case IEEE80211_WMMPARAMS_CWMAX:
        if (param[3] < 0 ||  param[3] > 15) {
            retv = -EINVAL;
        }
        else {
            retv = wlan_set_wmm_param(vap, WLAN_WME_CWMAX,
                                        bss, ac, param[3]);
        }
        break;
    case IEEE80211_WMMPARAMS_AIFS:
        if (param[3] < 0 ||  param[3] > 15) {
            retv = -EINVAL;
        }
        else {
            retv = wlan_set_wmm_param(vap, WLAN_WME_AIFS,
                                        bss, ac, param[3]);
        }
        break;
    case IEEE80211_WMMPARAMS_TXOPLIMIT:
        if (param[3] < 0 ||  param[3] > 8192) {
            retv = -EINVAL;
        }
        else {
            retv = wlan_set_wmm_param(vap, WLAN_WME_TXOPLIMIT,
                                        bss, ac, param[3]);
        }
        break;
    case IEEE80211_WMMPARAMS_ACM:
        if (param[3] < 0 ||  param[3] > 1) {
            retv = -EINVAL;
        }
        else {
            retv = wlan_set_wmm_param(vap, WLAN_WME_ACM,
                                        bss, ac, param[3]);
        }
        break;
    case IEEE80211_WMMPARAMS_NOACKPOLICY:
        if (param[3] < 0 ||  param[3] > 1) {
            retv = -EINVAL;
        }
        else {
            retv = wlan_set_wmm_param(vap, WLAN_WME_ACKPOLICY,
                                        bss, ac, param[3]);
        }
        break;
#if UMAC_VOW_DEBUG
    case IEEE80211_PARAM_VOW_DBG_CFG:
        {
            int *input_param = (int *) extra;
            if( input_param[1] >= MAX_VOW_CLIENTS_DBG_MONITOR ) {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Invalid Parameter: Acceptable index range [0 - %d]\n",
                        MAX_VOW_CLIENTS_DBG_MONITOR-1);
                retv = -EINVAL;
            } else {
                osifp->tx_dbg_vow_peer[input_param[1]][0] = input_param[2];
                osifp->tx_dbg_vow_peer[input_param[1]][1] = input_param[3];
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        if (ic->nss_funcs)
            ic->nss_funcs->ic_osif_nss_vdev_vow_dbg_cfg(vap->iv_txrx_handle, input_param[1]);
#endif
            }
        }
        break;
#endif

    default:
        return retv;
    }

    /* Reinitialise the vaps to update the wme params during runtime configuration */
    if (!bss && retv == EOK) {
        /*need to restart for local wmm changes*/
        retv = IS_UP(dev) ? osif_vap_init(dev,0) : 0;
    }

    return retv;
}

static int
ieee80211_ioctl_getwmmparams(struct net_device *dev,
    struct iw_request_info *info, void *w, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    int *param = (int *) extra;
    int ac = (param[1] < WME_NUM_AC) ? param[1] : WME_AC_BE;
    int bss = param[2];

    debug_print_ioctl(dev->name, IEEE80211_IOCTL_GETWMMPARAMS, "getwmmparams") ;
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                    "%s: param %d ac %d bss %d\n", __func__, param[0], ac, bss);
    switch (param[0])
    {
    case IEEE80211_WMMPARAMS_CWMIN:
        param[0] = wlan_get_wmm_param(vap, WLAN_WME_CWMIN,
                                            bss, ac);
        break;
    case IEEE80211_WMMPARAMS_CWMAX:
        param[0] = wlan_get_wmm_param(vap, WLAN_WME_CWMAX,
                                            bss, ac);
        break;
    case IEEE80211_WMMPARAMS_AIFS:
        param[0] = wlan_get_wmm_param(vap, WLAN_WME_AIFS,
                                            bss, ac);
        break;
    case IEEE80211_WMMPARAMS_TXOPLIMIT:
        param[0] = wlan_get_wmm_param(vap, WLAN_WME_TXOPLIMIT,
                                            bss, ac);
        break;
    case IEEE80211_WMMPARAMS_ACM:
        param[0] = wlan_get_wmm_param(vap, WLAN_WME_ACM,
                                            bss, ac);
        break;
    case IEEE80211_WMMPARAMS_NOACKPOLICY:
        param[0] = wlan_get_wmm_param(vap, WLAN_WME_ACKPOLICY,
                                            bss, ac);
        break;
    default:
        break;
    }
    return 0;
}

static int
ieee80211_ioctl_res_req(struct net_device *dev, struct iwreq *iwr)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211req_res *req;
#if UMAC_SUPPORT_ADMCTL
    struct ieee80211req_res_addts *addts;
#endif /* UMAC_SUPPORT_ADMCTL */
    struct ieee80211req_res_addnode *addnode;
    int ret = 0;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : len %d \n", __func__, iwr->u.data.length);
    if (iwr->u.data.length != sizeof(*req)) {
        return -EINVAL;
    }
    req = (struct ieee80211req_res *)OS_MALLOC(osifp->os_handle, sizeof(*req), GFP_KERNEL);
    if (req == NULL) {
        return -ENOMEM;
    }
    if (__xcopy_from_user(req, iwr->u.data.pointer, sizeof(*req))) {
        OS_FREE(req);
        return -EFAULT;
    }
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "req type %d \n", req->type);
    switch (req->type) {
#if UMAC_SUPPORT_ADMCTL
    case IEEE80211_RESREQ_ADDTS:
        addts = &req->u.addts;
        addts->status = wlan_admctl_addts(vap, req->macaddr, addts->tspecie);
        ret = (copy_to_user(iwr->u.data.pointer, req, sizeof(*req)) ?
        -EFAULT : 0);
        break;
#endif /* UMAC_SUPPORT_ADMCTL */
    case IEEE80211_RESREQ_ADDNODE:
        addnode = &req->u.addnode;
        ret = wlan_add_sta_node(vap, req->macaddr, addnode->auth_alg);
        break;
    default:
        break;
    }
    OS_FREE(req);
    return ret;
}

static int
ieee80211_ioctl_getwpaie(struct net_device *dev, struct iwreq *iwr)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211req_wpaie *wpaie;
    u_int8_t    ni_ie[IEEE80211_MAX_OPT_IE];
    u_int16_t len = IEEE80211_MAX_OPT_IE;
    int ret;

    if (iwr->u.data.length != sizeof(*wpaie))
        return -EINVAL;
    wpaie = (struct ieee80211req_wpaie *)OS_MALLOC(osifp->os_handle, sizeof(*wpaie), GFP_KERNEL);
    if (wpaie == NULL)
    return -ENOMEM;
    if (__xcopy_from_user(wpaie, iwr->u.data.pointer, IEEE80211_ADDR_LEN)) {
    OS_FREE(wpaie);
        return -EFAULT;
    }
    memset(wpaie->wpa_ie, 0, sizeof(wpaie->wpa_ie));
    memset(wpaie->rsn_ie, 0, sizeof(wpaie->rsn_ie));
    wlan_node_getwpaie(vap,wpaie->wpa_macaddr,ni_ie,&len);
    if (len > 0) {
        if ((*ni_ie) == IEEE80211_ELEMID_RSN) {
            memcpy(wpaie->rsn_ie, ni_ie, len);
        }
        memcpy(wpaie->wpa_ie, ni_ie, len);
    }
#ifdef ATH_WPS_IE
    memset(wpaie->wps_ie, 0, sizeof(wpaie->wps_ie));
    len = IEEE80211_MAX_OPT_IE;
    wlan_node_getwpsie(vap,wpaie->wpa_macaddr,ni_ie,&len);
    if (len > 0) {
        memcpy(wpaie->wps_ie, ni_ie, len);
    }
#endif /* ATH_WPS_IE */
    ret = (_copy_to_user(iwr->u.data.pointer, wpaie, sizeof(*wpaie)) ?
        -EFAULT : 0);
    OS_FREE(wpaie);
    return ret;
}


#if UMAC_SUPPORT_STA_STATS
/* This set of statistics is not completely implemented. Enable
   UMAC_SUPPORT_STA_STATS to avail of the partial list of
   statistics. */
static int
ieee80211_ioctl_getstastats(struct net_device *dev, struct iwreq *iwr)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    struct ieee80211_node *ni;
    u_int8_t macaddr[IEEE80211_ADDR_LEN];
    const int off = __offsetof(struct ieee80211req_sta_stats, is_stats);
    int error;

    if (iwr->u.data.length < off)
        return -EINVAL;
    if (__xcopy_from_user(macaddr, iwr->u.data.pointer, IEEE80211_ADDR_LEN))
        return -EFAULT;
    ni = ieee80211_vap_find_node(vap, macaddr);
    if (ni == NULL)
        return -EINVAL;     /* XXX */
    if (iwr->u.data.length > sizeof(struct ieee80211req_sta_stats))
        iwr->u.data.length = sizeof(struct ieee80211req_sta_stats);
    /* NB: copy out only the statistics */
    error = _copy_to_user(iwr->u.data.pointer + off, &ni->ni_stats,
        iwr->u.data.length - off);
    ieee80211_free_node(ni);
    return (error ? -EFAULT : 0);
}
#endif /* UMAC_SUPPORT_STA_STATS */

#define SCANREQ_GIVE_ALL_SCAN_ENTRIES 0
#define SCANREQ_GIVE_ONLY_DESSIRED_SSID 1
#define SCANREQ_GIVE_EXCEPT_DESSIRED_SSID 2

struct scanreq
{
    struct ieee80211req_scan_result *sr;
    size_t space;
    struct ieee80211vap *vap;
    u_int8_t scanreq_type;
};

static size_t
scan_space(wlan_scan_entry_t se, u_int16_t *ielen)
{
    u_int8_t ssid_len;
    *ielen = 0;

    wlan_scan_entry_ssid(se,&ssid_len);
    *ielen =  wlan_scan_entry_ie_len(se);
    return roundup(sizeof(struct ieee80211req_scan_result) +
                        *ielen +  ssid_len, sizeof(u_int32_t));
}

static int
get_scan_space(void *arg, wlan_scan_entry_t se)
{
    struct scanreq *req = arg;
    u_int16_t ielen;

    req->space += scan_space(se, &ielen);
    return 0;
}

static int
get_scan_space_rep_move(void *arg, wlan_scan_entry_t se)
{
    struct scanreq *req = arg;
    struct ieee80211vap *vap = req->vap;
    u_int16_t ielen;
    u_int8_t *ssid;
    u_int8_t ssid_len;
    u_int8_t *bssid;

    ssid = wlan_scan_entry_ssid(se,&ssid_len);
    bssid = wlan_scan_entry_bssid(se);

    /* Calculate scan space only for those scan entries that match
     * the SSID of the new Root AP
     */
    if (ssid) {
        if (!(strncmp(ssid, vap->iv_ic->ic_repeater_move.ssid.ssid,
                      vap->iv_ic->ic_repeater_move.ssid.len))) {
            if(IEEE80211_ADDR_IS_VALID(vap->iv_ic->ic_repeater_move.bssid)) {
                if (IEEE80211_ADDR_EQ(bssid, vap->iv_ic->ic_repeater_move.bssid)) {
                    req->space += scan_space(se, &ielen);
                }
            } else {
                req->space += scan_space(se, &ielen);
            }
        }
    }

    return 0;
}

static int
get_scan_result(void *arg, wlan_scan_entry_t se)
{
    struct scanreq *req = arg;
    struct ieee80211req_scan_result *sr;
    struct ieee80211vap *vap = req->vap;
    u_int16_t ielen, len, nr, nxr;
    u_int8_t *cp;
    u_int8_t ssid_len;
    u_int8_t *rates, *ssid, *bssid;
    bool des_ssid_found = 0;

    len = scan_space(se, &ielen);
    if (len > req->space)
        return 0;

    sr = req->sr;
    memset(sr, 0, sizeof(*sr));
    ssid = wlan_scan_entry_ssid(se,&ssid_len);
    bssid = wlan_scan_entry_bssid(se);
    sr->isr_ssid_len = ssid_len;

    if (req->scanreq_type == SCANREQ_GIVE_ONLY_DESSIRED_SSID) {
        des_ssid_found = ieee80211_vap_match_ssid((struct ieee80211vap *) vap->iv_ic->ic_sta_vap, ssid, ssid_len);
        if (!des_ssid_found) {
            return 0;
        } else {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Getting desired ssid from scan result\n");
        }
    }

    if (req->scanreq_type == SCANREQ_GIVE_EXCEPT_DESSIRED_SSID) {
        des_ssid_found = ieee80211_vap_match_ssid((struct ieee80211vap *) vap->iv_ic->ic_sta_vap, ssid, ssid_len);
        if (des_ssid_found) {
            return 0;
        }
    }

    if (vap->iv_ic->ic_repeater_move.state == REPEATER_MOVE_IN_PROGRESS) {
        if (ssid == NULL)
            return 0;

        if (bssid == NULL)
            return 0;

        if ((strncmp(ssid, vap->iv_ic->ic_repeater_move.ssid.ssid,
                     vap->iv_ic->ic_repeater_move.ssid.len)) != 0) {
            return 0;
        }

        if(IEEE80211_ADDR_IS_VALID(vap->iv_ic->ic_repeater_move.bssid)) {
            if (!IEEE80211_ADDR_EQ(bssid, vap->iv_ic->ic_repeater_move.bssid))
                return 0;
        }
    }

    if (ielen > 65534 ) {
        ielen = 0;
    }
    sr->isr_ie_len = ielen;
    sr->isr_len = len;
    sr->isr_freq = wlan_channel_frequency(wlan_scan_entry_channel(se));
    sr->isr_flags = 0;
    sr->isr_rssi = wlan_scan_entry_rssi(se);
    sr->isr_intval =  wlan_scan_entry_beacon_interval(se);
    sr->isr_capinfo = wlan_scan_entry_capinfo(se);
    sr->isr_erp =  wlan_scan_entry_erpinfo(se);
    IEEE80211_ADDR_COPY(sr->isr_bssid, wlan_scan_entry_bssid(se));
    rates = wlan_scan_entry_rates(se);
    nr = min((int)rates[1], IEEE80211_RATE_MAXSIZE);
    memcpy(sr->isr_rates, rates+2, nr);

    rates = wlan_scan_entry_xrates(se);
    nxr=0;
    if (rates) {
        nxr = min((int)rates[1], IEEE80211_RATE_MAXSIZE - nr);
        memcpy(sr->isr_rates+nr, rates+2, nxr);
    }
    sr->isr_nrates = nr + nxr;

    cp = (u_int8_t *)(sr+1);
    if (ssid) {
        memcpy(cp,ssid, sr->isr_ssid_len);
    }
    cp += sr->isr_ssid_len;

    if (ielen) {
        wlan_scan_entry_copy_ie_data(se,cp,&ielen);
        cp += ielen;
    }

    req->space -= len;
    req->sr = (struct ieee80211req_scan_result *)(((u_int8_t *)sr) + len);

    return 0;
}

static int
ieee80211_ioctl_getscanresults(struct net_device *dev, struct iwreq *iwr)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct scanreq req;
    int error = 0;
    ieee80211_scan_params scan_params;
    int time_elapsed = OS_SIWSCAN_TIMEOUT;
    bool scan_pause;
    struct ieee80211_node   *ni = NULL;
    struct ieee80211com *ic = vap->iv_ic;
#if DBDC_REPEATER_SUPPORT
    static int count = 1;
#endif
    bool space_exceeded = 0;

    debug_print_ioctl(dev->name, 0xffff, "getscanresults");

    if (!(dev->flags & IFF_UP)) {
        return -EINVAL;
    }

#if DBDC_REPEATER_SUPPORT
    if (ic->ic_global_list->delay_stavap_connection && !(ic->ic_radio_priority == 1) && count) {
        osifp->os_giwscan_count = 0;
        count--;
        return -EAGAIN;
    }
#endif


    /* Increase timeout value for EIR since a rpt scan itself takes 12 seconds */
    if (ieee80211_ic_enh_ind_rpt_is_set(vap->iv_ic))
        time_elapsed = OS_SIWSCAN_TIMEOUT * SIWSCAN_TIME_ENH_IND_RPT;

    if (osifp->os_opmode != IEEE80211_M_STA ||
        osifp->os_opmode != IEEE80211_M_P2P_DEVICE ||
        osifp->os_opmode != IEEE80211_M_P2P_CLIENT) {
        /* For station mode - umac connection sm always runs SCAN */
        if (wlan_scan_in_progress(vap) &&
		(time_after(osifp->os_last_siwscan + time_elapsed, OS_GET_TICKS())))
        {
            osifp->os_giwscan_count++;
            return -EAGAIN;
        }
    }

    req.vap = vap;
    req.space = 0;
    req.scanreq_type = SCANREQ_GIVE_ALL_SCAN_ENTRIES;
    if (vap->iv_ic->ic_repeater_move.state == REPEATER_MOVE_IN_PROGRESS) {
        wlan_scan_table_iterate(vap, get_scan_space_rep_move, (void *) &req);
    } else {
        wlan_scan_table_iterate(vap, get_scan_space, (void *) &req);
    }

    if (req.space > iwr->u.data.length) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "req space is greater than user buffer length\n");
        space_exceeded = 1;
        req.space = iwr->u.data.length;
    }

    if (req.space > 0) {
        size_t space;
        void *p;

        space = req.space;
        p = (void *)OS_MALLOC(osifp->os_handle, space, GFP_KERNEL);
        if (p == NULL)
            return -ENOMEM;
        req.sr = p;

        if (space_exceeded) {
            req.scanreq_type = SCANREQ_GIVE_ONLY_DESSIRED_SSID;
            wlan_scan_table_iterate(vap, get_scan_result,(void *) &req);
            req.scanreq_type = SCANREQ_GIVE_EXCEPT_DESSIRED_SSID;
            wlan_scan_table_iterate(vap, get_scan_result,(void *) &req);
        } else {
            wlan_scan_table_iterate(vap, get_scan_result,(void *) &req);
        }
        iwr->u.data.length = space - req.space;

        error = _copy_to_user(iwr->u.data.pointer, p, iwr->u.data.length);
        OS_FREE(p);
    } else {
        if (vap->iv_ic->ic_repeater_move.state == REPEATER_MOVE_IN_PROGRESS) {
            vap->iv_ic->ic_repeater_move.state = REPEATER_MOVE_STOP;
        }
        iwr->u.data.length = 0;
    }

#if ATH_SUPPORT_WRAP
    /* Indicate SIOCGIWSCAN directly for VAP's not able to scan */
    if (vap->iv_no_event_handler) {
        osifp->os_giwscan_count = 0;
        return error;
    }
#endif

    /* Increase timeout value for EIR since a rpt scan itself takes 12 seconds */
    if (ieee80211_ic_enh_ind_rpt_is_set(vap->iv_ic))
        time_elapsed = OS_SIWSCAN_TIMEOUT * SIWSCAN_TIME_ENH_IND_RPT;
    scan_pause =  (ieee80211_ic_enh_ind_rpt_is_set(vap->iv_ic)) ?(vap->iv_pause_scan  ) : 0;
    /* start a scan */
    if ((time_after(OS_GET_TICKS(), osifp->os_last_siwscan + time_elapsed)) && (osifp->os_giwscan_count == 0) && (vap->iv_opmode == IEEE80211_M_STA)&& !scan_pause) {
        if (ieee80211_ic_enh_ind_rpt_is_set(vap->iv_ic)) {
            int retv = 0;
            OS_MEMZERO(&scan_params, sizeof(scan_params));
            wlan_set_default_scan_parameters(vap, &scan_params, wlan_vap_get_opmode(vap), true, true, true, true, 0, NULL, 0);
            scan_params.flags |= IEEE80211_SCAN_FORCED;
            scan_params.min_rest_time = MIN_REST_TIME ;
            scan_params.max_rest_time = MAX_REST_TIME ;
            scan_params.min_dwell_time_active = MIN_DWELL_TIME_ACTIVE ;
            scan_params.max_dwell_time_active = MAX_DWELL_TIME_ACTIVE ;
            scan_params.type=IEEE80211_SCAN_BACKGROUND;
            scan_params.init_rest_time = INIT_REST_TIME;

            osifp->os_last_siwscan = OS_GET_TICKS();
            if(vap->iv_bss)
            {
                ni = vap->iv_bss;
            }

            if(ic->ic_use_custom_chan_list !=0 && vap->iv_opmode == IEEE80211_M_STA)
            {
                /*Use ic_custom_chan_list when vap is associated*/
                if(ni && ni->ni_associd >0 && ic->ic_custom_chanlist_assoc_size)

                {
                    scan_params.chan_list = (u_int32_t *)ic->ic_custom_chan_list_associated;
                    scan_params.num_channels = ic->ic_custom_chanlist_assoc_size;
                }
                else
                {
                    if(ic->ic_custom_chanlist_nonassoc_size)
                    {
                        scan_params.chan_list = (u_int32_t *)ic->ic_custom_chan_list_nonassociated;
                        scan_params.num_channels = ic->ic_custom_chanlist_nonassoc_size;
                    }
                }
                /*flush the old scan results*/
                wlan_scan_table_flush(vap);
            }

            retv = wlan_scan_start(vap, &scan_params, osifp->scan_requestor, IEEE80211_SCAN_PRIORITY_LOW, &(osifp->scan_id));
        }
    }

    osifp->os_giwscan_count = 0;

    return error;
}

/**
 * @brief
 *     - Function description:\n
 *     - iwpriv description:\n
 *         - iwpriv cmd: iwpriv athN getmac\n
 *             This commad prints the MAC Address of the VAP.
 *             - iwpriv category: COMMON
 *             - iwpriv arguments: N/A
 *             - iwpriv restart needed? No
 *             - iwpriv default value: N/A
 *             .
 */
static int
ieee80211_ioctl_getmac(struct net_device *dev, struct iwreq *iwr)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    uint8_t *macaddr;

    if (iwr->u.data.length < sizeof(IEEE80211_ADDR_LEN))
    {
        return -EFAULT;
    }

    macaddr = wlan_vap_get_macaddr(vap);

    return (_copy_to_user(iwr->u.data.pointer, macaddr, IEEE80211_ADDR_LEN) ? -EFAULT : 0);
}

#if QCA_AIRTIME_FAIRNESS

static int
ieee80211_ioctl_checkatfset(struct net_device *dev, struct iwreq *iwr)
{
    struct atf_subtype buf;

    if (copy_from_user(&buf, iwr->u.data.pointer, sizeof(struct atf_subtype))) {
	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: copy_from_user error\n", __func__);
	return -ENOMEM;
    }

    return buf.id_type;
}


int
ieee80211_ioctl_setatfssid(struct net_device *dev, struct iwreq *iwr)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    int error = 0;
    struct ssid_val *buf;

    buf = (struct ssid_val *)OS_MALLOC(osifp->os_handle, sizeof(struct ssid_val), GFP_KERNEL);
    if (!buf) {
       QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: memory alloc failed\n", __func__);
       return -ENOMEM;
    }

    if (copy_from_user(buf, iwr->u.data.pointer, sizeof(struct ssid_val))) {
       QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: copy_from_user error\n", __func__);
       kfree(buf);
       return -EFAULT;
    }

    error = ieee80211_ucfg_setatfssid(vap, buf);

    kfree(buf);
    return (error ? -EFAULT : 0);
}

int
ieee80211_ioctl_delatfssid(struct net_device *dev, struct iwreq *iwr)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    int error = 0;
    struct ssid_val *buf;

    buf = (struct ssid_val *)OS_MALLOC(osifp->os_handle, sizeof(struct ssid_val), GFP_KERNEL);
    if (!buf) {
       QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: memory alloc failed\n", __func__);
       return -ENOMEM;
    }
    if (copy_from_user(buf, iwr->u.data.pointer, sizeof(struct ssid_val))) {
       QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: copy_from_user error\n", __func__);
       kfree(buf);
       return -EFAULT;
    }

    error = ieee80211_ucfg_delatfssid(vap, buf);

    kfree(buf);
    return (error ? -EFAULT : 0);
}

int
ieee80211_ioctl_setatfsta(struct net_device *dev, struct iwreq *iwr)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    int error = 0;
    struct sta_val *buf;

    buf = (struct sta_val *)OS_MALLOC(osifp->os_handle, sizeof(struct sta_val), GFP_KERNEL);
    if (!buf) {
       QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: memory alloc failed\n", __func__);
       return -ENOMEM;
    }

    if (copy_from_user(buf, iwr->u.data.pointer, sizeof(struct sta_val))) {
       QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: copy_from_user error\n", __func__);
       kfree(buf);
       return -EFAULT;
    }

    error = ieee80211_ucfg_setatfsta(vap, buf);

    kfree(buf);
    return (error ? -EFAULT : 0);
}

int
ieee80211_ioctl_delatfsta(struct net_device *dev, struct iwreq *iwr)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    int error = 0;
    struct sta_val *buf;

    buf = (struct sta_val *)OS_MALLOC(osifp->os_handle, sizeof(struct sta_val), GFP_KERNEL);
    if (!buf) {
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: memory alloc failed\n", __func__);
        return -ENOMEM;
    }

    if (copy_from_user(buf, iwr->u.data.pointer, sizeof(struct sta_val))) {
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: copy_from_user error\n", __func__);
        kfree(buf);
        return -EFAULT;
    }

    error = ieee80211_ucfg_delatfsta(vap, buf);

    kfree(buf);
    return (error ? -EFAULT : 0);
}

/**
 * @brief function to show the configured groups & associated SSID's
 *
 */
static int ieee80211_atf_grouptable(struct ieee80211com *ic, struct atftable  *buf)
{
#define OTHER_SSID "Others   \0"
    u_int8_t  *sta_mac;
    u_int8_t  i, j, init_flag, k;
    u_int8_t  grp_index[ATF_CFG_NUM_VDEV];
    u_int32_t  leftperuint = (ic->atfcfg_set.percentage_unit == 0)?1000:ic->atfcfg_set.percentage_unit;
    struct     ieee80211_node *ni = NULL;

    if(ic->atfcfg_set.grp_num_cfg)
    {
        OS_MEMSET(grp_index, 0, sizeof(grp_index));
        buf->atf_group = 1;

        for (i = 0, buf->info_cnt = 0, k = 0; i < ic->atfcfg_set.grp_num_cfg; i++)
        {
            for (j = 0, init_flag = 0; j < ATF_ACTIVED_MAX_CLIENTS; j++)
            {
                ni = ieee80211_find_node(&ic->ic_sta, ic->atfcfg_set.peer_id[j].sta_mac);
                if(ni == NULL)
                    continue;

                if((ni != NULL) && ((ni == ni->ni_bss_node) ||
                            (ni->ni_vap->iv_opmode == IEEE80211_M_STA)))
                {
                    ieee80211_free_node(ni);
                    continue;
                } else if (ic->atfcfg_set.peer_id[j].index_group == (i+1)) {
                    if(init_flag == 0)
                    {
                        OS_MEMCPY((char *)(buf->atf_info[buf->info_cnt].grpname),(char *)(ic->atfcfg_set.atfgroup[i].grpname),strlen(ic->atfcfg_set.atfgroup[i].grpname));
                        buf->atf_info[buf->info_cnt].value = ic->atfcfg_set.atfgroup[i].grp_cfg_value;
                        buf->atf_info[buf->info_cnt].cfg_value = ic->atfcfg_set.atfgroup[i].grp_cfg_value;
                        buf->atf_info[buf->info_cnt].info_mark =0;
                        buf->info_cnt++;
                        init_flag++;
                        grp_index[i] = i+1;
                        k += 1;
                    }
                    sta_mac = &(ic->atfcfg_set.peer_id[j].sta_mac[0]);
                    buf->atf_info[buf->info_cnt].value = ic->atfcfg_set.peer_id[j].sta_cal_value;
                    OS_MEMCPY((char *)(buf->atf_info[buf->info_cnt].ssid),(char *)(ni->ni_vap->iv_bss->ni_essid),strlen(ni->ni_vap->iv_bss->ni_essid));
                    /* Assigning peer percentage from  Global value , though we don't use this value if grouping in enabled in ATF */
                    buf->atf_info[buf->info_cnt].cfg_value = ic->atfcfg_set.peer_id[j].sta_cfg_value[ATF_CFG_GLOBAL_INDEX];
                    buf->atf_info[buf->info_cnt].assoc_status = ic->atfcfg_set.peer_id[j].sta_assoc_status;
                    OS_MEMCPY((char *)(buf->atf_info[buf->info_cnt].sta_mac),(char *)sta_mac,IEEE80211_ADDR_LEN);
                    buf->atf_info[buf->info_cnt].info_mark =1;
                    buf->info_cnt++;

                }
                ieee80211_free_node(ni);
            }
            leftperuint -= ic->atfcfg_set.atfgroup[i].grp_cfg_value;
        }
        if( (ic->atfcfg_set.grp_num_cfg != k) && (ni != NULL) )
        {
            for (i = 0; i < ic->atfcfg_set.grp_num_cfg; i++)
            {
                if((ic->atfcfg_set.vap[i].cfg_flag == 1)&&(grp_index[i] == 0))
                {
                    OS_MEMCPY((char *)(buf->atf_info[buf->info_cnt].ssid),(char *)(ni->ni_vap->iv_bss->ni_essid),strlen(ni->ni_vap->iv_bss->ni_essid));
                    buf->atf_info[buf->info_cnt].value = ic->atfcfg_set.vap[i].vap_cfg_value;
                    buf->atf_info[buf->info_cnt].cfg_value = ic->atfcfg_set.vap[i].vap_cfg_value;
                    buf->atf_info[buf->info_cnt].info_mark =0;
                    buf->info_cnt++;
                }
            }
        }
        OS_MEMCPY((char *)(buf->atf_info[buf->info_cnt].grpname),"Others   ",strlen(OTHER_SSID));
        buf->atf_info[buf->info_cnt].value = leftperuint;
        buf->atf_info[buf->info_cnt].cfg_value = 0;
        buf->atf_info[buf->info_cnt].info_mark =0;
        buf->info_cnt++;

        for (j = 0; j < ATF_ACTIVED_MAX_CLIENTS; j++)
        {
            ni = ieee80211_find_node(&ic->ic_sta, ic->atfcfg_set.peer_id[j].sta_mac);
            if(ni == NULL)
                continue;

            if((ni != NULL) && ((ni == ni->ni_bss_node) ||
                        (ni->ni_vap->iv_opmode == IEEE80211_M_STA)))
            {
                ieee80211_free_node(ni);
                continue;
            } else if( ic->atfcfg_set.peer_id[j].index_group == 0xFF) {
                sta_mac = &(ic->atfcfg_set.peer_id[j].sta_mac[0]);
                buf->atf_info[buf->info_cnt].value = ic->atfcfg_set.peer_id[j].sta_cal_value;
                buf->atf_info[buf->info_cnt].cfg_value = ic->atfcfg_set.peer_id[j].sta_cfg_value[ATF_CFG_GLOBAL_INDEX];
                buf->atf_info[buf->info_cnt].assoc_status = ic->atfcfg_set.peer_id[j].sta_assoc_status;
                OS_MEMCPY((char *)(buf->atf_info[buf->info_cnt].sta_mac),(char *)sta_mac,IEEE80211_ADDR_LEN);
                OS_MEMCPY((char *)(buf->atf_info[buf->info_cnt].ssid), ni->ni_vap->iv_bss->ni_essid, strlen(ni->ni_vap->iv_bss->ni_essid));
                buf->atf_info[buf->info_cnt].info_mark =1;
                buf->info_cnt++;
            }
            ieee80211_free_node(ni);
            buf->busy = ic->ic_atf_chbusy;
        }
    }
    return EOK;
}

/**
 * @brief function to show the contents present in the atf table
 *
 */
static int ieee80211_ioctl_showatftable(struct net_device *dev, struct iwreq *iwr)
{
#define OTHER_SSID "Others   \0"
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211com *ic = vap->iv_ic;
    struct atftable  *buf;
    u_int8_t  *sta_mac;
    u_int8_t  i, j, z, init_flag,k;
    u_int8_t  vap_index[ATF_CFG_NUM_VDEV];
    u_int32_t leftperuint = (ic->atfcfg_set.percentage_unit == 0)?1000:ic->atfcfg_set.percentage_unit;
    struct     ieee80211_node *ni = NULL;

    buf = (struct atftable *)OS_MALLOC(osifp->os_handle, sizeof(struct atftable), GFP_KERNEL);
    if (!buf) {
	QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: memory alloc failed\n", __func__);
	return -ENOMEM;
    }

    if (copy_from_user(buf, iwr->u.data.pointer, sizeof(struct atftable))) {
	QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: copy_from_user error\n", __func__);
	kfree(buf);
	return -EFAULT;
    }

    memset(vap_index, 0, ATF_CFG_NUM_VDEV);

    /* Update the atf status from ic struct */
    if(!ic->ic_is_mode_offload(ic)) {
        buf->atf_status = ic->atf_commit;
    } else {
        /* Dynamic enable/disable is not supported in offload arch */
        buf->atf_status = -1;
    }

    if( (ic->atfcfg_set.grp_num_cfg) && (ic->ic_atf_ssidgroup) )
    {
        ieee80211_atf_grouptable(ic, buf);
    } else {
        for (i = 0, buf->info_cnt = 0, k = 0; i < ic->atfcfg_set.vap_num_cfg; i++)
        {
            for (j = 0, init_flag = 0; j < ATF_ACTIVED_MAX_CLIENTS; j++)
            {
                ni = ieee80211_find_node(&ic->ic_sta, ic->atfcfg_set.peer_id[j].sta_mac);
                if((ni != NULL) && ((ni == ni->ni_bss_node) ||
                            (ni->ni_vap->iv_opmode == IEEE80211_M_STA)))
                {
                    ieee80211_free_node(ni);
                    continue;
                } else if (ic->atfcfg_set.peer_id[j].index_vap == (i+1)){
                    if(init_flag == 0)
                    {
                        OS_MEMCPY((char *)(buf->atf_info[buf->info_cnt].ssid),(char *)(ic->atfcfg_set.vap[i].essid),strlen(ic->atfcfg_set.vap[i].essid));
                        buf->atf_info[buf->info_cnt].value = ic->atfcfg_set.vap[i].vap_cfg_value;
                        buf->atf_info[buf->info_cnt].cfg_value = ic->atfcfg_set.vap[i].vap_cfg_value;
                        buf->atf_info[buf->info_cnt].info_mark =0;
                        buf->info_cnt++;
                        init_flag++;
                        vap_index[i] = i+1;
                        k += 1;
                    }
                    sta_mac = &(ic->atfcfg_set.peer_id[j].sta_mac[0]);
                    buf->atf_info[buf->info_cnt].value = ic->atfcfg_set.peer_id[j].sta_cal_value;
                    OS_MEMCPY((char *)(buf->atf_info[buf->info_cnt].ssid),(char *)(ic->atfcfg_set.vap[i].essid),strlen(ic->atfcfg_set.vap[i].essid));
                    buf->atf_info[buf->info_cnt].cfg_value = ic->atfcfg_set.peer_id[j].sta_cfg_value[ic->atfcfg_set.peer_id[j].index_vap];

                    /* show global configuration if we don't have vap specific percentage */
                    if(!(buf->atf_info[buf->info_cnt].cfg_value)){
                        buf->atf_info[buf->info_cnt].cfg_value = ic->atfcfg_set.peer_id[j].sta_cfg_value[ATF_CFG_GLOBAL_INDEX];
                    }
                    /* Showing ATF PER PEER TABEL */
                    if(buf->show_per_peer_table == 1)
                    {
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,"\n::ATF PER PEER[%d]-%s PERCENTAGE TABLE::\n",j,ether_sprintf(sta_mac));
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,"_______________________________________________\n");
                        for( z =0 ;z<=ATF_CFG_NUM_VDEV;z++)
                        {
                            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,"%d ", ic->atfcfg_set.peer_id[j].sta_cfg_value[z]);
                        }
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,"\n______________________________________________________________\n");
                    }
                    buf->atf_info[buf->info_cnt].assoc_status = ic->atfcfg_set.peer_id[j].sta_assoc_status;
                    OS_MEMCPY((char *)(buf->atf_info[buf->info_cnt].sta_mac),(char *)sta_mac,IEEE80211_ADDR_LEN);
                    buf->atf_info[buf->info_cnt].info_mark =1;
                    if ((ni != NULL) && (!ic->ic_is_mode_offload(ic))) {
                        buf->atf_info[buf->info_cnt].all_tokens_used = ieee80211_atf_used_all_tokens(ic, ni);
                    } else {
                        buf->atf_info[buf->info_cnt].all_tokens_used = 0;
                    }

                    buf->info_cnt++;
                }
                ieee80211_free_node(ni);
            }
            leftperuint -= ic->atfcfg_set.vap[i].vap_cfg_value;
        }
        if(ic->atfcfg_set.vap_num_cfg != k)
        {
            for (i = 0; i < ic->atfcfg_set.vap_num_cfg; i++)
            {
                if((ic->atfcfg_set.vap[i].cfg_flag == 1)&&(vap_index[i] == 0))
                {
                    OS_MEMCPY((char *)(buf->atf_info[buf->info_cnt].ssid),(char *)(ic->atfcfg_set.vap[i].essid),strlen(ic->atfcfg_set.vap[i].essid));
                    buf->atf_info[buf->info_cnt].value = ic->atfcfg_set.vap[i].vap_cfg_value;
                    buf->atf_info[buf->info_cnt].cfg_value = ic->atfcfg_set.vap[i].vap_cfg_value;
                    buf->atf_info[buf->info_cnt].info_mark =0;
                    buf->info_cnt++;
                }
            }
        }
        OS_MEMCPY((char *)(buf->atf_info[buf->info_cnt].ssid),"Others   ",strlen(OTHER_SSID));
        buf->atf_info[buf->info_cnt].value = leftperuint;
        buf->atf_info[buf->info_cnt].cfg_value = 0;
        buf->atf_info[buf->info_cnt].info_mark =0;
        buf->info_cnt++;

        for (j = 0; j < ATF_ACTIVED_MAX_CLIENTS; j++)
        {
            ni = ieee80211_find_node(&ic->ic_sta, ic->atfcfg_set.peer_id[j].sta_mac);
            if((ni != NULL) && ((ni == ni->ni_bss_node) ||
                        (ni->ni_vap->iv_opmode == IEEE80211_M_STA)))
            {
                ieee80211_free_node(ni);
                continue;
            } else if( ic->atfcfg_set.peer_id[j].index_vap == 0xff) {
                sta_mac = &(ic->atfcfg_set.peer_id[j].sta_mac[0]);
                buf->atf_info[buf->info_cnt].value = ic->atfcfg_set.peer_id[j].sta_cal_value;
                buf->atf_info[buf->info_cnt].cfg_value = ic->atfcfg_set.peer_id[j].sta_cfg_value[ATF_CFG_GLOBAL_INDEX];
                buf->atf_info[buf->info_cnt].assoc_status = ic->atfcfg_set.peer_id[j].sta_assoc_status;
                OS_MEMCPY((char *)(buf->atf_info[buf->info_cnt].sta_mac),(char *)sta_mac,IEEE80211_ADDR_LEN);
                OS_MEMCPY((char *)(buf->atf_info[buf->info_cnt].ssid),"Others   ",strlen(OTHER_SSID));
                buf->atf_info[buf->info_cnt].info_mark =1;
                if ((ni != NULL) && (!ic->ic_is_mode_offload(ic))) {
                    buf->atf_info[buf->info_cnt].all_tokens_used = ieee80211_atf_used_all_tokens(ic, ni);
                } else {
                    buf->atf_info[buf->info_cnt].all_tokens_used = 0;
                }

                buf->info_cnt++;
            }
            ieee80211_free_node(ni);
            buf->busy = ic->ic_atf_chbusy;
        }
    }
    if (copy_to_user(iwr->u.data.pointer, buf, sizeof(struct atftable))) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: copy_to_user error\n", __func__);
        kfree(buf);
        return -EFAULT;
    }
    kfree(buf);
    return EOK;
#undef OTHER_SSID
}

static int
ieee80211_ioctl_showairtime(struct net_device *dev, struct iwreq *iwr)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211com *ic = vap->iv_ic;
    struct atftable  *buf;
    u_int8_t  *sta_mac;
    u_int8_t  i;

    buf = (struct atftable *)OS_MALLOC(osifp->os_handle, sizeof(struct atftable), GFP_KERNEL);
    if (!buf) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: memory alloc failed\n", __func__);
        return -ENOMEM;
    }

    if (copy_from_user(buf, iwr->u.data.pointer, sizeof(struct atftable))) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: copy_from_user error\n", __func__);
        kfree(buf);
        return -EFAULT;
    }

    for (i = 0, buf->info_cnt = 0; i < ATF_ACTIVED_MAX_CLIENTS; i++)
    {
        if (ic->atfcfg_set.peer_id[i].index_vap !=0)
        {
            sta_mac = &(ic->atfcfg_set.peer_id[i].sta_mac[0]);
            buf->atf_info[buf->info_cnt].value = ic->atfcfg_set.peer_id[i].sta_cal_value;
            buf->atf_info[buf->info_cnt].cfg_value = ic->atfcfg_set.peer_id[i].sta_cfg_value[ic->atfcfg_set.peer_id[i].index_vap];
            buf->atf_info[buf->info_cnt].assoc_status = ic->atfcfg_set.peer_id[i].sta_assoc_status;
            OS_MEMCPY((char *)(buf->atf_info[buf->info_cnt].sta_mac),(char *)sta_mac,IEEE80211_ADDR_LEN);
            buf->atf_info[buf->info_cnt].info_mark =1;
            buf->info_cnt++;
       }
    }
    if (copy_to_user(iwr->u.data.pointer, buf, sizeof(struct atftable))) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: copy_to_user error\n", __func__);
	kfree(buf);
        return -EFAULT;
    }
    kfree(buf);
    return EOK;
}

static int ieee80211_ioctl_flushtable(struct net_device *dev, struct iwreq *iwr)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211com *ic = vap->iv_ic;
    wlan_if_t tmpvap;
    int error = 0;
    int retv = 0;
    struct group_list *tmpgroup = NULL;

    memset(&(ic->atfcfg_set),0,sizeof(ic->atfcfg_set));

    if(!ic->ic_is_mode_offload(ic))
    {
        /* Mark ATF SSID groups for deletion - except the 'default' group */
        TAILQ_FOREACH(tmpgroup, &ic->ic_atfgroups, group_next) {
            if ( !(!(strncmp(tmpgroup->group_name, DEFAULT_GROUPNAME, strlen(DEFAULT_GROUPNAME))) &&
                (strlen(tmpgroup->group_name) == strlen(DEFAULT_GROUPNAME))) )
            {
                tmpgroup->group_del = 1;
            }
        }
    }

    TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
        struct net_device *tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
        if( IS_UP(tmpdev) )
            retv = osif_vap_init(tmpdev, RESCAN);
        if (retv != 0)
            error = -1;
    }
    return (error ? -EFAULT: 0);
}

/**
 * @brief Add a new ATF group
 * If the group is a new one, create a new group & add ssid to the group
 * If the group already exists, add ssid to the group
 */
static int
ieee80211_ioctl_addatfgroup(struct net_device *dev, struct iwreq *iwr)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211com *ic = vap->iv_ic;
    struct atf_group  *buf;
    u_int32_t groupindex = 0, groupssidindex = 0, i = 0, k = 0, error =0;
    u_int8_t addssid = 1, addgroup = 1;
    struct group_list *group = NULL;

    if(!ic->ic_atf_ssidgroup)
    {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "SSID grouping need to be enabled before group configuration \n\r");
        return -EINVAL;
    }
    if ((ic->ic_atf_sched & IEEE80211_ATF_SCHED_STRICT) && (!(ic->ic_atf_sched & IEEE80211_ATF_GROUP_SCHED_POLICY)))
    {
       QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\nStrict queue within groups is enabled and fair queue across groups is enabled. Invalid combination. Cannot addatfgroup \n");
       return -EFAULT;
    }

    buf = (struct atf_group *)OS_MALLOC(osifp->os_handle, sizeof(struct atf_group), GFP_KERNEL);
    if (!buf) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: memory alloc failed\n", __func__);
        return -ENOMEM;
    }

    if (copy_from_user(buf, iwr->u.data.pointer, sizeof(struct atf_group))) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: copy_from_user error\n", __func__);
        kfree(buf);
        return -EFAULT;
    }

    if ( (!(strncmp(buf->name, DEFAULT_GROUPNAME, strlen(DEFAULT_GROUPNAME))) &&
        (strlen(buf->name) == strlen(DEFAULT_GROUPNAME))) )
    {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Group name cannot be %s \n\r",__func__, buf->name);
        return -EINVAL;
    }

    for (i = 0; i < ic->atfcfg_set.grp_num_cfg; i++)
    {
        /* Check if group already exists */
        if( (strlen(ic->atfcfg_set.atfgroup[i].grpname) == strlen(buf->name)) &&
            !(strncmp( (char *)(ic->atfcfg_set.atfgroup[i].grpname), (char *)(buf->name), strlen(buf->name))) ) {
            addgroup = 0;
            groupindex = i;
            /* check if ssid is already part of the group */
            for(k = 0; k < ic->atfcfg_set.atfgroup[i].grp_num_ssid ;k++)
            {
                if ( (strlen(ic->atfcfg_set.atfgroup[i].grp_ssid[k]) == strlen(buf->ssid)) &&
                     !(strncmp( (char *)(ic->atfcfg_set.atfgroup[i].grp_ssid[k]), (char *)(buf->ssid), strlen(buf->ssid))) )
                {
                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "SSID (%s) already part of the group, %s \n\r", buf->ssid, buf->name);
                    addssid = 0;
                    error = 1;
                    break;
                }
            }
            break;
        }
    }

    /* Check if this SSID is already a part of some other group.
       The same SSID cannot be part of multiple groups.
     */
    if(addgroup || addssid)
    {
        /* Loop through each group */
        for(i=0; i < ic->atfcfg_set.grp_num_cfg; i++)
        {
            /* Loop through each ssid in the group */
            for(k=0; k < ic->atfcfg_set.atfgroup[i].grp_num_ssid; k++)
            {
                if( (strlen(ic->atfcfg_set.atfgroup[i].grp_ssid[k]) == strlen(buf->ssid)) &&
                    !(strncmp( (char *)(ic->atfcfg_set.atfgroup[i].grp_ssid[k]), (char *)(buf->ssid), strlen(buf->ssid))) )
                {
                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s already part of %s group - Same ssid cannot be part of Multiple groups\n\r",
                            buf->ssid, ic->atfcfg_set.atfgroup[i].grpname);
                    addgroup = 0;
                    addssid = 0;
                    error = 1;
                    break;
                }
            }
        }
    }

    /* Create New Group & Increment number of groups*/
    if(addgroup)
    {
        if(ic->atfcfg_set.grp_num_cfg >= ATF_ACTIVED_MAX_ATFGROUPS)
        {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Error!Cannot configure more than %d groups\n\r", ATF_ACTIVED_MAX_ATFGROUPS);
            kfree(buf);
            return -EINVAL;
        }
        groupindex = ic->atfcfg_set.grp_num_cfg;
        strlcpy(ic->atfcfg_set.atfgroup[groupindex].grpname, (char *)(buf->name), sizeof(ic->atfcfg_set.atfgroup[groupindex].grpname));
        ic->atfcfg_set.grp_num_cfg++;

        if(!ic->ic_is_mode_offload(ic))
        {
            /* Create a new entry in the group list */
            group = (struct group_list *)OS_MALLOC(ic->ic_osdev, sizeof(struct group_list), GFP_KERNEL);
            strlcpy(group->group_name, (char *)(buf->name), sizeof(group->group_name));
            group->atf_num_clients_borrow = 0;
            group->atf_num_clients = 0;
            group->atf_contributabletokens = 0;
            group->shadow_atf_contributabletokens = 0;
            group->group_del = 0;
            TAILQ_INSERT_TAIL(&ic->ic_atfgroups, group, group_next);

            /* Add reference to group list entry in config group struct */
            ic->atfcfg_set.atfgroup[groupindex].grplist_entry = group;
        }

    }

    /* add new ssid to the group & increment number of ssids in the group */
    if(addssid)
    {
        if(ic->atfcfg_set.atfgroup[groupindex].grp_num_ssid >= ATF_CFG_NUM_VDEV)
        {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Error!Cannot configure more than %d SSIDs in the group\n\r",CFG_NUM_VDEV);
            kfree(buf);
            return -EINVAL;
        }
        groupssidindex = ic->atfcfg_set.atfgroup[groupindex].grp_num_ssid;
        strlcpy(ic->atfcfg_set.atfgroup[groupindex].grp_ssid[groupssidindex], (char *)(buf->ssid) ,IEEE80211_NWID_LEN+1);
        ic->atfcfg_set.atfgroup[groupindex].grp_num_ssid++;
    }

    if (copy_to_user(iwr->u.data.pointer, buf, sizeof(struct atf_group))) {
	QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: copy_to_user error\n", __func__);
	error =  -EFAULT;
    }

    kfree(buf);

    return (error ? -EFAULT : 0);
}

/**
 * @brief Config Airtime for an ATF group
 * If group exisits, configure Airtime
 * Return error if group doesn't exist.
 */
static int
ieee80211_ioctl_configatfgroup(struct net_device *dev, struct iwreq *iwr)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211com *ic = vap->iv_ic;
    struct atf_group  *buf;
    u_int32_t i = 0, error =0, airtime_group = 0;
    u_int32_t  availableairtime = (ic->atfcfg_set.percentage_unit == 0)? 1000: ic->atfcfg_set.percentage_unit;
    struct group_list *group = NULL;

    if(!ic->ic_atf_ssidgroup)
    {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "SSID grouping need to be enabled before group configuration \n\r");
        return -EINVAL;
    }

   /* Find the Total Airtime configured (for all groups) */
    for(i=0; i < ic->atfcfg_set.grp_num_cfg; i++)
        airtime_group += ic->atfcfg_set.atfgroup[i].grp_cfg_value;

    buf = (struct atf_group *)OS_MALLOC(osifp->os_handle, sizeof(struct atf_group), GFP_KERNEL);
    if (!buf) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: memory alloc failed\n", __func__);
        return -ENOMEM;
    }

    if (copy_from_user(buf, iwr->u.data.pointer, sizeof(struct atf_group))) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: copy_from_user error\n", __func__);
        kfree(buf);
        return -EFAULT;
    }

    if ( (!(strncmp(buf->name, DEFAULT_GROUPNAME, strlen(DEFAULT_GROUPNAME))) &&
        (strlen(buf->name) == strlen(DEFAULT_GROUPNAME))) )
    {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Group '%s' cannot be configured \n\r",__func__, buf->name);
        return -EINVAL;
    }

    for (i = 0; i < ic->atfcfg_set.grp_num_cfg; i++)
    {
        /* Check if group exists */
        if( (strlen(ic->atfcfg_set.atfgroup[i].grpname) == strlen(buf->name)) &&
            !(strncmp( (char *)(ic->atfcfg_set.atfgroup[i].grpname), (char *)(buf->name), strlen(buf->name))) ) {
            if( (airtime_group -  ic->atfcfg_set.atfgroup[i].grp_cfg_value + buf->value) <= availableairtime )
            {
                ic->atfcfg_set.atfgroup[i].grp_cfg_value = buf->value;
                if(!ic->ic_is_mode_offload(ic))
                {
                    /* Add group airtime in the group list */
                    group = ic->atfcfg_set.atfgroup[i].grplist_entry;
                    if(group != NULL) {
                        group->group_airtime = buf->value;
                    }
                }
            } else {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Error!! Total Airtime configured for groups cannot be greater than %d \n\r", availableairtime/10);
                error = 1;
            }
            break;
        }
    }

    if( i == ic->atfcfg_set.grp_num_cfg )
    {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Error!! Invalid group name\n\r");
        error = 1;
    }

    kfree(buf);
    return (error ? -EFAULT : 0);
}

/**
 * @brief Delete ATF group
 * If group exisits, delete the group
 * Return error if group doesn't exist.
 */
static int
ieee80211_ioctl_delatfgroup(struct net_device *dev, struct iwreq *iwr)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211com *ic = vap->iv_ic;
    struct atf_group  *buf;
    u_int32_t i = 0, error = 0, delgroup = 0;
    struct group_list *tmpgroup = NULL;

    if(!ic->ic_atf_ssidgroup)
    {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "SSID grouping need to be enabled before group configuration \n\r");
        return -EINVAL;
    }

    buf = (struct atf_group *)OS_MALLOC(osifp->os_handle, sizeof(struct atf_group), GFP_KERNEL);
    if (!buf) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: memory alloc failed\n", __func__);
        return -ENOMEM;
    }

    if (copy_from_user(buf, iwr->u.data.pointer, sizeof(struct atf_group))) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: copy_from_user error\n", __func__);
        kfree(buf);
        return -EFAULT;
    }

    if ( (!(strncmp(buf->name, DEFAULT_GROUPNAME, strlen(DEFAULT_GROUPNAME))) &&
        (strlen(buf->name) == strlen(DEFAULT_GROUPNAME))) )
    {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Group '%s' cannot be deleted\n\r",__func__, buf->name);
        return -EINVAL;
    }

    for (i = 0; i < ic->atfcfg_set.grp_num_cfg; i++)
    {
        /* Check if group exists */
        if( (strlen(ic->atfcfg_set.atfgroup[i].grpname) == strlen(buf->name)) &&
            !(strncmp( (char *)(ic->atfcfg_set.atfgroup[i].grpname), (char *)(buf->name), strlen(buf->name))) ) {
            delgroup = 1;

            /* Clear Elements at this index */
            memset(&(ic->atfcfg_set.atfgroup[i]), 0, sizeof(ic->atfcfg_set.atfgroup[0]));

            /* Copy the 'i+1' the element to 'i'th position & clear the last element*/
            if(i != (ic->atfcfg_set.grp_num_cfg - 1))
            {
                memcpy(&ic->atfcfg_set.atfgroup[i], &ic->atfcfg_set.atfgroup[i+1],
                        (sizeof(ic->atfcfg_set.atfgroup[0]) * (ic->atfcfg_set.grp_num_cfg - i - 1)) );
            }

            /* Clear Last Element */
            memset(&(ic->atfcfg_set.atfgroup[ic->atfcfg_set.grp_num_cfg - 1]), 0, sizeof(ic->atfcfg_set.atfgroup[0]));
            ic->atfcfg_set.grp_num_cfg--;

            if(!ic->ic_is_mode_offload(ic))
            {
                /* Parse the group list and mark for deletion
                   The group entry will be removed from the list in cal_atf_alloc_tbl routine*/
                TAILQ_FOREACH(tmpgroup, &ic->ic_atfgroups, group_next) {
                    if ((strlen(tmpgroup->group_name) == strlen(buf->name)) &&
                        !(strncmp ( tmpgroup->group_name, (char *)(buf->name), strlen(buf->name))) ) {
                        tmpgroup->group_del = 1;
                    }
                }
            }
            break;
        }
    }

    if( !delgroup )
    {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Error!! Invalid group name. \n\r");
        error = 1;
    }

    kfree(buf);
    return (error ? -EFAULT : 0);
}

/**
 * @brief Shows ATF groups configured
 * Configured groups and corresponding SSID's will be listed
 *
 */
static int
ieee80211_ioctl_showatfgroup(struct net_device *dev, struct iwreq *iwr)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211com *ic = vap->iv_ic;
    struct atfgrouptable  *buf;
    u_int32_t i = 0, k = 0, error =0;

    if(!ic->ic_atf_ssidgroup)
    {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "SSID grouping need be enabled for this command to work \n\r");
        return -EINVAL;
    }

    if(!ic->atfcfg_set.grp_num_cfg)
    {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "No groups configured \n\r");
        return -EINVAL;
    }

    buf = (struct atfgrouptable *)OS_MALLOC(osifp->os_handle, sizeof(struct atfgrouptable), GFP_KERNEL);
    if (!buf) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: memory alloc failed\n", __func__);
        return -ENOMEM;
    }

    if (copy_from_user(buf, iwr->u.data.pointer, sizeof(struct atfgrouptable))) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: copy_from_user error\n", __func__);
        kfree(buf);
        return -EFAULT;
    }

    for (i = 0; i < ic->atfcfg_set.grp_num_cfg; i++)
    {
        OS_MEMCPY((char *)(buf->atf_groups[buf->info_cnt].grpname),(char *)ic->atfcfg_set.atfgroup[i].grpname,  IEEE80211_NWID_LEN);
        buf->atf_groups[buf->info_cnt].grp_num_ssid = ic->atfcfg_set.atfgroup[i].grp_num_ssid;
        buf->atf_groups[buf->info_cnt].grp_cfg_value = ic->atfcfg_set.atfgroup[i].grp_cfg_value;
        for (k = 0; k < ic->atfcfg_set.atfgroup[i].grp_num_ssid; k++)
        {
            OS_MEMCPY((char *)(buf->atf_groups[buf->info_cnt].grp_ssid[k]), (char *)(ic->atfcfg_set.atfgroup[i].grp_ssid[k]), IEEE80211_NWID_LEN);
        }
        buf->info_cnt++;
    }

    if(copy_to_user(iwr->u.data.pointer, buf, sizeof(struct atfgrouptable)))
    {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: copy_to_user failed\n",__func__);
        error =  -EFAULT;
    }
    kfree(buf);
    return (error ? -EFAULT : 0);
}

#endif

static int
ieee80211_ioctl_getstainfo(struct net_device *dev, struct iwreq *iwr)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    int error = 0, status = 0;
    uint32_t data_length = 0;
    void *p;

    data_length = iwr->u.data.length;
    data_length = ieee80211_ucfg_getstaspace(vap);
    if (data_length == 0)
        return -EPERM;

    if ((data_length > iwr->u.data.length) && (iwr->u.data.flags == 0)) {
        return data_length;
    }

    p = (void *)OS_MALLOC(osifp->os_handle, data_length, GFP_KERNEL);
    if (p == NULL)
        return -ENOMEM;

    status = ieee80211_ucfg_getstainfo(vap, p, &data_length);

    if (data_length > 0) {
        iwr->u.data.length = data_length;
        error = _copy_to_user(iwr->u.data.pointer, p, data_length);
        status = error ? -EFAULT : 0;
    } else {
        iwr->u.data.length = 0;
    }


    OS_FREE(p);

    return status;
}

#if UMAC_SUPPORT_ACFG
int ieee80211_set_vap_vendor_param(struct net_device *dev, void *data)
{
    int status = 0, req_len;
    osif_dev  *osifp = ath_netdev_priv(dev);
    acfg_vendor_param_req_t *req = NULL;

    req_len = sizeof(acfg_vendor_param_req_t);
    req = OS_MALLOC(osifp->os_handle, req_len, GFP_KERNEL);
    if(!req)
        return ENOMEM;

    if(copy_from_user(req, data, req_len))
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "copy_from_user error\n");
        status = -1;
        goto done;
    }
    status = osif_set_vap_vendor_param(dev, req);

done:
    kfree(req);
    return status;
}

int ieee80211_get_vap_vendor_param(struct net_device *dev, void *data)
{
    int status = 0, req_len;
    osif_dev  *osifp = ath_netdev_priv(dev);
    acfg_vendor_param_req_t *req = NULL;

    req_len = sizeof(acfg_vendor_param_req_t);
    req = OS_MALLOC(osifp->os_handle, req_len, GFP_KERNEL);
    if(!req)
        return ENOMEM;

    if(copy_from_user(req, data, req_len))
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "copy_from_user error\n");
        status = -1;
        goto done;
    }
    status = osif_get_vap_vendor_param(dev, req);

    if(copy_to_user(data, req, req_len))
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "copy_to_user error\n");
        status = -1;
    }
done:
    kfree(req);
    return status;
}
#endif //UMAC_SUPPORT_ACFG

/**
 * @brief
 *     - Function description:\n
 *     - iwpriv description:\n
 *         - iwpriv cmd: iwpriv athN doth_chanswitch channel tbtt\n
 *           This command will force the AP to perform a channel change,
 *           and will force a channel change announcement message to be
 *           sent.  This is used for testing the 802.11h channel switch
 *           mechanism.  The channel value indicates the channel to switch
 *           to, and the tbtt value indicates the number of beacons to
 *           wait before doing the switch.  This command does not have
 *           a corresponding get command; it is an action rather than a
 *           setting.
 *             - iwpriv category: N/A
 *             - iwpriv arguments:
 *             - iwpriv restart needed? Not sure
 *             - iwpriv default value: Not sure
 *             .
 */
int
ieee80211_ioctl_chanswitch(struct net_device *dev, struct iw_request_info *info,
    void *w, char *extra)
{
    wlan_if_t vap = NETDEV_TO_VAP(dev);
    int *param = (int *) extra;

    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Enabling Channel Switch Announcement on current channel\n");
    return (ieee80211_ucfg_set_chanswitch(vap, param[0], param[1], 0));
}

int
 ieee80211_ioctl_chn_n_widthswitch(struct net_device *dev, struct iw_request_info *info,
    void *w, char *extra)
{
    wlan_if_t vap = NETDEV_TO_VAP(dev);
    int *param = (int *) extra;

    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Enabling Channel and channel width Switch Announcement on current channel\n");
    return (ieee80211_ucfg_set_chanswitch(vap, param[0], param[1], param[2]));

}
static int
ieee80211_ioctl_get_scan_space(struct net_device *dev, struct iwreq *iw)
{
    osif_dev  *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct scanreq req;

    debug_print_ioctl(dev->name, 0xffff, "getscanspace") ;
    req.space = 0;
    wlan_scan_table_iterate(vap, get_scan_space, (void *) &req);

    iw->u.data.length = req.space;
    return 0;
}


#if WIRELESS_EXT >= 18
static int
ieee80211_ioctl_siwmlme(struct net_device *dev,
    struct iw_request_info *info, struct iw_point *erq, char *data)
{
    struct ieee80211req_mlme mlme;
    struct iw_mlme *wextmlme = (struct iw_mlme *)data;

    debug_print_ioctl(dev->name, SIOCSIWMLME, "siwmlme") ;
    memset(&mlme, 0, sizeof(mlme));

    switch(wextmlme->cmd) {
    case IW_MLME_DEAUTH:
        mlme.im_op = IEEE80211_MLME_DEAUTH;
        break;
    case IW_MLME_DISASSOC:
        mlme.im_op = IEEE80211_MLME_DISASSOC;
        break;
    default:
        return -EINVAL;
    }

    mlme.im_reason = wextmlme->reason_code;

    memcpy(mlme.im_macaddr, wextmlme->addr.sa_data, IEEE80211_ADDR_LEN);

    return ieee80211_ioctl_setmlme(dev, NULL, NULL, (char*)&mlme);
}

static int
ieee80211_ioctl_giwgenie(struct net_device *dev,
    struct iw_request_info *info, struct iw_point *out, char *buf)
{
//fixme this is a layering violation, directly accessing data
#if 0
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t nvap = osifp->os_if;
    struct ieee80211vap *vap = (void *) nvap;
    /* compile error to be fixed later */
    if (out->length < vap->iv_opt_ie_len)
        return -E2BIG;
#endif
    return ieee80211_ioctl_getoptie(dev, info, out, buf);
}

static int
ieee80211_ioctl_siwgenie(struct net_device *dev,
    struct iw_request_info *info, struct iw_point *erq, char *data)
{
    return ieee80211_ioctl_setoptie(dev, info, erq, data);
}


static int
siwauth_wapi_enable(struct net_device *dev,
    struct iw_request_info *info, struct iw_param *erq, char *buf)
{
    int value = erq->value;
    int args[2];

    args[0] = IEEE80211_PARAM_SETWAPI;
    args[1] = value;

    return ieee80211_ioctl_setparam(dev, NULL, NULL, (char*)args);
}

static int
siwauth_wpa_version(struct net_device *dev,
    struct iw_request_info *info, struct iw_param *erq, char *buf)
{
    int ver = erq->value;
    int args[2];

    args[0] = IEEE80211_PARAM_WPA;

    if ((ver & IW_AUTH_WPA_VERSION_WPA) && (ver & IW_AUTH_WPA_VERSION_WPA2))
        args[1] = 3;
    else if (ver & IW_AUTH_WPA_VERSION_WPA2)
        args[1] = 2;
    else if (ver & IW_AUTH_WPA_VERSION_WPA)
        args[1] = 1;
    else
        args[1] = 0;

    return ieee80211_ioctl_setparam(dev, NULL, NULL, (char*)args);
}

static int
iwcipher2ieee80211cipher(int iwciph)
{
#if ATH_SUPPORT_WAPI
#define IW_AUTH_CIPHER_SMS4 0x00000020
#endif
    switch(iwciph) {
    case IW_AUTH_CIPHER_NONE:
        return IEEE80211_CIPHER_NONE;
    case IW_AUTH_CIPHER_WEP40:
    case IW_AUTH_CIPHER_WEP104:
        return IEEE80211_CIPHER_WEP;
    case IW_AUTH_CIPHER_TKIP:
        return IEEE80211_CIPHER_TKIP;
    case IW_AUTH_CIPHER_CCMP:
        return IEEE80211_CIPHER_AES_CCM;
#if ATH_SUPPORT_WAPI
    case IW_AUTH_CIPHER_SMS4:
        return IEEE80211_CIPHER_WAPI;
#endif
    }
    return -1;
}

static int
ieee80211cipher2iwcipher(int ieee80211ciph)
{
#if ATH_SUPPORT_WAPI
#define IW_AUTH_CIPHER_SMS4 0x00000020
#endif
    switch(ieee80211ciph) {
    case IEEE80211_CIPHER_NONE:
        return IW_AUTH_CIPHER_NONE;
    case IEEE80211_CIPHER_WEP:
        return IW_AUTH_CIPHER_WEP104;
    case IEEE80211_CIPHER_TKIP:
        return IW_AUTH_CIPHER_TKIP;
    case IEEE80211_CIPHER_AES_CCM:
        return IW_AUTH_CIPHER_CCMP;
#if ATH_SUPPORT_WAPI
    case IEEE80211_CIPHER_WAPI:
        return IW_AUTH_CIPHER_SMS4;
#endif

    }
    return -1;
}

/* TODO We don't enforce wep key lengths. */
static int
siwauth_cipher_pairwise(struct net_device *dev,
    struct iw_request_info *info, struct iw_param *erq, char *buf)
{
    int iwciph = erq->value;
    unsigned int args[2];

    args[0] = IEEE80211_PARAM_UCASTCIPHER;
    args[1] = iwcipher2ieee80211cipher(iwciph);
    if (args[1] < 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_WARNING "%s: unknown pairwise cipher %d\n",
                dev->name, iwciph);
        return -EINVAL;
    }
    return ieee80211_ioctl_setparam(dev, NULL, NULL, (char*)args);
}

/* TODO We don't enforce wep key lengths. */
static int
siwauth_cipher_group(struct net_device *dev,
    struct iw_request_info *info, struct iw_param *erq, char *buf)
{
    int iwciph = erq->value;
    unsigned int args[2];

    args[0] = IEEE80211_PARAM_MCASTCIPHER;
    args[1] = iwcipher2ieee80211cipher(iwciph);
    if (args[1] < 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_WARNING "%s: unknown group cipher %d\n",
                dev->name, iwciph);
        return -EINVAL;
    }
    return ieee80211_ioctl_setparam(dev, NULL, NULL, (char*)args);
}

static int
siwauth_key_mgmt(struct net_device *dev,
    struct iw_request_info *info, struct iw_param *erq, char *buf)
{
    int iwkm = erq->value;
    int args[2];

    args[0] = IEEE80211_PARAM_KEYMGTALGS;
    args[1] = WPA_ASE_NONE;
    if (iwkm & IW_AUTH_KEY_MGMT_802_1X)
        args[1] |= WPA_ASE_8021X_UNSPEC;
    if (iwkm & IW_AUTH_KEY_MGMT_PSK)
        args[1] |= WPA_ASE_8021X_PSK;

    return ieee80211_ioctl_setparam(dev, NULL, NULL, (char*)args);
}

static int
siwauth_tkip_countermeasures(struct net_device *dev,
    struct iw_request_info *info, struct iw_param *erq, char *buf)
{
    int args[2];
    args[0] = IEEE80211_PARAM_COUNTERMEASURES;
    args[1] = erq->value;
    return ieee80211_ioctl_setparam(dev, NULL, NULL, (char*)args);
}

static int
siwauth_drop_unencrypted(struct net_device *dev,
    struct iw_request_info *info, struct iw_param *erq, char *buf)
{
    int args[2];
    args[0] = IEEE80211_PARAM_DROPUNENCRYPTED;
    args[1] = erq->value;
    return ieee80211_ioctl_setparam(dev, NULL, NULL, (char*)args);
}


static int
siwauth_80211_auth_alg(struct net_device *dev,
    struct iw_request_info *info, struct iw_param *erq, char *buf)
{
#define VALID_ALGS_MASK (IW_AUTH_ALG_OPEN_SYSTEM|IW_AUTH_ALG_SHARED_KEY|IW_AUTH_ALG_LEAP)
    int mode = erq->value;
    int args[2];

    args[0] = IEEE80211_PARAM_AUTHMODE;

    if (mode & ~VALID_ALGS_MASK) {
        return -EINVAL;
    }
    if (mode & IW_AUTH_ALG_LEAP) {
        args[1] = IEEE80211_AUTH_8021X;
    } else if ((mode & IW_AUTH_ALG_SHARED_KEY) &&
        (mode & IW_AUTH_ALG_OPEN_SYSTEM)) {
        args[1] = IEEE80211_AUTH_AUTO;
    } else if (mode & IW_AUTH_ALG_SHARED_KEY) {
        args[1] = IEEE80211_AUTH_SHARED;
    } else {
        args[1] = IEEE80211_AUTH_OPEN;
    }
    return ieee80211_ioctl_setparam(dev, NULL, NULL, (char*)args);
}

static int
siwauth_wpa_enabled(struct net_device *dev,
    struct iw_request_info *info, struct iw_param *erq, char *buf)
{
    int enabled = erq->value;
    int args[2];

    args[0] = IEEE80211_PARAM_WPA;
    if (enabled)
        args[1] = 3; /* enable WPA1 and WPA2 */
    else
        args[1] = 0; /* disable WPA1 and WPA2 */

    return ieee80211_ioctl_setparam(dev, NULL, NULL, (char*)args);
}

static int
siwauth_rx_unencrypted_eapol(struct net_device *dev,
    struct iw_request_info *info, struct iw_param *erq, char *buf)
{
    int rxunenc = erq->value;
    int args[2];

    args[0] = IEEE80211_PARAM_DROPUNENC_EAPOL;
    if (rxunenc)
        args[1] = 1;
    else
        args[1] = 0;

    return ieee80211_ioctl_setparam(dev, NULL, NULL, (char*)args);
}

static int
siwauth_roaming_control(struct net_device *dev,
    struct iw_request_info *info, struct iw_param *erq, char *buf)
{
    int roam = erq->value;
    int args[2];

    args[0] = IEEE80211_PARAM_ROAMING;
    switch(roam) {
    case IW_AUTH_ROAMING_ENABLE:
        args[1] = IEEE80211_ROAMING_AUTO;
        break;
    case IW_AUTH_ROAMING_DISABLE:
        args[1] = IEEE80211_ROAMING_MANUAL;
        break;
    default:
        return -EINVAL;
    }
    return ieee80211_ioctl_setparam(dev, NULL, NULL, (char*)args);
}

static int
siwauth_privacy_invoked(struct net_device *dev,
    struct iw_request_info *info, struct iw_param *erq, char *buf)
{
    int args[2];
    args[0] = IEEE80211_PARAM_PRIVACY;
    args[1] = erq->value;
    return ieee80211_ioctl_setparam(dev, NULL, NULL, (char*)args);
}

/*
* If this function is invoked it means someone is using the wireless extensions
* API instead of the private madwifi ioctls.  That's fine.  We translate their
* request into the format used by the private ioctls.  Note that the
* iw_request_info and iw_param structures are not the same ones as the
* private ioctl handler expects.  Luckily, the private ioctl handler doesn't
* do anything with those at the moment.  We pass NULL for those, because in
* case someone does modify the ioctl handler to use those values, a null
* pointer will be easier to debug than other bad behavior.
*/
static int
ieee80211_ioctl_siwauth(struct net_device *dev,
    struct iw_request_info *info, struct iw_param *erq, char *buf)
{
    int rc = -EINVAL;
#if ATH_SUPPORT_WAPI
#define IW_AUTH_WAPI_ENABLED 0x20
#endif
    switch(erq->flags & IW_AUTH_INDEX) {
#if ATH_SUPPORT_WAPI
    case IW_AUTH_WAPI_ENABLED:
        rc = siwauth_wapi_enable(dev, info, erq, buf);
        break;
#endif
    case IW_AUTH_WPA_VERSION:
        rc = siwauth_wpa_version(dev, info, erq, buf);
        break;
    case IW_AUTH_CIPHER_PAIRWISE:
        rc = siwauth_cipher_pairwise(dev, info, erq, buf);
        break;
    case IW_AUTH_CIPHER_GROUP:
        rc = siwauth_cipher_group(dev, info, erq, buf);
        break;
    case IW_AUTH_KEY_MGMT:
        rc = siwauth_key_mgmt(dev, info, erq, buf);
        break;
    case IW_AUTH_TKIP_COUNTERMEASURES:
        rc = siwauth_tkip_countermeasures(dev, info, erq, buf);
        break;
    case IW_AUTH_DROP_UNENCRYPTED:
        rc = siwauth_drop_unencrypted(dev, info, erq, buf);
        break;
    case IW_AUTH_80211_AUTH_ALG:
        rc = siwauth_80211_auth_alg(dev, info, erq, buf);
        break;
    case IW_AUTH_WPA_ENABLED:
        rc = siwauth_wpa_enabled(dev, info, erq, buf);
        break;
    case IW_AUTH_RX_UNENCRYPTED_EAPOL:
        rc = siwauth_rx_unencrypted_eapol(dev, info, erq, buf);
        break;
    case IW_AUTH_ROAMING_CONTROL:
        rc = siwauth_roaming_control(dev, info, erq, buf);
        break;
    case IW_AUTH_PRIVACY_INVOKED:
        rc = siwauth_privacy_invoked(dev, info, erq, buf);
        break;
    default:
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_WARNING "%s: unknown SIOCSIWAUTH flag %d\n",
            dev->name, erq->flags);
        break;
    }

    return rc;
}

static int
giwauth_wpa_version(struct net_device *dev,
    struct iw_request_info *info, struct iw_param *erq, char *buf)
{
    int ver;
    int rc;
    int arg = IEEE80211_PARAM_WPA;

    rc = ieee80211_ioctl_getparam(dev, NULL, NULL, (char*)&arg);
    if (rc)
        return rc;

    switch(arg) {
    case 1:
            ver = IW_AUTH_WPA_VERSION_WPA;
        break;
    case 2:
            ver = IW_AUTH_WPA_VERSION_WPA2;
        break;
    case 3:
            ver = IW_AUTH_WPA_VERSION|IW_AUTH_WPA_VERSION_WPA2;
        break;
    default:
        ver = IW_AUTH_WPA_VERSION_DISABLED;
        break;
    }

    erq->value = ver;
    return rc;
}

static int
giwauth_cipher_pairwise(struct net_device *dev,
    struct iw_request_info *info, struct iw_param *erq, char *buf)
{
    int rc;
    int arg = IEEE80211_PARAM_UCASTCIPHER;

    rc = ieee80211_ioctl_getparam(dev, NULL, NULL, (char*)&arg);
    if (rc)
        return rc;

    erq->value = ieee80211cipher2iwcipher(arg);
    if (erq->value < 0)
        return -EINVAL;
    return 0;
}


static int
giwauth_cipher_group(struct net_device *dev,
    struct iw_request_info *info, struct iw_param *erq, char *buf)
{
    int rc;
    int arg = IEEE80211_PARAM_MCASTCIPHER;

    rc = ieee80211_ioctl_getparam(dev, NULL, NULL, (char*)&arg);
    if (rc)
        return rc;

    erq->value = ieee80211cipher2iwcipher(arg);
    if (erq->value < 0)
        return -EINVAL;
    return 0;
}

static int
giwauth_key_mgmt(struct net_device *dev,
    struct iw_request_info *info, struct iw_param *erq, char *buf)
{
    int arg;
    int rc;

    arg = IEEE80211_PARAM_KEYMGTALGS;
    rc = ieee80211_ioctl_getparam(dev, NULL, NULL, (char*)&arg);
    if (rc)
        return rc;
    erq->value = 0;
    if (arg & WPA_ASE_8021X_UNSPEC)
        erq->value |= IW_AUTH_KEY_MGMT_802_1X;
    if (arg & WPA_ASE_8021X_PSK)
        erq->value |= IW_AUTH_KEY_MGMT_PSK;
    return 0;
}

static int
giwauth_tkip_countermeasures(struct net_device *dev,
    struct iw_request_info *info, struct iw_param *erq, char *buf)
{
    int arg;
    int rc;

    arg = IEEE80211_PARAM_COUNTERMEASURES;
    rc = ieee80211_ioctl_getparam(dev, NULL, NULL, (char*)&arg);
    if (rc)
        return rc;
    erq->value = arg;
    return 0;
}

static int
giwauth_drop_unencrypted(struct net_device *dev,
    struct iw_request_info *info, struct iw_param *erq, char *buf)
{
    int arg;
    int rc;
    arg = IEEE80211_PARAM_DROPUNENCRYPTED;
    rc = ieee80211_ioctl_getparam(dev, NULL, NULL, (char*)&arg);
    if (rc)
        return rc;
    erq->value = arg;
    return 0;
}

static int
giwauth_80211_auth_alg(struct net_device *dev,
    struct iw_request_info *info, struct iw_param *erq, char *buf)
{
    return -EOPNOTSUPP;
}

static int
giwauth_wpa_enabled(struct net_device *dev,
    struct iw_request_info *info, struct iw_param *erq, char *buf)
{
    int rc;
    int arg = IEEE80211_PARAM_WPA;

    rc = ieee80211_ioctl_getparam(dev, NULL, NULL, (char*)&arg);
    if (rc)
        return rc;

    erq->value = arg;
    return 0;

}

static int
giwauth_rx_unencrypted_eapol(struct net_device *dev,
    struct iw_request_info *info, struct iw_param *erq, char *buf)
{
    return -EOPNOTSUPP;
}

static int
giwauth_roaming_control(struct net_device *dev,
    struct iw_request_info *info, struct iw_param *erq, char *buf)
{
    int rc;
    int arg;

    arg = IEEE80211_PARAM_ROAMING;
    rc = ieee80211_ioctl_getparam(dev, NULL, NULL, (char*)&arg);
    if (rc)
        return rc;

    switch(arg) {
    case IEEE80211_ROAMING_DEVICE:
    case IEEE80211_ROAMING_AUTO:
        erq->value = IW_AUTH_ROAMING_ENABLE;
        break;
    default:
        erq->value = IW_AUTH_ROAMING_DISABLE;
        break;
    }

    return 0;
}

static int
giwauth_privacy_invoked(struct net_device *dev,
    struct iw_request_info *info, struct iw_param *erq, char *buf)
{
    int rc;
    int arg;
    arg = IEEE80211_PARAM_PRIVACY;
    rc = ieee80211_ioctl_getparam(dev, NULL, NULL, (char*)&arg);
    if (rc)
        return rc;
    erq->value = arg;
    return 0;
}

static int
ieee80211_ioctl_giwauth(struct net_device *dev,
    struct iw_request_info *info, struct iw_param *erq, char *buf)
{
    int rc = -EOPNOTSUPP;

    switch(erq->flags & IW_AUTH_INDEX) {
    case IW_AUTH_WPA_VERSION:
        rc = giwauth_wpa_version(dev, info, erq, buf);
        break;
    case IW_AUTH_CIPHER_PAIRWISE:
        rc = giwauth_cipher_pairwise(dev, info, erq, buf);
        break;
    case IW_AUTH_CIPHER_GROUP:
        rc = giwauth_cipher_group(dev, info, erq, buf);
        break;
    case IW_AUTH_KEY_MGMT:
        rc = giwauth_key_mgmt(dev, info, erq, buf);
        break;
    case IW_AUTH_TKIP_COUNTERMEASURES:
        rc = giwauth_tkip_countermeasures(dev, info, erq, buf);
        break;
    case IW_AUTH_DROP_UNENCRYPTED:
        rc = giwauth_drop_unencrypted(dev, info, erq, buf);
        break;
    case IW_AUTH_80211_AUTH_ALG:
        rc = giwauth_80211_auth_alg(dev, info, erq, buf);
        break;
    case IW_AUTH_WPA_ENABLED:
        rc = giwauth_wpa_enabled(dev, info, erq, buf);
        break;
    case IW_AUTH_RX_UNENCRYPTED_EAPOL:
        rc = giwauth_rx_unencrypted_eapol(dev, info, erq, buf);
        break;
    case IW_AUTH_ROAMING_CONTROL:
        rc = giwauth_roaming_control(dev, info, erq, buf);
        break;
    case IW_AUTH_PRIVACY_INVOKED:
        rc = giwauth_privacy_invoked(dev, info, erq, buf);
        break;
    default:
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_WARNING "%s: unknown SIOCGIWAUTH flag %d\n",
            dev->name, erq->flags);
        break;
    }

    return rc;
}

/*
* Retrieve information about a key.  Open question: should we allow
* callers to retrieve unicast keys based on a supplied MAC address?
* The ipw2200 reference implementation doesn't, so we don't either.
*/
static int
ieee80211_ioctl_giwencodeext(struct net_device *dev,
    struct iw_request_info *info, struct iw_point *erq, char *extra)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    struct iw_encode_ext *ext;
    struct ieee80211_key *wk;
    int error;
    u_int16_t kid=0;
    int max_key_len;

    if (!capable(CAP_NET_ADMIN))
        return -EPERM;

    max_key_len = erq->length - sizeof(*ext);
    if (max_key_len < 0)
        return -EINVAL;
    ext = (struct iw_encode_ext *)extra;

    error = getiwkeyix(vap, erq, &kid);
    if (error < 0)
        return error;

    wk = &vap->iv_nw_keys[kid];
    if (wk->wk_keylen > max_key_len)
        return -E2BIG;

    erq->flags = kid+1;
    memset(ext, 0, sizeof(*ext));

    ext->key_len = wk->wk_keylen;
    memcpy(ext->key, wk->wk_key, wk->wk_keylen);

    /* flags */
    if (wk->wk_flags & IEEE80211_KEY_GROUP)
        ext->ext_flags |= IW_ENCODE_EXT_GROUP_KEY;

    /* algorithm */
    switch(wk->wk_cipher->ic_cipher) {
    case IEEE80211_CIPHER_NONE:
        ext->alg = IW_ENCODE_ALG_NONE;
        erq->flags |= IW_ENCODE_DISABLED;
        break;
    case IEEE80211_CIPHER_WEP:
        ext->alg = IW_ENCODE_ALG_WEP;
        break;
    case IEEE80211_CIPHER_TKIP:
        ext->alg = IW_ENCODE_ALG_TKIP;
        break;
    case IEEE80211_CIPHER_AES_OCB:
    case IEEE80211_CIPHER_AES_CCM:
    case IEEE80211_CIPHER_CKIP:
        ext->alg = IW_ENCODE_ALG_CCMP;
        break;
    default:
        return -EINVAL;
    }
    return 0;
}

static int
ieee80211_ioctl_siwencodeext(struct net_device *dev,
    struct iw_request_info *info, struct iw_point *erq, char *extra)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    struct iw_encode_ext *ext = (struct iw_encode_ext *)extra;
    struct ieee80211req_key kr;
    int error;
    u_int16_t kid=0;

    debug_print_ioctl(dev->name, 0xffff, "siwencodeext") ;
    error = getiwkeyix(vap, erq, &kid);
    if (error < 0)
        return error;

    if (ext->key_len > (erq->length - sizeof(struct iw_encode_ext)))
        return -EINVAL;

    if (ext->alg == IW_ENCODE_ALG_NONE) {
        /* convert to the format used by IEEE_80211_IOCTL_DELKEY */
        struct ieee80211req_del_key dk;

        memset(&dk, 0, sizeof(dk));
        dk.idk_keyix = kid;
        memcpy(&dk.idk_macaddr, ext->addr.sa_data, IEEE80211_ADDR_LEN);

        return ieee80211_ioctl_delkey(dev, NULL, NULL, (char*)&dk);
    }

    if (ext->ext_flags & IW_ENCODE_EXT_GROUP_KEY){
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " WAPI :: %s[%d] group key \n",__func__,__LINE__);
    } else {
        if(!kid){
            kid = IEEE80211_KEYIX_NONE;
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WAPI :: %s[%d] \n",__func__,__LINE__);
        }
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WAPI :: %s[%d] unicast key \n",__func__,__LINE__);
    }
    /* TODO This memcmp for the broadcast address seems hackish, but
    * mimics what wpa supplicant was doing.  The wpa supplicant comments
    * make it sound like they were having trouble with
    * IEEE80211_IOCTL_SETKEY and static WEP keys.  It might be worth
    * figuring out what their trouble was so the rest of this function
    * can be implemented in terms of ieee80211_ioctl_setkey */
    if (ext->alg == IW_ENCODE_ALG_WEP &&
        memcmp(ext->addr.sa_data, "\xff\xff\xff\xff\xff\xff",
            IEEE80211_ADDR_LEN) == 0) {
        /* convert to the format used by SIOCSIWENCODE.  The old
        * format just had the key in the extra buf, whereas the
        * new format has the key tacked on to the end of the
        * iw_encode_ext structure */
        struct iw_request_info oldinfo;
        struct iw_point olderq;
        char *key;

        memset(&oldinfo, 0, sizeof(oldinfo));
        oldinfo.cmd = SIOCSIWENCODE;
        oldinfo.flags = info->flags;

        memset(&olderq, 0, sizeof(olderq));
        olderq.flags = erq->flags;
        olderq.pointer = erq->pointer;
        olderq.length = ext->key_len;

        key = ext->key;

        return ieee80211_ioctl_siwencode(dev, &oldinfo, &olderq, key);
    }

    /* convert to the format used by IEEE_80211_IOCTL_SETKEY */
    memset(&kr, 0, sizeof(kr));

#define IW_ENCODE_ALG_SMS4       0x20
    switch(ext->alg) {
    case IW_ENCODE_ALG_WEP:
        kr.ik_type = IEEE80211_CIPHER_WEP;
        break;
    case IW_ENCODE_ALG_TKIP:
        kr.ik_type = IEEE80211_CIPHER_TKIP;
        break;
    case IW_ENCODE_ALG_CCMP:
        kr.ik_type = IEEE80211_CIPHER_AES_CCM;
        break;
    case IW_ENCODE_ALG_SMS4:
        kr.ik_type = IEEE80211_CIPHER_WAPI;
        break;
    default:
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_WARNING "%s: unknown algorithm %d\n",
                dev->name, ext->alg);
        return -EINVAL;
    }

    kr.ik_keyix = kid;

    if (ext->key_len > sizeof(kr.ik_keydata)) {
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_WARNING "%s: key size %d is too large\n",
                dev->name, ext->key_len);
        return -E2BIG;
    }
    memcpy(kr.ik_keydata, ext->key, ext->key_len);
    kr.ik_keylen = ext->key_len;

    kr.ik_flags = IEEE80211_KEY_RECV;

    if (ext->ext_flags & IW_ENCODE_EXT_GROUP_KEY)
        kr.ik_flags |= IEEE80211_KEY_GROUP;

    if (ext->ext_flags & IW_ENCODE_EXT_SET_TX_KEY) {
        kr.ik_flags |= IEEE80211_KEY_XMIT | IEEE80211_KEY_DEFAULT;
        memcpy(kr.ik_macaddr, ext->addr.sa_data, IEEE80211_ADDR_LEN);
    }

    if (ext->ext_flags & IW_ENCODE_EXT_RX_SEQ_VALID) {
        memcpy(&kr.ik_keyrsc, ext->rx_seq, sizeof(kr.ik_keyrsc));
    }

    return ieee80211_ioctl_setkey(dev, NULL, NULL, (char*)&kr);
}
#endif /* WIRELESS_EXT >= 18 */


static int
ieee80211_ioctl_getmacaddr(struct net_device *dev,
    struct iw_request_info *info,
    void *w, char *extra)
{
    struct ieee80211vap *vap = NETDEV_TO_VAP(dev);
    union iwreq_data *u = w;
    debug_print_ioctl(dev->name, IEEE80211_IOCTL_GET_MACADDR, "getmacaddr") ;
    IEEE80211_ADDR_COPY(&(u->addr.sa_data), vap->iv_myaddr);
    return 0;
}

static int
ieee80211_ioctl_mcast_group(struct net_device *dev,
    struct iw_request_info *info, void *w, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211com *ic = vap->iv_ic;
    u_int32_t *param = (u_int32_t *) extra;
    int action;
    int wildcard;
    u_int32_t mcast_ip_addr;
    u_int8_t ucast_mac_addr[6];
    u_int32_t mac_addr_0_3;
    u_int32_t mac_addr_4_5;
    int j;

    action = param[0] & 0xffff;
    wildcard = param[0] >> 16;
    mcast_ip_addr = param[1];
    mac_addr_0_3 = param[2];
    mac_addr_4_5 = param[3];
    for (j = 0; j < 4; j++) {
        ucast_mac_addr[3-j] = mac_addr_0_3 & 0xff;
        mac_addr_0_3 >>= 8;
    }
    ucast_mac_addr[5] = mac_addr_4_5 & 0xff;
    mac_addr_4_5 >>= 8;
    ucast_mac_addr[4] = mac_addr_4_5 & 0xff;
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
        "mcast group update: action = %d, wildcard = %d, "
        "mcast IP addr = %08x, ucast MAC addr = "
        "%02x:%02x:%02x:%02x:%02x:%02x\n",
        action, wildcard,
        mcast_ip_addr,
        ucast_mac_addr[0],
        ucast_mac_addr[1],
        ucast_mac_addr[2],
        ucast_mac_addr[3],
        ucast_mac_addr[4],
        ucast_mac_addr[5]);

    ic->ic_mcast_group_update(
        ic, action, wildcard, (u_int8_t *)&mcast_ip_addr,
        sizeof(mcast_ip_addr), ucast_mac_addr, 0, 0, NULL, NULL, vap->iv_unit);

    return 0;
}

#define IW_PRIV_TYPE_OPTIE  IW_PRIV_TYPE_BYTE | IEEE80211_MAX_OPT_IE
#define IW_PRIV_TYPE_KEY \
    IW_PRIV_TYPE_BYTE | sizeof(struct ieee80211req_key)
#define IW_PRIV_TYPE_DELKEY \
    IW_PRIV_TYPE_BYTE | sizeof(struct ieee80211req_del_key)
#define IW_PRIV_TYPE_MLME \
    IW_PRIV_TYPE_BYTE | sizeof(struct ieee80211req_mlme)
#define IW_PRIV_TYPE_CHANLIST \
    IW_PRIV_TYPE_BYTE | sizeof(struct ieee80211req_chanlist)
#define IW_PRIV_TYPE_DBGREQ \
    IW_PRIV_TYPE_BYTE | sizeof(struct ieee80211req_athdbg)
/*
* There are 11 bits for size.  However, the
* size reqd is 4084 (>er than 11 bits).  Hence...
*/

/*
 * Disable this as ieee80211req_chaninfo size is
 * very huge upto 5K, which is not needed
 */
/*
 * IEEE80211_CHANINFO_MAX is restricted to 1024 integer as 4K buffer
 * is max for iwpriv version 25 and above.
 *  Also, Number of channels seen is in 64 or max 128 as of now
 */
#define IW_PRIV_TYPE_CHANINFO (IW_PRIV_TYPE_INT | IEEE80211_CHANINFO_MAX)

#define IW_PRIV_TYPE_APPIEBUF  (IW_PRIV_TYPE_BYTE | IEEE80211_APPIE_MAX)
#define IW_PRIV_TYPE_FILTER \
        IW_PRIV_TYPE_BYTE | sizeof(struct ieee80211req_set_filter)
#define IW_PRIV_TYPE_ACLMACLIST  (IW_PRIV_TYPE_ADDR | 256)

static const struct iw_priv_args ieee80211_priv_args[] = {
    /* NB: setoptie & getoptie are !IW_PRIV_SIZE_FIXED */
    { IEEE80211_IOCTL_SETOPTIE,
    IW_PRIV_TYPE_OPTIE, 0,            "setoptie" },
    { IEEE80211_IOCTL_GETOPTIE,
    0, IW_PRIV_TYPE_OPTIE,            "getoptie" },
    { IEEE80211_IOCTL_SETKEY,
    IW_PRIV_TYPE_KEY | IW_PRIV_SIZE_FIXED, 0, "setkey" },
    { IEEE80211_IOCTL_DELKEY,
    IW_PRIV_TYPE_DELKEY | IW_PRIV_SIZE_FIXED, 0,  "delkey" },
    { IEEE80211_IOCTL_SETMLME,
    IW_PRIV_TYPE_MLME | IW_PRIV_SIZE_FIXED, 0,    "setmlme" },
    { IEEE80211_IOCTL_ADDMAC,
    IW_PRIV_TYPE_ADDR | IW_PRIV_SIZE_FIXED | 1, 0,"addmac" },
    { IEEE80211_IOCTL_DELMAC,
    IW_PRIV_TYPE_ADDR | IW_PRIV_SIZE_FIXED | 1, 0,"delmac" },
    { IEEE80211_IOCTL_GET_MACADDR,
    0, IW_PRIV_TYPE_ACLMACLIST ,"getmac" },
    { IEEE80211_IOCTL_KICKMAC,
    IW_PRIV_TYPE_ADDR | IW_PRIV_SIZE_FIXED | 1, 0,"kickmac"},
    { IEEE80211_IOCTL_SETCHANLIST,
    IW_PRIV_TYPE_CHANLIST | IW_PRIV_SIZE_FIXED, 0,"setchanlist" },
    { IEEE80211_IOCTL_GETCHANLIST,
    0, IW_PRIV_TYPE_CHANLIST | IW_PRIV_SIZE_FIXED,"getchanlist" },
    { IEEE80211_IOCTL_GETCHANINFO,
    0, IW_PRIV_TYPE_CHANINFO | IW_PRIV_SIZE_FIXED,"getchaninfo" },
    { IEEE80211_IOCTL_SETMODE,
    IW_PRIV_TYPE_CHAR |  16, 0, "mode" },
    { IEEE80211_IOCTL_GETMODE,
    0, IW_PRIV_TYPE_CHAR | 16, "get_mode" },

#if WIRELESS_EXT >= 12
    { IEEE80211_IOCTL_SETWMMPARAMS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 4, 0,"setwmmparams" },
    { IEEE80211_IOCTL_GETWMMPARAMS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 3,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1,   "getwmmparams" },
    /*
    * These depends on sub-ioctl support which added in version 12.
    */
    { IEEE80211_IOCTL_SETWMMPARAMS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 3, 0,"" },
    { IEEE80211_IOCTL_GETWMMPARAMS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 2,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1,   "" },
    /* sub-ioctl handlers */
    { IEEE80211_WMMPARAMS_CWMIN,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 3, 0,"cwmin" },
    { IEEE80211_WMMPARAMS_CWMIN,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 2,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1,   "get_cwmin" },
    { IEEE80211_WMMPARAMS_CWMAX,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 3, 0,"cwmax" },
    { IEEE80211_WMMPARAMS_CWMAX,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 2,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1,   "get_cwmax" },
    { IEEE80211_WMMPARAMS_AIFS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 3, 0,"aifs" },
    { IEEE80211_WMMPARAMS_AIFS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 2,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1,   "get_aifs" },
    { IEEE80211_WMMPARAMS_TXOPLIMIT,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 3, 0,"txoplimit" },
    { IEEE80211_WMMPARAMS_TXOPLIMIT,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 2,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1,   "get_txoplimit" },
    { IEEE80211_WMMPARAMS_ACM,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 3, 0,"acm" },
    { IEEE80211_WMMPARAMS_ACM,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 2,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1,   "get_acm" },
    { IEEE80211_WMMPARAMS_NOACKPOLICY,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 3, 0,"noackpolicy" },
    { IEEE80211_WMMPARAMS_NOACKPOLICY,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 2,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1,   "get_noackpolicy" },
#if UMAC_VOW_DEBUG
    { IEEE80211_PARAM_VOW_DBG_CFG,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 3, 0,"vow_dbg_cfg" },
#endif

    { IEEE80211_IOCTL_SETPARAM,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 2, 0, "setparam" },
    /*
    * These depends on sub-ioctl support which added in version 12.
    */
    { IEEE80211_IOCTL_GETPARAM,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1,    "getparam" },

    /*
    * sub-ioctl handlers
    * A fairly weak attempt to validate args. Only params below with
    * get/set args that match these are allowed by the user space iwpriv
    * program.
    */
    { IEEE80211_IOCTL_SETPARAM,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "" },
    { IEEE80211_IOCTL_SETPARAM,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 2, 0, "" },
#if DBG_LVL_MAC_FILTERING
    { IEEE80211_IOCTL_SETPARAM,
    IW_PRIV_TYPE_BYTE | IW_PRIV_SIZE_FIXED | 8, 0, "" },
#endif
    { IEEE80211_IOCTL_SETPARAM,
    IW_PRIV_TYPE_BYTE | IW_PRIV_SIZE_FIXED | IEEE80211_ADDR_LEN, 0, "" },
    { IEEE80211_IOCTL_GETPARAM,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "" },
    { IEEE80211_IOCTL_GETPARAM,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "" },
    { IEEE80211_IOCTL_GETPARAM, 0,
    IW_PRIV_TYPE_BYTE | IW_PRIV_SIZE_FIXED | IEEE80211_ADDR_LEN, "" },
    { IEEE80211_IOCTL_GETPARAM, 0,
    IW_PRIV_TYPE_CHAR | IW_PRIV_SIZE_FIXED | 16, "" },
    { IEEE80211_IOCTL_GETPARAM, 0,
    IW_PRIV_TYPE_CHAR | IW_PRIV_SIZE_FIXED | (IEEE80211_ADDR_LEN * 2), "" },

    /*
    * sub-ioctl definitions
    *
    * IEEE80211_IOCTL_GETPARAM and IEEE80211_IOCTL_SETPARAM can
    * only return 1 int. Other values below are wrong.
    * fixme - check "g_bssid"
    */
    { IEEE80211_PARAM_AUTHMODE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "authmode" },
    { IEEE80211_PARAM_AUTHMODE,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_authmode" },
    { IEEE80211_PARAM_PROTMODE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "protmode" },
    { IEEE80211_PARAM_PROTMODE,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_protmode" },
    { IEEE80211_PARAM_MCASTCIPHER,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "mcastcipher" },
    { IEEE80211_PARAM_MCASTCIPHER,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_mcastcipher" },
    { IEEE80211_PARAM_MCASTKEYLEN,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "mcastkeylen" },
    { IEEE80211_PARAM_MCASTKEYLEN,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_mcastkeylen" },
    { IEEE80211_PARAM_UCASTCIPHERS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ucastciphers" },
    { IEEE80211_PARAM_UCASTCIPHERS,
    /*
    * NB: can't use "get_ucastciphers" 'cuz iwpriv command names
    *     must be <IFNAMESIZ which is 16.
    */
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_uciphers" },
    { IEEE80211_PARAM_UCASTCIPHER,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ucastcipher" },
    { IEEE80211_PARAM_UCASTCIPHER,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_ucastcipher" },
    { IEEE80211_PARAM_UCASTKEYLEN,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ucastkeylen" },
    { IEEE80211_PARAM_UCASTKEYLEN,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_ucastkeylen" },
    { IEEE80211_PARAM_KEYMGTALGS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "keymgtalgs" },
    { IEEE80211_PARAM_KEYMGTALGS,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_keymgtalgs" },
    { IEEE80211_PARAM_RSNCAPS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "rsncaps" },
    { IEEE80211_PARAM_RSNCAPS,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_rsncaps" },
    { IEEE80211_PARAM_PRIVACY,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "privacy" },
    { IEEE80211_PARAM_PRIVACY,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_privacy" },
    { IEEE80211_PARAM_COUNTERMEASURES,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "countermeasures" },
    { IEEE80211_PARAM_COUNTERMEASURES,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_countermeas" },
    { IEEE80211_PARAM_DROPUNENCRYPTED,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "dropunencrypted" },
    { IEEE80211_PARAM_DROPUNENCRYPTED,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_dropunencry" },
    { IEEE80211_PARAM_WPA,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "wpa" },
    { IEEE80211_PARAM_WPA,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_wpa" },
    { IEEE80211_PARAM_DRIVER_CAPS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "driver_caps" },
    { IEEE80211_PARAM_DRIVER_CAPS,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_driver_caps" },
    { IEEE80211_PARAM_MACCMD,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "maccmd" },
    { IEEE80211_PARAM_MACCMD,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_maccmd" },
    { IEEE80211_PARAM_MACCMD_SEC,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "maccmd_sec" },
    { IEEE80211_PARAM_MACCMD_SEC,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_maccmd_sec" },
    { IEEE80211_PARAM_WMM,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "wmm" },
    { IEEE80211_PARAM_WMM,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_wmm" },
    { IEEE80211_PARAM_HIDESSID,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "hide_ssid" },
    { IEEE80211_PARAM_HIDESSID,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_hide_ssid" },
    { IEEE80211_PARAM_APBRIDGE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ap_bridge" },
    { IEEE80211_PARAM_APBRIDGE,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_ap_bridge" },
    { IEEE80211_PARAM_INACT,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "inact" },
    { IEEE80211_PARAM_INACT,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_inact" },
    { IEEE80211_PARAM_INACT_AUTH,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "inact_auth" },
    { IEEE80211_PARAM_INACT_AUTH,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_inact_auth" },
    { IEEE80211_PARAM_INACT_INIT,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "inact_init" },
    { IEEE80211_PARAM_INACT_INIT,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_inact_init" },
    { IEEE80211_PARAM_SESSION_TIMEOUT,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "session" },
    { IEEE80211_PARAM_SESSION_TIMEOUT,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_session" },
    { IEEE80211_PARAM_DTIM_PERIOD,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "dtim_period" },
    { IEEE80211_PARAM_DTIM_PERIOD,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_dtim_period" },
    /* XXX bintval chosen to avoid 16-char limit */
    { IEEE80211_PARAM_BEACON_INTERVAL,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "bintval" },
    { IEEE80211_PARAM_BEACON_INTERVAL,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_bintval" },
    { IEEE80211_PARAM_SIFS_TRIGGER,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "sifs_trigger" },
    { IEEE80211_PARAM_SIFS_TRIGGER,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_sifs_trigger" },
    { IEEE80211_PARAM_DOTH,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "doth" },
    { IEEE80211_PARAM_DOTH,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_doth" },
    { IEEE80211_PARAM_PWRTARGET,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "doth_pwrtgt" },
    { IEEE80211_PARAM_PWRTARGET,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_doth_pwrtgt" },
    { IEEE80211_PARAM_GENREASSOC,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "doth_reassoc" },
    { IEEE80211_PARAM_COMPRESSION,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "compression" },
    { IEEE80211_PARAM_COMPRESSION,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_compression" },
    { IEEE80211_PARAM_FF,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ff" },
    { IEEE80211_PARAM_FF,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_ff" },
    { IEEE80211_PARAM_TURBO,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "turbo" },
    { IEEE80211_PARAM_TURBO,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_turbo" },
    { IEEE80211_PARAM_BURST,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "burst" },
    { IEEE80211_PARAM_BURST,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_burst" },
    { IEEE80211_IOCTL_CHANSWITCH,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 2, 0, "doth_chanswitch" },
    { IEEE80211_PARAM_PUREG,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "pureg" },
    { IEEE80211_PARAM_PUREG,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_pureg" },
    { IEEE80211_PARAM_AR,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ar" },
    { IEEE80211_PARAM_AR,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_ar" },
    { IEEE80211_PARAM_WDS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "wds" },
    { IEEE80211_PARAM_WDS,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_wds" },
#if WDS_VENDOR_EXTENSION
    { IEEE80211_PARAM_WDS_RX_POLICY,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "wds_policy" },
    { IEEE80211_PARAM_WDS_RX_POLICY,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_wds_poli" },
#endif
    { IEEE80211_PARAM_MCAST_RATE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "mcast_rate" },
    { IEEE80211_PARAM_MCAST_RATE,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_mcast_rate" },
    { IEEE80211_PARAM_COUNTRY_IE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "countryie" },
    { IEEE80211_PARAM_COUNTRY_IE,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_countryie" },
    /*
    * NB: these should be roamrssi* etc, but iwpriv usurps all
    *     strings that start with roam!
    */
    { IEEE80211_PARAM_UAPSDINFO,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "uapsd" },
    { IEEE80211_PARAM_UAPSDINFO,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_uapsd" },
#if ATH_SUPPORT_DSCP_OVERRIDE
    { IEEE80211_PARAM_VAP_DSCP_PRIORITY,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "vappriority" },
    { IEEE80211_PARAM_VAP_DSCP_PRIORITY,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_vappriority" },
#endif
#if UMAC_SUPPORT_STA_POWERSAVE
    { IEEE80211_PARAM_SLEEP,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "sleep" },
    { IEEE80211_PARAM_SLEEP,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_sleep" },
#endif
    { IEEE80211_PARAM_QOSNULL,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "qosnull" },
    { IEEE80211_PARAM_PSPOLL,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "pspoll" },
    { IEEE80211_PARAM_STA_PWR_SET_PSPOLL,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ips_pspoll" },
    { IEEE80211_PARAM_STA_PWR_SET_PSPOLL,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_ips_pspoll" },
    { IEEE80211_PARAM_EOSPDROP,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "eospdrop" },
    { IEEE80211_PARAM_EOSPDROP,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_eospdrop" },
    { IEEE80211_PARAM_MARKDFS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "markdfs" },
    { IEEE80211_PARAM_MARKDFS,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_markdfs" },
    { IEEE80211_PARAM_DFSDOMAIN,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_dfsdomain" },
    { IEEE80211_PARAM_CHANBW,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "chanbw" },
    { IEEE80211_PARAM_CHANBW,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_chanbw" },
    { IEEE80211_PARAM_SHORTPREAMBLE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "shpreamble" },
    { IEEE80211_PARAM_SHORTPREAMBLE,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_shpreamble" },
    { IEEE80211_PARAM_BLOCKDFSCHAN,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "blockdfschan" },
    { IEEE80211_IOCTL_SET_APPIEBUF,
    IW_PRIV_TYPE_APPIEBUF, 0,                     "setiebuf" },
    { IEEE80211_IOCTL_GET_APPIEBUF,
    0, IW_PRIV_TYPE_APPIEBUF,                     "getiebuf" },
    { IEEE80211_IOCTL_FILTERFRAME,
    IW_PRIV_TYPE_FILTER , 0,                      "setfilter" },
    { IEEE80211_PARAM_NETWORK_SLEEP,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "powersave" },
    { IEEE80211_PARAM_NETWORK_SLEEP,
      0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_powersave" },
#if UMAC_SUPPORT_WNM
    { IEEE80211_PARAM_WNM_SLEEP,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "wnmsleepmode" },
    { IEEE80211_PARAM_WNM_SLEEP,
      0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_wnmsleepmode" },
    { IEEE80211_PARAM_WNM_SMENTER,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "wnmsmenter" },
    { IEEE80211_PARAM_WNM_SMEXIT,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "wnmsmexit" },
#endif
    { IEEE80211_PARAM_DYN_BW_RTS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "dyn_bw_rts" },
    { IEEE80211_PARAM_DYN_BW_RTS ,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_dyn_bw_rts" },
    { IEEE80211_PARAM_CWM_EXTPROTMODE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "extprotmode" },
    { IEEE80211_PARAM_CWM_EXTPROTMODE,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_extprotmode" },
    { IEEE80211_PARAM_CWM_EXTPROTSPACING,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "extprotspac" },
    { IEEE80211_PARAM_CWM_EXTPROTSPACING,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_extprotspac" },
    { IEEE80211_PARAM_CWM_ENABLE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "cwmenable" },
    { IEEE80211_PARAM_CWM_ENABLE,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_cwmenable" },
    { IEEE80211_PARAM_CWM_EXTBUSYTHRESHOLD,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "extbusythres" },
    { IEEE80211_PARAM_CWM_EXTBUSYTHRESHOLD,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_extbusythres" },
    { IEEE80211_PARAM_SHORT_GI,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "shortgi" },
    { IEEE80211_PARAM_SHORT_GI,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_shortgi" },
    { IEEE80211_PARAM_MCS,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_mcsmode" },
    { IEEE80211_PARAM_CHAN_NOISE,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_channf" },
    { IEEE80211_PARAM_BANDWIDTH,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "bandwidth" },
    { IEEE80211_PARAM_FREQ_BAND,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "freq_band" },
    { IEEE80211_PARAM_EXTCHAN,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "extchan" },
    { IEEE80211_PARAM_BANDWIDTH,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_bandwidth" },
    { IEEE80211_PARAM_FREQ_BAND,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_freq_band" },
    { IEEE80211_PARAM_EXTCHAN,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_extchan" },
    { IEEE80211_PARAM_SECOND_CENTER_FREQ,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "cfreq2" },
    { IEEE80211_PARAM_SECOND_CENTER_FREQ,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_cfreq2" },
    { IEEE80211_PARAM_ATH_SUPPORT_VLAN,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "vlan_tag" },
    { IEEE80211_PARAM_ATH_SUPPORT_VLAN,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_vlan_tag" },
    /*
     * 11n A-MPDU, A-MSDU support
     */
    { IEEE80211_PARAM_AMPDU,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ampdu" },
    { IEEE80211_PARAM_AMPDU,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_ampdu" },
    { IEEE80211_PARAM_MAX_AMPDU,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "maxampdu" },
    { IEEE80211_PARAM_MAX_AMPDU,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_maxampdu" },
    { IEEE80211_PARAM_CUSTOM_CHAN_LIST,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "use_custom_chan" },
    { IEEE80211_PARAM_CUSTOM_CHAN_LIST,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_custom_chan" },
    { IEEE80211_PARAM_VHT_MAX_AMPDU,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "vhtmaxampdu" },
    { IEEE80211_PARAM_VHT_MAX_AMPDU,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_vhtmaxampdu" },
    { IEEE80211_PARAM_RESET_ONCE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "reset" },
    { IEEE80211_PARAM_AMSDU,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "amsdu" },
    { IEEE80211_PARAM_AMSDU,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_amsdu" },

    { IEEE80211_PARAM_COUNTRYCODE,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_countrycode" },
#if ATH_SUPPORT_IQUE
    /*
    * Mcast enhancement
    */
    { IEEE80211_PARAM_ME,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "mcastenhance" },
    { IEEE80211_PARAM_ME, 0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_mcastenhance" },
    { IEEE80211_PARAM_MEDUMP,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "medump_dummy" },
    { IEEE80211_PARAM_MEDUMP, 0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "medump" },
    { IEEE80211_PARAM_MEDEBUG,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "medebug" },
    { IEEE80211_PARAM_MEDEBUG, 0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_medebug" },
    { IEEE80211_PARAM_ME_SNOOPLENGTH,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "me_length" },
    { IEEE80211_PARAM_ME_SNOOPLENGTH, 0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_me_length" },
    { IEEE80211_PARAM_ME_TIMER,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "metimer" },
    { IEEE80211_PARAM_ME_TIMER, 0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_metimer" },
    { IEEE80211_PARAM_ME_TIMEOUT,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "metimeout" },
    { IEEE80211_PARAM_ME_TIMEOUT, 0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_metimeout" },
    { IEEE80211_PARAM_ME_DROPMCAST,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "medropmcast" },
    { IEEE80211_PARAM_ME_DROPMCAST, 0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_medropmcast" },
    { IEEE80211_PARAM_ME_SHOWDENY, 0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "me_showdeny" },
    { IEEE80211_PARAM_ME_CLEARDENY,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "me_cleardeny" },

    /*
    *  Headline block removal
    */
    { IEEE80211_PARAM_HBR_TIMER,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "hbrtimer" },
    { IEEE80211_PARAM_HBR_TIMER, 0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_hbrtimer" },
    { IEEE80211_PARAM_HBR_STATE, 0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_hbrstate" },

    /*
    * rate control / AC parameters for IQUE
    */
    { IEEE80211_PARAM_GETIQUECONFIG, 0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_iqueconfig" },
    { IEEE80211_IOCTL_SET_ACPARAMS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 4, 0, "acparams" },
    { IEEE80211_IOCTL_SET_RTPARAMS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 4, 0, "setrcparams" },
    /*
    * These depends on sub-ioctl support which added in version 12.
    */
    { IEEE80211_IOCTL_SET_RTPARAMS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 3, 0, "" },
    { IEEE80211_IOCTL_RCPARAMS_RTPARAM,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 3, 0, "rtparams" },
    { IEEE80211_IOCTL_RCPARAMS_RTMASK,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 3, 0, "setratemask" },

    { IEEE80211_IOCTL_SET_HBRPARAMS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 3, 0, "hbrparams" },
    { IEEE80211_IOCTL_SET_MEDENYENTRY,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 4, 0, "me_adddeny" },
#endif

    { IEEE80211_PARAM_SCANVALID,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "scanvalid"  },
    { IEEE80211_PARAM_SCANVALID, 0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_scanvalid" },
    { IEEE80211_IOCTL_SET_RXTIMEOUT,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 2, 0, "rxtimeout" },
    { IEEE80211_IOCTL_DBGREQ,
      IW_PRIV_TYPE_DBGREQ | IW_PRIV_SIZE_FIXED, 0, "dbgreq" },
    { IEEE80211_PARAM_SETADDBAOPER,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "setaddbaoper" },
    { IEEE80211_PARAM_11N_RATE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "set11NRates" },
    { IEEE80211_PARAM_11N_RATE,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get11NRates" },
    { IEEE80211_PARAM_11N_RETRIES,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "set11NRetries" },
    { IEEE80211_PARAM_11N_RETRIES,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get11NRetries" },
#if DBG_LVL_MAC_FILTERING
    { IEEE80211_PARAM_DBG_LVL_MAC,
    IW_PRIV_TYPE_BYTE | IW_PRIV_SIZE_FIXED | 8, 0, "dbgLVLmac" },
    { IEEE80211_PARAM_DBG_LVL_MAC,
       0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getdbgLVLmac" },
#endif
    { IEEE80211_PARAM_UMAC_VERBOSE_LVL,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "vbLVL" },
    { IEEE80211_PARAM_DBG_LVL,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "dbgLVL" },
    { IEEE80211_PARAM_DBG_LVL,
       0,IW_PRIV_TYPE_CHAR | IW_PRIV_SIZE_FIXED | 16, "getdbgLVL" },

    { IEEE80211_PARAM_11N_TX_AMSDU,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "no_HT_TxAmsdu" },
    { IEEE80211_PARAM_11N_TX_AMSDU,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_no_HT_TxAmsdu" },
    { IEEE80211_PARAM_CTSPROT_DTIM_BCN,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ctsprt_dtmbcn" },
    { IEEE80211_PARAM_CTSPROT_DTIM_BCN,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_ctsprt_dtmbcn" },

    { IEEE80211_PARAM_VSP_ENABLE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "vsp_enable" },
    { IEEE80211_PARAM_VSP_ENABLE,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_vsp_enable" },

    { IEEE80211_PARAM_DBG_LVL_HIGH,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "dbgLVL_high" },
    { IEEE80211_PARAM_DBG_LVL_HIGH,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getdbgLVL_high" },
    { IEEE80211_PARAM_MIXED_MODE,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_mixedmode" },
#if UMAC_SUPPORT_IBSS
    { IEEE80211_PARAM_IBSS_CREATE_DISABLE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "noIBSSCreate" },
    { IEEE80211_PARAM_IBSS_CREATE_DISABLE,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_noIBSSCreate" },
#endif
    { IEEE80211_PARAM_WEATHER_RADAR_CHANNEL,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "no_wradar" },
    { IEEE80211_PARAM_WEATHER_RADAR_CHANNEL,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_no_wradar" },
   { IEEE80211_PARAM_WEP_KEYCACHE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "wepkeycache" },
    { IEEE80211_PARAM_WEP_KEYCACHE,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_wepkeycache" },
    { IEEE80211_PARAM_WDS_AUTODETECT,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "wdsdetect" },
    { IEEE80211_PARAM_WDS_AUTODETECT,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_wdsdetect" },
    { IEEE80211_PARAM_WEP_TKIP_HT,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "htweptkip" },
    { IEEE80211_PARAM_WEP_TKIP_HT, 0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_htweptkip" },
    /*
    ** This is a "get" only
    */
    { IEEE80211_PARAM_PUREN,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "puren" },
    { IEEE80211_PARAM_PUREN,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_puren" },
    { IEEE80211_PARAM_PURE11AC,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "pure11ac" },
    { IEEE80211_PARAM_PURE11AC,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_pure11ac" },
    { IEEE80211_PARAM_STRICT_BW,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "strictbw" },
    { IEEE80211_PARAM_STRICT_BW,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_strictbw" },
    { IEEE80211_PARAM_BASICRATES,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "basicrates" },
    /*
    * 11d Beacon processing
    */
    { IEEE80211_PARAM_IGNORE_11DBEACON,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ignore11d"},
    { IEEE80211_PARAM_IGNORE_11DBEACON,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_ignore11d"},
    { IEEE80211_PARAM_STA_FORWARD,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "stafwd" },
    { IEEE80211_PARAM_STA_FORWARD,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_stafwd" },
#ifdef ATH_EXT_AP
    { IEEE80211_PARAM_EXTAP,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "extap" },
    { IEEE80211_PARAM_EXTAP, 0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_extap" },
#endif
    { IEEE80211_PARAM_CLR_APPOPT_IE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "clrappoptie" },
    { IEEE80211_PARAM_AUTO_ASSOC,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "autoassoc" },
    { IEEE80211_PARAM_AUTO_ASSOC,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_autoassoc" },
    { IEEE80211_PARAM_VAP_COUNTRY_IE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "vap_contryie" },
    { IEEE80211_PARAM_VAP_COUNTRY_IE,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_vapcontryie" },
    { IEEE80211_PARAM_VAP_DOTH,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "vap_doth" },
    { IEEE80211_PARAM_VAP_DOTH,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_vap_doth" },
    { IEEE80211_PARAM_HT40_INTOLERANT,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ht40intol" },
    { IEEE80211_PARAM_HT40_INTOLERANT,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_ht40intol" },
    { IEEE80211_PARAM_CHWIDTH,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "chwidth" },
    { IEEE80211_PARAM_CHWIDTH,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_chwidth" },
    { IEEE80211_PARAM_CHEXTOFFSET,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "chextoffset" },
    { IEEE80211_PARAM_CHEXTOFFSET,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_chextoffset" },
    { IEEE80211_PARAM_STA_QUICKKICKOUT,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "sko" },
    { IEEE80211_PARAM_STA_QUICKKICKOUT,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_sko" },
    { IEEE80211_PARAM_CHSCANINIT,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "chscaninit" },
    { IEEE80211_PARAM_CHSCANINIT,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_chscaninit" },
    { IEEE80211_PARAM_COEXT_DISABLE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "disablecoext" },
    { IEEE80211_PARAM_COEXT_DISABLE,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_disablecoext" },
#if ATH_SUPPORT_NR_SYNC
    { IEEE80211_PARAM_NR_SHARE_RADIO_FLAG,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "nrshareflag" },
    { IEEE80211_PARAM_NR_SHARE_RADIO_FLAG,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_nrshareflag" },
#endif
    { IEEE80211_PARAM_MFP_TEST,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "mfptest" },
    { IEEE80211_PARAM_MFP_TEST,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_mfptest" },

#if ATH_SUPPORT_HS20
    { IEEE80211_PARAM_OSEN,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "osen" },
    { IEEE80211_PARAM_OSEN, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_osen" },
#endif /* ATH_SUPPORT_HS20 */
#if UMAC_SUPPORT_BSSLOAD
    { IEEE80211_PARAM_QBSS_LOAD,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "qbssload" },
    { IEEE80211_PARAM_QBSS_LOAD, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_qbssload" },
#if ATH_SUPPORT_HS20
    { IEEE80211_PARAM_HC_BSSLOAD,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "hcbssload" },
    { IEEE80211_PARAM_HC_BSSLOAD, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_hcbssload" },
#endif /* ATH_SUPPORT_HS20 */
#endif /* UMAC_SUPPORT_BSSLOAD */
#if UMAC_SUPPORT_CHANUTIL_MEASUREMENT
    { IEEE80211_PARAM_CHAN_UTIL_ENAB,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "chutil_enab" },
    { IEEE80211_PARAM_CHAN_UTIL_ENAB, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_chutil_enab" },
    { IEEE80211_PARAM_CHAN_UTIL, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_chutil" },
#endif /* UMAC_SUPPORT_CHANUTIL_MEASUREMENT */
#if UMAC_SUPPORT_QUIET
    { IEEE80211_PARAM_QUIET_PERIOD,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "quiet" },
    { IEEE80211_PARAM_QUIET_PERIOD, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_quiet" },
#endif /* UMAC_SUPPORT_QUIET */
    { IEEE80211_PARAM_MBO,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "mbo" },
    { IEEE80211_PARAM_MBO, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_mbo" },
    { IEEE80211_PARAM_MBO_ASSOC_DISALLOW,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "mbo_asoc_dis"},
    { IEEE80211_PARAM_MBO_ASSOC_DISALLOW, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_mbo_asoc_dis"},
    { IEEE80211_PARAM_MBO_CAP,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "mbocap" },
    { IEEE80211_PARAM_MBO_CAP, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_mbocap" },
    { IEEE80211_PARAM_MBO_CELLULAR_PREFERENCE,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "mbo_cel_pref" },
    { IEEE80211_PARAM_MBO_CELLULAR_PREFERENCE, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_mbo_cel_pref" },
    { IEEE80211_PARAM_MBO_TRANSITION_REASON,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "mbo_trans_rs" },
    { IEEE80211_PARAM_MBO_TRANSITION_REASON, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_mbo_trans_rs" },
    { IEEE80211_PARAM_MBO_ASSOC_RETRY_DELAY,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "mbo_asoc_ret" },
    { IEEE80211_PARAM_MBO_ASSOC_RETRY_DELAY, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_mbo_asoc_ret" },
    { IEEE80211_PARAM_OCE,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "oce" },
    { IEEE80211_PARAM_OCE, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_oce" },
    { IEEE80211_PARAM_OCE_ASSOC_REJECT,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "oce_asoc_rej" },
    { IEEE80211_PARAM_OCE_ASSOC_REJECT, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_oce_asoc_rej" },
    { IEEE80211_PARAM_OCE_ASSOC_MIN_RSSI,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "oce_asoc_rssi" },
    { IEEE80211_PARAM_OCE_ASSOC_MIN_RSSI, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_oce_asoc_rssi" },
    { IEEE80211_PARAM_OCE_ASSOC_RETRY_DELAY,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "oce_asoc_dly" },
    { IEEE80211_PARAM_OCE_ASSOC_RETRY_DELAY, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_oce_asoc_dly" },
    { IEEE80211_PARAM_OCE_WAN_METRICS,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "oce_wan_mtr" },
    { IEEE80211_PARAM_OCE_WAN_METRICS, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_oce_wan_mtr" },
    { IEEE80211_PARAM_MGMT_RATE,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "mgmt_rate" },
    { IEEE80211_PARAM_MGMT_RATE, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_mgmt_rate" },
    { IEEE80211_PARAM_RRM_CAP,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "rrm" },
    { IEEE80211_PARAM_RRM_CAP, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_rrm" },
    { IEEE80211_PARAM_RRM_STATS,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "rrmstats" },
    { IEEE80211_PARAM_RRM_STATS, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_rrmstats" },
    { IEEE80211_PARAM_RRM_SLWINDOW,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "rrmslwin"},
    { IEEE80211_PARAM_RRM_SLWINDOW, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_rrmslwin" },
    { IEEE80211_PARAM_RRM_DEBUG,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "rrmdbg" },
    { IEEE80211_PARAM_RRM_DEBUG, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_rrmdbg" },
#if UMAC_SUPPORT_WNM
    { IEEE80211_PARAM_WNM_CAP,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "wnm" },
    { IEEE80211_PARAM_WNM_CAP, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_wnm" },
    { IEEE80211_PARAM_WNM_BSS_CAP,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "wnm_bss" },
    { IEEE80211_PARAM_WNM_BSS_CAP, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_wnm_bss" },
    { IEEE80211_PARAM_WNM_TFS_CAP,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "wnm_tfs" },
    { IEEE80211_PARAM_WNM_TFS_CAP, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_wnm_tfs" },
    { IEEE80211_PARAM_WNM_TIM_CAP,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "wnm_tim" },
    { IEEE80211_PARAM_WNM_TIM_CAP, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_wnm_tim" },
    { IEEE80211_PARAM_WNM_SLEEP_CAP,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "wnm_sleep" },
    { IEEE80211_PARAM_WNM_SLEEP_CAP, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_wnm_sleep" },
    { IEEE80211_PARAM_WNM_FMS_CAP,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "wnm_fms" },
    { IEEE80211_PARAM_WNM_FMS_CAP, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_wnm_fms" },
#endif
    { IEEE80211_IOCTL_SEND_MGMT,
    IW_PRIV_TYPE_APPIEBUF, 0,                     "sendmgmt" },
#ifdef ATH_SUPPORT_GREEN_AP
      { IEEE80211_IOCTL_GREEN_AP_PS_ENABLE,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ant_ps_on" },
      { IEEE80211_IOCTL_GREEN_AP_PS_ENABLE, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_ant_ps_on" },
      { IEEE80211_IOCTL_GREEN_AP_PS_TIMEOUT,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ps_timeout" },
      { IEEE80211_IOCTL_GREEN_AP_PS_TIMEOUT, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_ps_timeout" },
      { IEEE80211_IOCTL_GREEN_AP_ENABLE_PRINT,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "gap_dbgprint" },
      { IEEE80211_IOCTL_GREEN_AP_ENABLE_PRINT, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "gap_g_dbgprint" },
#if 0 /* No cycling for now EV 69649*/
      { IEEE80211_IOCTL_GREEN_AP_PS_ON_TIME,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ps_on_time" },
      { IEEE80211_IOCTL_GREEN_AP_PS_ON_TIME, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_ps_on_time" },
#endif /* No cycling for now */
#endif /*ATH_SUPPORT_GREEN_AP */

#endif /* WIRELESS_EXT >= 12 */

#if ATH_SUPPORT_WAPI
    { IEEE80211_PARAM_SETWAPI,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "setwapi" },
    { IEEE80211_PARAM_WAPIREKEY_USK,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "wapi_rkupkt" },
    { IEEE80211_PARAM_WAPIREKEY_USK, 0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_wapi_rkupkt" },
    { IEEE80211_PARAM_WAPIREKEY_MSK,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "wapi_rkmpkt" },
    { IEEE80211_PARAM_WAPIREKEY_MSK, 0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_wapi_rkmpkt" },
    { IEEE80211_PARAM_WAPIREKEY_UPDATE,
    IW_PRIV_TYPE_BYTE | IW_PRIV_SIZE_FIXED | IEEE80211_ADDR_LEN, 0, "wapi_rkupdate" },

#endif /*ATH_SUPPORT_WAPI*/
#ifdef ATH_WPS_IE
    { IEEE80211_PARAM_WPS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "wps" },
    { IEEE80211_PARAM_WPS, 0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_wps" },
#endif
    { IEEE80211_PARAM_CCMPSW_ENCDEC,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ccmpSwSelEn" },
    { IEEE80211_PARAM_CCMPSW_ENCDEC, 0,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_ccmpSwSelEn" },
    { IEEE80211_IOC_SCAN_FLUSH,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "s_scan_flush"},
#ifdef ATHEROS_LINUX_PERIODIC_SCAN
    { IEEE80211_PARAM_PERIODIC_SCAN,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "periodicScan" },
    { IEEE80211_PARAM_PERIODIC_SCAN,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_periodicScan" },
#endif
    { IEEE80211_PARAM_2G_CSA,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "csa2g" },
    { IEEE80211_PARAM_2G_CSA,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_csa2g" },
#ifdef ATH_SW_WOW
    { IEEE80211_PARAM_SW_WOW,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "sw_wow" },
    { IEEE80211_PARAM_SW_WOW,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_sw_wow" },
#endif
#if UMAC_SUPPORT_WDS
    { IEEE80211_IOCTL_GET_MACADDR,
      IW_PRIV_TYPE_ADDR | IW_PRIV_SIZE_FIXED | 2, 0, "" },
    { IEEE80211_PARAM_ADD_WDS_ADDR,
      IW_PRIV_TYPE_ADDR | IW_PRIV_SIZE_FIXED | 2, 0, "wdsaddr" },
#endif
#ifdef QCA_PARTNER_PLATFORM
    { IEEE80211_PARAM_PLTFRM_PRIVATE,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, CARRIER_PLTFRM_PRIVATE_SET },
    { IEEE80211_PARAM_PLTFRM_PRIVATE, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, CARRIER_PLTFRM_PRIVATE_GET },
#endif

    { IEEE80211_PARAM_NO_STOP_DISASSOC,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "no_disassoc" },
    { IEEE80211_PARAM_NO_STOP_DISASSOC, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_no_disassoc" },
#if UMAC_SUPPORT_VI_DBG
   /* Video debug parameters */
    { IEEE80211_PARAM_DBG_CFG,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "dbgcfg" },
    { IEEE80211_PARAM_DBG_CFG, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getdbgcfg" },
    { IEEE80211_PARAM_RESTART,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "dbgrestart" },
    { IEEE80211_PARAM_RESTART, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getdbgrestart" },
    { IEEE80211_PARAM_RXDROP_STATUS,
          IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "rxdropstats" },
    { IEEE80211_PARAM_RXDROP_STATUS, 0,
          IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getrxdropstats" },

#endif

#if ATH_SUPPORT_IBSS_DFS
    { IEEE80211_PARAM_IBSS_DFS_PARAM,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "setibssdfsparam" },
    { IEEE80211_PARAM_IBSS_DFS_PARAM,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getibssdfsparam" },
#endif

#if ATH_SUPPORT_IBSS_NETLINK_NOTIFICATION
    { IEEE80211_PARAM_IBSS_SET_RSSI_CLASS,
    IW_PRIV_TYPE_BYTE | IW_PRIV_SIZE_FIXED | IEEE80211_ADDR_LEN, 0, "s_ibssrssiclass"},
    { IEEE80211_PARAM_IBSS_START_RSSI_MONITOR,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "strtibssrssimon" },
    { IEEE80211_PARAM_IBSS_RSSI_HYSTERESIS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "setibssrssihyst" },
#endif
#ifdef ATH_SUPPORT_TxBF
    { IEEE80211_PARAM_TXBF_AUTO_CVUPDATE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "autocvupdate" },
    { IEEE80211_PARAM_TXBF_AUTO_CVUPDATE,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_autocvupdate" },
    { IEEE80211_PARAM_TXBF_CVUPDATE_PER,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "cvupdateper" },
    { IEEE80211_PARAM_TXBF_CVUPDATE_PER,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_cvupdateper" },
#endif
    { IEEE80211_PARAM_MAXSTA,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "maxsta"},
    { IEEE80211_PARAM_MAXSTA,0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_maxsta"},
    { IEEE80211_PARAM_SCAN_BAND,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "scanband" },
    { IEEE80211_PARAM_SCAN_BAND,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_scanband" },
    { IEEE80211_PARAM_SCAN_CHAN_EVENT,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "scanchevent" },
    { IEEE80211_PARAM_SCAN_CHAN_EVENT,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_scanchevent" },

#if ATH_SUPPORT_WIFIPOS
    { IEEE80211_PARAM_WIFIPOS_TXCORRECTION,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "txcorrection" },
    { IEEE80211_PARAM_WIFIPOS_TXCORRECTION,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_txcorrection" },
    { IEEE80211_PARAM_WIFIPOS_RXCORRECTION,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "rxcorrection" },
    { IEEE80211_PARAM_WIFIPOS_RXCORRECTION,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_rxcorrection" },
#endif
#if ATH_SUPPORT_WPA_SUPPLICANT_CHECK_TIME
    { IEEE80211_PARAM_REJOINT_ATTEMP_TIME,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "rejoingtime" },
    { IEEE80211_PARAM_REJOINT_ATTEMP_TIME,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_rejoingtime" },
#endif
    { IEEE80211_PARAM_SEND_DEAUTH,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "senddeauth" },
    { IEEE80211_PARAM_SEND_DEAUTH,
        0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_senddeauth" },
#if UMAC_SUPPORT_PROXY_ARP
    { IEEE80211_PARAM_PROXYARP_CAP,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "proxyarp" },
    { IEEE80211_PARAM_PROXYARP_CAP, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_proxyarp" },
#if UMAC_SUPPORT_DGAF_DISABLE
    { IEEE80211_PARAM_DGAF_DISABLE,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "dgaf_disable" },
    { IEEE80211_PARAM_DGAF_DISABLE, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_dgaf_disable" },
#endif
#endif
#if UMAC_SUPPORT_HS20_L2TIF
    { IEEE80211_PARAM_L2TIF_CAP,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "l2tif" },
    { IEEE80211_PARAM_L2TIF_CAP, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_l2tif" },
#endif
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
    { IEEE80211_PARAM_NOPBN,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "nopbn" },
    { IEEE80211_PARAM_NOPBN,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_nopbn" },
#endif
#if ATH_SUPPORT_DSCP_OVERRIDE
    { IEEE80211_PARAM_DSCP_OVERRIDE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "set_dscp_ovride" },
    { IEEE80211_PARAM_DSCP_OVERRIDE,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_dscp_ovride" },
    { IEEE80211_PARAM_DSCP_TID_MAP,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 2, 0, "s_dscp_tid_map" },
    { IEEE80211_PARAM_DSCP_TID_MAP,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_dscp_tid_map" },
#endif
    {IEEE80211_PARAM_SET_TXPWRADJUST,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "siwtxpwradjust" },
#if UMAC_SUPPORT_APONLY
    { IEEE80211_PARAM_APONLY,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "aponly" },
    { IEEE80211_PARAM_APONLY, 0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_aponly" },
#endif
    { IEEE80211_PARAM_TXRX_DBG,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "txrx_dbg" },
    { IEEE80211_PARAM_VAP_TXRX_FW_STATS,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "vap_txrx_stats" },
    { IEEE80211_PARAM_VAP_TXRX_FW_STATS_RESET,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "vap_txrx_st_rst" },
    { IEEE80211_PARAM_TXRX_FW_STATS,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "txrx_fw_stats" },
    { IEEE80211_PARAM_TXRX_FW_MSTATS,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "txrx_fw_mstats" },
    { IEEE80211_PARAM_TXRX_FW_STATS_RESET,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "txrx_fw_st_rst" },
    { IEEE80211_PARAM_TX_PPDU_LOG_CFG,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "tx_ppdu_log_cfg" },
    { IEEE80211_PARAM_VHT_MCS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "vhtmcs" },
    { IEEE80211_PARAM_VHT_MCS,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_vhtmcs" },
    { IEEE80211_PARAM_NSS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "nss" },
    { IEEE80211_PARAM_NSS,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_nss" },
    { IEEE80211_PARAM_STA_COUNT,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_sta_count" },
    { IEEE80211_PARAM_NO_VAP_RESET,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "novap_reset" },
    { IEEE80211_PARAM_NO_VAP_RESET,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_novap_reset" },
     { IEEE80211_PARAM_VHT_SGIMASK,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "vht_sgimask" },
    { IEEE80211_PARAM_VHT_SGIMASK,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_vht_sgimask" },
    { IEEE80211_PARAM_VHT80_RATEMASK,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "vht80_rate" },
    { IEEE80211_PARAM_VHT80_RATEMASK,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_vht80_rate" },
    { IEEE80211_PARAM_BW_NSS_RATEMASK,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "bw_nss_rate" },
    { IEEE80211_PARAM_LDPC,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ldpc" },
    { IEEE80211_PARAM_LDPC,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_ldpc" },
    { IEEE80211_PARAM_TX_STBC,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "tx_stbc" },
    { IEEE80211_PARAM_TX_STBC,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_tx_stbc" },
    { IEEE80211_PARAM_RX_STBC,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "rx_stbc" },
    { IEEE80211_PARAM_RX_STBC,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_rx_stbc" },
    { IEEE80211_PARAM_OPMODE_NOTIFY,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "opmode_notify" },
    { IEEE80211_PARAM_OPMODE_NOTIFY,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_opmod_notify" },
    { IEEE80211_IOCTL_CHN_WIDTHSWITCH,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 3, 0, "doth_ch_chwidth" },
    { IEEE80211_PARAM_DFS_CACTIMEOUT,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "set_cactimeout" },
    { IEEE80211_PARAM_DFS_CACTIMEOUT,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_cactimeout" },
    { IEEE80211_PARAM_ENABLE_RTSCTS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "enablertscts" },
    { IEEE80211_PARAM_ENABLE_RTSCTS,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_enablertscts" },
    { IEEE80211_PARAM_RC_NUM_RETRIES,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "rc_retries" },
    { IEEE80211_PARAM_RC_NUM_RETRIES,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_rc_retries" },
	{ IEEE80211_PARAM_BCAST_RATE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "bcast_rate" },
    { IEEE80211_PARAM_BCAST_RATE,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_bcast_rate" },
    { IEEE80211_PARAM_VHT_TX_MCSMAP,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "vht_txmcsmap" },
    { IEEE80211_PARAM_VHT_TX_MCSMAP,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_vht_txmcsmap" },
    { IEEE80211_PARAM_VHT_RX_MCSMAP,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "vht_rxmcsmap" },
    { IEEE80211_PARAM_VHT_RX_MCSMAP,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_vht_rxmcsmap" },
#if ATH_SUPPORT_WRAP
    { IEEE80211_PARAM_PROXY_STA,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_proxysta" },
    { IEEE80211_PARAM_PARENT_IFINDEX, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_parent" },
#endif
#if QCN_IE
    { IEEE80211_PARAM_BCAST_PROBE_RESPONSE_ENABLE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "set_bpr_enable" },
    { IEEE80211_PARAM_BCAST_PROBE_RESPONSE_ENABLE,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_bpr_enable" },
    { IEEE80211_PARAM_BCAST_PROBE_RESPONSE_DELAY,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "set_bpr_delay" },
    { IEEE80211_PARAM_BCAST_PROBE_RESPONSE_DELAY,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_bpr_delay" },
    { IEEE80211_PARAM_BCAST_PROBE_RESPONSE_LATENCY_COMPENSATION,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "set_bpr_latency" },
    { IEEE80211_PARAM_BCAST_PROBE_RESPONSE_LATENCY_COMPENSATION,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_bpr_latency" },
    { IEEE80211_PARAM_BEACON_LATENCY_COMPENSATION,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "set_bcn_latency" },
    { IEEE80211_PARAM_BEACON_LATENCY_COMPENSATION,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_bcn_latency" },
    { IEEE80211_PARAM_BCAST_PROBE_RESPONSE_STATS,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_bpr_stats" },
    { IEEE80211_PARAM_BCAST_PROBE_RESPONSE_STATS_CLEAR,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "clr_bpr_stats" },
#endif
    { IEEE80211_PARAM_ONETXCHAIN,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "set_onetxchain" },
    { IEEE80211_PARAM_SET_CABQ_MAXDUR,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "set_cabq_maxdur" },
	{ IEEE80211_PARAM_ENABLE_OL_STATS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "enable_ol_stats" },
   { IEEE80211_PARAM_GET_ACS,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_acs_state" },
    { IEEE80211_PARAM_GET_CAC,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_cac_state" },
    { IEEE80211_PARAM_IMPLICITBF,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "implicitbf" },
    { IEEE80211_PARAM_IMPLICITBF,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_implicitbf" },
	    { IEEE80211_PARAM_VHT_SUBFEE,
	    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "vhtsubfee" },
    { IEEE80211_PARAM_VHT_SUBFEE,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_vhtsubfee" },
    { IEEE80211_PARAM_VHT_MUBFEE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "vhtmubfee" },
    { IEEE80211_PARAM_VHT_MUBFEE,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_vhtmubfee" },
    { IEEE80211_PARAM_VHT_SUBFER,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "vhtsubfer" },
    { IEEE80211_PARAM_VHT_SUBFER,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_vhtsubfer" },
    { IEEE80211_PARAM_VHT_MUBFER,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "vhtmubfer" },
    { IEEE80211_PARAM_VHT_MUBFER,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_vhtmubfer" },
    { IEEE80211_PARAM_VHT_STS_CAP,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "vhtstscap" },
    { IEEE80211_PARAM_VHT_STS_CAP,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_vhtstscap" },
    { IEEE80211_PARAM_VHT_SOUNDING_DIM,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "vhtsounddim" },
    { IEEE80211_PARAM_VHT_SOUNDING_DIM,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_vhtsounddim" },


    { IEEE80211_PARAM_EXT_IFACEUP_ACS,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ext_ifu_acs" },
    { IEEE80211_PARAM_EXT_IFACEUP_ACS, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_ext_ifu_acs" },
    { IEEE80211_PARAM_EXT_ACS_IN_PROGRESS,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ext_acs_prg" },
    { IEEE80211_PARAM_EXT_ACS_IN_PROGRESS, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_ext_acs_prg" },
    { IEEE80211_PARAM_DESIRED_CHANNEL, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_deschan" },
    { IEEE80211_PARAM_DESIRED_PHYMODE, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_desmode" },
    { IEEE80211_PARAM_SEND_ADDITIONAL_IES,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "send_add_ies" },
    { IEEE80211_PARAM_SEND_ADDITIONAL_IES, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_send_add_ies" },
    { IEEE80211_PARAM_START_ACS_REPORT,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "acsreport" },
    { IEEE80211_PARAM_START_ACS_REPORT, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_acsreport" },
    { IEEE80211_PARAM_MIN_DWELL_ACS_REPORT,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "acsmindwell" },
    { IEEE80211_PARAM_MIN_DWELL_ACS_REPORT, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_acsmindwell" },
    { IEEE80211_PARAM_MAX_DWELL_ACS_REPORT,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "acsmaxdwell" },
    { IEEE80211_PARAM_MAX_DWELL_ACS_REPORT, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_acsmaxdwell" },
    { IEEE80211_PARAM_256QAM_2G,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "vht_11ng" },
    { IEEE80211_PARAM_256QAM_2G, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_vht_11ng" },
    { IEEE80211_PARAM_ACS_CH_HOP_LONG_DUR,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ch_long_dur" },
    { IEEE80211_PARAM_ACS_CH_HOP_LONG_DUR, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_ch_long_dur" },
    { IEEE80211_PARAM_ACS_CH_HOP_NO_HOP_DUR,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ch_nhop_dur" },
    { IEEE80211_PARAM_ACS_CH_HOP_NO_HOP_DUR, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_ch_nhop_dur" },
    { IEEE80211_PARAM_ACS_CH_HOP_CNT_WIN_DUR,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ch_cntwn_dur" },
    { IEEE80211_PARAM_ACS_CH_HOP_CNT_WIN_DUR, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_ch_cntwn_dur" },
    { IEEE80211_PARAM_ACS_CH_HOP_NOISE_TH,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ch_noise_th" },
    { IEEE80211_PARAM_ACS_CH_HOP_NOISE_TH, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_ch_noise_th" },
    { IEEE80211_PARAM_ACS_CH_HOP_CNT_TH,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ch_cnt_th" },
    { IEEE80211_PARAM_ACS_CH_HOP_CNT_TH, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_ch_cnt_th"},
    { IEEE80211_PARAM_ACS_ENABLE_CH_HOP,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ch_hop_en" },
    { IEEE80211_PARAM_ACS_ENABLE_CH_HOP, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_ch_hop_en"},
    { IEEE80211_PARAM_MAX_SCANENTRY,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "maxscanentry" },
    { IEEE80211_PARAM_MAX_SCANENTRY,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_maxscanentry" },
    { IEEE80211_PARAM_SCANENTRY_TIMEOUT,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "scanentryage" },
    { IEEE80211_PARAM_SCANENTRY_TIMEOUT,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_scanentryage" },
    { IEEE80211_PARAM_SCAN_MIN_DWELL,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "scanmindwell" },
    { IEEE80211_PARAM_SCAN_MIN_DWELL,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getscanmindwell" },
    { IEEE80211_PARAM_SCAN_MAX_DWELL,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "scanmaxdwell" },
    { IEEE80211_PARAM_SCAN_MAX_DWELL,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getscanmaxdwell" },
#if UMAC_VOW_DEBUG
    { IEEE80211_PARAM_VOW_DBG_ENABLE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "vow_dbg"},
    { IEEE80211_PARAM_VOW_DBG_ENABLE,
    0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_vow_dbg" },
#endif
#if ATH_SUPPORT_SPLITMAC
    { IEEE80211_PARAM_SPLITMAC,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "splitmac"},
    { IEEE80211_PARAM_SPLITMAC,
      0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1,   "get_splitmac" },
#endif
#ifdef ATH_PERF_PWR_OFFLOAD
    { IEEE80211_PARAM_VAP_TX_ENCAP_TYPE,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "encap_type" },
    { IEEE80211_PARAM_VAP_TX_ENCAP_TYPE,
      0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1,   "get_encap_type" },
    { IEEE80211_PARAM_VAP_RX_DECAP_TYPE,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "decap_type" },
    { IEEE80211_PARAM_VAP_RX_DECAP_TYPE,
      0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1,   "get_decap_type" },
#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
    { IEEE80211_PARAM_RAWMODE_SIM_TXAGGR,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "rawsim_txagr" },
    { IEEE80211_PARAM_RAWMODE_SIM_TXAGGR,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_rawsim_txagr" },
    { IEEE80211_PARAM_RAWMODE_PKT_SIM_STATS,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "rawsim_stats" },
    { IEEE80211_PARAM_CLR_RAWMODE_PKT_SIM_STATS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "clr_rawsim_stat" },
    { IEEE80211_PARAM_RAWMODE_SIM_DEBUG,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "rawsim_debug" },
    { IEEE80211_PARAM_RAWMODE_SIM_DEBUG,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_rawsim_debug" },
#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */
#endif /* ATH_PERF_PWR_OFFLOAD */
#if (HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE)
    { IEEE80211_PARAM_TSO_STATS,
	    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_tso_stats" },
    { IEEE80211_PARAM_TSO_STATS_RESET,
	    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "rst_tso_stats" },
#endif /* HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE */
#if HOST_SW_SG_ENABLE
    { IEEE80211_PARAM_SG_STATS,
	    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_sg_stats" },
    { IEEE80211_PARAM_SG_STATS_RESET,
	    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "rst_sg_stats" },
#endif /* HOST_SW_SG_ENABLE */
#if HOST_SW_LRO_ENABLE
    { IEEE80211_PARAM_LRO_STATS,
	    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_lro_stats" },
    { IEEE80211_PARAM_LRO_STATS_RESET,
	    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "rst_lro_stats" },
#endif /* HOST_SW_LRO_ENABLE */
#if RX_CHECKSUM_OFFLOAD
    { IEEE80211_PARAM_RX_CKSUM_ERR_STATS,
	    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_csum_stats" },
    { IEEE80211_PARAM_RX_CKSUM_ERR_RESET,
	    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "rst_csum_stats" },
#endif /* RX_CHECKSUM_OFFLOAD */

    { IEEE80211_IOCTL_GET_MACADDR,
    0, IW_PRIV_TYPE_ACLMACLIST, "" },
    { IEEE80211_PARAM_GET_MAC_LIST_SEC,
    0, IW_PRIV_TYPE_ACLMACLIST, "getmac_sec" },
    { IEEE80211_PARAM_GET_CONFIG_BSSID,
    0, IW_PRIV_TYPE_ACLMACLIST, "get_conf_bssid" },

    { IEEE80211_IOCTL_GET_MACADDR,
      IW_PRIV_TYPE_ADDR | IW_PRIV_SIZE_FIXED | 1, 0, "" },
    { IEEE80211_PARAM_SEND_WOWPKT,
      IW_PRIV_TYPE_ADDR | IW_PRIV_SIZE_FIXED | 1, 0, "sendwowpkt" },
    { IEEE80211_PARAM_ADD_MAC_LIST_SEC,
      IW_PRIV_TYPE_ADDR | IW_PRIV_SIZE_FIXED | 1, 0, "addmac_sec" },
    { IEEE80211_PARAM_DEL_MAC_LIST_SEC,
      IW_PRIV_TYPE_ADDR | IW_PRIV_SIZE_FIXED | 1, 0, "delmac_sec" },
    { IEEE80211_PARAM_CONFIG_BSSID,
      IW_PRIV_TYPE_ADDR | IW_PRIV_SIZE_FIXED | 1, 0, "conf_bssid" },
    { IEEE80211_PARAM_STA_FIXED_RATE,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "sta_fixed_rate" },
    { IEEE80211_PARAM_11NG_VHT_INTEROP,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "11ngvhtintop" },
    { IEEE80211_PARAM_11NG_VHT_INTEROP, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_11ngvhtintop" },
    { IEEE80211_PARAM_RX_SIGNAL_DBM, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_signal_dbm" },
#if QCA_AIRTIME_FAIRNESS
    { IEEE80211_PARAM_ATF_TXBUF_SHARE,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "atf_shr_buf" },
    { IEEE80211_PARAM_ATF_TXBUF_SHARE,
        0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_atf_shr_buf" },
    { IEEE80211_PARAM_ATF_TXBUF_MAX,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "atf_max_buf" },
    { IEEE80211_PARAM_ATF_TXBUF_MAX,
        0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_atf_max_buf" },
    { IEEE80211_PARAM_ATF_TXBUF_MIN,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "atf_min_buf" },
    { IEEE80211_PARAM_ATF_TXBUF_MIN,
        0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_atf_min_buf" },
    { IEEE80211_PARAM_ATF_OPT,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "commitatf" },
    { IEEE80211_PARAM_ATF_OPT,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_commitatf" },
    { IEEE80211_PARAM_ATF_MAX_CLIENT,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "atfmaxclient" },
    { IEEE80211_PARAM_ATF_MAX_CLIENT,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_atfmaxclient" },
    { IEEE80211_PARAM_ATF_PER_UNIT,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "perunit" },
    { IEEE80211_PARAM_ATF_PER_UNIT,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_perunit" },
    { IEEE80211_PARAM_ATF_SSID_GROUP,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "atfssidgroup" },
    { IEEE80211_PARAM_ATF_SSID_GROUP,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_atfssidgroup" },
    { IEEE80211_PARAM_ATF_OVERRIDE_AIRTIME_TPUT,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "atf_tput_at" },
    { IEEE80211_PARAM_ATF_OVERRIDE_AIRTIME_TPUT,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_atf_tput_at" },
#endif
    { IEEE80211_PARAM_BSS_CHAN_INFO,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "bss_chan_info" },
    { IEEE80211_PARAM_TX_MIN_POWER,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_minpower" },
    { IEEE80211_PARAM_TX_MAX_POWER,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_maxpower" },
#if ATH_SSID_STEERING
    { IEEE80211_PARAM_VAP_SSID_CONFIG,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ssid_config" },
    { IEEE80211_PARAM_VAP_SSID_CONFIG,
        0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_ssid_config" },
#endif
    { IEEE80211_PARAM_RX_FILTER_MONITOR,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "set_monrxfilter" },
    { IEEE80211_PARAM_RX_FILTER_MONITOR,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_monrxfilter" },
    { IEEE80211_PARAM_RX_FILTER_NEIGHBOUR_PEERS_MONITOR,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "neighbourfilter" },
    { IEEE80211_PARAM_RX_FILTER_SMART_MONITOR,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_smartmoncfg" },
    { IEEE80211_PARAM_RX_SMART_MONITOR_RSSI,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_smartmonrssi" },
    { IEEE80211_PARAM_RTT_ENABLE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "enable_rtt" },
    { IEEE80211_PARAM_LCI_ENABLE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "enable_lci" },
    { IEEE80211_PARAM_LCR_ENABLE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "enable_lcr" },
    { IEEE80211_PARAM_VAP_ENHIND,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "athnewind" },
    { IEEE80211_PARAM_VAP_ENHIND,0,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_athnewind" },
    { IEEE80211_PARAM_VAP_PAUSE_SCAN,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "pause_scan" },
    { IEEE80211_PARAM_VAP_PAUSE_SCAN,0,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_pause_scan" },
#if ATH_GEN_RANDOMNESS
    { IEEE80211_PARAM_RANDOMGEN_MODE,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "random_gen_mode" },
    { IEEE80211_PARAM_RANDOMGEN_MODE,0,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_random_gen" },
#endif
    { IEEE80211_PARAM_AMPDU_DENSITY_OVERRIDE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ampduden_ovrd" },
    { IEEE80211_PARAM_AMPDU_DENSITY_OVERRIDE,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_ampduden_ovrd" },
    { IEEE80211_PARAM_SMART_MESH_CONFIG,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "smesh_cfg" },
    { IEEE80211_PARAM_SMART_MESH_CONFIG,
        0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_smesh_cfg" },
    /* enable & disable (1/0) Bandwidth-NSS mapping in beacon */
    { IEEE80211_DISABLE_BCN_BW_NSS_MAP,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "bcnbwnssmap" },
    { IEEE80211_DISABLE_BCN_BW_NSS_MAP,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_bcnbwnssmap" },
    /* disable/enable (1/0) advertising Bandwidth-NSS mapping in STA mode*/
    { IEEE80211_DISABLE_STA_BWNSS_ADV,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "blbwnssmap" },
    { IEEE80211_DISABLE_STA_BWNSS_ADV,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_blbwnssmap" },
#if MESH_MODE_SUPPORT
    { IEEE80211_PARAM_ADD_LOCAL_PEER,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 2, 0, "addlocalpeer" },
    { IEEE80211_PARAM_SET_MHDR,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "setmhdr" },
    { IEEE80211_PARAM_ALLOW_DATA,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 2, 0, "allowdata" },
    { IEEE80211_PARAM_SET_MESHDBG,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "meshdbg" },
    { IEEE80211_PARAM_MESH_CAPABILITIES,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "meshcap" },
    { IEEE80211_PARAM_MESH_CAPABILITIES,
        0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_meshcap" },
    { IEEE80211_PARAM_CONFIG_MGMT_TX_FOR_MESH,
         IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1,0, "conf_meshtx" },
    { IEEE80211_PARAM_CONFIG_MGMT_TX_FOR_MESH,
        0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1,"g_conf_meshtx" },
    { IEEE80211_PARAM_CONFIG_RX_MESH_FILTER,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "mesh_rxfilter" },
#endif
#if ATH_DATA_RX_INFO_EN
  { IEEE80211_PARAM_RXINFO_PERPKT,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "rxinfo_perpkt" },
#endif

    { IEEE80211_PARAM_WHC_APINFO_WDS, 0,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_whc_wds" },
    { IEEE80211_PARAM_WHC_APINFO_SON, 0,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_whc_son" },
    { IEEE80211_PARAM_WHC_APINFO_ROOT_DIST,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "set_whc_dist" },
    { IEEE80211_PARAM_WHC_APINFO_ROOT_DIST, 0,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_whc_dist" },
    { IEEE80211_PARAM_WHC_APINFO_SFACTOR,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "set_whc_sfactor" },
    { IEEE80211_PARAM_WHC_APINFO_SFACTOR, 0,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_whc_sfactor" },
    { IEEE80211_PARAM_WHC_APINFO_RATE, 0,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_whc_rate" },
    { IEEE80211_PARAM_WHC_APINFO_UPLINK_RATE,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "set_whc_ul_rate" },
    { IEEE80211_PARAM_WHC_APINFO_UPLINK_RATE, 0,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_whc_ul_rate" },
    { IEEE80211_PARAM_WHC_APINFO_BSSID, 0,
    IW_PRIV_TYPE_CHAR | IW_PRIV_SIZE_FIXED | (IEEE80211_ADDR_LEN * 2), "get_whc_bssid" },
    { IEEE80211_PARAM_WHC_APINFO_CAP_BSSID, 0,
    IW_PRIV_TYPE_CHAR | IW_PRIV_SIZE_FIXED | (IEEE80211_ADDR_LEN * 2), "g_whc_cap_bssid" },
    { IEEE80211_PARAM_WHC_APINFO_BEST_UPLINK_OTHERBAND_BSSID, 0,
    IW_PRIV_TYPE_CHAR | IW_PRIV_SIZE_FIXED | (IEEE80211_ADDR_LEN * 2), "g_best_ob_bssid" },
    { IEEE80211_PARAM_WHC_APINFO_OTHERBAND_UPLINK_BSSID, 0,
    IW_PRIV_TYPE_CHAR | IW_PRIV_SIZE_FIXED | (IEEE80211_ADDR_LEN * 2), "g_whc_ob_bssid" },
    { IEEE80211_PARAM_WHC_APINFO_OTHERBAND_BSSID,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 2, 0, "otherband_bssid" },
    { IEEE80211_PARAM_CONFIG_ASSOC_WAR_160W,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "assocwar160" },
    { IEEE80211_PARAM_CONFIG_ASSOC_WAR_160W,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_assocwar160" },
    { IEEE80211_PARAM_WHC_CAP_RSSI,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "caprssi" },
    { IEEE80211_PARAM_WHC_CAP_RSSI,0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_caprssi" },
    { IEEE80211_PARAM_WHC_CURRENT_CAP_RSSI, 0,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_curr_caprssi" },
    { IEEE80211_PARAM_SON,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "son" },
    { IEEE80211_PARAM_SON,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_son" },
    { IEEE80211_PARAM_REPT_MULTI_SPECIAL,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "rept_spl" },
    { IEEE80211_PARAM_REPT_MULTI_SPECIAL, 0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_rept_spl" },
    { IEEE80211_PARAM_RAWMODE_PKT_SIM,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "rmode_pktsim" },
    { IEEE80211_PARAM_RAWMODE_PKT_SIM,
        0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_rmode_pktsim" },
    { IEEE80211_PARAM_CONFIG_RAW_DWEP_IND,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "rawdwepind" },
    { IEEE80211_PARAM_CONFIG_RAW_DWEP_IND,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_rawdwepind" },
#if UMAC_SUPPORT_ACFG
    { IEEE80211_PARAM_DIAG_WARN_THRESHOLD,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "set_warn_thres" },
    { IEEE80211_PARAM_DIAG_WARN_THRESHOLD,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_warn_thres" },
    { IEEE80211_PARAM_DIAG_ERR_THRESHOLD,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "set_err_thres" },
    { IEEE80211_PARAM_DIAG_ERR_THRESHOLD,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_err_thres" },
#endif
    { IEEE80211_PARAM_TXRX_VAP_STATS,
      IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "txrx_vap_stats" },
    { IEEE80211_PARAM_CONFIG_REV_SIG_160W,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "revsig160" },
    { IEEE80211_PARAM_CONFIG_REV_SIG_160W,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_revsig160" },
    { IEEE80211_PARAM_CONFIG_MU_CAP_WAR,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "mucapwar" },
    { IEEE80211_PARAM_CONFIG_MU_CAP_WAR,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_mucapwar" },
    { IEEE80211_PARAM_CONFIG_MU_CAP_TIMER,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "mudeasoc" },
    { IEEE80211_PARAM_CONFIG_MU_CAP_TIMER,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_mudeasoc" },
    { IEEE80211_PARAM_DISABLE_SELECTIVE_HTMCS_FOR_VAP,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "disable11nmcs" },
    { IEEE80211_PARAM_DISABLE_SELECTIVE_HTMCS_FOR_VAP,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_disable11nmcs" },
    { IEEE80211_PARAM_CONFIGURE_SELECTIVE_VHTMCS_FOR_VAP,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "conf_11acmcs" },
    { IEEE80211_PARAM_CONFIGURE_SELECTIVE_VHTMCS_FOR_VAP,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_conf_11acmcs" },
    { IEEE80211_PARAM_RDG_ENABLE,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "set_RDG_enable" },
    { IEEE80211_PARAM_RDG_ENABLE,
        0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_RDG_enable" },
    { IEEE80211_PARAM_DFS_SUPPORT,
        0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_DFS_support" },
    { IEEE80211_PARAM_DFS_ENABLE,
        0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_DFS_enable" },
    { IEEE80211_PARAM_ACS_SUPPORT,
        0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_ACS_support" },
    { IEEE80211_PARAM_SSID_STATUS,
        0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_SSID_status" },
    { IEEE80211_PARAM_DL_QUEUE_PRIORITY_SUPPORT,
        0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_DL_prisup" },
    { IEEE80211_PARAM_CLEAR_MIN_MAX_RSSI,
        0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "clear_mm_rssi" },
    { IEEE80211_PARAM_CLEAR_QOS,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "clear_qos" },
    { IEEE80211_PARAM_TRAFFIC_STATS,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "set_traf_stat" },
    { IEEE80211_PARAM_TRAFFIC_RATE,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "set_traf_rate" },
    { IEEE80211_PARAM_TRAFFIC_INTERVAL,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "set_traf_int" },
    { IEEE80211_PARAM_WATERMARK_THRESHOLD,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "set_waterm_th" },
    { IEEE80211_PARAM_WATERMARK_THRESHOLD,
        0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_waterm_th" },
    { IEEE80211_PARAM_WATERMARK_REACHED,
        0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_th_reach" },
    { IEEE80211_PARAM_ASSOC_REACHED,
        0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_assoc_reach" },
#if UMAC_SUPPORT_ACL
    { IEEE80211_PARAM_CONFIG_ASSOC_DENIAL_NOTIFY,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "acl_notify" },
    { IEEE80211_PARAM_CONFIG_ASSOC_DENIAL_NOTIFY,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1,"get_acl_notify" },
#endif /* UMAC_SUPPORT_ACL */
    { IEEE80211_PARAM_PEER_TX_MU_BLACKLIST_COUNT,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "mu_blklist_cnt" },
    { IEEE80211_PARAM_PEER_TX_COUNT,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "get_mu_tx_count" },
    { IEEE80211_PARAM_PEER_MUMIMO_TX_COUNT_RESET,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "rst_mu_tx_count" },
    { IEEE80211_PARAM_PEER_POSITION,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "get_mu_peer_pos" },
#if QCA_AIRTIME_FAIRNESS
    { IEEE80211_PARAM_ATF_SSID_SCHED_POLICY,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "atfssidsched" },
    { IEEE80211_PARAM_ATF_SSID_SCHED_POLICY,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_atfssidsched" },
#endif
    { IEEE80211_PARAM_DISABLE_SELECTIVE_LEGACY_RATE_FOR_VAP,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "dis_legacy" },
    { IEEE80211_PARAM_DISABLE_SELECTIVE_LEGACY_RATE_FOR_VAP,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_dis_legacy" },
    { IEEE80211_PARAM_ENABLE_VENDOR_IE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "vie_ena" },
    { IEEE80211_PARAM_ENABLE_VENDOR_IE,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1,"g_vie_ena" },
    { IEEE80211_PARAM_CONFIG_MON_DECODER,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "mon_decoder" },
    { IEEE80211_PARAM_CONFIG_MON_DECODER,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_mon_decoder" },
    { IEEE80211_PARAM_CONFIG_NSTSCAP_WAR,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "nstswar" },
    { IEEE80211_PARAM_CONFIG_NSTSCAP_WAR,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_nstswar" },
    { IEEE80211_PARAM_BEACON_RATE_FOR_VAP,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "set_bcn_rate" },
    { IEEE80211_PARAM_BEACON_RATE_FOR_VAP,
        0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_bcn_rate" },
    { IEEE80211_PARAM_SIFS_TRIGGER_RATE,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "sifs_tr_rate" },
    { IEEE80211_PARAM_SIFS_TRIGGER_RATE,
        0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_sifs_tr_rate" },
    { IEEE80211_PARAM_CHANNEL_SWITCH_MODE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "csmode" },
    { IEEE80211_PARAM_CHANNEL_SWITCH_MODE,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_csmode" },

    { IEEE80211_PARAM_ENABLE_ECSA_IE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "enable_ecsa" },
    { IEEE80211_PARAM_ENABLE_ECSA_IE,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_enable_ecsa" },

    { IEEE80211_PARAM_ECSA_OPCLASS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ecsa_opclass" },
    { IEEE80211_PARAM_ECSA_OPCLASS,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_ecsa_opclass" },
#if DYNAMIC_BEACON_SUPPORT
    { IEEE80211_PARAM_DBEACON_EN,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "dynamicbeacon" },
    { IEEE80211_PARAM_DBEACON_EN,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_dynamicbeacon" },
    { IEEE80211_PARAM_DBEACON_RSSI_THR,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "db_rssi_thr" },
    { IEEE80211_PARAM_DBEACON_RSSI_THR,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_db_rssi_thr" },
    { IEEE80211_PARAM_DBEACON_TIMEOUT,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "db_timeout" },
    { IEEE80211_PARAM_DBEACON_TIMEOUT,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_db_timeout" },
#endif
    { IEEE80211_PARAM_TXPOW_MGMT,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 2, 0, "s_txpow_mgmt" },
    { IEEE80211_PARAM_TXPOW_MGMT ,
        IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_txpow_mgmt" },

    { IEEE80211_PARAM_CONFIG_TX_CAPTURE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "tx_capture" },
    { IEEE80211_PARAM_CONFIG_TX_CAPTURE,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_tx_capture" },
    { IEEE80211_PARAM_BACKHAUL,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "backhaul" },
    { IEEE80211_PARAM_BACKHAUL,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get_backhaul" },
    { IEEE80211_PARAM_EXT_NSS_CAPABLE,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ext_nss" },
    { IEEE80211_PARAM_EXT_NSS_CAPABLE,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_ext_nss" },
    { IEEE80211_PARAM_SEND_PROBE_REQ,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "sendprobereq" },
    { IEEE80211_PARAM_CSL_SUPPORT,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "csl" },
    { IEEE80211_PARAM_CSL_SUPPORT,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_csl" },
    { IEEE80211_PARAM_CONFIG_TX_CAPTURE_DA,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "tx_capture_da" },
    { IEEE80211_PARAM_CONFIG_TX_CAPTURE_DA,
    0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_tx_capture_da" },
    { IEEE80211_PARAM_EXT_NSS_SUPPORT,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ext_nss_sup" },
    { IEEE80211_PARAM_EXT_NSS_SUPPORT,
    0,IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_ext_nss_sup" },
    { IEEE80211_PARAM_DISABLE_CABQ,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "disable_cabq" },
    { IEEE80211_PARAM_DISABLE_CABQ,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_disable_cabq" },
#if UMAC_SUPPORT_FILS
    { IEEE80211_PARAM_ENABLE_FILS,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "enable_fils" },
    { IEEE80211_PARAM_ENABLE_FILS,0,
    IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "g_enable_fils" },
#endif
};

static const iw_handler ieee80211_handlers[] = {
    (iw_handler) NULL,              /* SIOCSIWCOMMIT */
    (iw_handler) ieee80211_ioctl_giwname,       /* SIOCGIWNAME */
    (iw_handler) NULL,              /* SIOCSIWNWID */
    (iw_handler) NULL,              /* SIOCGIWNWID */
    (iw_handler) ieee80211_ioctl_siwfreq,       /* SIOCSIWFREQ */
    (iw_handler) ieee80211_ioctl_giwfreq,       /* SIOCGIWFREQ */
    (iw_handler) ieee80211_ioctl_siwmode,       /* SIOCSIWMODE */
    (iw_handler) ieee80211_ioctl_giwmode,       /* SIOCGIWMODE */
    (iw_handler) NULL,       /* SIOCSIWSENS */
    (iw_handler) NULL,       /* SIOCGIWSENS */
    (iw_handler) NULL /* not used */,       /* SIOCSIWRANGE */
    (iw_handler) ieee80211_ioctl_giwrange,  /* SIOCGIWRANGE */
    (iw_handler) NULL /* not used */,       /* SIOCSIWPRIV */
    (iw_handler) NULL /* kernel code */,        /* SIOCGIWPRIV */
    (iw_handler) NULL /* not used */,       /* SIOCSIWSTATS */
    (iw_handler) NULL /* kernel code */,        /* SIOCGIWSTATS */
#if ATH_SUPPORT_IWSPY
    (iw_handler) ieee80211_ioctl_siwspy,              /* SIOCSIWSPY */
    (iw_handler) ieee80211_ioctl_giwspy,              /* SIOCGIWSPY */
#else
    (iw_handler) NULL,              /* SIOCSIWSPY */
    (iw_handler) NULL,              /* SIOCGIWSPY */
#endif
    (iw_handler) NULL,              /* -- hole -- */
    (iw_handler) NULL,              /* -- hole -- */
    (iw_handler) ieee80211_ioctl_siwap,     /* SIOCSIWAP */
    (iw_handler) ieee80211_ioctl_giwap,     /* SIOCGIWAP */
#ifdef SIOCSIWMLME
    (iw_handler) NULL,      /* SIOCSIWMLME */
#else
    (iw_handler) NULL,              /* -- hole -- */
#endif
    (iw_handler) ieee80211_ioctl_iwaplist,      /* SIOCGIWAPLIST */
#ifdef SIOCGIWSCAN
    (iw_handler) ieee80211_ioctl_siwscan,       /* SIOCSIWSCAN */
    (iw_handler) ieee80211_ioctl_giwscan,       /* SIOCGIWSCAN */
#else
    (iw_handler) NULL,              /* SIOCSIWSCAN */
    (iw_handler) NULL,              /* SIOCGIWSCAN */
#endif /* SIOCGIWSCAN */
    (iw_handler) ieee80211_ioctl_siwessid,      /* SIOCSIWESSID */
    (iw_handler) ieee80211_ioctl_giwessid,      /* SIOCGIWESSID */
    (iw_handler) NULL,      /* SIOCSIWNICKN */
    (iw_handler) NULL,      /* SIOCGIWNICKN */
    (iw_handler) NULL,              /* -- hole -- */
    (iw_handler) NULL,              /* -- hole -- */
    (iw_handler) ieee80211_ioctl_siwrate,       /* SIOCSIWRATE */
    (iw_handler) ieee80211_ioctl_giwrate,       /* SIOCGIWRATE */
    (iw_handler) ieee80211_ioctl_siwrts,        /* SIOCSIWRTS */
    (iw_handler) ieee80211_ioctl_giwrts,        /* SIOCGIWRTS */
    (iw_handler) ieee80211_ioctl_siwfrag,       /* SIOCSIWFRAG */
    (iw_handler) ieee80211_ioctl_giwfrag,       /* SIOCGIWFRAG */
    (iw_handler) ieee80211_ioctl_siwtxpow,      /* SIOCSIWTXPOW */
    (iw_handler) ieee80211_ioctl_giwtxpow,      /* SIOCGIWTXPOW */
    (iw_handler) NULL,      /* SIOCSIWRETRY */
    (iw_handler) NULL,      /* SIOCGIWRETRY */
    (iw_handler) ieee80211_ioctl_siwencode,     /* SIOCSIWENCODE */
    (iw_handler) ieee80211_ioctl_giwencode,     /* SIOCGIWENCODE */
    (iw_handler) ieee80211_ioctl_siwpower,      /* SIOCSIWPOWER */
    (iw_handler) ieee80211_ioctl_giwpower,      /* SIOCGIWPOWER */
    (iw_handler) NULL,              /* -- hole -- */
    (iw_handler) NULL,              /* -- hole -- */
#if WIRELESS_EXT >= 18
    (iw_handler) ieee80211_ioctl_siwgenie /* NULL */,      /* SIOCSIWGENIE */
    (iw_handler) ieee80211_ioctl_giwgenie /* NULL */,      /* SIOCGIWGENIE */
    (iw_handler) ieee80211_ioctl_siwauth  /* NULL */,      /* SIOCSIWAUTH */
    (iw_handler) ieee80211_ioctl_giwauth  /* NULL */,      /* SIOCGIWAUTH */
    (iw_handler) ieee80211_ioctl_siwencodeext /*NULL */ ,  /* SIOCSIWENCODEEXT */
    (iw_handler) NULL,  /* SIOCGIWENCODEEXT */
#endif /* WIRELESS_EXT >= 18 */
};

static const iw_handler ieee80211_priv_handlers[] = {
    (iw_handler) ieee80211_ioctl_setparam,      /* SIOCWFIRSTPRIV+0 */
    (iw_handler) ieee80211_ioctl_getparam,      /* SIOCWFIRSTPRIV+1 */
    (iw_handler) ieee80211_ioctl_setkey,        /* SIOCWFIRSTPRIV+2 */
    (iw_handler) ieee80211_ioctl_setwmmparams,  /* SIOCWFIRSTPRIV+3 */
    (iw_handler) ieee80211_ioctl_delkey,        /* SIOCWFIRSTPRIV+4 */
    (iw_handler) ieee80211_ioctl_getwmmparams,  /* SIOCWFIRSTPRIV+5 */
    (iw_handler) ieee80211_ioctl_setmlme,       /* SIOCWFIRSTPRIV+6 */
    (iw_handler) ieee80211_ioctl_getchaninfo,   /* SIOCWFIRSTPRIV+7 */
    (iw_handler) ieee80211_ioctl_setoptie,      /* SIOCWFIRSTPRIV+8 */
    (iw_handler) ieee80211_ioctl_getoptie,      /* SIOCWFIRSTPRIV+9 */
    (iw_handler) ieee80211_ioctl_addmac,        /* SIOCWFIRSTPRIV+10 */
    (iw_handler) ieee80211_ioctl_getscanresults,/* SIOCWFIRSTPRIV+11 */
    (iw_handler) ieee80211_ioctl_delmac,        /* SIOCWFIRSTPRIV+12 */
    (iw_handler) ieee80211_ioctl_getchanlist,   /* SIOCWFIRSTPRIV+13 */
    (iw_handler) ieee80211_ioctl_setchanlist,   /* SIOCWFIRSTPRIV+14 */
    (iw_handler) ieee80211_ioctl_kickmac,       /* SIOCWFIRSTPRIV+15 */
    (iw_handler) ieee80211_ioctl_chanswitch,    /* SIOCWFIRSTPRIV+16 */
    (iw_handler) ieee80211_ioctl_getmode,       /* SIOCWFIRSTPRIV+17 */
    (iw_handler) ieee80211_ioctl_setmode,       /* SIOCWFIRSTPRIV+18 */
    (iw_handler) ieee80211_ioctl_getappiebuf,   /* SIOCWFIRSTPRIV+19 */
    (iw_handler) ieee80211_ioctl_setappiebuf,   /* SIOCWFIRSTPRIV+20 */
#if ATH_SUPPORT_IQUE
    (iw_handler) ieee80211_ioctl_setacparams,   /* SIOCWFIRSTPRIV+21 */
#else
    (iw_handler) NULL,                          /* SIOCWFIRSTPRIV+21 */
#endif
    (iw_handler) ieee80211_ioctl_setfilter,     /* SIOCWFIRSTPRIV+22 */
#if ATH_SUPPORT_IQUE
    (iw_handler) ieee80211_ioctl_setrcparams,   /* SIOCWFIRSTPRIV+23 */
#else
    (iw_handler) NULL,                          /* SIOCWFIRSTPRIV+23 */
#endif
    (iw_handler) ieee80211_ioctl_dbgreq,        /* SIOCWFIRSTPRIV+24 */
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
    (iw_handler) ieee80211_ioctl_ald_getStatistics, /* SIOCWFIRSTPRIV+25 */
#else
    (iw_handler) NULL,                          /* SIOCWFIRSTPRIV+25 */
#endif
    (iw_handler) ieee80211_ioctl_sendmgmt,      /* SIOCWFIRSTPRIV+26 */
#if ATH_SUPPORT_IQUE
    (iw_handler) ieee80211_ioctl_setmedenyentry, /* SIOCWFIRSTPRIV+27 */
#else
    (iw_handler) NULL,                          /* SIOCWFIRSTPRIV+27 */
#endif
    (iw_handler) ieee80211_ioctl_chn_n_widthswitch,  /* SIOCWFIRSTPRIV+28 */
    (iw_handler) ieee80211_ioctl_getaclmac,  /* SIOCWFIRSTPRIV+29 */
#if ATH_SUPPORT_IQUE
    (iw_handler) ieee80211_ioctl_sethbrparams,  /* SIOCWFIRSTPRIV+30 */
#else
    (iw_handler) NULL,
#endif
    (iw_handler) NULL,
#if 0
    /*
     * MCAST_GROUP is used only for debugging, with the conflicting
     * set_rxtimeout disabled.
     */
    (iw_handler) ieee80211_ioctl_mcast_group,   /* SIOCWFIRSTPRIV+31 */
#endif

};

#ifdef ATH_SUPPORT_HTC
#define N(a)    (sizeof (a) / sizeof (a[0]))
static iw_handler ieee80211_wrapper_handlers[N(ieee80211_handlers)];
static iw_handler ieee80211_priv_wrapper_handlers[N(ieee80211_priv_handlers)];

static struct iw_handler_def ieee80211_iw_handler_def = {
    .standard       = (iw_handler *) ieee80211_wrapper_handlers,
    .num_standard       = N(ieee80211_wrapper_handlers),
    .private        = (iw_handler *) ieee80211_priv_wrapper_handlers,
    .num_private        = N(ieee80211_priv_wrapper_handlers),
    .private_args       = (struct iw_priv_args *) ieee80211_priv_args,
    .num_private_args   = N(ieee80211_priv_args),
#if WIRELESS_EXT > 18
    .get_wireless_stats =   ieee80211_iw_getstats
#endif
};
#undef N
#else
static struct iw_handler_def ieee80211_iw_handler_def = {
#define N(a)    (sizeof (a) / sizeof (a[0]))
    .standard       = (iw_handler *) ieee80211_handlers,
    .num_standard       = N(ieee80211_handlers),
    .private        = (iw_handler *) ieee80211_priv_handlers,
    .num_private        = N(ieee80211_priv_handlers),
    .private_args       = (struct iw_priv_args *) ieee80211_priv_args,
    .num_private_args   = N(ieee80211_priv_args),
#if WIRELESS_EXT > 18
    .get_wireless_stats =   ieee80211_iw_getstats
#endif
#undef N
};
#endif

struct ioctl_name_tbl
{
    unsigned int ioctl;
    char *name;
};

static struct ioctl_name_tbl ioctl_names[] =
{
    {SIOCG80211STATS, "SIOCG80211STATS"},
    {SIOC80211IFDESTROY,"SIOC80211IFDESTROY"},
    {IEEE80211_IOCTL_GETKEY, "IEEE80211_IOCTL_GETKEY"},
    {IEEE80211_IOCTL_GETWPAIE,"IEEE80211_IOCTL_GETWPAIE"},
    {IEEE80211_IOCTL_RES_REQ,"IEEE80211_IOCTL_RES_REQ:"},
    {IEEE80211_IOCTL_STA_STATS, "IEEE80211_IOCTL_STA_STATS"},
    {IEEE80211_IOCTL_SCAN_RESULTS,"IEEE80211_IOCTL_SCAN_RESULTS"},
    {IEEE80211_IOCTL_STA_INFO, "IEEE80211_IOCTL_STA_INFO"},
    {IEEE80211_IOCTL_GETMAC, "IEEE80211_IOCTL_GETMAC"},
    {IEEE80211_IOCTL_P2P_BIG_PARAM, "IEEE80211_IOCTL_P2P_BIG_PARAM"},
    {IEEE80211_IOCTL_GET_SCAN_SPACE, "IEEE80211_IOCTL_GET_SCAN_SPACE"},
    {0, NULL}
};

static char *find_std_ioctl_name(int param)
{
    int i = 0;
    for (i = 0; ioctl_names[i].ioctl; i++) {
        if (ioctl_names[i].ioctl == param)
            return(ioctl_names[i].name ? ioctl_names[i].name : "UNNAMED");

    }
    return("Unknown IOCTL");
}

#ifdef ATH_SUPPORT_HTC
/*
 * Wrapper functions for all standard and private IOCTL functions
*/
static int
ieee80211_ioctl_wrapper(struct net_device *dev,
    struct iw_request_info *info,
    union iwreq_data *wrqu, char *extra)
{
#define N(a)    (sizeof (a) / sizeof (a[0]))
    osif_dev *osnetdev = ath_netdev_priv(dev);
    wlan_if_t vap = osnetdev->os_if;
    struct ieee80211com *ic = vap->iv_ic;
    int cmd_id;
    iw_handler handler;

    if ((!ic) ||
        (ic && ic->ic_delete_in_progress)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : #### delete is in progress, ic %p \n", __func__, ic);
        return -EINVAL;
    }

    /* private ioctls */
    if (info->cmd >= SIOCIWFIRSTPRIV) {
        cmd_id = (info->cmd - SIOCIWFIRSTPRIV);
        if (cmd_id < 0 || cmd_id >= N(ieee80211_priv_handlers)) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : #### wrong private ioctl 0x%x\n", __func__, info->cmd);
            return -EINVAL;
        }

        handler = ieee80211_priv_handlers[cmd_id];
        if (handler)
            return handler(dev, info, wrqu, extra);

        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : #### no registered private ioctl function for cmd 0x%x\n", __func__, info->cmd);
    }
    else { /* standard ioctls */
        cmd_id = (info->cmd - SIOCSIWCOMMIT);
        if (cmd_id < 0 || cmd_id >= N(ieee80211_handlers)) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : #### wrong standard ioctl 0x%x\n", __func__, info->cmd);
            return -EINVAL;
        }

        handler = ieee80211_handlers[cmd_id];
        if (handler)
            return handler(dev, info, wrqu, extra);

        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : #### no registered standard ioctl function for cmd 0x%x\n", __func__, info->cmd);
    }

    return -EINVAL;
#undef N
}
#endif


#if QCA_AIRTIME_FAIRNESS
int
ieee80211_ioctl_addsta_tput(struct net_device *dev, struct iwreq *iwr)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211com *ic = vap->iv_ic;
    struct sta_val buf;
    int i;
    u_int8_t mac[IEEE80211_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    if (ic->ic_atf_tput_based) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: throughput based airtime allocation in "
               "use, disable atf and try later\n", __func__);
        return -EBUSY;
    }

    if (copy_from_user(&buf, iwr->u.data.pointer, sizeof(struct sta_val))) {
       QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: copy_from_user error\n", __func__);
       return -EFAULT;
    }

    if (!OS_MEMCMP(buf.sta_mac, mac, IEEE80211_ADDR_LEN)) {
        /* Mac Addr of all 0xFF is used for reserved airtime */
        ic->ic_atf_resv_airtime = (buf.value & ATF_AIRTIME_MASK) >> ATF_AIRTIME_SHIFT;
        if (ic->ic_atf_resv_airtime > 100)
            ic->ic_atf_resv_airtime = 100;
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: reserved airtime %u\n", __func__, ic->ic_atf_resv_airtime);
    } else {
        OS_MEMSET(mac, 0x0, IEEE80211_ADDR_LEN);

        for (i = 0; i < ATF_TPUT_MAX_STA; i++) {
            if (!OS_MEMCMP(ic->ic_atf_tput_tbl[i].mac_addr, buf.sta_mac, IEEE80211_ADDR_LEN)) {
                /* Update existing entry */
                ic->ic_atf_tput_tbl[i].tput = buf.value & ATF_TPUT_MASK;
                ic->ic_atf_tput_tbl[i].airtime = (buf.value & ATF_AIRTIME_MASK) >> ATF_AIRTIME_SHIFT;
                if (ic->ic_atf_tput_tbl[i].airtime > 100)
                    ic->ic_atf_tput_tbl[i].airtime = 100;
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: %02x:%02x:%02x:%02x:%02x:%02x has minimum throughput %u, "
                       "max airtime %u, num entries %u\n", __func__, ic->ic_atf_tput_tbl[i].mac_addr[0],
                       ic->ic_atf_tput_tbl[i].mac_addr[1], ic->ic_atf_tput_tbl[i].mac_addr[2],
                       ic->ic_atf_tput_tbl[i].mac_addr[3], ic->ic_atf_tput_tbl[i].mac_addr[4],
                       ic->ic_atf_tput_tbl[i].mac_addr[5], ic->ic_atf_tput_tbl[i].tput,
                       ic->ic_atf_tput_tbl[i].airtime, ic->ic_atf_tput_tbl_num);
                break;
            }
        }

        if (i == ATF_TPUT_MAX_STA) {
            for (i = 0; i < ATF_TPUT_MAX_STA; i++) {
                if (!OS_MEMCMP(ic->ic_atf_tput_tbl[i].mac_addr, mac, IEEE80211_ADDR_LEN)) {
                    /* Create new entry */
                    OS_MEMCPY(ic->ic_atf_tput_tbl[i].mac_addr, buf.sta_mac, IEEE80211_ADDR_LEN);
                    ic->ic_atf_tput_tbl[i].tput = buf.value & ATF_TPUT_MASK;
                    ic->ic_atf_tput_tbl[i].airtime = (buf.value & ATF_AIRTIME_MASK) >> ATF_AIRTIME_SHIFT;
                    if (ic->ic_atf_tput_tbl[i].airtime > 100)
                        ic->ic_atf_tput_tbl[i].airtime = 100;
                    ic->ic_atf_tput_tbl_num++;
                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: %02x:%02x:%02x:%02x:%02x:%02x has minimum throughput %u, "
                           "max airtime %u, num entries %u\n", __func__, ic->ic_atf_tput_tbl[i].mac_addr[0],
                           ic->ic_atf_tput_tbl[i].mac_addr[1], ic->ic_atf_tput_tbl[i].mac_addr[2],
                           ic->ic_atf_tput_tbl[i].mac_addr[3], ic->ic_atf_tput_tbl[i].mac_addr[4],
                           ic->ic_atf_tput_tbl[i].mac_addr[5], ic->ic_atf_tput_tbl[i].tput,
                           ic->ic_atf_tput_tbl[i].airtime, ic->ic_atf_tput_tbl_num);
                    break;
                }
            }

            if (i == ATF_TPUT_MAX_STA) {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: out of entries\n", __func__);
                return -E2BIG;
            }
        }
    }

    return 0;
}

int
ieee80211_ioctl_delsta_tput(struct net_device *dev, struct iwreq *iwr)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211com *ic = vap->iv_ic;
    struct sta_val buf;
    int i;
    u_int8_t mac[IEEE80211_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    if (ic->ic_atf_tput_based) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: throughput based airtime allocation in "
               "use, disable atf and try later\n", __func__);
        return -EBUSY;
    }

    if (copy_from_user(&buf, iwr->u.data.pointer, sizeof(struct sta_val))) {
       QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: copy_from_user error\n", __func__);
       return -EFAULT;
    }

    if (!OS_MEMCMP(buf.sta_mac, mac, IEEE80211_ADDR_LEN)) {
        /* Clear whole table */
        for (i = 0; i < ATF_TPUT_MAX_STA; i++) {
            OS_MEMSET(ic->ic_atf_tput_tbl[i].mac_addr, 0x0, IEEE80211_ADDR_LEN);
        }
        ic->ic_atf_tput_tbl_num = 0;
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: flushing all entries, num entries %u\n", __func__, ic->ic_atf_tput_tbl_num);
    } else {
        for (i = 0; i < ATF_TPUT_MAX_STA; i++) {
            if (!OS_MEMCMP(ic->ic_atf_tput_tbl[i].mac_addr, buf.sta_mac, IEEE80211_ADDR_LEN)) {
                /* Remove one entry */
                OS_MEMSET(ic->ic_atf_tput_tbl[i].mac_addr, 0x0, IEEE80211_ADDR_LEN);
                ic->ic_atf_tput_tbl_num--;
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: flushing entry, num entries %u\n", __func__, ic->ic_atf_tput_tbl_num);
                break;
            }
        }

        if (i == ATF_TPUT_MAX_STA) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: entry not found\n", __func__);
        }
    }

    return 0;
}

int
ieee80211_ioctl_show_tput(struct net_device *dev, struct iwreq *iwr)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    struct ieee80211com *ic = vap->iv_ic;
    int i;
    u_int8_t mac[IEEE80211_ADDR_LEN] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n\n");
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "reserved airtime      : %u\n", ic->ic_atf_resv_airtime);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "number of entries     : %u\n", ic->ic_atf_tput_tbl_num);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "tput based atf in use : %u\n", ic->ic_atf_tput_based);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "      mac address     tput  airtime\n");
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "-----------------------------------\n");
    for (i = 0; i < ATF_TPUT_MAX_STA; i++) {
        if (OS_MEMCMP(ic->ic_atf_tput_tbl[i].mac_addr, mac, IEEE80211_ADDR_LEN)) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%02x:%02x:%02x:%02x:%02x:%02x %8u %8u\n",
                   ic->ic_atf_tput_tbl[i].mac_addr[0], ic->ic_atf_tput_tbl[i].mac_addr[1],
                   ic->ic_atf_tput_tbl[i].mac_addr[2], ic->ic_atf_tput_tbl[i].mac_addr[3],
                   ic->ic_atf_tput_tbl[i].mac_addr[4], ic->ic_atf_tput_tbl[i].mac_addr[5],
                   ic->ic_atf_tput_tbl[i].tput, ic->ic_atf_tput_tbl[i].airtime);
        }
    }
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n\n");

    return 0;
}
#endif

/*
* Handle private ioctl requests.
*/
int
ieee80211_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
    wlan_if_t vap = NETDEV_TO_VAP(dev);
#ifdef ATH_SUPPORT_HTC
    struct ieee80211com *ic;
#endif

#if QCA_AIRTIME_FAIRNESS
    uint16_t subcmd = 0;
#endif

    if (!vap) {
       return -EINVAL;
    }

#ifdef ATH_SUPPORT_HTC
    ic = vap->iv_ic;

    if ((!ic) ||
        (ic && ic->ic_delete_in_progress)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : #### delete is in progress, ic %p \n", __func__, ic);
        return -EINVAL;
    }
#endif
    debug_print_ioctl(dev->name, cmd, find_std_ioctl_name(cmd));
    switch (cmd)
    {

    case SIOCG80211STATS:
        return _copy_to_user(ifr->ifr_data, &vap->iv_stats,
            sizeof (vap->iv_stats) +
            sizeof(vap->iv_unicast_stats) +
            sizeof(vap->iv_multicast_stats)) ? -EFAULT : 0;

    case SIOC80211IFDESTROY:
        if (!capable(CAP_NET_ADMIN))
            return -EPERM;
        return osif_ioctl_delete_vap(dev);
    case IEEE80211_IOCTL_GETKEY:
        return ieee80211_ioctl_getkey(dev, (struct iwreq *) ifr);
    case IEEE80211_IOCTL_GETWPAIE:
        return ieee80211_ioctl_getwpaie(dev, (struct iwreq *) ifr);
    case IEEE80211_IOCTL_SCAN_RESULTS:
        return ieee80211_ioctl_getscanresults(dev, (struct iwreq *)ifr);
#if UMAC_SUPPORT_STA_STATS
    /* This set of statistics is not completely implemented. Enable
       UMAC_SUPPORT_STA_STATS to avail of the partial list of
       statistics. */
    case IEEE80211_IOCTL_STA_STATS:
        return ieee80211_ioctl_getstastats(dev, (struct iwreq *) ifr);
#endif /* UMAC_SUPPORT_STA_STATS */
    case IEEE80211_IOCTL_STA_INFO:
        return ieee80211_ioctl_getstainfo(dev, (struct iwreq *) ifr);
    case IEEE80211_IOCTL_GETMAC:
        return ieee80211_ioctl_getmac(dev, (struct iwreq *) ifr);
    case IEEE80211_IOCTL_CONFIG_GENERIC:
#if QCA_AIRTIME_FAIRNESS
        subcmd = ieee80211_ioctl_checkatfset(dev, (struct iwreq *) ifr);
        switch (subcmd)
        {
           case IEEE80211_IOCTL_ATF_ADDSSID:
             return ieee80211_ioctl_setatfssid(dev, (struct iwreq *) ifr);
           case IEEE80211_IOCTL_ATF_DELSSID:
             return ieee80211_ioctl_delatfssid(dev, (struct iwreq *) ifr);
           case IEEE80211_IOCTL_ATF_ADDSTA:
             return ieee80211_ioctl_setatfsta(dev, (struct iwreq *) ifr);
           case IEEE80211_IOCTL_ATF_DELSTA:
             return ieee80211_ioctl_delatfsta(dev, (struct iwreq *) ifr);
           case IEEE80211_IOCTL_ATF_SHOWATFTBL:
             return ieee80211_ioctl_showatftable(dev, (struct iwreq *) ifr);
           case IEEE80211_IOCTL_ATF_SHOWAIRTIME:
             return ieee80211_ioctl_showairtime(dev, (struct iwreq *) ifr);
           case IEEE80211_IOCTL_ATF_FLUSHTABLE:
             return ieee80211_ioctl_flushtable(dev, (struct iwreq *) ifr);
           case IEEE80211_IOCTL_ATF_ADDGROUP:
                return ieee80211_ioctl_addatfgroup(dev, (struct iwreq *) ifr);
           case IEEE80211_IOCTL_ATF_CONFIGGROUP:
               return ieee80211_ioctl_configatfgroup(dev, (struct iwreq *) ifr);
           case IEEE80211_IOCTL_ATF_DELGROUP:
               return ieee80211_ioctl_delatfgroup(dev, (struct iwreq *) ifr);
           case IEEE80211_IOCTL_ATF_SHOWGROUP:
                return ieee80211_ioctl_showatfgroup(dev, (struct iwreq *) ifr);
           case IEEE80211_IOCTL_ATF_ADDSTA_TPUT:
                return ieee80211_ioctl_addsta_tput(dev, (struct iwreq *)ifr);
           case IEEE80211_IOCTL_ATF_DELSTA_TPUT:
                return ieee80211_ioctl_delsta_tput(dev, (struct iwreq *)ifr);
           case IEEE80211_IOCTL_ATF_SHOW_TPUT:
                return ieee80211_ioctl_show_tput(dev, (struct iwreq *)ifr);
           default:
             break;
        }
#endif
        return ieee80211_ioctl_config_generic(dev, (struct iwreq *) ifr);
    case IEEE80211_IOCTL_P2P_BIG_PARAM:
        return ieee80211_ioctl_p2p_big_param(dev, (struct iwreq *) ifr);
    case IEEE80211_IOCTL_RES_REQ:
        return ieee80211_ioctl_res_req(dev, (struct iwreq *) ifr);
#ifdef ATH_SUPPORT_LINUX_VENDOR
    case SIOCDEVVENDOR:
        return osif_ioctl_vendor(dev, ifr, 1);
#endif
    case IEEE80211_IOCTL_GET_SCAN_SPACE:
        return ieee80211_ioctl_get_scan_space(dev, (struct iwreq *)ifr);
#if UMAC_SUPPORT_ACFG
    case ACFG_PVT_IOCTL:
        return acfg_handle_vap_ioctl(dev, ifr->ifr_data);
    case LINUX_PVT_SET_VENDORPARAM:
        return ieee80211_set_vap_vendor_param(dev, ifr->ifr_data);
    case LINUX_PVT_GET_VENDORPARAM:
        return ieee80211_get_vap_vendor_param(dev, ifr->ifr_data);
#endif
    }
    return -EOPNOTSUPP;
}

void ieee80211_ioctl_vattach(struct net_device *dev)
{
#ifdef ATH_SUPPORT_HTC
#define N(a)    (sizeof (a) / sizeof (a[0]))
    int index;

    /* initialize handler array */
    for(index = 0; index < N(ieee80211_wrapper_handlers); index++) {
        if(ieee80211_handlers[index])
            ieee80211_wrapper_handlers[index] = ieee80211_ioctl_wrapper;
        else
            ieee80211_wrapper_handlers[index] = NULL;
    }

    for(index = 0; index < N(ieee80211_priv_wrapper_handlers); index++) {
        if(ieee80211_priv_handlers[index])
            ieee80211_priv_wrapper_handlers[index] = ieee80211_ioctl_wrapper;
        else
            ieee80211_priv_wrapper_handlers[index] = NULL;
    }
#endif
#if WIRELESS_EXT <= 18
    dev->get_wireless_stats = ieee80211_iw_getstats;
#endif
    dev->wireless_handlers = &ieee80211_iw_handler_def;
#ifdef ATH_SUPPORT_HTC
#undef N
#endif
}

void
ieee80211_ioctl_vdetach(struct net_device *dev)
{
    dev->wireless_handlers = NULL;
}


/*
*
*  Display information to the console
*/

static void debug_print_ioctl(char *dev_name, int ioctl, char *ioctl_name)
{
    IOCTL_DPRINTF("***dev=%s  ioctl=0x%04x  name=%s\n", dev_name, ioctl, ioctl_name);
}

/*
*
* Search the ieee80211_priv_arg table for IEEE_IOCTL_SETPARAM defines to
* display the param name.
*
* Input:
*  int param - the ioctl number to look for
*      int set_flag - 1 if ioctl is set, 0 if a get
*
* Returns a string to display.
*/
static char *find_ieee_priv_ioctl_name(int param, int set_flag)
{

    struct iw_priv_args *pa = (struct iw_priv_args *) ieee80211_priv_args;
    int num_args  = ieee80211_iw_handler_def.num_private_args;
    int i;
    int found = 0;

    /* sub-ioctls will be after the IEEEE_IOCTL_SETPARAM - skip duplicate defines */
    for (i = 0; i < num_args; i++, pa++) {
        if (pa->cmd == IEEE80211_IOCTL_SETPARAM) {
            found = 1;
            break;
        }
    }

    /* found IEEEE_IOCTL_SETPARAM  */
    if (found) {
        /* now look for the sub-ioctl number */

        for (; i < num_args; i++, pa++) {
            if (pa->cmd == param) {
                if (set_flag) {
                    if (pa->set_args)
                        return(pa->name ? pa->name : "UNNAMED");
                } else if (pa->get_args)
                    return(pa->name ? pa->name : "UNNAMED");
            }
        }
    }
    return("Unknown IOCTL");
}

#if IEEE80211_DEBUG_NODELEAK
static int get_aid_count(struct ieee80211vap *vap)
{
    int i, j;
    int count = 0;
    uint32_t *chunk;

    if (vap == NULL) {
        return -1;
    }
    if (vap->iv_aid_bitmap == NULL) {
        return -2;
    }

    for (i = 0; i < howmany(vap->iv_max_aid, 32); i++) {
        chunk = &vap->iv_aid_bitmap[i];
        for (j = 0; j < 32; j++) {
            if (*chunk & (1 << j)) {
                count++;
            }
        }
    }
    return count;
}

#define IEEE80211_NODE_SAVEQ_DATAQ(_ni)     (&_ni->ni_dataq)
#define IEEE80211_NODE_SAVEQ_MGMTQ(_ni)     (&_ni->ni_mgmtq)
#define IEEE80211_NODE_SAVEQ_QLEN(_nsq)     (_nsq->nsq_len)
#define IEEE80211_NODE_SAVEQ_LOCK(_nsq)      spin_lock(&_nsq->nsq_lock)
#define IEEE80211_NODE_SAVEQ_UNLOCK(_nsq)    spin_unlock(&_nsq->nsq_lock)

static void
wlan_debug_dump_nodequeues_tgt(struct ieee80211_node *ni)
{
    struct node_powersave_queue *ps_q;
    struct ieee80211vap *vap;
    struct ieee80211com *ic;
    struct ath_node *an;
    struct ath_atx_tid *tid;
    struct ath_buf *bf;
    int t;
    int depth;
    int mcast_cnt;
    int line_count;

    vap = ni->ni_vap;
    ic = vap->iv_ic;

    if(ic->ic_is_mode_offload(ic)) {
        return;
    }

    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Node TID Queues");
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,  " (PS dql: ");
    ps_q = IEEE80211_NODE_SAVEQ_DATAQ(ni);
    if (ps_q) {
        IEEE80211_NODE_SAVEQ_LOCK(ps_q);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%d", IEEE80211_NODE_SAVEQ_QLEN(ps_q));
        IEEE80211_NODE_SAVEQ_UNLOCK(ps_q);
    } else {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "0");
    }
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,  " PS mql: ");
    ps_q  = IEEE80211_NODE_SAVEQ_MGMTQ(ni);
    if (ps_q) {
        IEEE80211_NODE_SAVEQ_LOCK(ps_q);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%d", IEEE80211_NODE_SAVEQ_QLEN(ps_q));
        IEEE80211_NODE_SAVEQ_UNLOCK(ps_q);
    } else {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "0");
    }
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "):");

    line_count = 0;
    an = (ATH_NODE_NET80211(ni))->an_sta;
    for (t = 0; t < WME_NUM_TID; t++) {
        tid = ATH_AN_2_TID(an, t);
        depth = 0;
        mcast_cnt = 0;
        TAILQ_FOREACH(bf, &tid->buf_q, bf_list) {
            depth++;
            if (bf->bf_ismcast) {
                mcast_cnt++;
            }
        }
        /* Print TID if packets have been sent, or */
        if (tid->seq_start != 0 ||
            /* packets should be in the queue, or */
            tid->seq_start != tid->seq_next ||
            /* packets are in the queue. */
            depth != 0) {
            line_count++;
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,  "\n   %p: no=%02d ac=0x%p hwq=%d sch=%d p=%d bp=%d cl=%d f=%d ",
                    tid, tid->tidno, tid->ac, (tid->ac != NULL ? tid->ac->qnum : -1),
                    tid->sched, tid->paused, tid->bar_paused, tid->cleanup_inprogress, tid->filtered);
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,  "ss=%d sn=%d d=%d mc=%d ac=%d ap=%d aa=%d as=%d bh=%d bt=%d",
                    tid->seq_start, tid->seq_next, depth, mcast_cnt, tid->addba_exchangecomplete,
                    tid->addba_exchangeinprogress, tid->addba_exchangeattempts, tid->addba_exchangestatuscode,
                    tid->baw_head, tid->baw_tail);
        }
    }
    if (line_count == 0) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " empty\n");
    } else {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n");
    }
}

void (*g_wlan_debug_dump_queues_tgt)(struct ieee80211com *ic) = NULL;

void wlan_debug_dump_queues_tgt_register(void* wlan_debug_dump_queues_tgt_func) {
    g_wlan_debug_dump_queues_tgt = wlan_debug_dump_queues_tgt_func;
}
EXPORT_SYMBOL(wlan_debug_dump_queues_tgt_register);

void ieee80211_dump_node_ref(struct node_trace *ntb);
void
wlan_debug_dump_nodes_tgt(void)
{
    struct ieee80211com *ic;
    struct ieee80211vap *vap;
    struct ieee80211_node_table *nt;
    struct ieee80211_node *ni;
    struct ieee80211_node *next;
    struct net_device *dev;
    OS_BEACON_DECLARE_AND_RESET_VAR(flags);

    for_each_netdev(&init_net, dev) {
        if (strncmp(dev->name, "wifi", 4)) {
            continue;
        }

        ic = (struct ieee80211com *)netdev_priv(dev);
        nt = &ic->ic_sta;

        if (g_wlan_debug_dump_queues_tgt)
            g_wlan_debug_dump_queues_tgt(ic);

        /* wifi information */
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: flags=0x%08x, chan=%02d, opmode=%d\n",
                ((osdev_t)ic->ic_osdev)->netdev->name, ic->ic_flags,
                ieee80211_chan2ieee(ic, ic->ic_curchan), ic->ic_opmode);

        /* vap information */
        TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: node_count=%d, state=%d, state_info=%d, deleted=%d\n",
                    (((osif_dev *)vap->iv_ifp)->netdev)->name, vap->iv_node_count, vap->iv_state,
                    vap->iv_state_info.iv_state, ieee80211_vap_deleted_is_set(vap));
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "      ps_pending=%d, ps_sta=%d, sta_assoc=%d, aid_count=%d, iv_bss=%p, is_deleted=%d\n",
                    vap->iv_ps_pending, vap->iv_ps_sta, vap->iv_sta_assoc, get_aid_count(vap), vap->iv_bss, ((osif_dev *)vap->iv_ifp)->is_deleted);
        }

        /* node information */
        OS_BEACON_READ_LOCK(&nt->nt_nodelock, &lock_state, flags);
        TAILQ_FOREACH_SAFE(ni, &nt->nt_node, ni_list, next) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "0x%p: %pM flags=0x%08x refcnt=%03d (%s)\n",
                ni, ni->ni_macaddr, ni->ni_flags, ieee80211_node_refcnt(ni),
                (((osif_dev *)ni->ni_vap->iv_ifp)->netdev)->name);
        }
        OS_BEACON_READ_UNLOCK(&nt->nt_nodelock, &lock_state, flags);

#if IEEE80211_DEBUG_NODELEAK
        {
        /* allocated node information */
        rwlock_state_t lock_state;
        OS_RWLOCK_READ_LOCK(&ic->ic_nodelock, &lock_state);
        TAILQ_FOREACH(ni, &ic->ic_nodes, ni_alloc_list) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "0x%p: %pM flags=0x%08x refcnt=%03d (%s) bss=%d temp=%d in_tbl=%d dqlen=%u, mqlen=%u, bss_node=%p, is_obss=%d, assoc_msec=%d\n",
                ni, ni->ni_macaddr, ni->ni_flags, ieee80211_node_refcnt(ni),
                (((osif_dev *)ni->ni_vap->iv_ifp)->netdev)->name,
                ni == ni->ni_vap->iv_bss, (ni->ni_flags & IEEE80211_NODE_TEMP) ? 1 : 0, (ni->ni_table) ? 1 : 0,
                ni->ni_dataq.nsq_len, ni->ni_mgmtq.nsq_len, ni->ni_bss_node, (ni->ni_flags & IEEE80211_NODE_EXT_STATS) ? 1 : 0, ni->ni_assocuptime == 0 ? 0 : jiffies_to_msecs((long)jiffies - (long)(ni->ni_assocuptime)));
            //            if(( ni != ni->ni_vap->iv_bss) && ((ni->ni_flags & IEEE80211_NODE_EXT_STATS) == 0)) {
            wlan_debug_dump_nodequeues_tgt(ni);
            if ( 1 ) {
                ieee80211_dump_node_ref(&ni->trace->aponly);
                ieee80211_dump_node_ref(&ni->trace->wireless);
                ieee80211_dump_node_ref(&ni->trace->bs);
                ieee80211_dump_node_ref(&ni->trace->node);
                ieee80211_dump_node_ref(&ni->trace->base);
                ieee80211_dump_node_ref(&ni->trace->crypto);
                ieee80211_dump_node_ref(&ni->trace->if_lmac);
                ieee80211_dump_node_ref(&ni->trace->mlme);
                ieee80211_dump_node_ref(&ni->trace->txrx);
                ieee80211_dump_node_ref(&ni->trace->wds);
                ieee80211_dump_node_ref(&ni->trace->misc);
            }
        }
        OS_RWLOCK_READ_UNLOCK(&ic->ic_nodelock, &lock_state);
        }
#endif
    }
    qdf_assert_always(0);
}
#endif /* IEEE80211_DEBUG_NODELEAK */
