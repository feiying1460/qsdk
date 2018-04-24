/*
 * Copyright (c) 2016-2017 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

/* This is the unified configuration file for iw, acfg and netlink cfg, etc. */
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/utsname.h>
#include <linux/if_arp.h>       /* XXX for ARPHRD_ETHER */
#include <net/iw_handler.h>

#include <asm/uaccess.h>

#include "if_media.h"
#include "_ieee80211.h"
#include <osif_private.h>
#include <wlan_opts.h>
#include <ieee80211_var.h>
#include "ieee80211_rateset.h"
#include "ieee80211_vi_dbg.h"
#if ATH_SUPPORT_IBSS_DFS
#include <ieee80211_regdmn.h>
#endif
#include "ieee80211_power_priv.h"
#include "../vendor/generic/ioctl/ioctl_vendor_generic.h"
#include <ol_if_athvar.h>

#include "if_athvar.h"
#include "if_athproto.h"
#include "base/ieee80211_node_priv.h"
#include "mlme/ieee80211_mlme_priv.h"
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_vdev_if.h>
#endif

#include <ieee80211_rate_estimate.h>

#include "ieee80211_ucfg.h"
#include <ieee80211_acl.h>

#define ONEMBPS 1000
#define HIGHEST_BASIC_RATE 24000
#define THREE_HUNDRED_FIFTY_MBPS 350000

extern int ol_ath_ucfg_get_user_postion(wlan_if_t vaphandle, u_int32_t aid);
extern int ol_ath_ucfg_get_peer_mumimo_tx_count(wlan_if_t vaphandle, u_int32_t aid);
extern int ol_ath_ucfg_reset_peer_mumimo_tx_count(wlan_if_t vaphandle, u_int32_t aid);
extern void osif_vap_down(struct net_device *dev);
static struct ieee80211_channel* checkchan(wlan_if_t vaphandle,
                                          int channel, int secChanOffset);
extern int ieee80211_rate_is_valid_basic(struct ieee80211vap *, u_int32_t);
#if MESH_MODE_SUPPORT
int ieee80211_add_localpeer(wlan_if_t vap, char *params);
int ieee80211_authorise_local_peer(wlan_if_t vap, char *params);
#endif

#if IEEE80211_DEBUG_NODELEAK
void wlan_debug_dump_nodes_tgt(void);
#endif

#ifdef QCA_PARTNER_PLATFORM
extern int wlan_pltfrm_set_param(wlan_if_t vaphandle, u_int32_t val);
extern int wlan_pltfrm_get_param(wlan_if_t vaphandle);
#endif
static const int basic_11b_rate[] = {1000, 2000, 5500, 11000 };
static const int basic_11bgn_rate[] = {1000, 2000, 5500, 6000, 11000, 12000, 24000 };
static const int basic_11na_rate[] = {6000, 12000, 24000 };

#define HIGHEST_BASIC_RATE 24000    /* Highest rate that can be used for mgmt frames */

int ieee80211_rep_datarate_estimater(u_int16_t backhaul_rate,
        u_int16_t ap_rate,
        u_int8_t root_distance,
        u_int8_t scaling_factor);
static int wlan_reset_peer_mumimo_tx_count(wlan_if_t vaphandle, u_int32_t aid)
{
    return ol_ath_ucfg_reset_peer_mumimo_tx_count(vaphandle, aid);
}

/* Get mu tx blacklisted count for the peer */
void wlan_get_mu_tx_blacklist_cnt(ieee80211_vap_t vap,int value)
{
    struct ieee80211_node *node = NULL;
    u_int16_t aid = 0;
    bool found = FALSE;
    struct ieee80211_node_table *nt = &vap->iv_ic->ic_sta;
    TAILQ_FOREACH(node, &nt->nt_node, ni_list) {
       ieee80211_ref_node(node);
       aid = IEEE80211_AID(node->ni_associd);
       ieee80211_free_node(node);
       if (aid == ((u_int16_t)value)) {
           qdf_print("Number of times MU tx blacklisted %u\n",node->ni_stats.ns_tx_mu_blacklisted_cnt);
           found = TRUE;
           break;
       }
    }
    if (found == FALSE) {
       qdf_print("Invalid AID value.\n");
    }
}

int ieee80211_ucfg_set_essid(wlan_if_t vap, ieee80211_ssid *data)
{
    osif_dev *osifp = (osif_dev *)vap->iv_ifp;
    struct net_device *dev = osifp->netdev;
    ieee80211_ssid   tmpssid;
    enum ieee80211_opmode opmode = wlan_vap_get_opmode(vap);

    if (osifp->is_delete_in_progress)
        return -EINVAL;

    if (opmode == IEEE80211_M_WDS)
        return -EOPNOTSUPP;

    if (ieee80211_dfs_is_ap_cac_timer_running(vap->iv_ic) && (opmode == IEEE80211_M_STA))
        return -EINVAL;

    OS_MEMZERO(&tmpssid, sizeof(ieee80211_ssid));

    if(data->len != 0)
    {
        if (data->len > IEEE80211_NWID_LEN)
            data->len = IEEE80211_NWID_LEN;

        tmpssid.len = data->len;
        OS_MEMCPY(tmpssid.ssid, data->ssid, data->len);
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "set SIOC80211NWID, %d characters\n", data->len);
        /*
         * Deduct a trailing \0 since iwconfig passes a string
         * length that includes this.  Unfortunately this means
         * that specifying a string with multiple trailing \0's
         * won't be handled correctly.  Not sure there's a good
         * solution; the API is botched (the length should be
         * exactly those bytes that are meaningful and not include
         * extraneous stuff).
         */
        if (data->len > 0 &&
                tmpssid.ssid[data->len-1] == '\0')
            tmpssid.len--;
    }

#ifdef ATH_SUPERG_XR
    if (vap->iv_xrvap != NULL && !(vap->iv_flags & IEEE80211_F_XR))
    {
        copy_des_ssid(vap->iv_xrvap, vap);
    }
#endif

    wlan_set_desired_ssidlist(vap,1,&tmpssid);

    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " \n DES SSID SET=%s \n", tmpssid.ssid);


#ifdef ATH_SUPPORT_P2P
    /* For P2P supplicant we do not want start connnection as soon as ssid is set */
    /* The difference in behavior between non p2p supplicant and p2p supplicant need to be fixed */
    /* see EV 73753 for more details */
    if ((osifp->os_opmode == IEEE80211_M_P2P_CLIENT
                || osifp->os_opmode == IEEE80211_M_STA
                || osifp->os_opmode == IEEE80211_M_P2P_GO) && !vap->auto_assoc)
        return 0;
#endif

    return (IS_UP(dev) &&
            ((osifp->os_opmode == IEEE80211_M_HOSTAP) || /* Call vap init for AP mode if netdev is UP */
             (vap->iv_ic->ic_roaming != IEEE80211_ROAMING_MANUAL))) ? osif_vap_init(dev, RESCAN) : 0;
}

int ieee80211_ucfg_get_essid(wlan_if_t vap, ieee80211_ssid *data, int *nssid)
{
    enum ieee80211_opmode opmode = wlan_vap_get_opmode(vap);

    if (opmode == IEEE80211_M_WDS)
        return -EOPNOTSUPP;

    *nssid = wlan_get_desired_ssidlist(vap, data, 1);
    if (*nssid <= 0)
    {
        if (opmode == IEEE80211_M_HOSTAP)
            data->len = 0;
        else
            wlan_get_bss_essid(vap, data);
    }

    return 0;
}

int ieee80211_ucfg_set_freq(wlan_if_t vap, int ieeechannel)
{
    int ret;
    struct ieee80211com *ic = vap->iv_ic;

    /* Channel change from user and radar are serialized using IEEE80211_CHANCHANGE_MARKRADAR flag.
     */
    IEEE80211_CHAN_CHANGE_LOCK(ic);
    if (!IEEE80211_CHANCHANGE_STARTED_IS_SET(ic) && !IEEE80211_CHANCHANGE_MARKRADAR_IS_SET(ic)) {
        IEEE80211_CHANCHANGE_STARTED_SET(ic);
        IEEE80211_CHANCHANGE_MARKRADAR_SET(ic);
        IEEE80211_CHAN_CHANGE_UNLOCK(ic);
        ret = ieee80211_ucfg_set_freq_internal(vap,ieeechannel);
        IEEE80211_CHANCHANGE_STARTED_CLEAR(ic);
        IEEE80211_CHANCHANGE_MARKRADAR_CLEAR(ic);
    } else {
        IEEE80211_CHAN_CHANGE_UNLOCK(ic);
        qdf_print("Channel Change is already on, Please try later\n");
        ret = -EBUSY;
    }
    return ret;
}

int ieee80211_ucfg_set_freq_internal(wlan_if_t vap, int ieeechannel)
{
    osif_dev *osnetdev = (osif_dev *)vap->iv_ifp;
    int retval;
    int waitcnt;

    if (osnetdev->is_delete_in_progress)
        return -EINVAL;

    if (ieeechannel == 0)
        ieeechannel = IEEE80211_CHAN_ANY;

    if (vap->iv_opmode == IEEE80211_M_IBSS) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : IBSS desired channel(%d)\n",
                __func__, ieeechannel);
        return wlan_set_desired_ibsschan(vap, ieeechannel);
    }
    else if (vap->iv_opmode == IEEE80211_M_HOSTAP || vap->iv_opmode == IEEE80211_M_MONITOR)
    {
        struct ieee80211com *ic = vap->iv_ic;
        struct ieee80211_channel *channel = NULL;
#if ATH_CHANNEL_BLOCKING
        struct ieee80211_channel *tmp_channel;
#endif
        struct ieee80211vap *tmpvap = NULL;

        if(ieeechannel != IEEE80211_CHAN_ANY){
            channel = ieee80211_find_dot11_channel(ic, ieeechannel, vap->iv_des_cfreq2, vap->iv_des_mode | ic->ic_chanbwflag);
            if (channel == NULL)
            {
                channel = ieee80211_find_dot11_channel(ic, ieeechannel, 0, IEEE80211_MODE_AUTO);
                if (channel == NULL)
                    return -EINVAL;
            }

            if(ieee80211_check_chan_mode_consistency(ic,vap->iv_des_mode,channel))
            {
                struct ieee80211vap *tmpvap = NULL;

                if(IEEE80211_VAP_IS_PUREG_ENABLED(vap))
                    IEEE80211_VAP_PUREG_DISABLE(vap);
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Chan mode consistency failed mode:%d chan:%d\n setting to AUTO mode", vap->iv_des_mode,ieeechannel);

                TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
                    tmpvap->iv_des_mode = IEEE80211_MODE_AUTO;
                }
            }

#if ATH_CHANNEL_BLOCKING
            tmp_channel = channel;
            channel = wlan_acs_channel_allowed(vap, channel, vap->iv_des_mode);
            if (channel == NULL)
            {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "channel blocked by acs\n");
                return -EINVAL;
            }

            if(tmp_channel != channel && ieee80211_check_chan_mode_consistency(ic,vap->iv_des_mode,channel))
            {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Chan mode consistency failed %x %d %d\n", vap->iv_des_mode,ieeechannel,channel->ic_ieee);
                return -EINVAL;
            }
#endif

            if(IEEE80211_IS_CHAN_RADAR(channel))
            {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "radar detected on channel .%d\n",channel->ic_ieee);
                return -EINVAL;
            }

        }

        if (channel != NULL) {
            if (ic->ic_curchan == channel) {
                if (vap->iv_des_chan[vap->iv_des_mode] == channel) {
                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n Channel is configured already!!\n");
                    return EOK;
                } else if ((vap->iv_des_chan[vap->iv_des_mode] != channel) && !ieee80211_vap_active_is_set(vap)){
                    retval = wlan_set_channel(vap, ieeechannel, vap->iv_des_cfreq2);
                    return retval;
                }
            }
        }

        /* In case of special vap mode only one vap will be created so avoiding unnecessary delays */
        if (!vap->iv_special_vap_mode) {
            TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
                if (tmpvap->iv_opmode == IEEE80211_M_STA) {
                    struct ieee80211_node *ni = tmpvap->iv_bss;
                    u_int16_t associd = ni->ni_associd;
                    IEEE80211_DELIVER_EVENT_MLME_DISASSOC_INDICATION(tmpvap, ni->ni_macaddr, associd, IEEE80211_STATUS_UNSPECIFIED);
                } else {
                    osif_dev *tmp_osnetdev = (osif_dev *)tmpvap->iv_ifp;
                    waitcnt = 0;
                    while(((qdf_atomic_read(&(tmpvap->init_in_progress))) &&
                                (tmpvap->iv_state_info.iv_state != IEEE80211_S_DFS_WAIT)) &&
                            waitcnt < OSIF_MAX_STOP_VAP_TIMEOUT_CNT) {
                        schedule_timeout_interruptible(OSIF_STOP_VAP_TIMEOUT);
                        waitcnt++;
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : XXXXXXXX WAITING FOR VAP INIT COMPLETE  \n",__func__);
                    }
                    tmp_osnetdev->is_stop_event_pending = 1;
                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Set freq vap %d stop send + %p\n",tmpvap->iv_unit, tmpvap);
                    /* If ACS is in progress, unregister scan handlers in ACS and cancel the scan*/
                    osif_vap_acs_cancel(tmp_osnetdev->netdev, 1);

                    wlan_mlme_stop_bss(tmpvap, 0);
                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Set freq vap %d stop send -%p\n",tmpvap->iv_unit, tmpvap);
                    /* wait for vap stop event before letting the caller go */
                    waitcnt = 0;
                    schedule_timeout_interruptible(OSIF_STOP_VAP_TIMEOUT);
                    while( tmp_osnetdev->is_stop_event_pending && waitcnt < OSIF_MAX_STOP_VAP_TIMEOUT_CNT) {
                        schedule_timeout_interruptible(OSIF_STOP_VAP_TIMEOUT);
                        waitcnt++;
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : XXXXXXXX WAITING FOR STOP EVENT  \n",__func__);
                    }

                    if (tmp_osnetdev->is_stop_event_pending) {
                        OS_DELAY(1000);
                    }

                    if (tmp_osnetdev->is_stop_event_pending) {
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Timeout waiting for %s vap %d to stop...continuing with other vaps\n", __FUNCTION__,
                                tmp_osnetdev->osif_is_mode_offload ? "OL" : "DA",
                                tmpvap->iv_unit);
#if IEEE80211_DEBUG_NODELEAK
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n%s: ########## INVOKING NODELEAK DEBUG DUMP #############\n", __func__);
			wlan_debug_dump_nodes_tgt();
#endif
                        continue;
                    }
                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Set wait done --%p\n",tmpvap);
                    tmp_osnetdev->is_stop_event_pending = 0;
                }
            }
        } else {
            if (qdf_atomic_read(&(vap->init_in_progress))) {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "VAP init in progress \n");
                return -EINVAL;
            }
        }

        retval = wlan_set_channel(vap, ieeechannel, vap->iv_des_cfreq2);

        /* In case of special vap mode only one vap will be created so avoiding unnecessary delays */
        if (!vap->iv_special_vap_mode) {
            if(!retval) {
                TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
                    struct net_device *tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
                    /* Set the desired chan for other VAP to same a this VAP */
                    /* Set des chan for all VAPs to be same */
                    if(tmpvap->iv_opmode == IEEE80211_M_HOSTAP ||
                            tmpvap->iv_opmode == IEEE80211_M_MONITOR ) {
                        tmpvap->iv_des_chan[vap->iv_des_mode] =
                            vap->iv_des_chan[vap->iv_des_mode];
                    retval = (IS_UP(tmpdev) && (vap->iv_novap_reset == 0)) ? osif_vap_init(tmpdev, RESCAN) : 0;
                    }
                }
            }
        }
        waitcnt = 0;
        while(waitcnt < OSIF_MAX_START_VAP_TIMEOUT_CNT) {
                bool completed = true;
                schedule_timeout_interruptible(OSIF_START_VAP_TIMEOUT);
                TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
                        if ((qdf_atomic_read(&(tmpvap->iv_is_start_sent)))) {
                                completed = false;
                                break;
                        }
                }
                if(completed) {
                        break;
                }
                waitcnt++;
        }
        if(waitcnt == OSIF_MAX_START_VAP_TIMEOUT_CNT) {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Timeout waiting for start response\n", __func__);
        }
        return retval;
    } else {
        retval = wlan_set_channel(vap, ieeechannel, vap->iv_des_cfreq2);
        return retval;
    }
}

int ieee80211_ucfg_set_chanswitch(wlan_if_t vaphandle, u_int8_t chan, u_int8_t tbtt, u_int16_t ch_width)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    int freq;
#ifdef MAGPIE_HIF_GMAC
    struct ieee80211vap *tmp_vap = NULL;
#endif
    u_int32_t flags = 0;
    struct ieee80211_channel    *radar_channel = NULL;

    if (ic->ic_strict_doth && ic->ic_non_doth_sta_cnt) {
            qdf_print("%s: strict_doth is enabled and non_doth_sta_cnt is %d"
                " Discarding channel switch request\n",
                __func__, ic->ic_non_doth_sta_cnt);
        return -EAGAIN;
    }

    freq = ieee80211_ieee2mhz(ic, chan, 0);
    ic->ic_chanchange_channel = NULL;

    if ((ch_width == 0) &&(ieee80211_find_channel(ic, freq, 0, ic->ic_curchan->ic_flags) == NULL)) {
        /* Switching between different modes is not allowed, print ERROR */
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s(): Channel capabilities do not match, chan flags 0x%x\n",
            __func__, ic->ic_curchan->ic_flags);
        return -EINVAL;
    } else {
        if(ch_width != 0){
          /* Set channel, chanflag, channel width from ch_width value */
          if(IEEE80211_IS_CHAN_VHT(ic->ic_curchan)){
            switch(ch_width){
            case CHWIDTH_20:
                flags = IEEE80211_CHAN_11AC_VHT20;
                break;
            case CHWIDTH_40:
                flags = IEEE80211_CHAN_11AC_VHT40PLUS;
                if (ieee80211_find_channel(ic, freq, 0, flags) == NULL) {
                    /*VHT40PLUS is no good, try minus*/
                    flags = IEEE80211_CHAN_11AC_VHT40MINUS;
                }
                break;
            case CHWIDTH_80:
                flags = IEEE80211_CHAN_11AC_VHT80;
                break;
            case CHWIDTH_160:
                if(IEEE80211_IS_CHAN_11AC_VHT80_80(ic->ic_curchan)){
                    flags = IEEE80211_CHAN_11AC_VHT80_80;
                }else{
                    flags = IEEE80211_CHAN_11AC_VHT160;
                }
                break;
            default:
                flags = IEEE80211_CHAN_11AC_VHT20;
                break;
            }
          }
#if ATH_SUPPORT_11N_CHANWIDTH_SWITCH
            else if(IEEE80211_IS_CHAN_11N(ic->ic_curchan)){
                    switch(ch_width){
                    case CHWIDTH_20:
                        flags = IEEE80211_CHAN_11NA_HT20;
                        break;
                    case CHWIDTH_40:
                        flags = IEEE80211_CHAN_11NA_HT40PLUS;
                        if (ieee80211_find_channel(ic, freq, 0, flags) == NULL) {
                            /*HT40PLUS is no good, try minus*/
                            flags = IEEE80211_CHAN_11NA_HT40MINUS;
                        }
                        break;
                    default:
                        flags = IEEE80211_CHAN_11NA_HT20;
                        break;
                    }
            }
#endif
            else{
                /*legacy doesn't support channel width change*/
                return -EINVAL;
            }

            ic->ic_chanchange_channel =
                ieee80211_find_channel(ic, freq, vap->iv_des_cfreq2, flags);

            if (ic->ic_chanchange_channel == NULL) {
                /* Channel is not available for the ch_width */
                return -EINVAL;
            }

            ic->ic_chanchange_secoffset =
                ieee80211_sec_chan_offset(ic->ic_chanchange_channel);

            /* Find destination channel width */
            ic->ic_chanchange_chwidth =
                ieee80211_get_chan_width(ic->ic_chanchange_channel);

            ic->ic_chanchange_chwidth = ch_width;
            ic->ic_chanchange_chanflag = flags;
        }
    }

    if(ic->ic_chanchange_channel != NULL){
        radar_channel = ic->ic_chanchange_channel;
    }else{
        radar_channel = ieee80211_find_channel(ic, freq, vap->iv_des_cfreq2, ic->ic_curchan->ic_flags);
    }

    if(radar_channel){
        if(IEEE80211_IS_CHAN_RADAR(radar_channel)){
            return -EINVAL;
        }
    }else{
        return -EINVAL;
    }

    /*  flag the beacon update to include the channel switch IE */
    ic->ic_chanchange_chan = chan;
    if (tbtt) {
        ic->ic_chanchange_tbtt = tbtt;
    } else {
        ic->ic_chanchange_tbtt = IEEE80211_RADAR_11HCOUNT;
    }
#ifdef MAGPIE_HIF_GMAC
    TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
        ic->ic_chanchange_cnt += ic->ic_chanchange_tbtt;
    }
#endif

    ic->ic_flags |= IEEE80211_F_CHANSWITCH;
    ic->ic_flags_ext2 |= IEEE80211_FEXT2_CSA_WAIT;

    return 0;
}

wlan_chan_t ieee80211_ucfg_get_current_channel(wlan_if_t vaphandle, bool hwChan)
{
    return wlan_get_current_channel(vaphandle, hwChan);
}

wlan_chan_t ieee80211_ucfg_get_bss_channel(wlan_if_t vaphandle)
{
    return wlan_get_bss_channel(vaphandle);
}

int ieee80211_ucfg_delete_vap(wlan_if_t vap)
{
    int status = -1;
    osif_dev *osif = (osif_dev *)wlan_vap_get_registered_handle(vap);
    struct net_device *dev = osif->netdev;

    if (dev) {
        status = osif_ioctl_delete_vap(dev);
    }
    return status;
}

int ieee80211_ucfg_set_rts(wlan_if_t vap, u_int32_t val)
{
    osif_dev *osif = (osif_dev *)wlan_vap_get_registered_handle(vap);
    struct net_device *dev = osif->netdev;
    u_int32_t curval;

    curval = wlan_get_param(vap, IEEE80211_RTS_THRESHOLD);
    if (val != curval)
    {
        wlan_set_param(vap, IEEE80211_RTS_THRESHOLD, val);
        if (IS_UP(dev))
            return osif_vap_init(dev, RESCAN);
    }

    return 0;
}

int ieee80211_ucfg_set_frag(wlan_if_t vap, u_int32_t val)
{
    osif_dev *osif = (osif_dev *)wlan_vap_get_registered_handle(vap);
    struct net_device *dev = osif->netdev;
    u_int32_t curval;

    if(wlan_get_desired_phymode(vap) < IEEE80211_MODE_11NA_HT20)
    {
        curval = wlan_get_param(vap, IEEE80211_FRAG_THRESHOLD);
        if (val != curval)
        {
            wlan_set_param(vap, IEEE80211_FRAG_THRESHOLD, val);
            if (IS_UP(dev))
                return osif_vap_init(dev, RESCAN);
        }
    } else {
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WARNING: Fragmentation with HT mode NOT ALLOWED!!\n");
        return -EINVAL;
    }

    return 0;
}

int ieee80211_ucfg_set_txpow(wlan_if_t vaphandle, int txpow)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    int is2GHz = IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan);
    int fixed = (ic->ic_flags & IEEE80211_F_TXPOW_FIXED) != 0;

    if (txpow > 0) {
        if ((ic->ic_caps & IEEE80211_C_TXPMGT) == 0)
            return -EINVAL;
        /*
         * txpow is in dBm while we store in 0.5dBm units
         */
        if(ic->ic_set_txPowerLimit)
            ic->ic_set_txPowerLimit(ic, 2*txpow, 2*txpow, is2GHz);
        ic->ic_flags |= IEEE80211_F_TXPOW_FIXED;
    }
    else {
        if (!fixed) return EOK;

        if(ic->ic_set_txPowerLimit)
            ic->ic_set_txPowerLimit(ic,IEEE80211_TXPOWER_MAX,
                    IEEE80211_TXPOWER_MAX, is2GHz);
        ic->ic_flags &= ~IEEE80211_F_TXPOW_FIXED;
    }
    return EOK;
}

int ieee80211_ucfg_get_txpow(wlan_if_t vaphandle, int *txpow, int *fixed)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;

    *txpow = (vap->iv_bss) ? (vap->iv_bss->ni_txpower/2) : 0;
    *fixed = (ic->ic_flags & IEEE80211_F_TXPOW_FIXED) != 0;
    return 0;
}

int ieee80211_ucfg_get_txpow_fraction(wlan_if_t vaphandle, int *txpow, int *fixed)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    if (vap->iv_bss)
    qdf_print("vap->iv_bss->ni_txpower = %d\n", vap->iv_bss->ni_txpower);
   *txpow = (vap->iv_bss) ? ((vap->iv_bss->ni_txpower*100)/2) : 0;
   *fixed = (ic->ic_flags & IEEE80211_F_TXPOW_FIXED) != 0;
    return 0;
}


int ieee80211_ucfg_set_ap(wlan_if_t vap, u_int8_t (*des_bssid)[IEEE80211_ADDR_LEN])
{
    osif_dev *osifp = (osif_dev *)wlan_vap_get_registered_handle(vap);
    struct net_device *dev = osifp->netdev;
    u_int8_t zero_bssid[] = { 0,0,0,0,0,0 };
    int status = 0;

    if (wlan_vap_get_opmode(vap) != IEEE80211_M_STA &&
        (u_int8_t)osifp->os_opmode != IEEE80211_M_P2P_DEVICE &&
        (u_int8_t)osifp->os_opmode != IEEE80211_M_P2P_CLIENT) {
        return -EINVAL;
    }

    if (IEEE80211_ADDR_EQ(des_bssid, zero_bssid)) {
        wlan_aplist_init(vap);
    } else {
        status = wlan_aplist_set_desired_bssidlist(vap, 1, des_bssid);
    }
    if (IS_UP(dev))
        return osif_vap_init(dev, RESCAN);

    return status;
}

int ieee80211_ucfg_get_ap(wlan_if_t vap, u_int8_t *addr)
{
    osif_dev *osnetdev = (osif_dev *)wlan_vap_get_registered_handle(vap);
    int status = 0;

    {
        static const u_int8_t zero_bssid[IEEE80211_ADDR_LEN];
        u_int8_t bssid[IEEE80211_ADDR_LEN];

        if(osnetdev->is_up) {
            status = wlan_vap_get_bssid(vap, bssid);
            if (status == EOK) {
                IEEE80211_ADDR_COPY(addr, bssid);
            }
        } else {
            IEEE80211_ADDR_COPY(addr, zero_bssid);
        }
    }

    return status;
}
extern  A_UINT32 dscp_tid_map[64];

static const struct
    {
        char *name;
        int mode;
        int elementconfig;
    } mappings[] = {
    {"AUTO",IEEE80211_MODE_AUTO,0x090909},
    {"11A",IEEE80211_MODE_11A,0x010909},
    {"11B",IEEE80211_MODE_11B,0x090909},
    {"11G",IEEE80211_MODE_11G,0x000909},
    {"FH",IEEE80211_MODE_FH,0x090909},
    {"TA",IEEE80211_MODE_TURBO_A,0x090909},
    {"TG",IEEE80211_MODE_TURBO_G,0x090909},
    {"11NAHT20",IEEE80211_MODE_11NA_HT20,0x010009},
    {"11NGHT20",IEEE80211_MODE_11NG_HT20,0x000009},
    {"11NAHT40PLUS",IEEE80211_MODE_11NA_HT40PLUS,0x010101},
    {"11NAHT40MINUS",IEEE80211_MODE_11NA_HT40MINUS,0x0101FF},
    {"11NGHT40PLUS",IEEE80211_MODE_11NG_HT40PLUS,0x000101},
    {"11NGHT40MINUS",IEEE80211_MODE_11NG_HT40MINUS,0x0001FF},
    {"11NGHT40",IEEE80211_MODE_11NG_HT40,0x000100},
    {"11NAHT40",IEEE80211_MODE_11NA_HT40,0x010100},
    {"11ACVHT20",IEEE80211_MODE_11AC_VHT20,0x010209},
    {"11ACVHT40PLUS",IEEE80211_MODE_11AC_VHT40PLUS,0x010301},
    {"11ACVHT40MINUS",IEEE80211_MODE_11AC_VHT40MINUS,0x0103FF},
    {"11ACVHT40",IEEE80211_MODE_11AC_VHT40,0x010300},
    {"11ACVHT80",IEEE80211_MODE_11AC_VHT80,0x010400},
    {"11ACVHT160",IEEE80211_MODE_11AC_VHT160,0x010500},
    {"11ACVHT80_80",IEEE80211_MODE_11AC_VHT80_80,0x010600},
};

struct elements{
#if _BYTE_ORDER == _BIG_ENDIAN
    char padd;
    char band;
    char bandwidth;
    char extchan;
#else
    char  extchan ;
    char  bandwidth;
    char  band;
    char  padd;
#endif
}  __attribute__ ((packed));

enum  {
      G = 0x0,
      A,
      B = 0x9,
};
enum  {
      NONHT =0x09,
      HT20 =0x0,
      HT40,
      VHT20,
      VHT40,
      VHT80,
      VHT160,
      VHT80_80,
};

#define INVALID_ELEMENT 0x9
#define DEFAULT_EXT_CHAN 0x0
#define MAX_SUPPORTED_MODES 22

static int ieee80211_ucfg_set_extchan( wlan_if_t vap, int extchan )
{
      int elementconfig;
      struct elements *elem;
      int i =0;
      enum ieee80211_phymode  phymode;
      phymode = wlan_get_desired_phymode(vap);
      elementconfig = mappings[phymode].elementconfig ;
      elem = (struct elements *)&elementconfig;
      elem->extchan = extchan;
      for( i = 0; i< MAX_SUPPORTED_MODES ; i ++){
          if( elementconfig == mappings[i].elementconfig)
              break;
      }
      if (i == MAX_SUPPORTED_MODES) {
          QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "unsupported config \n");
          return -1;
      }

      phymode=i;
      return wlan_set_desired_phymode(vap,phymode);
}

static int ieee80211_ucfg_set_bandwidth( wlan_if_t vap, int bandwidth)
{

      int elementconfig;
      struct elements *elem;
      int i =0;
      enum ieee80211_phymode  phymode;
      phymode = wlan_get_desired_phymode(vap);
      elementconfig = mappings[phymode].elementconfig ;
      elem = (struct elements *)&elementconfig;
      elem->bandwidth = bandwidth ;

      if ((bandwidth == HT20) || ( bandwidth == VHT20)){
          elem->extchan = INVALID_ELEMENT;
      }

      if (( bandwidth == HT40) || ( bandwidth == VHT40) ||  ( bandwidth == VHT80) || (bandwidth == VHT160) || (bandwidth == VHT80_80)) {
          if(elem->extchan == INVALID_ELEMENT) {
              elem->extchan = DEFAULT_EXT_CHAN;
          }
      }
      if( bandwidth == NONHT ){
          elem->extchan = INVALID_ELEMENT;
         }

      for( i = 0; i< MAX_SUPPORTED_MODES ; i ++){
          if( elementconfig == mappings[i].elementconfig)
              break;
      }
      if (i == MAX_SUPPORTED_MODES) {
          QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "unsupported config \n");
          return -1;
      }

      phymode=i;
      return wlan_set_desired_phymode(vap,phymode);
}

static int ieee80211_ucfg_set_band( wlan_if_t vap, int band )
{
      int elementconfig;
      struct elements *elem;
      int i =0;
      enum ieee80211_phymode  phymode;
      phymode = wlan_get_desired_phymode(vap);
      elementconfig = mappings[phymode].elementconfig ;
      elem = (struct elements *)&elementconfig;
      elem->band = band;

      if((elem->bandwidth == VHT40 || elem->bandwidth == VHT80 || elem->bandwidth == VHT160 || elem->bandwidth == VHT80_80 )&& band == G)
      {
          elem->bandwidth = HT40;
      }
      if(elem->bandwidth == VHT20 && band == G)
      {
          elem->bandwidth = HT20;
      }
      if( band == B )
      {
          elem->bandwidth = NONHT;
          elem->extchan = INVALID_ELEMENT;
      }
      for( i = 0; i< MAX_SUPPORTED_MODES ; i ++){
          if( elementconfig == mappings[i].elementconfig)
              break;
      }
      if (i == MAX_SUPPORTED_MODES) {
          QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "unsupported config \n");
          return -1;
      }
      phymode=i;
      return wlan_set_desired_phymode(vap,phymode);
}

int ieee80211_ucfg_get_bandwidth( wlan_if_t vap)
{
      int elementconfig;
      struct elements *elem;
      enum ieee80211_phymode  phymode;
      phymode = wlan_get_desired_phymode(vap);
      elementconfig = mappings[phymode].elementconfig ;
      elem = (struct elements *)&elementconfig;
      return(elem->bandwidth);
}
#if ATH_SUPPORT_DSCP_OVERRIDE
int ieee80211_ucfg_vap_get_dscp_tid_map(wlan_if_t vap, u_int8_t tos)
{
     if(vap->iv_override_dscp)
         return vap->iv_dscp_tid_map[(tos >> IP_DSCP_SHIFT) & IP_DSCP_MASK];
     else
	 return dscp_tid_map[(tos >> IP_DSCP_SHIFT) & IP_DSCP_MASK];
}

#endif
int ieee80211_ucfg_get_band( wlan_if_t vap)
{
      int elementconfig;
      struct elements *elem;
      enum ieee80211_phymode  phymode;
      phymode = wlan_get_desired_phymode(vap);
      elementconfig = mappings[phymode].elementconfig ;
      elem = (struct elements *)&elementconfig;
      return(elem->band);
}

int ieee80211_ucfg_get_extchan( wlan_if_t vap)
{
      int elementconfig;
      struct elements *elem;
      enum ieee80211_phymode  phymode;
      phymode = wlan_get_desired_phymode(vap);
      elementconfig = mappings[phymode].elementconfig ;
      elem = (struct elements *)&elementconfig;
      return(elem->extchan);
}

struct find_wlan_node_req {
    wlan_node_t node;
    int assoc_id;
};

static void
find_wlan_node_by_associd(void *arg, wlan_node_t node)
{
    struct find_wlan_node_req *req = (struct find_wlan_node_req *)arg;
    if (req->assoc_id == IEEE80211_AID(wlan_node_get_associd(node))) {
        req->node = node;
    }
}

static struct ieee80211_channel*
checkchan(wlan_if_t vaphandle, int channel, int secChanOffset)
{
    wlan_dev_t ic = wlan_vap_get_devhandle(vaphandle);
    int mode = 0;

#define MAX_2G_OFF_CHANNEL 27
    if (27 > channel) {
        if (secChanOffset == 40)
        mode = IEEE80211_MODE_11NG_HT40PLUS;
        else if (secChanOffset == -40)
            mode = IEEE80211_MODE_11NG_HT40MINUS;
        else
            mode = IEEE80211_MODE_11NG_HT20;
    } else {
        if (secChanOffset == 40)
        mode = IEEE80211_MODE_11NA_HT40PLUS;
        else if (secChanOffset == -40)
            mode = IEEE80211_MODE_11NA_HT40MINUS;
        else
            mode = IEEE80211_MODE_11NA_HT20;
    }
    return ieee80211_find_dot11_channel(ic, channel, 0, mode);
#undef MAX_2G_OFF_CHANNEL
}

#define IEEE80211_BINTVAL_IWMAX       3500   /* max beacon interval */
#define IEEE80211_BINTVAL_IWMIN       40     /* min beacon interval */
#define IEEE80211_BINTVAL_LP_IOT_IWMIN 25    /* min beacon interval for LP IOT */

int ieee80211_ucfg_setparam(wlan_if_t vap, int param, int value, char *extra)
{
    osif_dev  *osifp = (osif_dev *)wlan_vap_get_registered_handle(vap);
    struct net_device *dev = osifp->netdev;
    wlan_if_t tmpvap;
    wlan_dev_t ic = wlan_vap_get_devhandle(vap);
    int retv = 0;
    int error = 0;
    int prev_state = 0;
    int new_state = 0;
    int *val = (int*)extra;
    int deschan;
    int basic_valid_mask = 0;
    struct ieee80211_node *ni = vap->iv_bss;
    struct _rate_table {
        int *rates;
        int nrates;
    }rate_table;
    int found = 0;
    int frame_subtype = val[1];
    int tx_power = val[2];
    u_int8_t transmit_power = 0;
#if ATH_SUPPORT_NR_SYNC
    struct ieee80211com *tmp_ic = NULL;
    int i;
#endif

    if (osifp->is_delete_in_progress)
        return -EINVAL;

    switch (param)
    {
    case IEEE80211_PARAM_PEER_TX_MU_BLACKLIST_COUNT:
        if (value <= 0) {
           qdf_print("Invalid AID value.\n");
           return -EINVAL;
        }
        wlan_get_mu_tx_blacklist_cnt(vap,value);
        break;
    case IEEE80211_PARAM_PEER_TX_COUNT:
        if (ic->ic_vap_set_param) {
	   retv = ic->ic_vap_set_param(vap, IEEE80211_PEER_TX_COUNT_SET, (u_int32_t)value);
        }
        break;
    case IEEE80211_PARAM_PEER_MUMIMO_TX_COUNT_RESET:
	if (ic->ic_vap_set_param) {
            retv = ic->ic_vap_set_param(vap, IEEE80211_PEER_MUMIMO_TX_COUNT_RESET_SET, (u_int32_t)value);
        }
        break;
    case IEEE80211_PARAM_PEER_POSITION:
        if (ic->ic_vap_set_param) {
	    retv = ic->ic_vap_set_param(vap, IEEE80211_PEER_POSITION_SET, (u_int32_t)value);
        }
	break;
    case IEEE80211_PARAM_SET_TXPWRADJUST:
        wlan_set_param(vap, IEEE80211_SET_TXPWRADJUST, value);
        break;
    case IEEE80211_PARAM_MAXSTA: //set max stations allowed
        if (value > ic->ic_num_clients || value < 1) { // At least one station can associate with.
            return -EINVAL;
        }
        if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
            u_int16_t old_max_aid = vap->iv_max_aid;
            u_int16_t old_len = howmany(vap->iv_max_aid, 32) * sizeof(u_int32_t);
            if (value < vap->iv_sta_assoc) {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%d station associated with vap%d! refuse this request\n",
                            vap->iv_sta_assoc, vap->iv_unit);
                return -EINVAL;
            }
            /* We will reject station when associated aid >= iv_max_aid, such that
            max associated station should be value + 1 */
            vap->iv_max_aid = value + 1;
            /* The interface is up, we may need to reallocation bitmap(tim, aid) */
            if (IS_UP(dev)) {
                if (vap->iv_alloc_tim_bitmap) {
                    error = vap->iv_alloc_tim_bitmap(vap);
                }
                if(!error)
                	error = wlan_node_alloc_aid_bitmap(vap, old_len);
            }
            if(!error)
            	QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Setting Max Stations:%d\n", value);
           	else {
          		QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Setting Max Stations fail\n");
          		vap->iv_max_aid = old_max_aid;
          		return -ENOMEM;
          	}
        }
        else {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "This command only support on Host AP mode.\n");
            return -EINVAL;
        }
        break;
    case IEEE80211_PARAM_AUTO_ASSOC:
        wlan_set_param(vap, IEEE80211_AUTO_ASSOC, value);
        break;
    case IEEE80211_PARAM_VAP_COUNTRY_IE:
        wlan_set_param(vap, IEEE80211_FEATURE_COUNTRY_IE, value);
        break;
    case IEEE80211_PARAM_VAP_DOTH:
        wlan_set_param(vap, IEEE80211_FEATURE_DOTH, value);
        break;
    case IEEE80211_PARAM_HT40_INTOLERANT:
        wlan_set_param(vap, IEEE80211_HT40_INTOLERANT, value);
        break;
    case IEEE80211_PARAM_BSS_CHAN_INFO:
	if (value < BSS_CHAN_INFO_READ || value > BSS_CHAN_INFO_READ_AND_CLEAR)
	{
		QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Setting Param value to 1(read only)\n");
		value = BSS_CHAN_INFO_READ;
	}
	ic->ic_ath_bss_chan_info_stats(ic, value);
	break;

    case IEEE80211_PARAM_CHWIDTH:
        wlan_set_param(vap, IEEE80211_CHWIDTH, value);
        break;

    case IEEE80211_PARAM_CHEXTOFFSET:
        wlan_set_param(vap, IEEE80211_CHEXTOFFSET, value);
        break;
#ifdef ATH_SUPPORT_QUICK_KICKOUT
    case IEEE80211_PARAM_STA_QUICKKICKOUT:
            wlan_set_param(vap, IEEE80211_STA_QUICKKICKOUT, value);
        break;
#endif
#if ATH_SUPPORT_DSCP_OVERRIDE
    case IEEE80211_PARAM_VAP_DSCP_PRIORITY:
        retv = wlan_set_vap_priority_dscp_tid_map(vap,value);
        if(retv == EOK)
            retv = wlan_set_param(vap, IEEE80211_VAP_DSCP_PRIORITY, value);
        break;
#endif
    case IEEE80211_PARAM_CHSCANINIT:
        wlan_set_param(vap, IEEE80211_CHSCANINIT, value);
        break;

    case IEEE80211_PARAM_COEXT_DISABLE:
        if (value)
        {
            ic->ic_flags |= IEEE80211_F_COEXT_DISABLE;
        }
        else
        {
            ic->ic_flags &= ~IEEE80211_F_COEXT_DISABLE;
        }
        TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
            struct net_device *tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
            osifp = ath_netdev_priv(tmpdev);
            /* Bring down vap gracefully so flags are properly reset */
            osif_vap_down(tmpdev);
        }
        TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
            struct net_device *tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
            if( IS_UP(tmpdev) )
                osif_vap_init(tmpdev, RESCAN);
        }
        break;
#if ATH_SUPPORT_NR_SYNC
    case IEEE80211_PARAM_NR_SHARE_RADIO_FLAG:
        if(value == 0xff) {
            qdf_print("This feature is disabled, entered value :%d \n",value);
            qdf_print("Enter valid flag flag[0 ~ %d]! to Enable this feature \n",
                    (1 << MAX_RADIO_CNT) - 1);
        } else {
            if ((value < 0) || (value >= (1 << MAX_RADIO_CNT))) {
                qdf_print("please input valid flag[0 ~ %d]!\n", (1 << MAX_RADIO_CNT) - 1);
                return -EINVAL;
            }
        }
        /* sync the flag to all radios */
        for (i = 0; i < MAX_RADIO_CNT; i++) {
            tmp_ic = ic->ic_global_list->global_ic[i];
            if(tmp_ic)
                tmp_ic->ic_nr_share_radio_flag = value;
        }
        break;
#endif
    case IEEE80211_PARAM_AUTHMODE:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "set IEEE80211_IOC_AUTHMODE to %s\n",
        (value == IEEE80211_AUTH_WPA) ? "WPA" : (value == IEEE80211_AUTH_8021X) ? "802.1x" :
        (value == IEEE80211_AUTH_OPEN) ? "open" : (value == IEEE80211_AUTH_SHARED) ? "shared" :
        (value == IEEE80211_AUTH_AUTO) ? "auto" : "unknown" );
	if (ieee80211_dfs_is_ap_cac_timer_running(vap->iv_ic) && (wlan_vap_get_opmode(vap) == IEEE80211_M_STA)) {
	    return -EINVAL;
	}
        osifp->authmode = value;

        if (value != IEEE80211_AUTH_WPA) {
            ieee80211_auth_mode modes[1];
            u_int nmodes=1;
            modes[0] = value;
            error = wlan_set_authmodes(vap,modes,nmodes);
            if (error == 0 ) {
                if ((value == IEEE80211_AUTH_OPEN) || (value == IEEE80211_AUTH_SHARED)) {
                    error = wlan_set_param(vap,IEEE80211_FEATURE_PRIVACY, 0);
                    osifp->uciphers[0] = osifp->mciphers[0] = IEEE80211_CIPHER_NONE;
                    osifp->u_count = osifp->m_count = 1;
                } else {
                    error = wlan_set_param(vap,IEEE80211_FEATURE_PRIVACY, 1);
                }
            }
        }
        /*
        * set_auth_mode will reset the ucast and mcast cipher set to defaults,
        * we will reset them from our cached values for non-open mode.
        */
        if ((value != IEEE80211_AUTH_OPEN) && (value != IEEE80211_AUTH_SHARED)
                && (value != IEEE80211_AUTH_AUTO))
        {
            if (osifp->m_count)
                error = wlan_set_mcast_ciphers(vap,osifp->mciphers,osifp->m_count);
            if (osifp->u_count)
                error = wlan_set_ucast_ciphers(vap,osifp->uciphers,osifp->u_count);
        }

#ifdef ATH_SUPPORT_P2P
        /* For P2P supplicant we do not want start connnection as soon as auth mode is set */
        /* The difference in behavior between non p2p supplicant and p2p supplicant need to be fixed */
        /* see EV 73753 for more details */
        if (error == 0 && osifp->os_opmode != IEEE80211_M_P2P_CLIENT && osifp->os_opmode != IEEE80211_M_STA) {
            retv = ENETRESET;
        }
#else
        if (error == 0 ) {
            retv = ENETRESET;
        }

#endif /* ATH_SUPPORT_P2P */
        else {
            retv = error;
        }
        break;
    case IEEE80211_PARAM_MCASTKEYLEN:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "set IEEE80211_IOC_MCASTKEYLEN to %d\n", value);
        if (!(0 < value && value < IEEE80211_KEYBUF_SIZE)) {
            error = -EINVAL;
            break;
        }
        error = wlan_set_rsn_cipher_param(vap,IEEE80211_MCAST_CIPHER_LEN,value);
        retv = error;
        break;
    case IEEE80211_PARAM_UCASTCIPHERS:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "set IEEE80211_IOC_UCASTCIPHERS (0x%x) %s %s %s %s %s %s %s\n",
                value, (value & 1<<IEEE80211_CIPHER_WEP) ? "WEP" : "",
                (value & 1<<IEEE80211_CIPHER_TKIP) ? "TKIP" : "",
                (value & 1<<IEEE80211_CIPHER_AES_OCB) ? "AES-OCB" : "",
                (value & 1<<IEEE80211_CIPHER_AES_CCM) ? "AES-CCMP 128" : "",
                (value & 1<<IEEE80211_CIPHER_AES_CCM_256) ? "AES-CCMP 256" : "",
                (value & 1<<IEEE80211_CIPHER_AES_GCM) ? "AES-GCMP 128" : "",
                (value & 1<<IEEE80211_CIPHER_AES_GCM_256) ? "AES-GCMP 256" : "",
                (value & 1<<IEEE80211_CIPHER_CKIP) ? "CKIP" : "",
                (value & 1<<IEEE80211_CIPHER_WAPI) ? "WAPI" : "",
                (value & 1<<IEEE80211_CIPHER_NONE) ? "NONE" : "");
        {
            int count=0;
            if (value & 1<<IEEE80211_CIPHER_WEP)
                osifp->uciphers[count++] = IEEE80211_CIPHER_WEP;
            if (value & 1<<IEEE80211_CIPHER_TKIP)
                osifp->uciphers[count++] = IEEE80211_CIPHER_TKIP;
            if (value & 1<<IEEE80211_CIPHER_AES_CCM)
                osifp->uciphers[count++] = IEEE80211_CIPHER_AES_CCM;
            if (value & 1<<IEEE80211_CIPHER_AES_CCM_256)
                osifp->uciphers[count++] = IEEE80211_CIPHER_AES_CCM_256;
            if (value & 1<<IEEE80211_CIPHER_AES_GCM)
                osifp->uciphers[count++] = IEEE80211_CIPHER_AES_GCM;
            if (value & 1<<IEEE80211_CIPHER_AES_GCM_256)
                osifp->uciphers[count++] = IEEE80211_CIPHER_AES_GCM_256;
            if (value & 1<<IEEE80211_CIPHER_CKIP)
                osifp->uciphers[count++] = IEEE80211_CIPHER_CKIP;
#if ATH_SUPPORT_WAPI
            if (value & 1<<IEEE80211_CIPHER_WAPI)
                osifp->uciphers[count++] = IEEE80211_CIPHER_WAPI;
#endif
            if (value & 1<<IEEE80211_CIPHER_NONE)
                osifp->uciphers[count++] = IEEE80211_CIPHER_NONE;
            error = wlan_set_ucast_ciphers(vap,osifp->uciphers,count);
            if (error == 0) {
                error = ENETRESET;
            }
            else {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s Warning: wlan_set_ucast_cipher failed. cache the ucast cipher\n", __func__);
                error=0;
            }
            osifp->u_count=count;


        }
        retv = error;
        break;
    case IEEE80211_PARAM_UCASTCIPHER:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "set IEEE80211_IOC_UCASTCIPHER to %s\n",
                (value == IEEE80211_CIPHER_WEP) ? "WEP" :
                (value == IEEE80211_CIPHER_TKIP) ? "TKIP" :
                (value == IEEE80211_CIPHER_AES_OCB) ? "AES OCB" :
                (value == IEEE80211_CIPHER_AES_CCM) ? "AES CCM 128" :
                (value == IEEE80211_CIPHER_AES_CCM_256) ? "AES CCM 256" :
                (value == IEEE80211_CIPHER_AES_GCM) ? "AES GCM 128" :
                (value == IEEE80211_CIPHER_AES_GCM_256) ? "AES GCM 256" :
                (value == IEEE80211_CIPHER_CKIP) ? "CKIP" :
                (value == IEEE80211_CIPHER_WAPI) ? "WAPI" :
                (value == IEEE80211_CIPHER_NONE) ? "NONE" : "unknown");
        {
            ieee80211_cipher_type ctypes[1];
            ctypes[0] = (ieee80211_cipher_type) value;
            error = wlan_set_ucast_ciphers(vap,ctypes,1);
            /* save the ucast cipher info */
            osifp->uciphers[0] = ctypes[0];
            osifp->u_count=1;
            if (error == 0) {
                retv = ENETRESET;
            }
            else {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s Warning: wlan_set_ucast_cipher failed. cache the ucast cipher\n", __func__);
                error=0;
            }
        }
        retv = error;
        break;
    case IEEE80211_PARAM_MCASTCIPHER:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "set IEEE80211_IOC_MCASTCIPHER to %s\n",
                        (value == IEEE80211_CIPHER_WEP) ? "WEP" :
                        (value == IEEE80211_CIPHER_TKIP) ? "TKIP" :
                        (value == IEEE80211_CIPHER_AES_OCB) ? "AES OCB" :
                        (value == IEEE80211_CIPHER_AES_CCM) ? "AES CCM 128" :
                        (value == IEEE80211_CIPHER_AES_CCM_256) ? "AES CCM 256" :
                        (value == IEEE80211_CIPHER_AES_GCM) ? "AES GCM 128" :
                        (value == IEEE80211_CIPHER_AES_GCM_256) ? "AES GCM 256" :
                        (value == IEEE80211_CIPHER_CKIP) ? "CKIP" :
                        (value == IEEE80211_CIPHER_WAPI) ? "WAPI" :
                        (value == IEEE80211_CIPHER_NONE) ? "NONE" : "unknown");
        {
            ieee80211_cipher_type ctypes[1];
            ctypes[0] = (ieee80211_cipher_type) value;
            error = wlan_set_mcast_ciphers(vap, ctypes, 1);
            /* save the mcast cipher info */
            osifp->mciphers[0] = ctypes[0];
            osifp->m_count=1;
            if (error) {
                /*
                * ignore the error for now.
                * both the ucast and mcast ciphers
                * are set again when auth mode is set.
                */
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"%s", "Warning: wlan_set_mcast_cipher failed. cache the mcast cipher  \n");
                error=0;
            }
        }
        retv = error;
        break;
    case IEEE80211_PARAM_UCASTKEYLEN:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "set IEEE80211_IOC_UCASTKEYLEN to %d\n", value);
        if (!(0 < value && value < IEEE80211_KEYBUF_SIZE)) {
            error = -EINVAL;
            break;
        }
        error = wlan_set_rsn_cipher_param(vap,IEEE80211_UCAST_CIPHER_LEN,value);
        retv = error;
        break;
    case IEEE80211_PARAM_PRIVACY:
        retv = wlan_set_param(vap,IEEE80211_FEATURE_PRIVACY,value);
        break;
    case IEEE80211_PARAM_COUNTERMEASURES:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_COUNTER_MEASURES, value);
        break;
    case IEEE80211_PARAM_HIDESSID:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_HIDE_SSID, value);
        if (retv == EOK) {
            retv = ENETRESET;
        }
        break;
    case IEEE80211_PARAM_APBRIDGE:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_APBRIDGE, value);
        break;
    case IEEE80211_PARAM_KEYMGTALGS:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "set IEEE80211_IOC_KEYMGTALGS (0x%x) %s %s\n",
        value, (value & WPA_ASE_8021X_UNSPEC) ? "802.1x Unspecified" : "",
        (value & WPA_ASE_8021X_PSK) ? "802.1x PSK" : "");
        error = wlan_set_rsn_cipher_param(vap,IEEE80211_KEYMGT_ALGS,value);
        retv = error;
        break;
    case IEEE80211_PARAM_RSNCAPS:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "set IEEE80211_IOC_RSNCAPS to 0x%x\n", value);
        error = wlan_set_rsn_cipher_param(vap,IEEE80211_RSN_CAPS,value);
        retv = error;
        if (value & RSN_CAP_MFP_ENABLED) {
            /*
             * 802.11w PMF is enabled so change hw MFP QOS bits
             */
            wlan_crypto_set_hwmfpQos(vap, 1);
        }
        break;
    case IEEE80211_PARAM_WPA:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "set IEEE80211_IOC_WPA to %s\n",
        (value == 1) ? "WPA" : (value == 2) ? "RSN" :
        (value == 3) ? "WPA and RSN" : (value == 0)? "off" : "unknown");
        if (value > 3) {
            error = -EINVAL;
            break;
        } else {
            ieee80211_auth_mode modes[2];
            u_int nmodes=1;
            if (osifp->os_opmode == IEEE80211_M_STA ||
                osifp->os_opmode == IEEE80211_M_P2P_CLIENT) {
                error = wlan_set_rsn_cipher_param(vap,IEEE80211_KEYMGT_ALGS,WPA_ASE_8021X_PSK);
                if (!error) {
                    if ((value == 3) || (value == 2)) { /* Mixed mode or WPA2 */
                        modes[0] = IEEE80211_AUTH_RSNA;
                    } else { /* WPA mode */
                        modes[0] = IEEE80211_AUTH_WPA;
                    }
                }
                /* set supported cipher to TKIP and CCM
                * to allow WPA-AES, WPA2-TKIP: and MIXED mode
                */
                osifp->u_count = 2;
                osifp->uciphers[0] = IEEE80211_CIPHER_TKIP;
                osifp->uciphers[1] = IEEE80211_CIPHER_AES_CCM;
                osifp->m_count = 2;
                osifp->mciphers[0] = IEEE80211_CIPHER_TKIP;
                osifp->mciphers[1] = IEEE80211_CIPHER_AES_CCM;
            }
            else {
                if (value == 3) {
                    nmodes = 2;
                    modes[0] = IEEE80211_AUTH_WPA;
                    modes[1] = IEEE80211_AUTH_RSNA;
                } else if (value == 2) {
                    modes[0] = IEEE80211_AUTH_RSNA;
                } else {
                    modes[0] = IEEE80211_AUTH_WPA;
                }
            }
            error = wlan_set_authmodes(vap,modes,nmodes);
            /*
            * set_auth_mode will reset the ucast and mcast cipher set to defaults,
            * we will reset them from our cached values.
            */
            if (osifp->m_count)
                error = wlan_set_mcast_ciphers(vap,osifp->mciphers,osifp->m_count);
            if (osifp->u_count)
                error = wlan_set_ucast_ciphers(vap,osifp->uciphers,osifp->u_count);
        }
        retv = error;
        break;

    case IEEE80211_PARAM_CLR_APPOPT_IE:
        retv = wlan_set_clr_appopt_ie(vap);
        break;

    /*
    ** The setting of the manual rate table parameters and the retries are moved
    ** to here, since they really don't belong in iwconfig
    */

    case IEEE80211_PARAM_11N_RATE:
        retv = wlan_set_param(vap, IEEE80211_FIXED_RATE, value);
        break;

    case IEEE80211_PARAM_VHT_MCS:
        retv = wlan_set_param(vap, IEEE80211_FIXED_VHT_MCS, value);
    break;

    case IEEE80211_PARAM_NSS:
        if(!ic->ic_is_mode_offload(ic))
            return -EPERM;
        retv = wlan_set_param(vap, IEEE80211_FIXED_NSS, value);
	/*if the novap reset is set for debugging purpose we are not resetting the VAP*/
        if ((retv == 0) && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
        }
    break;

    case IEEE80211_PARAM_NO_VAP_RESET:
        vap->iv_novap_reset = value;
    break;

    case IEEE80211_PARAM_OPMODE_NOTIFY:
        retv = wlan_set_param(vap, IEEE80211_OPMODE_NOTIFY_ENABLE, value);
    break;

    case IEEE80211_PARAM_VHT_SGIMASK:
        retv = wlan_set_param(vap, IEEE80211_VHT_SGIMASK, value);
        if (retv == 0)
            retv = ENETRESET;
    break;

    case IEEE80211_PARAM_VHT80_RATEMASK:
        retv = wlan_set_param(vap, IEEE80211_VHT80_RATEMASK, value);
        if (retv == 0)
            retv = ENETRESET;
    break;

    case IEEE80211_PARAM_BW_NSS_RATEMASK:
        retv = wlan_set_param(vap, IEEE80211_BW_NSS_RATEMASK, value);
        if (retv == 0)
            retv = ENETRESET;
    break;

    case IEEE80211_PARAM_LDPC:
        retv = wlan_set_param(vap, IEEE80211_SUPPORT_LDPC, value);
        if (retv == 0)
            retv = ENETRESET;
    break;

    case IEEE80211_PARAM_TX_STBC:
        retv = wlan_set_param(vap, IEEE80211_SUPPORT_TX_STBC, value);
        if (retv == 0)
            retv = ENETRESET;
    break;

    case IEEE80211_PARAM_RX_STBC:
        retv = wlan_set_param(vap, IEEE80211_SUPPORT_RX_STBC, value);
        if (retv == 0)
            retv = ENETRESET;
    break;

    case IEEE80211_PARAM_VHT_TX_MCSMAP:
        retv = wlan_set_param(vap, IEEE80211_VHT_TX_MCSMAP, value);
        if (retv == 0)
            retv = ENETRESET;
    break;

    case IEEE80211_PARAM_VHT_RX_MCSMAP:
        retv = wlan_set_param(vap, IEEE80211_VHT_RX_MCSMAP, value);
        if (retv == 0)
            retv = ENETRESET;
    break;

    case IEEE80211_PARAM_11N_RETRIES:
        if (value)
            retv = wlan_set_param(vap, IEEE80211_FIXED_RETRIES, value);
        break;
    case IEEE80211_PARAM_SHORT_GI :
        retv = wlan_set_param(vap, IEEE80211_SHORT_GI, value);
        if (retv == 0)
            retv = ENETRESET;
        break;
    case IEEE80211_PARAM_BANDWIDTH :
        retv = ieee80211_ucfg_set_bandwidth(vap, value);
        break;
    case IEEE80211_PARAM_FREQ_BAND :
         retv = ieee80211_ucfg_set_band(vap, value);
         break;

    case IEEE80211_PARAM_EXTCHAN :
         retv = ieee80211_ucfg_set_extchan(vap, value);
         break;

    case IEEE80211_PARAM_SECOND_CENTER_FREQ :
         retv = wlan_set_param(vap, IEEE80211_SECOND_CENTER_FREQ, value);
         break;

    case IEEE80211_PARAM_ATH_SUPPORT_VLAN :
         if( value == 0 || value ==1) {
             vap->vlan_set_flags = value;
             if(value == 1) {
                 dev->features &= ~NETIF_F_HW_VLAN;
             }
             if(value == 0) {
                 dev->features |= NETIF_F_HW_VLAN;
             }
         }
         break;

    case IEEE80211_DISABLE_BCN_BW_NSS_MAP :
         if(value >= 0) {
             ic->ic_disable_bcn_bwnss_map = (value ? 1: 0);
             retv = EOK;
         }
         else
             retv = EINVAL;
         break;

    case IEEE80211_DISABLE_STA_BWNSS_ADV:
         if (value >= 0) {
             ic->ic_disable_bwnss_adv = (value ? 1: 0);
	     retv = EOK;
         } else
             retv = EINVAL;
	 break;
#if DBG_LVL_MAC_FILTERING
    case IEEE80211_PARAM_DBG_LVL_MAC:
          /* This takes 8 bytes as arguments <set/clear> <mac addr> <enable/disable>
          *  e.g. dbgLVLmac 1 0xaa 0xbb 0xcc 0xdd 0xee 0xff 1
          */
         retv = wlan_set_debug_mac_filtering_flags(vap, (unsigned char *)extra);
         break;
#endif

    case IEEE80211_PARAM_UMAC_VERBOSE_LVL:
        if (((value >= IEEE80211_VERBOSE_FORCE) && (value <= IEEE80211_VERBOSE_TRACE)) || (value == IEEE80211_VERBOSE_OFF)){
            wlan_set_umac_verbose_level(value);
        } else
            retv = EINVAL;
        break;

    case IEEE80211_PARAM_DBG_LVL:
         /*
          * NB: since the value is size of integer, we could only set the 32
          * LSBs of debug mask
          */
         if (vap->iv_csl_support && LOG_CSL_BASIC) {
             value |= IEEE80211_MSG_CSL;
         }
         retv = wlan_set_debug_flags(vap,value);
         break;

    case IEEE80211_PARAM_DBG_LVL_HIGH:
        /*
         * NB: This sets the upper 32 LSBs
         */
        {
            u_int64_t old = wlan_get_debug_flags(vap);
            retv = wlan_set_debug_flags(vap, (old & 0xffffffff) | ((u_int64_t) value << 32));
        }
        break;
#if UMAC_SUPPORT_IBSS
    case IEEE80211_PARAM_IBSS_CREATE_DISABLE:
        if (osifp->os_opmode != IEEE80211_M_IBSS) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                              "Can not be used in mode %d\n", osifp->os_opmode);
            return -EINVAL;
        }
        osifp->disable_ibss_create = !!value;
        break;
#endif
	case IEEE80211_PARAM_WEATHER_RADAR_CHANNEL:
        retv = wlan_set_param(vap, IEEE80211_WEATHER_RADAR, value);
        /* Making it zero so that it gets updated in Beacon */
        if ( EOK == retv)
            vap->iv_country_ie_chanflags = 0;
		break;
    case IEEE80211_PARAM_SEND_DEAUTH:
        retv = wlan_set_param(vap,IEEE80211_SEND_DEAUTH,value);
        break;
    case IEEE80211_PARAM_WEP_KEYCACHE:
        retv = wlan_set_param(vap, IEEE80211_WEP_KEYCACHE, value);
        break;
    case IEEE80211_PARAM_SIFS_TRIGGER:
        if ((value >= 0) && (ic->ic_is_mode_offload(ic))) {
            vap->iv_sifs_trigger_time = value;
            retv = ic->ic_vap_sifs_trigger(vap, value);
        } else
            return -EINVAL;
        break;
    case IEEE80211_PARAM_BEACON_INTERVAL:
        if (vap->iv_create_flags & IEEE80211_LP_IOT_VAP) {
            if (value > IEEE80211_BINTVAL_IWMAX || value < IEEE80211_BINTVAL_LP_IOT_IWMIN) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                                  "BEACON_INTERVAL should be within %d to %d\n",
                                  IEEE80211_BINTVAL_LP_IOT_IWMIN,
                                  IEEE80211_BINTVAL_IWMAX);
                return -EINVAL;
            }
        } else if (value > IEEE80211_BINTVAL_IWMAX || value < IEEE80211_BINTVAL_IWMIN) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                                  "BEACON_INTERVAL should be within %d to %d\n",
                                  IEEE80211_BINTVAL_IWMIN,
                                  IEEE80211_BINTVAL_IWMAX);
                return -EINVAL;
        }
        retv = wlan_set_param(vap, IEEE80211_BEACON_INTVAL, value);
        if (retv == EOK) {
            //retv = ENETRESET;
            wlan_if_t tmpvap;
            u_int8_t lp_vap_is_present = 0;
            u_int16_t lp_bintval = ic->ic_intval;

            /* Iterate to find if a LP IOT vap is there */
            TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
                if (tmpvap->iv_create_flags & IEEE80211_LP_IOT_VAP) {
                    lp_vap_is_present = 1;
                    /* If multiple lp iot vaps are present pick the least */
                    if (lp_bintval > tmpvap->iv_bss->ni_intval)  {
                        lp_bintval = tmpvap->iv_bss->ni_intval;
                    }
                }
            }

            /* Adjust regular beacon interval in ic to be a multiple of lp_iot beacon interval */
            if (lp_vap_is_present) {
                UP_CONVERT_TO_FACTOR_OF(ic->ic_intval, lp_bintval);
            }

            TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
                struct net_device *tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
                /* Adjust regular beacon interval in ni to be a multiple of lp_iot beacon interval */
                if (lp_vap_is_present) {
                    if (!(tmpvap->iv_create_flags & IEEE80211_LP_IOT_VAP)) {
                        /* up convert vap beacon interval to a factor of LP vap */
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                                          "Current beacon interval %d: Checking if up conversion is needed as lp_iot vap is present. ", ic->ic_intval);
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                                          "New beacon interval  %d \n", ic->ic_intval);
                        UP_CONVERT_TO_FACTOR_OF(tmpvap->iv_bss->ni_intval, lp_bintval);
                    }
                }
                retv = IS_UP(tmpdev) ? -osif_vap_init(tmpdev, RESCAN) : 0;
            }
        }
        break;
#if ATH_SUPPORT_AP_WDS_COMBO
    case IEEE80211_PARAM_NO_BEACON:
        retv = wlan_set_param(vap, IEEE80211_NO_BEACON, value);
        break;
#endif
    case IEEE80211_PARAM_PUREG:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_PUREG, value);
        /* NB: reset only if we're operating on an 11g channel */
        if (retv == 0) {
            wlan_chan_t chan = wlan_get_bss_channel(vap);
            if (chan != IEEE80211_CHAN_ANYC &&
                (IEEE80211_IS_CHAN_ANYG(chan) ||
                IEEE80211_IS_CHAN_11NG(chan)))
                retv = ENETRESET;
        }
        break;
    case IEEE80211_PARAM_PUREN:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_PURE11N, value);
        /* Reset only if we're operating on a 11ng channel */
        if (retv == 0) {
            wlan_chan_t chan = wlan_get_bss_channel(vap);
            if (chan != IEEE80211_CHAN_ANYC &&
            IEEE80211_IS_CHAN_11NG(chan))
            retv = ENETRESET;
        }
        break;
    case IEEE80211_PARAM_PURE11AC:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_PURE11AC, value);
        /* Reset if the channel is valid */
        if (retv == EOK) {
            wlan_chan_t chan = wlan_get_bss_channel(vap);
            if (chan != IEEE80211_CHAN_ANYC) {
                retv = ENETRESET;
	        }
        }
        break;
    case IEEE80211_PARAM_STRICT_BW:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_STRICT_BW, value);
        /* Reset if the channel is valid */
        if (retv == EOK) {
            wlan_chan_t chan = wlan_get_bss_channel(vap);
            if (chan != IEEE80211_CHAN_ANYC) {
                retv = ENETRESET;
	        }
        }
        break;
    case IEEE80211_PARAM_WDS:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_WDS, value);
        if (retv == 0) {
            /* WAR: set the auto assoc feature also for WDS */
            if (value) {
                wlan_set_param(vap, IEEE80211_AUTO_ASSOC, 1);
                /* disable STA powersave for WDS */
                if (wlan_vap_get_opmode(vap) == IEEE80211_M_STA) {
                    (void) wlan_set_powersave(vap,IEEE80211_PWRSAVE_NONE);
                    (void) wlan_pwrsave_force_sleep(vap,0);
                }
            }
        }
        break;
#if WDS_VENDOR_EXTENSION
    case IEEE80211_PARAM_WDS_RX_POLICY:
        retv = wlan_set_param(vap, IEEE80211_WDS_RX_POLICY, value);
        break;
#endif
    case IEEE80211_PARAM_VAP_PAUSE_SCAN:
        if (ieee80211_ic_enh_ind_rpt_is_set(vap->iv_ic)) {
            vap->iv_pause_scan = value ;
            retv = 0;
        } else retv =  EINVAL;
        break;
#if ATH_GEN_RANDOMNESS
    case IEEE80211_PARAM_RANDOMGEN_MODE:
        if(value < 0 || value > 2)
        {
         QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "INVALID mode please use between modes 0 to 2\n");
         break;
        }
        ic->random_gen_mode = value;
        break;
#endif
    case IEEE80211_PARAM_VAP_ENHIND:
        if (value) {
            retv = wlan_set_param(vap, IEEE80211_FEATURE_VAP_ENHIND, value);
        }
        else {
            retv = wlan_set_param(vap, IEEE80211_FEATURE_VAP_ENHIND, value);
        }
        break;

    case IEEE80211_PARAM_BLOCKDFSCHAN:
    {
        if (value)
        {
            ic->ic_flags_ext |= IEEE80211_FEXT_BLKDFSCHAN;
        }
        else
        {
            ic->ic_flags_ext &= ~IEEE80211_FEXT_BLKDFSCHAN;
        }

        retv = wlan_set_device_param(ic, IEEE80211_DEVICE_BLKDFSCHAN, value);
        if (retv == EOK) {
            retv = ENETRESET;
        }
    }
        break;
#if ATH_SUPPORT_WAPI
    case IEEE80211_PARAM_SETWAPI:
        retv = wlan_setup_wapi(vap, value);
        if (retv == 0) {
            retv = ENETRESET;
        }
        break;
    case IEEE80211_PARAM_WAPIREKEY_USK:
        retv = wlan_set_wapirekey_unicast(vap, value);
        break;
    case IEEE80211_PARAM_WAPIREKEY_MSK:
        retv = wlan_set_wapirekey_multicast(vap, value);
        break;
    case IEEE80211_PARAM_WAPIREKEY_UPDATE:
        retv = wlan_set_wapirekey_update(vap, (unsigned char*)&extra[4]);
        break;
#endif

    case IEEE80211_IOCTL_GREEN_AP_PS_ENABLE:
        wlan_set_device_param(ic, IEEE80211_DEVICE_GREEN_AP_PS_ENABLE, value?1:0);
        retv = 0;
        break;

    case IEEE80211_IOCTL_GREEN_AP_PS_TIMEOUT:
        wlan_set_device_param(ic, IEEE80211_DEVICE_GREEN_AP_PS_TIMEOUT, ((value > 20) && (value < 0xFFFF)) ? value : 20);
        retv = 0;
        break;

    case IEEE80211_IOCTL_GREEN_AP_PS_ON_TIME:
        wlan_set_device_param(ic, IEEE80211_DEVICE_GREEN_AP_PS_ON_TIME, value >= 0 ? value : 0);
        retv = 0;
        break;

    case IEEE80211_IOCTL_GREEN_AP_ENABLE_PRINT:
        wlan_set_device_param(ic, IEEE80211_DEVICE_GREEN_AP_ENABLE_PRINT, value?1:0);
        break;
#ifdef ATH_WPS_IE
    case IEEE80211_PARAM_WPS:
        retv = wlan_set_param(vap, IEEE80211_WPS_MODE, value);
        break;
#endif
#ifdef ATH_EXT_AP
    case IEEE80211_PARAM_EXTAP:
        if (value) {
            if (value == 3 /* dbg */) {
                extern void mi_tbl_dump(void *);
                mi_tbl_dump(vap->iv_ic->ic_miroot);
                break;
            }
            if (value == 2 /* dbg */) {
                extern void mi_tbl_purge(void *);
                IEEE80211_VAP_EXT_AP_DISABLE(vap);
				if (vap->iv_ic->ic_miroot)
					mi_tbl_purge(&vap->iv_ic->ic_miroot);
            }
            IEEE80211_VAP_EXT_AP_ENABLE(vap);
            /* Set the auto assoc feature for Extender Station */
            wlan_set_param(vap, IEEE80211_AUTO_ASSOC, 1);
            if (wlan_vap_get_opmode(vap) == IEEE80211_M_STA) {
                (void) wlan_set_powersave(vap,IEEE80211_PWRSAVE_NONE);
                (void) wlan_pwrsave_force_sleep(vap,0);
                /* Enable enhanced independent repeater mode for EXTAP */
                retv = wlan_set_param(vap, IEEE80211_FEATURE_VAP_ENHIND, value);
            }

        } else {
            IEEE80211_VAP_EXT_AP_DISABLE(vap);
            if (wlan_vap_get_opmode(vap) == IEEE80211_M_STA) {
                retv = wlan_set_param(vap, IEEE80211_FEATURE_VAP_ENHIND, value);
            }
        }
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (ic->nss_funcs)
        ic->nss_funcs->ic_osif_nss_ol_vdev_set_cfg(vap->iv_txrx_handle, OSIF_NSS_VDEV_EXTAP_CONFIG);
#endif
        break;
#endif
    case IEEE80211_PARAM_STA_FORWARD:
    retv = wlan_set_param(vap, IEEE80211_FEATURE_STAFWD, value);
    break;

    case IEEE80211_PARAM_DYN_BW_RTS:
        retv = ic->ic_vap_dyn_bw_rts(vap, value);
        if (retv == EOK) {
            vap->dyn_bw_rts = value;
        } else {
            return -EINVAL;
        }
        break;

    case IEEE80211_PARAM_CWM_EXTPROTMODE:
        if (value >= 0) {
            retv = wlan_set_device_param(ic,IEEE80211_DEVICE_CWM_EXTPROTMODE, value);
            if (retv == EOK) {
                retv = ENETRESET;
            }
        } else {
            retv = -EINVAL;
        }
        break;
    case IEEE80211_PARAM_CWM_EXTPROTSPACING:
        if (value >= 0) {
            retv = wlan_set_device_param(ic,IEEE80211_DEVICE_CWM_EXTPROTSPACING, value);
            if (retv == EOK) {
                retv = ENETRESET;
            }
        }
        else {
            retv = -EINVAL;
        }
        break;
    case IEEE80211_PARAM_CWM_ENABLE:
        if (value >= 0) {
            retv = wlan_set_device_param(ic,IEEE80211_DEVICE_CWM_ENABLE, value);
            if ((retv == EOK) && (vap->iv_novap_reset == 0)) {
                retv = ENETRESET;
            }
        } else {
            retv = -EINVAL;
        }
        break;
    case IEEE80211_PARAM_CWM_EXTBUSYTHRESHOLD:
        if (value >=0 && value <=100) {
            retv = wlan_set_device_param(ic,IEEE80211_DEVICE_CWM_EXTBUSYTHRESHOLD, value);
            if (retv == EOK) {
                retv = ENETRESET;
            }
        } else {
            retv = -EINVAL;
        }
        break;
    case IEEE80211_PARAM_DOTH:
        retv = wlan_set_device_param(ic, IEEE80211_DEVICE_DOTH, value);
        if (retv == EOK) {
            retv = ENETRESET;   /* XXX: need something this drastic? */
        }
        break;
    case IEEE80211_PARAM_SETADDBAOPER:
        if (value > 1 || value < 0) {
            return -EINVAL;
        }

        retv = wlan_set_device_param(ic, IEEE80211_DEVICE_ADDBA_MODE, value);
        break;
    case IEEE80211_PARAM_WMM:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_WMM, value);
        if (value) {
            /* WMM is enabled - reset number of subframes in AMPDU
             * to 64
             */
            wlan_set_param(vap, IEEE80211_FEATURE_AMPDU, 64);
        }
        else {
            wlan_set_param(vap, IEEE80211_FEATURE_AMPDU, 0);
        }
        if (retv == EOK) {
            retv = ENETRESET;
        }
        break;
    case IEEE80211_PARAM_PROTMODE:
        retv = wlan_set_device_param(ic, IEEE80211_DEVICE_PROTECTION_MODE, value);
        /* NB: if not operating in 11g this can wait */
        if (retv == EOK) {
            wlan_chan_t chan = wlan_get_bss_channel(vap);
            if (chan != IEEE80211_CHAN_ANYC &&
                (IEEE80211_IS_CHAN_ANYG(chan) ||
                IEEE80211_IS_CHAN_11NG(chan))) {
                retv = ENETRESET;
            }
        }
        break;
    case IEEE80211_PARAM_ROAMING:
        if (!(IEEE80211_ROAMING_DEVICE <= value &&
            value <= IEEE80211_ROAMING_MANUAL))
            return -EINVAL;
        ic->ic_roaming = value;
        if(value == IEEE80211_ROAMING_MANUAL)
            IEEE80211_VAP_AUTOASSOC_DISABLE(vap);
        else
            IEEE80211_VAP_AUTOASSOC_ENABLE(vap);
        break;
    case IEEE80211_PARAM_DROPUNENCRYPTED:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_DROP_UNENC, value);
        break;
    case IEEE80211_PARAM_DRIVER_CAPS:
        retv = wlan_set_param(vap, IEEE80211_DRIVER_CAPS, value); /* NB: for testing */
        break;
/*
* Support for Mcast Enhancement
*/
#if ATH_SUPPORT_IQUE
    case IEEE80211_PARAM_ME:
        wlan_set_param(vap, IEEE80211_ME, value);
        break;
    case IEEE80211_PARAM_MEDEBUG:
        wlan_set_param(vap, IEEE80211_MEDEBUG, value);
        break;
    case IEEE80211_PARAM_ME_SNOOPLENGTH:
        wlan_set_param(vap, IEEE80211_ME_SNOOPLENGTH, value);
        break;
    case IEEE80211_PARAM_ME_TIMER:
        wlan_set_param(vap, IEEE80211_ME_TIMER, value);
        break;
    case IEEE80211_PARAM_ME_TIMEOUT:
        wlan_set_param(vap, IEEE80211_ME_TIMEOUT, value);
        break;
    case IEEE80211_PARAM_HBR_TIMER:
        wlan_set_param(vap, IEEE80211_HBR_TIMER, value);
        break;
    case IEEE80211_PARAM_ME_DROPMCAST:
        wlan_set_param(vap, IEEE80211_ME_DROPMCAST, value);
        break;
    case IEEE80211_PARAM_ME_CLEARDENY:
        wlan_set_param(vap, IEEE80211_ME_CLEARDENY, value);
        break;
#endif

    case IEEE80211_PARAM_SCANVALID:
        if (osifp->os_opmode == IEEE80211_M_STA ||
                osifp->os_opmode == IEEE80211_M_P2P_CLIENT) {
            if (wlan_connection_sm_set_param(osifp->sm_handle,
                                             WLAN_CONNECTION_PARAM_SCAN_CACHE_VALID_TIME, value) == -EINVAL) {
                retv = -EINVAL;
            }
        } else {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                              "Can not be used in mode %d\n", osifp->os_opmode);
            retv = -EINVAL;
        }
        break;

    case IEEE80211_PARAM_DTIM_PERIOD:
        if (!(osifp->os_opmode == IEEE80211_M_HOSTAP ||
            osifp->os_opmode == IEEE80211_M_IBSS)) {
            return -EINVAL;
        }
        if (value > IEEE80211_DTIM_MAX ||
            value < IEEE80211_DTIM_MIN) {

            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                              "DTIM_PERIOD should be within %d to %d\n",
                              IEEE80211_DTIM_MIN,
                              IEEE80211_DTIM_MAX);
            return -EINVAL;
        }
        retv = wlan_set_param(vap, IEEE80211_DTIM_INTVAL, value);
        if (retv == EOK) {
            retv = ENETRESET;
        }

        break;
    case IEEE80211_PARAM_MACCMD:
        wlan_set_acl_policy(vap, value, IEEE80211_ACL_FLAG_ACL_LIST_1);
        break;
    case IEEE80211_PARAM_ENABLE_OL_STATS:
        /* This param should be eventually removed and re-used */
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Issue this command on parent device, like wifiX\n");
        break;
    case IEEE80211_PARAM_RTT_ENABLE:
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "KERN_DEBUG\n setting the rtt enable flag\n");
        vap->rtt_enable = value;
        break;
    case IEEE80211_PARAM_LCI_ENABLE:
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "KERN_DEBUG\n setting the lci enble flag\n");
        vap->lci_enable = value;
        break;
    case IEEE80211_PARAM_LCR_ENABLE:
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "KERN_DEBUG\n setting the lcr enble flag\n");
        vap->lcr_enable = value;
        break;
    case IEEE80211_PARAM_MCAST_RATE:
        /*
        * value is rate in units of Kbps
        * min: 1Mbps max: 350Mbps
        */
        if (value < ONEMBPS || value > THREE_HUNDRED_FIFTY_MBPS)
            retv = -EINVAL;
        else {
            retv = wlan_set_param(vap, IEEE80211_MCAST_RATE, value);
        }
        break;
    case IEEE80211_PARAM_BCAST_RATE:
        /*
        * value is rate in units of Kbps
        * min: 1Mbps max: 350Mbps
        */
        if (value < ONEMBPS || value > THREE_HUNDRED_FIFTY_MBPS)
            retv = -EINVAL;
        else {
        	retv = wlan_set_param(vap, IEEE80211_BCAST_RATE, value);
        }
        break;
    case IEEE80211_PARAM_MGMT_RATE:
        if(!ieee80211_rate_is_valid_basic(vap,value)){
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: rate %d is not valid. \n",__func__,value);
            retv = -EINVAL;
            break;
        }
       /*
        * value is rate in units of Kbps
        * min: 1000 kbps max: 300000 kbps
        */
        if (value < 1000 || value > 300000)
            retv = -EINVAL;
        else {
            retv = wlan_set_param(vap, IEEE80211_MGMT_RATE, value);
        }
        break;
    case IEEE80211_RTSCTS_RATE:
        if (!ieee80211_rate_is_valid_basic(vap,value)) {
            qdf_print("%s: Rate %d is not valid. \n",__func__,value);
            retv = -EINVAL;
            break;
        }
       /*
        * Here value represents rate in Kbps.
        * min: 1000 kbps max: 24000 kbps
        */
        if (value < ONEMBPS || value > HIGHEST_BASIC_RATE)
            retv = -EINVAL;
        else {
            retv = wlan_set_param(vap, IEEE80211_RTSCTS_RATE, value);
        }
        break;
    case IEEE80211_PARAM_CCMPSW_ENCDEC:
        if (value) {
            IEEE80211_VAP_CCMPSW_ENCDEC_ENABLE(vap);
        } else {
            IEEE80211_VAP_CCMPSW_ENCDEC_DISABLE(vap);
        }
        break;
    case IEEE80211_PARAM_NETWORK_SLEEP:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s set IEEE80211_IOC_POWERSAVE parameter %d \n",
                          __func__,value );
        do {
            ieee80211_pwrsave_mode ps_mode = IEEE80211_PWRSAVE_NONE;
            switch(value) {
            case 0:
                ps_mode = IEEE80211_PWRSAVE_NONE;
                break;
            case 1:
                ps_mode = IEEE80211_PWRSAVE_LOW;
                break;
            case 2:
                ps_mode = IEEE80211_PWRSAVE_NORMAL;
                break;
            case 3:
                ps_mode = IEEE80211_PWRSAVE_MAXIMUM;
                break;
            }
            error= wlan_set_powersave(vap,ps_mode);
        } while(0);
        break;

#if UMAC_SUPPORT_WNM
    case IEEE80211_PARAM_WNM_SLEEP:
        if (wlan_wnm_vap_is_set(vap) && ieee80211_wnm_sleep_is_set(vap->wnm)) {
            ieee80211_pwrsave_mode ps_mode = IEEE80211_PWRSAVE_NONE;
            if (value > 0)
                ps_mode = IEEE80211_PWRSAVE_WNM;
            else
                ps_mode = IEEE80211_PWRSAVE_NONE;

            if (wlan_vap_get_opmode(vap) == IEEE80211_M_STA)
                vap->iv_wnmsleep_intval = value > 0 ? value : 0;
            error = wlan_set_powersave(vap,ps_mode);
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "set IEEE80211_PARAM_WNM_SLEEP mode = %d\n", ps_mode);
        } else
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: WNM not supported\n", __func__);
	break;

    case IEEE80211_PARAM_WNM_SMENTER:
        if (!wlan_wnm_vap_is_set(vap) || !ieee80211_wnm_sleep_is_set(vap->wnm)) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: WNM not supported\n", __func__);
            return -EINVAL;
        }

        if (value % 2 == 0) {
            /* HACK: even interval means FORCE WNM Sleep: requires manual wnmsmexit */
            vap->iv_wnmsleep_force = 1;
        }

        ieee80211_wnm_sleepreq_to_app(vap, IEEE80211_WNMSLEEP_ACTION_ENTER, value);
        break;

    case IEEE80211_PARAM_WNM_SMEXIT:
        if (!wlan_wnm_vap_is_set(vap) || !ieee80211_wnm_sleep_is_set(vap->wnm)) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: WNM not supported\n", __func__);
            return -EINVAL;
        }
        vap->iv_wnmsleep_force = 0;
        ieee80211_wnm_sleepreq_to_app(vap, IEEE80211_WNMSLEEP_ACTION_EXIT, value);
	    break;
#endif

#ifdef ATHEROS_LINUX_PERIODIC_SCAN
    case IEEE80211_PARAM_PERIODIC_SCAN:
        if (wlan_vap_get_opmode(vap) == IEEE80211_M_STA) {
            if (osifp->os_periodic_scan_period != value){
                if (value && (value < OSIF_PERIODICSCAN_MIN_PERIOD))
                    osifp->os_periodic_scan_period = OSIF_PERIODICSCAN_MIN_PERIOD;
                else
                    osifp->os_periodic_scan_period = value;

                retv = ENETRESET;
            }
        }
        break;
#endif

#if ATH_SW_WOW
    case IEEE80211_PARAM_SW_WOW:
        if (wlan_vap_get_opmode(vap) == IEEE80211_M_STA) {
            retv = wlan_set_wow(vap, value);
        }
        break;
#endif

    case IEEE80211_PARAM_UAPSDINFO:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_UAPSD, value);
        if (retv == EOK) {
            retv = ENETRESET;
        }
	break ;
#if defined(UMAC_SUPPORT_STA_POWERSAVE) || defined(ATH_PERF_PWR_OFFLOAD)
    /* WFD Sigma use these two to do reset and some cases. */
    case IEEE80211_PARAM_SLEEP:
        /* XXX: Forced sleep for testing. Does not actually place the
         *      HW in sleep mode yet. this only makes sense for STAs.
         */
        /* enable/disable force  sleep */
        wlan_pwrsave_force_sleep(vap,value);
        break;
#endif
     case IEEE80211_PARAM_COUNTRY_IE:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_IC_COUNTRY_IE, value);
        if (retv == EOK) {
            retv = ENETRESET;
        }
        break;
    case IEEE80211_PARAM_2G_CSA:
        retv = wlan_set_device_param(ic, IEEE80211_DEVICE_2G_CSA, value);
        break;
#if UMAC_SUPPORT_BSSLOAD
    case IEEE80211_PARAM_QBSS_LOAD:
        if (value > 1 || value < 0) {
            return -EINVAL;
        } else {
            retv = wlan_set_param(vap, IEEE80211_QBSS_LOAD, value);
            if (retv == EOK)
                retv = ENETRESET;
        }
        break;
#if ATH_SUPPORT_HS20
    case IEEE80211_PARAM_HC_BSSLOAD:
        retv = wlan_set_param(vap, IEEE80211_HC_BSSLOAD, value);
        if (retv == EOK) {
            retv = ENETRESET;
        }
        break;
    case IEEE80211_PARAM_OSEN:
        if (value > 1 || value < 0)
            return -EINVAL;
        else
            wlan_set_param(vap, IEEE80211_OSEN, value);
        break;
#endif /* ATH_SUPPORT_HS20 */
#endif /* UMAC_SUPPORT_BSSLOAD */
#if UMAC_SUPPORT_CHANUTIL_MEASUREMENT
    case IEEE80211_PARAM_CHAN_UTIL_ENAB:
        if (value > 1 || value < 0) {
            return -EINVAL;
        } else {
            retv = wlan_set_param(vap, IEEE80211_CHAN_UTIL_ENAB, value);
            if (retv == EOK)
                retv = ENETRESET;
        }
        break;
#endif /* UMAC_SUPPORT_CHANUTIL_MEASUREMENT */
#if UMAC_SUPPORT_QUIET
    case IEEE80211_PARAM_QUIET_PERIOD:
        if (value > 1 || value < 0) {
            return -EINVAL;
        } else {
            retv = wlan_quiet_set_param(vap, value);
            if (retv == EOK)
                retv = ENETRESET;
        }
        break;
#endif /* UMAC_SUPPORT_QUIET */
    case IEEE80211_PARAM_START_ACS_REPORT:
        retv = wlan_set_param(vap, IEEE80211_START_ACS_REPORT, !!value);
        break;
    case IEEE80211_PARAM_MIN_DWELL_ACS_REPORT:
        retv = wlan_set_param(vap, IEEE80211_MIN_DWELL_ACS_REPORT, value);
        break;
    case IEEE80211_PARAM_MAX_DWELL_ACS_REPORT:
        retv = wlan_set_param(vap, IEEE80211_MAX_DWELL_ACS_REPORT, value);
        break;
    case IEEE80211_PARAM_SCAN_MIN_DWELL:
        retv = wlan_set_param(vap, IEEE80211_SCAN_MIN_DWELL, value);
       break;
    case IEEE80211_PARAM_SCAN_MAX_DWELL:
        retv = wlan_set_param(vap, IEEE80211_SCAN_MAX_DWELL, value);
       break;
    case IEEE80211_PARAM_ACS_CH_HOP_LONG_DUR:
        retv = wlan_set_param(vap,IEEE80211_ACS_CH_HOP_LONG_DUR, value);
        break;
    case IEEE80211_PARAM_ACS_CH_HOP_NO_HOP_DUR:
        retv = wlan_set_param(vap,IEEE80211_ACS_CH_HOP_NO_HOP_DUR,value);
        break;
    case IEEE80211_PARAM_ACS_CH_HOP_CNT_WIN_DUR:
        retv = wlan_set_param(vap,IEEE80211_ACS_CH_HOP_CNT_WIN_DUR, value);
        break;
    case IEEE80211_PARAM_ACS_CH_HOP_NOISE_TH:
        retv = wlan_set_param(vap,IEEE80211_ACS_CH_HOP_NOISE_TH,value);
        break;
    case IEEE80211_PARAM_ACS_CH_HOP_CNT_TH:
        retv = wlan_set_param(vap,IEEE80211_ACS_CH_HOP_CNT_TH, value);
        break;
    case IEEE80211_PARAM_ACS_ENABLE_CH_HOP:
        retv = wlan_set_param(vap,IEEE80211_ACS_ENABLE_CH_HOP, value);
        break;
    case IEEE80211_PARAM_MBO:
        retv = wlan_set_param(vap, IEEE80211_MBO, !!value);
        if (retv == EOK)
            retv = ENETRESET;
        break;
    case IEEE80211_PARAM_MBO_ASSOC_DISALLOW:
        retv = wlan_set_param(vap, IEEE80211_MBO_ASSOC_DISALLOW,value);
        break;
    case IEEE80211_PARAM_MBO_CELLULAR_PREFERENCE:
        retv = wlan_set_param(vap,IEEE80211_MBO_CELLULAR_PREFERENCE,value);
        break;
    case IEEE80211_PARAM_MBO_TRANSITION_REASON:
        retv  = wlan_set_param(vap,IEEE80211_MBO_TRANSITION_REASON,value);
        break;
    case IEEE80211_PARAM_MBO_ASSOC_RETRY_DELAY:
        retv  = wlan_set_param(vap,IEEE80211_MBO_ASSOC_RETRY_DELAY,value);
        break;
    case IEEE80211_PARAM_MBO_CAP:
        retv = wlan_set_param(vap, IEEE80211_MBOCAP, value);
        if (retv == EOK)
            retv = ENETRESET;
        break;
    case IEEE80211_PARAM_OCE:
        retv = wlan_set_param(vap, IEEE80211_OCE, !!value);
        if (retv == EOK)
            retv = ENETRESET;
        break;
    case IEEE80211_PARAM_OCE_ASSOC_REJECT:
        retv = wlan_set_param(vap, IEEE80211_OCE_ASSOC_REJECT, !!value);
        break;
    case IEEE80211_PARAM_OCE_ASSOC_MIN_RSSI:
        retv = wlan_set_param(vap, IEEE80211_OCE_ASSOC_MIN_RSSI, value);
        break;
    case IEEE80211_PARAM_OCE_ASSOC_RETRY_DELAY:
        retv = wlan_set_param(vap, IEEE80211_OCE_ASSOC_RETRY_DELAY, value);
        break;
    case IEEE80211_PARAM_OCE_WAN_METRICS:
        retv = wlan_set_param(vap, IEEE80211_OCE_WAN_METRICS, !!value);
        break;
    case IEEE80211_PARAM_RRM_CAP:
        retv = wlan_set_param(vap, IEEE80211_RRM_CAP, !!value);
        if (retv == EOK)
            retv = ENETRESET;
        break;
    case IEEE80211_PARAM_RRM_DEBUG:
        retv = wlan_set_param(vap, IEEE80211_RRM_DEBUG, value);
        break;
    case IEEE80211_PARAM_RRM_STATS:
        retv = wlan_set_param(vap, IEEE80211_RRM_STATS, !!value);
	break;
    case IEEE80211_PARAM_RRM_SLWINDOW:
        retv = wlan_set_param(vap, IEEE80211_RRM_SLWINDOW, !!value);
        break;
#if UMAC_SUPPORT_WNM
    case IEEE80211_PARAM_WNM_CAP:
        if (value > 1 || value < 0) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " ERR :- Invalid value %d Value to be either 0 or 1 \n", value);
            return -EINVAL;
        } else {
            retv = wlan_set_param(vap, IEEE80211_WNM_CAP, value);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
         if (ic->nss_funcs)
            ic->nss_funcs->ic_osif_nss_ol_vdev_set_cfg(vap->iv_txrx_handle, OSIF_NSS_WIFI_VDEV_CFG_WNM_CAP);
#endif
            if (retv == EOK)
                retv = ENETRESET;
        }
        break;
     case IEEE80211_PARAM_WNM_BSS_CAP: /* WNM Max BSS idle */
         if (value > 1 || value < 0) {
             QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " ERR :- Invalid value %d Value to be either 0 or 1 \n", value);
             return -EINVAL;
         } else {
             retv = wlan_set_param(vap, IEEE80211_WNM_BSS_CAP, value);
             if (retv == EOK)
                 retv = ENETRESET;
         }
         break;
     case IEEE80211_PARAM_WNM_TFS_CAP:
         if (value > 1 || value < 0) {
             QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " ERR :- Invalid value %d Value to be either 0 or 1 \n", value);
             return -EINVAL;
         } else {
             retv = wlan_set_param(vap, IEEE80211_WNM_TFS_CAP, value);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
         if (ic->nss_funcs)
             ic->nss_funcs->ic_osif_nss_ol_vdev_set_cfg(vap->iv_txrx_handle, OSIF_NSS_WIFI_VDEV_CFG_WNM_TFS);
#endif
             if (retv == EOK)
                 retv = ENETRESET;
         }
         break;
     case IEEE80211_PARAM_WNM_TIM_CAP:
         if (value > 1 || value < 0) {
             QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " ERR :- Invalid value %d Value to be either 0 or 1 \n", value);
             return -EINVAL;
         } else {
             retv = wlan_set_param(vap, IEEE80211_WNM_TIM_CAP, value);
             if (retv == EOK)
                 retv = ENETRESET;
         }
         break;
     case IEEE80211_PARAM_WNM_SLEEP_CAP:
         if (value > 1 || value < 0) {
             QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " ERR :- Invalid value %d Value to be either 0 or 1 \n", value);
             return -EINVAL;
         } else {
             retv = wlan_set_param(vap, IEEE80211_WNM_SLEEP_CAP, value);
             if (retv == EOK)
                 retv = ENETRESET;
         }
         break;
    case IEEE80211_PARAM_WNM_FMS_CAP:
        if (value > 1 || value < 0) {
            return -EINVAL;
        } else {
            retv = wlan_set_param(vap, IEEE80211_WNM_FMS_CAP, value);
            if (retv == EOK)
                retv = ENETRESET;
        }
        break;
#endif
    case IEEE80211_PARAM_PWRTARGET:
        retv = wlan_set_device_param(ic, IEEE80211_DEVICE_PWRTARGET, value);
        break;
    case IEEE80211_PARAM_AMPDU:
        if (value > IEEE80211_AMPDU_SUBFRAME_MAX || value < 0) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "AMPDU value range is 0 - %d\n", IEEE80211_AMPDU_SUBFRAME_MAX);
            return -EINVAL;
        }

        prev_state = vap->iv_ampdu ? 1:0;
        retv = wlan_set_param(vap, IEEE80211_FEATURE_AMPDU, value);
        new_state = vap->iv_ampdu ? 1:0;
        if (retv == EOK) {
            retv = ENETRESET;
        }

#if ATH_SUPPORT_IBSS_HT
        /*
         * config ic adhoc AMPDU capability
         */
        if (vap->iv_opmode == IEEE80211_M_IBSS) {

            wlan_dev_t ic = wlan_vap_get_devhandle(vap);

            if (value &&
               (ieee80211_ic_ht20Adhoc_is_set(ic) || ieee80211_ic_ht40Adhoc_is_set(ic))) {
                wlan_set_device_param(ic, IEEE80211_DEVICE_HTADHOCAGGR, 1);
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s IEEE80211_PARAM_AMPDU = %d and HTADHOC enable\n", __func__, value);
            } else {
                wlan_set_device_param(ic, IEEE80211_DEVICE_HTADHOCAGGR, 0);
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s IEEE80211_PARAM_AMPDU = %d and HTADHOC disable\n", __func__, value);
            }
            if ((prev_state) && (!new_state)) {
                retv = ENETRESET;
            } else {
                // don't reset
                retv = EOK;
            }
        }
#endif /* end of #if ATH_SUPPORT_IBSS_HT */

        break;
#if ATH_SUPPORT_WPA_SUPPLICANT_CHECK_TIME
    case IEEE80211_PARAM_REJOINT_ATTEMP_TIME:
        retv = wlan_set_param(vap,IEEE80211_REJOINT_ATTEMP_TIME,value);
        break;
#endif

        case IEEE80211_PARAM_AMSDU:
            vap->iv_amsdu = value;
            if(!osifp->osif_is_mode_offload) {
                ic->ic_set_config(vap);
            } else {
#if defined(TEMP_AGGR_CFG)
                /* configure the max amsdu subframes */
	        retv = ic->ic_vap_set_param(vap, IEEE80211_AMSDU_SET, value);
#endif
            }
	    break;

    case IEEE80211_PARAM_11N_TX_AMSDU:
        /* Enable/Disable Tx AMSDU for HT clients. Sanitise to 0 or 1 only */
        vap->iv_disable_ht_tx_amsdu = !!value;
        break;

    case IEEE80211_PARAM_CTSPROT_DTIM_BCN:
        retv = wlan_set_vap_cts2self_prot_dtim_bcn(vap, !!value);
        if (!retv)
            retv = EOK;
        else
            retv = -EINVAL;
       break;

    case IEEE80211_PARAM_VSP_ENABLE:
        /* Enable/Disable VSP for VOW */
        vap->iv_enable_vsp = !!value;
        break;

    case IEEE80211_PARAM_SHORTPREAMBLE:
        retv = wlan_set_param(vap, IEEE80211_SHORT_PREAMBLE, value);
        if (retv == EOK) {
            retv = ENETRESET;
        }
       break;

    case IEEE80211_PARAM_CHANBW:
        switch (value)
        {
        case 0:
            ic->ic_chanbwflag = 0;
            break;
        case 1:
            ic->ic_chanbwflag = IEEE80211_CHAN_HALF;
            break;
        case 2:
            ic->ic_chanbwflag = IEEE80211_CHAN_QUARTER;
            break;
        default:
            retv = -EINVAL;
            break;
        }

       /*
        * bandwidth change need reselection of channel based on the chanbwflag
        * This is required if the command is issued after the freq has been set
        * neither the chanbw param does not take effect
        */
       if ( retv == 0 ) {
           deschan = wlan_get_param(vap, IEEE80211_DESIRED_CHANNEL);
           retv  = wlan_set_channel(vap, deschan, vap->iv_des_cfreq2);

           if (retv == 0) {
               /*Reinitialize the vap*/
               retv = ENETRESET ;
           }
       }
        break;

    case IEEE80211_PARAM_INACT:
        wlan_set_param(vap, IEEE80211_RUN_INACT_TIMEOUT, value);
        break;
    case IEEE80211_PARAM_INACT_AUTH:
        wlan_set_param(vap, IEEE80211_AUTH_INACT_TIMEOUT, value);
        break;
    case IEEE80211_PARAM_INACT_INIT:
        wlan_set_param(vap, IEEE80211_INIT_INACT_TIMEOUT, value);
        break;
    case IEEE80211_PARAM_SESSION_TIMEOUT:
        wlan_set_param(vap, IEEE80211_SESSION_TIMEOUT, value);
        break;
    case IEEE80211_PARAM_WDS_AUTODETECT:
        wlan_set_param(vap, IEEE80211_WDS_AUTODETECT, value);
        break;
    case IEEE80211_PARAM_WEP_TKIP_HT:
		wlan_set_param(vap, IEEE80211_WEP_TKIP_HT, value);
        retv = ENETRESET;
        break;
    case IEEE80211_PARAM_IGNORE_11DBEACON:
        wlan_set_param(vap, IEEE80211_IGNORE_11DBEACON, value);
        break;
    case IEEE80211_PARAM_MFP_TEST:
        wlan_set_param(vap, IEEE80211_FEATURE_MFP_TEST, value);
        break;

#ifdef QCA_PARTNER_PLATFORM
    case IEEE80211_PARAM_PLTFRM_PRIVATE:
        retv = wlan_pltfrm_set_param(vap, value);
 	    if ( retv == EOK) {
 	        retv = ENETRESET;
 	    }
 	    break;
#endif

    case IEEE80211_PARAM_NO_STOP_DISASSOC:
        if (value)
            osifp->no_stop_disassoc = 1;
        else
            osifp->no_stop_disassoc = 0;
        break;
#if UMAC_SUPPORT_VI_DBG

        case IEEE80211_PARAM_DBG_CFG:
	    osifp->vi_dbg = value;
            ieee80211_vi_dbg_set_param(vap, IEEE80211_VI_DBG_CFG, value);
            break;

        case IEEE80211_PARAM_RESTART:
            ieee80211_vi_dbg_set_param(vap, IEEE80211_VI_RESTART, value);
            break;
        case IEEE80211_PARAM_RXDROP_STATUS:
            ieee80211_vi_dbg_set_param(vap, IEEE80211_VI_RXDROP_STATUS, value);
            break;
#endif
    case IEEE80211_IOC_WPS_MODE:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                        "set IEEE80211_IOC_WPS_MODE to 0x%x\n", value);
        retv = wlan_set_param(vap, IEEE80211_WPS_MODE, value);
        break;

    case IEEE80211_IOC_SCAN_FLUSH:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "set %s\n",
                        "IEEE80211_IOC_SCAN_FLUSH");
        wlan_scan_table_flush(vap);
        retv = 0; /* success */
        break;

#ifdef ATH_SUPPORT_TxBF
    case IEEE80211_PARAM_TXBF_AUTO_CVUPDATE:
        wlan_set_param(vap, IEEE80211_TXBF_AUTO_CVUPDATE, value);
        ic->ic_set_config(vap);
        break;
    case IEEE80211_PARAM_TXBF_CVUPDATE_PER:
        wlan_set_param(vap, IEEE80211_TXBF_CVUPDATE_PER, value);
        ic->ic_set_config(vap);
        break;
#endif
    case IEEE80211_PARAM_SCAN_BAND:
        if ((value == OSIF_SCAN_BAND_2G_ONLY  && IEEE80211_SUPPORT_PHY_MODE(ic,IEEE80211_MODE_11G)) ||
            (value == OSIF_SCAN_BAND_5G_ONLY  && IEEE80211_SUPPORT_PHY_MODE(ic,IEEE80211_MODE_11A)) ||
            (value == OSIF_SCAN_BAND_ALL))
        {
            osifp->os_scan_band = value;
        }
        retv = 0;
        break;

    case IEEE80211_PARAM_SCAN_CHAN_EVENT:
        if (osifp->osif_is_mode_offload &&
            wlan_vap_get_opmode(vap) == IEEE80211_M_HOSTAP) {
            osifp->is_scan_chevent = !!value;
            retv = 0;
        } else {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "IEEE80211_PARAM_SCAN_CHAN_EVENT is valid only for 11ac "
                   "offload, and in IEEE80211_M_HOSTAP(Access Point) mode\n");
            retv = -EOPNOTSUPP;
        }
        break;

#if UMAC_SUPPORT_PROXY_ARP
    case IEEE80211_PARAM_PROXYARP_CAP:
        wlan_set_param(vap, IEEE80211_PROXYARP_CAP, value);
	    break;
#if UMAC_SUPPORT_DGAF_DISABLE
    case IEEE80211_PARAM_DGAF_DISABLE:
        wlan_set_param(vap, IEEE80211_DGAF_DISABLE, value);
        break;
#endif
#endif
#if UMAC_SUPPORT_HS20_L2TIF
    case IEEE80211_PARAM_L2TIF_CAP:
        value = value ? 0 : 1;
        wlan_set_param(vap, IEEE80211_FEATURE_APBRIDGE, value);
       break;
#endif
    case IEEE80211_PARAM_EXT_IFACEUP_ACS:
        wlan_set_param(vap, IEEE80211_EXT_IFACEUP_ACS, value);
        break;

    case IEEE80211_PARAM_EXT_ACS_IN_PROGRESS:
        wlan_set_param(vap, IEEE80211_EXT_ACS_IN_PROGRESS, value);
        break;

    case IEEE80211_PARAM_SEND_ADDITIONAL_IES:
        wlan_set_param(vap, IEEE80211_SEND_ADDITIONAL_IES, value);
        break;

    case IEEE80211_PARAM_APONLY:
#if UMAC_SUPPORT_APONLY
        vap->iv_aponly = value ? true : false;
        ic->ic_aponly = vap->iv_aponly;
#else
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "APONLY not enabled\n");
#endif
        break;
    case IEEE80211_PARAM_ONETXCHAIN:
        vap->iv_force_onetxchain = value ? true : false;
        break;

    case IEEE80211_PARAM_SET_CABQ_MAXDUR:
        if (value > 0 && value < 100)
            wlan_set_param(vap, IEEE80211_SET_CABQ_MAXDUR, value);
        else
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Percentage should be between 0 and 100\n");
        break;
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
    case IEEE80211_PARAM_NOPBN:
        wlan_set_param(vap, IEEE80211_NOPBN, value);
        break;
#endif
#if ATH_SUPPORT_DSCP_OVERRIDE
    case IEEE80211_PARAM_DSCP_OVERRIDE:
        qdf_print("Set DSCP override %d\n",value);
        wlan_set_param(vap, IEEE80211_DSCP_OVERRIDE, value);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (ic->nss_funcs)
        ic->nss_funcs->ic_osif_nss_ol_vdev_set_cfg(vap->iv_txrx_handle, OSIF_NSS_WIFI_VDEV_CFG_DSCP_OVERRIDE);
#endif
        break;
    case IEEE80211_PARAM_DSCP_TID_MAP:
        qdf_print("Set vap dscp tid map\n");
        wlan_set_vap_dscp_tid_map(osifp->os_if, val[1], val[2]);
        break;
#endif
    case IEEE80211_PARAM_TXRX_VAP_STATS:
        if (!ic->ic_is_mode_offload(ic)) {
            qdf_print("TXRX_DBG Only valid for 11ac  \n");
        } else {
	    retv = ic->ic_vap_set_param(vap, IEEE80211_TXRX_VAP_STATS, value);
        }
        break;
    case IEEE80211_PARAM_TXRX_DBG:
        if(!ic->ic_is_mode_offload(ic)) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "TXRX_DBG Only valid for 11ac  \n");
        } else {
	    retv = ic->ic_vap_set_param(vap, IEEE80211_TXRX_DBG_SET, value);
        }
        break;
    case IEEE80211_PARAM_VAP_TXRX_FW_STATS:
        if (!ic->ic_is_mode_offload(ic)) {
            qdf_print("FW_STATS Only valid for offload radios \n");
            return -EINVAL ;
        } else {
            retv = ic->ic_vap_set_param(vap, IEEE80211_VAP_TXRX_FW_STATS, value);
        }
        break;
    case IEEE80211_PARAM_TXRX_FW_STATS:
        if(!ic->ic_is_mode_offload(ic)) {
            qdf_print("FW_STATS Only valid for 11ac  \n");
        } else {
            retv = ic->ic_vap_set_param(vap, IEEE80211_TXRX_FW_STATS, value);
        }
        break;
    case IEEE80211_PARAM_TXRX_FW_MSTATS:
        if(!ic->ic_is_mode_offload(ic)) {
           qdf_print("FW_MSTATS Only valid for 11ac  \n");
        } else {
           retv = ic->ic_vap_set_param(vap, IEEE80211_TXRX_FW_MSTATS, value);
        }
        break;
    case IEEE80211_PARAM_VAP_TXRX_FW_STATS_RESET:
       if (!ic->ic_is_mode_offload(ic)) {
           qdf_print("FW_STATS_RESET Only valid for offload radios  \n");
           return -EINVAL;
       } else {
           retv = ic->ic_vap_set_param(vap, IEEE80211_VAP_TXRX_FW_STATS_RESET, value);
       }
       break;
    case IEEE80211_PARAM_TXRX_FW_STATS_RESET:
       if (!ic->ic_is_mode_offload(ic)) {
            qdf_print("FW_STATS_RESET Only valid for 11ac  \n");
       }
       else {
           retv = ic->ic_vap_set_param(vap, IEEE80211_TXRX_FW_STATS_RESET, value);
       }
       break;
    case IEEE80211_PARAM_TX_PPDU_LOG_CFG:
        if (!ic->ic_is_mode_offload(ic)) {
            qdf_print("TX_PPDU_LOG_CFG  Only valid for 11ac  \n");
            break;
        }
        retv = ic->ic_vap_set_param(vap, IEEE80211_TX_PPDU_LOG_CFG_SET, value);
        break;
    case IEEE80211_PARAM_MAX_SCANENTRY:
        retv = wlan_set_param(vap, IEEE80211_MAX_SCANENTRY, value);
        break;
    case IEEE80211_PARAM_SCANENTRY_TIMEOUT:
        retv = wlan_set_param(vap, IEEE80211_SCANENTRY_TIMEOUT, value);
        break;
#if ATH_PERF_PWR_OFFLOAD && QCA_SUPPORT_RAWMODE_PKT_SIMULATION
    case IEEE80211_PARAM_CLR_RAWMODE_PKT_SIM_STATS:
        retv = wlan_set_param(vap, IEEE80211_CLR_RAWMODE_PKT_SIM_STATS, value);
        break;
#endif /* ATH_PERF_PWR_OFFLOAD && QCA_SUPPORT_RAWMODE_PKT_SIMULATION */
    default:
        retv = -EOPNOTSUPP;
        if (retv) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s parameter 0x%x is "
                            "not supported retv=%d\n", __func__, param, retv);
        }
        break;
#if ATH_SUPPORT_IBSS_DFS
     case IEEE80211_PARAM_IBSS_DFS_PARAM:
        {
#define IBSSDFS_CSA_TIME_MASK 0x00ff0000
#define IBSSDFS_ACTION_MASK   0x0000ff00
#define IBSSDFS_RECOVER_MASK  0x000000ff
            u_int8_t csa_in_tbtt;
            u_int8_t actions_threshold;
            u_int8_t rec_threshold_in_tbtt;

            csa_in_tbtt = (value & IBSSDFS_CSA_TIME_MASK) >> 16;
            actions_threshold = (value & IBSSDFS_ACTION_MASK) >> 8;
            rec_threshold_in_tbtt = (value & IBSSDFS_RECOVER_MASK);

            if (rec_threshold_in_tbtt > csa_in_tbtt &&
                actions_threshold > 0) {
                vap->iv_ibss_dfs_csa_threshold = csa_in_tbtt;
                vap->iv_ibss_dfs_csa_measrep_limit = actions_threshold;
                vap->iv_ibss_dfs_enter_recovery_threshold_in_tbtt = rec_threshold_in_tbtt;
                ieee80211_ibss_beacon_update_start(ic);
            } else {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "please enter a valid value .ex 0x010102\n");
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Ex.0xaabbcc aa[channel switch time] bb[actions count] cc[recovery time]\n");
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "recovery time must be bigger than channel switch time, actions count must > 0\n");
            }

#undef IBSSDFS_CSA_TIME_MASK
#undef IBSSDFS_ACTION_MASK
#undef IBSSDFS_RECOVER_MASK
        }
        break;
#endif
#if ATH_SUPPORT_IBSS_NETLINK_NOTIFICATION
    case IEEE80211_PARAM_IBSS_SET_RSSI_CLASS:
      {
	int i;
	u_int8_t rssi;
	u_int8_t *pvalue = (u_int8_t*)(extra + 4);

	/* 0th idx is 0 dbm(highest) always */
	vap->iv_ibss_rssi_class[0] = (u_int8_t)-1;

	for( i = 1; i < IBSS_RSSI_CLASS_MAX; i++ ) {
	  rssi = pvalue[i - 1];
	  /* Assumes the values in dbm are already sorted.
	   * Convert to rssi and store them */
	  vap->iv_ibss_rssi_class[i] = (rssi > 95 ? 0 : (95 - rssi));
	}
      }
      break;
    case IEEE80211_PARAM_IBSS_START_RSSI_MONITOR:
      vap->iv_ibss_rssi_monitor = value;
      /* set the hysteresis to atleast 1 */
      if (value && !vap->iv_ibss_rssi_hysteresis)
	vap->iv_ibss_rssi_hysteresis++;
      break;
    case IEEE80211_PARAM_IBSS_RSSI_HYSTERESIS:
      vap->iv_ibss_rssi_hysteresis = value;
        break;
#endif

#if ATH_SUPPORT_WIFIPOS
   case IEEE80211_PARAM_WIFIPOS_TXCORRECTION:
	ieee80211_wifipos_set_txcorrection(vap, value);
   	break;

   case IEEE80211_PARAM_WIFIPOS_RXCORRECTION:
	ieee80211_wifipos_set_rxcorrection(vap, value);
   	break;
#endif

   case IEEE80211_PARAM_DFS_CACTIMEOUT:
#if ATH_SUPPORT_DFS
        retv = ieee80211_dfs_override_cac_timeout(ic, value);
        if (retv != 0)
            retv = -EOPNOTSUPP;
        break;
#else
            retv = -EOPNOTSUPP;
        break;
#endif /* ATH_SUPPORT_DFS */

   case IEEE80211_PARAM_ENABLE_RTSCTS:
       retv = wlan_set_param(vap, IEEE80211_ENABLE_RTSCTS, value);
   break;
    case IEEE80211_PARAM_MAX_AMPDU:
        if ((value >= IEEE80211_MAX_AMPDU_MIN) &&
            (value <= IEEE80211_MAX_AMPDU_MAX)) {
            retv = wlan_set_param(vap, IEEE80211_MAX_AMPDU, value);
 	        if ( retv == EOK ) {
                retv = ENETRESET;
            }
        } else {
            retv = -EINVAL;
        }
        break;
    case IEEE80211_PARAM_VHT_MAX_AMPDU:
        if ((value >= IEEE80211_VHT_MAX_AMPDU_MIN) &&
            (value <= IEEE80211_VHT_MAX_AMPDU_MAX)) {
            retv = wlan_set_param(vap, IEEE80211_VHT_MAX_AMPDU, value);
            if ( retv == EOK ) {
                retv = ENETRESET;
            }
        } else {
            retv = -EINVAL;
        }
        break;
    case IEEE80211_PARAM_IMPLICITBF:
        retv = wlan_set_param(vap, IEEE80211_SUPPORT_IMPLICITBF, value);
        if ( retv == EOK ) {
            retv = ENETRESET;
        }
        break;

    case IEEE80211_PARAM_VHT_SUBFEE:
        if (value == 0 ) {
            /* if SU is disabled, disable MU as well */
            wlan_set_param(vap, IEEE80211_VHT_MUBFEE, value);
        }
        retv = wlan_set_param(vap, IEEE80211_VHT_SUBFEE, value);
        if (retv == EOK && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
        }
        break;

    case IEEE80211_PARAM_VHT_MUBFEE:
        if (value == 1) {
            /* if MU is enabled, enable SU as well */
            wlan_set_param(vap, IEEE80211_VHT_SUBFEE, value);
        }
        retv = wlan_set_param(vap, IEEE80211_VHT_MUBFEE, value);
        if (retv == EOK && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
        }
        break;

    case IEEE80211_PARAM_VHT_SUBFER:
        if (value == 0 ) {
            /* if SU is disabled, disable MU as well */
            wlan_set_param(vap, IEEE80211_VHT_MUBFER, value);
        }
        retv = wlan_set_param(vap, IEEE80211_VHT_SUBFER, value);
        if (retv == EOK && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
        }
        break;

    case IEEE80211_PARAM_VHT_MUBFER:
        if (value == 1 ) {
            /* if MU is enabled, enable SU as well */
            wlan_set_param(vap, IEEE80211_VHT_SUBFER, value);
        }
        retv = wlan_set_param(vap, IEEE80211_VHT_MUBFER, value);
        if (retv == 0 && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
        }
        break;

    case IEEE80211_PARAM_VHT_STS_CAP:
        retv = wlan_set_param(vap, IEEE80211_VHT_BF_STS_CAP, value);
        if (retv == 0)
            retv = ENETRESET;
        break;

    case IEEE80211_PARAM_VHT_SOUNDING_DIM:
        retv = wlan_set_param(vap, IEEE80211_VHT_BF_SOUNDING_DIM, value);
        if (retv == 0)
            retv = ENETRESET;
        break;

    case IEEE80211_PARAM_RC_NUM_RETRIES:
        retv = wlan_set_param(vap, IEEE80211_RC_NUM_RETRIES, value);
        break;
    case IEEE80211_PARAM_256QAM_2G:
        retv = wlan_set_param(vap, IEEE80211_256QAM, value);
        if (retv == EOK) {
            retv = ENETRESET;
        }
        break;
    case IEEE80211_PARAM_11NG_VHT_INTEROP:
        if (osifp->osif_is_mode_offload) {
            retv = wlan_set_param(vap, IEEE80211_11NG_VHT_INTEROP , value);
            if (retv == EOK) {
                retv = ENETRESET;
            }
        } else {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Not supported in this vap \n");
        }
        break;
#if UMAC_VOW_DEBUG
    case IEEE80211_PARAM_VOW_DBG_ENABLE:
        {
            osifp->vow_dbg_en = value;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        if (ic->nss_funcs)
            ic->nss_funcs->ic_osif_nss_ol_vdev_set_cfg(vap->iv_txrx_handle, OSIF_NSS_WIFI_VDEV_VOW_DBG_MODE);
#endif
        }
        break;
#endif

#if ATH_SUPPORT_SPLITMAC
    case IEEE80211_PARAM_SPLITMAC:
        vap->iv_splitmac = !!value;

        if (vap->iv_splitmac) {
            osifp->app_filter =  IEEE80211_FILTER_TYPE_ALL;
            wlan_set_param(vap, IEEE80211_TRIGGER_MLME_RESP, 1);
        } else {
            osifp->app_filter =  0;
            wlan_set_param(vap, IEEE80211_TRIGGER_MLME_RESP, 0);
        }
        break;
#endif
#if ATH_PERF_PWR_OFFLOAD
    case IEEE80211_PARAM_VAP_TX_ENCAP_TYPE:
        retv = wlan_set_param(vap, IEEE80211_VAP_TX_ENCAP_TYPE, value);
        if(retv == EOK) {
            retv = ENETRESET;
        }
        break;
    case IEEE80211_PARAM_VAP_RX_DECAP_TYPE:
        retv = wlan_set_param(vap, IEEE80211_VAP_RX_DECAP_TYPE, value);
        if(retv == EOK) {
            retv = ENETRESET;
        }
        break;
#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
    case IEEE80211_PARAM_RAWMODE_SIM_TXAGGR:
        retv = wlan_set_param(vap, IEEE80211_RAWMODE_SIM_TXAGGR, value);
        break;
    case IEEE80211_PARAM_RAWMODE_SIM_DEBUG:
        retv = wlan_set_param(vap, IEEE80211_RAWMODE_SIM_DEBUG, value);
        break;
#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */
#endif /* ATH_PERF_PWR_OFFLOAD */
    case IEEE80211_PARAM_STA_FIXED_RATE:
        /* set a fixed data rate for an associated STA on a AP vap.  * assumes that vap is already enabled for fixed rate, and * this
         * setting overrides the vap's setting.  * * encoding: aid << 8 | preamble_type << 6 | nss << 4 | mcs * preamble_type = 0x3 for
         * VHT  nss = 0 for 1 stream = 0x2 for HT = 1 for 2 streams = 0x1 for CCK = 2 for 3
         * streams = 0x0 for OFDM = 3 for 4 streams
         */
        if (osifp->os_opmode != IEEE80211_M_HOSTAP) {
            return -EINVAL;
    }
        if (wlan_get_param(vap, IEEE80211_FIXED_RATE) ||
                wlan_get_param(vap, IEEE80211_FIXED_VHT_MCS)) {
            struct find_wlan_node_req req;
            req.assoc_id = (value >> 8) & 0x7ff;
            req.node = NULL;
            wlan_iterate_station_list(vap, find_wlan_node_by_associd, &req);
            if (req.node) {
                u_int8_t fixed_rate = value & 0xff;
                retv = wlan_node_set_fixed_rate(req.node, fixed_rate);
            } else {
                return -EINVAL;
            }
        }
        break;

#if QCA_AIRTIME_FAIRNESS
    case IEEE80211_PARAM_ATF_TXBUF_SHARE:
        {
            int reset = 0;
            if (vap->iv_ic->atf_txbuf_share && !(value & 0xf))
                reset = 1;
            else if (!vap->iv_ic->atf_txbuf_share && (value & 0xf))
                reset = 1;
            vap->iv_ic->atf_txbuf_share = value & 0xf;
            if (reset) {
                wlan_if_t tmpvap;
                TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
                    struct net_device *tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
                    retv = IS_UP(tmpdev) ? -osif_vap_init(tmpdev, RESCAN) : 0;
                }
            }
            break;
        }
    case IEEE80211_PARAM_ATF_TXBUF_MAX:
        if (value >= 0 && value <= ATH_TXBUF)
            vap->iv_ic->atf_txbuf_max = value;
        else
            vap->iv_ic->atf_txbuf_max = ATF_MAX_BUFS;
        break;
    case IEEE80211_PARAM_ATF_TXBUF_MIN:
        if (value >= 0 && value <= ATH_TXBUF)
            vap->iv_ic->atf_txbuf_min = value;
        else
            vap->iv_ic->atf_txbuf_min = ATF_MIN_BUFS;
        break;
    case  IEEE80211_PARAM_ATF_OPT:
        retv = wlan_set_param(vap, IEEE80211_ATF_OPT, value);
        if(retv != EOK)
        {
            u_int16_t old_max_aid = 0, old_len = 0;
            u_int32_t numclients = 0;
            struct net_device *tmpdev = NULL;

            numclients = retv;
            TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
                old_max_aid = tmpvap->iv_max_aid;
                old_len = howmany(tmpvap->iv_max_aid, 32) * sizeof(u_int32_t);
                tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
                retv = IS_UP(tmpdev) ? -osif_vap_init(tmpdev, RESCAN) : 0;

                /* We will reject station when associated aid >= iv_max_aid, such that
                max associated station should be value + 1 */
                tmpvap->iv_max_aid = numclients;
                /* The interface is up, we may need to reallocation bitmap(tim, aid) */
                if (IS_UP(tmpdev)) {
                    if (tmpvap->iv_alloc_tim_bitmap) {
                        error = tmpvap->iv_alloc_tim_bitmap(tmpvap);
                    }
                    if(!error)
                        error = wlan_node_alloc_aid_bitmap(tmpvap, old_len);
                }
                if(error) {
                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Error! Failed to change the number of max clients to %d\n\r",numclients);
                    vap->iv_max_aid = old_max_aid;
                    return -ENOMEM;
                }
            }
            ic->ic_num_clients = numclients;
        } else if ((ic->ic_is_mode_offload(ic)) && (ic->ic_atf_tput_tbl_num)) {
            struct net_device *tmpdev = NULL;
            TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
                tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
                retv = IS_UP(tmpdev) ? -osif_vap_init(tmpdev, RESCAN) : 0;
            }

        }
        break;
    case IEEE80211_PARAM_ATF_OVERRIDE_AIRTIME_TPUT:
        vap->iv_ic->ic_atf_airtime_override = value;
        break;
    case  IEEE80211_PARAM_ATF_PER_UNIT:
        ic->atfcfg_set.percentage_unit = PER_UNIT_1000;
        break;
    case  IEEE80211_PARAM_ATF_MAX_CLIENT:
    {
        if(!osifp->osif_is_mode_offload) {
            u_int8_t resetvap = 0;
            u_int16_t old_max_aid = 0, old_len = 0;
            u_int32_t numclients = 0;
            struct net_device *tmpdev = NULL;

            if (ic->ic_atf_tput_based && value) {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "can't enable maxclients as tput based atf is enabled\n");
                return -EINVAL;
            }

            ic->ic_atf_maxclient = !!value;
            if(ic->ic_atf_maxclient)
            {
                /* set num_clients to IEEE80211_128_AID when ic_atf_maxclient is set */
                if(ic->ic_num_clients != IEEE80211_128_AID)
                {
                    numclients = IEEE80211_128_AID;
                    resetvap = 1;
                }
            } else {
                if( (ic->atf_commit) && (ic->ic_num_clients != IEEE80211_ATF_AID_DEF))
                {
                    /* When ATF is enabled, set num_clients to IEEE80211_ATF_AID_DEF */
                    numclients = IEEE80211_ATF_AID_DEF;
                    resetvap = 1;
                } else if (!(ic->atf_commit) && (ic->ic_num_clients != IEEE80211_512_AID)) {
                    /* When ATF is disabled, set num_clients to IEEE80211_128_AID */
                    numclients = IEEE80211_128_AID;
                    resetvap = 1;
                }
            }
            if(resetvap)
            {
                TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
                    old_max_aid = tmpvap->iv_max_aid;
                    old_len = howmany(tmpvap->iv_max_aid, 32) * sizeof(u_int32_t);
                    tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
                    retv = IS_UP(tmpdev) ? -osif_vap_init(tmpdev, RESCAN) : 0;
                    /* We will reject station when associated aid >= iv_max_aid, such that
                    max associated station should be value + 1 */
                    tmpvap->iv_max_aid = numclients;

                    /* The interface is up, we may need to reallocation bitmap(tim, aid) */
                    if (IS_UP(tmpdev)) {
                        if (tmpvap->iv_alloc_tim_bitmap) {
                            error = tmpvap->iv_alloc_tim_bitmap(tmpvap);
                        }
                        if(!error)
                            error = wlan_node_alloc_aid_bitmap(tmpvap, old_len);
                    }
                    if(error) {
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Error! Failed to change the number of max clients to %d\n\r",numclients);
                        vap->iv_max_aid = old_max_aid;
                        return -ENOMEM;
                    }
                    ic->ic_num_clients = numclients;
                }
            }
        } else {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ATF_MAX_CLIENT not valid for this VAP \n");
            retv = EOPNOTSUPP;
        }
    }
    break;
    case  IEEE80211_PARAM_ATF_SSID_GROUP:
        ic->ic_atf_ssidgroup = !!value;
    break;
    case IEEE80211_PARAM_ATF_SSID_SCHED_POLICY:
        retv = wlan_set_param(vap, IEEE80211_ATF_SSID_SCHED_POLICY, value);
    break;
#endif
#if ATH_SSID_STEERING
    case IEEE80211_PARAM_VAP_SSID_CONFIG:
        retv = wlan_set_param(vap, IEEE80211_VAP_SSID_CONFIG, value);
        break;
#endif
    case IEEE80211_PARAM_RX_FILTER_MONITOR:
        if(IEEE80211_M_MONITOR != vap->iv_opmode && !vap->iv_smart_monitor_vap && !vap->iv_special_vap_mode) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"Not monitor VAP or Smart monitor VAP!\n");
            return -EINVAL;
        }
        retv = wlan_set_param(vap, IEEE80211_RX_FILTER_MONITOR, value);
        break;
    case  IEEE80211_PARAM_RX_FILTER_NEIGHBOUR_PEERS_MONITOR:
        /* deliver configured bss peer packets, associated to smart
         * monitor vap and filter out other valid/invalid peers
         */
        if(!vap->iv_smart_monitor_vap) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"Not smart monitor VAP!\n");
            return -EINVAL;
        }
        retv = wlan_set_param(vap, IEEE80211_RX_FILTER_NEIGHBOUR_PEERS_MONITOR, value);
        break;
    case IEEE80211_PARAM_AMPDU_DENSITY_OVERRIDE:
        if(value < 0) {
            ic->ic_mpdudensityoverride = 0;
        } else if(value <= IEEE80211_HTCAP_MPDUDENSITY_MAX) {
            /* mpdudensityoverride
             * Bits
             * 7 --  4   3  2  1    0
             * +------------------+----+
             * |       |  MPDU    |    |
             * | Rsvd  | DENSITY  |E/D |
             * +---------------+-------+
             */
            ic->ic_mpdudensityoverride = 1;
            ic->ic_mpdudensityoverride |= ((u_int8_t)value & 0x07) << 1;
        } else {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Usage:\n"
                    "-1 - Disable mpdu density override \n"
                    "%d - No restriction \n"
                    "%d - 1/4 usec \n"
                    "%d - 1/2 usec \n"
                    "%d - 1 usec \n"
                    "%d - 2 usec \n"
                    "%d - 4 usec \n"
                    "%d - 8 usec \n"
                    "%d - 16 usec \n",
                    IEEE80211_HTCAP_MPDUDENSITY_NA,
                    IEEE80211_HTCAP_MPDUDENSITY_0_25,
                    IEEE80211_HTCAP_MPDUDENSITY_0_5,
                    IEEE80211_HTCAP_MPDUDENSITY_1,
                    IEEE80211_HTCAP_MPDUDENSITY_2,
                    IEEE80211_HTCAP_MPDUDENSITY_4,
                    IEEE80211_HTCAP_MPDUDENSITY_8,
                    IEEE80211_HTCAP_MPDUDENSITY_16);
            retv = EINVAL;
        }
        /* Reset VAP */
        if(retv != EINVAL) {
            wlan_chan_t chan = wlan_get_bss_channel(vap);
            if (chan != IEEE80211_CHAN_ANYC) {
                retv = ENETRESET;
            }
        }
        break;

    case IEEE80211_PARAM_SMART_MESH_CONFIG:
        retv = wlan_set_param(vap, IEEE80211_SMART_MESH_CONFIG, value);
        break;
#if MESH_MODE_SUPPORT
    case IEEE80211_PARAM_MESH_CAPABILITIES:
        retv = wlan_set_param(vap, IEEE80211_MESH_CAPABILITIES, value);
        break;
    case IEEE80211_PARAM_ADD_LOCAL_PEER:
        if (vap->iv_mesh_vap_mode) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "adding local peer \n");
            retv = ieee80211_add_localpeer(vap,extra);
        } else {
            return -EPERM;
        }
        break;
    case IEEE80211_PARAM_SET_MHDR:
        if(vap && vap->iv_mesh_vap_mode) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "setting mhdr %x\n",value);
            vap->mhdr = value;
        } else {
            return -EPERM;
        }
        break;
    case IEEE80211_PARAM_ALLOW_DATA:
        if (vap->iv_mesh_vap_mode) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " authorise keys \n");
            retv = ieee80211_authorise_local_peer(vap,extra);
        } else {
            return -EPERM;
        }
        break;
    case IEEE80211_PARAM_SET_MESHDBG:
        if(vap && vap->iv_mesh_vap_mode) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "mesh dbg %x\n",value);
            vap->mdbg = value;
        } else {
            return -EPERM;
        }
        break;
    case IEEE80211_PARAM_CONFIG_MGMT_TX_FOR_MESH:
        if (vap->iv_mesh_vap_mode) {
          retv = wlan_set_param(vap, IEEE80211_CONFIG_MGMT_TX_FOR_MESH, value);
        } else {
            return -EPERM;
        }
        break;

    case IEEE80211_PARAM_CONFIG_RX_MESH_FILTER:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_RX_MESH_FILTER, value);
        break;

#if ATH_DATA_RX_INFO_EN
    case IEEE80211_PARAM_RXINFO_PERPKT:
        vap->rxinfo_perpkt = value;
        break;
#endif
#endif
    case IEEE80211_PARAM_CONFIG_ASSOC_WAR_160W:
        if ((value == 0) || ASSOCWAR160_IS_VALID_CHANGE(value))
            retv = wlan_set_param(vap, IEEE80211_CONFIG_ASSOC_WAR_160W, value);
        else {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Invalid value %d. Valid bitmap values are 0:Disable, 1:Enable VHT OP, 3:Enable VHT OP and VHT CAP\n",value);
            return -EINVAL;
        }
        break;
    case IEEE80211_PARAM_WHC_APINFO_SFACTOR:
        if((vap->iv_opmode == IEEE80211_M_STA) && (value >= 1) && (value <= 100))
            vap->iv_whc_scaling_factor = value;
        break;
    case IEEE80211_PARAM_WHC_APINFO_UPLINK_RATE:
        ic->ic_uplink_rate = value;
        TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next)
        {
            if(tmpvap->iv_opmode == IEEE80211_M_HOSTAP)
            {
                IEEE80211_VAP_WHC_AP_INFO_UPDATE_ENABLE(tmpvap);
            }
        }
        break;
    case IEEE80211_PARAM_WHC_CAP_RSSI:
        vap->iv_whc_son_cap_rssi = value;
      break;
    case IEEE80211_PARAM_SON:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_SON, value);
        IEEE80211_VAP_WHC_AP_INFO_UPDATE_ENABLE(vap);
        break;
    case IEEE80211_PARAM_WHC_APINFO_OTHERBAND_BSSID:
        ieee80211_ucfg_set_otherband_bssid(vap, &val[1]);
        IEEE80211_VAP_WHC_AP_INFO_UPDATE_ENABLE(vap);
        break;
    case IEEE80211_PARAM_WHC_APINFO_ROOT_DIST:
        vap->iv_whc_root_ap_distance = value;
        IEEE80211_VAP_WHC_AP_INFO_UPDATE_ENABLE(vap);
        break;
    case IEEE80211_PARAM_REPT_MULTI_SPECIAL:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_REPT_MULTI_SPECIAL, value);
        break;
    case IEEE80211_PARAM_SEND_PROBE_REQ:
        ieee80211_ucfg_send_probereq(vap, value);
        break;
    case IEEE80211_PARAM_RAWMODE_PKT_SIM:
        retv = wlan_set_param(vap, IEEE80211_RAWMODE_PKT_SIM, value);
        break;
    case IEEE80211_PARAM_CONFIG_RAW_DWEP_IND:
        if ((value == 0) || (value == 1))
            retv = wlan_set_param(vap, IEEE80211_CONFIG_RAW_DWEP_IND, value);
        else {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Invalid value %d. Valid values are 0:Disable, 1:Enable\n",value);
            return -EINVAL;
        }
        break;
    case IEEE80211_PARAM_CUSTOM_CHAN_LIST:
        retv = wlan_set_param(vap,IEEE80211_CONFIG_PARAM_CUSTOM_CHAN_LIST, value);
        break;
#if UMAC_SUPPORT_ACFG
    case IEEE80211_PARAM_DIAG_WARN_THRESHOLD:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_DIAG_WARN_THRESHOLD, value);
        break;
    case IEEE80211_PARAM_DIAG_ERR_THRESHOLD:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_DIAG_ERR_THRESHOLD, value);
        break;
#endif
     case IEEE80211_PARAM_CONFIG_REV_SIG_160W:
        if(!wlan_get_param(vap, IEEE80211_CONFIG_ASSOC_WAR_160W)){
            if ((value == 0) || (value == 1))
                retv = wlan_set_param(vap, IEEE80211_CONFIG_REV_SIG_160W, value);
            else {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Invalid value %d. Valid values are 0:Disable, 1:Enable\n",value);
                return -EINVAL;
            }
        } else {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "revsig160 not supported with assocwar160\n");
            return -EINVAL;
        }
        break;
     case IEEE80211_PARAM_CONFIG_MU_CAP_WAR:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_MU_CAP_WAR, value);
        break;
     case IEEE80211_PARAM_CONFIG_MU_CAP_TIMER:
        if ((value >= 1) && (value <= 300))
            retv = wlan_set_param(vap, IEEE80211_CONFIG_MU_CAP_TIMER, value);
        else {
            IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_IOCTL,
                            "Invalid value %d. Valid value is between 1 and 300\n",value);
            return -EINVAL;
        }
        break;
    case IEEE80211_PARAM_DISABLE_SELECTIVE_HTMCS_FOR_VAP:
        if(vap->iv_opmode == IEEE80211_M_HOSTAP) {
            retv = wlan_set_param(vap, IEEE80211_CONFIG_DISABLE_SELECTIVE_HTMCS, value);
            if(retv == 0)
                retv = ENETRESET;
        } else {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "This iwpriv option disable_htmcs is valid only for AP mode vap\n");
        }
        break;
    case IEEE80211_PARAM_CONFIGURE_SELECTIVE_VHTMCS_FOR_VAP:
        if(vap->iv_opmode == IEEE80211_M_HOSTAP) {
            if(value != 0) {
                retv = wlan_set_param(vap, IEEE80211_CONFIG_CONFIGURE_SELECTIVE_VHTMCS, value);
                if(retv == 0)
                    retv = ENETRESET;
            }
        } else {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "This iwpriv option conf_11acmcs is valid only for AP mode vap\n");
        }
        break;
    case IEEE80211_PARAM_RDG_ENABLE:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_RDG_ENABLE, value);
        break;
    case IEEE80211_PARAM_CLEAR_QOS:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_CLEAR_QOS,value);
        break;
    case IEEE80211_PARAM_TRAFFIC_STATS:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_TRAFFIC_STATS,value);
        break;
    case IEEE80211_PARAM_TRAFFIC_RATE:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_TRAFFIC_RATE,value);
        break;
    case IEEE80211_PARAM_TRAFFIC_INTERVAL:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_TRAFFIC_INTERVAL,value);
        break;
    case IEEE80211_PARAM_WATERMARK_THRESHOLD:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_WATERMARK_THRESHOLD,value);
        break;
    case IEEE80211_PARAM_ENABLE_VENDOR_IE:
	if( value == 0 || value == 1) {
	    if (vap->iv_ena_vendor_ie != value) {
                vap->iv_update_vendor_ie = 1;
            }
	    vap->iv_ena_vendor_ie = value;
	} else {
	    qdf_print("%s Enter 1: enable vendor ie, 0: disable vendor ie \n",__func__);
	}
	break;
#if UMAC_SUPPORT_ACL
    case IEEE80211_PARAM_CONFIG_ASSOC_DENIAL_NOTIFY:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_ASSOC_DENIAL_NOTIFICATION, value);
        break;
    case IEEE80211_PARAM_MACCMD_SEC:
        retv = wlan_set_acl_policy(vap, value, IEEE80211_ACL_FLAG_ACL_LIST_2);
        break;
#endif /*UMAC_SUPPORT_ACL*/
    case IEEE80211_PARAM_CONFIG_MON_DECODER:
        if (IEEE80211_M_MONITOR != vap->iv_opmode) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"Not Monitor VAP!\n");
            return -EINVAL;
        }
        /* monitor vap decoder header type: radiotap=0(default) prism=1 */
        if (value != 0 && value != 1) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"Invalid value! radiotap=0(default) prism=1 \n");
            return -EINVAL;
        }
        wlan_set_param(vap, IEEE80211_CONFIG_MON_DECODER, value);
        break;
    case IEEE80211_PARAM_SIFS_TRIGGER_RATE:
        if (ic->ic_vap_set_param) {
           vap->iv_sifs_trigger_rate = value;
           retv = ic->ic_vap_set_param(vap, IEEE80211_SIFS_TRIGGER_RATE, (u_int32_t)value);
        }
        break;
    case IEEE80211_PARAM_BEACON_RATE_FOR_VAP:
        if(vap->iv_opmode == IEEE80211_M_HOSTAP) {
            int *rate_kbps = NULL;
            int i,j,rateKbps = 0;

            switch (vap->iv_des_mode)
            {
                case IEEE80211_MODE_11B:
                    {
                        rate_table.nrates = sizeof(basic_11b_rate)/sizeof(basic_11b_rate[0]);
                        rate_table.rates = (int *)&basic_11b_rate;
                        /* Checking the boundary condition for the valid rates */
                        if ((value < 1000) || (value > 11000)) {
                            qdf_print("%s : WARNING: Please try a valid rate between 1000 to 11000 kbps.\n",__func__);
                            return -EINVAL;
                        }
                    }
                    break;

                case IEEE80211_MODE_TURBO_G:
                case IEEE80211_MODE_11NG_HT20:
                case IEEE80211_MODE_11NG_HT40PLUS:
                case IEEE80211_MODE_11NG_HT40MINUS:
                case IEEE80211_MODE_11NG_HT40:
                case IEEE80211_MODE_11G:
                    {
                        rate_table.nrates = sizeof(basic_11bgn_rate)/sizeof(basic_11bgn_rate[0]);
                        rate_table.rates = (int *)&basic_11bgn_rate;
                        /* Checking the boundary condition for the valid rates */
                        if ((value < 1000) || (value > 24000)){
                            qdf_print("%s : WARNING: Please try a valid rate between 1000 to 24000 kbps.\n",__func__);
                            return -EINVAL;
                        }
                    }
                    break;

                case IEEE80211_MODE_11A:
                case IEEE80211_MODE_TURBO_A:
                case IEEE80211_MODE_11NA_HT20:
                case IEEE80211_MODE_11NA_HT40PLUS:
                case IEEE80211_MODE_11NA_HT40MINUS:
                case IEEE80211_MODE_11NA_HT40:
                case IEEE80211_MODE_11AC_VHT20:
                case IEEE80211_MODE_11AC_VHT40PLUS:
                case IEEE80211_MODE_11AC_VHT40MINUS:
                case IEEE80211_MODE_11AC_VHT40:
                case IEEE80211_MODE_11AC_VHT80:
                case IEEE80211_MODE_11AC_VHT160:
                case IEEE80211_MODE_11AC_VHT80_80:
                    {
                        rate_table.nrates = sizeof(basic_11na_rate)/sizeof(basic_11na_rate[0]);
                        rate_table.rates = (int *)&basic_11na_rate;
                        /* Checking the boundary condition for the valid rates */
                        if ((value < 6000) || (value > 24000)){
                            qdf_print("%s : WARNING: Please try a valid rate between 6000 to 24000 kbps.\n",__func__);
                            return -EINVAL;
                        }
                    }
                    break;

                default:
                    {
                        qdf_print("%s : WARNING:Invalid channel mode.\n",__func__);
                        return -EINVAL;
                    }
            }
            rate_kbps = rate_table.rates;

            /* Check if the rate given by user is a valid basic rate.
             * If it is valid basic rate then go with that rate or else
             * if the rate passed by the user is not valid basic rate but
             * it falls inside the valid rate boundary corresponding to the
             * phy mode, then opt for the next valid basic rate.
             */
            for (i = 0; i < rate_table.nrates; i++) {
                if (value == *rate_kbps) {
                    rateKbps = *rate_kbps;
                } else if (value < *rate_kbps) {
                    rateKbps = *rate_kbps;
                    qdf_print("%s : MSG: Not a valid basic rate.\n",__func__);
                    qdf_print("Since the requested rate is below 24Mbps, moving forward and selecting the next valid basic rate : %d (Kbps)\n",rateKbps);
                }
                if (rateKbps) {
                    for (j = 0; j < ni->ni_rates.rs_nrates; j++) {
                        if (rateKbps == (((ni->ni_rates.rs_rates[j] & IEEE80211_RATE_VAL)* 1000) / 2)) {
                            found = 1;
                            break;
                        }
                    }
                    if (!found) {
                        if (rateKbps == HIGHEST_BASIC_RATE) {
                            qdf_print("%s : MSG: Reached end of the table.\n",__func__);
                        } else {
                            value = *(rate_kbps+1);
                            qdf_print("%s : MSG: User opted rate is disabled. Hence going for the next rate: %d (Kbps)\n",__func__,value);
                        }
                    } else {
                        qdf_print("%s : Rate to be configured for beacon is: %d (Kbps)\n",__func__,rateKbps);
                        break;
                    }
                }
                rate_kbps++;
            }

            /* Suppose user has passed one rate and along with that rate the
             * higher rates are also not available in the rate table then
             * go with the lowest available basic rate.
             */
            if (!found) {
                rateKbps = vap->iv_mgt_rate;
                qdf_print("%s: MSG: The opted rate or higher rates are not available in node rate table.\n",__func__);
                qdf_print("MSG: Hence choosing the lowest available rate : %d (Kbps)\n",rateKbps);
            }
            retv = wlan_set_param(vap, IEEE80211_BEACON_RATE_FOR_VAP,rateKbps);
            if(retv == 0)
                retv = ENETRESET;
        } else {
            qdf_print("%s : WARNING: Setting beacon rate is allowed only for AP VAP \n",__func__);
            return -EINVAL;
        }
        break;
    case IEEE80211_PARAM_DISABLE_SELECTIVE_LEGACY_RATE_FOR_VAP:
        if(vap->iv_opmode == IEEE80211_M_HOSTAP) {

            switch (vap->iv_des_mode)
            {
                case IEEE80211_MODE_11A:
                case IEEE80211_MODE_TURBO_A:
                case IEEE80211_MODE_11NA_HT20:
                case IEEE80211_MODE_11NA_HT40PLUS:
                case IEEE80211_MODE_11NA_HT40MINUS:
                case IEEE80211_MODE_11NA_HT40:
                case IEEE80211_MODE_11AC_VHT20:
                case IEEE80211_MODE_11AC_VHT40PLUS:
                case IEEE80211_MODE_11AC_VHT40MINUS:
                case IEEE80211_MODE_11AC_VHT40:
                case IEEE80211_MODE_11AC_VHT80:
                case IEEE80211_MODE_11AC_VHT160:
                case IEEE80211_MODE_11AC_VHT80_80:
                   /* Mask has been set for rates: 24, 12 and 6 Mbps */
                    basic_valid_mask = 0x0150;
                    break;
                case IEEE80211_MODE_11B:
                   /* Mask has been set for rates: 11, 5.5, 2 and 1 Mbps */
                    basic_valid_mask = 0x000F;
                    break;
                case IEEE80211_MODE_TURBO_G:
                case IEEE80211_MODE_11NG_HT20:
                case IEEE80211_MODE_11NG_HT40PLUS:
                case IEEE80211_MODE_11NG_HT40MINUS:
                case IEEE80211_MODE_11NG_HT40:
                case IEEE80211_MODE_11G:
                   /* Mask has been set for rates: 24, 12, 6, 11, 5.5, 2 and 1 Mbps */
                    basic_valid_mask = 0x015F;
                    break;
                default:
                    break;
            }
           /*
            * Mask has been set as per the desired mode so that user will not be able to disable
            * all the supported basic rates.
            */

            if ((value & basic_valid_mask) != basic_valid_mask) {
                retv = wlan_set_param(vap, IEEE80211_CONFIG_DISABLE_SELECTIVE_LEGACY_RATE, value);
                if(retv == 0)
                    retv = ENETRESET;
            } else {
                qdf_print("%s : WARNING: Disabling all basic rates is not permitted.\n",__func__);
            }
        } else {
            qdf_print("%s : WARNING: This iwpriv option dis_legacy is valid only for the VAP in AP mode\n",__func__);
        }
        break;

    case IEEE80211_PARAM_CONFIG_NSTSCAP_WAR:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_NSTSCAP_WAR,value);
    break;

    case IEEE80211_PARAM_TXPOW_MGMT:
    {
        if(!tx_pow_mgmt_valid(frame_subtype,&tx_power))
            return -EINVAL;
        transmit_power = (tx_power &  0xFF);
        vap->iv_txpow_mgt_frm[(frame_subtype >> IEEE80211_FC0_SUBTYPE_SHIFT)] = transmit_power;
        if(ic->ic_is_mode_offload(ic)){
            retv = ic->ic_vap_set_param(vap, IEEE80211_CONFIG_VAP_TXPOW_MGMT, frame_subtype);
        } else {
            vap->iv_txpow_mgmt(vap,frame_subtype,transmit_power);
        }
    }
    break;

    case IEEE80211_PARAM_CHANNEL_SWITCH_MODE:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_CHANNEL_SWITCH_MODE, value);
        break;

    case IEEE80211_PARAM_ENABLE_ECSA_IE:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_ECSA_IE, value);
        break;

    case IEEE80211_PARAM_ECSA_OPCLASS:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_ECSA_OPCLASS, value);
        break;

    case IEEE80211_PARAM_BACKHAUL:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_BACKHAUL, value);
        break;

#if DYNAMIC_BEACON_SUPPORT
    case IEEE80211_PARAM_DBEACON_EN:
        if (value > 1  ||  value < 0) {
            qdf_print("Invalid value! value should be either 0 or 1 \n");
            return -EINVAL;
        }
        if (IEEE80211_VAP_IS_HIDESSID_ENABLED(vap)) {
            if (vap->iv_dbeacon != value) {
                if (value == 0) { /*  value 0 */
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "Resume beacon \n");
                    qdf_spin_lock_bh(&vap->iv_dbeacon_lock);
                    OS_CANCEL_TIMER(&vap->iv_dbeacon_suspend_beacon);
                    if (ieee80211_mlme_beacon_suspend_state(vap)) {
                        ieee80211_mlme_set_beacon_suspend_state(vap, false);
                    }
                    vap->iv_dbeacon = value;
                    qdf_spin_unlock_bh(&vap->iv_dbeacon_lock);
                } else { /*  value 1 */
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "Suspend beacon \n");
                    qdf_spin_lock_bh(&vap->iv_dbeacon_lock);
                    if (!ieee80211_mlme_beacon_suspend_state(vap)) {
                        ieee80211_mlme_set_beacon_suspend_state(vap, true);
                    }
                    vap->iv_dbeacon = value;
                    qdf_spin_unlock_bh(&vap->iv_dbeacon_lock);
                }
                wlan_deauth_all_stas(vap); /* dissociating all associated stations */
                retv = ENETRESET;
                break;
            }
            retv = EOK;
        } else {
            qdf_print("%s:%d: Dynamic beacon not allowed for vap-%d(%s)) as hidden ssid not configured. \n",
                    __func__,__LINE__,vap->iv_unit,vap->iv_netdev_name);
            qdf_print("Enable hidden ssid before enable dynamic beacon \n");
            return -EINVAL;
        }
        break;

    case IEEE80211_PARAM_DBEACON_RSSI_THR:
        if (value < 10  ||  value > 100) { /* min:10  max:100 */
            qdf_print("Invalid value %d. Valid values are between 10  to 100 \n",value);
            return -EINVAL;
        }
        vap->iv_dbeacon_rssi_thr = (int8_t)value;
        break;

    case IEEE80211_PARAM_DBEACON_TIMEOUT:
        if (value < 30  ||  value > 3600) { /* min:30 secs  max:1hour */
            qdf_print("Invalid value %d. Valid values are between 30secs to 3600secs \n",value);
            return -EINVAL;
        }
        vap->iv_dbeacon_timeout = value;
        break;

    case IEEE80211_PARAM_CONFIG_TX_CAPTURE:
        wlan_set_param(vap, IEEE80211_CONFIG_TX_CAPTURE, value);
        break;
#endif
    case IEEE80211_PARAM_CONFIG_TX_CAPTURE_DA:
        if (IEEE80211_M_MONITOR != vap->iv_opmode) {
            qdf_print("Not a Monitor VAP!\n");
            return -EINVAL;
        }
        /* Enable Tx capture for DA radio */
        if (value != 0 && value != 1) {
            qdf_print("Invalid value! Tx capture for DA. enable=1 disable=0(default)\n");
            return -EINVAL;
        }
        wlan_set_param(vap, IEEE80211_CONFIG_TX_CAPTURE_DA, value);
        break;


    case IEEE80211_PARAM_EXT_NSS_CAPABLE:
        if (!ic->ic_is_mode_offload(ic)) {
            return -EPERM;
        }
        retv = wlan_set_param(vap, IEEE80211_CONFIG_EXT_NSS_CAPABLE, value);
        if (retv == 0) {
            retv = ENETRESET;
        }
        break;

#if QCN_IE
    case IEEE80211_PARAM_BCAST_PROBE_RESPONSE_ENABLE:
        if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
            vap->iv_bpr_enable = !!value;
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "Set the bpr_enable to %d\n", vap->iv_bpr_enable);
        } else {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
                                        "Invalid. Allowed only in HOSTAP mode\n");
        }
        break;
    case IEEE80211_PARAM_BCAST_PROBE_RESPONSE_DELAY:
        if (value < 1 || value > 255) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "Invalid value! Broadcast response delay should be between 1 and 255 \n");
            return -EINVAL;
        }
        vap->iv_bpr_delay = value;
        break;
    case IEEE80211_PARAM_BCAST_PROBE_RESPONSE_LATENCY_COMPENSATION:
        if (value < 1 || value > 10) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"Invalid value!"
                "Broadcast response latency compensation should be between 1 and 10 \n");
            return -EINVAL;
        }
        ic->ic_bpr_latency_comp = value;
        break;
    case IEEE80211_PARAM_BEACON_LATENCY_COMPENSATION:
        if (value < 1 || value > 10) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"Invalid value!"
                "Beacon latency compensation should be between 1 and 10 \n");
            return -EINVAL;
        }
        ic->ic_bcn_latency_comp = value;
        break;
#endif

    case IEEE80211_PARAM_CSL_SUPPORT:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_CSL_SUPPORT, value);
        break;

    case IEEE80211_PARAM_EXT_NSS_SUPPORT:
        if (!ic->ic_is_mode_offload(ic)) {
            return -EPERM;
        }
        retv = wlan_set_param(vap, IEEE80211_CONFIG_EXT_NSS_SUPPORT, value);
        if (retv == 0) {
            retv = ENETRESET;
        }
        break;

    case IEEE80211_PARAM_DISABLE_CABQ :
        retv = wlan_set_param(vap, IEEE80211_FEATURE_DISABLE_CABQ, value);
        break;

    case IEEE80211_PARAM_ENABLE_FILS:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_FILS, value);
        break;
    }

    if (retv == ENETRESET)
    {
        retv = IS_UP(dev) ? osif_vap_init(dev, RESCAN) : 0;
    }
    return retv;

}

static char num_to_char(u_int8_t n)
{
    if ( n >= 10 && n <= 15 )
        return n  - 10 + 'A';
    if ( n >= 0 && n <= 9 )
        return n  + '0';
    return ' '; //Blank space
}

/* convert MAC address in array format to string format
 * inputs:
 *     addr - mac address array
 * output:
 *     macstr - MAC address string format */
static void macaddr_num_to_str(u_int8_t *addr, char *macstr)
{
    int i, j=0;

    for ( i = 0; i < IEEE80211_ADDR_LEN; i++ ) {
        macstr[j++] = num_to_char(addr[i] >> 4);
        macstr[j++] = num_to_char(addr[i] & 0xF);
    }
}

int ieee80211_ucfg_getparam(wlan_if_t vap, int param, int *value)
{
    osif_dev  *osifp = (osif_dev *)wlan_vap_get_registered_handle(vap);
    wlan_dev_t ic = wlan_vap_get_devhandle(vap);
    char *extra = (char *)value;
    int retv = 0;
    int *txpow_frm_subtype = value;
    u_int8_t frame_subtype;
#if ATH_SUPPORT_DFS
    int tmp;
#endif
	if (!osifp || osifp->is_delete_in_progress)
		return -EINVAL;

    switch (param)
    {
    case IEEE80211_PARAM_MAXSTA:
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Getting Max Stations: %d\n", vap->iv_max_aid - 1);
        *value = vap->iv_max_aid - 1;
        break;
    case IEEE80211_PARAM_AUTO_ASSOC:
        *value = wlan_get_param(vap, IEEE80211_AUTO_ASSOC);
        break;
    case IEEE80211_PARAM_VAP_COUNTRY_IE:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_COUNTRY_IE);
        break;
    case IEEE80211_PARAM_VAP_DOTH:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_DOTH);
        break;
    case IEEE80211_PARAM_HT40_INTOLERANT:
        *value = wlan_get_param(vap, IEEE80211_HT40_INTOLERANT);
        break;

    case IEEE80211_PARAM_CHWIDTH:
        *value = wlan_get_param(vap, IEEE80211_CHWIDTH);
        break;

    case IEEE80211_PARAM_CHEXTOFFSET:
        *value = wlan_get_param(vap, IEEE80211_CHEXTOFFSET);
        break;
#ifdef ATH_SUPPORT_QUICK_KICKOUT
    case IEEE80211_PARAM_STA_QUICKKICKOUT:
        *value = wlan_get_param(vap, IEEE80211_STA_QUICKKICKOUT);
        break;
#endif
    case IEEE80211_PARAM_CHSCANINIT:
        *value = wlan_get_param(vap, IEEE80211_CHSCANINIT);
        break;

    case IEEE80211_PARAM_COEXT_DISABLE:
        *value = ((ic->ic_flags & IEEE80211_F_COEXT_DISABLE) != 0);
        break;
#if ATH_SUPPORT_NR_SYNC
    case IEEE80211_PARAM_NR_SHARE_RADIO_FLAG:
        *value = ic->ic_nr_share_radio_flag;
        break;
#endif
    case IEEE80211_PARAM_AUTHMODE:
        //fixme how it used to be done: *value = osifp->authmode;
        {
            ieee80211_auth_mode modes[IEEE80211_AUTH_MAX];
            retv = wlan_get_auth_modes(vap, modes, IEEE80211_AUTH_MAX);
            if (retv > 0)
            {
                *value = modes[0];
                if((retv > 1) && (modes[0] == IEEE80211_AUTH_OPEN) && (modes[1] == IEEE80211_AUTH_SHARED))
                    *value =  IEEE80211_AUTH_AUTO;
                retv = 0;
            }
        }
        break;
     case IEEE80211_PARAM_BANDWIDTH:
         {
           *value=ieee80211_ucfg_get_bandwidth(vap);
           break;
         }
     case IEEE80211_PARAM_FREQ_BAND:
         {
           *value=ieee80211_ucfg_get_band(vap);
           break;
         }
     case IEEE80211_PARAM_EXTCHAN:
        {
           *value=ieee80211_ucfg_get_extchan(vap);
           break;
        }
     case IEEE80211_PARAM_SECOND_CENTER_FREQ:
        {
            if(vap->iv_des_mode == IEEE80211_MODE_11AC_VHT80_80) {

                *value= ieee80211_ieee2mhz(ic,vap->iv_bsschan->ic_vhtop_ch_freq_seg2,IEEE80211_CHAN_5GHZ);
            }
            else {
                *value = 0;
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " center freq not present \n");
            }
        }
        break;

     case IEEE80211_PARAM_ATH_SUPPORT_VLAN:
        {
            *value = vap->vlan_set_flags;   /* dev->flags to control VLAN tagged packets sent by NW stack */
            break;
        }

     case IEEE80211_DISABLE_BCN_BW_NSS_MAP:
        {
            *value = ic->ic_disable_bcn_bwnss_map;
            break;
        }
     case IEEE80211_DISABLE_STA_BWNSS_ADV:
        {
            *value = ic->ic_disable_bwnss_adv;
            break;
        }
     case IEEE80211_PARAM_MCS:
        {
            *value=-1;  /* auto rate */
            break;
        }
    case IEEE80211_PARAM_MCASTCIPHER:
        {
            ieee80211_cipher_type mciphers[1];
            int count;
            count = wlan_get_mcast_ciphers(vap,mciphers,1);
            if (count == 1)
                *value = mciphers[0];
        }
        break;
    case IEEE80211_PARAM_MCASTKEYLEN:
        *value = wlan_get_rsn_cipher_param(vap, IEEE80211_MCAST_CIPHER_LEN);
        break;
    case IEEE80211_PARAM_UCASTCIPHERS:
        do {
            ieee80211_cipher_type uciphers[IEEE80211_CIPHER_MAX];
            int i, count;
            count = wlan_get_ucast_ciphers(vap, uciphers, IEEE80211_CIPHER_MAX);
            *value = 0;
            for (i = 0; i < count; i++) {
                *value |= 1<<uciphers[i];
            }
    } while (0);
        break;
    case IEEE80211_PARAM_UCASTCIPHER:
        do {
            ieee80211_cipher_type uciphers[1];
            int count = 0;
            count = wlan_get_ucast_ciphers(vap, uciphers, 1);
            *value = 0;
            if (count == 1)
                *value |= 1<<uciphers[0];
        } while (0);
        break;
    case IEEE80211_PARAM_UCASTKEYLEN:
        *value = wlan_get_rsn_cipher_param(vap, IEEE80211_UCAST_CIPHER_LEN);
        break;
    case IEEE80211_PARAM_PRIVACY:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_PRIVACY);
        break;
    case IEEE80211_PARAM_COUNTERMEASURES:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_COUNTER_MEASURES);
        break;
    case IEEE80211_PARAM_HIDESSID:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_HIDE_SSID);
        break;
    case IEEE80211_PARAM_APBRIDGE:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_APBRIDGE);
        break;
    case IEEE80211_PARAM_KEYMGTALGS:
        *value = wlan_get_rsn_cipher_param(vap, IEEE80211_KEYMGT_ALGS);
        break;
    case IEEE80211_PARAM_RSNCAPS:
        *value = wlan_get_rsn_cipher_param(vap, IEEE80211_RSN_CAPS);
        break;
    case IEEE80211_PARAM_WPA:
        {
            ieee80211_auth_mode modes[IEEE80211_AUTH_MAX];
            int count, i;
            *value = 0;
            count = wlan_get_auth_modes(vap,modes,IEEE80211_AUTH_MAX);
            for (i = 0; i < count; i++) {
                if (modes[i] == IEEE80211_AUTH_WPA)
                    *value |= 0x1;
                if (modes[i] == IEEE80211_AUTH_RSNA)
                    *value |= 0x2;
            }
        }
        break;
#if DBG_LVL_MAC_FILTERING
    case IEEE80211_PARAM_DBG_LVL_MAC:
        *value = vap->iv_print.dbgLVLmac_on;
        break;
#endif
    case IEEE80211_PARAM_DBG_LVL:
        {
            char c[128];
            *value = (u_int32_t)wlan_get_debug_flags(vap);
            snprintf(c, sizeof(c), "0x%x", *value);
            strlcpy(extra, c, sizeof(c));
        }
        break;
    case IEEE80211_PARAM_DBG_LVL_HIGH:
        /* no need to show IEEE80211_MSG_ANY to user */
        *value = (u_int32_t)((wlan_get_debug_flags(vap) & 0x7fffffff00000000ULL) >> 32);
        break;
    case IEEE80211_PARAM_MIXED_MODE:
        *value = vap->mixed_encryption_mode;
        break;
#if UMAC_SUPPORT_IBSS
    case IEEE80211_PARAM_IBSS_CREATE_DISABLE:
        *value = osifp->disable_ibss_create;
        break;
#endif
	case IEEE80211_PARAM_WEATHER_RADAR_CHANNEL:
        *value = wlan_get_param(vap, IEEE80211_WEATHER_RADAR);
        break;
    case IEEE80211_PARAM_SEND_DEAUTH:
        *value = wlan_get_param(vap, IEEE80211_SEND_DEAUTH);
        break;
    case IEEE80211_PARAM_WEP_KEYCACHE:
        *value = wlan_get_param(vap, IEEE80211_WEP_KEYCACHE);
	break;
	case IEEE80211_PARAM_GET_ACS:
        *value = wlan_get_param(vap,IEEE80211_GET_ACS_STATE);
    break;
	case IEEE80211_PARAM_GET_CAC:
        *value = wlan_get_param(vap,IEEE80211_GET_CAC_STATE);
	break;
    case IEEE80211_PARAM_SIFS_TRIGGER:
        if (!ic->ic_is_mode_offload(ic))
            return -EPERM;
        *value = vap->iv_sifs_trigger_time;
        break;
    case IEEE80211_PARAM_BEACON_INTERVAL:
        *value = wlan_get_param(vap, IEEE80211_BEACON_INTVAL);
        break;
#if ATH_SUPPORT_AP_WDS_COMBO
    case IEEE80211_PARAM_NO_BEACON:
        *value = wlan_get_param(vap, IEEE80211_NO_BEACON);
        break;
#endif
    case IEEE80211_PARAM_PUREG:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_PUREG);
        break;
    case IEEE80211_PARAM_PUREN:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_PURE11N);
        break;
    case IEEE80211_PARAM_PURE11AC:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_PURE11AC);
        break;
    case IEEE80211_PARAM_STRICT_BW:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_STRICT_BW);
        break;
    case IEEE80211_PARAM_WDS:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_WDS);
        break;
#if WDS_VENDOR_EXTENSION
    case IEEE80211_PARAM_WDS_RX_POLICY:
        *value = wlan_get_param(vap, IEEE80211_WDS_RX_POLICY);
        break;
#endif
    case IEEE80211_IOCTL_GREEN_AP_PS_ENABLE:
        *value = (wlan_get_device_param(ic, IEEE80211_DEVICE_GREEN_AP_PS_ENABLE) ? 1:0);
        break;
    case IEEE80211_IOCTL_GREEN_AP_PS_TIMEOUT:
        *value = wlan_get_device_param(ic, IEEE80211_DEVICE_GREEN_AP_PS_TIMEOUT);
        break;
    case IEEE80211_IOCTL_GREEN_AP_PS_ON_TIME:
        *value = wlan_get_device_param(ic, IEEE80211_DEVICE_GREEN_AP_PS_ON_TIME);
        break;
    case IEEE80211_IOCTL_GREEN_AP_ENABLE_PRINT:
        *value = wlan_get_device_param(ic, IEEE80211_DEVICE_GREEN_AP_ENABLE_PRINT);
        break;

#ifdef ATH_WPS_IE
    case IEEE80211_PARAM_WPS:
        *value = wlan_get_param(vap, IEEE80211_WPS_MODE);
        break;
#endif
#ifdef ATH_EXT_AP
    case IEEE80211_PARAM_EXTAP:
        *value = (IEEE80211_VAP_IS_EXT_AP_ENABLED(vap) == IEEE80211_FEXT_AP);
        break;
#endif


    case IEEE80211_PARAM_STA_FORWARD:
    *value  = wlan_get_param(vap, IEEE80211_FEATURE_STAFWD);
    break;

    case IEEE80211_PARAM_DYN_BW_RTS:
        *value = wlan_get_param(vap, IEEE80211_DYN_BW_RTS);
        break;

    case IEEE80211_PARAM_CWM_EXTPROTMODE:
        *value = wlan_get_device_param(ic, IEEE80211_DEVICE_CWM_EXTPROTMODE);
        break;
    case IEEE80211_PARAM_CWM_EXTPROTSPACING:
        *value = wlan_get_device_param(ic, IEEE80211_DEVICE_CWM_EXTPROTSPACING);
        break;
    case IEEE80211_PARAM_CWM_ENABLE:
        *value = wlan_get_device_param(ic, IEEE80211_DEVICE_CWM_ENABLE);
        break;
    case IEEE80211_PARAM_CWM_EXTBUSYTHRESHOLD:
        *value = wlan_get_device_param(ic, IEEE80211_DEVICE_CWM_EXTBUSYTHRESHOLD);
        break;
    case IEEE80211_PARAM_DOTH:
        *value = wlan_get_device_param(ic, IEEE80211_DEVICE_DOTH);
        break;
    case IEEE80211_PARAM_WMM:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_WMM);
        break;
    case IEEE80211_PARAM_PROTMODE:
        *value = wlan_get_device_param(ic, IEEE80211_DEVICE_PROTECTION_MODE);
        break;
    case IEEE80211_PARAM_DRIVER_CAPS:
        *value = wlan_get_param(vap, IEEE80211_DRIVER_CAPS);
        break;
    case IEEE80211_PARAM_MACCMD:
        *value = wlan_get_acl_policy(vap, IEEE80211_ACL_FLAG_ACL_LIST_1);
        break;
    case IEEE80211_PARAM_DROPUNENCRYPTED:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_DROP_UNENC);
    break;
    case IEEE80211_PARAM_DTIM_PERIOD:
        *value = wlan_get_param(vap, IEEE80211_DTIM_INTVAL);
        break;
    case IEEE80211_PARAM_SHORT_GI:
        *value = wlan_get_param(vap, IEEE80211_SHORT_GI);
        break;
   case IEEE80211_PARAM_SHORTPREAMBLE:
        *value = wlan_get_param(vap, IEEE80211_SHORT_PREAMBLE);
        break;
   case IEEE80211_PARAM_CHAN_NOISE:
        *value = vap->iv_ic->ic_get_cur_chan_nf(vap->iv_ic);
        break;


    /*
    * Support to Mcast Enhancement
    */
#if ATH_SUPPORT_IQUE
    case IEEE80211_PARAM_ME:
        *value = wlan_get_param(vap, IEEE80211_ME);
        break;
    case IEEE80211_PARAM_MEDUMP:
        *value = wlan_get_param(vap, IEEE80211_MEDUMP);
        break;
    case IEEE80211_PARAM_MEDEBUG:
        *value = wlan_get_param(vap, IEEE80211_MEDEBUG);
        break;
    case IEEE80211_PARAM_ME_SNOOPLENGTH:
        *value = wlan_get_param(vap, IEEE80211_ME_SNOOPLENGTH);
        break;
    case IEEE80211_PARAM_ME_TIMER:
        *value = wlan_get_param(vap, IEEE80211_ME_TIMER);
        break;
    case IEEE80211_PARAM_ME_TIMEOUT:
        *value = wlan_get_param(vap, IEEE80211_ME_TIMEOUT);
        break;
    case IEEE80211_PARAM_HBR_TIMER:
        *value = wlan_get_param(vap, IEEE80211_HBR_TIMER);
        break;
    case IEEE80211_PARAM_HBR_STATE:
        wlan_get_hbrstate(vap);
        *value = 0;
        break;
    case IEEE80211_PARAM_ME_DROPMCAST:
        *value = wlan_get_param(vap, IEEE80211_ME_DROPMCAST);
        break;
    case IEEE80211_PARAM_ME_SHOWDENY:
        *value = wlan_get_param(vap, IEEE80211_ME_SHOWDENY);
        break;
    case IEEE80211_PARAM_GETIQUECONFIG:
        *value = wlan_get_param(vap, IEEE80211_IQUE_CONFIG);
        break;
#endif /*ATH_SUPPORT_IQUE*/

    case IEEE80211_PARAM_SCANVALID:
        *value = 0;
        if (osifp->os_opmode == IEEE80211_M_STA ||
                osifp->os_opmode == IEEE80211_M_P2P_CLIENT) {
            *value = wlan_connection_sm_get_param(osifp->sm_handle,
                                                    WLAN_CONNECTION_PARAM_SCAN_CACHE_VALID_TIME);
        }
        break;
    case IEEE80211_PARAM_COUNTRYCODE:
        *value = wlan_get_device_param(ic, IEEE80211_DEVICE_COUNTRYCODE);
        break;
    case IEEE80211_PARAM_11N_RATE:
        *value = wlan_get_param(vap, IEEE80211_FIXED_RATE);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Getting Rate Series: %x\n",*value);
        break;
    case IEEE80211_PARAM_VHT_MCS:
        *value = wlan_get_param(vap, IEEE80211_FIXED_VHT_MCS);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Getting VHT Rate set: %x\n",*value);
        break;
    case IEEE80211_PARAM_NSS:
        if(!ic->ic_is_mode_offload(ic))
            return -EPERM;
        *value = wlan_get_param(vap, IEEE80211_FIXED_NSS);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Getting Nss: %x\n",*value);
        break;
    case IEEE80211_PARAM_STA_COUNT:
        {
            int sta_count =0;
            if(osifp->os_opmode == IEEE80211_M_STA)
                return -EINVAL;

            sta_count = wlan_iterate_station_list(vap, NULL,NULL);
            *value = sta_count;
            break;
        }
    case IEEE80211_PARAM_NO_VAP_RESET:
        *value = vap->iv_novap_reset;
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Getting VAP reset: %x\n",*value);
        break;

    case IEEE80211_PARAM_VHT_SGIMASK:
        *value = wlan_get_param(vap, IEEE80211_VHT_SGIMASK);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Getting VHT SGI MASK: %x\n",*value);
        break;

    case IEEE80211_PARAM_VHT80_RATEMASK:
        *value = wlan_get_param(vap, IEEE80211_VHT80_RATEMASK);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Getting VHT80 RATE MASK: %x\n",*value);
        break;

    case IEEE80211_PARAM_OPMODE_NOTIFY:
        *value = wlan_get_param(vap, IEEE80211_OPMODE_NOTIFY_ENABLE);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Getting Notify element status: %x\n",*value);
        break;

    case IEEE80211_PARAM_LDPC:
        *value = wlan_get_param(vap, IEEE80211_SUPPORT_LDPC);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Getting LDPC: %x\n",*value);
        break;
    case IEEE80211_PARAM_TX_STBC:
        *value = wlan_get_param(vap, IEEE80211_SUPPORT_TX_STBC);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Getting TX STBC: %x\n",*value);
        break;
    case IEEE80211_PARAM_RX_STBC:
        *value = wlan_get_param(vap, IEEE80211_SUPPORT_RX_STBC);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Getting RX STBC: %x\n",*value);
        break;
    case IEEE80211_PARAM_VHT_TX_MCSMAP:
        *value = wlan_get_param(vap, IEEE80211_VHT_TX_MCSMAP);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Getting VHT TX MCS MAP set: %x\n",*value);
        break;
    case IEEE80211_PARAM_VHT_RX_MCSMAP:
        *value = wlan_get_param(vap, IEEE80211_VHT_RX_MCSMAP);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Getting VHT RX MCS MAP set: %x\n",*value);
        break;
    case IEEE80211_PARAM_11N_RETRIES:
        *value = wlan_get_param(vap, IEEE80211_FIXED_RETRIES);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Getting Retry Series: %x\n",*value);
        break;
    case IEEE80211_PARAM_MCAST_RATE:
        *value = wlan_get_param(vap, IEEE80211_MCAST_RATE);
        break;
    case IEEE80211_PARAM_BCAST_RATE:
        *value = wlan_get_param(vap, IEEE80211_BCAST_RATE);
        break;
    case IEEE80211_PARAM_CCMPSW_ENCDEC:
        *value = vap->iv_ccmpsw_seldec;
        break;
    case IEEE80211_PARAM_UAPSDINFO:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_UAPSD);
        break;
    case IEEE80211_PARAM_STA_PWR_SET_PSPOLL:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_PSPOLL);
        break;
    case IEEE80211_PARAM_NETWORK_SLEEP:
        *value= (u_int32_t)wlan_get_powersave(vap);
        break;
#if UMAC_SUPPORT_WNM
    case IEEE80211_PARAM_WNM_SLEEP:
        *value= (u_int32_t)wlan_get_powersave(vap);
        break;
#endif
#if UMAC_SUPPORT_BSSLOAD
    case IEEE80211_PARAM_QBSS_LOAD:
        *value = wlan_get_param(vap, IEEE80211_QBSS_LOAD);
	break;
#if ATH_SUPPORT_HS20
    case IEEE80211_PARAM_HC_BSSLOAD:
        *value = vap->iv_hc_bssload;
        break;
#endif /* ATH_SUPPORT_HS20 */
#endif /* UMAC_SUPPORT_BSSLOAD */
#if UMAC_SUPPORT_CHANUTIL_MEASUREMENT
    case IEEE80211_PARAM_CHAN_UTIL_ENAB:
        *value = wlan_get_param(vap, IEEE80211_CHAN_UTIL_ENAB);
        break;
    case IEEE80211_PARAM_CHAN_UTIL:
        *value = wlan_get_param(vap, IEEE80211_CHAN_UTIL);
        break;
#endif /* UMAC_SUPPORT_CHANUTIL_MEASUREMENT */
#if UMAC_SUPPORT_QUIET
    case IEEE80211_PARAM_QUIET_PERIOD:
        *value = wlan_quiet_get_param(vap);
        break;
#endif /* UMAC_SUPPORT_QUIET */
    case IEEE80211_PARAM_MBO:
        *value = wlan_get_param(vap, IEEE80211_MBO);
        break;
    case IEEE80211_PARAM_MBO_CAP:
        *value = wlan_get_param(vap, IEEE80211_MBOCAP);
        break;
    case IEEE80211_PARAM_MBO_ASSOC_DISALLOW:
        *value = wlan_get_param(vap,IEEE80211_MBO_ASSOC_DISALLOW);
        break;
    case IEEE80211_PARAM_MBO_CELLULAR_PREFERENCE:
        *value = wlan_get_param(vap,IEEE80211_MBO_CELLULAR_PREFERENCE);
        break;
    case IEEE80211_PARAM_MBO_TRANSITION_REASON:
        *value = wlan_get_param(vap,IEEE80211_MBO_TRANSITION_REASON);
        break;
    case IEEE80211_PARAM_MBO_ASSOC_RETRY_DELAY:
        *value = wlan_get_param(vap,IEEE80211_MBO_ASSOC_RETRY_DELAY);
        break;
    case IEEE80211_PARAM_OCE:
        *value = wlan_get_param(vap, IEEE80211_OCE);
        break;
    case IEEE80211_PARAM_OCE_ASSOC_REJECT:
        *value = wlan_get_param(vap, IEEE80211_OCE_ASSOC_REJECT);
        break;
    case IEEE80211_PARAM_OCE_ASSOC_MIN_RSSI:
        *value = wlan_get_param(vap, IEEE80211_OCE_ASSOC_MIN_RSSI);
        break;
    case IEEE80211_PARAM_OCE_ASSOC_RETRY_DELAY:
        *value = wlan_get_param(vap, IEEE80211_OCE_ASSOC_RETRY_DELAY);
        break;
    case IEEE80211_PARAM_OCE_WAN_METRICS:
        *value = wlan_get_param(vap, IEEE80211_OCE_WAN_METRICS);
        break;
    case IEEE80211_PARAM_MGMT_RATE:
        *value = wlan_get_param(vap, IEEE80211_MGMT_RATE);
        break;
    case IEEE80211_PARAM_RRM_CAP:
        *value = wlan_get_param(vap, IEEE80211_RRM_CAP);
        break;
    case IEEE80211_PARAM_START_ACS_REPORT:
        *value = wlan_get_param(vap, IEEE80211_START_ACS_REPORT);
        break;
    case IEEE80211_PARAM_MIN_DWELL_ACS_REPORT:
        *value = wlan_get_param(vap, IEEE80211_MIN_DWELL_ACS_REPORT);
        break;
    case IEEE80211_PARAM_ACS_CH_HOP_LONG_DUR:
        *value = wlan_get_param(vap,IEEE80211_ACS_CH_HOP_LONG_DUR);
        break;
    case IEEE80211_PARAM_SCAN_MIN_DWELL:
        *value = wlan_get_param(vap, IEEE80211_SCAN_MIN_DWELL);
        break;
    case IEEE80211_PARAM_SCAN_MAX_DWELL:
        *value = wlan_get_param(vap, IEEE80211_SCAN_MAX_DWELL);
        break;
    case IEEE80211_PARAM_ACS_CH_HOP_NO_HOP_DUR:
        *value = wlan_get_param(vap, IEEE80211_ACS_CH_HOP_NO_HOP_DUR);
        break;
    case IEEE80211_PARAM_ACS_CH_HOP_CNT_WIN_DUR:
        *value = wlan_get_param(vap,IEEE80211_ACS_CH_HOP_CNT_WIN_DUR);
        break;
    case IEEE80211_PARAM_ACS_CH_HOP_NOISE_TH:
        *value = wlan_get_param(vap,IEEE80211_ACS_CH_HOP_NOISE_TH);
        break;
    case IEEE80211_PARAM_ACS_CH_HOP_CNT_TH:
        *value = wlan_get_param(vap,IEEE80211_ACS_CH_HOP_CNT_TH);
        break;
    case IEEE80211_PARAM_ACS_ENABLE_CH_HOP:
        *value = wlan_get_param(vap,IEEE80211_ACS_ENABLE_CH_HOP);
        break;
    case IEEE80211_PARAM_MAX_DWELL_ACS_REPORT:
        *value = wlan_get_param(vap, IEEE80211_MAX_DWELL_ACS_REPORT);
        break;
    case IEEE80211_PARAM_RRM_DEBUG:
        *value = wlan_get_param(vap, IEEE80211_RRM_DEBUG);
	break;
    case IEEE80211_PARAM_RRM_SLWINDOW:
        *value = wlan_get_param(vap, IEEE80211_RRM_SLWINDOW);
	break;
    case IEEE80211_PARAM_RRM_STATS:
        *value = wlan_get_param(vap, IEEE80211_RRM_STATS);
	break;
#if UMAC_SUPPORT_WNM
    case IEEE80211_PARAM_WNM_CAP:
        *value = wlan_get_param(vap, IEEE80211_WNM_CAP);
	break;
    case IEEE80211_PARAM_WNM_BSS_CAP:
        *value = wlan_get_param(vap, IEEE80211_WNM_BSS_CAP);
        break;
    case IEEE80211_PARAM_WNM_TFS_CAP:
        *value = wlan_get_param(vap, IEEE80211_WNM_TFS_CAP);
        break;
    case IEEE80211_PARAM_WNM_TIM_CAP:
        *value = wlan_get_param(vap, IEEE80211_WNM_TIM_CAP);
        break;
    case IEEE80211_PARAM_WNM_SLEEP_CAP:
        *value = wlan_get_param(vap, IEEE80211_WNM_SLEEP_CAP);
        break;
    case IEEE80211_PARAM_WNM_FMS_CAP:
        *value = wlan_get_param(vap, IEEE80211_WNM_FMS_CAP);
	break;
#endif
#ifdef ATHEROS_LINUX_PERIODIC_SCAN
    case IEEE80211_PARAM_PERIODIC_SCAN:
        *value = osifp->os_periodic_scan_period;
        break;
#endif
#if ATH_SW_WOW
    case IEEE80211_PARAM_SW_WOW:
        *value = wlan_get_wow(vap);
        break;
#endif
    case IEEE80211_PARAM_AMPDU:
        *value = vap->iv_ampdu;
        break;
    case IEEE80211_PARAM_AMSDU:
#ifdef TEMP_AGGR_CFG
        if (osifp->osif_is_mode_offload) {
            *value = vap->iv_vht_amsdu;
            break;
        }
#endif
        *value = !!vap->iv_amsdu;
        break;
    case IEEE80211_PARAM_11N_TX_AMSDU:
        *value = vap->iv_disable_ht_tx_amsdu;
        break;
    case IEEE80211_PARAM_CTSPROT_DTIM_BCN:
        *value = vap->iv_cts2self_prot_dtim_bcn;
        break;
    case IEEE80211_PARAM_VSP_ENABLE:
        *value = vap->iv_enable_vsp;
        break;
    case IEEE80211_PARAM_MAX_AMPDU:
        *value = wlan_get_param(vap, IEEE80211_MAX_AMPDU);
        break;
    case IEEE80211_PARAM_VHT_MAX_AMPDU:
        *value = wlan_get_param(vap, IEEE80211_VHT_MAX_AMPDU);
        break;
#if ATH_SUPPORT_WPA_SUPPLICANT_CHECK_TIME
    case IEEE80211_PARAM_REJOINT_ATTEMP_TIME:
        *value = wlan_get_param(vap,IEEE80211_REJOINT_ATTEMP_TIME);
        break;
#endif
    case IEEE80211_PARAM_PWRTARGET:
        *value = wlan_get_device_param(ic, IEEE80211_DEVICE_PWRTARGET);
        break;
    case IEEE80211_PARAM_COUNTRY_IE:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_IC_COUNTRY_IE);
        break;

    case IEEE80211_PARAM_2G_CSA:
        *value = wlan_get_device_param(ic, IEEE80211_DEVICE_2G_CSA);
        break;

    case IEEE80211_PARAM_CHANBW:
        switch(ic->ic_chanbwflag)
        {
        case IEEE80211_CHAN_HALF:
            *value = 1;
            break;
        case IEEE80211_CHAN_QUARTER:
            *value = 2;
            break;
        default:
            *value = 0;
            break;
        }
        break;
    case IEEE80211_PARAM_MFP_TEST:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_MFP_TEST);
        break;

    case IEEE80211_PARAM_INACT:
        *value = wlan_get_param(vap,IEEE80211_RUN_INACT_TIMEOUT );
        break;
    case IEEE80211_PARAM_INACT_AUTH:
        *value = wlan_get_param(vap,IEEE80211_AUTH_INACT_TIMEOUT );
        break;
    case IEEE80211_PARAM_INACT_INIT:
        *value = wlan_get_param(vap,IEEE80211_INIT_INACT_TIMEOUT );
        break;
    case IEEE80211_PARAM_SESSION_TIMEOUT:
        *value = wlan_get_param(vap,IEEE80211_SESSION_TIMEOUT );
        break;
    case IEEE80211_PARAM_COMPRESSION:
        *value = wlan_get_param(vap, IEEE80211_COMP);
        break;
    case IEEE80211_PARAM_FF:
        *value = wlan_get_param(vap, IEEE80211_FF);
        break;
    case IEEE80211_PARAM_TURBO:
        *value = wlan_get_param(vap, IEEE80211_TURBO);
        break;
    case IEEE80211_PARAM_BURST:
        *value = wlan_get_param(vap, IEEE80211_BURST);
        break;
    case IEEE80211_PARAM_AR:
        *value = wlan_get_param(vap, IEEE80211_AR);
        break;
#if UMAC_SUPPORT_STA_POWERSAVE
    case IEEE80211_PARAM_SLEEP:
        *value = wlan_get_param(vap, IEEE80211_SLEEP);
        break;
#endif
    case IEEE80211_PARAM_EOSPDROP:
        *value = wlan_get_param(vap, IEEE80211_EOSPDROP);
        break;
    case IEEE80211_PARAM_MARKDFS:
		*value = wlan_get_param(vap, IEEE80211_MARKDFS);
        break;
    case IEEE80211_PARAM_DFSDOMAIN:
        *value = wlan_get_param(vap, IEEE80211_DFSDOMAIN);
        break;
    case IEEE80211_PARAM_WDS_AUTODETECT:
        *value = wlan_get_param(vap, IEEE80211_WDS_AUTODETECT);
        break;
    case IEEE80211_PARAM_WEP_TKIP_HT:
        *value = wlan_get_param(vap, IEEE80211_WEP_TKIP_HT);
        break;
    /*
    ** Support for returning the radio number
    */
    case IEEE80211_PARAM_ATH_RADIO:
		*value = wlan_get_param(vap, IEEE80211_ATH_RADIO);
        break;
    case IEEE80211_PARAM_IGNORE_11DBEACON:
        *value = wlan_get_param(vap, IEEE80211_IGNORE_11DBEACON);
        break;
#if ATH_SUPPORT_WAPI
    case IEEE80211_PARAM_WAPIREKEY_USK:
        *value = wlan_get_wapirekey_unicast(vap);
        break;
    case IEEE80211_PARAM_WAPIREKEY_MSK:
        *value = wlan_get_wapirekey_multicast(vap);
        break;
#endif

#ifdef QCA_PARTNER_PLATFORM
    case IEEE80211_PARAM_PLTFRM_PRIVATE:
        *value = wlan_pltfrm_get_param(vap);
        break;
#endif
    case IEEE80211_PARAM_NO_STOP_DISASSOC:
        *value = osifp->no_stop_disassoc;
        break;
#if UMAC_SUPPORT_VI_DBG

    case IEEE80211_PARAM_DBG_CFG:
        *value = ieee80211_vi_dbg_get_param(vap, IEEE80211_VI_DBG_CFG);
        break;

    case IEEE80211_PARAM_RESTART:
        *value = ieee80211_vi_dbg_get_param(vap, IEEE80211_VI_RESTART);
        break;
    case IEEE80211_PARAM_RXDROP_STATUS:
        *value = ieee80211_vi_dbg_get_param(vap, IEEE80211_VI_RXDROP_STATUS);
        break;
#endif

#if ATH_SUPPORT_IBSS_DFS
    case IEEE80211_PARAM_IBSS_DFS_PARAM:
        *value = vap->iv_ibss_dfs_csa_threshold << 16 |
                   vap->iv_ibss_dfs_csa_measrep_limit << 8 |
                   vap->iv_ibss_dfs_enter_recovery_threshold_in_tbtt;
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "channel swith time %d measurement report %d recover time %d \n",
                 vap->iv_ibss_dfs_csa_threshold,
                 vap->iv_ibss_dfs_csa_measrep_limit ,
                 vap->iv_ibss_dfs_enter_recovery_threshold_in_tbtt);
        break;
#endif

#ifdef ATH_SUPPORT_TxBF
    case IEEE80211_PARAM_TXBF_AUTO_CVUPDATE:
        *value = wlan_get_param(vap, IEEE80211_TXBF_AUTO_CVUPDATE);
        break;
    case IEEE80211_PARAM_TXBF_CVUPDATE_PER:
        *value = wlan_get_param(vap, IEEE80211_TXBF_CVUPDATE_PER);
        break;
#endif
    case IEEE80211_PARAM_SCAN_BAND:
        *value = osifp->os_scan_band;
        break;

    case IEEE80211_PARAM_SCAN_CHAN_EVENT:
        if (osifp->osif_is_mode_offload &&
            wlan_vap_get_opmode(vap) == IEEE80211_M_HOSTAP) {
            *value = osifp->is_scan_chevent;
        } else {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "IEEE80211_PARAM_SCAN_CHAN_EVENT is valid only for 11ac "
                   "offload, and in IEEE80211_M_HOSTAP(Access Point) mode\n");
            retv = EOPNOTSUPP;
            *value = 0;
        }
        break;
    case IEEE80211_PARAM_CONNECTION_SM_STATE:
        *value = 0;
        if (osifp->os_opmode == IEEE80211_M_STA) {
            *value = wlan_connection_sm_get_param(osifp->sm_handle,
                                                    WLAN_CONNECTION_PARAM_CURRENT_STATE);
        }
        break;

#if ATH_SUPPORT_WIFIPOS
    case IEEE80211_PARAM_WIFIPOS_TXCORRECTION:
	*value = ieee80211_wifipos_get_txcorrection(vap);
   	break;

    case IEEE80211_PARAM_WIFIPOS_RXCORRECTION:
	*value = ieee80211_wifipos_get_rxcorrection(vap);
   	break;
#endif

    case IEEE80211_PARAM_ROAMING:
        *value = ic->ic_roaming;
        break;
#if UMAC_SUPPORT_PROXY_ARP
    case IEEE80211_PARAM_PROXYARP_CAP:
        *value = wlan_get_param(vap, IEEE80211_PROXYARP_CAP);
	    break;
#if UMAC_SUPPORT_DGAF_DISABLE
    case IEEE80211_PARAM_DGAF_DISABLE:
        *value = wlan_get_param(vap, IEEE80211_DGAF_DISABLE);
	    break;
#endif
#endif
#if UMAC_SUPPORT_HS20_L2TIF
    case IEEE80211_PARAM_L2TIF_CAP:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_APBRIDGE) ? 0 : 1;
        break;
#endif
    case IEEE80211_PARAM_EXT_IFACEUP_ACS:
        *value = wlan_get_param(vap, IEEE80211_EXT_IFACEUP_ACS);
        break;

    case IEEE80211_PARAM_EXT_ACS_IN_PROGRESS:
        *value = wlan_get_param(vap, IEEE80211_EXT_ACS_IN_PROGRESS);
        break;

    case IEEE80211_PARAM_SEND_ADDITIONAL_IES:
        *value = wlan_get_param(vap, IEEE80211_SEND_ADDITIONAL_IES);
        break;

    case IEEE80211_PARAM_DESIRED_CHANNEL:
        *value = wlan_get_param(vap, IEEE80211_DESIRED_CHANNEL);
        break;

    case IEEE80211_PARAM_DESIRED_PHYMODE:
        *value = wlan_get_param(vap, IEEE80211_DESIRED_PHYMODE);
        break;

    case IEEE80211_PARAM_APONLY:
#if UMAC_SUPPORT_APONLY
        *value = vap->iv_aponly;
#else
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "APONLY not enabled\n");
#endif
        break;

#if ATH_SUPPORT_HYFI_ENHANCEMENTS
    case IEEE80211_PARAM_NOPBN:
        *value = wlan_get_param(vap, IEEE80211_NOPBN);
	break;
#endif
#if ATH_SUPPORT_DSCP_OVERRIDE
	case IEEE80211_PARAM_DSCP_OVERRIDE:
		*value = wlan_get_param(vap, IEEE80211_DSCP_OVERRIDE);
	break;
	case IEEE80211_PARAM_DSCP_TID_MAP:
		QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Get dscp_tid map\n");
		*value = ieee80211_ucfg_vap_get_dscp_tid_map(vap, value[1]);
	break;
        case IEEE80211_PARAM_VAP_DSCP_PRIORITY:
                *value = wlan_get_param(vap, IEEE80211_VAP_DSCP_PRIORITY);
        break;
#endif
#if ATH_SUPPORT_WRAP
    case IEEE80211_PARAM_PARENT_IFINDEX:
        *value = osifp->os_comdev->ifindex;
        break;

    case IEEE80211_PARAM_PROXY_STA:
        *value = vap->iv_psta;
        break;
#endif
#if RX_CHECKSUM_OFFLOAD
    case IEEE80211_PARAM_RX_CKSUM_ERR_STATS:
	{
	    if(osifp->osif_is_mode_offload) {
                ic->ic_vap_get_param(vap, IEEE80211_RX_CKSUM_ERR_STATS_GET);
	    } else
		QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "RX Checksum Offload Supported only for 11AC VAP \n");
	    break;
	}
    case IEEE80211_PARAM_RX_CKSUM_ERR_RESET:
	{
	    if(osifp->osif_is_mode_offload) {
                ic->ic_vap_get_param(vap, IEEE80211_RX_CKSUM_ERR_RESET_GET);
	    } else
		QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "RX Checksum Offload Supported only for 11AC VAP \n");
	    break;
	}

#endif /* RX_CHECKSM_OFFLOAD */

#if (HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE)
    case IEEE80211_PARAM_TSO_STATS:
	{
	    if(osifp->osif_is_mode_offload) {
		ic->ic_vap_get_param(vap, IEEE80211_TSO_STATS_GET);
	    } else
		QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "TSO Supported only for 11AC VAP \n");
	    break;
	}
    case IEEE80211_PARAM_TSO_STATS_RESET:
	{
	    if(osifp->osif_is_mode_offload) {
                ic->ic_vap_get_param(vap, IEEE80211_TSO_STATS_RESET_GET);
	    } else
		QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "TSO Supported only for 11AC VAP \n");
	    break;
	}
#endif /* HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE */

#if HOST_SW_SG_ENABLE
    case IEEE80211_PARAM_SG_STATS:
	{
	    if(osifp->osif_is_mode_offload) {
		ic->ic_vap_get_param(vap, IEEE80211_SG_STATS_GET);
	    } else
		QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "SG Supported only for 11AC VAP \n");
	    break;
	}
    case IEEE80211_PARAM_SG_STATS_RESET:
	{
	    if(osifp->osif_is_mode_offload) {
		ic->ic_vap_get_param(vap, IEEE80211_SG_STATS_RESET_GET);
	    } else {
		QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "SG Supported only for 11AC VAP \n");
            }
	    break;
	}
#endif /* HOST_SW_SG_ENABLE */

#if HOST_SW_LRO_ENABLE
    case IEEE80211_PARAM_LRO_STATS:
	{
	     if(osifp->osif_is_mode_offload) {
		QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Aggregated packets:  %d\n", vap->aggregated);
		QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Flushed packets:     %d\n", vap->flushed);
	     } else
		QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "LRO Supported only for 11AC VAP \n");
	     break;
	}
    case IEEE80211_PARAM_LRO_STATS_RESET:
	{
	     if(osifp->osif_is_mode_offload) {
		vap->aggregated = 0;
		vap->flushed = 0;
	     } else
		QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "LRO Supported only for 11AC VAP \n");
	     break;
	}
#endif /* HOST_SW_LRO_ENABLE */


    case IEEE80211_PARAM_MAX_SCANENTRY:
        *value = wlan_get_param(vap, IEEE80211_MAX_SCANENTRY);
        break;
    case IEEE80211_PARAM_SCANENTRY_TIMEOUT:
        *value = wlan_get_param(vap, IEEE80211_SCANENTRY_TIMEOUT);
        break;
#if ATH_PERF_PWR_OFFLOAD
    case IEEE80211_PARAM_VAP_TX_ENCAP_TYPE:
        *value = wlan_get_param(vap, IEEE80211_VAP_TX_ENCAP_TYPE);
        switch (*value)
        {
            case 0:
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Encap type: Raw\n");
                break;
            case 1:
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Encap type: Native Wi-Fi\n");
                break;
            case 2:
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Encap type: Ethernet\n");
                break;
            default:
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Encap type: Unknown\n");
                break;
        }
        break;
    case IEEE80211_PARAM_VAP_RX_DECAP_TYPE:
        *value = wlan_get_param(vap, IEEE80211_VAP_RX_DECAP_TYPE);
        switch (*value)
        {
            case 0:
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Decap type: Raw\n");
                break;
            case 1:
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Decap type: Native Wi-Fi\n");
                break;
            case 2:
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Decap type: Ethernet\n");
                break;
            default:
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Decap type: Unknown\n");
                break;
        }
        break;
#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
    case IEEE80211_PARAM_RAWMODE_SIM_TXAGGR:
        *value = wlan_get_param(vap, IEEE80211_RAWMODE_SIM_TXAGGR);
        break;
    case IEEE80211_PARAM_RAWMODE_PKT_SIM_STATS:
        *value = wlan_get_param(vap, IEEE80211_RAWMODE_PKT_SIM_STATS);
        break;
    case IEEE80211_PARAM_RAWMODE_SIM_DEBUG:
        *value = wlan_get_param(vap, IEEE80211_RAWMODE_SIM_DEBUG);
        break;
#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */
#endif /* ATH_PERF_PWR_OFFLOAD */
 case IEEE80211_PARAM_VAP_ENHIND:
        *value  = wlan_get_param(vap, IEEE80211_FEATURE_VAP_ENHIND);
        break;
    case IEEE80211_PARAM_VAP_PAUSE_SCAN:
        *value = vap->iv_pause_scan;
        break;
#if ATH_GEN_RANDOMNESS
    case IEEE80211_PARAM_RANDOMGEN_MODE:
        *value = ic->random_gen_mode;
        break;
#endif
    case IEEE80211_PARAM_WHC_APINFO_WDS:
        *value = ieee80211node_has_whc_apinfo_flag(
                vap->iv_bss, IEEE80211_NODE_WHC_APINFO_WDS);
        break;
    case IEEE80211_PARAM_WHC_APINFO_SON:
        *value = ieee80211node_has_whc_apinfo_flag(
                vap->iv_bss, IEEE80211_NODE_WHC_APINFO_SON);
        break;
    case IEEE80211_PARAM_WHC_APINFO_ROOT_DIST:
        *value = vap->iv_whc_root_ap_distance;
        break;
    case IEEE80211_PARAM_WHC_APINFO_SFACTOR:
        *value = vap->iv_whc_scaling_factor;
        break;
    case IEEE80211_PARAM_WHC_APINFO_BSSID:
        {
            char addr[IEEE80211_ADDR_LEN] = {0, 0, 0, 0, 0, 0};

            ieee80211_ucfg_find_best_uplink_bssid(vap, addr);
            macaddr_num_to_str(addr, extra);
        }
        break;
    case IEEE80211_PARAM_WHC_APINFO_RATE:
        *value = (int)ieee80211_rep_datarate_estimater(ic->ic_serving_ap_backhaul_rate,
                ic->ic_uplink_rate,
                (vap->iv_whc_root_ap_distance - 1),
                vap->iv_whc_scaling_factor);
        break;
    case IEEE80211_PARAM_WHC_APINFO_CAP_BSSID:
        {
            u_int8_t addr[IEEE80211_ADDR_LEN] = {0, 0, 0, 0, 0, 0};

            ieee80211_ucfg_find_cap_bssid(vap, addr);
            macaddr_num_to_str(addr, extra);
        }
        break;
    case IEEE80211_PARAM_WHC_APINFO_BEST_UPLINK_OTHERBAND_BSSID:
        {
            u_int8_t addr[IEEE80211_ADDR_LEN] = {0, 0, 0, 0, 0, 0};

            ieee80211_ucfg_get_best_otherband_uplink_bssid(vap, addr);
            macaddr_num_to_str(addr, extra);
        }
        break;
    case IEEE80211_PARAM_WHC_APINFO_OTHERBAND_UPLINK_BSSID:
        {
            u_int8_t addr[IEEE80211_ADDR_LEN] = {0, 0, 0, 0, 0, 0};

            ieee80211_ucfg_get_otherband_uplink_bssid(vap, addr);
            macaddr_num_to_str(addr, extra);
        }
        break;
    case IEEE80211_PARAM_WHC_APINFO_UPLINK_RATE:
        *value = ic->ic_uplink_rate;
        break;
    case IEEE80211_PARAM_SON:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_SON);
        break;
    case IEEE80211_PARAM_WHC_CAP_RSSI:
        *value = vap->iv_whc_son_cap_rssi;
      break;
    case IEEE80211_PARAM_WHC_CURRENT_CAP_RSSI:
      ieee80211_ucfg_get_cap_snr(vap, value);
      break;
    case IEEE80211_PARAM_REPT_MULTI_SPECIAL:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_REPT_MULTI_SPECIAL);
        break;
    case IEEE80211_PARAM_RX_SIGNAL_DBM:
        if (!osifp->osif_is_mode_offload){
            int8_t signal_dbm[6];

            *value = ic->ic_get_rx_signal_dbm(ic, signal_dbm);

            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Signal Strength in dBm [ctrl chain 0]: %d\n", signal_dbm[0]);
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Signal Strength in dBm [ctrl chain 1]: %d\n", signal_dbm[1]);
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Signal Strength in dBm [ctrl chain 2]: %d\n", signal_dbm[2]);
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Signal Strength in dBm [ext chain 0]: %d\n", signal_dbm[3]);
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Signal Strength in dBm [ext chain 1]: %d\n", signal_dbm[4]);
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Signal Strength in dBm [ext chain 2]: %d\n", signal_dbm[5]);
        } else {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"IEEE80211_PARAM_RX_SIGNAL_DBM is valid only for DA not supported for offload \n");
            retv = EOPNOTSUPP;
            *value = 0;
        }
	break;
    default:
        retv = EOPNOTSUPP;
        break;

   case IEEE80211_PARAM_DFS_CACTIMEOUT:
#if ATH_SUPPORT_DFS
        retv = ieee80211_dfs_get_override_cac_timeout(ic, &tmp);
        if (retv == 0)
            *value = tmp;
        else
            retv = EOPNOTSUPP;
        break;
#else
        retv = EOPNOTSUPP;
        break;
#endif /* ATH_SUPPORT_DFS */

   case IEEE80211_PARAM_ENABLE_RTSCTS:
       *value = wlan_get_param(vap, IEEE80211_ENABLE_RTSCTS);
       break;

   case IEEE80211_PARAM_RC_NUM_RETRIES:
       *value = wlan_get_param(vap, IEEE80211_RC_NUM_RETRIES);
       break;
   case IEEE80211_PARAM_256QAM_2G:
       *value = wlan_get_param(vap, IEEE80211_256QAM);
       break;
   case IEEE80211_PARAM_11NG_VHT_INTEROP:
       if (osifp->osif_is_mode_offload) {
            *value = wlan_get_param(vap, IEEE80211_11NG_VHT_INTEROP);
       } else {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Not supported in this Vap\n");
       }
       break;
#if UMAC_VOW_DEBUG
    case IEEE80211_PARAM_VOW_DBG_ENABLE:
        *value = (int)osifp->vow_dbg_en;
        break;
#endif
#if ATH_SUPPORT_SPLITMAC
    case IEEE80211_PARAM_SPLITMAC:
        *value = vap->iv_splitmac;
        break;
#endif
    case IEEE80211_PARAM_IMPLICITBF:
        *value = wlan_get_param(vap, IEEE80211_SUPPORT_IMPLICITBF);
        break;

    case IEEE80211_PARAM_VHT_SUBFEE:
        *value = wlan_get_param(vap, IEEE80211_VHT_SUBFEE);
        break;

    case IEEE80211_PARAM_VHT_MUBFEE:
        *value = wlan_get_param(vap, IEEE80211_VHT_MUBFEE);
        break;

    case IEEE80211_PARAM_VHT_SUBFER:
        *value = wlan_get_param(vap, IEEE80211_VHT_SUBFER);
        break;

    case IEEE80211_PARAM_VHT_MUBFER:
        *value = wlan_get_param(vap, IEEE80211_VHT_MUBFER);
        break;

    case IEEE80211_PARAM_VHT_STS_CAP:
        *value = wlan_get_param(vap, IEEE80211_VHT_BF_STS_CAP);
        break;

    case IEEE80211_PARAM_VHT_SOUNDING_DIM:
        *value = wlan_get_param(vap, IEEE80211_VHT_BF_SOUNDING_DIM);
        break;

#if QCA_AIRTIME_FAIRNESS
    case IEEE80211_PARAM_ATF_TXBUF_SHARE:
        *value = vap->iv_ic->atf_txbuf_share;
        break;
    case IEEE80211_PARAM_ATF_TXBUF_MAX:
        *value = vap->iv_ic->atf_txbuf_max;
        break;
    case IEEE80211_PARAM_ATF_TXBUF_MIN:
        *value = vap->iv_ic->atf_txbuf_min;
        break;
    case  IEEE80211_PARAM_ATF_OPT:
        *value = wlan_get_param(vap, IEEE80211_ATF_OPT);
        break;
    case IEEE80211_PARAM_ATF_OVERRIDE_AIRTIME_TPUT:
        *value = vap->iv_ic->ic_atf_airtime_override;
        break;
    case  IEEE80211_PARAM_ATF_PER_UNIT:
        *value = ic->atfcfg_set.percentage_unit;
        break;
    case  IEEE80211_PARAM_ATF_MAX_CLIENT:
        if(!osifp->osif_is_mode_offload) {
            *value = ic->ic_atf_maxclient;
        } else {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ATF_MAX_CLIENT not valid for this VAP \n");
            retv = EOPNOTSUPP;
        }
        break;
    case  IEEE80211_PARAM_ATF_SSID_GROUP:
        *value = ic->ic_atf_ssidgroup;
        break;
    case IEEE80211_PARAM_ATF_SSID_SCHED_POLICY:
            *value = wlan_get_param(vap, IEEE80211_ATF_SSID_SCHED_POLICY);
        break;
#endif
#if ATH_SSID_STEERING
    case IEEE80211_PARAM_VAP_SSID_CONFIG:
        *value = wlan_get_param(vap, IEEE80211_VAP_SSID_CONFIG);
        break;
#endif

    case IEEE80211_PARAM_TX_MIN_POWER:
        *value = ic->ic_curchan->ic_minpower;
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Get IEEE80211_PARAM_TX_MIN_POWER *value=%d\n",*value);
        break;
    case IEEE80211_PARAM_TX_MAX_POWER:
        *value = ic->ic_curchan->ic_maxpower;
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Get IEEE80211_PARAM_TX_MAX_POWER *value=%d\n",*value);
        break;
    case IEEE80211_PARAM_AMPDU_DENSITY_OVERRIDE:
        if(ic->ic_mpdudensityoverride & 0x1) {
            *value = ic->ic_mpdudensityoverride >> 1;
        } else {
            *value = -1;
        }
        break;

    case IEEE80211_PARAM_SMART_MESH_CONFIG:
        *value = wlan_get_param(vap, IEEE80211_SMART_MESH_CONFIG);
        break;

#if MESH_MODE_SUPPORT
    case IEEE80211_PARAM_MESH_CAPABILITIES:
        *value = wlan_get_param(vap, IEEE80211_MESH_CAPABILITIES);
        break;

    case IEEE80211_PARAM_CONFIG_MGMT_TX_FOR_MESH:
         *value = wlan_get_param(vap, IEEE80211_CONFIG_MGMT_TX_FOR_MESH);
         break;
#endif

    case IEEE80211_PARAM_RX_FILTER_MONITOR:
        if(IEEE80211_M_MONITOR != vap->iv_opmode && !vap->iv_smart_monitor_vap && !vap->iv_special_vap_mode) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"Not monitor VAP or Smart Monitor VAP!\n");
            return -EINVAL;
        }
#if ATH_PERF_PWR_OFFLOAD
        if(osifp->osif_is_mode_offload) {
           *value =  ic->mon_filter_osif_mac |
                       ic->ic_vap_get_param(vap, IEEE80211_RX_FILTER_MONITOR);
        }
        else {
           *value =  ic->mon_filter_osif_mac;
        }
#else
        *value =  ic->mon_filter_osif_mac;
#endif
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_IOCTL,
                  "osif MAC filter=%d\n", ic->mon_filter_osif_mac);
        break;

    case IEEE80211_PARAM_RX_FILTER_SMART_MONITOR:
        if(vap->iv_smart_monitor_vap) {
            *value = 1;
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"Smart Monitor VAP!\n");
        } else {
            *value = 0;
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"Not Smart Monitor VAP!\n");
        }
        break;

    case IEEE80211_PARAM_CONFIG_ASSOC_WAR_160W:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_ASSOC_WAR_160W);
        break;
     case IEEE80211_PARAM_CONFIG_MU_CAP_WAR:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_MU_CAP_WAR);
        break;
     case IEEE80211_PARAM_CONFIG_MU_CAP_TIMER:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_MU_CAP_TIMER);
        break;
    case IEEE80211_PARAM_RAWMODE_PKT_SIM:
        *value = wlan_get_param(vap, IEEE80211_RAWMODE_PKT_SIM);
        break;
    case IEEE80211_PARAM_CONFIG_RAW_DWEP_IND:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_RAW_DWEP_IND);
        break;
    case IEEE80211_PARAM_CUSTOM_CHAN_LIST:
        *value = wlan_get_param(vap,IEEE80211_CONFIG_PARAM_CUSTOM_CHAN_LIST);
        break;
#if UMAC_SUPPORT_ACFG
    case IEEE80211_PARAM_DIAG_WARN_THRESHOLD:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_DIAG_WARN_THRESHOLD);
        break;
    case IEEE80211_PARAM_DIAG_ERR_THRESHOLD:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_DIAG_ERR_THRESHOLD);
        break;
#endif
    case IEEE80211_PARAM_CONFIG_REV_SIG_160W:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_REV_SIG_160W);
        break;
    case IEEE80211_PARAM_DISABLE_SELECTIVE_HTMCS_FOR_VAP:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_DISABLE_SELECTIVE_HTMCS);
        break;
    case IEEE80211_PARAM_CONFIGURE_SELECTIVE_VHTMCS_FOR_VAP:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_CONFIGURE_SELECTIVE_VHTMCS);
        break;
    case IEEE80211_PARAM_RDG_ENABLE:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_RDG_ENABLE);
        break;
    case IEEE80211_PARAM_DFS_SUPPORT:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_DFS_SUPPORT);
        break;
    case IEEE80211_PARAM_DFS_ENABLE:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_DFS_ENABLE);
        break;
    case IEEE80211_PARAM_ACS_SUPPORT:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_ACS_SUPPORT);
        break;
    case IEEE80211_PARAM_SSID_STATUS:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_SSID_STATUS);
        break;
    case IEEE80211_PARAM_DL_QUEUE_PRIORITY_SUPPORT:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_DL_QUEUE_PRIORITY_SUPPORT);
        break;
    case IEEE80211_PARAM_CLEAR_MIN_MAX_RSSI:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_CLEAR_MIN_MAX_RSSI);
        break;
    case IEEE80211_PARAM_WATERMARK_THRESHOLD:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_WATERMARK_THRESHOLD);
        break;
    case IEEE80211_PARAM_WATERMARK_REACHED:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_WATERMARK_REACHED);
        break;
    case IEEE80211_PARAM_ASSOC_REACHED:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_ASSOC_REACHED);
        break;
    case IEEE80211_PARAM_ENABLE_VENDOR_IE:
	 *value = vap->iv_ena_vendor_ie;
        break;
#if UMAC_SUPPORT_ACL
    case IEEE80211_PARAM_CONFIG_ASSOC_DENIAL_NOTIFY:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_ASSOC_DENIAL_NOTIFICATION);
        break;
   case IEEE80211_PARAM_MACCMD_SEC:
        *value = wlan_get_acl_policy(vap, IEEE80211_ACL_FLAG_ACL_LIST_2);
        break;
#endif /* UMAC_SUPPORT_ACL */
    case IEEE80211_PARAM_CONFIG_MON_DECODER:
        if (IEEE80211_M_MONITOR != vap->iv_opmode) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"Not Monitor VAP!\n");
            return -EINVAL;
        }
        /* monitor vap decoder header type: radiotap=0(default) prism=1 */
        *value = wlan_get_param(vap, IEEE80211_CONFIG_MON_DECODER);
        break;
    case IEEE80211_PARAM_BEACON_RATE_FOR_VAP:
        if(vap->iv_opmode == IEEE80211_M_HOSTAP) {
            *value = wlan_get_param(vap, IEEE80211_BEACON_RATE_FOR_VAP);
        }
        break;
    case IEEE80211_PARAM_SIFS_TRIGGER_RATE:
        if (!ic->ic_is_mode_offload(ic))
            return -EPERM;
        *value = vap->iv_sifs_trigger_rate;
        break;
    case IEEE80211_PARAM_DISABLE_SELECTIVE_LEGACY_RATE_FOR_VAP:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_DISABLE_SELECTIVE_LEGACY_RATE);
        break;
    case IEEE80211_PARAM_CONFIG_NSTSCAP_WAR:
        *value = wlan_get_param(vap,IEEE80211_CONFIG_NSTSCAP_WAR);
        break;
    case IEEE80211_PARAM_CHANNEL_SWITCH_MODE:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_CHANNEL_SWITCH_MODE);
        break;

    case IEEE80211_PARAM_ENABLE_ECSA_IE:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_ECSA_IE);
        break;

    case IEEE80211_PARAM_ECSA_OPCLASS:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_ECSA_OPCLASS);
        break;

    case IEEE80211_PARAM_BACKHAUL:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_BACKHAUL);
        break;

#if DYNAMIC_BEACON_SUPPORT
    case IEEE80211_PARAM_DBEACON_EN:
        *value = vap->iv_dbeacon;
        break;

    case IEEE80211_PARAM_DBEACON_RSSI_THR:
        *value = vap->iv_dbeacon_rssi_thr;
        break;

    case IEEE80211_PARAM_DBEACON_TIMEOUT:
        *value = vap->iv_dbeacon_timeout;
        break;
#endif
#if QCN_IE
    case IEEE80211_PARAM_BCAST_PROBE_RESPONSE_ENABLE:
        *value = vap->iv_bpr_enable;
        break;
    case IEEE80211_PARAM_BCAST_PROBE_RESPONSE_LATENCY_COMPENSATION:
        *value = ic->ic_bpr_latency_comp;
        break;
    case IEEE80211_PARAM_BEACON_LATENCY_COMPENSATION:
        *value = ic->ic_bcn_latency_comp;
        break;
    case IEEE80211_PARAM_BCAST_PROBE_RESPONSE_DELAY:
        *value = vap->iv_bpr_delay;
        break;
    case IEEE80211_PARAM_BCAST_PROBE_RESPONSE_STATS:
        *value = 0;
        if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
                           "------------------------------------\n");
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
                           "| BPR feature enabled        - %d  |\n", vap->iv_bpr_enable);
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
                           "| BPR Latency compensation   - %d ms |\n", ic->ic_bpr_latency_comp);
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
                           "| Beacon Latency compensation- %d ms |\n", ic->ic_bcn_latency_comp);
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
                           "| BPR delay                  - %d ms |\n", vap->iv_bpr_delay);
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
                           "| Current Timestamp          - %lld |\n", ktime_to_ns(ktime_get()));
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
                           "| Next beacon Timestamp      - %lld |\n", ktime_to_ns(vap->iv_next_beacon_tstamp));
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
                           "| Timer expires in           - %lld |\n", ktime_to_ns(ktime_add(ktime_get(),                                                     hrtimer_get_remaining(&vap->bpr_timer.timer))));
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
                           "| BPR timer start count      - %u |\n", vap->iv_bpr_timer_start_count);
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
                           "| BPR timer resize count     - %u |\n", vap->iv_bpr_timer_resize_count);
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
                           "| BPR timer callback count   - %u |\n", vap->iv_bpr_callback_count);
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
                           "| BPR timer cancel count     - %u |\n", vap->iv_bpr_timer_cancel_count);
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
                           "------------------------------------\n");
        } else {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
                           "Invalid. Allowed only in HOSTAP mode\n");
        }
        break;
    case IEEE80211_PARAM_BCAST_PROBE_RESPONSE_STATS_CLEAR:
        *value = 0;
        vap->iv_bpr_timer_start_count  = 0;
        vap->iv_bpr_timer_resize_count = 0;
        vap->iv_bpr_callback_count     = 0;
        vap->iv_bpr_timer_cancel_count = 0;
        break;
#endif

    case IEEE80211_PARAM_TXPOW_MGMT:
        frame_subtype = txpow_frm_subtype[1];
        if (((frame_subtype & ~IEEE80211_FC0_SUBTYPE_MASK)!=0) || (frame_subtype < IEEE80211_FC0_SUBTYPE_ASSOC_REQ)
                || (frame_subtype > IEEE80211_FC0_SUBTYPE_DEAUTH) ) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Invalid value entered for frame subtype\n");
            return -EINVAL;
        }
        *value = vap->iv_txpow_mgt_frm[(frame_subtype >> IEEE80211_FC0_SUBTYPE_SHIFT)];
        break;

    case IEEE80211_PARAM_CONFIG_TX_CAPTURE:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_TX_CAPTURE);
        break;

    case IEEE80211_PARAM_EXT_NSS_CAPABLE:
        if (!ic->ic_is_mode_offload(ic)) {
            return -EPERM;
        }
        *value = wlan_get_param(vap, IEEE80211_CONFIG_EXT_NSS_CAPABLE);
        break;

    case IEEE80211_PARAM_CSL_SUPPORT:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_CSL_SUPPORT);
        break;

    case IEEE80211_PARAM_CONFIG_TX_CAPTURE_DA:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_TX_CAPTURE_DA);
        break;

    case IEEE80211_PARAM_EXT_NSS_SUPPORT:
        if (!ic->ic_is_mode_offload(ic)) {
            return -EPERM;
        }
        *value = wlan_get_param(vap, IEEE80211_CONFIG_EXT_NSS_SUPPORT);
        break;

    case IEEE80211_PARAM_DISABLE_CABQ:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_DISABLE_CABQ);
        break;

    case IEEE80211_PARAM_ENABLE_FILS:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_FILS);
        break;
    }

    if (retv) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : parameter 0x%x not supported \n", __func__, param);
        return -EOPNOTSUPP;
    }

    return retv;
}

int ieee80211_ucfg_get_maxphyrate(wlan_if_t vaphandle)
{
 struct ieee80211vap *vap = vaphandle;
 struct ieee80211com *ic = vap->iv_ic;

 if (!vap->iv_bss)
     return 0;

 /* Rate should show 0 if VAP is not UP */
 return(!ieee80211_vap_ready_is_set(vap) ? 0:ic->ic_get_maxphyrate(ic, vap->iv_bss) * 1000);
}

#define IEEE80211_MODE_TURBO_STATIC_A   IEEE80211_MODE_MAX

static int ieee80211_convert_mode(const char *mode)
{
#define TOUPPER(c) ((((c) > 0x60) && ((c) < 0x7b)) ? ((c) - 0x20) : (c))
    static const struct
    {
        char *name;
        int mode;
    } mappings[] = {
        /* NB: need to order longest strings first for overlaps */
        { "11AST" , IEEE80211_MODE_TURBO_STATIC_A },
        { "AUTO"  , IEEE80211_MODE_AUTO },
        { "11A"   , IEEE80211_MODE_11A },
        { "11B"   , IEEE80211_MODE_11B },
        { "11G"   , IEEE80211_MODE_11G },
        { "FH"    , IEEE80211_MODE_FH },
		{ "0"     , IEEE80211_MODE_AUTO },
		{ "1"     , IEEE80211_MODE_11A },
		{ "2"     , IEEE80211_MODE_11B },
		{ "3"     , IEEE80211_MODE_11G },
		{ "4"     , IEEE80211_MODE_FH },
		{ "5"     , IEEE80211_MODE_TURBO_STATIC_A },
	    { "TA"      , IEEE80211_MODE_TURBO_A },
	    { "TG"      , IEEE80211_MODE_TURBO_G },
	    { "11NAHT20"      , IEEE80211_MODE_11NA_HT20 },
	    { "11NGHT20"      , IEEE80211_MODE_11NG_HT20 },
	    { "11NAHT40PLUS"  , IEEE80211_MODE_11NA_HT40PLUS },
	    { "11NAHT40MINUS" , IEEE80211_MODE_11NA_HT40MINUS },
	    { "11NGHT40PLUS"  , IEEE80211_MODE_11NG_HT40PLUS },
	    { "11NGHT40MINUS" , IEEE80211_MODE_11NG_HT40MINUS },
        { "11NGHT40" , IEEE80211_MODE_11NG_HT40},
        { "11NAHT40" , IEEE80211_MODE_11NA_HT40},
        { "11ACVHT20", IEEE80211_MODE_11AC_VHT20},
        { "11ACVHT40PLUS", IEEE80211_MODE_11AC_VHT40PLUS},
        { "11ACVHT40MINUS", IEEE80211_MODE_11AC_VHT40MINUS},
        { "11ACVHT40", IEEE80211_MODE_11AC_VHT40},
        { "11ACVHT80", IEEE80211_MODE_11AC_VHT80},
        { "11ACVHT160", IEEE80211_MODE_11AC_VHT160},
        { "11ACVHT80_80", IEEE80211_MODE_11AC_VHT80_80},
        { NULL }
    };
    int i, j;
    const char *cp;

    for (i = 0; mappings[i].name != NULL; i++) {
        cp = mappings[i].name;
        for (j = 0; j < strlen(mode) + 1; j++) {
            /* convert user-specified string to upper case */
            if (TOUPPER(mode[j]) != cp[j])
                break;
            if (cp[j] == '\0')
                return mappings[i].mode;
        }
    }
    return -1;
#undef TOUPPER
}

int ieee80211_ucfg_set_phymode(wlan_if_t vap, char *modestr, int len)
{
    struct ieee80211com *ic = vap->iv_ic;
    char s[30];      /* big enough for ``11nght40plus'' */
    int mode;

    if (len > sizeof(s))        /* silently truncate */
        len = sizeof(s);

    if (strlcpy(s, modestr, len) >= len) {
        return -EINVAL;
    }

    /*
    ** Convert mode name into a specific mode
    */

    mode = ieee80211_convert_mode(s);
    if (mode < 0)
        return -EINVAL;

    /* OBSS scanning should only be enabled in 40 Mhz 2.4G */
    switch (mode) {
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40:
            {
                struct ieee80211vap *tmpvap = NULL;
                bool ht40_vap_found = false;
                /*Check if already any VAP is configured with HT40 mode*/
                TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
                    if((vap != tmpvap) &&
                      ((tmpvap->iv_des_mode == IEEE80211_MODE_11NG_HT40PLUS) ||
                      (tmpvap->iv_des_mode == IEEE80211_MODE_11NG_HT40MINUS) ||
                      (tmpvap->iv_des_mode == IEEE80211_MODE_11NG_HT40))) {
                        ht40_vap_found = true;
                        break;
                    }
                }
                /*
                * If any VAP is already configured with HT40 Mode
                * no need to clear disable coext flag,
                * as disable coext flag may be set by other VAP
                */
                if(!ht40_vap_found)
                    ic->ic_flags &= ~IEEE80211_F_COEXT_DISABLE;
            }
            break;
        default:
            ic->ic_flags |= IEEE80211_F_COEXT_DISABLE;
            break;
    }

#if ATH_SUPPORT_IBSS_HT
    /*
     * config ic adhoc ht capability
     */
    if (vap->iv_opmode == IEEE80211_M_IBSS) {

        wlan_dev_t ic = wlan_vap_get_devhandle(vap);

        switch (mode) {
        case IEEE80211_MODE_11NA_HT20:
        case IEEE80211_MODE_11NG_HT20:
            /* enable adhoc ht20 and aggr */
            wlan_set_device_param(ic, IEEE80211_DEVICE_HT20ADHOC, 1);
            wlan_set_device_param(ic, IEEE80211_DEVICE_HT40ADHOC, 0);
            break;
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40:
        case IEEE80211_MODE_11NA_HT40:
            /* enable adhoc ht40 and aggr */
            wlan_set_device_param(ic, IEEE80211_DEVICE_HT20ADHOC, 1);
            wlan_set_device_param(ic, IEEE80211_DEVICE_HT40ADHOC, 1);
            break;
        /* TODO: With IBSS support add VHT fields as well */
        default:
            /* clear adhoc ht20, ht40, aggr */
            wlan_set_device_param(ic, IEEE80211_DEVICE_HT20ADHOC, 0);
            wlan_set_device_param(ic, IEEE80211_DEVICE_HT40ADHOC, 0);
            break;
        } /* end of switch (mode) */
    }
#endif /* end of #if ATH_SUPPORT_IBSS_HT */

    return wlan_set_desired_phymode(vap, mode);
}

static const u_int8_t ieee80211broadcastaddr[IEEE80211_ADDR_LEN] =
{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/*
* Get a key index from a request.  If nothing is
* specified in the request we use the current xmit
* key index.  Otherwise we just convert the index
* to be base zero.
*/
static int getkeyix(wlan_if_t vap, u_int16_t flags, u_int16_t *kix)
{
    int kid;

    kid = flags & IW_ENCODE_INDEX;
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

/*
 * If authmode = IEEE80211_AUTH_OPEN, script apup would skip authmode setup.
 * Do default authmode setup here for OPEN mode.
 */
static int sencode_wep(struct net_device *dev)
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

int ieee80211_ucfg_set_encode(wlan_if_t vap, u_int16_t length, u_int16_t flags, void *keybuf)
{
    osif_dev *osifp = (osif_dev *)vap->iv_ifp;
    struct net_device *dev = osifp->netdev;
    ieee80211_keyval key_val;
    u_int16_t kid;
    int error = -EOPNOTSUPP;
    u_int8_t keydata[IEEE80211_KEYBUF_SIZE];
    int wepchange = 0;

    if (ieee80211_crypto_wep_mbssid_enabled())
        wlan_set_param(vap, IEEE80211_WEP_MBSSID, 1);  /* wep keys will start from 4 in keycache for support wep multi-bssid */
    else
        wlan_set_param(vap, IEEE80211_WEP_MBSSID, 0);  /* wep keys will allocate index 0-3 in keycache */

    if ((flags & IW_ENCODE_DISABLED) == 0)
    {
        /*
         * Enable crypto, set key contents, and
         * set the default transmit key.
         */
        error = getkeyix(vap, flags, &kid);
        if (error)
            return error;
        if (length > IEEE80211_KEYBUF_SIZE)
            return -EINVAL;

        /* XXX no way to install 0-length key */
        if (length > 0)
        {

            /* WEP key length should be 40,104, 128 bits only */
            if(!((length == IEEE80211_KEY_WEP40_LEN) ||
                        (length == IEEE80211_KEY_WEP104_LEN) ||
                        (length == IEEE80211_KEY_WEP128_LEN)))
            {

                IEEE80211_DPRINTF(vap, IEEE80211_MSG_CRYPTO, "WEP key is rejected due to key of length %d\n", length);
                osif_ioctl_delete_vap(dev);
                return -EINVAL;
            }

            /*
             * ieee80211_match_rsn_info() IBSS mode need.
             * Otherwise, it caused crash when tx frame find tx rate
             *   by node RateControl info not update.
             */
            if (osifp->os_opmode == IEEE80211_M_IBSS) {
                /* set authmode to IEEE80211_AUTH_OPEN */
                sencode_wep(dev);

                /* set keymgmtset to WPA_ASE_NONE */
                wlan_set_rsn_cipher_param(vap, IEEE80211_KEYMGT_ALGS, WPA_ASE_NONE);
            }

            OS_MEMCPY(keydata, keybuf, length);
            memset(&key_val, 0, sizeof(ieee80211_keyval));
            key_val.keytype = IEEE80211_CIPHER_WEP;
            key_val.keydir = IEEE80211_KEY_DIR_BOTH;
            key_val.keylen = length;
            key_val.keydata = keydata;
            key_val.macaddr = (u_int8_t *)ieee80211broadcastaddr;

            if (wlan_set_key(vap,kid,&key_val) != 0)
                return -EINVAL;
        }
        else
        {
            /*
             * When the length is zero the request only changes
             * the default transmit key.  Verify the new key has
             * a non-zero length.
             */
            if ( wlan_set_default_keyid(vap,kid) != 0  ) {
                QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n Invalid Key is being Set. Bringing VAP down! \n");
                osif_ioctl_delete_vap(dev);
                return -EINVAL;
            }
        }
        if (error == 0)
        {
            /*
             * The default transmit key is only changed when:
             * 1. Privacy is enabled and no key matter is
             *    specified.
             * 2. Privacy is currently disabled.
             * This is deduced from the iwconfig man page.
             */
            if (length == 0 ||
                    (wlan_get_param(vap,IEEE80211_FEATURE_PRIVACY)) == 0)
                wlan_set_default_keyid(vap,kid);
            wepchange = (wlan_get_param(vap,IEEE80211_FEATURE_PRIVACY)) == 0;
            wlan_set_param(vap,IEEE80211_FEATURE_PRIVACY, 1);
        }
    }
    else
    {
        if (wlan_get_param(vap,IEEE80211_FEATURE_PRIVACY) == 0)
            return 0;
        wlan_set_param(vap,IEEE80211_FEATURE_PRIVACY, 0);
        wepchange = 2;
        error = 0;
    }
    if (error == 0)
    {
        /* Set policy for unencrypted frames */
        if ((flags & IW_ENCODE_OPEN) &&
                (!(flags & IW_ENCODE_RESTRICTED)))
        {
            wlan_set_param(vap,IEEE80211_FEATURE_DROP_UNENC, 0);
        }
        else if (!(flags & IW_ENCODE_OPEN) &&
                (flags & IW_ENCODE_RESTRICTED))
        {
            wlan_set_param(vap,IEEE80211_FEATURE_DROP_UNENC, 1);
        }
        else
        {
            /* Default policy */
            if (wlan_get_param(vap,IEEE80211_FEATURE_PRIVACY))
                wlan_set_param(vap,IEEE80211_FEATURE_DROP_UNENC, 1);
            else
                wlan_set_param(vap,IEEE80211_FEATURE_DROP_UNENC, 0);
        }
    }
    if (error == 0 && IS_UP(dev) && wepchange)
    {
        /*
         * Device is up and running; we must kick it to
         * effect the change.  If we're enabling/disabling
         * crypto use then we must re-initialize the device
         * so the 802.11 state machine is reset.  Otherwise
         * the key state should have been updated above.
         */

        error = osif_vap_init(dev, RESCAN);
    }
    if(wepchange == 2){
       wlan_clear_vap_key(vap);
    }

#ifdef ATH_SUPERG_XR
    /* set the same params on the xr vap device if exists */
    if(!error && vap->iv_xrvap && !(vap->iv_flags & IEEE80211_F_XR))
        ieee80211_ucfg_set_encode(vap, ptr->len, ptr->flags,
                ptr->buff);
#endif
    return error;
}

int ieee80211_ucfg_set_rate(wlan_if_t vap, int value)
{
    int retv;

    retv = wlan_set_param(vap, IEEE80211_FIXED_RATE, value);
    if (EOK == retv) {
        if (value != IEEE80211_FIXED_RATE_NONE) {
            /* set default retries when setting fixed rate */
            retv = wlan_set_param(vap, IEEE80211_FIXED_RETRIES, 4);
        }
        else {
            retv = wlan_set_param(vap, IEEE80211_FIXED_RETRIES, 0);
        }
    }
    return retv;
}

#define IEEE80211_MODE_TURBO_STATIC_A   IEEE80211_MODE_MAX
int ieee80211_ucfg_get_phymode(wlan_if_t vap, char *modestr, u_int16_t *length)
{
    static const struct
    {
        char *name;
        int mode;
    } mappings[] = {
        /* NB: need to order longest strings first for overlaps */
        { "11AST" , IEEE80211_MODE_TURBO_STATIC_A },
        { "AUTO"  , IEEE80211_MODE_AUTO },
        { "11A"   , IEEE80211_MODE_11A },
        { "11B"   , IEEE80211_MODE_11B },
        { "11G"   , IEEE80211_MODE_11G },
        { "FH"    , IEEE80211_MODE_FH },
        { "TA"      , IEEE80211_MODE_TURBO_A },
        { "TG"      , IEEE80211_MODE_TURBO_G },
        { "11NAHT20"        , IEEE80211_MODE_11NA_HT20 },
        { "11NGHT20"        , IEEE80211_MODE_11NG_HT20 },
        { "11NAHT40PLUS"    , IEEE80211_MODE_11NA_HT40PLUS },
        { "11NAHT40MINUS"   , IEEE80211_MODE_11NA_HT40MINUS },
        { "11NGHT40PLUS"    , IEEE80211_MODE_11NG_HT40PLUS },
        { "11NGHT40MINUS"   , IEEE80211_MODE_11NG_HT40MINUS },
        { "11NGHT40"        , IEEE80211_MODE_11NG_HT40},
        { "11NAHT40"        , IEEE80211_MODE_11NA_HT40},
        { "11ACVHT20"       , IEEE80211_MODE_11AC_VHT20},
        { "11ACVHT40PLUS"   , IEEE80211_MODE_11AC_VHT40PLUS},
        { "11ACVHT40MINUS"  , IEEE80211_MODE_11AC_VHT40MINUS},
        { "11ACVHT40"       , IEEE80211_MODE_11AC_VHT40},
        { "11ACVHT80"       , IEEE80211_MODE_11AC_VHT80},
        { "11ACVHT160"      , IEEE80211_MODE_11AC_VHT160},
        { "11ACVHT80_80"    , IEEE80211_MODE_11AC_VHT80_80},
        { NULL }
    };
    enum ieee80211_phymode  phymode;
    int i;

    phymode = wlan_get_desired_phymode(vap);

    for (i = 0; mappings[i].name != NULL ; i++)
    {
        if (phymode == mappings[i].mode)
        {
            *length = strlen(mappings[i].name);
            strlcpy(modestr, mappings[i].name, *length + 1);
            break;
        }
    }
    return 0;
}
#undef IEEE80211_MODE_TURBO_STATIC_A

#if ATH_SUPPORT_SPLITMAC
bool ieee80211_ucfg_decrement_sta_count(wlan_if_t vap, struct ieee80211_node *ni)
{
    struct ieee80211com *ic = ni->ni_ic;

#if QCA_AIRTIME_FAIRNESS
    int i, order = 0;
#endif

    IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC | IEEE80211_MSG_DEBUG, ni,
                   "station with aid %d leaves (refcnt %u) \n",
                   IEEE80211_NODE_AID(ni), ieee80211_node_refcnt(ni));
    if(ni->ni_node_esc == true) {
        ni->ni_node_esc = false;
        vap->iv_ic->ic_auth_tx_xretry--;
        IEEE80211_DPRINTF(vap,  IEEE80211_MSG_AUTH, "%s ni = 0x%p ni->ni_macaddr = %s ic_auth_tx_xretry = %d\n",
                __func__, ni, ether_sprintf(ni->ni_macaddr), vap->iv_ic->ic_auth_tx_xretry);
    }
#ifdef ATH_SWRETRY
    if (ic->ic_reset_pause_tid)
        ic->ic_reset_pause_tid(ni->ni_ic, ni);
#endif

    KASSERT(vap->iv_opmode == IEEE80211_M_HOSTAP
            || vap->iv_opmode == IEEE80211_M_WDS ||
            vap->iv_opmode == IEEE80211_M_BTAMP  ||
            vap->iv_opmode == IEEE80211_M_IBSS,
            ("unexpected operating mode %u", vap->iv_opmode));

    /* Multicast enhancement: If the entry with the node's address exists in
     * the snoop table, it should be removed.
     */
    if (vap->iv_ique_ops.me_clean) {
        vap->iv_ique_ops.me_clean(ni);
    }
	/*
     * HBR / headline block removal: delete the node entity from the table
     * for HBR purpose
     */
    if (vap->iv_ique_ops.hbr_nodeleave) {
        vap->iv_ique_ops.hbr_nodeleave(vap, ni);
    }
    /*
     * If node wasn't previously associated all
     * we need to do is reclaim the reference.
     */
    /* XXX ibss mode bypasses 11g and notification */

    IEEE80211_NODE_STATE_LOCK_BH(ni);

    /*
     * Prevent _ieee80211_node_leave() from reentry which would mess up the
     * value of iv_sta_assoc. Before AP received the tx ack for "disassoc
     * request", it may have received the "auth (not SUCCESS status)" to do
     * node leave. With the flag, follow-up cleanup wouldn't call
     * _ieee80211_node_leave() again when execuating the tx_complete handler.
     */
    ni->ni_flags |= IEEE80211_NODE_LEAVE_ONGOING;

    if (ni->ni_associd) {
        IEEE80211_VAP_LOCK(vap);
        vap->iv_sta_assoc--;
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                          "%s, macaddr %s left,  decremented iv_sta_assoc(%hu)\n",
                          __func__, ether_sprintf(ni->ni_macaddr),vap->iv_sta_assoc);

        IEEE80211_VAP_UNLOCK(vap);
        IEEE80211_COMM_LOCK(ic);
        ic->ic_sta_assoc--;
        /* Update bss load element in beacon */
        ieee80211_vap_bssload_update_set(vap);

        if (IEEE80211_NODE_USE_HT(ni)) {
            ic->ic_ht_sta_assoc--;
            if (ni->ni_htcap & IEEE80211_HTCAP_C_GREENFIELD) {
                ASSERT(ic->ic_ht_gf_sta_assoc > 0);
                ic->ic_ht_gf_sta_assoc--;
            }
#if ATH_TxBF_DYNAMIC_LOF_ON_N_CHAIN_MASK
            iee80211_txbf_loforce_check(ni,0);
#endif
            if ((ni->ni_chwidth == IEEE80211_CWM_WIDTH40) || (ni->ni_chwidth == IEEE80211_CWM_WIDTH80))
	      ic->ic_ht40_sta_assoc--;
	  }


        if ((IEEE80211_IS_CHAN_ANYG(vap->iv_bsschan) ||
            IEEE80211_IS_CHAN_11NG(vap->iv_bsschan)))
            ieee80211_node_leave_11g(ni);

        ieee80211_admctl_node_leave(vap, ni);

        /*
         * Cleanup station state.  In particular clear various state that
         * might otherwise be reused if the node is reused before the
         * reference count goes to zero (and memory is reclaimed).
         *
         * If ni is not in node table, it has been reclaimed in another thread.
         */
#if QCA_AIRTIME_FAIRNESS
        /*
         *  ATF Node leave.
         */
        ieee80211_atf_node_join_leave(ni,0);

        if (ic->ic_atf_tput_based && ni->ni_atf_tput) {
            for (i = 0; i < ATF_TPUT_MAX_STA; i++) {
                if (!OS_MEMCMP(ic->ic_atf_tput_tbl[i].mac_addr, ni->ni_macaddr, IEEE80211_ADDR_LEN)) {
                    order = ic->ic_atf_tput_tbl[i].order;
                    ic->ic_atf_tput_tbl[i].order = 0;
                    break;
                }
            }
            if (order) {
                for (i = 0; i < ATF_TPUT_MAX_STA; i++) {
                    if (ic->ic_atf_tput_tbl[i].order > order) {
                        ic->ic_atf_tput_tbl[i].order--;
                    }
                }
                ic->ic_atf_tput_order_max--;
            }
            if(ic->ic_is_mode_offload(ic))
            {
                build_bwf_for_fm(ic);
            }
        }

#endif

        IEEE80211_COMM_UNLOCK(ic);
        ni->ni_flags &= ~IEEE80211_NODE_LEAVE_ONGOING;
        IEEE80211_NODE_STATE_UNLOCK_BH(ni);
        IEEE80211_DELETE_NODE_TARGET(ni, ic, vap, 0);
    } else {
        ieee80211_admctl_node_leave(vap, ni);
        ni->ni_flags &= ~IEEE80211_NODE_LEAVE_ONGOING;
        IEEE80211_NODE_STATE_UNLOCK_BH(ni);
    }

    if ((ni->ni_flags & IEEE80211_NODE_HT) &&
        (ni->ni_flags & IEEE80211_NODE_40_INTOLERANT)) {
        ieee80211_change_cw(ic);
    }

    return true;
}

int ieee80211_ucfg_splitmac_add_client(wlan_if_t vap, u_int8_t *stamac, u_int16_t associd,
                         u_int8_t qos, struct ieee80211_rateset lrates,
                         struct ieee80211_rateset htrates, u_int16_t vhtrates)
{
    struct ieee80211_node   *ni = NULL;
    struct ieee80211com *ic;
    u_int8_t newassoc;
    ieee80211_vht_rate_t vht;
    u_int16_t vhtrate_map = 0;
    u_int8_t i = 0;
    u_int8_t all_rates_zero_legacy = 1, all_rates_zero_ht = 1;

	if (!vap->iv_splitmac)
        return -EFAULT;

    ni = ieee80211_find_node(&vap->iv_ic->ic_sta, stamac);

    if (ni == NULL) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
                          "%s(): Node not found\n", __func__);
        return -EINVAL;
    }

    IEEE80211_NODE_STATE_LOCK(ni);

    if(ni->splitmac_state == IEEE80211_SPLITMAC_NODE_INIT) {
        IEEE80211_NODE_STATE_UNLOCK(ni);
        ieee80211_free_node(ni);
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
                          "%s(): splitmac_state in node init!\n", __func__);
        return -EINVAL;
    }

    ni->splitmac_state = IEEE80211_SPLITMAC_ASSOC_RESP_START;

    ic = ni->ni_ic;
    newassoc = (ni->ni_associd == 0);

    IEEE80211_NOTE(ni->ni_vap, IEEE80211_MSG_SPLITMAC, ni,
            "%s: 0x%x oldaid=%d newaid=%d\n", __func__,ni, ni->ni_associd, associd);

    /* override the aid */
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_SPLITMAC,
                      "%s(): Overriding AID for %s\n", __func__,
                      ether_sprintf(ni->ni_macaddr));

    if (associd == 0) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
                          "%s(): AID is 0...check\n", __func__);

        IEEE80211_NODE_STATE_UNLOCK(ni);

        ieee80211_free_node(ni);
        return -EINVAL;
    }

    if (IEEE80211_AID(ni->ni_associd) != associd) {
        if (IEEE80211_AID_ISSET(vap, associd)) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
                              "%s(): associd %d already in use...check\n",
                              __func__, associd);
            IEEE80211_NODE_STATE_UNLOCK(ni);

            ieee80211_free_node(ni);
            return -EINVAL;
        }
    }

    if (IEEE80211_AID(ni->ni_associd) != 0) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
                          "%s(): replacing old associd %d with new id %d\n"
                          , __func__, IEEE80211_AID(ni->ni_associd), associd);

        IEEE80211_NODE_STATE_UNLOCK(ni);
        ieee80211_ucfg_decrement_sta_count(vap, ni);
        IEEE80211_NODE_STATE_LOCK(ni);

        IEEE80211_AID_CLR(vap, ni->ni_associd);
    } else {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_SPLITMAC,
                          "%s(): New AID is %d\n", __func__, associd);
    }

    ni->ni_associd = associd | IEEE80211_RESV_AID_BITS;
    IEEE80211_AID_SET(vap, ni->ni_associd);

    /* override qos flag */
    if (qos)
        ni->ni_flags |= IEEE80211_NODE_QOS;
    else
        ni->ni_flags &= ~IEEE80211_NODE_QOS;

    /* override data rates */
    OS_MEMCPY(&ni->ni_rates, &lrates, sizeof(struct ieee80211_rateset));
    /* ni_htcap can be 0, should check ni_flags&IEEE80211_NODE_HT instead for HT capability */
    if (IEEE80211_NODE_USE_HT(ni)){
        OS_MEMCPY(&ni->ni_htrates, &htrates, sizeof(struct ieee80211_rateset));
    }else{
        OS_MEMSET(&ni->ni_htrates, 0, sizeof(struct ieee80211_rateset));
    }
    if (IEEE80211_NODE_USE_VHT(ni)){
        OS_MEMZERO(&vht, sizeof(ieee80211_vht_rate_t));
        OS_MEMSET(&(vht.rates), 0xff, MAX_VHT_STREAMS);

        vht.num_streams = ni->ni_streams;
        if(vht.num_streams > MAX_VHT_STREAMS){
            IEEE80211_NODE_STATE_UNLOCK(ni);
            IEEE80211_AID_CLR(vap, ni->ni_associd);
            ieee80211_free_node(ni);
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
                       "%s(): streams %d beyond max VHT streams \n", __func__, vht.num_streams);
            return -EINVAL;
        }
        for(i=0; i < vht.num_streams; i++){
            vht.rates[i] = vhtrates;
        }
        vhtrate_map = ieee80211_get_vht_rate_map(&vht);
        ni->ni_tx_vhtrates = vhtrate_map;
    }else{
        ni->ni_tx_vhtrates = 0;
    }

    IEEE80211_NODE_STATE_UNLOCK(ni);

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_SPLITMAC,"add_client: legacy rates\n");
    for(i=0; i<ni->ni_rates.rs_nrates; i++){
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_SPLITMAC,"%d ", ni->ni_rates.rs_rates[i]);
        if (ni->ni_rates.rs_rates[i] != 0) {
            all_rates_zero_legacy = 0;
        }
    }
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_SPLITMAC,"\n");

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_SPLITMAC,"add_client: HT rates\n");
    for(i=0; i<ni->ni_htrates.rs_nrates; i++){
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_SPLITMAC,"%d ", ni->ni_htrates.rs_rates[i]);
        if (ni->ni_htrates.rs_rates[i] != 0) {
            all_rates_zero_ht = 0;
        }
    }
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_SPLITMAC,"\n");

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_SPLITMAC,"add_client: VHT rate map=0x%x\n",
                                                            ni->ni_tx_vhtrates);

    switch(ni->ni_phymode){
        case IEEE80211_MODE_11A:
        case IEEE80211_MODE_11B:
        case IEEE80211_MODE_11G:
            /* if phymode is legacy, but no legacy rate found, return err */
            if (all_rates_zero_legacy == 1) {
                IEEE80211_AID_CLR(vap, ni->ni_associd);
                ieee80211_free_node(ni);
                return -EINVAL;
            }
        break;
        case IEEE80211_MODE_11NA_HT20:
        case IEEE80211_MODE_11NG_HT20:
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40:
        case IEEE80211_MODE_11NA_HT40:
            /* if phymode is HT, but no HT rate found, return err */
            if (ni->ni_htcap && all_rates_zero_ht == 1) {
                IEEE80211_AID_CLR(vap, ni->ni_associd);
                ieee80211_free_node(ni);
                return -EINVAL;
            }
        break;
        default:
        /*
         * For VHT rates, MCS 0-7 are mandatory and enforce in driver.
         * This API only exposes MCS 8,9 for caller. No need to check, even if MCS 8, 9 are all zero.
         */
        break;
    }

    /* do mlme stuff for processing assoc req here */
    ieee80211_mlme_recv_assoc_request(ni, 0, NULL, NULL);

    IEEE80211_NODE_STATE_LOCK(ni);
    ni->splitmac_state = IEEE80211_SPLITMAC_ASSOC_RESP_END;
    IEEE80211_NODE_STATE_UNLOCK(ni);

    ieee80211_free_node(ni);

    return 0;
}

int ieee80211_ucfg_splitmac_del_client(wlan_if_t vap, u_int8_t *stamac)
{
    struct ieee80211_node   *ni = NULL;
    struct ieee80211com *ic;

	if (!vap->iv_splitmac)
        return -EFAULT;

    ni = ieee80211_find_node(&vap->iv_ic->ic_sta, stamac);
    if (ni == NULL) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
                          "%s(): Node not found\n", __func__);
        return -EINVAL;
    }

    ic = ni->ni_ic;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_SPLITMAC,"%s(): Delete STA: %s\n",
                        __func__, ether_sprintf(stamac));
    IEEE80211_NODE_LEAVE(ni);
    ieee80211_free_node(ni);

    IEEE80211_DELIVER_EVENT_MLME_DISASSOC_COMPLETE(vap, stamac,
                                                     IEEE80211_REASON_ASSOC_LEAVE, IEEE80211_STATUS_SUCCESS);
    return 0;
}

int ieee80211_ucfg_splitmac_authorize_client(wlan_if_t vap, u_int8_t *stamac, u_int32_t authorize)
{
    struct ieee80211_node *ni=NULL;
    struct ieee80211com *ic;

	if (!vap->iv_splitmac)
        return -EFAULT;

    ni = ieee80211_find_node(&vap->iv_ic->ic_sta, stamac);
    if (ni == NULL) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
                          "%s(): Node not found\n", __func__);
        return -EINVAL;
    }

    ic = ni->ni_ic;

    authorize = !!authorize;
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_SPLITMAC,"%s(): Authorize STA: %s, authorize=%d\n",
                        __func__,ether_sprintf(stamac), authorize);
    wlan_node_authorize(vap, authorize, stamac);
    if(!authorize){
        /* Call node leave so that its AID can be released and reused by
        * another client.
        */
        IEEE80211_NODE_LEAVE(ni);
    }
    ieee80211_free_node(ni);

    return 0;
}

#define RXMIC_OFFSET 8

int ieee80211_ucfg_splitmac_set_key(wlan_if_t vap, u_int8_t *macaddr, u_int8_t cipher,
                      u_int16_t keyix, u_int32_t keylen, u_int8_t *keydata)
{
    int status = -EINVAL;
    ieee80211_keyval key_val;

	if (!vap->iv_splitmac)
        return -EFAULT;

	if (keylen > IEEE80211_KEYBUF_SIZE+IEEE80211_MICBUF_SIZE) {
		return -EINVAL;
	}

    if ((keyix != IEEE80211_KEYIX_NONE) &&
        (keyix >= IEEE80211_WEP_NKID) && (cipher != IEEE80211_CIPHER_AES_CMAC)) {
            return -EINVAL;
    }

    memset(&key_val,0, sizeof(ieee80211_keyval));

    key_val.keydir = IEEE80211_KEY_DIR_BOTH;
    key_val.keylen  = keylen;
    if (key_val.keylen > IEEE80211_KEYBUF_SIZE) {
        key_val.keylen  = IEEE80211_KEYBUF_SIZE;
    }
    key_val.rxmic_offset = IEEE80211_KEYBUF_SIZE + RXMIC_OFFSET;
    key_val.txmic_offset =  IEEE80211_KEYBUF_SIZE;
    key_val.keytype = cipher;
    key_val.macaddr = macaddr;
    key_val.keydata = keydata;

    /* allow keys to allocate anywhere in key cache */
    wlan_set_param(vap, IEEE80211_WEP_MBSSID, 1);

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_SPLITMAC,
            "\n\n%s: ******** SETKEY : key_idx= %d, key_type=%d, macaddr=%s, key_len=%d\n\n",
                      __func__, keyix, key_val.keytype, ether_sprintf(key_val.macaddr), key_val.keylen);

    status = wlan_set_key(vap, keyix, &key_val);

    wlan_set_param(vap, IEEE80211_WEP_MBSSID, 0);  /* put it back to default */

    return status;
}

int ieee80211_ucfg_splitmac_del_key(wlan_if_t vap, u_int8_t *macaddr, u_int16_t keyix)
{
	if (!vap->iv_splitmac)
        return -EFAULT;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_SPLITMAC,"%s(): for STA: %s\n",
                        __func__, ether_sprintf(macaddr));

    return wlan_del_key(vap, keyix, macaddr);
}

#endif /* ATH_SUPPORT_SPLITMAC */

struct stainforeq
{
    wlan_if_t vap;
    struct ieee80211req_sta_info *si;
    size_t  space;
};

static size_t
sta_space(const wlan_node_t node, size_t *ielen, wlan_if_t vap)
{
    u_int8_t    ni_ie[IEEE80211_MAX_OPT_IE];
    u_int16_t ni_ie_len = IEEE80211_MAX_OPT_IE;
    u_int8_t *macaddr = wlan_node_getmacaddr(node);
    *ielen = 0;

    if(!wlan_node_getwpaie(vap, macaddr, ni_ie, &ni_ie_len)) {
        *ielen += ni_ie_len;
        ni_ie_len = IEEE80211_MAX_OPT_IE;
    }
    if(!wlan_node_getwmeie(vap, macaddr, ni_ie, &ni_ie_len)) {
        *ielen += ni_ie_len;
        ni_ie_len = IEEE80211_MAX_OPT_IE;
    }
    if(!wlan_node_getathie(vap, macaddr, ni_ie, &ni_ie_len)) {
        *ielen += ni_ie_len;
        ni_ie_len = IEEE80211_MAX_OPT_IE;
    }
#ifdef ATH_WPS_IE
    if(!wlan_node_getwpsie(vap, macaddr, ni_ie, &ni_ie_len)) {
        *ielen += ni_ie_len;
        ni_ie_len = IEEE80211_MAX_OPT_IE;
    }
#endif /* ATH_WPS_IE */

    return roundup(sizeof(struct ieee80211req_sta_info) + *ielen,
        sizeof(u_int32_t));
}

static void
get_sta_space(void *arg, wlan_node_t node)
{
    struct stainforeq *req = arg;
    size_t ielen;

    /* already ignore invalid nodes in UMAC */
    req->space += sta_space(node, &ielen, req->vap);
}

static void
get_sta_info(void *arg, wlan_node_t node)
{
    struct stainforeq *req = arg;
    wlan_if_t vap = req->vap;
    struct ieee80211req_sta_info *si;
    size_t ielen, len;
    u_int8_t *cp;
    u_int8_t    ni_ie[IEEE80211_MAX_OPT_IE];
    u_int16_t ni_ie_len = IEEE80211_MAX_OPT_IE;
    u_int8_t *macaddr = wlan_node_getmacaddr(node);
    wlan_rssi_info rssi_info;
    wlan_chan_t chan = wlan_node_get_chan(node);
    ieee80211_rate_info rinfo;
    u_int32_t jiffies_now=0, jiffies_delta=0, jiffies_assoc=0;
    /* already ignore invalid nodes in UMAC */

    if (chan == IEEE80211_CHAN_ANYC) { /* XXX bogus entry */
        return;
    }

    len = sta_space(node, &ielen, vap);
    if (len > req->space) {
        return;
    }
    si = req->si;
    si->awake_time = node->awake_time;
    si->ps_time = node->ps_time;
    /* if node state is currently in power save when the wlanconfig command is given,
       add time from previous_ps_time until current time to power save time */
    if(node->ps_state == 1)
    {
    si->ps_time += qdf_get_system_timestamp() - node->previous_ps_time;
    }
    /* if node state is currently in active state when the wlanconfig command is given,
       add time from previous_ps_time until current time to awake time */
    else if(node->ps_state == 0)
    {
    si->awake_time += qdf_get_system_timestamp() - node->previous_ps_time;
    }
    si->isi_assoc_time = wlan_node_get_assocuptime(node);
    jiffies_assoc = wlan_node_get_assocuptime(node);		/* Jiffies to timespec conversion for si->isi_tr069_assoc_time */
    jiffies_now = OS_GET_TICKS();
    jiffies_delta = jiffies_now - jiffies_assoc;
    jiffies_to_timespec(jiffies_delta, &si->isi_tr069_assoc_time);
    si->isi_len = len;
    si->isi_ie_len = ielen;
    si->isi_freq = wlan_channel_frequency(chan);
    si->isi_flags = wlan_channel_flags(chan);
    si->isi_state = wlan_node_get_state_flag(node);
    if(vap->iv_ic->ic_is_mode_offload(vap->iv_ic)) {
        si->isi_ps = node->ps_state;
    } else {
        si->isi_ps = (si->isi_state & IEEE80211_NODE_PWR_MGT)?1:0;
    }
    si->isi_authmode =  wlan_node_get_authmode(node);
    if (wlan_node_getrssi(node, &rssi_info, WLAN_RSSI_RX) == 0) {
        si->isi_rssi = rssi_info.avg_rssi;
        si->isi_min_rssi = node->ni_rssi_min;
        si->isi_max_rssi = node->ni_rssi_max;
    }
    si->isi_capinfo = wlan_node_getcapinfo(node);
    si->isi_athflags = wlan_node_get_ath_flags(node);
    si->isi_erp = wlan_node_get_erp(node);
    si->isi_operating_bands = wlan_node_get_operating_bands(node);
    IEEE80211_ADDR_COPY(si->isi_macaddr, macaddr);

    if (wlan_node_txrate_info(node, &rinfo) == 0) {
        si->isi_txratekbps = rinfo.rate;
        si->isi_maxrate_per_client = rinfo.maxrate_per_client;
    }

    memset(&rinfo, 0, sizeof(rinfo));
    if (wlan_node_rxrate_info(node, &rinfo) == 0) {
        si->isi_rxratekbps = rinfo.rate;
    }
    si->isi_associd = wlan_node_get_associd(node);
    si->isi_txpower = wlan_node_get_txpower(node);
    si->isi_vlan = wlan_node_get_vlan(node);
    si->isi_cipher = IEEE80211_CIPHER_NONE;
    if (wlan_get_param(vap, IEEE80211_FEATURE_PRIVACY)) {
        do {
            ieee80211_cipher_type uciphers[1];
            int count = 0;
            count = wlan_node_get_ucast_ciphers(node, uciphers, 1);
            if (count == 1) {
                si->isi_cipher |= 1<<uciphers[0];
            }
        } while (0);
    }
    wlan_node_get_txseqs(node, si->isi_txseqs, sizeof(si->isi_txseqs));
    wlan_node_get_rxseqs(node, si->isi_rxseqs, sizeof(si->isi_rxseqs));
    si->isi_uapsd = wlan_node_get_uapsd(node);
    si->isi_opmode = IEEE80211_STA_OPMODE_NORMAL;
    if(vap->iv_ic->ic_is_mode_offload(vap->iv_ic))
        si->isi_inact = node->ni_stats.inactive_time;
    else
        si->isi_inact = wlan_node_get_inact(node);
    /* 11n */
    si->isi_htcap = wlan_node_get_htcap(node);
    si->isi_stamode= wlan_node_get_mode(node);

#if ATH_SUPPORT_EXT_STAT
    si->isi_vhtcap = node->ni_vhtcap;
    si->isi_chwidth = node->ni_chwidth;
#endif

    /* Extended capabilities */
    si->isi_ext_cap = wlan_node_get_extended_capabilities(node);
    si->isi_nss = wlan_node_get_nss(node);
    si->isi_is_256qam = wlan_node_get_256qam_support(node);

    cp = (u_int8_t *)(si+1);

    if(!wlan_node_getwpaie(vap, macaddr, ni_ie, &ni_ie_len)) {
        OS_MEMCPY(cp, ni_ie, ni_ie_len);
        cp += ni_ie_len;
        ni_ie_len = IEEE80211_MAX_OPT_IE;
    }
    if(!wlan_node_getwmeie(vap, macaddr, ni_ie, &ni_ie_len)) {
        OS_MEMCPY(cp, ni_ie, ni_ie_len);
        cp += ni_ie_len;
        ni_ie_len = IEEE80211_MAX_OPT_IE;
    }
    if(!wlan_node_getathie(vap, macaddr, ni_ie, &ni_ie_len)) {
        OS_MEMCPY(cp, ni_ie, ni_ie_len);
        cp += ni_ie_len;
        ni_ie_len = IEEE80211_MAX_OPT_IE;
    }
#ifdef ATH_WPS_IE
    if(!wlan_node_getwpsie(vap, macaddr, ni_ie, &ni_ie_len)) {
        OS_MEMCPY(cp, ni_ie, ni_ie_len);
        cp += ni_ie_len;
        ni_ie_len = IEEE80211_MAX_OPT_IE;
    }
#endif /* ATH_WPS_IE */

    req->si = (
    struct ieee80211req_sta_info *)(((u_int8_t *)si) + len);
    req->space -= len;
}
int ieee80211_ucfg_getstaspace(wlan_if_t vap)
{
    struct stainforeq req;


    /* estimate space required for station info */
    req.space = sizeof(struct stainforeq);
    req.vap = vap;
    wlan_iterate_station_list(vap, get_sta_space, &req);

    return req.space;

}
int ieee80211_ucfg_getstainfo(wlan_if_t vap, struct ieee80211req_sta_info *si, uint32_t *len)
{
    struct stainforeq req;


    if (*len < sizeof(struct ieee80211req_sta_info))
        return -EFAULT;

    /* estimate space required for station info */
    req.space = sizeof(struct stainforeq);
    req.vap = vap;

    if (*len > 0)
    {
        size_t space = *len;

        if (si == NULL)
            return -ENOMEM;

        req.si = si;
        req.space = *len;

        wlan_iterate_station_list(vap, get_sta_info, &req);
        *len = space - req.space;
    }
    else
        *len = 0;

    return 0;
}

#if ATH_SUPPORT_IQUE
int ieee80211_ucfg_rcparams_setrtparams(wlan_if_t vap, uint8_t rt_index, uint8_t per, uint8_t probe_intvl)
{
    if ((rt_index != 0 && rt_index != 1) || per > 100 ||
        probe_intvl > 100)
    {
        goto error;
    }
    wlan_set_rtparams(vap, rt_index, per, probe_intvl);
    return 0;

error:
    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "usage: rtparams rt_idx <0|1> per <0..100> probe_intval <0..100>\n");
    return -EINVAL;
}

int ieee80211_ucfg_rcparams_setratemask(wlan_if_t vap, uint8_t preamble, uint32_t mask_lower32, uint32_t mask_higher32)
{
    osif_dev *osifp = (osif_dev *)vap->iv_ifp;
    struct net_device *dev = osifp->netdev;
    struct ieee80211com *ic = vap->iv_ic;
    int retv = -EINVAL;

    if(!osifp->osif_is_mode_offload) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "This command is only supported on offload case!\n");
    } else {
        switch(preamble)
        {
            case 0:
                if (mask_lower32 > 0xFFF) {
                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Invalid ratemask for CCK/OFDM\n");
                    return retv;
                } else {
                    break;
                }
            case 1:
                /*Max mask is now 0xFFFFFFFF, no need to check*/
                break;
            case 2:
                if (mask_higher32 > 0xFF) {
                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Invalid ratemask for VHT\n");
                    return retv;
                } else {
                    break;
                }
            default:
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Invalid preamble type\n");
                return retv;
        }
        retv = ic->ic_vap_set_ratemask(vap, preamble, mask_lower32, mask_higher32);
        if (retv == ENETRESET) {
            retv = IS_UP(dev) ? osif_vap_init(dev, RESCAN) : 0;
        }
    }
    return retv;
}
#endif

#if QCA_AIRTIME_FAIRNESS
static void ieee80211_vap_iter_atf_ssid_validate(void *arg, struct ieee80211vap *vap)
{
    enum ieee80211_opmode opmode = wlan_vap_get_opmode(vap);
    struct ssid_val *atf_ssid_config = (struct ssid_val *)arg;
    ieee80211_ssid ssidlist;
    int des_nssid;

    des_nssid = wlan_get_desired_ssidlist(vap, &ssidlist, 1);
    if ( (des_nssid > 0) && (opmode == IEEE80211_M_HOSTAP) )
    {
        /* Compare VAP ssid with user provided SSID */
        if( (strlen((char *)(atf_ssid_config->ssid)) == ssidlist.len) &&
            !strncmp( (char *)(atf_ssid_config->ssid), ssidlist.ssid, strlen( (char*)atf_ssid_config->ssid)) )
        {
            atf_ssid_config->ssid_exist = 1;
        }
    }
    return;
}

int ieee80211_ucfg_setatfssid(wlan_if_t vap, struct ssid_val *val)
{
    struct ieee80211com *ic = vap->iv_ic;
    u_int8_t  i,vap_flag,firstIndex = 0xff;
    u_int8_t   num_vaps = 0, vap_index;
    u_int32_t  cumulative_vap_cfg_value = 0;

    /* Validate the SSID provided by the user
       display a message if configuration was done for a non-existing SSID
       Note that the configuration will be applied even for a non-exiting SSID
    */
    val->ssid_exist = 0;
    wlan_iterate_vap_list(ic, ieee80211_vap_iter_atf_ssid_validate ,(void *)val);
    if(!val->ssid_exist)
    {
       QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Airtime configuration applied for a non-existing SSID - %s:%d %%\n\r", val->ssid, (val->value/10));
    }

    num_vaps = ic->atfcfg_set.vap_num_cfg;
    for (vap_index = 0; (vap_index < ATF_CFG_NUM_VDEV) && (num_vaps != 0); vap_index++)
    {
        if(ic->atfcfg_set.vap[vap_index].cfg_flag)
        {
            if (strcmp((char *)(ic->atfcfg_set.vap[vap_index].essid), (char *)(val->ssid)) != 0)
            {
               cumulative_vap_cfg_value += ic->atfcfg_set.vap[vap_index].vap_cfg_value;
            }
            num_vaps--;
        }
    }
    cumulative_vap_cfg_value += val->value;
    if(cumulative_vap_cfg_value > PER_UNIT_1000)
    {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " WRONG CUMULATIVE CONFIGURATION VALUE %d, MAX VALUE IS 1000!!!!! \n", cumulative_vap_cfg_value);
        return -EFAULT;
    }


    for (i = 0, vap_flag = 0; i < ATF_CFG_NUM_VDEV; i++)
    {
        if(ic->atfcfg_set.vap[i].cfg_flag)
        {
            if (strcmp((char *)(ic->atfcfg_set.vap[i].essid), (char *)(val->ssid)) == 0)
            break;
        }else{
            if(vap_flag == 0)
            {
                firstIndex = i;
                vap_flag = 1;
            }
        }
    }

    if(i == ATF_CFG_NUM_VDEV)
    {
       if(firstIndex != 0xff)
       {
            i = firstIndex;
            OS_MEMCPY((char *)(ic->atfcfg_set.vap[i].essid),(char *)(val->ssid),strlen(val->ssid));
            ic->atfcfg_set.vap_num_cfg++;
            ic->atfcfg_set.vap[i].cfg_flag = 1;
            ic->atfcfg_set.vap[i].vap_cfg_value = val->value;
       }
       else
            printf("\n Vap number over %d vaps\n",ATF_CFG_NUM_VDEV);
    }
    else
       ic->atfcfg_set.vap[i].vap_cfg_value = val->value;

    return 0;
}

int ieee80211_ucfg_delatfssid(wlan_if_t vap, struct ssid_val *val)
{
    struct ieee80211com *ic = vap->iv_ic;
    u_int8_t  i,j;
    for (i = 0; (i < ATF_CFG_NUM_VDEV); i++)
    {
        if (ic->atfcfg_set.vap[i].cfg_flag)
        {
            if (strcmp((char *)(ic->atfcfg_set.vap[i].essid), (char *)(val->ssid)) == 0)
                break;
        }
    }
    if(i == ATF_CFG_NUM_VDEV)
    {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO," The input ssid does not exist\n");
    }else{
        memset(&(ic->atfcfg_set.vap[i].essid[0]), 0, IEEE80211_NWID_LEN+1);
        ic->atfcfg_set.vap[i].cfg_flag = 0;
        ic->atfcfg_set.vap[i].vap_cfg_value = 0;

        if((i+1)<=ic->atfcfg_set.vap_num_cfg )
        {
            for (j = 0; j < ATF_ACTIVED_MAX_CLIENTS; j++)

            {
                /* SSID at index (i+1) will be replaced with the one at last location*/
                ic->atfcfg_set.peer_id[j].sta_cfg_value[i+1] = ic->atfcfg_set.peer_id[j].sta_cfg_value[ic->atfcfg_set.vap_num_cfg];
                ic->atfcfg_set.peer_id[j].sta_cfg_value[ic->atfcfg_set.vap_num_cfg] = 0;
                /* If the peer is connected to the last SSID copy vap index as well */
                if(ic->atfcfg_set.peer_id[j].index_vap == ic->atfcfg_set.vap_num_cfg)
                {
                    ic->atfcfg_set.peer_id[j].index_vap = i+1;
                }
            }
            OS_MEMCPY((char *)&(ic->atfcfg_set.vap[i].essid[0]),(char *)(&(ic->atfcfg_set.vap[ic->atfcfg_set.vap_num_cfg-1].essid[0])),IEEE80211_NWID_LEN+1);
            ic->atfcfg_set.vap[i].cfg_flag = ic->atfcfg_set.vap[ic->atfcfg_set.vap_num_cfg-1].cfg_flag;
            ic->atfcfg_set.vap[i].vap_cfg_value = ic->atfcfg_set.vap[ic->atfcfg_set.vap_num_cfg-1].vap_cfg_value;

            memset(&(ic->atfcfg_set.vap[ic->atfcfg_set.vap_num_cfg-1].essid[0]), 0, IEEE80211_NWID_LEN+1);
            ic->atfcfg_set.vap[ic->atfcfg_set.vap_num_cfg-1].cfg_flag = 0;
            ic->atfcfg_set.vap[ic->atfcfg_set.vap_num_cfg-1].vap_cfg_value = 0;
        }
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO," SSID deleted \n");
        ic->atfcfg_set.vap_num_cfg--;
    }
    return 0;
}

int ieee80211_ucfg_setatfsta(wlan_if_t vap, struct sta_val *val)
{
    struct ieee80211com *ic = vap->iv_ic;
    u_int8_t  i,j,sta_flag,staIndex = 0xff;
    u_int64_t calbitmap;
    u_int8_t  sta_mac[IEEE80211_ADDR_LEN]={0,0,0,0,0,0};

    for (i = 0, calbitmap = 1, sta_flag = 0; i < ATF_ACTIVED_MAX_CLIENTS; i++)
    {
        if(ic->atfcfg_set.peer_id[i].cfg_flag)
        {
            if (IEEE80211_ADDR_EQ((char *)(ic->atfcfg_set.peer_id[i].sta_mac), (char *)(val->sta_mac)))
                break;
        }else{
            if (IEEE80211_ADDR_EQ((char *)(ic->atfcfg_set.peer_id[i].sta_mac), (char *)(val->sta_mac)))
            {
                ic->atfcfg_set.peer_num_cfg++;
                ic->atfcfg_set.peer_id[i].cfg_flag = 1;
                ic->atfcfg_set.peer_id[i].sta_cfg_mark = 1;
                ic->atfcfg_set.peer_cal_bitmap |= (calbitmap<<i);
                break;
            }else{
                if((sta_flag == 0)&&(IEEE80211_ADDR_EQ((char *)(ic->atfcfg_set.peer_id[i].sta_mac), (char *)sta_mac)))
                {
                    staIndex = i;
                    sta_flag = 1;
                }
            }
        }
    }


    if(i == ATF_ACTIVED_MAX_CLIENTS)
    {
        if(staIndex != 0xff)
        {
            i = staIndex;
            OS_MEMCPY((char *)(ic->atfcfg_set.peer_id[i].sta_mac),(char *)(val->sta_mac),IEEE80211_ADDR_LEN);
            ic->atfcfg_set.peer_num_cfg++;
            ic->atfcfg_set.peer_id[i].cfg_flag = 1;
            /* adding new configuration */
            if(val->ssid[0])
            {
                for (j = 0; (j < ATF_CFG_NUM_VDEV); j++)
                {
                    if (ic->atfcfg_set.vap[j].cfg_flag)
                    {
                        if (strcmp((char *)(ic->atfcfg_set.vap[j].essid), (char *)(val->ssid)) == 0)
                            break;
                    }
                }
                if(j == ATF_CFG_NUM_VDEV)
                {
                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO," The input ssid does not exist \n");
                    return -1;
                }else{
                    ic->atfcfg_set.peer_id[i].sta_cfg_value[j+1] = val->value;
                    ic->atfcfg_set.peer_id[i].index_vap = j+1;
                }
            }
            else{
                /* storing global configuration */
                ic->atfcfg_set.peer_id[i].sta_cfg_value[ATF_CFG_GLOBAL_INDEX] = val->value;
                ic->atfcfg_set.peer_id[i].index_vap = 0xff;
            }
            ic->atfcfg_set.peer_id[i].sta_cfg_mark = 1;
            ic->atfcfg_set.peer_id[i].sta_assoc_status = 0;
            ic->atfcfg_set.peer_cal_bitmap |= (calbitmap<<i);
        }
        else
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,"\n STA number over %d \n",ATF_ACTIVED_MAX_CLIENTS);
    }
    else
      /* editing already present  configuration */
        if(val->ssid[0])
        {
            for (j = 0; (j < ATF_CFG_NUM_VDEV); j++)
            {
                if (ic->atfcfg_set.vap[j].cfg_flag)
                {
                    if (strcmp((char *)(ic->atfcfg_set.vap[j].essid), (char *)(val->ssid)) == 0)
                        break;
                }
            }
            if(j == ATF_CFG_NUM_VDEV)
            {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO," The input ssid does not exist\n");
                return -1;
            }else{
                ic->atfcfg_set.peer_id[i].sta_cfg_value[j+1] = val->value;
            }
        }
        else{
            /* storing global configuration */
            ic->atfcfg_set.peer_id[i].sta_cfg_value[ATF_CFG_GLOBAL_INDEX] = val->value;
        }


    return 0;
}

int ieee80211_ucfg_delatfsta(wlan_if_t vap, struct sta_val *val)
{
    struct ieee80211com *ic = vap->iv_ic;
    u_int8_t  i, j, k;
    u_int64_t calbitmap = 1;

    for (i = 0; i < ATF_ACTIVED_MAX_CLIENTS; i++)
    {
        if (ic->atfcfg_set.peer_id[i].cfg_flag == 1)
        {
             if (IEEE80211_ADDR_EQ((char *)(ic->atfcfg_set.peer_id[i].sta_mac), (char *)(val->sta_mac)))
                break;
        }
    }

    if(i == ATF_ACTIVED_MAX_CLIENTS)
    {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " The input sta is not exist\n");
    }else{
         ic->atfcfg_set.peer_id[i].cfg_flag = 0;
         memset(&(ic->atfcfg_set.peer_id[i].sta_cfg_value[0]),0,(sizeof(ic->atfcfg_set.peer_id[i].sta_cfg_value)));
         ic->atfcfg_set.peer_num_cfg--;
         ic->atfcfg_set.peer_id[i].sta_cfg_mark = 0;
         if((ic->atfcfg_set.peer_id[i].sta_cal_value == 0 )&&(ic->atfcfg_set.peer_id[i].sta_assoc_status == 0))
          {
             for (k = 0, j = 0; k < ATF_ACTIVED_MAX_CLIENTS; k++)
             {
                 if (ic->atfcfg_set.peer_id[k].index_vap != 0)
                    j = k;
             }

             if(j == i)
             {
                 /*Delete this entry*/
                 QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,"\n last entry in table index=%d\n",j);
                 memset(&(ic->atfcfg_set.peer_id[i].sta_mac[0]),0,IEEE80211_ADDR_LEN);
                 memset(&(ic->atfcfg_set.peer_id[i].sta_cfg_value[0]),0,sizeof(ic->atfcfg_set.peer_id[i].sta_cfg_value));//flush out
                 ic->atfcfg_set.peer_id[i].sta_cal_value = 0;
                 ic->atfcfg_set.peer_id[i].sta_assoc_status = 0;
                 ic->atfcfg_set.peer_id[i].index_vap = 0;
                 ic->atfcfg_set.peer_cal_bitmap &= ~(calbitmap<<i);
             }else{
                 QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,"\n entry in table index=%d last_entry_index=%d\n",i,j);
                 ic->atfcfg_set.peer_id[i].cfg_flag = ic->atfcfg_set.peer_id[j].cfg_flag;
                 ic->atfcfg_set.peer_id[i].sta_cfg_mark = ic->atfcfg_set.peer_id[j].sta_cfg_mark;
                 ic->atfcfg_set.peer_id[i].sta_cfg_value[ic->atfcfg_set.peer_id[i].index_vap] = ic->atfcfg_set.peer_id[j].sta_cfg_value[ic->atfcfg_set.peer_id[j].index_vap];
                 ic->atfcfg_set.peer_id[i].index_vap = ic->atfcfg_set.peer_id[j].index_vap;
                 ic->atfcfg_set.peer_id[i].sta_cal_value = ic->atfcfg_set.peer_id[j].sta_cal_value;
                 ic->atfcfg_set.peer_id[i].sta_assoc_status = ic->atfcfg_set.peer_id[j].sta_assoc_status;
                 OS_MEMCPY((char *)(ic->atfcfg_set.peer_id[i].sta_mac),(char *)(ic->atfcfg_set.peer_id[j].sta_mac),IEEE80211_ADDR_LEN);
                 OS_MEMCPY((char *)(ic->atfcfg_set.peer_id[i].sta_cfg_value),(char *)(ic->atfcfg_set.peer_id[j].sta_cfg_value),sizeof(ic->atfcfg_set.peer_id[i].sta_cfg_value));
                 ic->atfcfg_set.peer_id[j].cfg_flag = 0;
                 ic->atfcfg_set.peer_id[j].sta_cfg_mark = 0;
                 memset(&(ic->atfcfg_set.peer_id[j].sta_cfg_value[0]),0,sizeof(ic->atfcfg_set.peer_id[i].sta_cfg_value));//flush out
                 memset(&(ic->atfcfg_set.peer_id[j].sta_mac[0]),0,IEEE80211_ADDR_LEN);
                 ic->atfcfg_set.peer_id[j].index_vap = 0;
                 ic->atfcfg_set.peer_id[j].sta_cal_value = 0;
                 ic->atfcfg_set.peer_id[j].sta_assoc_status = 0;
                 ic->atfcfg_set.peer_cal_bitmap &= ~(calbitmap<<j);
             }
          }
    }

    return 0;
}
#endif

struct ieee80211_uplinkinfo {
    /* Input parameters */
    struct {
        wlan_if_t      vap;
        u_int8_t       chwidth;
        u_int8_t       nss;
        u_int8_t       nss_160;
        wlan_phymode_e phymode;
        u_int8_t       essid[IEEE80211_NWID_LEN];
    } in;
    /* Output parameters */
    u_int16_t rate_estimate;
    u_int8_t  root_distance;
    u_int8_t  bssid[IEEE80211_ADDR_LEN];
    u_int8_t  otherband_bssid[IEEE80211_ADDR_LEN];
    u_int8_t  island_detected;
};

int ieee80211_rep_datarate_estimater(u_int16_t backhaul_rate,
        u_int16_t ap_rate,
        u_int8_t root_distance,
        u_int8_t scaling_factor)
{
    if(root_distance == 0)
    {
        /* Root AP, there is no STA backhaul link */
        return ap_rate;
    }
    else
    {
        int i;
        int rate;

        /* Estimate the data rate of repeater AP, (a*b)/(a+b) * (factor/100)^hopCount.
         * 64-bit by 64-bit divison can be an issue in some platform */
        rate = (backhaul_rate * ap_rate)/(backhaul_rate + ap_rate);

        for(i = 0; i < root_distance; i++)
            rate = (rate * scaling_factor)/100;

        return rate;
    }
}

int ieee80211_get_bssid_info(void *arg, wlan_scan_entry_t se)
{
    struct ieee80211_uplinkinfo *bestUL = (struct ieee80211_uplinkinfo *)arg;
    wlan_if_t vap = bestUL->in.vap;
    struct ieee80211com *ic = vap->iv_ic;
    u_int8_t se_ssid_len;
    u_int8_t *se_ssid = wlan_scan_entry_ssid(se, &se_ssid_len);
    u_int8_t *se_bssid = wlan_scan_entry_bssid(se);
    u_int8_t se_snr = wlan_scan_entry_rssi(se);
    u_int32_t se_ieee_phymode = wlan_scan_entry_phymode(se);
    struct ieee80211_ie_whc_apinfo *se_sonadv = NULL;
    u_int16_t se_uplinkrate, se_currentrate, tmprate;
    u_int8_t se_rootdistance;
    u_int8_t *se_otherband_bssid;
    u_int8_t se_nss, se_nss_160, se_nss_80p80, se_effective_nss, effective_nss, nss;
    enum ieee80211_cwm_width se_ieee_chwidth;
    wlan_chwidth_e se_chwidth, chwidth;
    wlan_phymode_e se_phymode, phymode;

    /* make sure ssid is same */
    if(se_ssid_len == 0 || OS_MEMCMP(se_ssid, bestUL->in.essid, se_ssid_len) != 0)
        return 0;

    se_sonadv = (struct ieee80211_ie_whc_apinfo *)ieee80211_scan_entry_sonie(se);
    if(se_sonadv == NULL)
        return 0;

    /* Parse and get the hop count */
    se_rootdistance = se_sonadv->whc_apinfo_root_ap_dist;
    /* Get the backhaul rate from scan entry */
    se_uplinkrate = LE_READ_2(&se_sonadv->whc_apinfo_uplink_rate);
    if((se_rootdistance == WHC_INVALID_ROOT_AP_DISTANCE)
            || (se_uplinkrate == 0))
    {
        /* Isolated Independent repeater entry, ignore it.
         * Also, If currently associated with isolated independent repeater,
         * mark it for recovery */
        if(IEEE80211_ADDR_EQ(vap->iv_bss->ni_bssid, se_bssid))
            bestUL->island_detected = 1;

        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: Ignored, rootdistance=%d uplinkrate=%d\n",
                ether_sprintf(se_bssid),
                se_rootdistance,
                se_uplinkrate);
        return 0;
    }
    /* Parse and get the uplink partner BSSID */
    if(IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan))
        se_otherband_bssid = se_sonadv->whc_apinfo_5g_bssid;
    else
        se_otherband_bssid = se_sonadv->whc_apinfo_24g_bssid;

    /* Get the NSS based on mode and extended nss support */
    wlan_scan_entry_numstreams(se, &se_nss, &se_nss_160, &se_nss_80p80);
    se_ieee_chwidth = convert_ieee_phymode_to_chwidth(se_ieee_phymode);
    if((se_ieee_chwidth == IEEE80211_CWM_WIDTH160) && se_nss_160) {
        se_effective_nss = se_nss_160;
        effective_nss    = bestUL->in.nss_160;
    }
    else if((se_ieee_chwidth == IEEE80211_CWM_WIDTH80_80) && se_nss_80p80) {
        se_effective_nss = se_nss_80p80;
        effective_nss    = bestUL->in.nss_160;
    }
    else {
        se_effective_nss = se_nss;
        effective_nss    = bestUL->in.nss;
    }

    /* Get the channel width and phymode from scan entry */
    se_phymode = convert_phymode(se_ieee_phymode);
    se_chwidth = convert_chwidth(se_ieee_chwidth);

    /* Use the minimum values of NSS, phymode and channel width
     * for calculating Rate estimate */
    nss     = QDF_MIN(se_effective_nss, effective_nss);
    phymode = QDF_MIN(se_phymode, bestUL->in.phymode);
    chwidth = QDF_MIN(se_chwidth, bestUL->in.chwidth);

    /* Current scan entry bssid rate estimate*/
    se_currentrate = ieee80211_SNRToPhyRateTablePerformLookup(vap,
            se_snr,
            nss,
            phymode,
            chwidth);

    if(se_rootdistance == 0) {
        /* Estimate the rate from RootAP beacon */
        if (vap->iv_whc_son_cap_rssi &&
                se_snr >= vap->iv_whc_son_cap_rssi) {
            tmprate = 0xffff; /* Max data rate, so cap is always preferred */
        } else {
            tmprate = se_currentrate;
        }
    } else {
        wlan_if_t tmpvap = NULL;

        /* Get the uplink BSSID from scan entry and compare it with our VAPs BSSID.
         * If it matches with any of our VAP's BSSID, discard this scan entry.
         * This will avoid unnecessary restarts by repacd */
        TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
            if (tmpvap->iv_opmode == IEEE80211_M_HOSTAP)
            {
                if (IEEE80211_ADDR_EQ(tmpvap->iv_myaddr, &se_sonadv->whc_apinfo_uplink_bssid))
                    return 0;
            }
        }

        /* Estimate the rate from repeater AP beacon */
        tmprate = ieee80211_rep_datarate_estimater(se_uplinkrate,
                se_currentrate,
                se_rootdistance,
                vap->iv_whc_scaling_factor);
    }

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: FH_snr %d FH_NSS %d BH_rate %d FH_rate %d estimate %d\n",
            ether_sprintf(se_bssid),
            se_snr,
            nss,
            se_uplinkrate,
            se_currentrate,
            tmprate);

    /* update the bssid if better than previous one */
    if(tmprate > bestUL->rate_estimate)
    {
        bestUL->rate_estimate = tmprate;
        OS_MEMCPY(bestUL->bssid, se_bssid, IEEE80211_ADDR_LEN);
        OS_MEMCPY(bestUL->otherband_bssid, se_otherband_bssid, IEEE80211_ADDR_LEN);
        bestUL->root_distance = se_rootdistance;
    }

    return 0;
}

void ieee80211_ucfg_get_phy_caps(wlan_if_t vap,
        wlan_phymode_e *phymode,
        u_int8_t *chwidth,
        u_int8_t *nss,
        u_int8_t *nss_160)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_bwnss_map nssmap = {0};
    u_int8_t rx_chainmask = ieee80211com_get_rx_chainmask(ic);

    if(vap->iv_des_mode == IEEE80211_MODE_AUTO)
    {
        if(ic->ic_modecaps & ((1 << IEEE80211_MODE_11AC_VHT20) |
                              (1 << IEEE80211_MODE_11AC_VHT40PLUS) |
                              (1 << IEEE80211_MODE_11AC_VHT40MINUS) |
                              (1 << IEEE80211_MODE_11AC_VHT40) |
                              (1 << IEEE80211_MODE_11AC_VHT80) |
                              (1 << IEEE80211_MODE_11AC_VHT160) |
                              (1 << IEEE80211_MODE_11AC_VHT80_80)))
            *phymode = wlan_phymode_vht;
        else if(ic->ic_modecaps & ((1 << IEEE80211_MODE_11NA_HT20) |
                                   (1 << IEEE80211_MODE_11NG_HT20) |
                                   (1 << IEEE80211_MODE_11NA_HT40PLUS) |
                                   (1 << IEEE80211_MODE_11NA_HT40MINUS) |
                                   (1 << IEEE80211_MODE_11NG_HT40PLUS) |
                                   (1 << IEEE80211_MODE_11NG_HT40MINUS) |
                                   (1 << IEEE80211_MODE_11NG_HT40) |
                                   (1 << IEEE80211_MODE_11NA_HT40)))
            *phymode = wlan_phymode_ht;
        else
            *phymode = wlan_phymode_basic;

        /* Find the channel width supported */
        if(ic->ic_modecaps & ((1 << IEEE80211_MODE_11AC_VHT160) |
                              (1 << IEEE80211_MODE_11AC_VHT80_80)))
            *chwidth = wlan_chwidth_160;
        else if(ic->ic_modecaps & ((1 << IEEE80211_MODE_11AC_VHT80)))
            *chwidth = wlan_chwidth_80;
        else if(ic->ic_modecaps & ((1 << IEEE80211_MODE_11AC_VHT40PLUS) |
                                   (1 << IEEE80211_MODE_11AC_VHT40MINUS) |
                                   (1 << IEEE80211_MODE_11AC_VHT40) |
                                   (1 << IEEE80211_MODE_11NA_HT40PLUS) |
                                   (1 << IEEE80211_MODE_11NA_HT40MINUS) |
                                   (1 << IEEE80211_MODE_11NG_HT40PLUS) |
                                   (1 << IEEE80211_MODE_11NG_HT40MINUS) |
                                   (1 << IEEE80211_MODE_11NG_HT40) |
                                   (1 << IEEE80211_MODE_11NA_HT40)))
            *chwidth = wlan_chwidth_40;
        else
            *chwidth = wlan_chwidth_20;
    }
    else {
        enum ieee80211_cwm_width ieee_chwidth = convert_ieee_phymode_to_chwidth(vap->iv_des_mode);

        *phymode = convert_phymode(vap->iv_des_mode);
        *chwidth = convert_chwidth(ieee_chwidth);
    }

    *nss = ieee80211_get_rxstreams(ic, vap);

    if(vap->iv_ext_nss_capable &&
           !ieee80211_get_bw_nss_mapping(vap, &nssmap, rx_chainmask))
        *nss_160 = nssmap.bw_nss_160 + 1;
    else
        *nss_160 = *nss;
}

int ieee80211_ucfg_find_best_uplink_bssid(wlan_if_t vap, char *bssid)
{
    struct ieee80211_uplinkinfo bestUL;
    struct ieee80211com *ic = vap->iv_ic;

    /* Fill the input parameters */
    OS_MEMSET(&bestUL, 0, sizeof(struct ieee80211_uplinkinfo));
    bestUL.in.vap = vap;
    OS_MEMCPY(&bestUL.in.essid, &vap->iv_des_ssid[0].ssid, vap->iv_des_ssid[0].len);
    ieee80211_ucfg_get_phy_caps(vap,
            &bestUL.in.phymode,
            &bestUL.in.chwidth,
            &bestUL.in.nss,
            &bestUL.in.nss_160);

    if(wlan_scan_table_iterate(vap, ieee80211_get_bssid_info, &bestUL) == 0)
    {
        /* If we found a BSSID other than current BSSID,
         * make sure its better than current BSSID by atleast 10% of max rate*/
        if(ieee80211_vap_ready_is_set(vap)
           && !IEEE80211_ADDR_EQ(vap->iv_bss->ni_bssid, &bestUL.bssid)
           && !bestUL.island_detected)
        {
            u_int16_t current_rate, max_rate;

            max_rate = ieee80211_ucfg_get_maxphyrate(vap) / 1000000;
            current_rate = ieee80211_rep_datarate_estimater(ic->ic_serving_ap_backhaul_rate,
                    ic->ic_uplink_rate,
                    (vap->iv_whc_root_ap_distance - 1),
                    vap->iv_whc_scaling_factor);
            if(bestUL.rate_estimate < (current_rate + (max_rate / 10)))
            {
                /* Keep currently serving AP as best bssid, populate otherband bssid as well */
                char ob_bssid[IEEE80211_ADDR_LEN] = {0, 0, 0, 0, 0, 0};
                ieee80211_ucfg_get_otherband_uplink_bssid(vap, ob_bssid);
                OS_MEMCPY(&vap->iv_ic->ic_otherband_uplink_bssid[0],
                             &ob_bssid, IEEE80211_ADDR_LEN);
                OS_MEMCPY(bssid, vap->iv_bss->ni_bssid, IEEE80211_ADDR_LEN);
                return 0;
            }
        }
        OS_MEMCPY(bssid, &bestUL.bssid, IEEE80211_ADDR_LEN);
        OS_MEMCPY(&vap->iv_ic->ic_otherband_uplink_bssid[0],
                &bestUL.otherband_bssid, IEEE80211_ADDR_LEN);
    }

    return 0;
}

int ieee80211_ucfg_get_best_otherband_uplink_bssid(wlan_if_t vap, char *bssid)
{
    OS_MEMCPY(bssid, &vap->iv_ic->ic_otherband_uplink_bssid[0], IEEE80211_ADDR_LEN);
    return 0;
}

struct ieee80211_uplinkbssid {
    wlan_if_t vap;
    u_int8_t essid[IEEE80211_NWID_LEN];
    u_int8_t bssid[IEEE80211_ADDR_LEN];
    int snr;
};

int ieee80211_get_cap_bssid(void *arg, wlan_scan_entry_t se)
{
    struct ieee80211_uplinkbssid *rootinfo = (struct ieee80211_uplinkbssid *)arg;
    u_int8_t se_ssid_len;
    u_int8_t *se_ssid = wlan_scan_entry_ssid(se, &se_ssid_len);
    u_int8_t *se_bssid = wlan_scan_entry_bssid(se);
    struct ieee80211_ie_whc_apinfo *se_sonadv = NULL;
    u_int8_t se_rootdistance, se_isrootap;

    /* make sure ssid is same */
    if(se_ssid_len == 0 || OS_MEMCMP(se_ssid, rootinfo->essid, se_ssid_len) != 0)
        return 0;

    se_sonadv = (struct ieee80211_ie_whc_apinfo *)ieee80211_scan_entry_sonie(se);
    if(se_sonadv == NULL)
        return 0;

    /* Parse and get the hop count */
    se_rootdistance = se_sonadv->whc_apinfo_root_ap_dist;
    se_isrootap = se_sonadv->whc_apinfo_is_root_ap;

    if(se_rootdistance == 0 && se_isrootap)
        OS_MEMCPY(rootinfo->bssid, se_bssid, IEEE80211_ADDR_LEN);

    return 0;
}

int ieee80211_ucfg_find_cap_bssid(wlan_if_t vap, char *bssid)
{
    struct ieee80211_uplinkbssid rootinfo;

    memset(&rootinfo, 0, sizeof(struct ieee80211_uplinkbssid));

    OS_MEMCPY(&rootinfo.essid, &vap->iv_des_ssid[0].ssid, vap->iv_des_ssid[0].len);

    if(wlan_scan_table_iterate(vap, ieee80211_get_cap_bssid, &rootinfo) == 0)
    {
        OS_MEMCPY(bssid, &rootinfo.bssid, IEEE80211_ADDR_LEN);
    }

    return 0;
}

int ieee80211_get_otherband_uplink_bssid(void *arg, wlan_scan_entry_t se)
{
    struct ieee80211_uplinkbssid *uplink = (struct ieee80211_uplinkbssid *)arg;
    wlan_if_t vap = uplink->vap;
    struct ieee80211com *ic = vap->iv_ic;
    u_int8_t se_ssid_len;
    u_int8_t *se_ssid = wlan_scan_entry_ssid(se, &se_ssid_len);
    u_int8_t *se_bssid = wlan_scan_entry_bssid(se);
    u_int8_t *se_otherband_bssid;
    struct ieee80211_ie_whc_apinfo *se_sonadv = NULL;

    /* make sure ssid is same */
    if(se_ssid_len == 0 || OS_MEMCMP(se_ssid, uplink->essid, se_ssid_len) != 0)
        return 0;

    se_sonadv = (struct ieee80211_ie_whc_apinfo *)ieee80211_scan_entry_sonie(se);
    if(se_sonadv == NULL)
        return 0;

    if(IEEE80211_ADDR_EQ(se_bssid, vap->iv_bss->ni_bssid))
    {
        /* Parse and get the uplink partner BSSID */
        if(IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan))
            se_otherband_bssid = se_sonadv->whc_apinfo_5g_bssid;
        else
            se_otherband_bssid = se_sonadv->whc_apinfo_24g_bssid;

        OS_MEMCPY(uplink->bssid, se_otherband_bssid, IEEE80211_ADDR_LEN);
    }

    return 0;
}

int ieee80211_ucfg_get_otherband_uplink_bssid(wlan_if_t vap, char *bssid)
{
    struct ieee80211_uplinkbssid uplink;

    memset(&uplink, 0, sizeof(struct ieee80211_uplinkbssid));

    uplink.vap = vap;
    OS_MEMCPY(&uplink.essid, &vap->iv_des_ssid[0].ssid, vap->iv_des_ssid[0].len);

    if(wlan_scan_table_iterate(vap, ieee80211_get_otherband_uplink_bssid, &uplink) == 0)
    {
        OS_MEMCPY(bssid, &uplink.bssid, IEEE80211_ADDR_LEN);
    }

    return 0;
}

int ieee80211_ucfg_set_otherband_bssid(wlan_if_t vap, int *val)
{
    u_int8_t *bssid = &vap->iv_ic->ic_otherband_bssid[0];

    bssid[0] = (uint8_t)((val[0] & 0xff000000) >> 24);
    bssid[1] = (uint8_t)((val[0] & 0x00ff0000) >> 16);
    bssid[2] = (uint8_t)((val[0] & 0x0000ff00) >> 8);
    bssid[3] = (uint8_t)((val[0] & 0x000000ff) >> 0);
    bssid[4] = (uint8_t)((val[1] & 0x0000ff00) >> 8);
    bssid[5] = (uint8_t)((val[1] & 0x000000ff) >> 0);

    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Otherband BSSID %x:%x:%x:%x:%x:%x\n",bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5]);

    return 0;
}

int ieee80211_ucfg_send_probereq(wlan_if_t vap, int val)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_node *ni = NULL;
    u_int8_t da[IEEE80211_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    u_int8_t bssid[IEEE80211_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    int error = 0;

    if (val) {
        if (vap->iv_opmode == IEEE80211_M_STA) {
            if ((ic->ic_strict_pscan_enable &&
                IEEE80211_IS_CHAN_PASSIVE(ic->ic_curchan))) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                    "strict passive scan enabled cant sent probe ignoring..\n");
            } else {
                ni = ieee80211_ref_bss_node(vap);
                if (ni) {
                    error = ieee80211_send_probereq(ni, vap->iv_myaddr, da,
                                bssid, ni->ni_essid, ni->ni_esslen,
                                vap->iv_opt_ie.ie, vap->iv_opt_ie.length);

                    ieee80211_free_node(ni);
                }
            }
        } else {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"VAP is not STA!\n");
            return -EINVAL;
        }
    } else {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"Value must be > 0\n");
        return -EINVAL;
    }

    if (error != 0)
        return error;

    return 0;
}

int ieee80211_get_cap_snr(void *arg, wlan_scan_entry_t se)
{
    struct ieee80211_uplinkbssid *rootinfo = (struct ieee80211_uplinkbssid *)arg;
    u_int8_t se_ssid_len;
    u_int8_t *se_ssid = wlan_scan_entry_ssid(se, &se_ssid_len);
    struct ieee80211_ie_whc_apinfo *se_sonadv = NULL;
    u_int8_t se_rootdistance, se_isrootap;

    /* make sure ssid is same */
    if(se_ssid_len == 0 || OS_MEMCMP(se_ssid, rootinfo->essid, se_ssid_len) != 0)
        return 0;

    se_sonadv = (struct ieee80211_ie_whc_apinfo *)ieee80211_scan_entry_sonie(se);
    if(se_sonadv == NULL)
        return 0;

    /* Parse and get the hop count */
    se_rootdistance = se_sonadv->whc_apinfo_root_ap_dist;
    se_isrootap = se_sonadv->whc_apinfo_is_root_ap;

    if(se_rootdistance == 0 && se_isrootap)
        rootinfo->snr = wlan_scan_entry_rssi(se);

    return 0;
}

int ieee80211_ucfg_get_cap_snr(wlan_if_t vap, int *cap_snr)
{
    struct ieee80211_uplinkbssid rootinfo;

    memset(&rootinfo, 0, sizeof(struct ieee80211_uplinkbssid));

    OS_MEMCPY(&rootinfo.essid, &vap->iv_des_ssid[0].ssid, vap->iv_des_ssid[0].len);

    if(wlan_scan_table_iterate(vap, ieee80211_get_cap_snr, &rootinfo) == 0)
    {
        *cap_snr = rootinfo.snr;
    }

    return 0;
}
