/*
 * Copyright (c) 2012 Qualcomm Atheros, Inc..
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * =====================================================================================
 *
 *       Filename:  icm_utils.c
 *
 *    Description:  Utility Functions for ICM
 *
 *        Version:  1.0
 *        Created:  05/17/2012 11:19:42 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  S.Karthikeyan (),
 *
 * =====================================================================================
 */


#include <stdio.h>
#include <icm.h>
#include <sys/time.h>
#include <errno.h>
#include "ath_classifier.h"
#include "spectral_ioctl.h"


/*
 * Function     : display_scan_db
 * Description  : Displays the contents of Scan results
 * Input params : pointer to icm
 * Return       : void
 *
 */
void icm_display_scan_db(ICM_INFO_T* picm)
{
    int i = 0;
    ICM_DEV_INFO_T* pdev = get_pdev();
    	/*
     * XXX : 5GHz frequencies are not correctly decoded
     */

    for (i = 0; i < MAX_SCAN_ENTRIES; i++) {
        if (picm->slist.elem[i].valid) {
            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL,  "Entry No    : %d\n", i);
            ICM_DPRINTF(pdev,
                        ICM_PRCTRL_FLAG_NO_PREFIX,
                        ICM_DEBUG_LEVEL_DEFAULT,
                        ICM_MODULE_ID_UTIL,
                        LINESTR);

            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL,  "\tBSSID     : %s\n", icm_ether_sprintf(picm->slist.elem[i].bssid));
            /* XXX - SSIDs need not necessarily be NULL terminated, as per standard. Handle this */
            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL,  "\tSSID      : %s\n", picm->slist.elem[i].ssid);
            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL,  "\tChannel   : %d  %s\n", picm->slist.elem[i].channel,((picm->slist.elem[i].channel == (-2))?"Invalid":"Valid"));
            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL,  "\tFrequency : %g\n", picm->slist.elem[i].freq);


            if (picm->slist.elem[i].htinfo.is_valid) {
                ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "HT Operation Info\n");

                ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tExtension Channel Offset : %d\n",
                    picm->slist.elem[i].htinfo.ext_channel_offset);
                ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tTx Channel Width         : %d\n",
                    picm->slist.elem[i].htinfo.tx_channel_width);
                ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tOBSS NoHT Present        : %d\n",
                    picm->slist.elem[i].htinfo.obss_nonht_present);
                ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tTx Burst Limit           : %d\n",
                    picm->slist.elem[i].htinfo.tx_burst_limit);
                ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tNon GF Present           : %d\n",
                    picm->slist.elem[i].htinfo.non_gf_present);
            }


            if (picm->slist.elem[i].vhtop.is_valid) {

                ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "VHT Operation Info\n");
                ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tChannel Width   : %d\n",
                    picm->slist.elem[i].vhtop.channel_width);
                ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tChannel CF Seg1 : %d\n",
                    picm->slist.elem[i].vhtop.channel_cf_seg1);
                ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tChannel CF Seg2 : %d\n",
                    picm->slist.elem[i].vhtop.channel_cf_seg2);

            }

            ICM_DPRINTF(pdev,
                        ICM_PRCTRL_FLAG_NO_PREFIX,
                        ICM_DEBUG_LEVEL_DEFAULT,
                        ICM_MODULE_ID_UTIL,
                        LINESTR);

            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL,  "\n");
        }
    }

}

/*
 * Function     : icm_ether_sprintf
 * Description  : print the mac address in user friendly string
 * Input params : pointer to address
 * Return       : const pointer to string
 *
 */
const char* icm_ether_sprintf(const uint8_t mac[6])
{
    static char buf[32];

    /* the format is done as per ntoh conversion */
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

/*
 * Function     : icm_convert_mhz2channel
 * Description  : converts MHz to IEEE channel
 * Input params : freq in MHz
 * Return       : channel number
 *
 */
int icm_convert_mhz2channel(u_int32_t freq)
{
#define IS_CHAN_IN_PUBLIC_SAFETY_BAND(_c) ((_c) > 4940 && (_c) < 4990)

    if (freq == 2484)
        return 14;
    if (freq < 2484)
        return (freq - 2407) / 5;
    if (freq < 5000) {
        if (IS_CHAN_IN_PUBLIC_SAFETY_BAND(freq)) {
            return ((freq * 10) + 
                (((freq % 5) == 2) ? 5 : 0) - 49400)/5;
        } else if (freq > 4900) {
            return (freq - 4000) / 5;
        } else {
            return 15 + ((freq - 2512) / 20);
        }
    }
    return (freq - 5000) / 5;
}

/*
 * Function     : icm_convert_ieee2mhz
 * Description  : converts IEEE channel to frequencey in MHz
 * Input params : IEEE channel
 * Return       : frequency in MHz
 */
u_int32_t icm_convert_ieee2mhz(int chan)
{
    if (chan == 14)
        return 2484;
    if (chan < 14)          /* 0-13 */
        return 2407 + chan * 5;
    if (chan < 27)          /* 15-26 */
        return 2512 + ((chan - 15) * 20);

    /* XXX Add handling of public safety band if applicable */

    return 5000 + (chan * 5);
}

void icm_display_channel_flags(ICM_CHANNEL_T* pch)
{
    ICM_DEV_INFO_T* pdev = get_pdev();
    if (IEEE80211_IS_CHAN_FHSS(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tFHSS\n");
    }

    if (IEEE80211_IS_CHAN_11NA(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t11na\n");
    } else if (IEEE80211_IS_CHAN_A(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t11a\n");
    } else if (IEEE80211_IS_CHAN_11NG(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t11ng\n");
    } else if (IEEE80211_IS_CHAN_G(pch) ||
        IEEE80211_IS_CHAN_PUREG(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t11g\n");
    } else if (IEEE80211_IS_CHAN_B(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t11b\n");
    }
    if (IEEE80211_IS_CHAN_TURBO(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tTurbo\n");
    }
    if(IEEE80211_IS_CHAN_11N_CTL_CAPABLE(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tControl capable\n");
    }
    if(IEEE80211_IS_CHAN_11N_CTL_U_CAPABLE(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tControl capable upper\n");
    }
    if(IEEE80211_IS_CHAN_11N_CTL_L_CAPABLE(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tControl capable lower\n");
    }

    if (IEEE80211_IS_CHAN_DFSFLAG(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tDFS\n");
    }

    if (IEEE80211_IS_CHAN_HALF(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tHalf\n");
    }

    if (IEEE80211_IS_CHAN_PASSIVE(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tPassive\n");
    }

    if (IEEE80211_IS_CHAN_QUARTER(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tQuarter\n");
    }
}


/*
 * Function     : icm_display_channels
 * Description  : prints supported channels
 * Input params : pointer to ICM
 * Return       : void
 *
 */
void icm_display_channels(ICM_INFO_T* picm)
{
    icm_print_chaninfo(picm, ICM_BAND_2_4G);
    icm_print_chaninfo(picm, ICM_BAND_5G);
    return ;
}

void icm_print_chaninfo(ICM_INFO_T* picm, ICM_BAND_T band)
{
    int i = 0;
    int wnw_found = 0;
    ICM_CHANNEL_LIST_T *pchlist = NULL;
    ICM_DEV_INFO_T* pdev = get_pdev();

    if (band == ICM_BAND_2_4G) {
        pchlist = &picm->chlist_bg;
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\nSupported 11BG Channels\n");
        ICM_DPRINTF(pdev,
                    ICM_PRCTRL_FLAG_NO_PREFIX,
                    ICM_DEBUG_LEVEL_DEFAULT,
                    ICM_MODULE_ID_UTIL,
                    LINESTR);
    } else {
        pchlist = &picm->chlist_a;
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\nSupported 11A Channels\n");
        ICM_DPRINTF(pdev,
            ICM_PRCTRL_FLAG_NO_PREFIX,
            ICM_DEBUG_LEVEL_DEFAULT,
            ICM_MODULE_ID_UTIL,
            LINESTR);
    }

    ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL, "total number of channels = %d\n", pchlist->count);
    for (i = 0; i < pchlist->count; i++) {
        wnw_found = icm_get_wireless_nw_in_channel(picm, pchlist->ch[i].channel);
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\nchannel : %d : Freq = %d MHz\n", pchlist->ch[i].channel, (int)pchlist->ch[i].freq);
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t- Is extension channel 20 MHz : %s\n",
           (pchlist->ch[i].used_as_secondary_20)?"Yes":"No" );
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t- Is secondary 40 MHz of 160/80+80 MHz BSS : %s\n",
           (pchlist->ch[i].used_as_160_80p80_secondary_40)?"Yes":"No" );
        if (wnw_found) {
            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t- Number of WNW %d\n", wnw_found);
        }
        icm_display_interference(pchlist->ch[i].flags);
        icm_display_channel_flags(&pchlist->ch[i]);
    }

    ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\n");

}


/*
 * Function     : icm_display_channels
 * Description  : prints supported channels
 * Input params : pointer to ICM
 * Return       : void
 *
 */
void icm_display_interference(int flags)
{
    ICM_DEV_INFO_T* pdev = get_pdev();
    if (flags & SPECT_CLASS_DETECT_MWO) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t- MWO Interfernce detected\n");
    }

    if (flags & SPECT_CLASS_DETECT_CW) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t- CW Interfernce detected\n");
    }

    if (flags & SPECT_CLASS_DETECT_WiFi) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t- WiFi Interfernce detected\n");

    }

    if (flags & SPECT_CLASS_DETECT_CORDLESS_24) {

        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t- CORDLESS 2.4GHz Interfernce detected\n");
    }

    if (flags & SPECT_CLASS_DETECT_CORDLESS_5) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t- CORDLESS 5GHz Interfernce detected\n");
    }

    if (flags & SPECT_CLASS_DETECT_BT) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t- BT Interfernce detected\n");

    }

    if (flags & SPECT_CLASS_DETECT_FHSS) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t- FHSS Interfernce detected\n");
    }


}

int icm_display_chan_properties(ICM_INFO_T* picm)
{
    int i;
    ICM_DEV_INFO_T* pdev = get_pdev();

    for (i = 0; i < MAX_NUM_CHANNELS; i++) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "%d %d : %d : %d : %d\n",
            i,
            picm->slist.chan_properties[i].cycle_count,
            picm->slist.chan_properties[i].channel_load,
            picm->slist.chan_properties[i].per,
            picm->slist.chan_properties[i].noisefloor);
    }
    return 0;
}

int icm_trim_spectral_scan_ch_list(ICM_INFO_T* picm)
{
    ICM_DEV_INFO_T* pdev = get_pdev();
    ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL, "Trimming 11BG Channels for Spectral Scan");
    picm->chlist_bg.count = 3;
    picm->chlist_bg.ch[0].channel = 1;
    picm->chlist_bg.ch[1].channel = 6;
    picm->chlist_bg.ch[2].channel = 11;
    return 0;
}


size_t os_strlcpy(char *dest, const char *src, size_t siz)
{
    const char *s = src;
    size_t left = siz;

    if (left) {
        /* Copy string up to the maximum size of the dest buffer */
        while (--left != 0) {
            if ((*dest++ = *s++) == '\0')
                break;
        }
    }

    if (left == 0) {
        /* Not enough room for the string; force NUL-termination */
        if (siz != 0)
            *dest = '\0';
        while (*s++)
            ; /* determine total src string length */
    }

    return s - src - 1;

}


void icm_print_dev_info(ICM_DEV_INFO_T* pdev)
{
    int i = 0, j = 0;
    ICM_INFO_T* picm = NULL;
    char width_str[ICM_MAX_CH_BW_STR_SIZE];
    char phy_spec_str[ICM_PHY_SPEC_STR_SIZE];

    ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL,  "server (built at %s %s)\n", __DATE__, __TIME__);
    ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL,  "daemon              : %s\n", (pdev->conf.daemon)?"enabled":"disabled");
    ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL,  "server mode         : %s\n", (pdev->conf.server_mode)?"enabled":"disabled");
    ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL,  "debug level         : %d\n", pdev->conf.dbg_level);
    ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL,  "debug module bitmap : 0x%x\n", pdev->conf.dbg_module_bitmap);
    ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL,  "socket              : %s\n", (CONFIGURED_SOCK_TYPE(pdev) == SOCK_TYPE_UDP)? "udp":"tcp");

    ICM_DPRINTF(pdev,
                ICM_PRCTRL_FLAG_NO_PREFIX,
                ICM_DEBUG_LEVEL_MAJOR,
                ICM_MODULE_ID_UTIL,
                LINESTR);

    for (i = 0; i < MAX_DEV_NUM; i++) {
        if (IS_DEV_ACTIVE(pdev, i)) {
            picm = &pdev->icm[i];
            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL,  "\n");
            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL,  "Device ID%d info\n", i);
            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL,  "radio interface     : %s\n", picm->radio_ifname);
            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL,  "device interface    : %s\n", picm->dev_ifname);
            for (j = 0; j < picm->numdevs; j++) {
                ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL, "VAP%d                : %s\n", (j+1), (char*)picm->dev_ifnames_list[j]);
            }

            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL,  "band                : %s\n", (picm->band == ICM_BAND_INVALID)?"none":((picm->band == ICM_BAND_2_4G)?"2.4GHz":"5 GHz"));
            icm_phy_spec_to_str(picm->phy_spec, phy_spec_str, sizeof(phy_spec_str));
            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL,  "PHY spec            : %s\n", phy_spec_str);
            icm_ch_bw_to_str(picm->channel_width, width_str, sizeof(width_str));
            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL,  "channel width       : %s\n", width_str);
            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL,  "default channel     : %d\n", picm->def_channel);
        }
    }
    
    ICM_DPRINTF(pdev,
            ICM_PRCTRL_FLAG_NO_PREFIX,
            ICM_DEBUG_LEVEL_MAJOR,
            ICM_MODULE_ID_UTIL,
            LINESTR);

}

int icm_get_iface_addr(ICM_DEV_INFO_T* pdev, char* ifname, u_int8_t *ifaddr)
{
    ICM_IOCSOCK_T *iocinfo = ICM_GET_ADDR_OF_IOCSOCK_INFO(pdev);
    struct ifreq ifr;

    ifr.ifr_addr.sa_family = AF_INET;
    if (strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        return FAILURE;
    }

    if (ioctl(iocinfo->sock_fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("icm : ioctl");
        return FAILURE;
    }

    memcpy(ifaddr, ifr.ifr_ifru.ifru_hwaddr.sa_data, MAX_ADDR_LEN);

    return SUCCESS;

}

int icm_phy_spec_to_str(ICM_PHY_SPEC_T physpec, char *str, int strbufflen)
{
    int status = FAILURE;

    if (str == NULL || strbufflen < ICM_PHY_SPEC_STR_SIZE) {
        return status;
    }

    switch(physpec)
    {
        case ICM_PHY_SPEC_11A:
            if (strlcpy(str, "11A", strbufflen) >= strbufflen) {
                fprintf(stderr, "src too long: %s\n", "11A");
                return FAILURE;
            }
            status = SUCCESS;
            break;

        case ICM_PHY_SPEC_11B:
            if (strlcpy(str, "11B", strbufflen) >= strbufflen) {
                fprintf(stderr, "src too long: %s\n", "11B");
                return FAILURE;
            }
            status = SUCCESS;
            break;

        case ICM_PHY_SPEC_11G:
            if (strlcpy(str, "11G", strbufflen) >= strbufflen) {
                fprintf(stderr, "src too long: %s\n", "11G");
                return FAILURE;
            }
            status = SUCCESS;
            break;

        case ICM_PHY_SPEC_FH:
            if (strlcpy(str, "FH", strbufflen) >= strbufflen) {
                fprintf(stderr, "src too long: %s\n", "FH");
                return FAILURE;
            }
            status = SUCCESS;
            break;

        case ICM_PHY_SPEC_TURBO_A:
            if (strlcpy(str, "TURBO A", strbufflen) >= strbufflen) {
                fprintf(stderr, "src too long: %s\n", "TURBO A");
                return FAILURE;
            }
            status = SUCCESS;
            break;

        case ICM_PHY_SPEC_TURBO_G:
            if (strlcpy(str, "TURBO G", strbufflen) >= strbufflen) {
                fprintf(stderr, "src too long: %s\n", "TURBO G");
                return FAILURE;
            }
            status = SUCCESS;
            break;

        case ICM_PHY_SPEC_11NA:
            if (strlcpy(str, "11NA", strbufflen) >= strbufflen) {
                fprintf(stderr, "src too long: %s\n", "11NA");
                return FAILURE;
            }
            status = SUCCESS;
            break;

        case ICM_PHY_SPEC_11NG:
            if (strlcpy(str, "11NG", strbufflen) >= strbufflen) {
                fprintf(stderr, "src too long: %s\n", "11NG");
                return FAILURE;
            }
            status = SUCCESS;
            break;

        case ICM_PHY_SPEC_11AC:
            if (strlcpy(str, "11AC", strbufflen) >= strbufflen) {
                fprintf(stderr, "src too long: %s\n", "11AC");
                return FAILURE;
            }
            status = SUCCESS;
            break;

        default:
            if (strlcpy(str, "none", strbufflen) >= strbufflen) {
                fprintf(stderr, "src too long: %s\n", "none");
                return FAILURE;
            }
            status = FAILURE;
            /* Failure */
            break;
    }
    str[strbufflen-1] = '\0';
    return status;
}

int icm_ch_bw_to_str(ICM_CH_BW_T bw, char *str, int strbufflen)
{
    int status = FAILURE;

    if (str == NULL || strbufflen < ICM_MAX_CH_BW_STR_SIZE) {
        return status;
    }

    switch(bw)
    {
        case ICM_CH_BW_20:
            if (strlcpy(str, "20", strbufflen) >= strbufflen) {
                fprintf(stderr, "src too long: %s\n", "20");
                return FAILURE;
            }
            status = SUCCESS;
            break;

        case ICM_CH_BW_40MINUS:
            if (strlcpy(str, "40MINUS", strbufflen) >= strbufflen) {
                fprintf(stderr, "src too long: %s\n", "40MINUS");
                return FAILURE;
            }
            status = SUCCESS;
            break;

        case ICM_CH_BW_40PLUS:
            if (strlcpy(str, "40PLUS", strbufflen) >= strbufflen) {
                fprintf(stderr, "src too long: %s\n", "40PLUS");
                return FAILURE;
            }
            status = SUCCESS;
            break;

        case ICM_CH_BW_40:
            if (strlcpy(str, "40", strbufflen) >= strbufflen) {
                fprintf(stderr, "src too long: %s\n", "40");
                return FAILURE;
            }
            status = SUCCESS;
            break;

        case ICM_CH_BW_80:
            if (strlcpy(str, "80", strbufflen) >= strbufflen) {
                fprintf(stderr, "src too long: %s\n", "80");
                return FAILURE;
            }
            status = SUCCESS;
            break;

        case ICM_CH_BW_160:
            if (strlcpy(str, "160", strbufflen) >= strbufflen) {
                fprintf(stderr, "src too long: %s\n", "160");
                return FAILURE;
            }
            status = SUCCESS;
            break;

        case ICM_CH_BW_80_PLUS_80:
            if (strlcpy(str, "80+80", strbufflen) >= strbufflen) {
                fprintf(stderr, "src too long: %s\n", "80+80");
                return FAILURE;
            }
            status = SUCCESS;
            break;

        default:
            if (strlcpy(str, "none", strbufflen) >= strbufflen) {
                fprintf(stderr, "src too long: %s\n", "none");
                return FAILURE;
            }
            status = FAILURE;
            /* Failure */
            break;
    }
    str[strbufflen-1] = '\0';
    return status;
}

/* XXX: Though the integer parameters we require as at present are all >=0,
        we should change the radio and vap get int function signatures
        below to factor in the fact that signed integers are being returned
        and error values shouldn't collide with valid param values. */

/*
 * Function     : get_radio_priv_int_param
 * Description  : Get a radio-private integer parameter
 * Input params : pointer to pdev info, radio interface name, required parameter
 * Return       : On success: Value of parameter
 *                On error  : -1
 */
int get_radio_priv_int_param(ICM_DEV_INFO_T* pdev, const char *ifname, int param)
{
    struct iwreq iwr;
    ICM_IOCSOCK_T *iocinfo = ICM_GET_ADDR_OF_IOCSOCK_INFO(pdev);

    memset(&iwr, 0, sizeof(iwr));
    if (strlcpy(iwr.ifr_name, ifname, IFNAMSIZ) >= IFNAMSIZ) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        return -1;
    }
    iwr.u.mode = param | ATH_PARAM_SHIFT;
    if (ioctl(iocinfo->sock_fd, ATH_IOCTL_GETPARAM, &iwr) < 0) {
        perror("ATH_IOCTL_GETPARAM");
        return -1;
    }

    return iwr.u.param.value;
}

/*
 * Function     : get_vap_priv_int_param
 * Description  : Return private parameter of the given VAP from driver.
 * Input params : const char pointer pointing to interface name and required parameter
 * Return       : Success: value of the private param
 *                Failure: -1
 *
 */
int get_vap_priv_int_param(ICM_DEV_INFO_T* pdev,
                           const char *ifname,
                           int param)
{
    ICM_IOCSOCK_T *iocinfo = ICM_GET_ADDR_OF_IOCSOCK_INFO(pdev);
    struct iwreq iwr;

    memset(&iwr, 0, sizeof(iwr));
    if (strlcpy(iwr.ifr_name, ifname, IFNAMSIZ) >= IFNAMSIZ) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        return -1;
    }
    iwr.u.mode = param;

    if (ioctl(iocinfo->sock_fd, IEEE80211_IOCTL_GETPARAM, &iwr) < 0) {
        perror("IEEE80211_IOCTL_GETPARAM");
        return -1;
    }
	/* returns value of the VAP private param(eg. phy spec channel width )*/
    return iwr.u.param.value;
}

/*
 * Function     : set_vap_priv_int_param
 * Description  : Set a device-private integer parameter
 * Input params : pointer to pdev info, device interface name, parameter,
 *                value.
 * Return       : On success: 0
 *                On error  : -1
 */
int set_vap_priv_int_param(ICM_DEV_INFO_T* pdev,
                              const char *ifname,
                              int param,
                              int32_t val)
{
    struct iwreq iwr;
    ICM_IOCSOCK_T *iocinfo = ICM_GET_ADDR_OF_IOCSOCK_INFO(pdev);

    memset(&iwr, 0, sizeof(iwr));
    if (strlcpy(iwr.ifr_name, ifname, IFNAMSIZ) >= IFNAMSIZ) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        return -1;
    }
    iwr.u.mode = param;
    memcpy(iwr.u.name + sizeof(int32_t), &val, sizeof(val));

    if (ioctl(iocinfo->sock_fd, IEEE80211_IOCTL_SETPARAM, &iwr) < 0) {
        perror("IEEE80211_IOCTL_SETPARAM");
        return -1;
    }

    return 0;
}

/*
 * Function     : is_11ac_offload
 * Description  : Return whether the radio referred to in picm
 *                is an 11ac offload radio.
 * Input params : Pointer to icm data structure
 * Return       : On success: 1 (Offload) or 0 (Direct Attach)
 *                On error  : -1
 */
int is_11ac_offload(ICM_INFO_T* picm)
{
    return get_radio_priv_int_param(get_pdev(),
                                    picm->radio_ifname,
                                    OL_ATH_PARAM_GET_IF_ID);
}

/*
 * Function     : icm_get_emiwar80p80
 * Description  : Return whether 80+80 EMI WAR is disabled,Skip only Bandedge or Skip All FC1>FC2
 * Input params : Pointer to icm data structure
 * Return       : On success: 2(Skip All FC1>FC2) 1 (Skip only BandEdge) or 0 (Not enabled)
 *                On error  : -1
 */
int icm_get_emiwar80p80(ICM_INFO_T* picm)
{
    return get_radio_priv_int_param(get_pdev(),
                                    picm->radio_ifname,
                                    OL_ATH_PARAM_EMIWAR_80P80);
}

/*
 * Function     : icm_compose_phymode_str
 * Description  : Compose complete PHY mode string from PHY Spec
 *                and channel width.
 * Input params : ICM enumeration for PHY Spec,
 *                ICM enumeration for Width,
 *                Address of char buffer into which string giving
 *                PHY mode should be passed, length of char buffer.
 * Return       : On success: String giving PHY mode. Uses address
 *                passed.
 *                On error  : NULL
 */
char* icm_compose_phymode_str(ICM_PHY_SPEC_T physpec,
                              ICM_CH_BW_T width,
                              char *phymode,
                              int phymodelen)
{
    int cont = 0;  /* Whether to proceed to next step */

    if (phymode == NULL)
    {
        err("%s: NULL char buffer passed", __func__);
        return NULL;
    }

    if (phymodelen < ICM_MAX_PHYMODE_STR_SIZE) {
        err("%s: Insufficient char buffer length %d", __func__, phymodelen);
        return NULL;
    }

    memset(phymode, 0, phymodelen);

    /* Note:
       - We do not currently support "11AST"
       - 160 and 80+80 support not added since corresponding
         PHY mode strings not defined at this time. */

    switch(physpec)
    {
        case ICM_PHY_SPEC_11A:
            if (strlcpy(phymode, "11A", phymodelen) >= phymodelen) {
                fprintf(stderr, "src too long: %s\n", "11A");
                return NULL;
            }
            break;

        case ICM_PHY_SPEC_11B:
            if (strlcpy(phymode, "11B", phymodelen) >= phymodelen) {
                fprintf(stderr, "src too long: %s\n", "11B");
                return NULL;
            }
            break;

        case ICM_PHY_SPEC_11G:
            if (strlcpy(phymode, "11G", phymodelen) >= phymodelen) {
                fprintf(stderr, "src too long: %s\n", "11G");
                return NULL;
            }
            break;

        case ICM_PHY_SPEC_FH:
            if (strlcpy(phymode, "FH", phymodelen) >= phymodelen) {
                fprintf(stderr, "src too long: %s\n", "FH");
                return NULL;
            }
            break;

        case ICM_PHY_SPEC_TURBO_A:
            if (strlcpy(phymode, "TA", phymodelen) >= phymodelen) {
                fprintf(stderr, "src too long: %s\n", "TA");
                return NULL;
            }
            break;

        case ICM_PHY_SPEC_TURBO_G:
            if (strlcpy(phymode, "TG", phymodelen) >= phymodelen) {
                fprintf(stderr, "src too long: %s\n", "TG");
                return NULL;
            }
            break;

        case ICM_PHY_SPEC_11NA:
            if (strlcpy(phymode, "11NAHT", phymodelen) >= phymodelen) {
                fprintf(stderr, "src too long: %s\n", "11NAHT");
                return NULL;
            }
            cont = 1;
            break;

        case ICM_PHY_SPEC_11NG:
            if (strlcpy(phymode, "11NGHT", phymodelen) >= phymodelen) {
                fprintf(stderr, "src too long: %s\n", "11NGHT");
                return NULL;
            }
            cont = 1;
            break;

        case ICM_PHY_SPEC_11AC:
            if (strlcpy(phymode, "11ACVHT", phymodelen) >= phymodelen) {
                fprintf(stderr, "src too long: %s\n", "11ACVHT");
                return NULL;
            }
            cont = 1;
            break;

        case ICM_PHY_SPEC_INVALID:
            err("%s: Invalid PHY spec enumeration %d", __func__, physpec);
            return NULL;
    }

    if (!cont) {
       return phymode;
    }
    phymode[phymodelen - 1] = '\0';

    switch (width)
    {
        case ICM_CH_BW_20:
            if (strlcat(phymode, "20", phymodelen) >= phymodelen) {
                fprintf(stderr, "src too long: %s\n", "20");
                return NULL;
            }
            break;

        case ICM_CH_BW_40MINUS:
            if (strlcat(phymode, "40MINUS", phymodelen) >= phymodelen) {
                fprintf(stderr, "src too long: %s\n", "40MINUS");
                return NULL;
            }
            break;

        case ICM_CH_BW_40PLUS:
            if (strlcat(phymode, "40PLUS", phymodelen) >= phymodelen) {
                fprintf(stderr, "src too long: %s\n", "40PLUS");
                return NULL;
            }
            break;

        case ICM_CH_BW_40:
            if (strlcat(phymode, "40", phymodelen) >= phymodelen) {
                fprintf(stderr, "src too long: %s\n", "40");
                return NULL;
            }
            break;

        case ICM_CH_BW_80:
            if (physpec != ICM_PHY_SPEC_11AC) {
                err("%s: Invalid PHY spec enumeration %d with width 80 MHz",
                    __func__,
                    physpec);
                return NULL;
            }
            if (strlcat(phymode, "80", phymodelen) >= phymodelen) {
                fprintf(stderr, "src too long: %s\n", "80");
                return NULL;
            }
            break;

        case ICM_CH_BW_160:
            if (physpec != ICM_PHY_SPEC_11AC) {
                err("%s: Invalid PHY spec enumeration %d with width 160 MHz",
                    __func__,
                    physpec);
                return NULL;
            }
            if (strlcat(phymode, "160", phymodelen) >= phymodelen) {
                fprintf(stderr, "src too long: %s\n", "160");
                return NULL;
            }
            break;

        case ICM_CH_BW_80_PLUS_80:
            if (physpec != ICM_PHY_SPEC_11AC) {
                err("%s: Invalid PHY spec enumeration %d with width 80+80 MHz",
                    __func__,
                    physpec);
                return NULL;
            }

            if (strlcat(phymode, "80_80", phymodelen) >= phymodelen) {
                fprintf(stderr, "src too long: %s\n", "80_80");
                return NULL;
            }
            break;

        case ICM_CH_BW_INVALID:
            err("%s: Invalid width enumeration %d", __func__, width);
            return NULL;
    }

    phymode[phymodelen - 1] = '\0';
    return phymode;
}

/*
 * Function     : icm_is_modulebitmap_valid
 * Description  : Determine if string giving module bitmap
 *                is valid. It is the caller's responsibility
 *                to ensure that the string is NULL terminated.
 * Input params : String giving module bitmap.
 * Return       : true if valid, false if invalid
 */
bool icm_is_modulebitmap_valid(const char* bitmapstr)
{
    long val = 0;

    val = strtol(bitmapstr, NULL, 0);

    if (errno != 0) {
        return false;
    }
    
    if (val < 0 || val > ICM_MODULE_ID_ALL) {
        return false;
    }
    
    return true;
}

/*
 * Function     : icm_is_debuglevel_valid
 * Description  : Determine if string giving debug level
 *                is valid. It is the caller's responsibility
 *                to ensure that the string is NULL terminated.
 * Input params : String giving debug level.
 * Return       : true if valid, false if invalid
 */
bool icm_is_debuglevel_valid(const char* dgblevelstr)
{
    long val = 0;

    val = strtol(dgblevelstr, NULL, 0);

    if (errno != 0) {
        return false;
    }

    if (val <= 0 || val >= ICM_DEBUG_LEVEL_INVALID) {
        return false;
    }
    
    return true;
}

/*
 * Function     : icm_get_channel_width
 * Description  : Get current channel width from driver
 * Input params : pointer to icm info structure
 * Return       : Channel width on success
 *                IEEE80211_CWM_WIDTHINVALID on failure
 */
enum ieee80211_cwm_width icm_get_channel_width(ICM_INFO_T* picm)
{
    enum ieee80211_cwm_width ch_width = 0;
    struct ifreq ifr;
    ICM_DEV_INFO_T* pdev = get_pdev();
    ICM_NLSOCK_T *pnlinfo = ICM_GET_ADDR_OF_NLSOCK_INFO(pdev);
    ICM_SPECTRAL_INFO_T *psinfo = NULL;

    if (picm == NULL) {
        err("icm: ICM Information structure is invalid");
        return IEEE80211_CWM_WIDTHINVALID;
    }

    psinfo = &picm->sinfo;
    psinfo->atd.ad_id = SPECTRAL_GET_CHAN_WIDTH | ATH_DIAG_DYN;
    psinfo->atd.ad_in_data = NULL;
    psinfo->atd.ad_in_size = 0;
    psinfo->atd.ad_out_data = (void*)&ch_width;
    psinfo->atd.ad_out_size = sizeof(u_int32_t);
    
    if (strlcpy(ifr.ifr_name, psinfo->atd.ad_name, IFNAMSIZ) >= IFNAMSIZ) {
        fprintf(stderr, "ad_name too long: %s\n", psinfo->atd.ad_name);
        ch_width = IEEE80211_CWM_WIDTHINVALID;
        return ch_width;
    }
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    ifr.ifr_data = (caddr_t)&psinfo->atd.ad_name;

    if (ioctl(pnlinfo->sock_fd, SIOCGATHPHYERR, &ifr) < 0) {
        ch_width = IEEE80211_CWM_WIDTHINVALID;
        perror("icm: SIOCGATHPHYERR ioctl fail (SPECTRAL_GET_CHAN_WIDTH)");
    }

    return ch_width;
}

/*
 * Function     : icm_get_channel_index
 * Description  : Find index of a given channel, in channel list
 * Input params : -pointer to channel list
 *                -IEEE channel number for which the index is required. It is
 *                the responsibility of the calling function (or function stack)
 *                to ensure this is valid.
 * Return       : Index of channel in list on success, or -1 on failure.
 */
int icm_get_channel_index(ICM_CHANNEL_LIST_T *pchlist, u_int32_t channel)
{
    int chn_idx = 0;

    for(chn_idx = 0; chn_idx < pchlist->count; chn_idx++) {
        if (pchlist->ch[chn_idx].channel == channel) {
            return chn_idx;
        }
    }

    return -1;
}

