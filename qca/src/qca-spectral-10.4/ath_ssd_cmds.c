/*
 * Copyright (c) 2014 Qualcomm Atheros, Inc..
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * =====================================================================================
 *
 *       Filename:  ath_ssd_cmds.c
 *
 *    Description:  Spectral Scan commands (IOCTLs)
 *
 *        Version:  1.0
 *       Revision:  none
 *       Compiler:  gcc
 *
 * =====================================================================================
 */


#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <netdb.h>
#include <net/if.h>

#include "if_athioctl.h"
#define  _LINUX_TYPES_H
#include "ath_classifier.h"
#include "spectral_ioctl.h"
#include "ath_ssd_defs.h"
#include "spectral_data.h"
#include "spec_msg_proto.h"
#include "spectral.h"

#ifndef ATH_DEFAULT
#define ATH_DEFAULT "wifi0"
#endif

/*
 * Function     : ath_ssd_init_spectral
 * Description  : initialize spectral related info
 * Input params : pointer to ath_ssd_info_t info structrue
 * Return       : success/failure
 *
 */
int ath_ssd_init_spectral(ath_ssd_info_t* pinfo)
{
    int err = SUCCESS;
    ath_ssd_spectral_info_t* psinfo = &pinfo->sinfo;

    if (pinfo->radio_ifname == NULL)
        return -EINVAL;

    if (strlcpy(psinfo->atd.ad_name, pinfo->radio_ifname, sizeof(psinfo->atd.ad_name)) >= sizeof(psinfo->atd.ad_name)) {
        fprintf(stderr, "radio_ifname too long: %s\n", pinfo->radio_ifname);
        return FAILURE;
    }

    return err;
}


/*
 * Function     : start_spectral_scan
 * Description  : start the spectrla scan on current channel
 * Input params : pointer to icm info structrue
 * Return       : success/failure
 *
 */
int ath_ssd_start_spectral_scan(ath_ssd_info_t* pinfo)
{
    u_int32_t status = SUCCESS;
    struct ifreq ifr;
    ath_ssd_nlsock_t *pnlinfo = GET_ADDR_OF_NLSOCKINFO(pinfo);

    ath_ssd_spectral_info_t* psinfo = &pinfo->sinfo;

    psinfo->atd.ad_id = SPECTRAL_ACTIVATE_SCAN | ATH_DIAG_DYN;
    psinfo->atd.ad_in_data = NULL;
    psinfo->atd.ad_in_size = 0;
    psinfo->atd.ad_out_data = (void*)&status;
    psinfo->atd.ad_out_size = sizeof(u_int32_t);
    if (strlcpy(ifr.ifr_name, psinfo->atd.ad_name, sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name)) {
        fprintf(stderr, "ad_name too long: %s\n", psinfo->atd.ad_name);
        return FAILURE;
    }
    ifr.ifr_data = (caddr_t)&psinfo->atd.ad_name;

    if (ioctl(pnlinfo->spectral_fd, SIOCGATHPHYERR, &ifr) < 0) {
        status = FAILURE;
        perror("ioctl fail");
    }

    return status;
}

/*
 * Function     : stop_spectral_scan
 * Description  : stop the spectrla scan on current channel
 * Input params : pointer to icm info structrue
 * Return       : success/failure
 *
 */
int ath_ssd_stop_spectral_scan(ath_ssd_info_t* pinfo)
{
    u_int32_t status = SUCCESS;
    struct ifreq ifr;

    ath_ssd_spectral_info_t* psinfo = &pinfo->sinfo;
    ath_ssd_nlsock_t *pnlinfo = GET_ADDR_OF_NLSOCKINFO(pinfo);

    /* XXX : We should set priority to 0 */

    psinfo->atd.ad_id = SPECTRAL_STOP_SCAN | ATH_DIAG_DYN;
    psinfo->atd.ad_in_data = NULL;
    psinfo->atd.ad_in_size = 0;
    psinfo->atd.ad_out_data = (void*)&status;
    psinfo->atd.ad_out_size = sizeof(u_int32_t);
    if (strlcpy(ifr.ifr_name, psinfo->atd.ad_name, sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name)) {
        fprintf(stderr, "ad_name too long: %s\n", psinfo->atd.ad_name);
        return FAILURE;
    }
    ifr.ifr_data = (caddr_t)&psinfo->atd.ad_name;

    if (ioctl(pnlinfo->spectral_fd, SIOCGATHPHYERR, &ifr) < 0) {
        status = FAILURE;
        perror("ioctl fail");
    }

    return status;
}

/*
 * Function     : set_spectral_param
 * Description  : set spectral param
 * Input params : pointer to icm info structrue
 * Return       : success/failure
 *
 */
int ath_ssd_set_spectral_param(ath_ssd_info_t* pinfo, int op, int param)
{
    int status = SUCCESS;
    SPECTRAL_PARAMS_T sp;
    struct ifreq ifr;
    ath_ssd_nlsock_t *pnlinfo = GET_ADDR_OF_NLSOCKINFO(pinfo);
    ath_ssd_spectral_info_t* psinfo = &pinfo->sinfo;

    ath_ssd_get_spectral_param(pinfo, &sp);

    switch(op) {
        case SPECTRAL_PARAM_FFT_PERIOD:
            sp.ss_fft_period = param;
            break;
        case SPECTRAL_PARAM_SCAN_PERIOD:
            sp.ss_period = param;
            break;
        case SPECTRAL_PARAM_SHORT_REPORT:
            {
                if (param) {
                    sp.ss_short_report = 1;
                } else {
                    sp.ss_short_report = 0;
                }
            }
            break;
        case SPECTRAL_PARAM_SCAN_COUNT:
            sp.ss_count = param;
            break;

        case SPECTRAL_PARAM_SPECT_PRI:
            sp.ss_spectral_pri = (!!param) ? true:false;
            break;

        case SPECTRAL_PARAM_FFT_SIZE:
            sp.ss_fft_size = param;
            break;

        case SPECTRAL_PARAM_GC_ENA:
            sp.ss_gc_ena = !!param;
            break;

        case SPECTRAL_PARAM_RESTART_ENA:
            sp.ss_restart_ena = !!param;
            break;

        case SPECTRAL_PARAM_NOISE_FLOOR_REF:
            sp.ss_noise_floor_ref = param;
            break;

        case SPECTRAL_PARAM_INIT_DELAY:
            sp.ss_init_delay = param;
            break;

        case SPECTRAL_PARAM_NB_TONE_THR:
            sp.ss_nb_tone_thr = param;
            break;

        case SPECTRAL_PARAM_STR_BIN_THR:
            sp.ss_str_bin_thr = param;
            break;

        case SPECTRAL_PARAM_WB_RPT_MODE:
            sp.ss_wb_rpt_mode = !!param;
            break;

        case SPECTRAL_PARAM_RSSI_RPT_MODE:
            sp.ss_rssi_rpt_mode = !!param;
            break;

        case SPECTRAL_PARAM_RSSI_THR:
            sp.ss_rssi_thr = param;
            break;

        case SPECTRAL_PARAM_PWR_FORMAT:
            sp.ss_pwr_format = !!param;
            break;

        case SPECTRAL_PARAM_RPT_MODE:
            sp.ss_rpt_mode = param;
            break;

        case SPECTRAL_PARAM_BIN_SCALE:
            sp.ss_bin_scale = param;
            break;

        case SPECTRAL_PARAM_DBM_ADJ:
            sp.ss_dBm_adj = !!param;
            break;

        case SPECTRAL_PARAM_CHN_MASK:
            sp.ss_chn_mask = param;
            break;
    }

    psinfo->atd.ad_id = SPECTRAL_SET_CONFIG | ATH_DIAG_IN;
    psinfo->atd.ad_out_data = NULL;
    psinfo->atd.ad_out_size = 0;
    psinfo->atd.ad_in_data = (void *) &sp;
    psinfo->atd.ad_in_size = sizeof(SPECTRAL_PARAMS_T);
    if (strlcpy(ifr.ifr_name, psinfo->atd.ad_name, sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name)) {
        fprintf(stderr, "ad_name too long: %s\n", psinfo->atd.ad_name);
        return FAILURE;
    }
    ifr.ifr_data = (caddr_t) &psinfo->atd;

    if (ioctl(pnlinfo->spectral_fd, SIOCGATHPHYERR, &ifr) < 0) {
        status = FAILURE;
    }

    return status;
}

void ath_ssd_get_spectral_param(ath_ssd_info_t* pinfo, SPECTRAL_PARAMS_T* sp)
{

    struct ifreq ifr;
    ath_ssd_nlsock_t *pnlinfo = GET_ADDR_OF_NLSOCKINFO(pinfo);
    ath_ssd_spectral_info_t* psinfo = &pinfo->sinfo;

    psinfo->atd.ad_id = SPECTRAL_GET_CONFIG | ATH_DIAG_DYN;
    psinfo->atd.ad_out_data = (void *)sp;
    psinfo->atd.ad_out_size = sizeof(SPECTRAL_PARAMS_T);
    if (strlcpy(ifr.ifr_name, psinfo->atd.ad_name, sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name)) {
        fprintf(stderr, "ad_name too long: %s\n", psinfo->atd.ad_name);
        return;
    }
    ifr.ifr_data = (caddr_t)&psinfo->atd;

    if (ioctl(pnlinfo->spectral_fd, SIOCGATHPHYERR, &ifr) < 0) {
        return;
    }
}

/*
 * Function     : get_channel_width
 * Description  : Get current channel width from driver
 * Input params : pointer to icm info structrue
 * Return       : success/failure
 *
 */
int get_channel_width(ath_ssd_info_t* pinfo)
{
    u_int32_t ch_width = 0;
    struct ifreq ifr;
    ath_ssd_nlsock_t *pnlinfo = GET_ADDR_OF_NLSOCKINFO(pinfo);

    ath_ssd_spectral_info_t* psinfo = &pinfo->sinfo;

    psinfo->atd.ad_id = SPECTRAL_GET_CHAN_WIDTH | ATH_DIAG_DYN;
    psinfo->atd.ad_in_data = NULL;
    psinfo->atd.ad_in_size = 0;
    psinfo->atd.ad_out_data = (void*)&ch_width;
    psinfo->atd.ad_out_size = sizeof(u_int32_t);
    if (strlcpy(ifr.ifr_name, psinfo->atd.ad_name, sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name)) {
        fprintf(stderr, "ad_name too long: %s\n", psinfo->atd.ad_name);
        ch_width = IEEE80211_CWM_WIDTHINVALID;
        return ch_width;
    }
    ifr.ifr_data = (caddr_t)&psinfo->atd.ad_name;

    if (ioctl(pnlinfo->spectral_fd, SIOCGATHPHYERR, &ifr) < 0) {
        ch_width = IEEE80211_CWM_WIDTHINVALID;
        perror("ioctl fail");
    }
    return ch_width;
}

/*
 * Function     : ath_ssd_is_advncd_spectral
 * Description  : Return whether advanced spectral capability
 *                (as on 11ac chipsets) is available on the
 *                given radio interface
 * Input params : pointer to ath_ssd_info_t
 * Output params: whether advanced spectral capability is
 *                available, filled into pointer to boolean
 *                passed
 * Return       : SUCCESS/FAILURE
 *
 */
int ath_ssd_is_advncd_spectral(ath_ssd_info_t* pinfo, bool *is_advanced)
{
    struct ifreq ifr;
    struct ath_spectral_caps caps;
    ath_ssd_nlsock_t *pnlinfo = GET_ADDR_OF_NLSOCKINFO(pinfo);
    ath_ssd_spectral_info_t* psinfo = &pinfo->sinfo;

    memset(&caps, 0, sizeof(caps));

    psinfo->atd.ad_id = SPECTRAL_GET_CAPABILITY_INFO | ATH_DIAG_DYN;
    psinfo->atd.ad_out_data = (void *)&caps;
    psinfo->atd.ad_out_size = sizeof(struct ath_spectral_caps);
    if (strlcpy(ifr.ifr_name, psinfo->atd.ad_name, sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name)) {
        fprintf(stderr, "ad_name too long: %s\n", psinfo->atd.ad_name);
        return FAILURE;
    }
    ifr.ifr_data = (caddr_t)&psinfo->atd;

    if (ioctl(pnlinfo->spectral_fd, SIOCGATHPHYERR, &ifr) < 0) {
        perror("ioctl fail");
        return FAILURE;
    }

    if (caps.advncd_spectral_cap) {
        *is_advanced = true;
    } else {
        *is_advanced = false;
    }

    return SUCCESS;
}

