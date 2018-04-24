/*
 * =====================================================================================
 *
 *       Filename:  ssd_proto.c
 *
 *    Description:  Spectral Scan Daemon Protocol handler
 *
 *        Version:  1.0
 *        Created:  11/21/2011 02:40:38 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  S.Karthikeyan (), 
 *        Company:  Qualcomm Atheros
 *
 *        Copyright (c) 2012 Qualcomm Atheros, Inc.
 *        All Rights Reserved
 *        Qualcomm Atheros Confidential and Proprietary
 *
 * =====================================================================================
 */



#include <signal.h>
#include <unistd.h>

#include "ssd_defs.h"
#include "ssd_data.h"
#include "ssd_utils.h"
#include "ssd_interf.h"

/*
 * Function     : ssd_stop_scan
 * Description  : stop the active spectral scan
 * Input params : void
 * Return       : void
 *
 */
void ssd_stop_scan(void)
{
    system("spectraltool stopscan");
}


/*
 * Function     : ssd_update_11g_freqs
 * Description  : TODO : Need some figuring here
 * Input params :
 * Return       :
 *
 */
void ssd_update_11g_freqs(ssd_info_t *pinfo)
{
    int freq;
    ssd_config_t *pconfig = GET_CONFIG_PTR(pinfo);
    ssd_samp_info_t *psinfo = GET_SAMP_INFO_PTR(pinfo);

    freq = pconfig->current_freq;
    pconfig->current_freq = pconfig->prev_freq;
    pconfig->prev_freq    = freq;

    psinfo->num_samp_saved = 0;
    psinfo->num_samp_sent  = 0;

    pinfo->stats.alarm = 0;
    ssd_clear_max_rssi_data(pinfo);
}

/*
 * Function     : ssd_switch_channel
 * Description  : switch channel
 * Input params : pointer to ssd_info_t
 * Return       : void
 *
 */
void ssd_switch_channel(ssd_info_t* pinfo)
{
    int change_channel;
    char cmd[CMD_BUF_SIZE] = {'\0'};
    static int first = FALSE;

    ssd_samp_info_t *psinfo = GET_SAMP_INFO_PTR(pinfo);

    alarm(0);
    ualarm(0, 0);

    ssd_stop_scan();

    if (pinfo->config.change_channel) {

        ssd_update_11g_freqs(pinfo);

        if (pinfo->config.current_freq == CHANNEL_03_FREQ)
            change_channel = CHANNEL_NUM_05;

        if (pinfo->config.current_freq == CHANNEL_11_FREQ)
            change_channel = CHANNEL_NUM_13;

        /*
         * Reset interference information on start of
         * fresh channel sweep
         */
        if (change_channel == CHANNEL_NUM_05) {
            clear_11g_interf_rsp(pinfo);
        }

        /* Track the channel sweep */
        if (first && (change_channel == CHANNEL_NUM_05)) {
            pinfo->channel_sweeped = TRUE;
        } else if (change_channel == CHANNEL_NUM_05) {
            first = TRUE;
            pinfo->channel_sweeped = FALSE;
        }

        if (pinfo->channel_sweeped)
            printf("CHANNEL SWEEPED\n");

        snprintf(cmd, sizeof(cmd), "%s %1d", "iwconfig ath0 channel", change_channel);
        system(cmd);

        pinfo->stats.channel_switch++;
        psinfo->total_channel_switches++;
    }
}


/*
 * Function     : ssd_start_scan
 * Description  : start spectral scan
 * Input params : pointer to ssd_info_t
 * Return       : void
 *
 */
void ssd_start_scan(ssd_info_t *pinfo)
{
    system("spectraltool priority 1");
    system("spectraltool startscan");

    if (!pinfo->config.classify)
        alarm(SSD_ALARAM_VAL);
    else
        ualarm(SSD_USEC_ALARM_VAL, 0);
}

/*
 * Function     : ssd_handle_client_request_msg
 * Description  : handles the request messages from gui
 * Input params : pointer to ssd_info_t, pointer to req msg, length of request msg
 * Return       : 
 *
 */
u_int8_t* ssd_handle_client_request_msg(ssd_info_t *pinfo, u_int8_t *buf, int *recvd_bytes)
{

    ssd_samp_info_t *psinfo = GET_SAMP_INFO_PTR(pinfo);

    struct DATA_REQ_VAL *req_val = NULL;
    struct FREQ_BW_REQ  *bw_req  = NULL;
    struct TLV *tlv = NULL;

    int tlv_len = 0;

    int i = 0;

    /* get the pointers to TLV */
    tlv         = (struct TLV*)buf;
    tlv_len     = htons(tlv->len);
    req_val     = (struct DATA_REQ_VAL*)tlv->value;

    /* mute compiler warning */
    tlv_len     = tlv_len;

    /* debug print */
    print_tag_type(tlv);

    bw_req = (struct FREQ_BW_REQ*)req_val->data;

    for (i = 0; i < req_val->count; i++) {

        printf("Req[%d].freq = %u\n", i, bw_req->freq);
        printf("Req[%d].bw   = %s\n", i, (bw_req->bw == BW_20)?"20MHz":"40MHz");

        /*
         * TODO: understand, the design 
         *  Index 0 : holds prev frequency
         *  Index 1 : holds current frequency
         */
        if (i == 0) {
           pinfo->config.prev_freq = bw_req->freq;
        } else {
           pinfo->config.current_freq = bw_req->freq;
        }

        bw_req++;
    }

    switch (tlv->tag) {
        case SAMP_FAST_REQUEST:
            printf("ssd recvd cmd : SAMP_FAST_REQUEST\n");
            /* Config params */
            pinfo->config.classify      = 0;

            /* SAMP params */
            psinfo->num_samp_to_save    = 0;
            psinfo->num_samp_sent       = 0;
            psinfo->num_resp_reqd       = 1;

            break;
        case SAMP_CLASSIFY_REQUEST:
            printf("ssd recvd cmd : SAMP_CLASSIFY_REQUEST\n");
            /* Config params */
            pinfo->config.classify       = 1;

            /* SAMP params */
            psinfo->num_samp_to_save     = 10;
            psinfo->num_samp_sent        = 0;
            psinfo->num_resp_reqd        = 5;
            break;
        default:
            /* Config params */
            pinfo->config.classify       = 1;

            /* SAMP params */
            psinfo->num_samp_to_save     = 10;
            psinfo->num_samp_sent        = 0;
            psinfo->num_resp_reqd        = 5;
            break;
    }
    ssd_switch_channel(pinfo);
    ssd_start_scan(pinfo);

    return NULL;
}

