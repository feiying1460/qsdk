/*
 * =====================================================================================
 *
 *       Filename:  ssd_utils.c
 *
 *    Description:  SSD Utility functions
 *
 *        Version:  1.0
 *        Created:  11/25/2011 05:03:01 PM
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
 *
 * =====================================================================================
 */

#include <signal.h>
#include <unistd.h>
#include <errno.h>

#include "ssd_defs.h"
#include "ssd_proto.h"
#include "ssd_data.h"
#include "classifier.h"

/*
 * Function     : convert_rssi_to_dbm
 * Description  :
 * Input params :
 * Return       :
 *
 */
int8_t convert_rssi_to_dbm(int8_t rssi)
{
    return (rssi - 96);
}


/*
 * Function     : print_samp_info
 * Description  : print SAMP info
 * Input params : pointer to ssd_samp_info_t
 * Return       : void
 *
 */
void print_samp_info(ssd_samp_info_t *psinfo)
{
    printf("lower max rssi  = %d\n", psinfo->lower_maxrssi);
    printf("upper max rssi  = %d\n", psinfo->upper_maxrssi);
    printf("lower last ts   = %d\n", psinfo->lower_last_tstamp);
    printf("upper last ts   = %d\n", psinfo->upper_last_tstamp);
    printf("num samp saved  = %d\n", psinfo->num_samp_saved);
    printf("num samp sent   = %d\n", psinfo->num_samp_sent);
    printf("num to save     = %d\n", psinfo->num_samp_to_save);
    printf("channel switch  = %d\n", psinfo->total_channel_switches);
}


/*
 * Function     : print_tag_type
 * Description  : print tag information
 * Input params :
 * Return       :
 *
 */
void print_tag_type(struct TLV* p)
{
    switch(p->tag) {
        case SAMP_FAST_REQUEST:
            printf("SAMP Fast Request\n");
            break;
        case SAMP_RESPONSE:
            printf("SAMP Response\n");
            break;
        case SAMP_CLASSIFY_REQUEST:
            printf("SAMP Classify Request\n");
            break;
        case SAMP_REQUEST:
            printf("SAMP Request\n");
            break;
        case LAST_SAMP_TAG_TYPE:
            printf("Last Samp Tag Type\n");
            break;
        case START_SCAN:
            printf("Start Scan\n");
            break;
        case START_SCAN_RSP:
            printf("Start Scan Response\n");
            break;
        case ERROR_RSP:
            printf("Error Response\n");
            break;
        case START_FULL_SCAN:
            printf("Start Full Scan\n");
            break;
        case GET_CURRENT_CHANNEL:
            printf("Get Current Channel\n");
            break;
        case GET_CURRENT_CHANNEL_RSP:
            printf("Get Current Channel Response\n");
            break;
        default:
            printf("err: unknown type\n");
            break;
    }

}


/*
 * Function     : print_args
 * Description  : prints the current running configuration
 * Input params :
 * Return       :
 *
 */
void print_args(ssd_info_t *pinfo)
{
    ssd_config_t *p = &pinfo->config;

    printf("\n--------------------------------------------------\n");
    printf("Spectral Settings :\n" );
    printf("----------------------------------------------------\n");
    printf("raw fft         : %s\n", (get_config(p, raw_fft))?"set":"not set");
    printf("scale data      : %s\n", (get_config(p, scale))?"set":"not set");
    printf("use rssi        : %s\n", (get_config(p, use_rssi))?"set":"not set");
    printf("flip            : %s\n", (get_config(p,flip))?"set":"not set");
    printf("index data      : %s\n", (get_config(p, index_data))?"set":"not set");
    printf("only rssi       : %s\n", (get_config(p,rssi_only))?"set":"not set");
    printf("power/bin       : %s\n", (get_config(p, power_per_bin))?"set":"not set");
    printf("eacs            : %s\n", (get_config(p, eacs))?"set":"not set");
    printf("change channel  : %s\n", (get_config(p,change_channel))?"set":"not set");
    printf("classification  : %s\n", (get_config(p, classify))?"set":"not set");
    printf("atheros ui      : %s\n\n", (get_config(p, atheros_ui))?"supported":"not supported");
    printf("----------------------------------------------------\n");
    printf("power (min)     : %d\n", get_config(p, minpower));
    printf("maxhold int     : %d\n", get_config(p, maxhold_interval));
    printf("----------------------------------------------------\n");
}

