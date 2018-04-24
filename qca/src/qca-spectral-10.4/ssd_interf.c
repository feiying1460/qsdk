/*
 * =====================================================================================
 *
 *       Filename:  ssd_interf.c
 *
 *    Description:  Interference related processing for Spectral Scan
 *
 *        Version:  1.0
 *        Created:  11/28/2011 07:15:51 PM
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

#include "ssd_defs.h"
#include "ssd_interf.h"

void update_11g_interf_detection(ssd_info_t *pinfo)
{
    update_11g_interf(pinfo, &pinfo->lwrband);
    update_11g_interf(pinfo, &pinfo->uprband);
}


void clear_11g_interf_rsp(ssd_info_t* pinfo)
{
    int i = 0;

    /*
     * We want to clear up the interference reports
     * once every sweep of the spectrum on the GUI.
     * This is once every two channel changes
     */
    pinfo->interf_count = 0;

    for (i = 0; i < MAX_INTERF_COUNT; i++) {
          pinfo->interf_rsp[i].interf_type = INTERF_NONE;
          pinfo->interf_rsp[i].interf_min_freq = 0;
          pinfo->interf_rsp[i].interf_max_freq = 0;
    }
}

int update_11g_interf(ssd_info_t *pinfo, struct ss *bd)
{
    int interf_count = pinfo->interf_count;
    struct INTERF_RSP *interf_rsp = NULL;
    int num_types_detected = 0;

    if (bd->count_mwo) {
        interf_rsp = &pinfo->interf_rsp[INTERF_MW];
        interf_rsp->interf_min_freq = (bd->mwo_min_freq/1000);
        interf_rsp->interf_max_freq = (bd->mwo_max_freq/1000);
        interf_rsp->interf_type = INTERF_MW;
        num_types_detected++;
    }

    if (bd->count_bts) {
        interf_rsp = &pinfo->interf_rsp[INTERF_BT];
        interf_rsp->interf_min_freq = (bd->bts_min_freq/1000);
        interf_rsp->interf_max_freq = (bd->bts_max_freq/1000);
        interf_rsp->interf_type = INTERF_BT;
        num_types_detected++;
    }

    if(bd->count_cph) {
        interf_rsp = &pinfo->interf_rsp[INTERF_DECT];
        interf_rsp->interf_min_freq = (bd->cph_min_freq/1000);
        interf_rsp->interf_max_freq = (bd->cph_max_freq/1000);
        interf_rsp->interf_type = INTERF_DECT;
        num_types_detected++;
    }

    if(bd->count_cwa){
        interf_rsp = &pinfo->interf_rsp[INTERF_TONE];
        interf_rsp->interf_min_freq = (bd->cwa_min_freq/1000);
        interf_rsp->interf_max_freq = (bd->cwa_max_freq/1000);
        interf_rsp->interf_type = INTERF_TONE;
        num_types_detected++;
    }


    interf_count = bd->count_mwo + bd->count_bts + bd->count_bth + bd->count_cwa + bd->count_cph;

    if (interf_count)
        pinfo->interf_count = interf_count;

    return num_types_detected;
}

void ssd_add_11g_interference_report(ssd_info_t *pinfo, struct INTERF_SRC_RSP *rsp)
{
    int i = 0;
    int count = 0;
    struct INTERF_RSP *interf_rsp = NULL;

    interf_rsp = &rsp->interf[0];

    for (i = 0; i < MAX_INTERF_COUNT; i++) {
        if (pinfo->interf_rsp[i].interf_type != INTERF_NONE) {
            count++;
            interf_rsp->interf_min_freq = htons(pinfo->interf_rsp[i].interf_min_freq);
            interf_rsp->interf_max_freq = htons(pinfo->interf_rsp[i].interf_max_freq);
            interf_rsp->interf_type     = pinfo->interf_rsp[i].interf_type;
            interf_rsp++;
        }
    }
    rsp->count = htons(count);
}


