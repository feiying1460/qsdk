/*
 * =====================================================================================
 *
 *       Filename:  ssd_list.c
 *
 *    Description:  Linked List to store spectral data
 *
 *        Version:  1.0
 *        Created:  11/28/2011 03:09:31 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  S.Karthikeyan (), 
 *        Company:  Qualcomm Atheros
 *
 *        Copyright (c) 2012 Qualcomm Atheros, Inc.
 *        All Rights Reserved
 *        Qualcomm Atheros Confidential and Proprietary
 * =====================================================================================
 */

#include "ssd_defs.h"


/*
 * Function     : init_ssd_samp_msg_buffers
 * Description  : initializes the FIFO to store SAMP message
 * Input params : pointer to ssd_info_t
 * Return       :
 *
 */
int ssd_init_ssd_samp_msg_buffers(ssd_info_t *pinfo)
{

    ssd_samp_msg_buffers_t *p_lower = &pinfo->lower_msg_pool;
    ssd_samp_msg_buffers_t *p_upper = &pinfo->upper_msg_pool;

    p_lower->read_index  = 0;
    p_lower->write_index = 0;
    p_lower->prev_index  = 0;
    p_lower->count       = 0;
    p_lower->freq        = GUI_LOWER_FREQ;

    p_upper->read_index  = 0;
    p_upper->write_index = 0;
    p_upper->prev_index  = 0;
    p_upper->count       = 0;
    p_upper->freq        = GUI_UPPER_FREQ;

    return 0;
}

/*
 * Function     : put_msg
 * Description  : inserts a new SAMP msg to FIFO
 * Input params : pointer to ssd_info_t, pointer to data, data length
 * Return       : 0 on success, -1 on failure
 *
 */
int put_msg(ssd_info_t *pinfo, char *data, int len, ssd_samp_msg_buffers_t *p)
{

    if (p->write_index == ((p->read_index - 1 + MAX_SAVED_SAMP_MESSAGES) % MAX_SAVED_SAMP_MESSAGES)) {
        return -1;
    }

    memcpy(&p->buf[p->write_index].msg, data, len);
    p->buf[p->write_index].length = len;
    p->write_index = (p->write_index + 1) % MAX_SAVED_SAMP_MESSAGES;
    p->buf[p->write_index].valid = TRUE;
    p->count++;

    return SSD_LIST_OK;
}

/*
 * Function     : get_msg
 * Description  : get the SAMP msg from FIFO
 * Input params : pointer to ssd_info_t, pointer to index
 * Return       : SSD_LIST_OK on success, SSD_LIST_EMPTY on failure
 *
 */
int get_msg(ssd_info_t *pinfo, int *index, ssd_samp_msg_buffers_t *p)
{
    if (p->write_index == p->read_index) {
        p->count = 0;
        return SSD_LIST_EMPTY;
    }

    *index = p->read_index;
    p->buf[p->read_index].valid = FALSE;
    p->prev_index = p->read_index;
    p->read_index = (p->read_index + 1) % MAX_SAVED_SAMP_MESSAGES;
    p->count--;
    return SSD_LIST_OK;
}
