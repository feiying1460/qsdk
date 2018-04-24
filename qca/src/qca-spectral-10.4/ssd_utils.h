/*
 * =====================================================================================
 *
 *       Filename:  ssd_utils.h
 *
 *    Description:  SSD Utility functions
 *
 *        Version:  1.0
 *        Created:  11/25/2011 05:03:14 PM
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

#ifndef _SSD_UTILS_H_
#define _SSD_UTILS_H_

extern int8_t convert_rssi_to_dbm(int8_t rssi);
extern void print_samp_info(ssd_samp_info_t *psinfo);
extern void print_tag_type(struct TLV* p);
extern void print_args(ssd_info_t *pinfo);


#endif  /* _SSD_UTILS_H_ */
