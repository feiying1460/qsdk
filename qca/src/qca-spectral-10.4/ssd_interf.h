/*
 * =====================================================================================
 *
 *       Filename:  ssd_interf.h
 *
 *    Description:  Interfernce related
 *
 *        Version:  1.0
 *        Created:  11/28/2011 08:02:11 PM
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

#ifndef _SSD_INTERF_H_
#define _SSD_INTERF_H_

extern void update_11g_interf_detection(ssd_info_t *pinfo);
extern void clear_11g_interf_rsp(ssd_info_t* pinfo);
extern int update_11g_interf(ssd_info_t *pinfo, struct ss *bd);
extern void ssd_add_11g_interference_report(ssd_info_t *pinfo, struct INTERF_SRC_RSP *rsp);

#endif  /* _SSD_INTERF_H_ */
