/*
 * =====================================================================================
 *
 *       Filename:  ssd_proto.h
 *
 *    Description:  Spectral Scan Protocol hanlder
 *
 *        Version:  1.0
 *        Created:  11/21/2011 02:57:07 PM
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

#ifndef _SSD_PROTO_H_
#define _SSD_PROTO_H_

extern u_int8_t* ssd_handle_client_request_msg(ssd_info_t *pinfo, u_int8_t *buf, int *recvd_bytes);
extern void ssd_switch_channel(ssd_info_t *pinfo);
extern void ssd_start_scan(ssd_info_t *pinfo);

#endif  /* _SSD_PROTO_H_ */
