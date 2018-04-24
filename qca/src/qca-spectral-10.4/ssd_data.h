/*
 * =====================================================================================
 *
 *       Filename:  ssd_data.h
 *
 *    Description:  Spectral Scan data handler
 *
 *        Version:  1.0
 *        Created:  11/22/2011 06:08:55 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  S.Karthikeyan (), 
 *        Company:  Qualcomm Atheros
 *
 *
 *        Copyright (c) 2012 Qualcomm Atheros, Inc.
 *        All Rights Reserved
 *        Qualcomm Atheros Confidential and Proprietary
 *
 * =====================================================================================
 */

#ifndef _SSD_DATA_H_
#define _SSD_DATA_H_

extern u_int8_t* ssd_build_single_SAMP_response(ssd_info_t *pinfo,
                                                uint16_t freq,
                                                int *num_bytes,
                                                u_int8_t *bin_pwr,
                                                int pwr_count,
                                                u_int8_t rssi,
                                                int8_t lower_rssi,
                                                int8_t upper_rssi,
                                                u_int8_t max_scale,
                                                int16_t max_mag,
                                                struct INTERF_SRC_RSP *interf);

extern void ssd_prepare_spectral_data_to_client(ssd_info_t *pinfo, SPECTRAL_SAMP_MSG* ss_msg, int client_fd);
extern void ssd_handle_spectral_data(ssd_info_t *pinfo, u_int8_t* buf, int *recvd_bytes, int client_fd, int nl_spectral_fd);
extern void ssd_clear_max_rssi_data(ssd_info_t* pinfo);
extern void init_bandinfo(struct ss *plwrband, struct ss *puprband, int print_enable);
extern void ms_init_classifier(struct ss *lwrband, struct ss *uprband, SPECTRAL_CLASSIFIER_PARAMS *cp);
extern void classifier(struct ss *bd, int timestamp, int last_capture_time, int rssi, int narrowband, int peak_index);
extern void ssd_save_this_spectral_msg(ssd_info_t *pinfo, SPECTRAL_SAMP_MSG* msg);
extern void ssd_save_maxrssi_samp_message(ssd_info_t *pinfo, SPECTRAL_SAMP_MSG* msg);
extern int ssd_can_send_saved_msg(ssd_info_t *pinfo);
extern void ssd_send_classified_spectral_data_to_client(ssd_info_t *pinfo, SPECTRAL_SAMP_MSG* msg, int client_fd);
extern void ssd_init_silent_samp_msg(ssd_info_t *pinfo);
extern void ssd_update_silent_samp_msg(ssd_info_t *pinfo, int freq);
extern void ssd_send_normal_spectral_data_to_client(ssd_info_t *pinfo, SPECTRAL_SAMP_MSG *ss_msg, int client_fd);


#endif  /* _SSD_H_ */
