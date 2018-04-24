/*
 * =====================================================================================
 *
 *       Filename:  ol_if_greenap.h
 *
 *    Description:  Green AP feature
 *
 *        Version:  1.0
 *        Created:  10/26/2012 01:35:42 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  S.Karthikeyan (), 
 *        Company:  Qualcomm Atheros Confidential and Proprietary
 *
 * =====================================================================================
 */


#ifndef __OL_IF_GREEN_AP_H__
#define __OL_IF_GREEN_AP_H__

#include "ath_green_ap.h"

extern int ol_init_green_ap_ops(struct ieee80211com* ic);
extern int ol_if_green_ap_attach(struct ieee80211com* ic);
extern int ol_if_green_ap_detach(struct ieee80211com* ic);

#endif  /* __OL_IF_GREEN_AP_H__ */
