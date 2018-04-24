/*
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 */

#include <osdep.h>
#include "osif_private.h"

#ifndef _ATH_BAND_STEERING__
#define _ATH_BAND_STEERING___

#if ATH_BAND_STEERING
struct band_steering_netlink {
    struct sock      *bsteer_sock;
    atomic_t         bsteer_refcnt;
};

int ath_band_steering_netlink_init(void);
int ath_band_steering_netlink_delete(void);
void ath_band_steering_netlink_send(ath_netlink_bsteering_event_t *event,u_int32_t pid);
#else
#define ath_band_steering_netlink_init() do {} while (0)
#define ath_band_steering_netlink_delete() do {} while (0)
#define ath_band_steering_netlink_send(ev,pid) do {} while (0)
#endif

#endif /* _ATH_BAND_STEERING___*/
