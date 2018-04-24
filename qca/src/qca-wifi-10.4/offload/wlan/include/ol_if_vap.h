/*
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */

int
ol_ath_vdev_start_send(struct ol_ath_softc_net80211 *scn, u_int8_t if_id,
        struct ieee80211_channel *chan, u_int32_t freq,
        bool disable_hw_ack, void *nl_handle);
int
ol_ath_vdev_restart_send(struct ol_ath_softc_net80211 *scn, u_int8_t if_id,
        struct ieee80211_channel *chan, u_int32_t freq, bool disable_hw_ack);

