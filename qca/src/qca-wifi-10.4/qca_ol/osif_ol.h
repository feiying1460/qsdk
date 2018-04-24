/*
 * Copyright (c) 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include "ieee80211_api.h"
#if ATH_PERF_PWR_OFFLOAD
#include <ol_cfg_raw.h>
#include <osif_rawmode.h>
#include <ol_if_athvar.h>
#endif /* ATH_PERF_PWR_OFFLOAD */
#include "ol_ath.h"
#include <linux/ethtool.h>

#if ATH_PERF_PWR_OFFLOAD
void osif_vap_setup_ol(struct ieee80211vap *vap,
                   osif_dev *osifp);
#endif /* ATH_PERF_PWR_OFFLOAD */
#if ATH_EXT_AP
extern int ath_ext_ap_rx_process(wlan_if_t vap, struct sk_buff *skb, int *nwifi);
extern int ath_ext_ap_tx_process(wlan_if_t vap, struct sk_buff **skb) ;
#define ATH_RX_EXT_AP_PROCESS(_vap,_skb,_nwifi) ath_ext_ap_rx_process(_vap, _skb, _nwifi)
#define ATH_TX_EXT_AP_PROCESS(_vap,_skb) ath_ext_ap_tx_process(_vap, _skb)

#else
#define ATH_RX_EXT_AP_PROCESS(_vap,_skb, _nwifi) 0
#define ATH_TX_EXT_AP_PROCESS(_vap,_skb) 0
#endif /* ATH_EXT_AP */

#if ATH_SUPPORT_WRAP
extern int ol_wrap_rx_process (os_if_t *osif ,struct net_device **dev ,wlan_if_t vap, struct sk_buff *skb, int *nwifi);
#define OL_WRAP_RX_PROCESS(_osif, _dev, _vap, _skb, _nwifi) ol_wrap_rx_process(_osif, _dev, _vap, _skb, _nwifi)
#else  /* ATH_SUPPORT_WRAP */
#define OL_WRAP_RX_PROCESS(_osif, _dev, _vap, _skb, _nwifi) 0
#endif /* ATH SUPPORT_WRAP */

#if ATH_SUPPORT_WRAP
extern bool wlan_is_mpsta(wlan_if_t vaphandle);
extern bool wlan_is_psta(wlan_if_t vaphandle);
#endif /* ATH_SUPPORT_WRAP */


#if QCA_OL_VLAN_WAR
extern int _ol_tx_vlan_war(struct sk_buff **skb ,struct ol_ath_softc_net80211 *scn);
#define  OL_TX_VLAN_WAR(_skb, _scn)  _ol_tx_vlan_war(_skb, _scn)
#else
#define  OL_TX_VLAN_WAR(_skb, _scn)  0
#endif

