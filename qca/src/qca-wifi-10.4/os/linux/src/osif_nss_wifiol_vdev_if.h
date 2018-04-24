/*
 * Copyright (c) 2015-2017 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * 2015-2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary. 
 */

/*
 * osif_nss_wifiol_vdev_if.h
 *
 * This file used for for interface to NSS WiFi Offload  VAP
 * ------------------------REVISION HISTORY-----------------------------
 * Qualcomm Atheros         15/june/2015              Created
 */

#ifndef __OSIF_NSS_WIFIOL_VDEV_IF_H
#define __OSIF_NSS_WIFIOL_VDEV_IF_H

#include <nss_api_if.h>
#include <osif_private.h>
#define OSIF_NSS_MAX_RADIOS 3

#define OSIF_NSS_VDEV_PKT_QUEUE_LEN 256
#define OSIF_NSS_VDEV_STALE_PKT_INTERVAL 1000

struct osif_nss_vdevinfo {
    uint32_t radio_id;
    uint32_t vdev_id;
    uint32_t epid;
    uint32_t downloadlen;
    uint32_t hdrcachelen;

    uint8_t *hdrcache;
    uint8_t *mac_addr;
    void *os_dev;
    uint32_t opmode;
    uint32_t mesh_mode_en;
};

struct osif_nss_vdev_cfg_pvt {
    struct completion complete;     /* completion structure */
    int response;               /* Response from FW */
};

struct osif_nss_vdev_vow_dbg_stats_pvt {
    struct completion complete;     /* completion structure */
    int response;               /* Response from FW */
    uint32_t rx_vow_dbg_counter;
    uint32_t tx_vow_dbg_counter[8];
};

enum osif_nss_error_types {
    OSIF_NSS_FAILURE_BAD_PARAM = 1,
    OSIF_NSS_FAILUE_MSG_TOO_SHORT,
    OSIF_NSS_FAILUE_NOT_SUPPORTED,
    OSIF_NSS_FAILURE_MAX
};

enum osif_nss_vdev_cmd {
    OSIF_NSS_VDEV_DROP_UNENC = 0,
    OSIF_NSS_VDEV_ENCAP_TYPE,
    OSIF_NSS_VDEV_DECAP_TYPE,
    OSIF_NSS_VDEV_ENABLE_ME,
    OSIF_NSS_WIFI_VDEV_NAWDS_MODE,
    OSIF_NSS_VDEV_EXTAP_CONFIG,
    OSIF_NSS_WIFI_VDEV_CFG_BSTEER,
    OSIF_NSS_WIFI_VDEV_VOW_DBG_MODE,
    OSIF_NSS_WIFI_VDEV_VOW_DBG_RST_STATS,
    OSIF_NSS_WIFI_VDEV_CFG_DSCP_OVERRIDE,
    OSIF_NSS_WIFI_VDEV_CFG_WNM_CAP,
    OSIF_NSS_WIFI_VDEV_CFG_WNM_TFS,
    OSIF_NSS_WIFI_VDEV_WDS_EXT_ENABLE,
    OSIF_NSS_WIFI_VDEV_MAX
};

#define OSIF_NSS_VDEV_CFG_TIMEOUT_MS 1000
#define NSS_PROXY_VAP_IF_NUMBER 999

int32_t osif_nss_ol_vap_delete(osif_dev *osifp);
int32_t osif_nss_ol_vap_up(osif_dev *osifp);
int32_t osif_nss_ol_vap_down(osif_dev *osifp);
int32_t osif_nss_ol_vap_xmit(osif_dev *osifp, struct sk_buff *skb);
int32_t osif_nss_ol_vap_hardstart(struct sk_buff *skb, struct net_device *dev);
void osif_nss_vdev_me_create_grp_list(struct ol_txrx_vdev_t *vdev, uint8_t *grp_addr, uint8_t *grp_ipaddr, uint32_t ether_type, uint32_t length);
void osif_nss_vdev_me_delete_grp_list(struct ol_txrx_vdev_t *vdev, uint8_t *grp_addr, uint8_t *grp_ipaddr, uint32_t ether_type);
void osif_nss_vdev_me_add_member_list(struct ol_txrx_vdev_t *vdev, struct MC_LIST_UPDATE* list_entry, uint32_t ether_type, uint32_t length, uint32_t peer_id);
void osif_nss_vdev_me_remove_member_list(struct ol_txrx_vdev_t *vdev, uint8_t *grp_ipaddr, uint8_t *grp_addr, uint8_t *grp_member_addr, uint32_t ether_type);
void osif_nss_vdev_me_update_member_list(struct ol_txrx_vdev_t *vdev, struct MC_LIST_UPDATE* list_entry, uint32_t ether_type);
void osif_nss_vdev_me_add_deny_member(struct ol_txrx_vdev_t *vdev, uint32_t grp_ipaddr);
void osif_nss_vdev_me_delete_deny_list(struct ol_txrx_vdev_t *vdev);
void osif_nss_vdev_me_dump_snooplist(struct ol_txrx_vdev_t *vdev);
void osif_nss_vdev_me_dump_denylist(struct ol_txrx_vdev_t *vdev);
void *osif_nss_vdev_get_nss_wifiol_ctx( void *vdevctx);
int osif_nss_vdev_get_nss_id( void *vdevctx);
int osif_nss_vdev_tx_raw(ol_txrx_vdev_handle vdev, qdf_nbuf_t *pnbuf);
int32_t osif_nss_ol_vap_create(struct ol_txrx_vdev_t * vdev, struct ieee80211vap *vap, osif_dev *osif, uint32_t nss_ifnum);
int32_t osif_nss_vdev_alloc(void *pdev_txrx_handle, struct ieee80211vap *vap);
void osif_nss_vdev_dealloc(osif_dev *osif, int32_t if_num);
void osif_nss_ol_vdev_set_cfg(struct ol_txrx_vdev_t * vdev, enum osif_nss_vdev_cmd osif_cmd);
void osif_nss_vdev_process_mpsta_tx(struct net_device *netdev, struct sk_buff *skb);
void osif_nss_vdev_process_mpsta_rx_to_tx(struct net_device *netdev, struct sk_buff *skb, __attribute__((unused)) struct napi_struct *napi);
void osif_nss_vdev_me_update_hifitlb(struct ol_txrx_vdev_t *vdev, struct ieee80211_me_hifi_table *table);
void osif_nss_vdev_me_reset_snooplist(struct ol_txrx_vdev_t *vdev);
int osif_nss_ol_ext_ap_rx(struct net_device *dev, struct sk_buff *skb);
int osif_nss_ol_ext_ap_tx(struct net_device *dev, struct sk_buff *skb);
void osif_nss_vdev_get_vow_dbg_stats(struct ol_txrx_vdev_t *vdev);
void osif_nss_vdev_vow_dbg_cfg(struct ol_txrx_vdev_t *vdev, int32_t val);
void osif_nss_vdev_set_dscp_tid_map(struct ol_txrx_vdev_t *vdev, uint32_t* dscp_map);
void osif_nss_vdev_process_extap_tx(struct net_device *netdev, struct sk_buff *skb);
void osif_nss_vdev_process_extap_rx_to_tx(struct net_device *netdev, struct sk_buff *skb);
void osif_nss_vdev_stale_pkts_timer(void *arg);
void osif_nss_vdev_process_wnm_tfs_tx(struct net_device *netdev, struct sk_buff *skb);
int32_t osif_nss_ol_vap_updchdhdr(struct ol_txrx_vdev_t * vdev);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
struct nss_wifi_offload_funcs {
    void (* ic_osif_nss_ol_store_other_pdev_stavap)(struct
                            ieee80211com* ic);
    void (* ic_osif_nss_vdev_me_reset_snooplist)(struct ol_txrx_vdev_t *vdev);
    void (* ic_osif_nss_vdev_me_update_member_list)(struct ol_txrx_vdev_t *vdev, struct MC_LIST_UPDATE* list_entry, uint32_t ether_type);
    int32_t (* ic_osif_nss_ol_vap_xmit)(osif_dev *osifp, struct sk_buff *skb);
    void (* ic_osif_nss_vdev_me_update_hifitlb)(struct ol_txrx_vdev_t *vdev, struct ieee80211_me_hifi_table *table);
    void (* ic_osif_nss_vdev_me_dump_denylist)(struct ol_txrx_vdev_t *vdev);
    void (* ic_osif_nss_vdev_me_add_deny_member)(struct ol_txrx_vdev_t *vdev, uint32_t grp_ipaddr);
    void (* ic_osif_nss_ol_vdev_set_cfg)(struct ol_txrx_vdev_t * vdev, enum osif_nss_vdev_cmd osif_cmd);
    void (* ic_osif_nss_vdev_process_mpsta_tx)(struct net_device *netdev, struct sk_buff *skb);
    int (* ic_osif_nss_ol_wifi_monitor_set_filter)(struct ieee80211com *ic, uint32_t filter_type);
    int (* ic_osif_nss_vdev_get_nss_id)( void *vdevctx);
    void (* ic_osif_nss_vdev_process_extap_tx)(struct net_device *netdev, struct sk_buff *skb);
    void (* ic_osif_nss_vdev_me_dump_snooplist)(struct ol_txrx_vdev_t *vdev);
    int32_t (* ic_osif_nss_ol_vap_delete)(osif_dev *osifp);
    void (* ic_osif_nss_vdev_me_add_member_list)(struct ol_txrx_vdev_t *vdev, struct MC_LIST_UPDATE* list_entry, uint32_t ether_type, uint32_t length, uint32_t peer_id);
    void (* ic_osif_nss_vdev_vow_dbg_cfg)(struct ol_txrx_vdev_t *vdev, int32_t val);
    void (* ic_osif_nss_ol_enable_dbdc_process)(struct ieee80211com* ic, uint32_t enable);
    void * (* ic_osif_nss_vdev_get_nss_wifiol_ctx)( void *vdevctx);
    void (* ic_osif_nss_vdev_me_delete_grp_list)(struct ol_txrx_vdev_t *vdev, uint8_t *grp_addr, uint8_t *grp_ipaddr, uint32_t ether_type);
    void (* ic_osif_nss_vdev_me_create_grp_list)(struct ol_txrx_vdev_t *vdev, uint8_t *grp_addr, uint8_t *grp_ipaddr, uint32_t ether_type, uint32_t length);
    void (* ic_osif_nss_vdev_me_delete_deny_list)(struct ol_txrx_vdev_t *vdev);
    void (* ic_osif_nss_vdev_me_remove_member_list)(struct ol_txrx_vdev_t *vdev, uint8_t *grp_ipaddr, uint8_t *grp_addr, uint8_t *grp_member_addr, uint32_t ether_type);
};

#endif /* QCA_NSS_WIFI_OFFLOAD_SUPPORT */


#endif /* __NSS_WIFI_MGR_H */
