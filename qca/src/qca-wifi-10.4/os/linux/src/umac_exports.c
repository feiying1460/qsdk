/*
 * Copyright (c) 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */
#include <linux/module.h>
#include <ieee80211_var.h>
#include <ieee80211_defines.h>
#include <ieee80211_acs.h>

#include <ieee80211_band_steering.h>
#include <ieee80211_channel.h>
#include <ieee80211_api.h>
#include <ieee80211_txrx_priv.h>
#include <ieee80211_wds.h>
#include <ieee80211_csa.h>
#include <if_smart_ant.h>
#include <ath_dev.h>
#include <ieee80211_regdmn.h>
#include <if_athvar.h>
#include <acfg_drv_event.h>
#include <ald_netlink.h>
#include <ieee80211_proto.h>
#include <ieee80211_admctl.h>
#include <ieee80211_vi_dbg.h>
#include <ieee80211_acfg.h>
#include <wdi_event_api.h>

/* Export ieee80211_acs.c functions */
EXPORT_SYMBOL(ieee80211_acs_set_param);
EXPORT_SYMBOL(ieee80211_acs_get_param);
EXPORT_SYMBOL(ieee80211_acs_stats_update);

/* Export ieee80211_ald.c functions */
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
EXPORT_SYMBOL(ieee80211_ald_record_tx);
#endif

/* Export ieee80211_aow.c/ieee80211_aow_mck.c functions */
#if ATH_SUPPORT_AOW
EXPORT_SYMBOL(wlan_get_tsf);
EXPORT_SYMBOL(wlan_aow_set_audioparams);
EXPORT_SYMBOL(wlan_aow_tx);
EXPORT_SYMBOL(wlan_aow_dispatch_data);
EXPORT_SYMBOL(wlan_aow_register_calls_to_usb);
EXPORT_SYMBOL(aow_register_usb_calls_to_wlan);
#endif

/* Export band_steering_direct_attach.c functions */
#if ATH_BAND_STEERING
EXPORT_SYMBOL(ieee80211_bsteering_direct_attach_rssi_update);
EXPORT_SYMBOL(wlan_bsteering_send_null);
EXPORT_SYMBOL(wlan_bsteering_set_overload_param);
EXPORT_SYMBOL(wlan_bsteering_direct_attach_enable);
EXPORT_SYMBOL(wlan_bsteering_set_inact_params);
EXPORT_SYMBOL(ieee80211_bsteering_mark_node_bs_inact);
EXPORT_SYMBOL(ieee80211_bsteering_is_vap_enabled);
EXPORT_SYMBOL(ieee80211_bsteering_direct_attach_txrate_update);
EXPORT_SYMBOL(ieee80211_bsteering_send_sta_stats);
EXPORT_SYMBOL(ieee80211_bsteering_send_txpower_change_event);
EXPORT_SYMBOL(ieee80211_bsteering_record_act_change);
EXPORT_SYMBOL(ieee80211_bsteering_send_vap_stop_event);
EXPORT_SYMBOL(ieee80211_bsteering_update_sta_stats);
EXPORT_SYMBOL(ieee80211_bsteering_record_inst_rssi);
EXPORT_SYMBOL(ieee80211_bsteering_record_inst_rssi_err);
EXPORT_SYMBOL(ieee80211_bsteering_record_rssi);
EXPORT_SYMBOL(ieee80211_bsteering_update_rate);
#endif

/* Export ieee80211_channel.c functions */
EXPORT_SYMBOL(ieee80211_chan2mode);
EXPORT_SYMBOL(ieee80211_ieee2mhz);
EXPORT_SYMBOL(ieee80211_find_channel);
EXPORT_SYMBOL(ieee80211_doth_findchan);
EXPORT_SYMBOL(ieee80211_find_dot11_channel);
EXPORT_SYMBOL(wlan_get_desired_phymode);
EXPORT_SYMBOL(wlan_get_dev_current_channel);
EXPORT_SYMBOL(wlan_set_channel);
EXPORT_SYMBOL(ieee80211_get_chan_width);
EXPORT_SYMBOL(ieee80211_check_channel_overlap);
EXPORT_SYMBOL(ieee80211_sec_chan_offset);
EXPORT_SYMBOL(wlan_get_current_phymode);
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
EXPORT_SYMBOL(ieee80211_print_nolhistory);
EXPORT_SYMBOL(ieee80211_clear_nolhistory);
#endif

/* Export ieee80211_common.c functions */
#if QCA_AIRTIME_FAIRNESS
extern unsigned int atf_mode;
extern unsigned int atf_msdu_desc;
extern unsigned int atf_peers;
extern unsigned int atf_max_vdevs;
EXPORT_SYMBOL(atf_mode);
EXPORT_SYMBOL(atf_msdu_desc);
EXPORT_SYMBOL(atf_peers);
EXPORT_SYMBOL(atf_max_vdevs);
#endif
EXPORT_SYMBOL(ieee80211_ifattach);
EXPORT_SYMBOL(ieee80211_ifdetach);
EXPORT_SYMBOL(ieee80211_dfs_reset);
EXPORT_SYMBOL(ieee80211_start_running);
EXPORT_SYMBOL(ieee80211_stop_running);
EXPORT_SYMBOL(wlan_get_device_param);
EXPORT_SYMBOL(wlan_get_device_mac_addr);
EXPORT_SYMBOL(ieee80211_vaps_active);
#if ATH_SUPPORT_EXT_STAT
EXPORT_SYMBOL(ieee80211_reset_client_rt_rate);
#endif

/* Export ieee80211_msg.c functions */
EXPORT_SYMBOL(ieee80211_note);
EXPORT_SYMBOL(ieee80211_note_mac);
EXPORT_SYMBOL(ieee80211_discard_frame);
EXPORT_SYMBOL(ieee80211_discard_mac);

/* Export ieee80211_node.c functions */
#if IEEE80211_DEBUG_REFCNT
EXPORT_SYMBOL(ieee80211_free_node_debug);
EXPORT_SYMBOL(ieee80211_find_node_debug);
EXPORT_SYMBOL(ieee80211_find_txnode_debug);
EXPORT_SYMBOL(ieee80211_find_rxnode_debug);
EXPORT_SYMBOL(ieee80211_find_rxnode_nolock_debug);
EXPORT_SYMBOL(ieee80211_ref_bss_node_debug);
#else
EXPORT_SYMBOL(ieee80211_free_node);
EXPORT_SYMBOL(ieee80211_find_node);
EXPORT_SYMBOL(ieee80211_find_txnode);
EXPORT_SYMBOL(ieee80211_find_rxnode);
EXPORT_SYMBOL(ieee80211_find_rxnode_nolock);
EXPORT_SYMBOL(ieee80211_ref_bss_node);
#endif

#if ATH_SUPPORT_WRAP
#if IEEE80211_DEBUG_REFCNT
EXPORT_SYMBOL(ieee80211_find_wrap_node_debug);
#else
EXPORT_SYMBOL(ieee80211_find_wrap_node);
#endif
EXPORT_SYMBOL(wlan_is_wrap);
#endif

EXPORT_SYMBOL(ieee80211_iterate_node);
EXPORT_SYMBOL(wlan_iterate_station_list);
EXPORT_SYMBOL(ieee80211_has_weptkipaggr);

#if ATH_SUPPORT_AOW
extern void ieee80211_send2all_nodes(void *reqvap, void *data, int len, u_int32_t seqno, u_int64_t tsf);
EXPORT_SYMBOL(ieee80211_send2all_nodes);
#endif

/* Export ieee80211_node_ap.c functions */
EXPORT_SYMBOL(ieee80211_tmp_node);

/* Export ieee80211_vap.c functions */
EXPORT_SYMBOL(ieee80211_vap_setup);
EXPORT_SYMBOL(ieee80211_vap_attach);
EXPORT_SYMBOL(ieee80211_vap_detach);
EXPORT_SYMBOL(wlan_iterate_vap_list);
EXPORT_SYMBOL(wlan_vap_get_hw_macaddr);
EXPORT_SYMBOL(ieee80211_new_opmode);
EXPORT_SYMBOL(wlan_vap_get_registered_handle);

/* Export ieee80211_crypto.c functions */
EXPORT_SYMBOL(ieee80211_crypto_newkey);
EXPORT_SYMBOL(ieee80211_crypto_delkey);
EXPORT_SYMBOL(ieee80211_crypto_setkey);
EXPORT_SYMBOL(ieee80211_crypto_clearkey);
EXPORT_SYMBOL(ieee80211_crypto_encap);
EXPORT_SYMBOL(ieee80211_crypto_decap);
EXPORT_SYMBOL(ieee80211_crypto_wep_setdummykey);

/* Export ieee80211_crypto_none.c functions */
EXPORT_SYMBOL(ieee80211_cipher_none);

/* Export ieee80211_rsn.c functions */
EXPORT_SYMBOL(wlan_restore_keys);

/* Export ieee80211_csa.c functions */
EXPORT_SYMBOL(ieee80211_start_csa);

/* Export ieee80211_dfs.c functions */
EXPORT_SYMBOL(ieee80211_mark_dfs);

#if ATH_SUPPORT_ZERO_CAC_DFS
EXPORT_SYMBOL(ieee80211_mark_precac_dfs);
EXPORT_SYMBOL(ieee80211_is_precac_timer_running);
EXPORT_SYMBOL(ieee80211_dfs_find_precac_secondary_vht80_chan);
EXPORT_SYMBOL(ieee80211_dfs_cancel_precac_timer);
EXPORT_SYMBOL(ieee80211_print_precaclists);
EXPORT_SYMBOL(ieee80211_reset_precaclists);
EXPORT_SYMBOL(ieee80211_dfs_get_freq_from_precac_required_list);
EXPORT_SYMBOL(ieee80211_dfs_start_precac_timer);
EXPORT_SYMBOL(ieee80211_dfs_override_precac_timeout);
EXPORT_SYMBOL(ieee80211_dfs_get_override_precac_timeout);
#endif

EXPORT_SYMBOL(ieee80211_send_rcsa);
EXPORT_SYMBOL(ieee80211_dfs_cac_cancel);
EXPORT_SYMBOL(ieee80211_update_dfs_next_channel);
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
EXPORT_SYMBOL(ieee80211_dfs_stacac_cancel);
#endif
EXPORT_SYMBOL(ieee80211_dfs_cac_start);
EXPORT_SYMBOL(ieee80211_unmark_radar);
EXPORT_SYMBOL(ieee80211_bringup_ap_vaps);
EXPORT_SYMBOL(ieee80211_random_channel);

/* Export ieee80211_extap.c functions */
extern void compute_udp_checksum(qdf_net_iphdr_t *p_iph, unsigned short  *ip_payload);
EXPORT_SYMBOL(compute_udp_checksum);

/* Export ieee80211_beacon.c functions */
EXPORT_SYMBOL(ieee80211_beacon_alloc);
EXPORT_SYMBOL(ieee80211_beacon_update);

/* Export ieee80211_ie.c functions */
#if ATH_SUPPORT_IBSS_DFS
EXPORT_SYMBOL(ieee80211_measurement_report_action);
#endif

/* Export ieee80211_mgmt.c functions */
EXPORT_SYMBOL(ieee80211_send_deauth);
EXPORT_SYMBOL(ieee80211_send_disassoc);
EXPORT_SYMBOL(ieee80211_send_action);
#ifdef ATH_SUPPORT_TxBF
EXPORT_SYMBOL(ieee80211_send_v_cv_action);
#endif
EXPORT_SYMBOL(ieee80211_send_bar);
EXPORT_SYMBOL(ieee80211_prepare_qosnulldata);
EXPORT_SYMBOL(ieee80211_recv_mgmt);
EXPORT_SYMBOL(ieee80211_recv_ctrl);

/* Export ieee80211_mlme.c functions */
EXPORT_SYMBOL(wlan_mlme_deauth_request);
EXPORT_SYMBOL(sta_disassoc);
EXPORT_SYMBOL(ieee80211_mlme_node_pwrsave);

/* Export ieee80211_mlme_sta.c functions */
EXPORT_SYMBOL(ieee80211_beacon_miss);
EXPORT_SYMBOL(ieee80211_notify_beacon_rssi);
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
EXPORT_SYMBOL(mlme_set_stacac_valid);
#endif
EXPORT_SYMBOL(mlme_indicate_sta_radar_detect);
EXPORT_SYMBOL(channel_switch_set_channel);

/* Export ieee80211_proto.c functions */
EXPORT_SYMBOL(ieee80211_state_event);
EXPORT_SYMBOL(ieee80211_wme_initglobalparams);
EXPORT_SYMBOL(ieee80211_wme_amp_overloadparams_locked);
EXPORT_SYMBOL(ieee80211_wme_updateparams_locked);
EXPORT_SYMBOL(ieee80211_dump_pkt);

/* Export ieee80211_power.c functions */
EXPORT_SYMBOL(ieee80211_power_class_attach);

/* Export ieee80211_power_queue.c functions */
EXPORT_SYMBOL(ieee80211_node_saveq_queue);
EXPORT_SYMBOL(ieee80211_node_saveq_flush);

/* Export ieee80211_sta_power.c functions */
EXPORT_SYMBOL(ieee80211_sta_power_event_tim);
EXPORT_SYMBOL(ieee80211_sta_power_event_dtim);

/* Export ieee80211_regdmn.c functions */
EXPORT_SYMBOL(ieee80211_set_regclassids);
EXPORT_SYMBOL(wlan_set_countrycode);
EXPORT_SYMBOL(wlan_set_regdomain);

/* Export ieee80211_resmgr.c functions */
EXPORT_SYMBOL(ieee80211_resmgr_attach);

/* Export ieee80211_scan.c functions */
EXPORT_SYMBOL(ieee80211_scan_class_attach);

/* Export ieee80211_scan_api.c functions */
EXPORT_SYMBOL(wlan_scan_in_progress_ic);

/* Export ieee80211_scanentry.c functions */
EXPORT_SYMBOL(wlan_scan_table_flush);

/* Export ieee80211_smart_ant_api.c functions */
#if UNIFIED_SMARTANTENNA
extern int register_smart_ant_ops(struct smartantenna_ops *sa_ops);
extern int deregister_smart_ant_ops(char *dev_name);
EXPORT_SYMBOL(g_sa_ops);
EXPORT_SYMBOL(rate_table_24);
EXPORT_SYMBOL(rate_table_5);
EXPORT_SYMBOL(register_smart_ant_ops);
EXPORT_SYMBOL(deregister_smart_ant_ops);
#endif

/* Export ieee80211_txbf.c functions */
#ifdef ATH_SUPPORT_TxBF
EXPORT_SYMBOL(ieee80211_set_TxBF_keycache);
EXPORT_SYMBOL(ieee80211_request_cv_update);
#endif

/* Export ieee80211_frag.c functions */
EXPORT_SYMBOL(ieee80211_fragment);
EXPORT_SYMBOL(ieee80211_defrag);

/* Export ieee80211_input.c functions */
EXPORT_SYMBOL(ieee80211_amsdu_input);
EXPORT_SYMBOL(ieee80211_input);
EXPORT_SYMBOL(ieee80211_input_all);
EXPORT_SYMBOL(ieee80211_input_monitor);

/* Export ieee80211_output.c functions */
EXPORT_SYMBOL(ieee80211_update_stats);
#ifdef ATH_SUPPORT_TxBF
extern void
ieee80211_tx_bf_completion_handler(struct ieee80211_node *ni,  struct ieee80211_tx_status *ts);
EXPORT_SYMBOL(ieee80211_tx_bf_completion_handler);
#endif
EXPORT_SYMBOL(ieee80211_kick_node);
EXPORT_SYMBOL(ieee80211_complete_wbuf);
EXPORT_SYMBOL(wlan_vap_send);
EXPORT_SYMBOL(__ieee80211_encap);
EXPORT_SYMBOL(ieee80211_8023frm_amsdu_check);
EXPORT_SYMBOL(ieee80211_amsdu_check);
EXPORT_SYMBOL(ieee80211_amsdu_encap);
EXPORT_SYMBOL(ieee80211_notify_queue_status);
EXPORT_SYMBOL(ieee80211_check_and_update_pn);

/* Export ieee80211_wds.c functions */
EXPORT_SYMBOL(ieee80211_nawds_disable_beacon);

/* Export ieee80211_wifipos.c functions */
#if ATH_SUPPORT_WIFIPOS
extern int ieee80211_update_wifipos_stats(ieee80211_wifiposdesc_t *wifiposdesc);
extern int ieee80211_isthere_wakeup_request(struct ieee80211_node *ni);
extern int ieee80211_update_ka_done(u_int8_t *sta_mac_addr, u_int8_t ka_tx_status);
EXPORT_SYMBOL(ieee80211_isthere_wakeup_request);
EXPORT_SYMBOL(ieee80211_update_ka_done);
EXPORT_SYMBOL(ieee80211_update_wifipos_stats);
EXPORT_SYMBOL(ieee80211_cts_done);
#endif

/* Export ieee80211_wnm.c functions */
EXPORT_SYMBOL(wlan_wnm_tfs_filter);
EXPORT_SYMBOL(ieee80211_timbcast_alloc);
EXPORT_SYMBOL(ieee80211_timbcast_update);
EXPORT_SYMBOL(ieee80211_wnm_timbcast_cansend);
EXPORT_SYMBOL(ieee80211_wnm_timbcast_enabled);
EXPORT_SYMBOL(ieee80211_timbcast_get_highrate);
EXPORT_SYMBOL(ieee80211_timbcast_get_lowrate);
EXPORT_SYMBOL(ieee80211_timbcast_lowrateenable);
EXPORT_SYMBOL(ieee80211_timbcast_highrateenable);
EXPORT_SYMBOL(ieee80211_wnm_fms_enabled);

#if UMAC_SUPPORT_ACFG
/* Export acfg_net_event.c functions */
EXPORT_SYMBOL(acfg_event_netlink_init);
EXPORT_SYMBOL(acfg_event_netlink_delete);
#endif

/* Export adf_net_vlan.c functions */
#if ATH_SUPPORT_VLAN
EXPORT_SYMBOL(qdf_net_get_vlan);
EXPORT_SYMBOL(qdf_net_is_vlan_defined);
#endif

/* Export ald_netlink.c functions */
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
EXPORT_SYMBOL(ald_init_netlink);
EXPORT_SYMBOL(ald_destroy_netlink);
EXPORT_SYMBOL(ieee80211_ald_update_phy_error_rate);
#endif

/* Export ath_green_ap.c functions */
EXPORT_SYMBOL(ath_green_ap_is_powersave_on);
EXPORT_SYMBOL(ath_green_ap_suspend);
EXPORT_SYMBOL(ath_green_ap_sc_get_enable_print);
EXPORT_SYMBOL(ath_green_ap_sc_set_enable_print);

/* Export osif_umac.c functions */
extern struct ath_softc_net80211 *global_scn[10];
extern struct ol_ath_softc_net80211 *ol_global_scn[10];
extern int num_global_scn;
extern int ol_num_global_scn;
extern unsigned long ath_ioctl_debug;
EXPORT_SYMBOL(global_scn);
EXPORT_SYMBOL(num_global_scn);
EXPORT_SYMBOL(ol_global_scn);
EXPORT_SYMBOL(ol_num_global_scn);
EXPORT_SYMBOL(ath_ioctl_debug);
#if ATH_DEBUG
extern unsigned long ath_rtscts_enable;
EXPORT_SYMBOL(ath_rtscts_enable);
#endif
EXPORT_SYMBOL(osif_restart_for_config);

/* Export ath_timer.c functions */
EXPORT_SYMBOL(ath_initialize_timer_module);
EXPORT_SYMBOL(ath_initialize_timer_int);
EXPORT_SYMBOL(ath_set_timer_period);
EXPORT_SYMBOL(ath_timer_is_initialized);
EXPORT_SYMBOL(ath_start_timer);
EXPORT_SYMBOL(ath_cancel_timer);
EXPORT_SYMBOL(ath_timer_is_active);
EXPORT_SYMBOL(ath_free_timer_int);

/* Export ath_wbuf.c functions */
EXPORT_SYMBOL(__wbuf_uapsd_update);
EXPORT_SYMBOL(wbuf_release);

/* Export if_bus.c functions*/
EXPORT_SYMBOL(bus_read_cachesize);

/* Export if_ath_pci.c functions */
extern unsigned int ahbskip;
EXPORT_SYMBOL(ahbskip);

/* Export osif_proxyarp.c functions */
int wlan_proxy_arp(wlan_if_t vap, wbuf_t wbuf);
EXPORT_SYMBOL(wlan_proxy_arp);

int do_proxy_arp(wlan_if_t vap, qdf_nbuf_t netbuf);
EXPORT_SYMBOL(do_proxy_arp);

/* Export ext_ioctl_drv_if.c functions */
EXPORT_SYMBOL(ieee80211_extended_ioctl_chan_switch);
EXPORT_SYMBOL(ieee80211_extended_ioctl_chan_scan);
EXPORT_SYMBOL(ieee80211_extended_ioctl_rep_move);

/* Export ieee80211_proto.h functions */
//EXPORT_SYMBOL(ieee80211_build_ibss_dfs_ie);
#if UMAC_SUPPORT_ACFG
/* Export ieee80211_ioctl_acfg.c */
void acfg_convert_to_acfgprofile (struct ieee80211_profile *profile,
                                acfg_radio_vap_info_t *acfg_profile);
EXPORT_SYMBOL(acfg_convert_to_acfgprofile);
#endif
/* Export ieee80211_admctl.c */
#if UMAC_SUPPORT_ADMCTL
EXPORT_SYMBOL(ieee80211_admctl_classify);
#endif

/* ieee80211_vi_dbg.c */
#if UMAC_SUPPORT_VI_DBG
EXPORT_SYMBOL(ieee80211_vi_dbg_input);
#endif

/* ieee80211_common.c */
EXPORT_SYMBOL(IEEE80211_DPRINTF);

#if QCA_PARTNER_PLATFORM
EXPORT_SYMBOL(ieee80211_smart_ant_cwm_action);
EXPORT_SYMBOL(ieee80211_smart_ant_update_rxfeedback);
EXPORT_SYMBOL(ieee80211_smart_ant_get_bcn_txantenna);
EXPORT_SYMBOL(ieee80211_smart_ant_convert_rate_2g);
EXPORT_SYMBOL(ieee80211_smart_ant_get_param);
EXPORT_SYMBOL(ieee80211_smart_ant_set_param);
EXPORT_SYMBOL(ieee80211_smart_ant_update_txfeedback);
EXPORT_SYMBOL(ieee80211_smart_ant_convert_rate_5g);
EXPORT_SYMBOL(wlan_vap_get_devhandle);
EXPORT_SYMBOL(wlan_scan_in_progress);
EXPORT_SYMBOL(ieee80211_vap_txrx_deliver_event);
EXPORT_SYMBOL(wlan_vap_unregister_mlme_event_handlers);
EXPORT_SYMBOL(wlan_vap_register_mlme_event_handlers);
EXPORT_SYMBOL(ieee80211_find_wds_node);
#endif
void ic_reset_params(struct ieee80211com *ic);
EXPORT_SYMBOL(ic_reset_params);

EXPORT_SYMBOL(IEEE80211_DPRINTF_IC);
EXPORT_SYMBOL(IEEE80211_DPRINTF_IC_CATEGORY);
EXPORT_SYMBOL(ieee80211_vap_join);
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
EXPORT_SYMBOL(ieee80211_ioctl_ald_getStatistics);
#endif
EXPORT_SYMBOL(ieee80211_bcn_prb_template_update);
EXPORT_SYMBOL(ieee80211_is_pmf_enabled);
EXPORT_SYMBOL(wlan_get_operational_rates);
EXPORT_SYMBOL(ieee80211_aplist_get_desired_bssid_count);
EXPORT_SYMBOL(ieee80211_vap_get_opmode);
EXPORT_SYMBOL(delete_default_vap_keys);
EXPORT_SYMBOL(ieee80211_reset_erp);
EXPORT_SYMBOL(ieee80211_wnm_bssmax_updaterx);
EXPORT_SYMBOL(ieee80211_notify_michael_failure);
EXPORT_SYMBOL(ieee80211_secondary20_channel_offset);
EXPORT_SYMBOL(wlan_vap_get_opmode);
EXPORT_SYMBOL(wlan_scan_entry_channel);
EXPORT_SYMBOL(ieee80211_send_mgmt);
EXPORT_SYMBOL(ieee80211_crypto_encap_mon);
EXPORT_SYMBOL(ieee80211_scan_table_flush);
EXPORT_SYMBOL(ieee80211_vap_mlme_inact_erp_timeout);
EXPORT_SYMBOL(ieee80211_vap_is_any_running);
EXPORT_SYMBOL(osif_restart_vaps);
EXPORT_SYMBOL(ieee80211_wme_initparams);
EXPORT_SYMBOL(wlan_get_countrycode);
EXPORT_SYMBOL(wlan_deauth_all_stas);
EXPORT_SYMBOL(ieee80211com_note);
EXPORT_SYMBOL(ieee80211_setpuregbasicrates);
EXPORT_SYMBOL(ieee80211_set_shortslottime);
EXPORT_SYMBOL(ieee80211_vap_get_scan_table);
EXPORT_SYMBOL(channel_type);
EXPORT_SYMBOL(ieee80211_aplist_get_desired_bssid);
EXPORT_SYMBOL(wlan_vap_get_bssid);
EXPORT_SYMBOL(ieee80211_add_vhtcap);
EXPORT_SYMBOL(ieee80211_get_chan_centre_freq);
EXPORT_SYMBOL(ieee80211_mhz2ieee);
#if UMAC_SUPPORT_ACFG
EXPORT_SYMBOL(acfg_send_event);
EXPORT_SYMBOL(acfg_chan_stats_event);
#endif
EXPORT_SYMBOL(ieee80211_vap_deliver_stop_error);
EXPORT_SYMBOL(ieee80211_mlme_sta_swbmiss_timer_disable);
EXPORT_SYMBOL(wlan_get_param);
EXPORT_SYMBOL(wlan_get_key);
EXPORT_SYMBOL(ieee80211_mlme_sta_bmiss_ind);
EXPORT_SYMBOL(ieee80211_phymode_name);
#if ATH_SUPPORT_WIFIPOS
EXPORT_SYMBOL(ieee80211com_init_netlink);
#endif
EXPORT_SYMBOL(ieee80211_mlme_sta_swbmiss_timer_alloc_id);
EXPORT_SYMBOL(wlan_channel_ieee);

#if MESH_MODE_SUPPORT
extern void ieee80211_check_timeout_mesh_peer(void *arg, wlan_if_t vaphandle);
EXPORT_SYMBOL(ieee80211_check_timeout_mesh_peer);
extern void os_if_tx_free_batch_ext(struct sk_buff *bufs, int tx_err);
EXPORT_SYMBOL(os_if_tx_free_batch_ext);
#endif /* MESH_MODE_SUPPORT */

EXPORT_SYMBOL(ieee80211_node_clear_keys);
EXPORT_SYMBOL(ieee80211_get_txstreams);
extern uint32_t promisc_is_active (struct ieee80211com *ic);
EXPORT_SYMBOL(promisc_is_active);
EXPORT_SYMBOL(ieee80211_vi_dbg_print_stats);
EXPORT_SYMBOL(ieee80211_getstreams);
EXPORT_SYMBOL(ieee80211_vap_get_aplist_config);
EXPORT_SYMBOL(ieee80211_add_htcap);
EXPORT_SYMBOL(ieee80211_session_timeout);
EXPORT_SYMBOL(wlan_set_param);
EXPORT_SYMBOL(transcap_dot3_to_eth2);
EXPORT_SYMBOL(wlan_get_vap_opmode_count);
EXPORT_SYMBOL(wlan_scan_macaddr_iterate);
EXPORT_SYMBOL(ieee80211_get_num_vaps_up);
EXPORT_SYMBOL(ieee80211_vap_deliver_stop);
extern unsigned int enable_pktlog_support;
EXPORT_SYMBOL(enable_pktlog_support);
#if DBDC_REPEATER_SUPPORT
EXPORT_SYMBOL(wlan_update_radio_priorities);
#endif
#if ATH_SUPPORT_WRAP && DBDC_REPEATER_SUPPORT
EXPORT_SYMBOL(osif_set_primary_radio_event);
#endif
