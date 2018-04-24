/*
 * Copyright (c) 2010, Atheros Communications Inc.
 * All Rights Reserved.
 *
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

/*
 * Atheros Wireless LAN controller driver for net80211 stack.
 */

#include "if_athvar.h"
#include "ath_cwm.h"
#include "if_ath_amsdu.h"
#include "if_ath_uapsd.h"
#include "if_ath_htc.h"
#include "if_llc.h"
#include "if_ath_quiet.h"
#include "if_ath_mat.h"

#include "asf_amem.h"     /* asf_amem_setup */
#include "asf_print.h"    /* asf_print_setup */

#include "qdf_mem.h"   /* qdf_mem_alloc_outline,free */
#include "qdf_lock.h"
#include "qdf_types.h"
#ifdef ATH_HTC_MII_RXIN_TASKLET
#include "htc_thread.h"
#endif
#include "ieee80211_api.h"
#include <ieee80211_dfs.h>
#include <ieee80211_csa.h>
#include "ieee80211_acs.h"
#include <ath_ald_external.h>
#include <ieee80211_ald.h>
#include <if_smart_ant.h>
#include <ald_netlink.h>
#include "ieee80211_radiotap.h"

#if ATH_SUPPORT_DFS
#include "ath_dfs_structs.h"
#include "ath_dfs_api.h"
#endif
#if ATH_DEBUG
extern unsigned long ath_rtscts_enable;      /* defined in ah_osdep.c  */
#endif
#ifdef ATH_SUPPORT_DFS
extern unsigned long ath_ignoredfs_enable;      /* defined in ah_osdep.c  */
#endif
#include "ath_lmac_state_event.h"

extern void ieee80211_cts_done(bool txok);

#if ATH_SUPPORT_WRAP
/*
 * WRAP hardware crypto configuration options.
 *
 * Do NOT change it without understanding of hardware Azimuth Mode.
 */
#define WRAP_HW_DECRYPT_PSTA_TKIP 1 /* pass basic ping test for WASP 1.3 and Peacock */
#define WRAP_HW_DECRYPT_PSTA_WEP  0 /* do not enable for WASP 1.3 and Peacock */
#define WRAP_HW_ENCRYPT_WRAP_CCMP 1 /* works for all chips */
#define WRAP_HW_ENCRYPT_WRAP_TKIP 1 /* works for all chips */
#define WRAP_HW_ENCRYPT_WRAP_WEP  0 /* works, but align it w/ WRAP_HW_DECRYPT_PSTA_WEP */
#endif

#define CHAN_UTIL_EVENT_FREQ    ( ATH_PERIODIC_STATS_INTVAL / ATH_CHAN_BUSY_INTVAL )

#if UNIFIED_SMARTANTENNA
int enable_smart_antenna_da = 0;
module_param(enable_smart_antenna_da, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(enable_smart_antenna_da,"Enable Smart Antenna for Direct Attach");
#endif
void da_reset_wifi(struct ath_softc *sc,struct ieee80211com *ic);
int osif_vap_hardstart(struct sk_buff *skb, struct net_device *dev);

#if DBDC_REPEATER_SUPPORT
extern struct global_ic_list ic_list;
#endif

extern int ath_get_radio_index(struct net_device *netdev);
extern int asf_adf_attach(void);

/*
 * Mapping between WIRELESS_MODE_XXX to IEEE80211_MODE_XXX
 */
static enum ieee80211_phymode
ath_mode_map[WIRELESS_MODE_MAX] = {
    IEEE80211_MODE_11A,
    IEEE80211_MODE_11B,
    IEEE80211_MODE_11G,
    IEEE80211_MODE_TURBO_A,
    IEEE80211_MODE_TURBO_G,
    IEEE80211_MODE_11NA_HT20,
    IEEE80211_MODE_11NG_HT20,
    IEEE80211_MODE_11NA_HT40PLUS,
    IEEE80211_MODE_11NA_HT40MINUS,
    IEEE80211_MODE_11NG_HT40PLUS,
    IEEE80211_MODE_11NG_HT40MINUS,
    IEEE80211_MODE_MAX          /* XXX: for XR */
};

/* UMACDFS: Find correct header file */

static void ath_net80211_rate_node_update(ieee80211_handle_t ieee, ieee80211_node_t node, int isnew);
static int ath_key_alloc(struct ieee80211vap *vap, struct ieee80211_key *k);
static int ath_key_delete(struct ieee80211vap *vap, const struct ieee80211_key *k,
                          struct ieee80211_node *ninfo);
static int
ath_key_map(struct ieee80211vap *vap, const struct ieee80211_key *k,
            const u_int8_t bssid[IEEE80211_ADDR_LEN], struct ieee80211_node *ni);

static int __ath_key_set(struct ieee80211vap *vap, const struct ieee80211_key *k,
                         const u_int8_t peermac[IEEE80211_ADDR_LEN], int is_proxy_addr);
static int ath_key_set(struct ieee80211vap *vap, struct ieee80211_key *k,
                       const u_int8_t peermac[IEEE80211_ADDR_LEN]);
#if ATH_SUPPORT_WRAP
static int ath_setup_proxykey(struct ieee80211vap *vap, const u_int8_t *proxy_mac,
                              struct ieee80211_key *k);
static int ath_setup_wrap_key(struct ieee80211vap *vap, const u_int8_t *mac,
                              struct ieee80211_key *k);
#endif
static void ath_key_update_begin(struct ieee80211vap *vap);
static void ath_key_update_end(struct ieee80211vap *vap);
static void ath_update_ps_mode(struct ieee80211vap *vap);
static void ath_net80211_set_config(struct ieee80211vap* vap);
static void ath_setTxPowerLimit(struct ieee80211com *ic, u_int32_t limit, u_int16_t tpcInDb, u_int32_t is2GHz);
static void ath_setTxPowerAdjust(struct ieee80211com *ic, int32_t Adjust, u_int32_t is2GHz);
static u_int8_t ath_net80211_get_common_power(struct ieee80211com *ic, struct ieee80211_channel *chan);
static u_int32_t ath_net80211_get_maxphyrate(struct ieee80211com *ic, struct ieee80211_node *ni);

static int  ath_getrmcounters(struct ieee80211com *ic, struct ieee80211_mib_cycle_cnts *pCnts);
static void ath_setReceiveFilter(struct ieee80211com *ic, u_int32_t filter);
static void ath_set_rx_sel_plcp_header(struct ieee80211com *ic, int8_t selEvm,
                                       int8_t justQuery);
static void ath_net80211_set_beacon_interval(struct ieee80211com *ic);

#ifdef ATH_CCX
static void ath_clearrmcounters(struct ieee80211com *ic);
static int  ath_updatermcounters(struct ieee80211com *ic, struct ath_mib_mac_stats* pStats);
static u_int64_t ath_getTSF64(struct ieee80211com *ic);
static int ath_getMfgSerNum(struct ieee80211com *ic, u_int8_t *pSrn, int limit);
static int ath_net80211_get_chanData(struct ieee80211com *ic, struct ieee80211_channel *pChan, struct ath_chan_data *pData);
static u_int32_t ath_net80211_get_curRSSI(struct ieee80211com *ic);
#endif
static u_int32_t ath_getTSF32(struct ieee80211com *ic);
static u_int16_t ath_net80211_find_countrycode(struct ieee80211com *ic, char* isoName);
static void ath_setup_keycacheslot(struct ieee80211_node *ni);
static void ath_net80211_log_text(struct ieee80211com *ic, char *text);
static int ath_vap_join(struct ieee80211vap *vap);
static int ath_vap_up(struct ieee80211vap *vap) ;
static int ath_vap_listen(struct ieee80211vap *vap) ;
static bool ath_net80211_need_beacon_sync(struct ieee80211com *ic);
static u_int32_t ath_net80211_wpsPushButton(struct ieee80211com *ic);
#if ATH_ANT_DIV_COMB
static void ath_vap_sa_normal_scan_handle(struct ieee80211vap *vap, enum ieee80211_state_event event);
#endif


#if ATH_SUPPORT_WIFIPOS
static void ath_net80211_pause_node(struct ieee80211com *ic, struct ieee80211_node* ni, bool pause);
#endif


#if IEEE80211_DEBUG_NODELEAK
static void ath_net80211_debug_print_nodeq_info(struct ieee80211_node *ni);
#endif
static void
ath_net80211_pwrsave_set_state(struct ieee80211com *ic, IEEE80211_PWRSAVE_STATE newstate);

static u_int32_t ath_net80211_gettsf32(struct ieee80211com *ic);
static u_int64_t ath_net80211_gettsf64(struct ieee80211com *ic);
#if ATH_SUPPORT_WIFIPOS
static u_int64_t ath_net80211_gettsftstamp(struct ieee80211com *ic);
static int ath_net80211_vap_reap_txqs(struct ieee80211com *ic, struct ieee80211vap *vap);
#endif
static void ath_net80211_update_node_txpow(struct ieee80211vap *vap, u_int16_t txpowlevel, u_int8_t *addr);
#if ATH_WOW_OFFLOAD
static int ath_net80211_wowoffload_rekey_misc_info_set(struct ieee80211com *ic, struct wow_offload_misc_info *wow_info);
static int
ath_net80211_wowoffload_txseqnum_update(struct ieee80211com *ic, struct ieee80211_node *ni, u_int32_t tidno, u_int16_t seqnum);
static int
ath_net80211_wow_offload_info_get(struct ieee80211com *ic, void *buf, u_int32_t param);
#endif /* ATH_WOW_OFFLOAD */
/*static*/ void ath_net80211_enable_tpc(struct ieee80211com *ic);
/*static*/ void ath_net80211_get_max_txpwr(struct ieee80211com *ic, u_int32_t* txpower );
static int ath_net80211_vap_pause_control (struct ieee80211com *ic, struct ieee80211vap *vap, bool pause);
static void ath_net80211_get_bssid(ieee80211_handle_t ieee,  struct
        ieee80211_frame_min *shdr, u_int8_t *bssid);
#ifdef ATH_TX99_DIAG
static struct ieee80211_channel *
ath_net80211_find_channel(struct ath_softc *sc, int ieee, u_int8_t des_cfreq2, enum ieee80211_phymode mode);
#endif
static void ath_net80211_set_ldpcconfig(ieee80211_handle_t ieee, u_int8_t ldpc);
static void ath_net80211_set_stbcconfig(ieee80211_handle_t ieee, u_int8_t stbc, u_int8_t istx);

#ifdef ATH_SUPPORT_TxBF     // For TxBF RC
static int  ath_net80211_txbf_alloc_key(struct ieee80211com *ic, struct ieee80211_node *ni);
static void ath_net80211_txbf_set_key(struct ieee80211com *ic, struct ieee80211_node *ni);
static void ath_net80211_init_sw_cvtimeout(struct ieee80211com *ic, struct ieee80211_node *ni);
#ifdef TXBF_DEBUG
static void ath_net80211_txbf_check_cvcache(struct ieee80211com *ic, struct ieee80211_node *ni);
#endif
static void ath_net80211_txbf_stats_rpt_inc(struct ieee80211com *ic, struct ieee80211_node *ni);
static void ath_net80211_txbf_set_rpt_received(struct ieee80211com *ic, struct ieee80211_node *ni);
#endif
static void ath_net80211_enablerifs_ldpcwar(struct ieee80211_node *ni, bool value);
static void ath_net80211_process_uapsd_trigger(struct ieee80211com *ic, struct ieee80211_node *ni, bool enforce_max_sp, bool *sent_eosp);
static int ath_net80211_is_hwbeaconproc_active(struct ieee80211com *ic);
static void ath_net80211_hw_beacon_rssi_threshold_enable(struct ieee80211com *ic, u_int32_t rssi_threshold);
static void ath_net80211_hw_beacon_rssi_threshold_disable(struct ieee80211com *ic);

#if UMAC_SUPPORT_VI_DBG
static void ath_net80211_set_vi_dbg_restart(struct ieee80211com *ic);
static void ath_net80211_set_vi_dbg_log(struct ieee80211com *ic, bool enable);
#endif

static void ath_net80211_set_noise_detection_param(struct ieee80211com *ic, int cmd,int val);
static void ath_net80211_get_noise_detection_param(struct ieee80211com *ic, int cmd,int *);
static u_int32_t ath_net80211_get_txbuf_free(struct ieee80211com *ic);
#if ATH_SUPPORT_KEYPLUMB_WAR
static int ath_key_checkandplumb(struct ieee80211vap *vap, struct ieee80211_node *ni);
#endif
#if UNIFIED_SMARTANTENNA
static void ath_net80211_smart_ant_enable(struct ieee80211com *ic,
                uint32_t enable, uint32_t mode, uint32_t rx_antenna);
static int ath_net80211_smart_ant_update_txfeedback(struct ieee80211_node *ni,
                void *tx_feedback);
static int ath_net80211_smart_ant_update_rxfeedback(ieee80211_handle_t ieee,
                wbuf_t wbuf, void *rx_feedback);
static void ath_net80211_smart_ant_set_rx_antenna(struct ieee80211com *ic,
                u_int32_t antenna);
static void ath_net80211_smart_ant_set_tx_antenna(struct ieee80211_node *ni,
                u_int32_t *antenna_array);
static void ath_net80211_smart_ant_set_tx_default_antenna(
                struct ieee80211com *ic, u_int32_t antenna);
static void ath_net80211_smart_ant_set_training_info(struct ieee80211_node *ni,
                uint32_t *rate_array, uint32_t *antenna_array, uint32_t numpkts);
static void ath_net80211_smart_ant_prepare_rateset(struct ieee80211com *ic,
                 struct ieee80211_node *ni, struct sa_rate_info *rate_info);
static int ath_net80211_smart_ant_setparam(ieee80211_handle_t, char *params);
static int ath_net80211_smart_ant_getparam(ieee80211_handle_t, char *params);
static void ath_net80211_smart_ant_set_node_config_ops(struct ieee80211_node *ni,
                uint32_t cmd_id, uint16_t args_count, u_int32_t args_arr[]);
#endif

#if ATH_TX_DUTY_CYCLE
int ath_net80211_enable_tx_duty_cycle(struct ieee80211com *ic, int active_pct);
int ath_net80211_disable_tx_duty_cycle(struct ieee80211com *ic);
int ath_net80211_get_tx_duty_cycle(struct ieee80211com *ic);
int ath_net80211_get_tx_busy(struct ieee80211com *ic);
#endif

#if ATH_SUPPORT_HYFI_ENHANCEMENTS
int ath_net80211_add_hmmc(struct ieee80211vap *vap, u_int32_t ip, u_int32_t mask);
int ath_net80211_del_hmmc(struct ieee80211vap *vap, u_int32_t ip, u_int32_t mask);
#endif
extern void smartantenna_sm(struct ieee80211_node *ni);
#if ATH_SUPPORT_HMMC
static int ath_net80211_add_hmmc(struct ieee80211com *ic, u_int32_t ip, u_int32_t mask);
static int ath_net80211_del_hmmc(struct ieee80211com *ic, u_int32_t ip, u_int32_t mask);
#endif

static u_int32_t  ath_net80211_get_total_per(ieee80211_handle_t ieee);
static u_int64_t  ath_net80211_get_tx_hw_retries(struct ieee80211com *ic);
static u_int64_t  ath_net80211_get_tx_hw_success(struct ieee80211com *ic);
#if UMAC_SUPPORT_WNM
static wbuf_t
ath_net80211_timbcast_alloc(ieee80211_handle_t ieee, int if_id, int highrate, ieee80211_tx_control_t *txctl);
static int
ath_net80211_timbcast_update(ieee80211_handle_t ieee, int if_id, wbuf_t);
static int
ath_net80211_timbcast_highrate(ieee80211_handle_t ieee, int if_id);
static int
ath_net80211_timbcast_lowrate(ieee80211_handle_t ieee, int if_id);
static int
ath_net80211_timbcast_cansend(ieee80211_handle_t ieee, int if_id);
static int
ath_net80211_wnm_fms_enabled(ieee80211_handle_t ieee, int if_id);
static int
ath_net80211_timbcast_enabled(ieee80211_handle_t ieee, int if_id);
#endif

#if LMAC_SUPPORT_POWERSAVE_QUEUE
static u_int8_t
ath_net80211_get_lmac_pwrsaveq_len(struct ieee80211com *ic, struct ieee80211_node *ni, u_int8_t frame_type);
static int
ath_net80211_node_pwrsaveq_send(struct ieee80211com *ic, struct ieee80211_node *ni, u_int8_t frame_type);
static void
ath_net80211_node_pwrsaveq_flush(struct ieee80211com *ic, struct ieee80211_node *ni);
static int
ath_net80211_node_pwrsaveq_drain(struct ieee80211com *ic, struct ieee80211_node *ni);
static int
ath_net80211_node_pwrsaveq_age(struct ieee80211com *ic, struct ieee80211_node *ni);
static void
ath_net80211_node_pwrsaveq_get_info(struct ieee80211com *ic, struct ieee80211_node *ni,
                                 ieee80211_node_saveq_info *info);
static void
ath_net80211_node_pwrsaveq_set_param(struct ieee80211com *ic, struct ieee80211_node *ni,
                                  enum ieee80211_node_saveq_param param, u_int32_t val);
#endif
#ifdef ATH_SUPPORT_DFS
static int ath_net80211_attach_dfs(struct ieee80211com *ic, void *pCap, void *radar_info);
static int ath_net80211_detach_dfs(struct ieee80211com *ic);
static int ath_net80211_enable_dfs(struct ieee80211com *ic, int *is_fastclk, void *pe);
static int ath_net80211_disable_dfs(struct ieee80211com *ic, int no_cac);
static void ath_net80211_dfs_rx_rcsa(struct ieee80211com *ic);
static void ath_net80211_dfs_cancel_waitfor_csa_timer(struct ieee80211com *ic);
static int ath_net80211_dfs_get_thresholds(struct ieee80211com *ic, void *pe);
static void ath_net80211_dfs_clist_update(struct ieee80211com *ic, int cmd,
             struct dfs_nol_chan_entry *nollist, int nentries);
static int ath_net80211_get_mib_cycle_counts_pct(struct ieee80211com *ic,
                                u_int32_t *rxc_pcnt, u_int32_t *rxf_pcnt, u_int32_t *txf_pcnt);
int ath_net80211_get_ext_busy(struct ieee80211com *ic);
#endif /* ATH_SUPPORT_DFS */
#if ATH_SUPPORT_FLOWMAC_MODULE
int ath_net80211_get_flowmac_enabled_state(struct ieee80211com *ic);
#endif
static int ath_net80211_dfs_proc_phyerr(ieee80211_handle_t ieee, void *buf, u_int16_t datalen, u_int8_t rssi,
                        u_int8_t ext_rssi, u_int32_t rs_tstamp, u_int64_t full_tsf);
static int ath_net80211_wds_is_enabled(ieee80211_handle_t ieee);
static void ath_net80211_restore_encr_keys(ieee80211_handle_t ieee);
#if ATH_SUPPORT_TIDSTUCK_WAR
static void ath_net80211_clear_rxtid(struct ieee80211com *ic, struct ieee80211_node *ni);
static void ath_net80211_rxtid_delba(ieee80211_node_t node, u_int8_t tid);
#endif

static void ath_config_rx_intr_mitigation(struct ieee80211com *ic, u_int32_t enable);
static WIRELESS_MODE ath_net80211_get_vap_bss_mode(ieee80211_handle_t ieee, ieee80211_node_t node);
static int ath_net80211_acs_set_param(ieee80211_handle_t ieee, int param, int flag);
static int ath_net80211_acs_get_param(ieee80211_handle_t ieee,int param);
#if ATH_TxBF_DYNAMIC_LOF_ON_N_CHAIN_MASK
static void ath_net80211_txbf_loforceon_update(struct ieee80211com *ic,bool loforcestate);
#endif
static int ath_net80211_get_rx_signal_dbm(struct ieee80211com *ic, int8_t *signal_dbm);
static void ath_net80211_node_pspoll(struct ieee80211_node* ni, bool value);
static int ath_net80211_tr69_process_request(struct ieee80211vap *vap, int cmdid, void * arg1, void *arg2);
static int ath_net80211_set_enable_min_rssi(ieee80211_handle_t ieee, u_int8_t val);
static u_int8_t ath_net80211_get_enable_min_rssi(ieee80211_handle_t ieee);
static int ath_net80211_set_min_rssi(ieee80211_handle_t ieee, int rssi);
static int ath_net80211_get_min_rssi(ieee80211_handle_t ieee);
static bool ath_modify_bcn_rate(struct ieee80211vap *vap);
static void ath_txpow_mgmt(struct ieee80211vap *vap,int frame_subtype,u_int8_t transmit_power);
#if ATH_DEBUG
/*
 * dprintf - it will end up calling the ath_print function defined in
 * ath_main.c since the if_ath layer and ath_dev layer share the same
 * asf_print_ctrl object with which the custom print function ath_print
 * is registered.
 */
void dprintf(
    struct ath_softc *sc, unsigned category, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    asf_vprint_category(&sc->sc_print, category, fmt, args);
    va_end(args);
}
#endif

#if ATH_SUPPORT_SPECTRAL

static void ath_net80211_start_spectral_scan(struct ieee80211com *ic, u_int8_t priority)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->ath_dev_start_spectral_scan(scn->sc_dev, priority);
}
static void ath_net80211_stop_spectral_scan(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->ath_dev_stop_spectral_scan(scn->sc_dev);
}

static void ath_net80211_record_chan_info(struct ieee80211com *ic,
                                          u_int16_t chan_num,
                                          bool are_chancnts_valid,
                                          u_int32_t scanend_clr_cnt,
                                          u_int32_t scanstart_clr_cnt,
                                          u_int32_t scanend_cycle_cnt,
                                          u_int32_t scanstart_cycle_cnt,
                                          bool is_nf_valid,
                                          int16_t nf,
                                          bool is_per_valid,
                                          u_int32_t per)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->ath_dev_record_chan_info(scn->sc_dev,
                                          chan_num,
                                          are_chancnts_valid,
                                          scanend_clr_cnt,
                                          scanstart_clr_cnt,
                                          scanend_cycle_cnt,
                                          scanstart_cycle_cnt,
                                          is_nf_valid,
                                          nf,
                                          is_per_valid,
                                          per);
}
#endif


static void ath_net80211_cw_interference_handler(ieee80211_handle_t ieee)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ieee80211vap *vap;
    /* Check if CW Interference is already been found and being handled */
    if (ic->cw_inter_found) return;
    spin_lock(&ic->ic_lock);
    /* Set the CW interference flag so that ACS does not bail out */
    ic->cw_inter_found = 1;
    spin_unlock(&ic->ic_lock);
    /* Loop through and figure the first VAP on this radio */
    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
            if (ieee80211_vap_active_is_set(vap) &&
                !wlan_set_channel(vap, IEEE80211_CHAN_ANY, 0)) {
                /* ACS is done on per radio, so calling it once is
                * good enough
                */
                spin_lock(&ic->ic_lock);
                goto done;
            }
        }
    }
    spin_lock(&ic->ic_lock);
    /* Should not come here, something is not right, hope something better happens
     * next time the flag is set
     */
    /*
     * reset cw_interference found flag since ACS is not triggered, so
     * it can change the channel on next CW intf detection
     */
    ic->cw_inter_found = 0;

//
done:
    spin_unlock(&ic->ic_lock);

}


#if ATH_SUPPORT_FLOWMAC_MODULE
static void
ath_net80211_flowmac_notify_state (ieee80211_handle_t ieee, int en)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ieee80211vap *vap;

    if (!ic) return;
    spin_lock(&ic->ic_lock);
    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if (vap) {
            vap->iv_flowmac = en;
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Notifying VAP %p  enabled state %d \n", vap, en);
        }
    }
    spin_unlock(&ic->ic_lock);
}
#endif

#if ATH_SUPPORT_IQUE
void ath_net80211_hbr_settrigger(ieee80211_node_t node, int event);
#endif

#if ATH_SUPPORT_VOWEXT
static u_int16_t ath_net80211_get_aid(ieee80211_node_t node);
#endif

static u_int32_t ath_net80211_txq_depth(struct ieee80211com *ic);
static u_int32_t ath_net80211_txq_depth_ac(struct ieee80211com *ic, int ac);
u_int32_t ath_net80211_getmfpsupport(struct ieee80211com *ic);
static void ath_net80211_setmfpQos(struct ieee80211com *ic, u_int32_t dot11w);

static int
ath_net80211_reg_vap_info_notify(
    struct ieee80211vap                 *vap,
    ath_vap_infotype                    infotype_mask,
    ieee80211_vap_ath_info_notify_func  callback,
    void                                *arg);

static int
ath_net80211_vap_info_update_notify(
    struct ieee80211vap                 *vap,
    ath_vap_infotype                    infotype_mask);

static int
ath_net80211_dereg_vap_info_notify(
    struct ieee80211vap                 *vap);

static int
ath_net80211_vap_info_get(
    struct ieee80211vap *vap,
    ath_vap_infotype    infotype,
    u_int32_t           *param1,
    u_int32_t           *param2);

/*---------------------
 * Support routines
 *---------------------
 */
static u_int
ath_chan2flags(struct ieee80211_channel *chan)
{
    u_int flags;
    static const u_int modeflags[] = {
        0,                   /* IEEE80211_MODE_AUTO           */
        CHANNEL_A,           /* IEEE80211_MODE_11A            */
        CHANNEL_B,           /* IEEE80211_MODE_11B            */
        CHANNEL_PUREG,       /* IEEE80211_MODE_11G            */
        0,                   /* IEEE80211_MODE_FH             */
        CHANNEL_108A,        /* IEEE80211_MODE_TURBO_A        */
        CHANNEL_108G,        /* IEEE80211_MODE_TURBO_G        */
        CHANNEL_A_HT20,      /* IEEE80211_MODE_11NA_HT20      */
        CHANNEL_G_HT20,      /* IEEE80211_MODE_11NG_HT20      */
        CHANNEL_A_HT40PLUS,  /* IEEE80211_MODE_11NA_HT40PLUS  */
        CHANNEL_A_HT40MINUS, /* IEEE80211_MODE_11NA_HT40MINUS */
        CHANNEL_G_HT40PLUS,  /* IEEE80211_MODE_11NG_HT40PLUS  */
        CHANNEL_G_HT40MINUS, /* IEEE80211_MODE_11NG_HT40MINUS */
    };

    flags = modeflags[ieee80211_chan2mode(chan)];

    if (IEEE80211_IS_CHAN_HALF(chan)) {
        flags |= CHANNEL_HALF;
    } else if (IEEE80211_IS_CHAN_QUARTER(chan)) {
        flags |= CHANNEL_QUARTER;
    }

    return flags;
}

/*
 * Compute numbner of chains based on chainmask
 */
static INLINE int
ath_get_numchains(int chainmask)
{
    int chains;

    switch (chainmask) {
    default:
        chains = 0;
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: invalid chainmask\n", __func__);
        break;
    case 1:
    case 2:
    case 4:
        chains = 1;
        break;
    case 3:
    case 5:
    case 6:
        chains = 2;
        break;
    case 7:
        chains = 3;
        break;
    }
    return chains;
}

/*
 * Determine the capabilities that are passed to rate control module.
 */
u_int32_t
ath_set_ratecap(struct ath_softc_net80211 *scn, struct ieee80211_node *ni,
        struct ieee80211vap *vap)
{
    int numtxchains;
    u_int32_t ratecap;

    ratecap = 0;
    numtxchains =
        ath_get_numchains(scn->sc_ops->have_capability(scn->sc_dev, ATH_CAP_TXCHAINMASK));

#if ATH_SUPPORT_WAPI
    /*
     * WAPI engine only support 2 stream rates at most
     */
    if (ieee80211_vap_wapi_is_set(vap)) {
        int wapimaxtxchains =
            scn->sc_ops->have_capability(scn->sc_dev, ATH_CAP_WAPI_MAXTXCHAINS);
        if (numtxchains > wapimaxtxchains) {
            numtxchains = wapimaxtxchains;
        }
    }
#endif

    /*
     *  Set three stream capability if all of the following are true
     *  - HAL supports three streams
     *  - three chains are available
     *  - remote node has advertised support for three streams
     */
    if (scn->sc_ops->have_capability(scn->sc_dev, ATH_CAP_TS) &&
        (numtxchains == 3) && (ni->ni_streams >= 3))
    {
        ratecap |= ATH_RC_TS_FLAG;
    }
    /*
     *  Set two stream capability if all of the following are true
     *  - HAL supports two streams
     *  - two or more chains are available
     *  - remote node has advertised support for two or more streams
     */
    if (scn->sc_ops->have_capability(scn->sc_dev, ATH_CAP_DS) &&
        (numtxchains >= 2) && (ni->ni_streams >= 2))
    {
        ratecap |= ATH_RC_DS_FLAG;
    }

    /*
     * With SM power save, only singe stream rates can be used.
     */
    if((ni->ni_htcap & IEEE80211_HTCAP_C_SM_MASK) == IEEE80211_HTCAP_C_SMPOWERSAVE_STATIC) {
        ratecap &= ~(ATH_RC_TS_FLAG|ATH_RC_DS_FLAG);
    }
    /*
     * If either of Implicit or Explicit TxBF is enabled for
     * the remote node, set the rate capability.
     */
#ifdef  ATH_SUPPORT_TxBF
    if ((ni->ni_explicit_noncompbf == AH_TRUE) ||
        (ni->ni_explicit_compbf == AH_TRUE) ||
        (ni->ni_implicit_bf == AH_TRUE))
    {
        ratecap |= ATH_RC_TXBF_FLAG;
    }
#endif
    return ratecap;
}

WIRELESS_MODE
ath_ieee2wmode(enum ieee80211_phymode mode)
{
    WIRELESS_MODE wmode;

    for (wmode = 0; wmode < WIRELESS_MODE_MAX; wmode++) {
        if (ath_mode_map[wmode] == mode)
            break;
    }

    return wmode;
}

static void ath_net80211_set_beacon_interval(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    if (scn->sc_ops->set_beacon_interval) {
        scn->sc_ops->set_beacon_interval(scn->sc_dev, ic->ic_intval);
    }
}

/* Query ATH layer for tx/rx chainmask and set in the com object via OS stack */
static void
ath_set_chainmask(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    int tx_chainmask = 0, rx_chainmask = 0;

    if (!scn->sc_ops->ath_get_config_param(scn->sc_dev, ATH_PARAM_TXCHAINMASK,
                                           &tx_chainmask))
        ieee80211com_set_tx_chainmask(ic, (u_int8_t) tx_chainmask);

    if (!scn->sc_ops->ath_get_config_param(scn->sc_dev, ATH_PARAM_RXCHAINMASK,
                                           &rx_chainmask))
        ieee80211com_set_rx_chainmask(ic, (u_int8_t) rx_chainmask);
}

#if ATH_SUPPORT_WAPI
/* Query ATH layer for max tx/rx chain supported by WAPI engine */
static void
ath_set_wapi_maxchains(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    ieee80211com_set_wapi_max_tx_chains(ic,
        (u_int8_t)scn->sc_ops->have_capability(scn->sc_dev, ATH_CAP_WAPI_MAXTXCHAINS));
    ieee80211com_set_wapi_max_rx_chains(ic,
        (u_int8_t)scn->sc_ops->have_capability(scn->sc_dev, ATH_CAP_WAPI_MAXRXCHAINS));
}
#endif

#ifdef  ATH_SUPPORT_TxBF
static void
ath_get_nodetxbfcaps(struct ieee80211_node *ni, ieee80211_txbf_caps_t **txbf)
{
    (*txbf)->channel_estimation_cap    = ni->ni_txbf.channel_estimation_cap;
    (*txbf)->csi_max_rows_bfer         = ni->ni_txbf.csi_max_rows_bfer;
    (*txbf)->comp_bfer_antennas        = ni->ni_txbf.comp_bfer_antennas;
    (*txbf)->noncomp_bfer_antennas     = ni->ni_txbf.noncomp_bfer_antennas;
    (*txbf)->csi_bfer_antennas         = ni->ni_txbf.csi_bfer_antennas;
    (*txbf)->minimal_grouping          = ni->ni_txbf.minimal_grouping;
    (*txbf)->explicit_comp_bf          = ni->ni_txbf.explicit_comp_bf;
    (*txbf)->explicit_noncomp_bf       = ni->ni_txbf.explicit_noncomp_bf;
    (*txbf)->explicit_csi_feedback     = ni->ni_txbf.explicit_csi_feedback;
    (*txbf)->explicit_comp_steering    = ni->ni_txbf.explicit_comp_steering;
    (*txbf)->explicit_noncomp_steering = ni->ni_txbf.explicit_noncomp_steering;
    (*txbf)->explicit_csi_txbf_capable = ni->ni_txbf.explicit_csi_txbf_capable;
    (*txbf)->calibration               = ni->ni_txbf.calibration;
    (*txbf)->implicit_txbf_capable     = ni->ni_txbf.implicit_txbf_capable;
    (*txbf)->tx_ndp_capable            = ni->ni_txbf.tx_ndp_capable;
    (*txbf)->rx_ndp_capable            = ni->ni_txbf.rx_ndp_capable;
    (*txbf)->tx_staggered_sounding     = ni->ni_txbf.tx_staggered_sounding;
    (*txbf)->rx_staggered_sounding     = ni->ni_txbf.rx_staggered_sounding;
    (*txbf)->implicit_rx_capable       = ni->ni_txbf.implicit_rx_capable;
}
#endif

/*
 * When the external power to our chip is switched off, the entire keycache memory
 * contains random values. This can happen when the system goes to hibernate.
 * We should re-initialized the keycache to prevent unwanted behavior.
 *
 */
static void
ath_clear_keycache(struct ath_softc_net80211 *scn)
{
    int i;
    struct ath_softc *sc = scn->sc_dev;
    struct ath_hal *ah = sc->sc_ah;

    for (i = 0; i < sc->sc_keymax; i++) {
        ath_hal_keyreset(ah, (u_int16_t)i);
    }
}

static void
ath_restore_keycache(struct ath_softc_net80211 *scn)
{
    struct ieee80211com *ic = &scn->sc_ic;
    ath_net80211_restore_encr_keys(ic);
}

/*------------------------------------------------------------
 * Callbacks for net80211 module, which will be hooked up as
 * ieee80211com vectors (ic->ic_xxx) accordingly.
 *------------------------------------------------------------
 */

static int
ath_init(struct ieee80211com *ic)
{
#define GREEN_AP_SUSPENDED    2
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ieee80211_channel *cc;
    HAL_CHANNEL hchan;
    int error = 0;

    /* stop protocol stack first */
    ieee80211_stop_running(ic);

    /* setup initial channel */
    cc = ieee80211_get_current_channel(ic);
    hchan.channel = ieee80211_chan2freq(ic, cc);
    hchan.channel_flags = ath_chan2flags(cc);

    /* open ath_dev */
    error = scn->sc_ops->open(scn->sc_dev, &hchan);
    if (error)
        return error;

    /* Clear and restore keycache, needed for some parts which put
     * random values when switched off */
    ATH_CLEAR_KEYCACHE(scn);
    ATH_RESTORE_KEYCACHE(scn);

    /* Set tx/rx chainmask */
    ath_set_chainmask(ic);

#if ATH_SUPPORT_WAPI
    /* Set WAPI max tx/rx chain */
    ath_set_wapi_maxchains(ic);
#endif

    /* Initialize CWM (Channel Width Management) */
    cwm_init(ic);

    /* kick start 802.11 state machine */
    ieee80211_start_running(ic);

    /* update max channel power to max regpower of current channel */
    ieee80211com_set_curchanmaxpwr(ic, cc->ic_maxregpower);

	/*
	** Enable the green AP function
	*/
    if(ic->ic_green_ap_get_enable(ic) == GREEN_AP_SUSPENDED) /* if it suspended */
    {
        ic->ic_green_ap_set_enable(ic,1);
    }
#undef GREEN_AP_SUSPENDED
    return error;
}

static int
ath_ic_stop(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_softc          *sc  = ATH_DEV_TO_SC(scn->sc_dev);

    da_reset_wifi(sc,ic);

    return 0;
}

static void ath_vap_iter_vap_create(void *arg, wlan_if_t vap)
{

    int *pid_mask = (int *) arg;
    u_int8_t myaddr[IEEE80211_ADDR_LEN];
    u_int8_t id = 0;
    struct ieee80211com *ic = vap->iv_ic;

#if ATH_SUPPORT_WRAP
    struct ath_vap_net80211 *avn = ATH_VAP_NET80211(vap);

    /* ProxySTA VAP has its own mac address and doesn't use mBSSID */
    if (avn->av_is_psta)
        return;
#endif
    ieee80211vap_get_macaddr(vap, myaddr);
    ATH_GET_VAP_ID(myaddr, wlan_vap_get_hw_macaddr(vap), id);
    (*pid_mask) |= (1 << id);
}

/**
 * createa  vap.
 * if IEEE80211_CLONE_BSSID flag is set then it will  allocate a new mac address.
 * if IEEE80211_CLONE_BSSID flag is not set then it will use passed in bssid as
 * the mac adddress.
 */

static struct ieee80211vap *
ath_vap_create(struct ieee80211com *ic,
               int                 opmode,
               int                 scan_priority_base,
               int                 flags,
               const u_int8_t      bssid[IEEE80211_ADDR_LEN],
               const u_int8_t      mataddr[IEEE80211_ADDR_LEN],
               void               *osifp_handle)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_vap_net80211 *avn;
    u_int8_t myaddr[IEEE80211_ADDR_LEN];
    struct ieee80211vap *vap;
    int id = 0, id_mask = 0;
    int nvaps = 0, nactivevaps = 0;
    int ic_opmode, ath_opmode = opmode;
    int nostabeacons = 0;
    struct ath_vap_config ath_vap_config;
#if ATH_SUPPORT_WRAP
    int ret;
#endif

    DPRINTF(scn, ATH_DEBUG_STATE,
            "%s : enter., opmode=%x, flags=0x%x\n",
            __func__,
	    opmode,
	    flags
	   );

    /* do a full search to mark all the allocated vaps */
    nvaps = wlan_iterate_vap_list(ic,ath_vap_iter_vap_create,(void *) &id_mask);
    nactivevaps = ieee80211_vaps_active(ic);
    id_mask |= scn->sc_prealloc_idmask; /* or in allocated ids */

    switch (opmode) {
    case IEEE80211_M_STA:   /* ap+sta for repeater application */
#if 0
        if ((nvaps != 0) && (!(flags & IEEE80211_NO_STABEACONS)))
            return NULL;   /* If using station beacons, must first up */
#endif

		/*Condition to block creation of more than one STA vap on non-wrap mode*/
		if((scn->sc_nstavaps > 0)
#if ATH_SUPPORT_WRAP
				&& (!scn->sc_npstavaps)
#endif
		  ){
			QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n\n A STA is already created. Not creating this STA\n\n");
			return NULL;
		}

#if ATH_SUPPORT_WRAP
        /* ProxySTA VAP assumes IEEE80211_NO_STABEACONS */
        if (flags & IEEE80211_CLONE_MACADDR) {
            flags |= IEEE80211_NO_STABEACONS;
        }
#endif
        if (flags & IEEE80211_NO_STABEACONS) {
            nostabeacons = 1;
            ic_opmode = IEEE80211_M_HOSTAP;	/* Run with chip in AP mode */
        } else {
            ic_opmode = opmode;
        }
        break;
    case IEEE80211_M_IBSS:
    case IEEE80211_M_MONITOR:
#if 0
    /*
     * TBD: Win7 usually has two STA ports created when configure one port in IBSS.
     */
        if (nvaps != 0)     /* only one */
            return NULL;
#endif
        ic_opmode = opmode;
        ath_opmode = opmode;
        break;
    case IEEE80211_M_HOSTAP:
    case IEEE80211_M_WDS:
        ic_opmode = IEEE80211_M_HOSTAP;
        break;
    case IEEE80211_M_BTAMP:
        ic_opmode = IEEE80211_M_HOSTAP;
        ath_opmode = IEEE80211_M_HOSTAP;
        break;
    default:
        return NULL;
    }

    /*
     * allocate protocol compliand P2P device adress
     * if p2p Device vap is being created and it is not allocated already.
     */
    if (flags & IEEE80211_P2PDEV_VAP) {
        id = ATH_P2PDEV_IF_ID;
    } else if ((flags & IEEE80211_CLONE_BSSID) &&
        nvaps != 0 && opmode != IEEE80211_M_WDS &&
        scn->sc_ops->have_capability(scn->sc_dev, ATH_CAP_BSSIDMASK)) {
        /*
         * Hardware supports the bssid mask and a unique bssid was
         * requested.  Assign a new mac address and expand our bssid
         * mask to cover the active virtual ap's with distinct
         * addresses.
         */
        // KASSERT(nvaps <= ATH_BCBUF, ("too many virtual ap's: %d", nvaps));
        for (id = 0; id < ATH_BCBUF; id++) {
            /* get the first available slot */
            if ((id_mask & (1 << id)) == 0)
                break;
        }
    }

#if ATH_SUPPORT_WRAP
    if (flags & IEEE80211_CLONE_MACADDR) {
        for (id = 0; id < ATH_VAPSIZE; id++) {
            /* get the first available slot */
            if ((id_mask & (1 << id)) == 0)
                break;
        }
    } else
#endif
    if ((flags & IEEE80211_CLONE_BSSID) == 0 ) {
        /* do not clone use the one passed in */

        /* extract the id from the bssid */
        ATH_GET_VAP_ID(bssid, ic->ic_my_hwaddr, id);
        if ( (scn->sc_prealloc_idmask & (1 << id)) == 0) {
            /* the mac address was not pre allocated with ath_vap_alloc_macaddr */
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: the vap mac address was not pre allocated \n",__func__);
            return NULL;
        }

        IEEE80211_ADDR_COPY(myaddr,ic->ic_my_hwaddr);
        /* generate the mac address from id and sanity check */
        ATH_SET_VAP_BSSID(myaddr,ic->ic_my_hwaddr, id);
        if (!IEEE80211_ADDR_EQ(bssid,myaddr)) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: invalid (not locally administered) mac address was passed\n",__func__);
            return NULL;
        }
    }
#if ATH_SUPPORT_WRAP
    if (flags & IEEE80211_CLONE_MACADDR) {
        if(id >= ATH_VAPSIZE) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "exceeding limit of maximum vap allowed Investigate \n");
            return NULL;
        }
    } else if(id >= ATH_BCBUF) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "exceeding limit of maximum vap allowed Investigate \n");
        return NULL;
    }
#else
    if(id >= ATH_BCBUF) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "exceeding limit of maximum vap allowed Investigate \n");
        return NULL;
    }
#endif

    /* create the corresponding VAP */
    avn = (struct ath_vap_net80211 *)OS_ALLOC_VAP(scn->sc_osdev,
                                                    sizeof(struct ath_vap_net80211));
    if (avn == NULL) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Can't allocate memory for ath_vap.\n");
        return NULL;
    }
     if(IEEE80211_CHK_VAP_TARGET(ic)){
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " Target vap exceeded  freeing \n");
        OS_FREE_VAP(avn);
        return NULL;
     }

    avn->av_sc = scn;
    avn->av_if_id = id;

    vap = &avn->av_vap;

    DPRINTF(scn, ATH_DEBUG_STATE,
            " add an interface for ath_dev opmode %d ic_opmode %d .\n",ath_opmode,ic_opmode);

    if (nactivevaps) {
        /*
         * if there are more vaps. do not change the
         * opmode . the opmode will be changed dynamically
         * whne vaps are brough up/down.
         */
        ic_opmode = ic->ic_opmode;
    } else {
        ic->ic_opmode = ic_opmode;
    }
    /* add an interface in ath_dev */
#if WAR_DELETE_VAP
    if (scn->sc_ops->add_interface(scn->sc_dev, id, vap, ic_opmode, ath_opmode, nostabeacons, &vap->iv_athvap))
#else
    if (scn->sc_ops->add_interface(scn->sc_dev, id, vap, ic_opmode, ath_opmode, nostabeacons))
#endif
    {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Unable to add an interface for ath_dev.\n");
        OS_FREE_VAP(avn);
        return NULL;
    }

    /* set the allocated id into the mask */
    scn->sc_prealloc_idmask |= (1 << id);

#if ATH_SUPPORT_WRAP
    if ((opmode == IEEE80211_M_HOSTAP) && (flags & IEEE80211_WRAP_VAP)) {
        avn->av_is_wrap = 1;
        vap->iv_wrap =1;
        ic->ic_nwrapvaps++;
        scn->sc_nwrapvaps++;
    } else if ((opmode == IEEE80211_M_STA) && (flags & IEEE80211_CLONE_MACADDR)) {
        if (!bssid[0] && !bssid[1] && !bssid[2] &&
            !bssid[3] && !bssid[4] && !bssid[5])
        {
            /*
             * Main ProxySTA VAP for uplink WPS PBC and
             * downlink multicast receive.
             */
            avn->av_is_mpsta = 1;
            vap->iv_mpsta = 1;
            scn->sc_mcast_recv_vap = vap;
        } else {
            /*
             * Generally, non-Main ProxySTA VAP's don't need to
             * register umac event handlers. We can save some memory
             * space by doing so. This is required to be done before
             * ieee80211_vap_setup. However we still give the scan
             * capability to the first ATH_NSCAN_PSTA_VAPS non-Main
             * PSTA VAP's. This optimizes the association speed for
             * the first several PSTA VAP's (common case).
             */
#define ATH_NSCAN_PSTA_VAPS 0
            if (scn->sc_nscanpsta >= ATH_NSCAN_PSTA_VAPS)
                vap->iv_no_event_handler = 1;
            else
                scn->sc_nscanpsta++;
        }
        avn->av_is_psta = 1;
        vap->iv_psta =1;
        scn->sc_npstavaps++;
    }

    if (flags & IEEE80211_CLONE_MATADDR) {
        avn->av_use_mat = 1;
        vap->iv_mat = 1;
        OS_MEMCPY(avn->av_mat_addr, mataddr, IEEE80211_ADDR_LEN);
        OS_MEMCPY(vap->iv_mat_addr, mataddr, IEEE80211_ADDR_LEN);
    }

    if (flags & IEEE80211_WRAP_WIRED_STA) {
        vap->iv_wired_pvap = 1;
    }
#endif
    vap->iv_unit = id;
    ieee80211_vap_setup(ic, vap, opmode, scan_priority_base, flags, bssid);
    vap->iv_ampdu = IEEE80211_AMPDU_SUBFRAME_DEFAULT;
    vap->iv_amsdu = 1;

#if ATH_SUPPORT_WRAP
    if (vap->iv_mpsta) {
        vap->iv_ic->ic_mpsta_vap = vap;
    }
    if (vap->iv_wrap) {
         vap->iv_ic->ic_wrap_vap = vap;
    }
#endif
    IEEE80211_VI_NEED_CWMIN_WORKAROUND_INIT(vap);
    /* override default ath_dev VAP configuration with IEEE VAP configuration */
    OS_MEMZERO(&ath_vap_config, sizeof(ath_vap_config));
    ath_vap_config.av_fixed_rateset = vap->iv_fixed_rateset;
    ath_vap_config.av_fixed_retryset = vap->iv_fixed_retryset;
#ifdef ATH_SUPPORT_TxBF
    ath_vap_config.av_auto_cv_update = vap->iv_autocvupdate;
    ath_vap_config.av_cvupdate_per = vap->iv_cvupdateper;
#endif
    ath_vap_config.av_short_gi = vap->iv_sgi;
    ath_vap_config.av_rc_txrate_fast_drop_en = vap->iv_rc_txrate_fast_drop_en;
    ath_vap_config.av_ampdu_sub_frames = (vap->iv_ampdu==0)?1:(vap->iv_ampdu);
    ath_vap_config.av_amsdu = !!vap->iv_amsdu;
    scn->sc_ops->config_interface(scn->sc_dev, id, &ath_vap_config);

    /* set up MAC address */
    ieee80211vap_get_macaddr(vap, myaddr);
    ATH_SET_VAP_BSSID(myaddr, wlan_vap_get_hw_macaddr((wlan_if_t)vap), id);
    ieee80211vap_set_macaddr(vap, myaddr);

#if ATH_SUPPORT_WRAP
    if (avn->av_is_wrap || avn->av_is_psta) {
        /* WRAP and PSTA VAP's are independent w/ each others */
        if(scn->sc_nwrapvaps) {
            ieee80211_ic_enh_ind_rpt_set(vap->iv_ic);
        }
        if (avn->av_is_wrap) {
            avn->av_psta_key.wk_keyix = IEEE80211_KEYIX_NONE;
        } else { /* avn->av_is_psta */
            if (avn->av_is_mpsta) {
                /*
                 * Main ProxySTA VAP also handles the downlink multicast receive
                 * on behalf of all the ProxySTA VAP's.
                 */
                avn->av_use_mat = 1;
                OS_MEMCPY(avn->av_mat_addr, vap->iv_myaddr, IEEE80211_ADDR_LEN);
            }
            else {
                 ieee80211vap_set_macaddr(vap, bssid);
            }
            /*
             * Always set the PSTA's MAC address to the key cache slot. This
             * is useful when it (later) enters the Azimuth Mode so that
             * unicast frames directed to us will be ACK'ed by the hardware.
             */
            ret = ath_setup_proxykey(vap, vap->iv_myaddr, &avn->av_psta_key);

            IEEE80211_DPRINTF(vap, IEEE80211_MSG_WRAP,
                    "%s: create proxy key for mac addr %s %s\n", __func__,
                    ether_sprintf(vap->iv_myaddr),
                    ret ? "succeeded" : "failed");
        }

        /* enter ProxySTA mode when the first WRAP or PSTA VAP is created */
        if (scn->sc_nwrapvaps + scn->sc_npstavaps == 1) {
            struct ath_softc *sc = ATH_DEV_TO_SC(scn->sc_dev);

            scn->sc_ops->set_proxysta(sc, 1);

            /* Disable LDPC in ProxySTA mode */
            ath_net80211_set_ldpcconfig(ic, 0);

            /* Use 8 usec mpdu density */
            ieee80211com_set_mpdudensity(ic, IEEE80211_HTCAP_MPDUDENSITY_8);

            /* Exclude LA bit from mbssid mask */
            if (sc->sc_hasbmask) {
                ath_hal_getbssidmask(sc->sc_ah, sc->sc_bssidmask);
                WRAP_SET_LA_BSSID_MASK(sc->sc_bssidmask);
                ath_hal_setbssidmask(sc->sc_ah, sc->sc_bssidmask);
            }
        }
    }
    vap->iv_wrap_mat_tx = ath_wrap_mat_tx;
    vap->iv_wrap_mat_rx = ath_wrap_mat_rx;
#endif


#if  0 //ATH_SUPPORT_WIFIPOS
    vap->iv_wifipos->status_request =       ieee80211_wifipos_status_request;
    vap->iv_wifipos->cap_request =          ieee80211_wifipos_cap_request;
    vap->iv_wifipos->sleep_request =        ieee80211_wifipos_sleep_request;
    vap->iv_wifipos->wakeup_request =       ieee80211_wifipos_wakeup_request;

    vap->iv_wifipos->nlsend_status_resp =   ieee80211_wifipos_nlsend_status_resp;
    vap->iv_wifipos->nlsend_cap_resp =      ieee80211_wifipos_nlsend_cap_resp;
    vap->iv_wifipos->nlsend_tsf_resp =      ieee80211_wifipos_nlsend_tsf_resp;
    vap->iv_wifipos->nlsend_sleep_resp =    ieee80211_wifipos_nlsend_sleep_resp;
    vap->iv_wifipos->nlsend_wakeup_resp =   ieee80211_wifipos_nlsend_wakeup_resp;
    vap->iv_wifipos->nlsend_empty_resp  =   ieee80211_wifipos_nlsend_empty_resp;
    vap->iv_wifipos->nlsend_probe_resp =    ieee80211_wifipos_nlsend_probe_resp;
    vap->iv_wifipos->nlsend_tsf_update =    ieee80211_wifipos_nlsend_tsf_update;

    vap->iv_wifipos->fsm =                  ieee80211_wifipos_fsm;

    vap->iv_wifipos->xmittsfrequest =       ieee80211_wifipos_xmittsfrequest;
    vap->iv_wifipos->xmitprobe      =       ieee80211_wifipos_xmitprobe;
#endif

    /* set user selected channel width to an invalid value by default */
    vap->iv_chwidth = IEEE80211_CWM_WIDTHINVALID;

    vap->iv_up = ath_vap_up;
    vap->iv_join = ath_vap_join;
    vap->iv_down = ath_vap_down;
    vap->iv_listen = ath_vap_listen;
    vap->iv_stopping = ath_vap_stopping;
    vap->iv_dfs_cac = ath_vap_dfs_cac;
    vap->iv_key_alloc = ath_key_alloc;
    vap->iv_key_delete = ath_key_delete;
    vap->iv_key_map    = ath_key_map;
    vap->iv_key_set = ath_key_set;
    vap->iv_key_update_begin = ath_key_update_begin;
    vap->iv_key_update_end = ath_key_update_end;

    vap->iv_reg_vap_ath_info_notify = ath_net80211_reg_vap_info_notify;
    vap->iv_vap_ath_info_update_notify = ath_net80211_vap_info_update_notify;
    vap->iv_dereg_vap_ath_info_notify = ath_net80211_dereg_vap_info_notify;
    vap->iv_vap_ath_info_get = ath_net80211_vap_info_get;

    vap->iv_update_ps_mode = ath_update_ps_mode;
    vap->iv_unit = id;
    vap->iv_update_node_txpow = ath_net80211_update_node_txpow;
#if ATH_ANT_DIV_COMB
    vap->iv_sa_normal_scan_handle = ath_vap_sa_normal_scan_handle;
#endif
#if ATH_WOW_OFFLOAD
    vap->iv_vap_wow_offload_rekey_misc_info_set = ath_net80211_wowoffload_rekey_misc_info_set;
    vap->iv_vap_wow_offload_info_get = ath_net80211_wow_offload_info_get;
    vap->iv_vap_wow_offload_txseqnum_update = ath_net80211_wowoffload_txseqnum_update;
#endif /* ATH_WOW_OFFLOAD */
    vap->iv_vap_send = wlan_vap_send;
    vap->iv_modify_bcn_rate = ath_modify_bcn_rate;
    vap->iv_txpow_mgmt = ath_txpow_mgmt;

    /* init IEEE80211_DPRINTF control object */
    ieee80211_dprintf_init(vap);
#if DBG_LVL_MAC_FILTERING
    vap->iv_print.dbgLVLmac_on = 0; /*initialize dbgLVLmac flag*/
#endif

    /* complete setup */
    (void) ieee80211_vap_attach(vap);

    if (opmode == IEEE80211_M_STA)
        scn->sc_nstavaps++;

    /* Note that if it was pre allocated, we need an explicit ath_vap_free_macaddr to free it. */

    DPRINTF(scn, ATH_DEBUG_STATE,
            "%s : exit. vap=0x%p is created.\n",
            __func__,
            vap
           );

    return vap;
}

static void
ath_vap_free(struct ieee80211vap *vap)
{
    struct ath_vap_net80211 *avn = ATH_VAP_NET80211(vap);

    OS_FREE_VAP(avn);

}

static void
ath_vap_delete(struct ieee80211vap *vap)
{
    struct ath_vap_net80211 *avn = ATH_VAP_NET80211(vap);
    struct ath_softc_net80211 *scn = avn->av_sc;
    int ret;

#ifndef ATH_SUPPORT_HTC
    KASSERT(ieee80211_vap_active_is_set(vap) == 0, ("vap not stopped"));
#else
#define WAIT_VAP_IDLE_INTERVALL 10000
    /* Because we will set vap active forcely to send p2p action frames, so we skipp active set check.
       And try to check vap->iv_state_info.iv_state = IEEE80211_S_INIT */
    KASSERT(vap->iv_state_info.iv_state == IEEE80211_S_INIT, ("vap not return to init state"));
    /* Check action frame queue, set deleted for each found. */
    {
        wbuf_t wbuf;
        struct ath_usb_p2p_action_queue *cur_action_wbuf;
        struct ieee80211_node *action_ni;

        /* check action queue, remove related */
        IEEE80211_STATE_P2P_ACTION_LOCK_IRQ(scn);
        cur_action_wbuf = scn->sc_p2p_action_queue_head;
        while(cur_action_wbuf) {
            wbuf = cur_action_wbuf->wbuf;
            action_ni = wbuf_get_node(wbuf);
            if (action_ni->ni_vap == vap) {
                QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "====== Remove queued action frames vap %p, wbuf %p\n",vap,wbuf);
                cur_action_wbuf->deleted = 1;
                if (cur_action_wbuf == scn->sc_p2p_action_queue_tail)
                    cur_action_wbuf = NULL;
            }
            if (cur_action_wbuf)
                cur_action_wbuf = cur_action_wbuf->next;
        }
        IEEE80211_STATE_P2P_ACTION_UNLOCK_IRQ(scn);
        /* sleep a while to let ongoing action cb complete */
        OS_SLEEP(WAIT_VAP_IDLE_INTERVALL);
    }
#undef WAIT_VAP_IDLE_INTERVALL
#endif

#if ATH_SUPPORT_WRAP
    /*
     * Both WRAP and ProxySTA VAP's populate keycache slot with
     * vap->iv_myaddr even when security is not used.
     */

    if (avn->av_is_wrap && (avn->av_psta_key.wk_keyix != IEEE80211_KEYIX_NONE)) {
        ath_key_delete(vap, &avn->av_psta_key, NULL);
        scn->sc_nwrapvaps--;
    } else if (avn->av_is_psta) {
        if (avn->av_psta_key.wk_valid) {
            ieee80211_crypto_delkey(vap, &avn->av_psta_key, NULL);
        } else {
            ath_key_delete(vap, &avn->av_psta_key, NULL);
        }
        if (scn->sc_mcast_recv_vap == vap) {
            scn->sc_mcast_recv_vap = NULL;
        }
        if (!avn->av_is_mpsta) {
            if (vap->iv_no_event_handler == 0)
                scn->sc_nscanpsta--;
        }
        scn->sc_npstavaps--;
    }
    /* exit ProxySTA mode when the last WRAP or PSTA VAP is deleted */
    if (avn->av_is_wrap || avn->av_is_psta) {
        if (scn->sc_nwrapvaps + scn->sc_npstavaps == 0) {
            struct ath_softc *sc = ATH_DEV_TO_SC(scn->sc_dev);

            scn->sc_ops->set_proxysta(scn->sc_dev, 0);
            ath_net80211_set_ldpcconfig(&scn->sc_ic, sc->sc_ldpcsupport);
            if (scn->sc_ops->have_capability(scn->sc_dev, ATH_CAP_ZERO_MPDU_DENSITY)) {
                ieee80211com_set_mpdudensity(&scn->sc_ic, IEEE80211_HTCAP_MPDUDENSITY_NA);
            }

            /* Restore mbssid mask */
            if (sc->sc_hasbmask) {
                ath_hal_getbssidmask(sc->sc_ah, sc->sc_bssidmask);
                ATH_SET_VAP_BSSID_MASK(sc->sc_bssidmask);
                ath_hal_setbssidmask(sc->sc_ah, sc->sc_bssidmask);
            }

            /* Enable aponly mode back */
            vap->iv_ic->ic_aponly = true;
        }
    }
#endif

    /* free pre-allocated mac address */
    scn->sc_prealloc_idmask &= ~(1 << avn->av_if_id);

    DPRINTF(scn, ATH_DEBUG_STATE,
            "%s : enter. vap=0x%p\n",
            __func__,
            vap
           );

    /* remove the interface from ath_dev */
#if WAR_DELETE_VAP
    ret = scn->sc_ops->remove_interface(scn->sc_dev, avn->av_if_id, vap->iv_athvap);
#else
    ret = scn->sc_ops->remove_interface(scn->sc_dev, avn->av_if_id);
#endif
    KASSERT(ret == 0, ("invalid interface id"));

    if (ieee80211vap_get_opmode(vap) == IEEE80211_M_STA)
        scn->sc_nstavaps--;

    IEEE80211_DELETE_VAP_TARGET(vap);

    /* detach VAP from the procotol stack */
    ieee80211_vap_detach(vap);

#if ATH_SUPPORT_WRAP
    if (vap->iv_mpsta) {
        vap->iv_ic->ic_mpsta_vap = NULL;
    }
    if (vap->iv_wrap) {
         vap->iv_ic->ic_wrap_vap = NULL;
    }
#endif

    /* deregister IEEE80211_DPRINTF control object */
    ieee80211_dprintf_deregister(vap);
}


/*
 * ath_vap_alloc_macaddr - pre allocate a mac address and return it in bssid
 * parameters:
 *     ic - Common structure
 *     bssid - pointer to MAC address, supplied by the caller.
 *             if *bssid already has a non-zero value, it is assued to be a hardcoded MAC address.
 *                 Then it will be only validated for locally administred bits.
 *             if *bssid is all zeros, then a new locally administered MAC address is generated
 */
static int
ath_vap_alloc_macaddr(struct ieee80211com *ic, u_int8_t *bssid)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    int id = 0, id_mask = 0;
    int nvaps = 0;

    DPRINTF(scn, ATH_DEBUG_STATE, "%s \n", __func__);

    /* do a full search to mark all the allocated vaps */
    nvaps = wlan_iterate_vap_list(ic,ath_vap_iter_vap_create,(void *) &id_mask);

    id_mask |= scn->sc_prealloc_idmask; /* or in allocated ids */


    if (IEEE80211_ADDR_IS_VALID(bssid) ) {
        /* request to preallocate a specific address */
        /* check if it is valid and it is available */
        u_int8_t tmp_mac2[IEEE80211_ADDR_LEN];
        u_int8_t tmp_mac1[IEEE80211_ADDR_LEN];
        IEEE80211_ADDR_COPY(tmp_mac1, ic->ic_my_hwaddr);
        IEEE80211_ADDR_COPY(tmp_mac2, bssid);
        if (ic->ic_is_macreq_enabled(ic)) {
            /* Ignore locally/globally administered bits */
            ATH_SET_VAP_BSSID_MASK_ALTER(tmp_mac1);
            ATH_SET_VAP_BSSID_MASK_ALTER(tmp_mac2);
        } else {
            tmp_mac1[ATH_VAP_ID_INDEX] &= ~(ATH_VAP_ID_MASK >> ATH_VAP_ID_SHIFT);
            if (ATH_VAP_ID_INDEX < (IEEE80211_ADDR_LEN - 1))
                tmp_mac1[ATH_VAP_ID_INDEX+1] &= ~( ATH_VAP_ID_MASK << ( OCTET-ATH_VAP_ID_SHIFT ) );

            tmp_mac1[0] |= IEEE802_MAC_LOCAL_ADMBIT ;
            tmp_mac2[ATH_VAP_ID_INDEX] &= ~(ATH_VAP_ID_MASK >> ATH_VAP_ID_SHIFT);
            if (ATH_VAP_ID_INDEX < (IEEE80211_ADDR_LEN - 1))
                tmp_mac2[ATH_VAP_ID_INDEX+1] &= ~( ATH_VAP_ID_MASK << ( OCTET-ATH_VAP_ID_SHIFT ) );
        }
        if (!IEEE80211_ADDR_EQ(tmp_mac1,tmp_mac2) ) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Invalid mac address requested %s  \n", __func__, ether_sprintf(bssid));
            return -1;
        }
        ATH_GET_VAP_ID(bssid, ic->ic_my_hwaddr, id);
        if ((id_mask & (1 << id)) != 0) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: mac address already allocated %s \n", __func__,ether_sprintf(bssid));
            return -1;
        }
     }
     else {

        for (id = 0; id < ATH_BCBUF; id++) {
             /* get the first available slot */
             if ((id_mask & (1 << id)) == 0)
                 break;
        }
       if (id == ATH_BCBUF) {
           /* no more ids left */
           QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: No more free slots left \n", __func__);
           return -1;
       }
    }

    /* set the allocated id in to the mask */
    scn->sc_prealloc_idmask |= (1 << id);

    IEEE80211_ADDR_COPY(bssid,ic->ic_my_hwaddr);
    /* copy the mac address into the bssid field */
    ATH_SET_VAP_BSSID(bssid,ic->ic_my_hwaddr, id);
    return 0;

}

/*
 * free a  pre allocateed  mac caddresses.
 */
static int
ath_vap_free_macaddr(struct ieee80211com *ic, u_int8_t *bssid)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    int id = 0;

    /* extract the id from the bssid */
    ATH_GET_VAP_ID(bssid, ic->ic_my_hwaddr, id);

#if UMAC_SUPPORT_P2P
    if (id == ATH_P2PDEV_IF_ID) {
        DPRINTF(scn, ATH_DEBUG_STATE, "%s P2P device mac address \n", __func__);
        return -1;
    }
#endif
    /* if it was pre allocated, remove it from pre allocated bitmap */
    if (scn->sc_prealloc_idmask & (1 << id) ) {
        scn->sc_prealloc_idmask &= ~(1 << id);
        return 0;
    } else {
        DPRINTF(scn, ATH_DEBUG_STATE, "%s not a pre allocated mac address \n", __func__);
        return -1;
    }
}

static void
ath_net80211_set_config(struct ieee80211vap* vap)
{
    struct ath_vap_net80211 *avn = ATH_VAP_NET80211(vap);
    struct ath_softc_net80211 *scn = avn->av_sc;
    struct ath_vap_config ath_vap_config;

    /* override default ath_dev VAP configuration with IEEE VAP configuration */
    OS_MEMZERO(&ath_vap_config, sizeof(ath_vap_config));
    ath_vap_config.av_fixed_rateset = vap->iv_fixed_rateset;
    ath_vap_config.av_fixed_retryset = vap->iv_fixed_retryset;
#if ATH_SUPPORT_AP_WDS_COMBO
    ath_vap_config.av_no_beacon = vap->iv_no_beacon;
#endif
#ifdef ATH_SUPPORT_TxBF
    ath_vap_config.av_auto_cv_update = vap->iv_autocvupdate;
    ath_vap_config.av_cvupdate_per = vap->iv_cvupdateper;
#endif
    ath_vap_config.av_short_gi = vap->iv_sgi;
    ath_vap_config.av_rc_txrate_fast_drop_en = vap->iv_rc_txrate_fast_drop_en;
    ath_vap_config.av_ampdu_sub_frames = (vap->iv_ampdu==0)?1:(vap->iv_ampdu);
    ath_vap_config.av_amsdu = !!vap->iv_amsdu;
    scn->sc_ops->config_interface(scn->sc_dev, avn->av_if_id, &ath_vap_config);
}

static struct ieee80211_node *
ath_net80211_node_alloc(struct ieee80211vap *vap, const u_int8_t *mac, bool tmpnode)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_vap_net80211 *avn = ATH_VAP_NET80211(vap);
    struct ath_node_net80211 *anode;

    anode = (struct ath_node_net80211 *)OS_MALLOC(scn->sc_osdev,
                                                  sizeof(struct ath_node_net80211),
                                                  GFP_ATOMIC);
    if (anode == NULL)
        return NULL;

    OS_MEMZERO(anode, sizeof(struct ath_node_net80211));

    /* attach a node in ath_dev module */
    anode->an_sta = scn->sc_ops->alloc_node(scn->sc_dev, avn->av_if_id, anode, tmpnode);
    if (anode->an_sta == NULL) {
        OS_FREE(anode);
        return NULL;
    }

#ifdef ATH_AMSDU
    ath_amsdu_node_attach(scn, anode);
#endif

    anode->an_node.ni_vap = vap;
#if IEEE80211_DEBUG_REFCNT
    anode->an_node.trace = (struct node_trace_all *)OS_MALLOC(ic->ic_osdev, sizeof(struct node_trace_all), GFP_KERNEL);
    if (anode->an_node.trace == NULL) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Can't create an node trace\n");
        return NULL;
    }
    OS_MEMZERO(anode->an_node.trace, sizeof(struct node_trace_all));
#endif
    return &anode->an_node;
}

static void
ath_force_ppm_enable (void *arg, struct ieee80211_node *ni)
{
    struct ieee80211com          *ic  = arg;
    struct ath_softc_net80211    *scn = ATH_SOFTC_NET80211(ic);

    scn->sc_ops->force_ppm_notify(scn->sc_dev, ATH_FORCE_PPM_ENABLE, ni->ni_macaddr);
}

static void
ath_net80211_node_free(struct ieee80211_node *ni)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    ath_node_t an = ATH_NODE_NET80211(ni)->an_sta;

#ifdef ATH_AMSDU
    ath_amsdu_node_detach(scn, ATH_NODE_NET80211(ni));
#endif

    scn->sc_node_free(ni);
    scn->sc_ops->free_node(scn->sc_dev, an);
    OS_FREE(ATH_NODE_NET80211(ni));
}

static void
ath_net80211_node_cleanup(struct ieee80211_node *ni)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_node_net80211 *anode = (struct ath_node_net80211 *)ni;

    //First get rid of ni from scn->sc_keyixmap if created
    //using ni->ni_ucastkey.wk_keyix;
    if(ni->ni_ucastkey.wk_valid &&
        (ni->ni_ucastkey.wk_keyix != IEEE80211_KEYIX_NONE)
       )
    {
        bool freenode = false;
        IEEE80211_KEYMAP_LOCK(scn);

        if(ni->ni_ucastkey.wk_keyix < ATH_KEYMAX)
        {
            if (scn->sc_keyixmap[ni->ni_ucastkey.wk_keyix] == ni) {
                scn->sc_keyixmap[ni->ni_ucastkey.wk_keyix] = NULL;
                freenode = true;
            }
        }

        IEEE80211_KEYMAP_UNLOCK(scn);

        if (freenode)
            ieee80211_free_node(ni);
    }

    /*
     * If AP mode, enable ForcePPM if only one Station is connected, or
     * disable it otherwise.
     */
    if (ni->ni_vap && ieee80211vap_get_opmode(ni->ni_vap) == IEEE80211_M_HOSTAP) {
        if (ieee80211com_can_enable_force_ppm(ic)) {
            ieee80211_iterate_node(ic, ath_force_ppm_enable, ic);
        }
        else {
            scn->sc_ops->force_ppm_notify(scn->sc_dev, ATH_FORCE_PPM_DISABLE, NULL);
        }
    }

    if (scn->sc_ops->cleanup_node(scn->sc_dev, anode->an_sta)) {
        /*
         * lmac cleanup has been skipped.
         * This is ok as long as ni refcnt is non-zero.
         */
        if (ieee80211_node_refcnt(ni) <= 0) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "lmac cleanup skipped when ni refcnt is 0. Possible race??\n");
        }
    }

#ifdef ATH_SWRETRY
    scn->sc_ops->set_swretrystate(scn->sc_dev, anode->an_sta, AH_FALSE);
    DPRINTF(scn, ATH_DEBUG_SWR, "%s: swr disable for ni %s\n", __func__, ether_sprintf(ni->ni_macaddr));
    /*
     * Also clear the tim bit when tid could be paused during PS mode.
     * node_saveq_cleanup might not clear it if UMAC PS queue is empty.
     */
    if (ni->ni_vap && ni->ni_vap->iv_set_tim != NULL)
        ni->ni_vap->iv_set_tim(ni, 0, false);
#endif
    scn->sc_node_cleanup(ni);
}

static u_int8_t
ath_net80211_node_getrssi(const struct ieee80211_node *ni,int8_t chain, u_int8_t flags )
{
    const struct ath_node_net80211 *anode = (const struct ath_node_net80211 *)ni;
    struct ieee80211com *ic = ni->ni_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

	return scn->sc_ops->get_noderssi(anode->an_sta, chain, flags);
}

static u_int32_t
ath_net80211_node_getrate(const struct ieee80211_node *ni, u_int8_t type)
{
    const struct ath_node_net80211 *anode = (const struct ath_node_net80211 *)ni;
    struct ieee80211com *ic = ni->ni_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);


        /* Get the user configured max rate for this client */
    if (type == IEEE80211_MAX_RATE_PER_CLIENT) {

         if (ni->ni_maxrate == 255) {
             return 0;
         } else {
             if (ni->ni_maxrate < 128)
                return (ni->ni_maxrate/2);
             else
                 return ni->ni_maxrate;
         }
    }

	return scn->sc_ops->get_noderate(anode->an_sta, type);
}

#if QCA_AIRTIME_FAIRNESS
static u_int32_t
ath_net80211_node_getairtime(const struct ieee80211_node *ni)
{
    const struct ath_node_net80211 *anode = (const struct ath_node_net80211 *)ni;
    struct ieee80211com *ic = ni->ni_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    int unused_token;
    u_int32_t airtime = 0;

    /* calc airtime %age*/
    scn->sc_ops->ath_atf_get_unused_txtoken(anode->an_sta, &unused_token);
    if (ni->ni_atf_stats.tokens) {
        u_int32_t used_tokens = ni->ni_atf_stats.tokens - ni->ni_atf_stats.unused;
        airtime = ( used_tokens / ni->ni_atf_stats.tokens ) * 100;
    }

    return airtime;
}
#endif

static u_int32_t
ath_net80211_node_get_last_txpower(const struct ieee80211_node *ni)
{
    const struct ath_node_net80211 *anode = (const struct ath_node_net80211 *)ni;
    struct ieee80211com *ic = ni->ni_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    return scn->sc_ops->get_last_txpower(anode->an_sta);
}

static INLINE int
ath_net80211_node_get_extradelimwar(ieee80211_node_t n)
{
    struct ieee80211_node *ni = (struct ieee80211_node *)n;
    if(ni != NULL) {
#if ATH_SUPPORT_WRAP
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ni->ni_ic);
    struct ath_softc *sc = ATH_DEV_TO_SC(scn->sc_dev);

#define PROXYSTA_HW_CRYPT_MIN_DELIMS 5
    /*
     * Hardware ProxySTA requires a minimum aggregation
     * delimiters between subframes when encryption is used.
     */
        if (sc->sc_enableproxysta) {
        return PROXYSTA_HW_CRYPT_MIN_DELIMS;
    }
#endif
    /*
     * When the receiver has issue with block ack generation, make
     * sure we add extra two delimiters, provided, only when the other
     * end point require this war.
     */
        if (ni->ni_flags & IEEE80211_NODE_EXTRADELIMWAR)
        return 2;

    }
    return 0;
}


static int
ath_net80211_reset_start(struct ieee80211com *ic, bool no_flush)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->reset_start(scn->sc_dev, no_flush, 0, 0);
}

static int
ath_net80211_reset_end(struct ieee80211com *ic, bool no_flush)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->reset_end(scn->sc_dev, no_flush);
}

static int
ath_net80211_reset(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->reset(scn->sc_dev);
}

static void ath_vap_iter_scan_start(void *arg, wlan_if_t vap)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(vap->iv_ic);

    if (ieee80211vap_get_opmode(vap) == IEEE80211_M_STA) {
        scn->sc_ops->force_ppm_notify(scn->sc_dev, ATH_FORCE_PPM_SUSPEND, NULL);
    }
}
static void ath_vap_iter_chan_changed(void *arg, wlan_if_t vap)
{
    if (ieee80211_vap_ready_is_set(vap)) {
        // Tell the vap that the channel change has happened.
        IEEE80211_DELIVER_EVENT_CHANNEL_CHANGE(vap, vap->iv_ic->ic_curchan);
    }
}

static void ath_vap_iter_post_set_channel(void *arg, wlan_if_t vap)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(vap->iv_ic);
    struct ath_vap_net80211 *avn;

    if (ieee80211_vap_ready_is_set(vap)) {

        /*
         * Always configure the beacon.
         * In ad-hoc, we may be the only peer in the network.
         * In infrastructure, we need to detect beacon miss
         * if the AP goes away while we are scanning.
         */


        avn = ATH_VAP_NET80211(vap);

       /*
         * if current channel is not the vaps bss channel,
         * ignore it.
         */
        if ( ieee80211_get_current_channel(vap->iv_ic) != vap->iv_bsschan) {
            return;
        }

       /*
        * TBD: if multiple vaps are running, only sync the first one.
        * RM should decide which one to synch to.
        */
       if (!scn->sc_syncbeacon) {
            scn->sc_ops->sync_beacon(scn->sc_dev, avn->av_if_id);
       }

        if (ieee80211vap_get_opmode(vap) == IEEE80211_M_IBSS) {
            /*
             * if tsf is 0. we are alone.
             * no need to sync tsf from beacons.
             */
            if (ieee80211_node_get_tsf(ieee80211vap_get_bssnode(vap)) != 0)
                scn->sc_syncbeacon = 1;
        } else {
          /*
           * if scheduler is active then we don not want to wait for beacon for sync.
           * the tsf is already maintained acoss channel changes and the tsf should be in
           * sync with the AP and waiting for a beacon (syncbeacon == 1) forces us to
           * to keep the chip awake until beacon is received and affects the powersave
           * functionality severely. imagine we are switching channel every 50msec for
           * STA + GO  (AP) operating on different channel with powersave tunred on on both
           * STA and GO. if there is no activity on both STA and GO we will have to wait for
           * say approximately 25 msec on the STAs BSS  channel after switching channel. without
           * this fix  the chip needs to  be awake for 25 msec every 100msec (25% of the time).
           */
          if (!ieee80211_resmgr_oc_scheduler_is_active(vap->iv_ic->ic_resmgr)) {
           scn->sc_syncbeacon = 1;
          }
        }

       /* Notify CWM */
        DPRINTF(scn, ATH_DEBUG_CWM, "%s\n", __func__);

        ath_cwm_up(NULL, vap);

        /* Resume ForcePPM operation as we return to home channel */
        if (ieee80211vap_get_opmode(vap) == IEEE80211_M_STA) {
            scn->sc_ops->force_ppm_notify(scn->sc_dev, ATH_FORCE_PPM_RESUME, NULL);
        }
    }
}

struct ath_iter_vaps_ready_arg {
    u_int8_t num_sta_vaps_ready;
    u_int8_t num_ibss_vaps_ready;
    u_int8_t num_ap_vaps_ready;
};

static void ath_vap_iter_vaps_ready(void *arg, wlan_if_t vap)
{
    struct ath_iter_vaps_ready_arg *params = (struct ath_iter_vaps_ready_arg *) arg;
    if (ieee80211_vap_ready_is_set(vap)) {
        switch(ieee80211vap_get_opmode(vap)) {
        case IEEE80211_M_HOSTAP:
        case IEEE80211_M_BTAMP:
            params->num_ap_vaps_ready++;
            break;

        case IEEE80211_M_IBSS:
            params->num_ibss_vaps_ready++;
            break;

        case IEEE80211_M_STA:
            params->num_sta_vaps_ready++;
            break;

        default:
            break;

        }
    }
}

static void
ath_net80211_enable_radar(struct ieee80211com *ic, int no_cac)
{
#if ATH_SUPPORT_DFS
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_dfs_radar_tab_info rinfo;

    /* Fetch current radar patterns from the lmac */
    OS_MEMZERO(&rinfo, sizeof(rinfo));
    /* XXX ew, void */
    scn->sc_ops->radar_get_info(scn->sc_dev, (void *) &rinfo);

    /*
     * Set the regulatory domain, radar pulse table and enable
     * radar events if required.
     */

    if(!scn->sc_isscan) {
        dfs_radar_enable(ic, &rinfo, no_cac);
        if (no_cac == 0)
            ieee80211_dfs_cac_start(ic);
    }
#endif
}

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
static void
ath_net80211_enable_sta_radar(struct ieee80211com *ic, int no_cac)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_dfs_radar_tab_info rinfo;

    /* Fetch current radar patterns from the lmac */
    OS_MEMZERO(&rinfo, sizeof(rinfo));
    /* XXX ew, void */
    scn->sc_ops->radar_get_info(scn->sc_dev, (void *) &rinfo);

    /*
     * Set the regulatory domain, radar pulse table and enable
     * radar events if required.
     */

    if(!scn->sc_isscan) {
        dfs_radar_enable(ic, &rinfo, no_cac);
    }
}
#endif

static int
ath_net80211_set_channel(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ieee80211_channel *chan;
    HAL_CHANNEL hchan;

    /*
     * Convert to a HAL channel description with
     * the flags constrained to reflect the current
     * operating mode.
     */
    chan = ieee80211_get_current_channel(ic);
    hchan.channel = ieee80211_chan2freq(ic, chan);
    hchan.channel_flags = ath_chan2flags(chan);
    KASSERT(hchan.channel != 0,
            ("bogus channel %u/0x%x", hchan.channel, hchan.channel_flags));
    /*
     * if scheduler is active then we don not want to wait for beacon for sync.
     * the tsf is already maintained acoss channel changes and the tsf should be in
     * sync with the AP and waiting for a beacon (syncbeacon == 1) forces us to
     * to keep the chip awake until beacon is received and affects the powersave
     * functionality severely. imagine we are switching channel every 50msec for
     * STA + GO  (AP) operating on different channel with powersave tunred on on both
     * STA and GO. if there is no activity on both STA and GO we will have to wait for
     * say approximately 25 msec on the STAs BSS  channel after switching. without
     * this fix  the chip needs to  be awake for 25 msec every 100msec (25% of the time).
     */
    if (ieee80211_resmgr_oc_scheduler_is_active(ic->ic_resmgr)) {
        scn->sc_syncbeacon = 0;
    }

    /*
     * Initialize CWM (Channel Width Management) .
     * this needs to be called before calling set channel in to the ath layer.
     * because the mac mode (ht40, ht20) is initialized by the cwm_init
     * and set_channel in ath layer gets the mac mode from the CWM module
     * and passes it down to HAL. if CWM is initialized after set_channel then
     * wrong mac mode is passed down to HAL and can result in TX hang when
     * switching from a HT40 to HT20 channel (ht40 mac mode is used for HT20 channel).
     */
    cwm_init(ic);
    /* set h/w channel */
#ifdef ATH_SUPPORT_DFS
    scn->sc_ops->set_channel(scn->sc_dev, &hchan, 0, 0, false, ath_ignoredfs_enable);
#else
    scn->sc_ops->set_channel(scn->sc_dev, &hchan, 0, 0, false, false);
#endif

    /* update max channel power to max regpower of current channel */
    ieee80211com_set_curchanmaxpwr(ic, chan->ic_maxregpower);

    ath_net80211_enable_radar(ic, 0);

    /*
     * If we are returning to our bss channel then mark state
     * so the next recv'd beacon's tsf will be used to sync the
     * beacon timers.  Note that since we only hear beacons in
     * sta/ibss mode this has no effect in other operating modes.
     */
    if (!scn->sc_isscan) {
        if ((ic->ic_opmode == IEEE80211_M_HOSTAP) || (ic->ic_opmode == IEEE80211_M_BTAMP)) {
            struct ath_iter_vaps_ready_arg params;
            params.num_sta_vaps_ready = params.num_ap_vaps_ready = params.num_ibss_vaps_ready = 0;
            /* there is atleast one AP VAP active */
            wlan_iterate_vap_list(ic,ath_vap_iter_vaps_ready,(void *) &params);
            if (params.num_ap_vaps_ready) {
                scn->sc_ops->sync_beacon(scn->sc_dev, ATH_IF_ID_ANY);
            }
        } else  {
             wlan_iterate_vap_list(ic, ath_vap_iter_post_set_channel, NULL);

        }
    }

    // Send Channel Changed Notifications
    wlan_iterate_vap_list(ic, ath_vap_iter_chan_changed, NULL);
    ic->ic_flags &= ~IEEE80211_F_DFS_CHANSWITCH_PENDING;
    return 0;
}
#if ATH_SUPPORT_WIFIPOS
static int
ath_net80211_get_channel_busy_info(struct ieee80211com *ic, u_int32_t *rxclear_pct, u_int32_t *rxframe_pct, u_int32_t *txframe_pct)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->ath_get_channel_busy_info(scn->sc_dev, rxclear_pct,rxframe_pct,txframe_pct);
}
static bool
ath_net80211_disable_hwq(struct ieee80211com *ic, u_int16_t mask)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->ath_disable_hwq(scn->sc_dev, mask);
}

/* \Functionality:  Calls the optimised channel change code. This
 *                  code is optimized for Wifi positioning.
 */

static int
ath_net80211_lean_set_channel(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ieee80211_channel *chan;
    HAL_CHANNEL hchan;

    /*
     * Convert to a HAL channel description with
     * the flags constrained to reflect the current
     * operating mode.
     */
    chan = ieee80211_get_current_channel(ic);
    hchan.channel = ieee80211_chan2freq(ic, chan);
    hchan.channel_flags = ath_chan2flags(chan);
    KASSERT(hchan.channel != 0,
            ("bogus channel %u/0x%x", hchan.channel, hchan.channel_flags));
    /*
     * if scheduler is active then we don not want to wait for beacon for sync.
     * the tsf is already maintained acoss channel changes and the tsf should be in
     * sync with the AP and waiting for a beacon (syncbeacon == 1) forces us to
     * to keep the chip awake until beacon is received and affects the powersave
     * functionality severely. imagine we are switching channel every 50msec for
     * STA + GO  (AP) operating on different channel with powersave tunred on on both
     * STA and GO. if there is no activity on both STA and GO we will have to wait for
     * say approximately 25 msec on the STAs BSS  channel after switching. without
     * this fix  the chip needs to  be awake for 25 msec every 100msec (25% of the time).
     */
    if (ieee80211_resmgr_oc_scheduler_is_active(ic->ic_resmgr)) {
        scn->sc_syncbeacon = 0;
    }

    /*
     * Initialize CWM (Channel Width Management) .
     * this needs to be called before calling set channel in to the ath layer.
     * because the mac mode (ht40, ht20) is initialized by the cwm_init
     * and set_channel in ath layer gets the mac mode from the CWM module
     * and passes it down to HAL. if CWM is initialized after set_channel then
     * wrong mac mode is passed down to HAL and can result in TX hang when
     * switching from a HT40 to HT20 channel (ht40 mac mode is used for HT20 channel).
     */
    cwm_init(ic);

    /* set h/w channel */
    scn->sc_ops->ath_lean_set_channel(scn->sc_dev, &hchan, 0, 0, false);

    /* update max channel power to max regpower of current channel */
    ieee80211com_set_curchanmaxpwr(ic, chan->ic_maxregpower);
    return 0;
}
static void
ath_net80211_resched_txq(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->ath_resched_txq(scn->sc_dev);
}
#endif
static bool
ath_direct_rate_check(struct ieee80211com *ic, int val)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->direct_rate_check(scn->sc_dev,val);
}

static void
ath_net80211_newassoc(struct ieee80211_node *ni, int isnew)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_node_net80211 *an = (struct ath_node_net80211 *)ni;
    struct ieee80211vap *vap = ni->ni_vap;

    ath_net80211_rate_node_update(ic, ni, isnew);

    scn->sc_ops->new_assoc(scn->sc_dev, an->an_sta, isnew, ((ni->ni_flags & IEEE80211_NODE_UAPSD)? 1: 0));

    /* force the legact client to go with one tx chain */
    if (!IEEE80211_NODE_USE_HT(ni) && vap->iv_force_onetxchain) {
        scn->sc_ops->set_node_tx_chainmask(an->an_sta, 1);
    }
    /*
     * If AP mode,
     * a) Setup the keycacheslot for open - required for UAPSD
     *    for other modes hostapd sets the key cache entry
     *    for static WEP case, not setting the key cache entry
     *    since, AP does not know the key index used by station
     *    in case of multiple WEP key scenario during assoc.
     * b) enable ForcePPM if only one Station is connected, or
     * disable it otherwise. ForcePPM applies only to 2GHz channels.
     */
    if (ieee80211vap_get_opmode(vap) == IEEE80211_M_HOSTAP) {
        if (isnew && !vap->iv_wps_mode) {
            ni->ni_ath_defkeyindex = IEEE80211_INVAL_DEFKEY;
            if (!RSN_AUTH_IS_WPA(&vap->iv_bss->ni_rsn) &&
                !RSN_AUTH_IS_WPA2(&vap->iv_bss->ni_rsn) &&
                !RSN_AUTH_IS_WAI(&vap->iv_bss->ni_rsn) &&
                !RSN_AUTH_IS_8021X(&vap->iv_bss->ni_rsn)) {
                ath_setup_keycacheslot(ni);
            }
        }
        if (IEEE80211_IS_CHAN_2GHZ(ni->ni_chan)) {
            enum ath_force_ppm_event_t    event = ieee80211com_can_enable_force_ppm(ic) ?
                ATH_FORCE_PPM_ENABLE : ATH_FORCE_PPM_DISABLE;

            scn->sc_ops->force_ppm_notify(scn->sc_dev, event, ni->ni_macaddr);
        }
#ifdef ATH_SWRETRY
		if (scn->sc_ops->have_capability(scn->sc_dev, ATH_CAP_SWRETRY_SUPPORT)) {
            scn->sc_ops->set_swretrystate(scn->sc_dev, ATH_NODE_NET80211(ni)->an_sta, AH_TRUE);
            DPRINTF(scn, ATH_DEBUG_SWR, "%s: swr enable for ni %s\n", __func__, ether_sprintf(ni->ni_macaddr));
        }
#endif
    }
#ifdef ATH_SUPPORT_TxBF
        // initial keycache for txbf.
    if ((ieee80211vap_get_opmode(vap) == IEEE80211_M_IBSS) || (ieee80211vap_get_opmode(vap) == IEEE80211_M_HOSTAP)) {
#if ATH_SUPPORT_WRAP
        struct ath_vap_net80211 *avn = ATH_VAP_NET80211(vap);

        if (!avn->av_is_wrap)
#endif
        if (ni->ni_explicit_compbf || ni->ni_explicit_noncompbf || ni->ni_implicit_bf) {
            struct ieee80211com     *ic = vap->iv_ic;

            ieee80211_set_TxBF_keycache(ic,ni);
            ni->ni_bf_update_cv = 1;
            ni->ni_allow_cv_update = 1;
        }
    }
#endif
}

#ifdef ATH_BT_COEX
/*
 * determine the bt coex mode when one of the vaps
 * changes its state.
 */
static void
ath_bt_coex_opmode(struct ieee80211vap *vap, bool vap_active)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ath_softc_net80211    *scn = ATH_SOFTC_NET80211(ic);
    struct ath_iter_new_opmode_arg params;

    DPRINTF(scn, ATH_DEBUG_STATE, "%s: active state %d\n", __func__, vap_active);

    params.num_sta_vaps_active = params.num_ibss_vaps_active = 0;
    params.num_ap_vaps_active = params.num_ap_sleep_vaps_active = 0;
    params.num_sta_nobeacon_vaps_active = 0;
    params.num_btamp_vaps_active = 0;
    params.vap = vap;
    params.vap_active = vap_active;
    wlan_iterate_vap_list(ic,ath_vap_iter_new_opmode,(void *) &params);
    /*
     * we cant support all 3 vap types active at the same time.
     */
    ASSERT(!(params.num_ap_vaps_active && params.num_sta_vaps_active && params.num_ibss_vaps_active));
    DPRINTF(scn, ATH_DEBUG_BTCOEX, "%s: ibss %d, btamp %d, ap %d, sta %d sta_nobeacon %d \n", __func__, params.num_ibss_vaps_active,
        params.num_btamp_vaps_active, params.num_ap_vaps_active, params.num_sta_vaps_active, params.num_sta_nobeacon_vaps_active);

    /*
     * IBSS can't be active with other vaps active at the same time. If there is an IBSS vap, set coex opmode to IBSS.
     * STA vap will have higher priority than the BTAMP and HOSTAP vaps.
     * BTAMP vap will be next.
     * HOSTAP will have the lowest priority.
     */
    if (params.num_ibss_vaps_active) {
        ic->ic_bt_coex_opmode = IEEE80211_M_IBSS;
        return;
    }
    if (params.num_sta_vaps_active) {
        ic->ic_bt_coex_opmode = IEEE80211_M_STA;
        return;
    }
    if (params.num_btamp_vaps_active) {
        ic->ic_bt_coex_opmode = IEEE80211_M_BTAMP;
        return;
    }
    if (params.num_ap_vaps_active) {
        ic->ic_bt_coex_opmode = IEEE80211_M_HOSTAP;
        return;
    }
    if (params.num_sta_nobeacon_vaps_active) {
        ic->ic_bt_coex_opmode = IEEE80211_M_HOSTAP;
        return;
    }
    if (params.num_ap_sleep_vaps_active) {
        ic->ic_bt_coex_opmode = IEEE80211_M_HOSTAP;
        return;
    }
}
#endif

struct ath_iter_newstate_arg {
    struct ieee80211vap *vap;
    int flags;
    bool is_ap_vap_running;
    bool is_any_vap_running;
    bool is_any_vap_active;
    bool is_any_ap_vap_ht;
};

static void ath_vap_iter_newstate(void *arg, wlan_if_t vap)
{
    struct ath_iter_newstate_arg *params = (struct ath_iter_newstate_arg *) arg;
    if (params->vap != vap) {
        if (ieee80211_vap_ready_is_set(vap)) {
            if (ieee80211vap_get_opmode(vap) == IEEE80211_M_HOSTAP ||
                ieee80211vap_get_opmode(vap) == IEEE80211_M_BTAMP) {
                params->is_ap_vap_running = true;
            }
            params->is_any_vap_running = true;
        }

        if (ieee80211_vap_active_is_set(vap)) {
            params->is_any_vap_active = true;
        }
    }

    if (ieee80211vap_get_opmode(vap) == IEEE80211_M_HOSTAP) {
        if( wlan_get_desired_phymode(vap) >= IEEE80211_MODE_11NA_HT20 ) {
            params->is_any_ap_vap_ht = true;
        }
    }
}

struct ath_iter_vaptype_params {
    enum ieee80211_opmode   opmode;
    wlan_if_t               vap;
    u_int8_t                vap_active;
};

static void ath_vap_iter_vaptype(void *arg, wlan_if_t vap)
{
    struct ath_iter_vaptype_params  *params = (struct ath_iter_vaptype_params *) arg;

    if (ieee80211vap_get_opmode(vap) == params->opmode) {
        if (ieee80211_vap_ready_is_set(vap)) {
            params->vap_active ++;
            if (!params->vap)
                params->vap = vap;
        }
    }
}

static void ath_wme_amp_overloadparams(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ath_iter_vaptype_params  params;

    OS_MEMZERO(&params, sizeof(struct ath_iter_vaptype_params));
    params.opmode = IEEE80211_M_BTAMP;
    wlan_iterate_vap_list(ic, ath_vap_iter_vaptype, &params);
    if ((ieee80211vap_get_opmode(vap) == IEEE80211_M_BTAMP && !params.vap_active) ||
        (ieee80211vap_get_opmode(vap) != IEEE80211_M_BTAMP && params.vap_active)) {
        ieee80211_wme_amp_overloadparams_locked(ic);
        //OS_EXEC_INTSAFE(ic->ic_osdev, ieee80211_wme_amp_overloadparams_locked, ic);
    }
}

static void ath_wme_amp_restoreparams(struct ieee80211com *ic)
{
    struct ath_iter_vaptype_params params;

    do {
        OS_MEMZERO(&params, sizeof(struct ath_iter_vaptype_params));
        params.opmode = IEEE80211_M_BTAMP;
        wlan_iterate_vap_list(ic, ath_vap_iter_vaptype, &params);
        if (params.vap_active)
            break;

        OS_MEMZERO(&params, sizeof(struct ath_iter_vaptype_params));
        params.opmode = IEEE80211_M_STA;
        wlan_iterate_vap_list(ic, ath_vap_iter_vaptype, &params);
        if (params.vap_active) {
            ieee80211_wme_updateparams_locked(params.vap);
            //OS_EXEC_INTSAFE(ic->ic_osdev, ieee80211_wme_updateparams_locked, params.vap);
            break;
        }

        OS_MEMZERO(&params, sizeof(struct ath_iter_vaptype_params));
        params.opmode = IEEE80211_M_HOSTAP;
        wlan_iterate_vap_list(ic, ath_vap_iter_vaptype, &params);
        if (params.vap_active) {
            ieee80211_wme_updateparams_locked(params.vap);
            //OS_EXEC_INTSAFE(ic->ic_osdev, ieee80211_wme_updateparams_locked, params.vap);
            break;
        }
    } while (0);
}

static int ath_vap_join(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_vap_net80211 *avn = ATH_VAP_NET80211(vap);
    enum ieee80211_opmode opmode = ieee80211vap_get_opmode(vap);
    struct ieee80211_node *ni = vap->iv_bss;
    struct ath_iter_newstate_arg params;
    u_int flags = 0;


    params.vap = vap;
    params.is_any_vap_active = false;
    params.is_any_ap_vap_ht = false;
    wlan_iterate_vap_list(ic,ath_vap_iter_newstate,(void *) &params);


    if (!ieee80211_resmgr_exists(ic) && !params.is_any_vap_active) {
        ath_net80211_pwrsave_set_state(ic,IEEE80211_PWRSAVE_AWAKE);
    }

    if (opmode != IEEE80211_M_STA && opmode != IEEE80211_M_IBSS) {
        DPRINTF(scn, ATH_DEBUG_STATE,
                "%s: remaining join operation is only for STA/IBSS mode\n",
                __func__);
        return 0;
    }

    ath_cwm_join(NULL, vap);
#ifdef ATH_SWRETRY
    scn->sc_ops->set_swretrystate(scn->sc_dev, ATH_NODE_NET80211(ni)->an_sta, AH_FALSE);
    DPRINTF(scn, ATH_DEBUG_SWR, "%s: swr disable for ni %s\n", __func__, ether_sprintf(ni->ni_macaddr));
#endif

    ic->ic_opmode = ieee80211_new_opmode(vap,true);
    scn->sc_ops->switch_opmode(scn->sc_dev, (HAL_OPMODE) ic->ic_opmode);

#ifdef ATH_BT_COEX
    ath_bt_coex_opmode(vap,true);
#endif

    flags = params.is_any_vap_active? 0: ATH_IF_HW_ON;
    if (IEEE80211_NODE_USE_HT(ni) || params.is_any_ap_vap_ht)
        flags |= ATH_IF_HT;
#ifdef ATH_BT_COEX
    {
        u_int32_t bt_event_param = ATH_COEX_WLAN_ASSOC_START;
        scn->sc_ops->bt_coex_event(scn->sc_dev, ATH_COEX_EVENT_WLAN_ASSOC, &bt_event_param);
    }
#endif

    return scn->sc_ops->join(scn->sc_dev, avn->av_if_id, ni->ni_bssid, flags);
}

static int ath_vap_up(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_vap_net80211 *avn = ATH_VAP_NET80211(vap);
    enum ieee80211_opmode opmode = ieee80211vap_get_opmode(vap);
    struct ieee80211_node *ni = vap->iv_bss;
    u_int flags = 0;
    int error = 0;
    int aid = 0;
    bool   is_ap_vap_running=false;
    struct ath_iter_newstate_arg params;

    if(opmode == IEEE80211_M_MONITOR){
        int setcfg_value = 1;
        /*In Case of MIX Mode bring up the HW in Promisc mode*/
        scn->sc_ops->ath_set_config_param(scn->sc_dev,
                        (ath_param_ID_t)ATH_PARAM_ALLOW_PROMISC,&setcfg_value);
	return 0;
    }
    /*
     * if it is the first AP VAP moving to RUN state then beacon
     * needs to be reconfigured.
     */
    params.vap = vap;
    params.is_ap_vap_running = false;
    params.is_any_vap_active = false;
    wlan_iterate_vap_list(ic,ath_vap_iter_newstate,(void *) &params);
    is_ap_vap_running = params.is_ap_vap_running;

    if (!ieee80211_resmgr_exists(ic) && !params.is_any_vap_active) {
        ath_net80211_pwrsave_set_state(ic,IEEE80211_PWRSAVE_AWAKE);
    }

    ath_cwm_up(NULL, vap);
    ath_wme_amp_overloadparams(vap);

#ifdef ATH_SWRETRY
    scn->sc_ops->set_swretrystate(scn->sc_dev, ATH_NODE_NET80211(ni)->an_sta, AH_FALSE);
    DPRINTF(scn, ATH_DEBUG_SWR, "%s: swr disable for ni %s\n", __func__, ether_sprintf(ni->ni_macaddr));
#endif
    switch (opmode) {
    case IEEE80211_M_HOSTAP:
    case IEEE80211_M_BTAMP:
    case IEEE80211_M_IBSS:
        /* Set default key index for static wep case */
        ni->ni_ath_defkeyindex = IEEE80211_INVAL_DEFKEY;
        if (!RSN_AUTH_IS_WPA(&ni->ni_rsn) &&
            !RSN_AUTH_IS_WPA2(&ni->ni_rsn) &&
            !RSN_AUTH_IS_8021X(&ni->ni_rsn) &&
            !RSN_AUTH_IS_WAI(&ni->ni_rsn) &&
            (vap->iv_def_txkey != IEEE80211_KEYIX_NONE)) {
            ni->ni_ath_defkeyindex = vap->iv_def_txkey;
        }

        if (ieee80211vap_has_athcap(vap, IEEE80211_ATHC_TURBOP))
            flags |= ATH_IF_DTURBO;

        if (IEEE80211_VAP_IS_PRIVACY_ENABLED(vap))
            flags |= ATH_IF_PRIVACY;

#if ATH_SUPPORT_WRAP
        if (avn->av_is_wrap) {
            if (avn->av_psta_key.wk_keyix != IEEE80211_KEYIX_NONE) {
                 ath_key_delete(vap, &avn->av_psta_key, NULL);
            }
            /*
             * Always set the AP's BSSID to the key cache slot. This is useful
             * when it (later) enters the Azimuth Mode so that unicast frames
             * directed to us will be ACK'ed by the hardware.
             */
            error = ath_setup_wrap_key(vap, vap->iv_myaddr, &avn->av_psta_key);

            IEEE80211_DPRINTF(vap, IEEE80211_MSG_WRAP,"%s: create wrap key for mac addr %s %s\n", __func__, ether_sprintf(vap->iv_myaddr), error ? "succeeded" : "failed");
        }
#endif

        if(!is_ap_vap_running) {
            flags |= ATH_IF_BEACON_ENABLE;

            if (!ieee80211_vap_ready_is_set(vap))
                flags |= ATH_IF_HW_ON;

            /*
             * if tsf is 0. we are starting a new ad-hoc network.
             * no need to wait and sync for beacons.
             */
            if (ieee80211_node_get_tsf(ni) != 0) {
                scn->sc_syncbeacon = 1;
                flags |= ATH_IF_BEACON_SYNC;
            } else {
                /*
                 *  Fix bug 27870.
                 *  When system wakes up from power save mode, we don't
                 *  know if the peers have left the ad hoc network or not,
                 *  so we have to configure beacon (& ~ATH_IF_BEACON_SYNC)
                 *  and also synchronize to older beacons (sc_syncbeacon
                 *  = 1).
                 *
                 *  The merge function should take care of it, but during
                 *  resume, sometimes the tsf in rx_status shows the
                 *  synchorized value, so merge routine does not get
                 *  called. It is safer we turn on sc_syncbeacon now.
                 *
                 *  There is no impact to synchronize twice, so just enable
                 *  sc_syncbeacon as long as it is ad hoc mode.
                 */
                if (opmode == IEEE80211_M_IBSS)
                    scn->sc_syncbeacon = 1;
                else
                    scn->sc_syncbeacon = 0;
            }
        }
        break;

    case IEEE80211_M_STA:
        aid = ni->ni_associd;
        scn->sc_syncbeacon = 1;
        flags |= ATH_IF_BEACON_SYNC; /* sync with next received beacon */

        if (ieee80211node_has_athflag(ni, IEEE80211_ATHC_TURBOP))
            flags |= ATH_IF_DTURBO;

        if (IEEE80211_NODE_USE_HT(ni))
            flags |= ATH_IF_HT;

#if defined(ATH_SWRETRY) && !ATH_SUPPORT_WRAP
        if (scn->sc_ops->have_capability(scn->sc_dev, ATH_CAP_SWRETRY_SUPPORT)) {
            /* We need to allocate keycache slot here
             * only if we enable sw retry mechanism
             */
            if (!vap->iv_wps_mode &&!RSN_AUTH_IS_WPA(&vap->iv_bss->ni_rsn) &&
                    !RSN_AUTH_IS_WPA2(&vap->iv_bss->ni_rsn) &&
                    !RSN_AUTH_IS_WAI(&vap->iv_bss->ni_rsn) &&
                    !RSN_AUTH_IS_8021X(&vap->iv_bss->ni_rsn)
#ifdef ATH_SUPPORT_TxBF
					/* Fix for EV-131769
					 * This condition is added to avoid allocation of key slot for node
					 * when key slot is already allocated for that node in mlme_process_asresp_elements() func*/
				&& !( ni->ni_explicit_compbf || ni->ni_explicit_noncompbf || ni->ni_implicit_bf)
#endif
					) {
                ath_setup_keycacheslot(ni);
            }

            /* Enabling SW Retry mechanism only for Infrastructure
             * mode and only when STA associates to AP and entered into
             * into RUN state.
             */
            scn->sc_ops->set_swretrystate(scn->sc_dev, ATH_NODE_NET80211(ni)->an_sta, AH_TRUE);
            DPRINTF(scn, ATH_DEBUG_SWR, "%s: swr enable for ni %s\n", __func__, ether_sprintf(ni->ni_macaddr));
        }
#endif
#ifdef ATH_BT_COEX
        {
            u_int32_t bt_event_param = ATH_COEX_WLAN_ASSOC_END_SUCCESS;
            scn->sc_ops->bt_coex_event(scn->sc_dev, ATH_COEX_EVENT_WLAN_ASSOC, &bt_event_param);
        }
#endif
        break;


    default:
        break;
    }
    /*
     * determine the new op mode depending upon how many
     * vaps are running and switch to the new opmode.
     */
    ic->ic_opmode = ieee80211_new_opmode(vap,true);
    scn->sc_ops->switch_opmode(scn->sc_dev, (HAL_OPMODE) ic->ic_opmode);

#ifdef ATH_BT_COEX
    ath_bt_coex_opmode(vap,true);
#endif

    error = scn->sc_ops->up(scn->sc_dev, avn->av_if_id, ni->ni_bssid, aid, flags);
    if (opmode == IEEE80211_M_STA && !ieee80211_vap_ready_is_set(vap)) {
        enum ath_force_ppm_event_t    event = ATH_FORCE_PPM_DISABLE;

        if (IEEE80211_IS_CHAN_2GHZ(ni->ni_chan)) {
            event = ATH_FORCE_PPM_ENABLE;
        }
        scn->sc_ops->force_ppm_notify(scn->sc_dev, event, ieee80211_node_get_bssid(vap->iv_bss));
    }
    return 0;
}
int ath_vap_dfs_cac(struct ieee80211vap *vap)
{
    int error = 0;

    struct ieee80211com *ic = vap->iv_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_vap_net80211 *avn = ATH_VAP_NET80211(vap);

    error = scn->sc_ops->dfs_wait(scn->sc_dev, avn->av_if_id);
    return error;
}

int ath_vap_stopping(struct ieee80211vap *vap)
{
    int error = 0;

    struct ieee80211com *ic = vap->iv_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_vap_net80211 *avn = ATH_VAP_NET80211(vap);

#ifdef ATH_SWRETRY
    scn->sc_ops->set_swretrystate(scn->sc_dev, ATH_NODE_NET80211(vap->iv_bss)->an_sta, AH_FALSE);
    DPRINTF(scn, ATH_DEBUG_SWR, "%s: swr disable for ni %s\n", __func__, ether_sprintf(vap->iv_bss->ni_macaddr));
#endif

    error = scn->sc_ops->stopping(scn->sc_dev, avn->av_if_id);
    return error;
}

static int ath_vap_listen(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_vap_net80211 *avn = ATH_VAP_NET80211(vap);
    struct ath_iter_newstate_arg params;

    params.vap = vap;
    params.is_any_vap_active = false;
    wlan_iterate_vap_list(ic,ath_vap_iter_newstate,(void *) &params);

    if (params.is_any_vap_active)
        return 0;

    if (!ieee80211_resmgr_exists(ic)) {
        ath_net80211_pwrsave_set_state(ic,IEEE80211_PWRSAVE_AWAKE);
    }

    ic->ic_opmode = ieee80211_new_opmode(vap,true);
    scn->sc_ops->switch_opmode(scn->sc_dev, (HAL_OPMODE) ic->ic_opmode);

#ifdef ATH_BT_COEX
    ath_bt_coex_opmode(vap,true);
    scn->sc_ops->bt_coex_event(scn->sc_dev, ATH_COEX_EVENT_WLAN_DISCONNECT, NULL);
#endif

    return scn->sc_ops->listen(scn->sc_dev, avn->av_if_id);
}

int ath_vap_down(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_vap_net80211 *avn = ATH_VAP_NET80211(vap);
    enum ieee80211_opmode opmode = ieee80211vap_get_opmode(vap);
    enum ieee80211_opmode old_ic_opmode = ic->ic_opmode;

    u_int flags = 0;
    int error = 0;
    struct ath_iter_newstate_arg params;

    if(opmode == IEEE80211_M_MONITOR){
        int setcfg_value = 0;
        /*In Case of MIX Mode bring up the HW in Promisc mode*/
        scn->sc_ops->ath_set_config_param(scn->sc_dev,
                        (ath_param_ID_t)ATH_PARAM_ALLOW_PROMISC,&setcfg_value);
        scn->sc_ops->set_rxfilter(scn->sc_dev);
	return 0;
    }

    ath_cwm_down(vap);
    ath_wme_amp_restoreparams(ic);

    /*
     * if there is no vap left in active state, turn off hardware
     */
    params.vap = vap;
    params.is_any_vap_active = false;
    wlan_iterate_vap_list(ic,ath_vap_iter_newstate,(void *) &params);

#ifdef ATH_BT_COEX
    {
        u_int32_t bt_event_param = ATH_COEX_WLAN_ASSOC_END_FAIL;
        scn->sc_ops->bt_coex_event(scn->sc_dev, ATH_COEX_EVENT_WLAN_ASSOC, &bt_event_param);
    }
    if (!params.is_any_vap_active) {
        scn->sc_ops->bt_coex_event(scn->sc_dev, ATH_COEX_EVENT_WLAN_DISCONNECT, NULL);
    }
#endif

    flags = params.is_any_vap_active? 0: ATH_IF_HW_OFF;
    error = scn->sc_ops->down(scn->sc_dev, avn->av_if_id, flags);

    /*
     * determine the new op mode depending upon how many
     * vaps are running and switch to the new opmode.
     */
    /*
     * If HW is to be shut off, do not change opmode. Switch_opmode
     * will enable global interrupt.
     */
    if (!(flags & ATH_IF_HW_OFF)) {
        ic->ic_opmode = ieee80211_new_opmode(vap,false);
        scn->sc_ops->switch_opmode(scn->sc_dev, (HAL_OPMODE) ic->ic_opmode);
    }

#ifdef ATH_BT_COEX
    ath_bt_coex_opmode(vap,false);
#endif

    if (opmode == IEEE80211_M_STA) {
        scn->sc_ops->force_ppm_notify(scn->sc_dev, ATH_FORCE_PPM_DISABLE, NULL);
        scn->sc_syncbeacon = 1;
    }
    /*
     * if we switched opmode to STA then we need to resync beacons.
     */
    if (old_ic_opmode != ic->ic_opmode && ic->ic_opmode == IEEE80211_M_STA) {
        scn->sc_syncbeacon = 1;
    }

    if (!ieee80211_resmgr_exists(ic) && !params.is_any_vap_active) {
        ath_net80211_pwrsave_set_state(ic,IEEE80211_PWRSAVE_FULL_SLEEP);
    }

    return error;
}

static void
ath_net80211_scan_start(struct ieee80211com *ic)
{
    struct ath_softc_net80211    *scn = ATH_SOFTC_NET80211(ic);
#if ATH_TX_DUTY_CYCLE
    struct ath_softc *sc = scn->sc_dev;

    if (sc->sc_tx_dc_enable) {
        scn->sc_ops->set_quiet(scn->sc_dev, 0, 0, 0, HAL_QUIET_DISABLE);
        DPRINTF(scn, ATH_DEBUG_SCAN, "%s: disable quiet time\n", __func__);
    }
#endif
    scn->sc_isscan = 1;
    scn->sc_syncbeacon = 0;
    scn->sc_ops->scan_start(scn->sc_dev);
    ath_cwm_scan_start(ic);

    /* Suspend ForcePPM since we are going off-channel */
    wlan_iterate_vap_list(ic,ath_vap_iter_scan_start,NULL);
}

static void
ath_net80211_scan_end(struct ieee80211com *ic)
{
    struct ath_softc_net80211    *scn = ATH_SOFTC_NET80211(ic);
#if ATH_TX_DUTY_CYCLE
    struct ath_softc *sc = scn->sc_dev;

    if (sc->sc_tx_dc_enable) {
        ath_net80211_enable_tx_duty_cycle(ic, sc->sc_tx_dc_active_pct);
        DPRINTF(scn, ATH_DEBUG_SCAN, "%s: re-enable quiet time: %u%% active\n", __func__, sc->sc_tx_dc_active_pct);
    }
#endif
    scn->sc_isscan = 0;
    scn->sc_ops->scan_end(scn->sc_dev);
    ath_cwm_scan_end(ic);
}
static void
ath_net80211_scan_enable_txq(struct ieee80211com *ic)
{
    struct ath_softc_net80211    *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->scan_enable_txq(scn->sc_dev);
}

static void
ath_net80211_led_enter_scan(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->led_scan_start(scn->sc_dev);
}

static void
ath_net80211_led_leave_scan(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->led_scan_end(scn->sc_dev);
}

static void
ath_beacon_update(struct ieee80211_node *ni, int rssi)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ni->ni_ic);
	int32_t avgbrssi;

	avgbrssi = scn->sc_ops->get_noderssi(ATH_NODE_NET80211(ni)->an_sta, -1, IEEE80211_RSSI_BEACON);
#ifdef ATH_BT_COEX
    /*
     * BT coex module will only look at beacon from one opmode at a time.
     * Beacons from other vap will be ignored.
     * TODO: This might be further optimized if BT coex module can periodically
     * check the RSSI from each vap. So these steps at each beacon receiving can
     * be removed.
     */
    if (ieee80211vap_get_opmode(ni->ni_vap) == ni->ni_ic->ic_bt_coex_opmode) {
        int8_t avgrssi;
        /* The return value of ATH_RSSI_OUT might be ATH_RSSI_DUMMY_MARKER which
         * is 0x127 (more than one byte). Make sure we dont' assign 0x127 to
         * avgrssi which is only one byte.
         */
        avgrssi =  (avgbrssi == -1) ? 0 : avgbrssi;
        scn->sc_ops->bt_coex_event(scn->sc_dev, ATH_COEX_EVENT_WLAN_RSSI_UPDATE, (void *)&avgrssi);
    }
#endif
	if (avgbrssi == -1) {
		avgbrssi = ATH_RSSI_DUMMY_MARKER;
	} else {
		avgbrssi = ATH_RSSI_IN(avgbrssi);
	}
    if (ieee80211vap_get_opmode(ni->ni_vap) != IEEE80211_M_BTAMP) {
    /* Update beacon-related information - rssi and others */
    scn->sc_ops->update_beacon_info(scn->sc_dev, avgbrssi);

    if (scn->sc_syncbeacon) {
        scn->sc_ops->sync_beacon(scn->sc_dev, (ATH_VAP_NET80211(ni->ni_vap))->av_if_id);
        scn->sc_syncbeacon = 0;
    }
}
}

static int
ath_wmm_update(struct ieee80211com *ic)
{
#define	ATH_EXPONENT_TO_VALUE(v)    ((1<<v)-1)
#define	ATH_TXOP_TO_US(v)           (v<<5)
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    int ac;
    struct wmeParams *wmep;
    HAL_TXQ_INFO qi;

    for (ac = 0; ac < WME_NUM_AC; ac++) {
        int error;

        wmep = ieee80211com_wmm_chanparams(ic, ac);

        qi.tqi_aifs = wmep->wmep_aifsn;
        qi.tqi_cwmin = ATH_EXPONENT_TO_VALUE(wmep->wmep_logcwmin);
        qi.tqi_cwmax = ATH_EXPONENT_TO_VALUE(wmep->wmep_logcwmax);
        qi.tqi_burst_time = ATH_TXOP_TO_US(wmep->wmep_txopLimit);
        /*
         * XXX Set the readyTime appropriately if used.
         */
        qi.tqi_ready_time = 0;

        /* WAR: Improve tx BE-queue performance for USB device */
        ATH_USB_UPDATE_CWIN_FOR_BE(qi);
        error = scn->sc_ops->txq_update(scn->sc_dev, scn->sc_ac2q[ac], &qi);
        ATH_USB_RESTORE_CWIN_FOR_BE(qi);

        if (error != 0)
            return -EIO;

        if (ac == WME_AC_BE)
            scn->sc_ops->txq_update(scn->sc_dev, scn->sc_beacon_qnum, &qi);

        ath_uapsd_txq_update(scn, &qi, ac);
    }
    return 0;
#undef ATH_TXOP_TO_US
#undef ATH_EXPONENT_TO_VALUE
}

void ath_htc_wmm_update_params(struct ieee80211com *ic)
{
    ath_wmm_update(ic);
}

static void
ath_keyprint(const char *tag, u_int ix,
             const HAL_KEYVAL *hk, const u_int8_t mac[IEEE80211_ADDR_LEN])
{
    static const char *ciphers[] = {
        "WEP",
        "AES-OCB",
        "AES-CCM",
        "CKIP",
        "TKIP",
        "CLR",
#if ATH_SUPPORT_WAPI
        "WAPI",
#endif
    };
    int i, n;
    int type = hk->kv_type & 0xf;

    if(type < sizeof(ciphers)/sizeof(ciphers[0]))
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: [%02u] %-7s ", tag, ix, ciphers[type]);
    for (i = 0, n = hk->kv_len; i < n; i++)
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%02x", hk->kv_val[i]);
    if (mac) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " mac %02x-%02x-%02x-%02x-%02x-%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " mac 00-00-00-00-00-00");
    }
    if (type == HAL_CIPHER_TKIP) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " mic ");
        for (i = 0; i < sizeof(hk->kv_mic); i++)
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%02x", hk->kv_mic[i]);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " txmic ");
		for (i = 0; i < sizeof(hk->kv_txmic); i++)
			QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%02x", hk->kv_txmic[i]);
    }
#if ATH_SUPPORT_WAPI
	else if (type == HAL_CIPHER_WAPI) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " Mic Key ");
		for (i = 0; i < (hk->kv_len/2); i++)
			QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%02x", hk->kv_mic[i]);
		for (i = 0; i < (hk->kv_len/2); i++)
			QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%02x", hk->kv_txmic[i]);
    }
#endif /*ATH_SUPPORT_WAPI*/

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n");
}

/*
 * Allocate one or more key cache slots for a uniacst key.  The
 * key itself is needed only to identify the cipher.  For hardware
 * TKIP with split cipher+MIC keys we allocate two key cache slot
 * pairs so that we can setup separate TX and RX MIC keys.  Note
 * that the MIC key for a TKIP key at slot i is assumed by the
 * hardware to be at slot i+64.  This limits TKIP keys to the first
 * 64 entries.
 */
static int
ath_key_alloc(struct ieee80211vap *vap, struct ieee80211_key *k)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    int opmode;
    u_int keyix;
#if ATH_SUPPORT_WRAP
    struct ath_vap_net80211 *avn = ATH_VAP_NET80211(vap);
#endif

    if (k->wk_flags & IEEE80211_KEY_GROUP) {
        opmode = ieee80211vap_get_opmode(vap);

        switch (opmode) {
        case IEEE80211_M_STA:
            /*
             * Allocate the key slot for WEP not from 0, but from 4,
             * if WEP on MBSSID is enabled in STA mode.
             */
            if (!ieee80211_wep_mbssid_cipher_check(k)) {
                if (!((&vap->iv_nw_keys[0] <= k) &&
                      (k < &vap->iv_nw_keys[IEEE80211_WEP_NKID]))) {
                    /* should not happen */
                    DPRINTF(scn, ATH_DEBUG_KEYCACHE,
                            "%s: bogus group key\n", __func__);
                    return IEEE80211_KEYIX_NONE;
                }
                keyix = k - vap->iv_nw_keys;
                return keyix;
            }
            break;

        case IEEE80211_M_IBSS:
            //ASSERT(scn->sc_mcastkey);
            if ((k->wk_flags & IEEE80211_KEY_PERSTA) == 0) {

                /*
                 * Multicast key search doesn't work on certain hardware, don't use shared key slot(0-3)
                 * for default Tx broadcast key in that case. This affects broadcast traffic reception with AES-CCMP.
                 */
                if ((!scn->sc_mcastkey) &&
					(k->wk_cipher->ic_cipher == IEEE80211_CIPHER_AES_CCM)) {
                    keyix = scn->sc_ops->key_alloc_single(scn->sc_dev);
                    if (keyix == -1)
                        return IEEE80211_KEYIX_NONE;
                    else
                        return keyix;
                }

                if (!((&vap->iv_nw_keys[0] <= k) &&
                      (k < &vap->iv_nw_keys[IEEE80211_WEP_NKID]))) {
                    /* should not happen */
                    DPRINTF(scn, ATH_DEBUG_KEYCACHE,
                            "%s: bogus group key\n", __func__);
                    return IEEE80211_KEYIX_NONE;
                }
                keyix = k - vap->iv_nw_keys;
                return keyix;

            } else if (!(k->wk_flags & IEEE80211_KEY_RECV)) {
                return IEEE80211_KEYIX_NONE;
            }

            if (k->wk_flags & IEEE80211_KEY_PERSTA) {
                if (k->wk_valid) {
                    return k->wk_keyix;
                }
            }
            /* fall thru to allocate a slot for _PERSTA keys */
            break;

        case IEEE80211_M_HOSTAP:
            /*
             * Group key allocation must be handled specially for
             * parts that do not support multicast key cache search
             * functionality.  For those parts the key id must match
             * the h/w key index so lookups find the right key.  On
             * parts w/ the key search facility we install the sender's
             * mac address (with the high bit set) and let the hardware
             * find the key w/o using the key id.  This is preferred as
             * it permits us to support multiple users for adhoc and/or
             * multi-station operation.
             * wep keys need to be allocated in fisrt 4 slots.
             */
            if ((!scn->sc_mcastkey || (k->wk_cipher->ic_cipher == IEEE80211_CIPHER_WEP)) &&
                                                                    (vap->iv_wep_mbssid == 0)) {
                if (!(&vap->iv_nw_keys[0] <= k &&
                      k < &vap->iv_nw_keys[IEEE80211_WEP_NKID])) {
                    /* should not happen */
                    DPRINTF(scn, ATH_DEBUG_KEYCACHE,
                            "%s: bogus group key\n", __func__);
                    return IEEE80211_KEYIX_NONE;
                }
                keyix = k - vap->iv_nw_keys;
                /*
                 * XXX we pre-allocate the global keys so
                 * have no way to check if they've already been allocated.
                 */
                return keyix;
            }
            /* fall thru to allocate a key cache slot */
            break;

        default:
            return IEEE80211_KEYIX_NONE;
            break;
        }
    }

    /*
     * We alloc two pair for WAPI when using the h/w to do
     * the SMS4 MIC
     */
#if ATH_SUPPORT_WAPI
    if (k->wk_cipher->ic_cipher == IEEE80211_CIPHER_WAPI)
        return scn->sc_ops->key_alloc_pair(scn->sc_dev);
#endif

#if ATH_SUPPORT_WRAP

    /* Reuse the pre-allocated key index for unicast key */
    if (avn->av_is_psta &&
        (avn->av_psta_key.wk_keyix != IEEE80211_KEYIX_NONE) &&
        !(k->wk_flags & IEEE80211_KEY_GROUP))
    {
        keyix = avn->av_psta_key.wk_keyix;
#if WRAP_HW_DECRYPT_PSTA_TKIP
        if (k->wk_cipher->ic_cipher == IEEE80211_CIPHER_TKIP) {
            struct ath_softc *sc = ATH_DEV_TO_SC(scn->sc_dev);
            if(keyix < ATH_KEYBYTES)
                setbit(sc->sc_keymap, keyix + 64);
        }
#endif
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_WRAP,
                "%s: reuse psta keyix %d, cipher %d\n",
                __func__, keyix, k->wk_cipher->ic_cipher);
    } else
#endif
    /*
     * We allocate two pair for TKIP when using the h/w to do
     * the MIC.  For everything else, including software crypto,
     * we allocate a single entry.  Note that s/w crypto requires
     * a pass-through slot on the 5211 and 5212.  The 5210 does
     * not support pass-through cache entries and we map all
     * those requests to slot 0.
     *
     * Allocate 1 pair of keys for WEP case. Make sure the key
     * is not a shared-key.
     */
    if (k->wk_flags & IEEE80211_KEY_SWCRYPT) {
        keyix = scn->sc_ops->key_alloc_single(scn->sc_dev);
    } else if ((k->wk_cipher->ic_cipher == IEEE80211_CIPHER_TKIP) &&
               ((k->wk_flags & IEEE80211_KEY_SWMIC) == 0))
    {
        if (scn->sc_splitmic) {
            keyix = scn->sc_ops->key_alloc_2pair(scn->sc_dev);
        } else {
            keyix = scn->sc_ops->key_alloc_pair(scn->sc_dev);
        }
    } else {
        keyix = scn->sc_ops->key_alloc_single(scn->sc_dev);
    }

    if (keyix == -1)
        keyix = IEEE80211_KEYIX_NONE;

    // Allocate clear key slot only after the rx key slot is allocated.
    // It will ensure that key cache search for incoming frame will match
    // correct index.
    if (k->wk_flags & IEEE80211_KEY_MFP) {
        /* Allocate a clear key entry for sw encryption of mgmt frames */
        k->wk_clearkeyix = scn->sc_ops->key_alloc_single(scn->sc_dev);
    }
    return keyix;
}

/*
 * Delete an entry in the key cache allocated by ath_key_alloc.
 */
static int
ath_key_delete(struct ieee80211vap *vap, const struct ieee80211_key *k,
               struct ieee80211_node *ninfo)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    const struct ieee80211_cipher *cip = k->wk_cipher;
    struct ieee80211_node *ni;
    u_int keyix = k->wk_keyix;
    int rxkeyoff = 0;
    int freeslot;
#if ATH_SUPPORT_WRAP
    struct ath_vap_net80211 *avn = ATH_VAP_NET80211(vap);
#endif

    if (keyix == IEEE80211_KEYIX_NONE || keyix >= ATH_KEYMAX) {
        qdf_print("%s: Not deleting key, invalid keyidx=%u \n", __func__, keyix);
        return 0;
    }

    DPRINTF(scn, ATH_DEBUG_KEYCACHE, "%s: delete key %u\n", __func__, keyix);

    /*
     * Don't touch keymap entries for global keys so
     * they are never considered for dynamic allocation.
     */
    freeslot = (keyix >= IEEE80211_WEP_NKID) ? 1 : 0;

#if ATH_SUPPORT_WRAP
    if (avn->av_is_psta && k != &avn->av_psta_key &&
        (keyix == avn->av_psta_key.wk_keyix ||
         (WRAP_HW_DECRYPT_PSTA_WEP &&
          k->wk_cipher->ic_cipher == IEEE80211_CIPHER_WEP)))
    {
        /*
         * Keep the PSTA key entry when upper layer delete its key.
         * ieee80211_crypto_resetkey sets the cipher to
         * ieee80211_cipher_none. So the key slot will become
         * HAL_CIPHER_CLR after this.
         */
        ieee80211_crypto_resetkey(vap, &avn->av_psta_key, avn->av_psta_key.wk_keyix);
        OS_MEMZERO(avn->av_psta_key.wk_key, sizeof(avn->av_psta_key.wk_key));
        __ath_key_set(vap, &avn->av_psta_key, vap->iv_myaddr, 1);
    } else if (avn->av_is_psta && !avn->av_is_mpsta && (k->wk_flags & IEEE80211_KEY_GROUP))
    {
       /*Ignore delete group key for psta*/
       return 1;

    } else
#endif
    scn->sc_ops->key_delete(scn->sc_dev, keyix, freeslot);
    /*
     * Check the key->node map and flush any ref.
     */
    IEEE80211_KEYMAP_LOCK(scn);
    ni = scn->sc_keyixmap[keyix];
    if (ni != NULL) {
        scn->sc_keyixmap[keyix] = NULL;
        IEEE80211_KEYMAP_UNLOCK(scn);
        ieee80211_free_node(ni);
    }else {
        IEEE80211_KEYMAP_UNLOCK(scn);
    }

    /*
     * Handle split tx/rx keying required for WAPI with h/w MIC.
     */
#if ATH_SUPPORT_WAPI
    if (cip->ic_cipher == IEEE80211_CIPHER_WAPI  && (keyix + 64) < ATH_KEYMAX)
    {
        IEEE80211_KEYMAP_LOCK(scn);

        ni = scn->sc_keyixmap[keyix+64];
        if (ni != NULL) {           /* as above... */
            //scn->sc_keyixmap[keyix+32] = NULL;
            scn->sc_keyixmap[keyix+64] = NULL;
            IEEE80211_KEYMAP_UNLOCK(scn);
            ieee80211_free_node(ni);
        }else {
            IEEE80211_KEYMAP_UNLOCK(scn);
        }

        scn->sc_ops->key_delete(scn->sc_dev, keyix+64, freeslot);   /* TX key MIC */
    }
#endif

    /*
     * Handle split tx/rx keying required for TKIP with h/w MIC.
     */
    if ((cip->ic_cipher == IEEE80211_CIPHER_TKIP) &&
        ((k->wk_flags & IEEE80211_KEY_SWMIC) == 0))
    {
        if (scn->sc_splitmic && (keyix + 32) < ATH_KEYMAX) {
            scn->sc_ops->key_delete(scn->sc_dev, keyix+32, freeslot);   /* RX key */
            IEEE80211_KEYMAP_LOCK(scn);
            ni = scn->sc_keyixmap[keyix+32];
            if (ni != NULL) {           /* as above... */
                scn->sc_keyixmap[keyix+32] = NULL;
                IEEE80211_KEYMAP_UNLOCK(scn);
                ieee80211_free_node(ni);
            }else {
                IEEE80211_KEYMAP_UNLOCK(scn);
            }
            if((keyix + 32 + 64) < ATH_KEYMAX) {
                scn->sc_ops->key_delete(scn->sc_dev, keyix+32+64, freeslot);   /* RX key MIC */
                ASSERT(scn->sc_keyixmap[keyix+32+64] == NULL);
            }
        }

        /*
         * When splitmic, this key+64 is Tx MIC key. When non-splitmic, this
         * key+64 is Rx/Tx (combined) MIC key.
         */
        if((keyix + 64) < ATH_KEYMAX) {
            scn->sc_ops->key_delete(scn->sc_dev, keyix+64, freeslot);
            ASSERT(scn->sc_keyixmap[keyix+64] == NULL);
        }
    }

    /* Remove the clear key allocated for MFP */
    if(k->wk_flags & IEEE80211_KEY_MFP) {
        scn->sc_ops->key_delete(scn->sc_dev, k->wk_clearkeyix, freeslot);
    }

    /* Remove receive key entry if one exists for static WEP case */
    if (ninfo != NULL) {
        rxkeyoff = ninfo->ni_rxkeyoff;
        if (rxkeyoff != 0 && (keyix + rxkeyoff) < ATH_KEYMAX) {
            ninfo->ni_rxkeyoff = 0;
            scn->sc_ops->key_delete(scn->sc_dev, keyix+rxkeyoff, freeslot);
            IEEE80211_KEYMAP_LOCK(scn);
            ni = scn->sc_keyixmap[keyix+rxkeyoff];
            if (ni != NULL) {   /* as above... */
                scn->sc_keyixmap[keyix+rxkeyoff] = NULL;
                IEEE80211_KEYMAP_UNLOCK(scn);
                ieee80211_free_node(ni);
            }else {
                IEEE80211_KEYMAP_UNLOCK(scn);
            }
        }
    }

    return 1;
}

static int
ath_key_map(struct ieee80211vap *vap, const struct ieee80211_key *k,
            const u_int8_t bssid[IEEE80211_ADDR_LEN], struct ieee80211_node *ni)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(vap->iv_ic);
    u_int keyix = k->wk_keyix;

    if (k->wk_flags & IEEE80211_KEY_GROUP) {
        return 0;
    }

    IEEE80211_KEYMAP_LOCK(scn);
    if (scn->sc_keyixmap[keyix])  {
        IEEE80211_KEYMAP_UNLOCK(scn);
        return 0;
    }
    IEEE80211_KEYMAP_UNLOCK(scn);

    if (!bssid || IEEE80211_IS_MULTICAST(bssid) || IEEE80211_IS_BROADCAST(bssid)) {
        return 0;
    }

    if (ni) {
        IEEE80211_KEYMAP_LOCK(scn);
        // Add one reference. This increment will be decreased when deleted.
        ieee80211_ref_node(ni);
        scn->sc_keyixmap[keyix] = ni;
        IEEE80211_KEYMAP_UNLOCK(scn);
    }
    return 1;
}


/*
 * Set a TKIP key into the hardware.  This handles the
 * potential distribution of key state to multiple key
 * cache slots for TKIP.
 * NB: return 1 for success, 0 otherwise.
 */
static int
ath_keyset_tkip(struct ath_softc_net80211 *scn, const struct ieee80211_key *k,
                HAL_KEYVAL *hk, const u_int8_t mac[IEEE80211_ADDR_LEN])
{
#define	IEEE80211_KEY_TXRX	(IEEE80211_KEY_XMIT | IEEE80211_KEY_RECV)

    KASSERT(k->wk_cipher->ic_cipher == IEEE80211_CIPHER_TKIP,
            ("got a non-TKIP key, cipher %u", k->wk_cipher->ic_cipher));

    if ((k->wk_flags & IEEE80211_KEY_TXRX) == IEEE80211_KEY_TXRX) {
        if (!scn->sc_splitmic) {
            /*
             * data key goes at first index,
             * the hal handles the MIC keys at index+64.
             */
            OS_MEMCPY(hk->kv_mic, k->wk_rxmic, sizeof(hk->kv_mic));
            OS_MEMCPY(hk->kv_txmic, k->wk_txmic, sizeof(hk->kv_txmic));
            KEYPRINTF(scn, k->wk_keyix, hk, mac);
            return (scn->sc_ops->key_set(scn->sc_dev, k->wk_keyix, hk, mac));
        } else {
            /*
             * TX key goes at first index, RX key at +32.
             * The hal handles the MIC keys at index+64.
             */
            OS_MEMCPY(hk->kv_mic, k->wk_txmic, sizeof(hk->kv_mic));
            KEYPRINTF(scn, k->wk_keyix, hk, NULL);
            if (!scn->sc_ops->key_set(scn->sc_dev, k->wk_keyix, hk, NULL)) {
		/*
		 * Txmic entry failed. No need to proceed further.
		 */
                return 0;
            }

            OS_MEMCPY(hk->kv_mic, k->wk_rxmic, sizeof(hk->kv_mic));
            KEYPRINTF(scn, k->wk_keyix+32, hk, mac);
            /* XXX delete tx key on failure? */
            return (scn->sc_ops->key_set(scn->sc_dev, k->wk_keyix+32, hk, mac));
        }
    } else if (k->wk_flags & IEEE80211_KEY_RECV) {
        /*
         * TX/RX key goes at first index.
         * The hal handles the MIC keys are index+64.
         */
        OS_MEMCPY(hk->kv_mic, k->wk_flags & IEEE80211_KEY_XMIT ?
               k->wk_txmic : k->wk_rxmic, sizeof(hk->kv_mic));
        KEYPRINTF(scn, k->wk_keyix, hk, mac);
        return (scn->sc_ops->key_set(scn->sc_dev, k->wk_keyix, hk, mac));
    }
    /* XXX key w/o xmit/recv; need this for compression? */
    return 0;
#undef IEEE80211_KEY_TXRX
}

/*
 * Set the key cache contents for the specified key.  Key cache
 * slot(s) must already have been allocated by ath_key_alloc.
 * NB: return 1 for success, 0 otherwise.
 */
static int
__ath_key_set(struct ieee80211vap *vap,
            const struct ieee80211_key *k,
            const u_int8_t peermac[IEEE80211_ADDR_LEN],
            int is_proxy_addr)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(vap->iv_ic);
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_node *ni = NULL;
    /* Cipher MAP has to be in the same order as ieee80211_cipher_type */
    static const u_int8_t ciphermap[] = {
        HAL_CIPHER_WEP,		/* IEEE80211_CIPHER_WEP     */
        HAL_CIPHER_TKIP,	/* IEEE80211_CIPHER_TKIP    */
        HAL_CIPHER_AES_OCB,	/* IEEE80211_CIPHER_AES_OCB */
        HAL_CIPHER_AES_CCM,	/* IEEE80211_CIPHER_AES_CCM */
#if ATH_SUPPORT_WAPI
        HAL_CIPHER_WAPI,	/* IEEE80211_CIPHER_WAPI    */
#else
        HAL_CIPHER_UNUSED,	/* IEEE80211_CIPHER_WAPI    */
#endif
        HAL_CIPHER_CKIP,	/* IEEE80211_CIPHER_CKIP    */
        HAL_CIPHER_UNUSED,      /* IEEE80211_CIPHER_AES_CMAC */
        HAL_CIPHER_UNUSED,      /* IEEE80211_CIPHER_AES_CCM_256 */
        HAL_CIPHER_UNUSED,      /* IEEE80211_CIPHER_AES_CMAC_256 */
        HAL_CIPHER_UNUSED,      /* IEEE80211_CIPHER_AES_GCM */
        HAL_CIPHER_UNUSED,      /* IEEE80211_CIPHER_AES_GCM_256 */
        HAL_CIPHER_UNUSED,      /* IEEE80211_CIPHER_AES_GMAC */
        HAL_CIPHER_UNUSED,      /* IEEE80211_CIPHER_AES_GMAC_256 */
#if UMAC_SUPPORT_FILS
        HAL_CIPHER_UNUSED,      /* IEEE80211_CIPHER_FILS_AEAD */
#endif
        HAL_CIPHER_CLR,         /* IEEE80211_CIPHER_NONE */
    };
    const struct ieee80211_cipher *cip = k->wk_cipher;
    u_int8_t gmac[IEEE80211_ADDR_LEN];
    const u_int8_t *mac = NULL;
    HAL_KEYVAL hk;
    int opmode, status;
    int key_type;
    int psta = 0;

#if ATH_SUPPORT_WRAP
    struct ath_softc *sc;
    struct ath_vap_net80211 *avn = ATH_VAP_NET80211(vap);
    sc = ATH_DEV_TO_SC(scn->sc_dev);
#endif
    ASSERT(cip != NULL);
    if (cip == NULL)
        return 0;

    if (k->wk_keyix == IEEE80211_KEYIX_NONE)
        return 0;

    opmode = ieee80211vap_get_opmode(vap);
    memset(&hk, 0, sizeof(hk));
    /*
     * Software crypto uses a "clear key" so non-crypto
     * state kept in the key cache are maintained and
     * so that rx frames have an entry to match.
     */
    if ((k->wk_flags & IEEE80211_KEY_SWCRYPT) != IEEE80211_KEY_SWCRYPT) {
        KASSERT(cip->ic_cipher < (sizeof(ciphermap)/sizeof(ciphermap[0])),
                ("invalid cipher type %u", cip->ic_cipher));
        key_type = ciphermap[cip->ic_cipher];
#if ATH_SUPPORT_WAPI
        if (key_type == HAL_CIPHER_WAPI)
            OS_MEMCPY(hk.kv_mic, k->wk_txmic, IEEE80211_MICBUF_SIZE);
#endif
        hk.kv_len  = k->wk_keylen;
        OS_MEMCPY(hk.kv_val, k->wk_key, k->wk_keylen);
    } else
        key_type = HAL_CIPHER_CLR;

    /*
     *  Strategy:
     *   For _M_STA mc tx, we will not setup a key at all since we never tx mc.
     *       _M_STA mc rx, we will use the keyID.
     *   for _M_IBSS mc tx, we will use the keyID, and no macaddr.
     *   for _M_IBSS mc rx, we will alloc a slot and plumb the mac of the peer node. BUT we
     *       will plumb a cleartext key so that we can do perSta default key table lookup
     *       in software.
     */
	if (k->wk_flags & IEEE80211_KEY_GROUP) {
		switch (opmode) {
			case IEEE80211_M_STA:
#if ATH_SUPPORT_WRAP
                                if (avn->av_is_psta && !(avn->av_is_mpsta)){
                                    QDF_PRINT_INFO(sc->sc_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:Ignore set group key for psta\n",__func__);
                                    return 1;
                                }
#endif
				/* default key:  could be group WPA key or could be static WEP key */
				if (ieee80211_wep_mbssid_mac(vap, k, gmac))
					mac = gmac;
				else
#if ATH_SUPPORT_WRAP
                    if(sc->sc_enableproxysta && ath_hal_getcapability(sc->sc_ah, HAL_CAP_WRAP_HW_DECRYPT, 0, NULL) == HAL_OK) {
                        /*group key should have RootAP mac address to recv bcast packets from RootAP*/
                        IEEE80211_ADDR_COPY(gmac, vap->iv_bss->ni_macaddr);
                        gmac[0] |= 0x01;
                        mac = gmac;
                    } else {
                        mac = NULL;
                    }
#else
                mac = NULL;
#endif
                break;

        case IEEE80211_M_IBSS:
            if (k->wk_flags & IEEE80211_KEY_RECV) {
                if (k->wk_flags & IEEE80211_KEY_PERSTA) {
                    //ASSERT(scn->sc_mcastkey); /* require this for perSta keys */
                    ASSERT(k->wk_keyix >= IEEE80211_WEP_NKID);

                    /*
                     * Group keys on hardware that supports multicast frame
                     * key search use a mac that is the sender's address with
                     * the bit 0 set instead of the app-specified address.
                     * This is a flag to indicate to the HAL that this is
                     * multicast key. Using any other bits for this flag will
                     * corrupt the MAC address.
                     * XXX: we should use a new parameter called "Multicast" and
                     * pass it to key_set routines instead of embedding this flag.
                     */
                    IEEE80211_ADDR_COPY(gmac, peermac);
                    gmac[0] |= 0x01;
                    mac = gmac;
                } else {
                    /* static wep */
                    mac = NULL;
                }
            } else if (k->wk_flags & IEEE80211_KEY_XMIT) {
                ASSERT(k->wk_keyix < IEEE80211_WEP_NKID);
                mac = NULL;
            } else {
                ASSERT(0);
                status = 0;
                goto done;
            }
            break;

        case IEEE80211_M_HOSTAP:
            if (scn->sc_mcastkey) {
                /*
                 * Group keys on hardware that supports multicast frame
                 * key search use a mac that is the sender's address with
                 * the bit 0 set instead of the app-specified address.
                 * This is a flag to indicate to the HAL that this is
                 * multicast key. Using any other bits for this flag will
                 * corrupt the MAC address.
                 * XXX: we should use a new parameter called "Multicast" and
                 * pass it to key_set routines instead of embedding this flag.
                 */
                IEEE80211_ADDR_COPY(gmac, vap->iv_bss->ni_macaddr);
                gmac[0] |= 0x01;
                mac = gmac;
            } else
                mac = peermac;
            break;

        default:
            ASSERT(0);
            break;
        }
    } else {
        /* key mapping key */
        ASSERT(k->wk_keyix >= IEEE80211_WEP_NKID);
        mac = peermac;
    }

    if ((mac != NULL))
        ni = ieee80211_find_node(&ic->ic_sta, mac);

#ifdef ATH_SUPPORT_UAPSD
    /*
     * For MACs that support trigger classification using keycache
     * set the bits to indicate trigger-enabled ACs.
     */
    if ((scn->sc_ops->have_capability(scn->sc_dev, ATH_CAP_EDMA_SUPPORT)) &&
       (opmode == IEEE80211_M_HOSTAP))
    {
        struct ieee80211_node *ni = NULL;
        u_int8_t ac;
        if(mac) {
            ni = ieee80211_vap_find_node(vap, mac);
        }
        if (ni) {
            for (ac = 0; ac < WME_NUM_AC; ac++) {
                hk.kv_apsd |= (ni->ni_uapsd_ac_trigena[ac]) ? (1 << ac) : 0;
            }
            ieee80211_free_node(ni);
        }
    }
#endif

#if ATH_SUPPORT_WRAP
	if (is_proxy_addr) {
#if WRAP_HW_DECRYPT_PSTA_WEP
			struct ath_vap_net80211 *avn = ATH_VAP_NET80211(vap);

			if (k->wk_keyix == avn->av_psta_key.wk_keyix) {
				mac = peermac;
			}
#endif
		psta = HAL_KEY_PROXY_STA_MASK;
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_WRAP, "%s: set proxy key %u type "
                "0x%x flags 0x%x mac addr %s\n", __func__,
                k->wk_keyix, key_type | psta, k->wk_flags,
                mac ? ether_sprintf(mac) : "(null)");
    }
#if WRAP_HW_ENCRYPT_WRAP_WEP
    {
        struct ath_vap_net80211 *avn = ATH_VAP_NET80211(vap);

        if (avn->av_is_wrap &&
            key_type == HAL_CIPHER_WEP &&
            k->wk_keyix != avn->av_psta_key.wk_keyix)
        {
            /*
             * Put zero mac address in the key cache [0-3] entries
             * for hw encryption only.
             */
            mac = NULL;
        }
    }
#endif
#endif

    hk.kv_type = key_type | psta;

    if (key_type == HAL_CIPHER_TKIP &&
        (k->wk_flags & IEEE80211_KEY_SWMIC) != IEEE80211_KEY_SWMIC)
    {
        status = ath_keyset_tkip(scn, k, &hk, mac);
    } else {
        status = (scn->sc_ops->key_set(scn->sc_dev, k->wk_keyix, &hk, mac) != 0);
        KEYPRINTF(scn, k->wk_keyix, &hk, mac);
    }

    if ((mac != NULL) && (cip->ic_cipher == IEEE80211_CIPHER_TKIP)) {
        struct ieee80211com *ic = vap->iv_ic;
        struct ieee80211_node *ni;
        ni = ieee80211_find_node(&ic->ic_sta, mac);
        if (ni) {
            ni->ni_flags |= IEEE80211_NODE_WEPTKIP;
            ath_net80211_rate_node_update(ic, ni, 1);
            ieee80211_free_node(ni);
        }
    }

    if ((k->wk_flags & IEEE80211_KEY_MFP) && (opmode == IEEE80211_M_STA)) {
        /* Create a clear key entry to be used for MFP */
        key_type = HAL_CIPHER_CLR;
        hk.kv_type = key_type | psta;
        KEYPRINTF(scn, k->wk_clearkeyix, &hk, mac);
        status = (scn->sc_ops->key_set(scn->sc_dev, k->wk_clearkeyix, &hk, NULL) != 0);
    }
#if ATH_SUPPORT_KEYPLUMB_WAR
    if (ni && status)
    {
        /* Save hal key, keyix, macaddr and use it later to check for keycache corruption */
        scn->sc_ops->save_halkey(ATH_NODE_NET80211(ni)->an_sta, &hk, k->wk_keyix, mac);
    }
#endif
    if (ni)
        ieee80211_free_node(ni);
done:
    return status;
}

#if ATH_SUPPORT_KEYPLUMB_WAR
static int ath_key_checkandplumb(struct ieee80211vap *vap,
        struct ieee80211_node *ni)
{

    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(vap->iv_ic);
    struct ieee80211_key *k = &ni->ni_ucastkey;

    return scn->sc_ops->checkandplumb_key(scn->sc_dev, ATH_NODE_NET80211(ni)->an_sta, k->wk_keyix);
}
#endif
static int
ath_key_set(struct ieee80211vap *vap,
            struct ieee80211_key *k,
            const u_int8_t peermac[IEEE80211_ADDR_LEN])
{
    int is_proxy_addr = 0;
#if ATH_SUPPORT_WRAP
    struct ath_vap_net80211 *avn = ATH_VAP_NET80211(vap);
    struct ieee80211com *ic = vap->iv_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_softc *sc = scn->sc_dev;
    bool   wrap_hw_decrypt = 0;
    if(ath_hal_getcapability(sc->sc_ah, HAL_CAP_WRAP_HW_DECRYPT, 0, NULL) == HAL_OK) {
        /*If HW Decryption is supported for WRAP feature, plumb group key in keycache
         * and dont enable sw decryption flags*/
         wrap_hw_decrypt = 1;
     }

    if (avn->av_is_wrap) {
        /*
         * See the WRAP hardware crypto configuration options at the
         * beginning for more details.
         */
       if ((k->wk_flags & IEEE80211_KEY_GROUP &&
             k->wk_cipher->ic_cipher != IEEE80211_CIPHER_WEP && !wrap_hw_decrypt) ||
            (!WRAP_HW_ENCRYPT_WRAP_WEP && k->wk_cipher->ic_cipher == IEEE80211_CIPHER_WEP) ||
            (!WRAP_HW_ENCRYPT_WRAP_TKIP && k->wk_cipher->ic_cipher == IEEE80211_CIPHER_TKIP) ||
            (!WRAP_HW_ENCRYPT_WRAP_CCMP && k->wk_cipher->ic_cipher == IEEE80211_CIPHER_AES_CCM))
        {
            k->wk_flags |= IEEE80211_KEY_SWCRYPT | IEEE80211_KEY_SWMIC;
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_WRAP, "%s: use software "
                    "encryption/decryption for WRAP VAP key type %d, "
                    "wk_flags 0x%x, keyix %d. Skip hardware key_set.\n",
                    __func__, k->wk_cipher->ic_cipher, k->wk_flags, k->wk_key);
            return 1;
        } else if (!wrap_hw_decrypt) {
            k->wk_flags |= IEEE80211_KEY_SWDECRYPT;
            if (k->wk_cipher->ic_cipher == IEEE80211_CIPHER_TKIP)
                k->wk_flags |= IEEE80211_KEY_SWDEMIC;

            IEEE80211_DPRINTF(vap, IEEE80211_MSG_WRAP, "%s: use software "
                    "decryption for WRAP VAP key type %d, wk_flags 0x%x, "
                    "keyix %d. Still do hardware key_set.\n",
                    __func__, k->wk_cipher->ic_cipher, k->wk_flags, k->wk_key);
        }
    } else if (avn->av_is_psta) {
        int ret;

        /*
         * PSTA VAP's use software decryption for TKIP and
         * group addressed frames.
         */
       if ((k->wk_flags & IEEE80211_KEY_GROUP &&
             k->wk_cipher->ic_cipher != IEEE80211_CIPHER_WEP && !wrap_hw_decrypt) ||
            (!WRAP_HW_DECRYPT_PSTA_WEP && k->wk_cipher->ic_cipher == IEEE80211_CIPHER_WEP) ||
            (!WRAP_HW_DECRYPT_PSTA_TKIP && k->wk_cipher->ic_cipher == IEEE80211_CIPHER_TKIP))
        {
            k->wk_flags |= IEEE80211_KEY_SWCRYPT | IEEE80211_KEY_SWMIC;
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_WRAP, "%s: use software "
                    "decryption for PSTA VAP key type %d, wk_flags 0x%x, "
                    "keyix %d. Skip hardware key_set.\n",
                    __func__, k->wk_cipher->ic_cipher, k->wk_flags, k->wk_key);
            return 1;
        }

       if (!(wrap_hw_decrypt && (k->wk_flags & IEEE80211_KEY_GROUP))) {
		   ret = ieee80211_crypto_newkey(vap, k->wk_cipher->ic_cipher,
				   k->wk_flags, &avn->av_psta_key);
		   if (!ret) {
			   IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY, "%s: "
					   "ieee80211_crypto_newkey failed %d!\n", __func__, ret);
			   return ret;
		   }
		   memcpy(avn->av_psta_key.wk_key, k->wk_key, sizeof(k->wk_key));
		   avn->av_psta_key.wk_keylen = k->wk_keylen;
		   peermac = vap->iv_myaddr;
		   is_proxy_addr = 1;
		   IEEE80211_DPRINTF(vap, IEEE80211_MSG_WRAP, "%s: wk_key %d, psta key %d\n",
				   __func__, k->wk_keyix, avn->av_psta_key.wk_keyix);

		   /* only used for PSTA hardware WEP decryption */
		   if (WRAP_HW_DECRYPT_PSTA_WEP && k->wk_cipher->ic_cipher == IEEE80211_CIPHER_WEP) {
			   __ath_key_set(vap, &avn->av_psta_key, vap->iv_myaddr, 1);
			   IEEE80211_DPRINTF(vap, IEEE80211_MSG_WRAP, "%s: set hardware WEP "
					   "for psta key %d\n", __func__, avn->av_psta_key.wk_keyix);
		   }
	   }
	}
#endif

    return __ath_key_set(vap, k, peermac, is_proxy_addr);
}

#if ATH_SUPPORT_WRAP
/*
 * Set the key cache contents for the specified proxy key.
 *
 * Return: non-zero for success, 0 for fail
 */
static int
ath_setup_proxykey(struct ieee80211vap *vap, const u_int8_t *proxy_mac,
                   struct ieee80211_key *k)
{
    u_int16_t keyix;

    ieee80211_crypto_resetkey(vap, k, IEEE80211_KEYIX_NONE);

    keyix = ath_key_alloc(vap, k);

    if (keyix == IEEE80211_KEYIX_NONE) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_WRAP, "%s: ath_key_alloc "
                "failed!\n", __func__);
        return -1;
    }

    k->wk_flags |= IEEE80211_KEY_RECV;
    k->wk_keyix = keyix;

    return __ath_key_set(vap, k, proxy_mac, 1);
}

static int
ath_setup_wrap_key(struct ieee80211vap *vap, const u_int8_t *mac,
                   struct ieee80211_key *k)
{
    u_int16_t keyix;
    struct ieee80211com *ic = vap->iv_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_softc *sc = scn->sc_dev;
    u_int8_t bmac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    struct ieee80211_key *key;
    int ret_value;

    ieee80211_crypto_resetkey(vap, k, IEEE80211_KEYIX_NONE);

    keyix = ath_key_alloc(vap, k);

    if (keyix == IEEE80211_KEYIX_NONE) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_WRAP, "%s: ath_key_alloc "
                "failed!\n", __func__);
        return 0;
    }

    k->wk_flags |= IEEE80211_KEY_SWCRYPT | IEEE80211_KEY_SWMIC;
    k->wk_keyix = keyix;

    /*
     * We still need to set the is_proxy_addr=1 here for WRAP VAP so that
     * hardware will ACK unicast frames to the AP.
     */
    ret_value =__ath_key_set(vap, k, mac, 1);
    if(ath_hal_getcapability(sc->sc_ah, HAL_CAP_WRAP_PROMISC, 0, NULL) == HAL_ENOTSUPP) {
        /* create key cache entry with bcast address to receive wild card probe request*/
        key = (struct ieee80211_key *)OS_MALLOC(ic->ic_osdev, sizeof(struct ieee80211_key), GFP_KERNEL);
        ieee80211_crypto_resetkey(vap, key, IEEE80211_KEYIX_NONE);
        keyix = ath_key_alloc(vap, key);

        if (keyix == IEEE80211_KEYIX_NONE) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_WRAP, "%s: ath_key_alloc "
                    "failed!\n", __func__);
            QDF_PRINT_INFO(sc->sc_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: ath_key_alloc "
                   "failed!\n", __func__);
            return 0;
		}
        key->wk_keyix = keyix;
        __ath_key_set(vap, key, bmac, 0);
    }
    return ret_value;
}
#endif

/*
 * key cache management
 * Key cache slot is allocated for open and wep cases
 */

 /*
 * Allocate a key cache slot to the station so we can
 * setup a mapping from key index to node. The key cache
 * slot is needed for managing antenna state and for
 * compression when stations do not use crypto.  We do
 * it uniliaterally here; if crypto is employed this slot
 * will be reassigned.
 */

static void
ath_setup_stationkey(struct ieee80211_node *ni)
{
    struct ieee80211vap *vap = ni->ni_vap;
    u_int16_t keyix;

    keyix = ath_key_alloc(vap, &ni->ni_ucastkey);
    if (keyix == IEEE80211_KEYIX_NONE) {
        /*
         * Key cache is full; we'll fall back to doing
         * the more expensive lookup in software.  Note
         * this also means no h/w compression.
         */
        /* XXX msg+statistic */
        return;
    } else {
        ni->ni_ucastkey.wk_keyix = keyix;
        ni->ni_ucastkey.wk_valid = AH_TRUE;
        /* NB: this will create a pass-thru key entry */
        ath_key_set(vap, &ni->ni_ucastkey, ni->ni_macaddr);

    }

    return;
}

/* Setup WEP key for the station if compression is negotiated.
 * When station and AP are using same default key index, use single key
 * cache entry for receive and transmit, else two key cache entries are
 * created. One for receive with MAC address of station and one for transmit
 * with NULL mac address. On receive key cache entry de-compression mask
 * is enabled.
 */

static void
ath_setup_stationwepkey(struct ieee80211_node *ni)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211_key *ni_key;
    struct ieee80211_key tmpkey;
    struct ieee80211_key *rcv_key, *xmit_key;
    int    txkeyidx, rxkeyidx = IEEE80211_KEYIX_NONE,i;
    u_int8_t null_macaddr[IEEE80211_ADDR_LEN] = {0,0,0,0,0,0};

    KASSERT(ni->ni_ath_defkeyindex < IEEE80211_WEP_NKID,
            ("got invalid node key index 0x%x", ni->ni_ath_defkeyindex));
    KASSERT(vap->iv_def_txkey < IEEE80211_WEP_NKID,
            ("got invalid vap def key index 0x%x", vap->iv_def_txkey));

    /* Allocate a key slot first */
    if (!ieee80211_crypto_newkey(vap,
                                 IEEE80211_CIPHER_WEP,
                                 IEEE80211_KEY_XMIT|IEEE80211_KEY_RECV,
                                 &ni->ni_ucastkey)) {
        return;
    }

    txkeyidx = ni->ni_ucastkey.wk_keyix;
    xmit_key = &vap->iv_nw_keys[vap->iv_def_txkey];

    /* Do we need seperate rx key? */
    if (ni->ni_ath_defkeyindex != vap->iv_def_txkey) {
        ni->ni_ucastkey.wk_keyix = IEEE80211_KEYIX_NONE;
        if (!ieee80211_crypto_newkey(vap,
                                     IEEE80211_CIPHER_WEP,
                                     IEEE80211_KEY_XMIT|IEEE80211_KEY_RECV,
                                     &ni->ni_ucastkey)) {
            ni->ni_ucastkey.wk_keyix = txkeyidx;
            ieee80211_crypto_delkey(vap, &ni->ni_ucastkey, ni);
            return;
        }
        rxkeyidx = ni->ni_ucastkey.wk_keyix;
        ni->ni_ucastkey.wk_keyix = txkeyidx;

        rcv_key = &vap->iv_nw_keys[ni->ni_ath_defkeyindex];
    } else {
        rcv_key = xmit_key;
        rxkeyidx = txkeyidx;
    }

    /* Remember receive key offset */
    ni->ni_rxkeyoff = rxkeyidx - txkeyidx;

    /* Setup xmit key */
    ni_key = &ni->ni_ucastkey;
    if (rxkeyidx != txkeyidx) {
        ni_key->wk_flags = IEEE80211_KEY_XMIT;
    } else {
        ni_key->wk_flags = IEEE80211_KEY_XMIT|IEEE80211_KEY_RECV;
    }
    ni_key->wk_keylen = xmit_key->wk_keylen;
    for(i=0;i<IEEE80211_TID_SIZE;++i)
        ni_key->wk_keyrsc[i] = xmit_key->wk_keyrsc[i];
    ni_key->wk_keytsc = 0;
    OS_MEMZERO(ni_key->wk_key, sizeof(ni_key->wk_key));
    OS_MEMCPY(ni_key->wk_key, xmit_key->wk_key, xmit_key->wk_keylen);
    ieee80211_crypto_setkey(vap, &ni->ni_ucastkey,
                            (rxkeyidx == txkeyidx) ? ni->ni_macaddr : null_macaddr,
                            (rxkeyidx == txkeyidx) ? ni : NULL);

    if (rxkeyidx != txkeyidx) {
        /* Setup recv key */
        ni_key = &tmpkey;
        ni_key->wk_keyix = rxkeyidx;
        ni_key->wk_flags = IEEE80211_KEY_RECV;
        ni_key->wk_keylen = rcv_key->wk_keylen;

        for(i = 0; i < IEEE80211_TID_SIZE; ++i)
            ni_key->wk_keyrsc[i] = rcv_key->wk_keyrsc[i];

        ni_key->wk_keytsc = 0;
        ni_key->wk_cipher = rcv_key->wk_cipher;
        ni_key->wk_private = rcv_key->wk_private;
        OS_MEMZERO(ni_key->wk_key, sizeof(ni_key->wk_key));
        OS_MEMCPY(ni_key->wk_key, rcv_key->wk_key, rcv_key->wk_keylen);
        ieee80211_crypto_setkey(vap, &tmpkey, ni->ni_macaddr, ni);
    }

    return;
}

/* Create a keycache entry for given node in clearcase as well as static wep.
 * For non clearcase/static wep case, the key is plumbed by hostapd.
 */
static void
ath_setup_keycacheslot(struct ieee80211_node *ni)
{
    struct ieee80211vap *vap = ni->ni_vap;

    if (ni->ni_ucastkey.wk_keyix != IEEE80211_KEYIX_NONE) {
        ieee80211_crypto_delkey(vap, &ni->ni_ucastkey, ni);
    }

    /* Only for clearcase and WEP case */
    if (!IEEE80211_VAP_IS_PRIVACY_ENABLED(vap) ||
        (ni->ni_ath_defkeyindex != IEEE80211_INVAL_DEFKEY)) {

        if (!IEEE80211_VAP_IS_PRIVACY_ENABLED(vap)) {
            KASSERT(ni->ni_ucastkey.wk_keyix  \
                    == IEEE80211_KEYIX_NONE, \
                    ("new node with a ucast key already setup (keyix %u)",\
                     ni->ni_ucastkey.wk_keyix));
            /*
             * For now, all chips support clr key.
             * // NB: 5210 has no passthru/clr key support
             * if (scn->sc_ops->has_cipher(scn->sc_dev, HAL_CIPHER_CLR))
             *   ath_setup_stationkey(ni);
             */
            ath_setup_stationkey(ni);

        } else {
            ath_setup_stationwepkey(ni);
        }
    }

    return;
}

/*
 * Block/unblock tx+rx processing while a key change is done.
 * We assume the caller serializes key management operations
 * so we only need to worry about synchronization with other
 * uses that originate in the driver.
 */
static void
ath_key_update_begin(struct ieee80211vap *vap)
{
#if ATH_SUPPORT_FLOWMAC_MODULE
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(vap->iv_ic);
#endif

    DPRINTF(ATH_SOFTC_NET80211(vap->iv_ic), ATH_DEBUG_KEYCACHE, "%s:\n",
        __func__);
#if ATH_SUPPORT_FLOWMAC_MODULE
    /*
     * When called from the rx tasklet we cannot use
     * tasklet_disable because it will block waiting
     * for us to complete execution.
     *
     * XXX Using in_softirq is not right since we might
     * be called from other soft irq contexts than
     * ath_rx_tasklet.
     */
    if (scn->sc_ops->netif_stop_queue) {
        scn->sc_ops->netif_stop_queue(scn->sc_dev);
    }
#endif
    ATH_HTC_RXPAUSE(vap->iv_ic);
}

static void
ath_key_update_end(struct ieee80211vap *vap)
{
#if ATH_SUPPORT_FLOWMAC_MODULE
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211((vap->iv_ic));
#endif
    DPRINTF(ATH_SOFTC_NET80211(vap->iv_ic), ATH_DEBUG_KEYCACHE, "%s:\n",
        __func__);
#if ATH_SUPPORT_FLOWMAC_MODULE
    if(scn->sc_ops->netif_wake_queue) {
        scn->sc_ops->netif_wake_queue(scn->sc_dev);
    }
#endif
    ATH_HTC_RXUNPAUSE(vap->iv_ic);
}

static void ath_node_update_dyn_uapsd(struct ieee80211_node *ni, uint8_t ac, int8_t ac_delivery, int8_t ac_trigger)
{
	if ( ac_delivery <= WME_UAPSD_AC_MAX_VAL) {
		ni->ni_uapsd_dyn_delivena[ac] = ac_delivery;
	}

	if ( ac_trigger <= WME_UAPSD_AC_MAX_VAL) {
		ni->ni_uapsd_dyn_trigena[ac] = ac_trigger;
	}
	return;
}

static void
ath_update_ps_mode(struct ieee80211vap *vap)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211((vap->iv_ic));
    struct ath_vap_net80211 *avn = ATH_VAP_NET80211(vap);

    /*
     * if vap is not running (or)
     * if we are waiting for syncbeacon
     * nothing to do.
     */
    if (!ieee80211_vap_ready_is_set(vap) || scn->sc_syncbeacon)
        return;

    /*
     * reconfigure the beacon timers.
     */
    scn->sc_ops->sync_beacon(scn->sc_dev, avn->av_if_id);
}

static void
ath_net80211_pwrsave_set_state(struct ieee80211com *ic, IEEE80211_PWRSAVE_STATE newstate)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    switch (newstate) {
    case IEEE80211_PWRSAVE_AWAKE:
		if (!ieee80211_ic_ignoreDynamicHalt_is_set(ic)) {
	        ath_resume(scn);
		}
        scn->sc_ops->awake(scn->sc_dev);
        break;
    case IEEE80211_PWRSAVE_NETWORK_SLEEP:
#if UMAC_SUPPORT_WNM
        // In WNM-Sleep, update the listen interval
        scn->sc_ops->set_beacon_config(scn->sc_dev,ATH_BEACON_CONFIG_REASON_RESET, ATH_IF_ID_ANY);
#endif
        scn->sc_ops->netsleep(scn->sc_dev);
        break;
    case IEEE80211_PWRSAVE_FULL_SLEEP:
		if (!ieee80211_ic_ignoreDynamicHalt_is_set(ic)) {
	        ath_suspend(scn);
		}
		else if(ath_net80211_txq_depth(ic)) {
			break;
		}
        scn->sc_ops->fullsleep(scn->sc_dev);
        break;
    default:
        DPRINTF(scn, ATH_DEBUG_STATE, "%s: wrong power save state %u\n",
                __func__, newstate);
    }
}

#ifdef ENCAP_OFFLOAD
int
ath_get_cipher_map(u_int32_t  cipher, u_int32_t *halKeyType)
{
    if (cipher == IEEE80211_CIPHER_WEP)          *halKeyType = HAL_KEY_TYPE_WEP;
    else if (cipher == IEEE80211_CIPHER_TKIP)    *halKeyType = HAL_KEY_TYPE_TKIP;
    else if (cipher == IEEE80211_CIPHER_AES_OCB) *halKeyType = HAL_KEY_TYPE_AES;
    else if (cipher == IEEE80211_CIPHER_AES_CCM) *halKeyType = HAL_KEY_TYPE_AES;
    else if (cipher == IEEE80211_CIPHER_CKIP)    *halKeyType = HAL_KEY_TYPE_WEP;
    else if (cipher == IEEE80211_CIPHER_NONE)    *halKeyType = HAL_KEY_TYPE_CLEAR;
    else return 1;
    return 0;
}

int
ath_tx_data_prepare(struct ath_softc_net80211 *scn, wbuf_t wbuf, int nextfraglen,
        ieee80211_tx_control_t *txctl)
{
    struct ieee80211_node *ni = wbuf_get_node(wbuf);
    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211_rsnparms *rsn = &vap->iv_rsn;
    struct ieee80211_key *key = NULL;
    struct ether_header *eh;
    int keyix = 0, pktlen = 0;
    u_int8_t keyid = 0;
    HAL_KEY_TYPE keytype = HAL_KEY_TYPE_CLEAR;

#if defined(ATH_SUPPORT_UAPSD) && !defined(MAGPIE_HIF_GMAC)
    if (wbuf_is_uapsd(wbuf))
        return ath_tx_prepare(scn, wbuf, nextfraglen, txctl);
#endif

    OS_MEMZERO(txctl, sizeof(ieee80211_tx_control_t));
    eh = (struct ether_header *)wbuf_header(wbuf);

    txctl->ismcast = IEEE80211_IS_MULTICAST(eh->ether_dhost);
    txctl->istxfrag = 0;  /* currently hardcoding to 0, revisit */

    pktlen = wbuf_get_pktlen(wbuf);

    /*
     * Set per-packet exemption type
     */
    if ((eh->ether_type != htons(ETHERTYPE_PAE)) &&
        IEEE80211_VAP_IS_PRIVACY_ENABLED(vap))
        wbuf_set_exemption_type(wbuf, WBUF_EXEMPT_NO_EXEMPTION);
    else if ((eh->ether_type == htons(ETHERTYPE_PAE)) &&
             (RSN_AUTH_IS_WPA(rsn) || RSN_AUTH_IS_WPA2(rsn)))
        wbuf_set_exemption_type(wbuf,
                WBUF_EXEMPT_ON_KEY_MAPPING_KEY_UNAVAILABLE);
    else
        wbuf_set_exemption_type(wbuf, WBUF_EXEMPT_ALWAYS);

    if (IEEE80211_VAP_IS_PRIVACY_ENABLED(vap)) {    /* crypto is on */
        /*
         * Find the key that would be used to encrypt the frame if the
         * frame were to be encrypted. For unicast frame, search the
         * matching key in the key mapping table first. If not found,
         * used default key. For multicast frame, only use the default key.
         */
        if (vap->iv_opmode == IEEE80211_M_STA ||
            !IEEE80211_IS_MULTICAST(eh->ether_dhost) ||
            (vap->iv_opmode == IEEE80211_M_WDS &&
            IEEE80211_VAP_IS_STATIC_WDS_ENABLED(vap)))
            /* use unicast key */
            key = &ni->ni_ucastkey;

        if (key && key->wk_valid) {
            txctl->key_mapping_key = 1;
            keyid = 0;
        }else if (vap->iv_def_txkey != IEEE80211_KEYIX_NONE) {
            key   = &vap->iv_nw_keys[vap->iv_def_txkey];
            key   = key->wk_valid ? key : NULL;
            keyid = key ? (uint8_t)vap->iv_def_txkey : 0;
        }else
            key = NULL;

        if (key) {
            keyix = (int8_t)key->wk_keyix;
            if (ath_get_cipher_map(key->wk_cipher->ic_cipher, &keytype) != 0) {
                DPRINTF(scn,ATH_DEBUG_ANY,"%s: Failed to identify Hal Key Type for ic_cipher %d \n",
                    __func__, key->wk_cipher->ic_cipher);
                return 1;
            }
        }
    } else if ((ni->ni_ucastkey.wk_cipher == &ieee80211_cipher_none) &&
               (keyix != IEEE80211_KEYIX_NONE))
        keyix =  ni->ni_ucastkey.wk_keyix;
    else
        keyix = HAL_TXKEYIX_INVALID;


    pktlen += IEEE80211_CRC_LEN;

    txctl->frmlen      = pktlen;
    txctl->keyix       = keyix;
    txctl->keyid       = keyid;
    txctl->keytype     = keytype;
    txctl->txpower     = ieee80211_node_get_txpower(ni);
    txctl->nextfraglen = nextfraglen;

    /*
     * NB: the 802.11 layer marks whether or not we should
     * use short preamble based on the current mode and
     * negotiated parameters.
     */
    if (IEEE80211_IS_SHPREAMBLE_ENABLED(ic) &&
        !IEEE80211_IS_BARKER_ENABLED(ic) &&
        ieee80211node_has_cap(ni, IEEE80211_CAPINFO_SHORT_PREAMBLE))
        txctl->shortPreamble = 1;

#if !defined(ATH_SWRETRY) || !defined(ATH_SWRETRY_MODIFY_DSTMASK)
    txctl->flags = HAL_TXDESC_CLRDMASK;    /* XXX needed for crypto errs */
#endif

    txctl->isdata = 1;
    txctl->atype  = HAL_PKT_TYPE_NORMAL;     /* default */

    if (txctl->ismcast)
        txctl->mcast_rate = vap->iv_mcast_rate;

    if (IEEE80211_NODE_USEAMPDU(ni) || ni->ni_flags & IEEE80211_NODE_QOS) {
        int ac = wbuf_get_priority(wbuf);
        txctl->isqosdata = 1;

        /* XXX validate frame priority, remove mask */
        txctl->qnum = scn->sc_ac2q[ac & 0x3];
        if (ieee80211com_wmm_chanparams(ic, ac)->wmep_noackPolicy)
            txctl->flags |= HAL_TXDESC_NOACK;
    }
    else {
        /*
         * Default all non-QoS traffic to the best-effort queue.
         */
        txctl->qnum = scn->sc_ac2q[WME_AC_BE];
        wbuf_set_priority(wbuf, WME_AC_BE);
    }

    /*
    * For HT capable stations, we save tidno for later use.
    * We also override seqno set by upper layer with the one
    * in tx aggregation state.
     */
    if (!txctl->ismcast && ieee80211node_has_flag(ni, IEEE80211_NODE_HT))
        txctl->ht = 1;

    /* Update the uapsd ctl for all frames */
    ath_uapsd_txctl_update(scn, wbuf, txctl);
    /*
    * If we are servicing one or more stations in power-save mode.
     */
    txctl->if_id = (ATH_VAP_NET80211(vap))->av_if_id;
    if (ieee80211vap_has_pssta(vap))
        txctl->ps = 1;

    if (IEEE80211_VAP_IS_NOCABQ_ENABLED(vap)) {
        txctl->nocabq = 1;
    }

    /*
    * Calculate miscellaneous flags.
     */
    if (wbuf_is_eapol(wbuf)) {
        txctl->use_minrate = 1;
    }

    if (txctl->ismcast) {
        txctl->flags |= HAL_TXDESC_NOACK;   /* no ack on broad/multicast */
    } else if (pktlen > ieee80211vap_get_rtsthreshold(vap)) {
        txctl->flags |= HAL_TXDESC_RTSENA;  /* RTS based on frame length */
    }

    /* Frame to enable SM power save */
    if (wbuf_is_smpsframe(wbuf)) {
        txctl->flags |= HAL_TXDESC_LOWRXCHAIN;
    }

    IEEE80211_HTC_SET_NODE_INDEX(txctl, wbuf);

    return 0;

}
#endif

struct ieee80211_txctl_cap {
	u_int8_t ismgmt;
	u_int8_t ispspoll;
	u_int8_t isbar;
	u_int8_t isdata;
	u_int8_t isqosdata;
	u_int8_t use_minrate;
	u_int8_t atype;
	u_int8_t ac;
	u_int8_t use_ni_minbasicrate;
	u_int8_t use_mgt_rate;
};

enum {
	IEEE80211_MGMT_DEFAULT	= 0,
	IEEE80211_MGMT_BEACON	= 1,
	IEEE80211_MGMT_PROB_RESP = 2,
	IEEE80211_MGMT_PROB_REQ = 3,
	IEEE80211_MGMT_ATIM		= 4,
	IEEE80211_CTL_DEFAULT	= 5,
	IEEE80211_CTL_PSPOLL	= 6,
	IEEE80211_CTL_BAR		= 7,
	IEEE80211_DATA_DEFAULT	= 8,
	IEEE80211_DATA_NODATA	= 9,
	IEEE80211_DATA_QOS		= 10,
	IEEE80211_TYPE4TXCTL_MAX= 11,
};

struct ieee80211_txctl_cap txctl_cap[IEEE80211_TYPE4TXCTL_MAX] = {
		{ 1, 0, 0, 0, 0, 1, HAL_PKT_TYPE_NORMAL, WME_AC_VO, 1, 1}, 	/*default for mgmt*/
		{ 1, 0, 0, 0, 0, 1, HAL_PKT_TYPE_BEACON, WME_AC_VO, 1, 1}, 	/*beacon*/
		{ 1, 0, 0, 0, 0, 1, HAL_PKT_TYPE_PROBE_RESP, WME_AC_VO, 1, 1}, /*prob resp*/
		{ 1, 0, 0, 0, 0, 1, HAL_PKT_TYPE_NORMAL, WME_AC_VO, 0, 1}, 	/*prob req*/
		{ 1, 0, 0, 0, 0, 1, HAL_PKT_TYPE_ATIM, WME_AC_VO, 1, 1},  		/*atim*/
		{ 0, 0, 0, 0, 0, 1, HAL_PKT_TYPE_NORMAL, WME_AC_VO, 0, 0}, 	/*default for ctl*/
		{ 0, 1, 0, 0, 0, 1, HAL_PKT_TYPE_PSPOLL, WME_AC_VO, 0, 0}, 	/*pspoll*/
		{ 0, 0, 1, 0, 0, 1, HAL_PKT_TYPE_NORMAL, WME_AC_VO, 0, 0}, 	/*bar*/
		{ 0, 0, 0, 1, 0, 0, HAL_PKT_TYPE_NORMAL, WME_AC_BE, 0, 1}, 	/*default for data*/
		{ 1, 0, 0, 0, 0, 1, HAL_PKT_TYPE_NORMAL, WME_AC_VO, 1, 1},		/*nodata*/
		{ 0, 0, 0, 1, 1, 0, HAL_PKT_TYPE_NORMAL, WME_AC_BE, 0, 1}, 	/*qos data, the AC to be modified based on pkt's ac*/
};

int
ath_tx_prepare(struct ath_softc_net80211 *scn, wbuf_t wbuf, int nextfraglen,
               ieee80211_tx_control_t *txctl)
{
    struct ieee80211_node *ni = wbuf_get_node(wbuf);
    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211_frame *wh;
    int keyix, hdrlen, pktlen;
    int type, subtype;
	int txctl_tab_index;
	u_int32_t txctl_flag_mask = 0;
	u_int8_t acnum, use_ni_minbasicrate, use_mgt_rate;

    HAL_KEY_TYPE keytype = HAL_KEY_TYPE_CLEAR;
	HAL_KEY_TYPE keytype_table[IEEE80211_CIPHER_MAX] = {
	    HAL_KEY_TYPE_WEP,	/*IEEE80211_CIPHER_WEP*/
    	HAL_KEY_TYPE_TKIP,	/*IEEE80211_CIPHER_TKIP*/
	    HAL_KEY_TYPE_AES,	/*IEEE80211_CIPHER_AES_OCB*/
    	HAL_KEY_TYPE_AES,	/*IEEE80211_CIPHER_AES_CCM*/
#if ATH_SUPPORT_WAPI
	    HAL_KEY_TYPE_WAPI,	/*IEEE80211_CIPHER_WAPI*/
#else
		HAL_KEY_TYPE_CLEAR,
#endif
    	HAL_KEY_TYPE_WEP,	/*IEEE80211_CIPHER_CKIP*/
		HAL_KEY_TYPE_CLEAR,	/*IEEE80211_CIPHER_NONE*/
	};

    OS_MEMZERO(txctl, sizeof(ieee80211_tx_control_t));

    wh = (struct ieee80211_frame *)wbuf_header(wbuf);

    txctl->iseap = wbuf_is_eapol(wbuf);
    txctl->ismcast = IEEE80211_IS_MULTICAST(wh->i_addr1);
    txctl->istxfrag = (wh->i_fc[1] & IEEE80211_FC1_MORE_FRAG) ||
        (((le16toh(*((u_int16_t *)&(wh->i_seq[0]))) >>
           IEEE80211_SEQ_FRAG_SHIFT) & IEEE80211_SEQ_FRAG_MASK) > 0);
    type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

    /*
     * Packet length must not include any
     * pad bytes; deduct them here.
     */
    hdrlen = ieee80211_anyhdrsize(wh);
    pktlen = wbuf_get_pktlen(wbuf);
    if (type == IEEE80211_FC0_TYPE_CTL &&
        (subtype == IEEE80211_FC0_SUBTYPE_CTS || subtype == IEEE80211_FC0_SUBTYPE_ACK)) {
        /*
         * For CTS and ACK, the hdr size is only 2+2+6.
         * Skip the padding deduction for these frames.
         */
    } else
    pktlen -= (hdrlen & 3);

    if (IEEE80211_VAP_IS_SAFEMODE_ENABLED(vap)) {
        /* For Safe Mode, the encryption and its encap is already done
           by the upper layer software. Driver do not modify the packet. */
        keyix = HAL_TXKEYIX_INVALID;
    }
    else if (wh->i_fc[1] & IEEE80211_FC1_WEP) {
        const struct ieee80211_cipher *cip;
        struct ieee80211_key *k;

        /*
         * Construct the 802.11 header+trailer for an encrypted
         * frame. The only reason this can fail is because of an
         * unknown or unsupported cipher/key type.
         */

        /* FFXXX: change to handle linked wbufs */
        k = ieee80211_crypto_encap(ni, wbuf);
        if (k == NULL) {
            /*
             * This can happen when the key is yanked after the
             * frame was queued.  Just discard the frame; the
             * 802.11 layer counts failures and provides
             * debugging/diagnostics.
             */
            DPRINTF(scn,ATH_DEBUG_ANY,"%s: ieee80211_crypto_encap failed \n",__func__);
            return -EIO;
        }
        /* update the value of wh since encap can reposition the header */
        wh = (struct ieee80211_frame *)wbuf_header(wbuf);

        /*
         * Adjust the packet + header lengths for the crypto
         * additions and calculate the h/w key index. When
         * a s/w mic is done the frame will have had any mic
         * added to it prior to entry so wbuf pktlen above will
         * account for it. Otherwise we need to add it to the
         * packet length.
         */
        cip = k->wk_cipher;
        hdrlen += cip->ic_header;
#ifndef QCA_PARTNER_PLATFORM
        pktlen += cip->ic_header + cip->ic_trailer;
#else
        if (wbuf_is_encap_done(wbuf))
            pktlen += cip->ic_trailer;
        else
            pktlen += cip->ic_header + cip->ic_trailer;
#endif

        if ((k->wk_flags & IEEE80211_KEY_SWMIC) == 0) {
            if ( ! txctl->istxfrag)
                pktlen += cip->ic_miclen;
            else {
                if (cip->ic_cipher != IEEE80211_CIPHER_TKIP)
                    pktlen += cip->ic_miclen;
            }
        }
        else{
            pktlen += cip->ic_miclen;
        }
		if (cip->ic_cipher < IEEE80211_CIPHER_MAX) {
			keytype = keytype_table[cip->ic_cipher];
		}
        if (((k->wk_flags & IEEE80211_KEY_MFP) && IEEE80211_IS_MFP_FRAME(wh))) {
			if (cip->ic_cipher == IEEE80211_CIPHER_TKIP) {
            	DPRINTF(scn, ATH_DEBUG_KEYCACHE, "%s: extend MHDR IE\n", __func__);
	            /* mfp packet len could be extended by MHDR IE */
    	        pktlen += sizeof(struct ieee80211_ccx_mhdr_ie);
			}

            keyix = k->wk_clearkeyix;
            keytype = HAL_KEY_TYPE_CLEAR;
        }
        else
            keyix = k->wk_keyix;


    }  else if (ni->ni_ucastkey.wk_cipher == &ieee80211_cipher_none) {
        /*
         * Use station key cache slot, if assigned.
         */
        keyix = ni->ni_ucastkey.wk_keyix;
        if (keyix == IEEE80211_KEYIX_NONE)
            keyix = HAL_TXKEYIX_INVALID;
    } else
        keyix = HAL_TXKEYIX_INVALID;

    pktlen += IEEE80211_CRC_LEN;

    txctl->frmlen = pktlen;
    txctl->keyix = keyix;
    txctl->keytype = keytype;
    txctl->txpower = ieee80211_node_get_txpower(ni);
    txctl->nextfraglen = nextfraglen;
#ifdef USE_LEGACY_HAL
    txctl->hdrlen = hdrlen;
#endif
#if ATH_SUPPORT_IQUE
    txctl->tidno = wbuf_get_tid(wbuf);
#endif
    /*
     * NB: the 802.11 layer marks whether or not we should
     * use short preamble based on the current mode and
     * negotiated parameters.
     */
    if (IEEE80211_IS_SHPREAMBLE_ENABLED(ic) &&
        !IEEE80211_IS_BARKER_ENABLED(ic) &&
        ieee80211node_has_cap(ni, IEEE80211_CAPINFO_SHORT_PREAMBLE)) {
        txctl->shortPreamble = 1;
    }

#if !defined(ATH_SWRETRY) || !defined(ATH_SWRETRY_MODIFY_DSTMASK)
    txctl->flags = HAL_TXDESC_CLRDMASK;    /* XXX needed for crypto errs */
#endif

    /*
     * Calculate Atheros packet type from IEEE80211
     * packet header and select h/w transmit queue.
     */
	if (type == IEEE80211_FC0_TYPE_MGT) {
		if (subtype == IEEE80211_FC0_SUBTYPE_BEACON) {
			txctl_tab_index = IEEE80211_MGMT_BEACON;
		} else if (subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP) {
			txctl_tab_index = IEEE80211_MGMT_PROB_RESP;
		} else if (subtype == IEEE80211_FC0_SUBTYPE_PROBE_REQ) {
			txctl_tab_index = IEEE80211_MGMT_PROB_REQ;
		} else if (subtype == IEEE80211_FC0_SUBTYPE_ATIM) {
			txctl_tab_index = IEEE80211_MGMT_ATIM;
		} else {
			txctl_tab_index = IEEE80211_MGMT_DEFAULT;
		}
	} else if (type == IEEE80211_FC0_TYPE_CTL) {
		if (subtype == IEEE80211_FC0_SUBTYPE_PS_POLL) {
			txctl_tab_index = IEEE80211_CTL_PSPOLL;
		} else if (subtype == IEEE80211_FC0_SUBTYPE_BAR) {
			txctl_tab_index = IEEE80211_CTL_BAR;
		} else {
			txctl_tab_index = IEEE80211_CTL_DEFAULT;
		}
	} else if (type == IEEE80211_FC0_TYPE_DATA) {
		if (subtype == IEEE80211_FC0_SUBTYPE_NODATA) {
			txctl_tab_index = IEEE80211_DATA_NODATA;
		} else if (subtype & IEEE80211_FC0_SUBTYPE_QOS) {
			txctl_tab_index = IEEE80211_DATA_QOS;
		} else {
			txctl_tab_index = IEEE80211_DATA_DEFAULT;
		}
	} else {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "bogus frame type 0x%x (%s)\n",
               wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK, __func__);
        /* XXX statistic */
        return -EIO;
	}
	txctl->ismgmt = txctl_cap[txctl_tab_index].ismgmt;
	txctl->ispspoll = txctl_cap[txctl_tab_index].ispspoll;
	txctl->isbar = txctl_cap[txctl_tab_index].isbar;
	txctl->isdata = txctl_cap[txctl_tab_index].isdata;
	txctl->isqosdata = txctl_cap[txctl_tab_index].isqosdata;
#if ATH_SUPPORT_WIFIPOS
    if (wbuf_is_pos(wbuf) || wbuf_is_keepalive(wbuf)) {
        if (wbuf_is_keepalive(wbuf))
            txctl->use_minrate = 1;
        else
            txctl->use_minrate = 0;
    }
	else
#endif
	txctl->use_minrate = txctl_cap[txctl_tab_index].use_minrate;
	txctl->atype = txctl_cap[txctl_tab_index].atype;
	acnum = txctl_cap[txctl_tab_index].ac;
	use_ni_minbasicrate = txctl_cap[txctl_tab_index].use_ni_minbasicrate;
	use_mgt_rate = txctl_cap[txctl_tab_index].use_mgt_rate;

    /* set Tx delayed report indicator */
#ifdef ATH_SUPPORT_TxBF
    if ((type == IEEE80211_FC0_TYPE_MGT)&&(subtype == IEEE80211_FC0_SUBTYPE_ACTION)){
        u_int8_t *v_cv_data = (u_int8_t *)(wbuf_header(wbuf) + sizeof(struct ieee80211_frame));

        if ((*(v_cv_data+1) == IEEE80211_ACTION_HT_COMP_BF)
            || (*(v_cv_data+1) == IEEE80211_ACTION_HT_NONCOMP_BF))
        {
            txctl->isdelayrpt = 1;
        }
    }
#endif
       /*
        * In offchannel tx mode Update  txctl field to use minrate
        */
        if (wbuf_is_offchan_tx(wbuf))
        {
            txctl->use_minrate = 1;
        }
	/*
	 * Update some txctl fields
	 */
	if (type == IEEE80211_FC0_TYPE_DATA && subtype != IEEE80211_FC0_SUBTYPE_NODATA) {
        if (wbuf_is_eapol(wbuf)) {
            txctl->use_minrate = 1;
		}
        if (txctl->ismcast) {
            txctl->mcast_rate = vap->iv_mcast_rate;
#if UMAC_SUPPORT_WNM
            /* add FMS stuff to txctl */
            txctl->isfmss = wbuf_is_fmsstream(wbuf);
            txctl->fmsq_id = wbuf_get_fmsqid(wbuf);
#endif /* UMAC_SUPPORT_WNM */
		}
        if (subtype & IEEE80211_FC0_SUBTYPE_QOS) {
            /* XXX validate frame priority, remove mask */
            acnum = wbuf_get_priority(wbuf) & 0x03;

            if (ieee80211com_wmm_chanparams(ic, acnum)->wmep_noackPolicy)
                txctl_flag_mask |= HAL_TXDESC_NOACK;

#ifdef ATH_SUPPORT_TxBF
            /* Qos frame with Order bit set indicates an HTC frame */
            if (wh->i_fc[1] & IEEE80211_FC1_ORDER) {
                int is4addr;
                u_int8_t *htc;
                u_int8_t  *tmpdata;

                is4addr = ((wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) ==
                            IEEE80211_FC1_DIR_DSTODS) ? 1 : 0;
                if (!is4addr) {
                    htc = ((struct ieee80211_qosframe_htc *)wh)->i_htc;
        		} else {
                    htc= ((struct ieee80211_qosframe_htc_addr4 *)wh)->i_htc;
                }

                tmpdata=(u_int8_t *) wh;
                /* This is a sounding frame */
                if ((htc[2] == IEEE80211_HTC2_CSI_COMP_BF) ||
                    (htc[2] == IEEE80211_HTC2_CSI_NONCOMP_BF) ||
                    ((htc[2] & IEEE80211_HTC2_CalPos)==3))
                {
                    //printk("==>%s,txctl flag before attach sounding%x,\n",__func__,txctl->flags);
                    if (ic->ic_txbf.tx_staggered_sounding &&
                        ni->ni_txbf.rx_staggered_sounding)
                    {
                        //txctl->flags |= HAL_TXDESC_STAG_SOUND;
                        txctl_flag_mask|=(HAL_TXDESC_STAG_SOUND<<HAL_TXDESC_TXBF_SOUND_S);
                    } else {
                        txctl_flag_mask |= (HAL_TXDESC_SOUND<<HAL_TXDESC_TXBF_SOUND_S);
                    }
                    txctl_flag_mask |= (ni->ni_txbf.channel_estimation_cap<<HAL_TXDESC_CEC_S);
                    //printk("==>%s,txctl flag %x,tx staggered sounding %x, rx staggered sounding %x\n"
                    //    ,__func__,txctl->flags,ic->ic_txbf.tx_staggered_sounding,ni->ni_txbf.rx_staggered_sounding);
                }

                if ((htc[2] & IEEE80211_HTC2_CalPos)!=0)    // this is a calibration frame
                {
                     txctl_flag_mask|=HAL_TXDESC_CAL;
                }
            }
#endif

        } else {
            /*
             * Default all non-QoS traffic to the best-effort queue.
             */
            wbuf_set_priority(wbuf, WME_AC_BE);
        }


        txctl_flag_mask |=
                ((ieee80211com_get_ldpccap(ic) & IEEE80211_HTCAP_C_LDPC_TX) &&
               (ni->ni_htcap & IEEE80211_HTCAP_C_ADVCODING)) ?
               HAL_TXDESC_LDPC : 0;

        /*
         * For HT capable stations, we save tidno for later use.
         * We also override seqno set by upper layer with the one
         * in tx aggregation state.
         */
        if (!txctl->ismcast && ieee80211node_has_flag(ni, IEEE80211_NODE_HT))
            txctl->ht = 1;
	}
    if (txctl->isnulldata) txctl->ht = 0;
	/*
	 * Set min rate and qnum in txctl based on acnum
	 */
	if (txctl->use_minrate) {
		if (use_ni_minbasicrate) {
            /*
             * Send out all mangement frames except Probe request
             * at minimum rate set by AP.
             */
            if (vap->iv_opmode == IEEE80211_M_STA &&
                (ni->ni_minbasicrate != 0)) {
                txctl->min_rate = ni->ni_minbasicrate;
            }
		}

        /*
         * if management rate is set, then use it.
         */
        if (use_mgt_rate) {
			if (vap->iv_mgt_rate) {
    	        txctl->min_rate = vap->iv_mgt_rate;
        	}
		}
	}
    txctl->qnum = scn->sc_ac2q[acnum];
    /* Update the uapsd ctl for all frames */
    ath_uapsd_txctl_update(scn, wbuf, txctl);

    /*
     * If we are servicing one or more stations in power-save mode.
     */
    txctl->if_id = (ATH_VAP_NET80211(vap))->av_if_id;
    if (ieee80211vap_has_pssta(vap))
        txctl->ps = 1;

    if (IEEE80211_VAP_IS_NOCABQ_ENABLED(vap)) {
        txctl->nocabq = 1;
    }

    /*
     * Calculate miscellaneous flags.
     */
    if (txctl->ismcast) {
        txctl_flag_mask |= HAL_TXDESC_NOACK;	/* no ack on broad/multicast */
    } else if (pktlen > ieee80211vap_get_rtsthreshold(vap)) {
            txctl_flag_mask |= HAL_TXDESC_RTSENA;	/* RTS based on frame length */
    } else if (vap->iv_protmode == IEEE80211_PROTECTION_RTS_CTS) {
            txctl_flag_mask |= HAL_TXDESC_RTSENA;	/* RTS/CTS  */
    } else if (vap->iv_protmode == IEEE80211_PROTECTION_CTSTOSELF) {
            txctl_flag_mask |= HAL_TXDESC_CTSENA;	/* CTS only */
    }

    /* Frame to enable SM power save */
    if (wbuf_is_smpsframe(wbuf)) {
        txctl_flag_mask |= HAL_TXDESC_LOWRXCHAIN;
    }
#if ATH_SUPPORT_WIFIPOS
    /*
     * Update txctl flag for CTS frame
     * This change has been done because we donot need any rts for cts2self pkt.
     * Also, if the enable_duration is not set, HW will update the duration field
     * of the pkt, irrespective of its type.
     */
    if(wbuf_get_cts_frame(wbuf)) {
        txctl_flag_mask |= HAL_TXDESC_NOACK;
        txctl_flag_mask |= HAL_TXDESC_ENABLE_DURATION;
    }


    /* copy the locationing bit */
    if (wbuf_is_pos(wbuf)) {
        txctl_flag_mask |= HAL_TXDESC_POS;
        txctl->wifiposdata = wbuf_get_wifipos(wbuf);
        if (txctl->wifiposdata) {
            ieee80211_wifipos_reqdata_t *txchain_data = (ieee80211_wifipos_reqdata_t *)txctl->wifiposdata;
            u_int8_t update_txchainmask = txchain_data->txchainmask;
            if(wbuf_is_vmf(wbuf))
                txctl_flag_mask |= HAL_TXDESC_VMF;
            if(update_txchainmask == 1)
                txctl_flag_mask |= HAL_TXDESC_POS_TXCHIN_1;
            if(update_txchainmask == 3)
                txctl_flag_mask |= HAL_TXDESC_POS_TXCHIN_2;
            if(update_txchainmask == 7)
                txctl_flag_mask |= HAL_TXDESC_POS_TXCHIN_3;
            //printk("update_txchainmask %x (%s) %d\n",update_txchainmask,__func__,__LINE__);
            if(txchain_data->hc_channel == txchain_data->oc_channel) {
                txctl->qnum = scn->sc_wifipos_hc_qnum;
            } else {
                txctl->qnum = scn->sc_wifipos_oc_qnum;
        }
        }
    }
    if(wbuf_is_keepalive(wbuf)) {
        txctl_flag_mask |= HAL_TXDESC_POS_KEEP_ALIVE;
    }
#endif

	/*
	 * Update txctl->flags based on the flag mask
	 */
	txctl->flags |= txctl_flag_mask;
    IEEE80211_HTC_SET_NODE_INDEX(txctl, wbuf);

    return 0;
}

/*
 * The function to send a frame (i.e., hardstart). The wbuf should already be
 * associated with the actual frame, and have a valid node instance.
 */

int
ath_tx_send(wbuf_t wbuf)
{
    struct ieee80211_node *ni = wbuf_get_node(wbuf);
    struct ieee80211com *ic = ni->ni_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    wbuf_t next_wbuf;

    /*
     * XXX TODO: Fast frame here
     */

#ifdef ATH_SUPPORT_DFS
    /*
     * EV 10538/79856
     * If we detect radar on the current channel, stop sending data
     * packets. There is a DFS requirment that the AP should stop
     * sending data packet within 250 ms of radar detection
     */

    if (ic->ic_curchan->ic_flags & IEEE80211_CHAN_RADAR ||
        (ni->ni_vap && !ieee80211_vap_ready_is_set(ni->ni_vap))) {
        goto bad;
    }
#endif

    ath_uapsd_pwrsave_check(wbuf, ni);

#ifdef ATH_AMSDU
    /* Check whether AMSDU is supported in this BlockAck agreement */
    if (IEEE80211_NODE_USEAMPDU(ni) &&
        scn->sc_ops->get_amsdusupported(scn->sc_dev,
                                        ATH_NODE_NET80211(ni)->an_sta,
                                        wbuf_get_tid(wbuf)))
    {
        wbuf = ath_amsdu_send(wbuf);
        if (wbuf == NULL)
            return 0;
    }
#endif

    /*
     * Encapsulate the packet for transmission
     */
#if defined(ENCAP_OFFLOAD) && defined(ATH_SUPPORT_UAPSD) && !defined(MAGPIE_HIF_GMAC)
    if (wbuf_is_uapsd(wbuf))
        wbuf = ieee80211_encap_force(ni, wbuf);
    else
#endif
    wbuf = ieee80211_encap(ni, wbuf);
    if (wbuf == NULL) {
        DPRINTF(scn,ATH_DEBUG_ANY,"%s: ieee80211_encap failed \n",__func__);
        goto bad;
    }

    /*
     * If node is HT capable, then send out ADDBA if
     * we haven't done so.
     *
     * XXX: send ADDBA here to avoid re-entrance of other
     * tx functions.
     */
    if (IEEE80211_NODE_USEAMPDU(ni) &&
        ic->ic_addba_mode == ADDBA_MODE_AUTO) {
        u_int8_t tidno = wbuf_get_tid(wbuf);
        struct ieee80211_action_mgt_args actionargs;

        spin_lock(&ic->ic_addba_lock);
        if (
#ifdef ATH_SUPPORT_UAPSD
           (!IEEE80211_NODE_AC_UAPSD_ENABLED(ni, TID_TO_WME_AC(tidno))) &&
#endif
           (scn->sc_ops->check_aggr(scn->sc_dev, ATH_NODE_NET80211(ni)->an_sta, tidno)) &&
           /* don't allow EAPOL frame to cause addba to avoid auth timeouts */
           !wbuf_is_eapol(wbuf) &&
           !ieee80211node_has_flag(ni, IEEE80211_NODE_PWR_MGT))
        {
            /* Send ADDBA request */
            actionargs.category = IEEE80211_ACTION_CAT_BA;
            actionargs.action   = IEEE80211_ACTION_BA_ADDBA_REQUEST;
            actionargs.arg1     = tidno;
            actionargs.arg2     = WME_MAX_BA;
            actionargs.arg3     = 0;

            ieee80211_send_action(ni, &actionargs, NULL);
        }
        spin_unlock(&ic->ic_addba_lock);
    }

    /* send down each fragment */
    while (wbuf != NULL) {
        int nextfraglen = 0;
        int error = 0;
        ATH_DEFINE_TXCTL(txctl, wbuf);
        HTC_WBUF_TX_DELCARE

        next_wbuf = wbuf_next(wbuf);
        if (next_wbuf != NULL)
            nextfraglen = wbuf_get_pktlen(next_wbuf);


#ifdef ENCAP_OFFLOAD
        if (ath_tx_data_prepare(scn, wbuf, nextfraglen, txctl) != 0)
            goto bad;
#else
        /* prepare this frame */
        if (ath_tx_prepare(scn, wbuf, nextfraglen, txctl) != 0)
            goto bad;
#endif
        /* send this frame to hardware */
        txctl->an = (ATH_NODE_NET80211(ni))->an_sta;

#if ATH_DEBUG
        /* For testing purpose, set the RTS/CTS flag according to global setting */
        if (!txctl->ismcast) {
            if (ath_rtscts_enable == 2)
                    txctl->flags |= HAL_TXDESC_RTSENA;
            else if (ath_rtscts_enable == 1)
                    txctl->flags |= HAL_TXDESC_CTSENA;
        }
#endif

#if UMAC_PER_PACKET_DEBUG
        wbuf_set_rate(wbuf, ni->ni_vap->iv_userrate);
        wbuf_set_retries(wbuf, ni->ni_vap->iv_userretries);
        wbuf_set_txpower(wbuf, ni->ni_vap->iv_usertxpower);
        wbuf_set_txchainmask(wbuf, ni->ni_vap->iv_usertxchainmask);
#endif

        HTC_WBUF_TX_DATA_PREPARE(ic, scn);

        if (error == 0) {
            if (scn->sc_ops->tx(scn->sc_dev, wbuf, txctl) != 0) {
                goto bad;
            }
            else {
                HTC_WBUF_TX_DATA_COMPLETE_STATUS(ic);
            }
        }

        wbuf = next_wbuf;
    }

    return 0;

bad:
    /* drop rest of the un-sent fragments */
    while (wbuf != NULL) {
        next_wbuf = wbuf_next(wbuf);

        IEEE80211_TX_COMPLETE_WITH_ERROR(wbuf);

        wbuf = next_wbuf;
    }

    return -EIO;
}

/*
 * The function to send a management frame. The wbuf should already
 * have a valid node instance.
 */
int
ath_tx_mgt_send(struct ieee80211com *ic, wbuf_t wbuf)
{
    struct ieee80211_node *ni = wbuf_get_node(wbuf);
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_softc  *sc  = ATH_DEV_TO_SC(scn->sc_dev);
    int error = 0;
    struct ieee80211_frame *wh;
    int type, subtype;
    ATH_DEFINE_TXCTL(txctl, wbuf);

  #ifdef ATH_SUPPORT_HTC
    struct ath_usb_p2p_action_queue *p2p_action_wbuf = NULL;
  #endif
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);

    type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

    if ((type == IEEE80211_FC0_TYPE_MGT) &&
       (subtype == IEEE80211_FC0_SUBTYPE_ACTION)) {
        ath_uapsd_pwrsave_check(wbuf, ni);
    }

    txctl->iseap = 0;
    /* Just bypass fragmentation and fast frame. */
    error = ath_tx_prepare(scn, wbuf, 0, txctl);
    if (!error) {
        HTC_WBUF_TX_DELCARE

        /* send this frame to hardware */
        txctl->an = (ATH_NODE_NET80211(ni))->an_sta;

        HTC_WBUF_TX_MGT_PREPARE(ic, scn, txctl);
        HTC_WBUF_TX_MGT_COMPLETE_STATUS(ic);

      #ifdef ATH_SUPPORT_HTC
        if (ni) {
            HTC_WBUF_TX_MGT_P2P_PREPARE(scn, ni, wbuf, p2p_action_wbuf);
            HTC_WBUF_TX_MGT_P2P_INQUEUE(scn, p2p_action_wbuf);
        }
      #endif

        HTC_WBUF_TX_MGT_COMPLETE_STATUS(ic);
        error = scn->sc_ops->tx(scn->sc_dev, wbuf, txctl);
        if (!error) {
            HTC_WBUF_TX_MGT_ACTION_FRAME_NODE_FREE(ni);
            sc->sc_stats.ast_tx_mgmt++;
            sc->sc_stats.ast_tx_bytes += wbuf_get_pktlen(wbuf);
            return 0;
        } else {
          DPRINTF(scn,ATH_DEBUG_ANY,"%s: send mgt frame failed \n",__func__);
          #ifdef ATH_SUPPORT_HTC
          HTC_WBUF_TX_MGT_P2P_DEQUEUE(scn, p2p_action_wbuf);
          #endif
          HTC_WBUF_TX_MGT_ERROR_STATUS(ic);
        }
    }

    /* fall thru... */
    IEEE80211_TX_COMPLETE_WITH_ERROR(wbuf);
    return error;
}

static u_int32_t
ath_net80211_txq_depth(struct ieee80211com *ic)
{
    int ac, qdepth = 0;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    for (ac = WME_AC_BE; ac <= WME_AC_VO; ac++) {
        qdepth += scn->sc_ops->txq_depth(scn->sc_dev, scn->sc_ac2q[ac]);
    }
    return qdepth;
}

static u_int32_t
ath_net80211_txq_depth_ac(struct ieee80211com *ic,int ac)
{
    int qdepth = 0;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    qdepth = scn->sc_ops->txq_depth(scn->sc_dev, scn->sc_ac2q[ac]);
    return qdepth;
}

#if ATH_TX_COMPACT
#ifdef ATH_SUPPORT_QUICK_KICKOUT
void ieee80211_kick_node(struct ieee80211_node *ni);
static void
ath_net80211_tx_node_kick_event(struct ieee80211_node *ni, u_int8_t *consretry,wbuf_t wbuf)
{


#if ATH_SUPPORT_WIFIPOS
    if(wbuf_is_pos(wbuf) || wbuf_is_keepalive(wbuf)){
         return ;
    }
#endif

    /* if the node is not a NAWDS repeater and failed count reaches
     * a pre-defined limit, kick out the node
     */
    if ((ni->ni_vap) &&  (ni->ni_vap->iv_opmode == IEEE80211_M_HOSTAP) &&
            (ni != ni->ni_vap->iv_bss)) {

        if (((ni->ni_flags & IEEE80211_NODE_NAWDS) == 0) &&
                ( *consretry >= ni->ni_vap->iv_sko_th) &&
                (!ieee80211_vap_wnm_is_set(ni->ni_vap))) {
            if (ni->ni_vap->iv_sko_th != 0) {
                ieee80211_kick_node(ni);
            }
        }
    }

}
#endif

static uint16_t ieee80211_tx_radiotap_len(uint8_t ht)
{
    uint16_t len;

    len = sizeof(struct ieee80211_radiotap_header);

    /* TSF bit0 */
    len = ALIGN(len, 8);
    len += 8;

    /* flags */
    len++;

    /* rate */
    len++;
    
    /* channel */
    len += 2;

    /* channel flags */
    len += 2;
    
    len = ALIGN(len, 2);

    /* u8 knonw, u8 flags, u8 mcs */
    if (ht) {
        len++;
        len++;
        len++;
    }
    len = ALIGN(len, 2);

    return len;
}

typedef struct {
    u_int8_t    phy;         /* CCK/OFDM/HT */
    u_int32_t   rate_Kbps;   /* transfer rate in kbs */
    u_int8_t    rate_code;   /* rate for h/w descriptors */
    u_int8_t    mcs;         /* MCS for HT */
} rate_code_table;

#define NUM_RATES_DA    (70)
rate_code_table da_rates[NUM_RATES_DA] = {
    /*   1 Mb */ {IEEE80211_T_CCK,     1000,    0x1b,   0xff},
    /*   2 Mb */ {IEEE80211_T_CCK,     2000,    0x1a,   0xff},
    /*   2 Mb_S */ {IEEE80211_T_CCK,     2000,    0x1e,   0xff},
    /* 5.5 Mb */ {IEEE80211_T_CCK,     5500,    0x19,   0xff},
    /* 5.5 Mb_S */ {IEEE80211_T_CCK,     5500,    0x1d,   0xff},
    /*  11 Mb */ {IEEE80211_T_CCK,    11000,    0x18,   0xff},
    /*  11 Mb_S */ {IEEE80211_T_CCK,    11000,    0x1c,   0xff},
    /*   6 Mb */ {IEEE80211_T_OFDM,    6000,    0x0b,   0xff},
    /*   9 Mb */ {IEEE80211_T_OFDM,    9000,    0x0f,   0xff},
    /*  12 Mb */ {IEEE80211_T_OFDM,   12000,    0x0a,   0xff},
    /*  18 Mb */ {IEEE80211_T_OFDM,   18000,    0x0e,   0xff},
    /*  24 Mb */ {IEEE80211_T_OFDM,   24000,    0x09,   0xff},
    /*  36 Mb */ {IEEE80211_T_OFDM,   36000,    0x0d,   0xff},
    /*  48 Mb */ {IEEE80211_T_OFDM,   48000,    0x08,   0xff},
    /*  54 Mb */ {IEEE80211_T_OFDM,   54000,    0x0c,   0xff},
    /* 6.5 Mb */ {IEEE80211_T_HT,      6500,    0x80,    0},
    /*  13 Mb */ {IEEE80211_T_HT,     13000,    0x81,    1},
    /*19.5 Mb */ {IEEE80211_T_HT,     19500,    0x82,    2},
    /*  26 Mb */ {IEEE80211_T_HT,     26000,    0x83,    3},
    /*  39 Mb */ {IEEE80211_T_HT,     39000,    0x84,    4},
    /*  52 Mb */ {IEEE80211_T_HT,     52000,    0x85,    5},
    /*58.5 Mb */ {IEEE80211_T_HT,     58500,    0x86,    6},
    /*  65 Mb */ {IEEE80211_T_HT,     65000,    0x87,    7},
    /*  13 Mb */ {IEEE80211_T_HT,     13000,    0x88,    8},
    /*  26 Mb */ {IEEE80211_T_HT,     26000,    0x89,    9},
    /*  39 Mb */ {IEEE80211_T_HT,     39000,    0x8a,   10},
    /*  52 Mb */ {IEEE80211_T_HT,     52000,    0x8b,   11},
    /*  78 Mb */ {IEEE80211_T_HT,     78000,    0x8c,   12},
    /* 104 Mb */ {IEEE80211_T_HT,    104000,    0x8d,   13},
    /* 117 Mb */ {IEEE80211_T_HT,    117000,    0x8e,   14},
    /* 130 Mb */ {IEEE80211_T_HT,    130000,    0x8f,   15},
    /*19.5 Mb */ {IEEE80211_T_HT,     19500,    0x90,   16},
    /*  39 Mb */ {IEEE80211_T_HT,     39000,    0x91,   17},
    /*58.5 Mb */ {IEEE80211_T_HT,     58500,    0x92,   18},
    /*  78 Mb */ {IEEE80211_T_HT,     78000,    0x93,   19},
    /* 117 Mb */ {IEEE80211_T_HT,    117000,    0x94,   20},
    /* 156 Mb */ {IEEE80211_T_HT,    156000,    0x95,   21},
    /*175.5Mb */ {IEEE80211_T_HT,    175500,    0x96,   22},
    /* 195 Mb */ {IEEE80211_T_HT,    195000,    0x97,   23},
    /*216.7Mb */ {IEEE80211_T_HT,    216700,    0x97,   23},
    /*13.5 Mb */ {IEEE80211_T_HT,     13500,    0x80,    0},
    /*27.0 Mb */ {IEEE80211_T_HT,     27000,    0x81,    1},
    /*40.5 Mb */ {IEEE80211_T_HT,     40500,    0x82,    2},
    /* 54 Mb  */ {IEEE80211_T_HT,     54000,    0x83,    3},
    /* 81 Mb  */ {IEEE80211_T_HT,     81000,    0x84,    4},
    /*108 Mb  */ {IEEE80211_T_HT,    108000,    0x85,    5},
    /*121.5Mb */ {IEEE80211_T_HT,    121500,    0x86,    6},
    /*135 Mb  */ {IEEE80211_T_HT,    135000,    0x87,    7},
    /*150 Mb  */ {IEEE80211_T_HT,    150000,    0x87,    7},
    /* 27 Mb  */ {IEEE80211_T_HT,     27000,    0x88,    8},
    /* 54 Mb  */ {IEEE80211_T_HT,     54000,    0x89,    9},
    /* 81 Mb  */ {IEEE80211_T_HT,     81000,    0x8a,   10},
    /*108 Mb  */ {IEEE80211_T_HT,    108000,    0x8b,   11},
    /*162 Mb  */ {IEEE80211_T_HT,    162000,    0x8c,   12},
    /*216 Mb  */ {IEEE80211_T_HT,    216000,    0x8d,   13},
    /*243 Mb  */ {IEEE80211_T_HT,    243000,    0x8e,   14},
    /*270 Mb  */ {IEEE80211_T_HT,    270000,    0x8f,   15},
    /*300 Mb  */ {IEEE80211_T_HT,    300000,    0x8f,   15},
    /*40.5 Mb */ {IEEE80211_T_HT,     40500,    0x90,   16},
    /* 81 Mb  */ {IEEE80211_T_HT,     81000,    0x91,   17},
    /*121.5Mb */ {IEEE80211_T_HT,    121500,    0x92,   18},
    /*162 Mb  */ {IEEE80211_T_HT,    162000,    0x93,   19},
    /*243 Mb  */ {IEEE80211_T_HT,    243000,    0x94,   20},
    /*270 Mb  */ {IEEE80211_T_HT,    270000,    0x95,   21},
    /*324 Mb  */ {IEEE80211_T_HT,    324000,    0x95,   21},
    /*360 Mb  */ {IEEE80211_T_HT,    360000,    0x95,   21},
    /*364.5Mb */ {IEEE80211_T_HT,    364500,    0x96,   22},
    /*405 Mb  */ {IEEE80211_T_HT,    405000,    0x96,   22},
    /*405 Mb  */ {IEEE80211_T_HT,    405000,    0x97,   23},
    /*450 Mb  */ {IEEE80211_T_HT,    450000,    0x97,   23},
};

static uint32_t get_ht_mcs_from_ratekbps(uint32_t ratekbps)
{
    int i;
    uint32_t ht_mcs = 0;

    for (i=0; i<NUM_RATES_DA; i++){
        if (ratekbps == da_rates[i].rate_Kbps) {
            ht_mcs = da_rates[i].mcs;
            break;
        }
    }

    if (ht_mcs == 0xff) {
        qdf_print("%s: no mcs found for ht ratecode=0x%x\n", __func__, ratekbps);
        return -EINVAL;
    }

    return ht_mcs;
}

static uint8_t get_pream_from_ratekbps(uint32_t ratekbps)
{
    int i;
    uint8_t pream = IEEE80211_T_MAX;

    for (i=0; i<NUM_RATES_DA; i++){
        if (ratekbps == da_rates[i].rate_Kbps) {
            pream = da_rates[i].phy;
            break;
        }
    }

    if (pream == IEEE80211_T_MAX) {
        qdf_print("%s: preamble not found for ratecode=0x%x\n", __func__, ratekbps);
        return -EINVAL;
    }
    return pream;
}

static uint8_t
ieee80211_add_tx_radiotap_header(struct ieee80211_node *ni, struct sk_buff *skb, ieee80211_tx_status_t *ts)
{
#define DATA_PAD 0x05
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = vap->iv_ic;
    uint32_t *it_present_p = NULL;
    uint32_t it_present_mask = 0;
    uint16_t rtap_len;
    unsigned char *pos;
    struct ieee80211_radiotap_header *rthdr = NULL;
    struct sk_buff *tskb = NULL;
    uint8_t cck=0, ofdm=0, ht=0, mcs=0, pream=IEEE80211_T_MAX;
    uint16_t chan_flags = 0, padding = 0;
    uint16_t chan_freq = ieee80211_chan2freq(ic, ic->ic_curchan);
    uint8_t radiotap_mcs_details = 0;

    pream = get_pream_from_ratekbps(ts->rateKbps);
    switch (pream){
        case IEEE80211_T_CCK:
            cck = 1;
            break;
        case IEEE80211_T_OFDM:
            ofdm = 1;
            break;
        case IEEE80211_T_HT:
            ht = 1;
            break;
        default:
            qdf_print("%s: pream=%d not valid\n", __func__, pream);
            qdf_nbuf_free(skb);
            return 0;
    }

    rtap_len = ieee80211_tx_radiotap_len(ht);
    if (qdf_nbuf_headroom(skb) < rtap_len) {
        tskb = qdf_nbuf_realloc_headroom(skb, rtap_len);
        if(tskb!=NULL){
            /*
             * qdf_nbuf_realloc_headroom won't do skb_clone as skb_realloc_headroom does.
             * so, no free's needed here.
             */
            skb = tskb;
        } else {
            qdf_print("%s: skb_realloc_headroom failed\n", __func__);
            qdf_nbuf_free(skb);
            return 0;
        }
    }

    rthdr = (struct ieee80211_radiotap_header *) qdf_nbuf_push_head(skb, rtap_len);
    qdf_mem_zero(rthdr, rtap_len);
    rthdr->it_len = cpu_to_le16(rtap_len);
    it_present_p = &rthdr->it_present;
    pos = (uint8_t *)(rthdr + 1);

    /* present mask */
    it_present_mask = BIT(IEEE80211_RADIOTAP_FLAGS) | BIT(IEEE80211_RADIOTAP_CHANNEL);
    put_unaligned_le32(it_present_mask, it_present_p);
    /* 8-byte alignment */
    while((pos - (u_int8_t *)rthdr) & 7) {
        *pos++ = 0;
    }
    /* TSF bit0 */
    put_unaligned_le64(ts->tstamp, pos);
    rthdr->it_present |= cpu_to_le32(BIT(IEEE80211_RADIOTAP_TSFT));
    pos += 8;

    /* flags */
    padding = BIT(DATA_PAD); 
    /* Set Data pad to true in radiotap header so that decoders can ignore
     * 2 bytes padding found after the mac header and decode the LLC header correctly
     */
    put_unaligned_le16(padding, pos);
    pos++;

    /* rate */
    if (ht) {
        /* HT rates */
        *pos = 0;
    } else {
        /* Legacy rates */
        rthdr->it_present |= cpu_to_le32(BIT(IEEE80211_RADIOTAP_RATE));
        /* radiotap needs rate in units of 100 Kbps */
        *pos = DIV_ROUND_UP(ts->rateKbps/100, 5);
    }
    pos++;
    
    /* channel freq */
    put_unaligned_le16(chan_freq, pos);
    pos +=2;

    /* channel flags */
    chan_flags = ic->ic_curchan->ic_flags;
    if (ofdm || ht) {
        chan_flags |= IEEE80211_CHAN_OFDM;
    } else if (cck) {
        chan_flags |= IEEE80211_CHAN_CCK;
    }
    put_unaligned_le16(chan_flags, pos);
    pos += 2;
    
    /* mcs */
    if (ht) {
        rthdr->it_present |= cpu_to_le32(BIT(IEEE80211_RADIOTAP_MCS));
        radiotap_mcs_details |= IEEE80211_RADIOTAP_MCS_HAVE_STBC | \
                                IEEE80211_RADIOTAP_MCS_HAVE_MCS | IEEE80211_RADIOTAP_MCS_HAVE_GI | \
                                IEEE80211_RADIOTAP_MCS_HAVE_BW;
        *pos++ = radiotap_mcs_details;
        pos++;
        mcs = get_ht_mcs_from_ratekbps(ts->rateKbps);
        *pos++ = mcs;
    }
    return 1;
}

static void ieee80211_tx_monitor(struct ieee80211_node *ni, struct sk_buff *skb, ieee80211_tx_status_t *ts)
{
#define CHECKSUM_NONE       0
#define PACKET_OTHERHOST    3    
#define ETH_P_802_2         0x0004
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = NULL;
    struct net_device *netdev = NULL;
    osif_dev  *osifp = NULL;
    uint32_t promisc_active = false, pkt_delivered = false;

    if (ieee80211_add_tx_radiotap_header(ni, skb, ts)) {
    
        skb_reset_mac_header(skb);
        skb->ip_summed = CHECKSUM_NONE;
        skb->pkt_type = PACKET_OTHERHOST;
        skb->protocol = htons(ETH_P_802_2);
        memset(skb->cb, 0, sizeof(skb->cb)); 
        TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
            if (vap && (vap->iv_opmode == IEEE80211_M_MONITOR)) {
                osifp = (osif_dev *)vap->iv_ifp;
                netdev = osifp->netdev;
                promisc_active = ((netdev->flags & IFF_UP) ? true : false);
                if (promisc_active) {
                    netdev->type = ARPHRD_IEEE80211_RADIOTAP;
                    skb->dev = netdev;
                    netif_rx(skb);
                    pkt_delivered = true;
                    break;
                }
            }
        }
        if (!pkt_delivered) 
        {
            qdf_nbuf_free(skb);
        }
    }
}

void ath_net80211_tx_complete_compact(struct ieee80211_node *ni, wbuf_t wbuf, ieee80211_tx_status_t *ts)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211_frame *wh;
    int type, subtype;
    ieee80211_vap_complete_buf_handler handler;
    void *arg;

    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
#if ATH_SUPPORT_WIFIPOS
    if (wbuf_get_cts_frame(wbuf))
        ieee80211_cts_done(1);
#endif
    
    if (ic->tx_capture_da && !(ic->ic_is_mode_offload(ic))) {
        struct sk_buff *skbcpy;
        skbcpy = qdf_nbuf_copy((qdf_nbuf_t)wbuf);
        if (skbcpy != NULL)
            ieee80211_tx_monitor(ni, skbcpy, ts);
    }

    /* only management and null data frames have the handler function */
    if (type == IEEE80211_FC0_TYPE_MGT || subtype == IEEE80211_FC0_SUBTYPE_NODATA) {
        wbuf_get_complete_handler(wbuf,(void **)&handler,&arg);
        if (handler) {
            handler(ni->ni_vap,wbuf,arg,wh->i_addr1,wh->i_addr2,wh->i_addr3,NULL);
        }
    }

    return;
}

static void
ath_net80211_free_node(struct ieee80211_node *ni,int txok)
{

    if (txok== 0) {
        /* Incase of udp downlink only traffic,
        * reload the ni_inact every time when a
        * frame is successfully acked by station.
         */
        ni->ni_inact = ni->ni_inact_reload;
    }

#ifdef ATH_SUPPORT_QUICK_KICKOUT
    if ((ni->ni_vap) && (ni->ni_flags & IEEE80211_NODE_KICK_OUT_DEAUTH)
            && ieee80211_node_refcnt(ni)==1)
        /* checking node count to one to make sure that no more packets
           are buffered in hardware queue*/
    {
        struct ieee80211_node *tempni;
        u_int16_t associd = 0;

        associd = ni->ni_associd;
        ni->ni_flags &=~ IEEE80211_NODE_KICK_OUT_DEAUTH;
        tempni=ieee80211_tmp_node(ni->ni_vap, ni->ni_macaddr);
        if (tempni != NULL) {
            IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_AUTH,
                    "%s: sending DEAUTH to %s, sta kickout reason %d\n",
                    __func__, ether_sprintf(tempni->ni_macaddr), IEEE80211_REASON_AUTH_EXPIRE);
            ieee80211_send_deauth(tempni, IEEE80211_REASON_AUTH_EXPIRE);
            /* claim node immediately */
            ieee80211_free_node(tempni);
            IEEE80211_DELIVER_EVENT_MLME_DEAUTH_INDICATION(ni->ni_vap, ni->ni_macaddr,
                    associd, IEEE80211_REASON_AUTH_EXPIRE);
        }
    }
#endif

    ieee80211_free_node(ni);

}

static void ath_net80211_check_and_update_pn(wbuf_t wbuf)
{
    ieee80211_check_and_update_pn(wbuf);
}
#endif // ATH_TX_COMPACT
#ifdef ATH_SUPPORT_TxBF
void
ieee80211_tx_bf_completion_handler(struct ieee80211_node *ni,  struct ieee80211_tx_status *ts);
static void
ath_net80211_handle_txbf_comp(struct ieee80211_node *ni,u_int8_t txbf_status,  u_int32_t tstamp, u_int32_t txok)
{
    struct ieee80211_tx_status ts;
    ts.ts_txbfstatus = txbf_status;
    ts.ts_tstamp     = tstamp;
    ts.ts_flags = txok;
    ieee80211_tx_bf_completion_handler(ni,&ts);

}
#endif
#if ATH_TX_COMPACT
static void ath_net80211_tx_update_stats(wbuf_t wbuf, ieee80211_tx_status_t *tx_status)
{
    struct ieee80211_tx_status ts;
    struct ieee80211_frame *wh;
    struct ieee80211_node *ni = wbuf_get_node(wbuf);
    int type, subtype;
    if( ni!=NULL && ni->ni_vap!=NULL ) {
        ts.ts_flags =
                ((tx_status->flags & ATH_TX_ERROR) ? IEEE80211_TX_ERROR : 0) |
                ((tx_status->flags & ATH_TX_XRETRY) ? IEEE80211_TX_XRETRY : 0);
        ts.ts_retries = tx_status->retries;
	    ts.ts_rateKbps = tx_status->rateKbps;
        wh = (struct ieee80211_frame *)wbuf_header(wbuf);

        type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
        subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
    	if ( type==IEEE80211_FC0_TYPE_DATA ) {
            ieee80211_update_stats(ni->ni_vap, wbuf, wh, type, subtype, &ts);
        }
    }
}
#endif //ATH_TX_COMPACT
static void
ath_net80211_tx_complete(wbuf_t wbuf, ieee80211_tx_status_t *tx_status, bool all_frag)
{
    struct ieee80211_tx_status ts;
#if ATH_FRAG_TX_COMPLETE_DEFER
    wbuf_t currfrag = wbuf;
    wbuf_t nextfrag = NULL;
#endif

    ts.ts_flags =
        ((tx_status->flags & ATH_TX_ERROR) ? IEEE80211_TX_ERROR : 0) |
        ((tx_status->flags & ATH_TX_XRETRY) ? IEEE80211_TX_XRETRY : 0) |
        ((tx_status->flags & ATH_TX_FLUSH) ? IEEE80211_TX_FLUSH : 0);
    ts.ts_retries = tx_status->retries;

    ath_update_txbf_tx_status(ts, tx_status);

#if ATH_SUPPORT_FLOWMAC_MODULE
    ts.ts_flowmac_flags |= IEEE80211_TX_FLOWMAC_DONE;
#endif
	ts.ts_rateKbps = tx_status->rateKbps;
#if ATH_FRAG_TX_COMPLETE_DEFER
    while (currfrag) {
        nextfrag = wbuf_next(currfrag);
        ieee80211_complete_wbuf(currfrag, &ts);
        currfrag = nextfrag;

        /* If not process all frag at one time, skip the loop */
        if (!all_frag)
            break;
    }
#else
    ieee80211_complete_wbuf(wbuf, &ts);
#endif
}

static void
ath_net80211_updateslot(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    int slottime;

    slottime = (IEEE80211_IS_SHSLOT_ENABLED(ic)) ?
        HAL_SLOT_TIME_9 : HAL_SLOT_TIME_20;

    if (IEEE80211_IS_CHAN_HALF(ic->ic_curchan))
        slottime = HAL_SLOT_TIME_13;
    if (IEEE80211_IS_CHAN_QUARTER(ic->ic_curchan))
        slottime = HAL_SLOT_TIME_21;

    scn->sc_ops->set_slottime(scn->sc_dev, slottime);
}

static void
ath_net80211_update_protmode(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    PROT_MODE mode = PROT_M_NONE;

    if (IEEE80211_IS_PROTECTION_ENABLED(ic)) {
        if (ic->ic_protmode == IEEE80211_PROT_RTSCTS)
            mode = PROT_M_RTSCTS;
        else if (ic->ic_protmode == IEEE80211_PROT_CTSONLY)
            mode = PROT_M_CTSONLY;
    }
    scn->sc_ops->set_protmode(scn->sc_dev, mode);
}

static void
ath_net80211_set_ampduparams(struct ieee80211_node *ni)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    scn->sc_ops->set_ampdu_params(scn->sc_dev,
                                 ATH_NODE_NET80211(ni)->an_sta,
                                 ieee80211_node_get_maxampdu(ni),
                                 ni->ni_mpdudensity);
}

static void
ath_net80211_set_weptkip_rxdelim(struct ieee80211_node *ni, u_int8_t rxdelim)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    scn->sc_ops->set_weptkip_rxdelim(scn->sc_dev,
                                 ATH_NODE_NET80211(ni)->an_sta,
                                 rxdelim);
}


static void
ath_net80211_addba_requestsetup(struct ieee80211_node *ni,
                                u_int8_t tidno,
                                struct ieee80211_ba_parameterset *baparamset,
                                u_int16_t *batimeout,
                                struct ieee80211_ba_seqctrl *basequencectrl,
                                u_int16_t buffersize
                                )
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->addba_request_setup(scn->sc_dev, ATH_NODE_NET80211(ni)->an_sta,
                                     tidno, baparamset, batimeout, basequencectrl,
                                     buffersize);
}

static void
ath_net80211_addba_responsesetup(struct ieee80211_node *ni,
                                 u_int8_t tidno,
                                 u_int8_t *dialogtoken, u_int16_t *statuscode,
                                 struct ieee80211_ba_parameterset *baparamset,
                                 u_int16_t *batimeout
                                 )
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->addba_response_setup(scn->sc_dev, ATH_NODE_NET80211(ni)->an_sta,
                                      tidno, dialogtoken, statuscode,
                                      baparamset, batimeout);
}

static int
ath_net80211_addba_requestprocess(struct ieee80211_node *ni,
                                  u_int8_t dialogtoken,
                                  struct ieee80211_ba_parameterset *baparamset,
                                  u_int16_t batimeout,
                                  struct ieee80211_ba_seqctrl basequencectrl
                                  )
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->addba_request_process(scn->sc_dev, ATH_NODE_NET80211(ni)->an_sta,
                                              dialogtoken, baparamset, batimeout,
                                              basequencectrl);
}

static void
ath_net80211_addba_responseprocess(struct ieee80211_node *ni,
                                   u_int16_t statuscode,
                                   struct ieee80211_ba_parameterset *baparamset,
                                   u_int16_t batimeout
                                   )
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->addba_response_process(scn->sc_dev,
                                        ATH_NODE_NET80211(ni)->an_sta,
                                        statuscode, baparamset, batimeout);
}

static void
ath_net80211_addba_clear(struct ieee80211_node *ni)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->addba_clear(scn->sc_dev, ATH_NODE_NET80211(ni)->an_sta);
}

static void
ath_net80211_delba_process(struct ieee80211_node *ni,
                           struct ieee80211_delba_parameterset *delbaparamset,
                           u_int16_t reasoncode
                           )
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->delba_process(scn->sc_dev, ATH_NODE_NET80211(ni)->an_sta,
                               delbaparamset, reasoncode);
}

#ifdef ATH_SUPPORT_TxBF // for TxBF RC
static void
ath_net80211_CSI_Frame_send(struct ieee80211_node *ni,
						u_int8_t	*CSI_buf,
                        u_int16_t	buf_len,
						u_int8_t    *mimo_control)
{
    //struct ieee80211com *ic = ni->ni_ic;
    //struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ieee80211_action_mgt_args actionargs;
    struct ieee80211_action_mgt_buf  actionbuf;

	//buf_len = wbuf_get_pktlen(wbuf);

    /* Send CSI Frame */
    actionargs.category = IEEE80211_ACTION_CAT_HT;
    actionargs.action   = IEEE80211_ACTION_HT_CSI;
    actionargs.arg1     = buf_len;
    actionargs.arg2     = 0;
    actionargs.arg3     = 0;
    actionargs.arg4     = CSI_buf;
	//actionargs.CSI_buf  = CSI_buf;
	/*MIMO control field (2B) + Sounding TimeStamp(4B)*/
	OS_MEMCPY(actionbuf.buf, mimo_control, MIMO_CONTROL_LEN);

    ieee80211_send_action(ni, &actionargs,(void *)&actionbuf);
}

static void
ath_net80211_v_cv_send(struct ieee80211_node *ni,
                       u_int8_t *data_buf,
                       u_int16_t buf_len)
{
    ieee80211_send_v_cv_action(ni, data_buf, buf_len);
}
static void
ath_net80211_txbf_stats_rpt_inc(struct ieee80211com *ic,
                                struct ieee80211_node *ni)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_softc          *sc  = ATH_DEV_TO_SC(scn->sc_dev);

    sc->sc_stats.ast_txbf_rpt_count++;
}
static void
ath_net80211_txbf_set_rpt_received(struct ieee80211com *ic,
                                struct ieee80211_node *ni)
{
    struct ath_node_net80211 *anode = (struct ath_node_net80211 *)ni;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    scn->sc_ops->txbf_set_rpt_received(anode->an_sta);
}
#endif

static int
ath_net80211_addba_send(struct ieee80211_node *ni,
                        u_int8_t tidno,
                        u_int16_t buffersize)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ieee80211_action_mgt_args actionargs;

    if (IEEE80211_NODE_USEAMPDU(ni) &&
        scn->sc_ops->check_aggr(scn->sc_dev, ATH_NODE_NET80211(ni)->an_sta, tidno)) {

        actionargs.category = IEEE80211_ACTION_CAT_BA;
        actionargs.action   = IEEE80211_ACTION_BA_ADDBA_REQUEST;
        actionargs.arg1     = tidno;
        actionargs.arg2     = buffersize;
        actionargs.arg3     = 0;

        ieee80211_send_action(ni, &actionargs, NULL);
        return 0;
    }

    return 1;
}

static void
ath_net80211_addba_status(struct ieee80211_node *ni, u_int8_t tidno, u_int16_t *status)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    *status = scn->sc_ops->addba_status(scn->sc_dev, ATH_NODE_NET80211(ni)->an_sta, tidno);
}

#if ATH_TX_DUTY_CYCLE
int ath_net80211_enable_tx_duty_cycle(struct ieee80211com *ic, int active_pct)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    int status = 0;

    DPRINTF(scn, ATH_DEBUG_ANY, "%s: pct=%d\n", __func__, active_pct);

    /* use 100% as shorthand to mean tx dc off */
    if (active_pct == 100) {
        return scn->sc_ops->tx_duty_cycle(scn->sc_dev, active_pct, false);
    }

    if (active_pct < 20 /*|| active_pct > 80*/) {
        status = -EINVAL;
    } else {
        /* enable tx dc */
        return scn->sc_ops->tx_duty_cycle(scn->sc_dev, active_pct, true);
    }

    return status;
}

int ath_net80211_disable_tx_duty_cycle(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_softc *sc = scn->sc_dev;
    int status = 0;

    DPRINTF(scn, ATH_DEBUG_ANY, "%s: currently %s\n", __func__, sc->sc_tx_dc_enable ? "ON" : "OFF");

    if (sc->sc_tx_dc_enable) {
        /* disable tx dc */
        if ((status = scn->sc_ops->tx_duty_cycle(scn->sc_dev, 0, false)) != 0)
        {
            return status;
        }
    }

    return status;
}

int ath_net80211_get_tx_duty_cycle(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_softc *sc = scn->sc_dev;
    return sc->sc_tx_dc_enable ? sc->sc_tx_dc_active_pct : 100;
}


int ath_net80211_get_tx_busy(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_softc *sc = scn->sc_dev;
    u_int32_t rxc_pcnt = 0, rxf_pcnt = 0, txf_pcnt = 0;
    int status = 0;

    if ((status = ath_hal_getMibCycleCountsPct(sc->sc_ah, &rxc_pcnt, &rxf_pcnt, &txf_pcnt)) != 0)
    {
        return -1;
    }
    return txf_pcnt;
}
#endif // ATH_TX_DUTY_CYCLE


static void
ath_net80211_delba_send(struct ieee80211_node *ni,
                        u_int8_t tidno,
                        u_int8_t initiator,
                        u_int16_t reasoncode)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ieee80211_action_mgt_args actionargs;

    /* tear down aggregation first */
    scn->sc_ops->aggr_teardown(scn->sc_dev, ATH_NODE_NET80211(ni)->an_sta, tidno, initiator);

    /* Send DELBA request */
    actionargs.category = IEEE80211_ACTION_CAT_BA;
    actionargs.action   = IEEE80211_ACTION_BA_DELBA;
    actionargs.arg1     = tidno;
    actionargs.arg2     = initiator;
    actionargs.arg3     = reasoncode;

    ieee80211_send_action(ni, &actionargs, NULL);
}

static void
ath_net80211_addba_setresponse(struct ieee80211_node *ni, u_int8_t tidno, u_int16_t statuscode)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    scn->sc_ops->set_addbaresponse(scn->sc_dev, ATH_NODE_NET80211(ni)->an_sta,
                                   tidno, statuscode);
}

static void
ath_net80211_addba_clearresponse(struct ieee80211_node *ni)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    scn->sc_ops->clear_addbaresponsestatus(scn->sc_dev, ATH_NODE_NET80211(ni)->an_sta);
}

static int
ath_net80211_set_country(struct ieee80211com *ic, char *isoName, u_int16_t cc, enum ieee80211_clist_cmd cmd)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    int retval = 0;
    if ((ic->ic_opmode == IEEE80211_M_HOSTAP || ic->ic_opmode == IEEE80211_M_IBSS)) {
#ifdef ATH_SUPPORT_DFS
        dfs_detach(ic);
#endif /* ATH_SUPPORT_DFS */
    }
    if ((ic->ic_opmode == IEEE80211_M_HOSTAP || ic->ic_opmode == IEEE80211_M_IBSS)) {
#ifdef ATH_SUPPORT_DFS
        dfs_attach(ic);
#endif /* ATH_SUPPORT_DFS */
    }
    retval = scn->sc_ops->set_country(scn->sc_dev, isoName, cc, cmd);
    return retval;
}

static void
ath_net80211_get_currentCountry(struct ieee80211com *ic, IEEE80211_COUNTRY_ENTRY *ctry)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->get_current_country(scn->sc_dev, (HAL_COUNTRY_ENTRY *)ctry);
}

static int
ath_net80211_set_regdomain(struct ieee80211com *ic, int regdomain)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->set_regdomain(scn->sc_dev, regdomain, AH_TRUE);
}

static int
ath_net80211_set_quiet(struct ieee80211_node *ni, u_int8_t *quiet_elm)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ni->ni_ic);
    struct ieee80211_quiet_ie *quiet = (struct ieee80211_quiet_ie *)quiet_elm;
    return scn->sc_ops->set_quiet(scn->sc_dev,
                                  quiet->period,
                                  quiet->period,
                                  quiet->offset + quiet->tbttcount*ni->ni_intval,
                                  HAL_QUIET_ENABLE);
}

static u_int16_t ath_net80211_find_countrycode(struct ieee80211com *ic, char* isoName)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    return scn->sc_ops->find_countrycode(scn->sc_dev, isoName);
}

#ifdef ATH_SUPPORT_TxBF
static int
ath_net80211_txbf_alloc_key(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ieee80211vap *vap = ni->ni_vap;
    u_int16_t keyidx = IEEE80211_KEYIX_NONE, status;

    status = scn->sc_ops->txbf_alloc_key(scn->sc_dev, ni->ni_macaddr, &keyidx);

    if (status != AH_FALSE) {
        ath_key_set(vap, &ni->ni_ucastkey, ni->ni_macaddr);
    }

    return keyidx;
}

static void
ath_net80211_txbf_set_key(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    scn->sc_ops->txbf_set_key(scn->sc_dev,ni->ni_ucastkey.wk_keyix,ni->ni_txbf.rx_staggered_sounding
        ,ni->ni_txbf.channel_estimation_cap,ni->ni_mmss);
}

static void
ath_net80211_init_sw_cv_timeout(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_softc          *sc  =  ATH_DEV_TO_SC(scn->sc_dev);
    struct ath_hal *ah = sc->sc_ah;
    int power=scn->sc_ops->getpwrsavestate(scn->sc_dev);

    ni->ni_sw_cv_timeout = sc->sc_reg_parm.TxBFSwCvTimeout;

    // when ni_sw_cv_timeout=0, it use H/W timer directly
    // when ni_sw_cv_timeout!=0, set H/W timer to 1 ms to trigger S/W timer
    /* WAR: EV:88809 Always Wake up chip before setting Phy related Registers
     * Restore the pwrsavestate after the setting is done
     */
    scn->sc_ops->setpwrsavestate(scn->sc_dev,ATH_PWRSAVE_AWAKE);

    if (ni->ni_sw_cv_timeout) {    // use S/W timer
        ath_hal_setHwCvTimeout(ah, AH_FALSE);
    } else {
        ath_hal_setHwCvTimeout(ah, AH_TRUE);
    }
    scn->sc_ops->setpwrsavestate(scn->sc_dev,power);
}

#ifdef TXBF_DEBUG
static void
ath_net80211_txbf_check_cvcache(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_softc          *sc  =  ATH_DEV_TO_SC(scn->sc_dev);
    u_int8_t nr = 0, numtxchains;

    if (ni->ni_explicit_compbf || ni->ni_explicit_noncompbf || ni->ni_implicit_bf) {
        /* TxBF BFer mode*/

        /* Get Nr from CV cache*/
        scn->sc_ops->txbf_get_cvcache_nr(sc, ni->ni_ucastkey.wk_keyix, &nr);

        /* get Tx chain*/
        numtxchains = ath_get_numchains(scn->sc_ops->have_capability(sc,
            ATH_CAP_TXCHAINMASK));
        /* Force to Print out warning message when Nr in CV cache is not equal to
        *  numtxchains. It indicates that something goes wrong in TxBF related
        *  code and needs futher debug.        */
        if (nr != numtxchains) {
            int debug;

            DPRINTF(scn, ATH_DEBUG_ANY,"==>%s:\nWARNING!!TxBF V/CV REPORT INCORRECT!!\n", __func__);
            DPRINTF(scn, ATH_DEBUG_ANY,"Nr=%d is not equal to numtxchains=%d \n", nr, numtxchains);
        }
    }
}
#endif
#endif

static u_int8_t   ath_net80211_get_ctl_by_country(struct ieee80211com *ic, u_int8_t *country, bool is2G)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->get_ctl_by_country(scn->sc_dev, country, is2G);
}

static u_int16_t   ath_net80211_dfs_isdfsregdomain(struct ieee80211com *ic)
{
#ifdef ATH_SUPPORT_DFS
    return dfs_isdfsregdomain(ic);
#else
    return 0;
#endif /* ATH_SUPPORT_DFS */
}
static int  ath_net80211_getdfsdomain(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->get_dfsdomain(scn->sc_dev);
}
static u_int16_t   ath_net80211_dfs_usenol(struct ieee80211com *ic)
{
#ifdef ATH_SUPPORT_DFS
    return(dfs_usenol(ic));
#else
    return 0;
#endif
}

static int   ath_net80211_dfs_attached(struct ieee80211com *ic)
{
#ifdef ATH_SUPPORT_DFS
    if ( ic->ic_dfs) {
        return 1;
    } else {
        dfs_attach(ic);
        return 1;
    }
#else
    return 0;
#endif
}

static u_int
ath_net80211_mhz2ieee(struct ieee80211com *ic, u_int freq, u_int flags)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->mhz2ieee(scn->sc_dev, freq, flags);
}

/*------------------------------------------------------------
 * Callbacks for ath_dev module, which calls net80211 API's
 * (ieee80211_xxx) accordingly.
 *------------------------------------------------------------
 */

static void
ath_net80211_channel_setup(ieee80211_handle_t ieee,
                           enum ieee80211_clist_cmd cmd,
                           const HAL_CHANNEL *chans, int nchan,
                           const u_int8_t *regclassids, u_int nregclass,
                           int countrycode)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ieee80211_channel *ichan;
    const HAL_CHANNEL *c;
    int i, j;

    /* XXX this is now done in ic_dfs_clist_update() */
    if ((cmd == CLIST_DFS_UPDATE) || (cmd == CLIST_NOL_UPDATE)) {
        qdf_print("%s: ERROR: DFS/NOL update; shouldn't happen here!\n",
          __func__);
        return;

    }

#if 0
    if (cmd == CLIST_DFS_UPDATE) {
        for (i = 0; i < nchan; i++) {
            ieee80211_enumerate_channels(ichan, ic, j) {
                if (chans[i].channel == ieee80211_chan2freq(ic, ichan))
                    IEEE80211_CHAN_CLR_RADAR(ichan);
            }
        }

        return;
    }

    if (cmd == CLIST_NOL_UPDATE) {
        for (i = 0; i < nchan; i++) {
            ieee80211_enumerate_channels(ichan, ic, j) {
                if (chans[i].channel == ieee80211_chan2freq(ic, ichan))
                    IEEE80211_CHAN_SET_RADAR(ichan);
            }
        }

        return;
    }
#endif

    if ((countrycode == CTRY_DEFAULT) || (cmd == CLIST_NEW_COUNTRY)) {
        /*
         * Convert HAL channels to ieee80211 ones.
         */
        for (i = 0; i < nchan; i++) {
            c = &chans[i];
            ichan = ieee80211_get_channel(ic, i);
            OS_MEMZERO(ichan, sizeof(struct ieee80211_channel));
            IEEE80211_CHAN_SETUP(ichan,
                                 scn->sc_ops->mhz2ieee(scn->sc_dev, c->channel, c->channel_flags),
                                 c->channel,
                                 c->channel_flags,
                                 0, /* ic_flagext */
                                 c->max_reg_tx_power,  /* dBm */
                                 c->max_tx_power / 4, /* 1/4 dBm */
                                 c->min_tx_power / 4,  /* 1/4 dBm */
                                 c->regClassId
                                 );
            if (c->priv_flags & CHANNEL_DFS) {
                IEEE80211_CHAN_SET_DFS(ichan);
            }
            if (c->priv_flags & CHANNEL_DFS_CLEAR) {
                IEEE80211_CHAN_SET_DFS_CLEAR(ichan);
            }
            if (c->priv_flags & CHANNEL_DISALLOW_ADHOC){
                IEEE80211_CHAN_SET_DISALLOW_ADHOC(ichan);
            }
            if (c->priv_flags & CHANNEL_NO_HOSTAP){
                IEEE80211_CHAN_SET_DISALLOW_HOSTAP(ichan);
            }
        }
        ieee80211_set_nchannels(ic, nchan);
    }
    else {
        /*
         * Logic AND the country channel and domain channels.
         */
        ieee80211_enumerate_channels(ichan, ic, i) {
            c = chans;
            for (j = 0; j < nchan; j++) {
                if (IEEE80211_CHAN_MATCH(ichan, c->channel, c->channel_flags, (~CHANNEL_PASSIVE))) {
                    IEEE80211_CHAN_SETUP(ichan,
                                         scn->sc_ops->mhz2ieee(scn->sc_dev, c->channel, c->channel_flags),
                                         c->channel,
                                         c->channel_flags,
                                         0, /* ic_flagext */
                                         c->max_reg_tx_power,  /* dBm */
                                         c->max_tx_power / 4, /* 1/4 dBm */
                                         c->min_tx_power / 4,  /* 1/4 dBm */
                                         c->regClassId
                                         );
                    if (c->priv_flags & CHANNEL_DFS) {
                        IEEE80211_CHAN_SET_DFS(ichan);
                    }
                    if (c->priv_flags & CHANNEL_DFS_CLEAR) {
                        IEEE80211_CHAN_SET_DFS_CLEAR(ichan);
                    }
                    if (c->priv_flags & CHANNEL_DISALLOW_ADHOC) {
                        IEEE80211_CHAN_SET_DISALLOW_ADHOC(ichan);
                    }
                    if (c->priv_flags & CHANNEL_NO_HOSTAP){
                        IEEE80211_CHAN_SET_DISALLOW_HOSTAP(ichan);
                    }
                    break;
                }
                c++;
            }

            if (j == nchan) {
                /* channel not found, exclude it from the channel list */
                IEEE80211_CHAN_EXCLUDE_11D(ichan);
            }
        }
    }

    /*
     * Copy regclass ids
     */
    ieee80211_set_regclassids(ic, regclassids, nregclass);
}


static int
ath_net80211_set_countrycode(ieee80211_handle_t ieee, char *isoName, u_int16_t cc, enum ieee80211_clist_cmd cmd)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);

    return wlan_set_countrycode(ic, isoName, cc, cmd);
}

static int
ath_net80211_set_regdomaincode(ieee80211_handle_t ieee, u_int16_t rd)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);

    return wlan_set_regdomain(ic, rd);
}

static void
ath_net80211_update_node_txpow(struct ieee80211vap *vap, u_int16_t txpowlevel, u_int8_t *addr)
{
    struct ieee80211_node *ni;
    ni = ieee80211_find_txnode(vap, addr);
    ASSERT(ni);
    if (!ni)
        return;
    ieee80211node_set_txpower(ni, txpowlevel);
}

#if ATH_WOW_OFFLOAD
static int
ath_net80211_wow_offload_info_get(struct ieee80211com *ic, void *buf, u_int32_t param)
{
    struct ath_softc_net80211   *scn = ATH_SOFTC_NET80211(ic);
    return(scn->sc_ops->ath_wowoffload_get_rekey_info(scn->sc_dev, buf, param));
}

static int
ath_net80211_wowoffload_rekey_misc_info_set(struct ieee80211com *ic, struct wow_offload_misc_info *wow_info)
{
    struct ath_softc_net80211   *scn = ATH_SOFTC_NET80211(ic);
    return(scn->sc_ops->ath_wowoffload_set_rekey_misc_info(scn->sc_dev, wow_info));
}

static int
ath_net80211_wowoffload_txseqnum_update(struct ieee80211com *ic, struct ieee80211_node *ni, u_int32_t tidno, u_int16_t seqnum)
{
    struct ath_node_net80211 *an = (struct ath_node_net80211 *)ni;
    struct ath_softc_net80211   *scn = ATH_SOFTC_NET80211(ic);
    return(scn->sc_ops->ath_wowoffload_update_txseqnum(scn->sc_dev, an->an_sta, tidno, seqnum));
}
#endif /* ATH_WOW_OFFLOAD */

/*
 * Temporarily change this to a non-static function.
 * This avoids a compiler warning / error about a static function being
 * defined but unused.
 * Once this function is referenced, it should be changed back to static.
 * The function declaration will also need to be changed back to static.
 *
 * The same applies to the ath_net80211_get_max_txpwr function below.
 */
/*static*/ void
ath_net80211_enable_tpc(struct ieee80211com *ic)
{
    struct ath_softc_net80211   *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->enable_tpc(scn->sc_dev);
}

/*static*/ void
ath_net80211_get_max_txpwr(struct ieee80211com *ic, u_int32_t* txpower )
{
    struct ath_softc_net80211   *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->get_maxtxpower(scn->sc_dev, txpower);
}

static void ath_vap_iter_update_txpow(void *arg, wlan_if_t vap)
{
    struct ieee80211_node *ni;
    u_int16_t txpowlevel = *((u_int16_t *) arg);
    ni = ieee80211vap_get_bssnode(vap);
    ASSERT(ni);
#if ATH_BAND_STEERING
    ieee80211_bsteering_send_txpower_change_event(vap,txpowlevel);
#endif

    ieee80211node_set_txpower(ni, txpowlevel);
}

static void
ath_net80211_update_txpow(ieee80211_handle_t ieee,
                          u_int16_t txpowlimit, u_int16_t txpowlevel)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);

    ieee80211com_set_txpowerlimit(ic, txpowlimit);

   wlan_iterate_vap_list(ic,ath_vap_iter_update_txpow,(void *) &txpowlevel);
}

struct ath_iter_update_beaconconfig_arg {
    struct ieee80211com *ic;
    int if_id;
    ieee80211_beacon_config_t *conf;
};

static void ath_vap_iter_update_beaconconfig(void *arg, wlan_if_t vap)
{
    struct ath_iter_update_beaconconfig_arg* params = (struct ath_iter_update_beaconconfig_arg*) arg;
    struct ieee80211_node *ni;
    if ((params->if_id == ATH_IF_ID_ANY && ieee80211vap_get_opmode(vap) == params->ic->ic_opmode) ||
        ((ATH_VAP_NET80211(vap))->av_if_id == params->if_id) ||
        (params->if_id == ATH_IF_ID_ANY && params->ic->ic_opmode == IEEE80211_M_HOSTAP &&
         ieee80211vap_get_opmode(vap) == IEEE80211_M_BTAMP)) {
        ni = ieee80211vap_get_bssnode(vap);
        params->conf->beacon_interval = ni->ni_intval;
        params->conf->listen_interval = ni->ni_lintval;
        params->conf->dtim_period = ni->ni_dtim_period;
        params->conf->dtim_count = ni->ni_dtim_count;
        params->conf->bmiss_timeout = vap->iv_ic->ic_bmisstimeout;
        params->conf->u.last_tsf = ni->ni_tstamp.tsf;
    }
}

static void
ath_net80211_get_beaconconfig(ieee80211_handle_t ieee, int if_id,
                              ieee80211_beacon_config_t *conf)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ath_iter_update_beaconconfig_arg params;
    params.ic = ic;
    params.if_id = if_id;
    params.conf = conf;

    wlan_iterate_vap_list(ic,ath_vap_iter_update_beaconconfig,(void *) &params);
}

static int16_t
ath_net80211_get_noisefloor(struct ieee80211com *ic, struct ieee80211_channel *chan, int wait_time)
{

    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    return scn->sc_ops->get_noisefloor(scn->sc_dev, chan->ic_freq,  ath_chan2flags(chan), wait_time);
}

static void
ath_net80211_get_chainnoisefloor(struct ieee80211com *ic, struct ieee80211_channel *chan, int16_t *nfBuf)
{

    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    scn->sc_ops->get_chainnoisefloor(scn->sc_dev, chan->ic_freq,  ath_chan2flags(chan), nfBuf);
}
#if ATH_SUPPORT_VOW_DCS
static void
ath_net80211_disable_dcsim(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->disable_dcsim(scn->sc_dev);
}
static void
ath_net80211_enable_dcsim(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->enable_dcsim(scn->sc_dev);
}
#endif
struct ath_iter_update_beaconalloc_arg {
    struct ieee80211com *ic;
    int if_id;
    ieee80211_beacon_offset_t *bo;
    ieee80211_tx_control_t *txctl;
    wbuf_t wbuf;
};

static void ath_vap_iter_beacon_alloc(void *arg, wlan_if_t vap)
{
    struct ath_iter_update_beaconalloc_arg* params = (struct ath_iter_update_beaconalloc_arg *) arg;
    struct ath_vap_net80211 *avn;
    struct ieee80211_node *ni;
#define USE_SHPREAMBLE(_ic)                   \
    (IEEE80211_IS_SHPREAMBLE_ENABLED(_ic) &&  \
     !IEEE80211_IS_BARKER_ENABLED(_ic))

        if ((ATH_VAP_NET80211(vap))->av_if_id == params->if_id) {
            ni = vap->iv_bss;
            avn = ATH_VAP_NET80211(vap);
            params->wbuf = ieee80211_beacon_alloc(ni, &avn->av_beacon_offsets);
            if (params->wbuf) {

                /* set up tim offset */
                params->bo->bo_tim = avn->av_beacon_offsets.bo_tim;

                /* setup tx control block for this beacon */
                params->txctl->txpower = ieee80211_node_get_txpower(ni);
                if (USE_SHPREAMBLE(vap->iv_ic))
                    params->txctl->shortPreamble = 1;
                params->txctl->min_rate = vap->iv_mgt_rate;

                /* send this frame to hardware */
                params->txctl->an = (ATH_NODE_NET80211(ni))->an_sta;

            }
        }

}

static wbuf_t
ath_net80211_beacon_alloc(ieee80211_handle_t ieee, int if_id,
                          ieee80211_beacon_offset_t *bo,
                          ieee80211_tx_control_t *txctl)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ath_iter_update_beaconalloc_arg params;

    ASSERT(if_id != ATH_IF_ID_ANY);

    params.ic = ic;
    params.if_id = if_id;
    params.txctl = txctl;
    params.bo = bo;
    params.wbuf = NULL;

    wlan_iterate_vap_list(ic,ath_vap_iter_beacon_alloc,(void *) &params);
    return params.wbuf;

#undef USE_SHPREAMBLE
}

#if UMAC_SUPPORT_WNM
static int
ath_net80211_beacon_update(ieee80211_handle_t ieee, int if_id,
                           ieee80211_beacon_offset_t *bo, wbuf_t wbuf,
                           int mcast, u_int32_t nfmsq_mask, u_int32_t *bcn_txant)
#else
static int
ath_net80211_beacon_update(ieee80211_handle_t ieee, int if_id,
                           ieee80211_beacon_offset_t *bo, wbuf_t wbuf,
                           int mcast, u_int32_t *bcn_txant)
#endif
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ieee80211vap *vap = NULL;
    struct ath_vap_net80211 *avn;
    int error = 0;

    ASSERT(if_id != ATH_IF_ID_ANY);

    /*
     * get a vap with the given id.
     * this function is called from SWBA.
     * in most of the platform this is directly called from
     * the interrupt handler, so we need to find our vap without using any
     * spin locks.
     */

    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if ((ATH_VAP_NET80211(vap))->av_if_id == if_id) {
            break;
        }
    }

    if (vap == NULL || (vap->iv_bss == NULL))
        return -EINVAL;

#if UMAC_SUPPORT_WDS
    /* disable beacon if VAP is operating in NAWDS bridge mode */
    if (ieee80211_nawds_disable_beacon(vap))
        return -EIO;
#endif

    /* Update the quiet param for beacon update */
    ath_quiet_update(ic, vap);

    avn = ATH_VAP_NET80211(vap);
#if UMAC_SUPPORT_WNM
    error = ieee80211_beacon_update(vap->iv_bss, &avn->av_beacon_offsets,
                                    wbuf, mcast, nfmsq_mask);
#else
    error = ieee80211_beacon_update(vap->iv_bss, &avn->av_beacon_offsets,
                                    wbuf, mcast);
#endif

    ieee80211_smart_ant_get_bcn_txantenna(ic, bcn_txant);

    if (!error) {
        /* set up tim offset */
        bo->bo_tim = avn->av_beacon_offsets.bo_tim;
#if UMAC_SUPPORT_WNM
        /* set up FMS desc offset */
        if (ieee80211_vap_wnm_is_set(vap) && ieee80211_wnm_fms_is_set(vap->wnm))
            bo->bo_fms_desc = avn->av_beacon_offsets.bo_fms_desc;
        else
            bo->bo_fms_desc = NULL;
#endif /* UMAC_SUPPORT_WNM */
    }

    return error;
}

static void
ath_net80211_beacon_miss(ieee80211_handle_t ieee)
{
    ieee80211_beacon_miss(NET80211_HANDLE(ieee));
}

static void
ath_net80211_notify_beacon_rssi(ieee80211_handle_t ieee)
{
    ieee80211_notify_beacon_rssi(NET80211_HANDLE(ieee));
}


static void ath_vap_iter_tim(void *arg, wlan_if_t vap)
{
    if ((vap->iv_opmode == IEEE80211_M_STA) &&
        ieee80211_vap_ready_is_set(vap)) {
        ieee80211_sta_power_event_tim(vap);
    }
}

static void
ath_net80211_proc_tim(ieee80211_handle_t ieee)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);

    /* Hardware TIM processing is only used in the case of
     * one active STA VAP.
     */
    wlan_iterate_vap_list(ic, ath_vap_iter_tim, NULL);
}

static void ath_vap_iter_dtim(void *arg, wlan_if_t vap)
{
    if ((vap->iv_opmode == IEEE80211_M_STA) &&
        ieee80211_vap_ready_is_set(vap)) {
        ieee80211_sta_power_event_dtim(vap);
    }
}

static void
ath_net80211_proc_dtim(ieee80211_handle_t ieee)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);

    /* Hardware DTIM processing is only used in the case of
     * one active STA VAP.
     */
    wlan_iterate_vap_list(ic, ath_vap_iter_dtim, NULL);
}

struct ath_iter_set_state_arg {
    int if_id;
    u_int8_t state;
};

static void ath_vap_iter_set_state(void *arg, wlan_if_t vap)
{
    struct ath_iter_set_state_arg *params = (struct ath_iter_set_state_arg *) arg;

    if ((ATH_VAP_NET80211(vap))->av_if_id == params->if_id) {
        ieee80211_state_event(vap,params->state);
    }
}

/******************************************************************************/
/*!
**  \brief shim callback to set VAP state
**
** This routine is used by DFS to change the state of the VAP after a CAC
** period, or when doing a channel change.  Required for layer seperation.
**
**  \param ieee     Pointer to shim structure (this)
**  \param if_id    VAP Index (1-4).  Zero is invalid.
**  \param state    Flag indicating INIT (0) or RUN (1) state
**
**  \return N/A
*/

static void
ath_net80211_set_vap_state(ieee80211_handle_t ieee,u_int8_t if_id, u_int8_t state)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ath_iter_set_state_arg params;

    params.if_id = if_id;

    /*
     * EV82313 - remove LMAC dependency on UMAC
     *
     * to remove dependency LMAC state events are different form UMAC.
     * We map LMAC states to UMAC states here
     */

    switch (state) {
    case LMAC_STATE_EVENT_UP:
        state = IEEE80211_STATE_EVENT_UP;
        break;
    case LMAC_STATE_EVENT_DFS_WAIT:
        state = IEEE80211_STATE_EVENT_DFS_WAIT;
        break;
    case LMAC_STATE_EVENT_DFS_CLEAR:
        state = IEEE80211_STATE_EVENT_DFS_CLEAR;
        break;
    case LMAC_STATE_EVENT_CHAN_SET:
        state = IEEE80211_STATE_EVENT_CHAN_SET;
        break;
    default:
        break;
    }
    params.state = state;

    wlan_iterate_vap_list(ic,ath_vap_iter_set_state,(void *) &params);
}

static int
ath_net80211_send_bar(ieee80211_node_t node, u_int8_t tidno, u_int16_t seqno)
{
    return ieee80211_send_bar((struct ieee80211_node *)node, tidno, seqno);
}
static void
ath_bsteering_rssi_update(ieee80211_handle_t ieee, u_int8_t *sta_mac_addr, u_int8_t tx_status,int8_t rssi,uint8_t subtype)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    ieee80211_bsteering_direct_attach_rssi_update(ic,sta_mac_addr, tx_status,rssi,subtype);
    return;
}

static void
ath_bsteering_rate_update(ieee80211_handle_t ieee, u_int8_t *sta_mac_addr, u_int8_t tx_status,u_int32_t rateKbps)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    ieee80211_bsteering_direct_attach_txrate_update(ic,sta_mac_addr,tx_status,rateKbps);
    return;
}

#if QCA_AIRTIME_FAIRNESS
static void
ath_net80211_atf_scheduling(ieee80211_handle_t ieee, u_int32_t sched)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    ic->ic_atf_sched = sched;
}

static u_int32_t
ath_net80211_get_atf_scheduling(ieee80211_handle_t ieee)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
	return ic->ic_atf_sched;
}

static u_int8_t
ath_net80211_get_atf_allocations(ieee80211_node_t node, u_int32_t *tx_tokens,
				 u_int32_t *alloted_tx_tokens, u_int32_t *unassigned_txtokens)
{
    struct ieee80211_node *ni = (struct ieee80211_node *)node;
    *tx_tokens = ni->shadow_tx_tokens;
    *alloted_tx_tokens = ni->ni_ic->ic_shadow_alloted_tx_tokens;
    *unassigned_txtokens = ni->ni_ic->ic_txtokens_common;
    return ni->ni_ic->atf_commit;
}

static void
ath_net80211_atf_obss_scale(ieee80211_handle_t ieee, u_int32_t scale)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    ic->atf_obss_scale = scale;
}

#endif

/*
 * Determine the current channel utilisation (self & obss) & send an event up the layer
 */
static void
ath_net80211_channel_util(ieee80211_handle_t ieee, u_int32_t bss_rx_busy_per, u_int32_t chan_busy_per)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    u_int8_t ctlrxc, extrxc, rfcnt, tfcnt, obss = 0, selfbss = 0;
    static u_int32_t selfutil_avg = 0, obssutil_avg = 0, count = 0;

    ctlrxc = chan_busy_per & 0xff;
    extrxc =(chan_busy_per & 0xff00) >> 8;
    rfcnt = (chan_busy_per & 0xff0000) >> 16;
    tfcnt = (chan_busy_per & 0xff000000) >> 24;

    //Tx & Rx of BSS
    selfbss = tfcnt + bss_rx_busy_per;

    if (ic->ic_curchan->ic_flags & IEEE80211_CHAN_HT20)
    {
        if( selfbss > ctlrxc )
        {
            selfbss = ctlrxc;
        }
        else {
            obss = ctlrxc - selfbss;
        }
    }
    else {
        if(selfbss > (ctlrxc + extrxc))
        {
            selfbss = (ctlrxc + extrxc);
        }
        else {
            obss = (ctlrxc + extrxc) - selfbss;
        }
    }

    selfutil_avg += selfbss;
    obssutil_avg += obss;
    count++;

    /* Send the event (averge value) based on the user configured interval */
    if(count == CHAN_UTIL_EVENT_FREQ)
    {
        selfutil_avg = (selfutil_avg / CHAN_UTIL_EVENT_FREQ);
        obssutil_avg = (obssutil_avg/CHAN_UTIL_EVENT_FREQ);
        OSIF_RADIO_DELIVER_EVENT_CHAN_UTIL(ic, selfutil_avg, obssutil_avg);

        count = 0;
        selfutil_avg = 0;
        obssutil_avg = 0;
    }
}

#if ATH_SUPPORT_WIFIPOS
int ieee80211_update_wifipos_stats(ieee80211_wifiposdesc_t *wifiposdesc);
int ieee80211_update_ka_done(u_int8_t *sta_mac_addr, u_int8_t ka_tx_status);
int ieee80211_isthere_wakeup_request(struct ieee80211_node *ni);
static void
ath_net80211_update_ka_done(u_int8_t *sta_mac_addr, u_int8_t ka_tx_status) {
    ieee80211_update_ka_done(sta_mac_addr, ka_tx_status);
}
static void
ath_net80211_update_wifipos_stats(ieee80211_wifiposdesc_t *wifiposdesc)
{
    ieee80211_update_wifipos_stats(wifiposdesc);
}
static int ath_net80211_isthere_wakeup_request( ieee80211_node_t node)
{
    struct ieee80211_node *ni = (struct ieee80211_node *)node;
    return ieee80211_isthere_wakeup_request(ni);
}
#endif

static void
ath_net80211_notify_qstatus(ieee80211_handle_t ieee, u_int16_t qdepth)
{
    ieee80211_notify_queue_status(NET80211_HANDLE(ieee), qdepth);
}
#ifndef ATHHTC_AP_REMOVE_STATS

static INLINE void
_ath_rxstat2ieee(struct ieee80211com *ic,
                ieee80211_rx_status_t *rx_status,
                struct ieee80211_rx_status *rs)
{
   int selevm;
   struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
   struct ath_softc *sc = ATH_DEV_TO_SC(scn->sc_dev);

    rs->rs_flags =
        ((rx_status->flags & ATH_RX_FCS_ERROR) ? IEEE80211_RX_FCS_ERROR : 0) |
        ((rx_status->flags & ATH_RX_MIC_ERROR) ? IEEE80211_RX_MIC_ERROR : 0) |
        ((rx_status->flags & ATH_RX_DECRYPT_ERROR) ? IEEE80211_RX_DECRYPT_ERROR : 0)
    | ((rx_status->flags & ATH_RX_KEYMISS) ? IEEE80211_RX_KEYMISS : 0);
    rs->rs_isvalidrssi = (rx_status->flags & ATH_RX_RSSI_VALID) ? 1 : 0;

    rs->rs_numchains = rx_status->numchains;
    rs->rs_phymode = ic->ic_curmode;
    rs->rs_freq = ic->ic_curchan->ic_freq;
    rs->rs_rssi = rx_status->rssi;
    rs->rs_abs_rssi = rx_status->abs_rssi;
    rs->rs_datarate = rx_status->rateKbps;
    rs->rs_rateieee = rx_status->rateieee;
    rs->rs_ratephy1  = rx_status->ratecode;
    rs->rs_isaggr = rx_status->isaggr;
    rs->rs_isapsd = rx_status->isapsd;
    rs->rs_noisefloor = rx_status->noisefloor;
    rs->rs_channel = rx_status->channel;
    rs->rs_full_chan = ic->ic_curchan;
    rs->rs_fcs_error = (rx_status->flags & ATH_RX_FCS_ERROR)? 1:0;

    selevm = ath_hal_setrxselevm(sc->sc_ah, 0, 1);

    if(!selevm) {
       memcpy(rs->rs_lsig, rx_status->lsig, IEEE80211_LSIG_LEN);
       memcpy(rs->rs_htsig, rx_status->htsig, IEEE80211_HTSIG_LEN);
       memcpy(rs->rs_servicebytes, rx_status->servicebytes, IEEE80211_SB_LEN);
    } else {
       memset(rs->rs_lsig, 0, IEEE80211_LSIG_LEN);
       memset(rs->rs_htsig, 0, IEEE80211_HTSIG_LEN);
       memset(rs->rs_servicebytes, 0, IEEE80211_SB_LEN);
    }

    rs->rs_tstamp.tsf = rx_status->tsf;

    ath_txbf_update_rx_status( rs, rx_status);
    OS_MEMCPY(rs->rs_rssictl, rx_status->rssictl, IEEE80211_MAX_ANTENNA);
    OS_MEMCPY(rs->rs_rssiextn, rx_status->rssiextn, IEEE80211_MAX_ANTENNA);
#if ATH_VOW_EXT_STATS
    rs->vow_extstats_offset = rx_status->vow_extstats_offset;
#endif
}

#define ATH_RXSTAT2IEEE(_ic, _rx_status, _rs)  _ath_rxstat2ieee(_ic, _rx_status, _rs)
#else
#define ATH_RXSTAT2IEEE(_ic, _rx_status, _rs)    (_rs)->rs_flags=0
#endif

int
ath_net80211_input(ieee80211_node_t node, wbuf_t wbuf, ieee80211_rx_status_t *rx_status)
{
    struct ieee80211_node *ni = (struct ieee80211_node *)node;
    struct ieee80211_rx_status rs;

    ATH_RXSTAT2IEEE(ni->ni_ic, rx_status, &rs);
    return ieee80211_input(ni, wbuf, &rs);
}

#ifdef ATH_SUPPORT_TxBF
void
ath_net80211_bf_rx(struct ieee80211com *ic, wbuf_t wbuf, ieee80211_rx_status_t *status)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_softc *sc = ATH_DEV_TO_SC(scn->sc_dev);

    /* Only UMAC code base need do this check, not need for XP */
    sc->do_node_check = 1;

    switch (status->bf_flags) {
        case ATH_BFRX_PKT_MORE_ACK:
        case ATH_BFRX_PKT_MORE_QoSNULL:
        /*Not ready yet*/
            break;
        case ATH_BFRX_PKT_MORE_DELAY:
            {   /*Find & save Node*/
                struct ieee80211_node *ni_T;
                struct ieee80211_frame_min *wh1;

                wh1 = (struct ieee80211_frame_min *)wbuf_header(wbuf);
                ni_T = IC_IEEE80211_FIND_NODE(ic,&ic->ic_sta, wh1->i_addr2);

                if (ni_T == NULL) {
                    DPRINTF(scn, ATH_DEBUG_RECV, "%s Can't Find the NODE of V/CV ?\n", __FUNCTION__);
                } else {
                    DPRINTF(scn, ATH_DEBUG_RECV, "%s save node of V/CV \n ", __FUNCTION__);
                    sc->v_cv_node = ni_T;
                }
            }
            break;
        case ATH_BFRX_DATA_UPLOAD_ACK:
        case ATH_BFRX_DATA_UPLOAD_QosNULL:
            /*Not ready yet*/
            break;
        case ATH_BFRX_DATA_UPLOAD_DELAY:
            {
                u_int8_t	*v_cv_data = (u_int8_t *) wbuf_header(wbuf);
                u_int16_t	buf_len = wbuf_get_pktlen(wbuf);

                if (sc->v_cv_node) {
                    DPRINTF(scn, ATH_DEBUG_RECV, "Send its C CV Report (%d) \n", buf_len);
                    ic->ic_v_cv_send(sc->v_cv_node, v_cv_data, buf_len);
                } else {
                    DPRINTF(scn, ATH_DEBUG_RECV, "%s v_cv_node to be NULL ???\n", __FUNCTION__);
                }
                sc->v_cv_node = NULL;

            }
            break;
        default:
            break;
    }
}
#endif

#if !UMAC_SUPPORT_OPMODE_APONLY
void
ath_net80211_rx_monitor(struct ieee80211com *ic, wbuf_t wbuf, ieee80211_rx_status_t *rx_status)
{
    struct ath_softc_net80211 *scn;
    scn = ATH_SOFTC_NET80211(ic);
    /*
     * Monitor mode: discard anything shorter than
     * an ack or cts, clean the skbuff, fabricate
     * the Prism header existing tools expect,
     * and dispatch.
     */
    if (wbuf_get_pktlen(wbuf) < IEEE80211_ACK_LEN) {
        DPRINTF(scn, ATH_DEBUG_RECV,
                "%s: runt packet %d\n", __func__, wbuf_get_pktlen(wbuf));
        wbuf_free(wbuf);
    } else {
        struct ieee80211_rx_status rs;
        ATH_RXSTAT2IEEE(ic, rx_status, &rs);
        ieee80211_input_monitor(ic, wbuf, &rs);
    }
	return;
}
#endif /* ! UMAC_SUPPORT_OPMODE_APONLY */

#define IS_CTL(wh)  \
    ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_CTL)
#define IS_PSPOLL(wh)   \
    ((wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) == IEEE80211_FC0_SUBTYPE_PS_POLL)
#define IS_BAR(wh) \
    ((wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) == IEEE80211_FC0_SUBTYPE_BAR)
#if ATH_SUPPORT_WRAP

int
wrap_psta_input_multicast(struct ath_softc_net80211 *scn, wbuf_t wbuf,
                          ieee80211_rx_status_t *rx_status)
{
    struct ieee80211_node *ni;
    ATH_RX_TYPE status;
    int type;
    struct ieee80211_frame *wh = (struct ieee80211_frame *)wbuf_header(wbuf);

    ASSERT(scn->sc_mcast_recv_vap);
    ASSERT(wbuf);

    ni = scn->sc_mcast_recv_vap->iv_bss;
    /*
     * Let ath_dev do some special rx frame processing. If the frame is not
     * consumed by ath_dev, indicate it up to the stack.
     */
    type = scn->sc_ops->rx_proc_frame(scn->sc_dev, ATH_NODE_NET80211(ni)->an_sta,
                                      IEEE80211_NODE_ISAMPDU(ni),
                                      wbuf, rx_status, &status);

    /* For OWL specific HW bug, 4addr aggr needs to be denied in
    * some cases. So check for delba send and send delba
    */
    if ((wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_DSTODS) {
        if (IEEE80211_NODE_WDSWAR_ISSENDDELBA(ni)) {
            struct ieee80211_qosframe_addr4 *whqos_4addr;
            int tid;

            whqos_4addr = (struct ieee80211_qosframe_addr4 *)wh;
            tid = whqos_4addr->i_qos[0] & IEEE80211_QOS_TID;
            ath_net80211_delba_send(ni, tid, 0, IEEE80211_REASON_UNSPECIFIED);
        }
    }

    if (status != ATH_RX_CONSUMED) {
        /*
         * Not consumed by ath_dev for out-of-order delivery,
         * indicate up the stack now.
         */
        type = ath_net80211_input(ni, wbuf, rx_status);
    }

    return type;
}
#endif

int
ath_net80211_rx(ieee80211_handle_t ieee, wbuf_t wbuf, ieee80211_rx_status_t *rx_status, u_int16_t keyix)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ieee80211_node *ni;
    struct ieee80211_frame *wh;
    int type;
    ATH_RX_TYPE status;
    struct ieee80211_qosframe_addr4      *whqos_4addr;
    int tid;
    int frame_type, frame_subtype;

#if USE_MULTIPLE_BUFFER_RCV
	wbuf_t wbuf_last;
#endif

    if ((NULL != ic->ic_mon_vap) && (ieee80211_vap_active_is_set(ic->ic_mon_vap))) {
        wbuf_t wbuf_orig = qdf_nbuf_copy((qdf_nbuf_t)wbuf);
        if(wbuf_orig){
            wbuf_t prev_wbuf = wbuf_orig;
            wbuf_t wbuf_tmp = qdf_nbuf_next((qdf_nbuf_t)wbuf);
            wbuf_t wbuf_cpy = NULL;

            while(wbuf_tmp){
                wbuf_cpy = qdf_nbuf_copy((qdf_nbuf_t)wbuf_tmp);
                if(!wbuf_cpy)
                    break;
                qdf_nbuf_set_next_ext((qdf_nbuf_t)prev_wbuf, (qdf_nbuf_t)wbuf_cpy);
                prev_wbuf = wbuf_cpy;
                wbuf_tmp = qdf_nbuf_next((qdf_nbuf_t)wbuf_tmp);
            }

            qdf_nbuf_set_next_ext((qdf_nbuf_t)prev_wbuf, NULL);
            ath_net80211_rx_monitor(ic, wbuf_orig, rx_status);
        }
    }

#if ATH_SUPPORT_IWSPY
    wh = (struct ieee80211_frame *) wbuf_header (wbuf);
	if (rx_status->flags & ATH_RX_RSSI_VALID)
	{
		ieee80211_input_iwspy_update_rssi(ic, wh->i_addr2, rx_status->rssi);
	}
#endif
    /*
     * From this point on we assume the frame is at least
     * as large as ieee80211_frame_min; verify that.
     */
    if (wbuf_get_pktlen(wbuf) < (ic->ic_minframesize + IEEE80211_CRC_LEN)) {
        DPRINTF(scn, ATH_DEBUG_RECV, "%s: short packet %d\n",
                    __func__, wbuf_get_pktlen(wbuf));
        wbuf_free(wbuf);
        return -1;
    }

#ifdef ATH_SUPPORT_TxBF
    ath_net80211_bf_rx(ic, wbuf, rx_status);
#endif
    /*
     * Normal receive.
     */
#if USE_MULTIPLE_BUFFER_RCV
    /* the CRC is at the end of the rx buf chain */
    wbuf_last = wbuf;
    while (wbuf_next(wbuf_last) != NULL)
		wbuf_last = wbuf_next(wbuf_last);
	wbuf_trim(wbuf_last, IEEE80211_CRC_LEN);
#else
	wbuf_trim(wbuf, IEEE80211_CRC_LEN);
#endif

    if (CHK_SC_DEBUG_SCN(scn, ATH_DEBUG_RECV)) {
        wh = (struct ieee80211_frame *)wbuf_header(wbuf);
        if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_DATA)
        ieee80211_dump_pkt(ic, wbuf_header(wbuf), wbuf_get_pktlen(wbuf) + IEEE80211_CRC_LEN,
                           rx_status->rateKbps, rx_status->rssi);
    }

    /*
     * Handle packets with keycache miss if WEP on MBSSID
     * is enabled.
     */
    {
        struct ieee80211_rx_status rs;
        ATH_RXSTAT2IEEE(ic, rx_status, &rs);

        if (ieee80211_crypto_handle_keymiss(ic, wbuf, &rs))
            return -1;
    }

    wh = (struct ieee80211_frame *) wbuf_header (wbuf);
    frame_type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    frame_subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

    /*
     * Locate the node for sender, track state, and then
     * pass the (referenced) node up to the 802.11 layer
     * for its use.  If the sender is unknown spam the
     * frame; it'll be dropped where it's not wanted.
     */
    IEEE80211_KEYMAP_LOCK(scn);
    ni = (keyix != HAL_RXKEYIX_INVALID) ? scn->sc_keyixmap[keyix] : NULL;
    /* check if lookup is right -- using mac address in packet */
    if (qdf_likely(ni!= NULL)) {
        bool correct = true;
        wh = (struct ieee80211_frame *) wbuf_header(wbuf);
        if (IS_CTL(wh) && !IS_PSPOLL(wh) && !IS_BAR(wh))
            correct  = (IEEE80211_ADDR_EQ(ni->ni_macaddr, wh->i_addr1));
        else
            correct  = (IEEE80211_ADDR_EQ(ni->ni_macaddr, wh->i_addr2));

        if (!correct) {
            ni = NULL;
        }
    }
    if (ni == NULL) {
        IEEE80211_KEYMAP_UNLOCK(scn);
        /*
         * No key index or no entry, do a lookup and
         * add the node to the mapping table if possible.
         */
        ni = ieee80211_find_rxnode(ic, (struct ieee80211_frame_min *)
                                   wbuf_header(wbuf));
        if (ni == NULL) {
            struct ieee80211_rx_status rs;

#if ATH_SUPPORT_WRAP
            struct ath_softc *sc = scn->sc_dev;

            wh = (struct ieee80211_frame *)wbuf_header(wbuf);
            type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;

            /*
             * If we are in ProxySTA (promiscuous) mode, we need to filter
             * out not interested frames as early as possible. We just let
             * broadcast/multicast frames go through - either data frames
             * manage frames (beacon/probe request/probe response/etc). We
             * also allow unicast class 2 frames (i.e Authentication) pass
             * because node might not be allocated at this point. We assume
             * each VAP will check A2 matches bssid.
             */
            if (sc->sc_enableproxysta) {
                int drop_frame = 0;

                if (!IEEE80211_IS_MULTICAST(wh->i_addr1) &&
                    (type == IEEE80211_FC0_TYPE_MGT ||
                     type == IEEE80211_FC0_TYPE_CTL))
                {
                    int subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
                    struct ieee80211_node *n1 =
                        ieee80211_find_node(&ic->ic_sta, wh->i_addr1);

                    /*
                     * Drop unicast management frames not directing
                     * to one of our AP BSS's except probe response.
                     */
                    if ((subtype != IEEE80211_FC0_SUBTYPE_PROBE_RESP) &&
                        (!n1 || n1 != n1->ni_vap->iv_bss ||
                         n1->ni_vap->iv_opmode != IEEE80211_M_HOSTAP))
                    {
                        drop_frame = 1;
                    }
                    if (n1) {
                        ieee80211_free_node(n1);
                    }
                }
                if (drop_frame ||
                    (!IEEE80211_IS_MULTICAST(wh->i_addr1) &&
                     type == IEEE80211_FC0_TYPE_DATA))
                {
                    wbuf_free(wbuf);
                    return -1;
                }
            }
#endif

            ATH_RXSTAT2IEEE(ic, rx_status, &rs);

#if ATH_SUPPORT_WRAP
            if (scn->sc_mcast_recv_vap &&
                ieee80211_vap_active_is_set(scn->sc_mcast_recv_vap) &&
                IEEE80211_IS_MULTICAST(wh->i_addr1) &&
                type == IEEE80211_FC0_TYPE_DATA)
            {
                return wrap_psta_input_multicast(scn, wbuf, rx_status);
            } else
#endif
            return ieee80211_input_all(ic, wbuf, &rs);
        }
    } else {
#if ATH_SUPPORT_WRAP
        struct ath_vap_net80211 *avn = ATH_VAP_NET80211(ni->ni_vap);

        KASSERT(!avn->av_is_wrap || ni != ni->ni_vap->iv_bss,
                ("find ni %s for WRAP VAP from sc_keyixmap[%d] directly",
                 ether_sprintf(ni->ni_macaddr), keyix));
#endif
        ieee80211_ref_node(ni);
        IEEE80211_KEYMAP_UNLOCK(scn);
    }
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    /*
     * Let ath_dev do some special rx frame processing. If the frame is not
     * consumed by ath_dev, indicate it up to the stack.
     */
    type = scn->sc_ops->rx_proc_frame(scn->sc_dev, ATH_NODE_NET80211(ni)->an_sta,
                                      IEEE80211_NODE_ISAMPDU(ni),
                                      wbuf, rx_status, &status);


    /* For OWL specific HW bug, 4addr aggr needs to be denied in
    * some cases. So check for delba send and send delba
    */
    if ( (wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_DSTODS ) {
        if (IEEE80211_NODE_WDSWAR_ISSENDDELBA(ni) ) {
	    whqos_4addr = (struct ieee80211_qosframe_addr4 *) wh;
            tid = whqos_4addr->i_qos[0] & IEEE80211_QOS_TID;
	    ath_net80211_delba_send(ni, tid, 0, IEEE80211_REASON_UNSPECIFIED);
	}
    }

    if (status != ATH_RX_CONSUMED) {
        /*
         * Not consumed by ath_dev for out-of-order delivery,
         * indicate up the stack now.
         */
        type = ath_net80211_input(ni, wbuf, rx_status);
    }

    ieee80211_free_node(ni);
    return type;
}

static void
ath_net80211_drain_amsdu(ieee80211_handle_t ieee)
{
#ifdef ATH_AMSDU
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    ath_amsdu_tx_drain(scn);
#endif
}
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
int
ath_net80211_node_ext_stats_enable(struct ieee80211_node *ni, u_int32_t enable)
{
    /* Stub for direct attach solutions. Do nothing */
    return 0;
}

void
ath_net80211_buffull_handler(ieee80211_handle_t ieee)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    ieee80211_buffull_handler(ic);
}

static void
ath_net80211_drop_query_from_sta(ieee80211_handle_t ieee, u_int32_t enable)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
	ic->ic_dropstaquery = enable;
}

static u_int32_t
ath_net80211_get_drop_query_from_sta(ieee80211_handle_t ieee)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
	return ic->ic_dropstaquery;
}

static void
ath_net80211_block_flooding_report(ieee80211_handle_t ieee, u_int32_t enable)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
	ic->ic_blkreportflood = enable;
}

static u_int32_t
ath_net80211_get_block_flooding_report(ieee80211_handle_t ieee)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
	return ic->ic_blkreportflood;
}

static void
ath_net80211_ald_update_phy_error_rate(struct ath_linkdiag *ald,
                                   u_int32_t new_phyerr)
{
    ieee80211_ald_update_phy_error_rate(ald, new_phyerr);
}
#endif

#if ATH_SUPPORT_SPECTRAL
static void
ath_net80211_spectral_indicate(ieee80211_handle_t ieee, void* spectral_buf, u_int32_t buf_size)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    IEEE80211_COMM_LOCK(ic);
    /* TBD: There should be only one ic_evtable */
    if (ic->ic_evtable[0]  && ic->ic_evtable[0]->wlan_dev_spectral_indicate) {
        (*ic->ic_evtable[0]->wlan_dev_spectral_indicate)(scn->sc_osdev, spectral_buf, buf_size);
    }
    IEEE80211_COMM_UNLOCK(ic);
}

#if UMAC_SUPPORT_ACS
static void  ath_net80211_spectral_eacs_update (ieee80211_handle_t ieee, int8_t nfc_ctl_rssi, int8_t nfc_ext_rssi,
                                                  int8_t ctrl_nf, int8_t ext_nf)
{
  #if ATH_ACS_SUPPORT_SPECTRAL && ATH_SUPPORT_SPECTRAL
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    ieee80211_update_eacs_counters(ic, nfc_ctl_rssi, nfc_ext_rssi, ctrl_nf, ext_nf);
#endif

}

static void ath_net80211_spectral_init_chan(ieee80211_handle_t ieee, int curchan, int extchan)
{

#if ATH_ACS_SUPPORT_SPECTRAL && ATH_SUPPORT_SPECTRAL
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    ieee80211_init_spectral_chan_loading(ic, curchan, extchan);
#endif
}

static int ath_net80211_spectral_get_freq(ieee80211_handle_t ieee)
{
        int freq_loading = 0;

#if ATH_ACS_SUPPORT_SPECTRAL && ATH_SUPPORT_SPECTRAL
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    freq_loading = ieee80211_get_spectral_freq_loading(ic);
#endif
    return freq_loading;
}
#endif

#endif

static void
ath_net80211_sm_pwrsave_update(struct ieee80211_node *ni, int smen, int dyn,
	int ratechg)
{
	struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ni->ni_ic);
	ATH_SM_PWRSAV mode;

	if (smen) {
		mode = ATH_SM_ENABLE;
	} else {
		if (dyn) {
			mode = ATH_SM_PWRSAV_DYNAMIC;
		} else {
			mode = ATH_SM_PWRSAV_STATIC;
		}
	}

	DPRINTF(scn, ATH_DEBUG_PWR_SAVE,
	    "%s: smen: %d, dyn: %d, ratechg: %d\n",
	    __func__, smen, dyn, ratechg);
	(scn->sc_ops->ath_sm_pwrsave_update)(scn->sc_dev,
	    ATH_NODE_NET80211(ni)->an_sta, mode, ratechg);
}

static void
ath_net80211_node_ps_update(struct ieee80211_node *ni, int pwrsave,
    int pause_resume)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ni->ni_ic);
    DPRINTF(scn, ATH_DEBUG_PWR_SAVE,
	    "%s: pwrsave %d \n", __func__, pwrsave);
    (scn->sc_ops->update_node_pwrsave)(scn->sc_dev,
                                       ATH_NODE_NET80211(ni)->an_sta, pwrsave,
                                       pause_resume);

}

static int
ath_net80211_node_queue_depth(struct ieee80211_node *ni)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ni->ni_ic);
    int queue_depth = 0;

    queue_depth = (scn->sc_ops->node_queue_depth)(scn->sc_dev,
                                       ATH_NODE_NET80211(ni)->an_sta);

    return queue_depth;

}

static void
ath_net80211_rate_setup(ieee80211_handle_t ieee, WIRELESS_MODE wMode,
                        RATE_TYPE type, const HAL_RATE_TABLE *rt)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    enum ieee80211_phymode mode = ath_mode_map[wMode];
    struct ieee80211_rateset *rs;
    int i, maxrates, rix;

    if (mode >= IEEE80211_MODE_MAX) {
        DPRINTF(ATH_SOFTC_NET80211(ic), ATH_DEBUG_ANY,
            "%s: unsupported mode %u\n", __func__, mode);
        return;
    }

    if (rt->rateCount > IEEE80211_RATE_MAXSIZE) {
        DPRINTF(ATH_SOFTC_NET80211(ic), ATH_DEBUG_ANY,
                "%s: rate table too small (%u > %u)\n",
                __func__, rt->rateCount, IEEE80211_RATE_MAXSIZE);
        maxrates = IEEE80211_RATE_MAXSIZE;
    } else {
        maxrates = rt->rateCount;
    }

    switch (type) {
    case NORMAL_RATE:
        rs = IEEE80211_SUPPORTED_RATES(ic, mode);
        break;
    case HALF_RATE:
        rs = IEEE80211_HALF_RATES(ic);
        break;
    case QUARTER_RATE:
        rs = IEEE80211_QUARTER_RATES(ic);
        break;
    default:
        DPRINTF(ATH_SOFTC_NET80211(ic), ATH_DEBUG_ANY,
            "%s: unknown rate type%u\n", __func__, type);
        return;
    }

    /* supported rates (non HT) */
    rix = 0;
    /* The macro IEEE80211_RATE_MAXSIZE redefined with value 44.
       But the size of the info array is 36.  To avoid array
       out of bound issue adding the boundry check with value 36*/
    for (i = 0; (i < maxrates) && (i < 36); i++) {
        if ((rt->info[i].phy == IEEE80211_T_HT))
            continue;
        rs->rs_rates[rix++] = rt->info[i].dot11Rate;
    }
    rs->rs_nrates = (u_int8_t)rix;
    if ((mode == IEEE80211_MODE_11NA_HT20)     || (mode == IEEE80211_MODE_11NG_HT20)      ||
        (mode == IEEE80211_MODE_11NA_HT40PLUS) || (mode == IEEE80211_MODE_11NA_HT40MINUS) ||
        (mode == IEEE80211_MODE_11NG_HT40PLUS) || (mode == IEEE80211_MODE_11NG_HT40MINUS)) {
        /* supported rates (HT) */
        rix = 0;
        rs = IEEE80211_HT_RATES(ic, mode);
        for (i = 0; (i < maxrates) && (i < 36); i++) {
            if (rt->info[i].phy == IEEE80211_T_HT) {
                rs->rs_rates[rix++] = rt->info[i].dot11Rate;
            }
        }
        rs->rs_nrates = (u_int8_t)rix;
    }
}

static void ath_net80211_update_txrate(ieee80211_node_t node, int txrate)
{
}

void ath_net80211_update_rate_node(struct ieee80211com *ic, struct ieee80211_node *ni,
                                   int isnew)
{
    ath_net80211_rate_node_update((ieee80211_handle_t )ic, (ieee80211_node_t)ni,
                                  isnew);
}

static void ath_net80211_rate_node_update(ieee80211_handle_t ieee, ieee80211_node_t node, int isnew)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ieee80211_node *ni = (struct ieee80211_node *)node;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_node_net80211 *an = (struct ath_node_net80211 *)ni;
    struct ieee80211vap *vap = ieee80211_node_get_vap(ni);
    u_int32_t capflag = 0;
    enum ieee80211_cwm_width ic_cw_width = ic->ic_cwm_get_width(ic);

    if (ni->ni_flags & IEEE80211_NODE_HT) {
        capflag |=  ATH_RC_HT_FLAG;
    if (ieee80211_ic_enh_ind_rpt_is_set(ic)) {
    if (ni->ni_chwidth == IEEE80211_CWM_WIDTH40) {
        capflag |=  ATH_RC_CW40_FLAG;
        }
        } else {
        if ((ni->ni_chwidth == IEEE80211_CWM_WIDTH40) &&
            (ic_cw_width == IEEE80211_CWM_WIDTH40))
        {
            capflag |=  ATH_RC_CW40_FLAG;
        }
        }
        if (((ni->ni_chwidth == IEEE80211_CWM_WIDTH20) && (ni->ni_htcap & IEEE80211_HTCAP_C_SHORTGI20)) ||
            ((ni->ni_chwidth == IEEE80211_CWM_WIDTH40) && (ni->ni_htcap & IEEE80211_HTCAP_C_SHORTGI20) && (ni->ni_htcap & IEEE80211_HTCAP_C_SHORTGI40))) {
            capflag |= ATH_RC_SGI_FLAG;
        }

        /* Rx STBC is a 2-bit mask. Needs to convert from ieee definition to ath definition. */
        capflag |= (((ni->ni_htcap & IEEE80211_HTCAP_C_RXSTBC) >> IEEE80211_HTCAP_C_RXSTBC_S)
                    << ATH_RC_RX_STBC_FLAG_S);

        capflag |= ath_set_ratecap(scn, ni, vap);

        if (ni->ni_flags & IEEE80211_NODE_WEPTKIP) {

            capflag |= ATH_RC_WEP_TKIP_FLAG;
            if (ieee80211_ic_wep_tkip_htrate_is_set(ic)) {
                /* TKIP supported at HT rates */
                if (ieee80211_has_weptkipaggr(ni)) {
                    /* Pass proprietary rx delimiter count for tkip w/aggr to ath_dev */
                    scn->sc_ops->set_weptkip_rxdelim(scn->sc_dev, an->an_sta, ni->ni_weptkipaggr_rxdelim);
                } else {
                    /* Atheros proprietary wep/tkip aggregation mode is not supported */
                    ni->ni_flags |= IEEE80211_NODE_NOAMPDU;
                }
            } else {
                /* no TKIP support at HT rates => disable HT and aggregation */
                capflag &= ~ATH_RC_HT_FLAG;
                ni->ni_flags |= IEEE80211_NODE_NOAMPDU;
            }
        }
    }

    if (ni->ni_flags & IEEE80211_NODE_UAPSD) {
        capflag |= ATH_RC_UAPSD_FLAG;
    }

#ifdef  ATH_SUPPORT_TxBF
    capflag |= (((ni->ni_txbf.channel_estimation_cap) << ATH_RC_CEC_FLAG_S) & ATH_RC_CEC_FLAG);
#endif
    ((struct ath_node *)an->an_sta)->an_cap = capflag;
    scn->sc_ops->ath_rate_newassoc(scn->sc_dev, an->an_sta, isnew, capflag,
                                   &ni->ni_rates, &ni->ni_htrates);
}

/* Iterator function */
static void
rate_cb(void *arg, struct ieee80211_node *ni)
{
    struct ieee80211vap *vap = (struct ieee80211vap *)arg;

    if ((ni != ni->ni_vap->iv_bss) && (vap == ni->ni_vap)) {
        ath_net80211_rate_node_update(vap->iv_ic, ni, 1);
    }
}

static void ath_net80211_rate_newstate(ieee80211_handle_t ieee, ieee80211_if_t if_data)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ieee80211vap *vap = (struct ieee80211vap *)if_data;
    struct ieee80211_node* ni = ieee80211vap_get_bssnode(vap);
    u_int32_t capflag = 0;
    ath_node_t an;
    enum ieee80211_cwm_width ic_cw_width = ic->ic_cwm_get_width(ic);

    ASSERT(ni);

    if (ieee80211vap_get_opmode(vap) != IEEE80211_M_STA) {

        if((vap->iv_bsschan == NULL) ||
                (vap->iv_bsschan == IEEE80211_CHAN_ANYC)){
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "VAP channel is not set for vap %p investigate!\n", vap);
            return;
        }
        /*
         * Sync rates for associated stations and neighbors.
         */
        wlan_iterate_station_list(vap, rate_cb, (void *)vap);

        if (ic_cw_width == IEEE80211_CWM_WIDTH40) {
            capflag |= ATH_RC_CW40_FLAG;
        }
        if (IEEE80211_IS_CHAN_11N(vap->iv_bsschan)) {
            capflag |= ATH_RC_HT_FLAG;
    	    if (scn->sc_ops->have_capability(scn->sc_dev, ATH_CAP_TS)) {
                capflag |= ATH_RC_TS_FLAG;
            }
    	    if (scn->sc_ops->have_capability(scn->sc_dev, ATH_CAP_DS)) {
                capflag |= ATH_RC_DS_FLAG;
            }
        }
    } else {
        if (ni->ni_flags & IEEE80211_NODE_HT) {
            capflag |=  ATH_RC_HT_FLAG;
            capflag |= ath_set_ratecap(scn, ni, vap);
        }
         if (ieee80211_ic_enh_ind_rpt_is_set(ic)) {
            if (vap->iv_bss->ni_chwidth == IEEE80211_CWM_WIDTH40) {
                capflag |= ATH_RC_CW40_FLAG;
            }
        } else {

            if ((vap->iv_bss->ni_chwidth == IEEE80211_CWM_WIDTH40) &&
                    (ic_cw_width == IEEE80211_CWM_WIDTH40))
            {
                capflag |= ATH_RC_CW40_FLAG;
            }
        }
        }
    if (ni) {
        if (((ni->ni_chwidth == IEEE80211_CWM_WIDTH20) && (ni->ni_htcap & IEEE80211_HTCAP_C_SHORTGI20)) ||
            ((ni->ni_chwidth == IEEE80211_CWM_WIDTH40) && (ni->ni_htcap & IEEE80211_HTCAP_C_SHORTGI20) && (ni->ni_htcap & IEEE80211_HTCAP_C_SHORTGI40))) {
            capflag |= ATH_RC_SGI_FLAG;
        }

        /* Rx STBC is a 2-bit mask. Needs to convert from ieee definition to ath definition. */
        capflag |= (((ni->ni_htcap & IEEE80211_HTCAP_C_RXSTBC) >> IEEE80211_HTCAP_C_RXSTBC_S)
                << ATH_RC_RX_STBC_FLAG_S);

        if (ni->ni_flags & IEEE80211_NODE_WEPTKIP) {
            capflag |= ATH_RC_WEP_TKIP_FLAG;
        }

        if (ni->ni_flags & IEEE80211_NODE_UAPSD) {
            capflag |= ATH_RC_UAPSD_FLAG;
        }
#ifdef  ATH_SUPPORT_TxBF
        capflag |= (((ni->ni_txbf.channel_estimation_cap) << ATH_RC_CEC_FLAG_S) & ATH_RC_CEC_FLAG);
#endif
        an = ((struct ath_node_net80211 *)ni)->an_sta;
        scn->sc_ops->ath_rate_newassoc(scn->sc_dev, an, 1, capflag,
                &ni->ni_rates, &ni->ni_htrates);
    }
}

static HAL_HT_MACMODE ath_net80211_cwm_macmode(ieee80211_handle_t ieee)
{
    return ath_cwm_macmode(ieee);
}

static void ath_net80211_chwidth_change(struct ieee80211_node *ni)
{
    ath_cwm_chwidth_change(ni);
}

#ifndef REMOVE_PKTLOG_PROTO
static u_int8_t *ath_net80211_parse_frm(ieee80211_handle_t ieee, wbuf_t wbuf,
        ieee80211_node_t node,
        void *frm, u_int16_t keyix)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ieee80211_node *ni = (struct ieee80211_node *)node;
    struct ieee80211_frame *wh;
    u_int8_t *llc = NULL;
    int icv_len, llc_start_offset, len;

    if (ni == NULL && keyix != HAL_RXKEYIX_INVALID) { /* rx node */
        ni = scn->sc_keyixmap[keyix];
        if (ni == NULL)
            return NULL;
    }

    wh = (struct ieee80211_frame *)frm;

    if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) != IEEE80211_FC0_TYPE_DATA) {
        return NULL;
    }

    if (ni) {
        if (ni->ni_ucastkey.wk_cipher == &ieee80211_cipher_none) {
            icv_len = 0;
        } else {
            struct ieee80211_key *k = &ni->ni_ucastkey;
            const struct ieee80211_cipher *cip = k->wk_cipher;

            icv_len = cip->ic_header;
        }
    }
    else {
        icv_len = 0;
    }

    /*
     * Get llc offset.
     */
    llc_start_offset = ieee80211_anyhdrspace(ic, wh) + icv_len;

    if (wbuf) {
        while(llc_start_offset > 0) {
            len = wbuf_get_len(wbuf);
            if (len >= llc_start_offset + sizeof(struct llc)) {
                llc = (u_int8_t *)(wbuf_raw_data(wbuf)) + llc_start_offset;
                break;
            }
            else {
                wbuf = wbuf_next_buf(wbuf);
                if (!wbuf) {
                    return NULL;
                }

            }
            llc_start_offset -= len;
        }

        if (!llc){
            return NULL;
        }
    }
    else {
        llc = (u_int8_t *)wh + ieee80211_anyhdrspace(ic, wh) + icv_len;
    }

    return llc;
}
#endif

#if ATH_SUPPORT_IQUE
void ath_net80211_hbr_settrigger(ieee80211_node_t node, int signal)
{
    struct ieee80211_node *ni;
    struct ieee80211vap *vap;
    ni = (struct ieee80211_node *)node;
    /* Node is associated, and not the AP self */
    if (ni && ni->ni_associd && ni != ni->ni_vap->iv_bss) {
        vap = ni->ni_vap;
        if (vap->iv_ique_ops.hbr_sendevent)
            vap->iv_ique_ops.hbr_sendevent(vap, ni->ni_macaddr, signal);
    }
}

static u_int8_t ath_net80211_get_hbr_block_state(ieee80211_node_t node)
{
    return ieee80211_node_get_hbr_block_state(node);
}
#endif /*ATH_SUPPORT_IQUE*/

#if ATH_SUPPORT_VOWEXT
static u_int16_t ath_net80211_get_aid(ieee80211_node_t node)
{
    return ieee80211_node_get_associd(node);
}
#endif

#if ATH_SUPPORT_DSCP_OVERRIDE
static void ath_net80211_set_dscp_override(ieee80211_handle_t ieee, u_int32_t val)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    ic->ic_override_dscp = !!val;
    return;
}

static u_int32_t ath_net80211_get_dscp_override(ieee80211_handle_t ieee)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    return ic->ic_override_dscp;
}

static void ath_net80211_set_dscp_tid_map(ieee80211_handle_t ieee, u_int8_t tos, u_int8_t tid)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);

    if (tid < 0 || tid > 7)
    {
        DPRINTF(ATH_SOFTC_NET80211(ic), ATH_DEBUG_ANY, "Unsupported tid %u\n", tid);
        return;
    }
    ic->ic_dscp_tid_map[(tos >> IP_DSCP_SHIFT) & IP_DSCP_MASK] = tid;
    return;
}

static u_int8_t ath_net80211_get_dscp_tid_map(ieee80211_handle_t ieee, u_int8_t tos)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    return ic->ic_dscp_tid_map[(tos >> IP_DSCP_SHIFT) & IP_DSCP_MASK];
}


static void ath_net80211_reset_dscp_tid_map(ieee80211_handle_t ieee, u_int8_t tid)
{
    int i;
    struct ieee80211com *ic = NET80211_HANDLE(ieee);

    if (tid < 0 || tid > 7)
    {
        DPRINTF(ATH_SOFTC_NET80211(ic), ATH_DEBUG_ANY, "Unsupported tid %u\n", tid);
        return;
    }
    for ( i = 0; i < IP_DSCP_MAP_LEN; i++)
    {
        ic->ic_dscp_tid_map[i] = tid;
    }
}

static void ath_net80211_set_igmp_dscp_override(ieee80211_handle_t ieee, u_int32_t enable)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    ic->ic_override_igmp_dscp = !!enable;
}

static u_int32_t ath_net80211_get_igmp_dscp_override(ieee80211_handle_t ieee)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    return ic->ic_override_igmp_dscp;
}

static void ath_net80211_set_igmp_dscp_tid_map(ieee80211_handle_t ieee, u_int8_t tid)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    if (tid > 7)
        DPRINTF(ATH_SOFTC_NET80211(ic), ATH_DEBUG_ANY, "Unsupported tid %u\n", tid);
    else
        ic->ic_dscp_igmp_tid = tid;
}

static u_int32_t ath_net80211_get_igmp_dscp_tid_map(ieee80211_handle_t ieee)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    return ic->ic_dscp_igmp_tid;
}

static void ath_net80211_set_hmmc_dscp_override(ieee80211_handle_t ieee, u_int32_t enable)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    ic->ic_override_hmmc_dscp = !!enable;
}

static u_int32_t ath_net80211_get_hmmc_dscp_override(ieee80211_handle_t ieee)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    return ic->ic_override_hmmc_dscp;
}

static void ath_net80211_set_hmmc_dscp_tid_map(ieee80211_handle_t ieee, u_int8_t tid)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    if (tid > 7)
        DPRINTF(ATH_SOFTC_NET80211(ic), ATH_DEBUG_ANY, "Unsupported tid %u\n", tid);
    else
        ic->ic_dscp_hmmc_tid = tid;
}

static u_int32_t ath_net80211_get_hmmc_dscp_tid_map(ieee80211_handle_t ieee)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    return ic->ic_dscp_hmmc_tid;
}
#endif


#ifdef ATH_SWRETRY
static u_int16_t ath_net80211_get_pwrsaveq_len(ieee80211_node_t node)
{
    return ieee80211_node_get_pwrsaveq_len(node);
}

static void ath_net80211_set_tim(ieee80211_node_t node,u_int8_t setflag)
{
    struct ieee80211_node *ni;
    struct ieee80211vap *vap;
    ni = (struct ieee80211_node *)node;
    /* Node is associated, and not the AP self */
    if (ni && ni->ni_associd && ni != ni->ni_vap->iv_bss) {
        vap = ni->ni_vap;
        if (vap->iv_set_tim != NULL)
            vap->iv_set_tim(ni, setflag, false);
    }
}

#endif

#if LMAC_SUPPORT_POWERSAVE_QUEUE
static u_int8_t ath_net80211_get_lmac_pwrsaveq_len(struct ieee80211com *ic, struct ieee80211_node *ni, u_int8_t frame_type)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_node_net80211 *an = (struct ath_node_net80211 *)ni;
    if (scn->sc_ops->get_pwrsaveq_len) {
        return scn->sc_ops->get_pwrsaveq_len(an->an_sta, frame_type);
    }
    return 0;
}

static int ath_net80211_node_pwrsaveq_send(struct ieee80211com *ic, struct ieee80211_node *ni, u_int8_t frame_type)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_node_net80211 *an = (struct ath_node_net80211 *)ni;
    if (scn->sc_ops->node_pwrsaveq_send) {
        return scn->sc_ops->node_pwrsaveq_send(an->an_sta, frame_type);
    }
    return 0;
}

static void ath_net80211_node_pwrsaveq_flush(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_node_net80211 *an = (struct ath_node_net80211 *)ni;
    if (scn->sc_ops->node_pwrsaveq_flush) {
        scn->sc_ops->node_pwrsaveq_flush(an->an_sta);
    }
    return;
}

static int ath_net80211_node_pwrsaveq_drain(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_node_net80211 *an = (struct ath_node_net80211 *)ni;
    if (scn->sc_ops->node_pwrsaveq_drain) {
        return scn->sc_ops->node_pwrsaveq_drain(an->an_sta);
    }
    return 0;
}

static int ath_net80211_node_pwrsaveq_age(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_node_net80211 *an = (struct ath_node_net80211 *)ni;
    if (scn->sc_ops->node_pwrsaveq_age) {
        return scn->sc_ops->node_pwrsaveq_age(an->an_sta);
    }
    return 0;
}

static void ath_net80211_node_pwrsaveq_get_info(struct ieee80211com *ic, struct ieee80211_node *ni,
        ieee80211_node_saveq_info *info)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_node_net80211 *an = (struct ath_node_net80211 *)ni;
    if (scn->sc_ops->node_pwrsaveq_get_info) {
        scn->sc_ops->node_pwrsaveq_get_info(an->an_sta, (void *)info);
    }
    return;
}

static void ath_net80211_node_pwrsaveq_set_param(struct ieee80211com *ic, struct ieee80211_node *ni,
        enum ieee80211_node_saveq_param param, u_int32_t val)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_node_net80211 *an = (struct ath_node_net80211 *)ni;
    if (scn->sc_ops->node_pwrsaveq_set_param) {
        scn->sc_ops->node_pwrsaveq_set_param(an->an_sta, (int)param, val);
    }
    return;
}
#endif

/*
 * If node is NULL, return the iv_bss node's flag
 * Otherwise, return the specified ni's flags
 */
static u_int32_t ath_net80211_get_node_flags(ieee80211_handle_t ieee, int if_id, ieee80211_node_t node)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ieee80211_node *ni = (struct ieee80211_node *)node;
    struct ieee80211_node *bss_node = NULL;
    struct ieee80211vap *vap = NULL;

    IEEE80211_COMM_LOCK(ic);
    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if ((ATH_VAP_NET80211(vap))->av_if_id == if_id)
            break;
    }
    IEEE80211_COMM_UNLOCK(ic);
    ASSERT(vap);

    bss_node = vap ? ieee80211vap_get_bssnode(vap) : NULL;

    if (!vap || !bss_node)
        return 0;

    if (ni == NULL)
        return bss_node->ni_flags;
    else {
        ASSERT(ni->ni_vap == vap);
        return ni->ni_flags;
    }
}
    u_int8_t *
ath_net80211_get_macaddr(ieee80211_node_t node)
{
    struct ieee80211_node *ni;
    ni = (struct ieee80211_node *)node;

    return ni->ni_macaddr;
}
static void
ath_txpow_mgmt(struct ieee80211vap *vap,int frame_subtype,u_int8_t transmit_power)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_vap_net80211 *avn = ATH_VAP_NET80211(vap);

    scn->sc_ops->txpow_mgmt(scn->sc_dev, avn->av_if_id, frame_subtype,transmit_power);
}


static bool
ath_modify_bcn_rate(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_vap_net80211 *avn = ATH_VAP_NET80211(vap);

    return scn->sc_ops->modify_bcn_rate(scn->sc_dev, avn->av_if_id, vap->iv_bcn_rate);
}

struct ieee80211_ops net80211_ops = {
    ath_get_netif_settings,                 /* get_netif_settings */
    ath_mcast_merge,                        /* netif_mcast_merge  */
    ath_net80211_channel_setup,             /* setup_channel_list */
    ath_net80211_set_countrycode,           /* set_countrycode    */
    ath_net80211_set_regdomaincode,         /* set_regdomaincode  */
    ath_net80211_update_txpow,              /* update_txpow       */
    ath_net80211_get_beaconconfig,          /* get_beacon_config  */
    ath_net80211_beacon_alloc,              /* get_beacon         */
    ath_net80211_beacon_update,             /* update_beacon      */
    ath_net80211_beacon_miss,               /* notify_beacon_miss */
    ath_net80211_notify_beacon_rssi,        /* notify_beacon_rssi */
    ath_net80211_proc_tim,                  /* proc_tim           */
    ath_net80211_proc_dtim,                 /* proc_dtim          */
    ath_net80211_send_bar,                  /* send_bar           */
    ath_net80211_notify_qstatus,            /* notify_txq_status  */
#if ATH_SUPPORT_WIFIPOS
    ath_net80211_update_wifipos_stats,      /* update_wifipos_stats */
    ath_net80211_isthere_wakeup_request,    /* isthere_wakeup_request */
    ath_net80211_update_ka_done,               /* update_ka_done */
#endif
    ath_net80211_tx_complete,               /* tx_complete        */
#if ATH_TX_COMPACT

#ifdef ATH_SUPPORT_QUICK_KICKOUT
    ath_net80211_tx_node_kick_event,         /* tx_node_kick_event */
#endif
    ath_net80211_tx_complete_compact,        /* tx_complete_compact */
    ath_net80211_free_node,                  /* tx_free_node      */

#ifdef ATH_SUPPORT_TxBF
    ath_net80211_handle_txbf_comp,           /* tx_handle_txbf_complete */
#endif
    ath_net80211_check_and_update_pn,       /* check_and_update_pn */
    ath_net80211_tx_update_stats,            /* tx_update_stats */
#endif // ATH_TX_COMPACT
    NULL,									/* tx_status		  */
    ath_net80211_rx,                        /* rx_indicate        */
    ath_net80211_input,                     /* rx_subframe        */
    ath_net80211_cwm_macmode,               /* cwm_macmode        */
#ifdef ATH_SUPPORT_DFS
    ath_net80211_dfs_test_return,           /* dfs_test_return    */
    ath_net80211_mark_dfs,                  /* mark_dfs           */
    ath_net80211_enable_radar_dfs,              /* enable radar       */
#endif
    ath_net80211_set_vap_state,             /* set_vap_state      */
    ath_net80211_change_channel,            /* change channel     */
    ath_net80211_switch_mode_static20,      /* change mode to static20 */
    ath_net80211_switch_mode_dynamic2040,   /* change mode to dynamic2040 */
    ath_net80211_rate_setup,                /* setup_rate */
    ath_net80211_update_txrate,             /* update_txrate */
    ath_net80211_rate_newstate,             /* rate_newstate */
    ath_net80211_rate_node_update,          /* rate_node_update */
    ath_net80211_drain_amsdu,               /* drain_amsdu */
    ath_net80211_node_get_extradelimwar,    /* node_get_extradelimwar */
#if ATH_SUPPORT_SPECTRAL
    ath_net80211_spectral_indicate,         /* spectral_indicate */
#if UMAC_SUPPORT_ACS
    ath_net80211_spectral_eacs_update,       /* spectral_eacs_update*/
    ath_net80211_spectral_init_chan,        /* spectral_init_chan_loading*/
    ath_net80211_spectral_get_freq,         /* spectral_get_freq_loading*/
#else
    NULL,
    NULL,
    NULL,
#endif
#endif
    ath_net80211_cw_interference_handler,
#ifdef ATH_SUPPORT_UAPSD
    ath_net80211_check_uapsdtrigger,        /* check_uapsdtrigger */
    ath_net80211_uapsd_eospindicate,        /* uapsd_eospindicate */
    ath_net80211_uapsd_allocqosnullframe,   /* uapsd_allocqosnull */
    ath_net80211_uapsd_getqosnullframe,     /* uapsd_getqosnullframe */
    ath_net80211_uapsd_retqosnullframe,     /* uapsd_retqosnullframe */
    ath_net80211_uapsd_deliverdata,         /* uapsd_deliverdata */
    ath_net80211_uapsd_pause_control,       /* uapsd_pause_control */
#endif
    NULL,                                   /* get_htmaxrate) */
#if ATH_SUPPORT_IQUE
    ath_net80211_hbr_settrigger,            /* hbr_settrigger */
    ath_net80211_get_hbr_block_state,       /* get_hbr_block_state */
#endif
#if ATH_SUPPORT_VOWEXT
    ath_net80211_get_aid,                   /* get_aid */
#endif
#ifdef ATH_SUPPORT_LINUX_STA
    NULL,                                   /* ath_net80211_suspend */
    NULL,                                   /* ath_net80211_resume */
#endif
#ifdef ATH_BT_COEX
    NULL,                                   /* bt_coex_ps_enable */
    NULL,                                   /*bt_coex_ps_poll */
#endif
#ifdef ATH_SUPPORT_HTC
    NULL,                                   /*ath_htc_gettargetnodeid */
    NULL,                                   /* ath_usb_wmm_update */
    NULL,                                   /*ath_htc_gettargetvapid */
    NULL,                                   /*ath_net80211_uapsd_credit_update*/
    NULL,                                   /* ath_net80211_rxcleanup */
#endif
#if ATH_SUPPORT_CFEND
    ath_net80211_cfend_alloc,               /* cfend_alloc */
#endif
#ifndef REMOVE_PKTLOG_PROTO
    ath_net80211_parse_frm,                 /* parse_frm */
#endif

    ath_net80211_get_bssid,
#ifdef ATH_TX99_DIAG
    ath_net80211_find_channel,
#endif
    ath_net80211_set_stbcconfig,            /* set_stbc_config */
    ath_net80211_set_ldpcconfig,            /* set_ldpc_config */
#if UNIFIED_SMARTANTENNA
    ath_net80211_smart_ant_update_txfeedback,      /* smart_ant_update_txfeedback */
    ath_net80211_smart_ant_update_rxfeedback,      /* smart_ant_update_rxfeedback */
    ath_net80211_smart_ant_setparam,     /* smart_ant_setparam */
    ath_net80211_smart_ant_getparam,     /* smart_ant_getparam */
#endif
    ath_net80211_get_total_per,                /* get_total_per */
#ifdef ATH_SWRETRY
    ath_net80211_get_pwrsaveq_len,          /* get_pwrsaveq_len */
    ath_net80211_set_tim,                   /* set_tim */
#endif
#if UMAC_SUPPORT_WNM
    ath_net80211_timbcast_alloc,
    ath_net80211_timbcast_update,
    ath_net80211_timbcast_highrate,
    ath_net80211_timbcast_lowrate,
    ath_net80211_timbcast_cansend,
    ath_net80211_timbcast_enabled,
    ath_net80211_wnm_fms_enabled,
#endif
    ath_net80211_get_node_flags,                /* get_node_flags */
#if ATH_SUPPORT_FLOWMAC_MODULE
    ath_net80211_flowmac_notify_state,          /* notify_flowmac_state */
#endif
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
    ath_net80211_buffull_handler,  /* buffull_handler */
    ath_net80211_drop_query_from_sta, /* drop_query_from_sta */
    ath_net80211_get_drop_query_from_sta, /* get_drop_query_from_sta */
    ath_net80211_block_flooding_report, /* block_flooding_report */
    ath_net80211_get_block_flooding_report, /* get_block_flooding_report */
    ath_net80211_ald_update_phy_error_rate,
#endif
#if ATH_SUPPORT_DSCP_OVERRIDE
    ath_net80211_set_dscp_override,         /* set_dscp_override  */
    ath_net80211_get_dscp_override,         /* get_dscp_override  */
    ath_net80211_set_dscp_tid_map,          /* set_dscp_tid_map   */
    ath_net80211_get_dscp_tid_map,          /* get_dscp_tid_map   */
    ath_net80211_reset_dscp_tid_map,        /* reset_dscp_tid_map */
    ath_net80211_set_igmp_dscp_override,    /* set_igmp_dscp_override */
    ath_net80211_get_igmp_dscp_override,    /* get_igmp_dscp_override */
    ath_net80211_set_igmp_dscp_tid_map,     /* set_igmp_dscp_tid_map */
    ath_net80211_get_igmp_dscp_tid_map,     /* get_igmp_dscp_tid_map */
    ath_net80211_set_hmmc_dscp_override,    /* set_hmmc_dscp_override */
    ath_net80211_get_hmmc_dscp_override,    /* get_hmmc_dscp_override */
    ath_net80211_set_hmmc_dscp_tid_map,     /* set_hmmc_dscp_tid_map */
    ath_net80211_get_hmmc_dscp_tid_map,     /* get_hmmc_dscp_tid_map */
#endif
    ath_net80211_dfs_proc_phyerr,               /* dfs_proc_phyerr */
#if ATH_SUPPORT_TIDSTUCK_WAR
    ath_net80211_rxtid_delba,               /* rxtid_delba */
#endif
    ath_net80211_wds_is_enabled,                /* wds_is_enabled */
    ath_net80211_get_macaddr,               /* get_mac_addr */
    ath_net80211_get_vap_bss_mode,              /* get_vap_bss_mode */
    ath_net80211_acs_set_param,               /* set acs_param*/
    ath_net80211_acs_get_param,               /* get acs_param*/
#if ATH_BAND_STEERING
    ath_bsteering_rssi_update,                  /* bsteering_rssi_update */
    ath_bsteering_rate_update,                  /* bsteering_rate_update */
#endif
#if QCA_AIRTIME_FAIRNESS
    ath_net80211_atf_scheduling,                /* atf_scheduling */
    ath_net80211_get_atf_scheduling,            /* get_atf_scheduling */
    ath_net80211_get_atf_allocations,           /* get_atf_allocations */
    ath_net80211_atf_obss_scale,                /* atf_obss_scale */
#endif
    ath_net80211_channel_util,                  /* proc_chan_util */
    ath_net80211_set_enable_min_rssi,            /* set_enable_min_rssi */
    ath_net80211_get_enable_min_rssi,            /* get_enable_min_rssi */
    ath_net80211_set_min_rssi,                   /* set_min_rssi */
    ath_net80211_get_min_rssi,                   /* get_min_rssi */
};

static void
ath_net80211_get_bssid(ieee80211_handle_t ieee,  struct
        ieee80211_frame_min *hdr, u_int8_t *bssid)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ieee80211_node *ni;

    ni = ieee80211_find_rxnode_nolock(ic, hdr);
    if (ni) {
        IEEE80211_ADDR_COPY(bssid, ni->ni_bssid);
        /*
         * find node would increment the ref count, if
         * node is identified make sure that is unrefed again
         */
        ieee80211_unref_node(&ni);
    }
}

void ath_net80211_switch_mode_dynamic2040(ieee80211_handle_t ieee)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    ath_cwm_switch_mode_dynamic2040(ic);
}

void
ath_net80211_switch_mode_static20(ieee80211_handle_t ieee)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    ath_cwm_switch_mode_static20(ic);
}


#ifdef ATH_SUPPORT_DFS
void
ath_net80211_dfs_test_return(ieee80211_handle_t ieee, u_int8_t ieeeChan)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);

    /* Return to the original channel we were on before the test mute */
    DPRINTF(ATH_SOFTC_NET80211(ieee), ATH_DEBUG_ANY,
        "Returning to channel %d\n", ieeeChan);

    ieee80211_start_csa(ic, ieeeChan);
}

/*
 * Signify that the current channel has had a radar event occur.
 */
void
ath_net80211_mark_dfs(ieee80211_handle_t ieee, struct ieee80211_channel *ichan)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_softc *sc = ATH_DEV_TO_SC(scn->sc_dev);

    DPRINTF(ATH_SOFTC_NET80211(ieee), ATH_DEBUG_ANY,
        "%s : Radar found on channel %d (%d MHz)\n",
        __func__, ichan->ic_ieee, ichan->ic_freq);

    /*
     * EV # 106953 - not meeting FCC closing time of 260ms.
     *
     * sc->sc_curchan needs CHANNEL_INTERFERENCE marked so TX can be aborted
     * early, before the channel change occurs.  However, the logic in the
     * Newma and previous drivers was to always set it regardless of whether
     * the reported channel actually is the current channel or not.
     *
     * The lmac/dfs code would set CHANNEL_INTERFERENCE on sc->sc_curchan.
     * This doesn't happen now as the DFS pattern matching code needs to
     * be driver-agnostic.
     *
     * Note that the channel comparison only works if the reported event
     * _always_ matches the HT40 channel (in case of HT40) - if we start
     * reporting HT20 events instead of a HT40 event, it won't work.
     * We have to actually check for channel _overlap_, not channel frequency
     * equality.  But for now, doing the below maintains the existing
     * (broken) semantics found in Newma and earlier drivers.
     *
     * Note: only set CHANNEL_INTERFERENCE if radar detection is being done.
     *
     * XXX TODO: since ieee80211_mark_dfs() is _not_ currently called
     * when usenol=0, the TX abort check will not actually occur here.
     * So we'll fail that particular test case with usenol=0.
     * Be prepared if that ever changes.
     */
    if (dfs_usenol(ic) == 1 || dfs_usenol(ic) == 0)
        sc->sc_curchan.priv_flags |= CHANNEL_INTERFERENCE;

    ieee80211_mark_dfs(ic, ichan);
}
/*
 * Enable DFS after reset by restoring the DFS settings.
 */
void
ath_net80211_enable_radar_dfs(ieee80211_handle_t ieee)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    ic->ic_enable_radar(ic, 1);
}
#endif

void
ath_net80211_change_channel(ieee80211_handle_t ieee, struct ieee80211_channel *chan)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    ic->ic_curchan = chan;
    ic->ic_set_channel(ic);
}

void
wlan_setTxPowerLimit(struct ieee80211com *ic, u_int32_t limit, u_int16_t tpcInDb, u_int32_t is2GHz)
{
    ath_setTxPowerLimit(ic, limit, tpcInDb, is2GHz);
}

void
ath_setTxPowerAdjust(struct ieee80211com *ic, int32_t adjust, u_int32_t is2GHz)
{
	struct ath_softc_net80211    *scn = ATH_SOFTC_NET80211(ic);
	scn->sc_ops->ath_set_txPwrAdjust(scn->sc_dev, adjust, is2GHz);
}

void
ath_setTxPowerLimit(struct ieee80211com *ic, u_int32_t limit, u_int16_t tpcInDb, u_int32_t is2GHz)
{
    struct ath_softc_net80211    *scn = ATH_SOFTC_NET80211(ic);
    /* called by ccx association for setting tx power */
    scn->sc_ops->ath_set_txPwrLimit(scn->sc_dev, limit, tpcInDb, is2GHz);
}

u_int8_t
ath_net80211_get_common_power(struct ieee80211com *ic, struct ieee80211_channel *chan)
{
    struct ath_softc_net80211    *scn = ATH_SOFTC_NET80211(ic);

    return scn->sc_ops->get_common_power(chan->ic_freq);
}

static u_int32_t
ath_net80211_get_maxphyrate(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_node_net80211 *an = (struct ath_node_net80211 *)ni;

    return scn->sc_ops->node_getmaxphyrate(scn->sc_dev, an->an_sta);
}

int
ath_getrmcounters(struct ieee80211com *ic, struct ieee80211_mib_cycle_cnts *pCnts)
{
    struct ath_softc_net80211    *scn = ATH_SOFTC_NET80211(ic);
    HAL_COUNTERS counters;
    int status;
    status = scn->sc_ops->ath_get_mibCycleCounts(scn->sc_dev, &counters);
    if ((pCnts != NULL) && (status == 0)) {
        pCnts->tx_frame_count = counters.tx_frame_count;
        pCnts->rx_frame_count = counters.rx_frame_count;
        pCnts->rx_clear_count = counters.rx_clear_count;
        pCnts->cycle_count = counters.cycle_count;
        pCnts->is_rx_active = counters.is_rx_active;
        pCnts->is_tx_active = counters.is_tx_active;
    }
    return status;
}

#ifdef DBG
u_int32_t
ath_hw_reg_read(struct ieee80211com *ic, u_int32_t reg)
{
    struct ath_softc_net80211    *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->ath_register_read(scn->sc_dev, reg);
}
#endif

void
ath_setReceiveFilter(struct ieee80211com *ic,u_int32_t filter)
{
    struct ath_softc_net80211    *scn = ATH_SOFTC_NET80211(ic);

    scn->sc_ops->ath_set_rxfilter(scn->sc_dev, filter);
}

void
ath_set_rx_sel_plcp_header(struct ieee80211com *ic,
                            int8_t selEvm, int8_t justQuery)
{
    struct ath_softc_net80211    *scn = ATH_SOFTC_NET80211(ic);

    scn->sc_ops->ath_set_sel_evm(scn->sc_dev, selEvm, justQuery);
}


#ifdef ATH_CCX
void
ath_clearrmcounters(struct ieee80211com *ic)
{
    struct ath_softc_net80211    *scn = ATH_SOFTC_NET80211(ic);

    scn->sc_ops->ath_clear_mibCounters(scn->sc_dev);
}

int
ath_updatermcounters(struct ieee80211com *ic, struct ath_mib_mac_stats *pStats)
{
    struct ath_softc_net80211    *scn = ATH_SOFTC_NET80211(ic);

    scn->sc_ops->ath_update_mibMacstats(scn->sc_dev);
    return scn->sc_ops->ath_get_mibMacstats(scn->sc_dev, pStats);
}

u_int8_t
ath_net80211_rcRateValueToPer(struct ieee80211com *ic, struct ieee80211_node *ni, int txRateKbps)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return (scn->sc_ops->rcRateValueToPer(scn->sc_dev, (struct ath_node *)(ATH_NODE_NET80211(ni)->an_sta),
            txRateKbps));
}

u_int64_t
ath_getTSF64(struct ieee80211com *ic)
{
    struct ath_softc_net80211    *scn = ATH_SOFTC_NET80211(ic);

    return scn->sc_ops->ath_get_tsf64(scn->sc_dev);
}

int
ath_getMfgSerNum(struct ieee80211com *ic, u_int8_t *pSrn, int limit)
{
    struct ath_softc_net80211    *scn = ATH_SOFTC_NET80211(ic);

    return scn->sc_ops->ath_get_sernum(scn->sc_dev, pSrn, limit);
}

int
ath_net80211_get_chanData(struct ieee80211com *ic, struct ieee80211_channel *pChan, struct ath_chan_data *pData)
{
    struct ath_softc_net80211    *scn = ATH_SOFTC_NET80211(ic);

    return scn->sc_ops->ath_get_chandata(scn->sc_dev, pChan, pData);

}

u_int32_t
ath_net80211_get_curRSSI(struct ieee80211com *ic)
{
    struct ath_softc_net80211    *scn = ATH_SOFTC_NET80211(ic);

    return scn->sc_ops->ath_get_curRSSI(scn->sc_dev);
}
#endif

#ifdef ATH_SWRETRY
/* Interface function for the IEEE layer to manipulate
 * the software retry state. Used during BMISS and
 * scanning state machine in IEEE layer
 */
void
ath_net80211_set_swretrystate(struct ieee80211_node *ni, int flag)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    ath_node_t node = ATH_NODE_NET80211(ni)->an_sta;

    scn->sc_ops->set_swretrystate(scn->sc_dev, node, flag);
    DPRINTF(scn, ATH_DEBUG_SWR, "%s: swr %s for ni %s\n", __func__, flag?"enable":"disable", ether_sprintf(ni->ni_macaddr));
}

/* Interface function for the IEEE layer to schedule one single
 * frame in LMAC upon PS-Poll frame
 */
int
ath_net80211_handle_pspoll(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    ath_node_t node = ATH_NODE_NET80211(ni)->an_sta;

    return scn->sc_ops->ath_handle_pspoll(scn->sc_dev, node);
}

/* Check whether there is pending frame in LMAC tid Q */
int
ath_net80211_exist_pendingfrm_tidq(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    ath_node_t node = ATH_NODE_NET80211(ni)->an_sta;

    return scn->sc_ops->get_exist_pendingfrm_tidq(scn->sc_dev, node);
}

int
ath_net80211_reset_pasued_tid(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    ath_node_t node = ATH_NODE_NET80211(ni)->an_sta;

    return scn->sc_ops->reset_paused_tid(scn->sc_dev, node);
}

#endif

#if ATH_SUPPORT_IQUE
void
ath_net80211_set_acparams(struct ieee80211com *ic, u_int8_t ac, u_int8_t use_rts,
                          u_int8_t aggrsize_scaling, u_int32_t min_kbps)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    scn->sc_ops->ath_set_acparams(scn->sc_dev, ac, use_rts, aggrsize_scaling, min_kbps);
}

void
ath_net80211_set_rtparams(struct ieee80211com *ic, u_int8_t ac, u_int8_t perThresh,
                          u_int8_t probeInterval)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    scn->sc_ops->ath_set_rtparams(scn->sc_dev, ac, perThresh, probeInterval);
}

void
ath_net80211_get_iqueconfig(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    scn->sc_ops->ath_get_iqueconfig(scn->sc_dev);
}

void
ath_net80211_set_hbrparams(struct ieee80211vap *iv, u_int8_t ac, u_int8_t enable, u_int8_t per)
{
	struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(iv->iv_ic);

	scn->sc_ops->ath_set_hbrparams(scn->sc_dev, ac, enable, per);
	/* Send ACTIVE signal to all nodes. Otherwise, if the hbr_enable is turned off when
	 * one state machine is in BLOCKING or PROBING state, the ratecontrol module
	 * will never send ACTIVE signals after hbr_enable is turned off, therefore
	 * the state machine will stay in the PROBING state forever
	 */
	/* TODO ieee80211_hbr_setstate_all(iv, HBR_SIGNAL_ACTIVE); */
}
#endif /*ATH_SUPPORT_IQUE*/


static u_int32_t ath_net80211_get_goodput(struct ieee80211_node *ni)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_node_net80211 *an = (struct ath_node_net80211 *)ni;

    if (scn->sc_ops->ath_get_goodput)
	    return (scn->sc_ops->ath_get_goodput(scn->sc_dev, an->an_sta))/100;
    return 0;
}

#ifdef ATH_USB
u_int32_t
ath_get_targetTSF32(struct ieee80211com *ic)
{
    struct ath_softc_net80211    *scn = ATH_SOFTC_NET80211(ic);
    struct ath_softc *sc = ATH_DEV_TO_SC(scn->sc_dev);

    return sc->curr_tsf;
}
#endif

u_int32_t
ath_getTSF32(struct ieee80211com *ic)
{
    struct ath_softc_net80211    *scn = ATH_SOFTC_NET80211(ic);

    return scn->sc_ops->ath_get_tsf32(scn->sc_dev);
}
#if !ATH_SUPPORT_STATS_APONLY
static void
ath_update_phystats(struct ieee80211com *ic, enum ieee80211_phymode mode)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    WIRELESS_MODE wmode;
    struct ath_phy_stats *ath_phystats;
    struct ieee80211_phy_stats *phy_stats;

    wmode = ath_ieee2wmode(mode);
    if (wmode == WIRELESS_MODE_MAX) {
        ASSERT(0);
        return;
    }

    /* get corresponding IEEE PHY stats array */
    phy_stats = &ic->ic_phy_stats[mode];

    /* get ath_dev PHY stats array */
    ath_phystats = scn->sc_ops->get_phy_stats(scn->sc_dev, wmode);

    /* update interested counters */
    phy_stats->ips_rx_fifoerr += ath_phystats->ast_rx_fifoerr;
    phy_stats->ips_rx_decrypterr += ath_phystats->ast_rx_decrypterr;
    phy_stats->ips_rx_crcerr += ath_phystats->ast_rx_crcerr;
    phy_stats->ips_tx_rts += ath_phystats->ast_tx_rts;
    phy_stats->ips_tx_longretry += ath_phystats->ast_tx_longretry;
}
#endif
static void
ath_clear_phystats(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->clear_stats(scn->sc_dev);
}

static int
ath_net80211_set_macaddr(struct ieee80211com *ic, u_int8_t *macaddr)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->set_macaddr(scn->sc_dev, macaddr);
    return 0;
}

static int
ath_net80211_set_chain_mask(struct ieee80211com *ic, ieee80211_device_param type, u_int32_t mask)
{
    u_int32_t curmask;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    switch(type) {
    case IEEE80211_DEVICE_TX_CHAIN_MASK:
        curmask=scn->sc_ops->have_capability(scn->sc_dev, ATH_CAP_TXCHAINMASK);
        if (mask != curmask) {
           scn->sc_ops->set_tx_chainmask(scn->sc_dev, mask);
        }
        break;
    case IEEE80211_DEVICE_RX_CHAIN_MASK:
        curmask=scn->sc_ops->have_capability(scn->sc_dev, ATH_CAP_RXCHAINMASK);
        if (mask != curmask) {
           scn->sc_ops->set_rx_chainmask(scn->sc_dev, mask);
        }
        break;
        /* always set the legacy chainmasks to avoid inconsistency between sc_config
         * and sc_tx/rx_chainmask
         */
    case IEEE80211_DEVICE_TX_CHAIN_MASK_LEGACY:
        scn->sc_ops->set_tx_chainmasklegacy(scn->sc_dev, mask);
        break;
    case IEEE80211_DEVICE_RX_CHAIN_MASK_LEGACY:
        scn->sc_ops->set_rx_chainmasklegacy(scn->sc_dev, mask);
        break;
    default:
        break;
    }
    return 0;
}

/*
 * Get the number of spatial streams supported, and set it
 * in the protocol layer.
 */
static void
ath_set_spatialstream(struct ath_softc_net80211 *scn)
{
    u_int8_t    stream;

    if (scn->sc_ops->have_capability(scn->sc_dev, ATH_CAP_DS)) {
        if (scn->sc_ops->have_capability(scn->sc_dev, ATH_CAP_TS))
            stream = 3;
        else
            stream = 2;
    } else {
        stream = 1;
    }

    ieee80211com_set_spatialstreams(&scn->sc_ic, stream);
}

#ifdef ATH_SUPPORT_TxBF
static int
ath_set_txbfcapability(struct ieee80211com *ic)
{
    struct ath_softc_net80211    *scn = ATH_SOFTC_NET80211(ic);
    ieee80211_txbf_caps_t *txbf_cap;
    int error;

    error = scn->sc_ops->get_txbf_caps(scn->sc_dev, &txbf_cap);

    if (AH_FALSE == error)
        return error;

    ic->ic_txbf.channel_estimation_cap    = txbf_cap->channel_estimation_cap;
    ic->ic_txbf.csi_max_rows_bfer         = txbf_cap->csi_max_rows_bfer;
    ic->ic_txbf.comp_bfer_antennas        = txbf_cap->comp_bfer_antennas;
    ic->ic_txbf.noncomp_bfer_antennas     = txbf_cap->noncomp_bfer_antennas;
    ic->ic_txbf.csi_bfer_antennas         = txbf_cap->csi_bfer_antennas;
    ic->ic_txbf.minimal_grouping          = txbf_cap->minimal_grouping;
    ic->ic_txbf.explicit_comp_bf          = txbf_cap->explicit_comp_bf;
    ic->ic_txbf.explicit_noncomp_bf       = txbf_cap->explicit_noncomp_bf;
    ic->ic_txbf.explicit_csi_feedback     = txbf_cap->explicit_csi_feedback;
    ic->ic_txbf.explicit_comp_steering    = txbf_cap->explicit_comp_steering;
    ic->ic_txbf.explicit_noncomp_steering = txbf_cap->explicit_noncomp_steering;
    ic->ic_txbf.explicit_csi_txbf_capable = txbf_cap->explicit_csi_txbf_capable;
    ic->ic_txbf.calibration               = txbf_cap->calibration;
    ic->ic_txbf.implicit_txbf_capable     = txbf_cap->implicit_txbf_capable;
    ic->ic_txbf.tx_ndp_capable            = txbf_cap->tx_ndp_capable;
    ic->ic_txbf.rx_ndp_capable            = txbf_cap->rx_ndp_capable;
    ic->ic_txbf.tx_staggered_sounding     = txbf_cap->tx_staggered_sounding;
    ic->ic_txbf.rx_staggered_sounding     = txbf_cap->rx_staggered_sounding;
    ic->ic_txbf.implicit_rx_capable       = txbf_cap->implicit_rx_capable;

    return 0;
}
#endif

static int
ath_node_add_wds_entry(struct ieee80211com *ic, const u_int8_t *dest_mac,
                       u_int8_t *peer_mac, u_int32_t flags)
{
    /* Stub for direct attach solutions. Do nothing */
    return 0;
}

static int
ath_vap_sifs_trigger(struct ieee80211vap *vap, u_int32_t val)
{
    /* Stub for DA. Do nothing */
    return 0;
}

static void
ath_node_del_wds_entry(struct ieee80211com *ic, u_int8_t *dest_mac, u_int32_t flags)
{
    /* Stub for direct attach solutions. Do nothing */
    return;
}

#if ATH_SUPPORT_HYFI_ENHANCEMENTS
static int
ath_node_update_wds_entry(struct ieee80211com *ic, u_int8_t *wds_macaddr, u_int8_t *peer_macaddr, u_int32_t flags)
{
    /* Stub for direct attach solutions. Do nothing */
    return EOK; /* Same API is defined for OL layer so returning success */
}

static int
ath_node_dump_wds_table(struct ieee80211com *ic){

    /* Stub for direct attach solutions. Do nothing */
    return EOK; /* Same API is defined for OL layer so returning success */
}

static int
ath_node_use_4addr(struct ieee80211_node *ni)
{
    /* Stub for direct attach solutions. Do nothing */
    return EOK; /* Same API is defined for OL layer so returning success */
}

#endif

#if QCA_AIRTIME_FAIRNESS
static void ath_net80211_atf_get_unused_txtoken( struct ieee80211com *ic,struct ieee80211_node *ni, int *unused_token)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_node *an;

    an = (struct ath_node *)((ATH_NODE_NET80211(ni))->an_sta);
    scn->sc_ops->ath_atf_get_unused_txtoken(an, unused_token);
}

static void ath_net80211_atf_update_node_txtoken( struct ieee80211com *ic,struct ieee80211_node *ni, struct atf_stats *stats)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_node *an;

    an = (struct ath_node *)((ATH_NODE_NET80211(ni))->an_sta);
    scn->sc_ops->ath_atf_update_node_txtoken(an, ni->tx_tokens, stats);
}

static void ath_net80211_atf_tokens_unassigned( struct ieee80211com *ic, u_int32_t tokens_unassigned)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->ath_atf_tokens_unassigned(scn->sc_dev, tokens_unassigned);
}

static void ath_net80211_atf_set_clear( struct ieee80211com *ic, u_int8_t enable_disable)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->ath_atf_set_clear(scn->sc_dev, enable_disable);
}

static u_int32_t ath_net80211_atf_debug_nodestate(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    struct ath_node *an;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    an = (struct ath_node *)((ATH_NODE_NET80211(ni))->an_sta);
    return scn->sc_ops->ath_atf_debug_nodestate(an);
}

static u_int8_t ath_net80211_atf_tokens_used(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    struct ath_node *an;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    an = (struct ath_node *)((ATH_NODE_NET80211(ni))->an_sta);
    return scn->sc_ops->ath_atf_tokens_used(an);
}

static void ath_net80211_atf_node_resume(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    struct ath_node *an;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    an = (struct ath_node *)((ATH_NODE_NET80211(ni))->an_sta);
    scn->sc_ops->ath_atf_node_resume(an);
}

static u_int32_t ath_net80211_node_buf_held(struct ieee80211_node *ni)
{
    struct ath_node *an;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ni->ni_ic);

    an = (struct ath_node *)((ATH_NODE_NET80211(ni))->an_sta);
    return scn->sc_ops->ath_node_buf_held(an);
}

static void ath_net80211_atf_capable_node( struct ieee80211com *ic, struct ieee80211_node *ni, u_int8_t val, u_int8_t atfstate_change)
{
    struct ath_node *an;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    an = (struct ath_node *)((ATH_NODE_NET80211(ni))->an_sta);
    scn->sc_ops->ath_atf_capable_node(an, val, atfstate_change);
}

static u_int32_t ath_net80211_atf_airtime_estimate(struct ieee80211com *ic,
                                  struct ieee80211_node *ni, u_int32_t tput, u_int32_t *possible_tput)
{
    struct ath_node *an;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    an = (struct ath_node *)((ATH_NODE_NET80211(ni))->an_sta);
    return scn->sc_ops->ath_atf_airtime_estimate(scn->sc_dev, an, tput, possible_tput);
}
#endif

static void ath_net80211_green_ap_set_enable( struct ieee80211com *ic, int val )
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->ath_green_ap_dev_set_enable(scn->sc_dev, val);
}

static int ath_net80211_green_ap_get_enable( struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->ath_green_ap_dev_get_enable(scn->sc_dev);
}


static void ath_net80211_green_ap_set_transition_time( struct ieee80211com *ic, int val )
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->ath_green_ap_dev_set_transition_time(scn->sc_dev, val);
}

static int ath_net80211_green_ap_get_transition_time( struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->ath_green_ap_dev_get_transition_time(scn->sc_dev);
}

static void ath_net80211_green_ap_set_on_time( struct ieee80211com *ic, int val )
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->ath_green_ap_dev_set_on_time(scn->sc_dev, val);
}

static void ath_net80211_green_ap_set_enable_print(struct ieee80211com* ic, int val)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->ath_green_ap_dev_set_enable_print(scn->sc_dev, val);
}


static int ath_net80211_green_ap_get_on_time( struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->ath_green_ap_dev_get_on_time(scn->sc_dev);
}

static int ath_net80211_green_ap_get_enable_print(struct ieee80211com* ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->ath_green_ap_dev_get_enable_print(scn->sc_dev);
}

static int16_t ath_net80211_get_cur_chan_noisefloor(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->ath_dev_get_noisefloor(scn->sc_dev);
}

static void
ath_net80211_get_cur_chan_stats(struct ieee80211com *ic, struct ieee80211_chan_stats *chan_stats)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->ath_dev_get_chan_stats(scn->sc_dev, (void *) chan_stats );
}


/*
 * Read NF and channel load registers and invoke ACS update API
 */
static void ath_net80211_get_chan_info(struct ieee80211com *ic, u_int8_t flags)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    u_int ieee_chan_num;
    struct ieee80211_chan_stats chan_stats;
    int16_t acs_noisefloor = 0;

    ieee_chan_num = ieee80211_chan2ieee(ic, ic->ic_curchan);

#if UMAC_SUPPORT_ACS
    if (flags == ACS_CHAN_STATS_NF) {
       acs_noisefloor = scn->sc_ops->ath_dev_get_noisefloor(scn->sc_dev);
    }
#else
    UNREFERENCED_PARAMETER(acs_noisefloor);
#endif
    scn->sc_ops->ath_dev_get_chan_stats(scn->sc_dev, (void *) &chan_stats );
    chan_stats.chan_tx_power_tput = 0;
    chan_stats.chan_tx_power_range = 0;
    ieee80211_acs_stats_update(ic->ic_acs, flags, ieee_chan_num,
                                    acs_noisefloor, &chan_stats);
}

static u_int32_t
ath_net80211_wpsPushButton(struct ieee80211com *ic)
{
    struct ath_softc_net80211  *scn = ATH_SOFTC_NET80211(ic);
    struct ath_ops             *ops = scn->sc_ops;

    return (ops->have_capability(scn->sc_dev, ATH_CAP_WPS_BUTTON));
}


static struct ieee80211_tsf_timer *
ath_net80211_tsf_timer_alloc(struct ieee80211com *ic,
                            tsftimer_clk_id tsf_id,
                            ieee80211_tsf_timer_function trigger_action,
                            ieee80211_tsf_timer_function overflow_action,
                            ieee80211_tsf_timer_function outofrange_action,
                            void *arg)
{
#ifdef ATH_GEN_TIMER
    struct ath_softc_net80211   *scn = ATH_SOFTC_NET80211(ic);
    struct ath_gen_timer        *ath_timer;

    /* Note: If there is a undefined field, ath_tsf_timer_alloc, during compile, it is because ATH_GEN_TIMER undefined. */
    ath_timer = scn->sc_ops->ath_tsf_timer_alloc(scn->sc_dev, tsf_id,
                                                 ATH_TSF_TIMER_FUNC(trigger_action),
                                                 ATH_TSF_TIMER_FUNC(overflow_action),
                                                 ATH_TSF_TIMER_FUNC(outofrange_action),
                                                 arg);
    return NET80211_TSF_TIMER(ath_timer);
#else
    return NULL;

#endif
}

static void
ath_net80211_tsf_timer_free(struct ieee80211com *ic, struct ieee80211_tsf_timer *timer)
{
#ifdef ATH_GEN_TIMER
    struct ath_softc_net80211   *scn = ATH_SOFTC_NET80211(ic);
    struct ath_gen_timer        *ath_timer = ATH_TSF_TIMER(timer);

    scn->sc_ops->ath_tsf_timer_free(scn->sc_dev, ath_timer);
#endif
}

static void
ath_net80211_tsf_timer_start(struct ieee80211com *ic, struct ieee80211_tsf_timer *timer,
                            u_int32_t timer_next, u_int32_t period)
{
#ifdef ATH_GEN_TIMER
    struct ath_softc_net80211   *scn = ATH_SOFTC_NET80211(ic);
    struct ath_gen_timer        *ath_timer = ATH_TSF_TIMER(timer);

    scn->sc_ops->ath_tsf_timer_start(scn->sc_dev, ath_timer, timer_next, period);
#endif
}

static void
ath_net80211_tsf_timer_stop(struct ieee80211com *ic, struct ieee80211_tsf_timer *timer)
{
#ifdef ATH_GEN_TIMER
    struct ath_softc_net80211   *scn = ATH_SOFTC_NET80211(ic);
    struct ath_gen_timer        *ath_timer = ATH_TSF_TIMER(timer);

    scn->sc_ops->ath_tsf_timer_stop(scn->sc_dev, ath_timer);
#endif
}


#if UMAC_SUPPORT_P2P
static int
ath_net80211_reg_notify_tx_bcn(struct ieee80211com *ic,
                               ieee80211_tx_bcn_notify_func callback,
                               void *arg)
{
    struct ath_softc_net80211   *scn = ATH_SOFTC_NET80211(ic);
    int                         retval = 0;

    /* Note: if you get compile error for undeclared ath_reg_notify_tx_bcn, then it is because
       the ATH_SUPPORT_P2P compile flag is not enabled. */
    retval = scn->sc_ops->ath_reg_notify_tx_bcn(scn->sc_dev,
                                            ATH_BCN_NOTIFY_FUNC(callback), arg);
    return retval;
}

static int
ath_net80211_dereg_notify_tx_bcn(struct ieee80211com *ic)
{
    struct ath_softc_net80211   *scn = ATH_SOFTC_NET80211(ic);
    int                         retval = 0;

    retval = scn->sc_ops->ath_dereg_notify_tx_bcn(scn->sc_dev);
    return retval;
}
#endif  //UMAC_SUPPORT_P2P

static int
ath_net80211_reg_vap_info_notify(
    struct ieee80211vap                 *vap,
    ath_vap_infotype                    infotype_mask,
    ieee80211_vap_ath_info_notify_func  callback,
    void                                *arg)
{
    struct ath_softc_net80211   *scn = ATH_SOFTC_NET80211(vap->iv_ic);
    int                         retval = 0;

    /*
     * Note: if you get compile error for undeclared ath_reg_vap_info_notify,
     * then it is because the ATH_SUPPORT_P2P compile flag is not enabled.
     */
    retval = scn->sc_ops->ath_reg_notify_vap_info(scn->sc_dev,
                                            vap->iv_unit,
                                            infotype_mask,
                                            ATH_VAP_NOTIFY_FUNC(callback), arg);
    return retval;
}

static int
ath_net80211_vap_info_update_notify(
    struct ieee80211vap                 *vap,
    ath_vap_infotype                    infotype_mask)
{
    struct ath_softc_net80211   *scn = ATH_SOFTC_NET80211(vap->iv_ic);
    int                         retval = 0;

    /*
     * Note: if you get compile error for undeclared ath_vap_info_update_notify,
     * then it is because the ATH_SUPPORT_P2P compile flag is not enabled.
     */
    retval = scn->sc_ops->ath_vap_info_update_notify(scn->sc_dev,
                                            vap->iv_unit,
                                            infotype_mask);
    return retval;
}

static int
ath_net80211_dereg_vap_info_notify(
    struct ieee80211vap                 *vap)
{
    struct ath_softc_net80211   *scn = ATH_SOFTC_NET80211(vap->iv_ic);
    int                         retval = 0;

    retval = scn->sc_ops->ath_dereg_notify_vap_info(scn->sc_dev, vap->iv_unit);
    return retval;
}

static int
ath_net80211_vap_info_get(
    struct ieee80211vap *vap,
    ath_vap_infotype    infotype,
    u_int32_t           *param1,
    u_int32_t           *param2)
{
    struct ath_softc_net80211   *scn = ATH_SOFTC_NET80211(vap->iv_ic);
    int                         retval = 0;

    retval = scn->sc_ops->ath_vap_info_get(scn->sc_dev, vap->iv_unit,
                                           infotype, param1, param2);
    return retval;
}

#ifdef ATH_BT_COEX
static int
ath_get_bt_coex_info(struct ieee80211com *ic, u_int32_t infoType)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->bt_coex_get_info(scn->sc_dev, infoType, NULL);
}
#endif

#if ATH_SLOW_ANT_DIV
static void
ath_net80211_antenna_diversity_suspend(struct ieee80211com *ic)
{
    struct ath_softc_net80211    *scn = ATH_SOFTC_NET80211(ic);

    scn->sc_ops->ath_antenna_diversity_suspend(scn->sc_dev);
}

static void
ath_net80211_antenna_diversity_resume(struct ieee80211com *ic)
{
    struct ath_softc_net80211    *scn = ATH_SOFTC_NET80211(ic);

    scn->sc_ops->ath_antenna_diversity_resume(scn->sc_dev);
}
#endif

u_int32_t
ath_net80211_getmfpsupport(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return(scn->sc_ops->ath_get_mfpsupport(scn->sc_dev));
}

static void
ath_net80211_setmfpQos(struct ieee80211com *ic, u_int32_t dot11w)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->ath_set_hw_mfp_qos(scn->sc_dev, dot11w);
}
void
ath_net80211_unref_node(struct ieee80211_node *ni)
{
            ieee80211_unref_node(&ni);
}
void ath_net80211_reset_stats(struct ieee80211_node *ni)
{
	/* Stub code for DA */
}
void ath_net80211_collect_stats(struct ieee80211_node *ni)
{
	/* Stub code for DA */
}

static bool
ath_net80211_is_mode_offload(struct ieee80211com *ic)
{
    /*
     * If this function is called, this is in direct attach mode
     */
    return FALSE;
}

static bool
ath_net80211_is_macreq_enabled(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    return ((scn->macreq_enabled == 1) ? TRUE : FALSE);
}

static u_int32_t
ath_net80211_get_mac_prealloc_idmask(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    return scn->sc_prealloc_idmask;
}

#if ATH_BAND_STEERING
static bool
ath_net80211_bs_set_params(struct ieee80211com *ic,
                           ieee80211_bsteering_lmac_param_t *params)
{
    return wlan_bsteering_set_inact_params(ic,
                                           params->inactivity_check_period,
                                           params->inactivity_threshold_normal,
                                           params->inactivity_threshold_overload);
}

static bool
ath_net80211_bs_enable(struct ieee80211com *ic, bool enable)
{
    return wlan_bsteering_direct_attach_enable(ic,enable);
}

static void
ath_net80211_bs_set_overload(struct ieee80211com *ic, bool overload)
{
    wlan_bsteering_set_overload_param(ic,overload);
    return;
}
static int32_t
ath_net80211_bsteering_send_rssi(struct ieee80211com *ic,
                u_int8_t *macaddr, struct ieee80211vap *vap)
{
    wlan_bsteering_send_null(ic,macaddr,vap);
    return EOK;
}

static bool
ath_net80211_bsteering_node_is_inact(struct ieee80211_node *ni)
{
    return ni->ni_bs_inact_flag;;
}
#endif /* ATH_BAND_STEERING */

int
ath_attach(u_int16_t devid, void *base_addr,
           struct ath_softc_net80211 *scn,
           osdev_t osdev, struct ath_reg_parm *ath_conf_parm,
           struct hal_reg_parm *hal_conf_parm, IEEE80211_REG_PARAMETERS *ieee80211_conf_parm)
{
    ath_dev_t               dev;
    struct ath_ops          *ops;
    struct ieee80211com     *ic;
    int                     error;
    int                     weptkipaggr_rxdelim = 0;
    int                     channel_switching_time_usec = 4000;
    int                     ldpccap;
    u_int16_t               ciphercap = 0;
#if QCA_AIRTIME_FAIRNESS || DBDC_REPEATER_SUPPORT
    int                     i;
#endif
#if DBDC_REPEATER_SUPPORT
    int j,k;
    struct ieee80211com     *tmp_ic;
#endif

    asf_adf_attach();

    /*
     * Also allocate our own dedicated asf_amem instance.
     * For now, this dedicated amem instance will be used by the
     * HAL's ath_hal_malloc.
     * Later this dedicated amem instance will be used throughout
     * the driver, rather than using the shared asf_amem instance.
     *
     * The platform-specific code that calls this ath_attach function
     * may have already set up an amem instance, if it had to do
     * memory allocation before calling ath_attach.  So, check if
     * scn->amem.handle is initialized already - if not, set it up here.
     */
    if (!scn->amem.handle) {
        qdf_spinlock_create(&scn->amem.lock);
        scn->amem.handle = asf_amem_create(
            NULL, /* name */
            0,  /* no limit on allocations */
            (asf_amem_alloc_fp) qdf_mem_alloc_outline,
            (asf_amem_free_fp) qdf_mem_free_outline,
            (void *) osdev,
            (asf_amem_lock_fp) qdf_spin_lock_bh_outline,
            (asf_amem_unlock_fp) qdf_spin_unlock_bh_outline,
            (void *) &scn->amem.lock,
            NULL /* use qdf_mem_alloc_outline + osdev to alloc this amem object */);
        if (!scn->amem.handle) {
            qdf_spinlock_destroy(&scn->amem.lock);
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,  "%s[%d]: Allocation of memory handle failed!\n", __func__, __LINE__ );
            return -ENOMEM;
        }
    }

    scn->sc_osdev = osdev;
#if UMAC_SUPPORT_P2P
    if (!ieee80211_conf_parm->noP2PDevMacPrealloc) {
        scn->sc_prealloc_idmask = (1 << ATH_P2PDEV_IF_ID);
    }
#endif
    ic = &scn->sc_ic;
    ic->ic_osdev = osdev;
#ifdef ATH_EXT_AP
    ic->ic_miroot = NULL;
#endif

    ic->recovery_in_progress = 0;
    ic->interface_id = ath_get_radio_index(osdev->netdev);

    /* init IEEE80211_DPRINTF_IC control object */
    ieee80211_dprintf_ic_init(ic);

    spin_lock_init(&ic->ic_lock);
    spin_lock_init(&ic->ic_main_sta_lock);
    spin_lock_init(&ic->ic_addba_lock);
    IEEE80211_STATE_LOCK_INIT(ic);
    spin_lock_init(&ic->ic_beacon_alloc_lock);
    spin_lock_init(&ic->ic_state_check_lock);
#ifndef REMOVE_PKT_LOG
    if(enable_pktlog_support) {
        //pktlog_set_pl_dev(&scn->pl_dev);
        /*
         * Change the argument from NULL of qdf_os_dev_t
         * pl_dev should be allocated before the dev_attach
         * dev_attach calls pktlog_attach that uses pl_dev
         */
        scn->pl_dev = (struct pktlog_handle_t *)
                        qdf_mem_alloc_outline(NULL,
                        sizeof(struct pktlog_handle_t));
        if (!scn->pl_dev) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,  "%s[%d]: Allocation of memory handle failed!\n", __func__, __LINE__ );
            return -ENOMEM;
        }
        scn->pl_dev->pl_funcs = NULL;
        //ath_pktlog_get_dev_name(scn->sc_osdev, &(scn->pl_dev->name));
        scn->pl_dev->scn = (ath_generic_softc_handle) scn;
        //((struct ath_softc *)(scn->sc_dev))->pl_dev = scn->pl_dev;
    }
#endif
    osif_register_dev_ops_xmit(osif_vap_hardstart, OSIF_NETDEV_TYPE_DA);
    /*
     * Create an Atheros Device object
     */
    error = ath_dev_attach(devid, base_addr,
                           ic, &net80211_ops, osdev,
                           &scn->sc_dev, &scn->sc_ops,
                           scn->amem.handle,
                           ath_conf_parm, hal_conf_parm);

    if (error != 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,  "%s[%d]: Device attach failed!, error[%d]\n", __func__, __LINE__, error );
        spin_lock_destroy(&ic->ic_lock);
        spin_lock_destroy(&ic->ic_main_sta_lock);
        spin_lock_destroy(&ic->ic_addba_lock);
        IEEE80211_STATE_LOCK_DESTROY(ic);
        if(scn->pl_dev) {
            qdf_mem_free(scn->pl_dev);
            scn->pl_dev = NULL;
        }
        ieee80211_dprintf_ic_deregister(ic);
        qdf_spinlock_destroy(&scn->amem.lock);
        asf_amem_destroy(scn->amem.handle, NULL);
        scn->amem.handle = NULL;
        return error;
    }

    dev = scn->sc_dev;
    ops = scn->sc_ops;

    ic->ic_qdf_dev = scn->qdf_dev;
    /* attach channel width management */
    error = ath_cwm_attach(scn, ath_conf_parm);
    if (error) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,  "%s[%d]: CWM attach failed!, error[%d]\n", __func__, __LINE__, error );
        ath_dev_free(dev);
        return error;
    }

#ifdef ATH_AMSDU
    /* attach amsdu transmit handler */
    ath_amsdu_attach(scn);
#endif

    /* setup ieee80211 flags */
    ieee80211com_clear_cap(ic, -1);
    ieee80211com_clear_athcap(ic, -1);
    ieee80211com_clear_athextcap(ic, -1);
    ieee80211com_clear_ciphercap(ic, -1);

    /* XXX not right but it's not used anywhere important */
    ieee80211com_set_phytype(ic, IEEE80211_T_OFDM);

    ciphercap = ( (1 << IEEE80211_CIPHER_WEP) |
                  (1 << IEEE80211_CIPHER_TKIP) |
                  (1 << IEEE80211_CIPHER_AES_OCB) |
                  (1 << IEEE80211_CIPHER_AES_CCM) |
                  (1 << IEEE80211_CIPHER_WAPI) |
                  (1 << IEEE80211_CIPHER_CKIP) |
                  (1 << IEEE80211_CIPHER_AES_CMAC) |
                  (1 << IEEE80211_CIPHER_NONE)
             );
    ieee80211com_set_ciphercap(ic, ciphercap);
    /*
     * Set the Atheros Advanced Capabilities from station config before
     * starting 802.11 state machine.
     */
    ieee80211com_set_athcap(ic, (ops->have_capability(dev, ATH_CAP_BURST) ? IEEE80211_ATHC_BURST : 0));

    /* Set Atheros Extended Capabilities */
    ieee80211com_set_athextcap(ic,
        ((ops->have_capability(dev, ATH_CAP_HT) &&
          !ops->have_capability(dev, ATH_CAP_4ADDR_AGGR))
         ? IEEE80211_ATHEC_OWLWDSWAR : 0));
    ieee80211com_set_athextcap(ic,
        ((ops->have_capability(dev, ATH_CAP_HT) &&
          ops->have_capability(dev, ATH_CAP_WEP_TKIP_AGGR) &&
          ieee80211_conf_parm->htEnableWepTkip)
         ? IEEE80211_ATHEC_WEPTKIPAGGR : 0));

    /* set ic caps to require badba workaround */
    ieee80211com_set_athextcap(ic,
            (ops->have_capability(dev, ATH_CAP_EXTRADELIMWAR) &&
            ieee80211_conf_parm->htEnableWepTkip)
            ? IEEE80211_ATHEC_EXTRADELIMWAR: 0);

    /* set ic caps to require PC check WAR */
    ieee80211com_set_athextcap(ic,(ops->have_capability(dev, ATH_CAP_PN_CHECK_WAR)) ? IEEE80211_ATHEC_PN_CHECK_WAR: 0);

    if(ieee80211_conf_parm->shortPreamble)
		ieee80211com_set_cap(ic,IEEE80211_C_SHPREAMBLE);
    ieee80211com_set_cap(ic,
                         IEEE80211_C_IBSS           /* ibss, nee adhoc, mode */
                         | IEEE80211_C_HOSTAP       /* hostap mode */
                         | IEEE80211_C_MONITOR      /* monitor mode */
                         | IEEE80211_C_SHSLOT       /* short slot time supported */
                         | IEEE80211_C_PMGT         /* capable of power management*/
                         | IEEE80211_C_WPA          /* capable of WPA1+WPA2 */
                         | IEEE80211_C_BGSCAN       /* capable of bg scanning */
        );

    /*
     * WMM enable
     */
    if (ops->have_capability(dev, ATH_CAP_WMM))
        ieee80211com_set_cap(ic, IEEE80211_C_WME);

    /* set up WMM AC to h/w qnum mapping */
    scn->sc_ac2q[WME_AC_BE] = ops->tx_get_qnum(dev, HAL_TX_QUEUE_DATA, HAL_WME_AC_BE);
    scn->sc_ac2q[WME_AC_BK] = ops->tx_get_qnum(dev, HAL_TX_QUEUE_DATA, HAL_WME_AC_BK);
    scn->sc_ac2q[WME_AC_VI] = ops->tx_get_qnum(dev, HAL_TX_QUEUE_DATA, HAL_WME_AC_VI);
    scn->sc_ac2q[WME_AC_VO] = ops->tx_get_qnum(dev, HAL_TX_QUEUE_DATA, HAL_WME_AC_VO);
    scn->sc_beacon_qnum = ops->tx_get_qnum(dev, HAL_TX_QUEUE_BEACON, 0);
#if ATH_SUPPORT_WIFIPOS
    scn->sc_wifipos_oc_qnum = ops->tx_get_qnum(dev, HAL_TX_QUEUE_WIFIPOS_OC, 0);
    scn->sc_wifipos_hc_qnum = ops->tx_get_qnum(dev, HAL_TX_QUEUE_WIFIPOS_HC, 0);
#endif

    ath_uapsd_attach(scn);

    /*
     * Query the hardware to figure out h/w crypto support.
     */
    if (ops->has_cipher(dev, HAL_CIPHER_WEP))
        ieee80211com_set_cap(ic, IEEE80211_C_WEP);
    if (ops->has_cipher(dev, HAL_CIPHER_AES_OCB))
        ieee80211com_set_cap(ic, IEEE80211_C_AES);
    if (ops->has_cipher(dev, HAL_CIPHER_AES_CCM))
        ieee80211com_set_cap(ic, IEEE80211_C_AES_CCM);
    if (ops->has_cipher(dev, HAL_CIPHER_CKIP))
        ieee80211com_set_cap(ic, IEEE80211_C_CKIP);
    if (ops->has_cipher(dev, HAL_CIPHER_TKIP)) {
        ieee80211com_set_cap(ic, IEEE80211_C_TKIP);
#if ATH_SUPPORT_WAPI
    if (ops->has_cipher(dev, HAL_CIPHER_WAPI)){
        ieee80211com_set_cap(ic, IEEE80211_C_WAPI);
    }
#endif
#if UNIFIED_SMARTANTENNA
    scn->enable_smart_antenna_da = enable_smart_antenna_da;
#endif
#if ATH_SUPPORT_WRAP
    if (ops->have_capability(dev, ATH_CAP_PROXYSTARXWAR)){
       ic->ic_proxystarxwar = 1;
    }
#endif
        /* Check if h/w does the MIC. */
        if (ops->has_cipher(dev, HAL_CIPHER_MIC)) {
            ieee80211com_set_cap(ic, IEEE80211_C_TKIPMIC);
            /*
             * Check if h/w does MIC correctly when
             * WMM is turned on.  If not, then disallow WMM.
             */
            if (ops->have_capability(dev, ATH_CAP_TKIP_WMEMIC)) {
                ieee80211com_set_cap(ic, IEEE80211_C_WME_TKIPMIC);
            } else {
                ieee80211com_clear_cap(ic, IEEE80211_C_WME);
            }

            /*
             * Check whether the separate key cache entries
             * are required to handle both tx+rx MIC keys.
             * With split mic keys the number of stations is limited
             * to 27 otherwise 59.
             */
            if (ops->have_capability(dev, ATH_CAP_TKIP_SPLITMIC))
                scn->sc_splitmic = 1;
                DPRINTF(scn, ATH_DEBUG_KEYCACHE, "%s\n", __func__);
        }
    }

    if (ops->have_capability(dev, ATH_CAP_MCAST_KEYSEARCH))
        scn->sc_mcastkey = 1;

    /* TPC enabled */
    if (ops->have_capability(dev, ATH_CAP_TXPOWER))
        ieee80211com_set_cap(ic, IEEE80211_C_TXPMGT);

    spin_lock_init(&(scn->sc_keyixmap_lock));
    /*
     * Default 11.h to start enabled.
     */
    ieee80211_ic_doth_set(ic);

#if UMAC_SUPPORT_WNM
    /* Default WNM enabled   */
    ieee80211_ic_wnm_set(ic);
#endif

    /*Default wradar channel filtering is disabled  */
    ic->ic_no_weather_radar_chan = 0;

    /* 11n Capabilities */
    ieee80211com_set_num_tx_chain(ic,1);
    ieee80211com_set_num_rx_chain(ic,1);
    ieee80211com_clear_htcap(ic, -1);
    ieee80211com_clear_htextcap(ic, -1);
    if (ops->have_capability(dev, ATH_CAP_HT)) {
        ieee80211com_set_cap(ic, IEEE80211_C_HT);
        ieee80211com_set_htcap(ic, IEEE80211_HTCAP_C_SHORTGI40
                        | IEEE80211_HTCAP_C_CHWIDTH40
                        | IEEE80211_HTCAP_C_DSSSCCK40);
        if (ops->have_capability(dev, ATH_CAP_HT20_SGI))
            ieee80211com_set_htcap(ic, IEEE80211_HTCAP_C_SHORTGI20);
        if (ops->have_capability(dev, ATH_CAP_DYNAMIC_SMPS)) {
            ieee80211com_set_htcap(ic, IEEE80211_HTCAP_C_SMPOWERSAVE_DYNAMIC);
        } else {
            ieee80211com_set_htcap(ic, IEEE80211_HTCAP_C_SMPOWERSAVE_DISABLED);
        }
        ieee80211com_set_htextcap(ic, IEEE80211_HTCAP_EXTC_TRANS_TIME_5000
                        | IEEE80211_HTCAP_EXTC_MCS_FEEDBACK_NONE);
        ieee80211com_set_roaming(ic, IEEE80211_ROAMING_AUTO);
        ieee80211com_set_maxampdu(ic, IEEE80211_HTCAP_MAXRXAMPDU_65536);
        if (ops->have_capability(dev, ATH_CAP_ZERO_MPDU_DENSITY)) {
            ieee80211com_set_mpdudensity(ic, IEEE80211_HTCAP_MPDUDENSITY_NA);
        } else {
            ieee80211com_set_mpdudensity(ic, IEEE80211_HTCAP_MPDUDENSITY_8);
        }
        IEEE80211_ENABLE_AMPDU(ic);


        if (!scn->sc_ops->ath_get_config_param(scn->sc_dev, ATH_PARAM_WEP_TKIP_AGGR_RX_DELIM,
                                           &weptkipaggr_rxdelim)) {
            ieee80211com_set_weptkipaggr_rxdelim(ic, (u_int8_t) weptkipaggr_rxdelim);
        }

        /* Fetch channel switching time parameter from ATH layer */
        scn->sc_ops->ath_get_config_param(scn->sc_dev, ATH_PARAM_CHANNEL_SWITCHING_TIME_USEC,
                                           &channel_switching_time_usec);
        ieee80211com_set_channel_switching_time_usec(ic, (u_int16_t) channel_switching_time_usec);

        ieee80211com_set_num_rx_chain(ic,
                  ops->have_capability(dev,  ATH_CAP_NUMRXCHAINS));
        ieee80211com_set_num_tx_chain(ic,
                  ops->have_capability(dev,  ATH_CAP_NUMTXCHAINS));

#ifdef ATH_SUPPORT_TxBF
        if (ops->have_capability(dev, ATH_CAP_TXBF)) {
            ath_set_txbfcapability(ic);
            //printk("==>%s:ATH have TxBF cap, set ie= %x \n",__func__,ic->ic_txbf.value);
        }
#endif
        //ieee80211com_set_ampdu_limit(ic, ath_configuration_parameters.aggrLimit);
        //ieee80211com_set_ampdu_subframes(ic, ath_configuration_parameters.aggrSubframes);
    }

    if (ops->have_capability(dev, ATH_CAP_TX_STBC)) {
        ieee80211com_set_htcap(ic, IEEE80211_HTCAP_C_TXSTBC);
    }

    /* Rx STBC is a 2-bit mask. Needs to convert from ath definition to ieee definition. */
    ieee80211com_set_htcap(ic, IEEE80211_HTCAP_C_RXSTBC &
                           (ops->have_capability(dev, ATH_CAP_RX_STBC) << IEEE80211_HTCAP_C_RXSTBC_S));

    ldpccap = ops->have_capability(dev, ATH_CAP_LDPC);
    if (ldpccap & HAL_LDPC_RX) {
        ieee80211com_set_htcap(ic, IEEE80211_HTCAP_C_ADVCODING);
    }
    ieee80211com_set_ldpccap(ic, ldpccap);

    /* 11n configuration */
    ieee80211com_clear_htflags(ic, -1);

    /*
     * Check for misc other capabilities.
     */
    if (ops->have_capability(dev, ATH_CAP_BURST))
        ieee80211com_set_cap(ic, IEEE80211_C_BURST);

    /* Set spatial streams */
    ath_set_spatialstream(scn);

    /*
     * Indicate we need the 802.11 header padded to a
     * 32-bit boundary for 4-address and QoS frames.
     */
    IEEE80211_ENABLE_DATAPAD(ic);

    /* get current mac address */
    ops->get_macaddr(dev, ic->ic_myaddr);

    /* get mac address from EEPROM */
    ops->get_hw_macaddr(dev, ic->ic_my_hwaddr);
#if ATH_SUPPORT_AP_WDS_COMBO
    /* Assume the LSB bits 0-2 of last byte in the h/w MAC address to be 0 always */
    KASSERT((ic->ic_my_hwaddr[IEEE80211_ADDR_LEN - 1] & 0x07) == 0,
		    ("Last 3 bits of h/w MAC addr is non-zero: %s", ether_sprintf(ic->ic_my_hwaddr)));
#endif

    HTC_SET_NET80211_OPS_FUNC(net80211_ops, ath_net80211_find_tgt_node_index,
            ath_htc_wmm_update,
            ath_net80211_find_tgt_vap_index,
            ath_net80211_uapsd_creditupdate,
            athnet80211_rxcleanup);


#ifdef ATH_SUPPORT_HTC
    scn->sc_p2p_action_queue_head = NULL;
    scn->sc_p2p_action_queue_tail = NULL;
    IEEE80211_STATE_P2P_ACTION_LOCK_INIT(scn);
#endif

    /* get default country info for 11d */
    ops->get_current_country(dev, (HAL_COUNTRY_ENTRY *)&ic->ic_country);

    /*
     * Setup some ieee80211com methods
     */
    ic->ic_mgtstart = ath_tx_mgt_send;
    ic->ic_init = ath_init;
    ic->ic_stop = ath_ic_stop;
    ic->ic_reset_start = ath_net80211_reset_start;
    ic->ic_reset = ath_net80211_reset;
    ic->ic_reset_end = ath_net80211_reset_end;
    ic->ic_newassoc = ath_net80211_newassoc;
    ic->ic_updateslot = ath_net80211_updateslot;

    ic->ic_wme.wme_update = ath_wmm_update;

    ic->ic_get_currentCountry = ath_net80211_get_currentCountry;
    ic->ic_set_country = ath_net80211_set_country;
    ic->ic_set_regdomain = ath_net80211_set_regdomain;
    ic->ic_set_quiet = ath_net80211_set_quiet;
#if UMAC_SUPPORT_ADMCTL
	ic->ic_node_update_dyn_uapsd = ath_node_update_dyn_uapsd;
#endif
    ic->ic_find_countrycode = ath_net80211_find_countrycode;

#ifdef ATH_SUPPORT_TxBF // For TxBF RC

    ic->ic_v_cv_send = ath_net80211_v_cv_send;
    ic->ic_txbf_alloc_key = ath_net80211_txbf_alloc_key;
    ic->ic_txbf_set_key = ath_net80211_txbf_set_key;
    ic->ic_init_sw_cv_timeout = ath_net80211_init_sw_cv_timeout;
    ic->ic_set_txbf_caps = ath_set_txbfcapability;
#ifdef TXBF_DEBUG
	ic->ic_txbf_check_cvcache = ath_net80211_txbf_check_cvcache;
#endif
    ic->ic_txbf_stats_rpt_inc = ath_net80211_txbf_stats_rpt_inc;
    ic->ic_txbf_set_rpt_received = ath_net80211_txbf_set_rpt_received;
#endif
#if defined(ATH_SUPPORT_TxBF) || ATH_DEBUG
#if IEEE80211_DEBUG_REFCNT
    ic->ic_ieee80211_find_node_debug = ieee80211_find_node_debug;
#else
    ic->ic_ieee80211_find_node = ieee80211_find_node;
#endif //IEEE80211_DEBUG_REFCNT
    ic->ic_ieee80211_unref_node = ath_net80211_unref_node;
#endif

    ic->ic_beacon_update = ath_beacon_update;
    ic->ic_txq_depth = ath_net80211_txq_depth;
    ic->ic_txq_depth_ac = ath_net80211_txq_depth_ac;

    ic->ic_chwidth_change = ath_net80211_chwidth_change;
    ic->ic_sm_pwrsave_update = ath_net80211_sm_pwrsave_update;
    ic->ic_update_protmode = ath_net80211_update_protmode;
    ic->ic_set_config = ath_net80211_set_config;

    /* This section Must be before calling ieee80211_ifattach() */
    ic->ic_tsf_timer_alloc = ath_net80211_tsf_timer_alloc;
    ic->ic_tsf_timer_free = ath_net80211_tsf_timer_free;
    ic->ic_tsf_timer_start = ath_net80211_tsf_timer_start;
    ic->ic_tsf_timer_stop = ath_net80211_tsf_timer_stop;
    ic->ic_get_TSF32        = ath_net80211_gettsf32;
#ifdef ATH_USB
    ic->ic_get_target_TSF32 = ath_get_targetTSF32;
#endif
    ic->ic_get_TSF64        = ath_net80211_gettsf64;
#if ATH_SUPPORT_WIFIPOS
    ic->ic_get_TSFTSTAMP    = ath_net80211_gettsftstamp;
#endif
#if UMAC_SUPPORT_P2P
    ic->ic_reg_notify_tx_bcn = ath_net80211_reg_notify_tx_bcn;
    ic->ic_dereg_notify_tx_bcn = ath_net80211_dereg_notify_tx_bcn;
#endif

    ic->ic_is_mode_offload = ath_net80211_is_mode_offload;
    ic->ic_is_macreq_enabled = ath_net80211_is_macreq_enabled;
    ic->ic_get_mac_prealloc_idmask = ath_net80211_get_mac_prealloc_idmask;

    /* Attach the direct attach print scan function */
    ic->ic_print_scan_config = wlan_print_scan_config;
    /* Setup Min frame size */
    ic->ic_minframesize = sizeof(struct ieee80211_frame_min);

    /* attach resmgr module */
    ieee80211_resmgr_attach(ic);

    /* attach scan module */
    ieee80211_scan_class_attach(ic);

    /* attach power module */
    ieee80211_power_class_attach(ic);

    ieee80211_wme_initglobalparams(ic);

    ic->ic_set_beacon_interval = ath_net80211_set_beacon_interval;
    /*
     * Attach ieee80211com object to net80211 protocal stack.
     */
    error = ieee80211_ifattach(ic, ieee80211_conf_parm);
    if (error) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,  "%s: failed!, error[%d]\n", __func__, error );
        ath_dev_free(dev);
        return error;
    }

    /*
     * Override default methods
     */
    ic->ic_vap_create = ath_vap_create;
    ic->ic_vap_delete = ath_vap_delete;
    ic->ic_vap_free = ath_vap_free;
    ic->ic_vap_alloc_macaddr = ath_vap_alloc_macaddr;
    ic->ic_vap_free_macaddr = ath_vap_free_macaddr;
    ic->ic_node_alloc = ath_net80211_node_alloc;
    scn->sc_node_free = ic->ic_node_free;
    ic->ic_node_free = ath_net80211_node_free;
    ic->ic_node_getrssi = ath_net80211_node_getrssi;
#if defined(MAGPIE_HIF_GMAC) || defined(MAGPIE_HIF_USB)
    ic->ic_node_getrate = ath_net80211_htc_node_getrate;
#else
    ic->ic_node_getrate = ath_net80211_node_getrate;
#endif
    ic->ic_node_psupdate = ath_net80211_node_ps_update;
    ic->ic_node_queue_depth = ath_net80211_node_queue_depth;
    scn->sc_node_cleanup = ic->ic_node_cleanup;
    ic->ic_node_cleanup = ath_net80211_node_cleanup;
#if QCA_AIRTIME_FAIRNESS
    ic->ic_node_getairtime = ath_net80211_node_getairtime;
#endif
    ic->ic_node_get_last_txpower = ath_net80211_node_get_last_txpower;

    ic->ic_scan_start = ath_net80211_scan_start;
    ic->ic_scan_end = ath_net80211_scan_end;
    ic->ic_led_scan_start = ath_net80211_led_enter_scan;
    ic->ic_led_scan_end = ath_net80211_led_leave_scan;
    ic->ic_set_channel = ath_net80211_set_channel;
    ic->ic_enable_radar = ath_net80211_enable_radar;

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
    ic->ic_enable_sta_radar = ath_net80211_enable_sta_radar;
#endif

#if ATH_SUPPORT_WIFIPOS
    ic->ic_lean_set_channel = ath_net80211_lean_set_channel;
    ic->ic_pause_node = ath_net80211_pause_node;
    ic->ic_resched_txq = ath_net80211_resched_txq;
    ic->ic_disable_hwq = ath_net80211_disable_hwq;
    ic->ic_vap_reap_txqs = ath_net80211_vap_reap_txqs;
    ic->ic_get_channel_busy_info = ath_net80211_get_channel_busy_info;
#endif
    ic->ic_pwrsave_set_state = ath_net80211_pwrsave_set_state;

    ic->ic_mhz2ieee = ath_net80211_mhz2ieee;

    ic->ic_set_ampduparams = ath_net80211_set_ampduparams;
    ic->ic_set_weptkip_rxdelim = ath_net80211_set_weptkip_rxdelim;
    ic->ic_addba_requestsetup = ath_net80211_addba_requestsetup;
    ic->ic_addba_responsesetup = ath_net80211_addba_responsesetup;
    ic->ic_addba_requestprocess = ath_net80211_addba_requestprocess;
    ic->ic_addba_responseprocess = ath_net80211_addba_responseprocess;
    ic->ic_addba_clear = ath_net80211_addba_clear;
    ic->ic_delba_process = ath_net80211_delba_process;
    ic->ic_addba_send = ath_net80211_addba_send;
    ic->ic_addba_status = ath_net80211_addba_status;
    ic->ic_delba_send = ath_net80211_delba_send;
    ic->ic_addba_setresponse = ath_net80211_addba_setresponse;
    ic->ic_addba_clearresponse = ath_net80211_addba_clearresponse;
    ic->ic_get_noisefloor = ath_net80211_get_noisefloor;
    ic->ic_get_chainnoisefloor = ath_net80211_get_chainnoisefloor;
#if ATH_SUPPORT_VOW_DCS
    ic->ic_disable_dcsim = ath_net80211_disable_dcsim;
    ic->ic_enable_dcsim = ath_net80211_enable_dcsim;
#endif
    ic->ic_set_txPowerLimit = ath_setTxPowerLimit;
	ic->ic_set_txPowerAdjust = ath_setTxPowerAdjust;
    ic->ic_get_common_power = ath_net80211_get_common_power;
    ic->ic_get_maxphyrate = ath_net80211_get_maxphyrate;
    ic->ic_get_TSF32        = ath_getTSF32;
#ifdef ATH_USB
    ic->ic_get_target_TSF32 = ath_get_targetTSF32;
#endif

    ic->ic_rmgetcounters = ath_getrmcounters;
    ic->ic_set_rxfilter     = ath_setReceiveFilter;
    ic->ic_set_rx_sel_plcp_header = ath_set_rx_sel_plcp_header;
#ifdef ATH_CCX
    ic->ic_rmclearcounters = ath_clearrmcounters;
    ic->ic_rmupdatecounters = ath_updatermcounters;
    ic->ic_rcRateValueToPer = ath_net80211_rcRateValueToPer;
    ic->ic_get_TSF32        = ath_getTSF32;
    ic->ic_get_TSF64        = ath_getTSF64;
    ic->ic_get_mfgsernum    = ath_getMfgSerNum;
    ic->ic_get_chandata     = ath_net80211_get_chanData;
    ic->ic_get_curRSSI      = ath_net80211_get_curRSSI;
#endif
#ifdef ATH_SWRETRY
    ic->ic_set_swretrystate = ath_net80211_set_swretrystate;
    ic->ic_handle_pspoll = ath_net80211_handle_pspoll;
    ic->ic_exist_pendingfrm_tidq = ath_net80211_exist_pendingfrm_tidq;
    ic->ic_reset_pause_tid = ath_net80211_reset_pasued_tid;
#endif
    ic->ic_get_wpsPushButton = ath_net80211_wpsPushButton;
#if !ATH_SUPPORT_STATS_APONLY
    ic->ic_update_phystats = ath_update_phystats;
#else
    ic->ic_update_phystats = NULL;
#endif
    ic->ic_clear_phystats = ath_clear_phystats;
    ic->ic_set_macaddr = ath_net80211_set_macaddr;
    ic->ic_log_text = ath_net80211_log_text;
    ic->ic_log_text_bh = ath_net80211_log_text;
    ic->ic_set_chain_mask = ath_net80211_set_chain_mask;
    ic->ic_need_beacon_sync = ath_net80211_need_beacon_sync;
#if QCA_AIRTIME_FAIRNESS
    ic->ic_atf_update_node_txtoken = ath_net80211_atf_update_node_txtoken;
    ic->ic_atf_set_enable_disable = ath_net80211_atf_set_clear;
    ic->ic_atf_tokens_used = ath_net80211_atf_tokens_used;
    ic->ic_atf_get_unused_txtoken = ath_net80211_atf_get_unused_txtoken;
    ic->ic_atf_node_resume = ath_net80211_atf_node_resume;
    ic->ic_node_buf_held = ath_net80211_node_buf_held;
    ic->atf_txbuf_max = ATF_MAX_BUFS;
    ic->atf_txbuf_min = ATF_MIN_BUFS;
    ic->atf_txbuf_share = 1;
    ic->ic_atf_tokens_unassigned = ath_net80211_atf_tokens_unassigned;
    ic->ic_atf_capable_node = ath_net80211_atf_capable_node;
    ic->ic_atf_airtime_estimate = ath_net80211_atf_airtime_estimate;
    ic->ic_atf_debug_nodestate = ath_net80211_atf_debug_nodestate;
    ic->ic_atf_tput_based = 0;
    ic->ic_atf_resv_airtime = ATF_TPUT_RESV_AIRTIME;
    for (i = 0; i < ATF_TPUT_MAX_STA; i++) {
        OS_MEMSET(ic->ic_atf_tput_tbl[i].mac_addr, 0x0, IEEE80211_ADDR_LEN);
        ic->ic_atf_tput_tbl[i].order = 0;
    }
    ic->ic_atf_tput_tbl_num = 0;
    ic->ic_atf_tput_order_max = 0;
    ic->ic_atf_airtime_override = 0;
#endif
    /* Functions for the green_ap feature */
    ic->ic_green_ap_set_enable = ath_net80211_green_ap_set_enable;
    ic->ic_green_ap_get_enable = ath_net80211_green_ap_get_enable;
    ic->ic_green_ap_set_transition_time = ath_net80211_green_ap_set_transition_time;
    ic->ic_green_ap_get_transition_time = ath_net80211_green_ap_get_transition_time;
    ic->ic_green_ap_set_on_time = ath_net80211_green_ap_set_on_time;
    ic->ic_green_ap_get_on_time = ath_net80211_green_ap_get_on_time;
    ic->ic_green_ap_set_print_level = ath_net80211_green_ap_set_enable_print;
    ic->ic_green_ap_get_print_level = ath_net80211_green_ap_get_enable_print;

    ic->ic_get_cur_chan_nf = ath_net80211_get_cur_chan_noisefloor;
    ic->ic_get_cur_chan_stats = ath_net80211_get_cur_chan_stats;

    ic->ic_hal_get_chan_info = ath_net80211_get_chan_info;
#if ATH_SUPPORT_SPECTRAL
    /* EACS with spectral functions */
    ic->ic_start_spectral_scan = ath_net80211_start_spectral_scan;
    ic->ic_stop_spectral_scan = ath_net80211_stop_spectral_scan;
    ic->ic_record_chan_info = ath_net80211_record_chan_info;
#endif
#ifdef ATH_BT_COEX
    ic->ic_get_bt_coex_info = ath_get_bt_coex_info;
#endif
    ic->ic_get_mfpsupport = ath_net80211_getmfpsupport;
    ic->ic_set_hwmfpQos   = ath_net80211_setmfpQos;
#if IEEE80211_DEBUG_NODELEAK
    ic->ic_print_nodeq_info = ath_net80211_debug_print_nodeq_info;
#endif
#if ATH_SUPPORT_IQUE
    ic->ic_set_acparams = ath_net80211_set_acparams;
    ic->ic_set_rtparams = ath_net80211_set_rtparams;
    ic->ic_get_iqueconfig = ath_net80211_get_iqueconfig;
	ic->ic_set_hbrparams = ath_net80211_set_hbrparams;
#endif
#if ATH_SLOW_ANT_DIV
    ic->ic_antenna_diversity_suspend = ath_net80211_antenna_diversity_suspend;
    ic->ic_antenna_diversity_resume = ath_net80211_antenna_diversity_resume;
#endif
    ic->ic_get_goodput = ath_net80211_get_goodput;
    ic->ic_get_ctl_by_country = ath_net80211_get_ctl_by_country;
    ic->ic_dfs_isdfsregdomain = ath_net80211_dfs_isdfsregdomain;
    ic->ic_dfs_usenol = ath_net80211_dfs_usenol;
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
    ic->ic_dfs_print_nolhistory = ieee80211_print_nolhistory;
    ic->ic_dfs_clear_nolhistory = ieee80211_clear_nolhistory;
#endif
    ic->ic_dfs_attached = ath_net80211_dfs_attached;
    ic->ic_get_dfsdomain = ath_net80211_getdfsdomain;

    /* The following functions are commented to avoid, comile
     * error
     *- KARTHI
     * Once the references to ath_net80211_enable_tpc and
     * ath_net80211_get_max_txpwr are restored, the function
     * declarations and definitions should be changed back to static.
     */
    //ic->ic_enable_hw_tpc = ath_net80211_enable_tpc;
    //ic->ic_get_tx_maxpwr = ath_net80211_get_max_txpwr;

    ic->ic_vap_pause_control = ath_net80211_vap_pause_control;
    ic->ic_enable_rifs_ldpcwar = ath_net80211_enablerifs_ldpcwar;
    ic->ic_process_uapsd_trigger = ath_net80211_process_uapsd_trigger;
    ic->ic_is_hwbeaconproc_active = ath_net80211_is_hwbeaconproc_active;
    ic->ic_hw_beacon_rssi_threshold_enable = ath_net80211_hw_beacon_rssi_threshold_enable;
    ic->ic_hw_beacon_rssi_threshold_disable = ath_net80211_hw_beacon_rssi_threshold_disable;

    IEEE80211_HTC_SET_IC_CALLBACK(ic);
#if UMAC_SUPPORT_VI_DBG
    ic->ic_set_vi_dbg_restart = ath_net80211_set_vi_dbg_restart;
    ic->ic_set_vi_dbg_log     = ath_net80211_set_vi_dbg_log;
#endif
    /*used as part of channel hopping algo to trigger noise detection in counter window */
    ic->ic_set_noise_detection_param     = ath_net80211_set_noise_detection_param;
    ic->ic_get_noise_detection_param     = ath_net80211_get_noise_detection_param;
	ic->ic_get_txbuf_free = ath_net80211_get_txbuf_free;
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
    ic->ic_hmmc_cnt = 3;
    ic->ic_hmmcs[0].ip = be32toh(0xeffffffa); /* 239.255.255.250 */
    ic->ic_hmmcs[0].mask = 0xffffffff;
    ic->ic_hmmcs[1].ip = be32toh(0xe00000fb); /* 224.0.0.251 */
    ic->ic_hmmcs[1].mask = 0xffffffff;
    ic->ic_hmmcs[2].ip = be32toh(0xe00000fc); /* 224.0.0.252 */
    ic->ic_hmmcs[2].mask = 0xffffffff;
	ic->ic_node_ext_stats_enable = ath_net80211_node_ext_stats_enable;
    ic->ic_reset_ald_stats = ath_net80211_reset_stats;
	ic->ic_collect_stats = ath_net80211_collect_stats;
#endif
#if UNIFIED_SMARTANTENNA
    if (scn->enable_smart_antenna_da) {
        ic->ic_smart_ant_enable = ath_net80211_smart_ant_enable;
        ic->ic_smart_ant_set_rx_antenna = ath_net80211_smart_ant_set_rx_antenna;
        ic->ic_smart_ant_set_tx_antenna = ath_net80211_smart_ant_set_tx_antenna;
        ic->ic_smart_ant_set_tx_default_antenna = ath_net80211_smart_ant_set_tx_default_antenna;
        ic->ic_smart_ant_set_training_info = ath_net80211_smart_ant_set_training_info;
        ic->ic_smart_ant_set_node_config_ops = ath_net80211_smart_ant_set_node_config_ops;
        ic->ic_smart_ant_prepare_rateset = ath_net80211_smart_ant_prepare_rateset;
        ic->max_fallback_rates = FALL_BACK_RATES_DIRECT_ATTACH; /* For direct attach chips, 11N rate series has 3 falbakc rates and 1 primary rate */
        ic->ic_smart_ant_state = SMART_ANT_STATE_DEFAULT;
        ic->vap_down_in_progress = FALSE;
        ic->radio_id = RADIO_ID_DIRECT_ATTACH;
    } else {
	    ic->ic_smart_ant_enable = NULL;
	    ic->ic_smart_ant_set_rx_antenna = NULL;
	    ic->ic_smart_ant_set_tx_antenna = NULL;
	    ic->ic_smart_ant_set_tx_default_antenna = NULL;
	    ic->ic_smart_ant_set_training_info = NULL;
	    ic->ic_smart_ant_set_node_config_ops = NULL;
	    ic->ic_smart_ant_prepare_rateset = NULL;
    }
#endif
#ifdef DBG
    ic->ic_hw_reg_read        = ath_hw_reg_read;
#endif
    ic->ic_get_tx_hw_retries  = ath_net80211_get_tx_hw_retries;
    ic->ic_get_tx_hw_success  = ath_net80211_get_tx_hw_success;
    ic->ic_rate_node_update   = ath_net80211_update_rate_node;
#if LMAC_SUPPORT_POWERSAVE_QUEUE
    ic->ic_get_lmac_pwrsaveq_len = ath_net80211_get_lmac_pwrsaveq_len;
    ic->ic_node_pwrsaveq_send = ath_net80211_node_pwrsaveq_send;
    ic->ic_node_pwrsaveq_flush = ath_net80211_node_pwrsaveq_flush;
    ic->ic_node_pwrsaveq_drain = ath_net80211_node_pwrsaveq_drain;
    ic->ic_node_pwrsaveq_age = ath_net80211_node_pwrsaveq_age;
    ic->ic_node_pwrsaveq_get_info = ath_net80211_node_pwrsaveq_get_info;
    ic->ic_node_pwrsaveq_set_param = ath_net80211_node_pwrsaveq_set_param;
#endif
#if ATH_SUPPORT_FLOWMAC_MODULE
    ic->ic_get_flowmac_enabled_State = ath_net80211_get_flowmac_enabled_state;
#endif
#ifdef ATH_SUPPORT_DFS
    ic->ic_dfs_attach = ath_net80211_attach_dfs;
    ic->ic_dfs_detach = ath_net80211_detach_dfs;
    ic->ic_dfs_enable = ath_net80211_enable_dfs;
    ic->ic_dfs_disable = ath_net80211_disable_dfs;
    ic->ic_get_ext_busy = ath_net80211_get_ext_busy;
    ic->ic_get_mib_cycle_counts_pct = ath_net80211_get_mib_cycle_counts_pct;
    ic->ic_dfs_control = dfs_control;
    ic->ic_dfs_get_thresholds = ath_net80211_dfs_get_thresholds;
    ic->ic_dfs_clist_update = ath_net80211_dfs_clist_update;
    ic->ic_dfs_notify_radar = ieee80211_mark_dfs;

#if ATH_SUPPORT_ZERO_CAC_DFS
    ic->ic_dfs_print_precaclists = ieee80211_print_precaclists;
    ic->ic_dfs_reset_precaclists = ieee80211_reset_precaclists;
    ic->ic_dfs_notify_precac_radar = ieee80211_mark_precac_dfs;
    ic->ic_dfs_cancel_precac_timer = ieee80211_dfs_cancel_precac_timer;
    ic->ic_dfs_is_precac_timer_running = ieee80211_is_precac_timer_running;
    ic->ic_dfs_find_precac_secondary_vht80_chan = ieee80211_dfs_find_precac_secondary_vht80_chan;
    ic->ic_get_nol_timeout = dfs_get_nol_timeout;
#endif

    ic->ic_dfs_send_rcsa  = ieee80211_send_rcsa;
    ic->ic_dfs_rx_rcsa   = ath_net80211_dfs_rx_rcsa;
    ic->ic_dfs_cancel_waitfor_csa_timer  = ath_net80211_dfs_cancel_waitfor_csa_timer;
    ic->ic_dfs_unmark_radar = ieee80211_unmark_radar;
    ic->ic_bringup_ap_vaps = ieee80211_bringup_ap_vaps;
    ic->ic_random_channel = ieee80211_random_channel;
#endif /* ATH_SUPPORT_DFS */

    ic->ic_find_channel = ieee80211_find_channel;
    ic->ic_ieee2mhz = ieee80211_ieee2mhz;
    ic->ic_vap_sifs_trigger = ath_vap_sifs_trigger;
    ic->ic_node_add_wds_entry = ath_node_add_wds_entry;
    ic->ic_node_del_wds_entry = ath_node_del_wds_entry;
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
    ic->ic_node_update_wds_entry = ath_node_update_wds_entry;
#endif
    ic->ic_node_authorize = NULL;
    ic->ic_start_csa = ieee80211_start_csa;
    ic->ic_rx_intr_mitigation = ath_config_rx_intr_mitigation;
#if ATH_TxBF_DYNAMIC_LOF_ON_N_CHAIN_MASK
    ic->ic_txbf_loforceon_update = ath_net80211_txbf_loforceon_update;
#endif
#if ATH_SUPPORT_KEYPLUMB_WAR
    ic->ic_checkandplumb_key = ath_key_checkandplumb;
#endif
    ic->ic_get_rx_signal_dbm = ath_net80211_get_rx_signal_dbm;
#if ATH_BAND_STEERING
    ic->ic_ath_send_rssi = ath_net80211_bsteering_send_rssi;
    ic->ic_node_isinact =  ath_net80211_bsteering_node_is_inact;
#endif
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
    ic->ic_node_dump_wds_table = ath_node_dump_wds_table;
    ic->ic_node_use_4addr = ath_node_use_4addr;
#endif

#ifdef QCA_PARTNER_PLATFORM
    ic->partner_com_params.ipc_ol_txrx_ast_find_hash_find = NULL;
    ic->partner_com_params.ipc_ol_txrx_peer_find_by_id = NULL;
    ic->partner_com_params.ipc_ol_ath_getvap = NULL;
#endif

    ic->ic_nl_handle = NULL;

#if ATH_SUPPORT_DFS
    /* Attach DFS */
    dfs_attach(ic);
#endif

#if ATH_SUPPORT_SPECTRAL
    spectral_attach(ic);
#endif
   ic->ic_scan_enable_txq = ath_net80211_scan_enable_txq;

#if UMAC_SUPPORT_APONLY
    ic->ic_aponly = true;
#else
    ic->ic_aponly = false;
#endif
    ic->ic_auth_tx_xretry = 0;

    ic->id_mask_vap_downed = 0;
#if ATH_TxBF_DYNAMIC_LOF_ON_N_CHAIN_MASK
    ic->ic_ht_txbf_sta_assoc = 0;
#endif
#if ATH_SUPPORT_TIDSTUCK_WAR
    ic->ic_clear_rxtid = ath_net80211_clear_rxtid;
#endif
    ic->ic_scan_entry_max_count = ATH_SCANENTRY_MAX;
    atomic_set(&(ic->ic_scan_entry_current_count),0);
    ic->ic_scan_entry_timeout = ATH_SCANENTRY_TIMEOUT;
    ic->ic_node_pspoll = ath_net80211_node_pspoll;
    ic->ic_tr69_request_process = ath_net80211_tr69_process_request;
#if ATH_BAND_STEERING
    ic->ic_bs_enable = ath_net80211_bs_enable;
    ic->ic_bs_set_overload = ath_net80211_bs_set_overload;
    ic->ic_bs_set_params = ath_net80211_bs_set_params;
#endif
#if ATH_SUPPORT_LOWI
    ic->ic_lowi_frame_send = NULL;
#endif
    ic->ic_rate_check = ath_direct_rate_check;

#if DBDC_REPEATER_SUPPORT
    /* Add ic to global list */
    GLOBAL_IC_LOCK(&ic_list);
    ic_list.global_ic[ic_list.num_global_ic++] = ic;
    ic_list.dbdc_process_enable = 1;
    ic_list.force_client_mcast_traffic = 0;
    ic_list.delay_stavap_connection = 0;
    ic_list.drop_secondary_mcast = 0;
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Set global_ic[%d]..gloabl_ic ptr:%p\n", __func__, ic_list.num_global_ic,&ic_list);

    ic_list.num_stavaps_up = 0;
    ic_list.is_dbdc_rootAP = 0;
    ic_list.iface_mgr_up = 0;
    ic_list.disconnect_timeout = 10;
    ic_list.reconfiguration_timeout = 60;
    ic_list.always_primary = 0;
    ic_list.num_fast_lane_ic = 0;
    ic_list.max_priority_stavap_up = NULL;
    GLOBAL_IC_UNLOCK(&ic_list);

    spin_lock(&ic->ic_lock);
    ic->ic_global_list = &ic_list;
    if (ic_list.num_global_ic) {
        /* In case of DBDC repeater configuration, pass Multicast/Broadcast and
         ethernet client traffic through this radio */
        ic->ic_radio_priority = ic_list.num_global_ic;
        if (ic_list.num_global_ic == 1) {
            ic->ic_primary_radio = 1;
        }
    }
    ic->fast_lane = 0;
    ic->fast_lane_ic = NULL;
    spin_unlock(&ic->ic_lock);

    k = 0;
    /*update other_ic list on each radio*/
    for (i=0; i < MAX_RADIO_CNT; i++) {
        GLOBAL_IC_LOCK(&ic_list);
        tmp_ic = ic_list.global_ic[i];
        GLOBAL_IC_UNLOCK(&ic_list);
        if (tmp_ic && (tmp_ic != ic)) {
            spin_lock(&ic->ic_lock);
            ic->other_ic[k++] = tmp_ic;
            spin_unlock(&ic->ic_lock);
	    for (j=0; j < MAX_RADIO_CNT-1 ; j++) {
		if (tmp_ic->other_ic[j] == NULL) {
		    spin_lock(&tmp_ic->ic_lock);
		    tmp_ic->other_ic[j] = ic;
		    spin_unlock(&tmp_ic->ic_lock);
		    break;
		}
	    }
	}
    }
#endif

    ic->tid_override_queue_mapping = 0;

    ic->ic_no_vlan = 0;
    ic->ic_atf_logging = 0;
    ic->ic_non_doth_sta_cnt = 0;

    return 0;
}

int
ath_detach(struct ath_softc_net80211 *scn)
{
    struct ieee80211com *ic = &scn->sc_ic;
#if DBDC_REPEATER_SUPPORT
    struct ieee80211com *tmp_ic;
    int i,j;
#endif

    ieee80211_stop_running(ic);
    spin_lock_destroy(&(scn->sc_keyixmap_lock));

    /*
     * NB: the order of these is important:
     * o call the 802.11 layer before detaching the hal to
     *   insure callbacks into the driver to delete global
     *   key cache entries can be handled
     * o reclaim the tx queue data structures after calling
     *   the 802.11 layer as we'll get called back to reclaim
     *   node state and potentially want to use them
     * o to cleanup the tx queues the hal is called, so detach
     *   it last
     * Other than that, it's straightforward...
     */
    ieee80211_ifdetach(ic);
    /* deregister IEEE80211_DPRINTF_IC control object */
    ieee80211_dprintf_ic_deregister(ic);
    ath_cwm_detach(scn);
#ifdef ATH_AMSDU
    ath_amsdu_detach(scn);
#endif

#if ATH_SUPPORT_DFS
    /* Detach DFS */
    dfs_detach(ic);
#endif

  #ifdef ATH_SUPPORT_HTC
    IEEE80211_STATE_P2P_ACTION_LOCK_IRQ(scn);
    while (scn->sc_p2p_action_queue_head) {
        struct ath_usb_p2p_action_queue *p2p_action_queue_head;
        p2p_action_queue_head = scn->sc_p2p_action_queue_head;
        scn->sc_p2p_action_queue_head = scn->sc_p2p_action_queue_head->next;
        wbuf_complete(p2p_action_queue_head->wbuf);
        OS_FREE(p2p_action_queue_head);
    }
    scn->sc_p2p_action_queue_head = NULL;
    scn->sc_p2p_action_queue_tail = NULL;
    IEEE80211_STATE_P2P_ACTION_UNLOCK_IRQ(scn);
    IEEE80211_STATE_P2P_ACTION_LOCK_DESTROY(scn);
  #endif

    ath_dev_free(scn->sc_dev);
    scn->sc_dev = NULL;
    scn->sc_ops = NULL;

    qdf_spinlock_destroy(&scn->amem.lock);
    asf_amem_destroy(scn->amem.handle, NULL);
    scn->amem.handle = NULL;

#if DBDC_REPEATER_SUPPORT
    /* Remove ic from global list */
    for (i=0; i < MAX_RADIO_CNT; i++) {
        tmp_ic = ic_list.global_ic[i];
        if (tmp_ic && (ic == tmp_ic)) {
            GLOBAL_IC_LOCK(&ic_list);
            ic_list.global_ic[i] = NULL;
            ic_list.num_global_ic--;
            QDF_PRINT_INFO(tmp_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: remove global_ic[%d]..gloabl_ic ptr:%p\n", __func__, ic_list.num_global_ic,&ic_list);
            GLOBAL_IC_UNLOCK(&ic_list);
        }
    }
    for (i=0; i < MAX_RADIO_CNT; i++) {
        GLOBAL_IC_LOCK(&ic_list);
        tmp_ic = ic_list.global_ic[i];
        GLOBAL_IC_UNLOCK(&ic_list);
        if (tmp_ic && (tmp_ic != ic)) {
            for (j=0; j < MAX_RADIO_CNT-1 ; j++) {
                if (tmp_ic->other_ic[j] == ic) {
		    spin_lock(&tmp_ic->ic_lock);
		    tmp_ic->other_ic[j] = NULL;
		    spin_unlock(&tmp_ic->ic_lock);
                    break;
                }
            }
        }
    }
#endif

#ifndef REMOVE_PKT_LOG
    if(scn->pl_dev){
        qdf_mem_free(scn->pl_dev);
        scn->pl_dev = NULL;
    }
#endif

    return 0;
}

int
ath_resume(struct ath_softc_net80211 *scn)
{
    /*
     * ignore if already resumed.
     */
    if (OS_ATOMIC_CMPXCHG(&(scn->sc_dev_enabled), 0, 1) == 1) return 0;

    return ath_init(&scn->sc_ic);
}

int
ath_suspend(struct ath_softc_net80211 *scn)
{
#ifdef ATH_SUPPORT_LINUX_STA
    struct ieee80211com *ic = &scn->sc_ic;
    int i=0;
#endif
    /*
     * ignore if already suspended;
     */
    if (OS_ATOMIC_CMPXCHG(&(scn->sc_dev_enabled), 1, 0) == 0) return 0;

    /* stop protocol stack first */
    ieee80211_stop_running(&scn->sc_ic);
    cwm_stop(&scn->sc_ic);

#ifdef ATH_SUPPORT_LINUX_STA
    /*
     * Stopping hardware in SCAN state may cause driver hang up and device malfuicntion
     * Set IEEE80211_SIWSCAN_TIMEOUT as maximum delay
     */
    while ((i < IEEE80211_SIWSCAN_TIMEOUT) && (ic->ic_flags & IEEE80211_F_SCAN))
    {
        OS_SLEEP(1000);
        i++;
    }
#endif

    return (*scn->sc_ops->stop)(scn->sc_dev);
}

static void ath_net80211_log_text(struct ieee80211com *ic, char *text)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->log_text(scn->sc_dev, text);
}


static bool ath_net80211_need_beacon_sync(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_syncbeacon;
}

#if ATH_SUPPORT_CFEND
wbuf_t
ath_net80211_cfend_alloc(ieee80211_handle_t ieee)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);

    return  ieee80211_cfend_alloc(ic);
}


#endif
#if IEEE80211_DEBUG_NODELEAK
static void ath_net80211_debug_print_nodeq_info(struct ieee80211_node *ni)
{
#ifdef AR_DEBUG
    struct ieee80211com *ic = ni->ni_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    ath_node_t node = ATH_NODE_NET80211(ni)->an_sta;
    scn->sc_ops->node_queue_stats(scn->sc_dev, node);
#endif
}
#endif

static u_int32_t ath_net80211_gettsf32(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->ath_get_tsf32(scn->sc_dev);
}

static u_int64_t ath_net80211_gettsf64(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->ath_get_tsf64(scn->sc_dev);
}

#if ATH_SUPPORT_WIFIPOS
static u_int64_t ath_net80211_gettsftstamp(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->ath_get_tsftstamp(scn->sc_dev);
}
#endif

struct pause_control_data {
    struct ieee80211vap *vap;
    struct ieee80211com *ic;
    bool  pause;
};

/* pause control iterator function */
static void
pause_control_cb(void *arg, struct ieee80211_node *ni)
{
    struct pause_control_data *pctrl_data = (struct pause_control_data *)arg;
    ath_node_t node = ATH_NODE_NET80211(ni)->an_sta;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(pctrl_data->ic);
    if (pctrl_data->vap == NULL || pctrl_data->vap == ni->ni_vap) {
        if (!((pctrl_data->pause !=0) ^ ((ni->ni_flags & IEEE80211_NODE_ATH_PAUSED) != 0))) {
            return;
        }
        if (pctrl_data->pause) {
           ni->ni_flags |= IEEE80211_NODE_ATH_PAUSED;
        } else {
           ni->ni_flags &= ~IEEE80211_NODE_ATH_PAUSED;
        }
        ath_net80211_uapsd_pause_control(ni, pctrl_data->pause);
        scn->sc_ops->ath_node_pause_control(scn->sc_dev, node, pctrl_data->pause);
        DPRINTF(scn, ATH_DEBUG_ANY, "%s ni 0x%x mac addr %s pause %d \n", __func__,ni, ether_sprintf(ni->ni_macaddr), pctrl_data->pause);
    }
}
#if ATH_SUPPORT_WIFIPOS
static int ath_net80211_vap_reap_txqs(struct ieee80211com *ic, struct ieee80211vap *vap)
{
    struct ath_vap_net80211 *avn;
    int if_id=ATH_IF_ID_ANY;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    if (vap) {
        avn = ATH_VAP_NET80211(vap);
        if_id = avn->av_if_id;
    }
    scn->sc_ops->ath_vap_reap_txqs(scn->sc_dev, if_id);
    return 0;

}
#endif
/*
 * pause/unpause vap(s).
 * if pause is true then perform pause operation.
 * if pause is false then perform unpause operation.
 * if vap is null the performa the requested operation on all the vaps.
 * if vap is non null the performa the requested operation on the vap.
 * part of the vap pause , pause all the nodes and call into ath layer to
 * pause the data on the HW queue.
 * part of the vap unpause , unpause all the nodes.
 */
static int ath_net80211_vap_pause_control (struct ieee80211com *ic, struct ieee80211vap *vap, bool pause)
{

    struct ath_vap_net80211 *avn;
    int if_id=ATH_IF_ID_ANY;
    struct pause_control_data pctrl_data;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    if (vap) {
        avn = ATH_VAP_NET80211(vap);
        if_id = avn->av_if_id;
        DPRINTF(scn, ATH_DEBUG_ANY, "%s : vap id %d \n", __func__,vap->iv_unit);
    }

    pctrl_data.vap = vap;
    pctrl_data.ic = ic;
    pctrl_data.pause = pause;
   /*
    * iterate all the nodes and issue the pause/unpause request.
    */
    ieee80211_iterate_node(ic, pause_control_cb, &pctrl_data );

    /* pause the vap data on the txq */
#ifdef ATH_SUPPORT_HTC
     ASSERT(scn->sc_ops->ath_wmi_pause_ctrl);
    if (vap) {
        struct ieee80211_node *ni = ieee80211vap_get_bssnode(vap);

        if (ni)
            scn->sc_ops->ath_wmi_pause_ctrl(scn->sc_dev, ((struct ath_node_net80211 *)ni)->an_sta, pause);
    }
#else
    scn->sc_ops->ath_vap_pause_control(scn->sc_dev, if_id, pause);
#endif

    return 0;

}
#if ATH_SUPPORT_WIFIPOS

/*
 * Functionality: To pause all the node in current vap
 */
static void
ath_net80211_pause_node(struct ieee80211com *ic, struct ieee80211_node *ni, bool pause)
{
    struct ath_vap_net80211 *avn;
    int if_id=ATH_IF_ID_ANY;
    struct pause_control_data pctrl_data;
    struct ieee80211vap *vap;
    vap = TAILQ_FIRST(&(ic)->ic_vaps) ;

        if (vap) {
            avn = ATH_VAP_NET80211(vap);
            if_id = avn->av_if_id;
        }

        pctrl_data.vap = vap;
        pctrl_data.ic = ic;
        pctrl_data.pause = pause;
        /*
         * iterate all the nodes and issue the pause/unpause request.
         */
        if(ni) {
           pause_control_cb(&pctrl_data, ni);
        } else {
            ieee80211_iterate_node(ic, pause_control_cb, &pctrl_data);
        }
}


#endif


#ifdef ATH_TX99_DIAG
static struct ieee80211_channel *
ath_net80211_find_channel(struct ath_softc *sc, int ieee, u_int8_t des_cfreq2, enum ieee80211_phymode mode)
{
    struct ieee80211com *ic = (struct ieee80211com *)sc->sc_ieee;
    return ieee80211_find_dot11_channel(ic, ieee, des_cfreq2, mode);
}
#endif

/*
 * disable rxrifs if STA,AP has both rifs and ldpc enabled.
 * ic_ldpcsta_assoc used to count ldpc sta associated and enable
 * rxrifs back if no ldpc sta is associated.
 */

static void ath_net80211_enablerifs_ldpcwar(struct ieee80211_node *ni, bool value)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    if (0 == scn->sc_ops->have_capability(scn->sc_dev, ATH_CAP_LDPCWAR))
    {
       if (vap->iv_opmode == IEEE80211_M_HOSTAP)
       {
            if (!value)
                ic->ic_ldpcsta_assoc++;
            else
                ic->ic_ldpcsta_assoc--;

            if (ic->ic_ldpcsta_assoc)
                value = 0;
            else
                value = 1;
       }
       scn->sc_ops->set_rifs(scn->sc_dev, value);
    }
}

static void
ath_net80211_set_stbcconfig(ieee80211_handle_t ieee, u_int8_t stbc, u_int8_t istx)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    u_int16_t htcap_flag = 0;

    if(istx) {
        htcap_flag = IEEE80211_HTCAP_C_TXSTBC;
    } else {
        struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
        struct ath_softc *sc = ATH_DEV_TO_SC(scn->sc_dev);
        u_int32_t supported = 0;

        if (ath_hal_rxstbcsupport(sc->sc_ah, &supported)) {
            htcap_flag = IEEE80211_HTCAP_C_RXSTBC & (supported << IEEE80211_HTCAP_C_RXSTBC_S);
        }
    }

    if(stbc) {
        ieee80211com_set_htcap(ic, htcap_flag);
    } else {
        ieee80211com_clear_htcap(ic, htcap_flag);
    }
}

static void
ath_net80211_set_ldpcconfig(ieee80211_handle_t ieee, u_int8_t ldpc)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    u_int16_t htcap_flag = IEEE80211_HTCAP_C_ADVCODING;
    u_int32_t supported = 0;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_softc *sc = ATH_DEV_TO_SC(scn->sc_dev);

#if ATH_SUPPORT_WRAP
    if (sc->sc_enableproxysta) {
        /*
         * When aggregation and decryption are used in ProxySTA mode, we
         * see hardware false ACK some subframes (within AMPDU) although
         * they are received with CRC errors. After disabling LDPC (which
         * burst pushing frames from BB to hardware MAC), the problem
         * goes away. Disabling LDPC makes WASP 1.3 and Peacock throughput
         * hit line rate.
         */
        ieee80211com_clear_htcap(ic, htcap_flag);
        ieee80211com_set_ldpccap(ic, HAL_LDPC_NONE);
    } else
#endif
    if (ldpc && ath_hal_ldpcsupport(sc->sc_ah, &supported))
    {
        if ((ldpc & HAL_LDPC_RX) && (supported & HAL_LDPC_RX))
        ieee80211com_set_htcap(ic, htcap_flag);
        else
            ieee80211com_clear_htcap(ic, htcap_flag);
        if ((supported & ldpc) == ldpc)
            ieee80211com_set_ldpccap(ic, ldpc);
        else
            ieee80211com_set_ldpccap(ic, HAL_LDPC_NONE);
    } else {
        ieee80211com_clear_htcap(ic, htcap_flag);
        ieee80211com_set_ldpccap(ic, HAL_LDPC_NONE);
    }
}

#if ATH_ANT_DIV_COMB
static void ath_vap_sa_normal_scan_handle(struct ieee80211vap *vap, enum ieee80211_state_event event)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    if (event == IEEE80211_STATE_EVENT_SCAN_START)
        scn->sc_ops->ath_sa_normal_scan_handle(scn->sc_dev, 1);
    else if (event == IEEE80211_STATE_EVENT_SCAN_END)
        scn->sc_ops->ath_sa_normal_scan_handle(scn->sc_dev, 0);

}
#endif

/*
 * Determine if hw beacon processing is active.
 *
 * If hw beacon processing is in use, then beacons are not passed
 * to software unless there is a change in the beacon
 * (i.e. the hw computed CRC changes).
 *
 * Hw beacon processing is only active if
 * - there is a single active STA VAP
 * - the hardware supports hw beacon processing (Osprey and later)
 * - software is configured for hw beacon processing
 */
static int ath_net80211_is_hwbeaconproc_active(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->get_hwbeaconproc_active(scn->sc_dev);
}

/*
 * Enable beacon RSSI threshold notification.
 *
 * When the hardware's average beacon RSSI falls below the given threshold,
 * the notification function ath_net80211_notify_beacon_rssi() is called.
 *
 */
static void ath_net80211_hw_beacon_rssi_threshold_enable(struct ieee80211com *ic,
                                            u_int32_t rssi_threshold)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->hw_beacon_rssi_threshold_enable(scn->sc_dev, rssi_threshold);
}

/*
 * Disable beacon RSSI threshold notification.
 *
 */
static void ath_net80211_hw_beacon_rssi_threshold_disable(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    scn->sc_ops->hw_beacon_rssi_threshold_disable(scn->sc_dev);
}

static void ath_net80211_process_uapsd_trigger(struct ieee80211com *ic, struct ieee80211_node *ni, bool enforce_max_sp, bool *sent_eosp)
{
    ath_net80211_uapsd_process_uapsd_trigger((void *) ic, ni, enforce_max_sp, sent_eosp);
}

#if UMAC_SUPPORT_VI_DBG
static void ath_net80211_set_vi_dbg_restart(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    if (scn->sc_ops->ath_set_vi_dbg_restart) {
        scn->sc_ops->ath_set_vi_dbg_restart(scn->sc_dev);
    }
}

static void ath_net80211_set_vi_dbg_log(struct ieee80211com *ic, bool enable)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    if (scn->sc_ops->ath_set_vi_dbg_log) {
        scn->sc_ops->ath_set_vi_dbg_log(scn->sc_dev, enable);
    }
}
#endif

static void ath_net80211_set_noise_detection_param(struct ieee80211com *ic, int cmd,int val)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    if (scn->sc_ops->set_noise_detection_param) {
        scn->sc_ops->set_noise_detection_param(scn->sc_dev,cmd,val);
    }
    return ;
}


static void ath_net80211_get_noise_detection_param(struct ieee80211com *ic, int cmd,int *val)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    if (scn->sc_ops->get_noise_detection_param) {
        scn->sc_ops->get_noise_detection_param(scn->sc_dev,cmd,val);
    }
    return ;
}

static void ath_config_rx_intr_mitigation(struct ieee80211com *ic,u_int32_t enable)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    if (scn->sc_ops->conf_rx_intr_mit) {
        scn->sc_ops->conf_rx_intr_mit(scn->sc_dev,enable);
    }
    return;
}
static u_int32_t ath_net80211_get_txbuf_free(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    if (scn->sc_ops->get_txbuf_free) {
       return scn->sc_ops->get_txbuf_free(scn->sc_dev);
    }
       return 0;
}

#if ATH_SUPPORT_HYFI_ENHANCEMENTS
int ath_net80211_add_hmmc(struct ieee80211vap *vap, u_int32_t ip, u_int32_t mask)
{
    int i;
    struct ieee80211com *ic = vap->iv_ic;
    int action = IGMP_ACTION_ADD_MEMBER, wildcard = IGMP_WILDCARD_SINGLE;

    if (!ic || !ip || !mask ||
            ((ip & htobe32(0xf0000000)) != htobe32(0xe0000000)))
        return -EINVAL;

    for (i = 0; i < ic->ic_hmmc_cnt; i++) {
        if (ic->ic_hmmcs[i].ip == ip)
            break;
    }
    if (i != ic->ic_hmmc_cnt) {
        ic->ic_hmmcs[i].ip = ip;
        ic->ic_hmmcs[i].mask = mask;
        return 0;
    }
    if (ic->ic_hmmc_cnt < ATH_HMMC_CNT_MAX) {
        ic->ic_hmmcs[ic->ic_hmmc_cnt].ip = ip;
        ic->ic_hmmcs[ic->ic_hmmc_cnt].mask = mask;
		if(ic->ic_is_mode_offload(ic))
	    	ic->ic_mcast_group_update(ic, action, wildcard, (u_int8_t *)&ic->ic_hmmcs[ic->ic_hmmc_cnt].ip,
                                      IGMP_IP_ADDR_LENGTH, NULL, 0, 0, NULL, (u_int8_t *)&ic->ic_hmmcs[ic->ic_hmmc_cnt].mask, vap->iv_unit);
        ic->ic_hmmc_cnt++;
        return 0;
    }
    return -1;
}

int ath_net80211_del_hmmc(struct ieee80211vap *vap, u_int32_t ip, u_int32_t mask)
{
    struct ieee80211com *ic = vap->iv_ic;
    int i, hmmc_size = sizeof(ic->ic_hmmcs) / ATH_HMMC_CNT_MAX;
    int action = IGMP_ACTION_DELETE_MEMBER, wildcard = IGMP_WILDCARD_ALL;

    if (!ic || !ip || !mask)
        return -EINVAL;

    if (!ic->ic_hmmc_cnt)
        return 0;

    for (i = 0; i < ic->ic_hmmc_cnt; i++) {
        if (ic->ic_hmmcs[i].ip == ip &&
                ic->ic_hmmcs[i].mask == mask)
            break;
    }

    if (i == ic->ic_hmmc_cnt)
        return -EINVAL;

	if(ic->ic_is_mode_offload(ic))
   		ic->ic_mcast_group_update(ic, action, wildcard, (u_int8_t *)&ip,
                                      IGMP_IP_ADDR_LENGTH, NULL, 0, 0, NULL, NULL, vap->iv_unit);
    OS_MEMCPY(&ic->ic_hmmcs[i], &ic->ic_hmmcs[i+1],
            (ic->ic_hmmc_cnt - i - 1) * hmmc_size );
    ic->ic_hmmc_cnt--;

    return 0;
}
#endif

static u_int32_t ath_net80211_get_total_per(ieee80211_handle_t ieee)
{
    /* Implemented here instead of lmac, so that it is available to
       umac code if required. */
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    /* TODO: Receive values as u_int64_t and handle the division */
    u_int32_t failures = ic->ic_get_tx_hw_retries(ic);
    u_int32_t success  = ic->ic_get_tx_hw_success(ic);

    if ((success + failures) == 0) {
        return 0;
    }

    return ((failures * 100) / (success + failures));
}

u_int64_t ath_net80211_get_tx_hw_retries(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->get_tx_hw_retries(scn->sc_dev);
}

u_int64_t ath_net80211_get_tx_hw_success(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->get_tx_hw_success(scn->sc_dev);
}

#if UMAC_SUPPORT_WNM
struct ath_iter_update_timbcastalloc_arg {
    struct ieee80211com *ic;
    int if_id;
    wbuf_t wbuf;
    int highrate;
    ieee80211_tx_control_t *txctl;
};

static void ath_vap_iter_timbcast_alloc(void *arg, wlan_if_t vap)
{
    struct ath_iter_update_timbcastalloc_arg* params = (struct ath_iter_update_timbcastalloc_arg *) arg;
    struct ath_vap_net80211 *avn;
    struct ieee80211_node *ni;
#define USE_SHPREAMBLE(_ic)                   \
    (IEEE80211_IS_SHPREAMBLE_ENABLED(_ic) &&  \
     !IEEE80211_IS_BARKER_ENABLED(_ic))

    if ((ATH_VAP_NET80211(vap))->av_if_id == params->if_id) {
        ni = vap->iv_bss;
        avn = ATH_VAP_NET80211(vap);
        params->wbuf = ieee80211_timbcast_alloc(ni);
        if (USE_SHPREAMBLE(vap->iv_ic)) {
            params->txctl->shortPreamble = 1;
        }
        if (params->highrate) {
            params->txctl->min_rate = ieee80211_timbcast_get_highrate(vap);
        } else {
            params->txctl->min_rate = ieee80211_timbcast_get_lowrate(vap);
        }
        /* send this frame to hardware */
        params->txctl->an = (ATH_NODE_NET80211(ni))->an_sta;
    }

}

static wbuf_t
ath_net80211_timbcast_alloc(ieee80211_handle_t ieee, int if_id, int highrate, ieee80211_tx_control_t *txctl)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ath_iter_update_timbcastalloc_arg params;

    ASSERT(if_id != ATH_IF_ID_ANY);

    params.ic = ic;
    params.if_id = if_id;
    params.wbuf = NULL;
    params.highrate = highrate;
    params.txctl = txctl;

    wlan_iterate_vap_list(ic,ath_vap_iter_timbcast_alloc,(void *) &params);
    return params.wbuf;

}

static int
ath_net80211_timbcast_update(ieee80211_handle_t ieee, int if_id, wbuf_t wbuf)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ieee80211vap *vap = NULL;
    struct ath_vap_net80211 *avn;
    int error = 0;

    ASSERT(if_id != ATH_IF_ID_ANY);

    /*
     * get a vap with the given id.
     * this function is called from SWBA.
     * in most of the platform this is directly called from
     * the interrupt handler, so we need to find our vap without using any
     * spin locks.
     */

    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if ((ATH_VAP_NET80211(vap))->av_if_id == if_id) {
            break;
        }
    }

    if (vap == NULL)
        return -EINVAL;

    avn = ATH_VAP_NET80211(vap);
    error = ieee80211_timbcast_update(vap->iv_bss, &avn->av_beacon_offsets,
                                    wbuf);
    return error;
}

static int
ath_net80211_timbcast_highrate(ieee80211_handle_t ieee, int if_id)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ieee80211vap *vap = NULL;

    ASSERT(if_id != ATH_IF_ID_ANY);

    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if ((ATH_VAP_NET80211(vap))->av_if_id == if_id) {
            break;
        }
    }

    if (vap == NULL)
        return -EINVAL;

    return ieee80211_timbcast_highrateenable(vap);
}

static int
ath_net80211_timbcast_lowrate(ieee80211_handle_t ieee, int if_id)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ieee80211vap *vap = NULL;

    ASSERT(if_id != ATH_IF_ID_ANY);

    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if ((ATH_VAP_NET80211(vap))->av_if_id == if_id) {
            break;
        }
    }

    if (vap == NULL)
        return -EINVAL;

    return ieee80211_timbcast_lowrateenable(vap);
}

static int
ath_net80211_timbcast_cansend(ieee80211_handle_t ieee, int if_id)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ieee80211vap *vap = NULL;

    ASSERT(if_id != ATH_IF_ID_ANY);

    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if ((ATH_VAP_NET80211(vap))->av_if_id == if_id) {
            break;
        }
    }

    if (vap == NULL)
        return -EINVAL;

    return (ieee80211_wnm_timbcast_cansend(vap));
}

static int
ath_net80211_wnm_fms_enabled(ieee80211_handle_t ieee, int if_id)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ieee80211vap *vap = NULL;

    ASSERT(if_id != ATH_IF_ID_ANY);

    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if ((ATH_VAP_NET80211(vap))->av_if_id == if_id) {
            break;
        }
    }

    if (vap == NULL)
        return -EINVAL;

    return (ieee80211_wnm_fms_enabled(vap));
}

static int
ath_net80211_timbcast_enabled(ieee80211_handle_t ieee, int if_id)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ieee80211vap *vap = NULL;

    ASSERT(if_id != ATH_IF_ID_ANY);

    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if ((ATH_VAP_NET80211(vap))->av_if_id == if_id) {
            break;
        }
    }

    if (vap == NULL)
        return -EINVAL;

    return (ieee80211_wnm_timbcast_enabled(vap));
}

#endif


#if ATH_SUPPORT_FLOWMAC_MODULE
int
ath_net80211_get_flowmac_enabled_state(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    return scn->sc_ops->get_flowmac_enabled_state(scn->sc_dev);
}
#endif
static int ath_net80211_get_rx_signal_dbm(struct ieee80211com *ic, int8_t *signal_dbm) {
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

    return scn->sc_ops->get_rx_signal_dbm(scn->sc_dev, signal_dbm);
}
int ath_net80211_dfs_proc_phyerr(ieee80211_handle_t ieee, void *buf, u_int16_t datalen, u_int8_t rssi,
                        u_int8_t ext_rssi, u_int32_t rs_tstamp, u_int64_t full_tsf)
{
#ifdef ATH_SUPPORT_DFS
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    dfs_process_phyerr(ic, buf, datalen, rssi, ext_rssi, rs_tstamp, full_tsf);
#else
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s[%d] DFS not defined yet got radar pulse\n", __func__, __LINE__);
#endif
    return 0;
}
#ifdef ATH_SUPPORT_DFS
int ath_net80211_attach_dfs(struct ieee80211com *ic, void *pCap, void *radar_info)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->ath_attach_dfs(scn->sc_dev, pCap, radar_info);
}
int ath_net80211_detach_dfs(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->ath_detach_dfs(scn->sc_dev);
}

/*
 * XXX TODO: change this API to take ath_dfs_phyerr_param or something
 * that's umac/ic abstraction happy. It should NOT take a void pointer -
 *  that makes it impossible to do runtime type checking.
 */
int ath_net80211_enable_dfs(struct ieee80211com *ic, int *is_fastclk, void *p)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_dfs_phyerr_param *pe = (struct ath_dfs_phyerr_param *) p;
    HAL_PHYERR_PARAM ph;

    OS_MEMZERO(&ph, sizeof(ph));

    ath_dfs_dfsparam_to_halparam(pe, &ph);

    return scn->sc_ops->ath_enable_dfs(scn->sc_dev, is_fastclk, &ph);
}
int ath_net80211_disable_dfs(struct ieee80211com *ic, int no_cac)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
    if (no_cac == 0) {
        if(ic->ic_opmode == IEEE80211_M_STA) {
        } else {
            ieee80211_dfs_cac_cancel(ic);
        }
    }
#else
    if (no_cac == 0)
        ieee80211_dfs_cac_cancel(ic);
#endif
    return scn->sc_ops->ath_disable_dfs(scn->sc_dev);
}
void ath_net80211_dfs_rx_rcsa(struct ieee80211com *ic)
{
    dfs_rx_rcsa(ic);
}
void ath_net80211_dfs_cancel_waitfor_csa_timer(struct ieee80211com *ic)
{
    dfs_cancel_waitfor_csa_timer(ic);
}


/*
 * XXX for now, just use a void * pointer; later on it should be
 * the shared PHY configuration parameters.
 */
int
ath_net80211_dfs_get_thresholds(struct ieee80211com *ic, void *p)
{
    HAL_PHYERR_PARAM ph;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    int retval;
    struct ath_dfs_phyerr_param *pe = (struct ath_dfs_phyerr_param *) p;

    OS_MEMZERO(&ph, sizeof(ph));

    retval = scn->sc_ops->ath_get_radar_thresholds(scn->sc_dev, &ph);
    if (retval != 0)
        return (retval);

    ath_dfs_halparam_to_dfsparam(&ph, pe);

    return (0);
}

/*
 * Update the channel list with the given NOL list.
 *
 * Since the NOL can contain entries which may match multiple
 * channels, we need to walk the channel list to ensure that
 * we correctly update _all_ channel entries in question.
 */
static void
ath_net80211_dfs_clist_update(struct ieee80211com *ic, int cmd,
    struct dfs_nol_chan_entry *nollist, int nentries)
{
	struct ieee80211_channel *chan;
	int i, j;
	int nol_found = 0;

	qdf_print("%s: called, cmd=%d, nollist=%p, nentries=%d\n",
	    __func__, cmd, nollist, nentries);

	/* XXX for now, only handle DFS_NOL_CLIST_CMD_UPDATE. */
	if (cmd != DFS_NOL_CLIST_CMD_UPDATE) {
		qdf_print("%s: cmd=%d, not handled!\n", __func__, cmd);
		return;
	}

	ieee80211_enumerate_channels(chan, ic, i) {
		/* XXX break into a shared function */
		nol_found = 0;
		for (j = 0; j < nentries; j++) {
			if (ieee80211_check_channel_overlap(ic, chan,
			    nollist[j].nol_chfreq, nollist[j].nol_chwidth)) {
				nol_found = 1;
				/*
				 * XXX break here for now; but later on when
				 * we're keeping a NOL timer per umac channel,
				 * we'll want to walk _all_ the NOL entries
				 * to find the maximum NOL time we need; then
				 * potentially update the NOL time for that
				 * umac channel.
				 */
				break;
			}
		}

		/*
		 * Dump out state transitions for now!
		 */
		if (nol_found && (! IEEE80211_IS_CHAN_RADAR(chan)))
			qdf_print("%s: radar found = chan=%p, freq=%d, "
			    "vht freq1=%d, freq2=%d, flags=0x%x\n",
			    __func__,
			    chan,
			    chan->ic_freq,
			    ieee80211_ieee2mhz(ic, chan->ic_vhtop_ch_freq_seg1, chan->ic_flags),
			    ieee80211_ieee2mhz(ic, chan->ic_vhtop_ch_freq_seg2, chan->ic_flags),
			    chan->ic_flags);
		else if ((! nol_found) && IEEE80211_IS_CHAN_RADAR(chan))
			qdf_print("%s: NOL clear = chan=%p, freq=%d, "
			    "vht freq1=%d, freq2=%d, flags=0x%x\n",
			    __func__,
			    chan,
			    chan->ic_freq,
			    ieee80211_ieee2mhz(ic, chan->ic_vhtop_ch_freq_seg1, chan->ic_flags),
			    ieee80211_ieee2mhz(ic, chan->ic_vhtop_ch_freq_seg2, chan->ic_flags),
			    chan->ic_flags);

		/*
		 * Now that we know whether there's a NOL entry overlapping
		 * this channel, let's set or clear the bits appropriately.
		 *
		 * XXX TODO: track the NOL timeout and if it's different
		 * to what's in the HAL channel, update the HAL by calling
		 * ath_hal_dfsfound() appropriately.
		 *
		 * XXX TODO: come up with a way to link back to the
		 * underlying HAL_CHANNEL.  Right now there's no way
		 * in this driver to translate between ieee80211_channel
		 * and the HAL_CHANNEL that it matches.
		 *
		 * For reference, the lmac/ath_dev code doesn't ever
		 * reference HAL_CHANNEL except when setting up the
		 * umac channel list.  sc->sc_curchan isn't a pointer
		 * to a HAL_CHANNEL, it's a synthesised copy of it.
		 * So setting CHANNEL_INTERFERENCE will only affect
		 * the current operating channel until the channel
		 * is changed - and at that point sc_curchan gets
		 * reset.  It's good enough for the TX to be aborted
		 * as the TX path checksc sc->sc_curchan, but it won't
		 * change anything permanent in HAL_CHANNEL.
		 */
		if (nol_found) {
			IEEE80211_CHAN_SET_RADAR(chan);
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
            /* The history information is permannent .If the
               not_found is false then we may clear earlier
               history. So do not clear the channel radar history */
			IEEE80211_CHAN_SET_HISTORY_RADAR(chan);
#endif
		} else {
			IEEE80211_CHAN_CLR_RADAR(chan);
		}
	}
    ic->ic_flags |= IEEE80211_F_DFS_CHANSWITCH_PENDING;
}

 int ath_net80211_get_mib_cycle_counts_pct(struct ieee80211com *ic,
                                u_int32_t *rxc_pcnt, u_int32_t *rxf_pcnt, u_int32_t *txf_pcnt)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->get_extbusyper(scn->sc_dev);
}

 int ath_net80211_get_ext_busy(struct ieee80211com *ic)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    return scn->sc_ops->get_extbusyper(scn->sc_dev);
}
#endif /* ATH_SUPPORT_DFS */

#if UNIFIED_SMARTANTENNA
static void ath_net80211_smart_ant_enable(struct ieee80211com *ic, uint32_t enable, uint32_t mode, uint32_t rx_antenna)
{
     struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
     if (scn->sc_ops->smart_ant_enable) {
        scn->sc_ops->smart_ant_enable(scn->sc_dev, enable, mode);
     }
    /* set RX antenna */
     if (scn->sc_ops->set_defaultantenna) {
        scn->sc_ops->set_defaultantenna(scn->sc_dev, rx_antenna);
     }
}

static int ath_net80211_smart_ant_update_txfeedback(struct ieee80211_node *ni, void *tx_feedback)
{
    int status = 0, i = 0;
    struct  sa_tx_feedback  *feedback = (struct  sa_tx_feedback *) tx_feedback;

    if (ni->ni_chwidth == IEEE80211_CWM_WIDTH40) {
        for (i=0; i<=ni->ni_ic->max_fallback_rates; i++) {
            feedback->rate_mcs[i] = ieee80211_smart_ant_convert_rate_5g(feedback->rate_mcs[i]);
            feedback->rate_mcs[i] = (feedback->rate_mcs[i] << 8);
        }
    } else {
        for (i=0; i<=ni->ni_ic->max_fallback_rates; i++) {
            feedback->rate_mcs[i] = ieee80211_smart_ant_convert_rate_5g(feedback->rate_mcs[i]);
        }
    }

    status = ieee80211_smart_ant_update_txfeedback(ni, tx_feedback);
    return status;
}

static int ath_net80211_smart_ant_update_rxfeedback(ieee80211_handle_t ieee, wbuf_t wbuf, void *rx_feedback)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ieee80211_node *ni = NULL;
    struct sa_rx_feedback *feedback = (struct sa_rx_feedback *)rx_feedback;
    int status = -1;
    ni = ieee80211_find_rxnode(ic, (struct ieee80211_frame_min *)wbuf_header(wbuf));
    if (ni == NULL)  {
        return -1;
    } else {
        if (ni->ni_chwidth == IEEE80211_CWM_WIDTH40) {
            feedback->rx_rate_mcs = ieee80211_smart_ant_convert_rate_5g(feedback->rx_rate_mcs);
            feedback->rx_rate_mcs = (feedback->rx_rate_mcs << 8);
        } else {
            feedback->rx_rate_mcs = ieee80211_smart_ant_convert_rate_5g(feedback->rx_rate_mcs);
        }

        status = ieee80211_smart_ant_update_rxfeedback(ni, rx_feedback);
        ieee80211_free_node(ni);
    }
    return status;
}
static void ath_net80211_smart_ant_set_rx_antenna(struct ieee80211com *ic, u_int32_t antenna)
{
     struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

     /*If LMAC has smart antenna support */
     if (scn->sc_ops->set_defaultantenna) {
        scn->sc_ops->set_defaultantenna(scn->sc_dev, antenna);
     }
}

static void ath_net80211_smart_ant_set_node_config_ops(struct ieee80211_node *ni, uint32_t cmd_id, uint16_t args_count, u_int32_t args_arr[])
{
    /* Do nothing for now. */
    return;
}

static void ath_net80211_smart_ant_set_tx_antenna(struct ieee80211_node *ni, u_int32_t *antenna_array)
{
     struct ieee80211com *ic = ni->ni_ic;
     struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
     struct ath_node_net80211 *an = (struct ath_node_net80211 *)ni;

     /*If LMAC has smart antenna support */
     if (scn->sc_ops->smart_ant_set_tx_antenna) {
         scn->sc_ops->smart_ant_set_tx_antenna(an->an_sta, antenna_array, (ic->max_fallback_rates+1));
     }
}

static void ath_net80211_smart_ant_set_tx_default_antenna(struct ieee80211com *ic, u_int32_t antenna)
{
     struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);

     /*If LMAC has smart antenna support */
     if (scn->sc_ops->smart_ant_set_tx_defaultantenna) {
        scn->sc_ops->smart_ant_set_tx_defaultantenna(scn->sc_dev, antenna);
     }

}

static void ath_net80211_smart_ant_set_training_info(struct ieee80211_node *ni, uint32_t *rate_array, uint32_t *antenna_array, uint32_t numpkts)
{
     struct ieee80211com *ic = ni->ni_ic;
     struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
     struct ath_node_net80211 *an = (struct ath_node_net80211 *)ni;
     int i = 0;

     if (ni->ni_chwidth == IEEE80211_CWM_WIDTH40) {
         for (i=0; i<=ic->max_fallback_rates; i++) {
             rate_array[i] = (rate_array[i] >> 8);
         }
     }

     for (i=0; i<=ic->max_fallback_rates; i++) {
         rate_array[i] = ieee80211_smart_ant_convert_rate_2g(rate_array[i]);
     }

     /*If LMAC has smart antenna support */
     if (scn->sc_ops->smart_ant_set_training_info) {
         scn->sc_ops->smart_ant_set_training_info(an->an_sta, rate_array, antenna_array, numpkts);
     }
}

static void ath_net80211_smart_ant_prepare_rateset(struct ieee80211com *ic,
                struct ieee80211_node *ni, struct sa_rate_info *rate_info)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_node_net80211 *an = (struct ath_node_net80211 *)ni;

    /*If LMAC has smart antenna support */
    if (scn->sc_ops->smart_ant_prepare_rateset) {
        scn->sc_ops->smart_ant_prepare_rateset(scn->sc_dev, an->an_sta, rate_info);
    }
}

static int ath_net80211_smart_ant_setparam(ieee80211_handle_t ieee, char *params)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    int status;
    status = ieee80211_smart_ant_set_param(ic, params);
    return status;
}

static int ath_net80211_smart_ant_getparam(ieee80211_handle_t ieee, char *params)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    uint32_t value = 0;
    value = ieee80211_smart_ant_get_param(ic, params);
    return value;
}

#endif
static void
ath_net80211_restore_encr_keys(ieee80211_handle_t ieee)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ieee80211vap *vap = NULL;

    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if (vap) {
            wlan_restore_keys(vap);
        }
    }
}

#if ATH_SUPPORT_TIDSTUCK_WAR
static void ath_net80211_clear_rxtid(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    ath_node_t node = ATH_NODE_NET80211(ni)->an_sta;
    scn->sc_ops->clear_rxtid(scn->sc_dev, node);
}

static void ath_net80211_rxtid_delba(ieee80211_node_t node, u_int8_t tid)
{
    struct ieee80211_node *ni = (struct ieee80211_node *)node;
    struct ieee80211_action_mgt_args actionargs;

    /* Send DELBA request */
    actionargs.category = IEEE80211_ACTION_CAT_BA;
    actionargs.action   = IEEE80211_ACTION_BA_DELBA;
    actionargs.arg1     = tid;
    actionargs.arg2     = 0;                                /* initiator */
    actionargs.arg3     = IEEE80211_REASON_QOS_TIMEOUT;     /* reasoncode */

    ieee80211_send_action(ni, &actionargs, NULL);
}
#endif

static int
ath_net80211_wds_is_enabled(ieee80211_handle_t ieee)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ieee80211vap *vap = NULL;
    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if(vap){
            if(IEEE80211_VAP_IS_WDS_ENABLED(vap)){
                return 1;
            }
#ifdef ATH_EXT_AP
            if (IEEE80211_VAP_IS_EXT_AP_ENABLED(vap)) {
                return 1;
            }
#endif
        }
    }
    return 0;
}


static WIRELESS_MODE ath_net80211_get_vap_bss_mode(ieee80211_handle_t ieee, ieee80211_node_t node)
{
    struct ieee80211_node *ni = (struct ieee80211_node *)node;
    struct ieee80211vap *vap = ni->ni_vap;

    return ath_ieee2wmode(ieee80211_chan2mode(vap->iv_bsschan));
}

static int
ath_net80211_acs_set_param(ieee80211_handle_t ieee, int param, int val)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);

    ieee80211_acs_set_param(ic->ic_acs, param,  val );
    return 0;
}
static int
ath_net80211_acs_get_param(ieee80211_handle_t ieee,int param)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);

    return  ieee80211_acs_get_param(ic->ic_acs, param );
}
#if ATH_TxBF_DYNAMIC_LOF_ON_N_CHAIN_MASK
static void  ath_net80211_txbf_loforceon_update(struct ieee80211com *ic,bool loforcestate)
{
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    if(scn->sc_ops->txbf_loforceon_update)
        scn->sc_ops->txbf_loforceon_update(scn->sc_dev,loforcestate);
}
#endif
static int
ath_net80211_set_enable_min_rssi(ieee80211_handle_t ieee, u_int8_t val)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    if(!!val)
       ic->ic_min_rssi_enable = true;
    else
       ic->ic_min_rssi_enable = false;
    return 1;
}

static u_int8_t
ath_net80211_get_enable_min_rssi(ieee80211_handle_t ieee)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    return ic->ic_min_rssi_enable;
}

static int
ath_net80211_set_min_rssi(ieee80211_handle_t ieee, int rssi)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    if( !(ic->ic_min_rssi_enable) ) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Cannot set, feature not enabled\n");
        return -1;
    }
    ic->ic_min_rssi = rssi;
    return 1;
}

static int
ath_net80211_get_min_rssi(ieee80211_handle_t ieee)
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    return ic->ic_min_rssi;
}
static void ath_net80211_node_pspoll(struct ieee80211_node *ni,bool value)
{
	struct ieee80211com *ic = ni->ni_ic;
	struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
	ath_node_t node = ATH_NODE_NET80211(ni)->an_sta;
	scn->sc_ops->node_pspoll(scn->sc_dev, node, value);
	ni->ni_pspoll = value;

}

static int
ath_net80211_tr69_get_fail_retrans_cnt(struct ieee80211vap *vap, u_int32_t *failretranscnt)
{
    struct ieee80211com *ic;
    struct ath_softc_net80211 *scn;
    struct ath_softc *sc;
    struct ath_vap_net80211 *avn;
    struct ath_vap_dev_stats vapstats;

    if (!vap)
        return -1;
    ic = vap->iv_ic;

    if (!ic)
        return -1;
    scn = ATH_SOFTC_NET80211(ic);

    if (!scn)
        return -1;
    sc = ATH_DEV_TO_SC(scn->sc_dev);

    if (!sc)
        return -1;
    avn  = ATH_VAP_NET80211(vap);

    if (!avn)
        return -1;

    scn->sc_ops->get_vap_stats(scn->sc_dev, avn->av_if_id, &vapstats);
    *failretranscnt = vapstats.av_tx_xretries;

    return 0;
}

static int
ath_net80211_tr69_get_retry_cnt(struct ieee80211vap *vap, u_int32_t *retranscnt)
{
    struct ieee80211com *ic;
    struct ath_softc_net80211 *scn;
    struct ath_softc *sc;
    struct ath_vap_net80211 *avn;
    struct ath_vap_dev_stats vapstats;

    if (!vap)
        return -1;
    ic = vap->iv_ic;

    if (!ic)
        return -1;
    scn = ATH_SOFTC_NET80211(ic);

    if (!scn)
        return -1;
    sc = ATH_DEV_TO_SC(scn->sc_dev);

    if (!sc)
        return -1;
    avn  = ATH_VAP_NET80211(vap);

    if (!avn)
        return -1;

    scn->sc_ops->get_vap_stats(scn->sc_dev, avn->av_if_id, &vapstats);
    *retranscnt = vapstats.av_tx_retries;

    return 0;
}

static int
ath_net80211_tr69_get_mul_retry_cnt(struct ieee80211vap *vap, u_int32_t *retranscnt)
{
    struct ieee80211com *ic;
    struct ath_softc_net80211 *scn;
    struct ath_softc *sc;
    struct ath_vap_net80211 *avn;
    struct ath_vap_dev_stats vapstats;

    if (!vap)
        return -1;
    ic = vap->iv_ic;

    if (!ic)
        return -1;
    scn = ATH_SOFTC_NET80211(ic);

    if (!scn)
        return -1;
    sc = ATH_DEV_TO_SC(scn->sc_dev);

    if (!sc)
        return -1;
    avn  = ATH_VAP_NET80211(vap);

    if (!avn)
        return -1;

    scn->sc_ops->get_vap_stats(scn->sc_dev, avn->av_if_id, &vapstats);
    *retranscnt = vapstats.av_tx_mretries;

    return 0;
}

static int
ath_net80211_tr69_get_ack_fail_cnt(struct ieee80211vap *vap, u_int32_t *ackfailcnt)
{
    struct ieee80211com *ic;
    struct ath_softc_net80211 *scn;
    struct ath_softc *sc;
    struct ath_vap_net80211 *avn;
    struct ath_vap_dev_stats vapstats;

    if (!vap)
        return -1;
    ic = vap->iv_ic;

    if (!ic)
        return -1;
    scn = ATH_SOFTC_NET80211(ic);

    if (!scn)
        return -1;
    sc = ATH_DEV_TO_SC(scn->sc_dev);

    if (!sc)
        return -1;
    avn  = ATH_VAP_NET80211(vap);

    if (!avn)
        return -1;

    scn->sc_ops->get_vap_stats(scn->sc_dev, avn->av_if_id, &vapstats);
    *ackfailcnt = vapstats.av_ack_failures;

    return 0;
}

static int
ath_net80211_tr69_get_aggr_pkt_cnt(struct ieee80211vap *vap, u_int32_t *aggrpkts)
{
    struct ieee80211com *ic;
    struct ath_softc_net80211 *scn;
    struct ath_softc *sc;
    struct ath_vap_net80211 *avn;
    struct ath_vap_dev_stats vapstats;

    if (!vap)
        return -1;
    ic = vap->iv_ic;

    if (!ic)
        return -1;
    scn = ATH_SOFTC_NET80211(ic);

    if (!scn)
        return -1;
    sc = ATH_DEV_TO_SC(scn->sc_dev);

    if (!sc)
        return -1;
    avn  = ATH_VAP_NET80211(vap);

    if (!avn)
        return -1;

    scn->sc_ops->get_vap_stats(scn->sc_dev, avn->av_if_id, &vapstats);
    *aggrpkts = vapstats.av_aggr_pkt_count;

    return 0;
}

static int
ath_net80211_tr69_get_sta_bytes_sent(struct ieee80211vap *vap, u_int32_t *bytessent, u_int8_t *dstmac)
{
    struct ieee80211com *ic;
    struct ieee80211_node *ni = NULL;

    if (!vap)
        return -1;
    ic = vap->iv_ic;

    if (!ic)
        return -1;

    ni = ieee80211_find_node(&ic->ic_sta, dstmac);
    if (ni == NULL) {
        return -ENOENT;
    }
    *bytessent = ni->ni_stats.ns_tx_bytes_success;

    ieee80211_free_node(ni);
    return 0;
}

static int
ath_net80211_tr69_get_sta_bytes_rcvd(struct ieee80211vap *vap, u_int32_t *bytesrcvd, u_int8_t *dstmac)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_node *ni = NULL;

    ni = ieee80211_find_node(&ic->ic_sta, dstmac);
    if (ni == NULL) {
        return -ENOENT;
    }
    *bytesrcvd = ni->ni_stats.ns_rx_bytes;
    ieee80211_free_node(ni);
    return 0;
}

#if 0
static int
ath_net80211_tr69_get_data_sent_ack(struct ieee80211vap *vap, struct ieee80211req_athdbg *req)
{
    ieee80211req_tr069_t * reqptr = &req->data.tr069_req;
    u_int32_t *datasentack = (u_int32_t *)reqptr->data_addr;
    //    strncpy(plcperrcnt,vap->iv_basic_rates,strlen(vap->iv_basic_rates));
    return 0;
}

static int
ath_net80211_tr69_get_data_sent_noack(struct ieee80211vap *vap, struct ieee80211req_athdbg *req)
{
    ieee80211req_tr069_t * reqptr = &req->data.tr069_req;
    u_int32_t *datasentnoack = (u_int32_t *)reqptr->data_addr;
    //    strncpy(plcperrcnt,vap->iv_basic_rates,strlen(vap->iv_basic_rates));
    return 0;
}
#endif
static int
ath_net80211_tr69_get_chan_util(struct ieee80211vap *vap, u_int32_t *chanutil)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    u_int8_t ctlrxc, extrxc, rfcnt, tfcnt;
    u_int32_t chanbusy;

    chanbusy = scn->sc_ops->get_chbusyper(scn->sc_dev);

    ctlrxc = chanbusy & 0xff;
    extrxc = (chanbusy & 0xff00) >> 8;
    rfcnt = (chanbusy & 0xff0000) >> 16;
    tfcnt = (chanbusy & 0xff000000) >> 24;

    if (vap->iv_ic->ic_curchan->ic_flags & IEEE80211_CHAN_HT20)
        *chanutil = ctlrxc - tfcnt;
    else
        *chanutil = (ctlrxc + extrxc) - tfcnt;

    return 0;
}

static int
ath_net80211_tr69_get_retrans_cnt(struct ieee80211vap *vap, u_int32_t *retranscnt)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ath_softc_net80211 *scn = ATH_SOFTC_NET80211(ic);
    struct ath_softc *sc = ATH_DEV_TO_SC(scn->sc_dev);
    struct ath_vap_net80211 *avn = ATH_VAP_NET80211(vap);
    struct ath_vap_dev_stats vapstats;

    if (!avn || !sc)
        return -1;

    scn->sc_ops->get_vap_stats(scn->sc_dev, avn->av_if_id, &vapstats);
    *retranscnt = vapstats.av_retry_count;

    return 0;
}

static int ath_net80211_tr69_process_request(struct ieee80211vap *vap, int cmdid, void * arg1, void *arg2)
{
	switch(cmdid){
#if 0
        case IEEE80211_TR069_GET_PLCP_ERR_CNT:
			ath_net80211_tr69_get_plcp_err_cnt(dev, arg1);
            break;
        case IEEE80211_TR069_GET_FCS_ERR_CNT:
			ath_net80211_tr69_get_fcs_err_cnt(dev, arg1);
            break;
        case IEEE80211_TR069_GET_PKTS_OTHER_RCVD:
			ath_net80211_tr69_get_pkts_other_rcvd(dev, req);
            break;
#endif
        case IEEE80211_TR069_GET_FAIL_RETRANS_CNT:
			ath_net80211_tr69_get_fail_retrans_cnt(vap, arg1);
            break;
        case IEEE80211_TR069_GET_RETRY_CNT:
			ath_net80211_tr69_get_retry_cnt(vap, arg1);
            break;
        case IEEE80211_TR069_GET_MUL_RETRY_CNT:
			ath_net80211_tr69_get_mul_retry_cnt(vap, arg1);
            break;
        case IEEE80211_TR069_GET_ACK_FAIL_CNT:
			ath_net80211_tr69_get_ack_fail_cnt(vap, arg1);
            break;
        case IEEE80211_TR069_GET_AGGR_PKT_CNT:
			ath_net80211_tr69_get_aggr_pkt_cnt(vap, arg1);
            break;
        case IEEE80211_TR069_GET_STA_BYTES_SENT:
			ath_net80211_tr69_get_sta_bytes_sent(vap, arg1, arg2);
            break;
        case IEEE80211_TR069_GET_STA_BYTES_RCVD:
			ath_net80211_tr69_get_sta_bytes_rcvd(vap, arg1, arg2);
            break;
#if 0
        case IEEE80211_TR069_GET_DATA_SENT_ACK:
			ath_net80211_tr69_get_data_sent_ack(dev, arg1);
            break;
        case IEEE80211_TR069_GET_DATA_SENT_NOACK:
			ath_net80211_tr69_get_data_sent_noack(dev, req);
            break;
#endif
        case IEEE80211_TR069_GET_CHAN_UTIL:
			ath_net80211_tr69_get_chan_util(vap, arg1);
            break;
        case IEEE80211_TR069_GET_RETRANS_CNT:
			ath_net80211_tr69_get_retrans_cnt(vap, arg1);
            break;
        default:
			break;
    }
    return 0;
}

void da_reset_wifi(struct ath_softc *sc,struct ieee80211com *ic)
{

    if (init_sc_params(sc,sc->sc_ah))
        qdf_print("%s init sc params failed\n",__func__);

    sc->sc_no_tx_3_chains  = 0;
    init_sc_params_complete(sc,sc->sc_ah);
    ath_hal_factory_reset(sc->sc_ah);

#if ATH_TX_COMPACT
    sc->sc_nodebug =1;
#else
    sc->sc_nodebug =0;
#endif
#if ATH_SUPPORT_AGGR_BURST
    if(sc->sc_reg_parm.burstEnable) {
        sc->sc_aggr_burst = true;
        sc->sc_aggr_burst_duration = sc->sc_reg_parm.burstDur;
    } else {
        sc->sc_aggr_burst = false;
        sc->sc_aggr_burst_duration = ATH_BURST_DURATION;
    }
#endif
    sc->sc_is_blockdfs_set = false;
    sc->sc_config.ampdu_rx_bsize             = 0;
    sc->sc_config.txpowlimit_override        = sc->sc_reg_parm.overRideTxPower;
    sc->sc_config.pwscale                    = 0;
    sc->sc_noreset                           = 0;
    sc->sc_config.cabqReadytime              = ATH_CABQ_READY_TIME;
    sc->sc_config.tpscale                    = 0;
    /*
    ** Set aggregation protection mode parameters
    */

    sc->sc_config.ath_aggr_prot = sc->sc_reg_parm.aggrProtEnable;
    sc->sc_config.ath_aggr_prot_duration = sc->sc_reg_parm.aggrProtDuration;
    sc->sc_config.ath_aggr_prot_max = sc->sc_reg_parm.aggrProtMax;
    sc->sc_reg_parm.gpioLedCustom            = 0;
    sc->sc_reg_parm.swapDefaultLED           = 0;
#ifdef ATH_SUPPORT_TxBF
    sc->sc_reg_parm.TxBFSwCvTimeout          = 1000;
#endif
    sc->sc_reg_parm.burst_beacons            = 0;
#if UMAC_SUPPORT_SMARTANTENNA //check
    init_smartantenna_params(ic);
    /* do hardware level disable */
    ath_hal_set_smartantenna(sc->sc_ah, 0);
    sc->sc_smartant_enable                   = 0;
#endif
}
