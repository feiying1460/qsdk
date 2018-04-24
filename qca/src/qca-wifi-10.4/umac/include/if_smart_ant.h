/*
* Copyright (c) 2013 Qualcomm Atheros, Inc..
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.
*/

#ifndef __IF_SMARTANETNNA_H__
#define __IF_SMARTANETNNA_H__

#if UNIFIED_SMARTANTENNA

#define SMART_ANT_STATE_INIT_DONE 0x01
#define SMART_ANT_STATE_DEINIT_DONE 0x20
#define SMART_ANT_STATE_DEFAULT 0x00

#define SMART_ANT_RECONFIGURE 0
#define SMART_ANT_NEW_CONFIGURATION 1

/* SMART_ANT_STA_NOT_CONNECTED when set in new_init
 * argument of ieee80211_smart_ant_init(), channel 0
 * needs to be configured to help scanning.
 */
#define SMART_ANT_STA_NOT_CONNECTED 2
#define SMART_ANT_INTERFACE_ID_SHIFT 4

#define SMART_ANT_MODE_SERIAL   0
#define SMART_ANT_MODE_PARALLEL 1

#define AR600P_ASSEMBLE_HW_RATECODE(_rate, _nss, _pream) \
    (((_pream) << 6) | ((_nss) << 4) | (_rate))
#define MAX_OFDM_CCK_RATES 12

#define HT_RATE_FLAG 0x80
#define HT_RATE_MASK 0x7f
#define HT_NSS_MASK 070
#define HT_NSS_SHIFT 3
#define HT_MCS_MASK 0x7
#define AR600P_PREAMBLE_HT 2

#define VHT_PREAMBLE_MASK 0xc0
#define VHT_NSS_MASK      0x30
#define VHT_NSS_SHIFT     4
#define VHT_MCS_MASK      0x0f
#define VHT_MCS_SHIFT     6

#define OPMODE_VHT 2
#define OPMODE_HT 1
#define OPMODE_CCK_OFDM 0

#define RATE_INDEX_CCK_OFDM 0
#define RATE_INDEX_BW20 1
#define RATE_INDEX_BW40 2

#define RADIO_ID_DIRECT_ATTACH  0
#define RADIO_ID_OFF_LOAD  1

#define FALL_BACK_RATES_DIRECT_ATTACH 3
#define FALL_BACK_RATES_OFF_LOAD 1

#define SA_PARM_TYPE_MASK 0xffff0000
#define SA_PARM_TYPE_SHIFT 24

#if QCA_PARTNER_PLATFORM
#define SA_INLINE
#else
#define SA_INLINE static inline
#endif

#include <ieee80211_rateset.h>
#include <qdf_atomic.h>
extern struct smartantenna_ops *g_sa_ops;
extern qdf_atomic_t g_sa_init;

extern uint32_t rate_table_24[MAX_OFDM_CCK_RATES];
extern uint32_t rate_table_5[MAX_OFDM_CCK_RATES];

SA_INLINE int ieee80211_smart_ant_init( struct ieee80211com *ic, struct ieee80211vap *vap, int new_init);
SA_INLINE int ieee80211_smart_ant_deinit( struct ieee80211com *ic, struct ieee80211vap *vap, int notify);
SA_INLINE void ieee80211_smart_ant_node_connect(struct ieee80211_node *ni, struct sa_rate_cap *rate_cap);
SA_INLINE void ieee80211_smart_ant_node_disconnect(struct ieee80211_node *ni);
SA_INLINE int ieee80211_smart_ant_update_txfeedback(struct ieee80211_node *ni, void *tx_feedback);
SA_INLINE int ieee80211_smart_ant_update_rxfeedback(struct ieee80211_node *ni, void *rx_feedback);
SA_INLINE int ieee80211_smart_ant_get_bcn_txantenna(struct ieee80211com *ic, u_int32_t *bcn_txant);
SA_INLINE int ieee80211_smart_ant_channel_change(struct ieee80211com *ic);
SA_INLINE int ieee80211_smart_ant_set_param( struct ieee80211com *ic, char *params);
SA_INLINE int ieee80211_smart_ant_get_param( struct ieee80211com *ic, char *params);
SA_INLINE uint32_t ieee80211_smart_ant_convert_rate_5g(uint32_t rate_code);
SA_INLINE uint32_t ieee80211_smart_ant_convert_rate_2g(uint32_t rate_code);
SA_INLINE int ieee80211_smart_ant_cwm_action(struct ieee80211com *ic);

static inline int __ieee80211_smart_ant_get_rxantenna(struct ieee80211com *ic, uint32_t *rx_ant)
{
    if (g_sa_ops->sa_get_rxantenna) {
        return (g_sa_ops->sa_get_rxantenna(ic->interface_id, rx_ant));
    } else {
        ASSERT(FALSE); /* This condition should not happen */
    }
    return SMART_ANT_STATUS_FAILURE;
}

static inline int __ieee80211_smart_ant_init( struct ieee80211com *ic, struct ieee80211vap *vap, int new_init)
{
    struct sa_config sa_init_config;
    u_int32_t rx_antenna;
    u_int32_t antenna_array[SMART_ANTENNA_MAX_RATE_SERIES];
    int i = 0;
    uint8_t tx_chainmask = 0, rx_chainmask = 0;
    int ret = 0;
    u_int32_t enable;
    struct ieee80211_node *ni;
    struct ieee80211_node_table  *nt = &ic->ic_sta;

    if (g_sa_ops == NULL) {
        printk("%s: Smart Antenna functions are not registered !!! \n", __func__);
        return SMART_ANT_STATUS_FAILURE;
    }

    if (ic->ic_smart_ant_enable == NULL) {
        printk("%s: Smart Antenna is not supported \n", __func__);
        ic->smart_ant_enable = 0;
        return SMART_ANT_STATUS_FAILURE;
    }
    /*
     *  handling Multile VAP cases
     */
    if (new_init & SMART_ANT_NEW_CONFIGURATION) {
        if (!(ic->ic_smart_ant_state & SMART_ANT_STATE_INIT_DONE)) {
            qdf_atomic_inc(&g_sa_init);
        } else {
            return SMART_ANT_STATUS_SUCCESS;
        }
    }

    if ((vap->iv_opmode == IEEE80211_M_HOSTAP) || (vap->iv_opmode == IEEE80211_M_STA)) {
        /* TODO: What abt repeater case, need to check calling place for repeater*/
        if (g_sa_ops->sa_init) {
            sa_init_config.radio_id = (ic->interface_id << SMART_ANT_INTERFACE_ID_SHIFT) | ic->radio_id;
            sa_init_config.max_fallback_rates = ic->max_fallback_rates;
            tx_chainmask = ieee80211com_get_tx_chainmask(ic);
            rx_chainmask = ieee80211com_get_rx_chainmask(ic);
            sa_init_config.nss =  ieee80211_getstreams(ic, tx_chainmask);
            sa_init_config.txrx_chainmask = (tx_chainmask | (rx_chainmask << 4));

            if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
                sa_init_config.bss_mode = SMART_ANT_BSS_MODE_AP;
            } else if (vap->iv_opmode == IEEE80211_M_STA) {
                sa_init_config.bss_mode = SMART_ANT_BSS_MODE_STA;
            }

            if (new_init & SMART_ANT_STA_NOT_CONNECTED) {
                new_init &= ~SMART_ANT_STA_NOT_CONNECTED;
                /* Set Channel number to 0 ("zero") to request default params from SA module
                 * to help scanning while station is not connected.
                 * Helpful only in IEEE80211_M_STA mode.
                 */
                sa_init_config.channel_num = 0;
            } else {
                sa_init_config.channel_num = ic->ic_curchan->ic_ieee;
            }
            /* Assume smart antenna module requires both Tx and Rx feedback for now.
             * smart antenna module can set these values to zero (0) if he doesn't
             * need any of Tx feedback or Rx feedback or both.
             */
            sa_init_config.txrx_feedback = SMART_ANT_TX_FEEDBACK_MASK | SMART_ANT_RX_FEEDBACK_MASK;
            ret = g_sa_ops->sa_init(&sa_init_config, new_init);
            ASSERT(ret < 0);  /* -ve value: init error */
            /* Bit 0 in ret is mode. all other bits are discarded. */
            ic->ic_smart_ant_mode = ret & SMART_ANT_MODE;

            __ieee80211_smart_ant_get_rxantenna(ic, &rx_antenna);
            /*
             * Create bitmap of smart antenna enabled and Tx/Rx feedback subscription
             * state. bit 0 represents smart antenna enabled/disabled, bit 4 represents
             * Tx subscription state and bit 5 represents Rx subscription state.
             */
            enable = SMART_ANT_ENABLE_MASK | (sa_init_config.txrx_feedback &
                    (SMART_ANT_TX_FEEDBACK_MASK | SMART_ANT_RX_FEEDBACK_MASK));
            /* Enable smart antenna for First new init */
            if (new_init & SMART_ANT_NEW_CONFIGURATION) {
                /* Enable smart antenna , params@ ic, enable, mode, RX antenna */
                ic->ic_smart_ant_enable(ic, enable, ic->ic_smart_ant_mode, rx_antenna);
                ic->ic_smart_ant_state |= SMART_ANT_STATE_INIT_DONE;
                ic->ic_smart_ant_state &= ~(SMART_ANT_STATE_DEINIT_DONE); /* clear de init */
                ic->smart_ant_enable = enable; /*save smart antenna enable bitmap */
            } else {
                ic->ic_smart_ant_set_rx_antenna(ic, rx_antenna);
            }

            for (i = 0; i <= ic->max_fallback_rates; i++) {
                antenna_array[i] = rx_antenna;
            }

            TAILQ_FOREACH(ni, &nt->nt_node, ni_list) {
                /* set TX antenna to default antennas to BSS node */
                if (IEEE80211_ADDR_EQ(ni->ni_macaddr, vap->iv_myaddr)) {
                    ic->ic_smart_ant_set_tx_antenna(ni, &antenna_array[0]);
                }
            }
        }
    }
    return SMART_ANT_STATUS_SUCCESS;
}

static inline int __ieee80211_smart_ant_deinit( struct ieee80211com *ic, struct ieee80211vap *vap, int notify)
{
    if (ic->ic_smart_ant_state & SMART_ANT_STATE_DEINIT_DONE ) {
        printk("Deinit is already done !!! \n");
        return 0;
    }
    if (g_sa_ops->sa_deinit) {
        if (notify) {
            qdf_atomic_dec(&g_sa_init);
            g_sa_ops->sa_deinit(ic->interface_id);
            ic->ic_smart_ant_enable(ic, 0, ic->ic_smart_ant_mode, 0);
            ic->smart_ant_enable = 0;
            ic->ic_smart_ant_state |= SMART_ANT_STATE_DEINIT_DONE;
            ic->ic_smart_ant_state &= ~(SMART_ANT_STATE_INIT_DONE); /* clear init */
        }
    }
    return SMART_ANT_STATUS_SUCCESS;
}
static inline uint32_t __ieee80211_smart_ant_convert_rate_5g(uint32_t rate_code)
{
    uint32_t rate_code_converted = 0;
    uint8_t mcs = 0, nss = 0, i = 0;
    if (IS_HT_RATE(rate_code)) {
        rate_code &= HT_RATE_MASK;
        nss = (rate_code & HT_NSS_MASK) >> HT_NSS_SHIFT;
        mcs = (rate_code & HT_MCS_MASK);
        rate_code_converted = AR600P_ASSEMBLE_HW_RATECODE(mcs, nss, AR600P_PREAMBLE_HT);
    } else {
        for(i = 0; i < MAX_OFDM_CCK_RATES; i++) {
            if (rate_table_24[i] == rate_code) {
                break;
            }
        }
        if (i < MAX_OFDM_CCK_RATES) {
            rate_code_converted = rate_table_5[i];
        }
    }
    return rate_code_converted;
}

static inline uint32_t __ieee80211_smart_ant_convert_rate_2g(uint32_t rate_code)
{
    uint32_t rate_code_converted = 0;
    uint8_t preamble = (rate_code & VHT_PREAMBLE_MASK) >> VHT_MCS_SHIFT;
    uint8_t nss = 0, mcs = 0;
    int i =0 ;
    if (preamble == AR600P_PREAMBLE_HT) {
        nss = (rate_code & VHT_NSS_MASK) >> VHT_NSS_SHIFT;
        mcs = (rate_code & VHT_MCS_MASK);

        rate_code_converted =  (HT_RATE_FLAG | nss << HT_NSS_SHIFT | mcs);
    } else {
        for(i = 0; i < MAX_OFDM_CCK_RATES; i++) {
            if (rate_table_5[i] == rate_code)
                break;
        }
        if (i < MAX_OFDM_CCK_RATES)
            rate_code_converted = rate_table_24[i];
    }
    return rate_code_converted;
}

static inline int __ieee80211_smart_ant_get_default_txantenna( struct ieee80211com *ic,  u_int32_t *default_txant)
{
    if (g_sa_ops->sa_get_txdefaultantenna) {
        return (g_sa_ops->sa_get_txdefaultantenna(ic->interface_id, default_txant));
    } else {
        ASSERT(FALSE); /* This condition should not happen */
    }
    return SMART_ANT_STATUS_FAILURE;
}

static inline int __ieee80211_smart_ant_get_bcn_txantenna( struct ieee80211com *ic,  u_int32_t *bcn_txant)
{
    if (g_sa_ops->sa_get_bcn_txantenna) {
        return (g_sa_ops->sa_get_bcn_txantenna(ic->interface_id, bcn_txant));
    } else {
        ASSERT(FALSE); /* This condition should not happen */
    }
    return SMART_ANT_STATUS_FAILURE;
}


static inline int __ieee80211_smart_ant_get_txantenna(struct ieee80211_node *ni, uint32_t *tx_ant_array)
{
    if (g_sa_ops->sa_get_txantenna) {
        return (g_sa_ops->sa_get_txantenna(ni->smart_ant_ccp, tx_ant_array));
    } else {
        ASSERT(FALSE); /* This condition should not happen */
    }
    return SMART_ANT_STATUS_FAILURE;
}

static inline int __ieee80211_smart_ant_get_node_config(struct ieee80211_node *ni, uint32_t id, uint32_t *config)
{
    if (g_sa_ops->sa_get_node_config) {
        return (g_sa_ops->sa_get_node_config(ni->smart_ant_ccp, id, config));
    } else {
        ASSERT(FALSE); /* This condition should not happen */
    }
    return SMART_ANT_STATUS_FAILURE;
}

static inline int __ieee80211_smart_ant_get_traininfo(struct ieee80211_node *ni, uint32_t *train_rate_array, uint32_t *train_ant_array, uint32_t *num_train_pkts)
{
    if (g_sa_ops->sa_get_traininginfo) {
        return (g_sa_ops->sa_get_traininginfo(ni->smart_ant_ccp, train_rate_array, train_ant_array, num_train_pkts));
    } else {
        ASSERT(FALSE); /* This condition should not happen */
    }
    return SMART_ANT_STATUS_FAILURE;
}


static inline int __ieee80211_smart_ant_update_txfeedback(struct ieee80211_node *ni, void *tx_feedback)
{
    uint32_t rx_antenna, tx_antenna_array[SMART_ANT_MAX_SA_CHAINS];
    uint8_t status = 0;
    struct ieee80211com *ic = ni->ni_ic;
    uint32_t train_rate_array[SMART_ANTENNA_MAX_RATE_SERIES];
    uint32_t train_antenna_array[SMART_ANT_MAX_SA_CHAINS], num_train_pkts;
    uint32_t tx_feedback_config = 0;

    if (ni->smart_ant_ccp == NULL) {
        return SMART_ANT_STATUS_FAILURE;
    }
    if (g_sa_ops->sa_update_txfeedback) {
        if (SMART_ANT_STATUS_SUCCESS == g_sa_ops->sa_update_txfeedback(ni->smart_ant_ccp, (struct  sa_tx_feedback *)tx_feedback, &status)) {
            if (status) {
		if (status & SMART_ANT_TX_FEEDBACK_CONFIG_REQUIRED) {
                    if ( SMART_ANT_STATUS_SUCCESS == __ieee80211_smart_ant_get_node_config(ni, SA_TX_FEEDBACK_CONFIG, &tx_feedback_config)) {
            	        /* configure target to send 1 tx feedback to host for N ppdus sent */
                        ic->ic_smart_ant_set_node_config_ops(ni, SA_TX_FEEDBACK_CONFIG, 1, &tx_feedback_config);
		    }
                }
                if (status & SMART_ANT_RX_CONFIG_REQUIRED) {
                    if ( SMART_ANT_STATUS_SUCCESS == __ieee80211_smart_ant_get_rxantenna(ic, &rx_antenna)) {
                        /* set RX antenna */
                        ic->ic_smart_ant_set_rx_antenna(ic, rx_antenna);
                    }
                }
                if (status & SMART_ANT_TX_CONFIG_REQUIRED) {
                    if ( SMART_ANT_STATUS_SUCCESS == __ieee80211_smart_ant_get_txantenna(ni, &tx_antenna_array[0])) {
                        /* set TX antenna array */
                        ic->ic_smart_ant_set_tx_antenna(ni, &tx_antenna_array[0]);
                    }
                }
                if (status & SMART_ANT_TRAINING_REQUIRED) {
                    /* TODO: Instead of passing 3 arguments we can pass structure with required fields */
                    /* Get train parameters and program train info to lower modules */
                    if ( SMART_ANT_STATUS_SUCCESS == g_sa_ops->sa_get_traininginfo(ni->smart_ant_ccp, &train_rate_array[0], &train_antenna_array[0], &num_train_pkts)) {
                        ic->ic_smart_ant_set_training_info(ni, &train_rate_array[0], &train_antenna_array[0], num_train_pkts);
                    }
                }
            }
        }
        return SMART_ANT_STATUS_SUCCESS;
    } else {
        return SMART_ANT_STATUS_FAILURE;
    }

}

static inline int __ieee80211_smart_ant_update_rxfeedback(struct ieee80211_node *ni, void *rx_feedback)
{
    uint32_t rx_antenna;
    uint8_t status = 0;
    struct ieee80211com *ic = ni->ni_ic;
    uint32_t train_rate_array[SMART_ANTENNA_MAX_RATE_SERIES];
    uint32_t train_antenna_array[SMART_ANT_MAX_SA_CHAINS], num_train_pkts;

    if (ni->smart_ant_ccp == NULL) {
        return SMART_ANT_STATUS_FAILURE;
    }
    if (g_sa_ops->sa_update_rxfeedback) {
        if( SMART_ANT_STATUS_SUCCESS == g_sa_ops->sa_update_rxfeedback(ni->smart_ant_ccp, (struct sa_rx_feedback *)rx_feedback, &status)) {
            if (status) {
                if (status & SMART_ANT_RX_CONFIG_REQUIRED) {
                    if ( SMART_ANT_STATUS_SUCCESS == __ieee80211_smart_ant_get_rxantenna(ic, &rx_antenna)) {
                        /* set RX antenna */
                        ic->ic_smart_ant_set_rx_antenna(ic, rx_antenna);
                    }
                }
                if (status & SMART_ANT_TRAINING_REQUIRED) {
                    /* TODO: Instead of passing 3 arguments we can pass structure with required fields */
                    /* Get train parameters and program train info to lower modules */
                    if ( SMART_ANT_STATUS_SUCCESS == g_sa_ops->sa_get_traininginfo(ni->smart_ant_ccp, &train_rate_array[0], &train_antenna_array[0], &num_train_pkts)) {
                        ic->ic_smart_ant_set_training_info(ni, &train_rate_array[0], &train_antenna_array[0], num_train_pkts);
                    }
                }
            }
            return SMART_ANT_STATUS_SUCCESS;
        }
    }
    return SMART_ANT_STATUS_FAILURE;
}


static inline void __ieee80211_smart_ant_node_connect(struct ieee80211_node *ni, struct sa_rate_cap *rate_cap)
{
    struct sa_node_info node_info;
    struct ieee80211com *ic = ni->ni_ic;
    struct sa_rate_info rate_info;
    uint8_t i = 0;
    uint32_t htindex = 0, legacyindex = 0;

    OS_MEMZERO(&node_info, sizeof(struct sa_node_info));

    if (ic->ic_smart_ant_prepare_rateset) {
        ic->ic_smart_ant_prepare_rateset(ic, ni, &rate_info);
        /* form rate set to sa module */
        for(i=0; i < rate_info.num_of_rates; i++) {
            if (IS_HT_RATE(rate_info.rates[i].ratecode)) { /* ht rate */
                if (ni->ni_chwidth == IEEE80211_CWM_WIDTH20) {
                    node_info.rate_cap.ratecode_20[htindex] = ieee80211_smart_ant_convert_rate_5g(rate_info.rates[i].ratecode);
                    htindex++;
                    node_info.rate_cap.ratecount[RATE_INDEX_BW20]++;
                } else {
                    node_info.rate_cap.ratecode_40[htindex] = ieee80211_smart_ant_convert_rate_5g(rate_info.rates[i].ratecode);
                    htindex++;
                    node_info.rate_cap.ratecount[RATE_INDEX_BW40]++;
                }
            } else { /* legacy rate */
                node_info.rate_cap.ratecode_legacy[legacyindex] = ieee80211_smart_ant_convert_rate_5g(rate_info.rates[i].ratecode);
                legacyindex++;
                node_info.rate_cap.ratecount[RATE_INDEX_CCK_OFDM]++;
            }
        }
    } else {
        /* rates are already set */
        if (rate_cap != NULL) {
            OS_MEMCPY(&node_info.rate_cap, rate_cap, sizeof(struct sa_rate_cap));
        }
    }

    IEEE80211_ADDR_COPY(node_info.mac_addr, ni->ni_macaddr);
    node_info.radio_id = ic->interface_id;

    node_info.max_ch_bw = ni->ni_chwidth;
    node_info.chainmask = ((ni->ni_streams) | (ni->ni_rxstreams << 4));
    node_info.opmode = ((ni->ni_flags & IEEE80211_NODE_VHT) ? OPMODE_VHT : (ni->ni_flags & IEEE80211_NODE_HT ? OPMODE_HT :OPMODE_CCK_OFDM));
    node_info.ni_cap = 0;

    if (ic->radio_id == RADIO_ID_OFF_LOAD)
        node_info.ni_cap |= DYNAMIC_BW_SUPPORTED; /* TODO: refined cap need to be filled */

    node_info.channel_num =  ic->ic_curchan->ic_ieee;
    if (g_sa_ops->sa_node_connect) {
        g_sa_ops->sa_node_connect(&ni->smart_ant_ccp, &node_info);
    }
}




static inline int __ieee80211_smart_ant_set_param( struct ieee80211com *ic, char *params)
{

    struct sa_config_params sa_params;
    uint32_t tx_antenna_array[SMART_ANT_MAX_SA_CHAINS];
    uint8_t  mac_addr[6] = {'\0'};
    uint32_t *config = (uint32_t *) params;
    uint32_t radio_mac1 = config[0];
    uint32_t mac2 = config[1];
    struct ieee80211_node *ni = NULL;
    int retval = 0;
    int config_required = 0;
    uint32_t rx_antenna = 0;
    uint32_t tx_feedback_config = 0;
    uint32_t train_rate_array[SMART_ANTENNA_MAX_RATE_SERIES];
    uint32_t train_antenna_array[SMART_ANT_MAX_SA_CHAINS], num_train_pkts;

    sa_params.radio_id = ic->interface_id;
    sa_params.param_type = (config[0] & SA_PARM_TYPE_MASK) >> SA_PARM_TYPE_SHIFT;
    sa_params.param_id  = config[2];
    sa_params.param_value  = config[3];
    sa_params.ccp = NULL;
    if (sa_params.param_type) {
	    /* look for node */
	    mac_addr[0] = (uint8_t)((radio_mac1 & 0x0000ff00) >> 8);
	    mac_addr[1] = (uint8_t)((radio_mac1 & 0x000000ff) >> 0);
	    mac_addr[2] = (uint8_t)((mac2 & 0xff000000) >> 24);
	    mac_addr[3] = (uint8_t)((mac2 & 0x00ff0000) >> 16);
	    mac_addr[4] = (uint8_t)((mac2 & 0x0000ff00) >> 8);
	    mac_addr[5] = (uint8_t)((mac2 & 0x000000ff) >> 0);
	    ni = ieee80211_find_node(&ic->ic_sta, mac_addr);
	    if ((ni == NULL) || (ni->smart_ant_ccp == NULL)) {
		    return SMART_ANT_STATUS_FAILURE;
	    }
	    sa_params.ccp  = ni->smart_ant_ccp;
            retval = g_sa_ops->sa_set_param(&sa_params);
	    ieee80211_free_node(ni);
    } else {
	    retval = g_sa_ops->sa_set_param(&sa_params);
    }

    config_required = (retval == SMART_ANT_STATUS_FAILURE) ? 0 : retval;
    if (config_required) {
        if (config_required & SMART_ANT_RX_CONFIG_REQUIRED) {
            if (SMART_ANT_STATUS_SUCCESS == __ieee80211_smart_ant_get_rxantenna(ic, &rx_antenna)) {
                /* set RX antenna */
                ic->ic_smart_ant_set_rx_antenna(ic, rx_antenna);
            }
        } else if ((config_required & SMART_ANT_TX_FEEDBACK_CONFIG_REQUIRED) && (ni != NULL)) {
            if (SMART_ANT_STATUS_SUCCESS == __ieee80211_smart_ant_get_node_config(ni, SA_TX_FEEDBACK_CONFIG, &tx_feedback_config)) {
                /* configure target to send 1 tx feedback to host for N ppdus sent */
                ic->ic_smart_ant_set_node_config_ops(ni, SA_TX_FEEDBACK_CONFIG, 1, &tx_feedback_config);
            }
        } else if ((config_required & SMART_ANT_TX_CONFIG_REQUIRED) && (ni != NULL)) {
            if ( SMART_ANT_STATUS_SUCCESS == __ieee80211_smart_ant_get_txantenna(ni, &tx_antenna_array[0])) {
                /* set TX antenna array */
                ic->ic_smart_ant_set_tx_antenna(ni, &tx_antenna_array[0]);
            }
        } else if ((config_required & SMART_ANT_TRAINING_REQUIRED) && (ni != NULL)) {
            if ( SMART_ANT_STATUS_SUCCESS == g_sa_ops->sa_get_traininginfo(ni->smart_ant_ccp, &train_rate_array[0], &train_antenna_array[0], &num_train_pkts)) {
                ic->ic_smart_ant_set_training_info(ni, &train_rate_array[0], &train_antenna_array[0], num_train_pkts);
            }
        }
    }

    return retval;
}

static inline int __ieee80211_smart_ant_get_param( struct ieee80211com *ic, char *params)
{
    struct sa_config_params sa_params;
    uint8_t  mac_addr[6] = {'\0'};
    uint32_t *config = (uint32_t *) params;
    uint32_t radio_mac1 = config[0];
    uint32_t mac2 = config[1];
    struct ieee80211_node *ni = NULL;
    int retval = 0;
    sa_params.radio_id = ic->interface_id;
    sa_params.param_type = (config[0] & SA_PARM_TYPE_MASK) >> SA_PARM_TYPE_SHIFT;
    sa_params.param_id  = config[2];
    if (sa_params.param_type) {
	    /* look for node */
	    mac_addr[0] = (uint8_t)((radio_mac1 & 0x0000ff00) >> 8);
	    mac_addr[1] = (uint8_t)((radio_mac1 & 0x000000ff) >> 0);
	    mac_addr[2] = (uint8_t)((mac2 & 0xff000000) >> 24);
	    mac_addr[3] = (uint8_t)((mac2 & 0x00ff0000) >> 16);
	    mac_addr[4] = (uint8_t)((mac2 & 0x0000ff00) >> 8);
	    mac_addr[5] = (uint8_t)((mac2 & 0x000000ff) >> 0);
	    ni = ieee80211_find_node(&ic->ic_sta, mac_addr);
	    if ((ni == NULL) || (ni->smart_ant_ccp == NULL)) {
		    return SMART_ANT_STATUS_FAILURE;
	    }
	    sa_params.ccp  = ni->smart_ant_ccp;
            retval = g_sa_ops->sa_get_param(&sa_params);
	    ieee80211_free_node(ni);
    } else {
	    retval = g_sa_ops->sa_get_param(&sa_params);
    }

    config[0] = sa_params.param_value;
    return (retval);
}



static inline void __ieee80211_smart_ant_node_disconnect(struct ieee80211_node *ni)
{
    struct ieee80211vap *vap = ni->ni_vap;
    /*  Do we need to check removing own vap/node ??? */
    if ((vap->iv_opmode == IEEE80211_M_HOSTAP) && (ni != ni->ni_bss_node)) {
        if (g_sa_ops->sa_node_disconnect) {
            if (ni->smart_ant_ccp != NULL) {
                g_sa_ops->sa_node_disconnect(ni->smart_ant_ccp);
                ni->smart_ant_ccp = NULL;
            }
        }
    } else if ((vap->iv_opmode == IEEE80211_M_STA) &&
               (!IEEE80211_ADDR_EQ(ni->ni_macaddr, vap->iv_myaddr))) {
        if (g_sa_ops->sa_node_disconnect) {
            if (ni->smart_ant_ccp != NULL) {
                g_sa_ops->sa_node_disconnect(ni->smart_ant_ccp);
                ni->smart_ant_ccp = NULL;
            }
        }
    }
}

static inline int __ieee80211_smart_ant_channel_change(struct ieee80211com *ic)
{
    struct ieee80211_node_table  *nt = &ic->ic_sta;
    struct ieee80211_node *ni = NULL, *next = NULL;
    rwlock_state_t lock_state;
    struct ieee80211vap *vap;

    vap = TAILQ_FIRST(&ic->ic_vaps);
    if (wlan_scan_in_progress(vap)) {
        return 0;
    }
    if ((ic->ic_smart_ant_state != SMART_ANT_STATE_INIT_DONE)) {
        return SMART_ANT_STATUS_FAILURE;
    }

    /* call smart antenna deint and init with re configuration */
    ieee80211_smart_ant_deinit(ic, vap, SMART_ANT_RECONFIGURE);

    if (ic->ic_opmode == IEEE80211_M_STA) {
        ieee80211_smart_ant_init(ic, vap, SMART_ANT_RECONFIGURE);
        ic->sta_not_connected_cfg = FALSE;
    } else {
        ieee80211_smart_ant_init(ic, vap, SMART_ANT_RECONFIGURE);
    }

    /* call node_connect to each node in the list */
    OS_RWLOCK_READ_LOCK(&nt->nt_nodelock, &lock_state);
    TAILQ_FOREACH_SAFE(ni, &nt->nt_node, ni_list, next) {
        if (IEEE80211_ADDR_EQ(ni->ni_macaddr, vap->iv_myaddr)) {
            continue;
        }
        if (ieee80211_node_is_authorized(ni)) {
            __ieee80211_smart_ant_node_connect(ni, NULL);
        }
    }
    OS_RWLOCK_READ_UNLOCK(&nt->nt_nodelock, &lock_state);
    return SMART_ANT_STATUS_SUCCESS;
}

static inline int __ieee80211_smart_ant_cwm_action(struct ieee80211com *ic)
{
    struct ieee80211_node_table  *nt = &ic->ic_sta;
    struct ieee80211_node *ni = NULL, *next = NULL;
    rwlock_state_t lock_state;
    struct ieee80211vap *vap;
    /* get current cwm mode */
    enum ieee80211_cwm_width ic_cw_width = ic->ic_cwm_get_width(ic);
    vap = TAILQ_FIRST(&ic->ic_vaps);

    if (!SMART_ANTENNA_ENABLED(ic)) {
        return SMART_ANT_STATUS_FAILURE;
    }

    /* call node_connect to each node in the list */
    OS_RWLOCK_READ_LOCK(&nt->nt_nodelock, &lock_state);
    TAILQ_FOREACH_SAFE(ni, &nt->nt_node, ni_list, next) {
        if (IEEE80211_ADDR_EQ(ni->ni_macaddr, vap->iv_myaddr)) {
            continue;
        }
        if ( (ni->ni_flags & IEEE80211_NODE_HT ) && (ni->ni_chwidth != ic_cw_width)) {
            if (ic_cw_width == IEEE80211_CWM_WIDTH40) {
                if (ni->ni_htcap & IEEE80211_HTCAP_C_CHWIDTH40) {
                    ni->ni_chwidth = ic_cw_width;
                    ieee80211_smart_ant_node_connect(ni, NULL);
                }
            }

            if (ic_cw_width == IEEE80211_CWM_WIDTH20) {
                ni->ni_chwidth = ic_cw_width;
                ieee80211_smart_ant_node_connect(ni, NULL);
            }
        }
    }
    OS_RWLOCK_READ_UNLOCK(&nt->nt_nodelock, &lock_state);

   return SMART_ANT_STATUS_SUCCESS;
}
#if QCA_PARTNER_PLATFORM
    /* Non-static funcs defined in .c file*/
#else
SA_INLINE int ieee80211_smart_ant_init( struct ieee80211com *ic, struct ieee80211vap *vap, int new_init)
{
    return (__ieee80211_smart_ant_init(ic, vap, new_init));
}

SA_INLINE int ieee80211_smart_ant_deinit( struct ieee80211com *ic, struct ieee80211vap *vap, int notify)
{
    if(SMART_ANTENNA_ENABLED(ic)) {
        return __ieee80211_smart_ant_deinit(ic, vap, notify);
    }
    return SMART_ANT_STATUS_FAILURE;
}

SA_INLINE void ieee80211_smart_ant_node_connect(struct ieee80211_node *ni, struct sa_rate_cap *rate_cap)
{
    if(SMART_ANTENNA_ENABLED(ni->ni_ic)) {
        __ieee80211_smart_ant_node_connect(ni, rate_cap);
    }
}

SA_INLINE void ieee80211_smart_ant_node_disconnect(struct ieee80211_node *ni)
{
    if(SMART_ANTENNA_ENABLED(ni->ni_ic)) {
        __ieee80211_smart_ant_node_disconnect(ni);
    }
}

SA_INLINE int ieee80211_smart_ant_update_txfeedback(struct ieee80211_node *ni, void *tx_feedback)
{
    if(SMART_ANTENNA_TX_FEEDBACK_ENABLED(ni->ni_ic)) {
        return (__ieee80211_smart_ant_update_txfeedback(ni, tx_feedback));
    }
    return SMART_ANT_STATUS_FAILURE;
}

SA_INLINE int ieee80211_smart_ant_update_rxfeedback(struct ieee80211_node *ni, void *rx_feedback)
{
    if(SMART_ANTENNA_RX_FEEDBACK_ENABLED(ni->ni_ic)) {
        return (__ieee80211_smart_ant_update_rxfeedback(ni, rx_feedback));
    }
    return SMART_ANT_STATUS_FAILURE;
}

SA_INLINE int ieee80211_smart_ant_get_bcn_txantenna(struct ieee80211com *ic, u_int32_t *bcn_txant)
{
    if(SMART_ANTENNA_ENABLED(ic)) {
        return (__ieee80211_smart_ant_get_bcn_txantenna(ic, bcn_txant));
    }
    return SMART_ANT_STATUS_FAILURE;
}

SA_INLINE int ieee80211_smart_ant_channel_change(struct ieee80211com *ic)
{
    if(SMART_ANTENNA_ENABLED(ic)) {
        return (__ieee80211_smart_ant_channel_change(ic));
    }
    return SMART_ANT_STATUS_FAILURE;
}

SA_INLINE int ieee80211_smart_ant_set_param( struct ieee80211com *ic, char *params)
{
    if(SMART_ANTENNA_ENABLED(ic)) {
        return (__ieee80211_smart_ant_set_param(ic, params));
    }
    return SMART_ANT_STATUS_FAILURE;
}

SA_INLINE int ieee80211_smart_ant_get_param( struct ieee80211com *ic, char *params)
{
    if(SMART_ANTENNA_ENABLED(ic)) {
        return (__ieee80211_smart_ant_get_param(ic, params));
    }
    return SMART_ANT_STATUS_FAILURE;
}

SA_INLINE uint32_t ieee80211_smart_ant_convert_rate_5g(uint32_t rate_code)
{
    return (__ieee80211_smart_ant_convert_rate_5g(rate_code));
}

SA_INLINE uint32_t ieee80211_smart_ant_convert_rate_2g(uint32_t rate_code)
{
    return (__ieee80211_smart_ant_convert_rate_2g(rate_code));
}
SA_INLINE int ieee80211_smart_ant_cwm_action(struct ieee80211com *ic)
{
    return (__ieee80211_smart_ant_cwm_action(ic));
}
#endif


#else
static inline int ieee80211_smart_ant_get_bcn_txantenna(struct ieee80211com *ic, u_int32_t *bcn_txant)
{
    *bcn_txant = 0xffffffff;
    return 0;
}
static inline int ieee80211_smart_ant_cwm_action(struct ieee80211com *ic)
{
    return 0;
}

#endif

#endif
