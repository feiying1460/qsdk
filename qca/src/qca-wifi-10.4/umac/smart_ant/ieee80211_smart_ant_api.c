/*
* Copyright (c) 2013 Qualcomm Atheros, Inc..
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.
*/
#if UNIFIED_SMARTANTENNA

#include <ieee80211_var.h>
#include <ieee80211_smart_ant_api.h>
#include <ath_cwm.h>
#include <if_smart_ant.h>
#include <qdf_atomic.h>

struct smartantenna_ops *g_sa_ops = NULL;
qdf_atomic_t g_sa_init;

uint32_t rate_table_24[MAX_OFDM_CCK_RATES] = {0x1b,0x1a,0x19,0x18,0x0b,0x0f,0x0a,0x0e,0x09,0x0d, 0x08,0x0c};
uint32_t rate_table_5[MAX_OFDM_CCK_RATES] = {0x43,0x42,0x41,0x40,0x03,0x07,0x02,0x06,0x01,0x05,0x00,0x04};

#ifdef QCA_PARTNER_PLATFORM
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

#ifdef QCA_PARTNER_PLATFORM
void ieee80211_smart_ant_node_connect(struct ieee80211_node *ni, struct sa_rate_cap *rate_cap)
#else
SA_INLINE void ieee80211_smart_ant_node_connect(struct ieee80211_node *ni, struct sa_rate_cap *rate_cap)
#endif
{
    if(SMART_ANTENNA_ENABLED(ni->ni_ic)) {
        __ieee80211_smart_ant_node_connect(ni, rate_cap);
    }
}
#ifdef QCA_PARTNER_PLATFORM
EXPORT_SYMBOL(ieee80211_smart_ant_node_connect);
#endif

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

int register_smart_ant_ops(struct smartantenna_ops *sa_ops)
{
    g_sa_ops = sa_ops;
    qdf_atomic_init(&g_sa_init);
    return SMART_ANT_STATUS_SUCCESS;
}

int deregister_smart_ant_ops(char *dev_name)
{
    struct ath_softc_net80211 *scn = NULL;
    struct ieee80211com *ic = NULL;
    struct net_device *dev = NULL;
    struct ieee80211vap *vap = NULL;

    dev = dev_get_by_name(&init_net, dev_name);
    if (!dev) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: device %s not Found! \n", __func__, dev_name);
        return SMART_ANT_STATUS_FAILURE;
    }

    scn = ath_netdev_priv(dev);
    if (scn == NULL)  {
        return SMART_ANT_STATUS_FAILURE;
    }

    ic = &scn->sc_ic;
    if (ic == NULL) {
        return SMART_ANT_STATUS_FAILURE;
    }
    vap = TAILQ_FIRST(&ic->ic_vaps);
    ieee80211_smart_ant_deinit(ic, vap, SMART_ANT_NEW_CONFIGURATION);
    dev_put(dev);
    if (qdf_atomic_read(&g_sa_init) == 0 ) {
        g_sa_ops = NULL;
    }
    return SMART_ANT_STATUS_SUCCESS;
}

#endif

