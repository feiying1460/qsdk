/*
 *  Copyright (c) 2008 Atheros Communications Inc.
 * All Rights Reserved.
 *
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#include "ieee80211_node_priv.h"
#include "ieee80211_wds.h"
#include "ieee80211_var.h"
#ifdef ATH_HTC_MII_RXIN_TASKLET
#include "htc_thread.h"
#endif
#include <if_smart_ant.h>
#include <mlme/ieee80211_mlme_priv.h>


#if IEEE80211_DEBUG_REFCNT
#define TRACENODE_INC(_ni, _func, _line, _file) do {                              \
    int index = 0, i;                                                 \
    struct node_trace *ntb;                                         \
    if (strstr (_file, "umac/mlme/") &&                           \
        strstr (_func, "ieee80211_send_mgmt"))                          \
        ntb = &(_ni)->trace->aponly;                                             \
    else if (strstr (_file, "os/linux/src/ieee80211_aponly.c"))        \
        ntb = &(_ni)->trace->aponly;                                           \
    else if (strstr (_file, "os/linux/src/ieee80211_wireless.c"))        \
        ntb = &(_ni)->trace->wireless;                                         \
    else if (strstr (_file, "umac/band_steering/band_steering.c"))       \
        ntb = &(_ni)->trace->bs;                                               \
    else if (strstr (_file, "umac/band_steering/band_steering_direct_attach.c")) \
        ntb = &(_ni)->trace->bs;                                               \
    else if (strstr (_file, "umac/base/ieee80211_node.c"))               \
        ntb = &(_ni)->trace->node;                                             \
    else if (strstr (_file, "umac/base/ieee80211_node_ap.c"))            \
        ntb = &(_ni)->trace->node;                                             \
    else if (strstr (_file, "umac/base/"))                               \
        ntb = &(_ni)->trace->base;                                             \
    else if (strstr (_file, "umac/crypto/"))                             \
        ntb = &(_ni)->trace->crypto;                                           \
    else if (strstr (_file, "umac/if_lmac/"))                            \
        ntb = &(_ni)->trace->if_lmac;                                          \
    else if (strstr (_file, "umac/mlme/"))                               \
        ntb = &(_ni)->trace->mlme;                                             \
    else if (strstr (_file, "umac/txrx/"))                               \
        ntb = &(_ni)->trace->txrx;                                             \
    else if (strstr (_file, "umac/wds/"))                                \
        ntb = &(_ni)->trace->wds;                                              \
    else                                                                \
        ntb = &(_ni)->trace->misc;                                             \
                                                                        \
    for(i = 0; i < NUM_TRACE_BUF; i++) {                                \
        if (((ntb)->inc.func[i] == _func) &&                            \
            ((ntb)->inc.line[i] == _line)) {                            \
            index = i;                                                  \
            break;                                                      \
        }                                                               \
    }                                                                   \
    if(i == NUM_TRACE_BUF) {                                        \
        atomic_inc(&((ntb)->inc.index));                                \
        index = (int)(atomic_read(&((ntb)->inc.index))) & (NUM_TRACE_BUF - 1); \
    }                                                                   \
    (ntb)->inc.func[index] = _func;                                     \
    (ntb)->inc.line[index] = _line;                                     \
    (ntb)->inc.count[index]++;                                          \
    atomic_inc(&(ntb)->refcnt);                                         \
    } while (0)

#define TRACENODE_DEC(_ni, _func, _line, _file) do {                     \
    int index = 0, i;                                               \
    struct node_trace *ntb;                                             \
    if (strstr (_file, "umac/if_lmac/") &&                              \
        strstr (_func, "ath_net80211_free_node"))                       \
        ntb = &(_ni)->trace->aponly;                                           \
    else if (strstr (_file, "umac/mlme/") &&                           \
        strstr (_func, "mlme_recv_auth_ap"))                            \
        ntb = &(_ni)->trace->node;                                             \
    else if (strstr (_file, "os/linux/src/ieee80211_aponly.c"))          \
        ntb = &(_ni)->trace->aponly;                                           \
    else if (strstr (_file, "os/linux/src/ieee80211_wireless.c"))        \
        ntb = &(_ni)->trace->wireless;                                         \
    else if (strstr (_file, "umac/band_steering/band_steering.c"))       \
        ntb = &(_ni)->trace->bs;                                               \
    else if (strstr (_file, "umac/band_steering/band_steering_direct_attach.c")) \
        ntb = &(_ni)->trace->bs;                                               \
    else if (strstr (_file, "umac/base/ieee80211_node.c"))               \
        ntb = &(_ni)->trace->node;                                             \
    else if (strstr (_file, "umac/base/ieee80211_node_ap.c"))            \
        ntb = &(_ni)->trace->node;                                             \
    else if (strstr (_file, "umac/base/"))                               \
        ntb = &(_ni)->trace->base;                                             \
    else if (strstr (_file, "umac/crypto/"))                             \
        ntb = &(_ni)->trace->crypto;                                           \
    else if (strstr (_file, "umac/if_lmac/"))                            \
        ntb = &(_ni)->trace->if_lmac;                                          \
    else if (strstr (_file, "umac/mlme/"))                               \
        ntb = &(_ni)->trace->mlme;                                             \
    else if (strstr (_file, "umac/txrx/"))                               \
        ntb = &(_ni)->trace->txrx;                                             \
    else if (strstr (_file, "umac/wds/"))                                \
        ntb = &(_ni)->trace->wds;                                              \
    else                                                                \
        ntb = &(_ni)->trace->misc;                                             \
                                                                        \
    for(i = 0; i < NUM_TRACE_BUF; i++) {                            \
        if (((ntb)->dec.func[i] == _func) &&                            \
            ((ntb)->dec.line[i] == _line)) {                            \
            index = i;                                                  \
            break;                                                      \
        }                                                               \
    }                                                                   \
    if(i == NUM_TRACE_BUF) {                                            \
        atomic_inc(&((ntb)->dec.index));                                \
        index = (int)(atomic_read(&((ntb)->dec.index))) & (NUM_TRACE_BUF - 1); \
    }                                                                   \
    (ntb)->dec.func[index] = _func;                                     \
    (ntb)->dec.line[index] = _line;                                     \
    (ntb)->dec.count[index]++;                                          \
    atomic_dec(&(ntb)->refcnt);                                    \
    } while (0)
#endif

#if IEEE80211_DEBUG_REFCNT
#define node_reclaim(nt,ni)  _node_reclaim(nt,ni,__func__,__LINE__,__FILE__)
#endif

#define	ieee80211_node_dectestref(_ni) \
    atomic_dec_and_test(&(_ni)->ni_refcnt)

static void
ieee80211_node_table_reset(struct ieee80211_node_table *nt, struct ieee80211vap *match);

struct ieee80211_iter_arg {
    int32_t count;
    wlan_if_t vap;
    u_int32_t flag;
    struct ieee80211_node *nodes[IEEE80211_512_AID];
};

#define IEEE80211_NODE_ITER_F_ASSOC_STA     0x1
#define IEEE80211_NODE_ITER_F_UNASSOC_STA   0x2
static void
ieee80211_node_iter(void *arg, struct ieee80211_node *ni);
#if UMAC_SUPPORT_PROXY_ARP
void
ieee80211_node_remove_ipv6_by_node(struct ieee80211_node_table *nt, struct ieee80211_node *ni);
#endif


extern void
ol_if_mgmt_drain(struct ieee80211_node *ni, int force);

static struct ieee80211_node *
node_alloc(struct ieee80211vap *vap, const u_int8_t *macaddr, bool tmpnode)
{
     struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_node *ni;

    /* create a node */
    ni = (struct ieee80211_node *)OS_MALLOC(ic->ic_osdev, sizeof(struct ieee80211_node), GFP_KERNEL);
    if (ni == NULL) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Can't create an node\n");
        return NULL;
    }
    OS_MEMZERO(ni, sizeof(struct ieee80211_node));

#if IEEE80211_DEBUG_REFCNT
    ni->trace = (struct node_trace_all *)OS_MALLOC(ic->ic_osdev, sizeof(struct node_trace_all), GFP_KERNEL);
    if (ni->trace == NULL) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Can't create an node trace\n");
        return NULL;
    }
    OS_MEMZERO(ni->trace, sizeof(struct node_trace_all));
#endif
    return ni;
}

#if IEEE80211_DEBUG_REFCNT
void ieee80211_dump_node_ref(struct node_trace *ntb)
{
    int idx, index = 0;

    if (atomic_read(&ntb->refcnt) == 0)
        return;

        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " incs\n");
    index = atomic_read(&ntb->inc.index) & (NUM_TRACE_BUF - 1);

    for(idx = index + 1; idx != index; idx = ((idx+1)&(NUM_TRACE_BUF-1)))
    {
        if(ntb->inc.func[idx])
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "cnt %d func %s line %d\n", 
                    ntb->inc.count[idx], 
                    ntb->inc.func[idx], 
                    ntb->inc.line[idx]);
    }
        if(ntb->inc.func[idx])
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "cnt %d func %s line %d\n", 
                    ntb->inc.count[idx], 
                    ntb->inc.func[idx], 
                    ntb->inc.line[idx]);

        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " decs\n");
    index = atomic_read(&ntb->dec.index) & (NUM_TRACE_BUF - 1);

    for(idx = index + 1; idx != index; idx = ((idx+1)&(NUM_TRACE_BUF-1)))
    {
        if(ntb->dec.func[idx])
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "cnt %d func %s line %d\n", 
                    ntb->dec.count[idx], 
                    ntb->dec.func[idx], 
                    ntb->dec.line[idx]);
    }
        if(ntb->dec.func[idx])
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "cnt %d func %s line %d\n", 
                    ntb->dec.count[idx], 
                    ntb->dec.func[idx], 
                    ntb->dec.line[idx]);

        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ref=%d\n", atomic_read(&ntb->refcnt));
}
#endif

/*
* allocates a node ,sets up the node and inserts the node into the node table.
* the allocated node will have 2 references one for adding it to the table and the
* the other for the caller to use.
*/

struct ieee80211_node *
ieee80211_alloc_node(struct ieee80211_node_table *nt,
                     struct ieee80211vap *vap,
                     const u_int8_t *macaddr)
{
    struct ieee80211com *ic = nt->nt_ic;
    struct ieee80211_node *ni;
    rwlock_state_t lock_state;
    int hash;
    int i;
    u_int8_t ac;
    OS_BEACON_DECLARE_AND_RESET_VAR(flags);

    if((!(IEEE80211_ADDR_IS_VALID(macaddr))) || (IEEE80211_IS_MULTICAST(macaddr))){
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_NODE,
                       "%s : Invalid MAC Address:%s \n",__func__, ether_sprintf(macaddr));
        vap->iv_stats.total_invalid_macaddr_nodealloc_failcnt++;
        return NULL;
    }
    if(IEEE80211_CHK_NODE_TARGET(ic))
        return NULL;
    ni = ic->ic_node_alloc(vap, macaddr, FALSE /* not temp node */);
    if (ni == NULL) {
        /* XXX msg */
        vap->iv_stats.is_rx_nodealloc++;
        return NULL;
    }

    ni->ni_last_rxauth_seq = 0xfff;
    ni->ni_last_auth_rx_time = 0;
    ni->ni_last_assoc_rx_time = 0;


    ieee80211_ref_node(ni);     /* mark referenced */

    atomic_set(&(ni->ni_rxfrag_lock), 0);
#if IEEE80211_DEBUG_NODELEAK
    OS_RWLOCK_WRITE_LOCK(&ic->ic_nodelock,&lock_state);
    TAILQ_INSERT_TAIL(&ic->ic_nodes, ni, ni_alloc_list);
    OS_RWLOCK_WRITE_UNLOCK(&ic->ic_nodelock,&lock_state);
#endif

    /* copy some default variables from parent */
    IEEE80211_ADDR_COPY(ni->ni_macaddr, macaddr);
    /* lp_iot_mode then set default beacon int val IEEE80211_LP_IOT_BCN_INTVAL_DEFAULT */
    if (vap->iv_create_flags & IEEE80211_LP_IOT_VAP)
        ni->ni_intval = IEEE80211_LP_IOT_BCN_INTVAL_DEFAULT;
    else
        ni->ni_intval = ic->ic_intval; /* default beacon interval */
    ni->ni_txpower = ic->ic_txpowlimit;	/* max power */
    ni->ni_vhtintop_subtype = VHT_INTEROP_OUI_SUBTYPE; /*Setting the interop IE*/
    ni->ni_node_esc = false;
    /* load inactivity values */
    ni->ni_inact_reload = vap->iv_inact_init;
    ni->ni_inact = ni->ni_inact_reload;
    /* init auth mode to be open and cipher sets to be clear */
    RSN_SET_AUTHMODE(&ni->ni_rsn, IEEE80211_AUTH_OPEN);
    RSN_SET_UCAST_CIPHER(&ni->ni_rsn, IEEE80211_CIPHER_NONE);
    RSN_SET_MCAST_CIPHER(&ni->ni_rsn, IEEE80211_CIPHER_NONE);

    /* disable session timeout here. Set it during authorize */
    ni->ni_session = IEEE80211_SESSION_TIME;

    /* init our unicast / receive key state */
    ieee80211_crypto_resetkey(vap, &ni->ni_ucastkey, IEEE80211_KEYIX_NONE);

    LIST_INSERT_HEAD(&vap->iv_dump_node_list, ni, ni_dump_list);
    ni->ni_vap = vap;

    if (vap->iv_opmode == IEEE80211_M_IBSS) {
        /* underlined vap is configured for IBSS so allocate
         * persta key memory and initialize it.
         */
        ni->ni_persta = (struct ni_persta_key *)
                        OS_MALLOC(ic->ic_osdev,sizeof(struct ni_persta_key), GFP_ATOMIC);
        if (ni->ni_persta == NULL) {
            ieee80211_free_node(ni);
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: freeing node as unable to allocate memory for ni_persta", __func__);
            return NULL;
        }
        OS_MEMSET(ni->ni_persta, 0 , sizeof(struct ni_persta_key));
        ieee80211_crypto_resetkey(vap, &ni->ni_persta->nips_hwkey, IEEE80211_KEYIX_NONE);
        for (i = 0; i < IEEE80211_WEP_NKID; i++) {
            ieee80211_crypto_resetkey(vap, &ni->ni_persta->nips_swkey[i], IEEE80211_KEYIX_NONE);
        }
    } else {
        /* Explicitly set ni_persta as NULL */
        ni->ni_persta = NULL;
    }

    ni->ni_ath_defkeyindex = IEEE80211_INVAL_DEFKEY;

    ni->ni_wme_miss_threshold = 0;

    /* IBSS-only: mark as unassociated by default. */
    ni->ni_assoc_state = IEEE80211_NODE_ADHOC_STATE_UNAUTH_UNASSOC;

    /* 11n or 11ac */
    ni->ni_chwidth = ic->ic_cwm_get_width(ic);

#if UNIFIED_SMARTANTENNA
    /* Initialize configuration control pointer to NULL */
    ni->smart_ant_ccp = NULL;
#endif

    ni->ni_ic = ic;

#if UMAC_SUPPORT_WNM
    ni->ni_wnm = (struct ieee80211_wnm_node *) OS_MALLOC(ic->ic_osdev,
                      (sizeof(struct ieee80211_wnm_node)),0);

    if(ni->ni_wnm == NULL) {
        if (ni->ni_persta) {
            OS_FREE(ni->ni_persta);
            ni->ni_persta = NULL;
        }
        ieee80211_free_node(ni);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: freeing node as unable to allocate memory for ni_wnm", __func__);
        return NULL;
    }
    OS_MEMSET(ni->ni_wnm, 0 , sizeof(struct ieee80211_wnm_node));
    /* ieee80211_wnm_nattach frees ni->ni_wnm if in case of failure */
    ieee80211_wnm_nattach(ni);
    if(ni->ni_wnm == NULL) {
        if (ni->ni_persta) {
            OS_FREE(ni->ni_persta);
            ni->ni_persta = NULL;
        }
        ieee80211_free_node(ni);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: freeing node as unable to allocate memory for ni_wnm", __func__);
        return NULL;
    }

#endif
#if ATH_SUPPORT_IBSS_NETLINK_NOTIFICATION
	ni->ni_rssi_class = 0;
#endif
 /* Initialize seq no of last & 2nd last received frames to 0xffff
     This is to avoid a case where valid frame (Retry bit is set & seq no as 0)
     gets dropped (assuming it as a duplicate frame) */
     for (i = 0; i < (IEEE80211_TID_SIZE+1); i++)
     {
        ni->ni_rxseqs[i] = ni->ni_last_rxseqs[i] = 0xffff;
     }

    IEEE80211_NODE_STATE_LOCK_INIT(ni);

    OS_BEACON_WRITE_LOCK(&nt->nt_nodelock, &lock_state, flags);

    IEEE80211_VAP_LOCK(vap);
    vap->iv_node_count++;
    IEEE80211_VAP_UNLOCK(vap);

    ni->ni_table = nt;
    ieee80211_ref_node(ni);     /* mark referenced for adding it to  the node table*/
    ni->ni_bss_node = ni;
    OS_BEACON_WRITE_UNLOCK(&nt->nt_nodelock, &lock_state, flags);
    ieee80211_node_saveq_attach(ni);

    /* set default rate and channel */
    ieee80211_node_set_chan(ni);

    //WME_UAPSD_NODE_TRIGSEQINIT(ni);
    /*
     * if vap is deleted while we are waiting for lock, delete  the node .
     */
    if (ieee80211_vap_deleted_is_set(vap)) {
        if (ni->ni_persta) {
            OS_FREE(ni->ni_persta);
            ni->ni_persta = NULL;
        }
#if UMAC_SUPPORT_WNM
        ieee80211_wnm_ndetach(ni);
        OS_FREE(ni->ni_wnm);
        ni->ni_wnm = NULL;
#endif
        ieee80211_sta_leave(ni);
        ieee80211_free_node(ni);
        return NULL;
    }

    for (ac = 0; ac < WME_NUM_AC; ac++) {
        ni->ni_uapsd_dyn_trigena[ac] = -1;
        ni->ni_uapsd_dyn_delivena[ac] = -1;
    }

    ni->previous_ps_time = qdf_get_system_timestamp();

#if QCA_AIRTIME_FAIRNESS
    ni->ni_block_tx_traffic = 0;

    ni->ni_atf_tput = 0;
    ni->ni_atf_airtime = 0;
    ni->ni_atf_airtime_new = 0;
    ni->ni_atf_airtime_more = 0;
    ni->ni_atf_airtime_subseq = 0;
    ni->ni_atf_airtime_cap = 0;
    ni->ni_atf_airtime_configured = 0;

    if (ic->ic_atf_tput_based) {
        for (i = 0; i < ATF_TPUT_MAX_STA; i++) {
            if (!OS_MEMCMP(ic->ic_atf_tput_tbl[i].mac_addr, ni->ni_macaddr, IEEE80211_ADDR_LEN)) {
                ni->ni_atf_tput = ic->ic_atf_tput_tbl[i].tput;
                ni->ni_atf_airtime_cap = ic->ic_atf_tput_tbl[i].airtime;
            }
        }
    }
#endif

    ieee80211node_clear_whc_rept_info(ni);

    ieee80211_admctl_init(ni);

    /* Add the node into hash table */
    hash = IEEE80211_NODE_HASH(macaddr);
    OS_BEACON_WRITE_LOCK(&nt->nt_nodelock, &lock_state, flags);
    TAILQ_INSERT_TAIL(&nt->nt_node, ni, ni_list);
    LIST_INSERT_HEAD(&nt->nt_hash[hash], ni, ni_hash);
    OS_BEACON_WRITE_UNLOCK(&nt->nt_nodelock, &lock_state, flags);

    IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
                   "%s: vap=0x%x, nodecount=%d, ni=0x%x, ni_bss_node=0x%x bss_ref=%d \n",__func__,
                   vap, vap->iv_node_count, ni, ni->ni_bss_node, ni->ni_bss_node->ni_refcnt);

    return ni;
}

/* Delete key before deleting peer */
void
ieee80211_node_clear_keys(struct ieee80211_node *ni)
{
    int i;
    struct ieee80211vap *vap = ni->ni_vap;
    if (vap) {
        /* Remove unicast and persta keys */
        if (ni->ni_ucastkey.wk_valid) {
            ieee80211_crypto_delkey(vap, &ni->ni_ucastkey, ni);
        }
        if (ni->ni_persta) {
            if (ni->ni_persta->nips_hwkey.wk_valid) {
                ieee80211_crypto_delkey(vap, &ni->ni_persta->nips_hwkey, ni);
            }
            for (i = 0; i < IEEE80211_WEP_NKID; i++) {
                if (ni->ni_persta->nips_swkey[i].wk_valid) {
                    ieee80211_crypto_delkey(vap, &ni->ni_persta->nips_swkey[i], ni);
                }
            }
        }
        IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
                       "node_cleanup: vap=0x%x, nodecount=%d, ni=0x%x, ni_bss_node=0x%x bss_ref=%d \n",
                       vap, vap->iv_node_count, ni, ni->ni_bss_node, ni->ni_bss_node->ni_refcnt);
    }
    else {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\nvap is null\n");
    }

}

/*
 * Reclaim any resources in a node and reset any critical
 * state.  Typically nodes are free'd immediately after,
 * but in some cases the storage may be reused so we need
 * to insure consistent state (should probably fix that).
 */
static void
node_cleanup(struct ieee80211_node *ni)
{
    struct ieee80211vap *vap = ni->ni_vap;

#define       N(a)    (sizeof(a)/sizeof(a[0]))

    ASSERT(vap);
    /*
     * Tmp node didn't attach pwr save staff, so skip ps queue
     * cleanup
     */
    if (!ieee80211node_has_flag(ni, IEEE80211_NODE_TEMP)) {
        ieee80211_node_saveq_cleanup(ni);
    }

    /*
     * Preserve SSID, WPA, and WME ie's so the bss node is
     * reusable during a re-auth/re-assoc state transition.
     * If we remove these data they will not be recreated
     * because they come from a probe-response or beacon frame
     * which cannot be expected prior to the association-response.
     * This should not be an issue when operating in other modes
     * as stations leaving always go through a full state transition
     * which will rebuild this state.
     *
     * XXX does this leave us open to inheriting old state?
     */
        ieee80211_node_clear_keys(ni);

    if (ni->ni_associd && vap && (vap->iv_aid_bitmap != NULL))
        IEEE80211_AID_CLR(vap, ni->ni_associd);
    ni->ni_associd = 0;
    ni->ni_assocuptime = 0;
    wep_mbssid_node_cleanup(ni);
    ni->ni_rxkeyoff = 0;


#if ATH_SUPPORT_SPLITMAC
    ni->splitmac_state = IEEE80211_SPLITMAC_NODE_INIT;
#endif

#undef N
}

static void
node_free(struct ieee80211_node *ni)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;
    int i, tick_counter = 0;
#define       N(a)    (sizeof(a)/sizeof(a[0]))

    ic->ic_node_cleanup(ni);

    while (OS_ATOMIC_CMPXCHG(&(ni->ni_rxfrag_lock), 0, 1) == 1) {
        /* busy wait; can be executed at IRQL <= DISPATCH_LEVEL */
        if (tick_counter++ > 100) {    // no more than 1ms
            break;
        }
        OS_DELAY(10);
    }

    if (ni->ni_rxfrag[0] != NULL) {
        wbuf_free(ni->ni_rxfrag[0]);
        ni->ni_rxfrag[0] = NULL;
    }

    (void) OS_ATOMIC_CMPXCHG(&(ni->ni_rxfrag_lock), 1, 0);

    if (ni->ni_challenge != NULL) {
        OS_FREE(ni->ni_challenge);
        ni->ni_challenge = NULL;
    }

#if IEEE80211_DEBUG_REFCNT
    if (ni->trace != NULL) {
        OS_FREE(ni->trace);
        ni->trace = NULL;
    }
#endif

    if (ni->ni_wpa_ie != NULL) {
        OS_FREE(ni->ni_wpa_ie);
        ni->ni_wpa_ie = NULL;
    }

    if (ni->ni_wps_ie != NULL) {
        OS_FREE(ni->ni_wps_ie);
        ni->ni_wps_ie = NULL;
    }

    if (ni->ni_ath_ie != NULL) {
        OS_FREE(ni->ni_ath_ie);
        ni->ni_ath_ie = NULL;
    }

#if UMAC_SUPPORT_WNM

        if (ni->ni_wnm != NULL) {
            ieee80211_wnm_ndetach(ni);
            OS_FREE(ni->ni_wnm);
            ni->ni_wnm = NULL;
        }
#endif

    if (ni->ni_wme_ie != NULL) {
        OS_FREE(ni->ni_wme_ie);
        ni->ni_wme_ie = NULL;
    }


    if (vap) {
        /* free unicast and persta keys */
        ieee80211_crypto_freekey(vap, &ni->ni_ucastkey);
        if (ni->ni_persta) {
            ieee80211_crypto_freekey(vap, &ni->ni_persta->nips_hwkey);
            for (i = 0; i < IEEE80211_WEP_NKID; i++) {
                ieee80211_crypto_freekey(vap, &ni->ni_persta->nips_swkey[i]);
            }
        }
    }

    if (ni->ni_persta) {
        OS_FREE(ni->ni_persta);
        ni->ni_persta = NULL;
    }

#if UMAC_SUPPORT_RRM
    if (ni->ni_rrm_stats) {
        OS_FREE(ni->ni_rrm_stats);
        ni->ni_rrm_stats = NULL;
    }
#endif

#if QCN_IE
    if (ni->ni_qcn_ie) {
        OS_FREE(ni->ni_qcn_ie);
        ni->ni_qcn_ie = NULL;
    }
#endif

    /* Tmp node doesn't attach the pwrsave queue */
    if (!ieee80211node_has_flag(ni, IEEE80211_NODE_TEMP)) {
        ieee80211_node_saveq_detach(ni);
    }
    ieee80211_admctl_deinit(ni);
#undef N
    LIST_REMOVE(ni, ni_dump_list);
}

static u_int8_t
node_getrssi(const struct ieee80211_node *ni,  int8_t chain, u_int8_t flags)
{
    return ni->ni_rssi;
}

#if IEEE80211_DEBUG_NODELEAK
void wlan_debug_dump_nodes_tgt(void);
#endif

void
_ieee80211_free_node(struct ieee80211_node *ni)
{
    struct ieee80211vap         *vap = ni->ni_vap;
    struct ieee80211_node       *ni_bss_node = ni->ni_bss_node;
    struct ieee80211com         *ic = ni->ni_ic;

    ASSERT(vap);

    if (ni->ni_table) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: WARN: Freeing node while its still present in node table"
               " ni: 0x%p, vap: 0x%p, bss_node: 0x%p, ic: 0x%p, ni_table: 0x%p,"
               " ic_sta: 0x%p, refcnt: %d\n", __func__, ni, vap, ni_bss_node,
               vap->iv_ic, ni->ni_table, (&(vap->iv_ic)->ic_sta),
               ieee80211_node_refcnt(ni));
    }

    if (ni->ni_ext_flags & IEEE80211_NODE_NON_DOTH_STA) {
        ic->ic_non_doth_sta_cnt--;
    }

    if (ni->ni_associd && vap->iv_aid_bitmap != NULL)
        IEEE80211_AID_CLR(vap, ni->ni_associd);

    if ((ni->ni_flags & IEEE80211_NODE_TEMP) == 0) {
        IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
                       "%s", "station free \n");
    }

#if IEEE80211_DEBUG_NODELEAK
    do {
        rwlock_state_t lock_state;
        OS_RWLOCK_WRITE_LOCK(&ni->ni_ic->ic_nodelock,&lock_state);
        TAILQ_REMOVE(&ni->ni_ic->ic_nodes, ni, ni_alloc_list);
        OS_RWLOCK_WRITE_UNLOCK(&ni->ni_ic->ic_nodelock,&lock_state);
    } while(0);
#endif

#if QCA_AIRTIME_FAIRNESS
    if (ni->ni_atf_debug) {
        OS_FREE(ni->ni_atf_debug);
        ni->ni_atf_debug = NULL;
    }
#endif

    IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
                   "%s: vap=0x%x, nodecount=%d, ni=0x%x, ni_bss_node=0x%x bss_ref=%d \n",__func__,
                   vap, vap->iv_node_count, ni, ni->ni_bss_node, ni->ni_bss_node->ni_refcnt);

    IEEE80211_NODE_STATE_LOCK_DESTROY(ni);

#ifdef ATH_SUPPORT_TxBF
    if ( ni->ni_explicit_compbf || ni->ni_explicit_noncompbf || ni->ni_implicit_bf){
        OS_CANCEL_TIMER(&(ni->ni_cv_timer));
        OS_FREE_TIMER(&(ni->ni_cv_timer));
        OS_CANCEL_TIMER(&(ni->ni_report_timer));
        OS_FREE_TIMER(&(ni->ni_report_timer));
        ni->ni_txbf_timer_initialized = 0;

        /* clear TxBF mode active indicator*/
        ni->ni_explicit_compbf = 0;
        ni->ni_explicit_noncompbf = 0;
        ni->ni_implicit_bf = 0;
    }
#endif
    if((ni == vap->iv_bss) && (vap->iv_node_count > 1)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "All nodes should be freed before bss node gets freed."
                 " node count is %d Investigate!!!!\n",vap->iv_node_count);
#if IEEE80211_DEBUG_NODELEAK
        wlan_debug_dump_nodes_tgt();
#endif
    }
#if UNIFIED_SMARTANTENNA
        ieee80211_smart_ant_node_disconnect(ni);
#endif

    ni->ni_ic->ic_node_free(ni);

    if (ni != ni_bss_node) {
        IEEE80211_VAP_LOCK(vap);
        vap->iv_node_count--;
        IEEE80211_VAP_UNLOCK(vap);
        ieee80211_free_node(ni_bss_node);
    } else {

        /* Do not call state event when state machine is running on any vap
         * to avoid deadlock*/
        if (ieee80211_get_sm_state(vap->iv_ic)) {
            ieee80211_vap_bss_node_freed(vap);
        } else {
            ieee80211_state_event(vap, IEEE80211_STATE_EVENT_BSS_NODE_FREED);
        }
    }
}

/*
 * Free a node. It is mostly used for decrementing
 * node reference count of an active ap or an associated station.
 * If this is last reference of the node (refcnt reaches 0),
 * free the memory.
 */
void
#if IEEE80211_DEBUG_REFCNT
ieee80211_free_node_debug(struct ieee80211_node *ni, const char *func, int line, const char *file)
#else
ieee80211_free_node(struct ieee80211_node *ni)
#endif
{
    if (ni) {
        if (ieee80211_node_dectestref(ni)) {
            ASSERT(ni->ni_table == NULL); /* node can not be in node table */
#if IEEE80211_DEBUG_REFCNT
            TRACENODE_DEC(ni, func, line, file);
#endif
            _ieee80211_free_node(ni);
        }
#if IEEE80211_DEBUG_REFCNT
         else
            TRACENODE_DEC(ni, func, line, file);
#endif
    }
}

/*
 * Reclaim a node. It is mostly used when a node leaves the network.
 * remove it from the node table and decrement the held reference..
 * It must be called with OS_WRITE_LOCK being held.
 */
static void
#if IEEE80211_DEBUG_REFCNT
_node_reclaim(struct ieee80211_node_table *nt, struct ieee80211_node *ni,
             const char *func, int line, const char *file)
#else
node_reclaim(struct ieee80211_node_table *nt, struct ieee80211_node *ni)
#endif
{
    if (ni->ni_table == NULL ) {
        return;
    }
    ASSERT(ieee80211_node_refcnt(ni));
    if (ieee80211_node_refcnt(ni) == 0) {
        ieee80211_note(ni->ni_vap, IEEE80211_MSG_NODE,
            "node_reclaim called with 0 refcount for %s, vap: 0x%p \n",
            ((ni == ni->ni_vap->iv_bss) ? "BSS NODE" : "NON BSS NODE"), ni->ni_vap);
    }
    /*
     * Other references are present, just remove the
     * node from the table so it cannot be found.  When
     * the references are dropped storage will be
     * reclaimed.
     */
    TAILQ_REMOVE(&nt->nt_node, ni, ni_list);
    LIST_REMOVE(ni, ni_hash);
#if UMAC_SUPPORT_PROXY_ARP
    if (ni->ni_ipv4_addr) {
        LIST_REMOVE(ni, ni_ipv4_hash);
    }
    ieee80211_node_remove_ipv6_by_node(nt, ni);
#endif
    ni->ni_table = NULL;    /* clear reference */

    ieee80211_free_node(ni); /* decrement the ref count */
}

struct ieee80211_node *
#if IEEE80211_DEBUG_REFCNT
_ieee80211_find_node_debug(struct ieee80211_node_table *nt, const u_int8_t *macaddr,
                     const char *func, int line, const char *file)
#else
_ieee80211_find_node(struct ieee80211_node_table *nt, const u_int8_t *macaddr)
#endif
{
    struct ieee80211_node *ni;
    int hash;

    hash = IEEE80211_NODE_HASH(macaddr);
    LIST_FOREACH(ni, &nt->nt_hash[hash], ni_hash) {
        if (IEEE80211_ADDR_EQ(ni->ni_macaddr, macaddr)) {
#if IEEE80211_DEBUG_REFCNT
            ieee80211_ref_node_debug(ni, func, line, file); /* mark referenced */
#else
            ieee80211_ref_node(ni); /* mark referenced */
#endif
            return ni;
        }
    }
    return NULL;
}

#if IEEE80211_DEBUG_REFCNT
#define	_ieee80211_find_node(nt, mac)   \
    _ieee80211_find_node_debug(nt, mac, __func__, __LINE__, __FILE__)
#endif

struct ieee80211_node *
#if IEEE80211_DEBUG_REFCNT
ieee80211_find_node_debug(struct ieee80211_node_table *nt, const u_int8_t *macaddr,
                          const char *func, int line, const char *file)
#else
ieee80211_find_node(struct ieee80211_node_table *nt, const u_int8_t *macaddr)
#endif
{
    struct ieee80211_node *ni;
    rwlock_state_t lock_state;
    OS_BEACON_DECLARE_AND_RESET_VAR(flags);

    OS_BEACON_READ_LOCK(&nt->nt_nodelock, &lock_state, flags);
#if IEEE80211_DEBUG_REFCNT
    ni = _ieee80211_find_node_debug(nt, macaddr, func, line, file);
#else
    ni = _ieee80211_find_node(nt, macaddr);
#endif
    OS_BEACON_READ_UNLOCK(&nt->nt_nodelock, &lock_state, flags);

    return ni;
}

/*
 * Return a reference to the appropriate node for sending
 * a data frame.  This handles node discovery in adhoc networks.
 */
struct ieee80211_node *
#if IEEE80211_DEBUG_REFCNT
ieee80211_find_txnode_debug(struct ieee80211vap *vap, const u_int8_t *macaddr,
                            const char *func, int line, const char *file)
#else
ieee80211_find_txnode(struct ieee80211vap *vap, const u_int8_t *macaddr)
#endif
{
    struct ieee80211_node_table *nt = &vap->iv_ic->ic_sta;
    struct ieee80211_node *ni = NULL;
    rwlock_state_t lock_state;

    OS_BEACON_DECLARE_AND_RESET_VAR(flags);

    OS_BEACON_READ_LOCK(&nt->nt_nodelock, &lock_state, flags);

    if (vap->iv_bss) {
        if (vap->iv_opmode == IEEE80211_M_STA ||
            vap->iv_opmode == IEEE80211_M_WDS) {
#if IEEE80211_DEBUG_REFCNT
            ni = ieee80211_ref_node_debug(vap->iv_bss, func, line, file);
#else
            ni = ieee80211_ref_node(vap->iv_bss);
#endif
        }
        else if  (IEEE80211_IS_MULTICAST(macaddr)) {
            if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
                if (vap->iv_sta_assoc > 0) {
#if IEEE80211_DEBUG_REFCNT
                    ni = ieee80211_ref_node_debug(vap->iv_bss, func, line, file);
#else
                    ni = ieee80211_ref_node(vap->iv_bss);
#endif
                }
                else {
                    /* No station associated to AP */
                    vap->iv_stats.is_tx_nonode++;
                    ni = NULL;
                }
            }
            else {
                ni = ieee80211_ref_node(vap->iv_bss);
            }
        }
        else {
            ni = _ieee80211_find_node(nt, macaddr);
            if (ni == NULL) {
                if( (vap->iv_opmode == IEEE80211_M_HOSTAP)  && wlan_get_param(vap, IEEE80211_FEATURE_WDS) ) {
                    ni = ieee80211_find_wds_node(nt, macaddr);
                }
            }
        }
    }
    OS_BEACON_READ_UNLOCK(&nt->nt_nodelock, &lock_state, flags);

    /*
     * Since all vaps share the same node table, we may find someone else's
     * node (sigh!).
     */
    if (ni && ni->ni_vap != vap)
    {
        ieee80211_unref_node(&ni);
        return NULL;
    }
    return ni;
}

#if IEEE80211_DEBUG_REFCNT
struct ieee80211_node *
ieee80211_find_rxnode_debug(struct ieee80211com *ic,
                            const struct ieee80211_frame_min *wh,
                            const char *func, int line, const char *file)
#else
struct ieee80211_node *
ieee80211_find_rxnode(struct ieee80211com *ic,
                      const struct ieee80211_frame_min *wh)
#endif
{
    struct ieee80211_node_table *nt = &ic->ic_sta;
    struct ieee80211_node *ni = NULL;
    rwlock_state_t lock_state;
    OS_BEACON_DECLARE_AND_RESET_VAR(flags);

    OS_BEACON_READ_LOCK(&nt->nt_nodelock, &lock_state, flags);
#if IEEE80211_DEBUG_REFCNT
    ni = ieee80211_find_rxnode_nolock_debug(ic, wh, func, line, file);
#else
    ni = ieee80211_find_rxnode_nolock(ic, wh);
#endif
    OS_BEACON_READ_UNLOCK(&nt->nt_nodelock, &lock_state, flags);

    return ni;
}

#if ATH_SUPPORT_WRAP
static struct ieee80211_node *
#if IEEE80211_DEBUG_REFCNT
_wrap_find_rxnode_debug(struct ieee80211_node_table *nt,
                        const uint8_t ra[IEEE80211_ADDR_LEN],
                        const uint8_t ta[IEEE80211_ADDR_LEN],
                        const char *func, int line, const char *file)
#else
_wrap_find_rxnode(struct ieee80211_node_table *nt,
                  const uint8_t ra[IEEE80211_ADDR_LEN],
                  const uint8_t ta[IEEE80211_ADDR_LEN])
#endif
{
    struct ieee80211_node *ni;
    int hash;

    hash = IEEE80211_NODE_HASH(ta);
    LIST_FOREACH(ni, &nt->nt_hash[hash], ni_hash) {
        if (IEEE80211_ADDR_EQ(ni->ni_macaddr, ta)) {
            if (ni->ni_vap->iv_opmode == IEEE80211_M_STA) {
                /*
                 * If multiple STA's associate to the same AP, we end up have
                 * multiple nodes w/ all their ni->ni_macaddr equals to the
                 * AP's MAC address in the node table. The way to distinguish
                 * them is to compare the node VAP's MAC address with RA. If
                 * RA is multicast address, return NULL directly because we
                 * couldn't find it anyway.
                 */
                if (IEEE80211_IS_MULTICAST(ra))
                    return NULL;
                if (!IEEE80211_ADDR_EQ(ra, ni->ni_vap->iv_myaddr))
                    continue;
            }
#if IEEE80211_DEBUG_REFCNT
            ieee80211_ref_node_debug(ni, func, line, file); /* mark referenced */
#else
            ieee80211_ref_node(ni); /* mark referenced */
#endif
            return ni;
        }
    }
    return NULL;
}

struct ieee80211_node *
#if IEEE80211_DEBUG_REFCNT
ieee80211_find_wrap_node_debug(struct ieee80211vap *vap, const u_int8_t *macaddr,
                               const char *func, int line, const char *file)
#else
ieee80211_find_wrap_node(struct ieee80211vap *vap, const u_int8_t *macaddr)
#endif
{
    struct ieee80211_node *ni;
    rwlock_state_t lock_state;
    OS_BEACON_DECLARE_AND_RESET_VAR(flags);
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_node_table *nt = &ic->ic_sta;

    OS_BEACON_READ_LOCK(&nt->nt_nodelock, &lock_state, flags);
#if IEEE80211_DEBUG_REFCNT
    ni = _wrap_find_rxnode_debug(nt, vap->iv_myaddr, macaddr, func, line, file);
#else
    ni = _wrap_find_rxnode(nt, vap->iv_myaddr, macaddr);
#endif
    OS_BEACON_READ_UNLOCK(&nt->nt_nodelock, &lock_state, flags);

    return ni;

}
#endif

#if !IEEE80211_DEBUG_REFCNT
struct ieee80211_node *
ieee80211_find_rxnode_nolock(struct ieee80211com *ic,
                      const struct ieee80211_frame_min *wh)
#else
struct ieee80211_node *
ieee80211_find_rxnode_nolock_debug(struct ieee80211com *ic,
                             const struct ieee80211_frame_min *wh,
                             const char *func, int line, const char *file)
#endif
{
#define	IS_CTL(wh)  \
    ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_CTL)
#define	IS_PSPOLL(wh)   \
    ((wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) == IEEE80211_FC0_SUBTYPE_PS_POLL)
#define	IS_BAR(wh) \
    ((wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) == IEEE80211_FC0_SUBTYPE_BAR)

    struct ieee80211_node_table *nt = &ic->ic_sta;

    if (IS_CTL(wh) && !IS_PSPOLL(wh) && !IS_BAR(wh))
        return _ieee80211_find_node(nt, wh->i_addr1);

#if ATH_SUPPORT_WRAP
#if IEEE80211_DEBUG_REFCNT
    return _wrap_find_rxnode_debug(nt, wh->i_addr1, wh->i_addr2, func, line, file);
#else
    return _wrap_find_rxnode(nt, wh->i_addr1, wh->i_addr2);
#endif
#else
    return _ieee80211_find_node(nt, wh->i_addr2);
#endif
#undef IS_BAR
#undef IS_PSPOLL
#undef IS_CTL
}

#if IEEE80211_DEBUG_REFCNT
struct ieee80211_node *
ieee80211_ref_node_debug(struct ieee80211_node *ni,
                          const char *func, int line, const char *file)
{
    atomic_inc(&(ni->ni_refcnt));
    TRACENODE_INC(ni, func, line, file);
    return ni;
}
EXPORT_SYMBOL(ieee80211_ref_node_debug);

void
ieee80211_unref_node_debug(struct ieee80211_node **ni,
                          const char *func, int line, const char *file)
{
    atomic_dec(&((*ni)->ni_refcnt));
    TRACENODE_DEC(*ni, func, line, file);
    *ni = NULL;			/* guard against use */
}
EXPORT_SYMBOL(ieee80211_unref_node_debug);
#endif

void
ieee80211_node_authorize(struct ieee80211_node *ni)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;

    ni->ni_flags |= IEEE80211_NODE_AUTH;
    ni->ni_inact_reload = ni->ni_vap->iv_inact_run;

    /* Deliver node authorize event */
    IEEE80211_DELIVER_EVENT_MLME_NODE_AUTHORIZED_INDICATION(vap, ni->ni_macaddr);

    if (ni->ni_inact > ni->ni_inact_reload)
        ni->ni_inact = ni->ni_inact_reload;

#if ATH_BAND_STEERING
        ni->ni_bs_inact_flag = false;
        ni->ni_bs_inact_reload = ni->ni_ic->ic_bs_inact;
        ni->ni_bs_inact = ni->ni_bs_inact_reload;
        ni->ni_bs_steering_flag = false;
#endif

    if (ic->ic_node_authorize) {
        ic->ic_node_authorize(ni,TRUE);
    }
    /* start session timeout */
    ni->ni_session = vap->iv_session;
}

void
ieee80211_node_unauthorize(struct ieee80211_node *ni)
{
    struct ieee80211com *ic = NULL;

    ni->ni_flags &= ~IEEE80211_NODE_AUTH;
    ni->ni_inact_reload = ni->ni_vap->iv_inact_auth;
    if (ni->ni_inact > ni->ni_inact_reload)
        ni->ni_inact = ni->ni_inact_reload;

    ic = ni->ni_ic;

    if (ic == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:WARN ni->ni_ic is NULL for ni(%p) ni_macddr %s\n",
                __func__, ni, ether_sprintf(ni->ni_macaddr));
    }
    else if(ic->ic_node_authorize) {
        ic->ic_node_authorize(ni,FALSE);
    }

    /* disable session timeout */
    ni->ni_session = IEEE80211_SESSION_TIME;
}

static void ieee80211_node_saveq_age_iter(void *arg, struct ieee80211_node *ni)
{
    struct ieee80211_iter_arg *itr_arg = (struct ieee80211_iter_arg *)arg;
    struct ieee80211com *ic = ni->ni_ic;

    if (ni->ni_associd != 0 && itr_arg->count < ic->ic_num_clients) {
        /* increment the ref count so that the node is not freed */
        itr_arg->nodes[itr_arg->count] = ieee80211_ref_node(ni);
        ++itr_arg->count;
    }

}

/*
 * age out frames in save queue in each node.
 */
static void ieee80211_timeout_node_saveq_age( struct ieee80211_node_table *nt)
{
  struct ieee80211com *ic = nt->nt_ic;
  struct ieee80211_iter_arg *itr_arg = NULL;
  u_int32_t i;

  itr_arg = (struct ieee80211_iter_arg *)qdf_mem_malloc(sizeof(struct ieee80211_iter_arg));
  if (itr_arg == NULL) {
          return;
  }

  itr_arg->count=0;
  itr_arg->vap=NULL;
  itr_arg->flag=0;

  ieee80211_iterate_node(ic,ieee80211_node_saveq_age_iter,(void *)itr_arg);
  for (i = 0;i < itr_arg->count; ++i)
  {
      /*
       * Age frames on the power save queue.
       */
      ieee80211_node_saveq_age(itr_arg->nodes[i]);

      /* decrement the ref count which is incremented above in ieee80211_sta_iter */
      ieee80211_free_node(itr_arg->nodes[i]);
  }
  qdf_mem_free(itr_arg);

}


/*
 * Timeout inactive stations and do related housekeeping.
 * Note that we cannot hold the node lock while sending a
 * frame as this would lead to a LOR.  Instead we use a
 * generation number to mark nodes that we've scanned and
 * drop the lock and restart a scan if we have to time out
 * a node.  Since we are single-threaded by virtue of
 * controlling the inactivity timer we can be sure this will
 * process each node only once.
 */
void
ieee80211_timeout_stations(struct ieee80211_node_table *nt)
{
    struct ieee80211_node *ni;
#if ATH_SUPPORT_TIDSTUCK_WAR || ATH_SUPPORT_KEYPLUMB_WAR
    struct ieee80211com *ic = nt->nt_ic;
#endif
#if ATH_SUPPORT_KEYPLUMB_WAR
    struct ieee80211_key    *k;    /* unicast key */
#endif
    u_int gen;
    u_int16_t associd;
    rwlock_state_t lock_state;
    OS_BEACON_DECLARE_AND_RESET_VAR(flags);

    ieee80211_timeout_node_saveq_age(nt);
    gen = nt->nt_scangen++;
restart:
    OS_BEACON_WRITE_LOCK(&nt->nt_nodelock, &lock_state, flags);
    TAILQ_FOREACH(ni, &nt->nt_node, ni_list) {
        if (ni->ni_scangen == gen)/* previously handled */
            continue;
        /*
         * Special case ourself; we may be idle for extended periods
         * of time and regardless reclaiming our state is wrong.
         */
        if (ni == ni->ni_vap->iv_bss) {
            /* NB: don't permit it to go negative */
            if (ni->ni_inact > 0)
                ni->ni_inact--;
            continue;
        }

        ni->ni_scangen = gen;

#ifdef ATH_SUPPORT_QUICK_KICKOUT
        if ((ni->ni_vap->iv_opmode == IEEE80211_M_HOSTAP) && ni->ni_kickout) {
            IEEE80211_NOTE(ni->ni_vap, IEEE80211_MSG_INACT, ni,
                           "station kicked out as it stayed in powersave for a long time (refcnt %u) associd %d\n",
                           ieee80211_node_refcnt(ni), IEEE80211_AID(ni->ni_associd));
            ni->ni_kickout = false;
            ieee80211_ref_node(ni);
            OS_BEACON_WRITE_UNLOCK(&nt->nt_nodelock, &lock_state, flags);
            ieee80211_kick_node(ni);
            ieee80211_free_node(ni);
            goto restart;
        }
#endif

        ni->ni_inact--;
#if UMAC_SUPPORT_NAWDS
        /* Never deauth the timeout NAWDS station.
         * But keep checking if it's still inactive.
         */
        if (ni->ni_flags & IEEE80211_NODE_NAWDS && ni->ni_inact <= 0) {
            ni->ni_inact = 1;
        }
#endif
        if ((ni->ni_vap->iv_create_flags & IEEE80211_LP_IOT_VAP) && (ni->ni_inact <= 0)) {
            ni->ni_inact = 1;
        }

        if (ni->ni_associd != 0) {

            /*
             * Probe the station before time it out.  We
             * send a null data frame which may not be
             * universally supported by drivers (need it
             * for ps-poll support so it should be...).
             */
#if ATH_SUPPORT_KEYPLUMB_WAR
            struct ieee80211vap * tmp_vap = ni->ni_vap;
            int i;

            k = &(ni->ni_ucastkey);
            if ((k) && (k->wk_cipher) && (k->wk_valid) &&
                    ((k->wk_cipher->ic_cipher == IEEE80211_CIPHER_AES_CCM) ||
                     (k->wk_cipher->ic_cipher == IEEE80211_CIPHER_TKIP) ||
                     (k->wk_cipher->ic_cipher == IEEE80211_CIPHER_AES_OCB)))
            {
                if(ic->ic_checkandplumb_key) {
                    if(!ic->ic_checkandplumb_key(tmp_vap, ni)) {
                        IEEE80211_DPRINTF(tmp_vap, IEEE80211_MSG_CRYPTO,
                                "%s: Software key: length %d flags %0x  valid %d keyix %d  cipher %s \n",
                                __FUNCTION__, k->wk_keylen , k->wk_flags, k->wk_valid, k->wk_keyix, k->wk_cipher->ic_name);
                        for (i = 0; i < k->wk_keylen; i++) {
                            IEEE80211_DPRINTF(tmp_vap, IEEE80211_MSG_CRYPTO, "%02x ", k->wk_key[i]);
                        }
                        IEEE80211_DPRINTF(tmp_vap, IEEE80211_MSG_CRYPTO, "%s: Key plumbed again in hw for STA (%s). Key mismatch\n",
                                __FUNCTION__, ether_sprintf(ni->ni_macaddr));
                    }
                }
            }
#endif
#if ATH_SUPPORT_TIDSTUCK_WAR
			/* Before Probing the station, clear RX TID stuck by sending DELBA */
            if (ni->ni_inact > ni->ni_vap->iv_inact_probe) {
                /*
                 * Grab a reference before unlocking the table
                 * so the node cannot be reclaimed before we
                 * send the frame.
                 */
                ieee80211_ref_node(ni);
                OS_BEACON_WRITE_UNLOCK(&nt->nt_nodelock, &lock_state, flags);
                ic->ic_clear_rxtid(ic, ni);
                ieee80211_free_node(ni);
                /*
                 * once the node table in unlocked.
                 * we need to rstart iterating the table
                 * as the table might have changed.
                 */
				goto restart;
			}
#endif

            if ((0 < ni->ni_inact) && (ni->ni_inact <= ni->ni_vap->iv_inact_probe)) {

                IEEE80211_NOTE(ni->ni_vap, IEEE80211_MSG_INACT, ni,
                               "probe station due to inactivity, inact %u \n",
                               ni->ni_inact);
                /*
                 * Grab a reference before unlocking the table
                 * so the node cannot be reclaimed before we
                 * send the frame.
                 */
                ieee80211_ref_node(ni);
                OS_BEACON_WRITE_UNLOCK(&nt->nt_nodelock, &lock_state, flags);
                ieee80211_send_nulldata(ni, 0);
                ieee80211_free_node(ni);
                /*
                 * once the node table in unlocked.
                 * we need to rstart iterating the table
                 * as the table might have changed.
                 */
                goto restart;
            }
        }

        /*
         * Make sure to timeout STAs who have sent 802.11
         * authentication but not have associated (a la M68).
         * Hostapd does not have timers to handle this, since
         * they don't know about these STAs.
         */
        if (ni->ni_inact <= 0) {
            IEEE80211_NOTE(ni->ni_vap, IEEE80211_MSG_INACT, ni,
                           "station timed out due to inactivity (refcnt %u) associd %d\n",
                           ieee80211_node_refcnt(ni), IEEE80211_AID(ni->ni_associd));
            /*
             * Send a deauthenticate frame and drop the station.
             * We grab a reference before unlocking the table so
             * the node cannot be reclaimed before we complete our
             * work.
             *
             * Separately we must drop the node lock before sending
             * in case the driver takes a lock, as this may result
             * in a LOR between the node lock and the driver lock.
             */
            ni->ni_vap->iv_stats.is_node_timeout++;
            ieee80211_ref_node(ni);
            OS_BEACON_WRITE_UNLOCK(&nt->nt_nodelock, &lock_state, flags);
            if (ni->ni_associd != 0) {
                /*
                 * wlan_mlme_deauth_request will call IEEE80211_NODE_LEAVE
                 * and also send notification to registered handlers .
                 */
                associd = ni->ni_associd;
                IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_AUTH, "%s: sending DEAUTH to %s, timeout stations reason %d\n",
                        __func__, ether_sprintf(ni->ni_macaddr), IEEE80211_REASON_AUTH_EXPIRE);
                wlan_mlme_deauth_request(ni->ni_vap,ni->ni_macaddr,IEEE80211_REASON_AUTH_EXPIRE);
                /* we need to send deauth indication to hostapd as indication
                   sent in wlan_mlme_deauth_request is in custom event and not
                   interpreted by hostpad */
                IEEE80211_DELIVER_EVENT_MLME_DEAUTH_INDICATION(ni->ni_vap, ni->ni_macaddr, associd, IEEE80211_REASON_AUTH_EXPIRE);
            } else if ( ni->ni_vap->iv_opmode == IEEE80211_M_IBSS || ni->ni_vap->iv_opmode == IEEE80211_M_STA) {
                ieee80211_sta_leave(ni);
            } else {
                associd = ni->ni_associd;
                IEEE80211_NODE_LEAVE(ni);

                if (ni) {
                    if (ni->ni_vap) {
                        /* EV77198 : Call MLME indication handler if node is in associated state */
                        IEEE80211_DELIVER_EVENT_MLME_DEAUTH_INDICATION(ni->ni_vap, ni->ni_macaddr, associd, IEEE80211_REASON_AUTH_EXPIRE);
                    }
                }
            }
            ieee80211_free_node(ni);
            goto restart;
        }
    }
    OS_BEACON_WRITE_UNLOCK(&nt->nt_nodelock, &lock_state, flags);
}

/*
 * Timeout stations whose session has expired.
 * For now, just send an event up the stack and let the higer layers handle it.
 */
void
ieee80211_session_timeout(struct ieee80211_node_table *nt)
{
    struct ieee80211_node *ni;
    rwlock_state_t lock_state;
    OS_BEACON_DECLARE_AND_RESET_VAR(flags);

    OS_BEACON_WRITE_LOCK(&nt->nt_nodelock, &lock_state, flags);
    TAILQ_FOREACH(ni, &nt->nt_node, ni_list) {
        /*
         * Special case ourself; we cannot timeout our session.
         */
        if (ni == ni->ni_vap->iv_bss) {
            /* NB: don't permit it to go negative */
            if (ni->ni_session > 0)
                ni->ni_session--;
            continue;
        }

        ni->ni_session--;
#if UMAC_SUPPORT_NAWDS
        /* Never timeout the session for NAWDS station. */
        if (ni->ni_flags & IEEE80211_NODE_NAWDS && ni->ni_session <= 0) {
            ni->ni_session = 1;
        }
#endif

        if (ni->ni_session <= 0) {
            /*
             * For now, just send an event up the stack and let the higer layers handle it.
             */
            IEEE80211_DELIVER_EVENT_SESSION_TIMEOUT(ni->ni_vap, ni->ni_macaddr);
        }
    }
    OS_BEACON_WRITE_UNLOCK(&nt->nt_nodelock, &lock_state, flags);
}

void
ieee80211_node_set_chan(struct ieee80211_node *ni)
{
    struct ieee80211_channel *chan = ni->ni_vap->iv_bsschan;

    KASSERT(chan != IEEE80211_CHAN_ANYC, ("bss channel not setup\n"));
    ni->ni_chan = chan;
    ieee80211_init_node_rates(ni, chan);
}


/**
* @brief    update new channel, channel width and phy mode after
*           changing channel and width dynamically.
*
* @param arg    opaque pointer. not used
* @param ni     node which needs to be updated
*
*/
void ieee80211_node_update_chan_and_phymode(void *arg, struct ieee80211_node *ni)
{
    struct ieee80211_channel *chan = ni->ni_vap->iv_bsschan;
    struct ieee80211com *ic = ni->ni_vap->iv_ic;
    enum ieee80211_cwm_width chwidth = 0;

    KASSERT(chan != IEEE80211_CHAN_ANYC,
        ("update_chan_and_phymode: bss channel not setup\n"));
    ni->ni_chan = chan;
    /* set node chan width to minimum of nodes previous chan width
     * and vap/ic chan width.
     */
    chwidth = ic->ic_cwm_get_width(ic);
    if (ni->ni_chwidth > chwidth) {
        ni->ni_chwidth = chwidth;
    }
    /* Update phy mode */
    ieee80211_update_ht_vht_phymode(ic, ni);
}

void
ieee80211_iterate_node(struct ieee80211com *ic, ieee80211_iter_func *func, void *arg)
{
    struct ieee80211_node_table *nt = &ic->ic_sta;
    struct ieee80211_node *ni = NULL, *next=NULL;
    rwlock_state_t lock_state;
    OS_BEACON_DECLARE_AND_RESET_VAR(flags);
    OS_BEACON_READ_LOCK(&nt->nt_nodelock, &lock_state, flags);
    TAILQ_FOREACH_SAFE(ni, &nt->nt_node, ni_list, next) {
        /* ieee80211_sta_leave may be called or RWLOCK_WRITE_LOCK may be acquired */
        /* TBD: this is not multi-thread safe. Should use wlan_iterate_station_list */
        ieee80211_ref_node(ni);
        (*func)(arg, ni);
        ieee80211_free_node(ni);
    }
    OS_BEACON_READ_UNLOCK(&nt->nt_nodelock, &lock_state, flags);
}

void
ieee80211_copy_bss(struct ieee80211_node *nbss, const struct ieee80211_node *obss)
{
    /* propagate useful state */
    nbss->ni_ath_flags = obss->ni_ath_flags;
    nbss->ni_txpower = obss->ni_txpower;
    nbss->ni_vlan = obss->ni_vlan;
    nbss->ni_beacon_rstamp = obss->ni_beacon_rstamp;
    nbss->ni_rssi = obss->ni_rssi;
}

/*
 * Function to get the total number of MU-MIMO
 * capable clients (including dedicated clients
 */
u_int16_t
get_mu_total_clients(MU_CAP_WAR *war)
{
    int cnt;
    u_int16_t total = 0;
    for (cnt=0;cnt<MU_CAP_CLIENT_TYPE_MAX;cnt++)
    {
        total += war->mu_cap_client_num[cnt];
    }
    return total;
}

/*
 * Function which determines whether the conditions are ripe
 * for the sole dedicated MU-MIMO 1X1 client to be kicked out
 * so that it can join back as SU-MIMO 2X2
 */
int
ieee80211_mu_cap_dedicated_mu_kickout(MU_CAP_WAR *war)
{
    if ((war->mu_cap_client_num[MU_CAP_DEDICATED_SU_CLIENT] == 0) &&
            (war->mu_cap_client_num[MU_CAP_CLIENT_NORMAL] == 0) &&
            (war->mu_cap_client_num[MU_CAP_DEDICATED_MU_CLIENT] == 1))
    {
        return 1;
    }
    return 0;
}

/*
 * Function which sets the probe response behaviour variable
 * based on the counts and overrides
 */
static void
update_probe_response_behaviour(MU_CAP_WAR *war)
{
    if ((!war->mu_cap_war_override) && (get_mu_total_clients(war) == 0)) {
        war->modify_probe_resp_for_dedicated = 1;
    } else {
        war->modify_probe_resp_for_dedicated = 0;
    }
}

/*
 * Find out whether this client is joining after
 * receiving our WAR-"hacked" probe response
 */
static int
is_node_result_of_modified_probe_response(u_int8_t *macaddr,
                                         MU_CAP_WAR *war)
{
    struct DEDICATED_CLIENT_MAC *dedicated_mac;
    struct DEDICATED_CLIENT_MAC *temp;
    int hash = IEEE80211_NODE_HASH(macaddr);
    LIST_FOREACH_SAFE(dedicated_mac, &war->dedicated_client_list[hash], list, temp) {
        if (IEEE80211_ADDR_EQ(dedicated_mac->macaddr, macaddr)) {
            /*
             * No need to keep this entry
             * beyond the time where it needs to be checked
             */
            LIST_REMOVE(dedicated_mac,list);
            war->dedicated_client_number--;
            OS_FREE(dedicated_mac);
            return 1;
        }
    }

    /*
     * If not present in database,means not result of tweaked probe response
     */
    return 0;
}

/*
 * Function to handle all the MU-CAP counts during
 * client join
 */
static u_int8_t
ieee80211_mu_cap_client_join(struct ieee80211_node *ni,
                            struct ieee80211vap *vap,
                            MU_CAP_WAR *war)
{
    u_int8_t new_timer_state = MU_TIMER_STOP;
    int new_index = get_mu_total_clients(war);
    int total_mu_capable_clients;
    int is_tweaked_probe_response =
       is_node_result_of_modified_probe_response(ni->ni_macaddr, war);

    /*Client joining*/
    /*
     * The check for new_index == MAX_PEER_NUM
     * is for avoiding Klocwork issues. This will
     * never happen
     */
    if (!ni->ni_mu_vht_cap || (new_index >= MAX_PEER_NUM))
    {
        return new_timer_state;
    }

    OS_MEMCPY(war->mu_cap_client_addr[new_index],
            (char *)(ni->ni_macaddr),
            IEEE80211_ADDR_LEN);

    /*
     * Classification of client into one of the below 3
     * -> Normal MU-Capable client
     * -> Dedicated MU-Capable (if responding to normal Probe-Resp)
     * -> Dedicated SU-Capable (if responding to "hacked" Probe-Resp)
     */
    if(!ni->ni_mu_dedicated) {
        war->mu_cap_client_flag[new_index] = MU_CAP_CLIENT_NORMAL;
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                "MU-Capable non-dedicated client joined, mac: %s\n",
                            ether_sprintf(ni->ni_macaddr));
    } else if (is_tweaked_probe_response) {
        war->mu_cap_client_flag[new_index] = MU_CAP_DEDICATED_SU_CLIENT;
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                "Dedicated SU-Capabale client joined, mac: %s\n",
                ether_sprintf(ni->ni_macaddr));
    } else {
        war->mu_cap_client_flag[new_index] = MU_CAP_DEDICATED_MU_CLIENT;
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                "Dedicated MU-Capabale client joined, mac: %s\n",
                ether_sprintf(ni->ni_macaddr));
    }

    /*
     * Increment the respective counters
     */
    war->mu_cap_client_num[war->mu_cap_client_flag[new_index]]++;
    if (!war->mu_cap_war)
    {
        /*
         * If WAR is disabled, take no
         * further action
         */
        return new_timer_state;
    }

    /*
     * Decide on the Kick-out action
     */
    total_mu_capable_clients =
        war->mu_cap_client_num[MU_CAP_CLIENT_NORMAL] +
        war->mu_cap_client_num[MU_CAP_DEDICATED_MU_CLIENT];

    if (((total_mu_capable_clients >= 1) &&
                (war->mu_cap_client_num[MU_CAP_DEDICATED_SU_CLIENT] >= 1)) ||
            (war->mu_cap_client_num[MU_CAP_DEDICATED_SU_CLIENT] >= 2)) {
        new_timer_state = MU_TIMER_PENDING;
        war->mu_timer_cmd = MU_CAP_TIMER_CMD_KICKOUT_SU_CLIENTS;
    } else if (ieee80211_mu_cap_dedicated_mu_kickout(war)) {
        new_timer_state = MU_TIMER_PENDING;
        war->mu_timer_cmd = MU_CAP_TIMER_CMD_KICKOUT_DEDICATED;
    }

    /*
     * Decide on override
     */
    if ((total_mu_capable_clients == 0) &&
            (war->mu_cap_client_num[MU_CAP_DEDICATED_SU_CLIENT] >= 2)) {
        /*
         * This is the tricky scenario
         * 2 dedicated clients joining together
         * Both join as 2x2 SU, then get kicked out
         * join back again as 2x2, and this becomes a cycle
         * override will ensure that this kick-out happens
         * only once.
         * The override will ensure that the next time,
         * they send probe request, the probe response will have
         * BF=1, making both of them join as 1x1.
         * Then at the time of the first dedicated client joining,
         * this override will be removed
         */
        war->mu_cap_war_override = 1;
    } else if (total_mu_capable_clients >= 1) {
        /*
         * There is a safe-guard for the mu-capable client count
         * So override can be removed, since the count will make sure
         * that the probe response has beamformer enabled.
         * There is no need of an override at this point
         */
        war->mu_cap_war_override = 0;
    }

    update_probe_response_behaviour(war);


    return new_timer_state;
}

/*
 * Function to handle all the MU-CAP counts during
 * client leave
 */
static u_int8_t
ieee80211_mu_cap_client_leave(struct ieee80211_node *ni,
                              struct ieee80211vap *vap,
                              MU_CAP_WAR *war)
{
    u_int8_t new_timer_state = MU_TIMER_STOP;
    int i;
    int total_mu_clients = get_mu_total_clients(war);
    int last_index = total_mu_clients - 1;

    if (total_mu_clients > MAX_PEER_NUM) {
        /*
         * This condition will never happen
         * Leaving the check here to make
         * Klocwork check pass
         */
        return new_timer_state;
    }

    /*Client leaving*/
    for (i = 0; i < total_mu_clients; i++) {
        if (IEEE80211_ADDR_EQ((char *)(war->mu_cap_client_addr[i]),
                                (char *)(ni->ni_macaddr))) {
            break;
        }
    }
    if (i == total_mu_clients) {
        return new_timer_state;
    }

    /* Decrement the respecitve counter*/
    war->mu_cap_client_num[war->mu_cap_client_flag[i]]--;
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
            "MU-Capable client leaving mac %s Type: %d\n",
                    ether_sprintf(ni->ni_macaddr), war->mu_cap_client_flag[i]);

    /*
     * Replace the entry for the leaving node with the last_index entry
     * Then, fill the last entry with zeroes
     */
    OS_MEMCPY((char *)(war->mu_cap_client_addr[i]),
            (char *)(war->mu_cap_client_addr[last_index]),
            IEEE80211_ADDR_LEN);
    qdf_mem_set(&(war->mu_cap_client_addr[last_index][0]),0,
                    IEEE80211_ADDR_LEN);
    war->mu_cap_client_flag[i] = war->mu_cap_client_flag[last_index];
    war->mu_cap_client_flag[last_index] = MU_CAP_CLIENT_NORMAL;

    if (!war->mu_cap_war) {
        /* WAR feature is disabled, no further action */
        return new_timer_state;
    }

    if (ieee80211_mu_cap_dedicated_mu_kickout(war)) {
        new_timer_state = MU_TIMER_PENDING;
        war->mu_timer_cmd = MU_CAP_TIMER_CMD_KICKOUT_DEDICATED;
    }
    update_probe_response_behaviour(war);
    return new_timer_state;
}

/*
 * Function to handle MU-Capable clients'
 * join and leaves
 */
 void
ieee80211_mu_cap_client_join_leave(struct ieee80211_node *ni,
                                    const u_int8_t type)
{
    struct    ieee80211vap *vap = ni->ni_vap;
    u_int8_t  new_timer_state = MU_TIMER_STOP;
    MU_CAP_WAR *war = &vap->iv_mu_cap_war;
    qdf_spin_lock_bh(&war->iv_mu_cap_lock);

    if(type)
    {
        new_timer_state = ieee80211_mu_cap_client_join(ni, vap, war);
    } else {
        new_timer_state = ieee80211_mu_cap_client_leave(ni, vap, war);
    }

    /* Check if to active timer task*/
    if (war->mu_cap_war &&
            (new_timer_state == MU_TIMER_PENDING) &&
            (war->iv_mu_timer_state != MU_TIMER_PENDING))
    {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                "Starting Dedicated client timer command is %d \n",
                       war->mu_timer_cmd);
        war->iv_mu_timer_state = MU_TIMER_PENDING;
        OS_SET_TIMER(&war->iv_mu_cap_timer,war->mu_cap_timer_period*1000);
    }
    qdf_spin_unlock_bh(&war->iv_mu_cap_lock);
}
#if QCA_AIRTIME_FAIRNESS
void
ieee80211_atf_node_join_leave(struct ieee80211_node *ni,const u_int8_t type)
{
    struct ieee80211com *ic = ni->ni_ic;
    u_int8_t  i,j;
    u_int64_t calbitmap;
    struct group_list *group = NULL;

    if(ni->ni_vap->iv_opmode == IEEE80211_M_STA){
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s ATF managed node %s ,ignore for join_leave \n",__func__,ether_sprintf(ni->ni_macaddr));
        return;
    }

    if(ic->atf_commit)
    {
        if(OS_MEMCMP(ni->ni_vap->iv_myaddr,ni->ni_macaddr,IEEE80211_ADDR_LEN) !=0 )
        {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ATM is re-allocating airtime because %s is now %s\n",
                    ether_sprintf(ni->ni_macaddr),
                    (type?"active":"inactive") );
        }
    }

    if(type)
    { /* Add join node */
       for (i = 0, calbitmap = 1; i < ATF_ACTIVED_MAX_CLIENTS; i++)
       {
           if (ic->atfcfg_set.peer_id[i].index_vap == 0)
           {
           /*    printk("\n Join sta MAC addr:%02x:%02x:%02x:%02x:%02x:%02x \n",
                        ni->ni_macaddr[0],ni->ni_macaddr[1],ni->ni_macaddr[2],
                        ni->ni_macaddr[3],ni->ni_macaddr[4],ni->ni_macaddr[5]);*/

               OS_MEMCPY((char *)(ic->atfcfg_set.peer_id[i].sta_mac),(char *)(ni->ni_macaddr),IEEE80211_ADDR_LEN);
               ic->atfcfg_set.peer_id[i].index_vap = 0xff;
               ic->atfcfg_set.peer_id[i].sta_assoc_status = 1;
               ic->atfcfg_set.peer_cal_bitmap |= (calbitmap<<i);
               break;
           }else{
               if (IEEE80211_ADDR_EQ((char *)(ic->atfcfg_set.peer_id[i].sta_mac), (char *)(ni->ni_macaddr)))
               {

                  if (ic->atfcfg_set.peer_id[i].cfg_flag)
                  {
                     ic->atfcfg_set.peer_id[i].sta_assoc_status = 1;
                     break;
                  }else
                     return;
                }
            }
        }
        if(!ic->ic_is_mode_offload(ic))
        {
            /* Point node to the default group list */
            group = TAILQ_FIRST(&ic->ic_atfgroups);
            ni->ni_atf_group = group;
        }
    }else{
      /* Remove leave node */
       for (i = 0, j = 0; i < ATF_ACTIVED_MAX_CLIENTS; i++)
       {
           if (ic->atfcfg_set.peer_id[i].index_vap != 0)
                  j = i;
       }

       for (i = 0, calbitmap = 1; i < ATF_ACTIVED_MAX_CLIENTS; i++)
       {
           if ((ic->atfcfg_set.peer_id[i].index_vap != 0)&&
               (IEEE80211_ADDR_EQ((char *)(ic->atfcfg_set.peer_id[i].sta_mac), (char *)(ni->ni_macaddr))))
           {
               /*printk("Leave sta MAC addr:%02x:%02x:%02x:%02x:%02x:%02x \n",
                        ni->ni_macaddr[0],ni->ni_macaddr[1],ni->ni_macaddr[2],
                        ni->ni_macaddr[3],ni->ni_macaddr[4],ni->ni_macaddr[5]); */

               if(j != i)
               {
                   if (ic->atfcfg_set.peer_id[i].cfg_flag)
                   {
                        /*ic->atfcfg_set.peer_num_cfg--;*/
                        ic->atfcfg_set.peer_id[i].index_vap = 0xff;
                        ic->atfcfg_set.peer_id[i].sta_cal_value = 0;
                        ic->atfcfg_set.peer_id[i].sta_assoc_status = 0;
                   }else{
                        /* non configured peer take care of index change */
                        ic->atfcfg_set.peer_id[i].cfg_flag = ic->atfcfg_set.peer_id[j].cfg_flag;
                        ic->atfcfg_set.peer_id[i].sta_cfg_mark = ic->atfcfg_set.peer_id[j].sta_cfg_mark;
                        OS_MEMCPY((char *)(ic->atfcfg_set.peer_id[i].sta_cfg_value),(char *)(ic->atfcfg_set.peer_id[j].sta_cfg_value),sizeof(ic->atfcfg_set.peer_id[i].sta_cfg_value));
                        ic->atfcfg_set.peer_id[i].index_vap = ic->atfcfg_set.peer_id[j].index_vap;
                        ic->atfcfg_set.peer_id[i].sta_cal_value = ic->atfcfg_set.peer_id[j].sta_cal_value;
                        ic->atfcfg_set.peer_id[i].sta_assoc_status = ic->atfcfg_set.peer_id[j].sta_assoc_status;
                        OS_MEMCPY((char *)(ic->atfcfg_set.peer_id[i].sta_mac),(char *)(ic->atfcfg_set.peer_id[j].sta_mac),IEEE80211_ADDR_LEN);
                        ic->atfcfg_set.peer_id[i].index_group = ic->atfcfg_set.peer_id[j].index_group;

                        ic->atfcfg_set.peer_id[j].cfg_flag = 0;
                        ic->atfcfg_set.peer_id[j].sta_cfg_mark = 0;
                        memset(&(ic->atfcfg_set.peer_id[j].sta_cfg_value[0]),0,sizeof(ic->atfcfg_set.peer_id[i].sta_cfg_value));
                        memset(&(ic->atfcfg_set.peer_id[j].sta_mac[0]),0,IEEE80211_ADDR_LEN);
                        ic->atfcfg_set.peer_id[j].index_vap = 0;
                        ic->atfcfg_set.peer_id[j].sta_cal_value = 0;
                        ic->atfcfg_set.peer_id[j].sta_assoc_status = 0;
                        ic->atfcfg_set.peer_cal_bitmap &= ~(calbitmap<<j);
                        ic->atfcfg_set.peer_id[j].index_group = 0;
                   }
                   break;
               }else{
                   if (ic->atfcfg_set.peer_id[i].cfg_flag)
                   {
                        ic->atfcfg_set.peer_id[i].index_vap = 0xff;
                   }else{
                        memset(&(ic->atfcfg_set.peer_id[i].sta_mac[0]),0,IEEE80211_ADDR_LEN);
                        ic->atfcfg_set.peer_id[i].index_vap = 0;
                        ic->atfcfg_set.peer_id[i].index_group = 0;
                        ic->atfcfg_set.peer_cal_bitmap &= ~(calbitmap<<i);
                   }
                   ic->atfcfg_set.peer_id[i].sta_cal_value = 0;
                   ic->atfcfg_set.peer_id[i].sta_assoc_status = 0;
                   break;
               }
           }
       }
    }

    if ( i == ATF_ACTIVED_MAX_CLIENTS)
    {
        /* printk("ieee80211_atf_node_join_leave-- Either join or leave failed!! \n"); */
        return;
    }
    /* Wake up timer to update alloc table*/
    spin_lock(&ic->atf_lock);
    if((ic->atf_fmcap)&&(ic->atf_mode))
    {
      if (ic->atf_tasksched == 0)
      {
          ic->atf_tasksched = 1;
          ic->atf_vap_handler = ni->ni_vap;
          OS_SET_TIMER(&ic->atfcfg_timer, IEEE80211_ATF_WAIT*1000);
      }else{
        /*printk("\n delay some secs, come back again??\n");*/
      }
    }
    spin_unlock(&ic->atf_lock);

}
#endif

/*
 * Leave the specified IBSS/BSS network.  The node is assumed to
 * be passed in with a held reference.
 */
#if IEEE80211_DEBUG_REFCNT
bool
ieee80211_sta_leave_debug(struct ieee80211_node *ni, const char *func, int line, const char *file)
#else
bool
ieee80211_sta_leave(struct ieee80211_node *ni)
#endif
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211_node_table *nt = &ic->ic_sta;
    rwlock_state_t lock_state;
    bool node_reclaimed=false;
    OS_BEACON_DECLARE_AND_RESET_VAR(flags);

    IEEE80211_NOTE(ni->ni_vap, IEEE80211_MSG_ASSOC, ni,
                   "%s: 0x%x \n", __func__,ni);
    OS_BEACON_WRITE_LOCK(&nt->nt_nodelock, &lock_state, flags);
    if (ni->ni_table != NULL) { /* if it is in the table */
        KASSERT((ni->ni_table == nt),
            ("%s: unexpected node table: &ic_sta: 0x%p, ni_table: 0x%p,"
             " ni_vap: 0x%p, ni_ic: 0x%p, refcnt: %d\n",
             __func__, &ic->ic_sta, ni->ni_table, ni->ni_vap, ni->ni_ic,
             ieee80211_node_refcnt(ni)));

        /* remove wds entries using that node */
        ieee80211_remove_wds_addr(nt, ni->ni_macaddr,IEEE80211_NODE_F_WDS_BEHIND | IEEE80211_NODE_F_WDS_REMOTE);
        ieee80211_del_wds_node(nt, ni);
        /* Refer the node for cleanup below */
        ieee80211_ref_node(ni);
        /* reclaim the node to remove it from node table */
        node_reclaim(nt, ni);
        node_reclaimed=true;
    }
    OS_BEACON_WRITE_UNLOCK(&nt->nt_nodelock, &lock_state, flags);
    /* cleanup the node */
    if (node_reclaimed) {
        IEEE80211_DELETE_NODE_TARGET(ni, ic, ni->ni_vap, 0);
        ic->ic_node_cleanup(ni);
        /* free the node */
        ieee80211_free_node(ni);
    }

    return node_reclaimed;
}

/*
 * Join the specified IBSS/BSS network.  The node is assumed to
 * be passed in with a reference already held for use in assigning
 * to iv_bss.
 */
int
ieee80211_sta_join_bss(struct ieee80211_node *selbs)
{
    struct ieee80211vap *vap = selbs->ni_vap;
    struct ieee80211_node_table *nt = &vap->iv_ic->ic_sta;
    struct ieee80211_node *obss;
    rwlock_state_t lock_state;
    struct ieee80211com *ic;
    OS_BEACON_DECLARE_AND_RESET_VAR(flags);

    /*
     * Committed to selbs. Leave old bss node if necessary
     */
    /*
     * iv_bss is used in:
     * 1. tx path in STA/WDS mode.
     * 2. rx input_all
     * 3. vap iteration
     * Use node table lock to synchronize the acess.
     */
    OS_BEACON_WRITE_LOCK(&nt->nt_nodelock, &lock_state, flags);
    obss = vap->iv_bss;
    ic = vap->iv_ic;
    vap->iv_bss = selbs;
    selbs->ni_bss_node = selbs;
    OS_BEACON_WRITE_UNLOCK(&nt->nt_nodelock, &lock_state, flags);
    if (obss != NULL) {
#if IEEE80211_DEBUG_NODELEAK
        obss->ni_flags |= IEEE80211_NODE_EXT_STATS;
#endif
        ieee80211_node_removeall_wds(&ic->ic_sta,obss);
        ieee80211_free_node(obss);
    }
   /*
    * In some cases, due to delay in getting response from the resource manager;
    * iv_mgt_rate is being set to the default rate (1Mbps for 2G and 6 Mbps for 5G)
    * even if that rate is disabled and that value will be sent to the FW to be set
    * as MGMT and RTS rate.
    * To avoid such situation setting the mgmt rate to the lowest available basic rate
    * before sending the rate code to the FW to set MGMT and RTS rate.
    */
    if(vap->iv_disabled_legacy_rate_set) {
        ieee80211_disable_legacy_rates(vap);
    }

    /* XXX: more to do when integrating with STATION layer */
    return 0;
}

int
ieee80211_setup_node_rsn(
    struct ieee80211_node *ni,
    ieee80211_scan_entry_t scan_entry
    )
{
    struct ieee80211vap *vap = ni->ni_vap;

    /* parse WPA/RSN IE and setup RSN info */
    if (ni->ni_capinfo & IEEE80211_CAPINFO_PRIVACY) {
        struct ieee80211_rsnparms rsn;
        u_int8_t *rsn_ie, *wpa_ie;
        u_int8_t *wapi_ie = NULL;

        int status = IEEE80211_STATUS_SUCCESS;

        rsn = ni->ni_rsn;
        rsn_ie  = ieee80211_scan_entry_rsn(scan_entry);
        wpa_ie  = ieee80211_scan_entry_wpa(scan_entry);
#if ATH_SUPPORT_WAPI
        wapi_ie = ieee80211_scan_entry_wapi(scan_entry);
#endif

        if (rsn_ie != NULL)
            status = ieee80211_parse_rsn(vap, rsn_ie, &rsn);

        /* if a RSN IE was not there, or it's not valid, check the WPA IE */
        if ((rsn_ie == NULL) || (status != IEEE80211_STATUS_SUCCESS)) {
            if (wpa_ie != NULL)
                status = ieee80211_parse_wpa(vap, wpa_ie, &rsn);
        }

#if ATH_SUPPORT_WAPI
        if (wapi_ie != NULL)
            status = ieee80211_parse_wapi(vap, wapi_ie, &rsn);
#endif
        /*
         * if both RSN, WPA and WAPI IEs are absent, then we are certain that cipher is WEP.
         * However, we can't decide whether it's open or shared-key yet.
         */
        if ((rsn_ie == NULL) && (wpa_ie == NULL) && (wapi_ie == NULL))
        {
            RSN_RESET_UCAST_CIPHERS(&rsn);
            RSN_SET_UCAST_CIPHER(&rsn, IEEE80211_CIPHER_WEP);
            RSN_RESET_MCAST_CIPHERS(&rsn);
            RSN_SET_MCAST_CIPHER(&rsn, IEEE80211_CIPHER_WEP);
            RSN_RESET_MCASTMGMT_CIPHERS(&rsn);
            RSN_SET_MCASTMGMT_CIPHER(&rsn, IEEE80211_CIPHER_NONE);
        }

        if (status != IEEE80211_STATUS_SUCCESS) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_NODE,
                              "%s: invalid security settings for node %s\n",
                              __func__, ether_sprintf(ni->ni_macaddr));
            return -EINVAL;
        }

        ni->ni_rsn = rsn;   /* update rsn parameters */
    }

    return 0;
}

int8_t derive_sec_chan_orientation( enum ieee80211_phymode phymode , u_int16_t pri_chan , u_int16_t center_chan)
{

    int8_t pri_center_ch_diff, sec_level;
    u_int16_t sec_chan_20,pri_chan_40_center;
    pri_center_ch_diff = pri_chan - center_chan;
    if(pri_center_ch_diff > 0)
        sec_level = -1;
    else
        sec_level = 1;

    switch(phymode) {
        case  IEEE80211_MODE_11AC_VHT80_80:
        case  IEEE80211_MODE_11AC_VHT80:
            if(sec_level*pri_center_ch_diff < -2 )
                sec_chan_20 = center_chan - (sec_level* 2);
            else
                sec_chan_20 = center_chan - (sec_level* 6);
            if(sec_chan_20 > pri_chan )
                return 1;
            else
                return -1;
        case IEEE80211_MODE_11AC_VHT160:
            if(sec_level*pri_center_ch_diff < -6 )
                pri_chan_40_center = center_chan - (2*sec_level*6);
            else
                pri_chan_40_center = center_chan - (2*sec_level*2);
            if(pri_chan_40_center > pri_chan)
                return 1;
            else
                return -1;
        default :
            return 0;
    }
}

#define IEEE80211_MODE_SET(bm,m)  ((bm) |= (1 << (m)))
#define IEEE80211_MODE_IS_SET(bm,m)  (((bm) & (1 << (m))) != 0 )
/*
 * check if the phymode forced by user is compatible (sub phy mode) with the phy mode of the AP.
 * if  it is compatible then return the phy mode else  return AUTO phy mode.
 *  bss_chan : bss chan of the AP .
 *  des_mode: mode forced by user for the STA.
 *  bss_mode: operating mode of the AP
*/

enum ieee80211_phymode ieee80211_get_phy_mode(struct ieee80211com *ic,
                                        struct ieee80211_channel *bss_chan,
                                        enum ieee80211_phymode des_mode, enum ieee80211_phymode bss_mode)
{
    u_int32_t mode_bitmap = 0;
    /*
     *  NOTE:-
     *  1)If a device is capable of VHT80_80 it must also support VHT160.
     *  2)However, if a device is capable  VHT160 it need not necessarily
     *  support VHT80_80.
     *  3)bss_mode is actually the mode of the channel in which AP
     *  has started operating in.
     *
     *  Given the bss_mode and des_mode the matrix entries give/output a
     *  compatible mode to be used for connection.
     *
     *
     *                                       bss_modes
     *                            (the mode of AP's current
     *                                 channel of operation)
     *                          =========================================
     *                          ||  160  |  80_80 |  80  |  40  |  20  ||
     *                  ========||=======|========|======|======|======||
     *                  ||160   ||  160  |  80    |  80  |  40  |  20  ||
     *                  ||------||-------|--------|------|------|------||
     *                  ||80_80 ||  160  |  80_80 |  80  |  40  |  20  ||
     *                  ||------||-------|--------|------|------|------||
     * des_modes        ||80    ||  80   |  80    |  80  |  40  |  20  ||
     * (the             ||------||-------|--------|------|------|------||
     * capability       ||40    ||  40   |  40    |  40  |  40  |  20  ||
     * of the STA)      ||------||-------|--------|------|------|------||
     *                  ||20    ||  20   |  20    |  20  |  20  |  20  ||
     *                  =================================================
     *
     *  In general, the compatible mode is intersection(lesser) of bss_mode and
     *  des_mode.
     *  There are two exceptions:
     *  Exception1:-  bss_mode = VHT160,   des_mode= VHT80_80
     *                  compatible_mode=VHT160
     *  Exception2:-  bss_mode = VHT80_80, des_mode= VHT160
     *                  compatible_mode=VHT80
     *
     *  In Exception1, since the des_mode is VHT80_80, the STA is also capable
     *  of VHT160 as per standard therefore compatible mode is VHT160.
     *
     *  In Exception2, since the bss_mode is VHT80_80 the AP should
     *  be able to support VHT160 as per standard but since the AP has already started in
     *  a channel with mode VHT80_80, STA must follow the channel with mode VHT80_80.
     *  And since STA's  desired mode is VHT160 if STA comes up in a channel
     *  with mode VHT160 then the AP's and STA's channels will not be compatible.
     *  Therefore, the common mode VHT80 is the compatible mode in this case.
     */


    /*
     * for the given APs phymode construct a bitmap of all compatible sub phy modes.
     */
    switch(bss_mode) {
        case IEEE80211_MODE_11AC_VHT80_80:
            IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11AC_VHT80_80);
            /* NOTE:- VHT160 is not set. See Exception2.*/
            IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11AC_VHT80);
            if (derive_sec_chan_orientation(bss_mode ,ieee80211_mhz2ieee(ic,bss_chan->ic_freq,IEEE80211_CHAN_5GHZ) , bss_chan->ic_vhtop_ch_freq_seg1) > 0) {
                IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11AC_VHT40PLUS);
                IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NA_HT40PLUS);
            } else {
                IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11AC_VHT40MINUS);
                IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NA_HT40MINUS);
            }
            IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11AC_VHT40);
            IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11AC_VHT20);
            IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NA_HT40);
            IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NA_HT20);
            IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11A);
            break;
        case IEEE80211_MODE_11AC_VHT160:
            IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11AC_VHT160);
            IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11AC_VHT80);
            if (derive_sec_chan_orientation(bss_mode ,ieee80211_mhz2ieee(ic,bss_chan->ic_freq,IEEE80211_CHAN_5GHZ) , bss_chan->ic_vhtop_ch_freq_seg2) > 0) {
                IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11AC_VHT40PLUS);
                IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NA_HT40PLUS);
            } else {
                IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11AC_VHT40MINUS);
                IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NA_HT40MINUS);
            }
            IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11AC_VHT40);
            IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11AC_VHT20);
            IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NA_HT40);
            IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NA_HT20);
            IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11A);
            break;
        case IEEE80211_MODE_11AC_VHT80:
            IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11AC_VHT80);
            if (derive_sec_chan_orientation(bss_mode ,ieee80211_mhz2ieee(ic,bss_chan->ic_freq,IEEE80211_CHAN_5GHZ) , bss_chan->ic_vhtop_ch_freq_seg1) > 0) {
              IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11AC_VHT40PLUS);
              IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NA_HT40PLUS);
            } else {
              IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11AC_VHT40MINUS);
              IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NA_HT40MINUS);
            }
            IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11AC_VHT40);
            IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11AC_VHT20);
            IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NA_HT40);
            IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NA_HT20);
            IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11A);
            break;
      case IEEE80211_MODE_11AC_VHT40PLUS:
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11AC_VHT40PLUS);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NA_HT40PLUS);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11AC_VHT40);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11AC_VHT20);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NA_HT40);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NA_HT20);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11A);
          break;
      case IEEE80211_MODE_11AC_VHT40MINUS:
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11AC_VHT40MINUS);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NA_HT40MINUS);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11AC_VHT40);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11AC_VHT20);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NA_HT40);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NA_HT20);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11A);
          break;
      case IEEE80211_MODE_11AC_VHT20:
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11AC_VHT20);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NA_HT20);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11A);
          break;
      case IEEE80211_MODE_11NA_HT40PLUS:
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NA_HT40PLUS);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NA_HT40);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NA_HT20);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11A);
          break;
      case IEEE80211_MODE_11NA_HT40MINUS:
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NA_HT40MINUS);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NA_HT20);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11A);
          break;
      case IEEE80211_MODE_11NA_HT20:
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NA_HT20);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11A);
          break;
      case IEEE80211_MODE_11NG_HT40PLUS:
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NG_HT40PLUS);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NG_HT40);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NG_HT20);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11G);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11B);
          break;
      case IEEE80211_MODE_11NG_HT40MINUS:
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NG_HT40MINUS);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NG_HT40);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NG_HT20);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11G);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11B);
          break;
      case IEEE80211_MODE_11NG_HT20:
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11NG_HT20);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11G);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11B);
          break;
      case IEEE80211_MODE_11A:
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11A);
          break;
      case IEEE80211_MODE_11G:
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11G);
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11B);
          break;
      case IEEE80211_MODE_11B:
          IEEE80211_MODE_SET(mode_bitmap, IEEE80211_MODE_11B);
          break;
    default:
        break;

    }
    /*
     * check if the user selected mode for STA is part of the bitmap of compatible phy modes.
     */
    if (IEEE80211_MODE_IS_SET(mode_bitmap, des_mode)) {
      /*
       * if user requested HT40 then return HT40PLUS  if HT40PLUS is comaptible with AP
       * else return HT40MINUS.
       */
        switch (des_mode) {
            case IEEE80211_MODE_11NA_HT40:
                if (IEEE80211_MODE_IS_SET(mode_bitmap,IEEE80211_MODE_11NA_HT40PLUS)) {
                    des_mode = IEEE80211_MODE_11NA_HT40PLUS;
                } else {
                    des_mode = IEEE80211_MODE_11NA_HT40MINUS;
                }
                break;
            case IEEE80211_MODE_11AC_VHT40:
                if (IEEE80211_MODE_IS_SET(mode_bitmap,IEEE80211_MODE_11AC_VHT40PLUS)) {
                    des_mode = IEEE80211_MODE_11AC_VHT40PLUS;
                } else {
                    des_mode = IEEE80211_MODE_11AC_VHT40MINUS;
                }
                break;
            case IEEE80211_MODE_11NG_HT40:
                if (IEEE80211_MODE_IS_SET(mode_bitmap,IEEE80211_MODE_11NG_HT40PLUS)) {
                    des_mode = IEEE80211_MODE_11NG_HT40PLUS;
                } else {
                    des_mode = IEEE80211_MODE_11NG_HT40MINUS;
                }
               break;
            default:
               break;
        }
    } else {
        /* Handle Exceptions:
         * Exception1 : BSS MODE = VHT160 and Desired mode = VHT80_80
         * Exception1 is handled automatically since bitmap is not set for des_mode
         * and the function returns AUTO. If AUTO is returned then STA connects
         * in Root AP's mode.
         *
         * Exception2 : BSS MODE = VHT80_80 and Desired mode = VHT160
         */
        if(bss_mode ==  IEEE80211_MODE_11AC_VHT80_80 && des_mode ==  IEEE80211_MODE_11AC_VHT160) {
            /* TODO xxxxx:- we also need to check elsewhere, if des_mode is really
             * supported by the hardware.
             */
            des_mode = IEEE80211_MODE_11AC_VHT80;
        } else {
            des_mode = IEEE80211_MODE_AUTO;
        }
    }
    return des_mode;
}

/*
 * Setup a node based on the scan entry
 */
int
ieee80211_setup_node(
    struct ieee80211_node *ni,
    ieee80211_scan_entry_t scan_entry
    )
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    u_int8_t *rates, *xrates;
    struct ieee80211_country_ie* countryie;
    u_int8_t *htcap = NULL;
    u_int8_t *htinfo = NULL;
    u_int8_t *vhtcap = NULL;
    u_int8_t *vhtop = NULL;
    u_int8_t *wme = NULL;
    u_int8_t *athextcap = NULL;
    u_int8_t *ssid;
    int i;
    int ht_rates_allowed;
    int error = 0;
    enum ieee80211_phymode phymode = IEEE80211_MODE_AUTO;


    ASSERT((vap->iv_opmode == IEEE80211_M_STA) ||
           (vap->iv_opmode == IEEE80211_M_IBSS));

    ni->ni_beacon_rstamp = OS_GET_TIMESTAMP();
    /*
     * If NIC does not support the channels in this node, NULL is returned.
     */
    ni->ni_chan = ieee80211_scan_entry_channel(scan_entry);

    /* Assert this in debug driver, but fail gracefully in release driver. */
    ASSERT((ni->ni_chan != NULL) && (ni->ni_chan != IEEE80211_CHAN_ANYC));
    if ((ni->ni_chan == NULL) || (ni->ni_chan == IEEE80211_CHAN_ANYC))
        return -EIO;

    if ((ni->ni_chan == NULL) || (ni->ni_chan == IEEE80211_CHAN_ANYC))
        return -EIO;

    phymode = ieee80211_chan2mode(ni->ni_chan);
    if (vap->iv_des_mode != IEEE80211_MODE_AUTO) {
        /* if desired mode is not auto then find if the requested mode
           is supported by the AP */
        phymode = ieee80211_get_phy_mode(ic,ni->ni_chan,vap->iv_des_mode,phymode);
        if (phymode != IEEE80211_MODE_AUTO) {
             ieee80211_note(vap, IEEE80211_MSG_NODE, "%s forcing sta to"
                 " associate in %d mode\n", __func__, phymode);
            ni->ni_chan = ieee80211_find_dot11_channel(ic, ni->ni_chan->ic_ieee, ni->ni_chan->ic_vhtop_ch_freq_seg2, phymode | ic->ic_chanbwflag);
            if ((ni->ni_chan == NULL) || (ni->ni_chan == IEEE80211_CHAN_ANYC)) {
                ieee80211_note(vap, IEEE80211_MSG_NODE,
                      "%s, an not find a channel with the desired mode \n", __func__);
             return -EIO;
            }
        }

    }
    if (phymode == IEEE80211_MODE_11AC_VHT160 || phymode == IEEE80211_MODE_11AC_VHT80_80) {
        struct ieee80211_channel_list chan_info;
        ieee80211_get_extchaninfo( ic, ni->ni_chan, &chan_info);

        for (i = 0; i < chan_info.cl_nchans; i++) {
            if(chan_info.cl_channels[i] && IEEE80211_IS_CHAN_RADAR(chan_info.cl_channels[i])) {
                phymode = IEEE80211_MODE_11AC_VHT80;
                ni->ni_chan = ieee80211_find_dot11_channel(ic, ni->ni_chan->ic_ieee, ni->ni_chan->ic_vhtop_ch_freq_seg2, phymode | ic->ic_chanbwflag);
                if ((ni->ni_chan == NULL) || (ni->ni_chan == IEEE80211_CHAN_ANYC)) {
                    ieee80211_note(vap, IEEE80211_MSG_NODE,
                        "%s, can not find a channel with the desired mode \n", __func__);
                    return -EIO;
                }
            }
        }
    }

    IEEE80211_ADDR_COPY(ni->ni_bssid, ieee80211_scan_entry_bssid(scan_entry));
    ssid = ieee80211_scan_entry_ssid(scan_entry, &ni->ni_esslen);
    if (ssid != NULL && (ni->ni_esslen < (IEEE80211_NWID_LEN+1)))
        OS_MEMCPY(ni->ni_essid, ssid, ni->ni_esslen);

    ni->ni_capinfo = ieee80211_scan_entry_capinfo(scan_entry);
    ni->ni_erp = ieee80211_scan_entry_erpinfo(scan_entry);

    countryie = (struct ieee80211_country_ie*)ieee80211_scan_entry_country(scan_entry);
    if(countryie) {
        ni->ni_cc[0] = countryie->cc[0];
        ni->ni_cc[1] = countryie->cc[1];
        ni->ni_cc[2] = countryie->cc[2];
    } else {
        ni->ni_cc[0] = 0;
        ni->ni_cc[1] = 0;
        ni->ni_cc[2] = 0;
    }

    ni->ni_intval = ieee80211_scan_entry_beacon_interval(scan_entry);
    ni->ni_lintval = ic->ic_lintval;
    LIMIT_BEACON_PERIOD(ni->ni_intval);

    /*
     * Verify that ATIM window is smaller than beacon interval.
     * This kind of misconfiguration can put hardware into unpredictable state
     */
    ASSERT(ni->ni_intval > vap->iv_atim_window);

    /* Clear node flags */
    //ni->ni_ext_caps = ni->ni_flags = ni->ni_ath_flags = ni->ni_htcap = 0;
    ni->ni_ext_caps = 0;
    ni->ni_flags = 0;
    ni->ni_htcap = 0;
    ni->ni_ath_flags = 0;
    ni->ni_vhtcap = 0;

    /* update WMM capability */
    if (((wme = ieee80211_scan_entry_wmeinfo_ie(scan_entry))  != NULL) ||
        ((wme = ieee80211_scan_entry_wmeparam_ie(scan_entry)) != NULL)) {
        u_int8_t    qosinfo;

        ni->ni_ext_caps |= IEEE80211_NODE_C_QOS;
        if (ieee80211_parse_wmeinfo(vap, wme, &qosinfo) >= 0) {
            if (qosinfo & WME_CAPINFO_UAPSD_EN) {
                ni->ni_ext_caps |= IEEE80211_NODE_C_UAPSD;
            }
        }
    }

    if ((athextcap = (u_int8_t *) ieee80211_scan_entry_athextcaps(scan_entry)) != NULL) {
        ieee80211_process_athextcap_ie(ni, athextcap);
    }

    /* parse WPA/RSN IE and setup RSN info */
    error = ieee80211_setup_node_rsn(ni, scan_entry);

    /*
     * With WEP and TKIP encryption algorithms:
     * Diable aggregation if IEEE80211_NODE_WEPTKIPAGGR is not set.
     * Disable 11n if IEEE80211_FEXT_WEP_TKIP_HTRATE is not set.
     */
    ht_rates_allowed = 1;
    if((IEEE80211_VAP_IS_PRIVACY_ENABLED(vap) &&
       (RSN_CIPHER_IS_WEP(&vap->iv_rsn) ||
        (RSN_CIPHER_IS_TKIP(&vap->iv_rsn) && !RSN_CIPHER_IS_CCMP128(&vap->iv_rsn) &&
         !RSN_CIPHER_IS_CCMP256(&vap->iv_rsn) && !RSN_CIPHER_IS_GCMP128(&vap->iv_rsn) &&
         !RSN_CIPHER_IS_GCMP256(&vap->iv_rsn))))
    || ((ni->ni_capinfo & IEEE80211_CAPINFO_PRIVACY) &&
        (RSN_CIPHER_IS_WEP(&ni->ni_rsn) ||
        (RSN_CIPHER_IS_TKIP(&ni->ni_rsn) && !RSN_CIPHER_IS_CCMP128(&ni->ni_rsn) &&
         !RSN_CIPHER_IS_CCMP256(&vap->iv_rsn) && !RSN_CIPHER_IS_GCMP128(&vap->iv_rsn) &&
         !RSN_CIPHER_IS_GCMP256(&vap->iv_rsn))))){
        ieee80211node_set_flag(ni, IEEE80211_NODE_WEPTKIP);
        if (ieee80211_ic_wep_tkip_htrate_is_set(ic)) {
            if (!ieee80211_has_weptkipaggr(ni))
                ieee80211node_set_flag(ni, IEEE80211_NODE_NOAMPDU);
        } else {
            ht_rates_allowed = 0;
        }
    }

    if ((vap->iv_opmode == IEEE80211_M_IBSS) &&
        !ieee80211_ic_ht20Adhoc_is_set(ic) &&
        !ieee80211_ic_ht40Adhoc_is_set(ic)) {
        ht_rates_allowed = 0;
    }

    if (ht_rates_allowed) {
        u_int8_t *bwnss_map = NULL;

        htcap  = ieee80211_scan_entry_htcap(scan_entry);
        htinfo = ieee80211_scan_entry_htinfo(scan_entry);
        if (htcap && (IEEE80211_IS_CHAN_11N(ni->ni_chan) || IEEE80211_IS_CHAN_VHT(ni->ni_chan) )) {
            ieee80211_parse_htcap(ni, htcap);
        }
        if (htinfo && (IEEE80211_IS_CHAN_11N(ni->ni_chan) || IEEE80211_IS_CHAN_VHT(ni->ni_chan) )) {
            ieee80211_parse_htinfo(ni, htinfo);
        }

        if ((vap->iv_opmode == IEEE80211_M_IBSS) && !ieee80211_ic_ht40Adhoc_is_set(ic)) {
            ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
        }

        if ((vap->iv_opmode == IEEE80211_M_IBSS) && !ieee80211_ic_htAdhocAggr_is_set(ic)) {
            ieee80211node_set_flag(ni, IEEE80211_NODE_NOAMPDU);
        }

        bwnss_map = ieee80211_scan_entry_bwnss_map(scan_entry);
        if (bwnss_map) {
            ni->ni_bwnss_map = IEEE80211_BW_NSS_FWCONF_160(*(u_int32_t *)bwnss_map);
        } else {
            ni->ni_bwnss_map = 0;
        }

        vhtcap  = ieee80211_scan_entry_vhtcap(scan_entry);
        vhtop  = ieee80211_scan_entry_vhtop(scan_entry);

        if (vhtcap && IEEE80211_IS_CHAN_VHT(ni->ni_chan) ) {
            ieee80211_parse_vhtcap(ni, vhtcap);
        }

        if (htinfo && vhtop && IEEE80211_IS_CHAN_VHT(ni->ni_chan) ) {
            ieee80211_parse_vhtop(ni, vhtop, htinfo);
        }

    }

    /* NB: must be after ni_chan is setup */
    rates = ieee80211_scan_entry_rates(scan_entry);
    xrates = ieee80211_scan_entry_xrates(scan_entry);
    if (rates) {
        ieee80211_setup_rates(ni, rates, xrates, IEEE80211_F_DOXSECT);
    }
    if (htcap && (IEEE80211_IS_CHAN_11N(ni->ni_chan) || IEEE80211_IS_CHAN_VHT(ni->ni_chan) )) {
        ieee80211_setup_ht_rates(ni, htcap, IEEE80211_F_DOXSECT);
    }
    if (htinfo && (IEEE80211_IS_CHAN_11N(ni->ni_chan) || IEEE80211_IS_CHAN_VHT(ni->ni_chan) )) {
        ieee80211_setup_basic_ht_rates(ni, htinfo);
    }
    if (vhtcap && IEEE80211_IS_CHAN_VHT(ni->ni_chan) ) {
        ieee80211_setup_vht_rates(ni, vhtcap, IEEE80211_F_DOXSECT);
    }

    /*
     * ieee80211_parse_vhtop would hav set the channel width based on APs operating mode/channel.
     * if vap is forced to operate in a different lower mode than what AP is opearing,
     *  then set the channel width based on  the forced channel/phy mode .
     */
    if (phymode != IEEE80211_MODE_AUTO) {
        switch(phymode) {
        case IEEE80211_MODE_11A          :
        case IEEE80211_MODE_11B          :
        case IEEE80211_MODE_11G          :
        case IEEE80211_MODE_11NA_HT20    :
        case IEEE80211_MODE_11NG_HT20    :
        case IEEE80211_MODE_11AC_VHT20   :
            ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
            break;
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40PLUS :
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11AC_VHT40PLUS:
        case IEEE80211_MODE_11AC_VHT40MINUS:
            ni->ni_chwidth = IEEE80211_CWM_WIDTH40;
            break;
        case IEEE80211_MODE_11AC_VHT80:
            ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
            break;
        case IEEE80211_MODE_11AC_VHT160:
        case IEEE80211_MODE_11AC_VHT80_80:
            ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
            break;
        default :
            break;

        }
    }

    /* Find min basic supported rate */
    ni->ni_minbasicrate = 0;
    for (i=0; i < ni->ni_rates.rs_nrates; i++) {
        if ((ni->ni_minbasicrate == 0) ||
            ((ni->ni_minbasicrate & IEEE80211_RATE_VAL) > (ni->ni_rates.rs_rates[i] & IEEE80211_RATE_VAL))) {
            ni->ni_minbasicrate = ni->ni_rates.rs_rates[i];
        }
    }

    /* Error at parsing WPA/RSN IE */
    if (error != 0)
        return error;

    return 0;
}

#if IEEE80211_DEBUG_REFCNT
struct ieee80211_node *
ieee80211_ref_bss_node_debug(struct ieee80211vap *vap,
                         const char *func, int line, const char *file)
#else  /* !IEEE80211_DEBUG_REFCNT */
struct ieee80211_node *
ieee80211_ref_bss_node(struct ieee80211vap *vap)
#endif  /* IEEE80211_DEBUG_REFCNT */
{
    struct ieee80211_node_table *nt = &vap->iv_ic->ic_sta;
    struct ieee80211_node *ni = NULL;
    rwlock_state_t lock_state;

    if (vap->iv_bss) {
        OS_BEACON_DECLARE_AND_RESET_VAR(flags);

        OS_BEACON_READ_LOCK(&nt->nt_nodelock, &lock_state, flags);
#if IEEE80211_DEBUG_REFCNT
        ni = ieee80211_ref_node_debug(vap->iv_bss, func, line, file);
#else
        ni = ieee80211_ref_node(vap->iv_bss);
#endif
        OS_BEACON_READ_UNLOCK(&nt->nt_nodelock, &lock_state, flags);

    }
    return ni;
}

/*
 * Reset bss state on transition to the INIT state.
 * Clear any stations from the table (they have been
 * deauth'd) and reset the bss node (clears key, rate,
 * etc. state).
 */
int
ieee80211_reset_bss(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_node *ni, *obss;
    struct ieee80211_node_table *nt = &ic->ic_sta;
    rwlock_state_t lock_state;
    OS_BEACON_DECLARE_AND_RESET_VAR(flags);

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s\n", __func__);

    /* mgmt pkts needs to be flushed */
    /* we should be calling ol layer through ic pointers and  */
    /* here layer violation has happened. This will be fixed in next  */
    /* immediate checkin as there is a time constraint  */
        /* going ahead with checkin */
    if(ic->ic_is_mode_offload(ic) && vap->iv_bss) {
        if(ic->ic_if_mgmt_drain)
            ic->ic_if_mgmt_drain (vap->iv_bss, 0);
    }
    ieee80211_node_table_reset(&ic->ic_sta, vap);

    ni = ieee80211_alloc_node(nt, vap, vap->iv_myaddr);
    if (ni == NULL) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Failed to create bss node\n");
        return -ENOMEM;
    }

    /*
     * iv_bss is used in:
     * 1. tx path in STA/WDS mode.
     * 2. rx input_all
     * 3. vap iteration
     * Use node table lock to synchronize the acess.
     */
    OS_BEACON_WRITE_LOCK(&nt->nt_nodelock, &lock_state, flags);
    obss = vap->iv_bss;
    vap->iv_bss = ni; /* alloc node gives the needed extra reference */

    /*
     * XXX: remove the default node from node table, because
     * it's not associated to any one. This will fix reference count
     * leak when freeing the default node.
     */
    node_reclaim(nt, ni);
    OS_BEACON_WRITE_UNLOCK(&nt->nt_nodelock, &lock_state, flags);

    if (obss != NULL) {
        /* Do we really need obss info?? */
        ieee80211_copy_bss(ni, obss);
#if IEEE80211_DEBUG_NODELEAK
        obss->ni_flags |= IEEE80211_NODE_EXT_STATS;
#endif
        ni->ni_intval = obss->ni_intval;
        /* Cleanup the old BSS node */
        ic->ic_node_cleanup(obss);
        IEEE80211_DELETE_NODE_TARGET(obss, ic, vap, 1);
        ieee80211_free_node(obss);
    }
    return 0;
}

/*
 * Node table support.
 */
static void
ieee80211_node_table_init(struct ieee80211com *ic,
                          struct ieee80211_node_table *nt,
                          const char *name
			  )
{
    int hash;

    nt->nt_ic = ic;
    OS_RWLOCK_INIT(&nt->nt_nodelock);
    OS_RWLOCK_INIT(&nt->nt_wds_nodelock);
    TAILQ_INIT(&nt->nt_node);
    for (hash = 0; hash < IEEE80211_NODE_HASHSIZE; hash++)
        LIST_INIT(&nt->nt_hash[hash]);
#if UMAC_SUPPORT_PROXY_ARP
    TAILQ_INIT(&nt->nt_ipv6_node);
    for (hash = 0; hash < IEEE80211_IPV4_HASHSIZE; hash++)
        LIST_INIT(&nt->nt_ipv4_hash[hash]);
    for (hash = 0; hash < IEEE80211_IPV6_HASHSIZE; hash++)
        LIST_INIT(&nt->nt_ipv6_hash[hash]);
#endif
    nt->nt_scangen = 1;
    nt->nt_name = name;
    ieee80211_wds_attach(nt);
}

static void
ieee80211_node_table_reset(struct ieee80211_node_table *nt, struct ieee80211vap *match)
{
    struct ieee80211_node *ni, *next;
    rwlock_state_t lock_state;
    OS_BEACON_DECLARE_AND_RESET_VAR(flags);

    OS_BEACON_WRITE_LOCK(&nt->nt_nodelock, &lock_state, flags);
	TAILQ_FOREACH_SAFE(ni, &nt->nt_node, ni_list, next) {
        if ((match != NULL) && (ni->ni_vap != match))
            continue;

        if (ni->ni_associd != 0) {
            struct ieee80211vap *vap = ni->ni_vap;

            if (vap->iv_aid_bitmap != NULL)
                IEEE80211_AID_CLR(vap, ni->ni_associd);
        }
        /* Remove WDS entries on node table reset.*/
#if UMAC_SUPPORT_WDS
        ieee80211_remove_wds_addr(nt, ni->ni_macaddr,IEEE80211_NODE_F_WDS_BEHIND | IEEE80211_NODE_F_WDS_REMOTE);
        ieee80211_del_wds_node(nt, ni);
#endif /* UMAC_SUPPORT_WDS */
        node_reclaim(nt, ni);
    }
    OS_BEACON_WRITE_UNLOCK(&nt->nt_nodelock, &lock_state, flags);
}

void
ieee80211_node_attach(struct ieee80211com *ic)
{
    ieee80211_node_table_init(ic, &ic->ic_sta, "station");
#if IEEE80211_DEBUG_NODELEAK
    TAILQ_INIT(&ic->ic_nodes);
    OS_RWLOCK_INIT(&(ic)->ic_nodelock);
#endif
    ic->ic_node_alloc = node_alloc;
    ic->ic_node_free = node_free;
    ic->ic_node_cleanup = node_cleanup;
    ic->ic_node_getrssi = node_getrssi;
    ic->ic_node_authorize = NULL;
}

void
ieee80211_node_detach(struct ieee80211com *ic)
{
    struct ieee80211_node_table *nt = &ic->ic_sta;
    ieee80211_node_table_reset(nt, NULL);
    OS_RWLOCK_DESTROY(&nt->nt_nodelock);
    ieee80211_wds_detach(nt);
}

void
ieee80211_node_vattach(struct ieee80211vap *vap)
{
    vap->iv_inact_init = IEEE80211_INACT_INIT;
    vap->iv_inact_auth = IEEE80211_INACT_AUTH;
    vap->iv_inact_run = IEEE80211_INACT_RUN;
    vap->iv_inact_probe = IEEE80211_INACT_PROBE;
    vap->iv_session = IEEE80211_SESSION_TIME;
}

void
ieee80211_node_latevdetach(struct ieee80211vap *vap)
{
    if (!ieee80211_vap_deleted_is_set(vap)) {
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: vap is not deleted by user, vap: 0x%p, vap->iv_bss: 0x%p\n",
            __func__, vap, vap->iv_bss);
    }
    if (vap->iv_node_count != 0) {
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: vap still has nodes, vap->iv_node_count: %d, refcnt: 0x%x\n", __func__,
            vap->iv_node_count, (vap->iv_bss ? ieee80211_node_refcnt(vap->iv_bss) : 0xffffffff));
    }

    /*
     * free the aid bitmap.
     */
    if (vap->iv_aid_bitmap) {
        OS_FREE(vap->iv_aid_bitmap);
        vap->iv_max_aid = 0;
    }
}

void
ieee80211_node_vdetach(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;

    ieee80211_node_table_reset(&ic->ic_sta, vap);
    if (vap->iv_bss != NULL) {
        IEEE80211_DELETE_NODE_TARGET(vap->iv_bss, ic, vap, 0);
        ieee80211_free_node(vap->iv_bss);
    }
}

int
ieee80211_node_latevattach(struct ieee80211vap *vap)
{
    int error = 0;

    /*
     * Allocate these only if needed.  Beware that we
     * know adhoc mode doesn't support ATIM yet...
     */
    if (vap->iv_opmode == IEEE80211_M_HOSTAP || \
        vap->iv_opmode == IEEE80211_M_BTAMP  || \
        vap->iv_opmode == IEEE80211_M_IBSS) {
        unsigned long bm_size;

        KASSERT(vap->iv_max_aid != 0, ("0 max aid"));

        bm_size = howmany(vap->iv_max_aid, 32) * sizeof(u_int32_t);
        vap->iv_aid_bitmap = (u_int32_t *)OS_MALLOC(vap->iv_ic->ic_osdev,
                                                    bm_size,
                                                    GFP_KERNEL);
        if (vap->iv_aid_bitmap == NULL) {
            /* XXX no way to recover */
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: no memory for AID bitmap!\n", __func__);
            vap->iv_max_aid = 0;
            return -ENOMEM;
        }
        OS_MEMZERO(vap->iv_aid_bitmap, bm_size);
    }

    error = ieee80211_reset_bss(vap);
    return error;
}

/*
 * Add the specified station to the station table.
 * calls alloc_node and hence return the node with 2 references.
 * one for adding it to the table and the
 * the other for the caller to use.
 */
struct ieee80211_node *
ieee80211_dup_bss(struct ieee80211vap *vap, const u_int8_t *macaddr)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_node *ni;

    ni = ieee80211_alloc_node(&ic->ic_sta, vap, macaddr);
    if (ni != NULL) {
        /*
         * Inherit from iv_bss.
         */
        ni->ni_authmode = vap->iv_bss->ni_authmode;
        ni->ni_txpower = vap->iv_bss->ni_txpower;
        IEEE80211_ADDR_COPY(ni->ni_bssid, vap->iv_bss->ni_bssid);
        ni->ni_rsn = vap->iv_bss->ni_rsn;
        ni->ni_bss_node = ieee80211_ref_bss_node(vap);
#ifndef MAGPIE_HIF_GMAC
        IEEE80211_ADD_NODE_TARGET(ni, vap, 0);
#endif
    }
    return ni;
}

#if IEEE80211_DEBUG_NODELEAK
void
ieee80211_dump_alloc_nodes(struct ieee80211com *ic)
{
    struct ieee80211_node *ni;
    u_int8_t  ssid[IEEE80211_NWID_LEN+4];
    rwlock_state_t lock_state;
    ieee80211_node_saveq_info qinfo;

    ieee80211com_note(ic, IEEE80211_MSG_NODE, "dumping all allocated nodes ... \n");
    OS_RWLOCK_READ_LOCK(&ic->ic_nodelock,&lock_state);
    TAILQ_FOREACH(ni, &ic->ic_nodes, ni_alloc_list) {
        ieee80211com_note(ic, IEEE80211_MSG_NODE, "node 0x%x mac %s  tmpnode: %d"
               " nodetable : %d flags 0x%x refcount: %d ", ni,
               ether_sprintf(ni->ni_macaddr),
               (ni->ni_flags & IEEE80211_NODE_TEMP) ? 1 : 0,
               (ni->ni_table) ? 1 : 0,ni->ni_flags, ieee80211_node_refcnt(ni));
        if (ni->ni_esslen) {
            OS_MEMCPY(ssid, ni->ni_essid, ni->ni_esslen);
            ssid[ni->ni_esslen] = 0;
        }
        ieee80211_node_saveq_get_info(ni, &qinfo);
        ieee80211com_note(ic, IEEE80211_MSG_NODE,
               "bssid %s cap 0x%x dqlen  %d mgtqlen %d  %s %s \n",
               ether_sprintf(ni->ni_bssid), ni->ni_capinfo,
                          qinfo.data_count, qinfo.mgt_count,
               ni->ni_esslen ? "ssid ":"",
               ni->ni_esslen ? (char *)ssid : "" );
        if (ic->ic_print_nodeq_info)
            ic->ic_print_nodeq_info(ni);
    }
    OS_RWLOCK_READ_UNLOCK(&ic->ic_nodelock,&lock_state);
}

void
wlan_dump_alloc_nodes(wlan_dev_t devhandle)
{
    struct ieee80211com *ic = (struct ieee80211com *) devhandle;
    ieee80211_dump_alloc_nodes(ic);
}
#endif

/* External UMAC APIs */

u_int16_t wlan_node_getcapinfo(wlan_node_t node)
{
    return node->ni_capinfo;
}

u_int32_t wlan_node_get_extended_capabilities(wlan_node_t node)
{
    return node->ni_ext_capabilities;
}

int  wlan_node_getwpaie(wlan_if_t vap, u_int8_t *macaddr, u_int8_t *ie, u_int16_t *len)
{
    struct ieee80211_node *ni;
    ni = ieee80211_vap_find_node(vap, macaddr);
    if (ni == NULL)
        return EINVAL;
    if (ni->ni_wpa_ie != NULL) {
        int ielen = ni->ni_wpa_ie[1] + 2;
        if (ielen > *len) {
            ieee80211_free_node(ni);
            return EINVAL;
        }
        OS_MEMCPY(ie, ni->ni_wpa_ie, ielen);
        *len = ielen;
    } else {
        *len = 0;
    }
    ieee80211_free_node(ni);

    return 0;

}

int  wlan_node_getwpsie(wlan_if_t vap, u_int8_t *macaddr, u_int8_t *ie, u_int16_t *len)
{
    struct ieee80211_node *ni;
    ni = ieee80211_vap_find_node(vap, macaddr);
    if (ni == NULL)
        return EINVAL;
    if (ni->ni_wps_ie != NULL) {
        int ielen = ni->ni_wps_ie[1] + 2;
        if (ielen > *len) {
            ieee80211_free_node(ni);
            return EINVAL;
        }
        OS_MEMCPY(ie, ni->ni_wps_ie, ielen);
        *len = ielen;
    } else {
        *len = 0;
    }
    ieee80211_free_node(ni);

    return 0;

}

int  wlan_node_getathie(wlan_if_t vap, u_int8_t *macaddr, u_int8_t *ie, u_int16_t *len)
{
    struct ieee80211_node *ni;
    ni = ieee80211_vap_find_node(vap, macaddr);
    if (ni == NULL)
        return EINVAL;
    if (ni->ni_ath_ie != NULL) {
        int ielen = ni->ni_ath_ie[1] + 2;
        if (ielen > *len) {
            ieee80211_free_node(ni);
            return EINVAL;
        }
        OS_MEMCPY(ie, ni->ni_ath_ie, ielen);
        *len = ielen;
    } else {
        *len = 0;
    }
    ieee80211_free_node(ni);

    return 0;

}

int  wlan_node_getwmeie(wlan_if_t vap, u_int8_t *macaddr, u_int8_t *ie, u_int16_t *len)
{
    struct ieee80211_node *ni;
    ni = ieee80211_vap_find_node(vap, macaddr);
    if (ni == NULL)
        return EINVAL;
    if (ni->ni_wme_ie != NULL) {
        int ielen = ni->ni_wme_ie[1] + 2;
        if (ielen > *len) {
            ieee80211_free_node(ni);
            return EINVAL;
        }
        OS_MEMCPY(ie, ni->ni_wme_ie, ielen);
        *len = ielen;
    } else {
        *len = 0;
    }
    ieee80211_free_node(ni);

    return 0;

}


static void ieee80211_node_iter(void *arg, struct ieee80211_node *ni)
{
    struct ieee80211_iter_arg *itr_arg = (struct ieee80211_iter_arg *)arg;
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;

    /*
     * ignore if the node does not belong to the requesting vap.
     */
    if (vap != itr_arg->vap)  {
         return;
    }

    /*
     * ignore BSS node for AP/IBSS mode
     */
    if ((ni == ni->ni_bss_node) &&
        ((vap->iv_opmode == IEEE80211_M_HOSTAP) || (vap->iv_opmode == IEEE80211_M_IBSS) ||
         (vap->iv_opmode == IEEE80211_M_BTAMP))) {
        return;
    }

    if (!(itr_arg->flag & IEEE80211_NODE_ITER_F_UNASSOC_STA)) {
        /*
         * ignore un associated stations for AP mode
         */
        if (vap->iv_opmode == IEEE80211_M_HOSTAP && (ni->ni_associd == 0)) {
            return;
        }

        /*
         * ignore un associated stations for IBSS mode
         */
        if (vap->iv_opmode == IEEE80211_M_IBSS &&
            (ni->ni_assoc_state != IEEE80211_NODE_ADHOC_STATE_AUTH_ASSOC)) {
            return;
        }
    }

    if (!(itr_arg->flag & IEEE80211_NODE_ITER_F_ASSOC_STA)) {
        /*
         * ignore associated stations for AP mode
         */
        if (vap->iv_opmode == IEEE80211_M_HOSTAP && (ni->ni_associd != 0)) {
            return;
        }

        /*
         * ignore associated stations for IBSS mode
         */
        if (vap->iv_opmode == IEEE80211_M_IBSS &&
            (ni->ni_assoc_state == IEEE80211_NODE_ADHOC_STATE_AUTH_ASSOC)) {
            return;
        }
    }

    if ((ic != NULL) && (itr_arg->count < ic->ic_num_clients)) {
        /* increment the ref count so that the node is not freed */
        itr_arg->nodes[itr_arg->count] = ieee80211_ref_node(ni);
    }

    ++itr_arg->count;
}


static int32_t
ieee80211_iterate_node_list(wlan_if_t vap,ieee80211_sta_iter_func iter_func,void *arg, u_int32_t flag)
{
  struct ieee80211com *ic = vap->iv_ic;
  struct ieee80211_iter_arg *itr_arg = NULL;
  int i, count;

  itr_arg = (struct ieee80211_iter_arg *)qdf_mem_malloc(sizeof(struct ieee80211_iter_arg));
  if (itr_arg == NULL) {
          return -1;
  }

  itr_arg->count=0;
  itr_arg->vap=vap;
  itr_arg->flag=flag;

  /*
   * we can not call the call back function iter_func from the ieee80211_sta_iter.
   * because the ieee80211_iter is called with nt lock held and will result in
   * dead lock if the implementation of iter_func calls bcak into umac to query more
   * info about the node (which is more likely).
   * instaed the ieee80211_sta_iter collects all the nodes in to the nodes array
   * part of the itr_arg and also increments the ref count on these nodes so that
   * they wont get freed.
   */

  ieee80211_iterate_node(ic,ieee80211_node_iter,(void *)itr_arg);
  for (i = 0;i < itr_arg->count; ++i)
  {
      if (i == ic->ic_num_clients) break;
      if (iter_func) {
          /*
           * node has been refed in ieee80211_sta_iter
           * so safe to acces the contentes of the node.
           */
          (* iter_func) (arg, itr_arg->nodes[i]);
      }
      /* decrement the ref count which is incremented above in ieee80211_sta_iter */
      ieee80211_free_node(itr_arg->nodes[i]);
  }
  count = itr_arg->count;
  qdf_mem_free(itr_arg);
  return (count);
}

int32_t wlan_iterate_all_sta_list(wlan_if_t vap,ieee80211_sta_iter_func iter_func,void *arg)
{
    return ieee80211_iterate_node_list(vap, iter_func, arg,
                                       IEEE80211_NODE_ITER_F_ASSOC_STA |
                                       IEEE80211_NODE_ITER_F_UNASSOC_STA);
}

int32_t wlan_iterate_station_list(wlan_if_t vap,ieee80211_sta_iter_func iter_func,void *arg)
{
    return ieee80211_iterate_node_list(vap, iter_func, arg,
                                       IEEE80211_NODE_ITER_F_ASSOC_STA);
}

int32_t wlan_iterate_unassoc_sta_list(wlan_if_t vap,ieee80211_sta_iter_func iter_func,void *arg)
{
    return ieee80211_iterate_node_list(vap, iter_func, arg,
                                       IEEE80211_NODE_ITER_F_UNASSOC_STA);
}

int wlan_node_txrate_info(wlan_node_t node, ieee80211_rate_info *rinfo)
{
    u_int8_t rc;
    rinfo->rate = node->ni_ic->ic_node_getrate(node, IEEE80211_RATE_TX);
    rinfo->lastrate = node->ni_ic->ic_node_getrate(node, IEEE80211_LASTRATE_TX);
    rc = (u_int8_t) node->ni_ic->ic_node_getrate(node, IEEE80211_RATECODE_TX);
    rinfo->mcs = rc;
    rinfo->type = (rinfo->mcs & 0x80)? IEEE80211_RATE_TYPE_MCS : IEEE80211_RATE_TYPE_LEGACY;
    rinfo->maxrate_per_client = node->ni_ic->ic_node_getrate(node,
                                                     IEEE80211_MAX_RATE_PER_CLIENT);
    rinfo->flags = (u_int8_t) node->ni_ic->ic_node_getrate(node, IEEE80211_RATEFLAGS_TX);
    return 0;
}

int wlan_node_rxrate_info(wlan_node_t node, ieee80211_rate_info *rinfo)
{
    u_int8_t rc;
    rinfo->rate = node->ni_ic->ic_node_getrate(node, IEEE80211_RATE_RX);
    rinfo->lastrate = node->ni_ic->ic_node_getrate(node, IEEE80211_LASTRATE_RX);
    rc = (u_int8_t) node->ni_ic->ic_node_getrate(node, IEEE80211_RATECODE_RX);
    rinfo->mcs = rc;
    rinfo->type = (rinfo->mcs & 0x80)? IEEE80211_RATE_TYPE_MCS : IEEE80211_RATE_TYPE_LEGACY;
    return 0;
}

int wlan_node_getrssi(wlan_node_t node,wlan_rssi_info *rssi_info,  wlan_rssi_type rssi_type )
{

    int chain_ix;
    int8_t avg_rssi = 0;
    u_int8_t flags=0;
    struct ieee80211_node *ni = node;
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = vap->iv_ic;

    if (rssi_type == WLAN_RSSI_TX)
        flags = IEEE80211_RSSI_TX;
    else if (rssi_type == WLAN_RSSI_RX)
        flags = IEEE80211_RSSI_RX;
    else if (rssi_type == WLAN_RSSI_BEACON)
        flags = IEEE80211_RSSI_BEACON;
    else if (rssi_type == WLAN_RSSI_RX_DATA)
        flags = IEEE80211_RSSI_RXDATA;

    if (rssi_type == WLAN_RSSI_TX) {
        rssi_info->valid_mask = ic->ic_tx_chainmask;
    } else {
        rssi_info->valid_mask = ic->ic_rx_chainmask;
    }

    avg_rssi = ic->ic_node_getrssi(ni,-1,flags);
    rssi_info->avg_rssi = (avg_rssi == -1) ? 0 : avg_rssi;
    for(chain_ix=0;chain_ix<MAX_CHAINS; ++chain_ix) {
        rssi_info->rssi_ctrl[chain_ix] = ic->ic_node_getrssi(ni, chain_ix ,flags);
    }
    flags |= IEEE80211_RSSI_EXTCHAN;
    for(chain_ix=0;chain_ix<MAX_CHAINS; ++chain_ix) {
        rssi_info->rssi_ext[chain_ix] = ic->ic_node_getrssi(ni, chain_ix ,flags);
    }
    return 0;

}

u_int8_t *wlan_node_getmacaddr(wlan_node_t node)
{
    return node->ni_macaddr;
}

u_int8_t *wlan_node_getbssid(wlan_node_t node)
{
    return node->ni_bssid;
}

u_int32_t wlan_node_set_assoc_decision(wlan_if_t vap, u_int8_t *macaddr, u_int16_t assoc_status, u_int16_t p2p_assoc_status)
{

    struct ieee80211_node *ni;
    ni = ieee80211_vap_find_node(vap, macaddr);
    if (ni == NULL)
        return EINVAL;
    ni->ni_assocstatus = assoc_status;
    ni->ni_p2p_assocstatus = p2p_assoc_status;
    ieee80211_free_node(ni);

    return 0;
}

u_int32_t wlan_node_get_assoc_decision(wlan_if_t vap, u_int8_t *macaddr)
{

    struct ieee80211_node *ni;
    u_int32_t assocstatus;

    ni = ieee80211_vap_find_node(vap, macaddr);
    if (ni == NULL)
        return EINVAL;
    assocstatus = ni->ni_assocstatus;
    ieee80211_free_node(ni);

    return (assocstatus);
}

wlan_chan_t wlan_node_get_chan(wlan_node_t node)
{
    return node->ni_chan;
}

u_int32_t wlan_node_get_state_flag(wlan_node_t node)
{
    return node->ni_flags;
}

u_int8_t wlan_node_get_authmode(wlan_node_t node)
{
    return node->ni_authmode;
}

u_int8_t wlan_node_get_operating_bands(wlan_node_t node)
{
    return node->ni_operating_bands;
}

u_int8_t wlan_node_get_ath_flags(wlan_node_t node)
{
    return node->ni_ath_flags;
}

u_int8_t wlan_node_get_erp(wlan_node_t node)
{
    return node->ni_erp;
}

systick_t wlan_node_get_assocuptime(wlan_node_t node)
{
    return node->ni_assocuptime;
}

u_int16_t wlan_node_get_associd(wlan_node_t node)
{
    return ieee80211_node_get_associd((struct ieee80211_node *)node);
}

u_int16_t wlan_node_get_txpower(wlan_node_t node)
{
    return ieee80211_node_get_txpower((struct ieee80211_node *)node);
}

u_int16_t wlan_node_get_vlan(wlan_node_t node)
{
    return node->ni_vlan;
}

int
wlan_node_get_ucast_ciphers(wlan_node_t node, ieee80211_cipher_type types[], u_int len)
{
    struct ieee80211_node *ni = node;
    struct ieee80211_rsnparms *rsn = &ni->ni_rsn;
    ieee80211_cipher_type cipher;
    u_int count = 0;

    for (cipher = IEEE80211_CIPHER_WEP; cipher < IEEE80211_CIPHER_MAX; cipher++) {
        if (RSN_HAS_UCAST_CIPHER(rsn, cipher)) {
            /* Is input buffer big enough */
            if (len <= count)
                return -EINVAL;

            types[count++] = cipher;
        }
    }

    return count;
}

void  wlan_node_get_txseqs(wlan_node_t node, u_int16_t *txseqs, u_int len)
{
    struct ieee80211_node *ni = node;

    if (len > sizeof(ni->ni_txseqs)) {
        len = sizeof(ni->ni_txseqs);
    }
    OS_MEMCPY(txseqs, ni->ni_txseqs, len);
}

void  wlan_node_get_rxseqs(wlan_node_t node, u_int16_t *rxseqs, u_int len)
{
    struct ieee80211_node *ni = node;

    if (len > sizeof(ni->ni_rxseqs)) {
        len = sizeof(ni->ni_rxseqs);
    }
    OS_MEMCPY(rxseqs, ni->ni_rxseqs, len);
}

u_int8_t wlan_node_get_uapsd(wlan_node_t node)
{
    return node->ni_uapsd;
}

u_int16_t wlan_node_get_inact(wlan_node_t node)
{
    struct ieee80211_node *ni = node;
    u_int16_t inact_time;

    /* NB: leave all cases in case we relax ni_associd == 0 check */
    if (ieee80211_node_is_authorized(ni)) {
        inact_time = ni->ni_vap->iv_inact_run;
    } else if (ni->ni_associd != 0) {
        inact_time = ni->ni_vap->iv_inact_auth;
    } else {
        inact_time = ni->ni_vap->iv_inact_init;
    }
    inact_time = (inact_time - ni->ni_inact) * IEEE80211_INACT_WAIT;

    return inact_time;
}

u_int16_t wlan_node_get_htcap(wlan_node_t node)
{
    return node->ni_htcap;
}

bool wlan_node_has_flag(struct ieee80211_node *ni, u_int16_t flag)
{
    return (ieee80211node_has_flag(ni, flag));
}


u_int16_t wlan_node_get_phymodes(struct ieee80211_node *ni)
{
    return ieee80211node_get_phymodes(ni);
}

u_int16_t wlan_node_get_mode(wlan_node_t node)
{

	return wlan_node_get_phymodes(node);
}

/* To check if WEP/TKIP Aggregation can be enabled for this node. */
int
ieee80211_has_weptkipaggr(struct ieee80211_node *ni)
{
    struct ieee80211com *ic = ni->ni_ic;

    /* Both the peer node and our hardware must support aggregation during wep/tkip */
    if ((ieee80211node_has_flag(ni, IEEE80211_NODE_WEPTKIPAGGR)) &&
        ieee80211com_has_athextcap(ic, IEEE80211_ATHEC_WEPTKIPAGGR)) {
        return 1;
    }
    return 0;
}


void wlan_node_set_txpwr(wlan_if_t vap, u_int16_t txpowlevel, u_int8_t *addr)
{
    struct ieee80211_node_table *nt = &vap->iv_ic->ic_sta;
    struct ieee80211_node *ni;
    ni = ieee80211_find_node(nt, addr);
    ASSERT(ni);
    if (!ni)
        return;
    ieee80211node_set_txpower(ni, txpowlevel);
    ieee80211_free_node(ni);
}

int wlan_node_alloc_aid_bitmap(wlan_if_t vap, u_int16_t old_len)
{
    u_int8_t    *bitmap = NULL;
    u_int16_t   len = howmany(vap->iv_max_aid, 32) * sizeof(u_int32_t);

    //printk("[%s] entry\n",__func__);

    bitmap = OS_MALLOC(vap->iv_ic->ic_osdev, len, GFP_KERNEL);
    if(!bitmap) {
        vap->iv_max_aid = old_len;
        return -1;
    }
    OS_MEMZERO(bitmap, len);
    if (vap->iv_aid_bitmap) {
        OS_MEMCPY(bitmap, vap->iv_aid_bitmap, len > old_len ? old_len : len);
        OS_FREE(vap->iv_aid_bitmap);
    }
    vap->iv_aid_bitmap = (u_int32_t *)bitmap;

    //printk("[%s] exist\n",__func__);

    return 0;
}

int wlan_send_rssi(struct ieee80211vap *vap, u_int8_t *macaddr)
{
    struct ieee80211com *ic = vap->iv_ic;
    if (ic->ic_ath_send_rssi)
        ic->ic_ath_send_rssi(ic, macaddr, vap);
    return 0;
}

int wlan_node_set_fixed_rate(wlan_node_t node, u_int8_t rate)
{
    struct ieee80211_node *ni = node;
    struct ieee80211com *ic = ni->ni_vap->iv_ic;
    ni->ni_fixed_rate = rate;
    if (ic->ic_set_sta_fixed_rate) {
	ic->ic_set_sta_fixed_rate(ni);
    }
    return 0;
}

u_int8_t wlan_node_get_fixed_rate(wlan_node_t node)
{
    return node->ni_fixed_rate;
}

u_int8_t wlan_node_get_nss(wlan_node_t node)
{
#define NSS_RX_SHIFT 4
    struct ieee80211_node *ni = node;
    return ((ni->ni_rxstreams << NSS_RX_SHIFT) | ni->ni_txstreams);
}

u_int8_t wlan_node_get_256qam_support(wlan_node_t node)
{
    struct ieee80211_node *ni = node;
    u_int8_t is_256qam = 0;
    is_256qam = (ni->ni_flags & IEEE80211_NODE_VHT) ? 1 : 0;

    return (is_256qam);
}

#if QCA_AIRTIME_FAIRNESS
u_int32_t wlan_node_get_airtime(wlan_node_t node)
{
    return node->ni_ic->ic_node_getairtime(node);
}
#endif

u_int32_t wlan_node_get_last_txpower(wlan_node_t node)
{
    return node->ni_ic->ic_node_get_last_txpower(node);
}
