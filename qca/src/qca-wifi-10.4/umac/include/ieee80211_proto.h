/*
 * Copyright (c) 2011,2017 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 *  Copyright (c) 2008 Atheros Communications Inc. 
 * All Rights Reserved.
 * 
 * 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */

#ifndef _ATH_STA_IEEE80211_PROTO_H
#define _ATH_STA_IEEE80211_PROTO_H

/*
 * 802.11 protocol implementation definitions.
 */

enum ieee80211_state {
    IEEE80211_S_INIT        = 0,    /* default state */
    IEEE80211_S_SCAN        = 1,    /* scanning */
    IEEE80211_S_JOIN        = 2,    /* join */
    IEEE80211_S_AUTH        = 3,    /* try to authenticate */
    IEEE80211_S_ASSOC       = 4,    /* try to assoc */
    IEEE80211_S_RUN         = 5,    /* associated */
    IEEE80211_S_DFS_WAIT,
    IEEE80211_S_WAIT_TXDONE,    /* waiting for pending tx before going to INI */
    IEEE80211_S_STOPPING,
    IEEE80211_S_STANDBY,        /* standby, waiting to re-start */

    IEEE80211_S_MAX /* must be last */
};

enum ieee80211_state_event {
    IEEE80211_STATE_EVENT_DOWN    = 0, 
    IEEE80211_STATE_EVENT_JOIN    , 
    IEEE80211_STATE_EVENT_SCAN_START    , 
    IEEE80211_STATE_EVENT_SCAN_END    , 
    IEEE80211_STATE_EVENT_TXDONE  ,
    IEEE80211_STATE_EVENT_UP      ,
    IEEE80211_STATE_EVENT_DFS_WAIT   ,
    IEEE80211_STATE_EVENT_DFS_CLEAR  ,
    IEEE80211_STATE_EVENT_FORCE_STOP  , 
    IEEE80211_STATE_EVENT_STANDBY,
    IEEE80211_STATE_EVENT_RESUME,
    IEEE80211_STATE_EVENT_BSS_NODE_FREED,
    IEEE80211_STATE_EVENT_CHAN_SET   ,
#if UMAC_REPEATER_DELAYED_BRINGUP    
    IEEE80211_STATE_EVENT_HANDSHAKE_FINISH   ,
#endif    
    IEEE80211_STATE_EVENT_RESTART_REQ ,
};


#define IEEE80211_ACTION_BUF_SIZE 256

#ifdef TARGET_SUPPORT_TSF_TIMER
typedef void (*defer_function)(void *arg);
typedef struct ieee80211_recv_defer_args {
    TAILQ_ENTRY(ieee80211_recv_defer_args) mlist;
    defer_function defer_fuc;
    void *arg;
}ieee80211_recv_defer_args_t;
#define IEEE80211_DEFER_LOCK_INIT(_ic)         spin_lock_init(&(_ic)->ic_defer_lock)
#define IEEE80211_DEFER_LOCK_BH(_ic)           spin_lock_bh(&(_ic)->ic_defer_lock)
#define IEEE80211_DEFER_UNLOCK_BH(_ic)         spin_unlock_bh(&(_ic)->ic_defer_lock)
#define IEEE80211_DEFER_LOCK(_ic)           spin_lock(&(_ic)->ic_defer_lock)
#define IEEE80211_DEFER_UNLOCK(_ic)         spin_unlock(&(_ic)->ic_defer_lock)
#define IEEE80211_DEFER_LOCK_DESTROY(_ic)      spin_lock_destroy(&(_ic)->ic_defer_lock)
#define IEEE80211_DEFER_CREATE(_ic, _func)     INIT_WORK(&_ic->ic_defer_work, _func, _ic)
#define IEEE80211_DEFER_DESTROY(_ic)           
#define IEEE80211_DEFER_SCHEDULE(_ic)          schedule_work(&_ic->ic_defer_work)
#define IEEE80211_DEFER_DISABLE(_ic)           
#define IEEE80211_TAILQ_INIT(_ic)              TAILQ_INIT(&_ic->ic_defer_data)
#endif

struct ieee80211_action_mgt_args {
    u_int8_t    category;
    u_int8_t    action;
    u_int32_t   arg1;
    u_int32_t   arg2;
    u_int32_t   arg3;
    u_int8_t    *arg4;
};

struct ieee80211_action_mgt_buf {
    u_int8_t    buf[IEEE80211_ACTION_BUF_SIZE];
};

typedef struct  _ieee80211_vap_state_info {
    u_int32_t     iv_state;
    spinlock_t    iv_state_lock; /* lock to serialize access to vap state machine */
    bool          iv_sm_running; /* indicates that the VAP SM is running */ 
}ieee80211_vap_state_info;

/* Any extra context information that might need to be considered in some
 * specific situations while creating a protocol frame.
 */
struct ieee80211_framing_extractx {
    bool    fectx_assocwar160_reqd;    /* Whether 160 MHz width association WAR
                                          is required. */
    bool    fectx_nstscapwar_reqd;     /* Whether STSCAP MBP WAR required */
    int     datarate;                  /* tx rate */
};

extern const char *ieee80211_mgt_subtype_name[];
extern const char *ieee80211_wme_acnames[];
/*
 * flags for ieee80211_send_cts
 */
#define IEEE80211_CTS_SMPS 1
#if ATH_SUPPORT_WIFIPOS
#define IEEE80211_CTS_WIFIPOS 1<<1
#endif

int ieee80211_state_event(struct ieee80211vap *vap, enum ieee80211_state_event event);

void ieee80211_proto_attach(struct ieee80211com *ic);
void ieee80211_proto_detach(struct ieee80211com *ic);

void ieee80211_proto_vattach(struct ieee80211vap *vap);
void ieee80211_proto_vdetach(struct ieee80211vap *vap);

int  ieee80211_vap_start(struct ieee80211vap *vap);
int  ieee80211_vap_join(struct ieee80211vap *vap);
void ieee80211_vap_stop(struct ieee80211vap *vap, bool force);
void ieee80211_vap_standby(struct ieee80211vap *vap);
void ieee80211_vap_bss_node_freed(struct ieee80211vap *vap);
void ieee80211_vap_restart(struct ieee80211vap *vap);
#if UMAC_REPEATER_DELAYED_BRINGUP
void ieee80211_vap_handshake_finish(struct ieee80211vap *vap);
#endif
int ieee80211_parse_wmeparams(struct ieee80211vap *vap, u_int8_t *frm, u_int8_t *qosinfo, int forced_update);
int ieee80211_parse_wmeinfo(struct ieee80211vap *vap, u_int8_t *frm, u_int8_t *qosinfo);
int ieee80211_parse_wmeie(u_int8_t *frm, const struct ieee80211_frame *wh, struct ieee80211_node *ni);

int ieee80211_parse_tspecparams(struct ieee80211vap *vap, u_int8_t *frm);
u_int32_t ieee80211_parse_mpdudensity(u_int32_t mpdudensity);
int ieee80211_parse_htcap(struct ieee80211_node *ni, u_int8_t *ie);
void ieee80211_parse_htinfo(struct ieee80211_node *ni, u_int8_t *ie);
int ieee80211_parse_dothparams(struct ieee80211vap *vap, u_int8_t *frm);

int ieee80211_parse_wpa(struct ieee80211vap *vap, u_int8_t *frm, struct ieee80211_rsnparms *rsn);
int ieee80211_parse_rsn(struct ieee80211vap *vap, u_int8_t *frm, struct ieee80211_rsnparms *rsn);
int ieee80211_parse_timeieparams(struct ieee80211vap *vap, u_int8_t *frm);

void ieee80211_process_athextcap_ie(struct ieee80211_node *ni, u_int8_t *ie);

/**
 * @brief Parse a Whole Home Coverage AP Info IE, storing the capabilities
 *        of the AP.
 *
 * @param [in] ni  the BSS node for the AP that advertised these capabilities
 * @param [in] ie  the beginning of the information element
 */
void ieee80211_process_whc_apinfo_ie(struct ieee80211_node *ni, const u_int8_t *ie);

void ieee80211_process_whc_rept_info_ie(struct ieee80211_node *ni, const u_int8_t *ie);

void ieee80211_parse_athParams(struct ieee80211_node *ni, u_int8_t *ie);
void ieee80211_parse_vhtcap(struct ieee80211_node *ni, u_int8_t *ie);
int ieee80211_check_mu_client_cap(struct ieee80211_node *ni, u_int8_t *ie);
void ieee80211_parse_vhtop(struct ieee80211_node *ni, u_int8_t *ie, u_int8_t *htinfo_ie);
void ieee80211_parse_opmode(struct ieee80211_node *ni, u_int8_t *ie, u_int8_t subtype);
void ieee80211_parse_opmode_notify(struct ieee80211_node *ni, u_int8_t *ie, u_int8_t subtype);
void ieee80211_add_opmode(u_int8_t *frm, struct ieee80211_node *ni,
                    struct ieee80211com *ic,  u_int8_t subtype);
u_int8_t *ieee80211_add_opmode_notify(u_int8_t *frm, struct ieee80211_node *ni,
                    struct ieee80211com *ic,  u_int8_t subtype);
int ieee80211_process_asresp_elements(struct ieee80211_node *ni,
                                  u_int8_t *frm,
                                  u_int32_t ie_len);
#if ATH_BAND_STEERING
void ieee80211_process_pwrcap(struct ieee80211_node *ni, u_int8_t *ie);
#endif

void ieee80211_prepare_qosnulldata(struct ieee80211_node *ni, wbuf_t wbuf, int ac);

int ieee80211_send_qosnulldata_offchan_tx_test(struct ieee80211_node *ni, int ac, int pwr_save);
int ieee80211_send_qosnulldata(struct ieee80211_node *ni, int ac, int pwr_save);
#if ATH_SUPPORT_WIFIPOS
int ieee80211_send_qosnulldata_keepalive(struct ieee80211_node *ni, int ac, int pwr_save, int keepalive);
#endif
int ieee80211_send_qosnull_probe(struct ieee80211_node *ni, int ac, int pwr_save, void *wifiposdata);
int ieee80211_send_null_probe(struct ieee80211_node *ni, int pwr_save, void *wifiposdata);

int ieee80211_send_nulldata(struct ieee80211_node *ni, int pwr_save);
#if ATH_SUPPORT_WIFIPOS
int ieee80211_send_nulldata_keepalive(struct ieee80211_node *ni, int pwr_save,int keepalive);
#endif
void ieee80211_check_and_update_pn(wbuf_t wbuf);

int ieee80211_send_pspoll(struct ieee80211_node *ni);

int ieee80211_send_cts(struct ieee80211_node *ni, int flags);

#if ATH_SUPPORT_WIFIPOS
int ieee80211_send_cts_to_self_dur(struct ieee80211_node *ni, u_int32_t dur);
#endif

int ieee80211_send_probereq(struct ieee80211_node *ni,
                            const u_int8_t        *sa,
                            const u_int8_t        *da,
                            const u_int8_t        *bssid,
                            const u_int8_t        *ssid, 
                            const u_int32_t       ssidlen,
                            const void            *optie, 
                            const size_t          optielen);

int ieee80211_send_proberesp(struct ieee80211_node *ni, u_int8_t *macaddr,
                            const void            *optie, 
                            const size_t          optielen,
                            struct ieee80211_framing_extractx *extractx);

int ieee80211_send_auth( struct ieee80211_node *ni, u_int16_t seq,
                         u_int16_t status, u_int8_t *challenge_txt, 
                         u_int8_t challenge_len,
                         struct ieee80211_app_ie_t *appie);
int ieee80211_send_deauth(struct ieee80211_node *ni, u_int16_t reason);
int ieee80211_send_disassoc(struct ieee80211_node *ni, u_int16_t reason);
int ieee80211_send_disassoc_with_callback(struct ieee80211_node *ni, u_int16_t reason,
                                          wlan_vap_complete_buf_handler handler,
                                          void *arg);
int ieee80211_send_assoc(struct ieee80211_node *ni,
                         int reassoc, u_int8_t *prev_bssid);
int ieee80211_send_assocresp(struct ieee80211_node *ni, 
                             u_int8_t reassoc, u_int16_t reason,
                             struct ieee80211_app_ie_t *optie);
wbuf_t ieee80211_setup_assocresp(struct ieee80211_node *ni, wbuf_t wbuf,
                                 u_int8_t reassoc, u_int16_t reason,
                                 struct ieee80211_app_ie_t *optie);
void ieee80211_process_external_radar_detect(struct ieee80211_node *ni);
wbuf_t ieee80211_getmgtframe(struct ieee80211_node *ni, int subtype, u_int8_t **frm, u_int8_t isboardcast);
int ieee80211_send_mgmt(struct ieee80211vap *vap,struct ieee80211_node *ni, wbuf_t wbuf, bool force_send);

int ieee80211_send_action( struct ieee80211_node *ni,
                           struct ieee80211_action_mgt_args *actionargs,
                           struct ieee80211_action_mgt_buf  *actionbuf );
#ifdef ATH_SUPPORT_TxBF
int ieee80211_send_v_cv_action(struct ieee80211_node *ni, u_int8_t *data_buf, u_int16_t buf_len);
#endif

int ieee80211_send_bar(struct ieee80211_node *ni, u_int8_t tidno, u_int16_t seqno);

int ieee80211_recv_mgmt(struct ieee80211_node *ni, wbuf_t wbuf, int subtype,
                        struct ieee80211_rx_status *rs);
#ifdef  ATH_HTC_MII_RXIN_TASKLET
void ieee80211_recv_mgmt_defer(void *arg);
#endif

int ieee80211_recv_ctrl(struct ieee80211_node *ni, wbuf_t wbuf,
						int subtype, struct ieee80211_rx_status *rs);

ieee80211_scan_entry_t ieee80211_update_beacon(struct ieee80211_node *ni, wbuf_t wbuf,
                                               struct ieee80211_frame *wh, int subtype,
                                               struct ieee80211_rx_status *rs);

void ieee80211_reset_erp(struct ieee80211com *,
                         enum ieee80211_phymode,
                         enum ieee80211_opmode);
void ieee80211_set_shortslottime(struct ieee80211com *, int onoff);


void ieee80211_dump_pkt(struct ieee80211com *ic,
                   const u_int8_t *buf, int len, int rate, int rssi);
void    ieee80211_change_cw(struct ieee80211com *ic);

#if UMAC_SUPPORT_AP || UMAC_SUPPORT_IBSS || UMAC_SUPPORT_BTAMP
struct ieee80211_beacon_offsets;
#if UMAC_SUPPORT_WNM
int
ieee80211_beacon_update(struct ieee80211_node *ni,
                        struct ieee80211_beacon_offsets *bo, wbuf_t wbuf, int mcast, u_int32_t nfmsq_mask);
#else
int
ieee80211_beacon_update(struct ieee80211_node *ni,
                        struct ieee80211_beacon_offsets *bo, wbuf_t wbuf, int mcast);
#endif
wbuf_t ieee80211_beacon_alloc(struct ieee80211_node *ni, struct ieee80211_beacon_offsets *bo);
#else
#if UMAC_SUPPORT_WNM
#define ieee80211_beacon_update(ni, bo,wbuf,mcast,nfmsq_mask) (-1)
#else
#define ieee80211_beacon_update(ni, bo,wbuf,mcast) (-1)
#endif
#define ieee80211_beacon_alloc(ni, bo)  (NULL)
#endif

struct ieee80211_bcn_prb_info;
int ieee80211_bcn_prb_template_update(struct ieee80211_node *ni,
                            struct ieee80211_bcn_prb_info *templ);

#if UMAC_SUPPORT_STA
void ieee80211_beacon_miss(struct ieee80211com *);
#else
#define ieee80211_beacon_miss(ic) /**/
#endif

/* beacon rssi threshold notification */
void ieee80211_notify_beacon_rssi(struct ieee80211com *);

/*
 * Return the size of the 802.11 header for a management or data frame.
 */
INLINE static int
ieee80211_hdrsize(const void *data)
{
    const struct ieee80211_frame *wh = (const struct ieee80211_frame *)data;
    int size = sizeof(struct ieee80211_frame);

    /* NB: we don't handle control frames */
    KASSERT((wh->i_fc[0]&IEEE80211_FC0_TYPE_MASK) != IEEE80211_FC0_TYPE_CTL,
            ("%s: control frame", __func__));
    if ((wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_DSTODS)
        size += IEEE80211_ADDR_LEN;
    
    if (IEEE80211_QOS_HAS_SEQ(wh)){
        size += sizeof(u_int16_t);
#ifdef ATH_SUPPORT_TxBF
        /* Qos frame with Order bit set indicates an HTC frame */
        if (wh->i_fc[1] & IEEE80211_FC1_ORDER) {
            size += sizeof(struct ieee80211_htc);
        }
#endif
    }
    return size;
}

/*
 * Like ieee80211_hdrsize, but handles any type of frame.
 */
static INLINE int
ieee80211_anyhdrsize(const void *data)
{
    const struct ieee80211_frame *wh = (const struct ieee80211_frame *)data;

    if ((wh->i_fc[0]&IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_CTL) {
        switch (wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) {
            case IEEE80211_FC0_SUBTYPE_CTS:
            case IEEE80211_FC0_SUBTYPE_ACK:
                return sizeof(struct ieee80211_frame_ack);
        }
        return sizeof(struct ieee80211_frame_min);
    } else
        return ieee80211_hdrsize(data);
}

typedef struct wme_phyParamType {
    u_int8_t aifsn;
    u_int8_t logcwmin;
    u_int8_t logcwmax;
    u_int16_t txopLimit;
    u_int8_t acm;
} wmeParamType;

struct wmeParams {
    u_int8_t    wmep_acm;           /* ACM parameter */
    u_int8_t    wmep_aifsn;         /* AIFSN parameters */
    u_int8_t    wmep_logcwmin;      /* cwmin in exponential form */
    u_int8_t    wmep_logcwmax;      /* cwmax in exponential form */
    u_int16_t   wmep_txopLimit;     /* txopLimit */
    u_int8_t    wmep_noackPolicy;   /* No-Ack Policy: 0=ack, 1=no-ack */
};

#define IEEE80211_EXPONENT_TO_VALUE(_exp)  (1 << (u_int32_t)(_exp)) - 1
#define IEEE80211_TXOP_TO_US(_txop)  (u_int32_t)(_txop) << 5
#define IEEE80211_US_TO_TXOP(_us)  (u_int16_t)((u_int32_t)(_us)) >> 5

struct chanAccParams{
    /* XXX: is there any reason to have multiple instances of cap_info??? */
    u_int8_t            cap_info;                   /* U-APSD flag + ver. of the current param set */
    struct wmeParams    cap_wmeParams[WME_NUM_AC];  /* WME params for each access class */ 
};

struct ieee80211_wme_state {
    u_int32_t   wme_flags;
#define	WME_F_AGGRMODE          0x00000001              /* STATUS: WME agressive mode */
#define WME_F_BSSPARAM_UPDATED  0x00000010              /* WME params broadcasted to STAs was updated */
    
    u_int       wme_hipri_traffic;              /* VI/VO frames in beacon interval */
    u_int       wme_hipri_switch_thresh;        /* agressive mode switch thresh */
    u_int       wme_hipri_switch_hysteresis;    /* agressive mode switch hysteresis */

    struct chanAccParams    wme_wmeChanParams;  /* configured WME parameters applied to itself */
    struct chanAccParams    wme_wmeBssChanParams;   /* configured WME parameters broadcasted to STAs */
    struct chanAccParams    wme_chanParams;     /* channel parameters applied to itself */
    struct chanAccParams    wme_bssChanParams;  /* channel parameters broadcasted to STAs */
    u_int8_t                wme_nonAggressiveMode;  /* don't use aggressive params and use WME params */

    /* update hardware tx params after wme state change */
    int	(*wme_update)(struct ieee80211com *);
};

void ieee80211_wme_initparams(struct ieee80211vap *);
void ieee80211_wme_initparams_locked(struct ieee80211vap *);
void ieee80211_wme_updateparams(struct ieee80211vap *);
void ieee80211_wme_updateinfo(struct ieee80211vap *);
void ieee80211_wme_updateparams_locked(struct ieee80211vap *);
void ieee80211_wme_updateinfo_locked(struct ieee80211vap *);
void ieee80211_wme_amp_overloadparams_locked(struct ieee80211com *ic);
void ieee80211_wme_initglobalparams(struct ieee80211com *ic);

/*
 * Beacon frames constructed by ieee80211_beacon_alloc
 * have the following structure filled in so drivers
 * can update the frame later w/ minimal overhead.
 */
struct ieee80211_beacon_offsets {
    u_int16_t	*bo_caps;		/* capabilities */
    u_int8_t    *bo_rates;      /* start of rate set */
    u_int8_t	*bo_tim;		/* start of atim/dtim */
    u_int8_t	*bo_wme;		/* start of WME parameters */
    u_int8_t	*bo_tim_trailer;	/* start of fixed-size tim trailer */
    u_int16_t	bo_tim_len;		/* atim/dtim length in bytes */
    u_int16_t	bo_tim_trailerlen;	/* trailer length in bytes */
    u_int8_t	*bo_chanswitch;		/* where channel switch IE will go */
    u_int16_t	bo_chanswitch_trailerlen;
    u_int8_t    *bo_pwrcnstr;           /* Power constraint IE */
    u_int8_t    *bo_quiet;              /* where quiet IE */
    u_int8_t	*bo_ath_caps;		/* where ath caps is */
    u_int8_t	*bo_xr;			/* start of xr element */
    u_int8_t	*bo_erp;		/* start of ERP element */
    u_int8_t    *bo_xrates;      /* start of xrate set */
    u_int8_t	*bo_htinfo;		/* start of HT Info element */
    u_int8_t    *bo_htinfo_pre_ana; /* start of pre ana HT Info element */ 
    u_int8_t    *bo_htinfo_vendor_specific;/* start of vendor specific HT Info element */ 
    u_int8_t    *bo_appie_buf;  /* start of APP IE buf */
    u_int16_t   bo_appie_buf_len;
    u_int8_t    *bo_obss_scan;          /* start of overlap BSS Scan element */
    u_int8_t    *bo_extcap;
    u_int8_t    *bo_htcap;
    u_int8_t    *bo_bssload;          /* start of bss load element */
    u_int8_t    *bo_secchanoffset;  /* start of secondary channel offset element */
    u_int16_t   bo_secchanoffset_trailerlen; /* number of bytes in beacon following bo_secchanoffset */
#if ATH_SUPPORT_IBSS_DFS
    u_int8_t    *bo_ibssdfs;  /* start of ibssdfs */
    u_int16_t	bo_ibssdfs_trailerlen;    
#endif /* ATH_SUPPORT_IBSS_DFS */
#if UMAC_SUPPORT_WNM
    u_int8_t     *bo_fms_desc;          /* start of FMS Descriptor */
    u_int8_t     *bo_fms_trailer;       /* start of FMS desc trailer */
    u_int16_t    bo_fms_len;            /* FMS desc length in bytes */
    u_int16_t    bo_fms_trailerlen;     /* FMS desc trailer length in bytes */
#endif
    u_int8_t    *bo_vhtcap;          /* start of VHT capability element */
    u_int8_t    *bo_vhtop;           /* start of VHT operational element */
    u_int8_t    *bo_vhttxpwr;        /* start of VHT Tx power Envelope element */
    u_int8_t    *bo_vhtchnsw;        /* start of VHT Channel switch wrapper element */
    u_int16_t	bo_vhtchnsw_trailerlen;	/* trailer length in bytes */
    u_int8_t    *bo_interop_vhtcap;  /* start of VHT Interop capability element */
    u_int8_t    *bo_bwnss_map;      /* start of Bandwidth NSS map element */
    u_int8_t    *bo_apriori_next_channel;   /* start of next channel element */
    u_int8_t    *bo_mbo_cap;         /*start of MBO capability */
    u_int8_t    *bo_whc_apinfo;          /* start of WHC ap info element(vendor IE) */
    u_int16_t   bo_whc_apinfo_len;   /* WHC ap info element length */
#if QCN_IE
    u_int8_t    *bo_qcn_ie;          /* start of QCN info element(vendor IE) */
    u_int16_t   bo_qcn_ie_len;       /* QCN info element length */
#endif
};

struct ieee80211_bcn_prb_info {
    u_int16_t	caps;		/* capabilities */
    u_int8_t    erp;            /* ERP */
    /* TBD: More elements to follow */
};

struct ieee80211_bwnss_map {
    u_int8_t bw_nss_160; /* Bandwidth NSS mapping for 160 MHz*/
#define IEEE80211_NSSMAP_SAME_NSS_FOR_ALL_BW    0x01 /* NSS used for all available BW will be same */
    u_int8_t flag; /* flag to indicate ext nss special cases */
};

/* XXX exposed 'cuz of beacon code botch */
u_int8_t *ieee80211_add_rates(u_int8_t *, const struct ieee80211_rateset *);
u_int8_t *ieee80211_add_xrates(u_int8_t *, const struct ieee80211_rateset *);
u_int8_t *ieee80211_add_ssid(u_int8_t *frm, const u_int8_t *ssid, u_int len);
u_int8_t *ieee80211_add_erp(u_int8_t *, struct ieee80211com *);
u_int8_t *ieee80211_add_athAdvCap(u_int8_t *, u_int8_t, u_int16_t);
u_int8_t *ieee80211_add_athextcap(u_int8_t *, u_int16_t, u_int8_t);

/**
 * @brief Add the Whole Home Coverage AP Info information element to a frame.
 *
 * @param [in] frm  the place in the frame to which to start writing the IE
 * @param [in] whc_caps  the bitmask that describes the AP's capabilities
 * @param [in] vap handle
 * @param [in] Pointer to length which gets total IE length
 *
 * @return pointer to where the remainder of the frame should be written
 */
u_int8_t *ieee80211_add_whc_ap_info_ie(u_int8_t *frm, u_int16_t whc_caps,
        struct ieee80211vap *vap, u_int16_t *ie_len);
u_int8_t *ieee80211_add_whc_rept_info_ie(u_int8_t *frm);

u_int8_t *ieee80211_add_wmeinfo(u_int8_t *frm, struct ieee80211_node *ni, 
                                u_int8_t wme_subtype, u_int8_t *wme_info, u_int8_t info_len);
u_int8_t *ieee80211_add_wme_param(u_int8_t *, struct ieee80211_wme_state *,
								  int uapsd_enable);
u_int8_t *ieee80211_add_country(u_int8_t *, struct ieee80211vap *vap);
u_int8_t *ieee80211_add_doth(u_int8_t *frm, struct ieee80211vap *vap);
u_int8_t *ieee80211_add_htcap(u_int8_t *, struct ieee80211_node *, u_int8_t);
u_int8_t *ieee80211_add_htcap_pre_ana(u_int8_t *, struct ieee80211_node *, u_int8_t);
u_int8_t *ieee80211_add_htcap_vendor_specific(u_int8_t *, struct ieee80211_node *, u_int8_t);
u_int8_t *ieee80211_add_htinfo(u_int8_t *, struct ieee80211_node *);
u_int8_t *ieee80211_add_htinfo_pre_ana(u_int8_t *, struct ieee80211_node *);
u_int8_t *ieee80211_add_htinfo_vendor_specific(u_int8_t *, struct ieee80211_node *);
void ieee80211_update_htinfo_cmn(struct ieee80211_ie_htinfo_cmn *ie, struct ieee80211_node *ni);
void ieee80211_update_obss_scan(struct ieee80211_ie_obss_scan *, struct ieee80211_node *);
u_int8_t *ieee80211_add_obss_scan(u_int8_t *, struct ieee80211_node *);
u_int8_t *ieee80211_add_extcap(u_int8_t *, struct ieee80211_node *);
u_int8_t *ieee80211_add_bw_nss_maping(u_int8_t *frm, struct ieee80211_bwnss_map *bw_nss_mapping);
u_int8_t *ieee80211_add_next_channel(u_int8_t *frm, struct ieee80211_node *ni, struct ieee80211com *ic, int subtype);
#if ATH_SUPPORT_HS20
u_int8_t *ieee80211_add_qosmapset(u_int8_t *frm, struct ieee80211_node *);
#endif

u_int8_t *ieee80211_setup_rsn_ie(struct ieee80211vap *vap, u_int8_t *ie);
u_int8_t *ieee80211_setup_wpa_ie(struct ieee80211vap *vap, u_int8_t *ie);
#if ATH_SUPPORT_WAPI
u_int8_t *ieee80211_setup_wapi_ie(struct ieee80211vap *vap, u_int8_t *ie);
int ieee80211_parse_wapi(struct ieee80211vap *vap, u_int8_t *frm, struct ieee80211_rsnparms *rsn);
#endif

#if UMAC_REPEATER_DELAYED_BRINGUP
/*it would be better handled by adding one more state in sta state machine
but right now to avoid it we are calling this directly from here
*/
extern void osif_check_pending_ap_vaps(wlan_dev_t comhandle, wlan_if_t vap);
#endif

void osif_restart_stop_ap_vaps(wlan_dev_t comhandle, wlan_if_t vap);
void osif_restart_start_ap_vaps(wlan_dev_t comhandle, wlan_if_t vap);
#if ATH_SUPPORT_IBSS_DFS
#define MIN_IBSS_DFS_IE_CONTENT_SIZE            9
#define IBSS_DFS_ZERO_MAP_SIZE                  7
#define DEFAULT_MAX_CSA_MEASREP_ACTION_PER_TBTT 2
#define INIT_IBSS_DFS_OWNER_RECOVERY_TIME_IN_TBTT    10
enum ieee80211_ibss_dfs_state {
    IEEE80211_IBSSDFS_OWNER = 0,
    IEEE80211_IBSSDFS_JOINER = 1,
    IEEE80211_IBSSDFS_WAIT_RECOVERY = 2,
    IEEE80211_IBSSDFS_CHANNEL_SWITCH = 3, 
};

void ieee80211_build_ibss_dfs_ie(struct ieee80211vap *vap);
u_int8_t *ieee80211_add_ibss_dfs(u_int8_t *frm, struct ieee80211vap *vap);
u_int8_t *ieee80211_add_ibss_csa(u_int8_t *frm, struct ieee80211vap *vap);
int ieee80211_measurement_report_action(    struct ieee80211vap *vap,     struct ieee80211_measurement_report_ie *pmeasrepie    );
int ieee80211_process_meas_report_ie(struct ieee80211_node *ni, struct ieee80211_action *pia);
#endif /* ATH_SUPPORT_IBSS_DFS */
void  ieee80211_build_countryie(struct ieee80211vap *vap);

struct ieee80211_channel * ieee80211_get_new_sw_chan (
            struct ieee80211_node *ni, struct ieee80211_channelswitch_ie *chanie,
            struct ieee80211_extendedchannelswitch_ie *echanie, struct ieee80211_ie_sec_chan_offset *secchanoffsetie,
            struct ieee80211_ie_wide_bw_switch *widebwie,
            u_int8_t *cswarp
);

int ieee80211_process_csa_ecsa_ie( struct ieee80211_node *ni, struct ieee80211_action *pia);

u_int8_t * ieee80211_add_mmie(struct ieee80211vap *vap, u_int8_t *bfrm, u_int32_t len);
u_int8_t * ieee80211_add_vhtcap(u_int8_t *frm, struct ieee80211_node *ni,
                     struct ieee80211com *ic, u_int8_t subtype, 
                     struct ieee80211_framing_extractx *extractx,
                     u_int8_t *macaddr);
u_int8_t * ieee80211_add_interop_vhtcap(u_int8_t *frm, struct ieee80211_node *ni,
                     struct ieee80211com *ic, u_int8_t subtype);
u_int8_t * ieee80211_add_vhtop(u_int8_t *frm, struct ieee80211_node *ni, 
                     struct ieee80211com *ic, u_int8_t subtype,
                     struct ieee80211_framing_extractx *extractx);
u_int8_t *
ieee80211_add_vht_txpwr_envlp(u_int8_t *frm, struct ieee80211_node *ni,
                    struct ieee80211com *ic,  u_int8_t subtype, u_int8_t is_subelement);
u_int8_t *
ieee80211_add_chan_switch_wrp(u_int8_t *frm, struct ieee80211_node *ni,
                    struct ieee80211com *ic,  u_int8_t subtype, u_int8_t extchswitch);
#if ATH_BAND_STEERING
void ieee80211_process_pwrcap_ie(struct ieee80211_node *ni, u_int8_t *ie);
#endif
#if ATH_SUPPORT_CFEND
wbuf_t ieee80211_cfend_alloc(struct ieee80211com *ic);
#endif
/* unalligned little endian access */     
#ifndef LE_READ_1
#define LE_READ_1(p)                            \
    ((u_int8_t)                                 \
    ((((const u_int8_t *)(p))[0]      )))
#endif

#ifndef LE_READ_2
#define LE_READ_2(p)                            \
    ((u_int16_t)                                \
    ((((const u_int8_t *)(p))[0]      ) |       \
    (((const u_int8_t *)(p))[1] <<  8)))
#endif

#ifndef LE_READ_4
#define LE_READ_4(p)                            \
    ((u_int32_t)                                \
    ((((const u_int8_t *)(p))[0]      ) |       \
    (((const u_int8_t *)(p))[1] <<  8) |        \
    (((const u_int8_t *)(p))[2] << 16) |        \
    (((const u_int8_t *)(p))[3] << 24)))
#endif

#ifndef BE_READ_4
#define BE_READ_4(p)                    	\
    ((u_int32_t)                    		\
     ((((const u_int8_t *)(p))[0] << 24) |      \
      (((const u_int8_t *)(p))[1] << 16) |      \
      (((const u_int8_t *)(p))[2] <<  8) |      \
      (((const u_int8_t *)(p))[3]      )))
#endif

__inline static int 
iswpaoui(u_int8_t *frm)
{
    return ((frm[1] > 3) && (LE_READ_4(frm+2) == ((WPA_OUI_TYPE<<24)|WPA_OUI)));
}
__inline static int 
isatheros_extcap_oui(u_int8_t *frm)
{
    return ((frm[1] > 3) && (LE_READ_4(frm+2) == ((ATH_OUI_EXTCAP_TYPE<<24)|ATH_OUI)));
}

__inline static int
isdedicated_cap_oui(u_int8_t *frm)
{
    return ((frm[1] > 3) && (LE_READ_4(frm+2) == ((DEDICATE_OUI_CAP_TYPE<<24)|DDT_OUI)));
}

__inline static int
isbwnss_oui(u_int8_t *frm)
{
    return ((frm[1] > 3) && (LE_READ_4(frm+2) == ((ATH_OUI_BW_NSS_MAP_TYPE<<24)|ATH_OUI)));
}

INLINE static int 
isatherosoui(u_int8_t *frm)
{
    return ((frm[1] > 3) && (LE_READ_4(frm+2) == ((ATH_OUI_TYPE<<24)|ATH_OUI)));
}

#if QCN_IE
INLINE static int
isqcn_oui(u_int8_t *frm)
{
    return ((frm[1] > 4) && (LE_READ_4(frm+2) == ((QCN_OUI_TYPE<<24)|QCA_OUI)));

}
INLINE static int
isfils_req_parm(u_int8_t *frm)
{
    /* For FILS Request Parameters Element ID extension is 0x02 */
    return ((frm[1] > 2) && (LE_READ_1(frm+2) == 0x02));

}
#endif

INLINE static int
isqca_whc_rept_oui(u_int8_t *frm, u_int8_t whc_subtype)
{
    return ((frm[1] > 4) && (LE_READ_4(frm+2) == ((QCA_OUI_WHC_REPT_TYPE<<24)|QCA_OUI)) &&
            (*(frm+6) == whc_subtype));
}

INLINE static int
isqca_whc_oui(u_int8_t *frm, u_int8_t whc_subtype)
{
    return ((frm[1] > 4) && (LE_READ_4(frm+2) == ((QCA_OUI_WHC_TYPE<<24)|QCA_OUI)) &&
            (*(frm+6) == whc_subtype));
}

INLINE static int
is_next_channel_oui(u_int8_t *frm)
{
    return ((frm[1] > 4) && (LE_READ_4(frm+2) == ((QCA_OUI_NC_TYPE<<24)|QCA_OUI)));
}

INLINE static int
iswmeoui(u_int8_t *frm, u_int8_t wme_subtype)
{
    return ((frm[1] > 4) && (LE_READ_4(frm+2) == ((WME_OUI_TYPE<<24)|WME_OUI)) &&
               (*(frm+6) == wme_subtype));
}
INLINE static int
ismbooui(u_int8_t *frm)
{
    return ((frm[1] > 3) && (LE_READ_4(frm+2) == ((MBO_OUI_TYPE<<24)|MBO_OUI)));
}

INLINE static int 
iswmeparam(u_int8_t *frm)
{
    return ((frm[1] > 5) && (LE_READ_4(frm+2) == ((WME_OUI_TYPE<<24)|WME_OUI)) &&
        (*(frm + 6) == WME_PARAM_OUI_SUBTYPE));
}

INLINE static int
isinterop_vht(u_int8_t *frm)
{
    return ((frm[1] > 12) && (BE_READ_4(frm+2) == ((VHT_INTEROP_OUI << 8)|VHT_INTEROP_TYPE)) &&
        ((*(frm + 6) == VHT_INTEROP_OUI_SUBTYPE) || (*(frm + 6) == VHT_INTEROP_OUI_SUBTYPE_VENDORSPEC)));
}


/* STNG TODO: move ieee80211_p2p_proto.h out of umac\p2p directory and into this directory. Then we can
 * include ieee80211_p2p_proto.h file instead of defining here */
#ifndef  IEEE80211_P2P_WFA_OUI
  #define IEEE80211_P2P_WFA_OUI     { 0x50,0x6f,0x9a }
#endif
#ifndef  IEEE80211_P2P_WFA_VER
  #define IEEE80211_P2P_WFA_VER     0x09                 /* ver 1.0 */
#endif
#define IEEE80211_WSC_OUI       { 0x00,0x50,0xF2 }      /* Microsoft WSC OUI bytes */

INLINE static int 
isp2poui(const u_int8_t *frm)
{
    const u_int8_t      wfa_oui[3] = IEEE80211_P2P_WFA_OUI;

    return ((frm[1] >= 4) && 
            (frm[2] == wfa_oui[0]) && 
            (frm[3] == wfa_oui[1]) && 
            (frm[4] == wfa_oui[2]) && 
            (frm[5] == IEEE80211_P2P_WFA_VER));
}

INLINE static int 
iswmeinfo(u_int8_t *frm)
{
    return ((frm[1] > 5) && (LE_READ_4(frm+2) == ((WME_OUI_TYPE<<24)|WME_OUI)) &&
        (*(frm + 6) == WME_INFO_OUI_SUBTYPE));
}
INLINE static int 
iswmetspec(u_int8_t *frm)
{
    return ((frm[1] > 5) && (LE_READ_4(frm+2) == ((WME_OUI_TYPE<<24)|WME_OUI)) &&
        (*(frm + 6) == WME_TSPEC_OUI_SUBTYPE));
}

INLINE static int 
ishtcap(u_int8_t *frm)
{
    return ((frm[1] > 3) && (BE_READ_4(frm+2) == ((VENDOR_HT_OUI<<8)|VENDOR_HT_CAP_ID)));
}

INLINE static int 
iswpsoui(const u_int8_t *frm)
{
    return frm[1] > 3 && BE_READ_4(frm+2) == WSC_OUI;
}


INLINE static int 
ishtinfo(u_int8_t *frm)
{
    return ((frm[1] > 3) && (BE_READ_4(frm+2) == ((VENDOR_HT_OUI<<8)|VENDOR_HT_INFO_ID)));
}

INLINE static int 
isssidl(u_int8_t *frm)
{
    return ((frm[1] > 5) && (LE_READ_4(frm+2) == ((SSIDL_OUI_TYPE<<24)|WPS_OUI)));
}

INLINE static int 
issfaoui(u_int8_t *frm)
{
    return ((frm[1] > 4) && (LE_READ_4(frm+2) == ((SFA_OUI_TYPE<<24)|SFA_OUI)));
}

INLINE static int 
iswcnoui(u_int8_t *frm)
{
    return ((frm[1] > 4) && (LE_READ_4(frm+2) == ((WCN_OUI_TYPE<<24)|WCN_OUI)));
}

int  ieee80211_intersect_extnss_160_80p80(struct ieee80211_node *ni);
u_int32_t  retrieve_seg2_for_extnss_160(u_int32_t *vhtcap, struct ieee80211_ie_vhtop *vhtop, struct ieee80211_ie_htinfo_cmn *htinfo);
u_int8_t extnss_160_validate_and_seg2_indicate(u_int32_t *vhtcap, struct ieee80211_ie_vhtop *vhtop, struct ieee80211_ie_htinfo_cmn *htinfo);
u_int32_t  retrieve_seg2_for_extnss_80p80(u_int32_t *vhtcap, struct ieee80211_ie_vhtop *vhtop, struct ieee80211_ie_htinfo_cmn *htinfo);
u_int8_t extnss_80p80_validate_and_seg2_indicate(u_int32_t *vhtcap, struct ieee80211_ie_vhtop *vhtop, struct ieee80211_ie_htinfo_cmn *htinfo);
bool ext_nss_160_supported(u_int32_t *vhtcap);
bool ext_nss_80p80_supported(u_int32_t *vhtcap);
bool validate_extnss_vhtcap(u_int32_t *vhtcap);
bool peer_ext_nss_capable(struct ieee80211_ie_vhtcap * vhtcap);
#endif /* end of _ATH_STA_IEEE80211_PROTO_H */
