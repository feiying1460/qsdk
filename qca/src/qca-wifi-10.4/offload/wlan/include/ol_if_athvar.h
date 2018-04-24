/*
 * Copyright (c) 2010, Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Defintions for the Atheros Wireless LAN controller driver.
 */
#ifndef _DEV_OL_ATH_ATHVAR_H
#define _DEV_OL_ATH_ATHVAR_H

#include <osdep.h>
#include <a_types.h>
#include <a_osapi.h>
#include "ieee80211_channel.h"
#include "ieee80211_proto.h"
#include "ieee80211_rateset.h"
#include "ieee80211_regdmn.h"
#include "ieee80211_wds.h"
#include "ieee80211_ique.h"
#include "ieee80211_acs.h"
#include "ieee80211_csa.h"
#include "asf_amem.h"
#include "qdf_types.h"
#include "qdf_trace.h"
#include "qdf_lock.h"
#include "qdf_lock.h"
#include "wmi_unified_api.h"
#include "htc_api.h"
#include "bmi_msg.h"
#include "ar_ops.h"
#if WLAN_FEATURE_FASTPATH
#include "ol_htt_api.h"
#endif /* WLAN_FEATURE_FASTPATH */
#include "cdp_txrx_cmn.h"
#include "cdp_txrx_ctrl.h"
#include "cdp_txrx_raw.h"
#include "cdp_txrx_me.h"
#include "cdp_txrx_pflow.h"
#include "cdp_txrx_mon.h"
#include "cdp_txrx_host_stats.h"

#include <pktlog_ac_api.h>
#include "epping_test.h"
#include "wdi_event_api.h"
#include <ieee80211_smart_ant_api.h>
#include "ol_helper.h"
#include "ol_if_thermal.h"
#if PERF_FIND_WDS_NODE
#include "wds_addr.h"
#endif
#if FW_CODE_SIGN
#include <misc/fw_auth.h>
#endif  /* FW_CODE_SIGN */
#if OL_ATH_SUPPORT_LED
#include <linux/gpio.h>
#endif

/* WRAP SKB marks used by the hooks to optimize */
#define WRAP_ATH_MARK              0x8000

#define WRAP_FLOOD                 0x0001  /*don't change see NF_BR_FLOOD netfilter_bridge.h*/
#define WRAP_DROP                  0x0002  /*mark used to drop short circuited pkt*/
#define WRAP_REFLECT               0x0004  /*mark used to identify reflected multicast*/
#define WRAP_ROUTE                 0x0008  /*mark used allow local deliver to the interface*/

#define WRAP_MARK_FLOOD            (WRAP_ATH_MARK | WRAP_FLOOD)
#define WRAP_MARK_DROP             (WRAP_ATH_MARK | WRAP_DROP)
#define WRAP_MARK_REFLECT          (WRAP_ATH_MARK | WRAP_REFLECT)
#define WRAP_MARK_ROUTE            (WRAP_ATH_MARK | WRAP_ROUTE)

#define WRAP_MARK_IS_FLOOD(_mark)  ((_mark & WRAP_ATH_MARK)?((_mark & WRAP_FLOOD)?1:0):0)
#define WRAP_MARK_IS_DROP(_mark)   ((_mark & WRAP_ATH_MARK)?((_mark & WRAP_DROP)?1:0):0)
#define WRAP_MARK_IS_REFLECT(_mark) ((_mark & WRAP_ATH_MARK)?((_mark & WRAP_REFLECT)?1:0):0)
#define WRAP_MARK_IS_ROUTE(_mark)  ((_mark & WRAP_ATH_MARK)?((_mark & WRAP_ROUTE)?1:0):0)

#define EXT_TID_NONPAUSE    19

#define RTT_LOC_CIVIC_INFO_LEN      16
#define RTT_LOC_CIVIC_REPORT_LEN    64

#define MAX_TIM_BITMAP_LENGTH 68 /* Max allowed TIM bitmap for 512 client is 64 + 4  (Gaurd lenght) */

typedef void * hif_handle_t;
typedef void * hif_softc_t;

extern unsigned int low_mem_system;

#if ATH_SUPPORT_DSCP_OVERRIDE
extern A_UINT32 dscp_tid_map[WMI_HOST_DSCP_MAP_MAX];
#endif

struct ath_version {
    u_int32_t    host_ver;
    u_int32_t    target_ver;
    u_int32_t    wlan_ver;
    u_int32_t    wlan_ver_1;
    u_int32_t    abi_ver;
};

typedef enum _ATH_BIN_FILE {
    ATH_OTP_FILE,
    ATH_FIRMWARE_FILE,
    ATH_PATCH_FILE,
    ATH_BOARD_DATA_FILE,
    ATH_FLASH_FILE,
    ATH_TARGET_EEPROM_FILE,
    ATH_UTF_FIRMWARE_FILE,
} ATH_BIN_FILE;

typedef enum _OTP_PARAM {
    PARAM_GET_EEPROM_ALL            = 0,
    PARAM_SKIP_MAC_ADDR             = 1,
    PARAM_SKIP_REG_DOMAIN           = 2,
    PARAM_SKIP_OTPSTREAM_ID_CAL_5G  = 4,
    PARAM_SKIP_OTPSTREAM_ID_CAL_2G  = 8,
    PARAM_GET_CHIPVER_BID           = 0x10,
    PARAM_USE_GOLDENTEMPLATE        = 0x20,
    PARAM_USE_OTP                   = 0x40,
    PARAM_SKIP_EEPROM               = 0x80,
    PARAM_EEPROM_SECTION_MAC        = 0x100,
    PARAM_EEPROM_SECTION_REGDMN     = 0x200,
    PARAM_EEPROM_SECTION_CAL        = 0x400,
    PARAM_OTP_SECTION_MAC           = 0x800,
    PARAM_OTP_SECTION_REGDMN        = 0x1000,
    PARAM_OTP_SECTION_CAL           = 0x2000,
    PARAM_SKIP_OTP                  = 0x4000,
    PARAM_GET_BID_FROM_FLASH        = 0x8000,
    PARAM_FLASH_SECTION_ALL         = 0x10000,
    PARAM_FLASH_ALL                 = 0x20000,
}OTP_PARAM;


typedef enum _ol_target_status  {
     OL_TRGET_STATUS_CONNECTED = 0,    /* target connected */
     OL_TRGET_STATUS_RESET,        /* target got reset */
     OL_TRGET_STATUS_EJECT,        /* target got ejected */
} ol_target_status;

enum ol_ath_tx_ecodes  {
    TX_IN_PKT_INCR=0,
    TX_OUT_HDR_COMPL,
    TX_OUT_PKT_COMPL,
    PKT_ENCAP_FAIL,
    TX_PKT_BAD,
    RX_RCV_MSG_RX_IND,
    RX_RCV_MSG_PEER_MAP,
    RX_RCV_MSG_TYPE_TEST
} ;

enum ol_recovery_option {
    RECOVERY_DISABLE = 0,
    RECOVERY_ENABLE_AUTO,       /* Automatically recover after FW assert */
    RECOVERY_ENABLE_WAIT        /* only do FW RAM dump and wait for user */
} ;

#ifndef ATH_CAP_DCS_CWIM
#define ATH_CAP_DCS_CWIM 0x1
#define ATH_CAP_DCS_WLANIM 0x2
#endif
#define STATS_MAX_RX_CES     12
#define STATS_MAX_RX_CES_PEREGRINE 8
/*
 * structure to hold the packet error count for CE and hif layer
*/
struct ol_ath_stats {
    int hif_pipe_no_resrc_count;
    int ce_ring_delta_fail_count;
    int sw_index[STATS_MAX_RX_CES];
    int write_index[STATS_MAX_RX_CES];
};

struct ol_ath_target_cap {
    target_resource_config     wlan_resource_config; /* default resource config,the os shim can overwrite it */
    /* any other future capabilities of the target go here */

};
/* callback to be called by durin target initialization sequence
 * to pass the target
 * capabilities and target default resource config to os shim.
 * the os shim can change the default resource config (or) the
 * service bit map to enable/disable the services. The change will
 * pushed down to target.
 */
typedef void   (* ol_ath_update_fw_config_cb)\
    (struct ol_ath_softc_net80211 *scn, struct ol_ath_target_cap *tgt_cap);

/*
 * memory chunck allocated by Host to be managed by FW
 * used only for low latency interfaces like pcie
 */
struct ol_ath_mem_chunk {
    u_int32_t *vaddr;
    u_int32_t paddr;
    qdf_dma_mem_context(memctx);
    u_int32_t len;
    u_int32_t req_id;
};
/** dcs wlan wireless lan interfernce mitigation stats */

/*
 * wlan_dcs_im_tgt_stats_t is defined in wmi_unified.h
 * The below stats are sent from target to host every one second.
 * prev_dcs_im_stats - The previous statistics at last known time
 * im_intr_count, number of times the interfernce is seen continuously
 * sample_count - int_intr_count of sample_count, the interference is seen
 */
typedef struct _wlan_dcs_im_host_stats {
	wmi_host_dcs_im_tgt_stats_t prev_dcs_im_stats;
    A_UINT8   im_intr_cnt;              		/* Interefernce detection counter */
    A_UINT8   im_samp_cnt;              		/* sample counter */
} wlan_dcs_im_host_stats_t;

typedef enum {
    DCS_DEBUG_DISABLE=0,
    DCS_DEBUG_CRITICAL=1,
    DCS_DEBUG_VERBOSE=2,
} wlan_dcs_debug_t;

#if ATH_SUPPORT_HYFI_ENHANCEMENTS
struct ol_ath_ald_record {
    u_int32_t               free_descs;
    u_int32_t               pool_size;
    u_int16_t               ald_free_buf_lvl; /* Buffer Full warning threshold */
    u_int                   ald_buffull_wrn;
};
#endif

#define DCS_PHYERR_PENALTY      500
#define DCS_PHYERR_THRESHOLD    300
#define DCS_RADARERR_THRESHOLD 1000
#define DCS_COCH_INTR_THRESHOLD  30 /* 30 % excessive channel utilization */
#define DCS_USER_MAX_CU          50 /* tx channel utilization due to our tx and rx */
#define DCS_INTR_DETECTION_THR    6
#define DCS_SAMPLE_SIZE          10

typedef struct ieee80211_mib_cycle_cnts periodic_chan_stats_t;

typedef struct _wlan_host_dcs_params {
    u_int8_t                dcs_enable; 			/* if dcs enabled or not, along with running state*/
    wlan_dcs_debug_t        dcs_debug;              /* 0-disable, 1-critical, 2-all */
    u_int32_t			    phy_err_penalty;     	/* phy error penalty*/
    u_int32_t			    phy_err_threshold;
    u_int32_t				radar_err_threshold;
    u_int32_t				coch_intr_thresh ;
    u_int32_t				user_max_cu; 			/* tx_cu + rx_cu */
    u_int32_t 				intr_detection_threshold;
    u_int32_t 				intr_detection_window;
    wlan_dcs_im_host_stats_t scn_dcs_im_stats;
    periodic_chan_stats_t   chan_stats;
} wlan_host_dcs_params_t;

#if OL_ATH_SUPPORT_LED
#define PEREGRINE_LED_GPIO    1
#define BEELINER_LED_GPIO    17
#define CASCADE_LED_GPIO     17
#define BESRA_LED_GPIO       17
#define IPQ4019_LED_GPIO     58

enum IPQ4019_LED_TYPE {
    IPQ4019_LED_SOURCE = 1,        /* Wifi LED source select */
    IPQ4019_LED_GPIO_PIN = 2,      /* Wifi LED GPIO */
};

typedef struct ipq4019_wifi_leds {
    uint32_t wifi0_led_gpio;      /* gpio of wifi0 led */
    uint32_t wifi1_led_gpio;      /* gpio of wifi1 led */
} ipq4019_wifi_leds_t;

typedef enum _OL_BLINK_STATE {
    OL_BLINK_DONE = 0,
    OL_BLINK_OFF_START = 1,
    OL_BLINK_ON_START = 2,
    OL_BLINK_STOP = 3,
    OL_NUMER_BLINK_STATE,
} OL_BLINK_STATE;

enum {
    LED_OFF = 0,
    LED_ON
};

typedef enum _OL_LED_EVENT {
    OL_ATH_LED_TX = 0,
    OL_ATH_LED_RX = 1,
    OL_ATH_LED_POLL = 2,
    OL_NUMER_LED_EVENT,
} OL_LED_EVENT;

typedef struct {
    u_int32_t    timeOn;      // LED ON time in ms
    u_int32_t    timeOff;     // LED OFF time in ms
} OL_LED_BLINK_RATES;

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
struct alloc_task_pvt_data {
    wmi_buf_t evt_buf;
    void *scn_handle;
};
#endif

#ifndef AR900B_REV_1
#define AR900B_REV_1 0x0
#endif

#ifndef AR900B_REV_2
#define AR900B_REV_2 0x1
#endif

/*
 *  Error types that needs to be muted as per rate limit
 *  Currently added for pn errors and sequnce errors only.
 *  In future this structure can be exapanded for other errors.
 */
#define DEFAULT_PRINT_RATE_LIMIT_VALUE 100

struct mute_error_types {
    u_int32_t  pn_errors;
    u_int32_t  seq_num_errors;
};

struct debug_config {
    int print_rate_limit; /* rate limit value */
    struct mute_error_types err_types;
};

/*
 * In parallel mode gpio_pin/func[0-4]- is chain[0-4] configuration
 * In serial mode gpio_pin/func[0]- Configuration for data signal
 *                gpio_pin/func[1]- Configuration for strobe signal
 */
struct ol_smart_ant_gpio_conf {
    u_int32_t gpio_pin[WMI_HAL_MAX_SANTENNA]; /* GPIO pin configuration for each chain */
    u_int32_t gpio_func[WMI_HAL_MAX_SANTENNA];/* GPIO function configuration for each chain */
};

struct ol_ath_softc_net80211 {
    struct ieee80211com     sc_ic;      /* NB: base class, must be first */
    ol_pktlog_dev_t 		*pl_dev;    /* Must be second- pktlog handle */
    u_int32_t               sc_prealloc_idmask;   /* preallocated vap id bitmap: can only support 32 vaps */
    u_int32_t               macreq_enabled;     /* user mac request feature enable/disable */
    struct {
        asf_amem_instance_handle handle;
        qdf_spinlock_t        lock;
    } amem;
#if ATH_DEBUG
    unsigned long rtsctsenable;
#endif
    /*
     * handle for code that uses the osdep.h version of OS
     * abstraction primitives
     */
    osdev_t         sc_osdev;
    u_int16_t  device_id;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    int nss_wifiol_id;
    int nss_pktlog_en;
    int nss_wifiol_ce_enabled;
    bool nss_enabled;
    struct {
        struct completion complete;     /* completion structure */
        int response;               /* Response from FW */
    } osif_nss_ol_wifi_cfg_complete;
    uint32_t nss_idx;
    int nss_ifnum;
    void *nss_wifiol_ctx;
    int32_t nss_wifiol_bypass_nw_process;
    uint32_t nss_wifi_ol_mode;
#endif

    /**
     * call back set by the os shim
     */
    ol_ath_update_fw_config_cb cfg_cb;

    /*
     * handle for code that uses adf version of OS
     * abstraction primitives
     */
    qdf_device_t   qdf_dev;

    ar_handle_t arh;

    struct ath_version      version;
    u_int8_t    is_version_match;

    /* Packet statistics */
    struct ol_ath_stats     pkt_stats;

    u_int32_t target_type;  /* A_TARGET_TYPE_* */
    /* Is this chip a derivative of beeliner - Used for common checks that apply to derivates of ar900b */
    bool is_ar900b;
    u_int32_t target_version;
    u_int32_t target_revision; /* release version of the  chip */
    ol_target_status  target_status; /* target status */
    bool             is_sim;   /* is this a simulator */
    bool  is_pci_device_type;  /* to differentiate a pci and a ahb device */
    u_int8_t cal_in_flash; /* calibration data is stored in flash */
    void *cal_mem; /* virtual address for the calibration data on the flash */

#ifdef AH_CAL_IN_FILE_HOST
    u_int8_t cal_in_file; /* calibration data is stored in file on file system */
#endif
#ifdef AH_CAL_IN_FLASH_PCI
    u_int8_t cal_idx; /* index of this radio in the CalAddr array */
#endif
    bool                dbg_log_init;
    bool                wmi_service_ready;
    bool                wmi_ready;
    bool                down_complete;
    atomic_t            reset_in_progress;
    TARGET_INIT_STATUS  wlan_init_status; /* status of target init */

    /* BMI info */
    void            *bmi_ol_priv; /* OS-dependent private info for BMI */
    bool            bmiDone;
    bool            bmiUADone;
    u_int8_t        *pBMICmdBuf;
    dma_addr_t      BMICmd_pa;
    OS_DMA_MEM_CONTEXT(bmicmd_dmacontext)

    u_int8_t        *pBMIRspBuf;
    dma_addr_t      BMIRsp_pa;
    u_int32_t       last_rxlen; /* length of last response */
    OS_DMA_MEM_CONTEXT(bmirsp_dmacontext)

    void            *diag_ol_priv; /* OS-dependent private info for DIAG access */

    /* Handles for Lower Layers : filled in at init time */
    void *hif_hdl;

    uint8_t                 device_index;       // arDeviceIndex from toba.

    /* HTC handles */
    void                    *htc_handle;
    wmi_unified_t           wmi_handle;
    uint8_t                 ps_report;
#if WLAN_FEATURE_FASTPATH
    htt_pdev_handle         htt_pdev;
#endif /* WLAN_FEATURE_FASTPATH */

    /* ol data path handle */
    ol_txrx_pdev_handle     pdev_txrx_handle;

    /* target resource config */
    target_resource_config  wlan_resource_config;
    target_resource_config     dbg_resource_config;
    wmi_host_ext_resource_config wlan_ext_resource_config;
    /* UMAC callback functions */
    void                    (*net80211_node_cleanup)(struct ieee80211_node *);
    void                    (*net80211_node_free)(struct ieee80211_node *);

    void		    (*pci_reconnect)(struct ol_ath_softc_net80211 *);

    A_UINT32                phy_capability; /* PHY Capability from Target*/
	A_UINT32                max_frag_entry; /* Max number of Fragment entry */

    /* UTF event information */
    struct {
        u_int8_t            *data;
        u_int32_t           length;
        u_int16_t           offset;
        u_int8_t            currentSeq;
        u_int8_t            expectedSeq;
    } utf_event_info;

    struct ol_wow_info      *scn_wowInfo;

    bool                    host_80211_enable; /* Enables native-wifi mode on host */
    bool                    nss_nwifi_offload; /* decap of NWIFI to 802.3 is offloaded to NSS */

    bool                    enableuartprint;    /* enable uart/serial prints from target */
#if defined(EPPING_TEST) && !defined(HIF_USB)
    /* for mboxping */
    HTC_ENDPOINT_ID         EppingEndpoint[4];
    qdf_spinlock_t       data_lock;
    struct sk_buff_head     epping_nodrop_queue;
    struct timer_list       epping_timer;
    bool                    epping_timer_running;
#endif
    u_int8_t                is_target_paused;
    TARGET_HAL_REG_CAPABILITIES hal_reg_capabilities;
    struct ol_regdmn *ol_regdmn_handle;
    u_int8_t                bcn_mode;
    u_int8_t                burst_enable;
    u_int8_t                cca_threshold;
#if ATH_SUPPORT_WRAP
    u_int8_t                mcast_bcast_echo;
    bool                    qwrap_enable;    /* enable/disable qwrap target config  */
#endif
    u_int8_t                dyngroup;
    u_int16_t               burst_dur;
    u_int8_t                arp_override;
    u_int8_t                igmpmld_override;
    u_int8_t                igmpmld_tid;
    struct ieee80211_mib_cycle_cnts  mib_cycle_cnts;  /* used for channel utilization for ol model */
    /*
     * Includes host side stack level stats +
     * radio level athstats
     */
    struct wlan_dbg_stats   ath_stats;

    int                     tx_rx_time_info_flag;

    /* This structure is used to update the radio level stats, the stats
        are directly fetched from the descriptors
    */
    struct ol_ath_radiostats     scn_stats;
    struct ieee80211_chan_stats chan_stats;     /* Used for channel radio-level stats */
    qdf_semaphore_t         scn_stats_sem;
    int16_t                 chan_nf;            /* noise_floor */
    u_int32_t               min_tx_power;
    u_int32_t               max_tx_power;
    u_int32_t               txpowlimit2G;
    u_int32_t               txpowlimit5G;
    u_int32_t               txpower_scale;
    u_int32_t               powerscale; /* reduce the final tx power */
    u_int32_t               chan_tx_pwr;
    u_int32_t               special_ap_vap; /*ap_monitor mode*/
    u_int32_t               smart_ap_monitor; /*smart ap monitor mode*/
    u_int32_t               vdev_count;
    u_int32_t               mon_vdev_count;
    qdf_atomic_t         peer_count;
    qdf_spinlock_t       scn_lock;

    u_int32_t               vow_config;

    u_int8_t                vow_extstats;
    u_int32_t               max_peers;
    u_int32_t               max_active_peers;	/* max active peers derived from max_descs */
    u_int32_t               max_vdevs;
    u_int32_t               max_descs;		/* max descs configured through module param */
    u_int32_t               max_clients;
    u_int32_t               max_vaps;

    /** DCS configuration and running state */
	wlan_host_dcs_params_t   scn_dcs;
    wdi_event_subscribe     scn_rx_peer_invalid_subscriber;
    u_int32_t               dtcs; /* Dynamic Tx Chainmask Selection enabled/disabled */
    u_int32_t               set_ht_vht_ies:1, /* true if vht ies are set on target */
                            sc_in_delete:1;   /* don't add any more VAPs */
    u_int32_t               sw_cal_support_check_flag:1; /* Added to check Cal MAC check support from FW */
#if PERF_FIND_WDS_NODE
    struct wds_table        scn_wds_table;
#endif
    u_int32_t               num_mem_chunks;
    struct wmi_host_mem_chunk mem_chunks[MAX_MEM_CHUNKS];
    bool                    scn_cwmenable;    /*CWM enable/disable state*/
    bool                    is_ani_enable;    /*ANI enable/diable state*/
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
	struct ol_ath_ald_record  buff_thresh;
#endif
#if ATH_RX_LOOPLIMIT_TIMER
    qdf_timer_t          rx_looplimit_timer;
    u_int32_t               rx_looplimit_timeout;        /* timeout intval */
    bool                    rx_looplimit_valid;
    bool                    rx_looplimit;
#endif
#if ATH_SUPPORT_SPECTRAL
    u_int8_t                scn_icm_active;  /* Whether Intelligent Channel Manager
                                                is active. */
#endif
    u_int32_t               peer_ext_stats_count;
#if ATH_SUPPORT_WRAP
    int                     sc_nwrapvaps; /* # of WRAP vaps */
    int                     sc_npstavaps; /* # of ProxySTA vaps */
    int                     sc_nscanpsta; /* # of scan-able non-Main ProxySTA vaps */
    qdf_spinlock_t       sc_mpsta_vap_lock; /* mpsta vap lock */
    struct ieee80211vap     *sc_mcast_recv_vap; /* the ProxySTA vap to receive multicast frames */
#endif
    int                     sc_chan_freq;           /* channel change freq in mhz */
    int                     sc_chan_band_center_f1; /* channel change band center freq in mhz */
    int                     sc_chan_band_center_f2; /* channel change band center freq in mhz */
    int                     sc_chan_phy_mode;    /* channel change PHY mode */
    int                     recovery_enable;	 /* enable/disable target recovery feature */
    //For Mcast
#if ATH_SUPPORT_IQUE && ATH_SUPPORT_ME_FW_BASED
    u_int16_t               pend_desc_removal;
    u_int16_t               pend_desc_addition;
#endif /*ATH_SUPPORT_IQUE && ATH_SUPPORT_ME_FW_BASE*/
#if OL_ATH_SUPPORT_LED
    os_timer_t                      scn_led_blink_timer;     /* led blinking timer */
    os_timer_t                      scn_led_poll_timer;     /* led polling timer */
    OL_BLINK_STATE                scn_blinking; /* LED blink operation active */
    u_int32_t               scn_led_time_on;  /* LED ON time for current blink in ms */
    u_int32_t               scn_led_byte_cnt;
    u_int32_t               scn_led_last_time;
    u_int32_t               scn_led_max_blink_rate_idx;
    u_int8_t                scn_led_gpio;
    const OL_LED_BLINK_RATES  *scn_led_blink_rate_table;   /* blinking rate table to be used */
#endif
    u_int32_t               sa_validate_sw; /* validate Smart Antenna Software */
    u_int32_t               enable_smart_antenna; /* enable smart antenna */
    struct ol_ath_cookie    scn_cookie; /*To manage WMI communication with Target per radio basis */
    u_int32_t               ol_rts_cts_rate;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
/* Workqueue to alloc dma memory in process context */
    qdf_workqueue_t *alloc_task_wqueue;
    qdf_work_t alloc_task;
#endif

    int                     sc_nstavaps;
    bool                    sc_is_blockdfs_set;
#if WDI_EVENT_ENABLE
    u_int32_t               scn_last_peer_invalid_time;  /*Time interval since last invalid was sent */
    u_int32_t               scn_peer_invalid_cnt;      /* number of permissible dauth in interval */
    u_int32_t               scn_user_peer_invalid_cnt; /* configurable by user  */
#endif
    u_int32_t               fwsuspendfailed;
    u_int32_t               aggr_burst_dur[WME_AC_VO+1]; /* maximum VO */
    bool                    scn_qboost_enable;    /*Qboost enable/disable state*/
    u_int32_t               scn_sifs_frmtype;    /*SIFS RESP enable/disable state*/
    u_int32_t               scn_sifs_uapsd;    /*SIFS RESP UAPSD enable/disable state*/
    bool                    scn_block_interbss;  /* block interbss traffic */
    u_int8_t                fw_disable_reset;
    u_int16_t               txbf_sound_period;
    bool                    scn_promisc;            /* Set or clear promisc mode */
    atomic_t                sc_dev_enabled;    /* dev is enabled */
    struct thermal_param    thermal_param;
#if UNIFIED_SMARTANTENNA
    wdi_event_subscribe sa_event_sub;
#endif
#if QCA_AIRTIME_FAIRNESS
    uint8_t     atf_strict_sched;
#endif
    u_int32_t               sc_dump_opts;       /* fw dump collection options*/
    struct work_struct 	    pci_reconnect_work;
    u_int8_t                dpdenable;
    int8_t                  sc_noise_floor_th; /* signal noise floor in dBm used in ch hoping */
    u_int16_t               sc_noise_floor_report_iter; /* #of iteration noise is higher then threshold */
    u_int16_t               sc_noise_floor_total_iter;/* total # of iteration */
    u_int8_t                sc_enable_noise_detection; /* Enable/Disable noise detection due to channel hopping in acs */
    u_int8_t                scn_mgmt_retry_limit; /*Management retry limit*/
    u_int16_t               scn_amsdu_mask;
    u_int16_t               scn_ampdu_mask;
#if ATH_SUPPORT_CODESWAP
   struct swap_seg_info     *target_otp_codeswap_seginfo ;     /* otp codeswap seginfo */
   struct swap_seg_info     *target_otp_dataswap_seginfo ;     /* otp dataswap seginfo */
   struct swap_seg_info     *target_bin_codeswap_seginfo ;     /* target bin codeswap seginfo */
   struct swap_seg_info     *target_bin_dataswap_seginfo ;     /* target bin dataswap seginfo */
   struct swap_seg_info     *target_bin_utf_codeswap_seginfo ; /* target utf bin codeswap seginfo */
   struct swap_seg_info     *target_bin_utf_dataswap_seginfo ; /* target utf bin dataswap seginfo */
   u_int64_t                *target_otp_codeswap_cpuaddr;      /* otp codeswap cpu addr */
   u_int64_t                *target_otp_dataswap_cpuaddr;      /* otp dataswap cpu addr */
   u_int64_t                *target_bin_codeswap_cpuaddr;      /* target bin codeswap cpu addr */
   u_int64_t                *target_bin_dataswap_cpuaddr;      /* target bin dataswap cpu addr */
   u_int64_t                *target_bin_utf_codeswap_cpuaddr;  /* target utf bin codeswap cpu addr */
   u_int64_t                *target_bin_utf_dataswap_cpuaddr;  /* target utf bin dataswap cpu addr */
#endif
   void *nbuf;
   void *nbuf1;
   struct debug_config      dbg;   /* debug support */
#if ATH_PROXY_NOACK_WAR
   bool sc_proxy_noack_war;
#endif
   u_int32_t                sc_arp_dbg_srcaddr;  /* ip address to monitor ARP */
   u_int32_t                sc_arp_dbg_dstaddr;  /* ip address to monitor ARP */
   u_int32_t                sc_arp_dbg_conf;   /* arp debug conf */
   u_int32_t                sc_tx_arp_req_count; /* tx arp request counters */
   u_int32_t                sc_rx_arp_req_count; /* rx arp request counters  */
   u_int32_t                sc_tx_arp_resp_count; /* tx arp response counters  */
   u_int32_t                sc_rx_arp_resp_count; /* rx arp response counters  */

   qdf_mempool_t mempool_ol_ath_node; /* Memory pool for nodes */
   qdf_mempool_t mempool_ol_ath_vap;  /* Memory pool for vaps */
   qdf_mempool_t mempool_ol_ath_peer; /* Memory pool for peer entry */
   qdf_mempool_t mempool_ol_rx_reorder_buf; /*  Memory pool for reorder buffers */
   bool      hybrid_mode;
   bool      periodic_chan_stats;
#if WMI_RECORDING
   struct proc_dir_entry *wmi_proc_entry;
#endif
#if ATH_DATA_TX_INFO_EN
    struct ieee80211_tx_status   *tx_status_buf;  /*per-msdu tx status info*/
    u_int32_t               enable_perpkt_txstats;
#endif
#if QCA_LTEU_SUPPORT
   u_int32_t                lteu_support;         /* LTEu support enabled/disabled */
#endif
   int                      btcoex_support;       /* btcoex HW/FW support */
   int                      btcoex_enable;        /* btcoex enable/disable */
   int                      btcoex_wl_priority;   /* btcoex WL priority */
   int                      btcoex_duration;      /* wlan duration for btcoex */
   int                      btcoex_period;        /* sum of wlan and bt duration */
   int                      btcoex_gpio;          /* btcoex gpio pin # for WL priority */
   int                      btcoex_duty_cycle;    /* FW capability for btcoex duty cycle */
   int                      coex_version;         /* coex version */
   int                      coex_gpio_pin_1;      /* coex gpio pin 1 */
   int                      coex_gpio_pin_2;      /* coex gpio pin 2 */
   int                      coex_gpio_pin_3;      /* coex gpio pin 3 */
   int                      coex_ss_priority;     /* coex subsystem priorities */
   int8_t                   band_filter_switch_support; /* band_filter_switch HW/FW support */
   u_int32_t                band_filter_switch_gpio;    /* bandfilter swicth gpio */
   u_int32_t                board_id;
   u_int32_t                chipid;
   u_int32_t                radio_id;
   struct ol_smart_ant_gpio_conf sa_gpio_conf; /* GPIO configuration */
   int16_t                  chan_nf_sec80;            /* noise_floor secondary 80 */
   uint16_t              radio_attached;
   uint32_t                 user_config_val;
   uint32_t                 soft_chain;
   bool                  invalid_vht160_info; /* is set when wireless modes and VHT cap's mismatch */
   struct targetdef_s *targetdef;
   uint32_t wifi_num;
   void			*pdevid;
};
#define OL_ATH_DCS_ENABLE(__arg1, val) ((__arg1) |= (val))
#define OL_ATH_DCS_DISABLE(__arg1, val) ((__arg1) &= ~(val))
#define OL_ATH_DCS_SET_RUNSTATE(__arg1) ((__arg1) |= 0x10)
#define OL_ATH_DCS_CLR_RUNSTATE(__arg1) ((__arg1) &= ~0x10)
#define OL_IS_DCS_ENABLED(__arg1) ((__arg1) & 0x0f)
#define OL_IS_DCS_RUNNING(__arg1) ((__arg1) & 0x10)
#define OL_ATH_CAP_DCS_CWIM     0x1
#define OL_ATH_CAP_DCS_WLANIM   0x2
#define OL_ATH_CAP_DCS_MASK  (OL_ATH_CAP_DCS_CWIM | OL_ATH_CAP_DCS_WLANIM)

#define ol_scn_host_80211_enable_get(_ol_pdev_hdl) \
    ((struct ol_ath_softc_net80211 *)(_ol_pdev_hdl))->host_80211_enable

#define ol_scn_nss_nwifi_offload_get(_ol_pdev_hdl) \
    ((struct ol_ath_softc_net80211 *)(_ol_pdev_hdl))->nss_nwifi_offload

#define ol_scn_target_revision(_ol_pdev_hdl) \
    (((struct ol_ath_softc_net80211 *)(_ol_pdev_hdl))->target_revision)

#define OL_ATH_SOFTC_NET80211(_ic)     ((struct ol_ath_softc_net80211 *)(_ic))

struct bcn_buf_entry {
    A_BOOL                        is_dma_mapped;
    wbuf_t                        bcn_buf;
    TAILQ_ENTRY(bcn_buf_entry)    deferred_bcn_list_elem;
};

struct ol_ath_vap_net80211 {
    struct ieee80211vap             av_vap;     /* NB: base class, must be first */
    struct ol_ath_softc_net80211    *av_sc;     /* back pointer to softc */
    ol_txrx_vdev_handle             av_txrx_handle;    /* ol data path handle */
    int                             av_if_id;   /* interface id */
    u_int64_t                       av_tsfadjust;       /* Adjusted TSF, host endian */
    bool                            av_beacon_offload;  /* Handle beacons in FW */
    wbuf_t                          av_wbuf;            /* Beacon buffer */
    A_BOOL                          is_dma_mapped;
    struct ieee80211_bcn_prb_info   av_bcn_prb_templ;   /* Beacon probe template */
    struct ieee80211_beacon_offsets av_beacon_offsets;  /* beacon fields offsets */
    bool                            av_ol_resmgr_wait;  /* UMAC waits for target */
                                                        /*   event to bringup vap*/
    qdf_spinlock_t               avn_lock;
    TAILQ_HEAD(, bcn_buf_entry)     deferred_bcn_list;  /* List of deferred bcn buffers */
    struct ieee80211_channel        *av_ol_resmgr_chan;  /* Channel ptr configured in the target*/
#if ATH_SUPPORT_WRAP
    u_int32_t                   av_is_psta:1,   /* is ProxySTA VAP */
                                av_is_mpsta:1,  /* is Main ProxySTA VAP */
                                av_is_wrap:1,   /* is WRAP VAP */
                                av_use_mat:1;   /* use MAT for this VAP */
    u_int8_t                    av_mat_addr[IEEE80211_ADDR_LEN];    /* MAT addr */
#endif
    bool                        av_restart_in_progress; /* vdev restart in progress */
    wmi_host_vdev_stats  vdev_stats;
    wmi_host_vdev_extd_stats  vdev_extd_stats;
};
#define OL_ATH_VAP_NET80211(_vap)      ((struct ol_ath_vap_net80211 *)(_vap))

struct ol_ath_node_net80211 {
    struct ieee80211_node       an_node;     /* NB: base class, must be first */
    ol_txrx_peer_handle         an_txrx_handle;    /* ol data path handle */
    u_int32_t                   an_ni_rx_rate;
    u_int32_t                   an_ni_tx_rate;
    u_int8_t                    an_ni_tx_ratecode;
    u_int8_t                    an_ni_tx_flags;
    u_int8_t                    an_ni_tx_power;
#if QCA_AIRTIME_FAIRNESS
    u_int16_t                   an_ni_atf_token_allocated;
    u_int16_t                   an_ni_atf_token_utilized;
#endif
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
	u_int32_t					an_tx_rates_used;
	u_int32_t					an_tx_cnt;
	u_int32_t					an_phy_err_cnt;
	u_int32_t					an_tx_bytes;
	u_int32_t					an_tx_ratecount;
#endif
};

#define OL_ATH_NODE_NET80211(_ni)      ((struct ol_ath_node_net80211 *)(_ni))

void ol_target_failure(void *instance, QDF_STATUS status);

void qboost_config(struct ieee80211vap *vap, struct ieee80211_node *ni, bool qboost_cfg);

int ol_ath_attach(u_int16_t devid, struct ol_ath_softc_net80211 *scn, IEEE80211_REG_PARAMETERS *ieee80211_conf_parm, ol_ath_update_fw_config_cb cb);

int ol_asf_adf_attach(struct ol_ath_softc_net80211 *scn);

int ol_asf_adf_detach(struct ol_ath_softc_net80211 *scn);

void ieee80211_mucap_vattach(struct ieee80211vap *vap);
void ieee80211_mucap_vdetach(struct ieee80211vap *vap);


void ol_ath_target_status_update(struct ol_ath_softc_net80211 *scn, ol_target_status status);


int ol_ath_detach(struct ol_ath_softc_net80211 *scn, int force);

void ol_ath_utf_detach(struct ol_ath_softc_net80211 *scn);
#ifdef QVIT
void ol_ath_qvit_detach(struct ol_ath_softc_net80211 *scn);
void ol_ath_qvit_attach(struct ol_ath_softc_net80211 *scn);
#endif

#if ATH_SUPPORT_WIFIPOS
extern unsigned int wifiposenable;

int ol_ieee80211_wifipos_xmitprobe (struct ieee80211vap *vap,
                                        ieee80211_wifipos_reqdata_t *reqdata);
int ol_ieee80211_wifipos_xmitrtt3 (struct ieee80211vap *vap, u_int8_t *mac_addr,
                                        int extra);
void ol_ath_rtt_keepalive_req(struct ieee80211vap *vap,
                         struct ieee80211_node *ni, bool stop);

int ol_ieee80211_lci_set (struct ieee80211vap *vap, void *reqdata);
int ol_ieee80211_lcr_set (struct ieee80211vap *vap, void *reqdata);

#endif
void ol_ath_suspend_resume_attach(struct ol_ath_softc_net80211 *scn);

int ol_ath_resume(struct ol_ath_softc_net80211 *scn);
int ol_ath_suspend(struct ol_ath_softc_net80211 *scn);

void ol_ath_vap_attach(struct ieee80211com *ic);

int ol_ath_cwm_attach(struct ol_ath_softc_net80211 *scn);

struct ieee80211vap *ol_ath_vap_get(struct ol_ath_softc_net80211 *scn, u_int8_t vdev_id);
struct ieee80211vap *ol_ath_getvap(struct ol_txrx_vdev_t *vdev);
u_int8_t *ol_ath_vap_get_myaddr(struct ol_ath_softc_net80211 *scn, u_int8_t vdev_id);

void ol_ath_beacon_attach(struct ieee80211com *ic);

int ol_ath_node_attach(struct ol_ath_softc_net80211 *scn, struct ieee80211com *ic);

void ol_ath_resmgr_attach(struct ieee80211com *ic);

void ol_ath_scan_attach(struct ieee80211com *ic);
#if ATH_SUPPORT_WIFIPOS
void ol_ath_rtt_meas_report_attach(struct ieee80211com *ic);
void ol_ath_rtt_netlink_attach(struct ieee80211com *ic);
void ol_if_rtt_detach(struct ieee80211com *ic);
#endif
#if ATH_SUPPORT_LOWI
void ol_ath_lowi_wmi_event_attach(struct ieee80211com *ic);
#endif

#if QCA_AIRTIME_FAIRNESS
int ol_ath_set_atf(struct ieee80211com *ic);
int ol_ath_send_atf_peer_request(struct ieee80211com *ic);
int ol_ath_set_atf_grouping(struct ieee80211com *ic);
int ol_ath_set_bwf(struct ieee80211com *ic);
#endif

void ol_chan_stats_event (struct ieee80211com *ic,
         periodic_chan_stats_t *pstats, periodic_chan_stats_t *nstats);

int ol_ath_invalidate_channel_stats(struct ieee80211com *ic);

int ol_ath_periodic_chan_stats_config(ol_scn_t scn,
        bool enable, u_int32_t stats_period);

void ol_ath_power_attach(struct ieee80211com *ic);

int ol_scan_update_channel_list(ieee80211_scanner_t ss);

struct ieee80211_channel *
ol_ath_find_full_channel(struct ieee80211com *ic, u_int32_t freq);

void ol_ath_utf_attach(struct ol_ath_softc_net80211 *scn);

int ol_ath_vap_send_data(struct ieee80211vap *vap, wbuf_t wbuf);

void ol_ath_vap_send_hdr_complete(void *ctx, HTC_PACKET_QUEUE *htc_pkt_list);


void ol_rx_indicate(void *ctx, wbuf_t wbuf);

void ol_rx_handler(void *ctx, HTC_PACKET *htc_packet);

enum ol_rx_err_type {
    OL_RX_ERR_DEFRAG_MIC,
    OL_RX_ERR_PN,
    OL_RX_ERR_UNKNOWN_PEER,
    OL_RX_ERR_MALFORMED,
    OL_RX_ERR_TKIP_MIC,
};

/**
 * @brief Provide notification of failure during host rx processing
 * @details
 *  Indicate an error during host rx data processing, including what
 *  kind of error happened, when it happened, which peer and TID the
 *  erroneous rx frame is from, and what the erroneous rx frame itself
 *  is.
 *
 * @param vdev_id - ID of the virtual device received the erroneous rx frame
 * @param peer_mac_addr - MAC address of the peer that sent the erroneous
 *      rx frame
 * @param tid - which TID within the peer sent the erroneous rx frame
 * @param tsf32  - the timstamp in TSF units of the erroneous rx frame, or
 *      one of the fragments that when reassembled, constitute the rx frame
 * @param err_type - what kind of error occurred
 * @param rx_frame - the rx frame that had an error
 */
void
ol_rx_err(
    ol_pdev_handle pdev,
    u_int8_t vdev_id,
    u_int8_t *peer_mac_addr,
    int tid,
    u_int32_t tsf32,
    enum ol_rx_err_type err_type,
    qdf_nbuf_t rx_frame);


enum ol_rx_notify_type {
    OL_RX_NOTIFY_IPV4_IGMP,
};


/**
 * @brief Provide notification of reception of data of special interest.
 * @details
 *  Indicate when "special" data has been received.  The nature of the
 *  data that results in it being considered special is specified in the
 *  notify_type argument.
 *  This function is currently used by the data-path SW to notify the
 *  control path SW when the following types of rx data are received:
 *    + IPv4 IGMP frames
 *      The control SW can use these to learn about multicast group
 *      membership, if it so chooses.
 *
 * @param pdev - handle to the ctrl SW's physical device object
 * @param vdev_id - ID of the virtual device received the special data
 * @param peer_mac_addr - MAC address of the peer that sent the special data
 * @param tid - which TID within the peer sent the special data
 * @param tsf32  - the timstamp in TSF units of the special data
 * @param notify_type - what kind of special data was received
 * @param rx_frame - the rx frame containing the special data
 */
int
ol_rx_notify(
    ol_pdev_handle pdev,
    u_int8_t vdev_id,
    u_int8_t *peer_mac_addr,
    int tid,
    u_int32_t tsf32,
    enum ol_rx_notify_type notify_type,
    qdf_nbuf_t rx_frame);



void ol_ath_mgmt_attach(struct ieee80211com *ic);

int ol_ath_tx_mgmt_send(struct ieee80211com *ic, wbuf_t wbuf);

void ol_ath_beacon_alloc(struct ieee80211com *ic, int if_id);

void ol_ath_beacon_stop(struct ol_ath_softc_net80211 *scn,
                   struct ol_ath_vap_net80211 *avn);

void ol_ath_beacon_free(struct ieee80211com *ic, int if_id);

void ol_ath_net80211_newassoc(struct ieee80211_node *ni, int isnew);

void ol_ath_phyerr_attach(struct ieee80211com *ic);
void ol_ath_phyerr_detach(struct ieee80211com *ic);
void ol_ath_phyerr_enable(struct ieee80211com *ic);
void ol_ath_phyerr_disable(struct ieee80211com *ic);

void ol_ath_vap_tx_lock(void *ptr);
void ol_ath_vap_tx_unlock(void *ptr);

int
ol_transfer_target_eeprom_caldata(struct ol_ath_softc_net80211 *scn, u_int32_t address, bool compressed);

int
ol_transfer_bin_file(struct ol_ath_softc_net80211 *scn, ATH_BIN_FILE file,
                    u_int32_t address, bool compressed);

int
__ol_ath_check_wmi_ready(struct ol_ath_softc_net80211 *scn);

void
__ol_ath_wmi_ready_event(struct ol_ath_softc_net80211 *scn);

void __ol_target_paused_event(struct ol_ath_softc_net80211 *scn);

u_int32_t host_interest_item_address(u_int32_t target_type, u_int32_t item_offset);

int
ol_ath_set_config_param(struct ol_ath_softc_net80211 *scn,
        ol_ath_param_t param, void *buff, bool *restart_vaps);

int
ol_ath_get_config_param(struct ol_ath_softc_net80211 *scn, ol_ath_param_t param, void *buff);

int
ol_hal_set_config_param(struct ol_ath_softc_net80211 *scn, ol_hal_param_t param, void *buff);

int
ol_hal_get_config_param(struct ol_ath_softc_net80211 *scn, ol_hal_param_t param, void *buff);

int
ol_net80211_set_mu_whtlist(wlan_if_t vap, u_int8_t *macaddr, u_int16_t tidmask);

uint32_t ol_get_phymode_info(uint32_t chan_mode);
unsigned int ol_ath_bmi_user_agent_init(struct ol_ath_softc_net80211 *scn);
int ol_ath_wait_for_bmi_user_agent(struct ol_ath_softc_net80211 *scn);
void ol_ath_signal_bmi_user_agent_done(struct ol_ath_softc_net80211 *scn);

void ol_ath_diag_user_agent_init(struct ol_ath_softc_net80211 *scn);
void ol_ath_diag_user_agent_fini(struct ol_ath_softc_net80211 *scn);
void ol_ath_host_config_update(struct ol_ath_softc_net80211 *scn);

void ol_ath_suspend_resume_attach(struct ol_ath_softc_net80211 *scn);
int ol_ath_suspend_target(struct ol_ath_softc_net80211 *scn, int disable_target_intr);
int ol_ath_resume_target(struct ol_ath_softc_net80211 *scn);
u_int ol_ath_mhz2ieee(struct ieee80211com *ic, u_int freq, u_int flags);
void ol_ath_set_ht_vht_ies(struct ieee80211_node *ni);

int ol_print_scan_config(wlan_if_t vaphandle, struct seq_file *m);

int wmi_unified_set_ap_ps_param(struct ol_ath_vap_net80211 *avn,
        struct ol_ath_node_net80211 *anode, A_UINT32 param, A_UINT32 value);
int wmi_unified_set_sta_ps_param(struct ol_ath_vap_net80211 *avn,
        A_UINT32 param, A_UINT32 value);

int ol_ath_wmi_send_vdev_param(struct ol_ath_softc_net80211 *scn, uint8_t if_id,
        uint32_t param_id, uint32_t param_value);
int ol_ath_wmi_send_sifs_trigger(struct ol_ath_softc_net80211 *scn, uint8_t if_id,
        uint32_t param_value);
int ol_ath_pdev_set_param(struct ol_ath_softc_net80211 *scn,
                    uint32_t param_id, uint32_t param_value, uint8_t pdev_id);
int
ol_ath_send_peer_assoc(struct ol_ath_softc_net80211 *scn, struct ieee80211com *ic,
                            struct ieee80211_node *ni, int isnew );
#if 0
int wmi_unified_pdev_get_tpc_config(wmi_unified_t wmi_handle, u_int32_t param);
int wmi_unified_pdev_caldata_version_check_cmd(wmi_unified_t wmi_handle, u_int32_t param);
#endif
int ol_ath_set_fw_hang(struct ol_ath_softc_net80211 *scn, u_int32_t delay_time_ms);
int peer_sta_kickout(struct ol_ath_softc_net80211 *scn, A_UINT8 *peer_macaddr);
int ol_ath_set_beacon_filter(wlan_if_t vap, u_int32_t *ie);
int ol_ath_remove_beacon_filter(wlan_if_t vap);
void ol_get_wlan_dbg_stats(struct ol_ath_softc_net80211 *scn, struct wlan_dbg_stats *dbg_stats);
int
ol_get_tx_free_desc(struct ol_ath_softc_net80211 *scn);
void ol_get_radio_stats(struct ol_ath_softc_net80211 *scn, struct ol_ath_radiostats *stats);
int
wmi_txpower_beacon(struct ol_ath_softc_net80211 *scn, u_int8_t tx_power,
                   struct ol_txrx_pdev_t *pdev);
#if 0
int
wmi_send_node_rate_sched(struct ol_ath_softc_net80211 *scn,
        wmi_peer_rate_retry_sched_cmd *cmd_buf);

int
wmi_unified_peer_flush_tids_send(wmi_unified_t wmi_handle,
                                 u_int8_t peer_addr[IEEE80211_ADDR_LEN],
                                 u_int32_t peer_tid_bitmap,
                                 u_int32_t vdev_id);
#endif
int
ol_ath_node_set_param(struct ol_ath_softc_net80211 *scn, u_int8_t *peer_addr,u_int32_t param_id,
        u_int32_t param_val,u_int32_t vdev_id);
#if UNIFIED_SMARTANTENNA
int ol_ath_smart_ant_rxfeedback(struct ol_txrx_pdev_t *pdev, struct ol_txrx_peer_t *peer, struct sa_rx_feedback *rx_feedback);
int ol_smart_ant_enabled(struct ol_ath_softc_net80211 *scn);
int ol_smart_ant_rx_feedback_enabled(struct ol_ath_softc_net80211 *scn);
#endif /* UNIFIED_SMARTANTENNA */
#if QCA_LTEU_SUPPORT
void ol_ath_nl_attach(struct ieee80211com *ic);
void ol_ath_nl_detach(struct ieee80211com *ic);
#endif

int
ol_gpio_config(struct ol_ath_softc_net80211 *scn, u_int32_t gpio_num, u_int32_t input,
                        u_int32_t pull_type, u_int32_t intr_mode);
int
ol_ath_gpio_output(struct ol_ath_softc_net80211 *scn, u_int32_t gpio_num, u_int32_t set);

#define DEFAULT_PERIOD  100         /* msec */
#define DEFAULT_WLAN_DURATION   80  /* msec */
#define COEX_VERSION_1  1           /* 3 wire coex */
#define COEX_VERSION_2  2           /* 2.5 wire coex */
#define COEX_VERSION_3  3           /* 2.5 wire coex+duty cycle */
#define COEX_VERSION_4  4           /* 4 wire coex */
int
ol_ath_btcoex_duty_cycle(struct ol_ath_softc_net80211 *scn,u_int32_t period, u_int32_t duration);
int
ol_ath_btcoex_wlan_priority(struct ol_ath_softc_net80211 *scn, u_int32_t val);
int
ol_ath_coex_ver_cfg(struct ol_ath_softc_net80211 *scn, void *cfg);

int ol_ath_packet_power_info_get(struct ol_ath_softc_net80211 *scn, u_int16_t rate_flags, u_int16_t nss, u_int16_t preamble, u_int16_t hw_rate);
#if 0
int ol_ath_nf_dbr_dbm_info_get(struct ol_ath_softc_net80211 *scn);

int
wmi_unified_pdev_fips(struct ol_ath_softc_net80211 *scn,
                      u_int8_t *key,
                      u_int32_t key_len,
                      u_int8_t *data,
                      u_int32_t data_len,
        		      u_int32_t mode,
                      u_int32_t op);
#endif
int
ieee80211_extended_ioctl_chan_switch (struct net_device *dev,
                     struct ieee80211com *ic, caddr_t *param);
int
ieee80211_extended_ioctl_chan_scan (struct net_device *dev,
                struct ieee80211com *ic, caddr_t *param);

int
ieee80211_extended_ioctl_rep_move (struct net_device *dev,
                struct ieee80211com *ic, caddr_t *param);

#if ATH_PROXY_NOACK_WAR
int32_t ol_ioctl_get_proxy_noack_war(struct ol_ath_softc_net80211 *scn, caddr_t param);
int32_t ol_ioctl_reserve_proxy_macaddr (struct ol_ath_softc_net80211 *scn, caddr_t *param);
int ol_ath_pdev_proxy_ast_reserve_event_handler (ol_scn_t scn, u_int8_t *data, u_int16_t datalen);
#endif
#if ATH_SUPPORT_WRAP && DBDC_REPEATER_SUPPORT
int32_t ol_ioctl_get_primary_radio(struct ol_ath_softc_net80211 *scn, caddr_t param);
int32_t ol_ioctl_get_mpsta_mac_addr(struct ol_ath_softc_net80211 *scn, caddr_t param);
void ol_ioctl_disassoc_clients(struct ol_ath_softc_net80211 *scn);
int32_t ol_ioctl_get_force_client_mcast(struct ol_ath_softc_net80211 *scn, caddr_t param);
int32_t ol_ioctl_get_max_priority_radio(struct ol_ath_softc_net80211 *scn, caddr_t param);
#endif
u_int16_t ol_ioctl_get_disconnection_timeout(struct ol_ath_softc_net80211 *scn, caddr_t param);
u_int8_t ol_ioctl_get_stavap_connection(struct ol_ath_softc_net80211 *scn, caddr_t param);
void ol_ioctl_iface_mgr_status(struct ol_ath_softc_net80211 *scn, caddr_t param);
int32_t ol_ioctl_get_preferred_uplink(struct ol_ath_softc_net80211 *scn, caddr_t param);
#if OL_ATH_SUPPORT_LED
extern void ol_ath_led_event(struct ol_ath_softc_net80211 *scn, OL_LED_EVENT event);
extern bool ipq4019_led_initialized;
extern void ipq4019_wifi_led(struct ol_ath_softc_net80211 *scn, int on_or_off);
extern void ipq4019_wifi_led_init(struct ol_ath_softc_net80211 *scn);
extern void ipq4019_wifi_led_deinit(struct ol_ath_softc_net80211 *scn);
#endif
int
ol_get_board_id(struct ol_ath_softc_net80211 *scn, char *boarddata_file );

int ol_ath_set_tx_capture (struct ol_ath_softc_net80211 *scn, int val);
#if OL_ATH_CE_DEBUG
void
CE_debug_desc_trace_enable(struct ol_ath_softc_net80211 *scn, uint32_t cfg);

#if OL_ATH_SMART_LOGGING
int32_t
ol_ath_enable_smart_log(struct ol_ath_softc_net80211 *scn, uint32_t cfg);

int32_t
send_fatal_cmd(struct ol_ath_softc_net80211 *scn, uint32_t cfg);
#endif /* OL_ATH_SMART_LOGGING */

uint32_t
CE_debug_desc_trace_enable_get(struct ol_ath_softc_net80211 *scn);
#endif /* OL_ATH_CE_DEBUG */

#ifdef BIG_ENDIAN_HOST
     /* This API is used in copying in elements to WMI message,
        since WMI message uses multilpes of 4 bytes, This API
        converts length into multiples of 4 bytes, and performs copy
     */
#define OL_IF_MSG_COPY_CHAR_ARRAY(destp, srcp, len)  do { \
      int j; \
      u_int32_t *src, *dest; \
      src = (u_int32_t *)srcp; \
      dest = (u_int32_t *)destp; \
      for(j=0; j < roundup(len, sizeof(u_int32_t))/4; j++) { \
          *(dest+j) = qdf_le32_to_cpu(*(src+j)); \
      } \
   } while(0)

/* This macro will not work for anything other than a multiple of 4 bytes */
#define OL_IF_SWAPBO(x, len)  do { \
      int numWords; \
      int i; \
      void *pv = &(x); \
      u_int32_t *wordPtr; \
      numWords = (len)/sizeof(u_int32_t); \
      wordPtr = (u_int32_t *)pv; \
      for (i = 0; i < numWords; i++) { \
          *(wordPtr + i) = __cpu_to_le32(*(wordPtr + i)); \
      } \
   } while(0)

#else

#define OL_IF_MSG_COPY_CHAR_ARRAY(destp, srcp, len)  do { \
    OS_MEMCPY(destp, srcp, len); \
   } while(0)

#endif
#define AR9887_DEVICE_ID    (0x0050)
#define AR9888_DEVICE_ID    (0x003c)

/*
    *  * options for firmware dump generation
    *      - 0x1 - Dump to file
    *      - 0x2 - Dump to crash scope
    *      - 0x4 - Do not crash the host after dump
    *      - 0x8 - host/target recovery without dump
    *
*/
#define FW_DUMP_TO_FILE                 0x1u
#define FW_DUMP_TO_CRASH_SCOPE          0x2u
#define FW_DUMP_NO_HOST_CRASH           0x4u
#define FW_DUMP_RECOVER_WITHOUT_CORE    0x8u
#define FW_DUMP_ADD_SIGNATURE           0x10u

#define VHT_MCS_SET_FOR_NSS(x, ss) ( ((x) & (3 << ((ss)<<1))) >> ((ss)<<1) )
#define VHT_MAXRATE_IDX_SHIFT   4

/*Monitor filter types*/
typedef enum _monitor_filter_type {
    MON_FILTER_ALL_DISABLE          = 0x0,   //disable all filters
    MON_FILTER_ALL_EN               = 0x01,  //enable all filters
    MON_FILTER_TYPE_OSIF_MAC        = 0x02,  //enable osif MAC addr based filter
    MON_FILTER_TYPE_UCAST_DATA      = 0x04,  //enable htt unicast data filter
    MON_FILTER_TYPE_MCAST_DATA      = 0x08,  //enable htt multicast cast data filter
    MON_FILTER_TYPE_NON_DATA        = 0x10,  //enable htt non-data filter

    MON_FILTER_TYPE_LAST            = 0x1f,  //last
} monitor_filter_type;


#if FW_CODE_SIGN
/* ideally these are supposed to go into a different file, in interest of time
 * where this involves LOST approvals etc, for all new files, adding it in the
 * current file, and would require reorg og the code, post the check-in. This
 * entire block would need to go into a file, fw_sign.h
 */
/* known product magic numbers */
#define FW_IMG_MAGIC_BEELINER       0x424c4e52U                      /* BLNR */
#define FW_IMG_MAGIC_CASCADE        0x43534345U                      /* CSCE */
#define FW_IMG_MAGIC_SWIFT          0x53574654U                      /* SWFT */
#define FW_IMG_MAGIC_PEREGRINE      0x5052474eU                      /* PRGN */
#define FW_IMG_MAGIC_DAKOTA         0x44414b54U                      /* DAKT */
#define FW_IMG_MAGIC_UNKNOWN        0x00000000U                      /* zero*/
/* chip idenfication numbers
 * Most of the times chip identifier is pcie device id. In few cases that could
 * be a non-pci device id if the device is not pci device. It is assumed at
 * at build time, it is known to the tools for which the firmware is getting
 * built.
 */
#define RSA_PSS1_SHA256 1

#ifndef NELEMENTS
#define NELEMENTS(__array) sizeof((__array))/sizeof ((__array)[0])
#endif

typedef struct _fw_device_id{
    u_int32_t      dev_id;                  /* this pcieid or internal device id */
    char       *dev_name;                    /* short form of the device name */
    u_int32_t      img_magic;                    /* image magic for this product */
} fw_device_id;

struct cert {
    const unsigned int cert_len;
    const unsigned char *cert;
};
enum {
    FW_SIGN_ERR_INTERNAL,
    FW_SIGN_ERR_INV_VER_STRING,
    FW_SIGN_ERR_INV_DEV_ID,
    FW_SIGN_ERR_INPUT,
    FW_SIGN_ERR_INPUT_FILE,
    FW_SIGN_ERR_FILE_FORMAT,
    FW_SIGN_ERR_FILE_ACCESS,
    FW_SIGN_ERR_CREATE_OUTPUT_FILE,
    FW_SIGN_ERR_UNSUPP_CHIPSET,
    FW_SIGN_ERR_FILE_WRITE,
    FW_SIGN_ERR_INVALID_FILE_MAGIC,
    FW_SIGN_ERR_INFILE_READ,
    FW_SIGN_ERR_IMAGE_VER,
    FW_SIGN_ERR_SIGN_ALGO,
    FW_SIGN_ERR_MAX
};

typedef uint fw_img_magic_t;
/* current version of the firmware signing , major 1, minor 0*/
#define THIS_FW_IMAGE_VERSION ((1<<15) | 0)

/* fw_img_file_magic
 * In current form of firmware download process, there are three different
 * kinds of files, that get downloaded. All of these can be in different
 * formats.
 *
 * 1. downloadable, executable, target resident (athwlan.bin)
 * 2. downloadable, executable, target non-resident otp (otp.bin)
 * 3. downloadable, non-executable, target file (fakeBoard)
 * 4. no-download, no-execute, host-resident code swap file.
 * 5. Add another for future
 * Each of these can be signed or unsigned, each of these can signed
 * with single key or can be signed with multiple keys, provisioning
 * all kinds in this list.
 * This list contains only filenames that are generic. Each board might
 * name their boards differently, but they continue to use same types.
 */
#define FW_IMG_FILE_MAGIC_TARGET_WLAN       0x5457414eu  /* target WLAN - TWLAN*/
#define FW_IMG_FILE_MAGIC_TARGET_OTP        0x544f5450u    /* target OTP TOTP */
#define FW_IMG_FILE_MAGIC_TARGET_BOARD_DATA 0x54424446u         /* target TBDF*/
#define FW_IMG_FILE_MAGIC_TARGET_CODE_SWAP  0x4857414eu         /* host HWLAN */
#define FW_IMG_FILE_MAGIC_INVALID           0

typedef uint fw_img_file_magic_t;

/* fw_img_sign_ver
 *
 * This supports for multiple revisions of this module to support different
 * features in future. This is defined in three numbers, major and minor
 * major - In general this would not change, unless, there is new header types
 *         are added or major crypto algorithms changed
 * minor - Minor changes like, adding new devices, new files etc.
 * There is no sub-release version for this, probably change another minor
 * version if really needs a change
 * All these are listed  in design document, probably in .c files
 */

/* fw_ver_rel_type
 * FW version release could be either test, of production, zero is not allowed
 */
#define FW_IMG_VER_REL_TEST         0x01
#define FW_IMG_VER_REL_PROD         0x02
#define FW_IMG_VER_REL_UNDEFIND     0x00

/*
 * fw_ver_maj, fw_ver_minor
 * major and minor versions are planned below.
 * u_int32_t  fw_ver_maj;                        * 32bits, MMMM.MMMM.SCEE.1111 *
 * u_int32_t  fw_ver_minor;                      * 32bits, mmmm.mmmm.rrrr.rrrr *
 */
/*
 * extrat major version number from fw_ver_maj field
 * Higher 16 bits of 32 bit quantity
 * FW_VER_GET_MAJOR - Extract Major version
 * FW_VER_SET_MAJOR - Clear the major version bits and set the bits
 */
#define FW_VER_MAJOR_MASK 0xffff0000u
#define FW_VER_MAJOR_SHIFT 16
#define FW_VER_GET_MAJOR(__mj)  (((__mj)->fw_ver_maj & FW_VER_MAJOR_MASK) >> FW_VER_MAJOR_SHIFT)
#define FW_VER_SET_MAJOR(__mj, __val)  (__mj)->fw_ver_maj =\
                        ((((__val) & 0x0000ffff) << FW_VER_MAJOR_SHIFT) |\
                        ((__mj)->fw_ver_maj  & ~FW_VER_MAJOR_MASK))

/*
 * Extract build variants. The following variants are defined at this moement.
 * This leaves out scope for future types.
 * This is just a number, so this can contain upto 255 values, 0 is undefined
 */
#define FW_VER_IMG_TYPE_S_RETAIL        0x1U
#define FW_VER_IMG_TYPE_E_ENTERPRISE    0x2U
#define FW_VER_IMG_TYPE_C_CARRIER       0x3U
#define FW_VER_IMG_TYPE_X_UNDEF         0x0U

#define FW_VER_IMG_TYPE_MASK            0x0000ff00
#define FW_VER_IMG_TYPE_SHIFT           8
#define FW_VER_GET_IMG_TYPE(__t) (((__t)->fw_ver_maj & FW_VER_IMG_TYPE_MASK) >>\
                                            FW_VER_IMG_TYPE_SHIFT)
#define FW_VER_SET_IMG_TYPE(__t, __val) \
        (__t)->fw_ver_maj  = \
            ((__t)->fw_ver_maj &~FW_VER_IMG_TYPE_MASK) | \
                ((((u_int32_t)(__val)) & 0xff) << FW_VER_IMG_TYPE_SHIFT)

#define FW_VER_IMG_TYPE_VER_MASK            0x000000ff
#define FW_VER_IMG_TYPE_VER_SHIFT           0

#define FW_VER_GET_IMG_TYPE_VER(__t) (((__t)->fw_ver_maj & \
                     FW_VER_IMG_TYPE_VER_MASK) >> FW_VER_IMG_TYPE_VER_SHIFT)

#define FW_VER_SET_IMG_TYPE_VER(__t, __val) (__t)->fw_ver_maj = \
                         ((__t)->fw_ver_maj&~FW_VER_IMG_TYPE_VER_MASK) |\
                         ((((u_int32_t)(__val)) & 0xff) << FW_VER_IMG_TYPE_VER_SHIFT)

#define FW_VER_IMG_MINOR_VER_MASK           0xffff0000
#define FW_VER_IMG_MINOR_VER_SHIFT          16
#define FW_VER_IMG_MINOR_SUBVER_MASK        0x0000ffff
#define FW_VER_IMG_MINOR_SUBVER_SHIFT       0

#define FW_VER_IMG_MINOR_RELNBR_MASK        0x0000ffff
#define FW_VER_IMG_MINOR_RELNBR_SHIFT       0

#define FW_VER_IMG_GET_MINOR_VER(__m) (((__m)->fw_ver_minor &\
                                        FW_VER_IMG_MINOR_VER_MASK) >>\
                                            FW_VER_IMG_MINOR_VER_SHIFT)

#define FW_VER_IMG_SET_MINOR_VER(__t, __val) (__t)->fw_ver_minor = \
                     ((__t)->fw_ver_minor &~FW_VER_IMG_MINOR_VER_MASK) |\
                     ((((u_int32_t)(__val)) & 0xffff) << FW_VER_IMG_MINOR_VER_SHIFT)

#define FW_VER_IMG_GET_MINOR_SUBVER(__m) (((__m)->fw_ver_minor & \
                     FW_VER_IMG_MINOR_SUBVER_MASK) >> FW_VER_IMG_MINOR_SUBVER_SHIFT)

#define FW_VER_IMG_SET_MINOR_SUBVER(__t, __val) (__t)->fw_ver_minor = \
                     ((__t)->fw_ver_minor&~FW_VER_IMG_MINOR_SUBVER_MASK) |\
                     ((((u_int32_t)(__val)) & 0xffff) << FW_VER_IMG_MINOR_SUBVER_SHIFT)

#define FW_VER_IMG_GET_MINOR_RELNBR(__m) (((__m)->fw_ver_bld_id &\
                     FW_VER_IMG_MINOR_RELNBR_MASK) >> FW_VER_IMG_MINOR_RELNBR_SHIFT)

#define FW_VER_IMG_SET_MINOR_RELNBR(__t, __val) (__t)->fw_ver_bld_id = \
                     ((__t)->fw_ver_bld_id &~FW_VER_IMG_MINOR_RELNBR_MASK) |\
                     ((((u_int32_t)(__val)) & 0xffff) << FW_VER_IMG_MINOR_RELNBR_SHIFT)

/* signed/unsigned - bit 0 of fw_hdr_flags */
#define FW_IMG_FLAGS_SIGNED                 0x00000001U
#define FW_IMG_FLAGS_UNSIGNED               0x00000000U
#define FW_IMG_IS_SIGNED(__phdr) ((__phdr)->fw_hdr_flags & FW_IMG_FLAGS_SIGNED)

/* file format type - bits 1,2,3*/
#define FW_IMG_FLAGS_FILE_FORMAT_MASK       0x0EU
#define FW_IMG_FLAGS_FILE_FORMAT_SHIFT      0x1U
#define FW_IMG_FLAGS_FILE_FORMAT_TEXT       0x1U
#define FW_IMG_FLAGS_FILE_FORMAT_BIN        0x2U
#define FW_IMG_FLAGS_FILE_FORMAT_UNKNOWN    0x0U
#define FW_IMG_FLAGS_FILE_FORMAT_GET(__flags) \
                    (((__flags) & FW_IMG_FLAGS_FILE_FORMAT_MASK) >> \
                    FW_IMG_FLAGS_FILE_FORMAT_SHIFT)

#define FW_IMG_FLAGS_FILE_COMPRES_MASK       0x10U
#define FW_IMG_FLAGS_FILE_COMPRES_SHIFT      0x4U
#define FW_IMG_FLAGS_COMPRESSED             0x1U
#define FW_IMG_FLAGS_UNCOMPRESSED           0x0U
#define FW_IMG_IS_COMPRESSED(__flags) ((__flags)&FW_IMG_FLAGS_FILE_COMPRES_MASK)
#define FW_IMG_FLAGS_SET_COMRESSED(__flags) \
                            ((__flags) |= 1 << FW_IMG_FLAGS_FILE_COMPRES_SHIFT)

#define FW_IMG_FLAGS_FILE_ENCRYPT_MASK       0x20U
#define FW_IMG_FLAGS_FILE_ENCRYPT_SHIFT      0x5U
#define FW_IMG_FLAGS_ENCRYPTED               0x1U
#define FW_IMG_FLAGS_UNENCRYPTED             0x0U
#define FW_IMG_IS_ENCRYPTED(__flags) ((__flags)&FW_IMG_FLAGS_FILE_ENCRYPT_MASK)
#define FW_IMG_FLAGS_SET_ENCRYPT(__flags) \
                            ((__flags) |= 1 << FW_IMG_FLAGS_FILE_ENCRYPT_SHIFT)

/* any file that is dowloaded is marked target resident
 * any file that is not downloaded but loaded at host
 * would be marked NOT TARGET RESIDENT file, or host resident file
 */
#define FW_IMG_FLAGS_FILE_TARGRES_MASK       0x40U
#define FW_IMG_FLAGS_FILE_TARGRES_SHIFT      0x6U
#define FW_IMG_FLAGS_TARGRES                 0x1U
#define FW_IMG_FLAGS_HOSTRES                 0x0U

#define FW_IMG_IS_TARGRES(__flags) ((__flags)&FW_IMG_FLAGS_FILE_TARGRES_MASK)

#define FW_IMG_FLAGS_SET_TARGRES(__flags) \
                   ((__flags) |= (1 <<FW_IMG_FLAGS_FILE_TARGRES_SHIFT))

#define FW_IMG_FLAGS_FILE_EXEC_MASK       0x80U
#define FW_IMG_FLAGS_FILE_EXEC_SHIFT      0x7U
#define FW_IMG_FLAGS_EXEC                 0x1U
#define FW_IMG_FLAGS_NONEXEC                 0x0U
#define FW_IMG_IS_EXEC(__flags) ((__flags)&FW_IMG_FLAGS_FILE_EXEC_MASK)
#define FW_IMG_FLAGS_SET_EXEC (__flags) \
                            ((__flags) |= 1 << FW_IMG_FLAGS_FILE_EXEC_SHIFT)

/* signing algorithms, only rsa-pss1 with sha256 is supported*/
enum {
    FW_IMG_SIGN_ALGO_UNSUPPORTED = 0,
    FW_IMG_SIGN_ALGO_RSAPSS1_SHA256  = 1
};
/* header of the firmware file, also contains the pointers to the file itself
 * and the signature at end of the file
 */
struct firmware_head {
    fw_img_magic_t      fw_img_magic_number;       /* product magic, eg, BLNR */
    u_int32_t              fw_chip_identification;/*firmware chip identification */

    /* boarddata, otp, swap, athwlan.bin etc */
    fw_img_file_magic_t fw_img_file_magic;
    u_int16_t              fw_img_sign_ver;        /* signing method version */

    u_int16_t              fw_img_spare1;                      /* undefined. */
    u_int32_t              fw_img_spare2;                       /* undefined */

    /* Versioning and release types */
    u_int32_t              fw_ver_rel_type;              /* production, test */
    u_int32_t              fw_ver_maj;        /* 32bits, MMMM.MMMM.SSEE.1111 */
    u_int32_t              fw_ver_minor;      /* 32bits, mmmm.mmmm.ssss.ssss */
    u_int32_t              fw_ver_bld_id;                 /* actual build id */
    /* image versioning is little tricky to handle. We assume there are three
     * different versions that we can encode.
     * MAJOR - 16 bits, lower 16 bits of this is spare, chip version encoded
               in lower 16 bits
     * minor - 16 bits, 0-65535,
     * sub-release - 16 bits, usually this would be zero. if required we
     * can use this. For eg. BL.2_1.400.2, is, Beeliner, 2.0, first major
     * release, build 400, and sub revision of 2 in the same build
     */
    u_int32_t             fw_ver_spare3;

     /* header identificaiton */
    u_int32_t              fw_hdr_length;                   /* header length */
    u_int32_t              fw_hdr_flags;                /* extra image flags */
    /* image flags are different single bit flags of different characterstics
    // At this point of time these flags include below, would extend as
    // required
    //                      signed/unsigned,
    //                      bin/text,
    //                      compressed/uncompressed,
    //                      unencrypted,
    //                      target_resident/host_resident,
    //                      executable/non-execuatable
    */
    u_int32_t              fw_hdr_spare4;                      /* future use */

    u_int32_t              fw_img_size;                       /* image size; */
    u_int32_t              fw_img_length;            /* image length in byes */
    /* there is no real requirement for keeping the size, the size is
     * fw_img_size = fw_img_length - ( header_size + signature)
     * in otherwords fw_img_size is actual image size that would be
     * downloaded to target board.
     */
    u_int32_t              fw_spare5;
    u_int32_t              fw_spare6;

    /* security details follows here after */
    u_int16_t              fw_sig_len;     /* index into known signature lengths */
    u_int8_t               fw_sig_algo;                   /* signature algorithm */
    u_int8_t               fw_oem_id;            /* oem ID, to access otp or etc */

#if 0
    /* actual image body    */
    u_int8_t              *fw_img_body;                     /* fw_img_size bytes */
    u_int8_t              *fw_img_padding;          /*if_any_upto_4byte_boundary */
    u_int8_t              *fw_signature;                  /* pointer to checksum */
#endif
};
#endif /* FW_CODE_SIGN */
#endif /* _DEV_OL_ATH_ATHVAR_H  */
