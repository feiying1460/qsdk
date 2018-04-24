/*
 * Copyright (c) 2013,2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

/**
 * This file defines WMI services bitmap and the set of WMI services . 
 * defines macrso to set/clear/get different service bits from the bitmap. 
 * the service bitmap is sent up to the host via WMI_READY command.
 *    
 */

#ifndef _WMI_SERVICES_H_
#define _WMI_SERVICES_H_


#ifdef __cplusplus
extern "C" {
#endif



typedef  enum  {
    WMI_SERVICE_BEACON_OFFLOAD=0,     /* beacon offload */
    WMI_SERVICE_SCAN_OFFLOAD,         /* scan offload */
    WMI_SERVICE_ROAM_OFFLOAD,         /* roam offload */
    WMI_SERVICE_BCN_MISS_OFFLOAD,     /* beacon miss offload */
    WMI_SERVICE_STA_PWRSAVE,          /* fake sleep + basic power save */
    WMI_SERVICE_STA_ADVANCED_PWRSAVE, /* uapsd, pspoll, force sleep */
    WMI_SERVICE_AP_UAPSD,             /* uapsd on AP */
    WMI_SERVICE_AP_DFS,               /* DFS on AP */
    WMI_SERVICE_11AC,                 /* supports 11ac */
    WMI_SERVICE_BLOCKACK,             /* Supports triggering ADDBA/DELBA from host*/
    WMI_SERVICE_PHYERR,               /* PHY error */
    WMI_SERVICE_BCN_FILTER,           /* Beacon filter support */
    WMI_SERVICE_RTT,                  /* RTT (round trip time) support */
    WMI_SERVICE_RATECTRL,             /* Rate-control */
    WMI_SERVICE_WOW,                  /* WOW Support */
    WMI_SERVICE_RATECTRL_CACHE,       /* Rate-control caching */
    WMI_SERVICE_IRAM_TIDS,            /* TIDs in IRAM */
    WMI_SERVICE_BURST,                /* SIFS spaced burst */
    WMI_SERVICE_SMART_ANTENNA_SW_SUPPORT,        /* SMARTANTENNA Software support */
    WMI_SERVICE_GTK_OFFLOAD,                /* GTK offload */
    WMI_SERVICE_SCAN_SCH,                   /* Scan Scheduler Service */
    WMI_SERVICE_CSA_OFFLOAD,          /* CSA offload service */
    WMI_SERVICE_CHATTER,              /* Chatter service */
    WMI_SERVICE_COEX_FREQAVOID,       /* FW report freq range to avoid */
    WMI_SERVICE_PACKET_POWER_SAVE ,   /* packet power save service */
    WMI_SERVICE_FORCE_FW_HANG,        /* Service to test the firmware recovery mechanism */
    WMI_SERVICE_SMART_ANTENNA_HW_SUPPORT, /* Smart Antenna HW support */
    WMI_SERVICE_GPIO,                 /* GPIO service */
    WMI_STA_UAPSD_BASIC_AUTO_TRIG,          /* Basic version of station UAPSD AC Trigger Generation Method with
                                             * variable tigger periods (service, delay, and suspend intervals) */
    WMI_STA_UAPSD_VAR_AUTO_TRIG,            /* Station UAPSD AC Trigger Generation Method with variable 
                                             * trigger periods (service, delay, and suspend intervals) */
    WMI_SERVICE_STA_KEEP_ALIVE,             /* Serivce to support the STA KEEP ALIVE mechanism */
    WMI_SERVICE_TX_ENCAP,                   /* Packet type for TX encapsulation */
    WMI_SERVICE_AP_PS_DETECT_OUT_OF_SYNC,   /* detect out-of-sync sleeping stations */
    WMI_SERVICE_EARLY_RX,                   /* adaptive early-rx feature */
    WMI_SERVICE_ENHANCED_PROXY_STA,         /* Enhanced ProxySTA mode support */
    WMI_SERVICE_TT,                         /* Thermal throttling support */
    WMI_SERVICE_ATF,                        /* Air Time Fairness support */
    WMI_SERVICE_PEER_CACHING,         /* QCache support (caching inactive peers to the host) */
    WMI_SERVICE_COEX_GPIO,            /* BTCOEX GPIO support */
    WMI_SERVICE_AUX_SPECTRAL_INTF,    /* Aux Radio enhancement support for ignoring spectral scan intf from main radios */
    WMI_SERVICE_AUX_CHAN_LOAD_INTF,   /* Aux Radio enhancement support for ignoring chan load intf from main radios*/
    WMI_SERVICE_BSS_CHANNEL_INFO_64,  /* BSS channel info (freq, noise floor, 64-bit counters) event support */
    WMI_SERVICE_EXT_RES_CFG_SUPPORT,  /* Support for extended resource configuration */
    WMI_SERVICE_MESH,                 /* MESH Service Support */
    WMI_SERVICE_RESTRT_CHNL_SUPPORT,  /* Restricted Channel Support */
    WMI_SERVICE_PEER_STATS,           /* support for per peer stats */
    WMI_SERVICE_MESH_11S,             /* 11S MESH Service Support */
    WMI_SERVICE_PERIODIC_CHAN_STAT_SUPPORT, /* periodic channel stats service */
    WMI_SERVICE_TX_MODE_PUSH_ONLY,    /* support only push mode, no queue in host */
    WMI_SERVICE_TX_MODE_PUSH_PULL,    /* support push and pull, host maintains queue for data packet */
    WMI_SERVICE_TX_MODE_DYNAMIC,      /* support dynamic switch between push and pull modes */
    WMI_SERVICE_VDEV_RX_FILTER,       /* Support per-vdev specs of which rx frames to filter out */
    WMI_SERVICE_BTCOEX,               /* Support BlueTooth coexistence */
    WMI_SERVICE_CHECK_CAL_VERSION,    /* Support cal version check */
    WMI_SERVICE_DBGLOG_WARN2,         /* Support a 2nd level of WARN in dbglog */
    WMI_SERVICE_BTCOEX_DUTY_CYCLE,    /* Support BlueTooth coexistence duty cycle */
    WMI_SERVICE_4_WIRE_COEX_SUPPORT,  /* Support for 4 wire COEX between WiFi, BT, ZB and Thread */
    WMI_SERVICE_EXTENDED_NSS_SUPPORT, /* Support for Extended NSS - VHT160/VHT80_80 Max NSS values */
    WMI_SERVICE_PROG_GPIO_BAND_SELECT,/* Support GPIO programming for specifying the band of operation */
    WMI_SERVICE_SMART_LOGGING_SUPPORT,/* Support for smart logging */

    WMI_MAX_SERVICE=64                      /* max service */
} WMI_SERVICE;

#define WMI_SERVICE_BM_SIZE   ((WMI_MAX_SERVICE + sizeof(A_UINT32)- 1)/sizeof(A_UINT32))


/*
 * turn on the WMI service bit corresponding to  the WMI service.
 */
#define WMI_SERVICE_ENABLE(pwmi_svc_bmap,svc_id) \
    ( (pwmi_svc_bmap)[(svc_id)/(sizeof(A_UINT32))] |= \
         (1 << ((svc_id)%(sizeof(A_UINT32)))) ) 

#define WMI_SERVICE_DISABLE(pwmi_svc_bmap,svc_id) \
    ( (pwmi_svc_bmap)[(svc_id)/(sizeof(A_UINT32))] &=  \
      ( ~(1 << ((svc_id)%(sizeof(A_UINT32)))) ) ) 
      
#define WMI_SERVICE_IS_ENABLED(pwmi_svc_bmap,svc_id) \
    ( ((pwmi_svc_bmap)[(svc_id)/(sizeof(A_UINT32))] &  \
       (1 << ((svc_id)%(sizeof(A_UINT32)))) ) != 0) 

#ifdef __cplusplus
}
#endif

#endif /*_WMI_SERVICES_H_*/
