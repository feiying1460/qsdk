/*
 * Copyright (c) 2010, Atheros Communications Inc. 
 * All Rights Reserved.
 * 
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */

#ifndef _IF_ATH_GREEN_AP_H
#define _IF_ATH_GREEN_AP_H

#include "ath_timer.h"

#define GREEN_AP_TODO(str)  printk(KERN_INFO "Green-AP : %s (%s : %d)\n", (str), __func__, __LINE__)
#define GREEN_AP_INFO(str)  printk(KERN_INFO "Green-AP : %s\n", (str))
#define green_ap_ops_not_registered(str)   printk(KERN_INFO"Green-AP : %s not registered\n", (str))
#define gap_not_yet_implemented(str)   printk(KERN_INFO"Green-AP : %s (%d) not yet implemented\n", __func__, __LINE__)

#define GET_GREEN_AP_OPS(green_ap) ((struct green_ap_ops*)(&((green_ap)->green_ap_ops)))
#define GET_GREEN_AP_ATHSOFTC(green_ap) ((struct ath_softc*)(((struct ath_green_ap*)green_ap)->ath_softc_handle))
#define GET_GREEN_AP_FROM_IC(ic)  ((struct ath_green_ap*)((ic)->ic_green_ap))

/* Enable to debug perf offload configuration interactions */
//#define OL_GREEN_AP_DEBUG_CONFIG_INTERACTIONS 1

typedef enum {
    ATH_PS_EVENT_INC_STA,
    ATH_PS_EVENT_DEC_STA,
    ATH_PS_EVENT_PS_ON,
    ATH_PS_EVENT_PS_WAIT,
}ath_ps_event;


#ifdef ATH_SUPPORT_GREEN_AP /* Right definations */
/*
 *  Copyright (c) 2008 Atheros Communications Inc.  All rights reserved.
 */

/*
 * Green-AP Function pointers
 */
typedef struct green_ap_ops {
    u_int32_t (*set_ap_ps_on_off)(void* arg, u_int32_t val);
    u_int32_t (*is_vap_active)(void* arg);
    u_int16_t (*get_current_channel)(void* arg);
    u_int32_t (*get_current_channel_flags)(void* arg);
    u_int32_t (*reset_dev)(void* arg);
}GREEN_AP_OPS;


/*
 * Public Interface for Green AP module
 */
 
typedef enum {
    ATH_PWR_SAVE_IDLE,
    ATH_PWR_SAVE_OFF,
    ATH_PWR_SAVE_WAIT,
    ATH_PWR_SAVE_ON,
} power_save_state;


struct ath_green_ap {
    struct ieee80211com* ic;
    void*  ath_softc_handle;
    GREEN_AP_OPS green_ap_ops;
    /* Variables for single antenna powersave */
    u_int16_t power_save_enable;
    power_save_state ps_state;
    u_int16_t num_nodes;        
    struct ath_timer	ps_timer;
    ath_ps_event timer_event;    
    u_int16_t ps_trans_time; /* In seconds */
    u_int16_t ps_on_time;
    u_int32_t dbg_print;
};

#define PS_RX_MASK (0x1)
#define PS_TX_MASK (0x1)

void* ath_green_ap_attach(struct ieee80211com *ic);
int ath_green_ap_detach(struct ieee80211com *ic);
void ath_green_ap_stop(struct ieee80211com  *ic);
void ath_green_ap_start(struct ieee80211com *ic);
u_int32_t ath_green_ap_is_powersave_on(struct ieee80211com* ic);
void ath_green_ap_state_mc(struct ieee80211com *ic, ath_ps_event event);
/* Config. functions called from command line */
void ath_green_ap_sc_set_enable(struct ieee80211com *ic, int32_t val );
int32_t ath_green_ap_sc_get_enable(struct ieee80211com *ic);
void ath_green_ap_sc_set_transition_time(struct ieee80211com *ic, int32_t val );
int32_t ath_green_ap_sc_get_transition_time(struct ieee80211com *ic);
void ath_green_ap_sc_set_on_time(struct ieee80211com *ic, int32_t val );
int32_t ath_green_ap_sc_get_on_time(struct ieee80211com *ic);
void ath_green_ap_suspend( struct ieee80211com *ic);
void green_ap_register_funcs(struct ath_green_ap* p_gap, GREEN_AP_OPS* p_ops);
int ath_green_ap_sc_get_enable_print(struct ieee80211com* ic);
void ath_green_ap_sc_set_enable_print(struct ieee80211com* ic, int val);
#else

struct ath_green_ap {
    int dummy;
};

/* Dummy defines so that the if_ath.c compiles without warning */
#define ath_green_ap_attach( sc)(0)
#define ath_green_ap_detach( sc) do{}while(0)
#define ath_green_ap_stop(dev)do{}while(0)
#define ath_green_ap_start( sc)do{}while(0)
#define ath_green_ap_is_powersave_on(dev) (0)
#define ath_green_ap_state_mc( dev, node_add_remove) do{}while(0)
#define ath_green_ap_sc_set_enable(dev, val )do{}while(0)
#define ath_green_ap_sc_get_enable(dev) (0)
#define ath_green_ap_sc_set_transition_time(dev, val) do{}while(0)
#define ath_green_ap_sc_get_transition_time(dev) (0)
#define ath_green_ap_sc_set_on_time(dev, val) do{}while(0)
#define ath_green_ap_sc_get_on_time(dev) (0)
#define ath_green_ap_suspend(sc)
#define green_ap_register_funcs(a, b) do{}while(0)
#define ath_green_ap_sc_get_enable_print(a) (0)
#define ath_green_ap_sc_set_enable_print(a, b) do{}while(0)

#endif // ATH_GREEN_AP

#endif //_IF_ATH_GREEN_AP_H

