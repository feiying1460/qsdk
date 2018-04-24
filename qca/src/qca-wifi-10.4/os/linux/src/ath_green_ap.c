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
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved. 
 * Qualcomm Atheros Confidential and Proprietary. 
 */ 

#include <osdep.h>
#include "ath_internal.h"
#include "ath_dev.h"
#include "ieee80211_var.h"
#include "ath_green_ap.h"


#define GREEN_AP_DISABLE (0)
#define GREEN_AP_ENABLE  (1)
#define GREEN_AP_SUSPEND (2)
#define ATH_PS_TRANSITON_TIME (20)


/* Function declarations */
static int ath_green_ap_ant_ps_mode_on_tmr_fun(void *ic_ptr);
static void green_ap_init_dummy_function_table(struct ath_green_ap* green_ap);

/*
 * Function     : ath_green_ap_attach
 * Description  : Attaches Green-AP module
 * Input        : Pointer to IC
 * Output       : Success/Failure
 *
 */
void* ath_green_ap_attach( struct ieee80211com* ic)
{
    struct ath_green_ap* green_ap = NULL;

    /* Sanity check */
    if ( ic->ic_green_ap != NULL ) {
        GREEN_AP_INFO("Green-AP Module already loaded\n");
        return NULL;
    }

    /* Allocate memory for Green-AP */
    green_ap = (struct ath_green_ap *) OS_MALLOC(ic->ic_osdev, sizeof(struct ath_green_ap), GFP_KERNEL);

    /* Sanity check */
    if ( green_ap == NULL ) {
        GREEN_AP_INFO("Green-AP : Fatal, No memory\n");
        return NULL;
    }

    /* Initialize */
    OS_MEMZERO(green_ap, sizeof(struct ath_green_ap));
    green_ap->ic    = ic;
    ic->ic_green_ap = green_ap;

    /* Init. the state */
    green_ap->power_save_enable     = GREEN_AP_DISABLE;     /* "DISABLED" is the initial state */
    green_ap->num_nodes             = 0;                    /* Initial node count is zero */
    green_ap->ps_state              = ATH_PWR_SAVE_IDLE;    /* "IDLE" is the initial power save state */
    green_ap->ps_trans_time         = ATH_PS_TRANSITON_TIME;/* Transtion time is set to 20 units */
    green_ap->ps_on_time            = 0;                    /* Force it to zero for the time being EV 69649 */
    green_ap->ps_timer.active_flag  = 0;                    /* Timer is inactive */

    /* Init dummy functions */
    green_ap_init_dummy_function_table(green_ap);

    /* Init the spin lock */
    spin_lock_init(&ic->green_ap_ps_lock);

    GREEN_AP_INFO("Green-AP : Attached\n");

    return green_ap;
}EXPORT_SYMBOL(ath_green_ap_attach);

/*
 * Function     : ath_green_ap_detach
 * Description  : Removes the Green-AP Module
 * Input        : Pointer to IC
 * Output       : Success/Failure
 *
 */
/* Detach function for green_ap */
int ath_green_ap_detach( struct ieee80211com* ic)
{
    struct ath_green_ap* green_ap = ic->ic_green_ap;

    /* Sanity check */
    if ( green_ap == NULL ) {
        GREEN_AP_INFO("Module not loaded\n");
        return -1;
    }

    spin_lock(&ic->green_ap_ps_lock);

    /* Delete the timer if it is on */
    if (ath_timer_is_initialized(&green_ap->ps_timer)) {
        ath_cancel_timer(&green_ap->ps_timer, CANCEL_NO_SLEEP);
        ath_free_timer(&green_ap->ps_timer);
    }

    /* Release the memory */
    OS_MEMZERO(green_ap, sizeof(*green_ap));
    OS_FREE(green_ap);
    ic->ic_green_ap = NULL;

    spin_unlock(&ic->green_ap_ps_lock);
    spin_lock_destroy(&ic->green_ap_ps_lock);
    GREEN_AP_INFO("Green-AP : Detached\n");
    return 0;
}EXPORT_SYMBOL(ath_green_ap_detach);

/*
 * Function     : ath_green_ap_ant_ps_mode_on_tmr_fun
 * Description  : Delays the transition from power save off to power save
 *                on, This function calls the state machine with given arg
 * Input        : Pointer to IC
 * Output       : Status
 *
 */
static int ath_green_ap_ant_ps_mode_on_tmr_fun(void *ic_ptr)
{
    struct ieee80211com* ic = (struct ieee80211com*)ic_ptr;
    struct ath_green_ap* green_ap = ic->ic_green_ap;
    ath_green_ap_state_mc(ic, green_ap->timer_event);
    return 0;
}

/*
 * Function     : ath_green_ap_ant_ps_reset
 * Description  : Reset fucntion, so that Antenna Mask can come into effect.
 *                This applies for only few of the hardware chips
 * Input        : Pointer to IC
 * Output       : Void
 *
 */
static void ath_green_ap_ant_ps_reset(struct ath_green_ap* green_ap)
{
    GREEN_AP_OPS* p_gpops = GET_GREEN_AP_OPS(green_ap);
    /*
    ** Add protection against green AP enabling interrupts
    ** when not valid or no VAPs exist
    */

    if(p_gpops->is_vap_active(green_ap)) {
        p_gpops->reset_dev(green_ap);
    } else  {
        GREEN_AP_INFO("Green AP tried to enable IRQs when invalid\n");
    }
}

/*
 * Function     : ath_green_ap_start
 * Description  : Triggers the Green-AP
 * Input        : Pointer to IC
 * Output       : Void
 *
 */
void ath_green_ap_start(struct ieee80211com* ic)
{
    struct ath_green_ap* green_ap = ic->ic_green_ap;

    /* Sanity check */
    if (green_ap == NULL){
        return;
    }

    /* Only is power save enabled */
    if (!green_ap->power_save_enable) {
        return;
    }

    /* Make sure the start function does not get called 2 times */
    spin_lock(&ic->green_ap_ps_lock);

    if (green_ap->ps_state == ATH_PWR_SAVE_IDLE) {

        ath_initialize_timer( ic->ic_osdev,
                            &green_ap->ps_timer,
                            green_ap->ps_trans_time * 1000 ,
                            ath_green_ap_ant_ps_mode_on_tmr_fun,
                            (void *)ic);

        /*
         * Force transition to the correct mode depending on the
         * Node count
         */
        if (green_ap->num_nodes) {
            /* Active nodes present, Switchoff the power save */
            green_ap->ps_state = ATH_PWR_SAVE_OFF;
        } else {
            /* No Active nodes, get into power save */
            GREEN_AP_INFO("Transition to Power save (WAIT)\n");
            green_ap->ps_state      = ATH_PWR_SAVE_WAIT;
            green_ap->timer_event   = ATH_PS_EVENT_PS_ON;
            ath_start_timer(&green_ap->ps_timer);
        }
    }

    spin_unlock(&ic->green_ap_ps_lock);
}EXPORT_SYMBOL(ath_green_ap_start);

/*
 * Function     : ath_green_ap_stop
 * Description  : Disable the Power save
 * Input        : Pointer to IC
 * Output       : Void
 *
 */
void ath_green_ap_stop(struct ieee80211com* ic)
{
    struct ath_green_ap* green_ap = ic->ic_green_ap;
    GREEN_AP_OPS* p_gpops = NULL;

    /* Sanity check */
    if (green_ap == NULL) {
        return;
    }

    p_gpops = GET_GREEN_AP_OPS(green_ap);

    /* Take the spin lock */
    spin_lock(&ic->green_ap_ps_lock);

    /* Delete the timer just to be sure */
    ath_cancel_timer(&green_ap->ps_timer, CANCEL_NO_SLEEP);
    ath_free_timer(&green_ap->ps_timer );

    /* Disable the power save */
    green_ap->power_save_enable = 0;

    if ( green_ap->ps_state == ATH_PWR_SAVE_ON) {
        /* Get the RX Chains out of power save mode */
        //ath_hal_setGreenApPsOnOff(sc->sc_ah, 0);
        p_gpops->set_ap_ps_on_off(green_ap, 0);
        ath_green_ap_ant_ps_reset(green_ap);
    }

    /* Set the mode to IDLE */
    green_ap->ps_state = ATH_PWR_SAVE_IDLE;

    /* Giveup the spin lock */
    spin_unlock(&ic->green_ap_ps_lock);

}EXPORT_SYMBOL(ath_green_ap_stop);

/*
 * Function     : ath_green_ap_is_powersave_on
 * Description  : Check the power save state
 * Input        : Pointer to IC
 * Output       : State 1 (On)/0 (Off)
 *
 */
u_int32_t ath_green_ap_is_powersave_on(struct ieee80211com* ic)
{
    struct ath_green_ap* green_ap = ic->ic_green_ap;
    u_int32_t state = 0;

    if (green_ap == NULL) {
        return 0;
    }

    state = ((green_ap->ps_state == ATH_PWR_SAVE_ON) && (green_ap->power_save_enable));
    return state;
}

/*
 * Function     : ath_green_ap_state_mc
 * Description  : State Machine
 * Input        : Pointer to IC, Power save Event
 * Output       : Void
 *
 */
void ath_green_ap_state_mc(struct ieee80211com* ic, ath_ps_event event)
{
    u_int16_t channel;
    u_int32_t channel_flags;
    struct ath_green_ap* green_ap = ic->ic_green_ap;
    wlan_if_t vap = NULL;
    u_int8_t is_vap_present;
    GREEN_AP_OPS* p_gpops = GET_GREEN_AP_OPS(green_ap);

    if (green_ap == NULL) {
        return;
    }

    is_vap_present = 0;
    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
            if (vap) {
                    is_vap_present = 1;
                    break;
            }
    }

    if(!is_vap_present) {
            return;
    }
    /* Take the lock */
    spin_lock(&ic->green_ap_ps_lock);

    channel = p_gpops->get_current_channel(green_ap);
    channel_flags = p_gpops->get_current_channel_flags(green_ap);

    /* Handle the increment and decrement events first */
    switch(event) {

        case ATH_PS_EVENT_INC_STA:
            green_ap->num_nodes++;
            break;

        case ATH_PS_EVENT_DEC_STA:
            if (green_ap->num_nodes) {
                green_ap->num_nodes--;
            }
            break;

        case ATH_PS_EVENT_PS_ON:
        case ATH_PS_EVENT_PS_WAIT:
            break;
            /* This event will be handled inside the state machine */
        default:
            break;
    }

    /* Confirm that power save is enabled  before doing state transitions */
    if (!green_ap->power_save_enable ) {
        spin_unlock(&ic->green_ap_ps_lock);
        return;
    }

    /* Now, Handle the state transitions */
    switch( green_ap->ps_state ) {

        case ATH_PWR_SAVE_IDLE:
            /* Nothing to be done in ths state, just keep track of the nodes*/
            break;

        case  ATH_PWR_SAVE_OFF:
            /* Check if all the nodes have been removed. If so, go to power
             * save mode */
            if (!green_ap->num_nodes) {

                /* All nodes have been removed. Trun on power save mode */
                green_ap->ps_state = ATH_PWR_SAVE_WAIT;

                green_ap->timer_event = ATH_PS_EVENT_PS_ON;
                ath_set_timer_period(&green_ap->ps_timer,green_ap->ps_trans_time * 1000);
                ath_start_timer(&green_ap->ps_timer);
            }

            break;

        case ATH_PWR_SAVE_WAIT:

            /* Make sure no new nodes have been added */
            if (!green_ap->num_nodes && (event == ATH_PS_EVENT_PS_ON)) {
                /* All nodes have been removed. Turn on power save mode */
                /* This is a fix for bug 62668: Kernel panic caused by
                 * invalid sc->sc_curcohan bootup.This condition is
                 * detected by checking if channel or channel_flags field in
                 * sc_curchan structure is zero.
                 * If this is the case, wait for some more time till a valid
                 * sc_curchan exists */
                if((channel == 0) ||
                   (channel_flags == 0) ) {

                    /* Stay in the current state and restart the timer to
                     * check later */
                    ath_set_timer_period( &green_ap->ps_timer,green_ap->ps_trans_time * 1000);
                    ath_start_timer(&green_ap->ps_timer);

                } else {

                    green_ap->ps_state = ATH_PWR_SAVE_ON;

                    p_gpops->set_ap_ps_on_off(green_ap, 1);

                    ath_green_ap_ant_ps_reset(green_ap);

                    if ( green_ap->ps_on_time ) {
                        green_ap->timer_event = ATH_PS_EVENT_PS_WAIT;
                        ath_set_timer_period(&green_ap->ps_timer, green_ap->ps_on_time * 1000);
                        ath_start_timer(&green_ap->ps_timer);
                    }

                    GREEN_AP_INFO("Transition to power save On\n");

                }

            } else if (green_ap->num_nodes) {
                /* Some new node has been added, move out of Power save mode */
                /* Delete the timer just to be sure */
                ath_cancel_timer( &green_ap->ps_timer, CANCEL_NO_SLEEP);
                green_ap->ps_state =ATH_PWR_SAVE_OFF;
                GREEN_AP_INFO("Transition to power save Off\n");
            }
            break;

        case  ATH_PWR_SAVE_ON:
            /*
             * Check if a node has been added. If so, move come out of power
             * save mode
             */
            if ( green_ap->num_nodes ) {

                /* A node has been added. Need to turn off power save */
                green_ap->ps_state = ATH_PWR_SAVE_OFF;

                /* Delete the timer if it is on and reset the green AP state*/
                ath_cancel_timer( &green_ap->ps_timer, CANCEL_NO_SLEEP);
                //ath_hal_setGreenApPsOnOff(sc->sc_ah, 0);
                p_gpops->set_ap_ps_on_off(green_ap, 0);
                ath_green_ap_ant_ps_reset(green_ap);
                GREEN_AP_INFO("Transition to power save Off\n");
            } else if ((green_ap->timer_event == ATH_PS_EVENT_PS_WAIT) &&
                        (green_ap->ps_on_time) ) {

                green_ap->timer_event = ATH_PS_EVENT_PS_ON;

                /*
                 * Do NOT reinitialize the timer, just set the period!
                 */

                ath_set_timer_period( &green_ap->ps_timer,green_ap->ps_trans_time * 1000);

                ath_start_timer(&green_ap->ps_timer);
                green_ap->ps_state = ATH_PWR_SAVE_WAIT;
                //ath_hal_setGreenApPsOnOff(sc->sc_ah, 0);
                p_gpops->set_ap_ps_on_off(green_ap, 0);
                ath_green_ap_ant_ps_reset(green_ap);
                GREEN_AP_INFO("Transition to power save Wait\n");
            }
            break;

        default:
            break;
    }

    spin_unlock(&ic->green_ap_ps_lock);
}EXPORT_SYMBOL(ath_green_ap_state_mc);

/*
 * Function     : ath_green_ap_suspend
 * Description  : Set the Green-AP state to Suspend
 * Input        : Pointer to IC
 * Output       : Void
 *
 */
void ath_green_ap_suspend(struct ieee80211com *ic)
{
    struct ath_green_ap* green_ap = ic->ic_green_ap;
    green_ap->power_save_enable = GREEN_AP_SUSPEND ;
    return ;
}

/*
 * Function     : ath_green_ap_sc_set_enable
 * Description  : Set the Power save Enable
 * Input        : Pointer to IC, val
 * Output       : Void
 *
 */
void ath_green_ap_sc_set_enable(struct ieee80211com *ic, int32_t val )
{
    struct ath_green_ap* green_ap = ic->ic_green_ap;
    GREEN_AP_OPS* p_gpops = GET_GREEN_AP_OPS(green_ap);

    if (green_ap == NULL) {
        return;
    }

    if ( val) {
        green_ap->power_save_enable = GREEN_AP_ENABLE;
        if (p_gpops->is_vap_active(green_ap)) {
            ath_green_ap_start(green_ap->ic);
        }
    }
    else {
        ath_green_ap_stop(green_ap->ic);
    }
}EXPORT_SYMBOL(ath_green_ap_sc_set_enable);

/*
 * Function     : ath_green_ap_sc_get_enable
 * Description  : Get the state of Enable
 * Input        : Pointer to IC
 * Output       : State
 *
 */
int32_t ath_green_ap_sc_get_enable(struct ieee80211com *ic)
{
    struct ath_green_ap* green_ap = ic->ic_green_ap;
    if (green_ap == NULL) {
        return 0;
    }

    return green_ap->power_save_enable;
}EXPORT_SYMBOL(ath_green_ap_sc_get_enable);

/*
 * Function     : ath_green_ap_sc_set_transition_time
 * Description  : Set the time value to make transition
 * Input        : Pointer to IC, Time value
 * Output       : Void
 *
 */
void ath_green_ap_sc_set_transition_time(struct ieee80211com *ic, int32_t val)
{
    struct ath_green_ap* green_ap = ic->ic_green_ap;
    if (green_ap == NULL) {
        return;
    }
    green_ap->ps_trans_time = val;
}EXPORT_SYMBOL(ath_green_ap_sc_set_transition_time);

/*
 * Function     : ath_green_ap_sc_get_transition_time
 * Description  : Get time value to make transition
 * Input        : Pointer to IC
 * Output       : Value
 *
 */
int32_t ath_green_ap_sc_get_transition_time(struct ieee80211com *ic)
{
    struct ath_green_ap* green_ap = ic->ic_green_ap;
    if (green_ap == NULL) {
        return 0;
    }
    return green_ap->ps_trans_time;
}EXPORT_SYMBOL(ath_green_ap_sc_get_transition_time);

/*
 * Function     : ath_green_ap_sc_get_on_time
 * Description  : Set the Power save on time
 * Input        : Pointer to IC, time value
 * Output       : Void
 *
 */
void ath_green_ap_sc_set_on_time(struct ieee80211com *ic, int32_t val )
{
    struct ath_green_ap *green_ap = ic->ic_green_ap;
    if (green_ap == NULL) {
        return;
    }
    green_ap->ps_on_time = val;
}EXPORT_SYMBOL(ath_green_ap_sc_set_on_time);

/*
 * Function     : ath_green_ap_sc_get_on_time
 * Description  : Get the configured power save on time
 * Input        : Pointer to IC
 * Output       : Time value
 *
 */
int32_t ath_green_ap_sc_get_on_time(struct ieee80211com *ic)
{
    struct ath_green_ap* green_ap = ic->ic_green_ap;
    if (green_ap == NULL) {
        return 0;
    }
    return green_ap->ps_on_time;
}EXPORT_SYMBOL(ath_green_ap_sc_get_on_time);

/*
 * Function     : null_ap_ps_on_off
 * Description  : Dummy Green-AP Function
 * Input        : Pointer to green_ap
 * Output       : Void
 *
 */
static u_int32_t null_ap_ps_on_off(void* arg, u_int32_t val)
{
    green_ap_ops_not_registered("ap_ps_on_off");
    return 0;
}

/*
 * Function     : null_is_vap_active
 * Description  : Dummy Green-AP Function
 * Input        :
 * Output       :
 *
 */
static u_int32_t null_is_vap_active(void* arg)
{
    green_ap_ops_not_registered("is_vap_active");
    return 0;
}

/*
 * Function     : null_get_current_channel
 * Description  : Dummy Green-AP Function
 * Input        :
 * Output       :
 *
 */
static u_int16_t null_get_current_channel(void* arg)
{
    green_ap_ops_not_registered("get_current_channel");
    return 0;
}

/*
 * Function     : null_get_current_channel_flags
 * Description  : Dummy Green-AP Function
 * Input        :
 * Output       :
 *
 */
static u_int32_t null_get_current_channel_flags(void* arg)
{
    green_ap_ops_not_registered("get_current_channel_flags");
    return 0;
}

/*
 * Function     : null_reset_dev
 * Description  : Dummy Green-AP Function
 * Input        :
 * Output       :
 *
 */
u_int32_t null_reset_dev(void* arg)
{
    green_ap_ops_not_registered("reset_dev");
    return 0;
}

/*
 * Function     : green_ap_init_dummy_function_table
 * Description  : Initialize Dummy Green-AP Function
 * Input        : Pointer to IC
 * Output       : Void
 *
 */
static void green_ap_init_dummy_function_table(struct ath_green_ap* green_ap)
{
    GREEN_AP_OPS* p_gpops = GET_GREEN_AP_OPS(green_ap);
    p_gpops->set_ap_ps_on_off = null_ap_ps_on_off;
    p_gpops->is_vap_active   = null_is_vap_active;
    p_gpops->get_current_channel = null_get_current_channel;
    p_gpops->get_current_channel_flags = null_get_current_channel_flags;
    p_gpops->reset_dev  = null_reset_dev;
}

/*
 * Function     : green_ap_register_funcs
 * Description  : Register Dummy Green-AP Function
 * Input        : Pointer to IC, Pointer to function table
 * Output       : Void
 *
 */
void green_ap_register_funcs(struct ath_green_ap* p_gap, GREEN_AP_OPS* p_ops)
{
    p_gap->green_ap_ops.set_ap_ps_on_off = p_ops->set_ap_ps_on_off;
    p_gap->green_ap_ops.is_vap_active    = p_ops->is_vap_active;
    p_gap->green_ap_ops.get_current_channel = p_ops->get_current_channel;
    p_gap->green_ap_ops.get_current_channel_flags = p_ops->get_current_channel_flags;
    p_gap->green_ap_ops.reset_dev = p_ops->reset_dev;
}EXPORT_SYMBOL(green_ap_register_funcs);

/*
 * Function     : ath_green_ap_sc_get_enable_print
 * Description  : Function to get Green AP debug print level
 * Input        : Pointer to IC
 * Output       : print level
 *
 */
int ath_green_ap_sc_get_enable_print(struct ieee80211com* ic)
{
    struct ath_green_ap* green_ap = ic->ic_green_ap;
    if (green_ap == NULL) {
        return -1;
    }
    return green_ap->dbg_print;
}

/*
 * Function     : ath_green_ap_sc_set_enable_print
 * Description  : Set the Green AP print level
 * Input        : Pointer to IC, Print level
 * Output       : Void
 *
 */
void ath_green_ap_sc_set_enable_print(struct ieee80211com* ic, int val)
{
    struct ath_green_ap* green_ap = ic->ic_green_ap;
    if (green_ap == NULL) {
        return;
    }
    green_ap->dbg_print = (val)?1:0;
}
