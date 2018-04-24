/*
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef _KTHREAD_H
#define _KTHREAD_H

#ifdef ATH_SUPPORT_HTC
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
#include <linux/autoconf.h>
#else
#include <generated/autoconf.h>
#endif
#else
#include <linux/config.h>
#endif


#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/wait.h>

#include <asm/unistd.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
#include <asm/semaphore.h>
#else
#include <linux/semaphore.h>
#endif

#include "osdep.h"
#include "osif_private.h"

#define HTC_THREAD_DELAY                          CONVERT_SEC_TO_SYSTEM_TIME(1)

#define MAX_TIME_EVENT_NUM                            16
#define MAX_TASKLET_EVENT_NUM                          4
#define MAX_DEFER_ITEM_NUM                            16

enum{
    DEFER_DONE       =0x0,
    DEFER_PENDING    =0x1,
};
#define WORK_ITEM_SET_MULTICAST                   0x0001
#define WORK_ITEM_SET_BEACON_DEFERED              0x0002
#define WORK_ITEM_SET_RX_STREAMMODE_TIMEOUT       0x0003
#define WORK_ITEM_SET_PS_DELIVER_EVENT            0x0004
#define WORK_ITEM_SET_TIMER_DELIVER_EVENT         0x0005
#define WORK_ITEM_SINGLE_ARG_DEFERED              0x0007
#define WORK_ITEM_SET_OS_SCHE_EVENT               0xffff    /* Common defer, keep last */

#define MAX_TXQ_BUF_NUM                    512

/* data structure for tx thread */
struct htc_tx_q
{
    struct sk_buff *htc_txbuf_q[MAX_TXQ_BUF_NUM];
    u_int16_t htc_txbuf_head;
    u_int16_t htc_txbuf_tail;
    int16_t htc_txbuf_count;

    wait_queue_head_t msg_wakeuplist;
    spinlock_t htc_txbuf_lock;
    volatile int msg_callback_flag;
    volatile int terminate;
    unsigned long last_jiffies;
};


typedef struct timer_event
{
    dummy_timer_func_t func;
    void *arg;    
} timer_event_t;

typedef struct tasklet
{
    htc_tq_struct_t  *tq;
    tasklet_callback_t func;
    void *ctx;
    int is_scheduled;
    int is_used;
} tasklet_t;

typedef struct defer
{
    defer_func_t func;
    void *param1;
    void *param2;
    void *param3;
    int func_id;
} defer_t;

typedef struct eventq
{
    timer_event_t timerEvents[MAX_TIME_EVENT_NUM];
    u_int8_t head;
    u_int8_t tail;
    int16_t count;

    tasklet_t taskletEvents[MAX_TASKLET_EVENT_NUM];
    int16_t tasklet_count;

    defer_t deferItems[MAX_DEFER_ITEM_NUM];
    u_int8_t defer_head;
    u_int8_t defer_tail;
    int16_t defer_count;

    wait_queue_head_t msg_wakeuplist;
    spinlock_t event_lock;
    spinlock_t tasklet_lock;
    volatile int msg_callback_flag;
    volatile int terminate;
    volatile int stopping;
} eventq_t;

/* prototypes */
int ath_create_htc_thread(osdev_t osdev);
void ath_terminate_htc_thread(osdev_t osdev);
void ath_htc_thread_stopping(osdev_t osdev);
int ath_put_defer_item(osdev_t osdev, defer_func_t func, int func_id, void *param1, void *param2, void *param3);

void ath_wakeup_htc_thread(struct eventq *event_q);
int ath_htc_thread(void *data);

void ath_register_htc_thread_callback(osdev_t osdev);


/* htc tx thread */
void ath_wakeup_htc_tx_thread(void);
int ath_put_txbuf(struct sk_buff *skb);
void ath_htc_tx_flush_txbuf(void);
int ath_create_htc_tx_thread(struct net_device *netdev);
void ath_terminate_htc_tx_thread(void);

#endif /* #ifdef ATH_SUPPORT_HTC */
#endif
