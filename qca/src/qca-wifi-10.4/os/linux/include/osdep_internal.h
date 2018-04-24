/*
 *  Copyright (c) 2005 Atheros Communications Inc.  All rights reserved.
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


#ifndef _ATH_LINUX_OSDEP_H
#define _ATH_LINUX_OSDEP_H

#include "wlan_opts.h"

#ifdef ADF_SUPPORT
#include "osdep_adf_internal.h"
#else /* Non ADF osdep definations */

#include "ah_osdep.h"
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
#include <linux/module.h>
#include <linux/usb.h>
#include <linux/spinlock.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <sys/queue.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <linux/inetdevice.h>
#include <linux/ipv6.h>
#include <linux/if_vlan.h>
#include <net/ipv6.h>
#include <net/ndisc.h>

#include <asm/checksum.h>
#include <asm/byteorder.h>
#include <asm/scatterlist.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
#include <asm/semaphore.h>
#else
#include <linux/semaphore.h>
#endif

#include <net/inet_ecn.h>                       /* XXX for TOS */

#include <linux/ratelimit.h>

#include "if_llc.h"
#include "if_upperproto.h"

#define OS_SET_WDTIMEOUT(__sc, __timeo) \
{\
    (__sc->sc_osdev->netdev)->watchdog_timeo = (__timeo);\
}

#define OS_CLR_NETDEV_FLAG(__sc, __flag)\
{\
    (__sc->sc_osdev->netdev)->flags &= ~(__flag);\
}
#define OS_NETIF_WAKE_QUEUE(__sc)\
{\
    netif_wake_queue((__sc->sc_osdev->netdev));\
}
#define OS_NETIF_STOP_QUEUE(__sc)\
{\
    netif_stop_queue((__sc->sc_osdev->netdev));\
}
#define OS_NETDEV_UPDATE_TRANS(__sc)\
{\
    (__sc->sc_osdev->netdev)->trans_start = jiffies;\
}

#ifndef ATH_SUPPORT_HTC
#include "asf_amem.h"      /* amalloc, afree */
#endif

#ifndef REMOVE_PKT_LOG
#include "ah_pktlog.h"
#endif

#ifdef ATH_SUPPORT_HTC
#include "a_types.h"
#include "a_osapi.h"
#include "htc.h"
#endif

#ifdef AR9100
#include <ar9100.h>
#endif /* AR9100 */

#define INLINE  __inline

#ifndef __ahdecl
#ifdef __i386__
#define __ahdecl    __attribute__((regparm(0)))
#else
#define __ahdecl
#endif
#endif

/* UNREFERENCED_PARAMETER - provide a dummy reference */
#define UNREFERENCED_PARAMETER(an) ((void) (an))

#ifdef AR9100
/*
 * Howl needs DDR FIFO flush before any desc/dma data can be read.
 */
#define ATH_FLUSH_FIFO    ar9100_flush_wmac
#else
#define ATH_FLUSH_FIFO()
#endif

#define OS_LOG_DBGPRINT(_xfmt, ...)

#if ATH_DEBUG
#ifndef ASSERT
#define ASSERT(exp) do {    \
    if (unlikely(!(exp))) {    \
        BUG();                \
    }                        \
} while (0)
#endif
#else
#define ASSERT(exp)
#endif /* ATH_DEBUG */

/*
 * Map Linux spin locks to OS independent names
 */
#define spin_lock_dpc(a)    \
    if (irqs_disabled()) {  \
        spin_lock(a);       \
    } else {                \
        spin_lock_bh(a);    \
    }
#define spin_unlock_dpc(a)  \
    if (irqs_disabled()) {  \
        spin_unlock(a);     \
    } else {                \
        spin_unlock_bh(a);  \
    }

#define spin_lock_destroy(a)

#define os_tasklet_lock(a, b)        spin_lock_irqsave(a, b)
#define os_tasklet_unlock(a, b)      spin_unlock_irqrestore(a, b)


/*
** Need to define byte order based on the CPU configuration.
*/
#define _LITTLE_ENDIAN  1234
#define _BIG_ENDIAN 4321
#ifdef CONFIG_CPU_BIG_ENDIAN
    #define _BYTE_ORDER    _BIG_ENDIAN
#else
    #define _BYTE_ORDER    _LITTLE_ENDIAN
#endif

/*
 * Deduce if tasklets are available.  If not then
 * fall back to using the immediate work queue.
 */
#include <linux/interrupt.h>
#ifdef DECLARE_TASKLET          /* native tasklets */
#define tq_struct tasklet_struct
#define ATH_INIT_TQUEUE(a,b,c)      tasklet_init((a),(b),(unsigned long)(c))
#define ATH_SCHEDULE_TQUEUE(a,b)    tasklet_schedule((a))
typedef unsigned long TQUEUE_ARG;
#define mark_bh(a)
#else                   /* immediate work queue */
#define ATH_INIT_TQUEUE(a,b,c)      INIT_TQUEUE(a,b,c)
#define ATH_SCHEDULE_TQUEUE(a,b) do {       \
    *(b) |= queue_task((a), &tq_immediate); \
} while(0)
typedef void *TQUEUE_ARG;
#define tasklet_disable(t)  do { (void) t; local_bh_disable(); } while (0)
#define tasklet_enable(t)   do { (void) t; local_bh_enable(); } while (0)
#endif /* !DECLARE_TASKLET */

#include <linux/sched.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,41)
#include <linux/tqueue.h>
#define ATH_WORK_THREAD            tq_struct
#define ATH_SCHEDULE_TASK(t)        schedule_task((t))
#define ATH_INIT_SCHED_TASK(t, f, d)    do { memset((t),0,sizeof(struct tq_struct)); \
                        (t)->routine = (void (*)(void*)) (f); \
                        (t)->data=(void *) (d); } while (0)
#define ATH_FLUSH_TASKS            flush_scheduled_tasks
#else
#include <linux/workqueue.h>
#define ATH_SCHEDULE_TASK(t)        schedule_work((t))
//#define ATH_INIT_SCHED_TASK(t, f, d)    (DECLARE_WORK((t), (f), (d)))
#define ATH_INIT_SCHED_TASK(t, f, d)    do { memset(((void *) (t)),0,sizeof(struct work_struct)); \
        PREPARE_WORK((t),((void (*)(void*))(f)),((void *) (d))); } while (0)
#define ATH_WORK_THREAD            work_struct
#define    ATH_FLUSH_TASKS            flush_scheduled_work
#endif /* KERNEL_VERSION < 2.5.41 */

/*
 * Guess how the interrupt handler should work.
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30))
#if !defined(IRQ_NONE)
typedef void irqreturn_t;
#define IRQ_NONE
#define IRQ_HANDLED
#endif /* !defined(IRQ_NONE) */
#endif

#ifndef SET_MODULE_OWNER
#define SET_MODULE_OWNER(dev) do {      \
    dev->owner = THIS_MODULE;       \
} while (0)
#endif

#ifndef SET_NETDEV_DEV
#define SET_NETDEV_DEV(ndev, pdev)
#endif

/*
 * Deal with the sysctl handler api changing.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8)
#define ATH_SYSCTL_DECL(f, ctl, write, filp, buffer, lenp, ppos) \
    f(ctl_table *ctl, int write, struct file *filp, void *buffer, \
        size_t *lenp)
#define ATH_SYSCTL_PROC_DOINTVEC(ctl, write, filp, buffer, lenp, ppos) \
    proc_dointvec(ctl, write, filp, buffer, lenp)
#define ATH_SYSCTL_PROC_DOSTRING(ctl, write, filp, buffer, lenp, ppos) \
    proc_dostring(ctl, write, filp, buffer, lenp)
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#define ATH_SYSCTL_DECL(f, ctl, write, filp, buffer, lenp, ppos) \
    f(ctl_table *ctl, int write, struct file *filp, void *buffer,\
        size_t *lenp, loff_t *ppos)
#define ATH_SYSCTL_PROC_DOINTVEC(ctl, write, filp, buffer, lenp, ppos) \
    proc_dointvec(ctl, write, filp, buffer, lenp, ppos)
#define ATH_SYSCTL_PROC_DOSTRING(ctl, write, filp, buffer, lenp, ppos) \
    proc_dostring(ctl, write, filp, buffer, lenp, ppos)
#else
#define ATH_SYSCTL_DECL(f, ctl, write, filp, buffer, lenp, ppos) \
    f(ctl_table *ctl, int write, struct file *filp, void *buffer,\
        size_t *lenp, loff_t *ppos)
#define ATH_SYSCTL_PROC_DOINTVEC(ctl, write, filp, buffer, lenp, ppos) \
    proc_dointvec(ctl, write, buffer, lenp, ppos)
#define ATH_SYSCTL_PROC_DOSTRING(ctl, write, filp, buffer, lenp, ppos) \
    proc_dostring(ctl, write, buffer, lenp, ppos)
#endif

#endif

/*
 * Byte Order stuff
 */
#define    le16toh(_x)    le16_to_cpu(_x)
#define    htole16(_x)    cpu_to_le16(_x)
#define    be16toh(_x)    be16_to_cpu(_x)
#define    htobe16(_x)    cpu_to_be16(_x)
#define    le32toh(_x)    le32_to_cpu(_x)
#define    htole32(_x)    cpu_to_le32(_x)
#define    be32toh(_x)    be32_to_cpu(_x)
#define    htobe32(_x)    cpu_to_be32(_x)
#define    le64toh(_x)    le64_to_cpu(_x)
#define    htole64(_x)    cpu_to_le64(_x)
#define    be64toh(_x)    be64_to_cpu(_x)
#define    htobe64(_x)    cpu_to_be64(_x)

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE  1
#endif
#define EOK    (0)


#define IP_PRI_SHIFT        5

#ifndef IPV6_VERSION_MASK
#define IPV6_VERSION_MASK           0xF0000000
#endif
#ifndef IPV6_PRIORITY_MASK
#define IPV6_PRIORITY_MASK          0x0FF00000
#endif
#ifndef IPV6_FLOWLABEL_MASK
#define IPV6_FLOWLABEL_MASK         0x000FFFFF
#endif
#ifndef IPV6_VERSION_SHIFT
#define IPV6_VERSION_SHIFT          28
#endif
#ifndef IPV6_PRIORITY_SHIFT
#define IPV6_PRIORITY_SHIFT         20
#endif
#ifndef IPV6_FLOWLABEL_SHIFT
#define IPV6_FLOWLABEL_SHIFT        0
#endif

#ifndef ARPHRD_IEEE80211
#define ARPHRD_IEEE80211 801		/* IEEE 802.11.  */
#endif

#define MAX_TX_RX_PACKET_SIZE     2500

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
#ifndef __bool_already_defined__
#define __bool_already_defined__
/* boolean */
typedef enum bool {
    false = 0,
    true  = 1,
} bool;
#endif /* __bool_already_defined__ */
#endif


static INLINE const char *
ether_sprintf(const uint8_t mac[6])
{
        static char buf[32];

        snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return buf;
}

typedef unsigned int rwlock_state_t;

/*
 * For packet capture, define the same physical layer packet header
 * structure as used in the wlan-ng driver
 */
typedef struct {
        u_int32_t did;
        u_int16_t status;
        u_int16_t len;
        u_int32_t data;
} p80211item_uint32_t;
typedef struct {
        u_int32_t msgcode;
        u_int32_t msglen;
#define WLAN_DEVNAMELEN_MAX 16
        u_int8_t devname[WLAN_DEVNAMELEN_MAX];
        p80211item_uint32_t hosttime;
        p80211item_uint32_t mactime;
        p80211item_uint32_t channel;
        p80211item_uint32_t rssi;
        p80211item_uint32_t sq;
        p80211item_uint32_t signal;
        p80211item_uint32_t noise;
        p80211item_uint32_t rate;
        p80211item_uint32_t istx;
        p80211item_uint32_t frmlen;
} wlan_ng_prism2_header;


/*
 * Transmitted frames have the following information
 * held in the sk_buff control buffer.  This is used to
 * communicate various inter-procedural state that needs
 * to be associated with the frame for the duration of
 * it's existence.
 *
 * NB: sizeof(cb) == 48 and the vlan code grabs the first
 *     8 bytes so we reserve/avoid it.
 */
struct ieee80211_cb {
        u_int8_t                vlan[8];        /* reserve for vlan tag info */
        struct ieee80211_node   *ni;
        void                    *context;       /* pointer to context area */
        u_int32_t               flags;
#define M_LINK0         0x01                    /* frame needs WEP encryption */
#define M_FF            0x02                    /* fast frame */
#define M_PWR_SAV       0x04                    /* bypass power save handling */
#define M_UAPSD         0x08                    /* frame flagged for u-apsd handling */
#define M_EAPOL         0x10                    /* frame flagged for EAPOL handling */
#define M_AMSDU         0x20                    /* frame flagged for AMSDU handling */
#define M_NULL_PWR_SAV  0x40                    /* null data with power save bit on */
#define M_PROBING       0x80                    /* frame flagged as a probing one */
#define M_ERROR         0x100                   /* frame flagged as error */
#define M_MOREDATA      0x200                   /* more data flag */
#define M_ENCAP_DONE    0x400                   /* already encaped as 802.11 frame */
#define M_ISCLONED		0x800					/* this skb is cloned */
#if ATH_SUPPORT_WIFIPOS
#define M_LOCATION      0x1000                  /* already encaped as 802.11 frame */
#define M_LOCATION_KEEPALIVE      0x2000        /* locationing keepalive frame  */
#endif
#ifdef ATH_SUPPORT_WAPI
#define M_WAI           0x4000
#endif
#if LMAC_SUPPORT_POWERSAVE_QUEUE
#define M_LEGACY_PS     0x8000
#endif
#define M_DHCP          0x10000                  /* frame flagged as a DHCP  */
#define M_QOSNULL       0x20000                  /* frame flagged as QOS NULL */
#define M_ARP           0x40000                  /* frame flagged as a ARP  */
        u_int8_t                u_tid;          /* user priority from vlan/ip tos   */
        u_int8_t                exemptiontype;  /* exemption type of this frame (0,1,2)*/
        u_int8_t                type;  /* type of this frame */
#if defined(ATH_SUPPORT_VOWEXT) || defined(ATH_SUPPORT_IQUE) || UMAC_SUPPORT_NAWDS != 0
        u_int8_t		firstxmit;
        u_int32_t		firstxmitts;
#endif
#if defined(ATH_SUPPORT_P2P) || (defined(ATH_SUPPORT_DEFERRED_NODE_CLEANUP) && ATH_SUPPORT_DEFERRED_NODE_CLEANUP !=0)
        void            *complete_handler;     /* complete handler */
        void            *complete_handler_arg; /* complete handler arg */
#endif
#if defined(ATH_SUPPORT_IQUE)
	u_int32_t		qin_timestamp;           /* timestamp of buffer's entry into queue */
#endif

#if USE_MULTIPLE_BUFFER_RCV
        size_t      buf_size;
#endif
        u_int8_t       offset;
};

#define MGMT_UMAC_CB_SIZE sizeof(struct ieee80211_cb)

#define M_FLAG_SET(_skb, _flag) \
        (((struct ieee80211_cb *)(_skb)->cb)->flags |= (_flag))
#define M_FLAG_CLR(_skb, _flag) \
        (((struct ieee80211_cb *)(_skb)->cb)->flags &= ~(_flag))
#define M_FLAG_GET(_skb, _flag) \
        (((struct ieee80211_cb *)(_skb)->cb)->flags & (_flag))
#define M_FLAG_KEEP_ONLY(_skb, _flag) \
        (((struct ieee80211_cb *)(_skb)->cb)->flags &= (_flag))

#define M_PWR_SAV_SET(skb) M_FLAG_SET((skb), M_PWR_SAV)
#define M_PWR_SAV_CLR(skb) M_FLAG_CLR((skb), M_PWR_SAV)
#define M_PWR_SAV_GET(skb) M_FLAG_GET((skb), M_PWR_SAV)

#define M_NULL_PWR_SAV_SET(skb) M_FLAG_SET((skb), M_NULL_PWR_SAV)
#define M_NULL_PWR_SAV_CLR(skb) M_FLAG_CLR((skb), M_NULL_PWR_SAV)
#define M_NULL_PWR_SAV_GET(skb) M_FLAG_GET((skb), M_NULL_PWR_SAV)

#define M_MOREDATA_SET(skb) M_FLAG_SET((skb), M_MOREDATA)
#define M_MOREDATA_CLR(skb) M_FLAG_CLR((skb), M_MOREDATA)
#define M_MOREDATA_GET(skb) M_FLAG_GET((skb), M_MOREDATA)

#define M_PROBING_SET(skb)  M_FLAG_SET((skb), M_PROBING)
#define M_PROBING_CLR(skb)  M_FLAG_CLR((skb), M_PROBING)
#define M_PROBING_GET(skb)  M_FLAG_GET((skb), M_PROBING)

#define M_CLONED_SET(skb)  M_FLAG_SET((skb), M_ISCLONED)
#define M_CLONED_CLR(skb)  M_FLAG_CLR((skb), M_ISCLONED)
#define M_CLONED_GET(skb)  M_FLAG_GET((skb), M_ISCLONED)

#if ATH_SUPPORT_WIFIPOS
#define M_LOC_SET(skb)  M_FLAG_SET((skb), M_LOCATION)
#define M_LOC_CLR(skb)  M_FLAG_CLR((skb), M_LOCATION)
#define M_LOC_GET(skb)  M_FLAG_GET((skb), M_LOCATION)

#define M_LOC_KEEPALIVE_SET(skb)  M_FLAG_SET((skb), M_LOCATION_KEEPALIVE)
#define M_LOC_KEEPALIVE_GET(skb)  M_FLAG_GET((skb), M_LOCATION_KEEPALIVE)
#endif
/*
 * Skbufs on the power save queue are tagged with an age and
 * timed out.  We reuse the hardware checksum field in the
 * mbuf packet header to store this data.
 * XXX use private cb area
 */
#define M_AGE_SET(skb,v)        (skb->csum = v)
#define M_AGE_GET(skb)          (skb->csum)
#define M_AGE_SUB(skb,adj)      (skb->csum -= adj)


#define OS_ATOMIC_CMPXCHG(_Counter, _cmp, _xchg)   cmpxchg((int32_t*)(_Counter), _cmp, _xchg)

#ifdef CONFIG_ARM
    /*
    ** This is in support of XScale build.  They have a limit on the udelay
    ** value, so we have to make sure we don't approach the limit
    */

static INLINE void OS_DELAY(unsigned long delay)
{
    unsigned long    mticks;
    unsigned long    leftover;
    int                i;

    /*
    ** slice into 1024 usec chunks (simplifies calculation)
    */

    mticks = delay >> 10;
    leftover = delay - (mticks << 10);

    for(i=0;i<mticks;i++)
    {
        udelay(1024);
    }

    udelay(leftover);
}

#else
    /*
     * Normal Delay functions. Time specified in microseconds.
     */
#ifndef OS_DELAY
    #define OS_DELAY(_us)            udelay(_us)
#endif

#endif

#define OS_SLEEP(_us)            schedule_timeout_uninterruptible(usecs_to_jiffies(_us))
#define OS_SLEEP_INTERRUPTIBLE(_us)            schedule_timeout_interruptible(usecs_to_jiffies(_us))

#define OS_MEMCPY(_dst, _src, _len)        memcpy(_dst, _src, _len)
#define OS_MEMMOVE(_dst, _src, _len)      memmove(_dst, _src, _len)
#define OS_MEMZERO(_buf, _len)            memset(_buf, 0, _len)
#define OS_MEMSET(_buf, _ch, _len)        memset(_buf, _ch, _len)
#define OS_MEMCMP(_mem1, _mem2, _len)    memcmp(_mem1, _mem2, _len)

#ifdef __ubicom32__
static inline void * OS_MACCPY(void *_mac1, const void *_mac2)
{
    u8 *mac1 = _mac1;
    const u8 *mac2 = _mac2;
    mac1[0] = mac2[0];
    mac1[1] = mac2[1];
    mac1[2] = mac2[2];
    mac1[3] = mac2[3];
    mac1[4] = mac2[4];
    mac1[5] = mac2[5];
    return mac1;
}

static inline int OS_MACCMP(const void *_mac1, const void *_mac2)
{
    const u8 *mac1 = _mac1;
    const u8 *mac2 = _mac2;
    return ((mac1[0] ^ mac2[0]) | (mac1[1] ^ mac2[1]) | (mac1[2] ^ mac2[2]) | (mac1[3] ^ mac2[3]) | (mac1[4] ^ mac2[4]) | (mac1[5] ^ mac2[5]));
}
#endif

#define OS_STRLEN(s)                    strlen(s)
/*
 * Locking interface for node
 */
#ifdef ATH_USB
typedef rwlock_t usb_readwrite_lock_t;
#endif

#define OS_RWLOCK_INIT(_rwl)        rwlock_init(_rwl)
#define OS_RWLOCK_DESTROY(_nt)

#ifdef CONFIG_SMP
/* Depent on the context's status. */
static INLINE void OS_RWLOCK_READ_LOCK(rwlock_t *rwl, rwlock_state_t *lock_state)
{
    if (irqs_disabled()) {
        read_lock(rwl);
    } else {
        read_lock_bh(rwl);
    }
}

static INLINE void OS_RWLOCK_WRITE_LOCK(rwlock_t *rwl, rwlock_state_t *lock_state)
{
    if (irqs_disabled()) {
        write_lock(rwl);
    } else {
        write_lock_bh(rwl);
    }
}

static INLINE void OS_RWLOCK_READ_UNLOCK(rwlock_t *rwl, rwlock_state_t *lock_state)
{
    if (irqs_disabled()) {
        read_unlock(rwl);
    } else {
        read_unlock_bh(rwl);
    }
}

static INLINE void OS_RWLOCK_WRITE_UNLOCK(rwlock_t *rwl, rwlock_state_t *lock_state)
{
    if (irqs_disabled()) {
        write_unlock(rwl);
    } else {
        write_unlock_bh(rwl);
    }
}
#else
static INLINE void OS_RWLOCK_READ_LOCK(rwlock_t *rwl, rwlock_state_t *lock_state)
{
    read_lock(rwl);
}

static INLINE void OS_RWLOCK_WRITE_LOCK(rwlock_t *rwl, rwlock_state_t *lock_state)
{
    write_lock(rwl);
}

static INLINE void OS_RWLOCK_READ_UNLOCK(rwlock_t *rwl, rwlock_state_t *lock_state)
{
    read_unlock(rwl);
}

static INLINE void OS_RWLOCK_WRITE_UNLOCK(rwlock_t *rwl, rwlock_state_t *lock_state)
{
    write_unlock(rwl);
}
#endif

static INLINE void OS_RWLOCK_READ_LOCK_BH(rwlock_t *rwl, rwlock_state_t *lock_state)
{
    read_lock_bh(rwl);
}

static INLINE void OS_RWLOCK_WRITE_LOCK_BH(rwlock_t *rwl, rwlock_state_t *lock_state)
{
    write_lock_bh(rwl);
}

static INLINE void OS_RWLOCK_READ_UNLOCK_BH(rwlock_t *rwl, rwlock_state_t *lock_state)
{
    read_unlock_bh(rwl);
}

static INLINE void OS_RWLOCK_WRITE_UNLOCK_BH(rwlock_t *rwl, rwlock_state_t *lock_state)
{
    write_unlock_bh(rwl);
}

/* Irqsave/restore version */
static INLINE void OS_RWLOCK_READ_LOCK_IRQSAVE(
    rwlock_t *rwl, rwlock_state_t *lock_state, unsigned long flags)
{
    read_lock_irqsave(rwl, flags);
}

static INLINE void OS_RWLOCK_WRITE_LOCK_IRQSAVE(
    rwlock_t *rwl, rwlock_state_t *lock_state, unsigned long flags)
{
    write_lock_irqsave(rwl, flags);
}

static INLINE void OS_RWLOCK_READ_UNLOCK_IRQRESTORE(
    rwlock_t *rwl, rwlock_state_t *lock_state, unsigned long flags)
{
    read_unlock_irqrestore(rwl, flags);
}

static INLINE void OS_RWLOCK_WRITE_UNLOCK_IRQRESTORE(
    rwlock_t *rwl, rwlock_state_t *lock_state, unsigned long flags)
{
    write_unlock_irqrestore(rwl, flags);
}

/* Calculate the modulo with the following restrictions:
    lowest 10 bits of div is zero.
    div is at most 20 bits.

Theory for the math.
    Suppose x = A + B
    Then x % r = ((A % r) + B) % r

    For our case, we let A be the top 32-bits of x which is non-zero.
    Then x = (2^22 * a) + b.
*/
static INLINE u_int32_t OS_MOD64_TBTT_OFFSET(u_int64_t num64, u_int32_t div)
{

    u_int32_t remainder_last10bits = (u_int32_t)num64 & 0x003FF;

    /* Remove the low 10 bits. */
    div = div >> 10;
    num64 = num64 >> 10;

    {
        /* Get the mod of the top 32 bits */
        u_int32_t num_hi = (u_int32_t)(num64 >> 22);
#define BITS_22_MASK    0x003FFFFF
#define BITS_10_MASK    0x000003FF
        u_int32_t num_lo = (u_int32_t)(num64) & BITS_22_MASK;

        u_int32_t remainder_hi = num_hi % div;
        u_int32_t remainder_lo = num_lo;

        u_int32_t remainder32 = (remainder_hi << 22) + remainder_lo;

        remainder32 = remainder32 % div;
        /* Put back the last 10 bits */
        remainder32 = (remainder32 << 10) + remainder_last10bits;

        return(remainder32);
    }
}

/*
 * System time interface
 */
typedef unsigned long    systime_t;
typedef unsigned long    systick_t;

static INLINE systime_t
OS_GET_TIMESTAMP(void)
{
    return jiffies;  /* Fix double conversion from jiffies to ms */
}

static INLINE systick_t
OS_GET_TICKS(void)
{
    return jiffies;
}

#define CONVERT_SYSTEM_TIME_TO_MS(_t)        jiffies_to_msecs(_t)
#define CONVERT_SYSTEM_TIME_TO_SEC(_t)        (jiffies_to_msecs(_t) / 1000)
#define CONVERT_SEC_TO_SYSTEM_TIME(_t)        ((_t) * HZ)
#define CONVERT_MS_TO_SYSTEM_TIME(_t)        ((_t) * HZ / 1000)

#ifdef ATH_USB

/* USB Endpoint definition */
#define USB_WLAN_TX_PIPE                    1
#define USB_WLAN_RX_PIPE                    2
#define USB_REG_IN_PIPE                     3
#define USB_REG_OUT_PIPE                    4
#define USB_WLAN_HP_TX_PIPE                 5
#define USB_WLAN_MP_TX_PIPE                 6

#define FIRMWARE_DOWNLOAD       0x30
#define FIRMWARE_DOWNLOAD_COMP  0x31
#define FIRMWARE_CONFIRM        0x32
#define ZM_FIRMWARE_WLAN_ADDR               0x501000
#define ZM_FIRMWARE_TEXT_ADDR		        0x903000
#define ZM_FIRMWARE_MAGPIE_TEXT_ADDR		0x906000

//#define ZM_USB_WAR_EP_INTTOBULK             1
#define ZM_USB_WAR_EP3_INTTOBULK            1

#define ZM_MAX_RX_BUFFER_SIZE               16384
//#define ZM_DONT_COPY_RX_BUFFER              1

#define ZM_USB_STREAM_MODE      1
#define ZM_USB_TX_STREAM_MODE 1
#if ZM_USB_TX_STREAM_MODE == 1
#define ZM_MAX_TX_AGGREGATE_NUM             20
#define ZM_USB_TX_BUF_SIZE                  32768
#ifdef BUILD_X86
#define ZM_MAX_TX_URB_NUM                   4             /* Offload the HIF queue effort to HCD. Compare to PB44 solution, URB recycle timing is more slower
                                                             in X86 solution and this make HIF queue is full frequently then start to drop packet. */
#else
#define ZM_MAX_TX_URB_NUM                   2
#endif
#define ZM_L1_TX_AGGREGATE_NUM              10
#define ZM_L1_TX_PACKET_THR                 5000
#define ZM_1MS_SHIFT_BITS                   18
#else
#define ZM_USB_TX_BUF_SIZE                  2048
#define ZM_MAX_TX_URB_NUM                   8
#endif

#define ZM_USB_REG_MAX_BUF_SIZE             64  // = MAX_MSGIN_BUF_SIZE
#define ZM_MAX_RX_URB_NUM                   2
#define ZM_MAX_TX_BUF_NUM                   256 //1024
#define ZM_MAX_TX_BUF_NUM_K2                128

#define ZM_MAX_USB_IN_NUM                   16

#define MAX_CMD_URB                         12   //4

#define ZM_RX_URB_BUF_ALLOC_TIMER           100

//#define ATH_USB_STREAM_MODE_TAG_LEN         4
#define ATH_USB_STREAM_MODE_TAG             0x4e00
//#define ATH_MAX_USB_IN_TRANSFER_SIZE        8192
//#define AHT_MAX_PKT_NUM_IN_TRANSFER         8

//#define ATH_USB_MAX_BUF_SIZE        8192
//#define ATH_MAX_TX_AGGREGATE_NUM    3
#define ZM_MAX_USB_URB_FAIL_COUNT             1

#define urb_t                       struct urb

typedef struct UsbTxQ
{
    struct sk_buff* buf; //qdf_nbuf_t      buf;
//    uint8_t       hdr[80];
    uint16_t      hdrlen;
//    uint8_t       snap[8];
    uint16_t      snapLen;
//    uint8_t       tail[16];
    uint16_t      tailLen;
    uint16_t      offset;
    uint32_t      timeStamp;
} UsbTxQ_t;

//typedef struct UsbCmdOutQ
//{
//    struct sk_buff* buf; //qdf_nbuf_t      buf;
//}UsbCmdOutQ;

typedef struct UsbUrbContext
{
    u_int8_t        index;
    u_int8_t        inUse;
    u_int16_t       flags;
    struct sk_buff* buf; //qdf_nbuf_t      buf;
    struct _NIC_DEV *osdev;
    urb_t           *urb;
}UsbUrbContext_t;

typedef struct _UsbRxUrbContext {
    u_int8_t        index;
    u_int8_t        inUse;
    u_int8_t        failcnt;
    struct sk_buff  *buf;
    struct _NIC_DEV *osdev;
    urb_t           *WlanRxDataUrb;
    uint8_t       *rxUsbBuf;
} UsbRxUrbContext;

typedef struct _UsbTxUrbContext {
    u_int8_t         index;
    u_int8_t         inUse;
    u_int16_t        delay_free;
    struct sk_buff   *buf;
    struct _NIC_DEV  *osdev;
    void             *pipe;
    urb_t            *urb;
#if ZM_USB_TX_STREAM_MODE == 1
    uint8_t        *txUsbBuf;
#endif
} UsbTxUrbContext;

typedef struct _hif_usb_tx_pipe {
    uint8_t               TxPipeNum;
    UsbTxQ_t                UsbTxBufQ[ZM_MAX_TX_BUF_NUM];
    uint16_t              TxBufHead;
    uint16_t              TxBufTail;
    uint16_t              TxBufCnt;
    uint16_t              TxUrbHead;
    uint16_t              TxUrbTail;
    uint16_t              TxUrbCnt;
    UsbTxUrbContext         TxUrbCtx[ZM_MAX_TX_URB_NUM];
    usb_complete_t          TxUrbCompleteCb;
} HIFUSBTxPipe;

typedef struct ath_usb_rx_info
{
    u_int16_t pkt_len;
    u_int16_t offset;
} ath_usb_rx_info_t;

typedef int (*os_intr_func)(void *);

#endif /* #ifdef ATH_USB */

typedef struct _NIC_DEV * osdev_t;

#ifdef ATH_SUPPORT_HTC
typedef void (*tasklet_callback_t)(void *ctx);

typedef struct htc_tq_struct
{
    struct tq_struct tq;
    osdev_t osdev;
} htc_tq_struct_t;

typedef void (*defer_func_t)(void *);
typedef void __ahdecl (*defer_func_t_write_reg_single)(void *, u_int, u_int32_t); /*cast function pointer for write_reg_single*/
typedef void (*defer_func_t_ps_deliver_event)(void *, void *); /*cast function pointer for ps_deliver_event*/
typedef void (*defer_func_t_timer_deliver_event)(void *, void *); /*cast function pointer for timer_deliver_event*/
typedef void (*defer_func_t_os_sche_event)(void *, void *); /*cast function pointer for os_sche_event*/

#endif /* #ifdef ATH_SUPPORT_HTC */

/*
 * Definition of OS-dependent device structure.
 * It'll be opaque to the actual ATH layer.
 */
struct _NIC_DEV {
    void                *bdev;      /* bus device handle */
    struct net_device   *netdev;    /* net device handle (wifi%d) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
    struct rtnl_link_stats64 devstats;
#else
    struct net_device_stats devstats;
#endif
    HAL_BUS_CONTEXT     bc;

#if ATH_PERF_PWR_OFFLOAD
    struct device       *device;    /* generic device */
    wait_queue_head_t   event_queue;
    unsigned int        wmi_timeout;
#endif /* PERF_PWR_OFFLOAD */

#if !NO_SIMPLE_CONFIG
    u_int32_t           sc_push_button_dur;
#endif

};

#define OS_ATH_GET_NETDEV(__sc) ((__sc)->sc_osdev->netdev)

#ifdef ATH_SUPPORT_HTC

static INLINE void
ATHUSB_INIT_TQUEUE(osdev_t                  osdev,
                   htc_tq_struct_t          *ptasklet,
                   tasklet_callback_t       func,
                   void                     *ctx)
{
    ptasklet->osdev = osdev;
    osdev->htcAddTasklet(osdev, ptasklet, func, ctx);
}

static INLINE void
ATHUSB_SCHEDULE_TQUEUE(htc_tq_struct_t    *ptasklet)
{
    osdev_t osdev = ptasklet->osdev;

     osdev->htcScheduleTasklet(osdev, ptasklet);
}

static INLINE void
ATHUSB_FREE_TQUEUE(osdev_t            osdev,
                   htc_tq_struct_t    *ptasklet)
{
    osdev->htcDelTasklet(osdev, ptasklet);

}
#endif /* #ifdef ATH_SUPPORT_HTC */

#ifndef ATH_SUPPORT_HTC
#define OS_MALLOC(osdev, size, gfp)                                          \
    (                                                                        \
        {                                                                    \
            void *p = osdev; /* avoid compiler warning about unused vars */  \
            if (p) p = 0;                                                    \
            amalloc(size);                                                   \
        }                                                                    \
    )
#define OS_FREE(_p) afree(_p)
#else /* #ifndef ATH_SUPPORT_HTC */
static INLINE unsigned char *
OS_MALLOC(osdev_t pNicDev, unsigned long ulSizeInBytes, int gfp)
{
    return kmalloc(ulSizeInBytes, gfp);
}
#define OS_FREE(_p)                       do { kfree(_p); _p = 0; } while (0)
#endif

#define OS_MALLOC_WITH_TAG(_ppMem, _size, _tag)    do {    \
    *(_ppMem) = kmalloc(_size, GFP_ATOMIC);                \
} while (0)

#define OS_FREE_WITH_TAG(_pMem, _size)    kfree(_pMem)


#if defined (ATH_PCI)
#include <if_ath_pci.h>
#elif defined ATH_AHB
#include <if_ath_ahb.h>
#elif defined (ATH_USB)
#include <if_ath_usb.h>
#else
#error "No bus type is specified"
#endif

typedef dma_addr_t * dma_context_t;

#define OS_DMA_MEM_CONTEXT(context)         \
    dma_addr_t   context;

#define OS_GET_DMA_MEM_CONTEXT(var, field)  \
    &(var->field)

#define OS_COPY_DMA_MEM_CONTEXT(dst, src)   \
    *dst = *src

#define OS_ZERO_DMA_MEM_CONTEXT(context)   \
    *context = 0

void bus_read_cachesize(osdev_t, int *csz, int bustype);

static INLINE void *
OS_MALLOC_CONSISTENT(osdev_t osdev, u_int32_t size, dma_addr_t *pa, dma_context_t context,
                     u_int32_t shmemalloc_retry)
{
    return bus_alloc_consistent(osdev, size, pa);
}

static INLINE void
OS_FREE_CONSISTENT(osdev_t osdev, u_int32_t size,
                   void *vaddr, dma_addr_t pa, dma_context_t context)
{
    bus_free_consistent(osdev, size, vaddr, pa);
}

static INLINE void *
OS_MALLOC_NONCONSISTENT(osdev_t osdev, u_int32_t size, dma_addr_t *pa, dma_context_t context,
                     u_int32_t shmemalloc_retry)
{
    return bus_alloc_consistent(osdev, size, pa);
}

static INLINE void
OS_FREE_NONCONSISTENT(osdev_t osdev, u_int32_t size,
                   void *vaddr, dma_addr_t pa, dma_context_t context)
{
    bus_free_consistent(osdev, size, vaddr, pa);
}

static INLINE void
OS_SYNC_SINGLE(osdev_t osdev, dma_addr_t pa, u_int32_t size, int dir, dma_context_t context)
{
    bus_dma_sync_single(osdev, pa, size, dir);
}

#ifdef __ubicom32__
static INLINE dma_addr_t
OS_MAP_SINGLE(osdev_t osdev, void *ptr, u_int32_t size, int dir, dma_context_t context)
{
    return bus_map_single(osdev, ptr, size, dir);
}
#endif

static INLINE void
OS_UNMAP_SINGLE(osdev_t osdev, dma_addr_t pa, u_int32_t size, int dir, dma_context_t context)
{
    bus_unmap_single(osdev, pa, size, dir);
}

#if ATH_SUPPORT_SHARED_IRQ
#define		ATH_LOCK_IRQ(_osdev)		disable_irq(_osdev->netdev->irq)
#define		ATH_UNLOCK_IRQ(_osdev)		enable_irq(_osdev->netdev->irq)
#else
#define		ATH_LOCK_IRQ(_osdev)
#define		ATH_UNLOCK_IRQ(_osdev)
#endif

#ifdef ATH_SUPPORT_HTC
#define OS_EXEC_INTSAFE(_osdev, _fn, _arg) do {    \
    _fn(_arg);                                    \
} while (0)
#else /* #ifdef ATH_SUPPORT_HTC */
#define OS_EXEC_INTSAFE(_osdev, _fn, _arg) do {    \
    unsigned long flags;                        \
    ATH_LOCK_IRQ(_osdev);    \
    local_irq_save(flags);                        \
    _fn(_arg);                                    \
    local_irq_restore(flags);                    \
    ATH_UNLOCK_IRQ(_osdev);   \
} while (0)
#endif /* #ifdef ATH_SUPPORT_HTC */

/*
 * Timer Interfaces. Use these macros to declare timer
 * and retrieve timer argument. This is mainly for resolving
 * different argument types for timer function in different OS.
 */
typedef void (*timer_func)(unsigned long);

#define OS_DECLARE_TIMER(_fn)                   \
    void _fn(unsigned long)

#define OS_TIMER_FUNC(_fn)                      \
 void _fn(unsigned long timer_arg)

#define OS_GET_TIMER_ARG(_arg, _type)           \
    (_arg) = (_type)(timer_arg)

/* XXX: need to fix this */
typedef void (*dummy_timer_func_t)(unsigned long arg);

#ifndef ATH_SUPPORT_HTC
typedef struct timer_list        os_timer_t;
#else

typedef struct htc_timer_list
{
    struct timer_list timer_obj;
    dummy_timer_func_t func;
    void *arg;
    int   activeflag;
    void *osdev;            /* per device kthread */
} htc_timer_t;

typedef struct htc_timer_list    os_timer_t;
#endif

#ifndef ATH_SUPPORT_HTC
static INLINE void
OS_INIT_TIMER(osdev_t pNicDev, os_timer_t *pTimer,
              void *fn, void * arg)
{

    init_timer(pTimer);
    (pTimer)->function = (dummy_timer_func_t)(fn);
    (pTimer)->data = (unsigned long)(arg);
}

#define OS_SET_TIMER(_timer, _ms)    mod_timer(_timer, jiffies + ((_ms)*HZ)/1000)

#define OS_CANCEL_TIMER(_timer)      del_timer(_timer)

#define OS_FREE_TIMER(_timer)        del_timer(_timer)

#else

static INLINE u_int32_t
OS_INIT_TIMER(osdev_t pNicDev, htc_timer_t *pTimer,
              void *fn, void *arg)
{
    init_timer(&(pTimer->timer_obj));
    pTimer->timer_obj.function = pNicDev->htcTimerHandler;
    pTimer->timer_obj.data = (unsigned long)pTimer;

    (pTimer)->func = (dummy_timer_func_t) fn;
    (pTimer)->arg = arg;
    (pTimer)->activeflag = 0;
    (pTimer)->osdev = (void *)pNicDev;      /* per device kthread */

    return 1;
}

static INLINE u_int32_t OS_SET_TIMER(htc_timer_t *pTimer, u_int32_t ms)
{
    pTimer->activeflag = 1;
    return mod_timer(&(pTimer->timer_obj), jiffies + ((ms)*HZ)/1000);
}

static INLINE u_int32_t OS_CANCEL_TIMER(htc_timer_t *pTimer)
{
    if(pTimer->activeflag != 1) {
        return 1;
    }
    pTimer->activeflag = 0;
    return del_timer(&(pTimer->timer_obj));
}

static INLINE void OS_FREE_TIMER(htc_timer_t *pTimer)
{
    if(pTimer->activeflag != 1) {
        return;
    }
    pTimer->activeflag = 0;
    del_timer(&(pTimer->timer_obj));
}
static INLINE void OS_PUT_DEFER_ITEM(osdev_t osdev, defer_func_t func, int func_id, void* param1, void* param2, void* param3)
{
     osdev->htcPutDeferItem(osdev, func, func_id, param1, param2, param3);
}

#endif /* #ifndef ATH_SUPPORT_HTC */

#ifdef ATH_SUPPORT_HTC
typedef struct semaphore   mesg_lock_t;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
#define mesg_lock_init(_msg_lock)        init_MUTEX(_msg_lock)
#else
#define mesg_lock_init(_msg_lock)        sema_init(_msg_lock, 1)
#endif
#define mesg_lock(_msg_lock)             down(_msg_lock)
#define mesg_unlock(_msg_lock)           up(_msg_lock)
#define mesg_lock_destroy(_msg_lock)
#else
typedef spinlock_t     mesg_lock_t;
#define mesg_lock_init(_msg_lock)        spin_lock_init(_msg_lock)
#define mesg_lock(_msg_lock)             spin_lock(_msg_lock)
#define mesg_unlock(_msg_lock)           spin_unlock(_msg_lock)
#define mesg_lock_destroy(_msg_lock)     spin_lock_destroy(_msg_lock)
#endif /* #ifndef ATH_SUPPORT_HTC */

static INLINE u_int32_t
OS_DEV_HAS_PENDING_SG(osdev_t osdev)
{
    return 0;
}

static INLINE void
OS_GET_RANDOM_BYTES(void *p, u_int16_t n)
{
    get_random_bytes(p, n);
}

typedef enum _mesgq_priority_t {
    MESGQ_PRIORITY_LOW,
    MESGQ_PRIORITY_NORMAL,
    MESGQ_PRIORITY_HIGH
} mesgq_priority_t;


typedef enum _mesgq_event_delivery_type {
    MESGQ_ASYNCHRONOUS_EVENT_DELIVERY,
    MESGQ_SYNCHRONOUS_EVENT_DELIVERY,
} mesgq_event_delivery_type;

typedef void* os_task_handle_t;
typedef void (*os_tasklet_routine_t)(
    void                *context,
    os_task_handle_t    task_handle
    );

typedef struct {
    os_tasklet_routine_t    routine;
    atomic_t                queued;
    void                    *data;
    spinlock_t              lock;
} os_task_t;

typedef struct _os_mesg_t {
    STAILQ_ENTRY(_os_mesg_t)  mesg_next;
    u_int16_t                 mesg_type;
    u_int16_t                 mesg_len;
    /* followed by mesg_len bytes */
} os_mesg_t;

typedef void (*os_mesg_handler_t)(
    void                *ctx,
    u_int16_t           mesg_type,
    u_int16_t           mesg_len,
    void                *mesg
    );

typedef struct {
    osdev_t                     dev_handle;
    int32_t                     num_queued;
    int32_t                     mesg_len;
    u_int8_t                    *mesg_queue_buf;
    STAILQ_HEAD(, _os_mesg_t)    mesg_head;        /* queued mesg buffers */
    STAILQ_HEAD(, _os_mesg_t)    mesg_free_head;   /* free mesg buffers  */
    mesg_lock_t                 lock;
    mesg_lock_t                 ev_handler_lock;
#ifdef USE_SOFTINTR
    void                        *_task;
#else
    os_timer_t                  _timer;
#endif
    os_mesg_handler_t           handler;
    void                        *ctx;
    u_int8_t                    is_synchronous:1;
} os_mesg_queue_t;

/*
 * OS_MESGQ_* API to deliver messages(events) asynchronosly.
 * messages are queued up into a queue and are delivered in the context of
 * timer thread. this will avoid reentrency issues across different
 * module boundaries.
 */

static INLINE void
os_mesgq_handler(void *timer_arg)
{
    os_mesg_queue_t    *queue = (os_mesg_queue_t*)timer_arg;
    os_mesg_t          *mesg;
    void               *msg;

    /*
     * Request access to message queue to retrieve message for processing
     */
    mesg_lock(&(queue->lock));

    mesg = STAILQ_FIRST(&queue->mesg_head);
    while(mesg) {
        STAILQ_REMOVE_HEAD(&queue->mesg_head, mesg_next);
        if (mesg->mesg_len) {
            msg =  (void *) (mesg+1);
        } else {
            msg = NULL;
        }
        /*
         * Release access to message queue before processing message
         */
        mesg_unlock(&(queue->lock));

        /*
         * Ensure just one message can be processes at a time.
         */
        mesg_lock(&(queue->ev_handler_lock));
        queue->handler(queue->ctx,mesg->mesg_type,mesg->mesg_len, msg);
        mesg_unlock(&(queue->ev_handler_lock));

        /*
         * Request access to message queue to retrieve next message
         */
        mesg_lock(&(queue->lock));
        queue->num_queued--;
        STAILQ_INSERT_TAIL(&queue->mesg_free_head,mesg, mesg_next);
        mesg = STAILQ_FIRST(&queue->mesg_head);
    }

    /*
     * Release message queue
     */
    mesg_unlock(&(queue->lock));
}

/*
 * initialize message queue.
 * devhandle   : os dev handle.
 * queue       : message queue.
 * mesg_len    : maximum length of message.
 * max_queued  : maximum number of messages that can be queued at any time.
 * msg_handler : handler function which will be called
 *                asynchronously to deliver each message.
 */
static INLINE int OS_MESGQ_INIT(osdev_t devhandle, os_mesg_queue_t *queue,
                                u_int32_t mesg_len, u_int32_t max_queued,
                                os_mesg_handler_t msg_handler, void *context,
                                mesgq_priority_t priority,
                                mesgq_event_delivery_type mq_type)
{
    int i,len;
    os_mesg_t *mesg;

    len = (mesg_len + sizeof(struct _os_mesg_t));
    queue->mesg_queue_buf = OS_MALLOC(devhandle, len*max_queued, 0);
    if (!queue->mesg_queue_buf)
        return -ENOMEM;
    queue->dev_handle = devhandle;
    STAILQ_INIT(&queue->mesg_head);
    STAILQ_INIT(&queue->mesg_free_head);
    mesg_lock_init(&(queue->lock));
    mesg_lock_init(&(queue->ev_handler_lock));
    mesg = (os_mesg_t *)queue->mesg_queue_buf;
    for (i=0;i<max_queued;++i) {
        STAILQ_INSERT_TAIL(&queue->mesg_free_head,mesg,mesg_next);
        mesg = (os_mesg_t *) ((u_int8_t *) mesg + len);
    }
    queue->mesg_len = mesg_len;
    queue->ctx = context;
    queue->handler = msg_handler;
    queue->num_queued = 0;
    if (mq_type == MESGQ_ASYNCHRONOUS_EVENT_DELIVERY) {
        queue->is_synchronous=0;
    } else {
        queue->is_synchronous=1;
    }
#ifdef USE_SOFTINTR
        queue->_task = softintr_establish(IPL_SOFTNET,os_mesgq_handler,(void *)queue);
#else
    OS_INIT_TIMER(devhandle,&queue->_timer, os_mesgq_handler, queue);
#endif

    return 0;
}

/*
 * send a message.
 * queue : message queue.
 * msg   : message (opaque) . the size of the message
 *         is equal to the mesg_length passed to the OS_MESG_INIT
 *
 */
static INLINE int OS_MESGQ_SEND(os_mesg_queue_t *queue,u_int16_t type, u_int16_t len,  void *msg)
{
    os_mesg_t *mesg;

    mesg_lock(&(queue->lock));
    if (queue->is_synchronous ) {
        queue->handler(queue->ctx,type,len, msg);
    } else {
        mesg = STAILQ_FIRST(&queue->mesg_free_head);
        KASSERT(len <= queue->mesg_len, ("len <= queue->mesg_len"));
        if (mesg) {
            STAILQ_REMOVE_HEAD(&queue->mesg_free_head, mesg_next);
            mesg->mesg_type = type;
            mesg->mesg_len = len;
            if (len) {
                OS_MEMCPY((u_int8_t *)(mesg+1),msg,len);
            }
            STAILQ_INSERT_TAIL(&queue->mesg_head, mesg, mesg_next);
            queue->num_queued++;
        } else {
            mesg_unlock(&(queue->lock));
            printk("No more message queue buffers !!! \n");
            return -ENOMEM;
        }
        if (queue->num_queued == 1) {
            /* schedule a task (timer) to handle the messages */
#ifdef USE_SOFTINTR
            softintr_schedule(queue->_task);
#else
            OS_SET_TIMER(&queue->_timer,1);
#endif
        }
    }
    mesg_unlock(&(queue->lock));
    return 0;
}

/*
 * this is only for single threaded operating systems.
 * assert for now.
 */
static INLINE int OS_MESGQ_SEND_SYNC(os_mesg_queue_t *queue,u_int16_t type, u_int16_t len,  void *msg, bool flush)
{
     KASSERT(0,(" mesg queue sync send is not supported by linux"));
     return 0;
}

/*
 * drain all the messages.
 * queue : message queue.
 */
static INLINE void OS_MESGQ_DRAIN(os_mesg_queue_t *queue, os_mesg_handler_t msg_handler)
{
    os_mesg_t *mesg;
    void *msg;

    mesg_lock(&(queue->lock));
#ifndef USE_SOFTINTR
    OS_CANCEL_TIMER(&queue->_timer);
#endif
    mesg = STAILQ_FIRST(&queue->mesg_head);
    while(mesg) {
        STAILQ_REMOVE_HEAD(&queue->mesg_head, mesg_next);
        queue->num_queued--;
        if (msg_handler != NULL) {
            if (mesg->mesg_len) {
                msg = (void *) (mesg+1);
            } else {
                msg = NULL;
            }
            msg_handler(queue->ctx, mesg->mesg_type, mesg->mesg_len, msg);
        }
        STAILQ_INSERT_TAIL(&queue->mesg_free_head,mesg, mesg_next);
        mesg = STAILQ_FIRST(&queue->mesg_head);
    }
    STAILQ_INIT(&queue->mesg_head);
    mesg_unlock(&(queue->lock));
}


/*
 * destroy the message queue.
 * queue : message queue.
 * reclaim all the resorces.
 */

static INLINE void OS_MESGQ_DESTROY(os_mesg_queue_t *queue)
{
    mesg_lock(&(queue->lock));
#ifdef USE_SOFTINTR
    softintr_disestablish(queue->_task);
#else
    OS_CANCEL_TIMER(&queue->_timer);
#endif
    queue->num_queued = 0;
    STAILQ_INIT(&queue->mesg_head);
    STAILQ_INIT(&queue->mesg_free_head);
    OS_FREE(queue->mesg_queue_buf);
#ifndef USE_SOFTINTR
    OS_FREE_TIMER(&queue->_timer);
#endif
    mesg_unlock(&(queue->lock));
    mesg_lock_destroy(&(queue->lock));
    mesg_lock_destroy(&(queue->ev_handler_lock));
}

static INLINE int OS_MESGQ_CAN_SEND_SYNC(void)
{
    return TRUE;
}
/*
 * temp WAR for windows hang (dead lock). It can be removed when VAP SM is re-written (bug 65137).
 */
static INLINE int
OS_SCHEDULE_ROUTING(osdev_t pNicDev,
                     os_tasklet_routine_t routine,
                     void* context)
{
#ifdef CONFIG_SMP
    OS_PUT_DEFER_ITEM(pNicDev,
                      (void *)routine,                        /*Defer function*/
                      0xffff,                                 /*WORK_ITEM_SET_OS_SCHE_EVENT*/
                      context,                                /*Params*/
                      NULL,
                      NULL);
#else
    routine(context, NULL);
#endif
    return 0;
}

static INLINE void
OS_FREE_ROUTING(void* workItemHandle)
{
}


/*
** These are required for network manager support
*/

#ifndef SET_NETDEV_DEV
#define    SET_NETDEV_DEV(ndev, pdev)
#endif

#ifdef to_net_dev
#define ATH_GET_NETDEV_DEV(ndev)    ((ndev)->dev.parent)
#else
#define ATH_GET_NETDEV_DEV(ndev)    ((ndev)->class_dev.dev)
#endif



/*
 * Opaque S/G List Entry
 */
typedef struct scatterlist            sg_t;

#include "hwdef.h"

#ifndef ARRAY_LENGTH
#define ARRAY_LENGTH(a)         (sizeof(a) / sizeof((a)[0]))
#endif

#ifndef MIN
#define MIN(a, b)                ((a) < (b) ? a : b)
#endif
#ifndef MAX
#define MAX(a, b)                ((a) > (b) ? a : b)
#endif

/*
 * PCI configuration space access
 */
#ifdef ATH_PCI

static INLINE u_int32_t
OS_PCI_READ_CONFIG(osdev_t osdev, u_int32_t offset, void *p, u_int32_t bytes)
{
    struct pci_dev *pdev = (struct pci_dev *)osdev->bdev;

    switch (bytes) {
    case 1:
        pci_read_config_byte(pdev, offset, p);
        break;
    case 2:
        pci_read_config_word(pdev, offset, p);
        break;
    case 4:
        pci_read_config_dword(pdev, offset, p);
        break;
    }
    return bytes;
}

static INLINE void
OS_PCI_WRITE_CONFIG(osdev_t osdev, u_int32_t offset, void *p, u_int32_t bytes)
{
    struct pci_dev *pdev = (struct pci_dev *)osdev->bdev;

    switch (bytes) {
    case 1:
        pci_write_config_byte(pdev, offset, *(u_int8_t *)p);
        break;
    case 2:
        pci_write_config_word(pdev, offset, *(u_int16_t *)p);
        break;
    case 4:
        pci_write_config_dword(pdev, offset, *(u_int32_t *)p);
        break;
    }
}

#else

static INLINE u_int32_t
OS_PCI_READ_CONFIG(osdev_t osdev, u_int32_t offset, void *p, u_int32_t bytes)
{
    OS_MEMSET(p, 0xff, bytes);
    return 0;
}

#define OS_PCI_WRITE_CONFIG(_osdev, _offset, _p, _bytes)

#endif

void *OS_ALLOC_VAP(osdev_t dev, u_int32_t len);
void OS_FREE_VAP(void *netif);

// ALLOC_DMA_MAP_CONTEXT_AREA is a NULL macro and is implemented only for BSD.
#define ALLOC_DMA_MAP_CONTEXT_AREA(os_handle, p_memctx)
#define FREE_DMA_CONTEXT_POOL(os_handle, name)
#define ALLOC_DMA_CONTEXT_POOL(os_handle, name, numdesc)

#ifdef QCA_LOWMEM_PLATFORM
#define ATH_QOSNULL_TXDESC    32
#else
#define ATH_QOSNULL_TXDESC    64
#endif
#define ATH_FRAG_PER_MSDU      1
#ifndef ATH_TXBUF
#define ATH_TXBUF   540/ATH_FRAG_PER_MSDU
#endif

/*
 * minimum h/w qdepth to be sustained to maximize aggregation
 */
#define ATH_AGGR_MIN_QDEPTH 2
#define OS_MAX_RXBUF_SIZE(_statuslen)   (IEEE80211_MAX_MPDU_LEN + _statuslen)

#if ATH_TX_POLL
#define ATH_TX_POLL_TIMER  80
#define hz                 100
#define MSEC_TO_TICKS(ms)  (((ms)*hz)/1000)
#endif

#define ATH_GET_RX_CONTEXT_BUF(_wbuf)  \
                          (ATH_RX_CONTEXT(_wbuf)->ctx_rxbuf)
#define ATH_SET_RX_CONTEXT_BUF(_wbuf, _bf)  \
                          (ATH_GET_RX_CONTEXT_BUF(_wbuf) = _bf)

// This macro is used to avoid another wrapper around ath_rxbuf_alloc.
// For Mac OS, we need to OR in ATH_RXBUF_ALLOC_DONTWAIT with length. Not needed for other OS'.
#define ATH_ALLOCATE_RXBUFFER(_sc, _len)   ath_rxbuf_alloc(_sc, _len)

#ifdef ATH_SUPPORT_HTC
#define OS_GET_HIF_HANDLE(h)   ((osdev_t)h)->host_hif_handle
#define OS_GET_HTC_HANDLE(h)   ((osdev_t)h)->host_htc_handle

#define OS_WBUF_TX_DECLARE()
#define OS_WBUF_TX_MGT_PREPARE(ic, scn, new_wbuf, tmp_wbuf, wbuf, txctl)
#define OS_WBUF_TX_MGT_COMPLETE_STATUS(ic, new_wbuf)
#define OS_WBUF_TX_MGT_ERROR_STATUS(ic, new_wbuf)
#define OS_WBUF_TX_DATA_PREPARE(ic, scn, new_wbuf, tmp_wbuf, wbuf)
#define OS_WBUF_TX_DATA_COMPLETE_STATUS(ic, new_wbuf)
#define OS_WBUF_TX_MGT_P2P_PREPARE(scn, ni, wbuf, p2p_action_wbuf)                                                  \
{                                                                                                                   \
    wlan_if_t vap = ni->ni_vap;                                                                                     \
    if (vap && vap->iv_ifp) {                                                                                       \
        struct ieee80211_frame *wh = (struct ieee80211_frame *)wbuf_header(wbuf);                                   \
        struct ieee80211_tx_status ts;                                                                              \
        ts.ts_flags = 0;                                                                                            \
        ts.ts_retries = 0;                                                                                          \
        if ((wh->i_fc[0] & 0xff) == 0xd0) {                                                                         \
            p2p_action_wbuf = (struct ath_usb_p2p_action_queue *)OS_MALLOC(scn->sc_osdev,                           \
                                                                           sizeof(struct ath_usb_p2p_action_queue), \
                                                                           GFP_ATOMIC);                             \
            if (p2p_action_wbuf) {                                                                                  \
                p2p_action_wbuf->wbuf = wbuf_clone(scn->sc_osdev, wbuf);                                            \
            } else {                                                                                                \
                printk("Allocated p2p_action_wbuf failed...\n");                                                    \
                IEEE80211_TX_COMPLETE_WITH_ERROR(wbuf);                                                             \
                return error;                                                                                       \
            }                                                                                                       \
            if (p2p_action_wbuf->wbuf) {                                                                            \
                p2p_action_wbuf->next = NULL;                                                                       \
            } else {                                                                                                \
                printk("Allocated P2P Action frame wbuf failed...\n");                                              \
                OS_FREE(p2p_action_wbuf);                                                                           \
                IEEE80211_TX_COMPLETE_WITH_ERROR(wbuf);                                                             \
                return error;                                                                                       \
            }                                                                                                       \
        }                                                                                                           \
    }                                                                                                               \
}
#define OS_WBUF_TX_MGT_P2P_INQUEUE(scn, p2p_action_wbuf)                                            \
{                                                                                                   \
    if (p2p_action_wbuf) {                                                                          \
        IEEE80211_STATE_P2P_ACTION_LOCK_IRQ(scn);                                                   \
        if (scn->sc_p2p_action_queue_tail == NULL) {                                                \
            scn->sc_p2p_action_queue_head = scn->sc_p2p_action_queue_tail = p2p_action_wbuf;        \
        } else {                                                                                    \
            scn->sc_p2p_action_queue_tail->next = p2p_action_wbuf;                                  \
            scn->sc_p2p_action_queue_tail = p2p_action_wbuf;                                        \
        }                                                                                           \
        p2p_action_wbuf->deleted = 0;                                                               \
        IEEE80211_STATE_P2P_ACTION_UNLOCK_IRQ(scn);                                                 \
    }                                                                                               \
}
#define OS_WBUF_TX_MGT_P2P_DEQUEUE(scn, p2p_action_wbuf)                            \
{                                                                                   \
    struct ath_usb_p2p_action_queue *temp_wbuf = NULL;                              \
    IEEE80211_STATE_P2P_ACTION_LOCK_IRQ(scn);                                       \
    temp_wbuf = scn->sc_p2p_action_queue_head;                                      \
    if (temp_wbuf->next == NULL) {                                                  \
        scn->sc_p2p_action_queue_head = scn->sc_p2p_action_queue_tail = NULL;       \
    } else {                                                                        \
        while(1) {                                                                  \
            scn->sc_p2p_action_queue_tail = temp_wbuf;                              \
            temp_wbuf = temp_wbuf->next;                                            \
            if (temp_wbuf->next == NULL) {                                          \
                scn->sc_p2p_action_queue_tail->next = NULL;                         \
                break;                                                              \
            }                                                                       \
        }                                                                           \
    }                                                                               \
    if (temp_wbuf != p2p_action_wbuf) {                                             \
        printk("Warning: p2p_action_wbuf is gone.\n");                              \
    } else {                                                                        \
        printk("Send to USB failed.\n");                                            \
    }                                                                               \
    IEEE80211_STATE_P2P_ACTION_UNLOCK_IRQ(scn);                                     \
    wbuf_release(scn->sc_osdev, p2p_action_wbuf->wbuf);                             \
    OS_FREE(p2p_action_wbuf);                                                       \
}
#endif /* end of ATH_SUPPORT_HTC */

#ifdef ATH_USB

u_int32_t
OS_Usb_SubmitMsgInUrb(osdev_t osdev);
u_int32_t
OS_Usb_SubmitCmdOutUrb(osdev_t osdev, uint8_t* buf, uint16_t len, void *context);
u_int32_t
OS_Usb_SubmitRxUrb(osdev_t osdev);
u_int32_t
OS_Usb_SubmitTxUrb(osdev_t osdev, uint8_t* buf, uint16_t len, void *context, HIFUSBTxPipe *pipe);
u_int16_t
OS_Usb_GetFreeTxBufferCnt(osdev_t osdev, HIFUSBTxPipe *pipe);
u_int16_t
OS_Usb_GetMaxTxBufferCnt(osdev_t osdev);
u_int16_t
OS_Usb_GetTxBufferCnt(osdev_t osdev, HIFUSBTxPipe *pipe);
u_int16_t
OS_Usb_GetTxBufferThreshold(osdev_t osdev);
u_int16_t
OS_Usb_GetFreeCmdOutBufferCnt(osdev_t osdev);
u_int16_t
OS_Usb_InitTxRxQ(osdev_t osdev);
void
OS_Usb_Enable_FwRcv(osdev_t osdev);

#define OS_Usb_Tx_Start_Stop(osdev, isstart)

#define OS_CHIP_IS_MAGPIE(_ic)          _ic->ic_osdev->isMagpie

#define KEVENT_BEACON_STUCK            1
#define KEVENT_BEACON_IMMUNITY         2
#define KEVENT_BEACON_SETSLOTTIME      3
#define KEVENT_WMM_UPDATE              4
#define KEVENT_BEACON_DONE             5

int ath_usb_create_thread(void *sc);
void ath_usb_schedule_thread(void *sc, int flag);

typedef struct semaphore usblock_t;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
#define OS_USB_LOCK_INIT(_usblock)      init_MUTEX(_usblock)
#else
#define OS_USB_LOCK_INIT(_usblock)      sema_init(_usblock, 1)
#endif
#define OS_USB_LOCK_DESTROY(_usblock)
#define OS_USB_LOCK(_usblock)           down(_usblock)
#define OS_USB_TRYLOCK(_usblock)        (!down_trylock(_usblock))
#define OS_USB_UNLOCK(_usblock)         up(_usblock)
#define ATHHTC_INIT_TXTQUEUE(a, b, c, d) tasklet_init(b, (void *)c, (unsigned long)d)
#define ATHHTC_SCHEDULE_TXTQUEUE(a)      tasklet_schedule(a)
#define ATHHTC_FREE_TXTQUEUE(a, b)       tasklet_kill(b)
#define ATHHTC_INIT_UAPSD_CREDITUPDATE(a, b, c, d) tasklet_init(b, (void *)c, (unsigned long)d)
#define ATHHTC_SCHEDULE_UAPSD_CREDITUPDATE(a)      tasklet_schedule(a)
#define ATHHTC_FREE_UAPSD_CREDITUPDATE(a, b)       tasklet_kill(b)

#endif

#ifdef ATH_SUPPORT_HTC
typedef struct semaphore htclock_t;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
#define OS_HTC_LOCK_INIT(_usblock)                      init_MUTEX(_usblock)
#else
#define OS_HTC_LOCK_INIT(_usblock)                      sema_init(_usblock, 1)
#endif
#define OS_HTC_LOCK_DESTROY(_usblock)
#define OS_HTC_LOCK(_usblock)                           down(_usblock)
#define OS_HTC_UNLOCK(_usblock)                         up(_usblock)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
#define	OS_MESG_QUEUE_LOCK_INIT(_queuelock)             init_MUTEX(_queuelock)
#else
#define	OS_MESG_QUEUE_LOCK_INIT(_queuelock)             sema_init(_queuelock, 1)
#endif
#define	OS_MESG_QUEUE_LOCK_DESTROY(_queuelock)
#define	OS_MESG_QUEUE_LOCK(_queuelock)                  down(_queuelock)
#define	OS_MESG_QUEUE_UNLOCK(_queuelock)                up(_queuelock)

#define OS_HTC_P2P_LOCK_INIT(_p2plock)                  spin_lock_init(_p2plock)
#define OS_HTC_P2P_LOCK_DESTROY(_p2plock)               spin_lock_destroy(_p2plock)
#define OS_HTC_P2P_LOCK_IRQ(_p2plock, _flags)           spin_lock_irqsave(_p2plock, _flags)
#define OS_HTC_P2P_UNLOCK_IRQ(_p2plock, _flags)         spin_unlock_irqrestore(_p2plock, _flags)

#define OS_KEYMAP_LOCK(_lock, _flags)                   spin_lock_irqsave(_lock, _flags)
#define OS_KEYMAP_UNLOCK(_lock, _flags)                 spin_unlock_irqrestore(_lock, _flags)

#define OS_STAT_LOCK(_lock)                             spin_lock_bh(_lock)
#define OS_STAT_UNLOCK(_lock)                           spin_unlock_bh(_lock)

#endif /* end of ATH_SUPPORT_HTC */

#define OS_IN_SOFTIRQ()       in_softirq()
typedef spinlock_t os_mgmt_lock_t;
#define OS_MGMT_LOCKINIT(_lock)                         spin_lock_init(_lock)
#define OS_MGMT_LOCKBH(_lock)                           spin_lock_bh(_lock)
#define OS_MGMT_UNLOCKBH(_lock)                         spin_unlock_bh(_lock)


typedef spinlock_t os_nodeleave_lock_t;
#define OS_NODELEAVE_LOCKINIT(_lock)                           spin_lock_init(_lock)
#define OS_NODELEAVE_LOCKBH(_lock)                             spin_lock_bh(_lock)
#define OS_NODELEAVE_UNLOCKBH(_lock)                           spin_unlock_bh(_lock)

typedef spinlock_t os_nawdsdefer_lock_t;
#define OS_NAWDSDEFER_LOCKINIT(_lock)                           spin_lock_init(_lock)
#define OS_NAWDSDEFER_LOCKBH(_lock)                             spin_lock_bh(_lock)
#define OS_NAWDSDEFER_UNLOCKBH(_lock)                           spin_unlock_bh(_lock)

#if ATH_SUPPORT_WIFIPOS
/* Stub function that does nothing. Used by netlink_kernel_create */

#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,31)
typedef void (*netlink_input)(struct sk_buff *skb);
#else
typedef void (*netlink_input)(struct sock *sk, int len);
#endif

static INLINE void *OS_NETLINK_CREATE(
    int unit, unsigned int groups, void *input, void *module)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
    extern struct net init_net;

    struct netlink_kernel_cfg cfg = {
        .groups = groups,
        .input  = input,
    };
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
    return(
        (void *) netlink_kernel_create(
				&init_net, unit, &cfg));
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
    return(
        (void *) netlink_kernel_create(
				&init_net, unit, (struct module *) module, &cfg));
#elif LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,24)
    return(
        (void *) netlink_kernel_create(
				&inet_net, unit, groups, (netlink_input) input, (struct mutex *) NULL, (struct module *) module));
#elif LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,22)
		return(
			(void *) netlink_kernel_create(
				unit, groups, (netlink_input) input, (struct mutex *) NULL, (struct module *) module));
#else
		return(
		(void *) netlink_kernel_create(
            unit, groups, (netlink_input) input, (struct module *) module));
#endif
}

static INLINE void OS_SOCKET_RELEASE(void *sock)
{
    netlink_kernel_release((struct sock *) sock);
}

static INLINE void OS_NETLINK_UCAST(
    void *ssk, struct sk_buff *skb, u32 pid,u32 nonblock)
{
    netlink_unicast((struct sock*) ssk, skb, pid,nonblock);
}

static INLINE void OS_NETLINK_BCAST(
    void *ssk, struct sk_buff *skb, u32 pid, u32 group, u32 allocation)
{
    netlink_broadcast((struct sock*) ssk, skb, pid, group, (gfp_t) allocation);
}
#define OS_NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))
#define OS_NLMSG_DATA(nlh)  ((void*)(((char*)nlh) + NLMSG_LENGTH(0)))

static INLINE void OS_SET_NETLINK_HEADER(
    void *nlmsghdr, u32 nlmsg_len, u16 nlmsg_type, u16 nlmsg_flags,
    u32 nlmsg_seq, u32 nlmsg_pid)
{
    struct nlmsghdr* hdr = (struct nlmsghdr *) nlmsghdr;
    hdr->nlmsg_len   = nlmsg_len;
    hdr->nlmsg_type  = nlmsg_type;
    hdr->nlmsg_flags = nlmsg_flags;
    hdr->nlmsg_seq   = nlmsg_seq;
    hdr->nlmsg_pid   = nlmsg_pid;
}

static INLINE void OS_DEVPUT(void *netd)
{
    dev_put((struct net_device *)netd);
}

#endif /*end of ATH_SUPPORT_WIFIPOS*/
#endif /* end of ADF_SUPPORT */

#if ATH_SUPPORT_CFEND
#define ATH_CFEND_LOCK_INIT(_sc)    spin_lock_init(&(_sc)->sc_cfend_lock)
#define ATH_CFEND_LOCK(_sc)         spin_lock(&(_sc)->sc_cfend_lock)
#define ATH_CFEND_UNLOCK(_sc)       spin_unlock(&(_sc)->sc_cfend_lock)
#define ATH_CFEND_LOCK_DESTROY(_sc) spin_lock_destroy(&(_sc)->sc_cfend_lock)
#endif

#ifdef HOST_OFFLOAD

void   atd_proxy_arp_send(struct sk_buff *nbuf);
void   atd_rx_from_wlan(struct sk_buff * nbuf);

static inline int _copy_to_user(void *dst ,void *src, int size)
{
    memcpy(dst,src,size);
    return 0;
}
static inline int __xcopy_from_user(void *dst ,void *src, int size)
{
    memcpy(dst,src,size);
    return 0;
}

#define _netif_carrier_on(dev)                                                \
                              do {                                            \
                                  union iwreq_data w;                         \
                                  netif_carrier_on(dev);                      \
                                  memset(&w, 0, sizeof(w));                   \
                                  w.data.flags = IEEE80211_EV_IF_RUNNING;     \
                                  WIRELESS_SEND_EVENT(dev,                    \
                                                     IWEVCUSTOM, &w, NULL);   \
                              } while (0)
#define _netif_carrier_off(dev)                                               \
                              do {                                            \
                                  union iwreq_data w;                         \
                                  netif_carrier_off(dev);                     \
                                  memset(&w, 0, sizeof(w));                   \
                                  w.data.flags = IEEE80211_EV_IF_NOT_RUNNING; \
                                  WIRELESS_SEND_EVENT(dev,                    \
                                                     IWEVCUSTOM, &w, NULL);   \
                              } while (0)

void
atd_event_handler(struct net_device     *dev, unsigned int  cmd,
			      union iwreq_data      *wreq, char *extra);

#define __osif_deliver_data(_osif, _skb) \
{\
    struct net_device *dev = ((osif_dev*)(_osif))->netdev;\
    _skb->dev = dev;\
    atd_rx_from_wlan(_skb);\
}


#define WIRELESS_SEND_EVENT     atd_event_handler

#else

#define __osif_deliver_data(_osif, _skb) osif_deliver_data(_osif, _skb)
#define _copy_to_user     copy_to_user
#define __xcopy_from_user   copy_from_user
#define _netif_carrier_on     netif_carrier_on
#define _netif_carrier_off    netif_carrier_off

#define WIRELESS_SEND_EVENT     wireless_send_event

#endif

#ifndef OS_EXPORT_SYMBOL
#define OS_EXPORT_SYMBOL(_sym) EXPORT_SYMBOL(_sym)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#define NETIF_F_HW_VLAN (NETIF_F_HW_VLAN_TX | NETIF_F_HW_VLAN_RX | NETIF_F_HW_VLAN_FILTER)
#else
#define NETIF_F_HW_VLAN (NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_CTAG_FILTER)
#endif

#ifndef OS_WMB
#define OS_WMB() wmb()
#endif

#endif /* end of _ATH_LINUX_OSDEP_H */
