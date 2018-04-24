/*
 * Copyright (c) 2012 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef REMOVE_PKT_LOG
#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif
#ifndef __KERNEL__
#define __KERNEL__
#endif
/*
 * Linux specific implementation of Pktlogs for 802.11ac
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <ath_internal.h>
#include <pktlog_ac_i.h>
#include <pktlog_ac_fmt.h>
#include <pktlog_ac.h>

#define PKTLOG_TAG "ATH_PKTLOG"
#define PKTLOG_DEVNAME_SIZE 32
#define WLANDEV_BASENAME "wifi"
#define MAX_WLANDEV 1
//static struct proc_dir_entry *g_pktlog_pde;

static int p_attach(struct ol_ath_softc_net80211 *sc);
static void pktlog_detach(struct ath_softc *sc);
static int pktlog_open(struct inode *i, struct file *f);
static int pktlog_release(struct inode *i, struct file *f);
static int pktlog_mmap(struct file *f, struct vm_area_struct *vma);
static ssize_t pktlog_read(struct file *file, char *buf, size_t nbytes,
                           loff_t * ppos);
//void pktlog_disable_adapter_logging(void);
//int pktlog_alloc_buf(ol_ath_generic_softc_handle sc,
//                                 struct ath_pktlog_info *pl_info);
//void pktlog_release_buf(struct ol_ath_softc_net80211 *scn);

/*
 * Linux implementation of helper functions
 */

static ol_pktlog_dev_t *get_pl_handle(struct net_device *dev)
{
    ol_ath_generic_softc_handle ath_sc = ath_netdev_priv(dev);
    ol_pktlog_dev_t *pl_dev = *((ol_pktlog_dev_t **)
                                        ((void*)ath_sc +
                                         sizeof(struct ieee80211com)));
    return pl_dev;
}

void ol_pl_set_name(ol_ath_softc_net80211_handle scn, net_device_handle dev){

    if(scn && scn->pl_dev && dev){
        scn->pl_dev->name = dev->name;
    }

    return;
}

void
pktlog_disable_adapter_logging(void)
{
    struct net_device *dev;
    int i;
    char dev_name[PKTLOG_DEVNAME_SIZE];

    // Disable any active per adapter logging
    for (i = 0; i < MAX_WLANDEV; i++) {
        snprintf(dev_name, sizeof(dev_name),
                 WLANDEV_BASENAME "%d", i);

        //snprintf(dev_name, sizeof(dev_name), "wifi-sim0");
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23))
        if ((dev = dev_get_by_name(&init_net,dev_name)) != NULL) {
#else
        if ((dev = dev_get_by_name(dev_name)) != NULL) {
#endif
            // Change this guy
            ol_pktlog_dev_t *pl_dev = get_pl_handle(dev);
            pl_dev->pl_info->log_state = 0;
            dev_put(dev);
        }
    }
}
EXPORT_SYMBOL (pktlog_disable_adapter_logging);

int
pktlog_alloc_buf(struct ol_ath_softc_net80211 *scn)
{
    u_int32_t page_cnt;
    unsigned long vaddr;
    struct page *vpg;
    struct ath_pktlog_info *pl_info;

    if(!scn || !scn->pl_dev){
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, PKTLOG_TAG
               "%s: Unable to allocate buffer"
               "scn or scn->pl_dev is null\n", __FUNCTION__);
        return -EINVAL;
    }

    pl_info = scn->pl_dev->pl_info;

    page_cnt = (sizeof(*(pl_info->buf)) +
                pl_info->buf_size) / PAGE_SIZE;

    if ((pl_info->buf = vmalloc((page_cnt + 2) * PAGE_SIZE))
        == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, PKTLOG_TAG
               "%s: Unable to allocate buffer"
               "(%d pages)\n", __FUNCTION__, page_cnt);
        return -ENOMEM;
    }

    pl_info->buf = (struct ath_pktlog_buf *)
        (((unsigned long) (pl_info->buf) + PAGE_SIZE - 1)
         & PAGE_MASK);

    for (vaddr = (unsigned long) (pl_info->buf);
         vaddr < ((unsigned long) (pl_info->buf)
                  + (page_cnt * PAGE_SIZE)); vaddr += PAGE_SIZE) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))
        vpg = vmalloc_to_page((const void *) vaddr);
#else
        vpg = virt_to_page(pktlog_virt_to_logical((void *) vaddr));
#endif
        SetPageReserved(vpg);
    }
    return 0;
}
EXPORT_SYMBOL (pktlog_alloc_buf);

void
pktlog_release_buf(struct ol_ath_softc_net80211 *scn)
{
    unsigned long page_cnt;
    unsigned long vaddr;
    struct page *vpg;
    struct ath_pktlog_info *pl_info;

    if(!scn || !scn->pl_dev){
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, PKTLOG_TAG
               "%s: Unable to allocate buffer"
               "scn or scn->pl_dev is null\n", __FUNCTION__);
        return;
    }

    pl_info = scn->pl_dev->pl_info;

    page_cnt =
        ((sizeof(*(pl_info->buf)) + pl_info->buf_size) / PAGE_SIZE) + 1;

    for (vaddr = (unsigned long) (pl_info->buf); vaddr <
         (unsigned long) (pl_info->buf) + (page_cnt * PAGE_SIZE);
         vaddr += PAGE_SIZE) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))
        vpg = vmalloc_to_page((const void *) vaddr);
#else
        vpg = virt_to_page(pktlog_virt_to_logical((void *) vaddr));
#endif
        ClearPageReserved(vpg);
    }

    vfree(pl_info->buf);
    pl_info->buf = NULL;
}
EXPORT_SYMBOL (pktlog_release_buf);

static int
p_attach(struct ol_ath_softc_net80211 *sc)
{
    /*printk("ol_pl_handle_addr:%d; g_pktlog_funcs: %d\n", &ol_pl_dev,
            ol_pl_dev.pl_funcs);
    printk("Size of IEEECOM: %d\n", sizeof(struct ieee80211com));*/

    return 0;
    /*struct ath_pktlog_info_lnx *pl_info_lnx;
    char *proc_name;
    struct proc_dir_entry *proc_entry;

    if (sc) {
        pl_info_lnx = kmalloc(sizeof(*pl_info_lnx), GFP_KERNEL);
        if (pl_info_lnx == NULL) {
            printk(PKTLOG_TAG "%s:allocation failed for pl_info\n", __FUNCTION__);
            return -ENOMEM;
        }
        sc->pl_info = &pl_info_lnx->info;
        proc_name = sc->sc_osdev->netdev->name;
    } else {
        if (g_pktlog_info == NULL) {
             allocate the global log structure
            pl_info_lnx = kmalloc(sizeof(*pl_info_lnx), GFP_KERNEL);
            if (pl_info_lnx == NULL) {
                printk(PKTLOG_TAG "%s:allocation failed for pl_info\n", __FUNCTION__);
                return -ENOMEM;
            }
            g_pktlog_info = &pl_info_lnx->info;
        } else {
            pl_info_lnx = PL_INFO_LNX(g_pktlog_info);
        }
        proc_name = PKTLOG_PROC_SYSTEM;
    }

     initialize log info
    pktlog_init(&pl_info_lnx->info);
    pl_info_lnx->proc_entry = NULL;
    pl_info_lnx->sysctl_header = NULL;

    proc_entry = create_proc_entry(proc_name, PKTLOG_PROC_PERM, g_pktlog_pde);

    if (proc_entry == NULL) {
        printk(PKTLOG_TAG "%s: create_proc_entry failed for %s\n",
               __FUNCTION__, proc_name);
        goto attach_fail1;
    }

    proc_entry->data = &pl_info_lnx->info;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
    proc_entry->owner = THIS_MODULE;
#endif
    proc_entry->proc_fops = &pktlog_fops;
    pl_info_lnx->proc_entry = proc_entry;

    if (pktlog_sysctl_register(sc)) {
        printk(PKTLOG_TAG "%s: sysctl register failed for %s\n",
               __FUNCTION__, proc_name);
        goto attach_fail2;
    }
    return 0;

attach_fail2:
    remove_proc_entry(proc_name, g_pktlog_pde);
attach_fail1:
    if(sc)
        kfree(sc->pl_info);
    return -1;*/
}
#endif
