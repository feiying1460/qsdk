/*
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef __ATH_PCI_H__
#define __ATH_PCI_H__

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
#include <asm/semaphore.h>
#else
#include <linux/semaphore.h>
#endif
#include <linux/interrupt.h>
#include <linux/platform_device.h>

#if DUMP_FW_RAM
#if ATH_SUPPORT_FW_RAM_DUMP_FOR_MIPS
#include <linux/ath79_wlan.h>
#endif
#endif
void ol_hif_close(void *hif_ctx);
int
ol_ath_ahb_probe(struct platform_device *pdev, const struct platform_device_id *id);
void
ol_ath_ahb_remove(struct platform_device *pdev);
extern void pci_defer_reconnect(struct work_struct *pci_reconnect_work);
void pci_reconnect_cb(struct ol_ath_softc_net80211 *scn);
#endif /* __ATH_PCI_H__ */
