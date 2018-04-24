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
 * Copyright (c) 2013, 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif

#include <linux/version.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/pci.h>
#include <if_athvar.h>
#include "if_ath_pci.h"
#include "ol_if_athvar.h"

int ol_ath_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id);
void ol_ath_pci_remove(struct pci_dev *pdev);
int ol_ath_pci_suspend(struct pci_dev *pdev, pm_message_t state);
int ol_ath_pci_resume(struct pci_dev *pdev);
void ol_ath_iw_detach(struct net_device *dev);
void ol_ath_iw_attach(struct net_device *dev);

#include "if_athvar.h"
#include "if_bus.h"
#include "osif_private.h"
#include <acfg_api_types.h>   /* for ACFG_WDT_REINIT_DONE */
#include <acfg_drv_event.h>

#ifndef ATH_BUS_PM
#ifdef CONFIG_PM
#define ATH_BUS_PM
#endif /* CONFIG_PM */
#endif /* ATH_BUS_PM */

#ifdef ATH_BUS_PM
#define ATH_PCI_PM_CONTROL 0x44
#endif

#ifdef AH_CAL_IN_FLASH_PCI
u_int32_t CalAddr[AH_CAL_RADIOS_PCI] = {AH_CAL_LOCATIONS_PCI};
int pci_dev_cnt=0;
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0))
/*
 * PCI initialization uses Linux 2.4.x version and
 * older kernels do not support this
 */
#error Atheros PCI version requires at least Linux kernel version 2.4.0
#endif /* kernel < 2.4.0 */

/*
 * Use a static table of PCI id's for now.  While this is the
 * "new way" to do things, we may want to switch back to having
 * the HAL check them by defining a probe method.
 */
DEFINE_PCI_DEVICE_TABLE(ath_pci_id_table) = {
    { 0x168c, 0x003c, PCI_ANY_ID, PCI_ANY_ID }, /* Peregrine PCIE  */
    { 0x168c, 0x0050, PCI_ANY_ID, PCI_ANY_ID }, /* Swift PCIE  */
    { 0x168c, 0x0040, PCI_ANY_ID, PCI_ANY_ID }, /* beeliner PCIE  */
    { 0x168c, 0x0046, PCI_ANY_ID, PCI_ANY_ID }, /* Cascade PCIE  */
    { 0x168c, 0x0056, PCI_ANY_ID, PCI_ANY_ID }, /* Besra PCIE  */
    { 0 }
};

#if QCA_PARTNER_DIRECTLINK_TX
extern void wlan_pltfrm_directlink_set_pcie_base(uint32_t mem);
#endif /* QCA_PARTNER_DIRECTLINK_TX */

static int
ath_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
    u_int8_t max_payload;
#ifdef AH_CAL_IN_FLASH_PCI
    pci_dev_cnt++;
#endif
    pci_read_config_byte(pdev, 0x74, &max_payload);
#if (ATH_PERF_PWR_OFFLOAD != 0) && defined(HIF_PCI)
#define AR9888_DEVICE_ID	(0x003c)
#define AR9887_DEVICE_ID    (0x0050)
#define AR900B_DEVICE_ID    (0x0040)
#define QCA9984_DEVICE_ID   (0x0046)
#define QCA9888_DEVICE_ID   (0x0056)
    /* emulation device id, peregrine id or beeliner id*/
    if (((id->device == 0xabcd) && (max_payload != 0)) || (id->device == AR9888_DEVICE_ID) || (id->device == AR9887_DEVICE_ID) || (id->device == AR900B_DEVICE_ID) || (id->device == QCA9984_DEVICE_ID) || (id->device == QCA9888_DEVICE_ID)) {
#if QCA_PARTNER_DIRECTLINK_TX
        wlan_pltfrm_directlink_set_pcie_base((uint32_t) pci_resource_start(pdev, 0));
#endif /* QCA_PARTNER_DIRECTLINK_TX */

        return ol_ath_pci_probe(pdev, id);
    }
#endif /* ATH_PERF_PWR_OFFLOAD && HIF_PCI */

    return (-ENODEV);
}

static void
ath_pci_remove(struct pci_dev *pdev)
{
    u_int8_t max_payload;

    pci_read_config_byte(pdev, 0x74, &max_payload);
#if (ATH_PERF_PWR_OFFLOAD != 0) && defined(HIF_PCI)
    if (((pdev->device == 0xabcd) && (max_payload != 0)) || (pdev->device == AR9888_DEVICE_ID) || (pdev->device == AR900B_DEVICE_ID) || (pdev->device == AR9887_DEVICE_ID) || (pdev->device == QCA9984_DEVICE_ID) || (pdev->device == QCA9888_DEVICE_ID)) {
        ol_ath_pci_remove(pdev);
        return;
    }
#endif /* ATH_PERF_PWR_OFFLOAD && HIF_PCI */
}

#ifdef ATH_BUS_PM
static int
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,10)
ath_pci_suspend(struct pci_dev *pdev, pm_message_t state)
#else
ath_pci_suspend(struct pci_dev *pdev, u32 state)
#endif
{
    u_int8_t max_payload;

    pci_read_config_byte(pdev, 0x74, &max_payload);
#if (ATH_PERF_PWR_OFFLOAD != 0) && defined(HIF_PCI)
    if (((pdev->device == 0xabcd) && (max_payload != 0)) || (pdev->device == AR9888_DEVICE_ID) || (pdev->device == AR900B_DEVICE_ID) || (pdev->device == AR9887_DEVICE_ID) || (pdev->device == QCA9984_DEVICE_ID) || (pdev->device == QCA9888_DEVICE_ID)) {
        if(ol_ath_pci_suspend(pdev, state)) {
            return (-1);
        }
        return 0;
    }
#endif /* ATH_PERF_PWR_OFFLOAD && HIF_PCI */

    return 0;
}

static int
ath_pci_resume(struct pci_dev *pdev)
{
    u_int8_t max_payload;

    pci_read_config_byte(pdev, 0x74, &max_payload);
#if (ATH_PERF_PWR_OFFLOAD != 0) && defined(HIF_PCI)
    if (((pdev->device == 0xabcd) && (max_payload != 0)) || pdev->device == AR9888_DEVICE_ID || (pdev->device == AR900B_DEVICE_ID) || (pdev->device == AR9887_DEVICE_ID) || (pdev->device == QCA9984_DEVICE_ID) || (pdev->device == QCA9888_DEVICE_ID)) {
        if (ol_ath_pci_resume(pdev)) {
            return (-1);
        }
        return 0;
    }
#endif /* ATH_PERF_PWR_OFFLOAD && HIF_PCI */

    return 0;
}
#endif /* ATH_BUS_PM */

MODULE_DEVICE_TABLE(pci, ath_pci_id_table);

static struct pci_driver ath_pci_driver = {
    .name       = "ath_ol_pci",
    .id_table   = ath_pci_id_table,
    .probe      = ath_pci_probe,
    .remove     = ath_pci_remove,
#ifdef ATH_BUS_PM
    .suspend    = ath_pci_suspend,
    .resume     = ath_pci_resume,
#endif /* ATH_BUS_PM */
    /* Linux 2.4.6 has save_state and enable_wake that are not used here */
};

/*
 * Module glue.
 */
#include "version.h"
static char *version = ATH_PCI_VERSION " (Atheros/multi-bss)";
static char *dev_info = "ath_ol_pci";

struct semaphore reset_in_progress;
bool driver_registered = false;


#if (ATH_PERF_PWR_OFFLOAD != 0) && defined(HIF_PCI)
/* peregrine */
#ifdef CONFIG_AR900B_SUPPORT
extern void ramdump_work_handler(void *scn);
#endif

void
ol_ath_pci_recovery_remove(struct pci_dev *pdev);

static void
ath_pci_recovery_remove(struct pci_dev *pdev)
{
    u_int8_t max_payload;

    pci_read_config_byte(pdev, 0x74, &max_payload);
#if (ATH_PERF_PWR_OFFLOAD != 0) && defined(HIF_PCI)
    if (((pdev->device == 0xabcd) && (max_payload != 0)) || (pdev->device == AR9888_DEVICE_ID) || (pdev->device == AR900B_DEVICE_ID) || (pdev->device == AR9887_DEVICE_ID) || (pdev->device == QCA9984_DEVICE_ID) || (pdev->device == QCA9888_DEVICE_ID)) {
        ol_ath_pci_recovery_remove(pdev);
        return;
    }
#endif /* ATH_PERF_PWR_OFFLOAD && HIF_PCI */

}

int
ol_ath_pci_recovery_probe(struct pci_dev *pdev, const struct pci_device_id *id);

static int
ath_pci_recovery_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
    u_int8_t max_payload;

    pci_read_config_byte(pdev, 0x74, &max_payload);
#if (ATH_PERF_PWR_OFFLOAD != 0) && defined(HIF_PCI)
    /* emulation device id, peregrine id or beeliner id*/
    if (((id->device == 0xabcd) && (max_payload != 0)) || (id->device == AR9888_DEVICE_ID) || (id->device == AR9887_DEVICE_ID) || (id->device == AR900B_DEVICE_ID) || (id->device == QCA9984_DEVICE_ID) || (id->device == QCA9888_DEVICE_ID)) {
#if QCA_PARTNER_DIRECTLINK_TX
        wlan_pltfrm_directlink_set_pcie_base((uint32_t) pci_resource_start(pdev, 0));
#endif /* QCA_PARTNER_DIRECTLINK_TX */

        return ol_ath_pci_recovery_probe(pdev, id);
    }
#endif /* ATH_PERF_PWR_OFFLOAD && HIF_PCI */

    return (-ENODEV);
}


int ath_pci_recover(struct ol_ath_softc_net80211 *scn)
{
    struct _NIC_DEV *aps_osdev;

    aps_osdev = scn->sc_osdev;

    ath_pci_recovery_probe((struct pci_dev *)(aps_osdev->bdev), (const struct pci_device_id *)scn->pdevid);
    ol_ath_iw_attach(pci_get_drvdata(aps_osdev->bdev));

    return 0;
}

extern struct ol_ath_softc_net80211 *ol_global_scn[10];
void pci_defer_reconnect(struct work_struct *pci_reconnect_work)
{
    struct pci_dev *pdev;
    const struct pci_device_id *id;
    struct _NIC_DEV *aps_osdev;
    struct ol_ath_softc_net80211 *scn;
    int recovery_enable;

#ifdef CONFIG_AR900B_SUPPORT
    scn = container_of(pci_reconnect_work, struct ol_ath_softc_net80211, pci_reconnect_work);
    ramdump_work_handler(scn);

    if (scn->recovery_enable) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Resetting the radio\n");
#endif
        if (down_interruptible(&reset_in_progress))
            return;

        if (!driver_registered) {
            up(&reset_in_progress);
            return;
        }

        recovery_enable = scn->recovery_enable;
        /* We are here because the target has crashed
         * hence remove the PCI device and reload it
         */
        aps_osdev = scn->sc_osdev;
        pdev = aps_osdev->bdev;
        id =(const struct pci_device_id *)scn->pdevid;

        rtnl_lock();
        ath_pci_recovery_remove(pdev);

        if (recovery_enable == RECOVERY_ENABLE_AUTO) {
            ath_pci_recovery_probe(pdev, id);

            /*Send event to user space */
#if UMAC_SUPPORT_ACFG
            OSIF_RADIO_DELIVER_EVENT_WATCHDOG(&(scn->sc_ic), ACFG_WDT_REINIT_DONE);
#endif
            scn->sc_ic.recovery_in_progress = 0;
        } else
            ol_ath_iw_detach(pci_get_drvdata(pdev));

        /* The recovery process resets recovery_enable flag. restore it here */
        scn->recovery_enable = recovery_enable;

        rtnl_unlock();

        up(&reset_in_progress);

#ifdef CONFIG_AR900B_SUPPORT
    }
#endif
    ;; //Do nothing
}
#endif  /* (ATH_PERF_PWR_OFFLOAD != 0) && defined(HIF_PCI) */

#include <linux/ethtool.h>

MODULE_AUTHOR("Errno Consulting, Sam Leffler");
MODULE_DESCRIPTION("Support for Atheros 802.11 wireless LAN cards.");
MODULE_SUPPORTED_DEVICE("Atheros WLAN cards");
#ifdef MODULE_LICENSE
MODULE_LICENSE("Dual BSD/GPL");
#endif

static int __init
init_ath_pci(void)
{

#ifdef ATH_AHB
    int pciret = 0, ahbret = 0;
    int init_ath_ahb(void);
#endif

#ifdef ATH_AHB
    ahbret = init_ath_ahb();
    if(ahbret < 0 ) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ath_ahb: Error while registering ath wlan ahb driver\n");
    }
#endif

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO "%s: %s\n", dev_info, version);

    if (pci_register_driver(&ath_pci_driver) < 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ath_pci: No devices found, driver not installed.\n");
        pci_unregister_driver(&ath_pci_driver);
#ifdef ATH_AHB
        pciret = -ENODEV;
#else
        return (-ENODEV);
#endif
    }


#ifdef ATH_AHB
    /*
     * Return failure only when there is no wlan device
     * on both pci and ahb buses.
     */
      if (ahbret && pciret) {
              /* which error takes priority ?? */
              return ahbret;
      }
#endif

    driver_registered = true;
    sema_init(&reset_in_progress, 1);
    return 0;
}
module_init(init_ath_pci);


static void __exit
exit_ath_pci(void)
{

#ifdef ATH_AHB
    void exit_ath_ahb(void);
#endif


    if (down_interruptible(&reset_in_progress))
        return;

    pci_unregister_driver(&ath_pci_driver);
    driver_registered = false;
    up(&reset_in_progress);

#ifdef ATH_AHB
        exit_ath_ahb();
#else
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO "%s: driver unloaded\n", dev_info);
#endif /* ATH_AHB */

}
module_exit(exit_ath_pci);
#if (ATH_PERF_PWR_OFFLOAD != 0) && defined(HIF_PCI)
EXPORT_SYMBOL(pci_defer_reconnect);
#endif /* defined(ATH_PERF_PWR_OFFLOAD) && defined(HIF_PCI) */
