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

#include <linux/if_arp.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/usb.h>

#include "if_athvar.h"

/* WMI/HTC/HIF */
#include "ath_htc.h"

struct ath_usb_softc {
    struct ath_softc_net80211   aps_sc;
    struct _NIC_DEV             aps_osdev;
#ifdef CONFIG_PM
    u32                         aps_pmstate[16];
#endif
};

#define VENDOR_ATHR             0x0CF3  //Atheros
#define PRODUCT_AR9271          0x9271
#define PRODUCT_MAGPIE_MERLIN   0x7010
#define PRODUCT_MAGPIE_KIWI     0x7015

#define DEVID_MAGPIE_MERLIN     0x002A
#define DEVID_MAGPIE_KIWI       0x002E

/* attach/detach entry */
extern int __ath_attach(u_int16_t devid, struct net_device *dev, HAL_BUS_CONTEXT *bus_context, osdev_t osdev);
extern int __ath_detach(struct net_device *dev);
extern int __ath_remove_interface(struct net_device *dev);
extern void __ath_set_delete(struct net_device *dev);

extern void init_wlan(void);

#ifdef ATH_MAGPIE
static const char ath_usb_driver_name[] = "MAGPIE";
#else
static const char ath_usb_driver_name[] = "ATHEROS_AR9271";
#endif

/* table of devices that work with this driver */
static struct usb_device_id ath_usb_ids[] = {
    { USB_DEVICE(VENDOR_ATHR, PRODUCT_AR9271) },
    { USB_DEVICE(VENDOR_ATHR, PRODUCT_MAGPIE_MERLIN) },
    { USB_DEVICE(VENDOR_ATHR, PRODUCT_MAGPIE_KIWI) },
    { }                 /* Terminating entry */
};

MODULE_DEVICE_TABLE(usb, ath_usb_ids);

extern const unsigned char usbFwImageMagpie[];
extern const unsigned long usbFwImageMagpieSize;
extern const unsigned char usbFwImageMagpie_1_1[];
extern const unsigned long usbFwImageMagpie_1_1_Size;
extern const unsigned char usbFwImage[];
extern const unsigned long usbFwImageSize;


/*
 * 
 */
int ath_host_attach(struct ath_softc_net80211 *scn, uint16_t devid)
{
#define HAL_BUS_TYPE_USB    0x02

    HAL_BUS_CONTEXT bus_context;
    struct ath_usb_softc *sc = (struct ath_usb_softc *)scn;
    struct net_device *dev = sc->aps_osdev.netdev;
    //osdev_t osdev = &sc->aps_osdev;

    bus_context.bc_info.bc_tag = NULL;
    bus_context.bc_info.cal_in_flash = 0;
    bus_context.bc_handle = (void*) NULL;
    bus_context.bc_bustype = HAL_BUS_TYPE_USB;

    if(__ath_attach(devid, dev, &bus_context, &sc->aps_osdev)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: __ath_attach fail!\n", __func__);
        return 1;
    }
    
    return 0;

#undef HAL_USB_TYPE_USB
}

/*
 * 
 */
void ath_host_detach(osdev_t osdev)
{
    __ath_detach(osdev->netdev);
}

void ath_remove_interface(osdev_t osdev)
{
    __ath_remove_interface(osdev->netdev);
}

void inline ath_set_delete(struct _NIC_DEV * osdev)
{
    __ath_set_delete(osdev->netdev);
}

void ath_os_hif_cb_assign(osdev_t osdev)
{
    osdev->os_usb_submitMsgInUrb         = OS_Usb_SubmitMsgInUrb;
    osdev->os_usb_submitCmdOutUrb        = OS_Usb_SubmitCmdOutUrb;
    osdev->os_usb_submitRxUrb            = OS_Usb_SubmitRxUrb;
    osdev->os_usb_submitTxUrb            = OS_Usb_SubmitTxUrb;
    osdev->os_usb_getFreeTxBufferCnt     = OS_Usb_GetFreeTxBufferCnt;
    osdev->os_usb_getMaxTxBufferCnt      = OS_Usb_GetMaxTxBufferCnt;
    osdev->os_usb_getTxBufferCnt         = OS_Usb_GetTxBufferCnt;
    osdev->os_usb_getTxBufferThreshold   = OS_Usb_GetTxBufferThreshold;
    osdev->os_usb_getFreeCmdOutBufferCnt = OS_Usb_GetFreeCmdOutBufferCnt;
    osdev->os_usb_initTxRxQ              = OS_Usb_InitTxRxQ;
    osdev->os_usb_enable_fwrcv           = OS_Usb_Enable_FwRcv;
}

#define HIF_USB_MAX_DEVICE  2
static int g_magpie_usb_ifc_max = HIF_USB_MAX_DEVICE;
static struct usb_interface **g_magpie_usb_ifc;
static int g_magpie_usb_device_count = 0;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
static void *ath_usb_probe(struct usb_device *dev, unsigned int ifnum,
                        const struct usb_device_id *id)
{
    struct usb_interface *interface = &dev->actconfig->interface[ifnum];
#else
static int ath_usb_probe(struct usb_interface *interface,
                      const struct usb_device_id *id)
{
    struct usb_device *dev = interface_to_usbdev(interface);
#endif

    struct net_device *net = NULL;
    struct ath_usb_softc *aps_usb_sc;
    //struct _NIC_DEV *os_hdl = NULL;
    int vendor_id, product_id;
    int result = 0;
    uint8_t* Image;
    uint32_t ImageSize;    
    uint16_t devid = 0x23;
    int i;
    int thread_create = 0;

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO "ath_usb_probe\n");

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
    usb_get_dev(dev);
#endif    

    vendor_id = dev->descriptor.idVendor;
    product_id = dev->descriptor.idProduct;

#if 1 
    /* usb device information display */  
    //printk(KERN_NOTICE "vendor_id = %04x\n", vendor_id);
    //printk(KERN_NOTICE "product_id = %04x\n", product_id);

    if (dev->speed == USB_SPEED_HIGH)
      QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_NOTICE "USB 2.0 Host\n");
    else
      QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_NOTICE "USB 1.1 Host\n");
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
    if (usb_set_configuration(dev, dev->config[0].bConfigurationValue))
    {
      QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "usb_set_configuration() failed\n");
      result = -EIO;
      goto fail;
    }
#endif

    for (i = 0; i < g_magpie_usb_ifc_max; i++) {
        if (g_magpie_usb_ifc[i] == NULL) {
            g_magpie_usb_ifc[i] = interface;
            g_magpie_usb_device_count++;
            break;
        }
    }
    if (i == g_magpie_usb_ifc_max) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: only %u usb devices are supported.\n", __FUNCTION__, i);
        result = -1;
        goto fail;
    } else {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: %dth device inserted\n",__FUNCTION__,g_magpie_usb_device_count);
    }

    /* allocate net devie */
    net = alloc_netdev(sizeof(struct ath_usb_softc), "wifi%d", ether_setup);
    if (net == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "ath_usb: no memory for device state\n");
        result = -EIO;
        goto fail;
    }
    aps_usb_sc = ath_netdev_priv(net);
    aps_usb_sc->aps_osdev.netdev = net;               // struct net_device
    aps_usb_sc->aps_osdev.bdev = (void *)aps_usb_sc;  // (void *) struct ath_usb_softc;
    aps_usb_sc->aps_osdev.wmi_dev = (void *)aps_usb_sc;  // (void *) struct ath_usb_softc;
    aps_usb_sc->aps_osdev.udev = dev;                 // struct usb_device
    aps_usb_sc->aps_osdev.interface = interface;      // struct usb_interface
    
    if (le16_to_cpu(product_id) == PRODUCT_MAGPIE_MERLIN) 
    {
        aps_usb_sc->aps_osdev.isMagpie = 1;               // Magpie
        devid = DEVID_MAGPIE_MERLIN;
    }
    else if (le16_to_cpu(product_id) == PRODUCT_MAGPIE_KIWI)
    {
    	aps_usb_sc->aps_osdev.isMagpie = 1;               // Magpie
    	devid = DEVID_MAGPIE_KIWI;
    }
    else
        aps_usb_sc->aps_osdev.isMagpie = 0;               // K2

    /* Firmware download */
    if (aps_usb_sc->aps_osdev.isMagpie == 1)
    {
        /* Magpie 1.1 */
        if (le16_to_cpu(dev->descriptor.bcdDevice) == 0x0202)
        {
            Image = (uint8_t *)usbFwImageMagpie_1_1;
            ImageSize = (uint32_t)usbFwImageMagpie_1_1_Size;
        }
        else
        {
            Image = (uint8_t *)usbFwImageMagpie;
            ImageSize = (uint32_t)usbFwImageMagpieSize;
        }
    } 
    else 
    {
        Image = (uint8_t *)usbFwImage;
        ImageSize = (uint32_t)usbFwImageSize;
    }

    aps_usb_sc->aps_osdev.Image = Image;
    aps_usb_sc->aps_osdev.ImageSize = ImageSize;
    aps_usb_sc->aps_osdev.enablFwRcv = 0;

    if (athUsbFirmwareDownload(&(aps_usb_sc->aps_osdev), Image, ImageSize, ZM_FIRMWARE_WLAN_ADDR))
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: athUsbFirmwareDownload fail!", __func__);
        result = -EIO;
        goto fail1;
    }
   
#ifdef NBUF_PREALLOC_POOL
    if(!athLnxAllocRegInBuf(&(aps_usb_sc->aps_osdev))) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: athLnxAllocRegInBuf fail!\n", __func__);
        result = -EIO;
        goto fail1;  
    }
#endif    
   
    /* urb */
    if (!athLnxAllocAllUrbs(&(aps_usb_sc->aps_osdev))) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: athLnxAllocAllUrbs fail!\n", __func__);
        result = -EIO;
        goto fail1;
    }

    /* os hif callback*/
    ath_os_hif_cb_assign(&(aps_usb_sc->aps_osdev));

    /* HTC/HIF/WMI */    
    if(MpHtcAttach(&(aps_usb_sc->aps_osdev))) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: MpHtcAttach fail!\n", __func__);
        result = -EIO;
        goto fail2;
    }
    
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
    usb_set_intfdata(interface, &(aps_usb_sc->aps_osdev));
#endif    

    ath_register_htc_thread_callback(&(aps_usb_sc->aps_osdev));

    if (ath_create_htc_thread(&(aps_usb_sc->aps_osdev)) != 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: create thread fail\n", __func__);
        result = -EINVAL;
        goto fail1;
    }

    if(g_magpie_usb_device_count == 1) {
        if (ath_create_htc_tx_thread(net) != 0) { 
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: create tx thread fail\n", __func__);
            result = -EINVAL; 
            goto fail1; 
        }
    }
    thread_create = 1;
    
    athLnxCreateRecoverWorkQueue(&(aps_usb_sc->aps_osdev));

    /* ath/hal attach */
    if (ath_host_attach(&(aps_usb_sc->aps_sc), devid)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: ath_host_attach fail!\n", __func__);
        result = -EIO;
        goto fail2;
    }

    athLnxStartPerSecTimer(&(aps_usb_sc->aps_osdev));

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
    usb_inc_dev_use(dev);
#endif
  
    goto done;

fail2:
    /* ath_host_attach fail */
    {
        osdev_t osdev = &(aps_usb_sc->aps_osdev);

        MpHtcDetach(osdev);
        HIF_USBDeviceDetached((void*)osdev);
        /* usb/urb release */
        athLnxUnlinkAllUrbs(osdev);
        athLnxFreeAllUrbs(osdev);
#ifdef NBUF_PREALLOC_POOL
        athLnxFreeRegInBuf(osdev);
#endif
        if(thread_create) {       
            ath_terminate_htc_thread(osdev);
            if(g_magpie_usb_device_count == 1)
                ath_terminate_htc_tx_thread();
        }
    }
   
fail1:
    /* firmware download fail */
    /* athLnxAllocAllUrbs fail */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
    /* always do this for ath_usb_disconnect() */
    usb_set_intfdata(interface, &(aps_usb_sc->aps_osdev));
#endif  

fail: 
    for (i = 0; i < g_magpie_usb_ifc_max; i++) {
        if (g_magpie_usb_ifc[i] == interface) {
            g_magpie_usb_ifc[i] = NULL;
            g_magpie_usb_device_count--;
            break;
        }
    }
    if(net) {
        free_netdev(net);
    }
done:    
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
    return aps_usb_sc->aps_osdev;
#else
    return result;
#endif  
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
static void ath_usb_disconnect(struct usb_device *dev, void *ptr)
#else
static void ath_usb_disconnect(struct usb_interface *interface)
#endif
  {    
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
    struct _NIC_DEV *os_hdl = (struct _NIC_DEV *) usb_get_intfdata(interface);
#else
    struct _NIC_DEV *os_hdl = (struct _NIC_DEV *)ptr;
#endif  
    int i;

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO "ath_usb_disconnect\n");

    for (i = 0; i < g_magpie_usb_ifc_max; i++) {          
        if (g_magpie_usb_ifc[i] == interface) {
            g_magpie_usb_ifc[i] = NULL;
            g_magpie_usb_device_count--; 
            break;
        }
    }
    
    if(i == g_magpie_usb_ifc_max) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: interface %p not found\n", __func__, interface);
        return;
    }

    ath_htc_thread_stopping(os_hdl);

    /* set delete flag */
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO "set deleted flag\n");
    ath_set_delete(os_hdl);
                
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))    
    usb_dec_dev_use(dev);
#else
    usb_put_dev(interface_to_usbdev(interface));
#endif
    if (os_hdl->isModuleExit == 0)
    {
        ath_remove_interface(os_hdl);
    }
#if 1
    /* HTC/HIF/WMI */
    MpHtcDetach(os_hdl);
#endif    

#if 1
    /* ath/hal detach */
    ath_host_detach(os_hdl);
#endif

    HIF_USBDeviceDetached((void*)os_hdl);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
    usb_set_intfdata(os_hdl->interface, NULL);
#endif        
    
#if 1 
    /* stop per second timer */
    athLnxStopPerSecTimer(os_hdl);

    /* usb/urb release */
    athLnxUnlinkAllUrbs(os_hdl);
    athLnxFreeAllUrbs(os_hdl);
#ifdef NBUF_PREALLOC_POOL
    athLnxFreeRegInBuf(os_hdl);
#endif    
#endif

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s, terminate htc thread %p\n", __func__, os_hdl->athHTC_task);
    ath_terminate_htc_thread(os_hdl);

    if(!g_magpie_usb_device_count) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s, last device disconnected, terminate tx thread\n",__func__);
        ath_terminate_htc_tx_thread();
    }
    
    free_netdev(os_hdl->netdev);    
}
 
static struct usb_driver ath_usb_driver = {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15))
    .owner        = THIS_MODULE,
#endif
#endif
    .name         = ath_usb_driver_name,
    .probe        = ath_usb_probe,
    .disconnect   = ath_usb_disconnect,
    .id_table     = ath_usb_ids,
};

int ath_module_init(void)
{
    int i;
    
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO "%s loaded\n", __func__);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO "%s : Max. WiFi device support to %d\n", __func__, g_magpie_usb_ifc_max);

    if ((g_magpie_usb_ifc_max > HIF_USB_MAX_DEVICE) ||
        ((g_magpie_usb_ifc = (struct usb_interface **)kmalloc((sizeof(struct usb_interface *) * g_magpie_usb_ifc_max), 
                                                              GFP_ATOMIC)) == NULL)){
        BUG();
    }    

    for (i = 0; i < g_magpie_usb_ifc_max; i++){
        g_magpie_usb_ifc[i] = NULL;
    }
    
    /* Init wlan reg params */
    init_wlan();
        
    usb_register(&ath_usb_driver);

    return 0;
}

void
ath_module_exit(void) 
{
    int i;
    struct _NIC_DEV *os_hdl;    

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO "%s exit\n", __func__);

    for (i = 0; i < g_magpie_usb_ifc_max; i++) {
        if(g_magpie_usb_ifc[i] != NULL) {
            os_hdl = (struct _NIC_DEV *) usb_get_intfdata(g_magpie_usb_ifc[i]);
            if(os_hdl) {
                os_hdl->isModuleExit = 1;
                athLnxRebootCmd(os_hdl);
            }
        }
    }
    usb_deregister(&ath_usb_driver);

    kfree(g_magpie_usb_ifc);
}

MODULE_AUTHOR("Atheros Communications, Inc.");
MODULE_DESCRIPTION("Support for Atheros 802.11 wireless LAN cards.");
MODULE_SUPPORTED_DEVICE("Atheros WLAN cards");
#ifdef MODULE_LICENSE
MODULE_LICENSE("Dual BSD/GPL");
#endif

module_param(g_magpie_usb_ifc_max, int, 0);
MODULE_PARM_DESC(g_magpie_usb_ifc_max, "Max. WiFi device support.");
module_init(ath_module_init);
module_exit(ath_module_exit);
