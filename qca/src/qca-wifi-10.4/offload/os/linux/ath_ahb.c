/*
 * Copyright (c) 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <hif.h>
#include <osdep.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/if_arp.h>
#include "ath_pci.h"
#include "ol_ath.h"
#include "hif.h"
#include "hif_napi.h"
#include <linux/platform_device.h>
#include <linux/device.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include "ah_devid.h"
#include <qdf_mem.h>
#include <osif_private.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0))
#include <drivers/leds/leds-ipq.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
#include <drivers/leds/leds-ipq40xx.h>
#endif

extern struct g_wifi_info g_winfo;

void *ol_hif_open(struct device *dev, void *bdev, void *bid,
        enum ath_hal_bus_type bus_type, bool reinit, qdf_device_t qdf_dev);
void ol_hif_close(void *hif_ctx);

int ol_ath_target_stop(struct ieee80211com *ic);
void ic_reset_params(struct ieee80211com *ic);
int ol_ath_target_start(struct ol_ath_softc_net80211 *scn);
void osif_recover_vap_create(struct ieee80211com *ic);
int osif_recover_vap_delete(struct ieee80211com *ic);

void ol_ath_check_btcoex_support(struct ol_ath_softc_net80211 *scn)
{
	struct platform_device *pdev = (struct platform_device *) (scn->sc_osdev->bdev);
	struct device_node *dev_node = pdev->dev.of_node;

	/* Get btcoex HW support info from device tree */
	of_property_read_u32(dev_node, "btcoex_support", &scn->btcoex_support);
	if (scn->btcoex_support) {
		of_property_read_u32(dev_node, "wlan_prio_gpio", &scn->btcoex_gpio);       /* WL Priority */
		of_property_read_u32(dev_node, "coex_gpio_pin_1", &scn->coex_gpio_pin_1);  /* BT Priority */
		of_property_read_u32(dev_node, "coex_gpio_pin_2", &scn->coex_gpio_pin_2);  /* ZB Priority */
		of_property_read_u32(dev_node, "coex_gpio_pin_3", &scn->coex_gpio_pin_3);  /* Grant */
	}
	qdf_print("btcoex_support %d, wlan_prio_gpio %d, coex_gpio_pin %d %d %d\n",
			  scn->btcoex_support, scn->btcoex_gpio,
			  scn->coex_gpio_pin_1, scn->coex_gpio_pin_2, scn->coex_gpio_pin_3);
}
void ol_ath_check_bandfilter_switch_gpio_support(struct ol_ath_softc_net80211 *scn)
{
    struct platform_device *pdev = (struct platform_device *) (scn->sc_osdev->bdev);
    struct device_node *dev_node = pdev->dev.of_node;
    scn->band_filter_switch_gpio = 0;
    if(0 == of_property_read_u32(dev_node, "dual_band_switch_gpio", &scn->band_filter_switch_gpio))
        scn->band_filter_switch_support = 1;
    else
        scn->band_filter_switch_support = 0;

}
int
ol_ath_ahb_probe(struct platform_device *pdev, const struct platform_device_id *id)
{

    struct ol_attach_t ol_cfg;
    void *hif_context = NULL;
    struct hif_target_info *tgt_info = NULL;
    struct _NIC_DEV *aps_osdev = NULL;
    qdf_device_t  qdf_dev = NULL;    /* qdf handle */
    int ret = 0;
    struct ol_ath_softc_net80211 *scn;
    bool flag = false;
    int i;

    if (id->driver_data != IPQ4019_DEVICE_ID) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Unsupported device\n");
        ret = -EIO;
        goto err_notsup;
    }

    aps_osdev = qdf_mem_malloc(sizeof(*aps_osdev));
    if (aps_osdev == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s %d mem alloc failure \n",__func__,__LINE__);
        ret = -ENOMEM;
        goto err_notsup;
    }
    OS_MEMSET(aps_osdev, 0, sizeof(*(aps_osdev)));
    aps_osdev->bdev = pdev;
    aps_osdev->device = &pdev->dev;
    aps_osdev->bc.bc_bustype = HAL_BUS_TYPE_AHB;

    /* initialize the qdf_dev handle */
    qdf_dev = qdf_mem_malloc(sizeof(*(qdf_dev)));
    if (qdf_dev == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s %d mem alloc failure \n",__func__,__LINE__);
        ret = -ENOMEM;
        goto cleanup_aps_dev;
    }

    OS_MEMSET(qdf_dev, 0, sizeof(*(qdf_dev)));
    qdf_dev->drv_hdl = NULL; /* bus handle */
    qdf_dev->dev = &pdev->dev; /* device */
    qdf_dev->drv = aps_osdev;
    ol_cfg.bus_type = BUS_TYPE_AHB;
    qdf_dev->netdev = ol_create_radio_netdev(&ol_cfg);

    hif_context  = (void *)ol_hif_open(&pdev->dev, (void *)pdev, (void *)id, HAL_BUS_TYPE_AHB, 0,qdf_dev);
    if(hif_context == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Error in ol_hif_open\n");
        ret = -ENOMEM;
        goto cleanup_adf_dev;
    }

    tgt_info = hif_get_target_info_handle(hif_context);
    if(!tgt_info) {
        ret = -EIO;
        goto err;
    }

    ol_cfg.devid = id->driver_data;
    ol_cfg.target_type = tgt_info->target_type;
    ol_cfg.pdevid = (void *)id;

    ret = __ol_ath_attach(hif_context, &ol_cfg, aps_osdev, qdf_dev);
    if(ret != 0) {
        ret = -EIO;
        goto cleanup_hif_context;
    }

    scn = ath_netdev_priv(aps_osdev->netdev);
    for (i = 0; i < NUM_MAX_RADIOS; i++) {
        if (g_winfo.wifi_radios[i].sc == NULL) {
            g_winfo.wifi_radios[i].sc = (void *)scn;
            g_winfo.wifi_radios[i].wifi_radio_type = OFFLOAD;
            scn->wifi_num = i;
            flag = true;
            qdf_print("%s num_radios=%d, wifi_radios[%d].sc = %p wifi_radio_type = %d\n",
                    __func__, i, i, g_winfo.wifi_radios[i].sc, g_winfo.wifi_radios[i].wifi_radio_type);
            break;
        } else
            continue;
    }
    g_winfo.num_radios++;
    if(g_winfo.num_radios > NUM_MAX_RADIOS) {
        qdf_print("%s: Need to increase the NUM_MAX_RADIOS\n", __func__);
	goto err_attach;
    }

    ol_ath_diag_user_agent_init(scn);

    /* store the pdev here to access during ol_ath_ahb_remove() */
    platform_set_drvdata(pdev, aps_osdev->netdev);

    return 0;
err_attach:
    if (flag) {
        g_winfo.num_radios--;
        g_winfo.wifi_radios[scn->wifi_num].sc = NULL;
    }

err:
cleanup_hif_context:
    if (hif_context) {
        hif_disable_isr(hif_context);
        ol_hif_close(hif_context);
    }
cleanup_adf_dev:
    qdf_mem_free(qdf_dev);
cleanup_aps_dev:
    qdf_mem_free(aps_osdev);
err_notsup:
    return ret;
}

void
ol_ath_ahb_recovery_remove(struct platform_device *pdev)
{
    struct net_device *dev = platform_get_drvdata(pdev);
    struct ol_ath_softc_net80211 *scn;
    struct ieee80211com *ic;

    scn = ath_netdev_priv(dev);
    ic =  &scn->sc_ic;

    if (osif_recover_vap_delete(ic) != 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ERROR: FW Recovery failed\n");
    }

    ol_ath_target_stop(ic);
    dev_close(dev);
    ic_reset_params(ic);
}

int
ol_ath_ahb_recovery_probe(struct platform_device *pdev, const struct platform_device_id *id)
{
    struct net_device *dev = platform_get_drvdata(pdev);
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);
    struct ieee80211com *ic;

    ic =  &scn->sc_ic;

    ol_ath_target_start(scn);

    osif_recover_vap_create(ic);

    return 0;
}

#define REMOVE_VAP_TIMEOUT_COUNT  20
#define REMOVE_VAP_TIMEOUT        (HZ/10)

void
ol_ath_ahb_remove(struct platform_device *pdev)
{
    struct net_device *dev = platform_get_drvdata(pdev);
    struct ol_ath_softc_net80211 *scn;
    u_int32_t target_ver,target_type;
    struct hif_opaque_softc *sc;
    void __iomem *mem;
    int target_paused = TRUE;
    int waitcnt = 0;
    void *hif_cxt = NULL;
    struct _NIC_DEV *aps_osdev = NULL;
    qdf_device_t  qdf_dev = NULL;    /* qdf handle */
    uint32_t wifi_num = 0;

    /* Attach did not succeed, all resources have been
     * freed in error handler
     */
    if (!dev) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "dev is null\n");
        return;
    }
    scn = ath_netdev_priv(dev);
    hif_cxt = scn->hif_hdl;
    sc = (struct hif_opaque_softc *)scn->hif_hdl;
    mem = (void __iomem *)dev->mem_start;

    __ol_vap_delete_on_rmmod(dev);

    while (atomic_read(&scn->reset_in_progress)  && (waitcnt < REMOVE_VAP_TIMEOUT_COUNT)) {
        schedule_timeout_interruptible(REMOVE_VAP_TIMEOUT);
        waitcnt++;
    }

    /* Suspend the target if it is not done during the last vap removal */

    if (!(scn->down_complete)) {
        /* Suspend Target */
        qdf_print("Suspending Target - with disable_intr set :%s (sc %p) scn=%p\n",dev->name,sc, scn);
        if (!ol_ath_suspend_target(scn, 1)) {
            u_int32_t  timeleft;
            qdf_print("waiting for target paused event from target :%s (sc %p)\n",dev->name,sc);
            /* wait for the event from Target*/
            timeleft = wait_event_interruptible_timeout(scn->sc_osdev->event_queue,
                    (scn->is_target_paused == TRUE),
                    200);
            if(!timeleft || signal_pending(current)) {
                qdf_print("ERROR: Failed to receive target paused event :%s (sc %p)\n",dev->name,sc);
                target_paused = FALSE;
            }
            /*
             * reset is_target_paused and host can check that in next time,
             * or it will always be TRUE and host just skip the waiting
             * condition, it causes target assert due to host already suspend
             */
            scn->is_target_paused = FALSE;
        }
    }

    /* Copy the pointer as netdev will be freed in __ol_ath_detach */
    aps_osdev = scn->sc_osdev;
    qdf_dev = scn->qdf_dev;
    wifi_num = scn->wifi_num;

    if (!scn->down_complete) {
        ol_ath_diag_user_agent_fini(scn);
    }
    /* save target_version since scn is not valid after __ol_ath_detach */
    target_ver = scn->target_version;
    target_type = scn->target_type;
    if (target_paused == TRUE) {
        __ol_ath_detach(dev);
    } else {
        scn->fwsuspendfailed = 1;
        wmi_stop(scn->wmi_handle);
    }

    if (target_paused != TRUE) {
        __ol_ath_detach(dev);
    }

    if(aps_osdev)
        kfree(aps_osdev);
    if(qdf_dev)
        kfree(qdf_dev);

    g_winfo.num_radios--;
    g_winfo.wifi_radios[wifi_num].sc = NULL;

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO "ath_ahb_remove\n");
}


#if OL_ATH_SUPPORT_LED
/* Temporarily defining the core_sw_output address here as
ar900b,qca9884,qca9888 didn't define the macro in FW cmn headers */
#define CORE_SW_OUTPUT 0x82004

void ol_ath_led_event(struct ol_ath_softc_net80211 *scn, OL_LED_EVENT event);
extern bool ipq4019_led_initialized;
extern uint32_t ipq4019_led_type;
extern struct ol_ath_softc_net80211 *ol_global_scn[GLOBAL_SCN_SIZE];
extern int ol_num_global_scn;

void ipq4019_wifi_led(struct ol_ath_softc_net80211 *scn, int on_or_off)
{
    struct hif_opaque_softc *hif_hdl = (struct hif_opaque_softc *)(scn->hif_hdl);

    if (!hif_hdl)
        return;

    if (!ipq4019_led_initialized) {
        return;
    }
    if ((ipq4019_led_type == IPQ4019_LED_GPIO_PIN) &&
        (scn->scn_led_gpio > 0)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
            gpio_set_value_cansleep(scn->scn_led_gpio, on_or_off);
#endif
    } else if (ipq4019_led_type == IPQ4019_LED_SOURCE) {
        hif_reg_write(hif_hdl, CORE_SW_OUTPUT, on_or_off);
    }
    return;
}

uint8_t ipq4019_is_wifi_gpio_shared(struct ol_ath_softc_net80211 *scn)
{
    struct ol_ath_softc_net80211 *tmp_scn = NULL;
    int32_t scn_idx = 0;
    int32_t scn_num = 0;

    while ((scn_num < ol_num_global_scn) && (scn_idx < GLOBAL_SCN_SIZE)) {
        tmp_scn = ol_global_scn[scn_idx++];
        if (tmp_scn == NULL)
            continue;
        scn_num++;
        if (tmp_scn == scn)
            continue;
        if (tmp_scn->scn_led_gpio == scn->scn_led_gpio) {
            // same gpio is already requested
            return TRUE;
        }
    }
    return FALSE;
}

void ipq4019_wifi_led_init(struct ol_ath_softc_net80211 *scn)
{
    struct platform_device *pdev = (struct platform_device *)(scn->sc_osdev->bdev);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
    uint32_t wifi_core_id=0xffffffff;
    int32_t led_gpio = 0;
    uint32_t led_num = 0;
    uint32_t led_source = 0;
    int32_t ret = -1;
#endif // linux kernel > 3.14

    if (!pdev ) {
        return;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
    if (of_property_read_u32(pdev->dev.of_node, "core-id", &wifi_core_id) != 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Wifi LED init failed.. Couldn't get core id\r\n", __func__);
        return;
    }

    led_gpio = of_get_named_gpio(pdev->dev.of_node, "wifi-led-gpios", 0);
    if (led_gpio <= 0) {
        /* no led gpio.. get led source */
        if ((ret = of_property_read_u32(pdev->dev.of_node, "wifi_led_num", &led_num)) ||
            (ret = of_property_read_u32(pdev->dev.of_node, "wifi_led_source", &led_source))) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Wifi LED init failed.. Couldn't get led gpio/led source\r\n", __func__);
            return;
        }
    }

    if ((wifi_core_id == 0) || (wifi_core_id == 1)) {
        if ((led_gpio > 0) && (gpio_is_valid(led_gpio))) {
            int32_t ret_status = 0;
            ipq4019_led_type = IPQ4019_LED_GPIO_PIN; // led type gpio
            scn->scn_led_gpio = led_gpio;
            /* check if this gpio is already requested/shared between wifi radios */
            if (!ipq4019_is_wifi_gpio_shared(scn)) {
                //ret_status = gpio_request_one(led_gpio, GPIOF_OUT_INIT_LOW, "wifi-led-gpios");
                ret_status = gpio_request_one(led_gpio, GPIOF_DIR_OUT, "wifi-led-gpios");
                if (ret_status != 0) {
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Wifi LED gpio request failed.. \r\n", __func__);
                    return;
                }
            }
        } else if (led_num > 0) {
            ipq4019_led_type = IPQ4019_LED_SOURCE; // led source selected
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0))
#ifdef CONFIG_LEDS_IPQ
	    ipq_led_source_select(led_num, led_source);
#endif
#else
            ipq40xx_led_source_select(led_num, led_source);
#endif
            scn->scn_led_gpio = 0;
        }
    }

    if ((led_gpio > 0) || (led_num > 0)) {
        ipq4019_led_initialized = 1;
    }

#endif /* linux kernel > 3.14 */
    return;
}

void ipq4019_wifi_led_deinit(struct ol_ath_softc_net80211 *scn)
{
    if (ipq4019_led_type == IPQ4019_LED_GPIO_PIN) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
        if ((scn->scn_led_gpio) && (gpio_is_valid(scn->scn_led_gpio))) {
            /* check if this gpio is freed already by another scn context */
            if (!ipq4019_is_wifi_gpio_shared(scn)) {
                gpio_set_value_cansleep(scn->scn_led_gpio, 0);
                gpio_free(scn->scn_led_gpio);
            }
        }
#endif
    } else if (ipq4019_led_type == IPQ4019_LED_SOURCE) {
        /* nothing to be done */
    }
    scn->scn_led_gpio = 0;
    ipq4019_led_initialized = 0;
}

struct valid_reg_range {
    uint32_t start;
    uint32_t end;
} ipq4019_soc_reg_range[] = {
    { 0x080000, 0x080000 },
    { 0x080020, 0x080020 },
    { 0x080028, 0x080050 },
    { 0x0800d4, 0x0800ec },
    { 0x08010c, 0x080118 },
    { 0x080284, 0x080290 },
    { 0x0802a8, 0x0802b8 },
    { 0x0802dc, 0x08030c },
    { 0x082000, 0x083fff }};

QDF_STATUS hif_diag_read_soc_ipq4019(struct hif_opaque_softc *hif_device, uint32_t address, uint8_t *data, int nbytes)
{
    uint32_t *ptr= (uint32_t *)data;
    uint32_t pSaddr,pEaddr,pRSaddr,pREaddr;
    int range = 0;

    if( nbytes % 4 ){
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Pls check length value:%s,length:%x\n",__func__,nbytes);
    }

    for(range = 0; range < (nbytes/4); range++) {
        ptr[range] = 0xdeadbeef;
    }

    pSaddr = address;
    pEaddr = address + nbytes - 4;

    for(range = 0; range < 9; range++){

        if( ipq4019_soc_reg_range[range].start >= pSaddr &&  ipq4019_soc_reg_range[range].start <= pEaddr ){

            pRSaddr = ipq4019_soc_reg_range[range].start;

            if(ipq4019_soc_reg_range[range].end <= pEaddr){
                pREaddr = ipq4019_soc_reg_range[range].end;
            }else{
                pREaddr = pEaddr;
            }

        }else if( pSaddr > ipq4019_soc_reg_range[range].start  && pSaddr <= ipq4019_soc_reg_range[range].end ){

            pRSaddr = pSaddr;
            if(ipq4019_soc_reg_range[range].end <= pEaddr){
                pREaddr = ipq4019_soc_reg_range[range].end;
            }else{
                pREaddr = pEaddr;
            }

        }else {
            continue;
        }

        hif_diag_read_mem(hif_device,pRSaddr,data+(pRSaddr-address),pREaddr-pRSaddr+4);
    }
    return QDF_STATUS_SUCCESS;
}
#endif
