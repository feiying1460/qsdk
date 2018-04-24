/*
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <osdep.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/if_arp.h>
#include "bmi_msg.h" /* TARGET_TYPE_ */
#include "ol_if_athvar.h"
#include "ol_ath.h"
#include "hif.h"
#include "hif_napi.h"
#include <osapi_linux.h>
#include<ol_txrx_types.h>
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_if.h>
#endif
#include <osif_private.h>
#include <ath_pci.h>
extern struct g_wifi_info g_winfo;

void *ol_hif_open(struct device *dev, void *bdev, void *bid,
        enum ath_hal_bus_type bus_type, bool reinit, qdf_device_t qdf_dev);
int osif_recover_vap_delete(struct ieee80211com *ic);
void osif_recover_vap_create(struct ieee80211com *ic);
int ol_ath_target_stop(struct ieee80211com *ic);
int ol_ath_target_start(struct ol_ath_softc_net80211 *scn);
void ic_reset_params(struct ieee80211com *ic);
static int qca_napi_create (void *hif_ctx);
static int qca_napi_destroy (void *hif_ctx, int force);
#if !defined(REMOVE_PKT_LOG) && defined(QCA_LOWMEM_PLATFORM)
extern unsigned int enable_pktlog_support;
#endif

#define BAR_NUM                    0

int
ol_ath_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{

    struct ol_attach_t ol_cfg;
    void *hif_context;
    struct hif_target_info *tgt_info;
    struct _NIC_DEV *aps_osdev = NULL;
    int ret = 0;
    qdf_device_t         qdf_dev = NULL;    /* qdf handle */
    uint32_t i;
    struct ol_ath_softc_net80211 *scn;
    bool flag = false;

    aps_osdev = kmalloc(sizeof(*aps_osdev),GFP_KERNEL);
    if(aps_osdev == NULL) {
	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Error while allocating aps_osdev\n");
	ret =-1;
	goto cleanup1;
    }
    OS_MEMSET(aps_osdev, 0, sizeof(*(aps_osdev)));

    aps_osdev->bdev = pdev;
    aps_osdev->device = &pdev->dev;
    aps_osdev->bc.bc_bustype = HAL_BUS_TYPE_PCI;

    /* initialize the qdf_dev handle */
    qdf_dev = kmalloc(sizeof(*(qdf_dev)), GFP_KERNEL);
    if (qdf_dev == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s %d mem alloc failure \n",__func__,__LINE__);
        return -1;
    }

    OS_MEMSET(qdf_dev, 0, sizeof(*(qdf_dev)));
    qdf_dev->drv_hdl = pdev; /* bus handle */
    qdf_dev->dev = &pdev->dev; /* device */
    qdf_dev->drv = aps_osdev;

    pci_set_drvdata(pdev, NULL);

    ol_cfg.bus_type = BUS_TYPE_PCIE;
    qdf_dev->netdev = ol_create_radio_netdev(&ol_cfg);

    hif_context  = ol_hif_open(&pdev->dev, pdev, (void *)id, HAL_BUS_TYPE_PCI, 0,qdf_dev);

    if(hif_context == NULL) {
	ret = -1;
	goto cleanup1;
    }

    tgt_info = hif_get_target_info_handle(hif_context);

    ol_cfg.devid = id->device;
    ol_cfg.target_type = tgt_info->target_type;
    ol_cfg.target_revision = tgt_info->target_revision;
    ol_cfg.pdevid = (void *)id;

    ret = __ol_ath_attach(hif_context, &ol_cfg, aps_osdev, qdf_dev);
    if(ret != 0) {
        ret = -EIO;
        goto cleanup2;
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
    pci_set_drvdata(pdev, aps_osdev->netdev);
    return 0;
err_attach:
    if (flag) {
        g_winfo.num_radios--;
        g_winfo.wifi_radios[scn->wifi_num].sc = NULL;
    }
    ret = -EIO;

cleanup2:
    if (hif_context) {
        hif_disable_isr(hif_context);
        ol_hif_close(hif_context);
    }

cleanup1:
    if (qdf_dev) {
	OS_FREE(qdf_dev);
    }
    if (aps_osdev) {
	OS_FREE(aps_osdev);
    }
     return ret;
}


void pci_reconnect_cb(struct ol_ath_softc_net80211 *scn)
{
        schedule_work(&scn->pci_reconnect_work);
}


/**
 * qca_napi_destroy() - destroys the NAPI structures for a given netdev
 * @force: if set, will force-disable the instance before _del'ing
     *
 * Destroy NAPI instances. This function is called
 * unconditionally during module removal. It destroy
 * napi structures through the proper HTC/HIF calls.
 *
 * Return:
 *    number of NAPI instances destroyed
 */


#if FEATURE_NAPI
static int qca_napi_destroy (void *hif_ctx, int force)
{
    int rc = 0;
    int i;
    uint32_t hdd_napi_map =0;// hif_napi_get_cemap(hif_ctx);

    NAPI_DEBUG("--> (force=%d)\n", force);
    if (hdd_napi_map) {
        for (i = 0; i < CE_COUNT_MAX; i++) {
            if (hdd_napi_map & (0x01 << i)) {
                if (0 <= hif_napi_destroy(
                            hif_ctx,
                            NAPI_PIPE2ID(i), force)) {
                    rc++;
                    hdd_napi_map &= ~(0x01 << i);
                } else
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "cannot destroy napi %d: (pipe:%d), f=%d\n",
                            i,
                            NAPI_PIPE2ID(i), force);
            }
        }
    }

    /* if all instances are removed, it is likely that hif_context has been
     * removed as well, so the cached value of the napi context also needs
     * to be removed
         */
    if (force)
        QDF_ASSERT(hdd_napi_map == 0);

    NAPI_DEBUG("<-- [rc=%d]\n", rc);
    return rc;
}

/**
 * qca_napi_poll() - NAPI poll function
 * @napi  : pointer to NAPI struct
 * @budget: the pre-declared budget
 *
 * Implementation of poll function. This function is called
 * by kernel during softirq processing.
 *
 * NOTE FOR THE MAINTAINER:
 *   Make sure this is very close to the ce_tasklet code.
 *
 * Return:
 *   int: the amount of work done ( <= budget )
 */
int qca_napi_poll(struct napi_struct *napi, int budget)
{
	struct qca_napi_info *napi_info;
	napi_info = (struct qca_napi_info *)
		container_of(napi, struct qca_napi_info, napi);
	return hif_napi_poll(napi_info->hif_ctx, napi, budget);
}

static int qca_napi_create (void *hif_ctx)
{
    uint8_t ul, dl;
    int     ul_polled, dl_polled;
    int     rc = 0;

    NAPI_DEBUG("-->\n");
    /*
     * hif_map_service_to_pipe should be changed to consider
     * target type to find service to pipe mapping table and
     * and should serch this table to find correct mapping as
     * Win and MCL may have a different mappings.
     * Right now using default MCL mapping table.
     */
    if (QDF_STATUS_SUCCESS !=
            hif_map_service_to_pipe(hif_ctx, HTT_DATA_MSG_SVC,
                        &dl, &ul, &ul_polled, &dl_polled)) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: cannot map service to pipe\n", __func__);
            rc = -EINVAL;
    } else {
        rc = hif_napi_create(hif_ctx, qca_napi_poll, QCA_NAPI_BUDGET, QCA_NAPI_DEF_SCALE);
        if (rc < 0) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: ERR(%d) creating NAPI on pipe %d\n", __func__, rc, dl);
        } else {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: napi instance %d created on pipe %d\n", __func__, rc, dl);
    }
    }
    NAPI_DEBUG("<-- [rc=%d]\n", rc);

    return rc;
}
#endif
void *ol_hif_open(struct device *dev, void *bdev, void *bid,
        enum ath_hal_bus_type bus_type, bool reinit, qdf_device_t qdf_dev)
{
    QDF_STATUS status;
    int ret = 0;
    void *hif_ctx;
    struct hif_driver_state_callbacks cbk;

        OS_MEMSET(&cbk, 0, sizeof(cbk));
        cbk.context = dev;

        hif_ctx = hif_open(qdf_dev, 0, bus_type, &cbk);
        if (!hif_ctx) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: hif_open error", __func__);
            return NULL;
        }
#ifdef QCA_LOWMEM_PLATFORM
        if(!enable_pktlog_support) {
           /*Disable Copy Engine 8 recv buffer enqueue*/
           hif_set_attribute(hif_ctx,HIF_LOWDESC_CE_NO_PKTLOG_CFG);
        } else {
           hif_set_attribute(hif_ctx,HIF_LOWDESC_CE_CFG);
        }
#endif
	status = hif_enable(hif_ctx, dev, bdev, bid, bus_type,
			(reinit == true) ?  HIF_ENABLE_TYPE_REINIT :
			HIF_ENABLE_TYPE_PROBE);
	if (!QDF_IS_STATUS_SUCCESS(status)) {
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "hif_enable error = %d, reinit = %d",
				status, reinit);
		ret = /*cdf_status_to_os_return(status)*/ -status;
		goto err_hif_close;
	}
#if FEATURE_NAPI
#define NAPI_ANY -1
	ret = qca_napi_create(hif_ctx);
	if (ret <= 0) {
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: NAPI creation error, rc: 0x%x", __func__, status);
		return NULL;
	}
	hif_napi_event(hif_ctx, NAPI_EVT_CMD_STATE, (void *)0x1);
	if (hif_napi_enabled(hif_ctx, NAPI_ANY)) {
		NAPI_DEBUG("hdd_napi_create returned: %d", status);
		if (ret <= 0) {
			qdf_print("NAPI creation error, rc: 0x%x, reinit = %d",
					status, reinit);
			ret = -EFAULT;
			goto err_napi_destroy;
		}
	}
#endif
    return hif_ctx;

#if FEATURE_NAPI
err_napi_destroy:
	qca_napi_destroy(hif_ctx, true);
#endif

err_hif_close:
	hif_close(hif_ctx);
	return NULL;
}

void ol_hif_close(void *hif_ctx)
{
    if (hif_ctx == NULL)
	return;

    hif_disable(hif_ctx, HIF_DISABLE_TYPE_REMOVE);

    hif_close(hif_ctx);
}

#define REMOVE_VAP_TIMEOUT_COUNT  20
#define REMOVE_VAP_TIMEOUT        (HZ/10)

void
ol_ath_pci_remove(struct pci_dev *pdev)
{
    struct net_device *dev = pci_get_drvdata(pdev);
    struct ol_ath_softc_net80211 *scn;
    u_int32_t target_ver;
    struct hif_opaque_softc *sc;
    int target_paused = TRUE;
    int waitcnt = 0;
    struct _NIC_DEV *osdev = NULL;
    qdf_device_t  qdf_dev = NULL;    /* qdf handle */
    u_int32_t wifi_num = 0;

    /* Attach did not succeed, all resources have been
     * freed in error handler
     */
    if (!dev)
        return;

    scn = ath_netdev_priv(dev);
    sc = (struct hif_opaque_softc *) scn->hif_hdl;

    __ol_vap_delete_on_rmmod(dev);

    while (atomic_read(&scn->reset_in_progress)  && (waitcnt < REMOVE_VAP_TIMEOUT_COUNT)) {
        schedule_timeout_interruptible(REMOVE_VAP_TIMEOUT);
        waitcnt++;
    }

    /* Suspend the target if it is not done during the last vap removal */
    if (!(scn->down_complete)) {

        /* Suspend Target */
        qdf_print(KERN_INFO"Suspending Target - with disable_intr set :%s (sc %p)\n",dev->name,sc);
        if (!ol_ath_suspend_target(scn, 1)) {
            u_int32_t  timeleft;
            qdf_print(KERN_INFO"waiting for target paused event from target :%s (sc %p)\n",dev->name,sc);
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
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (!(scn->down_complete)) {
    preempt_disable();

    if (scn->nss_wifi_ol_mode) {
            osif_nss_ol_wifi_pause(scn);
            qdf_print("%s:nss wifi offload pause\n",__FUNCTION__);
            mdelay(100);

            osif_nss_ol_wifi_reset(scn, 100);
    }

    preempt_enable();
    }
#endif

    if (!scn->down_complete) {
        ol_ath_diag_user_agent_fini(scn);
    }

    /* save target_version since scn is not valid after __ol_ath_detach */

    target_ver = scn->target_version;
    osdev = scn->sc_osdev;
    qdf_dev = scn->qdf_dev;
    wifi_num = scn->wifi_num;

    if (target_paused == TRUE) {
    __ol_ath_detach(dev);
    } else {
        scn->fwsuspendfailed = 1;
        wmi_stop(scn->wmi_handle);
    }

    if (target_paused != TRUE) {
        __ol_ath_detach(dev);
    }

    if(osdev)
        kfree(osdev);

    if(qdf_dev)
        kfree(qdf_dev);

    g_winfo.num_radios--;
    g_winfo.wifi_radios[wifi_num].sc = NULL;

    pci_set_drvdata(pdev, NULL);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO "ath_pci_remove\n");
}


#define OL_ATH_PCI_PM_CONTROL 0x44

int
ol_ath_pci_suspend(struct pci_dev *pdev, pm_message_t state)
{
    struct net_device *dev = pci_get_drvdata(pdev);
    u32 val;

    if (__ol_ath_suspend(dev))
        return (-1);

    pci_read_config_dword(pdev, OL_ATH_PCI_PM_CONTROL, &val);
    if ((val & 0x000000ff) != 0x3) {
        PCI_SAVE_STATE(pdev,
            ((struct ath_pci_softc *)ath_netdev_priv(dev))->aps_pmstate);
        pci_disable_device(pdev);
        pci_write_config_dword(pdev, OL_ATH_PCI_PM_CONTROL, (val & 0xffffff00) | 0x03);
    }
    return 0;
}

int
ol_ath_pci_resume(struct pci_dev *pdev)
{
    struct net_device *dev = pci_get_drvdata(pdev);
    u32 val;
    int err;

    err = pci_enable_device(pdev);
    if (err)
        return err;

    pci_read_config_dword(pdev, OL_ATH_PCI_PM_CONTROL, &val);
    if ((val & 0x000000ff) != 0) {
        PCI_RESTORE_STATE(pdev,
            ((struct ath_pci_softc *)ath_netdev_priv(dev))->aps_pmstate);

        pci_write_config_dword(pdev, OL_ATH_PCI_PM_CONTROL, val & 0xffffff00);

        /*
         * Suspend/Resume resets the PCI configuration space, so we have to
         * re-disable the RETRY_TIMEOUT register (0x41) to keep
         * PCI Tx retries from interfering with C3 CPU state
         *
         */
        pci_read_config_dword(pdev, 0x40, &val);

        if ((val & 0x0000ff00) != 0)
            pci_write_config_dword(pdev, 0x40, val & 0xffff00ff);
    }

    if (__ol_ath_resume(dev))
        return (-1);

    return 0;
}

void
ol_ath_pci_recovery_remove(struct pci_dev *pdev)
{
    struct net_device *dev = pci_get_drvdata(pdev);
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
ol_ath_pci_recovery_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
    struct net_device *dev = pci_get_drvdata(pdev);
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);
    struct ieee80211com *ic;

    ic =  &scn->sc_ic;

    ol_ath_target_start(scn);

    osif_recover_vap_create(ic);

    return 0;
}
