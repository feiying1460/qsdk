/*
 * Copyright (c) 2011, Atheros Communications Inc.
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
 * UMAC beacon specific offload interface functions - for power and performance offload model
 */
#include "ol_if_athvar.h"
#include "qdf_mem.h"
#include <ol_txrx_types.h>
#include <if_smart_ant.h>

#if ATH_PERF_PWR_OFFLOAD
/*
 *  WMI API for sending beacons
 */
#define BCN_SEND_BY_REF

void
ol_ath_beacon_send(struct ol_ath_softc_net80211 *scn,
        int vid,
        wbuf_t wbuf)
{
    struct beacon_params param;
    qdf_mem_set(&param, sizeof(param), 0);
    param.wbuf = wbuf;
    param.vdev_id = vid;
    if (ol_cfg_is_high_latency(NULL)) {
        param.is_high_latency = TRUE;

#ifdef DEBUG_BEACON
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s frm length %d \n",__func__,bcn_len);
#endif
        wmi_unified_beacon_send_cmd(scn->wmi_handle, &param);
    } else {
        A_UINT16  frame_ctrl;
        struct ieee80211_frame *wh;
        struct ieee80211_node *ni = wbuf_get_node(wbuf);
        struct ieee80211vap *vap = ni->ni_vap;
        struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
        struct ieee80211_beacon_offsets *bo = &avn->av_beacon_offsets;
        struct ieee80211_tim_ie *tim_ie = (struct ieee80211_tim_ie *)
            bo->bo_tim;
        struct ol_txrx_vdev_t *vdev = vap->iv_txrx_handle;
        struct ol_txrx_pdev_t *pdev = vdev->pdev;
        A_UINT32 bcn_txant = 0;

        /* Get the frame ctrl field */
        wh = (struct ieee80211_frame *)wbuf_header(wbuf);
        frame_ctrl = __le16_to_cpu(*((A_UINT16 *)wh->i_fc));

        /* get the DTIM count */

        if (tim_ie->tim_count == 0) {
            param.is_dtim_count_zero = TRUE;
            if (tim_ie->tim_bitctl & 0x01) {
                /* deliver CAB traffic in next DTIM beacon */
                param.is_bitctl_reqd = TRUE;
            }
        }
        /* Map the beacon buffer to DMA region */
        qdf_nbuf_map_single(pdev->osdev, wbuf, QDF_DMA_TO_DEVICE);


        ieee80211_smart_ant_get_bcn_txantenna(ni->ni_ic, &bcn_txant);

        param.frame_ctrl = frame_ctrl;
        param.bcn_txant = bcn_txant;
        if(!avn->av_restart_in_progress) {
            wmi_unified_beacon_send_cmd(scn->wmi_handle, &param);
        }
    }
    return;
}

/*
 *  WMI API for sending beacon probe template
 */
void
ol_ath_bcn_prb_template_send(ol_scn_t scn, int vid,
                       int buf_len,  struct ieee80211_bcn_prb_info *bufp)
{
    struct bcn_prb_template_params param;
    /*
     * The target will store this  information for use with
     * the beacons and probes.
     */
    param.vdev_id = vid;
    param.buf_len = buf_len;
    param.caps = bufp->caps;
    param.erp  = bufp->erp;

    /* TODO: Few more elements to be added and copied to the template buffer */

    /* Send the beacon probe template to the target */
#if 0
    wmi_unified_bcn_prb_template_cmd_send(scn->wmi_handle, &param);
#endif
    return;
}

/*
 * Function to update beacon probe template
 */
static void
ol_ath_beacon_probe_template_update(struct ieee80211_node *ni)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);

    /* Update required only if we are in firmware offload mode */
    if (!avn->av_beacon_offload) {
         return;
    }

    /* Populate the beacon probe template */
    if (!(ieee80211_bcn_prb_template_update(vap->iv_bss,
                                             &avn->av_bcn_prb_templ))) {
        ol_ath_bcn_prb_template_send(scn, avn->av_if_id,
                   sizeof(avn->av_bcn_prb_templ), &avn->av_bcn_prb_templ);
    }

    return;
}

#if UMAC_SUPPORT_QUIET
/*
 *  WMI API for sending cmd to set/unset Quiet Mode
 */
static void
ol_ath_set_quiet_mode(struct ieee80211com *ic,uint8_t enable)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ieee80211_quiet_param *quiet_ic = ic->ic_quiet;
    struct set_quiet_mode_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.enabled = enable;
    param.intval = ic->ic_intval;
    param.period = quiet_ic->period*ic->ic_intval;
    param.duration = quiet_ic->duration;
    param.offset = quiet_ic->offset;
    wmi_unified_set_quiet_mode_cmd_send(scn->wmi_handle, &param);
}
#endif

int
ol_ath_set_beacon_filter(wlan_if_t vap, u_int32_t *ie)
{
    /* Issue WMI command to set beacon filter */
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    struct ol_ath_softc_net80211 *scn = avn->av_sc;
    struct set_beacon_filter_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.vdev_id = avn->av_if_id;
    param.ie = ie;

    return wmi_unified_set_beacon_filter_cmd_send(scn->wmi_handle, &param);
}

int
ol_ath_remove_beacon_filter(wlan_if_t vap)
{
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    struct ol_ath_softc_net80211 *scn = avn->av_sc;
    struct remove_beacon_filter_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.vdev_id = avn->av_if_id;
    return wmi_unified_remove_beacon_filter_cmd_send(scn->wmi_handle, &param);
}

void
ol_ath_set_probe_filter(void *data)
{
    /* TODO: Issue WMI command to set probe response filter */
    return;
}

static void
ol_ath_beacon_update(struct ieee80211_node *ni, int rssi)
{
    /* Stub for peregrine */
    return;
}

static int
ol_ath_net80211_is_hwbeaconproc_active(struct ieee80211com *ic)
{
    /* Stub for peregrine */
    return 0;
}

static void
ol_ath_net80211_hw_beacon_rssi_threshold_enable(struct ieee80211com *ic,
                                            u_int32_t rssi_threshold)
{
    /* TODO: Issue WMI command to set beacon RSSI filter */
    return;

}

static void
ol_ath_net80211_hw_beacon_rssi_threshold_disable(struct ieee80211com *ic)
{
    /* TODO: Issue WMI command to disable beacon RSSI filter */
    return;
}

struct ol_ath_iter_update_beacon_arg {
    struct ieee80211com *ic;
    int if_id;
};

/* Move the beacon buffer to deferred_bcn_list */
static void
ol_ath_vap_defer_beacon_buf_free(struct ol_ath_vap_net80211 *avn)
{
    struct bcn_buf_entry* buf_entry;
    buf_entry = (struct bcn_buf_entry *)qdf_mem_malloc(
	         sizeof(struct bcn_buf_entry));
    if (buf_entry) {
        qdf_spin_lock(&avn->avn_lock);
	if(avn->av_wbuf == NULL){
		qdf_spin_unlock(&avn->avn_lock);
		qdf_mem_free(buf_entry);
		return;
	}
#ifdef BCN_SEND_BY_REF
        buf_entry->is_dma_mapped = avn->is_dma_mapped;
        /* cleat dma_mapped flag */
        avn->is_dma_mapped = 0;
#endif
        buf_entry->bcn_buf = avn->av_wbuf;
        TAILQ_INSERT_TAIL(&avn->deferred_bcn_list, buf_entry, deferred_bcn_list_elem);
        avn->av_wbuf =  NULL;
        qdf_spin_unlock(&avn->avn_lock);
    }
    else {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ERROR: qdf_mem_malloc failed %s: %d \n", __func__, __LINE__);
        ASSERT(0);
    }
}

/*
 * Function to allocate beacon in host mode
 */
static void
ol_ath_vap_iter_beacon_alloc(void *arg, wlan_if_t vap)
{
    struct ol_ath_iter_update_beacon_arg* params = (struct ol_ath_iter_update_beacon_arg *)arg;
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    struct ieee80211_node *ni;

    if (avn->av_if_id == params->if_id) {
        if (avn->av_beacon_offload) {
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Beacon processing offloaded to the firmware\n");
        } else {
            ni = vap->iv_bss;
	    /* Beacon buffer is already allocate
	     * Move the beacon buffer to deferred_bcn_list to
	     * free the buffer on vap stop
	     * and allocate a new beacon buufer
	     */
	     ol_ath_vap_defer_beacon_buf_free(avn);
	     avn->av_wbuf = ieee80211_beacon_alloc(ni, &avn->av_beacon_offsets);
	     if (avn->av_wbuf == NULL) {
                   QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ERROR ieee80211_beacon_alloc failed in %s:%d\n", __func__, __LINE__);
             A_ASSERT(0);
            }
        }
    }
    return;
}

/*
 * Function to free beacon in host mode
 */
static void
ol_ath_vap_iter_beacon_free(void *arg, wlan_if_t vap)
{
    struct ol_ath_iter_update_beacon_arg* params = (struct ol_ath_iter_update_beacon_arg *)arg;
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
#ifdef BCN_SEND_BY_REF
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
#endif

    if (avn->av_if_id == params->if_id) {
        if (avn->av_beacon_offload) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Beacon processing offloaded to the firmware\n");
        } else {
            struct bcn_buf_entry* buf_entry,*buf_temp;
            struct ieee80211_tx_status ts;
            ts.ts_flags = 0;
            ts.ts_retries = 0;
            qdf_spin_lock(&avn->avn_lock);
            TAILQ_FOREACH_SAFE(buf_entry, &avn->deferred_bcn_list, deferred_bcn_list_elem,buf_temp) {
                TAILQ_REMOVE(&avn->deferred_bcn_list, buf_entry, deferred_bcn_list_elem);
#ifdef BCN_SEND_BY_REF
                if (buf_entry->is_dma_mapped == 1) {
                    qdf_nbuf_unmap_single(scn->qdf_dev,
                              buf_entry->bcn_buf,
                              QDF_DMA_TO_DEVICE);
                    buf_entry->is_dma_mapped = 0;
                }
#endif
                ieee80211_complete_wbuf(buf_entry->bcn_buf, &ts);
                qdf_mem_free(buf_entry);
            }
            qdf_spin_unlock(&avn->avn_lock);
        }
    }
    return;
}

/*
 * offload beacon APIs for other offload modules
 */
void
ol_ath_beacon_alloc(struct ieee80211com *ic, int if_id)
{
    struct ol_ath_iter_update_beacon_arg params;

    params.ic = ic;
    params.if_id = if_id;
    wlan_iterate_vap_list(ic,ol_ath_vap_iter_beacon_alloc,(void *) &params);
}

void
ol_ath_beacon_stop(struct ol_ath_softc_net80211 *scn,
                   struct ol_ath_vap_net80211 *avn)
{
    if (avn->av_beacon_offload) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Beacon processing offloaded to the firmware\n");
    } else {
        struct ieee80211_tx_status ts;
        ts.ts_flags = 0;
        ts.ts_retries = 0;
	/* Move the beacon buffer to deferred_bcn_list
	 * and wait for stooped event from Target.
	 * beacon buffer in deferred_bcn_list gets freed - on
	 * vap stopped event from Target
	 */
	 ol_ath_vap_defer_beacon_buf_free(avn);
     }
     return;
}


void
ol_ath_beacon_free(struct ieee80211com *ic, int if_id)
{
    struct ol_ath_iter_update_beacon_arg params;

    params.ic = ic;
    params.if_id = if_id;
    wlan_iterate_vap_list(ic,ol_ath_vap_iter_beacon_free,(void *) &params);
}

#if UMAC_SUPPORT_QUIET
/*
 * Function to update quiet element in the beacon and the VAP quite params
 */
static void
ol_ath_update_quiet_params(struct ieee80211com *ic, struct ieee80211vap *vap)
{

    struct ieee80211_quiet_param *quiet_iv = vap->iv_quiet;
    struct ieee80211_quiet_param *quiet_ic = ic->ic_quiet;
    struct ieee80211vap *quiet_vap = TAILQ_FIRST(&ic->ic_vaps);

    /* Update quiet params for the vap with beacon offset 0 */
    if (quiet_ic->is_enabled) {

        struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
        u_int32_t tsf_adj = avn->av_tsfadjust;

        /* convert tsf adjust in to TU */
        tsf_adj = tsf_adj >> 10;

        /* Compute the beacon_offset from slot 0 */
        if (tsf_adj) {
           quiet_iv->beacon_offset = ic->ic_intval - tsf_adj;
        }
        else {
            quiet_iv->beacon_offset = 0;
        }

        while(quiet_vap != NULL) {
            if(!quiet_vap->iv_vap_is_down)
                    break;
            quiet_vap = TAILQ_NEXT(quiet_vap, iv_next);
        }

		if (quiet_vap && (vap->iv_unit == quiet_vap->iv_unit)) {
			quiet_ic->beacon_offset = quiet_iv->beacon_offset;

			if (quiet_ic->tbttcount == 1) {
				quiet_ic->tbttcount = quiet_ic->period;
			}
			else {
				quiet_ic->tbttcount--;
			}

			if (quiet_ic->tbttcount == 1) {
				ol_ath_set_quiet_mode(ic,1);
			}
			else if (quiet_ic->tbttcount == (quiet_ic->period-1)) {
				ol_ath_set_quiet_mode(ic,0);
			}

		}
	} else if (quiet_ic->tbttcount != quiet_ic->period) {
  		/* quiet support is disabled
         * since tbttcount is not '0', the hw quiet period was set before
         * so just disable the hw quiet period and
         * tbttcount to 0.
         */
		quiet_ic->tbttcount = quiet_ic->period;
		ol_ath_set_quiet_mode(ic,0);
	}
}
#endif /* UMAC_SUPPORT_QUIET */

/*
 * Return the appropriate VAP given the Id
 */
struct ieee80211vap *
ol_ath_get_vap(struct ieee80211com *ic, u_int32_t if_id)
{
    struct ieee80211vap *vap = NULL;
    struct ol_ath_vap_net80211 *avn;

    /*  Get a VAP with the given id.  */
    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if ((OL_ATH_VAP_NET80211(vap))->av_if_id == if_id) {
            break;
        }
    }

    if (vap == NULL) {
        return NULL;
    }

#if UMAC_SUPPORT_WDS
    /* Disable beacon if VAP is operating in NAWDS bridge mode */
    if (ieee80211_nawds_disable_beacon(vap)){
        return NULL;
    }
#endif

    /* Allow this only for host beaconing mode */
    avn = OL_ATH_VAP_NET80211(vap);
    if (avn->av_beacon_offload) {
        return NULL;
    }

    return vap;
}

/* returns the pointer to beacon buffer for the vdev
 * used by pktlog message handler to retrieve the beacon
 * header
 */

void *
ol_ath_get_bcn_header(ol_pdev_handle pdev, A_UINT32 vdev_id)
{
    struct ieee80211vap *vap;
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)pdev;
    struct ol_ath_vap_net80211 *avn;

    vap = ol_ath_vap_get(scn, vdev_id);
    avn = OL_ATH_VAP_NET80211(vap);

    if ((avn == NULL) || (avn->av_wbuf == NULL))
    {
        ASSERT(avn != NULL);
        ASSERT(avn->av_wbuf != NULL);
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Invalid buffer pointer\n",__func__);
        return NULL;
    }

    return (wbuf_header(avn->av_wbuf));
}

/* returns the pointer to beacon buffer for the vdev
 * used by pktlog message handler
 */

void *
ol_ath_get_bcn_buffer(ol_pdev_handle pdev, A_UINT32 vdev_id)
{
    struct ieee80211vap *vap;
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)pdev;
    struct ol_ath_vap_net80211 *avn;

    vap = ol_ath_vap_get(scn, vdev_id);
    avn = OL_ATH_VAP_NET80211(vap);

    if ((avn == NULL) || (avn->av_wbuf == NULL))
    {
        ASSERT(avn != NULL);
        ASSERT(avn->av_wbuf != NULL);
        qdf_print("%s(): beacon buffer vacant\n",__func__);
        return NULL;
    }

    return (avn->av_wbuf);
}

/* prep and send beacon for a vap */
static inline int
ol_prepare_send_vap_bcn(struct ieee80211vap *vap,
                        struct ol_ath_softc_net80211 *scn,
                        u_int32_t if_id,
                        wmi_host_tim_info *tim_info)
{
    struct ol_ath_vap_net80211 *avn;
    struct ieee80211com *ic = vap->iv_ic;
    int error = 0;

        /*
         * Update the TIM bitmap. At VAP attach memory will be allocated for TIM
         * based on the iv_max_aid set. Update this field and beacon update will
         * automatically take care of populating the bitmap in the beacon buffer.
         */
        if (vap->iv_tim_bitmap && tim_info->tim_changed) {

            /* The tim bitmap is a byte array that is passed through WMI as a
             * 32bit word array. The CE will correct for endianess which is
             * _not_ what we want here. Un-swap the words so that the byte
             * array is in the correct order.
             */
#ifdef BIG_ENDIAN_HOST
            int j;
            for (j = 0; j < WMI_HOST_TIM_BITMAP_ARRAY_SIZE; j++) {
                tim_info->tim_bitmap[j] = le32_to_cpu(tim_info->tim_bitmap[j]);
            }
#endif

            if(tim_info->tim_len <= MAX_TIM_BITMAP_LENGTH) {
                vap->iv_tim_len = (u_int16_t)tim_info->tim_len;
                OS_MEMCPY(vap->iv_tim_bitmap, tim_info->tim_bitmap, vap->iv_tim_len);
                vap->iv_ps_pending = tim_info->tim_num_ps_pending;

                IEEE80211_VAP_TIMUPDATE_ENABLE(vap);
            } else {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n %s : Ignoring TIM Update for the VAP (%d)  because of INVALID Tim length from the firmware \n", __func__, if_id);
            }

        }

        /* Update quiet params and beacon update will take care of the rest */
        avn = OL_ATH_VAP_NET80211(vap);
     	qdf_spin_lock(&avn->avn_lock);

        if (avn->av_wbuf == NULL) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "beacon buffer av_wbuf is NULL - Ignoring SWBA event \n");
	    qdf_spin_unlock(&avn->avn_lock);
            return -1;
        }

#if UMAC_SUPPORT_WNM

        if (ieee80211_wnm_timbcast_enabled(vap) > 0) {
            if (ieee80211_wnm_timbcast_cansend(vap) > 0) {
                struct ieee80211_node *ni = vap->iv_bss;
                wbuf_t wbuf_tim_hr = NULL;
                wbuf_t wbuf_tim_lr = NULL;

                if (ni && ieee80211_timbcast_highrateenable(vap)) {
                    wbuf_tim_hr = ieee80211_timbcast_alloc(ni);
                    if (wbuf_tim_hr) {
                        error = ieee80211_timbcast_update(vap->iv_bss,
                                             &avn->av_beacon_offsets, wbuf_tim_hr);
                        if (error) {
                            wbuf_free(wbuf_tim_hr);
                            wbuf_tim_hr = NULL;
                        } else {
                            wbuf_set_tid(wbuf_tim_hr, EXT_TID_NONPAUSE);
                            wbuf_set_tx_rate(wbuf_tim_hr, 0, 0, 1); //24Mbps
                            ieee80211_send_mgmt(vap, ni, wbuf_tim_hr, true);
                        }
                    }
                    ieee80211_free_node(ni);
                }
                if (ni && ieee80211_timbcast_lowrateenable(vap)) {
                    wbuf_tim_lr = ieee80211_timbcast_alloc(ni);
                    if (wbuf_tim_lr) {
                        error = ieee80211_timbcast_update(vap->iv_bss,
                                              &avn->av_beacon_offsets, wbuf_tim_lr);
                        if (error) {
                            wbuf_free(wbuf_tim_lr);
                            wbuf_tim_lr = NULL;
                        } else {
                            ieee80211_send_mgmt(vap, ni, wbuf_tim_lr, true);
                        }
                    }
                    ieee80211_free_node(ni);
                }
            }
        }
#endif

#if UMAC_SUPPORT_QUIET
        ol_ath_update_quiet_params(ic, vap);
#endif /* UMAC_SUPPORT_QUIET */
#if UMAC_SUPPORT_WNM
	if(vap->iv_bss) {
            error = ieee80211_beacon_update(vap->iv_bss, &avn->av_beacon_offsets,
                                        avn->av_wbuf, tim_info->tim_mcast,0);
	}
#else
	if(vap->iv_bss) {
            error = ieee80211_beacon_update(vap->iv_bss, &avn->av_beacon_offsets,
                                        avn->av_wbuf, tim_info->tim_mcast);
	}
#endif
        if (error != -1) {
            /* Send beacon to target */
#ifdef BCN_SEND_BY_REF
        if (avn->is_dma_mapped) {
            struct ol_txrx_vdev_t *vdev = vap->iv_txrx_handle;
            struct ol_txrx_pdev_t *pdev = vdev->pdev;

            qdf_nbuf_unmap_single(pdev->osdev,
                                  avn->av_wbuf,
                                  QDF_DMA_TO_DEVICE);
            avn->is_dma_mapped = 0;
        }
#endif

            ol_ath_beacon_send(scn, if_id, avn->av_wbuf);
            vap->iv_stats.tx_beacon_swba_cnt++;

#ifdef BCN_SEND_BY_REF
            avn->is_dma_mapped = 1;
#endif
        }
	qdf_spin_unlock(&avn->avn_lock);
        return 0;
}

/*
 * Handler for Host SWBA events in host mode
 */
static int
ol_ath_beacon_swba_handler(struct ol_ath_softc_net80211 *scn,
                           uint8_t *data)
{
    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211vap *vap = NULL;
    wmi_host_tim_info tim_info;
    u_int32_t if_id;
    u_int8_t vdev_id=0,i=0;
    u_int32_t vdev_map_ev, vdev_map;


    if(wmi_extract_swba_vdev_map(scn->wmi_handle, data, &vdev_map_ev)) {
        qdf_print("Unable to extact vdev map from swba event\n");
        return -1;
    }

    vdev_map = vdev_map_ev;
    /* Generate LP IOT vap beacons first and then send other vap beacons later
    */
    if (ic->ic_num_lp_iot_vaps) { /* if there LP IOT vaps */
        for (;vdev_map;vdev_id++, vdev_map >>= 1) {
            if (!(vdev_map & 0x1)) {
                continue;
            }

            /* Get the VAP corresponding to the id */
            vap = ol_ath_get_vap(ic, (u_int32_t)vdev_id);
            if (vap == NULL) {
                /*should continue if current vap's NULL*/
                continue;
            }
            if (vap->iv_create_flags & IEEE80211_LP_IOT_VAP)   {
#if ATH_NON_BEACON_AP
                if (IEEE80211_VAP_IS_NON_BEACON_ENABLED(vap)){
                    /*for non-beaconing VAP, don't send beacon*/
                    continue;
                }
#endif
                /* If vap is not active, no need to queue beacons to FW, Ignore SWBA*/
                if (!ieee80211_vap_active_is_set(vap)) {
                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "vap %d: drop SWBA event, since vap is not active  \n", vdev_id);
                    continue;
                }
                if (wmi_extract_swba_tim_info(scn->wmi_handle, data, i, &tim_info)) {
                    return -1;
                }
                if (ol_prepare_send_vap_bcn(vap, scn, (u_int32_t)vdev_id, &tim_info)<0)
                    return -1;
           }
           i++;
        }
    }

    /* Generate a beacon for all vaps other than lp_iot vaps specified in the list */
    vdev_map = vdev_map_ev;
    for (vdev_id=0,i=0;vdev_map;vdev_id++,vdev_map >>= 1) {

        if (!(vdev_map & 0x1)) {
            continue;
        }

        if_id = vdev_id;

        /* Get the VAP corresponding to the id */
        vap = ol_ath_get_vap(ic, if_id);
        if (vap == NULL) {
            /*should continue if current vap's NULL*/
            continue;
        }
        /* Skip LP IOT vaps. They have been sent already */
        if (!(vap->iv_create_flags & IEEE80211_LP_IOT_VAP)) {
#if ATH_NON_BEACON_AP
             if (IEEE80211_VAP_IS_NON_BEACON_ENABLED(vap)){
                 /*for non-beaconing VAP, don't send beacon*/
                 continue;
            }
#endif
            /* If vap is not active, no need to queue beacons to FW, Ignore SWBA*/
            if (!ieee80211_vap_active_is_set(vap)) {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "vap %d: drop SWBA event, since vap is not active  \n", vdev_id);
                continue;
            }
            if (wmi_extract_swba_tim_info(scn->wmi_handle, data, i, &tim_info)) {
                return -1;
            }
            if (ol_prepare_send_vap_bcn(vap, scn, (u_int32_t)vdev_id, &tim_info)<0)
                return -1;
        }
        i++;
    }
    return 0;
}

/*
 * TSF Offset event handler
 */
static int
ol_ath_tsf_offset_event_handler(struct ol_ath_softc_net80211 *scn,
                         u_int32_t vdev_map, u_int32_t *adjusted_tsf)
{
    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211vap *vap = NULL;
    struct ol_ath_vap_net80211 *avn;
    struct ieee80211_frame  *wh;
    u_int32_t if_id=0;
    u_int64_t adjusted_tsf_le;
#if defined(CONFIG_AR900B_SUPPORT) || defined(CONFIG_AR9888_SUPPORT)

	u_int64_t tx_delay = 0;
#endif

    for ( ;(vdev_map); vdev_map >>= 1, if_id++) {

        if (!(vdev_map & 0x1)) {
            continue;
        }

        /* Get the VAP corresponding to the id */
        vap = ol_ath_get_vap( ic, if_id);
        if (vap == NULL) {
            return -1;
        }

        avn = OL_ATH_VAP_NET80211(vap);
        if (avn->av_wbuf == NULL) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "beacon buffer av_wbuf is NULL - Ignoring tsf offset event \n");
            return -1;
        }

        /* Save the adjusted TSF */
        avn->av_tsfadjust = adjusted_tsf[if_id];

#if defined (CONFIG_AR900B_SUPPORT) || defined (CONFIG_AR9888_SUPPORT)
        if (scn->is_ar900b) {
            if (IEEE80211_IS_CHAN_PUREG(ic->ic_curchan) || IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan)
                                || IEEE80211_IS_CHAN_OFDM(ic->ic_curchan)) {
                /* 6Mbps Beacon: */
                tx_delay = 56; /*20(lsig)+2(service)+32(6mbps, 24 bytes) = 54us + 2us(MAC/BB DELAY) */
            }
            else if(IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan)) {
                /* 1Mbps Beacon: */
                tx_delay = 386; /*144 us ( LPREAMBLE) + 48 (PLCP Header) + 192 (1Mbps, 24 ytes) = 384 us + 2us(MAC/BB DELAY */
            }
            /* Save the adjusted TSF */
            avn->av_tsfadjust = adjusted_tsf[if_id] - tx_delay;
        }
#endif

        /*
         * Make the TSF offset negative so beacons in the same staggered batch
         * have the same TSF.
         */
        adjusted_tsf_le = cpu_to_le64(0ULL - avn->av_tsfadjust);

        /* Update the timstamp in the beacon buffer with adjusted TSF */
        wh = (struct ieee80211_frame *)wbuf_header(avn->av_wbuf);
        OS_MEMCPY(&wh[1], &adjusted_tsf_le, sizeof(adjusted_tsf_le));
    }

    return 0;
}

/* WMI Beacon related Event APIs */
static int
ol_beacon_swba_handler(ol_scn_t scn, u_int8_t *data, u_int16_t datalen)
{
    return ol_ath_beacon_swba_handler(scn, data);
}

static int
ol_tbttoffset_update_event_handler(ol_scn_t sc, u_int8_t *data, u_int16_t datalen)
{
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)sc;
    uint32_t vdev_map, *tbttoffset_list;

    if(wmi_extract_tbttoffset_update_params(scn->wmi_handle, data, &vdev_map,
                                                          &tbttoffset_list)) {
        qdf_print("Failed toextract\n");
        return -1;
    }

    return ol_ath_tsf_offset_event_handler(scn, vdev_map,
                     tbttoffset_list);
}


/*
 * Beacon related attach functions for offload solutions
 */
void
ol_ath_beacon_attach(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    ic->ic_beacon_probe_template_update = ol_ath_beacon_probe_template_update;
    ic->ic_beacon_update = ol_ath_beacon_update;
    ic->ic_is_hwbeaconproc_active = ol_ath_net80211_is_hwbeaconproc_active;
    ic->ic_hw_beacon_rssi_threshold_enable = ol_ath_net80211_hw_beacon_rssi_threshold_enable;
    ic->ic_hw_beacon_rssi_threshold_disable = ol_ath_net80211_hw_beacon_rssi_threshold_disable;

    /* Register WMI event handlers */
    wmi_unified_register_event_handler(scn->wmi_handle, wmi_host_swba_event_id,
                                            ol_beacon_swba_handler, WMI_RX_UMAC_CTX);
    wmi_unified_register_event_handler(scn->wmi_handle, wmi_tbttoffset_update_event_id,
                                           ol_tbttoffset_update_event_handler, WMI_RX_UMAC_CTX);
}
#endif
