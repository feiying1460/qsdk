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
 * LMAC management specific offload interface functions - for PHY error handling
 */
#include "ol_if_athvar.h"

/* This enables verbose printing of PHY error debugging */
#define ATH_PHYERR_DEBUG        0

#if ATH_PERF_PWR_OFFLOAD

#if ATH_SUPPORT_DFS
#include "ath_dfs_structs.h"
#include "dfs_interface.h"
#include "dfs.h"                /* for DFS_*_DOMAIN */
#endif /* ATH_SUPPORT_DFS */

#if ATH_SUPPORT_SPECTRAL
#include "spectral.h"
#include "ol_if_spectral.h"
#endif

#define AR900B_DFS_PHYERR_MASK      0x4
#define AR900B_SPECTRAL_PHYERR_MASK 0x4000000

static int
ol_ath_phyerr_rx_event_handler_wifi2_0(ol_scn_t scn, u_int8_t *data,
        u_int16_t datalen);
/*
 * XXX TODO: talk to Nitin about the endian-ness of this - what's
 * being byteswapped by the firmware?!
 */
static int
ol_ath_phyerr_rx_event_handler(ol_scn_t scn, u_int8_t *data,
    u_int16_t datalen)
{
    wmi_host_phyerr_t phyerr;
#if ATH_SUPPORT_DFS || ATH_SUPPORT_SPECTRAL
    struct ieee80211com *ic = &scn->sc_ic;
#endif /* ATH_SUPPORT_DFS || ATH_SUPPORT_SPECTRAL */
    uint16_t buf_offset = 0;
#if ATH_SUPPORT_SPECTRAL
    spectral_acs_stats_t acs_stats;
    struct ath_spectral* spectral = (struct ath_spectral*) ic->ic_spectral;
#endif

    if (scn->target_type == TARGET_TYPE_AR900B  || scn->target_type == TARGET_TYPE_QCA9984 || \
                        scn->target_type == TARGET_TYPE_QCA9888 || scn->target_type == TARGET_TYPE_IPQ4019) {
        return ol_ath_phyerr_rx_event_handler_wifi2_0(scn, data, datalen);
    }

    /* Ensure it's at least the size of the header */
    if(wmi_extract_comb_phyerr(scn->wmi_handle, data,
                       datalen, &buf_offset, &phyerr )) {
#if ATH_SUPPORT_SPECTRAL
        spectral->ath_spectral_stats.datalen_discards++;
#endif
        return (1);             /* XXX what should errors be? */
    }

    /* Loop over the bufp, extracting out phyerrors */
    /*
     * XXX wmi_unified_comb_phyerr_rx_event.bufp is a char pointer,
     * which isn't correct here - what we have received here
     * is an array of TLV-style PHY errors.
     */
    while (buf_offset < datalen) {

        if(wmi_extract_single_phyerr(scn->wmi_handle, data,
                       datalen, &buf_offset, &phyerr )) {
#if ATH_SUPPORT_SPECTRAL
	        spectral->ath_spectral_stats.datalen_discards++;
#endif
	        return (1);             /* XXX what should errors be? */
	}
#if ATH_SUPPORT_DFS
        /*
         * If required, pass radar events to the dfs pattern matching code.
         *
         * Don't pass radar events with no buffer payload.
         */
        if (phyerr.phy_err_code == 0x5 || phyerr.phy_err_code == 0x24) {
            if (phyerr.buf_len > 0)
                dfs_process_phyerr(ic, &phyerr.bufp[0], phyerr.buf_len,
                  phyerr.rf_info.rssi_comb & 0xff,
                  phyerr.rf_info.rssi_comb & 0xff, /* XXX Extension RSSI */
                  phyerr.tsf_timestamp,
                  phyerr.tsf64);
        }
#endif /* ATH_SUPPORT_DFS */

#if ATH_SUPPORT_SPECTRAL

        /*
         * If required, pass spectral events to the spectral module
         *
         */
        if (phyerr.phy_err_code == PHY_ERROR_FALSE_RADAR_EXT ||
            phyerr.phy_err_code == PHY_ERROR_SPECTRAL_SCAN) {
            if (phyerr.buf_len > 0) {
                SPECTRAL_RFQUAL_INFO rfqual_info;
                SPECTRAL_CHAN_INFO   chan_info;

                OS_MEMCPY(&rfqual_info, &phyerr.rf_info, sizeof(wmi_host_rf_info_t));
                OS_MEMCPY(&chan_info, &phyerr.chan_info, sizeof(wmi_host_chan_info_t));

                if (phyerr.phy_err_code == PHY_ERROR_SPECTRAL_SCAN) {
                    spectral_process_phyerr(ic->ic_spectral, phyerr.bufp, phyerr.buf_len, &rfqual_info, &chan_info, phyerr.tsf64, &acs_stats);
                }

#if ATH_ACS_SUPPORT_SPECTRAL && ATH_SUPPORT_SPECTRAL
                if (phyerr.phy_err_code == PHY_ERROR_SPECTRAL_SCAN) {
                    ieee80211_init_spectral_chan_loading(ic, chan_info.center_freq1, 0);
                    ieee80211_update_eacs_counters(ic, acs_stats.nfc_ctl_rssi,
                                                       acs_stats.nfc_ext_rssi,
                                                       acs_stats.ctrl_nf,
                                                       acs_stats.ext_nf);
                }
#endif
#ifdef SPECTRAL_SUPPORT_LOGSPECTRAL
                spectral_send_tlv_to_host(ic->ic_spectral, phyerr.bufp, phyerr.buf_len);
#endif
            }
        }
#endif  /* ATH_SUPPORT_SPECTRAL */

    }
     return (0);
}

static int
ol_ath_phyerr_rx_event_handler_wifi2_0(ol_scn_t scn, u_int8_t *data,
        u_int16_t datalen)
{
    struct ieee80211com *ic = &scn->sc_ic;
    wmi_host_phyerr_t phyerr;
#if ATH_SUPPORT_SPECTRAL
    spectral_acs_stats_t acs_stats;
    struct ath_spectral* spectral = (struct ath_spectral*) ic->ic_spectral;
#endif

    /* sanity check on data length */
    if (wmi_extract_composite_phyerr(scn->wmi_handle, data,
                       datalen, &phyerr )) {
#if ATH_SUPPORT_SPECTRAL
        spectral->ath_spectral_stats.datalen_discards++;
#endif
        return (1);
    }

    /* handle different PHY Error conditions */
    if (((phyerr.phy_err_mask0 & (AR900B_DFS_PHYERR_MASK | AR900B_SPECTRAL_PHYERR_MASK)) == 0)) {
        /* unknown PHY error, currently only Spectral and DFS are handled */
        return (1);
    }

    /* Handle Spectral PHY Error */
    if ((phyerr.phy_err_mask0 & AR900B_SPECTRAL_PHYERR_MASK)) {
#if ATH_SUPPORT_SPECTRAL
        if (phyerr.buf_len > 0) {
            SPECTRAL_RFQUAL_INFO rfqual_info;
            SPECTRAL_CHAN_INFO   chan_info;

            OS_MEMCPY(&rfqual_info, &phyerr.rf_info, sizeof(wmi_host_rf_info_t));
            OS_MEMCPY(&chan_info, &phyerr.chan_info, sizeof(wmi_host_chan_info_t));

            if ( phyerr.phy_err_mask0 & AR900B_SPECTRAL_PHYERR_MASK) {
                spectral_process_phyerr(ic->ic_spectral, phyerr.bufp, phyerr.buf_len, &rfqual_info, &chan_info, phyerr.tsf64, &acs_stats);
             }

#if ATH_ACS_SUPPORT_SPECTRAL && ATH_SUPPORT_SPECTRAL
             if ( phyerr.phy_err_mask0 & AR900B_SPECTRAL_PHYERR_MASK) {
                    ieee80211_init_spectral_chan_loading(ic, chan_info.center_freq1, 0);
                    ieee80211_update_eacs_counters(ic, acs_stats.nfc_ctl_rssi,
                                                       acs_stats.nfc_ext_rssi,
                                                       acs_stats.ctrl_nf,
                                                       acs_stats.ext_nf);
             }
#endif
#ifdef SPECTRAL_SUPPORT_LOGSPECTRAL
             spectral_send_tlv_to_host(ic->ic_spectral, phyerr.bufp, phyerr.buf_len);
#endif
        }
#endif  /* ATH_SUPPORT_SPECTRAL */

    } else if ((phyerr.phy_err_mask0 & AR900B_DFS_PHYERR_MASK)) {
        if (phyerr.buf_len > 0) {
#if ATH_SUPPORT_DFS
            dfs_process_phyerr(ic, phyerr.bufp, phyerr.buf_len,
                phyerr.rf_info.rssi_comb & 0xff,
                phyerr.rf_info.rssi_comb & 0xff, /* XXX Extension RSSI */
                phyerr.tsf_timestamp,
                phyerr.tsf64);
#endif /*ATH_SUPPORT_DFS*/
        }
    }
     return (0);
}

/*
 * Enable PHY errors.
 *
 * For now, this just enables the DFS PHY errors rather than
 * being able to select which PHY errors to enable.
 */
void
ol_ath_phyerr_enable(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    wmi_unified_phyerr_enable_cmd_send(scn->wmi_handle);
}

/*
 * Disbale PHY errors.
 *
 * For now, this just disables the DFS PHY errors rather than
 * being able to select which PHY errors to disable.
 */
void
ol_ath_phyerr_disable(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    wmi_unified_phyerr_disable_cmd_send(scn->wmi_handle);
}

/*
 * PHY error attach functions for offload solutions
 */
void
ol_ath_phyerr_attach(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    qdf_print(KERN_DEBUG"%s: called\n", __func__);

    /* Register WMI event handlers */
    wmi_unified_register_event_handler(scn->wmi_handle,
      wmi_phyerr_event_id,
      ol_ath_phyerr_rx_event_handler,
      WMI_RX_UMAC_CTX);
}

/*
 * Detach the PHY error module.
 */
void
ol_ath_phyerr_detach(struct ieee80211com *ic)
{

    /* XXX TODO: see what needs to be unregistered */
    qdf_print(KERN_INFO"%s: called\n", __func__);
}

#endif /* ATH_PERF_PWR_OFFLOAD */
