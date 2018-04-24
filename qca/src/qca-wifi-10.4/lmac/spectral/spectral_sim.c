/*
 * Copyright (c) 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#if QCA_SUPPORT_SPECTRAL_SIMULATION
#include "spectral.h"
#include "spectral_sim.h"
#include "spectral_sim_internal.h"
#include "_ieee80211.h"
#include "ieee80211_api.h"
#include "ieee80211_defines.h"

/* Helper functions */

static int populate_report_static(ath_spectralsim_report *report,
                              enum ieee80211_cwm_width width,
                              bool is_80_80);
static void depopulate_report(ath_spectralsim_report *report);

static int populate_reportset_static(ath_spectralsim_reportset *reportset,
                              enum ieee80211_cwm_width width,
                              bool is_80_80);
static int populate_reportset_fromfile(ath_spectralsim_reportset *reportset,
                              enum ieee80211_cwm_width width,
                              bool is_80_80);
static void depopulate_reportset(ath_spectralsim_reportset *reportset);

static int populate_simdata(ath_spectralsim_context *simctx);
static void depopulate_simdata(ath_spectralsim_context *simctx);
static OS_TIMER_FUNC(spectral_sim_phyerrdelivery_handler);


/* Static configuration.
   For now, we will be having a single configuration per BW, and a single
   report per configuration (since we need the data only for ensuring correct
   format handling).
   
   Extend this for more functionality if required in the future.
 */

/* Statically populate simulation data for one report. */
static int populate_report_static(ath_spectralsim_report *report,
                              enum ieee80211_cwm_width width,
                              bool is_80_80)
{
    qdf_assert_always(report != NULL);

    switch(width)
    {
        case IEEE80211_CWM_WIDTH20:
            report->data = NULL;
            report->data = (u_int8_t*)
                qdf_mem_alloc(NULL, sizeof(reportdata_20));

            if (report->data == NULL) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Spectral simulation: Could not allocate memory for "
                       "report data\n");
                goto bad;
            }
            
            report->datasize = sizeof(reportdata_20);
            qdf_mem_copy(report->data,
                    reportdata_20, report->datasize);
   
            qdf_mem_copy(&report->rfqual_info,
                    &rfqual_info_20, sizeof(report->rfqual_info));
            
            qdf_mem_copy(&report->chan_info,
                    &chan_info_20, sizeof(report->chan_info));
            
            break;
        case IEEE80211_CWM_WIDTH40:
            report->data = NULL;
            report->data = (u_int8_t*)
                qdf_mem_alloc(NULL, sizeof(reportdata_40));

            if (report->data == NULL) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Spectral simulation: Could not allocate memory for "
                       "report data\n");
                goto bad;
            }
            
            report->datasize = sizeof(reportdata_40);
            qdf_mem_copy(report->data,
                    reportdata_40, report->datasize);
   
            qdf_mem_copy(&report->rfqual_info,
                    &rfqual_info_40, sizeof(report->rfqual_info));
            
            qdf_mem_copy(&report->chan_info,
                    &chan_info_40, sizeof(report->chan_info));
            
            break;
        case IEEE80211_CWM_WIDTH80:
            report->data = NULL;
            report->data = (u_int8_t*)
                qdf_mem_alloc(NULL, sizeof(reportdata_80));

            if (report->data == NULL) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Spectral simulation: Could not allocate memory for "
                       "report data\n");
                goto bad;
            }
            
            report->datasize = sizeof(reportdata_80);
            qdf_mem_copy(report->data,
                    reportdata_80, report->datasize);
   
            qdf_mem_copy(&report->rfqual_info,
                    &rfqual_info_80, sizeof(report->rfqual_info));
            
            qdf_mem_copy(&report->chan_info,
                    &chan_info_80, sizeof(report->chan_info));
            
            break;
        case IEEE80211_CWM_WIDTH160:
            if (is_80_80) {
                report->data = NULL;
                report->data = (u_int8_t*)
                    qdf_mem_alloc(NULL, sizeof(reportdata_80_80));

                if (report->data == NULL) {
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Spectral simulation: Could not allocate memory for "
                           "report data\n");
                    goto bad;
                }
                
                report->datasize = sizeof(reportdata_80_80);
                qdf_mem_copy(report->data,
                        reportdata_80_80, report->datasize);
       
                qdf_mem_copy(&report->rfqual_info,
                        &rfqual_info_80_80, sizeof(report->rfqual_info));
                
                qdf_mem_copy(&report->chan_info,
                        &chan_info_80_80, sizeof(report->chan_info));

            } else {
                report->data = NULL;
                report->data = (u_int8_t*)
                    qdf_mem_alloc(NULL, sizeof(reportdata_160));

                if (report->data == NULL) {
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Spectral simulation: Could not allocate memory for "
                           "report data\n");
                    goto bad;
                }
                
                report->datasize = sizeof(reportdata_160);
                qdf_mem_copy(report->data,
                        reportdata_160, report->datasize);
       
                qdf_mem_copy(&report->rfqual_info,
                        &rfqual_info_160, sizeof(report->rfqual_info));
                
                qdf_mem_copy(&report->chan_info,
                        &chan_info_160, sizeof(report->chan_info));
            }
            break;
        default:
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Unhandled width. Please correct. Asserting\n");
            qdf_assert_always(0);
    }

    return 0;

bad:
    return -1;
}

static void depopulate_report(ath_spectralsim_report *report)
{
    if (report == NULL) {
        return;
    }

    if (report->data != NULL) {
        qdf_mem_free(report->data);
        report->data = NULL;
        report->datasize = 0;
    }

    return;
}

/* Statically populate simulation data for a given configuration. */
static int populate_reportset_static(ath_spectralsim_reportset *reportset,
                              enum ieee80211_cwm_width width,
                              bool is_80_80)
{
    int ret = 0;
    ath_spectralsim_report *report = NULL;
    
    qdf_assert_always(reportset != NULL);
    
    reportset->headreport = NULL;
    reportset->curr_report = NULL;

    /* For now, we populate only one report */
    report = (ath_spectralsim_report*)
        qdf_mem_alloc(NULL, sizeof(ath_spectralsim_report));

    if (report == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Spectral simulation: Could not allocate memory for report.\n");
        goto bad;
    }

    qdf_mem_zero(report, sizeof(*report));

    switch(width)
    {
        case IEEE80211_CWM_WIDTH20:
            qdf_mem_copy(&reportset->config,
                    &config_20_1, sizeof(reportset->config));
            
            if ((ret = populate_report_static(report, 
                            IEEE80211_CWM_WIDTH20, 0)) != 0) {
                    goto bad;
            }

            report->next = NULL;
            reportset->headreport = report;
            break;
        case IEEE80211_CWM_WIDTH40:
            qdf_mem_copy(&reportset->config,
                    &config_40_1, sizeof(reportset->config));
            
            if ((ret = populate_report_static(report, 
                            IEEE80211_CWM_WIDTH40, 0)) != 0) {
                    goto bad;
            }

            report->next = NULL;
            reportset->headreport = report;
            break;
        case IEEE80211_CWM_WIDTH80:
            qdf_mem_copy(&reportset->config,
                    &config_80_1, sizeof(reportset->config));
            
            if ((ret = populate_report_static(report, 
                            IEEE80211_CWM_WIDTH80, 0)) != 0) {
                    goto bad;
            }

            report->next = NULL;
            reportset->headreport = report;
            break;
        case IEEE80211_CWM_WIDTH160:
            if (is_80_80) {
                qdf_mem_copy(&reportset->config,
                        &config_80_80_1, sizeof(reportset->config));
                
                if ((ret = populate_report_static(report, 
                                IEEE80211_CWM_WIDTH160, 1)) != 0) {
                        goto bad;
                }

                report->next = NULL;
                reportset->headreport = report;
            } else {
                qdf_mem_copy(&reportset->config,
                        &config_160_1, sizeof(reportset->config));
                
                if ((ret = populate_report_static(report, 
                                IEEE80211_CWM_WIDTH160, 0)) != 0) {
                        goto bad;
                }

                report->next = NULL;
                reportset->headreport = report;
            }
            break;
        default:
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Unhandled width. Please rectify.\n");
            qdf_assert_always(0);
    };

    reportset->curr_report = reportset->headreport;

    return 0;

bad:
    depopulate_reportset(reportset);
    return -1;
}

static void depopulate_reportset(ath_spectralsim_reportset *reportset)
{
    ath_spectralsim_report *curr_report = NULL;
    ath_spectralsim_report *next_report = NULL;
   
    if (reportset == NULL) {
        return;
    }
    
    curr_report = reportset->headreport;

    while(curr_report)
    {
        next_report = curr_report->next;
        depopulate_report(curr_report);
        qdf_mem_free(curr_report);
        curr_report = next_report;
    }
}

/* Populate simulation data for a given bandwidth by loading from a file.
   This is a place-holder only. To be implemented in the future on a need
   basis.

   A different file per bandwidth is suggested for better segregation of data
   sets (since data is likely to be very different across BWs).
 */
static int populate_reportset_fromfile(ath_spectralsim_reportset *reportset,
                              enum ieee80211_cwm_width width,
                              bool is_80_80)
{
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: To be implemented if required\n", __func__);

    return 0;
}

/* Populate simulation data */
static int populate_simdata(ath_spectralsim_context *simctx)
{
    /* For now, we use static population. Switch to loading from a file if 
     * needed in the future.
     */

    simctx->bw20_headreportset = NULL;
    SPECTRAL_SIM_REPORTSET_ALLOCPOPL_SINGLE(simctx,
            simctx->bw20_headreportset,
            IEEE80211_CWM_WIDTH20,
            0);

    simctx->bw40_headreportset = NULL;
    SPECTRAL_SIM_REPORTSET_ALLOCPOPL_SINGLE(simctx,
            simctx->bw40_headreportset,
            IEEE80211_CWM_WIDTH40,
            0);

    simctx->bw80_headreportset = NULL;
    SPECTRAL_SIM_REPORTSET_ALLOCPOPL_SINGLE(simctx,
            simctx->bw80_headreportset,
            IEEE80211_CWM_WIDTH80,
            0);

    simctx->bw160_headreportset = NULL;
    SPECTRAL_SIM_REPORTSET_ALLOCPOPL_SINGLE(simctx,
            simctx->bw160_headreportset,
            IEEE80211_CWM_WIDTH160,
            0);

    simctx->bw80_80_headreportset = NULL;
    SPECTRAL_SIM_REPORTSET_ALLOCPOPL_SINGLE(simctx,
            simctx->bw80_80_headreportset,
            IEEE80211_CWM_WIDTH160,
            1);
   
    simctx->curr_reportset = NULL;

    simctx->is_enabled = false;
    simctx->is_active = false;
    
    simctx->ssim_starting_tsf64 = 0;
    simctx->ssim_count = 0;
    simctx->ssim_period_ms = 0;

    return 0;
}

static void depopulate_simdata(ath_spectralsim_context *simctx)
{
    if (simctx == NULL)
    {
        return;
    }

    SPECTRAL_SIM_REPORTSET_DEPOPLFREE_LIST(simctx->bw20_headreportset);
    SPECTRAL_SIM_REPORTSET_DEPOPLFREE_LIST(simctx->bw40_headreportset);
    SPECTRAL_SIM_REPORTSET_DEPOPLFREE_LIST(simctx->bw80_headreportset);
    SPECTRAL_SIM_REPORTSET_DEPOPLFREE_LIST(simctx->bw160_headreportset);
    SPECTRAL_SIM_REPORTSET_DEPOPLFREE_LIST(simctx->bw80_80_headreportset);
}

static
OS_TIMER_FUNC(spectral_sim_phyerrdelivery_handler)
{
    struct ieee80211com *ic = NULL;
    struct ath_spectral *spectral = NULL;
    ath_spectralsim_context *simctx = NULL;
    ath_spectralsim_reportset *curr_reportset = NULL;    
    ath_spectralsim_report *curr_report = NULL;
    spectral_acs_stats_t acs_stats;
    u_int64_t curr_tsf64 = 0;
   
    OS_GET_TIMER_ARG(ic, struct ieee80211com *);
    qdf_assert_always(ic != NULL);
    
    spectral = ic->ic_spectral;
    qdf_assert_always(spectral != NULL);

    simctx = (ath_spectralsim_context *)spectral->simctx;
    qdf_assert_always(simctx != NULL);

    if (!simctx->is_active) {
        return;
    }

    curr_reportset = simctx->curr_reportset;
    qdf_assert_always(curr_reportset != NULL);

    curr_report = curr_reportset->curr_report;
    qdf_assert_always(curr_report != NULL);

    qdf_assert_always(curr_reportset->headreport != NULL);

    /* We use a simulation TSF since in offload architectures we can't expect to
     * get an accurate current TSF from HW. 
     * In case of TSF wrap over, we'll use it as-is for now since the simulation
     * is intended only for format verification.
     */
    curr_tsf64 = simctx->ssim_starting_tsf64 +
        ((simctx->ssim_period_ms * simctx->ssim_count) * 1000);

    spectral_process_phyerr(spectral,
            curr_report->data,
            curr_report->datasize,
            &curr_report->rfqual_info,
            &curr_report->chan_info,
            curr_tsf64,
            &acs_stats);

    simctx->ssim_count++;

    if (curr_report->next != NULL) {
        curr_reportset->curr_report = curr_report->next;
    } else {
        curr_reportset->curr_report = curr_reportset->headreport;
    }

    if (curr_reportset->config.ss_count != 0 &&
        simctx->ssim_count == curr_reportset->config.ss_count) {
        spectral_sim_stop_spectral_scan(spectral);
    } else {
        OS_SET_TIMER(&simctx->ssim_pherrdelivery_timer,
                     simctx->ssim_period_ms);
    }
}

/* Module services */

int spectral_sim_attach(struct ath_spectral *spectral)
{
    ath_spectralsim_context *simctx = NULL;
    struct ieee80211com *ic = NULL;

    qdf_assert_always(spectral != NULL);
    
    ic = spectral->ic;
    qdf_assert_always(ic != NULL);
    
    simctx = (ath_spectralsim_context*)
                qdf_mem_alloc(NULL, sizeof(ath_spectralsim_context)); 
   
    if (simctx == NULL) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Spectral simulation: Could not allocate memory for context\n");
        return -1;
    }

    qdf_mem_zero(simctx, sizeof(*simctx));

    spectral->simctx = simctx;

    if (populate_simdata(simctx) != 0) {
        qdf_mem_free(simctx);
        spectral->simctx = NULL;
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Spectral simulation attach failed\n");
        return -1;
    }

    OS_INIT_TIMER(ic->ic_osdev,
            &simctx->ssim_pherrdelivery_timer,
            spectral_sim_phyerrdelivery_handler,
            (void *)(ic));

    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Spectral simulation attached\n");

    return 0;
}

void spectral_sim_detach(struct ath_spectral *spectral)
{
    ath_spectralsim_context *simctx = NULL;

    qdf_assert_always(spectral != NULL);
    
    simctx = (ath_spectralsim_context *)spectral->simctx;
    qdf_assert_always(simctx != NULL);

    OS_FREE_TIMER(&simctx->ssim_pherrdelivery_timer);

    depopulate_simdata(simctx);
    qdf_mem_free(simctx);
    spectral->simctx = NULL;
    
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Spectral simulation detached\n");
}

u_int32_t spectral_sim_is_spectral_active(void* arg)
{
    struct ath_spectral *spectral = NULL;
    ath_spectralsim_context *simctx = NULL;

    spectral = (struct ath_spectral *)arg;
    qdf_assert_always(spectral != NULL); 
    
    simctx = (ath_spectralsim_context *)spectral->simctx;
    qdf_assert_always(simctx != NULL);
    
    return simctx->is_active;
}

u_int32_t spectral_sim_is_spectral_enabled(void* arg)
{
    struct ath_spectral *spectral = NULL;
    ath_spectralsim_context *simctx = NULL;

    spectral = (struct ath_spectral *)arg;
    qdf_assert_always(spectral != NULL); 
    
    simctx = (ath_spectralsim_context *)spectral->simctx;
    qdf_assert_always(simctx != NULL);
    
    return simctx->is_enabled;
}

u_int32_t spectral_sim_start_spectral_scan(void* arg)
{
    struct ath_spectral *spectral = NULL;
    ath_spectralsim_context *simctx = NULL;
    struct ieee80211com *ic = NULL;

    spectral = (struct ath_spectral *)arg;
    qdf_assert_always(spectral != NULL); 
    
    simctx = (ath_spectralsim_context *)spectral->simctx;
    qdf_assert_always(simctx != NULL);
   
    if (simctx->curr_reportset == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Spectral simulation: No current report set configured  - unable "
               "to start simulated Spectral scan\n");
        return 0;
    }

    if (simctx->curr_reportset->curr_report == NULL) {
         QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Spectral simulation: No report data instances populated - "
                "unable to start simulated Spectral scan\n");
        return 0;
    }

    if (!simctx->is_enabled) {
        simctx->is_enabled = true;
    }

    simctx->is_active = true;
    
    ic = spectral->ic;
    qdf_assert_always(ic != NULL);

    simctx->ssim_starting_tsf64 = ic->ic_get_TSF64(ic);
    simctx->ssim_count = 0;

    /* TODO: Support high resolution timer in microseconds if required, so that
     * we can support default periods such as ~200 us.  For now, we use 1
     * millisecond since the current use case for the simulation is to validate
     * formats rather than have a time dependent classification.
     */
    simctx->ssim_period_ms = 1; 

    OS_SET_TIMER(&simctx->ssim_pherrdelivery_timer,
                 simctx->ssim_period_ms);

    return 1;
}

u_int32_t spectral_sim_stop_spectral_scan(void* arg)
{
    struct ath_spectral *spectral = NULL;
    ath_spectralsim_context *simctx = NULL;

    spectral = (struct ath_spectral *)arg;
    qdf_assert_always(spectral != NULL); 

    simctx = (ath_spectralsim_context *)spectral->simctx;
    qdf_assert_always(simctx != NULL);

    OS_CANCEL_TIMER(&simctx->ssim_pherrdelivery_timer);

    simctx->is_active = false;
    simctx->is_enabled = false;
    
    simctx->ssim_starting_tsf64 = 0;
    simctx->ssim_count = 0;
    simctx->ssim_period_ms = 0;

    return 1;
}

u_int32_t spectral_sim_configure_params(void* arg, HAL_SPECTRAL_PARAM* params)
{
    struct ath_spectral *spectral = NULL;
    ath_spectralsim_context *simctx = NULL;
    struct ieee80211vap *vap = NULL;
    struct ieee80211com *ic = NULL;
    enum ieee80211_phymode phymode;
    u_int8_t bw;
    ath_spectralsim_reportset *des_headreportset = NULL, *temp_reportset = NULL;
    bool is_invalid_width = false;

    qdf_assert_always(params != NULL); 

#ifdef SPECTRAL_SIM_DUMP_PARAM_DATA
    {
        int i = 0;

        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n");
        
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Spectral simulation: Param data dump:\n"
               "ss_fft_period=%hu\n"
               "ss_period=%hu\n"
               "ss_count=%hu\n"
               "ss_short_report=%hu\n"
               "radar_bin_thresh_sel=%hhu\n"
               "ss_spectral_pri=%hu\n"
               "ss_fft_size=%hu\n"
               "ss_gc_ena=%hu\n"
               "ss_restart_ena=%hu\n"
               "ss_noise_floor_ref=%hu\n"
               "ss_init_delay=%hu\n"
               "ss_nb_tone_thr=%hu\n"
               "ss_str_bin_thr=%hu\n"
               "ss_wb_rpt_mode=%hu\n"
               "ss_rssi_rpt_mode=%hu\n"
               "ss_rssi_thr=%hu\n"
               "ss_pwr_format=%hu\n"
               "ss_rpt_mode=%hu\n"
               "ss_bin_scale=%hu\n"
               "ss_dBm_adj=%hu\n"
               "ss_chn_mask=%hu\n"
               "ss_nf_temp_data=%d\n",
               params->ss_fft_period,
               params->ss_period,
               params->ss_count,
               params->ss_short_report,
               params->radar_bin_thresh_sel,
               params->ss_spectral_pri,
               params->ss_fft_size,
               params->ss_gc_ena,
               params->ss_restart_ena,
               params->ss_noise_floor_ref,
               params->ss_init_delay,
               params->ss_nb_tone_thr,
               params->ss_str_bin_thr,
               params->ss_wb_rpt_mode,
               params->ss_rssi_rpt_mode,
               params->ss_rssi_thr,
               params->ss_pwr_format,
               params->ss_rpt_mode,
               params->ss_bin_scale,
               params->ss_dBm_adj,
               params->ss_chn_mask,
               params->ss_nf_temp_data);

        for (i = 0; i < AH_MAX_CHAINS * 2; i++)
        {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ss_nf_cal[%d]=%hhd\n",i,params->ss_nf_cal[i]);
        }

        for (i = 0; i < AH_MAX_CHAINS * 2; i++)
        {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ss_nf_pwr[%d]=%hhd\n",i,params->ss_nf_pwr[i]);
        }

        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n");
    } 
#endif /* SPECTRAL_SIM_DUMP_PARAM_DATA */

    spectral = (struct ath_spectral *)arg;
    qdf_assert_always(spectral != NULL); 
    
    simctx = (ath_spectralsim_context *)spectral->simctx;
    qdf_assert_always(simctx != NULL);

    ic = spectral->ic;
    qdf_assert_always(ic != NULL);

    vap = TAILQ_FIRST(&ic->ic_vaps);

    if (vap == NULL) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Spectral simulation: No VAPs found - not proceeding with param "
               "config.\n");
        return 0;
    }

    if (vap->iv_chwidth != IEEE80211_CWM_WIDTHINVALID) {
        bw = vap->iv_chwidth;
    } else {
        bw = ic->ic_cwm_get_width(ic);
    }

    switch(bw)
    {
        case IEEE80211_CWM_WIDTH20:
            des_headreportset = simctx->bw20_headreportset;
            break;
        case IEEE80211_CWM_WIDTH40:
            des_headreportset = simctx->bw40_headreportset;
            break;
        case IEEE80211_CWM_WIDTH80:
            des_headreportset = simctx->bw80_headreportset;
            break;
        case IEEE80211_CWM_WIDTH160:
            phymode = vap->iv_des_mode;
            
            if (phymode == IEEE80211_MODE_11AC_VHT160) {
                des_headreportset = simctx->bw160_headreportset;
            } else if (phymode == IEEE80211_MODE_11AC_VHT80_80) {
                des_headreportset = simctx->bw80_80_headreportset;
            } else {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Spectral simulation: Unexpected PHY mode %u found for "
                       "width 160 MHz...asserting.\n", phymode);
                qdf_assert_always(0);
            }
            
            break;
         case IEEE80211_CWM_WIDTHINVALID:
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Spectral simulation: Invalid width configured - not "
                   "proceeding with param config.\n");
            is_invalid_width = true;
         default:
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Spectral simulation: Unknown width %u...asserting\n", bw);
            qdf_assert_always(0);
            break;
    }

    if (is_invalid_width == true)
    {
        return 0;
    }

    if (des_headreportset == NULL) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Spectral simulation: No simulation data present for configured "
               "bandwidth/PHY mode - unable to proceed with param config.\n");
        return 0;
    }
    
    simctx->curr_reportset = NULL;
    temp_reportset = des_headreportset;

    while(temp_reportset) {
        if (qdf_mem_cmp(&temp_reportset->config,
                    params, sizeof(HAL_SPECTRAL_PARAM)) == 0) {
            /* Found a matching config. We are done. */
            simctx->curr_reportset = temp_reportset;
            break;
        }

        temp_reportset = temp_reportset->next;
    }

    if (simctx->curr_reportset == NULL) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Spectral simulation: No simulation data present for desired "
               "Spectral configuration - unable to proceed with param config.\n");
        return 0;
    }

    if (simctx->curr_reportset->curr_report == NULL) {
         QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Spectral simulation: No report data instances populated "
                "for desired Spectral configuration - unable to proceed with "
                "param config\n");
        return 0;
    }

    return 1;
}

u_int32_t spectral_sim_get_params(void* arg, HAL_SPECTRAL_PARAM* params)
{
    struct ath_spectral *spectral = NULL;
    ath_spectralsim_context *simctx = NULL;

    qdf_assert_always(params != NULL); 

    spectral = (struct ath_spectral *)arg;
    qdf_assert_always(spectral != NULL); 
    
    simctx = (ath_spectralsim_context *)spectral->simctx;
    qdf_assert_always(simctx != NULL);
   
    if (simctx->curr_reportset == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Spectral simulation: No configured reportset found.\n");
        return 0;
    }

    qdf_mem_copy(params, &simctx->curr_reportset->config, sizeof(*params));

    return 1;
}

EXPORT_SYMBOL(spectral_sim_is_spectral_active);
EXPORT_SYMBOL(spectral_sim_is_spectral_enabled);
EXPORT_SYMBOL(spectral_sim_start_spectral_scan);
EXPORT_SYMBOL(spectral_sim_stop_spectral_scan);
EXPORT_SYMBOL(spectral_sim_configure_params);
EXPORT_SYMBOL(spectral_sim_get_params);

#endif /* QCA_SUPPORT_SPECTRAL_SIMULATION */
