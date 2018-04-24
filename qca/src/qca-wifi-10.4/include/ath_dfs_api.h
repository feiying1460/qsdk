/*
 * Copyright (c) 2012 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */
#ifndef	__ATH_DFS_API_H__
#define	__ATH_DFS_API_H__

/*
 * Assert that the NOVAL values match.
 */
#if (ATH_DFS_PHYERR_PARAM_NOVAL != HAL_PHYERR_PARAM_NOVAL)
#error "ATH_DFS_PHYERR_PARAM_NOVAL != HAL_PHYERR_PARAM_NOVAL"
#endif

/*
 * Assert that the ENABLE values match.
 */
#if (ATH_DFS_PHYERR_PARAM_ENABLE != HAL_PHYERR_PARAM_ENABLE)
#error "ATH_DFS_PHYERR_PARAM_ENABLE != HAL_PHYERR_PARAM_ENABLE"
#endif

/*
 * These two methods are used by the lmac glue to copy between
 * the DFS and HAL PHY configuration.
 *
 * I'm "cheating" here and assuming that the ENABLE and NOVAL
 * values match - see the above macros.
 */
static inline void
ath_dfs_halparam_to_dfsparam(const HAL_PHYERR_PARAM *src,
    struct ath_dfs_phyerr_param *dst)
{

    dst->pe_firpwr = src->pe_firpwr;
    dst->pe_rrssi = src->pe_rrssi;
    dst->pe_height = src->pe_height;
    dst->pe_prssi = src->pe_prssi;
    dst->pe_inband = src->pe_inband;
    dst->pe_relpwr = src->pe_relpwr;
    dst->pe_relstep = src->pe_relstep;
    dst->pe_maxlen = src->pe_maxlen;
}

static inline void
ath_dfs_dfsparam_to_halparam(struct ath_dfs_phyerr_param *src,
    HAL_PHYERR_PARAM *dst)
{

    dst->pe_firpwr = src->pe_firpwr;
    dst->pe_rrssi = src->pe_rrssi;
    dst->pe_height = src->pe_height;
    dst->pe_prssi = src->pe_prssi;
    dst->pe_inband = src->pe_inband;
    dst->pe_relpwr = src->pe_relpwr;
    dst->pe_relstep = src->pe_relstep;
    dst->pe_maxlen = src->pe_maxlen;
}

#endif	/* __ATH_DFS_API_H__ */
