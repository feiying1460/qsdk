/*
 * Copyright (c) 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef _SPECTRAL_SIM_H_
#define _SPECTRAL_SIM_H_

#if QCA_SUPPORT_SPECTRAL_SIMULATION
#include "ah.h"
#include "spectral.h"

/**
 * @brief Initialize Spectral Simulation functionality
 * @details
 *  Setup data structures to be used for serving out data corresponding to
 *  various bandwidths and configurations.
 *
 * @param spectral - ath_spectral structure
 * @return Integer status value. 0:Success, -1:Failure
 */
int spectral_sim_attach(struct ath_spectral *spectral);

/**
 * @brief De-initialize Spectral Simulation functionality
 * @details
 *  Free up data structures used for serving out data corresponding to various
 *  bandwidths and configurations.
 *
 * @param spectral - ath_spectral structure
 */
void spectral_sim_detach(struct ath_spectral *spectral);

/**
 * @brief Check if Spectral (simulated) is active
 *
 * @param arg - pointer to ath_spectral structure
 * @return Integer status value. 0: Not active, 1: Active
 */
u_int32_t spectral_sim_is_spectral_active(void* arg);

/**
 * @brief Check if Spectral (simulated) is enabled
 *
 * @param arg - pointer to ath_spectral structure
 * @return Integer status value. 0: Not enabled, 1: Enabled
 */
u_int32_t spectral_sim_is_spectral_enabled(void* arg);

/**
 * @brief Start Spectral simulation
 *
 * @param arg - pointer to ath_spectral structure
 * @return Integer status value. 0: Failure, 1: Success
 */
u_int32_t spectral_sim_start_spectral_scan(void* arg);

/**
 * @brief Stop Spectral simulation
 *
 * @param arg - pointer to ath_spectral structure
 * @return Integer status value. 0: Failure, 1: Success
 */
u_int32_t spectral_sim_stop_spectral_scan(void* arg);

/**
 * @brief Configure Spectral parameters into simulation
 * @details
 *  Internally, this function actually searches if a record set with the desired
 *  configuration has been loaded. If so, it points to the record set for
 *  later usage when the simulation is started. If not, it returns an error.
 *
 * @param arg - pointer to ath_spectral structure
 * @param params - pointer to HAL_SPECTRAL_PARAM structure bearing Spectral
 *                 configuration
 * @return Integer status value. 0: Failure, 1: Success
 */
u_int32_t spectral_sim_configure_params(void* arg, HAL_SPECTRAL_PARAM* params);

/**
 * @brief Get Spectral parameters configured into simulation
 *
 * @param arg - pointer to ath_spectral structure
 * @param params - pointer to HAL_SPECTRAL_PARAM structure which should be
 *                 populated with Spectral configuration
 * @return Integer status value. 0: Failure, 1: Success
 */
u_int32_t spectral_sim_get_params(void* arg, HAL_SPECTRAL_PARAM* params);

#endif /* QCA_SUPPORT_SPECTRAL_SIMULATION */
#endif /* _SPECTRAL_SIM_H_ */
