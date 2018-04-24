/*
 * Copyright (c) 2017, The Linux Foundation. All rights reserved.
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


/**
 * @defgroup
 * @{
 */
#ifndef _HPPE_UNIPHY_H_
#define _HPPE_UNIPHY_H_

#define UNIPHY_OFFSET_CALIB_4_MAX_ENTRY	3
#define UNIPHY_MODE_CTRL_MAX_ENTRY	3
#define UNIPHY_CHANNEL0_INPUT_OUTPUT_4_MAX_ENTRY	3
#define UNIPHY_CHANNEL1_INPUT_OUTPUT_4_MAX_ENTRY	3
#define UNIPHY_CHANNEL2_INPUT_OUTPUT_4_MAX_ENTRY	3
#define UNIPHY_CHANNEL3_INPUT_OUTPUT_4_MAX_ENTRY	3
#define UNIPHY_CHANNEL4_INPUT_OUTPUT_4_MAX_ENTRY	3
#define SR_XS_PCS_KR_STS1_MAX_ENTRY	3
#define VR_XS_PCS_DIG_CTRL1_MAX_ENTRY	3
#define SR_MII_CTRL_MAX_ENTRY	3
#define VR_MII_AN_CTRL_MAX_ENTRY	3
#define VR_MII_AN_INTR_STS_MAX_ENTRY	3


sw_error_t
hppe_uniphy_offset_calib_4_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		union uniphy_offset_calib_4_u *value);

sw_error_t
hppe_uniphy_offset_calib_4_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		union uniphy_offset_calib_4_u *value);

sw_error_t
hppe_uniphy_mode_ctrl_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		union uniphy_mode_ctrl_u *value);

sw_error_t
hppe_uniphy_mode_ctrl_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		union uniphy_mode_ctrl_u *value);

sw_error_t
hppe_uniphy_channel0_input_output_4_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		union uniphy_channel0_input_output_4_u *value);

sw_error_t
hppe_uniphy_channel0_input_output_4_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		union uniphy_channel0_input_output_4_u *value);

sw_error_t
hppe_uniphy_channel1_input_output_4_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		union uniphy_channel1_input_output_4_u *value);

sw_error_t
hppe_uniphy_channel1_input_output_4_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		union uniphy_channel1_input_output_4_u *value);

sw_error_t
hppe_uniphy_channel2_input_output_4_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		union uniphy_channel2_input_output_4_u *value);

sw_error_t
hppe_uniphy_channel2_input_output_4_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		union uniphy_channel2_input_output_4_u *value);

sw_error_t
hppe_uniphy_channel3_input_output_4_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		union uniphy_channel3_input_output_4_u *value);

sw_error_t
hppe_uniphy_channel3_input_output_4_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		union uniphy_channel3_input_output_4_u *value);

sw_error_t
hppe_uniphy_channel4_input_output_4_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		union uniphy_channel4_input_output_4_u *value);

sw_error_t
hppe_uniphy_channel4_input_output_4_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		union uniphy_channel4_input_output_4_u *value);

sw_error_t
hppe_sr_xs_pcs_kr_sts1_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		union sr_xs_pcs_kr_sts1_u *value);

sw_error_t
hppe_sr_xs_pcs_kr_sts1_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		union sr_xs_pcs_kr_sts1_u *value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		union vr_xs_pcs_dig_ctrl1_u *value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		union vr_xs_pcs_dig_ctrl1_u *value);

sw_error_t
hppe_sr_mii_ctrl_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		union sr_mii_ctrl_u *value);

sw_error_t
hppe_sr_mii_ctrl_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		union sr_mii_ctrl_u *value);

sw_error_t
hppe_vr_mii_an_ctrl_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		union vr_mii_an_ctrl_u *value);

sw_error_t
hppe_vr_mii_an_ctrl_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		union vr_mii_an_ctrl_u *value);

sw_error_t
hppe_vr_mii_an_intr_sts_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		union vr_mii_an_intr_sts_u *value);

sw_error_t
hppe_vr_mii_an_intr_sts_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		union vr_mii_an_intr_sts_u *value);

sw_error_t
hppe_uniphy_offset_calib_4_mmd1_reg_cal_rep_time_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_offset_calib_4_mmd1_reg_cal_rep_time_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_offset_calib_4_mmd1_reg_pll_locked_reg_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_offset_calib_4_mmd1_reg_pll_locked_reg_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_offset_calib_4_mmd1_reg_clr_sampler_calib_timeout_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_offset_calib_4_mmd1_reg_clr_sampler_calib_timeout_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_offset_calib_4_mmd1_reg_lockdet_lckdt_reg_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_offset_calib_4_mmd1_reg_lockdet_lckdt_reg_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_offset_calib_4_mmd1_reg_cal_detect_time_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_offset_calib_4_mmd1_reg_cal_detect_time_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_offset_calib_4_mmd1_reg_calibration_done_reg_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_offset_calib_4_mmd1_reg_calibration_done_reg_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_offset_calib_4_mmd1_reg_smpl_cal_ready_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_offset_calib_4_mmd1_reg_smpl_cal_ready_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_mode_ctrl_newaddedfromhere_ch1_ch0_sgmii_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_mode_ctrl_newaddedfromhere_ch1_ch0_sgmii_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_mode_ctrl_newaddedfromhere_usxg_en_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_mode_ctrl_newaddedfromhere_usxg_en_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_mode_ctrl_newaddedfromhere_ch4_ch1_0_sgmii_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_mode_ctrl_newaddedfromhere_ch4_ch1_0_sgmii_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_mode_ctrl_newaddedfromhere_sgplus_mode_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_mode_ctrl_newaddedfromhere_sgplus_mode_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_mode_ctrl_newaddedfromhere_xpcs_mode_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_mode_ctrl_newaddedfromhere_xpcs_mode_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_mode_ctrl_newaddedfromhere_ch0_psgmii_qsgmii_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_mode_ctrl_newaddedfromhere_ch0_psgmii_qsgmii_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_mode_ctrl_newaddedfromhere_ch0_athr_csco_mode_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_mode_ctrl_newaddedfromhere_ch0_athr_csco_mode_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_mode_ctrl_newaddedfromhere_sw_v17_v18_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_mode_ctrl_newaddedfromhere_sw_v17_v18_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_mode_ctrl_newaddedfromhere_ch0_mode_ctrl_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_mode_ctrl_newaddedfromhere_ch0_mode_ctrl_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_mode_ctrl_newaddedfromhere_sgmii_even_low_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_mode_ctrl_newaddedfromhere_sgmii_even_low_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_mode_ctrl_newaddedfromhere_ch0_qsgmii_sgmii_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_mode_ctrl_newaddedfromhere_ch0_qsgmii_sgmii_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_mode_ctrl_newaddedfromhere_sg_mode_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_mode_ctrl_newaddedfromhere_sg_mode_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel0_input_output_4_newaddedfromhere_ch0_mr_restart_an_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel0_input_output_4_newaddedfromhere_ch0_mr_restart_an_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel0_input_output_4_newaddedfromhere_ch0_rem_phy_lpbk_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel0_input_output_4_newaddedfromhere_ch0_rem_phy_lpbk_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel0_input_output_4_newaddedfromhere_ch0_mr_reg4_ch_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel0_input_output_4_newaddedfromhere_ch0_mr_reg4_ch_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel0_input_output_4_newaddedfromhere_ch0_power_on_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel0_input_output_4_newaddedfromhere_ch0_power_on_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel0_input_output_4_newaddedfromhere_ch0_mr_main_reset_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel0_input_output_4_newaddedfromhere_ch0_mr_main_reset_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel0_input_output_4_newaddedfromhere_ch0_force_speed_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel0_input_output_4_newaddedfromhere_ch0_force_speed_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel0_input_output_4_newaddedfromhere_ch0_adp_sw_rstn_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel0_input_output_4_newaddedfromhere_ch0_adp_sw_rstn_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel0_input_output_4_newaddedfromhere_ch0_speed_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel0_input_output_4_newaddedfromhere_ch0_speed_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel0_input_output_4_newaddedfromhere_ch0_mr_an_enable_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel0_input_output_4_newaddedfromhere_ch0_mr_an_enable_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel0_input_output_4_newaddedfromhere_ch0_mr_np_loaded_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel0_input_output_4_newaddedfromhere_ch0_mr_np_loaded_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel0_input_output_4_newaddedfromhere_ch0_mr_loopback_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel0_input_output_4_newaddedfromhere_ch0_mr_loopback_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel1_input_output_4_newaddedfromhere_ch1_adp_sw_rstn_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel1_input_output_4_newaddedfromhere_ch1_adp_sw_rstn_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel1_input_output_4_newaddedfromhere_ch1_power_on_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel1_input_output_4_newaddedfromhere_ch1_power_on_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel1_input_output_4_newaddedfromhere_ch1_mr_main_reset_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel1_input_output_4_newaddedfromhere_ch1_mr_main_reset_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel1_input_output_4_newaddedfromhere_ch1_mr_an_enable_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel1_input_output_4_newaddedfromhere_ch1_mr_an_enable_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel1_input_output_4_newaddedfromhere_ch1_speed_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel1_input_output_4_newaddedfromhere_ch1_speed_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel1_input_output_4_newaddedfromhere_ch1_rem_phy_lpbk_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel1_input_output_4_newaddedfromhere_ch1_rem_phy_lpbk_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel1_input_output_4_newaddedfromhere_ch1_mr_reg4_ch_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel1_input_output_4_newaddedfromhere_ch1_mr_reg4_ch_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel1_input_output_4_newaddedfromhere_ch1_mr_np_loaded_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel1_input_output_4_newaddedfromhere_ch1_mr_np_loaded_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel1_input_output_4_newaddedfromhere_ch1_force_speed_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel1_input_output_4_newaddedfromhere_ch1_force_speed_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel1_input_output_4_newaddedfromhere_ch1_mr_restart_an_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel1_input_output_4_newaddedfromhere_ch1_mr_restart_an_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel1_input_output_4_newaddedfromhere_ch1_mr_loopback_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel1_input_output_4_newaddedfromhere_ch1_mr_loopback_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel2_input_output_4_newaddedfromhere_ch2_rem_phy_lpbk_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel2_input_output_4_newaddedfromhere_ch2_rem_phy_lpbk_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel2_input_output_4_newaddedfromhere_ch2_adp_sw_rstn_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel2_input_output_4_newaddedfromhere_ch2_adp_sw_rstn_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel2_input_output_4_newaddedfromhere_ch2_mr_main_reset_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel2_input_output_4_newaddedfromhere_ch2_mr_main_reset_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel2_input_output_4_newaddedfromhere_ch2_mr_loopback_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel2_input_output_4_newaddedfromhere_ch2_mr_loopback_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel2_input_output_4_newaddedfromhere_ch2_mr_restart_an_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel2_input_output_4_newaddedfromhere_ch2_mr_restart_an_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel2_input_output_4_newaddedfromhere_ch2_speed_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel2_input_output_4_newaddedfromhere_ch2_speed_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel2_input_output_4_newaddedfromhere_ch2_mr_np_loaded_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel2_input_output_4_newaddedfromhere_ch2_mr_np_loaded_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel2_input_output_4_newaddedfromhere_ch2_force_speed_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel2_input_output_4_newaddedfromhere_ch2_force_speed_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel2_input_output_4_newaddedfromhere_ch2_mr_an_enable_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel2_input_output_4_newaddedfromhere_ch2_mr_an_enable_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel2_input_output_4_newaddedfromhere_ch2_power_on_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel2_input_output_4_newaddedfromhere_ch2_power_on_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel2_input_output_4_newaddedfromhere_ch2_mr_reg4_ch_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel2_input_output_4_newaddedfromhere_ch2_mr_reg4_ch_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel3_input_output_4_newaddedfromhere_ch3_mr_main_reset_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel3_input_output_4_newaddedfromhere_ch3_mr_main_reset_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel3_input_output_4_newaddedfromhere_ch3_speed_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel3_input_output_4_newaddedfromhere_ch3_speed_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel3_input_output_4_newaddedfromhere_ch3_mr_np_loaded_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel3_input_output_4_newaddedfromhere_ch3_mr_np_loaded_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel3_input_output_4_newaddedfromhere_ch3_adp_sw_rstn_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel3_input_output_4_newaddedfromhere_ch3_adp_sw_rstn_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel3_input_output_4_newaddedfromhere_ch3_power_on_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel3_input_output_4_newaddedfromhere_ch3_power_on_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel3_input_output_4_newaddedfromhere_ch3_mr_an_enable_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel3_input_output_4_newaddedfromhere_ch3_mr_an_enable_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel3_input_output_4_newaddedfromhere_ch3_mr_reg4_ch_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel3_input_output_4_newaddedfromhere_ch3_mr_reg4_ch_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel3_input_output_4_newaddedfromhere_ch3_mr_restart_an_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel3_input_output_4_newaddedfromhere_ch3_mr_restart_an_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel3_input_output_4_newaddedfromhere_ch3_rem_phy_lpbk_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel3_input_output_4_newaddedfromhere_ch3_rem_phy_lpbk_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel3_input_output_4_newaddedfromhere_ch3_force_speed_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel3_input_output_4_newaddedfromhere_ch3_force_speed_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel3_input_output_4_newaddedfromhere_ch3_mr_loopback_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel3_input_output_4_newaddedfromhere_ch3_mr_loopback_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel4_input_output_4_newaddedfromhere_ch4_mr_loopback_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel4_input_output_4_newaddedfromhere_ch4_mr_loopback_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel4_input_output_4_newaddedfromhere_ch4_mr_reg4_ch_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel4_input_output_4_newaddedfromhere_ch4_mr_reg4_ch_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel4_input_output_4_newaddedfromhere_ch4_mr_restart_an_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel4_input_output_4_newaddedfromhere_ch4_mr_restart_an_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel4_input_output_4_newaddedfromhere_ch4_mr_an_enable_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel4_input_output_4_newaddedfromhere_ch4_mr_an_enable_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel4_input_output_4_newaddedfromhere_ch4_force_speed_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel4_input_output_4_newaddedfromhere_ch4_force_speed_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel4_input_output_4_newaddedfromhere_ch4_mr_main_reset_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel4_input_output_4_newaddedfromhere_ch4_mr_main_reset_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel4_input_output_4_newaddedfromhere_ch4_power_on_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel4_input_output_4_newaddedfromhere_ch4_power_on_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel4_input_output_4_newaddedfromhere_ch4_speed_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel4_input_output_4_newaddedfromhere_ch4_speed_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel4_input_output_4_newaddedfromhere_ch4_rem_phy_lpbk_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel4_input_output_4_newaddedfromhere_ch4_rem_phy_lpbk_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel4_input_output_4_newaddedfromhere_ch4_mr_np_loaded_25m_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel4_input_output_4_newaddedfromhere_ch4_mr_np_loaded_25m_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_uniphy_channel4_input_output_4_newaddedfromhere_ch4_adp_sw_rstn_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_uniphy_channel4_input_output_4_newaddedfromhere_ch4_adp_sw_rstn_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_sr_xs_pcs_kr_sts1_plu_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_sr_xs_pcs_kr_sts1_plu_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_sr_xs_pcs_kr_sts1_prbs31abl_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_sr_xs_pcs_kr_sts1_prbs31abl_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_sr_xs_pcs_kr_sts1_rpcs_bklk_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_sr_xs_pcs_kr_sts1_rpcs_bklk_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_sr_xs_pcs_kr_sts1_prcs_hiber_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_sr_xs_pcs_kr_sts1_prcs_hiber_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_sr_xs_pcs_kr_sts1_prbs9abl_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_sr_xs_pcs_kr_sts1_prbs9abl_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_vr_rst_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_vr_rst_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_usra_rst_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_usra_rst_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_en_2_5g_mode_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_en_2_5g_mode_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_dskbyp_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_dskbyp_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_en_vsmmd1_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_en_vsmmd1_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_init_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_init_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_cl37_bp_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_cl37_bp_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_pwrsv_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_pwrsv_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_dtxlaned_3_1_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_dtxlaned_3_1_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_usxg_en_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_usxg_en_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_r2tlbe_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_r2tlbe_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_cr_cjn_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_cr_cjn_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_dtxlaned_0_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_dtxlaned_0_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_byp_pwrup_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_vr_xs_pcs_dig_ctrl1_byp_pwrup_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_sr_mii_ctrl_lpm_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_sr_mii_ctrl_lpm_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_sr_mii_ctrl_duplex_mode_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_sr_mii_ctrl_duplex_mode_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_sr_mii_ctrl_ss6_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_sr_mii_ctrl_ss6_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_sr_mii_ctrl_ss5_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_sr_mii_ctrl_ss5_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_sr_mii_ctrl_ss13_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_sr_mii_ctrl_ss13_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_sr_mii_ctrl_an_enable_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_sr_mii_ctrl_an_enable_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_sr_mii_ctrl_restart_an_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_sr_mii_ctrl_restart_an_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_sr_mii_ctrl_rst_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_sr_mii_ctrl_rst_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_sr_mii_ctrl_lbe_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_sr_mii_ctrl_lbe_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_vr_mii_an_ctrl_pcs_mode_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_vr_mii_an_ctrl_pcs_mode_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_vr_mii_an_ctrl_mii_an_intr_en_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_vr_mii_an_ctrl_mii_an_intr_en_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_vr_mii_an_ctrl_sgmii_link_sts_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_vr_mii_an_ctrl_sgmii_link_sts_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_vr_mii_an_ctrl_tx_config_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_vr_mii_an_ctrl_tx_config_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_vr_mii_an_ctrl_mii_ctrl_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_vr_mii_an_ctrl_mii_ctrl_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_vr_mii_an_intr_sts_usxg_an_sts_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_vr_mii_an_intr_sts_usxg_an_sts_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_vr_mii_an_intr_sts_cl37_ansgm_sts_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_vr_mii_an_intr_sts_cl37_ansgm_sts_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

sw_error_t
hppe_vr_mii_an_intr_sts_cl37_ancmplt_intr_get(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t *value);

sw_error_t
hppe_vr_mii_an_intr_sts_cl37_ancmplt_intr_set(
		a_uint32_t dev_id,
		a_uint32_t index,
		a_uint32_t value);

#endif

