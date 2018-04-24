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
#include "sw.h"
#include "hppe_uniphy_reg.h"
#include "hppe_uniphy.h"
#include "hppe_init.h"
#include "ssdk_init.h"
#include "adpt.h"

#ifdef HAWKEYE_CHIP
static sw_error_t
__adpt_hppe_uniphy_10g_r_linkup(a_uint32_t dev_id, a_uint32_t uniphy_index)
{
	a_uint32_t reg_value = 0;
	a_uint32_t retries = 100, linkup = 0;

	union sr_xs_pcs_kr_sts1_u sr_xs_pcs_kr_sts1;

	memset(&sr_xs_pcs_kr_sts1, 0, sizeof(sr_xs_pcs_kr_sts1));
	ADPT_DEV_ID_CHECK(dev_id);

	//wait 10G_R link up  to uniphy;
	while (linkup != UNIPHY_10GR_LINKUP) {
		mdelay(1);
		if (retries-- == 0)
			return SW_TIMEOUT;
		reg_value = 0;
		hppe_sr_xs_pcs_kr_sts1_get(0, uniphy_index, &sr_xs_pcs_kr_sts1);
		reg_value = sr_xs_pcs_kr_sts1.bf.plu;
		linkup = (reg_value & UNIPHY_10GR_LINKUP);
	}

	return SW_OK;
}

static sw_error_t
__adpt_hppe_uniphy_calibration(a_uint32_t dev_id, a_uint32_t uniphy_index)
{
	a_uint32_t reg_value = 0;
	a_uint32_t retries = 100, calibration_done = 0;

	union uniphy_offset_calib_4_u uniphy_offset_calib_4;

	memset(&uniphy_offset_calib_4, 0, sizeof(uniphy_offset_calib_4));
	ADPT_DEV_ID_CHECK(dev_id);

	//wait calibration done to uniphy;
	while (calibration_done != UNIPHY_CALIBRATION_DONE) {
		mdelay(1);
		if (retries-- == 0)
		{
			printk("uniphy callibration time out!\n");
			return SW_TIMEOUT;
		}
		reg_value = 0;
		hppe_uniphy_offset_calib_4_get(0, uniphy_index, &uniphy_offset_calib_4);
		reg_value = uniphy_offset_calib_4.bf.mmd1_reg_calibration_done_reg;

		calibration_done = (reg_value & UNIPHY_CALIBRATION_DONE);
	}

	return SW_OK;
}

static sw_error_t
__adpt_hppe_uniphy_usxgmii_mode_set(a_uint32_t dev_id, a_uint32_t uniphy_index)
{
	a_uint32_t reg_value, i;
	sw_error_t rv = SW_OK;

	union uniphy_mode_ctrl_u uniphy_mode_ctrl;
	union vr_xs_pcs_dig_ctrl1_u vr_xs_pcs_dig_ctrl1;
	union vr_mii_an_ctrl_u vr_mii_an_ctrl;
	union sr_mii_ctrl_u sr_mii_ctrl;

	memset(&uniphy_mode_ctrl, 0, sizeof(uniphy_mode_ctrl));
	memset(&vr_xs_pcs_dig_ctrl1, 0, sizeof(vr_xs_pcs_dig_ctrl1));
	memset(&vr_mii_an_ctrl, 0, sizeof(vr_mii_an_ctrl));
	memset(&sr_mii_ctrl, 0, sizeof(sr_mii_ctrl));
	ADPT_DEV_ID_CHECK(dev_id);

	// disable instance clock;
	for (i = 1; i < 2; i++)
	{
		qca_hppe_gcc_uniphy_port_clock_set(0, uniphy_index,
			i, A_FALSE);
	}

	// keep xpcs to reset status;
	reg_value = 0;
	qca_hppe_gcc_uniphy_reg_read(0, 0x4 + (uniphy_index * HPPE_GCC_UNIPHY_REG_INC),
		(a_uint8_t *)&reg_value, 4);
	reg_value |= 0x4;
	qca_hppe_gcc_uniphy_reg_write(0, 0x4 + (uniphy_index * HPPE_GCC_UNIPHY_REG_INC),
		(a_uint8_t *)&reg_value, 4);

	// configure uniphy to usxgmii mode;
	hppe_uniphy_mode_ctrl_get(0, uniphy_index, &uniphy_mode_ctrl);
	uniphy_mode_ctrl.bf.newaddedfromhere_ch0_psgmii_qsgmii = 0;
	uniphy_mode_ctrl.bf.newaddedfromhere_ch0_qsgmii_sgmii = 0;
	uniphy_mode_ctrl.bf.newaddedfromhere_sg_mode = 0;
	uniphy_mode_ctrl.bf.newaddedfromhere_sgplus_mode = 0;
	uniphy_mode_ctrl.bf.newaddedfromhere_xpcs_mode = 1;
	hppe_uniphy_mode_ctrl_set(0, uniphy_index, &uniphy_mode_ctrl);

	//configure uniphy usxgmii gcc software reset;
	reg_value = 0;
	qca_hppe_gcc_uniphy_reg_read(0, 0x4 + (uniphy_index * HPPE_GCC_UNIPHY_REG_INC),
		(a_uint8_t *)&reg_value, 4);
	reg_value |= HPPE_GCC_UNIPHY_USXGMII_SOFT_RESET;
	qca_hppe_gcc_uniphy_reg_write(0, 0x4 + (uniphy_index * HPPE_GCC_UNIPHY_REG_INC),
		(a_uint8_t *)&reg_value, 4);
	// release reset;
	reg_value &= ~HPPE_GCC_UNIPHY_USXGMII_SOFT_RESET;
	qca_hppe_gcc_uniphy_reg_write(0, 0x4 + (uniphy_index * HPPE_GCC_UNIPHY_REG_INC),
		(a_uint8_t *)&reg_value, 4);

	//wait calibration done to uniphy;
	rv = __adpt_hppe_uniphy_calibration(dev_id, uniphy_index);

	// enable instance clock;
	for (i = 1; i < 2; i++)
	{
		qca_hppe_gcc_uniphy_port_clock_set(0, uniphy_index,
			i, A_TRUE);
	}

	// release xpcs reset status;
	reg_value = 0;
	qca_hppe_gcc_uniphy_reg_read(0, 0x4 + (uniphy_index * HPPE_GCC_UNIPHY_REG_INC),
		(a_uint8_t *)&reg_value, 4);
	reg_value &= ~0x4;
	qca_hppe_gcc_uniphy_reg_write(0, 0x4 + (uniphy_index * HPPE_GCC_UNIPHY_REG_INC),
		(a_uint8_t *)&reg_value, 4);

	//wait 10g base_r link up;
	rv = __adpt_hppe_uniphy_10g_r_linkup(dev_id, uniphy_index);

	//enable uniphy usxgmii;
	hppe_vr_xs_pcs_dig_ctrl1_get(0, uniphy_index, &vr_xs_pcs_dig_ctrl1);
	vr_xs_pcs_dig_ctrl1.bf.usxg_en = 1;
	hppe_vr_xs_pcs_dig_ctrl1_set(0, uniphy_index, &vr_xs_pcs_dig_ctrl1);

	//enable uniphy autoneg complete interrupt and 10M/100M 8-bits MII width;
	hppe_vr_mii_an_ctrl_get(0, uniphy_index, &vr_mii_an_ctrl);
	vr_mii_an_ctrl.bf.mii_an_intr_en = 1;
	vr_mii_an_ctrl.bf.mii_ctrl = 1;
	hppe_vr_mii_an_ctrl_set(0, uniphy_index, &vr_mii_an_ctrl);

	//enable uniphy autoneg ability and usxgmii 10g speed and full duplex;
	hppe_sr_mii_ctrl_get(0, uniphy_index, &sr_mii_ctrl);
	sr_mii_ctrl.bf.an_enable = 1;
	sr_mii_ctrl.bf.ss5 = 0;
	sr_mii_ctrl.bf.ss6 = 1;
	sr_mii_ctrl.bf.ss13 = 1;
	sr_mii_ctrl.bf.duplex_mode = 1;
	hppe_sr_mii_ctrl_set(0, uniphy_index, &sr_mii_ctrl);

	return rv;
}

static sw_error_t
__adpt_hppe_uniphy_psgmii_mode_set(a_uint32_t dev_id, a_uint32_t uniphy_index)
{
	a_uint32_t reg_value, i;
	sw_error_t rv = SW_OK;

	union uniphy_mode_ctrl_u uniphy_mode_ctrl;

	memset(&uniphy_mode_ctrl, 0, sizeof(uniphy_mode_ctrl));
	ADPT_DEV_ID_CHECK(dev_id);

	// keep xpcs to reset status;
	reg_value = 0;
	qca_hppe_gcc_uniphy_reg_read(0, 0x4 + (uniphy_index * HPPE_GCC_UNIPHY_REG_INC),
		(a_uint8_t *)&reg_value, 4);
	reg_value |= 0x4;
	qca_hppe_gcc_uniphy_reg_write(0, 0x4 + (uniphy_index * HPPE_GCC_UNIPHY_REG_INC),
		(a_uint8_t *)&reg_value, 4);
	// disable instance0 clock;
	for (i = 1; i < 6; i++)
	{
		qca_hppe_gcc_uniphy_port_clock_set(0, uniphy_index,
			i, A_FALSE);
	}

	// configure uniphy to Athr mode and psgmii mode
	hppe_uniphy_mode_ctrl_get(0, uniphy_index, &uniphy_mode_ctrl);
	uniphy_mode_ctrl.bf.newaddedfromhere_ch0_athr_csco_mode_25m = 0;
	uniphy_mode_ctrl.bf.newaddedfromhere_ch0_psgmii_qsgmii = 1;
	uniphy_mode_ctrl.bf.newaddedfromhere_ch0_qsgmii_sgmii = 0;
	uniphy_mode_ctrl.bf.newaddedfromhere_sg_mode = 0;
	uniphy_mode_ctrl.bf.newaddedfromhere_sgplus_mode = 0;
	uniphy_mode_ctrl.bf.newaddedfromhere_xpcs_mode = 0;
	hppe_uniphy_mode_ctrl_set(0, uniphy_index, &uniphy_mode_ctrl);

	//configure uniphy gcc software reset;
	reg_value = 0;
	qca_hppe_gcc_uniphy_reg_read(0, 0x4 + (uniphy_index * HPPE_GCC_UNIPHY_REG_INC),
		(a_uint8_t *)&reg_value, 4);
	reg_value |= HPPE_GCC_UNIPHY_PSGMII_SOFT_RESET;
	qca_hppe_gcc_uniphy_reg_write(0, 0x4 + (uniphy_index * HPPE_GCC_UNIPHY_REG_INC),
		(a_uint8_t *)&reg_value, 4);
	// release reset;
	reg_value &= ~HPPE_GCC_UNIPHY_PSGMII_SOFT_RESET;
	qca_hppe_gcc_uniphy_reg_write(0, 0x4 + (uniphy_index * HPPE_GCC_UNIPHY_REG_INC),
		(a_uint8_t *)&reg_value, 4);

	//wait uniphy calibration done;
	rv = __adpt_hppe_uniphy_calibration(dev_id, uniphy_index);

	return rv;
}


sw_error_t
adpt_hppe_uniphy_mode_set(a_uint32_t dev_id, a_uint32_t index, a_uint32_t mode)
{
	sw_error_t rv = SW_OK;

	if (mode == PORT_WRAPPER_MAX)
		return SW_OK;

	switch(mode) {
		case PORT_WRAPPER_PSGMII:
			rv = __adpt_hppe_uniphy_psgmii_mode_set(dev_id, index);
			break;

		case PORT_WRAPPER_QSGMII:

			break;

		case PORT_WRAPPER_USXGMII:
			rv = __adpt_hppe_uniphy_usxgmii_mode_set(dev_id, index);
			break;

		default:
			break;
	}
	return rv;
}
sw_error_t adpt_hppe_uniphy_init(a_uint32_t dev_id)
{
	adpt_api_t *p_adpt_api = NULL;

	p_adpt_api = adpt_api_ptr_get(dev_id);

	if(p_adpt_api == NULL)
		return SW_FAIL;

	p_adpt_api->adpt_uniphy_mode_set = adpt_hppe_uniphy_mode_set;

	return SW_OK;
}
#endif

/**
 * @}
 */
