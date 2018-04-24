/*
 * Copyright (c) 2016-2017, The Linux Foundation. All rights reserved.
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
#include "hppe_portctrl_reg.h"
#include "hppe_portctrl.h"
#include "hppe_xgportctrl_reg.h"
#include "hppe_xgportctrl.h"
#include "hppe_uniphy_reg.h"
#include "hppe_uniphy.h"
#include "hppe_fdb_reg.h"
#include "hppe_fdb.h"
#include "hppe_global_reg.h"
#include "hppe_global.h"
#include "adpt.h"
#include "hsl.h"
#include "hsl_dev.h"
#include "hsl_port_prop.h"
#include "hsl_phy.h"
#include "hppe_init.h"
#include "ssdk_init.h"

extern a_bool_t hppe_mac_port_valid_check (fal_port_t port_id);

static a_bool_t
__adpt_hppe_port_phy_connected (a_uint32_t dev_id, fal_port_t port_id)
{
  if (0 == port_id)
    {
      return A_FALSE;
    }
  else
    {

      return hppe_mac_port_valid_check (port_id);
    }
}
static sw_error_t
__adpt_xgmac_port_rx_status_get(a_uint32_t dev_id, fal_port_t port_id, a_uint32_t* port_rxmac_status)
{
	sw_error_t rv = SW_OK;
	union mac_rx_configuration_u xgmac_rx_enable;

	memset(&xgmac_rx_enable, 0, sizeof(xgmac_rx_enable));
	port_id = HPPE_TO_XGMAC_PORT_ID(port_id);
	rv = hppe_mac_rx_configuration_get(dev_id, port_id,  &xgmac_rx_enable);
	if( rv != SW_OK )
		return rv;
	*port_rxmac_status = xgmac_rx_enable.bf.re;

	return rv;
}
static sw_error_t
__adpt_gmac_port_rx_status_get(a_uint32_t dev_id, fal_port_t port_id, a_uint32_t* port_rxmac_status)
{
	sw_error_t rv = SW_OK;
	union mac_enable_u gmac_rx_enable;

	memset(&gmac_rx_enable, 0, sizeof(gmac_rx_enable));
	port_id = HPPE_TO_GMAC_PORT_ID(port_id);
	rv = hppe_mac_enable_get(dev_id, port_id, &gmac_rx_enable);
	if( rv != SW_OK )
		return rv;
	* port_rxmac_status = gmac_rx_enable.bf.rxmac_en;

	return rv;
}

static sw_error_t
__adpt_xgmac_port_rx_status_set(a_uint32_t dev_id, fal_port_t port_id, a_bool_t enable)
{
	sw_error_t rv = SW_OK;
	union mac_rx_configuration_u xgmac_rx_enable;

	memset(&xgmac_rx_enable, 0, sizeof(xgmac_rx_enable));
	port_id = HPPE_TO_XGMAC_PORT_ID(port_id);
	rv |=  hppe_mac_rx_configuration_get(dev_id, port_id,  &xgmac_rx_enable);
	if (A_TRUE == enable)
		 xgmac_rx_enable.bf.re = 1;
	if (A_FALSE == enable)
		 xgmac_rx_enable.bf.re= 0;
	rv |= hppe_mac_rx_configuration_set(dev_id, port_id, &xgmac_rx_enable);

	return rv;
}

static sw_error_t
__adpt_gmac_port_rx_status_set(a_uint32_t dev_id, fal_port_t port_id, a_bool_t enable)
{
	sw_error_t rv = SW_OK;
	union mac_enable_u gmac_rx_enable;

	memset(&gmac_rx_enable, 0, sizeof(gmac_rx_enable));
	port_id = HPPE_TO_GMAC_PORT_ID(port_id);
	rv |= hppe_mac_enable_get(dev_id, port_id, &gmac_rx_enable);
	if (A_TRUE == enable)
		gmac_rx_enable.bf.rxmac_en = 1;
	if (A_FALSE == enable)
		gmac_rx_enable.bf.rxmac_en = 0;
	rv |= hppe_mac_enable_set(dev_id, port_id, &gmac_rx_enable);

	return rv;
}

static sw_error_t
__adpt_xgmac_port_tx_status_get(a_uint32_t dev_id, fal_port_t port_id, a_uint32_t *port_txmac_status)
{
	sw_error_t rv = SW_OK;
	union mac_tx_configuration_u xgmac_tx_enable;

	memset(&xgmac_tx_enable, 0, sizeof(xgmac_tx_enable));
	port_id = HPPE_TO_XGMAC_PORT_ID(port_id);
	rv = hppe_mac_tx_configuration_get(dev_id, port_id,  &xgmac_tx_enable);
	if( rv != SW_OK )
		return  rv;
	*port_txmac_status = xgmac_tx_enable.bf.te;

	return SW_OK;
}

static sw_error_t
__adpt_gmac_port_tx_status_get(a_uint32_t dev_id, fal_port_t port_id, a_uint32_t *port_txmac_status)
{
	sw_error_t rv = SW_OK;
	union mac_enable_u gmac_tx_enable;

	memset(&gmac_tx_enable, 0, sizeof(gmac_tx_enable));
	port_id = HPPE_TO_GMAC_PORT_ID(port_id);
	rv = hppe_mac_enable_get(dev_id, port_id, &gmac_tx_enable);
	if( rv != SW_OK )
		return  rv;
	*port_txmac_status = gmac_tx_enable.bf.txmac_en;

	return SW_OK;
}
static sw_error_t
__adpt_xgmac_port_tx_status_set (a_uint32_t dev_id, fal_port_t port_id, a_bool_t enable)
{
	sw_error_t rv = SW_OK;
	union mac_tx_configuration_u xgmac_tx_enable;

	memset(&xgmac_tx_enable, 0, sizeof(xgmac_tx_enable));
	port_id = HPPE_TO_XGMAC_PORT_ID(port_id);
	 rv |=hppe_mac_tx_configuration_get(dev_id, port_id,  &xgmac_tx_enable);
	 if (A_TRUE == enable)
		 xgmac_tx_enable.bf.te = 1;
	 if (A_FALSE == enable)
		 xgmac_tx_enable.bf.te = 0;
	 rv |= hppe_mac_tx_configuration_set(dev_id, port_id, &xgmac_tx_enable);

	 return SW_OK;
}

static sw_error_t
__adpt_gmac_port_tx_status_set (a_uint32_t dev_id, fal_port_t port_id, a_bool_t enable)
{
	sw_error_t rv = SW_OK;
	union mac_enable_u gmac_tx_enable;

	memset(&gmac_tx_enable, 0, sizeof(gmac_tx_enable));
	port_id = HPPE_TO_GMAC_PORT_ID(port_id);
	rv |= hppe_mac_enable_get(dev_id, port_id, &gmac_tx_enable);
	if (A_TRUE == enable)
		gmac_tx_enable.bf.txmac_en = 1;
	if (A_FALSE == enable)
		gmac_tx_enable.bf.txmac_en = 0;
	rv |= hppe_mac_enable_set(dev_id, port_id, &gmac_tx_enable);

	return SW_OK;
}

static sw_error_t
__adpt_xgmac_port_txfc_status_get(a_uint32_t dev_id, fal_port_t port_id, a_uint32_t* txfc_status)
{
	sw_error_t rv = SW_OK;
	union mac_q0_tx_flow_ctrl_u xgmac_txfc_enable;

	memset(&xgmac_txfc_enable, 0, sizeof(xgmac_txfc_enable));
	port_id = HPPE_TO_XGMAC_PORT_ID(port_id);
	rv = hppe_mac_q0_tx_flow_ctrl_get(dev_id, port_id, &xgmac_txfc_enable);
	if( rv != SW_OK )
		return rv;
	*txfc_status = xgmac_txfc_enable.bf.tfe;

	return  SW_OK;
}

static sw_error_t
__adpt_gmac_port_txfc_status_get(a_uint32_t dev_id, fal_port_t port_id, a_uint32_t* txfc_status)
{
	sw_error_t rv = SW_OK;
	union mac_enable_u gmac_txfc_enable;

	memset(&gmac_txfc_enable, 0, sizeof(gmac_txfc_enable));
	port_id = HPPE_TO_GMAC_PORT_ID(port_id);
	rv = hppe_mac_enable_get(dev_id, port_id, &gmac_txfc_enable);
	if( rv != SW_OK )
		return rv;
	*txfc_status = gmac_txfc_enable.bf.tx_flow_en;

	return  SW_OK;
}
static sw_error_t
__adpt_xgmac_port_txfc_status_set(a_uint32_t dev_id, fal_port_t port_id,  a_bool_t enable)
{
	sw_error_t rv = SW_OK;
	union mac_q0_tx_flow_ctrl_u xgmac_txfc_enable;

	memset(&xgmac_txfc_enable, 0, sizeof(xgmac_txfc_enable));
	port_id = HPPE_TO_XGMAC_PORT_ID(port_id);
	rv |= hppe_mac_q0_tx_flow_ctrl_get(dev_id, port_id,  &xgmac_txfc_enable);
	if (A_TRUE == enable)
		xgmac_txfc_enable.bf.tfe = 1;
	if (A_FALSE == enable)
		xgmac_txfc_enable.bf.tfe = 0;
	 rv |= hppe_mac_q0_tx_flow_ctrl_set(dev_id, port_id,  &xgmac_txfc_enable);

	 return SW_OK;
}

static sw_error_t
__adpt_gmac_port_txfc_status_set(a_uint32_t dev_id, fal_port_t port_id,  a_bool_t enable)
{
	sw_error_t rv = SW_OK;
	union mac_enable_u gmac_txfc_enable;

	memset(&gmac_txfc_enable, 0, sizeof(gmac_txfc_enable));
	port_id = HPPE_TO_GMAC_PORT_ID(port_id);
	rv |= hppe_mac_enable_get(dev_id, port_id, &gmac_txfc_enable);
	if (A_TRUE == enable)
		gmac_txfc_enable.bf.tx_flow_en = 1;
	if (A_FALSE == enable)
		gmac_txfc_enable.bf.tx_flow_en = 0;
	rv |= hppe_mac_enable_set(dev_id, port_id, &gmac_txfc_enable);

	return SW_OK;
}
static sw_error_t
__adpt_xgmac_port_rxfc_status_get(a_uint32_t dev_id, fal_port_t port_id,  a_uint32_t* rxfc_status)
{
	sw_error_t rv = SW_OK;
	union mac_rx_flow_ctrl_u xgmac_rxfc_enable;

	memset(&xgmac_rxfc_enable, 0, sizeof(xgmac_rxfc_enable));
	port_id = HPPE_TO_XGMAC_PORT_ID(port_id);
	rv = hppe_mac_rx_flow_ctrl_get(dev_id, port_id, &xgmac_rxfc_enable);
	if(rv != SW_OK)
		return rv;
	*rxfc_status = xgmac_rxfc_enable.bf.rfe;

	return  SW_OK;
}

static sw_error_t
__adpt_gmac_port_rxfc_status_get(a_uint32_t dev_id, fal_port_t port_id, a_uint32_t* rxfc_status)
{
	sw_error_t rv = SW_OK;
	union mac_enable_u gmac_rxfc_enable;

	memset(&gmac_rxfc_enable, 0, sizeof(gmac_rxfc_enable));
	port_id = HPPE_TO_GMAC_PORT_ID(port_id);
	rv = hppe_mac_enable_get(dev_id, port_id, &gmac_rxfc_enable);
	if( rv != SW_OK)
		return rv;
	*rxfc_status = gmac_rxfc_enable.bf.rx_flow_en;

	return SW_OK;
}
static sw_error_t
__adpt_xgmac_port_rxfc_status_set(a_uint32_t dev_id,fal_port_t port_id, a_bool_t enable)
{
	sw_error_t rv = SW_OK;
	union mac_rx_flow_ctrl_u xgmac_rxfc_enable;

	memset(&xgmac_rxfc_enable, 0, sizeof(xgmac_rxfc_enable));
	port_id = HPPE_TO_XGMAC_PORT_ID(port_id);
	rv |= hppe_mac_rx_flow_ctrl_get(dev_id, port_id, &xgmac_rxfc_enable);
	if (A_TRUE == enable)
		xgmac_rxfc_enable.bf.rfe= 1;
	if (A_FALSE == enable)
		xgmac_rxfc_enable.bf.rfe = 0;
	rv |= hppe_mac_rx_flow_ctrl_set(dev_id, port_id, &xgmac_rxfc_enable);

	return SW_OK;
}

static sw_error_t
__adpt_gmac_port_rxfc_status_set(a_uint32_t dev_id,fal_port_t port_id, a_bool_t enable)
{
	sw_error_t rv = SW_OK;
	union mac_enable_u gmac_rxfc_enable;

	memset(&gmac_rxfc_enable, 0, sizeof(gmac_rxfc_enable));
	port_id = HPPE_TO_GMAC_PORT_ID(port_id);
	rv |= hppe_mac_enable_get(dev_id, port_id, &gmac_rxfc_enable);
	if (A_TRUE == enable)
		gmac_rxfc_enable.bf.rx_flow_en = 1;
	if (A_FALSE == enable)
		gmac_rxfc_enable.bf.rx_flow_en = 0;
	rv |= hppe_mac_enable_set(dev_id, port_id, &gmac_rxfc_enable);

	return SW_OK;
}

sw_error_t
adpt_hppe_port_local_loopback_get(a_uint32_t dev_id, fal_port_t port_id,
					a_bool_t * enable)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(enable);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_local_loopback_get)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_local_loopback_get (dev_id, phy_id, enable);

	return rv;

}

sw_error_t
adpt_hppe_port_autoneg_restart(a_uint32_t dev_id, fal_port_t port_id)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_restart_autoneg)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_restart_autoneg (dev_id, phy_id);
	return rv;

}
sw_error_t
adpt_hppe_port_duplex_set(a_uint32_t dev_id, fal_port_t port_id,
				fal_port_duplex_t duplex)
{
	union mac_enable_u mac_enable;
	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	memset(&mac_enable, 0, sizeof(mac_enable));
	ADPT_DEV_ID_CHECK(dev_id);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_INCL_CPU))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_duplex_set)
		return SW_NOT_SUPPORTED;

	if (FAL_DUPLEX_BUTT <= duplex)
	{
		return SW_BAD_PARAM;
	}
	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_duplex_set (dev_id, phy_id, duplex);
	SW_RTN_ON_ERROR (rv);

#if 0
	port_id = port_id - 1;
	hppe_mac_enable_get(dev_id, port_id, &mac_enable);

	if (FAL_HALF_DUPLEX == duplex)
		mac_enable.bf.duplex = 0;
	if (FAL_FULL_DUPLEX == duplex)
		mac_enable.bf.duplex = 1;

	hppe_mac_enable_set(dev_id, port_id, &mac_enable);

#endif

	return rv;
}
sw_error_t
adpt_hppe_port_rxmac_status_get(a_uint32_t dev_id, fal_port_t port_id,
				      a_bool_t * enable)
{
	sw_error_t rv = SW_OK;
	a_uint32_t port_rxmac_status = 0, port_mac_type;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(enable);

	port_mac_type = qca_hppe_port_mac_type_get(dev_id, port_id);
	if (port_mac_type == HPPE_PORT_XGMAC_TYPE)
		__adpt_xgmac_port_rx_status_get( dev_id, port_id, &port_rxmac_status);
	else if (port_mac_type == HPPE_PORT_GMAC_TYPE)
		 __adpt_gmac_port_rx_status_get( dev_id, port_id, &port_rxmac_status);
	else
		return SW_BAD_VALUE;

	if (port_rxmac_status)
		*enable = A_TRUE;
	else
		*enable = A_FALSE;

	return rv;
}

sw_error_t
adpt_hppe_port_cdt(a_uint32_t dev_id, fal_port_t port_id,
		a_uint32_t mdi_pair, fal_cable_status_t * cable_status,
		a_uint32_t * cable_len)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(cable_status);
	ADPT_NULL_POINT_CHECK(cable_len);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_cdt)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_cdt (dev_id, phy_id, mdi_pair, cable_status, cable_len);

	return rv;

}
sw_error_t
adpt_hppe_port_txmac_status_set(a_uint32_t dev_id, fal_port_t port_id,
				      a_bool_t enable)
{
	a_uint32_t port_mac_type;

	ADPT_DEV_ID_CHECK(dev_id);

	port_mac_type =qca_hppe_port_mac_type_get(dev_id, port_id);
	if (port_mac_type == HPPE_PORT_XGMAC_TYPE)
		__adpt_xgmac_port_tx_status_set( dev_id, port_id, enable);
	else if (port_mac_type == HPPE_PORT_GMAC_TYPE)
		__adpt_gmac_port_tx_status_set( dev_id, port_id, enable);
	else
		return SW_BAD_VALUE;

	return SW_OK;
}
sw_error_t
adpt_hppe_port_combo_fiber_mode_set(a_uint32_t dev_id,
						  a_uint32_t port_id,
						  fal_port_fiber_mode_t mode)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_combo_fiber_mode_set)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_combo_fiber_mode_set (dev_id, phy_id, mode);

	return rv;

}
sw_error_t
adpt_hppe_port_combo_medium_status_get(a_uint32_t dev_id,
						     a_uint32_t port_id,
						     fal_port_medium_t *
						     medium)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(medium);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_combo_medium_status_get)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_combo_medium_status_get (dev_id, phy_id, medium);

	return rv;

}

sw_error_t
adpt_hppe_port_magic_frame_mac_set(a_uint32_t dev_id, fal_port_t port_id,
				   fal_mac_addr_t * mac)
{
	sw_error_t rv;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(mac);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_magic_frame_mac_set)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_magic_frame_mac_set (dev_id, phy_id,mac);

	return rv;

}
sw_error_t
adpt_hppe_port_powersave_set(a_uint32_t dev_id, fal_port_t port_id,
			  a_bool_t enable)
{
	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_powersave_set)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_powersave_set (dev_id, phy_id, enable);

	return rv;

}
sw_error_t
adpt_hppe_port_hibernate_set(a_uint32_t dev_id, fal_port_t port_id,
			  a_bool_t enable)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_hibernation_set)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_hibernation_set (dev_id, phy_id, enable);

	return rv;

}
sw_error_t
adpt_hppe_port_max_frame_size_set(a_uint32_t dev_id, fal_port_t port_id,
		a_uint32_t max_frame)
{
	union mac_ctrl2_u mac_ctrl2;

	memset(&mac_ctrl2, 0, sizeof(mac_ctrl2));
	ADPT_DEV_ID_CHECK(dev_id);

	port_id = port_id -1;
	hppe_mac_ctrl2_get(dev_id, port_id, &mac_ctrl2);
	mac_ctrl2.bf.maxfr = max_frame;
	hppe_mac_ctrl2_set(dev_id, port_id, &mac_ctrl2);
	return SW_OK;
}

sw_error_t
adpt_hppe_port_8023az_get(a_uint32_t dev_id, fal_port_t port_id,
				a_bool_t * enable)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(enable);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_8023az_get)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_8023az_get (dev_id, phy_id, enable);

	return rv;

}

sw_error_t
adpt_hppe_port_rxfc_status_get(a_uint32_t dev_id, fal_port_t port_id,
				     a_bool_t * enable)
{
	sw_error_t rv = SW_OK;
	a_uint32_t rxfc_status = 0, port_mac_type;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(enable);

	port_mac_type =qca_hppe_port_mac_type_get(dev_id, port_id);
	if (port_mac_type == HPPE_PORT_XGMAC_TYPE)
		__adpt_xgmac_port_rxfc_status_get( dev_id, port_id, &rxfc_status);
	else if (port_mac_type == HPPE_PORT_GMAC_TYPE)
		__adpt_gmac_port_rxfc_status_get( dev_id, port_id, &rxfc_status);
	else
		return SW_BAD_VALUE;

	if (rxfc_status)
		*enable = A_TRUE;
	else
		*enable = A_FALSE;

	return rv;
}

sw_error_t
adpt_hppe_port_txfc_status_get(a_uint32_t dev_id, fal_port_t port_id,
				     a_bool_t * enable)
{
	a_uint32_t txfc_status = 0, port_mac_type;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(enable);

	port_mac_type =qca_hppe_port_mac_type_get(dev_id, port_id);
	if (port_mac_type == HPPE_PORT_XGMAC_TYPE)
		__adpt_xgmac_port_txfc_status_get( dev_id, port_id, &txfc_status);
	else if (port_mac_type == HPPE_PORT_GMAC_TYPE)
		__adpt_gmac_port_txfc_status_get( dev_id, port_id, &txfc_status);
	else
		return SW_BAD_VALUE;

	if (txfc_status)
		*enable = A_TRUE;
	else
		*enable = A_FALSE;

	return SW_OK;
}

sw_error_t
adpt_hppe_port_remote_loopback_set(a_uint32_t dev_id, fal_port_t port_id,
					 a_bool_t enable)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_remote_loopback_set)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_remote_loopback_set (dev_id, phy_id, enable);

	return rv;

}

sw_error_t
adpt_hppe_port_mru_set(a_uint32_t dev_id, fal_port_t port_id,
		fal_mru_ctrl_t *ctrl)
{
	union mru_mtu_ctrl_tbl_u mru_mtu_ctrl_tbl;

	memset(&mru_mtu_ctrl_tbl, 0, sizeof(mru_mtu_ctrl_tbl));
	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(ctrl);

	hppe_mru_mtu_ctrl_tbl_get(dev_id, port_id, &mru_mtu_ctrl_tbl);
	mru_mtu_ctrl_tbl.bf.mru = ctrl->mru_size;
	mru_mtu_ctrl_tbl.bf.mru_cmd = (a_uint32_t)ctrl->action;

	return hppe_mru_mtu_ctrl_tbl_set(dev_id, port_id, &mru_mtu_ctrl_tbl);
}
sw_error_t
adpt_hppe_port_autoneg_status_get(a_uint32_t dev_id, fal_port_t port_id,
					a_bool_t * status)
{

	a_uint32_t phy_id = 0;
	sw_error_t rv = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(status);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_autoneg_status_get)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	*status = phy_drv->phy_autoneg_status_get (dev_id, phy_id);

	return SW_OK;

}

sw_error_t
adpt_hppe_port_txmac_status_get(a_uint32_t dev_id, fal_port_t port_id,
				      a_bool_t * enable)
{
	sw_error_t rv = SW_OK;
	a_uint32_t port_txmac_status = 0, port_mac_type;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(enable);

	port_mac_type =qca_hppe_port_mac_type_get(dev_id, port_id);
	if (port_mac_type == HPPE_PORT_XGMAC_TYPE)
		__adpt_xgmac_port_tx_status_get( dev_id, port_id, &port_txmac_status);
	else if (port_mac_type == HPPE_PORT_GMAC_TYPE)
		__adpt_gmac_port_tx_status_get( dev_id, port_id, &port_txmac_status);
	else
		return SW_BAD_VALUE;

	if (port_txmac_status)
		*enable = A_TRUE;
	else
		*enable = A_FALSE;

	return rv;
}

sw_error_t
adpt_hppe_port_mdix_get(a_uint32_t dev_id, fal_port_t port_id,
			      fal_port_mdix_mode_t * mode)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(mode);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_mdix_get)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_mdix_get (dev_id, phy_id, mode);

	return rv;

}

sw_error_t
adpt_hppe_ports_link_status_get(a_uint32_t dev_id, a_uint32_t * status)
{

	sw_error_t rv = 0;
	a_uint32_t port_id;
	a_uint32_t phy_id;
	hsl_dev_t *pdev = NULL;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(status);

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_link_status_get)
		return SW_NOT_SUPPORTED;

	pdev = hsl_dev_ptr_get(dev_id);
	if (pdev == NULL)
		return SW_NOT_INITIALIZED;

	*status = 0x0;
	for (port_id = 0; port_id < pdev->nr_ports; port_id++)
	{
		/* for those ports without PHY device supposed always link up */
		if (A_FALSE == __adpt_hppe_port_phy_connected(dev_id, port_id))
		{
			*status |= (0x1 << port_id);
		}
		else
		{
			rv = hsl_port_prop_get_phyid(dev_id, port_id, &phy_id);
			SW_RTN_ON_ERROR(rv);

			if (A_TRUE == phy_drv->phy_link_status_get (dev_id, phy_id))
			{
				*status |= (0x1 << port_id);
			}
			else
			{
				*status &= ~(0x1 << port_id);
			}
		}
	}
	return SW_OK;

}

sw_error_t
adpt_hppe_port_mac_loopback_set(a_uint32_t dev_id, fal_port_t port_id,
				 a_bool_t enable)
{
	union mac_ctrl2_u mac_ctrl2;

	memset(&mac_ctrl2, 0, sizeof(mac_ctrl2));
	ADPT_DEV_ID_CHECK(dev_id);

	port_id = port_id - 1;
	hppe_mac_ctrl2_get(dev_id, port_id, &mac_ctrl2);

	if (A_TRUE == enable)
		mac_ctrl2.bf.mac_loop_back = 1;
	if (A_FALSE== enable)
		mac_ctrl2.bf.mac_loop_back = 0;

	hppe_mac_ctrl2_set(dev_id, port_id, &mac_ctrl2);

	return SW_OK;
}
sw_error_t
adpt_hppe_port_phy_id_get(a_uint32_t dev_id, fal_port_t port_id,
		      a_uint16_t * org_id, a_uint16_t * rev_id)
{
	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(org_id);
	ADPT_NULL_POINT_CHECK(rev_id);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	{
		return SW_BAD_PARAM;
	}

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_id_get)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	 rv = phy_drv->phy_id_get (dev_id, phy_id,org_id,rev_id);

	return rv;

}

sw_error_t
adpt_hppe_port_mru_get(a_uint32_t dev_id, fal_port_t port_id,
		fal_mru_ctrl_t *ctrl)
{
	sw_error_t rv = SW_OK;
	union mru_mtu_ctrl_tbl_u mru_mtu_ctrl_tbl;

	memset(&mru_mtu_ctrl_tbl, 0, sizeof(mru_mtu_ctrl_tbl));
	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(ctrl);


	rv = hppe_mru_mtu_ctrl_tbl_get(dev_id, port_id, &mru_mtu_ctrl_tbl);

	if( rv != SW_OK )
		return rv;

	ctrl->mru_size = mru_mtu_ctrl_tbl.bf.mru;
	ctrl->action = (fal_fwd_cmd_t)mru_mtu_ctrl_tbl.bf.mru_cmd;

	return SW_OK;
}

sw_error_t
adpt_hppe_port_power_on(a_uint32_t dev_id, fal_port_t port_id)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_power_on)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_power_on(dev_id, phy_id);

	return rv;

}
sw_error_t
adpt_hppe_port_speed_set(a_uint32_t dev_id, fal_port_t port_id,
			       fal_port_speed_t speed)
{
	union mac_speed_u mac_speed;
	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	memset(&mac_speed, 0, sizeof(mac_speed));
	ADPT_DEV_ID_CHECK(dev_id);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_INCL_CPU))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_speed_set)
		return SW_NOT_SUPPORTED;

	if (FAL_SPEED_1000 < speed)
	  {
		return SW_BAD_PARAM;
	  }

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_speed_set (dev_id, phy_id, speed);
	SW_RTN_ON_ERROR (rv);

#if 0
	port_id = port_id - 1;
	hppe_mac_speed_get(dev_id, port_id, &mac_speed);

	if(FAL_SPEED_1000 == speed)
		mac_speed.bf.mac_speed = 2;
	if(FAL_SPEED_100 == speed)
		mac_speed.bf.mac_speed = 1;
	if(FAL_SPEED_10 == speed)
		mac_speed.bf.mac_speed = 0;

	hppe_mac_speed_set(dev_id, port_id, &mac_speed);
#endif

	return rv;
}
sw_error_t
adpt_hppe_port_interface_mode_get(a_uint32_t dev_id, fal_port_t port_id,
			      fal_port_interface_mode_t * mode)
{
	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(mode);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_interface_mode_get)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_interface_mode_get (dev_id, phy_id,mode);

	return rv;

}

sw_error_t
adpt_hppe_port_duplex_get(a_uint32_t dev_id, fal_port_t port_id,
				fal_port_duplex_t * pduplex)
{
	union mac_enable_u mac_enable;
	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	memset(&mac_enable, 0, sizeof(mac_enable));
	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(pduplex);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_INCL_CPU))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_duplex_get)
		return SW_NOT_SUPPORTED;

	/* for those ports without PHY device supposed always full duplex */
	if (A_FALSE == __adpt_hppe_port_phy_connected (dev_id, port_id))
	{
		*pduplex = FAL_FULL_DUPLEX;
	}
	else
	{
		rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
		SW_RTN_ON_ERROR (rv);
		rv = phy_drv->phy_duplex_get (dev_id, phy_id, pduplex);
		SW_RTN_ON_ERROR (rv);
	}

#if 0
	port_id = port_id - 1;
	rv = hppe_mac_enable_get(dev_id, port_id, &mac_enable);

	if( rv != SW_OK )
		return rv;

	if (mac_enable.bf.duplex == 0)
		*pduplex = FAL_HALF_DUPLEX;
	if (mac_enable.bf.duplex == 1)
		*pduplex = FAL_FULL_DUPLEX;

#endif

	return rv;
}

sw_error_t
adpt_hppe_port_autoneg_adv_get(a_uint32_t dev_id, fal_port_t port_id,
				     a_uint32_t * autoadv)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(autoadv);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_autoneg_adv_get)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	*autoadv = 0;
	rv = phy_drv->phy_autoneg_adv_get (dev_id, phy_id, autoadv);
	SW_RTN_ON_ERROR (rv);

	return SW_OK;

}

sw_error_t
adpt_hppe_port_mdix_status_get(a_uint32_t dev_id, fal_port_t port_id,
				     fal_port_mdix_status_t * mode)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(mode);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_mdix_status_get)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_mdix_status_get (dev_id, phy_id, mode);

	return rv;

}

sw_error_t
adpt_hppe_port_mtu_set(a_uint32_t dev_id, fal_port_t port_id,
		fal_mtu_ctrl_t *ctrl)
{
	union mru_mtu_ctrl_tbl_u mru_mtu_ctrl_tbl;
	union mac_jumbo_size_u mac_jumbo_ctrl;
	union mc_mtu_ctrl_tbl_u mc_mtu_ctrl_tb;

	memset(&mru_mtu_ctrl_tbl, 0, sizeof(mru_mtu_ctrl_tbl));
	memset(&mac_jumbo_ctrl, 0, sizeof(mac_jumbo_ctrl));
	memset(&mc_mtu_ctrl_tb, 0, sizeof(mc_mtu_ctrl_tb));
	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(ctrl);

	if ((port_id > 0) && (port_id < 7))
	{
		hppe_mac_jumbo_size_get(dev_id, port_id - 1, &mac_jumbo_ctrl);
		mac_jumbo_ctrl.bf.mac_jumbo_size = ctrl->mtu_size;
		hppe_mac_jumbo_size_set(dev_id, port_id - 1, &mac_jumbo_ctrl);
	}

	hppe_mru_mtu_ctrl_tbl_get(dev_id, port_id, &mru_mtu_ctrl_tbl);
	mru_mtu_ctrl_tbl.bf.mtu = ctrl->mtu_size;
	mru_mtu_ctrl_tbl.bf.mtu_cmd = (a_uint32_t)ctrl->action;
	hppe_mru_mtu_ctrl_tbl_set(dev_id, port_id, &mru_mtu_ctrl_tbl);

	if ((port_id >= 0) && (port_id <= 7))
	{
		hppe_mc_mtu_ctrl_tbl_get(dev_id, port_id, &mc_mtu_ctrl_tb);
		mc_mtu_ctrl_tb.bf.mtu = ctrl->mtu_size;
		mc_mtu_ctrl_tb.bf.mtu_cmd = (a_uint32_t)ctrl->action;
		hppe_mc_mtu_ctrl_tbl_set(dev_id, port_id, &mc_mtu_ctrl_tb);
	}

	return SW_OK;
}
sw_error_t
adpt_hppe_port_link_status_get(a_uint32_t dev_id, fal_port_t port_id,
				     a_bool_t * status)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(status);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_INCL_CPU))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_link_status_get)
	  return SW_NOT_SUPPORTED;

	/* for those ports without PHY device supposed always link up */
	if (A_FALSE == __adpt_hppe_port_phy_connected (dev_id, port_id))
	  {
		*status = A_TRUE;
	  }
	else
	  {
		rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
		SW_RTN_ON_ERROR (rv);

		if (A_TRUE == phy_drv->phy_link_status_get (dev_id, phy_id))
		{
			*status = A_TRUE;
		}
		else
		{
			*status = A_FALSE;
		}
	  }

	return SW_OK;

}

sw_error_t
adpt_hppe_port_8023az_set(a_uint32_t dev_id, fal_port_t port_id,
				a_bool_t enable)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_8023az_set)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_8023az_set (dev_id, phy_id, enable);

	return rv;

}
sw_error_t
adpt_hppe_port_powersave_get(a_uint32_t dev_id, fal_port_t port_id,
			  a_bool_t * enable)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(enable);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_powersave_get)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_powersave_get (dev_id, phy_id, enable);

	return rv;

}

sw_error_t
adpt_hppe_port_combo_prefer_medium_get(a_uint32_t dev_id,
						     a_uint32_t port_id,
						     fal_port_medium_t *
						     medium)
{
	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(medium);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_combo_prefer_medium_get)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_combo_prefer_medium_get (dev_id, phy_id, medium);

	return rv;

}
sw_error_t
adpt_hppe_port_max_frame_size_get(a_uint32_t dev_id, fal_port_t port_id,
		a_uint32_t *max_frame)
{
	sw_error_t rv = SW_OK;
	union mac_ctrl2_u mac_ctrl2;

	memset(&mac_ctrl2, 0, sizeof(mac_ctrl2));
	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(max_frame);


	rv = hppe_mac_ctrl2_get(dev_id, port_id, &mac_ctrl2);

	if( rv != SW_OK )
		return rv;

	*max_frame = mac_ctrl2.bf.maxfr;

	return SW_OK;
}

sw_error_t
adpt_hppe_port_combo_prefer_medium_set(a_uint32_t dev_id,
					     a_uint32_t port_id,
					     fal_port_medium_t medium)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_combo_prefer_medium_set)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_combo_prefer_medium_set (dev_id, phy_id, medium);

	return rv;

}
sw_error_t
adpt_hppe_port_power_off(a_uint32_t dev_id, fal_port_t port_id)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_power_off)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_power_off(dev_id, phy_id);

	return rv;

}
sw_error_t
adpt_hppe_port_txfc_status_set(a_uint32_t dev_id, fal_port_t port_id,
				     a_bool_t enable)
{
	a_uint32_t port_mac_type;

	ADPT_DEV_ID_CHECK(dev_id);

	port_mac_type =qca_hppe_port_mac_type_get(dev_id, port_id);
	if (port_mac_type == HPPE_PORT_XGMAC_TYPE)
		__adpt_xgmac_port_txfc_status_set( dev_id, port_id, enable);
	else if (port_mac_type == HPPE_PORT_GMAC_TYPE)
		__adpt_gmac_port_txfc_status_set( dev_id, port_id, enable);
	else
		return SW_BAD_VALUE;

	return SW_OK;
}
sw_error_t
adpt_hppe_port_counter_set(a_uint32_t dev_id, fal_port_t port_id,
		   a_bool_t enable)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_counter_set)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_counter_set (dev_id, phy_id, enable);

	return rv;
}
sw_error_t
adpt_hppe_port_combo_fiber_mode_get(a_uint32_t dev_id,
						  a_uint32_t port_id,
						  fal_port_fiber_mode_t * mode)
{
	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(mode);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
	  	return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_combo_fiber_mode_get)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_combo_fiber_mode_get (dev_id, phy_id, mode);

	return rv;

}

sw_error_t
adpt_hppe_port_local_loopback_set(a_uint32_t dev_id,
						fal_port_t port_id,
						a_bool_t enable)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_local_loopback_set)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_local_loopback_set (dev_id, phy_id, enable);

	return rv;

}
sw_error_t
adpt_hppe_port_wol_status_set(a_uint32_t dev_id, fal_port_t port_id,
			      a_bool_t enable)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	{
		return SW_BAD_PARAM;
	}

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_wol_status_set)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_wol_status_set (dev_id, phy_id, enable);

	return rv;


}
sw_error_t
adpt_hppe_port_magic_frame_mac_get(a_uint32_t dev_id, fal_port_t port_id,
				   fal_mac_addr_t * mac)
{

	sw_error_t rv;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(mac);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_magic_frame_mac_get)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_magic_frame_mac_get (dev_id, phy_id,mac);

	return rv;

}

sw_error_t
adpt_hppe_port_flowctrl_get(a_uint32_t dev_id, fal_port_t port_id,
				  a_bool_t * enable)
{
	sw_error_t rv = SW_OK;
	a_bool_t txfc_enable, rxfc_enable;

	rv = adpt_hppe_port_txfc_status_get(dev_id, port_id,  &txfc_enable);
	rv |= adpt_hppe_port_rxfc_status_get(dev_id, port_id,  &rxfc_enable);
	if(rv != SW_OK)
		return rv;
	*enable = txfc_enable & rxfc_enable;

	return SW_OK;
}

sw_error_t
adpt_hppe_port_rxmac_status_set(a_uint32_t dev_id, fal_port_t port_id,
				      a_bool_t enable)
{
	a_uint32_t port_mac_type;

	ADPT_DEV_ID_CHECK(dev_id);

	port_mac_type =qca_hppe_port_mac_type_get(dev_id, port_id);
	if (port_mac_type == HPPE_PORT_XGMAC_TYPE)
		__adpt_xgmac_port_rx_status_set(dev_id, port_id, enable);
	else if (port_mac_type == HPPE_PORT_GMAC_TYPE)
		__adpt_gmac_port_rx_status_set(dev_id, port_id, enable);
	else
		return SW_BAD_VALUE;

	return SW_OK;
}
sw_error_t
adpt_hppe_port_counter_get(a_uint32_t dev_id, fal_port_t port_id,
		   a_bool_t * enable)
{

	sw_error_t rv;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(enable);

	 if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	   {
		return SW_BAD_PARAM;
	   }

	 SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	 if (NULL == phy_drv->phy_counter_get)
		return SW_NOT_SUPPORTED;

	 rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	 SW_RTN_ON_ERROR (rv);

	 rv = phy_drv->phy_counter_get (dev_id, phy_id, enable);

	 return rv;

}

sw_error_t
adpt_hppe_port_interface_mode_set(a_uint32_t dev_id, fal_port_t port_id,
			      fal_port_interface_mode_t mode)
{

	sw_error_t rv;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_interface_mode_set)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_interface_mode_set (dev_id, phy_id,mode);

	return rv;

}
sw_error_t
adpt_hppe_port_mac_loopback_get(a_uint32_t dev_id, fal_port_t port_id,
				 a_bool_t * enable)
{
	sw_error_t rv = SW_OK;
	union mac_ctrl2_u mac_ctrl2;

	memset(&mac_ctrl2, 0, sizeof(mac_ctrl2));
	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(enable);

	port_id = port_id - 1;
	rv = hppe_mac_ctrl2_get(dev_id, port_id, &mac_ctrl2);

	if( rv != SW_OK )
		return rv;

	*enable = mac_ctrl2.bf.mac_loop_back;

	return SW_OK;
}

sw_error_t
adpt_hppe_port_hibernate_get(a_uint32_t dev_id, fal_port_t port_id,
			  a_bool_t * enable)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(enable);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_hibernation_get)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_hibernation_get (dev_id, phy_id, enable);

	return rv;

}

sw_error_t
adpt_hppe_port_autoneg_adv_set(a_uint32_t dev_id, fal_port_t port_id,
				     a_uint32_t autoadv)
{
	sw_error_t rv = 0;
	a_uint32_t phy_id;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_autoneg_adv_set)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_autoneg_adv_set (dev_id, phy_id, autoadv);
	SW_RTN_ON_ERROR (rv);

	return SW_OK;

}
sw_error_t
adpt_hppe_port_remote_loopback_get(a_uint32_t dev_id, fal_port_t port_id,
					 a_bool_t * enable)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(enable);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_remote_loopback_get)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_remote_loopback_get (dev_id, phy_id, enable);

	return rv;

}

sw_error_t
adpt_hppe_port_counter_show(a_uint32_t dev_id, fal_port_t port_id,
				 fal_port_counter_info_t * counter_info)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(counter_info);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_counter_show)
	  return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_counter_show (dev_id, phy_id,counter_info);

	return rv;

}
sw_error_t
adpt_hppe_port_autoneg_enable(a_uint32_t dev_id, fal_port_t port_id)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_autoneg_enable_set)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_autoneg_enable_set (dev_id, phy_id);
	return rv;

}
sw_error_t
adpt_hppe_port_mtu_get(a_uint32_t dev_id, fal_port_t port_id,
		fal_mtu_ctrl_t *ctrl)
{
	sw_error_t rv = SW_OK;
	union mru_mtu_ctrl_tbl_u mru_mtu_ctrl_tbl;

	memset(&mru_mtu_ctrl_tbl, 0, sizeof(mru_mtu_ctrl_tbl));
	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(ctrl);

	rv = hppe_mru_mtu_ctrl_tbl_get(dev_id, port_id, &mru_mtu_ctrl_tbl);

	if( rv != SW_OK )
		return rv;

	ctrl->mtu_size = mru_mtu_ctrl_tbl.bf.mtu;
	ctrl->action = (fal_fwd_cmd_t)mru_mtu_ctrl_tbl.bf.mtu_cmd;

	return SW_OK;
}

sw_error_t
adpt_hppe_port_interface_mode_status_get(a_uint32_t dev_id, fal_port_t port_id,
			      fal_port_interface_mode_t * mode)
{

	sw_error_t rv;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(mode);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_interface_mode_status_get)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_interface_mode_status_get (dev_id, phy_id,mode);

	return rv;

}

sw_error_t
adpt_hppe_port_reset(a_uint32_t dev_id, fal_port_t port_id)
{

	sw_error_t rv;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_reset)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_reset(dev_id, phy_id);

	return rv;

}
sw_error_t
adpt_hppe_port_rxfc_status_set(a_uint32_t dev_id, fal_port_t port_id,
				     a_bool_t enable)
{
	a_uint32_t port_mac_type;

	ADPT_DEV_ID_CHECK(dev_id);

	port_mac_type =qca_hppe_port_mac_type_get(dev_id, port_id);
	if(port_mac_type == HPPE_PORT_XGMAC_TYPE)
		__adpt_xgmac_port_rxfc_status_set( dev_id, port_id, enable);
	else if (port_mac_type == HPPE_PORT_GMAC_TYPE)
		__adpt_gmac_port_rxfc_status_set( dev_id, port_id, enable);
	else
		return SW_BAD_VALUE;

	return SW_OK;
}
sw_error_t
adpt_hppe_port_flowctrl_set(a_uint32_t dev_id, fal_port_t port_id,
				  a_bool_t enable)
{
	sw_error_t rv = SW_OK;

	rv = adpt_hppe_port_txfc_status_set(dev_id, port_id, enable);
	rv |= adpt_hppe_port_rxfc_status_set(dev_id, port_id, enable);
	if(rv != SW_OK)
		return rv;

	return SW_OK;
}
sw_error_t
adpt_hppe_port_speed_get(a_uint32_t dev_id, fal_port_t port_id,
			       fal_port_speed_t * pspeed)
{
	sw_error_t rv = 0;
	union mac_speed_u mac_speed;
	a_uint32_t phy_id;
	hsl_phy_ops_t *phy_drv;

	memset(&mac_speed, 0, sizeof(mac_speed));
	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(pspeed);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_INCL_CPU))
	{
		return SW_BAD_PARAM;
	}

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_speed_get)
		return SW_NOT_SUPPORTED;

	/* for those ports without PHY device supposed always 1000Mbps */
	if (A_FALSE == __adpt_hppe_port_phy_connected (dev_id, port_id))
	{
		*pspeed = FAL_SPEED_1000;
	}
	else
	{
		rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
		SW_RTN_ON_ERROR (rv);
		rv = phy_drv->phy_speed_get (dev_id, phy_id, pspeed);
		SW_RTN_ON_ERROR (rv);
	}


#if 0
	port_id = port_id - 1;
	rv = hppe_mac_speed_get(dev_id, port_id, &mac_speed);

	if( rv != SW_OK )
		return rv;

	if (mac_speed.bf.mac_speed == 0)
		*pspeed = FAL_SPEED_10;
	if (mac_speed.bf.mac_speed == 1)
		*pspeed = FAL_SPEED_100;
	if (mac_speed.bf.mac_speed == 2)
		*pspeed = FAL_SPEED_1000;
#endif

	return rv;
}

sw_error_t
adpt_hppe_port_mdix_set(a_uint32_t dev_id, fal_port_t port_id,
			      fal_port_mdix_mode_t mode)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	  {
		return SW_BAD_PARAM;
	  }

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_mdix_set)
		return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_mdix_set (dev_id, phy_id, mode);

	return rv;

}
sw_error_t
adpt_hppe_port_wol_status_get(a_uint32_t dev_id, fal_port_t port_id,
			      a_bool_t * enable)
{

	sw_error_t rv = 0;
	a_uint32_t phy_id = 0;
	hsl_phy_ops_t *phy_drv;

	ADPT_DEV_ID_CHECK(dev_id);
	ADPT_NULL_POINT_CHECK(enable);

	if (A_TRUE != hsl_port_prop_check (dev_id, port_id, HSL_PP_PHY))
	{
		return SW_BAD_PARAM;
	}

	SW_RTN_ON_NULL (phy_drv = hsl_phy_api_ops_get (dev_id));
	if (NULL == phy_drv->phy_wol_status_get)
	  return SW_NOT_SUPPORTED;

	rv = hsl_port_prop_get_phyid (dev_id, port_id, &phy_id);
	SW_RTN_ON_ERROR (rv);

	rv = phy_drv->phy_wol_status_get (dev_id, phy_id, enable);

	return rv;

}


sw_error_t
adpt_hppe_port_source_filter_get(a_uint32_t dev_id,
				fal_port_t port_id, a_bool_t * enable)
{
	sw_error_t rv = SW_OK;
	union port_in_forward_u port_in_forward = {0};

	ADPT_DEV_ID_CHECK(dev_id);

	rv = hppe_port_in_forward_get(dev_id, port_id, &port_in_forward);

	if (rv != SW_OK)
		return rv;

	if (port_in_forward.bf.source_filtering_bypass == A_TRUE)
		*enable = A_FALSE;
	else
		*enable = A_TRUE;

	return SW_OK;
}

sw_error_t
adpt_hppe_port_source_filter_set(a_uint32_t dev_id,
				fal_port_t port_id, a_bool_t enable)
{
	union port_in_forward_u port_in_forward = {0};

	ADPT_DEV_ID_CHECK(dev_id);

	if (enable == A_TRUE)
		port_in_forward.bf.source_filtering_bypass = A_FALSE;
	else
		port_in_forward.bf.source_filtering_bypass = A_TRUE;

	return hppe_port_in_forward_set(dev_id, port_id, &port_in_forward);
}
#ifdef HAWKEYE_CHIP
static sw_error_t
adpt_hppe_port_bridge_txmac_set(a_uint32_t dev_id, fal_port_t port_id, a_bool_t enable)
{
	sw_error_t rv = SW_OK;
	union port_bridge_ctrl_u port_bridge_ctrl = {0};

	ADPT_DEV_ID_CHECK(dev_id);

	rv = hppe_port_bridge_ctrl_get(dev_id, port_id, &port_bridge_ctrl);

	if( rv != SW_OK )
		return rv;

	if(enable == A_TRUE)
		port_bridge_ctrl.bf.txmac_en= 1;
	else
		port_bridge_ctrl.bf.txmac_en= 0;

	return hppe_port_bridge_ctrl_set(dev_id, port_id, &port_bridge_ctrl);
}
#endif
static sw_error_t
__adpt_hppe_gmac_speed_set(a_uint32_t dev_id, a_uint32_t port_id, fal_port_speed_t speed)
{
	sw_error_t rv = SW_OK;
	union mac_speed_u mac_speed;

	memset(&mac_speed, 0, sizeof(mac_speed));
	ADPT_DEV_ID_CHECK(dev_id);

	port_id = HPPE_TO_GMAC_PORT_ID(port_id);
	hppe_mac_speed_get(dev_id, port_id, &mac_speed);

	if(FAL_SPEED_10 == speed)
		mac_speed.bf.mac_speed = 0;
	else if(FAL_SPEED_100 == speed)
		mac_speed.bf.mac_speed = 1;
	else if(FAL_SPEED_1000 == speed)
		mac_speed.bf.mac_speed = 2;

	rv = hppe_mac_speed_set(dev_id, port_id, &mac_speed);

	return rv;
}

static sw_error_t
__adpt_hppe_xgmac_speed_set(a_uint32_t dev_id, a_uint32_t port_id, fal_port_speed_t speed)
{
	sw_error_t rv = SW_OK;
	union mac_tx_configuration_u mac_tx_configuration;
	a_uint32_t mode;

	memset(&mac_tx_configuration, 0, sizeof(mac_tx_configuration));
	ADPT_DEV_ID_CHECK(dev_id);

	port_id = HPPE_TO_XGMAC_PORT_ID(port_id);
	hppe_mac_tx_configuration_get(dev_id, port_id, &mac_tx_configuration);

	if(FAL_SPEED_1000 == speed)
	{
		mac_tx_configuration.bf.uss= 0;
		mac_tx_configuration.bf.ss= 3;
	}
	else if(FAL_SPEED_10000 == speed)
	{
		if (port_id == 0)
		{
			mode = ssdk_dt_global_get_mac_mode(HPPE_UNIPHY_INSTANCE1);
		}
		else
		{
			mode = ssdk_dt_global_get_mac_mode(HPPE_UNIPHY_INSTANCE2);
		}
		if (mode == PORT_WRAPPER_USXGMII)
		{
			mac_tx_configuration.bf.uss= 1;
			mac_tx_configuration.bf.ss= 0;
		}
		else
		{
			mac_tx_configuration.bf.uss= 0;
			mac_tx_configuration.bf.ss= 0;
		}
	}
	else if(FAL_SPEED_5000 == speed)
	{
		mac_tx_configuration.bf.uss= 1;
		mac_tx_configuration.bf.ss= 1;
	}
	else if(FAL_SPEED_2500 == speed)
	{
		if (port_id == 0)
		{
			mode = ssdk_dt_global_get_mac_mode(HPPE_UNIPHY_INSTANCE1);
		}
		else
		{
			mode = ssdk_dt_global_get_mac_mode(HPPE_UNIPHY_INSTANCE2);
		}
		if (mode == PORT_WRAPPER_USXGMII)
		{
			mac_tx_configuration.bf.uss= 1;
			mac_tx_configuration.bf.ss= 2;
		}
		else
		{
			mac_tx_configuration.bf.uss= 0;
			mac_tx_configuration.bf.ss= 2;
		}
	}
	else if(FAL_SPEED_100 == speed)
	{
		mac_tx_configuration.bf.uss= 0;
		mac_tx_configuration.bf.ss= 3;
	}
	else if(FAL_SPEED_10 == speed)
	{
		mac_tx_configuration.bf.uss= 0;
		mac_tx_configuration.bf.ss= 3;
	}

	rv = hppe_mac_tx_configuration_set(dev_id, port_id, &mac_tx_configuration);

	return rv;
}

static sw_error_t
__adpt_hppe_gmac_duplex_set(a_uint32_t dev_id, a_uint32_t port_id, fal_port_duplex_t duplex)
{
	sw_error_t rv = SW_OK;
	union mac_enable_u mac_enable;

	memset(&mac_enable, 0, sizeof(mac_enable));
	ADPT_DEV_ID_CHECK(dev_id);

	port_id = HPPE_TO_GMAC_PORT_ID(port_id);
	hppe_mac_enable_get(dev_id, port_id, &mac_enable);

	if (FAL_FULL_DUPLEX == duplex)
		mac_enable.bf.duplex = 1;
	else
		mac_enable.bf.duplex = 0;

	rv = hppe_mac_enable_set(dev_id, port_id, &mac_enable);

	return rv;
}

sw_error_t
adpt_hppe_port_mac_duplex_set(a_uint32_t dev_id, a_uint32_t port_id, fal_port_duplex_t duplex)
{
	sw_error_t rv = SW_OK;
	a_uint32_t port_mac_type;

	port_mac_type = qca_hppe_port_mac_type_get(dev_id, port_id);
	if (port_mac_type == HPPE_PORT_XGMAC_TYPE)
	{
		return rv;
	}
	else if (port_mac_type == HPPE_PORT_GMAC_TYPE)
	{
		rv = __adpt_hppe_gmac_duplex_set(dev_id, port_id, duplex);
	}
	else
	{
		return SW_BAD_VALUE;
	}

	return rv;
}

sw_error_t
adpt_hppe_port_mux_set(a_uint32_t dev_id, fal_port_t port_id, a_uint32_t port_type)
{
	sw_error_t rv = SW_OK;
	union port_mux_ctrl_u port_mux_ctrl;
	a_uint32_t mode, mode1;

	memset(&port_mux_ctrl, 0, sizeof(port_mux_ctrl));
	ADPT_DEV_ID_CHECK(dev_id);

	rv = hppe_port_mux_ctrl_get(dev_id, &port_mux_ctrl);
	port_mux_ctrl.bf.port4_pcs_sel = 1;

	if (port_id == HPPE_MUX_PORT1)
	{
		if (port_type == HPPE_PORT_GMAC_TYPE)
		{
			mode = ssdk_dt_global_get_mac_mode(HPPE_UNIPHY_INSTANCE0);
			mode1 = ssdk_dt_global_get_mac_mode(HPPE_UNIPHY_INSTANCE1);
			if ((mode == PORT_WRAPPER_PSGMII) || (mode == PORT_WRAPPER_SGMII4_RGMII4))
			{
				port_mux_ctrl.bf.port5_pcs_sel = 1;
				port_mux_ctrl.bf.port5_gmac_sel = 1;
			}
			else if (mode1 == PORT_WRAPPER_SGMII0_RGMII4)
			{
				port_mux_ctrl.bf.port5_pcs_sel = 2;
				port_mux_ctrl.bf.port5_gmac_sel = 1;
			}
		}
		else if (port_type == HPPE_PORT_XGMAC_TYPE)
		{
			port_mux_ctrl.bf.port5_pcs_sel = 2;
			port_mux_ctrl.bf.port5_gmac_sel = 0;
		}
	}
	else if (port_id == HPPE_MUX_PORT2)
	{
		if (port_type == HPPE_PORT_GMAC_TYPE)
		{
			port_mux_ctrl.bf.port6_pcs_sel = 1;
			port_mux_ctrl.bf.port6_gmac_sel = 1;
		}
		else if (port_type == HPPE_PORT_XGMAC_TYPE)
		{
			port_mux_ctrl.bf.port6_pcs_sel = 1;
			port_mux_ctrl.bf.port6_gmac_sel = 0;
		}
	}
	else
	{
		return SW_OK;
	}
	rv = hppe_port_mux_ctrl_set(dev_id, &port_mux_ctrl);

	return rv;
}
sw_error_t
adpt_hppe_port_mac_speed_set(a_uint32_t dev_id, a_uint32_t port_id,
				fal_port_speed_t speed)
{
	sw_error_t rv = SW_OK;
	a_uint32_t port_mac_type;

	port_mac_type = qca_hppe_port_mac_type_get(dev_id, port_id);
	if (port_mac_type == HPPE_PORT_XGMAC_TYPE)
	{
		rv = __adpt_hppe_xgmac_speed_set(dev_id, port_id, speed);

	}
	else if (port_mac_type == HPPE_PORT_GMAC_TYPE)
	{
		rv = __adpt_hppe_gmac_speed_set(dev_id, port_id, speed);
	}
	else
	{
		return SW_BAD_VALUE;
	}
	return rv;
}

#if 0
static sw_error_t
adpt_hppe_port_mac_select(a_uint32_t dev_id, a_uint32_t port_id,
				a_uint32_t speed)
{
	sw_error_t rv = SW_OK;
	a_uint32_t port_mac_type, mode;

	if (port_id == HPPE_MUX_PORT2)
	{
		mode = ssdk_dt_global_get_mac_mode(HPPE_UNIPHY_INSTANCE2);
		if (mode == PORT_WRAPPER_USXGMII)
		{
			port_mac_type = __adpt_hppe_port_mac_type_get(port_id);
			if (speed < FAL_SPEED_1000)
			{
				//select gmac;
				if (port_mac_type != HPPE_PORT_GMAC_TYPE)
				{
					rv = adpt_hppe_port_mux_set(0, 0x3b);
				}
				hppe_port_type[1] = HPPE_PORT_GMAC_TYPE;
			}
			else
			{
				//select xgmac;
				if (port_mac_type != HPPE_PORT_XGMAC_TYPE)
				{
					rv = adpt_hppe_port_mux_set(0, 0x1b);
				}
				hppe_port_type[1] = HPPE_PORT_XGMAC_TYPE;
			}
		}
	}

	return rv;
}
#endif
#ifdef HAWKEYE_CHIP
static void
adpt_hppe_uniphy_psgmii_port_reset(a_uint32_t dev_id, a_uint32_t uniphy_index,
			a_uint32_t port_id)
{
	union uniphy_channel0_input_output_4_u uniphy_channel0_input_output_4;
	union uniphy_channel1_input_output_4_u uniphy_channel1_input_output_4;
	union uniphy_channel2_input_output_4_u uniphy_channel2_input_output_4;
	union uniphy_channel3_input_output_4_u uniphy_channel3_input_output_4;
	union uniphy_channel4_input_output_4_u uniphy_channel4_input_output_4;

	memset(&uniphy_channel0_input_output_4, 0, sizeof(uniphy_channel0_input_output_4));
	memset(&uniphy_channel1_input_output_4, 0, sizeof(uniphy_channel1_input_output_4));
	memset(&uniphy_channel2_input_output_4, 0, sizeof(uniphy_channel2_input_output_4));
	memset(&uniphy_channel3_input_output_4, 0, sizeof(uniphy_channel3_input_output_4));
	memset(&uniphy_channel4_input_output_4, 0, sizeof(uniphy_channel4_input_output_4));

	if (port_id == 1)
	{
		hppe_uniphy_channel0_input_output_4_get(0, uniphy_index, &uniphy_channel0_input_output_4);
		uniphy_channel0_input_output_4.bf.newaddedfromhere_ch0_adp_sw_rstn = 0;
		hppe_uniphy_channel0_input_output_4_set(0, uniphy_index, &uniphy_channel0_input_output_4);
		uniphy_channel0_input_output_4.bf.newaddedfromhere_ch0_adp_sw_rstn = 1;
		hppe_uniphy_channel0_input_output_4_set(0, uniphy_index, &uniphy_channel0_input_output_4);
	}
	else if (port_id == 2)
	{
		hppe_uniphy_channel1_input_output_4_get(0, uniphy_index, &uniphy_channel1_input_output_4);
		uniphy_channel1_input_output_4.bf.newaddedfromhere_ch1_adp_sw_rstn = 0;
		hppe_uniphy_channel1_input_output_4_set(0, uniphy_index, &uniphy_channel1_input_output_4);
		uniphy_channel1_input_output_4.bf.newaddedfromhere_ch1_adp_sw_rstn = 1;
		hppe_uniphy_channel1_input_output_4_set(0, uniphy_index, &uniphy_channel1_input_output_4);
	}
	else if (port_id == 3)
	{
		hppe_uniphy_channel2_input_output_4_get(0, uniphy_index, &uniphy_channel2_input_output_4);
		uniphy_channel2_input_output_4.bf.newaddedfromhere_ch2_adp_sw_rstn = 0;
		hppe_uniphy_channel2_input_output_4_set(0, uniphy_index, &uniphy_channel2_input_output_4);
		uniphy_channel2_input_output_4.bf.newaddedfromhere_ch2_adp_sw_rstn = 1;
		hppe_uniphy_channel2_input_output_4_set(0, uniphy_index, &uniphy_channel2_input_output_4);
	}
	else if (port_id == 4)
	{
		hppe_uniphy_channel3_input_output_4_get(0, uniphy_index, &uniphy_channel3_input_output_4);
		uniphy_channel3_input_output_4.bf.newaddedfromhere_ch3_adp_sw_rstn = 0;
		hppe_uniphy_channel3_input_output_4_set(0, uniphy_index, &uniphy_channel3_input_output_4);
		uniphy_channel3_input_output_4.bf.newaddedfromhere_ch3_adp_sw_rstn = 1;
		hppe_uniphy_channel3_input_output_4_set(0, uniphy_index, &uniphy_channel3_input_output_4);
	}
	else if (port_id == 5)
	{
		hppe_uniphy_channel4_input_output_4_get(0, uniphy_index, &uniphy_channel4_input_output_4);
		uniphy_channel4_input_output_4.bf.newaddedfromhere_ch4_adp_sw_rstn = 0;
		hppe_uniphy_channel4_input_output_4_set(0, uniphy_index, &uniphy_channel4_input_output_4);
		uniphy_channel4_input_output_4.bf.newaddedfromhere_ch4_adp_sw_rstn = 1;
		hppe_uniphy_channel4_input_output_4_set(0, uniphy_index, &uniphy_channel4_input_output_4);
	}

	return;
}
static void
adpt_hppe_uniphy_usxgmii_port_reset(a_uint32_t dev_id, a_uint32_t uniphy_index,
			a_uint32_t port_id)
{
	union vr_xs_pcs_dig_ctrl1_u vr_xs_pcs_dig_ctrl1;

	memset(&vr_xs_pcs_dig_ctrl1, 0, sizeof(vr_xs_pcs_dig_ctrl1));

	hppe_vr_xs_pcs_dig_ctrl1_get(0, uniphy_index, &vr_xs_pcs_dig_ctrl1);
	vr_xs_pcs_dig_ctrl1.bf.usra_rst = 1;
	hppe_vr_xs_pcs_dig_ctrl1_set(0, uniphy_index, &vr_xs_pcs_dig_ctrl1);

	return;
}
static void
adpt_hppe_uniphy_port_adapter_reset(a_uint32_t dev_id, a_uint32_t port_id)
{
	a_uint32_t uniphy_index, mode;

	if (port_id < HPPE_MUX_PORT1)
	{
		uniphy_index = HPPE_UNIPHY_INSTANCE0;
		adpt_hppe_uniphy_psgmii_port_reset(0, uniphy_index,
						port_id);
	}
	else
	{
		if (port_id == HPPE_MUX_PORT1)
		{
			mode = ssdk_dt_global_get_mac_mode(HPPE_UNIPHY_INSTANCE0);
			if ((mode == PORT_WRAPPER_PSGMII) || (mode == PORT_WRAPPER_SGMII4_RGMII4))
			{
				uniphy_index = HPPE_UNIPHY_INSTANCE0;
				adpt_hppe_uniphy_psgmii_port_reset(0, uniphy_index,
						port_id);
				return;
			}
			else
				uniphy_index = HPPE_UNIPHY_INSTANCE1;
		}
		else
			uniphy_index = HPPE_UNIPHY_INSTANCE2;

		mode = ssdk_dt_global_get_mac_mode(uniphy_index);

		if ((mode == PORT_WRAPPER_SGMII_PLUS) || (mode == PORT_WRAPPER_SGMII0_RGMII4))
		{
			/* only reset channel 0 */
			adpt_hppe_uniphy_psgmii_port_reset(0, uniphy_index, 1);
		}
		else if (mode == PORT_WRAPPER_USXGMII)
		{
			adpt_hppe_uniphy_usxgmii_port_reset(0, uniphy_index,
						port_id);
		}
	}

	return;
}
static void
adpt_hppe_uniphy_usxgmii_speed_set(a_uint32_t dev_id, a_uint32_t uniphy_index,
				fal_port_speed_t speed)
{
	union sr_mii_ctrl_u sr_mii_ctrl;
	memset(&sr_mii_ctrl, 0, sizeof(sr_mii_ctrl));

	hppe_sr_mii_ctrl_get(0, uniphy_index, &sr_mii_ctrl);
	sr_mii_ctrl.bf.duplex_mode = 1;
	if (speed == FAL_SPEED_10)
	{
		sr_mii_ctrl.bf.ss5 = 0;
		sr_mii_ctrl.bf.ss6 = 0;
		sr_mii_ctrl.bf.ss13 = 0;
	}
	else if (speed == FAL_SPEED_100)
	{
		sr_mii_ctrl.bf.ss5 = 0;
		sr_mii_ctrl.bf.ss6 = 0;
		sr_mii_ctrl.bf.ss13 = 1;
	}
	else if (speed == FAL_SPEED_1000)
	{
		sr_mii_ctrl.bf.ss5 = 0;
		sr_mii_ctrl.bf.ss6 = 1;
		sr_mii_ctrl.bf.ss13 = 0;
	}
	else if (speed == FAL_SPEED_10000)
	{
		sr_mii_ctrl.bf.ss5 = 0;
		sr_mii_ctrl.bf.ss6 = 1;
		sr_mii_ctrl.bf.ss13 = 1;
	}
	else if (speed == FAL_SPEED_2500)
	{
		sr_mii_ctrl.bf.ss5 = 1;
		sr_mii_ctrl.bf.ss6 = 0;
		sr_mii_ctrl.bf.ss13 = 0;
	}
	else if (speed == FAL_SPEED_5000)
	{
		sr_mii_ctrl.bf.ss5 = 1;
		sr_mii_ctrl.bf.ss6 = 0;
		sr_mii_ctrl.bf.ss13 = 1;
	}
	hppe_sr_mii_ctrl_set(0, uniphy_index, &sr_mii_ctrl);

	return;
}
static void
adpt_hppe_uniphy_usxgmii_duplex_set(a_uint32_t dev_id, a_uint32_t uniphy_index,
				fal_port_duplex_t duplex)
{
	union sr_mii_ctrl_u sr_mii_ctrl;
	memset(&sr_mii_ctrl, 0, sizeof(sr_mii_ctrl));

	hppe_sr_mii_ctrl_get(0, uniphy_index, &sr_mii_ctrl);

	if (duplex == FAL_FULL_DUPLEX)
		sr_mii_ctrl.bf.duplex_mode = 1;
	else
		sr_mii_ctrl.bf.duplex_mode = 0;

	hppe_sr_mii_ctrl_set(0, uniphy_index, &sr_mii_ctrl);

	return;
}
sw_error_t
adpt_hppe_uniphy_usxgmii_autoneg_completed(a_uint32_t dev_id,
				a_uint32_t uniphy_index)
{
	a_uint32_t autoneg_complete = 0, retries = 100;
	union vr_mii_an_intr_sts_u vr_mii_an_intr_sts;

	memset(&vr_mii_an_intr_sts, 0, sizeof(vr_mii_an_intr_sts));

	// swith uniphy xpcs auto-neg complete and clear interrupt
	while (autoneg_complete != 0x1) {
		mdelay(1);
		if (retries-- == 0)
		{
			printk("uniphy autoneg time out!\n");
			return SW_TIMEOUT;
		}
		hppe_vr_mii_an_intr_sts_get(0, uniphy_index, &vr_mii_an_intr_sts);
		autoneg_complete = vr_mii_an_intr_sts.bf.cl37_ancmplt_intr;
	}

	vr_mii_an_intr_sts.bf.cl37_ancmplt_intr = 0;
	hppe_vr_mii_an_intr_sts_set(0, uniphy_index, &vr_mii_an_intr_sts);

	return SW_OK;
}
static void
adpt_hppe_uniphy_speed_set(a_uint32_t dev_id, a_uint32_t port_id, fal_port_speed_t speed)
{
	a_uint32_t uniphy_index, mode;

	if (port_id == HPPE_MUX_PORT1)
		uniphy_index = HPPE_UNIPHY_INSTANCE1;
	else if (port_id == HPPE_MUX_PORT2)
		uniphy_index = HPPE_UNIPHY_INSTANCE2;

	mode = ssdk_dt_global_get_mac_mode(uniphy_index);
	if (mode == PORT_WRAPPER_USXGMII)
	{
		adpt_hppe_uniphy_usxgmii_autoneg_completed(0,uniphy_index);
		/* configure xpcs speed at usxgmii mode */
		adpt_hppe_uniphy_usxgmii_speed_set(0, uniphy_index, speed);
	}

	return;
}
static void
adpt_hppe_uniphy_duplex_set(a_uint32_t dev_id, a_uint32_t port_id, fal_port_duplex_t duplex)
{
	a_uint32_t uniphy_index, mode;

	if (port_id == HPPE_MUX_PORT1)
		uniphy_index = HPPE_UNIPHY_INSTANCE1;
	else if (port_id == HPPE_MUX_PORT2)
		uniphy_index = HPPE_UNIPHY_INSTANCE2;

	mode = ssdk_dt_global_get_mac_mode(uniphy_index);
	if (mode == PORT_WRAPPER_USXGMII)
	{
		/* adpt_hppe_uniphy_usxgmii_autoneg_completed(0,uniphy_index); */
		/* configure xpcs duplex at usxgmii mode */
		adpt_hppe_uniphy_usxgmii_duplex_set(0, uniphy_index, duplex);
	}

	return;
}
static void
adpt_hppe_uniphy_autoneg_status_check(a_uint32_t dev_id, a_uint32_t port_id)
{
	a_uint32_t uniphy_index, mode;

	if (port_id == HPPE_MUX_PORT1)
		uniphy_index = HPPE_UNIPHY_INSTANCE1;
	else if (port_id == HPPE_MUX_PORT2)
		uniphy_index = HPPE_UNIPHY_INSTANCE2;

	mode = ssdk_dt_global_get_mac_mode(uniphy_index);
	if (mode == PORT_WRAPPER_USXGMII)
	{
		adpt_hppe_uniphy_usxgmii_autoneg_completed(0,uniphy_index);;
	}
	return;
}
#endif
void adpt_hppe_port_ctrl_func_bitmap_init(a_uint32_t dev_id)
{
	adpt_api_t *p_adpt_api = NULL;

	p_adpt_api = adpt_api_ptr_get(dev_id);

	if(p_adpt_api == NULL)
		return;

	p_adpt_api->adpt_port_ctrl_func_bitmap[0] = ((1 << FUNC_ADPT_PORT_LOCAL_LOOPBACK_GET)|
						(1 << FUNC_ADPT_PORT_AUTONEG_RESTART)|
						(1 << FUNC_ADPT_PORT_DUPLEX_SET)|
						(1 << FUNC_ADPT_PORT_RXMAC_STATUS_GET)|
						(1 << FUNC_ADPT_PORT_CDT)|
						(1 << FUNC_ADPT_PORT_TXMAC_STATUS_SET)|
						(1 << FUNC_ADPT_PORT_COMBO_FIBER_MODE_SET)|
						(1 << FUNC_ADPT_PORT_COMBO_MEDIUM_STATUS_GET)|
						(1 << FUNC_ADPT_PORT_MAGIC_FRAME_MAC_SET)|
						(1 << FUNC_ADPT_PORT_POWERSAVE_SET)|
						(1 << FUNC_ADPT_PORT_HIBERNATE_SET)|
						(1 << FUNC_ADPT_PORT_8023AZ_GET)|
						(1 << FUNC_ADPT_PORT_RXFC_STATUS_GET)|
						(1 << FUNC_ADPT_PORT_TXFC_STATUS_GET)|
						(1 << FUNC_ADPT_PORT_REMOTE_LOOPBACK_SET)|
						(1 << FUNC_ADPT_PORT_FLOWCTRL_SET)|
						(1 << FUNC_ADPT_PORT_MRU_SET)|
						(1 << FUNC_ADPT_PORT_AUTONEG_STATUS_GET)|
						(1 << FUNC_ADPT_PORT_TXMAC_STATUS_GET)|
						(1 << FUNC_ADPT_PORT_MDIX_GET)|
						(1 << FUNC_ADPT_PORTS_LINK_STATUS_GET)|
						(1 << FUNC_ADPT_PORT_MAC_LOOPBACK_SET)|
						(1 << FUNC_ADPT_PORT_PHY_ID_GET)|
						(1 << FUNC_ADPT_PORT_MRU_GET)|
						(1 << FUNC_ADPT_PORT_POWER_ON)|
						(1 << FUNC_ADPT_PORT_SPEED_SET)|
						(1 << FUNC_ADPT_PORT_INTERFACE_MODE_GET)|
						(1 << FUNC_ADPT_PORT_DUPLEX_GET)|
						(1 << FUNC_ADPT_PORT_AUTONEG_ADV_GET)|
						(1 << FUNC_ADPT_PORT_MDIX_STATUS_GET)|
						(1 << FUNC_ADPT_PORT_MTU_SET)|
						(1 << FUNC_ADPT_PORT_LINK_STATUS_GET));


	p_adpt_api->adpt_port_ctrl_func_bitmap[1] = ((1 << (FUNC_ADPT_PORT_8023AZ_SET % 32))|
						(1 << (FUNC_ADPT_PORT_POWERSAVE_GET % 32))|
						(1 << (FUNC_ADPT_PORT_COMBO_PREFER_MEDIUM_GET % 32))|
						(1 << (FUNC_ADPT_PORT_COMBO_PREFER_MEDIUM_SET % 32))|
						(1 << (FUNC_ADPT_PORT_POWER_OFF % 32))|
						(1 << (FUNC_ADPT_PORT_TXFC_STATUS_SET % 32))|
						(1 << (FUNC_ADPT_PORT_COUNTER_SET % 32))|
						(1 << (FUNC_ADPT_PORT_COMBO_FIBER_MODE_GET % 32))|
						(1 << (FUNC_ADPT_PORT_LOCAL_LOOPBACK_SET % 32))|
						(1 << (FUNC_ADPT_PORT_WOL_STATUS_SET % 32))|
						(1 << (FUNC_ADPT_PORT_MAGIC_FRAME_MAC_GET % 32))|
						(1 << (FUNC_ADPT_PORT_FLOWCTRL_GET % 32))|
						(1 << (FUNC_ADPT_PORT_RXMAC_STATUS_SET % 32))|
						(1 << (FUNC_ADPT_PORT_COUNTER_GET % 32))|
						(1 << (FUNC_ADPT_PORT_INTERFACE_MODE_SET % 32))|
						(1 << (FUNC_ADPT_PORT_MAC_LOOPBACK_GET % 32))|
						(1 << (FUNC_ADPT_PORT_HIBERNATE_GET % 32))|
						(1 << (FUNC_ADPT_PORT_AUTONEG_ADV_SET % 32))|
						(1 << (FUNC_ADPT_PORT_REMOTE_LOOPBACK_GET % 32))|
						(1 << (FUNC_ADPT_PORT_COUNTER_SHOW % 32))|
						(1 << (FUNC_ADPT_PORT_AUTONEG_ENABLE % 32))|
						(1 << (FUNC_ADPT_PORT_MTU_GET % 32))|
						(1 << (FUNC_ADPT_PORT_INTERFACE_MODE_STATUS_GET % 32))|
						(1 << (FUNC_ADPT_PORT_RESET % 32))|
						(1 << (FUNC_ADPT_PORT_RXFC_STATUS_SET % 32))|
						(1 << (FUNC_ADPT_PORT_SPEED_GET % 32))|
						(1 << (FUNC_ADPT_PORT_MDIX_SET % 32))|
						(1 << (FUNC_ADPT_PORT_WOL_STATUS_GET % 32))|
						(1 << (FUNC_ADPT_PORT_MAX_FRAME_SIZE_SET % 32))|
						(1 << (FUNC_ADPT_PORT_MAX_FRAME_SIZE_GET % 32))|
						(1 << (FUNC_ADPT_PORT_SOURCE_FILTER_GET % 32))|
						(1 << (FUNC_ADPT_PORT_SOURCE_FILTER_SET % 32)));

	return;

}

static void adpt_hppe_port_ctrl_func_unregister(a_uint32_t dev_id, adpt_api_t *p_adpt_api)
{
	if(p_adpt_api == NULL)
		return;

	p_adpt_api->adpt_port_local_loopback_get = NULL;
	p_adpt_api->adpt_port_autoneg_restart = NULL;
	p_adpt_api->adpt_port_duplex_set = NULL;
	p_adpt_api->adpt_port_rxmac_status_get = NULL;
	p_adpt_api->adpt_port_cdt = NULL;
	p_adpt_api->adpt_port_txmac_status_set = NULL;
	p_adpt_api->adpt_port_combo_fiber_mode_set = NULL;
	p_adpt_api->adpt_port_combo_medium_status_get = NULL;
	p_adpt_api->adpt_port_magic_frame_mac_set = NULL;
	p_adpt_api->adpt_port_powersave_set = NULL;
	p_adpt_api->adpt_port_hibernate_set = NULL;
	p_adpt_api->adpt_port_8023az_get = NULL;
	p_adpt_api->adpt_port_rxfc_status_get = NULL;
	p_adpt_api->adpt_port_txfc_status_get = NULL;
	p_adpt_api->adpt_port_remote_loopback_set = NULL;
	p_adpt_api->adpt_port_flowctrl_set = NULL;
	p_adpt_api->adpt_port_mru_set = NULL;
	p_adpt_api->adpt_port_autoneg_status_get = NULL;
	p_adpt_api->adpt_port_txmac_status_get = NULL;
	p_adpt_api->adpt_port_mdix_get = NULL;
	p_adpt_api->adpt_ports_link_status_get = NULL;
	p_adpt_api->adpt_port_mac_loopback_set = NULL;
	p_adpt_api->adpt_port_phy_id_get = NULL;
	p_adpt_api->adpt_port_mru_get = NULL;
	p_adpt_api->adpt_port_power_on = NULL;
	p_adpt_api->adpt_port_speed_set = NULL;
	p_adpt_api->adpt_port_interface_mode_get = NULL;
	p_adpt_api->adpt_port_duplex_get = NULL;
	p_adpt_api->adpt_port_autoneg_adv_get = NULL;
	p_adpt_api->adpt_port_mdix_status_get = NULL;
	p_adpt_api->adpt_port_mtu_set = NULL;
	p_adpt_api->adpt_port_link_status_get = NULL;
	p_adpt_api->adpt_port_8023az_set = NULL;
	p_adpt_api->adpt_port_powersave_get = NULL;
	p_adpt_api->adpt_port_combo_prefer_medium_get = NULL;
	p_adpt_api->adpt_port_combo_prefer_medium_set = NULL;
	p_adpt_api->adpt_port_power_off = NULL;
	p_adpt_api->adpt_port_txfc_status_set = NULL;
	p_adpt_api->adpt_port_counter_set = NULL;
	p_adpt_api->adpt_port_combo_fiber_mode_get = NULL;
	p_adpt_api->adpt_port_local_loopback_set = NULL;
	p_adpt_api->adpt_port_wol_status_set = NULL;
	p_adpt_api->adpt_port_magic_frame_mac_get = NULL;
	p_adpt_api->adpt_port_flowctrl_get = NULL;
	p_adpt_api->adpt_port_rxmac_status_set = NULL;
	p_adpt_api->adpt_port_counter_get = NULL;
	p_adpt_api->adpt_port_interface_mode_set = NULL;
	p_adpt_api->adpt_port_mac_loopback_get = NULL;
	p_adpt_api->adpt_port_hibernate_get = NULL;
	p_adpt_api->adpt_port_autoneg_adv_set = NULL;
	p_adpt_api->adpt_port_remote_loopback_get = NULL;
	p_adpt_api->adpt_port_counter_show = NULL;
	p_adpt_api->adpt_port_autoneg_enable = NULL;
	p_adpt_api->adpt_port_mtu_get = NULL;
	p_adpt_api->adpt_port_interface_mode_status_get = NULL;
	p_adpt_api->adpt_port_reset = NULL;
	p_adpt_api->adpt_port_rxfc_status_set = NULL;
	p_adpt_api->adpt_port_speed_get = NULL;
	p_adpt_api->adpt_port_mdix_set = NULL;
	p_adpt_api->adpt_port_wol_status_get = NULL;
	p_adpt_api->adpt_port_max_frame_size_set = NULL;
	p_adpt_api->adpt_port_max_frame_size_get = NULL;
	p_adpt_api->adpt_port_source_filter_get = NULL;
	p_adpt_api->adpt_port_source_filter_set = NULL;

	return;

}

sw_error_t adpt_hppe_port_ctrl_init(a_uint32_t dev_id)
{
	adpt_api_t *p_adpt_api = NULL;

	p_adpt_api = adpt_api_ptr_get(dev_id);

	if(p_adpt_api == NULL)
		return SW_FAIL;

	adpt_hppe_port_ctrl_func_unregister(dev_id, p_adpt_api);

	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_LOCAL_LOOPBACK_GET))
	{
		p_adpt_api->adpt_port_local_loopback_get = adpt_hppe_port_local_loopback_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_AUTONEG_RESTART))
	{
		p_adpt_api->adpt_port_autoneg_restart = adpt_hppe_port_autoneg_restart;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_DUPLEX_SET))
	{
		p_adpt_api->adpt_port_duplex_set = adpt_hppe_port_duplex_set;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_RXMAC_STATUS_GET))
	{
		p_adpt_api->adpt_port_rxmac_status_get = adpt_hppe_port_rxmac_status_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_CDT))
	{
		p_adpt_api->adpt_port_cdt = adpt_hppe_port_cdt;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_TXMAC_STATUS_SET))
	{
		p_adpt_api->adpt_port_txmac_status_set = adpt_hppe_port_txmac_status_set;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_COMBO_FIBER_MODE_SET))
	{
		p_adpt_api->adpt_port_combo_fiber_mode_set = adpt_hppe_port_combo_fiber_mode_set;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_COMBO_MEDIUM_STATUS_GET))
	{
		p_adpt_api->adpt_port_combo_medium_status_get = adpt_hppe_port_combo_medium_status_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_MAGIC_FRAME_MAC_SET))
	{
		p_adpt_api->adpt_port_magic_frame_mac_set = adpt_hppe_port_magic_frame_mac_set;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_POWERSAVE_SET))
	{
		p_adpt_api->adpt_port_powersave_set = adpt_hppe_port_powersave_set;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_HIBERNATE_SET))
	{
		p_adpt_api->adpt_port_hibernate_set = adpt_hppe_port_hibernate_set;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_8023AZ_GET))
	{
		p_adpt_api->adpt_port_8023az_get = adpt_hppe_port_8023az_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_RXFC_STATUS_GET))
	{
		p_adpt_api->adpt_port_rxfc_status_get = adpt_hppe_port_rxfc_status_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_TXFC_STATUS_GET))
	{
		p_adpt_api->adpt_port_txfc_status_get = adpt_hppe_port_txfc_status_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_REMOTE_LOOPBACK_SET))
	{
		p_adpt_api->adpt_port_remote_loopback_set = adpt_hppe_port_remote_loopback_set;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_FLOWCTRL_SET))
	{
		p_adpt_api->adpt_port_flowctrl_set = adpt_hppe_port_flowctrl_set;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_MRU_SET))
	{
		p_adpt_api->adpt_port_mru_set = adpt_hppe_port_mru_set;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_AUTONEG_STATUS_GET))
	{
		p_adpt_api->adpt_port_autoneg_status_get = adpt_hppe_port_autoneg_status_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_TXMAC_STATUS_GET))
	{
		p_adpt_api->adpt_port_txmac_status_get = adpt_hppe_port_txmac_status_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_MDIX_GET))
	{
		p_adpt_api->adpt_port_mdix_get = adpt_hppe_port_mdix_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORTS_LINK_STATUS_GET))
	{
		p_adpt_api->adpt_ports_link_status_get = adpt_hppe_ports_link_status_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_MAC_LOOPBACK_SET))
	{
		p_adpt_api->adpt_port_mac_loopback_set = adpt_hppe_port_mac_loopback_set;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_PHY_ID_GET))
	{
		p_adpt_api->adpt_port_phy_id_get = adpt_hppe_port_phy_id_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_MRU_GET))
	{
		p_adpt_api->adpt_port_mru_get = adpt_hppe_port_mru_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_POWER_ON))
	{
		p_adpt_api->adpt_port_power_on = adpt_hppe_port_power_on;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_SPEED_SET))
	{
		p_adpt_api->adpt_port_speed_set = adpt_hppe_port_speed_set;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_INTERFACE_MODE_GET))
	{
		p_adpt_api->adpt_port_interface_mode_get = adpt_hppe_port_interface_mode_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_DUPLEX_GET))
	{
		p_adpt_api->adpt_port_duplex_get = adpt_hppe_port_duplex_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_AUTONEG_ADV_GET))
	{
		p_adpt_api->adpt_port_autoneg_adv_get = adpt_hppe_port_autoneg_adv_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_MDIX_STATUS_GET))
	{
		p_adpt_api->adpt_port_mdix_status_get = adpt_hppe_port_mdix_status_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_MTU_SET))
	{
		p_adpt_api->adpt_port_mtu_set = adpt_hppe_port_mtu_set;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[0] & (1 << FUNC_ADPT_PORT_LINK_STATUS_GET))
	{
		p_adpt_api->adpt_port_link_status_get = adpt_hppe_port_link_status_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_8023AZ_SET % 32)))
	{
		p_adpt_api->adpt_port_8023az_set = adpt_hppe_port_8023az_set;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_POWERSAVE_GET % 32)))
	{
		p_adpt_api->adpt_port_powersave_get = adpt_hppe_port_powersave_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_COMBO_PREFER_MEDIUM_GET % 32)))
	{
		p_adpt_api->adpt_port_combo_prefer_medium_get = adpt_hppe_port_combo_prefer_medium_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_COMBO_PREFER_MEDIUM_SET % 32)))
	{
		p_adpt_api->adpt_port_combo_prefer_medium_set = adpt_hppe_port_combo_prefer_medium_set;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_POWER_OFF % 32)))
	{
		p_adpt_api->adpt_port_power_off = adpt_hppe_port_power_off;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_TXFC_STATUS_SET  % 32)))
	{
		p_adpt_api->adpt_port_txfc_status_set = adpt_hppe_port_txfc_status_set;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_COUNTER_SET % 32)))
	{
		p_adpt_api->adpt_port_counter_set = adpt_hppe_port_counter_set;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_COMBO_FIBER_MODE_GET % 32)))
	{
		p_adpt_api->adpt_port_combo_fiber_mode_get = adpt_hppe_port_combo_fiber_mode_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_LOCAL_LOOPBACK_SET % 32)))
	{
		p_adpt_api->adpt_port_local_loopback_set = adpt_hppe_port_local_loopback_set;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_WOL_STATUS_SET % 32)))
	{
		p_adpt_api->adpt_port_wol_status_set = adpt_hppe_port_wol_status_set;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_MAGIC_FRAME_MAC_GET % 32)))
	{
		p_adpt_api->adpt_port_magic_frame_mac_get = adpt_hppe_port_magic_frame_mac_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_FLOWCTRL_GET % 32)))
	{
		p_adpt_api->adpt_port_flowctrl_get = adpt_hppe_port_flowctrl_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_RXMAC_STATUS_SET % 32)))
	{
		p_adpt_api->adpt_port_rxmac_status_set = adpt_hppe_port_rxmac_status_set;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_COUNTER_GET % 32)))
	{
		p_adpt_api->adpt_port_counter_get = adpt_hppe_port_counter_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_INTERFACE_MODE_SET % 32)))
	{
		p_adpt_api->adpt_port_interface_mode_set = adpt_hppe_port_interface_mode_set;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_MAC_LOOPBACK_GET % 32)))
	{
		p_adpt_api->adpt_port_mac_loopback_get = adpt_hppe_port_mac_loopback_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_HIBERNATE_GET % 32)))
	{
		p_adpt_api->adpt_port_hibernate_get = adpt_hppe_port_hibernate_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_AUTONEG_ADV_SET % 32)))
	{
		p_adpt_api->adpt_port_autoneg_adv_set = adpt_hppe_port_autoneg_adv_set;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_REMOTE_LOOPBACK_GET % 32)))
	{
		p_adpt_api->adpt_port_remote_loopback_get = adpt_hppe_port_remote_loopback_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_COUNTER_SHOW % 32)))
	{
		p_adpt_api->adpt_port_counter_show = adpt_hppe_port_counter_show;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_AUTONEG_ENABLE % 32)))
	{
		p_adpt_api->adpt_port_autoneg_enable = adpt_hppe_port_autoneg_enable;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_MTU_GET % 32)))
	{
		p_adpt_api->adpt_port_mtu_get = adpt_hppe_port_mtu_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_INTERFACE_MODE_STATUS_GET % 32)))
	{
		p_adpt_api->adpt_port_interface_mode_status_get = adpt_hppe_port_interface_mode_status_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_RESET % 32)))
	{
		p_adpt_api->adpt_port_reset = adpt_hppe_port_reset;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_RXFC_STATUS_SET % 32)))
	{
		p_adpt_api->adpt_port_rxfc_status_set = adpt_hppe_port_rxfc_status_set;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_SPEED_GET % 32)))
	{
		p_adpt_api->adpt_port_speed_get = adpt_hppe_port_speed_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_MDIX_SET % 32)))
	{
		p_adpt_api->adpt_port_mdix_set = adpt_hppe_port_mdix_set;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_WOL_STATUS_GET % 32)))
	{
		p_adpt_api->adpt_port_wol_status_get = adpt_hppe_port_wol_status_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_MAX_FRAME_SIZE_SET % 32)))
	{
		p_adpt_api->adpt_port_max_frame_size_set = adpt_hppe_port_max_frame_size_set;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_MAX_FRAME_SIZE_GET % 32)))
	{
		p_adpt_api->adpt_port_max_frame_size_get = adpt_hppe_port_max_frame_size_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_SOURCE_FILTER_GET % 32)))
	{
		p_adpt_api->adpt_port_source_filter_get = adpt_hppe_port_source_filter_get;
	}
	if(p_adpt_api->adpt_port_ctrl_func_bitmap[1] & (1 <<  (FUNC_ADPT_PORT_SOURCE_FILTER_SET % 32)))
	{
		p_adpt_api->adpt_port_source_filter_set = adpt_hppe_port_source_filter_set;
	}

	p_adpt_api->adpt_port_mac_mux_set = adpt_hppe_port_mux_set;
	p_adpt_api->adpt_port_mac_speed_set = adpt_hppe_port_mac_speed_set;
	p_adpt_api->adpt_port_mac_duplex_set = adpt_hppe_port_mac_duplex_set;

	return SW_OK;
}

/**
 * @}
 */
