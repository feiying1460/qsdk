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
 * @defgroup dess_init HPPE_INIT
 * @{
 */
#include "sw.h"
#include "hsl.h"
#include "hsl_dev.h"
#include "hsl_port_prop.h"
#include "sd.h"


static ssdk_init_cfg * hppe_cfg[SW_MAX_NR_DEV] = { 0 };

enum hppe_port_wrapper_cfg {
	HPPE_PORT_SGMII = 0,
	HPPE_PORT_QSGMII_2GMAC,
	HPPE_PORT_PSGMII,
	HPPE_PORT_PSGMII_SGMII,
	HPPE_PORT_QSGMII_2SGMIIPLUS,
	HPPE_PORT_QSGMII_3GMAC_2SGMIIPLUS,
	HPPE_PORT_XFI,
	HPPE_PORT_2XFI,
	HPPE_PORT_2XFI_SGMII,
	HPPE_PORT_QSGMII_2XFI,
	HPPE_PORT_WRAPPER_MAX
};


a_uint32_t hppe_pbmp[HPPE_PORT_WRAPPER_MAX] = {
	(1<<1), /*HPPE_PORT_SGMIII*/
	((1<<1) | (1<<2)), /*HPPE_PORT_QSGMII_2GMAC*/
	((1<<1) | (1<<2) | (1<<3) | (1<<4) | (1<<5)), /*HPPE_PORT_PSGMII*/
	((1<<1) | (1<<2) | (1<<3) | (1<<4) | (1<<5) |(1<<6)), /*HPPE_PORT_PSGMII_SGMII*/
	((1<<1) | (1<<2) | (1<<3) | (1<<4) | (1<<5) |(1<<6)), /*HPPE_PORT_QSGMII_2SGMIIPLUS*/
	((1<<1) | (1<<2) | (1<<3) | (1<<4) | (1<<5)), /*HPPE_PORT_QSGMII_3GMAC_2SGMIIPLUS*/
	(1<<1), /*HPPE_PORT_XFI*/
	((1<<1) | (1<<2)), /*HPPE_PORT_2XFI*/
	((1<<1) | (1<<2) | (1<<3)), /*HPPE_PORT_2XFI_SGMII*/
	((1<<1) | (1<<2) | (1<<3) | (1<<4) | (1<<5) |(1<<6)), /*HPPE_PORT_QSGMII_2XFI*/
	};

enum hppe_port_wrapper_cfg hppe_get_port_config(void)
{
	return hppe_cfg[0]->mac_mode;
}

a_bool_t hppe_mac_port_valid_check(fal_port_t port_id)
{
	a_uint32_t bitmap = 0;
	enum hppe_port_wrapper_cfg cfg;

//	cfg = hppe_get_port_config();
	cfg = HPPE_PORT_PSGMII;
	bitmap = hppe_pbmp[cfg];

	return SW_IS_PBMP_MEMBER(bitmap, port_id);

}
static sw_error_t
hppe_portproperty_init(a_uint32_t dev_id)
{
	hsl_port_prop_t p_type;
	hsl_dev_t *pdev = NULL;
	fal_port_t port_id;
	enum hppe_port_wrapper_cfg cfg;
	a_uint32_t bitmap = 0;

	pdev = hsl_dev_ptr_get(dev_id);
	if (pdev == NULL)
		return SW_NOT_INITIALIZED;

//	cfg = hppe_get_port_config();
	cfg = HPPE_PORT_PSGMII;
	bitmap = hppe_pbmp[cfg];

	/* for port property set, SSDK should not generate some limitations */
	for (port_id = 0; port_id < pdev->nr_ports; port_id++)
	{
		hsl_port_prop_portmap_set(dev_id, port_id);

		for (p_type = HSL_PP_PHY; p_type < HSL_PP_BUTT; p_type++)
		{
			switch (p_type)
			{
				case HSL_PP_PHY:
	                    /* Only port0 without PHY device */
	                    if (port_id != pdev->cpu_port_nr)
	                    {
					if(SW_IS_PBMP_MEMBER(bitmap, port_id))
						SW_RTN_ON_ERROR(hsl_port_prop_set(dev_id, port_id, p_type));
	                    }
	                    break;

				case HSL_PP_INCL_CPU:
	                    /* include cpu port but exclude wan port in some cases */
	                    /* but which port is wan port, we are no meaning */
					if (port_id == pdev->cpu_port_nr)
						SW_RTN_ON_ERROR(hsl_port_prop_set(dev_id, port_id, p_type));
					if(SW_IS_PBMP_MEMBER(bitmap, port_id))
						SW_RTN_ON_ERROR(hsl_port_prop_set(dev_id, port_id, p_type));
				break;

				case HSL_PP_EXCL_CPU:
				/* exclude cpu port and wan port in some cases */
	                    /* which port is wan port, we are no meaning but port0 is
	                       always CPU port */
					if (port_id != pdev->cpu_port_nr)
					{
						if(SW_IS_PBMP_MEMBER(bitmap, port_id))
							SW_RTN_ON_ERROR(hsl_port_prop_set(dev_id, port_id, p_type));
					}
				break;

				default:
				break;
			}
		}

		if (port_id != pdev->cpu_port_nr)
		{
			SW_RTN_ON_ERROR(hsl_port_prop_set_phyid
			(dev_id, port_id, port_id - 1));
		}
	}

	return SW_OK;
}

static sw_error_t
hppe_dev_init(a_uint32_t dev_id, ssdk_init_cfg *cfg)
{
	hsl_dev_t *pdev = NULL;
	a_uint32_t i = 0, port_nr = 0, tmp = 0;

	pdev = hsl_dev_ptr_get(dev_id);
	if (pdev == NULL)
		return SW_NOT_INITIALIZED;

	tmp = cfg->port_cfg.lan_bmp | cfg->port_cfg.wan_bmp;
	for(i = 0; i < SW_MAX_NR_PORT; i++) {
		if(tmp & (1 << i)) {
			port_nr++;
		}
	}
	pdev->nr_phy = port_nr;
	for(i = 0; i < SW_MAX_NR_PORT; i++) {
		if(cfg->port_cfg.cpu_bmp & (1 << i)) {
			port_nr++;
			pdev->cpu_port_nr = i;
			break;
		}
	}
	if(i >= SW_MAX_NR_PORT)
		return SW_BAD_VALUE;
	pdev->nr_ports = port_nr;
	pdev->nr_vlans = 4096;
	pdev->hw_vlan_query = A_TRUE;
	pdev->nr_queue = port_nr;
	pdev->cpu_mode = cfg->cpu_mode;
	pdev->wan_bmp = cfg->port_cfg.wan_bmp;

	return SW_OK;
}

sw_error_t
hppe_cleanup(a_uint32_t dev_id)
{

    if (hppe_cfg[dev_id])
    {
        SW_RTN_ON_ERROR(hsl_port_prop_cleanup_by_dev(dev_id));

        aos_mem_free(hppe_cfg[dev_id]);
        hppe_cfg[dev_id] = NULL;
    }

    return SW_OK;
}

/**
 * @brief Init hsl layer.
 * @details Comments:
 *   This operation will init hsl layer and hsl layer
 * @param[in] dev_id device id
 * @param[in] cfg configuration for initialization
 * @return SW_OK or error code
 */
sw_error_t hppe_init(a_uint32_t dev_id, ssdk_init_cfg *cfg)
{
    HSL_DEV_ID_CHECK(dev_id);

    printk("HPPE initializing...\n");
    if (NULL == hppe_cfg[dev_id])
    {
        hppe_cfg[dev_id] = aos_mem_alloc(sizeof (ssdk_init_cfg));
    }

    if (NULL == hppe_cfg[dev_id])
    {
        return SW_OUT_OF_MEM;
    }

    aos_mem_copy(hppe_cfg[dev_id], cfg, sizeof (ssdk_init_cfg));

    SW_RTN_ON_ERROR(hppe_dev_init(dev_id, cfg));

#if !(defined(KERNEL_MODULE) && defined(USER_MODE))
	{
		hsl_api_t *p_api;

		SW_RTN_ON_ERROR(hsl_port_prop_init());
		SW_RTN_ON_ERROR(hsl_port_prop_init_by_dev(dev_id));
		SW_RTN_ON_ERROR(hppe_portproperty_init(dev_id));

		SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));
		p_api->dev_clean   = hppe_cleanup;
		p_api->reg_get = sd_reg_hdr_get;
		p_api->reg_set = sd_reg_hdr_set;
		p_api->phy_get = sd_reg_mdio_get;
		p_api->phy_set = sd_reg_mdio_set;

	}
#endif

    return SW_OK;
}

/**
 * @}
 */

