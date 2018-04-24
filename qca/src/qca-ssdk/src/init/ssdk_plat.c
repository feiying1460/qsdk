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

#include "sw.h"
#include "ssdk_init.h"
#include "fal_init.h"
#include "fal.h"
#include "hsl.h"
#include "hsl_dev.h"
#include "ssdk_init.h"
#include <linux/kconfig.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/phy.h>
#include <linux/platform_device.h>
#include <linux/types.h>
//#include <asm/mach-types.h>
#include <generated/autoconf.h>
#include <linux/if_arp.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/phy.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/string.h>
#if defined(ISIS) ||defined(ISISC) ||defined(GARUDA)
#include <f1_phy.h>
#endif
#if defined(ATHENA) ||defined(SHIVA) ||defined(HORUS)
#include <f2_phy.h>
#endif
#ifdef IN_MALIBU_PHY
#include <malibu_phy.h>
#endif
#if defined(CONFIG_OF) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0))
#include <linux/switch.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#elif defined(CONFIG_OF) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
#include <linux/switch.h>
#include <linux/of.h>
#include <drivers/leds/leds-ipq40xx.h>
#include <linux/of_platform.h>
#include <linux/reset.h>
#else
#include <net/switch.h>
#include <linux/ar8216_platform.h>
#include <drivers/net/phy/ar8216.h>
#include <drivers/net/ethernet/atheros/ag71xx/ag71xx.h>
#endif
#include "ssdk_plat.h"
#include "ref_vlan.h"
#include "ref_fdb.h"
#include "ref_mib.h"
#include "ref_port_ctrl.h"
#include "ref_misc.h"
#include "ref_uci.h"
#include "shell.h"
#ifdef BOARD_AR71XX
#include "ssdk_uci.h"
#endif

#ifdef IN_IP
#if defined (CONFIG_NF_FLOW_COOKIE)
#include "fal_flowcookie.h"
#ifdef IN_SFE
#include <shortcut-fe/sfe.h>
#endif
#endif
#endif

#ifdef IN_RFS
#if defined(CONFIG_VLAN_8021Q) || defined(CONFIG_VLAN_8021Q_MODULE)
#include <linux/if_vlan.h>
#endif
#include <qca-rfs/rfs_dev.h>
#ifdef IN_IP
#include "fal_rfs.h"
#endif
#endif

static struct mii_bus *miibus = NULL;

extern struct qca_phy_priv *qca_phy_priv_global;
extern ssdk_dt_cfg ssdk_dt_global;
extern ssdk_chip_type SSDK_CURRENT_CHIP_TYPE;
extern void __iomem *hppe_uniphy_addr;

static struct mutex switch_mdio_lock;

#ifdef BOARD_IPQ806X
#define IPQ806X_MDIO_BUS_NAME			"mdio-gpio"
#endif

#ifdef BOARD_AR71XX
#define IPQ806X_MDIO_BUS_NAME			"ag71xx-mdio"
#endif
#define MDIO_BUS_0						0
#define MDIO_BUS_1						1
#define IPQ806X_MDIO_BUS_NUM			MDIO_BUS_0

#define ISIS_CHIP_ID 0x18
#define ISIS_CHIP_REG 0
#define SHIVA_CHIP_ID 0x1f
#define SHIVA_CHIP_REG 0x10

/*
 * Using ISIS's address as default
  */
static int switch_chip_id = ISIS_CHIP_ID;
static int switch_chip_reg = ISIS_CHIP_REG;

#if defined(CONFIG_OF) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
struct ag71xx_mdio {
	struct mii_bus		*mii_bus;
	int			mii_irq[PHY_MAX_ADDR];
	void __iomem		*mdio_base;
};
#endif

#ifdef BOARD_AR71XX
static uint32_t switch_chip_id_adjuest(void)
{
	uint32_t chip_version = 0;
	chip_version = (qca_ar8216_mii_read(0)&0xff00)>>8;
	if((chip_version !=0) && (chip_version !=0xff))
		return 0;

	switch_chip_id = SHIVA_CHIP_ID;
	switch_chip_reg = SHIVA_CHIP_REG;

	chip_version = (qca_ar8216_mii_read(0)&0xff00)>>8;
	printk("chip_version:0x%x\n", chip_version);
	return 1;
}
#endif

static inline void
split_addr(uint32_t regaddr, uint16_t *r1, uint16_t *r2, uint16_t *page)
{
	regaddr >>= 1;
	*r1 = regaddr & 0x1e;

	regaddr >>= 5;
	*r2 = regaddr & 0x7;

	regaddr >>= 3;
	*page = regaddr & 0x3ff;
}

a_uint32_t
qca_ar8216_mii_read(a_uint32_t reg)
{
        struct mii_bus *bus = miibus;
        uint16_t r1, r2, page;
        uint16_t lo, hi;

        split_addr((uint32_t) reg, &r1, &r2, &page);
        mutex_lock(&switch_mdio_lock);
        mdiobus_write(bus, switch_chip_id, switch_chip_reg, page);
	udelay(100);
        lo = mdiobus_read(bus, 0x10 | r2, r1);
        hi = mdiobus_read(bus, 0x10 | r2, r1 + 1);
        mutex_unlock(&switch_mdio_lock);
        return (hi << 16) | lo;
}

void
qca_ar8216_mii_write(a_uint32_t reg, a_uint32_t val)
{
        struct mii_bus *bus = miibus;
        uint16_t r1, r2, r3;
        uint16_t lo, hi;

        split_addr((a_uint32_t) reg, &r1, &r2, &r3);
        lo = val & 0xffff;
        hi = (a_uint16_t) (val >> 16);

        mutex_lock(&switch_mdio_lock);
        mdiobus_write(bus, switch_chip_id, switch_chip_reg, r3);
	udelay(100);
        if(SSDK_CURRENT_CHIP_TYPE != CHIP_SHIVA) {
            mdiobus_write(bus, 0x10 | r2, r1, lo);
            mdiobus_write(bus, 0x10 | r2, r1 + 1, hi);
        } else {
            mdiobus_write(bus, 0x10 | r2, r1 + 1, hi);
            mdiobus_write(bus, 0x10 | r2, r1, lo);
        }
        mutex_unlock(&switch_mdio_lock);
}

a_bool_t
phy_addr_validation_check(a_uint32_t phy_addr)
{

	if (phy_addr  == SSDK_PHY_BCAST_ID)
		return A_TRUE;
	else if ((phy_addr > SSDK_PSGMII_ID) || (phy_addr < SSDK_PHY_MIN_ID))
		return A_FALSE;
	else
		return A_TRUE;
}

sw_error_t
qca_ar8327_phy_read(a_uint32_t dev_id, a_uint32_t phy_addr,
                           a_uint32_t reg, a_uint16_t* data)
{
	struct mii_bus *bus = miibus;
	int phy_dest_addr;
	if (A_TRUE != phy_addr_validation_check (phy_addr))
	{
		return SW_BAD_PARAM;
	}
	if (phy_addr == SSDK_PSGMII_ID)
		phy_dest_addr = qca_phy_priv_global->phy_address[phy_addr -1] + 1;
	else if (phy_addr == SSDK_PHY_BCAST_ID)
		phy_dest_addr = SSDK_PHY_BCAST_ID;
	else
		phy_dest_addr = qca_phy_priv_global->phy_address[phy_addr];

	*data = mdiobus_read(bus, phy_dest_addr, reg);
	return 0;
}

sw_error_t
qca_ar8327_phy_write(a_uint32_t dev_id, a_uint32_t phy_addr,
                            a_uint32_t reg, a_uint16_t data)
{
	struct mii_bus *bus = miibus;
	int phy_dest_addr;
	if (A_TRUE != phy_addr_validation_check (phy_addr))
	{
		return SW_BAD_PARAM;
	}
	if (phy_addr == SSDK_PSGMII_ID)
		phy_dest_addr = qca_phy_priv_global->phy_address[phy_addr -1] + 1;
	else if (phy_addr == SSDK_PHY_BCAST_ID)
		phy_dest_addr = SSDK_PHY_BCAST_ID;
	else
		phy_dest_addr = qca_phy_priv_global->phy_address[phy_addr];

	mdiobus_write(bus, phy_dest_addr, reg, data);
	return 0;
}

void
qca_ar8327_phy_dbg_write(a_uint32_t dev_id, a_uint32_t phy_addr,
                                a_uint16_t dbg_addr, a_uint16_t dbg_data)
{
	struct mii_bus *bus = miibus;
	int phy_dest_addr;
	if (A_TRUE != phy_addr_validation_check (phy_addr))
	{
		return ;
	}
	if (phy_addr == SSDK_PSGMII_ID)
		phy_dest_addr = qca_phy_priv_global->phy_address[phy_addr -1] + 1;
	else if (phy_addr == SSDK_PHY_BCAST_ID)
		phy_dest_addr = SSDK_PHY_BCAST_ID;
	else
		phy_dest_addr = qca_phy_priv_global->phy_address[phy_addr];

	mdiobus_write(bus, phy_dest_addr, QCA_MII_DBG_ADDR, dbg_addr);
	mdiobus_write(bus, phy_dest_addr, QCA_MII_DBG_DATA, dbg_data);
}

void
qca_ar8327_phy_dbg_read(a_uint32_t dev_id, a_uint32_t phy_addr,
		                a_uint16_t dbg_addr, a_uint16_t *dbg_data)
{
	struct mii_bus *bus = miibus;
	int phy_dest_addr;
	if (A_TRUE != phy_addr_validation_check (phy_addr))
	{
		return ;
	}
	if (phy_addr == SSDK_PSGMII_ID)
		phy_dest_addr = qca_phy_priv_global->phy_address[phy_addr -1] + 1;
	else if (phy_addr == SSDK_PHY_BCAST_ID)
		phy_dest_addr = SSDK_PHY_BCAST_ID;
	else
		phy_dest_addr = qca_phy_priv_global->phy_address[phy_addr];

	mdiobus_write(bus, phy_dest_addr, QCA_MII_DBG_ADDR, dbg_addr);
	*dbg_data = mdiobus_read(bus, phy_dest_addr, QCA_MII_DBG_DATA);
}


void
qca_ar8327_mmd_write(a_uint32_t dev_id, a_uint32_t phy_addr,
                          a_uint16_t addr, a_uint16_t data)
{
	struct mii_bus *bus = miibus;
	int phy_dest_addr;
	if (A_TRUE != phy_addr_validation_check (phy_addr))
	{
		return ;
	}
	if (phy_addr == SSDK_PSGMII_ID)
		phy_dest_addr = qca_phy_priv_global->phy_address[phy_addr -1] + 1;
	else if (phy_addr == SSDK_PHY_BCAST_ID)
		phy_dest_addr = SSDK_PHY_BCAST_ID;
	else
		phy_dest_addr = qca_phy_priv_global->phy_address[phy_addr];

	mdiobus_write(bus, phy_dest_addr, QCA_MII_MMD_ADDR, addr);
	mdiobus_write(bus, phy_dest_addr, QCA_MII_MMD_DATA, data);
}

void qca_phy_mmd_write(u32 dev_id, u32 phy_id,
                     u16 mmd_num, u16 reg_id, u16 reg_val)
{
	qca_ar8327_phy_write(dev_id, phy_id,
			QCA_MII_MMD_ADDR, mmd_num);
	qca_ar8327_phy_write(dev_id, phy_id,
			QCA_MII_MMD_DATA, reg_id);
	qca_ar8327_phy_write(dev_id, phy_id,
			QCA_MII_MMD_ADDR,
			0x4000 | mmd_num);
	qca_ar8327_phy_write(dev_id, phy_id,
		QCA_MII_MMD_DATA, reg_val);
}

u16 qca_phy_mmd_read(u32 dev_id, u32 phy_id,
		u16 mmd_num, u16 reg_id)
{
	u16 value = 0;
	qca_ar8327_phy_write(dev_id, phy_id,
			QCA_MII_MMD_ADDR, mmd_num);
	qca_ar8327_phy_write(dev_id, phy_id,
			QCA_MII_MMD_DATA, reg_id);
	qca_ar8327_phy_write(dev_id, phy_id,
			QCA_MII_MMD_ADDR,
			0x4000 | mmd_num);
	qca_ar8327_phy_read(dev_id, phy_id,
			QCA_MII_MMD_DATA, &value);
	return value;
}

sw_error_t
qca_switch_reg_read(a_uint32_t dev_id, a_uint32_t reg_addr, a_uint8_t * reg_data, a_uint32_t len)
{
	uint32_t reg_val = 0;

	if (len != sizeof (a_uint32_t))
        return SW_BAD_LEN;

	if ((reg_addr%4)!= 0)
	return SW_BAD_PARAM;

	reg_val = readl(qca_phy_priv_global->hw_addr + reg_addr);

	aos_mem_copy(reg_data, &reg_val, sizeof (a_uint32_t));
	return 0;
}

sw_error_t
qca_switch_reg_write(a_uint32_t dev_id, a_uint32_t reg_addr, a_uint8_t * reg_data, a_uint32_t len)
{
	uint32_t reg_val = 0;
	if (len != sizeof (a_uint32_t))
        return SW_BAD_LEN;

	if ((reg_addr%4)!= 0)
	return SW_BAD_PARAM;

	aos_mem_copy(&reg_val, reg_data, sizeof (a_uint32_t));
	writel(reg_val, qca_phy_priv_global->hw_addr + reg_addr);
	return 0;
}

sw_error_t
qca_psgmii_reg_read(a_uint32_t dev_id, a_uint32_t reg_addr, a_uint8_t * reg_data, a_uint32_t len)
{
	uint32_t reg_val = 0;

	if (len != sizeof (a_uint32_t))
        return SW_BAD_LEN;

	if((reg_addr%4)!=0)
	return SW_BAD_PARAM;

	if (qca_phy_priv_global->psgmii_hw_addr == NULL)
		return SW_NOT_SUPPORTED;

	reg_val = readl(qca_phy_priv_global->psgmii_hw_addr + reg_addr);

	aos_mem_copy(reg_data, &reg_val, sizeof (a_uint32_t));
	return 0;
}

sw_error_t
qca_psgmii_reg_write(a_uint32_t dev_id, a_uint32_t reg_addr, a_uint8_t * reg_data, a_uint32_t len)
{
	uint32_t reg_val = 0;
	if (len != sizeof (a_uint32_t))
        return SW_BAD_LEN;

	if((reg_addr%4)!=0)
	return SW_BAD_PARAM;

	if (qca_phy_priv_global->psgmii_hw_addr == NULL)
		return SW_NOT_SUPPORTED;

	aos_mem_copy(&reg_val, reg_data, sizeof (a_uint32_t));
	writel(reg_val, qca_phy_priv_global->psgmii_hw_addr + reg_addr);
	return 0;
}

static int miibus_get(void)
{
#if defined(CONFIG_OF) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
	#ifndef BOARD_AR71XX
	struct device_node *mdio_node = NULL;
	struct platform_device *mdio_plat = NULL;
	struct ipq40xx_mdio_data *mdio_data = NULL;

	if(ssdk_dt_global.switch_reg_access_mode == HSL_REG_LOCAL_BUS)
		mdio_node = of_find_compatible_node(NULL, NULL, "qcom,ipq40xx-mdio");
	else
		mdio_node = of_find_compatible_node(NULL, NULL, "virtual,mdio-gpio");

	if (!mdio_node) {
		printk("No MDIO node found in DTS!\n");
		return 0;
	}

	mdio_plat = of_find_device_by_node(mdio_node);
	if (!mdio_plat) {
		printk("cannot find platform device from mdio node\n");
		return 1;
	}

	if(ssdk_dt_global.switch_reg_access_mode == HSL_REG_LOCAL_BUS)
	{
		mdio_data = dev_get_drvdata(&mdio_plat->dev);
		if (!mdio_data) {
                	printk("cannot get mdio_data reference from device data\n");
                	return 1;
        	}
		miibus = mdio_data->mii_bus;
	}
	else
		miibus = dev_get_drvdata(&mdio_plat->dev);

	if (!miibus) {
		printk("cannot get mii bus reference from device data\n");
		return 1;
	}
	#else
	struct ag71xx_mdio *am;
	struct device_node *mdio_node = NULL;
	struct platform_device *mdio_plat = NULL;

	mdio_node = of_find_compatible_node(NULL, NULL, "qca,ag71xx-mdio");
	if (!mdio_node) {
		printk("No MDIO node found in DTS!\n");
		return 1;
	}
	mdio_plat = of_find_device_by_node(mdio_node);
	if (!mdio_plat) {
		printk("cannot find platform device from mdio node\n");
		return 1;
	}
	am = dev_get_drvdata(&mdio_plat->dev);
	if (!am) {
                	printk("cannot get mdio_data reference from device data\n");
                	return 1;
	}
	miibus = am->mii_bus;
	if (!miibus) {
		printk("cannot get mii bus reference from device data\n");
		return 1;
	}
	switch_chip_id_adjuest();
	#endif
#else
#ifdef BOARD_AR71XX
	struct ag71xx_mdio *am;
#endif
	struct device *miidev;
	char busid[MII_BUS_ID_SIZE];
	snprintf(busid, MII_BUS_ID_SIZE, "%s.%d",
		IPQ806X_MDIO_BUS_NAME, IPQ806X_MDIO_BUS_NUM);

	miidev = bus_find_device_by_name(&platform_bus_type, NULL, busid);
	if (!miidev) {
		printk("cannot get mii bus\n");
		return 1;
	}

#ifdef BOARD_AR71XX
	am = dev_get_drvdata(miidev);
	miibus = am->mii_bus;
#else
	miibus = dev_get_drvdata(miidev);
#endif

#ifdef BOARD_AR71XX
	if(switch_chip_id_adjuest()) {

		snprintf(busid, MII_BUS_ID_SIZE, "%s.%d",
		IPQ806X_MDIO_BUS_NAME, MDIO_BUS_1);

		miidev = bus_find_device_by_name(&platform_bus_type, NULL, busid);
		if (!miidev) {
			printk("cannot get mii bus\n");
			return 1;
		}

		am = dev_get_drvdata(miidev);
		miibus = am->mii_bus;
		printk("chip_version:0x%x\n", (qca_ar8216_mii_read(0)&0xff00)>>8);
	}
#endif

	if(!miidev){
		printk("mdio bus '%s' get FAIL\n", busid);
		return 1;
	}
#endif

	return 0;
}

int
ssdk_plat_init(ssdk_init_cfg *cfg)
{
	#ifdef BOARD_AR71XX
	int rv = 0;
	#endif
	printk("ssdk_plat_init start\n");
	mutex_init(&switch_mdio_lock);

	if(miibus_get())
		return -ENODEV;


	#if defined(DESS) || defined(HPPE)
	if(ssdk_dt_global.switch_reg_access_mode == HSL_REG_LOCAL_BUS) {
		qca_phy_priv_global->hw_addr = ioremap_nocache(ssdk_dt_global.switchreg_base_addr,
					ssdk_dt_global.switchreg_size);
		if (!qca_phy_priv_global->hw_addr) {
			printk("%s ioremap fail.", __func__);
			return -1;
		}
		if(ssdk_dt_global.uniphy_reg_access_mode == HSL_REG_LOCAL_BUS) {
			hppe_uniphy_addr = ioremap_nocache(ssdk_dt_global.uniphyreg_base_addr,
						ssdk_dt_global.uniphyreg_size);
			if (!hppe_uniphy_addr) {
				printk("%s ioremap fail.", __func__);
				return -1;
			}
		}
		if (!ssdk_dt_global.ess_clk || IS_ERR(ssdk_dt_global.ess_clk))
			return 0;
		/* Enable ess clock here */
		printk("enable ess clk\n");
		clk_prepare_enable(ssdk_dt_global.ess_clk);

		cfg->reg_mode = HSL_HEADER;
	}

	if(ssdk_dt_global.psgmii_reg_access_mode == HSL_REG_LOCAL_BUS) {
		if (!request_mem_region(ssdk_dt_global.psgmiireg_base_addr,
				ssdk_dt_global.psgmiireg_size, "psgmii_mem")) {
			printk("%s Unable to request psgmii resource.", __func__);
			return -1;
		}

		qca_phy_priv_global->psgmii_hw_addr = ioremap_nocache(ssdk_dt_global.psgmiireg_base_addr,
				ssdk_dt_global.psgmiireg_size);
		if (!qca_phy_priv_global->psgmii_hw_addr) {
			printk("%s ioremap fail.", __func__);
			cfg->reg_func.psgmii_reg_set = NULL;
			cfg->reg_func.psgmii_reg_get = NULL;
			return -1;
		}

		cfg->reg_func.psgmii_reg_set = qca_psgmii_reg_write;
		cfg->reg_func.psgmii_reg_get = qca_psgmii_reg_read;
	}
	#endif

	if(ssdk_dt_global.switch_reg_access_mode == HSL_REG_MDIO) {
		cfg->reg_mode = HSL_MDIO;
	} else
		return 0;

	return 0;
}

void
ssdk_plat_exit(void)
{
    printk("ssdk_plat_exit\n");

	if (ssdk_dt_global.switch_reg_access_mode == HSL_REG_LOCAL_BUS) {
		iounmap(qca_phy_priv_global->hw_addr);
		iounmap(qca_phy_priv_global->psgmii_hw_addr);
		release_mem_region(ssdk_dt_global.switchreg_base_addr,
					ssdk_dt_global.switchreg_size);
		release_mem_region(ssdk_dt_global.psgmiireg_base_addr,
					ssdk_dt_global.psgmiireg_size);
	}

}

