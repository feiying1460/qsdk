#
# Copyright (c) 2014 Qualcomm Atheros, Inc..
#
# All Rights Reserved.
# Qualcomm Atheros Confidential and Proprietary.
#
CURR_DIR=$(shell pwd)
FWPROTOCOL_SUPPORT:=$(CURR_DIR)/fwprotocol/support
FWPROTOCOL_TOOLS:=$(CURR_DIR)/fwprotocol/tools
include config.mk

ifeq ($(INSTALL_ROOT),)
INSTALL_ROOT:=$(CURR_DIR)/root
endif


#########################################################
############ WLAN DRIVER BUILD CONFIGURATION ############
#########################################################

$(warning "MAKE=$(MAKE)")
$(warning "MAKEARCH=$(MAKEARCH)")
$(warning "TARGET=$(TARGET)")
$(warning "TOPDIR=$(TOPDIR)")
$(warning "INSTALL_ROOT=$(INSTALL_ROOT)")

LINUX_KARCH:=$(ARCH)

########################################################
############## WLAN CONFIG OVERRIDE FACILITY ###########
########################################################
ifneq ($(QCAWLAN_MAKEOPTS_EXTRAS),)
	QCAWLAN_MAKEOPTS+=$(QCAWLAN_MAKEOPTS_EXTRAS)
$(warning "QCAWLAN_MAKEOPTS_EXTRAS=$(QCAWLAN_MAKEOPTS_EXTRAS)")
endif

ifeq ($(ARCH),mips)
	HAL_TARGET:=mipsisa32-be-elf
endif
ifeq ($(ARCH),arm)
	HAL_TARGET:=armv4-le-elf
QCAWLAN_MAKEOPTS+=BUILD_ARM=y
endif
ifeq ($(ARCH),x86)
	HAL_TARGET:=i386-elf
endif
ifeq ($(QCA_PLATFORM),ar71xx)
	QCAWLAN_MAKEOPTS+= \
		BUS=dual \
	        AH_CAL_IN_DRAM_FROM_HOST=1 \
	        AH_CAL_RADIOS_AHB=1 \
		AH_CAL_RADIOS_PCI=1 \
	        AH_SUPPORT_SCORPION=1 \
            AH_SUPPORT_DRAGONFLY=1 \
            AH_SUPPORT_HONEYBEE=1
endif
ifeq ($(QCA_PLATFORM),ipq806x)
	QCAWLAN_MAKEOPTS+=BUILD_ARM_MSM=y \
		AH_CAL_RADIOS_PCI=3 \
                AH_CAL_LOCATIONS_PCI=0,0x4000,0x8000
endif
MAKEARCH:=$(MAKE) ARCH=$(LINUX_KARCH) CROSS_COMPILE=$(TARGET_CROSS)

QCAWLAN_MAKEOPTS+= \
	TOOLPATH= \
	TOOLPREFIX=$(TARGET_CROSS) \
	NO_SIMPLE_CONFIG=1 \
	USE_PLATFORM_FRAMEWORK=1 \
	TARGET=$(HAL_TARGET) \
	BIG_ENDIAN_HOST=$(BIG_ENDIAN_HOST) \
	ARCH=$(LINUX_KARCH) \
	KERNELARCH=$(LINUX_KARCH) \
	KERNELVER=$(LINUX_VERSION) \
	FIRMWARE_REL_PATH=offload \
	PERF_PWR_OFFLOAD_DIR_PATH=$(CURR_DIR)/offload \
	QCA_NSS_INCLUDE=$(STAGING_DIR)/usr/include/qca-nss-drv \
	KBUILDPATH=$(LINUX_SRC_DIR) \
	KERNELPATH=$(LINUX_DIR)

src_prepare:
	mkdir -p  $(CURR_DIR)/halphy_tools
	cp -af $(FW_INCLUDE_PATH)/* $(CURR_DIR)/offload/include/
	cp -af $(HALPHY_TOOLS_PATH)/* $(CURR_DIR)/halphy_tools/

env_prepare:
	@echo "============================PREPARING==========================="
	@echo $(QCAWLAN_MAKEOPTS)
	mkdir -p $(CURR_DIR)/root/usr/www/cgi-bin
	mkdir -p $(CURR_DIR)/root/sbin

hal_build:
	@echo "========================BUILDING HAL==========================="
	($(foreach var,$(strip $(QCAWLAN_MAKEOPTS)),export $(var);) \
	    $(MAKE) -C $(CURR_DIR)/hal/linux TARGET=$(HAL_TARGET))
	($(foreach var,$(strip $(QCAWLAN_MAKEOPTS)),export $(var);) \
	    $(MAKE) -C $(CURR_DIR)/hal/linux TARGET=$(HAL_TARGET) release)

driver_build:
	@echo "===========================BUILDING DRIVER================================="
	($(foreach var,$(strip $(QCAWLAN_MAKEOPTS)),export $(var);) \
		$(MAKEARCH) -C $(CURR_DIR)/os/linux TARGET=$(HAL_TARGET))

driver_installonly:
	cp -af $(foreach module,$(QCAWLAN_MODULE_LIST),$(module)) $(INSTALL_ROOT_DRV)
	@echo "===========================INSTALL DRIVER DONE====================================="

driver_install: driver_build driver_installonly
	@echo "============================DRIVER INSTALLED================================"
tools_build:
	@echo "===========================BUILDING TOOLS================================="
	($(foreach var,$(strip $(QCAWLAN_MAKEOPTS)),export $(var);) \
	    $(MAKEARCH) -C $(CURR_DIR)/os/linux/tools \
	    QCACFLAGS="$(TARGET_CFLAGS)"  \
	    QCALDFLAGS="-Wl,--gc-sections $(TARGET_LDFLAGS)" \
	        INSTALL_ROOT=$(CURR_DIR)/root ath_tools wlanconfig)
	($(foreach var,$(strip $(QCAWLAN_MAKEOPTS)),export $(var);) \
		$(MAKEARCH) -C $(CURR_DIR)/halphy_tools/host/testcmd_tlv \
		-f makefile.linux WLAN_TOP=$(CURR_DIR))

tools_installonly:
	@echo "==============================INSTALLING TOOLS==================================="
	$(INSTALL_BIN) $(foreach tool,$(QCAWLAN_TOOL_LIST),$(CURR_DIR)/os/linux/tools/$(tool)) $(INSTALL_BIN_DEST)
	$(INSTALL_BIN) $(CURR_DIR)/halphy_tools/host/testcmd_tlv/Linux/athtestcmd $(INSTALL_BIN_DEST)
	$(INSTALL_DATA) $(CURR_DIR)/halphy_tools/host/testcmd_tlv/Linux/*.so $(INSTALL_LIB_DEST)

tools_install: tools_build tools_installonly

install_headers:
	@echo "================================INSTALL HEADERS====================================="
	cp -af $(foreach header,$(QCAWLAN_HEADERS),$(CURR_DIR)/$(header)) $(INSTALL_DEST)

all_build: env_prepare hal_build driver_build tools_build
	@echo "========================Finished qca-wifi-10.4 build================================"

all_installonly: driver_installonly tools_installonly
	@echo "========================Finished qca-wifi-10.4 install=============================="

all_install: all_build all_installonly

