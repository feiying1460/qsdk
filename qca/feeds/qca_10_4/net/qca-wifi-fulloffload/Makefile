include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=qca-wifi-fulloffload
PKG_SOURCE:=fulloffload-driver-2.9.2.069.tar.bz2
PKG_SOURCE_URL:=http://tritium.qca.qualcomm.com/software/NBU/QCA9558.ILQ.2.1/
PKG_VERSION:=2.9.2.069
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/$(PKG_NAME)-$(BUILD_VARIANT)-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=PACKAGE_kmod-qca-wifi-10.4-unified-perf:qca-wifi-10.4 PACKAGE_kmod-qca-wifi-10.4-fulloffload:qca-wifi-10.4
include $(INCLUDE_DIR)/package-version-override.mk
include $(INCLUDE_DIR)/local-development.mk

WLAN_DRIVER_PATH:=$(TOPDIR)/qca/src/qca-wifi-10.4

ifeq ($(DUMP)$(PKG_VERSION),)
  PKG_REV:=$(shell git ls-remote $(PKG_SOURCE_URL) $(PKG_BRANCH) | cut -b -7)
  PKG_VERSION:=g$(PKG_REV)
endif

include $(INCLUDE_DIR)/package.mk

ifeq ($(ARCH),mips)
BIG_ENDIAN_HOST=1
endif
ifeq ($(ARCH),arm)
BIG_ENDIAN_HOST=0
endif

LOCAL_TYPE=$(strip \
		$(if $(findstring host,$(BUILD_VARIANT)),host, \
		target \
	))

#QCAWLAN_MODULE_NAME:= $(notdir $(basename $(strip $(QCAWLAN_MODULE_LIST))))
QCAWLAN_FULLOFFLOAD_MODULE_LIST:=
ifneq ($(LOCAL_TYPE),target)
QCAWLAN_FULLOFFLOAD_MODULE_LIST+=$(PKG_BUILD_DIR)/host/build/linux/thin_driver/atd.$(LINUX_KMOD_SUFFIX)
QCAWLAN_FULLOFFLOAD_MODULE_LIST+=$(PKG_BUILD_DIR)/host/build/linux/hif/gmac/hif_gmac.$(LINUX_KMOD_SUFFIX)
QCAWLAN_FULLOFFLOAD_MODULE_LIST+=$(PKG_BUILD_DIR)/host/build/linux/fw_loader/mdio/mdio.$(LINUX_KMOD_SUFFIX)
QCAWLAN_FULLOFFLOAD_MODULE_LIST+=$(PKG_BUILD_DIR)/host/build/linux/fw_loader/gmac/fwd.$(LINUX_KMOD_SUFFIX)
QCAWLAN_FULLOFFLOAD_MODULE_LIST+=$(PKG_BUILD_DIR)/host/build/linux/adf/adf.$(LINUX_KMOD_SUFFIX)
endif
ifneq ($(LOCAL_TYPE),host)
QCAWLAN_FULLOFFLOAD_MODULE_LIST+=$(PKG_BUILD_DIR)/target/linux/build/wasp/thin_driver/atd.$(LINUX_KMOD_SUFFIX)
QCAWLAN_FULLOFFLOAD_MODULE_LIST+=$(PKG_BUILD_DIR)/target/linux/build/wasp/hif_gmac/hif_gmac.$(LINUX_KMOD_SUFFIX)
endif

QCAWLAN_FULLOFFLOAD_MODULE_NAME:= $(notdir $(basename $(strip $(QCAWLAN_FULLOFFLOAD_MODULE_LIST))))

MAKEOPTS+= \
	$(TARGET_CONFIGURE_OPTS) \
	WLAN_TOP=$(STAGING_DIR)/usr \
	COPTS="$(TARGET_CFLAGS) -I. -I$(PKG_BUILD_DIR)/include -I$(PKG_BUILD_DIR)/apps/bypass/include -I$(PKG_BUILD_DIR)/apps/acfg/include"

#########################################################
##################### CONFIG RULES ######################
#########################################################

define KernelPackage/$(PKG_NAME)-host
  SECTION:=QCA
  CATEGORY:=QCA Proprietary software
  URL:=http://www.qca.qualcomm.com
  MAINTAINER:=Qualcomm Atheros
  TITLE:=QCA Wireless Fulloffload Host Driver
  DEPENDS:=+libgcc +libc
  FILES:= $(strip $(QCAWLAN_FULLOFFLOAD_MODULE_LIST))
  MENU:=1
  VARIANT:=host
endef

define KernelPackage/$(PKG_NAME)-host/Description
ppp  This package contains the fulloffload host for QCA WLAN chipsets
endef

define KernelPackage/$(PKG_NAME)-host/config
$(call Package/$(PKG_NAME)/override_source_path,kmod-$(PKG_NAME)$(1))
$(call Package/$(PKG_NAME)/override_version,kmod-$(PKG_NAME)$(1),$(PKG_SUPPORTED_VERSION))
endef

define KernelPackage/$(PKG_NAME)-target
  SECTION:=QCA
  CATEGORY:=QCA Proprietary software
  URL:=http://www.qca.qualcomm.com
  MAINTAINER:=Qualcomm Atheros
  TITLE:=QCA Wireless Fulloffload Target Driver
  DEPENDS:=+libgcc +libc
  FILES:= $(strip $(QCAWLAN_FULLOFFLOAD_MODULE_LIST))
  MENU:=1
  VARIANT:=target
endef

define KernelPackage/$(PKG_NAME)-target/Description
  This package contains the fulloffload for QCA WLAN chipsets
endef

define KernelPackage/$(PKG_NAME)-target/config
$(call Package/$(PKG_NAME)/override_source_path,kmod-$(PKG_NAME)$(1))
$(call Package/$(PKG_NAME)/override_version,kmod-$(PKG_NAME)$(1),$(PKG_SUPPORTED_VERSION))
endef

#########################################################
################### INSTALLDEV RULES ####################
#########################################################
define Build/InstallDev
	$(INSTALL_DIR) $(STAGING_DIR)/usr/include
endef

#########################################################
################# BUILD/INSTALL RULES ###################
#########################################################
define Build/Prepare
	$(TAR) xjvf $(TOPDIR)/dl/$(PKG_SOURCE) -C $(TOPDIR)/dl
	$(CP) $(TOPDIR)/dl/fulloffload_build/lsdk/drivers/full_offload/* $(PKG_BUILD_DIR)
	$(CP) $(TOPDIR)/qca/src/qca-wifi-10.4/adf $(PKG_BUILD_DIR)
	mkdir -p ./patches
	$(CP) $(TOPDIR)/qca/src/qca-wifi-10.4/patches/fulloffload/* patches/
	$(Build/Patch)
endef

define Build/Compile
	$(Build/Compile/qca-wifi-fulloffload-$(LOCAL_TYPE))
endef

define Build/Compile/qca-wifi-fulloffload-host
		export MAKE="$(MAKE)"; \
		export ARCH="$(ARCH)"; \
		export BIG_ENDIAN_HOST="$(BIG_ENDIAN_HOST)"; \
		export TOOLPREFIX="$(TARGET_CROSS)"; \
		export KERNELARCH="$(LINUX_KARCH)"; \
		export KERNELVER="$(LINUX_VERSION)"; \
		export KBUILDPATH="$(LINUX_SRC_DIR)"; \
		export KERNELPATH="$(LINUX_DIR)"; \
		export WLAN_DRIVER_PATH="$(WLAN_DRIVER_PATH)"; \
		export NO_SIMPLE_CONFIG=1; \
		$(MAKE) -C $(PKG_BUILD_DIR)/host/build/linux -I$(STAGING_DIR)/usr/include TARGET=mipsisa32-be-elf BUS=gmac all
		$(MAKE) -C $(PKG_BUILD_DIR)/apps/acfg/target/linux/ lib $(MAKEOPTS)
		$(MAKE) -C $(PKG_BUILD_DIR)/apps/bypass/host/linux $(MAKEOPTS)
endef

define Build/Compile/qca-wifi-fulloffload-target
		export MAKE="$(MAKE)"; \
		export ARCH="$(ARCH)"; \
		export BIG_ENDIAN_HOST="$(BIG_ENDIAN_HOST)"; \
		export TOOLPREFIX="$(TARGET_CROSS)"; \
		export KERNELARCH="$(LINUX_KARCH)"; \
		export KERNELVER="$(LINUX_VERSION)"; \
		export KBUILDPATH="$(LINUX_SRC_DIR)"; \
		export KERNELPATH="$(LINUX_DIR)"; \
		export WLAN_DRIVER_PATH="$(WLAN_DRIVER_PATH)"; \
		export NO_SIMPLE_CONFIG=1; \
		$(MAKE) -C $(PKG_BUILD_DIR)/target/linux/build/wasp -I$(STAGING_DIR)/usr/include TARGET=mipsisa32-be-elf BUS=gmac BOOT=FLASH_MODE
		$(MAKE) -C $(PKG_BUILD_DIR)/apps/acfg/target/linux/ lib $(MAKEOPTS)
		$(MAKE) -C $(PKG_BUILD_DIR)/apps/bypass/target/linux/ $(MAKEOPTS)
endef

define KernelPackage/$(PKG_NAME)-host/install
	mkdir -p ./files
	echo $(QCAWLAN_FULLOFFLOAD_MODULE_NAME) | sed 's, ,\n,g' > ./files/qca-wifi-fulloffload-modules
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/apps/bypass/host/linux/byp_cli $(1)/usr/sbin
endef

define KernelPackage/$(PKG_NAME)-target/install
	mkdir -p ./files
	echo $(QCAWLAN_FULLOFFLOAD_MODULE_NAME) | sed 's, ,\n,g' > ./files/qca-wifi-fulloffload-modules
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/apps/bypass/target/linux/bypd $(1)/usr/sbin
endef

# Host variant
$(eval $(call KernelPackage,$(PKG_NAME)-host))

# Target variant
$(eval $(call KernelPackage,$(PKG_NAME)-target))
