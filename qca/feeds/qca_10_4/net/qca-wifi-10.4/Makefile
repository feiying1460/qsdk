include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG:=qca-wifi
PKG_NAME:=$(PKG)-10.4
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=ssh://qca-git01.qualcomm.com:29418/wifi/$(PKG_NAME).git
PKG_BRANCH:=master
PKG_RELEASE:=1

DRIVER_PATH:=$(TOPDIR)/qca/src/qca-wifi-10.4
FW_INCLUDE_PATH:=$(TOPDIR)/dl/include
HALPHY_TOOLS_PATH:=$(TOPDIR)/dl/wlan/halphy_tools

include $(INCLUDE_DIR)/local-development.mk
ifeq ($(DUMP)$(PKG_VERSION),)
  PKG_REV:=$(shell git ls-remote $(PKG_SOURCE_URL) $(PKG_BRANCH) | cut -b -7)
  PKG_VERSION:=g$(PKG_REV)
endif

PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)-$(BUILD_VARIANT)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package-version-override.mk
include $(INCLUDE_DIR)/package.mk

FW_hw2_asic:=qca-wifi-fw-hw2-10.4-asic
FW_hw3_asic:=qca-wifi-fw-hw3-10.4-asic
FW_hw4_asic:=qca-wifi-fw-hw4-10.4-asic
FW_hw4_emu_bb:=qca-wifi-fw-hw4-10.4-emu_bb
FW_hw4_emu_m2m:=qca-wifi-fw-hw4-10.4-emu_m2m
FW_hw5_asic:=qca-wifi-fw-hw5-10.4-asic
FW_hw6_asic:=qca-wifi-fw-hw6-10.4-asic
FW_hw5_emu_bb:=qca-wifi-fw-hw5-10.4-emu_bb
FW_hw5_emu_m2m:=qca-wifi-fw-hw5-10.4-emu_m2m
FW_hw7_asic:=qca-wifi-fw-hw7-10.4-asic
FW_hw8_asic:=qca-wifi-fw-hw8-10.4-asic
FW_hw9_asic:=qca-wifi-fw-hw9-10.4-asic

FW_10_4:=$(FW_hw2_asic) $(FW_hw3_asic) $(FW_hw4_emu_bb) $(FW_hw4_emu_m2m) $(FW_hw4_asic) $(FW_hw5_asic) $(FW_hw6_asic) $(FW_hw5_emu_bb) $(FW_hw5_emu_m2m) $(FW_hw7_asic) $(FW_hw8_asic) $(FW_hw9_asic)

#Set QCAWLAN_MAKEOPTS according to selected BUILD_VARIANT and platform
ifneq ($(KERNEL_BUILD_DIR),)
export DRIVER_PATH
include $(DRIVER_PATH)/config.mk
endif

#########################################################
############ WLAN DRIVER BUILD CONFIGURATION ############
#########################################################



ifeq ($(ARCH),mips)
BIG_ENDIAN_HOST=1
endif
ifeq ($(ARCH),arm)
BIG_ENDIAN_HOST=0
endif



QCAWLAN_MODULE_NAME:= $(notdir $(basename $(strip $(QCAWLAN_MODULE_LIST))))

#########################################################
##################### CONFIG RULES ######################
#########################################################

define KernelPackage/$(PKG_NAME)/Default
  SECTION:=QCA
  CATEGORY:=QCA Proprietary software
  URL:=http://www.qca.qualcomm.com
  MAINTAINER:=Qualcomm Atheros
  TITLE:=QCA Wireless LAN Driver
  DEPENDS:=+libgcc +libc +wireless-tools +librt +iproute2 \
	  @(!(PACKAGE_kmod-ath&&PACKAGE_kmod-mac80211))
  PKG_BUILD_DEPENDS+=$(FW_10_4)
  FILES:= $(strip $(QCAWLAN_MODULE_LIST))
  MENU:=1
  PROVIDES:=kmod-qca-wifi-10.4
endef

$(eval $(call RequireCommand,uuencode, \
	Please install sharutils which provides uuencode required for build \
))

define KernelPackage/$(PKG_NAME)/Description/Default
  This package contains a driver for QCA WLAN chipsets
  It also installs the QCA WLAN tools, such as:
  - wlanconfig
  - athstats
  - pktlogconf
  - ...
endef

define KernelPackage/$(PKG_NAME)/config/Default
$(call Package/$(PKG_NAME)/override_source_path,kmod-$(PKG_NAME)$(1))
$(call Package/$(PKG_NAME)/override_version,kmod-$(PKG_NAME)$(1),$(PKG_SUPPORTED_VERSION))
endef

#########################################################
################### INSTALLDEV RULES ####################
#########################################################
define Build/InstallDev
	$(INSTALL_DIR) $(STAGING_DIR)/usr/include
	$(MAKE) -C $(PKG_BUILD_DIR) INSTALL_DEST="$(STAGING_DIR)/usr/include/" install_headers
endef

#########################################################
################# BUILD/INSTALL RULES ###################
#########################################################
Hooks/Prepare/Pre += qca-wifi_update_patches_version
define qca-wifi_update_patches_version

	[ ! -h patches ] || rm patches
	[ ! -d patches-$(PKG_BRANCH) ] || \
		ln -s patches-$(PKG_BRANCH) patches
endef

define Build/Compile
		export FW_INCLUDE_PATH="$(FW_INCLUDE_PATH)"; \
		export HALPHY_TOOLS_PATH="$(HALPHY_TOOLS_PATH)"; \
		export MAKE="$(MAKE)"; \
		export LINUX_VERSION="$(LINUX_VERSION)"; \
		export LINUX_DIR="$(LINUX_DIR)"; \
		export LINUX_SRC_DIR="$(LINUX_SRC_DIR)"; \
		export ARCH="$(ARCH)"; \
		export BUILD_VARIANT="$(BUILD_VARIANT)"; \
		export TARGET_CROSS="$(TARGET_CROSS)"; \
		export QCA_PLATFORM="$(ARCH_PACKAGES)"; \
		export BIG_ENDIAN_HOST="$(BIG_ENDIAN_HOST)"; \
		export TARGET_CFLAGS="$(TARGET_CFLAGS)"; \
		export TARGET_LDFLAGS="$(TARGET_LDFLAGS)"; \
		$(MAKE) -C $(PKG_BUILD_DIR) src_prepare all_build
endef

define KernelPackage/$(PKG_NAME)/install/Default
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/usr/lib
	$(INSTALL_DIR) $(1)/lib/wifi
	$(INSTALL_DIR) $(1)/lib/sbin
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/init.d

	$(INSTALL_DATA) ./files/qcawifi.sh $(1)/lib/wifi

	echo $(QCAWLAN_MODULE_NAME) | sed 's, ,\n,g' > ./files/qca-wifi-modules
	$(INSTALL_DATA) ./files/qca-wifi-modules $(1)/lib/wifi

	$(INSTALL_DATA) ./files/qcawifi_countrycode.txt $(1)/lib/wifi

	$(INSTALL_BIN) ./files/wifi_try $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/wifi_try $(1)/lib/sbin/

	$(INSTALL_CONF) ./files/ssid-steering.config $(1)/etc/config/ssid-steering
	$(INSTALL_BIN) ./files/ssid_steering.init $(1)/etc/init.d/ssid_steering

	[ ! -d files-$(PKG_BRANCH) ] || \
		$(CP) ./files-$(PKG_BRANCH)/* $(1)/
	export INSTALL_BIN="$(INSTALL_BIN)"; \
	export INSTALL_DATA="$(INSTALL_DATA)"; \
	$(MAKE) -C $(PKG_BUILD_DIR) QCAWLAN_TOOL_LIST="$(QCAWLAN_TOOL_LIST)" INSTALL_BIN_DEST="$(1)/usr/sbin" INSTALL_LIB_DEST="$(1)/usr/lib" tools_installonly
endef

#########################################################
################# VARIANTS DEFINITION ###################
#########################################################

# Default variant (Akronite only)
define KernelPackage/$(PKG_NAME)-akronite-perf
$(call KernelPackage/$(PKG_NAME)/Default)
  VARIANT:=akronite-perf
  DEPENDS+=@TARGET_ipq806x +TARGET_ipq806x:kmod-qca-nss-drv
endef

define KernelPackage/$(PKG_NAME)-akronite-perf/Description
$(call define KernelPackage/$(PKG_NAME)/Description/Default)
endef

define KernelPackage/$(PKG_NAME)-akronite-perf/config
$(call KernelPackage/$(PKG_NAME)/config/Default,-akronite-perf)
endef

define KernelPackage/$(PKG_NAME)-akronite-perf/install
$(call KernelPackage/$(PKG_NAME)/install/Default,$(1))
endef
$(eval $(call KernelPackage,$(PKG_NAME)-akronite-perf))

# Emulation variant for ipq806x
define KernelPackage/$(PKG_NAME)-akronite-perf-emu
$(call KernelPackage/$(PKG_NAME)/Default)
  VARIANT:=akronite-perf-emu
  DEPENDS+=@TARGET_ipq806x +TARGET_ipq806x:kmod-qca-nss-drv
endef

define KernelPackage/$(PKG_NAME)-akronite-perf-emu/Description
$(call define KernelPackage/$(PKG_NAME)/Description/Default)
endef

define KernelPackage/$(PKG_NAME)-akronite-perf-emu/config
$(call KernelPackage/$(PKG_NAME)/config/Default,-akronite-perf-emu)
endef

define KernelPackage/$(PKG_NAME)-akronite-perf-emu/install
$(call KernelPackage/$(PKG_NAME)/install/Default,$(1))
endef
$(eval $(call KernelPackage,$(PKG_NAME)-akronite-perf-emu))

# Perf variant
define KernelPackage/$(PKG_NAME)-perf
$(call KernelPackage/$(PKG_NAME)/Default)
  VARIANT:=perf
  DEPENDS+=@TARGET_ar71xx
endef

define KernelPackage/$(PKG_NAME)-perf/Description
$(call define KernelPackage/$(PKG_NAME)/Description/Default)
endef

define KernelPackage/$(PKG_NAME)-perf/config
$(call KernelPackage/$(PKG_NAME)/config/Default,-perf)
endef

define KernelPackage/$(PKG_NAME)-perf/install
$(call KernelPackage/$(PKG_NAME)/install/Default,$(1))
endef
$(eval $(call KernelPackage,$(PKG_NAME)-perf))

# New datapath variant
define KernelPackage/$(PKG_NAME)-unified-perf
$(call KernelPackage/$(PKG_NAME)/Default)
  VARIANT:=unified-perf
  DEPENDS+=@TARGET_ar71xx
endef

define KernelPackage/$(PKG_NAME)-unified-perf/Description
$(call define KernelPackage/$(PKG_NAME)/Description/Default)
endef

define KernelPackage/$(PKG_NAME)-unified-perf/config
$(call KernelPackage/$(PKG_NAME)/config/Default,-unified-perf)
endef

define KernelPackage/$(PKG_NAME)-unified-perf/install
$(call KernelPackage/$(PKG_NAME)/install/Default,$(1))
endef
$(eval $(call KernelPackage,$(PKG_NAME)-unified-perf))

# Dakota variant
define KernelPackage/$(PKG_NAME)-dakota-perf
$(call KernelPackage/$(PKG_NAME)/Default)
  VARIANT:=dakota-perf
  DEPENDS+=@TARGET_ipq806x +TARGET_ipq806x:kmod-qca-nss-drv
endef

define KernelPackage/$(PKG_NAME)-dakota-perf/Description
$(call define KernelPackage/$(PKG_NAME)/Description/Default)
endef

define KernelPackage/$(PKG_NAME)-dakota-perf/config
$(call KernelPackage/$(PKG_NAME)/config/Default,-dakota-perf)
endef

define KernelPackage/$(PKG_NAME)-dakota-perf/install
$(call KernelPackage/$(PKG_NAME)/install/Default,$(1))
endef
$(eval $(call KernelPackage,$(PKG_NAME)-dakota-perf))

# Unified variant
define KernelPackage/$(PKG_NAME)-unified-profile
$(call KernelPackage/$(PKG_NAME)/Default)
  VARIANT:=unified-profile
  DEPENDS+=@TARGET_ipq806x +TARGET_ipq806x:kmod-qca-nss-drv
endef

define KernelPackage/$(PKG_NAME)-unified-profile/Description
$(call define KernelPackage/$(PKG_NAME)/Description/Default)
endef

define KernelPackage/$(PKG_NAME)-unified-profile/config
$(call KernelPackage/$(PKG_NAME)/config/Default,-unified-profile)
endef

define KernelPackage/$(PKG_NAME)-unified-profile/install
$(call KernelPackage/$(PKG_NAME)/install/Default,$(1))
endef
$(eval $(call KernelPackage,$(PKG_NAME)-unified-profile))

# MIPS Lowmem variant
define KernelPackage/$(PKG_NAME)-lowmem-profile
$(call KernelPackage/$(PKG_NAME)/Default)
  VARIANT:=lowmem-profile
  DEPENDS+=@TARGET_ar71xx
endef

define KernelPackage/$(PKG_NAME)-lowmem-profile/Description
$(call define KernelPackage/$(PKG_NAME)/Description/Default)
endef

define KernelPackage/$(PKG_NAME)-lowmem-profile/config
$(call KernelPackage/$(PKG_NAME)/config/Default,-unified-perf)
endef

define KernelPackage/$(PKG_NAME)-lowmem-profile/install
$(call KernelPackage/$(PKG_NAME)/install/Default,$(1))
endef
$(eval $(call KernelPackage,$(PKG_NAME)-lowmem-profile))

# Fulloffload variant
define KernelPackage/$(PKG_NAME)-fulloffload
$(call KernelPackage/$(PKG_NAME)/Default)
 VARIANT:=fulloffload
 DEPENDS+=@TARGET_ar71xx
endef

define KernelPackage/$(PKG_NAME)-fulloffload/Description
$(call define KernelPackage/$(PKG_NAME)/Description/Default)
endef

define KernelPackage/$(PKG_NAME)-fulloffload/config
$(call KernelPackage/$(PKG_NAME)/config/Default,-fulloffload)
endef

define KernelPackage/$(PKG_NAME)-fulloffload/install
$(call KernelPackage/$(PKG_NAME)/install/Default,$(1))
endef
$(eval $(call KernelPackage,$(PKG_NAME)-fulloffload))
