include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=qca-nss-drv
PKG_SOURCE_PROTO:=git
PKG_BRANCH:=master
PKG_RELEASE:=2

include $(INCLUDE_DIR)/local-development.mk
ifeq ($(DUMP)$(PKG_VERSION),)
  PKG_VERSION:=$(shell git ls-remote $(PKG_SOURCE_URL) $(PKG_BRANCH) | cut -b -7)
endif
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define KernelPackage/qca-nss-drv
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  DEPENDS:=+TARGET_ipq806x_QSDK_Deluxe:kmod-qca-nss-dp \
	+TARGET_ipq807x:kmod-qca-nss-dp \
	+TARGET_ipq_ipq807x:kmod-qca-nss-dp \
	+TARGET_ipq_ipq807x_64:kmod-qca-nss-dp \
	+TARGET_ipq806x_QSDK_Premium:kmod-qca-nss-gmac \
	+TARGET_ipq806x_QSDK_Deluxe_Temp:kmod-qca-nss-gmac \
	+TARGET_ipq_ipq806x:kmod-qca-nss-gmac \
	+TARGET_ipq_ipq40xx:kmod-qca-nss-gmac \
	+kmod-ppp +kmod-pppoe @!LINUX_3_18
  TITLE:=Kernel driver for NSS (core driver)
  FILES:=$(PKG_BUILD_DIR)/qca-nss-drv.ko
  AUTOLOAD:=$(call AutoLoad,32,qca-nss-drv)
endef

define KernelPackage/qca-nss-drv/install
	$(INSTALL_DIR) $(1)/lib/debug
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/sysctl.d
	$(INSTALL_DIR) $(1)/etc/hotplug.d/firmware
	$(INSTALL_DIR) $(1)/etc/config

	$(INSTALL_BIN) ./files/qca-nss-drv.debug $(1)/lib/debug/qca-nss-drv
	$(INSTALL_BIN) ./files/qca-nss-drv.init $(1)/etc/init.d/qca-nss-drv
	$(INSTALL_BIN) ./files/qca-nss-drv.sysctl $(1)/etc/sysctl.d/qca-nss-drv.conf
	$(INSTALL_BIN) ./files/qca-nss-drv.hotplug $(1)/etc/hotplug.d/firmware/10-qca-nss-fw
	$(INSTALL_BIN) ./files/qca-nss-drv.conf $(1)/etc/config/nss

endef

define KernelPackage/qca-nss-drv/Description
This package contains a NSS driver for QCA chipset
endef

define Build/InstallDev
	mkdir -p $(1)/usr/include/qca-nss-drv
	$(CP) $(PKG_BUILD_DIR)/exports/* $(1)/usr/include/qca-nss-drv/
endef

EXTRA_CFLAGS+= -I$(STAGING_DIR)/usr/include/qca-nss-gmac -I$(STAGING_DIR)/usr/include/qca-nss-dp

# Only Deluxe profile compiles ipq807x, else we compile ipq806x, this will be replaced by subtarget framework from QSDK team
ifeq ($(CONFIG_TARGET_ipq806x_QSDK_Deluxe),y)
subtarget:=ipq807x
else
subtarget:=ipq806x
endif

ifeq ($(CONFIG_TARGET_ipq807x),y)
subtarget:=ipq807x
endif

ifeq ($(CONFIG_TARGET_ipq),y)
subtarget:=$(SUBTARGET)
endif

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		SUBDIRS="$(PKG_BUILD_DIR)" \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" SoC="$(subtarget)" \
		modules
endef

$(eval $(call KernelPackage,qca-nss-drv))
