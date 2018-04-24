include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=qca-nss-cfi
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

PKG_BUILD_DEPENDS:=ocf-crypto-headers

#
# There was a drastic change in the Crypto API of Linux kenrel in May 2015.
# In order to support the CFI drivers for kernel versions before May, 2015
# i.e. 4.0 we have created a 'v1.0' directory with the driver files that will
# work for kernels before 4.0.
# For kernels 4.0 and newer, we have created a 'v2.0' directory that contains
# the driver files which support the new changes in Crypto API.
#
ifeq ($(findstring 4.4, $(LINUX_VERSION)),)
 CFI_CRYPTOAPI_DIR:=cryptoapi/v1.0
 CFI_OCF_DIR:=ocf/v1.0
else
 CFI_CRYPTOAPI_DIR:=cryptoapi/v2.0
 CFI_OCF_DIR:=ocf/v1.0
endif

define KernelPackage/qca-nss-cfi
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  DEPENDS:=@TARGET_ipq806x||TARGET_ipq807x||TARGET_ipq +kmod-qca-nss-crypto +kmod-crypto-ocf @!LINUX_3_18
  TITLE:=Kernel driver for NSS cfi
  FILES:=$(PKG_BUILD_DIR)/$(CFI_OCF_DIR)/qca-nss-cfi-ocf.ko \
	 $(PKG_BUILD_DIR)/ipsec/qca-nss-ipsec.ko \
	 $(PKG_BUILD_DIR)/$(CFI_CRYPTOAPI_DIR)/qca-nss-cfi-cryptoapi.ko
  AUTOLOAD:=$(call AutoLoad,59,qca-nss-cfi-ocf qca-nss-cfi-cryptoapi qca-nss-ipsec)
endef

define KernelPackage/qca-nss-cfi/Description
This package contains a NSS cfi driver for QCA chipset
endef

EXTRA_CFLAGS+= \
	-DCONFIG_NSS_DEBUG_LEVEL=4 \
	-I$(STAGING_DIR)/usr/include/qca-nss-crypto \
	-I$(STAGING_DIR)/usr/include/crypto \
	-I$(STAGING_DIR)/usr/include/qca-nss-drv \

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		SUBDIRS="$(PKG_BUILD_DIR)" \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		CC="$(TARGET_CC)" \
		CFI_CRYPTOAPI_DIR=$(CFI_CRYPTOAPI_DIR) \
		CFI_OCF_DIR=$(CFI_OCF_DIR) \
		modules
endef

$(eval $(call KernelPackage,qca-nss-cfi))
