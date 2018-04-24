include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=qca-mcs-apps
PKG_RELEASE:=1

include $(INCLUDE_DIR)/local-development.mk
ifeq ($(DUMP)$(PKG_VERSION),)
  PKG_REV:=$(shell git ls-remote $(PKG_SOURCE_URL) $(PKG_BRANCH) | cut -b -7)
  PKG_VERSION:=g$(PKG_REV)
endif
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

WIFI_10_4_U:=PACKAGE_kmod-qca-wifi-10.4-unified-profile
WIFI_10_4_AK:=PACKAGE_kmod-qca-wifi-10.4-akronite-perf
WIFI_10_4_DK:=PACKAGE_kmod-qca-wifi-10.4-dakota-perf
WIFI_10_2_MIPS:=PACKAGE_kmod-qca-wifi-perf
WIFI_10_2_ARM:=PACKAGE_kmod-qca-wifi-akronite-perf
SSDK_NOHNAT:=PACKAGE_kmod-qca-ssdk-nohnat
SSDK_HNAT:=PACKAGE_kmod-qca-ssdk-hnat

WIFI_PKGS:=$(WIFI_10_4_U)||$(WIFI_10_4_AK)||$(WIFI_10_4_DK)||$(WIFI_10_2_MIPS)||$(WIFI_10_2_ARM)
PKG_BUILD_DEPENDS:=$(WIFI_10_4_U):kmod-qca-wifi-10.4 $(WIFI_10_4_AK):kmod-qca-wifi-10.4 $(WIFI_10_2_MIPS):kmod-qca-wifi \
	$(WIFI_10_2_ARM):kmod-qca-wifi $(WIFI_10_4_DK):kmod-qca-wifi-10.4
SSDK_PKGS:=$(SSDK_NOHNAT)||$(SSDK_HNAT)
PKG_BUILD_DEPENDS+=$(SSDK_NOHNAT):kmod-qca-ssdk-nohnat $(SSDK_HNAT):kmod-qca-ssdk-hnat

QCAMCS_MAKE_OPTS:= \
        CROSS=$(TARGET_CROSS) \
        GWLIB=$(STAGING_DIR)/usr/lib \
        MCSTOP=$(PKG_BUILD_DIR) \
        GWINCLUDE=$(STAGING_DIR)/usr/include/hyficommon \
        ATHDIR=$(STAGING_DIR)/usr/include \
        KMCDIR=$(STAGING_DIR)/usr/include/qca-mcs \
        QCASSDKDIR=$(STAGING_DIR)/usr/include/qca-ssdk \
        INSTALL_ROOT=$(PKG_BUILD_DIR)/install \
        STAGING_DIR=$(STAGING_DIR) \
	TARGET_CFLAGS="$(TARGET_CFLAGS)" \
	TARGET_LDFLAGS="$(TARGET_LDFLAGS)"

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/package-version-override.mk

define Package/qca-mcs-apps/config
  $(call Package/$(PKG_NAME)/override_version,$(PKG_NAME))
  $(call Package/$(PKG_NAME)/override_source_path,$(PKG_NAME))
endef

define Package/qca-mcs-apps
  SECTION:=QCA
  CATEGORY:=QCA Proprietary software
  URL:=http://www.qca.qualcomm.com
  MAINTAINER:=Qualcomm Atheros
  DEPENDS:=@$(WIFI_PKGS) +kmod-qca-mcs \
	   +libhyficommon +libpthread @$(SSDK_PKGS)
  TITLE:=IGMP/MLD snooping daemon and tools
endef

define Package/qca-mcs-apps/description
  This package installs the IGMP/MLD snooping daemon and tools
endef


define Build/Compile
	mkdir -p $(PKG_BUILD_DIR)/install/sbin
	$(MAKE) -C $(PKG_BUILD_DIR) $(strip $(QCAMCS_MAKE_OPTS)) subdirs
endef

define Package/qca-mcs-apps/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/install/sbin/mcsd $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/install/sbin/mcsctl $(1)/usr/sbin
	$(INSTALL_BIN) ./files/mcst $(1)/usr/sbin/mcst
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/mcsd.init $(1)/etc/init.d/mcsd
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_BIN) ./files/mcsd.config $(1)/etc/config/mcsd
	$(INSTALL_DIR) $(1)/etc/hotplug.d/net
	$(INSTALL_BIN) ./files/mcsd.hotplug $(1)/etc/hotplug.d/net/28-mcsd
endef

$(eval $(call BuildPackage,qca-mcs-apps))
