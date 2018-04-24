include $(TOPDIR)/rules.mk

PKG:=qca-iface-mgr
PKG_NAME:=$(PKG)-10.4
PKG_SOURCE_PROTO:=git
PKG_BRANCH:=master
PKG_RELEASE:=1

include $(INCLUDE_DIR)/local-development.mk
ifeq ($(DUMP)$(PKG_VERSION),)
  PKG_REV:=$(shell git ls-remote $(PKG_SOURCE_URL) $(PKG_BRANCH) | cut -b -7)
  PKG_VERSION:=g$(PKG_REV)
endif

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package-version-override.mk
include $(INCLUDE_DIR)/package.mk

PKG_BUILD_DEPENDS:=qca-hostap-10.4

define Package/$(PKG_NAME)
  SECTION:=QCA
  CATEGORY:=QCA Proprietary software
  URL:=http://www.qca.qualcomm.com
  MAINTAINER:=Qualcomm Atheros
  TITLE:=QCA Interface manager daemon
  DEPENDS:=qca-hostap-10.4 @(!(PACKAGE_hostapd))
endef

define Package/$(PKG_NAME)/config
$(call Package/$(PKG_NAME)/override_source_path,$(PKG))
$(call Package/$(PKG_NAME)/override_version,$(PKG),$(PKG_SUPPORTED_VERSION))
endef

define Package/$(PKG_NAME)/description
  User Space application to manage interfaces
endef

TARGET_CFLAGS += \
		  -I$(STAGING_DIR)/usr/include

MAKEOPTS+= \
           $(TARGET_CONFIGURE_OPTS) \
	   CFLAGS="$(TARGET_CFLAGS)" \
           COPTS="$(TARGET_CFLAGS)" \
           WPA_PATH=$(STAGING_DIR)/usr/lib \
           LIBS="$(TARGET_LDFLAGS)"

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) $(MAKEOPTS)
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/iface-mgr $(1)/usr/sbin

	$(INSTALL_DIR) $(1)/lib/wifi
	$(INSTALL_DATA) ./files/iface_mgr.sh $(1)/lib/wifi
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
