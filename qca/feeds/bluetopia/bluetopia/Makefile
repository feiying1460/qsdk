#
# Copyright (c) 2015 Qualcomm Atheros, Inc.
#
# All Rights Reserved.
# Qualcomm Atheros Confidential and Proprietary.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bluetopia
PKG_VERSION:=4.2.1.c1_9
PKG_DIST_VERSION:=4.2.1.c1
PKG_RELEASE:=1
PKG_FOLDER=BLUETOPIA


PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=http://tritium.qca.qualcomm.com/software/NBU/$(PKG_FOLDER)/
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_DIST_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_DIST_VERSION)

# Bluetopia Root Paths
export BLUETOPIA_SOURCE_PATH:=$(PKG_BUILD_DIR)/bt_host/Build
export BLUETOPIAPM_SOURCE_PATH:=$(PKG_BUILD_DIR)/bt_host_pm/Build
export BLUETOPIA_ROOT_PATH:=$(PKG_DIST_DIR)/Bluetopia_Dist
export BTPM_DIST_PATH:=$(PKG_DIST_DIR)/BluetopiaPM_Dist

# Bluetopia Core Include and Library Path
BLUETOPIA_INCLUDE_PATH:=$(BLUETOPIA_ROOT_PATH)/include
export BLUETOPIA_LIB_PATH:=$(BLUETOPIA_ROOT_PATH)/lib

# Bluetopia Debug Include and Library Path
BLUETOPIA_DEBUG_INCLUDE_PATH:=$(BLUETOPIA_ROOT_PATH)/debug/include
BLUETOPIA_DEBUG_LIB_PATH:=$(BLUETOPIA_ROOT_PATH)/debug/lib

# Bluetopia Profiles Root Path
export BLUETOPIA_PROFILE_ROOT_PATH:=$(BLUETOPIA_ROOT_PATH)/profiles

# Bluetopia VSER Include and Library Path
BLUETOPIA_VSER_INCLUDE_PATH:=$(BLUETOPIA_ROOT_PATH)/VSER/include
BLUETOPIA_VSER_LIB_PATH:=$(BLUETOPIA_ROOT_PATH)/VSER/lib

# Bluetopia VNET Include and Library Path
BLUETOPIA_VNET_INCLUDE_PATH:=$(BLUETOPIA_ROOT_PATH)/VNET/include
BLUETOPIA_VNET_LIB_PATH:=$(BLUETOPIA_ROOT_PATH)/VNET/lib

# Bluetopia SBC Include and Library Path
BLUETOPIA_SBC_INCLUDE_PATH:=$(BLUETOPIA_ROOT_PATH)/SBC/include
BLUETOPIA_SBC_LIB_PATH:=$(BLUETOPIA_ROOT_PATH)/SBC/lib

# Bluetopia Simple XML Parser Path
export BLUETOPIA_XML_PATH:=$(BLUETOPIA_ROOT_PATH)/XML/SS1SXMLP

# Bluetopia Distribution Path
export BLUETOPIA_PATH:=$(BLUETOPIA_ROOT_PATH)


include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=QCA
  CATEGORY:=QCA Proprietary software
  TITLE:=$(1) - QCA Bluetopia
  DEPENDS:=+libpthread 
endef

define Package/$(PKG_NAME)/description
  This package contains Bluetopia PM and Bluetopia binaries
endef

MAKE_FLAGS="CC=$$(TARGET_CC)" \
	   "GLOBLDFLAGS=$$(TARGET_LDFLAGS)" \
	   "GLOBCFLAGS=$$(TARGET_CFLAGS)"

INCLDIRS = -I$(BLUETOPIA_INCLUDE_PATH)        \
	   -I$(BLUETOPIA_DEBUG_INCLUDE_PATH)  \
	   -I$(BLUETOPIA_VSER_INCLUDE_PATH)   \
	   -I$(BLUETOPIA_VNET_INCLUDE_PATH)   \
	   -I$(BLUETOPIA_SBC_INCLUDE_PATH) 

LIBDIRS = -L$(BLUETOPIA_LIB_PATH)          \
	  -L$(BLUETOPIA_DEBUG_LIB_PATH)    \
	  -L$(BLUETOPIA_VSER_LIB_PATH)     \
	  -L$(BLUETOPIA_VNET_LIB_PATH)     \
	  -L$(BLUETOPIA_SBC_LIB_PATH)      

PM_MAKE_FLAGS="CC=$$(TARGET_CC)" \
	   "GLOBLDFLAGS=$$(TARGET_LDFLAGS)" \
	   "GLOBCFLAGS=$$(TARGET_CFLAGS)" \
	   "BLUETOPIA_INCLUDE_PATH=$$(BLUETOPIA_ROOT_PATH)/include"

define Build/Prepare
    $(TAR) xjvf $(TOPDIR)/dl/$(PKG_SOURCE) -C $(PKG_BUILD_DIR)
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host/Build/Linux/btpscert  -f BTPSCERT.mak all $(MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host/Build/Linux/btpsfile  -f BTPSFILE.mak all $(MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host/Build/Linux/btpskrnl  -f BTPSKRNL.mak all $(MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host/Build/Linux/btpsvend  -f BTPSVEND.mak all $(MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host/Build/Linux/debug/SS1BTDBG   -f SS1BTDBG.mak all $(MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host/Build/Linux/hcidrv_lin  -f HCIDRV.mak all $(MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host/Build/Linux/ss1btps  -f SS1BTPS.mak all $(MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host/Build/Linux/ss1btle  -f SS1BTPS.mak all $(MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host/Build/Linux/VSER/SS1SER  -f SS1SER.mak all $(MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host/Build/Linux/VSER/SS1VSER  -f SS1VSER.mak all $(MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host/Build/Linux/VNET/SS1VNET  -f SS1VNET.mak all $(MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host/Build/Linux/XML/SS1SXMLP  -f SS1SXMLP.mak all $(MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host/Build/Linux/profiles/GATT -f SS1BTGAT.mak all $(MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host/Build/Linux/profiles/GATT -f SS1BTGAT_LE.mak all $(MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host/Build/Linux/profiles_gatt/GAPS -f SS1BTGAP.mak all $(MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host/Build/Linux/profiles_gatt/DIS -f SS1BTDIS.mak all $(MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host/Build/Linux/profiles_gatt/sample/LinuxSPPLE -f LinuxSPPLE.mak all $(MAKE_FLAGS)


	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host/Build/Linux/sample/LinuxSCO -f LinuxSCO.mak all $(MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host/Build/Linux/sample/LinuxHCI -f LinuxHCI.mak all $(MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host/Build/Linux/sample/LinuxL2CAP -f LinuxL2CAP.mak all $(MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host/Build/Linux/sample/LinuxSDP -f LinuxSDP.mak all $(MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host/Build/Linux/sample/SS1BTVEN -f SS1BTVEN.mak all $(MAKE_FLAGS)

	echo 'creating Bluetopia Dist area'
	/bin/sh $(PKG_BUILD_DIR)/bt_host/Build/MakeFull_win.sh /d $(BLUETOPIA_ROOT_PATH) /s $(BLUETOPIA_SOURCE_PATH)
	echo 'done creating Bluetopia Dist area'

	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/btpmcert -f BTPMCERT.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/btpmdbg -f BTPMDBG.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/btpmerr -f BTPMERR.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/btpmset -f BTPMSET.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/btpmipc/client -f BTPMIPC.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/btpmipc/server -f BTPMIPC.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/btpmmodc/client -f BTPMMODC.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/btpmmodc/server -f BTPMMODC.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/btpmscom/client -f BTPMSCOM.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/btpmscom/server -f BTPMSCOM.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/btpmsppm/client -f BTPMSPPM.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/btpmsppm/server -f BTPMSPPM.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/btpmgatm/client -f BTPMGATM.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/btpmgatm/server -f BTPMGATM.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/btpmdevm/client -f BTPMDEVM.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/btpmdevm/server -f BTPMDEVM.mak all $(PM_MAKE_FLAGS)

	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/ss1btpml/client -f SS1BTPML.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/ss1btpml/server -f SS1BTPML.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/ss1btpm_10sec/client -f SS1BTPM_10S.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/ss1btpm_10sec/server -f SS1BTPM_10S.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/ss1btpm_1sec/client -f SS1BTPM_1S.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/ss1btpm_1sec/server -f SS1BTPM_1S.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/ss1btpm_100ms/client -f SS1BTPM_100MS.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/ss1btpm_100ms/server -f SS1BTPM_100MS.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/ss1btpm/client -f SS1BTPM.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/ss1btpm/server -f SS1BTPM.mak all $(PM_MAKE_FLAGS)

	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/sample/LinuxSPPLE_PM -f LinuxSPPLE_PM.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/sample/LinuxGATM -f LinuxGATM_CLT.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/sample/LinuxGATM -f LinuxGATM_SRV.mak all $(PM_MAKE_FLAGS)
	$(MAKE) -C $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/sample/LinuxDEVM -f LinuxDEVM.mak all $(PM_MAKE_FLAGS)

	echo 'creating BluetopiaPM Dist area with default interval 20sec'
	/bin/sh $(PKG_BUILD_DIR)/bt_host_pm/Build/MakeFull.sh /d $(BTPM_DIST_PATH) /s $(BLUETOPIAPM_SOURCE_PATH)
	echo 'done creating Bluetopia Dist area'

endef


define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/PS_KEY_CSR8811.txt $(1)/usr/bin
	$(INSTALL_BIN) ./files/bluetopia.init $(1)/etc/init.d/bluetopia
	$(INSTALL_BIN) \
	    $(PKG_BUILD_DIR)/bt_host/Build/Linux/sample/LinuxHCI/LinuxHCI $(1)/usr/bin/
	$(INSTALL_BIN) \
	    $(PKG_BUILD_DIR)/bt_host/Build/Linux/sample/LinuxL2CAP/LinuxL2CAP $(1)/usr/bin/
	$(INSTALL_BIN) \
	    $(PKG_BUILD_DIR)/bt_host/Build/Linux/sample/LinuxSCO/LinuxSCO $(1)/usr/bin/
	$(INSTALL_BIN) \
	    $(PKG_BUILD_DIR)/bt_host/Build/Linux/sample/LinuxSDP/LinuxSDP $(1)/usr/bin/
	$(INSTALL_BIN) \
	    $(PKG_BUILD_DIR)/bt_host/Build/Linux/sample/SS1BTVEN/libSS1BTVEN.a $(1)/usr/lib/
	$(INSTALL_BIN) \
	    $(PKG_BUILD_DIR)/bt_host/Build/Linux/profiles_gatt/sample/LinuxSPPLE/LinuxSPPLE $(1)/usr/bin
	$(INSTALL_BIN) \
	    $(PKG_BUILD_DIR)/bt_host/Build/Linux/profiles/GATT/libSS1BTGAT.a  $(1)/usr/bin
	$(INSTALL_BIN) \
	    $(PKG_BUILD_DIR)/bt_host/Build/Linux/profiles/GATT/libSS1BTGAT_LE.a  $(1)/usr/bin
	$(INSTALL_BIN) \
	    $(PKG_BUILD_DIR)/bt_host/Build/Linux/btpsvend/libBTPSVEND.a  $(1)/usr/bin
	$(INSTALL_BIN) \
	    $(PKG_BUILD_DIR)/bt_host/Build/Linux/btpsfile/libBTPSFILE.a  $(1)/usr/bin
	$(INSTALL_BIN) \
	    $(PKG_BUILD_DIR)/bt_host/Build/Linux/ss1btps/libSS1BTPS.a  $(1)/usr/bin
	$(INSTALL_BIN) \
	    $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/ss1btpm/server/SS1BTPM  $(1)/usr/bin
	$(INSTALL_BIN) \
	    $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/ss1btpm_10sec/server/SS1BTPM_10S  $(1)/usr/bin
	$(INSTALL_BIN) \
	    $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/ss1btpm_1sec/server/SS1BTPM_1S  $(1)/usr/bin
	$(INSTALL_BIN) \
	    $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/ss1btpm_100ms/server/SS1BTPM_100MS  $(1)/usr/bin
	$(INSTALL_BIN) \
	    $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/sample/LinuxSPPLE_PM/LinuxSPPLE_PM  $(1)/usr/bin
	$(INSTALL_BIN) \
	    $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/sample/LinuxGATM/LinuxGATM_CLT  $(1)/usr/bin
	$(INSTALL_BIN) \
	    $(PKG_BUILD_DIR)/bt_host_pm/Build/Linux/sample/LinuxDEVM/LinuxDEVM  $(1)/usr/bin
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
