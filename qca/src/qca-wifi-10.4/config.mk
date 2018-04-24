#
# Copyright (c) 2014 Qualcomm Atheros, Inc..
#
# All Rights Reserved.
# Qualcomm Atheros Confidential and Proprietary.
#

LINUX_KMOD_SUFFIX:=ko
QCAWLAN_MODULE_LIST:=
PWD:=$(shell pwd)
# These two functions are used to define options based on WLAN config
if_opt_set=       $(if $(filter $(1)=1,$(QCAWLAN_MAKEOPTS)),$(2),)
if_opt_clear=     $(if $(filter $(1)=0,$(QCAWLAN_MAKEOPTS)),$(2),)

# Use the function below to add driver opts depending on menuconfig values
append_if_notnull=QCAWLAN_MAKEOPTS+=$(if $(call qstrip,$(1)),$(2),$(3))

ifneq ($(BUILD_VARIANT),)
ifneq ($(DRIVER_PATH),)
QCAWLAN_MAKEOPTS:=$(shell cat $(DRIVER_PATH)/os/linux/configs/config.wlan.$(subst -,.,$(BUILD_VARIANT)))
else
QCAWLAN_MAKEOPTS:=$(shell cat $(PWD)/os/linux/configs/config.wlan.$(subst -,.,$(BUILD_VARIANT)))
endif
endif

QCAWLAN_HEADERS:= \
   cmn_dev/qdf/inc/qdf_types.h \
   cmn_dev/qdf/inc/qdf_status.h \
   cmn_dev/qdf/linux/src/i_qdf_types.h \
   asf/include/asf_amem.h \
   offload/include/a_types.h \
   offload/include/athdefs.h \
   offload/include/wlan_defs.h \
   offload/include/ol_txrx_stats.h \
   cmn_dev/dp/inc/cdp_txrx_stats_struct.h \
   include/ieee80211_defines.h \
   include/_ieee80211.h \
   include/ieee80211.h \
   include/ieee80211_wnm_proto.h \
   include/ieee80211_band_steering_api.h \
   include/if_upperproto.h \
   include/compat.h \
   include/wlan_opts.h \
   include/sys/queue.h \
   include/ieee80211_phytype.h \
   include/ieee80211_rrm.h \
   hal/linux/ah_osdep.h \
   os/linux/include/ath_ald_external.h \
   os/linux/include/ieee80211_external.h \
   os/linux/include/ieee80211_ioctl.h \
   os/linux/include/ieee80211_ev.h \
   os/linux/include/ieee80211_wpc.h \
   os/linux/tools/athrs_ctrl.h \
   lmac/ath_dev/if_athioctl.h \
   lmac/dfs/dfs_ioctl.h \
   lmac/spectral/spectral_ioctl.h \
   include/acfg_wsupp_api.h \
   include/acfg_event_types.h \
   include/acfg_event.h \
   include/acfg_api_types.h \
   include/appbr_types.h \
   include/bypass_types.h \
   os/linux/src/ath_band_steering.h \
   os/linux/src/ath_ssid_steering.h \
   include/ieee80211_external_config.h

#########################################################
############ WLAN DRIVER BUILD CONFIGURATION ############
#########################################################
# Module list
# This list is filled dynamically based on the WLAN configuration
# It depends on the content of the wlan config file (.profile)
QCAWLAN_MODULE_LIST+=$(strip $(call if_opt_set, WIFI_MEM_MANAGER_SUPPORT, \
	$(PKG_BUILD_DIR)/os/linux/mem/mem_manager.$(LINUX_KMOD_SUFFIX)))
QCAWLAN_MODULE_LIST+=$(PKG_BUILD_DIR)/asf/asf.$(LINUX_KMOD_SUFFIX)
QCAWLAN_MODULE_LIST+=$(PKG_BUILD_DIR)/cmn_dev/qdf/qdf.$(LINUX_KMOD_SUFFIX)
QCAWLAN_MODULE_LIST+=$(strip $(call if_opt_set, ATH_SUPPORT_DFS, \
	$(PKG_BUILD_DIR)/lmac/dfs/ath_dfs.$(LINUX_KMOD_SUFFIX)))
QCAWLAN_MODULE_LIST+=$(strip $(call if_opt_set, ATH_SUPPORT_SPECTRAL, \
	$(PKG_BUILD_DIR)/lmac/spectral/ath_spectral.$(LINUX_KMOD_SUFFIX)))
QCAWLAN_MODULE_LIST+=$(PKG_BUILD_DIR)/umac/umac.$(LINUX_KMOD_SUFFIX)
QCAWLAN_MODULE_LIST+=$(PKG_BUILD_DIR)/os/linux/ath_hal/ath_hal.$(LINUX_KMOD_SUFFIX)
QCAWLAN_MODULE_LIST+=$(PKG_BUILD_DIR)/lmac/ratectrl/ath_rate_atheros.$(LINUX_KMOD_SUFFIX)
QCAWLAN_MODULE_LIST+=$(strip $(call if_opt_set, ATH_SUPPORT_TX99, \
	$(PKG_BUILD_DIR)/lmac/tx99/hst_tx99.$(LINUX_KMOD_SUFFIX)))
QCAWLAN_MODULE_LIST+=$(PKG_BUILD_DIR)/lmac/ath_dev/ath_dev.$(LINUX_KMOD_SUFFIX)
QCAWLAN_MODULE_LIST+=$(PKG_BUILD_DIR)/qca_da/qca_da.$(LINUX_KMOD_SUFFIX)
QCAWLAN_MODULE_LIST+=$(PKG_BUILD_DIR)/qca_ol/qca_ol.$(LINUX_KMOD_SUFFIX)
QCAWLAN_MODULE_LIST+=$(PKG_BUILD_DIR)/lmac/ath_pktlog/ath_pktlog.$(LINUX_KMOD_SUFFIX)
QCAWLAN_MODULE_LIST+=$(strip $(call if_opt_set, UNIFIED_SMARTANTENNA, \
	$(PKG_BUILD_DIR)/smartantenna/smart_antenna.$(LINUX_KMOD_SUFFIX)))
QCAWLAN_MODULE_LIST+=$(strip $(call if_opt_set, ATH_SW_WOW_SUPPORT, \
	$(PKG_BUILD_DIR)/wow/sw_wow.$(LINUX_KMOD_SUFFIX)))

#########################################################
################# BUILD/INSTALL RULES ###################
#########################################################
QCAWLAN_TOOL_LIST:= 80211stats athstats athstatsclr apstats pktlogconf pktlogdump wifitool wlanconfig thermaltool wps_enhc exttool assocdenialnotify
QCAWLAN_TOOL_LIST+= $(call if_opt_set, ATH_SUPPORT_DFS, radartool)
QCAWLAN_TOOL_LIST+= $(call if_opt_set, ATH_SUPPORT_SPECTRAL, spectraltool)
QCAWLAN_TOOL_LIST+= $(call if_opt_set, ATH_SUPPORT_IBSS_PRIVATE_SECURITY, athadhoc)
QCAWLAN_TOOL_LIST+= $(call if_opt_set, ATH_SSID_STEERING, ssidsteering)
QCAWLAN_TOOL_LIST+= $(call if_opt_set, ATH_SUPPORT_TX99, tx99tool)
QCAWLAN_TOOL_LIST+= $(call if_opt_set, DEBUG_TOOLS, dumpregs reg)

