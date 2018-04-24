/*
 * Copyright (c) 2017 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc
 * Notifications and licenses are retained for attribution purposes only
 */
/*
 * Copyright (c) 2010, Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/*
 * Copyright (c) 2013-2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include "ol_if_athvar.h"
#include <hif.h>
#include <osdep.h>
#include <wbuf.h>
#include <linux/firmware.h>
#include <linux/pci.h>
#include <linux/proc_fs.h>
#include "sw_version.h"
#include "ieee80211_var.h"
#include "ieee80211_ioctl.h"
#include "ol_if_athvar.h"
#include "if_athioctl.h"
#include "osif_private.h"
#include "osapi_linux.h"
#include "if_media.h"
#include "bmi_msg.h" /* TARGET_TYPE_ */
#include "bmi.h"
#include "reg_struct.h"
#include "regtable.h"
#include "ol_ath.h"
#include "epping_test.h"
#include "ol_helper.h"
#include "a_debug.h"
#include "pktlog_ac_api.h"
#include "ol_regdomain.h"
#include "ieee80211_ioctl_acfg.h"
#include "ald_netlink.h"
#include "ath_pci.h"
#include "bin_sig.h"
#include <ol_if_thermal.h>
#include "ah_devid.h"
#if ATH_SUPPORT_CODESWAP
#include "ol_swap.h"
#include <linux/dma-mapping.h>
#endif
#include "ath_pci.h"

#if defined(CONFIG_HL_SUPPORT)
#include "wlan_tgt_def_config_hl.h"    /* TODO: check if we need a seperated config file */
#else
#include "wlan_tgt_def_config.h"
#endif

#if ATH_BAND_STEERING
#include "ath_band_steering.h"
#endif
#if ATH_SUPPORT_LOWI
#include "ath_lowi_if.h"
#endif

#include "ath_netlink.h"

#ifdef A_SIMOS_DEVHOST
#include "sim_io.h"
#endif
#ifdef QVIT
#include <qvit/qvit_defs.h>
#endif
#if PERF_FIND_WDS_NODE
#include "wds_addr.h"
#endif
#if MESH_MODE_SUPPORT
#include <if_meta_hdr.h>
#endif
#if WIFI_MEM_MANAGER_SUPPORT
#include "mem_manager.h"
#endif

#include "ol_ath_ucfg.h"
#include <targaddrs.h>

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <nss_api_if.h>
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,4,103)
#include <osif_fs.h>
#endif
#include "ol_txrx_types.h"
#include "pktlog_ac.h"
unsigned int enableuartprint = 0;
module_param(enableuartprint, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(enableuartprint,
        "Enable uart/serial prints from target");
EXPORT_SYMBOL(enableuartprint);

unsigned int enable_tx_tcp_cksum = 0;
module_param(enable_tx_tcp_cksum, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(enable_tx_tcp_cksum,
        "Enable TX TCP checksum");
EXPORT_SYMBOL(enable_tx_tcp_cksum);

unsigned int vow_config = 0;
module_param(vow_config, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(vow_config,
        "Do VoW Configuration");
EXPORT_SYMBOL(vow_config);

unsigned short max_descs = 0;
module_param(max_descs, ushort, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(max_descs,
        "Override Default descriptors the value should be between 1424 and 2198");
EXPORT_SYMBOL(max_descs);

#if QCA_AIRTIME_FAIRNESS
extern unsigned int atf_mode;
extern unsigned int atf_msdu_desc;
extern unsigned int atf_peers;
extern unsigned int atf_max_vdevs;
#endif

#if ATH_SUPPORT_WRAP
unsigned int qwrap_enable = 0;
module_param(qwrap_enable, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(qwrap_enable,
        "Enable qwrap target config ");
EXPORT_SYMBOL(qwrap_enable);
#endif

unsigned int max_peers = 0;
module_param(max_peers, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(max_peers,
        "Override Default Peers");
EXPORT_SYMBOL(max_peers);

unsigned int max_vdevs = 0;
module_param(max_vdevs, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(max_vdevs,
        "Override Default VDEVs");
EXPORT_SYMBOL(max_vdevs);

unsigned int sa_validate_sw = 0;
module_param(sa_validate_sw, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(sa_validate_sw,
        "Validate Smart Antenna Software");
EXPORT_SYMBOL(sa_validate_sw);

/* User can configure the buffers for each AC, via UCI commands during init time only */
unsigned int OL_ACBKMinfree = 0;
module_param(OL_ACBKMinfree, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(OL_ACBKMinfree,
        "offload : Min Free buffers reserved for AC-BK");
EXPORT_SYMBOL(OL_ACBKMinfree);

unsigned int OL_ACBEMinfree = 0;
module_param(OL_ACBEMinfree, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(OL_ACBEMinfree,
        "offload : Min Free buffers reserved for AC-BE");
EXPORT_SYMBOL(OL_ACBEMinfree);

unsigned int OL_ACVIMinfree = 0;
module_param(OL_ACVIMinfree, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(OL_ACVIMinfree,
        "offload : Min Free buffers reserved for AC-VI");
EXPORT_SYMBOL(OL_ACVIMinfree);

unsigned int OL_ACVOMinfree = 0;
module_param(OL_ACVOMinfree, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(OL_ACVOMinfree,
        "offload : Min Free buffers reserved for AC-VO");
EXPORT_SYMBOL(OL_ACVOMinfree);

#ifdef AH_CAL_IN_FLASH_PCI
extern u_int32_t CalAddr[];
extern int pci_dev_cnt;
#endif

int dfs_disable = 0;
module_param(dfs_disable, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
EXPORT_SYMBOL(dfs_disable);

/* PLL parameters Start */
int32_t frac = -1;
module_param(frac, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
EXPORT_SYMBOL(frac);

int32_t intval = -1;
module_param(intval, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
EXPORT_SYMBOL(intval);

/* PLL parameters End */
int32_t ar900b_20_targ_clk = -1;
module_param(ar900b_20_targ_clk, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
EXPORT_SYMBOL(ar900b_20_targ_clk);

int32_t qca9888_20_targ_clk = -1;
module_param(qca9888_20_targ_clk, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
EXPORT_SYMBOL(qca9888_20_targ_clk);

uint32_t otp_mod_param = 0xffffffff;
module_param(otp_mod_param, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
EXPORT_SYMBOL(otp_mod_param);

unsigned int cfg_iphdr_pad = 1;
module_param(cfg_iphdr_pad, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(cfg_iphdr_pad,
        "offload : Disable IP header padding to manage IP header unalignment");
EXPORT_SYMBOL(cfg_iphdr_pad);

unsigned int emu_type = 0;
module_param(emu_type, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(emu_type,
        "Emulation Type : 0-->ASIC, 1-->M2M, 2-->BB");
EXPORT_SYMBOL(emu_type);

unsigned int enable_smart_antenna = 0;
module_param(enable_smart_antenna, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(enable_smart_antenna,
        "Enable Smart Antenna ");
EXPORT_SYMBOL(enable_smart_antenna);

unsigned int max_active_peers = 0;
module_param(max_active_peers, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(max_active_peers,
        "Max active peers in peer qcache");
EXPORT_SYMBOL(max_active_peers);

unsigned int low_mem_system = 0;
module_param(low_mem_system, int, 0644);
EXPORT_SYMBOL(low_mem_system);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_if.h>
unsigned int nss_wifi_olcfg = 0x0;
unsigned int nss_wifi_ol_skip_nw_process = 0x0;
module_param(nss_wifi_olcfg, uint, 0644);
module_param(nss_wifi_ol_skip_nw_process, uint, 0644);
#endif

/* Module parameter to input a list of IEEE channels to scan.  This is primarily
 * intended as a debug feature for environments such as emulation platforms. The
 * module parameter mechanism is used so that regular QSDK configuration
 * recipes used in testing are left undisturbed as far as possible (for fixed
 * BSS channel scenarios).
 * It is the end user's responsibility to ensure appropriateness of channel
 * numbers passed while using this debug mechanism, since regulations keep
 * evolving.
 *
 * Example usage: insmod umac.ko <other params...> ol_scan_chanlist=1,6,11,36
 */
unsigned short ol_scan_chanlist[IEEE80211_CUSTOM_SCAN_ORDER_MAXSIZE];
int ol_scan_chanlist_size = 0;
module_param_array(ol_scan_chanlist,
        ushort, &ol_scan_chanlist_size, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(ol_scan_chanlist,
        "offload: Specifies list of IEEE channels to scan in client mode");
EXPORT_SYMBOL(ol_scan_chanlist);
EXPORT_SYMBOL(ol_scan_chanlist_size);

#if FW_CODE_SIGN
unsigned int fw_code_sign=0;
/* module permissions are selectivly chosen to make sure that it is not visibile
 * outside in either proc or debugfs. Only root has visibility to write, at
 * once. Changing this would not impact, as changes to this has no impact.
 *
 * use fw_code_sign=2, for debug dumping few header information
 * use fw_code_sign=3, for debug dumping of all bytes that is being processed
 */
module_param(fw_code_sign, uint, S_IWUSR);
EXPORT_SYMBOL(fw_code_sign);

/* function prototypes related to FW_CODE_SIGN
*/

static int request_secure_firmware(struct firmware **fw_entry, const char *file,
                                    struct device *dev, int dev_id);
static void release_secure_firmware(struct firmware *fw_entry);
static inline void htonlm(void *sptr, int len);
static inline void ntohlm(void *sptr, int len);
static inline int fw_check_img_magic(unsigned int img_magic);
static inline int fw_check_chip_id(unsigned int chip_id);
static inline int fw_sign_check_file_magic(unsigned int file_type);
static inline int fw_sign_get_hash_algo (struct firmware_head *h);
static struct firmware_head *fw_unpack(unsigned char *fw, int chip_id,
                                   int *err);
static const unsigned char  * fw_sign_get_cert_buffer(struct firmware_head *h,
                                   int *cert_type, int *len);
static inline int fw_sign_get_pk_algo (struct firmware_head *h);
static inline int fw_check_sig_algorithm(int s);
static void fw_hex_dump(unsigned char *p, int len);
#endif /* FW_CODE_SIGN */
int ol_ath_ucfg_utf_unified_cmd(struct ol_ath_softc_net80211 *scn, int cmd, char *userdata);
void wmi_proc_remove(wmi_unified_t wmi_handle, struct proc_dir_entry *par_entry, int id);

extern int ol_ath_target_start(struct ol_ath_softc_net80211 *scn);
extern unsigned int fw_dump_options;
void ahb_defer_reconnect(struct work_struct *ahb_reconnect_work);

/*
 * Maximum acceptable MTU
 * MAXFRAMEBODY - WEP - QOS - RSN/WPA:
 * 2312 - 8 - 2 - 12 = 2290
 */
#define ATH_MAX_MTU     2290
#define ATH_MIN_MTU     32
#define MAX_UTF_LENGTH 2048

#define QC98XX_EEPROM_SIZE_LARGEST_AR900B   12064
#define QC98XX_EEPROM_SIZE_LARGEST_AR988X   2116
#define FLASH_CAL_START_OFFSET              0x1000

static uint32_t QC98XX_EEPROM_SIZE_LARGEST;
/*
** Prototype for iw attach
*/

#ifdef ATH_SUPPORT_LINUX_STA
#ifdef CONFIG_SYSCTL
void ath_dynamic_sysctl_register(struct ol_ath_softc_net80211 *sc);
void ath_dynamic_sysctl_unregister(struct ol_ath_softc_net80211 *sc);
#endif
#endif
#if OS_SUPPORT_ASYNC_Q
static void os_async_mesg_handler( void  *ctx, u_int16_t  mesg_type, u_int16_t  mesg_len, void  *mesg );
#endif

void ol_ath_iw_attach(struct net_device *dev);
#if !NO_SIMPLE_CONFIG
extern int32_t unregister_simple_config_callback(char *name);
extern int32_t register_simple_config_callback (char *name, void *callback, void *arg1, void *arg2);
static irqreturn_t jumpstart_intr(int cpl, void *dev_id, struct pt_regs *regs, void *push_dur);
#endif

#if defined(ATH_TX99_DIAG) && (!defined(ATH_PERF_PWR_OFFLOAD))
extern u_int8_t tx99_ioctl(struct net_device *dev, struct ol_ath_softc_net80211 *sc, int cmd, void *addr);
#endif

#ifdef HIF_SDIO
#define NOHIFSCATTERSUPPORT_DEFAULT    1
unsigned int nohifscattersupport = NOHIFSCATTERSUPPORT_DEFAULT;
#endif

extern int ol_ath_utf_cmd(ol_scn_t scn, u_int8_t *data, u_int16_t len);
extern int ol_ath_utf_rsp(ol_scn_t scn, u_int8_t *payload);

#ifdef QCA_PARTNER_PLATFORM
extern void WAR_PLTFRM_PCI_WRITE32(char *addr, u32 offset, u32 value, unsigned int war1);
extern void ath_pltfrm_init( struct net_device *dev );
#endif
#if WMI_RECORDING
extern int ath_get_radio_index(struct net_device *netdev);
#endif

extern struct ol_ath_softc_net80211 *ol_global_scn[GLOBAL_SCN_SIZE];
extern int ol_num_global_scn;

unsigned int testmode = 0;
module_param(testmode, int, 0644);

#if QCA_LTEU_SUPPORT
unsigned int lteu_support = 0;
module_param(lteu_support, int, 0644);
#endif

/*
 * Signal how to handle BMI:
 *  0 --> driver handles BMI
 *  1 --> user agent handles BMI
 */
unsigned int bmi = 0;
module_param(bmi, int, 0644);


#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
extern int osif_nss_ol_assign_ifnum(int radio_id, struct ol_ath_softc_net80211 *scn, bool is_2g);
#endif

#if OL_ATH_SMART_LOGGING
extern ssize_t smart_logs_dump(struct device *dev,
                               struct device_attribute *attr, char *buf);
#endif /* OL_ATH_SMART_LOGGING */

int ath_ahb_recover(struct ol_ath_softc_net80211 *scn);
int ath_pci_recover(struct ol_ath_softc_net80211 *scn);

/* The code below is used to register a hw_caps file in sysfs */
static ssize_t wifi_hwcaps_show(struct device *dev,
                               struct device_attribute *attr, char *buf)
{
    struct net_device *net = to_net_dev(dev);
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(net);
    struct ieee80211com *ic = &scn->sc_ic;

    u_int32_t hw_caps = ic->ic_modecaps;

    strlcpy(buf, "802.11", strlen("802.11") + 1);
    if (hw_caps &
        1 << IEEE80211_MODE_11A)
        strlcat(buf, "a", strlen("a") + strlen(buf) + 1);
    if (hw_caps &
        1 << IEEE80211_MODE_11B)
        strlcat(buf, "b", strlen("b") + strlen(buf) + 1);
    if (hw_caps &
        1 << IEEE80211_MODE_11G)
        strlcat(buf, "g", strlen("g") +  strlen(buf) + 1);
    if (hw_caps &
        (1 << IEEE80211_MODE_11NA_HT20 |
         1 << IEEE80211_MODE_11NG_HT20 |
         1 << IEEE80211_MODE_11NA_HT40PLUS |
         1 << IEEE80211_MODE_11NA_HT40MINUS |
         1 << IEEE80211_MODE_11NG_HT40PLUS |
         1 << IEEE80211_MODE_11NG_HT40MINUS |
         1 << IEEE80211_MODE_11NG_HT40 |
         1 << IEEE80211_MODE_11NA_HT40))
        strlcat(buf, "n", strlen("n") + strlen(buf) + 1);
    if(hw_caps &
        (1 << IEEE80211_MODE_11AC_VHT20 |
         1 << IEEE80211_MODE_11AC_VHT40PLUS |
         1 << IEEE80211_MODE_11AC_VHT40MINUS |
         1 << IEEE80211_MODE_11AC_VHT40 |
         1 << IEEE80211_MODE_11AC_VHT80 |
         1 << IEEE80211_MODE_11AC_VHT160 |
         1 << IEEE80211_MODE_11AC_VHT80_80))
        strlcat(buf, "/ac", strlen("/ac" ) + strlen(buf) + 1);
    return strlen(buf);
}
static DEVICE_ATTR(hwcaps, S_IRUGO, wifi_hwcaps_show, NULL);

/* Handler for sysfs entry hwmodes - returns all the hwmodes supported by the radio */
static ssize_t wifi_hwmodes_show(struct device *dev,
                               struct device_attribute *attr, char *buf)
{
    struct ol_ath_softc_net80211 *scn = NULL;
    struct ieee80211com *ic = NULL;
    u_int32_t hw_caps = 0;
    int len = 0;
    struct net_device *net = to_net_dev(dev);

    scn = ath_netdev_priv(net);
    if(!scn){
       return 0;
    }

    ic = &scn->sc_ic;
    if(!ic){
        return 0;
    }

    hw_caps = ic->ic_modecaps;

    if (hw_caps &
        1 << IEEE80211_MODE_11A)
        strlcat(buf, "11A ", strlen("11A ") + strlen(buf) + 1);
    if (hw_caps &
        1 << IEEE80211_MODE_11B)
        strlcat(buf, "11B ", strlen("11B ") + strlen(buf) + 1);
    if (hw_caps &
        1 << IEEE80211_MODE_11G)
        strlcat(buf, "11G ", strlen("11G ") + strlen(buf) + 1);
    if (hw_caps &
        1 << IEEE80211_MODE_FH)
        strlcat(buf, "FH ", strlen("FH ") + strlen(buf) + 1);
    if (hw_caps &
        1 << IEEE80211_MODE_TURBO_A)
        strlcat(buf, "TURBO_A ", strlen("TURBO_A ") + strlen(buf) + 1);
    if (hw_caps &
        1 << IEEE80211_MODE_TURBO_G)
        strlcat(buf, "TURBO_G ", strlen("TURBO_G ") + strlen(buf) + 1);
    if (hw_caps &
        1 << IEEE80211_MODE_11NA_HT20)
        strlcat(buf, "11NA_HT20 ", strlen("11NA_HT20 ") + strlen(buf) + 1);
    if (hw_caps &
        1 << IEEE80211_MODE_11NG_HT20)
        strlcat(buf, "11NG_HT20 ", strlen("11NG_HT20 ") + strlen(buf) + 1);
    if (hw_caps &
        1 << IEEE80211_MODE_11NA_HT40PLUS)
        strlcat(buf, "11NA_HT40PLUS ", strlen("11NA_HT40PLUS ") + strlen(buf) + 1);
    if (hw_caps &
        1 << IEEE80211_MODE_11NA_HT40MINUS)
        strlcat(buf, "11NA_HT40MINUS ", strlen("11NA_HT40MINUS ") + strlen(buf) + 1);
    if (hw_caps &
        1 << IEEE80211_MODE_11NG_HT40PLUS)
        strlcat(buf, "11NG_HT40PLUS ", strlen("11NG_HT40PLUS ") + strlen(buf) + 1);
    if (hw_caps &
        1 << IEEE80211_MODE_11NG_HT40MINUS)
        strlcat(buf, "11NG_HT40MINUS ", strlen("11NG_HT40MINUS ") + strlen(buf) + 1);
    if (hw_caps &
        1 << IEEE80211_MODE_11NG_HT40)
        strlcat(buf, "11NG_HT40 ", strlen("11NG_HT40 ") + strlen(buf) + 1);
    if (hw_caps &
        1 << IEEE80211_MODE_11NA_HT40)
        strlcat(buf, "11NA_HT40 ", strlen("11NA_HT40 ") + strlen(buf) + 1);
    if (hw_caps &
        1 << IEEE80211_MODE_11AC_VHT20)
        strlcat(buf, "11AC_VHT20 ", strlen("11AC_VHT20 ") + strlen(buf) + 1);
    if (hw_caps &
        1 << IEEE80211_MODE_11AC_VHT40PLUS)
        strlcat(buf, "11AC_VHT40PLUS ", strlen("11AC_VHT40PLUS ") + strlen(buf) + 1);
    if (hw_caps &
        1 << IEEE80211_MODE_11AC_VHT40MINUS)
        strlcat(buf, "11AC_VHT40MINUS ", strlen("11AC_VHT40MINUS ") + strlen(buf) + 1);
    if (hw_caps &
        1 << IEEE80211_MODE_11AC_VHT40)
        strlcat(buf, "11AC_VHT40 ", strlen("11AC_VHT40 ") + strlen(buf) + 1);
    if (hw_caps &
        1 << IEEE80211_MODE_11AC_VHT80)
        strlcat(buf, "11AC_VHT80 ", strlen("11AC_VHT80 ") + strlen(buf) + 1);
    if (hw_caps &
        1 << IEEE80211_MODE_11AC_VHT160)
        strlcat(buf, "11AC_VHT160 ", strlen("11AC_VHT160 ") + strlen(buf) + 1);
    if (hw_caps &
        1 << IEEE80211_MODE_11AC_VHT80_80)
        strlcat(buf, "11AC_VHT80_80 ", strlen("11AC_VHT80_80 ") + strlen(buf) + 1);
    len = strlen(buf);
    if(len > 0){
        buf[len - 1] = '\0';
    }

    return strlen(buf);
}
static DEVICE_ATTR(hwmodes, S_IRUGO, wifi_hwmodes_show, NULL);

/*Handler for sysfs entry 2g_maxchwidth - returns the maximum channel width supported by the device in 2.4GHz*/
static ssize_t wifi_2g_maxchwidth_show(struct device *dev,
                               struct device_attribute *attr, char *buf)
{
    struct ol_ath_softc_net80211 *scn = NULL;
    struct ieee80211com *ic = NULL;
    u_int32_t hw_caps = 0;
    struct net_device *net = to_net_dev(dev);

    scn = ath_netdev_priv(net);
    if(!scn){
       return 0;
    }

    ic = &scn->sc_ic;
    if(!ic){
        return 0;
    }

    hw_caps = ic->ic_modecaps;

    if (hw_caps &
        (1 << IEEE80211_MODE_11NG_HT40MINUS |
         1 << IEEE80211_MODE_11NG_HT40PLUS |
	 1 << IEEE80211_MODE_11NG_HT40))
         strlcpy(buf, "40", strlen("40") + strlen(buf) + 1);
    else if (hw_caps & (1 << IEEE80211_MODE_11NG_HT20 ))
        strlcpy(buf, "20", strlen("20") + strlen(buf) + 1);

    /* NOTE: Only >=n chipsets are considered for now since productization will
     * involve only such chipsets. In the unlikely case where lower chipsets/crimped
     * phymodes are to be handled, it is a separate TODO and relevant enums need
     * to be considered.*/

    return strlen(buf);
}

static DEVICE_ATTR(2g_maxchwidth, S_IRUGO, wifi_2g_maxchwidth_show, NULL);

/*Handler for sysfs entry 5g_maxchwidth - returns the maximum channel width supported by the device in 5GHz*/
static ssize_t wifi_5g_maxchwidth_show(struct device *dev,
                               struct device_attribute *attr, char *buf)
{
    struct ol_ath_softc_net80211 *scn = NULL;
    struct ieee80211com *ic = NULL;
    u_int32_t hw_caps = 0;
    struct net_device *net = to_net_dev(dev);

    scn = ath_netdev_priv(net);
    if(!scn){
       return 0;
    }

    ic = &scn->sc_ic;
    if(!ic){
        return 0;
    }

    hw_caps = ic->ic_modecaps;

    if (hw_caps & (1 << IEEE80211_MODE_11AC_VHT160)) {
	    strlcpy(buf, "160", strlen("160") +  1);
    }
    else if (hw_caps & (1 << IEEE80211_MODE_11AC_VHT80)) {
	    strlcpy(buf, "80", strlen("80") +  1);
    }
    else if (hw_caps &
        (1 << IEEE80211_MODE_11AC_VHT40 |
         1 << IEEE80211_MODE_11AC_VHT40MINUS |
	 1 << IEEE80211_MODE_11AC_VHT40PLUS |
         1 <<  IEEE80211_MODE_11NA_HT40 |
         1 <<  IEEE80211_MODE_11NA_HT40MINUS |
         1 <<  IEEE80211_MODE_11NA_HT40PLUS)) {
	    strlcpy(buf, "40", strlen("40") + 1);
    }
    else if (hw_caps &
        (1 << IEEE80211_MODE_11AC_VHT20 |
         1 << IEEE80211_MODE_11NA_HT20)) {
           strlcpy(buf, "20", strlen("20") + 1);
    }

    /* NOTE: Only >=n chipsets are considered for now since productization will
     * involve only such chipsets. In the unlikely case where lower chipsets/crimped
     * phymodes are to be handled, it is a separate TODO and relevant enums need
     * to be considered.*/

    return strlen(buf);
}

static DEVICE_ATTR(5g_maxchwidth, S_IRUGO, wifi_5g_maxchwidth_show, NULL);

/*Handler for sysfs entry is_offload - returns if the radio is offload or not */
static ssize_t wifi_is_offload_show(struct device *dev,
                               struct device_attribute *attr, char *buf)
{
    strlcpy(buf, "1", strlen("1") + 1);

    return strlen(buf);
}

static DEVICE_ATTR(is_offload, S_IRUGO, wifi_is_offload_show, NULL);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
/* Handler for sysfs entry nssoffload -
 * returns whether this radio is capable of being offloaded to NSS.
 */
static ssize_t wifi_nssoffload_show(struct device *dev,
                               struct device_attribute *attr, char *buf)
{
    struct net_device *net = to_net_dev(dev);
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(net);

    uint32_t target_type = scn->target_type;

    if (nss_cmn_get_nss_enabled() != true) {
        strlcpy(buf, "NA", strlen("NA") + 1);
        return strlen(buf);
    }

    switch (target_type) {
        case TARGET_TYPE_QCA9984:
	case TARGET_TYPE_AR900B:
            strlcpy(buf, "capable", strlen("capable") + 1);
        break;
	default:
            strlcpy(buf, "NA", strlen("NA") +1);
	break;
    }
    return strlen(buf);
}
static DEVICE_ATTR(nssoffload, S_IRUGO, wifi_nssoffload_show, NULL);
#endif

/***** ciphercaps for OL radio *****/

static ssize_t wifi_ol_ciphercaps_show(struct device *dev,struct device_attribute *attr, char *buf)
{
    struct net_device *net = to_net_dev(dev);
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(net);
    struct ieee80211com *ic = &scn->sc_ic;
    u_int16_t ciphercaps = ic->ic_cipher_caps;
    ol_scn_is_target_ar900b(scn);

    if ( !buf )
        return 0 ;

    buf[0]='\0';

    if ( ciphercaps & 1<<IEEE80211_CIPHER_WEP ) {
        strlcat(buf, "wep40,", strlen("wep40,") + strlen(buf) + 1);
        strlcat(buf, "wep104,", strlen("wep104,") + strlen(buf) + 1);
        if (  scn->is_ar900b )
            strlcat(buf, "wep128,", strlen("wep128,") + strlen(buf) + 1);
    }
    if ( ciphercaps & 1<<IEEE80211_CIPHER_TKIP )
        strlcat(buf, "tkip,", strlen("tkip,") + strlen(buf) + 1);
    if ( ciphercaps & 1<<IEEE80211_CIPHER_AES_OCB )
        strlcat(buf, "aes-ocb,", strlen("aes-ocb,") + strlen(buf) + 1);
    if ( ciphercaps & 1<<IEEE80211_CIPHER_AES_CCM )
        strlcat(buf, "aes-ccmp-128,", strlen("aes-ccmp-128,") + strlen(buf) + 1);
    if ( ciphercaps & 1<<IEEE80211_CIPHER_AES_CCM_256 )
        strlcat(buf, "aes-ccmp-256,", strlen("aes-ccmp-256,") + strlen(buf) + 1);
    if ( ciphercaps & 1<<IEEE80211_CIPHER_AES_GCM )
        strlcat(buf, "aes-gcmp-128,", strlen("aes-gcmp-128,") + strlen(buf) + 1);
    if ( ciphercaps & 1<<IEEE80211_CIPHER_AES_GCM_256 )
        strlcat(buf, "aes-gcmp-256,", strlen("aes-gcmp-256,") + strlen(buf) + 1);
    if ( ciphercaps & 1<<IEEE80211_CIPHER_CKIP )
        strlcat(buf, "ckip,", strlen("ckip,") + strlen(buf) + 1);
    if ( ciphercaps & 1<<IEEE80211_CIPHER_WAPI )
        strlcat(buf, "wapi,", strlen("wapi,") + strlen(buf) + 1);
    if ( ciphercaps & 1<<IEEE80211_CIPHER_AES_CMAC )
        strlcat(buf, "aes-cmac-128,", strlen("aes-cmac-128,") + strlen(buf) + 1);
    if ( ciphercaps & 1<<IEEE80211_CIPHER_AES_CMAC_256  )
        strlcat(buf, "aes-cmac-256,", strlen("aes-cmac-256,") + strlen(buf) + 1);
    if ( ciphercaps & 1<<IEEE80211_CIPHER_AES_GMAC )
        strlcat(buf, "aes-gmac-128,", strlen("aes-gmac-128,") + strlen(buf) + 1);
    if ( ciphercaps & 1<<IEEE80211_CIPHER_AES_GMAC_256 )
        strlcat(buf, "aes-gmac-256,", strlen("aes-gmac-256,") + strlen(buf) + 1);
    if ( ciphercaps & 1<<IEEE80211_CIPHER_NONE )
        strlcat(buf, "none", strlen("none") + strlen(buf) + 1);
    return strlen(buf);
}

static DEVICE_ATTR(ciphercaps, S_IRUGO, wifi_ol_ciphercaps_show, NULL);

#if OL_ATH_SMART_LOGGING
static DEVICE_ATTR(smartlogs_dump, S_IRUGO, smart_logs_dump, NULL);
#endif /* OL_ATH_SMART_LOGGING */

#if OL_ATH_CE_DEBUG
static DEVICE_ATTR(celogs_dump, S_IRUGO, hif_dump_desc_trace_buf, NULL);
#endif /* OL_ATH_CE_DEBUG */

static struct attribute *wifi_device_attrs[] = {
    &dev_attr_hwcaps.attr,
    &dev_attr_hwmodes.attr,       /*sysfs entry for displaying all the hwmodes supported by the radio*/
    &dev_attr_5g_maxchwidth.attr, /*sysfs entry for displaying the max channel width supported in 5Ghz*/
    &dev_attr_2g_maxchwidth.attr, /*sysfs entry for displaying the max channel width supported in 2.4Ghz*/
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    &dev_attr_nssoffload.attr,   /*sysfs entry for displaying whether nss offload is supported or not*/
#endif
    &dev_attr_ciphercaps.attr,  /*sysfs entry for displaying the supported ciphercap's in OL Chips*/
    &dev_attr_is_offload.attr,  /*sysfs entry for displaying whether the radio is offload or not*/
#if OL_ATH_SMART_LOGGING
    &dev_attr_smartlogs_dump.attr,  /*sysfs entry for dumping all the smart logs*/
#endif /* OL_ATH_SMART_LOGGING */
#if OL_ATH_CE_DEBUG
    &dev_attr_celogs_dump.attr,  /*sysfs entry for dumping all the Copy engine debug logs*/
#endif /* OL_ATH_CE_DEBUG */
    NULL
};


static struct attribute_group wifi_attr_group = {
       .attrs  = wifi_device_attrs,
};


static DEVICE_ATTR(mode, S_IRUGO | S_IWUSR, wifi_thermal_mode_show, wifi_thermal_mode_store);
static DEVICE_ATTR(temp, S_IRUGO, wifi_thermal_temp_show, NULL);
static DEVICE_ATTR(thlvl, S_IRUGO | S_IWUSR, wifi_thermal_thlvl_show, wifi_thermal_thlvl_store);
static DEVICE_ATTR(dc, S_IRUGO | S_IWUSR, wifi_thermal_dutycycle_show, wifi_thermal_dutycycle_store);
static DEVICE_ATTR(off, S_IRUGO | S_IWUSR, wifi_thermal_offpercent_show, wifi_thermal_offpercent_store);

static struct attribute *wifi_thermal_attrs[] = {
    &dev_attr_mode.attr,
    &dev_attr_temp.attr,
    &dev_attr_thlvl.attr,
    &dev_attr_dc.attr,
    &dev_attr_off.attr,
    NULL
};

static struct attribute_group wifi_thermal_group = {
       .attrs  = wifi_thermal_attrs,
       .name = "thermal",
};

/*
 * Register Thermal Mitigation Functionality
 */

int32_t ol_ath_thermal_mitigation_attach (struct ol_ath_softc_net80211 *scn,
                                      struct net_device *dev)
{
    int retval = TH_SUCCESS;
#if THERMAL_DEBUG
    //scn->thermal_param.tt_support = TH_TRUE;
#endif
    scn->thermal_param.th_cfg.log_lvl = TH_DEBUG_LVL0;
    TH_DEBUG_PRINT(TH_DEBUG_LVL1, scn, "%s: ++\n", __func__);

    if (get_tt_supported(scn)) {
        if (sysfs_create_group(&dev->dev.kobj, &wifi_thermal_group)) {
            TH_DEBUG_PRINT(TH_DEBUG_LVL0, scn, "%s: unable to register wifi_thermal_group for %s\n", __func__, dev->name);
            return TH_FAIL;
        }
        retval = __ol_ath_thermal_mitigation_attach(scn);
        if (retval) {
            scn->thermal_param.tt_support = TH_FALSE;
            sysfs_remove_group(&dev->dev.kobj, &wifi_thermal_group);
            TH_DEBUG_PRINT(TH_DEBUG_LVL0, scn, "%s: unable to initialize TT\n", __func__);
        }
    } else {
        TH_DEBUG_PRINT(TH_DEBUG_LVL0, scn, "%s: TT not supported in FW\n", __func__);
    }

    TH_DEBUG_PRINT(TH_DEBUG_LVL1, scn, "%s: --\n", __func__);

    return retval;
}
EXPORT_SYMBOL(ol_ath_thermal_mitigation_attach);

int32_t ol_ath_thermal_mitigation_detach(struct ol_ath_softc_net80211 *scn,
                                      struct net_device *dev)
{
    int retval = 0;

    TH_DEBUG_PRINT(TH_DEBUG_LVL0, scn, "%s: ++\n", __func__);

    if (get_tt_supported(scn)) {
        retval = __ol_ath_thermal_mitigation_detach(scn);
        sysfs_remove_group(&dev->dev.kobj, &wifi_thermal_group);
    }

    TH_DEBUG_PRINT(TH_DEBUG_LVL0, scn, "%s: --\n", __func__);
    return retval;
}
EXPORT_SYMBOL(ol_ath_thermal_mitigation_detach);

#ifndef ADF_SUPPORT
void *
OS_ALLOC_VAP(osdev_t osdev, u_int32_t len)
{
    void *netif;

    netif = OS_MALLOC(osdev, len, GFP_KERNEL);
    if (netif != NULL)
        OS_MEMZERO(netif, len);

    return netif;
}

void
OS_FREE_VAP(void *netif)
{
    OS_FREE(netif);
}

#endif

#if 0
/*
 * Merge multicast addresses from all vap's to form the
 * hardware filter.  Ideally we should only inspect our
 * own list and the 802.11 layer would merge for us but
 * that's a bit difficult so for now we put the onus on
 * the driver.
 */
void
ath_mcast_merge(ieee80211_handle_t ieee, u_int32_t mfilt[2])
{
    struct ieee80211com *ic = NET80211_HANDLE(ieee);
    struct ieee80211vap *vap;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
    struct netdev_hw_addr *ha;
#else
    struct dev_mc_list *mc;
#endif
    u_int32_t val;
    u_int8_t pos;

    mfilt[0] = mfilt[1] = 0;
    /* XXX locking */
    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        struct net_device *dev = ((osif_dev *)vap->iv_ifp)->netdev;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
        netdev_for_each_mc_addr(ha, dev) {
            /* calculate XOR of eight 6-bit values */
            val = LE_READ_4(ha->addr + 0);
            pos = (val >> 18) ^ (val >> 12) ^ (val >> 6) ^ val;
            val = LE_READ_4(ha->addr + 3);
            pos ^= (val >> 18) ^ (val >> 12) ^ (val >> 6) ^ val;
            pos &= 0x3f;
            mfilt[pos / 32] |= (1 << (pos % 32));
        }
#else
        for (mc = dev->mc_list; mc; mc = mc->next) {
            /* calculate XOR of eight 6bit values */
            val = LE_READ_4(mc->dmi_addr + 0);
            pos = (val >> 18) ^ (val >> 12) ^ (val >> 6) ^ val;
            val = LE_READ_4(mc->dmi_addr + 3);
            pos ^= (val >> 18) ^ (val >> 12) ^ (val >> 6) ^ val;
            pos &= 0x3f;
            mfilt[pos / 32] |= (1 << (pos % 32));
        }
#endif
    }
}
#endif
static int
ath_netdev_open(struct net_device *dev)
{
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);

    int ol_ath_ret;
    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211vap *vap;
    osif_dev  *osifp;
    struct net_device *netdev;
    u_int8_t myaddr[IEEE80211_ADDR_LEN];
    u_int8_t id = 0;

#ifdef ATH_BUS_PM
    if (scn->sc_osdev->isDeviceAsleep)
        return -EPERM;
#endif /* ATH_BUS_PM */

    /* recover VAPs if recovery in progress */
    if ((scn->recovery_enable == RECOVERY_ENABLE_WAIT) && (ic->recovery_in_progress == 1)) {
        int recovery_enable;
        recovery_enable = scn->recovery_enable;
        if (scn->target_type == TARGET_TYPE_IPQ4019) {
            ath_ahb_recover(scn);
        } else {
            ath_pci_recover(scn);
        }
        /*Send event to user space */
#if UMAC_SUPPORT_ACFG
        OSIF_RADIO_DELIVER_EVENT_WATCHDOG(&(scn->sc_ic), ACFG_WDT_REINIT_DONE);
#endif
        scn->sc_ic.recovery_in_progress = 0;
        /* The recovery process resets recovery_enable flag. restore it here */
        scn->recovery_enable = recovery_enable;
    }

    ol_ath_ret = ol_ath_resume(scn);
    if(ol_ath_ret == 0){
        dev->flags |= IFF_UP | IFF_RUNNING;      /* we are ready to go */
        /*  If physical radio interface wifiX is shutdown,all virtual interfaces(athX) should gets shutdown and
            all these downed virtual interfaces should gets up when physical radio interface(wifiX) is up.Refer EV 116786.
         */
        vap = TAILQ_FIRST(&ic->ic_vaps);
        while (vap != NULL) {
            osifp = (osif_dev *)vap->iv_ifp;
            netdev = osifp->netdev;
            ieee80211vap_get_macaddr(vap, myaddr);
            ATH_GET_VAP_ID(myaddr, wlan_vap_get_hw_macaddr(vap), id);
            if( ic->id_mask_vap_downed & ( 1 << id ) ){
                dev_change_flags(netdev,netdev->flags | ( IFF_UP ));
                ic->id_mask_vap_downed &= (~( 1 << id ));
            }
            vap = TAILQ_NEXT(vap, iv_next);
        }
    }
    return ol_ath_ret;
}

static int
ath_netdev_stop(struct net_device *dev)
{
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);

    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211vap *vap;
    osif_dev  *osifp;
    struct net_device *netdev;
    u_int8_t myaddr[IEEE80211_ADDR_LEN];
    u_int8_t id = 0;

    /*  If physical radio interface wifiX is shutdown,all virtual interfaces(athX) should gets shutdown and
        all these downed virtual interfaces should gets up when physical radio interface(wifiX) is up.Refer EV 116786.
     */

    vap = TAILQ_FIRST(&ic->ic_vaps);
    while (vap != NULL) {
        osifp = (osif_dev *)vap->iv_ifp;
        netdev = osifp->netdev;
        if (IS_IFUP(netdev)) {
            dev_change_flags(netdev,netdev->flags & ( ~IFF_UP ));
            ieee80211vap_get_macaddr(vap, myaddr);
            ATH_GET_VAP_ID(myaddr, wlan_vap_get_hw_macaddr(vap), id);
            ic->id_mask_vap_downed |= ( 1 << id);
        }
        vap = TAILQ_NEXT(vap, iv_next);
    }

    dev->flags &= ~IFF_RUNNING;
    return ol_ath_suspend(scn);
}

#ifdef EPPING_TEST
//#define EPPING_DEBUG 1
#ifdef EPPING_DEBUG
#define EPPING_PRINTF(...) printk(__VA_ARGS__)
#else
#define EPPING_PRINTF(...)
#endif
static inline int
__ath_epping_data_tx(struct sk_buff *skb, struct net_device *dev)
{
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);
    EPPING_HEADER *eppingHdr = A_NETBUF_DATA(skb);
    HTC_ENDPOINT_ID eid = ENDPOINT_UNUSED;
    struct cookie * cookie = NULL;
    A_UINT8 ac = 0;

    /* allocate resource for this packet */
    qdf_spin_lock_bh(&scn->data_lock);
    cookie = ol_alloc_cookie(scn);
    qdf_spin_unlock_bh(&scn->data_lock);

    /* no resource */
    if (cookie == NULL)
        return -1;

    /*
     * a quirk of linux, the payload of the frame is 32-bit aligned and thus
     * the addition of the HTC header will mis-align the start of the HTC
     * frame, so we add some padding which will be stripped off in the target
     */
    if (EPPING_ALIGNMENT_PAD > 0) {
        A_NETBUF_PUSH(skb, EPPING_ALIGNMENT_PAD);
    }

    /* prepare ep/HTC information */
    ac = eppingHdr->StreamNo_h;
    eid = scn->EppingEndpoint[ac];
    SET_HTC_PACKET_INFO_TX(&cookie->HtcPkt,
         cookie, A_NETBUF_DATA(skb), A_NETBUF_LEN(skb), eid, 0);
    SET_HTC_PACKET_NET_BUF_CONTEXT(&cookie->HtcPkt, skb);

    /* send the packet */
    htc_send_pkt(scn->htc_handle, &cookie->HtcPkt);

    return 0;
}

static void
epping_timer_expire(unsigned long data)
{
    struct net_device *dev = (struct net_device *) data;
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);
    struct sk_buff *nodrop_skb;

    EPPING_PRINTF("%s: queue len: %d\n", __func__,
            skb_queue_len(&scn->epping_nodrop_queue));

    if (!skb_queue_len(&scn->epping_nodrop_queue)) {
        /* nodrop queue is empty so no need to arm timer */
        scn->epping_timer_running = 0;
        return;
    }

    /* try to flush nodrop queue */
    while ((nodrop_skb = skb_dequeue(&scn->epping_nodrop_queue))) {
        if (__ath_epping_data_tx(nodrop_skb, dev)) {
            EPPING_PRINTF("nodrop: %p xmit fail in timer\n", nodrop_skb);
            /* fail to xmit so put the nodrop packet to the nodrop queue */
            skb_queue_head(&scn->epping_nodrop_queue, nodrop_skb);
            break;
        } else {
            EPPING_PRINTF("nodrop: %p xmit ok in timer\n", nodrop_skb);
        }
    }

    /* if nodrop queue is not empty, continue to arm timer */
    if (nodrop_skb) {
        scn->epping_timer_running = 1;
        mod_timer(&scn->epping_timer, jiffies + HZ / 10);
    } else {
        scn->epping_timer_running = 0;
    }
}

static int
ath_epping_data_tx(struct sk_buff *skb, struct net_device *dev)
{
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);
    struct sk_buff *nodrop_skb;
    EPPING_HEADER *eppingHdr;
    A_UINT8 ac = 0;

    if (!eppingtest) {
        goto pkt_invalid;
    }

    eppingHdr = A_NETBUF_DATA(skb);

    if (!IS_EPPING_PACKET(eppingHdr)) {
         AR_DEBUG_PRINTF(ATH_DEBUG, ("not endpoint ping packets in %s\n",
                 __FUNCTION__));
        goto pkt_invalid;
    }

    /* the stream ID is mapped to an access class */
    ac = eppingHdr->StreamNo_h;
    if (ac != 0 && ac != 1) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ac %d is not mapped to mboxping service id = %d\n",
             ac, eppingtest);
        goto pkt_invalid;
    }

    /*
     * some EPPING packets cannot be dropped no matter what access class
     * it was sent on. A special care has been taken:
     * 1. when there is no TX resource, queue the control packets to
     *    a special queue
     * 2. when there is TX resource, send the queued control packets first
     *    and then other packets
     * 3. a timer launches to check if there is queued control packets and
     *    flush them
     */

    /* check the nodrop queue first */
    while ((nodrop_skb = skb_dequeue(&scn->epping_nodrop_queue))) {
        if (__ath_epping_data_tx(nodrop_skb, dev)) {
            EPPING_PRINTF("nodrop: %p xmit fail\n", nodrop_skb);
            /* fail to xmit so put the nodrop packet to the nodrop queue */
            skb_queue_head(&scn->epping_nodrop_queue, nodrop_skb);
            /* no cookie so free the current skb */
            goto tx_fail;
        } else {
            EPPING_PRINTF("nodrop: %p xmit ok\n", nodrop_skb);
        }
    }

    /* send the original packet */
    if (__ath_epping_data_tx(skb, dev))
        goto tx_fail;

    return 0;

tx_fail:
    if (!IS_EPING_PACKET_NO_DROP(eppingHdr)) {
pkt_invalid:
        /* no packet to send, cleanup */
        A_NETBUF_FREE(skb);
        return -ENOMEM;
    } else {
        EPPING_PRINTF("nodrop: %p queued\n", skb);
        skb_queue_tail(&scn->epping_nodrop_queue, skb);
        if (!scn->epping_timer_running) {
            scn->epping_timer_running = 1;
            mod_timer(&scn->epping_timer, jiffies + HZ / 10);
        }
    }

    return 0;
}
#endif

static int
ath_netdev_hardstart(struct sk_buff *skb, struct net_device *dev)
{
#ifdef EPPING_TEST
    return ath_epping_data_tx(skb, dev);
#else
    return 0;
#endif
}

static void
ath_netdev_tx_timeout(struct net_device *dev)
{
#if 0
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);

    DPRINTF(scn, ATH_DEBUG_WATCHDOG, "%s: %sRUNNING\n",
            __func__, (dev->flags & IFF_RUNNING) ? "" : "!");

	if (dev->flags & IFF_RUNNING) {
        scn->sc_ops->reset_start(scn->sc_dev, 0, 0, 0);
        scn->sc_ops->reset(scn->sc_dev);
        scn->sc_ops->reset_end(scn->sc_dev, 0);
	}
#endif
}

static int
ath_netdev_set_macaddr(struct net_device *dev, void *addr)
{
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);
    struct ieee80211com *ic = &scn->sc_ic;
    struct sockaddr *mac = addr;

    if (netif_running(dev)) {
#if 0
        DPRINTF(scn, ATH_DEBUG_ANY,
            "%s: cannot set address; device running\n", __func__);
#endif
        return -EBUSY;
    }
#if 0
    DPRINTF(scn, ATH_DEBUG_ANY, "%s: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
        __func__,
        mac->sa_data[0], mac->sa_data[1], mac->sa_data[2],
        mac->sa_data[3], mac->sa_data[4], mac->sa_data[5]);
#endif

    /* XXX not right for multiple vap's */
    IEEE80211_ADDR_COPY(ic->ic_myaddr, mac->sa_data);
    IEEE80211_ADDR_COPY(ic->ic_my_hwaddr, mac->sa_data);
    IEEE80211_ADDR_COPY(dev->dev_addr, mac->sa_data);
    scn->sc_ic.ic_set_macaddr(&scn->sc_ic, dev->dev_addr);
    return 0;
}

static void
ath_netdev_set_mcast_list(struct net_device *dev)
{
#if 0
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);
    scn->sc_ops->mc_upload(scn->sc_dev);
#endif
}

static int
ath_change_mtu(struct net_device *dev, int mtu)
{
    if (!(ATH_MIN_MTU < mtu && mtu <= ATH_MAX_MTU)) {
#if 0
        DPRINTF((struct ol_ath_softc_net80211 *) ath_netdev_priv(dev),
            ATH_DEBUG_ANY, "%s: invalid %d, min %u, max %u\n",
            __func__, mtu, ATH_MIN_MTU, ATH_MAX_MTU);
#endif
        return -EINVAL;
    }
#if 0
    DPRINTF((struct ol_ath_softc_net80211 *) ath_netdev_priv(dev), ATH_DEBUG_ANY,
        "%s: %d\n", __func__, mtu);
#endif

    dev->mtu = mtu;
    return 0;
}

int ath_hal_getdiagstate(struct ieee80211com* ic, u_int id, void* indata, u_int32_t insize, void* outdata, u_int32_t* outsize)
{
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "SPECTRAL : NOT IMPLEMENTED YET %s : %d\n", __func__, __LINE__);
    return 0;
}

static int
ath_ioctl_diag(struct ol_ath_softc_net80211 *scn, struct ath_diag *ad)
{

    struct ieee80211com* ic = &scn->sc_ic;
    void *indata    = NULL;
    void *outdata   = NULL;

    int error = 0;

    u_int id= ad->ad_id & ATH_DIAG_ID;
    u_int32_t insize    = ad->ad_in_size;
    u_int32_t outsize   = ad->ad_out_size;

    if (ad->ad_id & ATH_DIAG_IN) {
        /*
         * Copy in data.
         */
        indata = OS_MALLOC(scn->sc_osdev, insize, GFP_KERNEL);
        if (indata == NULL) {
            error = -ENOMEM;
            goto bad;
        }
        if (__xcopy_from_user(indata, ad->ad_in_data, insize)) {
            error = -EFAULT;
            goto bad;
        }
    }
    if (ad->ad_id & ATH_DIAG_DYN) {
        /*
         * Allocate a buffer for the results (otherwise the HAL
         * returns a pointer to a buffer where we can read the
         * results).  Note that we depend on the HAL leaving this
         * pointer for us to use below in reclaiming the buffer;
         * may want to be more defensive.
         */
        outdata = OS_MALLOC(scn->sc_osdev, outsize, GFP_KERNEL);
        if (outdata == NULL) {
            error = -ENOMEM;
            goto bad;
        }

        id = id & ~ATH_DIAG_DYN;
    }

    if (ath_hal_getdiagstate(ic, id, indata, insize, &outdata, &outsize)) {
        if (outsize < ad->ad_out_size)
            ad->ad_out_size = outsize;
        if (outdata && _copy_to_user(ad->ad_out_data, outdata, ad->ad_out_size))
            error = -EFAULT;
    } else {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "SIOCATHDIAG : Error\n");
        error = -EINVAL;
    }
bad:
    if ((ad->ad_id & ATH_DIAG_IN) && indata != NULL)
        kfree(indata);
    if ((ad->ad_id & ATH_DIAG_DYN) && outdata != NULL)
        kfree(outdata);
    return error;
}

#ifdef ATH_USB
#include "usb_eth.h"
#else
extern int ol_ath_ioctl_ethtool(struct ol_ath_softc_net80211 *scn, int cmd, void *addr);
#endif

///TODO: Should this be defined here..
//#if ATH_PERF_PWR_OFFLOAD
int
utf_unified_ioctl (struct ol_ath_softc_net80211 *scn, struct ifreq *ifr)
{
    unsigned int cmd = 0;
    char *userdata;

    get_user(cmd, (int *)ifr->ifr_data);
    userdata = (char *)(((unsigned int *)ifr->ifr_data)+1);

    return ol_ath_ucfg_utf_unified_cmd(scn, cmd, userdata);
}

int ol_acfg_handle_ioctl(struct net_device *dev, void *data);

static int
ath_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);
    struct ieee80211com *ic = &scn->sc_ic;
    //struct ath_phy_stats *ps;
    int error=0;
    char *userdata = NULL;
    struct extended_ioctl_wrapper extended_cmd;
    struct ath_diag ad;

    if (cmd == ATH_IOCTL_EXTENDED) {
        /*
         * This allows for many more wireless ioctls than would otherwise
         * be available.  Applications embed the actual ioctl command in
         * the first word of the parameter block, and use the command
         * ATH_IOCTL_EXTENDED_CMD on the ioctl call.
         */
        get_user(cmd, (int *)ifr->ifr_data);
        userdata = (char *)(((unsigned int *)ifr->ifr_data)+1);
    }

    switch (cmd) {

#ifdef QVIT
    case SIOCIOCTLQVIT:
            error = qvit_unified_ioctl(dev, scn,ifr);
            break;
#endif
    case SIOCGATHEACS:
#if 0
#if ATH_SUPPORT_SPECTRAL
        error = osif_ioctl_eacs(dev, ifr, scn->sc_osdev);
#endif
#endif
        break;
    case SIOCGATHSTATS:
        {
            struct ath_stats_container asc;

            error = __xcopy_from_user(&asc, ifr->ifr_data, sizeof(asc) );
            if(error)
            {
                error = -EFAULT;
                break;
            }

            if (ol_ath_target_start(scn)) {
                qdf_print("failed to start the target\n");
                return -1;
            }

            error = ol_ath_ucfg_get_ath_stats(scn, &asc);

            if (error || _copy_to_user(ifr->ifr_data, &asc, sizeof(asc)))
            {
                error = -EFAULT;
                break;
            }
        }
        break;
    case SIOCGATHSTATSCLR:
#if 0
        as = scn->sc_ops->get_ath_stats(scn->sc_dev);
        error = 0;
#endif
        break;
    case SIOCGATHPHYSTATS:
         if(((dev->flags & IFF_UP) == 0)){
         return -ENXIO;
         }
        if (_copy_to_user(ifr->ifr_data, &scn->scn_stats,
                    sizeof(scn->scn_stats))) {
            error = -EFAULT;
        } else {
            error = 0;
        }
        break;
    case SIOCGATHDIAG:
#if 1
        if (!capable(CAP_NET_ADMIN))
            error = -EPERM;
        else
            error = ath_ioctl_diag(scn, (struct ath_diag *) ifr);
#endif
        break;
#if defined(ATH_SUPPORT_DFS) || defined(ATH_SUPPORT_SPECTRAL)
    case SIOCGATHPHYERR:
        if (!capable(CAP_NET_ADMIN)) {
            error = -EPERM;
        } else {
            if (ol_ath_target_start(scn)) {
                qdf_print("failed to start the target\n");
                return -1;
            }

            if (__xcopy_from_user(&ad, ifr->ifr_data, sizeof(ad))) {
                return -EFAULT;
            }
            error = ol_ath_ucfg_phyerr(scn, &ad);
        }
        break;
#endif
    case SIOCETHTOOL:
#if 0
        if (__xcopy_from_user(&cmd, ifr->ifr_data, sizeof(cmd)))
            error = -EFAULT;
        else
            error = ol_ath_ioctl_ethtool(scn, cmd, ifr->ifr_data);
#endif
        break;
    case SIOC80211IFCREATE:
        {
            struct ieee80211_clone_params cp;

            if (__xcopy_from_user(&cp, ifr->ifr_data, sizeof(cp))) {
                return -EFAULT;
            }
            error = ol_ath_ucfg_create_vap(scn, &cp, ifr->ifr_name);
        }
        break;
#if defined(ATH_TX99_DIAG) && (!defined(ATH_PERF_PWR_OFFLOAD))
    case SIOCIOCTLTX99:
        if (ol_ath_target_start(scn)) {
            qdf_print("failed to start the target\n");
            return -1;
        }

        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Call Tx99 ioctl %d \n",cmd);
        error = tx99_ioctl(dev, ATH_DEV_TO_SC(scn->sc_dev), cmd, ifr->ifr_data);
        break;
#else
    case SIOCIOCTLTX99:
        if (ol_ath_target_start(scn)) {
            qdf_print("failed to start the target\n");
            return -1;
        }

        error = utf_unified_ioctl(scn,ifr);
        break;
#endif
#ifdef ATH_SUPPORT_LINUX_VENDOR
    case SIOCDEVVENDOR:
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: SIOCDEVVENDOR TODO\n", __func__);
        //error = osif_ioctl_vendor(dev, ifr, 0);
        break;
#endif
#ifdef ATH_BUS_PM
    case SIOCSATHSUSPEND:
      {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: SIOCSATHSUSPEND TODO\n", __func__);
#if 0
        struct ieee80211com *ic = &scn->sc_ic;
        struct ieee80211vap *tmpvap;
        int val = 0;
        if (__xcopy_from_user(&val, ifr->ifr_data, sizeof(int)))
          return -EFAULT;

        if(val) {
          /* suspend only if all vaps are down */
          TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
            struct net_device *tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
            if (tmpdev->flags & IFF_RUNNING)
              return -EBUSY;
          }
          error = bus_device_suspend(scn->sc_osdev);
        }
        else
          error = bus_device_resume(scn->sc_osdev);

        if (!error)
            scn->sc_osdev->isDeviceAsleep = val;
#endif
      }
      break;
#endif /* ATH_BUS_PM */
    case SIOCG80211PROFILE:
      {
          struct ieee80211_profile *profile;

          profile = (struct ieee80211_profile *)kmalloc(
                  sizeof (struct ieee80211_profile), GFP_KERNEL);
          if (profile == NULL) {
              error = -ENOMEM;
              break;
          }
          OS_MEMSET(profile, 0, sizeof (struct ieee80211_profile));

          error = ol_ath_ucfg_get_vap_info(scn, profile);

          error = _copy_to_user(ifr->ifr_data, profile,
                  sizeof(struct ieee80211_profile));

          kfree(profile);
          profile = NULL;
      }
      break;
#if UMAC_SUPPORT_ACFG
    case ACFG_PVT_IOCTL:
        error = ol_acfg_handle_ioctl(dev, ifr->ifr_data);
        break;
#endif
    case SIOCGATHEXTENDED:
        {
            if (__xcopy_from_user(&extended_cmd, ifr->ifr_data, sizeof(extended_cmd))) {
                return (-EFAULT);
            }

            if (scn->sc_in_delete) {
                error = -ENODEV;
            }
            if (ol_ath_target_start(scn)) {
                qdf_print("failed to start the target\n");
                return -1;
            }

            switch (extended_cmd.cmd) {

                case EXTENDED_SUBIOCTL_THERMAL_SET_PARAM:
                    error = ol_ath_ioctl_set_thermal_handler(scn, extended_cmd.data);
                    break;

                case EXTENDED_SUBIOCTL_THERMAL_GET_PARAM:
                    error = ol_ath_ioctl_get_thermal_handler(scn, extended_cmd.data);
                    break;

#if ATH_PROXY_NOACK_WAR
                case EXTENDED_SUBIOCTL_OL_GET_PROXY_NOACK_WAR:
                    error = ol_ioctl_get_proxy_noack_war(scn, extended_cmd.data);
                    break;
                case EXTENDED_SUBIOCTL_OL_RESERVE_PROXY_MACADDR:
                    error = ol_ioctl_reserve_proxy_macaddr(scn, extended_cmd.data);
                    break;
#endif
                case EXTENDED_SUBIOCTL_CHANNEL_SWITCH:
                    error = ieee80211_extended_ioctl_chan_switch(dev, ic, extended_cmd.data);
                    break;

                case EXTENDED_SUBIOCTL_CHANNEL_SCAN:
                    error = ieee80211_extended_ioctl_chan_scan(dev, ic, extended_cmd.data);
                    break;

                case EXTENDED_SUBIOCTL_REPEATER_MOVE:
                    error = ieee80211_extended_ioctl_rep_move(dev, ic, extended_cmd.data);
                    break;

#if ATH_SUPPORT_WRAP && DBDC_REPEATER_SUPPORT
                case EXTENDED_SUBIOCTL_GET_PRIMARY_RADIO:
                    error = ol_ioctl_get_primary_radio(scn, extended_cmd.data);
                    break;
                case EXTENDED_SUBIOCTL_GET_MPSTA_MAC_ADDR:
                    error = ol_ioctl_get_mpsta_mac_addr(scn, extended_cmd.data);
                    break;
                case EXTENDED_SUBIOCTL_DISASSOC_CLIENTS:
                    ol_ioctl_disassoc_clients(scn);
                    break;
                case EXTENDED_SUBIOCTL_GET_FORCE_CLIENT_MCAST:
                    error = ol_ioctl_get_force_client_mcast(scn, extended_cmd.data);
                    break;
                case EXTENDED_SUBIOCTL_GET_MAX_PRIORITY_RADIO:
                    error = ol_ioctl_get_max_priority_radio(scn, extended_cmd.data);
                    break;
#endif
                case EXTENDED_SUBIOCTL_IFACE_MGR_STATUS:
                    ol_ioctl_iface_mgr_status(scn, extended_cmd.data);
                    break;
                case EXTENDED_SUBIOCTL_GET_STAVAP_CONNECTION:
                    error = ol_ioctl_get_stavap_connection(scn, extended_cmd.data);
                    break;
                case EXTENDED_SUBIOCTL_GET_DISCONNECTION_TIMEOUT:
                    error = ol_ioctl_get_disconnection_timeout(scn, extended_cmd.data);
                    break;
#if DBDC_REPEATER_SUPPORT
                case EXTENDED_SUBIOCTL_GET_PREF_UPLINK:
                    ol_ioctl_get_preferred_uplink(scn, extended_cmd.data);
                break;
#endif
                default:
                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: unsupported extended command %d\n", __func__, extended_cmd.cmd);
                    break;
            }
        }
        break;

    default:
        error = -EINVAL;
        break;
    }

    return error;
}

/*
 * Return netdevice statistics.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
static struct rtnl_link_stats64 *
ath_getstats(struct net_device *dev, struct rtnl_link_stats64* stats64)
#else
static struct net_device_stats *
ath_getstats(struct net_device *dev)
#endif
{
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);
    ol_txrx_pdev_handle pdev;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
    struct net_device_stats *stats = NULL;
#else
    struct rtnl_link_stats64 *stats = NULL;
#endif
    stats = &scn->sc_osdev->devstats;
#if 0
    struct ath_stats *as;
    struct ath_phy_stats *ps;
    struct ath_11n_stats *ans;
    WIRELESS_MODE wmode;

    stats = &scn->sc_osdev->devstats;

    as = scn->sc_ops->get_ath_stats(scn->sc_dev);
    ans = scn->sc_ops->get_11n_stats(scn->sc_dev);
    /* update according to private statistics */
    stats->tx_errors = as->ast_tx_xretries
             + as->ast_tx_fifoerr
             + as->ast_tx_filtered
             ;
    stats->tx_dropped = as->ast_tx_nobuf
            + as->ast_tx_encap
            + as->ast_tx_nonode
            + as->ast_tx_nobufmgt;
    /* Add tx beacons, tx mgmt, tx, 11n tx */
    stats->tx_packets = as->ast_be_xmit
            + as->ast_tx_mgmt
            + as->ast_tx_packets
            + ans->tx_pkts;
    /* Add rx, 11n rx (rx mgmt is included) */
    stats->rx_packets = as->ast_rx_packets
            + ans->rx_pkts;

    for (wmode = 0; wmode < WIRELESS_MODE_MAX; wmode++) {
        ps = scn->sc_ops->get_phy_stats(scn->sc_dev, wmode);
        stats->rx_errors = ps->ast_rx_fifoerr;
        stats->rx_dropped = ps->ast_rx_tooshort;
        stats->rx_crc_errors = ps->ast_rx_crcerr;
    }

#endif
    if (!scn->sc_ic.ic_is_mode_offload) {
        goto stats_done;
    }
    pdev = scn->pdev_txrx_handle;
    if (!pdev) {
        goto stats_done;
    }
    stats->tx_packets = (stats_t)pdev->stats.pub.tx.delivered.pkts;
    stats->tx_bytes = (stats_t)pdev->stats.pub.tx.delivered.bytes;
    stats->tx_errors = (stats_t)(pdev->stats.pub.tx.dropped.host_reject.pkts
                       + pdev->stats.pub.tx.dropped.download_fail.pkts
                       + pdev->stats.pub.tx.dropped.target_discard.pkts
                       + pdev->stats.pub.tx.dropped.no_ack.pkts);
    stats->tx_dropped = stats->tx_errors;

    stats->rx_packets = (stats_t)(pdev->stats.pub.rx.delivered.pkts
                        + pdev->stats.pub.rx.forwarded.pkts);
    stats->rx_bytes = (stats_t)(pdev->stats.pub.rx.delivered.bytes
                      + pdev->stats.pub.rx.forwarded.bytes);
stats_done:
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
    return stats;
#else
    memcpy(stats64, stats, sizeof(struct rtnl_link_stats64));
    return stats64;
#endif
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
static const struct net_device_ops athdev_net_ops = {
    .ndo_open    = ath_netdev_open,
    .ndo_stop    = ath_netdev_stop,
    .ndo_start_xmit = ath_netdev_hardstart,
    .ndo_set_mac_address = ath_netdev_set_macaddr,
    .ndo_tx_timeout = ath_netdev_tx_timeout,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
    .ndo_get_stats64 = ath_getstats,
#else
    .ndo_get_stats = ath_getstats,
#endif
    .ndo_change_mtu = ath_change_mtu,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
    .ndo_set_multicast_list = ath_netdev_set_mcast_list,
#else
    .ndo_set_rx_mode = ath_netdev_set_mcast_list,
#endif
    .ndo_do_ioctl = ath_ioctl,
};
#endif

static struct ieee80211_reg_parameters ol_wlan_reg_params = {
    .sleepTimePwrSave = 100,         /* wake up every beacon */
    .sleepTimePwrSaveMax = 1000,     /* wake up every 10 th beacon */
    .sleepTimePerf=100,              /* station wakes after this many mS in max performance mode */
    .inactivityTimePwrSaveMax=400,   /* in max PS mode, how long (in mS) w/o Tx/Rx before going back to sleep */
    .inactivityTimePwrSave=200,      /* in normal PS mode, how long (in mS) w/o Tx/Rx before going back to sleep */
    .inactivityTimePerf=400,         /* in max perf mode, how long (in mS) w/o Tx/Rx before going back to sleep */
    .psPollEnabled=0,                /* Use PS-POLL to retrieve data frames after TIM is received */
    .wmeEnabled    = 1,
    .enable2GHzHt40Cap = 1,
    .cwmEnable = 1,
    .cwmExtBusyThreshold = IEEE80211_CWM_EXTCH_BUSY_THRESHOLD,
    .ignore11dBeacon = 1,
    .p2pGoUapsdEnable = 1,
    .extapUapsdEnable = 1,
#ifdef ATH_SUPPORT_TxBF
    .autocvupdate = 0,
#define DEFAULT_PER_FOR_CVUPDATE 30
    .cvupdateper = DEFAULT_PER_FOR_CVUPDATE,
#endif
    .regdmn = 0,
    .wModeSelect = REGDMN_MODE_ALL,
    .netBand = REGDMN_MODE_ALL,
    .extendedChanMode = 0,
};

void   ol_ath_linux_update_fw_config_cb( struct ol_ath_softc_net80211 *scn,
                          struct ol_ath_target_cap *tgt_cap)
{

    /*
     * tgt_cap contains default target resource configuration
     * which can be modified here, if required
     */
#if ATH_OL_11AC_DMA_BURST
    /* 0: 128B - default, 1: 256B, 2: 64B */
	tgt_cap->wlan_resource_config.dma_burst_size = ATH_OL_11AC_DMA_BURST;
#endif

#if ATH_OL_11AC_MAC_AGGR_DELIM
	tgt_cap->wlan_resource_config.mac_aggr_delim = ATH_OL_11AC_MAC_AGGR_DELIM;
#endif

    /* Override the no. of max fragments as per platform configuration */
	tgt_cap->wlan_resource_config.max_frag_entries =
                MIN(QCA_OL_11AC_TX_MAX_FRAGS, scn->max_frag_entry);
    scn->max_frag_entry = tgt_cap->wlan_resource_config.max_frag_entries;
}

int ol_ath_verify_vow_config(struct ol_ath_softc_net80211 *scn)
{
    int vow_max_sta = ((scn->vow_config) & 0xffff0000) >> 16;
    int vow_max_desc_persta = ((scn->vow_config) & 0x0000ffff);

    if(scn->target_type == TARGET_TYPE_AR9888) {
        if((vow_max_sta * vow_max_desc_persta) > TOTAL_VOW_ALLOCABLE) {
            int vow_unrsvd_sta_num = 0, vow_rsvd_num = 0;

        vow_rsvd_num = TOTAL_VOW_ALLOCABLE/vow_max_desc_persta;

        vow_unrsvd_sta_num = vow_max_sta - vow_rsvd_num;

        if( (vow_unrsvd_sta_num * vow_max_desc_persta) > VOW_DESC_GRAB_MAX ) {
            /*cannot support the request*/
            vow_unrsvd_sta_num = VOW_DESC_GRAB_MAX / vow_max_desc_persta;
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: ERROR: Invalid vow_config\n",__func__);
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Can support only %d clients for %d desc\n", __func__,
                    vow_rsvd_num + vow_unrsvd_sta_num,
                    vow_max_desc_persta);

            return -1;
        }
    }
    } else if(scn->is_ar900b) {
        /* Check not required as of now */
    }
    /* VoW takes precedence over max_descs and max_active_peers config. It will choose these
     * param accordingly */
    if( vow_max_sta ) {
        scn->max_descs = 0;
        scn->max_active_peers = 0;
    }
    return 0;
}

int ol_ath_verify_max_descs(struct ol_ath_softc_net80211 *scn)
{

    if (!scn->is_ar900b || scn->vow_config) {
        scn->max_descs = 0;
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Overiding max_descs module param \n");
        return 0;
    }

    /*
     * the max_descs is a 16 bit value whose range falls between CFG_TGT_NUM_MSDU_DESC_AR900B *
     * CFG_TGT_NUM_MAX_MSDU_DESC
     * based on the max_descs value we derive max_active_peers value.
     * the dafult max_descs is CFG_TGT_NUM_MSDU_DESC_AR900B &
     * default max_active_peers is CFG_TGT_QCACHE_ACTIVE_PEERS
     * Each active peer consumes 780 bytes of DRAM and each descriptor 16 bytes
     * hence for every increase of 48 (780/16) descriptors we need to reduce
     * the active peer count by 1.
     * to ensure any future optimizations to firmware which help in reducing
     * the memory consumed by active peer, we allow a cushion of 2 descriptors
     * thus setting the value to 46 descriptors for one active peer.
     * To ensure minimum of CFG_TGT_QCACHE_MIN_ACTIVE_PEERS peers are always active we do not exceed max_descs
     * beyond CFG_TGT_QCACHE_MIN_ACTIVE_PEERS.
     */
    if (scn->max_descs < CFG_TGT_NUM_MSDU_DESC_AR900B) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "max_descs cannot be less then %d", CFG_TGT_NUM_MSDU_DESC_AR900B);
        scn->max_descs = CFG_TGT_NUM_MSDU_DESC_AR900B;
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "setting max_descs to %d\n", scn->max_descs);
        scn->max_active_peers = CFG_TGT_QCACHE_ACTIVE_PEERS;
    }
    else if (scn->max_descs > CFG_TGT_NUM_MAX_MSDU_DESC_AR900B) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "max_descs cannot exceed %d", CFG_TGT_NUM_MAX_MSDU_DESC_AR900B);
        scn->max_descs = CFG_TGT_NUM_MAX_MSDU_DESC_AR900B;
	    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "setting the max_descs to %d\n", CFG_TGT_NUM_MAX_MSDU_DESC_AR900B);
        scn->max_active_peers = CFG_TGT_QCACHE_MIN_ACTIVE_PEERS;
    }
    else {
        scn->max_active_peers = CFG_TGT_QCACHE_ACTIVE_PEERS -
           ((scn->max_descs - CFG_TGT_NUM_MSDU_DESC_AR900B)/CFG_TGT_NUM_MSDU_DESC_PER_ACTIVE_PEER + 1);
    }

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "max_descs: %d, max_active_peers: %d\n", scn->max_descs, scn->max_active_peers);

    return 0;
}

extern ar_handle_t ar_attach(int target_type);
extern void ar_detach(ar_handle_t arh);

#if ATH_SUPPORT_CODESWAP

static int ol_get_powerof2(int d)
{
     int pow=1;
     int i=1;
     while(i<=d)
     {
          pow=pow*2;
          i++;
     }
     return pow;
}

int
ol_swap_seg_alloc (struct ol_ath_softc_net80211 *scn, struct swap_seg_info **ret_seg_info, u_int64_t **scn_cpuaddr, const char* filename, int type)
{
#if WIFI_MEM_MANAGER_SUPPORT
    struct ieee80211com *ic;
    int intr_ctxt;
#endif

    void *cpu_addr;
    dma_addr_t dma_handle;
    struct swap_seg_info *seg_info = NULL;
#if FW_CODE_SIGN
    struct firmware *fw_entry;
#else
    const struct firmware *fw_entry;
#endif /* FW_CODE_SIGN */
    int  swap_size=0, is_powerof_2=0, start=1, poweroff=0;
    int rfwst;

    if(!filename) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: File name is Null \n",__func__);
        goto end_swap_alloc;
    }

#if FW_CODE_SIGN
    rfwst = request_secure_firmware(&fw_entry, filename, scn->sc_osdev->device,
                scn->device_id);
#else
    rfwst = request_firmware(&fw_entry, filename, scn->sc_osdev->device);
#endif /* FW_CODE_SIGN */
    if (rfwst != 0)  {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Failed to get fw: %s\n", filename);
        goto end_swap_alloc;
    }
    swap_size = fw_entry->size;
#if FW_CODE_SIGN
    release_secure_firmware(fw_entry);
#else
    release_firmware(fw_entry);
#endif /* FW_CODE_SIGN */
    if (swap_size == 0)  {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : swap_size is 0\n ",__func__);
        goto end_swap_alloc;
    }

    /* check swap_size is power of 2 */
    is_powerof_2 = ((swap_size != 0) && !(swap_size & (swap_size - 1)));


    /* set the swap_size to nearest power of 2 celing */
    if (is_powerof_2 == 0) {
        while (swap_size <= EVICT_BIN_MAX_SIZE) {
            poweroff = ol_get_powerof2(start);
            start++;
            if (poweroff > swap_size) {
                swap_size = poweroff;
                break;
            }
        }
    }

    if (swap_size > EVICT_BIN_MAX_SIZE) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Exceeded Max allocation %d,Swap Alloc failed: exited \n", __func__,swap_size);
        goto end_swap_alloc;
    }

#if WIFI_MEM_MANAGER_SUPPORT
    ic = &scn->sc_ic;
    intr_ctxt = (in_interrupt() || irqs_disabled()) ? 1 : 0;
    cpu_addr = (void *) wifi_cmem_allocation(ic->interface_id, (CM_CODESWAP + type), swap_size, (void *)scn->qdf_dev->drv_hdl/*(void *)scn->sc_osdev->device*/, &dma_handle, intr_ctxt);
#else
    cpu_addr = dma_alloc_coherent(scn->sc_osdev->device, swap_size,
                                        &dma_handle, GFP_KERNEL);
#endif
    if (!cpu_addr || !dma_handle) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " Memory Alloc failed for swap feature\n");
          goto end_swap_alloc;
    }

    seg_info = devm_kzalloc(scn->sc_osdev->device, sizeof(*seg_info),
                                               GFP_KERNEL);
    if (!seg_info) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Fail to allocate memory for seg_info\n");
            goto end_dma_alloc;
    }

    memset(seg_info, 0, sizeof(*seg_info));
    seg_info->seg_busaddr[0]   = dma_handle;
    seg_info->seg_cpuaddr[0]   = (u_int64_t)(unsigned long)cpu_addr;
    seg_info->seg_size         = swap_size;
    seg_info->seg_total_bytes  = swap_size;
    /* currently design assumes 1 valid code/data segment */
    seg_info->num_segs         = 1;
    seg_info->seg_size_log2    = ilog2(swap_size);
    *(scn_cpuaddr)   = cpu_addr;

    *(ret_seg_info) = seg_info;

    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"%s: Successfully allocated memory for SWAP size=%d \n", __func__,swap_size);

    return 0;

end_dma_alloc:
    dma_free_coherent(scn->sc_osdev->device, swap_size, cpu_addr, dma_handle);

end_swap_alloc:
    return -1;

}

int
ol_swap_wlan_memory_expansion(struct ol_ath_softc_net80211 *scn, struct swap_seg_info *seg_info,const char*  filename, u_int32_t *target_addr)
{
    struct device *dev;
#if FW_CODE_SIGN
    struct firmware *fw_entry;
#else
    const struct firmware *fw_entry;
#endif /* FW_CODE_SIGN */
    u_int32_t fw_entry_size, size_left, dma_size_left;
    char *fw_temp;
    char *fw_data;
    char *dma_virt_addr;
    u_int32_t total_length = 0, length=0;
    /* 3 Magic zero dwords will be there in swap bin files */
    unsigned char fw_code_swap_magic[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                           0x00, 0x00 };
    int status = -1;
    int rfwst = 0;
    dev = scn->sc_osdev->device;

    if (!seg_info) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "seg_info is NULL\n");
        goto end;
    }
#if FW_CODE_SIGN
    rfwst = request_secure_firmware(&fw_entry, filename, dev, scn->device_id);
#else
    rfwst = request_firmware(&fw_entry, filename, dev);
#endif /* FW_CODE_SIGN */
    if (rfwst != 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Failed to get fw: %s\n", filename);
        goto end;
    }
    if (!fw_entry || !fw_entry->data) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: INVALID FW entries\n", __func__);
        goto release_fw;
    }

    dma_virt_addr = (char *)(unsigned long)seg_info->seg_cpuaddr[0];
    fw_data = (u8 *) fw_entry->data;
    fw_temp = fw_data;
    fw_entry_size = fw_entry->size;
    if (fw_entry_size > EVICT_BIN_MAX_SIZE) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Exceeded Max allocation, Swap exit \n", __func__);
        goto release_fw;
    }
    size_left = fw_entry_size;
    dma_size_left = seg_info->seg_size;
   /* parse codeswap bin file for address,length,value
    * and copy bin file to host allocated memory. Current
    * desing will have 2 semgment, 1'st valid segment ,2nd
    * will be all zero followed by target address where
    * host want to write the seginfo swap structure
    */
    while ((size_left && fw_temp) && (dma_size_left > 0)) {
        fw_temp = fw_temp + 4;
        size_left = size_left - 4;
#if defined(BIG_ENDIAN_HOST)
        length = qdf_le32_to_cpu(*(int *)fw_temp);
#else
        length = *(int *)fw_temp;
#endif
    qdf_print("%s: length:%d size_left:%d dma_size_left:%d fw_temp:%p fw_entry_size:%d\n",
                      __func__, length, size_left, dma_size_left, fw_temp,fw_entry->size);
        if ((length > size_left || length <= 0) ||
            (dma_size_left <= 0 || length > dma_size_left)) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"Swap: wrong length read:%d\n",length);
            break;
        }
        fw_temp = fw_temp + 4;
        size_left = size_left - 4;
#if AH_NEED_TX_DATA_SWAP
        /* Do byte swap before storing in to DMA address */
        {
            int i=0;
            u_int32_t* dest_addr= (u_int32_t*)dma_virt_addr;
            u_int32_t* src_addr= (u_int32_t*)fw_temp;
            for (i=0; i < (length+3)/4; i++) {
                dest_addr[i] = qdf_le32_to_cpu(src_addr[i]);
            }
        }
#else
        qdf_print("%s: dma_virt_addr :%p fw_temp: %p length: %d\n",
                      __func__, dma_virt_addr, fw_temp, length);
        memcpy(dma_virt_addr, fw_temp, length);
#endif
        dma_size_left = dma_size_left - length;
        size_left = size_left - length;
        fw_temp = fw_temp + length;
        dma_virt_addr = dma_virt_addr + length;
        total_length += length;
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"Swap: bytes_left to copy: fw:%d; dma_page:%d\n",
                                      size_left, dma_size_left);
    }
    /* we are end of the last segment where 3 dwords
     * are zero and after that a dword which has target
     * address where host write the swap info struc to fw
     */
    if(( 0 == (size_left - 12))&& length == 0) {
        fw_temp = fw_temp - 4;
        if (memcmp(fw_temp,fw_code_swap_magic,12) == 0) {
            fw_temp = fw_temp + 12;
#if defined(BIG_ENDIAN_HOST)
            {
                u_int32_t swap_target_addr = qdf_le32_to_cpu(*(int *)fw_temp);
                memcpy(target_addr,&swap_target_addr,4);
            }
#else
            memcpy(target_addr,fw_temp,4);
#endif
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"%s: Swap total_bytes copied: %d Target address %x \n", __func__, total_length,*target_addr);
            status = 0;
        }

    }
    seg_info->seg_total_bytes = total_length;

release_fw:
#if FW_CODE_SIGN
    release_secure_firmware(fw_entry);
#else
    release_firmware(fw_entry);
#endif  /* FW_CODE_SIGN */
end:
    return status;
}
#endif

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
void ol_ath_enable_fraglist(struct net_device *dev)
{
    struct ol_ath_softc_net80211 *scn;
    void *nss_wifiol_ctx = NULL;

    scn = ath_netdev_priv(dev);
    nss_wifiol_ctx= scn->nss_wifiol_ctx;

    if (!nss_wifiol_ctx) {
        return;
    }

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,2,0) || PARTNER_ETHTOOL_SUPPORTED
    dev->hw_features |= NETIF_F_SG | NETIF_F_FRAGLIST;
    /* Folowing is required to have fraglist support for VLAN over VAP interfaces */
    dev->vlan_features |= NETIF_F_SG | NETIF_F_FRAGLIST;
    dev->features |= NETIF_F_SG | NETIF_F_FRAGLIST;
#else
    dev->features |= NETIF_F_SG | NETIF_F_FRAGLIST;
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,3,0) || PARTNER_ETHTOOL_SUPPORTED
    /* ethtool interface changed for kernel versions > 3.3.0,
     * Corresponding changes as follows */
    dev->wanted_features |= NETIF_F_SG | NETIF_F_FRAGLIST;
#endif
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Enabled Fraglist bit for the radio %s features %x \n", dev->name,(unsigned int)dev->features);
}
#endif

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
int global_radio_id=0;
int nssradio_id=0;
#endif
static int wifi_start_idx = 0;

struct net_device *ol_create_radio_netdev(struct ol_attach_t *ol_cfg)
{
    struct net_device *dev;
    char radio_if[IFNAMSIZ];

    snprintf(radio_if, IFNAMSIZ, "%s%d", "wifi", wifi_start_idx++);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
    dev = alloc_netdev(sizeof(struct ol_ath_softc_net80211), ol_cfg->bus_type == BUS_TYPE_SIM ? "wifi-sim%d" : "wifi%d", 0, ether_setup);
#else
    dev = alloc_netdev(sizeof(struct ol_ath_softc_net80211), ol_cfg->bus_type == BUS_TYPE_SIM ? "wifi-sim%d" : "wifi%d", ether_setup);
#endif

    dev_alloc_name(dev, dev->name);

    return dev;
}


int
__ol_ath_attach(void *hif_hdl, struct ol_attach_t *ol_cfg, osdev_t osdev, qdf_device_t qdf_dev)
{
    struct ol_ath_softc_net80211 *scn;
    struct ieee80211com *ic;
    int error = 0;
    struct net_device *dev;
    u_int32_t i = 0, irq = 0;
    u_int32_t radio_id = 0;
    dev = (struct net_device *)qdf_dev->netdev;

    if (dev == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "ath: Cannot allocate softc\n");
        error = -ENOMEM;
        goto bad0;
    }

    scn = ath_netdev_priv(dev);


    OS_MEMZERO(scn, sizeof(*scn));

    if(ol_cfg->bus_type == BUS_TYPE_AHB)
        INIT_WORK(&scn->pci_reconnect_work, ahb_defer_reconnect);
    else
        INIT_WORK(&scn->pci_reconnect_work, pci_defer_reconnect);

    scn->recovery_enable = 0;
    scn->pci_reconnect = pci_reconnect_cb;

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n%s() Allocated scn %p\n", __func__, scn);
#ifdef EPPING_TEST
    qdf_spinlock_create(&scn->data_lock);
    skb_queue_head_init(&scn->epping_nodrop_queue);
    setup_timer(&scn->epping_timer, epping_timer_expire, (unsigned long) dev);
    scn->epping_timer_running = 0;
#endif
    scn->sc_osdev = osdev;
    scn->hif_hdl = hif_hdl;
    scn->radio_attached = 0;
    scn->sc_osdev->netdev = dev;
#ifdef AH_CAL_IN_FLASH_PCI
    scn->cal_idx = pci_dev_cnt;
#endif
    if (hif_get_irq_num(scn->hif_hdl, &irq, 1) < 0)
	    qdf_print("ERROR: not able to retrive radio's irq number \n");
    dev->irq = irq;
    /* Used to get fw stats */
    sema_init(&scn->scn_stats_sem, 0);

    /* initialize the dump options */
    scn->sc_dump_opts = fw_dump_options;

    /*
     * Don't leave arp type as ARPHRD_ETHER as this is no eth device
     */
    dev->type = ARPHRD_IEEE80211;

    /* show that no dedicated amem instance has been created yet */
    scn->amem.handle = NULL;
    ic = &scn->sc_ic;

    /* Create amem instance, we can use OS_MALLOC beyond this point */
    error = ol_asf_adf_attach(scn);
    if (error)
        goto bad1;

    scn->target_type = ol_cfg->target_type;
    scn->target_revision = ol_cfg->target_revision;
    scn->device_id = ol_cfg->devid;
    scn->pdevid = ol_cfg->pdevid;
    scn->targetdef = hif_get_targetdef(hif_hdl);
    ol_scn_is_target_ar900b(scn);

    /*
     * set caldata length based upon current target type.
     */
    if (scn->target_type == TARGET_TYPE_AR9888) {
        QC98XX_EEPROM_SIZE_LARGEST = QC98XX_EEPROM_SIZE_LARGEST_AR988X;
    } else {
        QC98XX_EEPROM_SIZE_LARGEST = QC98XX_EEPROM_SIZE_LARGEST_AR900B;
    }

    scn->arh = ar_attach(scn->target_type);
    if (!(scn->arh)) {
        error = -ENOMEM;
        ol_asf_adf_detach(scn);
        goto bad1;
    }

    scn->qdf_dev = qdf_dev;

    qdf_dev->drv = osdev;
    osdev->qdf_dev = scn->qdf_dev;
    /*
     * create and initialize ath layer
     */
    if (ol_cfg->bus_type == BUS_TYPE_SIM ) {
        scn->is_sim=true;
    }

    /* Init timeout */
    scn->sc_osdev->wmi_timeout = 10;

    /* Init timeout (uninterrupted wait) */
    scn->sc_osdev->wmi_timeout_unintr = 2;

#if PERF_FIND_WDS_NODE
    wds_table_init(&scn->scn_wds_table);
#endif
    scn->enableuartprint = enableuartprint;
    scn->vow_config = vow_config;
    scn->max_descs = max_descs;
    scn->max_peers = max_peers;
    scn->max_vdevs = max_vdevs;
    scn->sa_validate_sw = sa_validate_sw;
    scn->enable_smart_antenna = enable_smart_antenna;
    scn->max_active_peers = max_active_peers;
    scn->is_ani_enable = true;
    scn->dbg.print_rate_limit = DEFAULT_PRINT_RATE_LIMIT_VALUE;

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    scn->nss_wifi_ol_mode = 0;
    scn->nss_wifiol_id = -1;
    scn->nss_ifnum = -1;
    if (nss_cmn_get_nss_enabled() == true) {
            if (nss_wifi_olcfg & (1 << global_radio_id )) {
                    if ((scn->target_type == TARGET_TYPE_AR900B)
                                    || (scn->target_type == TARGET_TYPE_QCA9984)) {
                            scn->nss_wifiol_id = nssradio_id;
                            scn->nss_ifnum = osif_nss_ol_assign_ifnum(scn->nss_wifiol_id, scn ,(nss_wifi_olcfg >> 16 & (1 << global_radio_id)));
                            if (scn->nss_ifnum == -1) {
                                    scn->nss_wifiol_id=-1;
                                    qdf_print("Unable to assign interface number for radio %d\n", scn->nss_wifiol_id);
                                    error=-EINVAL;
                                    goto bad4;
                            }
                            nssradio_id++;
                            scn->nss_wifi_ol_mode = 1;
                            scn->nss_wifiol_bypass_nw_process = (nss_wifi_ol_skip_nw_process & (1 << global_radio_id));
                            qdf_print("nss_wifi_olcfg value is %x\n", nss_wifi_olcfg);
                            qdf_print("Got NSS IFNUM as %d\n", scn->nss_ifnum);
                    } else {
                            qdf_print("Target type not supported in NSS wifi offload %x", scn->target_type);
                    }
            }
            if (scn->nss_wifi_ol_mode) {
                    osif_nss_ol_wifi_init(scn);
            }
    }
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "nss register id %d offload mode enabled = %d nss config %x Target Type %x \n",
            scn->nss_wifiol_id, scn->nss_wifi_ol_mode, nss_wifi_olcfg, scn->target_type);
    global_radio_id++;
#endif

#if QCA_AIRTIME_FAIRNESS
    ic->atf_mode = atf_mode;
    if (ic->atf_mode && (scn->target_type == TARGET_TYPE_AR9888 &&
                            scn->target_version == AR9888_REV2_VERSION)) {
        ic->atf_msdu_desc = atf_msdu_desc;
        ic->atf_peers = atf_peers;
        ic->atf_max_vdevs = atf_max_vdevs;
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ">>ATF<<: User provided peer = %d, vdevs = %d, msdu_desc = %d\n",
                   ic->atf_peers, ic->atf_max_vdevs, ic->atf_msdu_desc);
    }
#endif
#ifdef QCA_LOWMEM_PLATFORM
    ic->ic_num_clients = IEEE80211_33_AID;
#else
    if (scn->target_type == TARGET_TYPE_AR9888)
    {
        ic->ic_num_clients = IEEE80211_128_AID;
    }
    else
    {
        ic->ic_num_clients = IEEE80211_512_AID;
    }
#endif

#if ATH_SUPPORT_WRAP
    scn->qwrap_enable = qwrap_enable;
#endif

    if (ol_scan_chanlist_size > 0) {
        /* Populate custom scan order.
         * This is done at the IC level rather than VAP level since it is meant
         * for use with inputs provided via a module parameter. See comments for
         * ol_scan_chanlist.
         */

        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Populating custom scan order\n");

        qdf_mem_set(ic->ic_custom_scan_order,
                sizeof(ic->ic_custom_scan_order), 0);

        for (i = 0;
                i < MIN(ol_scan_chanlist_size, IEEE80211_N(ic->ic_custom_scan_order));
                i++)
        {
            ic->ic_custom_scan_order[i] =
                ieee80211_ieee2mhz(ic, ol_scan_chanlist[i], 0);
            ic->ic_custom_scan_order_size++;
        }
    } else {
        ic->ic_custom_scan_order_size = 0;
    }

    /* if max active peers is explicitly configured, then max_descs will be ignored.
     * max_active_peers takes precedence over max_desc */
    if (scn->max_active_peers) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Using max_active_peers configured.\n%s\n",
               (scn->max_descs)?"Ignoring max_descs. max_active_peers takes precedence":"");
        scn->max_descs = 0;
    } else if (scn->max_descs) {
        ol_ath_verify_max_descs(scn);
    }

    if(ol_ath_verify_vow_config(scn)) {
        /*cannot accomadate vow config requested*/
        error = -EINVAL;
        goto bad4;
    }

#if ATH_SSID_STEERING
    if(EOK != ath_ssid_steering_netlink_init()) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "SSID steering socket init failed __investigate__\n");
        goto bad4;
    }
#endif

    init_waitqueue_head(&scn->sc_osdev->event_queue);

    /*
     * Resolving name to avoid a crash in request_irq() on new kernels
     */
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"%s: dev name %s\n", __func__,dev->name);

    /*get radio id from linux alloc-ed id*/
    radio_id = (u_int32_t)(dev->name[strlen(dev->name)-1]-'0');
    scn->radio_id = radio_id;

#if WMI_RECORDING
    scn->wmi_proc_entry = proc_mkdir(dev->name, NULL);
    if(scn->wmi_proc_entry == NULL) {
      QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "error while creating proc entry for %s\n", dev->name);
    }
#endif

#if QCA_LTEU_SUPPORT
#define LTEU_SUPPORT0    0x1
#define LTEU_SUPPORT1    0x2
#define LTEU_SUPPORT2    0x4
    if (!strncmp("wifi0", dev->name, sizeof("wifi0") - 1))
        scn->lteu_support = (lteu_support & LTEU_SUPPORT0) ? 1 : 0;
    else if (!strncmp("wifi1", dev->name, sizeof("wifi1") - 1))
        scn->lteu_support = (lteu_support & LTEU_SUPPORT1) ? 1 : 0;
    else if (!strncmp("wifi2", dev->name, sizeof("wifi2") - 1))
        scn->lteu_support = (lteu_support & LTEU_SUPPORT2) ? 1 : 0;
#endif

    /*
     * pktlog scn initialization
     */
#ifndef REMOVE_PKT_LOG
    if(enable_pktlog_support) {
        ol_pl_sethandle(&(scn->pl_dev), scn);
        ol_pl_set_name(scn, dev);
    } else {
        scn->pl_dev = NULL;
    }
#endif
    scn->dpdenable = 1;
    scn->scn_amsdu_mask = 0xffff;
    scn->scn_ampdu_mask = 0xffff;

#ifdef QCA_PARTNER_PLATFORM
    ath_pltfrm_init( dev );
#endif

    error = ol_ath_attach(ol_cfg->devid, scn, &ol_wlan_reg_params, ol_ath_linux_update_fw_config_cb);
    if (error)
        goto bad4;

#if ATH_BAND_STEERING
    if ( EOK != ath_band_steering_netlink_init()) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Band steering socket init failed __investigate__ \n");
    }
#endif
#if ATH_SUPPORT_LOWI
    if ( EOK != ath_lowi_if_netlink_init()) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "LOWI driver intferace socket init failed __investigate__ \n");
    }
#endif

    ath_adhoc_netlink_init();

#if ATH_RXBUF_RECYCLE
    ath_rxbuf_recycle_init(osdev);
#endif

    ald_init_netlink();

    osif_attach(dev);
#if 0
    /* For STA Mode default CWM mode is Auto */
    if ( ic->ic_opmode == IEEE80211_M_STA)
        ic->ic_cwm_set_mode(ic, IEEE80211_CWM_MODE2040);
#endif

    /*
     * initialize tx/rx engine
     */
#if 0
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: init tx/rx TODO\n", __func__);
    error = scn->sc_ops->tx_init(scn->sc_dev, ATH_TXBUF);
    if (error != 0)
        goto badTBD;

    error = scn->sc_ops->rx_init(scn->sc_dev, ATH_RXBUF);
    if (error != 0)
        goto badTBD;
#endif

    /*
     * setup net device
     */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
    dev->netdev_ops = &athdev_net_ops;
#else
    dev->open = ath_netdev_open;
    dev->stop = ath_netdev_stop;
    dev->hard_start_xmit = ath_netdev_hardstart;
    dev->set_mac_address = ath_netdev_set_macaddr;
    dev->tx_timeout = ath_netdev_tx_timeout;
    dev->set_multicast_list = ath_netdev_set_mcast_list;
    dev->do_ioctl = ath_ioctl;
    dev->get_stats = ath_getstats;
    dev->change_mtu = ath_change_mtu;
#endif
    dev->watchdog_timeo = 5 * HZ;           /* XXX */
    dev->tx_queue_len = ATH_TXBUF-1;        /* 1 for mgmt frame */

    if (scn->is_ar900b) {
        dev->needed_headroom = sizeof (struct ieee80211_qosframe) +
                                sizeof(struct llc) + IEEE80211_ADDR_LEN +
#if MESH_MODE_SUPPORT
                                sizeof(struct meta_hdr_s) +
#endif
                                IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN;

        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"%s: needed_headroom reservation %d\n", __func__,
                        dev->needed_headroom);
    }
    else {
    dev->hard_header_len += sizeof (struct ieee80211_qosframe) +
                            sizeof(struct llc) + IEEE80211_ADDR_LEN +
#if MESH_MODE_SUPPORT
                            sizeof(struct meta_hdr_s) +
#endif
                            IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN;

        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: hard_header_len reservation %d\n", __func__,
                        dev->hard_header_len);
    }

    if (enable_tx_tcp_cksum) {
        dev->features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
    }

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    ol_ath_enable_fraglist(dev);
#endif

#ifdef QVIT
// Enable ethtool support
#ifdef QVIT_DEBUG
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "QVIT: %s: calling ethtool_ops\n", __func__);
#endif
    qvit_set_ethtool(dev);
#endif

    /*
    ** Attach the iwpriv handlers for perf_pwr_offload device
    */

    ol_ath_iw_attach(dev);

#if OS_SUPPORT_ASYNC_Q
   OS_MESGQ_INIT(osdev, &osdev->async_q, sizeof(os_async_q_mesg),
        OS_ASYNC_Q_MAX_MESGS,os_async_mesg_handler, osdev,MESGQ_PRIORITY_NORMAL,MESGQ_ASYNCHRONOUS_EVENT_DELIVERY);
#endif

    /* Kernel 2.6.25 needs valid dev_addr before  register_netdev */
    IEEE80211_ADDR_COPY(dev->dev_addr,ic->ic_myaddr);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
    SET_MODULE_OWNER(dev);
#endif
    SET_NETDEV_DEV(dev, osdev->device);
    /*
     * finally register netdev and ready to go
     */
    if ((error = register_netdev(dev)) != 0) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: unable to register device\n", dev->name);
        goto bad5;
    }
#if !NO_SIMPLE_CONFIG
    /* Request Simple Config intr handler */
    register_simple_config_callback (dev->name, (void *) jumpstart_intr, (void *) dev,
                                     (void *)&osdev->sc_push_button_dur);
#endif
    sysfs_create_group(&dev->dev.kobj, &wifi_attr_group);
    error = ol_ath_thermal_mitigation_attach(scn, dev);
    if (error) {
        TH_DEBUG_PRINT(TH_DEBUG_LVL0, scn, "%s: unable to attach TT\n", dev->name);
        goto bad5;
    }
#ifdef ATH_SUPPORT_LINUX_STA
#ifdef CONFIG_SYSCTL
    ath_dynamic_sysctl_register(ATH_DEV_TO_SC(scn->sc_dev));
#endif
#endif

#if ATH_RX_LOOPLIMIT_TIMER
    scn->rx_looplimit_timeout = 1;           /* 1 ms by default */
    scn->rx_looplimit_valid = true;          /* set to valid after initilization */
    scn->rx_looplimit = false;
#endif

    /*
     *Should not use ol_num_global_scn as index of the array.
     *Problem with that is: if recovery is enabled, when one of the radio(say wifi0) got target assert,
     *it'll do detach&attach, in attach function __ol_ath_attach(),
     *the ol_num_global_scn is already 1(assume AP has 2 radios),
     *then ol_global_scn[1]=scn will overwrite the scn for wifi1 which was saved in ol_global_scn[1]
     */
    ol_global_scn[radio_id] = scn;
    ol_num_global_scn++;
    scn->radio_attached = 1;

    return 0;


bad5:
    /* TODO - ol_ath_detach */
#if OS_SUPPORT_ASYNC_Q
   OS_MESGQ_DRAIN(&osdev->async_q,NULL);
   OS_MESGQ_DESTROY(&osdev->async_q);
#endif
    osif_detach(dev);

    ald_destroy_netlink();

#if ATH_RXBUF_RECYCLE
    ath_rxbuf_recycle_destroy(osdev);
#endif

    ath_adhoc_netlink_delete();

#if ATH_BAND_STEERING
    ath_band_steering_netlink_delete();
#endif
#if ATH_SUPPORT_LOWI
    ath_lowi_if_netlink_delete();
#endif

bad4:
#if WMI_RECORDING
    if(scn->wmi_proc_entry) {
        wmi_proc_remove(scn->wmi_handle, scn->wmi_proc_entry, ath_get_radio_index(dev));
        remove_proc_entry(dev->name, NULL);
    }
#endif

#if ATH_SSID_STEERING
    ath_ssid_steering_netlink_delete();
#endif
#if PERF_FIND_WDS_NODE
    wds_table_uninit(&scn->scn_wds_table);
#endif

#if ATH_SUPPORT_CODESWAP
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n%s() scn %p Detaching Codeswap\n", __func__, scn);
    ol_codeswap_detach(scn);
#endif

bad1:
    /* TODO - free dev -- reverse alloc_netdev */
    free_netdev(dev);

bad0:
    return error;
}

int
__ol_vap_delete_on_rmmod(struct net_device *dev)
{
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);
    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211vap *vap;
    struct ieee80211vap *vapnext;
    osif_dev  *osifp;
    struct net_device *netdev;

    rtnl_lock();
    /*
     * Don't add any more VAPs after this.
     * Else probably the detach should be done with rtnl_lock() held.
     */
    scn->sc_in_delete = 1;
    vap = TAILQ_FIRST(&ic->ic_vaps);
    while (vap != NULL) {
        /* osif_ioctl_delete_vap() destroy vap->iv_next information,
        so need to store next VAP address in vapnext */
        vapnext = TAILQ_NEXT(vap, iv_next);
        osifp = (osif_dev *)vap->iv_ifp;
        netdev = osifp->netdev;
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Remove interface on %s\n",netdev->name);
        dev_close(netdev);
        osif_ioctl_delete_vap(netdev);
        vap = vapnext;
    }
    rtnl_unlock();

    return 0;
}

int
__ol_ath_detach(struct net_device *dev)
{
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);
    int status;
    int scn_num, scn_idx;

    /*
     * Ok if you are here, no communication with target as
     * already SUSPEND COmmand is gone to target.
     * So cleanup only on Host
     */

    osif_detach(dev);

#ifdef ATH_SUPPORT_LINUX_STA
#ifdef CONFIG_SYSCTL
    ath_dynamic_sysctl_unregister(ATH_DEV_TO_SC(scn->sc_dev));
#endif
#endif

#ifndef NO_SIMPLE_CONFIG
    unregister_simple_config_callback(dev->name);
#endif

#ifdef QVIT
    qvit_cleanup();
#endif
    if (!(scn->down_complete))
        ol_ath_thermal_mitigation_detach(scn, dev);

    sysfs_remove_group(&dev->dev.kobj, &wifi_attr_group);

    if (dev->reg_state == NETREG_REGISTERED)
        unregister_netdev(dev);

#if OS_SUPPORT_ASYNC_Q
   OS_MESGQ_DRAIN(&scn->sc_osdev->async_q,NULL);
   OS_MESGQ_DESTROY(&scn->sc_osdev->async_q);
#endif

#if 0
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: init tx/rx cleanup TODO\n", __func__);
    scn->sc_ops->rx_cleanup(scn->sc_dev);
    scn->sc_ops->tx_cleanup(scn->sc_dev);
#endif


    ath_adhoc_netlink_delete();


#if ATH_BAND_STEERING
    ath_band_steering_netlink_delete();
#endif
#if ATH_SUPPORT_LOWI
    ath_lowi_if_netlink_delete();
#endif

#if ATH_SSID_STEERING
    ath_ssid_steering_netlink_delete();
#endif

#if ATH_RXBUF_RECYCLE
    ath_rxbuf_recycle_destroy(scn->sc_osdev);
#endif /* ATH_RXBUF_RECYCLE */

    ald_destroy_netlink();

    status = ol_ath_detach(scn, 1); /* Force Detach */
#if PERF_FIND_WDS_NODE
    wds_table_uninit(&scn->scn_wds_table);
#endif
    ar_detach(scn->arh);

    scn_idx = 0;
    scn_num = 0;
    while ((scn_num < ol_num_global_scn) && (scn_idx < GLOBAL_SCN_SIZE)) {
        if (ol_global_scn[scn_idx] == scn) {
            ol_global_scn[scn_idx] = NULL;
            break;
        } else if (ol_global_scn[scn_idx] != NULL) {
            scn_num++;
        }
        scn_idx++;
    }

    ol_num_global_scn--;

#if WMI_RECORDING
    if (scn->wmi_proc_entry){
      remove_proc_entry(dev->name, NULL);
    }
#endif

    free_netdev(dev);
#ifdef EPPING_TEST
    qdf_spinlock_destroy(&scn->data_lock);
    del_timer(&scn->epping_timer);
    scn->epping_timer_running = 0;
    skb_queue_purge(&scn->epping_nodrop_queue);
#endif

    return status;
}

void
__ol_target_paused_event(struct ol_ath_softc_net80211 *scn)
{
    wake_up(&scn->sc_osdev->event_queue);
}

void
__ol_ath_suspend_resume_attach(struct net_device *dev)
{
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);
    ol_ath_suspend_resume_attach(scn);
}

int
__ol_ath_suspend(struct net_device *dev)
{
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);
    u_int32_t  timeleft;

    ath_netdev_stop(dev);
    /* Suspend target with diable_target_intr set to 0 */
    if (!ol_ath_suspend_target(scn, 0)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "waiting for target paused event from target\n");
        /* wait for the event from Target*/
        timeleft = wait_event_interruptible_timeout(scn->sc_osdev->event_queue,
                                                    (scn->is_target_paused == TRUE),
                                                    200);
        if(!timeleft || signal_pending(current)) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Failed to receive target paused event \n");
            return -EIO;
        }
        /*
         * reset is_target_paused and host can check that in next time,
         * or it will always be TRUE and host just skip the waiting
         * condition, it causes target assert due to host already suspend
         */
        scn->is_target_paused = FALSE;
        return (0);
    }
    return (-1);
}

int
__ol_ath_resume(struct net_device *dev)
{
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);

    if (ol_ath_resume_target(scn)) {
        return -1;
    }
    ath_netdev_open(dev);
    return 0;
}


void __ol_ath_target_status_update(struct net_device *dev, ol_target_status status)
{
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);
    ol_ath_target_status_update(scn,status);
}

#if !NO_SIMPLE_CONFIG
/*
 * Handler for front panel SW jumpstart switch
 */
static irqreturn_t
jumpstart_intr (int cpl, void *dev_id, struct pt_regs *regs, void *push_time)
{
    struct net_device *dev = dev_id;
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);
    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211vap *vap;
    u_int32_t           push_duration;
    int is_ap_vap_notified = 0;
    /*
    ** Iterate through all VAPs, since any of them may have WPS enabled
    */

    vap = TAILQ_FIRST(&ic->ic_vaps);
    while (vap != NULL) {
        if (push_time) {
            push_duration = *(u_int32_t *)push_time;
        } else {
            push_duration = 0;
        }
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
        if (!ieee80211_vap_nopbn_is_set(vap))
        {
#endif
	        /* Since we are having single physical push button on device ,
    	       and for push button + muti bss combination mode we will be have limitations,
        	   we designed that,physical push button notification will be sent to first
	           AP vap(main BSS) and all sta vaps.
    	    */
	        if (vap->iv_opmode != IEEE80211_M_HOSTAP || is_ap_vap_notified == 0 ){
    	        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "SC Pushbutton Notify on %s for %d sec(s) and the vap %p dev %p:\n",dev->name,
        	            push_duration, vap, (struct net_device *)(((osif_dev *)vap->iv_ifp)->netdev));
	            osif_notify_push_button ((((osif_dev *)vap->iv_ifp)->os_handle), push_duration);
    	        if(vap->iv_opmode == IEEE80211_M_HOSTAP)
        	        is_ap_vap_notified = 1;
	        }
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
        }
#endif
        vap = TAILQ_NEXT(vap, iv_next);

    }
    return IRQ_HANDLED;
}
#endif

#if OS_SUPPORT_ASYNC_Q
static void os_async_mesg_handler( void  *ctx, u_int16_t  mesg_type, u_int16_t  mesg_len, void  *mesg )
{
    if (mesg_type == OS_SCHEDULE_ROUTING_MESG_TYPE) {
        os_schedule_routing_mesg  *s_mesg = (os_schedule_routing_mesg *) mesg;
        s_mesg->routine(s_mesg->context, NULL);
    }
}
#endif

static int qc98xx_verify_checksum(void *eeprom)
{
    uint16_t *p_half;
    uint16_t sum = 0;
    int i;

    p_half = (uint16_t *)eeprom;
    for (i = 0; i < QC98XX_EEPROM_SIZE_LARGEST / 2; i++) {
        sum ^= le16_to_cpu(*p_half++);
    }
    if (sum != 0xffff) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s error: flash checksum 0x%x, computed 0x%x \n", __func__,
                le16_to_cpu(*((uint16_t *)eeprom + 1)), sum ^ 0xFFFF);
        return -1;
    }
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: flash checksum passed: 0x%4x\n", __func__, le16_to_cpu(*((uint16_t *)eeprom + 1)));
    return 0;
}

#define I2C_SDA_GPIO_PIN    5
#define I2C_SDA_PIN_CONFIG  3
#define SI_CLK_GPIO_PIN     17
#define SI_CLK_PIN_CONFIG   3
void config_target_eeprom(struct ol_ath_softc_net80211 *scn)
{
	struct hif_opaque_softc *hif_hdl = (struct hif_opaque_softc *)(scn->hif_hdl);

    /* Enable SI clock */
    hif_reg_write(hif_hdl, (RTC_SOC_BASE_ADDRESS + CLOCK_CONTROL_OFFSET), 0x0);

    /* Configure GPIOs for I2C operation */
    hif_reg_write(hif_hdl,(GPIO_BASE_ADDRESS + GPIO_PIN0_OFFSET + I2C_SDA_GPIO_PIN*4),
                     (WLAN_GPIO_PIN0_CONFIG_SET(I2C_SDA_PIN_CONFIG) |
                      WLAN_GPIO_PIN0_PAD_PULL_SET(1)));

    hif_reg_write(hif_hdl, (GPIO_BASE_ADDRESS + GPIO_PIN0_OFFSET + SI_CLK_GPIO_PIN*4),
                     (WLAN_GPIO_PIN0_CONFIG_SET(SI_CLK_PIN_CONFIG) |
                      WLAN_GPIO_PIN0_PAD_PULL_SET(1)));

    hif_reg_write(hif_hdl,(GPIO_BASE_ADDRESS + GPIO_ENABLE_W1TS_LOW_ADDRESS),
                      1 << SI_CLK_GPIO_PIN);

    /* In Swift ASIC - EEPROM clock will be (110MHz/512) = 214KHz */
    hif_reg_write(hif_hdl, (SI_BASE_ADDRESS + SI_CONFIG_OFFSET),
                      (SI_CONFIG_ERR_INT_SET(1) |
                      SI_CONFIG_BIDIR_OD_DATA_SET(1) |
                      SI_CONFIG_I2C_SET(1) |
                      SI_CONFIG_POS_SAMPLE_SET(1) |
                      SI_CONFIG_INACTIVE_CLK_SET(1) |
                      SI_CONFIG_INACTIVE_DATA_SET(1) |
                      SI_CONFIG_DIVIDER_SET(8)));

}

#define SI_OK                               1
#define SI_ERR                              0
#define DEVICE_SELECT                       0xa0
#define DEVICE_READ                         0xa1000000
#define EEPROM_ADDR_OFFSET_LEN              16 /* in bits */
#define EEPROM_ADDR_OFFSET_LOWER_BYTE_MASK  0x00ff
#define EEPROM_ADDR_OFFSET_UPPER_BYTE_MASK  0xff00

#define MAX_WAIT_COUNTER_POLL_DONE_BIT      100000 /* 1 sec(100000 * 10 usecs) */
#define DELAY_BETWEEN_DONE_BIT_POLL         10     /* In usecs */
static int eeprom_byte_read(struct ol_ath_softc_net80211 *scn, u_int16_t addr_offset, u_int8_t *data)
{

	struct hif_opaque_softc *hif_hdl = (struct hif_opaque_softc *)(scn->hif_hdl);
	u_int32_t reg;
    int wait_limit;

    /* set device select byte and for the read operation */
    reg = DEVICE_SELECT |
          ((addr_offset & EEPROM_ADDR_OFFSET_LOWER_BYTE_MASK) << EEPROM_ADDR_OFFSET_LEN) |
          (addr_offset & EEPROM_ADDR_OFFSET_UPPER_BYTE_MASK) |
          DEVICE_READ ;
    hif_reg_write(hif_hdl, SI_BASE_ADDRESS + SI_TX_DATA0_OFFSET, reg);

    /* write transmit data, transfer length, and START bit */
    hif_reg_write(hif_hdl, SI_BASE_ADDRESS + SI_CS_OFFSET,
                                (SI_CS_START_SET(1) |
                                 SI_CS_RX_CNT_SET(1) |
                                 SI_CS_TX_CNT_SET(4)));

    wait_limit = MAX_WAIT_COUNTER_POLL_DONE_BIT;
    /* poll CS_DONE_INT bit */
    reg = hif_reg_read(hif_hdl, SI_BASE_ADDRESS + SI_CS_OFFSET);
    /* Wait for maximum 1 sec */
    while((wait_limit--) && ((reg & SI_CS_DONE_INT_MASK) != SI_CS_DONE_INT_MASK)) {
            OS_DELAY(DELAY_BETWEEN_DONE_BIT_POLL);
            reg = hif_reg_read(hif_hdl, SI_BASE_ADDRESS + SI_CS_OFFSET);
    }
    if(wait_limit == 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Timeout waiting for DONE_INT bit to be set in SI_CONFIG register\n", __func__);
        return SI_ERR;
    }

    /*
     * Clear DONE_INT bit
     * DONE_INT bit is cleared when 1 is written to this field (or) when the
     * START bit is set in this register
     */
    hif_reg_write(hif_hdl, SI_BASE_ADDRESS + SI_CS_OFFSET, reg);

    if((reg & SI_CS_DONE_ERR_MASK) == SI_CS_DONE_ERR_MASK)
    {
        return SI_ERR;
    }

    /* extract receive data */
    reg = hif_reg_read(hif_hdl, SI_BASE_ADDRESS + SI_RX_DATA0_OFFSET);
    *data = (reg & 0xff);

    return SI_OK;
}
int
ol_transfer_target_eeprom_caldata(struct ol_ath_softc_net80211 *scn, u_int32_t address, bool compressed)
{
    int status = EOK;
    struct firmware fwtemp = {0};
    struct firmware *fw_entry = &fwtemp;
    u_int32_t fw_entry_size, orig_size = 0;
    int i;
    uint32_t *savedestp, *destp, *srcp = NULL;
    u_int8_t *pdst, *psrc,*ptr = NULL;

    struct hif_opaque_softc *sc = (struct hif_opaque_softc *)(scn->hif_hdl);
    if(!sc) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ERROR: sc ptr is NULL\n");
        return -EINVAL;
    }
    if (scn->target_type == TARGET_TYPE_AR9888) {
        QC98XX_EEPROM_SIZE_LARGEST = QC98XX_EEPROM_SIZE_LARGEST_AR988X;
    } else {
        QC98XX_EEPROM_SIZE_LARGEST = QC98XX_EEPROM_SIZE_LARGEST_AR900B;
    }

    // Check for target/host driver mismatch
    if ( scn->target_version != AR9887_REV1_VERSION) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ERROR: UNSUPPORTED TARGET VERSION 0x%x \n", scn->target_version);
        return EOK;
    }
    else {
        u_int8_t *tmp_ptr;
        u_int16_t addr_offset;
        ptr = vmalloc(QC98XX_EEPROM_SIZE_LARGEST);
        if ( NULL == ptr ){
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s %d: target eeprom caldata memory allocation failed\n",__func__, __LINE__);
        return -EINVAL;
        } else {
            tmp_ptr = ptr;
            /* Config for Target EEPROM access */
            config_target_eeprom(scn);
            /* For Swift 2116 bytes of caldata is stored in target */
            for(addr_offset = 0;  addr_offset < QC98XX_EEPROM_SIZE_LARGEST; addr_offset++) {
                if(eeprom_byte_read(scn, addr_offset, tmp_ptr) != SI_OK) {
                    if (ptr)
                        vfree(ptr);
                    return -EINVAL;
                }
                //printk("%s: addr_offset %d value %02x\n", __func__,addr_offset,*tmp_ptr);
                tmp_ptr++;
            }
            if (le16_to_cpu(*(uint16_t *)ptr) != QC98XX_EEPROM_SIZE_LARGEST) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Target EEPROM caldata len %d doesn't equal to %d\n", __func__,
                        le16_to_cpu(*(uint16_t *)ptr), QC98XX_EEPROM_SIZE_LARGEST);
                if (ptr)
                    vfree(ptr);
                return -EINVAL;
            }
            if (qc98xx_verify_checksum(ptr)){
                if (ptr)
                    vfree(ptr);
                return -EINVAL;
            }
            srcp = (uint32_t *)ptr;
            orig_size = QC98XX_EEPROM_SIZE_LARGEST;
            fw_entry->data = ptr;
            fw_entry->size = (orig_size + 3) & ~3;
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s %d: Download Target EEPROM caldata len %d\n",
                    __func__, __LINE__, fw_entry->size);

            savedestp = destp = vmalloc(fw_entry->size);
            if(destp == NULL)
            {
                if (ptr)
                    vfree(ptr);
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s %d: memory allocation failed\n",__func__, __LINE__);
                return -EINVAL;
            }
            pdst = (uint8_t *)destp;
            psrc = (uint8_t *)srcp;

            /* Add pad bytes if required */
            for (i = 0; i < fw_entry->size; i++) {
                if (i < orig_size)
                    pdst[i] = psrc[i];
                else
                    pdst[i] = 0;
            }
            for(i=0; i < (fw_entry->size)/4; i++) {
                *destp = cpu_to_le32(*srcp);
                destp++; srcp++;
            }

            destp = savedestp;
            fw_entry_size = fw_entry->size;

            if (compressed) {
                status = BMIFastDownload(sc, address, (u_int8_t *)destp, fw_entry_size, scn);
            } else {
                status = BMIWriteMemory(sc, address, (u_int8_t *)destp, fw_entry_size, scn);
            }
        }

        if (status != EOK) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s :%d BMI operation failed \n",__func__, __LINE__);
        }

        if (ptr)
            vfree(ptr);

        if(destp)
            vfree(destp);

        if (status != EOK) {
            return -1;
        }
      return status;
    }
}

#define MAX_FILENAME_BUFF_SIZE  256
#define MAX_ABSOLUTE_FILE_SIZE  512

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,4,103) && defined(AH_CAL_IN_FLASH_PCI)
#ifndef CALDATA0_FILE_PATH
#define CALDATA0_FILE_PATH	"/tmp/wifi0.caldata"
#endif

#ifndef CALDATA1_FILE_PATH
#define CALDATA1_FILE_PATH	"/tmp/wifi1.caldata"
#endif

#ifndef CALDATA2_FILE_PATH
#define CALDATA2_FILE_PATH	"/tmp/wifi2.caldata"
#endif
#endif

int
ol_transfer_bin_file(struct ol_ath_softc_net80211 *scn, ATH_BIN_FILE file,
                    u_int32_t address, bool compressed)
{
    int status = EOK;
    const char *filename = NULL;
    const char *pathname = NULL;
    struct firmware fwtemp = {0};
    struct firmware *fw_entry = NULL;
    u_int32_t offset;
    u_int32_t fw_entry_size;
    u_int8_t *tempEeprom = NULL;
    u_int32_t board_data_size = 0;
    u_int8_t *ptr = NULL;
    uint32_t *srcp = NULL;
    uint32_t orig_size = 0;
    char buf[MAX_FILENAME_BUFF_SIZE];
    char absolute_filename[MAX_ABSOLUTE_FILE_SIZE] ;
    int i = 0;
    uint32_t *savedestp = NULL, *destp = NULL;
    u_int8_t *pad_dst = NULL, *pad_src = NULL;
    int rfwst=0;
    struct ieee80211com *ic = &scn->sc_ic;

    /*
     * set caldata length based upon current target type.
     */
    if (scn->target_type == TARGET_TYPE_AR9888) {
        QC98XX_EEPROM_SIZE_LARGEST = QC98XX_EEPROM_SIZE_LARGEST_AR988X;
    } else {
        QC98XX_EEPROM_SIZE_LARGEST = QC98XX_EEPROM_SIZE_LARGEST_AR900B;
    }

    switch (file)
    {
        default:
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Unknown file type\n", __func__);
            return -1;

        case ATH_OTP_FILE:
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"\n Selecting  OTP binary for CHIP Version %d\n", scn->target_revision);
            if (scn->target_version == AR6004_REV1_VERSION) {
                filename = AR6004_REV1_OTP_FILE;
            } else if (scn->target_version == AR9888_REV2_VERSION) {
                filename = AR9888_REV2_OTP_FILE;
            } else if (scn->target_version == AR9887_REV1_VERSION) {
                filename = AR9887_REV1_OTP_FILE;
            } else if (scn->target_version == AR9888_DEV_VERSION) {
                filename = AR9888_DEV_OTP_FILE;
            } else if (scn->target_type == TARGET_TYPE_AR900B) {
                if(scn->target_revision == AR900B_REV_1){
                    filename = AR900B_VER1_OTP_FILE;
                } else if(scn->target_revision == AR900B_REV_2) {
                    filename = AR900B_VER2_OTP_FILE;
                }
            } else if (scn->target_type == TARGET_TYPE_QCA9984) {
                if(emu_type == 0) {
                    if(scn->target_version == QCA9984_DEV_VERSION) {
                        filename = QCA9984_HW_VER1_OTP_FILE;
                    }
                } else {
                    /* otp.bin must not be loaded for emulation
                     * platforms and hence ignoring QCA9984_EMU
                     * cases
                     */
                }
            } else if (scn->target_type == TARGET_TYPE_QCA9888) {
                if(emu_type == 0) {
                    if(scn->target_version == QCA9888_DEV_VERSION) {
                        filename = QCA9888_HW_VER2_OTP_FILE;
                    }
                } else {
                    /* otp.bin must not be loaded for emulation
                     * platforms and hence ignoring QCA9984_EMU
                     * cases
                     */
                }
            } else if (scn->target_type == TARGET_TYPE_IPQ4019) {
                if(emu_type == 0) {
                    if(scn->target_version == IPQ4019_DEV_VERSION) {
                        filename = IPQ4019_HW_VER1_OTP_FILE;
                    }
                } else {
                    /* otp.bin must not be loaded for emulation
                     * platforms and hence ignoring IPQ4019_EMU
                     * cases
                     */
                }
            } else {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: no OTP file defined\n", __func__);
                return -ENOENT;
            }
#if ATH_SUPPORT_CODESWAP
            if (ol_ath_code_data_swap(scn,filename,ATH_OTP_FILE)) {
                return -EIO;
            }
#endif
            break;

        case ATH_FIRMWARE_FILE:
            if ( testmode ) {
                if ( testmode == 1 ) {
                    A_UINT32 param;

                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Test mode\n", __func__);
                    if (scn->target_version == AR6004_REV1_VERSION) {
                        filename = AR6004_REV1_UTF_FIRMWARE_FILE;
                    } else if (scn->target_version == AR9888_REV2_VERSION) {
                        filename = AR9888_REV2_UTF_FIRMWARE_FILE;
                    } else if (scn->target_version == AR9887_REV1_VERSION) {
                        filename = AR9887_REV1_UTF_FIRMWARE_FILE;
                    } else if (scn->target_version == AR9888_DEV_VERSION) {
                        filename = AR9888_DEV_UTF_FIRMWARE_FILE;
                    } else if (scn->target_type == TARGET_TYPE_AR900B) {
                        if(scn->target_revision == AR900B_REV_1){
                            filename = AR900B_VER1_UTF_FIRMWARE_FILE;
                        } else if(scn->target_revision == AR900B_REV_2) {
                            filename = AR900B_VER2_UTF_FIRMWARE_FILE;
                        }
                    } else if (scn->target_type == TARGET_TYPE_QCA9984) {
                        if(emu_type == 0) {
                            if(scn->target_version == QCA9984_DEV_VERSION) {
                                filename = QCA9984_HW_VER1_UTF_FIRMWARE_FILE;
                            }
                        } else if(emu_type == 1) {
                            filename = QCA9984_M2M_VER1_UTF_FIRMWARE_FILE;
                        } else if(emu_type == 2) {
                            filename = QCA9984_BB_VER1_UTF_FIRMWARE_FILE;
                        }
                    } else if (scn->target_type == TARGET_TYPE_QCA9888) {
                        if(emu_type == 0) {
                            if(scn->target_version == QCA9888_DEV_VERSION) {
                                filename = QCA9888_HW_VER2_UTF_FIRMWARE_FILE;
                            }
                        } else if(emu_type == 1) {
                            filename = QCA9888_M2M_VER2_UTF_FIRMWARE_FILE;
                        } else if(emu_type == 2) {
                            filename = QCA9888_BB_VER2_UTF_FIRMWARE_FILE;
                        }
                    } else if (scn->target_type == TARGET_TYPE_IPQ4019) {
                        if(emu_type == 0) {
                            if(scn->target_version == IPQ4019_DEV_VERSION) {
                                filename = IPQ4019_HW_VER1_UTF_FIRMWARE_FILE;
                            }
                        } else if(emu_type == 1) {
                            filename = IPQ4019_M2M_VER1_UTF_FIRMWARE_FILE;
                        } else if(emu_type == 2) {
                            filename = IPQ4019_BB_VER1_UTF_FIRMWARE_FILE;
                        }
                    } else {
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: no firmware file defined\n", __func__);
                        return EOK;
                    }
                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Downloading firmware file: %s\n", __func__, filename);

                    if (BMIReadMemory(scn->hif_hdl,
                        host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_fw_swap)),
                        (A_UCHAR *)&param,4, scn)!= A_OK)
                    {
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "BMIReadMemory for setting FW swap flags failed \n");
                        return A_ERROR;
                    }
                    param |= HI_DESC_IN_FW_BIT;
                    if (BMIWriteMemory(scn->hif_hdl,
                        host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_fw_swap)),
                        (A_UCHAR *)&param,4, scn) != A_OK)
                    {
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "BMIWriteMemory for setting FW swap flags failed \n");
                        return A_ERROR;
                    }
                }
#if ATH_SUPPORT_CODESWAP
                if(ol_ath_code_data_swap(scn,filename,ATH_UTF_FIRMWARE_FILE)) {
                    return -EIO;
                }
#endif
            }
            else {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"\n Mission mode: Firmware CHIP Version %d\n", scn->target_revision);
                if (scn->target_version == AR6004_REV1_VERSION) {
                    filename = AR6004_REV1_FIRMWARE_FILE;
                } else if (scn->target_version == AR9888_REV2_VERSION) {
#if QCA_LTEU_SUPPORT
                    if(scn->lteu_support) {
                        filename = AR9888_REV2_FIRMWARE_FILE_LTEU;
                    } else {
#endif
#if QCA_AIRTIME_FAIRNESS
                    if(ic->atf_mode) {
                        filename = AR9888_REV2_ATF_FIRMWARE_FILE;
                    } else {
#endif
                        filename = AR9888_REV2_FIRMWARE_FILE;
#if QCA_AIRTIME_FAIRNESS
                   }
#endif
#if QCA_LTEU_SUPPORT
                   }
#endif
                } else if (scn->target_version == AR9887_REV1_VERSION) {
                    filename = AR9887_REV1_FIRMWARE_FILE;
                } else if (scn->target_version == AR9888_DEV_VERSION) {
                    filename = AR9888_DEV_FIRMWARE_FILE;
                } else if (scn->target_type == TARGET_TYPE_AR900B) {
                    if(scn->target_revision == AR900B_REV_1){
                        filename = AR900B_VER1_FIRMWARE_FILE;
                    } else if(scn->target_revision == AR900B_REV_2) {
                        filename = AR900B_VER2_FIRMWARE_FILE;
                    }
                } else if (scn->target_type == TARGET_TYPE_QCA9984) {
                    if(emu_type == 0) {
                        if(scn->target_version == QCA9984_DEV_VERSION) {
                            filename = QCA9984_HW_VER1_FIRMWARE_FILE;
                        }
                    } else if(emu_type == 1) {
                        filename = QCA9984_M2M_VER1_FIRMWARE_FILE;
                    } else if(emu_type == 2) {
                        filename = QCA9984_BB_VER1_FIRMWARE_FILE;
                    }
                } else if (scn->target_type == TARGET_TYPE_QCA9888) {
                    if(emu_type == 0) {
                        if(scn->target_version == QCA9888_DEV_VERSION) {
                            filename = QCA9888_HW_VER2_FIRMWARE_FILE;
                        }
                    } else if(emu_type == 1) {
                        filename = QCA9888_M2M_VER2_FIRMWARE_FILE;
                    } else if(emu_type == 2) {
                        filename = QCA9888_BB_VER2_FIRMWARE_FILE;
                    }
                } else if (scn->target_type == TARGET_TYPE_IPQ4019) {
                    if(emu_type == 0) {
                        if(scn->target_version == IPQ4019_DEV_VERSION) {
                            filename = IPQ4019_HW_VER1_FIRMWARE_FILE;
                        }
                    } else if(emu_type == 1) {
                        filename = IPQ4019_M2M_VER1_FIRMWARE_FILE;
                    } else if(emu_type == 2) {
                        filename = IPQ4019_BB_VER1_FIRMWARE_FILE;
                    }
                } else {
                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: no firmware file defined\n", __func__);
                    return EOK;
                }
#if ATH_SUPPORT_CODESWAP
                if(ol_ath_code_data_swap(scn,filename,ATH_FIRMWARE_FILE)) {
                    return -EIO;
                }
#endif
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Downloading firmware file: %s\n", __func__, filename);
            }

#ifdef EPPING_TEST
            if (eppingtest) {
                bypasswmi = TRUE;
                filename = AR6004_REV1_EPPING_FIRMWARE_FILE;
                compressed = 0;
            }
#endif
            break;

        case ATH_PATCH_FILE:
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: no Patch file defined\n", __func__);
            return EOK;

        case ATH_BOARD_DATA_FILE:
            if (scn->target_version == AR6004_REV1_VERSION) {
                filename = AR6004_REV1_BOARD_DATA_FILE;
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Board data file AR6004\n", __func__);
            } else if (scn->target_version == AR9888_REV2_VERSION) {
                filename = AR9888_REV2_BOARD_DATA_FILE;
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Board data file AR9888v2\n", __func__);
            } else if (scn->target_version == AR9887_REV1_VERSION) {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Board data file AR9887v1\n", __func__);
                if (testmode ==1) {
                    filename = AR9887_REV1_BOARDDATA_FILE;
                } else {
                    filename = AR9887_REV1_BOARD_DATA_FILE;
                }
            } else if (scn->target_version == AR9888_DEV_VERSION) {
                filename = AR9888_DEV_BOARD_DATA_FILE;
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Board data file AR9888\n", __func__);
            } else if (scn->target_version == SOC_SW_VERSION) {

		/* QDART condition only */
                if(testmode == 1) {

                    /* initialize file vars */
                    qdf_mem_set(buf, MAX_FILENAME_BUFF_SIZE, 0);
                    qdf_mem_set(absolute_filename,MAX_ABSOLUTE_FILE_SIZE, 0);

                    /* get the PATH variable */
                    if (scn->target_type == TARGET_TYPE_AR900B) {
                        if (scn->target_revision == AR900B_REV_1) {
                            pathname = AR900B_VER1_PATH;
                        } else if (scn->target_revision == AR900B_REV_2) {
                            pathname = AR900B_VER2_PATH;
                        }
                    } else if (scn->target_type == TARGET_TYPE_QCA9984) {
                        if(emu_type == 0) {
                            if(scn->target_version == QCA9984_DEV_VERSION) {
                                pathname = QCA9984_HW_VER1_PATH;
                            }
                        } else if(emu_type == 1) {
                            pathname = QCA9984_M2M_VER1_PATH;
                        } else if(emu_type == 2) {
                            pathname = QCA9984_BB_VER1_PATH;
                        }
                    } else if (scn->target_type == TARGET_TYPE_QCA9888) {
                        if(emu_type == 0) {
                            if(scn->target_version == QCA9888_DEV_VERSION) {
                                pathname = QCA9888_HW_VER2_PATH;
                            }
                        } else if(emu_type == 1) {
                            pathname = QCA9888_M2M_VER2_PATH;
                        } else if(emu_type == 2) {
                            pathname = QCA9888_BB_VER2_PATH;
                        }
                    } else if (scn->target_type == TARGET_TYPE_IPQ4019) {
                        if(emu_type == 0) {
                            if(scn->target_version == IPQ4019_DEV_VERSION) {
                                pathname = IPQ4019_HW_VER1_PATH;
                            }
                        } else if(emu_type == 1) {
                            pathname = IPQ4019_M2M_VER1_PATH;
                        } else if(emu_type == 2) {
                            pathname = IPQ4019_BB_VER1_PATH;
                        }
                    }

                    /* get the file name */
                    if(!qdf_mem_cmp(scn->sc_osdev->netdev->name, "wifi0", 5)){
                        filename = "boarddata_0.bin";
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n wifi0 Select filename %s\n", filename);
                    } else if (!qdf_mem_cmp(scn->sc_osdev->netdev->name, "wifi1", 5)){
                        filename = "boarddata_1.bin";
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n wifi1 Select filename %s\n", filename);
                    } else {
                        filename = "boarddata_2.bin";
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n wifi2 Select filename %s\n", filename);
                    }


                    /* validate PATH and FILE vars */
                    if ((pathname == NULL) || (filename == NULL)) {
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n %s : Unable to get the PATH/FILE name, check chip revision", __FUNCTION__);
                        return EOK;
                    }

                    /* create absolute PATH variable */
                    if (strlcat(absolute_filename, pathname, MAX_ABSOLUTE_FILE_SIZE) >= MAX_ABSOLUTE_FILE_SIZE) {
		        qdf_print("ifname too long: %s\n", pathname);
		        return -1;
		    }
                    if (strlcat(absolute_filename, filename, MAX_ABSOLUTE_FILE_SIZE) >= MAX_ABSOLUTE_FILE_SIZE) {
		       qdf_print("ifname too long: %s\n", filename);
                       return -1;
                    }
                    filename = absolute_filename;

                    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n %s : (Test Mode) For interface (%s) selected filename %s\n",
                            __FUNCTION__, scn->sc_osdev->netdev->name, absolute_filename);

                } else { /* Mission-mode condition only */
#ifdef CONFIG_AR900B_SUPPORT
                    filename = NULL;
                    qdf_mem_set(buf, MAX_FILENAME_BUFF_SIZE, 0);
                    qdf_mem_set(absolute_filename,MAX_ABSOLUTE_FILE_SIZE, 0);
                    if(ol_get_board_id(scn, buf) < 0) {
                        qdf_print("\n %s : BoardData Download Failed\n",__FUNCTION__);
                        return -1;
                    }
                    if (scn->target_type == TARGET_TYPE_AR900B) {
                        if(scn->target_revision == AR900B_REV_1){
                            filename = AR900B_VER1_PATH;
                        } else if(scn->target_revision == AR900B_REV_2) {
                            filename = AR900B_VER2_PATH;
                        }
                    } else if (scn->target_type == TARGET_TYPE_QCA9984) {
                        if(emu_type == 0) {
                            if(scn->target_version == QCA9984_DEV_VERSION) {
                                filename = QCA9984_HW_VER1_PATH;
                            }
                        } else if(emu_type == 1) {
                            filename = QCA9984_M2M_VER1_PATH;
                        } else if(emu_type == 2) {
                            filename = QCA9984_BB_VER1_PATH;
                        }
                    } else if (scn->target_type == TARGET_TYPE_QCA9888) {
                        if(emu_type == 0) {
                            if(scn->target_version == QCA9888_DEV_VERSION) {
                                filename = QCA9888_HW_VER2_PATH;
                            }
                        } else if(emu_type == 1) {
                            filename = QCA9888_M2M_VER2_PATH;
                        } else if(emu_type == 2) {
                            filename = QCA9888_BB_VER2_PATH;
                        }
                    } else if (scn->target_type == TARGET_TYPE_IPQ4019) {
                        if(emu_type == 0) {
                            if(scn->target_version == IPQ4019_DEV_VERSION) {
                                filename = IPQ4019_HW_VER1_PATH;
                            }
                        } else if(emu_type == 1) {
                            filename = IPQ4019_M2M_VER1_PATH;
                        } else if(emu_type == 2) {
                            filename = IPQ4019_BB_VER1_PATH;
                        }
                    } else {
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n %s : Unable to get the PATH/FILE name, check chip revision", __FUNCTION__);
                        return EOK;
                    }

                    /* validate PATH and FILE vars */
                    if (filename == NULL) {
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n %s : Unable to get the FILE name, check chip revision", __FUNCTION__);
                        return EOK;
                    }

                    if (strlcat(absolute_filename,filename,MAX_ABSOLUTE_FILE_SIZE) >= MAX_ABSOLUTE_FILE_SIZE) {
		        qdf_print("filename too long: %s\n", filename);
		        return -1;
		    }
                    if (strlcat(absolute_filename,buf,MAX_ABSOLUTE_FILE_SIZE) >= MAX_ABSOLUTE_FILE_SIZE) {
		        qdf_print("filename too long: %s\n", buf);
                        return -1;
                    }
                    filename = absolute_filename ;
#else
                    filename = ARXXXX_DEV_BOARD_DATA_FILE;
#endif
                }
            } else {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: no Board data file defined\n", __func__);
                return EOK;
            }
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Board Data File download to address=0x%x file name=%s\n", __func__,
                     address,(filename ? filename : "ERROR: NULL FILE NAME"));
            break;

        case ATH_FLASH_FILE:
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: flash data file defined\n", __func__);
            break;

    }
    // No File present for Flash only memmapped
    if(file != ATH_FLASH_FILE) {
        if (!filename) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:%d filename null \n", __func__, __LINE__);
            if ( emu_type && file == ATH_OTP_FILE ) {
                return -ENOENT;
            }
            return -1;
        }
#if FW_CODE_SIGN
        rfwst = request_secure_firmware((struct firmware **)&fw_entry,
                filename, scn->sc_osdev->device, scn->device_id);
#else
        rfwst = request_firmware((const struct firmware **)&fw_entry, filename, scn->sc_osdev->device);
#endif  /* FW_CODE_SIGN */
        if ((rfwst != 0)) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Failed to get %s\n", __func__, filename);

            if ( file == ATH_OTP_FILE ) {
                return -ENOENT;
            }
            return -1;
        }

        srcp = (uint32_t *)fw_entry->data;
        orig_size = fw_entry->size;
        fw_entry->size = (orig_size + (sizeof(int) - 1)) & ~(sizeof(int) - 1); /* round off to 4 bytes */
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"%s %d: downloading file %d, Download data len %d\n", __func__, __LINE__, file, fw_entry->size);
    }

    if (file == ATH_FLASH_FILE)
    {
#ifdef  ATH_CAL_NAND_FLASH
        int ret_val=0;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,4,103)
        int ret_len;
#else
        char * filename;
#endif
	u_int32_t cal_location;
#endif
        fw_entry = (struct firmware *)&fwtemp;
#ifdef AH_CAL_IN_FLASH_PCI
        if (!scn->cal_in_flash) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: flash cal data address is not mapped\n", __func__);
            return -EINVAL;
        }

#ifdef  ATH_CAL_NAND_FLASH
			cal_location = CalAddr[scn->cal_idx-1];
			QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Cal location [%d]: %08x\n", scn->cal_idx-1, cal_location);
			ptr = vmalloc(QC98XX_EEPROM_SIZE_LARGEST);
        if ( NULL == ptr )
        {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s %d: flash cal data(NAND)memory allocation failed\n",__func__, __LINE__);
            return -EINVAL;
        }
        else
        {
            if(!qdf_mem_cmp(scn->sc_osdev->netdev->name, "wifi0", 5))
            {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n Wifi0 NAND FLASH Select OFFSET 0x%x\n",cal_location + FLASH_CAL_START_OFFSET);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,4,103)
                ret_val = OS_NAND_FLASH_READ(ATH_CAL_NAND_PARTITION, cal_location + FLASH_CAL_START_OFFSET ,QC98XX_EEPROM_SIZE_LARGEST,&ret_len,ptr);
#else
                filename = CALDATA0_FILE_PATH;
                if(A_ERROR ==  qdf_fs_read(filename, 0, QC98XX_EEPROM_SIZE_LARGEST, ptr)) {
                        qdf_print("%s[%d], Error: Reading %s failed.\n", __func__, __LINE__, filename);
                        ret_val =  -EINVAL;
                }
#endif
            }
            else
            {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n %s NAND FLASH Select OFFSET 0x%x\n",scn->sc_osdev->netdev->name, cal_location + FLASH_CAL_START_OFFSET);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,4,103)
                ret_val = OS_NAND_FLASH_READ(ATH_CAL_NAND_PARTITION, cal_location + FLASH_CAL_START_OFFSET ,QC98XX_EEPROM_SIZE_LARGEST,&ret_len,ptr);
#else
                if (!qdf_mem_cmp(scn->sc_osdev->netdev->name, "wifi1", 5)) {
                        filename = CALDATA1_FILE_PATH;
                } else if (!qdf_mem_cmp(scn->sc_osdev->netdev->name, "wifi2", 5)) {
                        filename = CALDATA2_FILE_PATH;
                }
                if(A_ERROR ==  qdf_fs_read(filename, 0, QC98XX_EEPROM_SIZE_LARGEST, ptr)) {
                        qdf_print("%s[%d], Error: Reading %s failed.\n", __func__, __LINE__, filename);
                        ret_val =  -EINVAL;
                }
#endif
            }
            if (ret_val)
            {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s %d: ATH_CAL_NAND Partition flash cal data(NAND) read failed\n",__func__, __LINE__ );
                if (ptr) {
                    vfree(ptr);
                }
                return -EINVAL;
            }
        }
#else
        if (!scn->cal_mem ){
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: NOR FLASH cal data address is not mapped\n", __func__);
            return -EINVAL;
        }

        if(!qdf_mem_cmp(scn->sc_osdev->netdev->name, "wifi0", 5))
        {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n NOR FLASH Wifi0 Select OFFSET %x\n",FLASH_CAL_START_OFFSET);
            ptr = scn->cal_mem + FLASH_CAL_START_OFFSET;
        }
        else
        {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n %s NOR FLASH Select OFFSET %x\n",scn->sc_osdev->netdev->name, FLASH_CAL_START_OFFSET);
            ptr = scn->cal_mem + FLASH_CAL_START_OFFSET;
        }

#endif
#endif

#ifdef AH_CAL_IN_FILE_HOST
	{
		char * filename;

		if (!scn->cal_in_file) {
			QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: cal data file is not ready.\n", __func__);
			return -EINVAL;
		}

		if (0 == qdf_mem_cmp(scn->sc_osdev->netdev->name, "wifi0", 5))
		{
			filename = CALDATA0_FILE_PATH;
		}
		else if (0 == qdf_mem_cmp(scn->sc_osdev->netdev->name, "wifi1", 5))
		{
			filename = CALDATA1_FILE_PATH;
		}
		else if (0 == qdf_mem_cmp(scn->sc_osdev->netdev->name, "wifi2", 5))
		{
			filename = CALDATA2_FILE_PATH;
		}
		else
		{
			QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s[%d], Error, Please check why none of wifi0 wifi1 or wifi2 is your device name (%s).\n",
					__func__, __LINE__, scn->sc_osdev->netdev->name);
			return A_ERROR;
		}

		QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s[%d] Get Caldata for %s.\n", __func__, __LINE__, scn->sc_osdev->netdev->name);

		if(NULL == filename)
		{
			QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s[%d], Error: File name is null, please assign right caldata file name.\n", __func__, __LINE__);
			return -EINVAL;
		}

		ptr = vmalloc(QC98XX_EEPROM_SIZE_LARGEST);
		if ( NULL == ptr ){
			QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s %d: Memory allocation for calibration file failed.\n",__func__, __LINE__);
			return -A_NO_MEMORY;
		}

		if(A_ERROR ==  qdf_fs_read(filename, 0, QC98XX_EEPROM_SIZE_LARGEST, ptr))
		{
			scn->cal_in_file = 0;
			QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s[%d], Error: Reading %s failed.\n", __func__, __LINE__, filename);
			if(ptr)
				vfree(ptr);
			return A_ERROR;
		}
	}
#endif

        if (NULL == ptr) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s %d: Memory allocation failed.\n",__func__, __LINE__);

            return -EINVAL;
        }

        if (le16_to_cpu(*(uint16_t *)ptr) != QC98XX_EEPROM_SIZE_LARGEST) {
#ifdef AH_CAL_IN_FILE_HOST
            scn->cal_in_file = 0;
#endif
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: flash cal data len %d doesn't equal to %d\n", __func__, le16_to_cpu(*(uint16_t *)ptr), QC98XX_EEPROM_SIZE_LARGEST);
#if defined(ATH_CAL_NAND_FLASH) || defined(AH_CAL_IN_FILE_HOST)
            if (ptr) {
                vfree(ptr);
            }
#endif
            return -EINVAL;
        }

        if (qc98xx_verify_checksum(ptr)){
#ifdef AH_CAL_IN_FILE_HOST
            scn->cal_in_file = 0;
#endif
#if defined(ATH_CAL_NAND_FLASH) || defined(AH_CAL_IN_FILE_HOST)
            if (ptr) {
                vfree(ptr);
            }
#endif
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n ===> CAL CHECKSUM FAILED <=== \n");
            return -EINVAL;
        }

        srcp = (uint32_t *)ptr;
        orig_size = QC98XX_EEPROM_SIZE_LARGEST;
        fw_entry->data = ptr;
        fw_entry->size = (orig_size + 3) & ~3;
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s %d: Download Flash data len %d\n", __func__, __LINE__, fw_entry->size);
    }

    if (fw_entry->data == NULL) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:%d fw_entry->data == NULL \n", __func__, __LINE__);
#if defined(ATH_CAL_NAND_FLASH) || defined(AH_CAL_IN_FILE_HOST)
        if (ptr) {
            vfree(ptr);
        }
#endif
        return -EINVAL;
    }

    savedestp = destp = vmalloc(fw_entry->size);
    if(destp == NULL)
    {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s %d: memory allocation failed\n",__func__, __LINE__);
#if FW_CODE_SIGN
        release_secure_firmware(fw_entry);
#else
        release_firmware(fw_entry);
#endif  /* FW_CODE_SIGN */
#if defined(ATH_CAL_NAND_FLASH) || defined(AH_CAL_IN_FILE_HOST)
        if (ptr) {
            vfree(ptr);
        }
#endif
        return A_ERROR;
    }
    pad_dst = (uint8_t *)destp;
    pad_src = (uint8_t *)srcp;

    /* Add pad bytes if required */
    for (i = 0; i < fw_entry->size; i++) {
        if (i < orig_size) {
            pad_dst[i] = pad_src[i];
        } else {
            pad_dst[i] = 0;
        }
    }

    for (i = 0; i < (fw_entry->size)/4; i++) {
	    *destp = qdf_cpu_to_le32(*srcp);
	    destp++; srcp++;
    }

    destp = savedestp;

    fw_entry_size = fw_entry->size;
    tempEeprom = NULL;

    if ((file == ATH_BOARD_DATA_FILE) || (file == ATH_FLASH_FILE))
    {
        u_int32_t board_ext_address = 0;
        int32_t board_ext_data_size;

        tempEeprom = OS_MALLOC(scn->sc_osdev, fw_entry_size, GFP_ATOMIC);
        if (!tempEeprom) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Memory allocation failed\n", __func__);
#if FW_CODE_SIGN
            release_secure_firmware(fw_entry);
#else
            release_firmware(fw_entry);
#endif /* FW_CODE_SIGN */
#if defined(ATH_CAL_NAND_FLASH) || defined(AH_CAL_IN_FILE_HOST)
            if (ptr) {
                vfree(ptr);
            }
#endif
            if(destp) {
                vfree(destp);
            }

            return A_ERROR;
        }

        OS_MEMCPY(tempEeprom, (u_int8_t *)destp, fw_entry_size);

        switch (scn->target_type)
        {
            default:
                board_ext_data_size = 0;
                break;
            case TARGET_TYPE_AR6004:
                board_data_size =  AR6004_BOARD_DATA_SZ;
                board_ext_data_size = AR6004_BOARD_EXT_DATA_SZ;
                break;
            case TARGET_TYPE_AR9888:
                board_data_size =  AR9888_BOARD_DATA_SZ;
                board_ext_data_size = AR9888_BOARD_EXT_DATA_SZ;
                break;
        }

#ifdef SOFTMAC_FILE_USED
        ar6000_softmac_update(ar, tempEeprom, board_data_size);
#endif

        /* Determine where in Target RAM to write Board Data */
        if (BMIReadMemory(scn->hif_hdl,
                HOST_INTEREST_ITEM_ADDRESS(scn->target_type, hi_board_ext_data),
                (u_int8_t *)&board_ext_address, 4, scn)!= A_OK)
        {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "BMIReadMemory for Board extended Data download failed \n");
#if FW_CODE_SIGN
            release_secure_firmware(fw_entry);
#else
            release_firmware(fw_entry);
#endif /* FW_CODE_SIGN */
#if defined(ATH_CAL_NAND_FLASH) || defined(AH_CAL_IN_FILE_HOST)
            if (ptr) {
                vfree(ptr);
            }
#endif
            if(destp) {
                vfree(destp);
            }

            return A_ERROR;
        }
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"Board extended Data download address: 0x%x\n", board_ext_address);

        /*
         * Check whether the target has allocated memory for extended board
         * data and file contains extended board data
         */
        if ((board_ext_address) && (fw_entry_size == (board_data_size + board_ext_data_size)))
        {
            u_int32_t param;

            status = BMIWriteMemory(scn->hif_hdl, board_ext_address,
                    (u_int8_t *)(((A_UINT32)tempEeprom) + board_data_size), board_ext_data_size, scn);

            if (status != EOK) {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: BMI operation failed: %d\n", __func__, __LINE__);
#if FW_CODE_SIGN
                release_secure_firmware(fw_entry);
#else
                release_firmware(fw_entry);
#endif  /* FW_CODE_SIGN */
#if defined(ATH_CAL_NAND_FLASH) || defined(AH_CAL_IN_FILE_HOST)
                if (ptr) {
                    vfree(ptr);
                }
#endif
                if(destp) {
                    vfree(destp);
                }

                return -1;
            }

            /* Record the fact that extended board Data IS initialized */
            param = (board_ext_data_size << 16) | 1;
            BMIWriteMemory(scn->hif_hdl,
                    HOST_INTEREST_ITEM_ADDRESS(scn->target_type, hi_board_ext_data_config),
                    (u_int8_t *)&param, 4, scn);

            fw_entry_size = board_data_size;
        }
    }

    offset = 0;

#if defined(ATH_CONFIG_FW_SIGN)

    A_UINT32 length;
    SIGN_HEADER_T *sign_header;

    if (0 || (file == ATH_FIRMWARE_FILE) || (file == ATH_OTP_FILE) || (file == ATH_BOARD_DATA_FILE)) {

        if (file == ATH_BOARD_DATA_FILE) {
            /* board data is not uploaded using segmented write but
             * sending to BMI_SEGMENTED_WRITE_ADDR is the only way to
             * reset the secure boot state machine. Hence the following.
             */
		#waring "ATH_BOARD_DATA_FILE inside\n";
            status = BMISignStreamStart(scn->hif_hdl, BMI_SEGMENTED_WRITE_ADDR, (u_int8_t *)destp, sizeof(SIGN_HEADER_T), scn);
        } else {
            status = BMISignStreamStart(scn->hif_hdl, address, (u_int8_t *)destp, sizeof(SIGN_HEADER_T), scn);
        }

        if(A_FAILED(status)) {
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("Unable to start sign stream\n"));
#if defined(ATH_CAL_NAND_FLASH) || defined(AH_CAL_IN_FILE_HOST)
            if (ptr) {
                vfree(ptr);
            }
#endif
            if(destp) {
                vfree(destp);
            }

            return A_ERROR;
        }

        sign_header = (SIGN_HEADER_T *)(destp);
        offset = sizeof(SIGN_HEADER_T);
        fw_entry_size = length = sign_header->rampatch_len - sizeof(SIGN_HEADER_T);
    }

#endif

    if (compressed) {

        status = BMIFastDownload(scn->hif_hdl, address, (u_int8_t *)destp + offset, fw_entry_size, scn);
    } else {
        status = (0
#if ! defined(ATH_CONFIG_FW_SIGN)
            || (file == ATH_BOARD_DATA_FILE)
#endif
            || (file == ATH_FLASH_FILE)
            );
        if (status && tempEeprom) {
            status = BMIWriteMemory(scn->hif_hdl, address, (u_int8_t *)tempEeprom, fw_entry_size, scn);
        } else {

#if defined(ATH_CONFIG_FW_SIGN)
            status = BMIWriteMemory(scn->hif_hdl, address, (u_int8_t *)destp + offset, fw_entry_size, scn);
#else
            status = BMIWriteMemory(scn->hif_hdl, address, (u_int8_t *)destp, fw_entry_size, scn);
#endif
        }
    }

#if defined(ATH_CONFIG_FW_SIGN)
    if (0 || (file == ATH_FIRMWARE_FILE) || (file == ATH_OTP_FILE) || (file == ATH_BOARD_DATA_FILE)) {

        status = BMISignStreamStart(scn->hif_hdl, 0, (u_int8_t *)destp + length + sizeof(SIGN_HEADER_T), sign_header->total_len - sign_header->rampatch_len, scn);

        if(A_FAILED(status)) {
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("Unable to end sign stream\n"));
        }
    }
#endif

    if (file == ATH_FLASH_FILE) {
#if defined(ATH_CAL_NAND_FLASH) || defined(AH_CAL_IN_FILE_HOST)
        if (ptr) {
            vfree(ptr);
        }
#endif
    }

    if(destp) {
        vfree(destp);
    }

    if (tempEeprom) {
        OS_FREE(tempEeprom);
    }

    if (status != EOK) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "BMI operation failed: %d\n", __LINE__);
#if FW_CODE_SIGN
        release_secure_firmware(fw_entry);
#else
        release_firmware(fw_entry);
#endif  /* FW_CODE_SIGN */
        return -1;
    }

    if(file != ATH_FLASH_FILE) {
#if FW_CODE_SIGN
        release_secure_firmware(fw_entry);
#else
        release_firmware(fw_entry);
#endif /* FW_CODE_SIGN */
    }

    return status;
}

int
__ol_ath_check_wmi_ready(struct ol_ath_softc_net80211 *scn)
{
    int32_t timeleft;
    /*It is observed in some high CPU load scenarios, WMI_INIT is sent late
     * proivinding aditional 5 sec time to send WMI_INIT and receive WMI
     * ready event only for these conditions
     */
    timeleft = wait_event_interruptible_timeout(scn->sc_osdev->event_queue,
                ((scn->wmi_service_ready == TRUE) && (scn->wmi_ready == TRUE)),
                (scn->sc_osdev->wmi_timeout+5) * HZ);

    if (!timeleft)
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WMI is not ready\n");
        return -EIO;
    } else if (signal_pending(current)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Wait was interrupted by a signal. Error code = %d\n", timeleft);

        /* WAR: Wait uninterrupted for a small amount of time to give a chance
         * to pending events to come through. Else we could have issues on
         * preemptible kernels leading to crashes in the control stack since
         * communication is attempted when our caller is doing a cleanup. The
         * wait is expected to be very short if the FW is working correctly (a
         * max of ~200 ms has been seen so far).
         *
         * This is a reasonable trade-off versus having multiple lock checks
         * deep in the stack - this would touch all WMI communication and impose
         * unnecessary penalties for an init time requirement (there exist
         * scenarios requiring high WMI event traffic during regular operation
         * post init).
         */

        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Waiting uninterrupted for %u second(s) before returning\n",
                    scn->sc_osdev->wmi_timeout_unintr);
        timeleft = wait_event_timeout(scn->sc_osdev->event_queue,
                (scn->wmi_ready == TRUE), scn->sc_osdev->wmi_timeout_unintr * HZ);

        if (!timeleft && scn->wmi_ready != TRUE) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "**WMI ready not received from FW despite wait of %u "
                   "second(s). Investigate!! Bailing out**\n",
                   scn->sc_osdev->wmi_timeout_unintr);
        }

        /* Return irrespective of result */
        return -EIO;
    }

    if (scn->version.abi_ver != SOC_ABI_VERSION) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ABI Version mismatch: Host(0x%x), Target(0x%x)\n",
                SOC_ABI_VERSION, scn->version.abi_ver);
    }

    /* Return failure if FW anounced 160/80+80 MHz wireless modes
     * and vhtcap entries are either invalid or out of sync.
     */
    if (scn->invalid_vht160_info) {
        return -EPERM;
    }

    return EOK;
}

void
__ol_ath_wmi_ready_event(struct ol_ath_softc_net80211 *scn)
{
    wake_up(&scn->sc_osdev->event_queue);
}

#define BMI_EXCHANGE_TIMEOUT_MS  1000

/*
 * Issue a BMI command from a user agent to a Target.
 *
 * Note: A single buffer is used for requests and responses.
 * Synchronization is not enforced by this module.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
static ssize_t
ath_sysfs_BMI_write(struct file *file, struct kobject *kobj,
                   struct bin_attribute *bin_attr,
                   char *buf, loff_t pos, size_t count)
#else
static ssize_t
ath_sysfs_BMI_write(struct kobject *kobj,
                   struct bin_attribute *bin_attr,
                   char *buf, loff_t pos, size_t count)
#endif
{
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)(bin_attr->private);
    A_UINT32 cmd;
    unsigned int nbytes;
    A_UINT8 *bmi_response_buf;
    u_int32_t *bmi_response_lengthp;

    nbytes = min(count, (size_t)BMI_DATASZ_MAX);
    OS_MEMCPY(scn->pBMICmdBuf, buf, nbytes); /* NB: buf is in kernel space */
    cmd = *((A_UINT32 *)scn->pBMICmdBuf); /* peek at command */

    if (cmd == BMI_DONE) {
        /*
         * Handle BMI_DONE specially -- signal
         * that the BMI user agent is done.
         */
        ol_ath_signal_bmi_user_agent_done(scn);
        return nbytes;
    }

    switch(cmd) {
    /* Commands that expect a response from the Target */
    case BMI_READ_MEMORY:
    case BMI_EXECUTE:
    case BMI_READ_SOC_WORD:
    case BMI_GET_TARGET_INFO:
    case BMI_ROMPATCH_INSTALL:
    case BMI_NVRAM_PROCESS:
        bmi_response_buf = scn->pBMIRspBuf;
        bmi_response_lengthp = &scn->last_rxlen;
        break;

    /* Commands that do NOT expect a response from the Target */
    case BMI_WRITE_MEMORY:
    case BMI_SET_APP_START:
    case BMI_WRITE_SOC_WORD:
    case BMI_ROMPATCH_UNINSTALL:
    case BMI_ROMPATCH_ACTIVATE:
    case BMI_ROMPATCH_DEACTIVATE:
    case BMI_LZ_STREAM_START:
    case BMI_LZ_DATA:
        bmi_response_buf = NULL;
        bmi_response_lengthp = NULL;
        break;

    default:
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "BMI sysfs command unknown (%d)\n", cmd);
        return A_ERROR;
    }

    if (QDF_STATUS_SUCCESS != hif_exchange_bmi_msg(scn->hif_hdl,
                               scn->BMICmd_pa,
                               scn->BMIRsp_pa,
                               scn->pBMICmdBuf,
                               (A_UINT32)nbytes,
                               bmi_response_buf,
                               bmi_response_lengthp,
                               BMI_EXCHANGE_TIMEOUT_MS))

    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "BMI sysfs command failed\n");
        return A_ERROR;
    }

    return nbytes;
}

/*
 * Pass a Target's response back to a user agent.  The response
 * is to a BMI command that was issued earlier through
 * ath_sysfs_BMI_write.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
static ssize_t
ath_sysfs_BMI_read(struct file *file, struct kobject *kobj,
                   struct bin_attribute *bin_attr,
                   char *buf, loff_t pos, size_t count)
#else
static ssize_t
ath_sysfs_BMI_read(struct kobject *kobj,
                   struct bin_attribute *bin_attr,
                   char *buf, loff_t pos, size_t count)
#endif
{
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)(bin_attr->private);
    unsigned int nbytes;

    nbytes = min(count, scn->last_rxlen);
    OS_MEMCPY(buf, scn->pBMIRspBuf, nbytes); /* NB: buf is in kernel space */

    return nbytes;
}

unsigned int
ol_ath_bmi_user_agent_init(struct ol_ath_softc_net80211 *scn)
{
    int ret;
    struct bin_attribute *BMI_fsattr;

    if (!bmi) {
        return 0; /* User agent not requested */
    }

    scn->bmiUADone = FALSE;

    BMI_fsattr = OS_MALLOC(scn->sc_osdev, sizeof(*BMI_fsattr), GFP_KERNEL);
    if (!BMI_fsattr) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Memory allocation failed\n", __func__);
        return 0;
    }
    OS_MEMZERO(BMI_fsattr, sizeof(*BMI_fsattr));

    BMI_fsattr->attr.name = "bmi";
    BMI_fsattr->attr.mode = 0600;
    BMI_fsattr->read = ath_sysfs_BMI_read;
    BMI_fsattr->write = ath_sysfs_BMI_write;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
    sysfs_bin_attr_init(BMI_fsattr);
#endif
    ret = sysfs_create_bin_file(&scn->sc_osdev->device->kobj, BMI_fsattr);
    if (ret) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: sysfs create failed\n", __func__);
        OS_FREE(BMI_fsattr);
        return 0;
    }

    BMI_fsattr->private = scn;
    scn->bmi_ol_priv = (void *)BMI_fsattr;

    return bmi;
}

int
ol_ath_wait_for_bmi_user_agent(struct ol_ath_softc_net80211 *scn)
{
    int rv;
    struct bin_attribute *BMI_fsattr = (struct bin_attribute *)scn->bmi_ol_priv;

    rv = wait_event_interruptible(scn->sc_osdev->event_queue, (scn->bmiUADone));

    sysfs_remove_bin_file(&scn->sc_osdev->device->kobj, BMI_fsattr);
    scn->bmi_ol_priv = NULL; /* sanity */

    return rv;
}

void
ol_ath_signal_bmi_user_agent_done(struct ol_ath_softc_net80211 *scn)
{
    scn->bmiUADone = TRUE;
    wake_up(&scn->sc_osdev->event_queue);
}

extern void ath_sysfs_diag_init(struct ol_ath_softc_net80211 *scn);
extern void ath_sysfs_diag_fini(struct ol_ath_softc_net80211 *scn);

void
ol_ath_diag_user_agent_init(struct ol_ath_softc_net80211 *scn)
{
#if defined(CONFIG_ATH_SYSFS_DIAG_SUPPORT)
    ath_sysfs_diag_init(scn);
#endif
}

void
ol_ath_diag_user_agent_fini(struct ol_ath_softc_net80211 *scn)
{
#if defined(CONFIG_ATH_SYSFS_DIAG_SUPPORT)
    ath_sysfs_diag_fini(scn);
#endif
}


#if defined(HIF_PCI)
/* BEGIN AR9888v1 WORKAROUND for EV#106293 { */

/*
 * This is a workaround for a HW issue in AR9888v1 in which there is
 * some chance that a write from Host to Target register at address X
 * may have a side effect of writing a value to X+4 (as well as the
 * requested write to X).  The value written to X+4 is whatever value
 * was read by the Host 3 reads prior.  The write to X+4 is just as
 * if software * had done it intentionally (so all effects that would
 * normally occur if that register were written do occur).
 *
 * Example1: Host tries to clear a few bits in a Copy Engine's HOST_IS
 * register (offset 0x30). As a side effect, the CE's MISC_IE register
 * (offset 0x34) is overwritten with a recently read value.
 *
 * Example2: A CE is used for Host to Target transfers, so the
 * Source Ring is maintained by the Host.  When the Host writes the
 * Source Ring Write Index, the Destination Ring Write Index is corrupted.
 *
 * The general workaround is to
 *  A) force the third read prior to a write(X) to be a read(X+4).
 *     That way, when X+4 is overwritten, it will be overwritten
 *     with the value that was there originally.
 *  B) Use a dedicated spin lock and block interrupts in order to
 *     guarantee that the above 3 reads + write occur atomically
 *     with respect to other writes from Host to Target.
 * In addition, special handling is needed for cases when re-writing
 * a value to the register at X+4 has side effects.  The only case
 * of this that occurs in practice is Example2, above.  If we simply
 * allow hardware to re-commit the value in DST_WR_IDX we may run
 * into problems: The Target may update DST_WR_IDX after our first
 * read but before the write. In that case, our re-commit is a
 * stale value. This has a catostophic side-effect because the CE
 * interprets this as a Destination Overflow.  The CE reacts by
 * setting the DST_OVFL bit in MISC_IS and halting the CE. It can
 * only be restarted with a very expensive operation of flushing,
 * re-queueing descriptors (and per-transfer software arguments)
 * and then re-starting the CE.  Rather than attempt this expensive
 * recovery process, we try to avoid this situation by synchronizing
 * Host writes(SR_WR_IDX) with Target writes(DST_WR_IDX).  The
 * currently implementation uses the low bit of DST_WATERMARK
 * register for this synchronization and it relies on reasonable
 * timing characteristics (rather than a stronger synchronization
 * algorithm --  Dekker's, etc.).  Because we rely on timing -- as
 * well as to minimize busy waiting on the Target side -- both
 * Host and Target disable interrupts for the duration of the
 * workaround.
 *
 * The intent is to fix this in HW so this is a temporary workaround.
 */


/*
 * Allow this workaround to be disabled when the driver is loaded
 * by adding "war1=0" to "insmod umac".  There is still a bit of
 * additional overhead.  Can be disabled on the small portion (10%?)
 * of boards that don't suffer from EV#106293.
 */
unsigned int war1 = 1;
module_param(war1, int, 0644);

/*
 * Allow to use CDC WAR which reaches less peak throughput but allow
 * SoC to go to sleep. By default it is disabled.
 */
unsigned int war1_allow_sleep = 0;
module_param(war1_allow_sleep, int, 0644);

DEFINE_SPINLOCK(pciwar_lock);

void
WAR_PCI_WRITE32(char *addr, u32 offset, u32 value)
{
#ifdef QCA_PARTNER_PLATFORM
    WAR_PLTFRM_PCI_WRITE32(addr, offset, value, war1);
#else
    if (war1) {
        unsigned long irq_flags;

        spin_lock_irqsave(&pciwar_lock, irq_flags);

        (void)ioread32((void __iomem *)(addr+offset+4)); /* 3rd read prior to write */
        (void)ioread32((void __iomem *)(addr+offset+4)); /* 2nd read prior to write */
        (void)ioread32((void __iomem *)(addr+offset+4)); /* 1st read prior to write */
        iowrite32((u32)(value), (void __iomem *)(addr+offset));

        spin_unlock_irqrestore(&pciwar_lock, irq_flags);
    } else {
        iowrite32((u32)(value), (void __iomem *)(addr+offset));
    }
#endif
}
EXPORT_SYMBOL(war1);
EXPORT_SYMBOL(war1_allow_sleep);
EXPORT_SYMBOL(WAR_PCI_WRITE32);
/* } END AR9888v1 WORKAROUND for EV#106293 */
#endif

/* Update host conig based on Target info */
void ol_ath_host_config_update(struct ol_ath_softc_net80211 *scn)
{
    if (scn->target_version == AR900B_DEV_VERSION || (scn->target_version == AR9888_REV2_VERSION) || (scn->target_version == AR9887_REV1_VERSION || scn->target_version == QCA9984_DEV_VERSION || scn->target_version == IPQ4019_DEV_VERSION || scn->target_version == QCA9888_DEV_VERSION)) {
        /* AR9888v1 CDC WORKAROUND for EV#106293 */
#if defined(HIF_PCI)
        hif_ce_war_disable();
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"\n CE WAR Disabled\n");
#endif
    }

#if QCA_LTEU_SUPPORT
    if (scn->target_version != AR9888_REV2_VERSION) {
        scn->lteu_support = 0;
    }
#endif
}

EXPORT_SYMBOL(__ol_ath_attach);
EXPORT_SYMBOL(__ol_ath_detach);
EXPORT_SYMBOL(ol_transfer_bin_file);
EXPORT_SYMBOL(__ol_ath_target_status_update);
EXPORT_SYMBOL(__ol_ath_check_wmi_ready);
EXPORT_SYMBOL(__ol_ath_wmi_ready_event);
EXPORT_SYMBOL(ol_ath_bmi_user_agent_init);
EXPORT_SYMBOL(ol_ath_wait_for_bmi_user_agent);
EXPORT_SYMBOL(ol_ath_signal_bmi_user_agent_done);
EXPORT_SYMBOL(ol_ath_diag_user_agent_init);
EXPORT_SYMBOL(ol_ath_diag_user_agent_fini);
EXPORT_SYMBOL(ol_ath_host_config_update);

#ifndef REMOVE_PKT_LOG
extern struct ol_pl_os_dep_funcs *g_ol_pl_os_dep_funcs;
#endif

#if FW_CODE_SIGN


const static fw_device_id fw_auth_supp_devs[] =
    {
        {0x3Cu, "PEREGRINE",    FW_IMG_MAGIC_PEREGRINE},
        {0x50u, "SWIFT",        FW_IMG_MAGIC_SWIFT},
        {0x40u, "BEELINER",     FW_IMG_MAGIC_BEELINER},
        {0x46u, "CASCADE",      FW_IMG_MAGIC_CASCADE},
        {0x12ef,"DAKOTA",       FW_IMG_MAGIC_DAKOTA},
        {0x0u,  "UNSUPP",       FW_IMG_MAGIC_UNKNOWN}
    };

const unsigned char test_target_wlan_x509[] = {
  0x30, 0x82, 0x05, 0xa2, 0x30, 0x82, 0x03, 0x8a, 0xa0, 0x03, 0x02, 0x01,
  0x02, 0x02, 0x09, 0x00, 0xaa, 0x19, 0xdc, 0x72, 0xfd, 0x7f, 0xf0, 0x61,
  0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
  0x05, 0x05, 0x00, 0x30, 0x60, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55,
  0x04, 0x0a, 0x0c, 0x09, 0x4d, 0x61, 0x67, 0x72, 0x61, 0x74, 0x68, 0x65,
  0x61, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x13,
  0x47, 0x6c, 0x61, 0x63, 0x69, 0x65, 0x72, 0x20, 0x73, 0x69, 0x67, 0x6e,
  0x69, 0x6e, 0x67, 0x20, 0x6b, 0x65, 0x79, 0x31, 0x2c, 0x30, 0x2a, 0x06,
  0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x1d,
  0x73, 0x6c, 0x61, 0x72, 0x74, 0x69, 0x62, 0x61, 0x72, 0x74, 0x66, 0x61,
  0x73, 0x74, 0x40, 0x6d, 0x61, 0x67, 0x72, 0x61, 0x74, 0x68, 0x65, 0x61,
  0x2e, 0x68, 0x32, 0x67, 0x32, 0x30, 0x20, 0x17, 0x0d, 0x31, 0x34, 0x30,
  0x38, 0x31, 0x33, 0x31, 0x32, 0x30, 0x34, 0x33, 0x39, 0x5a, 0x18, 0x0f,
  0x32, 0x31, 0x31, 0x34, 0x30, 0x37, 0x32, 0x30, 0x31, 0x32, 0x30, 0x34,
  0x33, 0x39, 0x5a, 0x30, 0x60, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55,
  0x04, 0x0a, 0x0c, 0x09, 0x4d, 0x61, 0x67, 0x72, 0x61, 0x74, 0x68, 0x65,
  0x61, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x13,
  0x47, 0x6c, 0x61, 0x63, 0x69, 0x65, 0x72, 0x20, 0x73, 0x69, 0x67, 0x6e,
  0x69, 0x6e, 0x67, 0x20, 0x6b, 0x65, 0x79, 0x31, 0x2c, 0x30, 0x2a, 0x06,
  0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x1d,
  0x73, 0x6c, 0x61, 0x72, 0x74, 0x69, 0x62, 0x61, 0x72, 0x74, 0x66, 0x61,
  0x73, 0x74, 0x40, 0x6d, 0x61, 0x67, 0x72, 0x61, 0x74, 0x68, 0x65, 0x61,
  0x2e, 0x68, 0x32, 0x67, 0x32, 0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06,
  0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
  0x03, 0x82, 0x02, 0x0f, 0x00, 0x30, 0x82, 0x02, 0x0a, 0x02, 0x82, 0x02,
  0x01, 0x00, 0xd4, 0xfe, 0xc2, 0x51, 0x6d, 0xd6, 0x4c, 0xd3, 0xb3, 0x6c,
  0xa3, 0x29, 0x58, 0x44, 0x11, 0x3f, 0x58, 0x6b, 0x65, 0xb0, 0xf4, 0xdb,
  0x60, 0xe5, 0x3a, 0x3a, 0x31, 0x58, 0xb5, 0x2b, 0x5f, 0x20, 0x64, 0x55,
  0xe8, 0x29, 0x55, 0x0f, 0xa0, 0x66, 0xa6, 0x02, 0x63, 0x40, 0x72, 0xd5,
  0x35, 0xa9, 0x5a, 0x04, 0x39, 0x2b, 0x03, 0xe1, 0x8b, 0xfa, 0xf6, 0x39,
  0xc5, 0x5d, 0xa9, 0x8d, 0x82, 0x0c, 0xd5, 0x32, 0x42, 0x57, 0x4c, 0x56,
  0x7b, 0x69, 0xf8, 0x5a, 0x28, 0x3a, 0x9c, 0x08, 0x2a, 0x1a, 0x9a, 0x4e,
  0xe7, 0xfa, 0x89, 0x4d, 0x14, 0x5d, 0x8c, 0x16, 0xb2, 0xfd, 0x94, 0x60,
  0xd4, 0xa2, 0x64, 0x92, 0x30, 0xc7, 0x72, 0x7f, 0x6a, 0x17, 0xb5, 0x76,
  0x5f, 0xaf, 0x5c, 0x2f, 0x06, 0x16, 0x9a, 0x27, 0xc7, 0xd0, 0xae, 0xe3,
  0x0e, 0xba, 0x1d, 0xaf, 0x17, 0xf1, 0x5d, 0xa6, 0x0d, 0x67, 0x0b, 0xf2,
  0x2d, 0x60, 0xc1, 0x2e, 0x0c, 0x5c, 0xdf, 0xed, 0x9e, 0x9d, 0x60, 0xd1,
  0x8e, 0x48, 0xf3, 0x4d, 0xc7, 0xa3, 0x41, 0x02, 0x53, 0x5f, 0xb4, 0xe9,
  0xcc, 0x60, 0x04, 0x47, 0xc7, 0x27, 0x1e, 0xf4, 0x65, 0xbe, 0x90, 0xb7,
  0x97, 0x3c, 0x65, 0x0b, 0xee, 0x6b, 0x8f, 0xe3, 0xfd, 0xd5, 0x78, 0x2b,
  0xb7, 0x09, 0x2e, 0xd9, 0x5e, 0x2e, 0xae, 0x80, 0x0d, 0xa5, 0x74, 0xb7,
  0xbc, 0x8d, 0x10, 0x21, 0x8a, 0x35, 0x63, 0x5a, 0x27, 0x94, 0xe9, 0x7a,
  0x5e, 0x3a, 0x91, 0x75, 0xad, 0xc2, 0xe4, 0x66, 0xbd, 0x49, 0x1f, 0x20,
  0x24, 0x3c, 0xad, 0x40, 0x57, 0x43, 0x29, 0x2f, 0x53, 0xad, 0xa9, 0xf6,
  0x26, 0xad, 0x5e, 0x37, 0xd4, 0x34, 0xab, 0x45, 0xbe, 0x41, 0x89, 0xba,
  0x6d, 0x15, 0xba, 0x26, 0xfd, 0xbf, 0x59, 0x28, 0x94, 0x2d, 0xb2, 0x55,
  0xcf, 0x46, 0x60, 0x5c, 0xe6, 0x20, 0x30, 0xee, 0x45, 0xae, 0x81, 0x86,
  0x14, 0xd9, 0x83, 0x85, 0x3e, 0x32, 0x53, 0xe3, 0xf8, 0x70, 0xb1, 0xb7,
  0xf0, 0x5d, 0xc2, 0x71, 0xae, 0x7b, 0x7e, 0x48, 0x6c, 0x0d, 0x7c, 0x83,
  0x27, 0xea, 0xc5, 0xc7, 0xca, 0x7a, 0x51, 0xd8, 0x2d, 0x55, 0x5b, 0x68,
  0xa9, 0xca, 0x6f, 0xbb, 0x45, 0x05, 0x61, 0x57, 0xf7, 0x89, 0xa0, 0xd9,
  0xcc, 0xbd, 0x81, 0x6b, 0xde, 0xf4, 0x47, 0xad, 0x00, 0xc0, 0x43, 0xe1,
  0x97, 0xc2, 0xc2, 0xbb, 0x0b, 0x88, 0x07, 0x39, 0x8e, 0x86, 0x28, 0x84,
  0xcb, 0xdc, 0x64, 0x5b, 0x08, 0xc8, 0xad, 0x55, 0xb6, 0x02, 0xa7, 0xa7,
  0xa7, 0x01, 0x7d, 0xc0, 0xca, 0xdb, 0x56, 0xf7, 0x73, 0xc9, 0xc8, 0xf2,
  0x33, 0xe9, 0xd6, 0xf1, 0x47, 0xcc, 0xd3, 0x45, 0xdb, 0x6d, 0x05, 0x31,
  0xe6, 0x81, 0x85, 0x9c, 0x46, 0x47, 0x87, 0x57, 0x1e, 0x97, 0xae, 0x72,
  0x6d, 0xb7, 0x9b, 0x6b, 0x8b, 0xa0, 0x90, 0xdc, 0x47, 0x20, 0xd4, 0x1b,
  0x20, 0xb9, 0x0c, 0x8e, 0x9d, 0x31, 0xce, 0xca, 0xe6, 0x24, 0x2d, 0xcb,
  0x6d, 0x54, 0xbe, 0xab, 0x1e, 0xaa, 0xbf, 0x95, 0xa8, 0x55, 0xca, 0x32,
  0x53, 0xe2, 0x02, 0xbd, 0x43, 0x98, 0x04, 0xef, 0x62, 0x0f, 0xe9, 0x0f,
  0x37, 0xbb, 0xdd, 0x8c, 0x08, 0x5f, 0xab, 0x04, 0x8d, 0x12, 0x48, 0x16,
  0xd4, 0x20, 0xee, 0x5a, 0xf3, 0xfb, 0x7d, 0x52, 0x1d, 0x48, 0xcf, 0x2c,
  0x25, 0xa8, 0x4d, 0xd3, 0x80, 0x92, 0x8e, 0x21, 0xe9, 0x9b, 0xfe, 0x58,
  0x15, 0x61, 0xa8, 0xd0, 0x9e, 0x51, 0xe2, 0xa9, 0x7d, 0xc2, 0x7c, 0x8c,
  0x4b, 0xf0, 0x3a, 0x6d, 0xcd, 0xa3, 0xc0, 0xba, 0xbb, 0x01, 0x5c, 0x7f,
  0x36, 0x91, 0x7f, 0x4a, 0x63, 0xe6, 0x83, 0xaf, 0x61, 0x04, 0xc0, 0x66,
  0xa7, 0xef, 0xbc, 0xa7, 0xbe, 0x68, 0x39, 0x80, 0xd6, 0xad, 0x02, 0x03,
  0x01, 0x00, 0x01, 0xa3, 0x5d, 0x30, 0x5b, 0x30, 0x0c, 0x06, 0x03, 0x55,
  0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0b, 0x06,
  0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x1d,
  0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x56, 0x47, 0xf1,
  0xdb, 0xd8, 0xf7, 0x0c, 0xe0, 0xd1, 0x74, 0xfd, 0x2c, 0x62, 0x86, 0x9d,
  0x6e, 0xb9, 0xb4, 0x97, 0x48, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23,
  0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x56, 0x47, 0xf1, 0xdb, 0xd8, 0xf7,
  0x0c, 0xe0, 0xd1, 0x74, 0xfd, 0x2c, 0x62, 0x86, 0x9d, 0x6e, 0xb9, 0xb4,
  0x97, 0x48, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
  0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01, 0x00, 0x11, 0x45,
  0xf2, 0x16, 0x31, 0xb0, 0xac, 0x53, 0x01, 0x2f, 0x8b, 0xac, 0x33, 0xd2,
  0xed, 0x5b, 0x4b, 0x0f, 0x62, 0x09, 0xcf, 0xbc, 0x9a, 0xf0, 0x6a, 0x58,
  0xc0, 0x4d, 0x55, 0x68, 0x3b, 0x2e, 0x66, 0x27, 0x24, 0xab, 0x14, 0xd6,
  0x7c, 0x4c, 0x1b, 0x24, 0x7e, 0x43, 0x96, 0x74, 0xb8, 0x65, 0x8f, 0x25,
  0x90, 0x32, 0xb8, 0xfd, 0xc9, 0x99, 0x5b, 0x15, 0xaf, 0x77, 0x02, 0x46,
  0x3b, 0xb6, 0x0d, 0xfa, 0xcb, 0x8b, 0xb7, 0xaa, 0x9d, 0x31, 0x16, 0xc4,
  0xfb, 0xfe, 0x44, 0xbe, 0xd5, 0x58, 0xe0, 0x11, 0x6c, 0x37, 0x54, 0x0d,
  0xd7, 0xb9, 0x95, 0x3d, 0x1f, 0xf9, 0x7b, 0x81, 0xfa, 0xf1, 0xd8, 0x19,
  0x7a, 0xff, 0x29, 0xa5, 0xac, 0x69, 0xe3, 0xae, 0x86, 0x15, 0x5a, 0x86,
  0xd4, 0xb6, 0xf7, 0x09, 0x5d, 0x8c, 0xf3, 0x39, 0x88, 0xc6, 0xa7, 0x39,
  0x37, 0xc9, 0xb2, 0x30, 0x5b, 0x11, 0xb6, 0xf1, 0x92, 0xcb, 0x88, 0x82,
  0x70, 0x0e, 0x0a, 0x5e, 0x11, 0x83, 0xec, 0xab, 0x09, 0x39, 0xf6, 0x6c,
  0x42, 0x52, 0x39, 0xa9, 0x58, 0xa6, 0x2e, 0x58, 0x32, 0x95, 0x0e, 0x13,
  0x89, 0x9d, 0x48, 0x3c, 0x1f, 0xfa, 0x6b, 0xaa, 0x59, 0x6d, 0xd6, 0xac,
  0x53, 0x56, 0xb0, 0x25, 0x72, 0x9d, 0xf0, 0x38, 0xb1, 0x96, 0x67, 0x0a,
  0xdb, 0x36, 0x34, 0x90, 0x3f, 0x6a, 0x18, 0xa1, 0x96, 0xbc, 0xfa, 0x72,
  0x9c, 0x49, 0x6a, 0xbb, 0x9d, 0xe9, 0xc3, 0xcf, 0xdb, 0x56, 0xb8, 0x46,
  0x15, 0x35, 0x9d, 0x6a, 0x2a, 0x07, 0xf2, 0xfa, 0x58, 0xc3, 0x4f, 0x52,
  0x74, 0x1c, 0xe4, 0x92, 0xaa, 0x26, 0x40, 0xac, 0xaa, 0xe8, 0x50, 0x77,
  0xdc, 0x07, 0x82, 0x59, 0x6e, 0xd8, 0xc9, 0x21, 0xaa, 0x95, 0x00, 0xf8,
  0x6a, 0xc0, 0x9e, 0x88, 0xb1, 0xa4, 0x26, 0xba, 0xef, 0x52, 0x9d, 0x17,
  0x33, 0x0b, 0xde, 0x1a, 0xa8, 0x9c, 0xe5, 0x72, 0x57, 0xd2, 0xad, 0x23,
  0xae, 0x75, 0x30, 0x65, 0xf5, 0xcb, 0xb6, 0xdf, 0x24, 0x3a, 0xb2, 0x3b,
  0xa7, 0xe2, 0x64, 0xcf, 0x65, 0x06, 0x4b, 0xfa, 0x77, 0xa3, 0xc8, 0x16,
  0x73, 0x25, 0x32, 0x8a, 0x96, 0x50, 0x35, 0x65, 0x43, 0x27, 0x06, 0x56,
  0x45, 0xbd, 0x20, 0xc9, 0xaf, 0x98, 0x20, 0x78, 0xb0, 0xca, 0x47, 0x93,
  0x1f, 0x82, 0x0b, 0x77, 0xaa, 0x85, 0xf7, 0x9b, 0xa3, 0xb8, 0xb7, 0xc3,
  0x57, 0xa1, 0x5d, 0x0c, 0x5c, 0x36, 0x32, 0xd4, 0x19, 0x4f, 0x98, 0xa6,
  0x34, 0x72, 0xe7, 0xb3, 0xdb, 0xd4, 0xed, 0xc9, 0x98, 0x44, 0x71, 0x97,
  0xc4, 0x94, 0x46, 0x9e, 0xdd, 0x64, 0x8a, 0x79, 0xee, 0x90, 0x5b, 0xbb,
  0xc3, 0xc7, 0xde, 0x20, 0xb6, 0x78, 0x66, 0xae, 0xd5, 0x98, 0x5c, 0x20,
  0x9c, 0x75, 0xfe, 0x1a, 0xd4, 0x50, 0xd0, 0x8b, 0x3b, 0xee, 0x55, 0x0c,
  0x17, 0xf8, 0x4c, 0x00, 0x47, 0x33, 0x59, 0xcf, 0x97, 0x13, 0x29, 0x7e,
  0xb9, 0xbd, 0x86, 0x01, 0x82, 0x94, 0x26, 0x05, 0x96, 0x32, 0xf0, 0xf3,
  0x03, 0xf7, 0x2c, 0x1f, 0xcd, 0x64, 0x83, 0xcf, 0xc0, 0xa9, 0x7b, 0xcb,
  0x34, 0x3c, 0x72, 0x88, 0xec, 0x81, 0x96, 0x30, 0x6c, 0x3a, 0xf0, 0xe2,
  0x09, 0x7a, 0x49, 0x2d, 0x58, 0x50, 0x9b, 0x1e, 0xc0, 0x26, 0xc4, 0x3f,
  0xd1, 0x78, 0x71, 0x9e, 0x2c, 0x50, 0x29, 0x82, 0x28, 0x86, 0x32, 0xe5,
  0x55, 0x48, 0x4d, 0xf4, 0x45, 0x72, 0x70, 0x3e, 0x0c, 0x6e, 0xd3, 0x13,
  0x82, 0xdb, 0x11, 0xa6, 0x0c, 0x29, 0x84, 0xe0, 0xe5, 0x01, 0x43, 0xc4,
  0xe8, 0x48, 0x18, 0x96, 0x2c, 0x69, 0xe9, 0x1c, 0xea, 0xcc, 0xf1, 0x32,
  0xca, 0x68, 0xf5, 0x8a, 0x34, 0x12, 0x5f, 0xdc, 0x2f, 0xe3, 0xa0, 0xb8,
  0x11, 0x8b, 0x18, 0x9e, 0x48, 0x42
};
const unsigned int test_target_wlan_x509_len = 1446;

struct cert fw_test_certs[4] =  {
    {sizeof (test_target_wlan_x509), &test_target_wlan_x509[0]},
    {sizeof (test_target_wlan_x509), &test_target_wlan_x509[0]},
    {sizeof (test_target_wlan_x509), &test_target_wlan_x509[0]},
    {sizeof (test_target_wlan_x509), &test_target_wlan_x509[0]}
};
struct cert fw_prod_certs[4] =  {
    {sizeof (test_target_wlan_x509), &test_target_wlan_x509[0]},
    {sizeof (test_target_wlan_x509), &test_target_wlan_x509[0]},
    {sizeof (test_target_wlan_x509), &test_target_wlan_x509[0]},
    {sizeof (test_target_wlan_x509), &test_target_wlan_x509[0]}
};
 /* interface function to return the firmware file pointers
 * Description:
 * Load the firmware, check security attributes and then see if this requires
 * firmware authentication or not. If no firmware authentication required
 * return firmware pointer, otherwise, returns the firmware pointer iff signature
 * checks are good.  if code sign feature is disabled, do nothing, but return
 * the same fw_entry pointer, if enabled, process the header and advance the
 * fw_entry->data pointer by header size, reduce the size by the header
 * in the fw_entry, while freeing make sure that we go back by header size
 * and free.
 */
static int
request_secure_firmware(struct firmware **fw_entry, const char *file,
        struct device *dev, int dev_id)
{
    unsigned char *fw;
    unsigned int len=0;
    struct auth_input fw_check_buffer;
    int cert_type, err=0;
    struct firmware_head *h;
    int status = 0;

    if(!file) return -1;

    status = request_firmware((const struct firmware **)fw_entry, file, dev);

    if (status != 0) return status;

    /* code sign is not enabled, assume the real file starts from the start of
     * the file and return success. There is no risk in this, because
     * fw_code_sign module param can't modified from out side.
     */
    if (!fw_code_sign) return status;

    /* below is only when code sign is enabled
     */
    fw = (unsigned char*)(*fw_entry)->data;                 /* the start of the firmware file */

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s Total Firmware file allocated %d\n", __func__, (*fw_entry)->size);
    h = fw_unpack(fw, dev_id, &err);
    if(!h) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: something wrong in reading the firmware header", __func__);
        release_firmware(*fw_entry);
        return -1;
    }
    /* we assume post the integration of the code, all files continue to have
     * this header if not, there is some thing wrong. Also in case of signed
     * files, firmware signing version would be present and if that is zero,
     * that is not signed
     */
    if (h && !h->fw_img_sign_ver) {
       goto fail;
    }

    /* now the fimrware is unpacked, build and pass it to kernel
     */
    memset(&fw_check_buffer, 0, sizeof(fw_check_buffer));
    fw_check_buffer.certBuffer = (unsigned char *)fw_sign_get_cert_buffer(h, &cert_type, &len);
    if (fw_check_buffer.certBuffer) {
        int err=0;
        fw_check_buffer.signature = (unsigned char*)fw +
                                    h->fw_hdr_length + h->fw_img_size;
        /* sign is calculated with header */
        fw_check_buffer.data = fw ;
        fw_check_buffer.cert_len = len;
        fw_check_buffer.sig_len = h->fw_sig_len;
        fw_check_buffer.data_len = h->fw_img_size + h->fw_hdr_length;
        fw_check_buffer.sig_hash_algo = fw_sign_get_hash_algo(h);
        fw_check_buffer.pk_algo = fw_sign_get_pk_algo(h);
        fw_check_buffer.cert_type = cert_type;
        /* we are done with all, now call into linux and see what it returns,
         * if authentication is good, return the pointer to fw, otherwise,
         * free the buffer and return NULL
         */

        if (fw_code_sign >= 2) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "fw_check_buffer.signature %x,\n"
                   "fw_check_buffer.data %x,\n"
                   "fw_check_buffer.cert_len %x,\n"
                   "fw_check_buffer.sig_len %x,\n"
                   "fw_check_buffer.data_len %x,\n"
                   "fw_check_buffer.sig_hash_algo %x,\n"
                   "fw_check_buffer.pk_algo %x,\n"
                   "fw_check_buffer.cert_type %x\n",
            (unsigned int)fw_check_buffer.signature ,
            (unsigned int)fw_check_buffer.data ,
            (unsigned int)fw_check_buffer.cert_len ,
            (unsigned int)fw_check_buffer.sig_len ,
            (unsigned int)fw_check_buffer.data_len,
            (unsigned int)fw_check_buffer.sig_hash_algo ,
            (unsigned int)fw_check_buffer.pk_algo ,
            (unsigned int)fw_check_buffer.cert_type );
        }
        if ((err=authenticate_fw(&fw_check_buffer)) < 0)  {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: authentication status %d \n", __func__, err);
            goto fail;
        } else {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: authentication status %d \n", __func__, err);
        }
    } else {
        goto fail;
    }
    /*
     * caller is not aware of that firmware is signed, make sure that caller
     * gets the real firmware pointer, this is, nothing but, fw->data+sizeof(h0;
     * data pointer is of type u8, so regular math should work
     */
    (*fw_entry)->data += sizeof(struct firmware_head);
    /* fw_img_size is actual size of file for loading, check WAR for
     * release_secure_firmware how this impacts free of the firmware.
     */
    (*fw_entry)->size = h->fw_img_size;
    if (h) kfree(h);
    return 0;
fail:
    release_firmware(*fw_entry);
    if(h) kfree(h);
    return -1;
}

/* release_secure_firmware
 * Description
 *      In case of code signing, the firmware has extra pointers, because
 *      request_secure_firmware uses the request_firmware internally, which
 *      does simply loads the firmware. Because of this, we either need to
 *      move the firmware pointer back by size of the header or free it
 *      simply, based firmware entry
 */
static void
release_secure_firmware(struct firmware *fw_entry)
{
    struct firmware_head *h;

    if (!fw_entry) return;
    if (!fw_code_sign) return release_firmware(fw_entry);
    /* modify the firmware data pointer */
    fw_entry->data -= sizeof (struct firmware_head);
    /*
     * release_firmware actually frees the virtual pages based on size allocated
     * earlier, so correct the size size back to correct number
     */
    h = (struct firmware_head *) (fw_entry->data);

    /*
     * In fw_unpack(), the header bytes are copied to a distinct block of memory
     * because  sign compuation  happens post converting to network byte order.
     *
     * Before freeing, there is no use of this memory, and we can aovid copy
     * and do the in-memory conversion in place.
     *
     * fw_entry->size is set by linux kernel and it is always equal to size of
     * the firmware file. So it is fine to assign the same number of bytes
     * to size. release_firmware() actually gets number of pages from size.
     */
    ntohlm(h, sizeof(struct firmware_head));
    fw_entry->size = h->fw_img_length;

    if (fw_code_sign >= 2) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\nFirmware header base        :0x%8x\n", (unsigned int)h);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "                length      :0x%8x\n", h->fw_hdr_length);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "                img size    :0x%8x\n", h->fw_img_size);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "                img length  :0x%8x\n", h->fw_img_length);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "                img magic   :0x%8x\n", h->fw_img_magic_number);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "                chip id     :0x%8x\n", h->fw_chip_identification);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "                file magic  :0x%8x\n", h->fw_img_file_magic);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "                signing ver :0x%8x\n", h->fw_img_sign_ver);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "                ver M/S/E   :%x/%x/%x\n",
                                                    FW_VER_GET_MAJOR(h),
                                                    FW_VER_GET_IMG_TYPE(h),
                                                    FW_VER_GET_IMG_TYPE_VER(h));
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "                flags       :%x\n",h->fw_hdr_flags);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "                sign length :%8x\n", h->fw_sig_len);
    }
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s Total Firmware file allocated %d\n", __func__, fw_entry->size);
    release_firmware(fw_entry);
}
/*
 * dump the bytes in 2 bytes, and 16 bytes per line
 */
static void
fw_hex_dump(unsigned char *p, int len)
{
    int i=0;

    for (i=0; i<len; i++) {
        if (!(i%16)) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n");
        }
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%2x ", p[i]);
    }
}
/*
 * fw_unpack extracts the firmware header from the bin file, that is loaded
 * through request_firmware(). Firmware header is in network byte order. This is
 * copied to a block of memory and converted to host byteorder to make sure that
 * the firmware header do not depend on system where it is generated.
 *
 * Post filling that it does check lot of sanity checks and then returns pointer
 * to firmware header.
 */
static struct firmware_head *
fw_unpack(unsigned char *fw, int chip_id, int *err)
{
    struct firmware_head *th, *h;
    int i = 0;

    if (!fw) return FW_SIGN_ERR_INTERNAL;

    /* at this point, the firmware header is in network byte order
     * load that into memort and convert to host byte order
     */
    th = kmalloc(sizeof(struct firmware_head), GFP_KERNEL);
    if (!th) {
        return NULL;
    }
    memcpy(th, fw, sizeof(struct firmware_head));

	ntohlm(th, sizeof(struct firmware_head));
    /* do not access header before this line */
    h = th;

    if (fw_code_sign >= 2) {
        unsigned char *data, *signature;

        if (fw_code_sign >= 3) {
            fw_hex_dump((unsigned char*)h, sizeof(struct firmware_head));
        }

        signature = (unsigned char*)fw + h->fw_hdr_length + h->fw_img_size;
        data = (unsigned char *)fw + sizeof(struct firmware_head);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\nFirmware header base        :0x%8x\n", (unsigned int)fw);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "                length      :0x%8x\n", h->fw_hdr_length);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "                img size    :0x%8x\n", h->fw_img_size);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "                img length  :0x%8x\n", h->fw_img_length);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "                img magic   :0x%8x\n", h->fw_img_magic_number);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "                chip id     :0x%8x\n", h->fw_chip_identification);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "                file magic  :0x%8x\n", h->fw_img_file_magic);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "                signing ver :0x%8x\n", h->fw_img_sign_ver);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "                ver M/S/E   :%x/%x/%x\n",
                                                    FW_VER_GET_MAJOR(h),
                                                    FW_VER_GET_IMG_TYPE(h),
                                                    FW_VER_GET_IMG_TYPE_VER(h));
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "                flags       :%x\n",h->fw_hdr_flags);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "                sign length :%8x\n", h->fw_sig_len);
        if (fw_code_sign >= 3) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " ==== HEX DUMPS OF REGIONS ====\n");
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "SIGNATURE:\n");
            fw_hex_dump(signature, h->fw_sig_len);
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\nDATA\n");
            fw_hex_dump(data, h->fw_img_size);
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "=== HEX DUMP END ===\n");
        }
    }
    if ( (i=fw_check_img_magic(h->fw_img_magic_number)) >= 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Chip Identification:%x Device Magic %x: %s found\n",
                fw_auth_supp_devs[i].dev_id,
                fw_auth_supp_devs[i].img_magic,
                fw_auth_supp_devs[i].dev_name);
    } else {
        *err = -FW_SIGN_ERR_UNSUPP_CHIPSET;
        kfree(h);
        return NULL;
    }
    if ( (chip_id == h->fw_chip_identification) &&
            (fw_check_chip_id(h->fw_chip_identification) >= 0)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Chip Identification:%x Device Magic %x: %s found\n",
                fw_auth_supp_devs[i].dev_id,
                fw_auth_supp_devs[i].img_magic,
                fw_auth_supp_devs[i].dev_name);
    } else {
        *err =  -FW_SIGN_ERR_INV_DEV_ID;
        kfree(h);
        return NULL;
    }

    if (fw_sign_check_file_magic(h->fw_img_file_magic) >= 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Found good image magic %x\n", h->fw_img_file_magic);
    } else {
        *err = -FW_SIGN_ERR_INVALID_FILE_MAGIC;
        kfree(h);
        return NULL;
    }
    /* dump various versions */
    if (h->fw_img_sign_ver && (h->fw_img_sign_ver  != THIS_FW_IMAGE_VERSION)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Firmware is not signed with same version, as the tool\n");
        *err = -FW_SIGN_ERR_IMAGE_VER;
        kfree(h);
        return NULL;
    }
    /* check and dump the versions that are available in the file for now
     * TODO roll back check would be added in future
     */
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Major: %d S/E/C: %d Version %d\n",
            FW_VER_GET_MAJOR(h), FW_VER_GET_IMG_TYPE(h), FW_VER_GET_IMG_TYPE_VER(h));

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Minor: %d sub version:%d build_id %d\n",
            FW_VER_IMG_GET_MINOR_VER(h),
            FW_VER_IMG_GET_MINOR_SUBVER(h),
            FW_VER_IMG_GET_MINOR_RELNBR(h));

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Header Flags %x\n", h->fw_hdr_flags);
    /* sanity can be added, but ignored for now, if this goes
     * wrong, file authentication goes wrong
     */
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "image size %d \n", h->fw_img_size);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "image length %d \n", h->fw_img_length);
    /* check if signature algorithm is supported or not */
    if (!fw_check_sig_algorithm(h->fw_sig_algo)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "image signing algorithm mismatch %d \n", h->fw_sig_algo);
        *err = -FW_SIGN_ERR_SIGN_ALGO;
        kfree(h);
        return NULL;
    }

    /* do not check oem for now */
    /* TODO dump the sinagure now here, and passit down to kernel
     * crypto module
     */
    return h;
}
/*
 * find and check the known chip ids
 */
static inline int
fw_check_chip_id(unsigned int chip_id)
{
    int i=0;

    for (i = 0;
         ((i < NELEMENTS(fw_auth_supp_devs)) && (fw_auth_supp_devs[i].dev_id != chip_id) &&
            (fw_auth_supp_devs[i].dev_id != 0)) ;
         i++)
       ;
    if (fw_auth_supp_devs[i].dev_id == 0) return -1;
    return i;
}
/*
 * validate file image magic numbers
 */
inline int
fw_check_img_magic(unsigned int img_magic)
{
    int i=0;

    for (i = 0;
         ((i < NELEMENTS(fw_auth_supp_devs)) && (fw_auth_supp_devs[i].img_magic != img_magic) &&
            (fw_auth_supp_devs[i].dev_id != 0)) ;
         i++)
       ;
    if (fw_auth_supp_devs[i].dev_id == 0) return -1;
    return i;
}
/*
 * check image magics
 */
static inline int
fw_sign_check_file_magic(unsigned int file_type)
{
    switch (file_type) {
    case FW_IMG_FILE_MAGIC_TARGET_BOARD_DATA:
    case FW_IMG_FILE_MAGIC_TARGET_WLAN:
    case FW_IMG_FILE_MAGIC_TARGET_OTP:
    case FW_IMG_FILE_MAGIC_TARGET_CODE_SWAP:
        return 0;
    case FW_IMG_FILE_MAGIC_INVALID:
        return -FW_SIGN_ERR_INVALID_FILE_MAGIC;
    default:
        return -FW_SIGN_ERR_INVALID_FILE_MAGIC;
    }
    return 0;
}

/*
 * get supported hash method
 */
static int
fw_sign_get_hash_algo (struct firmware_head *h)
{
    if(!h) return -1;

    /* avoid warning */
    h = h;

    /* right now do not check any thing but return one known
     * algorithm, fix this by looking at versions of the
     * signing
     */
    return HASH_ALGO_SHA256;
}

/*
 * At this time, do not use any thing, but return the same known algorithm type. Ideally we should
 * add this by knowing the file type and signature version
 */
static int
fw_sign_get_pk_algo (struct firmware_head *h)
{
    if(!h) return -1;

    /* avoid warning*/
    h = h;
    /* FIXME based on signing algorithm, we should choose
     * different keys, right now return only one
     */
    return PKEY_ALGO_RSA;
}
/*
 * get certficate buffer based on file type and signing version
 */
const unsigned char  *
fw_sign_get_cert_buffer(struct firmware_head *h, int *cert_type, int *len)
{
    int idx=0;

    if (!h) return NULL;

    /* based on signing version, we should be filling these numbers, right now now checks */
    *cert_type = PKEY_ID_X509;
    switch (h->fw_img_file_magic)
    {
        case FW_IMG_FILE_MAGIC_TARGET_WLAN:
            idx = 0;
            break;
        case FW_IMG_FILE_MAGIC_TARGET_OTP:
            idx = 1;
            break;
        case FW_IMG_FILE_MAGIC_TARGET_BOARD_DATA:
            idx = 2;
            break;
        case FW_IMG_FILE_MAGIC_TARGET_CODE_SWAP:
            idx = 3;
            break;
        default:
            return NULL;
    }
    if (h->fw_ver_rel_type == FW_IMG_VER_REL_TEST) {
        *len = fw_test_certs[idx].cert_len;
        return &fw_test_certs[idx].cert[0];
    } else if (h->fw_ver_rel_type == FW_IMG_VER_REL_PROD) {
        *len = fw_prod_certs[idx].cert_len;
        return &fw_prod_certs[idx].cert[0];
    } else {
        return NULL;
    }
}
static inline int
fw_check_sig_algorithm(int s)
{
    switch (s) {
        case RSA_PSS1_SHA256:
            return 1;
    }
    return 0;
}
/* utility functions */
static inline void
htonlm(void *sptr, int len)
{
    int i = 0;
    unsigned int *dptr = (unsigned int*)sptr;
    /* length 0 is not allowed, minimum 4 bytes */
    if (len <= 0) len = 4;
    for(i=0; i<len/4; i++) {
        dptr[i] = htonl(dptr[i]);
    }
}
static inline void
ntohlm(void *sptr, int len)
{
    int i = 0;
    unsigned int *dptr = (unsigned int*)sptr;
    /* length 0 is not allowed, minimum 4 bytes */
    if (len <= 0) len = 4;
    for(i=0; i<len/4; i++) {
        dptr[i] = ntohl(dptr[i]);
    }
}
#endif  /* FW_CODE_SIGN */
